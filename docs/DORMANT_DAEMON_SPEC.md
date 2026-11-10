# Dormant Mode Daemon Specification

> **Bead**: `process_triage-2kz`
> **Status**: Specification
> **Version**: 1.0.0

## Overview

The dormant mode daemon (`ptd`) provides 24/7 lightweight monitoring with automatic escalation when system conditions warrant intervention. It bridges the gap between manual on-demand scans and continuous protection.

### Design Philosophy

1. **Never become the problem** - Strict overhead budget; daemon must not consume noticeable resources
2. **Detect, don't act** - Default behavior is to prepare plans for human/agent review, not execute
3. **Escalate intelligently** - Use statistical triggers to avoid false alarms from transient spikes

---

## Operating Modes

| Mode | Trigger | Behavior |
|------|---------|----------|
| **Dormant** | Default | Minimal signal collection at low frequency |
| **Alert** | Trigger threshold crossed | Quick scan, notify user, prepare inbox item |
| **Escalated** | Sustained alert | Deep scan suspects, generate full session plan |

### State Machine

```
┌─────────────┐
│   DORMANT   │◄──────────────────┐
│  (default)  │                    │
└──────┬──────┘                    │
       │ trigger detected          │ cooldown expires
       ▼                           │
┌─────────────┐                    │
│    ALERT    │────────────────────┤
│ (quick scan)│                    │
└──────┬──────┘                    │
       │ sustained                 │
       ▼                           │
┌─────────────┐                    │
│  ESCALATED  │────────────────────┘
│ (deep scan) │
└─────────────┘
```

---

## Overhead Budget

The daemon MUST NOT exceed these resource limits:

| Resource | Dormant | Alert | Escalated |
|----------|---------|-------|-----------|
| **CPU** | < 0.1% avg | < 1% avg | < 5% burst |
| **Memory** | < 10 MB RSS | < 25 MB RSS | < 50 MB RSS |
| **I/O** | < 1 KB/s avg | < 100 KB/s | < 1 MB/s burst |
| **Wake frequency** | 30-60s | 5s | continuous |

### Self-Limiting Mechanisms

```rust
// Daemon enforces its own budget
struct OverheadBudget {
    max_cpu_percent: f32,      // 0.1 default
    max_memory_mb: u32,        // 10 default
    max_io_bytes_per_sec: u64, // 1024 default

    // Automatic backoff on budget breach
    backoff_factor: f32,       // 2.0
    max_backoff_seconds: u32,  // 300 (5 min)
}
```

**Enforcement**:
1. Use `nice 19` and `ionice -c3` (idle class) for all daemon operations
2. Self-monitor CPU/memory; back off if exceeding budget
3. Log budget breaches as telemetry events

---

## Signal Collection

### Dormant Mode Signals

Minimal, low-cost signals collected every 30-60 seconds:

| Signal | Source | Cost |
|--------|--------|------|
| Load average | `/proc/loadavg` | ~1 syscall |
| Memory pressure | `/proc/meminfo` (MemAvailable) | ~1 syscall |
| PSI stall times | `/proc/pressure/{cpu,memory,io}` | ~3 syscalls |
| Process count | `/proc` directory entry count | ~1 syscall |
| Orphan count | Unsupervised PID-1 adoptees in login/transient workloads (Linux) | One stat read per PID; cgroup + identity recheck for possible adoptees |

The orphan trigger excludes service/container placement and processes that lead
their own session (falling back to process-group leadership only when the session
ID is unavailable). It requires unchanged birth and lineage
across the placement read. An incomplete, unreadable or unsupported census is
`null` in tick JSON and `NaN` in the `pt_orphan_count` metric; it interrupts the
sustained-trigger window without supplying a zero to the EWMA. A readable empty
census produces an observed zero. Old daemon state must establish a fresh
placement-aware orphan window before it can trigger a plan.

### Data Structures

```rust
/// Lightweight signal sample for dormant monitoring
struct DormantSample {
    timestamp: SystemTime,
    load_avg_1m: f32,
    load_avg_5m: f32,
    mem_available_pct: f32,
    psi_cpu_some_total_us: u64,
    psi_mem_some_total_us: u64,
    psi_io_some_total_us: u64,
    process_count: u32,
    orphan_count_estimate: Option<u32>,
}
```

---

## Trigger Specification

### Trigger Types

| Trigger | Condition | Rationale |
|---------|-----------|-----------|
| **Sustained Load** | Load avg > 2×cores for 5+ minutes | Probable runaway processes |
| **Memory Pressure** | MemAvailable < 10% for 3+ minutes | Memory exhaustion risk |
| **PSI Stall Spike** | CPU/IO some > 25% avg over 2 min | System responsiveness degraded |
| **Orphan Spike** | Orphan count delta > 10 in 5 min | Parent death cascade |
| **Process Explosion** | Process count delta > 50 in 5 min | Fork bomb or runaway spawning |

### Detection Algorithm

Use EWMA (Exponentially Weighted Moving Average) for noise-robust detection:

```rust
struct TriggerDetector {
    /// EWMA smoothing factor (0.1 = slow, 0.5 = responsive)
    alpha: f32,

    /// Current EWMA values per signal
    ewma: HashMap<SignalType, f32>,

    /// Threshold crossing duration
    threshold_duration: HashMap<SignalType, Duration>,

    /// Minimum sustained duration before trigger fires
    min_sustained_duration: Duration,  // default: 2 minutes
}

impl TriggerDetector {
    fn update(&mut self, sample: &DormantSample) -> Option<TriggerEvent> {
        // Update EWMA for each signal
        // Check if any signal exceeds threshold
        // Track duration of threshold crossing
        // Fire trigger if sustained >= min_sustained_duration
    }
}
```

### Sequential Testing (Optional)

For agents requiring statistical rigor, use time-uniform concentration bounds:

```rust
/// Confidence-bounded trigger using sequential testing
struct SequentialTrigger {
    /// Running sum of log-likelihood ratios
    log_lr_sum: f64,

    /// Upper and lower thresholds (from SPRT)
    upper_threshold: f64,  // log(1/alpha) for "abnormal"
    lower_threshold: f64,  // log(beta) for "normal"

    sample_count: u64,
}
```

This allows triggers to fire with controllable false-positive rates even under continuous monitoring.

---

## Escalation Protocol

### Phase 1: Alert (Quick Scan)

When a trigger fires:

1. Acquire global lock `.pt-lock` (non-blocking, skip if held)
2. Run quick 3-sample scan (same as `pt scan`)
3. Compute basic scores without full inference
4. If candidates found:
   - Create inbox entry
   - Send notification (if configured)
   - Enter cooldown
5. If no candidates: reset trigger, return to dormant

### Phase 2: Escalation (Deep Scan)

If trigger persists after alert:

1. Run targeted deep scan on top candidates from quick scan
2. Full inference pipeline
3. Generate action plan
4. Create full session in inbox
5. Extended cooldown

### Cooldown Rules

| Event | Cooldown Duration |
|-------|-------------------|
| Alert (no candidates) | 5 minutes |
| Alert (candidates found) | 15 minutes |
| Escalation complete | 1 hour |
| Manual session started | 2 hours |
| Plan applied | 4 hours |

```rust
struct CooldownManager {
    last_alert: Option<SystemTime>,
    last_escalation: Option<SystemTime>,
    last_manual_run: Option<SystemTime>,
    last_plan_applied: Option<SystemTime>,

    fn is_in_cooldown(&self) -> bool;
    fn remaining_cooldown(&self) -> Duration;
}
```

---

## Integration Specifications

### Linux: systemd User Service

`pt-core daemon install` writes `ptd.service` under
`$XDG_CONFIG_HOME/systemd/user`, or `~/.config/systemd/user` when that variable is
unset. Installation alone writes the definition; activation requires
`--activate`. Existing manager enablement is preserved.

```bash
# Inspect the exact definition and manager argument arrays without changing anything
pt-core --config "$HOME/.config/process_triage" --dry-run daemon install --activate

# Write the definition without starting the daemon
pt-core --config "$HOME/.config/process_triage" daemon install

# Enable monitoring now and at subsequent user logins
pt-core --config "$HOME/.config/process_triage" daemon install --activate

# Inspect the definition and the manager's observed state
pt-core daemon service-status

# Inspect the daemon's own PID, pressure state, and persisted monitoring status
pt-core daemon status

# View logs
journalctl --user -u ptd.service -f

# Preview, then stop/disable the service and remove its verified definition
pt-core --dry-run daemon uninstall
pt-core daemon uninstall
```

The generated unit runs the absolute path of the installing `pt-core` executable
in the foreground, with an explicit absolute configuration directory:

```text
/absolute/path/pt-core --config /absolute/config --dry-run daemon start --foreground
```

`--dry-run` is part of the installed command even when installation is activated.
The daemon generates review plans; that flag disables automatic mitigation in
both initial configuration and subsequent reloads, and propagates to children.
The service uses `Restart=on-failure`, a 30-second restart delay, and idle I/O and
CPU scheduling priority. Its internal overhead controls manage sampling. A
watchdog is not configured because the daemon does not implement `sd_notify`.

Arguments are individually quoted. The `ExecStart=:` prefix disables systemd
environment-variable substitution and `%%` preserves literal percent signs in
paths. See [systemd.service command lines](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html)
and [systemd unit syntax](https://www.freedesktop.org/software/systemd/man/latest/systemd.syntax.html).

### macOS: launchd Agent

The same commands write
`~/Library/LaunchAgents/com.processtriage.ptd.plist`. The plist uses a literal,
XML-escaped `ProgramArguments` array for the same foreground, review-only
command. New definitions contain `Disabled=true`; explicit activation enables
and bootstraps the agent in `gui/<current-user-id>`. If that managed agent is
already loaded, activation uses non-force `kickstart`, preserving a running
daemon. Restart after an unsuccessful exit is throttled to 30 seconds.

This is a user launch agent and requires the user's graphical login session.
Manager enablement persists separately from the plist, so the definition's
`Disabled` key alone does not establish current status. `daemon service-status`
shows the actual `launchctl print` output and whether the managed definition
could be verified. An absent service is distinguished from a missing GUI domain
or an inaccessible manager. See Apple's
[launchd job guide](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)
and [launchd.plist reference](https://github.com/apple-oss-distributions/launchd/blob/main/man/launchd.plist.5).

### Ownership, failures, and upgrades

Installation uses exclusive file creation and private permissions. Symlinks,
foreign definitions, writable-by-others files, and locally edited managed
definitions are refused. A managed fingerprint detects edits; it is not an
authentication boundary against the owning user. Activation and removal also
verify the manager's loaded definition path. Linux unit drop-ins are refused,
including those discovered after reloading the manager.

Repeating an identical installation is safe. A changed executable or config
path requires inspecting and uninstalling the old definition before installing
the new one. The existing service definition therefore remains inspectable when
a binary has moved. User configuration and daemon history survive uninstall.

Manager commands use literal argument arrays, a 15-second timeout, and bounded
output. Failure diagnostics retain the command, exit status, stdout, and stderr.
Failed activation retains the definition for diagnosis. Failed deactivation
retains the definition rather than forgetting a service that may still be
running; a final reload failure after removal is reported. `--dry-run` performs
no writes or manager calls and reports planned commands and conditional steps.
Pure definition/command tests and retained-directory file tests cover these
contracts; real service-manager activation must be validated on Linux and macOS
hosts before claiming deployment evidence.

---

## Inbox UX

### Session Types

| Type | Source | Icon | Priority |
|------|--------|------|----------|
| `daemon_alert` | Daemon quick scan | :bell: | Normal |
| `daemon_escalation` | Daemon deep scan | :warning: | High |
| `manual` | User-initiated | :person: | Normal |
| `agent` | Agent-initiated | :robot: | Normal |

### Inbox Entry Structure

```json
{
  "session_id": "ptd-20260115-143022-abc123",
  "type": "daemon_escalation",
  "created_at": "2026-01-15T14:30:22Z",
  "trigger": {
    "type": "sustained_load",
    "value": 24.5,
    "threshold": 12.8,
    "duration_seconds": 312
  },
  "summary": {
    "candidates_found": 3,
    "top_candidate": {
      "pid": 12345,
      "comm": "runaway-test",
      "score": 87,
      "recommendation": "KILL"
    }
  },
  "plan_ready": true,
  "expires_at": "2026-01-16T14:30:22Z"
}
```

### Notification Methods

| Method | Configuration | Default |
|--------|---------------|---------|
| Desktop notification | `notify-send` / osascript | Enabled |
| Terminal bell | BEL character on next pt run | Enabled |
| Email | SMTP settings in config | Disabled |
| Webhook | URL in config | Disabled |
| File flag | `~/.local/share/process_triage/inbox.flag` | Enabled |

---

## Coordination with Manual/Agent Runs

### Lock Semantics

```rust
/// Lock states for coordination
enum LockState {
    /// No active pt session
    Free,

    /// Manual pt run in progress
    ManualSession { pid: u32, started: SystemTime },

    /// Agent session in progress
    AgentSession { agent_id: String, started: SystemTime },

    /// Daemon alert/escalation in progress
    DaemonSession { trigger: TriggerType, started: SystemTime },
}
```

### Priority Rules

1. **Manual/Agent takes precedence**: If user starts `pt` or agent runs, daemon yields immediately
2. **Daemon defers to cooldown**: After manual/agent run, daemon enters extended cooldown
3. **Lock timeout**: Daemon never holds lock > 5 minutes; hard-release if exceeded
4. **Stale lock detection**: If lock holder PID doesn't exist, daemon can acquire

### Lock File Format

`~/.local/share/process_triage/.pt-lock`:

```json
{
  "holder": "daemon",
  "pid": 54321,
  "started_at": "2026-01-15T14:30:22Z",
  "operation": "quick_scan",
  "timeout_at": "2026-01-15T14:35:22Z"
}
```

---

## Safety Constraints

### Never Execute Destructive Actions

The daemon MUST NOT:
- Send SIGKILL or SIGTERM to any process
- Execute any action plan automatically
- Modify process state (pause, renice, cgroup)

The daemon MAY (if explicitly configured):
- Execute non-destructive mitigations: `pause` (SIGSTOP)
- Apply resource throttling: `renice`, `cgroup cpu.max`
- These require explicit `policy.json` configuration:

```json
{
  "daemon": {
    "auto_mitigate": false,
    "allowed_auto_actions": [],
    "require_human_for_kill": true
  }
}
```

### Watchdog and Self-Termination

```rust
impl Daemon {
    /// Self-terminate if overhead budget exceeded repeatedly
    fn check_budget_compliance(&mut self) {
        if self.consecutive_budget_breaches > 3 {
            log::error!("Daemon repeatedly exceeding budget, self-terminating");
            self.shutdown(ExitCode::BUDGET_EXCEEDED);
        }
    }

    /// Respond to systemd watchdog
    fn notify_watchdog(&self) {
        if let Ok(()) = sd_notify::watchdog() {
            // Watchdog notified
        }
    }
}
```

---

## Configuration

### Implemented Load Thresholds

The default daemon load trigger compares the one-minute load with **2.0 times the
online CPU count observed in the same pressure snapshot**. It requires three
consecutive observed breaches by default and retains the configured tick-based
cooldown. CPU capacity is read on each tick, so a changed capacity changes the
threshold for that tick. This is a load-pressure signal; it does not establish
that any particular process is abandoned.

Native `DaemonConfig` JSON uses `triggers.load_per_cpu_threshold` for this ratio.
An explicit numeric `triggers.load_threshold` remains an absolute load threshold
and takes precedence over the ratio, preserving existing configurations. Omitting
the absolute threshold or setting it to `null` selects the ratio. The legacy
`sustained_load.threshold_multiplier` format below also selects a per-CPU ratio.

Missing, zero, or invalid capacity cannot become a guessed one-CPU observation.
Missing or non-finite/negative load cannot become zero activity. Such a reading
breaks the consecutive-breach sequence, preserves the last observed load EWMA,
and skips the load trigger. Other trigger types still run. Trigger state records
`load_unavailable_reason`, and `load_evidence_unavailable` audit events report
new or changed failures without repeating the same failure every tick. An
explicit absolute threshold needs no CPU count, but still requires a valid load
observation; when a pressure snapshot exists, its missing load is never replaced
with a scalar fallback.

Fired load triggers report `current_value`, `ewma_value`, and the effective
`threshold` in raw load-average units. The description also includes the observed
CPU count and per-CPU ratio when capacity normalization is active.

### Daemon-Specific Config

`~/.config/process_triage/daemon.json`:

```json
{
  "enabled": true,
  "collection_interval_seconds": 30,
  "triggers": {
    "sustained_load": {
      "enabled": true,
      "threshold_multiplier": 2.0,
      "min_duration_seconds": 300
    },
    "memory_pressure": {
      "enabled": true,
      "threshold_percent": 10,
      "min_duration_seconds": 180
    },
    "psi_stall": {
      "enabled": true,
      "threshold_percent": 25,
      "min_duration_seconds": 120
    },
    "orphan_spike": {
      "enabled": true,
      "threshold_delta": 10,
      "window_seconds": 300
    }
  },
  "cooldown": {
    "after_alert_seconds": 300,
    "after_escalation_seconds": 3600,
    "after_manual_run_seconds": 7200
  },
  "notifications": {
    "desktop": true,
    "terminal_bell": true,
    "webhook_url": null,
    "email": null
  },
  "auto_mitigate": {
    "enabled": false,
    "allowed_actions": []
  },
  "overhead_budget": {
    "max_cpu_percent": 0.1,
    "max_memory_mb": 10,
    "max_io_bytes_per_sec": 1024
  }
}
```

---

## Telemetry

### Daemon-Specific Events

| Event | Fields | Purpose |
|-------|--------|---------|
| `daemon_started` | version, config_hash | Track daemon lifecycle |
| `daemon_sample` | signals, duration_us | Monitor collection overhead |
| `daemon_trigger` | trigger_type, value, threshold | Audit trigger decisions |
| `daemon_alert` | session_id, candidates | Track alert rate |
| `daemon_escalation` | session_id, plan_summary | Track escalation rate |
| `daemon_budget_breach` | resource, actual, budget | Debug overhead issues |
| `daemon_cooldown` | reason, duration | Track idle periods |
| `daemon_shutdown` | reason, uptime | Track daemon stability |

---

## CLI Interface

### Daemon Management Commands

```bash
# Start daemon (usually via systemd/launchd)
# Default behavior is foreground when no subcommand is provided.
pt-core daemon

# Background start (default for explicit start)
pt-core daemon start

# Foreground start (explicit)
pt-core daemon start --foreground

# Check daemon status
pt-core daemon status

# View daemon logs (planned)
# pt-core daemon logs --tail 100

# Stop daemon gracefully
pt-core daemon stop

# Force immediate scan (planned, for testing)
# pt-core daemon trigger --type manual

# Configure daemon (planned)
# pt-core daemon config --set collection_interval_seconds=60
```

### Inbox Commands

```bash
# List pending daemon sessions
pt agent inbox
pt-core agent inbox

# Show only unread items
pt agent inbox --unread

# Acknowledge or dismiss an item
pt agent inbox --ack <item_id>

# Clear acknowledged items
pt agent inbox --clear

# Clear all items, including unacknowledged
pt agent inbox --clear-all
```

---

## Implementation Checklist

- [ ] Core daemon loop with signal collection
- [ ] EWMA trigger detection
- [ ] Lock coordination with manual/agent runs
- [ ] Inbox session management
- [ ] systemd user service integration
- [ ] launchd agent integration
- [ ] Desktop notification support
- [ ] Overhead budget enforcement
- [ ] Self-watchdog and termination
- [ ] Telemetry event emission
- [ ] CLI commands (status, logs, stop, trigger)
- [ ] Tests: trigger detection accuracy
- [ ] Tests: lock coordination edge cases
- [ ] Tests: overhead budget compliance
- [ ] Docs: User guide for daemon setup
