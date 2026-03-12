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
| Orphan count | PIDs with PPID=1 (sampled) | ~100 syscalls |

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
    orphan_count_estimate: u32,
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

**Service Unit**: `~/.config/systemd/user/ptd.service`

```ini
[Unit]
Description=Process Triage Dormant Daemon
Documentation=man:ptd(1)
After=default.target

[Service]
Type=simple
ExecStart=/usr/local/bin/pt-core daemon
Restart=on-failure
RestartSec=30
Nice=19
IOSchedulingClass=idle
MemoryMax=50M
CPUQuota=5%

# Watchdog: daemon must respond within 60s
WatchdogSec=60

# Environment
Environment=PT_DAEMON_MODE=1

[Install]
WantedBy=default.target
```

**Timer Unit** (alternative to always-running): `~/.config/systemd/user/ptd.timer`

```ini
[Unit]
Description=Process Triage periodic check

[Timer]
OnBootSec=5min
OnUnitActiveSec=1min
AccuracySec=10s

[Install]
WantedBy=timers.target
```

**Commands**:
```bash
# Enable and start
systemctl --user enable ptd.service
systemctl --user start ptd.service

# Check status
systemctl --user status ptd.service

# View logs
journalctl --user -u ptd.service -f
```

### macOS: launchd Agent

**Plist**: `~/Library/LaunchAgents/com.processtriage.ptd.plist`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.processtriage.ptd</string>

    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/pt-core</string>
        <string>daemon</string>
    </array>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>

    <key>Nice</key>
    <integer>19</integer>

    <key>LowPriorityIO</key>
    <true/>

    <key>ProcessType</key>
    <string>Background</string>

    <key>StandardOutPath</key>
    <string>/tmp/ptd.out.log</string>

    <key>StandardErrorPath</key>
    <string>/tmp/ptd.err.log</string>

    <key>EnvironmentVariables</key>
    <dict>
        <key>PT_DAEMON_MODE</key>
        <string>1</string>
    </dict>
</dict>
</plist>
```

**Commands**:
```bash
# Load and start
launchctl load ~/Library/LaunchAgents/com.processtriage.ptd.plist

# Unload
launchctl unload ~/Library/LaunchAgents/com.processtriage.ptd.plist

# Check status
launchctl list | grep processtriage
```

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
