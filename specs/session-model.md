# Session Model and Artifact Directory Specification

**Version**: 1.0.0
**Status**: Draft
**Bead**: process_triage-qje

---

## 1. Overview

Every pt operation creates a **session** - a durable unit of work with a unique identity, structured artifacts, and defined lifecycle. Sessions enable:

1. **Auditability**: Full trace of what was scanned, computed, and decided
2. **Resumability**: Interrupted operations can continue from checkpoints
3. **Reproducibility**: Artifacts contain enough context to replay decisions
4. **Learning**: Historical sessions inform Bayesian priors
5. **Collaboration**: Sessions can be bundled and shared

---

## 2. Session Identity

### 2.1 Session ID Format

Session IDs follow a structured format for human-readability, sortability, and uniqueness:

```
pt-YYYYMMDD-HHMMSS-XXXX
```

| Component | Description | Example |
|-----------|-------------|---------|
| `pt` | Fixed prefix for namespace | `pt` |
| `YYYYMMDD` | Date in UTC | `20260115` |
| `HHMMSS` | Time in UTC | `143022` |
| `XXXX` | Random suffix (base32 lowercase, 4 chars) | `a7xq` |

**Example**: `pt-20260115-143022-a7xq`

### 2.2 Session ID Properties

| Property | Requirement | Rationale |
|----------|-------------|-----------|
| **URL-safe** | `[a-z0-9-]` only | Can be used in paths, URLs, filenames |
| **Time-sortable** | Lexicographic sort = chronological | Directory listings show recent first |
| **Globally unique** | 4-char random suffix | ~1M sessions before collision risk |
| **Fixed length** | Always 23 characters | Predictable column widths |
| **Human-readable** | Date/time extractable | Operators can identify sessions visually |

### 2.3 Session ID Generation

```rust
fn generate_session_id() -> String {
    let now = Utc::now();
    let date = now.format("%Y%m%d");
    let time = now.format("%H%M%S");
    let suffix = generate_base32_random(4);  // e.g., "a7xq"
    format!("pt-{}-{}-{}", date, time, suffix)
}
```

**Base32 alphabet**: `abcdefghijklmnopqrstuvwxyz234567` (RFC 4648, lowercase)

### 2.4 Session ID Validation Regex

```regex
^pt-[0-9]{8}-[0-9]{6}-[a-z2-7]{4}$
```

---

## 3. Directory Layout

### 3.1 Root Location

Sessions are stored under the XDG data directory:

```
$XDG_DATA_HOME/process_triage/sessions/<session_id>/
```

Default: `~/.local/share/process_triage/sessions/`

Override: `$PROCESS_TRIAGE_DATA/sessions/`

### 3.2 Session Directory Structure

```
~/.local/share/process_triage/sessions/
└── pt-20260115-143022-a7xq/
    ├── manifest.json         # Session metadata and state
    ├── context.json          # System context at session start
    ├── capabilities.json     # Capabilities manifest (from wrapper)
    │
    ├── scan/                  # Evidence collection phase
    │   ├── quick.jsonl       # Quick scan samples
    │   ├── deep.jsonl        # Deep scan samples (if applicable)
    │   ├── features.parquet  # Derived feature matrix
    │   └── probes/           # Raw probe outputs
    │       ├── ps.txt
    │       ├── lsof.jsonl
    │       └── ...
    │
    ├── inference/            # Inference phase
    │   ├── posteriors.parquet  # P(class|evidence) for each process
    │   ├── ledger.jsonl        # Evidence ledger (audit trail)
    │   └── bayes_factors.json  # Per-process Bayes factors
    │
    ├── decision/             # Decision phase
    │   ├── plan.json         # Action plan
    │   ├── plan.md           # Human-readable plan
    │   └── safety_gates.json # Safety gate evaluations
    │
    ├── action/               # Execution phase
    │   ├── outcomes.jsonl    # What actually happened
    │   ├── verifications.json # TOCTOU checks
    │   └── errors.jsonl      # Any execution errors
    │
    ├── telemetry/            # Telemetry partitions
    │   ├── runs.parquet
    │   ├── proc_samples.parquet
    │   └── decisions.parquet
    │
    ├── logs/                 # Diagnostic logs
    │   ├── session.jsonl     # Structured log
    │   └── session.log       # Human-readable log
    │
    └── exports/              # Generated outputs
        ├── report.html       # Single-file HTML report
        └── bundle.ptb        # Exportable bundle (if created)
```

### 3.3 File Purposes

| File | Purpose | Format | When Created |
|------|---------|--------|--------------|
| `manifest.json` | Session metadata, state, timestamps | JSON | Session start |
| `context.json` | System state: load, memory, user, host | JSON | Session start |
| `capabilities.json` | Copy of capabilities manifest | JSON | Session start |
| `scan/quick.jsonl` | Process samples from quick scan | JSONL | During quick scan |
| `scan/deep.jsonl` | Deep scan evidence | JSONL | During deep scan |
| `scan/features.parquet` | Feature matrix (columnar) | Parquet | After feature extraction |
| `scan/provenance.json` | Persisted provenance graph snapshot for replay | JSON | After provenance capture |
| `scan/provenance_audit.json` | Audit sidecar describing persisted/redacted/omitted provenance sections | JSON | When provenance is persisted |
| `scan/probes/` | Raw output from diagnostic tools | Various | During collection |
| `inference/posteriors.parquet` | Posterior probabilities | Parquet | After inference |
| `inference/ledger.jsonl` | Evidence chain for each process | JSONL | During inference |
| `inference/bayes_factors.json` | Summary Bayes factors | JSON | After inference |
| `decision/plan.json` | Structured action plan | JSON | After decision |
| `decision/plan.md` | Markdown action plan | Markdown | After decision |
| `decision/safety_gates.json` | Safety evaluation results | JSON | During decision |
| `action/outcomes.jsonl` | What happened (killed, spared, etc.) | JSONL | During action |
| `action/verifications.json` | TOCTOU verification results | JSON | During action |
| `action/errors.jsonl` | Action execution errors | JSONL | During action |
| `telemetry/*.parquet` | Structured telemetry | Parquet | Throughout session |
| `logs/session.jsonl` | Structured event log | JSONL | Throughout session |
| `logs/session.log` | Human-readable log | Text | Throughout session |
| `exports/report.html` | Generated HTML report | HTML | On demand |
| `exports/bundle.ptb` | Shareable bundle | ZIP | On demand |

---

## 4. Session Lifecycle

### 4.1 State Machine

Sessions progress through defined states:

```
                    ┌──────────────────────────────────────────────┐
                    │                                              │
                    ▼                                              │
┌─────────┐     ┌─────────┐     ┌─────────┐     ┌─────────────┐   │
│ created │────▶│scanning │────▶│ planned │────▶│  executing  │   │
└─────────┘     └─────────┘     └─────────┘     └─────────────┘   │
                    │                │                  │          │
                    │                │                  │          │
                    ▼                ▼                  ▼          │
               ┌─────────┐     ┌─────────┐     ┌─────────────┐    │
               │  failed │     │cancelled│     │  completed  │────┘
               └─────────┘     └─────────┘     └─────────────┘  (new session
                                                                for resume)
                    │                │
                    │                │
                    ▼                ▼
               ┌─────────────────────────┐
               │  archived (read-only)   │
               └─────────────────────────┘
```

### 4.2 State Definitions

| State | Description | Artifacts Present |
|-------|-------------|-------------------|
| `created` | Session initialized, no work done | `manifest.json`, `context.json` |
| `scanning` | Evidence collection in progress | `scan/` being populated |
| `planned` | Plan generated, awaiting user action | `decision/plan.json` exists |
| `executing` | Actions being executed | `action/outcomes.jsonl` being populated |
| `completed` | All actions finished successfully | `action/outcomes.jsonl` finalized |
| `cancelled` | User cancelled (Ctrl+C, explicit cancel) | Partial artifacts |
| `failed` | Unrecoverable error during operation | Error logged in `manifest.json` |
| `archived` | Session past retention, read-only | All artifacts, marked non-writable |

### 4.3 State Transitions

| From | To | Trigger |
|------|----|---------|
| `created` | `scanning` | Scan begins |
| `scanning` | `planned` | Inference and planning complete |
| `scanning` | `failed` | Unrecoverable scan error |
| `scanning` | `cancelled` | User cancellation |
| `planned` | `executing` | User confirms plan execution |
| `planned` | `cancelled` | User declines plan |
| `planned` | `completed` | User chooses "spare all" (no actions) |
| `executing` | `completed` | All actions succeed |
| `executing` | `completed` | All actions finish (some may have failed) |
| `executing` | `failed` | Critical execution failure |
| `*` | `archived` | Retention period expires |

### 4.4 Resumability

Sessions in certain states can be **resumed**:

| State | Resumable? | Resume Behavior |
|-------|------------|-----------------|
| `created` | Yes | Start fresh scan |
| `scanning` | Yes | Continue from last checkpoint |
| `planned` | Yes | Re-show plan, allow action |
| `executing` | Yes | Skip completed actions, continue |
| `completed` | No | Start new session |
| `cancelled` | Yes | Create new session with context |
| `failed` | No | Start new session |
| `archived` | No | Read-only |

Resume creates a **child session** that references the parent:

```json
{
  "session_id": "pt-20260115-150000-b2yq",
  "parent_session_id": "pt-20260115-143022-a7xq",
  "resume_reason": "user requested continuation"
}
```

---

## 5. Manifest Schema

### 5.1 manifest.json Structure

```json
{
  "schema_version": "1.0.0",
  "session_id": "pt-20260115-143022-a7xq",
  "parent_session_id": null,

  "state": "completed",
  "state_history": [
    {"state": "created", "ts": "2026-01-15T14:30:22Z"},
    {"state": "scanning", "ts": "2026-01-15T14:30:23Z"},
    {"state": "planned", "ts": "2026-01-15T14:30:45Z"},
    {"state": "executing", "ts": "2026-01-15T14:31:02Z"},
    {"state": "completed", "ts": "2026-01-15T14:31:15Z"}
  ],

  "mode": "interactive",
  "deep_scan": true,

  "initiated_by": {
    "type": "user",
    "uid": 1000,
    "username": "developer"
  },

  "timing": {
    "created_at": "2026-01-15T14:30:22Z",
    "completed_at": "2026-01-15T14:31:15Z",
    "duration_ms": 53000
  },

  "summary": {
    "processes_scanned": 412,
    "candidates_found": 7,
    "actions_planned": 3,
    "actions_executed": 3,
    "kills_successful": 2,
    "kills_failed": 0,
    "spares": 4
  },

  "artifacts": {
    "scan_quick": true,
    "scan_deep": true,
    "features": true,
    "posteriors": true,
    "ledger": true,
    "plan": true,
    "outcomes": true,
    "report": false,
    "bundle": false
  },

  "error": null,

  "retention": {
    "policy": "default",
    "expires_at": "2026-01-22T14:30:22Z",
    "preserve_for_priors": true
  },

  "checksums": {
    "plan.json": "sha256:abcd1234...",
    "outcomes.jsonl": "sha256:efgh5678..."
  },

  "pt_version": "2.0.0",
  "pt_core_version": "2.0.0"
}
```

### 5.2 Manifest Updates

The manifest is updated at each state transition:

1. **Atomic writes**: Write to temp file, then rename
2. **Append-only state_history**: Never remove entries
3. **Checksums**: Updated when critical files are finalized
4. **Timestamps**: Always in UTC ISO 8601

---

## 6. Session Modes

### 6.1 Mode Types

| Mode | Description | Typical Artifacts |
|------|-------------|-------------------|
| `interactive` | Human-driven TUI session | All artifacts |
| `robot_plan` | Agent: plan-only, no execution | Scan + inference + plan |
| `robot_apply` | Agent: execution from explicit PIDs | Minimal scan + actions |
| `daemon_alert` | Dormant daemon triggered session | Scan + plan (no auto-exec) |
| `scan_only` | View-only scan, no planning | Scan artifacts only |
| `export` | Bundle/report generation from existing | Exports only |

### 6.2 Mode-Specific Artifacts

```
Mode              scan/  inference/  decision/  action/  telemetry/
─────────────────────────────────────────────────────────────────────
interactive       ✓      ✓           ✓          ✓        ✓
robot_plan        ✓      ✓           ✓          ✗        ✓
robot_apply       ✓      ✓           ✓          ✓        ✓
daemon_alert      ✓      ✓           ✓          ✗        ✓
scan_only         ✓      ✗           ✗          ✗        ✓
export            ✗      ✗           ✗          ✗        ✗
```

---

## 7. Retention Policy

### 7.1 Default Retention

| Session State | Default Retention | Rationale |
|---------------|-------------------|-----------|
| `completed` | 7 days | Keep recent history |
| `cancelled` | 1 day | Limited value |
| `failed` | 3 days | Debug window |
| `archived` | Indefinite (read-only) | Explicitly preserved |

### 7.2 Retention Configuration

```json
{
  "retention": {
    "default_days": 7,
    "cancelled_days": 1,
    "failed_days": 3,
    "max_sessions": 100,
    "max_disk_mb": 1024,
    "preserve_actions": true
  }
}
```

### 7.3 Cleanup Semantics

When sessions are cleaned up:

1. **Telemetry preserved**: Aggregated into main telemetry lake
2. **Decisions preserved**: Kill/spare patterns merged to priors
3. **Outcomes preserved**: Action logs archived for audit
4. **Session directory removed**: All other artifacts deleted

**Preserved data** (migrated before deletion):

```
session/telemetry/*.parquet → ~/.local/share/process_triage/telemetry/
session/action/outcomes.jsonl → ~/.local/share/process_triage/audit/
session/inference/ledger.jsonl → (extracted patterns only)
```

### 7.4 Cleanup Command

```bash
# Preview cleanup
pt-core sessions cleanup --dry-run

# Execute cleanup
pt-core sessions cleanup

# Force cleanup (ignore retention)
pt-core sessions cleanup --force --older-than 1d

# Preserve specific session
pt-core sessions preserve pt-20260115-143022-a7xq --reason "important case"
```

---

## 8. Session Index

### 8.1 Index File

A lightweight index enables fast session enumeration without scanning directories:

```
~/.local/share/process_triage/sessions/index.jsonl
```

**Format** (append-only JSONL):

```json
{"session_id":"pt-20260115-143022-a7xq","state":"completed","mode":"interactive","created_at":"2026-01-15T14:30:22Z","candidates":7,"actions":3}
{"session_id":"pt-20260115-150000-b2yq","state":"planned","mode":"robot_plan","created_at":"2026-01-15T15:00:00Z","candidates":12,"actions":0}
```

### 8.2 Index Operations

| Operation | Complexity | Description |
|-----------|------------|-------------|
| List recent | O(1) | Tail index file |
| Find by ID | O(log n) | Binary search (sorted by time) |
| Filter by state | O(n) | Scan index |
| Full rebuild | O(n) | Scan session directories |

### 8.3 Index Maintenance

- **Auto-rebuild**: If index missing or corrupt, rebuild from directories
- **Compaction**: Periodically remove entries for deleted sessions
- **Atomic updates**: Append to temp, then rename

---

## 9. Locking and Concurrency

### 9.1 Session Lock

Each active session holds an exclusive lock:

```
~/.local/share/process_triage/sessions/<session_id>/.lock
```

**Lock semantics**:
- `flock(LOCK_EX | LOCK_NB)` - non-blocking exclusive
- Held for session duration
- Released on normal exit or crash (kernel releases)

### 9.2 Global Lock

A global lock prevents concurrent pt invocations from conflicting:

```
~/.local/share/process_triage/.pt-lock
```

**Behavior**:
- Quick scan: Shared lock (multiple readers OK)
- Deep scan / action: Exclusive lock
- Lock timeout: 30 seconds with advisory message

### 9.3 Concurrent Access

| Operation | Lock Type | Concurrent Access |
|-----------|-----------|-------------------|
| `pt scan` | Shared | Multiple scans OK |
| `pt deep` | Exclusive | Single instance |
| `pt agent plan` | Shared | Multiple plans OK |
| `pt agent apply` | Exclusive | Single instance |
| `pt daemon` | Exclusive | Single daemon |
| `pt sessions list` | None | Always allowed |
| `pt bundle` | Session-specific | Isolated to session |

---

## 10. Error Handling

### 10.1 Session Creation Failures

| Failure | Behavior |
|---------|----------|
| Disk full | Exit code 1, no session created |
| Permission denied | Exit code 4, no session created |
| Invalid session dir | Exit code 1, cleanup partial |

### 10.2 Mid-Session Failures

| Failure | Session State | Recovery |
|---------|---------------|----------|
| Scan tool timeout | `failed` | Retry with longer timeout |
| Inference error | `failed` | Check input data |
| Action partial fail | `completed` | Review outcomes.jsonl |
| Ctrl+C during scan | `cancelled` | Resume supported |
| Ctrl+C during action | `executing` | Resume skips completed |
| Crash | `scanning`/`executing` | Lock released, resume supported |

### 10.3 Error Recording

Errors are recorded in `manifest.json`:

```json
{
  "error": {
    "type": "scan_timeout",
    "message": "lsof timed out after 30s",
    "timestamp": "2026-01-15T14:30:30Z",
    "recoverable": true,
    "context": {
      "tool": "lsof",
      "timeout_ms": 30000,
      "pid_count": 2500
    }
  }
}
```

---

## 11. Session Queries

### 11.1 List Sessions

```bash
# List all sessions
pt-core sessions list

# Filter by state
pt-core sessions list --state=completed

# Filter by time
pt-core sessions list --since=2026-01-14 --until=2026-01-16

# Filter by mode
pt-core sessions list --mode=interactive

# JSON output for agents
pt-core sessions list --format=json
```

### 11.2 Session Details

```bash
# Show session summary
pt-core sessions show pt-20260115-143022-a7xq

# Show specific artifact
pt-core sessions show pt-20260115-143022-a7xq --artifact=plan

# Show state history
pt-core sessions show pt-20260115-143022-a7xq --history
```

### 11.3 Session Diff

```bash
# Compare two sessions
pt-core sessions diff pt-20260115-143022-a7xq pt-20260115-150000-b2yq

# Diff with previous session
pt-core sessions diff pt-20260115-143022-a7xq --prev
```

---

## 12. Integration with Other Components

### 12.1 Telemetry Lake

Session telemetry is partitioned and merged into the global lake:

```
sessions/<session_id>/telemetry/  →  telemetry/
                                      ├── runs/year=2026/month=01/day=15/
                                      ├── proc_samples/year=2026/month=01/day=15/
                                      └── decisions/year=2026/month=01/day=15/
```

### 12.2 Bundle Export

Sessions can be exported as `.ptb` bundles:

```bash
pt-core bundle create --session=pt-20260115-143022-a7xq --output=case-123.ptb
```

Bundle contains:
- All session artifacts (excluding raw probe output by default)
- Manifest with checksums
- Redacted per policy

### 12.3 Report Generation

```bash
pt-core report --session=pt-20260115-143022-a7xq --output=report.html
```

Report is written to `exports/report.html` within session.

### 12.4 Daemon Sessions

Dormant daemon creates sessions for alerts:

```json
{
  "mode": "daemon_alert",
  "initiated_by": {
    "type": "daemon",
    "daemon_session": "ptd-20260115-000000-xxxx",
    "trigger": "memory_pressure"
  }
}
```

---

## 13. Schema Evolution

### 13.1 Versioning Strategy

- `schema_version` in manifest enables forward compatibility
- Older readers ignore unknown fields
- Breaking changes increment major version
- Migration scripts provided for major upgrades

### 13.2 Backward Compatibility

| Manifest Version | pt-core 2.x | pt-core 3.x |
|------------------|-------------|-------------|
| 1.0.x | Full support | Full support + migration |
| 2.0.x | Unsupported | Full support |

---

## 14. Security Considerations

### 14.1 Sensitive Data

Sessions may contain sensitive information:
- Process command lines (may include secrets)
- File paths
- User/host identifiers

**Mitigations**:
- Redaction policy applied to all persistent artifacts
- Bundle export respects redaction settings
- Report generation applies additional sanitization

### 14.2 Access Control

Session directories use restrictive permissions:

```bash
~/.local/share/process_triage/sessions/  # drwx------
~/.local/share/process_triage/sessions/pt-.../  # drwx------
```

---

## 15. References

- PLAN: §3.0 Execution & Packaging Architecture
- PLAN: §3.1.7 Session Model
- Bead: process_triage-4r8 (Telemetry Schema)
- Bead: process_triage-k4yc.3 (Bundle Specification)
- Bead: process_triage-8n3 (Redaction Policy)
