# Telemetry Schema and Partitioning Specification

**Version**: 1.0.0
**Status**: Draft
**Bead**: process_triage-4r8

---

## 1. Overview

Process Triage maintains a structured telemetry lake for:

1. **Calibration**: Measuring prediction accuracy over time
2. **Learning**: Informing Bayesian priors from historical data
3. **Audit**: Tracking all decisions and outcomes
4. **Analysis**: Enabling cross-session pattern discovery
5. **Fleet aggregation**: Supporting multi-host deployments

**Storage format**: Apache Parquet (columnar, compressed)
**Query engine**: DuckDB (embedded, zero-copy reads)
**Compression**: zstd (default), snappy (fallback)

---

## 2. Directory Layout

### 2.1 Telemetry Lake Structure

```
~/.local/share/process_triage/telemetry/
├── runs/
│   └── year=2026/month=01/day=15/
│       └── host_id=<hash>/
│           └── runs_<timestamp>.parquet
├── proc_samples/
│   └── year=2026/month=01/day=15/
│       └── host_id=<hash>/
│           └── samples_<timestamp>.parquet
├── proc_features/
│   └── year=2026/month=01/day=15/
│       └── host_id=<hash>/
│           └── features_<timestamp>.parquet
├── proc_inference/
│   └── year=2026/month=01/day=15/
│       └── host_id=<hash>/
│           └── inference_<timestamp>.parquet
├── outcomes/
│   └── year=2026/month=01/day=15/
│       └── host_id=<hash>/
│           └── outcomes_<timestamp>.parquet
├── audit/
│   └── year=2026/month=01/day=15/
│       └── audit_<timestamp>.parquet
└── _metadata/
    ├── schema_version.json
    └── host_info.json
```

### 2.2 Partitioning Strategy

| Partition Level | Key | Purpose |
|-----------------|-----|---------|
| **Level 1** | `year=YYYY` | Annual archives |
| **Level 2** | `month=MM` | Monthly rollups |
| **Level 3** | `day=DD` | Daily partitions |
| **Level 4** | `host_id=<hash>` | Fleet aggregation |

**host_id**: SHA-256 truncated hash of `<hostname>:<machine-id>`

### 2.3 File Naming

```
<table>_<timestamp>_<session_suffix>.parquet
```

Example: `runs_20260115T143022Z_a7xq.parquet`

---

## 3. Schema Definitions

### 3.1 runs Table

Records metadata for each pt session.

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `session_id` | `STRING` | No | Session identifier (e.g., pt-20260115-143022-a7xq) |
| `host_id` | `STRING` | No | Hashed host identifier |
| `hostname` | `STRING` | Yes | Hostname (may be redacted) |
| `username` | `STRING` | Yes | Username (may be redacted) |
| `uid` | `INT32` | Yes | Unix UID |
| `mode` | `STRING` | No | Session mode (interactive, robot_plan, etc.) |
| `deep_scan` | `BOOLEAN` | No | Whether deep scan was enabled |
| `started_at` | `TIMESTAMP_MICROS` | No | Session start time (UTC) |
| `ended_at` | `TIMESTAMP_MICROS` | Yes | Session end time (UTC) |
| `duration_ms` | `INT64` | Yes | Total duration in milliseconds |
| `state` | `STRING` | No | Final session state |
| `processes_scanned` | `INT32` | No | Total processes examined |
| `candidates_found` | `INT32` | No | Processes flagged as candidates |
| `kills_attempted` | `INT32` | No | Kill actions attempted |
| `kills_successful` | `INT32` | No | Kill actions that succeeded |
| `spares` | `INT32` | No | Processes explicitly spared |
| `pt_version` | `STRING` | No | pt wrapper version |
| `pt_core_version` | `STRING` | No | pt-core binary version |
| `schema_version` | `STRING` | No | Telemetry schema version |
| `capabilities_hash` | `STRING` | Yes | Hash of capabilities manifest |
| `config_snapshot` | `STRING` | Yes | JSON string of active config |
| `os_family` | `STRING` | No | Operating system family |
| `os_version` | `STRING` | Yes | OS version string |
| `kernel_version` | `STRING` | Yes | Kernel version |
| `arch` | `STRING` | No | CPU architecture |
| `cores` | `INT16` | Yes | Number of CPU cores |
| `memory_bytes` | `INT64` | Yes | Total system memory |

**Parquet metadata**:
- Row group size: 64KB
- Compression: zstd level 3
- Dictionary encoding: session_id, mode, state, os_family, arch

### 3.2 proc_samples Table

Raw per-process measurements from each scan.

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `session_id` | `STRING` | No | Session identifier |
| `sample_ts` | `TIMESTAMP_MICROS` | No | Sample timestamp (UTC) |
| `sample_seq` | `INT16` | No | Sample sequence within session (0, 1, 2...) |
| `pid` | `INT32` | No | Process ID |
| `ppid` | `INT32` | No | Parent process ID |
| `pgid` | `INT32` | Yes | Process group ID |
| `sid` | `INT32` | Yes | Session ID (POSIX) |
| `uid` | `INT32` | No | Owner UID |
| `euid` | `INT32` | Yes | Effective UID |
| `start_time_boot` | `INT64` | No | Start time in clock ticks since boot |
| `start_id` | `STRING` | No | Stable identity: `<boot_id>:<start_time>:<pid>` |
| `age_s` | `INT64` | No | Process age in seconds |
| `cmd` | `STRING` | No | Command name (comm) |
| `cmdline` | `STRING` | Yes | Full command line (may be redacted) |
| `cmdline_hash` | `STRING` | Yes | SHA-256 of original cmdline |
| `exe` | `STRING` | Yes | Executable path |
| `cwd` | `STRING` | Yes | Current working directory |
| `tty` | `STRING` | Yes | Controlling TTY |
| `state` | `STRING` | No | Process state (R/S/D/Z/T) |
| `utime_ticks` | `INT64` | No | User CPU ticks |
| `stime_ticks` | `INT64` | No | System CPU ticks |
| `cutime_ticks` | `INT64` | Yes | Children user ticks |
| `cstime_ticks` | `INT64` | Yes | Children system ticks |
| `rss_bytes` | `INT64` | No | Resident set size |
| `vsize_bytes` | `INT64` | Yes | Virtual memory size |
| `shared_bytes` | `INT64` | Yes | Shared memory |
| `text_bytes` | `INT64` | Yes | Text (code) size |
| `data_bytes` | `INT64` | Yes | Data + stack size |
| `nice` | `INT8` | Yes | Nice value |
| `priority` | `INT16` | Yes | Static priority |
| `num_threads` | `INT16` | Yes | Thread count |
| `cpu_percent` | `FLOAT` | Yes | CPU percentage (0-100 per core) |
| `mem_percent` | `FLOAT` | Yes | Memory percentage |
| `io_read_bytes` | `INT64` | Yes | Total bytes read |
| `io_write_bytes` | `INT64` | Yes | Total bytes written |
| `io_read_ops` | `INT64` | Yes | Read syscall count |
| `io_write_ops` | `INT64` | Yes | Write syscall count |
| `voluntary_ctxt_switches` | `INT64` | Yes | Voluntary context switches |
| `nonvoluntary_ctxt_switches` | `INT64` | Yes | Involuntary context switches |
| `wchan` | `STRING` | Yes | Wait channel |
| `oom_score` | `INT16` | Yes | OOM killer score |
| `oom_score_adj` | `INT16` | Yes | OOM score adjustment |
| `cgroup_path` | `STRING` | Yes | Cgroup path |
| `systemd_unit` | `STRING` | Yes | Systemd unit name |
| `container_id` | `STRING` | Yes | Container ID if containerized |
| `ns_pid` | `INT64` | Yes | PID namespace inode |
| `ns_mnt` | `INT64` | Yes | Mount namespace inode |
| `fd_count` | `INT16` | Yes | Open file descriptor count |
| `tcp_listen_count` | `INT16` | Yes | TCP listening sockets |
| `tcp_estab_count` | `INT16` | Yes | Established TCP connections |
| `child_count` | `INT16` | Yes | Direct child process count |

**Parquet metadata**:
- Row group size: 1MB
- Compression: zstd level 3
- Dictionary encoding: session_id, cmd, state, tty, wchan, systemd_unit
- Sorting: session_id, sample_seq, pid

### 3.3 proc_features Table

Derived features computed from raw samples.

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `session_id` | `STRING` | No | Session identifier |
| `pid` | `INT32` | No | Process ID |
| `start_id` | `STRING` | No | Stable process identity |
| `feature_ts` | `TIMESTAMP_MICROS` | No | Feature computation timestamp |
| | | | |
| **Type Classification** | | | |
| `proc_type` | `STRING` | No | Classified type (test, dev_server, agent, etc.) |
| `proc_type_conf` | `FLOAT` | No | Type classification confidence (0-1) |
| | | | |
| **Age Features** | | | |
| `age_s` | `INT64` | No | Process age in seconds |
| `age_ratio` | `FLOAT` | No | age / expected_lifetime for type |
| `age_bucket` | `STRING` | No | Age bucket (1h, 6h, 1d, 3d, 7d, 14d, 30d) |
| | | | |
| **CPU Features** | | | |
| `cpu_pct_instant` | `FLOAT` | No | Instantaneous CPU % |
| `cpu_pct_avg` | `FLOAT` | Yes | Average CPU % over samples |
| `cpu_delta_ticks` | `INT64` | Yes | CPU tick change between samples |
| `cpu_utilization` | `FLOAT` | Yes | Effective utilization (vs cores) |
| `cpu_stalled` | `BOOLEAN` | Yes | No CPU progress detected |
| `cpu_spinning` | `BOOLEAN` | Yes | High CPU, no progress |
| | | | |
| **Memory Features** | | | |
| `mem_mb` | `FLOAT` | No | RSS in megabytes |
| `mem_pct` | `FLOAT` | No | Memory percentage |
| `mem_growth_rate` | `FLOAT` | Yes | Bytes/second growth |
| `mem_bucket` | `STRING` | No | Memory bucket (tiny, small, medium, large, huge) |
| | | | |
| **I/O Features** | | | |
| `io_read_rate` | `FLOAT` | Yes | Bytes/second read |
| `io_write_rate` | `FLOAT` | Yes | Bytes/second write |
| `io_active` | `BOOLEAN` | Yes | I/O activity detected |
| `io_idle` | `BOOLEAN` | Yes | No I/O activity |
| | | | |
| **State Features** | | | |
| `is_orphan` | `BOOLEAN` | No | PPID = 1 |
| `is_zombie` | `BOOLEAN` | No | State = Z |
| `is_stopped` | `BOOLEAN` | No | State = T |
| `is_sleeping` | `BOOLEAN` | No | State = S |
| `is_running` | `BOOLEAN` | No | State = R |
| | | | |
| **TTY Features** | | | |
| `has_tty` | `BOOLEAN` | No | Has controlling TTY |
| `tty_active` | `BOOLEAN` | Yes | TTY session is active |
| `tty_dead` | `BOOLEAN` | Yes | TTY session is dead |
| | | | |
| **Network Features** | | | |
| `has_network` | `BOOLEAN` | Yes | Has network connections |
| `is_listener` | `BOOLEAN` | Yes | Has listening sockets |
| | | | |
| **Children Features** | | | |
| `has_children` | `BOOLEAN` | No | Has child processes |
| `children_active` | `BOOLEAN` | Yes | Children have CPU activity |
| | | | |
| **Pattern Features** | | | |
| `cmd_pattern` | `STRING` | No | Normalized command pattern |
| `cmd_category` | `STRING` | No | Command category (test_runner, dev_server, etc.) |
| `is_protected` | `BOOLEAN` | No | Matches protected pattern |
| | | | |
| **Historical Features** | | | |
| `prior_decision` | `STRING` | Yes | Historical decision (kill/spare/unknown) |
| `prior_decision_count` | `INT32` | Yes | How many times pattern seen |

**Parquet metadata**:
- Row group size: 512KB
- Compression: zstd level 3
- Dictionary encoding: session_id, proc_type, age_bucket, mem_bucket, cmd_category

### 3.4 proc_inference Table

Inference results including posteriors and evidence.

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `session_id` | `STRING` | No | Session identifier |
| `pid` | `INT32` | No | Process ID |
| `start_id` | `STRING` | No | Stable process identity |
| `inference_ts` | `TIMESTAMP_MICROS` | No | Inference timestamp |
| | | | |
| **Posterior Probabilities** | | | |
| `p_abandoned` | `FLOAT` | No | P(abandoned | evidence) |
| `p_legitimate` | `FLOAT` | No | P(legitimate | evidence) |
| `p_uncertain` | `FLOAT` | No | P(uncertain | evidence) |
| | | | |
| **Bayesian Factors** | | | |
| `log_bayes_factor` | `FLOAT` | No | log(P(E|H1) / P(E|H0)) |
| `bayes_factor_interpretation` | `STRING` | No | strong_kill, moderate_kill, weak, moderate_spare, strong_spare |
| | | | |
| **Scores and Confidence** | | | |
| `score` | `FLOAT` | No | Aggregate score (0-100+) |
| `confidence` | `STRING` | No | high, medium, low |
| `recommendation` | `STRING` | No | KILL, REVIEW, SPARE |
| | | | |
| **Evidence Breakdown** | | | |
| `evidence_prior` | `FLOAT` | No | Prior contribution |
| `evidence_age` | `FLOAT` | No | Age evidence contribution |
| `evidence_cpu` | `FLOAT` | No | CPU evidence contribution |
| `evidence_memory` | `FLOAT` | No | Memory evidence contribution |
| `evidence_io` | `FLOAT` | No | I/O evidence contribution |
| `evidence_state` | `FLOAT` | No | State evidence contribution |
| `evidence_network` | `FLOAT` | No | Network evidence contribution |
| `evidence_children` | `FLOAT` | No | Children evidence contribution |
| `evidence_history` | `FLOAT` | No | Historical decision contribution |
| `evidence_deep` | `FLOAT` | Yes | Deep scan evidence (if applicable) |
| | | | |
| **Evidence Ledger** | | | |
| `evidence_tags` | `LIST<STRING>` | No | List of evidence tags (orphan, stuck, idle_io, etc.) |
| `evidence_ledger_json` | `STRING` | Yes | Full evidence ledger as JSON |
| | | | |
| **Safety Gates** | | | |
| `passed_safety_gates` | `BOOLEAN` | No | All safety gates passed |
| `blocked_by_gate` | `STRING` | Yes | Which gate blocked (if any) |
| `safety_gate_details` | `STRING` | Yes | Gate evaluation details JSON |

**Parquet metadata**:
- Row group size: 512KB
- Compression: zstd level 3
- Dictionary encoding: session_id, confidence, recommendation, bayes_factor_interpretation

### 3.5 outcomes Table

Records what actually happened to each process.

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `session_id` | `STRING` | No | Session identifier |
| `outcome_ts` | `TIMESTAMP_MICROS` | No | Outcome timestamp |
| `pid` | `INT32` | No | Process ID at decision time |
| `start_id` | `STRING` | No | Stable process identity |
| | | | |
| **Decision** | | | |
| `recommendation` | `STRING` | No | What was recommended |
| `decision` | `STRING` | No | What user decided (kill, spare, defer) |
| `decision_source` | `STRING` | No | user, auto, timeout, default |
| | | | |
| **Action** | | | |
| `action_type` | `STRING` | Yes | kill, spare, pause, resume |
| `action_attempted` | `BOOLEAN` | No | Was action attempted |
| `action_successful` | `BOOLEAN` | Yes | Did action succeed |
| `signal_sent` | `STRING` | Yes | TERM, KILL, STOP, CONT |
| `signal_response` | `STRING` | Yes | died, ignored, not_found |
| | | | |
| **Verification** | | | |
| `verified_identity` | `BOOLEAN` | Yes | TOCTOU check passed |
| `pid_at_action` | `INT32` | Yes | PID verified before action |
| `start_id_matched` | `BOOLEAN` | Yes | Start ID matched |
| | | | |
| **Result** | | | |
| `process_state_after` | `STRING` | Yes | Process state after action |
| `memory_freed_bytes` | `INT64` | Yes | Estimated memory freed |
| `error_message` | `STRING` | Yes | Error if action failed |
| | | | |
| **Feedback** | | | |
| `user_feedback` | `STRING` | Yes | correct, incorrect, unsure |
| `feedback_ts` | `TIMESTAMP_MICROS` | Yes | When feedback was given |
| `feedback_note` | `STRING` | Yes | User's note |
| | | | |
| **Context** | | | |
| `cmd` | `STRING` | No | Command name |
| `cmdline_hash` | `STRING` | Yes | Command line hash |
| `score` | `FLOAT` | No | Score at decision time |
| `proc_type` | `STRING` | No | Classified process type |

**Parquet metadata**:
- Row group size: 256KB
- Compression: zstd level 3
- Dictionary encoding: session_id, recommendation, decision, decision_source, action_type, signal_sent

### 3.6 audit Table

Audit trail for compliance and debugging.

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `audit_ts` | `TIMESTAMP_MICROS` | No | Event timestamp |
| `session_id` | `STRING` | No | Session identifier |
| `event_type` | `STRING` | No | Event type (scan_start, inference_complete, kill_sent, etc.) |
| `severity` | `STRING` | No | info, warning, error |
| `actor` | `STRING` | No | user, system, daemon |
| `target_pid` | `INT32` | Yes | Target PID if applicable |
| `target_start_id` | `STRING` | Yes | Target stable ID |
| `message` | `STRING` | No | Human-readable message |
| `details_json` | `STRING` | Yes | Additional details as JSON |
| `host_id` | `STRING` | No | Host identifier |

---

## 4. Schema Versioning

### 4.1 Version File

```
~/.local/share/process_triage/telemetry/_metadata/schema_version.json
```

```json
{
  "current_version": "1.0.0",
  "compatible_versions": ["1.0.0"],
  "upgrade_from": null,
  "last_checked": "2026-01-15T14:30:00Z"
}
```

### 4.2 Version Compatibility

| Schema Version | pt-core 2.x | pt-core 3.x |
|----------------|-------------|-------------|
| 1.0.x | Full support | Full support |
| 2.0.x | Read-only | Full support |

### 4.3 Schema Evolution Rules

1. **Additive changes** (minor version): New nullable columns
2. **Breaking changes** (major version): Column type changes, required columns
3. **Metadata preserved**: Old data readable with schema evolution

---

## 5. Retention Policy

### 5.1 Per-Table Retention

| Table | Default Retention | Rationale |
|-------|-------------------|-----------|
| `runs` | 90 days | Session history |
| `proc_samples` | 30 days | High volume |
| `proc_features` | 30 days | Derived data |
| `proc_inference` | 90 days | Learning data |
| `outcomes` | 365 days | Audit trail |
| `audit` | 365 days | Compliance |

### 5.2 Retention Configuration

```json
{
  "telemetry_retention": {
    "runs_days": 90,
    "proc_samples_days": 30,
    "proc_features_days": 30,
    "proc_inference_days": 90,
    "outcomes_days": 365,
    "audit_days": 365,
    "max_disk_gb": 10,
    "auto_compact": true
  }
}
```

### 5.3 Compaction

Periodic compaction merges small Parquet files:

```bash
pt-core telemetry compact --table=proc_samples --older-than=7d
```

---

## 6. DuckDB Integration

### 6.1 Virtual Database

DuckDB views provide unified access:

```sql
-- Auto-discovery of Parquet files
CREATE OR REPLACE VIEW runs AS
SELECT * FROM read_parquet('~/.local/share/process_triage/telemetry/runs/**/*.parquet', hive_partitioning=true);

CREATE OR REPLACE VIEW proc_samples AS
SELECT * FROM read_parquet('~/.local/share/process_triage/telemetry/proc_samples/**/*.parquet', hive_partitioning=true);

-- ... similar for other tables
```

### 6.2 Standard Queries

#### Calibration Curve
```sql
-- Predicted vs actual kill rates by score bucket
SELECT
    FLOOR(score / 10) * 10 AS score_bucket,
    COUNT(*) AS n,
    AVG(CASE WHEN decision = 'kill' THEN 1.0 ELSE 0.0 END) AS kill_rate,
    AVG(CASE WHEN action_successful THEN 1.0 ELSE 0.0 END) AS success_rate
FROM proc_inference i
JOIN outcomes o USING (session_id, pid)
GROUP BY 1
ORDER BY 1;
```

#### FDR Over Time
```sql
-- False discovery rate by week
SELECT
    DATE_TRUNC('week', outcome_ts) AS week,
    COUNT(*) AS total_kills,
    SUM(CASE WHEN user_feedback = 'incorrect' THEN 1 ELSE 0 END) AS false_discoveries,
    SUM(CASE WHEN user_feedback = 'incorrect' THEN 1 ELSE 0 END)::FLOAT / NULLIF(COUNT(*), 0) AS fdr
FROM outcomes
WHERE decision = 'kill' AND user_feedback IS NOT NULL
GROUP BY 1
ORDER BY 1;
```

#### Command Category Statistics
```sql
-- Kill/spare ratios by command category
SELECT
    cmd_category,
    COUNT(*) AS n,
    AVG(score) AS avg_score,
    SUM(CASE WHEN decision = 'kill' THEN 1 ELSE 0 END) AS kills,
    SUM(CASE WHEN decision = 'spare' THEN 1 ELSE 0 END) AS spares
FROM proc_features f
JOIN outcomes o USING (session_id, pid)
GROUP BY 1
ORDER BY n DESC;
```

### 6.3 Macros

```sql
-- Session summary macro
CREATE OR REPLACE MACRO session_summary(sid) AS TABLE
    SELECT
        r.session_id,
        r.mode,
        r.started_at,
        r.duration_ms,
        r.candidates_found,
        r.kills_successful,
        COUNT(DISTINCT o.pid) AS outcomes_recorded
    FROM runs r
    LEFT JOIN outcomes o ON r.session_id = o.session_id
    WHERE r.session_id = sid
    GROUP BY 1, 2, 3, 4, 5, 6;

-- Recent sessions
CREATE OR REPLACE MACRO recent_sessions(n) AS TABLE
    SELECT * FROM runs
    ORDER BY started_at DESC
    LIMIT n;
```

---

## 7. Write Patterns

### 7.1 Batched Writes

During a session, telemetry is buffered and written in batches:

```rust
struct TelemetryWriter {
    buffer: Vec<Row>,
    batch_size: usize,  // default: 1000 rows
    flush_interval: Duration,  // default: 30 seconds
}

impl TelemetryWriter {
    fn write(&mut self, row: Row) {
        self.buffer.push(row);
        if self.buffer.len() >= self.batch_size {
            self.flush();
        }
    }

    fn flush(&mut self) {
        // Write Parquet file
        // Clear buffer
    }
}
```

### 7.2 Crash Safety

- Each Parquet file is written atomically (temp file + rename)
- Incomplete sessions leave partial but valid files
- Recovery on next startup merges partial data

### 7.3 Concurrent Writes

- Each session writes to session-specific files
- File naming includes session suffix to prevent conflicts
- Final merge happens during cleanup/compaction

---

## 8. Query Performance

### 8.1 Predicate Pushdown

Partitioning enables efficient filtering:

```sql
-- Only reads January 2026 data
SELECT * FROM proc_samples
WHERE year = 2026 AND month = 1;
```

### 8.2 Column Pruning

Parquet columnar format enables reading only needed columns:

```sql
-- Only reads pid, score, recommendation columns
SELECT pid, score, recommendation FROM proc_inference;
```

### 8.3 Suggested Indexes

For frequent queries, consider:
- Session ID lookup index
- Time range index
- Command pattern index

---

## 9. Redaction

### 9.1 Redacted Fields

Fields that may contain sensitive data are redacted per policy:

| Field | Redaction Policy |
|-------|------------------|
| `cmdline` | Hash or truncate secrets |
| `hostname` | May be hashed |
| `username` | May be hashed |
| `cwd` | May be truncated |
| `exe` | May be normalized |

### 9.2 Redaction Markers

```
[REDACTED:hash:abc123]
[REDACTED:pattern:secret]
```

See: specs/redaction-policy.md (process_triage-8n3)

---

## 10. Fleet Mode

### 10.1 Cross-Host Aggregation

Fleet mode aggregates telemetry across hosts:

```sql
-- Fleet-wide statistics
SELECT
    host_id,
    DATE_TRUNC('day', started_at) AS day,
    COUNT(*) AS sessions,
    SUM(kills_successful) AS total_kills
FROM runs
GROUP BY 1, 2
ORDER BY 1, 2;
```

### 10.2 Host Info Metadata

```json
{
  "host_id": "a1b2c3d4...",
  "hostname_hash": "e5f6g7h8...",
  "first_seen": "2026-01-01T00:00:00Z",
  "last_seen": "2026-01-15T14:30:00Z",
  "os_family": "linux",
  "arch": "x86_64"
}
```

---

## 11. References

- PLAN: §3.3 Telemetry Storage
- Apache Parquet: https://parquet.apache.org/
- DuckDB: https://duckdb.org/
- Bead: process_triage-qje (Session Model)
- Bead: process_triage-8n3 (Redaction Policy)
- Bead: process_triage-k4yc.2 (DuckDB Views)
