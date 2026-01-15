# pt-core CLI Surface Specification

**Version**: 1.0.0
**Status**: Draft
**Bead**: process_triage-3mi

---

## 1. Overview

This document specifies the complete CLI surface for `pt-core`, the Rust binary that implements all Process Triage functionality.

### Design Principles

1. **Golden path first**: `pt-core run` (or just `pt`) provides a single coherent workflow
2. **Token-efficient**: Agent outputs minimize verbosity by default
3. **Stable schemas**: JSON outputs include `schema_version` for forward compatibility
4. **Automation-friendly**: Exit codes have semantic meaning
5. **Progressive disclosure**: Basic usage is simple; power features are discoverable

---

## 2. Global Options

These options apply to all subcommands:

| Option | Short | Type | Description |
|--------|-------|------|-------------|
| `--help` | `-h` | flag | Show help for command |
| `--version` | `-V` | flag | Show version information |
| `--capabilities` | | path/json | Path to capabilities manifest (or inline JSON) |
| `--discover-caps` | | flag | Auto-discover capabilities (slower than cached) |
| `--config` | `-c` | path | Config directory (default: `~/.config/process_triage`) |
| `--data-dir` | | path | Data directory (default: `~/.local/share/process_triage`) |
| `--format` | `-f` | enum | Output format (see Section 5) |
| `--quiet` | `-q` | flag | Suppress non-essential output |
| `--verbose` | `-v` | flag | Increase verbosity (can repeat: `-vv`, `-vvv`) |
| `--color` | | enum | Color output: `auto`, `always`, `never` |
| `--log-level` | | enum | Logging level: `error`, `warn`, `info`, `debug`, `trace` |

### Version Output

```
pt-core --version
pt-core 2.0.0 (abc123f 2026-01-15)
Schema: 1.0.0
```

```
pt-core --version --format json
{
  "name": "pt-core",
  "version": "2.0.0",
  "commit": "abc123f",
  "build_date": "2026-01-15",
  "schema_version": "1.0.0",
  "features": ["deep", "report", "daemon"]
}
```

---

## 3. Subcommands

### 3.1 `pt-core run` (Default Golden Path)

The default subcommand when no command is specified. Runs the complete workflow:
scan → infer → decide → TUI approval → apply.

```
pt-core run [OPTIONS]
pt-core [OPTIONS]  # Equivalent
```

| Option | Type | Description |
|--------|------|-------------|
| `--deep` | flag | Force deep scan on all candidates |
| `--shadow` | flag | Compute plan but never execute actions |
| `--dry-run` | flag | Print plan without executing (even with `--robot`) |
| `--robot` | flag | Skip TUI, execute pre-toggled plan automatically |
| `--min-age` | duration | Only consider processes older than threshold (default: `5m`) |
| `--limit` | int | Limit candidate count |
| `--goal` | string | Resource recovery target (e.g., `"free 4GB RAM"`) |

**Robot mode controls** (require `--robot`):

| Option | Type | Description |
|--------|------|-------------|
| `--min-posterior` | float | Only act if P(abandoned) > threshold |
| `--max-blast-radius` | string | Limit total impact (e.g., `2GB`, `5 processes`) |
| `--max-kills` | int | Maximum kill actions per run |
| `--only-categories` | list | Only act on specified categories |
| `--exclude-categories` | list | Never act on specified categories |
| `--require-known-signature` | flag | Only act on pattern library matches |

### 3.2 `pt-core scan`

Quick scan only (no inference, no decisions). Useful for data collection.

```
pt-core scan [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--samples` | int | Number of samples for delta computation (default: 3) |
| `--interval` | duration | Interval between samples (default: `2s`) |
| `--min-age` | duration | Filter processes by minimum age |
| `--include-protected` | flag | Include system-protected processes |

### 3.3 `pt-core deep-scan`

Deep scan with expensive probes (I/O, network, stack sampling, etc.).

```
pt-core deep-scan [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--pids` | list | Specific PIDs to scan (default: all candidates) |
| `--probes` | list | Specific probes to run (default: all available) |
| `--timeout` | duration | Per-probe timeout (default: `30s`) |
| `--budget` | int | Overhead budget percentage (default: 5%) |

### 3.4 `pt-core infer`

Run inference on collected data. Usually used with a session.

```
pt-core infer --session <id> [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--session` | string | Session ID with scan data (required) |
| `--priors` | path | Custom priors file |
| `--galaxy-brain` | flag | Generate full math ledger |

### 3.5 `pt-core decide`

Generate action plan from inference results.

```
pt-core decide --session <id> [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--session` | string | Session ID with inference data (required) |
| `--policy` | path | Custom policy file |
| `--fdr-alpha` | float | FDR control level (default: 0.05) |

### 3.6 `pt-core ui`

Launch interactive TUI for plan approval.

```
pt-core ui [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--session` | string | Session ID to display |
| `--theme` | enum | UI theme: `dark`, `light`, `auto` |

### 3.7 `pt-core agent` (Agent CLI)

Token-efficient CLI for AI agents. See Section 4 for full specification.

```
pt-core agent <SUBCOMMAND> [OPTIONS]
```

Subcommands: `snapshot`, `plan`, `explain`, `apply`, `verify`, `diff`, `sessions`, `status`, `tail`, `inbox`, `export`, `report`, `capabilities`, `watch`, `fleet`.

### 3.8 `pt-core duck`

Run DuckDB queries on telemetry data.

```
pt-core duck [OPTIONS] [QUERY]
```

| Option | Type | Description |
|--------|------|-------------|
| `--report` | string | Run named report: `recent`, `decisions`, `outcomes` |
| `--since` | duration | Time filter for queries |
| `--output` | path | Write results to file |

### 3.9 `pt-core bundle`

Create shareable `.ptb` bundle from a session.

```
pt-core bundle --session <id> --out <path> [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--session` | string | Session ID (required) |
| `--out` | path | Output path (required) |
| `--profile` | enum | Redaction level: `minimal`, `safe`, `forensic` |
| `--encrypt` | flag | Encrypt bundle for secure transport |
| `--include-raw` | flag | Include raw probe outputs |

### 3.10 `pt-core report`

Generate single-file HTML report.

```
pt-core report --session <id> --out <path> [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--session` | string | Session ID (required) |
| `--out` | path | Output path (required) |
| `--galaxy-brain` | flag | Include full math ledger |
| `--embed-assets` | flag | Inline CDN assets for offline viewing |
| `--title` | string | Custom report title |

### 3.11 `pt-core daemon`

Run dormant monitoring mode.

```
pt-core daemon [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--interval` | duration | Check interval (default: `5m`) |
| `--threshold` | enum | Trigger sensitivity: `low`, `medium`, `high`, `critical` |
| `--notify-exec` | string | Command to execute on escalation |
| `--oneshot` | flag | Run once and exit (for cron) |

### 3.12 `pt-core inbox`

List daemon-created sessions pending review.

```
pt-core inbox [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--limit` | int | Maximum entries to show |
| `--filter` | enum | Filter: `pending`, `reviewed`, `all` |

---

## 4. Agent CLI Specification

The `pt-core agent` subcommands are optimized for AI agent workflows.

### 4.1 `agent snapshot`

One-shot comprehensive reconnaissance.

```
pt-core agent snapshot [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--top` | int | Processes per category (default: 10) |
| `--include-env` | flag | Include environment variable summaries |
| `--include-network` | flag | Include network connection summary |
| `--format` | enum | Output format (default: `json`) |

**Output includes**:
- System state (loadavg, memory, CPU, PSI)
- Process census (by state, orphans, zombies)
- Resource hogs (top CPU, memory, IO)
- Anomaly indicators
- Capability report
- Session ID for follow-up commands

### 4.2 `agent plan`

Create action plan with candidates.

```
pt-core agent plan [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--deep` | flag | Force deep scan on all candidates |
| `--session` | string | Reuse existing session |
| `--signatures` | path | Additional signature file |
| `--community-signatures` | flag | Include community signatures |
| `--min-age` | duration | Minimum process age |
| `--limit` | int | Limit candidate count |
| `--only` | enum | Filter: `kill`, `review`, `all` |
| `--since` | string | Session ID for differential mode |
| `--since-time` | duration | Time for differential mode (e.g., `2h`) |
| `--goal` | string | Resource recovery target |
| `--include-predictions` | flag | Add trajectory analysis |
| `--format` | enum | Output format |

### 4.3 `agent explain`

Drill down into a specific process.

```
pt-core agent explain --session <id> --pid <pid> [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--session` | string | Session ID (required) |
| `--pid` | int | Process ID (required) |
| `--include` | list | Include: `samples`, `raw`, `ledger` |
| `--galaxy-brain` | flag | Full mathematical derivation |
| `--show-dependencies` | flag | Show process tree |
| `--show-blast-radius` | flag | Compute total impact |
| `--show-history` | flag | Process lifecycle narrative |
| `--what-if` | flag | Show hypothetical evidence shifts |
| `--format` | enum | Output format |

### 4.4 `agent apply`

Execute actions from a plan.

```
pt-core agent apply --session <id> [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--session` | string | Session ID (required) |
| `--recommended` | flag | Apply all recommended actions |
| `--pids` | list | Specific PIDs (must be in plan) |
| `--targets` | list | Explicit identity tuples: `pid:start_id` |
| `--yes` | flag | Required for execution |
| `--resume` | flag | Resume interrupted session |
| `--min-posterior` | float | Confidence threshold |
| `--max-blast-radius` | string | Impact limit |
| `--max-kills` | int | Kill count limit |

### 4.5 `agent verify`

Verify outcomes after apply.

```
pt-core agent verify --session <id> [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--session` | string | Session ID (required) |
| `--format` | enum | Output format |

### 4.6 `agent diff`

Compare before/after state.

```
pt-core agent diff --session <id> [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--session` | string | Session ID (required) |
| `--baseline` | string | Alternative baseline session |
| `--format` | enum | Output format |

### 4.7 `agent sessions`

List sessions.

```
pt-core agent sessions [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--limit` | int | Maximum entries |
| `--filter` | enum | Filter: `active`, `completed`, `all` |
| `--format` | enum | Output format |

### 4.8 `agent status`

Get session status.

```
pt-core agent status --session <id> [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--session` | string | Session ID (required) |
| `--format` | enum | Output format |

### 4.9 `agent tail`

Stream progress events.

```
pt-core agent tail --session <id> [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--session` | string | Session ID (required) |
| `--follow` | flag | Continue streaming new events |
| `--format` | enum | Output format (default: `jsonl`) |

### 4.10 `agent inbox`

List daemon-created pending plans.

```
pt-core agent inbox [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--limit` | int | Maximum entries |
| `--format` | enum | Output format |

### 4.11 `agent export`

Export session as bundle.

```
pt-core agent export --session <id> --out <path> [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--session` | string | Session ID (required) |
| `--out` | path | Output path (required) |
| `--profile` | enum | Redaction: `minimal`, `safe`, `forensic` |
| `--galaxy-brain` | flag | Include math ledger |
| `--encrypt` | flag | Encrypt bundle |

### 4.12 `agent report`

Generate HTML report.

```
pt-core agent report --session <id> --out <path> [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--session` | string | Session ID (required) |
| `--out` | path | Output path (required) |
| `--galaxy-brain` | flag | Include math ledger |
| `--embed-assets` | flag | Inline assets |

### 4.13 `agent capabilities`

Report capabilities of this installation.

```
pt-core agent capabilities [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--check-action` | string | Check specific action availability |
| `--format` | enum | Output format |

### 4.14 `agent watch`

Background monitoring for agents.

```
pt-core agent watch [OPTIONS]
```

| Option | Type | Description |
|--------|------|-------------|
| `--notify-exec` | string | Command on threshold crossing |
| `--threshold` | enum | Trigger: `low`, `medium`, `high`, `critical` |
| `--interval` | duration | Check frequency (default: `60s`) |
| `--format` | enum | Output format (default: `jsonl`) |

### 4.15 `agent fleet`

Fleet operations (multi-host).

```
pt-core agent fleet <SUBCOMMAND> [OPTIONS]
```

Subcommands: `plan`, `apply`, `report`

---

## 5. Output Formats

### 5.1 Format Options

| Format | Description | Use Case |
|--------|-------------|----------|
| `json` | Token-efficient JSON (default for agent) | Agent workflows, parsing |
| `md` | Human-readable Markdown | User review, documentation |
| `jsonl` | Streaming newline-delimited JSON | Progress events, logs |
| `summary` | One-line summary | Quick checks, dashboards |
| `metrics` | Key=value pairs | Monitoring integration |
| `slack` | Human-friendly narrative | Chat notifications |
| `prose` | Natural language paragraphs | Agent-to-user handoff |
| `exitcode` | Minimal output, use exit code | Silent automation |

### 5.2 Format Modifiers

| Modifier | Description |
|----------|-------------|
| `--compact` | Omit optional/verbose fields |
| `--fields <list>` | Include only specified fields |
| `--include-prose` | Add prose_summary to JSON output |
| `--prose-style <style>` | Prose style: `terse`, `conversational`, `formal`, `technical` |

### 5.3 JSON Output Schema Invariants

Every JSON output includes:

```json
{
  "schema_version": "1.0.0",
  "session_id": "sess-20260115-143022-abc123",
  "generated_at": "2026-01-15T14:30:22Z",
  "host_id": "devbox1.example.com",
  "summary": { ... },
  ...
}
```

---

## 6. Exit Codes

### 6.1 Standard Exit Codes

| Code | Constant | Meaning |
|------|----------|---------|
| 0 | `OK_CLEAN` | Success: nothing to do / clean run |
| 1 | `OK_CANDIDATES` | Candidates exist (plan produced) but no actions executed |
| 2 | `OK_APPLIED` | Actions executed successfully |
| 3 | `ERR_PARTIAL` | Partial failure: some actions failed |
| 4 | `ERR_BLOCKED` | Blocked by safety gates or policy |
| 5 | `ERR_GOAL_UNREACHABLE` | Goal not achievable (insufficient candidates) |
| 6 | `ERR_INTERRUPTED` | Session interrupted; resumable |
| 10 | `ERR_ARGS` | Invalid arguments |
| 11 | `ERR_CAPABILITY` | Required capability missing |
| 12 | `ERR_PERMISSION` | Permission denied |
| 13 | `ERR_VERSION` | Version mismatch (wrapper/core) |
| 14 | `ERR_LOCK` | Lock contention (another pt running) |
| 15 | `ERR_SESSION` | Session not found or invalid |
| 20 | `ERR_INTERNAL` | Internal error (bug) |
| 21 | `ERR_IO` | I/O error |
| 22 | `ERR_TIMEOUT` | Operation timed out |

### 6.2 Exit Code Escape Hatches

| Option | Description |
|--------|-------------|
| `--exit-code always0` | Always exit 0 (for `set -e` workflows) |
| `--exit-code strict` | Exit non-zero on any warning |

### 6.3 Exit Code Examples

```bash
# Normal scan, nothing suspicious
pt-core agent plan
# Exit: 0 (OK_CLEAN)

# Candidates found, plan produced
pt-core agent plan
# Exit: 1 (OK_CANDIDATES)

# Actions executed successfully
pt-core agent apply --session abc123 --recommended --yes
# Exit: 2 (OK_APPLIED)

# Some actions failed
pt-core agent apply --session abc123 --recommended --yes
# Exit: 3 (ERR_PARTIAL)

# Safety gate blocked action
pt-core agent apply --session abc123 --pids 1  # PID 1 is protected
# Exit: 4 (ERR_BLOCKED)
```

---

## 7. Schema Versioning Strategy

### 7.1 Version Format

Schema versions use semantic versioning: `MAJOR.MINOR.PATCH`

| Change Type | Version Bump | Example |
|-------------|--------------|---------|
| Breaking change | MAJOR | Removing field, changing semantics |
| New optional field | MINOR | Adding `trajectory` to candidates |
| Bug fix | PATCH | Fixing typo in field name |

### 7.2 Compatibility Rules

1. **Additive preferred**: New fields are added as optional; old clients ignore them
2. **Deprecation before removal**: Fields are marked deprecated for one major version
3. **Schema in every output**: `schema_version` is always present
4. **Version negotiation**: Clients can request specific schema versions via header

### 7.3 Schema Evolution Example

```json
// Version 1.0.0
{
  "schema_version": "1.0.0",
  "candidates": [{"pid": 1234, "classification": "abandoned"}]
}

// Version 1.1.0 (added trajectory, optional)
{
  "schema_version": "1.1.0",
  "candidates": [{
    "pid": 1234,
    "classification": "abandoned",
    "trajectory": {"trend": "worsening", "time_to_threshold": 3600}
  }]
}

// Version 2.0.0 (breaking: renamed classification -> state)
{
  "schema_version": "2.0.0",
  "candidates": [{"pid": 1234, "state": "abandoned"}]
}
```

### 7.4 Deprecation Notices

Deprecated fields include a warning in verbose output:

```json
{
  "schema_version": "1.2.0",
  "candidates": [...],
  "_deprecations": [
    {"field": "candidates[].classification", "replacement": "candidates[].state", "removal_version": "2.0.0"}
  ]
}
```

---

## 8. Error Output

### 8.1 Error Format

Errors are always structured:

```json
{
  "error": {
    "code": "ERR_PERMISSION",
    "message": "Cannot read /proc/1234/io: Permission denied",
    "details": {
      "pid": 1234,
      "path": "/proc/1234/io",
      "errno": 13
    },
    "suggestion": "Run with elevated privileges or exclude protected processes",
    "documentation_url": "https://process-triage.dev/errors/ERR_PERMISSION"
  }
}
```

### 8.2 Warning Output

Warnings do not change exit code but are logged:

```json
{
  "warnings": [
    {
      "code": "WARN_TOOL_UNAVAILABLE",
      "message": "bpftrace not available; some deep scan probes disabled",
      "severity": "info"
    }
  ],
  ...
}
```

---

## 9. Help Output

### 9.1 Standard Help

```
$ pt-core --help
pt-core 2.0.0
Process Triage - Bayesian-inspired zombie/abandoned process killer

USAGE:
    pt-core [OPTIONS] [SUBCOMMAND]

OPTIONS:
    -h, --help        Show help information
    -V, --version     Show version information
    -f, --format      Output format [json|md|summary|metrics|slack|prose|exitcode]
    -q, --quiet       Suppress non-essential output
    -v, --verbose     Increase verbosity (-v, -vv, -vvv)

SUBCOMMANDS:
    run         Full workflow: scan → infer → decide → TUI → apply (default)
    scan        Quick scan only
    deep-scan   Deep scan with expensive probes
    infer       Run inference on collected data
    decide      Generate action plan
    ui          Interactive TUI
    agent       Agent/robot CLI (token-efficient)
    duck        Query telemetry with DuckDB
    bundle      Create shareable .ptb bundle
    report      Generate HTML report
    daemon      Run dormant monitoring mode
    inbox       List pending daemon sessions

Run 'pt-core <SUBCOMMAND> --help' for more information on a command.
```

### 9.2 Agent Help

```
$ pt-core agent --help
pt-core-agent
Agent/robot CLI for AI-driven workflows

USAGE:
    pt-core agent <SUBCOMMAND> [OPTIONS]

SUBCOMMANDS:
    snapshot      One-shot system reconnaissance
    plan          Create action plan with candidates
    explain       Drill down into specific process
    apply         Execute actions from plan
    verify        Verify outcomes after apply
    diff          Compare before/after state
    sessions      List sessions
    status        Get session status
    tail          Stream progress events
    inbox         List daemon-created pending plans
    export        Export session as bundle
    report        Generate HTML report
    capabilities  Report installation capabilities
    watch         Background monitoring
    fleet         Fleet operations (multi-host)

All agent commands output JSON by default for token efficiency.
Use --format md for human-readable output.
```

---

## 10. References

- PLAN §3.0: Execution & Packaging Architecture
- PLAN §3.5: Agent/Robot CLI Contract
- PLAN §7.0: Golden Path UX
- Bead: process_triage-kze (Package Architecture)
- Bead: process_triage-40mt.2 (CLI Skeleton Implementation)
