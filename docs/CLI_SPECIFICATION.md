# CLI Specification

> **Bead**: `process_triage-3mi`
> **Status**: Specification
> **Version**: 1.0.0

## Overview

This document specifies the complete CLI surface for `pt-core`, the Rust monolith that handles all inference, decisioning, telemetry, and UI operations. The CLI is designed with both human users and AI agents as first-class citizens.

### Design Principles

1. **Token-efficient defaults**: Return "just enough" information; deeper details on demand
2. **Stable schemas**: Additive changes only; `schema_version` bumped only when unavoidable
3. **Identity safety**: Every process reference includes `pid` + `start_id` + `uid` for revalidation
4. **Automation-friendly**: Deterministic exit codes, structured outputs, fine-grained control
5. **Progressive disclosure**: Simple commands for common cases, full power for experts

---

## Exit Codes

Exit codes communicate operation outcome without requiring output parsing.

| Code | Name | Meaning |
|------|------|---------|
| 0 | `CLEAN` | Clean / nothing to do |
| 1 | `PLAN_READY` | Candidates exist (plan produced) but no actions executed |
| 2 | `ACTIONS_OK` | Actions executed successfully |
| 3 | `PARTIAL_FAIL` | Partial failure executing actions |
| 4 | `POLICY_BLOCKED` | Blocked by safety gates / policy |
| 5 | `GOAL_UNREACHABLE` | Goal not achievable (insufficient candidates) |
| 6 | `INTERRUPTED` | Session interrupted / resumable |
| 10+ | `INTERNAL_ERROR` | Tooling/internal error |

### Exit Code Modifiers

- `--exit-code always0` - Always exit 0 (for `set -e` workflows that parse JSON)

---

## Output Formats

All commands support multiple output formats via `--format <format>`:

| Format | Description | Use Case |
|--------|-------------|----------|
| `json` | Token-efficient structured JSON | Default; machine consumption, agent integration |
| `md` | Human-readable Markdown | Terminal display, documentation |
| `jsonl` | Streaming JSON Lines | Progress events, real-time integration |
| `summary` | One-line summary | Quick status checks |
| `metrics` | Key=value pairs | Monitoring/alerting systems |
| `slack` | Human-friendly narrative | Chat handoff, notifications |
| `exitcode` | Minimal output | Scripts that only need exit code |
| `prose` | Structured natural language | Agent-to-user communication |

### Output Controls

- `--fields <list>` - Include only specified fields
- `--compact` - Omit optional/verbose fields
- `--limit <N>` - Limit array sizes
- `--only kill|review|all` - Filter candidates by recommendation

### Schema Invariants

Every JSON output includes:
```json
{
  "schema_version": "1.0.0",
  "session_id": "pt-20260115-143022-a7xq",
  "generated_at": "2026-01-15T14:30:22Z",
  "host_id": "devbox1.example.com",
  "summary": { ... }
}
```

---

## Global Flags

These flags apply to most commands:

| Flag | Description |
|------|-------------|
| `--capabilities <path>` | Path to capabilities manifest (from pt wrapper) |
| `--config <path>` | Override config directory |
| `--format <format>` | Output format (see above) |
| `--verbose` / `-v` | Increase verbosity |
| `--quiet` / `-q` | Decrease verbosity |
| `--no-color` | Disable colored output |
| `--timeout <seconds>` | Abort if operation exceeds time limit |

### Mode Flags

| Flag | Description |
|------|-------------|
| `--robot` | Non-interactive mode; execute policy-approved actions automatically |
| `--shadow` | Full pipeline but never execute actions (calibration mode) |
| `--dry-run` | Compute plan only, no execution even with `--robot` |
| `--standalone` | Run without wrapper (uses detected/default capabilities) |

---

## Command Reference

### `pt-core run` (Default Command)

Interactive golden path: scan → infer → plan → TUI approval → staged apply.

```
pt-core run [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--deep` | Force deep scan with all available probes |
| `--signatures <path>` | Load additional signature patterns |
| `--community-signatures` | Include signed community signatures |
| `--min-age <seconds>` | Only consider processes older than threshold |

---

### `pt-core scan`

Quick multi-sample scan only (no inference or action).

```
pt-core scan [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--deep` | Force deep scan |
| `--samples <N>` | Number of samples to collect (default: 3) |
| `--interval <ms>` | Interval between samples (default: 500) |

---

### `pt-core deep-scan`

Full deep scan with all available probes.

```
pt-core deep-scan [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--pids <list>` | Target specific PIDs only |
| `--budget <seconds>` | Maximum time budget for deep scan |

---

### `pt-core infer`

Run inference on existing scan data.

```
pt-core infer --session <id> [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--session <id>` | Session containing scan data |
| `--galaxy-brain` | Include full mathematical derivation |

---

### `pt-core decide`

Compute action plan from inference results.

```
pt-core decide --session <id> [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--session <id>` | Session with inference results |
| `--goal <spec>` | Resource recovery goal (see Goals section) |

---

### `pt-core ui`

Launch TUI for plan approval.

```
pt-core ui --session <id> [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--session <id>` | Session with plan to approve |
| `--galaxy-brain` | Enable math mode in TUI |

---

## Agent CLI Commands

The `agent` subcommand provides a hyper-ergonomic interface optimized for AI agents.

### `pt-core agent plan`

Create/compute a triage plan.

```
pt-core agent plan [OPTIONS]
```

**Core Options:**

| Option | Description |
|--------|-------------|
| `--deep` | Force deep scan on all candidates |
| `--session <id>` | Reuse existing session snapshot |
| `--signatures <path>` | Load additional signatures |
| `--community-signatures` | Include community signatures |
| `--min-age <seconds>` | Minimum process age filter |
| `--min-posterior <N>` | Minimum posterior probability threshold (default: 0.7). Alias: `--threshold` |
| `--limit <N>` | Limit candidate count in output |
| `--only kill\|review\|all` | Filter by recommendation category |
| `--format <format>` | Output format |

**Differential Mode:** *(Coming in v1.2 - flags are parsed but produce a warning)*

| Option | Description |
|--------|-------------|
| `--since <session-id>` | Compare against prior session |
| `--since-time <ts\|dur>` | Compare against time (e.g., `2h`) |

Differential output will include: `new`, `worsened`, `resolved`, `persistent`

**Goal-Oriented Mode:** *(Coming in v1.2 - flags are parsed but produce a warning)*

| Option | Description |
|--------|-------------|
| `--goal "free <amount> RAM"` | Target memory recovery |
| `--goal "CPU < <percent>"` | Target CPU utilization |
| `--goal "free port <port>"` | Target port recovery |
| `--goal "free <N> processes"` | Reduce process count |

**Predictive Mode:** *(Coming in v1.2 - flags are parsed but produce a warning)*

| Option | Description |
|--------|-------------|
| `--include-predictions` | Add trajectory analysis |

> **Note:** When any of the above future flags are used, the plan is still generated normally but includes a `stub_flags` section in the output warning that the flags are parsed but not yet functional.

---

### `pt-core agent explain`

Drill-down into a specific process.

```
pt-core agent explain --session <id> --pid <pid> [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--format json\|md` | Output format |
| `--include raw` | Include capped/redacted raw samples |
| `--include ledger` | Include full evidence ledger |
| `--galaxy-brain` | Full mathematical derivation |
| `--show-dependencies` | Show process tree with annotations |
| `--show-blast-radius` | Compute total impact |
| `--show-history` | Reconstruct process lifecycle narrative |
| `--what-if` | Show hypothetical evidence shifts |

---

### `pt-core agent apply`

Execute actions from a plan.

```
pt-core agent apply --session <id> [OPTIONS]
```

**Target Selection:**

| Option | Description |
|--------|-------------|
| `--recommended` | Apply all recommended actions |
| `--pids <list>` | Apply to specific PIDs |
| `--targets <list>` | Explicit identity tuples (`pid:start_id`) |

**Confirmation:**

| Option | Description |
|--------|-------------|
| `--yes` | Required for execution |

**Confidence-Bounded Automation:**

| Option | Description |
|--------|-------------|
| `--min-posterior <threshold>` | Only act above threshold (e.g., `0.99`) |
| `--max-blast-radius <amount>` | Limit total impact (e.g., `2GB`) |
| `--max-kills <N>` | Limit kill actions per run |
| `--require-known-signature` | Only act on pattern library matches |
| `--only-categories <list>` | Only specified categories |
| `--exclude-categories <list>` | Never specified categories |
| `--abort-on-unknown` | Stop on unexpected conditions |

**Resumability:**

| Option | Description |
|--------|-------------|
| `--resume` | Resume interrupted session |

---

### `pt-core agent sessions`

List sessions, or show details for a specific session.

```
pt-core agent sessions [OPTIONS]
pt-core agent sessions --session <id> [--detail]
```

| Option | Description |
|--------|-------------|
| `--session <id>` | Show details for specific session (consolidates `show`/`status`). Aliases: `--status`, `--show` |
| `--detail` | Include full session detail (plan contents, actions taken) |
| `--limit <N>` | Limit results in list mode |
| `--state <state>` | Filter by session state |
| `--format json\|md` | Output format |
| `--cleanup` | Remove old sessions |
| `--older-than <duration>` | For cleanup: age threshold (default: 7d) |

---

### `pt-core agent show` *(Deprecated)*

> **Note**: This command is deprecated. Use `pt-core agent sessions --session <id>` instead.

Show session details.

```
pt-core agent show --session <id> [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--format json\|md` | Output format |

---

### `pt-core agent status` *(Deprecated)*

> **Note**: This command is deprecated. Use `pt-core agent sessions --session <id>` instead.

Show session status (applied vs pending actions).

```
pt-core agent status --session <id> [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--format json\|md` | Output format |

---

### `pt-core agent tail`

Stream progress/outcomes.

```
pt-core agent tail --session <id> [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--format jsonl` | Streaming events |

---

### `pt-core agent verify`

Post-action outcome confirmation.

```
pt-core agent verify --session <id> [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--session <id>` | Session ID (required) |
| `--wait <seconds>` | Wait for processes to terminate with timeout (default: 0 = no wait) |
| `--check-respawn` | Check if killed processes have respawned (matches command signatures) |
| `--format json\|md` | Output format |

**Action Outcome States:**

| State | Description |
|-------|-------------|
| `confirmed_dead` | Process gone, PID not reused |
| `confirmed_stopped` | Process paused/frozen as intended |
| `still_running` | Action may have failed |
| `respawned` | Process died but restarted (supervised) |
| `pid_reused` | PID exists but different process |
| `cascaded` | Action caused additional deaths |
| `timeout` | Outcome undetermined in time |

---

### `pt-core agent diff`

Before/after comparison.

```
pt-core agent diff --base <id> [OPTIONS]
pt-core agent diff --before <id> --after <id> [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--base <id>` | Base session (the "before" snapshot). Aliases: `--session`, `--since`, `--before` |
| `--compare <id>` | Compare session (the "after" snapshot, default: latest). Aliases: `--vs`, `--after` |
| `--focus <type>` | Focus output on specific changes: `new`, `removed`, `changed`, `improved`, `persistent`, `all` (default: `all`) |
| `--format json\|md\|prose` | Output format |

Output includes: `new` (processes appearing), `worsened`, `improved`, `resolved` (processes gone), `persistent` (suspicious across sessions).

---

### `pt-core agent export`

Export session bundle. Agent-friendly alias for `pt-core bundle create`.

```
pt-core agent export [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--session <id>` | Session to export (default: latest) |
| `--out <path>` | Output path for bundle |
| `--profile minimal\|safe\|forensic` | Redaction level (default: safe) |
| `--include-telemetry` | Include raw telemetry data |
| `--include-dumps` | Include full process dumps |
| `--encrypt` | Encrypt bundle with passphrase |
| `--passphrase <text>` | Passphrase for encryption (or use `PT_BUNDLE_PASSPHRASE`) |

---

### `pt-core agent report`

Generate HTML report.

```
pt-core agent report --session <id> --out <path> [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--profile minimal\|safe\|forensic` | Redaction level |
| `--galaxy-brain` | Include math ledger |
| `--embed-assets` | Inline CDN assets |

---

### `pt-core agent inbox`

List daemon-created sessions pending review.

```
pt-core agent inbox [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--limit <N>` | Limit results |
| `--format json\|md` | Output format |

---

### `pt-core agent watch`

Background monitoring mode.

```
pt-core agent watch [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--notify-exec <cmd>` | Execute via shell on threshold crossing |
| `--notify-cmd <cmd>` | Execute directly (no shell) on threshold crossing |
| `--notify-arg <arg>` | Repeatable args for `--notify-cmd` |
| `--format jsonl` | Stream events |
| `--threshold low\|medium\|high\|critical` | Trigger sensitivity |
| `--interval <seconds>` | Check frequency (default: 60) |

Notes:
- If both `--notify-cmd` and `--notify-exec` are set, `--notify-cmd` takes precedence.

**Events Emitted:**

| Event | Description |
|-------|-------------|
| `candidate_detected` | New process crosses threshold |
| `severity_escalated` | Existing candidate worsens |
| `goal_violated` | Resource target exceeded |
| `baseline_anomaly` | Significant deviation from baseline |

---

### `pt-core agent snapshot`

One-shot comprehensive reconnaissance.

```
pt-core agent snapshot [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--label <text>` | Label for the snapshot |
| `--top <N>` | Limit to top N processes by resource usage (CPU+memory) |
| `--include-env` | Include environment variable keys (redacted values) |
| `--include-network` | Include network socket counts per process |
| `--format json\|md\|summary` | Output format |

Returns: system state, process census, resource hogs, anomalies, capabilities, session_id.

---

### `pt-core agent capabilities`

Report available capabilities.

```
pt-core agent capabilities [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--format json\|md` | Output format |
| `--check-action <action>` | Check specific action availability |

Returns: platform info, data sources, supervisors, actions, permissions, limits.

---

### `pt-core agent list-priors`

Show current priors.

```
pt-core agent list-priors [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--format json\|md` | Output format |

---

### `pt-core agent export-priors`

Export learned priors.

```
pt-core agent export-priors --out <path> [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--host-profile <name>` | Tag with machine characteristics |

---

### `pt-core agent import-priors`

Import priors from file.

```
pt-core agent import-priors --from <path> [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--merge` | Merge with existing (default) |
| `--replace` | Replace existing |

---

### `pt-core agent fleet plan`

Fleet-wide planning (multi-host).

```
pt-core agent fleet plan --hosts <file|list> [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--hosts <spec>` | Host file or comma-separated list |
| `--parallel <N>` | Concurrent connections |

---

### `pt-core agent fleet apply`

Fleet-wide action execution.

```
pt-core agent fleet apply --session <fleet-session-id> [OPTIONS]
```

---

### `pt-core agent fleet status`

Fleet session status.

```
pt-core agent fleet status --session <fleet-session-id> [OPTIONS]
```

---

## Other Commands

### `pt-core duck`

DuckDB query interface for telemetry.

```
pt-core duck [OPTIONS] <query>
```

| Option | Description |
|--------|-------------|
| `--format json\|csv\|table` | Output format |

---

### `pt-core shadow`

Manage shadow-mode observation workflows.

```
pt-core shadow <command> [OPTIONS]
```

**Commands:**

| Command | Description |
|---------|-------------|
| `start` | Start the shadow observation loop |
| `stop` | Stop the background observer |
| `status` | Show observer status and storage stats |
| `export` | Export shadow observations |
| `report` | Generate validation report from shadow observations |

**Common Options:**

| Option | Description |
|--------|-------------|
| `--output <path>` | Write output to file (stdout if omitted) |
| `--limit <N>` | Limit observations analyzed/exported |
| `--threshold <0-1>` | Kill threshold used for report metrics |

---

### `pt-core bundle`

Create `.ptb` session bundle.

```
pt-core bundle --session <id> --out <path> [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--profile minimal\|safe\|forensic` | Redaction level |

---

### `pt-core report`

Generate standalone HTML report.

```
pt-core report --session <id> --out <path> [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--galaxy-brain` | Include math ledger |
| `--embed-assets` | Inline assets for offline |

---

### `pt-core daemon`

Run in dormant/background mode.

```
pt-core daemon [start|stop|status] [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `start` | Start daemon (default behavior if no subcommand) |
| `stop` | Stop daemon |
| `status` | Check daemon status |
| `--foreground` | Run in foreground (default when no subcommand) |

Notes:
- `pt-core daemon` (no subcommand) runs in the foreground.
- `pt-core daemon start` backgrounds by default; use `--foreground` to keep it attached.

---

### `pt-core inbox`

List daemon-created sessions (alias for `agent inbox`).

```
pt-core inbox [OPTIONS]
```

---

### `pt-core history`

Show decision history.

```
pt-core history [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--limit <N>` | Limit results |
| `--format json\|md` | Output format |

---

### `pt-core clear`

Clear decision memory.

```
pt-core clear [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--confirm` | Required confirmation flag |

---

### `pt-core help`

Show help.

```
pt-core help [COMMAND]
```

---

## Prose Output Mode

The `--format prose` option generates structured natural language for agent-to-user communication.

### Prose Sections

| Section | Content |
|---------|---------|
| `executive` | One paragraph overview |
| `actions` | What was done and why |
| `rationale` | Evidence and reasoning |
| `next_steps` | Recommendations |

### Prose Style Controls

| Option | Description |
|--------|-------------|
| `--prose-style terse` | Minimal, bullet-point |
| `--prose-style conversational` | Natural, friendly (default) |
| `--prose-style formal` | Professional report |
| `--prose-style technical` | Include technical details |

### Including Prose in JSON

```
--include-prose
```

Adds `prose_summary` object to JSON output with `executive`, `actions`, `rationale`, `next_steps` fields.

---

## Galaxy-Brain Mode

The `--galaxy-brain` flag enables full mathematical derivation output.

### Galaxy-Brain Schema

```json
{
  "galaxy_brain": {
    "enabled": true,
    "cards": [
      {
        "id": "posterior_core",
        "title": "Posterior Core",
        "equations": ["log P(C|x) = log P(C) + ...", ...],
        "values": { "log_prior_useful": -2.11, ... },
        "intuition": "CPU+TTY dominate; IO softens confidence."
      },
      ...
    ]
  }
}
```

### Standard Card IDs

| ID | Description |
|----|-------------|
| `posterior_core` | Main posterior computation |
| `hazard_time_varying` | Time-varying hazard analysis |
| `conformal_interval` | Conformal prediction intervals |
| `conformal_class` | Conformal class sets |
| `e_fdr` | Anytime-valid FDR control |
| `alpha_investing` | Alpha-investing budget |
| `voi` | Value of Information |

---

## Mandatory Candidate Fields

Every candidate in `pt agent plan` output includes:

| Field | Description |
|-------|-------------|
| `pid` | Process ID |
| `start_id` | Stable start identifier |
| `uid` | User ID |
| `ppid` | Parent PID |
| `cmd_short` | Truncated command |
| `cmd_full` | Full command (may be redacted) |
| `category` | Process category |
| `runtime_seconds` | How long running |
| `rss_mb` | Memory usage |
| `cpu_pct` | CPU percentage |
| `recommendation` | `kill` / `review` / `spare` |
| `posterior_abandoned` | P(abandoned\|evidence) |
| `confidence` | Confidence indicator |
| `evidence_summary` | Key evidence points |
| `matched_signature` | Pattern match (if any) |
| `novel_pattern` | True if no signature match |

---

## Session Lifecycle

```
snapshot → plan → explain → apply → verify → diff → export/report
    ↓        ↓        ↑        ↓        ↑
    └── all share session_id ──┘
```

Sessions are stored in `~/.local/share/process_triage/sessions/<session_id>/`

Default retention: 7 days

---

## Version Information

```
pt-core --version
```

Output: `pt-core 1.0.0 (schema 1.0.0)`
