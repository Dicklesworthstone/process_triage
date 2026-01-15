# Golden Path UX Specification

> **Bead**: `process_triage-6rf`
> **Status**: Specification
> **Version**: 1.0.0

## Overview

This document specifies the default user experience flow that makes `pt` feel like "one coherent run" rather than "a pile of verbs". The golden path is the default behavior when a user simply runs `pt` or `pt run` without additional arguments.

### Design Philosophy

1. **One coherent run**: The default experience is a guided workflow, not a command menu
2. **Progressive disclosure**: Simple by default, power on demand
3. **Never destructive by default**: All actions require explicit approval
4. **Durable sessions**: Every run creates artifacts that can be reviewed, resumed, or shared
5. **Alien artifact quality**: The tool should feel polished, intentional, and slightly magical

---

## Golden Path State Machine

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         GOLDEN PATH FLOW                                 │
└─────────────────────────────────────────────────────────────────────────┘

                              ┌──────────┐
                              │  START   │
                              └────┬─────┘
                                   │
                                   ▼
                         ┌─────────────────┐
                         │  CAPABILITIES   │ Detect OS, tools, privileges
                         │    DETECTION    │ Write capabilities.json
                         └────────┬────────┘
                                  │
                                  ▼
                         ┌─────────────────┐
                         │    SESSION      │ Create session_id
                         │    CREATION     │ Initialize artifact directory
                         └────────┬────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ STAGE 1: QUICK SCAN                                                      │
│ ─────────────────                                                        │
│ • Multi-sample process scan (3 samples @ 500ms intervals)               │
│ • Compute deltas (not single snapshot)                                   │
│ • Categorize processes by command type and CWD                          │
│ • Identify obvious candidates                                            │
│                                                                          │
│ Progress: [████████░░░░░░░░░░░░] 40% Scanning... (sample 2/3)           │
│                                                                          │
│ Output: scan_results.json in session directory                          │
└────────────────────────────┬────────────────────────────────────────────┘
                             │
                             ▼
                    ┌────────────────┐
                    │ candidates > 0 │───No────┐
                    │       ?        │         │
                    └────────┬───────┘         │
                             │Yes              │
                             ▼                 │
┌─────────────────────────────────────────┐    │
│ STAGE 2: DEEP SCAN (if needed)          │    │
│ ─────────────────────────────           │    │
│ • Additional probes on candidates       │    │
│ • lsof, strace, perf (if available)     │    │
│ • Network connection analysis           │    │
│ • Parent-child relationship mapping     │    │
│                                         │    │
│ Progress: [████████████░░░░░░░░] 60%    │    │
│                                         │    │
│ Output: deep_scan_results.json          │    │
└────────────────────┬────────────────────┘    │
                     │                         │
                     ▼                         │
┌─────────────────────────────────────────┐    │
│ STAGE 3: INFERENCE                      │    │
│ ─────────────────                       │    │
│ • Bayesian posterior computation        │    │
│ • Evidence ledger generation            │    │
│ • Confidence intervals                  │    │
│ • Category-specific prior adjustments   │    │
│                                         │    │
│ Progress: [████████████████░░░░] 80%    │    │
│                                         │    │
│ Output: inference_results.json          │    │
└────────────────────┬────────────────────┘    │
                     │                         │
                     ▼                         │
┌─────────────────────────────────────────┐    │
│ STAGE 4: PLAN GENERATION                │    │
│ ──────────────────────                  │    │
│ • Decision tree with staged actions     │    │
│ • Safety gate evaluation                │    │
│ • Loss matrix computation               │    │
│ • Recommendation ranking                │    │
│                                         │    │
│ Progress: [████████████████████] 100%   │    │
│                                         │    │
│ Output: plan.json                       │    │
└────────────────────┬────────────────────┘    │
                     │                         │
                     ▼                         │
┌─────────────────────────────────────────┐    │
│ STAGE 5: TUI APPROVAL                   │    │
│ ─────────────────────                   │    │
│ • Two-pane layout (list + detail)       │    │
│ • Pre-toggled recommendations           │    │
│ • Keyboard navigation                   │    │
│ • Evidence drill-down                   │    │
│ • Galaxy-brain toggle (g)               │    │
│                                         │    │
│ User actions:                           │    │
│   [Space] Toggle selection              │    │
│   [Enter] View details                  │    │
│   [a] Apply plan                        │    │
│   [q] Quit without action               │    │
│   [e] Export session                    │    │
│   [g] Galaxy-brain mode                 │    │
│   [?] Help                              │    │
└────────────┬─────────────────┬──────────┘    │
             │                 │               │
             │Apply            │Quit           │
             ▼                 ▼               │
┌─────────────────────┐  ┌──────────┐         │
│ STAGE 6: STAGED     │  │ SESSION  │         │
│ EXECUTION           │  │ SAVED    │─────────┤
│ ───────────────     │  │ (resume  │         │
│ Phase 1: Pause      │  │ later)   │         │
│   └─ Verify         │  └──────────┘         │
│ Phase 2: Throttle   │                       │
│   └─ Verify         │                       │
│ Phase 3: Kill       │                       │
│   └─ Verify         │                       │
│                     │                       │
│ (Staged with gates  │                       │
│  between phases)    │                       │
└────────────┬────────┘                       │
             │                                │
             ▼                                │
┌─────────────────────────────────────────┐   │
│ STAGE 7: AFTER VIEW                     │   │
│ ─────────────────                       │   │
│ • Before/after diff                     │   │
│ • Actions taken summary                 │   │
│ • Outcome verification                  │   │
│ • Resource recovery summary             │   │
│                                         │   │
│ Affordances:                            │   │
│   [r] Generate report                   │   │
│   [b] Create bundle                     │   │
│   [c] Copy session ID                   │   │
│   [Enter] Exit                          │   │
└────────────┬────────────────────────────┘   │
             │                                │
             ▼                                ▼
        ┌─────────┐                    ┌───────────┐
        │  EXIT   │                    │ CLEAN EXIT│
        │ code 2  │                    │  code 0   │
        └─────────┘                    └───────────┘
```

---

## Default Behavior Specification

### What `pt` Does With No Arguments

When a user runs `pt` or `pt run` with no arguments:

1. **Capabilities Detection** (automatic, ~100ms)
   - Detect OS, available tools, privileges
   - Cache results for session

2. **Session Creation** (automatic, ~50ms)
   - Generate `session_id`: `pt-YYYYMMDD-HHMMSS-xxxx`
   - Create artifact directory: `~/.local/share/process_triage/sessions/<session_id>/`

3. **Quick Scan** (user sees progress, ~2 seconds)
   - 3 process snapshots at 500ms intervals
   - Compute deltas to detect activity patterns
   - Categorize by command type and CWD
   - Display progress bar

4. **Deep Scan** (if candidates found, ~5-30 seconds)
   - Additional probes on suspicious processes
   - Only runs if quick scan found candidates
   - Probe availability depends on capabilities

5. **Inference** (automatic, ~500ms)
   - Bayesian posterior computation
   - Evidence ledger generation

6. **Plan Generation** (automatic, ~100ms)
   - Create staged action plan
   - Apply safety gates

7. **TUI Approval** (interactive)
   - Show plan with pre-toggled recommendations
   - Wait for user action

8. **Staged Execution** (if user approves)
   - Execute in phases: pause → throttle → kill
   - Verify between phases

9. **After View** (automatic after execution)
   - Show before/after diff
   - Offer export options

### Exit Codes

| Code | State | Meaning |
|------|-------|---------|
| 0 | `CLEAN` | No candidates found (system is clean) |
| 1 | `PLAN_READY` | Candidates exist but user quit without action |
| 2 | `ACTIONS_OK` | Actions executed successfully |
| 3 | `PARTIAL_FAIL` | Some actions failed |
| 4 | `POLICY_BLOCKED` | Safety gates blocked all actions |
| 6 | `INTERRUPTED` | Session interrupted (Ctrl+C) - resumable |

---

## Progress Visualization

### Animated Progress Bar

During scan and inference phases, display an animated progress bar:

```
┌─────────────────────────────────────────────────────────────────────────┐
│ pt - Process Triage                                      session: a7xq │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Stage 1 of 4: Quick Scan                                              │
│                                                                         │
│  [████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░] 30%                      │
│                                                                         │
│  Collecting sample 2 of 3...                                           │
│  Found 847 processes, 12 initial candidates                            │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Stage Indicators

```
  ● Quick Scan     ○ Deep Scan     ○ Inference     ○ Plan
  ↑ current        ○ pending       ○ pending       ○ pending
```

---

## TUI Layout Specification

### Two-Pane Layout

```
┌──────────────────────────────────────────────────────────────────────────┐
│ pt - Process Triage                    Session: pt-20260115-143022-a7xq │
│ 5 candidates • 3 recommended for action • Est. 2.4 GB recoverable       │
├────────────────────────────────┬─────────────────────────────────────────┤
│ CANDIDATES                     │ DETAILS                                 │
│ ────────────                   │ ───────                                 │
│                                │                                         │
│ [x] ● 15234 jest --watch       │ PID: 15234                             │
│     ↳ 98% abandoned, 2.1 GB    │ Command: node .../jest --watch         │
│                                │ Runtime: 3d 14h 22m                    │
│ [x] ● 8821 next dev            │ User: alice                            │
│     ↳ 92% abandoned, 340 MB    │ CWD: ~/projects/webapp                 │
│                                │ Memory: 2.1 GB RSS                     │
│ [x] ○ 9012 vite                │ CPU: 0.1% (avg 0.3%)                   │
│     ↳ 85% abandoned, 180 MB    │                                         │
│                                │ ── Evidence ──────────────────────────  │
│ [ ] ○ 4521 python manage.py    │ • No TTY attachment [+0.8]             │
│     ↳ 45% review, 120 MB       │ • Orphaned (PPID=1) [+0.6]             │
│                                │ • Category: test runner [+0.4]         │
│ [ ] ○ 7891 cargo build         │ • 3d runtime exceeds typical [+0.3]    │
│     ↳ 32% review, 890 MB       │ • Low CPU activity [+0.2]              │
│                                │                                         │
│                                │ Recommendation: KILL                    │
│                                │ Confidence: HIGH (σ < 0.05)            │
│                                │                                         │
│                                │ [g] Galaxy-brain mode                   │
├────────────────────────────────┴─────────────────────────────────────────┤
│ [Space] Toggle  [↑↓] Navigate  [Enter] Details  [a] Apply  [q] Quit     │
└──────────────────────────────────────────────────────────────────────────┘
```

### Visual Language

| Symbol | Meaning |
|--------|---------|
| `●` | Recommended for action (kill/pause) |
| `○` | Review - uncertain, needs human judgment |
| `◌` | Spare - probably safe to keep |
| `[x]` | Selected for action |
| `[ ]` | Not selected |
| `↳` | Subprocess/context indicator |

### Color Scheme

| Element | Color | Meaning |
|---------|-------|---------|
| Red/Orange | `●` badge | High confidence kill recommendation |
| Yellow | `○` badge | Review needed |
| Green | `◌` badge | Safe/spare |
| Cyan | Session ID | Informational |
| White | Normal text | Content |
| Dim | Metadata | Secondary information |

---

## Expert Mode Access

Expert features are accessible without cluttering the default experience:

### Via Flags

```bash
# Quick scan only (no inference/plan)
pt scan

# Force deep scan on all processes
pt run --deep

# Goal-oriented mode
pt run --goal "free 2GB RAM"

# Differential mode (compare to previous)
pt run --since pt-20260114-093022-b3xk

# Robot mode (non-interactive)
pt run --robot --yes

# Shadow mode (dry run with full pipeline)
pt run --shadow
```

### Via TUI Hotkeys

| Key | Action | Notes |
|-----|--------|-------|
| `g` | Toggle galaxy-brain mode | Show full math derivation |
| `d` | Toggle deep scan view | Show probe results |
| `t` | Toggle tree view | Show process hierarchy |
| `f` | Filter menu | Filter by category/status |
| `/` | Search | Search by PID/command |
| `?` | Help overlay | Show all keyboard shortcuts |

### Via Subcommands

```bash
# Expert subcommands available but not in default path
pt scan              # Scan only
pt infer             # Run inference on session
pt decide            # Generate plan from inference
pt ui                # Launch TUI for session
pt agent plan        # Agent-optimized interface
pt daemon            # Background monitoring
pt history           # View past sessions
```

---

## Session Persistence

### Artifact Directory Structure

Every run creates a session directory:

```
~/.local/share/process_triage/sessions/pt-20260115-143022-a7xq/
├── capabilities.json      # Detected capabilities
├── scan_quick.json        # Quick scan results
├── scan_deep.json         # Deep scan results (if run)
├── inference.json         # Inference results
├── plan.json              # Generated plan
├── execution.json         # Execution log (if actions taken)
├── outcomes.json          # Verification results
├── metadata.json          # Session metadata
└── telemetry.parquet      # Detailed telemetry (partitioned)
```

### Session Lifecycle

```
                    ┌─────────────┐
         create     │   ACTIVE    │ ◀─── pt run, pt scan, etc.
            │       │             │
            ▼       └──────┬──────┘
       ┌─────────┐         │
       │ PENDING │─────────┤ quit without action
       │         │         │
       └────┬────┘         │
            │              │
            │ pt resume    │ apply actions
            ▼              ▼
       ┌─────────┐    ┌─────────┐
       │ RESUMED │───▶│COMPLETED│
       └─────────┘    └─────────┘
            │              │
            │              ▼
            │        ┌─────────┐
            └───────▶│ARCHIVED │ ◀─── 7 day retention
                     └─────────┘
```

### Resume Capability

Interrupted or pending sessions can be resumed:

```bash
# Resume most recent pending session
pt resume

# Resume specific session
pt resume pt-20260115-143022-a7xq

# List pending sessions
pt sessions --pending
```

---

## Interruption Handling

### Ctrl+C Behavior

| Stage | Ctrl+C Action | Recovery |
|-------|--------------|----------|
| Scanning | Stop scan, save partial results | `pt resume` continues from last sample |
| Inference | Complete current computation, exit | `pt resume` uses completed inference |
| TUI | Exit TUI, preserve plan | `pt resume` shows plan again |
| Execution | Stop between phases | `pt resume` continues from last phase |

### Signal Handling

```
SIGINT (Ctrl+C)  → Graceful shutdown, save state
SIGTERM          → Graceful shutdown, save state
SIGQUIT          → Immediate exit, partial state save
SIGHUP           → Ignored in foreground, terminates in background
```

---

## Error States

### Common Error Flows

```
┌─────────────────────────────────────────────────────────────────────────┐
│ ERROR: No candidates found                                              │
│                                                                         │
│ System appears clean. No processes matched triage criteria.             │
│                                                                         │
│ If this is unexpected, try:                                             │
│   • Lower minimum age: pt run --min-age 300                            │
│   • Force deep scan: pt run --deep                                      │
│   • Check specific PIDs: pt explain --pid 1234                         │
│                                                                         │
│ Session saved: pt-20260115-143022-a7xq                                  │
│ Exit code: 0 (CLEAN)                                                    │
└─────────────────────────────────────────────────────────────────────────┘
```

```
┌─────────────────────────────────────────────────────────────────────────┐
│ ERROR: Insufficient privileges                                          │
│                                                                         │
│ Some probes require elevated privileges:                                │
│   • perf: requires perf_event_paranoid ≤ 2                             │
│   • lsof: some process info requires same UID or root                  │
│                                                                         │
│ Options:                                                                 │
│   • Run with sudo: sudo pt run                                         │
│   • Continue with reduced capability: pt run --standalone               │
│                                                                         │
│ Exit code: 10 (CAPABILITY_ERROR)                                        │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Mode Summary

| Mode | Invocation | Behavior |
|------|------------|----------|
| **Default** | `pt` or `pt run` | Full golden path with TUI approval |
| **Scan only** | `pt scan` | Quick scan, no inference or actions |
| **Robot** | `pt run --robot --yes` | Non-interactive, execute policy-approved |
| **Shadow** | `pt run --shadow` | Full pipeline, no execution (calibration) |
| **Dry-run** | `pt run --dry-run` | Compute plan, show what would happen |
| **Goal** | `pt run --goal "..."` | Target-oriented resource recovery |
| **Differential** | `pt run --since <id>` | Compare to previous session |
| **Resume** | `pt resume` | Continue interrupted session |
| **Agent** | `pt agent plan` | Token-efficient agent interface |
| **Daemon** | `pt daemon` | Background monitoring mode |

---

## Acceptance Criteria

- [ ] Default `pt` runs the complete golden path without additional flags
- [ ] Every run creates a durable session with artifacts
- [ ] Progress is visible during all computational phases
- [ ] TUI approval is required before any destructive action
- [ ] Execution is staged with verification between phases
- [ ] Sessions can be interrupted and resumed
- [ ] Expert features are accessible without modifying defaults
- [ ] Exit codes accurately reflect outcomes
- [ ] Error states provide actionable guidance

---

## Test Plan

### Unit Tests
- State machine transitions
- Session directory creation
- Progress bar rendering

### Integration Tests
- Full golden path with mock process data
- Interrupt and resume flow
- TUI keyboard navigation

### E2E Tests
- Real process scanning on test system
- Before/after verification
- Session export and reload

---

## References

- CLI Specification: `docs/CLI_SPECIFICATION.md`
- Session Model: `docs/schemas/session.schema.json`
- TUI Layout: `process_triage-6sfz`
- Plan Section 7.0 mapping: `docs/PLAN_UX_EXPLAINABILITY_MAPPING.md`
