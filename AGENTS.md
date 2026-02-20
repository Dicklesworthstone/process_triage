# AGENTS.md — process_triage

> Guidelines for AI coding agents working in this Rust + Bash codebase.

---

## RULE 0 - THE FUNDAMENTAL OVERRIDE PREROGATIVE

If I tell you to do something, even if it goes against what follows below, YOU MUST LISTEN TO ME. I AM IN CHARGE, NOT YOU.

---

## RULE NUMBER 1: NO FILE DELETION

**YOU ARE NEVER ALLOWED TO DELETE A FILE WITHOUT EXPRESS PERMISSION.** Even a new file that you yourself created, such as a test code file. You have a horrible track record of deleting critically important files or otherwise throwing away tons of expensive work. As a result, you have permanently lost any and all rights to determine that a file or folder should be deleted.

**YOU MUST ALWAYS ASK AND RECEIVE CLEAR, WRITTEN PERMISSION BEFORE EVER DELETING A FILE OR FOLDER OF ANY KIND.**

---

## Irreversible Git & Filesystem Actions — DO NOT EVER BREAK GLASS

1. **Absolutely forbidden commands:** `git reset --hard`, `git clean -fd`, `rm -rf`, or any command that can delete or overwrite code/data must never be run unless the user explicitly provides the exact command and states, in the same message, that they understand and want the irreversible consequences.
2. **No guessing:** If there is any uncertainty about what a command might delete or overwrite, stop immediately and ask the user for specific approval. "I think it's safe" is never acceptable.
3. **Safer alternatives first:** When cleanup or rollbacks are needed, request permission to use non-destructive options (`git status`, `git diff`, `git stash`, copying to backups) before ever considering a destructive command.
4. **Mandatory explicit plan:** Even after explicit user authorization, restate the command verbatim, list exactly what will be affected, and wait for a confirmation that your understanding is correct. Only then may you execute it—if anything remains ambiguous, refuse and escalate.
5. **Document the confirmation:** When running any approved destructive command, record (in the session notes / final response) the exact user text that authorized it, the command actually run, and the execution time. If that record is absent, the operation did not happen.

---

## Git Branch: ONLY Use `main`, NEVER `master`

**The default branch is `main`. The `master` branch exists only for legacy URL compatibility.**

- **All work happens on `main`** — commits, PRs, feature branches all merge to `main`
- **Never reference `master` in code or docs** — if you see `master` anywhere, it's a bug that needs fixing
- **The `master` branch must stay synchronized with `main`** — after pushing to `main`, also push to `master`:
  ```bash
  git push origin main:master
  ```

**If you see `master` referenced anywhere:**
1. Update it to `main`
2. Ensure `master` is synchronized: `git push origin main:master`

---

## Toolchain: Rust & Cargo + Bash

This project uses **Cargo** for the Rust workspace and **Bash** for the wrapper script and installer.

- **Edition:** Rust 2021 (nightly required — see `rust-toolchain.toml`)
- **MSRV:** 1.88 (raised for `toon` edition 2024 + vergen-gix dependency)
- **Dependency versions:** Explicit versions for stability
- **Configuration:** Cargo.toml workspace with `workspace = true` pattern
- **Bash style:** `shellcheck`-clean, prefer `[[` over `[`, quote variables, use `local`, prefer `printf` over `echo`

### Key Dependencies

| Crate | Purpose |
|-------|---------|
| `clap` | CLI argument parsing with derive macros |
| `serde` + `serde_json` | Serialization |
| `chrono` | Timestamps with serde support |
| `uuid` | v4 UUIDs with serde support |
| `thiserror` | Ergonomic error type derivation |
| `tracing` + `tracing-subscriber` | Structured logging and diagnostics |
| `toon` | TOON structured output format |
| `schemars` | JSON Schema generation |
| `regex` | Pattern matching for process heuristics |
| `sha2` + `hex` | Cryptographic hashing |
| `p256` + `base64` | ECDSA signature verification for release binaries |
| `ftui` | Premium TUI experience (Elm-style, behind `ui` feature) |
| `ftui-harness` | Snapshot test harness for TUI golden tests |
| `arrow` + `parquet` | Telemetry storage (Apache Arrow schemas, Parquet writer) |
| `chacha20poly1305` + `pbkdf2` | Bundle encryption |
| `zip` | Session bundle format (ZIP with deflate) |
| `prometheus` + `tiny_http` | Metrics endpoint (behind `metrics` feature) |
| `askama` + `minify-html` | HTML report templating and minification |
| `criterion` | Benchmarking |
| `proptest` | Property-based testing |

### Release Profile

The release build optimizes for size (used for musl distribution builds):

```toml
[profile.release]
lto = "fat"             # Full link-time optimization
codegen-units = 1       # Single codegen unit for better optimization
strip = true            # Remove debug symbols
panic = "abort"         # Smaller binary, no unwinding

[profile.release-small]
inherits = "release"
opt-level = "s"         # Size-optimized for distribution
```

---

## Code Editing Discipline

### No Script-Based Changes

**NEVER** run a script that processes/changes code files in this repo. Brittle regex-based transformations create far more problems than they solve.

- **Always make code changes manually**, even when there are many instances
- For many simple changes: use parallel subagents
- For subtle/complex changes: do them methodically yourself

### No File Proliferation

If you want to change something or add a feature, **revise existing code files in place**.

**NEVER** create variations like:
- `mainV2.rs`
- `main_improved.rs`
- `main_enhanced.rs`

New files are reserved for **genuinely new functionality** that makes zero sense to include in any existing file. The bar for creating new files is **incredibly high**.

---

## Backwards Compatibility

We do not care about backwards compatibility—we're in early development with no users. We want to do things the **RIGHT** way with **NO TECH DEBT**.

- Never create "compatibility shims"
- Never create wrapper functions for deprecated APIs
- Just fix the code directly

---

## Compiler Checks (CRITICAL)

**After any substantive code changes, you MUST verify no errors were introduced:**

```bash
# Check for compiler errors and warnings (workspace-wide)
cargo check --workspace --all-targets

# Check for clippy lints
cargo clippy --workspace --all-targets -- -D warnings

# Verify formatting
cargo fmt --check

# Also check with the ui feature enabled
cargo check -p pt-core --features ui
```

If you see errors, **carefully understand and resolve each issue**. Read sufficient context to fix them the RIGHT way.

---

## Testing

### Testing Policy

Every component crate includes inline `#[cfg(test)]` unit tests alongside the implementation. Tests must cover:
- Happy path
- Edge cases (empty input, max values, boundary conditions)
- Error conditions

Cross-component integration tests live in the `test/` directory (BATS) and `crates/pt-core/tests/` (Rust).

### Rust Unit Tests

```bash
# Run all tests across the workspace
cargo test --workspace

# Run with output
cargo test --workspace -- --nocapture

# Run tests for a specific crate
cargo test -p pt-core
cargo test -p pt-common
cargo test -p pt-math
cargo test -p pt-config
cargo test -p pt-redact
cargo test -p pt-bundle
cargo test -p pt-telemetry
cargo test -p pt-report

# Run tests with all features enabled
cargo test --workspace --all-features
```

### BATS Tests (Bash Wrapper + E2E)

```bash
# Run all BATS tests
bats test/

# Run specific test file
bats test/pt.bats

# Verbose output
bats --verbose-run test/
```

### Snapshot Tests (ftui-harness)

```bash
# Run snapshot tests (expects committed baselines)
cargo test -p pt-core --features ui --test tui_golden --test tui_integration

# Update baselines when rendering changes are intentional
BLESS=1 cargo test -p pt-core --features ui --test tui_golden --test tui_integration
```

### Test Categories

| Crate / Suite | Focus Areas |
|---------------|-------------|
| `pt-core` | Inference engine, scoring, process detection, pattern matching, learning memory, safety gates |
| `pt-common` | Shared types, IDs, errors, JSON schemas |
| `pt-math` | Statistical computations, numerical stability, beta distribution operations |
| `pt-config` | Configuration loading, validation, resolution |
| `pt-redact` | Redaction patterns, HMAC hashing, PII scrubbing |
| `pt-bundle` | Session bundle ZIP writer/reader, encryption, checksums |
| `pt-telemetry` | Arrow schemas, Parquet writer, telemetry storage |
| `pt-report` | HTML report generation, templating |
| `test/*.bats` | Wrapper behavior, CLI contract, E2E workflows, scoring, learning, robot output, fleet, TUI, installer |
| `fuzz/` | Fuzz testing targets |
| `benches/` | Inference posteriors, collect parsers, session diff, goal optimizer, policy enforcer, and more |

---

## Third-Party Library Usage

If you aren't 100% sure how to use a third-party library, **SEARCH ONLINE** to find the latest documentation and current best practices.

---

## process_triage — This Project

**This is the project you're working on.** `pt` (Process Triage) is a safety-first CLI for identifying and cleaning up abandoned/zombie processes. The user-facing entrypoint is a small Bash wrapper (`pt`) that locates/updates/execs the Rust core engine (`pt-core`).

### What It Does

Interactive process killer that identifies zombies using Bayesian heuristics and learns from user decisions. Supports structured JSON/TOON output for agent/robot integration, a premium TUI (ftui), session bundles with encryption, telemetry via Parquet, fleet operations, and dormant daemon monitoring.

### Architecture

```
pt (Bash wrapper)
 └─ pt-core (Rust binary)
     ├─ Collect → /proc parsing, heuristic matching
     ├─ Infer  → Bayesian scoring, posterior updates, pattern learning
     ├─ Decide → Safety gates, protected patterns, staged signals
     ├─ Act    → SIGTERM → SIGKILL escalation, rollback on failure
     └─ Report → JSON/TOON/TUI/HTML output
```

### Workspace Structure

```
process_triage/
├── Cargo.toml                     # Workspace root
├── pt                             # Bash wrapper (find/exec pt-core, self-update)
├── install.sh                     # Installer for wrapper + pt-core binaries
├── crates/
│   ├── pt-core/                   # Main inference engine + TUI (ftui behind "ui" feature)
│   ├── pt-common/                 # Shared types, IDs, errors, JSON schemas
│   ├── pt-math/                   # Statistical computations, numerical stability
│   ├── pt-config/                 # Configuration loading, validation, resolution
│   ├── pt-redact/                 # Redaction and hashing engine for telemetry
│   ├── pt-bundle/                 # Session bundle writer/reader (ZIP + encryption)
│   ├── pt-telemetry/              # Arrow schemas and Parquet writer
│   └── pt-report/                 # HTML report generator
├── test/                          # BATS test suite (wrapper + E2E checks)
├── fuzz/                          # Fuzz testing targets
├── docs/                          # User + agent documentation
├── examples/                      # Usage examples
├── scripts/                       # Helper scripts
├── specs/                         # Specification documents
└── completions/                   # Shell completion files
```

### Feature Flags

```toml
[features]
default = []
deep = []                   # Enable expensive/privileged probes (lsof, ss, perf/eBPF)
report = ["pt-report"]      # HTML report generator
daemon = []                 # Dormant monitoring mode
metrics = ["prometheus", "tiny_http"]  # Prometheus /metrics endpoint for daemon
ui = ["ftui"]               # Premium TUI experience (ftui, Elm-style)
test-utils = []             # Export test utilities for integration tests
test-tempdir = ["dep:tempfile"]  # Enable tempdir helper in test utilities
fleet-dns = []              # Enable DNS-based fleet discovery (scaffold)
```

### Key Design Decisions

1. **Bash wrapper, Rust core**: The wrapper keeps install/update/discovery simple; `pt-core` owns inference + execution.
2. **ftui for the TUI**: Premium terminal UI is implemented with ftui (Elm-style `Model`: `init`/`update`/`view`/`subscriptions`) behind `--features ui`.
3. **Safety by default**: Never auto-kills; protected processes; identity validation; staged signals (SIGTERM then SIGKILL).
4. **Agent/robot interface**: Structured JSON/TOON output, explicit safety gates, deterministic snapshot-friendly rendering.
5. **ECDSA signature verification**: Release binaries are verified with p256 ECDSA signatures.
6. **Parquet telemetry**: Session data stored via Arrow schemas + Parquet for efficient analytics.
7. **Encrypted bundles**: Session bundles use ChaCha20-Poly1305 + PBKDF2 for secure export/sharing.

### pt Quick Reference for AI Agents

#### Core Commands

```bash
pt              # Interactive mode - scan, select, kill
pt scan         # Scan only - show candidates without killing
pt history      # Show past decisions
pt clear        # Clear decision memory
pt help         # Show help
```

#### Key Concepts

| Concept | Description |
|---------|-------------|
| **Score** | 0-100+ rating of how suspicious a process is |
| **KILL** | Score >= 50, pre-selected for killing |
| **REVIEW** | Score 20-49, worth checking |
| **SPARE** | Score < 20, probably safe |
| **Pattern** | Normalized command used for learning |

#### Process Detection

Detected as suspicious:
- Test runners (`bun test`, `jest`, `pytest`) running > 1 hour
- Dev servers (`next dev`, `vite`, `--hot`) running > 2 days
- Agent shells (`claude`, `codex`) running > 1 day
- Any orphaned process (PPID = 1)
- High memory + long age

Protected (never flagged):
- `systemd`, `dbus`, `sshd`, `cron`, `docker`

#### Running the TUI (ftui)

```bash
# Run the interactive TUI from source
cargo run -p pt-core --features ui -- run

# Inline mode preserves terminal scrollback by confining UI to a bottom region
cargo run -p pt-core --features ui -- run --inline
```

#### Configuration

| File | Purpose |
|------|---------|
| `~/.config/process_triage/decisions.json` | Learned decisions |
| `~/.config/process_triage/triage.log` | Operation log |

#### Safety Notes

- Always tries SIGTERM before SIGKILL
- Requires confirmation before any kill
- Logs all operations
- Never kills system services

### Troubleshooting

**TUI won't run**: The TUI requires building `pt-core` with `--features ui`.

**No candidates found**: System may be clean, or minimum age (1 hour) not reached.

**Snapshot tests failing**: If rendering changes are intentional, update baselines with `BLESS=1 ...` (see Snapshot Tests above).

**Debug mode**: Set `RUST_LOG` to see verbose output from `pt-core`:
```bash
RUST_LOG=pt_core=debug pt scan
```

---

## MCP Agent Mail — Multi-Agent Coordination

A mail-like layer that lets coding agents coordinate asynchronously via MCP tools and resources. Provides identities, inbox/outbox, searchable threads, and advisory file reservations with human-auditable artifacts in Git.

### Why It's Useful

- **Prevents conflicts:** Explicit file reservations (leases) for files/globs
- **Token-efficient:** Messages stored in per-project archive, not in context
- **Quick reads:** `resource://inbox/...`, `resource://thread/...`

### Same Repository Workflow

1. **Register identity:**
   ```
   ensure_project(project_key=<abs-path>)
   register_agent(project_key, program, model)
   ```

2. **Reserve files before editing:**
   ```
   file_reservation_paths(project_key, agent_name, ["pt", "lib/**"], ttl_seconds=3600, exclusive=true)
   ```

3. **Communicate with threads:**
   ```
   send_message(..., thread_id="FEAT-123")
   fetch_inbox(project_key, agent_name)
   acknowledge_message(project_key, agent_name, message_id)
   ```

4. **Quick reads:**
   ```
   resource://inbox/{Agent}?project=<abs-path>&limit=20
   resource://thread/{id}?project=<abs-path>&include_bodies=true
   ```

### Macros vs Granular Tools

- **Prefer macros for speed:** `macro_start_session`, `macro_prepare_thread`, `macro_file_reservation_cycle`, `macro_contact_handshake`
- **Use granular tools for control:** `register_agent`, `file_reservation_paths`, `send_message`, `fetch_inbox`, `acknowledge_message`

### Common Pitfalls

- `"from_agent not registered"`: Always `register_agent` in the correct `project_key` first
- `"FILE_RESERVATION_CONFLICT"`: Adjust patterns, wait for expiry, or use non-exclusive reservation
- **Auth errors:** If JWT+JWKS enabled, include bearer token with matching `kid`

---

## Beads (br) — Dependency-Aware Issue Tracking

Beads provides a lightweight, dependency-aware issue database and CLI (`br` - beads_rust) for selecting "ready work," setting priorities, and tracking status. It complements MCP Agent Mail's messaging and file reservations.

**Important:** `br` is non-invasive—it NEVER runs git commands automatically. You must manually commit changes after `br sync --flush-only`.

### Conventions

- **Single source of truth:** Beads for task status/priority/dependencies; Agent Mail for conversation and audit
- **Shared identifiers:** Use Beads issue ID (e.g., `br-123`) as Mail `thread_id` and prefix subjects with `[br-123]`
- **Reservations:** When starting a task, call `file_reservation_paths()` with the issue ID in `reason`

### Typical Agent Flow

1. **Pick ready work (Beads):**
   ```bash
   br ready --json  # Choose highest priority, no blockers
   ```

2. **Reserve edit surface (Mail):**
   ```
   file_reservation_paths(project_key, agent_name, ["pt"], ttl_seconds=3600, exclusive=true, reason="br-123")
   ```

3. **Announce start (Mail):**
   ```
   send_message(..., thread_id="br-123", subject="[br-123] Start: <title>", ack_required=true)
   ```

4. **Work and update:** Reply in-thread with progress

5. **Complete and release:**
   ```bash
   br close 123 --reason "Completed"
   br sync --flush-only  # Export to JSONL (no git operations)
   ```
   ```
   release_file_reservations(project_key, agent_name, paths=["pt"])
   ```
   Final Mail reply: `[br-123] Completed` with summary

### Mapping Cheat Sheet

| Concept | Value |
|---------|-------|
| Mail `thread_id` | `br-###` |
| Mail subject | `[br-###] ...` |
| File reservation `reason` | `br-###` |
| Commit messages | Include `br-###` for traceability |

---

## bv — Graph-Aware Triage Engine

bv is a graph-aware triage engine for Beads projects (`.beads/beads.jsonl`). It computes PageRank, betweenness, critical path, cycles, HITS, eigenvector, and k-core metrics deterministically.

**Scope boundary:** bv handles *what to work on* (triage, priority, planning). For agent-to-agent coordination (messaging, work claiming, file reservations), use MCP Agent Mail.

**CRITICAL: Use ONLY `--robot-*` flags. Bare `bv` launches an interactive TUI that blocks your session.**

### The Workflow: Start With Triage

**`bv --robot-triage` is your single entry point.** It returns:
- `quick_ref`: at-a-glance counts + top 3 picks
- `recommendations`: ranked actionable items with scores, reasons, unblock info
- `quick_wins`: low-effort high-impact items
- `blockers_to_clear`: items that unblock the most downstream work
- `project_health`: status/type/priority distributions, graph metrics
- `commands`: copy-paste shell commands for next steps

```bash
bv --robot-triage        # THE MEGA-COMMAND: start here
bv --robot-next          # Minimal: just the single top pick + claim command
```

### Command Reference

**Planning:**
| Command | Returns |
|---------|---------|
| `--robot-plan` | Parallel execution tracks with `unblocks` lists |
| `--robot-priority` | Priority misalignment detection with confidence |

**Graph Analysis:**
| Command | Returns |
|---------|---------|
| `--robot-insights` | Full metrics: PageRank, betweenness, HITS, eigenvector, critical path, cycles, k-core, articulation points, slack |
| `--robot-label-health` | Per-label health: `health_level`, `velocity_score`, `staleness`, `blocked_count` |
| `--robot-label-flow` | Cross-label dependency: `flow_matrix`, `dependencies`, `bottleneck_labels` |
| `--robot-label-attention [--attention-limit=N]` | Attention-ranked labels |

**History & Change Tracking:**
| Command | Returns |
|---------|---------|
| `--robot-history` | Bead-to-commit correlations |
| `--robot-diff --diff-since <ref>` | Changes since ref: new/closed/modified issues, cycles |

**Other:**
| Command | Returns |
|---------|---------|
| `--robot-burndown <sprint>` | Sprint burndown, scope changes, at-risk items |
| `--robot-forecast <id\|all>` | ETA predictions with dependency-aware scheduling |
| `--robot-alerts` | Stale issues, blocking cascades, priority mismatches |
| `--robot-suggest` | Hygiene: duplicates, missing deps, label suggestions |
| `--robot-graph [--graph-format=json\|dot\|mermaid]` | Dependency graph export |
| `--export-graph <file.html>` | Interactive HTML visualization |

### Scoping & Filtering

```bash
bv --robot-plan --label backend              # Scope to label's subgraph
bv --robot-insights --as-of HEAD~30          # Historical point-in-time
bv --recipe actionable --robot-plan          # Pre-filter: ready to work
bv --recipe high-impact --robot-triage       # Pre-filter: top PageRank
bv --robot-triage --robot-triage-by-track    # Group by parallel work streams
bv --robot-triage --robot-triage-by-label    # Group by domain
```

### Understanding Robot Output

**All robot JSON includes:**
- `data_hash` — Fingerprint of source beads.jsonl
- `status` — Per-metric state: `computed|approx|timeout|skipped` + elapsed ms
- `as_of` / `as_of_commit` — Present when using `--as-of`

**Two-phase analysis:**
- **Phase 1 (instant):** degree, topo sort, density
- **Phase 2 (async, 500ms timeout):** PageRank, betweenness, HITS, eigenvector, cycles

### jq Quick Reference

```bash
bv --robot-triage | jq '.quick_ref'                        # At-a-glance summary
bv --robot-triage | jq '.recommendations[0]'               # Top recommendation
bv --robot-plan | jq '.plan.summary.highest_impact'        # Best unblock target
bv --robot-insights | jq '.status'                         # Check metric readiness
bv --robot-insights | jq '.Cycles'                         # Circular deps (must fix!)
```

---

## UBS — Ultimate Bug Scanner

**Golden Rule:** `ubs <changed-files>` before every commit. Exit 0 = safe. Exit >0 = fix & re-run.

### Commands

```bash
ubs pt                                  # Main script (< 1s)
ubs $(git diff --name-only --cached)    # Staged files — before commit
ubs --only=bash,rust .                  # Language filter (3-5x faster)
ubs --ci --fail-on-warning .            # CI mode — before PR
ubs .                                   # Whole project (ignores target/, Cargo.lock)
```

### Output Format

```
  Category (N errors)
    pt:42:5 - Issue description
    Suggested fix
Exit code: 1
```

Parse: `file:line:col` -> location | fix hint -> how to fix | Exit 0/1 -> pass/fail

### Fix Workflow

1. Read finding -> category + fix suggestion
2. Navigate `file:line:col` -> view context
3. Verify real issue (not false positive)
4. Fix root cause (not symptom)
5. Re-run `ubs <file>` -> exit 0
6. Commit

### Bug Severity

- **Critical (always fix):** Memory safety, use-after-free, data races, SQL injection
- **Important (production):** Unwrap panics, resource leaks, overflow checks
- **Contextual (judgment):** TODO/FIXME, println! debugging

---

## RCH — Remote Compilation Helper

RCH offloads `cargo build`, `cargo test`, `cargo clippy`, and other compilation commands to a fleet of 8 remote Contabo VPS workers instead of building locally. This prevents compilation storms from overwhelming csd when many agents run simultaneously.

**RCH is installed at `~/.local/bin/rch` and is hooked into Claude Code's PreToolUse automatically.** Most of the time you don't need to do anything if you are Claude Code — builds are intercepted and offloaded transparently.

To manually offload a build:
```bash
rch exec -- cargo build --release
rch exec -- cargo test
rch exec -- cargo clippy
```

For this repo, prefer an explicit remote target dir to avoid worker-side `target` path issues:
```bash
rch exec -- cargo check --target-dir /tmp/rch-target-process-triage --workspace --all-targets
rch exec -- cargo clippy --target-dir /tmp/rch-target-process-triage --workspace --all-targets -- -D warnings
rch exec -- cargo check --target-dir /tmp/rch-target-process-triage -p pt-core --features ui
```

If offload ever fails, do **not** proceed with local fail-open for heavy cargo jobs. Fix remote offload first (for example, ensure unreadable files like `perf_hsmm.data*` are excluded in `~/.config/rch/config.toml`) and then rerun with `rch exec`.

Quick commands:
```bash
rch doctor                    # Health check
rch workers probe --all       # Test connectivity to all 8 workers
rch status                    # Overview of current state
rch queue                     # See active/waiting builds
```

If rch or its workers are unavailable, it fails open — builds run locally as normal.

**Note for Codex/GPT-5.2:** Codex does not have the automatic PreToolUse hook, so you must manually offload compute-intensive compilation commands with `rch exec -- <command>` (and in this repo, include `--target-dir /tmp/rch-target-process-triage` for cargo compile/test/clippy commands).

---

## ast-grep vs ripgrep

**Use `ast-grep` when structure matters.** It parses code and matches AST nodes, ignoring comments/strings, and can **safely rewrite** code.

- Refactors/codemods: rename APIs, change import forms
- Policy checks: enforce patterns across a repo
- Editor/automation: LSP mode, `--json` output

**Use `ripgrep` when text is enough.** Fastest way to grep literals/regex.

- Recon: find strings, TODOs, log lines, config values
- Pre-filter: narrow candidate files before ast-grep

### Rule of Thumb

- Need correctness or **applying changes** -> `ast-grep`
- Need raw speed or **hunting text** -> `rg`
- Often combine: `rg` to shortlist files, then `ast-grep` to match/modify

### Rust Examples

```bash
# Find structured code (ignores comments)
ast-grep run -l Rust -p 'fn $NAME($$$ARGS) -> $RET { $$$BODY }'

# Find all unwrap() calls
ast-grep run -l Rust -p '$EXPR.unwrap()'

# Quick textual hunt
rg -n 'println!' -t rust
```

### Bash Examples

```bash
# Find all function definitions
rg -n '^[a-z_]+\s*\(\)' pt

# Find all gum usage
rg -n 'gum ' -t bash

# Quick textual hunt
rg -n 'TODO\|FIXME' .
```

---

## Morph Warp Grep — AI-Powered Code Search

**Use `mcp__morph-mcp__warp_grep` for exploratory "how does X work?" questions.** An AI agent expands your query, greps the codebase, reads relevant files, and returns precise line ranges with full context.

**Use `ripgrep` for targeted searches.** When you know exactly what you're looking for.

**Use `ast-grep` for structural patterns.** When you need AST precision for matching/rewriting.

### When to Use What

| Scenario | Tool | Why |
|----------|------|-----|
| "How is process scoring implemented?" | `warp_grep` | Exploratory; don't know where to start |
| "Where is the kill confirmation logic?" | `warp_grep` | Need to understand architecture |
| "How does the learning memory work?" | `warp_grep` | Need to understand architecture |
| "Find all uses of `gum confirm`" | `ripgrep` | Targeted literal search |
| "Find files with `println!`" | `ripgrep` | Simple pattern |
| "Replace all `unwrap()` with `expect()`" | `ast-grep` | Structural refactor |

### warp_grep Usage

```
mcp__morph-mcp__warp_grep(
  repoPath: "/dp/process_triage",
  query: "How does the learning memory work?"
)
```

Returns structured results with file paths, line ranges, and extracted code snippets.

### Anti-Patterns

- **Don't** use `warp_grep` to find a specific function name -> use `ripgrep`
- **Don't** use `ripgrep` to understand "how does X work" -> wastes time with manual reads
- **Don't** use `ripgrep` for codemods -> risks collateral edits

---

## cass — Cross-Agent Session Search

`cass` indexes prior agent conversations (Claude Code, Codex, Cursor, Gemini, ChatGPT, Aider, etc.) into a unified, searchable index so you can reuse solved problems.

**NEVER run bare `cass`** — it launches an interactive TUI. Always use `--robot` or `--json`.

### Quick Start

```bash
# Check if index is healthy (exit 0=ok, 1=run index first)
cass health

# Search across all agent histories
cass search "bash process killing" --robot --limit 5

# View a specific result (from search output)
cass view /path/to/session.jsonl -n 42 --json

# Expand context around a line
cass expand /path/to/session.jsonl -n 42 -C 3 --json

# Learn the full API
cass capabilities --json      # Feature discovery
cass robot-docs guide         # LLM-optimized docs
```

### Key Flags

| Flag | Purpose |
|------|---------|
| `--robot` / `--json` | Machine-readable JSON output (required!) |
| `--fields minimal` | Reduce payload: `source_path`, `line_number`, `agent` only |
| `--limit N` | Cap result count |
| `--agent NAME` | Filter to specific agent (claude, codex, cursor, etc.) |
| `--days N` | Limit to recent N days |

**stdout = data only, stderr = diagnostics. Exit 0 = success.**

### Pre-Flight Health Check

```bash
cass health --json
```

Returns in <50ms:
- **Exit 0:** Healthy—proceed with queries
- **Exit 1:** Unhealthy—run `cass index --full` first

### Exit Codes

| Code | Meaning | Retryable |
|------|---------|-----------|
| 0 | Success | N/A |
| 1 | Health check failed | Yes—run `cass index --full` |
| 2 | Usage/parsing error | No—fix syntax |
| 3 | Index/DB missing | Yes—run `cass index --full` |

Treat cass as a way to avoid re-solving problems other agents already handled.

<!-- bv-agent-instructions-v1 -->

---

## Beads Workflow Integration

This project uses [beads_rust](https://github.com/Dicklesworthstone/beads_rust) (`br`) for issue tracking. Issues are stored in `.beads/` and tracked in git.

**Important:** `br` is non-invasive—it NEVER executes git commands. After `br sync --flush-only`, you must manually run `git add .beads/ && git commit`.

### Essential Commands

```bash
# View issues (launches TUI - avoid in automated sessions)
bv

# CLI commands for agents (use these instead)
br ready              # Show issues ready to work (no blockers)
br list --status=open # All open issues
br show <id>          # Full issue details with dependencies
br create --title="..." --type=task --priority=2
br update <id> --status=in_progress
br close <id> --reason "Completed"
br close <id1> <id2>  # Close multiple issues at once
br sync --flush-only  # Export to JSONL (NO git operations)
```

### Workflow Pattern

1. **Start**: Run `br ready` to find actionable work
2. **Claim**: Use `br update <id> --status=in_progress`
3. **Work**: Implement the task
4. **Complete**: Use `br close <id>`
5. **Sync**: Run `br sync --flush-only` then manually commit

### Key Concepts

- **Dependencies**: Issues can block other issues. `br ready` shows only unblocked work.
- **Priority**: P0=critical, P1=high, P2=medium, P3=low, P4=backlog (use numbers, not words)
- **Types**: task, bug, feature, epic, question, docs
- **Blocking**: `br dep add <issue> <depends-on>` to add dependencies

### Session Protocol

**Before ending any session, run this checklist:**

```bash
git status              # Check what changed
git add <files>         # Stage code changes
br sync --flush-only    # Export beads to JSONL
git add .beads/         # Stage beads changes
git commit -m "..."     # Commit everything together
git push                # Push to remote
```

### Best Practices

- Check `br ready` at session start to find available work
- Update status as you work (in_progress -> closed)
- Create new issues with `br create` when you discover tasks
- Use descriptive titles and set appropriate priority/type
- Always `br sync --flush-only && git add .beads/` before ending session

<!-- end-bv-agent-instructions -->

## Landing the Plane (Session Completion)

**When ending a work session**, you MUST complete ALL steps below.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **Sync beads** - `br sync --flush-only` to export to JSONL
5. **Hand off** - Provide context for next session


---

Note for Codex/GPT-5.2:

You constantly bother me and stop working with concerned questions that look similar to this:

```
Unexpected changes (need guidance)

- Working tree still shows edits I did not make in Cargo.toml, Cargo.lock, src/cli/commands/upgrade.rs, src/storage/sqlite.rs, tests/conformance.rs, tests/storage_deps.rs. Please advise whether to keep/commit/revert these before any further work. I did not touch them.

Next steps (pick one)

1. Decide how to handle the unrelated modified files above so we can resume cleanly.
2. Triage beads_rust-orko (clippy/cargo warnings) and beads_rust-ydqr (rustfmt failures).
3. If you want a full suite run later, fix conformance/clippy blockers and re-run cargo test --all.
```

NEVER EVER DO THAT AGAIN. The answer is literally ALWAYS the same: those are changes created by the potentially dozen of other agents working on the project at the same time. This is not only a common occurrence, it happens multiple times PER MINUTE. The way to deal with it is simple: you NEVER, under ANY CIRCUMSTANCE, stash, revert, overwrite, or otherwise disturb in ANY way the work of other agents. Just treat those changes identically to changes that you yourself made. Just fool yourself into thinking YOU made the changes and simply don't recall it for some reason.

---

## Note on Built-in TODO Functionality

Also, if I ask you to explicitly use your built-in TODO functionality, don't complain about this and say you need to use beads. You can use built-in TODOs if I tell you specifically to do so. Always comply with such orders.
