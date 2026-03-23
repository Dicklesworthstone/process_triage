# pt

<div align="center">
  <img src="pt_illustration.webp" alt="pt - Bayesian process triage with provenance-aware blast-radius estimation">
</div>

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT%2BOpenAI%2FAnthropic%20Rider-blue.svg)](./LICENSE)

</div>

```bash
curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/process_triage/main/install.sh | bash
```

**`pt` finds and kills zombie processes so you don't have to.** It uses Bayesian inference over 40+ statistical models, provenance-aware blast-radius estimation, and conformal risk control to classify every process on your machine, then tells you exactly *why* it thinks something should die and exactly *what would break* if you kill it.

---

## The Problem

Development machines accumulate abandoned processes. Stuck `bun test` workers. Forgotten `next dev` servers from last week's branch. Orphaned Claude/Copilot sessions. Build processes that completed but never exited. They silently eat RAM, CPU, and file descriptors until your 64-core workstation grinds to a halt.

Manually hunting them with `ps aux | grep` is tedious, error-prone, and teaches you nothing about whether killing something will break something else.

## The Solution

`pt` automates detection with statistical inference, estimates collateral damage via process provenance graphs, and presents ranked candidates with full evidence transparency:

```bash
$ pt scan
 KILL  PID 84721  bun test          score=87  age=3h22m  cpu=0.0%  mem=1.2GB  orphan
 KILL  PID 71003  next dev          score=72  age=2d4h   cpu=0.1%  mem=340MB  detached
 REVIEW PID 55190 cargo build       score=34  age=45m    cpu=12%   mem=890MB
 SPARE  PID 1204  postgres          protected (infrastructure)
```

## Why pt?

| Feature | `ps aux \| grep` | `htop` | `pt` |
|---------|:-:|:-:|:-:|
| Finds abandoned processes automatically | - | - | Yes |
| Bayesian confidence scoring | - | - | Yes |
| Explains *why* a process is suspicious | - | - | Yes |
| Estimates blast radius before kill | - | - | Yes |
| Learns from your past decisions | - | - | Yes |
| Protected process lists | - | - | Yes |
| Fleet-wide distributed triage | - | - | Yes |
| Conformal FDR control for automation | - | - | Yes |
| Safe kill signals (SIGTERM → SIGKILL) | - | - | Yes |
| Interactive TUI | - | Yes | Yes |

---

## Quick Example

```bash
# Install (one-liner)
curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/process_triage/main/install.sh | bash

# Interactive mode — scan, review, confirm, kill
pt

# Quick scan — just show candidates, don't kill anything
pt scan

# Deep scan — collect network, I/O, queue depth evidence for higher confidence
pt deep

# Agent/robot mode — structured JSON output for CI/automation
pt agent plan --format json

# Compare two sessions to see what changed
pt diff --last

# Shadow mode — record recommendations without acting (calibration)
pt shadow start
```

---

## Design Philosophy

**1. Conservative by default.** No process is ever killed without explicit confirmation. Robot mode requires 95%+ posterior confidence, passes through conformal prediction gates, and checks blast-radius risk before any automated action.

**2. Transparent decisions.** Every recommendation comes with a full evidence ledger: which features contributed, how much each shifted the posterior, what the Bayes factor is, and what would break if you proceed. No black boxes.

**3. Provenance-aware safety.** Beyond checking whether a process *looks* abandoned, `pt` traces process lineage, maps shared resources (lockfiles, sockets, listeners), estimates direct and transitive blast radius, and blocks kills that would cascade across the system.

**4. Distribution-free guarantees.** Robot mode uses Mondrian conformal prediction to provide finite-sample FDR control. The coverage guarantee `P(Y in C(X)) >= 1-alpha` holds without parametric assumptions, as long as the calibration data is exchangeable with the test distribution.

**5. No mocks, no fakes.** Core inference modules are tested against real system state, not mocked /proc filesystems. If the test passes, the code works on real machines.

---

## How It Actually Works

### The Inference Pipeline

Every process on your system passes through a five-stage pipeline:

```
          ┌─────────┐     ┌─────────┐     ┌─────────┐     ┌─────────┐     ┌─────────┐
 /proc ──→│ Collect │────→│  Infer  │────→│ Decide  │────→│   Act   │────→│ Report  │
          └─────────┘     └─────────┘     └─────────┘     └─────────┘     └─────────┘
           25 modules      41 modules      40 modules      13 modules      5 formats
```

**Collect** reads `/proc/[pid]/stat`, `/proc/[pid]/io`, `/proc/[pid]/fd`, `/proc/net/tcp`, cgroup controllers, GPU devices, systemd units, and container metadata. It also builds a shared-resource graph mapping which processes hold the same lockfiles, sockets, and listeners.

**Infer** runs the evidence through 40+ statistical models. The ensemble includes changepoint detectors, regime-switching filters, queueing models, extreme value analysis, and conformal predictors. Each model contributes an evidence term to the posterior.

**Decide** picks the optimal action using expected-loss minimization, subject to FDR control, blast-radius constraints, causal safety gates, and configurable policy enforcement. Rather than a binary kill/spare, it evaluates 8 possible actions (Keep, Renice, Pause, Freeze, Throttle, Quarantine, Restart, Kill) and picks the one with lowest expected loss.

**Act** executes the chosen action with TOCTOU-safe identity verification, staged signal escalation, and rollback on failure. Actions beyond kill include cgroup-based CPU throttling, cpuset quarantine (pin to limited cores), cgroup v2 freezing, and nice-value adjustment.

**Report** produces output in JSON, TOON (token-optimized), HTML, or interactive TUI. Every report includes the evidence ledger, Bayes factor breakdown, provenance explanation with counterfactual stories, and missing-evidence diagnostics.

### The Statistical Models

`pt` doesn't rely on a single classifier. It runs an ensemble of 40+ specialized models, each contributing evidence terms to the posterior:

| Model | What It Detects | How It Works |
|-------|----------------|--------------|
| **BOCPD** | Sudden behavior changes | Bayesian Online Change-Point Detection with run-length recursion |
| **HSMM** | State transitions with duration | Hidden Semi-Markov Model with Gamma-distributed dwell times |
| **IMM** | Regime switching | Interacting Multiple Model filter bank with Markov transitions |
| **Kalman** | Trend estimation | Scalar Kalman filter + Rauch-Tung-Striebel backward smoother |
| **CTW** | Sequential prediction | Context Tree Weighting with Krichevsky-Trofimov estimator |
| **Hawkes** | Burst detection | Self-exciting point process (branching ratio n=alpha/beta) |
| **EVT/GPD** | Tail risk | Extreme Value Theory with Generalized Pareto Distribution |
| **Conformal** | Distribution-free coverage | Mondrian split conformal with blocked + adaptive variants |
| **Martingale** | Anytime-valid testing | Azuma-Hoeffding + Freedman/Bernstein bounds |
| **Wasserstein** | Distribution drift | 1D earth-mover's distance for non-stationarity detection |
| **M/M/1 Queue** | Socket stall detection | EWMA-smoothed queue depth with logistic rho estimation |
| **Compound Poisson** | Bursty I/O | Markov-modulated Levy subordinator |
| **Belief Prop** | Hierarchical inference | Message-passing over process lineage trees |
| **Robust Bayes** | Model misspecification | Credal sets + Safe-Bayes eta-tempering |
| **BMA** | Model uncertainty | Bayesian Model Averaging across competing posteriors |
| **Sketches** | Heavy hitters | Count-Min Sketch + T-Digest + Space-Saving for pattern detection |

All computation happens in log-domain using numerically stable log-sum-exp to prevent overflow/underflow.

### The 8 Actions

Most tools only know "kill" or "don't kill." `pt` evaluates 8 possible actions ranked by expected loss:

| Action | Signal/Mechanism | Reversible | When Used |
|--------|-----------------|:--:|-----------|
| **Keep** | No action | Yes | Process is useful or uncertain |
| **Renice** | `nice` value adjustment | Yes | Low-priority but not harmful |
| **Pause** | `SIGSTOP` | Yes | Temporarily stop for investigation |
| **Freeze** | cgroup v2 freezer | Yes | More robust than SIGSTOP (handles children) |
| **Throttle** | cgroup CPU quota | Yes | Limit CPU without stopping |
| **Quarantine** | cpuset controller | Yes | Pin to limited cores |
| **Restart** | Kill + supervisor respawn | Partial | Supervised process that needs cycling |
| **Kill** | SIGTERM → SIGKILL | No | Process is abandoned/zombie |

### Evidence Collection: What /proc Files Are Parsed

On Linux, `pt` reads 12+ files per process during a deep scan:

| File | Data Extracted |
|------|---------------|
| `/proc/[pid]/stat` | PID, PPID, state, utime, stime, starttime, vsize, rss, num_threads |
| `/proc/[pid]/io` | rchar, wchar, syscr, syscw, read_bytes, write_bytes |
| `/proc/[pid]/fd/` | Open file descriptors with type (socket, pipe, file, device) |
| `/proc/[pid]/schedstat` | CPU time, wait time, timeslices |
| `/proc/[pid]/sched` | Voluntary/involuntary context switches, priority |
| `/proc/[pid]/statm` | Memory pages (size, resident, shared, text, data) |
| `/proc/[pid]/cgroup` | cgroup v1/v2 paths, CPU/memory limits |
| `/proc/[pid]/wchan` | Kernel wait channel (detects D-state processes) |
| `/proc/[pid]/environ` | Environment variables (for workspace/supervisor detection) |
| `/proc/net/tcp` | TCP connections with tx_queue/rx_queue depths |
| `/proc/net/udp` | UDP socket state |
| `/proc/net/unix` | Unix domain sockets with reference counts |

Critical file detection recognizes 20+ patterns: git locks (`.git/index.lock`), package manager locks (dpkg, apt, rpm, npm, pnpm, yarn, cargo), SQLite WAL/journal files, database write handles, and generic `.lock`/`.lck` files.

### The TUI

The interactive TUI is built on **ftui** (an Elm-style Model-View-Update framework for terminals):

- **Responsive layout**: adapts to terminal width with breakpoints at 80/120/200 columns (single-panel, two-pane, three-pane)
- **Process table**: sortable by score, age, CPU, memory, with live filtering via search input
- **Detail panel**: expanded evidence view for the selected process including Bayes factors, evidence term glyphs, and decision rationale
- **Command palette**: fuzzy-searchable action palette for power users
- **Inline mode** (`pt run --inline`): confines the UI to a bottom region, preserving terminal scrollback above

Build with `cargo run -p pt-core --features ui -- run`.

### Session Diffing

`pt diff --last` compares two scan snapshots and classifies every process into lifecycle transitions:

| Transition | Meaning |
|------------|---------|
| `Appeared` | New process since last scan |
| `Resolved` | Process exited since last scan |
| `Stable` | Same classification and score |
| `NewlyOrphaned` | Parent died, process adopted by init |
| `Reparented` | Process moved to a new parent |
| `StateChanged` | Classification changed (e.g., Useful → Abandoned) |
| `OwnershipChanged` | User or group changed |

Each delta includes `score_drift` (how much the score changed), `worsened`/`improved` flags, and continuity confidence.

### MCP Server

`pt` includes a Model Context Protocol server for AI agent integration:

```bash
pt-core mcp   # Start JSON-RPC 2.0 server over stdio
```

Available tools: `scan` (quick or deep), `score_process` (score a specific PID), `list_resources`, `read_resource`. AI agents can use this to query process state, run scans, and make triage decisions without CLI parsing.

### Learning Tutorials

```bash
pt learn list              # Show available tutorials
pt learn show 01           # Read a tutorial
pt learn verify --all      # Verify completion
```

Seven built-in tutorials covering first-run safety, stuck test runners, port conflicts, agent workflow, fleet operations, shadow mode, and deep scanning. Each includes verification steps that confirm you actually ran the commands.

---

## Installation

### Quick Install (recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/process_triage/main/install.sh | bash
```

Installs `pt` (bash wrapper) and `pt-core` (Rust engine) to `~/.local/bin/`.

### Package Managers

```bash
# Homebrew (macOS/Linux)
brew tap process-triage/tap && brew install pt

# Scoop (Windows via WSL2)
scoop bucket add process-triage https://github.com/process-triage/scoop-bucket
scoop install pt

# Winget (Windows native)
winget install --id ProcessTriage.pt --source winget
```

### From Source

```bash
git clone https://github.com/Dicklesworthstone/process_triage.git
cd process_triage
cargo build --release -p pt-core
ln -s "$(pwd)/pt" ~/.local/bin/pt
```

### Verified Install

```bash
# Verify ECDSA signatures + checksums (fail-closed on missing/invalid metadata)
VERIFY=1 curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/process_triage/main/install.sh | bash
```

**Platforms:** Linux x86_64 (primary), Linux aarch64, macOS x86_64, macOS aarch64, Windows x86_64 (via WSL2/Scoop/Winget)

---

## Quick Start

### 1. Interactive Mode (recommended)

```bash
pt
```

Runs the full triage workflow: **Scan** → **Review** → **Confirm** → **Kill**.

Use `pt run --inline` to preserve terminal scrollback.

### 2. Scan Only

```bash
pt scan        # Quick scan (~1 second)
pt deep        # Deep scan with I/O, network, queue depth probes (~10-30 seconds)
```

### 3. Agent/Robot Mode

```bash
pt agent plan --format json       # Structured JSON plan
pt agent plan --format toon       # Token-optimized output
pt agent apply --session <id>     # Execute a plan
pt agent verify --session <id>    # Confirm outcomes
pt agent watch --format jsonl     # Stream events
```

### 4. Shadow Mode (calibration)

```bash
pt shadow start                   # Observe without acting
pt shadow report -f md            # ASCII calibration report
pt shadow stop                    # Stop observer
```

---

## Command Reference

| Command | Description | Example |
|---------|-------------|---------|
| `pt` | Interactive triage (scan + review + kill) | `pt` |
| `pt run --inline` | Interactive with preserved scrollback | `pt run --inline` |
| `pt scan` | Quick scan, show candidates | `pt scan` |
| `pt deep` | Deep scan with extra probes | `pt deep` |
| `pt agent plan` | Generate structured plan | `pt agent plan --format json` |
| `pt agent apply` | Execute a plan | `pt agent apply --session <id>` |
| `pt agent verify` | Confirm outcomes | `pt agent verify --session <id>` |
| `pt agent watch` | Stream events | `pt agent watch --format jsonl` |
| `pt agent report` | Generate HTML report | `pt agent report --session <id>` |
| `pt diff` | Compare two sessions | `pt diff --last` |
| `pt learn` | Interactive tutorials | `pt learn list` |
| `pt bundle create` | Export session bundle | `pt bundle create --session <id> --output out.ptb` |
| `pt report` | HTML report from session | `pt report --session <id> --output report.html` |
| `pt shadow start` | Start calibration observer | `pt shadow start` |
| `pt config validate` | Validate config files | `pt-core config validate policy.json` |
| `pt --version` | Show version | `pt --version` |
| `pt --help` | Full help | `pt --help` |

---

## Core Concepts

### Four-State Classification

Every process is classified into one of four states via Bayesian posterior updates:

| State | Description | Typical Action |
|-------|-------------|----------------|
| **Useful** | Actively doing productive work | Leave alone |
| **Useful-Bad** | Running but stalled, leaking, or deadlocked | Throttle, review |
| **Abandoned** | Was useful, now forgotten | Kill (usually recoverable) |
| **Zombie** | Terminated but not reaped by parent | Clean up |

### Evidence Sources

| Evidence | What It Measures | Impact |
|----------|------------------|--------|
| CPU activity | Active computation vs idle | Idle + old = suspicious |
| Runtime vs expected lifetime | Overdue processes | Long-running test = likely stuck |
| Parent PID | Orphaned (PPID=1)? | Orphans are suspicious |
| I/O activity | Recent file/network I/O | No I/O for hours = abandoned |
| TTY state | Interactive or detached? | Detached old processes = suspicious |
| Network queues | Socket rx/tx queue depth | Deep queues = stalled (useful-bad) |
| Command category | Test runner, dev server, build tool? | Sets prior expectations |
| Past decisions | Have you spared similar processes? | Learns from your patterns |

### Confidence Levels

| Level | Posterior | Robot Mode |
|-------|-----------|------------|
| `very_high` | > 0.99 | Auto-kill eligible |
| `high` | > 0.95 | Auto-kill eligible |
| `medium` | > 0.80 | Requires confirmation |
| `low` | < 0.80 | Review only |

---

## Safety Model

### Identity Validation

Every kill target is verified by a triple `<boot_id>:<start_time_ticks>:<pid>` that prevents PID-reuse attacks, stale plan execution, and race conditions.

### Protected Processes

These are **never** flagged: `systemd`, `dbus`, `sshd`, `cron`, `docker`, `containerd`, `postgres`, `mysql`, `redis`, `nginx`, `apache`, `caddy`, and any root-owned process. Configurable via `policy.json`.

### Staged Kill Signals

1. **SIGTERM** — graceful shutdown request
2. **Wait** — configurable timeout for cleanup
3. **SIGKILL** — forced termination if SIGTERM fails

### Provenance-Aware Blast Radius

`pt` goes beyond simple process metrics. It builds a **shared-resource graph** mapping which processes share lockfiles, sockets, listeners, and pidfiles. Before any kill, it estimates:

- **Direct impact**: co-holders of shared resources, supervised processes, children
- **Indirect impact**: transitive dependencies via BFS with confidence decay
- **Risk classification**: Low / Medium / High / Critical

```
blast_radius:
  risk_level: Medium
  total_affected: 3
  risk_score: 0.35
  direct: "shares 2 resource(s) with 3 process(es), owns 1 active listener(s)"
  counterfactual: "Killing would affect 3 other processes"
```

High-risk kills require confirmation. Critical-risk kills are blocked in robot mode.

### Robot/Agent Safety Gates

| Gate | Default | Purpose |
|------|---------|---------|
| `min_posterior` | 0.95 | Minimum Bayesian confidence |
| `conformal_alpha` | 0.05 | FDR control via Mondrian conformal prediction |
| `max_blast_radius` | Critical | Block kills above this risk level |
| `max_kills` | 10 | Per-session kill limit |
| `fdr_budget` | 0.05 | e-value Benjamini-Hochberg correction |
| `causal_snapshot` | Complete | Require fleet-wide consistent cut |
| `protected_patterns` | (see above) | Always enforced |

---

## Architecture

```
pt (Bash wrapper)
 └─ pt-core (Rust binary, 8 crates, 100+ modules)
     ├─ Collect ─────── /proc parsing, network queues, cgroup limits,
     │                  GPU detection, systemd units, containers,
     │                  lockfile/pidfile ownership, workspace resolver,
     │                  shared-resource graph, provenance continuity
     │
     ├─ Infer ──────── Bayesian posteriors (log-domain), BOCPD, HSMM,
     │                  Kalman filters, conformal prediction (Mondrian),
     │                  queueing-theoretic stall detection (M/M/1 + EWMA),
     │                  belief propagation, Hawkes processes, EVT,
     │                  martingale testing, context-tree weighting
     │
     ├─ Decide ─────── Expected-loss minimization, FDR control (eBH/eBY),
     │                  Value of Information, active sensing, CVaR,
     │                  distributionally robust optimization,
     │                  blast-radius estimation, provenance scoring,
     │                  causal snapshots (Chandy-Lamport), Gittins indices
     │
     ├─ Act ────────── SIGTERM → SIGKILL escalation, cgroup throttle,
     │                  cpuset quarantine, renice, process freeze,
     │                  recovery trees, rollback on failure
     │
     └─ Report ─────── JSON/TOON/HTML output, evidence ledger,
                        Galaxy-Brain cards, provenance explanations,
                        counterfactual stories, session bundles
```

### Workspace Structure

```
process_triage/
├── Cargo.toml              # Workspace root
├── pt                      # Bash wrapper
├── install.sh              # Installer + ECDSA verification
├── crates/
│   ├── pt-core/            # Main engine (41 inference + 40 decision + 25 collect modules)
│   ├── pt-common/          # Shared types, evidence schemas, provenance IDs
│   ├── pt-config/          # Configuration loading, priors, policy validation
│   ├── pt-math/            # Log-domain arithmetic, numerical stability
│   ├── pt-bundle/          # Session bundles (ZIP + ChaCha20-Poly1305 encryption)
│   ├── pt-redact/          # HMAC hashing, PII scrubbing, redaction profiles
│   ├── pt-telemetry/       # Arrow schemas, Parquet writer, LMAX disruptor
│   └── pt-report/          # HTML report templating (Askama + minify-html)
├── test/                   # BATS test suite
├── docs/                   # User + architecture documentation
│   └── math/PROOFS.md      # Formal mathematical guarantees
├── examples/configs/       # Scenario configurations
├── fuzz/                   # Fuzz testing targets
└── benches/                # Criterion benchmarks
```

---

## Configuration

### Directory Layout

```
~/.config/process_triage/
├── decisions.json      # Learned kill/spare decisions
├── priors.json         # Bayesian hyperparameters
├── policy.json         # Safety policy
└── triage.log          # Audit log

~/.local/share/process_triage/
└── sessions/
    └── pt-20260115-143022-a7xq/
        ├── manifest.json       # Session metadata
        ├── snapshot.json       # Initial process state
        ├── provenance.json     # Process provenance graph
        ├── plan.json           # Generated recommendations
        └── audit.jsonl         # Action audit trail
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PROCESS_TRIAGE_CONFIG` | `~/.config/process_triage` | Config directory |
| `PROCESS_TRIAGE_DATA` | `~/.local/share/process_triage` | Data/session directory |
| `PT_OUTPUT_FORMAT` | (unset) | Default output format (`json`, `toon`) |
| `NO_COLOR` | (unset) | Disable colored output |
| `PROCESS_TRIAGE_RETENTION` | `7` | Session retention in days |
| `PROCESS_TRIAGE_NO_PERSIST` | (unset) | Disable session persistence |
| `PT_BUNDLE_PASSPHRASE` | (unset) | Default bundle encryption passphrase |

### Priors Configuration (`priors.json`)

```json
{
  "schema_version": "1.0.0",
  "classes": {
    "useful":    { "prior_prob": 0.70, "cpu_beta": {"alpha": 5.0, "beta": 3.0} },
    "useful_bad":{ "prior_prob": 0.05, "cpu_beta": {"alpha": 2.0, "beta": 4.0},
                   "queue_saturation_beta": {"alpha": 6.0, "beta": 1.0} },
    "abandoned": { "prior_prob": 0.15, "cpu_beta": {"alpha": 1.0, "beta": 5.0} },
    "zombie":    { "prior_prob": 0.10, "cpu_beta": {"alpha": 1.0, "beta": 9.0} }
  }
}
```

See [docs/PRIORS_SCHEMA.md](docs/PRIORS_SCHEMA.md) for the full specification.

### Policy Configuration (`policy.json`)

```json
{
  "protected_patterns": ["systemd", "sshd", "docker", "postgres"],
  "min_process_age_seconds": 3600,
  "robot_mode": {
    "enabled": false,
    "min_posterior": 0.99,
    "max_blast_radius_mb": 2048,
    "max_kills": 5
  }
}
```

---

## Telemetry and Data Governance

All data stays local. Nothing is sent anywhere.

| Data | Purpose | Retention |
|------|---------|-----------|
| Process metadata | Classification input | Session lifetime |
| Evidence samples | Audit trail | Configurable (default: 7 days) |
| Kill/spare decisions | Learning | Indefinite (user-controlled) |
| Provenance graphs | Blast-radius estimation | Session lifetime |
| Session manifests | Reproducibility | Configurable (default: 30 days) |

### Redaction

Sensitive data is hashed/redacted before persistence. Four profiles: `minimal` (hashes only), `standard` (redacted paths), `debug` (full detail, local only), `share` (anonymized for export).

See [docs/PROVENANCE_PRIVACY_MODEL.md](docs/PROVENANCE_PRIVACY_MODEL.md) and [docs/PROVENANCE_CONTROLS_AND_ROLLOUT.md](docs/PROVENANCE_CONTROLS_AND_ROLLOUT.md).

---

## Session Bundles and Reports

### Encrypted Session Bundles (`.ptb`)

```bash
# Export a session
pt bundle create --session <id> --profile safe --output session.ptb

# With encryption (ChaCha20-Poly1305 + PBKDF2)
pt bundle create --session <id> --encrypt --passphrase "correct horse battery staple"
```

### HTML Reports

```bash
pt report --session <id> --output report.html
pt report --session <id> --output report.html --include-ledger --embed-assets
```

---

## Fleet Mode

`pt` supports multi-host triage with distributed safety guarantees:

```bash
# Scan a fleet of hosts via SSH
pt-core fleet scan --inventory hosts.toml --parallel 10

# Pooled FDR control across hosts (e-value Benjamini-Yekutieli)
pt-core fleet plan --fdr-method eby --alpha 0.05
```

Fleet mode uses **Chandy-Lamport consistent snapshots** to prevent triage cascades: a process on Host A won't be killed if it's a dependency of a Useful process on Host B. Tentative hosts (timeout/unreachable) trigger conservative fallback; no auto-kills until the cut is complete.

---

## GPU and Container Awareness

### GPU Process Detection

`pt` detects GPU-bound processes via `nvidia-smi` (CUDA) and `rocm-smi` (AMD ROCm):

```bash
$ pt deep   # Automatically detects GPU processes
```

| Field Collected | NVIDIA | AMD |
|----------------|:------:|:---:|
| Device name, UUID, index | Yes | Yes |
| Total/used VRAM (MiB) | Yes | Yes |
| GPU utilization % | Yes | Yes |
| Temperature | Yes | Yes |
| Per-process GPU memory | Yes | Yes |
| Driver version | Yes | Yes |

A process consuming 8GB of VRAM on a 12GB GPU gets a higher blast-radius score than one using 200MB. If neither `nvidia-smi` nor `rocm-smi` is available, GPU detection silently degrades with a provenance warning.

### Container and Kubernetes Detection

`pt` automatically detects containerized processes through three mechanisms (in priority order):

1. **Cgroup path patterns**: Parses `/proc/[pid]/cgroup` for Docker (`/docker/<64hex>`), Podman (`libpod-<id>`), containerd, LXC, and CRI-O patterns
2. **Marker files**: Checks for `/.dockerenv` (Docker) and `/.containerenv` (Podman)
3. **Environment variables**: Reads `KUBERNETES_SERVICE_HOST`, `POD_NAME`, `POD_NAMESPACE`, `POD_UID` for Kubernetes metadata

For Kubernetes pods, `pt` extracts the QoS class (Guaranteed / Burstable / BestEffort), pod name, namespace, and container name. Container-managed processes get special treatment in the decision engine, since killing a process inside a container that will be restarted by its orchestrator may be pointless.

---

## Daemon Mode (Background Monitoring)

`pt` can run as a persistent background monitor that watches system health and triggers triage when conditions deteriorate:

```bash
pt-core daemon start              # Start background monitor
pt-core daemon status             # Check daemon state
pt-core daemon stop               # Stop monitor
```

### How It Works

The daemon runs a tick-based event loop (default: every 60 seconds) that evaluates trigger conditions:

| Trigger | Default Threshold | What It Detects |
|---------|------------------|-----------------|
| Load average | > 2.0 sustained | CPU overload |
| Orphan count | > 10 | Process leak |
| Memory pressure | > 85% used | Memory exhaustion |

When a trigger fires for multiple consecutive ticks (sustained window), the daemon escalates: it runs a quick scan, infers posteriors, generates a plan, and optionally executes low-risk actions or sends notifications.

### Self-Limiting

The daemon enforces overhead budgets on itself:

- **CPU cap**: 2.0% by default (configurable)
- **RSS cap**: 64MB by default (configurable)
- **Event audit ring**: Circular buffer of 100 recent events for debugging

If the daemon itself exceeds its budget, it backs off automatically.

---

## Process Signature Database

`pt` ships with a built-in database of known process signatures: command patterns that indicate specific process types (test runners, dev servers, build tools, agents).

```bash
pt-core signature list              # Show all signatures
pt-core signature add \
  --name "stuck-jest" \
  --pattern "jest" \
  --arg-pattern "--runInBand" \
  --category test_runner             # Add custom signature

pt-core signature export > sigs.json # Export for sharing
pt-core signature import sigs.json   # Import from file
```

Signatures are matched against a `ProcessMatchContext` that includes the process name, command-line arguments, environment variables, container info, and network state. Matched signatures adjust the Bayesian prior: a `test_runner` signature shifts the prior toward "likely to be stuck if old."

---

## Supervision Detection

`pt` detects 8 types of process supervision to avoid killing managed processes (which would just respawn):

| Supervisor | Detection Method | Confidence |
|-----------|-----------------|:----------:|
| **systemd** | Cgroup path + `NOTIFY_SOCKET` env | 0.95 |
| **launchd** | `XPC_SERVICE_NAME` env | 0.95 |
| **Docker/containerd** | Cgroup path patterns, `/.dockerenv` | 0.95 |
| **VS Code** | `VSCODE_PID`, `VSCODE_IPC_HOOK` env | 0.95 |
| **Claude/Codex** | `CLAUDE_SESSION_ID`, `CODEX_SESSION_ID` env | 0.95 |
| **GitHub Actions** | `GITHUB_ACTIONS`, `GITHUB_WORKFLOW` env | 0.95 |
| **tmux/screen** | `TMUX` or `STY` env | 0.30 |
| **nohup/disown** | Signal mask analysis (`SigIgn` in `/proc/[pid]/status`) | varies |

Supervised processes get higher blast-radius scores because killing them may be futile (the supervisor will restart them). The evidence ledger notes this: "Supervisor may auto-restart (reducing kill effectiveness)."

For nohup detection, `pt` reads the signal mask from `/proc/[pid]/status` and checks whether SIGHUP (bit 0) is ignored. It also looks for `nohup.out` in the file descriptor table. This distinguishes intentional backgrounding from forgotten processes.

---

## User Intent Detection

Before flagging a process, `pt` checks whether a human is actively using it. Nine signal types contribute to a "user intent score" that suppresses false positives:

| Signal | Weight | What It Checks |
|--------|:------:|---------------|
| Foreground job | 0.95 | Process group ID matches TTY foreground group |
| Editor focus | 0.90 | Attached to IDE (VS Code, etc.) |
| tmux session | 0.85 | Running inside tmux |
| screen session | 0.85 | Running inside screen |
| Recent TTY activity | 0.80 | Terminal FD touched within 5 minutes |
| Active repo context | 0.75 | CWD in a git repo with recent activity |
| Active TTY | 0.70 | Has controlling terminal |
| Recent shell activity | 0.65 | Shell parent recently active |
| SSH session | 0.60 | Connected via SSH |

The final score is computed as `1 - product(1 - w_i)` across all detected signals (probabilistic combination). A high intent score suppresses the abandonment posterior; even an old, idle process is safe if someone just switched to its tmux pane.

---

## Incremental Scanning

Full re-scans are wasteful when most processes haven't changed. The incremental engine tracks a process inventory across sessions and only re-infers processes with material state changes:

| Change Type | Triggers Re-inference? | Detection |
|-------------|:---------------------:|-----------|
| New process | Yes | Not in previous inventory |
| Process exited | Yes (record departure) | In previous but not current |
| CPU spike (> 5pp) | Yes | `\|current - previous\| > threshold` |
| RSS spike (> 20%) | Yes | `\|delta\| / previous > fraction` |
| Process state change | Yes | State enum comparison |
| Stale entry (> 10 min) | Yes | Forced re-scan |
| Unchanged | No (age-only update) | No material change detected |

Process identity is tracked via a SHA-256 hash of `(pid, uid, comm, cmd)`, producing a stable 16-character hex fingerprint. The inventory supports up to 100,000 entries with LRU eviction.

---

## Respawn Loop Detection

Killing a supervised process that immediately restarts is pointless. `pt` tracks kill-respawn cycles and adjusts its recommendations:

```
Kill → respawn in 2s → Kill → respawn in 2s → Kill → respawn in 2s
                     ↓
         "Respawn loop detected (3 cycles in 60s)"
         Recommendation: systemctl stop <unit> instead
```

After detecting a loop (2+ respawns within 30 seconds of each kill, within a 1-hour window), `pt` discounts the kill action's utility:

```
utility_multiplier = 1.0 - 0.8 * min(loop_count / 5, 1.0)
```

At 5+ loops, kill utility drops to 20% of baseline. The recommendation escalates from "kill" to "stop supervisor" to "disable supervisor" as the loop count increases.

---

## Memory Pressure Response

The daemon monitors system memory and escalates scan cadence when pressure rises:

| Mode | Threshold | Scan Interval | Action |
|------|-----------|:-------------:|--------|
| Normal | < 80% used | 300s | Continue monitoring |
| Warning | >= 80% used | 60s | Generate triage plan |
| Emergency | >= 95% used | 15s | Urgent plan, prioritize high-RSS candidates |

Transitions require 2 consecutive signals at the new level (prevents flapping on momentary spikes). De-escalation also requires 2 consecutive normal readings.

On Linux, `pt` reads Pressure Stall Information (`/proc/pressure/memory`) when available, using `memory.some` as a more accurate signal than raw utilization. PSI thresholds: 20% for warning, 60% for emergency.

---

## Goal-Based Kill Set Selection

Instead of ranking processes individually, `pt` can optimize kill sets to achieve resource goals:

```bash
pt agent plan --goal "free 4GB memory" --format json
pt agent plan --goal "free port 8080" --format json
```

The optimizer evaluates which combination of kills achieves the goal with minimum collateral damage. Three algorithms are available:

| Algorithm | When Used | Guarantee |
|-----------|-----------|-----------|
| **Greedy** | Default (any N) | 1 - 1/e approximation for submodular objectives |
| **DP-exact** | N <= 30 candidates | Optimal solution |
| **Local search** | Refinement pass | Swap-based improvement on greedy |

Each candidate's "efficiency" is `contribution / expected_loss`, measuring how much resource it frees per unit of risk. The optimizer selects the minimum-cost set that meets the target.

---

## Off-Policy Evaluation

Before deploying a new triage policy (different thresholds, different priors), `pt` can evaluate it against historical decisions without running it live:

| Estimator | Bias | Variance | When to Use |
|-----------|:----:|:--------:|-------------|
| **IPS** (Inverse Propensity Scoring) | Unbiased | High | Baseline, sufficient data |
| **Doubly Robust** | Unbiased if either model correct | Lower | Preferred when available |

The doubly-robust estimator combines importance weighting with a direct reward model:

```
V_DR = (1/n) * sum[ r_hat(s, pi) + w_i * (r_i - r_hat(s, a_i)) ]
```

where `w_i = min(pi_new(a|s) / pi_old(a|s), 10.0)` is the clipped importance ratio. The effective sample size `ESS = (sum w_i)^2 / sum w_i^2` must exceed 100 for reliable estimates.

Recommendations: **Deploy** if the 95% CI lower bound exceeds the current policy's value. **Hold** if inconclusive. **Unreliable** if ESS is too low.

---

## Wait-Free /proc Probing

Some processes are in **D-state** (uninterruptible sleep), and reading their `/proc` files can block the entire scan. The prober uses Linux `io_uring` for non-blocking reads:

1. Submit all `/proc/[pid]/*` reads as async I/O operations
2. Add a global timeout entry (100ms default)
3. Process completions as they arrive
4. Mark timed-out probes (the process is likely stuck on I/O)

This prevents a single hung NFS mount or frozen block device from stalling the entire triage pipeline. Processes with timed-out probes get `confidence: "low"` and D-state diagnostics in their plan entry.

---

## The Evidence Ledger

The evidence ledger is the core explainability tool. Every triage candidate gets a detailed breakdown showing exactly how each piece of evidence shifted the posterior:

```
PID 84721 (bun test) — Score: 87 — Classification: Abandoned

  Evidence Ledger:
  🎲 prior         Bayes factor: 1.00   (baseline)
  💻 cpu           Bayes factor: 8.42   decisive → supports abandoned
  ⏱  runtime       Bayes factor: 5.23   strong   → supports abandoned
  👻 orphan        Bayes factor: 3.71   strong   → supports abandoned
  🖥  tty           Bayes factor: 0.89   weak     → supports useful
  🌐 net           Bayes factor: 1.12   weak     → supports abandoned
  💾 io_active     Bayes factor: 4.55   strong   → supports abandoned
  🚦 queue_sat     Bayes factor: 1.00   neutral
  🚩 state_flag    Bayes factor: 1.34   weak     → supports abandoned

  Posterior: P(abandoned)=0.87  P(useful)=0.06  P(useful_bad)=0.04  P(zombie)=0.03
  Log-odds (abandoned vs useful): 2.67 bits
```

Each evidence term has a glyph, a Bayes factor (ratio of likelihoods), a strength label (decisive/strong/substantial/weak), and a direction (which class it supports). The strength thresholds follow standard Bayesian interpretation: decisive = |delta_bits| > 3.3 (>10:1 odds), strong = > 2.0 (>4:1), substantial = > 1.0 (>2:1).

Access this via `pt deep` (interactive) or `pt agent plan --deep --format json` (structured).

---

## Plan Format and Example Output

When you run `pt agent plan --format json`, the output is a deterministic, resumable plan:

```json
{
  "plan_id": "plan-a7c92e3f1b2d4e5f",
  "session_id": "pt-20260317-150000-a7xq",
  "generated_at": "2026-03-17T15:00:00Z",
  "actions": [
    {
      "action_id": "act-1234567890abcdef",
      "target": {
        "pid": 84721,
        "start_id": "boot-abc123:1234567890:84721"
      },
      "action": "kill",
      "order": 0,
      "stage": 0,
      "timeouts": {
        "preflight_ms": 2000,
        "execute_ms": 10000,
        "verify_ms": 5000
      },
      "pre_checks": [
        "verify_identity",
        "check_not_protected",
        "check_data_loss_gate"
      ],
      "rationale": {
        "expected_loss": 0.05,
        "expected_recovery": 0.95,
        "posterior": {
          "abandoned": 0.87,
          "useful": 0.06,
          "useful_bad": 0.04,
          "zombie": 0.03
        },
        "memory_mb": 1024.5,
        "category": "test_runner"
      },
      "routing": "direct",
      "confidence": "normal"
    }
  ],
  "gates_summary": {
    "total_candidates": 47,
    "blocked_candidates": 8,
    "pre_toggled_actions": 1
  }
}
```

**Key design choices:**
- **IDs are deterministic** (FNV-1a 64-bit hashes, not UUIDs); the same inputs always produce the same plan
- **Zombie routing**: Z-state processes are routed to their parent for `restart` (forcing reap), not killed directly
- **D-state handling**: Processes in uninterruptible sleep get `confidence: "low"` with diagnostic fields (wchan, I/O counters, D-state duration)
- **Pre-checks**: Every action has a list of safety checks that must pass before execution (identity verification, protection check, data-loss gate, supervisor check)

---

## Session Lifecycle (Type-State Machine)

Sessions enforce valid state transitions at **compile time** using Rust's type system:

```
Created ──→ Scanning ──→ Planned ──→ Executing ──→ Completed
   │          │            │          │
   └─→ Failed ←┴────────────┴──────────┘
   └─→ Cancelled
```

Each state is a zero-sized marker type. The method `TypedSession<Scanning>::finish_scan()` returns a `TypedSession<Planned>`. You cannot call `start_execution()` on a session that hasn't been planned yet, because the method doesn't exist on that type. Invalid transitions are caught by the compiler, not by runtime checks.

---

## The Bash Wrapper

The `pt` script is a thin Bash wrapper that locates and execs `pt-core`:

**Binary discovery** (checked in order):
1. `$PT_CORE_PATH` (explicit override)
2. `./pt-core` (same directory)
3. `./target/release/pt-core` (cargo build artifact)
4. `~/.local/bin/pt-core`
5. `/usr/local/bin/pt-core`
6. PATH lookup via `which`

**UI mode selection**: Checks for TTY, CI environment, and `$TERM` to decide between TUI and shell mode. Override with `--shell`, `--tui`, or `$PT_UI_MODE`.

**Built-in commands**:
- `pt update` — Fetches latest version, runs signed installer
- `pt history` — Shows past kill/spare decisions (requires `jq`)
- `pt clear` — Resets decision memory with confirmation
- `pt deep` — Alias for `deep-scan`

The wrapper is deliberately simple (~200 lines of shellcheck-clean Bash) so the Rust engine can be updated independently.

---

## Shell Completions

Tab completion is available for Bash, Fish, and Zsh:

```bash
# Bash
source completions/pt-core.bash

# Fish
cp completions/pt-core.fish ~/.config/fish/completions/

# Zsh
cp completions/_pt-core ~/.zfunc/
```

Completions cover all subcommands, options, and argument values, including `--format` choices (json, toon, md, jsonl, summary, metrics, prose), `--theme` options (dark, light, high-contrast, no-color), and session IDs.

---

## How pt Learns From Your Decisions

When you kill or spare a process, `pt` remembers. The learning system normalizes command patterns at three specificity levels and stores them for future sessions:

| Level | What's Preserved | Example |
|-------|-----------------|---------|
| **Exact** | Full command with specific args | `node /home/user/project/.bin/jest --watch tests/` |
| **Standard** | Generalized paths, preserved flags | `node .*/jest --watch .*` |
| **Broad** | Base command only | `node .*jest.*` |

**Normalization rules** applied automatically:
- Home paths (`/home/user/...`) → `.*`
- Temp paths (`/tmp/...`) → `.*`
- Port numbers (`--port 8080`) → `\d+`
- UUIDs → `[0-9a-f-]+`
- Long numbers (4+ digits) → `\d+`
- Versioned interpreters (`python3.11`) → `python.*`

When `pt` sees a process matching a learned pattern, it adjusts the prior probability: processes you've killed before get a higher abandonment prior, while processes you've spared get a lower one. Three specificity levels prevent both over-fitting (exact match only) and over-generalizing (matching every `node` process).

---

## Critical File Detection

Before killing any process, `pt` checks what files it has open. 20+ detection rules across 9 categories identify files that indicate active work in progress:

| Category | Examples | Strength | Kill Impact |
|----------|----------|:--------:|-------------|
| **SQLite WAL/Journal** | `.sqlite-wal`, `.db-journal` | Hard | Blocks kill — active transaction |
| **Git Locks** | `.git/index.lock`, `packed-refs.lock` | Hard | Blocks kill — repository corruption risk |
| **Git Rebase/Merge** | `rebase-merge/`, `MERGE_HEAD`, `CHERRY_PICK_HEAD` | Hard | Blocks kill — interactive operation |
| **System Package Locks** | `/var/lib/dpkg/lock`, `.rpm.lock`, `pacman/db.lck` | Hard | Blocks kill — package manager transaction |
| **Node Package Locks** | `.package-lock.json`, `.pnpm-lock.yaml` | Hard | Blocks kill — npm/pnpm/yarn install |
| **Cargo Locks** | `.cargo/registry/.package-cache-lock` | Hard | Blocks kill — cargo registry operation |
| **Database Files** | `.db`, `.sqlite3`, `.ldb`, `.mdb` | Soft | Warns — possible data loss |
| **Application Locks** | `.lock`, `.lck`, `/lock/` patterns | Soft | Warns — process may hold coordination lock |
| **Generic Writes** | Any file open for writing | Soft | Noted — contextual evaluation |

**Hard** detections always block automated kills. **Soft** detections add weight to the blast-radius score and generate remediation hints (e.g., "Wait for database transaction to complete, or checkpoint the WAL file").

---

## Workspace Detection

`pt` determines which git repository and worktree each process belongs to, providing project context for triage decisions:

1. Reads `/proc/[pid]/cwd` to get the process's working directory
2. Walks up the directory tree looking for `.git`
3. If `.git` is a file (git worktree), parses the `gitdir:` pointer and resolves back to the main repository root via `commondir`
4. Reads `HEAD` to determine branch status (on branch, detached HEAD, or corrupted)

This means `pt` can tell you "this stuck `cargo build` is in your `feature/auth` worktree of the `backend` repo," instead of just "PID 12345 is running cargo."

A process with a deleted CWD (the directory was removed while the process was running) gets an elevated suspicion score, since it's likely orphaned from a branch that was cleaned up.

---

## cgroup Integration

### CPU Throttling (Instead of Killing)

For processes classified as Useful-Bad (misbehaving but needed), `pt` can throttle CPU usage via cgroup controllers instead of killing:

```
Throttle formula: quota_us = max(target_fraction × period_us, 1000)

Example: 25% throttle = 25,000 µs quota per 100,000 µs period
         2 cores max  = 200,000 µs quota per 100,000 µs period
         Minimum      = 1,000 µs (prevents complete starvation)
```

| Aspect | cgroup v1 | cgroup v2 |
|--------|-----------|-----------|
| **Quota file** | `cpu.cfs_quota_us` + `cpu.cfs_period_us` | `cpu.max` (single file: `"quota period"`) |
| **Weight** | `cpu.shares` (relative) | `cpu.weight` (1-10000) |
| **Memory** | `memory.limit_in_bytes` | `memory.max` + `memory.high` |
| **Write order** | Period must be set before quota | Single atomic write |
| **Detection** | Hierarchy ID != 0 in `/proc/[pid]/cgroup` | Hierarchy ID = 0 |

`pt` auto-detects cgroup version (v1, v2, or hybrid) and uses the appropriate interface. Previous settings are captured for reversal.

### cpuset Quarantine

For extreme cases, `pt` can pin a process to a limited set of CPU cores via the cpuset controller, isolating it from the rest of the system without killing it.

---

## Action Recovery Trees

When an action fails, `pt` consults a structured recovery tree with diagnosis and fallback options:

```
Kill action failed (Timeout)
 ├─ Diagnosis: "Process did not terminate within grace period"
 ├─ Alternative 1: Escalate to SIGKILL (requirements: process exists)
 ├─ Alternative 2: Investigate D-state (requirements: process in uninterruptible sleep)
 ├─ Alternative 3: Stop supervisor first, then retry kill
 └─ Alternative 4: Escalate to user for manual intervention
```

**Failure categories** with specific recovery strategies:

| Failure | Primary Recovery | Fallback |
|---------|-----------------|----------|
| Permission denied | Retry with elevated privileges | Escalate to user |
| Process not found | Verify goal achieved (may have exited) | Skip |
| Timeout | Escalate signal (SIGTERM → SIGKILL) | Investigate D-state |
| Supervisor conflict | Stop supervisor, mask unit, retry | Check for respawn |
| Identity mismatch | Abort (PID reused; wrong process) | Re-scan and re-plan |
| Resource conflict | Wait and retry with backoff | Skip |

Recovery is always *forward* (escalate to more forceful actions), never backward (no automatic undo). Reversal metadata is captured so a human can manually undo if needed.

---

## Telemetry: Lock-Free Event Recording

Session telemetry is recorded via an **LMAX Disruptor**, a lock-free, wait-free ring buffer designed for ultra-low-latency event recording:

```
Producer (triage loop) ──→ [Ring Buffer] ──→ Consumer (Parquet writer)
                               ↑
                        Pre-allocated, fixed-size
                        Cache-line aligned (64 bytes)
                        Power-of-2 capacity
                        Bitmask indexing (no modulo)
```

**Why a disruptor instead of a channel?**
- **Zero allocation**: All event slots are pre-allocated at startup. No heap allocation during triage.
- **No contention**: Producer and consumer sequences are on separate cache lines (64-byte alignment via `#[repr(align(64))]`), eliminating false sharing.
- **Wait-free**: Producer never blocks. If the buffer is full, the event is simply dropped. Telemetry should never slow down triage decisions.
- **Bitmask indexing**: Capacity is always a power of 2, so `index = sequence & (capacity - 1)` avoids expensive modulo operations.

Events are fixed-size structs (timestamp + event type + PID + 128-byte detail buffer) written to Apache Parquet via Arrow schemas for efficient columnar analytics.

---

## Bundle Format Internals

A `.ptb` file is a ZIP archive (optionally encrypted) containing a manifest and session artifacts:

```
session.ptb (ZIP or encrypted envelope)
├── manifest.json       # Bundle metadata + file checksums
├── snapshot.json       # Redacted process state
├── inference.jsonl     # Per-process posteriors
├── plan.json           # Generated action plan
├── actions.json        # Executed actions + outcomes
├── provenance.json     # Process provenance graph
└── audit.jsonl         # Action audit trail
```

### Encryption Envelope

When encrypted, the ZIP payload is wrapped in a `PTBENC01` envelope:

```
[8 bytes:  "PTBENC01"]        Magic header
[4 bytes:  KDF iterations]    PBKDF2 iteration count (default 100,000)
[16 bytes: salt]              Random salt for key derivation
[12 bytes: nonce]             Random nonce for ChaCha20
[rest:     ciphertext]        ChaCha20-Poly1305 authenticated ciphertext
```

Key derivation uses PBKDF2-HMAC-SHA256 with 100,000 iterations. The resulting 256-bit key feeds ChaCha20-Poly1305 for authenticated encryption. The 16-byte Poly1305 tag provides tamper detection.

### Integrity Verification

Every file in the bundle has a SHA-256 checksum in the manifest. The reader verifies checksums on load and rejects bundles with mismatched hashes. Maximum bundle size for in-memory reading is 100MB (prevents OOM on malicious files).

---

## Numerical Stability

All Bayesian computation happens in **log-domain** to prevent the floating-point catastrophes that plague naive probability implementations:

**The problem**: Multiplying many small probabilities (e.g., `0.001 * 0.002 * 0.0003 * ...`) underflows to zero in IEEE 754 double precision. Dividing by the sum of such products for normalization produces 0/0 = NaN.

**The solution**: Work with log-probabilities throughout:
- Multiplication becomes addition: `log(a * b) = log(a) + log(b)`
- Normalization uses log-sum-exp: `log(sum(exp(x_i))) = max(x) + log(sum(exp(x_i - max(x))))`
- The max-subtraction trick ensures the largest exponent is `exp(0) = 1`, preventing overflow

The `pt-math` crate provides `log_sum_exp`, `log_beta_pdf`, `log_gamma`, `gamma_log_pdf`, and `normalize_log_probs`, all numerically stable. The implementation has been validated with 21 stress tests covering 1000+ parameter combinations with zero panics.

---

## Mathematical Foundations

The inference engine is backed by formal mathematical guarantees documented in [docs/math/PROOFS.md](docs/math/PROOFS.md):

| Guarantee | Method | Invariant |
|-----------|--------|-----------|
| Posterior sums to 1 | Log-sum-exp normalization | `sum P(C\|x) = 1` |
| FDR control | e-value eBH/eBY | `E[FDP] <= alpha` |
| Coverage | Mondrian conformal prediction | `P(Y in C(X)) >= 1-alpha` |
| Numerical stability | Log-domain arithmetic | No overflow/underflow |
| Queue stall detection | M/M/1 queueing theory | `P(N >= L) = rho^L` |
| Fleet safety | Chandy-Lamport snapshots | No kills on invalid cut |

---

## Decision Theory Deep Dive

The decision engine goes far beyond simple threshold-based kill/spare. It implements a full decision-theoretic framework:

### Expected Loss Minimization

For each candidate, `pt` computes the expected loss for all 8 possible actions under the current posterior:

```
E[L(action)] = sum_c P(c | evidence) * L(action, c)
```

The loss matrix encodes domain knowledge: killing a useful process is very expensive (loss = 100), but keeping an abandoned process is only moderately costly (loss = 10). The action with minimum expected loss wins.

### Value of Information

Before committing to an action, `pt` evaluates whether gathering more evidence would change the decision. The VoI framework considers 9 probe types:

| Probe | Cost | What It Reveals |
|-------|------|-----------------|
| Wait 5 min | ~5 min | Whether CPU/IO patterns change |
| Wait 15 min | ~15 min | Longer behavioral observation |
| Quick scan | ~1 sec | Basic process state |
| Deep scan | ~30 sec | Full /proc inspection |
| Stack sample | ~2 sec | Thread backtraces |
| Strace | ~5 sec | System call activity |
| Network snapshot | ~3 sec | Socket states and queue depths |
| I/O snapshot | ~2 sec | Read/write rates |
| Cgroup inspect | ~1 sec | Resource limits and usage |

A probe is only worth taking if its expected information gain exceeds its cost: `VoI(m) = E[loss_reduction(m)] - cost(m)`. Probes are ranked by a Whittle-style index `(-VoI) / cost` for budget-constrained scheduling.

### FDR Control for Multiple Kill Decisions

When triaging many processes at once, killing the top-N by score without correction inflates the false discovery rate. `pt` uses e-value based multiple testing:

- **eBH** (e-value Benjamini-Hochberg): assumes positive regression dependency
- **eBY** (e-value Benjamini-Yekutieli): conservative, handles arbitrary dependence

The correction factor `c(m) = H_m = sum 1/j` for eBY means you can kill fewer processes per session, but each kill has a controlled false discovery rate.

### Contextual Bandits for Action Selection

For processes where the optimal action is uncertain, `pt` uses a LinUCB contextual bandit with ridge regression per-action models. This balances exploitation (take the action with best historical outcomes) against exploration (try actions we're uncertain about to gather data).

### Gittins Index for Probe Scheduling

The Wonham filter (continuous-time Bayesian filter using matrix exponential `exp(Q * dt)`) estimates the current regime, and the Gittins index computes the optimal probe order under discounted rewards. This determines whether to invest time in a deeper scan or commit to an action now.

---

## Fuzz Testing

13 fuzz targets exercise every parser that touches external input:

```bash
# Run a fuzz target (requires cargo-fuzz)
cargo fuzz run fuzz_proc_stat
```

| Target | What It Fuzzes |
|--------|---------------|
| `fuzz_proc_stat` | `/proc/[pid]/stat` parser |
| `fuzz_proc_io` | `/proc/[pid]/io` parser |
| `fuzz_proc_sched` | `/proc/[pid]/sched` parser |
| `fuzz_proc_schedstat` | `/proc/[pid]/schedstat` parser |
| `fuzz_proc_statm` | `/proc/[pid]/statm` parser |
| `fuzz_proc_cgroup` | `/proc/[pid]/cgroup` parser |
| `fuzz_proc_environ` | `/proc/[pid]/environ` parser |
| `fuzz_network_tcp` | `/proc/net/tcp` parser |
| `fuzz_network_udp` | `/proc/net/udp` parser |
| `fuzz_network_unix` | `/proc/net/unix` parser |
| `fuzz_bundle_reader` | `.ptb` bundle format parser |
| `fuzz_config_policy` | `policy.json` deserializer |
| `fuzz_config_priors` | `priors.json` deserializer |

Every `/proc` parser must handle arbitrary garbage input without panicking or corrupting state.

---

## Scenario Configurations

Ready-to-use profiles in [examples/configs/](examples/configs/):

| Profile | Use Case | Min Age | Robot Mode | Max Kills |
|---------|----------|---------|:----------:|-----------|
| `developer.json` | Aggressive dev cleanup | 30 min | Off | Unlimited |
| `server.json` | Conservative production | 4 hours | Off | 3 |
| `ci.json` | CI/CD automation | 15 min | On | 10 |
| `fleet.json` | Multi-host discovery | 1 hour | On | 5/host |

```bash
pt-core config validate examples/configs/developer.json --format summary
```

---

## Troubleshooting

### "gum: command not found"

```bash
# Debian/Ubuntu
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://repo.charm.sh/apt/gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/charm.gpg
echo "deb [signed-by=/etc/apt/keyrings/charm.gpg] https://repo.charm.sh/apt/ * *" | sudo tee /etc/apt/sources.list.d/charm.list
sudo apt update && sudo apt install gum

# macOS
brew install gum
```

### "No candidates found"

Expected on clean systems! `pt` won't invent problems. Check: minimum age threshold is 1 hour by default. To lower it:

```bash
pt agent plan --min-age 60  # 1 minute instead of 1 hour
```

### Permission errors

```bash
sudo setcap cap_sys_ptrace=ep $(which pt-core)  # Grant /proc access
sudo pt deep                                      # Or run elevated
```

### "pt-core not found"

```bash
curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/process_triage/main/install.sh | bash
ls -la ~/.local/bin/pt-core
```

### TUI won't run

The TUI requires building with `--features ui`:

```bash
cargo run -p pt-core --features ui -- run
```

---

## Limitations

- **Linux-first**: Deep scan features (`/proc` parsing, cgroup limits, io_uring probes) require Linux. macOS has basic collection via `ps`/`lsof`.
- **No Windows native**: Windows support is via WSL2 only.
- **Calibration needed**: Conformal prediction gates require 20+ human-reviewed calibration samples before they activate. Until then, robot mode uses posterior-only gating.
- **Single-machine focus**: Fleet mode exists but is newer and less battle-tested than single-host triage.
- **No automatic recovery**: `pt` kills processes but doesn't restart them. If the process has a supervisor (systemd, Docker), the supervisor handles restart.

---

## FAQ

**Q: Will `pt` ever kill something it shouldn't?**
By design, no. Interactive mode always asks for confirmation. Robot mode requires 95%+ posterior confidence, passes through conformal FDR control, and checks blast-radius risk. Protected processes are never flagged regardless of score.

**Q: How does it learn from my decisions?**
Kill/spare decisions are saved to `decisions.json`. When `pt` sees a similar command pattern again, it adjusts the prior based on your past choices.

**Q: Does it phone home?**
No. All data stays on your machine. No telemetry, no analytics, no network calls (except `install.sh` downloading the binary).

**Q: Can I use it in CI/CD?**
Yes. `pt agent plan --format json` produces structured output with exit codes. Set `robot_mode.enabled = true` in `policy.json` and configure safety gates appropriately.

**Q: What's the "Galaxy-Brain" mode?**
The evidence ledger's detailed view that shows every Bayes factor, every evidence term contribution, and the full posterior computation. Available via `pt deep` or `pt agent plan --deep --format json`.

**Q: How is this different from `kill -9`?**
`pt` tells you *what* to kill and *why*, with confidence scores and impact estimates. It also uses staged signals (SIGTERM first), validates process identity to prevent PID-reuse mistakes, and logs everything for audit.

**Q: Why so many statistical models? Isn't a simple heuristic enough?**
Simple heuristics work for obvious cases (zombie processes, 0% CPU for hours). But the interesting cases are ambiguous: a process using 2% CPU might be doing useful background work or might be a stuck event loop. Different models capture different signals. BOCPD catches sudden behavior changes, HSMM models state transitions, queueing theory detects socket stalls. The ensemble gives more robust classification than any single model.

**Q: What happens if `pt` kills a supervised process?**
If the process is managed by systemd, Docker, or another supervisor, the supervisor will typically restart it. `pt` detects supervisor relationships and factors this into its recommendation. Supervised processes get a higher blast-radius score (since killing them may not accomplish anything if they auto-restart), and the evidence ledger notes "Supervisor may auto-restart (reducing kill effectiveness)."

**Q: How does provenance-aware blast radius differ from just counting child processes?**
Child count is a crude proxy. Blast radius traces *shared resources*: two processes that share a lockfile, a TCP listener on the same port, or a pidfile are connected even if they have no parent-child relationship. It then propagates transitively. If A shares a lockfile with B, and B shares a listener with C, killing A may indirectly affect C. Confidence decays with graph distance (50% per hop by default).

**Q: Can I tune the Bayesian priors?**
Yes. Edit `~/.config/process_triage/priors.json`. Each of the four classes (Useful, Useful-Bad, Abandoned, Zombie) has configurable Beta distribution parameters for CPU, orphan status, TTY, network activity, I/O activity, queue saturation, and runtime (Gamma distribution). The defaults work well for development machines; production servers may want higher `useful.prior_prob`.

**Q: What's TOON output format?**
TOON is a token-optimized structured output format designed for AI agents. It's more compact than JSON (fewer tokens for the same information), making it cheaper to consume in LLM contexts. Use `pt agent plan --format toon` or set `PT_OUTPUT_FORMAT=toon`.

**Q: How accurate is the queue stall detection?**
The M/M/1 queueing model estimates traffic intensity (rho) from socket queue depths parsed from `/proc/net/tcp`. It uses EWMA smoothing to avoid false positives from transient spikes. A process is flagged as stalled when rho exceeds 0.9 and the smoothed queue depth exceeds 4KB for at least 2 consecutive observations. The signal feeds into the posterior as a Beta-Bernoulli evidence term favoring the Useful-Bad class.

---

## About Contributions

Please don't take this the wrong way, but I do not accept outside contributions for any of my projects. I simply don't have the mental bandwidth to review anything, and it's my name on the thing, so I'm responsible for any problems it causes; thus, the risk-reward is highly asymmetric from my perspective. I'd also have to worry about other "stakeholders," which seems unwise for tools I mostly make for myself for free. Feel free to submit issues, and even PRs if you want to illustrate a proposed fix, but know I won't merge them directly. Instead, I'll have Claude or Codex review submissions via `gh` and independently decide whether and how to address them. Bug reports in particular are welcome. Sorry if this offends, but I want to avoid wasted time and hurt feelings. I understand this isn't in sync with the prevailing open-source ethos that seeks community contributions, but it's the only way I can move at this velocity and keep my sanity.

---

## Origins

Created by **Jeffrey Emanuel** after a session where 23 stuck `bun test` workers and a 31GB Hyprland instance brought a 64-core workstation to its knees. Manual process hunting is tedious; statistical inference should do the work.

---

## License

MIT License (with OpenAI/Anthropic Rider) — see [LICENSE](LICENSE) for details.

---

<div align="center">

Built with Rust, Bash, and hard-won frustration.

[Documentation](docs/) · [Agent Guide](docs/AGENT_INTEGRATION_GUIDE.md) · [Math Proofs](docs/math/PROOFS.md) · [Issues](https://github.com/Dicklesworthstone/process_triage/issues)

</div>
