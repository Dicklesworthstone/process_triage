# pt

<div align="center">
  <img src="pt_illustration.webp" alt="pt - Bayesian-inspired zombie/abandoned process detection and cleanup">
</div>

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT%2BOpenAI%2FAnthropic%20Rider-blue.svg)](./LICENSE)
[![CI](https://github.com/Dicklesworthstone/process_triage/actions/workflows/ci.yml/badge.svg)](https://github.com/Dicklesworthstone/process_triage/actions/workflows/ci.yml)

</div>

**Process Triage** — Bayesian-inspired zombie/abandoned process detection and cleanup

`pt` identifies and safely manages abandoned processes on your system using a four-class Bayesian inference model. It gathers runtime evidence, computes posterior probabilities, and presents recommendations with full transparency—you always see *why* a process is flagged before any action is taken.

**Non-negotiables:**
- **Conservative by default**: No process is ever killed automatically without explicit confirmation
- **Transparent decisions**: Every recommendation includes the evidence and reasoning behind it
- **Safe operations**: Protected process lists, identity validation, staged kill signals

---

## Quick Install

```bash
curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/process_triage/main/install.sh | bash
```

This installs:
- `pt` — The main bash wrapper for interactive use
- `pt-core` — The Rust inference engine (downloaded automatically for your platform)

### Package Managers

**Homebrew (macOS/Linux):**
```bash
brew tap process-triage/tap
brew install pt
```

**Scoop (Windows via WSL2):**
```powershell
scoop bucket add process-triage https://github.com/process-triage/scoop-bucket
scoop install pt
```

**Winget (Windows native):**
```powershell
winget install --id ProcessTriage.pt --source winget
```

<details>
<summary>Manual installation / alternative methods</summary>

```bash
# Clone and symlink
git clone https://github.com/Dicklesworthstone/process_triage.git
ln -s "$(pwd)/process_triage/pt" ~/.local/bin/pt

# Or install to system-wide location
PT_SYSTEM=1 curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/process_triage/main/install.sh | bash

# Verify signatures + checksums (fail-closed on missing/invalid metadata)
VERIFY=1 curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/process_triage/main/install.sh | bash

# Optional: pin expected release-key fingerprint (from release-signing-public.pem.sha256)
PT_RELEASE_PUBLIC_KEY_FINGERPRINT=<64-hex-sha256> VERIFY=1 \
  curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/process_triage/main/install.sh | bash

# Optional: pin a local trusted release key file instead of downloading it
PT_RELEASE_PUBLIC_KEY_FILE=/path/to/release-signing-public.pem VERIFY=1 \
  curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/process_triage/main/install.sh | bash
```

**Platforms supported:**
- Linux x86_64 (primary)
- Linux aarch64 (ARM64)
- macOS x86_64 (Intel)
- macOS aarch64 (Apple Silicon)
- Windows x86_64 (Winget/Scoop packaging path)

</details>

For Windows package publication and maintainer token requirements, see
[`docs/WINDOWS_PACKAGING.md`](docs/WINDOWS_PACKAGING.md).

---

## What Problem Does This Solve?

Long-running development machines accumulate abandoned processes:
- **Stuck tests**: Jest/pytest workers that hung but never terminated
- **Forgotten dev servers**: Next.js/Vite processes from last week's feature branch
- **Orphaned agents**: Claude/Copilot shell sessions that outlived their usefulness
- **Build artifacts**: Cargo/webpack processes that completed but never exited

These processes consume RAM, CPU, and file descriptors. Manually hunting them through `ps aux | grep` is tedious and error-prone. `pt` automates the detection using statistical inference and presents candidates with confidence scores.

---

## Quickstart: The Golden Path

### Interactive Mode (Recommended)

```bash
pt
```

If you prefer to preserve terminal scrollback (logs and progress above the UI), use inline mode:

```bash
pt run --inline
```

This runs the full triage workflow:
1. **Scan** — Enumerate processes, compute initial scores
2. **Review** — Present candidates sorted by abandonment probability
3. **Confirm** — Select which processes to terminate
4. **Kill** — Send SIGTERM, wait, escalate to SIGKILL if needed

### Quick Scan (Information Only)

```bash
pt scan
```

Shows candidates without offering to kill them. Useful for monitoring system state.

### Deep Scan (More Evidence)

```bash
pt deep
```

Runs additional probes: I/O activity, CPU progress over time, TTY state, network connections, child processes. Higher confidence scores but takes ~10-30 seconds longer.

### Other Commands

```bash
pt history     # View past kill/spare decisions
pt clear       # Clear learned decisions (fresh start)
pt learn       # Interactive tutorial progress + guided exercises
pt diff --last # Compare the latest two sessions
pt --version   # Show version
pt --help      # Full command reference
```

### Shadow Mode (Calibration)

Shadow mode records recommendations and outcomes for calibration without taking any actions.

```bash
pt shadow start                         # Start background observer
pt shadow status                        # Check observer status
pt shadow stop                          # Stop observer
pt shadow export --export-format=json > shadow_data.json
pt shadow report --threshold 0.5 --output shadow_report.json
pt shadow report -f md --threshold 0.5  # ASCII calibration report + curve
```

---

## Core Concepts

### Four-State Classification Model

Every process is classified into one of four states:

| State | Description | Typical Action |
|-------|-------------|----------------|
| **Useful** | Actively doing productive work | Leave alone |
| **Useful-but-bad** | Running but misbehaving (stuck, leaking) | Throttle, review |
| **Abandoned** | Was useful, now forgotten | Kill (usually recoverable) |
| **Zombie** | Terminated but not reaped by parent | Clean up |

The inference engine computes `P(state | evidence)` for all four states using Bayesian posterior updates.

### Evidence-Based Scoring

Each process is evaluated against multiple evidence sources:

| Evidence | What It Measures | Impact |
|----------|------------------|--------|
| Process type | Test runner? Dev server? Build tool? | Prior expectations |
| Age vs lifetime | How long has it been running vs expected? | Overdue processes score higher |
| Parent PID | Is it orphaned (PPID=1)? | Orphaned processes are suspicious |
| CPU activity | Is it actively computing or idle? | Idle + old = likely abandoned |
| I/O activity | Recent file/network I/O? | No I/O for hours = suspicious |
| TTY state | Interactive? Detached? | Detached old processes are suspicious |
| Memory usage | Consuming significant RAM? | High memory + old = priority target |
| Past decisions | Have you spared similar processes before? | Learns from your patterns |

### Confidence Levels

Posterior probabilities translate to confidence:

| Confidence | Posterior | Meaning |
|------------|-----------|---------|
| `very_high` | > 0.99 | Near certain, safe for automation |
| `high` | > 0.95 | High confidence, recommend action |
| `medium` | > 0.80 | Moderate confidence, worth reviewing |
| `low` | < 0.80 | Uncertain, more evidence needed |

### Evidence Ledger (Galaxy-Brain Mode)

For full transparency, use the deep scan with JSON output:

```bash
pt deep
# Or for agent/scripted use with detailed output:
pt robot plan --deep --format json
# Token-optimized structured output:
pt robot plan --deep --format toon
```

The JSON output includes the evidence behind each decision:
- Prior probabilities for each class
- Evidence source contributions
- Final posterior computation
- Decision rationale

---

## Safety Model

### Identity Validation

Before killing any process, `pt` validates the target identity:

```
<boot_id>:<start_time_ticks>:<pid>
```

This prevents:
- **PID reuse attacks**: A new process reusing an old PID won't be killed
- **Stale plan execution**: Plans from before a reboot are invalidated
- **Race conditions**: If the process exits and PID is reused, the action is blocked

### Protected Processes

These processes are **never** flagged, regardless of score:

- System services: `systemd`, `dbus`, `pulseaudio`, `pipewire`
- Infrastructure: `sshd`, `cron`, `docker`, `containerd`
- Databases: `postgres`, `mysql`, `redis`, `elasticsearch`
- Web servers: `nginx`, `apache`, `caddy`
- Any process owned by root (unless explicitly targeted)

Protected patterns are configurable in `policy.json`.

### Staged Kill Signals

Process termination follows a graceful sequence:

1. **SIGTERM** — Request graceful shutdown
2. **Wait** — Allow time for cleanup (configurable timeout)
3. **SIGKILL** — Force termination if SIGTERM fails

### Blast Radius Assessment

Every candidate includes impact analysis:

```
blast_radius:
  memory_mb: 1200
  cpu_pct: 98
  child_count: 3
  risk_level: low
  summary: "Killing frees 1.2GB RAM, terminates 3 children; no external impact"
```

High blast-radius actions require explicit confirmation.

### Robot/Agent Mode Gates

For automated use (`pt agent` or `pt robot`), additional safety gates apply:

| Gate | Default | Purpose |
|------|---------|---------|
| `min_posterior` | 0.95 | Minimum confidence for automation |
| `max_kills` | 10 | Per-session kill limit |
| `max_blast_radius` | 4GB | Maximum memory impact per session |
| `fdr_budget` | 0.05 | False Discovery Rate control |
| `protected_patterns` | (see above) | Always enforced |

---

## Configuration

### Directory Layout

```
~/.config/process_triage/         # or $XDG_CONFIG_HOME/process_triage
├── decisions.json                # Learned kill/spare decisions
├── priors.json                   # Bayesian hyperparameters (advanced)
├── policy.json                   # Safety policy configuration
└── triage.log                    # Operation audit log

~/.local/share/process_triage/    # or $XDG_DATA_HOME/process_triage
└── sessions/                     # Session artifacts
    └── pt-20260115-143022-a7xq/
        ├── manifest.json         # Session metadata
        ├── snapshot.json         # Initial process state
        ├── plan.json             # Generated recommendations
        └── audit.jsonl           # Action audit trail
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PROCESS_TRIAGE_CONFIG` | `~/.config/process_triage` | Config directory |
| `PROCESS_TRIAGE_DATA` | `~/.local/share/process_triage` | Data/session directory |
| `XDG_CONFIG_HOME` | `~/.config` | XDG fallback for config |
| `XDG_DATA_HOME` | `~/.local/share` | XDG fallback for data |
| `NO_COLOR` | (unset) | Disable colored output |

### Priors Configuration (`priors.json`)

For advanced users, the Bayesian priors can be tuned:

```json
{
  "schema_version": "1.0.0",
  "classes": {
    "useful": {
      "prior_prob": 0.70,
      "cpu_beta": { "alpha": 5.0, "beta": 3.0 }
    },
    "abandoned": {
      "prior_prob": 0.15,
      "cpu_beta": { "alpha": 1.0, "beta": 5.0 }
    }
  }
}
```

See [docs/PRIORS_SCHEMA.md](docs/PRIORS_SCHEMA.md) for the full specification.

### Policy Configuration (`policy.json`)

```json
{
  "protected_patterns": [
    "systemd", "sshd", "docker", "postgres"
  ],
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

## Interactive Tutorials and Docs

Use the built-in tutorial workflow to learn the safest operational patterns:

```bash
pt learn
pt learn list
pt learn show 01
pt learn verify --all --mark-complete
```

- Tutorial docs: [docs/tutorials/README.md](docs/tutorials/README.md)
- Architecture overview + flow diagram: [docs/architecture/README.md](docs/architecture/README.md)
- ADR index: [docs/adr/](docs/adr/)
- Demo scripts and recording references: [docs/demos/README.md](docs/demos/README.md)

## Scenario Configurations

Ready-to-use scenario examples live in [examples/configs/](examples/configs/):

- `developer.json`: aggressive dev-machine cleanup profile
- `server.json`: conservative production profile
- `ci.json`: automation/CI-friendly profile
- `fleet.json`: multi-host discovery config (with static inventory)

Validate them quickly:

```bash
pt-core config validate examples/configs/developer.json --format summary
pt-core config validate examples/configs/server.json --format summary
pt-core config validate examples/configs/ci.json --format summary
```

---

## Telemetry and Data Governance

### What Is Collected

`pt` stores evidence and decisions locally for learning and reproducibility:

| Data | Purpose | Retention |
|------|---------|-----------|
| Process metadata | Classification input | Session lifetime |
| Evidence samples | Audit trail, debugging | Configurable (default: 7 days) |
| Kill/spare decisions | Learning future suggestions | Indefinite (user-controlled) |
| Session manifests | Reproducibility | Configurable (default: 30 days) |

### Redaction Policy

Sensitive data is hashed/redacted before persistence:

- **Command arguments**: Paths with user directories are normalized
- **Environment variables**: Never stored
- **File contents**: Never read or stored
- **Network data**: IP addresses are hashed

Redaction profiles control the level of detail preserved:

| Profile | Use Case | Data Preserved |
|---------|----------|----------------|
| `minimal` | Maximum privacy | Hashes only, no plaintext |
| `standard` | Normal operation | Redacted paths, normalized commands |
| `debug` | Troubleshooting | Full detail (local only) |
| `share` | Sending to others | Redacted + anonymized |

### Opting Out

To minimize data collection:

```bash
# Set minimal retention
export PROCESS_TRIAGE_RETENTION=1  # 1 day

# Or disable session persistence entirely
export PROCESS_TRIAGE_NO_PERSIST=1
```

---

## Sharing and Reproducibility

### Session Bundles (`.ptb`)

Export a complete session for sharing or archival:

```bash
pt bundle create --session pt-20260115-143022-a7xq --profile safe --output session.ptb
```

Will create a `.ptb` bundle containing:
- Session manifest and plan
- Redacted process metadata
- Evidence summaries (no raw data)
- Decision rationale

#### Optional Encryption

Encrypt bundles explicitly with a passphrase:

```bash
pt bundle create --session pt-20260115-143022-a7xq --profile safe --encrypt \
  --passphrase "correct horse battery staple"
```

You can also set `PT_BUNDLE_PASSPHRASE` to avoid passing the passphrase on the command line.

Threat model and limitations:
- Protects bundle contents at rest/in transit with passphrase-based encryption.
- Does not hide bundle size or the fact that a bundle exists.
- Does not protect data after decryption; keep decrypted outputs local and access-controlled.
- Security depends on passphrase strength (use a strong, unique passphrase).

### HTML Reports — Planned

Generate a human-readable report:

```bash
# Planned feature
pt report --session pt-20260115-143022-a7xq --output report.html
```

Reports will include:
- Executive summary
- Candidate details with evidence
- Actions taken and outcomes
- System resource impact

Two modes planned:
- **CDN mode** (default): Smaller file, requires internet for styling
- **Offline mode** (`--embed-assets`): Self-contained, works without network

---

## Troubleshooting

### "gum: command not found"

The interactive UI requires [gum](https://github.com/charmbracelet/gum). `pt` attempts auto-installation, but if that fails:

```bash
# Debian/Ubuntu
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://repo.charm.sh/apt/gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/charm.gpg
echo "deb [signed-by=/etc/apt/keyrings/charm.gpg] https://repo.charm.sh/apt/ * *" | sudo tee /etc/apt/sources.list.d/charm.list
sudo apt update && sudo apt install gum

# macOS
brew install gum

# Direct binary
curl -fsSL https://github.com/charmbracelet/gum/releases/latest/download/gum_Linux_x86_64.tar.gz | tar xz
sudo mv gum /usr/local/bin/
```

### "No candidates found"

This is often expected! If your system is clean, `pt` won't invent problems. Common reasons:
- **Minimum age threshold**: By default, only processes older than 1 hour are considered
- **No matching patterns**: Your processes don't match known suspicious patterns
- **Clean system**: Congratulations!

To lower thresholds for testing, use the robot/agent interface:

```bash
pt robot plan --min-age 60  # 1 minute instead of 1 hour
```

### Permission errors

```bash
# If pt-core can't read /proc
sudo setcap cap_sys_ptrace=ep $(which pt-core)

# Or run specific commands with elevated privileges
sudo pt deep
```

### "pt-core not found"

The Rust binary may not have installed correctly:

```bash
# Re-run installer
curl -fsSL https://raw.githubusercontent.com/Dicklesworthstone/process_triage/main/install.sh | bash

# Check installation
ls -la ~/.local/bin/pt-core
```

---

## For AI Agents

`pt` includes a dedicated agent interface for programmatic integration:

```bash
pt agent plan --format json      # Generate actionable plan
pt agent plan --format toon      # Token-optimized plan output
pt agent apply --session <id>    # Execute plan
pt agent verify --session <id>   # Confirm outcomes
pt agent watch --format jsonl    # Stream watch events (JSONL)
```

You can also set a default format via env vars:

```bash
PT_OUTPUT_FORMAT=toon pt agent plan
TOON_DEFAULT_FORMAT=toon pt agent plan
```

See [docs/AGENT_INTEGRATION_GUIDE.md](docs/AGENT_INTEGRATION_GUIDE.md) for:
- Session lifecycle and mental model
- JSON schema reference
- Exit codes and error handling
- Safety gates for automation
- Complete workflow examples

---

## Development and Contributing

### Running Tests

```bash
# BATS tests (bash wrapper)
bats test/

# Rust tests
cargo test --workspace

# Full CI suite
./test/e2e_runner.sh
```

### Code Style

- **Bash**: shellcheck clean, use `[[` over `[`, quote all variables
- **Rust**: `cargo fmt` and `cargo clippy` with no warnings
- **Tests**: Every new feature needs corresponding test coverage

### Coverage

Run coverage locally:

```bash
scripts/coverage.sh
```

### No-Mock Policy (Core Modules)

Core modules avoid mocking frameworks to keep behavior grounded in real system state.

```bash
scripts/check_no_mocks.sh
```

### Project Structure

```
├── pt                    # Main bash wrapper
├── install.sh            # Installer script
├── crates/               # Rust workspace
│   ├── pt-core/          # Main inference engine
│   ├── pt-common/        # Shared types
│   ├── pt-math/          # Statistical computations
│   └── ...
├── docs/                 # User-facing documentation
├── specs/                # Developer specifications
└── test/                 # BATS test suite
```

---

## Origins

Created by **Jeffrey Emanuel** after a session where 23 stuck `bun test` workers and a 31GB Hyprland instance brought a 64-core workstation to its knees. Manual process hunting is tedious—statistical inference should do the work.

---

## License

MIT License (with OpenAI/Anthropic Rider) — see [LICENSE](LICENSE) for details.

---

<div align="center">

Built with Rust, Bash, and hard-won frustration.

[Documentation](docs/) · [Agent Guide](docs/AGENT_INTEGRATION_GUIDE.md) · [Issues](https://github.com/Dicklesworthstone/process_triage/issues)

</div>
