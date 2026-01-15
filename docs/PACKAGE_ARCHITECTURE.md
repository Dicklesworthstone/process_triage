# Package Architecture Specification

> **Bead**: `process_triage-kze`
> **Status**: Specification
> **Version**: 1.0.0

## Overview

Process Triage uses a two-tier architecture:

1. **`pt`** (Bash wrapper): Cross-platform installer, capability discovery, environment detection
2. **`pt-core`** (Rust monolith): All inference, decisioning, telemetry, and UI

This separation enables:
- Graceful degradation on any platform (wrapper handles messy platform specifics)
- Clean, testable core (assumes capabilities are known via manifest)
- Independent development of wrapper and core against a stable interface

---

## pt (Bash Wrapper) Responsibilities

The wrapper is intentionally minimal. It handles platform-specific concerns so the core can focus on inference and UX.

### 1. OS and Environment Detection

```bash
# Detect OS family
os_family()  # → linux | darwin | freebsd | unknown

# Detect package manager
pkg_manager()  # → apt | brew | dnf | pacman | apk | pkg | none

# Detect init system
init_system()  # → systemd | launchd | openrc | sysvinit | unknown

# Detect shell
user_shell()  # → bash | zsh | fish | sh
```

### 2. Capability Discovery

The wrapper probes for available tools and records their presence/version:

```bash
# Required tools (must exist for basic operation)
- ps (procps or BSD)
- kill
- bash 4.0+

# Core tools (highly recommended)
- jq (JSON processing)
- gum (TUI components)

# Deep scan tools (optional, enhance evidence collection)
- lsof
- ss / netstat
- pgrep
- who / w
- git

# Advanced instrumentation (optional, require privileges)
- perf
- bpftrace / bcc
- strace / dtruss
- sysdig
- iotop
- nethogs
- pidstat / iostat / mpstat / sar
- smem
- nvidia-smi / rocm-smi
```

### 3. Maximal Tool Installation (Phase 3a)

The wrapper attempts to install missing tools when possible:

```bash
pt_install_tools() {
    # Only with user consent or --auto-install flag
    # Never requires sudo interactively (use sudo -n)
    # Logs what was installed vs skipped
}
```

**Installation policy**:
- Prefer system package manager
- Fall back to direct binary download for gum, pt-core
- Never block on interactive prompts
- Always report what's available vs missing

### 4. pt-core Binary Management

```bash
# Locate or download pt-core binary
pt_core_path()  # → /usr/local/bin/pt-core | ~/.local/bin/pt-core | ./pt-core

# Version check
pt_core_version()  # → semver string

# Download/update pt-core
pt_core_install()  # Downloads from releases, verifies checksum
```

### 5. Capabilities Manifest Generation

The wrapper generates a JSON manifest describing the environment:

```json
{
  "manifest_version": "1.0.0",
  "generated_at": "2026-01-15T12:00:00Z",
  "os": {
    "family": "linux",
    "release": "Ubuntu 24.04",
    "kernel": "6.17.0-8-generic",
    "arch": "x86_64"
  },
  "init_system": "systemd",
  "package_manager": "apt",
  "user": {
    "uid": 1000,
    "username": "developer",
    "home": "/home/developer",
    "shell": "/bin/bash"
  },
  "tools": {
    "ps": {"available": true, "path": "/usr/bin/ps", "version": "procps 4.0.4"},
    "jq": {"available": true, "path": "/usr/bin/jq", "version": "1.7.1"},
    "gum": {"available": true, "path": "/usr/bin/gum", "version": "0.14.1"},
    "lsof": {"available": true, "path": "/usr/bin/lsof", "version": "4.98.0"},
    "ss": {"available": true, "path": "/usr/sbin/ss", "version": "iproute2-6.4.0"},
    "perf": {"available": true, "path": "/usr/bin/perf", "version": "6.17"},
    "bpftrace": {"available": false, "reason": "not installed"},
    "nvidia-smi": {"available": false, "reason": "no nvidia driver"}
  },
  "privileges": {
    "can_sudo": false,
    "perf_paranoid": 2,
    "ptrace_scope": 1
  },
  "paths": {
    "config_dir": "/home/developer/.config/process_triage",
    "data_dir": "/home/developer/.local/share/process_triage",
    "telemetry_dir": "/home/developer/.local/share/process_triage/telemetry",
    "lock_file": "/home/developer/.local/share/process_triage/pt.lock"
  }
}
```

### 6. Launch pt-core

```bash
# Standard launch
pt_launch() {
    local manifest_file
    manifest_file=$(mktemp)
    generate_capabilities_manifest > "$manifest_file"

    exec pt-core "$@" --capabilities "$manifest_file"
}

# Or via environment variable
PT_CAPABILITIES_MANIFEST=/path/to/manifest.json pt-core "$@"
```

### 7. User-Facing Commands (Thin Wrappers)

The `pt` script exposes friendly commands that delegate to `pt-core`:

| `pt` Command | Delegates To |
|--------------|--------------|
| `pt` (default) | `pt-core run` |
| `pt scan` | `pt-core scan` |
| `pt deep` | `pt-core run --deep` |
| `pt history` | `pt-core history` |
| `pt clear` | `pt-core clear` |
| `pt inbox` | `pt-core inbox` |
| `pt agent ...` | `pt-core agent ...` |
| `pt help` | `pt-core help` |

---

## pt-core (Rust Monolith) Responsibilities

The core handles all computationally intensive and safety-critical operations.

### 1. Subcommand Structure

```
pt-core
├── run              # Default golden path: scan → infer → plan → TUI → apply
├── scan             # Quick multi-sample scan only
├── deep-scan        # Full deep scan with all available probes
├── infer            # Run inference on existing scan data
├── decide           # Compute action plan from inference results
├── ui               # Launch TUI for plan approval
├── agent            # Agent/robot CLI (no TUI)
│   ├── plan         # Generate action plan (JSON)
│   ├── explain      # Explain specific process/decision
│   ├── apply        # Execute approved plan
│   ├── sessions     # List/manage sessions
│   ├── status       # Show session status
│   ├── tail         # Stream progress events
│   ├── verify       # Verify plan still valid
│   ├── diff         # Compare sessions
│   ├── export       # Export session bundle
│   ├── report       # Generate HTML report
│   ├── inbox        # Daemon-created sessions
│   ├── watch        # Background monitoring mode
│   ├── snapshot     # Capture system state
│   ├── capabilities # Report available capabilities
│   ├── list-priors  # Show current priors
│   ├── import-priors # Import priors from file
│   └── export-priors # Export priors to file
├── duck             # DuckDB query interface for telemetry
├── bundle           # Create .ptb session bundle
├── report           # Generate standalone HTML report
├── daemon           # Dormant mode (ptd)
├── inbox            # List daemon-created sessions
├── history          # Show decision history
├── clear            # Clear decision memory
└── help             # Show help
```

### 2. Core Modes

| Mode | Flag | Behavior |
|------|------|----------|
| Default | (none) | scan → infer → plan → TUI approval → staged apply |
| Robot | `--robot` | Skip TUI, execute policy-approved plan automatically |
| Shadow | `--shadow` | Full pipeline but never execute actions (calibration) |
| Dry-run | `--dry-run` | Compute plan only, no execution even with `--robot` |

### 3. Evidence Collection

- Orchestrate staged pipeline: quick scan → ranking → targeted deep scan
- Multi-sample quick scans for delta computation
- Budgeted deep scans (VOI-driven probe selection)
- Self-protection: overhead caps, nice/ionice, concurrency limits

### 4. Inference Engine

- Closed-form Bayesian posterior computation
- Conjugate prior updates (Beta-Binomial, Gamma, Dirichlet)
- Evidence ledger generation (per-term log-likelihood contributions)
- Bayes factor computation
- BOCPD change-point detection
- Survival/hazard analysis

### 5. Decision Theory

- Expected loss computation
- SPRT-style stopping thresholds
- FDR control (BH/BY/alpha-investing)
- Action plan generation with staged execution

### 6. Action Execution

- Identity revalidation before each action (PID + start_id)
- SIGTERM → wait → SIGKILL escalation
- Supervisor-aware routing (systemctl, pm2, docker)
- Outcome logging

### 7. Telemetry

- Parquet-first append-only writes
- DuckDB views for analysis
- Redaction/hashing before persistence
- Retention policy enforcement

### 8. UX

- TUI with gum components
- Progressive disclosure
- Evidence ledger display
- Galaxy-brain math mode

---

## Interface Contract

### Capabilities Manifest Schema

See `docs/schemas/capabilities.schema.json` for the full JSON Schema.

Key fields:
- `manifest_version`: Schema version (semver)
- `os`: Operating system family, release, kernel, arch
- `init_system`: systemd, launchd, etc.
- `package_manager`: apt, brew, etc.
- `user`: uid, username, home, shell
- `tools`: Map of tool name → availability, path, version
- `privileges`: can_sudo, perf_paranoid, ptrace_scope
- `paths`: config_dir, data_dir, telemetry_dir, lock_file
- `system`: cpu_count, memory_total_bytes, clk_tck, boot_id

### Passing Capabilities to pt-core

**Option 1: CLI flag** (preferred)
```bash
pt-core run --capabilities /tmp/caps.json
```

**Option 2: Environment variable**
```bash
PT_CAPABILITIES_MANIFEST=/tmp/caps.json pt-core run
```

**Option 3: Standard location** (fallback)
```bash
# pt-core looks for ~/.config/process_triage/capabilities.json
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Invalid arguments |
| 3 | Capabilities manifest missing/invalid |
| 4 | Lock acquisition failed |
| 10 | No candidates found |
| 11 | All candidates already handled |
| 20 | Action execution failed (some) |
| 21 | Action execution failed (all) |
| 30 | Policy violation blocked action |
| 40 | User cancelled |

---

## Version Coordination

### Compatibility Matrix

| pt wrapper | pt-core | Status |
|------------|---------|--------|
| 1.x | 1.x | Compatible |
| 1.x | 2.x | Wrapper upgrade required |
| 2.x | 1.x | Core upgrade required |

### Version Check Protocol

1. Wrapper checks its own version against minimum required by manifest schema
2. Wrapper checks pt-core version via `pt-core --version`
3. If incompatible, wrapper emits warning and suggests upgrade
4. Core validates manifest_version and fails fast if unsupported

---

## Standalone Mode

For testing and development, pt-core can run without the wrapper:

```bash
# Use default/detected capabilities
pt-core run --standalone

# Or provide explicit overrides
pt-core run --os linux --tools "ps,jq,gum,lsof"
```

In standalone mode, pt-core:
- Uses sensible defaults for paths
- Skips unavailable tools gracefully
- Still enforces all safety constraints

---

## File Layout

```
~/.config/process_triage/
├── priors.json              # Bayesian hyperparameters
├── policy.json              # Loss matrix, guardrails
├── capabilities.json        # Cached capabilities (optional)
└── redaction.json           # Redaction/hashing rules

~/.local/share/process_triage/
├── telemetry/
│   ├── runs/                # Run metadata (Parquet)
│   ├── proc_samples/        # Process samples (Parquet)
│   ├── proc_features/       # Derived features (Parquet)
│   ├── proc_inference/      # Inference results (Parquet)
│   ├── decisions/           # User decisions (Parquet)
│   ├── actions/             # Executed actions (Parquet)
│   └── outcomes/            # Action outcomes (Parquet)
├── sessions/
│   └── <session_id>/        # Per-session artifacts
├── bundles/                 # Exported .ptb files
├── reports/                 # Generated HTML reports
├── decisions.json           # Legacy decision memory (migration)
├── triage.log               # Legacy log (migration)
└── pt.lock                  # Coordination lock file
```

---

## Security Considerations

1. **Privilege Separation**: Wrapper runs as user; never elevates pt-core
2. **Manifest Integrity**: Core validates manifest schema; rejects malformed
3. **Lock Enforcement**: Single active pt-core per user prevents races
4. **Redaction**: Sensitive data hashed before telemetry persistence
5. **Action Validation**: Identity revalidation before every kill

---

## Implementation Checklist

- [ ] Wrapper: OS detection functions
- [ ] Wrapper: Package manager detection
- [ ] Wrapper: Tool availability probing
- [ ] Wrapper: Capabilities manifest generation
- [ ] Wrapper: pt-core binary management
- [ ] Wrapper: Command delegation
- [ ] Core: Manifest parsing and validation
- [ ] Core: Standalone mode fallbacks
- [ ] Core: Version check protocol
- [ ] Schema: capabilities.schema.json
- [ ] Tests: Manifest generation
- [ ] Tests: Cross-version compatibility
- [ ] Docs: User-facing command reference
