# Package Architecture Specification

**Version**: 1.0.0
**Status**: Draft
**Bead**: process_triage-kze

---

## 1. Overview

Process Triage uses a two-tier architecture:

| Component | Language | Role |
|-----------|----------|------|
| **pt** | Bash | Thin wrapper: installation, capability discovery, launcher |
| **pt-core** | Rust | Monolithic binary: scan, infer, decide, UI, telemetry |

This separation achieves:
1. **Cross-platform ergonomics**: Bash handles platform-specific installation quirks
2. **Numeric correctness**: Rust handles all math (log-domain, special functions)
3. **Performance**: Structured concurrency for collection, fast inference
4. **Testability**: Core logic isolated from environment bootstrapping

---

## 2. Component Responsibilities

### 2.1 pt (Bash Wrapper)

The bash wrapper is responsible for **environment preparation** only. It must NOT contain inference logic, scoring, or decision-making.

#### Responsibilities

| Category | Responsibility | Details |
|----------|---------------|---------|
| **Install** | Self-bootstrap | Auto-install `pt-core` binary if missing |
| **Install** | Tool installation | Install diagnostic tools (sysstat, perf, bpftrace, etc.) |
| **Detect** | OS detection | Identify Linux vs macOS, distro, package manager |
| **Detect** | Capability discovery | Probe which tools are available and functional |
| **Detect** | Permission discovery | Check sudo availability, ptrace scope, eBPF access |
| **Launch** | Version check | Verify pt-core version compatibility |
| **Launch** | Invoke pt-core | Pass capabilities manifest, forward arguments |
| **UX** | Golden path | `pt` with no args → full-auto workflow |

#### What pt Must NOT Do

- Perform inference or scoring
- Make kill/spare decisions
- Parse process data (beyond capability probing)
- Write telemetry
- Implement any algorithm from the spec

### 2.2 pt-core (Rust Monolith)

The Rust binary owns **all functional logic**. It is the "alien artifact."

#### Subcommands

| Subcommand | Purpose |
|------------|---------|
| `pt-core scan` | Quick scan (ps + basic features) |
| `pt-core deep-scan` | Deep scan (/proc, probes, instrumentation) |
| `pt-core infer` | Compute posteriors and Bayes factors |
| `pt-core decide` | Apply decision theory, generate action plan |
| `pt-core ui` | Interactive TUI (Apply Plan mode) |
| `pt-core agent` | Agent/robot CLI (JSON/MD/JSONL outputs) |
| `pt-core duck` | Run DuckDB queries on telemetry |
| `pt-core bundle` | Create shareable .ptb bundles |
| `pt-core report` | Generate single-file HTML report |
| `pt-core daemon` | Dormant monitoring mode |
| `pt-core inbox` | List daemon-created sessions |

#### Responsibilities

| Category | Responsibility |
|----------|---------------|
| **Collection** | Orchestrate quick/deep scans |
| **Collection** | Run tool probes with timeouts and caps |
| **Collection** | Parse and structure raw tool output |
| **Features** | Compute derived features (CPU deltas, change-points, etc.) |
| **Inference** | Compute posteriors P(class|evidence) |
| **Inference** | Generate evidence ledger |
| **Decision** | Compute expected loss |
| **Decision** | Apply FDR/alpha-investing gates |
| **Decision** | Generate action plan |
| **Action** | Validate target identity before kill |
| **Action** | Execute SIGTERM/SIGKILL with TOCTOU safety |
| **Telemetry** | Write Parquet partitions |
| **Telemetry** | Apply redaction policy |
| **UI** | Human TUI (gum-style experience) |
| **UI** | Agent/robot structured output |
| **Report** | Galaxy-brain mode explanations |

---

## 3. Interface Contract

### 3.1 Capabilities Manifest

The wrapper discovers system capabilities and passes them to pt-core via a JSON manifest.

#### Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["schema_version", "os", "tools"],
  "properties": {
    "schema_version": {
      "type": "string",
      "const": "1.0.0"
    },
    "os": {
      "type": "object",
      "required": ["family", "name"],
      "properties": {
        "family": { "enum": ["linux", "macos"] },
        "name": { "type": "string" },
        "version": { "type": "string" },
        "kernel": { "type": "string" },
        "arch": { "enum": ["x86_64", "aarch64"] }
      }
    },
    "tools": {
      "type": "object",
      "additionalProperties": {
        "type": "object",
        "required": ["available"],
        "properties": {
          "available": { "type": "boolean" },
          "path": { "type": "string" },
          "version": { "type": "string" },
          "permissions": {
            "type": "object",
            "properties": {
              "sudo": { "type": "boolean" },
              "cap_sys_ptrace": { "type": "boolean" },
              "cap_perfmon": { "type": "boolean" },
              "bpf": { "type": "boolean" }
            }
          },
          "notes": { "type": "string" }
        }
      }
    },
    "proc_fs": {
      "type": "object",
      "properties": {
        "available": { "type": "boolean" },
        "readable_fields": {
          "type": "array",
          "items": { "type": "string" }
        }
      }
    },
    "cgroups": {
      "type": "object",
      "properties": {
        "version": { "enum": ["v1", "v2", "hybrid", "none"] },
        "readable": { "type": "boolean" }
      }
    },
    "systemd": {
      "type": "object",
      "properties": {
        "available": { "type": "boolean" },
        "user_units": { "type": "boolean" }
      }
    },
    "discovered_at": {
      "type": "string",
      "format": "date-time"
    }
  }
}
```

#### Example Manifest

```json
{
  "schema_version": "1.0.0",
  "os": {
    "family": "linux",
    "name": "Ubuntu",
    "version": "24.04",
    "kernel": "6.8.0-40-generic",
    "arch": "x86_64"
  },
  "tools": {
    "ps": { "available": true, "path": "/usr/bin/ps", "version": "procps-ng 4.0.4" },
    "ss": { "available": true, "path": "/usr/sbin/ss", "version": "iproute2-6.1.0" },
    "lsof": { "available": true, "path": "/usr/bin/lsof", "version": "4.98.0" },
    "perf": {
      "available": true,
      "path": "/usr/bin/perf",
      "version": "6.8.12",
      "permissions": { "cap_perfmon": true }
    },
    "bpftrace": {
      "available": true,
      "path": "/usr/bin/bpftrace",
      "version": "0.20.0",
      "permissions": { "bpf": true, "sudo": true }
    },
    "pidstat": { "available": true, "path": "/usr/bin/pidstat", "version": "12.7.4" },
    "nvidia-smi": { "available": false }
  },
  "proc_fs": {
    "available": true,
    "readable_fields": ["stat", "status", "io", "cgroup", "wchan", "fd"]
  },
  "cgroups": {
    "version": "v2",
    "readable": true
  },
  "systemd": {
    "available": true,
    "user_units": true
  },
  "discovered_at": "2026-01-15T08:45:00Z"
}
```

### 3.2 Invocation Protocol

#### Passing the Manifest

The wrapper passes the capabilities manifest via:

1. **Environment variable** (preferred for large manifests):
   ```bash
   PT_CAPABILITIES=/tmp/pt-caps-$$.json pt-core "$@"
   ```

2. **CLI flag** (for explicit control):
   ```bash
   pt-core --capabilities /path/to/manifest.json "$@"
   ```

3. **Stdin** (for piped workflows):
   ```bash
   generate_caps | pt-core --capabilities - "$@"
   ```

#### Caching

The wrapper caches the capabilities manifest at `~/.cache/process_triage/capabilities.json` with a TTL:
- Default TTL: 1 hour
- Force refresh: `pt --refresh-caps`
- The cache includes a hash of installed packages to detect changes

### 3.3 Exit Codes

Both `pt` and `pt-core` use consistent exit codes:

| Code | Meaning | Usage |
|------|---------|-------|
| 0 | Success | Normal completion |
| 1 | General error | Unspecified failure |
| 2 | Invalid arguments | CLI parsing error |
| 3 | Capability error | Required tool missing |
| 4 | Permission denied | Insufficient privileges |
| 5 | Version mismatch | Wrapper/core incompatible |
| 10 | No candidates | Scan found nothing suspicious |
| 11 | User cancelled | Interactive mode abort |
| 12 | Safety gate triggered | Action blocked by policy |
| 20 | Partial success | Some actions failed |
| 21 | Lock contention | Another pt instance running |

### 3.4 Version Coordination

#### Semantic Versioning

Both components use semver: `MAJOR.MINOR.PATCH`

| Component | Version Location |
|-----------|-----------------|
| pt (bash) | `VERSION` variable in script |
| pt-core | `Cargo.toml` version, exposed via `--version` |

#### Compatibility Matrix

The wrapper enforces version compatibility:

```
wrapper_major == core_major AND wrapper_minor <= core_minor
```

Example:
- pt 2.3.0 + pt-core 2.3.0 → OK
- pt 2.3.0 + pt-core 2.4.1 → OK (core newer)
- pt 2.3.0 + pt-core 2.2.0 → FAIL (core older than wrapper expects)
- pt 2.3.0 + pt-core 3.0.0 → FAIL (major mismatch)

#### Version Handshake

```bash
# In pt wrapper
CORE_VERSION=$(pt-core --version --format=json | jq -r .version)
if ! version_compatible "$WRAPPER_VERSION" "$CORE_VERSION"; then
    echo "Error: pt-core version $CORE_VERSION incompatible with pt $WRAPPER_VERSION"
    exit 5
fi
```

---

## 4. Standalone Mode

pt-core MUST be usable without the wrapper for testing and advanced use:

```bash
# Direct invocation with inline capabilities
pt-core --capabilities '{"schema_version":"1.0.0","os":{"family":"linux","name":"Ubuntu"},"tools":{}}' scan

# Minimal mode (discover capabilities at runtime)
pt-core --discover-caps scan
```

When `--discover-caps` is passed, pt-core performs its own (potentially slower) capability discovery instead of relying on the wrapper's cached manifest.

---

## 5. Directory Layout

```
~/.config/process_triage/
├── priors.json           # Bayesian hyperparameters
├── policy.json           # Loss matrix and guardrails
└── decisions.json        # Learning memory (legacy, migrating)

~/.cache/process_triage/
├── capabilities.json     # Cached capabilities manifest
└── capabilities.hash     # Hash for invalidation

~/.local/share/process_triage/
├── telemetry/            # Parquet partitions
│   ├── runs/
│   ├── proc_samples/
│   ├── proc_inference/
│   ├── decisions/
│   └── actions/
├── sessions/             # Per-session artifacts
│   └── <session_id>/
│       ├── plan.json
│       ├── ledger.json
│       └── report.html
└── bundles/              # Exported .ptb files
```

---

## 6. Installation Flow

### First Run

```
┌─────────────────────────────────────────────────┐
│                    pt (bash)                     │
├─────────────────────────────────────────────────┤
│ 1. Check if pt-core exists                      │
│    └─ If missing: download/install pt-core      │
│                                                 │
│ 2. Check pt-core version compatibility          │
│    └─ If incompatible: prompt for update        │
│                                                 │
│ 3. Check/refresh capabilities cache             │
│    └─ If stale: probe tools, write manifest     │
│                                                 │
│ 4. Attempt maximal tool installation            │
│    └─ apt/dnf/brew install diagnostic tools     │
│    └─ Update capabilities cache                 │
│                                                 │
│ 5. Launch pt-core with capabilities             │
│    └─ PT_CAPABILITIES=... pt-core "$@"          │
└─────────────────────────────────────────────────┘
```

### pt-core Binary Distribution

| Platform | Distribution Method |
|----------|---------------------|
| Linux x86_64 | GitHub releases, static musl binary |
| Linux aarch64 | GitHub releases, static musl binary |
| macOS x86_64 | GitHub releases, universal binary |
| macOS aarch64 | GitHub releases, universal binary |
| Cargo | `cargo install pt-core` |
| Homebrew | `brew install pt-core` |
| Nix | `nix profile install pt-core` |

---

## 7. Migration Path

The current `pt` bash script will be refactored in phases:

### Phase 1: Extract Wrapper
- Factor out installation and capability detection into new minimal `pt`
- Current scoring/inference stays in bash temporarily as `pt-legacy`

### Phase 2: Implement pt-core
- Build Rust implementation following this spec
- `pt-core` handles all inference from day 1

### Phase 3: Cutover
- `pt` launches `pt-core` by default
- `pt --legacy` for backward compatibility (temporary)

### Phase 4: Remove Legacy
- Delete bash inference code
- `pt` is purely a wrapper

---

## 8. Testing Strategy

### Wrapper Tests

```bash
# Test capability detection
bats test/wrapper/caps-detection.bats

# Test version compatibility
bats test/wrapper/version-compat.bats

# Test installation flow
bats test/wrapper/install.bats
```

### Interface Tests

```bash
# Test manifest schema compliance
cargo test -p pt-core --test manifest_schema

# Test exit codes
cargo test -p pt-core --test exit_codes

# Test wrapper → core invocation
bats test/integration/wrapper-core.bats
```

### Contract Tests

Both sides can work independently against the interface:
- Wrapper team: generate manifests, test exit code handling
- Core team: accept manifests, produce correct exit codes

---

## 9. Open Questions

1. **Manifest compression**: Should large manifests be gzipped when passed via env var?
   - Recommendation: No, keep simple. Size is manageable (<10KB typical).

2. **Remote capability discovery**: Should pt-core support discovering capabilities over SSH for fleet mode?
   - Recommendation: Defer to fleet mode design (separate bead).

3. **Binary embedding**: Should the pt bash script embed a compressed pt-core binary for offline installs?
   - Recommendation: Optional, via `pt --bundle` for air-gapped deployments.

---

## 10. References

- PLAN §3.0: Execution & Packaging Architecture
- PLAN §3.1: Data Collection Layer
- PLAN §10: Phase 1 - Spec and Config
- Bead: process_triage-40mt (pt-core bootstrap)
- Bead: process_triage-3mi (CLI surface definition)
