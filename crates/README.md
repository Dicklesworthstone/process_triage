# Process Triage Rust Crates

This directory contains the Rust workspace that powers Process Triage. `pt-core`
is the user-facing binary, while the other crates provide shared types,
configuration, math, redaction, bundling, telemetry, and report generation.

## Workspace Structure

```text
crates/
├── pt-bundle/     # Session bundle writer/reader and encryption helpers
├── pt-common/     # Shared types, schemas, IDs, and output contracts
├── pt-config/     # Configuration loading, presets, and validation
├── pt-core/       # Main CLI, orchestration, inference, planning, and actions
├── pt-math/       # Numerical helpers for Bayesian and statistical routines
├── pt-report/     # HTML report generation
├── pt-redact/     # Redaction, normalization, and hashing for persisted data
└── pt-telemetry/  # Telemetry schemas, retention, and Parquet/shadow storage
```

## Crate Responsibilities

### pt-core

The main binary crate. Responsibilities include:
- CLI subcommand routing (`run`, `scan`, `agent`, `robot`, `shadow`, `bundle`)
- Session lifecycle management and artifact persistence
- Process collection, inference, decisioning, planning, and action execution
- Structured output, TUI integration, MCP support, and capability detection

### pt-common

Shared foundational types and contracts:
- Process/session identity types and schema constants
- Output format types used across CLI, agent, and robot flows
- Shared configuration schema pieces and capability metadata

### pt-config

Configuration handling:
- Loading and resolving config directories and files
- Preset definitions and validation
- Shared policy and priors parsing used by `pt-core`

### pt-math

Numerical and statistical primitives:
- Stable Bayesian/log-domain helpers
- Probability utilities used by inference and calibration code
- Benchmark coverage for core math routines

### pt-redact

Privacy and persistence safety:
- Command/path normalization
- Field classification and redaction policies
- Hashing and redaction engines for persisted artifacts

### pt-bundle

Session bundle packaging:
- Bundle manifests and checksums
- ZIP-based bundle read/write paths
- Optional encryption helpers for shareable session artifacts

### pt-telemetry

Observability and retention:
- Arrow/Parquet schema definitions and writers
- Shadow-mode storage helpers
- Retention and pruning logic for telemetry/session data

### pt-report

Reporting output:
- Askama-based HTML report generation
- Evidence, action, and overview report sections
- Report-specific configuration and rendering tests

## Building

```bash
# Check the full workspace
cargo check --workspace --all-targets

# Run tests across the workspace
cargo test --workspace

# Run the main binary from source
cargo run -p pt-core -- --help
```

## Feature Flags

`pt-core` exposes optional features for higher-cost probes and extra output
surfaces:

- `deep` - Enable expensive or privileged probes such as `lsof` and `ss`
- `report` - Enable HTML report generation through `pt-report`
- `daemon` - Enable dormant monitoring mode
- `metrics` - Enable Prometheus/tiny_http metrics endpoints
- `ui` - Enable the ftui-based TUI

Feature flags add capabilities and output surfaces; they do not change the core
policy guarantees around confirmation and safe action application.

## Cross-Platform Notes

- Use `cfg(target_os = "linux")` and `cfg(target_os = "macos")` for OS-specific code
- Linux collection relies on `/proc`, cgroups, and related kernel interfaces
- macOS collection uses platform tools and APIs such as `ps`, `lsof`, and launchd detection
- Platform provenance should remain explicit in collected evidence and capability reporting
