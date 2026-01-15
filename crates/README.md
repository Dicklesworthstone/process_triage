# Process Triage Rust Crates

This directory contains the Rust workspace for `pt-core`, the Process Triage inference and decision engine.

## Workspace Structure

```
crates/
├── pt-core/      # Binary crate: CLI entrypoint and orchestration
├── pt-common/    # Library crate: shared types, IDs, errors, schemas
└── pt-math/      # Library crate: numerical stability primitives
```

## Crate Responsibilities

### pt-core (binary)

The main entry point. Responsibilities:
- CLI subcommand routing (`run`, `scan`, `agent`, etc.)
- Session lifecycle management
- Coordination between inference, decision, and action modules
- Output formatting and exit codes

### pt-common (library)

Shared foundational types. Responsibilities:
- Process identity types (`ProcessId`, `StartId`, `SessionId`)
- Schema versioning constants
- Unified error types with error codes
- Output format specifications

### pt-math (library)

Numerical stability primitives for log-domain Bayesian inference:
- `log_sum_exp` - numerically stable log-sum-exp
- `log_add_exp` / `log_sub_exp` - pairwise operations
- `log_gamma` - log-gamma function (lgamma)
- `log_beta` / `log_factorial` / `log_binomial` - combinatorial functions

## Future Crates (planned)

These will be added as implementation progresses:

- `pt-collect` - Process collection abstractions + platform-specific implementations
- `pt-features` - Deterministic derived features + provenance tracking
- `pt-infer` - Posterior computation, Bayes factors, evidence ledger
- `pt-decide` - Expected-loss, stopping rules, VOI, FDR gates
- `pt-action` - Action planning + staged execution
- `pt-telemetry` - Parquet writer, redaction, event schemas
- `pt-report` - HTML report generation
- `pt-bundle` - `.ptb` pack/unpack + manifest/checksums

## Building

```bash
# Build all crates
cargo build

# Build release
cargo build --release

# Run tests
cargo test --workspace

# Run pt-core
cargo run -p pt-core -- --help
```

## Feature Flags

`pt-core` supports these compile-time features:

- `deep` - Enable expensive/privileged probes (lsof, ss, perf/eBPF)
- `report` - HTML report generator dependencies
- `daemon` - Dormant monitoring mode
- `ui` - Premium TUI experience

Feature flags never change inference math semantics—they only control available evidence sources and output surfaces.

## Adding New Evidence Sources

When adding a new evidence source, follow this path:

1. **Collection** (`pt-collect`): Add platform-specific collection code
2. **Features** (`pt-features`): Add deterministic feature derivation with provenance
3. **Inference** (`pt-infer`): Add likelihood term to posterior computation
4. **Ledger** (`pt-infer`): Include in math ledger for galaxy-brain mode
5. **Tests**: Add unit tests at each layer

## Cross-Platform Notes

- Use `cfg(target_os = "linux")` and `cfg(target_os = "macos")` for platform-specific code
- Linux collectors use `/proc`, cgroups, etc.
- macOS collectors use `ps`, `proc_pidinfo`, `lsof` equivalents
- Always tag features with platform provenance
