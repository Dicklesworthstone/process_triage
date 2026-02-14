# Architecture Overview

`pt` uses a Bash wrapper for installation/update/discovery and delegates inference + execution to `pt-core` (Rust).

## Dataflow

```mermaid
flowchart LR
    A[pt wrapper] --> B[pt-core CLI]
    B --> C[Config Loader]
    B --> D[Process Sampler]
    D --> E[Evidence Extractors]
    E --> F[Bayesian Inference]
    F --> G[Risk and Policy Gates]
    G --> H[Plan Output]
    H --> I[Review UX or Agent JSON]
    I --> J[Apply Engine]
    J --> K[Audit and Telemetry]
```

Raw source for the diagram: `docs/architecture/flow.mmd`.

## Components

- `pt`: thin wrapper for binary lookup, install/update ergonomics.
- `pt-core`: command surface, inference, safety gates, report/session artifacts.
- `pt-config`: shared schemas + preset definitions.
- `pt-telemetry`: retention, shadow mode, and observability artifacts.

## Safety-Critical Boundaries

- Decisions are recommendations until explicit apply paths are invoked.
- Identity validation and protected pattern checks execute before signal dispatch.
- Robot/agent flows inherit policy-based constraints (posterior thresholds, kill caps, blast-radius limits).
