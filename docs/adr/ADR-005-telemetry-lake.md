# ADR-005: Local-First Telemetry Lake with Redaction

- Status: Accepted
- Date: 2026-02-14

## Context

Debugging inference behavior requires reproducible evidence artifacts, but process metadata can include sensitive details.

## Decision

Persist local telemetry/session artifacts by default with redaction-aware profiles and bounded retention controls.

## Consequences

- Enables reproducibility and model calibration loops.
- Avoids mandatory external telemetry services.
- Requires ongoing governance of retention/redaction defaults.
