# ADR-004: False Discovery Rate (FDR) Control for Batch Decisions

- Status: Accepted
- Date: 2026-02-14

## Context

Batch plans can magnify statistical error when multiple candidates are acted on at once.

## Decision

Apply FDR control to batch candidate selection and expose selection/rejection counts in artifacts.

## Consequences

- Improves global safety characteristics of multi-action runs.
- May defer some plausible actions when confidence is borderline.
- Gives operators a clear precision/recall tradeoff dial via policy.
