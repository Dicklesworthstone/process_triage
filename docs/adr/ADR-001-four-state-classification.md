# ADR-001: Four-State Classification Model

- Status: Accepted
- Date: 2026-02-14

## Context

Process cleanup decisions cannot be reduced to a binary keep/kill decision without losing risk signal quality.

## Decision

Use four explicit process states: `useful`, `useful_bad`, `abandoned`, and `zombie`.

## Consequences

- Improves explainability of recommendations.
- Enables policy/loss tuning by class.
- Supports safer automation gates than a binary model.
