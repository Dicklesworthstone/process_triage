# ADR-002: Bayesian Inference as the Primary Scoring Engine

- Status: Accepted
- Date: 2026-02-14

## Context

Heuristic-only systems drift and are hard to calibrate when evidence quality changes across hosts and workloads.

## Decision

Use Bayesian posterior inference (`P(state | evidence)`) as the canonical score source.

## Consequences

- Adds principled uncertainty handling.
- Produces transparent probability outputs for human/agent review.
- Supports configurable priors without changing runtime decision plumbing.
