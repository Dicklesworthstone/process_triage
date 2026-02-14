# ADR-003: Safety Gates Before Any Destructive Action

- Status: Accepted
- Date: 2026-02-14

## Context

False positives in process cleanup can cause data loss, broken sessions, and service interruption.

## Decision

Require explicit safety gates: identity validation, protected patterns/users, staged signals, and confirmation requirements.

## Consequences

- Reduces accidental termination risk.
- Adds small latency to action execution.
- Keeps robot mode constrained and auditable.
