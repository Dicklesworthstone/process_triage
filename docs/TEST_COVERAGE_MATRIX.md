# Test Coverage Matrix (No-Mock & E2E Logging)

Last updated: 2026-01-15

## Executive Summary

We do **not** have full no-mock unit coverage or complete E2E integration scripts with
rich JSONL logging. Many unit tests exist, but several critical paths rely on
synthetic fixtures or no-op runners rather than real process interactions. E2E
coverage is partial and logging artifacts are not consistently standardized.

This matrix summarizes current coverage and identifies gaps. Each gap is linked
to a bead (existing or newly created) for systematic closure.

Legend:
- U = Unit tests (module-level)
- I = Integration tests (CLI/real system interactions)
- E = End-to-end workflows
- P = Property-based tests
- NM = No-mock / real system interaction coverage
- ✓ = present, ~ = partial, ✗ = missing

## Coverage Matrix

| Area | U | I | E | P | NM | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| pt-core collect (quick/deep/proc parsers) | ✓ | ~ | ✗ | ✗ | ✗ | Unit tests are fixture/string based; no real /proc harness yet. |
| pt-core cgroup/container/systemd | ✓ | ~ | ✗ | ✗ | ✗ | Tests parse synthetic paths/strings; no live systemd/cgroup coverage. |
| pt-core action (executor/signal/recovery) | ✓ | ✗ | ✗ | ✗ | ✗ | No real process pause/kill; mostly in-memory/no-op. |
| pt-core decision (expected loss/enforcer/FDR) | ✓ | ~ | ✗ | ✗ | ~ | Uses config fixtures; no mockless integration of policy + priors. |
| pt-core inference (posterior, ledgers, advanced models) | ✓ | ✗ | ✗ | ~ | ~ | Unit tests + some math property tests exist; no E2E. |
| pt-core logging/events/progress | ✓ | ✗ | ✗ | ✗ | ~ | JSONL tests exist but not validated against schemas. |
| pt-core plan/session | ✓ | ✗ | ~ | ✗ | ~ | Plan tests exist; session E2E partial. |
| pt-common (id/config/galaxy_brain) | ✓ | ✗ | ✗ | ✗ | ~ | Unit tests only. |
| pt-config (policy/priors/resolve) | ✓ | ✗ | ✗ | ✗ | ~ | Unit tests with fixtures. |
| pt-math | ✓ | ✗ | ✗ | ✓ | ~ | Property tests exist, but not end-to-end. |
| pt-redact | ✓ | ~ | ✗ | ✗ | ~ | Integration tests exist; no E2E harness. |
| pt-telemetry | ✓ | ✗ | ✗ | ✗ | ~ | Unit tests exist; no retention/E2E. |
| bash pt (BATS) | ✓ | ~ | ~ | ✗ | ~ | BATS covers wrapper paths; no full E2E w/ logs. |

## Gaps and Bead Mapping

### No-mock test gap map (P0)
- `process_triage-aii.7.1` — Coverage matrix + gap map (this document)
- `process_triage-aii.7.2` — Real-process test harness (spawn/cleanup, /proc snapshots, PID reuse)
- `process_triage-aii.7.3` — No-mock evidence collection tests (quick/deep/cgroup/container/systemd)
- `process_triage-aii.7.4` — No-mock action execution tests (pause/kill, verify, TOCTOU)
- `process_triage-aii.7.5` — No-mock decision + policy gate tests
- `process_triage-aii.7.6` — No-mock logging/telemetry tests (JSONL schema + retention)

### E2E logging harness and workflows (P0)
- `process_triage-aii.7.7` — E2E runner harness with JSONL logs + artifacts
- `process_triage-aii.7.8` — E2E CLI workflows with detailed JSONL logging
- `process_triage-aii.7.9` — E2E agent workflows with detailed JSONL logging

### CI/Artifacts (P1)
- `process_triage-aii.7.10` — CI upload of E2E JSONL logs + artifacts

### Existing related beads (already in queue)
- `process_triage-c3n` — Integration tests for evidence collection
- `process_triage-5h69` — E2E agent workflows
- `process_triage-be8` — E2E CLI workflows
- `process_triage-zbd` — Main pt workflow E2E
- `process_triage-c982` — Safety gate tests
- `process_triage-y3ao` — Automation/robot mode tests
- `process_triage-aii.*` — Other E2E/benchmark/property suites

## Notes on “No-Mock” Policy

Current unit tests rely on fixtures or synthetic strings. To comply with the
no-mock policy, tests must:
- Use real processes spawned by a harness (short-lived, deterministic).
- Capture `/proc`/cgroup/systemd outputs live (with graceful skips when not available).
- Emit structured JSONL logs for every test case and E2E run.

## Next Actions

1. Implement the real-process harness (`process_triage-aii.7.2`).
2. Wire evidence collection + action tests to use it (`process_triage-aii.7.3`, `aii.7.4`).
3. Add the E2E runner harness and log/artefact layout (`process_triage-aii.7.7`).
4. Expand CLI/agent E2E coverage with logs (`aii.7.8`, `aii.7.9`).

