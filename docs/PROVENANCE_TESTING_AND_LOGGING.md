# Provenance Testing And Logging

This document is the standard place for provenance fixture usage, regression coverage, and structured debug-log vocabulary.

It exists to satisfy `bd-ppcl.16`: later provenance beads should be able to add coverage without inventing new fixture layouts or ad hoc trace messages.

## Canonical Fixture Pack

The provenance fixture pack lives in `test/fixtures/pt-core/`:

| Fixture | Purpose |
|---------|---------|
| `provenance_privacy_snapshot.json` | Graph snapshot with redacted/missing/conflicted evidence |
| `provenance_output_disabled.json` | Golden snapshot: `CandidateProvenanceOutput::disabled()` |
| `provenance_output_full.json` | Golden snapshot: full output with score_impact breakdown |
| `provenance_output_redacted_high_blast.json` | Golden snapshot: partial redaction + high blast radius |
| `logs/provenance_debug_trace.jsonl` | Canonical debug trace event vocabulary |

Those fixtures intentionally cover:

- redacted evidence
- missing evidence
- conflicted/derived evidence
- confidence downgrade warnings
- explicit privacy-policy metadata
- structured output contract serialization stability (disabled, full, redacted+high-blast variants)
- score-impact feature contributions

## Shared Helper API

Rust integration tests should use the shared loader in:

- `crates/pt-core/tests/support/provenance_fixture.rs`

Available helpers:

- `provenance_fixture_path(name)`
- `provenance_log_fixture_path(name)`
- `load_provenance_graph_fixture(name)`
- `load_provenance_trace_fixture(name)`

The goal is to keep future provenance tests loading the same fixture shapes instead of open-coding path logic repeatedly.

## Coverage Guidance

Use these layers consistently:

- unit tests: pure provenance helpers, policy rules, selectors, confidence downgrade logic
- Rust integration tests: schema round-trips, session/bundle boundaries, output formatting, graph reasoning
- BATS: CLI-visible provenance output, report generation, bundle import/export behavior, daemon/fleet shell workflows
- snapshots/golden tests: TUI/report/JSON or TOON rendering when provenance becomes user-visible

Every provenance bead should include at least one negative-path test when it touches:

- redaction
- omission
- contradiction/conflict handling
- confidence downgrade behavior
- policy-gated output

## Debug-Log Vocabulary

Use these canonical event names in structured logs:

- `provenance_fixture_loaded`
- `provenance_evidence_redacted`
- `provenance_evidence_missing`
- `provenance_confidence_downgraded`
- `provenance_graph_warning_emitted`
- `provenance_blast_radius_reasoned`
- `provenance_evidence_selected` (per-feature log-likelihood trace)
- `provenance_blast_radius_computed` (risk score, level, affected count)

Required fields by event family:

- all events: `event`, `timestamp`, `session_id`, `privacy_version`, `message`
- evidence events: `evidence_id`, plus `selector` or `status` when relevant
- downgrade events: `before`, `after`, `warning_code`
- blast-radius events: `node_id`, `edge_id`, `reason`, `confidence`

## Failure Triage Rules

When provenance tests fail, debug in this order:

1. schema mismatch or fixture drift
2. redaction-policy mismatch
3. missing/contradictory evidence handling
4. confidence downgrade propagation
5. user-visible message/rendering drift

If a failure touches privacy behavior, the trace should say whether the value was:

- redacted
- withheld by policy
- omitted because collection is forbidden
- missing because the collector could not observe it

Do not collapse those cases into a generic “unavailable” message in logs or tests.
