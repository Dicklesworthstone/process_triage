# Provenance Controls And Rollout

This document defines the control contract introduced for `bd-ppcl.17`.

It is intentionally explicit about two things:

- which provenance controls exist
- how they resolve to safe defaults in each runtime context

The typed implementation lives in `crates/pt-config/src/provenance.rs`.

## Control Surfaces

The control model exposes the same knobs through config, environment variables, and CLI flags:

| Purpose | Config key | Environment | CLI flag |
|---------|------------|-------------|----------|
| Rollout posture | `provenance.posture` | `PT_PROVENANCE_POSTURE` | `--provenance-posture` |
| Collection depth | `provenance.collection_depth` | `PT_PROVENANCE_DEPTH` | `--provenance-depth` |
| Persistence posture | `provenance.persistence` | `PT_PROVENANCE_PERSIST` | `--provenance-persist` |
| Export posture | `provenance.export` | `PT_PROVENANCE_EXPORT` | `--provenance-export` |
| Redaction level | `provenance.redaction_level` | `PT_PROVENANCE_REDACTION` | `--provenance-redaction` |
| Explanation verbosity | `provenance.explanation_verbosity` | `PT_PROVENANCE_EXPLAIN` | `--provenance-explain` |

Those names are currently a contract and a testable default-resolution model. Later provenance implementation beads should wire them into actual CLI/config parsing without renaming them.

## Rollout Postures

| Posture | Intent |
|---------|--------|
| `disabled` | No provenance collection or explanation |
| `conservative` | Safe-by-default local collection with no export |
| `standard` | Normal operator-facing provenance with redacted export |
| `deep` | Rich provenance for explicit troubleshooting or support flows |

## Context Defaults

The same posture does not mean the same behavior in every command mode. Context caps keep the feature from becoming surprising.

| Context | Collection | Persistence | Export | Redaction | Explanation |
|---------|------------|-------------|--------|-----------|-------------|
| `scan` | up to `standard` | up to `session_only` | up to `redacted` | any | up to `standard` |
| `deep_scan` | up to `deep` | up to `session_and_bundle` | up to `consented` | any | up to `verbose` |
| `daemon` | up to `minimal` | up to `session_only` | `none` | `strict` | up to `summary` |
| `fleet` | up to `standard` | up to `session_only` | up to `redacted` | up to `balanced` | up to `standard` |
| `report` | `none` new collection | up to `session_and_bundle` | up to `consented` | any | up to `verbose` |

## Coherence Rules

The resolver enforces these invariants:

- outside report rendering, no collection means no persistence, no export, and no explanation stream
- consented export downgrades to redacted export when consent prompts are unavailable
- daemon mode never exports provenance and always forces strict redaction
- report mode is output-only; it cannot trigger fresh provenance collection
- if degraded fallbacks are forbidden, an otherwise invalid posture collapses to disabled instead of guessing

## Debug Logging Contract

Resolvers and future CLI wiring should emit:

- `provenance_control_posture_resolved`

And include:

- `context`
- `posture`
- `collection_depth`
- `persistence`
- `export`
- `redaction_level`
- `explanation_verbosity`
- `forced_downgrades`

If a command mode forces a safer posture than the user asked for, the downgrade reason should be machine-visible and human-readable.
