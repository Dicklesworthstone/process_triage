# Provenance Privacy Model

This document defines the privacy contract for provenance data introduced by the `bd-ppcl.15` bead.

The goal is simple: provenance should make process triage safer and more explainable without turning session artifacts, logs, bundles, reports, or fleet output into a leak of local repo names, filesystem layout, host identities, or accidental secrets.

## Core Rules

Every provenance field must have explicit rules for:

- collection
- persistence
- export
- display
- logging
- retention
- operator consent

Those rules are now machine-visible in [`pt_common::provenance::ProvenancePrivacyPolicy`](/data/projects/process_triage/crates/pt-common/src/provenance.rs).

## Sensitivity Classes

The typed contract uses these sensitivity levels:

- `public_operational`: low-risk operational metadata such as collector names
- `operator_context`: local workflow context that can reveal habits or session structure
- `local_path`: repo roots, worktrees, lockfile paths, and other on-disk identifiers
- `infrastructure_identity`: hostnames and comparable fleet-identifying context
- `secret_adjacent`: raw command lines, env values, or similarly dangerous surfaces

## Handling Semantics

The policy uses one of these actions per surface:

- `allow`: retain the value verbatim
- `summarize`: keep the semantic meaning but not the literal original text
- `hash`: emit a stable redacted identifier
- `redact`: replace the value with a redaction sentinel
- `omit`: do not carry the value onto that surface

This avoids vague "we redact stuff" language. A later bead can point to a typed rule and implement it directly.

## Retention and Consent

Retention classes are intentionally coarse:

- `ephemeral`: do not preserve beyond the immediate operation
- `session`: keep only for the active/local session artifact
- `short_term`: bounded local persistence
- `long_term`: safe for durable retention if still policy-compliant

Consent levels are also explicit:

- `none`: no extra consent gate
- `explicit_operator`: operator must explicitly opt in before disclosure on that surface
- `support_escalation`: only for deliberate support/debug workflows

## Consequences of Missing or Redacted Evidence

Later provenance consumers must not silently treat missing data as safe. The typed policy already records what happens when evidence is missing or redacted:

- confidence may downgrade to `medium`, `low`, or `unknown`
- explanations must add an explicit note when privacy policy withheld detail
- some surfaces should suppress specifics entirely rather than guessing

That means provenance-aware scoring, output, and action-gating work can say:

- what was hidden
- why it was hidden
- how that affected confidence

## Default Policy Shape

The default policy currently covers the highest-risk/most-foundational selectors:

- process labels
- raw process command attributes
- workspace labels and `repo_root`
- host labels and snapshot host IDs
- procfs and git evidence sources
- filesystem path evidence
- raw command-line evidence
- environment-value evidence
- snapshot session IDs

This is intentionally the minimum contract needed to unblock downstream beads. Future provenance collectors and output surfaces should extend the selector set instead of introducing ad hoc privacy logic elsewhere.
