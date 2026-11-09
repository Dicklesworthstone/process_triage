# Fixture Governance

This repo uses deterministic, redacted fixtures for no-mock and E2E tests. Each fixture set lives under
`test/fixtures/<domain>/` and includes a `fixture_manifest.json` with checksums and metadata.

## Layout

```
test/fixtures/
├── config/
│   ├── fixture_manifest.json
│   ├── logs/fixture_capture.jsonl
│   └── *.json
├── pt-core/
│   ├── fixture_manifest.json
│   ├── logs/fixture_capture.jsonl
│   └── *.json
└── manifest_examples/
    ├── fixture_manifest.json
    ├── logs/fixture_capture.jsonl
    └── <suite>/...
```

## Manifest Schema

Schema location:
- `specs/schemas/fixture-manifest.schema.json`

Validation command:
```bash
scripts/validate_fixture_manifest.py test/fixtures/<domain>/fixture_manifest.json
```

## Capture / Refresh

Use the capture script to (re)generate manifests deterministically:

```bash
python3 scripts/fixture_capture.py test/fixtures/config \
  --fixture-id config-YYYYMMDD \
  --domain config \
  --description "Config priors/policy fixtures" \
  --origin manual-copy \
  --command "cp crates/pt-config/tests/fixtures/*.json test/fixtures/config/" \
  --source-path "crates/pt-config/tests/fixtures" \
  --tool-version "pt=$(cat VERSION)" \
  --tool-version "schema=fixture-manifest@1" \
  --redaction-profile safe \
  --exclude "logs/*"
```

A JSONL log entry is appended to `logs/fixture_capture.jsonl` with:
- `event`
- `timestamp`
- `fixture_id`
- `duration_ms`
- `artifacts[]`

## Redaction Rules

The capture tool normalizes common sensitive values in metadata:
- Home paths: `/home/<user>` or `/Users/<user>` → `/home/USER`
- UUIDs: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` → `<UUID>`
- Long hex identifiers (>= 32 chars) → `<HEX>`

Fixtures themselves must already be redacted; the manifest validator enforces redaction for
metadata fields (`source.command`, `source.paths`).

## Private live replay recordings and scoring

Record a live census and its scoring observations, then evaluate that recording
without inspecting the replay machine's processes:

```bash
nice -n 19 pt-core scan --format json --record-replay /private/path/scan.json
pt-core scan --replay-scores /private/path/scan.json --format json
```

Recording uses one shared 500 ms activity window by default. Set
`--record-replay-window-ms 0` to use lifetime CPU observations without waiting
for an activity window, or choose a window up to 60,000 ms. This option requires
`--record-replay`. Expensive activity and provenance probes are collected only
for processes eligible under the capture's policy. The complete unfiltered
inventory is retained, including protected, young, and unavailable processes.
Placement and scoring observations are checked against process identities
during capture. Deep scans cannot use this option.

The snapshot contains raw commands, identities, placement, activity, and derived
provenance scoring inputs. It is a **private recording, not a redacted fixture**.
The destination must be new: an existing file or symlink is refused. On Unix it
is created with at most owner read/write permissions. If writing fails, the
command fails and retains any partial file for inspection. Neither recording nor
scoring replay executes process actions.

### What scoring replay evaluates

`--replay-scores` uses the same scorer and protection rules as production, with
the recorded observations supplied explicitly. It does not read live PIDs,
cgroups, service managers, or activity counters. Use `--config DIR` to select
the configuration to evaluate; current priors, signatures, human verdicts, and
their current decay are applied. Historical configuration and the original
evaluation time are not reconstructed.

The JSON report is under `replay`. It includes `population_size`, counts for
`scored`, `protected`, `too_young`, and `unavailable`, and one row in
`processes` for every captured process. Scored rows include the posterior,
evidence ledger, prior source, and matched signature. The four status counts sum
to the retained population. Selecting a broader policy later does not manufacture
observations for processes that were not probed during capture: those rows stay
unavailable when their recorded inputs are insufficient. JSONL emits the full
report as one JSON line.

Replay requires a complete, identity-consistent scoring context from the same
operating system. Inventory-only snapshots still load through `load_snapshot`
and `ReplaySnapshot::to_scan_result`, but are rejected by `--replay-scores`.
Incomplete or mismatched context is rejected rather than replaced by live data.
The `anonymize` helper discards scoring context because hashing commands changes
signature matching and cannot establish faithful scoring equivalence.

### Scope and regression coverage

This command is explicitly **scoring only**. It does not generate action
recommendations, apply tree safety or live execution prechecks, authorize
supervisor restarts, or claim kill/review accuracy. Services still require fresh
live restart eligibility, so replay does not waive their placement protection.
Derived provenance terms are replayed; raw collectors and provenance classifiers
are not rerun.

The CLI regressions in `cli_formats::replay_recording` cover the exact live
inventory, private permissions, existing-file/symlink preservation, offline
scoring, complete population accounting, current-policy reevaluation, JSONL,
and refusal of unsupported or incomplete inputs. Core regressions cover shared
scoring, signature and human-prior precedence, identity matching, and omitted
observations.

Redact and review recordings before sharing or committing them, then use the
manifest and redaction checks above. Raw collector capture/injection, redacted
decision equivalence, and full `agent plan` action parity remain acceptance
work for `bd-l3s5.1` and related replay beads.

## Reviewed captures and paired score evaluation

Create a private review template from a captured census:

```bash
pt-core replay label-template --snapshot /private/path/scan.json \
  --output /private/path/scan.labels.json --host-id dev-box --split holdout
```

The template retains every process identity and leaves every verdict unknown.
Review the capture independently and fill in explicit useful/abandoned judgments
with the required reviewer, timestamp, and rationale. An abandoned judgment here
labels the model's combined abandoned-or-zombie event; it does not authorize an
action. Keep unknown rows in the document. Neither regex matches, current model
recommendations, successful kills, nor disappearing PIDs supply labels.

The review document binds to the complete capture with a stable SHA-256 digest.
Evaluation rejects a different capture, changed identities, duplicate entries,
and missing census rows. Review files contain raw process details and use private,
non-overwriting creation just like captures.

Compare two configurations against the same observations and reviewed labels:

```bash
pt-core --config /private/candidate-config replay evaluate \
  --snapshot /private/path/scan.json --labels /private/path/scan.labels.json \
  --baseline-config /private/incumbent-config --format json
```

Both models use the production scorer in the same invocation. The report keeps
the complete population, label coverage, and both models' protection/unavailable
outcomes. Paired metrics use the same labeled processes scored by both models;
coverage losses remain visible when a changed policy excludes a difficult case.
Unreadable or invalid learned-verdict and user-signature inputs are rejected so
an incomplete model cannot silently replace either configuration.
The existing calibration sample-support requirements remain in force, and
insufficient support is reported without fabricated metrics. Lower Brier score
and log loss indicate better probability predictions on the evaluated labels.

The host identifier and training/holdout split are declarations supplied by the
reviewer. A single-capture comparison does not establish that a model's training
data excluded that host. Record the split honestly and retain the model and
capture fingerprints when comparing results across hosts. Both configurations
evaluate learned-prior decay at one shared timestamp. This command does not
reconstruct historical model state or write labels into the learned decision
store.

These are score-level comparisons. They do not measure final KILL/REVIEW
precision, zombie-routing quality, or a false-kill guarantee; those require the
full production decision replay and independent fleet corpus described above.

## Provenance Fixtures

Canonical provenance fixtures now live in the `pt-core` fixture domain:

- `test/fixtures/pt-core/provenance_privacy_snapshot.json`
- `test/fixtures/pt-core/logs/provenance_debug_trace.jsonl`

The shared Rust-side loader for these fixtures is documented in
`docs/PROVENANCE_TESTING_AND_LOGGING.md`.
