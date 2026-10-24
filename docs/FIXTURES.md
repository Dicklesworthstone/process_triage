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

## Private live replay recordings

`pt-core scan --record-replay PATH` connects the quick scan to the existing
`pt_core::replay::ReplaySnapshot` recorder. For example:

```bash
nice -n 19 pt-core scan --format json --record-replay /private/path/scan.json
```

The snapshot contains the exact inventory from that one scan, including raw
command lines and identities. It is a **private recording, not a redacted
fixture**. The destination must be new: an existing file or symlink is refused.
On Unix it is created with at most owner read/write permissions. If writing
fails, the command fails and retains any partial file for inspection. No process
action is executed. Deep scans cannot use this option.

The native `load_snapshot` and `ReplaySnapshot::to_scan_result` consumers read
this format; no second replay format is introduced. The integration regressions
in `cli_formats::replay_recording` compare the recorded and restored inventory
with the same live command's JSON, and check existing-file/symlink preservation
and unsupported deep-scan refusal.

Redact and review recordings before sharing or committing them, then use the
manifest and redaction checks above. This seam does not capture raw `/proc`
collector inputs, inject collectors, prove redacted decision equivalence, or
establish `agent plan` replay parity. Those remain acceptance work for
`bd-l3s5.1`; a snapshot-loader test alone does not complete that Bead.

## Provenance Fixtures

Canonical provenance fixtures now live in the `pt-core` fixture domain:

- `test/fixtures/pt-core/provenance_privacy_snapshot.json`
- `test/fixtures/pt-core/logs/provenance_debug_trace.jsonl`

The shared Rust-side loader for these fixtures is documented in
`docs/PROVENANCE_TESTING_AND_LOGGING.md`.
