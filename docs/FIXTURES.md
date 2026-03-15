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

## Provenance Fixtures

Canonical provenance fixtures now live in the `pt-core` fixture domain:

- `test/fixtures/pt-core/provenance_privacy_snapshot.json`
- `test/fixtures/pt-core/logs/provenance_debug_trace.jsonl`

The shared Rust-side loader for these fixtures is documented in
`docs/PROVENANCE_TESTING_AND_LOGGING.md`.
