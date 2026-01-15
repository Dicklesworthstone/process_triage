# Bundle and Report Specification

**Version**: 1.0.0
**Status**: Draft
**Bead**: process_triage-2ws

---

## 1. Overview

Process Triage exports shareable artifacts via two related mechanisms:

1. **`.ptb` bundle**: A portable archive containing a session snapshot, manifest, and optional report.
2. **HTML report**: A single-file, premium report designed to render locally via `file://`.

Bundles enable collaboration, support requests, and reproducible investigations without sharing raw sensitive data. Reports make the same information human-friendly with drill-down explanations and “galaxy-brain” math transparency.

---

## 2. `.ptb` Bundle Format

### 2.1 Container

- **Default container**: ZIP (cross-platform, easy to inspect, browser-friendly).
- **Optional container**: `tar.zst` for power users (smaller, faster).
- Container selection must be explicit in CLI flags to avoid ambiguity.

### 2.2 Directory Layout

```
<bundle>.ptb
├── manifest.json           # Bundle manifest + checksums (required)
├── plan.json               # Action plan (if generated)
├── summary.json            # Topline summary for quick preview
├── report.html             # Single-file report (optional)
├── telemetry/              # Parquet partitions (optional)
│   └── ...
├── raw/                    # Raw tool outputs (optional, profile-dependent)
│   └── ...
└── policies/
    ├── priors.json          # Priors snapshot used for inference
    ├── policy.json          # Policy snapshot used for decisions
    └── redaction.json       # Redaction policy snapshot
```

**Required**: `manifest.json`.

**Profile-dependent**:
- `plan.json` and `summary.json` are required for `safe` and `forensic` profiles.
- `telemetry/` is optional in `safe`, required in `forensic`.
- `raw/` is only allowed in `forensic` and must pass redaction gates.

### 2.3 Manifest Schema

Manifest file path: `specs/schemas/bundle-manifest.schema.json`

Key fields:

| Field | Type | Required | Description |
|------|------|----------|-------------|
| `schema_version` | string | yes | Schema version (`1.0.0`) |
| `bundle_id` | string | yes | Stable bundle identifier |
| `created_at` | string (date-time) | yes | Creation timestamp (UTC) |
| `session_id` | string | yes | Source session ID |
| `export_profile` | string | yes | `minimal` / `safe` / `forensic` / `custom` |
| `container` | object | yes | Container format + compression details |
| `policy_snapshot` | object | yes | Hashes of priors/policy/redaction |
| `contents` | array | yes | File inventory with checksums |
| `redaction_applied` | boolean | yes | Whether redaction/hashing ran |
| `encryption` | object | no | Encryption settings if enabled |

### 2.4 Checksums and Integrity

All files in the bundle **must** be listed in `manifest.json.contents` with:

- `path` (relative)
- `sha256` (lowercase hex)
- `size_bytes`
- `content_type` (best-effort MIME)
- `redaction_level` (`none`/`normalized`/`hashed`/`redacted`)

The manifest itself is included in `contents` with a checksum computed over its bytes **excluding** its own checksum entry (two-pass write).

### 2.5 Export Profiles

| Profile | Intended Use | Telemetry | Raw Tool Output | Redaction |
|---------|--------------|-----------|------------------|-----------|
| `minimal` | Quick share | none | none | high (strict) |
| `safe` | Collaboration | summaries + features | none | strict |
| `forensic` | Deep debug | full telemetry | optional | strict + additional consent |
| `custom` | User policy | configurable | configurable | per policy |

### 2.6 Encryption

Encryption is optional and policy-gated.

- Supported algorithms: `age`, `gpg`, `zip-aes-256`.
- If encryption is enabled, `manifest.json` must still be readable (metadata-only), while all other files are encrypted as a payload.
- Manifest must include `encryption` metadata: algorithm, key_id, and whether payload is encrypted.

### 2.7 Redaction Policy Integration

Bundles must record:
- `redaction_policy_id`
- `redaction_policy_hash`
- `redaction_applied` boolean

Export must refuse to include disallowed raw fields per the redaction policy.

---

## 3. HTML Report Specification

### 3.1 Requirements

- **Single file** (no external assets except CDN links).
- **Works via `file://`** (no server required).
- **Loads under 2 seconds** with typical bundles.
- **Mobile responsive** (read-only view is sufficient).

### 3.2 Sections

1. **Overview**: session summary, counts, top risks
2. **Candidates**: sortable table with filtering
3. **Evidence**: per-candidate evidence ledger
4. **Actions**: planned vs executed actions
5. **Telemetry**: timeline charts
6. **Galaxy-brain**: math derivation cards (log-odds, Bayes factors)

### 3.3 CDN Library Stack (Pinned + SRI)

Recommended:
- Tailwind CSS (layout)
- Tabulator (tables)
- ECharts (plots)
- Mermaid (graphs)
- KaTeX (math rendering)
- JSZip (optional bundle import)

Each CDN link must include **SRI hashes** and a version pin. The report must still render with a “limited mode” if CDN fails (fallback styles + basic tables).

### 3.4 Offline Embed Mode

`--embed-assets` will inline CSS/JS (base64 or raw) to allow fully offline reports.

- Embed size limit must be enforced (policy controlled)
- Embedded asset versions must be recorded in report metadata

### 3.5 Security

- All injected data must be HTML-escaped.
- Avoid `innerHTML` for untrusted fields.
- No remote execution; only local rendering.

---

## 4. CLI Surface (Summary)

- `pt-core bundle create --session <id> --out <path> [--profile safe|forensic] [--encrypt]`
- `pt-core report --session <id> --out report.html [--embed-assets]`
- `pt bundle` and `pt report` are thin wrappers.

---

## 5. Test Plan

- Validate `manifest.json` against schema.
- Verify bundle structure for each export profile.
- Verify `report.html` renders with CDN blocked (limited mode).
- Verify checksums validate and detect tampering.

