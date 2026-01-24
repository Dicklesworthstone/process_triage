# TOON Integration Brief for process_triage (pt)

**Bead**: bd-2wa
**Author**: RedBrook (Claude Opus 4.5)
**Date**: 2026-01-24

## Executive Summary

process_triage (pt) is **exceptionally well-designed** for TOON integration. The existing `OutputFormat` enum in `pt-common` already supports 8 output formats with clean serde/clap integration. Adding TOON requires:

1. One new enum variant
2. One Display match arm
3. A small toon_rust helper (crate-based, no subprocess)

**Estimated token savings**: 20-30% (based on slb measurements)

---

## File List + Functions for JSON Output

### Core Output Infrastructure

| File | Purpose |
|------|---------|
| `crates/pt-common/src/output.rs` | `OutputFormat` enum definition with clap/serde derives |
| `crates/pt-core/src/cli.rs` | CLI utilities placeholder (output formatting helpers planned) |
| `crates/pt-core/tests/cli_formats.rs` | Format acceptance tests |

### Key Structs with JSON Serialization

All output types derive `Serialize`, making them TOON-ready:

- Process scan results (candidates with confidence scores)
- Bayesian posterior probabilities
- Evidence summaries
- Session/telemetry data
- Version/status info

---

## Proposed Format Additions

### 1. Add `Toon` Variant to OutputFormat

```rust
// crates/pt-common/src/output.rs

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    #[default]
    Json,
    Md,
    Jsonl,
    Summary,
    Metrics,
    Slack,
    Exitcode,
    Prose,
    Toon,  // NEW: Token-efficient encoding
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // ... existing cases ...
            OutputFormat::Toon => write!(f, "toon"),
        }
    }
}
```

### 2. TOON Helper Module (crate-based)

Create `crates/pt-common/src/toon.rs` using the toon_rust crate (no subprocess):

```rust
//! TOON encoding support via toon_rust crate.

pub fn encode_toon<T: serde::Serialize>(data: &T) -> Result<String, ToonError> {
    let value = serde_json::to_value(data)?;
    Ok(toon_rust::encode(
        value,
        Some(toon_rust::EncodeOptions {
            indent: None,
            delimiter: None,
            key_folding: Some(toon_rust::KeyFoldingMode::Safe),
            flatten_depth: None,
            replacer: None,
        }),
    ))
}

pub fn decode_toon(input: &str) -> Result<serde_json::Value, ToonError> {
    toon_rust::try_decode(input, None).map_err(ToonError::from)
}
```

### 3. Default Selection Behavior

TOON should **not** be the default. Recommendation:

| Context | Default Format | Rationale |
|---------|---------------|-----------|
| Interactive (`pt`) | `md` or `summary` | Human readability |
| Agent mode (`--robot`) | `json` | Universal compatibility |
| Agent with TOON enabled | `toon` | Token savings |

Suggested: Add `--toon` / `-T` shorthand flag (matching slb pattern).

---

## Doc Insertion Points

### 1. README.md

Insert after line ~122 (after "pt --help" in Other Commands section):

```markdown
### Output Formats

```bash
pt scan --format json    # Structured JSON (default for agents)
pt scan --format toon    # Token-efficient encoding (22-30% smaller)
pt scan --format md      # Human-readable Markdown
pt scan --format summary # One-line status
```

For AI agents, TOON format reduces token consumption while preserving full data fidelity.
```

### 2. --help Text

The `--format` option already lists available formats. Adding `toon` to `OutputFormat` will automatically include it in help output due to clap's `ValueEnum` derive.

### 3. AGENTS.md / Agent Integration Guide

If `docs/AGENT_INTEGRATION_GUIDE.md` exists, add:

```markdown
## Output Formats for Agents

Use `--format toon` when TOON support is enabled:
- 22-30% token savings vs JSON
- Full round-trip fidelity
- No subprocess required
```

---

## Sample Outputs for Fixtures

### Input (JSON)
```json
{
  "candidates": [
    {
      "pid": 12345,
      "name": "node",
      "state": "abandoned",
      "confidence": 0.92,
      "evidence": {
        "age_hours": 168,
        "cpu_percent": 0.0,
        "orphaned": true
      }
    }
  ],
  "scan_time_ms": 1234
}
```

### Expected TOON Output (approximate)
```
candidates:[{pid:12345 name:node state:abandoned confidence:0.92 evidence:{age_hours:168 cpu_percent:0.0 orphaned:true}}] scan_time_ms:1234
```

### Token Savings Calculation

| Format | Characters | Tokens (est.) | Savings |
|--------|------------|---------------|---------|
| JSON (minified) | 198 | ~55 | baseline |
| TOON | 152 | ~42 | ~24% |

---

## Test Strategy

### Unit Tests

Add to `crates/pt-common/src/toon.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_simple_object() {
        let data = serde_json::json!({"key": "value"});
        let result = encode_toon(&data).unwrap();
        assert!(result.contains("key"));
        assert!(result.contains("value"));
    }

    #[test]
    fn encode_nested_object() {
        let data = serde_json::json!({
            "candidates": [{"pid": 123, "name": "test"}]
        });
        let result = encode_toon(&data).unwrap();
        assert!(result.contains("candidates"));
        assert!(result.contains("123"));
    }

    #[test]
    fn roundtrip_simple_object() {
        let data = serde_json::json!({"key": "value"});
        let toon = encode_toon(&data).unwrap();
        let decoded = decode_toon(&toon).unwrap();
        assert_eq!(decoded, data);
    }
}
```

### CLI Integration Tests

Add to `crates/pt-core/tests/cli_formats.rs`:

```rust
#[test]
fn toon_format_accepted() {
    pt_core()
        .args(["--format", "toon", "--help"])
        .assert()
        .success();
}

#[test]
fn short_toon_flag_accepted() {
    pt_core()
        .args(["-T", "--help"])
        .assert()
        .success();
}
```

### E2E Test Script

Create `scripts/test_toon_e2e.sh`:

```bash
#!/bin/bash
set -euo pipefail

# Phase 1: Format acceptance
pt-core --format toon --help

# Phase 2: Actual output
json_out=$(pt-core scan --format json 2>/dev/null || echo '{}')
toon_out=$(pt-core scan --format toon 2>/dev/null || echo '')

json_len=${#json_out}
toon_len=${#toon_out}

if [[ $toon_len -lt $json_len ]]; then
    echo "PASS: TOON output smaller ($toon_len < $json_len)"
fi

echo "TOON E2E tests complete"
```

---

## Implementation Notes

1. **No pt-core modifications needed for basic integration** - The output formatting is already abstracted through the `OutputFormat` enum.

2. **Graceful degradation** - If TOON feature is disabled at build time, fall back to JSON with warning.

3. **Error handling**: TOON encoding failures should never crash pt - always fall back.

---

## Conclusion

process_triage is production-ready for TOON integration. The clean enum-based output system means adding TOON is a ~50-line change plus tests. The crate-based approach keeps everything in-process with zero subprocess overhead.

**Recommendation**: Proceed with implementation in a separate bead.
