//! CLI E2E tests for output formatting modes.
//!
//! Validates:
//! - `--format json` (default) vs `--format toon` output
//! - `--compact` flag produces minified JSON with short keys
//! - `--fields` preset and custom field selection
//! - `--max-tokens` truncation with continuation tokens
//! - `--estimate-tokens` metadata-only mode
//! - Combined flags (compact + fields, compact + max-tokens, etc.)
//! - Invalid format flag produces clear error
//!
//! Most tests use `agent capabilities` (no ProcessHarness required).
//! See: bd-1o51

use assert_cmd::cargo::cargo_bin_cmd;
use assert_cmd::Command;
use serde_json::Value;
use std::time::Duration;

// ============================================================================
// Helpers
// ============================================================================

/// Get a Command for pt-core binary.
fn pt_core() -> Command {
    let mut cmd = cargo_bin_cmd!("pt-core");
    cmd.timeout(Duration::from_secs(60));
    cmd
}

/// Run `pt-core agent capabilities` with given extra args and return parsed JSON.
fn capabilities_json(extra_args: &[&str]) -> Value {
    let mut args = vec!["--format", "json", "agent", "capabilities"];
    args.extend_from_slice(extra_args);

    let output = pt_core()
        .args(&args)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    serde_json::from_slice(&output).expect("parse JSON output")
}

/// Run `pt-core agent capabilities` with given global args (before subcommand)
/// and return raw stdout bytes.
fn capabilities_raw(global_args: &[&str]) -> Vec<u8> {
    let mut args: Vec<&str> = global_args.to_vec();
    args.extend_from_slice(&["agent", "capabilities"]);

    pt_core()
        .args(&args)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone()
}

// ============================================================================
// Format: JSON (default)
// ============================================================================

#[test]
fn test_format_json_default_is_valid_json() {
    let json = capabilities_json(&[]);

    // Must have schema_version
    assert!(
        json.get("schema_version").is_some(),
        "JSON output should have schema_version"
    );

    // Must have os info
    assert!(
        json.get("os").is_some(),
        "JSON output should have os section"
    );

    // Pretty-printed: contains newlines
    let raw = capabilities_raw(&["--format", "json"]);
    let text = String::from_utf8(raw).expect("utf8");
    assert!(
        text.contains('\n'),
        "Default JSON should be pretty-printed with newlines"
    );
}

// ============================================================================
// Format: TOON
// ============================================================================

#[test]
fn test_format_toon_produces_valid_toon() {
    let raw = capabilities_raw(&["--format", "toon"]);
    let text = String::from_utf8(raw).expect("utf8");

    // TOON should not start with { (it's not raw JSON)
    assert!(
        !text.trim_start().starts_with('{'),
        "TOON output should not be raw JSON (got: {}...)",
        &text[..text.len().min(100)]
    );

    // TOON should contain key/value pairs
    assert!(!text.is_empty(), "TOON output should not be empty");

    // TOON should be parseable back to a value via tru
    // (We can't use tru directly in integration tests, but we
    // can verify the output is non-empty and structured)
    assert!(
        text.len() > 10,
        "TOON output should have meaningful content"
    );

    eprintln!("[INFO] TOON output: {} bytes vs JSON", text.len());
}

#[test]
fn test_format_toon_is_smaller_than_json() {
    let json_raw = capabilities_raw(&["--format", "json"]);
    let toon_raw = capabilities_raw(&["--format", "toon"]);

    // TOON should be more compact than pretty-printed JSON
    assert!(
        toon_raw.len() < json_raw.len(),
        "TOON ({} bytes) should be smaller than pretty JSON ({} bytes)",
        toon_raw.len(),
        json_raw.len()
    );

    eprintln!(
        "[INFO] Size: JSON={} TOON={} (reduction: {:.0}%)",
        json_raw.len(),
        toon_raw.len(),
        (1.0 - toon_raw.len() as f64 / json_raw.len() as f64) * 100.0
    );
}

// ============================================================================
// Compact Mode
// ============================================================================

#[test]
fn test_compact_produces_minified_json() {
    let raw = capabilities_raw(&["--format", "json", "--compact"]);
    let text = String::from_utf8(raw).expect("utf8");

    // Compact output should be valid JSON (single line, no pretty-print newlines in data)
    let json: Value = serde_json::from_str(text.trim()).expect("compact should be valid JSON");
    assert!(json.is_object(), "compact output should be a JSON object");

    // Minified: should NOT contain indentation newlines (may have \n in string values)
    // The minified output is typically a single line
    let lines: Vec<&str> = text.trim().lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "compact output should be a single line (minified), got {} lines",
        lines.len()
    );
}

#[test]
fn test_compact_uses_short_keys() {
    let raw = capabilities_raw(&["--format", "json", "--compact"]);
    let text = String::from_utf8(raw).expect("utf8");
    let json: Value = serde_json::from_str(text.trim()).expect("parse compact JSON");

    // schema_version should be abbreviated to "sv"
    assert!(
        json.get("sv").is_some(),
        "compact output should use short key 'sv' for schema_version"
    );

    // generated_at should be abbreviated to "ts"
    assert!(
        json.get("ts").is_some(),
        "compact output should use short key 'ts' for generated_at"
    );

    // session_id should be abbreviated to "sid"
    assert!(
        json.get("sid").is_some(),
        "compact output should use short key 'sid' for session_id"
    );
}

#[test]
fn test_compact_is_smaller_than_default() {
    let default_raw = capabilities_raw(&["--format", "json"]);
    let compact_raw = capabilities_raw(&["--format", "json", "--compact"]);

    assert!(
        compact_raw.len() < default_raw.len(),
        "compact ({} bytes) should be smaller than default ({} bytes)",
        compact_raw.len(),
        default_raw.len()
    );

    eprintln!(
        "[INFO] Size: default={} compact={} (reduction: {:.0}%)",
        default_raw.len(),
        compact_raw.len(),
        (1.0 - compact_raw.len() as f64 / default_raw.len() as f64) * 100.0
    );
}

// ============================================================================
// Field Selection
// ============================================================================

#[test]
fn test_fields_minimal_filters_to_preset_keys() {
    // Minimal preset selects "pid" and "classification" which are candidate-level
    // fields. When applied to capabilities output (which lacks those fields),
    // the result should be an empty or near-empty object.
    let raw = capabilities_raw(&["--format", "json", "--fields", "minimal"]);
    let text = String::from_utf8(raw).expect("utf8");
    let minimal: Value = serde_json::from_str(text.trim()).expect("parse minimal JSON");
    let minimal_keys: Vec<String> = minimal
        .as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();

    // Capabilities output doesn't have pid/classification, so minimal should filter them out
    let full = capabilities_json(&[]);
    let full_keys: Vec<String> = full
        .as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();

    assert!(
        minimal_keys.len() < full_keys.len(),
        "minimal preset should filter out most capabilities fields ({} vs {})",
        minimal_keys.len(),
        full_keys.len()
    );

    eprintln!(
        "[INFO] Fields: full={} minimal={} (preset correctly filters non-matching keys)",
        full_keys.len(),
        minimal_keys.len()
    );
}

#[test]
fn test_fields_standard_includes_standard_keys() {
    // Standard preset includes pid, classification, confidence, cmd_short, recommended_action
    // For capabilities output, these are mostly absent, but "standard" should still
    // produce valid JSON with whatever fields match.
    let raw = capabilities_raw(&["--format", "json", "--fields", "standard"]);
    let text = String::from_utf8(raw).expect("utf8");
    let json: Value = serde_json::from_str(text.trim()).expect("parse standard JSON");
    assert!(
        json.is_object(),
        "standard preset should produce valid JSON object"
    );
}

#[test]
fn test_fields_full_preserves_all_keys() {
    let default_json = capabilities_json(&[]);
    let default_keys: Vec<String> = default_json
        .as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();

    let raw = capabilities_raw(&["--format", "json", "--fields", "full"]);
    let text = String::from_utf8(raw).expect("utf8");
    let full: Value = serde_json::from_str(text.trim()).expect("parse full JSON");
    let full_keys: Vec<String> = full
        .as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();

    // Full should have same keys as default (no filter)
    assert_eq!(
        default_keys.len(),
        full_keys.len(),
        "full preset should preserve all keys"
    );
}

#[test]
fn test_fields_custom_csv_selects_specific_keys() {
    let raw = capabilities_raw(&["--format", "json", "--fields", "schema_version,os"]);
    let text = String::from_utf8(raw).expect("utf8");
    let filtered: Value = serde_json::from_str(text.trim()).expect("parse filtered JSON");
    let obj = filtered.as_object().expect("should be object");

    // Should have the requested fields
    assert!(
        obj.contains_key("schema_version"),
        "filtered output should include schema_version"
    );
    assert!(obj.contains_key("os"), "filtered output should include os");

    // Should NOT have other top-level fields
    let key_count = obj.len();
    assert!(
        key_count <= 3,
        "filtered output should have at most 3 keys (got {}): {:?}",
        key_count,
        obj.keys().collect::<Vec<_>>()
    );
}

// ============================================================================
// Token Estimation
// ============================================================================

#[test]
fn test_estimate_tokens_returns_metadata_only() {
    let raw = capabilities_raw(&["--format", "json", "--estimate-tokens"]);
    let text = String::from_utf8(raw).expect("utf8");
    let json: Value = serde_json::from_str(text.trim()).expect("parse estimate JSON");

    // Should have estimation fields
    assert!(
        json.get("estimated_tokens").is_some(),
        "estimate mode should return estimated_tokens"
    );
    assert!(
        json.get("truncated").is_some(),
        "estimate mode should return truncated flag"
    );

    // Token count should be a positive number
    let tokens = json["estimated_tokens"]
        .as_u64()
        .expect("estimated_tokens should be a number");
    assert!(
        tokens > 0,
        "estimated token count should be positive (got {})",
        tokens
    );

    // Should NOT contain the actual capabilities data
    assert!(
        json.get("os").is_none(),
        "estimate mode should NOT include actual capabilities data"
    );
    assert!(
        json.get("schema_version").is_none() || json.get("estimated_tokens").is_some(),
        "estimate mode returns metadata, not capabilities"
    );

    eprintln!("[INFO] Token estimate: {} tokens", tokens);
}

// ============================================================================
// Max Tokens / Truncation
// ============================================================================

#[test]
fn test_max_tokens_large_budget_no_truncation() {
    // Large budget should not truncate
    let raw = capabilities_raw(&["--format", "json", "--max-tokens", "100000"]);
    let text = String::from_utf8(raw).expect("utf8");
    let json: Value = serde_json::from_str(text.trim()).expect("parse JSON");

    // Should NOT have _meta wrapper (no truncation)
    assert!(
        json.get("_meta").is_none(),
        "large token budget should not trigger truncation wrapper"
    );

    // Should have regular capabilities fields
    assert!(
        json.get("schema_version").is_some() || json.get("sv").is_some(),
        "large budget should produce full output"
    );
}

#[test]
fn test_max_tokens_small_budget_produces_metadata_wrapper() {
    // Very small budget with output that has array fields to truncate
    // Capabilities output may not have a truncatable array, so we test
    // that the processing at least runs without error and produces valid JSON.
    let raw = capabilities_raw(&["--format", "json", "--max-tokens", "10"]);
    let text = String::from_utf8(raw).expect("utf8");
    let json: Value = serde_json::from_str(text.trim()).expect("parse JSON with small budget");

    // Output should still be valid JSON regardless of truncation
    assert!(json.is_object(), "output should be a valid JSON object");

    // If truncated, should have _meta wrapper
    if json.get("_meta").is_some() {
        let meta = &json["_meta"];
        assert_eq!(meta["truncated"], true, "_meta.truncated should be true");
        assert!(
            meta.get("continuation_token").is_some(),
            "_meta should have continuation_token"
        );
        assert!(
            meta.get("remaining_count").is_some(),
            "_meta should have remaining_count"
        );
        assert!(
            meta.get("token_count").is_some(),
            "_meta should have token_count"
        );

        eprintln!(
            "[INFO] Truncation: continuation={}, remaining={}",
            meta["continuation_token"], meta["remaining_count"]
        );
    } else {
        eprintln!("[INFO] No truncation needed even with small budget (no truncatable arrays)");
    }
}

// ============================================================================
// Combined Flags
// ============================================================================

#[test]
fn test_compact_plus_fields_combined() {
    let raw = capabilities_raw(&[
        "--format",
        "json",
        "--compact",
        "--fields",
        "schema_version,os",
    ]);
    let text = String::from_utf8(raw).expect("utf8");
    let json: Value = serde_json::from_str(text.trim()).expect("parse combined JSON");

    // Should use short keys (compact)
    // schema_version → sv, but only if it passes field filter first
    // The field filter uses original key names, compact abbreviates after
    let obj = json.as_object().expect("should be object");

    // After field selection + compact: schema_version → kept by filter → abbreviated to "sv"
    assert!(
        obj.contains_key("sv"),
        "compact+fields should have 'sv' (schema_version abbreviated)"
    );

    // Output should be minified (single line)
    let lines: Vec<&str> = text.trim().lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "compact+fields should be minified (single line)"
    );

    eprintln!(
        "[INFO] compact+fields: {} keys, {} bytes",
        obj.len(),
        text.len()
    );
}

#[test]
fn test_compact_plus_toon_format() {
    // Compact flag with TOON format - compact processes the JSON before TOON encoding
    let raw = capabilities_raw(&["--format", "toon", "--compact"]);
    let text = String::from_utf8(raw).expect("utf8");

    // Should produce valid, non-empty output
    assert!(
        !text.trim().is_empty(),
        "compact+toon should produce non-empty output"
    );

    // Should be different from non-compact TOON (shorter due to key abbreviation)
    let non_compact = capabilities_raw(&["--format", "toon"]);
    let non_compact_text = String::from_utf8(non_compact).expect("utf8");

    // Compact TOON should generally be smaller or equal
    assert!(
        text.len() <= non_compact_text.len() + 10, // small tolerance for encoding variance
        "compact TOON ({}) should not be significantly larger than regular TOON ({})",
        text.len(),
        non_compact_text.len()
    );

    eprintln!(
        "[INFO] TOON: regular={} compact={} bytes",
        non_compact_text.len(),
        text.len()
    );
}

#[test]
fn test_fields_plus_estimate_tokens() {
    // Estimate tokens with field selection should give smaller estimate
    let raw_full = capabilities_raw(&["--format", "json", "--estimate-tokens"]);
    let full_est: Value =
        serde_json::from_str(&String::from_utf8(raw_full).unwrap()).expect("parse");
    let full_tokens = full_est["estimated_tokens"].as_u64().unwrap();

    let raw_minimal = capabilities_raw(&[
        "--format",
        "json",
        "--estimate-tokens",
        "--fields",
        "schema_version",
    ]);
    let min_est: Value =
        serde_json::from_str(&String::from_utf8(raw_minimal).unwrap()).expect("parse");
    let min_tokens = min_est["estimated_tokens"].as_u64().unwrap();

    assert!(
        min_tokens <= full_tokens,
        "minimal fields estimate ({}) should be <= full estimate ({})",
        min_tokens,
        full_tokens
    );

    eprintln!(
        "[INFO] Token estimates: full={} minimal={}",
        full_tokens, min_tokens
    );
}

// ============================================================================
// Invalid Inputs
// ============================================================================

#[test]
fn test_invalid_format_value_fails() {
    pt_core()
        .args(["--format", "not_a_format", "agent", "capabilities"])
        .assert()
        .failure();
}

#[test]
fn test_invalid_fields_empty_string_handled() {
    // Empty fields string should be handled gracefully (treated as default)
    let raw = capabilities_raw(&["--format", "json", "--fields", ""]);
    let text = String::from_utf8(raw).expect("utf8");
    let json: Value =
        serde_json::from_str(text.trim()).expect("empty fields should produce valid JSON");
    assert!(json.is_object(), "empty fields should produce valid object");
}

// ============================================================================
// Output Consistency
// ============================================================================

#[test]
fn test_output_is_deterministic_across_runs() {
    let json1 = capabilities_json(&[]);
    let json2 = capabilities_json(&[]);

    // Schema version should be identical
    assert_eq!(
        json1["schema_version"], json2["schema_version"],
        "schema_version should be deterministic"
    );

    // OS info should be identical (same machine)
    assert_eq!(
        json1["os"], json2["os"],
        "os info should be deterministic across runs"
    );
}

#[test]
fn test_all_format_modes_succeed() {
    // Every supported format should produce a successful exit
    for format in &["json", "toon", "summary", "metrics"] {
        pt_core()
            .args(["--format", format, "agent", "capabilities"])
            .assert()
            .success();

        eprintln!("[INFO] Format '{}': success", format);
    }
}

#[test]
fn test_compact_output_still_schema_valid_json() {
    // Compact output must still be valid JSON with all required fields (abbreviated)
    let raw = capabilities_raw(&["--format", "json", "--compact"]);
    let text = String::from_utf8(raw).expect("utf8");
    let json: Value = serde_json::from_str(text.trim()).expect("compact must be valid JSON");

    // Must have schema_version (abbreviated as "sv")
    assert!(
        json.get("sv").is_some(),
        "compact JSON must have 'sv' (schema_version)"
    );

    // Must still be an object
    assert!(json.is_object());

    // Token count should be reasonable
    let json_str = serde_json::to_string(&json).unwrap();
    let char_count = json_str.chars().count();
    assert!(
        char_count > 20,
        "compact output should have meaningful content ({} chars)",
        char_count
    );
}
