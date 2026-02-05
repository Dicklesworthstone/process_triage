//! No-mock output formatting tests using real fixtures.

use pt_core::output::{encode_toon_value, CompactConfig, FieldSelector, TokenEfficientOutput};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use toon_rust::try_decode;

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("test")
        .join("fixtures")
        .join("output")
}

fn load_json_fixture(name: &str) -> Value {
    let path = fixtures_dir().join(name);
    let contents = fs::read_to_string(&path).expect("read output fixture");
    serde_json::from_str(&contents).expect("parse output fixture")
}

#[test]
fn test_scan_minimal_field_selection() {
    let input = load_json_fixture("scan_input.json");
    let expected = load_json_fixture("scan_expected_minimal.json");

    let selector = FieldSelector::parse("processes,pid,classification,summary")
    .expect("parse selector");

    let filtered = selector.filter_value(input);
    assert_eq!(filtered, expected);
}

#[test]
fn test_scan_compact_output() {
    let input = load_json_fixture("scan_input.json");
    let expected = load_json_fixture("scan_expected_compact.json");

    let compacted = CompactConfig::all().compact_value(input);
    assert_eq!(compacted, expected);
}

#[test]
fn test_plan_minimal_field_selection() {
    let input = load_json_fixture("plan_input.json");
    let expected = load_json_fixture("plan_expected_minimal.json");

    let selector = FieldSelector::parse("candidates,pid,classification,summary")
    .expect("parse selector");

    let filtered = selector.filter_value(input);
    assert_eq!(filtered, expected);
}

#[test]
fn test_plan_compact_output() {
    let input = load_json_fixture("plan_input.json");
    let expected = load_json_fixture("plan_expected_compact.json");

    let compacted = CompactConfig::all().compact_value(input);
    assert_eq!(compacted, expected);
}

#[test]
fn test_explain_minimal_field_selection() {
    let input = load_json_fixture("explain_input.json");
    let expected = load_json_fixture("explain_expected_minimal.json");

    let selector = FieldSelector::parse("results,pid,classification,summary")
    .expect("parse selector");

    let filtered = selector.filter_value(input);
    assert_eq!(filtered, expected);
}

#[test]
fn test_plan_toon_roundtrip() {
    let input = load_json_fixture("plan_input.json");
    let encoded = encode_toon_value(&input);
    let decoded = try_decode(&encoded, None).expect("decode toon");

    assert_eq!(decoded, input.into());
}

#[test]
fn test_plan_truncation_output() {
    let input = load_json_fixture("plan_input.json");
    let expected = load_json_fixture("plan_expected_truncated.json");

    let processor = TokenEfficientOutput::new().with_max_tokens(120);
    let output = processor.process(input);

    assert!(output.truncated, "expected truncation to occur");
    assert_eq!(output.json, expected);
    assert_eq!(output.remaining_count, Some(2));
    assert!(output.continuation_token.is_some());
}
