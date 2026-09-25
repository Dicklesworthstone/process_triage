//! CLI E2E tests for config preset commands.
//!
//! Validates:
//! - `pt-core config list-presets` output schema
//! - `pt-core config show-preset <name>` for all valid presets
//! - `pt-core config diff-preset <name>` shows differences
//! - `pt-core config export-preset <name>` writes valid JSON file
//! - `pt-core config validate` with valid and invalid configs
//! - Exit codes for success and error paths
//! - Invalid preset name produces clear error
//!
//! See: bd-ns1s

use assert_cmd::cargo::cargo_bin_cmd;
use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use std::fs;
use std::io::Write;
use std::time::Duration;
use tempfile::tempdir;

// ============================================================================
// Helpers
// ============================================================================

/// Get a Command for pt-core binary.
fn pt_core() -> Command {
    let mut cmd = cargo_bin_cmd!("pt-core");
    cmd.timeout(Duration::from_secs(60));
    cmd
}

// ============================================================================
// List Presets
// ============================================================================

#[test]
fn test_config_list_presets_success() {
    pt_core()
        .args(["--format", "json", "config", "list-presets"])
        .assert()
        .success()
        .code(0);
}

#[test]
fn test_config_list_presets_json_schema() {
    let output = pt_core()
        .args(["--format", "json", "config", "list-presets"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).expect("parse JSON");

    // Should have session_id
    assert!(
        json.get("session_id").is_some(),
        "list-presets should have session_id"
    );

    // Should have presets array
    let presets = json["presets"]
        .as_array()
        .expect("presets should be an array");

    // Should have at least 4 presets (developer, server, ci, paranoid)
    assert!(
        presets.len() >= 4,
        "should have at least 4 presets (got {})",
        presets.len()
    );

    // Each preset should have name and description
    for (i, preset) in presets.iter().enumerate() {
        assert!(
            preset.get("name").is_some(),
            "preset[{}] should have 'name'",
            i
        );
        assert!(
            preset.get("description").is_some(),
            "preset[{}] should have 'description'",
            i
        );
        assert!(
            !preset["name"].as_str().unwrap_or("").is_empty(),
            "preset[{}] name should not be empty",
            i
        );
        assert!(
            !preset["description"].as_str().unwrap_or("").is_empty(),
            "preset[{}] description should not be empty",
            i
        );
    }

    // Verify known preset names are present
    let names: Vec<&str> = presets.iter().filter_map(|p| p["name"].as_str()).collect();

    for expected in &["developer", "server", "ci", "paranoid"] {
        assert!(
            names.contains(expected),
            "presets should include '{}' (found: {:?})",
            expected,
            names
        );
    }

    eprintln!(
        "[INFO] list-presets: {} presets ({:?})",
        presets.len(),
        names
    );
}

// ============================================================================
// Show Preset
// ============================================================================

#[test]
fn test_config_show_preset_all_valid_presets() {
    let valid_presets = ["developer", "server", "ci", "paranoid"];

    for preset in valid_presets {
        let output = pt_core()
            .args(["--format", "json", "config", "show-preset", preset])
            .assert()
            .success()
            .code(0)
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).expect("parse JSON");

        assert!(
            json.get("session_id").is_some(),
            "show-preset '{}' should have session_id",
            preset
        );
        assert!(
            json.get("preset").is_some(),
            "show-preset '{}' should have preset name",
            preset
        );
        assert!(
            json.get("policy").is_some(),
            "show-preset '{}' should have policy object",
            preset
        );

        // Policy should be an object with safety-relevant fields
        let policy = &json["policy"];
        assert!(
            policy.is_object(),
            "preset '{}' policy should be an object",
            preset
        );

        eprintln!(
            "[INFO] show-preset '{}': policy has {} top-level keys",
            preset,
            policy.as_object().map(|o| o.len()).unwrap_or(0)
        );
    }
}

#[test]
fn test_config_show_preset_alias_names() {
    // Aliases should work too
    let aliases = [
        ("dev", "developer"),
        ("srv", "server"),
        ("production", "server"),
        ("prod", "server"),
        ("safe", "paranoid"),
        ("cautious", "paranoid"),
        ("continuous-integration", "ci"),
    ];

    for (alias, canonical) in aliases {
        let output = pt_core()
            .args(["--format", "json", "config", "show-preset", alias])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).expect("parse JSON");
        let preset_name = json["preset"].as_str().unwrap_or("");

        // The returned preset name should be the canonical name
        assert_eq!(
            preset_name.to_lowercase(),
            canonical.to_lowercase(),
            "alias '{}' should resolve to preset '{}'",
            alias,
            canonical
        );
    }
}

#[test]
fn test_config_show_preset_invalid_name_fails() {
    pt_core()
        .args(["--format", "json", "config", "show-preset", "nonexistent"])
        .assert()
        .failure()
        .code(10); // ArgsError
}

#[test]
fn test_config_show_preset_invalid_name_error_message() {
    pt_core()
        .args([
            "--format",
            "json",
            "config",
            "show-preset",
            "invalid_preset",
        ])
        .assert()
        .failure()
        .stderr(predicates::str::contains("Unknown preset").or(
            predicates::str::contains("unknown preset").or(predicates::str::contains("Available")),
        ));
}

// ============================================================================
// Diff Preset
// ============================================================================

#[test]
fn test_config_diff_preset_success() {
    let output = pt_core()
        .args(["--format", "json", "config", "diff-preset", "developer"])
        .assert()
        .success()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).expect("parse JSON");

    assert!(
        json.get("session_id").is_some(),
        "diff-preset should have session_id"
    );
    assert!(
        json.get("preset").is_some(),
        "diff-preset should have preset name"
    );
    assert!(
        json.get("differences_count").is_some(),
        "diff-preset should have differences_count"
    );
    assert!(
        json.get("differences").is_some(),
        "diff-preset should have differences array"
    );

    let diff_count = json["differences_count"].as_u64().unwrap_or(0);
    let differences = json["differences"]
        .as_array()
        .expect("differences should be array");

    assert_eq!(
        diff_count,
        differences.len() as u64,
        "differences_count should match array length"
    );

    // Each difference should have path, current, preset
    for (i, diff) in differences.iter().enumerate() {
        assert!(
            diff.get("path").is_some(),
            "difference[{}] should have 'path'",
            i
        );
        assert!(
            diff.get("current").is_some(),
            "difference[{}] should have 'current'",
            i
        );
        assert!(
            diff.get("preset").is_some(),
            "difference[{}] should have 'preset'",
            i
        );
    }

    eprintln!("[INFO] diff-preset 'developer': {} differences", diff_count);
}

#[test]
fn test_config_diff_preset_all_presets() {
    for preset in &["developer", "server", "ci", "paranoid"] {
        pt_core()
            .args(["--format", "json", "config", "diff-preset", preset])
            .assert()
            .success()
            .code(0);
    }
}

#[test]
fn test_config_diff_preset_invalid_name_fails() {
    pt_core()
        .args(["--format", "json", "config", "diff-preset", "nonexistent"])
        .assert()
        .failure()
        .code(10);
}

// ============================================================================
// Export Preset
// ============================================================================

#[test]
fn test_config_export_preset_to_file() {
    let dir = tempdir().expect("tempdir");
    let output_path = dir.path().join("exported_policy.json");

    pt_core()
        .args([
            "--format",
            "json",
            "config",
            "export-preset",
            "developer",
            "--output",
            output_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .code(0);

    // File should exist and be valid JSON
    assert!(output_path.exists(), "exported file should exist");

    let content = fs::read_to_string(&output_path).expect("read exported file");
    let json: Value = serde_json::from_str(&content).expect("exported file should be valid JSON");
    assert!(json.is_object(), "exported policy should be a JSON object");

    eprintln!(
        "[INFO] export-preset: wrote {} bytes to {}",
        content.len(),
        output_path.display()
    );
}

#[test]
fn test_config_export_preset_all_presets() {
    let dir = tempdir().expect("tempdir");

    for preset in &["developer", "server", "ci", "paranoid"] {
        let path = dir.path().join(format!("{}.json", preset));

        pt_core()
            .args([
                "--format",
                "json",
                "config",
                "export-preset",
                preset,
                "--output",
                path.to_str().unwrap(),
            ])
            .assert()
            .success();

        assert!(path.exists(), "exported {} should exist", preset);
        let content = fs::read_to_string(&path).expect("read file");
        let _: Value = serde_json::from_str(&content)
            .unwrap_or_else(|e| panic!("exported '{}' should be valid JSON: {}", preset, e));
    }
}

#[test]
fn test_config_export_preset_invalid_name_fails() {
    let dir = tempdir().expect("tempdir");
    let path = dir.path().join("should_not_exist.json");

    pt_core()
        .args([
            "--format",
            "json",
            "config",
            "export-preset",
            "nonexistent",
            "--output",
            path.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .code(10);

    assert!(
        !path.exists(),
        "file should not be created for invalid preset"
    );
}

// ============================================================================
// Validate Config
// ============================================================================

#[test]
fn test_config_validate_defaults_success() {
    let output = pt_core()
        .args(["--format", "json", "config", "validate"])
        .assert()
        .success()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).expect("parse JSON");

    assert_eq!(
        json["status"], "valid",
        "default config should validate as 'valid'"
    );
    assert!(
        json.get("priors").is_some(),
        "validate output should have priors section"
    );
    assert!(
        json.get("policy").is_some(),
        "validate output should have policy section"
    );

    // Both should indicate using defaults
    assert!(
        json["priors"]["using_defaults"].as_bool().unwrap_or(false),
        "priors should be using defaults"
    );
    assert!(
        json["policy"]["using_defaults"].as_bool().unwrap_or(false),
        "policy should be using defaults"
    );
}

#[test]
fn test_config_validate_with_exported_preset() {
    let dir = tempdir().expect("tempdir");
    let policy_path = dir.path().join("policy.json");

    // Export a preset, then validate it
    pt_core()
        .args([
            "--format",
            "json",
            "config",
            "export-preset",
            "developer",
            "--output",
            policy_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Validate with the exported policy
    let output = pt_core()
        .args([
            "--format",
            "json",
            "config",
            "validate",
            policy_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).expect("parse JSON");
    assert_eq!(json["status"], "valid");
}

/// The file type comes from the content, not the name: a policy saved as
/// `priors.json` validates as a policy, and a JSON file that is neither is rejected
/// (it used to load defaults and report "valid").
#[test]
fn test_config_validate_detects_file_kind_by_content() {
    let dir = tempdir().expect("tempdir");
    let misnamed_policy = dir.path().join("priors.json");
    pt_core()
        .args([
            "--format",
            "json",
            "config",
            "export-preset",
            "developer",
            "--output",
            misnamed_policy.to_str().unwrap(),
        ])
        .assert()
        .success();
    let output = pt_core()
        .args([
            "--format",
            "json",
            "config",
            "validate",
            misnamed_policy.to_str().unwrap(),
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: Value = serde_json::from_slice(&output).expect("parse JSON");
    assert_eq!(json["status"], "valid");
    assert_eq!(json["policy"]["using_defaults"], false, "{json}");
    assert_eq!(json["priors"]["using_defaults"], true, "{json}");

    let junk = dir.path().join("policy_backup.json");
    fs::write(&junk, r#"{"hello": 1}"#).expect("write junk");
    let output = pt_core()
        .args([
            "--format",
            "json",
            "config",
            "validate",
            junk.to_str().unwrap(),
        ])
        .assert()
        .code(10)
        .get_output()
        .stdout
        .clone();
    let json: Value = serde_json::from_slice(&output).expect("parse JSON");
    assert_eq!(json["status"], "invalid");
}

#[test]
fn test_config_validate_invalid_json_fails() {
    let dir = tempdir().expect("tempdir");
    let bad_policy = dir.path().join("bad_policy.json");

    // Write invalid JSON
    let mut f = fs::File::create(&bad_policy).expect("create file");
    f.write_all(b"{ this is not valid json !!!").expect("write");

    pt_core()
        .args([
            "--format",
            "json",
            "config",
            "validate",
            bad_policy.to_str().unwrap(),
        ])
        .assert()
        .failure();
}

// ============================================================================
// Preset Consistency
// ============================================================================

#[test]
fn test_presets_are_deterministic() {
    // Same preset should produce identical policy JSON across invocations
    let output1 = pt_core()
        .args(["--format", "json", "config", "show-preset", "paranoid"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let output2 = pt_core()
        .args(["--format", "json", "config", "show-preset", "paranoid"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json1: Value = serde_json::from_slice(&output1).expect("parse JSON 1");
    let json2: Value = serde_json::from_slice(&output2).expect("parse JSON 2");

    // Policy should be identical
    assert_eq!(
        json1["policy"], json2["policy"],
        "preset policy should be deterministic"
    );
}

#[test]
fn test_presets_differ_from_each_other() {
    // Different presets should have different policies
    let dev_output = pt_core()
        .args(["--format", "json", "config", "show-preset", "developer"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let paranoid_output = pt_core()
        .args(["--format", "json", "config", "show-preset", "paranoid"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let dev: Value = serde_json::from_slice(&dev_output).expect("parse dev");
    let paranoid: Value = serde_json::from_slice(&paranoid_output).expect("parse paranoid");

    // Policies should differ
    assert_ne!(
        dev["policy"], paranoid["policy"],
        "developer and paranoid presets should have different policies"
    );
}

// ============================================================================
// Config Show
// ============================================================================

#[test]
fn test_config_show_default_success() {
    pt_core()
        .args(["--format", "json", "config", "show"])
        .assert()
        .success()
        .code(0);
}

// ============================================================================
// Output Format Compatibility
// ============================================================================

#[test]
fn test_config_commands_work_with_all_formats() {
    for format in &["json", "toon", "summary"] {
        pt_core()
            .args(["--format", format, "config", "list-presets"])
            .assert()
            .success();

        pt_core()
            .args(["--format", format, "config", "show-preset", "developer"])
            .assert()
            .success();

        eprintln!("[INFO] Config commands work with format '{}'", format);
    }
}
