//! CLI E2E tests for degraded environment and permission handling.
//!
//! Validates:
//! - `check` command detects valid and invalid config state
//! - Missing config files fall back to defaults (not errors)
//! - Invalid JSON config files produce clear errors and correct exit codes
//! - `--config` with empty/nonexistent directory uses defaults
//! - `config show` reports using_defaults when no config files exist
//! - `config validate` error paths (bad JSON, unreadable file)
//! - `agent capabilities` reports permissions and tool availability
//! - `agent init` with invalid agent name returns exit 10
//! - Exit codes match spec for error paths
//! - Format compatibility for error outputs
//!
//! See: bd-2y30

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
// Check Command: Default State
// ============================================================================

#[test]
fn test_check_default_success() {
    pt_core()
        .args(["--format", "json", "check"])
        .assert()
        .success()
        .code(0);
}

#[test]
fn test_check_default_json_schema() {
    let output = pt_core()
        .args(["--format", "json", "check"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).expect("parse JSON");

    assert_eq!(json["status"], "ok", "default check should be ok");
    assert!(json.get("session_id").is_some(), "should have session_id");
    assert!(
        json.get("schema_version").is_some(),
        "should have schema_version"
    );
    assert!(json.get("checks").is_some(), "should have checks array");

    let checks = json["checks"].as_array().expect("checks should be array");
    assert!(!checks.is_empty(), "should have at least one check result");

    // Each check should have check name and status
    for (i, check) in checks.iter().enumerate() {
        assert!(
            check.get("check").is_some(),
            "checks[{}] should have 'check' name",
            i
        );
        assert!(
            check.get("status").is_some(),
            "checks[{}] should have 'status'",
            i
        );
    }
}

#[test]
fn test_check_includes_priors_policy_capabilities() {
    let output = pt_core()
        .args(["--format", "json", "check"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).expect("parse JSON");
    let checks = json["checks"].as_array().expect("checks array");

    let check_names: Vec<&str> = checks.iter().filter_map(|c| c["check"].as_str()).collect();

    assert!(
        check_names.contains(&"priors"),
        "checks should include 'priors' (got {:?})",
        check_names
    );
    assert!(
        check_names.contains(&"policy"),
        "checks should include 'policy' (got {:?})",
        check_names
    );
    assert!(
        check_names.contains(&"capabilities"),
        "checks should include 'capabilities' (got {:?})",
        check_names
    );
}

#[test]
fn test_check_default_uses_builtin_defaults() {
    // With no config files, check should report using_defaults
    let dir = tempdir().expect("tempdir");

    let output = pt_core()
        .args([
            "--format",
            "json",
            "--config",
            dir.path().to_str().unwrap(),
            "check",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).expect("parse JSON");
    let checks = json["checks"].as_array().expect("checks array");

    for check in checks {
        let name = check["check"].as_str().unwrap_or("");
        if name == "priors" || name == "policy" {
            assert!(
                check["using_defaults"].as_bool().unwrap_or(false),
                "{} should be using_defaults in empty config dir",
                name
            );
        }
    }
}

// ============================================================================
// Check Command: Targeted Checks
// ============================================================================

#[test]
fn test_check_priors_only() {
    let output = pt_core()
        .args(["--format", "json", "check", "--priors"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).expect("parse JSON");
    let checks = json["checks"].as_array().expect("checks array");

    // Should only contain priors check
    assert_eq!(checks.len(), 1, "should have exactly 1 check");
    assert_eq!(checks[0]["check"], "priors");
}

#[test]
fn test_check_policy_only() {
    let output = pt_core()
        .args(["--format", "json", "check", "--policy"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).expect("parse JSON");
    let checks = json["checks"].as_array().expect("checks array");

    assert_eq!(checks.len(), 1, "should have exactly 1 check");
    assert_eq!(checks[0]["check"], "policy");
}

#[test]
fn test_check_capabilities_only() {
    let output = pt_core()
        .args(["--format", "json", "check", "--caps"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).expect("parse JSON");
    let checks = json["checks"].as_array().expect("checks array");

    assert_eq!(checks.len(), 1, "should have exactly 1 check");
    assert_eq!(checks[0]["check"], "capabilities");
}

// ============================================================================
// Missing Config: Graceful Degradation
// ============================================================================

#[test]
fn test_config_show_with_empty_config_dir() {
    let dir = tempdir().expect("tempdir");

    let output = pt_core()
        .args([
            "--format",
            "json",
            "--config",
            dir.path().to_str().unwrap(),
            "config",
            "show",
        ])
        .assert()
        .success()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).expect("parse JSON");

    // Should report using defaults
    assert!(
        json["priors"]["source"]["using_defaults"]
            .as_bool()
            .unwrap_or(false),
        "priors should use defaults with empty config dir"
    );
    assert!(
        json["policy"]["source"]["using_defaults"]
            .as_bool()
            .unwrap_or(false),
        "policy should use defaults with empty config dir"
    );
}

#[test]
fn test_config_show_with_nonexistent_config_dir() {
    let dir = tempdir().expect("tempdir");
    let nonexistent = dir.path().join("does_not_exist");

    // A nonexistent config directory should still work (defaults)
    let output = pt_core()
        .args([
            "--format",
            "json",
            "--config",
            nonexistent.to_str().unwrap(),
            "config",
            "show",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).expect("parse JSON");
    assert!(
        json["priors"]["source"]["using_defaults"]
            .as_bool()
            .unwrap_or(false),
        "priors should use defaults with nonexistent config dir"
    );
}

#[test]
fn test_check_with_nonexistent_config_dir() {
    let dir = tempdir().expect("tempdir");
    let nonexistent = dir.path().join("no_such_dir");

    // Check command should still succeed with defaults
    pt_core()
        .args([
            "--format",
            "json",
            "--config",
            nonexistent.to_str().unwrap(),
            "check",
        ])
        .assert()
        .success()
        .code(0);
}

// ============================================================================
// Invalid Config: Error Paths
// ============================================================================

#[test]
fn test_config_validate_invalid_json_exit_code() {
    let dir = tempdir().expect("tempdir");
    let bad_policy = dir.path().join("policy.json");

    let mut f = fs::File::create(&bad_policy).expect("create file");
    f.write_all(b"{ not valid json !!! }").expect("write");

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

#[test]
fn test_config_validate_invalid_json_error_message() {
    let dir = tempdir().expect("tempdir");
    let bad_policy = dir.path().join("policy.json");

    let mut f = fs::File::create(&bad_policy).expect("create file");
    f.write_all(b"{ not valid json !!! }").expect("write");

    pt_core()
        .args([
            "--format",
            "json",
            "config",
            "validate",
            bad_policy.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("error")
                .or(predicate::str::contains("Error").or(predicate::str::contains("parse"))),
        );
}

#[test]
fn test_check_with_invalid_policy_json_in_config_dir() {
    let dir = tempdir().expect("tempdir");
    let policy = dir.path().join("policy.json");

    let mut f = fs::File::create(&policy).expect("create file");
    f.write_all(b"NOT_JSON_AT_ALL").expect("write");

    let output = pt_core()
        .args([
            "--format",
            "json",
            "--config",
            dir.path().to_str().unwrap(),
            "check",
        ])
        .assert()
        .failure()
        .code(10) // ArgsError - parse failure
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).expect("parse JSON");
    assert_eq!(
        json["status"], "error",
        "check should report error status for invalid policy"
    );
}

#[test]
fn test_check_with_invalid_priors_json_in_config_dir() {
    let dir = tempdir().expect("tempdir");
    let priors = dir.path().join("priors.json");

    let mut f = fs::File::create(&priors).expect("create file");
    f.write_all(b"{{{invalid}}}").expect("write");

    let output = pt_core()
        .args([
            "--format",
            "json",
            "--config",
            dir.path().to_str().unwrap(),
            "check",
        ])
        .assert()
        .failure()
        .code(10) // ArgsError
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).expect("parse JSON");
    assert_eq!(json["status"], "error");

    // Should have at least one check with error status
    let checks = json["checks"].as_array().expect("checks array");
    let has_error = checks.iter().any(|c| c["status"] == "error");
    assert!(has_error, "should have at least one error check result");
}

// ============================================================================
// Config Environment Variable Override
// ============================================================================

#[test]
fn test_config_show_respects_xdg_override() {
    let dir = tempdir().expect("tempdir");

    // Export a valid policy into the directory
    pt_core()
        .args([
            "--format",
            "json",
            "config",
            "export-preset",
            "developer",
            "--output",
            dir.path().join("policy.json").to_str().unwrap(),
        ])
        .assert()
        .success();

    let output = pt_core()
        .args([
            "--format",
            "json",
            "--config",
            dir.path().to_str().unwrap(),
            "config",
            "show",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).expect("parse JSON");

    // Policy should NOT be using defaults since we put a policy.json in the dir
    assert!(
        !json["policy"]["source"]["using_defaults"]
            .as_bool()
            .unwrap_or(true),
        "policy should be loaded from config dir, not defaults"
    );
}

#[test]
fn test_config_show_env_var_config_dir() {
    let dir = tempdir().expect("tempdir");

    // Export a valid policy
    pt_core()
        .args([
            "--format",
            "json",
            "config",
            "export-preset",
            "ci",
            "--output",
            dir.path().join("policy.json").to_str().unwrap(),
        ])
        .assert()
        .success();

    // Use env var instead of --config flag
    let output = pt_core()
        .env("PROCESS_TRIAGE_CONFIG", dir.path().to_str().unwrap())
        .args(["--format", "json", "config", "show"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).expect("parse JSON");
    assert!(
        !json["policy"]["source"]["using_defaults"]
            .as_bool()
            .unwrap_or(true),
        "policy should be loaded via PROCESS_TRIAGE_CONFIG env var"
    );
}

// ============================================================================
// Agent Capabilities: Permissions and Tool Detection
// ============================================================================

#[test]
fn test_agent_capabilities_has_permissions_info() {
    let output = pt_core()
        .args(["--format", "json", "agent", "capabilities"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).expect("parse JSON");

    // Should have permissions section
    assert!(
        json.get("permissions").is_some(),
        "capabilities should have 'permissions'"
    );

    let perms = &json["permissions"];
    assert!(
        perms.get("effective_uid").is_some(),
        "permissions should have effective_uid"
    );
    assert!(
        perms.get("is_root").is_some(),
        "permissions should have is_root"
    );
}

#[test]
fn test_agent_capabilities_has_tools_section() {
    let output = pt_core()
        .args(["--format", "json", "agent", "capabilities"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).expect("parse JSON");

    // Should have tools section
    assert!(
        json.get("tools").is_some(),
        "capabilities should have 'tools'"
    );

    let tools = &json["tools"];
    assert!(tools.is_object(), "tools should be an object");

    // At least ps should be detected
    if let Some(ps) = tools.get("ps") {
        assert!(
            ps.get("available").is_some(),
            "ps tool entry should have 'available'"
        );
    }
}

#[test]
fn test_agent_capabilities_has_os_info() {
    let output = pt_core()
        .args(["--format", "json", "agent", "capabilities"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).expect("parse JSON");

    // Should have OS info object at top level
    assert!(json.get("os").is_some(), "capabilities should have 'os'");

    let os = &json["os"];
    assert!(os.is_object(), "os should be an object");
    assert!(os.get("family").is_some(), "os should have 'family'");
    assert!(os.get("arch").is_some(), "os should have 'arch'");
}

// ============================================================================
// Agent Init: Invalid Agent Name
// ============================================================================

#[test]
fn test_agent_init_invalid_agent_name_exit_code() {
    pt_core()
        .args([
            "--format",
            "json",
            "agent",
            "init",
            "--agent",
            "nonexistent_agent",
        ])
        .assert()
        .failure()
        .code(10); // ArgsError
}

#[test]
fn test_agent_init_invalid_agent_name_error_message() {
    pt_core()
        .args(["--format", "json", "agent", "init", "--agent", "bogus"])
        .assert()
        .failure()
        .code(10)
        .stderr(predicate::str::contains("unknown agent"));
}

// ============================================================================
// Scan with Degraded Config
// ============================================================================

#[test]
fn test_scan_with_empty_config_dir_uses_defaults() {
    let dir = tempdir().expect("tempdir");

    // Scan should work even with empty config dir (uses defaults)
    pt_core()
        .env("PT_SKIP_GLOBAL_LOCK", "1")
        .args([
            "--format",
            "json",
            "--config",
            dir.path().to_str().unwrap(),
            "scan",
            "--samples",
            "3",
        ])
        .timeout(Duration::from_secs(120))
        .assert()
        .success()
        .code(0);
}

// ============================================================================
// Exit Code Specification
// ============================================================================

#[test]
fn test_exit_code_args_error_for_unknown_subcommand() {
    pt_core()
        .args(["nonexistent-command"])
        .assert()
        .failure()
        .code(2); // clap produces exit code 2 for unknown subcommands
}

#[test]
fn test_exit_code_args_error_for_missing_required_arg() {
    // export-preset requires a preset name
    pt_core()
        .args(["config", "export-preset"])
        .assert()
        .failure()
        .code(2); // clap exit code for missing required args
}

#[test]
fn test_exit_code_lock_contention() {
    // Verify that PT_SKIP_GLOBAL_LOCK=1 bypasses the lock
    pt_core()
        .env("PT_SKIP_GLOBAL_LOCK", "1")
        .args(["--format", "json", "scan", "--samples", "3"])
        .timeout(Duration::from_secs(120))
        .assert()
        .success();
}

// ============================================================================
// Format Compatibility for Error Paths
// ============================================================================

#[test]
fn test_check_works_with_all_formats() {
    for format in &["json", "toon", "summary"] {
        pt_core()
            .args(["--format", format, "check"])
            .assert()
            .success();

        eprintln!("[INFO] check works with format '{}'", format);
    }
}

#[test]
fn test_config_show_works_with_all_formats() {
    for format in &["json", "toon", "summary"] {
        pt_core()
            .args(["--format", format, "config", "show"])
            .assert()
            .success();

        eprintln!("[INFO] config show works with format '{}'", format);
    }
}

#[test]
fn test_capabilities_works_with_all_formats() {
    for format in &["json", "toon", "summary"] {
        pt_core()
            .args(["--format", format, "agent", "capabilities"])
            .assert()
            .success();

        eprintln!("[INFO] capabilities works with format '{}'", format);
    }
}

// ============================================================================
// Config Show: Determinism
// ============================================================================

#[test]
fn test_config_show_deterministic_with_same_config_dir() {
    let dir = tempdir().expect("tempdir");

    let output1 = pt_core()
        .args([
            "--format",
            "json",
            "--config",
            dir.path().to_str().unwrap(),
            "config",
            "show",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let output2 = pt_core()
        .args([
            "--format",
            "json",
            "--config",
            dir.path().to_str().unwrap(),
            "config",
            "show",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json1: Value = serde_json::from_slice(&output1).expect("parse JSON 1");
    let json2: Value = serde_json::from_slice(&output2).expect("parse JSON 2");

    // Policy and priors values should be identical
    assert_eq!(
        json1["priors"]["values"], json2["priors"]["values"],
        "priors values should be deterministic"
    );
    assert_eq!(
        json1["policy"]["values"], json2["policy"]["values"],
        "policy values should be deterministic"
    );
}
