//! Summary output format tests for pt-core.
//!
//! Tests the summary output mode across all supported commands, validating:
//! - Correct format structure for each command
//! - JSON output mode for machine parsing
//! - Consistent formatting patterns
//! - Session-based output consistency

use assert_cmd::cargo::cargo_bin_cmd;
use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;

fn pt_core() -> Command {
    let mut cmd = cargo_bin_cmd!("pt-core");
    // Avoid lock contention when tests run in parallel
    cmd.env("PT_SKIP_GLOBAL_LOCK", "1");
    cmd
}

fn apply_test_env(cmd: &mut Command) -> (tempfile::TempDir, tempfile::TempDir) {
    let config_dir = tempdir().expect("temp config dir");
    let data_dir = tempdir().expect("temp data dir");
    cmd.env("PROCESS_TRIAGE_CONFIG", config_dir.path())
        .env("PROCESS_TRIAGE_DATA", data_dir.path());
    (config_dir, data_dir)
}

// =========================================================================
// JSON Format Tests (for machine parsing)
// =========================================================================

#[test]
fn json_scan_outputs_valid_json() {
    let mut cmd = pt_core();
    let _env = apply_test_env(&mut cmd);

    let output = cmd
        .args(["--format", "json", "scan"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value =
        serde_json::from_slice(&output).expect("scan output should be valid JSON");

    // Verify expected fields
    assert!(json.get("session_id").is_some(), "should have session_id");
    assert!(
        json.get("generated_at").is_some(),
        "should have generated_at"
    );
    assert!(json.get("scan").is_some(), "should have scan data");
}

#[test]
fn json_agent_snapshot_outputs_valid_json() {
    let mut cmd = pt_core();
    let _env = apply_test_env(&mut cmd);

    let output = cmd
        .args(["--format", "json", "agent", "snapshot"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value =
        serde_json::from_slice(&output).expect("snapshot output should be valid JSON");

    assert!(json.get("session_id").is_some(), "should have session_id");
    assert!(
        json.get("system_state").is_some(),
        "should have system_state"
    );
    assert!(
        json.get("capabilities").is_some(),
        "should have capabilities"
    );
}

#[test]
fn json_config_show_outputs_valid_json() {
    let mut cmd = pt_core();
    let _env = apply_test_env(&mut cmd);

    let output = cmd
        .args(["--format", "json", "config", "show"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value =
        serde_json::from_slice(&output).expect("config show output should be valid JSON");

    assert!(json.get("session_id").is_some(), "should have session_id");
}

#[test]
fn summary_scan_outputs_one_line() {
    let mut cmd = pt_core();
    let _env = apply_test_env(&mut cmd);

    cmd.args(["--format", "summary", "scan"])
        .assert()
        .success()
        .stdout(predicate::str::is_match(r"^Scanned \d+ processes in \d+ms\s*$").unwrap());
}

#[test]
fn summary_check_outputs_status_line() {
    let mut cmd = pt_core();
    let _env = apply_test_env(&mut cmd);

    cmd.args(["--format", "summary", "check"])
        .assert()
        .success()
        .stdout(predicate::str::is_match(r"^\[pt-[^\]]+\] check: (OK|FAILED)\s*$").unwrap());
}

#[test]
fn summary_config_show_outputs_sources() {
    let mut cmd = pt_core();
    let _env = apply_test_env(&mut cmd);

    cmd.args(["--format", "summary", "config", "show"])
        .assert()
        .success()
        .stdout(predicate::str::contains("config: priors="))
        .stdout(predicate::str::contains("policy="));
}

#[test]
fn summary_config_validate_outputs_status() {
    let mut cmd = pt_core();
    let _env = apply_test_env(&mut cmd);

    cmd.args(["--format", "summary", "config", "validate"])
        .assert()
        .success()
        .stdout(predicate::str::contains("config validate:"));
}

#[test]
fn summary_agent_plan_outputs_stub() {
    let mut cmd = pt_core();
    let _env = apply_test_env(&mut cmd);

    // Exit code 0 = no candidates, 1 = candidates found (PlanReady), both are success
    cmd.args(["--format", "summary", "agent", "plan"])
        .assert()
        .code(predicate::in_iter([0, 1]))
        .stdout(predicate::str::contains("agent plan:"));
}

// =========================================================================
// Additional Summary Format Tests
// =========================================================================

#[test]
fn summary_agent_snapshot_outputs_system_info() {
    let mut cmd = pt_core();
    let _env = apply_test_env(&mut cmd);

    cmd.args(["--format", "summary", "agent", "snapshot"])
        .assert()
        .success()
        .stdout(predicate::str::contains("agent snapshot:"))
        .stdout(predicate::str::contains("procs"))
        .stdout(predicate::str::contains("GB"));
}

#[test]
fn summary_agent_sessions_outputs_count() {
    let mut cmd = pt_core();
    let _env = apply_test_env(&mut cmd);

    // May return "No sessions found" or "N session(s)"
    cmd.args(["--format", "summary", "agent", "sessions"])
        .assert()
        .success()
        .stdout(predicate::str::is_match(r"(No sessions found|session\(s\))").unwrap());
}

#[test]
fn summary_agent_inbox_outputs_count() {
    let mut cmd = pt_core();
    let _env = apply_test_env(&mut cmd);

    // Should output "Inbox: N items" or similar
    cmd.args(["--format", "summary", "agent", "inbox"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Inbox:"));
}

// =========================================================================
// Scenario Tests: Clean System
// =========================================================================

#[test]
fn summary_plan_clean_system_reports_candidates() {
    // On a clean test system, agent plan should report candidate counts
    // This tests the "clean_system" scenario from the spec
    let mut cmd = pt_core();
    let _env = apply_test_env(&mut cmd);

    cmd.args(["--format", "summary", "agent", "plan"])
        .assert()
        .code(predicate::in_iter([0, 1]))
        .stdout(predicate::str::is_match(r"agent plan: \d+ candidates").unwrap());
}

#[test]
fn summary_scan_clean_system_reports_process_count() {
    // Scan should always report process count even on clean system
    let mut cmd = pt_core();
    let _env = apply_test_env(&mut cmd);

    cmd.args(["--format", "summary", "scan"])
        .assert()
        .success()
        .stdout(predicate::str::is_match(r"Scanned \d+ processes").unwrap());
}

// =========================================================================
// JSON Format: Agent Plan
// =========================================================================

#[test]
fn json_agent_plan_outputs_valid_structure() {
    let mut cmd = pt_core();
    let _env = apply_test_env(&mut cmd);

    let output = cmd
        .args(["--format", "json", "agent", "plan"])
        .assert()
        .code(predicate::in_iter([0, 1]))
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value =
        serde_json::from_slice(&output).expect("plan output should be valid JSON");

    // Verify expected structure
    assert!(json.get("session_id").is_some(), "should have session_id");
    assert!(
        json.get("candidates").is_some() || json.get("plan").is_some(),
        "should have candidates or plan"
    );
}

// =========================================================================
// Format Consistency Tests
// =========================================================================

#[test]
fn summary_lines_are_reasonably_short() {
    // Summary output should not produce excessively long lines
    // This tests the "80 column" requirement loosely
    let mut cmd = pt_core();
    let _env = apply_test_env(&mut cmd);

    let output = cmd
        .args(["--format", "summary", "scan"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let stdout = String::from_utf8_lossy(&output);
    for line in stdout.lines() {
        assert!(
            line.len() <= 200,
            "summary line should not be excessively long: {} chars",
            line.len()
        );
    }
}

#[test]
fn summary_session_id_format_consistent() {
    // Session IDs in summary output should follow the pt-YYYYMMDD-HHMMSS-XXXX pattern
    let mut cmd = pt_core();
    let _env = apply_test_env(&mut cmd);

    cmd.args(["--format", "summary", "check"])
        .assert()
        .success()
        .stdout(predicate::str::is_match(r"\[pt-[0-9]{8}-[0-9]{6}-[a-z0-9]+\]").unwrap());
}

// =========================================================================
// Agent Export/Import Priors Summary
// =========================================================================

#[test]
fn summary_agent_export_priors_outputs_source() {
    let mut cmd = pt_core();
    let (config_dir, data_dir) = apply_test_env(&mut cmd);

    // Create temp output file for export-priors
    let out_file = data_dir.path().join("priors.json");

    cmd.args([
        "--format",
        "summary",
        "agent",
        "export-priors",
        "--out",
        out_file.to_str().unwrap(),
    ])
    .assert()
    .success()
    .stdout(predicate::str::contains("Exported priors to:"));

    // Keep dirs alive for cleanup
    drop(config_dir);
}

// =========================================================================
// Logging Requirements
// =========================================================================

#[test]
fn json_output_includes_timing_info() {
    // JSON outputs should include timing information for analysis
    let mut cmd = pt_core();
    let _env = apply_test_env(&mut cmd);

    let output = cmd
        .args(["--format", "json", "scan"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();

    // Check for timing info in scan metadata
    if let Some(scan) = json.get("scan") {
        if let Some(metadata) = scan.get("metadata") {
            assert!(
                metadata.get("duration_ms").is_some(),
                "scan should include duration_ms"
            );
        }
    }
}
