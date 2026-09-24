#![cfg(feature = "test-utils")]

use assert_cmd::cargo::cargo_bin_cmd;
use predicates::prelude::*;
use pt_core::test_utils::ProcessHarness;

#[test]
fn test_cli_scan_real() {
    if !ProcessHarness::is_available() {
        return;
    }

    let mut cmd = cargo_bin_cmd!("pt-core");
    cmd.args(["scan", "--format", "json", "--robot"])
        .assert()
        .success()
        // Be robust against whitespace in pretty-printed JSON
        .stdout(predicate::str::contains("scan_type").and(predicate::str::contains("quick")));
}

#[test]
fn test_cli_scan_jsonl_log() {
    if !ProcessHarness::is_available() {
        return;
    }

    let mut cmd = cargo_bin_cmd!("pt-core");
    // With --format json, logs should be JSONL on stderr
    cmd.args(["scan", "--format", "json", "--robot"])
        .assert()
        .success()
        .stderr(predicate::str::contains("\"event\":").and(predicate::str::contains("scan")));
}

#[test]
fn test_cli_run_dry_run_real() {
    if !ProcessHarness::is_available() {
        return;
    }

    // Interactive mode without a terminal (robot/CI) must refuse with a capability
    // error and point at the agent interface, not report success.
    let mut cmd = cargo_bin_cmd!("pt-core");
    cmd.args(["run", "--dry-run", "--format", "json", "--robot"])
        .assert()
        .code(11)
        .stdout(predicate::str::contains("pt agent plan"));
}
