//! Summary output format tests for pt-core.

use assert_cmd::cargo::cargo_bin_cmd;
use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;

fn pt_core() -> Command {
    cargo_bin_cmd!("pt-core")
}

fn apply_test_env(cmd: &mut Command) -> (tempfile::TempDir, tempfile::TempDir) {
    let config_dir = tempdir().expect("temp config dir");
    let data_dir = tempdir().expect("temp data dir");
    cmd.env("PROCESS_TRIAGE_CONFIG", config_dir.path())
        .env("PROCESS_TRIAGE_DATA", data_dir.path());
    (config_dir, data_dir)
}

#[test]
fn summary_scan_outputs_one_line() {
    let mut cmd = pt_core();
    let _env = apply_test_env(&mut cmd);

    cmd.args(["--format", "summary", "scan"])
        .assert()
        .success()
        .stdout(
            predicate::str::is_match(r"^Scanned \d+ processes in \d+ms\s*$").unwrap(),
        );
}

#[test]
fn summary_check_outputs_status_line() {
    let mut cmd = pt_core();
    let _env = apply_test_env(&mut cmd);

    cmd.args(["--format", "summary", "check"])
        .assert()
        .success()
        .stdout(
            predicate::str::is_match(r"^\[pt-[^\]]+\] check: (OK|FAILED)\s*$")
                .unwrap(),
        );
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
