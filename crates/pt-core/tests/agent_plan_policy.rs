//! Agent plan policy field tests.
//!
//! Ensures policy enforcement metadata is emitted in agent plan JSON output.

use assert_cmd::cargo::cargo_bin_cmd;
use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use std::time::Duration;
use tempfile::TempDir;

thread_local! {
    /// Private pt state for the running test (libtest gives each test its own
    /// thread), removed when the test ends. Keeps the test out of the runner's
    /// own pt data directory and its execution-policy lock.
    static PRIVATE_STATE: TempDir = tempfile::Builder::new()
        .prefix("pt-agent-plan-policy-")
        .tempdir()
        .expect("create private pt state directory");
}

/// Get a Command for pt-core binary with sample-size limit for faster testing.
fn pt_core_fast() -> Command {
    let mut cmd = cargo_bin_cmd!("pt-core");
    cmd.timeout(Duration::from_secs(120));
    // Avoid lock contention when tests run in parallel
    cmd.env("PT_SKIP_GLOBAL_LOCK", "1");
    PRIVATE_STATE.with(|state| {
        let root = state.path();
        cmd.env("PROCESS_TRIAGE_DATA", root.join("data"))
            .env("PROCESS_TRIAGE_CONFIG", root.join("config"))
            .env("XDG_DATA_HOME", root.join("xdg-data"))
            .env("XDG_CONFIG_HOME", root.join("xdg-config"))
            .env("XDG_CACHE_HOME", root.join("xdg-cache"))
            .env_remove("PT_CONFIG_DIR");
    });
    cmd.args(["--standalone"]);
    cmd
}

/// Default sample size for tests that need inference coverage.
const TEST_SAMPLE_SIZE: &str = "10";

#[test]
fn agent_plan_emits_policy_fields() {
    let output = pt_core_fast()
        .args([
            "--format",
            "json",
            "agent",
            "plan",
            "--sample-size",
            TEST_SAMPLE_SIZE,
        ])
        .assert()
        // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
        .code(predicate::in_iter([0, 1]))
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).expect("Output should be valid JSON");

    let summary = json
        .get("summary")
        .expect("Missing summary in agent plan output");
    assert!(
        summary.get("policy_blocked").is_some(),
        "Missing summary.policy_blocked"
    );
    assert!(
        summary.get("policy_blocked").unwrap().is_number(),
        "summary.policy_blocked should be a number"
    );

    let candidates = json
        .get("candidates")
        .and_then(|v| v.as_array())
        .expect("Missing candidates array in agent plan output");

    for candidate in candidates {
        assert!(
            candidate.get("policy_blocked").is_some(),
            "Missing candidate.policy_blocked"
        );
        let policy = candidate.get("policy").expect("Missing candidate.policy");
        assert!(policy.is_object(), "candidate.policy should be an object");
        assert!(
            policy.get("allowed").is_some(),
            "candidate.policy.allowed missing"
        );
    }
}
