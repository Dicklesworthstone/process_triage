//! Agent plan policy field tests.
//!
//! Ensures policy enforcement metadata is emitted in agent plan JSON output.

use assert_cmd::cargo::cargo_bin_cmd;
use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use std::time::Duration;

/// Get a Command for pt-core binary with sample-size limit for faster testing.
fn pt_core_fast() -> Command {
    let mut cmd = cargo_bin_cmd!("pt-core");
    cmd.timeout(Duration::from_secs(120));
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
        let policy = candidate
            .get("policy")
            .expect("Missing candidate.policy");
        assert!(policy.is_object(), "candidate.policy should be an object");
        assert!(
            policy.get("allowed").is_some(),
            "candidate.policy.allowed missing"
        );
    }
}
