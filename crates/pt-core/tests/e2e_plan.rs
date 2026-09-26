//! End-to-end tests for agent plan workflow.
//!
//! Tests the `agent plan` command which generates action plans
//! without execution for review and validation.

use assert_cmd::cargo::cargo_bin_cmd;
use assert_cmd::Command;
use predicates::prelude::*;
use pt_common::config::policy::Policy;
use serde_json::Value;
use std::time::Duration;
use tempfile::tempdir;

/// Get a Command for pt-core binary.
fn pt_core() -> Command {
    let mut cmd = cargo_bin_cmd!("pt-core");
    // Extended timeout for debug builds/slow environments
    cmd.timeout(Duration::from_secs(300));
    // Avoid lock contention when tests run in parallel
    cmd.env("PT_SKIP_GLOBAL_LOCK", "1");
    cmd
}

/// Get a Command for pt-core binary with sample-size limit for faster testing.
/// Uses --sample-size to limit inference to N processes, making tests complete
/// in seconds instead of minutes in debug builds.
fn pt_core_fast() -> Command {
    let mut cmd = cargo_bin_cmd!("pt-core");
    cmd.timeout(Duration::from_secs(120));
    // Avoid lock contention when tests run in parallel
    cmd.env("PT_SKIP_GLOBAL_LOCK", "1");
    // Sample 50 processes for faster testing while still exercising the inference path
    cmd.args(["--standalone"]);
    cmd
}

/// Default sample size for tests that need inference coverage
const TEST_SAMPLE_SIZE: &str = "10";

// ============================================================================
// Basic Plan Tests
// ============================================================================

mod plan_basic {
    use super::*;

    #[test]
    fn plan_runs_without_error() {
        // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
        pt_core_fast()
            .args(["agent", "plan", "--sample-size", TEST_SAMPLE_SIZE])
            .assert()
            .code(predicate::in_iter([0, 1]));
    }

    #[test]
    fn plan_with_json_format() {
        pt_core_fast()
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
            .stdout(predicate::str::contains("schema_version"))
            .stdout(predicate::str::contains("session_id"));
    }

    #[test]
    fn plan_produces_valid_json() {
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

        // Verify required fields exist
        assert!(
            json.get("schema_version").is_some(),
            "Missing schema_version"
        );
        assert!(json.get("session_id").is_some(), "Missing session_id");
        assert!(json.get("generated_at").is_some(), "Missing generated_at");
    }

    #[test]
    fn plan_emits_progress_events() {
        pt_core_fast()
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
            .stderr(
                predicate::str::contains("\"event\":").and(predicate::str::contains("plan_ready")),
            );
    }
}

// ============================================================================
// Plan Options Tests
// ============================================================================

mod plan_options {
    use super::*;

    #[test]
    fn plan_with_max_candidates() {
        pt_core_fast()
            .args([
                "agent",
                "plan",
                "--max-candidates",
                "10",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
            .code(predicate::in_iter([0, 1]));
    }

    #[test]
    fn plan_with_threshold() {
        pt_core_fast()
            .args([
                "agent",
                "plan",
                "--threshold",
                "0.8",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
            .code(predicate::in_iter([0, 1]));
    }

    #[test]
    fn plan_with_only_filter_kill() {
        pt_core_fast()
            .args([
                "agent",
                "plan",
                "--only",
                "kill",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
            .code(predicate::in_iter([0, 1]));
    }

    #[test]
    fn plan_with_only_filter_review() {
        pt_core_fast()
            .args([
                "agent",
                "plan",
                "--only",
                "review",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
            .code(predicate::in_iter([0, 1]));
    }

    #[test]
    fn plan_with_only_filter_all() {
        pt_core_fast()
            .args([
                "agent",
                "plan",
                "--only",
                "all",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
            .code(predicate::in_iter([0, 1]));
    }

    #[test]
    fn plan_with_yes_flag() {
        pt_core_fast()
            .args(["agent", "plan", "--yes", "--sample-size", TEST_SAMPLE_SIZE])
            .assert()
            // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
            .code(predicate::in_iter([0, 1]));
    }

    #[test]
    fn plan_with_combined_options() {
        pt_core_fast()
            .args([
                "agent",
                "plan",
                "--max-candidates",
                "5",
                "--threshold",
                "0.9",
                "--only",
                "kill",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
            .code(predicate::in_iter([0, 1]));
    }

    #[test]
    fn plan_with_goal_includes_goal_fields() {
        let output = pt_core_fast()
            .args([
                "--format",
                "json",
                "agent",
                "plan",
                "--goal",
                "free 1GB RAM",
                "--threshold",
                "0",
                "--max-candidates",
                "5",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            .code(predicate::in_iter([0, 1]))
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).expect("Output should be valid JSON");
        assert_eq!(
            json.get("goal").and_then(|v| v.as_str()),
            Some("free 1GB RAM")
        );
        assert!(
            json.get("goal_progress")
                .and_then(|v| v.as_array())
                .is_some(),
            "expected goal_progress array in plan output"
        );
        assert!(
            json.get("goal_summary").is_some(),
            "expected goal_summary in plan output"
        );

        if let Some(stub_flags) = json.get("stub_flags") {
            let flags_used: Vec<&str> = stub_flags
                .get("flags_used")
                .and_then(|v| v.as_array())
                .map(|items| items.iter().filter_map(|v| v.as_str()).collect())
                .unwrap_or_default();
            assert!(
                !flags_used.contains(&"--goal"),
                "--goal should not be treated as stub flag anymore"
            );
        }
    }

    /// A goal must never bypass per-candidate safety: every pid in the kill set is a
    /// candidate whose own recommendation is `kill`; goal picks that are not
    /// kill-recommended are listed for review instead.
    #[test]
    fn plan_goal_never_puts_non_kill_candidates_in_kill_set() {
        let output = pt_core_fast()
            .args([
                "--format",
                "json",
                "agent",
                "plan",
                "--goal",
                "free 64GB RAM",
                "--threshold",
                "0",
                "--min-age",
                "0",
                "--max-candidates",
                "200",
            ])
            .assert()
            .code(predicate::in_iter([0, 1, 5]))
            .get_output()
            .stdout
            .clone();
        let json: Value = serde_json::from_slice(&output).expect("valid JSON");
        let candidates = json["candidates"].as_array().cloned().unwrap_or_default();
        let action_of = |pid: u64| {
            candidates
                .iter()
                .find(|c| c["pid"].as_u64() == Some(pid))
                .and_then(|c| c["recommended_action"].as_str())
                .map(str::to_string)
        };
        let kill_set = json["recommendations"]["kill_set"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        for pid in kill_set.iter().filter_map(|v| v.as_u64()) {
            assert_eq!(
                action_of(pid).as_deref(),
                Some("kill"),
                "pid {pid} is in kill_set without a kill recommendation"
            );
        }
        if let Some(needing_review) = json["summary"]["goal_selected_needing_review"].as_array() {
            for pid in needing_review.iter().filter_map(|v| v.as_u64()) {
                assert_ne!(action_of(pid).as_deref(), Some("kill"));
            }
        }
    }

    #[test]
    fn plan_includes_signature_inference_metadata() {
        let output = pt_core_fast()
            .args([
                "--format",
                "json",
                "agent",
                "plan",
                "--threshold",
                "0",
                "--max-candidates",
                "5",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            .code(predicate::in_iter([0, 1]))
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).expect("Output should be valid JSON");
        let summary = json
            .get("summary")
            .and_then(|v| v.as_object())
            .expect("expected summary object");
        assert!(
            summary.contains_key("signature_fast_path_enabled"),
            "summary should include signature fast-path enablement"
        );
        assert!(
            summary.contains_key("signature_matches"),
            "summary should include signature match count"
        );
        assert!(
            summary.contains_key("signature_fast_path_used"),
            "summary should include signature fast-path usage count"
        );

        if let Some(first_candidate) = json
            .get("candidates")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
        {
            assert!(
                first_candidate.get("signature").is_some(),
                "candidate should include signature metadata"
            );
            assert!(
                first_candidate.get("inference").is_some(),
                "candidate should include inference metadata"
            );
        }
    }

    #[test]
    fn plan_respects_policy_disabling_signature_fast_path() {
        let config_dir = tempdir().expect("temp config dir");
        let mut policy = Policy::default();
        policy.signature_fast_path.enabled = false;
        let policy_path = config_dir.path().join("policy.json");
        std::fs::write(
            &policy_path,
            serde_json::to_vec_pretty(&policy).expect("serialize policy"),
        )
        .expect("write policy.json");

        let output = pt_core_fast()
            .env("PT_CONFIG_DIR", config_dir.path().display().to_string())
            .args([
                "--format",
                "json",
                "agent",
                "plan",
                "--threshold",
                "0",
                "--max-candidates",
                "5",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            .code(predicate::in_iter([0, 1]))
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).expect("Output should be valid JSON");
        let enabled = json
            .get("summary")
            .and_then(|v| v.get("signature_fast_path_enabled"))
            .and_then(|v| v.as_bool());
        assert_eq!(enabled, Some(false));
    }
}

// ============================================================================
// Prediction Output Tests
// ============================================================================

mod plan_predictions {
    use super::*;

    #[test]
    fn plan_with_predictions_includes_field_when_candidates_exist() {
        let output = pt_core_fast()
            .args([
                "--format",
                "json",
                "agent",
                "plan",
                "--include-predictions",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            .code(predicate::in_iter([0, 1]))
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).expect("valid JSON");
        let candidates = json
            .get("candidates")
            .and_then(|c| c.as_array())
            .cloned()
            .unwrap_or_default();

        if let Some(candidate) = candidates.first() {
            assert!(
                candidate.get("predictions").is_some(),
                "predictions should be included when flag is set"
            );
        }
    }

    #[test]
    fn plan_without_predictions_omits_field_when_candidates_exist() {
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
            .code(predicate::in_iter([0, 1]))
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).expect("valid JSON");
        let candidates = json
            .get("candidates")
            .and_then(|c| c.as_array())
            .cloned()
            .unwrap_or_default();

        if let Some(candidate) = candidates.first() {
            assert!(
                candidate.get("predictions").is_none(),
                "predictions should be omitted by default"
            );
        }
    }
}

// ============================================================================
// Output Format Tests
// ============================================================================

mod plan_formats {
    use super::*;

    #[test]
    fn plan_json_format() {
        pt_core_fast()
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
            .stdout(predicate::str::starts_with("{"));
    }

    #[test]
    fn plan_summary_format() {
        pt_core_fast()
            .args([
                "--format",
                "summary",
                "agent",
                "plan",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
            .code(predicate::in_iter([0, 1]))
            .stdout(predicate::str::contains("agent plan"));
    }

    #[test]
    fn plan_prose_format() {
        pt_core_fast()
            .args([
                "--format",
                "prose",
                "agent",
                "plan",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
            .code(predicate::in_iter([0, 1]))
            .stdout(predicate::str::contains("pt-core"));
    }

    #[test]
    fn plan_exitcode_format() {
        // Exitcode format produces no output on success
        pt_core_fast()
            .args([
                "--format",
                "exitcode",
                "agent",
                "plan",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
            .code(predicate::in_iter([0, 1]))
            .stdout(predicate::str::is_empty());
    }
}

// ============================================================================
// Schema Validation Tests
// ============================================================================

mod plan_schema {
    use super::*;

    #[test]
    fn plan_has_schema_version() {
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

        let json: Value = serde_json::from_slice(&output).unwrap();
        let version = json
            .get("schema_version")
            .expect("Missing schema_version")
            .as_str()
            .expect("schema_version should be string");

        // Schema version should be semver-like
        assert!(
            version.contains('.'),
            "Schema version should be semver format: {}",
            version
        );
    }

    #[test]
    fn plan_session_id_is_valid() {
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

        let json: Value = serde_json::from_slice(&output).unwrap();
        let session_id = json
            .get("session_id")
            .expect("Missing session_id")
            .as_str()
            .expect("session_id should be string");

        // Session ID should be non-empty
        assert!(!session_id.is_empty(), "Session ID should not be empty");
        assert!(
            session_id.len() >= 8,
            "Session ID seems too short: {}",
            session_id
        );
    }

    #[test]
    fn plan_generated_at_is_iso8601() {
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

        let json: Value = serde_json::from_slice(&output).unwrap();
        let generated_at = json
            .get("generated_at")
            .expect("Missing generated_at")
            .as_str()
            .expect("generated_at should be string");

        // ISO 8601 timestamps contain 'T' separator
        assert!(
            generated_at.contains('T'),
            "Timestamp should be ISO 8601: {}",
            generated_at
        );
    }

    #[test]
    fn candidates_include_ppid_and_state_fields() {
        let output = pt_core_fast()
            .args([
                "--format",
                "json",
                "agent",
                "plan",
                "--threshold",
                "0",
                "--max-candidates",
                "5",
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
        let candidates = json
            .get("candidates")
            .and_then(|v| v.as_array())
            .expect("candidates must be an array");

        assert!(
            !candidates.is_empty(),
            "expected at least one candidate at threshold 0"
        );

        for candidate in candidates {
            assert!(
                candidate.get("ppid").is_some(),
                "candidate missing ppid field"
            );
            assert!(
                candidate.get("state").is_some(),
                "candidate missing state field"
            );
        }
    }

    #[test]
    fn candidates_include_policy_fields() {
        let output = pt_core_fast()
            .args([
                "--format",
                "json",
                "agent",
                "plan",
                "--threshold",
                "0",
                "--max-candidates",
                "5",
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
            "summary missing policy_blocked field"
        );
        assert!(
            summary.get("policy_blocked").unwrap().is_number(),
            "summary.policy_blocked should be a number"
        );

        let candidates = json
            .get("candidates")
            .and_then(|v| v.as_array())
            .expect("candidates must be an array");

        assert!(
            !candidates.is_empty(),
            "expected at least one candidate at threshold 0"
        );

        for candidate in candidates {
            assert!(
                candidate.get("policy_blocked").is_some(),
                "candidate missing policy_blocked field"
            );
            let policy = candidate
                .get("policy")
                .expect("candidate missing policy field");
            assert!(policy.is_object(), "candidate.policy should be an object");
            assert!(
                policy.get("allowed").is_some(),
                "candidate.policy.allowed missing"
            );
        }
    }
}

// ============================================================================
// Integration Tests
// ============================================================================

mod plan_integration {
    use super::*;

    #[test]
    fn plan_with_dry_run() {
        pt_core_fast()
            .args([
                "--dry-run",
                "--format",
                "json",
                "agent",
                "plan",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
            .code(predicate::in_iter([0, 1]));
    }

    #[test]
    fn plan_with_robot_mode() {
        pt_core_fast()
            .args([
                "--robot",
                "--format",
                "json",
                "agent",
                "plan",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
            .code(predicate::in_iter([0, 1]));
    }

    #[test]
    fn plan_with_shadow_mode() {
        pt_core_fast()
            .args([
                "--shadow",
                "--format",
                "json",
                "agent",
                "plan",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
            .code(predicate::in_iter([0, 1]));
    }

    #[test]
    fn plan_with_verbose_flag() {
        pt_core_fast()
            .args([
                "-v",
                "--format",
                "json",
                "agent",
                "plan",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
            .code(predicate::in_iter([0, 1]));
    }

    #[test]
    fn plan_with_quiet_flag() {
        pt_core_fast()
            .args([
                "-q",
                "--format",
                "json",
                "agent",
                "plan",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
            .code(predicate::in_iter([0, 1]));
    }

    #[test]
    fn plan_with_standalone_flag() {
        // pt_core_fast already includes --standalone, so just test format
        pt_core_fast()
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
            .code(predicate::in_iter([0, 1]));
    }

    #[test]
    fn consecutive_plans_have_different_session_ids() {
        let output1 = pt_core_fast()
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

        let output2 = pt_core_fast()
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

        let json1: Value = serde_json::from_slice(&output1).unwrap();
        let json2: Value = serde_json::from_slice(&output2).unwrap();

        let id1 = json1.get("session_id").unwrap().as_str().unwrap();
        let id2 = json2.get("session_id").unwrap().as_str().unwrap();

        assert_ne!(id1, id2, "Each plan should have unique session ID");
    }
}

// ============================================================================
// Error Handling Tests
// ============================================================================

mod plan_errors {
    use super::*;

    #[test]
    fn plan_with_invalid_format_fails() {
        pt_core()
            .args(["--format", "invalid_format", "agent", "plan"])
            .assert()
            .failure();
    }

    // NOTE: Threshold validation not yet implemented in stub
    // When implemented, add test for invalid threshold values

    #[test]
    fn plan_help_works() {
        pt_core()
            .args(["agent", "plan", "--help"])
            .assert()
            // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
            .code(predicate::in_iter([0, 1]))
            .stdout(predicate::str::contains("plan"))
            .stdout(predicate::str::contains("threshold"));
    }
}

// ============================================================================
// Inference Safety Tests (wi80)
// ============================================================================
// These tests verify critical safety properties:
// - Kernel threads (PPID 0 or 2) are never in candidates
// - Zombie processes are detected with classification "zombie"
// - Candidates are ranked by max_posterior, not scan order

mod inference_safety {
    use super::*;

    /// Larger sample size for safety tests that need broader coverage
    const SAFETY_SAMPLE_SIZE: &str = "20";

    /// Parse the final JSON plan from stdout (which contains progress events before the plan).
    fn parse_plan_json(output: &[u8]) -> Value {
        // The output is JSONL format with progress events, then the final plan.
        // We need to find the last valid JSON object that contains "candidates".
        let stdout_str = String::from_utf8_lossy(output);

        // Try parsing from the end - the plan is the last multi-line JSON object
        // Look for the final { at start of a line that begins the plan
        for line in stdout_str.lines().rev() {
            if line.trim_start().starts_with('{') {
                if let Ok(json) = serde_json::from_str::<Value>(line) {
                    if json.get("candidates").is_some() || json.get("schema_version").is_some() {
                        return json;
                    }
                }
            }
        }

        // If JSONL parsing fails, try full parse
        serde_json::from_slice(output).expect("Should produce valid JSON")
    }

    #[test]
    fn kernel_threads_never_in_candidates() {
        // Run with high candidate limit to get more coverage
        // Note: Uses sample-size for faster testing; kernel thread filtering happens
        // during scan, not inference, so this still tests the safety property.
        let output = pt_core_fast()
            .args([
                "--format",
                "json",
                "agent",
                "plan",
                "--max-candidates",
                "100",
                "--sample-size",
                SAFETY_SAMPLE_SIZE,
            ])
            .assert()
            .code(predicate::in_iter([0, 1]))
            .get_output()
            .stdout
            .clone();

        let json = parse_plan_json(&output);

        if let Some(candidates) = json.get("candidates").and_then(|c| c.as_array()) {
            for candidate in candidates {
                let ppid = candidate.get("ppid").and_then(|p| p.as_u64());
                let pid = candidate.get("pid").and_then(|p| p.as_u64()).unwrap_or(0);

                if let Some(ppid_val) = ppid {
                    // PID 1 (init) has PPID 0 but is special
                    if pid == 1 {
                        continue;
                    }

                    assert!(
                        ppid_val != 0 && ppid_val != 2,
                        "Kernel thread (PPID {}) found in candidates: PID {} - this should never happen",
                        ppid_val,
                        pid
                    );
                }
            }
        }
    }

    #[test]
    fn zombie_processes_classified_correctly() {
        // Run with high candidate limit
        // Note: This test verifies that IF a zombie is in the sample, it's classified correctly.
        // Sampling doesn't affect the classification logic itself.
        let output = pt_core_fast()
            .args([
                "--format",
                "json",
                "agent",
                "plan",
                "--max-candidates",
                "100",
                "--sample-size",
                SAFETY_SAMPLE_SIZE,
            ])
            .assert()
            .code(predicate::in_iter([0, 1]))
            .get_output()
            .stdout
            .clone();

        let json = parse_plan_json(&output);

        if let Some(candidates) = json.get("candidates").and_then(|c| c.as_array()) {
            for candidate in candidates {
                let state = candidate.get("state").and_then(|s| s.as_str());
                let classification = candidate.get("classification").and_then(|c| c.as_str());

                // If state is "Z" (zombie), classification must be "zombie"
                if state == Some("Z") {
                    assert_eq!(
                        classification,
                        Some("zombie"),
                        "Process with state=Z must have classification=zombie, got {:?}",
                        classification
                    );

                    // Verify zombie posterior is the highest
                    if let Some(posterior) = candidate.get("posterior") {
                        let zombie_post = posterior
                            .get("zombie")
                            .and_then(|z| z.as_f64())
                            .unwrap_or(0.0);
                        let useful_post = posterior
                            .get("useful")
                            .and_then(|z| z.as_f64())
                            .unwrap_or(0.0);
                        let useful_bad_post = posterior
                            .get("useful_bad")
                            .and_then(|z| z.as_f64())
                            .unwrap_or(0.0);
                        let abandoned_post = posterior
                            .get("abandoned")
                            .and_then(|z| z.as_f64())
                            .unwrap_or(0.0);

                        let max_other = useful_post.max(useful_bad_post).max(abandoned_post);
                        assert!(
                            zombie_post >= max_other,
                            "Zombie process should have highest zombie posterior, got zombie={:.4} vs max_other={:.4}",
                            zombie_post, max_other
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn candidates_sorted_by_posterior_descending() {
        let output = pt_core_fast()
            .args([
                "--format",
                "json",
                "agent",
                "plan",
                "--max-candidates",
                "50",
                "--sample-size",
                SAFETY_SAMPLE_SIZE,
            ])
            .assert()
            .code(predicate::in_iter([0, 1]))
            .get_output()
            .stdout
            .clone();

        let json = parse_plan_json(&output);

        if let Some(candidates) = json.get("candidates").and_then(|c| c.as_array()) {
            if candidates.len() < 2 {
                // Not enough candidates to verify sorting
                return;
            }

            // Ranking key: P(abandoned or zombie), i.e. the suspicion the score shows
            // (never max-over-classes, which ranked confidently-useful processes first).
            let mut prev_suspicion: Option<f64> = None;

            for (i, candidate) in candidates.iter().enumerate() {
                if let Some(posterior) = candidate.get("posterior") {
                    let abandoned = posterior
                        .get("abandoned")
                        .and_then(|z| z.as_f64())
                        .unwrap_or(0.0);
                    let zombie = posterior
                        .get("zombie")
                        .and_then(|z| z.as_f64())
                        .unwrap_or(0.0);
                    let suspicion = abandoned + zombie;

                    if let Some(prev) = prev_suspicion {
                        assert!(
                            suspicion <= prev + 0.0001, // Small epsilon for float comparison
                            "Candidates not sorted by P(abandoned or zombie) at index {}: prev={:.4}, curr={:.4}",
                            i, prev, suspicion
                        );
                    }
                    if let Some(score) = candidate.get("score").and_then(|s| s.as_u64()) {
                        assert_eq!(
                            score,
                            (suspicion * 100.0).round() as u64,
                            "score must equal 100 * P(abandoned or zombie)"
                        );
                    }

                    prev_suspicion = Some(suspicion);
                }
            }
        }
    }

    #[test]
    fn protected_filter_stats_in_summary() {
        let output = pt_core_fast()
            .args([
                "--format",
                "json",
                "agent",
                "plan",
                "--sample-size",
                SAFETY_SAMPLE_SIZE,
            ])
            .assert()
            .code(predicate::in_iter([0, 1]))
            .get_output()
            .stdout
            .clone();

        let json = parse_plan_json(&output);

        if let Some(summary) = json.get("summary") {
            // Verify protected_filtered is present and parseable as an unsigned count
            if let Some(filtered) = summary.get("protected_filtered") {
                assert!(
                    filtered.as_u64().is_some(),
                    "protected_filtered should be u64-compatible, got {filtered:?}"
                );
            }

            // Verify total_processes_scanned is reasonable
            if let Some(total) = summary
                .get("total_processes_scanned")
                .and_then(|t| t.as_u64())
            {
                assert!(
                    total > 0,
                    "total_processes_scanned should be positive, got {}",
                    total
                );
            }
        }
    }

    #[test]
    fn candidate_json_has_required_fields() {
        let output = pt_core_fast()
            .args([
                "--format",
                "json",
                "agent",
                "plan",
                "--max-candidates",
                "10",
                "--sample-size",
                SAFETY_SAMPLE_SIZE,
            ])
            .assert()
            .code(predicate::in_iter([0, 1]))
            .get_output()
            .stdout
            .clone();

        let json = parse_plan_json(&output);

        if let Some(candidates) = json.get("candidates").and_then(|c| c.as_array()) {
            for (i, candidate) in candidates.iter().enumerate() {
                // Required fields from smiw fix
                assert!(
                    candidate.get("pid").is_some(),
                    "Candidate {} missing pid field",
                    i
                );
                assert!(
                    candidate.get("ppid").is_some(),
                    "Candidate {} missing ppid field (needed for kernel thread filtering verification)", i
                );
                assert!(
                    candidate.get("state").is_some(),
                    "Candidate {} missing state field (needed for zombie detection verification)",
                    i
                );
                assert!(
                    candidate.get("user").is_some(),
                    "Candidate {} missing user field",
                    i
                );
                assert!(
                    candidate.get("posterior").is_some(),
                    "Candidate {} missing posterior field",
                    i
                );
                assert!(
                    candidate.get("classification").is_some(),
                    "Candidate {} missing classification field",
                    i
                );
            }
        }
    }
}

/// Age of `pid` in seconds from /proc (the kernel's own start ticks + btime): an
/// independent check on the ages the plan reports.
#[cfg(target_os = "linux")]
fn proc_age_seconds(pid: u32) -> f64 {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).expect("stat");
    let after_comm = stat.rsplit_once(')').expect("comm").1;
    // After ")": state is field 3 overall; starttime is field 22 -> index 19 here.
    let start_ticks: f64 = after_comm
        .split_whitespace()
        .nth(19)
        .unwrap()
        .parse()
        .unwrap();
    let btime: f64 = std::fs::read_to_string("/proc/stat")
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix("btime "))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    // SAFETY: sysconf has no preconditions.
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as f64;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    now - (btime + start_ticks / hz)
}

/// blast_radius.child_count is the real number of direct children (it was a
/// hard-coded 0).
#[cfg(unix)]
#[test]
fn plan_blast_radius_counts_real_children() {
    let mut parent = std::process::Command::new("sh")
        .args(["-c", "sleep 60 & sleep 60 & wait"])
        .spawn()
        .expect("spawn parent");
    let pid = parent.id();
    std::thread::sleep(Duration::from_millis(500));
    let data_dir = tempdir().expect("data dir");
    let output = pt_core()
        .env("PROCESS_TRIAGE_DATA", data_dir.path())
        .env("PROCESS_TRIAGE_RETENTION", "off")
        .args([
            "--format",
            "json",
            "agent",
            "plan",
            "--min-age",
            "0",
            "--min-posterior",
            "0",
            "--max-candidates",
            "100000",
        ])
        .output()
        .expect("run plan");
    // Kill the sleeps (children of sh) and sh itself.
    let _ = std::process::Command::new("pkill")
        .args(["-P", &pid.to_string()])
        .status();
    let _ = parent.kill();
    let _ = parent.wait();

    let json: Value = serde_json::from_slice(&output.stdout).expect("plan JSON");
    let candidate = json["candidates"]
        .as_array()
        .expect("candidates")
        .iter()
        .find(|c| c["pid"].as_u64() == Some(u64::from(pid)))
        .unwrap_or_else(|| panic!("pid {pid} not in plan"))
        .clone();
    assert_eq!(candidate["blast_radius"]["child_count"], 2, "{candidate}");
}

/// A candidate's age in the plan equals the kernel's start time, to the second.
#[cfg(target_os = "linux")]
#[test]
fn plan_age_matches_proc_start_time() {
    let mut child = std::process::Command::new("sleep")
        .arg("120")
        .spawn()
        .expect("spawn sleep");
    let pid = child.id();
    std::thread::sleep(Duration::from_secs(3));
    let data_dir = tempdir().expect("data dir");

    let before = proc_age_seconds(pid);
    let output = pt_core()
        .env("PROCESS_TRIAGE_DATA", data_dir.path())
        .env("PROCESS_TRIAGE_RETENTION", "off")
        .args([
            "--format",
            "json",
            "agent",
            "plan",
            "--min-age",
            "0",
            "--min-posterior",
            "0",
            "--max-candidates",
            "100000",
        ])
        .output()
        .expect("run plan");
    let after = proc_age_seconds(pid);
    let _ = child.kill();
    let _ = child.wait();

    let json: Value = serde_json::from_slice(&output.stdout).expect("plan JSON");
    let candidate = json["candidates"]
        .as_array()
        .expect("candidates")
        .iter()
        .find(|c| c["pid"].as_u64() == Some(u64::from(pid)))
        .unwrap_or_else(|| panic!("pid {pid} not in plan"))
        .clone();
    let age = candidate["age_seconds"].as_f64().expect("age_seconds");
    assert!(
        age >= before.floor() - 1.0 && age <= after.ceil() + 1.0,
        "plan age {age} outside /proc age window [{before:.2}, {after:.2}]"
    );
}

/// `agent plan --deep` feeds deep-scan evidence into the posterior: a process
/// holding a TCP connection gets a `net` ledger term, which the quick scan
/// cannot see.
#[cfg(target_os = "linux")]
#[test]
fn plan_deep_adds_network_evidence() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    // bash opens fd 3 to the listener, then execs sleep, which inherits it.
    let mut child = std::process::Command::new("bash")
        .args([
            "-c",
            &format!("exec 3<>/dev/tcp/127.0.0.1/{port}; exec sleep 120"),
        ])
        .spawn()
        .expect("spawn bash");
    let pid = child.id();
    let _conn = listener.accept().expect("accept");
    std::thread::sleep(Duration::from_millis(500));
    let data_dir = tempdir().expect("data dir");

    let plan = |deep: bool| -> Value {
        let mut args = vec![
            "--format",
            "json",
            "agent",
            "plan",
            "--min-age",
            "0",
            "--min-posterior",
            "0",
            "--max-candidates",
            "100000",
        ];
        if deep {
            args.push("--deep");
        }
        let output = pt_core()
            .env("PROCESS_TRIAGE_DATA", data_dir.path())
            .env("PROCESS_TRIAGE_RETENTION", "off")
            .args(&args)
            .output()
            .expect("run plan");
        serde_json::from_slice(&output.stdout).expect("plan JSON")
    };
    let factors = |json: &Value| -> Vec<String> {
        json["candidates"]
            .as_array()
            .expect("candidates")
            .iter()
            .find(|c| c["pid"].as_u64() == Some(u64::from(pid)))
            .unwrap_or_else(|| panic!("pid {pid} not in plan"))["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .filter_map(|e| e["factor"].as_str().map(String::from))
            .collect()
    };

    let quick = plan(false);
    let deep = plan(true);
    let _ = child.kill();
    let _ = child.wait();

    assert!(
        !factors(&quick).contains(&"net".to_string()),
        "quick plan has no network evidence: {:?}",
        factors(&quick)
    );
    assert!(
        factors(&deep).contains(&"net".to_string()),
        "deep plan should carry a net term: {:?}",
        factors(&deep)
    );
    assert!(quick["summary"]["deep_scan_ms"].is_null());
    assert!(
        deep["summary"]["deep_scan_ms"].is_u64(),
        "{}",
        deep["summary"]
    );
    assert!(
        deep["summary"]["deep_coverage"]["net"]
            .as_u64()
            .unwrap_or(0)
            > 0,
        "{}",
        deep["summary"]
    );
    assert!(
        deep["summary"]["deep_evidence_pids"].as_u64().unwrap_or(0) > 0,
        "{}",
        deep["summary"]
    );
}

/// A real zombie is never reniced/killed/paused: the plan routes it to its parent.
#[cfg(target_os = "linux")]
#[test]
fn plan_routes_zombie_to_parent() {
    // sh forks `sleep 0`, then execs `sleep 120`, which never reaps it.
    let mut parent = std::process::Command::new("sh")
        .args(["-c", "sleep 0 & exec sleep 120"])
        .spawn()
        .expect("spawn parent");
    let parent_pid = parent.id();
    std::thread::sleep(Duration::from_secs(1));
    let data_dir = tempdir().expect("data dir");
    let output = pt_core()
        .env("PROCESS_TRIAGE_DATA", data_dir.path())
        .env("PROCESS_TRIAGE_RETENTION", "off")
        .args([
            "--format",
            "json",
            "agent",
            "plan",
            "--min-age",
            "0",
            "--min-posterior",
            "0",
            "--max-candidates",
            "100000",
        ])
        .output()
        .expect("run plan");
    let _ = parent.kill();
    let _ = parent.wait();

    let json: Value = serde_json::from_slice(&output.stdout).expect("plan JSON");
    let zombie = json["candidates"]
        .as_array()
        .expect("candidates")
        .iter()
        .find(|c| c["ppid"].as_u64() == Some(u64::from(parent_pid)))
        .unwrap_or_else(|| panic!("zombie child of {parent_pid} not in plan"))
        .clone();
    assert!(
        zombie["state"].as_str().unwrap_or("").starts_with('Z'),
        "{zombie}"
    );
    let routing = &zombie["zombie_routing"];
    assert_eq!(routing["route_to"], "parent", "{zombie}");
    assert_eq!(routing["parent_pid"], parent_pid, "{zombie}");
    assert_eq!(routing["parent_comm"], "sleep", "{zombie}");
    let rec = zombie["recommendation"].as_str().unwrap_or("");
    assert!(
        ![
            "KILL",
            "RENICE",
            "PAUSE",
            "FREEZE",
            "THROTTLE",
            "QUARANTINE"
        ]
        .contains(&rec),
        "zombie got a direct action {rec}: {zombie}"
    );
    // A live process has no routing block.
    let parent_candidate = json["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["pid"].as_u64() == Some(u64::from(parent_pid)));
    if let Some(p) = parent_candidate {
        assert!(p["zombie_routing"].is_null(), "{p}");
    }
}

/// The plan runs the same data-loss check apply does: with kill made the cheapest
/// action, a process holding a regular file open for writing is policy-blocked in
/// the plan, and one with stdio on /dev/null is not.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn plan_blocks_kill_of_open_writer() {
    let config_dir = tempdir().expect("config dir");
    let mut policy = pt_core::config::Policy::default();
    for row in [
        &mut policy.loss_matrix.useful,
        &mut policy.loss_matrix.useful_bad,
        &mut policy.loss_matrix.abandoned,
        &mut policy.loss_matrix.zombie,
    ] {
        row.keep = 10.0;
        row.kill = 0.0;
    }
    policy.guardrails.min_process_age_seconds = 0;
    std::fs::write(
        config_dir.path().join("policy.json"),
        serde_json::to_vec_pretty(&policy).expect("serialize policy"),
    )
    .expect("write policy.json");

    let file_dir = tempdir().expect("file dir");
    let log = file_dir.path().join("journal.log");
    let spawn = |script: String| {
        std::process::Command::new("sh")
            .args(["-c", &script])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn")
    };
    let mut writer = spawn(format!("exec sleep 305 3>>'{}'", log.display()));
    let mut idle = spawn("exec sleep 306".to_string());
    std::thread::sleep(Duration::from_millis(500));

    let data_dir = tempdir().expect("data dir");
    let output = pt_core()
        .env("PROCESS_TRIAGE_DATA", data_dir.path())
        .env("PROCESS_TRIAGE_CONFIG", config_dir.path())
        .env("PROCESS_TRIAGE_RETENTION", "off")
        .args([
            "--format",
            "json",
            "agent",
            "plan",
            "--min-age",
            "0",
            "--min-posterior",
            "0",
            "--max-candidates",
            "100000",
        ])
        .output()
        .expect("run plan");
    let _ = writer.kill();
    let _ = writer.wait();
    let _ = idle.kill();
    let _ = idle.wait();

    let json: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "plan JSON ({e}); stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    let candidate = |pid: u32| -> Value {
        json["candidates"]
            .as_array()
            .expect("candidates")
            .iter()
            .find(|c| c["pid"].as_u64() == Some(u64::from(pid)))
            .unwrap_or_else(|| panic!("pid {pid} not in plan"))
            .clone()
    };
    let w = candidate(writer.id());
    assert_eq!(w["policy"]["allowed"], false, "{w}");
    assert_eq!(
        w["policy"]["violation"]["rule"], "data_loss_gates.block_if_open_write_fds",
        "{w}"
    );
    let i = candidate(idle.id());
    assert_ne!(
        i["policy"]["violation"]["rule"], "data_loss_gates.block_if_open_write_fds",
        "{i}"
    );
}

/// An agent CLI is identified in the plan (`agent_kind`) and never gets an
/// automatic action.
#[cfg(unix)]
#[test]
fn plan_identifies_agent_cli_kind() {
    // argv[0] = "claude": looks like a Claude Code session to pt.
    let mut agent = std::process::Command::new("bash")
        .args(["-c", "exec -a claude sleep 120"])
        .spawn()
        .expect("spawn agent lookalike");
    let pid = agent.id();
    std::thread::sleep(Duration::from_millis(500));
    let data_dir = tempdir().expect("data dir");
    let output = pt_core()
        .env("PROCESS_TRIAGE_DATA", data_dir.path())
        .env("PROCESS_TRIAGE_RETENTION", "off")
        .args([
            "--format",
            "json",
            "agent",
            "plan",
            "--min-age",
            "0",
            "--min-posterior",
            "0",
            "--max-candidates",
            "100000",
        ])
        .output()
        .expect("run plan");
    let _ = agent.kill();
    let _ = agent.wait();

    let json: Value = serde_json::from_slice(&output.stdout).expect("plan JSON");
    let c = json["candidates"]
        .as_array()
        .expect("candidates")
        .iter()
        .find(|c| c["pid"].as_u64() == Some(u64::from(pid)))
        .unwrap_or_else(|| panic!("pid {pid} not in plan"))
        .clone();
    assert_eq!(c["agent_kind"], "claude", "{c}");
    let rec = c["recommendation"].as_str().unwrap_or("");
    assert!(matches!(rec, "KEEP" | "REVIEW"), "agent got {rec}: {c}");
    // No controlling terminal: no liveness evidence.
    assert_eq!(c["agent_liveness"]["live"], false, "{c}");
}

/// An agent CLI on a terminal with recent I/O is live: kept, not surfaced for review.
#[cfg(target_os = "linux")]
#[test]
fn plan_keeps_agent_with_active_terminal() {
    // `script` gives the lookalike a real pty (just created, so recently active).
    // Its stdin stays an open pipe: at EOF `script` would end the pty session and
    // the lookalike would lose its terminal.
    let mut agent = std::process::Command::new("script")
        // 137: distinct from plan_identifies_agent_cli_kind's lookalike (runs in parallel)
        .args(["-qc", "exec -a claude sleep 137", "/dev/null"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("spawn script");
    let _stdin = agent.stdin.take();
    std::thread::sleep(Duration::from_millis(800));
    let data_dir = tempdir().expect("data dir");
    let output = pt_core()
        .env("PROCESS_TRIAGE_DATA", data_dir.path())
        .env("PROCESS_TRIAGE_RETENTION", "off")
        .args([
            "--format",
            "json",
            "agent",
            "plan",
            "--min-age",
            "0",
            "--min-posterior",
            "0",
            "--max-candidates",
            "100000",
        ])
        .output()
        .expect("run plan");
    let _ = std::process::Command::new("pkill")
        .args(["-P", &agent.id().to_string()])
        .status();
    let _ = agent.kill();
    let _ = agent.wait();

    let json: Value = serde_json::from_slice(&output.stdout).expect("plan JSON");
    let c = json["candidates"]
        .as_array()
        .expect("candidates")
        .iter()
        .find(|c| {
            c["agent_kind"] == "claude"
                && c["command"]
                    .as_str()
                    .unwrap_or("")
                    .starts_with("claude 137")
        })
        .unwrap_or_else(|| panic!("agent lookalike not in plan"))
        .clone();
    assert_eq!(c["agent_liveness"]["live"], true, "{c}");
    assert!(
        c["agent_liveness"]["tty"]
            .as_str()
            .unwrap_or("")
            .contains("pts"),
        "{c}"
    );
    assert_eq!(c["recommendation"], "KEEP", "{c}");
}
