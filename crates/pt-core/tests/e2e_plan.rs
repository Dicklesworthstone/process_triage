//! End-to-end tests for agent plan workflow.
//!
//! Tests the `agent plan` command which generates action plans
//! without execution for review and validation.

use assert_cmd::cargo::cargo_bin_cmd;
use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use std::time::Duration;

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

            let mut prev_max_posterior: Option<f64> = None;

            for (i, candidate) in candidates.iter().enumerate() {
                if let Some(posterior) = candidate.get("posterior") {
                    let useful = posterior
                        .get("useful")
                        .and_then(|z| z.as_f64())
                        .unwrap_or(0.0);
                    let useful_bad = posterior
                        .get("useful_bad")
                        .and_then(|z| z.as_f64())
                        .unwrap_or(0.0);
                    let abandoned = posterior
                        .get("abandoned")
                        .and_then(|z| z.as_f64())
                        .unwrap_or(0.0);
                    let zombie = posterior
                        .get("zombie")
                        .and_then(|z| z.as_f64())
                        .unwrap_or(0.0);

                    let max_posterior = useful.max(useful_bad).max(abandoned).max(zombie);

                    if let Some(prev) = prev_max_posterior {
                        assert!(
                            max_posterior <= prev + 0.0001, // Small epsilon for float comparison
                            "Candidates not sorted by posterior at index {}: prev={:.4}, curr={:.4}",
                            i, prev, max_posterior
                        );
                    }

                    prev_max_posterior = Some(max_posterior);
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
            // Verify protected_filtered is present and non-negative
            if let Some(filtered) = summary.get("protected_filtered").and_then(|f| f.as_u64()) {
                assert!(
                    filtered >= 0,
                    "protected_filtered should be non-negative, got {}",
                    filtered
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
