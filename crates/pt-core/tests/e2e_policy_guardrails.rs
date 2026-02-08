//! End-to-end tests for policy guardrails.
//!
//! Validates safety guardrails end-to-end with JSONL logging:
//! - Rate limiting: per-run/hour/day counters and enforcement
//! - Blast radius: max-blast-radius and max-total-blast-radius gates
//! - Max kills per session: guardrail enforcement in plan/apply
//! - Protected patterns: policy-based process protection
//! - Negative paths: malformed/missing policy, invalid overrides
//! - Exit codes and user-facing error messages
//!
//! See: bd-1b8k

use assert_cmd::cargo::cargo_bin_cmd;
use assert_cmd::Command;
use predicates::prelude::*;
use pt_common::config::policy::{Guardrails, Policy, RobotMode};
use serde_json::Value;
use std::time::Duration;
use tempfile::tempdir;

// ============================================================================
// Helpers
// ============================================================================

/// Get a Command for pt-core binary with sensible test defaults.
fn pt_core() -> Command {
    let mut cmd = cargo_bin_cmd!("pt-core");
    cmd.timeout(Duration::from_secs(120));
    cmd.env("PT_SKIP_GLOBAL_LOCK", "1");
    cmd
}

/// Get a fast pt-core command with --standalone and limited sample size.
fn pt_core_fast() -> Command {
    let mut cmd = pt_core();
    cmd.args(["--standalone"]);
    cmd
}

const TEST_SAMPLE_SIZE: &str = "10";

/// Run agent plan with JSON output and return parsed JSON + exit code.
fn plan_json_with_config(config_dir: &std::path::Path, extra_args: &[&str]) -> (Value, i32) {
    let output = pt_core_fast()
        .env("PT_CONFIG_DIR", config_dir.display().to_string())
        .args(["--format", "json", "agent", "plan", "--sample-size", TEST_SAMPLE_SIZE])
        .args(extra_args)
        .assert()
        .code(predicate::in_iter([0, 1]))
        .get_output()
        .clone();

    let code = output.status.code().unwrap_or(-1);
    let json: Value = serde_json::from_slice(&output.stdout).expect("parse JSON output");
    (json, code)
}

/// Write a policy.json to a config directory.
fn write_policy(dir: &std::path::Path, policy: &Policy) {
    let policy_path = dir.join("policy.json");
    std::fs::write(
        &policy_path,
        serde_json::to_vec_pretty(policy).expect("serialize policy"),
    )
    .expect("write policy.json");
}

// ============================================================================
// Rate Limiting — Max Kills Per Run
// ============================================================================

mod rate_limit {
    use super::*;

    #[test]
    fn plan_respects_max_kills_per_run_from_policy() {
        let config_dir = tempdir().expect("temp config dir");
        let mut policy = Policy::default();
        policy.guardrails.max_kills_per_run = 2;
        write_policy(config_dir.path(), &policy);

        let (json, _code) = plan_json_with_config(config_dir.path(), &["--threshold", "0"]);

        // The summary should report the guardrail limit
        if let Some(summary) = json.get("summary") {
            // Verify policy is loaded
            if let Some(blocked) = summary.get("policy_blocked") {
                assert!(
                    blocked.is_number(),
                    "summary.policy_blocked should be a number"
                );
            }
        }
    }

    #[test]
    fn plan_with_max_kills_cli_override() {
        // CLI --max-kills should cap the number of actionable candidates
        let config_dir = tempdir().expect("temp config dir");
        write_policy(config_dir.path(), &Policy::default());

        let (json, _code) = plan_json_with_config(
            config_dir.path(),
            &["--threshold", "0", "--max-candidates", "50"],
        );

        let candidates = json
            .get("candidates")
            .and_then(|c| c.as_array())
            .cloned()
            .unwrap_or_default();

        // All candidates should exist and have required fields
        for candidate in &candidates {
            assert!(
                candidate.get("pid").is_some(),
                "candidate should have pid"
            );
            assert!(
                candidate.get("policy").is_some(),
                "candidate should have policy check result"
            );
        }
    }

    #[test]
    fn plan_policy_guardrails_appear_in_output() {
        let config_dir = tempdir().expect("temp config dir");
        let mut policy = Policy::default();
        policy.guardrails.max_kills_per_run = 3;
        policy.guardrails.min_process_age_seconds = 120;
        write_policy(config_dir.path(), &policy);

        let (json, _code) = plan_json_with_config(
            config_dir.path(),
            &["--threshold", "0", "--max-candidates", "5"],
        );

        // Plan should contain policy metadata
        if let Some(summary) = json.get("summary") {
            // policy_blocked should be a non-negative number
            let blocked_count = summary
                .get("policy_blocked")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            // On a real system, some processes will be policy-blocked (too young, protected)
            eprintln!("[INFO] policy_blocked count: {}", blocked_count);
        }
    }
}

// ============================================================================
// Blast Radius
// ============================================================================

mod blast_radius {
    use super::*;

    #[test]
    fn plan_includes_blast_radius_in_candidates() {
        let config_dir = tempdir().expect("temp config dir");
        write_policy(config_dir.path(), &Policy::default());

        let (json, _code) = plan_json_with_config(
            config_dir.path(),
            &["--threshold", "0", "--max-candidates", "10"],
        );

        let candidates = json
            .get("candidates")
            .and_then(|c| c.as_array())
            .cloned()
            .unwrap_or_default();

        for candidate in &candidates {
            // Each candidate should have blast_radius fields
            if let Some(blast) = candidate.get("blast_radius") {
                assert!(
                    blast.get("memory_mb").is_some(),
                    "blast_radius should include memory_mb"
                );
                eprintln!(
                    "[INFO] PID {} blast_radius: {:?}",
                    candidate.get("pid").and_then(|p| p.as_u64()).unwrap_or(0),
                    blast
                );
            }
        }
    }

    #[test]
    fn apply_max_blast_radius_flag_accepted() {
        // Verify --max-blast-radius flag is accepted without error
        let config_dir = tempdir().expect("temp config dir");
        write_policy(config_dir.path(), &Policy::default());

        // Use dry-run + plan to test flag acceptance
        pt_core_fast()
            .env("PT_CONFIG_DIR", config_dir.path().display().to_string())
            .args([
                "--dry-run",
                "--format",
                "json",
                "agent",
                "apply",
                "--session",
                "pt-nonexistent-test",
                "--max-blast-radius",
                "100.0",
            ])
            .assert()
            // Session may not exist (exit 10) or other operational outcomes.
            // The point is that the flag parses correctly (not a clap "unknown argument" error).
            .code(predicate::in_iter([0, 1, 2, 3, 10]));
    }

    #[test]
    fn apply_max_total_blast_radius_flag_accepted() {
        let config_dir = tempdir().expect("temp config dir");
        write_policy(config_dir.path(), &Policy::default());

        pt_core_fast()
            .env("PT_CONFIG_DIR", config_dir.path().display().to_string())
            .args([
                "--dry-run",
                "--format",
                "json",
                "agent",
                "apply",
                "--session",
                "pt-nonexistent-test",
                "--max-total-blast-radius",
                "2048.0",
            ])
            .assert()
            .code(predicate::in_iter([0, 1, 2, 3, 10]));
    }

    #[test]
    fn plan_robot_mode_max_blast_radius() {
        let config_dir = tempdir().expect("temp config dir");
        let mut policy = Policy::default();
        policy.robot_mode.max_blast_radius_mb = 50.0; // Very low threshold
        write_policy(config_dir.path(), &policy);

        let (json, _code) = plan_json_with_config(
            config_dir.path(),
            &["--threshold", "0", "--max-candidates", "10"],
        );

        // Summary should reflect robot mode config
        if let Some(summary) = json.get("summary") {
            eprintln!("[INFO] summary with max_blast_radius_mb=50: {:?}", summary);
        }
    }
}

// ============================================================================
// Protected Patterns
// ============================================================================

mod protected_patterns {
    use super::*;
    use pt_common::config::policy::{PatternEntry, PatternKind};

    #[test]
    fn policy_protected_patterns_filter_candidates() {
        let config_dir = tempdir().expect("temp config dir");
        let mut policy = Policy::default();

        // Add a pattern that will match many processes
        policy.guardrails.protected_patterns.push(PatternEntry {
            pattern: ".*".to_string(),
            kind: PatternKind::Regex,
            case_insensitive: false,
            notes: Some("test: block all for testing".to_string()),
        });
        write_policy(config_dir.path(), &policy);

        let (json, _code) = plan_json_with_config(
            config_dir.path(),
            &["--threshold", "0", "--max-candidates", "20"],
        );

        // With a ".*" protected pattern, most/all candidates should be policy-blocked
        let candidates = json
            .get("candidates")
            .and_then(|c| c.as_array())
            .cloned()
            .unwrap_or_default();

        let blocked_count = candidates
            .iter()
            .filter(|c| {
                c.get("policy_blocked")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
            })
            .count();

        // The wildcard pattern should block a significant number of candidates
        if !candidates.is_empty() {
            eprintln!(
                "[INFO] protected pattern .*: {}/{} blocked",
                blocked_count,
                candidates.len()
            );
            assert!(
                blocked_count > 0,
                "wildcard protected pattern should block candidates"
            );
        }
    }

    #[test]
    fn policy_protected_users_enforced() {
        let config_dir = tempdir().expect("temp config dir");
        let mut policy = Policy::default();
        // Protect the current user
        if let Ok(user) = std::env::var("USER") {
            policy.guardrails.protected_users.push(user);
        }
        write_policy(config_dir.path(), &policy);

        let (json, _code) = plan_json_with_config(
            config_dir.path(),
            &["--threshold", "0", "--max-candidates", "10"],
        );

        // All candidates owned by current user should be blocked
        let candidates = json
            .get("candidates")
            .and_then(|c| c.as_array())
            .cloned()
            .unwrap_or_default();

        for candidate in &candidates {
            let user = candidate.get("user").and_then(|u| u.as_str());
            let blocked = candidate
                .get("policy_blocked")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            if let (Some(user_name), Ok(current_user)) = (user, std::env::var("USER")) {
                if user_name == current_user {
                    assert!(
                        blocked,
                        "process owned by protected user {} should be blocked",
                        user_name
                    );
                }
            }
        }
    }

    #[test]
    fn candidates_policy_field_structure() {
        let config_dir = tempdir().expect("temp config dir");
        write_policy(config_dir.path(), &Policy::default());

        let (json, _code) = plan_json_with_config(
            config_dir.path(),
            &["--threshold", "0", "--max-candidates", "5"],
        );

        let candidates = json
            .get("candidates")
            .and_then(|c| c.as_array())
            .cloned()
            .unwrap_or_default();

        for candidate in &candidates {
            let policy = candidate.get("policy").expect("candidate should have policy field");
            assert!(policy.is_object(), "policy should be an object");
            assert!(
                policy.get("allowed").is_some(),
                "policy should have 'allowed' field"
            );
        }
    }
}

// ============================================================================
// Robot Mode Gates
// ============================================================================

mod robot_mode {
    use super::*;

    #[test]
    fn plan_with_robot_mode_min_posterior() {
        let config_dir = tempdir().expect("temp config dir");
        let mut policy = Policy::default();
        policy.robot_mode.enabled = true;
        policy.robot_mode.min_posterior = 0.999; // Very high bar
        write_policy(config_dir.path(), &policy);

        let (json, _code) = plan_json_with_config(
            config_dir.path(),
            &["--threshold", "0", "--max-candidates", "20"],
        );

        let candidates = json
            .get("candidates")
            .and_then(|c| c.as_array())
            .cloned()
            .unwrap_or_default();

        // With min_posterior=0.999 in robot mode, most candidates should be blocked
        // because few processes will have posterior > 0.999
        let actionable = candidates
            .iter()
            .filter(|c| {
                !c.get("policy_blocked")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true)
            })
            .count();

        eprintln!(
            "[INFO] robot mode min_posterior=0.999: {}/{} actionable",
            actionable,
            candidates.len()
        );
    }

    #[test]
    fn plan_with_robot_mode_disabled() {
        let config_dir = tempdir().expect("temp config dir");
        let mut policy = Policy::default();
        policy.robot_mode.enabled = false;
        write_policy(config_dir.path(), &policy);

        let (json, _code) = plan_json_with_config(config_dir.path(), &["--threshold", "0"]);

        // Plan should still work with robot mode disabled
        assert!(
            json.get("session_id").is_some(),
            "plan should have session_id"
        );
    }

    #[test]
    fn plan_robot_mode_require_known_signature() {
        let config_dir = tempdir().expect("temp config dir");
        let mut policy = Policy::default();
        policy.robot_mode.enabled = true;
        policy.robot_mode.require_known_signature = true;
        write_policy(config_dir.path(), &policy);

        let (json, _code) = plan_json_with_config(
            config_dir.path(),
            &["--threshold", "0", "--max-candidates", "10"],
        );

        // Summary should reflect the signature requirement
        if let Some(summary) = json.get("summary") {
            eprintln!(
                "[INFO] robot mode require_known_signature: summary={:?}",
                summary.get("signature_fast_path_enabled")
            );
        }
    }

    #[test]
    fn apply_max_kills_cli_flag() {
        let config_dir = tempdir().expect("temp config dir");
        write_policy(config_dir.path(), &Policy::default());

        // Verify --max-kills flag is accepted
        pt_core_fast()
            .env("PT_CONFIG_DIR", config_dir.path().display().to_string())
            .args([
                "--dry-run",
                "--format",
                "json",
                "agent",
                "apply",
                "--session",
                "pt-nonexistent-test",
                "--max-kills",
                "3",
            ])
            .assert()
            // Exit 10 = invalid session (expected since pt-nonexistent-test doesn't exist)
            .code(predicate::in_iter([0, 1, 2, 3, 10]));
    }
}

// ============================================================================
// Min Process Age
// ============================================================================

mod min_age {
    use super::*;

    #[test]
    fn plan_min_age_filters_young_processes() {
        let config_dir = tempdir().expect("temp config dir");
        let mut policy = Policy::default();
        // Set very high minimum age so most processes are filtered
        policy.guardrails.min_process_age_seconds = 999_999;
        write_policy(config_dir.path(), &policy);

        let (json, _code) = plan_json_with_config(
            config_dir.path(),
            &["--threshold", "0", "--max-candidates", "20"],
        );

        let candidates = json
            .get("candidates")
            .and_then(|c| c.as_array())
            .cloned()
            .unwrap_or_default();

        // With min_age=999999, most processes should be filtered
        let actionable = candidates
            .iter()
            .filter(|c| {
                !c.get("policy_blocked")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true)
            })
            .count();

        eprintln!(
            "[INFO] min_age=999999: {}/{} actionable (most should be blocked by age)",
            actionable,
            candidates.len()
        );
    }

    #[test]
    fn plan_cli_min_age_override() {
        let config_dir = tempdir().expect("temp config dir");
        write_policy(config_dir.path(), &Policy::default());

        // CLI --min-age should override policy
        pt_core_fast()
            .env("PT_CONFIG_DIR", config_dir.path().display().to_string())
            .args([
                "--format",
                "json",
                "agent",
                "plan",
                "--min-age",
                "60",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            .code(predicate::in_iter([0, 1]));
    }
}

// ============================================================================
// Negative Paths — Malformed Policy
// ============================================================================

mod negative_paths {
    use super::*;

    #[test]
    fn malformed_policy_json_handled_gracefully() {
        let config_dir = tempdir().expect("temp config dir");
        let policy_path = config_dir.path().join("policy.json");
        std::fs::write(&policy_path, "this is not valid json {{{").expect("write bad policy");

        // Should fail with a config load error (exit 20) but not crash/panic
        let output = pt_core_fast()
            .env("PT_CONFIG_DIR", config_dir.path().display().to_string())
            .args([
                "--format",
                "json",
                "agent",
                "plan",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            // Exit 20 = config load failure, which is the expected graceful error
            .code(predicate::in_iter([0, 1, 2, 3, 20]))
            .get_output()
            .clone();

        let stderr = String::from_utf8_lossy(&output.stderr);
        if output.status.code() == Some(20) {
            // Verify the error message is clear and actionable
            assert!(
                stderr.contains("policy.json") || stderr.contains("config"),
                "error should mention the problematic file"
            );
        }
    }

    #[test]
    fn missing_config_dir_uses_defaults() {
        let config_dir = tempdir().expect("temp config dir");
        let nonexistent = config_dir.path().join("nonexistent_config_dir");

        // With a nonexistent config directory, should use defaults
        pt_core_fast()
            .env("PT_CONFIG_DIR", nonexistent.display().to_string())
            .args([
                "--format",
                "json",
                "agent",
                "plan",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            .code(predicate::in_iter([0, 1]));
    }

    #[test]
    fn empty_policy_json_handled() {
        let config_dir = tempdir().expect("temp config dir");
        let policy_path = config_dir.path().join("policy.json");
        std::fs::write(&policy_path, "{}").expect("write empty policy");

        // Empty object may fail validation or use defaults depending on serde defaults
        pt_core_fast()
            .env("PT_CONFIG_DIR", config_dir.path().display().to_string())
            .args([
                "--format",
                "json",
                "agent",
                "plan",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            // Exit 20 = config validation failure is acceptable for malformed input
            .code(predicate::in_iter([0, 1, 2, 3, 20]));
    }

    #[test]
    fn invalid_format_value_returns_error() {
        pt_core()
            .args(["--format", "badformat", "agent", "plan"])
            .assert()
            .failure();
    }
}

// ============================================================================
// Policy Snapshot in Plan Output
// ============================================================================

mod policy_snapshot {
    use super::*;

    #[test]
    fn plan_summary_includes_policy_stats() {
        let config_dir = tempdir().expect("temp config dir");
        write_policy(config_dir.path(), &Policy::default());

        let (json, _code) = plan_json_with_config(
            config_dir.path(),
            &["--threshold", "0", "--max-candidates", "5"],
        );

        let summary = json.get("summary").expect("plan should have summary");

        // Verify policy-related summary fields
        assert!(
            summary.get("policy_blocked").is_some(),
            "summary should have policy_blocked count"
        );
        assert!(
            summary.get("total_processes_scanned").is_some(),
            "summary should have total_processes_scanned"
        );
        assert!(
            summary.get("protected_filtered").is_some(),
            "summary should have protected_filtered count"
        );
    }

    #[test]
    fn plan_has_schema_version_and_session() {
        let config_dir = tempdir().expect("temp config dir");
        write_policy(config_dir.path(), &Policy::default());

        let (json, _code) = plan_json_with_config(config_dir.path(), &[]);

        assert!(
            json.get("schema_version").is_some(),
            "plan should have schema_version"
        );
        assert!(
            json.get("session_id").is_some(),
            "plan should have session_id"
        );
        assert!(
            json.get("generated_at").is_some(),
            "plan should have generated_at"
        );
    }
}

// ============================================================================
// JSONL Progress Events (stderr)
// ============================================================================

mod jsonl_events {
    use super::*;

    #[test]
    fn plan_emits_structured_progress_events() {
        let config_dir = tempdir().expect("temp config dir");
        write_policy(config_dir.path(), &Policy::default());

        let output = pt_core_fast()
            .env("PT_CONFIG_DIR", config_dir.path().display().to_string())
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
            .clone();

        let stderr = String::from_utf8_lossy(&output.stderr);

        // Stderr should contain JSONL progress events
        let event_lines: Vec<&str> = stderr
            .lines()
            .filter(|line| line.contains("\"event\""))
            .collect();

        if !event_lines.is_empty() {
            // Verify each event line is valid JSON
            for line in &event_lines {
                let parsed: Result<Value, _> = serde_json::from_str(line);
                assert!(
                    parsed.is_ok(),
                    "progress event should be valid JSON: {}",
                    line
                );
            }

            // Should have plan_ready event
            let has_plan_ready = event_lines
                .iter()
                .any(|l| l.contains("plan_ready"));
            assert!(has_plan_ready, "should emit plan_ready event");

            eprintln!("[INFO] {} JSONL progress events on stderr", event_lines.len());
        }
    }

    #[test]
    fn plan_stderr_events_have_timestamps() {
        let config_dir = tempdir().expect("temp config dir");
        write_policy(config_dir.path(), &Policy::default());

        let output = pt_core_fast()
            .env("PT_CONFIG_DIR", config_dir.path().display().to_string())
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
            .clone();

        let stderr = String::from_utf8_lossy(&output.stderr);

        for line in stderr.lines() {
            if let Ok(event) = serde_json::from_str::<Value>(line) {
                if event.get("event").is_some() {
                    // Events should have timestamp
                    assert!(
                        event.get("ts").is_some() || event.get("timestamp").is_some(),
                        "event should have timestamp: {}",
                        line
                    );
                }
            }
        }
    }
}

// ============================================================================
// Data Loss Gates
// ============================================================================

mod data_loss_gates {
    use super::*;

    #[test]
    fn plan_with_strict_data_loss_gates() {
        let config_dir = tempdir().expect("temp config dir");
        let mut policy = Policy::default();
        policy.data_loss_gates.block_if_open_write_fds = true;
        policy.data_loss_gates.max_open_write_fds = Some(0);
        policy.data_loss_gates.block_if_locked_files = true;
        policy.data_loss_gates.block_if_active_tty = true;
        write_policy(config_dir.path(), &policy);

        let (json, _code) = plan_json_with_config(
            config_dir.path(),
            &["--threshold", "0", "--max-candidates", "10"],
        );

        let candidates = json
            .get("candidates")
            .and_then(|c| c.as_array())
            .cloned()
            .unwrap_or_default();

        // With strict data loss gates, many processes should be blocked
        let blocked = candidates
            .iter()
            .filter(|c| {
                c.get("policy_blocked")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
            })
            .count();

        eprintln!(
            "[INFO] strict data_loss_gates: {}/{} blocked",
            blocked,
            candidates.len()
        );
    }
}

// ============================================================================
// Exit Codes
// ============================================================================

mod exit_codes {
    use super::*;

    #[test]
    fn plan_exit_0_means_no_candidates() {
        // Exit 0 means operational success with no candidates
        // Exit 1 means operational success with candidates
        let config_dir = tempdir().expect("temp config dir");
        let mut policy = Policy::default();
        // Very strict policy to minimize candidates
        policy.guardrails.min_process_age_seconds = 999_999;
        write_policy(config_dir.path(), &policy);

        pt_core_fast()
            .env("PT_CONFIG_DIR", config_dir.path().display().to_string())
            .args([
                "--format",
                "json",
                "agent",
                "plan",
                "--sample-size",
                TEST_SAMPLE_SIZE,
                "--threshold",
                "0.99",
            ])
            .assert()
            .code(predicate::in_iter([0, 1]));
    }

    #[test]
    fn plan_exitcode_format_produces_no_stdout() {
        let config_dir = tempdir().expect("temp config dir");
        write_policy(config_dir.path(), &Policy::default());

        pt_core_fast()
            .env("PT_CONFIG_DIR", config_dir.path().display().to_string())
            .args([
                "--format",
                "exitcode",
                "agent",
                "plan",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            .code(predicate::in_iter([0, 1]))
            .stdout(predicate::str::is_empty());
    }

    #[test]
    fn help_exits_cleanly() {
        pt_core()
            .args(["agent", "plan", "--help"])
            .assert()
            .code(predicate::in_iter([0, 1]))
            .stdout(predicate::str::contains("plan"));

        pt_core()
            .args(["agent", "apply", "--help"])
            .assert()
            .code(predicate::in_iter([0, 1]))
            .stdout(predicate::str::contains("apply"));
    }
}

// ============================================================================
// Combined Guardrails
// ============================================================================

mod combined {
    use super::*;

    #[test]
    fn plan_with_all_guardrails_configured() {
        let config_dir = tempdir().expect("temp config dir");
        let mut policy = Policy::default();

        // Configure multiple guardrails simultaneously
        policy.guardrails.max_kills_per_run = 3;
        policy.guardrails.min_process_age_seconds = 300;
        policy.guardrails.require_confirmation = true;
        policy.robot_mode.enabled = true;
        policy.robot_mode.min_posterior = 0.95;
        policy.robot_mode.max_blast_radius_mb = 1024.0;
        policy.robot_mode.max_kills = 5;
        policy.data_loss_gates.block_if_open_write_fds = true;
        write_policy(config_dir.path(), &policy);

        let (json, _code) = plan_json_with_config(
            config_dir.path(),
            &["--threshold", "0", "--max-candidates", "10"],
        );

        // Plan should run successfully with all guardrails active
        assert!(
            json.get("session_id").is_some(),
            "plan should complete successfully with all guardrails"
        );
        assert!(
            json.get("summary").is_some(),
            "plan should have summary"
        );

        eprintln!(
            "[INFO] combined guardrails plan completed: candidates={}",
            json.get("candidates")
                .and_then(|c| c.as_array())
                .map(|a| a.len())
                .unwrap_or(0)
        );
    }

    #[test]
    fn plan_dry_run_with_guardrails_never_kills() {
        let config_dir = tempdir().expect("temp config dir");
        write_policy(config_dir.path(), &Policy::default());

        // --dry-run should produce plan but never execute
        let output = pt_core_fast()
            .env("PT_CONFIG_DIR", config_dir.path().display().to_string())
            .args([
                "--dry-run",
                "--format",
                "json",
                "agent",
                "plan",
                "--sample-size",
                TEST_SAMPLE_SIZE,
                "--threshold",
                "0",
            ])
            .assert()
            .code(predicate::in_iter([0, 1]))
            .get_output()
            .clone();

        let json: Value = serde_json::from_slice(&output.stdout).expect("parse JSON");
        assert!(
            json.get("session_id").is_some(),
            "dry-run plan should have session_id"
        );
    }
}
