//! Automation mode tests for --robot, --shadow, and --dry-run flags.
//!
//! Tests verify that automation modes:
//! - Don't prompt for user input
//! - Respect safety gates
//! - Execute (or not) actions appropriately
//! - Handle stdin/TTY absence gracefully

use assert_cmd::cargo::cargo_bin_cmd;
use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use std::time::Duration;

/// Predicate for valid `agent plan` exit codes.
/// Exit code 0 = Clean (no candidates)
/// Exit code 1 = PlanReady (candidates exist, plan produced)
/// Both are valid success states per exit_codes.rs.
fn plan_exit_codes() -> impl predicates::Predicate<i32> {
    predicate::in_iter([0, 1])
}

/// Get a Command for pt-core binary with timeout.
fn pt_core() -> Command {
    let mut cmd = cargo_bin_cmd!("pt-core");
    cmd.timeout(Duration::from_secs(30));
    cmd
}

/// Get a Command with clean config (non-existent config dir forces defaults).
fn pt_core_clean() -> Command {
    let mut cmd = pt_core();
    cmd.arg("--config")
        .arg("/tmp/pt-core-test-nonexistent-config");
    cmd
}

// ============================================================================
// Robot Mode Tests
// ============================================================================

mod robot_mode {
    use super::*;

    #[test]
    fn test_robot_mode_no_prompts() {
        // Robot mode should never prompt for input - stdin can be closed
        // and the command should still complete successfully
        pt_core()
            .args(["--robot", "--format", "json", "scan"])
            .write_stdin("") // Empty stdin - no user input available
            .assert()
            .success();
    }

    #[test]
    fn test_robot_mode_scan_produces_json() {
        let output = pt_core()
            .args(["--robot", "--format", "json", "scan"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: Value =
            serde_json::from_slice(&output).expect("Robot mode scan should produce valid JSON");
        assert!(json.get("schema_version").is_some());
        assert!(json.get("session_id").is_some());
    }

    #[test]
    fn test_robot_mode_agent_snapshot() {
        let output = pt_core()
            .args(["--robot", "--format", "json", "agent", "snapshot"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output)
            .expect("Robot mode agent snapshot should produce valid JSON");
        assert!(json.get("session_id").is_some());
    }

    #[test]
    fn test_robot_mode_agent_plan() {
        let output = pt_core()
            .args(["--robot", "--format", "json", "agent", "plan"])
            .assert()
            .code(plan_exit_codes())
            .get_output()
            .stdout
            .clone();

        let json: Value =
            serde_json::from_slice(&output).expect("Robot mode agent plan should produce valid JSON");
        assert!(json.get("session_id").is_some());
    }

    #[test]
    fn test_robot_mode_respects_policy() {
        // Robot mode should still respect policy configuration
        pt_core_clean()
            .args(["--robot", "--format", "json", "check", "--policy"])
            .assert()
            .success()
            .stdout(predicate::str::contains("policy"));
    }

    #[test]
    fn test_robot_mode_with_config_check() {
        // Robot mode should work with config validation
        pt_core_clean()
            .args(["--robot", "--format", "json", "check", "--all"])
            .assert()
            .success();
    }
}

// ============================================================================
// Shadow Mode Tests
// ============================================================================

mod shadow_mode {
    use super::*;

    #[test]
    fn test_shadow_mode_no_actions_executed() {
        // Shadow mode runs full pipeline but never executes actions
        // It should complete successfully without making any changes
        pt_core()
            .args(["--shadow", "--format", "json", "agent", "plan"])
            .assert()
            .code(plan_exit_codes());
    }

    #[test]
    fn test_shadow_mode_produces_plan() {
        let output = pt_core()
            .args(["--shadow", "--format", "json", "agent", "plan"])
            .assert()
            .code(plan_exit_codes())
            .get_output()
            .stdout
            .clone();

        let json: Value =
            serde_json::from_slice(&output).expect("Shadow mode should produce valid JSON plan");
        assert!(json.get("schema_version").is_some());
        assert!(json.get("session_id").is_some());
    }

    #[test]
    fn test_shadow_mode_scan() {
        // Shadow mode should allow scanning (read-only operation)
        let output = pt_core()
            .args(["--shadow", "--format", "json", "scan"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).expect("Shadow scan should produce JSON");
        assert!(json.get("scan").is_some());
    }

    #[test]
    fn test_shadow_mode_logs_recommendations() {
        // Shadow mode should log what it would do (stderr contains event logs)
        pt_core()
            .args(["--shadow", "--format", "json", "agent", "plan"])
            .assert()
            .code(plan_exit_codes())
            // Stderr should contain structured log events
            .stderr(predicate::str::contains("event"));
    }
}

// ============================================================================
// Dry Run Mode Tests
// ============================================================================

mod dry_run_mode {
    use super::*;

    #[test]
    fn test_dry_run_shows_plan() {
        // Dry run computes plan but doesn't execute
        let output = pt_core()
            .args(["--dry-run", "--format", "json", "agent", "plan"])
            .assert()
            .code(plan_exit_codes())
            .get_output()
            .stdout
            .clone();

        let json: Value =
            serde_json::from_slice(&output).expect("Dry run should produce valid JSON");
        assert!(json.get("session_id").is_some());
    }

    #[test]
    fn test_dry_run_no_state_changes() {
        // Run dry-run, then verify we can still run normal commands
        pt_core()
            .args(["--dry-run", "--format", "json", "agent", "plan"])
            .assert()
            .code(plan_exit_codes());

        // Should be able to run again - no state corruption
        pt_core()
            .args(["--format", "json", "scan"])
            .assert()
            .success();
    }

    #[test]
    fn test_dry_run_scan() {
        pt_core()
            .args(["--dry-run", "--format", "json", "scan"])
            .assert()
            .success();
    }

    #[test]
    fn test_dry_run_agent_snapshot() {
        pt_core()
            .args(["--dry-run", "--format", "json", "agent", "snapshot"])
            .assert()
            .success();
    }
}

// ============================================================================
// Combined Mode Tests
// ============================================================================

mod combined_modes {
    use super::*;

    #[test]
    fn test_robot_shadow_combination() {
        // Robot + shadow: non-interactive, full pipeline, no execution
        pt_core()
            .args(["--robot", "--shadow", "--format", "json", "agent", "plan"])
            .assert()
            .code(plan_exit_codes());
    }

    #[test]
    fn test_robot_dry_run_combination() {
        // Robot + dry-run: non-interactive, plan only
        pt_core()
            .args(["--robot", "--dry-run", "--format", "json", "agent", "plan"])
            .assert()
            .code(plan_exit_codes());
    }

    #[test]
    fn test_shadow_dry_run_combination() {
        // Shadow + dry-run: both modes together
        pt_core()
            .args(["--shadow", "--dry-run", "--format", "json", "agent", "plan"])
            .assert()
            .code(plan_exit_codes());
    }

    #[test]
    fn test_all_automation_flags() {
        // All three flags together
        pt_core()
            .args([
                "--robot",
                "--shadow",
                "--dry-run",
                "--format",
                "json",
                "agent",
                "plan",
            ])
            .assert()
            .code(plan_exit_codes());
    }
}

// ============================================================================
// Stdin/TTY Handling Tests
// ============================================================================

mod stdin_tty_handling {
    use super::*;

    #[test]
    fn test_stdin_closed_no_hang() {
        // With stdin closed (empty), command should not hang waiting for input
        pt_core()
            .args(["--robot", "--format", "json", "scan"])
            .write_stdin("")
            .timeout(Duration::from_secs(10))
            .assert()
            .success();
    }

    #[test]
    fn test_stdin_closed_agent_plan() {
        // Agent plan with closed stdin should work in robot mode
        pt_core()
            .args(["--robot", "--format", "json", "agent", "plan"])
            .write_stdin("")
            .timeout(Duration::from_secs(10))
            .assert()
            .code(plan_exit_codes());
    }

    #[test]
    fn test_piped_input_robot_mode() {
        // Robot mode should handle piped input gracefully
        pt_core()
            .args(["--robot", "--format", "json", "scan"])
            .write_stdin("ignored input\n")
            .assert()
            .success();
    }

    #[test]
    fn test_non_interactive_environment() {
        // Simulate non-interactive environment (CI/CD)
        pt_core()
            .args(["--robot", "--format", "json", "agent", "snapshot"])
            .env_remove("TERM") // No terminal
            .write_stdin("")
            .assert()
            .success();
    }
}

// ============================================================================
// Safety Gate Verification Tests
// ============================================================================

mod safety_gates {
    use super::*;

    #[test]
    fn test_robot_mode_check_capabilities() {
        // Robot mode should report capabilities correctly
        let output = pt_core()
            .args(["--robot", "--format", "json", "agent", "capabilities"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output)
            .expect("Robot mode capabilities should produce valid JSON");
        assert!(json.get("os").is_some());
    }

    #[test]
    fn test_config_validation_in_robot_mode() {
        // Policy validation should work in robot mode
        pt_core_clean()
            .args(["--robot", "--format", "json", "config", "validate"])
            .assert()
            .success()
            .stdout(predicate::str::contains("valid"));
    }

    #[test]
    fn test_priors_check_in_robot_mode() {
        // Priors check should work in robot mode
        pt_core_clean()
            .args(["--robot", "--format", "json", "check", "--priors"])
            .assert()
            .success();
    }

    #[test]
    fn test_policy_check_in_robot_mode() {
        // Policy check should work in robot mode
        pt_core_clean()
            .args(["--robot", "--format", "json", "check", "--policy"])
            .assert()
            .success();
    }
}

// ============================================================================
// Output Format Tests in Automation Modes
// ============================================================================

mod output_formats {
    use super::*;

    #[test]
    fn test_robot_json_output_has_schema() {
        let output = pt_core()
            .args(["--robot", "--format", "json", "scan"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).unwrap();
        assert!(json.get("schema_version").is_some());
        assert!(json.get("session_id").is_some());
        assert!(json.get("generated_at").is_some());
    }

    #[test]
    fn test_shadow_json_output_has_schema() {
        let output = pt_core()
            .args(["--shadow", "--format", "json", "scan"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).unwrap();
        assert!(json.get("schema_version").is_some());
    }

    #[test]
    fn test_dry_run_json_output_has_schema() {
        let output = pt_core()
            .args(["--dry-run", "--format", "json", "scan"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).unwrap();
        assert!(json.get("schema_version").is_some());
    }

    #[test]
    fn test_automation_modes_stderr_is_jsonl() {
        // In JSON format mode, stderr should be JSONL for machine parsing
        pt_core()
            .args(["--robot", "--format", "json", "scan"])
            .assert()
            .success()
            .stderr(predicate::str::contains("\"event\":"));
    }
}
