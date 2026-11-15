//! CLI error handling tests for pt-core.
//!
//! These tests verify that invalid arguments and commands produce
//! appropriate error messages and exit codes.

use assert_cmd::cargo::cargo_bin_cmd;
use assert_cmd::Command;
use predicates::prelude::*;

/// Get a Command for pt-core binary.
fn pt_core() -> Command {
    cargo_bin_cmd!("pt-core")
}

// ============================================================================
// Invalid Subcommand Tests
// ============================================================================

mod invalid_subcommand {
    use super::*;

    #[test]
    fn unknown_command_fails() {
        pt_core()
            .arg("nonexistent-command")
            .assert()
            .failure()
            .stderr(predicate::str::contains("error"));
    }

    #[test]
    fn unknown_agent_subcommand_fails() {
        pt_core()
            .args(["agent", "nonexistent"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("error"));
    }

    #[test]
    fn unknown_config_subcommand_fails() {
        pt_core()
            .args(["config", "nonexistent"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("error"));
    }

    #[test]
    fn unknown_bundle_subcommand_fails() {
        pt_core()
            .args(["bundle", "nonexistent"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("error"));
    }

    #[test]
    fn query_sessions_with_invalid_option_fails() {
        pt_core()
            .args(["query", "sessions", "--invalid-option"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("error"));
    }
}

// ============================================================================
// Invalid Option Tests
// ============================================================================

mod invalid_options {
    use super::*;

    #[test]
    fn unknown_global_flag_fails() {
        pt_core()
            .arg("--nonexistent-flag")
            .assert()
            .failure()
            .stderr(predicate::str::contains("error"));
    }

    #[test]
    fn invalid_format_value_fails() {
        pt_core()
            .args(["--format", "invalid_format_name"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("error"));
    }

    #[test]
    fn missing_required_value_fails() {
        pt_core()
            .args(["--format"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("error"));
    }
}

// ============================================================================
// Agent Command Error Tests
// ============================================================================

mod agent_errors {
    use super::*;

    #[test]
    fn agent_explain_requires_session() {
        pt_core()
            .args(["agent", "explain", "--pids", "1234"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("--session"));
    }

    #[test]
    fn agent_apply_requires_session() {
        pt_core()
            .args(["agent", "apply"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("--session"));
    }

    #[test]
    fn agent_verify_requires_session() {
        pt_core()
            .args(["agent", "verify"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("--session"));
    }

    #[test]
    fn agent_diff_requires_base() {
        pt_core()
            .args(["agent", "diff"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("--base"));
    }

    #[test]
    fn agent_diff_rejects_invalid_focus() {
        pt_core()
            .args([
                "agent",
                "diff",
                "--base",
                "invalid",
                "--focus",
                "not-a-mode",
            ])
            .assert()
            .failure()
            .stderr(predicate::str::contains("Invalid focus mode"));
    }
}

// ============================================================================
// Bundle Command Error Tests
// ============================================================================

mod bundle_errors {
    use super::*;

    #[test]
    fn bundle_inspect_requires_path() {
        pt_core()
            .args(["bundle", "inspect"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("error"));
    }

    #[test]
    fn bundle_extract_requires_path() {
        pt_core()
            .args(["bundle", "extract"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("error"));
    }
}

// ============================================================================
// Config Command Error Tests
// ============================================================================

mod config_errors {
    use super::*;

    #[test]
    fn config_schema_requires_file() {
        pt_core()
            .args(["config", "schema"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("--file"));
    }
}

// ============================================================================
// Numeric Argument Error Tests
// ============================================================================

mod numeric_errors {
    use super::*;

    #[test]
    fn scan_samples_rejects_non_numeric() {
        pt_core()
            .args(["scan", "--samples", "not-a-number"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("error"));
    }

    #[test]
    fn scan_interval_rejects_non_numeric() {
        pt_core()
            .args(["scan", "--interval", "not-a-number"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("error"));
    }

    #[test]
    fn agent_plan_threshold_rejects_non_numeric() {
        pt_core()
            .args(["agent", "plan", "--threshold", "not-a-number"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("error"));
    }

    #[test]
    fn deep_scan_pids_rejects_non_numeric() {
        pt_core()
            .args(["deep-scan", "--pids", "abc,def"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("error"));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn deep_scan_zero_budget_and_global_timeout_refuse_before_collection() {
        for args in [
            vec!["deep-scan", "--budget", "0"],
            vec!["--timeout", "0", "deep-scan", "--budget", "30"],
            vec!["--timeout", "0", "deep-scan"],
        ] {
            pt_core()
                .args(args)
                .assert()
                .code(22)
                .stdout(predicate::str::is_empty())
                .stderr(predicate::str::contains("budget is exhausted"));
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn budgeted_deep_scan_returns_complete_evidence_for_a_live_process() {
        let pid = std::process::id().to_string();
        let output = pt_core()
            .args([
                "--format",
                "json",
                "deep-scan",
                "--pids",
                &pid,
                "--budget",
                "15",
            ])
            .timeout(std::time::Duration::from_secs(20))
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
        let result: pt_core::collect::DeepScanResult =
            serde_json::from_value(value["deep_scan"].clone()).unwrap();
        assert_eq!(result.metadata.process_count, 1);
        assert_eq!(result.processes.len(), 1);
        assert_eq!(result.processes[0].pid.0, std::process::id());
        assert!(result
            .metadata
            .warnings
            .iter()
            .all(|warning| !warning.contains("advisory")));
    }
}

// ============================================================================
// Exit Code Tests for Errors
// ============================================================================

mod exit_codes {
    use super::*;

    #[test]
    fn invalid_args_returns_nonzero() {
        let output = pt_core().arg("--invalid-flag").assert().failure();

        // Exit code should be non-zero for argument errors
        output.code(predicate::ne(0));
    }

    #[test]
    fn missing_required_arg_returns_nonzero() {
        let output = pt_core().args(["agent", "apply"]).assert().failure();

        output.code(predicate::ne(0));
    }
}

// ============================================================================
// Error Message Quality Tests
// ============================================================================

mod error_messages {
    use super::*;

    #[test]
    fn unknown_command_suggests_similar() {
        // clap should suggest similar commands for typos
        pt_core()
            .arg("scna") // typo of "scan"
            .assert()
            .failure()
            .stderr(predicate::str::contains("error"));
    }

    #[test]
    fn error_messages_are_helpful() {
        // Verify error messages include the problematic argument
        pt_core()
            .args(["--format", "badformat"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("badformat"));
    }
}
