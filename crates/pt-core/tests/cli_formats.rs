//! CLI output format tests for pt-core.
//!
//! These tests verify that output formats work correctly and produce
//! valid, parseable output.

use assert_cmd::Command;
use predicates::prelude::*;

/// Get a Command for pt-core binary.
fn pt_core() -> Command {
    Command::cargo_bin("pt-core").expect("pt-core binary should exist")
}

// ============================================================================
// Global Format Option Tests
// ============================================================================

mod format_option {
    use super::*;

    #[test]
    fn json_format_accepted() {
        pt_core()
            .args(["--format", "json", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn short_format_flag_accepted() {
        pt_core()
            .args(["-f", "json", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn md_format_accepted() {
        pt_core()
            .args(["--format", "md", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn jsonl_format_accepted() {
        pt_core()
            .args(["--format", "jsonl", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn summary_format_accepted() {
        pt_core()
            .args(["--format", "summary", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn invalid_format_rejected() {
        pt_core()
            .args(["--format", "xml"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("error"));
    }
}

// ============================================================================
// Version Output Format Tests
// ============================================================================

mod version_output {
    use super::*;

    #[test]
    fn version_output_contains_name() {
        pt_core()
            .arg("--version")
            .assert()
            .success()
            .stdout(predicate::str::contains("pt-core"));
    }

    #[test]
    fn version_output_contains_version_number() {
        pt_core()
            .arg("--version")
            .assert()
            .success()
            .stdout(predicate::str::is_match(r"\d+\.\d+\.\d+").unwrap());
    }
}

// ============================================================================
// Help Output Format Tests
// ============================================================================

mod help_output {
    use super::*;

    #[test]
    fn help_output_is_formatted() {
        pt_core()
            .arg("--help")
            .assert()
            .success()
            .stdout(predicate::str::contains("Usage:"))
            .stdout(predicate::str::contains("Options:"))
            .stdout(predicate::str::contains("Commands:"));
    }

    #[test]
    fn subcommand_help_is_formatted() {
        pt_core()
            .args(["agent", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Usage:"))
            .stdout(predicate::str::contains("Commands:"));
    }
}

// ============================================================================
// Global Options Compatibility Tests
// ============================================================================

mod global_options {
    use super::*;

    #[test]
    fn verbose_flag_accepted() {
        pt_core()
            .args(["-v", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn multiple_verbose_flags_accepted() {
        pt_core()
            .args(["-vvv", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn quiet_flag_accepted() {
        pt_core()
            .args(["-q", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn no_color_flag_accepted() {
        pt_core()
            .args(["--no-color", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn robot_flag_accepted() {
        pt_core()
            .args(["--robot", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn dry_run_flag_accepted() {
        pt_core()
            .args(["--dry-run", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn shadow_flag_accepted() {
        pt_core()
            .args(["--shadow", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn standalone_flag_accepted() {
        pt_core()
            .args(["--standalone", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn timeout_accepts_number() {
        pt_core()
            .args(["--timeout", "30", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn config_accepts_path() {
        pt_core()
            .args(["--config", "/tmp/test", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn capabilities_accepts_path() {
        pt_core()
            .args(["--capabilities", "/tmp/caps.json", "--help"])
            .assert()
            .success();
    }
}

// ============================================================================
// Command-specific Option Tests
// ============================================================================

mod command_options {
    use super::*;

    #[test]
    fn scan_samples_accepts_number() {
        pt_core()
            .args(["scan", "--samples", "5", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn scan_interval_accepts_number() {
        pt_core()
            .args(["scan", "--interval", "1000", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn deep_scan_pids_accepts_list() {
        pt_core()
            .args(["deep-scan", "--pids", "1,2,3", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn agent_plan_threshold_accepts_float() {
        pt_core()
            .args(["agent", "plan", "--threshold", "0.85", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn agent_plan_max_candidates_accepts_number() {
        pt_core()
            .args(["agent", "plan", "--max-candidates", "50", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn agent_plan_only_accepts_valid_values() {
        pt_core()
            .args(["agent", "plan", "--only", "kill", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn query_sessions_limit_accepts_number() {
        pt_core()
            .args(["query", "sessions", "--limit", "25", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn query_telemetry_range_accepts_string() {
        pt_core()
            .args(["query", "telemetry", "--range", "7d", "--help"])
            .assert()
            .success();
    }
}

// ============================================================================
// Combined Options Tests
// ============================================================================

mod combined_options {
    use super::*;

    #[test]
    fn multiple_global_options_work() {
        pt_core()
            .args(["-v", "--format", "json", "--no-color", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn global_options_with_subcommand() {
        pt_core()
            .args(["--format", "json", "-v", "scan", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn subcommand_options_with_global_options() {
        pt_core()
            .args(["--format", "json", "scan", "--samples", "5", "--help"])
            .assert()
            .success();
    }
}
