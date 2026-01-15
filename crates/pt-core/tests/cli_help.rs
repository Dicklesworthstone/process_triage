//! CLI help output tests for pt-core.
//!
//! These tests verify that all commands and subcommands correctly display
//! their help text without errors.

use assert_cmd::Command;
use predicates::prelude::*;

/// Get a Command for pt-core binary.
fn pt_core() -> Command {
    Command::cargo_bin("pt-core").expect("pt-core binary should exist")
}

// ============================================================================
// Top-level Help Tests
// ============================================================================

mod top_level {
    use super::*;

    #[test]
    fn help_flag_works() {
        pt_core()
            .arg("--help")
            .assert()
            .success()
            .stdout(predicate::str::contains("Process Triage Core"));
    }

    #[test]
    fn help_subcommand_works() {
        pt_core()
            .arg("help")
            .assert()
            .success()
            .stdout(predicate::str::contains("Process Triage Core"));
    }

    #[test]
    fn version_flag_works() {
        pt_core()
            .arg("--version")
            .assert()
            .success()
            .stdout(predicate::str::contains("pt-core"));
    }

    #[test]
    fn help_shows_all_commands() {
        let output = pt_core()
            .arg("--help")
            .assert()
            .success();

        // Verify main commands are listed
        output
            .stdout(predicate::str::contains("run"))
            .stdout(predicate::str::contains("scan"))
            .stdout(predicate::str::contains("agent"))
            .stdout(predicate::str::contains("config"))
            .stdout(predicate::str::contains("bundle"))
            .stdout(predicate::str::contains("report"))
            .stdout(predicate::str::contains("query"))
            .stdout(predicate::str::contains("check"));
    }

    #[test]
    fn help_shows_global_options() {
        pt_core()
            .arg("--help")
            .assert()
            .success()
            .stdout(predicate::str::contains("--format"))
            .stdout(predicate::str::contains("--verbose"))
            .stdout(predicate::str::contains("--robot"))
            .stdout(predicate::str::contains("--dry-run"));
    }
}

// ============================================================================
// Run Command Help Tests
// ============================================================================

mod run_command {
    use super::*;

    #[test]
    fn run_help_works() {
        pt_core()
            .args(["run", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Interactive golden path"));
    }

    #[test]
    fn run_help_shows_options() {
        pt_core()
            .args(["run", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("--deep"))
            .stdout(predicate::str::contains("--signatures"));
    }
}

// ============================================================================
// Scan Command Help Tests
// ============================================================================

mod scan_command {
    use super::*;

    #[test]
    fn scan_help_works() {
        pt_core()
            .args(["scan", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Quick multi-sample scan"));
    }

    #[test]
    fn scan_help_shows_options() {
        pt_core()
            .args(["scan", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("--samples"))
            .stdout(predicate::str::contains("--interval"));
    }
}

// ============================================================================
// Deep-Scan Command Help Tests
// ============================================================================

mod deep_scan_command {
    use super::*;

    #[test]
    fn deep_scan_help_works() {
        pt_core()
            .args(["deep-scan", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Full deep scan"));
    }

    #[test]
    fn deep_scan_help_shows_options() {
        pt_core()
            .args(["deep-scan", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("--pids"))
            .stdout(predicate::str::contains("--budget"));
    }
}

// ============================================================================
// Query Command Help Tests
// ============================================================================

mod query_command {
    use super::*;

    #[test]
    fn query_help_works() {
        pt_core()
            .args(["query", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Query telemetry"));
    }

    #[test]
    fn query_sessions_help_works() {
        pt_core()
            .args(["query", "sessions", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Query recent sessions"));
    }

    #[test]
    fn query_actions_help_works() {
        pt_core()
            .args(["query", "actions", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Query action history"));
    }

    #[test]
    fn query_telemetry_help_works() {
        pt_core()
            .args(["query", "telemetry", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Query telemetry data"));
    }
}

// ============================================================================
// Bundle Command Help Tests
// ============================================================================

mod bundle_command {
    use super::*;

    #[test]
    fn bundle_help_works() {
        pt_core()
            .args(["bundle", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("diagnostic bundle"));
    }

    #[test]
    fn bundle_create_help_works() {
        pt_core()
            .args(["bundle", "create", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Create a new diagnostic bundle"));
    }

    #[test]
    fn bundle_inspect_help_works() {
        pt_core()
            .args(["bundle", "inspect", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Inspect an existing bundle"));
    }

    #[test]
    fn bundle_extract_help_works() {
        pt_core()
            .args(["bundle", "extract", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Extract bundle contents"));
    }
}

// ============================================================================
// Report Command Help Tests
// ============================================================================

mod report_command {
    use super::*;

    #[test]
    fn report_help_works() {
        pt_core()
            .args(["report", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Generate HTML reports"));
    }

    #[test]
    fn report_help_shows_options() {
        pt_core()
            .args(["report", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("--session"))
            .stdout(predicate::str::contains("--output"));
    }
}

// ============================================================================
// Check Command Help Tests
// ============================================================================

mod check_command {
    use super::*;

    #[test]
    fn check_help_works() {
        pt_core()
            .args(["check", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Validate configuration"));
    }

    #[test]
    fn check_help_shows_options() {
        pt_core()
            .args(["check", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("--priors"))
            .stdout(predicate::str::contains("--policy"))
            .stdout(predicate::str::contains("--capabilities"));
    }
}

// ============================================================================
// Agent Command Help Tests
// ============================================================================

mod agent_command {
    use super::*;

    #[test]
    fn agent_help_works() {
        pt_core()
            .args(["agent", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Agent/robot subcommands"));
    }

    #[test]
    fn agent_plan_help_works() {
        pt_core()
            .args(["agent", "plan", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Generate action plan"));
    }

    #[test]
    fn agent_explain_help_works() {
        pt_core()
            .args(["agent", "explain", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Explain reasoning"));
    }

    #[test]
    fn agent_apply_help_works() {
        pt_core()
            .args(["agent", "apply", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Execute actions"));
    }

    #[test]
    fn agent_verify_help_works() {
        pt_core()
            .args(["agent", "verify", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Verify action outcomes"));
    }

    #[test]
    fn agent_diff_help_works() {
        pt_core()
            .args(["agent", "diff", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Show changes between sessions"));
    }

    #[test]
    fn agent_snapshot_help_works() {
        pt_core()
            .args(["agent", "snapshot", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Create session snapshot"));
    }

    #[test]
    fn agent_capabilities_help_works() {
        pt_core()
            .args(["agent", "capabilities", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Dump current capabilities"));
    }
}

// ============================================================================
// Config Command Help Tests
// ============================================================================

mod config_command {
    use super::*;

    #[test]
    fn config_help_works() {
        pt_core()
            .args(["config", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Configuration management"));
    }

    #[test]
    fn config_show_help_works() {
        pt_core()
            .args(["config", "show", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Show current configuration"));
    }

    #[test]
    fn config_schema_help_works() {
        pt_core()
            .args(["config", "schema", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Print JSON schema"));
    }

    #[test]
    fn config_validate_help_works() {
        pt_core()
            .args(["config", "validate", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Validate configuration"));
    }
}

// ============================================================================
// Telemetry Command Help Tests
// ============================================================================

mod telemetry_command {
    use super::*;

    #[test]
    fn telemetry_help_works() {
        pt_core()
            .args(["telemetry", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Telemetry management"));
    }
}

// ============================================================================
// Version Command Tests
// ============================================================================

mod version_command {
    use super::*;

    #[test]
    fn version_command_works() {
        pt_core()
            .arg("version")
            .assert()
            .success();
    }
}
