//! End-to-end tests for full agent workflows.
//!
//! Tests complete workflow sequences: snapshot → plan → (skip apply) → verify
//! to ensure the pipeline works correctly in dry-run mode.

use assert_cmd::cargo::cargo_bin_cmd;
use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use std::time::Duration;

/// Get a Command for pt-core binary with clean config (using temp dir).
fn pt_core_clean() -> Command {
    let mut cmd = cargo_bin_cmd!("pt-core");
    cmd.timeout(Duration::from_secs(300));
    // Avoid lock contention when tests run in parallel
    cmd.env("PT_SKIP_GLOBAL_LOCK", "1");
    // Use a non-existent config dir to force defaults
    cmd.arg("--config")
        .arg("/tmp/pt-core-test-nonexistent-config");
    cmd
}

/// Get a Command for pt-core binary (may use user config).
fn pt_core() -> Command {
    let mut cmd = cargo_bin_cmd!("pt-core");
    cmd.timeout(Duration::from_secs(300));
    // Avoid lock contention when tests run in parallel
    cmd.env("PT_SKIP_GLOBAL_LOCK", "1");
    cmd
}

// ============================================================================
// Scan Workflow Tests
// ============================================================================

mod scan_workflow {
    use super::*;

    #[test]
    fn scan_produces_valid_json() {
        let output = pt_core()
            .args(["--format", "json", "scan"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: Value =
            serde_json::from_slice(&output).expect("Scan output should be valid JSON");

        assert!(
            json.get("schema_version").is_some(),
            "Missing schema_version"
        );
        assert!(json.get("session_id").is_some(), "Missing session_id");
        assert!(json.get("scan").is_some(), "Missing scan data");
    }

    #[test]
    fn scan_includes_processes() {
        let output = pt_core()
            .args(["--format", "json", "scan"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).unwrap();
        let scan = json.get("scan").expect("Missing scan data");
        let processes = scan.get("processes").expect("Missing processes array");

        assert!(processes.is_array(), "processes should be an array");
        // On any running system, there should be at least a few processes
        let procs = processes.as_array().unwrap();
        assert!(!procs.is_empty(), "Should have at least one process");
    }

    #[test]
    fn scan_process_has_required_fields() {
        let output = pt_core()
            .args(["--format", "json", "scan"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).unwrap();
        let scan = json.get("scan").unwrap();
        let processes = scan.get("processes").unwrap().as_array().unwrap();

        // Check first process has expected fields
        if let Some(first) = processes.first() {
            assert!(first.get("pid").is_some(), "Process missing pid");
            assert!(first.get("ppid").is_some(), "Process missing ppid");
            assert!(first.get("comm").is_some(), "Process missing comm");
            assert!(first.get("user").is_some(), "Process missing user");
            assert!(first.get("state").is_some(), "Process missing state");
        }
    }

    #[test]
    fn scan_has_metadata() {
        let output = pt_core()
            .args(["--format", "json", "scan"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).unwrap();
        let scan = json.get("scan").expect("Missing scan data");
        let metadata = scan.get("metadata").expect("Missing metadata");

        assert!(
            metadata.get("process_count").is_some(),
            "Missing process_count"
        );
        assert!(metadata.get("duration_ms").is_some(), "Missing duration_ms");
        assert!(metadata.get("platform").is_some(), "Missing platform");
    }
}

// ============================================================================
// Agent Command Workflow Tests
// ============================================================================

mod agent_workflow {
    use super::*;

    #[test]
    fn snapshot_then_plan_workflow() {
        // Step 1: Create snapshot
        let snapshot_output = pt_core()
            .args(["--format", "json", "agent", "snapshot"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let snapshot: Value =
            serde_json::from_slice(&snapshot_output).expect("Snapshot should produce valid JSON");
        assert!(snapshot.get("session_id").is_some());

        // Step 2: Create plan (would use snapshot session_id in real impl)
        // Exit code 0 = no candidates, 1 = candidates found (PlanReady), both are success
        // Use --sample-size to limit inference for faster tests
        let plan_output = pt_core()
            .args(["--format", "json", "agent", "plan", "--sample-size", "50"])
            .assert()
            .code(predicate::in_iter([0, 1]))
            .get_output()
            .stdout
            .clone();

        let plan: Value =
            serde_json::from_slice(&plan_output).expect("Plan should produce valid JSON");
        assert!(plan.get("session_id").is_some());
    }

    #[test]
    fn dry_run_workflow_does_not_modify_state() {
        // Run full pipeline with --dry-run
        // Exit code 0 = no candidates, 1 = candidates found (PlanReady), both are success
        // Use --sample-size to limit inference for faster tests
        pt_core()
            .args([
                "--dry-run",
                "--format",
                "json",
                "agent",
                "plan",
                "--sample-size",
                "50",
            ])
            .assert()
            .code(predicate::in_iter([0, 1]));

        // Verify we can still run commands (no state corruption)
        pt_core()
            .args(["--format", "json", "scan"])
            .assert()
            .success();
    }

    #[test]
    fn shadow_mode_workflow() {
        // Shadow mode should run full pipeline but never execute
        // Exit code 0 = no candidates, 1 = candidates found (PlanReady), both are success
        // Use --sample-size to limit inference for faster tests
        pt_core()
            .args([
                "--shadow",
                "--format",
                "json",
                "agent",
                "plan",
                "--sample-size",
                "50",
            ])
            .assert()
            .code(predicate::in_iter([0, 1]));
    }

    #[test]
    fn robot_mode_with_dry_run() {
        // Robot mode + dry-run should generate plan but not execute
        // Exit code 0 = no candidates, 1 = candidates found (PlanReady), both are success
        // Use --sample-size to limit inference for faster tests
        pt_core()
            .args([
                "--robot",
                "--dry-run",
                "--format",
                "json",
                "agent",
                "plan",
                "--sample-size",
                "50",
            ])
            .assert()
            .code(predicate::in_iter([0, 1]));
    }
}

// ============================================================================
// Verify Workflow Tests
// ============================================================================

mod verify_workflow {
    use super::*;

    #[test]
    fn verify_help_works() {
        pt_core()
            .args(["agent", "verify", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("session"));
    }

    #[test]
    fn explain_help_works() {
        pt_core()
            .args(["agent", "explain", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("session"))
            .stdout(predicate::str::contains("pids"));
    }

    #[test]
    fn apply_help_works() {
        pt_core()
            .args(["agent", "apply", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("session"));
    }

    #[test]
    fn diff_help_works() {
        pt_core()
            .args(["agent", "diff", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("base"));
    }
}

// ============================================================================
// Check Command Workflow Tests (using clean config)
// ============================================================================

mod check_workflow {
    use super::*;

    #[test]
    fn check_all_produces_valid_json() {
        let output = pt_core_clean()
            .args(["--format", "json", "check", "--all"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: Value =
            serde_json::from_slice(&output).expect("Check output should be valid JSON");

        assert!(
            json.get("schema_version").is_some(),
            "Missing schema_version"
        );
        assert!(json.get("status").is_some(), "Missing status");
        assert!(json.get("checks").is_some(), "Missing checks array");
    }

    #[test]
    fn check_priors_with_defaults() {
        pt_core_clean()
            .args(["--format", "json", "check", "--priors"])
            .assert()
            .success()
            .stdout(predicate::str::contains("priors"));
    }

    #[test]
    fn check_policy_with_defaults() {
        pt_core_clean()
            .args(["--format", "json", "check", "--policy"])
            .assert()
            .success()
            .stdout(predicate::str::contains("policy"));
    }

    #[test]
    fn check_capabilities() {
        pt_core_clean()
            .args(["--format", "json", "check", "--check-capabilities"])
            .assert()
            .success()
            .stdout(predicate::str::contains("capabilities"));
    }
}

// ============================================================================
// Config Workflow Tests (using clean config)
// ============================================================================

mod config_workflow {
    use super::*;

    #[test]
    fn config_show_produces_valid_json() {
        let output = pt_core_clean()
            .args(["--format", "json", "config", "show"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: Value =
            serde_json::from_slice(&output).expect("Config show should produce valid JSON");

        assert!(
            json.get("schema_version").is_some(),
            "Missing schema_version"
        );
        assert!(json.get("priors").is_some(), "Missing priors section");
        assert!(json.get("policy").is_some(), "Missing policy section");
    }

    #[test]
    fn config_show_priors() {
        pt_core_clean()
            .args(["--format", "json", "config", "show", "--file", "priors"])
            .assert()
            .success()
            .stdout(predicate::str::contains("priors"));
    }

    #[test]
    fn config_show_policy() {
        pt_core_clean()
            .args(["--format", "json", "config", "show", "--file", "policy"])
            .assert()
            .success()
            .stdout(predicate::str::contains("policy"));
    }

    #[test]
    fn config_validate_succeeds_with_defaults() {
        pt_core_clean()
            .args(["--format", "json", "config", "validate"])
            .assert()
            .success()
            .stdout(predicate::str::contains("valid"));
    }
}

// ============================================================================
// Capabilities Workflow Tests
// ============================================================================

mod capabilities_workflow {
    use super::*;

    #[test]
    fn agent_capabilities_produces_valid_json() {
        let output = pt_core()
            .args(["--format", "json", "agent", "capabilities"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: Value =
            serde_json::from_slice(&output).expect("Capabilities should produce valid JSON");

        assert!(
            json.get("schema_version").is_some(),
            "Missing schema_version"
        );
        assert!(json.get("os").is_some(), "Missing os section");
    }

    #[test]
    fn capabilities_shows_os_info() {
        let output = pt_core()
            .args(["--format", "json", "agent", "capabilities"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).unwrap();
        let os = json.get("os").expect("Missing os section");

        assert!(os.get("family").is_some(), "Missing os.family");
        assert!(os.get("arch").is_some(), "Missing os.arch");
    }
}

// ============================================================================
// Full Pipeline Integration Tests (using clean config)
// ============================================================================

mod full_pipeline {
    use super::*;

    #[test]
    fn scan_check_config_pipeline() {
        // Verify that running multiple commands in sequence works
        // and doesn't corrupt any state

        // 1. Check configuration (using clean config)
        pt_core_clean()
            .args(["--format", "json", "check", "--all"])
            .assert()
            .success();

        // 2. Show config (using clean config)
        pt_core_clean()
            .args(["--format", "json", "config", "show"])
            .assert()
            .success();

        // 3. Run scan
        pt_core()
            .args(["--format", "json", "scan"])
            .assert()
            .success();

        // 4. Check capabilities
        pt_core()
            .args(["--format", "json", "agent", "capabilities"])
            .assert()
            .success();
    }

    #[test]
    fn session_ids_are_unique_across_commands() {
        let scan_output = pt_core()
            .args(["--format", "json", "scan"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let snapshot_output = pt_core()
            .args(["--format", "json", "agent", "snapshot"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let scan_json: Value = serde_json::from_slice(&scan_output).unwrap();
        let snapshot_json: Value = serde_json::from_slice(&snapshot_output).unwrap();

        let scan_id = scan_json.get("session_id").unwrap().as_str().unwrap();
        let snapshot_id = snapshot_json.get("session_id").unwrap().as_str().unwrap();

        assert_ne!(
            scan_id, snapshot_id,
            "Different commands should have different session IDs"
        );
    }

    #[test]
    fn all_json_outputs_have_consistent_schema() {
        // Commands that don't depend on config files
        // Note: "agent plan" returns exit code 1 (PlanReady) when candidates exist, which is success
        // Use --sample-size for agent plan to limit inference for faster tests
        let commands = vec![
            vec!["--format", "json", "scan"],
            vec!["--format", "json", "agent", "snapshot"],
            vec!["--format", "json", "agent", "plan", "--sample-size", "50"],
            vec!["--format", "json", "agent", "capabilities"],
        ];

        for args in commands {
            let is_agent_plan = args.contains(&"plan");
            let assertion = pt_core().args(&args).assert();

            // agent plan returns 0 (no candidates) or 1 (PlanReady, candidates found)
            let output = if is_agent_plan {
                assertion
                    .code(predicate::in_iter([0, 1]))
                    .get_output()
                    .stdout
                    .clone()
            } else {
                assertion.success().get_output().stdout.clone()
            };

            let json: Value = serde_json::from_slice(&output)
                .unwrap_or_else(|e| panic!("Invalid JSON from {:?}: {}", args, e));

            assert!(
                json.get("schema_version").is_some(),
                "Missing schema_version from {:?}",
                args
            );
            assert!(
                json.get("session_id").is_some(),
                "Missing session_id from {:?}",
                args
            );
            assert!(
                json.get("generated_at").is_some(),
                "Missing generated_at from {:?}",
                args
            );
        }
    }

    #[test]
    fn config_commands_produce_valid_json_with_clean_config() {
        // Test check and config commands using clean config
        let check_output = pt_core_clean()
            .args(["--format", "json", "check", "--all"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let check_json: Value =
            serde_json::from_slice(&check_output).expect("check --all should produce valid JSON");
        assert!(check_json.get("schema_version").is_some());

        let config_output = pt_core_clean()
            .args(["--format", "json", "config", "show"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let config_json: Value =
            serde_json::from_slice(&config_output).expect("config show should produce valid JSON");
        assert!(config_json.get("schema_version").is_some());
    }
}
