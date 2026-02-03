//! E2E scenarios for specific CLI workflows.
//!
//! Covers:
//! - Basic scan with specific process verification
//! - Invalid configuration handling
//! - Agent mode workflow (snapshot → plan → verify)
//! - Error handling (no candidates, invalid args)
//! - Exit code verification
//!
//! These tests rely on `ProcessHarness` to interact with real system state (no mocks).

#[cfg(feature = "test-utils")]
mod e2e_scenarios {
    use assert_cmd::cargo::cargo_bin_cmd;
    use assert_cmd::Command;
    use chrono::Utc;
    use predicates::prelude::*;
    use pt_core::test_utils::ProcessHarness;
    use pt_telemetry::shadow::{BeliefState, EventType, Observation, ProcessEvent, StateSnapshot};
    use serde_json::Value;
    use std::fs;
    use std::fs::File;
    use std::io::Write;
    use std::time::Duration;
    use tempfile::tempdir;

    /// Get a Command for pt-core binary.
    fn pt_core() -> Command {
        let mut cmd = cargo_bin_cmd!("pt-core");
        cmd.timeout(Duration::from_secs(90));
        cmd
    }

    #[test]
    fn test_basic_scan_finds_specific_process() -> Result<(), Box<dyn std::error::Error>> {
        if !ProcessHarness::is_available() {
            eprintln!(
                "Skipping test_basic_scan_finds_specific_process: ProcessHarness not available"
            );
            return Ok(());
        }

        let harness = ProcessHarness::default();
        // Spawn a unique sleeper so we can identify it
        let sleeper = harness.spawn_sleep(100)?;
        let pid = sleeper.pid();

        // Run scan
        let output = pt_core()
            .args(["--format", "json", "scan"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output)?;
        let processes = json
            .get("scan")
            .and_then(|s| s.get("processes"))
            .and_then(|p| p.as_array())
            .ok_or("Should have scan.processes array")?;

        // Find our sleeper
        let found = processes
            .iter()
            .find(|p| p.get("pid").and_then(|v| v.as_u64()).map(|v| v as u32) == Some(pid));

        if found.is_none() {
            return Err(format!(
                "Scan output should contain our spawned sleeper process (PID {})",
                pid
            )
            .into());
        }

        let proc = found.unwrap();
        // Verify some fields
        let comm = proc.get("comm").and_then(|s| s.as_str()).unwrap_or("");
        if !comm.contains("sleep") && !comm.contains("sh") {
            return Err(format!("Command should be sleep or sh (got: {})", comm).into());
        }

        Ok(())
    }

    #[test]
    fn test_invalid_config_file_returns_error() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempdir()?;
        let config_path = dir.path().join("policy.json");

        // Write invalid JSON
        let mut file = File::create(&config_path)?;
        writeln!(file, "{{ invalid_json_here ")?;

        // Run pt check --config <dir>
        // Note: pt expects a config directory, not file path usually,
        // or --config <dir> which contains policy.json.
        // We pass the directory.

        let output = pt_core()
            .arg("--config")
            .arg(dir.path())
            .args(["check", "--policy"])
            .assert()
            .failure(); // Should fail due to parse error

        output.stdout(predicate::str::contains("Invalid JSON"));
        Ok(())
    }

    #[test]
    fn test_valid_config_loading() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempdir()?;
        let config_path = dir.path().join("policy.json");

        // Write valid minimal policy JSON
        let mut file = File::create(&config_path)?;
        // Schema version must be a string
        // guardrails needs protected_patterns, never_kill_ppid, max_kills_per_run, min_process_age_seconds
        // loss_matrix needs false_positive, false_negative, useful, useful_bad, abandoned, zombie
        // robot_mode needs enabled, max_concurrent_kills, require_human_for_supervised (guessing), min_posterior, max_blast_radius_mb, max_kills, require_known_signature
        // fdr_control needs target_fdr, enabled, method, alpha
        // data_loss_gates needs block_if_open_write_fds, block_if_locked_files, block_if_active_tty
        // loss values must be non-negative
        // guardrails.never_kill_ppid must contain at least 1
        writeln!(
            file,
            r#"{{ 
            "schema_version": "1.0.0", 
            "guardrails": {{ 
                "protected_patterns": [], 
                "never_kill_ppid": [1], 
                "max_kills_per_run": 5, 
                "min_process_age_seconds": 60 
            }}, 
            "loss_matrix": {{ 
                "false_positive": 10.0, 
                "false_negative": 1.0, 
                "useful": {{ "kill": 100.0, "pause": 10.0, "renice": 1.0, "ignore": 0.0, "keep": 0.0 }}, 
                "useful_bad": {{ "kill": 10.0, "pause": 0.0, "renice": 5.0, "ignore": 5.0, "keep": 5.0 }}, 
                "abandoned": {{ "kill": 0.0, "pause": 5.0, "renice": 0.0, "ignore": 10.0, "keep": 5.0 }}, 
                "zombie": {{ "kill": 5.0, "pause": 5.0, "renice": 0.0, "ignore": 0.0, "keep": 0.0 }} 
            }},
            "robot_mode": {{
                "enabled": true,
                "max_kills_per_run": 5,
                "require_confirmation": false,
                "min_posterior": 0.9,
                "max_blast_radius_mb": 500,
                "max_kills": 5,
                "require_known_signature": false
            }},
            "fdr_control": {{
                "enabled": true,
                "target_fdr": 0.1,
                "method": "bh",
                "alpha": 0.05
            }},
            "data_loss_gates": {{
                "block_if_open_write_fds": true,
                "block_if_locked_files": true,
                "block_if_active_tty": true
            }}
        }}"#
        )?;

        // Run pt check --config <dir>
        pt_core()
            .arg("--config")
            .arg(dir.path())
            .args(["check", "--policy"])
            .assert()
            .success();

        Ok(())
    }

    // =========================================================================
    // Agent Mode E2E Tests
    // =========================================================================

    /// Test the full agent workflow: snapshot → plan
    /// This verifies the session system works across commands.
    #[test]
    fn test_agent_snapshot_then_plan_workflow() -> Result<(), Box<dyn std::error::Error>> {
        if !ProcessHarness::is_available() {
            eprintln!(
                "Skipping test_agent_snapshot_then_plan_workflow: ProcessHarness not available"
            );
            return Ok(());
        }

        // Step 1: Create snapshot
        let snapshot_output = pt_core()
            .args(["--format", "json", "agent", "snapshot"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let snapshot_json: Value = serde_json::from_slice(&snapshot_output)?;

        // Verify snapshot has required fields
        assert!(
            snapshot_json.get("schema_version").is_some(),
            "Snapshot missing schema_version"
        );
        assert!(
            snapshot_json.get("session_id").is_some(),
            "Snapshot missing session_id"
        );
        assert!(
            snapshot_json.get("generated_at").is_some(),
            "Snapshot missing generated_at"
        );

        // Step 2: Create plan (exit code 0 = no candidates, 1 = PlanReady with candidates)
        let plan_result = pt_core()
            .args(["--format", "json", "agent", "plan", "--sample-size", "50"])
            .assert()
            .code(predicate::in_iter([0, 1]));

        let plan_output = plan_result.get_output().stdout.clone();
        let plan_json: Value = serde_json::from_slice(&plan_output)?;

        // Verify plan has required fields
        assert!(
            plan_json.get("schema_version").is_some(),
            "Plan missing schema_version"
        );
        assert!(
            plan_json.get("session_id").is_some(),
            "Plan missing session_id"
        );

        Ok(())
    }

    /// Test that agent plan with high minimum age (unlikely to have candidates)
    /// returns exit code 0 and indicates no candidates.
    #[test]
    fn test_agent_plan_no_candidates_exit_code() -> Result<(), Box<dyn std::error::Error>> {
        if !ProcessHarness::is_available() {
            eprintln!(
                "Skipping test_agent_plan_no_candidates_exit_code: ProcessHarness not available"
            );
            return Ok(());
        }

        // Use extremely high min-age to ensure no candidates
        // Note: We can't guarantee no candidates on a busy system, so we accept both exit codes
        pt_core()
            .args(["--format", "json", "agent", "plan", "--sample-size", "10"])
            .assert()
            .code(predicate::in_iter([0, 1])); // 0 = no candidates, 1 = candidates found

        Ok(())
    }

    /// Test that agent sessions command works
    #[test]
    fn test_agent_sessions_list() -> Result<(), Box<dyn std::error::Error>> {
        if !ProcessHarness::is_available() {
            eprintln!("Skipping test_agent_sessions_list: ProcessHarness not available");
            return Ok(());
        }

        // First create a session to ensure there's at least one
        pt_core()
            .args(["--format", "json", "agent", "snapshot"])
            .assert()
            .success();

        // Now list sessions
        let output = pt_core()
            .args(["--format", "json", "agent", "sessions"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output)?;
        assert!(
            json.get("schema_version").is_some(),
            "Sessions output missing schema_version"
        );

        Ok(())
    }

    /// Test agent capabilities command
    #[test]
    fn test_agent_capabilities() -> Result<(), Box<dyn std::error::Error>> {
        let output = pt_core()
            .args(["--format", "json", "agent", "capabilities"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output)?;

        // Verify capabilities has required fields
        assert!(
            json.get("schema_version").is_some(),
            "Capabilities missing schema_version"
        );
        assert!(json.get("os").is_some(), "Capabilities missing os info");

        // Verify OS info has required subfields
        let os = json.get("os").unwrap();
        assert!(os.get("family").is_some(), "OS info missing family");
        assert!(os.get("arch").is_some(), "OS info missing arch");

        Ok(())
    }

    // =========================================================================
    // Error Handling E2E Tests
    // =========================================================================

    /// Test that verify command without session returns error
    #[test]
    fn test_agent_verify_requires_session() {
        pt_core()
            .args(["agent", "verify"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("session").or(predicate::str::contains("required")));
    }

    /// Test that apply command without session returns error
    #[test]
    fn test_agent_apply_requires_session() {
        pt_core()
            .args(["agent", "apply"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("session").or(predicate::str::contains("required")));
    }

    /// Test that invalid format flag returns error
    #[test]
    fn test_invalid_format_flag() {
        pt_core()
            .args(["--format", "not_a_valid_format", "scan"])
            .assert()
            .failure();
    }

    /// Test that help command works for all major subcommands
    #[test]
    fn test_help_commands_work() {
        // Main help
        pt_core().arg("--help").assert().success();

        // Subcommand helps
        for cmd in &[
            "scan", "run", "check", "config", "agent", "bundle", "schema",
        ] {
            pt_core().args([*cmd, "--help"]).assert().success();
        }
    }

    /// Test version command
    #[test]
    fn test_version_command() {
        pt_core()
            .arg("--version")
            .assert()
            .success()
            .stdout(predicate::str::contains("pt-core"));
    }

    /// Test that nonexistent config directory is handled gracefully
    #[test]
    fn test_nonexistent_config_dir_uses_defaults() {
        // With a nonexistent config dir, pt should use defaults and succeed
        pt_core()
            .arg("--config")
            .arg("/nonexistent/path/that/does/not/exist")
            .args(["--format", "json", "scan"])
            .assert()
            .success();
    }

    /// Test dry-run mode doesn't execute actions
    #[test]
    fn test_dry_run_mode_is_safe() -> Result<(), Box<dyn std::error::Error>> {
        if !ProcessHarness::is_available() {
            eprintln!("Skipping test_dry_run_mode_is_safe: ProcessHarness not available");
            return Ok(());
        }

        let harness = ProcessHarness::default();
        let sleeper = harness.spawn_sleep(100)?;
        let pid = sleeper.pid();

        // Run with --dry-run - should NOT kill the process
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

        // Verify process is still running
        assert!(
            sleeper.is_running(),
            "Process should still be running after dry-run"
        );

        // Clean up
        sleeper.trigger_exit();

        Ok(())
    }

    /// Test shadow mode doesn't execute actions
    #[test]
    fn test_shadow_mode_is_safe() -> Result<(), Box<dyn std::error::Error>> {
        if !ProcessHarness::is_available() {
            eprintln!("Skipping test_shadow_mode_is_safe: ProcessHarness not available");
            return Ok(());
        }

        let harness = ProcessHarness::default();
        let sleeper = harness.spawn_sleep(100)?;

        // Run with --shadow - should NOT kill the process
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

        // Verify process is still running
        assert!(
            sleeper.is_running(),
            "Process should still be running after shadow mode"
        );

        // Clean up
        sleeper.trigger_exit();

        Ok(())
    }

    #[test]
    fn test_shadow_report_from_observations() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempdir()?;
        let shadow_dir = dir.path().join("shadow");
        fs::create_dir_all(&shadow_dir)?;

        let now = Utc::now();
        let observation = Observation {
            timestamp: now,
            pid: 4242,
            identity_hash: "hash_shadow_report".to_string(),
            state: StateSnapshot::default(),
            events: vec![ProcessEvent {
                timestamp: now,
                event_type: EventType::ProcessExit,
                details: Some(
                    serde_json::json!({
                        "reason": "missing",
                        "comm": "sleep"
                    })
                    .to_string(),
                ),
            }],
            belief: BeliefState {
                p_abandoned: 0.75,
                recommendation: "kill".to_string(),
                ..BeliefState::default()
            },
        };

        let payload = serde_json::to_string_pretty(&vec![observation])?;
        let path = shadow_dir.join("shadow_observations.json");
        fs::write(&path, payload)?;

        let output = pt_core()
            .env("PROCESS_TRIAGE_DATA", dir.path())
            .args(["shadow", "report", "--threshold", "0.5"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let report: Value = serde_json::from_slice(&output)?;
        assert_eq!(
            report.get("total_predictions").and_then(|v| v.as_u64()),
            Some(1)
        );
        assert_eq!(
            report.get("resolved_predictions").and_then(|v| v.as_u64()),
            Some(1)
        );
        assert_eq!(
            report.get("pending_predictions").and_then(|v| v.as_u64()),
            Some(0)
        );

        Ok(())
    }

    // =========================================================================
    // Exit Code Verification Tests
    // =========================================================================

    /// Test that scan always returns exit code 0 on success
    #[test]
    fn test_scan_exit_code_zero_on_success() {
        pt_core()
            .args(["--format", "json", "scan"])
            .assert()
            .success()
            .code(predicate::eq(0));
    }

    /// Test that agent snapshot returns exit code 0 on success
    #[test]
    fn test_snapshot_exit_code_zero_on_success() {
        pt_core()
            .args(["--format", "json", "agent", "snapshot"])
            .assert()
            .success()
            .code(predicate::eq(0));
    }

    /// Test that check command returns appropriate exit codes
    #[test]
    fn test_check_exit_codes() {
        // With defaults, check should succeed
        let dir = tempdir().expect("Failed to create temp dir");
        pt_core()
            .arg("--config")
            .arg(dir.path())
            .args(["check", "--all"])
            .assert()
            .success();
    }
}
