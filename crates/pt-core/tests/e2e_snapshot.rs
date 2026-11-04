//! End-to-end tests for agent snapshot workflow.
//!
//! Tests the `agent snapshot` command which creates session snapshots
//! for later comparison and verification.

use assert_cmd::cargo::cargo_bin_cmd;
use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use std::time::Duration;

/// Get a Command for pt-core binary.
fn pt_core() -> Command {
    let mut cmd = cargo_bin_cmd!("pt-core");
    cmd.timeout(Duration::from_secs(30));
    cmd
}

// ============================================================================
// Basic Snapshot Tests
// ============================================================================

mod snapshot_basic {
    use super::*;

    #[test]
    fn snapshot_runs_without_error() {
        pt_core().args(["agent", "snapshot"]).assert().success();
    }

    #[test]
    fn snapshot_with_json_format() {
        pt_core()
            .args(["--format", "json", "agent", "snapshot"])
            .assert()
            .success()
            .stdout(predicate::str::contains("schema_version"))
            .stdout(predicate::str::contains("session_id"));
    }

    #[test]
    fn snapshot_produces_valid_json() {
        let output = pt_core()
            .args(["--format", "json", "agent", "snapshot"])
            .assert()
            .success()
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
    fn snapshot_with_label() {
        pt_core()
            .args(["agent", "snapshot", "--label", "test-snapshot"])
            .assert()
            .success();
    }
}

// ============================================================================
// Output Format Tests
// ============================================================================

mod snapshot_formats {
    use super::*;

    #[test]
    fn snapshot_json_format() {
        pt_core()
            .args(["--format", "json", "agent", "snapshot"])
            .assert()
            .success()
            .stdout(predicate::str::starts_with("{"));
    }

    #[test]
    fn snapshot_summary_format() {
        pt_core()
            .args(["--format", "summary", "agent", "snapshot"])
            .assert()
            .success()
            .stdout(predicate::str::contains("agent snapshot"));
    }

    #[test]
    fn snapshot_prose_format() {
        pt_core()
            .args(["--format", "prose", "agent", "snapshot"])
            .assert()
            .success()
            .stdout(predicate::str::contains("pt-core"));
    }

    #[test]
    fn snapshot_exitcode_format() {
        // Exitcode format produces no output on success
        pt_core()
            .args(["--format", "exitcode", "agent", "snapshot"])
            .assert()
            .success()
            .stdout(predicate::str::is_empty());
    }
}

// ============================================================================
// Schema Validation Tests
// ============================================================================

mod snapshot_schema {
    use super::*;

    #[test]
    fn snapshot_has_schema_version() {
        let output = pt_core()
            .args(["--format", "json", "agent", "snapshot"])
            .assert()
            .success()
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
    fn snapshot_session_id_is_valid() {
        let output = pt_core()
            .args(["--format", "json", "agent", "snapshot"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).unwrap();
        let session_id = json
            .get("session_id")
            .expect("Missing session_id")
            .as_str()
            .expect("session_id should be string");

        // Session ID should be non-empty and have reasonable format
        assert!(!session_id.is_empty(), "Session ID should not be empty");
        assert!(
            session_id.len() >= 8,
            "Session ID seems too short: {}",
            session_id
        );
    }

    #[test]
    fn snapshot_generated_at_is_iso8601() {
        let output = pt_core()
            .args(["--format", "json", "agent", "snapshot"])
            .assert()
            .success()
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
}

// ============================================================================
// Integration Tests
// ============================================================================

mod snapshot_integration {
    use super::*;

    #[test]
    fn consecutive_snapshots_have_different_session_ids() {
        let output1 = pt_core()
            .args(["--format", "json", "agent", "snapshot"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let output2 = pt_core()
            .args(["--format", "json", "agent", "snapshot"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json1: Value = serde_json::from_slice(&output1).unwrap();
        let json2: Value = serde_json::from_slice(&output2).unwrap();

        let id1 = json1.get("session_id").unwrap().as_str().unwrap();
        let id2 = json2.get("session_id").unwrap().as_str().unwrap();

        assert_ne!(id1, id2, "Each snapshot should have unique session ID");
    }

    #[test]
    fn snapshot_with_verbose_flag() {
        pt_core()
            .args(["-v", "--format", "json", "agent", "snapshot"])
            .assert()
            .success();
    }

    #[test]
    fn snapshot_with_quiet_flag() {
        pt_core()
            .args(["-q", "--format", "json", "agent", "snapshot"])
            .assert()
            .success();
    }

    #[test]
    fn snapshot_with_standalone_flag() {
        pt_core()
            .args(["--standalone", "--format", "json", "agent", "snapshot"])
            .assert()
            .success();
    }
}

// ============================================================================
// Error Handling Tests
// ============================================================================

mod snapshot_errors {
    use super::*;

    #[test]
    fn snapshot_with_invalid_format_fails() {
        pt_core()
            .args(["--format", "invalid_format", "agent", "snapshot"])
            .assert()
            .failure();
    }

    #[test]
    fn snapshot_help_works() {
        pt_core()
            .args(["agent", "snapshot", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("snapshot"));
    }
}

mod snapshot_policy_safety {
    use super::*;
    use pt_core::config::Policy;
    use pt_core::exit_codes::ExitCode;
    use std::fs;
    use std::path::Path;
    use tempfile::TempDir;

    fn snapshot_command(config: &Path, data: &Path) -> Command {
        let mut cmd = pt_core();
        cmd.timeout(Duration::from_secs(120))
            .env("PROCESS_TRIAGE_DATA", data)
            .env("PROCESS_TRIAGE_RETENTION", "off")
            .env("PT_SKIP_GLOBAL_LOCK", "1")
            .arg("--config")
            .arg(config)
            .args(["--format", "json", "agent", "snapshot"]);
        cmd
    }

    #[cfg(unix)]
    #[test]
    fn snapshot_keeps_young_process_in_inventory_without_action_advice() {
        struct OwnedChild(std::process::Child);
        impl Drop for OwnedChild {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        let child = OwnedChild(
            std::process::Command::new("sleep")
                .arg("300")
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("spawn owned process"),
        );
        let config = TempDir::new().expect("config directory");
        let data = TempDir::new().expect("data directory");
        let mut policy = Policy::default();
        // Isolate the age gate even when the test runner is root or supervised.
        policy.guardrails.builtin_protection = false;
        policy.guardrails.protected_users.clear();
        policy.guardrails.protected_categories.clear();
        policy.guardrails.never_kill_ppid.clear();
        policy.guardrails.min_process_age_seconds = u64::MAX;
        // Inference is observable in the control run without requesting any
        // intervention or needing writable-descriptor probes on unrelated PIDs.
        for row in [
            &mut policy.loss_matrix.useful,
            &mut policy.loss_matrix.useful_bad,
            &mut policy.loss_matrix.abandoned,
            &mut policy.loss_matrix.zombie,
        ] {
            row.keep = 0.0;
            row.kill = 10.0;
            row.pause = Some(10.0);
            row.throttle = Some(10.0);
            row.restart = Some(10.0);
            row.renice = Some(10.0);
        }

        let take_snapshot = |policy: &Policy| {
            fs::write(
                config.path().join("policy.json"),
                serde_json::to_vec(policy).expect("serialize policy"),
            )
            .expect("write policy");
            let output = snapshot_command(config.path(), data.path())
                .assert()
                .success()
                .get_output()
                .stdout
                .clone();
            let response: Value = serde_json::from_slice(&output).expect("snapshot JSON");
            let session = Path::new(response["session_dir"].as_str().expect("session directory"));
            let inventory: Value = serde_json::from_slice(
                &fs::read(session.join("scan/inventory.json")).expect("persisted inventory"),
            )
            .expect("inventory JSON");
            let inference: Value = serde_json::from_slice(
                &fs::read(session.join("inference/results.json")).expect("persisted inference"),
            )
            .expect("inference JSON");
            (inventory, inference)
        };

        let (inventory, inference) = take_snapshot(&policy);
        assert!(inventory["payload"]["records"]
            .as_array()
            .expect("inventory records")
            .iter()
            .any(|record| record["pid"].as_u64() == Some(u64::from(child.0.id()))));
        assert!(inference["payload"]["candidates"]
            .as_array()
            .expect("inference candidates")
            .is_empty());

        policy.guardrails.min_process_age_seconds = 0;
        let (_, inference) = take_snapshot(&policy);
        let candidate = inference["payload"]["candidates"]
            .as_array()
            .expect("control inference candidates")
            .iter()
            .find(|record| record["pid"].as_u64() == Some(u64::from(child.0.id())))
            .expect("age-zero control must score the same owned process");
        assert_eq!(candidate["recommended_action"], "keep", "{candidate}");
    }

    #[test]
    fn snapshot_rejects_malformed_policy_instead_of_skipping_inference() {
        let config = TempDir::new().expect("config directory");
        let data = TempDir::new().expect("data directory");
        fs::write(config.path().join("policy.json"), "{ malformed policy")
            .expect("write malformed policy");
        snapshot_command(config.path(), data.path())
            .assert()
            .code(ExitCode::InternalError.as_i32())
            .stderr(predicate::str::contains("agent snapshot: config error"))
            .stdout(predicate::str::is_empty());
    }

    #[test]
    fn snapshot_rejects_invalid_force_review_rule() {
        let config = TempDir::new().expect("config directory");
        let data = TempDir::new().expect("data directory");
        let mut policy = Policy::default();
        let mut pattern = policy.guardrails.protected_patterns[0].clone();
        pattern.pattern = "[".to_string();
        policy.guardrails.force_review_patterns.push(pattern);
        fs::write(
            config.path().join("policy.json"),
            serde_json::to_vec(&policy).expect("serialize policy"),
        )
        .expect("write policy");
        snapshot_command(config.path(), data.path())
            .assert()
            .code(ExitCode::InternalError.as_i32())
            .stderr(predicate::str::contains(
                "agent snapshot: policy enforcer error",
            ))
            .stderr(predicate::str::contains("guardrails.force_review_patterns"))
            .stdout(predicate::str::is_empty());
    }
}
