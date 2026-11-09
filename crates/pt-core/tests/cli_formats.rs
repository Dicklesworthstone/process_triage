//! CLI output format tests for pt-core.
//!
//! These tests verify that output formats work correctly and produce
//! valid, parseable output.

use assert_cmd::cargo::cargo_bin_cmd;
use assert_cmd::Command;
use predicates::prelude::*;

/// Get a Command for pt-core binary.
fn pt_core() -> Command {
    cargo_bin_cmd!("pt-core")
}

mod replay_recording {
    use super::*;

    // Retain captures for inspection; these tests never delete capture evidence.
    fn capture_dir() -> std::path::PathBuf {
        tempfile::tempdir().expect("capture directory").keep()
    }

    struct CaptureCase {
        root: std::path::PathBuf,
        config: std::path::PathBuf,
        data: std::path::PathBuf,
    }

    impl CaptureCase {
        fn new() -> Self {
            let root = capture_dir();
            let config = root.join("config");
            let data = root.join("data");
            std::fs::create_dir_all(&config).expect("isolated capture configuration");
            std::fs::create_dir_all(&data).expect("isolated capture data");
            Self { root, config, data }
        }

        fn command(&self) -> Command {
            let mut command = pt_core();
            command
                .env_remove("PT_CONFIG_DIR")
                .env_remove("PT_SKIP_GLOBAL_LOCK")
                .env("PROCESS_TRIAGE_CONFIG", &self.config)
                .env("PROCESS_TRIAGE_DATA", &self.data)
                .env("PROCESS_TRIAGE_RETENTION", "off")
                .arg("--config")
                .arg(&self.config)
                .timeout(std::time::Duration::from_secs(120));
            command
        }

        fn record_command(&self, path: &std::path::Path) -> Command {
            let mut command = self.command();
            command
                .args([
                    "scan",
                    "--format",
                    "json",
                    "--robot",
                    "--record-replay-window-ms",
                    "0",
                    "--record-replay",
                ])
                .arg(path);
            command
        }

        fn record(&self, path: &std::path::Path) -> serde_json::Value {
            let output = self
                .record_command(path)
                .assert()
                .success()
                .get_output()
                .stdout
                .clone();
            serde_json::from_slice(&output).expect("live capture scan JSON")
        }

        fn replay(&self, path: &std::path::Path, format: &str) -> std::process::Output {
            self.command()
                .args(["scan", "--robot", "--format", format, "--replay-scores"])
                .arg(path)
                .assert()
                .success()
                .get_output()
                .clone()
        }

        fn write_policy(&self, policy: &pt_core::config::Policy) {
            std::fs::write(
                self.config.join("policy.json"),
                serde_json::to_vec_pretty(policy).expect("capture policy JSON"),
            )
            .expect("write isolated capture policy");
        }
    }

    fn assert_complete_scoring_census(
        output: &serde_json::Value,
        inventory: &serde_json::Value,
    ) {
        assert!(output["schema_version"].is_string(), "{output}");
        assert_eq!(output["command"], "scan replay-scores");
        let replay = &output["replay"];
        assert_eq!(replay["scoring_only"], true);
        assert_eq!(
            replay["configuration_scope"],
            "current_configuration_and_current_learned_verdict_decay"
        );
        assert_eq!(replay["requested_window_ms"], 0);
        assert!(replay["limitations"].as_array().is_some_and(|items| !items.is_empty()));

        let expected = inventory.as_array().expect("recorded scan census");
        let rows = replay["processes"].as_array().expect("scoring census");
        assert_eq!(replay["population_size"].as_u64(), Some(expected.len() as u64));
        assert_eq!(rows.len(), expected.len(), "no protected or unavailable row is dropped");
        let mut counted = 0;
        for (status, counter) in [
            ("scored", "scored_count"),
            ("protected", "protected_count"),
            ("too_young", "too_young_count"),
            ("unavailable", "unavailable_count"),
        ] {
            let actual = rows.iter().filter(|row| row["status"] == status).count() as u64;
            assert_eq!(replay[counter].as_u64(), Some(actual), "{counter}: {replay}");
            counted += actual;
        }
        assert_eq!(counted, expected.len() as u64);
        for process in expected {
            let row = rows
                .iter()
                .find(|row| row["pid"] == process["pid"])
                .expect("every recorded PID remains in the scoring denominator");
            assert_eq!(row["start_id"], process["start_id"]);
            assert_eq!(row["uid"], process["uid"]);
            if row["status"] == "scored" {
                assert!(row["posterior"].is_object(), "{row}");
                assert!(!row["ledger"].is_null(), "{row}");
            } else {
                assert!(row["posterior"].is_null(), "{row}");
                assert!(row["ledger"].is_null(), "{row}");
                if row["status"] == "protected" {
                    assert!(row["protection"].is_object(), "{row}");
                } else {
                    assert!(row["reason"].is_string(), "{row}");
                }
            }
            assert!(row.get("recommended_action").is_none(), "{row}");
        }
        assert!(output.get("actions").is_none());
        assert!(replay.get("actions").is_none());
    }

    #[test]
    fn quick_scan_records_the_exact_live_inventory_for_native_replay() {
        let case = CaptureCase::new();
        let path = case.root.join("scan.json");
        let displayed = case.record(&path);
        let snapshot = pt_core::replay::load_snapshot(&path).expect("native snapshot loader");
        assert!(
            !snapshot.processes.is_empty(),
            "a live scan must contain processes"
        );
        assert_eq!(
            serde_json::to_value(&snapshot.processes).expect("recorded inventory"),
            displayed["scan"]["processes"]
        );
        assert_eq!(
            snapshot.scan_metadata.process_count,
            snapshot.processes.len()
        );
        assert_eq!(
            Some(snapshot.context.platform.as_str()),
            displayed["scan"]["metadata"]["platform"].as_str()
        );
        let restored = snapshot.to_scan_result();
        assert_eq!(
            serde_json::to_value(&restored.processes).expect("restored inventory"),
            displayed["scan"]["processes"]
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path)
                .expect("capture metadata")
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o077,
                0,
                "capture must not expose raw commands to other users"
            );
        }
    }

    #[test]
    fn replay_recording_preserves_an_existing_capture() {
        let case = CaptureCase::new();
        let path = case.root.join("existing.json");
        let original = b"useful earlier capture\n";
        std::fs::write(&path, original).expect("existing capture");
        case.record_command(&path)
            .assert()
            .code(21)
            .stderr(predicate::str::contains("replay recording failed"));
        assert_eq!(
            std::fs::read(&path).expect("preserved capture"),
            original.as_slice()
        );
    }

    #[test]
    fn deep_scan_cannot_silently_ignore_replay_recording() {
        let case = CaptureCase::new();
        let path = case.root.join("unsupported.json");
        case.command()
            .args(["scan", "--deep", "--record-replay"])
            .arg(&path)
            .assert()
            .failure()
            .stderr(predicate::str::contains("cannot be used with"));
        assert!(
            !path.exists(),
            "an unsupported recording must not create a file"
        );
    }

    #[cfg(unix)]
    #[test]
    fn replay_recording_never_follows_an_existing_symlink() {
        let case = CaptureCase::new();
        let target = case.root.join("valuable.json");
        let link = case.root.join("capture.json");
        let original = b"useful work behind a symlink\n";
        std::fs::write(&target, original).expect("target capture");
        std::os::unix::fs::symlink(&target, &link).expect("capture symlink");
        case.record_command(&link).assert().code(21);
        assert_eq!(
            std::fs::read(&target).expect("preserved target"),
            original.as_slice()
        );
        assert!(std::fs::symlink_metadata(&link)
            .expect("preserved link")
            .file_type()
            .is_symlink());
    }

    #[cfg(unix)]
    #[test]
    fn scoring_replay_keeps_exited_targets_and_uses_current_policy_without_actions() {
        struct ChildGuard(std::process::Child);
        impl ChildGuard {
            fn spawn() -> Self {
                Self(
                    std::process::Command::new("sleep")
                        .arg("631")
                        .env_clear()
                        .stdin(std::process::Stdio::null())
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .spawn()
                        .expect("owned replay target"),
                )
            }
        }
        impl Drop for ChildGuard {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        let case = CaptureCase::new();
        // This configuration exercises scoring only; no action runner is invoked.
        // It admits the owned target even on a root worker or inside a CI service
        // cgroup, without altering any observation in the retained capture.
        let mut policy = pt_core::config::Policy::default();
        policy.guardrails.builtin_protection = false;
        policy.guardrails.protected_users.clear();
        policy.guardrails.protected_patterns.clear();
        policy.guardrails.never_kill_pid.clear();
        policy.guardrails.never_kill_ppid.clear();
        policy.guardrails.min_process_age_seconds = 0;
        case.write_policy(&policy);

        let mut target = ChildGuard::spawn();
        let pid = target.0.id();
        let path = case.root.join("owned-process.json");
        let captured = case.record(&path);
        assert!(target.0.try_wait().expect("target alive during capture").is_none());
        let original = std::fs::read(&path).expect("retained capture bytes");
        let inventory = &captured["scan"]["processes"];
        let recorded = inventory
            .as_array()
            .unwrap()
            .iter()
            .find(|process| process["pid"].as_u64() == Some(u64::from(pid)))
            .expect("live owned target was captured");

        let before: serde_json::Value =
            serde_json::from_slice(&case.replay(&path, "json").stdout)
                .expect("scoring replay JSON");
        assert_complete_scoring_census(&before, inventory);
        let before_row = before["replay"]["processes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["pid"].as_u64() == Some(u64::from(pid)))
            .unwrap();
        assert_eq!(before_row["status"], "scored", "{before_row}");
        assert_eq!(before_row["start_id"], recorded["start_id"]);
        assert!(target.0.try_wait().expect("scoring never signals targets").is_none());

        target.0.kill().expect("end only the owned source process");
        target.0.wait().expect("reap owned source process");
        // A new live process is unrelated to the recorded denominator. It also
        // detects an accidental action side effect while replaying stale PIDs.
        let mut sentinel = ChildGuard::spawn();
        let after: serde_json::Value =
            serde_json::from_slice(&case.replay(&path, "json").stdout)
                .expect("offline scoring JSON");
        assert_complete_scoring_census(&after, inventory);
        assert_eq!(
            after["replay"]["processes"],
            before["replay"]["processes"],
            "live process exit must not change a recorded scoring input"
        );
        assert!(sentinel.0.try_wait().expect("sentinel survives replay").is_none());

        policy.guardrails.min_process_age_seconds = u64::MAX;
        case.write_policy(&policy);
        let current: serde_json::Value =
            serde_json::from_slice(&case.replay(&path, "json").stdout)
                .expect("current-policy replay");
        assert_complete_scoring_census(&current, inventory);
        let current_row = current["replay"]["processes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["pid"].as_u64() == Some(u64::from(pid)))
            .unwrap();
        assert_eq!(current_row["status"], "too_young", "{current_row}");
        assert_eq!(current_row["start_id"], recorded["start_id"]);
        assert!(current_row["posterior"].is_null());
        assert!(current_row["ledger"].is_null());
        assert!(sentinel.0.try_wait().expect("policy replay is read-only").is_none());
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }

    #[test]
    fn scoring_replay_jsonl_preserves_the_census_and_rejects_incomplete_context() {
        let case = CaptureCase::new();
        let path = case.root.join("scoring.json");
        let captured = case.record(&path);
        let original = std::fs::read(&path).expect("captured bytes");
        let output = case.replay(&path, "jsonl");
        let text = String::from_utf8(output.stdout).expect("JSONL UTF-8");
        let lines: Vec<_> = text.lines().filter(|line| !line.trim().is_empty()).collect();
        assert_eq!(lines.len(), 1, "JSONL emits one complete record: {text}");
        let report: serde_json::Value = serde_json::from_str(lines[0]).expect("one JSONL record");
        assert_complete_scoring_census(&report, &captured["scan"]["processes"]);

        let snapshot: serde_json::Value =
            serde_json::from_slice(&original).expect("capture document");
        let mut legacy = snapshot.clone();
        assert!(legacy.as_object_mut().unwrap().remove("scoring_context").is_some());
        let legacy_path = case.root.join("inventory-only.json");
        std::fs::write(&legacy_path, serde_json::to_vec_pretty(&legacy).unwrap()).unwrap();
        case.command()
            .args(["scan", "--format", "json", "--replay-scores"])
            .arg(&legacy_path)
            .assert()
            .failure()
            .stderr(predicate::str::contains("inventory-only snapshot"));

        let mut partial = snapshot;
        let contexts = partial["scoring_context"]["processes"]
            .as_object_mut()
            .expect("per-process scoring context");
        let removed_pid = contexts.keys().next().expect("nonempty census").clone();
        contexts.remove(&removed_pid);
        let partial_path = case.root.join("missing-process-context.json");
        std::fs::write(&partial_path, serde_json::to_vec_pretty(&partial).unwrap()).unwrap();
        case.command()
            .args(["scan", "--format", "jsonl", "--replay-scores"])
            .arg(&partial_path)
            .assert()
            .failure()
            .stderr(predicate::str::contains("complete recorded census"));
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }

    #[test]
    fn replay_capture_window_requires_recording_and_a_bounded_value() {
        let case = CaptureCase::new();
        case.command()
            .args(["scan", "--record-replay-window-ms", "0"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("--record-replay"));
        let path = case.root.join("invalid-window.json");
        case.command()
            .args([
                "scan",
                "--record-replay-window-ms",
                "60001",
                "--record-replay",
            ])
            .arg(&path)
            .assert()
            .failure()
            .stderr(predicate::str::contains("--record-replay-window-ms"));
        assert!(!path.exists());
    }

    #[test]
    fn reviewed_capture_cli_preserves_unknowns_and_compares_explicit_configurations() {
        let case = CaptureCase::new();
        let snapshot_path = case.root.join("review-source.json");
        let captured = case.record(&snapshot_path);
        let labels_path = case.root.join("review-labels.json");
        case.command()
            .args(["replay", "label-template", "--snapshot"])
            .arg(&snapshot_path)
            .arg("--output")
            .arg(&labels_path)
            .args(["--host-id", "owned-cli-fixture", "--split", "holdout"])
            .assert()
            .success();
        let original = std::fs::read(&labels_path).expect("private review template");
        let labels: serde_json::Value =
            serde_json::from_slice(&original).expect("review template JSON");
        let rows = labels["processes"].as_array().expect("complete review census");
        let inventory = captured["scan"]["processes"].as_array().unwrap();
        assert_eq!(rows.len(), inventory.len());
        assert_eq!(labels["host_id"], "owned-cli-fixture");
        assert_eq!(labels["split"], "holdout");
        for process in inventory {
            let row = rows.iter().find(|row| row["pid"] == process["pid"]).unwrap();
            assert_eq!(row["start_id"], process["start_id"]);
            assert_eq!(row["uid"], process["uid"]);
            assert_eq!(row["cmd"], process["cmd"]);
            for field in ["verdict", "reviewer", "reviewed_at", "rationale"] {
                assert!(row.get(field).is_some_and(serde_json::Value::is_null));
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&labels_path).unwrap().permissions().mode() & 0o077,
                0
            );
        }

        // Creating a second template must preserve the reviewer's existing work.
        case.command()
            .args(["replay", "label-template", "--snapshot"])
            .arg(&snapshot_path)
            .arg("--output")
            .arg(&labels_path)
            .args(["--host-id", "owned-cli-fixture", "--split", "holdout"])
            .assert()
            .failure();
        assert_eq!(std::fs::read(&labels_path).unwrap(), original);

        let baseline_config = case.root.join("baseline-config");
        std::fs::create_dir(&baseline_config).unwrap();
        let mut policy = pt_core::config::Policy::default();
        policy.guardrails.min_process_age_seconds = u64::MAX;
        case.write_policy(&policy);
        let output = case.command()
            .args(["replay", "evaluate", "--snapshot"])
            .arg(&snapshot_path)
            .arg("--labels")
            .arg(&labels_path)
            .arg("--baseline-config")
            .arg(&baseline_config)
            .args(["--format", "jsonl"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let text = String::from_utf8(output).unwrap();
        assert_eq!(text.lines().count(), 1, "comparison JSONL is one complete record");
        let output: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(output["command"], "replay evaluate");
        let comparison = &output["comparison"];
        assert_eq!(comparison["scoring_only"], true);
        assert_eq!(comparison["snapshot_sha256"], labels["snapshot_sha256"]);
        assert_eq!(comparison["coverage"]["population_size"], rows.len());
        assert_eq!(comparison["coverage"]["reviewed_count"], 0);
        assert_eq!(comparison["coverage"]["unlabeled_count"], rows.len());
        assert!(comparison["paired_metrics"].is_null());
        assert!(comparison["metrics_unavailable_reason"].is_string());
        assert_ne!(
            comparison["baseline"]["configuration_sha256"],
            comparison["candidate"]["configuration_sha256"]
        );
        assert!(comparison.get("actions").is_none());

        // Omitting a hard-to-score process must fail, not shrink the denominator.
        let mut incomplete = labels;
        incomplete["processes"].as_array_mut().unwrap().pop();
        let incomplete_path = case.root.join("incomplete-review.json");
        std::fs::write(&incomplete_path, serde_json::to_vec(&incomplete).unwrap()).unwrap();
        case.command()
            .args(["replay", "evaluate", "--snapshot"])
            .arg(&snapshot_path)
            .arg("--labels")
            .arg(&incomplete_path)
            .arg("--baseline-config")
            .arg(&baseline_config)
            .assert()
            .failure();
        assert_eq!(std::fs::read(&labels_path).unwrap(), original);

        // An unreadable incumbent must not silently become a built-in-only model.
        let signatures_path = baseline_config.join("signatures.json");
        let corrupt_signatures = b"{ incomplete signature configuration";
        std::fs::write(&signatures_path, corrupt_signatures).unwrap();
        case.command()
            .args(["replay", "evaluate", "--snapshot"])
            .arg(&snapshot_path)
            .arg("--labels")
            .arg(&labels_path)
            .arg("--baseline-config")
            .arg(&baseline_config)
            .assert()
            .failure()
            .stderr(predicate::str::contains("baseline model could not be loaded completely"));
        assert_eq!(std::fs::read(&signatures_path).unwrap(), corrupt_signatures);
        assert_eq!(std::fs::read(&labels_path).unwrap(), original);
    }
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
    fn toon_format_accepted() {
        pt_core()
            .args(["--format", "toon", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn short_format_flag_accepted() {
        pt_core().args(["-f", "json", "--help"]).assert().success();
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
        pt_core().args(["-v", "--help"]).assert().success();
    }

    #[test]
    fn multiple_verbose_flags_accepted() {
        pt_core().args(["-vvv", "--help"]).assert().success();
    }

    #[test]
    fn quiet_flag_accepted() {
        pt_core().args(["-q", "--help"]).assert().success();
    }

    #[test]
    fn no_color_flag_accepted() {
        pt_core().args(["--no-color", "--help"]).assert().success();
    }

    #[test]
    fn robot_flag_accepted() {
        pt_core().args(["--robot", "--help"]).assert().success();
    }

    #[test]
    fn dry_run_flag_accepted() {
        pt_core().args(["--dry-run", "--help"]).assert().success();
    }

    #[test]
    fn shadow_flag_accepted() {
        pt_core().args(["--shadow", "--help"]).assert().success();
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
