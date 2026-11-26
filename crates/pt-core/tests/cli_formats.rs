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
            self.command_with_config(&self.config)
        }

        fn command_with_config(&self, config: &std::path::Path) -> Command {
            let mut command = pt_core();
            command
                .env_remove("PT_CONFIG_DIR")
                .env_remove("PT_SKIP_GLOBAL_LOCK")
                .env("PROCESS_TRIAGE_CONFIG", config)
                .env("PROCESS_TRIAGE_DATA", &self.data)
                .env("PROCESS_TRIAGE_RETENTION", "off")
                .arg("--config")
                .arg(config)
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

    fn assert_complete_scoring_census(output: &serde_json::Value, inventory: &serde_json::Value) {
        assert!(output["schema_version"].is_string(), "{output}");
        assert_eq!(output["command"], "scan replay-scores");
        let replay = &output["replay"];
        assert_eq!(replay["scoring_only"], true);
        assert_eq!(
            replay["configuration_scope"],
            "current_configuration_and_current_learned_verdict_decay"
        );
        assert_eq!(replay["requested_window_ms"], 0);
        assert!(replay["limitations"]
            .as_array()
            .is_some_and(|items| !items.is_empty()));

        let expected = inventory.as_array().expect("recorded scan census");
        let rows = replay["processes"].as_array().expect("scoring census");
        assert_eq!(
            replay["population_size"].as_u64(),
            Some(expected.len() as u64)
        );
        assert_eq!(
            rows.len(),
            expected.len(),
            "no protected or unavailable row is dropped"
        );
        let mut counted = 0;
        for (status, counter) in [
            ("scored", "scored_count"),
            ("protected", "protected_count"),
            ("too_young", "too_young_count"),
            ("unavailable", "unavailable_count"),
        ] {
            let actual = rows.iter().filter(|row| row["status"] == status).count() as u64;
            assert_eq!(
                replay[counter].as_u64(),
                Some(actual),
                "{counter}: {replay}"
            );
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
        assert!(target
            .0
            .try_wait()
            .expect("target alive during capture")
            .is_none());
        let original = std::fs::read(&path).expect("retained capture bytes");
        let inventory = &captured["scan"]["processes"];
        let recorded = inventory
            .as_array()
            .unwrap()
            .iter()
            .find(|process| process["pid"].as_u64() == Some(u64::from(pid)))
            .expect("live owned target was captured");

        let before: serde_json::Value = serde_json::from_slice(&case.replay(&path, "json").stdout)
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
        assert!(target
            .0
            .try_wait()
            .expect("scoring never signals targets")
            .is_none());

        target.0.kill().expect("end only the owned source process");
        target.0.wait().expect("reap owned source process");
        // A new live process is unrelated to the recorded denominator. It also
        // detects an accidental action side effect while replaying stale PIDs.
        let mut sentinel = ChildGuard::spawn();
        let after: serde_json::Value = serde_json::from_slice(&case.replay(&path, "json").stdout)
            .expect("offline scoring JSON");
        assert_complete_scoring_census(&after, inventory);
        assert_eq!(
            after["replay"]["processes"], before["replay"]["processes"],
            "live process exit must not change a recorded scoring input"
        );
        assert!(sentinel
            .0
            .try_wait()
            .expect("sentinel survives replay")
            .is_none());

        policy.guardrails.min_process_age_seconds = u64::MAX;
        case.write_policy(&policy);
        let current: serde_json::Value = serde_json::from_slice(&case.replay(&path, "json").stdout)
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
        assert!(sentinel
            .0
            .try_wait()
            .expect("policy replay is read-only")
            .is_none());
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
        let lines: Vec<_> = text
            .lines()
            .filter(|line| !line.trim().is_empty())
            .collect();
        assert_eq!(lines.len(), 1, "JSONL emits one complete record: {text}");
        let report: serde_json::Value = serde_json::from_str(lines[0]).expect("one JSONL record");
        assert_complete_scoring_census(&report, &captured["scan"]["processes"]);

        let snapshot: serde_json::Value =
            serde_json::from_slice(&original).expect("capture document");
        let mut legacy = snapshot.clone();
        assert!(legacy
            .as_object_mut()
            .unwrap()
            .remove("scoring_context")
            .is_some());
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

    #[cfg(unix)]
    fn refit_capture(
        case: &CaptureCase,
        name: &str,
        first_pid: u32,
        counts: (usize, usize, usize),
        split: &str,
    ) -> (std::path::PathBuf, std::path::PathBuf) {
        use pt_core::collect::{ProcessRecord, ProcessState, ScanMetadata, ScanResult};
        use pt_core::replay::{ReplayProcessInputs, ReplayScoringContext};

        let scorer = pt_core::scoring::Scorer::new(
            pt_core::config::Priors::default(),
            pt_core::decision::decision_store::DecisionStore::default(),
            pt_core::supervision::signature::SignatureDatabase::new(),
            pt_core::inference::FastPathConfig::disabled(),
        );
        let count = u32::try_from(counts.0 + counts.1 + counts.2).unwrap();
        let recorded_at = chrono::Utc::now();
        let processes = (first_pid..first_pid + count)
            .map(|pid| ProcessRecord {
                pid: pt_common::ProcessId(pid),
                ppid: pt_common::ProcessId(7),
                uid: 1000,
                user: "refit-fixture".to_string(),
                pgid: Some(pid),
                sid: Some(pid),
                start_id: pt_common::StartId::from_linux("refit-cli-fixture", 1_234_567_890, pid),
                comm: "refit-worker".to_string(),
                cmd: "refit-worker --synthetic-cli-case".to_string(),
                state: ProcessState::Sleeping,
                cpu_percent: 0.0,
                rss_bytes: 10 * 1024 * 1024,
                vsz_bytes: 50 * 1024 * 1024,
                tty: None,
                start_time_unix: recorded_at.timestamp() - 7200,
                elapsed: std::time::Duration::from_secs(7200),
                source: "refit-cli-fixture".to_string(),
                container_info: None,
            })
            .collect::<Vec<_>>();
        let process_count = processes.len();
        let scan = ScanResult {
            processes,
            metadata: ScanMetadata {
                scan_type: "refit-cli-fixture".to_string(),
                platform: std::env::consts::OS.to_string(),
                boot_id: Some("refit-cli-fixture".to_string()),
                started_at: recorded_at.to_rfc3339(),
                duration_ms: 0,
                process_count,
                warnings: Vec::new(),
            },
        };
        let mut snapshot = pt_core::replay::record_snapshot(&scan, Some(name)).unwrap();
        let inputs = snapshot
            .processes
            .iter()
            .map(|process| {
                let observations = scorer.recorded_observations(process, None);
                #[cfg(target_os = "linux")]
                let observations = {
                    let mut observations = observations;
                    observations.provenance = Some(pt_core::scoring::derive_provenance_adjustment(
                        process.pid.0,
                        &pt_core::scoring::ProvenanceInferenceBundle::default(),
                    ));
                    observations
                };
                (
                    process.pid.0,
                    ReplayProcessInputs {
                        identity: pt_common::ProcessIdentity::full(
                            process.pid.0,
                            process.start_id.clone(),
                            process.uid,
                            process.pgid,
                            process.sid,
                            pt_common::IdentityQuality::Full,
                        ),
                        cgroup_role: Some(pt_core::collect::cgroup::CgroupRole::LoginSession),
                        observations: Some(observations),
                        unavailable_reason: None,
                    },
                )
            })
            .collect();
        snapshot.scoring_context = Some(ReplayScoringContext {
            schema_version: 1,
            platform: std::env::consts::OS.to_string(),
            requested_window_ms: 0,
            invoker_chain: std::collections::BTreeSet::new(),
            processes: inputs,
        });
        let snapshot_path = case.root.join(format!("{name}.json"));
        snapshot.save(&snapshot_path).unwrap();
        let labels_path = case.root.join(format!("{name}-labels.json"));
        case.command()
            .args(["replay", "label-template", "--snapshot"])
            .arg(&snapshot_path)
            .arg("--output")
            .arg(&labels_path)
            .args(["--host-id", name, "--split", split])
            .assert()
            .success();
        let mut labels: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&labels_path).unwrap()).unwrap();
        for (index, row) in labels["processes"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .enumerate()
        {
            if index < counts.0 + counts.1 {
                row["verdict"] = serde_json::json!(if index < counts.0 {
                    "abandoned"
                } else {
                    "useful"
                });
                row["reviewer"] = serde_json::json!("refit-cli-fixture");
                row["reviewed_at"] = serde_json::json!(chrono::Utc::now().to_rfc3339());
                row["rationale"] = serde_json::json!(
                    "Synthetic label exercising the offline CLI contract, not measured calibration"
                );
            }
        }
        std::fs::write(&labels_path, serde_json::to_vec_pretty(&labels).unwrap()).unwrap();
        (snapshot_path, labels_path)
    }

    #[cfg(unix)]
    #[test]
    fn replay_refit_cli_exports_loadable_priors_without_activation_or_holdout_leakage() {
        let case = CaptureCase::new();
        let mut policy = pt_core::config::Policy::default();
        policy.guardrails.min_process_age_seconds = 0;
        policy.guardrails.builtin_protection = false;
        policy.guardrails.protected_users.clear();
        policy.guardrails.protected_patterns.clear();
        policy.guardrails.never_kill_pid.clear();
        policy.guardrails.never_kill_ppid.clear();
        case.write_policy(&policy);
        let mut priors = pt_core::config::Priors::default();
        priors.classes.useful.prior_prob = 0.60;
        priors.classes.useful_bad.prior_prob = 0.15;
        priors.classes.abandoned.prior_prob = 0.20;
        priors.classes.zombie.prior_prob = 0.05;
        let incumbent_path = case.config.join("priors.json");
        let incumbent = serde_json::to_vec_pretty(&priors).unwrap();
        std::fs::write(&incumbent_path, &incumbent).unwrap();
        let (training, training_labels) =
            refit_capture(&case, "training", 1000, (15, 5, 3), "training");
        let (holdout, holdout_labels) =
            refit_capture(&case, "holdout", 2000, (5, 15, 0), "holdout");
        let add_args = |command: &mut Command, output: &std::path::Path| {
            command
                .args(["replay", "refit", "--training-snapshot"])
                .arg(&training)
                .arg("--training-labels")
                .arg(&training_labels)
                .arg("--snapshot")
                .arg(&holdout)
                .arg("--labels")
                .arg(&holdout_labels)
                .arg("--output")
                .arg(output)
                .args(["--format", "json"]);
        };
        let destination = case.root.join("candidate-one");
        let mut command = case.command();
        add_args(&mut command, &destination);
        let output = command.assert().success().get_output().stdout.clone();
        let result: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(result["command"], "replay refit");
        assert_eq!(result["activated"], false);
        assert_eq!(result["artifact_scope"], "candidate_priors_only");
        assert_eq!(result["refit"]["training"]["reviewed_count"], 20);
        assert_eq!(result["refit"]["training"]["unlabeled_count"], 3);
        assert!(
            result["refit"]["candidate_abandonment_prior"]
                .as_f64()
                .unwrap()
                > 0.25
        );
        assert_eq!(result["refit"]["holdout"]["coverage"]["paired_count"], 20);
        assert!(result["refit"]["holdout"]["paired_metrics"].is_object());
        let candidate = std::fs::read(destination.join("priors.json")).unwrap();
        let saved_report = std::fs::read(destination.join("refit.json")).unwrap();
        let loaded = pt_core::config::load_config(&pt_core::config::ConfigOptions {
            config_dir: Some(destination.clone()),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            serde_json::to_value(loaded.priors).unwrap(),
            result["refit"]["candidate_priors"]
        );
        assert_eq!(std::fs::read(&incumbent_path).unwrap(), incumbent);

        // A second holdout review changes evaluation, never the fitted artifact.
        let mut reviewed: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&holdout_labels).unwrap()).unwrap();
        for row in reviewed["processes"].as_array_mut().unwrap() {
            row["verdict"] = serde_json::json!(if row["verdict"] == "useful" {
                "abandoned"
            } else {
                "useful"
            });
        }
        std::fs::write(
            &holdout_labels,
            serde_json::to_vec_pretty(&reviewed).unwrap(),
        )
        .unwrap();
        let second = case.root.join("candidate-two");
        let mut command = case.command();
        add_args(&mut command, &second);
        let output = command.assert().success().get_output().stdout.clone();
        let changed: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(
            result["refit"]["version_id"],
            changed["refit"]["version_id"]
        );
        assert_eq!(
            std::fs::read(second.join("priors.json")).unwrap(),
            candidate
        );
        assert_ne!(
            result["refit"]["holdout"]["labels_sha256"],
            changed["refit"]["holdout"]["labels_sha256"]
        );
        assert_ne!(
            result["refit"]["holdout"]["paired_metrics"],
            changed["refit"]["holdout"]["paired_metrics"]
        );
        let mut command = case.command();
        add_args(&mut command, &destination);
        command.assert().failure();
        assert_eq!(
            std::fs::read(destination.join("refit.json")).unwrap(),
            saved_report
        );
        assert_eq!(std::fs::read(&incumbent_path).unwrap(), incumbent);

        // Defaults can be loaded from an absent config directory. Export must
        // not turn that location into the next active model by writing priors.
        let absent_config = case.root.join("absent-default-config");
        let mut command = pt_core();
        command
            .env_remove("PT_CONFIG_DIR")
            .env("PROCESS_TRIAGE_CONFIG", &absent_config)
            .env("PROCESS_TRIAGE_DATA", &case.data)
            .env("PROCESS_TRIAGE_RETENTION", "off");
        add_args(&mut command, &absent_config);
        command.assert().failure().stderr(predicate::str::contains(
            "refit output must be separate from the active configuration directory",
        ));
        assert!(!absent_config.join("priors.json").exists());
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
        let rows = labels["processes"]
            .as_array()
            .expect("complete review census");
        let inventory = captured["scan"]["processes"].as_array().unwrap();
        assert_eq!(rows.len(), inventory.len());
        assert_eq!(labels["host_id"], "owned-cli-fixture");
        assert_eq!(labels["split"], "holdout");
        for process in inventory {
            let row = rows
                .iter()
                .find(|row| row["pid"] == process["pid"])
                .unwrap();
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
                std::fs::metadata(&labels_path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o077,
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
        let output = case
            .command()
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
        assert_eq!(
            text.lines().count(),
            1,
            "comparison JSONL is one complete record"
        );
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
            .stderr(predicate::str::contains(
                "baseline model could not be loaded completely",
            ));
        assert_eq!(std::fs::read(&signatures_path).unwrap(), corrupt_signatures);
        assert_eq!(std::fs::read(&labels_path).unwrap(), original);
    }

    mod prior_refit {
        use super::*;
        use pt_core::collect::cgroup::CgroupRole;
        use pt_core::collect::{ProcessRecord, ProcessState, ScanMetadata, ScanResult};
        use pt_core::config::{Policy, Priors};
        use pt_core::decision::decision_store::{DecisionStore, Verdict};
        use pt_core::inference::FastPathConfig;
        use pt_core::replay::{
            make_review_template, record_snapshot, ReplayProcessInputs, ReplayScoringContext,
            ReviewSplit, ReviewVerdict,
        };
        use pt_core::scoring::Scorer;
        use pt_core::supervision::pattern_persistence::DisabledPatterns;
        use pt_core::supervision::signature::{
            SignatureDatabase, SignatureSchema, SupervisorSignature,
        };
        use pt_core::supervision::SupervisorCategory;
        use pt_common::{IdentityQuality, ProcessId, ProcessIdentity, StartId};
        use std::collections::BTreeSet;
        use std::path::{Path, PathBuf};

        const TRAINING_BOOT: &str = "11111111-1111-4111-8111-111111111111";
        const HOLDOUT_BOOT: &str = "22222222-2222-4222-8222-222222222222";

        struct ReviewedCapture {
            snapshot: PathBuf,
            labels: PathBuf,
        }

        // Synthetic observations and labels exercise the CLI contract and
        // independent probability arithmetic only; they are not fleet evidence.
        fn capture(
            case: &CaptureCase,
            name: &str,
            boot: &str,
            split: ReviewSplit,
            count: u32,
            useful_count: usize,
        ) -> ReviewedCapture {
            let scorer = Scorer::new(
                Priors::default(),
                DecisionStore::default(),
                SignatureDatabase::new(),
                FastPathConfig::disabled(),
            );
            let captured_at = chrono::Utc::now();
            let processes: Vec<_> = (100..100 + count)
                .map(|pid| ProcessRecord {
                    pid: ProcessId(pid),
                    ppid: ProcessId(7),
                    pgid: Some(pid),
                    sid: Some(pid),
                    uid: 1000,
                    user: "contract-reviewer".to_string(),
                    comm: "__pt_refit_contract__".to_string(),
                    cmd: "__pt_refit_contract__ --synthetic".to_string(),
                    start_id: StartId::from_linux(boot, 1000 + u64::from(pid), pid),
                    state: ProcessState::Sleeping,
                    cpu_percent: 0.0,
                    rss_bytes: 10 * 1024 * 1024,
                    vsz_bytes: 50 * 1024 * 1024,
                    tty: None,
                    start_time_unix: captured_at.timestamp() - 7200,
                    elapsed: std::time::Duration::from_secs(7200),
                    source: "synthetic-cli-contract".to_string(),
                    container_info: None,
                })
                .collect();
            let scan = ScanResult {
                metadata: ScanMetadata {
                    scan_type: "synthetic-cli-contract".to_string(),
                    platform: std::env::consts::OS.to_string(),
                    boot_id: Some(boot.to_string()),
                    started_at: captured_at.to_rfc3339(),
                    duration_ms: 0,
                    process_count: processes.len(),
                    warnings: Vec::new(),
                },
                processes,
            };
            let mut snapshot = record_snapshot(&scan, Some(name)).unwrap();
            let inputs = snapshot
                .processes
                .iter()
                .map(|process| {
                    let observations = scorer.recorded_observations(process, None);
                    #[cfg(target_os = "linux")]
                    let observations = {
                        let mut observations = observations;
                        observations.provenance =
                            Some(pt_core::scoring::derive_provenance_adjustment(
                                process.pid.0,
                                &pt_core::scoring::ProvenanceInferenceBundle::default(),
                            ));
                        observations
                    };
                    (
                        process.pid.0,
                        ReplayProcessInputs {
                            identity: ProcessIdentity::full(
                                process.pid.0,
                                process.start_id.clone(),
                                process.uid,
                                process.pgid,
                                process.sid,
                                IdentityQuality::Full,
                            ),
                            cgroup_role: Some(CgroupRole::LoginSession),
                            observations: Some(observations),
                            unavailable_reason: None,
                        },
                    )
                })
                .collect();
            snapshot.scoring_context = Some(ReplayScoringContext {
                schema_version: 1,
                platform: std::env::consts::OS.to_string(),
                requested_window_ms: 0,
                invoker_chain: BTreeSet::new(),
                processes: inputs,
            });
            let mut labels = make_review_template(&snapshot, name, split).unwrap();
            for (index, process) in labels.processes.iter_mut().enumerate() {
                process.verdict = Some(if index < useful_count {
                    ReviewVerdict::Useful
                } else {
                    ReviewVerdict::Abandoned
                });
                process.reviewer = Some("synthetic-contract-reviewer".to_string());
                process.reviewed_at = Some("2026-11-09T00:00:00Z".to_string());
                process.rationale = Some("Synthetic CLI contract label, not fleet evidence".into());
            }
            let capture = ReviewedCapture {
                snapshot: case.root.join(format!("{name}-snapshot.json")),
                labels: case.root.join(format!("{name}-labels.json")),
            };
            snapshot.save_new_private(&capture.snapshot).unwrap();
            labels.save_new_private(&capture.labels).unwrap();
            capture
        }

        fn configure_neutral_likelihoods(case: &CaptureCase) {
            let mut policy = Policy::default();
            policy.guardrails.min_process_age_seconds = 0;
            policy.guardrails.builtin_protection = false;
            policy.guardrails.protected_users.clear();
            policy.guardrails.protected_patterns.clear();
            policy.guardrails.never_kill_pid.clear();
            policy.guardrails.never_kill_ppid.clear();
            policy.signature_fast_path.enabled = false;
            case.write_policy(&policy);

            // Equal likelihoods make P(abandoned or zombie) equal the prior
            // mass, giving a known optimum without relying on model heuristics.
            let mut priors = Priors::default();
            // Categorical likelihoods are stored outside the class parameters.
            priors.state_flags = None;
            priors.command_categories = None;
            let parameters = priors.classes.useful.clone();
            for (class, probability) in [
                (&mut priors.classes.useful, 0.6),
                (&mut priors.classes.useful_bad, 0.2),
                (&mut priors.classes.abandoned, 0.15),
                (&mut priors.classes.zombie, 0.05),
            ] {
                *class = parameters.clone();
                class.prior_prob = probability;
            }
            std::fs::write(
                case.config.join("priors.json"),
                serde_json::to_vec_pretty(&priors).unwrap(),
            )
            .unwrap();

            // Frozen versions must preserve the loaded overlays and learning,
            // even though these unrelated patterns cannot affect this cohort.
            let mut signatures = SignatureSchema::new();
            signatures.add(
                SupervisorSignature::new("refit-export-contract", SupervisorCategory::Agent)
                    .with_process_patterns(vec![r"^__pt_export_unrelated__$"]),
            );
            std::fs::write(
                case.config.join("signatures.json"),
                serde_json::to_vec_pretty(&signatures).unwrap(),
            )
            .unwrap();
            let mut disabled = DisabledPatterns::default();
            disabled.disabled.insert("claude".to_string());
            assert!(SignatureDatabase::with_defaults()
                .signatures()
                .iter()
                .any(|signature| signature.name == "claude"));
            std::fs::create_dir(case.config.join("patterns")).unwrap();
            std::fs::write(
                case.config.join("patterns/disabled.json"),
                serde_json::to_vec_pretty(&disabled).unwrap(),
            )
            .unwrap();
            let mut decisions = DecisionStore::load(&case.config).unwrap();
            decisions.record(
                "__pt_export_unrelated__",
                "__pt_export_unrelated__ --retained",
                Verdict::Spare,
            );
            decisions.save().unwrap();
            assert!(!decisions.is_empty());
            assert!(decisions
                .learned_prior(
                    "__pt_refit_contract__",
                    "__pt_refit_contract__ --synthetic",
                    &priors,
                )
                .is_none());
        }

        fn refit_command(
            case: &CaptureCase,
            training: &ReviewedCapture,
            holdout: &ReviewedCapture,
            output: &Path,
        ) -> Command {
            let mut command = case.command();
            command
                .args([
                    "replay",
                    "refit",
                    "--method",
                    "score-grid",
                    "--training-snapshot",
                ])
                .arg(&training.snapshot)
                .arg("--training-labels")
                .arg(&training.labels)
                .arg("--holdout-snapshot")
                .arg(&holdout.snapshot)
                .arg("--holdout-labels")
                .arg(&holdout.labels)
                .arg("--output")
                .arg(output)
                .args(["--max-change-fraction", "0.2", "--grid-points", "21"])
                .args(["--format", "json"]);
            command
        }

        #[cfg(unix)]
        fn assert_private_tree(path: &Path) {
            use std::os::unix::fs::PermissionsExt;
            let metadata = std::fs::symlink_metadata(path).unwrap();
            assert!(metadata.is_file() || metadata.is_dir(), "{}", path.display());
            assert_eq!(metadata.permissions().mode() & 0o077, 0, "{}", path.display());
            if metadata.is_dir() {
                for entry in std::fs::read_dir(path).unwrap() {
                    assert_private_tree(&entry.unwrap().path());
                }
            }
        }

        #[test]
        fn refit_cli_saves_loadable_accepted_and_rejected_versions_without_activation() {
            for (holdout_count, useful_count, accepted) in [(10, 5, true), (40, 35, false)] {
                let case = CaptureCase::new();
                configure_neutral_likelihoods(&case);
                let training = capture(
                    &case,
                    "training",
                    TRAINING_BOOT,
                    ReviewSplit::Training,
                    10,
                    5,
                );
                let holdout = capture(
                    &case,
                    "holdout",
                    HOLDOUT_BOOT,
                    ReviewSplit::Holdout,
                    holdout_count,
                    useful_count,
                );
                let input_paths = [
                    case.config.join("priors.json"),
                    case.config.join("policy.json"),
                    case.config.join("signatures.json"),
                    case.config.join("decisions.json"),
                    case.config.join("patterns/disabled.json"),
                    training.snapshot.clone(),
                    training.labels.clone(),
                    holdout.snapshot.clone(),
                    holdout.labels.clone(),
                ];
                let originals: Vec<_> = input_paths
                    .iter()
                    .map(|path| (path, std::fs::read(path).unwrap()))
                    .collect();
                let version = case.root.join("version-001");
                let stdout = refit_command(&case, &training, &holdout, &version)
                    .assert()
                    .success()
                    .get_output()
                    .stdout
                    .clone();
                let output: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
                assert_eq!(output["command"], "replay refit");
                let report = &output["refit"];
                assert_eq!(report["accepted"], accepted, "{report}");
                assert_eq!(
                    report["status"],
                    if accepted { "improved" } else { "rejected" }
                );
                assert!((report["incumbent_prior_mass"].as_f64().unwrap() - 0.2).abs() < 1e-10);
                assert!((report["candidate_prior_mass"].as_f64().unwrap() - 0.24).abs() < 1e-10);
                assert_eq!(report["training"]["paired_metrics"]["sample_count"], 10);
                assert_eq!(
                    report["holdout"]["paired_metrics"]["sample_count"],
                    holdout_count
                );
                assert_eq!(report["training_safeguards"]["passed"], true);
                assert_eq!(report["holdout_safeguards"]["passed"], true);
                let holdout_metrics = &report["holdout"]["paired_metrics"];
                assert_eq!(
                    holdout_metrics["candidate"]["log_loss"].as_f64().unwrap()
                        < holdout_metrics["baseline"]["log_loss"].as_f64().unwrap(),
                    accepted
                );
                assert!(report["limitations"]
                    .as_array()
                    .is_some_and(|items| !items.is_empty()));
                if !accepted {
                    assert!(report["reasons"]
                        .as_array()
                        .is_some_and(|items| !items.is_empty()));
                }

                let candidate = version.join("candidate");
                let incumbent = version.join("incumbent");
                let report_path = version.join("report.json");
                assert_eq!(output["artifact"]["directory"], serde_json::json!(&version));
                assert_eq!(
                    output["artifact"]["candidate_config"],
                    serde_json::json!(&candidate)
                );
                assert_eq!(
                    output["artifact"]["incumbent_config"],
                    serde_json::json!(&incumbent)
                );
                assert_eq!(output["artifact"]["report"], serde_json::json!(&report_path));
                let saved_report = std::fs::read(&report_path).unwrap();
                assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(&saved_report).unwrap(),
                    *report
                );
                for (directory, key) in [
                    (&incumbent, "incumbent_priors"),
                    (&candidate, "candidate_priors"),
                ] {
                    let priors = std::fs::read(directory.join("priors.json")).unwrap();
                    assert_eq!(
                        serde_json::from_slice::<serde_json::Value>(&priors).unwrap(),
                        report[key]
                    );
                }
                #[cfg(unix)]
                assert_private_tree(&version);

                // Reload both ordinary configuration directories through the
                // real evaluator and require exactly the frozen fingerprints.
                let stdout = case
                    .command_with_config(&candidate)
                    .args(["replay", "evaluate", "--snapshot"])
                    .arg(&holdout.snapshot)
                    .arg("--labels")
                    .arg(&holdout.labels)
                    .arg("--baseline-config")
                    .arg(&incumbent)
                    .args(["--format", "json"])
                    .assert()
                    .success()
                    .get_output()
                    .stdout
                    .clone();
                let reloaded: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
                assert_eq!(reloaded["command"], "replay evaluate");
                for (side, key) in [
                    ("baseline", "incumbent_configuration_sha256"),
                    ("candidate", "candidate_configuration_sha256"),
                ] {
                    assert_eq!(
                        reloaded["comparison"][side]["configuration_sha256"],
                        report[key]
                    );
                }
                assert_eq!(
                    reloaded["comparison"]["paired_metrics"]["sample_count"],
                    holdout_count
                );

                let frozen_paths = [
                    report_path.clone(),
                    candidate.join("priors.json"),
                    candidate.join("signatures.json"),
                    candidate.join("decisions.json"),
                    candidate.join("patterns/disabled.json"),
                    incumbent.join("priors.json"),
                ];
                let frozen_bytes: Vec<_> = frozen_paths
                    .iter()
                    .map(|path| (path, std::fs::read(path).unwrap()))
                    .collect();
                refit_command(&case, &training, &holdout, &version)
                    .assert()
                    .failure()
                    .stderr(predicate::str::contains("output already exists"));
                #[cfg(unix)]
                {
                    let alias = case.root.join("existing-version-link");
                    std::os::unix::fs::symlink(&version, &alias).unwrap();
                    refit_command(&case, &training, &holdout, &alias)
                        .assert()
                        .failure()
                        .stderr(predicate::str::contains("output already exists"));
                }
                for (path, frozen) in frozen_bytes {
                    assert_eq!(std::fs::read(path).unwrap(), frozen, "{}", path.display());
                }
                for (path, original) in originals {
                    assert_eq!(std::fs::read(path).unwrap(), original, "{}", path.display());
                }
                assert!(!case.data.join("sessions").exists());
            }
        }

        #[test]
        fn refit_cli_rejects_shared_process_births_despite_different_capture_names() {
            let case = CaptureCase::new();
            configure_neutral_likelihoods(&case);
            let training = capture(
                &case,
                "training-host",
                TRAINING_BOOT,
                ReviewSplit::Training,
                10,
                5,
            );
            let holdout = capture(
                &case,
                "holdout-host",
                TRAINING_BOOT,
                ReviewSplit::Holdout,
                10,
                5,
            );
            let version = case.root.join("overlapping-version");
            let priors = std::fs::read(case.config.join("priors.json")).unwrap();
            let decisions = std::fs::read(case.config.join("decisions.json")).unwrap();
            refit_command(&case, &training, &holdout, &version)
                .assert()
                .failure()
                .stderr(predicate::str::contains("share a process incarnation"));
            assert!(
                !version.exists(),
                "invalid holdout must not publish a model version"
            );
            assert_eq!(std::fs::read(case.config.join("priors.json")).unwrap(), priors);
            assert_eq!(
                std::fs::read(case.config.join("decisions.json")).unwrap(),
                decisions
            );
            assert!(!case.data.join("sessions").exists());
        }
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

#[cfg(target_os = "linux")]
mod partial_deep_scan {
    use super::*;
    use serde_json::Value;
    use std::time::Duration;

    #[test]
    fn zero_budget_and_global_timeout_return_explicit_partial_results() {
        let pid = std::process::id().to_string();
        for limits in [
            vec!["--budget", "0"],
            vec!["--budget", "0", "--timeout", "60"],
            vec!["--budget", "60", "--timeout", "0"],
            vec!["--timeout", "0"],
        ] {
            let output = pt_core()
                .args([
                    "deep-scan",
                    "--allow-partial",
                    "--format",
                    "json",
                    "--pids",
                    &pid,
                ])
                .args(limits)
                .timeout(Duration::from_secs(10))
                .assert()
                .code(22)
                .get_output()
                .stdout
                .clone();
            let result: Value = serde_json::from_slice(&output).unwrap();
            let scan = &result["deep_scan"];
            assert_eq!(scan["processes"].as_array().unwrap().len(), 0);
            let collection = &scan["metadata"]["collection"];
            assert_eq!(collection["complete"], false);
            assert_eq!(collection["timed_out"], true);
            assert_eq!(collection["budget_ms"], 0);
            assert_eq!(collection["processed_count"], 0);
            assert!(scan["metadata"]["warnings"]
                .as_array()
                .is_some_and(|warnings| !warnings.is_empty()));
        }
    }

    #[test]
    fn budgeted_scan_collects_live_process_without_creating_session_artifacts() {
        let temp = tempfile::tempdir().unwrap();
        let config = temp.path().join("config");
        let data = temp.path().join("data");
        let pid = std::process::id();
        let output = pt_core()
            .env("PT_CONFIG_DIR", &config)
            .env("PROCESS_TRIAGE_DATA", &data)
            .env("PATH", temp.path().join("no-vendor-tools"))
            .args([
                "deep-scan",
                "--allow-partial",
                "--format",
                "json",
                "--pids",
                &pid.to_string(),
                "--budget",
                "30",
            ])
            .timeout(Duration::from_secs(40))
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let result: Value = serde_json::from_slice(&output).unwrap();
        let scan = &result["deep_scan"];
        assert_eq!(scan["processes"].as_array().unwrap().len(), 1);
        assert_eq!(scan["processes"][0]["pid"], pid);
        let collection = &scan["metadata"]["collection"];
        assert_eq!(collection["complete"], true);
        assert_eq!(collection["timed_out"], false);
        assert_eq!(collection["requested_count"], 1);
        assert_eq!(collection["processed_count"], 1);
        assert_eq!(collection["incomplete_count"], 0);
        assert_eq!(collection["stage"], "complete");
        assert!(!config.exists());
        assert!(!data.exists());
    }

    #[test]
    fn partial_jsonl_is_one_parseable_record_and_exitcode_is_quiet() {
        let output = pt_core()
            .args([
                "deep-scan",
                "--allow-partial",
                "--budget",
                "0",
                "--format",
                "jsonl",
            ])
            .timeout(Duration::from_secs(10))
            .assert()
            .code(22)
            .get_output()
            .stdout
            .clone();
        let text = String::from_utf8(output).unwrap();
        assert_eq!(text.lines().count(), 1);
        let result: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            result["deep_scan"]["metadata"]["collection"]["timed_out"],
            true
        );
        let estimate = pt_core()
            .args([
                "deep-scan",
                "--allow-partial",
                "--budget",
                "0",
                "--format",
                "jsonl",
                "--estimate-tokens",
            ])
            .timeout(Duration::from_secs(10))
            .assert()
            .code(22)
            .get_output()
            .stdout
            .clone();
        let estimate_text = String::from_utf8(estimate).unwrap();
        assert_eq!(estimate_text.lines().count(), 1);
        let estimate: Value = serde_json::from_str(&estimate_text).unwrap();
        assert!(estimate["estimated_tokens"].is_number());
        assert!(estimate.get("deep_scan").is_none());

        pt_core()
            .args([
                "deep-scan",
                "--allow-partial",
                "--budget",
                "0",
                "--format",
                "exitcode",
            ])
            .timeout(Duration::from_secs(10))
            .assert()
            .code(22)
            .stdout("");
    }

    #[test]
    fn partial_mode_requires_a_supported_collection_deadline() {
        for limits in [vec![], vec!["--budget", "18446744073709551615"]] {
            pt_core()
                .args(["deep-scan", "--allow-partial"])
                .args(limits)
                .timeout(Duration::from_secs(10))
                .assert()
                .code(10)
                .stdout("");
        }
    }

    #[test]
    fn worker_is_hidden_and_rejects_malformed_requests() {
        pt_core()
            .arg("--help")
            .assert()
            .success()
            .stdout(predicate::str::contains("__deep-scan-worker").not());
        pt_core()
            .arg("__deep-scan-worker")
            .write_stdin("this is not a scan request")
            .timeout(Duration::from_secs(10))
            .assert()
            .code(20)
            .stdout("")
            .stderr(predicate::str::contains("Deep scan worker failed"));
    }
}

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
