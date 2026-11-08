//! End-to-end tests for agent plan workflow.
//!
//! Tests the `agent plan` command which generates action plans
//! without execution for review and validation.

use assert_cmd::cargo::cargo_bin_cmd;
use assert_cmd::Command;
use predicates::prelude::*;
use pt_common::config::policy::Policy;
use serde_json::Value;
use std::time::Duration;
use tempfile::tempdir;

/// Get a Command for pt-core binary.
fn pt_core() -> Command {
    let mut cmd = cargo_bin_cmd!("pt-core");
    // Extended timeout for debug builds/slow environments
    cmd.timeout(Duration::from_secs(300));
    // Avoid lock contention when tests run in parallel
    cmd.env("PT_SKIP_GLOBAL_LOCK", "1");
    cmd
}

/// Get a Command for pt-core binary with sample-size limit for faster testing.
/// Uses --sample-size to limit inference to N processes, making tests complete
/// in seconds instead of minutes in debug builds.
fn pt_core_fast() -> Command {
    let mut cmd = cargo_bin_cmd!("pt-core");
    cmd.timeout(Duration::from_secs(120));
    // Avoid lock contention when tests run in parallel
    cmd.env("PT_SKIP_GLOBAL_LOCK", "1");
    // Sample 50 processes for faster testing while still exercising the inference path
    cmd.args(["--standalone"]);
    cmd
}

/// Default sample size for tests that need inference coverage
const TEST_SAMPLE_SIZE: &str = "10";

#[cfg(target_os = "linux")]
mod plan_differential {
    use super::*;
    use chrono::{DateTime, FixedOffset, Utc};
    use pt_common::SessionId;
    use pt_core::session::snapshot_persist::{
        load_inference, load_inventory, persist_inference, persist_inventory, InferenceArtifact,
        InventoryArtifact,
    };
    use pt_core::session::{SessionHandle, SessionManifest, SessionMode, SessionStore};
    use std::os::unix::process::CommandExt;
    use std::path::PathBuf;
    use std::process::Stdio;

    struct OwnedChild(std::process::Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    struct Fixture {
        root: PathBuf,
        config: PathBuf,
        data: PathBuf,
        child: OwnedChild,
    }

    impl Fixture {
        fn new() -> Self {
            let root =
                std::env::temp_dir().join(format!("pt-plan-differential-{}", uuid::Uuid::new_v4()));
            let config = root.join("config");
            let data = root.join("data");
            std::fs::create_dir_all(&config).unwrap();
            eprintln!("retained differential plan evidence: {}", root.display());
            // Observe only our owned child. Host-specific exclusions would hide
            // root-owned fixtures in containers; no actions are ever applied.
            let mut policy = pt_core::config::Policy::default();
            policy.guardrails.builtin_protection = false;
            policy.guardrails.protected_patterns.clear();
            policy.guardrails.force_review_patterns.clear();
            policy.guardrails.protected_users.clear();
            policy.guardrails.protected_groups.clear();
            policy.guardrails.protected_categories.clear();
            policy.guardrails.never_kill_pid.clear();
            policy.guardrails.never_kill_ppid.clear();
            policy.guardrails.min_process_age_seconds = 0;
            policy.load_aware.enabled = false;
            std::fs::write(
                config.join("policy.json"),
                serde_json::to_vec_pretty(&policy).unwrap(),
            )
            .unwrap();
            let mut child = std::process::Command::new("sleep");
            child
                .arg("300")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            // SAFETY: setsid is async-signal-safe and touches no Rust shared state.
            unsafe {
                child.pre_exec(|| {
                    if libc::setsid() == -1 {
                        Err(std::io::Error::last_os_error())
                    } else {
                        Ok(())
                    }
                });
            }
            Self {
                root,
                config,
                data,
                child: OwnedChild(child.spawn().unwrap()),
            }
        }

        fn store(&self) -> SessionStore {
            SessionStore::at_data_dir(&self.data)
        }

        fn command(&self) -> Command {
            let mut command = pt_core();
            command
                .timeout(Duration::from_secs(120))
                .env_remove("PT_SKIP_GLOBAL_LOCK")
                .env_remove("PT_CONFIG_DIR")
                .env("PROCESS_TRIAGE_CONFIG", &self.config)
                .env("PROCESS_TRIAGE_DATA", &self.data)
                .env("PROCESS_TRIAGE_RETENTION", "off")
                .arg("--config")
                .arg(&self.config)
                .args([
                    "--format",
                    "json",
                    "agent",
                    "plan",
                    "--pretty",
                    "--min-age",
                    "0",
                    "--min-posterior",
                    "0",
                    "--max-candidates",
                    "1",
                    "--window-ms",
                    "0",
                    "--pids",
                ])
                .arg(self.child.0.id().to_string());
            command
        }

        fn plan(&self, args: &[&str]) -> Value {
            let output = self.command().args(args).output().unwrap();
            assert_eq!(output.status.code(), Some(1), "{output:?}");
            serde_json::from_slice(&output.stdout).unwrap()
        }

        fn handle(&self, plan: &Value) -> SessionHandle {
            self.store()
                .open(&SessionId::parse(plan["session_id"].as_str().unwrap()).unwrap())
                .unwrap()
        }

        fn snapshot(
            &self,
            inventory: InventoryArtifact,
            inference: InferenceArtifact,
            timestamp: &str,
        ) -> (SessionId, SessionHandle) {
            let id = SessionId::new();
            let handle = self
                .store()
                .create(&SessionManifest::new(
                    &id,
                    None,
                    SessionMode::RobotPlan,
                    None,
                ))
                .unwrap();
            let host = pt_core::logging::get_host_id();
            persist_inventory(&handle, &id.0, &host, inventory).unwrap();
            persist_inference(&handle, &id.0, &host, inference).unwrap();
            // Timestamp metadata is outside the payload checksum. Keep both
            // payloads/checksums valid while placing the fixture in history.
            rewrite_header(&handle, "scan/inventory.json", "generated_at", timestamp);
            rewrite_header(&handle, "inference/results.json", "generated_at", timestamp);
            (id, handle)
        }

        fn empty_snapshot(&self, timestamp: &str) -> (SessionId, SessionHandle) {
            self.snapshot(
                InventoryArtifact {
                    total_system_processes: 0,
                    protected_filtered: 0,
                    record_count: 0,
                    records: vec![],
                },
                InferenceArtifact {
                    candidate_count: 0,
                    candidates: vec![],
                },
                timestamp,
            )
        }

        fn assert_full_current_plan(&self, plan: &Value) {
            let candidates = plan["candidates"].as_array().unwrap();
            assert_eq!(candidates.len(), 1, "{plan}");
            assert_eq!(candidates[0]["pid"], self.child.0.id());
            assert!(plan["actions"].is_array());
            assert!(plan["policy_snapshot"].is_object());
            assert_eq!(plan["differential"]["advisory_only"], true);
            assert_eq!(plan["differential"]["plan_scope"], "complete_fresh_plan");
            assert_eq!(plan["differential"]["summary"]["total_new"], 1);
            assert!(plan.get("stub_flags").is_none());
            let handle = self.handle(plan);
            let inventory =
                load_inventory(&handle).expect("current inventory passes checksum validation");
            let inference =
                load_inference(&handle).expect("current inference passes checksum validation");
            assert_eq!(inventory.payload.records.len(), 1);
            assert_eq!(inventory.payload.records[0].pid, self.child.0.id());
            assert_eq!(inference.payload.candidates.len(), 1);
            assert_eq!(
                inference.payload.candidates[0].start_id,
                candidates[0]["start_id"].as_str().unwrap()
            );
            assert_eq!(
                inference.payload.candidates[0].recommended_action,
                candidates[0]["recommended_action"].as_str().unwrap()
            );
            let persisted: Value = serde_json::from_slice(
                &std::fs::read(handle.dir.join("decision/plan.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(
                persisted, *plan,
                "stdout and executable plan must retain the same comparison and current actions"
            );
        }
    }

    fn rewrite_header(handle: &SessionHandle, path: &str, key: &str, value: &str) {
        let path = handle.dir.join(path);
        let mut artifact: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        artifact[key] = serde_json::json!(value);
        std::fs::write(path, serde_json::to_vec_pretty(&artifact).unwrap()).unwrap();
    }

    #[test]
    fn predictions_load_recorded_observations_from_previous_real_plans() {
        let fixture = Fixture::new();
        let first = fixture.plan(&[]);
        let candidate = &first["candidates"][0];
        assert_eq!(candidate["pid"], fixture.child.0.id());
        assert!(candidate.get("predictions").is_none());
        let observation = &candidate["resource_observation"];
        assert_eq!(observation["source"], "quick_scan");
        assert!(observation["sample"]["rss_bytes"].is_u64());
        assert!(observation["sample"]["cpu_percent"].is_null());
        let saved: Value = serde_json::from_slice(
            &std::fs::read(fixture.handle(&first).dir.join("decision/plan.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(saved["candidates"][0]["resource_observation"], *observation);

        let second = fixture.plan(&["--include-predictions"]);
        let predictions = &second["candidates"][0]["predictions"];
        assert_eq!(
            predictions["diagnostics"]["model"],
            "observed_resource_trends"
        );
        assert_eq!(predictions["diagnostics"]["n_observations"], 2);
        assert_eq!(predictions["diagnostics"]["calibrated"], false);
        assert_eq!(predictions["trajectory"]["label"], "unknown");
        assert!(predictions.get("memory").is_none());
        assert!(predictions.get("cpu").is_none());
        assert!(predictions.get("eta_abandoned").is_none());
        assert!(predictions.get("eta_resource_limit").is_none());

        let selected = fixture.plan(&[
            "--include-predictions",
            "--prediction-fields",
            "diagnostics",
        ]);
        let predictions = &selected["candidates"][0]["predictions"];
        assert_eq!(predictions.as_object().unwrap().len(), 1);
        assert_eq!(predictions["diagnostics"]["n_observations"], 3);
        assert!(selected["candidates"][0]["resource_observation"].is_object());
    }

    #[test]
    fn since_keeps_a_complete_fresh_plan_and_checked_observations() {
        let fixture = Fixture::new();
        let original = fixture.plan(&[]);
        let baseline = fixture.handle(&original);
        let inventory = load_inventory(&baseline).unwrap();
        let inference = load_inference(&baseline).unwrap();
        let plan = fixture.plan(&["--since", original["session_id"].as_str().unwrap()]);
        fixture.assert_full_current_plan(&plan);
        assert_eq!(
            plan["differential"]["baseline"]["inventory_sha256"],
            inventory.integrity_sha256
        );
        assert_eq!(
            plan["differential"]["baseline"]["inference_sha256"],
            inference.integrity_sha256
        );
        assert_eq!(plan["differential"]["summary"]["total_old"], 1);
        assert_ne!(plan["session_id"], original["session_id"]);
        let minimal = fixture.plan(&[
            "--since",
            original["session_id"].as_str().unwrap(),
            "--minimal",
        ]);
        assert_eq!(
            minimal["differential"]["baseline"]["session_id"],
            original["session_id"]
        );
        assert_eq!(minimal["candidates"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn since_resume_reads_baseline_before_writes_and_pid_reuse_is_new() {
        let fixture = Fixture::new();
        let original = fixture.plan(&[]);
        let handle = fixture.handle(&original);
        let mut inventory = load_inventory(&handle).unwrap().payload;
        let inference = load_inference(&handle).unwrap().payload;
        inventory.records[0].state = "T".to_string();
        persist_inventory(
            &handle,
            original["session_id"].as_str().unwrap(),
            &pt_core::logging::get_host_id(),
            inventory,
        )
        .unwrap();
        let previous = load_inventory(&handle).unwrap();
        let id = original["session_id"].as_str().unwrap();
        let resumed = fixture.plan(&["--session", id, "--since", id]);
        fixture.assert_full_current_plan(&resumed);
        assert_eq!(resumed["session_id"], original["session_id"]);
        assert_eq!(
            resumed["differential"]["baseline"]["inventory_sha256"],
            previous.integrity_sha256
        );
        assert_eq!(resumed["differential"]["summary"]["changed_count"], 1);
        assert!(
            resumed["differential"]["changes"][0]["lifecycle"]["signals"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("state_transition"))
        );

        let mut reused_inventory = load_inventory(&handle).unwrap().payload;
        let mut reused_inference = inference;
        let previous_birth = format!("previous-boot:1:{}", fixture.child.0.id());
        reused_inventory.records[0].start_id = previous_birth.clone();
        reused_inference.candidates[0].start_id = previous_birth.clone();
        let (reuse_id, _) =
            fixture.snapshot(reused_inventory, reused_inference, &Utc::now().to_rfc3339());
        let current = fixture.plan(&["--since", &reuse_id.0]);
        fixture.assert_full_current_plan(&current);
        assert_eq!(current["differential"]["summary"]["new_count"], 1);
        assert_eq!(current["differential"]["summary"]["resolved_count"], 1);
        let absent = current["differential"]["changes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|delta| delta["kind"] == "resolved")
            .unwrap();
        assert_eq!(absent["start_id"], previous_birth);
        assert!(absent["lifecycle"]["reason"]
            .as_str()
            .unwrap()
            .contains("does not establish process exit"));
    }

    #[test]
    fn since_time_selects_by_artifact_chronology_for_duration_and_timestamp() {
        let fixture = Fixture::new();
        let now = Utc::now();
        let (_, older) = fixture.empty_snapshot(&(now - chrono::Duration::hours(3)).to_rfc3339());
        let offset = FixedOffset::west_opt(12 * 3600).unwrap();
        let selected_time = (now - chrono::Duration::minutes(75))
            .with_timezone(&offset)
            .to_rfc3339();
        let (selected, _) = fixture.empty_snapshot(&selected_time);
        fixture.empty_snapshot(&(now - chrono::Duration::minutes(30)).to_rfc3339());
        // A misleading manifest date must not outrank more recent observations.
        let mut manifest = older.read_manifest().unwrap();
        manifest.timing.created_at = (now + chrono::Duration::days(1)).to_rfc3339();
        older.write_manifest(&manifest).unwrap();
        let (_, foreign) =
            fixture.empty_snapshot(&(now - chrono::Duration::minutes(65)).to_rfc3339());
        rewrite_header(
            &foreign,
            "inference/results.json",
            "host_id",
            "another-host",
        );
        let (_, corrupt) =
            fixture.empty_snapshot(&(now - chrono::Duration::minutes(62)).to_rfc3339());
        rewrite_header(
            &corrupt,
            "scan/inventory.json",
            "integrity_sha256",
            "invalid-checksum",
        );
        let cutoff = (now - chrono::Duration::hours(1)).to_rfc3339();
        for requested_time in [&cutoff[..], "1h"] {
            let plan = fixture.plan(&["--since-time", requested_time]);
            fixture.assert_full_current_plan(&plan);
            assert_eq!(plan["differential"]["baseline"]["session_id"], selected.0);
            assert_eq!(plan["differential"]["skipped_incompatible_sessions"], 2);
            let observed = DateTime::parse_from_rfc3339(
                plan["differential"]["baseline"]["observed_at"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(
                observed,
                DateTime::parse_from_rfc3339(&selected_time).unwrap()
            );
        }
    }

    #[test]
    fn since_rejects_invalid_missing_or_incompatible_baselines_before_creating_a_plan() {
        let fixture = Fixture::new();
        let missing = SessionId::new();
        for args in [
            vec!["--since", "not-a-session"],
            vec!["--since", &missing.0],
            vec!["--since-time", "nonsense"],
            vec!["--since-time", "0h"],
            vec!["--since-time=-1h"],
            vec!["--since-time", "9223372036854775807d"],
            vec!["--since-time", "2999-01-01T00:00:00Z"],
            vec!["--since-time", "1h"],
            vec!["--since", &missing.0, "--since-time", "1h"],
        ] {
            fixture.command().args(args).assert().code(10);
            assert!(fixture
                .store()
                .list_sessions(&Default::default())
                .unwrap()
                .is_empty());
        }
        for (artifact, field, value, expected_error) in [
            (
                "scan/inventory.json",
                "session_id",
                "pt-20260101-000000-abcd",
                "session ID mismatch",
            ),
            (
                "inference/results.json",
                "host_id",
                "foreign-host",
                "host ID mismatch",
            ),
            (
                "scan/inventory.json",
                "integrity_sha256",
                "bad",
                "integrity check failed",
            ),
            (
                "inference/results.json",
                "generated_at",
                "bad",
                "invalid timestamp",
            ),
        ] {
            let (id, handle) = fixture.empty_snapshot(&Utc::now().to_rfc3339());
            rewrite_header(&handle, artifact, field, value);
            let before = fixture
                .store()
                .list_sessions(&Default::default())
                .unwrap()
                .len();
            fixture
                .command()
                .args(["--since", &id.0])
                .assert()
                .code(10)
                .stderr(predicate::str::contains(expected_error));
            assert_eq!(
                fixture
                    .store()
                    .list_sessions(&Default::default())
                    .unwrap()
                    .len(),
                before
            );
            assert!(!handle.dir.join("decision/plan.json").exists());
        }
        let id = SessionId::new();
        let empty = fixture
            .store()
            .create(&SessionManifest::new(
                &id,
                None,
                SessionMode::RobotPlan,
                None,
            ))
            .unwrap();
        fixture
            .command()
            .args(["--since", &id.0])
            .assert()
            .code(10)
            .stderr(predicate::str::contains("inventory"));
        assert!(!empty.dir.join("decision/plan.json").exists());
        assert!(fixture.root.is_dir());
    }
}

// ============================================================================
// Basic Plan Tests
// ============================================================================

mod plan_basic {
    use super::*;

    #[test]
    fn plan_runs_without_error() {
        // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
        pt_core_fast()
            .args(["agent", "plan", "--sample-size", TEST_SAMPLE_SIZE])
            .assert()
            .code(predicate::in_iter([0, 1]));
    }

    #[test]
    fn plan_with_json_format() {
        pt_core_fast()
            .args([
                "--format",
                "json",
                "agent",
                "plan",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
            .code(predicate::in_iter([0, 1]))
            .stdout(predicate::str::contains("schema_version"))
            .stdout(predicate::str::contains("session_id"));
    }

    #[test]
    fn plan_produces_valid_json() {
        let output = pt_core_fast()
            .args([
                "--format",
                "json",
                "agent",
                "plan",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
            .code(predicate::in_iter([0, 1]))
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
    fn plan_emits_progress_events() {
        pt_core_fast()
            .args([
                "--format",
                "json",
                "agent",
                "plan",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
            .code(predicate::in_iter([0, 1]))
            .stderr(
                predicate::str::contains("\"event\":").and(predicate::str::contains("plan_ready")),
            );
    }
}

// ============================================================================
// Plan Options Tests
// ============================================================================

mod plan_options {
    use super::*;

    #[test]
    fn plan_with_max_candidates() {
        pt_core_fast()
            .args([
                "agent",
                "plan",
                "--max-candidates",
                "10",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
            .code(predicate::in_iter([0, 1]));
    }

    #[test]
    fn plan_with_threshold() {
        pt_core_fast()
            .args([
                "agent",
                "plan",
                "--threshold",
                "0.8",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
            .code(predicate::in_iter([0, 1]));
    }

    #[test]
    fn plan_with_only_filter_kill() {
        pt_core_fast()
            .args([
                "agent",
                "plan",
                "--only",
                "kill",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
            .code(predicate::in_iter([0, 1]));
    }

    #[test]
    fn plan_with_only_filter_review() {
        pt_core_fast()
            .args([
                "agent",
                "plan",
                "--only",
                "review",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
            .code(predicate::in_iter([0, 1]));
    }

    #[test]
    fn plan_with_only_filter_all() {
        pt_core_fast()
            .args([
                "agent",
                "plan",
                "--only",
                "all",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
            .code(predicate::in_iter([0, 1]));
    }

    #[test]
    fn plan_with_yes_flag() {
        pt_core_fast()
            .args(["agent", "plan", "--yes", "--sample-size", TEST_SAMPLE_SIZE])
            .assert()
            // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
            .code(predicate::in_iter([0, 1]));
    }

    #[test]
    fn plan_with_combined_options() {
        pt_core_fast()
            .args([
                "agent",
                "plan",
                "--max-candidates",
                "5",
                "--threshold",
                "0.9",
                "--only",
                "kill",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
            .code(predicate::in_iter([0, 1]));
    }

    #[test]
    fn plan_with_goal_includes_goal_fields() {
        let output = pt_core_fast()
            .args([
                "--format",
                "json",
                "agent",
                "plan",
                "--goal",
                "free 1GB RAM",
                "--threshold",
                "0",
                "--max-candidates",
                "5",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            .code(predicate::in_iter([0, 1]))
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).expect("Output should be valid JSON");
        assert_eq!(
            json.get("goal").and_then(|v| v.as_str()),
            Some("free 1GB RAM")
        );
        assert!(
            json.get("goal_progress")
                .and_then(|v| v.as_array())
                .is_some(),
            "expected goal_progress array in plan output"
        );
        assert!(
            json.get("goal_summary").is_some(),
            "expected goal_summary in plan output"
        );

        if let Some(stub_flags) = json.get("stub_flags") {
            let flags_used: Vec<&str> = stub_flags
                .get("flags_used")
                .and_then(|v| v.as_array())
                .map(|items| items.iter().filter_map(|v| v.as_str()).collect())
                .unwrap_or_default();
            assert!(
                !flags_used.contains(&"--goal"),
                "--goal should not be treated as stub flag anymore"
            );
        }
    }

    /// Goal selection and projected recovery must agree with the final
    /// executable kill plan, including each target's process incarnation.
    #[test]
    fn plan_goal_never_puts_non_kill_candidates_in_kill_set() {
        let output = pt_core_fast()
            .args([
                "--format",
                "json",
                "agent",
                "plan",
                "--goal",
                "free 64GB RAM",
                "--threshold",
                "0",
                "--min-age",
                "0",
                "--max-candidates",
                "200",
            ])
            .assert()
            .code(predicate::in_iter([0, 1, 5]))
            .get_output()
            .stdout
            .clone();
        let json: Value = serde_json::from_slice(&output).expect("valid JSON");
        let candidates = json["candidates"].as_array().cloned().unwrap_or_default();
        let action_of = |pid: u64| {
            candidates
                .iter()
                .find(|c| c["pid"].as_u64() == Some(pid))
                .and_then(|c| c["recommended_action"].as_str())
                .map(str::to_string)
        };
        let kill_set = json["recommendations"]["kill_set"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        for pid in kill_set.iter().filter_map(|v| v.as_u64()) {
            assert_eq!(
                action_of(pid).as_deref(),
                Some("kill"),
                "pid {pid} is in kill_set without a kill recommendation"
            );
        }
        if let Some(needing_review) = json["summary"]["goal_selected_needing_review"].as_array() {
            for pid in needing_review.iter().filter_map(|v| v.as_u64()) {
                assert_ne!(action_of(pid).as_deref(), Some("kill"));
            }
        }

        let selected = json["goal_summary"]["selected_pids"]
            .as_array()
            .expect("goal-selected PIDs");
        let actions = json["actions"].as_array().expect("executable actions");
        let mut projected_memory_mb = 0.0;
        for pid in selected {
            let candidate = candidates
                .iter()
                .find(|candidate| candidate["pid"] == *pid)
                .unwrap_or_else(|| panic!("selected PID {pid} is not a returned candidate"));
            assert_eq!(candidate["recommended_action"], "kill", "{candidate}");
            assert_eq!(candidate["goal_selected"], true, "{candidate}");
            assert!(
                actions.iter().any(|action| {
                    action["action"] == "kill"
                        && action["blocked"] == false
                        && matches!(action["routing"].as_str(), None | Some("direct"))
                        && action["original_zombie_target"].is_null()
                        && action["target"] == candidate["action_target"]
                        && action["target"]["pid"] == candidate["pid"]
                        && action["target"]["start_id"] == candidate["start_id"]
                        && action["target"]["uid"] == candidate["uid"]
                }),
                "goal recovery has no matching executable kill: {candidate}"
            );
            let evidence = &candidate["goal_resources"];
            assert_eq!(evidence["memory_basis"], "private_clean_plus_private_dirty");
            let private_bytes = evidence["private_memory_bytes"]
                .as_u64().expect("selected recovery requires measured private bytes");
            let observed = &evidence["private_memory"];
            for field in ["pid", "start_id", "uid"] {
                assert_eq!(observed["identity"][field], candidate["action_target"][field]);
            }
            let clean = observed["private_clean_bytes"].as_u64().unwrap();
            let dirty = observed["private_dirty_bytes"].as_u64().unwrap();
            assert_eq!(clean.checked_add(dirty), Some(private_bytes));
            projected_memory_mb += private_bytes as f64 / (1024.0 * 1024.0);
        }
        for candidate in &candidates {
            let evidence = &candidate["goal_resources"];
            assert_eq!(evidence["memory_basis"], "private_clean_plus_private_dirty");
            if evidence["private_memory_bytes"].is_null() {
                assert!(evidence["private_memory"].is_null(), "{candidate}");
            } else {
                let identity = &evidence["private_memory"]["identity"];
                assert_eq!(identity["pid"], candidate["pid"]);
                assert_eq!(identity["start_id"], candidate["start_id"]);
                assert_eq!(identity["uid"], candidate["uid"]);
            }
            let selected_for_goal = selected.contains(&candidate["pid"]);
            assert_eq!(
                candidate["goal_selected"].as_bool(),
                Some(selected_for_goal),
                "{candidate}"
            );
            if !selected_for_goal {
                assert!(candidate.get("goal_rank").is_none(), "{candidate}");
            }
        }
        assert_eq!(json["summary"]["goal_selected_count"], selected.len());
        let reported_recovery = json["goal_summary"]["projected_recovery"][0]
            .as_f64()
            .expect("projected memory recovery");
        assert!(
            (reported_recovery - projected_memory_mb).abs() < 1e-6,
            "reported {reported_recovery} MiB from {projected_memory_mb} measured private MiB"
        );
        let measurement = &json["goal_summary"]["resource_observations"]["memory"];
        assert_eq!(measurement["basis"], "private_clean_plus_private_dirty");
        assert_eq!(measurement["source"], "proc_pid_smaps_rollup");
        assert_eq!(measurement["unit"], "MiB");
        assert_eq!(measurement["guaranteed_recovery"], false);

        let mut measured_kill_bytes = Some(0_u64);
        let mut seen_targets = std::collections::BTreeSet::new();
        for action in actions
            .iter()
            .filter(|action| action["action"] == "kill" && action["blocked"] == false)
        {
            let target = &action["target"];
            let identity = (
                target["pid"].as_u64().unwrap(),
                target["start_id"].as_str().unwrap(),
                target["uid"].as_u64().unwrap(),
            );
            if !seen_targets.insert(identity) {
                continue;
            }
            let private_bytes = candidates.iter().find_map(|candidate| {
                let evidence = &candidate["goal_resources"];
                let measured_identity = &evidence["private_memory"]["identity"];
                ["pid", "start_id", "uid"]
                    .iter()
                    .all(|field| measured_identity[*field] == target[*field])
                    .then(|| evidence["private_memory_bytes"].as_u64())
                    .flatten()
            });
            measured_kill_bytes =
                measured_kill_bytes.and_then(|total| total.checked_add(private_bytes?));
        }
        let recommendations = &json["recommendations"];
        match measured_kill_bytes {
            Some(bytes) => {
                let expected_gib = bytes as f64 / (1024.0 * 1024.0 * 1024.0);
                assert_eq!(
                    recommendations["expected_memory_freed_gb"],
                    (expected_gib * 100.0).round() / 100.0
                );
            }
            None => assert!(recommendations["expected_memory_freed_gb"].is_null()),
        }
        assert_eq!(
            recommendations["expected_memory_basis"],
            "private_clean_plus_private_dirty"
        );
        assert_eq!(recommendations["expected_memory_unit"], "GiB");
        assert_eq!(recommendations["expected_memory_is_guaranteed"], false);
    }

    #[test]
    fn plan_includes_signature_inference_metadata() {
        let output = pt_core_fast()
            .args([
                "--format",
                "json",
                "agent",
                "plan",
                "--threshold",
                "0",
                "--max-candidates",
                "5",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            .code(predicate::in_iter([0, 1]))
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).expect("Output should be valid JSON");
        let summary = json
            .get("summary")
            .and_then(|v| v.as_object())
            .expect("expected summary object");
        assert!(
            summary.contains_key("signature_fast_path_enabled"),
            "summary should include signature fast-path enablement"
        );
        assert!(
            summary.contains_key("signature_matches"),
            "summary should include signature match count"
        );
        assert!(
            summary.contains_key("signature_fast_path_used"),
            "summary should include signature fast-path usage count"
        );

        if let Some(first_candidate) = json
            .get("candidates")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
        {
            assert!(
                first_candidate.get("signature").is_some(),
                "candidate should include signature metadata"
            );
            assert!(
                first_candidate.get("inference").is_some(),
                "candidate should include inference metadata"
            );
        }
    }

    #[test]
    fn plan_respects_policy_disabling_signature_fast_path() {
        let config_dir = tempdir().expect("temp config dir");
        let mut policy = Policy::default();
        policy.signature_fast_path.enabled = false;
        let policy_path = config_dir.path().join("policy.json");
        std::fs::write(
            &policy_path,
            serde_json::to_vec_pretty(&policy).expect("serialize policy"),
        )
        .expect("write policy.json");

        let output = pt_core_fast()
            .env("PT_CONFIG_DIR", config_dir.path().display().to_string())
            .args([
                "--format",
                "json",
                "agent",
                "plan",
                "--threshold",
                "0",
                "--max-candidates",
                "5",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            .code(predicate::in_iter([0, 1]))
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).expect("Output should be valid JSON");
        let enabled = json
            .get("summary")
            .and_then(|v| v.get("signature_fast_path_enabled"))
            .and_then(|v| v.as_bool());
        assert_eq!(enabled, Some(false));
    }
}

// ============================================================================
// Prediction Output Tests
// ============================================================================

mod plan_predictions {
    use super::*;

    #[test]
    fn plan_with_predictions_includes_field_when_candidates_exist() {
        let output = pt_core_fast()
            .args([
                "--format",
                "json",
                "agent",
                "plan",
                "--include-predictions",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            .code(predicate::in_iter([0, 1]))
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).expect("valid JSON");
        let candidates = json
            .get("candidates")
            .and_then(|c| c.as_array())
            .cloned()
            .unwrap_or_default();

        if let Some(candidate) = candidates.first() {
            assert!(
                candidate.get("predictions").is_some(),
                "predictions should be included when flag is set"
            );
        }
    }

    #[test]
    fn plan_without_predictions_omits_field_when_candidates_exist() {
        let output = pt_core_fast()
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
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).expect("valid JSON");
        let candidates = json
            .get("candidates")
            .and_then(|c| c.as_array())
            .cloned()
            .unwrap_or_default();

        if let Some(candidate) = candidates.first() {
            assert!(
                candidate.get("predictions").is_none(),
                "predictions should be omitted by default"
            );
        }
    }
}

// ============================================================================
// Output Format Tests
// ============================================================================

mod plan_formats {
    use super::*;

    #[test]
    fn plan_json_format() {
        pt_core_fast()
            .args([
                "--format",
                "json",
                "agent",
                "plan",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
            .code(predicate::in_iter([0, 1]))
            .stdout(predicate::str::starts_with("{"));
    }

    #[test]
    fn plan_summary_format() {
        pt_core_fast()
            .args([
                "--format",
                "summary",
                "agent",
                "plan",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
            .code(predicate::in_iter([0, 1]))
            .stdout(predicate::str::contains("agent plan"));
    }

    #[test]
    fn plan_prose_format() {
        pt_core_fast()
            .args([
                "--format",
                "prose",
                "agent",
                "plan",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
            .code(predicate::in_iter([0, 1]))
            .stdout(predicate::str::contains("pt-core"));
    }

    #[test]
    fn plan_exitcode_format() {
        // Exitcode format produces no output on success
        pt_core_fast()
            .args([
                "--format",
                "exitcode",
                "agent",
                "plan",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
            .code(predicate::in_iter([0, 1]))
            .stdout(predicate::str::is_empty());
    }
}

// ============================================================================
// Schema Validation Tests
// ============================================================================

mod plan_schema {
    use super::*;

    #[test]
    fn plan_has_schema_version() {
        let output = pt_core_fast()
            .args([
                "--format",
                "json",
                "agent",
                "plan",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
            .code(predicate::in_iter([0, 1]))
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
    fn plan_session_id_is_valid() {
        let output = pt_core_fast()
            .args([
                "--format",
                "json",
                "agent",
                "plan",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
            .code(predicate::in_iter([0, 1]))
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).unwrap();
        let session_id = json
            .get("session_id")
            .expect("Missing session_id")
            .as_str()
            .expect("session_id should be string");

        // Session ID should be non-empty
        assert!(!session_id.is_empty(), "Session ID should not be empty");
        assert!(
            session_id.len() >= 8,
            "Session ID seems too short: {}",
            session_id
        );
    }

    #[test]
    fn plan_generated_at_is_iso8601() {
        let output = pt_core_fast()
            .args([
                "--format",
                "json",
                "agent",
                "plan",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
            .code(predicate::in_iter([0, 1]))
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

    #[test]
    fn candidates_include_ppid_and_state_fields() {
        let output = pt_core_fast()
            .args([
                "--format",
                "json",
                "agent",
                "plan",
                "--threshold",
                "0",
                "--max-candidates",
                "5",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
            .code(predicate::in_iter([0, 1]))
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).expect("Output should be valid JSON");
        let candidates = json
            .get("candidates")
            .and_then(|v| v.as_array())
            .expect("candidates must be an array");

        assert!(
            !candidates.is_empty(),
            "expected at least one candidate at threshold 0"
        );

        for candidate in candidates {
            assert!(
                candidate.get("ppid").is_some(),
                "candidate missing ppid field"
            );
            assert!(
                candidate.get("state").is_some(),
                "candidate missing state field"
            );
        }
    }

    #[test]
    fn candidates_include_policy_fields() {
        let output = pt_core_fast()
            .args([
                "--format",
                "json",
                "agent",
                "plan",
                "--threshold",
                "0",
                "--max-candidates",
                "5",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
            .code(predicate::in_iter([0, 1]))
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).expect("Output should be valid JSON");
        let summary = json
            .get("summary")
            .expect("Missing summary in agent plan output");
        assert!(
            summary.get("policy_blocked").is_some(),
            "summary missing policy_blocked field"
        );
        assert!(
            summary.get("policy_blocked").unwrap().is_number(),
            "summary.policy_blocked should be a number"
        );

        let candidates = json
            .get("candidates")
            .and_then(|v| v.as_array())
            .expect("candidates must be an array");

        assert!(
            !candidates.is_empty(),
            "expected at least one candidate at threshold 0"
        );

        for candidate in candidates {
            assert!(
                candidate.get("policy_blocked").is_some(),
                "candidate missing policy_blocked field"
            );
            let policy = candidate
                .get("policy")
                .expect("candidate missing policy field");
            assert!(policy.is_object(), "candidate.policy should be an object");
            assert!(
                policy.get("allowed").is_some(),
                "candidate.policy.allowed missing"
            );
        }
    }
}

// ============================================================================
// Integration Tests
// ============================================================================

mod plan_integration {
    use super::*;

    #[test]
    fn plan_with_dry_run() {
        pt_core_fast()
            .args([
                "--dry-run",
                "--format",
                "json",
                "agent",
                "plan",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
            .code(predicate::in_iter([0, 1]));
    }

    #[test]
    fn plan_with_robot_mode() {
        pt_core_fast()
            .args([
                "--robot",
                "--format",
                "json",
                "agent",
                "plan",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
            .code(predicate::in_iter([0, 1]));
    }

    #[test]
    fn plan_with_shadow_mode() {
        pt_core_fast()
            .args([
                "--shadow",
                "--format",
                "json",
                "agent",
                "plan",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
            .code(predicate::in_iter([0, 1]));
    }

    #[test]
    fn plan_with_verbose_flag() {
        pt_core_fast()
            .args([
                "-v",
                "--format",
                "json",
                "agent",
                "plan",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
            .code(predicate::in_iter([0, 1]));
    }

    #[test]
    fn plan_with_quiet_flag() {
        pt_core_fast()
            .args([
                "-q",
                "--format",
                "json",
                "agent",
                "plan",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
            .code(predicate::in_iter([0, 1]));
    }

    #[test]
    fn plan_with_standalone_flag() {
        // pt_core_fast already includes --standalone, so just test format
        pt_core_fast()
            .args([
                "--format",
                "json",
                "agent",
                "plan",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
            .code(predicate::in_iter([0, 1]));
    }

    #[test]
    fn consecutive_plans_have_different_session_ids() {
        let output1 = pt_core_fast()
            .args([
                "--format",
                "json",
                "agent",
                "plan",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
            .code(predicate::in_iter([0, 1]))
            .get_output()
            .stdout
            .clone();

        let output2 = pt_core_fast()
            .args([
                "--format",
                "json",
                "agent",
                "plan",
                "--sample-size",
                TEST_SAMPLE_SIZE,
            ])
            .assert()
            // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
            .code(predicate::in_iter([0, 1]))
            .get_output()
            .stdout
            .clone();

        let json1: Value = serde_json::from_slice(&output1).unwrap();
        let json2: Value = serde_json::from_slice(&output2).unwrap();

        let id1 = json1.get("session_id").unwrap().as_str().unwrap();
        let id2 = json2.get("session_id").unwrap().as_str().unwrap();

        assert_ne!(id1, id2, "Each plan should have unique session ID");
    }
}

// ============================================================================
// Error Handling Tests
// ============================================================================

mod plan_errors {
    use super::*;

    #[test]
    fn plan_with_invalid_format_fails() {
        pt_core()
            .args(["--format", "invalid_format", "agent", "plan"])
            .assert()
            .failure();
    }

    // NOTE: Threshold validation not yet implemented in stub
    // When implemented, add test for invalid threshold values

    #[test]
    fn plan_help_works() {
        pt_core()
            .args(["agent", "plan", "--help"])
            .assert()
            // Exit code 0 = no candidates, 1 = candidates found (both are operational success)
            .code(predicate::in_iter([0, 1]))
            .stdout(predicate::str::contains("plan"))
            .stdout(predicate::str::contains("threshold"));
    }
}

// ============================================================================
// Inference Safety Tests (wi80)
// ============================================================================
// These tests verify critical safety properties:
// - Kernel threads (PPID 0 or 2) are never in candidates
// - Zombie processes are detected with classification "zombie"
// - Candidates are ranked by max_posterior, not scan order

mod inference_safety {
    use super::*;

    /// Larger sample size for safety tests that need broader coverage
    const SAFETY_SAMPLE_SIZE: &str = "20";

    /// Parse the final JSON plan from stdout (which contains progress events before the plan).
    fn parse_plan_json(output: &[u8]) -> Value {
        // The output is JSONL format with progress events, then the final plan.
        // We need to find the last valid JSON object that contains "candidates".
        let stdout_str = String::from_utf8_lossy(output);

        // Try parsing from the end - the plan is the last multi-line JSON object
        // Look for the final { at start of a line that begins the plan
        for line in stdout_str.lines().rev() {
            if line.trim_start().starts_with('{') {
                if let Ok(json) = serde_json::from_str::<Value>(line) {
                    if json.get("candidates").is_some() || json.get("schema_version").is_some() {
                        return json;
                    }
                }
            }
        }

        // If JSONL parsing fails, try full parse
        serde_json::from_slice(output).expect("Should produce valid JSON")
    }

    #[test]
    fn kernel_threads_never_in_candidates() {
        // Run with high candidate limit to get more coverage
        // Note: Uses sample-size for faster testing; kernel thread filtering happens
        // during scan, not inference, so this still tests the safety property.
        let output = pt_core_fast()
            .args([
                "--format",
                "json",
                "agent",
                "plan",
                "--max-candidates",
                "100",
                "--sample-size",
                SAFETY_SAMPLE_SIZE,
            ])
            .assert()
            .code(predicate::in_iter([0, 1]))
            .get_output()
            .stdout
            .clone();

        let json = parse_plan_json(&output);

        if let Some(candidates) = json.get("candidates").and_then(|c| c.as_array()) {
            for candidate in candidates {
                let ppid = candidate.get("ppid").and_then(|p| p.as_u64());
                let pid = candidate.get("pid").and_then(|p| p.as_u64()).unwrap_or(0);

                if let Some(ppid_val) = ppid {
                    // PID 1 (init) has PPID 0 but is special
                    if pid == 1 {
                        continue;
                    }

                    assert!(
                        ppid_val != 0 && ppid_val != 2,
                        "Kernel thread (PPID {}) found in candidates: PID {} - this should never happen",
                        ppid_val,
                        pid
                    );
                }
            }
        }
    }

    #[test]
    fn zombie_processes_classified_correctly() {
        // Run with high candidate limit
        // Note: This test verifies that IF a zombie is in the sample, it's classified correctly.
        // Sampling doesn't affect the classification logic itself.
        let output = pt_core_fast()
            .args([
                "--format",
                "json",
                "agent",
                "plan",
                "--max-candidates",
                "100",
                "--sample-size",
                SAFETY_SAMPLE_SIZE,
            ])
            .assert()
            .code(predicate::in_iter([0, 1]))
            .get_output()
            .stdout
            .clone();

        let json = parse_plan_json(&output);

        if let Some(candidates) = json.get("candidates").and_then(|c| c.as_array()) {
            for candidate in candidates {
                let state = candidate.get("state").and_then(|s| s.as_str());
                let classification = candidate.get("classification").and_then(|c| c.as_str());

                // If state is "Z" (zombie), classification must be "zombie"
                if state == Some("Z") {
                    assert_eq!(
                        classification,
                        Some("zombie"),
                        "Process with state=Z must have classification=zombie, got {:?}",
                        classification
                    );

                    // Verify zombie posterior is the highest
                    if let Some(posterior) = candidate.get("posterior") {
                        let zombie_post = posterior
                            .get("zombie")
                            .and_then(|z| z.as_f64())
                            .unwrap_or(0.0);
                        let useful_post = posterior
                            .get("useful")
                            .and_then(|z| z.as_f64())
                            .unwrap_or(0.0);
                        let useful_bad_post = posterior
                            .get("useful_bad")
                            .and_then(|z| z.as_f64())
                            .unwrap_or(0.0);
                        let abandoned_post = posterior
                            .get("abandoned")
                            .and_then(|z| z.as_f64())
                            .unwrap_or(0.0);

                        let max_other = useful_post.max(useful_bad_post).max(abandoned_post);
                        assert!(
                            zombie_post >= max_other,
                            "Zombie process should have highest zombie posterior, got zombie={:.4} vs max_other={:.4}",
                            zombie_post, max_other
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn candidates_sorted_by_posterior_descending() {
        let output = pt_core_fast()
            .args([
                "--format",
                "json",
                "agent",
                "plan",
                "--max-candidates",
                "50",
                "--sample-size",
                SAFETY_SAMPLE_SIZE,
            ])
            .assert()
            .code(predicate::in_iter([0, 1]))
            .get_output()
            .stdout
            .clone();

        let json = parse_plan_json(&output);

        if let Some(candidates) = json.get("candidates").and_then(|c| c.as_array()) {
            if candidates.len() < 2 {
                // Not enough candidates to verify sorting
                return;
            }

            // Ranking key: P(abandoned or zombie), i.e. the suspicion the score shows
            // (never max-over-classes, which ranked confidently-useful processes first).
            let mut prev_suspicion: Option<f64> = None;

            for (i, candidate) in candidates.iter().enumerate() {
                if let Some(posterior) = candidate.get("posterior") {
                    let abandoned = posterior
                        .get("abandoned")
                        .and_then(|z| z.as_f64())
                        .unwrap_or(0.0);
                    let zombie = posterior
                        .get("zombie")
                        .and_then(|z| z.as_f64())
                        .unwrap_or(0.0);
                    let suspicion = abandoned + zombie;

                    if let Some(prev) = prev_suspicion {
                        assert!(
                            suspicion <= prev + 0.0001, // Small epsilon for float comparison
                            "Candidates not sorted by P(abandoned or zombie) at index {}: prev={:.4}, curr={:.4}",
                            i, prev, suspicion
                        );
                    }
                    if let Some(score) = candidate.get("score").and_then(|s| s.as_u64()) {
                        assert_eq!(
                            score,
                            (suspicion * 100.0).round() as u64,
                            "score must equal 100 * P(abandoned or zombie)"
                        );
                    }

                    prev_suspicion = Some(suspicion);
                }
            }
        }
    }

    #[test]
    fn protected_filter_stats_in_summary() {
        let output = pt_core_fast()
            .args([
                "--format",
                "json",
                "agent",
                "plan",
                "--sample-size",
                SAFETY_SAMPLE_SIZE,
            ])
            .assert()
            .code(predicate::in_iter([0, 1]))
            .get_output()
            .stdout
            .clone();

        let json = parse_plan_json(&output);

        if let Some(summary) = json.get("summary") {
            // Verify protected_filtered is present and parseable as an unsigned count
            if let Some(filtered) = summary.get("protected_filtered") {
                assert!(
                    filtered.as_u64().is_some(),
                    "protected_filtered should be u64-compatible, got {filtered:?}"
                );
            }

            // Verify total_processes_scanned is reasonable
            if let Some(total) = summary
                .get("total_processes_scanned")
                .and_then(|t| t.as_u64())
            {
                assert!(
                    total > 0,
                    "total_processes_scanned should be positive, got {}",
                    total
                );
            }
        }
    }

    #[test]
    fn candidate_json_has_required_fields() {
        let output = pt_core_fast()
            .args([
                "--format",
                "json",
                "agent",
                "plan",
                "--max-candidates",
                "10",
                "--sample-size",
                SAFETY_SAMPLE_SIZE,
            ])
            .assert()
            .code(predicate::in_iter([0, 1]))
            .get_output()
            .stdout
            .clone();

        let json = parse_plan_json(&output);

        if let Some(candidates) = json.get("candidates").and_then(|c| c.as_array()) {
            for (i, candidate) in candidates.iter().enumerate() {
                // Required fields from smiw fix
                assert!(
                    candidate.get("pid").is_some(),
                    "Candidate {} missing pid field",
                    i
                );
                assert!(
                    candidate.get("ppid").is_some(),
                    "Candidate {} missing ppid field (needed for kernel thread filtering verification)", i
                );
                assert!(
                    candidate.get("state").is_some(),
                    "Candidate {} missing state field (needed for zombie detection verification)",
                    i
                );
                assert!(
                    candidate.get("user").is_some(),
                    "Candidate {} missing user field",
                    i
                );
                assert!(
                    candidate.get("posterior").is_some(),
                    "Candidate {} missing posterior field",
                    i
                );
                assert!(
                    candidate.get("classification").is_some(),
                    "Candidate {} missing classification field",
                    i
                );
            }
        }
    }
}

/// Age of `pid` in seconds from /proc (the kernel's own start ticks + btime): an
/// independent check on the ages the plan reports.
#[cfg(target_os = "linux")]
fn proc_age_seconds(pid: u32) -> f64 {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).expect("stat");
    let after_comm = stat.rsplit_once(')').expect("comm").1;
    // After ")": state is field 3 overall; starttime is field 22 -> index 19 here.
    let start_ticks: f64 = after_comm
        .split_whitespace()
        .nth(19)
        .unwrap()
        .parse()
        .unwrap();
    let btime: f64 = std::fs::read_to_string("/proc/stat")
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix("btime "))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    // SAFETY: sysconf has no preconditions.
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as f64;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    now - (btime + start_ticks / hz)
}

/// blast_radius.child_count is the real number of direct children (it was a
/// hard-coded 0).
#[cfg(unix)]
#[test]
fn plan_blast_radius_counts_real_children() {
    let mut parent = std::process::Command::new("sh")
        .args(["-c", "sleep 60 & sleep 60 & wait"])
        .spawn()
        .expect("spawn parent");
    let pid = parent.id();
    std::thread::sleep(Duration::from_millis(500));
    let data_dir = tempdir().expect("data dir");
    let output = pt_core()
        .env("PROCESS_TRIAGE_DATA", data_dir.path())
        .env("PROCESS_TRIAGE_RETENTION", "off")
        .args([
            "--format",
            "json",
            "agent",
            "plan",
            "--min-age",
            "0",
            "--min-posterior",
            "0",
            "--max-candidates",
            "100000",
        ])
        .output()
        .expect("run plan");
    // Kill the sleeps (children of sh) and sh itself.
    let _ = std::process::Command::new("pkill")
        .args(["-P", &pid.to_string()])
        .status();
    let _ = parent.kill();
    let _ = parent.wait();

    let json: Value = serde_json::from_slice(&output.stdout).expect("plan JSON");
    let candidate = json["candidates"]
        .as_array()
        .expect("candidates")
        .iter()
        .find(|c| c["pid"].as_u64() == Some(u64::from(pid)))
        .unwrap_or_else(|| panic!("pid {pid} not in plan"))
        .clone();
    assert_eq!(candidate["blast_radius"]["child_count"], 2, "{candidate}");
}

/// A candidate's age in the plan equals the kernel's start time, to the second.
#[cfg(target_os = "linux")]
#[test]
fn plan_age_matches_proc_start_time() {
    let mut child = std::process::Command::new("sleep")
        .arg("120")
        .spawn()
        .expect("spawn sleep");
    let pid = child.id();
    std::thread::sleep(Duration::from_secs(3));
    let data_dir = tempdir().expect("data dir");

    let before = proc_age_seconds(pid);
    let output = pt_core()
        .env("PROCESS_TRIAGE_DATA", data_dir.path())
        .env("PROCESS_TRIAGE_RETENTION", "off")
        .args([
            "--format",
            "json",
            "agent",
            "plan",
            "--min-age",
            "0",
            "--min-posterior",
            "0",
            "--max-candidates",
            "100000",
        ])
        .output()
        .expect("run plan");
    let after = proc_age_seconds(pid);
    let _ = child.kill();
    let _ = child.wait();

    let json: Value = serde_json::from_slice(&output.stdout).expect("plan JSON");
    let candidate = json["candidates"]
        .as_array()
        .expect("candidates")
        .iter()
        .find(|c| c["pid"].as_u64() == Some(u64::from(pid)))
        .unwrap_or_else(|| panic!("pid {pid} not in plan"))
        .clone();
    let age = candidate["age_seconds"].as_f64().expect("age_seconds");
    assert!(
        age >= before.floor() - 1.0 && age <= after.ceil() + 1.0,
        "plan age {age} outside /proc age window [{before:.2}, {after:.2}]"
    );
}

/// `agent plan --deep` feeds deep-scan evidence into the posterior: a process
/// holding a TCP connection gets a `net` ledger term, which the quick scan
/// cannot see.
#[cfg(target_os = "linux")]
#[test]
fn plan_deep_adds_network_evidence() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    // bash opens fd 3 to the listener, then execs sleep, which inherits it.
    let mut child = std::process::Command::new("bash")
        .args([
            "-c",
            &format!("exec 3<>/dev/tcp/127.0.0.1/{port}; exec sleep 120"),
        ])
        .spawn()
        .expect("spawn bash");
    let pid = child.id();
    let _conn = listener.accept().expect("accept");
    std::thread::sleep(Duration::from_millis(500));
    let data_dir = tempdir().expect("data dir");

    let pid_arg = pid.to_string();
    let plan = |deep: bool, window_ms: &str| -> Value {
        let mut args = vec![
            "--format",
            "json",
            "agent",
            "plan",
            "--min-age",
            "0",
            "--min-posterior",
            "0",
            "--max-candidates",
            "100000",
            "--pids",
            pid_arg.as_str(),
            "--window-ms",
            window_ms,
        ];
        if deep {
            args.push("--deep");
        }
        let output = pt_core()
            .env("PROCESS_TRIAGE_DATA", data_dir.path())
            .env("PROCESS_TRIAGE_RETENTION", "off")
            .args(&args)
            .output()
            .expect("run plan");
        serde_json::from_slice(&output.stdout).expect("plan JSON")
    };
    let factors = |json: &Value| -> Vec<String> {
        json["candidates"]
            .as_array()
            .expect("candidates")
            .iter()
            .find(|c| c["pid"].as_u64() == Some(u64::from(pid)))
            .unwrap_or_else(|| panic!("pid {pid} not in plan"))["evidence"]
            .as_array()
            .expect("evidence")
            .iter()
            .filter_map(|e| e["factor"].as_str().map(String::from))
            .collect()
    };

    let quick = plan(false, "25");
    let deep = plan(true, "25");
    let legacy = plan(true, "0");
    let _ = child.kill();
    let _ = child.wait();

    assert!(
        !factors(&quick).contains(&"net".to_string()),
        "quick plan has no network evidence: {:?}",
        factors(&quick)
    );
    assert!(
        factors(&deep).contains(&"net".to_string()),
        "deep plan should carry a net term: {:?}",
        factors(&deep)
    );
    for output in [&quick, &deep] {
        assert_eq!(output["args"]["window_ms"], 25);
        let host_window = &output["system_state"]["pressure_window"];
        assert!(
            host_window["seconds"]
                .as_f64()
                .is_some_and(|seconds| seconds >= 0.025),
            "host pressure uses the completed process-sampling interval: {host_window}"
        );
        let candidate = output["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .find(|candidate| candidate["pid"].as_u64() == Some(u64::from(pid)))
            .expect("owned process remains a candidate");
        let activity = &candidate["activity"];
        assert_eq!(activity["source"], "procfs_window", "{candidate}");
        assert_eq!(activity["pid"], pid);
        assert_eq!(activity["start_id"], candidate["start_id"]);
        assert_eq!(activity["uid"], candidate["uid"]);
        assert_eq!(activity["requested_window_ms"], 25);
        assert!(
            activity["cpu_window_seconds"].as_f64().unwrap() >= 0.025,
            "{activity}"
        );
        assert!(activity["cpu_percent"].as_f64().unwrap() >= 0.0);
        assert_eq!(candidate["cpu_percent"], activity["cpu_percent"]);
        assert!(candidate["cpu_lifetime_percent"].is_number());
        let host_cpu = &output["system_state"]["cpu_usage"];
        if host_cpu.is_null() {
            assert!(candidate["cpu_host_percent"].is_null());
            assert!(output["system_state"]["pressure"]["unavailable"]
                .as_array().unwrap().iter().any(|source| source["source"] == "cpu_usage"),
                "an unavailable host CPU interval must retain its reason");
        } else {
            let total = host_cpu["total_ticks"].as_u64().unwrap();
            assert!(total > 0);
            assert!(host_cpu["logical_cpus"].as_u64().unwrap() > 0);
            assert!(host_cpu["busy_ticks"].as_u64().unwrap() <= total);
            assert!(host_cpu["window_seconds"].as_f64().unwrap()
                >= activity["cpu_window_seconds"].as_f64().unwrap());
            assert_eq!(candidate["cpu_host_percent"].as_f64(),
                Some(100.0 * (activity["cpu_ticks"].as_u64().unwrap() as f64 / total as f64)));
        }
        assert_eq!(
            candidate["blast_radius"]["cpu_pct"],
            candidate["cpu_percent"]
        );
        let pressure = &activity["pressure"];
        assert!(
            pressure["major_faults_per_second"].is_number(),
            "{pressure}"
        );
        assert!(pressure["memory"]["rss_bytes"].is_u64(), "{pressure}");
        assert!(pressure["memory"]["swap_bytes"].is_u64(), "{pressure}");
        assert!(pressure["memory"]["threads"].as_u64().unwrap() > 0);
        for (measurement, error) in [
            ("leader_run_queue_wait_percent", "scheduler_error"),
            ("leader_blkio_delay_percent", "blkio_error"),
        ] {
            assert!(
                pressure[measurement].is_number() || pressure[error].is_string(),
                "{measurement} is measured or explicitly unavailable: {pressure}"
            );
        }
    }
    for output in [&quick, &deep, &legacy] {
        let session_dir = data_dir
            .path()
            .join("sessions")
            .join(output["session_id"].as_str().expect("session ID"));
        let persisted_state: Value = serde_json::from_slice(
            &std::fs::read(session_dir.join("scan/system_state.json"))
                .expect("persisted host pressure evidence"),
        )
        .unwrap();
        let persisted_plan: Value = serde_json::from_slice(
            &std::fs::read(session_dir.join("decision/plan.json")).expect("persisted plan"),
        )
        .unwrap();
        assert_eq!(persisted_state, output["system_state"]);
        assert_eq!(persisted_plan["system_state"], output["system_state"]);
    }
    let legacy_candidate = legacy["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .find(|candidate| candidate["pid"].as_u64() == Some(u64::from(pid)))
        .expect("single-snapshot candidate");
    assert_eq!(legacy["args"]["window_ms"], 0);
    assert!(legacy["system_state"]
        .get("pressure_window")
        .expect("explicit pressure-window availability")
        .is_null());
    assert!(legacy_candidate["activity"].is_null());
    assert!(legacy["system_state"]["cpu_usage"].is_null());
    assert!(legacy_candidate["cpu_host_percent"].is_null());
    assert_eq!(
        legacy_candidate["cpu_percent"],
        legacy_candidate["cpu_lifetime_percent"]
    );
    assert!(
        !factors(&legacy).contains(&"io_active".to_string()),
        "single deep counters must not become current I/O evidence"
    );
    assert!(quick["summary"]["deep_scan_ms"].is_null());
    assert!(
        deep["summary"]["deep_scan_ms"].is_u64(),
        "{}",
        deep["summary"]
    );
    assert!(
        deep["summary"]["deep_coverage"]["net"]
            .as_u64()
            .unwrap_or(0)
            > 0,
        "{}",
        deep["summary"]
    );
    assert!(
        deep["summary"]["deep_evidence_pids"].as_u64().unwrap_or(0) > 0,
        "{}",
        deep["summary"]
    );
}

/// A real zombie is never reniced/killed/paused: the plan routes it to its parent.
#[cfg(target_os = "linux")]
#[test]
fn plan_routes_zombie_to_parent() {
    // sh forks `sleep 0`, then execs `sleep 120`, which never reaps it.
    let mut parent = std::process::Command::new("sh")
        .args(["-c", "sleep 0 & exec sleep 120"])
        .spawn()
        .expect("spawn parent");
    let parent_pid = parent.id();
    std::thread::sleep(Duration::from_secs(1));
    let data_dir = tempdir().expect("data dir");
    let output = pt_core()
        .env("PROCESS_TRIAGE_DATA", data_dir.path())
        .env("PROCESS_TRIAGE_RETENTION", "off")
        .args([
            "--format",
            "json",
            "agent",
            "plan",
            "--min-age",
            "0",
            "--min-posterior",
            "0",
            "--max-candidates",
            "100000",
        ])
        .output()
        .expect("run plan");
    let _ = parent.kill();
    let _ = parent.wait();

    let json: Value = serde_json::from_slice(&output.stdout).expect("plan JSON");
    let zombie = json["candidates"]
        .as_array()
        .expect("candidates")
        .iter()
        .find(|c| c["ppid"].as_u64() == Some(u64::from(parent_pid)))
        .unwrap_or_else(|| panic!("zombie child of {parent_pid} not in plan"))
        .clone();
    assert!(
        zombie["state"].as_str().unwrap_or("").starts_with('Z'),
        "{zombie}"
    );
    let routing = &zombie["zombie_routing"];
    assert_eq!(routing["route_to"], "parent", "{zombie}");
    assert_eq!(routing["parent_pid"], parent_pid, "{zombie}");
    assert_eq!(routing["parent_comm"], "sleep", "{zombie}");
    let rec = zombie["recommendation"].as_str().unwrap_or("");
    assert!(
        ![
            "KILL",
            "RENICE",
            "PAUSE",
            "FREEZE",
            "THROTTLE",
            "QUARANTINE"
        ]
        .contains(&rec),
        "zombie got a direct action {rec}: {zombie}"
    );
    // A live process has no routing block.
    let parent_candidate = json["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["pid"].as_u64() == Some(u64::from(parent_pid)));
    if let Some(p) = parent_candidate {
        assert!(p["zombie_routing"].is_null(), "{p}");
    }
}

/// The plan runs the same data-loss check apply does: with kill made the cheapest
/// action, a process holding a regular file open for writing is policy-blocked in
/// the plan, and one with stdio on /dev/null is not.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn plan_blocks_kill_of_open_writer() {
    let config_dir = tempdir().expect("config dir");
    let mut policy = pt_core::config::Policy::default();
    for row in [
        &mut policy.loss_matrix.useful,
        &mut policy.loss_matrix.useful_bad,
        &mut policy.loss_matrix.abandoned,
        &mut policy.loss_matrix.zombie,
    ] {
        row.keep = 10.0;
        row.kill = 0.0;
    }
    policy.guardrails.min_process_age_seconds = 0;
    std::fs::write(
        config_dir.path().join("policy.json"),
        serde_json::to_vec_pretty(&policy).expect("serialize policy"),
    )
    .expect("write policy.json");

    let file_dir = tempdir().expect("file dir");
    let log = file_dir.path().join("journal.log");
    let spawn = |script: String| {
        std::process::Command::new("sh")
            .args(["-c", &script])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn")
    };
    let mut writer = spawn(format!("exec sleep 305 3>>'{}'", log.display()));
    let mut idle = spawn("exec sleep 306".to_string());
    std::thread::sleep(Duration::from_millis(500));

    let data_dir = tempdir().expect("data dir");
    let output = pt_core()
        .env("PROCESS_TRIAGE_DATA", data_dir.path())
        .env("PROCESS_TRIAGE_CONFIG", config_dir.path())
        .env("PROCESS_TRIAGE_RETENTION", "off")
        .args([
            "--format",
            "json",
            "agent",
            "plan",
            "--min-age",
            "0",
            "--min-posterior",
            "0",
            "--max-candidates",
            "100000",
        ])
        .output()
        .expect("run plan");
    let _ = writer.kill();
    let _ = writer.wait();
    let _ = idle.kill();
    let _ = idle.wait();

    let json: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "plan JSON ({e}); stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    let candidate = |pid: u32| -> Value {
        json["candidates"]
            .as_array()
            .expect("candidates")
            .iter()
            .find(|c| c["pid"].as_u64() == Some(u64::from(pid)))
            .unwrap_or_else(|| panic!("pid {pid} not in plan"))
            .clone()
    };
    let w = candidate(writer.id());
    assert_eq!(w["policy"]["allowed"], false, "{w}");
    assert_eq!(
        w["policy"]["violation"]["rule"], "data_loss_gates.block_if_open_write_fds",
        "{w}"
    );
    let i = candidate(idle.id());
    assert_ne!(
        i["policy"]["violation"]["rule"], "data_loss_gates.block_if_open_write_fds",
        "{i}"
    );
}

/// `--only kill` must describe the executable plan after data-loss refusals and
/// the per-run kill budget, including the artifacts consumed by session diff.
#[cfg(target_os = "linux")]
#[test]
fn plan_only_kill_filters_final_policy_and_budget_decisions() {
    use std::collections::BTreeSet;
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;

    // Clean up only children owned by this test, including on assertion failure.
    struct OwnedChild(std::process::Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    let root = std::env::temp_dir().join(format!("pt-plan-only-final-{}", uuid::Uuid::new_v4()));
    let config_dir = root.join("config");
    std::fs::create_dir_all(&config_dir).expect("create retained plan config");
    eprintln!("retained final plan filter evidence: {}", root.display());

    let mut policy = pt_core::config::Policy::default();
    for row in [
        &mut policy.loss_matrix.useful,
        &mut policy.loss_matrix.useful_bad,
        &mut policy.loss_matrix.abandoned,
        &mut policy.loss_matrix.zombie,
    ] {
        row.keep = 10.0;
        row.kill = 0.0;
    }
    // Restrict inference to our children below. Disable host-specific protection
    // only in this fixture policy so root-owned/containerized CI is deterministic;
    // the real data-loss gate and kill budget remain enabled.
    policy.guardrails.builtin_protection = false;
    policy.guardrails.protected_patterns.clear();
    policy.guardrails.force_review_patterns.clear();
    policy.guardrails.protected_users.clear();
    policy.guardrails.protected_groups.clear();
    policy.guardrails.protected_categories.clear();
    policy.guardrails.never_kill_pid.clear();
    policy.guardrails.never_kill_ppid.clear();
    policy.guardrails.min_process_age_seconds = 0;
    policy.guardrails.max_kills_per_run = 1;
    policy.load_aware.enabled = false;
    std::fs::write(
        config_dir.join("policy.json"),
        serde_json::to_vec_pretty(&policy).expect("serialize fixture policy"),
    )
    .expect("write fixture policy");

    let spawn = |stdout: Stdio| {
        let mut command = std::process::Command::new("sleep");
        command
            .arg("300")
            .stdin(Stdio::null())
            .stdout(stdout)
            .stderr(Stdio::null());
        // SAFETY: setsid is async-signal-safe and this callback touches no shared
        // state. A new session gives the fixture no inherited controlling TTY.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() == -1 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        OwnedChild(command.spawn().expect("spawn owned sleep fixture"))
    };
    let mut writer = spawn(Stdio::from(
        std::fs::File::create(root.join("writer-output.txt")).expect("open writer output"),
    ));
    let mut first_control = spawn(Stdio::null());
    let mut second_control = spawn(Stdio::null());
    let writer_pid = u64::from(writer.0.id());
    let control_pids = [
        u64::from(first_control.0.id()),
        u64::from(second_control.0.id()),
    ];
    let fixture_pids = BTreeSet::from([writer_pid, control_pids[0], control_pids[1]]);
    let selected_pids = fixture_pids
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let pid_set = |rows: &[Value]| -> BTreeSet<u64> {
        rows.iter()
            .map(|row| row["pid"].as_u64().expect("record PID"))
            .collect()
    };

    for only in ["all", "kill"] {
        let data_dir = root.join(format!("data-{only}"));
        let output = pt_core()
            .timeout(Duration::from_secs(120))
            .env_remove("PT_SKIP_GLOBAL_LOCK")
            .env_remove("PT_CONFIG_DIR")
            .env("PROCESS_TRIAGE_CONFIG", &config_dir)
            .env("PROCESS_TRIAGE_DATA", &data_dir)
            .env("PROCESS_TRIAGE_RETENTION", "off")
            .arg("--config")
            .arg(&config_dir)
            .args([
                "--format",
                "json",
                "agent",
                "plan",
                "--pretty",
                "--pids",
                &selected_pids,
                "--min-age",
                "0",
                "--min-posterior",
                "0",
                "--max-candidates",
                "3",
                "--only",
                only,
                "--goal",
                "free 1 FDs",
            ])
            .output()
            .expect("run actual agent plan");
        std::fs::write(root.join(format!("{only}.stdout")), &output.stdout)
            .expect("retain plan stdout");
        std::fs::write(root.join(format!("{only}.stderr")), &output.stderr)
            .expect("retain plan stderr");
        assert_eq!(output.status.code(), Some(1), "{only}: {output:?}");
        let plan: Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|error| panic!("{only}: invalid plan JSON ({error}): {output:?}"));
        let candidates = plan["candidates"].as_array().expect("plan candidates");
        assert_eq!(plan["summary"]["candidates_returned"], candidates.len());
        assert_eq!(plan["summary"]["kill_recommendations"], 1, "{only}: {plan}");

        let kills: Vec<_> = candidates
            .iter()
            .filter(|candidate| candidate["recommended_action"] == "kill")
            .collect();
        assert_eq!(kills.len(), 1, "{only}: {plan}");
        let kill = kills[0];
        let kill_pid = kill["pid"].as_u64().expect("kill PID");
        assert!(control_pids.contains(&kill_pid), "{only}: {kill}");
        assert_eq!(kill["policy"]["allowed"], true, "{only}: {kill}");

        // The production goal collector must measure the selected child's
        // descriptors and recompute recovery after the writer refusal and kill
        // budget. The sleep fixtures keep their descriptor tables unchanged.
        let measured_fds = std::fs::read_dir(format!("/proc/{kill_pid}/fd"))
            .expect("read owned control descriptors")
            .collect::<Result<Vec<_>, _>>()
            .expect("enumerate owned control descriptors")
            .len();
        assert!(measured_fds > 0);
        assert_eq!(kill["goal_resources"]["fd_count"], measured_fds);
        assert_eq!(kill["goal_selected"], true);
        assert_eq!(plan["goal_summary"]["achievable"], true, "{only}: {plan}");
        assert_eq!(
            plan["goal_summary"]["selected_pids"],
            serde_json::json!([kill_pid])
        );
        assert_eq!(plan["goal_summary"]["targets"][0]["unit"], "descriptors");
        assert_eq!(
            plan["goal_summary"]["projected_recovery"][0].as_f64(),
            Some(measured_fds as f64),
            "{only}: {plan}"
        );
        assert_eq!(plan["summary"]["goal_selected_count"], 1);

        if only == "all" {
            assert_eq!(candidates.len(), 3, "{plan}");
            assert_eq!(pid_set(candidates), fixture_pids, "{plan}");
            let writer = candidates
                .iter()
                .find(|candidate| candidate["pid"].as_u64() == Some(writer_pid))
                .expect("writer remains visible for review");
            assert_eq!(writer["recommended_action"], "review", "{writer}");
            assert_eq!(writer["goal_selected"], false, "{writer}");
            assert_eq!(writer["policy"]["allowed"], false, "{writer}");
            assert_eq!(
                writer["policy"]["violation"]["rule"], "data_loss_gates.block_if_open_write_fds",
                "{writer}"
            );
            let budget_review = candidates
                .iter()
                .find(|candidate| {
                    candidate["pid"].as_u64() != Some(writer_pid)
                        && candidate["pid"].as_u64() != Some(kill_pid)
                })
                .expect("second control remains visible for budget review");
            assert_eq!(
                budget_review["recommended_action"], "review",
                "{budget_review}"
            );
            assert_eq!(budget_review["policy"]["allowed"], true, "{budget_review}");
            assert_eq!(budget_review["goal_selected"], false, "{budget_review}");
            assert_eq!(budget_review["plan_budget"]["rule"], "max_planned_kills");
            assert_eq!(budget_review["plan_budget"]["limit"], 1);
            assert_eq!(plan["summary"]["review_recommendations"], 2);
        } else {
            assert_eq!(
                candidates.len(),
                1,
                "--only kill leaked a review row: {plan}"
            );
            assert_eq!(plan["summary"]["review_recommendations"], 0);
        }

        // Both output modes expose exactly one executable action. A fresh scan
        // may rank either control first, so compare identities within each plan.
        let actions = plan["actions"].as_array().expect("executable actions");
        assert_eq!(actions.len(), 1, "{only}: {plan}");
        let action = &actions[0];
        assert_eq!(action["action"], "kill", "{only}: {action}");
        assert_eq!(action["blocked"], false, "{only}: {action}");
        assert_eq!(action["target"]["pid"], kill_pid);
        assert_eq!(action["target"]["start_id"], kill["start_id"]);
        assert_eq!(kill["action_target"], action["target"]);
        assert_eq!(
            kill["plan_action_ids"],
            serde_json::json!([action["action_id"]])
        );
        assert_eq!(
            plan["recommendations"]["kill_set"],
            serde_json::json!([kill_pid])
        );
        let review_pids: BTreeSet<u64> = plan["recommendations"]["review_set"]
            .as_array()
            .expect("review set")
            .iter()
            .map(|pid| pid.as_u64().expect("review PID"))
            .collect();
        assert_eq!(
            review_pids,
            pid_set(candidates)
                .difference(&BTreeSet::from([kill_pid]))
                .copied()
                .collect::<BTreeSet<_>>()
        );
        assert!(plan["recommendations"]["spare_set"]
            .as_array()
            .unwrap()
            .is_empty());
        assert_eq!(
            plan["recommended"]["actions"],
            serde_json::json!([{
                "pid": kill_pid,
                "action": "kill",
                "stage": action["stage"],
                "action_id": action["action_id"],
            }])
        );

        let session_dir = data_dir
            .join("sessions")
            .join(plan["session_id"].as_str().expect("session ID"));
        let read_artifact = |path: &str| -> Value {
            let bytes = std::fs::read(session_dir.join(path))
                .unwrap_or_else(|error| panic!("{only}: missing {path}: {error}"));
            serde_json::from_slice(&bytes)
                .unwrap_or_else(|error| panic!("{only}: invalid {path}: {error}"))
        };
        assert_eq!(read_artifact("decision/plan.json"), plan);
        let inventory = read_artifact("scan/inventory.json");
        let inference = read_artifact("inference/results.json");
        assert_eq!(inventory["payload"]["record_count"], candidates.len());
        assert_eq!(inference["payload"]["candidate_count"], candidates.len());
        assert_eq!(
            pid_set(inventory["payload"]["records"].as_array().unwrap()),
            pid_set(candidates)
        );
        let inferred = inference["payload"]["candidates"].as_array().unwrap();
        assert_eq!(pid_set(inferred), pid_set(candidates));
        for record in inferred {
            let candidate = candidates
                .iter()
                .find(|candidate| candidate["pid"] == record["pid"])
                .expect("persisted inference refers to returned candidate");
            assert_eq!(record["start_id"], candidate["start_id"]);
            assert_eq!(
                record["recommended_action"],
                candidate["recommended_action"]
            );
        }
    }

    for child in [&mut writer, &mut first_control, &mut second_control] {
        assert!(
            child.0.try_wait().expect("check owned child").is_none(),
            "planning executed an action"
        );
    }
}

/// Holding /dev/fuse is sufficient to make a disruptive recommendation unsafe:
/// pausing the server can hang all mount users, and killing it strands the mount.
/// This exercises the real CLI and descriptor collector, without mounting a
/// filesystem or acting on any process. A real mounted-filesystem test remains a
/// separate platform integration check.
#[cfg(target_os = "linux")]
#[test]
fn plan_reviews_fuse_device_holders_before_disruptive_actions() {
    use std::fs::OpenOptions;
    use std::process::{Child, Command as ProcessCommand, Stdio};

    struct OwnedChild(Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    let device = match OpenOptions::new().read(true).write(true).open("/dev/fuse") {
        Ok(device) => device,
        Err(error) => {
            eprintln!("SKIP real FUSE descriptor integration: cannot open /dev/fuse: {error}");
            return;
        }
    };
    let server = OwnedChild(
        ProcessCommand::new("sleep")
            .arg("307")
            .stdin(Stdio::from(device))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn test-owned FUSE descriptor holder"),
    );
    let control = OwnedChild(
        ProcessCommand::new("sleep")
            .arg("308")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn test-owned control"),
    );
    let pids = format!("{},{}", server.0.id(), control.0.id());
    let config_dir = tempdir().expect("config dir");
    let data_dir = tempdir().expect("data dir");

    for proposed_action in ["kill", "pause"] {
        let mut policy = pt_core::config::Policy::default();
        for row in [
            &mut policy.loss_matrix.useful,
            &mut policy.loss_matrix.useful_bad,
            &mut policy.loss_matrix.abandoned,
            &mut policy.loss_matrix.zombie,
        ] {
            row.keep = 10.0;
            if proposed_action == "kill" {
                row.kill = 0.0;
            } else {
                row.pause = Some(0.0);
            }
        }
        policy.guardrails.min_process_age_seconds = 0;
        policy.guardrails.protected_users.clear();
        std::fs::write(
            config_dir.path().join("policy.json"),
            serde_json::to_vec_pretty(&policy).expect("serialize policy"),
        )
        .expect("write policy");

        let output = pt_core()
            .env("PROCESS_TRIAGE_DATA", data_dir.path())
            .env("PROCESS_TRIAGE_RETENTION", "off")
            .arg("--config")
            .arg(config_dir.path())
            .args([
                "--format",
                "json",
                "agent",
                "plan",
                "--min-age",
                "0",
                "--min-posterior",
                "0",
                "--pids",
                &pids,
            ])
            .output()
            .expect("run FUSE safety plan");
        assert!(
            matches!(output.status.code(), Some(0 | 1)),
            "{proposed_action}: {}",
            String::from_utf8_lossy(&output.stderr),
        );
        let document: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "{proposed_action} plan JSON ({error}): {}",
                String::from_utf8_lossy(&output.stderr)
            )
        });
        let candidates = document["candidates"].as_array().expect("candidates");
        let holder = candidates
            .iter()
            .find(|candidate| candidate["pid"].as_u64() == Some(u64::from(server.0.id())))
            .unwrap_or_else(|| panic!("FUSE holder absent: {document}"));
        let ordinary = candidates
            .iter()
            .find(|candidate| candidate["pid"].as_u64() == Some(u64::from(control.0.id())))
            .unwrap_or_else(|| panic!("control absent: {document}"));
        assert_eq!(holder["fuse_server"], true, "{holder}");
        assert_eq!(ordinary["fuse_server"], false, "{ordinary}");
        assert_eq!(holder["recommended_action"], "review", "{holder}");
        assert!(
            holder["fuse_mounts"].is_array() || holder["fuse_mounts"].is_null(),
            "{holder}"
        );
        assert!(
            holder.to_string().contains("fusermount"),
            "missing unmount advice: {holder}"
        );
        assert!(
            document["actions"]
                .as_array()
                .expect("executable actions")
                .iter()
                .all(|action| {
                    action["target"]["pid"].as_u64() != Some(u64::from(server.0.id()))
                        || action["blocked"].as_bool() == Some(true)
                        || action["action"].as_str() == Some("keep")
                }),
            "FUSE holder acquired an executable action: {document}",
        );
    }
}

/// An agent CLI is identified in the plan (`agent_kind`) and never gets an
/// automatic action.
#[cfg(unix)]
#[test]
fn plan_identifies_agent_cli_kind() {
    // argv[0] = "claude": looks like a Claude Code session to pt.
    let mut agent = std::process::Command::new("bash")
        .args(["-c", "exec -a claude sleep 120"])
        .spawn()
        .expect("spawn agent lookalike");
    let pid = agent.id();
    std::thread::sleep(Duration::from_millis(500));
    let data_dir = tempdir().expect("data dir");
    let output = pt_core()
        .env("PROCESS_TRIAGE_DATA", data_dir.path())
        .env("PROCESS_TRIAGE_RETENTION", "off")
        .args([
            "--format",
            "json",
            "agent",
            "plan",
            "--min-age",
            "0",
            "--min-posterior",
            "0",
            "--max-candidates",
            "100000",
        ])
        .output()
        .expect("run plan");
    let _ = agent.kill();
    let _ = agent.wait();

    let json: Value = serde_json::from_slice(&output.stdout).expect("plan JSON");
    let c = json["candidates"]
        .as_array()
        .expect("candidates")
        .iter()
        .find(|c| c["pid"].as_u64() == Some(u64::from(pid)))
        .unwrap_or_else(|| panic!("pid {pid} not in plan"))
        .clone();
    assert_eq!(c["agent_kind"], "claude", "{c}");
    let rec = c["recommendation"].as_str().unwrap_or("");
    assert!(matches!(rec, "KEEP" | "REVIEW"), "agent got {rec}: {c}");
    // No controlling terminal: no liveness evidence.
    assert_eq!(c["agent_liveness"]["live"], false, "{c}");
}

/// An agent CLI on a terminal with recent I/O is live: kept, not surfaced for review.
#[cfg(target_os = "linux")]
#[test]
fn plan_keeps_agent_with_active_terminal() {
    // `script` gives the lookalike a real pty (just created, so recently active).
    // Its stdin stays an open pipe: at EOF `script` would end the pty session and
    // the lookalike would lose its terminal.
    let mut agent = std::process::Command::new("script")
        // 137: distinct from plan_identifies_agent_cli_kind's lookalike (runs in parallel)
        .args(["-qc", "exec -a claude sleep 137", "/dev/null"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("spawn script");
    let _stdin = agent.stdin.take();
    std::thread::sleep(Duration::from_millis(800));
    let data_dir = tempdir().expect("data dir");
    let output = pt_core()
        .env("PROCESS_TRIAGE_DATA", data_dir.path())
        .env("PROCESS_TRIAGE_RETENTION", "off")
        .args([
            "--format",
            "json",
            "agent",
            "plan",
            "--min-age",
            "0",
            "--min-posterior",
            "0",
            "--max-candidates",
            "100000",
        ])
        .output()
        .expect("run plan");
    let _ = std::process::Command::new("pkill")
        .args(["-P", &agent.id().to_string()])
        .status();
    let _ = agent.kill();
    let _ = agent.wait();

    let json: Value = serde_json::from_slice(&output.stdout).expect("plan JSON");
    let c = json["candidates"]
        .as_array()
        .expect("candidates")
        .iter()
        .find(|c| {
            c["agent_kind"] == "claude"
                && c["command"]
                    .as_str()
                    .unwrap_or("")
                    .starts_with("claude 137")
        })
        .unwrap_or_else(|| panic!("agent lookalike not in plan"))
        .clone();
    assert_eq!(c["agent_liveness"]["live"], true, "{c}");
    assert!(
        c["agent_liveness"]["tty"]
            .as_str()
            .unwrap_or("")
            .contains("pts"),
        "{c}"
    );
    assert_eq!(c["recommendation"], "KEEP", "{c}");
}
