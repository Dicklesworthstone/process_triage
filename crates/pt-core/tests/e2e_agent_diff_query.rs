//! E2E tests for `agent diff` and `query` subcommands.
//!
//! `agent diff` compares candidates between two sessions (plan.json).
//! `query sessions` lists persisted sessions; other query subcommands are stubs.

use assert_cmd::cargo::cargo_bin_cmd;
use assert_cmd::Command;
use pt_common::SessionId;
use pt_core::exit_codes::ExitCode;
use pt_core::session::{SessionContext, SessionManifest, SessionMode, SessionStore};
use serde_json::Value;
use std::env;
use std::fs;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use tempfile::TempDir;

static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn with_temp_data_dir<T>(f: impl FnOnce(&TempDir) -> T) -> T {
    let _guard = ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    let old = env::var("PROCESS_TRIAGE_DATA").ok();
    let dir = TempDir::new().expect("create temp data dir");
    env::set_var("PROCESS_TRIAGE_DATA", dir.path());

    let result = f(&dir);

    match old {
        Some(val) => env::set_var("PROCESS_TRIAGE_DATA", val),
        None => env::remove_var("PROCESS_TRIAGE_DATA"),
    }

    result
}

fn pt_core_fast() -> Command {
    let mut cmd = cargo_bin_cmd!("pt-core");
    cmd.timeout(Duration::from_secs(120));
    cmd.env("PT_SKIP_GLOBAL_LOCK", "1");
    cmd
}

/// Create a session with a plan.json containing the given candidates JSON array.
fn create_session_with_candidates(
    _dir: &TempDir,
    candidates: &[Value],
    generated_at: &str,
) -> SessionId {
    let store = SessionStore::from_env().expect("session store from env");
    let session_id = SessionId::new();
    let manifest = SessionManifest::new(&session_id, None, SessionMode::RobotPlan, None);
    let handle = store.create(&manifest).expect("create session");
    let ctx = SessionContext::new(
        &session_id,
        "host-test".to_string(),
        "run-test".to_string(),
        None,
    );
    handle.write_context(&ctx).expect("write context");

    let plan = serde_json::json!({
        "schema_version": "1.0.0",
        "plan_id": format!("plan-{}", session_id.0),
        "session_id": session_id.0,
        "host_id": "host-test",
        "generated_at": generated_at,
        "candidates": candidates,
    });

    let decision_dir = handle.dir.join("decision");
    fs::create_dir_all(&decision_dir).expect("create decision dir");
    fs::write(
        decision_dir.join("plan.json"),
        serde_json::to_string_pretty(&plan).expect("serialize plan"),
    )
    .expect("write plan");

    session_id
}

fn make_candidate(pid: u32, classification: &str, action: &str, score: f64) -> Value {
    serde_json::json!({
        "pid": pid,
        "uid": 1000,
        "start_id": format!("test-boot:12345:{pid}"),
        "command_short": format!("proc-{}", pid),
        "command": format!("/usr/bin/proc-{}", pid),
        "classification": classification,
        "recommended_action": action,
        "score": (score * 100.0).round() as u32,
        "posterior": {
            "abandoned": score,
            "useful": 1.0 - score,
            "useful_bad": 0.0,
            "zombie": 0.0,
        },
    })
}

// ============================================================================
// agent diff tests
// ============================================================================

#[test]
fn diff_requires_base_flag() {
    pt_core_fast().args(["agent", "diff"]).assert().failure();
}

#[test]
fn diff_invalid_base_returns_args_error() {
    with_temp_data_dir(|dir| {
        pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", dir.path())
            .args(["agent", "diff", "--base", "not-a-valid-session"])
            .assert()
            .code(ExitCode::ArgsError.as_i32());
    });
}

#[test]
fn diff_missing_base_session_returns_args_error() {
    with_temp_data_dir(|dir| {
        pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", dir.path())
            .args(["agent", "diff", "--base", "pt-20260101-000000-zzzz"])
            .assert()
            .code(ExitCode::ArgsError.as_i32());
    });
}

#[test]
fn diff_base_without_plan_returns_args_error() {
    with_temp_data_dir(|dir| {
        // Create session but no plan.json
        let store = SessionStore::from_env().expect("store");
        let session_id = SessionId::new();
        let manifest = SessionManifest::new(&session_id, None, SessionMode::RobotPlan, None);
        let handle = store.create(&manifest).expect("create");
        let ctx = SessionContext::new(
            &session_id,
            "host-test".to_string(),
            "run-test".to_string(),
            None,
        );
        handle.write_context(&ctx).expect("write ctx");

        pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", dir.path())
            .args(["agent", "diff", "--base", &session_id.0])
            .assert()
            .code(ExitCode::ArgsError.as_i32());
    });
}

#[test]
fn diff_single_session_no_compare_returns_args_error() {
    with_temp_data_dir(|dir| {
        // Only one session exists — no compare session to find
        let base = create_session_with_candidates(
            dir,
            &[make_candidate(100, "abandoned", "kill", 0.9)],
            "2026-01-01T00:00:00Z",
        );

        pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", dir.path())
            .args(["agent", "diff", "--base", &base.0])
            .assert()
            .code(ExitCode::ArgsError.as_i32());
    });
}

#[test]
fn diff_two_sessions_produces_json() {
    with_temp_data_dir(|dir| {
        let base = create_session_with_candidates(
            dir,
            &[
                make_candidate(100, "abandoned", "kill", 0.9),
                make_candidate(200, "useful", "keep", 0.1),
            ],
            "2026-01-01T00:00:00Z",
        );

        let compare = create_session_with_candidates(
            dir,
            &[
                make_candidate(100, "abandoned", "kill", 0.95),
                make_candidate(300, "zombie", "kill", 0.99),
            ],
            "2026-01-01T01:00:00Z",
        );

        let output = pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", dir.path())
            .args(["agent", "diff", "--base", &base.0, "--compare", &compare.0])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).expect("output should be valid JSON");

        // Check structure
        assert!(json.get("comparison").is_some(), "should have comparison");
        assert!(json.get("delta").is_some(), "should have delta");
        assert!(json.get("summary").is_some(), "should have summary");

        let comparison = &json["comparison"];
        assert_eq!(comparison["prior_session"].as_str().unwrap(), base.0);
        assert_eq!(comparison["current_session"].as_str().unwrap(), compare.0);

        let summary = &json["summary"];
        assert_eq!(summary["prior_candidates"].as_u64().unwrap(), 2);
        assert_eq!(summary["current_candidates"].as_u64().unwrap(), 2);

        // PID 200 was in base but not in compare → resolved
        assert!(
            summary["resolved_count"].as_u64().unwrap() >= 1,
            "PID 200 should be resolved"
        );

        // PID 300 is new in compare
        assert!(
            summary["new_count"].as_u64().unwrap() >= 1,
            "PID 300 should be new"
        );
    });
}

#[test]
fn diff_focus_new_only() {
    with_temp_data_dir(|dir| {
        let base = create_session_with_candidates(
            dir,
            &[make_candidate(100, "abandoned", "kill", 0.9)],
            "2026-01-01T00:00:00Z",
        );

        let compare = create_session_with_candidates(
            dir,
            &[
                make_candidate(100, "abandoned", "kill", 0.9),
                make_candidate(300, "zombie", "kill", 0.99),
            ],
            "2026-01-01T01:00:00Z",
        );

        let output = pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", dir.path())
            .args([
                "agent",
                "diff",
                "--base",
                &base.0,
                "--compare",
                &compare.0,
                "--focus",
                "new",
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).expect("valid JSON");
        assert_eq!(json["focus"].as_str().unwrap(), "new");

        // With focus=new, other delta categories should be empty
        let delta = &json["delta"];
        assert!(
            delta["worsened"].as_array().unwrap().is_empty(),
            "worsened should be empty with focus=new"
        );
        assert!(
            delta["resolved"].as_array().unwrap().is_empty(),
            "resolved should be empty with focus=new"
        );
    });
}

#[test]
fn diff_focus_removed() {
    with_temp_data_dir(|dir| {
        let base = create_session_with_candidates(
            dir,
            &[
                make_candidate(100, "abandoned", "kill", 0.9),
                make_candidate(200, "useful", "keep", 0.1),
            ],
            "2026-01-01T00:00:00Z",
        );

        let compare = create_session_with_candidates(
            dir,
            &[make_candidate(100, "abandoned", "kill", 0.9)],
            "2026-01-01T01:00:00Z",
        );

        let output = pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", dir.path())
            .args([
                "agent",
                "diff",
                "--base",
                &base.0,
                "--compare",
                &compare.0,
                "--focus",
                "removed",
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).expect("valid JSON");
        assert_eq!(json["focus"].as_str().unwrap(), "removed");

        let delta = &json["delta"];
        // PID 200 was removed
        let resolved = delta["resolved"].as_array().unwrap();
        assert!(
            !resolved.is_empty(),
            "should have at least one resolved entry"
        );

        // Other categories should be empty with focus=removed
        assert!(delta["new"].as_array().unwrap().is_empty());
        assert!(delta["worsened"].as_array().unwrap().is_empty());
    });
}

#[test]
fn diff_focus_changed_detects_worsened() {
    with_temp_data_dir(|dir| {
        // Base: PID 100 is "keep"
        let base = create_session_with_candidates(
            dir,
            &[make_candidate(100, "useful", "keep", 0.1)],
            "2026-01-01T00:00:00Z",
        );

        // Compare: PID 100 escalated to "kill"
        let compare = create_session_with_candidates(
            dir,
            &[make_candidate(100, "abandoned", "kill", 0.9)],
            "2026-01-01T01:00:00Z",
        );

        let output = pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", dir.path())
            .args([
                "agent",
                "diff",
                "--base",
                &base.0,
                "--compare",
                &compare.0,
                "--focus",
                "changed",
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).expect("valid JSON");
        let delta = &json["delta"];
        let worsened = delta["worsened"].as_array().unwrap();
        assert!(
            !worsened.is_empty(),
            "should detect worsened candidate (keep → kill)"
        );
        assert_eq!(worsened[0]["score_change"], 80);
        assert_eq!(worsened[0]["cmd_short"], "proc-100");
    });
}

#[test]
fn diff_keeps_identical_commands_distinct_and_detects_pid_reuse() {
    with_temp_data_dir(|dir| {
        let mut old = vec![
            make_candidate(100, "abandoned", "kill", 0.9),
            make_candidate(200, "abandoned", "kill", 0.9),
            make_candidate(300, "abandoned", "kill", 0.9),
        ];
        for candidate in &mut old {
            candidate["command_short"] = serde_json::json!("worker");
            candidate["command"] = serde_json::json!("worker --serve");
        }
        let mut current = vec![old[0].clone(), old[2].clone(), old[1].clone()];
        current[1]["start_id"] = serde_json::json!("test-boot:67890:300");
        // Ownership is part of identity, even if the PID and start token match.
        current[2]["uid"] = serde_json::json!(1001);
        let base = create_session_with_candidates(dir, &old, "2026-01-01T00:00:00Z");
        let compare = create_session_with_candidates(dir, &current, "2026-01-01T01:00:00Z");
        let run = || {
            pt_core_fast()
                .env("PROCESS_TRIAGE_DATA", dir.path())
                .args(["agent", "diff", "--base", &base.0, "--compare", &compare.0])
                .assert()
                .success()
                .get_output()
                .stdout
                .clone()
        };
        let output = run();
        assert_eq!(output, run(), "comparison ordering must be deterministic");
        let json: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(json["summary"]["new_count"], 2);
        assert_eq!(json["summary"]["resolved_count"], 2);
        assert_eq!(json["summary"]["persistent_count"], 1);
        assert_eq!(json["delta"]["persistent"][0]["pid"], 100);
        assert_eq!(json["delta"]["new"][0]["pid"], 200);
        assert_eq!(json["delta"]["new"][1]["start_id"], "test-boot:67890:300");
        assert_eq!(json["delta"]["resolved"][0]["uid"], 1000);
    });
}

#[test]
fn diff_reports_suspicion_drift_without_action_changes() {
    with_temp_data_dir(|dir| {
        let base = create_session_with_candidates(
            dir,
            &[make_candidate(100, "useful", "review", 0.1)],
            "2026-01-01T00:00:00Z",
        );
        let compare = create_session_with_candidates(
            dir,
            &[make_candidate(100, "useful", "review", 0.3)],
            "2026-01-01T01:00:00Z",
        );
        let output = pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", dir.path())
            .args(["agent", "diff", "--base", &base.0, "--compare", &compare.0])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let json: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(json["summary"]["worsened_count"], 1);
        assert_eq!(json["delta"]["worsened"][0]["score_change"], 20);
        assert_eq!(json["summary"]["improved_count"], 0);
    });
}

#[test]
fn diff_focus_changed_preserves_action_and_classification_changes() {
    with_temp_data_dir(|dir| {
        let base = create_session_with_candidates(
            dir,
            &[
                make_candidate(100, "useful_bad", "pause", 0.4),
                make_candidate(200, "useful", "review", 0.4),
                make_candidate(300, "useful_bad", "review", 0.4),
            ],
            "2026-01-01T00:00:00Z",
        );
        let compare = create_session_with_candidates(
            dir,
            &[
                make_candidate(100, "useful_bad", "resume", 0.4),
                make_candidate(200, "useful", "throttle", 0.4),
                make_candidate(300, "abandoned", "review", 0.4),
            ],
            "2026-01-01T01:00:00Z",
        );
        for focus in ["changed", "all", "new"] {
            let output = pt_core_fast()
                .env("PROCESS_TRIAGE_DATA", dir.path())
                .args([
                    "agent",
                    "diff",
                    "--base",
                    &base.0,
                    "--compare",
                    &compare.0,
                    "--focus",
                    focus,
                ])
                .assert()
                .success()
                .get_output()
                .stdout
                .clone();
            let json: Value = serde_json::from_slice(&output).unwrap();
            assert_eq!(json["summary"]["changed_count"], 3);
            for category in ["worsened_count", "improved_count", "persistent_count"] {
                assert_eq!(json["summary"][category], 0);
            }
            let changed = json["delta"]["changed"].as_array().unwrap();
            if focus == "new" {
                assert!(changed.is_empty());
            } else {
                assert_eq!(changed.len(), 3);
                assert_eq!(changed[0]["prior_action"], "pause");
                assert_eq!(changed[0]["current_action"], "resume");
                assert_eq!(changed[0]["score_change"], 0);
                assert_eq!(changed[1]["current_action"], "throttle");
                assert_eq!(changed[2]["prior_classification"], "useful_bad");
                assert_eq!(changed[2]["current_classification"], "abandoned");
            }
        }
    });
}

#[test]
fn diff_rejects_incomplete_or_duplicate_candidate_identities() {
    with_temp_data_dir(|dir| {
        let candidate = make_candidate(100, "abandoned", "kill", 0.9);
        let base = create_session_with_candidates(
            dir,
            std::slice::from_ref(&candidate),
            "2026-01-01T00:00:00Z",
        );
        let mut missing_identity = candidate.clone();
        missing_identity.as_object_mut().unwrap().remove("start_id");
        for candidates in [vec![missing_identity], vec![candidate.clone(), candidate]] {
            let compare = create_session_with_candidates(dir, &candidates, "2026-01-01T01:00:00Z");
            pt_core_fast()
                .env("PROCESS_TRIAGE_DATA", dir.path())
                .args(["agent", "diff", "--base", &base.0, "--compare", &compare.0])
                .assert()
                .code(ExitCode::ArgsError.as_i32());
        }
    });
}

#[test]
fn diff_latest_skips_action_only_and_foreign_host_plans() {
    with_temp_data_dir(|dir| {
        let base = create_session_with_candidates(
            dir,
            &[make_candidate(100, "useful", "keep", 0.1)],
            "2026-01-01T00:00:00Z",
        );
        let compare = create_session_with_candidates(
            dir,
            &[make_candidate(100, "abandoned", "kill", 0.9)],
            "2026-01-01T01:00:00Z",
        );
        let action_only = create_session_with_candidates(dir, &[], "2026-01-01T02:00:00Z");
        let foreign = create_session_with_candidates(dir, &[], "2026-01-01T03:00:00Z");
        let store = SessionStore::from_env().unwrap();
        let action_path = store
            .open(&action_only)
            .unwrap()
            .dir
            .join("decision/plan.json");
        fs::write(
            action_path,
            serde_json::to_vec(&serde_json::json!({
                "session_id": action_only.0,
                "actions": [],
            }))
            .unwrap(),
        )
        .unwrap();
        let foreign_path = store.open(&foreign).unwrap().dir.join("decision/plan.json");
        let mut foreign_plan: Value =
            serde_json::from_slice(&fs::read(&foreign_path).unwrap()).unwrap();
        foreign_plan["host_id"] = serde_json::json!("another-host");
        fs::write(&foreign_path, serde_json::to_vec(&foreign_plan).unwrap()).unwrap();

        let output = pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", dir.path())
            .args(["agent", "diff", "--base", &base.0])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let json: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(json["comparison"]["current_session"], compare.0);
        assert_eq!(json["delta"]["worsened"][0]["score_change"], 80);

        // Explicit references remain errors rather than silently choosing a
        // different session when the named evidence is incompatible.
        for incompatible in [&action_only, &foreign] {
            pt_core_fast()
                .env("PROCESS_TRIAGE_DATA", dir.path())
                .args([
                    "agent",
                    "diff",
                    "--base",
                    &base.0,
                    "--compare",
                    &incompatible.0,
                ])
                .assert()
                .code(ExitCode::ArgsError.as_i32());
        }
    });
}

#[cfg(unix)]
#[test]
fn diff_latest_uses_plan_observation_times_instead_of_session_creation_order() {
    with_temp_data_dir(|dir| {
        // This older directory represents a resumed session. Its observation
        // is newer after applying the timezone offset, despite its creation
        // order and the misleading lexical order of the timestamp strings.
        let resumed = create_session_with_candidates(
            dir,
            &[make_candidate(100, "abandoned", "kill", 0.9)],
            "2026-01-01T01:00:00Z",
        );
        let resumed_handle = SessionStore::from_env().unwrap().open(&resumed).unwrap();
        let mut manifest = resumed_handle.read_manifest().unwrap();
        manifest.timing.created_at = "2025-12-01T00:00:00Z".to_string();
        resumed_handle.write_manifest(&manifest).unwrap();
        let base = create_session_with_candidates(
            dir,
            &[make_candidate(100, "useful", "keep", 0.1)],
            "2026-01-01T00:00:00Z",
        );
        create_session_with_candidates(
            dir,
            &[make_candidate(100, "useful_bad", "review", 0.3)],
            "2026-01-01T02:30:00+02:00",
        );
        let output = pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", dir.path())
            .args(["agent", "diff", "--base", &base.0, "--compare", "latest"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let json: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(json["comparison"]["current_session"], resumed.0);
        assert_eq!(json["delta"]["worsened"][0]["score_change"], 80);
    });
}

#[cfg(unix)]
#[test]
fn diff_consumes_real_plans_with_concurrent_identical_workers() {
    struct Worker(std::process::Child);
    impl Worker {
        fn spawn() -> Self {
            Self(
                std::process::Command::new("sleep")
                    .arg("120")
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .expect("spawn disposable worker"),
            )
        }
    }
    impl Drop for Worker {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    with_temp_data_dir(|dir| {
        let config_dir = dir.path().join("config");
        fs::create_dir_all(&config_dir).unwrap();
        let mut policy = pt_common::config::policy::Policy::default();
        policy.guardrails.builtin_protection = false;
        policy.guardrails.protected_users.clear();
        policy.guardrails.min_process_age_seconds = 0;
        fs::write(
            config_dir.join("policy.json"),
            serde_json::to_vec(&policy).unwrap(),
        )
        .unwrap();
        let stable = Worker::spawn();
        let departed = Worker::spawn();
        let plan = |pids: &[u32]| {
            let selected = pids
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(",");
            let output = pt_core_fast()
                .env("PROCESS_TRIAGE_DATA", dir.path())
                .arg("--config")
                .arg(&config_dir)
                .args([
                    "--format",
                    "json",
                    "agent",
                    "plan",
                    "--pids",
                    &selected,
                    "--min-age",
                    "0",
                    "--min-posterior",
                    "0",
                    "--window-ms",
                    "0",
                ])
                .assert()
                .code(ExitCode::PlanReady.as_i32())
                .get_output()
                .stdout
                .clone();
            let json: Value = serde_json::from_slice(&output).unwrap();
            let actual: std::collections::BTreeSet<_> = json["candidates"]
                .as_array()
                .unwrap()
                .iter()
                .map(|candidate| candidate["pid"].as_u64().unwrap() as u32)
                .collect();
            assert_eq!(actual, pids.iter().copied().collect());
            json
        };
        let base = plan(&[stable.0.id(), departed.0.id()]);
        let departed_pid = departed.0.id();
        drop(departed);
        let arrived = Worker::spawn();
        let compare = plan(&[stable.0.id(), arrived.0.id()]);
        let output = pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", dir.path())
            .args([
                "agent",
                "diff",
                "--base",
                base["session_id"].as_str().unwrap(),
                "--compare",
                compare["session_id"].as_str().unwrap(),
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let json: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(json["summary"]["prior_candidates"], 2);
        assert_eq!(json["summary"]["current_candidates"], 2);
        assert_eq!(json["summary"]["new_count"], 1);
        assert_eq!(json["summary"]["resolved_count"], 1);
        assert_eq!(json["delta"]["new"][0]["pid"], arrived.0.id());
        assert_eq!(json["delta"]["new"][0]["cmd_short"], "sleep");
        assert_eq!(json["delta"]["resolved"][0]["pid"], departed_pid);
    });
}

#[test]
fn diff_summary_format() {
    with_temp_data_dir(|dir| {
        let base = create_session_with_candidates(
            dir,
            &[make_candidate(100, "abandoned", "kill", 0.9)],
            "2026-01-01T00:00:00Z",
        );

        let compare = create_session_with_candidates(
            dir,
            &[make_candidate(100, "abandoned", "kill", 0.9)],
            "2026-01-01T01:00:00Z",
        );

        let output = pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", dir.path())
            .args([
                "--format",
                "summary",
                "agent",
                "diff",
                "--base",
                &base.0,
                "--compare",
                &compare.0,
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let stdout = String::from_utf8_lossy(&output);
        // Summary format should contain "agent diff:" prefix
        assert!(
            stdout.contains("agent diff:"),
            "summary output should contain 'agent diff:'"
        );
    });
}

#[test]
fn diff_empty_candidates() {
    with_temp_data_dir(|dir| {
        let base = create_session_with_candidates(dir, &[], "2026-01-01T00:00:00Z");

        let compare = create_session_with_candidates(dir, &[], "2026-01-01T01:00:00Z");

        let output = pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", dir.path())
            .args(["agent", "diff", "--base", &base.0, "--compare", &compare.0])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).expect("valid JSON");
        let summary = &json["summary"];
        assert_eq!(summary["prior_candidates"].as_u64().unwrap(), 0);
        assert_eq!(summary["current_candidates"].as_u64().unwrap(), 0);
        assert_eq!(summary["new_count"].as_u64().unwrap(), 0);
    });
}

// ============================================================================
// query tests (sessions implemented; actions/telemetry remain stubs)
// ============================================================================

#[test]
fn query_without_subcommand_is_usage_error() {
    // Root query without a subcommand prints guidance; it is a usage error, not success
    // (agents must not read a guidance stub as a completed query).
    pt_core_fast()
        .args(["query"])
        .assert()
        .code(10)
        .stdout(predicates::str::contains("query sessions"));
}

#[test]
fn query_sessions_subcommand() {
    with_temp_data_dir(|dir| {
        let created = create_session_with_candidates(
            dir,
            &[make_candidate(9001, "abandoned", "terminate", 0.92)],
            "2026-01-01T00:00:00Z",
        );

        let output = pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", dir.path())
            .args(["--format", "json", "query", "sessions", "--limit", "10"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).expect("valid JSON");
        assert_eq!(json["status"].as_str(), Some("ok"));
        assert_eq!(json["query"].as_str(), Some("sessions"));
        assert!(
            json["sessions"].as_array().is_some(),
            "sessions field should be an array"
        );

        let found = json["sessions"].as_array().unwrap().iter().any(|session| {
            session["session_id"]
                .as_str()
                .map(|id| id == created.0.as_str())
                .unwrap_or(false)
        });
        assert!(found, "expected created session to appear in query output");
    });
}

#[test]
fn query_actions_subcommand_reports_missing_capability() {
    // Not implemented yet: must say so with exit 11 (CapabilityError), never exit 0.
    pt_core_fast()
        .args(["query", "actions"])
        .assert()
        .code(11)
        .stdout(predicates::str::contains("not yet implemented"));
}

/// Every stub command reports `"status": "stub"` and exits 11 (CapabilityError),
/// never 0. (`output_stub` returns that exit code and is `#[must_use]`, so new
/// stubs cannot silently exit 0; this checks the shipped ones end to end.)
#[test]
fn every_stub_command_exits_capability_error() {
    let mut stubs: Vec<Vec<&str>> = vec![
        vec!["query", "actions"],
        vec!["query", "telemetry"],
        vec!["query", "last hour kills"],
        vec![
            "telemetry",
            "export",
            "-o",
            "/nonexistent/pt-export.parquet",
        ],
        vec!["telemetry", "redact"],
    ];
    if !cfg!(target_os = "linux") {
        stubs.push(vec!["deep-scan"]);
    }
    for args in stubs {
        let output = pt_core_fast()
            .args(["--format", "json"])
            .args(&args)
            .output()
            .expect("run stub");
        assert_eq!(output.status.code(), Some(11), "{args:?}");
        let json: Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|e| panic!("{args:?}: stub output not JSON ({e})"));
        assert_eq!(json["status"], "stub", "{args:?}: {json}");
    }
}

#[test]
fn query_telemetry_subcommand_reports_missing_capability() {
    pt_core_fast()
        .args(["query", "telemetry"])
        .assert()
        .code(11)
        .stdout(predicates::str::contains("not yet implemented"));
}
