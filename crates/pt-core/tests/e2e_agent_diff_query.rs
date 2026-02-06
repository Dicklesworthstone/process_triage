//! E2E tests for `agent diff` and `query` subcommands.
//!
//! `agent diff` compares candidates between two sessions (plan.json).
//! `query` is currently a stub (returns success with a stub message).

use assert_cmd::cargo::cargo_bin_cmd;
use assert_cmd::Command;
use pt_core::exit_codes::ExitCode;
use pt_core::session::{SessionContext, SessionManifest, SessionMode, SessionStore};
use pt_common::SessionId;
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
        "cmd_short": format!("proc-{}", pid),
        "cmd_full": format!("/usr/bin/proc-{}", pid),
        "classification": classification,
        "recommended_action": action,
        "posterior": {
            "abandoned": score,
            "useful": 1.0 - score,
        },
    })
}

// ============================================================================
// agent diff tests
// ============================================================================

#[test]
fn diff_requires_base_flag() {
    pt_core_fast()
        .args(["agent", "diff"])
        .assert()
        .failure();
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
        let manifest =
            SessionManifest::new(&session_id, None, SessionMode::RobotPlan, None);
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
            .args([
                "agent", "diff", "--base", &base.0, "--compare", &compare.0,
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: Value =
            serde_json::from_slice(&output).expect("output should be valid JSON");

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
        assert!(!resolved.is_empty(), "should have at least one resolved entry");

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
            .args([
                "agent", "diff", "--base", &base.0, "--compare", &compare.0,
            ])
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
// query tests (stub implementation)
// ============================================================================

#[test]
fn query_returns_success() {
    // query is a stub but should return Clean exit code
    pt_core_fast()
        .args(["query"])
        .assert()
        .success();
}

#[test]
fn query_sessions_subcommand() {
    pt_core_fast()
        .args(["query", "sessions"])
        .assert()
        .success();
}

#[test]
fn query_actions_subcommand() {
    pt_core_fast()
        .args(["query", "actions"])
        .assert()
        .success();
}

#[test]
fn query_telemetry_subcommand() {
    pt_core_fast()
        .args(["query", "telemetry"])
        .assert()
        .success();
}
