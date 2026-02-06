//! E2E tests for `agent explain`, `agent sessions`, and `agent verify` commands.
//!
//! Tests these subcommands end-to-end through the CLI binary, verifying
//! JSON output schema, exit codes, and correct behavior.

use assert_cmd::cargo::cargo_bin_cmd;
use assert_cmd::Command;
use pt_common::{IdentityQuality, ProcessId, ProcessIdentity, SessionId, StartId};
use pt_core::decision::Action;
use pt_core::exit_codes::ExitCode;
use pt_core::plan::{
    ActionConfidence, ActionHook, ActionRationale, ActionRouting, ActionTimeouts, GatesSummary,
    Plan, PlanAction,
};
use pt_core::session::{SessionContext, SessionManifest, SessionMode, SessionStore};
use serde_json::Value;
use std::env;
use std::fs;
use std::process::Command as ProcessCommand;
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
    // Avoid lock contention when tests run in parallel
    cmd.env("PT_SKIP_GLOBAL_LOCK", "1");
    cmd
}

/// Create a test session with a plan containing the given process identity.
fn create_session_with_plan(_dir: &TempDir, identity: ProcessIdentity, blocked: bool) -> SessionId {
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

    let plan = Plan {
        plan_id: "plan-test".to_string(),
        session_id: session_id.0.clone(),
        generated_at: chrono::Utc::now().to_rfc3339(),
        policy_id: None,
        policy_version: "1.0.0".to_string(),
        actions: vec![PlanAction {
            action_id: "action-1".to_string(),
            target: identity,
            action: Action::Kill,
            order: 0,
            stage: 0,
            timeouts: ActionTimeouts::default(),
            pre_checks: vec![],
            rationale: ActionRationale {
                expected_loss: None,
                expected_recovery: None,
                expected_recovery_stddev: None,
                posterior_odds_abandoned_vs_useful: None,
                sprt_boundary: None,
                posterior: None,
                memory_mb: None,
                has_known_signature: None,
                category: None,
            },
            on_success: Vec::<ActionHook>::new(),
            on_failure: Vec::<ActionHook>::new(),
            blocked,
            routing: ActionRouting::Direct,
            confidence: ActionConfidence::Normal,
            original_zombie_target: None,
            d_state_diagnostics: None,
        }],
        pre_toggled: Vec::new(),
        gates_summary: GatesSummary {
            total_candidates: 1,
            blocked_candidates: if blocked { 1 } else { 0 },
            pre_toggled_actions: 0,
        },
    };

    let decision_dir = handle.dir.join("decision");
    fs::create_dir_all(&decision_dir).expect("create decision dir");
    let plan_path = decision_dir.join("plan.json");
    fs::write(
        &plan_path,
        serde_json::to_string_pretty(&plan).expect("serialize plan"),
    )
    .expect("write plan");

    // Also create inference dir for explain to write into
    fs::create_dir_all(handle.dir.join("inference")).expect("create inference dir");

    session_id
}

fn test_identity(pid: u32) -> ProcessIdentity {
    ProcessIdentity {
        pid: ProcessId(pid),
        start_id: StartId(format!("boot:1:{}", pid)),
        uid: 1000,
        pgid: None,
        sid: None,
        quality: IdentityQuality::Full,
    }
}

// ============================================================================
// agent explain tests
// ============================================================================

#[test]
fn explain_requires_session_flag() {
    // agent explain without --session should fail with ArgsError
    pt_core_fast()
        .args(["--format", "json", "agent", "explain"])
        .assert()
        .failure();
}

#[test]
fn explain_requires_pids_or_target() {
    with_temp_data_dir(|dir| {
        let session_id = create_session_with_plan(dir, test_identity(999_990), false);

        // explain with session but no --pids or --target should fail
        pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", dir.path())
            .args([
                "--format",
                "json",
                "agent",
                "explain",
                "--session",
                &session_id.0,
            ])
            .assert()
            .code(ExitCode::ArgsError.as_i32());
    });
}

#[test]
fn explain_invalid_session_returns_args_error() {
    with_temp_data_dir(|dir| {
        pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", dir.path())
            .args([
                "--format",
                "json",
                "agent",
                "explain",
                "--session",
                "not-a-valid-session-id",
                "--pids",
                "1",
            ])
            .assert()
            .code(ExitCode::ArgsError.as_i32());
    });
}

#[test]
fn explain_missing_session_returns_args_error() {
    with_temp_data_dir(|dir| {
        // Valid format but doesn't exist
        pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", dir.path())
            .args([
                "--format",
                "json",
                "agent",
                "explain",
                "--session",
                "pt-20260101-000000-zzzz",
                "--pids",
                "1",
            ])
            .assert()
            .code(ExitCode::ArgsError.as_i32());
    });
}

#[test]
#[cfg(target_os = "linux")]
fn explain_live_process_returns_explanation() {
    with_temp_data_dir(|dir| {
        // Spawn a known process so we have a valid PID to explain
        let child = ProcessCommand::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep process");
        let pid = child.id();
        let _guard = ChildGuard { child };

        let session_id = create_session_with_plan(dir, test_identity(pid), false);

        let output = pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", dir.path())
            .args([
                "--format",
                "json",
                "agent",
                "explain",
                "--session",
                &session_id.0,
                "--pids",
                &pid.to_string(),
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).expect("valid JSON");
        assert_eq!(
            json.get("command").and_then(|v| v.as_str()),
            Some("agent explain"),
        );
        assert!(json.get("schema_version").is_some());
        assert_eq!(
            json.get("session_id").and_then(|v| v.as_str()),
            Some(session_id.0.as_str()),
        );

        let explanations = json
            .get("explanations")
            .and_then(|v| v.as_array())
            .expect("explanations array");
        assert_eq!(explanations.len(), 1, "Expected one explanation");

        let expl = &explanations[0];
        assert_eq!(expl.get("pid").and_then(|v| v.as_u64()), Some(pid as u64),);
        // Process was live, so we expect a full explanation with classification
        // (classification is a string like "useful", "abandoned", "zombie")
        // OR if the process exited between spawn and scan, we get an error entry.
        if expl.get("error").is_none() {
            assert!(
                expl.get("classification")
                    .and_then(|v| v.as_str())
                    .is_some(),
                "Expected classification string for live process, got: {}",
                expl,
            );
            assert!(expl.get("posterior").is_some(), "Expected posterior field",);
        }
    });
}

#[test]
fn explain_nonexistent_pid_returns_error_entry() {
    with_temp_data_dir(|dir| {
        let fake_pid = 999_999u32;
        let session_id = create_session_with_plan(dir, test_identity(fake_pid), false);

        let output = pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", dir.path())
            .args([
                "--format",
                "json",
                "agent",
                "explain",
                "--session",
                &session_id.0,
                "--pids",
                &fake_pid.to_string(),
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).expect("valid JSON");
        let explanations = json
            .get("explanations")
            .and_then(|v| v.as_array())
            .expect("explanations array");
        assert_eq!(explanations.len(), 1);

        let expl = &explanations[0];
        assert_eq!(
            expl.get("pid").and_then(|v| v.as_u64()),
            Some(fake_pid as u64),
        );
        assert!(
            expl.get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .contains("not found"),
            "Expected 'not found' error for nonexistent PID",
        );
    });
}

#[test]
fn explain_saves_to_session_dir() {
    with_temp_data_dir(|dir| {
        let fake_pid = 999_998u32;
        let session_id = create_session_with_plan(dir, test_identity(fake_pid), false);

        pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", dir.path())
            .args([
                "--format",
                "json",
                "agent",
                "explain",
                "--session",
                &session_id.0,
                "--pids",
                &fake_pid.to_string(),
            ])
            .assert()
            .success();

        // Check that explain.json was written to session
        let explain_path = dir
            .path()
            .join("sessions")
            .join(&session_id.0)
            .join("inference")
            .join("explain.json");
        assert!(
            explain_path.exists(),
            "explain.json should be saved to session inference dir",
        );

        let content = fs::read_to_string(&explain_path).expect("read explain.json");
        let saved: Value = serde_json::from_str(&content).expect("parse explain.json");
        assert!(saved.get("explanations").is_some());
    });
}

#[test]
fn explain_with_target_flag() {
    with_temp_data_dir(|dir| {
        let fake_pid = 999_997u32;
        let session_id = create_session_with_plan(dir, test_identity(fake_pid), false);

        // Use --target format: pid:start_id
        let output = pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", dir.path())
            .args([
                "--format",
                "json",
                "agent",
                "explain",
                "--session",
                &session_id.0,
                "--target",
                &format!("{}:boot:1:{}", fake_pid, fake_pid),
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).expect("valid JSON");
        let explanations = json
            .get("explanations")
            .and_then(|v| v.as_array())
            .expect("explanations array");
        assert_eq!(explanations.len(), 1);
        assert_eq!(
            explanations[0].get("pid").and_then(|v| v.as_u64()),
            Some(fake_pid as u64),
        );
    });
}

// ============================================================================
// agent sessions tests
// ============================================================================

#[test]
fn sessions_list_empty_returns_ok() {
    with_temp_data_dir(|dir| {
        let output = pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", dir.path())
            .args(["--format", "json", "agent", "sessions"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).expect("valid JSON");
        assert_eq!(json.get("status").and_then(|v| v.as_str()), Some("ok"));
        assert_eq!(json.get("total_count").and_then(|v| v.as_u64()), Some(0),);
        let sessions = json
            .get("sessions")
            .and_then(|v| v.as_array())
            .expect("sessions array");
        assert!(sessions.is_empty());
    });
}

#[test]
fn sessions_list_shows_created_session() {
    with_temp_data_dir(|dir| {
        let session_id = create_session_with_plan(dir, test_identity(111_111), false);

        let output = pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", dir.path())
            .args(["--format", "json", "agent", "sessions"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).expect("valid JSON");
        assert_eq!(json.get("total_count").and_then(|v| v.as_u64()), Some(1),);

        let sessions = json
            .get("sessions")
            .and_then(|v| v.as_array())
            .expect("sessions array");
        assert_eq!(sessions.len(), 1);
        assert_eq!(
            sessions[0].get("session_id").and_then(|v| v.as_str()),
            Some(session_id.0.as_str()),
        );
    });
}

#[test]
fn sessions_detail_shows_session_info() {
    with_temp_data_dir(|dir| {
        let session_id = create_session_with_plan(dir, test_identity(222_222), false);

        let output = pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", dir.path())
            .args([
                "--format",
                "json",
                "agent",
                "sessions",
                "--session",
                &session_id.0,
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).expect("valid JSON");
        assert_eq!(
            json.get("session_id").and_then(|v| v.as_str()),
            Some(session_id.0.as_str()),
        );
        assert_eq!(json.get("status").and_then(|v| v.as_str()), Some("ok"));
        // Should have progress info
        assert!(json.get("progress").is_some(), "Expected progress field");
    });
}

#[test]
fn sessions_detail_invalid_session_returns_error() {
    with_temp_data_dir(|dir| {
        pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", dir.path())
            .args([
                "--format",
                "json",
                "agent",
                "sessions",
                "--session",
                "not-valid",
            ])
            .assert()
            .code(ExitCode::ArgsError.as_i32());
    });
}

#[test]
fn sessions_detail_missing_session_returns_error() {
    with_temp_data_dir(|dir| {
        pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", dir.path())
            .args([
                "--format",
                "json",
                "agent",
                "sessions",
                "--session",
                "pt-20260101-000000-zzzz",
            ])
            .assert()
            .code(ExitCode::ArgsError.as_i32());
    });
}

#[test]
fn sessions_list_with_limit() {
    with_temp_data_dir(|dir| {
        // Create 3 sessions
        create_session_with_plan(dir, test_identity(333_331), false);
        create_session_with_plan(dir, test_identity(333_332), false);
        create_session_with_plan(dir, test_identity(333_333), false);

        // List with limit=2
        let output = pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", dir.path())
            .args(["--format", "json", "agent", "sessions", "--limit", "2"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).expect("valid JSON");
        let sessions = json
            .get("sessions")
            .and_then(|v| v.as_array())
            .expect("sessions array");
        assert_eq!(
            sessions.len(),
            2,
            "Expected exactly 2 sessions with --limit 2"
        );
    });
}

#[test]
fn sessions_cleanup_empty_store() {
    with_temp_data_dir(|dir| {
        let output = pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", dir.path())
            .args([
                "--format",
                "json",
                "agent",
                "sessions",
                "--cleanup",
                "--older-than",
                "1d",
            ])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).expect("valid JSON");
        assert_eq!(json.get("removed_count").and_then(|v| v.as_u64()), Some(0),);
    });
}

// ============================================================================
// agent verify tests
// ============================================================================

#[test]
fn verify_requires_session_flag() {
    pt_core_fast()
        .args(["--format", "json", "agent", "verify"])
        .assert()
        .failure();
}

#[test]
fn verify_invalid_session_returns_args_error() {
    with_temp_data_dir(|dir| {
        pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", dir.path())
            .args([
                "--format",
                "json",
                "agent",
                "verify",
                "--session",
                "not-a-valid-session-id",
            ])
            .assert()
            .code(ExitCode::ArgsError.as_i32());
    });
}

#[test]
fn verify_missing_plan_returns_args_error() {
    with_temp_data_dir(|dir| {
        // Create session without a plan
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
        // No plan.json written

        pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", dir.path())
            .args([
                "--format",
                "json",
                "agent",
                "verify",
                "--session",
                &session_id.0,
            ])
            .assert()
            .code(ExitCode::ArgsError.as_i32());
    });
}

#[test]
fn verify_with_plan_produces_json() {
    with_temp_data_dir(|dir| {
        // Use a PID that almost certainly doesn't exist
        let fake_pid = 999_996u32;
        let session_id = create_session_with_plan(dir, test_identity(fake_pid), false);

        let output = pt_core_fast()
            .env("PROCESS_TRIAGE_DATA", dir.path())
            .args([
                "--format",
                "json",
                "agent",
                "verify",
                "--session",
                &session_id.0,
            ])
            .assert()
            .get_output()
            .stdout
            .clone();

        let json: Value = serde_json::from_slice(&output).expect("valid JSON");
        assert!(json.get("schema_version").is_some());
        assert_eq!(
            json.get("session_id").and_then(|v| v.as_str()),
            Some(session_id.0.as_str()),
        );
        assert!(
            json.get("verification").is_some(),
            "Expected verification field"
        );
    });
}

// ============================================================================
// helpers
// ============================================================================

struct ChildGuard {
    child: std::process::Child,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
