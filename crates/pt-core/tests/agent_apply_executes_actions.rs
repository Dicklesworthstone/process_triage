//! `agent apply` really executes non-signal actions.
//!
//! Before 2026-09-24 `agent apply` only had a signal runner: kill/pause/resume could
//! run, and every other planned action (renice, freeze, throttle, quarantine) failed.
//! This test applies a real renice and then a real kill to a spawned child process
//! with its live identity (no dry-run) and checks each effect in /proc.

#![cfg(target_os = "linux")]

use assert_cmd::cargo::cargo_bin_cmd;
use pt_common::{IdentityQuality, ProcessId, ProcessIdentity, SessionId};
use pt_core::collect::{quick_scan, QuickScanOptions};
use pt_core::config::Policy;
use pt_core::decision::Action;
use pt_core::plan::{
    ActionConfidence, ActionHook, ActionRationale, ActionRouting, ActionTimeouts, GatesSummary,
    Plan, PlanAction,
};
use pt_core::session::{SessionContext, SessionManifest, SessionMode, SessionStore};
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::{Child, Command as ProcessCommand};
use std::time::Duration;
use tempfile::TempDir;

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Nice value of a live process (field 19 of /proc/<pid>/stat).
fn nice_of(pid: u32) -> Option<i64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = stat.rsplit_once(')')?.1;
    // After ")": state(3) ppid(4) ... nice is overall field 19 -> index 16 here.
    rest.split_whitespace().nth(16)?.parse().ok()
}

fn plan_action(action: Action, identity: &ProcessIdentity) -> PlanAction {
    PlanAction {
        action_id: format!("a-{action:?}").to_lowercase(),
        target: identity.clone(),
        action,
        order: 0,
        stage: 0,
        timeouts: ActionTimeouts::default(),
        pre_checks: Vec::new(),
        rationale: ActionRationale {
            expected_loss: None,
            expected_recovery: None,
            expected_recovery_stddev: None,
            posterior_odds_abandoned_vs_useful: None,
            sprt_boundary: None,
            posterior: None,
            memory_mb: Some(1.0),
            has_known_signature: None,
            category: None,
        },
        on_success: Vec::<ActionHook>::new(),
        on_failure: Vec::<ActionHook>::new(),
        blocked: false,
        routing: ActionRouting::Direct,
        confidence: ActionConfidence::Normal,
        original_zombie_target: None,
        d_state_diagnostics: None,
    }
}

/// Create a session holding a one-action plan; return the session id.
fn session_with_plan(data_dir: &Path, action: PlanAction) -> String {
    std::env::set_var("PROCESS_TRIAGE_DATA", data_dir);
    let store = SessionStore::from_env().expect("store");
    std::env::remove_var("PROCESS_TRIAGE_DATA");
    let session_id = SessionId::new();
    let handle = store
        .create(&SessionManifest::new(
            &session_id,
            None,
            SessionMode::RobotPlan,
            None,
        ))
        .expect("create session");
    handle
        .write_context(&SessionContext::new(
            &session_id,
            "host-test".to_string(),
            "run-test".to_string(),
            None,
        ))
        .expect("write context");
    let plan = Plan {
        plan_id: format!("plan-{}", action.action_id),
        session_id: session_id.0.clone(),
        generated_at: chrono::Utc::now().to_rfc3339(),
        policy_id: None,
        policy_version: "1.0.0".to_string(),
        actions: vec![action],
        pre_toggled: Vec::new(),
        gates_summary: GatesSummary {
            total_candidates: 1,
            blocked_candidates: 0,
            pre_toggled_actions: 0,
        },
    };
    let decision_dir = handle.dir.join("decision");
    fs::create_dir_all(&decision_dir).expect("decision dir");
    fs::write(
        decision_dir.join("plan.json"),
        serde_json::to_string_pretty(&plan).expect("serialize plan"),
    )
    .expect("write plan");
    session_id.0
}

/// Run a real (non-dry-run) `agent apply` and return the single outcome status.
fn apply(data_dir: &Path, config_dir: &Path, session: &str, target: &str) -> (String, Value) {
    let out = cargo_bin_cmd!("pt-core")
        .timeout(Duration::from_secs(120))
        .env("PT_SKIP_GLOBAL_LOCK", "1")
        .env("PROCESS_TRIAGE_DATA", data_dir)
        .env("PROCESS_TRIAGE_CONFIG", config_dir)
        .env("PROCESS_TRIAGE_RETENTION", "off")
        .args([
            "--format",
            "json",
            "agent",
            "apply",
            "--session",
            session,
            "--targets",
            target,
            "--yes",
        ])
        .output()
        .expect("run agent apply");
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let json: Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "apply output not JSON ({e}): {stdout}\nstderr: {}",
            String::from_utf8_lossy(&out.stderr)
        )
    });
    let status = json["outcomes"][0]["status"]
        .as_str()
        .unwrap_or("missing")
        .to_string();
    (status, json)
}

#[test]
fn agent_apply_executes_renice_then_kill_on_live_process() {
    let data_dir = TempDir::new().expect("data dir");
    let config_dir = TempDir::new().expect("config dir");
    let mut policy = Policy::default();
    policy.robot_mode.enabled = true;
    policy.robot_mode.min_posterior = 0.0;
    policy.robot_mode.require_human_for_supervised = false;
    fs::write(
        config_dir.path().join("policy.json"),
        serde_json::to_string_pretty(&policy).expect("serialize policy"),
    )
    .expect("write policy");

    let child = ProcessCommand::new("sleep")
        .arg("300")
        .spawn()
        .expect("spawn sleep");
    let mut guard = ChildGuard(child);
    let pid = guard.0.id();
    let nice_before = nice_of(pid).expect("read nice");

    // Real identity of the live child, exactly as a plan records it.
    let scan = quick_scan(&QuickScanOptions {
        pids: vec![pid],
        include_kernel_threads: false,
        timeout: Some(Duration::from_secs(30)),
        progress: None,
    })
    .expect("quick_scan child");
    let rec = scan
        .processes
        .iter()
        .find(|p| p.pid.0 == pid)
        .expect("child in scan");
    let identity = ProcessIdentity {
        pid: ProcessId(pid),
        start_id: rec.start_id.clone(),
        uid: rec.uid,
        pgid: rec.pgid,
        sid: rec.sid,
        quality: IdentityQuality::Full,
    };
    let target = format!("{}:{}", pid, identity.start_id.0);

    // 1) Renice: previously failed in apply ("requires ... support").
    let s1 = session_with_plan(data_dir.path(), plan_action(Action::Renice, &identity));
    let (status, json) = apply(data_dir.path(), config_dir.path(), &s1, &target);
    assert_eq!(status, "success", "renice outcome: {json}");
    // Renice only lowers priority: target nice is the default (10); a child that
    // already runs at nice >= 10 (the test was launched under `nice`) is left alone.
    let nice_after = nice_of(pid).expect("child alive after renice");
    let target_nice = i64::from(pt_core::action::renice::DEFAULT_NICE_VALUE);
    assert_eq!(
        nice_after,
        nice_before.max(target_nice),
        "unexpected nice after renice (before {nice_before})"
    );

    // 2) Kill.
    let s2 = session_with_plan(data_dir.path(), plan_action(Action::Kill, &identity));
    let (status, json) = apply(data_dir.path(), config_dir.path(), &s2, &target);
    assert_eq!(status, "success", "kill outcome: {json}");
    let exited = (0..50).any(|_| {
        if matches!(guard.0.try_wait(), Ok(Some(_))) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
        false
    });
    assert!(exited, "child {pid} still running after apply kill");
}
