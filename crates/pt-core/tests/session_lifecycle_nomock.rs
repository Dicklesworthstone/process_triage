//! No-mock session lifecycle + verify tests.
//!
//! Covers:
//! - Session creation, persistence, and state transitions
//! - Plan generation from DecisionBundle fixtures
//! - Verify outcomes using real processes (TOCTOU checks)

#![cfg(feature = "test-utils")]

use chrono::Utc;
use pt_common::{IdentityQuality, ProcessId, ProcessIdentity, SessionId, StartId};
use pt_core::collect::{quick_scan, ProcessRecord, QuickScanOptions};
use pt_core::config::Policy;
use pt_core::decision::{Action, DecisionOutcome, DecisionRationale, ExpectedLoss};
use pt_core::plan::{generate_plan, DecisionBundle, DecisionCandidate};
use pt_core::session::{SessionContext, SessionManifest, SessionMode, SessionState, SessionStore};
use pt_core::session::resume::{
    CurrentIdentity, ExecutionPlan, PlannedAction, RevalidationIdentity, resume_plan,
};
use pt_core::test_utils::ProcessHarness;
use pt_core::verify::{AgentPlan, BlastRadius, PlanCandidate, VerifyOutcome, verify_plan};
use std::env;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use std::thread;
use tempfile::TempDir;

static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn with_temp_data_dir<T>(f: impl FnOnce(&TempDir) -> T) -> T {
    let _guard = ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("env lock poisoned");

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

fn scan_pid(pid: u32) -> Vec<ProcessRecord> {
    let options = QuickScanOptions {
        pids: vec![pid],
        include_kernel_threads: false,
        timeout: Some(Duration::from_secs(2)),
        progress: None,
    };
    match quick_scan(&options) {
        Ok(result) => result.processes,
        Err(_) => Vec::new(),
    }
}

fn record_for_pid(pid: u32) -> Option<ProcessRecord> {
    scan_pid(pid).into_iter().find(|p| p.pid.0 == pid)
}

fn wait_for_record(pid: u32) -> Option<ProcessRecord> {
    for _ in 0..10 {
        if let Some(record) = record_for_pid(pid) {
            return Some(record);
        }
        thread::sleep(Duration::from_millis(50));
    }
    None
}

fn current_identity(pid: u32) -> Option<CurrentIdentity> {
    let record = record_for_pid(pid)?;
    Some(CurrentIdentity {
        pid,
        start_id: record.start_id.0,
        uid: record.uid,
        alive: true,
    })
}

fn make_decision() -> DecisionOutcome {
    DecisionOutcome {
        expected_loss: vec![ExpectedLoss {
            action: Action::Kill,
            loss: 0.5,
        }],
        optimal_action: Action::Kill,
        sprt_boundary: None,
        posterior_odds_abandoned_vs_useful: None,
        recovery_expectations: None,
        rationale: DecisionRationale {
            chosen_action: Action::Kill,
            tie_break: false,
            disabled_actions: vec![],
            used_recovery_preference: false,
            posterior: None,
            memory_mb: None,
            has_known_signature: None,
            category: None,
        },
        risk_sensitive: None,
        dro: None,
    }
}

#[test]
fn test_session_lifecycle_persistence_nomock() {
    with_temp_data_dir(|_dir| {
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

        handle.update_state(SessionState::Planned).expect("state planned");
        handle
            .update_state(SessionState::Executing)
            .expect("state executing");
        handle
            .update_state(SessionState::Completed)
            .expect("state completed");

        let updated = handle.read_manifest().expect("read manifest");
        assert_eq!(updated.state, SessionState::Completed);
        assert!(updated.state_history.len() >= 4);

        assert!(handle.dir.exists());
        assert!(handle.dir.join("decision").exists());

        // Plan generation fixture (no mocks)
        let identity = ProcessIdentity {
            pid: ProcessId(1000),
            start_id: StartId("boot:1:1000".to_string()),
            uid: 1000,
            pgid: None,
            sid: Some(1000),
            quality: IdentityQuality::Full,
        };
        let bundle = DecisionBundle {
            session_id: session_id.clone(),
            policy: Policy::default(),
            candidates: vec![DecisionCandidate {
                identity,
                ppid: None,
                decision: make_decision(),
                blocked_reasons: vec![],
                stage_pause_before_kill: false,
                process_state: None,
                parent_identity: None,
                d_state_diagnostics: None,
            }],
            generated_at: Some(Utc::now().to_rfc3339()),
        };
        let plan = generate_plan(&bundle);
        assert!(!plan.actions.is_empty());

        let plan_path = handle.dir.join("decision").join("plan.json");
        let content = serde_json::to_string_pretty(&plan).expect("serialize plan");
        std::fs::write(&plan_path, content).expect("write plan");
        assert!(plan_path.exists());
    });
}

#[test]
fn test_verify_plan_with_real_process_nomock() {
    if !ProcessHarness::is_available() {
        return;
    }

    let harness = ProcessHarness::default();
    let proc = harness
        .spawn_sleep(10)
        .expect("spawn sleep process");
    let pid = proc.pid();

    let record = match wait_for_record(pid) {
        Some(r) => r,
        None => return,
    };
    let records = vec![record.clone()];

    let plan = AgentPlan {
        session_id: "pt-test".to_string(),
        generated_at: Some(Utc::now().to_rfc3339()),
        candidates: vec![PlanCandidate {
            pid,
            uid: record.uid,
            cmd_short: record.comm.clone(),
            cmd_full: record.cmd.clone(),
            start_id: Some(record.start_id.0.clone()),
            recommended_action: "kill".to_string(),
            blast_radius: Some(BlastRadius {
                memory_mb: 0.0,
                cpu_pct: 0.0,
            }),
        }],
    };

    let report_running = verify_plan(&plan, &records, Utc::now(), Utc::now());
    assert_eq!(report_running.action_outcomes.len(), 1);
    assert_eq!(
        report_running.action_outcomes[0].outcome,
        VerifyOutcome::StillRunning
    );

    let wrong_start_time = (record.start_time_unix.max(0) as u64).saturating_add(1);
    let legacy_start_id = format!("{}:{}", pid, wrong_start_time);
    let plan_mismatch = AgentPlan {
        session_id: "pt-test".to_string(),
        generated_at: Some(Utc::now().to_rfc3339()),
        candidates: vec![PlanCandidate {
            pid,
            uid: record.uid,
            cmd_short: record.comm.clone(),
            cmd_full: record.cmd.clone(),
            start_id: Some(legacy_start_id),
            recommended_action: "kill".to_string(),
            blast_radius: Some(BlastRadius {
                memory_mb: 0.0,
                cpu_pct: 0.0,
            }),
        }],
    };

    let report_mismatch = verify_plan(&plan_mismatch, &records, Utc::now(), Utc::now());
    assert_eq!(report_mismatch.action_outcomes.len(), 1);
    assert_eq!(
        report_mismatch.action_outcomes[0].outcome,
        VerifyOutcome::PidReused
    );

    proc.trigger_exit();
    proc.wait_for_exit(Duration::from_secs(2));

    let mut records_after = Vec::new();
    let mut gone = false;
    for _ in 0..10 {
        records_after = scan_pid(pid);
        if !records_after.iter().any(|p| p.pid.0 == pid) {
            gone = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    if !gone {
        return;
    }

    let report_dead = verify_plan(&plan, &records_after, Utc::now(), Utc::now());
    assert_eq!(report_dead.action_outcomes.len(), 1);
    assert!(matches!(
        report_dead.action_outcomes[0].outcome,
        VerifyOutcome::ConfirmedDead | VerifyOutcome::PidReused
    ));
}

#[test]
fn test_resume_plan_with_real_process_nomock() {
    if !ProcessHarness::is_available() {
        return;
    }

    let harness = ProcessHarness::default();
    let proc = harness
        .spawn_sleep(15)
        .expect("spawn sleep process");
    let pid = proc.pid();

    let record = match wait_for_record(pid) {
        Some(r) => r,
        None => return,
    };

    let identity = RevalidationIdentity {
        pid,
        start_id: record.start_id.0.clone(),
        uid: record.uid,
    };
    let action = PlannedAction {
        identity: identity.clone(),
        action: "kill".to_string(),
        expected_loss: 0.1,
        rationale: "resume-test".to_string(),
    };
    let mut plan = ExecutionPlan::new("session-resume", vec![action]);

    let result = resume_plan(&mut plan, |pid| current_identity(pid), |a| {
        if a.identity.pid == pid {
            proc.trigger_exit();
        }
        Ok(())
    });

    assert_eq!(result.newly_applied, 1);
    assert!(plan.is_complete());

    proc.wait_for_exit(Duration::from_secs(2));

    let second = resume_plan(&mut plan, |pid| current_identity(pid), |_| Ok(()));
    assert_eq!(second.previously_applied, 1);
    assert_eq!(second.newly_applied, 0);
}

#[test]
fn test_resume_plan_identity_mismatch_nomock() {
    if !ProcessHarness::is_available() {
        return;
    }

    let harness = ProcessHarness::default();
    let proc = harness
        .spawn_sleep(10)
        .expect("spawn sleep process");
    let pid = proc.pid();

    let record = match wait_for_record(pid) {
        Some(r) => r,
        None => return,
    };

    let identity = RevalidationIdentity {
        pid,
        start_id: format!("mismatch:{}", record.start_id.0),
        uid: record.uid,
    };
    let action = PlannedAction {
        identity,
        action: "kill".to_string(),
        expected_loss: 0.1,
        rationale: "resume-mismatch".to_string(),
    };
    let mut plan = ExecutionPlan::new("session-mismatch", vec![action]);

    let result = resume_plan(&mut plan, |pid| current_identity(pid), |_| Ok(()));
    assert_eq!(result.skipped_identity_mismatch, 1);
    assert_eq!(result.newly_applied, 0);

    proc.trigger_exit();
    proc.wait_for_exit(Duration::from_secs(2));
}

#[test]
fn test_resume_plan_process_gone_nomock() {
    if !ProcessHarness::is_available() {
        return;
    }

    let harness = ProcessHarness::default();
    let proc = harness
        .spawn_sleep(5)
        .expect("spawn sleep process");
    let pid = proc.pid();

    let record = match wait_for_record(pid) {
        Some(r) => r,
        None => return,
    };

    let identity = RevalidationIdentity {
        pid,
        start_id: record.start_id.0,
        uid: record.uid,
    };
    let action = PlannedAction {
        identity,
        action: "kill".to_string(),
        expected_loss: 0.1,
        rationale: "resume-gone".to_string(),
    };
    let mut plan = ExecutionPlan::new("session-gone", vec![action]);

    proc.trigger_exit();
    proc.wait_for_exit(Duration::from_secs(2));

    let result = resume_plan(&mut plan, |pid| current_identity(pid), |_| Ok(()));
    assert_eq!(result.skipped_process_gone, 1);
    assert_eq!(result.newly_applied, 0);
}
