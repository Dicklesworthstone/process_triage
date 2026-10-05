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
use pt_core::session::resume::{
    resume_plan, CurrentIdentity, ExecutionPlan, PlannedAction, RevalidationIdentity,
};
use pt_core::session::{SessionContext, SessionManifest, SessionMode, SessionState, SessionStore};
use pt_core::test_utils::ProcessHarness;
use pt_core::verify::{capture_execution_clock, verify_plan, SavedActionOutcome, VerifyOutcome};
use std::env;
use std::fs;
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::Duration;
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

fn read_boot_id() -> Option<String> {
    let contents = fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    Some(contents.trim().to_string())
}

fn parse_start_time_ticks(stat: &str) -> Option<u64> {
    let end = stat.rfind(')')?;
    let rest = stat.get(end + 2..)?;
    let fields: Vec<&str> = rest.split_whitespace().collect();
    if fields.len() < 20 {
        return None;
    }
    fields[19].parse().ok()
}

fn uid_from_status(status: &str) -> Option<u32> {
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest
                .split_whitespace()
                .next()
                .and_then(|val| val.parse::<u32>().ok());
        }
    }
    None
}

fn current_identity_from_proc(pid: u32, boot_id: &str) -> Option<CurrentIdentity> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let start_time_ticks = parse_start_time_ticks(&stat)?;
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let uid = uid_from_status(&status)?;
    let start_id = StartId::from_linux(boot_id, start_time_ticks, pid);
    Some(CurrentIdentity {
        pid,
        start_id: start_id.0,
        uid,
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

        handle
            .update_state(SessionState::Planned)
            .expect("state planned");
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

    let harness = ProcessHarness;
    let proc = harness.spawn_sleep(10).expect("spawn sleep process");
    let pid = proc.pid();

    let record = wait_for_record(pid).expect("live verification target must be observable");
    let records = vec![record.clone()];
    let identity = ProcessIdentity {
        pid: record.pid,
        start_id: record.start_id.clone(),
        uid: record.uid,
        pgid: record.pgid,
        sid: record.sid,
        quality: IdentityQuality::Full,
    };
    let bundle = DecisionBundle {
        session_id: SessionId::new(),
        policy: Policy::default(),
        generated_at: Some(Utc::now().to_rfc3339()),
        candidates: vec![DecisionCandidate {
            identity,
            ppid: Some(record.ppid.0),
            decision: make_decision(),
            blocked_reasons: vec![],
            stage_pause_before_kill: false,
            process_state: Some(record.state),
            parent_identity: None,
            d_state_diagnostics: None,
        }],
    };
    let plan = generate_plan(&bundle);
    assert_eq!(plan.actions.len(), 1);
    // Deliberately claim success while the real target remains alive. This is
    // a verification fault-injection record, not evidence that apply executed.
    let execution = SavedActionOutcome {
        action_id: plan.actions[0].action_id.clone(),
        pid,
        status: "success".to_string(),
        target: Some(plan.actions[0].target.clone()),
        command: Some(record.cmd.clone()),
        parent_pid: Some(record.ppid.0),
        parent_identity: None,
        executed_at: Some(Utc::now()),
        execution_clock: capture_execution_clock(),
        time_ms: None,
    };
    let report_running = verify_plan(
        &plan,
        &[execution.clone()],
        &records,
        Utc::now(),
        Utc::now(),
    )
    .expect("verify bound execution evidence");
    assert_eq!(report_running.action_outcomes.len(), 1);
    assert!(matches!(
        report_running.action_outcomes[0].outcome,
        VerifyOutcome::StillRunning
    ));

    let mut reused_record = record.clone();
    let mut parts = record.start_id.0.rsplitn(3, ':');
    let identity_pid = parts.next().expect("identity PID");
    let ticks = parts
        .next()
        .expect("identity ticks")
        .parse::<u64>()
        .unwrap();
    let boot = parts.next().expect("identity boot");
    reused_record.start_id = StartId(format!("{boot}:{}:{identity_pid}", ticks.saturating_add(1)));
    let report_mismatch = verify_plan(
        &plan,
        &[execution.clone()],
        &[reused_record],
        Utc::now(),
        Utc::now(),
    )
    .expect("verify changed process identity");
    assert_eq!(report_mismatch.action_outcomes.len(), 1);
    assert!(matches!(
        report_mismatch.action_outcomes[0].outcome,
        VerifyOutcome::PidReused
    ));

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

    assert!(gone, "owned verification target must exit and disappear");
    let report_dead = verify_plan(&plan, &[execution], &records_after, Utc::now(), Utc::now())
        .expect("verify observed target disappearance");
    assert_eq!(report_dead.action_outcomes.len(), 1);
    assert!(matches!(
        report_dead.action_outcomes[0].outcome,
        VerifyOutcome::ConfirmedDead
    ));
}

#[test]
fn test_resume_plan_with_real_process_nomock() {
    if !ProcessHarness::is_available() {
        return;
    }

    let harness = ProcessHarness;
    let proc = harness.spawn_sleep(15).expect("spawn sleep process");
    let pid = proc.pid();

    if wait_for_record(pid).is_none() {
        return;
    }

    let boot_id = match read_boot_id() {
        Some(id) => id,
        None => return,
    };
    let identity = match current_identity_from_proc(pid, &boot_id) {
        Some(cur) => RevalidationIdentity {
            pid,
            start_id: cur.start_id.clone(),
            uid: cur.uid,
        },
        None => return,
    };
    let action = PlannedAction {
        identity: identity.clone(),
        action: "kill".to_string(),
        expected_loss: 0.1,
        rationale: "resume-test".to_string(),
    };
    let mut plan = ExecutionPlan::new("session-resume", vec![action]);

    let result = resume_plan(
        &mut plan,
        |pid| current_identity_from_proc(pid, &boot_id),
        |a| {
            if a.identity.pid == pid {
                proc.trigger_exit();
            }
            Ok(())
        },
    );

    assert_eq!(result.newly_applied, 1);
    assert!(plan.is_complete());

    proc.wait_for_exit(Duration::from_secs(2));

    let second = resume_plan(
        &mut plan,
        |pid| current_identity_from_proc(pid, &boot_id),
        |_| Ok(()),
    );
    assert_eq!(second.previously_applied, 1);
    assert_eq!(second.newly_applied, 0);
}

#[test]
fn test_resume_plan_identity_mismatch_nomock() {
    if !ProcessHarness::is_available() {
        return;
    }

    let harness = ProcessHarness;
    let proc = harness.spawn_sleep(10).expect("spawn sleep process");
    let pid = proc.pid();

    if wait_for_record(pid).is_none() {
        return;
    }

    let boot_id = match read_boot_id() {
        Some(id) => id,
        None => return,
    };
    let identity = match current_identity_from_proc(pid, &boot_id) {
        Some(cur) => RevalidationIdentity {
            pid,
            start_id: format!("mismatch:{}", cur.start_id),
            uid: cur.uid,
        },
        None => return,
    };
    let action = PlannedAction {
        identity,
        action: "kill".to_string(),
        expected_loss: 0.1,
        rationale: "resume-mismatch".to_string(),
    };
    let mut plan = ExecutionPlan::new("session-mismatch", vec![action]);

    let result = resume_plan(
        &mut plan,
        |pid| current_identity_from_proc(pid, &boot_id),
        |_| Ok(()),
    );
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

    let harness = ProcessHarness;
    let proc = harness.spawn_sleep(5).expect("spawn sleep process");
    let pid = proc.pid();

    let boot_id = match read_boot_id() {
        Some(id) => id,
        None => return,
    };
    let identity = match current_identity_from_proc(pid, &boot_id) {
        Some(cur) => RevalidationIdentity {
            pid,
            start_id: cur.start_id,
            uid: cur.uid,
        },
        None => return,
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

    let result = resume_plan(
        &mut plan,
        |pid| current_identity_from_proc(pid, &boot_id),
        |_| Ok(()),
    );
    assert_eq!(result.skipped_process_gone, 1);
    assert_eq!(result.newly_applied, 0);
}
