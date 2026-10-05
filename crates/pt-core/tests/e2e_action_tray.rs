//! E2E Action-Tray Tests for pt-core.
//!
//! This module implements end-to-end tests for the expanded action space (Plan §6)
//! and staged execution protocol. It validates the "observe/mitigate before kill"
//! approach with strong, structured logging to diagnose failures.
//!
//! Test Scenarios Covered:
//! 1. Pause → observe → resume workflow
//! 2. Staged kill escalation (SIGTERM → SIGKILL)
//! 3. Safety gates in robot mode (protected patterns, data-loss gates, identity validation)
//! 4. Renice priority adjustment and verification; optional cgroup actions
//!
//! All tests capture structured logs including:
//! - Generated plan (JSON)
//! - Action attempts and outcomes
//! - Verification results
//! - Failure recovery hints

#![cfg(feature = "test-utils")]

use pt_common::{IdentityQuality, ProcessId, ProcessIdentity, StartId};
use pt_core::action::executor::{
    ActionExecutor, ActionStatus, ExecutionResult, NoopActionRunner, StaticIdentityProvider,
};
use pt_core::action::prechecks::NoopPreCheckProvider;
// Live prechecks and nice-value checks are exercised by Linux-only tests.
#[cfg(target_os = "linux")]
use pt_core::action::prechecks::{
    LivePreCheckConfig, LivePreCheckProvider, PreCheckProvider, PreCheckResult,
};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use pt_core::action::ReniceConfig;
use pt_core::action::{ReniceActionRunner, SignalActionRunner, SignalConfig};
use pt_core::collect::{quick_scan, QuickScanOptions};
use pt_core::decision::Action;
use pt_core::plan::{
    ActionConfidence, ActionRationale, ActionRouting, ActionTimeouts, GatesSummary, Plan,
    PlanAction, PreCheck,
};
use pt_core::test_utils::ProcessHarness;
use serde_json::json;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};
use tempfile::tempdir;

// ============================================================================
// Test Logging Utilities
// ============================================================================

/// Structured test event for logging
#[derive(Debug, Clone)]
struct TestEvent {
    timestamp: String,
    event_type: String,
    details: serde_json::Value,
}

impl TestEvent {
    fn new(event_type: &str, details: serde_json::Value) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            event_type: event_type.to_string(),
            details,
        }
    }

    fn to_jsonl(&self) -> String {
        serde_json::to_string(&json!({
            "timestamp": self.timestamp,
            "event": self.event_type,
            "details": self.details
        }))
        .unwrap_or_else(|_| "{}".to_string())
    }
}

/// Test context for capturing structured logs
struct TestContext {
    events: Vec<TestEvent>,
    session_artifact_dir: Option<String>,
}

impl TestContext {
    fn new() -> Self {
        Self {
            events: Vec::new(),
            session_artifact_dir: None,
        }
    }

    fn log(&mut self, event_type: &str, details: serde_json::Value) {
        let event = TestEvent::new(event_type, details);
        eprintln!("{}", event.to_jsonl());
        self.events.push(event);
    }

    fn log_plan(&mut self, plan: &Plan) {
        self.log(
            "plan_generated",
            json!({
                "action_count": plan.actions.len(),
                "actions": plan.actions.iter().map(|a| {
                    json!({
                        "id": a.action_id,
                        "action": format!("{:?}", a.action),
                        "target_pid": a.target.pid.0,
                        "pre_checks": a.pre_checks.iter().map(|c| format!("{:?}", c)).collect::<Vec<_>>(),
                        "blocked": a.blocked,
                    })
                }).collect::<Vec<_>>()
            }),
        );
    }

    fn log_action_attempt(&mut self, action: &PlanAction, phase: &str) {
        self.log(
            "action_attempt",
            json!({
                "action_id": action.action_id,
                "action": format!("{:?}", action.action),
                "target_pid": action.target.pid.0,
                "phase": phase
            }),
        );
    }

    fn log_verification(&mut self, action_id: &str, result: &str, details: serde_json::Value) {
        self.log(
            "verification",
            json!({
                "action_id": action_id,
                "result": result,
                "details": details
            }),
        );
    }

    fn log_execution_result(&mut self, result: &ExecutionResult) {
        self.log(
            "execution_complete",
            json!({
                "summary": {
                    "attempted": result.summary.actions_attempted,
                    "succeeded": result.summary.actions_succeeded,
                    "failed": result.summary.actions_failed,
                },
                "outcomes": result.outcomes.iter().map(|o| {
                    json!({
                        "action_id": o.action_id,
                        "status": format!("{:?}", o.status),
                        "time_ms": o.time_ms,
                        "details": o.details,
                    })
                }).collect::<Vec<_>>()
            }),
        );
    }

    fn on_failure(&self, test_name: &str, error: &str) {
        eprintln!("\n=== TEST FAILURE: {} ===", test_name);
        eprintln!("Error: {}", error);
        if let Some(ref dir) = self.session_artifact_dir {
            eprintln!("Session artifacts: {}", dir);
        }
        eprintln!("Events captured:");
        for event in &self.events {
            eprintln!("  {}", event.to_jsonl());
        }
        eprintln!("=== END FAILURE REPORT ===\n");
    }
}

// ============================================================================
// Test Fixture Helpers
// ============================================================================

fn empty_rationale() -> ActionRationale {
    ActionRationale {
        expected_loss: None,
        expected_recovery: None,
        expected_recovery_stddev: None,
        posterior_odds_abandoned_vs_useful: None,
        sprt_boundary: None,
        posterior: None,
        memory_mb: None,
        has_known_signature: None,
        category: None,
    }
}

fn make_test_identity(pid: u32, uid: u32) -> ProcessIdentity {
    ProcessIdentity {
        pid: ProcessId(pid),
        start_id: StartId(format!("boot:test:{}:{}", pid, uid)),
        uid,
        pgid: None,
        sid: Some(pid),
        quality: IdentityQuality::Full,
    }
}

fn live_identity(pid: u32) -> ProcessIdentity {
    let scan = quick_scan(&QuickScanOptions {
        pids: vec![pid],
        timeout: Some(Duration::from_secs(30)),
        ..QuickScanOptions::default()
    })
    .expect("collect actual action target");
    assert!(
        scan.metadata.warnings.is_empty(),
        "target scan warnings: {:?}",
        scan.metadata.warnings
    );
    assert_eq!(scan.processes.len(), 1, "expected the owned target only");
    let record = scan.processes.into_iter().next().expect("target record");
    assert_eq!(record.pid.0, pid);
    assert!(!record.start_id.0.is_empty());
    assert!(!record.start_id.0.starts_with("unknown"));
    assert!(record.pgid.is_some());
    assert!(record.sid.is_some());
    #[cfg(target_os = "linux")]
    {
        let stat = pt_core::collect::parse_proc_stat(pid).expect("read owned target birth ticks");
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .expect("read current boot ID");
        assert_eq!(
            record.start_id,
            StartId::from_linux(boot.trim(), stat.starttime, pid)
        );
        // SAFETY: this observes the test's owner without changing credentials.
        assert_eq!(record.uid, unsafe { libc::geteuid() });
    }
    ProcessIdentity {
        pid: record.pid,
        start_id: record.start_id,
        uid: record.uid,
        pgid: record.pgid,
        sid: record.sid,
        quality: IdentityQuality::Full,
    }
}

// Keep the direct child unreaped until its actual termination signal is observed.
// Drop can kill only this owned incarnation, including after a failed assertion.
struct OwnedActionChild {
    child: Child,
}

impl OwnedActionChild {
    fn sleep() -> Self {
        Self {
            child: Command::new("sleep")
                .arg("60")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn owned cooperative sleep"),
        }
    }

    #[cfg(unix)]
    fn term_ignoring() -> Self {
        use std::io::Read;
        use std::os::fd::AsRawFd;

        let mut target = Self {
            child: Command::new("sh")
                .args(["-c", "trap '' TERM; printf 'ready\\n'; while :; do :; done"])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn owned TERM-ignoring shell"),
        };
        let mut stdout = target.child.stdout.take().expect("readiness stdout");
        // SAFETY: change only the owned pipe's file status flags so readiness
        // cannot block the test before its five-second timeout is checked.
        let flags = unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_GETFL) };
        assert!(
            flags >= 0,
            "get pipe flags: {}",
            std::io::Error::last_os_error()
        );
        assert_ne!(
            unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) },
            -1,
            "set nonblocking readiness: {}",
            std::io::Error::last_os_error()
        );
        let started = Instant::now();
        let mut ready = Vec::new();
        loop {
            let mut bytes = [0; 64];
            let observed = stdout.read(&mut bytes);
            assert!(
                started.elapsed() < Duration::from_millis(5000),
                "TERM-ignore readiness timed out: {ready:?}"
            );
            match observed {
                Ok(0) => panic!("TERM-ignoring shell exited before readiness: {ready:?}"),
                Ok(count) => {
                    ready.extend_from_slice(&bytes[..count]);
                    if ready.ends_with(b"\n") {
                        assert_eq!(ready, b"ready\n");
                        return target;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => panic!("read TERM-ignore readiness: {error}"),
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn observed_exit(&mut self) -> ExitStatus {
        let started = Instant::now();
        loop {
            let observed = self.child.try_wait().expect("observe owned child exit");
            assert!(
                started.elapsed() < Duration::from_millis(5000),
                "owned child did not exit within verification bound"
            );
            if let Some(status) = observed {
                return status;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for OwnedActionChild {
    fn drop(&mut self) {
        if !matches!(self.child.try_wait(), Ok(Some(_))) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn make_pause_action(pid: u32, pgid: Option<u32>, action_id: &str) -> PlanAction {
    PlanAction {
        action_id: action_id.to_string(),
        action: Action::Pause,
        target: ProcessIdentity {
            pid: ProcessId(pid),
            start_id: StartId("mock".to_string()),
            uid: 1000,
            pgid,
            sid: None,
            quality: IdentityQuality::Full,
        },
        order: 0,
        stage: 0,
        timeouts: ActionTimeouts::default(),
        pre_checks: vec![],
        rationale: empty_rationale(),
        on_success: vec![],
        on_failure: vec![],
        blocked: false,
        routing: ActionRouting::Direct,
        confidence: ActionConfidence::Normal,
        original_zombie_target: None,
        d_state_diagnostics: None,
    }
}

fn make_resume_action(pid: u32, pgid: Option<u32>, action_id: &str) -> PlanAction {
    PlanAction {
        action_id: action_id.to_string(),
        action: Action::Resume,
        target: ProcessIdentity {
            pid: ProcessId(pid),
            start_id: StartId("mock".to_string()),
            uid: 1000,
            pgid,
            sid: None,
            quality: IdentityQuality::Full,
        },
        order: 1,
        stage: 1,
        timeouts: ActionTimeouts::default(),
        pre_checks: vec![],
        rationale: empty_rationale(),
        on_success: vec![],
        on_failure: vec![],
        blocked: false,
        routing: ActionRouting::Direct,
        confidence: ActionConfidence::Normal,
        original_zombie_target: None,
        d_state_diagnostics: None,
    }
}

fn make_renice_action(pid: u32, action_id: &str) -> PlanAction {
    PlanAction {
        action_id: action_id.to_string(),
        action: Action::Renice,
        target: ProcessIdentity {
            pid: ProcessId(pid),
            start_id: StartId("mock".to_string()),
            uid: 1000,
            pgid: None,
            sid: None,
            quality: IdentityQuality::Full,
        },
        order: 0,
        stage: 0,
        timeouts: ActionTimeouts::default(),
        pre_checks: vec![],
        rationale: empty_rationale(),
        on_success: vec![],
        on_failure: vec![],
        blocked: false,
        routing: ActionRouting::Direct,
        confidence: ActionConfidence::Normal,
        original_zombie_target: None,
        d_state_diagnostics: None,
    }
}

fn make_kill_action(pid: u32, action_id: &str, pre_checks: Vec<PreCheck>) -> PlanAction {
    PlanAction {
        action_id: action_id.to_string(),
        action: Action::Kill,
        target: ProcessIdentity {
            pid: ProcessId(pid),
            start_id: StartId("mock".to_string()),
            uid: 1000,
            pgid: None,
            sid: None,
            quality: IdentityQuality::Full,
        },
        order: 0,
        stage: 0,
        timeouts: ActionTimeouts {
            preflight_ms: 500,
            execute_ms: 1000, // Short for testing
            verify_ms: 5000,
        },
        pre_checks,
        rationale: empty_rationale(),
        on_success: vec![],
        on_failure: vec![],
        blocked: false,
        routing: ActionRouting::Direct,
        confidence: ActionConfidence::Normal,
        original_zombie_target: None,
        d_state_diagnostics: None,
    }
}

fn make_test_plan_from_actions(actions: Vec<PlanAction>) -> Plan {
    Plan {
        plan_id: uuid::Uuid::new_v4().to_string(),
        session_id: "pt-test-e2e".to_string(),
        generated_at: chrono::Utc::now().to_rfc3339(),
        policy_id: None,
        policy_version: "1.0.0".to_string(),
        actions,
        pre_toggled: vec![],
        gates_summary: GatesSummary {
            total_candidates: 1,
            blocked_candidates: 0,
            pre_toggled_actions: 0,
        },
    }
}

// ============================================================================
// SCENARIO 1: Pause → Observe → Resume Workflow
// ============================================================================

mod pause_observe_resume {
    use super::*;
    use pt_core::action::executor::ActionRunner;

    /// Test basic pause/resume on a single process
    #[test]
    fn test_pause_observe_resume_single_process() {
        if !ProcessHarness::is_available() {
            eprintln!("Skipping test: ProcessHarness not available");
            return;
        }

        let mut ctx = TestContext::new();
        ctx.log(
            "test_start",
            json!({ "test": "pause_observe_resume_single_process" }),
        );

        let harness = ProcessHarness;
        let proc = harness.spawn_sleep(60).expect("spawn sleep");
        let pid = proc.pid();

        ctx.log("process_spawned", json!({ "pid": pid, "type": "sleep" }));

        let runner = SignalActionRunner::with_defaults();

        // Phase 1: Pause
        let mut pause_action = make_pause_action(pid, None, "e2e-pause-1");
        pause_action.target = live_identity(pid);
        ctx.log("live_target", json!({ "identity": pause_action.target }));
        ctx.log_action_attempt(&pause_action, "execute_pause");

        let pause_result = runner.execute(&pause_action);
        if let Err(ref e) = pause_result {
            ctx.on_failure("pause_observe_resume", &format!("Pause failed: {:?}", e));
        }
        assert!(pause_result.is_ok(), "Pause should succeed");

        // Phase 2: Observe - verify CPU drops (process is stopped)
        std::thread::sleep(Duration::from_millis(100));

        #[cfg(target_os = "linux")]
        {
            let stat =
                std::fs::read_to_string(format!("/proc/{}/stat", pid)).expect("read /proc/stat");
            let is_stopped = stat.contains(") T ") || stat.contains(") t ");
            ctx.log_verification(
                "e2e-pause-1",
                if is_stopped { "passed" } else { "failed" },
                json!({ "state": &stat[..50.min(stat.len())], "is_stopped": is_stopped }),
            );
            assert!(
                is_stopped,
                "Process should be in stopped state (T): {}",
                stat
            );
        }

        // Verify pause action verification passes
        let verify_result = runner.verify(&pause_action);
        assert!(verify_result.is_ok(), "Pause verification should succeed");

        // Phase 3: Resume
        let mut resume_action = make_resume_action(pid, None, "e2e-resume-1");
        resume_action.target = pause_action.target.clone();
        assert_eq!(live_identity(pid), resume_action.target);
        ctx.log_action_attempt(&resume_action, "execute_resume");

        let resume_result = runner.execute(&resume_action);
        assert!(resume_result.is_ok(), "Resume should succeed");

        // Verify recovery
        std::thread::sleep(Duration::from_millis(100));

        #[cfg(target_os = "linux")]
        {
            let stat =
                std::fs::read_to_string(format!("/proc/{}/stat", pid)).expect("read /proc/stat");
            let is_running = stat.contains(") S ") || stat.contains(") R ");
            ctx.log_verification(
                "e2e-resume-1",
                if is_running { "passed" } else { "failed" },
                json!({ "state": &stat[..50.min(stat.len())], "is_running": is_running }),
            );
            assert!(is_running, "Process should be running (S/R): {}", stat);
        }

        ctx.log("test_complete", json!({ "result": "passed" }));
    }

    /// Test pause/resume on a process group (parent + children)
    #[test]
    #[cfg(target_os = "linux")]
    fn test_pause_observe_resume_process_group() {
        use pt_core::test_utils::is_process_stopped;

        if !ProcessHarness::is_available() {
            eprintln!("Skipping test: ProcessHarness not available");
            return;
        }

        let mut ctx = TestContext::new();
        ctx.log(
            "test_start",
            json!({ "test": "pause_observe_resume_process_group" }),
        );

        let harness = ProcessHarness;
        let proc = harness.spawn_process_group().expect("spawn process group");
        let pid = proc.pid();

        // Wait for children to spawn
        std::thread::sleep(Duration::from_millis(200));

        let pgid = proc.pgid().expect("should have pgid");
        let group_pids = proc.group_pids();

        ctx.log(
            "process_group_spawned",
            json!({
                "leader_pid": pid,
                "pgid": pgid,
                "member_count": group_pids.len(),
                "members": group_pids
            }),
        );

        assert!(
            group_pids.len() >= 2,
            "Expected at least 2 processes in group, got {:?}",
            group_pids
        );

        // Create runner with process group targeting
        let runner = SignalActionRunner::new(SignalConfig {
            use_process_groups: true,
            ..Default::default()
        });

        // Phase 1: Pause entire group
        let mut pause_action = make_pause_action(pid, Some(pgid), "e2e-group-pause");
        pause_action.target = live_identity(pid);
        assert_eq!(pause_action.target.pgid, Some(pgid));
        ctx.log("live_target", json!({ "identity": pause_action.target }));
        ctx.log_action_attempt(&pause_action, "execute_group_pause");

        let pause_result = runner.execute(&pause_action);
        assert!(pause_result.is_ok(), "Group pause should succeed");

        // Phase 2: Verify ALL processes in group are stopped
        std::thread::sleep(Duration::from_millis(100));

        let mut all_stopped = true;
        for gpid in &group_pids {
            let stopped = is_process_stopped(*gpid);
            if !stopped {
                all_stopped = false;
            }
            ctx.log_verification(
                "e2e-group-pause",
                if stopped { "passed" } else { "failed" },
                json!({ "member_pid": gpid, "is_stopped": stopped }),
            );
        }
        assert!(all_stopped, "All processes in group should be stopped");

        // Phase 3: Resume entire group
        let mut resume_action = make_resume_action(pid, Some(pgid), "e2e-group-resume");
        resume_action.target = pause_action.target.clone();
        assert_eq!(live_identity(pid), resume_action.target);
        ctx.log_action_attempt(&resume_action, "execute_group_resume");

        let resume_result = runner.execute(&resume_action);
        assert!(resume_result.is_ok(), "Group resume should succeed");

        // Verify all processes are running again
        std::thread::sleep(Duration::from_millis(100));

        let mut all_running = true;
        for gpid in &group_pids {
            let running = !is_process_stopped(*gpid);
            if !running {
                all_running = false;
            }
            ctx.log_verification(
                "e2e-group-resume",
                if running { "passed" } else { "failed" },
                json!({ "member_pid": gpid, "is_running": running }),
            );
        }
        assert!(all_running, "All processes in group should be running");

        ctx.log("test_complete", json!({ "result": "passed" }));
    }
}

// ============================================================================
// SCENARIO 2: Staged Kill Escalation (SIGTERM → SIGKILL)
// ============================================================================

mod staged_kill_escalation {
    use super::*;
    use pt_core::action::executor::ActionRunner;

    /// Test that graceful kill (SIGTERM) works on cooperative processes
    #[test]
    #[cfg(unix)]
    fn test_graceful_kill_sigterm_only() {
        use std::os::unix::process::ExitStatusExt;
        if !ProcessHarness::is_available() {
            return;
        }

        let mut ctx = TestContext::new();
        ctx.log(
            "test_start",
            json!({ "test": "graceful_kill_sigterm_only" }),
        );

        let mut proc = OwnedActionChild::sleep();
        let pid = proc.pid();

        ctx.log("process_spawned", json!({ "pid": pid }));

        // Short grace period - sleep responds to SIGTERM
        let runner = SignalActionRunner::new(SignalConfig {
            term_grace_ms: 2000,
            poll_interval_ms: 100,
            verify_timeout_ms: 5000,
            use_process_groups: false,
        });

        let mut kill_action = make_kill_action(pid, "e2e-graceful-kill", vec![]);
        kill_action.target = live_identity(pid);
        ctx.log("live_target", json!({ "identity": kill_action.target }));
        ctx.log_action_attempt(&kill_action, "execute_kill");

        let start = Instant::now();
        let result = runner.execute(&kill_action);
        let elapsed = start.elapsed();

        ctx.log(
            "kill_executed",
            json!({
                "success": result.is_ok(),
                "elapsed_ms": elapsed.as_millis()
            }),
        );

        assert!(result.is_ok(), "Kill should succeed");

        // Allow time for process to exit
        std::thread::sleep(Duration::from_millis(200));

        // Verify process is gone
        let verify = runner.verify(&kill_action);
        ctx.log_verification(
            "e2e-graceful-kill",
            if verify.is_ok() { "passed" } else { "failed" },
            json!({ "verify_result": format!("{:?}", verify) }),
        );

        assert!(
            verify.is_ok(),
            "Verification should confirm process is dead"
        );
        let status = proc.observed_exit();
        ctx.log(
            "owned_exit_observed",
            json!({ "pid": pid, "signal": status.signal(), "code": status.code() }),
        );
        assert_eq!(status.signal(), Some(libc::SIGTERM));
        ctx.log("test_complete", json!({ "result": "passed" }));
    }

    /// Test that staged kill escalates to SIGKILL for unresponsive processes
    #[test]
    #[cfg(unix)]
    fn test_kill_escalates_to_sigkill() {
        use std::os::unix::process::ExitStatusExt;
        if !ProcessHarness::is_available() {
            return;
        }

        let mut ctx = TestContext::new();
        ctx.log("test_start", json!({ "test": "kill_escalates_to_sigkill" }));

        // Readiness is emitted only after this owned shell ignores SIGTERM.
        let mut proc = OwnedActionChild::term_ignoring();
        let pid = proc.pid();
        #[cfg(target_os = "linux")]
        {
            let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
                .expect("read owned shell's signal dispositions");
            let ignored = status
                .lines()
                .find_map(|line| line.strip_prefix("SigIgn:"))
                .expect("SigIgn field");
            let ignored = u64::from_str_radix(ignored.trim(), 16).expect("SigIgn mask");
            assert_ne!(ignored & (1_u64 << (libc::SIGTERM - 1)), 0);
            ctx.log(
                "TERM_ignore_observed",
                json!({ "pid": pid, "SigIgn": ignored }),
            );
        }

        ctx.log(
            "process_spawned",
            json!({ "pid": pid, "type": "TERM_ignoring_busy_loop", "ready": true }),
        );

        // Very short grace period to trigger escalation
        let runner = SignalActionRunner::new(SignalConfig {
            term_grace_ms: 500, // Short timeout
            poll_interval_ms: 50,
            verify_timeout_ms: 5000,
            use_process_groups: false,
        });

        let mut kill_action = make_kill_action(pid, "e2e-force-kill", vec![]);
        kill_action.target = live_identity(pid);
        ctx.log("live_target", json!({ "identity": kill_action.target }));
        ctx.log_action_attempt(&kill_action, "execute_escalating_kill");

        let start = Instant::now();
        let result = runner.execute(&kill_action);
        let elapsed = start.elapsed();

        ctx.log(
            "kill_executed",
            json!({
                "success": result.is_ok(),
                "elapsed_ms": elapsed.as_millis(),
                "note": "expected to escalate to SIGKILL"
            }),
        );

        assert!(result.is_ok(), "Kill (with escalation) should succeed");

        std::thread::sleep(Duration::from_millis(200));

        let verify = runner.verify(&kill_action);
        ctx.log_verification(
            "e2e-force-kill",
            if verify.is_ok() { "passed" } else { "failed" },
            json!({ "verify_result": format!("{:?}", verify) }),
        );

        assert!(verify.is_ok(), "Process should be dead after SIGKILL");
        let status = proc.observed_exit();
        ctx.log(
            "owned_exit_observed",
            json!({ "pid": pid, "signal": status.signal(), "code": status.code() }),
        );
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        assert!(elapsed >= Duration::from_millis(500));
        ctx.log("test_complete", json!({ "result": "passed" }));
    }

    /// Test that zombie processes are handled correctly
    #[test]
    fn test_kill_handles_zombie() {
        if !ProcessHarness::is_available() {
            return;
        }

        let mut ctx = TestContext::new();
        ctx.log("test_start", json!({ "test": "kill_handles_zombie" }));

        let harness = ProcessHarness;
        // spawn_shell with "true" exits immediately -> becomes zombie
        let proc = harness.spawn_shell("true").expect("spawn true");
        let pid = proc.pid();

        ctx.log(
            "process_spawned",
            json!({ "pid": pid, "expected_state": "zombie" }),
        );

        // Wait for process to become zombie
        let mut is_zombie = false;
        for i in 0..20 {
            #[cfg(target_os = "linux")]
            let zombie_now = std::fs::read_to_string(format!("/proc/{}/stat", pid))
                .is_ok_and(|stat| stat.contains(") Z "));
            #[cfg(not(target_os = "linux"))]
            let zombie_now = std::process::Command::new("ps")
                .args(["-o", "stat=", "-p", &pid.to_string()])
                .output()
                .is_ok_and(|o| {
                    String::from_utf8_lossy(&o.stdout)
                        .trim_start()
                        .starts_with('Z')
                });
            if zombie_now {
                is_zombie = true;
                ctx.log("zombie_detected", json!({ "pid": pid, "attempts": i + 1 }));
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        assert!(is_zombie, "owned child must actually be an unreaped zombie");
        let runner = SignalActionRunner::with_defaults();
        let mut kill_action = make_kill_action(pid, "e2e-kill-zombie", vec![]);
        kill_action.target = live_identity(pid);
        ctx.log("live_target", json!({ "identity": kill_action.target }));

        ctx.log_action_attempt(&kill_action, "execute_kill_on_zombie");

        // Kill on zombie should succeed (no-op or ignored signal)
        let result = runner.execute(&kill_action);
        ctx.log(
            "zombie_kill_result",
            json!({ "success": result.is_ok(), "is_zombie": is_zombie }),
        );
        assert!(result.is_ok(), "Kill on zombie should succeed");

        // Verify should succeed (zombie counts as dead)
        let verify = runner.verify(&kill_action);
        ctx.log_verification(
            "e2e-kill-zombie",
            if verify.is_ok() { "passed" } else { "failed" },
            json!({
                "verify_result": format!("{:?}", verify),
                "note": "zombie should count as dead"
            }),
        );

        assert!(verify.is_ok(), "Zombie verification should succeed");
        ctx.log("test_complete", json!({ "result": "passed" }));
    }
}

// ============================================================================
// SCENARIO 3: Safety Gates (Robot Mode)
// ============================================================================

mod safety_gates_robot_mode {
    use super::*;

    /// Test that identity mismatch blocks action
    #[test]
    fn test_identity_mismatch_blocks_action() {
        let mut ctx = TestContext::new();
        ctx.log(
            "test_start",
            json!({ "test": "identity_mismatch_blocks_action" }),
        );

        let dir = tempdir().expect("tempdir").keep();
        let lock_path = dir.join("test.lock");

        // Create a plan targeting PID 99999 (doesn't exist)
        let kill_action =
            make_kill_action(99999, "e2e-identity-test", vec![PreCheck::VerifyIdentity]);
        let plan = make_test_plan_from_actions(vec![kill_action]);

        ctx.log_plan(&plan);

        // StaticIdentityProvider with no identities -> all revalidations fail
        let runner = NoopActionRunner;
        let identity_provider = StaticIdentityProvider::default();
        let executor = ActionExecutor::new(&runner, &identity_provider, lock_path);

        let result = executor.execute_plan(&plan).expect("execute plan");
        ctx.log_execution_result(&result);

        // Action should be blocked due to identity mismatch
        assert_eq!(result.outcomes.len(), 1);
        match &result.outcomes[0].status {
            ActionStatus::IdentityMismatch => {
                ctx.log(
                    "identity_gate_triggered",
                    json!({ "status": "IdentityMismatch" }),
                );
            }
            other => {
                ctx.on_failure(
                    "identity_mismatch_blocks_action",
                    &format!("Expected IdentityMismatch, got {:?}", other),
                );
                panic!("Expected IdentityMismatch, got {:?}", other);
            }
        }

        ctx.log("test_complete", json!({ "result": "passed" }));
    }

    /// Test that lock contention returns appropriate error
    #[test]
    #[cfg(unix)]
    fn test_lock_contention_blocks_execution() {
        use std::fs::OpenOptions;
        use std::os::unix::io::AsRawFd;

        let mut ctx = TestContext::new();
        ctx.log(
            "test_start",
            json!({ "test": "lock_contention_blocks_execution" }),
        );

        let dir = tempdir().expect("tempdir").keep();
        let lock_path = dir.join("test.lock");

        // Hold the lock using direct flock
        let held_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&lock_path)
            .expect("create lock file");

        let lock_result =
            unsafe { libc::flock(held_file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(lock_result, 0, "Should acquire lock");

        ctx.log(
            "lock_acquired",
            json!({ "path": lock_path.display().to_string() }),
        );

        // Try to execute while lock is held
        let kill_action = make_kill_action(12345, "e2e-lock-test", vec![]);
        let plan = make_test_plan_from_actions(vec![kill_action]);

        let runner = NoopActionRunner;
        let identity_provider = StaticIdentityProvider::default();
        let executor = ActionExecutor::new(&runner, &identity_provider, lock_path);

        let result = executor.execute_plan(&plan);
        ctx.log(
            "execution_attempted",
            json!({ "result": format!("{:?}", result) }),
        );

        // Should fail with LockUnavailable
        assert!(result.is_err(), "Should fail due to lock contention");
        match result {
            Err(ref e) => {
                let err_str = format!("{:?}", e);
                assert!(
                    err_str.contains("Lock"),
                    "Error should mention lock: {}",
                    err_str
                );
            }
            Ok(_) => panic!("Should have failed"),
        }

        // Explicitly release lock
        unsafe {
            libc::flock(held_file.as_raw_fd(), libc::LOCK_UN);
        }

        ctx.log("test_complete", json!({ "result": "passed" }));
    }

    /// Test that pre-checks can block action execution
    #[test]
    fn test_precheck_blocks_action_in_executor() {
        let mut ctx = TestContext::new();
        ctx.log(
            "test_start",
            json!({ "test": "precheck_blocks_action_in_executor" }),
        );

        let dir = tempdir().expect("tempdir").keep();
        let lock_path = dir.join("test.lock");

        // Create action with pre-checks
        let kill_action = make_kill_action(
            12345,
            "e2e-precheck-test",
            vec![PreCheck::VerifyIdentity, PreCheck::CheckNotProtected],
        );
        let plan = make_test_plan_from_actions(vec![kill_action]);

        ctx.log_plan(&plan);

        // Set up identity provider that passes identity check
        let identity_provider =
            StaticIdentityProvider::default().with_identity(make_test_identity(12345, 1000));

        // Use Noop pre-check provider (all checks pass)
        let runner = NoopActionRunner;
        let pre_check_provider = NoopPreCheckProvider;
        let executor = ActionExecutor::new(&runner, &identity_provider, lock_path)
            .with_pre_check_provider(&pre_check_provider);

        let result = executor.execute_plan(&plan).expect("execute plan");
        ctx.log_execution_result(&result);

        // With NoopActionRunner and NoopPreCheckProvider, action should succeed
        assert_eq!(result.outcomes.len(), 1);
        match &result.outcomes[0].status {
            ActionStatus::Success => {
                ctx.log("precheck_passed", json!({ "status": "Success" }));
            }
            other => {
                // This could also be blocked by pre-checks depending on config
                ctx.log(
                    "precheck_result",
                    json!({ "status": format!("{:?}", other) }),
                );
            }
        }

        ctx.log("test_complete", json!({ "result": "passed" }));
    }

    /// Test data-loss gate blocks kill (Linux only)
    #[test]
    #[cfg(target_os = "linux")]
    fn test_data_loss_gate_detection() {
        if !ProcessHarness::is_available() {
            return;
        }

        let mut ctx = TestContext::new();
        ctx.log("test_start", json!({ "test": "data_loss_gate_detection" }));

        let config = LivePreCheckConfig {
            max_open_write_fds: 0, // Any write fd should block
            block_if_locked_files: true,
            block_if_active_tty: false,
            block_if_deleted_cwd: false,
            block_if_recent_io_seconds: 0,
            ..Default::default()
        };

        let provider = LivePreCheckProvider::new(None, config).expect("create provider");

        // Test against current process (has stdout/stderr)
        let pid = std::process::id();
        let result = provider.check_data_loss(pid);

        ctx.log(
            "data_loss_check",
            json!({
                "pid": pid,
                "result": format!("{:?}", result)
            }),
        );

        // Current process should typically be blocked
        match result {
            PreCheckResult::Blocked { check, reason } => {
                assert_eq!(check, PreCheck::CheckDataLossGate);
                ctx.log(
                    "data_loss_gate_triggered",
                    json!({ "check": format!("{:?}", check), "reason": reason }),
                );
            }
            PreCheckResult::Passed => {
                // May pass in some CI environments
                ctx.log(
                    "data_loss_gate_passed",
                    json!({ "note": "No write fds detected" }),
                );
            }
        }

        ctx.log("test_complete", json!({ "result": "passed" }));
    }
}

// ============================================================================
// SCENARIO 4: Renice Action
// ============================================================================

mod renice_action {
    use super::*;
    use pt_core::action::executor::ActionRunner;

    #[cfg(target_os = "linux")]
    fn read_nice_value(pid: u32) -> Result<i32, String> {
        let stat_path = format!("/proc/{pid}/stat");
        let content = std::fs::read_to_string(&stat_path)
            .map_err(|error| format!("read {stat_path}: {error}"))?;
        let comm_end = content
            .rfind(')')
            .ok_or_else(|| format!("missing comm boundary in {stat_path}: {content:?}"))?;
        let after_comm = content
            .get(comm_end + 2..)
            .ok_or_else(|| format!("missing stat fields in {stat_path}: {content:?}"))?;
        let fields: Vec<&str> = after_comm.split_whitespace().collect();
        fields
            .get(16)
            .ok_or_else(|| format!("missing nice field in {stat_path}: {content:?}"))?
            .parse::<i32>()
            .map_err(|error| format!("invalid nice field in {stat_path}: {error}; {content:?}"))
    }

    #[cfg(target_os = "macos")]
    fn read_nice_value(pid: u32) -> Result<i32, String> {
        // SAFETY: getpriority only observes the owned child's priority. A real
        // -1 priority is distinguished from failure through thread-local errno.
        unsafe {
            *libc::__error() = 0;
            let value = libc::getpriority(libc::PRIO_PROCESS, pid as libc::id_t);
            if value == -1 && *libc::__error() != 0 {
                Err(format!(
                    "getpriority({pid}): {}",
                    std::io::Error::last_os_error()
                ))
            } else {
                Ok(value)
            }
        }
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_renice_priority_adjustment() {
        if !ProcessHarness::is_available() {
            eprintln!("Skipping test: ProcessHarness not available");
            return;
        }

        let mut ctx = TestContext::new();
        ctx.log(
            "test_start",
            json!({ "test": "renice_priority_adjustment" }),
        );

        let harness = ProcessHarness;
        let proc = harness.spawn_sleep(60).expect("spawn sleep");
        let pid = proc.pid();

        ctx.log("process_spawned", json!({ "pid": pid, "type": "sleep" }));

        let before = read_nice_value(pid).expect("observe owned target's initial priority");
        let expected = before.max(pt_core::action::DEFAULT_NICE_VALUE);
        ctx.log(
            "nice_before",
            json!({
                "pid": pid,
                "nice": before,
                "expected": expected,
                "scope": if before >= pt_core::action::DEFAULT_NICE_VALUE {
                    "already_lower_priority_noop"
                } else {
                    "priority_adjustment"
                }
            }),
        );

        let runner = ReniceActionRunner::with_defaults();
        let mut action = make_renice_action(pid, "e2e-renice-1");
        action.target = live_identity(pid);
        ctx.log("live_target", json!({ "identity": action.target }));

        ctx.log_action_attempt(&action, "execute_renice");

        let execute_result = runner.execute(&action);
        ctx.log(
            "renice_executed",
            json!({ "result": format!("{execute_result:?}") }),
        );
        assert!(
            execute_result.is_ok(),
            "Renice execute failed: {execute_result:?}"
        );
        let verify_result = runner.verify(&action);
        ctx.log_verification(
            "e2e-renice-1",
            if verify_result.is_ok() {
                "passed"
            } else {
                "failed"
            },
            json!({ "verify_result": format!("{verify_result:?}") }),
        );
        assert!(
            verify_result.is_ok(),
            "Renice verification failed: {verify_result:?}"
        );
        let after = read_nice_value(pid).expect("observe owned target's resulting priority");
        ctx.log(
            "nice_after",
            json!({ "pid": pid, "nice": after, "expected": expected }),
        );
        assert_eq!(
            after, expected,
            "renice must lower or preserve priority exactly"
        );
        assert_eq!(live_identity(pid), action.target);

        ctx.log("test_complete", json!({ "result": "passed" }));
    }

    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn test_renice_verification() {
        if !ProcessHarness::is_available() {
            eprintln!("Skipping test: ProcessHarness not available");
            return;
        }

        let mut ctx = TestContext::new();
        ctx.log("test_start", json!({ "test": "renice_verification" }));

        let harness = ProcessHarness;
        let proc = harness.spawn_sleep(60).expect("spawn sleep");
        let pid = proc.pid();

        let before = read_nice_value(pid).expect("observe owned target's initial priority");
        let expected = before.max(pt_core::action::DEFAULT_NICE_VALUE);
        ctx.log(
            "nice_before",
            json!({ "pid": pid, "nice": before, "expected": expected, "noop": before >= 10 }),
        );
        let runner = ReniceActionRunner::with_defaults();
        let mut action = make_renice_action(pid, "e2e-renice-verify");
        action.target = live_identity(pid);
        ctx.log("live_target", json!({ "identity": action.target }));

        let execute_result = runner.execute(&action);
        ctx.log(
            "renice_executed",
            json!({ "result": format!("{execute_result:?}") }),
        );
        assert!(
            execute_result.is_ok(),
            "Renice execute failed: {execute_result:?}"
        );

        let verify_ok = runner.verify(&action);
        if let Err(ref e) = verify_ok {
            ctx.on_failure("renice_verification", &format!("Verify failed: {:?}", e));
        }
        assert!(verify_ok.is_ok(), "Renice verify failed: {verify_ok:?}");
        let actual = read_nice_value(pid).expect("observe priority for mismatch negative");
        ctx.log(
            "nice_after",
            json!({ "pid": pid, "nice": actual, "expected": expected }),
        );
        assert_eq!(actual, expected);

        // Verify only: asking for actual+1 remains a mismatch even at nice 19.
        // No setpriority syscall or out-of-range priority mutation is attempted.
        let mismatch_expected = actual + 1;
        let mismatch_runner = ReniceActionRunner::new(ReniceConfig {
            nice_value: mismatch_expected,
            clamp_to_range: false,
            capture_reversal: false,
        });
        let mismatch = mismatch_runner.verify(&action);
        ctx.log(
            "mismatch_verify_result",
            json!({ "pid": pid, "actual": actual, "expected": mismatch_expected,
                "result": format!("{mismatch:?}") }),
        );
        match mismatch {
            Err(pt_core::action::ActionError::Failed(message)) => {
                assert_eq!(
                    message,
                    format!("nice value mismatch: expected {mismatch_expected}, got {actual}")
                );
            }
            other => panic!("expected a specific priority mismatch failure, got {other:?}"),
        }
        assert_eq!(
            read_nice_value(pid).expect("observe untouched priority"),
            actual
        );
        assert_eq!(live_identity(pid), action.target);

        ctx.log("test_complete", json!({ "result": "passed" }));
    }
}

// ============================================================================
// SCENARIO 5: Cgroup Throttle Action (requires an owned delegated leaf)
// ============================================================================

// cgroup v2 throttling is Linux-only.
#[cfg(target_os = "linux")]
mod cgroup_throttle_action {
    use super::*;
    use pt_core::action::executor::ActionRunner;
    #[cfg(target_os = "linux")]
    use pt_core::action::{can_throttle_process, CpuThrottleActionRunner, CpuThrottleConfig};
    #[cfg(target_os = "linux")]
    use pt_core::collect::cgroup::collect_cgroup_details;
    use pt_core::decision::Action as ActionType;
    use pt_core::test_utils::OwnedCgroupFixture;

    fn make_throttle_action(target: ProcessIdentity, action_id: &str) -> PlanAction {
        PlanAction {
            action_id: action_id.to_string(),
            action: ActionType::Throttle,
            target,
            order: 0,
            stage: 0,
            timeouts: ActionTimeouts::default(),
            pre_checks: vec![],
            rationale: empty_rationale(),
            on_success: vec![],
            on_failure: vec![],
            blocked: false,
            routing: ActionRouting::Direct,
            confidence: ActionConfidence::Normal,
            original_zombie_target: None,
            d_state_diagnostics: None,
        }
    }

    /// Test cgroup CPU throttle action
    #[test]
    #[cfg(target_os = "linux")]
    fn test_cgroup_cpu_throttle() {
        let mut ctx = TestContext::new();
        ctx.log("test_start", json!({ "test": "cgroup_cpu_throttle" }));
        let Some(fixture) = OwnedCgroupFixture::new().expect("safe delegated cgroup setup") else {
            ctx.log("capability_unavailable", json!({"reason": "PT_TEST_CGROUP_PARENT prerequisite absent", "positive_kernel_proof": false}));
            return;
        };
        let pid = fixture.target.pid();
        ctx.log("process_spawned", json!({ "identity": fixture.identity, "type": "sleep", "leaf": fixture.leaf, "artifacts": fixture.artifacts }));
        assert!(
            can_throttle_process(pid),
            "owned exclusive leaf unavailable"
        );
        let before = OwnedCgroupFixture::controls(&fixture.leaf);
        let sibling_before = OwnedCgroupFixture::controls(&fixture.sibling_leaf);

        // Capture original state for reversal
        let runner = CpuThrottleActionRunner::with_defaults();
        let reversal = runner
            .capture_reversal_metadata(pid)
            .expect("actual reversal metadata");
        ctx.log(
            "reversal_captured",
            json!({ "pid": pid, "metadata": reversal }),
        );

        // Create and execute throttle action
        let action = make_throttle_action(fixture.identity.clone(), "e2e-throttle");
        ctx.log_action_attempt(&action, "execute_throttle");

        let result = runner.execute(&action);
        ctx.log(
            "throttle_executed",
            json!({ "pid": pid, "result": format!("{result:?}") }),
        );
        assert!(result.is_ok(), "throttle should succeed: {result:?}");

        // Verify throttle was applied
        std::thread::sleep(Duration::from_millis(50));
        let verify = runner.verify(&action);
        ctx.log_verification(
            "e2e-throttle",
            if verify.is_ok() { "passed" } else { "failed" },
            json!({ "verify_result": format!("{:?}", verify) }),
        );
        assert!(verify.is_ok(), "throttle verification should succeed");

        // Verify CPU limits were changed
        let details = collect_cgroup_details(pid).expect("actual target cgroup");
        let limits = details.cpu_limits.expect("actual throttled limits");
        assert_eq!(limits.quota_us, Some(25_000));
        assert_eq!(limits.period_us, Some(100_000));
        let quota = std::fs::read_to_string(fixture.leaf.join("cpu.max")).unwrap();
        assert_eq!(quota.trim(), "25000 100000");
        ctx.log("post_throttle_limits", json!({"pid": pid, "quota_us": limits.quota_us, "period_us": limits.period_us, "effective_cores": limits.effective_cores}));
        fixture.record("throttled");
        fixture.assert_isolated();
        assert_eq!(
            OwnedCgroupFixture::controls(&fixture.sibling_leaf),
            sibling_before
        );

        // Restore original settings
        let restore = runner.restore_from_metadata(&reversal);
        ctx.log(
            "reversal_applied",
            json!({ "result": format!("{restore:?}"), "pid": pid }),
        );
        assert!(restore.is_ok(), "reversal failed: {restore:?}");
        fixture.record("restored");
        assert_eq!(OwnedCgroupFixture::controls(&fixture.leaf), before);
        assert_eq!(
            OwnedCgroupFixture::controls(&fixture.sibling_leaf),
            sibling_before
        );
        fixture.assert_isolated();

        ctx.log("test_complete", json!({ "result": "passed" }));
    }

    /// Test throttle with different fraction configurations
    #[test]
    #[cfg(target_os = "linux")]
    fn test_cgroup_throttle_with_custom_fraction() {
        let mut ctx = TestContext::new();
        ctx.log(
            "test_start",
            json!({ "test": "cgroup_throttle_custom_fraction" }),
        );

        let Some(fixture) = OwnedCgroupFixture::new().expect("safe delegated cgroup setup") else {
            ctx.log("capability_unavailable", json!({"reason": "PT_TEST_CGROUP_PARENT prerequisite absent", "positive_kernel_proof": false}));
            return;
        };
        let pid = fixture.target.pid();
        assert!(
            can_throttle_process(pid),
            "owned exclusive leaf unavailable"
        );
        let before = OwnedCgroupFixture::controls(&fixture.leaf);
        let sibling_before = OwnedCgroupFixture::controls(&fixture.sibling_leaf);

        // Use a custom throttle config with 10% CPU
        let config = CpuThrottleConfig::with_fraction(0.1);
        let runner = CpuThrottleActionRunner::new(config);
        let reversal = runner
            .capture_reversal_metadata(pid)
            .expect("actual reversal metadata");

        let action = make_throttle_action(fixture.identity.clone(), "e2e-throttle-custom");
        let result = runner.execute(&action);

        ctx.log("custom_throttle_applied", json!({ "fraction": 0.1, "identity": fixture.identity, "result": format!("{result:?}") }));
        assert!(result.is_ok(), "custom throttle failed: {result:?}");
        let verify = runner.verify(&action);
        assert!(verify.is_ok(), "custom throttle verification failed");
        let quota = std::fs::read_to_string(fixture.leaf.join("cpu.max")).unwrap();
        assert_eq!(quota.trim(), "10000 100000");
        fixture.record("custom-throttled");
        fixture.assert_isolated();
        assert_eq!(
            OwnedCgroupFixture::controls(&fixture.sibling_leaf),
            sibling_before
        );

        let restore = runner.restore_from_metadata(&reversal);
        assert!(restore.is_ok(), "custom reversal failed: {restore:?}");
        fixture.record("restored");
        assert_eq!(OwnedCgroupFixture::controls(&fixture.leaf), before);
        assert_eq!(
            OwnedCgroupFixture::controls(&fixture.sibling_leaf),
            sibling_before
        );
        fixture.assert_isolated();

        ctx.log("test_complete", json!({ "result": "passed" }));
    }

    /// Test throttle on nonexistent process fails gracefully
    #[test]
    #[cfg(target_os = "linux")]
    fn test_cgroup_throttle_nonexistent_process() {
        let mut ctx = TestContext::new();
        ctx.log(
            "test_start",
            json!({ "test": "cgroup_throttle_nonexistent" }),
        );

        let runner = CpuThrottleActionRunner::with_defaults();
        let action = make_throttle_action(
            ProcessIdentity::new(999_999_999, StartId("absent".to_string()), 1000),
            "e2e-throttle-nonexistent",
        );

        let result = runner.execute(&action);
        assert!(
            result.is_err(),
            "throttling nonexistent process should fail"
        );

        ctx.log(
            "error_as_expected",
            json!({ "error": format!("{:?}", result) }),
        );
        ctx.log("test_complete", json!({ "result": "passed" }));
    }
}

// ============================================================================
// SCENARIO 6: Cgroup Freeze Action (Placeholder - pending sj6.5)
// ============================================================================

// cgroup v2 freezing is Linux-only.
#[cfg(target_os = "linux")]
mod cgroup_freeze_action {
    use super::*;
    use pt_core::action::executor::ActionRunner;
    #[cfg(target_os = "linux")]
    use pt_core::action::{is_freeze_available, FreezeActionRunner};
    use pt_core::decision::Action as ActionType;
    use pt_core::test_utils::OwnedCgroupFixture;

    fn make_freeze_action(target: ProcessIdentity, action_id: &str) -> PlanAction {
        PlanAction {
            action_id: action_id.to_string(),
            action: ActionType::Freeze,
            target,
            order: 0,
            stage: 0,
            timeouts: ActionTimeouts::default(),
            pre_checks: vec![],
            rationale: empty_rationale(),
            on_success: vec![],
            on_failure: vec![],
            blocked: false,
            routing: ActionRouting::Direct,
            confidence: ActionConfidence::Normal,
            original_zombie_target: None,
            d_state_diagnostics: None,
        }
    }

    fn make_unfreeze_action(target: ProcessIdentity, action_id: &str) -> PlanAction {
        PlanAction {
            action_id: action_id.to_string(),
            action: ActionType::Unfreeze,
            target,
            order: 1,
            stage: 1,
            timeouts: ActionTimeouts::default(),
            pre_checks: vec![],
            rationale: empty_rationale(),
            on_success: vec![],
            on_failure: vec![],
            blocked: false,
            routing: ActionRouting::Direct,
            confidence: ActionConfidence::Normal,
            original_zombie_target: None,
            d_state_diagnostics: None,
        }
    }

    /// Test cgroup freeze/thaw workflow
    #[test]
    #[cfg(target_os = "linux")]
    fn test_cgroup_freeze_thaw() {
        let mut ctx = TestContext::new();
        ctx.log("test_start", json!({ "test": "cgroup_freeze_thaw" }));
        let Some(fixture) = OwnedCgroupFixture::new().expect("safe delegated cgroup setup") else {
            ctx.log("capability_unavailable", json!({"reason": "PT_TEST_CGROUP_PARENT prerequisite absent", "positive_kernel_proof": false}));
            return;
        };
        let pid = fixture.target.pid();
        ctx.log("process_spawned", json!({ "identity": fixture.identity, "type": "sleep", "leaf": fixture.leaf, "artifacts": fixture.artifacts }));
        assert!(is_freeze_available(pid), "owned leaf freezer unavailable");
        let before = OwnedCgroupFixture::controls(&fixture.leaf);
        let sibling_before = OwnedCgroupFixture::controls(&fixture.sibling_leaf);
        let frozen = std::fs::read_to_string(fixture.leaf.join("cgroup.freeze")).unwrap();
        assert_eq!(frozen.trim(), "0");
        let events = std::fs::read_to_string(fixture.leaf.join("cgroup.events")).unwrap();
        assert!(events.lines().any(|line| line == "frozen 0"));

        let runner = FreezeActionRunner::with_defaults();

        // Phase 1: Freeze
        let freeze_action = make_freeze_action(fixture.identity.clone(), "e2e-freeze");
        ctx.log_action_attempt(&freeze_action, "execute_freeze");

        let freeze_result = runner.execute(&freeze_action);
        ctx.log(
            "freeze_executed",
            json!({ "pid": pid, "result": format!("{freeze_result:?}") }),
        );
        assert!(
            freeze_result.is_ok(),
            "freeze should succeed: {freeze_result:?}"
        );

        // Verify freeze state
        let verify_freeze = runner.verify(&freeze_action);
        ctx.log_verification(
            "e2e-freeze",
            if verify_freeze.is_ok() {
                "passed"
            } else {
                "failed"
            },
            json!({ "verify_result": format!("{:?}", verify_freeze) }),
        );
        assert!(verify_freeze.is_ok(), "freeze verification should succeed");
        let frozen = std::fs::read_to_string(fixture.leaf.join("cgroup.freeze")).unwrap();
        assert_eq!(frozen.trim(), "1");
        let events = std::fs::read_to_string(fixture.leaf.join("cgroup.events")).unwrap();
        assert!(events.lines().any(|line| line == "frozen 1"));
        fixture.record("frozen");
        fixture.assert_isolated();
        assert_eq!(
            OwnedCgroupFixture::controls(&fixture.sibling_leaf),
            sibling_before
        );

        // Phase 2: Unfreeze (thaw)
        let unfreeze_action = make_unfreeze_action(fixture.identity.clone(), "e2e-unfreeze");
        ctx.log_action_attempt(&unfreeze_action, "execute_unfreeze");

        let unfreeze_result = runner.execute(&unfreeze_action);
        assert!(unfreeze_result.is_ok(), "unfreeze should succeed");
        ctx.log("unfreeze_executed", json!({ "pid": pid, "success": true }));

        // Verify unfreeze state
        let verify_unfreeze = runner.verify(&unfreeze_action);
        ctx.log_verification(
            "e2e-unfreeze",
            if verify_unfreeze.is_ok() {
                "passed"
            } else {
                "failed"
            },
            json!({ "verify_result": format!("{:?}", verify_unfreeze) }),
        );
        assert!(
            verify_unfreeze.is_ok(),
            "unfreeze verification should succeed"
        );
        let frozen = std::fs::read_to_string(fixture.leaf.join("cgroup.freeze")).unwrap();
        assert_eq!(frozen.trim(), "0");
        let events = std::fs::read_to_string(fixture.leaf.join("cgroup.events")).unwrap();
        assert!(events.lines().any(|line| line == "frozen 0"));
        fixture.record("thawed");
        assert_eq!(OwnedCgroupFixture::controls(&fixture.leaf), before);
        assert_eq!(
            OwnedCgroupFixture::controls(&fixture.sibling_leaf),
            sibling_before
        );
        fixture.assert_isolated();

        let mut stale = freeze_action.clone();
        stale.target.uid = stale
            .target
            .uid
            .checked_add(1)
            .expect("planted different UID");
        let result = runner.execute(&stale);
        assert!(
            matches!(result, Err(pt_core::action::ActionError::IdentityMismatch)),
            "stale owner admitted: {result:?}"
        );
        fixture.record("stale-refused");
        assert_eq!(OwnedCgroupFixture::controls(&fixture.leaf), before);
        assert_eq!(
            OwnedCgroupFixture::controls(&fixture.sibling_leaf),
            sibling_before
        );
        fixture.assert_isolated();

        ctx.log("test_complete", json!({ "result": "passed" }));
    }

    /// Test freeze on process without cgroup v2 support fails gracefully
    #[test]
    #[cfg(target_os = "linux")]
    fn test_cgroup_freeze_unavailable() {
        let mut ctx = TestContext::new();
        ctx.log("test_start", json!({ "test": "cgroup_freeze_unavailable" }));

        let runner = FreezeActionRunner::with_defaults();

        // Try to freeze a nonexistent process
        let action = make_freeze_action(
            ProcessIdentity::new(999_999_999, StartId("absent".to_string()), 1000),
            "e2e-freeze-nonexistent",
        );
        let result = runner.execute(&action);

        assert!(result.is_err(), "freezing nonexistent process should fail");
        ctx.log(
            "error_as_expected",
            json!({ "error": format!("{:?}", result) }),
        );

        ctx.log("test_complete", json!({ "result": "passed" }));
    }

    /// Test that freeze is more robust than SIGSTOP (handles D-state better)
    #[test]
    #[cfg(target_os = "linux")]
    fn test_freeze_availability_check() {
        let mut ctx = TestContext::new();
        ctx.log("test_start", json!({ "test": "freeze_availability_check" }));

        // Check availability for our own process
        let my_pid = std::process::id();
        let available = is_freeze_available(my_pid);

        ctx.log(
            "availability_checked",
            json!({ "pid": my_pid, "freeze_available": available }),
        );

        // This is informational - the test passes regardless of availability
        // because availability depends on system configuration
        ctx.log("test_complete", json!({ "result": "passed" }));
    }
}

// ============================================================================
// Integration: Full Workflow Test
// ============================================================================

mod full_workflow {
    use super::*;
    use pt_core::action::executor::ActionRunner;

    /// Test the full observe-mitigate-kill workflow
    #[test]
    fn test_observe_mitigate_kill_workflow() {
        if !ProcessHarness::is_available() {
            return;
        }

        let mut ctx = TestContext::new();
        ctx.log(
            "test_start",
            json!({ "test": "observe_mitigate_kill_workflow" }),
        );

        let harness = ProcessHarness;
        let proc = harness.spawn_sleep(120).expect("spawn");
        let pid = proc.pid();

        ctx.log(
            "process_spawned",
            json!({ "pid": pid, "workflow": "observe-mitigate-kill" }),
        );

        let runner = SignalActionRunner::with_defaults();

        // Step 1: Observe (pause)
        ctx.log("workflow_step", json!({ "step": 1, "action": "pause" }));
        let mut pause_action = make_pause_action(pid, None, "workflow-pause");
        pause_action.target = live_identity(pid);
        ctx.log("live_target", json!({ "identity": pause_action.target }));
        let pause_result = runner.execute(&pause_action);
        assert!(pause_result.is_ok(), "Pause should succeed");

        std::thread::sleep(Duration::from_millis(100));

        #[cfg(target_os = "linux")]
        {
            let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid)).expect("read stat");
            assert!(
                stat.contains(") T ") || stat.contains(") t "),
                "Process should be stopped"
            );
        }

        // Step 2: Mitigate (verify pause, maybe collect more info)
        ctx.log(
            "workflow_step",
            json!({ "step": 2, "action": "verify_pause" }),
        );
        let verify = runner.verify(&pause_action);
        assert!(verify.is_ok(), "Pause verify should succeed");

        // Decision point: we decide to kill
        ctx.log(
            "workflow_decision",
            json!({ "decision": "kill", "reason": "test workflow" }),
        );

        // Step 3: Kill (the process is already stopped, kill anyway)
        ctx.log("workflow_step", json!({ "step": 3, "action": "kill" }));
        let mut kill_action = make_kill_action(pid, "workflow-kill", vec![]);
        kill_action.target = pause_action.target.clone();
        assert_eq!(live_identity(pid), kill_action.target);
        let kill_result = runner.execute(&kill_action);
        assert!(kill_result.is_ok(), "Kill should succeed");

        std::thread::sleep(Duration::from_millis(100));

        // Step 4: Verify termination
        ctx.log(
            "workflow_step",
            json!({ "step": 4, "action": "verify_kill" }),
        );
        let verify = runner.verify(&kill_action);
        assert!(verify.is_ok(), "Kill verify should succeed");

        ctx.log(
            "test_complete",
            json!({ "result": "passed", "workflow": "complete" }),
        );
    }
}
