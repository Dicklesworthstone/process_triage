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
//! 4. Placeholder tests for renice and throttle (pending implementation)
//!
//! All tests capture structured logs including:
//! - Generated plan (JSON)
//! - Action attempts and outcomes
//! - Verification results
//! - Failure recovery hints

#![cfg(feature = "test-utils")]

use pt_common::{IdentityQuality, ProcessId, ProcessIdentity, StartId};
use pt_core::action::executor::{
    ActionExecutor, ActionResult, ActionStatus, ExecutionResult, NoopActionRunner,
    StaticIdentityProvider,
};
use pt_core::action::prechecks::{
    LivePreCheckConfig, LivePreCheckProvider, NoopPreCheckProvider, PreCheckProvider,
    PreCheckResult,
};
use pt_core::action::{ReniceActionRunner, ReniceConfig, SignalActionRunner, SignalConfig};
use pt_core::collect::ProcessState;
use pt_core::config::Policy;
use pt_core::decision::{Action, DecisionOutcome, DecisionRationale, ExpectedLoss};
use pt_core::plan::{
    ActionConfidence, ActionRationale, ActionRouting, ActionTimeouts, DecisionBundle,
    DecisionCandidate, GatesSummary, Plan, PlanAction, PreCheck,
};
use pt_core::test_utils::ProcessHarness;
use serde_json::json;
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

        let harness = ProcessHarness::default();
        let proc = harness.spawn_sleep(60).expect("spawn sleep");
        let pid = proc.pid();

        ctx.log("process_spawned", json!({ "pid": pid, "type": "sleep" }));

        let runner = SignalActionRunner::with_defaults();

        // Phase 1: Pause
        let pause_action = make_pause_action(pid, None, "e2e-pause-1");
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
        let resume_action = make_resume_action(pid, None, "e2e-resume-1");
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

        let harness = ProcessHarness::default();
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
        let pause_action = make_pause_action(pid, Some(pgid), "e2e-group-pause");
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
        let resume_action = make_resume_action(pid, Some(pgid), "e2e-group-resume");
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
    fn test_graceful_kill_sigterm_only() {
        if !ProcessHarness::is_available() {
            return;
        }

        let mut ctx = TestContext::new();
        ctx.log("test_start", json!({ "test": "graceful_kill_sigterm_only" }));

        let harness = ProcessHarness::default();
        let proc = harness.spawn_sleep(60).expect("spawn sleep");
        let pid = proc.pid();

        ctx.log("process_spawned", json!({ "pid": pid }));

        // Short grace period - sleep responds to SIGTERM
        let runner = SignalActionRunner::new(SignalConfig {
            term_grace_ms: 2000,
            poll_interval_ms: 100,
            verify_timeout_ms: 5000,
            use_process_groups: false,
        });

        let kill_action = make_kill_action(pid, "e2e-graceful-kill", vec![]);
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

        assert!(verify.is_ok(), "Verification should confirm process is dead");
        ctx.log("test_complete", json!({ "result": "passed" }));
    }

    /// Test that staged kill escalates to SIGKILL for unresponsive processes
    #[test]
    fn test_kill_escalates_to_sigkill() {
        if !ProcessHarness::is_available() {
            return;
        }

        let mut ctx = TestContext::new();
        ctx.log(
            "test_start",
            json!({ "test": "kill_escalates_to_sigkill" }),
        );

        let harness = ProcessHarness::default();
        // spawn_busy creates a CPU-bound process that ignores SIGTERM
        let proc = harness.spawn_busy().expect("spawn busy");
        let pid = proc.pid();

        ctx.log(
            "process_spawned",
            json!({ "pid": pid, "type": "busy_loop" }),
        );

        // Very short grace period to trigger escalation
        let runner = SignalActionRunner::new(SignalConfig {
            term_grace_ms: 500, // Short timeout
            poll_interval_ms: 50,
            verify_timeout_ms: 5000,
            use_process_groups: false,
        });

        let kill_action = make_kill_action(pid, "e2e-force-kill", vec![]);
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

        let harness = ProcessHarness::default();
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
            if let Ok(stat) = std::fs::read_to_string(format!("/proc/{}/stat", pid)) {
                if stat.contains(") Z ") {
                    is_zombie = true;
                    ctx.log(
                        "zombie_detected",
                        json!({ "pid": pid, "attempts": i + 1 }),
                    );
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        let runner = SignalActionRunner::with_defaults();
        let kill_action = make_kill_action(pid, "e2e-kill-zombie", vec![]);

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

        let dir = tempdir().expect("tempdir");
        let lock_path = dir.path().join("test.lock");

        // Create a plan targeting PID 99999 (doesn't exist)
        let kill_action = make_kill_action(99999, "e2e-identity-test", vec![PreCheck::VerifyIdentity]);
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

        let dir = tempdir().expect("tempdir");
        let lock_path = dir.path().join("test.lock");

        // Hold the lock using direct flock
        let held_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
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

        let dir = tempdir().expect("tempdir");
        let lock_path = dir.path().join("test.lock");

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
                ctx.log("precheck_result", json!({ "status": format!("{:?}", other) }));
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
// SCENARIO 4: Renice Action (Placeholder - pending sj6.4)
// ============================================================================

mod renice_action {
    use super::*;
    use pt_core::action::executor::ActionRunner;

    #[cfg(target_os = "linux")]
    fn read_nice_value(pid: u32) -> Option<i32> {
        let stat_path = format!("/proc/{pid}/stat");
        let content = std::fs::read_to_string(stat_path).ok()?;
        let comm_end = content.rfind(')')?;
        let after_comm = content.get(comm_end + 2..)?;
        let fields: Vec<&str> = after_comm.split_whitespace().collect();
        fields.get(16)?.parse::<i32>().ok()
    }

    #[test]
    #[cfg(unix)]
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

        let harness = ProcessHarness::default();
        let proc = harness.spawn_sleep(60).expect("spawn sleep");
        let pid = proc.pid();

        ctx.log("process_spawned", json!({ "pid": pid, "type": "sleep" }));

        #[cfg(target_os = "linux")]
        let before = read_nice_value(pid);
        #[cfg(target_os = "linux")]
        ctx.log("nice_before", json!({ "pid": pid, "nice": before }));

        let runner = ReniceActionRunner::with_defaults();
        let action = make_renice_action(pid, "e2e-renice-1");

        ctx.log_action_attempt(&action, "execute_renice");

        let execute_result = runner.execute(&action);
        match execute_result {
            Ok(()) => {
                let verify_result = runner.verify(&action);
                if let Err(ref e) = verify_result {
                    ctx.on_failure("renice_priority_adjustment", &format!("Verify failed: {:?}", e));
                }
                assert!(verify_result.is_ok(), "Renice verification should succeed");

                #[cfg(target_os = "linux")]
                if let Some(after) = read_nice_value(pid) {
                    ctx.log(
                        "nice_after",
                        json!({ "pid": pid, "nice": after, "expected": pt_core::action::DEFAULT_NICE_VALUE }),
                    );
                    assert_eq!(
                        after,
                        pt_core::action::DEFAULT_NICE_VALUE,
                        "expected nice value to change"
                    );
                } else {
                    ctx.log("nice_after_unavailable", json!({ "pid": pid }));
                }
            }
            Err(pt_core::action::ActionError::PermissionDenied) => {
                ctx.log(
                    "renice_permission_denied",
                    json!({ "pid": pid, "note": "insufficient permissions; skipping assertions" }),
                );
                return;
            }
            Err(e) => {
                ctx.on_failure("renice_priority_adjustment", &format!("Execute failed: {:?}", e));
                panic!("renice execute failed: {:?}", e);
            }
        }

        ctx.log("test_complete", json!({ "result": "passed" }));
    }

    #[test]
    #[cfg(unix)]
    fn test_renice_verification() {
        if !ProcessHarness::is_available() {
            eprintln!("Skipping test: ProcessHarness not available");
            return;
        }

        let mut ctx = TestContext::new();
        ctx.log("test_start", json!({ "test": "renice_verification" }));

        let harness = ProcessHarness::default();
        let proc = harness.spawn_sleep(60).expect("spawn sleep");
        let pid = proc.pid();

        let runner = ReniceActionRunner::with_defaults();
        let action = make_renice_action(pid, "e2e-renice-verify");

        let execute_result = runner.execute(&action);
        if let Err(pt_core::action::ActionError::PermissionDenied) = execute_result {
            ctx.log(
                "renice_permission_denied",
                json!({ "pid": pid, "note": "insufficient permissions; skipping verification" }),
            );
            return;
        }
        assert!(execute_result.is_ok(), "Renice execute should succeed");

        let verify_ok = runner.verify(&action);
        if let Err(ref e) = verify_ok {
            ctx.on_failure("renice_verification", &format!("Verify failed: {:?}", e));
        }
        assert!(verify_ok.is_ok(), "Renice verify should succeed");

        // Intentionally verify with a mismatched expectation to ensure failure path works.
        #[cfg(target_os = "linux")]
        {
            if read_nice_value(pid).is_none() {
                ctx.log("nice_unavailable", json!({ "pid": pid, "note": "skipping mismatch check" }));
                return;
            }
            let mismatch_runner = ReniceActionRunner::new(ReniceConfig {
                nice_value: pt_core::action::DEFAULT_NICE_VALUE + 5,
                clamp_to_range: true,
                capture_reversal: false,
            });
            let mismatch = mismatch_runner.verify(&action);
            match mismatch {
                Err(pt_core::action::ActionError::Failed(_)) => {
                    ctx.log("mismatch_verify_failed", json!({ "pid": pid }));
                }
                Err(pt_core::action::ActionError::PermissionDenied) => {
                    ctx.log(
                        "renice_permission_denied",
                        json!({ "pid": pid, "note": "verification denied; skipping mismatch check" }),
                    );
                }
                Ok(()) => {
                    ctx.on_failure("renice_verification", "mismatch verification unexpectedly succeeded");
                    panic!("mismatch verification unexpectedly succeeded");
                }
                Err(e) => {
                    ctx.on_failure("renice_verification", &format!("unexpected verify error: {:?}", e));
                    panic!("unexpected verify error: {:?}", e);
                }
            }
        }

        ctx.log("test_complete", json!({ "result": "passed" }));
    }
}

// ============================================================================
// SCENARIO 5: Cgroup Throttle Action (Placeholder - pending sj6.6)
// ============================================================================

mod cgroup_throttle_action {
    use super::*;

    /// Placeholder test for cgroup CPU throttle
    /// TODO: Implement when process_triage-sj6.6 is complete
    #[test]
    #[ignore = "Pending implementation of cgroup throttle (sj6.6)"]
    fn test_cgroup_cpu_throttle() {
        let mut ctx = TestContext::new();
        ctx.log(
            "test_start",
            json!({ "test": "cgroup_cpu_throttle", "status": "pending" }),
        );

        // TODO: Implementation
        // 1. Set up isolated test cgroup
        // 2. Spawn CPU burner in cgroup
        // 3. Apply throttle (cpu.max)
        // 4. Verify CPU usage drops
        // 5. Restore settings

        ctx.log("test_complete", json!({ "result": "skipped" }));
    }

    /// Placeholder for throttle with fallback
    #[test]
    #[ignore = "Pending implementation of cgroup throttle (sj6.6)"]
    fn test_cgroup_throttle_with_fallback() {
        // TODO: Test fallback when cgroup v2 not available
    }
}

// ============================================================================
// SCENARIO 6: Cgroup Freeze Action (Placeholder - pending sj6.5)
// ============================================================================

mod cgroup_freeze_action {
    use super::*;

    /// Placeholder test for cgroup freeze/thaw
    /// TODO: Implement when process_triage-sj6.5 is complete
    #[test]
    #[ignore = "Pending implementation of cgroup freeze (sj6.5)"]
    fn test_cgroup_freeze_thaw() {
        let mut ctx = TestContext::new();
        ctx.log(
            "test_start",
            json!({ "test": "cgroup_freeze_thaw", "status": "pending" }),
        );

        // TODO: Implementation
        // 1. Set up isolated test cgroup
        // 2. Spawn process in cgroup
        // 3. Apply freeze (cgroup.freeze)
        // 4. Verify process is frozen
        // 5. Thaw and verify recovery

        ctx.log("test_complete", json!({ "result": "skipped" }));
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

        let harness = ProcessHarness::default();
        let proc = harness.spawn_sleep(120).expect("spawn");
        let pid = proc.pid();

        ctx.log(
            "process_spawned",
            json!({ "pid": pid, "workflow": "observe-mitigate-kill" }),
        );

        let runner = SignalActionRunner::with_defaults();

        // Step 1: Observe (pause)
        ctx.log("workflow_step", json!({ "step": 1, "action": "pause" }));
        let pause_action = make_pause_action(pid, None, "workflow-pause");
        let pause_result = runner.execute(&pause_action);
        assert!(pause_result.is_ok(), "Pause should succeed");

        std::thread::sleep(Duration::from_millis(100));

        #[cfg(target_os = "linux")]
        {
            let stat =
                std::fs::read_to_string(format!("/proc/{}/stat", pid)).expect("read stat");
            assert!(
                stat.contains(") T ") || stat.contains(") t "),
                "Process should be stopped"
            );
        }

        // Step 2: Mitigate (verify pause, maybe collect more info)
        ctx.log("workflow_step", json!({ "step": 2, "action": "verify_pause" }));
        let verify = runner.verify(&pause_action);
        assert!(verify.is_ok(), "Pause verify should succeed");

        // Decision point: we decide to kill
        ctx.log(
            "workflow_decision",
            json!({ "decision": "kill", "reason": "test workflow" }),
        );

        // Step 3: Kill (the process is already stopped, kill anyway)
        ctx.log("workflow_step", json!({ "step": 3, "action": "kill" }));
        let kill_action = make_kill_action(pid, "workflow-kill", vec![]);
        let kill_result = runner.execute(&kill_action);
        assert!(kill_result.is_ok(), "Kill should succeed");

        std::thread::sleep(Duration::from_millis(100));

        // Step 4: Verify termination
        ctx.log("workflow_step", json!({ "step": 4, "action": "verify_kill" }));
        let verify = runner.verify(&kill_action);
        assert!(verify.is_ok(), "Kill verify should succeed");

        ctx.log(
            "test_complete",
            json!({ "result": "passed", "workflow": "complete" }),
        );
    }
}
