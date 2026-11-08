//! Staged action execution protocol.

use crate::action::prechecks::PreCheckProvider;
use crate::plan::{Plan, PlanAction, PreCheck};
use pt_common::ProcessIdentity;
use serde::Serialize;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;
use thiserror::Error;

/// Errors during plan execution.
#[derive(Debug, Error)]
pub enum ExecutionError {
    #[error("failed to acquire action lock")]
    LockUnavailable,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Errors during action execution.
#[derive(Debug, Error)]
pub enum ActionError {
    #[error("identity mismatch")]
    IdentityMismatch,
    #[error("process not found")]
    ProcessNotFound,
    #[error("permission denied")]
    PermissionDenied,
    #[error("timeout")]
    Timeout,
    #[error("action failed: {0}")]
    Failed(String),
}

/// Status of a single action.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActionStatus {
    Success,
    IdentityMismatch,
    ProcessNotFound,
    PermissionDenied,
    Timeout,
    Failed,
    Skipped,
    /// Pre-check failed (protected, data-loss risk, etc.)
    PreCheckBlocked {
        check: PreCheck,
        reason: String,
    },
}

/// Per-action result with timing and details.
#[derive(Debug, Clone, Serialize)]
pub struct ActionResult {
    pub action_id: String,
    pub status: ActionStatus,
    pub time_ms: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// Summary of execution results.
#[derive(Debug, Clone, Serialize)]
pub struct ExecutionSummary {
    pub actions_attempted: usize,
    pub actions_succeeded: usize,
    pub actions_failed: usize,
}

/// Full execution result with per-action outcomes.
#[derive(Debug, Clone, Serialize)]
pub struct ExecutionResult {
    pub summary: ExecutionSummary,
    pub outcomes: Vec<ActionResult>,
}

/// Trait for executing actions (signals, cgroup ops, etc.).
pub trait ActionRunner {
    fn execute(&self, action: &PlanAction) -> Result<(), ActionError>;
    fn verify(&self, action: &PlanAction) -> Result<(), ActionError>;

    /// Revalidate the identity of the target process before taking action.
    fn revalidate(
        &self,
        _action: &PlanAction,
        _provider: &dyn IdentityProvider,
    ) -> Result<bool, ActionError> {
        Ok(true)
    }
}

/// No-op action runner (used for tests and scaffolding).
#[derive(Debug, Default)]
pub struct NoopActionRunner;

impl ActionRunner for NoopActionRunner {
    fn execute(&self, _action: &PlanAction) -> Result<(), ActionError> {
        Ok(())
    }

    fn verify(&self, _action: &PlanAction) -> Result<(), ActionError> {
        Ok(())
    }
}

/// Trait for revalidating identity before action.
pub trait IdentityProvider {
    fn revalidate(&self, target: &ProcessIdentity) -> Result<bool, ActionError>;
}

/// Static identity provider for tests.
#[derive(Debug, Default)]
pub struct StaticIdentityProvider {
    identities: HashMap<u32, ProcessIdentity>,
}

impl StaticIdentityProvider {
    pub fn with_identity(mut self, identity: ProcessIdentity) -> Self {
        self.identities.insert(identity.pid.0, identity);
        self
    }
}

impl IdentityProvider for StaticIdentityProvider {
    fn revalidate(&self, target: &ProcessIdentity) -> Result<bool, ActionError> {
        match self.identities.get(&target.pid.0) {
            Some(current) => Ok(current.matches(target)),
            None => Ok(false),
        }
    }
}

/// Action executor with staged protocol.
pub struct ActionExecutor<'a> {
    runner: &'a dyn ActionRunner,
    identity_provider: &'a dyn IdentityProvider,
    pre_check_provider: Option<&'a dyn PreCheckProvider>,
    lock_path: PathBuf,
}

impl<'a> ActionExecutor<'a> {
    pub fn new(
        runner: &'a dyn ActionRunner,
        identity_provider: &'a dyn IdentityProvider,
        lock_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            runner,
            identity_provider,
            pre_check_provider: None,
            lock_path: lock_path.into(),
        }
    }

    /// Set the pre-check provider for safety gates.
    pub fn with_pre_check_provider(mut self, provider: &'a dyn PreCheckProvider) -> Self {
        self.pre_check_provider = Some(provider);
        self
    }

    pub fn execute_plan(&self, plan: &Plan) -> Result<ExecutionResult, ExecutionError> {
        let _lock = ActionLock::acquire(&self.lock_path)?;

        let mut outcomes = Vec::new();
        let mut succeeded = 0;
        let mut failed = 0;

        for action in &plan.actions {
            let start = Instant::now();
            let (result, details) = self.execute_action(action);
            let time_ms = start.elapsed().as_millis();
            match &result {
                ActionStatus::Success => succeeded += 1,
                ActionStatus::Skipped => {}
                _ => failed += 1,
            }

            outcomes.push(ActionResult {
                action_id: action.action_id.clone(),
                status: result,
                time_ms,
                details,
            });
        }

        Ok(ExecutionResult {
            summary: ExecutionSummary {
                actions_attempted: plan.actions.len(),
                actions_succeeded: succeeded,
                actions_failed: failed,
            },
            outcomes,
        })
    }

    fn execute_action(&self, action: &PlanAction) -> (ActionStatus, Option<String>) {
        if action.blocked {
            return (ActionStatus::Skipped, None);
        }

        if action.routing == crate::plan::ActionRouting::Supervisor
            || action.supervisor_restart.is_some()
        {
            if let Err(error) = super::supervisor::restart_binding_for_action(action) {
                return outcome_from_error(error);
            }
            if self.pre_check_provider.is_none() {
                return outcome_from_error(ActionError::Failed(
                    "supervisor restart requires the live plan-aware safety prechecks".to_string(),
                ));
            }
        }

        // The plan's pre-checks plus the ones pt requires for this action type.
        let pre_checks = crate::plan::effective_pre_checks(action);

        // Run identity verification pre-check first
        if pre_checks.contains(&PreCheck::VerifyIdentity) {
            match self.identity_provider.revalidate(&action.target) {
                Ok(true) => {}
                Ok(false) => return outcome_from_error(ActionError::IdentityMismatch),
                Err(error) => {
                    return (ActionStatus::IdentityMismatch, Some(error.to_string()));
                }
            }
        }

        // Just-in-time revalidation by the runner itself
        match self.runner.revalidate(action, self.identity_provider) {
            Ok(true) => {}
            Ok(false) => return outcome_from_error(ActionError::IdentityMismatch),
            Err(error) => return outcome_from_error(error),
        }

        // Run other pre-checks (protected, data-loss, supervisor, session safety)
        if let Some(provider) = self.pre_check_provider {
            let results = provider.run_checks_for_plan(action);

            // If any pre-check fails, block the action
            for result in results {
                if let crate::action::prechecks::PreCheckResult::Blocked { check, reason } = result
                {
                    return (ActionStatus::PreCheckBlocked { check, reason }, None);
                }
            }
        }

        if let Err(err) = self.runner.execute(action) {
            return outcome_from_error(err);
        }

        if let Err(err) = self.runner.verify(action) {
            return outcome_from_error(err);
        }

        (ActionStatus::Success, None)
    }
}

fn outcome_from_error(error: ActionError) -> (ActionStatus, Option<String>) {
    // A failed action can already have changed part of its target. Preserve the
    // runner's explanation in persisted/JSON outcomes instead of discarding it.
    let details = error.to_string();
    (status_from_error(error), Some(details))
}

fn status_from_error(err: ActionError) -> ActionStatus {
    match err {
        ActionError::IdentityMismatch => ActionStatus::IdentityMismatch,
        ActionError::ProcessNotFound => ActionStatus::ProcessNotFound,
        ActionError::PermissionDenied => ActionStatus::PermissionDenied,
        ActionError::Timeout => ActionStatus::Timeout,
        ActionError::Failed(_) => ActionStatus::Failed,
    }
}

struct ActionLock {
    file: std::fs::File,
}

impl ActionLock {
    fn acquire(path: &Path) -> Result<Self, ExecutionError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false) // Keep lock file contents (advisory lock only)
            .open(path)?;

        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = file.as_raw_fd();
            // LOCK_EX = Exclusive lock
            // LOCK_NB = Non-blocking (fail if held)
            let result = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };

            if result != 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    return Err(ExecutionError::LockUnavailable);
                }
                return Err(ExecutionError::Io(err));
            }
        }

        // On non-unix, we just hold the file handle (basic locking)
        // Ideally we'd use a crate like fs2 for cross-platform, but we stick to libc/std

        // Truncate and write our PID
        file.set_len(0)?;
        let mut writer = &file;
        let _ = writer.write_all(format!("{}", std::process::id()).as_bytes());
        let _ = writer.flush();

        Ok(Self { file })
    }
}

impl Drop for ActionLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            // Best effort unlock
            unsafe {
                libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
            }
        }
        // Do NOT remove the lock file. Removing it introduces a race condition
        // where a waiting process might acquire a lock on a file descriptor
        // that refers to a deleted inode, while a new process creates a new file.
        // Letting the empty lock file persist is safe and standard practice.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Policy;
    use crate::decision::{Action, DecisionOutcome, ExpectedLoss};
    use crate::plan::{DecisionBundle, DecisionCandidate};
    use pt_common::{IdentityQuality, ProcessId, SessionId, StartId};
    use tempfile::tempdir;

    fn make_plan() -> Plan {
        let identity = ProcessIdentity {
            pid: ProcessId(123),
            start_id: StartId("boot:1:123".to_string()),
            uid: 1000,
            pgid: None,
            sid: None,
            quality: IdentityQuality::Full,
        };
        let decision = DecisionOutcome {
            expected_loss: vec![ExpectedLoss {
                action: Action::Pause,
                loss: 1.0,
            }],
            optimal_action: Action::Pause,
            sprt_boundary: None,
            posterior_odds_abandoned_vs_useful: None,
            recovery_expectations: None,
            rationale: crate::decision::DecisionRationale {
                chosen_action: Action::Pause,
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
        };
        let bundle = DecisionBundle {
            session_id: SessionId("pt-20260115-120000-abcd".to_string()),
            policy: Policy::default(),
            candidates: vec![DecisionCandidate {
                identity,
                ppid: None,
                decision,
                blocked_reasons: vec![],
                stage_pause_before_kill: false,
                process_state: None,
                parent_identity: None,
                d_state_diagnostics: None,
                supervisor_restart: None,
            }],
            generated_at: Some("2026-01-15T12:00:00Z".to_string()),
        };
        crate::plan::generate_plan(&bundle)
    }

    #[test]
    fn identity_mismatch_blocks_action() {
        let plan = make_plan();
        let dir = tempdir().expect("tempdir");
        let runner = NoopActionRunner;
        let identity_provider = StaticIdentityProvider::default();
        let executor = ActionExecutor::new(&runner, &identity_provider, dir.path().join("lock"));
        let result = executor.execute_plan(&plan).expect("execute");
        assert_eq!(result.outcomes[0].status, ActionStatus::IdentityMismatch);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn supervisor_restart_cannot_bypass_plan_aware_prechecks() {
        struct CountingRunner(std::cell::Cell<bool>);
        impl ActionRunner for CountingRunner {
            fn execute(&self, _: &PlanAction) -> Result<(), ActionError> {
                self.0.set(true);
                Ok(())
            }
            fn verify(&self, _: &PlanAction) -> Result<(), ActionError> {
                Ok(())
            }
        }
        let mut plan = make_plan();
        let action = &mut plan.actions[0];
        action.action = crate::decision::Action::Restart;
        action.routing = crate::plan::ActionRouting::Supervisor;
        // SAFETY: geteuid only reads the test process's credentials.
        let uid = unsafe { libc::geteuid() };
        action.target.uid = uid;
        action.supervisor_restart = Some(crate::action::SystemdUserServiceBinding {
            target: action.target.clone(),
            unit: "worker-proof.service".into(),
            control_group: format!(
                "/user.slice/user-{uid}.slice/user@{uid}.service/worker-proof.service"
            ),
            invocation_id: "1234567890abcdef1234567890abcdef".into(),
        });
        let identities = StaticIdentityProvider::default().with_identity(action.target.clone());
        let runner = CountingRunner(std::cell::Cell::new(false));
        let dir = tempdir().unwrap();
        let executor = ActionExecutor::new(&runner, &identities, dir.path().join("restart.lock"));
        let result = executor.execute_plan(&plan).unwrap();
        assert_eq!(result.outcomes[0].status, ActionStatus::Failed);
        assert!(!runner.0.get());

        let provider = crate::action::NoopPreCheckProvider;
        let executor = executor.with_pre_check_provider(&provider);
        let result = executor.execute_plan(&plan).unwrap();
        assert!(matches!(
            result.outcomes[0].status,
            ActionStatus::PreCheckBlocked {
                check: PreCheck::CheckSupervisor,
                ..
            }
        ));
        assert!(!runner.0.get());
    }

    #[test]
    fn execution_and_verification_failures_preserve_partial_action_details() {
        struct PartialRunner {
            fail_during_verify: bool,
        }
        const DETAIL: &str = "renice incomplete: permission denied; 1 thread priority write(s) already succeeded; changes were not rolled back";
        impl ActionRunner for PartialRunner {
            fn execute(&self, _: &PlanAction) -> Result<(), ActionError> {
                if self.fail_during_verify {
                    Ok(())
                } else {
                    Err(ActionError::Failed(DETAIL.into()))
                }
            }
            fn verify(&self, _: &PlanAction) -> Result<(), ActionError> {
                assert!(
                    self.fail_during_verify,
                    "verification must not run after execution failure"
                );
                Err(ActionError::Failed(DETAIL.into()))
            }
        }
        for fail_during_verify in [false, true] {
            let plan = make_plan();
            let dir = tempdir().expect("tempdir");
            let runner = PartialRunner { fail_during_verify };
            let provider =
                StaticIdentityProvider::default().with_identity(plan.actions[0].target.clone());
            let executor = ActionExecutor::new(&runner, &provider, dir.path().join("lock"));
            let result = executor.execute_plan(&plan).expect("execute");
            assert_eq!(result.summary.actions_failed, 1);
            assert_eq!(result.outcomes[0].status, ActionStatus::Failed);
            let expected = format!("action failed: {DETAIL}");
            assert_eq!(
                result.outcomes[0].details.as_deref(),
                Some(expected.as_str())
            );
            let json = serde_json::to_value(&result).expect("serialize outcome");
            assert!(json["outcomes"][0]["details"]
                .as_str()
                .unwrap()
                .contains("changes were not rolled back"));
        }
    }

    #[test]
    fn lock_contention_returns_error() {
        let plan = make_plan();
        let dir = tempdir().expect("tempdir");
        let lock_path = dir.path().join("lock");
        let _held = ActionLock::acquire(&lock_path).expect("lock");
        let runner = NoopActionRunner;
        let identity_provider = StaticIdentityProvider::default();
        let executor = ActionExecutor::new(&runner, &identity_provider, lock_path);
        let err = executor.execute_plan(&plan).unwrap_err();
        match err {
            ExecutionError::LockUnavailable => {}
            _ => panic!("unexpected error"),
        }
    }

    // ── ActionStatus serde ──────────────────────────────────────────

    #[test]
    fn action_status_serde_success() {
        let json = serde_json::to_string(&ActionStatus::Success).unwrap();
        assert_eq!(json, r#""success""#);
    }

    #[test]
    fn action_status_serde_identity_mismatch() {
        let json = serde_json::to_string(&ActionStatus::IdentityMismatch).unwrap();
        assert_eq!(json, r#""identity_mismatch""#);
    }

    #[test]
    fn action_status_serde_permission_denied() {
        let json = serde_json::to_string(&ActionStatus::PermissionDenied).unwrap();
        assert_eq!(json, r#""permission_denied""#);
    }

    #[test]
    fn action_status_serde_timeout() {
        let json = serde_json::to_string(&ActionStatus::Timeout).unwrap();
        assert_eq!(json, r#""timeout""#);
    }

    #[test]
    fn action_status_serde_failed() {
        let json = serde_json::to_string(&ActionStatus::Failed).unwrap();
        assert_eq!(json, r#""failed""#);
    }

    #[test]
    fn action_status_serde_skipped() {
        let json = serde_json::to_string(&ActionStatus::Skipped).unwrap();
        assert_eq!(json, r#""skipped""#);
    }

    #[test]
    fn action_status_serde_pre_check_blocked() {
        let status = ActionStatus::PreCheckBlocked {
            check: PreCheck::VerifyIdentity,
            reason: "pid changed".to_string(),
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("pre_check_blocked"));
        assert!(json.contains("pid changed"));
    }

    #[test]
    fn action_status_eq() {
        assert_eq!(ActionStatus::Success, ActionStatus::Success);
        assert_ne!(ActionStatus::Success, ActionStatus::Failed);
    }

    // ── status_from_error ───────────────────────────────────────────

    #[test]
    fn status_from_error_identity_mismatch() {
        assert_eq!(
            status_from_error(ActionError::IdentityMismatch),
            ActionStatus::IdentityMismatch
        );
    }

    #[test]
    fn status_from_error_permission_denied() {
        assert_eq!(
            status_from_error(ActionError::PermissionDenied),
            ActionStatus::PermissionDenied
        );
    }

    #[test]
    fn status_from_error_timeout() {
        assert_eq!(
            status_from_error(ActionError::Timeout),
            ActionStatus::Timeout
        );
    }

    #[test]
    fn status_from_error_failed() {
        assert_eq!(
            status_from_error(ActionError::Failed("err".into())),
            ActionStatus::Failed
        );
    }

    // ── ActionError display ─────────────────────────────────────────

    #[test]
    fn action_error_display() {
        assert_eq!(
            ActionError::IdentityMismatch.to_string(),
            "identity mismatch"
        );
        assert_eq!(
            ActionError::PermissionDenied.to_string(),
            "permission denied"
        );
        assert_eq!(ActionError::Timeout.to_string(), "timeout");
        assert!(ActionError::Failed("oops".into())
            .to_string()
            .contains("oops"));
    }

    // ── ExecutionError display ──────────────────────────────────────

    #[test]
    fn execution_error_display() {
        assert!(ExecutionError::LockUnavailable.to_string().contains("lock"));
    }

    // ── NoopActionRunner ────────────────────────────────────────────

    #[test]
    fn noop_runner_execute_succeeds() {
        let runner = NoopActionRunner;
        let plan = make_plan();
        assert!(runner.execute(&plan.actions[0]).is_ok());
    }

    #[test]
    fn noop_runner_verify_succeeds() {
        let runner = NoopActionRunner;
        let plan = make_plan();
        assert!(runner.verify(&plan.actions[0]).is_ok());
    }

    // ── StaticIdentityProvider ──────────────────────────────────────

    #[test]
    fn static_identity_provider_empty_returns_false() {
        let provider = StaticIdentityProvider::default();
        let identity = ProcessIdentity {
            pid: ProcessId(1),
            start_id: StartId("boot:1:1".to_string()),
            uid: 1000,
            pgid: None,
            sid: None,
            quality: IdentityQuality::Full,
        };
        assert!(!provider.revalidate(&identity).unwrap());
    }

    #[test]
    fn static_identity_provider_with_matching_identity() {
        let identity = ProcessIdentity {
            pid: ProcessId(123),
            start_id: StartId("boot:1:123".to_string()),
            uid: 1000,
            pgid: None,
            sid: None,
            quality: IdentityQuality::Full,
        };
        let provider = StaticIdentityProvider::default().with_identity(identity.clone());
        assert!(provider.revalidate(&identity).unwrap());
    }

    #[test]
    fn static_identity_provider_pid_not_found() {
        let identity_in = ProcessIdentity {
            pid: ProcessId(123),
            start_id: StartId("boot:1:123".to_string()),
            uid: 1000,
            pgid: None,
            sid: None,
            quality: IdentityQuality::Full,
        };
        let provider = StaticIdentityProvider::default().with_identity(identity_in);
        let query = ProcessIdentity {
            pid: ProcessId(999),
            start_id: StartId("boot:1:999".to_string()),
            uid: 1000,
            pgid: None,
            sid: None,
            quality: IdentityQuality::Full,
        };
        assert!(!provider.revalidate(&query).unwrap());
    }

    // ── ActionLock ──────────────────────────────────────────────────

    #[test]
    fn action_lock_acquires_and_writes_pid() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("action.lock");
        {
            let _lock = ActionLock::acquire(&path).unwrap();
            assert!(path.exists());
            let content = std::fs::read_to_string(&path).unwrap();
            let pid: u32 = content.trim().parse().unwrap();
            assert_eq!(pid, std::process::id());
        }
        // After drop, lock file is NOT removed (per design comment in code)
        assert!(path.exists());
    }

    #[test]
    fn action_lock_double_acquire_fails() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("double.lock");
        let _lock1 = ActionLock::acquire(&path).unwrap();
        let result = ActionLock::acquire(&path);
        assert!(result.is_err());
    }

    // ── ActionResult serialization ──────────────────────────────────

    #[test]
    fn action_result_serializes() {
        let r = ActionResult {
            action_id: "act-1".to_string(),
            status: ActionStatus::Success,
            time_ms: 42,
            details: None,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("act-1"));
        assert!(json.contains("success"));
        assert!(!json.contains("details")); // skip_serializing_if None
    }

    #[test]
    fn action_result_with_details() {
        let r = ActionResult {
            action_id: "act-2".to_string(),
            status: ActionStatus::Failed,
            time_ms: 100,
            details: Some("something went wrong".to_string()),
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("something went wrong"));
    }

    // ── ExecutionResult serialization ────────────────────────────────

    #[test]
    fn execution_result_serializes() {
        let r = ExecutionResult {
            summary: ExecutionSummary {
                actions_attempted: 3,
                actions_succeeded: 2,
                actions_failed: 1,
            },
            outcomes: vec![],
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"actions_attempted\":3"));
        assert!(json.contains("\"actions_succeeded\":2"));
    }

    // ── ActionExecutor success path ─────────────────────────────────

    #[test]
    fn executor_success_with_matching_identity() {
        let plan = make_plan();
        let dir = tempdir().unwrap();
        let runner = NoopActionRunner;
        let target_identity = plan.actions[0].target.clone();
        let identity_provider = StaticIdentityProvider::default().with_identity(target_identity);
        let executor = ActionExecutor::new(&runner, &identity_provider, dir.path().join("lock"));
        let result = executor.execute_plan(&plan).unwrap();
        assert_eq!(result.outcomes[0].status, ActionStatus::Success);
        assert_eq!(result.summary.actions_succeeded, 1);
        assert_eq!(result.summary.actions_failed, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn executor_passes_action_context_to_live_protection_without_bypassing_other_protections() {
        use crate::action::prechecks::{LivePreCheckConfig, LivePreCheckProvider, PreCheckResult};
        use crate::config::policy::Guardrails;

        // Exercise real live protection through executor dispatch. Isolate
        // unrelated probes, and use a no-op runner: no process is signalled.
        struct ProtectionOnly(LivePreCheckProvider);
        impl PreCheckProvider for ProtectionOnly {
            fn check_not_protected(&self, pid: u32) -> PreCheckResult {
                self.0.check_not_protected(pid)
            }

            fn check_not_protected_for_action(&self, pid: u32, action: Action) -> PreCheckResult {
                self.0.check_not_protected_for_action(pid, action)
            }

            fn check_data_loss(&self, _pid: u32) -> PreCheckResult {
                PreCheckResult::Passed
            }

            fn check_supervisor(&self, _pid: u32) -> PreCheckResult {
                PreCheckResult::Passed
            }

            fn check_session_safety(&self, _pid: u32, _sid: Option<u32>) -> PreCheckResult {
                PreCheckResult::Passed
            }
        }

        let mut guardrails = Guardrails {
            protected_patterns: Vec::new(),
            protected_users: Vec::new(),
            never_kill_pid: Vec::new(),
            never_kill_ppid: Vec::new(),
            ..Guardrails::default()
        };
        let provider = ProtectionOnly(
            LivePreCheckProvider::new(Some(&guardrails), LivePreCheckConfig::default()).unwrap(),
        );
        let mut plan = make_plan();
        plan.actions[0].target.pid = ProcessId(u32::MAX);
        // An edited saved plan must not opt out of mandatory apply-time safety.
        plan.actions[0].pre_checks.clear();
        let identity_provider =
            StaticIdentityProvider::default().with_identity(plan.actions[0].target.clone());
        let runner = NoopActionRunner;
        let dir = tempdir().unwrap().keep();

        for action in [
            Action::Kill,
            Action::Restart,
            Action::Pause,
            Action::Freeze,
            Action::Throttle,
            Action::Renice,
            Action::Quarantine,
        ] {
            plan.actions[0].action = action;
            let executor = ActionExecutor::new(&runner, &identity_provider, dir.join("lock"))
                .with_pre_check_provider(&provider);
            let result = executor.execute_plan(&plan).unwrap();
            assert!(
                matches!(&result.outcomes[0].status, ActionStatus::PreCheckBlocked {
                    check: PreCheck::CheckNotProtected, reason
                } if reason.contains("complete infrastructure evidence")),
                "{action:?}: {:?}",
                result.outcomes[0].status
            );
        }
        for action in [
            Action::Keep,
            Action::Resume,
            Action::Unfreeze,
            Action::Unquarantine,
        ] {
            plan.actions[0].action = action;
            let executor = ActionExecutor::new(&runner, &identity_provider, dir.join("lock"))
                .with_pre_check_provider(&provider);
            let result = executor.execute_plan(&plan).unwrap();
            assert_eq!(
                result.outcomes[0].status,
                ActionStatus::Success,
                "{action:?}"
            );
        }

        guardrails.never_kill_pid.push(u32::MAX);
        let provider = ProtectionOnly(
            LivePreCheckProvider::new(Some(&guardrails), LivePreCheckConfig::default()).unwrap(),
        );
        for action in [Action::Resume, Action::Unfreeze, Action::Unquarantine] {
            plan.actions[0].action = action;
            let executor = ActionExecutor::new(&runner, &identity_provider, dir.join("lock"))
                .with_pre_check_provider(&provider);
            let result = executor.execute_plan(&plan).unwrap();
            assert!(
                matches!(&result.outcomes[0].status, ActionStatus::PreCheckBlocked {
                    check: PreCheck::CheckNotProtected, reason
                } if reason.contains("protected PID")),
                "{action:?}: {:?}",
                result.outcomes[0].status
            );
        }
    }

    #[test]
    fn executor_blocked_action_skipped() {
        let mut plan = make_plan();
        plan.actions[0].blocked = true;
        let dir = tempdir().unwrap();
        let runner = NoopActionRunner;
        let identity_provider = StaticIdentityProvider::default();
        let executor = ActionExecutor::new(&runner, &identity_provider, dir.path().join("lock"));
        let result = executor.execute_plan(&plan).unwrap();
        assert_eq!(result.outcomes[0].status, ActionStatus::Skipped);
        // Skipped actions don't count as succeeded or failed
        assert_eq!(result.summary.actions_succeeded, 0);
        assert_eq!(result.summary.actions_failed, 0);
    }

    #[test]
    fn executor_empty_plan() {
        let mut plan = make_plan();
        plan.actions.clear();
        let dir = tempdir().unwrap();
        let runner = NoopActionRunner;
        let identity_provider = StaticIdentityProvider::default();
        let executor = ActionExecutor::new(&runner, &identity_provider, dir.path().join("lock"));
        let result = executor.execute_plan(&plan).unwrap();
        assert_eq!(result.summary.actions_attempted, 0);
        assert!(result.outcomes.is_empty());
    }

    #[test]
    fn executor_has_timing() {
        let plan = make_plan();
        let dir = tempdir().unwrap();
        let runner = NoopActionRunner;
        let identity_provider = StaticIdentityProvider::default();
        let executor = ActionExecutor::new(&runner, &identity_provider, dir.path().join("lock"));
        let result = executor.execute_plan(&plan).unwrap();
        // time_ms should be a small non-negative number (noop is fast)
        assert!(result.outcomes[0].time_ms < 1000);
    }
}
