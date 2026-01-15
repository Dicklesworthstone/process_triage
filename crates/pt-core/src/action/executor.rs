//! Staged action execution protocol.

use crate::action::prechecks::PreCheckProvider;
use crate::plan::{Plan, PlanAction, PreCheck};
use pt_common::ProcessIdentity;
use serde::Serialize;
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
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
            let result = self.execute_action(action);
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
                details: None,
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

    fn execute_action(&self, action: &PlanAction) -> ActionStatus {
        if action.blocked {
            return ActionStatus::Skipped;
        }

        // Run identity verification pre-check first
        if action.pre_checks.contains(&PreCheck::VerifyIdentity) {
            match self.identity_provider.revalidate(&action.target) {
                Ok(true) => {}
                Ok(false) => return ActionStatus::IdentityMismatch,
                Err(_) => return ActionStatus::IdentityMismatch,
            }
        }

        // Run other pre-checks (protected, data-loss, supervisor, session safety)
        if let Some(ref provider) = self.pre_check_provider {
            let pid = action.target.pid.0;
            let sid = action.target.sid;
            let results = provider.run_checks(&action.pre_checks, pid, sid);

            // If any pre-check fails, block the action
            for result in results {
                if let crate::action::prechecks::PreCheckResult::Blocked { check, reason } = result
                {
                    return ActionStatus::PreCheckBlocked { check, reason };
                }
            }
        }

        if let Err(err) = self.runner.execute(action) {
            return status_from_error(err);
        }

        if let Err(err) = self.runner.verify(action) {
            return status_from_error(err);
        }

        ActionStatus::Success
    }
}

fn status_from_error(err: ActionError) -> ActionStatus {
    match err {
        ActionError::IdentityMismatch => ActionStatus::IdentityMismatch,
        ActionError::PermissionDenied => ActionStatus::PermissionDenied,
        ActionError::Timeout => ActionStatus::Timeout,
        ActionError::Failed(_) => ActionStatus::Failed,
    }
}

struct ActionLock {
    lock_path: PathBuf,
}

impl ActionLock {
    fn acquire(path: &Path) -> Result<Self, ExecutionError> {
        let file = OpenOptions::new().create_new(true).write(true).open(path);
        match file {
            Ok(mut handle) => {
                // Write PID to lock file for stale lock detection
                let _ = handle.write_all(format!("{}", std::process::id()).as_bytes());
                Ok(Self {
                    lock_path: path.to_path_buf(),
                })
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                // Check if the lock is stale (holder process is dead)
                if Self::is_stale_lock(path) {
                    // Try to remove stale lock and acquire
                    if fs::remove_file(path).is_ok() {
                        return Self::acquire(path); // Retry acquisition
                    }
                }
                Err(ExecutionError::LockUnavailable)
            }
            Err(err) => Err(ExecutionError::Io(err)),
        }
    }

    /// Check if a lock file is stale (holder process no longer exists).
    fn is_stale_lock(path: &Path) -> bool {
        if let Ok(contents) = fs::read_to_string(path) {
            if let Ok(pid) = contents.trim().parse::<u32>() {
                // Check if process with this PID exists
                #[cfg(unix)]
                {
                    let result = unsafe { libc::kill(pid as i32, 0) };
                    if result == 0 {
                        return false;
                    }
                    let err = std::io::Error::last_os_error();
                    return match err.raw_os_error() {
                        Some(code) if code == libc::ESRCH => true,
                        Some(code) if code == libc::EPERM => false,
                        _ => true,
                    };
                }
                #[cfg(not(unix))]
                {
                    let _ = pid;
                    return false;
                }
            }
        }
        // Can't read/parse lock file - might be corrupted, treat as stale
        true
    }
}

impl Drop for ActionLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_path);
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
            },
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
}
