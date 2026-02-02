//! Resumable apply workflow with strict identity revalidation.
//!
//! Enables pausing and later resuming a plan execution by:
//! 1. Persisting execution progress to an append-only log.
//! 2. Revalidating process identities before resuming.
//! 3. Failing closed on any identity mismatch.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Identity tuple for revalidation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RevalidationIdentity {
    pub pid: u32,
    pub start_id: String,
    pub uid: u32,
}

/// A planned action to execute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlannedAction {
    pub identity: RevalidationIdentity,
    pub action: String,
    pub expected_loss: f64,
    pub rationale: String,
}

/// Outcome of one executed action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionEntry {
    pub identity: RevalidationIdentity,
    pub action: String,
    pub status: ExecutionStatus,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Status of an individual action execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    /// Successfully applied.
    Applied,
    /// Skipped (already applied in prior run).
    Skipped,
    /// Failed to apply.
    Failed,
    /// Blocked by identity mismatch.
    IdentityMismatch,
    /// Pending (not yet attempted).
    Pending,
}

/// Current system identity snapshot for one process (from /proc or equivalent).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrentIdentity {
    pub pid: u32,
    pub start_id: String,
    pub uid: u32,
    /// Whether the process is still alive.
    pub alive: bool,
}

/// Result of identity revalidation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevalidationResult {
    pub identity: RevalidationIdentity,
    pub valid: bool,
    pub reason: RevalidationOutcome,
}

/// Detailed revalidation outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevalidationOutcome {
    /// Identity matches — safe to proceed.
    Match,
    /// Process no longer exists.
    ProcessGone,
    /// PID exists but start_id differs (PID reuse detected).
    PidReused,
    /// PID exists, start_id matches, but UID changed (ownership change).
    UidChanged,
}

/// Execution plan state for resumability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionPlan {
    pub session_id: String,
    pub created_at: String,
    pub actions: Vec<PlannedAction>,
    pub log: Vec<ExecutionEntry>,
}

impl ExecutionPlan {
    /// Create a new execution plan.
    pub fn new(session_id: &str, actions: Vec<PlannedAction>) -> Self {
        Self {
            session_id: session_id.to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            actions,
            log: Vec::new(),
        }
    }

    /// Get the set of actions that have already been successfully applied.
    pub fn applied_set(&self) -> HashMap<RevalidationIdentity, &ExecutionEntry> {
        self.log
            .iter()
            .filter(|e| e.status == ExecutionStatus::Applied)
            .map(|e| (e.identity.clone(), e))
            .collect()
    }

    /// Get the list of pending actions (not yet applied or skipped).
    pub fn pending_actions(&self) -> Vec<&PlannedAction> {
        let applied = self.applied_set();
        self.actions
            .iter()
            .filter(|a| !applied.contains_key(&a.identity))
            .collect()
    }

    /// Record an execution entry.
    pub fn record(&mut self, entry: ExecutionEntry) {
        self.log.push(entry);
    }

    /// Check if all actions are complete (applied, skipped, or failed).
    pub fn is_complete(&self) -> bool {
        self.pending_actions().is_empty()
    }
}

// ---------------------------------------------------------------------------
// Revalidation
// ---------------------------------------------------------------------------

/// Revalidate a planned identity against current system state.
pub fn revalidate_identity(
    planned: &RevalidationIdentity,
    current: Option<&CurrentIdentity>,
) -> RevalidationResult {
    match current {
        None => RevalidationResult {
            identity: planned.clone(),
            valid: false,
            reason: RevalidationOutcome::ProcessGone,
        },
        Some(cur) => {
            if !cur.alive {
                return RevalidationResult {
                    identity: planned.clone(),
                    valid: false,
                    reason: RevalidationOutcome::ProcessGone,
                };
            }
            if cur.start_id != planned.start_id {
                return RevalidationResult {
                    identity: planned.clone(),
                    valid: false,
                    reason: RevalidationOutcome::PidReused,
                };
            }
            if cur.uid != planned.uid {
                return RevalidationResult {
                    identity: planned.clone(),
                    valid: false,
                    reason: RevalidationOutcome::UidChanged,
                };
            }
            RevalidationResult {
                identity: planned.clone(),
                valid: true,
                reason: RevalidationOutcome::Match,
            }
        }
    }
}

/// Resume result for the entire plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResumeResult {
    pub session_id: String,
    pub previously_applied: usize,
    pub newly_applied: usize,
    pub skipped_identity_mismatch: usize,
    pub skipped_process_gone: usize,
    pub failed: usize,
    pub entries: Vec<ExecutionEntry>,
}

/// Resume an execution plan, revalidating identities and executing pending actions.
///
/// The `execute_fn` callback performs the actual action and returns Ok(()) on success.
/// The `lookup_fn` retrieves the current system identity for a PID.
pub fn resume_plan<E, L>(
    plan: &mut ExecutionPlan,
    lookup_fn: L,
    mut execute_fn: E,
) -> ResumeResult
where
    E: FnMut(&PlannedAction) -> Result<(), String>,
    L: Fn(u32) -> Option<CurrentIdentity>,
{
    let previously_applied = plan.applied_set().len();
    let pending = plan.pending_actions().into_iter().cloned().collect::<Vec<_>>();

    let mut newly_applied = 0;
    let mut skipped_mismatch = 0;
    let mut skipped_gone = 0;
    let mut failed = 0;
    let mut entries = Vec::new();

    for action in &pending {
        let current = lookup_fn(action.identity.pid);
        let validation = revalidate_identity(&action.identity, current.as_ref());

        if !validation.valid {
            let status = match validation.reason {
                RevalidationOutcome::ProcessGone => {
                    skipped_gone += 1;
                    ExecutionStatus::Skipped
                }
                _ => {
                    skipped_mismatch += 1;
                    ExecutionStatus::IdentityMismatch
                }
            };
            let entry = ExecutionEntry {
                identity: action.identity.clone(),
                action: action.action.clone(),
                status,
                timestamp: chrono::Utc::now().to_rfc3339(),
                error: Some(format!("{:?}", validation.reason)),
            };
            entries.push(entry.clone());
            plan.record(entry);
            continue;
        }

        match execute_fn(action) {
            Ok(()) => {
                newly_applied += 1;
                let entry = ExecutionEntry {
                    identity: action.identity.clone(),
                    action: action.action.clone(),
                    status: ExecutionStatus::Applied,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    error: None,
                };
                entries.push(entry.clone());
                plan.record(entry);
            }
            Err(err) => {
                failed += 1;
                let entry = ExecutionEntry {
                    identity: action.identity.clone(),
                    action: action.action.clone(),
                    status: ExecutionStatus::Failed,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    error: Some(err),
                };
                entries.push(entry.clone());
                plan.record(entry);
            }
        }
    }

    ResumeResult {
        session_id: plan.session_id.clone(),
        previously_applied,
        newly_applied,
        skipped_identity_mismatch: skipped_mismatch,
        skipped_process_gone: skipped_gone,
        failed,
        entries,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn id(pid: u32) -> RevalidationIdentity {
        RevalidationIdentity {
            pid,
            start_id: format!("boot1:{}:{}", pid * 100, pid),
            uid: 1000,
        }
    }

    fn action(pid: u32) -> PlannedAction {
        PlannedAction {
            identity: id(pid),
            action: "kill".to_string(),
            expected_loss: 0.1,
            rationale: "test".to_string(),
        }
    }

    fn cur(pid: u32) -> CurrentIdentity {
        CurrentIdentity {
            pid,
            start_id: format!("boot1:{}:{}", pid * 100, pid),
            uid: 1000,
            alive: true,
        }
    }

    #[test]
    fn test_revalidate_match() {
        let planned = id(1);
        let current = cur(1);
        let result = revalidate_identity(&planned, Some(&current));
        assert!(result.valid);
        assert_eq!(result.reason, RevalidationOutcome::Match);
    }

    #[test]
    fn test_revalidate_process_gone() {
        let planned = id(1);
        let result = revalidate_identity(&planned, None);
        assert!(!result.valid);
        assert_eq!(result.reason, RevalidationOutcome::ProcessGone);
    }

    #[test]
    fn test_revalidate_pid_reused() {
        let planned = id(1);
        let mut current = cur(1);
        current.start_id = "boot2:999:1".to_string(); // Different start_id
        let result = revalidate_identity(&planned, Some(&current));
        assert!(!result.valid);
        assert_eq!(result.reason, RevalidationOutcome::PidReused);
    }

    #[test]
    fn test_revalidate_uid_changed() {
        let planned = id(1);
        let mut current = cur(1);
        current.uid = 2000;
        let result = revalidate_identity(&planned, Some(&current));
        assert!(!result.valid);
        assert_eq!(result.reason, RevalidationOutcome::UidChanged);
    }

    #[test]
    fn test_revalidate_dead_process() {
        let planned = id(1);
        let mut current = cur(1);
        current.alive = false;
        let result = revalidate_identity(&planned, Some(&current));
        assert!(!result.valid);
        assert_eq!(result.reason, RevalidationOutcome::ProcessGone);
    }

    #[test]
    fn test_execution_plan_pending() {
        let plan = ExecutionPlan::new("s1", vec![action(1), action(2), action(3)]);
        assert_eq!(plan.pending_actions().len(), 3);
        assert!(!plan.is_complete());
    }

    #[test]
    fn test_execution_plan_applied_skipped() {
        let mut plan = ExecutionPlan::new("s1", vec![action(1), action(2)]);
        plan.record(ExecutionEntry {
            identity: id(1),
            action: "kill".to_string(),
            status: ExecutionStatus::Applied,
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            error: None,
        });
        assert_eq!(plan.pending_actions().len(), 1);
        assert_eq!(plan.applied_set().len(), 1);
    }

    #[test]
    fn test_resume_all_valid() {
        let mut plan = ExecutionPlan::new("s1", vec![action(1), action(2)]);
        let result = resume_plan(
            &mut plan,
            |pid| Some(cur(pid)),
            |_action| Ok(()),
        );
        assert_eq!(result.newly_applied, 2);
        assert_eq!(result.previously_applied, 0);
        assert!(plan.is_complete());
    }

    #[test]
    fn test_resume_partial_then_complete() {
        let mut plan = ExecutionPlan::new("s1", vec![action(1), action(2), action(3)]);

        // First run: apply 1 and 2, simulate failure on 3.
        let _r1 = resume_plan(
            &mut plan,
            |pid| Some(cur(pid)),
            |a| if a.identity.pid == 3 { Err("oops".into()) } else { Ok(()) },
        );
        assert_eq!(plan.applied_set().len(), 2);

        // Second run: retry 3 successfully.
        let r2 = resume_plan(
            &mut plan,
            |pid| Some(cur(pid)),
            |_| Ok(()),
        );
        assert_eq!(r2.previously_applied, 2);
        assert_eq!(r2.newly_applied, 1);
    }

    #[test]
    fn test_resume_identity_mismatch_fails_closed() {
        let mut plan = ExecutionPlan::new("s1", vec![action(1)]);
        // Return a different start_id → PID reuse.
        let result = resume_plan(
            &mut plan,
            |_pid| Some(CurrentIdentity {
                pid: 1,
                start_id: "boot2:999:1".to_string(),
                uid: 1000,
                alive: true,
            }),
            |_| Ok(()),
        );
        assert_eq!(result.skipped_identity_mismatch, 1);
        assert_eq!(result.newly_applied, 0);
    }

    #[test]
    fn test_resume_process_gone() {
        let mut plan = ExecutionPlan::new("s1", vec![action(1)]);
        let result = resume_plan(&mut plan, |_| None, |_| Ok(()));
        assert_eq!(result.skipped_process_gone, 1);
        assert_eq!(result.newly_applied, 0);
    }

    #[test]
    fn test_resume_idempotent() {
        let mut plan = ExecutionPlan::new("s1", vec![action(1)]);
        let _r1 = resume_plan(&mut plan, |pid| Some(cur(pid)), |_| Ok(()));
        assert_eq!(plan.applied_set().len(), 1);

        // Resume again: nothing to do.
        let r2 = resume_plan(&mut plan, |pid| Some(cur(pid)), |_| Ok(()));
        assert_eq!(r2.previously_applied, 1);
        assert_eq!(r2.newly_applied, 0);
    }
}
