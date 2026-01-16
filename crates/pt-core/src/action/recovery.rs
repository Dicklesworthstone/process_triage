//! Failure recovery and retry planning for action execution.

use crate::decision::Action;
use serde::Serialize;

/// Failure classification for recovery decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    Transient,
    Permanent,
    Escalate,
}

/// Recovery decision returned by the planner.
#[derive(Debug, Clone, Serialize)]
pub struct RecoveryDecision {
    pub kind: FailureKind,
    pub retry_action: Option<Action>,
    pub delay_ms: Option<u64>,
    pub attempts_left: Option<u32>,
}

/// Retry policy for recovery planning.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    pub max_retries: u32,
    pub base_backoff_ms: u64,
    pub term_grace_ms: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 2,
            base_backoff_ms: 250,
            term_grace_ms: 5_000,
        }
    }
}

/// Action failure status from executor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionFailure {
    IdentityMismatch,
    PermissionDenied,
    Timeout,
    Failed,
}

/// Determine recovery decision based on failure, action, and attempt.
pub fn plan_recovery(
    action: Action,
    failure: ActionFailure,
    attempt: u32,
    policy: &RetryPolicy,
) -> RecoveryDecision {
    match failure {
        ActionFailure::IdentityMismatch | ActionFailure::PermissionDenied => RecoveryDecision {
            kind: FailureKind::Permanent,
            retry_action: None,
            delay_ms: None,
            attempts_left: None,
        },
        ActionFailure::Timeout => {
            if attempt >= policy.max_retries {
                RecoveryDecision {
                    kind: FailureKind::Permanent,
                    retry_action: None,
                    delay_ms: None,
                    attempts_left: Some(0),
                }
            } else {
                let delay = policy.base_backoff_ms.saturating_mul(2_u64.pow(attempt));
                RecoveryDecision {
                    kind: FailureKind::Transient,
                    retry_action: Some(action),
                    delay_ms: Some(delay),
                    attempts_left: Some(policy.max_retries - attempt),
                }
            }
        }
        ActionFailure::Failed => {
            if attempt >= policy.max_retries {
                RecoveryDecision {
                    kind: FailureKind::Permanent,
                    retry_action: None,
                    delay_ms: None,
                    attempts_left: Some(0),
                }
            } else {
                match action {
                    Action::Kill => RecoveryDecision {
                        kind: FailureKind::Escalate,
                        retry_action: Some(Action::Kill),
                        delay_ms: Some(policy.term_grace_ms),
                        attempts_left: Some(policy.max_retries.saturating_sub(attempt)),
                    },
                    _ => RecoveryDecision {
                        kind: FailureKind::Transient,
                        retry_action: Some(action),
                        delay_ms: Some(policy.base_backoff_ms),
                        attempts_left: Some(policy.max_retries.saturating_sub(attempt)),
                    },
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_denied_is_permanent() {
        let policy = RetryPolicy::default();
        let decision = plan_recovery(Action::Kill, ActionFailure::PermissionDenied, 0, &policy);
        assert_eq!(decision.kind, FailureKind::Permanent);
        assert!(decision.retry_action.is_none());
    }

    #[test]
    fn timeout_retries_with_backoff() {
        let policy = RetryPolicy::default();
        let decision = plan_recovery(Action::Pause, ActionFailure::Timeout, 0, &policy);
        assert_eq!(decision.kind, FailureKind::Transient);
        assert_eq!(decision.retry_action, Some(Action::Pause));
        assert_eq!(decision.delay_ms, Some(policy.base_backoff_ms));
    }

    #[test]
    fn kill_failure_escalates_with_grace() {
        let policy = RetryPolicy::default();
        let decision = plan_recovery(Action::Kill, ActionFailure::Failed, 0, &policy);
        assert_eq!(decision.kind, FailureKind::Escalate);
        assert_eq!(decision.retry_action, Some(Action::Kill));
        assert_eq!(decision.delay_ms, Some(policy.term_grace_ms));
    }

    #[test]
    fn failed_respects_max_retries() {
        let policy = RetryPolicy {
            max_retries: 2,
            ..Default::default()
        };
        // Attempt 3 (exceeds max_retries=2)
        let decision = plan_recovery(Action::Pause, ActionFailure::Failed, 3, &policy);
        assert_eq!(decision.kind, FailureKind::Permanent);
    }
}
