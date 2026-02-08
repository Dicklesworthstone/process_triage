//! Structured failure recovery trees for action execution.
//!
//! This module provides tree-based recovery strategies that offer deterministic
//! fallback paths when actions fail. Each action type has an associated recovery
//! tree that maps failure categories to ordered lists of alternatives.

use crate::decision::Action;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Extended failure categories for recovery decisions.
///
/// These categories are more granular than `ActionFailure` to enable
/// precise recovery tree branching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCategory {
    /// Insufficient privileges to perform action.
    PermissionDenied,
    /// Target process no longer exists (already dead or wrong target).
    ProcessNotFound,
    /// Kernel/system protection blocked the action.
    ProcessProtected,
    /// Action didn't complete within expected time.
    Timeout,
    /// Supervisor restarted the process after action.
    SupervisorConflict,
    /// Resource held by another process/system.
    ResourceConflict,
    /// Process identity changed (PID reuse / TOCTOU).
    IdentityMismatch,
    /// Action blocked by pre-check (data loss risk, session safety).
    PreCheckBlocked,
    /// Unknown or unanticipated failure.
    UnexpectedError,
}

impl std::fmt::Display for FailureCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FailureCategory::PermissionDenied => write!(f, "permission_denied"),
            FailureCategory::ProcessNotFound => write!(f, "process_not_found"),
            FailureCategory::ProcessProtected => write!(f, "process_protected"),
            FailureCategory::Timeout => write!(f, "timeout"),
            FailureCategory::SupervisorConflict => write!(f, "supervisor_conflict"),
            FailureCategory::ResourceConflict => write!(f, "resource_conflict"),
            FailureCategory::IdentityMismatch => write!(f, "identity_mismatch"),
            FailureCategory::PreCheckBlocked => write!(f, "pre_check_blocked"),
            FailureCategory::UnexpectedError => write!(f, "unexpected_error"),
        }
    }
}

/// A single recovery alternative with requirements and instructions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryAlternative {
    /// The alternative action to attempt.
    pub action: RecoveryAction,
    /// Human-readable explanation of this alternative.
    pub explanation: String,
    /// Requirements that must be met for this alternative.
    pub requirements: Vec<Requirement>,
    /// Whether this action is reversible.
    pub reversible: bool,
    /// Command hint for the user/agent (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_hint: Option<String>,
    /// Notes for the agent/user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// Types of recovery actions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryAction {
    /// Retry the same action.
    Retry,
    /// Retry with elevated privileges (sudo).
    RetryWithSudo,
    /// Escalate to a more forceful action.
    Escalate(Action),
    /// Stop the supervisor before retrying.
    StopSupervisor,
    /// Mask the supervisor unit and stop.
    MaskAndStop,
    /// Verify if the goal was achieved anyway.
    VerifyGoal,
    /// Check if a replacement process spawned.
    CheckRespawn,
    /// Investigate process state (D-state, etc.).
    Investigate,
    /// Report to user for manual intervention.
    EscalateToUser,
    /// Wait and retry after delay.
    WaitAndRetry { delay_ms: u64 },
    /// Skip this action (goal may be unachievable).
    Skip,
    /// Custom action with command.
    Custom { command: String },
}

/// Requirements for a recovery alternative.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Requirement {
    /// sudo must be available.
    SudoAvailable,
    /// Target process must still exist.
    ProcessExists,
    /// Process must be supervised by systemd.
    SystemdSupervised,
    /// Process must be supervised by docker.
    DockerSupervised,
    /// Process must be supervised by pm2.
    Pm2Supervised,
    /// Process is in D-state (uninterruptible sleep).
    InDState,
    /// Retry budget not exhausted.
    RetryBudgetAvailable,
    /// User confirmation required.
    UserConfirmation,
    /// Cgroup v2 available.
    CgroupV2Available,
}

/// A recovery branch for a specific failure category.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryBranch {
    /// Human-readable diagnosis of the failure.
    pub diagnosis: String,
    /// Ordered list of alternatives to try.
    pub alternatives: Vec<RecoveryAlternative>,
    /// Verification step after recovery (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification: Option<String>,
    /// Maximum attempts for this branch.
    pub max_attempts: u32,
}

/// A complete recovery tree for an action type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryTree {
    /// The action this tree applies to.
    pub action: Action,
    /// Recovery branches indexed by failure category.
    pub branches: HashMap<FailureCategory, RecoveryBranch>,
    /// Default branch for unmapped failures.
    pub default_branch: RecoveryBranch,
}

impl RecoveryTree {
    /// Get the recovery branch for a failure category.
    pub fn get_branch(&self, category: FailureCategory) -> &RecoveryBranch {
        self.branches.get(&category).unwrap_or(&self.default_branch)
    }

    /// Create the default recovery tree for Kill action.
    pub fn kill_tree() -> Self {
        let mut branches = HashMap::new();

        // Permission denied
        branches.insert(
            FailureCategory::PermissionDenied,
            RecoveryBranch {
                diagnosis: "Current user lacks permission to signal this process".to_string(),
                alternatives: vec![
                    RecoveryAlternative {
                        action: RecoveryAction::RetryWithSudo,
                        explanation: "Retry with elevated privileges".to_string(),
                        requirements: vec![Requirement::SudoAvailable],
                        reversible: false,
                        command_hint: Some("sudo kill -TERM <pid>".to_string()),
                        notes: None,
                    },
                    RecoveryAlternative {
                        action: RecoveryAction::EscalateToUser,
                        explanation: "Process owned by another user; requires elevated privileges"
                            .to_string(),
                        requirements: vec![],
                        reversible: true,
                        command_hint: None,
                        notes: Some("Manual intervention required".to_string()),
                    },
                ],
                verification: None,
                max_attempts: 2,
            },
        );

        // Process not found
        branches.insert(
            FailureCategory::ProcessNotFound,
            RecoveryBranch {
                diagnosis: "Process no longer exists".to_string(),
                alternatives: vec![
                    RecoveryAlternative {
                        action: RecoveryAction::VerifyGoal,
                        explanation: "Check if goal achieved (process may have exited naturally)"
                            .to_string(),
                        requirements: vec![],
                        reversible: true,
                        command_hint: Some("pt agent verify --session <id>".to_string()),
                        notes: None,
                    },
                    RecoveryAlternative {
                        action: RecoveryAction::CheckRespawn,
                        explanation: "If supervised, check if replacement spawned".to_string(),
                        requirements: vec![],
                        reversible: true,
                        command_hint: None,
                        notes: Some("Look for new PID with same command pattern".to_string()),
                    },
                ],
                verification: Some("Confirm no matching process exists".to_string()),
                max_attempts: 1,
            },
        );

        // Timeout
        branches.insert(
            FailureCategory::Timeout,
            RecoveryBranch {
                diagnosis: "Process did not terminate within grace period".to_string(),
                alternatives: vec![
                    RecoveryAlternative {
                        action: RecoveryAction::Escalate(Action::Kill),
                        explanation: "Escalate to SIGKILL".to_string(),
                        requirements: vec![Requirement::ProcessExists],
                        reversible: false,
                        command_hint: Some("kill -9 <pid>".to_string()),
                        notes: Some("SIGKILL cannot be caught or ignored".to_string()),
                    },
                    RecoveryAlternative {
                        action: RecoveryAction::Investigate,
                        explanation: "Process may be in uninterruptible sleep".to_string(),
                        requirements: vec![Requirement::InDState],
                        reversible: true,
                        command_hint: None,
                        notes: Some(
                            "D-state processes are waiting on I/O; check device/mount status"
                                .to_string(),
                        ),
                    },
                ],
                verification: Some("Verify process state changed".to_string()),
                max_attempts: 3,
            },
        );

        // Supervisor conflict
        branches.insert(
            FailureCategory::SupervisorConflict,
            RecoveryBranch {
                diagnosis: "Process was killed but immediately respawned by supervisor".to_string(),
                alternatives: vec![
                    RecoveryAlternative {
                        action: RecoveryAction::StopSupervisor,
                        explanation: "Stop the supervisor service".to_string(),
                        requirements: vec![Requirement::SystemdSupervised],
                        reversible: true,
                        command_hint: Some("systemctl stop <service>".to_string()),
                        notes: None,
                    },
                    RecoveryAlternative {
                        action: RecoveryAction::MaskAndStop,
                        explanation: "Mask unit to prevent auto-restart, then stop".to_string(),
                        requirements: vec![Requirement::SystemdSupervised],
                        reversible: true,
                        command_hint: Some(
                            "systemctl mask <service> && systemctl stop <service>".to_string(),
                        ),
                        notes: Some("Unmask with: systemctl unmask <service>".to_string()),
                    },
                    RecoveryAlternative {
                        action: RecoveryAction::Custom {
                            command: "docker stop <container>".to_string(),
                        },
                        explanation: "Stop the docker container".to_string(),
                        requirements: vec![Requirement::DockerSupervised],
                        reversible: true,
                        command_hint: Some("docker stop <container>".to_string()),
                        notes: None,
                    },
                    RecoveryAlternative {
                        action: RecoveryAction::Custom {
                            command: "pm2 stop <app>".to_string(),
                        },
                        explanation: "Stop the pm2 managed application".to_string(),
                        requirements: vec![Requirement::Pm2Supervised],
                        reversible: true,
                        command_hint: Some("pm2 stop <app>".to_string()),
                        notes: None,
                    },
                ],
                verification: Some("Verify process does not respawn".to_string()),
                max_attempts: 3,
            },
        );

        // Identity mismatch
        branches.insert(
            FailureCategory::IdentityMismatch,
            RecoveryBranch {
                diagnosis: "Process identity changed (possible PID reuse)".to_string(),
                alternatives: vec![RecoveryAlternative {
                    action: RecoveryAction::Skip,
                    explanation: "Target process is no longer the intended process; skip action"
                        .to_string(),
                    requirements: vec![],
                    reversible: true,
                    command_hint: None,
                    notes: Some(
                        "PID may have been recycled to a different process; verify target"
                            .to_string(),
                    ),
                }],
                verification: None,
                max_attempts: 1,
            },
        );

        // Pre-check blocked
        branches.insert(
            FailureCategory::PreCheckBlocked,
            RecoveryBranch {
                diagnosis: "Action blocked by safety pre-check".to_string(),
                alternatives: vec![RecoveryAlternative {
                    action: RecoveryAction::EscalateToUser,
                    explanation: "Safety check prevented action; user override required"
                        .to_string(),
                    requirements: vec![Requirement::UserConfirmation],
                    reversible: true,
                    command_hint: None,
                    notes: Some("Review pre-check reason before overriding".to_string()),
                }],
                verification: None,
                max_attempts: 1,
            },
        );

        let default_branch = RecoveryBranch {
            diagnosis: "Unexpected failure during action execution".to_string(),
            alternatives: vec![
                RecoveryAlternative {
                    action: RecoveryAction::WaitAndRetry { delay_ms: 1000 },
                    explanation: "Wait and retry the action".to_string(),
                    requirements: vec![Requirement::RetryBudgetAvailable],
                    reversible: true,
                    command_hint: None,
                    notes: None,
                },
                RecoveryAlternative {
                    action: RecoveryAction::EscalateToUser,
                    explanation: "Report failure to user for investigation".to_string(),
                    requirements: vec![],
                    reversible: true,
                    command_hint: None,
                    notes: None,
                },
            ],
            verification: None,
            max_attempts: 2,
        };

        Self {
            action: Action::Kill,
            branches,
            default_branch,
        }
    }

    /// Create the default recovery tree for Pause action.
    pub fn pause_tree() -> Self {
        let mut branches = HashMap::new();

        // Permission denied
        branches.insert(
            FailureCategory::PermissionDenied,
            RecoveryBranch {
                diagnosis: "Current user lacks permission to pause this process".to_string(),
                alternatives: vec![
                    RecoveryAlternative {
                        action: RecoveryAction::RetryWithSudo,
                        explanation: "Retry with elevated privileges".to_string(),
                        requirements: vec![Requirement::SudoAvailable],
                        reversible: true,
                        command_hint: Some("sudo kill -STOP <pid>".to_string()),
                        notes: None,
                    },
                    RecoveryAlternative {
                        action: RecoveryAction::EscalateToUser,
                        explanation: "Process owned by another user".to_string(),
                        requirements: vec![],
                        reversible: true,
                        command_hint: None,
                        notes: None,
                    },
                ],
                verification: None,
                max_attempts: 2,
            },
        );

        // Process not found
        branches.insert(
            FailureCategory::ProcessNotFound,
            RecoveryBranch {
                diagnosis: "Process no longer exists".to_string(),
                alternatives: vec![RecoveryAlternative {
                    action: RecoveryAction::VerifyGoal,
                    explanation: "Process may have already terminated".to_string(),
                    requirements: vec![],
                    reversible: true,
                    command_hint: None,
                    notes: None,
                }],
                verification: None,
                max_attempts: 1,
            },
        );

        // Timeout
        branches.insert(
            FailureCategory::Timeout,
            RecoveryBranch {
                diagnosis: "Pause signal did not take effect in time".to_string(),
                alternatives: vec![RecoveryAlternative {
                    action: RecoveryAction::Retry,
                    explanation: "Retry pause operation".to_string(),
                    requirements: vec![
                        Requirement::ProcessExists,
                        Requirement::RetryBudgetAvailable,
                    ],
                    reversible: true,
                    command_hint: None,
                    notes: Some("Process may be in a critical section".to_string()),
                }],
                verification: Some("Verify process state is 'T' (stopped)".to_string()),
                max_attempts: 3,
            },
        );

        // Identity mismatch
        branches.insert(
            FailureCategory::IdentityMismatch,
            RecoveryBranch {
                diagnosis: "Process identity changed".to_string(),
                alternatives: vec![RecoveryAlternative {
                    action: RecoveryAction::Skip,
                    explanation: "Skip to avoid pausing wrong process".to_string(),
                    requirements: vec![],
                    reversible: true,
                    command_hint: None,
                    notes: None,
                }],
                verification: None,
                max_attempts: 1,
            },
        );

        let default_branch = RecoveryBranch {
            diagnosis: "Unexpected failure during pause".to_string(),
            alternatives: vec![RecoveryAlternative {
                action: RecoveryAction::WaitAndRetry { delay_ms: 500 },
                explanation: "Wait and retry".to_string(),
                requirements: vec![Requirement::RetryBudgetAvailable],
                reversible: true,
                command_hint: None,
                notes: None,
            }],
            verification: None,
            max_attempts: 2,
        };

        Self {
            action: Action::Pause,
            branches,
            default_branch,
        }
    }

    /// Create the default recovery tree for Renice action.
    pub fn renice_tree() -> Self {
        let mut branches = HashMap::new();

        // Permission denied
        branches.insert(
            FailureCategory::PermissionDenied,
            RecoveryBranch {
                diagnosis: "Insufficient privileges to change process priority".to_string(),
                alternatives: vec![
                    RecoveryAlternative {
                        action: RecoveryAction::RetryWithSudo,
                        explanation: "Retry with elevated privileges".to_string(),
                        requirements: vec![Requirement::SudoAvailable],
                        reversible: true,
                        command_hint: Some("sudo renice <priority> -p <pid>".to_string()),
                        notes: Some("Only root can lower nice values".to_string()),
                    },
                    RecoveryAlternative {
                        action: RecoveryAction::Escalate(Action::Pause),
                        explanation: "Fall back to pausing the process instead".to_string(),
                        requirements: vec![Requirement::ProcessExists],
                        reversible: true,
                        command_hint: None,
                        notes: Some("Pause is more aggressive than renice".to_string()),
                    },
                ],
                verification: None,
                max_attempts: 2,
            },
        );

        // Resource conflict (cgroup limits)
        branches.insert(
            FailureCategory::ResourceConflict,
            RecoveryBranch {
                diagnosis: "Process priority constrained by cgroup limits".to_string(),
                alternatives: vec![RecoveryAlternative {
                    action: RecoveryAction::EscalateToUser,
                    explanation: "Cgroup configuration prevents priority change".to_string(),
                    requirements: vec![],
                    reversible: true,
                    command_hint: None,
                    notes: Some("May need to modify cgroup cpu.weight settings".to_string()),
                }],
                verification: None,
                max_attempts: 1,
            },
        );

        // Process not found
        branches.insert(
            FailureCategory::ProcessNotFound,
            RecoveryBranch {
                diagnosis: "Process no longer exists".to_string(),
                alternatives: vec![RecoveryAlternative {
                    action: RecoveryAction::VerifyGoal,
                    explanation: "Process may have already terminated".to_string(),
                    requirements: vec![],
                    reversible: true,
                    command_hint: None,
                    notes: None,
                }],
                verification: None,
                max_attempts: 1,
            },
        );

        let default_branch = RecoveryBranch {
            diagnosis: "Unexpected failure during renice".to_string(),
            alternatives: vec![RecoveryAlternative {
                action: RecoveryAction::WaitAndRetry { delay_ms: 250 },
                explanation: "Wait and retry".to_string(),
                requirements: vec![Requirement::RetryBudgetAvailable],
                reversible: true,
                command_hint: None,
                notes: None,
            }],
            verification: None,
            max_attempts: 2,
        };

        Self {
            action: Action::Renice,
            branches,
            default_branch,
        }
    }

    /// Create the default recovery tree for Throttle action.
    pub fn throttle_tree() -> Self {
        let mut branches = HashMap::new();

        // Permission denied
        branches.insert(
            FailureCategory::PermissionDenied,
            RecoveryBranch {
                diagnosis: "Insufficient privileges to modify cgroup settings".to_string(),
                alternatives: vec![
                    RecoveryAlternative {
                        action: RecoveryAction::RetryWithSudo,
                        explanation: "Retry with elevated privileges".to_string(),
                        requirements: vec![Requirement::SudoAvailable],
                        reversible: true,
                        command_hint: None,
                        notes: Some("Cgroup operations typically require root".to_string()),
                    },
                    RecoveryAlternative {
                        action: RecoveryAction::Escalate(Action::Renice),
                        explanation: "Fall back to renice (less effective but lower privilege)"
                            .to_string(),
                        requirements: vec![Requirement::ProcessExists],
                        reversible: true,
                        command_hint: None,
                        notes: None,
                    },
                ],
                verification: None,
                max_attempts: 2,
            },
        );

        // Resource conflict
        branches.insert(
            FailureCategory::ResourceConflict,
            RecoveryBranch {
                diagnosis: "Cgroup v2 not available or hierarchy conflict".to_string(),
                alternatives: vec![
                    RecoveryAlternative {
                        action: RecoveryAction::Escalate(Action::Renice),
                        explanation: "Fall back to renice".to_string(),
                        requirements: vec![Requirement::ProcessExists],
                        reversible: true,
                        command_hint: None,
                        notes: None,
                    },
                    RecoveryAlternative {
                        action: RecoveryAction::Escalate(Action::Pause),
                        explanation: "Fall back to pause".to_string(),
                        requirements: vec![Requirement::ProcessExists],
                        reversible: true,
                        command_hint: None,
                        notes: None,
                    },
                ],
                verification: None,
                max_attempts: 2,
            },
        );

        let default_branch = RecoveryBranch {
            diagnosis: "Unexpected failure during throttle".to_string(),
            alternatives: vec![RecoveryAlternative {
                action: RecoveryAction::Escalate(Action::Renice),
                explanation: "Fall back to renice".to_string(),
                requirements: vec![Requirement::ProcessExists],
                reversible: true,
                command_hint: None,
                notes: None,
            }],
            verification: None,
            max_attempts: 2,
        };

        Self {
            action: Action::Throttle,
            branches,
            default_branch,
        }
    }

    /// Create the default recovery tree for Restart action.
    pub fn restart_tree() -> Self {
        let mut branches = HashMap::new();

        // Permission denied
        branches.insert(
            FailureCategory::PermissionDenied,
            RecoveryBranch {
                diagnosis: "Insufficient privileges to restart service".to_string(),
                alternatives: vec![RecoveryAlternative {
                    action: RecoveryAction::RetryWithSudo,
                    explanation: "Retry with elevated privileges".to_string(),
                    requirements: vec![Requirement::SudoAvailable],
                    reversible: true,
                    command_hint: Some("sudo systemctl restart <service>".to_string()),
                    notes: None,
                }],
                verification: None,
                max_attempts: 2,
            },
        );

        // Supervisor conflict (already restarting)
        branches.insert(
            FailureCategory::SupervisorConflict,
            RecoveryBranch {
                diagnosis: "Service is in a conflicting state (starting/stopping)".to_string(),
                alternatives: vec![RecoveryAlternative {
                    action: RecoveryAction::WaitAndRetry { delay_ms: 5000 },
                    explanation: "Wait for service state to stabilize".to_string(),
                    requirements: vec![Requirement::RetryBudgetAvailable],
                    reversible: true,
                    command_hint: None,
                    notes: Some("Service may be in StartPre/StopPost phases".to_string()),
                }],
                verification: Some("Verify service reached active state".to_string()),
                max_attempts: 3,
            },
        );

        // Process not found (service doesn't exist)
        branches.insert(
            FailureCategory::ProcessNotFound,
            RecoveryBranch {
                diagnosis: "Service unit not found".to_string(),
                alternatives: vec![RecoveryAlternative {
                    action: RecoveryAction::EscalateToUser,
                    explanation: "Service may need to be created or installed".to_string(),
                    requirements: vec![],
                    reversible: true,
                    command_hint: None,
                    notes: None,
                }],
                verification: None,
                max_attempts: 1,
            },
        );

        let default_branch = RecoveryBranch {
            diagnosis: "Unexpected failure during restart".to_string(),
            alternatives: vec![RecoveryAlternative {
                action: RecoveryAction::WaitAndRetry { delay_ms: 2000 },
                explanation: "Wait and retry".to_string(),
                requirements: vec![Requirement::RetryBudgetAvailable],
                reversible: true,
                command_hint: None,
                notes: None,
            }],
            verification: None,
            max_attempts: 3,
        };

        Self {
            action: Action::Restart,
            branches,
            default_branch,
        }
    }
}

/// Recovery hint included in action results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryHint {
    /// The recommended recovery action.
    pub recommended_action: RecoveryAction,
    /// Human-readable explanation.
    pub explanation: String,
    /// How to reverse this action (if reversible).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reversibility: Option<String>,
    /// Suggested next step for the agent.
    pub agent_next_step: String,
}

/// Action attempt record for audit trail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionAttempt {
    /// The action attempted.
    pub action: Action,
    /// The result of the attempt.
    pub result: AttemptResult,
    /// Duration in milliseconds.
    pub time_ms: u64,
    /// Attempt number (1-indexed).
    pub attempt_number: u32,
}

/// Result of an action attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptResult {
    Success,
    Failed { category: FailureCategory },
    ProcessRespawned,
    Skipped { reason: String },
}

/// Database of recovery trees for all action types.
#[derive(Debug, Clone)]
pub struct RecoveryTreeDatabase {
    trees: HashMap<Action, RecoveryTree>,
}

impl Default for RecoveryTreeDatabase {
    fn default() -> Self {
        Self::new()
    }
}

impl RecoveryTreeDatabase {
    /// Create a new database with default recovery trees.
    pub fn new() -> Self {
        let mut trees = HashMap::new();
        trees.insert(Action::Kill, RecoveryTree::kill_tree());
        trees.insert(Action::Pause, RecoveryTree::pause_tree());
        trees.insert(Action::Renice, RecoveryTree::renice_tree());
        trees.insert(Action::Throttle, RecoveryTree::throttle_tree());
        trees.insert(Action::Restart, RecoveryTree::restart_tree());
        Self { trees }
    }

    /// Get the recovery tree for an action.
    pub fn get_tree(&self, action: Action) -> Option<&RecoveryTree> {
        self.trees.get(&action)
    }

    /// Look up recovery branch for an action and failure category.
    pub fn lookup(&self, action: Action, category: FailureCategory) -> Option<&RecoveryBranch> {
        self.trees.get(&action).map(|t| t.get_branch(category))
    }
}

/// Context for checking requirements.
#[derive(Debug, Clone, Default)]
pub struct RequirementContext {
    /// Whether sudo is available on this system.
    pub sudo_available: bool,
    /// Whether the target process still exists.
    pub process_exists: bool,
    /// Whether the process is supervised by systemd.
    pub systemd_supervised: bool,
    /// Whether the process is supervised by docker.
    pub docker_supervised: bool,
    /// Whether the process is supervised by pm2.
    pub pm2_supervised: bool,
    /// Whether the process is in D-state.
    pub in_d_state: bool,
    /// Current retry budget remaining.
    pub retry_budget: u32,
    /// Whether user confirmation is available (interactive mode).
    pub user_confirmation_available: bool,
    /// Whether cgroup v2 is available.
    pub cgroup_v2_available: bool,
}

impl RequirementContext {
    /// Check if a requirement is met.
    pub fn is_met(&self, requirement: &Requirement) -> bool {
        match requirement {
            Requirement::SudoAvailable => self.sudo_available,
            Requirement::ProcessExists => self.process_exists,
            Requirement::SystemdSupervised => self.systemd_supervised,
            Requirement::DockerSupervised => self.docker_supervised,
            Requirement::Pm2Supervised => self.pm2_supervised,
            Requirement::InDState => self.in_d_state,
            Requirement::RetryBudgetAvailable => self.retry_budget > 0,
            Requirement::UserConfirmation => self.user_confirmation_available,
            Requirement::CgroupV2Available => self.cgroup_v2_available,
        }
    }

    /// Check if all requirements in a list are met.
    pub fn all_met(&self, requirements: &[Requirement]) -> bool {
        requirements.iter().all(|r| self.is_met(r))
    }

    /// Consume one retry from the budget.
    pub fn consume_retry(&mut self) {
        self.retry_budget = self.retry_budget.saturating_sub(1);
    }
}

/// Trait for checking requirements against the live system.
pub trait RequirementChecker: std::fmt::Debug {
    /// Build a requirement context for a given process.
    fn build_context(&self, pid: u32) -> RequirementContext;

    /// Check if sudo is available.
    fn check_sudo_available(&self) -> bool;

    /// Check if a process exists.
    fn check_process_exists(&self, pid: u32) -> bool;

    /// Check if a process is in D-state.
    fn check_in_d_state(&self, pid: u32) -> bool;

    /// Check if cgroup v2 is available.
    fn check_cgroup_v2_available(&self) -> bool;
}

/// No-op requirement checker for testing.
#[derive(Debug, Default)]
pub struct NoopRequirementChecker {
    /// Default context to return.
    pub default_context: RequirementContext,
}

impl RequirementChecker for NoopRequirementChecker {
    fn build_context(&self, _pid: u32) -> RequirementContext {
        self.default_context.clone()
    }

    fn check_sudo_available(&self) -> bool {
        self.default_context.sudo_available
    }

    fn check_process_exists(&self, _pid: u32) -> bool {
        self.default_context.process_exists
    }

    fn check_in_d_state(&self, _pid: u32) -> bool {
        self.default_context.in_d_state
    }

    fn check_cgroup_v2_available(&self) -> bool {
        self.default_context.cgroup_v2_available
    }
}

/// Live requirement checker that queries the system.
#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
pub struct LiveRequirementChecker {
    /// Cached sudo availability (checked once).
    sudo_available: std::cell::OnceCell<bool>,
    /// Cached cgroup v2 availability.
    cgroup_v2_available: std::cell::OnceCell<bool>,
}

#[cfg(target_os = "linux")]
impl LiveRequirementChecker {
    pub fn new() -> Self {
        Self {
            sudo_available: std::cell::OnceCell::new(),
            cgroup_v2_available: std::cell::OnceCell::new(),
        }
    }

    fn read_proc_stat(&self, pid: u32) -> Option<char> {
        use std::fs;
        let path = format!("/proc/{}/stat", pid);
        let content = fs::read_to_string(&path).ok()?;
        // Parse state from stat file: pid (comm) state ...
        // Find the last ')' to handle commands with parentheses
        let after_comm = content.rfind(')')? + 1;
        let rest = content.get(after_comm..)?.trim_start();
        rest.chars().next()
    }
}

#[cfg(target_os = "linux")]
impl RequirementChecker for LiveRequirementChecker {
    fn build_context(&self, pid: u32) -> RequirementContext {
        RequirementContext {
            sudo_available: self.check_sudo_available(),
            process_exists: self.check_process_exists(pid),
            systemd_supervised: false, // TODO: integrate with supervision detection
            docker_supervised: false,  // TODO: integrate with supervision detection
            pm2_supervised: false,     // TODO: integrate with supervision detection
            in_d_state: self.check_in_d_state(pid),
            retry_budget: 3, // Default budget
            user_confirmation_available: false,
            cgroup_v2_available: self.check_cgroup_v2_available(),
        }
    }

    fn check_sudo_available(&self) -> bool {
        *self.sudo_available.get_or_init(|| {
            std::process::Command::new("sudo")
                .arg("-n")
                .arg("true")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        })
    }

    fn check_process_exists(&self, pid: u32) -> bool {
        std::path::Path::new(&format!("/proc/{}", pid)).exists()
    }

    fn check_in_d_state(&self, pid: u32) -> bool {
        self.read_proc_stat(pid).map(|s| s == 'D').unwrap_or(false)
    }

    fn check_cgroup_v2_available(&self) -> bool {
        *self
            .cgroup_v2_available
            .get_or_init(|| std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists())
    }
}

/// Session tracking for recovery attempts per target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverySession {
    /// Target process identity (PID + start_id for uniqueness).
    pub target_pid: u32,
    pub target_start_id: Option<String>,
    /// All attempts made during this session.
    pub attempts: Vec<ActionAttempt>,
    /// Current retry budget for each failure category.
    pub budgets: HashMap<FailureCategory, u32>,
    /// Maximum total attempts across all categories.
    pub max_total_attempts: u32,
    /// Current total attempts.
    pub total_attempts: u32,
}

impl RecoverySession {
    /// Create a new recovery session for a target.
    pub fn new(target_pid: u32, target_start_id: Option<String>, max_total_attempts: u32) -> Self {
        Self {
            target_pid,
            target_start_id,
            attempts: Vec::new(),
            budgets: HashMap::new(),
            max_total_attempts,
            total_attempts: 0,
        }
    }

    /// Record an attempt.
    pub fn record_attempt(&mut self, attempt: ActionAttempt) {
        self.total_attempts += 1;
        self.attempts.push(attempt);
    }

    /// Check if the retry budget is exhausted for a category.
    pub fn is_budget_exhausted(&self, category: FailureCategory, max_for_category: u32) -> bool {
        let used = self.budgets.get(&category).copied().unwrap_or(0);
        used >= max_for_category || self.total_attempts >= self.max_total_attempts
    }

    /// Consume one attempt from a category's budget.
    pub fn consume_budget(&mut self, category: FailureCategory) {
        *self.budgets.entry(category).or_insert(0) += 1;
    }

    /// Get the number of attempts for a specific category.
    pub fn attempts_for_category(&self, category: FailureCategory) -> u32 {
        self.budgets.get(&category).copied().unwrap_or(0)
    }

    /// Get all attempts as a slice.
    pub fn all_attempts(&self) -> &[ActionAttempt] {
        &self.attempts
    }

    /// Check if any attempts have been made.
    pub fn has_attempts(&self) -> bool {
        !self.attempts.is_empty()
    }
}

/// Result of a recovery attempt.
#[derive(Debug, Clone, Serialize)]
pub struct RecoveryOutcome {
    /// The action that was attempted.
    pub attempted_action: RecoveryAction,
    /// Whether recovery succeeded.
    pub success: bool,
    /// The result of the attempt.
    pub result: AttemptResult,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    /// Explanation of what happened.
    pub explanation: String,
    /// Next recommended step (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_step: Option<RecoveryAction>,
}

/// Recovery executor that walks recovery trees and attempts alternatives.
#[derive(Debug)]
pub struct RecoveryExecutor<'a> {
    /// Database of recovery trees.
    database: &'a RecoveryTreeDatabase,
    /// Requirement checker.
    checker: &'a dyn RequirementChecker,
    /// Default maximum total attempts per session.
    pub max_total_attempts: u32,
}

impl<'a> RecoveryExecutor<'a> {
    /// Create a new recovery executor.
    pub fn new(database: &'a RecoveryTreeDatabase, checker: &'a dyn RequirementChecker) -> Self {
        Self {
            database,
            checker,
            max_total_attempts: 5,
        }
    }

    /// Set the maximum total attempts.
    pub fn with_max_attempts(mut self, max: u32) -> Self {
        self.max_total_attempts = max;
        self
    }

    /// Find viable alternatives for a failure.
    pub fn find_alternatives(
        &self,
        action: Action,
        category: FailureCategory,
        pid: u32,
        session: &RecoverySession,
    ) -> Vec<&RecoveryAlternative> {
        let context = self.checker.build_context(pid);

        // Get the recovery branch
        let branch = match self.database.lookup(action, category) {
            Some(b) => b,
            None => return vec![],
        };

        // Check if budget is exhausted
        if session.is_budget_exhausted(category, branch.max_attempts) {
            return vec![];
        }

        // Filter to alternatives with met requirements
        branch
            .alternatives
            .iter()
            .filter(|alt| context.all_met(&alt.requirements))
            .collect()
    }

    /// Get the best (first viable) alternative for a failure.
    pub fn get_best_alternative(
        &self,
        action: Action,
        category: FailureCategory,
        pid: u32,
        session: &RecoverySession,
    ) -> Option<&RecoveryAlternative> {
        self.find_alternatives(action, category, pid, session)
            .into_iter()
            .next()
    }

    /// Generate a recovery hint for output.
    pub fn generate_hint(
        &self,
        action: Action,
        category: FailureCategory,
        pid: u32,
        session: &RecoverySession,
    ) -> Option<RecoveryHint> {
        let branch = self.database.lookup(action, category)?;
        let alternative = self.get_best_alternative(action, category, pid, session)?;

        Some(RecoveryHint {
            recommended_action: alternative.action.clone(),
            explanation: alternative.explanation.clone(),
            reversibility: if alternative.reversible {
                alternative.notes.clone()
            } else {
                Some("This action is not reversible".to_string())
            },
            agent_next_step: format!(
                "{}; diagnosis: {}",
                alternative
                    .command_hint
                    .as_deref()
                    .unwrap_or("Investigate further"),
                branch.diagnosis
            ),
        })
    }

    /// Create a new recovery session for a target.
    pub fn create_session(&self, pid: u32, start_id: Option<String>) -> RecoverySession {
        RecoverySession::new(pid, start_id, self.max_total_attempts)
    }

    /// Classify a failure from ActionError-like inputs.
    pub fn classify_failure(&self, error_kind: &str, pid: u32, respawned: bool) -> FailureCategory {
        if respawned {
            return FailureCategory::SupervisorConflict;
        }

        match error_kind {
            "permission_denied" | "PermissionDenied" => FailureCategory::PermissionDenied,
            "not_found" | "ProcessNotFound" | "NotFound" => FailureCategory::ProcessNotFound,
            "protected" | "ProcessProtected" => FailureCategory::ProcessProtected,
            "timeout" | "Timeout" => FailureCategory::Timeout,
            "identity_mismatch" | "IdentityMismatch" => FailureCategory::IdentityMismatch,
            "pre_check_blocked" | "PreCheckBlocked" => FailureCategory::PreCheckBlocked,
            "resource_conflict" | "ResourceConflict" => FailureCategory::ResourceConflict,
            _ => {
                // Check if process is in D-state for timeout-like failures
                if self.checker.check_in_d_state(pid) {
                    FailureCategory::Timeout
                } else {
                    FailureCategory::UnexpectedError
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kill_tree_has_permission_denied_branch() {
        let tree = RecoveryTree::kill_tree();
        let branch = tree.get_branch(FailureCategory::PermissionDenied);
        assert!(!branch.alternatives.is_empty());
        assert_eq!(branch.alternatives[0].action, RecoveryAction::RetryWithSudo);
    }

    #[test]
    fn test_kill_tree_timeout_escalates() {
        let tree = RecoveryTree::kill_tree();
        let branch = tree.get_branch(FailureCategory::Timeout);
        assert!(matches!(
            branch.alternatives[0].action,
            RecoveryAction::Escalate(Action::Kill)
        ));
    }

    #[test]
    fn test_kill_tree_supervisor_conflict() {
        let tree = RecoveryTree::kill_tree();
        let branch = tree.get_branch(FailureCategory::SupervisorConflict);
        assert_eq!(
            branch.alternatives[0].action,
            RecoveryAction::StopSupervisor
        );
    }

    #[test]
    fn test_database_has_all_action_trees() {
        let db = RecoveryTreeDatabase::new();
        assert!(db.get_tree(Action::Kill).is_some());
        assert!(db.get_tree(Action::Pause).is_some());
        assert!(db.get_tree(Action::Renice).is_some());
        assert!(db.get_tree(Action::Throttle).is_some());
        assert!(db.get_tree(Action::Restart).is_some());
        // Keep doesn't need recovery
        assert!(db.get_tree(Action::Keep).is_none());
    }

    #[test]
    fn test_lookup_returns_default_for_unknown_category() {
        let db = RecoveryTreeDatabase::new();
        let branch = db.lookup(Action::Kill, FailureCategory::UnexpectedError);
        assert!(branch.is_some());
        assert!(!branch.unwrap().alternatives.is_empty());
    }

    #[test]
    fn test_pause_tree_identity_mismatch_skips() {
        let tree = RecoveryTree::pause_tree();
        let branch = tree.get_branch(FailureCategory::IdentityMismatch);
        assert_eq!(branch.alternatives[0].action, RecoveryAction::Skip);
    }

    #[test]
    fn test_throttle_falls_back_to_renice() {
        let tree = RecoveryTree::throttle_tree();
        let branch = tree.get_branch(FailureCategory::ResourceConflict);
        assert!(matches!(
            branch.alternatives[0].action,
            RecoveryAction::Escalate(Action::Renice)
        ));
    }

    #[test]
    fn test_failure_category_display() {
        assert_eq!(
            FailureCategory::PermissionDenied.to_string(),
            "permission_denied"
        );
        assert_eq!(
            FailureCategory::SupervisorConflict.to_string(),
            "supervisor_conflict"
        );
    }

    #[test]
    fn test_recovery_tree_serialization() {
        let tree = RecoveryTree::kill_tree();
        let json = serde_json::to_string(&tree).expect("serialize");
        assert!(json.contains("permission_denied"));
        assert!(json.contains("supervisor_conflict"));
    }

    // Tests for RequirementContext
    #[test]
    fn test_requirement_context_is_met() {
        let context = RequirementContext {
            sudo_available: true,
            process_exists: true,
            retry_budget: 3,
            ..Default::default()
        };
        assert!(context.is_met(&Requirement::SudoAvailable));
        assert!(context.is_met(&Requirement::ProcessExists));
        assert!(context.is_met(&Requirement::RetryBudgetAvailable));
        assert!(!context.is_met(&Requirement::InDState));
    }

    #[test]
    fn test_requirement_context_all_met() {
        let context = RequirementContext {
            sudo_available: true,
            process_exists: true,
            retry_budget: 3,
            ..Default::default()
        };
        assert!(context.all_met(&[Requirement::SudoAvailable, Requirement::ProcessExists]));
        assert!(!context.all_met(&[Requirement::SudoAvailable, Requirement::InDState]));
        assert!(context.all_met(&[])); // Empty requirements always pass
    }

    #[test]
    fn test_requirement_context_consume_retry() {
        let mut context = RequirementContext {
            retry_budget: 3,
            ..Default::default()
        };
        context.consume_retry();
        assert_eq!(context.retry_budget, 2);
        context.consume_retry();
        context.consume_retry();
        assert_eq!(context.retry_budget, 0);
        context.consume_retry(); // Should saturate at 0
        assert_eq!(context.retry_budget, 0);
    }

    // Tests for RecoverySession
    #[test]
    fn test_recovery_session_new() {
        let session = RecoverySession::new(1234, Some("boot:1:1234".to_string()), 5);
        assert_eq!(session.target_pid, 1234);
        assert_eq!(session.target_start_id, Some("boot:1:1234".to_string()));
        assert_eq!(session.max_total_attempts, 5);
        assert_eq!(session.total_attempts, 0);
        assert!(!session.has_attempts());
    }

    #[test]
    fn test_recovery_session_record_attempt() {
        let mut session = RecoverySession::new(1234, None, 5);
        session.record_attempt(ActionAttempt {
            action: Action::Kill,
            result: AttemptResult::Failed {
                category: FailureCategory::PermissionDenied,
            },
            time_ms: 100,
            attempt_number: 1,
        });
        assert!(session.has_attempts());
        assert_eq!(session.total_attempts, 1);
        assert_eq!(session.all_attempts().len(), 1);
    }

    #[test]
    fn test_recovery_session_budget_tracking() {
        let mut session = RecoverySession::new(1234, None, 5);

        // Initial budget is not exhausted
        assert!(!session.is_budget_exhausted(FailureCategory::Timeout, 3));

        // Consume budget
        session.consume_budget(FailureCategory::Timeout);
        session.consume_budget(FailureCategory::Timeout);
        assert_eq!(session.attempts_for_category(FailureCategory::Timeout), 2);

        // Different categories are tracked separately
        assert_eq!(
            session.attempts_for_category(FailureCategory::PermissionDenied),
            0
        );

        // Exhaust budget
        session.consume_budget(FailureCategory::Timeout);
        assert!(session.is_budget_exhausted(FailureCategory::Timeout, 3));
    }

    #[test]
    fn test_recovery_session_total_attempts_limit() {
        let mut session = RecoverySession::new(1234, None, 3);
        session.consume_budget(FailureCategory::Timeout);
        session.record_attempt(ActionAttempt {
            action: Action::Kill,
            result: AttemptResult::Failed {
                category: FailureCategory::Timeout,
            },
            time_ms: 100,
            attempt_number: 1,
        });
        session.record_attempt(ActionAttempt {
            action: Action::Kill,
            result: AttemptResult::Failed {
                category: FailureCategory::Timeout,
            },
            time_ms: 100,
            attempt_number: 2,
        });
        session.record_attempt(ActionAttempt {
            action: Action::Kill,
            result: AttemptResult::Failed {
                category: FailureCategory::Timeout,
            },
            time_ms: 100,
            attempt_number: 3,
        });
        // Total attempts exhausted even if category budget isn't
        assert!(session.is_budget_exhausted(FailureCategory::PermissionDenied, 10));
    }

    // Tests for NoopRequirementChecker
    #[test]
    fn test_noop_requirement_checker() {
        let checker = NoopRequirementChecker {
            default_context: RequirementContext {
                sudo_available: true,
                process_exists: true,
                ..Default::default()
            },
        };
        assert!(checker.check_sudo_available());
        assert!(checker.check_process_exists(1234));
        assert!(!checker.check_in_d_state(1234));
        assert!(!checker.check_cgroup_v2_available());
    }

    // Tests for RecoveryExecutor
    #[test]
    fn test_recovery_executor_find_alternatives() {
        let db = RecoveryTreeDatabase::new();
        let checker = NoopRequirementChecker {
            default_context: RequirementContext {
                sudo_available: true,
                process_exists: true,
                retry_budget: 3,
                ..Default::default()
            },
        };
        let executor = RecoveryExecutor::new(&db, &checker);
        let session = executor.create_session(1234, None);

        // Should find RetryWithSudo for permission denied
        let alts = executor.find_alternatives(
            Action::Kill,
            FailureCategory::PermissionDenied,
            1234,
            &session,
        );
        assert!(!alts.is_empty());
        assert_eq!(alts[0].action, RecoveryAction::RetryWithSudo);
    }

    #[test]
    fn test_recovery_executor_no_alternatives_without_requirements() {
        let db = RecoveryTreeDatabase::new();
        let checker = NoopRequirementChecker {
            default_context: RequirementContext {
                sudo_available: false, // sudo not available
                process_exists: true,
                retry_budget: 3,
                ..Default::default()
            },
        };
        let executor = RecoveryExecutor::new(&db, &checker);
        let session = executor.create_session(1234, None);

        // Should only find EscalateToUser (no sudo requirement)
        let alts = executor.find_alternatives(
            Action::Kill,
            FailureCategory::PermissionDenied,
            1234,
            &session,
        );
        assert_eq!(alts.len(), 1);
        assert_eq!(alts[0].action, RecoveryAction::EscalateToUser);
    }

    #[test]
    fn test_recovery_executor_exhausted_budget() {
        let db = RecoveryTreeDatabase::new();
        let checker = NoopRequirementChecker {
            default_context: RequirementContext {
                sudo_available: true,
                process_exists: true,
                retry_budget: 3,
                ..Default::default()
            },
        };
        let executor = RecoveryExecutor::new(&db, &checker);
        let mut session = executor.create_session(1234, None);

        // Exhaust budget for permission denied
        session.consume_budget(FailureCategory::PermissionDenied);
        session.consume_budget(FailureCategory::PermissionDenied);

        // Should have no alternatives now (max_attempts = 2 for permission denied)
        let alts = executor.find_alternatives(
            Action::Kill,
            FailureCategory::PermissionDenied,
            1234,
            &session,
        );
        assert!(alts.is_empty());
    }

    #[test]
    fn test_recovery_executor_generate_hint() {
        let db = RecoveryTreeDatabase::new();
        let checker = NoopRequirementChecker {
            default_context: RequirementContext {
                sudo_available: true,
                process_exists: true,
                retry_budget: 3,
                ..Default::default()
            },
        };
        let executor = RecoveryExecutor::new(&db, &checker);
        let session = executor.create_session(1234, None);

        let hint = executor.generate_hint(
            Action::Kill,
            FailureCategory::PermissionDenied,
            1234,
            &session,
        );
        assert!(hint.is_some());
        let hint = hint.unwrap();
        assert_eq!(hint.recommended_action, RecoveryAction::RetryWithSudo);
        assert!(hint.agent_next_step.contains("diagnosis"));
    }

    #[test]
    fn test_recovery_executor_classify_failure() {
        let db = RecoveryTreeDatabase::new();
        let checker = NoopRequirementChecker::default();
        let executor = RecoveryExecutor::new(&db, &checker);

        assert_eq!(
            executor.classify_failure("permission_denied", 1234, false),
            FailureCategory::PermissionDenied
        );
        assert_eq!(
            executor.classify_failure("timeout", 1234, false),
            FailureCategory::Timeout
        );
        assert_eq!(
            executor.classify_failure("any_error", 1234, true),
            FailureCategory::SupervisorConflict
        );
        assert_eq!(
            executor.classify_failure("unknown", 1234, false),
            FailureCategory::UnexpectedError
        );
    }

    #[test]
    fn test_recovery_session_serialization() {
        let mut session = RecoverySession::new(1234, Some("boot:1:1234".to_string()), 5);
        session.record_attempt(ActionAttempt {
            action: Action::Kill,
            result: AttemptResult::Success,
            time_ms: 50,
            attempt_number: 1,
        });
        let json = serde_json::to_string(&session).expect("serialize");
        assert!(json.contains("1234"));
        assert!(json.contains("boot:1:1234"));
    }

    #[test]
    fn test_recovery_outcome_serialization() {
        let outcome = RecoveryOutcome {
            attempted_action: RecoveryAction::RetryWithSudo,
            success: false,
            result: AttemptResult::Failed {
                category: FailureCategory::PermissionDenied,
            },
            duration_ms: 100,
            explanation: "Sudo not available".to_string(),
            next_step: Some(RecoveryAction::EscalateToUser),
        };
        let json = serde_json::to_string(&outcome).expect("serialize");
        assert!(json.contains("retry_with_sudo"));
        assert!(json.contains("escalate_to_user"));
    }

    // ── FailureCategory ───────────────────────────────────────────────

    #[test]
    fn failure_category_serde_roundtrip() {
        let variants = [
            FailureCategory::PermissionDenied,
            FailureCategory::ProcessNotFound,
            FailureCategory::ProcessProtected,
            FailureCategory::Timeout,
            FailureCategory::SupervisorConflict,
            FailureCategory::ResourceConflict,
            FailureCategory::IdentityMismatch,
            FailureCategory::PreCheckBlocked,
            FailureCategory::UnexpectedError,
        ];
        for v in variants {
            let json = serde_json::to_string(&v).unwrap();
            let back: FailureCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(back, v);
        }
    }

    #[test]
    fn failure_category_display_all() {
        assert_eq!(
            FailureCategory::ProcessNotFound.to_string(),
            "process_not_found"
        );
        assert_eq!(
            FailureCategory::ProcessProtected.to_string(),
            "process_protected"
        );
        assert_eq!(FailureCategory::Timeout.to_string(), "timeout");
        assert_eq!(
            FailureCategory::ResourceConflict.to_string(),
            "resource_conflict"
        );
        assert_eq!(
            FailureCategory::IdentityMismatch.to_string(),
            "identity_mismatch"
        );
        assert_eq!(
            FailureCategory::PreCheckBlocked.to_string(),
            "pre_check_blocked"
        );
        assert_eq!(
            FailureCategory::UnexpectedError.to_string(),
            "unexpected_error"
        );
    }

    // ── RecoveryAction serde ──────────────────────────────────────────

    #[test]
    fn recovery_action_serde_roundtrip() {
        let actions = vec![
            RecoveryAction::Retry,
            RecoveryAction::RetryWithSudo,
            RecoveryAction::StopSupervisor,
            RecoveryAction::MaskAndStop,
            RecoveryAction::VerifyGoal,
            RecoveryAction::CheckRespawn,
            RecoveryAction::Investigate,
            RecoveryAction::EscalateToUser,
            RecoveryAction::Skip,
            RecoveryAction::Escalate(Action::Kill),
            RecoveryAction::WaitAndRetry { delay_ms: 500 },
            RecoveryAction::Custom {
                command: "test".to_string(),
            },
        ];
        for action in actions {
            let json = serde_json::to_string(&action).unwrap();
            let back: RecoveryAction = serde_json::from_str(&json).unwrap();
            assert_eq!(back, action);
        }
    }

    // ── Requirement serde ─────────────────────────────────────────────

    #[test]
    fn requirement_serde_roundtrip() {
        let reqs = vec![
            Requirement::SudoAvailable,
            Requirement::ProcessExists,
            Requirement::SystemdSupervised,
            Requirement::DockerSupervised,
            Requirement::Pm2Supervised,
            Requirement::InDState,
            Requirement::RetryBudgetAvailable,
            Requirement::UserConfirmation,
            Requirement::CgroupV2Available,
        ];
        for r in reqs {
            let json = serde_json::to_string(&r).unwrap();
            let back: Requirement = serde_json::from_str(&json).unwrap();
            assert_eq!(back, r);
        }
    }

    // ── Remaining trees ───────────────────────────────────────────────

    #[test]
    fn renice_tree_permission_denied() {
        let tree = RecoveryTree::renice_tree();
        assert_eq!(tree.action, Action::Renice);
        let branch = tree.get_branch(FailureCategory::PermissionDenied);
        assert!(branch
            .alternatives
            .iter()
            .any(|a| a.action == RecoveryAction::RetryWithSudo));
    }

    #[test]
    fn renice_tree_resource_conflict() {
        let tree = RecoveryTree::renice_tree();
        let branch = tree.get_branch(FailureCategory::ResourceConflict);
        assert!(!branch.alternatives.is_empty());
    }

    #[test]
    fn throttle_tree_action() {
        let tree = RecoveryTree::throttle_tree();
        assert_eq!(tree.action, Action::Throttle);
    }

    #[test]
    fn restart_tree_action() {
        let tree = RecoveryTree::restart_tree();
        assert_eq!(tree.action, Action::Restart);
    }

    #[test]
    fn restart_tree_permission_denied_has_alternatives() {
        let tree = RecoveryTree::restart_tree();
        let branch = tree.get_branch(FailureCategory::PermissionDenied);
        assert!(!branch.alternatives.is_empty());
    }

    #[test]
    fn restart_tree_supervisor_conflict() {
        let tree = RecoveryTree::restart_tree();
        let branch = tree.get_branch(FailureCategory::SupervisorConflict);
        assert!(!branch.alternatives.is_empty());
    }

    // ── get_branch default fallback ───────────────────────────────────

    #[test]
    fn get_branch_unmapped_returns_default() {
        let tree = RecoveryTree::kill_tree();
        // ResourceConflict is not in kill_tree branches
        let branch = tree.get_branch(FailureCategory::ResourceConflict);
        // Should return the default branch
        assert!(!branch.alternatives.is_empty());
        assert!(branch.diagnosis.contains("Unexpected"));
    }

    // ── RecoveryBranch serde ──────────────────────────────────────────

    #[test]
    fn recovery_branch_serde_roundtrip() {
        let branch = RecoveryBranch {
            diagnosis: "test".to_string(),
            alternatives: vec![RecoveryAlternative {
                action: RecoveryAction::Retry,
                explanation: "try again".to_string(),
                requirements: vec![Requirement::ProcessExists],
                reversible: true,
                command_hint: Some("retry".to_string()),
                notes: None,
            }],
            verification: Some("check it worked".to_string()),
            max_attempts: 3,
        };
        let json = serde_json::to_string(&branch).unwrap();
        let back: RecoveryBranch = serde_json::from_str(&json).unwrap();
        assert_eq!(back.max_attempts, 3);
        assert_eq!(back.alternatives.len(), 1);
    }

    // ── RequirementContext extras ──────────────────────────────────────

    #[test]
    fn requirement_context_default() {
        let ctx = RequirementContext::default();
        assert!(!ctx.sudo_available);
        assert!(!ctx.process_exists);
        assert_eq!(ctx.retry_budget, 0);
    }

    #[test]
    fn requirement_context_supervisor_requirements() {
        let ctx = RequirementContext {
            systemd_supervised: true,
            docker_supervised: false,
            pm2_supervised: true,
            ..Default::default()
        };
        assert!(ctx.is_met(&Requirement::SystemdSupervised));
        assert!(!ctx.is_met(&Requirement::DockerSupervised));
        assert!(ctx.is_met(&Requirement::Pm2Supervised));
    }

    #[test]
    fn requirement_context_cgroup_v2() {
        let ctx = RequirementContext {
            cgroup_v2_available: true,
            ..Default::default()
        };
        assert!(ctx.is_met(&Requirement::CgroupV2Available));
    }

    #[test]
    fn requirement_context_user_confirmation() {
        let ctx = RequirementContext {
            user_confirmation_available: true,
            ..Default::default()
        };
        assert!(ctx.is_met(&Requirement::UserConfirmation));
    }

    // ── RecoveryTreeDatabase ──────────────────────────────────────────

    #[test]
    fn database_lookup_nonexistent_action() {
        let db = RecoveryTreeDatabase::new();
        // Resume doesn't have a tree
        assert!(db.get_tree(Action::Resume).is_none());
    }

    #[test]
    fn database_lookup_kill_timeout() {
        let db = RecoveryTreeDatabase::new();
        let branch = db.lookup(Action::Kill, FailureCategory::Timeout);
        assert!(branch.is_some());
        let branch = branch.unwrap();
        assert!(branch.alternatives.len() >= 1);
    }

    #[test]
    fn database_lookup_no_tree_returns_none() {
        let db = RecoveryTreeDatabase::new();
        assert!(db.lookup(Action::Keep, FailureCategory::Timeout).is_none());
    }

    // ── AttemptResult serde ───────────────────────────────────────────

    #[test]
    fn attempt_result_serde_roundtrip() {
        let variants = vec![
            AttemptResult::Success,
            AttemptResult::Failed {
                category: FailureCategory::Timeout,
            },
            AttemptResult::Skipped {
                reason: "not needed".to_string(),
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let _: AttemptResult = serde_json::from_str(&json).unwrap();
        }
    }

    // ── RecoveryExecutor extras ───────────────────────────────────────

    #[test]
    fn recovery_executor_with_max_attempts() {
        let db = RecoveryTreeDatabase::new();
        let checker = NoopRequirementChecker::default();
        let executor = RecoveryExecutor::new(&db, &checker).with_max_attempts(10);
        let session = executor.create_session(999, None);
        assert_eq!(session.max_total_attempts, 10);
    }

    #[test]
    fn recovery_executor_get_best_alternative() {
        let db = RecoveryTreeDatabase::new();
        let checker = NoopRequirementChecker {
            default_context: RequirementContext {
                sudo_available: true,
                process_exists: true,
                retry_budget: 3,
                ..Default::default()
            },
        };
        let executor = RecoveryExecutor::new(&db, &checker);
        let session = executor.create_session(1234, None);

        let best = executor.get_best_alternative(
            Action::Kill,
            FailureCategory::PermissionDenied,
            1234,
            &session,
        );
        assert!(best.is_some());
        assert_eq!(best.unwrap().action, RecoveryAction::RetryWithSudo);
    }

    #[test]
    fn recovery_executor_classify_process_not_found() {
        let db = RecoveryTreeDatabase::new();
        let checker = NoopRequirementChecker::default();
        let executor = RecoveryExecutor::new(&db, &checker);
        assert_eq!(
            executor.classify_failure("not_found", 1, false),
            FailureCategory::ProcessNotFound
        );
    }

    #[test]
    fn recovery_executor_classify_protected() {
        let db = RecoveryTreeDatabase::new();
        let checker = NoopRequirementChecker::default();
        let executor = RecoveryExecutor::new(&db, &checker);
        assert_eq!(
            executor.classify_failure("protected", 1, false),
            FailureCategory::ProcessProtected
        );
    }

    // ── RecoveryHint serde ────────────────────────────────────────────

    #[test]
    fn recovery_hint_serde_roundtrip() {
        let hint = RecoveryHint {
            recommended_action: RecoveryAction::Retry,
            explanation: "try again".to_string(),
            reversibility: Some("undo it".to_string()),
            agent_next_step: "diagnosis: retry".to_string(),
        };
        let json = serde_json::to_string(&hint).unwrap();
        let back: RecoveryHint = serde_json::from_str(&json).unwrap();
        assert_eq!(back.recommended_action, RecoveryAction::Retry);
    }

    // ── ActionAttempt serde ───────────────────────────────────────────

    #[test]
    fn action_attempt_serde_roundtrip() {
        let attempt = ActionAttempt {
            action: Action::Kill,
            result: AttemptResult::Success,
            time_ms: 50,
            attempt_number: 1,
        };
        let json = serde_json::to_string(&attempt).unwrap();
        let back: ActionAttempt = serde_json::from_str(&json).unwrap();
        assert_eq!(back.attempt_number, 1);
        assert!(matches!(back.result, AttemptResult::Success));
    }
}
