//! Action execution system.

pub mod executor;
pub mod prechecks;
pub mod recovery;
pub mod recovery_tree;
pub mod renice;
pub mod supervisor;
#[cfg(unix)]
pub mod signal;

pub use executor::{
    ActionError, ActionExecutor, ActionResult, ActionRunner, ActionStatus, ExecutionError,
    ExecutionResult, ExecutionSummary, IdentityProvider, NoopActionRunner, StaticIdentityProvider,
};
pub use recovery::{plan_recovery, ActionFailure, FailureKind, RecoveryDecision, RetryPolicy};
pub use renice::{ReniceActionRunner, ReniceConfig, DEFAULT_NICE_VALUE, MAX_NICE_VALUE};
#[cfg(target_os = "linux")]
pub use signal::LiveIdentityProvider;
#[cfg(unix)]
pub use signal::{SignalActionRunner, SignalConfig};
pub use supervisor::{
    plan_action_from_app_supervision, plan_action_from_container_supervision,
    plan_action_from_supervisor_info, SupervisorActionConfig, SupervisorActionError,
    SupervisorActionResult, SupervisorActionRunner, SupervisorCommand, SupervisorParameters,
    SupervisorPlanAction, SupervisorType,
};

pub use prechecks::{
    LivePreCheckConfig, NoopPreCheckProvider, PreCheckError, PreCheckProvider, PreCheckResult,
    SupervisorAction, SupervisorInfo,
};
#[cfg(target_os = "linux")]
pub use prechecks::LivePreCheckProvider;

pub use recovery_tree::{
    ActionAttempt, AttemptResult, FailureCategory, NoopRequirementChecker, RecoveryAction,
    RecoveryAlternative, RecoveryBranch, RecoveryExecutor, RecoveryHint, RecoveryOutcome,
    RecoverySession, RecoveryTree, RecoveryTreeDatabase, Requirement, RequirementChecker,
    RequirementContext,
};
#[cfg(target_os = "linux")]
pub use recovery_tree::LiveRequirementChecker;
