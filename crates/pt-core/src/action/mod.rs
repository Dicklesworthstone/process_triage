//! Action execution system.

#[cfg(target_os = "linux")]
pub mod cgroup_throttle;
#[cfg(target_os = "linux")]
pub mod cpuset_quarantine;
pub mod executor;
#[cfg(target_os = "linux")]
pub mod freeze;

#[cfg(test)]
mod repro_cpuset;

pub mod prechecks;
pub mod recovery;
pub mod recovery_tree;
pub mod renice;
#[cfg(unix)]
pub mod signal;
pub mod supervisor;

#[cfg(target_os = "linux")]
pub use cgroup_throttle::{
    can_throttle_process, CpuThrottleActionRunner, CpuThrottleConfig, ThrottleResult,
    ThrottleReversalMetadata, DEFAULT_PERIOD_US, DEFAULT_THROTTLE_FRACTION, MIN_QUOTA_US,
};
#[cfg(target_os = "linux")]
pub use cpuset_quarantine::{
    can_quarantine_cpuset, CpusetQuarantineActionRunner, CpusetQuarantineConfig, QuarantineResult,
    QuarantineReversalMetadata, DEFAULT_QUARANTINE_CPUS, MIN_QUARANTINE_CPUS,
};
pub use executor::{
    ActionError, ActionExecutor, ActionResult, ActionRunner, ActionStatus, ExecutionError,
    ExecutionResult, ExecutionSummary, IdentityProvider, NoopActionRunner, StaticIdentityProvider,
};
#[cfg(target_os = "linux")]
pub use freeze::{is_freeze_available, FreezeActionRunner, FreezeConfig};
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

#[cfg(target_os = "linux")]
pub use prechecks::LivePreCheckProvider;
pub use prechecks::{
    LivePreCheckConfig, NoopPreCheckProvider, PreCheckError, PreCheckProvider, PreCheckResult,
    SupervisorAction, SupervisorInfo,
};

#[cfg(target_os = "linux")]
pub use recovery_tree::LiveRequirementChecker;
pub use recovery_tree::{
    ActionAttempt, AttemptResult, FailureCategory, NoopRequirementChecker, RecoveryAction,
    RecoveryAlternative, RecoveryBranch, RecoveryExecutor, RecoveryHint, RecoveryOutcome,
    RecoverySession, RecoveryTree, RecoveryTreeDatabase, Requirement, RequirementChecker,
    RequirementContext,
};
