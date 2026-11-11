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

pub mod dispatch;
pub mod memory_cap;
pub mod prechecks;
pub mod recovery;
pub mod recovery_tree;
pub mod renice;
pub mod reversal;
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
pub use dispatch::{
    planning_action_feasibility, planning_action_feasibility_with_restart, CompositeActionRunner,
};
pub use executor::{
    ActionError, ActionExecutor, ActionResult, ActionRunner, ActionStatus, ExecutionError,
    ExecutionResult, ExecutionSummary, IdentityProvider, NoopActionRunner, StaticIdentityProvider,
};
#[cfg(target_os = "linux")]
pub use freeze::{is_freeze_available, FreezeActionRunner, FreezeConfig};
#[cfg(target_os = "linux")]
pub use memory_cap::MemoryCapActionRunner;
pub use memory_cap::{observe_memory_cap, plan_memory_cap, MemoryCapPlan, MIN_MEMORY_CAP_BYTES};
pub use recovery::{plan_recovery, ActionFailure, FailureKind, RecoveryDecision, RetryPolicy};
pub use renice::{
    ReniceActionRunner, ReniceConfig, ReniceResult, ReniceReversalMetadata, DEFAULT_NICE_VALUE,
    MAX_NICE_VALUE,
};
pub use reversal::{
    RestorationObservation, RestorationStatus, ReversalJournal, ReversalOutcome, ReversalRecord,
};
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use signal::LiveIdentityProvider;
#[cfg(unix)]
pub use signal::{SignalActionRunner, SignalConfig};
#[cfg(target_os = "linux")]
pub use supervisor::plan_action_from_container_supervision;
pub use supervisor::{
    discover_systemd_user_restart, plan_action_from_app_supervision,
    plan_action_from_supervisor_info, validate_systemd_user_restart, SupervisorActionConfig,
    SupervisorActionError, SupervisorActionResult, SupervisorActionRunner, SupervisorCommand,
    SupervisorParameters, SupervisorPlanAction, SupervisorType, SystemdUserServiceBinding,
};

#[cfg(any(target_os = "linux", target_os = "macos"))]
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
