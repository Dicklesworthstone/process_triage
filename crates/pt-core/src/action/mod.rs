//! Action execution system.

pub mod executor;
pub mod recovery;

pub use executor::{
    ActionError, ActionExecutor, ActionResult, ActionStatus, ExecutionError, ExecutionResult,
    ExecutionSummary, NoopActionRunner, StaticIdentityProvider,
};
pub use recovery::{plan_recovery, ActionFailure, FailureKind, RecoveryDecision, RetryPolicy};
