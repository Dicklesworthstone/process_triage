//! Decision theory utilities (expected loss, thresholds, FDR control, policy enforcement).

pub mod alpha_investing;
pub mod causal_interventions;
pub mod dependency_loss;
pub mod enforcer;
pub mod expected_loss;
pub mod fdr_selection;
pub mod robot_constraints;

pub use alpha_investing::{
    AlphaInvestingPolicy, AlphaInvestingStore, AlphaUpdate, AlphaWealthState,
};
pub use causal_interventions::{
    apply_outcome, apply_outcomes, expected_recovery, expected_recovery_by_action,
    expected_recovery_for_action, recovery_for_class, recovery_table, InterventionOutcome,
    ProcessClass, RecoveryExpectation, RecoveryTable,
};
pub use enforcer::{
    CriticalFilesSummary, EnforcerError, PolicyCheckResult, PolicyEnforcer, PolicyViolation,
    ProcessCandidate, ViolationKind,
};
pub use expected_loss::{
    decide_action, decide_action_with_recovery, Action, ActionFeasibility, DecisionError,
    DecisionOutcome, DecisionRationale, DisabledAction, ExpectedLoss, SprtBoundary,
};
pub use fdr_selection::{
    by_correction_factor, select_fdr, CandidateSelection, FdrCandidate, FdrError, FdrMethod,
    FdrSelectionResult, TargetIdentity,
};
pub use dependency_loss::{
    compute_critical_file_inflation, compute_dependency_scaling, scale_kill_loss,
    should_block_kill, CriticalFileInflation, CriticalFileInflationResult, DependencyFactors,
    DependencyScaling, DependencyScalingResult,
};
pub use robot_constraints::{
    ConstraintCheckResult, ConstraintChecker, ConstraintKind, ConstraintMetrics,
    ConstraintSource, ConstraintSources, ConstraintViolation, RobotCandidate,
    RuntimeRobotConstraints,
};
