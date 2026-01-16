//! Decision theory utilities (expected loss, thresholds, FDR control, policy enforcement).

pub mod alpha_investing;
pub mod causal_interventions;
pub mod composite_test;
pub mod cvar;
pub mod dependency_loss;
pub mod dro;
pub mod enforcer;
pub mod expected_loss;
pub mod fdr_selection;
pub mod load_aware;
pub mod robot_constraints;
pub mod voi;

pub use alpha_investing::{
    AlphaInvestingPolicy, AlphaInvestingStore, AlphaUpdate, AlphaWealthState,
};
pub use causal_interventions::{
    apply_outcome, apply_outcomes, expected_recovery, expected_recovery_by_action,
    expected_recovery_for_action, recovery_for_class, recovery_table, InterventionOutcome,
    ProcessClass, RecoveryExpectation, RecoveryTable,
};
pub use dependency_loss::{
    compute_critical_file_inflation, compute_dependency_scaling, scale_kill_loss,
    should_block_kill, CriticalFileInflation, CriticalFileInflationResult, DependencyFactors,
    DependencyScaling, DependencyScalingResult,
};
pub use enforcer::{
    CriticalFilesSummary, EnforcerError, PolicyCheckResult, PolicyEnforcer, PolicyViolation,
    ProcessCandidate, ViolationKind,
};
pub use expected_loss::{
    apply_dro_control, apply_risk_sensitive_control, decide_action, decide_action_with_recovery,
    Action, ActionFeasibility, DecisionError, DecisionOutcome, DecisionRationale, DisabledAction,
    ExpectedLoss, SprtBoundary,
};
pub use fdr_selection::{
    by_correction_factor, select_fdr, CandidateSelection, FdrCandidate, FdrError, FdrMethod,
    FdrSelectionResult, TargetIdentity,
};
pub use load_aware::{apply_load_to_loss_matrix, compute_load_adjustment, LoadAdjustment, LoadSignals};
pub use robot_constraints::{
    ConstraintCheckResult, ConstraintChecker, ConstraintKind, ConstraintMetrics, ConstraintSource,
    ConstraintSources, ConstraintViolation, RobotCandidate, RuntimeRobotConstraints,
};
pub use cvar::{
    compute_cvar, decide_with_cvar, CvarError, CvarLoss, CvarTrigger, RiskSensitiveOutcome,
};
pub use voi::{
    compute_voi, select_probe_by_information_gain, ProbeCost, ProbeCostModel, ProbeInformationGain,
    ProbeType, ProbeVoi, VoiAnalysis, VoiError,
};
pub use dro::{
    apply_dro_gate, compute_adaptive_epsilon, compute_wasserstein_dro, decide_with_dro,
    is_de_escalation, DroError, DroLoss, DroOutcome, DroTrigger,
};
pub use composite_test::{
    glr_bernoulli, mixture_sprt_bernoulli, mixture_sprt_beta_sequential, mixture_sprt_multiclass,
    needs_composite_test, CompositeEvidenceAggregator, CompositeTestError, CompositeTestOutcome,
    GlrConfig, GlrResult, MixtureSprtConfig, MixtureSprtResult, MixtureSprtState,
};
