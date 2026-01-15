//! Inference engine modules.

pub mod belief_prop;
pub mod bocpd;
pub mod evt;
pub mod hawkes;
pub mod hazard;
#[cfg(target_os = "linux")]
pub mod impact;
pub mod kalman;
pub mod ledger;
pub mod posterior;
pub mod ppc;
pub mod robust;
pub mod wasserstein;

pub use belief_prop::{
    propagate_beliefs, BeliefPropConfig, BeliefPropError, BeliefPropEvidence, BeliefPropResult,
    BeliefPropagator, ProcessNode, ProcessTree, State, TreeSummary,
};
pub use bocpd::{
    BatchResult, BocpdConfig, BocpdDetector, BocpdError, BocpdEvidence, BocpdUpdateResult,
    ChangePoint, EmissionModel,
};
pub use evt::{
    BatchEvtAnalyzer, EstimationMethod, EvtError, EvtEvidence, GpdConfig, GpdFitter, GpdResult,
    TailType, ThresholdMethod,
};
pub use hawkes::{
    BurstLevel, CrossExcitationSummary, HawkesConfig, HawkesDetector, HawkesEvidence, HawkesResult,
};
pub use hazard::{
    GammaParams, HazardEvidence, HazardModel, HazardResult, Regime, RegimePriors, RegimeState,
    RegimeStats, RegimeTransition,
};
pub use kalman::{
    FilterState, KalmanConfig, KalmanEvidence, KalmanFilter, KalmanResult, KalmanSummary,
};
pub use ledger::{
    default_glyph_map, get_glyph, BayesFactorEntry, Classification, Confidence, Direction,
    EvidenceLedger, FeatureGlyph,
};
pub use posterior::{
    compute_posterior, ClassScores, CpuEvidence, Evidence, EvidenceTerm, PosteriorError,
    PosteriorResult,
};
pub use ppc::{
    AggregatedPpcEvidence, BatchPpcChecker, FallbackAction, PpcChecker, PpcConfig, PpcError,
    PpcEvidence, PpcResult, StatisticCheck, TestStatistic,
};
pub use robust::{
    best_case_expected_loss, select_eta_prequential, worst_case_expected_loss, CredalSet,
    RobustConfig, RobustError, RobustEvidence, RobustGate, RobustResult, TemperedPosterior,
};
pub use wasserstein::{
    wasserstein_1d, wasserstein_2_squared, AggregatedDriftEvidence, DriftAction, DriftMonitor,
    DriftResult, DriftSeverity, WassersteinConfig, WassersteinDetector, WassersteinError,
    WassersteinEvidence,
};
#[cfg(target_os = "linux")]
pub use impact::{
    compute_impact_score, compute_impact_scores_batch, CriticalWriteCategory, ImpactComponents,
    ImpactConfig, ImpactError, ImpactEvidence, ImpactResult, ImpactScorer, ImpactSeverity,
    MissingDataSource, SupervisorLevel,
};
