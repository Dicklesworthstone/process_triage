//! Inference engine modules.

pub mod belief_prop;
pub mod belief_state;
pub mod beta_stacy;
pub mod bma;
pub mod bocpd;
pub mod compound_poisson;
pub mod ctw;
pub mod conformal;
pub mod evt;
pub mod graph_smoothing;
pub mod hawkes;
pub mod hazard;
pub mod hsmm;
#[cfg(target_os = "linux")]
pub mod impact;
pub mod imm;
pub mod kalman;
pub mod kl_surprisal;
pub mod ledger;
pub mod martingale;
pub mod mpp;
pub mod posterior;
pub mod ppc;
pub mod robust;
pub mod robust_stats;
pub mod sketches;
pub mod wasserstein;

pub use belief_prop::{
    propagate_beliefs, BeliefPropConfig, BeliefPropError, BeliefPropEvidence, BeliefPropResult,
    BeliefPropagator, ProcessNode, ProcessTree, State, TreeSummary,
};
pub use belief_state::{
    belief_js_divergence, belief_kl_divergence, update_belief, update_belief_batch, BeliefState,
    BeliefStateError, BeliefUpdateConfig, BeliefUpdateResult, ObservationLikelihood, ProcessState,
    TransitionModel, NUM_STATES,
};
pub use beta_stacy::{
    BetaParams, BetaStacyError, BetaStacyModel, BetaStacyBin, BinningKind, BinningScheme,
    BinSpec, LifetimeSample,
};
pub use bma::{combine_posteriors, BmaError, ModelAveragedPosterior, ModelPosterior, ModelWeight};
pub use bocpd::{
    BatchResult, BocpdConfig, BocpdDetector, BocpdError, BocpdEvidence, BocpdUpdateResult,
    ChangePoint, EmissionModel,
};
pub use ctw::{
    CtwBatchResult, CtwConfig, CtwError, CtwEvidence, CtwFeatures, CtwPredictor, CtwProvenance,
    CtwUpdateResult, DiscretizationMode, Discretizer, DiscretizerConfig,
};
pub use conformal::{
    AdaptiveConformalRegressor, BlockedConformalRegressor, ConformalClassifier, ConformalConfig,
    ConformalError, ConformalEvidence, ConformalInterval, ConformalPredictionSet,
    ConformalRegressor,
};
pub use evt::{
    BatchEvtAnalyzer, EstimationMethod, EvtError, EvtEvidence, GpdConfig, GpdFitter, GpdResult,
    TailType, ThresholdMethod,
};
pub use graph_smoothing::{
    build_neighbors, edges_from_clusters, smooth_values, GraphSmoothingConfig,
    GraphSmoothingError, GraphSmoothingResult,
};
pub use hawkes::{
    summarize_cross_excitation, BurstLevel, CrossExcitationConfig, CrossExcitationSummary,
    HawkesConfig, HawkesDetector, HawkesEvidence, HawkesResult,
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
    best_case_expected_loss, minimax_expected_loss_gate, select_eta_prequential,
    worst_case_expected_loss, CredalSet, DecisionStabilityAnalysis, LeastFavorablePrior,
    MinimaxConfig, MinimaxEvidence, MinimaxGate, MinimaxResult, RobustConfig, RobustError,
    RobustEvidence, RobustGate, RobustResult, TemperedPosterior,
};
pub use robust_stats::{
    summarize as summarize_robust_stats, RobustStatsConfig, RobustStatsError, RobustSummary,
};
pub use wasserstein::{
    wasserstein_1d, wasserstein_2_squared, AggregatedDriftEvidence, DriftAction, DriftMonitor,
    DriftResult, DriftSeverity, WassersteinConfig, WassersteinDetector, WassersteinError,
    WassersteinEvidence,
};
pub use sketches::{
    CountMinConfig, CountMinSketch, HeavyHitter, PercentileSummary, SketchError, SketchEvidence,
    SketchManager, SketchManagerConfig, SketchResult, SketchSummary, SpaceSaving,
    SpaceSavingConfig, TDigest, TDigestConfig,
};
pub use martingale::{
    BatchMartingaleAnalyzer, BoundParameters, BoundType, MartingaleAnalyzer, MartingaleConfig,
    MartingaleError, MartingaleEvidence, MartingaleResult, MartingaleUpdateResult,
};
pub use kl_surprisal::{
    kl_divergence_discrete, symmetric_kl_divergence, AbnormalitySeverity, BatchKlAnalyzer,
    BernoulliObservation, DeviationDirection, DeviationType, KlSurprisalAnalyzer,
    KlSurprisalConfig, KlSurprisalError, KlSurprisalEvidence, KlSurprisalFeatures,
    KlSurprisalResult, ReferenceClass,
};
pub use mpp::{
    BatchMppAnalyzer, BurstinessLevel, InterArrivalStats, MarkDistribution, MarkedEvent,
    MarkedPointProcess, MppConfig, MppEvidence, MppSummary,
};
#[cfg(target_os = "linux")]
pub use impact::{
    compute_impact_score, compute_impact_scores_batch, CriticalWriteCategory, ImpactComponents,
    ImpactConfig, ImpactError, ImpactEvidence, ImpactResult, ImpactScorer, ImpactSeverity,
    MissingDataSource, SupervisorLevel,
};
pub use imm::{
    BatchImmAnalyzer, ImmAnalyzer, ImmConfig, ImmError, ImmEvidence, ImmResult, ImmState,
    ImmUpdateResult, ModeFilterState, Regime as ImmRegime,
};
pub use hsmm::{
    BatchHsmmAnalyzer, DurationStats, GammaDuration, HsmmAnalyzer, HsmmConfig, HsmmError,
    HsmmEvidence, HsmmResult, HsmmState, StateSwitch,
};
pub use compound_poisson::{
    BatchCompoundPoissonAnalyzer, BurstEvent, CompoundPoissonAnalyzer, CompoundPoissonConfig,
    CompoundPoissonError, CompoundPoissonEvidence, CompoundPoissonParams, CompoundPoissonResult,
    CompoundPoissonSummary, GammaParams as CpGammaParams, RegimeStats as CpRegimeStats,
};
