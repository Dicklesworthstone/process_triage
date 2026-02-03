//! Inference engine modules.

pub mod belief_prop;
pub mod belief_state;
pub mod beta_stacy;
pub mod bma;
pub mod bocpd;
pub mod compound_poisson;
pub mod confidence_viz;
pub mod conformal;
pub mod copula;
pub mod ctw;
pub mod evt;
pub mod explain;
pub mod explain_api;
pub mod flip_conditions;
pub mod galaxy_brain;
pub mod graph_smoothing;
pub mod hawkes;
pub mod hazard;
pub mod hsmm;
pub mod imm;
#[cfg(target_os = "linux")]
pub mod impact;
pub mod kalman;
pub mod kl_surprisal;
pub mod ledger;
pub mod ledger_display;
pub mod martingale;
pub mod mpp;
pub mod posterior;
pub mod ppc;
pub mod prior_override;
pub mod robust;
pub mod robust_stats;
pub mod signature_fast_path;
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
    BetaParams, BetaStacyBin, BetaStacyError, BetaStacyModel, BinSpec, BinningKind, BinningScheme,
    LifetimeSample,
};
pub use bma::{combine_posteriors, BmaError, ModelAveragedPosterior, ModelPosterior, ModelWeight};
pub use bocpd::{
    BatchResult, BocpdConfig, BocpdDetector, BocpdError, BocpdEvidence, BocpdUpdateResult,
    ChangePoint, EmissionModel,
};
pub use compound_poisson::{
    BatchCompoundPoissonAnalyzer, BurstEvent, CompoundPoissonAnalyzer, CompoundPoissonConfig,
    CompoundPoissonError, CompoundPoissonEvidence, CompoundPoissonParams, CompoundPoissonResult,
    CompoundPoissonSummary, GammaParams as CpGammaParams, RegimeStats as CpRegimeStats,
};
pub use conformal::{
    AdaptiveConformalRegressor, BlockedConformalRegressor, ConformalClassifier, ConformalConfig,
    ConformalError, ConformalEvidence, ConformalInterval, ConformalPredictionSet,
    ConformalRegressor,
};
pub use copula::{summarize_copula_dependence, CopulaConfig, CopulaSummary};
pub use ctw::{
    CtwBatchResult, CtwConfig, CtwError, CtwEvidence, CtwFeatures, CtwPredictor, CtwProvenance,
    CtwUpdateResult, DiscretizationMode, Discretizer, DiscretizerConfig,
};
pub use evt::{
    BatchEvtAnalyzer, EstimationMethod, EvtError, EvtEvidence, GpdConfig, GpdFitter, GpdResult,
    TailType, ThresholdMethod,
};
pub use graph_smoothing::{
    build_neighbors, edges_from_clusters, smooth_values, GraphSmoothingConfig, GraphSmoothingError,
    GraphSmoothingResult,
};
pub use hawkes::{
    summarize_cross_excitation, BurstLevel, CrossExcitationConfig, CrossExcitationSummary,
    HawkesConfig, HawkesDetector, HawkesEvidence, HawkesResult,
};
pub use hazard::{
    GammaParams, HazardEvidence, HazardModel, HazardResult, Regime, RegimePriors, RegimeState,
    RegimeStats, RegimeTransition,
};
pub use hsmm::{
    BatchHsmmAnalyzer, DurationStats, GammaDuration, HsmmAnalyzer, HsmmConfig, HsmmError,
    HsmmEvidence, HsmmResult, HsmmState, StateSwitch,
};
pub use imm::{
    BatchImmAnalyzer, ImmAnalyzer, ImmConfig, ImmError, ImmEvidence, ImmResult, ImmState,
    ImmUpdateResult, ModeFilterState, Regime as ImmRegime,
};
#[cfg(target_os = "linux")]
pub use impact::{
    compute_impact_score, compute_impact_scores_batch, CriticalWriteCategory, ImpactComponents,
    ImpactConfig, ImpactError, ImpactEvidence, ImpactResult, ImpactScorer, ImpactSeverity,
    MissingDataSource, SupervisorLevel,
};
pub use kalman::{
    FilterState, KalmanConfig, KalmanEvidence, KalmanFilter, KalmanResult, KalmanSummary,
};
pub use kl_surprisal::{
    kl_divergence_discrete, symmetric_kl_divergence, AbnormalitySeverity, BatchKlAnalyzer,
    BernoulliObservation, DeviationDirection, DeviationType, KlSurprisalAnalyzer,
    KlSurprisalConfig, KlSurprisalError, KlSurprisalEvidence, KlSurprisalFeatures,
    KlSurprisalResult, ReferenceClass,
};
pub use ledger::{
    build_process_explanation, default_glyph_map, get_glyph, BayesFactorEntry, Classification,
    Confidence, Direction, EvidenceLedger, FeatureGlyph,
};
pub use martingale::{
    BatchMartingaleAnalyzer, BoundParameters, BoundType, MartingaleAnalyzer, MartingaleConfig,
    MartingaleError, MartingaleEvidence, MartingaleResult, MartingaleUpdateResult,
};
pub use mpp::{
    BatchMppAnalyzer, BurstinessLevel, InterArrivalStats, MarkDistribution, MarkedEvent,
    MarkedPointProcess, MppConfig, MppEvidence, MppSummary,
};
pub use posterior::{
    compute_posterior, ClassScores, CpuEvidence, Evidence, EvidenceTerm, PosteriorError,
    PosteriorResult,
};
pub use ppc::{
    AggregatedPpcEvidence, BatchPpcChecker, FallbackAction, PpcChecker, PpcConfig, PpcError,
    PpcEvidence, PpcResult, StatisticCheck, TestStatistic,
};
pub use prior_override::{
    compute_posterior_with_overrides, resolve_priors, AppliedOverrides, OverriddenPrior,
    PriorContext, PriorSource, PriorSourceInfo, ResolvedPriors, UserPriorOverrides,
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
pub use sketches::{
    CountMinConfig, CountMinSketch, HeavyHitter, PercentileSummary, SketchError, SketchEvidence,
    SketchManager, SketchManagerConfig, SketchResult, SketchSummary, SpaceSaving,
    SpaceSavingConfig, TDigest, TDigestConfig,
};
pub use wasserstein::{
    wasserstein_1d, wasserstein_2_squared, AggregatedDriftEvidence, DriftAction, DriftMonitor,
    DriftResult, DriftSeverity, WassersteinConfig, WassersteinDetector, WassersteinError,
    WassersteinEvidence,
};
