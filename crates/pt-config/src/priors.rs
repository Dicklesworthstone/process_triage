//! Bayesian prior configuration types.
//!
//! These types match the priors.schema.json specification.

use serde::{Deserialize, Serialize};

/// Complete priors configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Priors {
    pub schema_version: String,

    #[serde(default)]
    pub description: Option<String>,

    #[serde(default)]
    pub host_profile: Option<String>,

    #[serde(default)]
    pub created_at: Option<String>,

    #[serde(default)]
    pub updated_at: Option<String>,

    pub classes: ClassPriors,

    #[serde(default)]
    pub hazard_regimes: Vec<HazardRegime>,

    #[serde(default)]
    pub semi_markov: Option<SemiMarkovParams>,

    #[serde(default)]
    pub change_point: Option<ChangePointParams>,

    #[serde(default)]
    pub causal_interventions: Option<CausalInterventions>,

    #[serde(default)]
    pub command_categories: Option<CommandCategories>,

    #[serde(default)]
    pub state_flags: Option<StateFlags>,

    #[serde(default)]
    pub hierarchical: Option<HierarchicalParams>,

    #[serde(default)]
    pub robust_bayes: Option<RobustBayesParams>,

    #[serde(default)]
    pub error_rate: Option<ErrorRateParams>,

    #[serde(default)]
    pub bocpd: Option<BocpdParams>,
}

/// Per-class Bayesian hyperparameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassPriors {
    pub useful: ClassParams,
    pub useful_bad: ClassParams,
    pub abandoned: ClassParams,
    pub zombie: ClassParams,
}

/// Parameters for a single process class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassParams {
    pub prior_prob: f64,
    pub cpu_beta: BetaParams,

    #[serde(default)]
    pub runtime_gamma: Option<GammaParams>,

    pub orphan_beta: BetaParams,
    pub tty_beta: BetaParams,
    pub net_beta: BetaParams,

    #[serde(default)]
    pub io_active_beta: Option<BetaParams>,

    #[serde(default)]
    pub hazard_gamma: Option<GammaParams>,

    #[serde(default)]
    pub competing_hazards: Option<CompetingHazards>,
}

/// Beta distribution parameters: Beta(alpha, beta).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BetaParams {
    pub alpha: f64,
    pub beta: f64,

    #[serde(rename = "_comment", default)]
    pub comment: Option<String>,
}

impl BetaParams {
    pub fn new(alpha: f64, beta: f64) -> Self {
        Self {
            alpha,
            beta,
            comment: None,
        }
    }

    /// Create uniform (uninformative) Beta(1, 1) priors.
    pub fn uniform() -> Self {
        Self::new(1.0, 1.0)
    }

    /// Calculate the mean of the Beta distribution: alpha / (alpha + beta).
    pub fn mean(&self) -> f64 {
        self.alpha / (self.alpha + self.beta)
    }

    /// Calculate the variance of the Beta distribution.
    /// Formula: alpha * beta / ((alpha + beta)^2 * (alpha + beta + 1))
    pub fn variance(&self) -> f64 {
        let sum = self.alpha + self.beta;
        (self.alpha * self.beta) / (sum * sum * (sum + 1.0))
    }

    /// Create weakly informative Beta(2, 2) priors with mode at 0.5.
    pub fn weakly_informative() -> Self {
        Self::new(2.0, 2.0)
    }

    /// Calculate the mode of the Beta distribution.
    /// Returns None when alpha <= 1 or beta <= 1 (mode is undefined).
    /// Formula: (alpha - 1) / (alpha + beta - 2) when alpha > 1 and beta > 1.
    pub fn mode(&self) -> Option<f64> {
        if self.alpha <= 1.0 || self.beta <= 1.0 {
            None
        } else {
            Some((self.alpha - 1.0) / (self.alpha + self.beta - 2.0))
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.alpha <= 0.0 || self.beta <= 0.0 {
            return Err("alpha and beta must be positive".to_string());
        }
        Ok(())
    }
}

impl Default for BetaParams {
    fn default() -> Self {
        Self::uniform()
    }
}

/// Gamma distribution parameters: Gamma(shape, rate).
/// Note: uses RATE parameterization (rate = 1/scale).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GammaParams {
    pub shape: f64,
    pub rate: f64,

    #[serde(rename = "_comment", default)]
    pub comment: Option<String>,
}

impl GammaParams {
    pub fn new(shape: f64, rate: f64) -> Self {
        Self {
            shape,
            rate,
            comment: None,
        }
    }
}

/// Dirichlet distribution parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirichletParams {
    pub alpha: Vec<f64>,
}

/// Competing hazard rates for a class.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompetingHazards {
    #[serde(default)]
    pub finish: Option<GammaParams>,

    #[serde(default)]
    pub abandon: Option<GammaParams>,

    #[serde(default)]
    pub degrade: Option<GammaParams>,
}

/// Piecewise-constant hazard regime.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HazardRegime {
    pub name: String,

    #[serde(default)]
    pub description: Option<String>,

    pub gamma: GammaParams,

    #[serde(default)]
    pub trigger_conditions: Vec<String>,
}

/// Semi-Markov state duration parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemiMarkovParams {
    #[serde(default)]
    pub useful_duration: Option<GammaParams>,

    #[serde(default)]
    pub useful_bad_duration: Option<GammaParams>,

    #[serde(default)]
    pub abandoned_duration: Option<GammaParams>,

    #[serde(default)]
    pub zombie_duration: Option<GammaParams>,
}

/// Change-point detection priors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangePointParams {
    #[serde(default)]
    pub p_before: Option<BetaParams>,

    #[serde(default)]
    pub p_after: Option<BetaParams>,

    #[serde(default)]
    pub tau_geometric_p: Option<f64>,

    #[serde(rename = "_comment", default)]
    pub comment: Option<String>,
}

/// Causal intervention outcome priors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CausalInterventions {
    #[serde(default)]
    pub pause: Option<InterventionPriors>,

    #[serde(default)]
    pub throttle: Option<InterventionPriors>,

    #[serde(default)]
    pub kill: Option<InterventionPriors>,

    #[serde(default)]
    pub restart: Option<InterventionPriors>,
}

/// Per-class intervention outcome priors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterventionPriors {
    #[serde(default)]
    pub useful: Option<BetaParams>,

    #[serde(default)]
    pub useful_bad: Option<BetaParams>,

    #[serde(default)]
    pub abandoned: Option<BetaParams>,

    #[serde(default)]
    pub zombie: Option<BetaParams>,
}

/// Command category Dirichlet priors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandCategories {
    pub category_names: Vec<String>,

    #[serde(default)]
    pub useful: Option<DirichletParams>,

    #[serde(default)]
    pub useful_bad: Option<DirichletParams>,

    #[serde(default)]
    pub abandoned: Option<DirichletParams>,

    #[serde(default)]
    pub zombie: Option<DirichletParams>,

    #[serde(rename = "_comment", default)]
    pub comment: Option<String>,
}

/// Process state flag Dirichlet priors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateFlags {
    pub flag_names: Vec<String>,

    #[serde(default)]
    pub useful: Option<DirichletParams>,

    #[serde(default)]
    pub useful_bad: Option<DirichletParams>,

    #[serde(default)]
    pub abandoned: Option<DirichletParams>,

    #[serde(default)]
    pub zombie: Option<DirichletParams>,

    #[serde(rename = "_comment", default)]
    pub comment: Option<String>,
}

/// Hierarchical/empirical Bayes settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HierarchicalParams {
    #[serde(default)]
    pub shrinkage_enabled: Option<bool>,

    #[serde(default)]
    pub shrinkage_strength: Option<f64>,

    #[serde(rename = "_comment", default)]
    pub comment: Option<String>,
}

/// Robust Bayes / credal set settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RobustBayesParams {
    #[serde(default)]
    pub class_prior_bounds: Option<ClassPriorBounds>,

    #[serde(default)]
    pub safe_bayes_eta: Option<f64>,

    #[serde(default)]
    pub auto_eta_enabled: Option<bool>,

    #[serde(rename = "_comment", default)]
    pub comment: Option<String>,
}

/// Prior probability bounds for credal sets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassPriorBounds {
    #[serde(default)]
    pub useful: Option<PriorBounds>,

    #[serde(default)]
    pub useful_bad: Option<PriorBounds>,

    #[serde(default)]
    pub abandoned: Option<PriorBounds>,

    #[serde(default)]
    pub zombie: Option<PriorBounds>,
}

/// Lower/upper bounds for a class prior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriorBounds {
    pub lower: f64,
    pub upper: f64,
}

/// Error rate tracking priors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorRateParams {
    #[serde(default)]
    pub false_kill: Option<BetaParams>,

    #[serde(default)]
    pub false_spare: Option<BetaParams>,
}

/// BOCPD (Bayesian Online Change-Point Detection) settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BocpdParams {
    #[serde(default)]
    pub hazard_lambda: Option<f64>,

    #[serde(default)]
    pub min_run_length: Option<u32>,

    #[serde(rename = "_comment", default)]
    pub comment: Option<String>,
}

impl Priors {
    /// Load priors from a JSON file.
    pub fn from_file(path: &std::path::Path) -> Result<Self, crate::validate::ValidationError> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            crate::validate::ValidationError::IoError(format!(
                "Failed to read {}: {}",
                path.display(),
                e
            ))
        })?;

        Self::parse_json(&content)
    }

    /// Parse priors from a JSON string.
    pub fn parse_json(json: &str) -> Result<Self, crate::validate::ValidationError> {
        serde_json::from_str(json).map_err(|e| {
            crate::validate::ValidationError::ParseError(format!("Invalid JSON: {}", e))
        })
    }

    /// Get the prior probability for a class.
    pub fn class_prior(&self, class: &str) -> Option<f64> {
        match class {
            "useful" => Some(self.classes.useful.prior_prob),
            "useful_bad" => Some(self.classes.useful_bad.prior_prob),
            "abandoned" => Some(self.classes.abandoned.prior_prob),
            "zombie" => Some(self.classes.zombie.prior_prob),
            _ => None,
        }
    }

    /// Check if class priors sum to 1.0 (within tolerance).
    pub fn priors_sum_to_one(&self, tolerance: f64) -> bool {
        let sum = self.classes.useful.prior_prob
            + self.classes.useful_bad.prior_prob
            + self.classes.abandoned.prior_prob
            + self.classes.zombie.prior_prob;

        (sum - 1.0).abs() < tolerance
    }
}

/// Embedded default priors JSON for fallback.
const DEFAULT_PRIORS_JSON: &str = include_str!("schemas/priors.default.json");

impl Default for Priors {
    fn default() -> Self {
        // Parse the embedded default priors JSON
        // This should never fail since the JSON is embedded at compile time
        Self::parse_json(DEFAULT_PRIORS_JSON).expect("Embedded default priors JSON is invalid")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helper ─────────────────────────────────────────────────────

    fn minimal_priors_json() -> &'static str {
        r#"{
            "schema_version": "1.0.0",
            "classes": {
                "useful": {
                    "prior_prob": 0.7,
                    "cpu_beta": {"alpha": 2.0, "beta": 5.0},
                    "orphan_beta": {"alpha": 1.0, "beta": 20.0},
                    "tty_beta": {"alpha": 5.0, "beta": 3.0},
                    "net_beta": {"alpha": 3.0, "beta": 5.0}
                },
                "useful_bad": {
                    "prior_prob": 0.1,
                    "cpu_beta": {"alpha": 8.0, "beta": 2.0},
                    "orphan_beta": {"alpha": 2.0, "beta": 8.0},
                    "tty_beta": {"alpha": 3.0, "beta": 5.0},
                    "net_beta": {"alpha": 4.0, "beta": 4.0}
                },
                "abandoned": {
                    "prior_prob": 0.15,
                    "cpu_beta": {"alpha": 1.0, "beta": 10.0},
                    "orphan_beta": {"alpha": 8.0, "beta": 2.0},
                    "tty_beta": {"alpha": 1.0, "beta": 10.0},
                    "net_beta": {"alpha": 1.0, "beta": 8.0}
                },
                "zombie": {
                    "prior_prob": 0.05,
                    "cpu_beta": {"alpha": 1.0, "beta": 100.0},
                    "orphan_beta": {"alpha": 15.0, "beta": 1.0},
                    "tty_beta": {"alpha": 1.0, "beta": 50.0},
                    "net_beta": {"alpha": 1.0, "beta": 100.0}
                }
            }
        }"#
    }

    #[test]
    fn test_parse_minimal_priors() {
        let priors = Priors::parse_json(minimal_priors_json()).unwrap();
        assert_eq!(priors.schema_version, "1.0.0");
        assert!((priors.classes.useful.prior_prob - 0.7).abs() < 0.001);
        assert!(priors.priors_sum_to_one(0.01));
    }

    // ── BetaParams ─────────────────────────────────────────────────

    #[test]
    fn beta_new() {
        let b = BetaParams::new(3.0, 7.0);
        assert!((b.alpha - 3.0).abs() < f64::EPSILON);
        assert!((b.beta - 7.0).abs() < f64::EPSILON);
        assert!(b.comment.is_none());
    }

    #[test]
    fn beta_uniform() {
        let b = BetaParams::uniform();
        assert!((b.alpha - 1.0).abs() < f64::EPSILON);
        assert!((b.beta - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn beta_weakly_informative() {
        let b = BetaParams::weakly_informative();
        assert!((b.alpha - 2.0).abs() < f64::EPSILON);
        assert!((b.beta - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn beta_default_is_uniform() {
        let b = BetaParams::default();
        assert_eq!(b, BetaParams::uniform());
    }

    #[test]
    fn beta_mean_uniform() {
        let b = BetaParams::uniform();
        assert!((b.mean() - 0.5).abs() < 1e-12);
    }

    #[test]
    fn beta_mean_asymmetric() {
        let b = BetaParams::new(2.0, 8.0);
        assert!((b.mean() - 0.2).abs() < 1e-12);
    }

    #[test]
    fn beta_mean_concentrated() {
        let b = BetaParams::new(100.0, 1.0);
        // mean ~ 100/101 ≈ 0.9901
        assert!((b.mean() - 100.0 / 101.0).abs() < 1e-12);
    }

    #[test]
    fn beta_variance_uniform() {
        let b = BetaParams::uniform();
        // Var = 1*1 / (4 * 3) = 1/12
        assert!((b.variance() - 1.0 / 12.0).abs() < 1e-12);
    }

    #[test]
    fn beta_variance_symmetric() {
        let b = BetaParams::new(5.0, 5.0);
        // Var = 25 / (100 * 11) = 25/1100
        assert!((b.variance() - 25.0 / 1100.0).abs() < 1e-12);
    }

    #[test]
    fn beta_variance_decreases_with_concentration() {
        let weak = BetaParams::new(2.0, 2.0);
        let strong = BetaParams::new(20.0, 20.0);
        assert!(strong.variance() < weak.variance());
    }

    #[test]
    fn beta_mode_symmetric() {
        let b = BetaParams::new(5.0, 5.0);
        let mode = b.mode().unwrap();
        assert!((mode - 0.5).abs() < 1e-12);
    }

    #[test]
    fn beta_mode_asymmetric() {
        let b = BetaParams::new(3.0, 7.0);
        // mode = (3-1)/(3+7-2) = 2/8 = 0.25
        let mode = b.mode().unwrap();
        assert!((mode - 0.25).abs() < 1e-12);
    }

    #[test]
    fn beta_mode_none_alpha_le_1() {
        let b = BetaParams::new(1.0, 5.0);
        assert!(b.mode().is_none());
    }

    #[test]
    fn beta_mode_none_beta_le_1() {
        let b = BetaParams::new(5.0, 1.0);
        assert!(b.mode().is_none());
    }

    #[test]
    fn beta_mode_none_both_one() {
        let b = BetaParams::uniform();
        assert!(b.mode().is_none());
    }

    #[test]
    fn beta_validate_ok() {
        let b = BetaParams::new(1.0, 1.0);
        assert!(b.validate().is_ok());
    }

    #[test]
    fn beta_validate_zero_alpha() {
        let b = BetaParams::new(0.0, 1.0);
        assert!(b.validate().is_err());
    }

    #[test]
    fn beta_validate_negative_beta() {
        let b = BetaParams::new(1.0, -1.0);
        assert!(b.validate().is_err());
    }

    #[test]
    fn beta_validate_both_negative() {
        let b = BetaParams::new(-2.0, -3.0);
        let err = b.validate().unwrap_err();
        assert!(err.contains("positive"));
    }

    #[test]
    fn beta_serde_roundtrip() {
        let b = BetaParams::new(2.5, 7.3);
        let json = serde_json::to_string(&b).unwrap();
        let back: BetaParams = serde_json::from_str(&json).unwrap();
        assert_eq!(b, back);
    }

    #[test]
    fn beta_serde_with_comment() {
        let json = r#"{"alpha": 2.0, "beta": 3.0, "_comment": "test"}"#;
        let b: BetaParams = serde_json::from_str(json).unwrap();
        assert_eq!(b.comment.as_deref(), Some("test"));
    }

    #[test]
    fn beta_eq() {
        let a = BetaParams::new(1.0, 2.0);
        let b = BetaParams::new(1.0, 2.0);
        assert_eq!(a, b);
    }

    #[test]
    fn beta_ne() {
        let a = BetaParams::new(1.0, 2.0);
        let b = BetaParams::new(1.0, 3.0);
        assert_ne!(a, b);
    }

    // ── GammaParams ────────────────────────────────────────────────

    #[test]
    fn gamma_new() {
        let g = GammaParams::new(2.0, 0.5);
        assert!((g.shape - 2.0).abs() < f64::EPSILON);
        assert!((g.rate - 0.5).abs() < f64::EPSILON);
        assert!(g.comment.is_none());
    }

    #[test]
    fn gamma_serde_roundtrip() {
        let g = GammaParams::new(3.0, 1.5);
        let json = serde_json::to_string(&g).unwrap();
        let back: GammaParams = serde_json::from_str(&json).unwrap();
        assert!((back.shape - 3.0).abs() < f64::EPSILON);
        assert!((back.rate - 1.5).abs() < f64::EPSILON);
    }

    // ── DirichletParams ────────────────────────────────────────────

    #[test]
    fn dirichlet_serde_roundtrip() {
        let d = DirichletParams {
            alpha: vec![1.0, 2.0, 3.0],
        };
        let json = serde_json::to_string(&d).unwrap();
        let back: DirichletParams = serde_json::from_str(&json).unwrap();
        assert_eq!(back.alpha, vec![1.0, 2.0, 3.0]);
    }

    // ── Priors ─────────────────────────────────────────────────────

    #[test]
    fn priors_default_loads() {
        let priors = Priors::default();
        assert!(!priors.schema_version.is_empty());
        assert!(priors.priors_sum_to_one(0.001));
    }

    #[test]
    fn priors_default_has_four_classes() {
        let priors = Priors::default();
        assert!(priors.classes.useful.prior_prob > 0.0);
        assert!(priors.classes.useful_bad.prior_prob > 0.0);
        assert!(priors.classes.abandoned.prior_prob > 0.0);
        assert!(priors.classes.zombie.prior_prob > 0.0);
    }

    #[test]
    fn priors_class_prior_useful() {
        let priors = Priors::parse_json(minimal_priors_json()).unwrap();
        let p = priors.class_prior("useful").unwrap();
        assert!((p - 0.7).abs() < 1e-6);
    }

    #[test]
    fn priors_class_prior_useful_bad() {
        let priors = Priors::parse_json(minimal_priors_json()).unwrap();
        let p = priors.class_prior("useful_bad").unwrap();
        assert!((p - 0.1).abs() < 1e-6);
    }

    #[test]
    fn priors_class_prior_abandoned() {
        let priors = Priors::parse_json(minimal_priors_json()).unwrap();
        let p = priors.class_prior("abandoned").unwrap();
        assert!((p - 0.15).abs() < 1e-6);
    }

    #[test]
    fn priors_class_prior_zombie() {
        let priors = Priors::parse_json(minimal_priors_json()).unwrap();
        let p = priors.class_prior("zombie").unwrap();
        assert!((p - 0.05).abs() < 1e-6);
    }

    #[test]
    fn priors_class_prior_unknown_none() {
        let priors = Priors::parse_json(minimal_priors_json()).unwrap();
        assert!(priors.class_prior("unknown").is_none());
    }

    #[test]
    fn priors_class_prior_empty_string_none() {
        let priors = Priors::parse_json(minimal_priors_json()).unwrap();
        assert!(priors.class_prior("").is_none());
    }

    #[test]
    fn priors_sum_to_one_exact() {
        let priors = Priors::parse_json(minimal_priors_json()).unwrap();
        // 0.7 + 0.1 + 0.15 + 0.05 = 1.0
        assert!(priors.priors_sum_to_one(1e-12));
    }

    #[test]
    fn priors_sum_to_one_tight_tolerance() {
        let priors = Priors::parse_json(minimal_priors_json()).unwrap();
        assert!(priors.priors_sum_to_one(0.001));
    }

    #[test]
    fn priors_sum_not_one_fails() {
        let json = r#"{
            "schema_version": "1.0.0",
            "classes": {
                "useful": { "prior_prob": 0.5, "cpu_beta": {"alpha":1,"beta":1}, "orphan_beta": {"alpha":1,"beta":1}, "tty_beta": {"alpha":1,"beta":1}, "net_beta": {"alpha":1,"beta":1} },
                "useful_bad": { "prior_prob": 0.1, "cpu_beta": {"alpha":1,"beta":1}, "orphan_beta": {"alpha":1,"beta":1}, "tty_beta": {"alpha":1,"beta":1}, "net_beta": {"alpha":1,"beta":1} },
                "abandoned": { "prior_prob": 0.1, "cpu_beta": {"alpha":1,"beta":1}, "orphan_beta": {"alpha":1,"beta":1}, "tty_beta": {"alpha":1,"beta":1}, "net_beta": {"alpha":1,"beta":1} },
                "zombie": { "prior_prob": 0.1, "cpu_beta": {"alpha":1,"beta":1}, "orphan_beta": {"alpha":1,"beta":1}, "tty_beta": {"alpha":1,"beta":1}, "net_beta": {"alpha":1,"beta":1} }
            }
        }"#;
        let priors = Priors::parse_json(json).unwrap();
        // Sum = 0.8, fails with tight tolerance
        assert!(!priors.priors_sum_to_one(0.01));
    }

    #[test]
    fn priors_parse_invalid_json() {
        let result = Priors::parse_json("{not valid json}");
        assert!(result.is_err());
    }

    #[test]
    fn priors_parse_missing_classes() {
        let result = Priors::parse_json(r#"{"schema_version": "1.0.0"}"#);
        assert!(result.is_err());
    }

    #[test]
    fn priors_serde_roundtrip() {
        let priors = Priors::parse_json(minimal_priors_json()).unwrap();
        let json = serde_json::to_string(&priors).unwrap();
        let back = Priors::parse_json(&json).unwrap();
        assert_eq!(back.schema_version, "1.0.0");
        assert!((back.classes.useful.prior_prob - 0.7).abs() < 1e-6);
    }

    #[test]
    fn priors_optional_fields_default_none() {
        let priors = Priors::parse_json(minimal_priors_json()).unwrap();
        assert!(priors.description.is_none());
        assert!(priors.host_profile.is_none());
        assert!(priors.semi_markov.is_none());
        assert!(priors.change_point.is_none());
        assert!(priors.causal_interventions.is_none());
        assert!(priors.command_categories.is_none());
        assert!(priors.state_flags.is_none());
        assert!(priors.hierarchical.is_none());
        assert!(priors.robust_bayes.is_none());
        assert!(priors.error_rate.is_none());
        assert!(priors.bocpd.is_none());
    }

    #[test]
    fn priors_hazard_regimes_default_empty() {
        let priors = Priors::parse_json(minimal_priors_json()).unwrap();
        assert!(priors.hazard_regimes.is_empty());
    }

    #[test]
    fn priors_from_file_nonexistent() {
        let result = Priors::from_file(std::path::Path::new("/nonexistent/priors.json"));
        assert!(result.is_err());
    }

    // ── ClassParams ────────────────────────────────────────────────

    #[test]
    fn class_params_optional_fields() {
        let priors = Priors::parse_json(minimal_priors_json()).unwrap();
        let useful = &priors.classes.useful;
        assert!(useful.runtime_gamma.is_none());
        assert!(useful.io_active_beta.is_none());
        assert!(useful.hazard_gamma.is_none());
        assert!(useful.competing_hazards.is_none());
    }

    // ── Extended types serde ───────────────────────────────────────

    #[test]
    fn competing_hazards_serde() {
        let ch = CompetingHazards {
            finish: Some(GammaParams::new(2.0, 0.1)),
            abandon: None,
            degrade: Some(GammaParams::new(1.0, 0.5)),
        };
        let json = serde_json::to_string(&ch).unwrap();
        let back: CompetingHazards = serde_json::from_str(&json).unwrap();
        assert!(back.finish.is_some());
        assert!(back.abandon.is_none());
        assert!(back.degrade.is_some());
    }

    #[test]
    fn hazard_regime_serde() {
        let hr = HazardRegime {
            name: "startup".to_string(),
            description: Some("Initial phase".to_string()),
            gamma: GammaParams::new(1.0, 0.01),
            trigger_conditions: vec!["cpu > 80".to_string()],
        };
        let json = serde_json::to_string(&hr).unwrap();
        let back: HazardRegime = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "startup");
        assert_eq!(back.trigger_conditions.len(), 1);
    }

    #[test]
    fn semi_markov_serde() {
        let sm = SemiMarkovParams {
            useful_duration: Some(GammaParams::new(2.0, 0.1)),
            useful_bad_duration: None,
            abandoned_duration: None,
            zombie_duration: Some(GammaParams::new(1.0, 0.01)),
        };
        let json = serde_json::to_string(&sm).unwrap();
        let back: SemiMarkovParams = serde_json::from_str(&json).unwrap();
        assert!(back.useful_duration.is_some());
        assert!(back.zombie_duration.is_some());
    }

    #[test]
    fn change_point_serde() {
        let cp = ChangePointParams {
            p_before: Some(BetaParams::new(2.0, 8.0)),
            p_after: Some(BetaParams::new(8.0, 2.0)),
            tau_geometric_p: Some(0.01),
            comment: None,
        };
        let json = serde_json::to_string(&cp).unwrap();
        let back: ChangePointParams = serde_json::from_str(&json).unwrap();
        assert!(back.p_before.is_some());
        assert!((back.tau_geometric_p.unwrap() - 0.01).abs() < 1e-12);
    }

    #[test]
    fn hierarchical_params_serde() {
        let hp = HierarchicalParams {
            shrinkage_enabled: Some(true),
            shrinkage_strength: Some(0.5),
            comment: None,
        };
        let json = serde_json::to_string(&hp).unwrap();
        let back: HierarchicalParams = serde_json::from_str(&json).unwrap();
        assert_eq!(back.shrinkage_enabled, Some(true));
        assert!((back.shrinkage_strength.unwrap() - 0.5).abs() < 1e-12);
    }

    #[test]
    fn robust_bayes_serde() {
        let rb = RobustBayesParams {
            class_prior_bounds: Some(ClassPriorBounds {
                useful: Some(PriorBounds {
                    lower: 0.5,
                    upper: 0.9,
                }),
                useful_bad: None,
                abandoned: None,
                zombie: None,
            }),
            safe_bayes_eta: Some(0.1),
            auto_eta_enabled: Some(false),
            comment: None,
        };
        let json = serde_json::to_string(&rb).unwrap();
        let back: RobustBayesParams = serde_json::from_str(&json).unwrap();
        assert!((back.safe_bayes_eta.unwrap() - 0.1).abs() < 1e-12);
        let bounds = back.class_prior_bounds.unwrap();
        let ub = bounds.useful.unwrap();
        assert!((ub.lower - 0.5).abs() < 1e-12);
        assert!((ub.upper - 0.9).abs() < 1e-12);
    }

    #[test]
    fn error_rate_serde() {
        let er = ErrorRateParams {
            false_kill: Some(BetaParams::new(1.0, 99.0)),
            false_spare: Some(BetaParams::new(1.0, 9.0)),
        };
        let json = serde_json::to_string(&er).unwrap();
        let back: ErrorRateParams = serde_json::from_str(&json).unwrap();
        assert!(back.false_kill.is_some());
        assert!(back.false_spare.is_some());
    }

    #[test]
    fn bocpd_serde() {
        let bp = BocpdParams {
            hazard_lambda: Some(100.0),
            min_run_length: Some(5),
            comment: None,
        };
        let json = serde_json::to_string(&bp).unwrap();
        let back: BocpdParams = serde_json::from_str(&json).unwrap();
        assert!((back.hazard_lambda.unwrap() - 100.0).abs() < 1e-12);
        assert_eq!(back.min_run_length, Some(5));
    }

    #[test]
    fn prior_bounds_serde() {
        let pb = PriorBounds {
            lower: 0.01,
            upper: 0.99,
        };
        let json = serde_json::to_string(&pb).unwrap();
        let back: PriorBounds = serde_json::from_str(&json).unwrap();
        assert!((back.lower - 0.01).abs() < 1e-12);
        assert!((back.upper - 0.99).abs() < 1e-12);
    }

    #[test]
    fn intervention_priors_serde() {
        let ip = InterventionPriors {
            useful: Some(BetaParams::new(1.0, 1.0)),
            useful_bad: None,
            abandoned: Some(BetaParams::new(2.0, 3.0)),
            zombie: None,
        };
        let json = serde_json::to_string(&ip).unwrap();
        let back: InterventionPriors = serde_json::from_str(&json).unwrap();
        assert!(back.useful.is_some());
        assert!(back.useful_bad.is_none());
        assert!(back.abandoned.is_some());
    }

    #[test]
    fn causal_interventions_serde() {
        let ci = CausalInterventions {
            pause: Some(InterventionPriors {
                useful: Some(BetaParams::new(1.0, 1.0)),
                useful_bad: None,
                abandoned: None,
                zombie: None,
            }),
            throttle: None,
            kill: None,
            restart: None,
        };
        let json = serde_json::to_string(&ci).unwrap();
        let back: CausalInterventions = serde_json::from_str(&json).unwrap();
        assert!(back.pause.is_some());
        assert!(back.throttle.is_none());
    }

    #[test]
    fn command_categories_serde() {
        let cc = CommandCategories {
            category_names: vec!["daemon".to_string(), "batch".to_string()],
            useful: Some(DirichletParams {
                alpha: vec![2.0, 1.0],
            }),
            useful_bad: None,
            abandoned: None,
            zombie: None,
            comment: None,
        };
        let json = serde_json::to_string(&cc).unwrap();
        let back: CommandCategories = serde_json::from_str(&json).unwrap();
        assert_eq!(back.category_names.len(), 2);
        assert_eq!(back.useful.unwrap().alpha, vec![2.0, 1.0]);
    }

    #[test]
    fn state_flags_serde() {
        let sf = StateFlags {
            flag_names: vec!["sleeping".to_string(), "stopped".to_string()],
            useful: None,
            useful_bad: None,
            abandoned: None,
            zombie: Some(DirichletParams {
                alpha: vec![5.0, 1.0],
            }),
            comment: Some("test".to_string()),
        };
        let json = serde_json::to_string(&sf).unwrap();
        let back: StateFlags = serde_json::from_str(&json).unwrap();
        assert_eq!(back.flag_names.len(), 2);
        assert!(back.zombie.is_some());
        assert_eq!(back.comment.as_deref(), Some("test"));
    }
}
