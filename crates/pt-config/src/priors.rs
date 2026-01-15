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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BetaParams {
    pub alpha: f64,
    pub beta: f64,

    #[serde(rename = "_comment", default)]
    pub comment: Option<String>,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_priors() {
        let json = r#"{
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
        }"#;

        let priors = Priors::parse_json(json).unwrap();
        assert_eq!(priors.schema_version, "1.0.0");
        assert!((priors.classes.useful.prior_prob - 0.7).abs() < 0.001);
        assert!(priors.priors_sum_to_one(0.01));
    }
}
