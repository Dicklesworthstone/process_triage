//! Empirical Bayes hyperparameter refits from shadow-mode logs.
//!
//! Implements conjugate updates for Beta, Gamma, and Dirichlet distributions
//! used in process classification priors. Updates are conservative (bounded
//! change per round), versioned, and support rollback.
//!
//! # Conjugate Update Rules
//!
//! - **Beta(α, β)**: observe k successes in n trials → Beta(α+k, β+n-k)
//! - **Gamma(shape, rate)**: observe n values with sum S → Gamma(shape+n, rate+S)
//!   (when used as conjugate prior for exponential rate)
//! - **Dirichlet(α₁..αₖ)**: observe counts c₁..cₖ → Dirichlet(α₁+c₁, ..., αₖ+cₖ)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Configuration for empirical Bayes refits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmpiricalBayesConfig {
    /// Maximum relative change per parameter per refit (0.0 to 1.0).
    pub max_change_fraction: f64,
    /// Minimum observations before any refit is attempted.
    pub min_observations: usize,
    /// Discount factor for new evidence (0.0 = ignore, 1.0 = full conjugate).
    /// Controls how aggressively new data updates priors.
    pub learning_rate: f64,
}

impl Default for EmpiricalBayesConfig {
    fn default() -> Self {
        Self {
            max_change_fraction: 0.3,
            min_observations: 20,
            learning_rate: 0.5,
        }
    }
}

/// A snapshot of prior parameters before/after a refit, for rollback.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriorSnapshot {
    /// Unique version identifier.
    pub version: u64,
    /// When this snapshot was created.
    pub created_at: DateTime<Utc>,
    /// Reason for the refit.
    pub reason: String,
    /// Number of observations used.
    pub observation_count: usize,
    /// Parameter values: path → value.
    pub parameters: HashMap<String, ParamValue>,
}

/// A parameter value that can be a Beta, Gamma, Dirichlet, or scalar.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ParamValue {
    Beta { alpha: f64, beta: f64 },
    Gamma { shape: f64, rate: f64 },
    Dirichlet { alpha: Vec<f64> },
    Scalar(f64),
}

/// Observation summary for a single Beta-distributed feature.
#[derive(Debug, Clone)]
pub struct BetaObservation {
    /// Feature path (e.g., "classes.abandoned.cpu_beta").
    pub path: String,
    /// Number of successes (feature present).
    pub successes: u64,
    /// Number of trials.
    pub trials: u64,
}

/// Observation summary for a Gamma-distributed feature.
#[derive(Debug, Clone)]
pub struct GammaObservation {
    /// Parameter path (e.g., "classes.useful.runtime_gamma").
    pub path: String,
    /// Number of observations.
    pub count: u64,
    /// Sum of observed values.
    pub sum: f64,
}

/// Observation summary for a Dirichlet-distributed feature.
#[derive(Debug, Clone)]
pub struct DirichletObservation {
    /// Parameter path (e.g., "command_categories.abandoned").
    pub path: String,
    /// Counts per category.
    pub counts: Vec<u64>,
}

/// A single proposed parameter change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamChange {
    /// Parameter path.
    pub path: String,
    /// Value before refit.
    pub before: ParamValue,
    /// Value after refit.
    pub after: ParamValue,
    /// Whether the change was clamped by safety bounds.
    pub clamped: bool,
}

/// Result of an empirical Bayes refit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefitResult {
    /// When the refit was computed.
    pub computed_at: DateTime<Utc>,
    /// Configuration used.
    pub config: EmpiricalBayesConfig,
    /// Snapshot of parameters before refit (for rollback).
    pub snapshot_before: PriorSnapshot,
    /// Proposed changes.
    pub changes: Vec<ParamChange>,
    /// Whether any changes are proposed.
    pub has_changes: bool,
}

/// Perform a conjugate Beta update with bounded learning rate.
///
/// Returns updated (alpha, beta) and whether the change was clamped.
pub fn conjugate_beta_update(
    prior_alpha: f64,
    prior_beta: f64,
    successes: u64,
    trials: u64,
    config: &EmpiricalBayesConfig,
) -> (f64, f64, bool) {
    if trials == 0 {
        return (prior_alpha, prior_beta, false);
    }

    let failures = trials - successes;
    let lr = config.learning_rate;

    // Discounted conjugate update.
    let raw_alpha = prior_alpha + lr * successes as f64;
    let raw_beta = prior_beta + lr * failures as f64;

    // Clamp each parameter's relative change.
    let (alpha, clamped_a) = clamp_param(prior_alpha, raw_alpha, config.max_change_fraction);
    let (beta, clamped_b) = clamp_param(prior_beta, raw_beta, config.max_change_fraction);

    (alpha, beta, clamped_a || clamped_b)
}

/// Perform a conjugate Gamma update with bounded learning rate.
///
/// For Gamma(shape, rate) as conjugate prior for exponential rate parameter:
/// posterior = Gamma(shape + n, rate + sum_x).
///
/// Returns updated (shape, rate) and whether the change was clamped.
pub fn conjugate_gamma_update(
    prior_shape: f64,
    prior_rate: f64,
    count: u64,
    sum: f64,
    config: &EmpiricalBayesConfig,
) -> (f64, f64, bool) {
    if count == 0 {
        return (prior_shape, prior_rate, false);
    }

    let lr = config.learning_rate;

    let raw_shape = prior_shape + lr * count as f64;
    let raw_rate = prior_rate + lr * sum;

    let (shape, clamped_s) = clamp_param(prior_shape, raw_shape, config.max_change_fraction);
    let (rate, clamped_r) = clamp_param(prior_rate, raw_rate, config.max_change_fraction);

    (shape, rate, clamped_s || clamped_r)
}

/// Perform a conjugate Dirichlet update with bounded learning rate.
///
/// Dirichlet(α) + counts c → Dirichlet(α + c).
///
/// Returns updated alpha vector and whether any component was clamped.
pub fn conjugate_dirichlet_update(
    prior_alpha: &[f64],
    counts: &[u64],
    config: &EmpiricalBayesConfig,
) -> (Vec<f64>, bool) {
    assert_eq!(
        prior_alpha.len(),
        counts.len(),
        "Dirichlet alpha and counts must have same length"
    );

    let lr = config.learning_rate;
    let mut any_clamped = false;
    let mut result = Vec::with_capacity(prior_alpha.len());

    for (a, c) in prior_alpha.iter().zip(counts.iter()) {
        let raw = a + lr * *c as f64;
        let (val, clamped) = clamp_param(*a, raw, config.max_change_fraction);
        if clamped {
            any_clamped = true;
        }
        result.push(val);
    }

    (result, any_clamped)
}

/// Compute a complete refit from observation summaries.
pub fn compute_refit(
    beta_obs: &[BetaObservation],
    gamma_obs: &[GammaObservation],
    dirichlet_obs: &[DirichletObservation],
    current_params: &HashMap<String, ParamValue>,
    config: &EmpiricalBayesConfig,
    version: u64,
) -> RefitResult {
    let total_obs: u64 = beta_obs.iter().map(|o| o.trials).sum::<u64>()
        + gamma_obs.iter().map(|o| o.count).sum::<u64>()
        + dirichlet_obs.iter().map(|o| o.counts.iter().sum::<u64>()).sum::<u64>();

    let snapshot_before = PriorSnapshot {
        version,
        created_at: Utc::now(),
        reason: "pre-refit snapshot".to_string(),
        observation_count: total_obs as usize,
        parameters: current_params.clone(),
    };

    let mut changes = Vec::new();

    if (total_obs as usize) < config.min_observations {
        return RefitResult {
            computed_at: Utc::now(),
            config: config.clone(),
            snapshot_before,
            changes,
            has_changes: false,
        };
    }

    // Process Beta observations.
    for obs in beta_obs {
        if let Some(ParamValue::Beta { alpha, beta }) = current_params.get(&obs.path) {
            let (new_alpha, new_beta, clamped) =
                conjugate_beta_update(*alpha, *beta, obs.successes, obs.trials, config);

            if (new_alpha - alpha).abs() > 1e-6 || (new_beta - beta).abs() > 1e-6 {
                changes.push(ParamChange {
                    path: obs.path.clone(),
                    before: ParamValue::Beta {
                        alpha: *alpha,
                        beta: *beta,
                    },
                    after: ParamValue::Beta {
                        alpha: new_alpha,
                        beta: new_beta,
                    },
                    clamped,
                });
            }
        }
    }

    // Process Gamma observations.
    for obs in gamma_obs {
        if let Some(ParamValue::Gamma { shape, rate }) = current_params.get(&obs.path) {
            let (new_shape, new_rate, clamped) =
                conjugate_gamma_update(*shape, *rate, obs.count, obs.sum, config);

            if (new_shape - shape).abs() > 1e-6 || (new_rate - rate).abs() > 1e-6 {
                changes.push(ParamChange {
                    path: obs.path.clone(),
                    before: ParamValue::Gamma {
                        shape: *shape,
                        rate: *rate,
                    },
                    after: ParamValue::Gamma {
                        shape: new_shape,
                        rate: new_rate,
                    },
                    clamped,
                });
            }
        }
    }

    // Process Dirichlet observations.
    for obs in dirichlet_obs {
        if let Some(ParamValue::Dirichlet { alpha }) = current_params.get(&obs.path) {
            if alpha.len() == obs.counts.len() {
                let (new_alpha, clamped) =
                    conjugate_dirichlet_update(alpha, &obs.counts, config);

                let changed = alpha
                    .iter()
                    .zip(new_alpha.iter())
                    .any(|(a, b)| (a - b).abs() > 1e-6);
                if changed {
                    changes.push(ParamChange {
                        path: obs.path.clone(),
                        before: ParamValue::Dirichlet {
                            alpha: alpha.clone(),
                        },
                        after: ParamValue::Dirichlet { alpha: new_alpha },
                        clamped,
                    });
                }
            }
        }
    }

    let has_changes = !changes.is_empty();

    RefitResult {
        computed_at: Utc::now(),
        config: config.clone(),
        snapshot_before,
        changes,
        has_changes,
    }
}

/// Clamp a parameter's change to within max_change_fraction of current.
fn clamp_param(current: f64, proposed: f64, max_fraction: f64) -> (f64, bool) {
    if current <= 0.0 {
        return (proposed.max(0.001), false);
    }

    let max_delta = current * max_fraction;
    let lo = (current - max_delta).max(0.001);
    let hi = current + max_delta;

    if proposed < lo {
        (lo, true)
    } else if proposed > hi {
        (hi, true)
    } else {
        (proposed, false)
    }
}

/// Version tracker for prior snapshots (rollback support).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriorVersionHistory {
    /// Ordered list of snapshots, newest last.
    pub snapshots: Vec<PriorSnapshot>,
    /// Current version number.
    pub current_version: u64,
}

impl PriorVersionHistory {
    pub fn new() -> Self {
        Self {
            snapshots: Vec::new(),
            current_version: 0,
        }
    }

    /// Record a new snapshot and bump the version.
    pub fn record(&mut self, mut snapshot: PriorSnapshot) -> u64 {
        self.current_version += 1;
        snapshot.version = self.current_version;
        self.snapshots.push(snapshot);
        self.current_version
    }

    /// Get the snapshot at a specific version for rollback.
    pub fn get_version(&self, version: u64) -> Option<&PriorSnapshot> {
        self.snapshots.iter().find(|s| s.version == version)
    }

    /// Get the most recent snapshot before the current one (for rollback).
    pub fn previous(&self) -> Option<&PriorSnapshot> {
        if self.snapshots.len() >= 2 {
            self.snapshots.get(self.snapshots.len() - 2)
        } else {
            None
        }
    }
}

impl Default for PriorVersionHistory {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conjugate_beta_update_basic() {
        let config = EmpiricalBayesConfig {
            learning_rate: 1.0,
            max_change_fraction: 10.0, // No clamping
            ..Default::default()
        };

        // Beta(2, 5) + 10 successes in 20 trials = Beta(12, 15)
        let (alpha, beta, clamped) = conjugate_beta_update(2.0, 5.0, 10, 20, &config);
        assert!(!clamped);
        assert!((alpha - 12.0).abs() < 1e-9);
        assert!((beta - 15.0).abs() < 1e-9);
    }

    #[test]
    fn test_conjugate_beta_update_with_learning_rate() {
        let config = EmpiricalBayesConfig {
            learning_rate: 0.5,
            max_change_fraction: 10.0,
            ..Default::default()
        };

        // Beta(2, 5) + 0.5*(10 successes, 10 failures) = Beta(7, 10)
        let (alpha, beta, _) = conjugate_beta_update(2.0, 5.0, 10, 20, &config);
        assert!((alpha - 7.0).abs() < 1e-9);
        assert!((beta - 10.0).abs() < 1e-9);
    }

    #[test]
    fn test_conjugate_beta_update_clamped() {
        let config = EmpiricalBayesConfig {
            learning_rate: 1.0,
            max_change_fraction: 0.3,
            ..Default::default()
        };

        // Beta(2, 5) + 100 successes in 100 trials → would be Beta(102, 5)
        // But clamped: alpha can only go to 2 + 0.3*2 = 2.6
        let (alpha, _, clamped) = conjugate_beta_update(2.0, 5.0, 100, 100, &config);
        assert!(clamped);
        assert!((alpha - 2.6).abs() < 1e-9);
    }

    #[test]
    fn test_conjugate_gamma_update() {
        let config = EmpiricalBayesConfig {
            learning_rate: 1.0,
            max_change_fraction: 10.0,
            ..Default::default()
        };

        // Gamma(3, 1) + 5 observations summing to 10 = Gamma(8, 11)
        let (shape, rate, clamped) = conjugate_gamma_update(3.0, 1.0, 5, 10.0, &config);
        assert!(!clamped);
        assert!((shape - 8.0).abs() < 1e-9);
        assert!((rate - 11.0).abs() < 1e-9);
    }

    #[test]
    fn test_conjugate_dirichlet_update() {
        let config = EmpiricalBayesConfig {
            learning_rate: 1.0,
            max_change_fraction: 10.0,
            ..Default::default()
        };

        let prior = vec![1.0, 1.0, 1.0];
        let counts = vec![5, 3, 2];
        let (result, clamped) = conjugate_dirichlet_update(&prior, &counts, &config);
        assert!(!clamped);
        assert!((result[0] - 6.0).abs() < 1e-9);
        assert!((result[1] - 4.0).abs() < 1e-9);
        assert!((result[2] - 3.0).abs() < 1e-9);
    }

    #[test]
    fn test_compute_refit_insufficient_data() {
        let config = EmpiricalBayesConfig {
            min_observations: 50,
            ..Default::default()
        };

        let beta_obs = vec![BetaObservation {
            path: "classes.abandoned.cpu_beta".to_string(),
            successes: 3,
            trials: 5,
        }];

        let mut params = HashMap::new();
        params.insert(
            "classes.abandoned.cpu_beta".to_string(),
            ParamValue::Beta {
                alpha: 1.0,
                beta: 10.0,
            },
        );

        let result = compute_refit(&beta_obs, &[], &[], &params, &config, 0);
        assert!(!result.has_changes);
    }

    #[test]
    fn test_compute_refit_with_data() {
        let config = EmpiricalBayesConfig {
            min_observations: 5,
            learning_rate: 0.5,
            max_change_fraction: 50.0,
            ..Default::default()
        };

        let beta_obs = vec![BetaObservation {
            path: "classes.abandoned.cpu_beta".to_string(),
            successes: 30,
            trials: 100,
        }];

        let mut params = HashMap::new();
        params.insert(
            "classes.abandoned.cpu_beta".to_string(),
            ParamValue::Beta {
                alpha: 1.0,
                beta: 10.0,
            },
        );

        let result = compute_refit(&beta_obs, &[], &[], &params, &config, 0);
        assert!(result.has_changes);
        assert_eq!(result.changes.len(), 1);

        match &result.changes[0].after {
            ParamValue::Beta { alpha, beta } => {
                // 1.0 + 0.5*30 = 16.0, 10.0 + 0.5*70 = 45.0
                assert!((alpha - 16.0).abs() < 1e-6);
                assert!((beta - 45.0).abs() < 1e-6);
            }
            _ => panic!("Expected Beta"),
        }
    }

    #[test]
    fn test_version_history() {
        let mut history = PriorVersionHistory::new();

        let snap1 = PriorSnapshot {
            version: 0,
            created_at: Utc::now(),
            reason: "initial".to_string(),
            observation_count: 100,
            parameters: HashMap::new(),
        };

        let v1 = history.record(snap1);
        assert_eq!(v1, 1);

        let snap2 = PriorSnapshot {
            version: 0,
            created_at: Utc::now(),
            reason: "refit round 1".to_string(),
            observation_count: 200,
            parameters: HashMap::new(),
        };

        let v2 = history.record(snap2);
        assert_eq!(v2, 2);

        assert!(history.previous().is_some());
        assert_eq!(history.previous().unwrap().version, 1);
        assert!(history.get_version(1).is_some());
        assert!(history.get_version(3).is_none());
    }

    #[test]
    fn test_zero_observations_noop() {
        let config = EmpiricalBayesConfig::default();
        let (a, b, c) = conjugate_beta_update(2.0, 5.0, 0, 0, &config);
        assert!((a - 2.0).abs() < 1e-9);
        assert!((b - 5.0).abs() < 1e-9);
        assert!(!c);

        let (s, r, c) = conjugate_gamma_update(3.0, 1.0, 0, 0.0, &config);
        assert!((s - 3.0).abs() < 1e-9);
        assert!((r - 1.0).abs() < 1e-9);
        assert!(!c);
    }
}
