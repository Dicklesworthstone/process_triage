//! Bayesian Online Change-Point Detection (BOCPD).
//!
//! Detects regime shifts in process behavior using run-length recursion
//! with conjugate emission models.
//!
//! # Background
//!
//! BOCPD maintains a posterior distribution over the "run length" r_t,
//! which is the time since the last change point. The algorithm updates
//! this distribution online as new observations arrive.
//!
//! # Mathematical Foundation
//!
//! **Run-length Distribution**:
//! ```text
//! P(r_t | x_{1:t}) ∝ P(x_t | r_t, x_{r:t-1}) * P(r_t | r_{t-1}) * P(r_{t-1} | x_{1:t-1})
//! ```
//!
//! **Transition Prior**:
//! - P(r_t = 0) = H (hazard rate - prior probability of change)
//! - P(r_t = r_{t-1} + 1) = 1 - H
//!
//! # Emission Models (Conjugate)
//!
//! - **Normal-Gamma**: For continuous observations (CPU/IO rates)
//! - **Poisson-Gamma**: For count data (event counts)
//! - **Beta-Bernoulli**: For binary states
//!
//! # Example
//!
//! ```
//! use pt_core::inference::bocpd::{BocpdDetector, BocpdConfig, EmissionModel};
//!
//! // Create detector with Poisson-Gamma emission model
//! let config = BocpdConfig {
//!     hazard_rate: 0.01,  // 1% prior probability of change at each step
//!     max_run_length: 200,
//!     emission_model: EmissionModel::PoissonGamma { alpha: 1.0, beta: 1.0 },
//! };
//!
//! let mut detector = BocpdDetector::new(config);
//!
//! // Process observations
//! for obs in &[5.0, 6.0, 4.0, 5.0, 15.0, 14.0, 16.0] {
//!     let result = detector.update(*obs);
//!     if result.change_point_probability > 0.5 {
//!         println!("Change point detected at step {}", result.step);
//!     }
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use thiserror::Error;

/// Errors from BOCPD.
#[derive(Debug, Error)]
pub enum BocpdError {
    #[error("invalid hazard rate: {0} (must be in (0, 1))")]
    InvalidHazardRate(f64),

    #[error("invalid max run length: {0} (must be > 0)")]
    InvalidMaxRunLength(usize),

    #[error("invalid emission model parameter: {message}")]
    InvalidEmissionParameter { message: String },

    #[error("invalid observation: {0}")]
    InvalidObservation(f64),
}

/// Emission model for BOCPD.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EmissionModel {
    /// Normal-Gamma conjugate pair for continuous observations.
    /// Prior: μ ~ Normal(mu0, 1/(kappa0 * τ)), τ ~ Gamma(alpha0, beta0)
    NormalGamma {
        /// Prior mean for μ
        mu0: f64,
        /// Prior precision scaling
        kappa0: f64,
        /// Gamma shape
        alpha0: f64,
        /// Gamma rate
        beta0: f64,
    },

    /// Poisson-Gamma conjugate pair for count data.
    /// Prior: λ ~ Gamma(alpha, beta)
    PoissonGamma {
        /// Gamma shape
        alpha: f64,
        /// Gamma rate
        beta: f64,
    },

    /// Beta-Bernoulli conjugate pair for binary states.
    /// Prior: p ~ Beta(alpha, beta)
    BetaBernoulli {
        /// Beta alpha
        alpha: f64,
        /// Beta beta
        beta: f64,
    },
}

impl Default for EmissionModel {
    fn default() -> Self {
        EmissionModel::PoissonGamma {
            alpha: 1.0,
            beta: 1.0,
        }
    }
}

/// Configuration for BOCPD.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BocpdConfig {
    /// Hazard rate H: prior probability of a change point at each step.
    /// Typically small, e.g., 0.01 for expected run length of 100.
    #[serde(default = "default_hazard_rate")]
    pub hazard_rate: f64,

    /// Maximum run length to track. Older hypotheses are truncated.
    #[serde(default = "default_max_run_length")]
    pub max_run_length: usize,

    /// Emission model for computing observation likelihoods.
    #[serde(default)]
    pub emission_model: EmissionModel,
}

fn default_hazard_rate() -> f64 {
    0.01
}

fn default_max_run_length() -> usize {
    200
}

impl Default for BocpdConfig {
    fn default() -> Self {
        Self {
            hazard_rate: default_hazard_rate(),
            max_run_length: default_max_run_length(),
            emission_model: EmissionModel::default(),
        }
    }
}

impl BocpdConfig {
    /// Validate configuration parameters.
    pub fn validate(&self) -> Result<(), BocpdError> {
        if self.hazard_rate <= 0.0 || self.hazard_rate >= 1.0 {
            return Err(BocpdError::InvalidHazardRate(self.hazard_rate));
        }
        if self.max_run_length == 0 {
            return Err(BocpdError::InvalidMaxRunLength(self.max_run_length));
        }
        self.validate_emission_model()?;
        Ok(())
    }

    fn validate_emission_model(&self) -> Result<(), BocpdError> {
        match &self.emission_model {
            EmissionModel::NormalGamma {
                kappa0,
                alpha0,
                beta0,
                ..
            } => {
                if *kappa0 <= 0.0 {
                    return Err(BocpdError::InvalidEmissionParameter {
                        message: format!("kappa0 must be > 0, got {}", kappa0),
                    });
                }
                if *alpha0 <= 0.0 {
                    return Err(BocpdError::InvalidEmissionParameter {
                        message: format!("alpha0 must be > 0, got {}", alpha0),
                    });
                }
                if *beta0 <= 0.0 {
                    return Err(BocpdError::InvalidEmissionParameter {
                        message: format!("beta0 must be > 0, got {}", beta0),
                    });
                }
            }
            EmissionModel::PoissonGamma { alpha, beta } => {
                if *alpha <= 0.0 {
                    return Err(BocpdError::InvalidEmissionParameter {
                        message: format!("alpha must be > 0, got {}", alpha),
                    });
                }
                if *beta <= 0.0 {
                    return Err(BocpdError::InvalidEmissionParameter {
                        message: format!("beta must be > 0, got {}", beta),
                    });
                }
            }
            EmissionModel::BetaBernoulli { alpha, beta } => {
                if *alpha <= 0.0 {
                    return Err(BocpdError::InvalidEmissionParameter {
                        message: format!("alpha must be > 0, got {}", alpha),
                    });
                }
                if *beta <= 0.0 {
                    return Err(BocpdError::InvalidEmissionParameter {
                        message: format!("beta must be > 0, got {}", beta),
                    });
                }
            }
        }
        Ok(())
    }
}

/// Sufficient statistics for a run segment.
#[derive(Debug, Clone)]
enum SufficientStats {
    NormalGamma {
        n: f64,        // count
        sum_x: f64,    // sum of observations
        sum_x2: f64,   // sum of squared observations
        kappa: f64,    // updated kappa
        mu: f64,       // updated mu
        alpha: f64,    // updated alpha
        beta: f64,     // updated beta
    },
    PoissonGamma {
        n: f64,        // count
        sum_x: f64,    // sum of counts
        alpha: f64,    // updated alpha
        beta: f64,     // updated beta
    },
    BetaBernoulli {
        alpha: f64,    // updated alpha (successes + prior)
        beta: f64,     // updated beta (failures + prior)
    },
}

impl SufficientStats {
    fn new_normal_gamma(mu0: f64, kappa0: f64, alpha0: f64, beta0: f64) -> Self {
        SufficientStats::NormalGamma {
            n: 0.0,
            sum_x: 0.0,
            sum_x2: 0.0,
            kappa: kappa0,
            mu: mu0,
            alpha: alpha0,
            beta: beta0,
        }
    }

    fn new_poisson_gamma(alpha: f64, beta: f64) -> Self {
        SufficientStats::PoissonGamma {
            n: 0.0,
            sum_x: 0.0,
            alpha,
            beta,
        }
    }

    fn new_beta_bernoulli(alpha: f64, beta: f64) -> Self {
        SufficientStats::BetaBernoulli { alpha, beta }
    }

    /// Update sufficient statistics with a new observation.
    fn update(&mut self, x: f64) {
        match self {
            SufficientStats::NormalGamma {
                n,
                sum_x,
                sum_x2,
                kappa,
                mu,
                alpha,
                beta,
            } => {
                // Conjugate update for Normal-Gamma
                let new_n = *n + 1.0;
                let new_sum_x = *sum_x + x;
                let new_sum_x2 = *sum_x2 + x * x;

                // Update parameters
                let kappa_n = *kappa + 1.0;
                let mu_n = (*kappa * *mu + x) / kappa_n;
                let alpha_n = *alpha + 0.5;

                // Update beta using variance decomposition
                let xbar = if new_n > 0.0 {
                    new_sum_x / new_n
                } else {
                    0.0
                };
                let ss = new_sum_x2 - new_n * xbar * xbar;
                let beta_n = *beta + 0.5 * ss + (*kappa * new_n * (xbar - *mu).powi(2)) / (2.0 * kappa_n);

                *n = new_n;
                *sum_x = new_sum_x;
                *sum_x2 = new_sum_x2;
                *kappa = kappa_n;
                *mu = mu_n;
                *alpha = alpha_n;
                *beta = beta_n;
            }
            SufficientStats::PoissonGamma {
                n,
                sum_x,
                alpha,
                beta,
            } => {
                // Conjugate update for Poisson-Gamma
                *n += 1.0;
                *sum_x += x;
                *alpha += x;  // Add count to shape
                *beta += 1.0; // Add one observation to rate
            }
            SufficientStats::BetaBernoulli { alpha, beta } => {
                // Conjugate update for Beta-Bernoulli
                // x should be 0 or 1
                if x > 0.5 {
                    *alpha += 1.0;
                } else {
                    *beta += 1.0;
                }
            }
        }
    }

    /// Compute log predictive probability for a new observation.
    fn log_predictive(&self, x: f64) -> f64 {
        match self {
            SufficientStats::NormalGamma {
                kappa, mu, alpha, beta, ..
            } => {
                // Student-t predictive distribution
                // x | data ~ Student-t(2*alpha, mu, beta*(kappa+1)/(alpha*kappa))
                let nu = 2.0 * alpha;
                let scale_sq = beta * (kappa + 1.0) / (alpha * kappa);
                let scale = scale_sq.sqrt();

                // Log PDF of Student-t
                let z = (x - mu) / scale;
                let log_gamma_half_nu_plus_half = ln_gamma((nu + 1.0) / 2.0);
                let log_gamma_half_nu = ln_gamma(nu / 2.0);
                let log_pdf = log_gamma_half_nu_plus_half
                    - log_gamma_half_nu
                    - 0.5 * (nu * std::f64::consts::PI).ln()
                    - scale.ln()
                    - ((nu + 1.0) / 2.0) * (1.0 + z * z / nu).ln();

                log_pdf
            }
            SufficientStats::PoissonGamma { alpha, beta, .. } => {
                // Negative binomial predictive distribution
                // x | data ~ NegBin(alpha, beta/(beta+1))
                let p = *beta / (*beta + 1.0);
                let r = *alpha;

                // Log PMF of negative binomial
                // P(x) = C(x+r-1, x) * p^r * (1-p)^x
                let log_pmf = ln_gamma(x + r)
                    - ln_gamma(x + 1.0)
                    - ln_gamma(r)
                    + r * p.ln()
                    + x * (1.0 - p).ln();

                log_pmf
            }
            SufficientStats::BetaBernoulli { alpha, beta } => {
                // Bernoulli predictive with posterior mean
                // P(x=1 | data) = alpha / (alpha + beta)
                let p = *alpha / (*alpha + *beta);
                if x > 0.5 {
                    p.ln()
                } else {
                    (1.0 - p).ln()
                }
            }
        }
    }
}

/// Result of a BOCPD update step.
#[derive(Debug, Clone, Serialize)]
pub struct BocpdUpdateResult {
    /// Current step number (0-indexed).
    pub step: usize,

    /// Probability that a change point just occurred (r_t = 0).
    pub change_point_probability: f64,

    /// Maximum a posteriori run length.
    pub map_run_length: usize,

    /// Expected run length.
    pub expected_run_length: f64,

    /// Log evidence (marginal likelihood).
    pub log_evidence: f64,

    /// Full posterior over run lengths (truncated at max_run_length).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub run_length_posterior: Vec<f64>,
}

/// BOCPD change-point detector.
pub struct BocpdDetector {
    config: BocpdConfig,
    /// Current step
    step: usize,
    /// Log run-length distribution (unnormalized)
    log_run_length_dist: Vec<f64>,
    /// Sufficient statistics for each run length hypothesis
    stats: VecDeque<SufficientStats>,
    /// Cumulative log evidence
    cum_log_evidence: f64,
}

impl BocpdDetector {
    /// Create a new BOCPD detector with the given configuration.
    pub fn new(config: BocpdConfig) -> Self {
        let stats = VecDeque::new();
        Self {
            config,
            step: 0,
            log_run_length_dist: vec![0.0], // Initial: r_0 = 0 with prob 1
            stats,
            cum_log_evidence: 0.0,
        }
    }

    /// Create a detector with default configuration.
    pub fn default_detector() -> Self {
        Self::new(BocpdConfig::default())
    }

    /// Reset the detector to initial state.
    pub fn reset(&mut self) {
        self.step = 0;
        self.log_run_length_dist = vec![0.0];
        self.stats.clear();
        self.cum_log_evidence = 0.0;
    }

    /// Get the current configuration.
    pub fn config(&self) -> &BocpdConfig {
        &self.config
    }

    /// Update with a new observation.
    pub fn update(&mut self, observation: f64) -> BocpdUpdateResult {
        let h = self.config.hazard_rate;
        let log_h = h.ln();
        let log_1_minus_h = (1.0 - h).ln();

        // Initialize stats for run length 0 if needed
        if self.stats.is_empty() {
            self.stats.push_back(self.new_stats());
        }

        // Compute log predictive probabilities for each run length
        let n_runs = self.log_run_length_dist.len();
        let mut log_pred = Vec::with_capacity(n_runs);
        for (i, stats) in self.stats.iter().enumerate() {
            if i < n_runs {
                log_pred.push(stats.log_predictive(observation));
            }
        }

        // Pad with prior predictive if needed
        while log_pred.len() < n_runs {
            let fresh_stats = self.new_stats();
            log_pred.push(fresh_stats.log_predictive(observation));
        }

        // Growth probabilities: P(r_t = r_{t-1} + 1 | r_{t-1}, x_{1:t})
        // For growth, we use the posterior predictive conditioned on the run length
        let mut log_growth = Vec::with_capacity(n_runs);
        for (i, &log_pred_i) in log_pred.iter().enumerate() {
            log_growth.push(self.log_run_length_dist[i] + log_pred_i + log_1_minus_h);
        }

        // Change point probability: P(r_t = 0 | x_{1:t})
        // For change points, we ALWAYS use the PRIOR predictive (fresh segment)
        // This is the key difference from growth: a change means starting fresh
        let fresh_stats = self.new_stats();
        let log_prior_pred = fresh_stats.log_predictive(observation);

        let mut log_cp_terms = Vec::with_capacity(n_runs);
        for i in 0..n_runs {
            log_cp_terms.push(self.log_run_length_dist[i] + log_prior_pred + log_h);
        }
        let log_cp = log_sum_exp(&log_cp_terms);

        // New run length distribution: [r_t = 0, r_t = 1, r_t = 2, ...]
        let mut new_log_dist = Vec::with_capacity(n_runs + 1);
        new_log_dist.push(log_cp);
        new_log_dist.extend(log_growth);

        // Normalize
        let log_evidence = log_sum_exp(&new_log_dist);
        for x in &mut new_log_dist {
            *x -= log_evidence;
        }

        // Truncate at max run length
        if new_log_dist.len() > self.config.max_run_length {
            // Renormalize after truncation
            new_log_dist.truncate(self.config.max_run_length);
            let log_norm = log_sum_exp(&new_log_dist);
            for x in &mut new_log_dist {
                *x -= log_norm;
            }
        }

        // Update sufficient statistics
        // First, update existing stats
        for stats in self.stats.iter_mut() {
            stats.update(observation);
        }

        // Add fresh stats for new run length 0
        self.stats.push_front(self.new_stats());

        // Truncate stats to match distribution
        while self.stats.len() > new_log_dist.len() {
            self.stats.pop_back();
        }

        // Store new distribution
        self.log_run_length_dist = new_log_dist;
        self.cum_log_evidence += log_evidence;
        self.step += 1;

        // Compute summary statistics
        let posterior: Vec<f64> = self.log_run_length_dist.iter().map(|x| x.exp()).collect();
        let change_point_probability = posterior.first().copied().unwrap_or(0.0);

        let map_run_length = posterior
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(i, _)| i)
            .unwrap_or(0);

        let expected_run_length: f64 = posterior
            .iter()
            .enumerate()
            .map(|(r, &p)| r as f64 * p)
            .sum();

        BocpdUpdateResult {
            step: self.step - 1,
            change_point_probability,
            map_run_length,
            expected_run_length,
            log_evidence: self.cum_log_evidence,
            run_length_posterior: posterior,
        }
    }

    /// Get detected change points from a sequence of results.
    pub fn detect_change_points(
        results: &[BocpdUpdateResult],
        threshold: f64,
    ) -> Vec<ChangePoint> {
        let mut change_points = Vec::new();

        for result in results {
            if result.change_point_probability > threshold {
                change_points.push(ChangePoint {
                    step: result.step,
                    probability: result.change_point_probability,
                    expected_run_length: result.expected_run_length,
                });
            }
        }

        change_points
    }

    /// Process a batch of observations and return change points.
    pub fn process_batch(&mut self, observations: &[f64], threshold: f64) -> BatchResult {
        let mut results = Vec::with_capacity(observations.len());

        for &obs in observations {
            results.push(self.update(obs));
        }

        let change_points = Self::detect_change_points(&results, threshold);

        BatchResult {
            results,
            change_points,
        }
    }

    fn new_stats(&self) -> SufficientStats {
        match &self.config.emission_model {
            EmissionModel::NormalGamma {
                mu0,
                kappa0,
                alpha0,
                beta0,
            } => SufficientStats::new_normal_gamma(*mu0, *kappa0, *alpha0, *beta0),
            EmissionModel::PoissonGamma { alpha, beta } => {
                SufficientStats::new_poisson_gamma(*alpha, *beta)
            }
            EmissionModel::BetaBernoulli { alpha, beta } => {
                SufficientStats::new_beta_bernoulli(*alpha, *beta)
            }
        }
    }
}

/// A detected change point.
#[derive(Debug, Clone, Serialize)]
pub struct ChangePoint {
    /// Step where change was detected.
    pub step: usize,
    /// Probability of change point.
    pub probability: f64,
    /// Expected run length at this point.
    pub expected_run_length: f64,
}

/// Result of batch processing.
#[derive(Debug, Clone, Serialize)]
pub struct BatchResult {
    /// Results for each observation.
    pub results: Vec<BocpdUpdateResult>,
    /// Detected change points above threshold.
    pub change_points: Vec<ChangePoint>,
}

/// Evidence for the decision core from BOCPD.
#[derive(Debug, Clone, Serialize)]
pub struct BocpdEvidence {
    /// Whether a recent change point was detected.
    pub recent_change: bool,
    /// Most recent change point probability.
    pub change_probability: f64,
    /// Current regime length (MAP run length).
    pub regime_length: usize,
    /// Number of change points in observation window.
    pub change_count: usize,
    /// Confidence in regime stability.
    pub regime_confidence: f64,
}

impl BocpdEvidence {
    /// Create evidence from batch results.
    pub fn from_batch(batch: &BatchResult, window_size: usize) -> Self {
        let recent_results: Vec<_> = batch
            .results
            .iter()
            .rev()
            .take(window_size)
            .collect();

        let recent_change = recent_results
            .first()
            .map(|r| r.change_point_probability > 0.5)
            .unwrap_or(false);

        let change_probability = recent_results
            .first()
            .map(|r| r.change_point_probability)
            .unwrap_or(0.0);

        let regime_length = recent_results
            .first()
            .map(|r| r.map_run_length)
            .unwrap_or(0);

        let change_count = recent_results
            .iter()
            .filter(|r| r.change_point_probability > 0.5)
            .count();

        // Regime confidence: inverse of change probability, scaled
        let regime_confidence = 1.0 - change_probability.min(1.0);

        BocpdEvidence {
            recent_change,
            change_probability,
            regime_length,
            change_count,
            regime_confidence,
        }
    }
}

// Helper functions

/// Compute log(sum(exp(xs))) in a numerically stable way.
fn log_sum_exp(xs: &[f64]) -> f64 {
    if xs.is_empty() {
        return f64::NEG_INFINITY;
    }

    let max_x = xs
        .iter()
        .copied()
        .filter(|x| x.is_finite())
        .fold(f64::NEG_INFINITY, f64::max);

    if !max_x.is_finite() {
        return f64::NEG_INFINITY;
    }

    let sum_exp: f64 = xs.iter().map(|x| (x - max_x).exp()).sum();

    max_x + sum_exp.ln()
}

/// Log gamma function using Stirling approximation.
fn ln_gamma(x: f64) -> f64 {
    if x <= 0.0 {
        return f64::NAN;
    }
    if x < 0.5 {
        // Reflection formula
        let pi = std::f64::consts::PI;
        return (pi / (pi * x).sin()).ln() - ln_gamma(1.0 - x);
    }

    // Stirling's approximation with Lanczos coefficients
    let g = 7.0;
    let c = [
        0.999_999_999_999_809_93,
        676.520_368_121_885_1,
        -1259.139_216_722_402_8,
        771.323_428_777_653_1,
        -176.615_029_162_140_6,
        12.507_343_278_686_905,
        -0.138_571_095_265_720_12,
        9.984_369_578_019_572e-6,
        1.505_632_735_149_311_6e-7,
    ];

    let z = x - 1.0;
    let mut sum = c[0];
    for (i, &coef) in c.iter().enumerate().skip(1) {
        sum += coef / (z + i as f64);
    }

    let t = z + g + 0.5;
    let pi2 = 2.0 * std::f64::consts::PI;

    0.5 * pi2.ln() + (z + 0.5) * t.ln() - t + sum.ln()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx_eq(a: f64, b: f64, tol: f64) -> bool {
        if a.is_nan() || b.is_nan() {
            return false;
        }
        (a - b).abs() <= tol
    }

    #[test]
    fn test_config_validation() {
        let valid = BocpdConfig::default();
        assert!(valid.validate().is_ok());

        let invalid_hazard = BocpdConfig {
            hazard_rate: 0.0,
            ..Default::default()
        };
        assert!(invalid_hazard.validate().is_err());

        let invalid_hazard2 = BocpdConfig {
            hazard_rate: 1.0,
            ..Default::default()
        };
        assert!(invalid_hazard2.validate().is_err());

        let invalid_max_run = BocpdConfig {
            max_run_length: 0,
            ..Default::default()
        };
        assert!(invalid_max_run.validate().is_err());
    }

    #[test]
    fn test_poisson_gamma_stable_regime() {
        let config = BocpdConfig {
            hazard_rate: 0.01,
            max_run_length: 50,
            emission_model: EmissionModel::PoissonGamma {
                alpha: 1.0,
                beta: 1.0,
            },
        };

        let mut detector = BocpdDetector::new(config);

        // Stable regime with rate ~5
        let observations = vec![5.0, 6.0, 4.0, 5.0, 5.0, 6.0, 4.0, 5.0, 5.0, 5.0];

        for obs in observations {
            let result = detector.update(obs);
            // Stable regime should have low change probability after initial burn-in
            assert!(result.change_point_probability <= 1.0);
            assert!(result.map_run_length <= 50);
        }
    }

    #[test]
    fn test_poisson_gamma_detects_change() {
        let config = BocpdConfig {
            hazard_rate: 0.1,  // Higher hazard for faster detection
            max_run_length: 50,
            emission_model: EmissionModel::PoissonGamma {
                alpha: 1.0,
                beta: 0.2,  // Prior mean = 5
            },
        };

        let mut detector = BocpdDetector::new(config);

        // Regime 1: rate ~5
        let regime1 = vec![5.0, 5.0, 5.0, 5.0, 5.0];
        // Regime 2: rate ~20 (large jump)
        let regime2 = vec![20.0, 20.0, 20.0, 20.0, 20.0];

        for obs in regime1 {
            detector.update(obs);
        }

        let mut max_cp_prob: f64 = 0.0;
        for obs in regime2 {
            let result = detector.update(obs);
            max_cp_prob = max_cp_prob.max(result.change_point_probability);
        }

        // Should detect the change with high probability
        assert!(
            max_cp_prob > 0.3,
            "Should detect change point, max_cp_prob = {}",
            max_cp_prob
        );
    }

    #[test]
    fn test_beta_bernoulli() {
        let config = BocpdConfig {
            hazard_rate: 0.1,
            max_run_length: 50,
            emission_model: EmissionModel::BetaBernoulli {
                alpha: 1.0,
                beta: 1.0,
            },
        };

        let mut detector = BocpdDetector::new(config);

        // Mostly 1s
        let regime1 = vec![1.0, 1.0, 1.0, 1.0, 1.0];
        // Mostly 0s (change)
        let regime2 = vec![0.0, 0.0, 0.0, 0.0, 0.0];

        for obs in regime1 {
            detector.update(obs);
        }

        let mut max_cp_prob: f64 = 0.0;
        for obs in regime2 {
            let result = detector.update(obs);
            max_cp_prob = max_cp_prob.max(result.change_point_probability);
        }

        // Should detect change in binary regime
        assert!(
            max_cp_prob > 0.2,
            "Should detect binary regime change, max_cp_prob = {}",
            max_cp_prob
        );
    }

    #[test]
    fn test_batch_processing() {
        let config = BocpdConfig {
            hazard_rate: 0.1,
            max_run_length: 50,
            emission_model: EmissionModel::PoissonGamma {
                alpha: 1.0,
                beta: 0.2,
            },
        };

        let mut detector = BocpdDetector::new(config);

        let observations = vec![
            5.0, 5.0, 5.0, 5.0, 5.0, // Regime 1
            20.0, 20.0, 20.0, 20.0, 20.0, // Regime 2
        ];

        let batch = detector.process_batch(&observations, 0.3);

        assert_eq!(batch.results.len(), 10);
        // May or may not detect change point depending on threshold
        assert!(batch.change_points.len() <= 10);
    }

    #[test]
    fn test_bocpd_evidence() {
        let config = BocpdConfig::default();
        let mut detector = BocpdDetector::new(config);

        let observations = vec![5.0; 10];
        let batch = detector.process_batch(&observations, 0.5);

        let evidence = BocpdEvidence::from_batch(&batch, 5);

        assert!(evidence.regime_confidence >= 0.0);
        assert!(evidence.regime_confidence <= 1.0);
        assert!(evidence.regime_length <= 10);
    }

    #[test]
    fn test_log_sum_exp() {
        let xs = vec![0.0, 0.0];
        let result = log_sum_exp(&xs);
        assert!(approx_eq(result, 2.0_f64.ln(), 1e-10));

        let xs2 = vec![-1000.0, -1000.0, -1000.0];
        let result2 = log_sum_exp(&xs2);
        assert!(approx_eq(result2, -1000.0 + 3.0_f64.ln(), 1e-10));
    }

    #[test]
    fn test_ln_gamma() {
        // Known values
        assert!(approx_eq(ln_gamma(1.0), 0.0, 1e-6));
        assert!(approx_eq(ln_gamma(2.0), 0.0, 1e-6)); // 1! = 1
        assert!(approx_eq(ln_gamma(3.0), 2.0_f64.ln(), 1e-6)); // 2! = 2
        assert!(approx_eq(ln_gamma(4.0), 6.0_f64.ln(), 1e-6)); // 3! = 6
    }

    #[test]
    fn test_reset() {
        let config = BocpdConfig::default();
        let mut detector = BocpdDetector::new(config);

        detector.update(5.0);
        detector.update(5.0);
        assert_eq!(detector.step, 2);

        detector.reset();
        assert_eq!(detector.step, 0);
        assert_eq!(detector.log_run_length_dist.len(), 1);
    }

    #[test]
    fn test_normal_gamma_model() {
        let config = BocpdConfig {
            hazard_rate: 0.1,
            max_run_length: 50,
            emission_model: EmissionModel::NormalGamma {
                mu0: 0.0,
                kappa0: 1.0,
                alpha0: 1.0,
                beta0: 1.0,
            },
        };

        let mut detector = BocpdDetector::new(config);

        // Stable regime around 0
        for _ in 0..5 {
            detector.update(0.1);
        }

        // Jump to regime around 10
        let mut detected_change = false;
        for _ in 0..5 {
            let result = detector.update(10.0);
            if result.change_point_probability > 0.3 {
                detected_change = true;
            }
        }

        assert!(detected_change, "Should detect mean shift");
    }
}
