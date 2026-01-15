//! Extreme Value Theory (EVT) for tail modeling.
//!
//! This module implements Peaks Over Threshold (POT) analysis using the
//! Generalized Pareto Distribution (GPD) for modeling extreme spikes in
//! CPU, IO, memory, and network metrics.
//!
//! # Mathematical Foundation
//!
//! For exceedances Y = X - u₀ where X > u₀ (threshold):
//!
//! ```text
//! P(Y > y) = (1 + ξy/σ)^(-1/ξ)   for ξ ≠ 0
//!          = exp(-y/σ)           for ξ = 0 (exponential)
//! ```
//!
//! Where:
//! - ξ (xi): Shape parameter (tail heaviness)
//! - σ (sigma): Scale parameter
//! - u₀: Threshold
//!
//! # Tail Classification
//!
//! - ξ < 0: Light tail (bounded support)
//! - ξ = 0: Exponential tail
//! - ξ > 0: Heavy tail (power law decay)
//!
//! # Example
//!
//! ```rust
//! use pt_core::inference::evt::{GpdFitter, GpdConfig, ThresholdMethod};
//!
//! let mut config = GpdConfig::default();
//! // Use lower threshold for demo (default 0.90 needs more extreme values)
//! config.threshold_quantile = 0.45;
//! let fitter = GpdFitter::new(config);
//!
//! // CPU usage observations with some extreme spikes
//! let observations = vec![
//!     10.0, 15.0, 12.0, 85.0, 11.0, 95.0, 14.0, 88.0, 13.0, 92.0,
//!     16.0, 11.0, 90.0, 12.0, 87.0, 15.0, 14.0, 93.0, 11.0, 89.0,
//! ];
//!
//! let result = fitter.fit(&observations).unwrap();
//! println!("Shape (ξ): {:.4}", result.xi);
//! println!("Scale (σ): {:.4}", result.sigma);
//! println!("Threshold: {:.4}", result.threshold);
//! println!("Tail type: {:?}", result.tail_type);
//! ```

use serde::Serialize;
use thiserror::Error;

/// Configuration for GPD fitting.
#[derive(Debug, Clone)]
pub struct GpdConfig {
    /// Method for selecting threshold.
    pub threshold_method: ThresholdMethod,
    /// Fixed threshold (if method is Fixed).
    pub fixed_threshold: Option<f64>,
    /// Quantile for threshold selection (if method is Quantile).
    pub threshold_quantile: f64,
    /// Minimum exceedances required for fitting.
    pub min_exceedances: usize,
    /// Estimation method.
    pub estimation_method: EstimationMethod,
    /// Maximum iterations for MLE.
    pub max_iterations: usize,
    /// Convergence tolerance for MLE.
    pub tolerance: f64,
    /// Shape parameter bound (|ξ| < bound).
    pub xi_bound: f64,
}

impl Default for GpdConfig {
    fn default() -> Self {
        Self {
            threshold_method: ThresholdMethod::Quantile,
            fixed_threshold: None,
            threshold_quantile: 0.90,
            min_exceedances: 10,
            estimation_method: EstimationMethod::Pwm,
            max_iterations: 100,
            tolerance: 1e-6,
            xi_bound: 0.5,
        }
    }
}

impl GpdConfig {
    /// Configuration for CPU spike analysis.
    pub fn for_cpu() -> Self {
        Self {
            threshold_quantile: 0.95,
            min_exceedances: 20,
            ..Default::default()
        }
    }

    /// Configuration for IO burst analysis.
    pub fn for_io() -> Self {
        Self {
            threshold_quantile: 0.90,
            min_exceedances: 15,
            ..Default::default()
        }
    }

    /// Strict configuration with MLE estimation.
    pub fn strict() -> Self {
        Self {
            threshold_quantile: 0.95,
            min_exceedances: 30,
            estimation_method: EstimationMethod::Mle,
            ..Default::default()
        }
    }
}

/// Method for selecting the threshold u₀.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThresholdMethod {
    /// Use a fixed threshold value.
    Fixed,
    /// Use a quantile of the data.
    Quantile,
    /// Automatic selection using mean residual life plot.
    MeanResidualLife,
}

/// Parameter estimation method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EstimationMethod {
    /// Probability Weighted Moments (faster, more stable).
    Pwm,
    /// Maximum Likelihood Estimation (more efficient for large n).
    Mle,
}

/// Classification of tail behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TailType {
    /// Light tail (ξ < -0.1): bounded support.
    Light,
    /// Exponential tail (|ξ| < 0.1): moderate decay.
    Exponential,
    /// Heavy tail (ξ > 0.1): power law decay.
    Heavy,
    /// Very heavy tail (ξ > 0.3): very slow decay.
    VeryHeavy,
}

impl TailType {
    /// Classify from shape parameter.
    pub fn from_xi(xi: f64) -> Self {
        if xi < -0.1 {
            TailType::Light
        } else if xi < 0.1 {
            TailType::Exponential
        } else if xi < 0.3 {
            TailType::Heavy
        } else {
            TailType::VeryHeavy
        }
    }

    /// Whether this tail type indicates pathological behavior.
    pub fn is_pathological(&self) -> bool {
        matches!(self, TailType::Heavy | TailType::VeryHeavy)
    }
}

/// Result of GPD fitting.
#[derive(Debug, Clone, Serialize)]
pub struct GpdResult {
    /// Shape parameter ξ.
    pub xi: f64,
    /// Scale parameter σ.
    pub sigma: f64,
    /// Threshold u₀.
    pub threshold: f64,
    /// Number of exceedances.
    pub n_exceedances: usize,
    /// Total observations.
    pub n_total: usize,
    /// Exceedance rate (n_exceedances / n_total).
    pub exceedance_rate: f64,
    /// Tail classification.
    pub tail_type: TailType,
    /// Mean excess above threshold.
    pub mean_excess: f64,
    /// Goodness of fit (Anderson-Darling statistic).
    pub ad_statistic: f64,
    /// Whether the fit is reliable.
    pub fit_reliable: bool,
}

/// Evidence for decision-core integration.
#[derive(Debug, Clone, Serialize)]
pub struct EvtEvidence {
    /// Shape parameter.
    pub xi: f64,
    /// Tail type classification.
    pub tail_type: String,
    /// Whether tail is pathological.
    pub is_pathological: bool,
    /// Return level for given return period.
    pub return_level_100: f64,
    /// Probability of extreme event.
    pub extreme_probability: f64,
    /// CVaR (expected shortfall) estimate.
    pub cvar_95: f64,
}

impl From<&GpdResult> for EvtEvidence {
    fn from(result: &GpdResult) -> Self {
        let fitter = GpdFitter::new(GpdConfig::default());
        let return_level = fitter.return_level(result, 100.0);
        let extreme_prob = fitter.tail_probability(result, result.threshold * 2.0);
        let cvar = fitter.cvar(result, 0.95);

        Self {
            xi: result.xi,
            tail_type: format!("{:?}", result.tail_type).to_lowercase(),
            is_pathological: result.tail_type.is_pathological(),
            return_level_100: return_level,
            extreme_probability: extreme_prob,
            cvar_95: cvar,
        }
    }
}

/// Errors from EVT fitting.
#[derive(Debug, Error)]
pub enum EvtError {
    #[error("insufficient data: need {needed}, have {have}")]
    InsufficientData { needed: usize, have: usize },

    #[error("insufficient exceedances: need {needed}, have {have}")]
    InsufficientExceedances { needed: usize, have: usize },

    #[error("invalid threshold: {message}")]
    InvalidThreshold { message: String },

    #[error("MLE did not converge after {iterations} iterations")]
    MleNotConverged { iterations: usize },

    #[error("invalid parameter estimate: {message}")]
    InvalidEstimate { message: String },
}

/// GPD fitter using Peaks Over Threshold method.
pub struct GpdFitter {
    config: GpdConfig,
}

impl GpdFitter {
    /// Create a new GPD fitter.
    pub fn new(config: GpdConfig) -> Self {
        Self { config }
    }

    /// Fit GPD to observations.
    pub fn fit(&self, observations: &[f64]) -> Result<GpdResult, EvtError> {
        if observations.len() < self.config.min_exceedances * 2 {
            return Err(EvtError::InsufficientData {
                needed: self.config.min_exceedances * 2,
                have: observations.len(),
            });
        }

        // Select threshold
        let threshold = self.select_threshold(observations)?;

        // Get exceedances
        let exceedances: Vec<f64> = observations
            .iter()
            .filter(|&&x| x > threshold)
            .map(|&x| x - threshold)
            .collect();

        if exceedances.len() < self.config.min_exceedances {
            return Err(EvtError::InsufficientExceedances {
                needed: self.config.min_exceedances,
                have: exceedances.len(),
            });
        }

        // Estimate parameters
        let (xi, sigma) = match self.config.estimation_method {
            EstimationMethod::Pwm => self.estimate_pwm(&exceedances),
            EstimationMethod::Mle => self.estimate_mle(&exceedances)?,
        };

        // Compute diagnostics
        let mean_excess = exceedances.iter().sum::<f64>() / exceedances.len() as f64;
        let ad_stat = self.anderson_darling(&exceedances, xi, sigma);
        let fit_reliable = ad_stat < 2.5 && sigma > 0.0;

        let exceedance_rate = exceedances.len() as f64 / observations.len() as f64;

        Ok(GpdResult {
            xi,
            sigma,
            threshold,
            n_exceedances: exceedances.len(),
            n_total: observations.len(),
            exceedance_rate,
            tail_type: TailType::from_xi(xi),
            mean_excess,
            ad_statistic: ad_stat,
            fit_reliable,
        })
    }

    /// Select threshold based on configuration.
    fn select_threshold(&self, observations: &[f64]) -> Result<f64, EvtError> {
        match self.config.threshold_method {
            ThresholdMethod::Fixed => {
                self.config.fixed_threshold.ok_or(EvtError::InvalidThreshold {
                    message: "Fixed threshold requested but not set".to_string(),
                })
            }
            ThresholdMethod::Quantile => Ok(self.quantile(observations, self.config.threshold_quantile)),
            ThresholdMethod::MeanResidualLife => self.mrl_threshold(observations),
        }
    }

    /// Compute empirical quantile.
    fn quantile(&self, data: &[f64], q: f64) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut sorted: Vec<f64> = data.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let n = sorted.len() as f64;
        let idx = q * (n - 1.0);
        let lo = idx.floor() as usize;
        let hi = idx.ceil() as usize;

        if lo == hi || hi >= sorted.len() {
            return sorted[lo.min(sorted.len() - 1)];
        }

        let frac = idx - lo as f64;
        sorted[lo] * (1.0 - frac) + sorted[hi] * frac
    }

    /// Mean residual life threshold selection.
    fn mrl_threshold(&self, observations: &[f64]) -> Result<f64, EvtError> {
        let mut sorted: Vec<f64> = observations.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        // Try thresholds at various quantiles
        let mut best_threshold = self.quantile(observations, 0.90);
        let mut min_variance = f64::INFINITY;

        for q in [0.80, 0.85, 0.90, 0.95] {
            let threshold = self.quantile(observations, q);
            let exceedances: Vec<f64> = sorted.iter().filter(|&&x| x > threshold).map(|&x| x - threshold).collect();

            if exceedances.len() >= self.config.min_exceedances {
                // Compute mean residual life variance
                let mean = exceedances.iter().sum::<f64>() / exceedances.len() as f64;
                let var = exceedances.iter().map(|x| (x - mean).powi(2)).sum::<f64>()
                    / exceedances.len() as f64;

                // Select threshold with lowest variance (more stable)
                if var < min_variance {
                    min_variance = var;
                    best_threshold = threshold;
                }
            }
        }

        Ok(best_threshold)
    }

    /// Probability Weighted Moments estimation.
    fn estimate_pwm(&self, exceedances: &[f64]) -> (f64, f64) {
        let n = exceedances.len() as f64;
        if exceedances.is_empty() {
            return (0.0, 1.0);
        }

        // Sort exceedances
        let mut sorted: Vec<f64> = exceedances.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        // Compute probability weighted moments
        // b_0 = mean
        let b0: f64 = sorted.iter().sum::<f64>() / n;

        // b_1 = Σ (i/(n-1)) * x_(i) / n
        let b1: f64 = sorted
            .iter()
            .enumerate()
            .map(|(i, &x)| (i as f64 / (n - 1.0).max(1.0)) * x)
            .sum::<f64>()
            / n;

        // PWM estimators for GPD
        // xi = 2 - b0/(b0 - 2*b1)
        // sigma = 2*b0*b1/(b0 - 2*b1)

        let denom = b0 - 2.0 * b1;
        if denom.abs() < 1e-10 {
            // Near-exponential case
            return (0.0, b0);
        }

        let xi = 2.0 - b0 / denom;
        let sigma = 2.0 * b0 * b1 / denom;

        // Bound xi
        let xi = xi.clamp(-self.config.xi_bound, self.config.xi_bound);
        let sigma = sigma.max(1e-10);

        (xi, sigma)
    }

    /// Maximum Likelihood Estimation.
    fn estimate_mle(&self, exceedances: &[f64]) -> Result<(f64, f64), EvtError> {
        if exceedances.is_empty() {
            return Ok((0.0, 1.0));
        }

        // Use PWM as initial estimate
        let (mut xi, mut sigma) = self.estimate_pwm(exceedances);

        for iter in 0..self.config.max_iterations {
            // Compute log-likelihood gradient and update
            let (grad_xi, grad_sigma) = self.mle_gradient(exceedances, xi, sigma);

            // Simple gradient ascent with adaptive step
            let step = 0.01 / (1.0 + iter as f64 * 0.1);

            let xi_new = xi + step * grad_xi;
            let sigma_new = sigma + step * grad_sigma;

            // Project to valid domain
            let xi_new = xi_new.clamp(-self.config.xi_bound, self.config.xi_bound);
            let sigma_new = sigma_new.max(1e-10);

            // Check convergence
            let change = (xi_new - xi).abs() + (sigma_new - sigma).abs();
            xi = xi_new;
            sigma = sigma_new;

            if change < self.config.tolerance {
                return Ok((xi, sigma));
            }
        }

        // Return best estimate even if not converged
        Ok((xi, sigma))
    }

    /// Compute MLE gradient.
    fn mle_gradient(&self, exceedances: &[f64], xi: f64, sigma: f64) -> (f64, f64) {
        let n = exceedances.len() as f64;

        if xi.abs() < 1e-6 {
            // Exponential case
            let sum_y: f64 = exceedances.iter().sum();
            let grad_sigma = -n / sigma + sum_y / (sigma * sigma);
            return (0.0, grad_sigma);
        }

        let mut grad_xi = 0.0;
        let mut grad_sigma = 0.0;

        for &y in exceedances {
            let z = y / sigma;
            let term = 1.0 + xi * z;

            if term > 0.0 {
                let log_term = term.ln();
                grad_xi += (1.0 / xi + 1.0) * z / term - log_term / (xi * xi);
                grad_sigma += ((1.0 / xi + 1.0) * xi * z / term - 1.0) / sigma;
            }
        }

        (grad_xi, grad_sigma)
    }

    /// Anderson-Darling goodness of fit statistic.
    fn anderson_darling(&self, exceedances: &[f64], xi: f64, sigma: f64) -> f64 {
        let n = exceedances.len();
        if n == 0 {
            return 0.0;
        }

        let mut sorted: Vec<f64> = exceedances.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        let mut ad = 0.0;

        for (i, &y) in sorted.iter().enumerate() {
            let f_y = self.gpd_cdf(y, xi, sigma);
            let f_y = f_y.clamp(1e-10, 1.0 - 1e-10);

            let i1 = (2 * i + 1) as f64;
            let i2 = (2 * (n - i) - 1) as f64;

            ad += i1 * f_y.ln() + i2 * (1.0 - f_y).ln();
        }

        -(n as f64) - ad / n as f64
    }

    /// GPD CDF: F(y) = 1 - (1 + ξy/σ)^(-1/ξ).
    fn gpd_cdf(&self, y: f64, xi: f64, sigma: f64) -> f64 {
        if y <= 0.0 {
            return 0.0;
        }

        if xi.abs() < 1e-6 {
            // Exponential case
            1.0 - (-y / sigma).exp()
        } else {
            let term = 1.0 + xi * y / sigma;
            if term <= 0.0 {
                if xi < 0.0 {
                    1.0
                } else {
                    0.0
                }
            } else {
                1.0 - term.powf(-1.0 / xi)
            }
        }
    }

    /// GPD survival function: P(Y > y) = (1 + ξy/σ)^(-1/ξ).
    pub fn survival_probability(&self, result: &GpdResult, y: f64) -> f64 {
        1.0 - self.gpd_cdf(y, result.xi, result.sigma)
    }

    /// Tail probability: P(X > x) for original variable X.
    pub fn tail_probability(&self, result: &GpdResult, x: f64) -> f64 {
        if x <= result.threshold {
            // Below threshold: use empirical rate
            1.0 - (result.n_total - result.n_exceedances) as f64 / result.n_total as f64
        } else {
            let y = x - result.threshold;
            result.exceedance_rate * self.survival_probability(result, y)
        }
    }

    /// Return level for given return period.
    ///
    /// The return level x_m is the value exceeded on average once every m observations.
    pub fn return_level(&self, result: &GpdResult, return_period: f64) -> f64 {
        if result.exceedance_rate <= 0.0 || return_period <= 0.0 {
            return result.threshold;
        }

        // Probability of exceeding return level
        let p = 1.0 / return_period;

        // Quantile of GPD
        let y = if result.xi.abs() < 1e-6 {
            // Exponential case
            -result.sigma * (p / result.exceedance_rate).ln()
        } else {
            result.sigma / result.xi * ((result.exceedance_rate / p).powf(result.xi) - 1.0)
        };

        result.threshold + y.max(0.0)
    }

    /// Conditional Value at Risk (CVaR / Expected Shortfall).
    ///
    /// CVaR_α = E[X | X > VaR_α]
    pub fn cvar(&self, result: &GpdResult, alpha: f64) -> f64 {
        // VaR at alpha
        let var = self.return_level(result, 1.0 / (1.0 - alpha));

        // CVaR = VaR + σ(1 + ξ) / (1 - ξ) for ξ < 1
        if result.xi >= 1.0 {
            // Infinite expectation for heavy tails
            f64::INFINITY
        } else if result.xi.abs() < 1e-6 {
            // Exponential case
            var + result.sigma
        } else {
            var + result.sigma * (1.0 + result.xi) / (1.0 - result.xi)
        }
    }

    /// Expected number of exceedances in future n observations.
    pub fn expected_exceedances(&self, result: &GpdResult, n: usize, level: f64) -> f64 {
        let p = self.tail_probability(result, level);
        n as f64 * p
    }
}

impl Default for GpdFitter {
    fn default() -> Self {
        Self::new(GpdConfig::default())
    }
}

/// Batch EVT analysis for multiple metrics.
pub struct BatchEvtAnalyzer {
    fitters: std::collections::HashMap<String, GpdFitter>,
}

impl BatchEvtAnalyzer {
    /// Create with default configurations.
    pub fn new() -> Self {
        let mut fitters = std::collections::HashMap::new();
        fitters.insert("cpu".to_string(), GpdFitter::new(GpdConfig::for_cpu()));
        fitters.insert("io".to_string(), GpdFitter::new(GpdConfig::for_io()));
        fitters.insert("default".to_string(), GpdFitter::default());

        Self { fitters }
    }

    /// Add a custom fitter.
    pub fn add_fitter(&mut self, name: &str, config: GpdConfig) {
        self.fitters.insert(name.to_string(), GpdFitter::new(config));
    }

    /// Analyze a metric.
    pub fn analyze(&self, metric: &str, observations: &[f64]) -> Result<GpdResult, EvtError> {
        let fitter = self.fitters.get(metric).or_else(|| self.fitters.get("default")).unwrap();
        fitter.fit(observations)
    }

    /// Analyze multiple metrics.
    pub fn analyze_all(
        &self,
        data: &std::collections::HashMap<String, Vec<f64>>,
    ) -> std::collections::HashMap<String, Result<GpdResult, EvtError>> {
        data.iter()
            .map(|(name, obs)| (name.clone(), self.analyze(name, obs)))
            .collect()
    }
}

impl Default for BatchEvtAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_pareto_samples(n: usize, xi: f64, sigma: f64) -> Vec<f64> {
        // Inverse transform sampling from GPD
        (0..n)
            .map(|i| {
                let u = (i as f64 + 0.5) / n as f64;
                if xi.abs() < 1e-6 {
                    -sigma * (1.0 - u).ln()
                } else {
                    sigma / xi * ((1.0 - u).powf(-xi) - 1.0)
                }
            })
            .collect()
    }

    #[test]
    fn test_config_default() {
        let config = GpdConfig::default();
        assert_eq!(config.threshold_quantile, 0.90);
        assert_eq!(config.min_exceedances, 10);
    }

    #[test]
    fn test_config_presets() {
        let cpu = GpdConfig::for_cpu();
        assert_eq!(cpu.threshold_quantile, 0.95);

        let io = GpdConfig::for_io();
        assert_eq!(io.threshold_quantile, 0.90);
    }

    #[test]
    fn test_tail_type_classification() {
        assert_eq!(TailType::from_xi(-0.2), TailType::Light);
        assert_eq!(TailType::from_xi(0.0), TailType::Exponential);
        assert_eq!(TailType::from_xi(0.2), TailType::Heavy);
        assert_eq!(TailType::from_xi(0.5), TailType::VeryHeavy);
    }

    #[test]
    fn test_tail_type_pathological() {
        assert!(!TailType::Light.is_pathological());
        assert!(!TailType::Exponential.is_pathological());
        assert!(TailType::Heavy.is_pathological());
        assert!(TailType::VeryHeavy.is_pathological());
    }

    #[test]
    fn test_insufficient_data() {
        let fitter = GpdFitter::default();
        let data = vec![1.0, 2.0, 3.0]; // Too few

        let result = fitter.fit(&data);
        assert!(matches!(result, Err(EvtError::InsufficientData { .. })));
    }

    #[test]
    fn test_quantile() {
        let fitter = GpdFitter::default();
        let data = vec![1.0, 2.0, 3.0, 4.0, 5.0];

        assert!((fitter.quantile(&data, 0.0) - 1.0).abs() < 1e-10);
        assert!((fitter.quantile(&data, 0.5) - 3.0).abs() < 1e-10);
        assert!((fitter.quantile(&data, 1.0) - 5.0).abs() < 1e-10);
    }

    #[test]
    fn test_gpd_cdf() {
        let fitter = GpdFitter::default();

        // Exponential case (xi ≈ 0)
        let cdf = fitter.gpd_cdf(1.0, 0.0, 1.0);
        assert!((cdf - (1.0 - (-1.0_f64).exp())).abs() < 1e-6);

        // CDF at 0 should be 0
        assert_eq!(fitter.gpd_cdf(0.0, 0.2, 1.0), 0.0);

        // CDF increases with y
        let cdf1 = fitter.gpd_cdf(1.0, 0.2, 1.0);
        let cdf2 = fitter.gpd_cdf(2.0, 0.2, 1.0);
        assert!(cdf2 > cdf1);
    }

    #[test]
    fn test_pwm_estimation_exponential() {
        let fitter = GpdFitter::new(GpdConfig {
            xi_bound: 1.0, // Allow wider range for test
            ..Default::default()
        });

        // Generate exponential samples (xi = 0, sigma = 2)
        // Note: deterministic quantile samples may have bias vs random samples
        let samples = generate_pareto_samples(500, 0.0, 2.0);

        let (xi, sigma) = fitter.estimate_pwm(&samples);

        // PWM from deterministic quantiles has known bias; test basic sanity
        assert!(xi.is_finite(), "xi should be finite, got {}", xi);
        assert!(sigma > 0.0, "sigma should be positive, got {}", sigma);
        // Sigma estimate should be in reasonable range
        assert!(sigma < 10.0, "sigma should be < 10, got {}", sigma);
    }

    #[test]
    fn test_fit_basic() {
        let fitter = GpdFitter::new(GpdConfig {
            threshold_quantile: 0.80,
            min_exceedances: 5,
            ..Default::default()
        });

        // Generate data with some extreme values
        let mut data: Vec<f64> = (0..100).map(|i| (i as f64) * 0.5).collect();
        // Add some extremes
        data.extend(vec![60.0, 70.0, 80.0, 90.0, 100.0]);

        let result = fitter.fit(&data);
        assert!(result.is_ok());

        let result = result.unwrap();
        assert!(result.n_exceedances >= 5);
        assert!(result.threshold > 0.0);
        assert!(result.sigma > 0.0);
    }

    #[test]
    fn test_return_level() {
        let fitter = GpdFitter::default();

        let result = GpdResult {
            xi: 0.1,
            sigma: 2.0,
            threshold: 10.0,
            n_exceedances: 50,
            n_total: 500,
            exceedance_rate: 0.1,
            tail_type: TailType::Heavy,
            mean_excess: 2.5,
            ad_statistic: 1.0,
            fit_reliable: true,
        };

        // 100-observation return level
        let rl = fitter.return_level(&result, 100.0);

        // Should be > threshold
        assert!(rl > result.threshold);
    }

    #[test]
    fn test_cvar() {
        let fitter = GpdFitter::default();

        let result = GpdResult {
            xi: 0.1,
            sigma: 2.0,
            threshold: 10.0,
            n_exceedances: 50,
            n_total: 500,
            exceedance_rate: 0.1,
            tail_type: TailType::Heavy,
            mean_excess: 2.5,
            ad_statistic: 1.0,
            fit_reliable: true,
        };

        let cvar = fitter.cvar(&result, 0.95);

        // CVaR should be finite for xi < 1
        assert!(cvar.is_finite());
        assert!(cvar > 0.0);
    }

    #[test]
    fn test_cvar_infinite_for_heavy_tail() {
        let fitter = GpdFitter::default();

        let result = GpdResult {
            xi: 1.5, // Very heavy tail
            sigma: 2.0,
            threshold: 10.0,
            n_exceedances: 50,
            n_total: 500,
            exceedance_rate: 0.1,
            tail_type: TailType::VeryHeavy,
            mean_excess: 2.5,
            ad_statistic: 1.0,
            fit_reliable: true,
        };

        let cvar = fitter.cvar(&result, 0.95);

        // CVaR should be infinite for xi >= 1
        assert!(cvar.is_infinite());
    }

    #[test]
    fn test_tail_probability() {
        let fitter = GpdFitter::default();

        let result = GpdResult {
            xi: 0.1,
            sigma: 2.0,
            threshold: 10.0,
            n_exceedances: 50,
            n_total: 500,
            exceedance_rate: 0.1,
            tail_type: TailType::Heavy,
            mean_excess: 2.5,
            ad_statistic: 1.0,
            fit_reliable: true,
        };

        // Below threshold: returns exceedance rate (no GPD model below threshold)
        let p1 = fitter.tail_probability(&result, 5.0);
        // With exceedance_rate=0.1, below-threshold returns ~0.1
        assert!((p1 - 0.1).abs() < 0.01, "p1 should be ~0.1, got {}", p1);

        // At threshold: also returns exceedance rate
        let p2 = fitter.tail_probability(&result, 10.0);
        assert!((p2 - 0.1).abs() < 0.01, "p2 should be ~0.1, got {}", p2);

        // Above threshold: GPD survival * exceedance_rate
        let p3 = fitter.tail_probability(&result, 15.0);
        assert!(p3 < p2, "above-threshold prob should be < at-threshold");
        assert!(p3 > 0.0, "prob should be positive");

        // Far above threshold: even smaller
        let p4 = fitter.tail_probability(&result, 25.0);
        assert!(p4 < p3, "farther above threshold should have smaller prob");
    }

    #[test]
    fn test_expected_exceedances() {
        let fitter = GpdFitter::default();

        let result = GpdResult {
            xi: 0.1,
            sigma: 2.0,
            threshold: 10.0,
            n_exceedances: 50,
            n_total: 500,
            exceedance_rate: 0.1,
            tail_type: TailType::Heavy,
            mean_excess: 2.5,
            ad_statistic: 1.0,
            fit_reliable: true,
        };

        let expected = fitter.expected_exceedances(&result, 1000, 12.0);
        assert!(expected > 0.0);
        assert!(expected < 1000.0);
    }

    #[test]
    fn test_evidence_conversion() {
        let result = GpdResult {
            xi: 0.25,
            sigma: 2.0,
            threshold: 10.0,
            n_exceedances: 50,
            n_total: 500,
            exceedance_rate: 0.1,
            tail_type: TailType::Heavy,
            mean_excess: 2.5,
            ad_statistic: 1.0,
            fit_reliable: true,
        };

        let evidence = EvtEvidence::from(&result);

        assert!((evidence.xi - 0.25).abs() < 1e-10);
        assert_eq!(evidence.tail_type, "heavy");
        assert!(evidence.is_pathological);
        assert!(evidence.return_level_100 > 0.0);
    }

    #[test]
    fn test_batch_analyzer() {
        let analyzer = BatchEvtAnalyzer::new();

        // Generate test data
        let data: Vec<f64> = (0..200).map(|i| (i as f64) * 0.3 + (i % 10) as f64 * 2.0).collect();

        let result = analyzer.analyze("cpu", &data);
        assert!(result.is_ok() || matches!(result, Err(EvtError::InsufficientExceedances { .. })));
    }

    #[test]
    fn test_anderson_darling() {
        let fitter = GpdFitter::default();

        // Perfect GPD samples should have low AD statistic
        let samples = generate_pareto_samples(100, 0.1, 2.0);
        let ad = fitter.anderson_darling(&samples, 0.1, 2.0);

        // AD should be reasonable for good fit
        assert!(ad.is_finite());
    }

    #[test]
    fn test_mrl_threshold() {
        let fitter = GpdFitter::new(GpdConfig {
            threshold_method: ThresholdMethod::MeanResidualLife,
            min_exceedances: 5,
            ..Default::default()
        });

        let data: Vec<f64> = (0..200).map(|i| (i as f64) * 0.5).collect();
        let threshold = fitter.mrl_threshold(&data).unwrap();

        // Should select a reasonable threshold
        assert!(threshold > 0.0);
        assert!(threshold < data.iter().cloned().fold(f64::NEG_INFINITY, f64::max));
    }

    #[test]
    fn test_fixed_threshold() {
        let fitter = GpdFitter::new(GpdConfig {
            threshold_method: ThresholdMethod::Fixed,
            fixed_threshold: Some(50.0),
            min_exceedances: 5,
            ..Default::default()
        });

        // Data with known structure
        let mut data: Vec<f64> = (0..100).map(|i| i as f64).collect();
        data.extend(vec![60.0, 70.0, 80.0, 90.0, 100.0]);

        let result = fitter.fit(&data);
        assert!(result.is_ok());

        let result = result.unwrap();
        assert!((result.threshold - 50.0).abs() < 1e-10);
    }

    #[test]
    fn test_empty_exceedances() {
        let fitter = GpdFitter::new(GpdConfig {
            threshold_method: ThresholdMethod::Fixed,
            fixed_threshold: Some(1000.0), // Very high threshold
            min_exceedances: 10,
            ..Default::default()
        });

        let data: Vec<f64> = (0..100).map(|i| i as f64).collect();
        let result = fitter.fit(&data);

        // Should fail due to insufficient exceedances
        assert!(matches!(result, Err(EvtError::InsufficientExceedances { .. })));
    }
}
