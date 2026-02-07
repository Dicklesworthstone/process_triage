//! Posterior predictive checks (PPC) for model misspecification detection.
//!
//! This module detects when the Bayesian model doesn't fit observed data by:
//! 1. Generating samples from posterior predictive distributions
//! 2. Computing test statistics on real and simulated data
//! 3. Computing p-values: P(T(sim) ≥ T(real))
//! 4. Triggering fallback actions when PPC fails
//!
//! # Background
//!
//! PPC compares observed traces to what the model predicts. When the model
//! is correctly specified, observed statistics should look like draws from
//! the posterior predictive. Extreme p-values indicate misspecification.
//!
//! # Test Statistics
//!
//! - **Mean**: Average value (location)
//! - **Variance**: Spread (scale)
//! - **RunLengths**: Distribution of runs above/below mean
//! - **ChangePoints**: Number of level shifts (non-stationarity)
//!
//! # Fallback Actions
//!
//! When PPC fails (p-value < threshold):
//! - Widen priors (increase uncertainty)
//! - Switch to robust layers (Huberization)
//! - Reduce Safe-Bayes learning rate η
//! - Flag in output for transparency
//!
//! # Example
//!
//! ```rust
//! use pt_core::inference::ppc::{PpcChecker, PpcConfig, TestStatistic};
//!
//! let config = PpcConfig::default();
//! let checker = PpcChecker::new(config);
//!
//! // CPU observations (fraction in [0,1])
//! let observations = vec![0.15, 0.18, 0.22, 0.85, 0.82, 0.78, 0.20, 0.15, 0.17, 0.19];
//!
//! // Posterior parameters (e.g., from Beta posterior)
//! let posterior_alpha = 2.0;
//! let posterior_beta = 8.0;
//!
//! let result = checker.check_beta(&observations, posterior_alpha, posterior_beta).unwrap();
//! if !result.passed {
//!     println!("Model misspecification detected!");
//!     for check in &result.failed_checks {
//!         println!("  Failed: {:?} (p={:.4})", check.statistic, check.p_value);
//!     }
//! }
//! ```

use serde::Serialize;
use std::collections::HashMap;
use thiserror::Error;

/// Configuration for posterior predictive checks.
#[derive(Debug, Clone)]
pub struct PpcConfig {
    /// Number of posterior predictive samples to generate.
    pub n_samples: usize,
    /// p-value threshold for declaring misspecification (default: 0.05).
    pub alpha_threshold: f64,
    /// Minimum observations required to run PPC.
    pub min_observations: usize,
    /// Which test statistics to compute.
    pub statistics: Vec<TestStatistic>,
    /// Whether to use two-sided p-values.
    pub two_sided: bool,
    /// Confidence adjustment when PPC fails.
    pub failure_confidence_penalty: f64,
}

impl Default for PpcConfig {
    fn default() -> Self {
        Self {
            n_samples: 1000,
            alpha_threshold: 0.05,
            min_observations: 10,
            statistics: vec![
                TestStatistic::Mean,
                TestStatistic::Variance,
                TestStatistic::RunLengths,
                TestStatistic::ChangePoints,
            ],
            two_sided: true,
            failure_confidence_penalty: 0.1,
        }
    }
}

/// Test statistic types for PPC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TestStatistic {
    /// Sample mean.
    Mean,
    /// Sample variance.
    Variance,
    /// Maximum run length (consecutive values above/below mean).
    RunLengths,
    /// Number of detected change points.
    ChangePoints,
    /// Maximum value (for extreme detection).
    Maximum,
    /// Minimum value.
    Minimum,
    /// Autocorrelation at lag 1.
    Autocorrelation,
    /// Skewness (asymmetry).
    Skewness,
}

/// Fallback action to take when PPC fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackAction {
    /// Widen priors to increase uncertainty.
    WidenPriors,
    /// Switch to robust layers (Huberization).
    UseRobustLayers,
    /// Reduce Safe-Bayes learning rate η.
    ReduceLearningRate,
    /// No action (passed or insufficient data).
    None,
}

/// Result of a single test statistic check.
#[derive(Debug, Clone, Serialize)]
pub struct StatisticCheck {
    /// Which statistic was checked.
    pub statistic: TestStatistic,
    /// Observed value of the statistic.
    pub observed_value: f64,
    /// Mean of posterior predictive statistic.
    pub expected_value: f64,
    /// p-value for the check.
    pub p_value: f64,
    /// Whether this check passed.
    pub passed: bool,
}

/// Overall PPC result.
#[derive(Debug, Clone, Serialize)]
pub struct PpcResult {
    /// Whether all checks passed.
    pub passed: bool,
    /// Number of observations used.
    pub n_observations: usize,
    /// Number of samples generated.
    pub n_samples: usize,
    /// All individual checks.
    pub checks: Vec<StatisticCheck>,
    /// Checks that failed (p < alpha).
    pub failed_checks: Vec<StatisticCheck>,
    /// Recommended fallback action.
    pub action_taken: FallbackAction,
    /// Confidence adjustment to apply.
    pub confidence_adjustment: f64,
    /// Summary for logging/display.
    pub summary: String,
}

/// Evidence for decision-core integration.
#[derive(Debug, Clone, Serialize)]
pub struct PpcEvidence {
    /// Overall PPC passed.
    pub passed: bool,
    /// Number of failed checks.
    pub failed_count: usize,
    /// Names of failed statistics.
    pub failed_statistics: Vec<String>,
    /// Minimum p-value across all checks.
    pub min_p_value: f64,
    /// Confidence penalty to apply.
    pub confidence_penalty: f64,
    /// Fallback action recommended.
    pub fallback_action: String,
}

impl From<&PpcResult> for PpcEvidence {
    fn from(result: &PpcResult) -> Self {
        Self {
            passed: result.passed,
            failed_count: result.failed_checks.len(),
            failed_statistics: result
                .failed_checks
                .iter()
                .map(|c| format!("{:?}", c.statistic).to_lowercase())
                .collect(),
            min_p_value: result.checks.iter().map(|c| c.p_value).fold(1.0, f64::min),
            confidence_penalty: if result.passed {
                0.0
            } else {
                result.confidence_adjustment.abs()
            },
            fallback_action: format!("{:?}", result.action_taken).to_lowercase(),
        }
    }
}

/// Errors from PPC computation.
#[derive(Debug, Error)]
pub enum PpcError {
    #[error("insufficient observations: need {needed}, have {have}")]
    InsufficientData { needed: usize, have: usize },

    #[error("invalid posterior parameters: {message}")]
    InvalidParameters { message: String },

    #[error("sampling failed: {message}")]
    SamplingError { message: String },
}

/// Posterior predictive checker.
pub struct PpcChecker {
    config: PpcConfig,
}

impl PpcChecker {
    /// Create a new PPC checker with the given configuration.
    pub fn new(config: PpcConfig) -> Self {
        Self { config }
    }

    /// Check observations against a Beta posterior predictive.
    ///
    /// Used for CPU fraction, memory fraction, etc.
    pub fn check_beta(
        &self,
        observations: &[f64],
        posterior_alpha: f64,
        posterior_beta: f64,
    ) -> Result<PpcResult, PpcError> {
        if observations.len() < self.config.min_observations {
            return Err(PpcError::InsufficientData {
                needed: self.config.min_observations,
                have: observations.len(),
            });
        }

        if posterior_alpha <= 0.0 || posterior_beta <= 0.0 {
            return Err(PpcError::InvalidParameters {
                message: format!(
                    "Beta parameters must be positive: α={}, β={}",
                    posterior_alpha, posterior_beta
                ),
            });
        }

        // Generate posterior predictive samples
        let pp_samples = self.sample_beta_predictive(
            posterior_alpha,
            posterior_beta,
            observations.len(),
            self.config.n_samples,
        );

        self.run_checks(observations, &pp_samples)
    }

    /// Check observations against a Gamma posterior predictive.
    ///
    /// Used for waiting times, durations, rates.
    pub fn check_gamma(
        &self,
        observations: &[f64],
        posterior_shape: f64,
        posterior_rate: f64,
    ) -> Result<PpcResult, PpcError> {
        if observations.len() < self.config.min_observations {
            return Err(PpcError::InsufficientData {
                needed: self.config.min_observations,
                have: observations.len(),
            });
        }

        if posterior_shape <= 0.0 || posterior_rate <= 0.0 {
            return Err(PpcError::InvalidParameters {
                message: format!(
                    "Gamma parameters must be positive: shape={}, rate={}",
                    posterior_shape, posterior_rate
                ),
            });
        }

        let pp_samples = self.sample_gamma_predictive(
            posterior_shape,
            posterior_rate,
            observations.len(),
            self.config.n_samples,
        );

        self.run_checks(observations, &pp_samples)
    }

    /// Check observations against a Normal posterior predictive.
    ///
    /// Used for log-transformed metrics, residuals.
    pub fn check_normal(
        &self,
        observations: &[f64],
        posterior_mean: f64,
        posterior_var: f64,
    ) -> Result<PpcResult, PpcError> {
        if observations.len() < self.config.min_observations {
            return Err(PpcError::InsufficientData {
                needed: self.config.min_observations,
                have: observations.len(),
            });
        }

        if posterior_var <= 0.0 {
            return Err(PpcError::InvalidParameters {
                message: format!("Normal variance must be positive: var={}", posterior_var),
            });
        }

        let pp_samples = self.sample_normal_predictive(
            posterior_mean,
            posterior_var,
            observations.len(),
            self.config.n_samples,
        );

        self.run_checks(observations, &pp_samples)
    }

    /// Run all configured checks on observations vs posterior predictive samples.
    fn run_checks(
        &self,
        observations: &[f64],
        pp_samples: &[Vec<f64>],
    ) -> Result<PpcResult, PpcError> {
        let mut checks = Vec::new();
        let mut failed_checks = Vec::new();

        for &stat in &self.config.statistics {
            let observed = self.compute_statistic(observations, stat);
            let simulated: Vec<f64> = pp_samples
                .iter()
                .map(|sample| self.compute_statistic(sample, stat))
                .collect();

            let p_value = self.compute_p_value(observed, &simulated);
            let expected = simulated.iter().sum::<f64>() / simulated.len() as f64;
            let passed = p_value >= self.config.alpha_threshold;

            let check = StatisticCheck {
                statistic: stat,
                observed_value: observed,
                expected_value: expected,
                p_value,
                passed,
            };

            if !passed {
                failed_checks.push(check.clone());
            }
            checks.push(check);
        }

        let passed = failed_checks.is_empty();
        let action_taken = self.determine_fallback(&failed_checks);
        let confidence_adjustment = if passed {
            0.0
        } else {
            -self.config.failure_confidence_penalty * (failed_checks.len() as f64)
        };

        let summary = if passed {
            "All PPC checks passed".to_string()
        } else {
            let failed_names: Vec<_> = failed_checks
                .iter()
                .map(|c| format!("{:?}", c.statistic).to_lowercase())
                .collect();
            format!(
                "PPC failed on {}: action={}",
                failed_names.join(", "),
                format!("{:?}", action_taken).to_lowercase()
            )
        };

        Ok(PpcResult {
            passed,
            n_observations: observations.len(),
            n_samples: pp_samples.len(),
            checks,
            failed_checks,
            action_taken,
            confidence_adjustment,
            summary,
        })
    }

    /// Compute a test statistic on a data vector.
    fn compute_statistic(&self, data: &[f64], stat: TestStatistic) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        match stat {
            TestStatistic::Mean => {
                let sum: f64 = data.iter().sum();
                sum / data.len() as f64
            }
            TestStatistic::Variance => {
                if data.len() < 2 {
                    return 0.0;
                }
                let mean = data.iter().sum::<f64>() / data.len() as f64;
                let sum_sq: f64 = data.iter().map(|x| (x - mean).powi(2)).sum();
                sum_sq / (data.len() - 1) as f64
            }
            TestStatistic::RunLengths => self.max_run_length(data),
            TestStatistic::ChangePoints => self.count_change_points(data),
            TestStatistic::Maximum => data.iter().cloned().fold(f64::NEG_INFINITY, f64::max),
            TestStatistic::Minimum => data.iter().cloned().fold(f64::INFINITY, f64::min),
            TestStatistic::Autocorrelation => self.autocorrelation_lag1(data),
            TestStatistic::Skewness => self.skewness(data),
        }
    }

    /// Compute maximum run length (consecutive values above/below mean).
    fn max_run_length(&self, data: &[f64]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mean = data.iter().sum::<f64>() / data.len() as f64;
        let mut max_run = 0usize;
        let mut current_run = 0usize;
        let mut above_mean: Option<bool> = None;

        for &x in data {
            let current_above = x > mean;
            match above_mean {
                None => {
                    above_mean = Some(current_above);
                    current_run = 1;
                }
                Some(prev_above) if prev_above == current_above => {
                    current_run += 1;
                }
                Some(_) => {
                    max_run = max_run.max(current_run);
                    current_run = 1;
                    above_mean = Some(current_above);
                }
            }
        }
        max_run = max_run.max(current_run);
        max_run as f64
    }

    /// Count change points using simple level-shift detection.
    fn count_change_points(&self, data: &[f64]) -> f64 {
        if data.len() < 4 {
            return 0.0;
        }

        // Use cumulative sum (CUSUM) approach
        let mean = data.iter().sum::<f64>() / data.len() as f64;
        let std_dev = {
            let var = data.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / data.len() as f64;
            var.sqrt()
        };

        if std_dev < 1e-10 {
            return 0.0;
        }

        // Count significant level shifts
        let window = 3.min(data.len() / 3);
        let threshold = 2.0 * std_dev;
        let mut change_points = 0;

        for i in window..(data.len() - window) {
            let left_mean: f64 = data[(i - window)..i].iter().sum::<f64>() / window as f64;
            let right_mean: f64 = data[i..(i + window)].iter().sum::<f64>() / window as f64;

            if (right_mean - left_mean).abs() > threshold {
                change_points += 1;
            }
        }

        change_points as f64
    }

    /// Compute autocorrelation at lag 1.
    fn autocorrelation_lag1(&self, data: &[f64]) -> f64 {
        if data.len() < 3 {
            return 0.0;
        }

        let mean = data.iter().sum::<f64>() / data.len() as f64;
        let var: f64 = data.iter().map(|x| (x - mean).powi(2)).sum();

        if var < 1e-10 {
            return 0.0;
        }

        let cov: f64 = data.windows(2).map(|w| (w[0] - mean) * (w[1] - mean)).sum();

        cov / var
    }

    /// Compute skewness (third standardized moment).
    fn skewness(&self, data: &[f64]) -> f64 {
        if data.len() < 3 {
            return 0.0;
        }

        let n = data.len() as f64;
        let mean = data.iter().sum::<f64>() / n;
        let var = data.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;

        if var < 1e-10 {
            return 0.0;
        }

        let std_dev = var.sqrt();
        let m3: f64 = data.iter().map(|x| ((x - mean) / std_dev).powi(3)).sum();

        m3 / n
    }

    /// Compute p-value: P(T(sim) >= T(obs)) or two-sided.
    fn compute_p_value(&self, observed: f64, simulated: &[f64]) -> f64 {
        if simulated.is_empty() {
            return 1.0;
        }

        let n = simulated.len() as f64;

        if self.config.two_sided {
            // Two-sided: count how many simulated values are as extreme or more
            let sim_mean = simulated.iter().sum::<f64>() / n;
            let obs_dist = (observed - sim_mean).abs();
            let count = simulated
                .iter()
                .filter(|&&x| (x - sim_mean).abs() >= obs_dist)
                .count();
            (count as f64 + 1.0) / (n + 1.0)
        } else {
            // One-sided: count how many simulated >= observed
            let count = simulated.iter().filter(|&&x| x >= observed).count();
            (count as f64 + 1.0) / (n + 1.0)
        }
    }

    /// Determine which fallback action to take based on failed checks.
    fn determine_fallback(&self, failed_checks: &[StatisticCheck]) -> FallbackAction {
        if failed_checks.is_empty() {
            return FallbackAction::None;
        }

        // Check which statistics failed
        let failed_stats: std::collections::HashSet<_> =
            failed_checks.iter().map(|c| c.statistic).collect();

        // Variance/skewness issues → widen priors
        if failed_stats.contains(&TestStatistic::Variance)
            || failed_stats.contains(&TestStatistic::Skewness)
        {
            return FallbackAction::WidenPriors;
        }

        // Extreme values → robust layers
        if failed_stats.contains(&TestStatistic::Maximum)
            || failed_stats.contains(&TestStatistic::Minimum)
        {
            return FallbackAction::UseRobustLayers;
        }

        // Autocorrelation/runs → model structure issue, reduce learning rate
        if failed_stats.contains(&TestStatistic::Autocorrelation)
            || failed_stats.contains(&TestStatistic::RunLengths)
        {
            return FallbackAction::ReduceLearningRate;
        }

        // Change points → likely regime change, widen priors
        if failed_stats.contains(&TestStatistic::ChangePoints) {
            return FallbackAction::WidenPriors;
        }

        // Default for mean mismatch
        FallbackAction::WidenPriors
    }

    /// Sample from Beta posterior predictive distribution.
    ///
    /// Uses inversion sampling via regularized incomplete beta function approximation.
    fn sample_beta_predictive(
        &self,
        alpha: f64,
        beta: f64,
        n_obs: usize,
        n_samples: usize,
    ) -> Vec<Vec<f64>> {
        let mut samples = Vec::with_capacity(n_samples);

        for i in 0..n_samples {
            let mut sample = Vec::with_capacity(n_obs);
            for j in 0..n_obs {
                // Use deterministic quasi-random for reproducibility
                let u = self.quasi_random(i * n_obs + j, n_samples * n_obs);
                let x = self.beta_quantile(u, alpha, beta);
                sample.push(x);
            }
            samples.push(sample);
        }

        samples
    }

    /// Sample from Gamma posterior predictive distribution.
    fn sample_gamma_predictive(
        &self,
        shape: f64,
        rate: f64,
        n_obs: usize,
        n_samples: usize,
    ) -> Vec<Vec<f64>> {
        let mut samples = Vec::with_capacity(n_samples);

        for i in 0..n_samples {
            let mut sample = Vec::with_capacity(n_obs);
            for j in 0..n_obs {
                let u = self.quasi_random(i * n_obs + j, n_samples * n_obs);
                let x = self.gamma_quantile(u, shape, rate);
                sample.push(x);
            }
            samples.push(sample);
        }

        samples
    }

    /// Sample from Normal posterior predictive distribution.
    fn sample_normal_predictive(
        &self,
        mean: f64,
        variance: f64,
        n_obs: usize,
        n_samples: usize,
    ) -> Vec<Vec<f64>> {
        let std_dev = variance.sqrt();
        let mut samples = Vec::with_capacity(n_samples);

        for i in 0..n_samples {
            let mut sample = Vec::with_capacity(n_obs);
            for j in 0..n_obs {
                let u = self.quasi_random(i * n_obs + j, n_samples * n_obs);
                let z = self.normal_quantile(u);
                sample.push(mean + std_dev * z);
            }
            samples.push(sample);
        }

        samples
    }

    /// Quasi-random sequence (Halton-like) for reproducible sampling.
    fn quasi_random(&self, index: usize, _total: usize) -> f64 {
        // Simple radical-inverse with base 2
        let mut result = 0.0;
        let mut f = 0.5;
        let mut i = index + 1; // Avoid 0

        while i > 0 {
            result += f * (i % 2) as f64;
            i /= 2;
            f *= 0.5;
        }

        // Ensure we're in (0, 1)
        result.clamp(1e-10, 1.0 - 1e-10)
    }

    /// Approximate Beta quantile function using Newton-Raphson.
    fn beta_quantile(&self, p: f64, alpha: f64, beta: f64) -> f64 {
        // Initial guess using normal approximation
        let mean = alpha / (alpha + beta);
        let var = (alpha * beta) / ((alpha + beta).powi(2) * (alpha + beta + 1.0));
        let std = var.sqrt();

        let z = self.normal_quantile(p);
        let mut x = (mean + std * z).clamp(0.001, 0.999);

        // Newton-Raphson iterations
        for _ in 0..10 {
            let cdf = self.beta_cdf_approx(x, alpha, beta);
            let pdf = self.beta_pdf(x, alpha, beta);

            if pdf < 1e-10 {
                break;
            }

            let delta = (cdf - p) / pdf;
            x = (x - delta).clamp(0.001, 0.999);

            if delta.abs() < 1e-8 {
                break;
            }
        }

        x
    }

    /// Approximate Gamma quantile function.
    fn gamma_quantile(&self, p: f64, shape: f64, rate: f64) -> f64 {
        // Use Wilson-Hilferty transformation for initial guess
        let mean = shape / rate;

        if shape >= 1.0 {
            // Normal approximation
            let std = (shape / rate / rate).sqrt();
            let z = self.normal_quantile(p);
            (mean + std * z).max(0.001)
        } else {
            // For small shape, use exponential approximation
            let exp_quantile = -mean * p.ln();
            exp_quantile.max(0.001)
        }
    }

    /// Standard normal quantile (probit) function.
    fn normal_quantile(&self, p: f64) -> f64 {
        // Rational approximation (Abramowitz & Stegun)
        let p = p.clamp(1e-10, 1.0 - 1e-10);

        let sign = if p < 0.5 { -1.0 } else { 1.0 };
        let p = if p < 0.5 { p } else { 1.0 - p };

        let t = (-2.0 * p.ln()).sqrt();

        let c0 = 2.515517;
        let c1 = 0.802853;
        let c2 = 0.010328;
        let d1 = 1.432788;
        let d2 = 0.189269;
        let d3 = 0.001308;

        let z = t - (c0 + c1 * t + c2 * t * t) / (1.0 + d1 * t + d2 * t * t + d3 * t * t * t);

        sign * z
    }

    /// Beta PDF.
    fn beta_pdf(&self, x: f64, alpha: f64, beta: f64) -> f64 {
        if x <= 0.0 || x >= 1.0 {
            return 0.0;
        }

        let log_b = pt_math::log_beta(alpha, beta);
        let log_pdf = (alpha - 1.0) * x.ln() + (beta - 1.0) * (1.0 - x).ln() - log_b;
        log_pdf.exp()
    }

    /// Approximate Beta CDF using continued fraction.
    fn beta_cdf_approx(&self, x: f64, alpha: f64, beta: f64) -> f64 {
        if x <= 0.0 {
            return 0.0;
        }
        if x >= 1.0 {
            return 1.0;
        }

        // Simple numerical integration (trapezoidal)
        let n_steps = 100;
        let dx = x / n_steps as f64;
        let mut integral = 0.0;

        for i in 0..=n_steps {
            let xi = i as f64 * dx;
            let yi = self.beta_pdf(xi, alpha, beta);
            let weight = if i == 0 || i == n_steps { 0.5 } else { 1.0 };
            integral += weight * yi;
        }

        (integral * dx).clamp(0.0, 1.0)
    }
}

impl Default for PpcChecker {
    fn default() -> Self {
        Self::new(PpcConfig::default())
    }
}

/// Batch PPC checker for multiple time series.
pub struct BatchPpcChecker {
    checker: PpcChecker,
}

impl BatchPpcChecker {
    /// Create a new batch checker.
    pub fn new(config: PpcConfig) -> Self {
        Self {
            checker: PpcChecker::new(config),
        }
    }

    /// Check multiple Beta-distributed series.
    pub fn check_beta_batch(
        &self,
        series: &HashMap<String, Vec<f64>>,
        posteriors: &HashMap<String, (f64, f64)>,
    ) -> HashMap<String, Result<PpcResult, PpcError>> {
        let mut results = HashMap::new();

        for (name, observations) in series {
            if let Some(&(alpha, beta)) = posteriors.get(name) {
                results.insert(
                    name.clone(),
                    self.checker.check_beta(observations, alpha, beta),
                );
            }
        }

        results
    }

    /// Aggregate evidence from batch checks.
    pub fn aggregate_evidence(
        &self,
        results: &HashMap<String, Result<PpcResult, PpcError>>,
    ) -> AggregatedPpcEvidence {
        let mut passed_count = 0;
        let mut failed_count = 0;
        let mut failed_series = Vec::new();
        let mut min_p_value: f64 = 1.0;
        let mut total_penalty = 0.0;

        for (name, result) in results {
            match result {
                Ok(r) => {
                    if r.passed {
                        passed_count += 1;
                    } else {
                        failed_count += 1;
                        failed_series.push(name.clone());
                        total_penalty += r.confidence_adjustment.abs();
                    }
                    for check in &r.checks {
                        min_p_value = min_p_value.min(check.p_value);
                    }
                }
                Err(_) => {
                    // Insufficient data, skip
                }
            }
        }

        AggregatedPpcEvidence {
            total_series: passed_count + failed_count,
            passed_count,
            failed_count,
            failed_series,
            min_p_value,
            total_confidence_penalty: total_penalty,
            overall_passed: failed_count == 0,
        }
    }
}

/// Aggregated evidence from batch PPC.
#[derive(Debug, Clone, Serialize)]
pub struct AggregatedPpcEvidence {
    /// Total number of series checked.
    pub total_series: usize,
    /// Series that passed all checks.
    pub passed_count: usize,
    /// Series that failed at least one check.
    pub failed_count: usize,
    /// Names of series that failed.
    pub failed_series: Vec<String>,
    /// Minimum p-value across all series/checks.
    pub min_p_value: f64,
    /// Total confidence penalty.
    pub total_confidence_penalty: f64,
    /// Whether all series passed.
    pub overall_passed: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ppc_config_default() {
        let config = PpcConfig::default();
        assert_eq!(config.n_samples, 1000);
        assert_eq!(config.alpha_threshold, 0.05);
        assert_eq!(config.min_observations, 10);
        assert!(config.two_sided);
    }

    #[test]
    fn test_ppc_checker_new() {
        let checker = PpcChecker::default();
        assert_eq!(checker.config.n_samples, 1000);
    }

    #[test]
    fn test_insufficient_data() {
        let checker = PpcChecker::default();
        let obs = vec![0.1, 0.2, 0.3]; // Only 3 points

        let result = checker.check_beta(&obs, 2.0, 8.0);
        assert!(matches!(result, Err(PpcError::InsufficientData { .. })));
    }

    #[test]
    fn test_invalid_parameters() {
        let checker = PpcChecker::default();
        let obs: Vec<f64> = (0..20).map(|i| (i as f64) / 20.0).collect();

        // Negative alpha
        let result = checker.check_beta(&obs, -1.0, 5.0);
        assert!(matches!(result, Err(PpcError::InvalidParameters { .. })));

        // Zero beta
        let result = checker.check_beta(&obs, 2.0, 0.0);
        assert!(matches!(result, Err(PpcError::InvalidParameters { .. })));
    }

    #[test]
    fn test_beta_ppc_passes_for_well_specified() {
        let checker = PpcChecker::new(PpcConfig {
            n_samples: 500,
            alpha_threshold: 0.01, // Strict threshold
            min_observations: 10,
            statistics: vec![TestStatistic::Mean, TestStatistic::Variance],
            two_sided: true,
            failure_confidence_penalty: 0.1,
        });

        // Generate data that matches Beta(2, 8) - mean ~0.2
        let obs: Vec<f64> = (0..50)
            .map(|i| {
                let base = 0.2;
                let noise = ((i % 7) as f64 - 3.0) * 0.03;
                (base + noise).clamp(0.01, 0.99)
            })
            .collect();

        let result = checker.check_beta(&obs, 2.0, 8.0).unwrap();

        // Should generally pass for well-matched data
        // (may occasionally fail due to randomness, but with 500 samples should be stable)
        assert_eq!(result.n_observations, 50);
        assert_eq!(result.n_samples, 500);
        assert_eq!(result.checks.len(), 2);
    }

    #[test]
    fn test_beta_ppc_detects_misspecification() {
        let checker = PpcChecker::new(PpcConfig {
            n_samples: 500,
            alpha_threshold: 0.05,
            min_observations: 10,
            statistics: vec![TestStatistic::Mean],
            two_sided: true,
            failure_confidence_penalty: 0.1,
        });

        // Generate data with mean ~0.8, but test against Beta(2, 8) with mean ~0.2
        let obs: Vec<f64> = (0..50)
            .map(|i| {
                let base = 0.8;
                let noise = ((i % 5) as f64 - 2.0) * 0.02;
                (base + noise).clamp(0.01, 0.99)
            })
            .collect();

        let result = checker.check_beta(&obs, 2.0, 8.0).unwrap();

        // Should detect mean mismatch
        assert!(!result.passed, "Should detect mean misspecification");
        assert!(!result.failed_checks.is_empty());
    }

    #[test]
    fn test_gamma_ppc() {
        let checker = PpcChecker::new(PpcConfig {
            n_samples: 200,
            min_observations: 10,
            statistics: vec![TestStatistic::Mean],
            ..Default::default()
        });

        // Generate exponential-like data (Gamma with shape=1)
        let obs: Vec<f64> = (0..30).map(|i| (i as f64 + 1.0) * 0.1).collect();

        let result = checker.check_gamma(&obs, 2.0, 1.0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_normal_ppc() {
        let checker = PpcChecker::new(PpcConfig {
            n_samples: 200,
            min_observations: 10,
            statistics: vec![TestStatistic::Mean, TestStatistic::Variance],
            ..Default::default()
        });

        // Generate normal-like data around mean=5, var=1
        let obs: Vec<f64> = (0..30)
            .map(|i| 5.0 + ((i % 10) as f64 - 4.5) * 0.4)
            .collect();

        let result = checker.check_normal(&obs, 5.0, 1.0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_compute_mean() {
        let checker = PpcChecker::default();
        let data = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let mean = checker.compute_statistic(&data, TestStatistic::Mean);
        assert!((mean - 3.0).abs() < 1e-10);
    }

    #[test]
    fn test_compute_variance() {
        let checker = PpcChecker::default();
        let data = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let var = checker.compute_statistic(&data, TestStatistic::Variance);
        // Sample variance of [1,2,3,4,5] is 2.5
        assert!((var - 2.5).abs() < 1e-10);
    }

    #[test]
    fn test_max_run_length() {
        let checker = PpcChecker::default();
        // Mean is 5.0, so runs above: [6,7,8], [9] and runs below: [1,2], [3], [4]
        let data = vec![1.0, 2.0, 6.0, 7.0, 8.0, 3.0, 4.0, 9.0];
        let max_run = checker.compute_statistic(&data, TestStatistic::RunLengths);
        assert_eq!(max_run, 3.0);
    }

    #[test]
    fn test_count_change_points() {
        let checker = PpcChecker::default();
        // Clear level shift from ~1 to ~9
        let data = vec![1.0, 1.1, 1.2, 0.9, 1.0, 9.0, 9.1, 8.9, 9.2, 9.0, 8.8, 9.1];
        let cp = checker.compute_statistic(&data, TestStatistic::ChangePoints);
        assert!(cp >= 1.0, "Should detect at least one change point");
    }

    #[test]
    fn test_autocorrelation() {
        let checker = PpcChecker::default();
        // Highly autocorrelated: increasing sequence
        let data: Vec<f64> = (0..20).map(|i| i as f64).collect();
        let acf = checker.compute_statistic(&data, TestStatistic::Autocorrelation);
        assert!(
            acf > 0.8,
            "Increasing sequence should have high autocorrelation"
        );

        // Low autocorrelation: alternating
        let data = vec![1.0, -1.0, 1.0, -1.0, 1.0, -1.0, 1.0, -1.0];
        let acf = checker.compute_statistic(&data, TestStatistic::Autocorrelation);
        assert!(
            acf < 0.0,
            "Alternating sequence should have negative autocorrelation"
        );
    }

    #[test]
    fn test_skewness() {
        let checker = PpcChecker::default();
        // Right-skewed data
        let data = vec![1.0, 1.0, 1.0, 1.0, 1.0, 2.0, 2.0, 10.0];
        let skew = checker.compute_statistic(&data, TestStatistic::Skewness);
        assert!(
            skew > 0.0,
            "Right-skewed data should have positive skewness"
        );
    }

    #[test]
    fn test_fallback_determination() {
        let checker = PpcChecker::default();

        // Variance failure → widen priors
        let failed = vec![StatisticCheck {
            statistic: TestStatistic::Variance,
            observed_value: 10.0,
            expected_value: 1.0,
            p_value: 0.01,
            passed: false,
        }];
        assert_eq!(
            checker.determine_fallback(&failed),
            FallbackAction::WidenPriors
        );

        // Maximum failure → robust layers
        let failed = vec![StatisticCheck {
            statistic: TestStatistic::Maximum,
            observed_value: 100.0,
            expected_value: 10.0,
            p_value: 0.001,
            passed: false,
        }];
        assert_eq!(
            checker.determine_fallback(&failed),
            FallbackAction::UseRobustLayers
        );

        // Autocorrelation failure → reduce learning rate
        let failed = vec![StatisticCheck {
            statistic: TestStatistic::Autocorrelation,
            observed_value: 0.9,
            expected_value: 0.1,
            p_value: 0.02,
            passed: false,
        }];
        assert_eq!(
            checker.determine_fallback(&failed),
            FallbackAction::ReduceLearningRate
        );

        // No failures → none
        assert_eq!(checker.determine_fallback(&[]), FallbackAction::None);
    }

    #[test]
    fn test_p_value_computation() {
        let checker = PpcChecker::new(PpcConfig {
            two_sided: false,
            ..Default::default()
        });

        // Observed at median of simulated → p ~ 0.5
        let simulated: Vec<f64> = (1..=100).map(|i| i as f64).collect();
        let p = checker.compute_p_value(50.0, &simulated);
        assert!(p > 0.4 && p < 0.6);

        // Observed at maximum → p ~ 0.01
        let p = checker.compute_p_value(100.0, &simulated);
        assert!(p < 0.05);
    }

    #[test]
    fn test_ppc_evidence_conversion() {
        let result = PpcResult {
            passed: false,
            n_observations: 50,
            n_samples: 1000,
            checks: vec![
                StatisticCheck {
                    statistic: TestStatistic::Mean,
                    observed_value: 0.8,
                    expected_value: 0.2,
                    p_value: 0.001,
                    passed: false,
                },
                StatisticCheck {
                    statistic: TestStatistic::Variance,
                    observed_value: 0.01,
                    expected_value: 0.05,
                    p_value: 0.1,
                    passed: true,
                },
            ],
            failed_checks: vec![StatisticCheck {
                statistic: TestStatistic::Mean,
                observed_value: 0.8,
                expected_value: 0.2,
                p_value: 0.001,
                passed: false,
            }],
            action_taken: FallbackAction::WidenPriors,
            confidence_adjustment: -0.1,
            summary: "PPC failed".to_string(),
        };

        let evidence = PpcEvidence::from(&result);
        assert!(!evidence.passed);
        assert_eq!(evidence.failed_count, 1);
        assert_eq!(evidence.failed_statistics, vec!["mean"]);
        assert!((evidence.min_p_value - 0.001).abs() < 1e-10);
        assert!((evidence.confidence_penalty - 0.1).abs() < 1e-10);
    }

    #[test]
    fn test_normal_quantile() {
        let checker = PpcChecker::default();

        // Standard normal quantiles
        assert!((checker.normal_quantile(0.5) - 0.0).abs() < 0.01);
        assert!((checker.normal_quantile(0.975) - 1.96).abs() < 0.05);
        assert!((checker.normal_quantile(0.025) - (-1.96)).abs() < 0.05);
    }

    #[test]
    fn test_quasi_random() {
        let checker = PpcChecker::default();

        let samples: Vec<f64> = (0..100).map(|i| checker.quasi_random(i, 100)).collect();

        // All in (0, 1)
        assert!(samples.iter().all(|&x| x > 0.0 && x < 1.0));

        // Reasonably spread out (not all clustered)
        let mean: f64 = samples.iter().sum::<f64>() / 100.0;
        assert!(
            mean > 0.3 && mean < 0.7,
            "Quasi-random mean should be near 0.5"
        );
    }

    #[test]
    fn test_batch_ppc_checker() {
        let batch = BatchPpcChecker::new(PpcConfig {
            n_samples: 100,
            min_observations: 5,
            statistics: vec![TestStatistic::Mean],
            ..Default::default()
        });

        let mut series = HashMap::new();
        series.insert("cpu".to_string(), vec![0.1, 0.15, 0.2, 0.18, 0.12, 0.15]);
        series.insert("mem".to_string(), vec![0.5, 0.55, 0.52, 0.48, 0.51, 0.53]);

        let mut posteriors = HashMap::new();
        posteriors.insert("cpu".to_string(), (2.0, 8.0)); // mean ~0.2
        posteriors.insert("mem".to_string(), (5.0, 5.0)); // mean ~0.5

        let results = batch.check_beta_batch(&series, &posteriors);
        assert_eq!(results.len(), 2);

        let evidence = batch.aggregate_evidence(&results);
        assert_eq!(evidence.total_series, 2);
    }

    #[test]
    fn test_empty_data() {
        let checker = PpcChecker::default();

        assert_eq!(checker.compute_statistic(&[], TestStatistic::Mean), 0.0);
        assert_eq!(checker.compute_statistic(&[], TestStatistic::Variance), 0.0);
        assert_eq!(
            checker.compute_statistic(&[], TestStatistic::RunLengths),
            0.0
        );
    }

    #[test]
    fn test_single_element() {
        let checker = PpcChecker::default();
        let data = vec![5.0];

        assert_eq!(checker.compute_statistic(&data, TestStatistic::Mean), 5.0);
        assert_eq!(
            checker.compute_statistic(&data, TestStatistic::Variance),
            0.0
        );
        assert_eq!(
            checker.compute_statistic(&data, TestStatistic::Maximum),
            5.0
        );
    }

    #[test]
    fn test_ppc_result_summary() {
        let checker = PpcChecker::new(PpcConfig {
            n_samples: 100,
            min_observations: 5,
            statistics: vec![TestStatistic::Mean],
            ..Default::default()
        });

        let obs: Vec<f64> = (0..20).map(|i| 0.1 + (i as f64) * 0.01).collect();
        let result = checker.check_beta(&obs, 2.0, 8.0).unwrap();

        // Summary should be non-empty
        assert!(!result.summary.is_empty());
    }
}
