//! Kalman filtering and smoothing for noisy time series.
//!
//! This module implements scalar (univariate) Kalman filtering and RTS
//! smoothing for denoising CPU%, load, and other resource time series.
//!
//! # Model
//!
//! Linear Gaussian state-space model:
//! ```text
//! x_t = A × x_{t-1} + w_t    (state evolution)
//! y_t = C × x_t + v_t        (observation)
//! ```
//!
//! Where:
//! - `x_t` is the true underlying signal
//! - `y_t` is the noisy observation
//! - `w_t ~ N(0, Q)` is process noise
//! - `v_t ~ N(0, R)` is observation noise
//!
//! For scalar case with A=1, C=1:
//! - `x_t = x_{t-1} + w_t` (random walk)
//! - `y_t = x_t + v_t`
//!
//! # Algorithm
//!
//! 1. **Forward filter**: Compute filtered estimates P(x_t | y_1:t)
//! 2. **Backward smoother** (RTS): Compute smoothed estimates P(x_t | y_1:T)
//!
//! # Example
//!
//! ```
//! use pt_core::inference::kalman::{KalmanFilter, KalmanConfig};
//!
//! // Noisy observations
//! let observations = vec![50.0, 52.0, 48.0, 55.0, 51.0, 49.0];
//!
//! // Create filter with default config
//! let config = KalmanConfig::default();
//! let filter = KalmanFilter::new(config);
//!
//! // Run filter and smoother
//! let result = filter.smooth(&observations);
//!
//! println!("Smoothed values: {:?}", result.smoothed_means);
//! println!("Uncertainties: {:?}", result.smoothed_stds);
//! ```

use serde::{Deserialize, Serialize};

/// Configuration for the Kalman filter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KalmanConfig {
    /// State transition coefficient (A). Default: 1.0 (random walk).
    pub transition_coef: f64,
    /// Observation coefficient (C). Default: 1.0 (direct observation).
    pub observation_coef: f64,
    /// Process noise variance (Q).
    pub process_noise: f64,
    /// Observation noise variance (R).
    pub observation_noise: f64,
    /// Initial state mean.
    pub initial_mean: f64,
    /// Initial state variance.
    pub initial_variance: f64,
    /// Whether to auto-estimate noise parameters from data.
    pub auto_tune: bool,
}

impl KalmanConfig {
    /// Create a config for CPU% smoothing (values 0-100).
    pub fn for_cpu() -> Self {
        Self {
            transition_coef: 1.0,
            observation_coef: 1.0,
            process_noise: 4.0,       // ~2% std per step
            observation_noise: 25.0,  // ~5% measurement noise std
            initial_mean: 50.0,
            initial_variance: 400.0,  // ~20% initial uncertainty
            auto_tune: false,
        }
    }

    /// Create a config for load average smoothing.
    pub fn for_load() -> Self {
        Self {
            transition_coef: 1.0,
            observation_coef: 1.0,
            process_noise: 0.04,      // Small process noise
            observation_noise: 0.16,  // Moderate observation noise
            initial_mean: 1.0,
            initial_variance: 1.0,
            auto_tune: false,
        }
    }

    /// Create a config for memory usage (MB) smoothing.
    pub fn for_memory() -> Self {
        Self {
            transition_coef: 1.0,
            observation_coef: 1.0,
            process_noise: 100.0,      // ~10MB std process noise
            observation_noise: 400.0,  // ~20MB measurement noise
            initial_mean: 1000.0,
            initial_variance: 10000.0,
            auto_tune: false,
        }
    }
}

impl Default for KalmanConfig {
    fn default() -> Self {
        Self {
            transition_coef: 1.0,
            observation_coef: 1.0,
            process_noise: 1.0,
            observation_noise: 1.0,
            initial_mean: 0.0,
            initial_variance: 100.0,
            auto_tune: true,
        }
    }
}

/// State at a single time step after filtering.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct FilterState {
    /// Filtered mean E[x_t | y_1:t].
    pub mean: f64,
    /// Filtered variance Var[x_t | y_1:t].
    pub variance: f64,
    /// Predicted mean E[x_t | y_1:t-1].
    pub predicted_mean: f64,
    /// Predicted variance Var[x_t | y_1:t-1].
    pub predicted_variance: f64,
    /// Kalman gain at this step.
    pub kalman_gain: f64,
    /// Innovation (prediction error).
    pub innovation: f64,
}

/// Result of Kalman smoothing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KalmanResult {
    /// Smoothed state means E[x_t | y_1:T].
    pub smoothed_means: Vec<f64>,
    /// Smoothed state standard deviations.
    pub smoothed_stds: Vec<f64>,
    /// Smoothed state variances.
    pub smoothed_variances: Vec<f64>,
    /// Filtered state means E[x_t | y_1:t] (before smoothing).
    pub filtered_means: Vec<f64>,
    /// Filtered state variances.
    pub filtered_variances: Vec<f64>,
    /// Log-likelihood of the observations.
    pub log_likelihood: f64,
    /// Mean squared innovation (for model diagnostics).
    pub mean_squared_innovation: f64,
    /// Number of observations processed.
    pub n_observations: usize,
    /// Estimated process noise (if auto-tuned).
    pub estimated_process_noise: Option<f64>,
    /// Estimated observation noise (if auto-tuned).
    pub estimated_observation_noise: Option<f64>,
}

/// Scalar Kalman filter with RTS smoother.
#[derive(Debug, Clone)]
pub struct KalmanFilter {
    config: KalmanConfig,
}

impl KalmanFilter {
    /// Create a new filter with the given configuration.
    pub fn new(config: KalmanConfig) -> Self {
        Self { config }
    }

    /// Create a filter with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(KalmanConfig::default())
    }

    /// Run forward filtering only (no smoothing).
    pub fn filter(&self, observations: &[f64]) -> Vec<FilterState> {
        let n = observations.len();
        if n == 0 {
            return vec![];
        }

        let (q, r) = self.get_noise_params(observations);
        let a = self.config.transition_coef;
        let c = self.config.observation_coef;

        let mut states = Vec::with_capacity(n);

        // Initialize
        let mut x_filt = self.get_initial_mean(observations);
        let mut p_filt = self.config.initial_variance;

        for &y in observations {
            // Predict step
            let x_pred = a * x_filt;
            let p_pred = a * a * p_filt + q;

            // Update step
            let innovation = y - c * x_pred;
            let s = c * c * p_pred + r; // Innovation variance
            let k = p_pred * c / s; // Kalman gain

            x_filt = x_pred + k * innovation;
            p_filt = (1.0 - k * c) * p_pred;

            // Ensure variance stays positive
            p_filt = p_filt.max(1e-10);

            states.push(FilterState {
                mean: x_filt,
                variance: p_filt,
                predicted_mean: x_pred,
                predicted_variance: p_pred,
                kalman_gain: k,
                innovation,
            });
        }

        states
    }

    /// Run forward filtering and backward RTS smoothing.
    pub fn smooth(&self, observations: &[f64]) -> KalmanResult {
        let n = observations.len();
        if n == 0 {
            return KalmanResult {
                smoothed_means: vec![],
                smoothed_stds: vec![],
                smoothed_variances: vec![],
                filtered_means: vec![],
                filtered_variances: vec![],
                log_likelihood: 0.0,
                mean_squared_innovation: 0.0,
                n_observations: 0,
                estimated_process_noise: None,
                estimated_observation_noise: None,
            };
        }

        let (q, r) = self.get_noise_params(observations);
        let a = self.config.transition_coef;

        // Forward filter
        let filter_states = self.filter(observations);

        // Extract filtered means and variances
        let filtered_means: Vec<f64> = filter_states.iter().map(|s| s.mean).collect();
        let filtered_variances: Vec<f64> = filter_states.iter().map(|s| s.variance).collect();

        // Compute log-likelihood and mean squared innovation
        let c = self.config.observation_coef;
        let mut log_likelihood = 0.0;
        let mut sum_sq_innovation = 0.0;

        for state in &filter_states {
            let s = c * c * state.predicted_variance + r;
            log_likelihood += -0.5 * (state.innovation * state.innovation / s + s.ln() + std::f64::consts::TAU.ln() / 2.0);
            sum_sq_innovation += state.innovation * state.innovation;
        }
        let mean_squared_innovation = sum_sq_innovation / n as f64;

        // Backward RTS smoother
        let mut smoothed_means = filtered_means.clone();
        let mut smoothed_variances = filtered_variances.clone();

        // Start from the end (last filtered state is already smoothed)
        for t in (0..n - 1).rev() {
            // Smoother gain
            let p_pred_next = a * a * filtered_variances[t] + q;
            let j = a * filtered_variances[t] / p_pred_next.max(1e-10);

            // Smoothed mean
            smoothed_means[t] = filtered_means[t]
                + j * (smoothed_means[t + 1] - a * filtered_means[t]);

            // Smoothed variance
            smoothed_variances[t] = filtered_variances[t]
                + j * j * (smoothed_variances[t + 1] - p_pred_next);

            // Ensure variance stays positive
            smoothed_variances[t] = smoothed_variances[t].max(1e-10);
        }

        let smoothed_stds: Vec<f64> = smoothed_variances.iter().map(|v| v.sqrt()).collect();

        let (est_q, est_r) = if self.config.auto_tune {
            (Some(q), Some(r))
        } else {
            (None, None)
        };

        KalmanResult {
            smoothed_means,
            smoothed_stds,
            smoothed_variances,
            filtered_means,
            filtered_variances,
            log_likelihood,
            mean_squared_innovation,
            n_observations: n,
            estimated_process_noise: est_q,
            estimated_observation_noise: est_r,
        }
    }

    /// Get noise parameters, optionally auto-tuning from data.
    fn get_noise_params(&self, observations: &[f64]) -> (f64, f64) {
        if !self.config.auto_tune || observations.len() < 3 {
            return (self.config.process_noise, self.config.observation_noise);
        }

        // Simple estimation from data
        // Use the variance of differences as a proxy for total noise
        let diffs: Vec<f64> = observations.windows(2).map(|w| w[1] - w[0]).collect();
        let diff_var = variance(&diffs);

        // Total variance in differences is approximately 2R + Q for random walk model
        // Split roughly: assume Q ~ diff_var/3, R ~ diff_var/3
        let q = (diff_var / 3.0).max(0.01);
        let r = (diff_var / 3.0).max(0.01);

        (q, r)
    }

    /// Get initial mean, optionally from first observation.
    fn get_initial_mean(&self, observations: &[f64]) -> f64 {
        if self.config.auto_tune && !observations.is_empty() {
            observations[0]
        } else {
            self.config.initial_mean
        }
    }

    /// Smooth a time series and return only the smoothed values.
    pub fn smooth_values(&self, observations: &[f64]) -> Vec<f64> {
        self.smooth(observations).smoothed_means
    }

    /// Get smoothed value at a specific index with uncertainty.
    pub fn get_smoothed(&self, result: &KalmanResult, index: usize) -> Option<(f64, f64)> {
        if index < result.n_observations {
            Some((result.smoothed_means[index], result.smoothed_stds[index]))
        } else {
            None
        }
    }
}

impl Default for KalmanFilter {
    fn default() -> Self {
        Self::with_defaults()
    }
}

/// Evidence term for integration with the decision core.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KalmanEvidence {
    /// Summary of smoothing results.
    pub summary: KalmanSummary,
    /// Log-odds contribution (based on noise characteristics).
    pub log_odds: f64,
    /// Feature glyph for display.
    pub glyph: char,
    /// Short description.
    pub description: String,
}

/// Summary statistics from Kalman smoothing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KalmanSummary {
    /// Mean of smoothed values.
    pub mean: f64,
    /// Standard deviation of smoothed values.
    pub std: f64,
    /// Minimum smoothed value.
    pub min: f64,
    /// Maximum smoothed value.
    pub max: f64,
    /// Average smoothing uncertainty.
    pub avg_uncertainty: f64,
    /// Noise ratio (observation noise / signal variance).
    pub noise_ratio: f64,
    /// Trend direction (positive = increasing).
    pub trend: f64,
}

impl KalmanEvidence {
    /// Create evidence from a smoothed CPU% time series.
    pub fn from_cpu_result(result: &KalmanResult) -> Self {
        let summary = Self::compute_summary(result);

        // High average CPU with high certainty → useful_bad (potential runaway)
        // Stable low CPU → useful
        let log_odds = if summary.mean > 80.0 && summary.avg_uncertainty < 10.0 {
            // High CPU with confidence
            1.0
        } else if summary.mean > 60.0 {
            // Elevated CPU
            0.3
        } else if summary.mean < 5.0 && summary.avg_uncertainty < 5.0 {
            // Idle with confidence → might be abandoned
            0.2
        } else {
            0.0
        };

        let glyph = if summary.mean > 80.0 {
            '●'
        } else if summary.mean > 50.0 {
            '◑'
        } else if summary.mean > 20.0 {
            '◐'
        } else {
            '○'
        };

        let description = format!(
            "CPU smoothed: {:.1}% ± {:.1}% (trend: {:+.2}%/step)",
            summary.mean, summary.avg_uncertainty, summary.trend
        );

        Self {
            summary,
            log_odds,
            glyph,
            description,
        }
    }

    /// Compute summary statistics from result.
    fn compute_summary(result: &KalmanResult) -> KalmanSummary {
        let n = result.n_observations;
        if n == 0 {
            return KalmanSummary {
                mean: 0.0,
                std: 0.0,
                min: 0.0,
                max: 0.0,
                avg_uncertainty: 0.0,
                noise_ratio: 0.0,
                trend: 0.0,
            };
        }

        let mean = result.smoothed_means.iter().sum::<f64>() / n as f64;
        let variance = result.smoothed_means.iter()
            .map(|x| (x - mean).powi(2))
            .sum::<f64>() / n as f64;
        let std = variance.sqrt();

        let min = result.smoothed_means.iter().cloned().fold(f64::INFINITY, f64::min);
        let max = result.smoothed_means.iter().cloned().fold(f64::NEG_INFINITY, f64::max);

        let avg_uncertainty = result.smoothed_stds.iter().sum::<f64>() / n as f64;

        let noise_ratio = if variance > 0.0 {
            avg_uncertainty.powi(2) / variance
        } else {
            1.0
        };

        // Simple trend: slope from first to last
        let trend = if n > 1 {
            (result.smoothed_means[n - 1] - result.smoothed_means[0]) / (n - 1) as f64
        } else {
            0.0
        };

        KalmanSummary {
            mean,
            std,
            min,
            max,
            avg_uncertainty,
            noise_ratio,
            trend,
        }
    }
}

/// Compute variance of a slice.
fn variance(data: &[f64]) -> f64 {
    let n = data.len();
    if n < 2 {
        return 0.0;
    }
    let mean = data.iter().sum::<f64>() / n as f64;
    data.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1) as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx_eq(a: f64, b: f64, tol: f64) -> bool {
        (a - b).abs() <= tol
    }

    #[test]
    fn test_kalman_config_default() {
        let config = KalmanConfig::default();
        assert!(config.auto_tune);
        assert_eq!(config.transition_coef, 1.0);
        assert_eq!(config.observation_coef, 1.0);
    }

    #[test]
    fn test_kalman_config_for_cpu() {
        let config = KalmanConfig::for_cpu();
        assert!(!config.auto_tune);
        assert_eq!(config.initial_mean, 50.0);
    }

    #[test]
    fn test_kalman_empty_observations() {
        let filter = KalmanFilter::with_defaults();
        let result = filter.smooth(&[]);

        assert_eq!(result.n_observations, 0);
        assert!(result.smoothed_means.is_empty());
    }

    #[test]
    fn test_kalman_single_observation() {
        let filter = KalmanFilter::with_defaults();
        let result = filter.smooth(&[50.0]);

        assert_eq!(result.n_observations, 1);
        assert_eq!(result.smoothed_means.len(), 1);
    }

    #[test]
    fn test_kalman_constant_signal() {
        let config = KalmanConfig {
            process_noise: 0.1,
            observation_noise: 1.0,
            initial_mean: 50.0,
            initial_variance: 10.0,
            auto_tune: false,
            ..KalmanConfig::default()
        };
        let filter = KalmanFilter::new(config);

        // Constant signal with some noise
        let observations = vec![50.0, 50.5, 49.5, 50.2, 49.8, 50.0];
        let result = filter.smooth(&observations);

        // Smoothed values should be close to 50
        for val in &result.smoothed_means {
            assert!(
                (*val - 50.0).abs() < 3.0,
                "Smoothed value {} too far from 50",
                val
            );
        }
    }

    #[test]
    fn test_kalman_trending_signal() {
        let config = KalmanConfig {
            process_noise: 1.0,
            observation_noise: 1.0,
            initial_mean: 0.0,
            initial_variance: 10.0,
            auto_tune: false,
            ..KalmanConfig::default()
        };
        let filter = KalmanFilter::new(config);

        // Linear trend: 0, 10, 20, 30, 40, 50
        let observations: Vec<f64> = (0..6).map(|i| i as f64 * 10.0).collect();
        let result = filter.smooth(&observations);

        // Smoothed values should follow the trend
        for (i, val) in result.smoothed_means.iter().enumerate() {
            let expected = i as f64 * 10.0;
            assert!(
                (*val - expected).abs() < 10.0,
                "Smoothed[{}] = {} too far from expected {}",
                i,
                val,
                expected
            );
        }
    }

    #[test]
    fn test_kalman_reduces_noise() {
        let config = KalmanConfig {
            process_noise: 1.0,
            observation_noise: 100.0, // High observation noise
            initial_mean: 50.0,
            initial_variance: 10.0,
            auto_tune: false,
            ..KalmanConfig::default()
        };
        let filter = KalmanFilter::new(config);

        // Noisy observations around 50
        let observations = vec![60.0, 40.0, 70.0, 30.0, 55.0, 45.0];
        let result = filter.smooth(&observations);

        // Variance of smoothed should be less than variance of raw
        let raw_var = variance(&observations);
        let smooth_var = variance(&result.smoothed_means);

        assert!(
            smooth_var < raw_var,
            "Smoothing should reduce variance: raw={:.2}, smooth={:.2}",
            raw_var,
            smooth_var
        );
    }

    #[test]
    fn test_kalman_uncertainty_decreases() {
        let filter = KalmanFilter::new(KalmanConfig::for_cpu());

        let observations = vec![50.0, 52.0, 48.0, 51.0, 49.0, 50.0, 51.0, 49.0];
        let result = filter.smooth(&observations);

        // Smoothed uncertainties should generally be smaller than filtered
        // (smoothing uses more information)
        let avg_filtered_var = result.filtered_variances.iter().sum::<f64>()
            / result.n_observations as f64;
        let avg_smoothed_var = result.smoothed_variances.iter().sum::<f64>()
            / result.n_observations as f64;

        assert!(
            avg_smoothed_var <= avg_filtered_var + 1e-6,
            "Smoothed variance {} should be <= filtered {}",
            avg_smoothed_var,
            avg_filtered_var
        );
    }

    #[test]
    fn test_kalman_filter_states() {
        let filter = KalmanFilter::new(KalmanConfig::for_cpu());
        let observations = vec![50.0, 55.0, 45.0];

        let states = filter.filter(&observations);

        assert_eq!(states.len(), 3);
        for state in &states {
            assert!(state.variance > 0.0);
            assert!(state.kalman_gain > 0.0 && state.kalman_gain < 1.0);
        }
    }

    #[test]
    fn test_kalman_smooth_values() {
        let filter = KalmanFilter::with_defaults();
        let observations = vec![1.0, 2.0, 3.0, 4.0, 5.0];

        let smoothed = filter.smooth_values(&observations);

        assert_eq!(smoothed.len(), 5);
    }

    #[test]
    fn test_kalman_evidence() {
        let filter = KalmanFilter::new(KalmanConfig::for_cpu());
        let observations = vec![45.0, 50.0, 48.0, 52.0, 47.0];

        let result = filter.smooth(&observations);
        let evidence = KalmanEvidence::from_cpu_result(&result);

        assert!(evidence.summary.mean > 40.0 && evidence.summary.mean < 60.0);
        assert!(evidence.log_odds.is_finite());
        assert!(!evidence.description.is_empty());
    }

    #[test]
    fn test_kalman_auto_tune() {
        let config = KalmanConfig {
            auto_tune: true,
            ..KalmanConfig::default()
        };
        let filter = KalmanFilter::new(config);

        let observations = vec![10.0, 15.0, 12.0, 18.0, 14.0, 16.0];
        let result = filter.smooth(&observations);

        assert!(result.estimated_process_noise.is_some());
        assert!(result.estimated_observation_noise.is_some());
    }

    #[test]
    fn test_kalman_log_likelihood() {
        let filter = KalmanFilter::new(KalmanConfig::for_cpu());
        let observations = vec![50.0, 52.0, 48.0, 51.0, 49.0];

        let result = filter.smooth(&observations);

        // Log-likelihood should be finite and negative
        assert!(result.log_likelihood.is_finite());
    }

    #[test]
    fn test_variance_helper() {
        let data = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let var = variance(&data);

        // Variance of 1,2,3,4,5 is 2.5 (sample variance)
        assert!(approx_eq(var, 2.5, 1e-10));
    }

    #[test]
    fn test_variance_empty() {
        let var = variance(&[]);
        assert!(approx_eq(var, 0.0, 1e-10));
    }

    #[test]
    fn test_kalman_summary_trend() {
        let filter = KalmanFilter::new(KalmanConfig::for_cpu());

        // Increasing trend
        let observations = vec![40.0, 50.0, 60.0, 70.0, 80.0];
        let result = filter.smooth(&observations);
        let evidence = KalmanEvidence::from_cpu_result(&result);

        assert!(evidence.summary.trend > 0.0, "Trend should be positive");
    }
}
