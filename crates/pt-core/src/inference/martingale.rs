//! Martingale concentration and time-uniform confidence sequences.
//!
//! This module implements Plan §4.25 / §2(AP)/§2(BM): martingale concentration bounds
//! as deterministic, interpretable summaries for detecting sustained anomalies.
//!
//! These are not replacements for the conjugate inference core; they provide
//! conservative "sustained deviation" evidence terms and safety gates that remain
//! valid under optional stopping (time-uniform bounds).
//!
//! # Mathematical Foundation
//!
//! ## Azuma-Hoeffding (Bounded Increments)
//!
//! For a martingale (Mₙ) with bounded increments |Mᵢ - Mᵢ₋₁| ≤ cᵢ:
//! ```text
//! P(Mₙ - M₀ ≥ t) ≤ exp(-t² / (2∑cᵢ²))
//! ```
//!
//! ## Freedman/Bernstein (Variance-Adaptive)
//!
//! When conditional variances Vᵢ = E[(Mᵢ - Mᵢ₋₁)² | Fᵢ₋₁] are available:
//! ```text
//! P(Mₙ ≥ t and Vₙ ≤ v) ≤ exp(-t² / (2(v + ct/3)))
//! ```
//! This provides tighter bounds when actual variance is much smaller than worst-case.
//!
//! ## Time-Uniform Confidence Sequences
//!
//! For anytime-valid inference (valid under optional stopping), we use the
//! method of mixtures (conjugate prior over the parameter) to get bounds like:
//! ```text
//! P(∃n: |Sₙ/n - μ| > √(2(1 + 1/n)log(√(n+1)/α)/n)) ≤ α
//! ```
//! These remain valid even when stopping time is chosen adaptively.
//!
//! # Usage
//!
//! ```
//! use pt_core::inference::martingale::{MartingaleAnalyzer, MartingaleConfig};
//!
//! let config = MartingaleConfig::default();
//! let mut analyzer = MartingaleAnalyzer::new(config);
//!
//! // Feed bounded increments
//! for &increment in &[0.1, -0.2, 0.15, -0.05, 0.3] {
//!     analyzer.update_bounded(increment, 0.5); // bound c = 0.5
//! }
//!
//! // Get summary with tail bounds
//! let result = analyzer.summary();
//! println!("Tail probability bound: {:.4}", result.tail_probability);
//! ```

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors from martingale analysis.
#[derive(Debug, Error)]
pub enum MartingaleError {
    #[error("invalid bound: {0} (must be positive)")]
    InvalidBound(f64),

    #[error("invalid confidence level: {0} (must be in (0, 1))")]
    InvalidConfidence(f64),

    #[error("invalid variance: {0} (must be non-negative)")]
    InvalidVariance(f64),

    #[error("insufficient data: need at least {needed} observations, have {have}")]
    InsufficientData { needed: usize, have: usize },
}

/// Configuration for martingale analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MartingaleConfig {
    /// Default bound on increment magnitude (|Xᵢ - Xᵢ₋₁| ≤ c).
    #[serde(default = "default_increment_bound")]
    pub default_increment_bound: f64,

    /// Confidence level for tail bounds (α in P(deviation) ≤ α).
    #[serde(default = "default_confidence")]
    pub confidence_level: f64,

    /// Whether to use log-domain arithmetic for numerical stability.
    #[serde(default = "default_use_log_domain")]
    pub use_log_domain: bool,

    /// Minimum observations before computing bounds.
    #[serde(default = "default_min_observations")]
    pub min_observations: usize,

    /// Bernstein constant (c/3 factor in variance term).
    #[serde(default = "default_bernstein_factor")]
    pub bernstein_factor: f64,
}

fn default_increment_bound() -> f64 {
    1.0
}

fn default_confidence() -> f64 {
    0.05
}

fn default_use_log_domain() -> bool {
    true
}

fn default_min_observations() -> usize {
    3
}

fn default_bernstein_factor() -> f64 {
    1.0 / 3.0
}

impl Default for MartingaleConfig {
    fn default() -> Self {
        Self {
            default_increment_bound: default_increment_bound(),
            confidence_level: default_confidence(),
            use_log_domain: default_use_log_domain(),
            min_observations: default_min_observations(),
            bernstein_factor: default_bernstein_factor(),
        }
    }
}

impl MartingaleConfig {
    /// Validate configuration.
    pub fn validate(&self) -> Result<(), MartingaleError> {
        if self.default_increment_bound <= 0.0 {
            return Err(MartingaleError::InvalidBound(self.default_increment_bound));
        }
        if self.confidence_level <= 0.0 || self.confidence_level >= 1.0 {
            return Err(MartingaleError::InvalidConfidence(self.confidence_level));
        }
        Ok(())
    }

    /// Conservative configuration for high-stakes anomaly detection.
    pub fn conservative() -> Self {
        Self {
            default_increment_bound: 1.0,
            confidence_level: 0.01,
            use_log_domain: true,
            min_observations: 5,
            bernstein_factor: 1.0 / 3.0,
        }
    }

    /// Sensitive configuration for early anomaly detection.
    pub fn sensitive() -> Self {
        Self {
            default_increment_bound: 1.0,
            confidence_level: 0.10,
            use_log_domain: true,
            min_observations: 3,
            bernstein_factor: 1.0 / 3.0,
        }
    }
}

/// Result of a single martingale update.
#[derive(Debug, Clone, Serialize)]
pub struct MartingaleUpdateResult {
    /// Current step number.
    pub step: usize,
    /// Current cumulative sum.
    pub cumulative_sum: f64,
    /// Sum of squared bounds (for Azuma-Hoeffding).
    pub sum_squared_bounds: f64,
    /// Sum of conditional variances (for Freedman/Bernstein).
    pub sum_variances: f64,
    /// Instantaneous Azuma-Hoeffding tail bound.
    pub azuma_tail_bound: f64,
    /// Instantaneous Bernstein tail bound (if variance info available).
    pub bernstein_tail_bound: Option<f64>,
}

/// Evidence from martingale analysis for the inference layer.
#[derive(Debug, Clone, Serialize)]
pub struct MartingaleEvidence {
    /// Type of evidence: "sustained_anomaly" or "normal_variation".
    pub evidence_type: String,
    /// Description of the finding.
    pub description: String,
    /// Weight/importance of this evidence (0-1).
    pub weight: f64,
    /// Which bound produced this evidence.
    pub bound_type: BoundType,
    /// Parameters used for the bound.
    pub parameters: BoundParameters,
}

/// Type of concentration bound used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundType {
    /// Azuma-Hoeffding for bounded increments.
    AzumaHoeffding,
    /// Freedman/Bernstein variance-adaptive bound.
    FreedmanBernstein,
    /// Time-uniform (anytime-valid) confidence sequence.
    TimeUniform,
    /// Composite/combined bound.
    Combined,
}

impl std::fmt::Display for BoundType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BoundType::AzumaHoeffding => write!(f, "Azuma-Hoeffding"),
            BoundType::FreedmanBernstein => write!(f, "Freedman-Bernstein"),
            BoundType::TimeUniform => write!(f, "time-uniform"),
            BoundType::Combined => write!(f, "combined"),
        }
    }
}

/// Parameters used in bound computation.
#[derive(Debug, Clone, Serialize)]
pub struct BoundParameters {
    /// Number of observations.
    pub n: usize,
    /// Increment bound c.
    pub increment_bound: f64,
    /// Sum of squared bounds.
    pub sum_squared_bounds: f64,
    /// Sum of variances (for Bernstein).
    pub sum_variances: Option<f64>,
    /// Time horizon (for time-uniform).
    pub time_horizon: Option<f64>,
}

/// Summary result from martingale analysis.
#[derive(Debug, Clone, Serialize)]
pub struct MartingaleResult {
    /// Number of observations processed.
    pub n: usize,
    /// Cumulative sum/statistic.
    pub cumulative_sum: f64,
    /// Sample mean.
    pub sample_mean: f64,
    /// Azuma-Hoeffding tail probability bound.
    pub azuma_tail_bound: f64,
    /// Bernstein tail probability bound.
    pub bernstein_tail_bound: Option<f64>,
    /// Time-uniform confidence radius.
    pub time_uniform_radius: f64,
    /// Combined (tightest) tail bound.
    pub tail_probability: f64,
    /// E-value for sustained anomaly (reciprocal of tail bound).
    pub e_value: f64,
    /// Anomaly score (log of e-value, clipped).
    pub anomaly_score: f64,
    /// Whether anomaly is detected at configured confidence.
    pub anomaly_detected: bool,
    /// Which bound type produced the tightest result.
    pub best_bound: BoundType,
    /// Evidence summary for ledger.
    pub evidence: MartingaleEvidence,
}

/// Streaming martingale analyzer.
///
/// Maintains running statistics for concentration bound computation.
#[derive(Debug, Clone)]
pub struct MartingaleAnalyzer {
    config: MartingaleConfig,
    /// Number of observations.
    n: usize,
    /// Cumulative sum of increments.
    cumulative_sum: f64,
    /// Sum of squared bounds (for Azuma).
    sum_squared_bounds: f64,
    /// Sum of conditional variances (for Bernstein).
    sum_variances: f64,
    /// Whether variance info has been provided.
    has_variance_info: bool,
    /// Log of sum of squared bounds (for numerical stability).
    log_sum_sq_bounds: f64,
}

impl MartingaleAnalyzer {
    /// Create a new analyzer with the given configuration.
    pub fn new(config: MartingaleConfig) -> Self {
        Self {
            config,
            n: 0,
            cumulative_sum: 0.0,
            sum_squared_bounds: 0.0,
            sum_variances: 0.0,
            has_variance_info: false,
            log_sum_sq_bounds: f64::NEG_INFINITY,
        }
    }

    /// Reset the analyzer state.
    pub fn reset(&mut self) {
        self.n = 0;
        self.cumulative_sum = 0.0;
        self.sum_squared_bounds = 0.0;
        self.sum_variances = 0.0;
        self.has_variance_info = false;
        self.log_sum_sq_bounds = f64::NEG_INFINITY;
    }

    /// Update with a new bounded increment.
    ///
    /// # Arguments
    /// * `increment` - The martingale increment (Mₙ - Mₙ₋₁)
    /// * `bound` - The bound on |increment| (cₙ where |increment| ≤ cₙ)
    pub fn update_bounded(&mut self, increment: f64, bound: f64) -> MartingaleUpdateResult {
        let bound = bound.abs().max(increment.abs());

        self.n += 1;
        self.cumulative_sum += increment;
        self.sum_squared_bounds += bound * bound;

        // Log-domain update for numerical stability
        let log_bound_sq = 2.0 * bound.abs().ln();
        self.log_sum_sq_bounds = log_add_exp(self.log_sum_sq_bounds, log_bound_sq);

        let azuma_tail = self.compute_azuma_bound();

        MartingaleUpdateResult {
            step: self.n,
            cumulative_sum: self.cumulative_sum,
            sum_squared_bounds: self.sum_squared_bounds,
            sum_variances: self.sum_variances,
            azuma_tail_bound: azuma_tail,
            bernstein_tail_bound: None,
        }
    }

    /// Update with increment and conditional variance.
    ///
    /// # Arguments
    /// * `increment` - The martingale increment
    /// * `bound` - The bound on |increment|
    /// * `variance` - The conditional variance E[(Mₙ - Mₙ₋₁)² | Fₙ₋₁]
    pub fn update_with_variance(
        &mut self,
        increment: f64,
        bound: f64,
        variance: f64,
    ) -> MartingaleUpdateResult {
        let bound = bound.abs().max(increment.abs());

        self.n += 1;
        self.cumulative_sum += increment;
        self.sum_squared_bounds += bound * bound;
        self.sum_variances += variance.max(0.0);
        self.has_variance_info = true;

        let log_bound_sq = 2.0 * bound.abs().ln();
        self.log_sum_sq_bounds = log_add_exp(self.log_sum_sq_bounds, log_bound_sq);

        let azuma_tail = self.compute_azuma_bound();
        let bernstein_tail = self.compute_bernstein_bound(bound);

        MartingaleUpdateResult {
            step: self.n,
            cumulative_sum: self.cumulative_sum,
            sum_squared_bounds: self.sum_squared_bounds,
            sum_variances: self.sum_variances,
            azuma_tail_bound: azuma_tail,
            bernstein_tail_bound: Some(bernstein_tail),
        }
    }

    /// Update with default increment bound from config.
    pub fn update(&mut self, increment: f64) -> MartingaleUpdateResult {
        self.update_bounded(increment, self.config.default_increment_bound)
    }

    /// Compute Azuma-Hoeffding tail bound.
    ///
    /// P(Sₙ ≥ t) ≤ exp(-t² / (2∑cᵢ²))
    fn compute_azuma_bound(&self) -> f64 {
        if self.n == 0 || self.sum_squared_bounds <= 0.0 {
            return 1.0;
        }

        let t = self.cumulative_sum.abs();
        let denominator = 2.0 * self.sum_squared_bounds;

        if self.config.use_log_domain {
            // log(exp(-t²/denom)) = -t²/denom
            let log_prob = -(t * t) / denominator;
            log_prob.exp().min(1.0)
        } else {
            (-(t * t) / denominator).exp().min(1.0)
        }
    }

    /// Compute Freedman/Bernstein variance-adaptive bound.
    ///
    /// P(Sₙ ≥ t and Vₙ ≤ v) ≤ exp(-t² / (2(v + ct/3)))
    fn compute_bernstein_bound(&self, max_bound: f64) -> f64 {
        if self.n == 0 {
            return 1.0;
        }

        let t = self.cumulative_sum.abs();
        let v = self.sum_variances;
        let c = max_bound;
        let factor = self.config.bernstein_factor;

        let denominator = 2.0 * (v + c * t * factor);
        if denominator <= 0.0 {
            return 1.0;
        }

        if self.config.use_log_domain {
            let log_prob = -(t * t) / denominator;
            log_prob.exp().min(1.0)
        } else {
            (-(t * t) / denominator).exp().min(1.0)
        }
    }

    /// Compute time-uniform confidence radius.
    ///
    /// For a mean estimate μ̂ₙ = Sₙ/n with bounded observations in [-c, c],
    /// the time-uniform confidence interval at level α is approximately:
    ///
    /// |μ̂ₙ - μ| ≤ c × √(2(1 + 1/n) × log(√(n+1)/α) / n)
    ///
    /// This uses the method of mixtures for anytime-valid inference.
    pub fn time_uniform_radius(&self, alpha: f64, bound: f64) -> f64 {
        if self.n == 0 {
            return f64::INFINITY;
        }

        let n = self.n as f64;

        // Time-uniform radius using stitched boundary
        // Based on Howard et al. (2021) "Time-uniform, nonparametric..."
        let log_term = ((n + 1.0).sqrt() / alpha).ln();
        

        bound * (2.0 * (1.0 + 1.0 / n) * log_term / n).sqrt()
    }

    /// Compute e-value from the martingale.
    ///
    /// E-value is the reciprocal of the p-value bound, used for safe testing.
    /// E > 1/α provides evidence against the null at level α.
    pub fn e_value(&self) -> f64 {
        let tail_bound = self.compute_azuma_bound().max(1e-300);
        (1.0 / tail_bound).min(1e15)
    }

    /// Get the current number of observations.
    pub fn len(&self) -> usize {
        self.n
    }

    /// Check if analyzer is empty.
    pub fn is_empty(&self) -> bool {
        self.n == 0
    }

    /// Get summary result with all bounds.
    pub fn summary(&self) -> MartingaleResult {
        let azuma_tail = self.compute_azuma_bound();

        let bernstein_tail = if self.has_variance_info {
            let max_bound = self.sum_squared_bounds.sqrt() / (self.n as f64).sqrt();
            Some(self.compute_bernstein_bound(max_bound))
        } else {
            None
        };

        let time_uniform_radius = self.time_uniform_radius(
            self.config.confidence_level,
            self.config.default_increment_bound,
        );

        // Combined tail bound is the tightest available
        let mut tail_probability = azuma_tail;
        let mut best_bound = BoundType::AzumaHoeffding;

        if let Some(bern) = bernstein_tail {
            if bern < tail_probability {
                tail_probability = bern;
                best_bound = BoundType::FreedmanBernstein;
            }
        }

        // Convert deviation to tail probability for time-uniform
        if self.n > 0 {
            let sample_mean = self.cumulative_sum / self.n as f64;
            let threshold = time_uniform_radius;
            if sample_mean.abs() > threshold {
                // Crude approximation: if outside confidence interval,
                // tail probability is roughly exp(-n × (deviation/bound)²/2)
                let z = sample_mean.abs() / self.config.default_increment_bound;
                let tu_tail = (-(self.n as f64) * z * z / 2.0).exp();
                if tu_tail < tail_probability {
                    tail_probability = tu_tail;
                    best_bound = BoundType::TimeUniform;
                }
            }
        }

        let e_value = (1.0 / tail_probability.max(1e-300)).min(1e15);
        let anomaly_score = e_value.ln().clamp(0.0, 30.0); // Cap at 30 nats ≈ 13 bits
        let anomaly_detected = tail_probability < self.config.confidence_level;

        let sample_mean = if self.n > 0 {
            self.cumulative_sum / self.n as f64
        } else {
            0.0
        };

        let evidence = MartingaleEvidence {
            evidence_type: if anomaly_detected {
                "sustained_anomaly".to_string()
            } else {
                "normal_variation".to_string()
            },
            description: format!(
                "{} bound: P(deviation ≥ {:.3}) ≤ {:.4} (e-value: {:.2})",
                best_bound,
                self.cumulative_sum.abs(),
                tail_probability,
                e_value
            ),
            weight: anomaly_score / 10.0, // Normalize to 0-3 range approx
            bound_type: best_bound,
            parameters: BoundParameters {
                n: self.n,
                increment_bound: self.config.default_increment_bound,
                sum_squared_bounds: self.sum_squared_bounds,
                sum_variances: if self.has_variance_info {
                    Some(self.sum_variances)
                } else {
                    None
                },
                time_horizon: None,
            },
        };

        MartingaleResult {
            n: self.n,
            cumulative_sum: self.cumulative_sum,
            sample_mean,
            azuma_tail_bound: azuma_tail,
            bernstein_tail_bound: bernstein_tail,
            time_uniform_radius,
            tail_probability,
            e_value,
            anomaly_score,
            anomaly_detected,
            best_bound,
            evidence,
        }
    }
}

impl Default for MartingaleAnalyzer {
    fn default() -> Self {
        Self::new(MartingaleConfig::default())
    }
}

/// Compute log(exp(a) + exp(b)) in a numerically stable way.
#[inline]
fn log_add_exp(a: f64, b: f64) -> f64 {
    if a == f64::NEG_INFINITY {
        return b;
    }
    if b == f64::NEG_INFINITY {
        return a;
    }

    let (max_val, min_val) = if a > b { (a, b) } else { (b, a) };
    max_val + (1.0 + (min_val - max_val).exp()).ln()
}

/// Batch analyzer for multiple streams.
#[derive(Debug, Clone)]
pub struct BatchMartingaleAnalyzer {
    config: MartingaleConfig,
    analyzers: std::collections::HashMap<String, MartingaleAnalyzer>,
}

impl BatchMartingaleAnalyzer {
    /// Create a new batch analyzer.
    pub fn new(config: MartingaleConfig) -> Self {
        Self {
            config,
            analyzers: std::collections::HashMap::new(),
        }
    }

    /// Update a specific stream by ID.
    pub fn update(&mut self, id: &str, increment: f64) -> MartingaleUpdateResult {
        let analyzer = self
            .analyzers
            .entry(id.to_string())
            .or_insert_with(|| MartingaleAnalyzer::new(self.config.clone()));
        analyzer.update(increment)
    }

    /// Update a stream with bounded increment.
    pub fn update_bounded(
        &mut self,
        id: &str,
        increment: f64,
        bound: f64,
    ) -> MartingaleUpdateResult {
        let analyzer = self
            .analyzers
            .entry(id.to_string())
            .or_insert_with(|| MartingaleAnalyzer::new(self.config.clone()));
        analyzer.update_bounded(increment, bound)
    }

    /// Get summary for a specific stream.
    pub fn summary(&self, id: &str) -> Option<MartingaleResult> {
        self.analyzers.get(id).map(|a| a.summary())
    }

    /// Get summaries for all streams.
    pub fn summaries(&self) -> Vec<(String, MartingaleResult)> {
        self.analyzers
            .iter()
            .map(|(id, analyzer)| (id.clone(), analyzer.summary()))
            .collect()
    }

    /// Get IDs of all streams with detected anomalies.
    pub fn anomalous_streams(&self) -> Vec<String> {
        self.analyzers
            .iter()
            .filter_map(|(id, analyzer)| {
                let summary = analyzer.summary();
                if summary.anomaly_detected {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Reset all analyzers.
    pub fn reset(&mut self) {
        self.analyzers.clear();
    }

    /// Remove a specific stream.
    pub fn remove(&mut self, id: &str) -> Option<MartingaleAnalyzer> {
        self.analyzers.remove(id)
    }
}

/// Feature output for proc_features integration.
#[derive(Debug, Clone, Serialize)]
pub struct MartingaleFeatures {
    /// Process ID this applies to.
    pub pid: u32,
    /// Number of observations.
    pub n: usize,
    /// Cumulative deviation.
    pub cumulative_deviation: f64,
    /// Best tail probability bound.
    pub tail_probability: f64,
    /// E-value for anomaly.
    pub e_value: f64,
    /// Normalized anomaly score (0-1).
    pub anomaly_score: f64,
    /// Time-uniform confidence radius.
    pub confidence_radius: f64,
    /// Whether anomaly detected.
    pub anomaly_detected: bool,
    /// Bound type used.
    pub bound_type: BoundType,
    /// Signal type analyzed (e.g., "cpu_busy", "io_burst").
    pub signal_type: String,
}

impl MartingaleFeatures {
    /// Create features from analyzer result.
    pub fn from_result(pid: u32, result: &MartingaleResult, signal_type: &str) -> Self {
        Self {
            pid,
            n: result.n,
            cumulative_deviation: result.cumulative_sum,
            tail_probability: result.tail_probability,
            e_value: result.e_value,
            anomaly_score: (result.anomaly_score / 10.0).min(1.0), // Normalize to 0-1
            confidence_radius: result.time_uniform_radius,
            anomaly_detected: result.anomaly_detected,
            bound_type: result.best_bound,
            signal_type: signal_type.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_martingale_config_default() {
        let config = MartingaleConfig::default();
        assert!(config.validate().is_ok());
        assert_eq!(config.default_increment_bound, 1.0);
        assert!((config.confidence_level - 0.05).abs() < 1e-10);
    }

    #[test]
    fn test_martingale_config_validation() {
        let mut config = MartingaleConfig::default();

        config.default_increment_bound = -1.0;
        assert!(config.validate().is_err());

        config.default_increment_bound = 1.0;
        config.confidence_level = 0.0;
        assert!(config.validate().is_err());

        config.confidence_level = 1.0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_analyzer_empty() {
        let analyzer = MartingaleAnalyzer::default();
        assert!(analyzer.is_empty());
        assert_eq!(analyzer.len(), 0);

        let summary = analyzer.summary();
        assert_eq!(summary.n, 0);
        assert_eq!(summary.cumulative_sum, 0.0);
    }

    #[test]
    fn test_azuma_hoeffding_bound() {
        // For bounded increments with |Xᵢ| ≤ 1 and Sₙ = n × 0.5
        // P(Sₙ ≥ t) ≤ exp(-t²/(2n))
        let mut analyzer = MartingaleAnalyzer::default();

        // Add 10 increments of +0.5 each
        for _ in 0..10 {
            analyzer.update_bounded(0.5, 1.0);
        }

        let summary = analyzer.summary();
        assert_eq!(summary.n, 10);
        assert!((summary.cumulative_sum - 5.0).abs() < 1e-10);

        // Azuma bound: exp(-25 / 20) = exp(-1.25) ≈ 0.287
        assert!(summary.azuma_tail_bound < 0.35);
        assert!(summary.azuma_tail_bound > 0.2);
    }

    #[test]
    fn test_bernstein_bound_tighter() {
        // When variance is small, Bernstein should be tighter than Azuma
        let mut analyzer = MartingaleAnalyzer::default();

        // Increments with small variance
        for _ in 0..10 {
            // Increment = 0.5, bound = 1.0, variance = 0.01 (small)
            analyzer.update_with_variance(0.5, 1.0, 0.01);
        }

        let summary = analyzer.summary();
        let bern = summary.bernstein_tail_bound.unwrap();

        // Bernstein should be tighter when actual variance is small
        // (In this test case, v = 0.1, which is much smaller than n × c² = 10)
        assert!(bern <= summary.azuma_tail_bound);
    }

    #[test]
    fn test_time_uniform_radius() {
        let config = MartingaleConfig {
            confidence_level: 0.05,
            default_increment_bound: 1.0,
            ..Default::default()
        };
        let mut analyzer = MartingaleAnalyzer::new(config);

        // Add some observations
        for _ in 0..100 {
            analyzer.update(0.0);
        }

        let radius = analyzer.time_uniform_radius(0.05, 1.0);

        // With n=100, α=0.05, c=1.0:
        // radius ≈ √(2 × 1.01 × ln(√101/0.05) / 100) ≈ 0.4
        assert!(radius > 0.2);
        assert!(radius < 0.8);
    }

    #[test]
    fn test_anomaly_detection() {
        let config = MartingaleConfig {
            confidence_level: 0.05,
            default_increment_bound: 1.0,
            ..Default::default()
        };
        let mut analyzer = MartingaleAnalyzer::new(config);

        // Add significant positive drift
        for _ in 0..20 {
            analyzer.update(0.8);
        }

        let summary = analyzer.summary();
        // With strong positive drift, should detect anomaly
        assert!(summary.anomaly_detected);
        assert!(summary.e_value > 20.0);
    }

    #[test]
    fn test_no_false_positive_on_zero_mean() {
        let config = MartingaleConfig {
            confidence_level: 0.05,
            default_increment_bound: 1.0,
            ..Default::default()
        };
        let mut analyzer = MartingaleAnalyzer::new(config);

        // Centered around zero
        for i in 0..20 {
            let increment = if i % 2 == 0 { 0.3 } else { -0.3 };
            analyzer.update(increment);
        }

        let summary = analyzer.summary();
        // Should not detect anomaly for approximately zero mean
        assert!(!summary.anomaly_detected || summary.tail_probability > 0.01);
    }

    #[test]
    fn test_e_value_monotonicity() {
        // E-value should increase (evidence strengthens) with more extreme deviations
        let mut analyzer1 = MartingaleAnalyzer::default();
        let mut analyzer2 = MartingaleAnalyzer::default();

        for _ in 0..10 {
            analyzer1.update(0.3); // Small drift
            analyzer2.update(0.8); // Large drift
        }

        let e1 = analyzer1.summary().e_value;
        let e2 = analyzer2.summary().e_value;

        assert!(e2 > e1, "Larger deviation should yield larger e-value");
    }

    #[test]
    fn test_batch_analyzer() {
        let mut batch = BatchMartingaleAnalyzer::new(MartingaleConfig::default());

        // Update multiple streams
        batch.update("cpu", 0.5);
        batch.update("io", 0.2);
        batch.update("cpu", 0.5);

        let cpu_summary = batch.summary("cpu").unwrap();
        let io_summary = batch.summary("io").unwrap();

        assert_eq!(cpu_summary.n, 2);
        assert_eq!(io_summary.n, 1);
        assert!((cpu_summary.cumulative_sum - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_log_add_exp() {
        // log(exp(-100) + exp(-100)) = -100 + log(2) ≈ -99.307
        let result = log_add_exp(-100.0, -100.0);
        let expected = -100.0 + 2.0_f64.ln();
        assert!((result - expected).abs() < 1e-10);

        // Edge cases
        assert_eq!(log_add_exp(f64::NEG_INFINITY, 0.0), 0.0);
        assert_eq!(log_add_exp(0.0, f64::NEG_INFINITY), 0.0);
    }

    #[test]
    fn test_bound_parameters_serialization() {
        let params = BoundParameters {
            n: 100,
            increment_bound: 1.0,
            sum_squared_bounds: 100.0,
            sum_variances: Some(5.0),
            time_horizon: None,
        };

        let json = serde_json::to_string(&params).unwrap();
        assert!(json.contains("\"n\":100"));
        assert!(json.contains("\"sum_variances\":5.0"));
    }

    #[test]
    fn test_features_from_result() {
        let mut analyzer = MartingaleAnalyzer::default();
        for _ in 0..10 {
            analyzer.update(0.5);
        }

        let result = analyzer.summary();
        let features = MartingaleFeatures::from_result(1234, &result, "cpu_busy");

        assert_eq!(features.pid, 1234);
        assert_eq!(features.n, 10);
        assert_eq!(features.signal_type, "cpu_busy");
        assert!(features.anomaly_score >= 0.0 && features.anomaly_score <= 1.0);
    }

    #[test]
    fn test_reset() {
        let mut analyzer = MartingaleAnalyzer::default();
        for _ in 0..10 {
            analyzer.update(0.5);
        }

        assert_eq!(analyzer.len(), 10);
        analyzer.reset();
        assert!(analyzer.is_empty());
    }

    #[test]
    fn test_known_analytic_case() {
        // Known case: 10 increments of exactly +c where c=1
        // Sₙ = 10, ∑cᵢ² = 10
        // Azuma: P(S ≥ 10) ≤ exp(-100/20) = exp(-5) ≈ 0.0067
        let mut analyzer = MartingaleAnalyzer::new(MartingaleConfig {
            default_increment_bound: 1.0,
            ..Default::default()
        });

        for _ in 0..10 {
            analyzer.update_bounded(1.0, 1.0);
        }

        let summary = analyzer.summary();
        let expected = (-5.0_f64).exp();

        assert!(
            (summary.azuma_tail_bound - expected).abs() < 0.001,
            "Azuma bound: got {}, expected {}",
            summary.azuma_tail_bound,
            expected
        );
    }
}
