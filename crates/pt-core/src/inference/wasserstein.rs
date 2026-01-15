//! Wasserstein distance for distribution drift detection.
//!
//! This module implements 1D Wasserstein distance computation for detecting
//! when current process behavior drifts from established baselines.
//!
//! # Mathematical Foundation
//!
//! The 1-Wasserstein distance (earth mover's distance) between distributions P and Q:
//!
//! ```text
//! W_1(P, Q) = ∫_0^1 |F_P^{-1}(u) - F_Q^{-1}(u)| du
//! ```
//!
//! For empirical samples, this reduces to the L1 distance between sorted values:
//!
//! ```text
//! W_1 ≈ (1/n) Σ_i |x_{(i)} - y_{(i)}|
//! ```
//!
//! # Use Cases
//!
//! - Detect when current process behavior differs from baseline
//! - Trigger DRO gating when drift exceeds threshold
//! - Monitor for calibration staleness
//! - Per-machine baseline comparison
//!
//! # Example
//!
//! ```rust
//! use pt_core::inference::wasserstein::{WassersteinDetector, WassersteinConfig, DriftResult};
//!
//! let config = WassersteinConfig::default();
//! let detector = WassersteinDetector::new(config);
//!
//! // Baseline distribution (historical)
//! let baseline = vec![0.1, 0.15, 0.2, 0.18, 0.12, 0.22, 0.19, 0.14];
//!
//! // Current observations
//! let current = vec![0.5, 0.55, 0.52, 0.48, 0.51, 0.53, 0.49, 0.54];
//!
//! let result = detector.detect_drift(&baseline, &current);
//! if result.drifted {
//!     println!("Distribution drift detected!");
//!     println!("  Distance: {:.4}", result.distance);
//!     println!("  Threshold: {:.4}", result.threshold);
//! }
//! ```

use serde::Serialize;
use std::collections::HashMap;
use thiserror::Error;

/// Configuration for Wasserstein drift detection.
#[derive(Debug, Clone)]
pub struct WassersteinConfig {
    /// Fixed drift threshold (if adaptive_threshold is false).
    pub drift_threshold: f64,
    /// Use adaptive threshold based on baseline variability.
    pub adaptive_threshold: bool,
    /// Multiplier for adaptive threshold (e.g., 2.0 = 2 standard deviations).
    pub adaptive_multiplier: f64,
    /// Minimum samples required for valid comparison.
    pub min_samples: usize,
    /// Enable interpolation for unequal sample sizes.
    pub interpolate_unequal: bool,
    /// DRO trigger multiplier (drift > trigger_multiplier * threshold triggers DRO).
    pub dro_trigger_multiplier: f64,
}

impl Default for WassersteinConfig {
    fn default() -> Self {
        Self {
            drift_threshold: 0.1,
            adaptive_threshold: true,
            adaptive_multiplier: 2.5,
            min_samples: 10,
            interpolate_unequal: true,
            dro_trigger_multiplier: 1.5,
        }
    }
}

impl WassersteinConfig {
    /// Configuration for CPU usage drift detection.
    pub fn for_cpu() -> Self {
        Self {
            drift_threshold: 0.15,
            adaptive_threshold: true,
            adaptive_multiplier: 2.0,
            min_samples: 20,
            interpolate_unequal: true,
            dro_trigger_multiplier: 1.5,
        }
    }

    /// Configuration for memory usage drift detection.
    pub fn for_memory() -> Self {
        Self {
            drift_threshold: 0.1,
            adaptive_threshold: true,
            adaptive_multiplier: 2.5,
            min_samples: 15,
            interpolate_unequal: true,
            dro_trigger_multiplier: 2.0,
        }
    }

    /// Configuration for runtime distribution drift.
    pub fn for_runtime() -> Self {
        Self {
            drift_threshold: 300.0, // seconds
            adaptive_threshold: true,
            adaptive_multiplier: 3.0,
            min_samples: 30,
            interpolate_unequal: true,
            dro_trigger_multiplier: 1.5,
        }
    }

    /// Strict configuration for sensitive features.
    pub fn strict() -> Self {
        Self {
            drift_threshold: 0.05,
            adaptive_threshold: false,
            adaptive_multiplier: 1.5,
            min_samples: 50,
            interpolate_unequal: true,
            dro_trigger_multiplier: 1.2,
        }
    }
}

/// Drift severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftSeverity {
    /// No significant drift detected.
    None,
    /// Minor drift within acceptable bounds.
    Minor,
    /// Moderate drift approaching threshold.
    Moderate,
    /// Significant drift exceeding threshold.
    Significant,
    /// Severe drift requiring immediate attention.
    Severe,
}

impl DriftSeverity {
    /// Determine severity from distance ratio (distance / threshold).
    pub fn from_ratio(ratio: f64) -> Self {
        if ratio < 0.5 {
            DriftSeverity::None
        } else if ratio < 0.8 {
            DriftSeverity::Minor
        } else if ratio < 1.0 {
            DriftSeverity::Moderate
        } else if ratio < 2.0 {
            DriftSeverity::Significant
        } else {
            DriftSeverity::Severe
        }
    }

    /// Whether this severity level triggers DRO gating.
    pub fn triggers_dro(&self) -> bool {
        matches!(self, DriftSeverity::Significant | DriftSeverity::Severe)
    }
}

/// Recommended action based on drift detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftAction {
    /// No action needed.
    None,
    /// Continue monitoring with increased frequency.
    Monitor,
    /// Flag in evidence ledger.
    Flag,
    /// Trigger DRO conservative gating.
    TriggerDro,
    /// Initiate recalibration.
    Recalibrate,
}

/// Result of drift detection.
#[derive(Debug, Clone, Serialize)]
pub struct DriftResult {
    /// Whether significant drift was detected.
    pub drifted: bool,
    /// Computed Wasserstein distance.
    pub distance: f64,
    /// Threshold used for comparison.
    pub threshold: f64,
    /// Ratio of distance to threshold.
    pub ratio: f64,
    /// Severity classification.
    pub severity: DriftSeverity,
    /// Recommended action.
    pub action: DriftAction,
    /// Whether DRO should be triggered.
    pub trigger_dro: bool,
    /// Number of baseline samples used.
    pub baseline_n: usize,
    /// Number of current samples used.
    pub current_n: usize,
    /// Baseline statistics (mean, std).
    pub baseline_stats: (f64, f64),
    /// Current statistics (mean, std).
    pub current_stats: (f64, f64),
}

/// Evidence for decision-core integration.
#[derive(Debug, Clone, Serialize)]
pub struct WassersteinEvidence {
    /// Whether drift was detected.
    pub drifted: bool,
    /// Wasserstein distance.
    pub distance: f64,
    /// Drift severity.
    pub severity: String,
    /// Whether DRO was triggered.
    pub dro_triggered: bool,
    /// Confidence penalty based on drift magnitude.
    pub confidence_penalty: f64,
    /// Recommended action.
    pub action: String,
}

impl From<&DriftResult> for WassersteinEvidence {
    fn from(result: &DriftResult) -> Self {
        // Confidence penalty scales with drift severity
        let confidence_penalty = match result.severity {
            DriftSeverity::None => 0.0,
            DriftSeverity::Minor => 0.02,
            DriftSeverity::Moderate => 0.05,
            DriftSeverity::Significant => 0.1,
            DriftSeverity::Severe => 0.2,
        };

        Self {
            drifted: result.drifted,
            distance: result.distance,
            severity: format!("{:?}", result.severity).to_lowercase(),
            dro_triggered: result.trigger_dro,
            confidence_penalty,
            action: format!("{:?}", result.action).to_lowercase(),
        }
    }
}

/// Errors from Wasserstein computation.
#[derive(Debug, Error)]
pub enum WassersteinError {
    #[error("insufficient baseline samples: need {needed}, have {have}")]
    InsufficientBaseline { needed: usize, have: usize },

    #[error("insufficient current samples: need {needed}, have {have}")]
    InsufficientCurrent { needed: usize, have: usize },

    #[error("invalid threshold: {message}")]
    InvalidThreshold { message: String },

    #[error("empty distribution")]
    EmptyDistribution,
}

/// Wasserstein drift detector.
pub struct WassersteinDetector {
    config: WassersteinConfig,
}

impl WassersteinDetector {
    /// Create a new detector with the given configuration.
    pub fn new(config: WassersteinConfig) -> Self {
        Self { config }
    }

    /// Compute 1D Wasserstein distance between two empirical distributions.
    ///
    /// For equal-sized samples, this is the mean absolute difference of sorted values.
    /// For unequal sizes, uses linear interpolation of quantiles.
    pub fn wasserstein_distance(&self, p: &[f64], q: &[f64]) -> f64 {
        if p.is_empty() || q.is_empty() {
            return 0.0;
        }

        // Sort both distributions
        let mut p_sorted: Vec<f64> = p.to_vec();
        let mut q_sorted: Vec<f64> = q.to_vec();
        p_sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        q_sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

        if p.len() == q.len() {
            // Equal sizes: direct comparison
            self.wasserstein_equal(&p_sorted, &q_sorted)
        } else if self.config.interpolate_unequal {
            // Unequal sizes: interpolate to common grid
            self.wasserstein_interpolate(&p_sorted, &q_sorted)
        } else {
            // Subsample to equal sizes
            self.wasserstein_subsample(&p_sorted, &q_sorted)
        }
    }

    /// Wasserstein distance for equal-sized sorted samples.
    fn wasserstein_equal(&self, p: &[f64], q: &[f64]) -> f64 {
        let n = p.len() as f64;
        let sum: f64 = p.iter().zip(q.iter()).map(|(pi, qi)| (pi - qi).abs()).sum();
        sum / n
    }

    /// Wasserstein distance using quantile interpolation.
    fn wasserstein_interpolate(&self, p: &[f64], q: &[f64]) -> f64 {
        // Use the larger sample size as the grid
        let n = p.len().max(q.len());
        let mut total = 0.0;

        for i in 0..n {
            let u = (i as f64 + 0.5) / n as f64; // Quantile level
            let p_quantile = self.quantile_interpolate(p, u);
            let q_quantile = self.quantile_interpolate(q, u);
            total += (p_quantile - q_quantile).abs();
        }

        total / n as f64
    }

    /// Wasserstein distance by subsampling to equal sizes.
    fn wasserstein_subsample(&self, p: &[f64], q: &[f64]) -> f64 {
        let n = p.len().min(q.len());

        // Subsample by taking evenly spaced indices
        let p_sub: Vec<f64> = (0..n)
            .map(|i| {
                let idx = (i * p.len()) / n;
                p[idx]
            })
            .collect();

        let q_sub: Vec<f64> = (0..n)
            .map(|i| {
                let idx = (i * q.len()) / n;
                q[idx]
            })
            .collect();

        self.wasserstein_equal(&p_sub, &q_sub)
    }

    /// Linear interpolation for quantile function.
    fn quantile_interpolate(&self, sorted: &[f64], u: f64) -> f64 {
        if sorted.is_empty() {
            return 0.0;
        }
        if sorted.len() == 1 {
            return sorted[0];
        }

        let u = u.clamp(0.0, 1.0);
        let n = sorted.len() as f64;

        // Index in [0, n-1]
        let idx = u * (n - 1.0);
        let lo = idx.floor() as usize;
        let hi = idx.ceil() as usize;

        if lo == hi || hi >= sorted.len() {
            return sorted[lo.min(sorted.len() - 1)];
        }

        let frac = idx - lo as f64;
        sorted[lo] * (1.0 - frac) + sorted[hi] * frac
    }

    /// Detect drift between baseline and current distributions.
    pub fn detect_drift(&self, baseline: &[f64], current: &[f64]) -> DriftResult {
        // Compute Wasserstein distance
        let distance = self.wasserstein_distance(baseline, current);

        // Compute statistics
        let baseline_stats = self.compute_stats(baseline);
        let current_stats = self.compute_stats(current);

        // Determine threshold
        let threshold = if self.config.adaptive_threshold {
            self.adaptive_threshold(baseline)
        } else {
            self.config.drift_threshold
        };

        // Compute ratio and severity
        let ratio = if threshold > 0.0 {
            distance / threshold
        } else {
            0.0
        };
        let severity = DriftSeverity::from_ratio(ratio);

        // Determine if DRO should be triggered
        let trigger_dro = distance > threshold * self.config.dro_trigger_multiplier;

        // Determine action
        let action = if severity == DriftSeverity::None {
            DriftAction::None
        } else if severity == DriftSeverity::Minor {
            DriftAction::Monitor
        } else if severity == DriftSeverity::Moderate {
            DriftAction::Flag
        } else if trigger_dro {
            DriftAction::TriggerDro
        } else if severity == DriftSeverity::Severe {
            DriftAction::Recalibrate
        } else {
            DriftAction::TriggerDro
        };

        DriftResult {
            drifted: distance > threshold,
            distance,
            threshold,
            ratio,
            severity,
            action,
            trigger_dro,
            baseline_n: baseline.len(),
            current_n: current.len(),
            baseline_stats,
            current_stats,
        }
    }

    /// Detect drift with validation.
    pub fn detect_drift_validated(
        &self,
        baseline: &[f64],
        current: &[f64],
    ) -> Result<DriftResult, WassersteinError> {
        if baseline.len() < self.config.min_samples {
            return Err(WassersteinError::InsufficientBaseline {
                needed: self.config.min_samples,
                have: baseline.len(),
            });
        }

        if current.len() < self.config.min_samples {
            return Err(WassersteinError::InsufficientCurrent {
                needed: self.config.min_samples,
                have: current.len(),
            });
        }

        Ok(self.detect_drift(baseline, current))
    }

    /// Compute adaptive threshold based on baseline variability.
    fn adaptive_threshold(&self, baseline: &[f64]) -> f64 {
        if baseline.len() < 2 {
            return self.config.drift_threshold;
        }

        // Estimate variability using bootstrap-like resampling
        let n = baseline.len();
        let half = n / 2;

        if half < 2 {
            return self.config.drift_threshold;
        }

        // Split baseline into halves and compute W_1 between them
        let first_half: Vec<f64> = baseline[..half].to_vec();
        let second_half: Vec<f64> = baseline[half..].to_vec();

        let internal_distance = self.wasserstein_distance(&first_half, &second_half);

        // Threshold is multiplier times internal variability
        let adaptive = internal_distance * self.config.adaptive_multiplier;

        // Ensure minimum threshold
        adaptive.max(self.config.drift_threshold * 0.5)
    }

    /// Compute mean and standard deviation.
    fn compute_stats(&self, data: &[f64]) -> (f64, f64) {
        if data.is_empty() {
            return (0.0, 0.0);
        }

        let n = data.len() as f64;
        let mean = data.iter().sum::<f64>() / n;

        if data.len() < 2 {
            return (mean, 0.0);
        }

        let var = data.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0);
        (mean, var.sqrt())
    }
}

impl Default for WassersteinDetector {
    fn default() -> Self {
        Self::new(WassersteinConfig::default())
    }
}

/// Multi-feature drift monitor.
pub struct DriftMonitor {
    detectors: HashMap<String, WassersteinDetector>,
    baselines: HashMap<String, Vec<f64>>,
}

impl DriftMonitor {
    /// Create a new drift monitor with default configurations.
    pub fn new() -> Self {
        let mut detectors = HashMap::new();

        // Set up default detectors for common features
        detectors.insert("cpu".to_string(), WassersteinDetector::new(WassersteinConfig::for_cpu()));
        detectors.insert(
            "memory".to_string(),
            WassersteinDetector::new(WassersteinConfig::for_memory()),
        );
        detectors.insert(
            "runtime".to_string(),
            WassersteinDetector::new(WassersteinConfig::for_runtime()),
        );

        Self {
            detectors,
            baselines: HashMap::new(),
        }
    }

    /// Add or update a feature detector.
    pub fn add_detector(&mut self, name: &str, config: WassersteinConfig) {
        self.detectors
            .insert(name.to_string(), WassersteinDetector::new(config));
    }

    /// Set baseline for a feature.
    pub fn set_baseline(&mut self, name: &str, baseline: Vec<f64>) {
        self.baselines.insert(name.to_string(), baseline);
    }

    /// Check drift for a single feature.
    pub fn check_feature(
        &self,
        name: &str,
        current: &[f64],
    ) -> Result<DriftResult, WassersteinError> {
        let detector = self.detectors.get(name).ok_or(WassersteinError::InvalidThreshold {
            message: format!("No detector configured for feature: {}", name),
        })?;

        let baseline = self.baselines.get(name).ok_or(WassersteinError::EmptyDistribution)?;

        detector.detect_drift_validated(baseline, current)
    }

    /// Check drift for all configured features.
    pub fn check_all(
        &self,
        current_data: &HashMap<String, Vec<f64>>,
    ) -> HashMap<String, Result<DriftResult, WassersteinError>> {
        let mut results = HashMap::new();

        for (name, baseline) in &self.baselines {
            if let Some(current) = current_data.get(name) {
                if let Some(detector) = self.detectors.get(name) {
                    results.insert(
                        name.clone(),
                        detector.detect_drift_validated(baseline, current),
                    );
                }
            }
        }

        results
    }

    /// Get aggregated drift evidence.
    pub fn aggregate_evidence(
        &self,
        results: &HashMap<String, Result<DriftResult, WassersteinError>>,
    ) -> AggregatedDriftEvidence {
        let mut total_features = 0;
        let mut drifted_count = 0;
        let mut drifted_features = Vec::new();
        let mut max_severity = DriftSeverity::None;
        let mut any_dro_triggered = false;
        let mut total_penalty = 0.0;

        for (name, result) in results {
            if let Ok(r) = result {
                total_features += 1;

                if r.drifted {
                    drifted_count += 1;
                    drifted_features.push(name.clone());
                }

                if r.trigger_dro {
                    any_dro_triggered = true;
                }

                // Track max severity
                let severity_rank = match r.severity {
                    DriftSeverity::None => 0,
                    DriftSeverity::Minor => 1,
                    DriftSeverity::Moderate => 2,
                    DriftSeverity::Significant => 3,
                    DriftSeverity::Severe => 4,
                };
                let current_max_rank = match max_severity {
                    DriftSeverity::None => 0,
                    DriftSeverity::Minor => 1,
                    DriftSeverity::Moderate => 2,
                    DriftSeverity::Significant => 3,
                    DriftSeverity::Severe => 4,
                };
                if severity_rank > current_max_rank {
                    max_severity = r.severity;
                }

                // Accumulate penalty
                let evidence = WassersteinEvidence::from(r);
                total_penalty += evidence.confidence_penalty;
            }
        }

        AggregatedDriftEvidence {
            total_features,
            drifted_count,
            drifted_features,
            max_severity: format!("{:?}", max_severity).to_lowercase(),
            dro_triggered: any_dro_triggered,
            total_confidence_penalty: total_penalty,
            overall_drifted: drifted_count > 0,
        }
    }
}

impl Default for DriftMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Aggregated drift evidence from multiple features.
#[derive(Debug, Clone, Serialize)]
pub struct AggregatedDriftEvidence {
    /// Total features monitored.
    pub total_features: usize,
    /// Number of features with detected drift.
    pub drifted_count: usize,
    /// Names of drifted features.
    pub drifted_features: Vec<String>,
    /// Maximum drift severity across all features.
    pub max_severity: String,
    /// Whether any feature triggered DRO.
    pub dro_triggered: bool,
    /// Total confidence penalty.
    pub total_confidence_penalty: f64,
    /// Whether any feature drifted.
    pub overall_drifted: bool,
}

/// Compute 1D Wasserstein distance (convenience function).
pub fn wasserstein_1d(p: &[f64], q: &[f64]) -> f64 {
    let detector = WassersteinDetector::default();
    detector.wasserstein_distance(p, q)
}

/// Compute 2-Wasserstein distance (sum of squared differences of sorted values).
pub fn wasserstein_2_squared(p: &[f64], q: &[f64]) -> f64 {
    if p.is_empty() || q.is_empty() {
        return 0.0;
    }

    let mut p_sorted: Vec<f64> = p.to_vec();
    let mut q_sorted: Vec<f64> = q.to_vec();
    p_sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    q_sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    if p.len() == q.len() {
        let n = p.len() as f64;
        let sum: f64 = p_sorted
            .iter()
            .zip(q_sorted.iter())
            .map(|(pi, qi)| (pi - qi).powi(2))
            .sum();
        sum / n
    } else {
        // Use interpolation for unequal sizes
        let n = p.len().max(q.len());
        let mut total = 0.0;

        for i in 0..n {
            let u = (i as f64 + 0.5) / n as f64;
            let p_q = quantile(p, u);
            let q_q = quantile(q, u);
            total += (p_q - q_q).powi(2);
        }

        total / n as f64
    }
}

/// Linear quantile interpolation.
fn quantile(sorted: &[f64], u: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }

    let mut data = sorted.to_vec();
    data.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let n = data.len() as f64;
    let idx = u * (n - 1.0);
    let lo = idx.floor() as usize;
    let hi = idx.ceil() as usize;

    if lo == hi || hi >= data.len() {
        return data[lo.min(data.len() - 1)];
    }

    let frac = idx - lo as f64;
    data[lo] * (1.0 - frac) + data[hi] * frac
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = WassersteinConfig::default();
        assert_eq!(config.drift_threshold, 0.1);
        assert!(config.adaptive_threshold);
        assert_eq!(config.min_samples, 10);
    }

    #[test]
    fn test_config_presets() {
        let cpu = WassersteinConfig::for_cpu();
        assert_eq!(cpu.drift_threshold, 0.15);
        assert_eq!(cpu.min_samples, 20);

        let mem = WassersteinConfig::for_memory();
        assert_eq!(mem.drift_threshold, 0.1);

        let runtime = WassersteinConfig::for_runtime();
        assert_eq!(runtime.drift_threshold, 300.0);
    }

    #[test]
    fn test_wasserstein_identical() {
        let detector = WassersteinDetector::default();
        let data = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let dist = detector.wasserstein_distance(&data, &data);
        assert!((dist - 0.0).abs() < 1e-10, "Identical distributions should have W=0");
    }

    #[test]
    fn test_wasserstein_shifted() {
        let detector = WassersteinDetector::default();
        let p = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let q = vec![2.0, 3.0, 4.0, 5.0, 6.0]; // Shifted by 1

        let dist = detector.wasserstein_distance(&p, &q);
        assert!((dist - 1.0).abs() < 1e-10, "Shift of 1 should give W=1");
    }

    #[test]
    fn test_wasserstein_scaled() {
        let detector = WassersteinDetector::default();
        let p = vec![0.0, 1.0, 2.0, 3.0, 4.0];
        let q = vec![0.0, 2.0, 4.0, 6.0, 8.0]; // Scaled by 2

        let dist = detector.wasserstein_distance(&p, &q);
        // Mean absolute difference: |0-0| + |1-2| + |2-4| + |3-6| + |4-8| = 0+1+2+3+4 = 10
        // W = 10/5 = 2
        assert!((dist - 2.0).abs() < 1e-10);
    }

    #[test]
    fn test_wasserstein_unequal_sizes() {
        let detector = WassersteinDetector::default();
        let p = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let q = vec![1.0, 2.0, 3.0]; // Different size

        let dist = detector.wasserstein_distance(&p, &q);
        // Should handle unequal sizes via interpolation
        assert!(dist >= 0.0);
        assert!(dist < 2.0); // Should be reasonable
    }

    #[test]
    fn test_wasserstein_empty() {
        let detector = WassersteinDetector::default();
        let empty: Vec<f64> = vec![];
        let data = vec![1.0, 2.0, 3.0];

        assert_eq!(detector.wasserstein_distance(&empty, &data), 0.0);
        assert_eq!(detector.wasserstein_distance(&data, &empty), 0.0);
        assert_eq!(detector.wasserstein_distance(&empty, &empty), 0.0);
    }

    #[test]
    fn test_wasserstein_single_element() {
        let detector = WassersteinDetector::default();
        let p = vec![5.0];
        let q = vec![10.0];

        let dist = detector.wasserstein_distance(&p, &q);
        assert!((dist - 5.0).abs() < 1e-10);
    }

    #[test]
    fn test_drift_detection_no_drift() {
        let detector = WassersteinDetector::new(WassersteinConfig {
            drift_threshold: 1.0,
            adaptive_threshold: false,
            ..Default::default()
        });

        let baseline = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let current = vec![1.1, 2.1, 3.1, 4.1, 5.1]; // Small shift of 0.1

        let result = detector.detect_drift(&baseline, &current);
        assert!(!result.drifted);
        assert_eq!(result.severity, DriftSeverity::None);
        assert_eq!(result.action, DriftAction::None);
    }

    #[test]
    fn test_drift_detection_significant_drift() {
        let detector = WassersteinDetector::new(WassersteinConfig {
            drift_threshold: 0.5,
            adaptive_threshold: false,
            dro_trigger_multiplier: 1.5,
            ..Default::default()
        });

        let baseline = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let current = vec![3.0, 4.0, 5.0, 6.0, 7.0]; // Shift of 2.0

        let result = detector.detect_drift(&baseline, &current);
        assert!(result.drifted);
        assert!(result.trigger_dro);
        assert!(matches!(
            result.severity,
            DriftSeverity::Significant | DriftSeverity::Severe
        ));
    }

    #[test]
    fn test_drift_severity_from_ratio() {
        assert_eq!(DriftSeverity::from_ratio(0.3), DriftSeverity::None);
        assert_eq!(DriftSeverity::from_ratio(0.6), DriftSeverity::Minor);
        assert_eq!(DriftSeverity::from_ratio(0.9), DriftSeverity::Moderate);
        assert_eq!(DriftSeverity::from_ratio(1.5), DriftSeverity::Significant);
        assert_eq!(DriftSeverity::from_ratio(3.0), DriftSeverity::Severe);
    }

    #[test]
    fn test_drift_severity_triggers_dro() {
        assert!(!DriftSeverity::None.triggers_dro());
        assert!(!DriftSeverity::Minor.triggers_dro());
        assert!(!DriftSeverity::Moderate.triggers_dro());
        assert!(DriftSeverity::Significant.triggers_dro());
        assert!(DriftSeverity::Severe.triggers_dro());
    }

    #[test]
    fn test_adaptive_threshold() {
        let detector = WassersteinDetector::new(WassersteinConfig {
            adaptive_threshold: true,
            adaptive_multiplier: 2.0,
            drift_threshold: 0.1,
            ..Default::default()
        });

        // Baseline with some internal variability
        let baseline: Vec<f64> = (0..100)
            .map(|i| 1.0 + (i % 10) as f64 * 0.1)
            .collect();

        let threshold = detector.adaptive_threshold(&baseline);
        // Should be > 0 and influenced by internal variability
        assert!(threshold > 0.0);
    }

    #[test]
    fn test_validated_insufficient_samples() {
        let detector = WassersteinDetector::new(WassersteinConfig {
            min_samples: 20,
            ..Default::default()
        });

        let baseline = vec![1.0, 2.0, 3.0]; // Only 3 samples
        let current = vec![1.0, 2.0, 3.0, 4.0, 5.0]; // Only 5 samples

        let result = detector.detect_drift_validated(&baseline, &current);
        assert!(matches!(result, Err(WassersteinError::InsufficientBaseline { .. })));

        let baseline: Vec<f64> = (0..30).map(|i| i as f64).collect();
        let result = detector.detect_drift_validated(&baseline, &current);
        assert!(matches!(result, Err(WassersteinError::InsufficientCurrent { .. })));
    }

    #[test]
    fn test_wasserstein_evidence() {
        let result = DriftResult {
            drifted: true,
            distance: 1.5,
            threshold: 1.0,
            ratio: 1.5,
            severity: DriftSeverity::Significant,
            action: DriftAction::TriggerDro,
            trigger_dro: true,
            baseline_n: 100,
            current_n: 50,
            baseline_stats: (5.0, 1.0),
            current_stats: (6.5, 1.2),
        };

        let evidence = WassersteinEvidence::from(&result);
        assert!(evidence.drifted);
        assert!((evidence.distance - 1.5).abs() < 1e-10);
        assert_eq!(evidence.severity, "significant");
        assert!(evidence.dro_triggered);
        assert!((evidence.confidence_penalty - 0.1).abs() < 1e-10);
    }

    #[test]
    fn test_drift_monitor() {
        let mut monitor = DriftMonitor::new();

        // Set baselines
        monitor.set_baseline("cpu", (0..50).map(|i| 0.1 + (i % 10) as f64 * 0.02).collect());
        monitor.set_baseline("memory", (0..50).map(|i| 0.5 + (i % 5) as f64 * 0.01).collect());

        // Current data (no significant drift)
        let mut current = HashMap::new();
        current.insert("cpu".to_string(), (0..30).map(|i| 0.12 + (i % 10) as f64 * 0.02).collect());
        current.insert("memory".to_string(), (0..30).map(|i| 0.51 + (i % 5) as f64 * 0.01).collect());

        let results = monitor.check_all(&current);
        assert_eq!(results.len(), 2);

        let evidence = monitor.aggregate_evidence(&results);
        assert_eq!(evidence.total_features, 2);
    }

    #[test]
    fn test_convenience_function() {
        let p = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let q = vec![2.0, 3.0, 4.0, 5.0, 6.0];

        let dist = wasserstein_1d(&p, &q);
        assert!((dist - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_wasserstein_2() {
        let p = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let q = vec![2.0, 3.0, 4.0, 5.0, 6.0];

        let dist_sq = wasserstein_2_squared(&p, &q);
        // All differences are 1, squared = 1, mean = 1
        assert!((dist_sq - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_quantile_interpolation() {
        let detector = WassersteinDetector::default();
        let data = vec![0.0, 1.0, 2.0, 3.0, 4.0];

        // Exact quantiles
        assert!((detector.quantile_interpolate(&data, 0.0) - 0.0).abs() < 1e-10);
        assert!((detector.quantile_interpolate(&data, 1.0) - 4.0).abs() < 1e-10);
        assert!((detector.quantile_interpolate(&data, 0.5) - 2.0).abs() < 1e-10);

        // Interpolated
        assert!((detector.quantile_interpolate(&data, 0.25) - 1.0).abs() < 1e-10);
        assert!((detector.quantile_interpolate(&data, 0.75) - 3.0).abs() < 1e-10);
    }

    #[test]
    fn test_compute_stats() {
        let detector = WassersteinDetector::default();

        let data = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let (mean, std) = detector.compute_stats(&data);

        assert!((mean - 3.0).abs() < 1e-10);
        // Sample std dev of [1,2,3,4,5] = sqrt(2.5) ≈ 1.581
        assert!((std - 1.5811388300841898).abs() < 1e-10);
    }

    #[test]
    fn test_stats_empty() {
        let detector = WassersteinDetector::default();
        let (mean, std) = detector.compute_stats(&[]);
        assert_eq!(mean, 0.0);
        assert_eq!(std, 0.0);
    }

    #[test]
    fn test_stats_single() {
        let detector = WassersteinDetector::default();
        let (mean, std) = detector.compute_stats(&[5.0]);
        assert_eq!(mean, 5.0);
        assert_eq!(std, 0.0);
    }

    #[test]
    fn test_result_stats_populated() {
        let detector = WassersteinDetector::default();
        let baseline = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let current = vec![2.0, 3.0, 4.0, 5.0, 6.0];

        let result = detector.detect_drift(&baseline, &current);

        assert!((result.baseline_stats.0 - 3.0).abs() < 1e-10);
        assert!((result.current_stats.0 - 4.0).abs() < 1e-10);
    }

    #[test]
    fn test_aggregated_evidence() {
        let mut results = HashMap::new();

        results.insert(
            "cpu".to_string(),
            Ok(DriftResult {
                drifted: true,
                distance: 0.5,
                threshold: 0.3,
                ratio: 1.67,
                severity: DriftSeverity::Significant,
                action: DriftAction::TriggerDro,
                trigger_dro: true,
                baseline_n: 100,
                current_n: 50,
                baseline_stats: (0.2, 0.05),
                current_stats: (0.7, 0.1),
            }),
        );

        results.insert(
            "memory".to_string(),
            Ok(DriftResult {
                drifted: false,
                distance: 0.01,
                threshold: 0.1,
                ratio: 0.1,
                severity: DriftSeverity::None,
                action: DriftAction::None,
                trigger_dro: false,
                baseline_n: 100,
                current_n: 50,
                baseline_stats: (0.5, 0.02),
                current_stats: (0.51, 0.02),
            }),
        );

        let monitor = DriftMonitor::new();
        let evidence = monitor.aggregate_evidence(&results);

        assert_eq!(evidence.total_features, 2);
        assert_eq!(evidence.drifted_count, 1);
        assert!(evidence.drifted_features.contains(&"cpu".to_string()));
        assert!(evidence.dro_triggered);
        assert!(evidence.overall_drifted);
    }
}
