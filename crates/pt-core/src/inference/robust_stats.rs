//! Robust statistics summaries for outlier suppression.
//!
//! Implements Huberized mean/scale along with trimmed and winsorized means
//! for stable feature extraction under noisy signals.

use serde::Serialize;
use thiserror::Error;

const MAD_TO_SIGMA: f64 = 1.4826;

/// Configuration for robust statistics summaries.
#[derive(Debug, Clone)]
pub struct RobustStatsConfig {
    /// Huber delta (in units of robust scale).
    pub huber_delta: f64,
    /// Trim fraction for trimmed mean (0.0..0.5).
    pub trim_fraction: f64,
    /// Winsorization fraction (0.0..0.5).
    pub winsor_fraction: f64,
    /// Minimum samples required after filtering.
    pub min_samples: usize,
    /// Max iterations for Huber mean refinement.
    pub max_iterations: usize,
    /// Convergence tolerance (in units of scale).
    pub convergence_tol: f64,
    /// Minimum scale to avoid divide-by-zero.
    pub min_scale: f64,
}

impl Default for RobustStatsConfig {
    fn default() -> Self {
        Self {
            huber_delta: 1.5,
            trim_fraction: 0.1,
            winsor_fraction: 0.1,
            min_samples: 5,
            max_iterations: 20,
            convergence_tol: 1e-3,
            min_scale: 1e-6,
        }
    }
}

/// Summary statistics for robust signal characterization.
#[derive(Debug, Clone, Serialize)]
pub struct RobustSummary {
    pub n_total: usize,
    pub n_used: usize,
    pub median: f64,
    pub mad: f64,
    pub robust_scale: f64,
    pub trimmed_mean: Option<f64>,
    pub winsorized_mean: Option<f64>,
    pub huber_mean: f64,
    pub huber_loss: f64,
    pub outlier_fraction: f64,
}

/// Errors raised during robust summary computation.
#[derive(Debug, Error)]
pub enum RobustStatsError {
    #[error("not enough samples: {n} (min {min})")]
    NotEnoughSamples { n: usize, min: usize },
    #[error("invalid trim fraction: {value}")]
    InvalidTrimFraction { value: f64 },
    #[error("invalid winsor fraction: {value}")]
    InvalidWinsorFraction { value: f64 },
}

/// Compute robust summary statistics from samples.
pub fn summarize(
    samples: &[f64],
    config: &RobustStatsConfig,
) -> Result<RobustSummary, RobustStatsError> {
    if !(0.0..0.5).contains(&config.trim_fraction) {
        return Err(RobustStatsError::InvalidTrimFraction {
            value: config.trim_fraction,
        });
    }
    if !(0.0..0.5).contains(&config.winsor_fraction) {
        return Err(RobustStatsError::InvalidWinsorFraction {
            value: config.winsor_fraction,
        });
    }

    let cleaned = filter_finite(samples);
    if cleaned.len() < config.min_samples {
        return Err(RobustStatsError::NotEnoughSamples {
            n: cleaned.len(),
            min: config.min_samples,
        });
    }

    let median = median(&cleaned);
    let mad = mad(&cleaned, median);
    let robust_scale = (MAD_TO_SIGMA * mad).max(config.min_scale);
    let trimmed_mean = trimmed_mean(&cleaned, config.trim_fraction);
    let winsorized_mean = winsorized_mean(&cleaned, config.winsor_fraction);
    let (huber_mean, huber_loss, outlier_fraction) =
        huber_summary(&cleaned, median, robust_scale, config);

    Ok(RobustSummary {
        n_total: samples.len(),
        n_used: cleaned.len(),
        median,
        mad,
        robust_scale,
        trimmed_mean,
        winsorized_mean,
        huber_mean,
        huber_loss,
        outlier_fraction,
    })
}

fn filter_finite(samples: &[f64]) -> Vec<f64> {
    samples.iter().copied().filter(|v| v.is_finite()).collect()
}

fn median(samples: &[f64]) -> f64 {
    let mut values = samples.to_vec();
    values.sort_by(|a, b| a.total_cmp(b));
    let mid = values.len() / 2;
    if values.len().is_multiple_of(2) {
        (values[mid - 1] + values[mid]) / 2.0
    } else {
        values[mid]
    }
}

fn mad(samples: &[f64], center: f64) -> f64 {
    let mut deviations: Vec<f64> = samples.iter().map(|v| (v - center).abs()).collect();
    deviations.sort_by(|a, b| a.total_cmp(b));
    let mid = deviations.len() / 2;
    if deviations.len().is_multiple_of(2) {
        (deviations[mid - 1] + deviations[mid]) / 2.0
    } else {
        deviations[mid]
    }
}

fn trimmed_mean(samples: &[f64], fraction: f64) -> Option<f64> {
    if samples.is_empty() {
        return None;
    }
    let mut values = samples.to_vec();
    values.sort_by(|a, b| a.total_cmp(b));
    let trim = ((values.len() as f64) * fraction).floor() as usize;
    if trim * 2 >= values.len() {
        return None;
    }
    let slice = &values[trim..values.len() - trim];
    if slice.is_empty() {
        None
    } else {
        Some(slice.iter().sum::<f64>() / slice.len() as f64)
    }
}

fn winsorized_mean(samples: &[f64], fraction: f64) -> Option<f64> {
    if samples.is_empty() {
        return None;
    }
    let mut values = samples.to_vec();
    values.sort_by(|a, b| a.total_cmp(b));
    let trim = ((values.len() as f64) * fraction).floor() as usize;
    if trim * 2 >= values.len() {
        return None;
    }
    let lower = values[trim];
    let upper = values[values.len() - trim - 1];
    let sum = values.iter().map(|v| v.clamp(lower, upper)).sum::<f64>();
    Some(sum / values.len() as f64)
}

fn huber_summary(
    samples: &[f64],
    initial: f64,
    scale: f64,
    config: &RobustStatsConfig,
) -> (f64, f64, f64) {
    let mut mean = initial;
    let delta_scaled = config.huber_delta * scale;
    let mut loss = 0.0;
    let mut outlier_count = 0usize;

    for _ in 0..config.max_iterations {
        let mut weighted_sum = 0.0;
        let mut weight_total = 0.0;
        loss = 0.0;
        outlier_count = 0;
        for value in samples {
            let residual = value - mean;
            let abs_r = residual.abs();
            if abs_r > delta_scaled {
                outlier_count += 1;
            }
            let weight = if abs_r <= delta_scaled {
                1.0
            } else {
                delta_scaled / abs_r
            };
            weighted_sum += weight * value;
            weight_total += weight;
            loss += if abs_r <= delta_scaled {
                0.5 * residual * residual
            } else {
                delta_scaled * (abs_r - 0.5 * delta_scaled)
            };
        }

        if weight_total <= 0.0 {
            break;
        }
        let new_mean = weighted_sum / weight_total;
        let delta = (new_mean - mean).abs();
        mean = new_mean;
        if delta <= config.convergence_tol * scale {
            break;
        }
    }

    let outlier_fraction = if samples.is_empty() {
        0.0
    } else {
        outlier_count as f64 / samples.len() as f64
    };
    let avg_loss = if samples.is_empty() {
        0.0
    } else {
        loss / samples.len() as f64
    };
    (mean, avg_loss, outlier_fraction)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn huber_mean_resists_outlier() {
        let samples = vec![1.0, 1.0, 1.0, 1.0, 10.0];
        let config = RobustStatsConfig {
            min_samples: 3,
            ..Default::default()
        };
        let summary = summarize(&samples, &config).unwrap();
        let simple_mean = samples.iter().sum::<f64>() / samples.len() as f64;
        assert!(summary.huber_mean < simple_mean);
        assert!(summary.huber_mean < 2.0);
        assert!(summary.outlier_fraction > 0.0);
    }

    #[test]
    fn trimmed_mean_removes_extremes() {
        let samples = vec![1.0, 1.0, 1.0, 1.0, 10.0];
        let config = RobustStatsConfig {
            trim_fraction: 0.2,
            min_samples: 3,
            ..Default::default()
        };
        let summary = summarize(&samples, &config).unwrap();
        assert_eq!(summary.trimmed_mean.unwrap(), 1.0);
    }

    #[test]
    fn winsorized_mean_clamps_outliers() {
        let samples = vec![1.0, 1.0, 1.0, 1.0, 10.0];
        let config = RobustStatsConfig {
            winsor_fraction: 0.2,
            min_samples: 3,
            ..Default::default()
        };
        let summary = summarize(&samples, &config).unwrap();
        assert!((summary.winsorized_mean.unwrap() - 1.0).abs() < 1e-6);
    }

    #[test]
    fn handles_constant_samples() {
        let samples = vec![5.0, 5.0, 5.0, 5.0, 5.0];
        let summary = summarize(&samples, &RobustStatsConfig::default()).unwrap();
        assert!(summary.robust_scale > 0.0);
        assert_eq!(summary.median, 5.0);
        assert_eq!(summary.huber_mean, 5.0);
    }

    #[test]
    fn filters_non_finite_values() {
        let samples = vec![1.0, f64::NAN, 2.0, f64::INFINITY, 3.0, 4.0, 5.0];
        let config = RobustStatsConfig {
            min_samples: 3,
            ..Default::default()
        };
        let summary = summarize(&samples, &config).unwrap();
        assert_eq!(summary.n_used, 5);
        assert!(summary.median.is_finite());
    }
}
