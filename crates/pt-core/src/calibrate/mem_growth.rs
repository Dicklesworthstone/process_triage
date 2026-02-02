//! Memory growth rate estimation with uncertainty.
//!
//! Estimates memory leak rates from time-stamped RSS/USS samples using robust
//! linear regression. Handles outliers, sparse data, and bursty allocation
//! patterns gracefully.
//!
//! # Output
//!
//! - Slope (bytes/second) with confidence interval
//! - Fit quality diagnostics (R², residuals, outlier fraction)
//! - "Insufficient data" when below evidence thresholds

use serde::{Deserialize, Serialize};

/// A single memory observation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemSample {
    /// Timestamp in seconds (monotonic within a series).
    pub t: f64,
    /// RSS in bytes.
    pub rss_bytes: u64,
    /// USS (Unique Set Size) in bytes, if available.
    pub uss_bytes: Option<u64>,
}

/// Configuration for memory growth estimation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemGrowthConfig {
    /// Minimum samples before producing an estimate.
    pub min_samples: usize,
    /// Minimum time span in seconds.
    pub min_time_span_secs: f64,
    /// Quantile for outlier trimming (fraction to trim from each tail).
    /// 0.0 = no trimming, 0.1 = trim 10% from each end.
    pub trim_fraction: f64,
}

impl Default for MemGrowthConfig {
    fn default() -> Self {
        Self {
            min_samples: 10,
            min_time_span_secs: 60.0,
            trim_fraction: 0.1,
        }
    }
}

/// Result of memory growth estimation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemGrowthEstimate {
    /// Estimated slope in bytes per second.
    pub slope_bytes_per_sec: f64,
    /// Slope in human-friendly units (MB/hour).
    pub slope_mb_per_hour: f64,
    /// Standard error of the slope estimate.
    pub slope_se: f64,
    /// Lower bound of 95% confidence interval (bytes/sec).
    pub slope_ci_low: f64,
    /// Upper bound of 95% confidence interval (bytes/sec).
    pub slope_ci_high: f64,
    /// Intercept of the linear fit (bytes).
    pub intercept_bytes: f64,
    /// R² of the fit.
    pub r_squared: f64,
    /// Fit diagnostics.
    pub diagnostics: FitDiagnostics,
    /// Predicted memory at a horizon, if requested.
    pub prediction: Option<MemPrediction>,
}

/// Fit quality diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FitDiagnostics {
    /// Number of samples used (after trimming).
    pub n_used: usize,
    /// Number of samples provided.
    pub n_total: usize,
    /// Time span of samples in seconds.
    pub time_span_secs: f64,
    /// Mean absolute residual (bytes).
    pub mean_abs_residual: f64,
    /// Median absolute residual (bytes).
    pub median_abs_residual: f64,
    /// Fraction of points considered outliers.
    pub outlier_fraction: f64,
    /// Whether the estimate is considered reliable.
    pub reliable: bool,
    /// Reason if not reliable.
    pub unreliable_reason: Option<String>,
}

/// Memory prediction at a future time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemPrediction {
    /// Horizon in seconds from last observation.
    pub horizon_secs: f64,
    /// Predicted RSS in bytes.
    pub predicted_bytes: u64,
    /// Lower bound of prediction interval.
    pub interval_low_bytes: u64,
    /// Upper bound of prediction interval.
    pub interval_high_bytes: u64,
}

/// Error from memory growth estimation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MemGrowthError {
    /// Not enough samples.
    InsufficientSamples { have: usize, need: usize },
    /// Time span too short.
    InsufficientTimeSpan { have_secs: f64, need_secs: f64 },
    /// Degenerate data (all same value, etc.).
    DegenerateData(String),
}

impl std::fmt::Display for MemGrowthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsufficientSamples { have, need } => {
                write!(f, "Insufficient samples: {} (need {})", have, need)
            }
            Self::InsufficientTimeSpan {
                have_secs,
                need_secs,
            } => write!(
                f,
                "Time span too short: {:.0}s (need {:.0}s)",
                have_secs, need_secs
            ),
            Self::DegenerateData(msg) => write!(f, "Degenerate data: {}", msg),
        }
    }
}

/// Estimate memory growth rate from samples.
///
/// Uses trimmed linear regression for robustness against outliers.
pub fn estimate_mem_growth(
    samples: &[MemSample],
    config: &MemGrowthConfig,
    predict_horizon_secs: Option<f64>,
) -> Result<MemGrowthEstimate, MemGrowthError> {
    if samples.len() < config.min_samples {
        return Err(MemGrowthError::InsufficientSamples {
            have: samples.len(),
            need: config.min_samples,
        });
    }

    let t_min = samples.iter().map(|s| s.t).fold(f64::INFINITY, f64::min);
    let t_max = samples.iter().map(|s| s.t).fold(f64::NEG_INFINITY, f64::max);
    let time_span = t_max - t_min;

    if time_span < config.min_time_span_secs {
        return Err(MemGrowthError::InsufficientTimeSpan {
            have_secs: time_span,
            need_secs: config.min_time_span_secs,
        });
    }

    // Use USS if available, otherwise RSS.
    let values: Vec<f64> = samples
        .iter()
        .map(|s| s.uss_bytes.unwrap_or(s.rss_bytes) as f64)
        .collect();
    let times: Vec<f64> = samples.iter().map(|s| s.t).collect();

    // Trimmed regression: sort by value, remove extreme quantiles.
    let n = values.len();
    let trim_count = (n as f64 * config.trim_fraction) as usize;
    let mut indexed: Vec<(usize, f64)> = values.iter().copied().enumerate().collect();
    indexed.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

    let keep_indices: std::collections::HashSet<usize> = indexed[trim_count..n - trim_count]
        .iter()
        .map(|(i, _)| *i)
        .collect();

    let n_used = keep_indices.len();
    let outlier_fraction = 1.0 - n_used as f64 / n as f64;

    // Compute regression on kept points.
    let (slope, intercept, r_squared, slope_se) =
        robust_linreg(&times, &values, &keep_indices)?;

    // Residuals for diagnostics.
    let mut residuals: Vec<f64> = keep_indices
        .iter()
        .map(|&i| (values[i] - (slope * times[i] + intercept)).abs())
        .collect();
    residuals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let mean_abs_residual = residuals.iter().sum::<f64>() / residuals.len().max(1) as f64;
    let median_abs_residual = if residuals.is_empty() {
        0.0
    } else {
        residuals[residuals.len() / 2]
    };

    let reliable = n_used >= config.min_samples && r_squared > 0.1;
    let unreliable_reason = if !reliable {
        Some(if n_used < config.min_samples {
            format!("Only {} samples after trimming", n_used)
        } else {
            format!("Low R²: {:.3}", r_squared)
        })
    } else {
        None
    };

    // 95% CI: slope ± 1.96 * SE
    let slope_ci_low = slope - 1.96 * slope_se;
    let slope_ci_high = slope + 1.96 * slope_se;

    let prediction = predict_horizon_secs.map(|horizon| {
        let future_t = t_max + horizon;
        let pred_val = slope * future_t + intercept;
        let pred_se = slope_se * horizon; // Simplified prediction SE
        let pred_bytes = pred_val.max(0.0) as u64;
        let low = (pred_val - 2.0 * pred_se).max(0.0) as u64;
        let high = (pred_val + 2.0 * pred_se).max(0.0) as u64;

        MemPrediction {
            horizon_secs: horizon,
            predicted_bytes: pred_bytes,
            interval_low_bytes: low,
            interval_high_bytes: high,
        }
    });

    Ok(MemGrowthEstimate {
        slope_bytes_per_sec: slope,
        slope_mb_per_hour: slope * 3600.0 / (1024.0 * 1024.0),
        slope_se,
        slope_ci_low,
        slope_ci_high,
        intercept_bytes: intercept,
        r_squared,
        diagnostics: FitDiagnostics {
            n_used,
            n_total: n,
            time_span_secs: time_span,
            mean_abs_residual,
            median_abs_residual,
            outlier_fraction,
            reliable,
            unreliable_reason,
        },
        prediction,
    })
}

/// Compute linear regression on selected indices with standard error.
fn robust_linreg(
    times: &[f64],
    values: &[f64],
    keep: &std::collections::HashSet<usize>,
) -> Result<(f64, f64, f64, f64), MemGrowthError> {
    let n = keep.len() as f64;
    if n < 3.0 {
        return Err(MemGrowthError::DegenerateData(
            "Need at least 3 points for regression".to_string(),
        ));
    }

    let sum_t: f64 = keep.iter().map(|&i| times[i]).sum();
    let sum_v: f64 = keep.iter().map(|&i| values[i]).sum();
    let sum_tv: f64 = keep.iter().map(|&i| times[i] * values[i]).sum();
    let sum_t2: f64 = keep.iter().map(|&i| times[i] * times[i]).sum();
    let sum_v2: f64 = keep.iter().map(|&i| values[i] * values[i]).sum();

    let denom = n * sum_t2 - sum_t * sum_t;
    if denom.abs() < 1e-15 {
        return Err(MemGrowthError::DegenerateData(
            "All timestamps identical".to_string(),
        ));
    }

    let slope = (n * sum_tv - sum_t * sum_v) / denom;
    let intercept = (sum_v - slope * sum_t) / n;

    // R²
    let mean_v = sum_v / n;
    let ss_tot = sum_v2 - n * mean_v * mean_v;
    let ss_res: f64 = keep
        .iter()
        .map(|&i| {
            let pred = slope * times[i] + intercept;
            (values[i] - pred).powi(2)
        })
        .sum();

    let r_squared = if ss_tot > 1e-15 {
        (1.0 - ss_res / ss_tot).max(0.0)
    } else {
        0.0
    };

    // Standard error of slope.
    let mse = ss_res / (n - 2.0).max(1.0);
    let se = (mse / (sum_t2 - sum_t * sum_t / n).max(1e-15)).sqrt();

    Ok((slope, intercept, r_squared, se))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_leaking(n: usize, rate_bytes_per_sec: f64, base: u64) -> Vec<MemSample> {
        let mut state: u64 = 12345;
        (0..n)
            .map(|i| {
                let t = i as f64 * 10.0; // 10-second intervals
                // Add small deterministic noise so SE > 0.
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                let noise = ((state >> 33) as f64 / (1u64 << 31) as f64 - 0.5) * rate_bytes_per_sec * 2.0;
                let val = base as f64 + rate_bytes_per_sec * t + noise;
                MemSample {
                    t,
                    rss_bytes: val.max(0.0) as u64,
                    uss_bytes: None,
                }
            })
            .collect()
    }

    fn make_flat(n: usize, value: u64) -> Vec<MemSample> {
        (0..n)
            .map(|i| MemSample {
                t: i as f64 * 10.0,
                rss_bytes: value,
                uss_bytes: None,
            })
            .collect()
    }

    #[test]
    fn test_detects_leak() {
        let rate = 1024.0; // 1 KB/s leak
        let samples = make_leaking(60, rate, 100_000_000);
        let config = MemGrowthConfig::default();

        let est = estimate_mem_growth(&samples, &config, None).unwrap();
        assert!(
            (est.slope_bytes_per_sec - rate).abs() < 10.0,
            "Expected ~{}, got {}",
            rate,
            est.slope_bytes_per_sec
        );
        assert!(est.r_squared > 0.99);
        assert!(est.diagnostics.reliable);
    }

    #[test]
    fn test_flat_series() {
        let samples = make_flat(30, 50_000_000);
        let config = MemGrowthConfig {
            min_samples: 5,
            min_time_span_secs: 30.0,
            ..Default::default()
        };

        let est = estimate_mem_growth(&samples, &config, None).unwrap();
        assert!(est.slope_bytes_per_sec.abs() < 1.0);
    }

    #[test]
    fn test_insufficient_samples() {
        let samples = make_leaking(3, 1000.0, 100_000_000);
        let config = MemGrowthConfig::default();

        let err = estimate_mem_growth(&samples, &config, None).unwrap_err();
        match err {
            MemGrowthError::InsufficientSamples { have: 3, need: 10 } => {}
            _ => panic!("Expected InsufficientSamples, got {:?}", err),
        }
    }

    #[test]
    fn test_insufficient_time_span() {
        // 10 samples at 1-second intervals = 9s total, below 60s minimum.
        let samples: Vec<MemSample> = (0..10)
            .map(|i| MemSample {
                t: i as f64,
                rss_bytes: 100_000_000,
                uss_bytes: None,
            })
            .collect();
        let config = MemGrowthConfig::default();

        let err = estimate_mem_growth(&samples, &config, None).unwrap_err();
        match err {
            MemGrowthError::InsufficientTimeSpan { .. } => {}
            _ => panic!("Expected InsufficientTimeSpan, got {:?}", err),
        }
    }

    #[test]
    fn test_with_outliers() {
        let mut samples = make_leaking(50, 500.0, 100_000_000);
        // Add spike outliers.
        samples[10].rss_bytes = 999_999_999;
        samples[20].rss_bytes = 999_999_999;
        samples[30].rss_bytes = 1;

        let config = MemGrowthConfig {
            trim_fraction: 0.1,
            ..Default::default()
        };

        let est = estimate_mem_growth(&samples, &config, None).unwrap();
        // Should still detect the ~500 bytes/sec trend despite outliers.
        assert!(
            (est.slope_bytes_per_sec - 500.0).abs() < 100.0,
            "Expected ~500, got {}",
            est.slope_bytes_per_sec
        );
    }

    #[test]
    fn test_confidence_interval() {
        let samples = make_leaking(60, 1024.0, 100_000_000);
        let config = MemGrowthConfig::default();

        let est = estimate_mem_growth(&samples, &config, None).unwrap();
        assert!(est.slope_ci_low < est.slope_bytes_per_sec);
        assert!(est.slope_ci_high > est.slope_bytes_per_sec);
        assert!(est.slope_ci_low > 0.0); // Positive leak should have positive CI.
    }

    #[test]
    fn test_prediction() {
        let rate = 1024.0;
        let samples = make_leaking(60, rate, 100_000_000);
        let config = MemGrowthConfig::default();

        let est = estimate_mem_growth(&samples, &config, Some(3600.0)).unwrap();
        let pred = est.prediction.unwrap();

        // After 1 hour, should grow by ~1024*3600 = 3.7MB.
        let last_val = samples.last().unwrap().rss_bytes;
        let expected = last_val + (rate * 3600.0) as u64;
        let error_pct = (pred.predicted_bytes as f64 - expected as f64).abs() / expected as f64;
        assert!(
            error_pct < 0.05,
            "Prediction error {:.1}%",
            error_pct * 100.0
        );
        assert!(pred.interval_low_bytes < pred.predicted_bytes);
        assert!(pred.interval_high_bytes > pred.predicted_bytes);
    }

    #[test]
    fn test_no_nan_inf() {
        // Adversarial: very small values.
        let samples: Vec<MemSample> = (0..20)
            .map(|i| MemSample {
                t: i as f64 * 10.0,
                rss_bytes: (i + 1) as u64,
                uss_bytes: None,
            })
            .collect();
        let config = MemGrowthConfig {
            min_samples: 5,
            min_time_span_secs: 10.0,
            ..Default::default()
        };

        let est = estimate_mem_growth(&samples, &config, Some(300.0)).unwrap();
        assert!(!est.slope_bytes_per_sec.is_nan());
        assert!(!est.slope_bytes_per_sec.is_infinite());
        assert!(!est.r_squared.is_nan());
    }

    #[test]
    fn test_scaling_invariance() {
        let rate = 500.0;
        let samples_a = make_leaking(30, rate, 100_000_000);

        // Scale values by 2x.
        let samples_b: Vec<MemSample> = samples_a
            .iter()
            .map(|s| MemSample {
                t: s.t,
                rss_bytes: s.rss_bytes * 2,
                uss_bytes: None,
            })
            .collect();

        let config = MemGrowthConfig::default();
        let est_a = estimate_mem_growth(&samples_a, &config, None).unwrap();
        let est_b = estimate_mem_growth(&samples_b, &config, None).unwrap();

        let ratio = est_b.slope_bytes_per_sec / est_a.slope_bytes_per_sec;
        assert!(
            (ratio - 2.0).abs() < 0.01,
            "Slope should scale linearly, ratio={}",
            ratio
        );
    }

    #[test]
    fn test_uses_uss_when_available() {
        let samples: Vec<MemSample> = (0..20)
            .map(|i| {
                let t = i as f64 * 10.0;
                MemSample {
                    t,
                    rss_bytes: 200_000_000, // RSS is flat (shared pages)
                    uss_bytes: Some(100_000_000 + (1000.0 * t) as u64), // USS grows
                }
            })
            .collect();

        let config = MemGrowthConfig {
            min_samples: 5,
            min_time_span_secs: 30.0,
            ..Default::default()
        };

        let est = estimate_mem_growth(&samples, &config, None).unwrap();
        // Should detect the USS growth, not the flat RSS.
        assert!(est.slope_bytes_per_sec > 500.0);
    }
}
