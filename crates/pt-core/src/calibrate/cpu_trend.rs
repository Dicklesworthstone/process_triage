//! CPU trend analysis and time-to-threshold prediction.
//!
//! Computes trend labels, EWMA-smoothed estimates, and forecasts for
//! CPU utilization series. Handles noisy data gracefully and avoids
//! false precision when variance is high.

use serde::{Deserialize, Serialize};

/// A single CPU observation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuSample {
    /// Timestamp in seconds (monotonic).
    pub t: f64,
    /// CPU utilization as a fraction (0.0 to 1.0+).
    /// Values > 1.0 represent multi-core usage.
    pub cpu_frac: f64,
}

/// Configuration for CPU trend analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuTrendConfig {
    /// EWMA half-life in samples (smaller = more reactive).
    pub ewma_half_life: f64,
    /// Minimum samples to produce a trend label.
    pub min_samples: usize,
    /// Minimum time span in seconds.
    pub min_time_span_secs: f64,
    /// Threshold for "bursty" classification: coefficient of variation.
    pub bursty_cv_threshold: f64,
    /// Minimum absolute slope (fraction/second) to call increasing/decreasing.
    pub min_slope_per_sec: f64,
    /// Minimum R² for the linear fit to trust the trend direction.
    pub min_r_squared: f64,
}

impl Default for CpuTrendConfig {
    fn default() -> Self {
        Self {
            ewma_half_life: 5.0,
            min_samples: 5,
            min_time_span_secs: 30.0,
            bursty_cv_threshold: 0.5,
            min_slope_per_sec: 0.001,
            min_r_squared: 0.3,
        }
    }
}

/// Trend classification for a CPU series.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CpuTrendLabel {
    Increasing,
    Stable,
    Decreasing,
    Bursty,
    Unknown,
}

impl std::fmt::Display for CpuTrendLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Increasing => write!(f, "increasing"),
            Self::Stable => write!(f, "stable"),
            Self::Decreasing => write!(f, "decreasing"),
            Self::Bursty => write!(f, "bursty"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Result of CPU trend analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuTrendResult {
    /// Classified trend label.
    pub label: CpuTrendLabel,
    /// Confidence in the label (0.0 to 1.0).
    pub confidence: f64,
    /// EWMA-smoothed current estimate (fraction).
    pub smoothed_current: f64,
    /// Linear slope (fraction per second).
    pub slope_per_sec: f64,
    /// R² of the linear fit.
    pub r_squared: f64,
    /// Sample variance of CPU values.
    pub variance: f64,
    /// Coefficient of variation.
    pub cv: f64,
    /// Number of samples used.
    pub sample_count: usize,
    /// Time window span in seconds.
    pub window_secs: f64,
    /// Optional ETA to a threshold.
    pub threshold_eta: Option<ThresholdEta>,
}

/// Predicted time to exceed a CPU threshold.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdEta {
    /// The threshold (fraction).
    pub threshold: f64,
    /// Estimated seconds until threshold is reached.
    pub eta_secs: f64,
    /// Confidence in the estimate (0.0 to 1.0).
    pub confidence: f64,
}

/// Error from CPU trend analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CpuTrendError {
    InsufficientSamples { have: usize, need: usize },
    InsufficientTimeSpan { have_secs: f64, need_secs: f64 },
}

impl std::fmt::Display for CpuTrendError {
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
        }
    }
}

/// Compute EWMA over a series of (time, value) pairs.
///
/// Uses time-weighted decay: alpha = 1 - exp(-dt / half_life).
fn ewma(samples: &[(f64, f64)], half_life: f64) -> Vec<f64> {
    if samples.is_empty() {
        return vec![];
    }
    let decay_rate = (2.0_f64).ln() / half_life;
    let mut result = Vec::with_capacity(samples.len());
    let mut smoothed = samples[0].1;
    result.push(smoothed);

    for i in 1..samples.len() {
        let dt = (samples[i].0 - samples[i - 1].0).max(0.001);
        let alpha = 1.0 - (-decay_rate * dt).exp();
        smoothed = alpha * samples[i].1 + (1.0 - alpha) * smoothed;
        result.push(smoothed);
    }
    result
}

/// Analyse a CPU utilization series.
///
/// Returns trend label, smoothed estimate, and optional threshold ETA.
pub fn analyze_cpu_trend(
    samples: &[CpuSample],
    config: &CpuTrendConfig,
    threshold: Option<f64>,
) -> Result<CpuTrendResult, CpuTrendError> {
    if samples.len() < config.min_samples {
        return Err(CpuTrendError::InsufficientSamples {
            have: samples.len(),
            need: config.min_samples,
        });
    }

    let t_min = samples.iter().map(|s| s.t).fold(f64::INFINITY, f64::min);
    let t_max = samples
        .iter()
        .map(|s| s.t)
        .fold(f64::NEG_INFINITY, f64::max);
    let time_span = t_max - t_min;

    if time_span < config.min_time_span_secs {
        return Err(CpuTrendError::InsufficientTimeSpan {
            have_secs: time_span,
            need_secs: config.min_time_span_secs,
        });
    }

    let n = samples.len() as f64;
    let values: Vec<f64> = samples.iter().map(|s| s.cpu_frac).collect();

    // Basic statistics.
    let mean = values.iter().sum::<f64>() / n;
    let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (n - 1.0).max(1.0);
    let std_dev = variance.sqrt();
    let cv = if mean.abs() > 1e-12 {
        std_dev / mean
    } else {
        0.0
    };

    // Linear regression.
    let times: Vec<f64> = samples.iter().map(|s| s.t).collect();
    let (slope, _intercept, r_squared) = linreg(&times, &values);

    // EWMA smoothing.
    let tv_pairs: Vec<(f64, f64)> = samples.iter().map(|s| (s.t, s.cpu_frac)).collect();
    let smoothed = ewma(&tv_pairs, config.ewma_half_life);
    let smoothed_current = *smoothed.last().unwrap_or(&mean);

    // Classify.
    let label = classify(slope, r_squared, cv, config);

    // Confidence: higher with more samples and better fit.
    let sample_factor = (samples.len() as f64 / 20.0).min(1.0);
    let fit_factor = r_squared;
    let confidence = match label {
        CpuTrendLabel::Increasing | CpuTrendLabel::Decreasing => {
            (sample_factor * 0.5 + fit_factor * 0.5).min(1.0)
        }
        CpuTrendLabel::Stable => (sample_factor * 0.7 + (1.0 - cv).max(0.0) * 0.3).min(1.0),
        CpuTrendLabel::Bursty => (sample_factor * 0.6 + cv.min(1.0) * 0.4).min(1.0),
        CpuTrendLabel::Unknown => 0.0,
    };

    // Threshold ETA: only for increasing trends with sufficient confidence.
    let threshold_eta = threshold.and_then(|thresh| {
        if label != CpuTrendLabel::Increasing || slope <= 0.0 {
            return None;
        }
        if smoothed_current >= thresh {
            return Some(ThresholdEta {
                threshold: thresh,
                eta_secs: 0.0,
                confidence,
            });
        }
        let remaining = thresh - smoothed_current;
        let eta = remaining / slope;
        // Only report if eta is reasonable (< 30 days) and confidence is OK.
        if eta > 0.0 && eta < 30.0 * 86400.0 && r_squared >= config.min_r_squared {
            Some(ThresholdEta {
                threshold: thresh,
                eta_secs: eta,
                confidence: (confidence * r_squared.sqrt()).min(1.0),
            })
        } else {
            None
        }
    });

    Ok(CpuTrendResult {
        label,
        confidence,
        smoothed_current,
        slope_per_sec: slope,
        r_squared,
        variance,
        cv,
        sample_count: samples.len(),
        window_secs: time_span,
        threshold_eta,
    })
}

fn classify(slope: f64, r_squared: f64, cv: f64, config: &CpuTrendConfig) -> CpuTrendLabel {
    // High CV → bursty, regardless of trend.
    if cv > config.bursty_cv_threshold {
        return CpuTrendLabel::Bursty;
    }

    // Check for directional trend.
    if r_squared >= config.min_r_squared && slope.abs() >= config.min_slope_per_sec {
        if slope > 0.0 {
            return CpuTrendLabel::Increasing;
        } else {
            return CpuTrendLabel::Decreasing;
        }
    }

    // Low slope + low CV → stable.
    if slope.abs() < config.min_slope_per_sec {
        return CpuTrendLabel::Stable;
    }

    // Slope is significant but R² is low → can't tell.
    CpuTrendLabel::Unknown
}

/// Simple linear regression returning (slope, intercept, r_squared).
fn linreg(x: &[f64], y: &[f64]) -> (f64, f64, f64) {
    let n = x.len() as f64;
    if n < 2.0 {
        return (0.0, 0.0, 0.0);
    }
    let sx: f64 = x.iter().sum();
    let sy: f64 = y.iter().sum();
    let sxy: f64 = x.iter().zip(y).map(|(a, b)| a * b).sum();
    let sx2: f64 = x.iter().map(|a| a * a).sum();
    let sy2: f64 = y.iter().map(|a| a * a).sum();

    let denom = n * sx2 - sx * sx;
    if denom.abs() < 1e-15 {
        return (0.0, sy / n, 0.0);
    }

    let slope = (n * sxy - sx * sy) / denom;
    let intercept = (sy - slope * sx) / n;

    let ss_tot = sy2 - sy * sy / n;
    let ss_res: f64 = x
        .iter()
        .zip(y)
        .map(|(xi, yi)| {
            let pred = slope * xi + intercept;
            (yi - pred).powi(2)
        })
        .sum();

    let r_sq = if ss_tot > 1e-15 {
        (1.0 - ss_res / ss_tot).max(0.0)
    } else {
        0.0
    };

    (slope, intercept, r_sq)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ramp(n: usize, start: f64, end: f64) -> Vec<CpuSample> {
        (0..n)
            .map(|i| {
                let t = i as f64 * 10.0;
                let frac = i as f64 / (n - 1) as f64;
                CpuSample {
                    t,
                    cpu_frac: start + (end - start) * frac,
                }
            })
            .collect()
    }

    fn make_flat(n: usize, value: f64) -> Vec<CpuSample> {
        (0..n)
            .map(|i| CpuSample {
                t: i as f64 * 10.0,
                cpu_frac: value,
            })
            .collect()
    }

    fn make_bursty(n: usize) -> Vec<CpuSample> {
        // Alternate between low and high.
        (0..n)
            .map(|i| CpuSample {
                t: i as f64 * 10.0,
                cpu_frac: if i % 2 == 0 { 0.05 } else { 0.95 },
            })
            .collect()
    }

    #[test]
    fn test_increasing() {
        let samples = make_ramp(30, 0.1, 0.8);
        let config = CpuTrendConfig {
            min_samples: 5,
            min_time_span_secs: 30.0,
            ..Default::default()
        };
        let result = analyze_cpu_trend(&samples, &config, None).unwrap();
        assert_eq!(result.label, CpuTrendLabel::Increasing);
        assert!(result.slope_per_sec > 0.0);
        assert!(result.r_squared > 0.9);
        assert!(result.confidence > 0.5);
    }

    #[test]
    fn test_decreasing() {
        let samples = make_ramp(30, 0.9, 0.1);
        let config = CpuTrendConfig {
            min_samples: 5,
            min_time_span_secs: 30.0,
            ..Default::default()
        };
        let result = analyze_cpu_trend(&samples, &config, None).unwrap();
        assert_eq!(result.label, CpuTrendLabel::Decreasing);
        assert!(result.slope_per_sec < 0.0);
    }

    #[test]
    fn test_stable() {
        let samples = make_flat(30, 0.25);
        let config = CpuTrendConfig {
            min_samples: 5,
            min_time_span_secs: 30.0,
            ..Default::default()
        };
        let result = analyze_cpu_trend(&samples, &config, None).unwrap();
        assert_eq!(result.label, CpuTrendLabel::Stable);
        assert!(result.slope_per_sec.abs() < 0.001);
    }

    #[test]
    fn test_bursty() {
        let samples = make_bursty(30);
        let config = CpuTrendConfig {
            min_samples: 5,
            min_time_span_secs: 30.0,
            ..Default::default()
        };
        let result = analyze_cpu_trend(&samples, &config, None).unwrap();
        assert_eq!(result.label, CpuTrendLabel::Bursty);
        assert!(result.cv > 0.5);
    }

    #[test]
    fn test_threshold_eta() {
        let samples = make_ramp(30, 0.1, 0.5);
        let config = CpuTrendConfig {
            min_samples: 5,
            min_time_span_secs: 30.0,
            ..Default::default()
        };
        let result = analyze_cpu_trend(&samples, &config, Some(0.7)).unwrap();
        assert_eq!(result.label, CpuTrendLabel::Increasing);
        let eta = result.threshold_eta.expect("Should have ETA for increasing trend");
        assert!(eta.eta_secs > 0.0);
        assert!(eta.confidence > 0.0);
    }

    #[test]
    fn test_no_eta_for_stable() {
        let samples = make_flat(30, 0.25);
        let config = CpuTrendConfig {
            min_samples: 5,
            min_time_span_secs: 30.0,
            ..Default::default()
        };
        let result = analyze_cpu_trend(&samples, &config, Some(0.7)).unwrap();
        assert!(result.threshold_eta.is_none());
    }

    #[test]
    fn test_already_above_threshold() {
        let samples = make_ramp(30, 0.6, 0.9);
        let config = CpuTrendConfig {
            min_samples: 5,
            min_time_span_secs: 30.0,
            ..Default::default()
        };
        let result = analyze_cpu_trend(&samples, &config, Some(0.7)).unwrap();
        // Smoothed current should be near 0.9; already above 0.7.
        if let Some(eta) = &result.threshold_eta {
            assert_eq!(eta.eta_secs, 0.0);
        }
    }

    #[test]
    fn test_insufficient_samples() {
        let samples = make_flat(3, 0.5);
        let config = CpuTrendConfig::default();
        let err = analyze_cpu_trend(&samples, &config, None).unwrap_err();
        match err {
            CpuTrendError::InsufficientSamples { have: 3, .. } => {}
            _ => panic!("Expected InsufficientSamples, got {:?}", err),
        }
    }

    #[test]
    fn test_ewma_smoothing() {
        // EWMA should reduce noise.
        let noisy: Vec<CpuSample> = (0..50)
            .map(|i| {
                let base = 0.3;
                let noise = if i % 3 == 0 { 0.1 } else { -0.05 };
                CpuSample {
                    t: i as f64 * 10.0,
                    cpu_frac: base + noise,
                }
            })
            .collect();
        let config = CpuTrendConfig {
            min_samples: 5,
            min_time_span_secs: 30.0,
            ..Default::default()
        };
        let result = analyze_cpu_trend(&noisy, &config, None).unwrap();
        // Smoothed should be near 0.3.
        assert!(
            (result.smoothed_current - 0.3).abs() < 0.1,
            "Smoothed={}, expected ~0.3",
            result.smoothed_current
        );
    }

    #[test]
    fn test_monotonic_not_decreasing() {
        // Property: strictly increasing → not Decreasing.
        let samples: Vec<CpuSample> = (0..30)
            .map(|i| CpuSample {
                t: i as f64 * 10.0,
                cpu_frac: 0.01 * (i as f64 + 1.0),
            })
            .collect();
        let config = CpuTrendConfig {
            min_samples: 5,
            min_time_span_secs: 30.0,
            ..Default::default()
        };
        let result = analyze_cpu_trend(&samples, &config, None).unwrap();
        assert_ne!(result.label, CpuTrendLabel::Decreasing);
    }
}
