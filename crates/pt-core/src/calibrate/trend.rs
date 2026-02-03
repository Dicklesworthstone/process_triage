//! Trend detection and classification for per-process resource trajectories.
//!
//! Classifies time-series data (memory, CPU, etc.) into human/agent-friendly
//! labels: stable, increasing, decreasing, periodic, or change-point.
//!
//! Uses simple linear regression with robust statistics. More advanced methods
//! (Kalman, IMM, BOCPD) can feed into these classifiers as they become available.

use serde::{Deserialize, Serialize};

/// A single timestamped measurement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimePoint {
    /// Seconds since some epoch (monotonic within a series).
    pub t: f64,
    /// Observed value.
    pub value: f64,
}

/// Classification of a resource trend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrendClass {
    /// No significant trend (slope near zero relative to mean).
    Stable,
    /// Significant positive slope.
    Increasing,
    /// Significant negative slope.
    Decreasing,
    /// Periodic/oscillating pattern detected.
    Periodic,
    /// Abrupt level shift detected.
    ChangePoint,
}

impl std::fmt::Display for TrendClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrendClass::Stable => write!(f, "stable"),
            TrendClass::Increasing => write!(f, "increasing"),
            TrendClass::Decreasing => write!(f, "decreasing"),
            TrendClass::Periodic => write!(f, "periodic"),
            TrendClass::ChangePoint => write!(f, "change_point"),
        }
    }
}

/// A detected change point in the series.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangePoint {
    /// Time of the change point.
    pub t: f64,
    /// Index in the original series.
    pub index: usize,
    /// Magnitude of the level shift.
    pub magnitude: f64,
    /// Direction: "increase" or "decrease".
    pub direction: String,
}

/// Summary of trend analysis for a single metric.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendSummary {
    /// Metric name (e.g., "memory_rss_mb").
    pub metric: String,
    /// Classified trend.
    pub trend: TrendClass,
    /// Linear regression slope (units per time unit).
    pub slope: f64,
    /// Unit description for the slope.
    pub slope_unit: String,
    /// R² of the linear fit.
    pub r_squared: f64,
    /// Number of data points.
    pub n: usize,
    /// Time span of the series in seconds.
    pub duration_secs: f64,
    /// Mean value over the series.
    pub mean_value: f64,
    /// Standard deviation of values.
    pub std_dev: f64,
    /// Detected change points (if any).
    pub change_points: Vec<ChangePoint>,
    /// Human-readable interpretation.
    pub interpretation: String,
    /// Time to reach a threshold (optional, in seconds).
    pub time_to_threshold: Option<f64>,
}

/// Configuration for trend classification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendConfig {
    /// Minimum R² to consider a linear trend significant.
    pub min_r_squared: f64,
    /// Minimum |slope * duration / mean| ratio to classify as increasing/decreasing.
    /// This is the relative change over the observation window.
    pub min_relative_change: f64,
    /// Threshold for change-point detection: minimum step size as fraction of std_dev.
    pub change_point_threshold: f64,
    /// Minimum number of points to attempt classification.
    pub min_points: usize,
}

impl Default for TrendConfig {
    fn default() -> Self {
        Self {
            min_r_squared: 0.3,
            min_relative_change: 0.1,
            change_point_threshold: 2.0,
            min_points: 5,
        }
    }
}

/// Linear regression result.
#[derive(Debug, Clone)]
struct LinRegResult {
    slope: f64,
    intercept: f64,
    r_squared: f64,
}

/// Compute simple linear regression on (t, value) pairs.
fn linear_regression(points: &[TimePoint]) -> Option<LinRegResult> {
    let n = points.len() as f64;
    if n < 2.0 {
        return None;
    }

    let sum_t: f64 = points.iter().map(|p| p.t).sum();
    let sum_v: f64 = points.iter().map(|p| p.value).sum();
    let sum_tv: f64 = points.iter().map(|p| p.t * p.value).sum();
    let sum_t2: f64 = points.iter().map(|p| p.t * p.t).sum();
    let sum_v2: f64 = points.iter().map(|p| p.value * p.value).sum();

    let denom = n * sum_t2 - sum_t * sum_t;
    if denom.abs() < 1e-15 {
        return None;
    }

    let slope = (n * sum_tv - sum_t * sum_v) / denom;
    let intercept = (sum_v - slope * sum_t) / n;

    // R² calculation.
    let mean_v = sum_v / n;
    let ss_tot = sum_v2 - n * mean_v * mean_v;
    let ss_res: f64 = points
        .iter()
        .map(|p| {
            let predicted = slope * p.t + intercept;
            (p.value - predicted).powi(2)
        })
        .sum();

    let r_squared = if ss_tot > 1e-15 {
        1.0 - ss_res / ss_tot
    } else {
        0.0
    };

    Some(LinRegResult {
        slope,
        intercept,
        r_squared,
    })
}

/// Detect change points using a simple sliding window mean comparison.
///
/// Splits the series at each point and compares means of left and right halves.
/// A change point is detected when the difference exceeds threshold * std_dev.
fn detect_change_points(points: &[TimePoint], threshold: f64, std_dev: f64) -> Vec<ChangePoint> {
    if points.len() < 6 || std_dev < 1e-15 {
        return Vec::new();
    }

    let min_half = 3;
    let mut best_score = 0.0f64;
    let mut best_idx = 0;

    for split in min_half..(points.len() - min_half) {
        let left_mean: f64 = points[..split].iter().map(|p| p.value).sum::<f64>() / split as f64;
        let right_mean: f64 =
            points[split..].iter().map(|p| p.value).sum::<f64>() / (points.len() - split) as f64;
        let diff = (right_mean - left_mean).abs();

        if diff > best_score {
            best_score = diff;
            best_idx = split;
        }
    }

    let normalized = best_score / std_dev;
    if normalized >= threshold {
        let left_mean: f64 =
            points[..best_idx].iter().map(|p| p.value).sum::<f64>() / best_idx as f64;
        let right_mean: f64 = points[best_idx..].iter().map(|p| p.value).sum::<f64>()
            / (points.len() - best_idx) as f64;
        let direction = if right_mean > left_mean {
            "increase"
        } else {
            "decrease"
        };

        vec![ChangePoint {
            t: points[best_idx].t,
            index: best_idx,
            magnitude: best_score,
            direction: direction.to_string(),
        }]
    } else {
        Vec::new()
    }
}

/// Detect periodicity using autocorrelation on detrended residuals.
///
/// First removes the linear trend, then checks for significant
/// autocorrelation at some lag in the residuals.
fn detect_periodicity(points: &[TimePoint]) -> bool {
    if points.len() < 12 {
        return false;
    }

    // Detrend: remove linear fit.
    let reg = match linear_regression(points) {
        Some(r) => r,
        None => return false,
    };

    let residuals: Vec<f64> = points
        .iter()
        .map(|p| p.value - (reg.slope * p.t + reg.intercept))
        .collect();

    let n = residuals.len();
    let mean: f64 = residuals.iter().sum::<f64>() / n as f64;
    let variance: f64 = residuals.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n as f64;

    if variance < 1e-15 {
        return false;
    }

    // Check autocorrelation at lags 2..n/3 for significant peaks.
    let max_lag = n / 3;
    for lag in 2..max_lag {
        let mut ac = 0.0f64;
        for i in 0..(n - lag) {
            ac += (residuals[i] - mean) * (residuals[i + lag] - mean);
        }
        ac /= (n - lag) as f64 * variance;

        if ac > 0.5 {
            return true;
        }
    }

    false
}

/// Classify a time series and produce a trend summary.
pub fn classify_trend(
    metric: &str,
    points: &[TimePoint],
    config: &TrendConfig,
    value_unit: &str,
    threshold: Option<f64>,
) -> Option<TrendSummary> {
    if points.len() < config.min_points {
        return None;
    }

    let n = points.len();
    let duration = points.last().unwrap().t - points.first().unwrap().t;
    if duration <= 0.0 {
        return None;
    }

    let values: Vec<f64> = points.iter().map(|p| p.value).collect();
    let mean_value: f64 = values.iter().sum::<f64>() / n as f64;
    let variance: f64 = values.iter().map(|v| (v - mean_value).powi(2)).sum::<f64>() / n as f64;
    let std_dev = variance.sqrt();

    let reg = linear_regression(points)?;

    let change_points = detect_change_points(points, config.change_point_threshold, std_dev);
    let is_periodic = detect_periodicity(points);

    // Relative change over the observation window.
    let relative_change = if mean_value.abs() > 1e-15 {
        (reg.slope * duration / mean_value).abs()
    } else {
        0.0
    };

    // Classify.
    let trend = if !change_points.is_empty() {
        TrendClass::ChangePoint
    } else if is_periodic {
        TrendClass::Periodic
    } else if reg.r_squared >= config.min_r_squared && relative_change >= config.min_relative_change
    {
        if reg.slope > 0.0 {
            TrendClass::Increasing
        } else {
            TrendClass::Decreasing
        }
    } else {
        TrendClass::Stable
    };

    let slope_per_hour = reg.slope * 3600.0;
    let slope_unit = format!("{}/hour", value_unit);

    // Time to threshold (if increasing and threshold provided).
    let time_to_threshold = match (threshold, trend) {
        (Some(thresh), TrendClass::Increasing) if reg.slope > 1e-15 => {
            let current = reg.slope * points.last().unwrap().t + reg.intercept;
            if current < thresh {
                Some((thresh - current) / reg.slope)
            } else {
                Some(0.0)
            }
        }
        _ => None,
    };

    let interpretation = match trend {
        TrendClass::Stable => format!(
            "{} is stable around {:.1} {} (σ={:.2})",
            metric, mean_value, value_unit, std_dev
        ),
        TrendClass::Increasing => {
            let projected = slope_per_hour * 24.0;
            format!(
                "{} is increasing at {:.2} {}; +{:.1} {} projected in 24h",
                metric, slope_per_hour, slope_unit, projected, value_unit
            )
        }
        TrendClass::Decreasing => format!(
            "{} is decreasing at {:.2} {}",
            metric, slope_per_hour, slope_unit
        ),
        TrendClass::Periodic => format!(
            "{} shows periodic behavior around mean {:.1} {}",
            metric, mean_value, value_unit
        ),
        TrendClass::ChangePoint => {
            let cp = &change_points[0];
            format!(
                "{} has a level shift of {:.1} {} ({}) at t={:.0}s",
                metric, cp.magnitude, value_unit, cp.direction, cp.t
            )
        }
    };

    Some(TrendSummary {
        metric: metric.to_string(),
        trend,
        slope: slope_per_hour,
        slope_unit,
        r_squared: reg.r_squared,
        n,
        duration_secs: duration,
        mean_value,
        std_dev,
        change_points,
        interpretation,
        time_to_threshold,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_linear(n: usize, slope: f64, intercept: f64) -> Vec<TimePoint> {
        (0..n)
            .map(|i| TimePoint {
                t: i as f64 * 60.0, // 1-minute intervals
                value: slope * (i as f64 * 60.0) + intercept,
            })
            .collect()
    }

    fn make_stable(n: usize, value: f64, noise: f64) -> Vec<TimePoint> {
        // Use a LCG-like sequence for non-periodic deterministic jitter.
        let mut state = 12345u64;
        (0..n)
            .map(|i| {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                let frac = (state >> 33) as f64 / (1u64 << 31) as f64; // 0..1
                let jitter = noise * (frac - 0.5);
                TimePoint {
                    t: i as f64 * 60.0,
                    value: value + jitter,
                }
            })
            .collect()
    }

    fn make_step(n: usize, before: f64, after: f64) -> Vec<TimePoint> {
        (0..n)
            .map(|i| TimePoint {
                t: i as f64 * 60.0,
                value: if i < n / 2 { before } else { after },
            })
            .collect()
    }

    fn make_periodic(n: usize, amplitude: f64, period: usize) -> Vec<TimePoint> {
        (0..n)
            .map(|i| TimePoint {
                t: i as f64 * 60.0,
                value: 100.0
                    + amplitude * (2.0 * std::f64::consts::PI * i as f64 / period as f64).sin(),
            })
            .collect()
    }

    #[test]
    fn test_classify_increasing() {
        // Memory growing at ~20 MB/hour from 50 MB.
        let slope = 20.0 / 3600.0; // MB per second
        let points = make_linear(60, slope, 50.0); // 60 minutes
        let config = TrendConfig::default();

        let summary = classify_trend("memory_rss_mb", &points, &config, "MB", Some(200.0));
        assert!(summary.is_some());
        let s = summary.unwrap();
        assert_eq!(s.trend, TrendClass::Increasing);
        assert!((s.slope - 20.0).abs() < 0.1); // ~20 MB/hour
        assert!(s.r_squared > 0.99);
        assert!(s.time_to_threshold.is_some());
        assert!(s.interpretation.contains("increasing"));
    }

    #[test]
    fn test_classify_decreasing() {
        let slope = -20.0 / 3600.0;
        let points = make_linear(60, slope, 100.0);
        let config = TrendConfig::default();

        let summary = classify_trend("cpu_pct", &points, &config, "%", None);
        let s = summary.unwrap();
        assert_eq!(s.trend, TrendClass::Decreasing);
        assert!(s.slope < 0.0);
    }

    #[test]
    fn test_classify_stable() {
        let points = make_stable(60, 50.0, 0.5);
        let config = TrendConfig::default();

        let summary = classify_trend("cpu_pct", &points, &config, "%", None);
        let s = summary.unwrap();
        assert_eq!(s.trend, TrendClass::Stable);
        assert!(s.interpretation.contains("stable"));
    }

    #[test]
    fn test_classify_change_point() {
        let points = make_step(60, 100.0, 300.0);
        let config = TrendConfig::default();

        let summary = classify_trend("memory_rss_mb", &points, &config, "MB", None);
        let s = summary.unwrap();
        assert_eq!(s.trend, TrendClass::ChangePoint);
        assert!(!s.change_points.is_empty());
        assert!(s.change_points[0].magnitude > 100.0);
        assert_eq!(s.change_points[0].direction, "increase");
    }

    #[test]
    fn test_classify_periodic() {
        let points = make_periodic(120, 30.0, 20); // Amplitude 30, period 20 samples
        let config = TrendConfig::default();

        let summary = classify_trend("io_kbps", &points, &config, "KB/s", None);
        let s = summary.unwrap();
        assert_eq!(s.trend, TrendClass::Periodic);
    }

    #[test]
    fn test_insufficient_points() {
        let points = make_linear(3, 1.0, 0.0);
        let config = TrendConfig::default();

        assert!(classify_trend("x", &points, &config, "u", None).is_none());
    }

    #[test]
    fn test_time_to_threshold() {
        // Start at 50, growing 30/hour. Threshold at 200.
        let slope = 30.0 / 3600.0;
        let points = make_linear(60, slope, 50.0); // 60 minutes
        let config = TrendConfig::default();

        let s = classify_trend("mem", &points, &config, "MB", Some(200.0)).unwrap();
        assert_eq!(s.trend, TrendClass::Increasing);
        assert!(s.time_to_threshold.is_some());
        let ttt = s.time_to_threshold.unwrap();
        assert!(ttt > 0.0);
        assert!(ttt < 40000.0);
    }

    #[test]
    fn test_deterministic_output() {
        let points = make_linear(60, 0.001, 50.0);
        let config = TrendConfig::default();

        let s1 = classify_trend("mem", &points, &config, "MB", None).unwrap();
        let s2 = classify_trend("mem", &points, &config, "MB", None).unwrap();

        assert_eq!(s1.trend, s2.trend);
        assert!((s1.slope - s2.slope).abs() < 1e-12);
        assert!((s1.r_squared - s2.r_squared).abs() < 1e-12);
    }
}
