//! Integration tests for trajectory prediction and baseline-related utilities.
//!
//! Covers linear, exponential-like, periodic, and asymptotic trajectories plus
//! confidence interval generation and change-point detection.

use pt_core::calibrate::cpu_trend::{analyze_cpu_trend, CpuSample, CpuTrendConfig, CpuTrendLabel};
use pt_core::calibrate::kalman::{KalmanConfig, KalmanFilter};
use pt_core::calibrate::mem_growth::{estimate_mem_growth, MemGrowthConfig, MemSample};
use pt_core::calibrate::trend::{classify_trend, TimePoint, TrendClass, TrendConfig};
use pt_core::inference::bocpd::BocpdDetector;
use pt_core::inference::copula::{summarize_copula_dependence, CopulaConfig};

fn make_linear_points(n: usize, slope_per_sec: f64, start: f64, step_secs: f64) -> Vec<TimePoint> {
    (0..n)
        .map(|i| {
            let t = i as f64 * step_secs;
            TimePoint {
                t,
                value: start + slope_per_sec * t,
            }
        })
        .collect()
}

fn make_periodic_points(n: usize, amplitude: f64, period: usize, step_secs: f64) -> Vec<TimePoint> {
    (0..n)
        .map(|i| TimePoint {
            t: i as f64 * step_secs,
            value: 100.0
                + amplitude * (2.0 * std::f64::consts::PI * i as f64 / period as f64).sin(),
        })
        .collect()
}

fn make_asymptotic_decay(
    n: usize,
    start: f64,
    asymptote: f64,
    rate_per_sec: f64,
    step_secs: f64,
) -> Vec<TimePoint> {
    (0..n)
        .map(|i| {
            let t = i as f64 * step_secs;
            let value = asymptote + (start - asymptote) * (-rate_per_sec * t).exp();
            TimePoint { t, value }
        })
        .collect()
}

fn make_exponential_mem_samples(
    n: usize,
    base_bytes: u64,
    rate_per_sec: f64,
    step_secs: f64,
) -> Vec<MemSample> {
    (0..n)
        .map(|i| {
            let t = i as f64 * step_secs;
            let val = (base_bytes as f64 * (rate_per_sec * t).exp()).round() as u64;
            MemSample {
                t,
                rss_bytes: val,
                uss_bytes: None,
            }
        })
        .collect()
}

fn make_relative_change_series(
    mean: f64,
    relative_change: f64,
    duration_secs: f64,
    step_secs: f64,
) -> Vec<TimePoint> {
    let slope = mean * relative_change / duration_secs;
    let start = mean - slope * duration_secs / 2.0;
    let n = (duration_secs / step_secs).round() as usize + 1;
    make_linear_points(n, slope, start, step_secs)
}

fn make_cpu_samples(values: &[f64], step_secs: f64) -> Vec<CpuSample> {
    values
        .iter()
        .enumerate()
        .map(|(i, value)| CpuSample {
            t: i as f64 * step_secs,
            cpu_frac: *value,
        })
        .collect()
}

#[test]
fn test_linear_trajectory_prediction() {
    let slope = 20.0 / 3600.0; // 20 MB/hour.
    let points = make_linear_points(60, slope, 50.0, 60.0);
    let config = TrendConfig::default();

    let summary = classify_trend("memory_rss_mb", &points, &config, "MB", Some(200.0)).unwrap();
    assert_eq!(summary.trend, TrendClass::Increasing);
    assert!(summary.time_to_threshold.is_some());
    assert!(summary.r_squared > 0.9);
}

#[test]
fn test_exponential_growth_detected_as_leak() {
    let samples = make_exponential_mem_samples(12, 100_000_000, 0.0005, 60.0);
    let config = MemGrowthConfig::default();
    let last = samples.last().unwrap().rss_bytes as f64;

    let estimate = estimate_mem_growth(&samples, &config, Some(600.0)).unwrap();
    assert!(estimate.slope_bytes_per_sec > 0.0);
    if let Some(pred) = estimate.prediction {
        assert!(pred.predicted_bytes as f64 > last);
    }
}

#[test]
fn test_periodic_trajectory_detection() {
    let points = make_periodic_points(120, 30.0, 20, 60.0);
    let config = TrendConfig::default();
    let summary = classify_trend("io_kbps", &points, &config, "KB/s", None).unwrap();
    assert_eq!(summary.trend, TrendClass::Periodic);
}

#[test]
fn test_asymptotic_convergence_detection() {
    let points = make_asymptotic_decay(60, 90.0, 10.0, 0.001, 60.0);
    let config = TrendConfig::default();
    let summary = classify_trend("cpu_pct", &points, &config, "%", None).unwrap();
    assert!(matches!(
        summary.trend,
        TrendClass::Decreasing | TrendClass::Stable | TrendClass::ChangePoint
    ));
}

#[test]
fn test_kalman_prediction_interval_bounds() {
    let mut filter = KalmanFilter::new(KalmanConfig::cpu());
    for i in 0..30 {
        let t = i as f64 * 10.0;
        let value = 0.1 + 0.01 * i as f64;
        filter.update(value, t);
    }

    let pred = filter.predict_future(60.0);
    assert!(pred.interval_high > pred.interval_low);
    assert!(pred.value >= pred.interval_low && pred.value <= pred.interval_high);
    assert!(pred.std_dev > 0.0);
}

#[test]
fn test_regime_change_detection() {
    let mut points = make_linear_points(30, 0.0, 100.0, 60.0);
    let mut step = make_linear_points(30, 0.0, 300.0, 60.0);
    points.append(&mut step);

    let config = TrendConfig::default();
    let summary = classify_trend("memory_rss_mb", &points, &config, "MB", None).unwrap();
    assert_eq!(summary.trend, TrendClass::ChangePoint);
    assert!(!summary.change_points.is_empty());
}

#[test]
fn test_trend_detection_sensitivity_levels() {
    let config = TrendConfig::default();
    let duration_secs = 600.0;
    let step_secs = 60.0;

    let low = make_relative_change_series(100.0, 0.05, duration_secs, step_secs);
    let medium = make_relative_change_series(100.0, 0.10, duration_secs, step_secs);
    let high = make_relative_change_series(100.0, 0.20, duration_secs, step_secs);

    let low_summary = classify_trend("cpu_pct", &low, &config, "%", None).unwrap();
    let medium_summary = classify_trend("cpu_pct", &medium, &config, "%", None).unwrap();
    let high_summary = classify_trend("cpu_pct", &high, &config, "%", None).unwrap();

    assert_eq!(low_summary.trend, TrendClass::Stable);
    assert_eq!(medium_summary.trend, TrendClass::Increasing);
    assert_eq!(high_summary.trend, TrendClass::Increasing);
}

#[test]
fn test_noise_rejection_stable_cpu_trend() {
    let baseline = 0.5;
    let noise = [
        0.00, 0.04, -0.03, 0.02, -0.01, 0.01, -0.02, 0.03, -0.04, 0.02, -0.01, 0.0,
    ];
    let values: Vec<f64> = noise.iter().map(|n| baseline + n).collect();
    let samples = make_cpu_samples(&values, 30.0);
    let config = CpuTrendConfig::default();

    let result = analyze_cpu_trend(&samples, &config, None).unwrap();
    assert_eq!(result.label, CpuTrendLabel::Stable);
}

#[test]
fn test_kalman_accuracy_on_linear_series() {
    let mut filter = KalmanFilter::new(KalmanConfig::cpu());
    let slope_per_sec = 0.002;
    let step_secs = 10.0;

    for i in 0..40 {
        let t = i as f64 * step_secs;
        let value = 0.2 + slope_per_sec * t;
        filter.update(value, t);
    }

    let horizon = 60.0;
    let pred = filter.predict_future(horizon);
    let last_t = 39.0 * step_secs;
    let expected = 0.2 + slope_per_sec * (last_t + horizon);
    let error = (pred.value - expected).abs();

    assert!(error <= pred.std_dev * 3.0);
}

#[test]
fn test_bocpd_detects_regime_change() {
    let mut detector = BocpdDetector::default_detector();
    let mut baseline_probs = Vec::new();
    let mut change_probs = Vec::new();

    for i in 0..40 {
        let update = detector.update(1.0 + (i as f64 * 0.01));
        baseline_probs.push(update.change_point_probability);
    }

    for i in 0..20 {
        let update = detector.update(6.0 + (i as f64 * 0.01));
        change_probs.push(update.change_point_probability);
    }

    let baseline_avg: f64 = baseline_probs.iter().sum::<f64>() / baseline_probs.len() as f64;
    let change_max = change_probs
        .iter()
        .cloned()
        .fold(0.0_f64, f64::max);

    assert!(change_max > baseline_avg * 2.5);
    assert!(change_max > baseline_avg + 0.02);
}

#[test]
fn test_memory_leak_scenario_prediction() {
    let samples = vec![
        MemSample {
            t: 0.0,
            rss_bytes: 100_000_000,
            uss_bytes: None,
        },
        MemSample {
            t: 60.0,
            rss_bytes: 105_000_000,
            uss_bytes: None,
        },
        MemSample {
            t: 120.0,
            rss_bytes: 110_000_000,
            uss_bytes: None,
        },
        MemSample {
            t: 180.0,
            rss_bytes: 115_000_000,
            uss_bytes: None,
        },
        MemSample {
            t: 240.0,
            rss_bytes: 120_000_000,
            uss_bytes: None,
        },
        MemSample {
            t: 300.0,
            rss_bytes: 125_000_000,
            uss_bytes: None,
        },
    ];

    let config = MemGrowthConfig {
        min_samples: 5,
        ..MemGrowthConfig::default()
    };
    let estimate = estimate_mem_growth(&samples, &config, Some(300.0)).unwrap();
    let pred = estimate.prediction.expect("prediction present");

    let predicted_mb = pred.predicted_bytes as f64 / 1_000_000.0;
    assert!((predicted_mb - 145.0).abs() < 8.0);
}

#[test]
fn test_initialization_completing_and_stable_series() {
    let init_points = vec![
        TimePoint { t: 0.0, value: 90.0 },
        TimePoint { t: 30.0, value: 85.0 },
        TimePoint { t: 60.0, value: 70.0 },
        TimePoint { t: 90.0, value: 40.0 },
        TimePoint { t: 120.0, value: 10.0 },
    ];
    let stable_points = vec![
        TimePoint { t: 0.0, value: 50.0 },
        TimePoint { t: 60.0, value: 52.0 },
        TimePoint { t: 120.0, value: 49.0 },
        TimePoint { t: 180.0, value: 51.0 },
        TimePoint { t: 240.0, value: 50.0 },
    ];

    let config = TrendConfig::default();
    let init_summary = classify_trend("cpu_pct", &init_points, &config, "%", None).unwrap();
    let stable_summary = classify_trend("cpu_pct", &stable_points, &config, "%", None).unwrap();

    assert_eq!(init_summary.trend, TrendClass::Decreasing);
    assert_eq!(stable_summary.trend, TrendClass::Stable);
}

#[test]
fn test_multi_metric_trajectory_and_correlation_detection() {
    let cpu_points = make_linear_points(15, 0.002, 0.4, 30.0);
    let mem_points = make_linear_points(15, 50.0, 100.0, 30.0);

    let config = TrendConfig::default();
    let cpu_summary = classify_trend("cpu_pct", &cpu_points, &config, "%", None).unwrap();
    let mem_summary = classify_trend("memory_rss_mb", &mem_points, &config, "MB", None).unwrap();

    assert_eq!(cpu_summary.trend, TrendClass::Increasing);
    assert_eq!(mem_summary.trend, TrendClass::Increasing);

    let stream_a: Vec<f64> = (0..20).map(|i| i as f64).collect();
    let stream_b: Vec<f64> = (0..20).map(|i| i as f64 * 1.5 + 0.5).collect();
    let summary = summarize_copula_dependence(
        &[
            ("cpu".to_string(), stream_a),
            ("mem".to_string(), stream_b),
        ],
        &CopulaConfig::default(),
    );

    assert!(summary.max_abs_corr > 0.9);
    assert!(summary.effective_evidence_multiplier < 1.0);
}
