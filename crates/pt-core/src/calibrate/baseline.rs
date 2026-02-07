//! Per-host baseline fitting and anomaly scoring.
//!
//! Fits baseline distributions from historical telemetry and scores new
//! observations as anomalous or normal relative to the host's own history.
//! Handles cold-start by falling back to conservative global priors.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A metric observation for baseline building.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineObservation {
    /// Metric value (RSS bytes, CPU fraction, FD count, etc.).
    pub value: f64,
    /// Optional category/signature for stratified baselines.
    pub category: Option<String>,
}

/// Configuration for baseline fitting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineConfig {
    /// Minimum observations for a reliable baseline.
    pub min_observations: usize,
    /// Number of observations below which we blend with global prior.
    pub cold_start_threshold: usize,
    /// Trim fraction for robust statistics (each tail).
    pub trim_fraction: f64,
    /// Schema version for serialization.
    pub schema_version: u32,
}

impl Default for BaselineConfig {
    fn default() -> Self {
        Self {
            min_observations: 10,
            cold_start_threshold: 30,
            trim_fraction: 0.05,
            schema_version: 1,
        }
    }
}

/// Summary statistics for a baseline distribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineSummary {
    /// Number of observations used.
    pub n: usize,
    /// Mean (trimmed if configured).
    pub mean: f64,
    /// Standard deviation.
    pub std_dev: f64,
    /// Median.
    pub median: f64,
    /// Median absolute deviation.
    pub mad: f64,
    /// Percentiles: p5, p25, p50, p75, p95.
    pub percentiles: [f64; 5],
    /// Whether this is a cold-start baseline (blended with global).
    pub cold_start: bool,
    /// Schema version.
    pub schema_version: u32,
}

/// Anomaly score for a single observation against a baseline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyScore {
    /// Raw z-score (may be unreliable for heavy-tailed distributions).
    pub z_score: f64,
    /// Robust z-score using MAD.
    pub robust_z_score: f64,
    /// Percentile rank (0.0 to 1.0).
    pub percentile_rank: f64,
    /// Whether the observation is anomalous (robust_z > 3 or percentile > 0.99).
    pub is_anomalous: bool,
    /// Whether the baseline used cold-start blending.
    pub cold_start: bool,
}

/// A collection of per-key baselines (keyed by host_id, or host_id+category).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BaselineStore {
    /// Baselines keyed by identifier (e.g., "host:metric" or "host:metric:category").
    pub baselines: HashMap<String, BaselineSummary>,
    /// Global fallback baseline (aggregated across all hosts).
    pub global: Option<BaselineSummary>,
}

/// Fit a baseline summary from observations.
pub fn fit_baseline(observations: &[f64], config: &BaselineConfig) -> Option<BaselineSummary> {
    if observations.is_empty() {
        return None;
    }

    let mut sorted = observations.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let n = sorted.len();
    let trim_count = (n as f64 * config.trim_fraction) as usize;
    let trimmed = if trim_count > 0 && n > 2 * trim_count {
        &sorted[trim_count..n - trim_count]
    } else {
        &sorted[..]
    };

    let tn = trimmed.len() as f64;
    let mean = trimmed.iter().sum::<f64>() / tn;
    let variance = trimmed.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (tn - 1.0).max(1.0);
    let std_dev = variance.sqrt();

    let median = percentile_sorted(&sorted, 0.50);
    let mad = {
        let mut deviations: Vec<f64> = sorted.iter().map(|v| (v - median).abs()).collect();
        deviations.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        percentile_sorted(&deviations, 0.50) * 1.4826 // Scale to match std_dev for normal
    };

    let percentiles = [
        percentile_sorted(&sorted, 0.05),
        percentile_sorted(&sorted, 0.25),
        median,
        percentile_sorted(&sorted, 0.75),
        percentile_sorted(&sorted, 0.95),
    ];

    let cold_start = n < config.cold_start_threshold;

    Some(BaselineSummary {
        n,
        mean,
        std_dev,
        median,
        mad,
        percentiles,
        cold_start,
        schema_version: config.schema_version,
    })
}

/// Blend a host baseline with a global baseline for cold-start mitigation.
///
/// Uses shrinkage: blended = λ * host + (1-λ) * global,
/// where λ = n_host / cold_start_threshold.
pub fn blend_with_global(
    host: &BaselineSummary,
    global: &BaselineSummary,
    cold_start_threshold: usize,
) -> BaselineSummary {
    let lambda = (host.n as f64 / cold_start_threshold as f64).min(1.0);

    let blend = |h: f64, g: f64| lambda * h + (1.0 - lambda) * g;

    BaselineSummary {
        n: host.n,
        mean: blend(host.mean, global.mean),
        std_dev: blend(host.std_dev, global.std_dev),
        median: blend(host.median, global.median),
        mad: blend(host.mad, global.mad),
        percentiles: [
            blend(host.percentiles[0], global.percentiles[0]),
            blend(host.percentiles[1], global.percentiles[1]),
            blend(host.percentiles[2], global.percentiles[2]),
            blend(host.percentiles[3], global.percentiles[3]),
            blend(host.percentiles[4], global.percentiles[4]),
        ],
        cold_start: host.n < cold_start_threshold,
        schema_version: host.schema_version,
    }
}

/// Score an observation against a baseline.
pub fn score_anomaly(value: f64, baseline: &BaselineSummary) -> AnomalyScore {
    let z_score = if baseline.std_dev > 1e-12 {
        (value - baseline.mean) / baseline.std_dev
    } else {
        0.0
    };

    let robust_z_score = if baseline.mad > 1e-12 {
        (value - baseline.median) / baseline.mad
    } else {
        0.0
    };

    // Approximate percentile rank from sorted percentiles.
    let percentile_rank = estimate_percentile_rank(value, &baseline.percentiles);

    let is_anomalous = robust_z_score.abs() > 3.0 || percentile_rank > 0.99;

    AnomalyScore {
        z_score,
        robust_z_score,
        percentile_rank,
        is_anomalous,
        cold_start: baseline.cold_start,
    }
}

/// Estimate percentile rank from the 5 stored percentiles using linear interpolation.
fn estimate_percentile_rank(value: f64, percentiles: &[f64; 5]) -> f64 {
    let pcts = [0.05, 0.25, 0.50, 0.75, 0.95];

    if value <= percentiles[0] {
        return 0.05 * (value / percentiles[0].max(1e-12)).clamp(0.0, 1.0);
    }
    if value >= percentiles[4] {
        // Extrapolate conservatively above p95.
        return (0.95
            + 0.05
                * ((value - percentiles[4]) / (percentiles[4] - percentiles[3]).max(1e-12))
                    .min(1.0))
        .min(1.0);
    }

    for i in 0..4 {
        if value >= percentiles[i] && value <= percentiles[i + 1] {
            let range = percentiles[i + 1] - percentiles[i];
            if range < 1e-12 {
                return pcts[i];
            }
            let frac = (value - percentiles[i]) / range;
            return pcts[i] + frac * (pcts[i + 1] - pcts[i]);
        }
    }

    0.5 // Fallback.
}

/// Compute a percentile from a sorted slice (linear interpolation).
fn percentile_sorted(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    if sorted.len() == 1 {
        return sorted[0];
    }
    let idx = p * (sorted.len() - 1) as f64;
    let lo = idx.floor() as usize;
    let hi = (lo + 1).min(sorted.len() - 1);
    let frac = idx - lo as f64;
    sorted[lo] * (1.0 - frac) + sorted[hi] * frac
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_normal_ish(n: usize, mean: f64, std: f64) -> Vec<f64> {
        // Deterministic pseudo-normal via Box-Muller with LCG.
        let mut state: u64 = 42;
        let mut values = Vec::with_capacity(n);
        for _ in 0..n {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let u1 = (state >> 33) as f64 / (1u64 << 31) as f64;
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let u2 = (state >> 33) as f64 / (1u64 << 31) as f64;
            let z = (-2.0 * u1.max(1e-10).ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
            values.push(mean + std * z);
        }
        values
    }

    #[test]
    fn test_fit_baseline() {
        let obs = make_normal_ish(100, 500.0, 50.0);
        let config = BaselineConfig::default();
        let bl = fit_baseline(&obs, &config).unwrap();
        assert_eq!(bl.n, 100);
        assert!((bl.mean - 500.0).abs() < 30.0);
        assert!(bl.std_dev > 10.0);
        assert!(!bl.cold_start);
    }

    #[test]
    fn test_cold_start_flag() {
        let obs = make_normal_ish(10, 100.0, 10.0);
        let config = BaselineConfig {
            cold_start_threshold: 30,
            ..Default::default()
        };
        let bl = fit_baseline(&obs, &config).unwrap();
        assert!(bl.cold_start);
    }

    #[test]
    fn test_score_normal() {
        let obs = make_normal_ish(200, 1000.0, 100.0);
        let config = BaselineConfig::default();
        let bl = fit_baseline(&obs, &config).unwrap();

        let score = score_anomaly(1050.0, &bl);
        assert!(!score.is_anomalous);
        assert!(score.z_score.abs() < 2.0);
    }

    #[test]
    fn test_score_anomalous() {
        let obs = make_normal_ish(200, 1000.0, 100.0);
        let config = BaselineConfig::default();
        let bl = fit_baseline(&obs, &config).unwrap();

        // Way above: 4 std devs.
        let score = score_anomaly(1500.0, &bl);
        assert!(score.is_anomalous);
        assert!(score.robust_z_score > 3.0);
    }

    #[test]
    fn test_blend_with_global() {
        let host = BaselineSummary {
            n: 10,
            mean: 200.0,
            std_dev: 20.0,
            median: 200.0,
            mad: 15.0,
            percentiles: [160.0, 185.0, 200.0, 215.0, 240.0],
            cold_start: true,
            schema_version: 1,
        };
        let global = BaselineSummary {
            n: 1000,
            mean: 500.0,
            std_dev: 100.0,
            median: 500.0,
            mad: 75.0,
            percentiles: [300.0, 425.0, 500.0, 575.0, 700.0],
            cold_start: false,
            schema_version: 1,
        };

        let blended = blend_with_global(&host, &global, 30);
        // λ = 10/30 = 0.333
        assert!(blended.cold_start);
        assert!(blended.mean > 200.0 && blended.mean < 500.0);
        let expected_mean = (10.0 / 30.0) * 200.0 + (20.0 / 30.0) * 500.0;
        assert!((blended.mean - expected_mean).abs() < 0.1);
    }

    #[test]
    fn test_empty_observations() {
        let config = BaselineConfig::default();
        assert!(fit_baseline(&[], &config).is_none());
    }

    #[test]
    fn test_single_observation() {
        let config = BaselineConfig {
            min_observations: 1,
            ..Default::default()
        };
        let bl = fit_baseline(&[42.0], &config).unwrap();
        assert_eq!(bl.n, 1);
        assert_eq!(bl.median, 42.0);
    }

    #[test]
    fn test_percentile_rank_boundaries() {
        let bl = BaselineSummary {
            n: 100,
            mean: 50.0,
            std_dev: 10.0,
            median: 50.0,
            mad: 7.5,
            percentiles: [30.0, 40.0, 50.0, 60.0, 70.0],
            cold_start: false,
            schema_version: 1,
        };
        let low = score_anomaly(25.0, &bl);
        assert!(low.percentile_rank < 0.05);
        let mid = score_anomaly(50.0, &bl);
        assert!((mid.percentile_rank - 0.5).abs() < 0.1);
        let high = score_anomaly(75.0, &bl);
        assert!(high.percentile_rank > 0.95);
    }

    #[test]
    fn test_schema_version_persists() {
        let config = BaselineConfig {
            schema_version: 42,
            ..Default::default()
        };
        let obs = make_normal_ish(50, 100.0, 10.0);
        let bl = fit_baseline(&obs, &config).unwrap();
        assert_eq!(bl.schema_version, 42);
    }
}
