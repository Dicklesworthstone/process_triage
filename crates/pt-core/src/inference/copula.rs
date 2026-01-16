//! Copula-based dependence summaries for correlated evidence.
//!
//! This module estimates a simple dependence structure across multiple
//! evidence streams using a Gaussian-copula-style Spearman correlation layer.
//! The output is a deterministic summary that can be used to down-weight
//! overconfident evidence when signals are strongly correlated.
//!
//! The closed-form posterior core remains unchanged; this only emits
//! conservative summaries (correlations + an effective evidence multiplier).

use serde::{Deserialize, Serialize};

/// Configuration for copula dependence summaries.
#[derive(Debug, Clone)]
pub struct CopulaConfig {
    /// Whether copula summaries are enabled.
    pub enabled: bool,
    /// Minimum samples required per pair.
    pub min_samples: usize,
    /// Maximum number of streams to consider.
    pub max_features: usize,
    /// Lower bound for the effective evidence multiplier.
    pub min_multiplier: f64,
}

impl Default for CopulaConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_samples: 12,
            max_features: 4,
            min_multiplier: 0.2,
        }
    }
}

impl CopulaConfig {
    /// Disable the copula layer entirely (neutral summary).
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }
}

/// Summary of dependence across evidence streams.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CopulaSummary {
    /// Pairwise Spearman correlations.
    pub pairs: Vec<(String, String, f64)>,
    /// Average absolute correlation across pairs.
    pub avg_abs_corr: f64,
    /// Maximum absolute correlation across pairs.
    pub max_abs_corr: f64,
    /// Effective evidence multiplier (<= 1.0).
    pub effective_evidence_multiplier: f64,
    /// Count of streams included.
    pub feature_count: usize,
    /// Minimum sample count across included streams.
    pub sample_count: usize,
    /// Whether the copula layer was enabled.
    pub enabled: bool,
    /// Diagnostics for auditability.
    pub diagnostics: Vec<String>,
}

/// Produce copula dependence summaries for a set of streams.
pub fn summarize_copula_dependence(
    streams: &[(String, Vec<f64>)],
    config: &CopulaConfig,
) -> CopulaSummary {
    if !config.enabled {
        return CopulaSummary {
            pairs: Vec::new(),
            avg_abs_corr: 0.0,
            max_abs_corr: 0.0,
            effective_evidence_multiplier: 1.0,
            feature_count: 0,
            sample_count: 0,
            enabled: false,
            diagnostics: vec!["copula_disabled".to_string()],
        };
    }

    let mut diagnostics = Vec::new();
    let mut pairs = Vec::new();

    let features: Vec<(String, Vec<f64>)> = streams
        .iter()
        .take(config.max_features)
        .map(|(name, values)| (name.clone(), values.clone()))
        .collect();

    let feature_count = features.len();
    if feature_count < 2 {
        diagnostics.push("insufficient_streams".to_string());
        return CopulaSummary {
            pairs,
            avg_abs_corr: 0.0,
            max_abs_corr: 0.0,
            effective_evidence_multiplier: 1.0,
            feature_count,
            sample_count: 0,
            enabled: true,
            diagnostics,
        };
    }

    let sample_count = features
        .iter()
        .map(|(_, values)| values.len())
        .min()
        .unwrap_or(0);
    if sample_count < config.min_samples {
        diagnostics.push("insufficient_samples".to_string());
        return CopulaSummary {
            pairs,
            avg_abs_corr: 0.0,
            max_abs_corr: 0.0,
            effective_evidence_multiplier: 1.0,
            feature_count,
            sample_count,
            enabled: true,
            diagnostics,
        };
    }

    let mut abs_sum = 0.0;
    let mut abs_max = 0.0;
    let mut pair_count = 0usize;

    for i in 0..feature_count {
        for j in (i + 1)..feature_count {
            let (ref name_i, ref values_i) = features[i];
            let (ref name_j, ref values_j) = features[j];

            let corr = spearman_corr(values_i, values_j).unwrap_or(0.0);
            pairs.push((name_i.clone(), name_j.clone(), corr));

            let abs_corr = corr.abs();
            abs_sum += abs_corr;
            if abs_corr > abs_max {
                abs_max = abs_corr;
            }
            pair_count += 1;
        }
    }

    let avg_abs_corr = if pair_count > 0 {
        abs_sum / pair_count as f64
    } else {
        0.0
    };

    let raw_multiplier = 1.0 / (1.0 + avg_abs_corr * (feature_count.saturating_sub(1) as f64));
    let effective_multiplier = raw_multiplier.clamp(config.min_multiplier, 1.0).min(1.0);

    if avg_abs_corr >= 0.7 {
        diagnostics.push("high_dependence".to_string());
    } else if avg_abs_corr >= 0.3 {
        diagnostics.push("moderate_dependence".to_string());
    } else {
        diagnostics.push("low_dependence".to_string());
    }

    CopulaSummary {
        pairs,
        avg_abs_corr,
        max_abs_corr: abs_max,
        effective_evidence_multiplier: effective_multiplier,
        feature_count,
        sample_count,
        enabled: true,
        diagnostics,
    }
}

fn spearman_corr(x: &[f64], y: &[f64]) -> Option<f64> {
    let n = x.len().min(y.len());
    if n < 2 {
        return None;
    }

    let mut fx = Vec::with_capacity(n);
    let mut fy = Vec::with_capacity(n);
    for idx in 0..n {
        let xv = x[idx];
        let yv = y[idx];
        if xv.is_finite() && yv.is_finite() {
            fx.push(xv);
            fy.push(yv);
        }
    }

    if fx.len() < 2 {
        return None;
    }

    let rx = ranks(&fx);
    let ry = ranks(&fy);
    pearson_corr(&rx, &ry)
}

fn pearson_corr(x: &[f64], y: &[f64]) -> Option<f64> {
    if x.len() != y.len() || x.len() < 2 {
        return None;
    }
    let n = x.len() as f64;
    let mean_x = x.iter().sum::<f64>() / n;
    let mean_y = y.iter().sum::<f64>() / n;

    let mut num = 0.0;
    let mut denom_x = 0.0;
    let mut denom_y = 0.0;

    for i in 0..x.len() {
        let dx = x[i] - mean_x;
        let dy = y[i] - mean_y;
        num += dx * dy;
        denom_x += dx * dx;
        denom_y += dy * dy;
    }

    if denom_x <= 1e-12 || denom_y <= 1e-12 {
        return None;
    }

    Some(num / (denom_x * denom_y).sqrt())
}

fn ranks(values: &[f64]) -> Vec<f64> {
    let mut indexed: Vec<(usize, f64)> = values.iter().copied().enumerate().collect();
    indexed.sort_by(|a, b| a.1.total_cmp(&b.1));

    let mut ranks = vec![0.0; values.len()];
    let mut i = 0usize;
    while i < indexed.len() {
        let mut j = i;
        while j + 1 < indexed.len() && indexed[j + 1].1 == indexed[i].1 {
            j += 1;
        }
        let avg_rank = (i + j) as f64 / 2.0 + 1.0;
        for k in i..=j {
            ranks[indexed[k].0] = avg_rank;
        }
        i = j + 1;
    }
    ranks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_copula_disabled_is_neutral() {
        let config = CopulaConfig::disabled();
        let summary = summarize_copula_dependence(&[], &config);

        assert!(!summary.enabled);
        assert!(summary.pairs.is_empty());
        assert!(summary.effective_evidence_multiplier == 1.0);
    }

    #[test]
    fn test_copula_high_correlation_reduces_multiplier() {
        let streams = vec![
            ("cpu".to_string(), (0..100).map(|i| i as f64).collect()),
            (
                "io".to_string(),
                (0..100).map(|i| i as f64 + 0.01).collect(),
            ),
            (
                "net".to_string(),
                (0..100).map(|i| i as f64 + 0.02).collect(),
            ),
        ];

        let summary = summarize_copula_dependence(&streams, &CopulaConfig::default());

        assert!(summary.avg_abs_corr > 0.95);
        assert!(summary.effective_evidence_multiplier < 0.5);
        assert!(summary.max_abs_corr > 0.95);
    }

    #[test]
    fn test_copula_low_correlation_keeps_multiplier_high() {
        let streams = vec![
            ("cpu".to_string(), (0..100).map(|i| i as f64).collect()),
            (
                "io".to_string(),
                (0..100).map(|i| (i * 37 % 100) as f64).collect(),
            ),
        ];

        let summary = summarize_copula_dependence(&streams, &CopulaConfig::default());

        assert!(summary.avg_abs_corr < 0.2);
        assert!(summary.effective_evidence_multiplier > 0.8);
    }

    #[test]
    fn test_copula_insufficient_samples_gate() {
        let streams = vec![
            ("cpu".to_string(), vec![0.0, 1.0, 2.0]),
            ("io".to_string(), vec![0.1, 1.1, 2.1]),
        ];
        let config = CopulaConfig {
            min_samples: 10,
            ..Default::default()
        };

        let summary = summarize_copula_dependence(&streams, &config);

        assert!(summary.pairs.is_empty());
        assert!(summary.effective_evidence_multiplier == 1.0);
        assert!(summary
            .diagnostics
            .contains(&"insufficient_samples".to_string()));
    }
}
