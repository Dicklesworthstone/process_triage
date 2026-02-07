//! Bias detection and analysis for calibration data.
//!
//! Identifies systematic biases in predictions across different dimensions:
//! - Process type (dev servers vs test runners vs build tools)
//! - Score ranges (overconfidence in high/low scores)
//! - Temporal patterns (drift over time)
//! - Host-specific effects

use super::{CalibrationData, CalibrationError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Detected bias in a specific stratum.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiasResult {
    /// Name of the stratum (e.g., "test_runner", "high_confidence").
    pub stratum: String,
    /// Number of samples in this stratum.
    pub sample_count: usize,
    /// Mean predicted probability.
    pub mean_predicted: f64,
    /// Actual positive rate.
    pub actual_rate: f64,
    /// Bias direction: positive = overconfident, negative = underconfident.
    pub bias: f64,
    /// Whether the bias is statistically significant.
    pub significant: bool,
    /// Recommended adjustment factor.
    pub suggested_adjustment: f64,
}

/// Summary of bias analysis across all strata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiasAnalysis {
    /// Overall bias (mean predicted - actual rate).
    pub overall_bias: f64,
    /// Bias results by process type.
    pub by_proc_type: Vec<BiasResult>,
    /// Bias results by score range.
    pub by_score_range: Vec<BiasResult>,
    /// Bias results by host (if multiple hosts).
    pub by_host: Vec<BiasResult>,
    /// Recommendations for prior adjustments.
    pub recommendations: Vec<String>,
}

impl Default for BiasAnalysis {
    fn default() -> Self {
        Self {
            overall_bias: 0.0,
            by_proc_type: Vec::new(),
            by_score_range: Vec::new(),
            by_host: Vec::new(),
            recommendations: Vec::new(),
        }
    }
}

/// Analyze bias in calibration data.
pub fn analyze_bias(data: &[CalibrationData]) -> Result<BiasAnalysis, CalibrationError> {
    if data.is_empty() {
        return Err(CalibrationError::NoData);
    }

    let min_samples = 5; // Minimum samples for meaningful analysis

    // Overall bias
    let overall_predicted: f64 = data.iter().map(|d| d.predicted).sum::<f64>() / data.len() as f64;
    let overall_actual: f64 = data.iter().filter(|d| d.actual).count() as f64 / data.len() as f64;
    let overall_bias = overall_predicted - overall_actual;

    // Bias by process type
    let by_proc_type = analyze_by_stratum(
        data,
        |d| d.proc_type.clone().unwrap_or_else(|| "unknown".to_string()),
        min_samples,
    );

    // Bias by score range
    let by_score_range = analyze_by_score_range(data, min_samples);

    // Bias by host
    let by_host = analyze_by_stratum(
        data,
        |d| d.host_id.clone().unwrap_or_else(|| "default".to_string()),
        min_samples,
    );

    // Generate recommendations
    let recommendations = generate_recommendations(&by_proc_type, &by_score_range, overall_bias);

    Ok(BiasAnalysis {
        overall_bias,
        by_proc_type,
        by_score_range,
        by_host,
        recommendations,
    })
}

/// Analyze bias for a grouping function.
fn analyze_by_stratum<F>(data: &[CalibrationData], key_fn: F, min_samples: usize) -> Vec<BiasResult>
where
    F: Fn(&CalibrationData) -> String,
{
    let mut groups: HashMap<String, Vec<&CalibrationData>> = HashMap::new();

    for d in data {
        let key = key_fn(d);
        groups.entry(key).or_default().push(d);
    }

    groups
        .into_iter()
        .filter(|(_, v)| v.len() >= min_samples)
        .map(|(stratum, samples)| {
            let sample_count = samples.len();
            let mean_predicted: f64 =
                samples.iter().map(|d| d.predicted).sum::<f64>() / sample_count as f64;
            let actual_rate: f64 =
                samples.iter().filter(|d| d.actual).count() as f64 / sample_count as f64;
            let bias = mean_predicted - actual_rate;

            // Simple significance test: |bias| > 2 * standard error
            let se = (mean_predicted * (1.0 - mean_predicted) / sample_count as f64).sqrt();
            let significant = bias.abs() > 2.0 * se && sample_count >= 20;

            // Suggested adjustment: multiplicative correction
            let suggested_adjustment = if mean_predicted > 0.01 {
                actual_rate / mean_predicted
            } else {
                1.0
            };

            BiasResult {
                stratum,
                sample_count,
                mean_predicted,
                actual_rate,
                bias,
                significant,
                suggested_adjustment,
            }
        })
        .collect()
}

/// Analyze bias by score ranges.
fn analyze_by_score_range(data: &[CalibrationData], min_samples: usize) -> Vec<BiasResult> {
    let ranges = [
        ("very_low (0-20)", 0.0, 0.2),
        ("low (20-40)", 0.2, 0.4),
        ("medium (40-60)", 0.4, 0.6),
        ("high (60-80)", 0.6, 0.8),
        ("very_high (80-100)", 0.8, 1.0),
    ];

    ranges
        .iter()
        .filter_map(|(name, low, high)| {
            let samples: Vec<_> = data
                .iter()
                .filter(|d| d.predicted >= *low && d.predicted < *high)
                .collect();

            if samples.len() < min_samples {
                return None;
            }

            let sample_count = samples.len();
            let mean_predicted: f64 =
                samples.iter().map(|d| d.predicted).sum::<f64>() / sample_count as f64;
            let actual_rate: f64 =
                samples.iter().filter(|d| d.actual).count() as f64 / sample_count as f64;
            let bias = mean_predicted - actual_rate;

            let se = (mean_predicted * (1.0 - mean_predicted) / sample_count as f64).sqrt();
            let significant = bias.abs() > 2.0 * se && sample_count >= 20;

            let suggested_adjustment = if mean_predicted > 0.01 {
                actual_rate / mean_predicted
            } else {
                1.0
            };

            Some(BiasResult {
                stratum: name.to_string(),
                sample_count,
                mean_predicted,
                actual_rate,
                bias,
                significant,
                suggested_adjustment,
            })
        })
        .collect()
}

/// Generate actionable recommendations based on bias analysis.
fn generate_recommendations(
    by_proc_type: &[BiasResult],
    by_score_range: &[BiasResult],
    overall_bias: f64,
) -> Vec<String> {
    let mut recs = Vec::new();

    // Overall bias recommendation
    if overall_bias > 0.1 {
        recs.push(format!(
            "Model is overconfident overall (bias={:.2}). Consider lowering base priors.",
            overall_bias
        ));
    } else if overall_bias < -0.1 {
        recs.push(format!(
            "Model is underconfident overall (bias={:.2}). Consider raising base priors.",
            overall_bias
        ));
    }

    // Process type specific recommendations
    for result in by_proc_type {
        if result.significant && result.bias.abs() > 0.15 {
            if result.bias > 0.0 {
                recs.push(format!(
                    "Overconfident on '{}' (bias={:.2}, n={}). Lower {} prior by {:.0}%.",
                    result.stratum,
                    result.bias,
                    result.sample_count,
                    result.stratum,
                    (1.0 - result.suggested_adjustment) * 100.0
                ));
            } else {
                recs.push(format!(
                    "Underconfident on '{}' (bias={:.2}, n={}). Raise {} prior by {:.0}%.",
                    result.stratum,
                    result.bias,
                    result.sample_count,
                    result.stratum,
                    (result.suggested_adjustment - 1.0) * 100.0
                ));
            }
        }
    }

    // Score range recommendations
    for result in by_score_range {
        if result.significant && result.bias.abs() > 0.15
            && result.bias > 0.0 {
                recs.push(format!(
                    "Overconfident in {} range (bias={:.2}). Model may need calibration.",
                    result.stratum, result.bias
                ));
            }
    }

    if recs.is_empty() {
        recs.push(
            "Model calibration looks reasonable. No significant biases detected.".to_string(),
        );
    }

    recs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_data(pairs: &[(f64, bool, &str)]) -> Vec<CalibrationData> {
        pairs
            .iter()
            .map(|&(predicted, actual, proc_type)| CalibrationData {
                predicted,
                actual,
                proc_type: Some(proc_type.to_string()),
                ..Default::default()
            })
            .collect()
    }

    #[test]
    fn test_analyze_bias_empty() {
        let result = analyze_bias(&[]);
        assert!(matches!(result, Err(CalibrationError::NoData)));
    }

    #[test]
    fn test_analyze_bias_balanced() {
        let data = make_data(&[
            (0.8, true, "test"),
            (0.7, true, "test"),
            (0.3, false, "test"),
            (0.2, false, "test"),
            (0.9, true, "test"),
        ]);
        let analysis = analyze_bias(&data).unwrap();
        // Overall bias should be small for well-calibrated data
        assert!(analysis.overall_bias.abs() < 0.3);
    }

    #[test]
    fn test_overconfident_detection() {
        // Model predicts high but actual rate is low
        let data: Vec<CalibrationData> = (0..50)
            .map(|_| CalibrationData {
                predicted: 0.9,
                actual: false, // Always wrong
                proc_type: Some("test".to_string()),
                ..Default::default()
            })
            .collect();

        let analysis = analyze_bias(&data).unwrap();
        assert!(analysis.overall_bias > 0.5); // Severely overconfident
    }

    #[test]
    fn test_underconfident_detection() {
        // Model predicts low but actual rate is high
        let data: Vec<CalibrationData> = (0..50)
            .map(|_| CalibrationData {
                predicted: 0.1,
                actual: true,
                proc_type: Some("test".to_string()),
                ..Default::default()
            })
            .collect();

        let analysis = analyze_bias(&data).unwrap();
        assert!(analysis.overall_bias < -0.5);
    }

    #[test]
    fn test_single_sample() {
        let data = make_data(&[(0.5, true, "test")]);
        let analysis = analyze_bias(&data).unwrap();
        // With only 1 sample, still computes overall bias
        assert!((analysis.overall_bias - (0.5 - 1.0)).abs() < 1e-6);
    }

    #[test]
    fn test_by_proc_type_min_samples() {
        // Only 3 samples per type, below min_samples=5
        let data = make_data(&[
            (0.9, true, "a"),
            (0.9, true, "a"),
            (0.9, true, "a"),
            (0.1, false, "b"),
            (0.1, false, "b"),
            (0.1, false, "b"),
        ]);
        let analysis = analyze_bias(&data).unwrap();
        // Neither group reaches min_samples=5
        assert!(analysis.by_proc_type.is_empty());
    }

    #[test]
    fn test_by_proc_type_above_min_samples() {
        let data = make_data(&[
            (0.9, true, "daemon"),
            (0.9, true, "daemon"),
            (0.8, true, "daemon"),
            (0.7, false, "daemon"),
            (0.6, true, "daemon"),
        ]);
        let analysis = analyze_bias(&data).unwrap();
        assert_eq!(analysis.by_proc_type.len(), 1);
        assert_eq!(analysis.by_proc_type[0].stratum, "daemon");
        assert_eq!(analysis.by_proc_type[0].sample_count, 5);
    }

    #[test]
    fn test_by_score_range() {
        // 5 samples in the high range (0.6-0.8)
        let data: Vec<CalibrationData> = (0..5)
            .map(|i| CalibrationData {
                predicted: 0.7,
                actual: i < 3, // 3 true, 2 false
                proc_type: None,
                ..Default::default()
            })
            .collect();
        let analysis = analyze_bias(&data).unwrap();
        assert!(!analysis.by_score_range.is_empty());
        let high = analysis
            .by_score_range
            .iter()
            .find(|r| r.stratum.contains("60-80"));
        assert!(high.is_some());
        let h = high.unwrap();
        assert_eq!(h.sample_count, 5);
        assert!((h.actual_rate - 0.6).abs() < 1e-6);
    }

    #[test]
    fn test_by_host() {
        let data: Vec<CalibrationData> = (0..10)
            .map(|i| CalibrationData {
                predicted: 0.5,
                actual: i < 5,
                host_id: Some("host-1".to_string()),
                ..Default::default()
            })
            .collect();
        let analysis = analyze_bias(&data).unwrap();
        assert_eq!(analysis.by_host.len(), 1);
        assert_eq!(analysis.by_host[0].stratum, "host-1");
    }

    #[test]
    fn test_bias_result_serde() {
        let br = BiasResult {
            stratum: "test".to_string(),
            sample_count: 100,
            mean_predicted: 0.8,
            actual_rate: 0.6,
            bias: 0.2,
            significant: true,
            suggested_adjustment: 0.75,
        };
        let json = serde_json::to_string(&br).unwrap();
        let back: BiasResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.stratum, "test");
        assert_eq!(back.sample_count, 100);
        assert!(back.significant);
    }

    #[test]
    fn test_bias_analysis_default() {
        let ba = BiasAnalysis::default();
        assert!((ba.overall_bias - 0.0).abs() < f64::EPSILON);
        assert!(ba.by_proc_type.is_empty());
        assert!(ba.by_score_range.is_empty());
        assert!(ba.by_host.is_empty());
        assert!(ba.recommendations.is_empty());
    }

    #[test]
    fn test_bias_analysis_serde() {
        let ba = BiasAnalysis {
            overall_bias: 0.15,
            by_proc_type: Vec::new(),
            by_score_range: Vec::new(),
            by_host: Vec::new(),
            recommendations: vec!["test rec".to_string()],
        };
        let json = serde_json::to_string(&ba).unwrap();
        let back: BiasAnalysis = serde_json::from_str(&json).unwrap();
        assert!((back.overall_bias - 0.15).abs() < 1e-6);
        assert_eq!(back.recommendations.len(), 1);
    }

    #[test]
    fn test_recommendations_overconfident() {
        let data: Vec<CalibrationData> = (0..50)
            .map(|_| CalibrationData {
                predicted: 0.9,
                actual: false,
                proc_type: Some("test".to_string()),
                ..Default::default()
            })
            .collect();
        let analysis = analyze_bias(&data).unwrap();
        assert!(!analysis.recommendations.is_empty());
        assert!(analysis.recommendations[0].contains("overconfident"));
    }

    #[test]
    fn test_recommendations_underconfident() {
        let data: Vec<CalibrationData> = (0..50)
            .map(|_| CalibrationData {
                predicted: 0.1,
                actual: true,
                proc_type: Some("test".to_string()),
                ..Default::default()
            })
            .collect();
        let analysis = analyze_bias(&data).unwrap();
        assert!(!analysis.recommendations.is_empty());
        assert!(analysis.recommendations[0].contains("underconfident"));
    }

    #[test]
    fn test_recommendations_well_calibrated() {
        // Roughly calibrated data
        let data: Vec<CalibrationData> = (0..20)
            .map(|i| CalibrationData {
                predicted: 0.5,
                actual: i % 2 == 0, // ~50% actual rate
                proc_type: Some("test".to_string()),
                ..Default::default()
            })
            .collect();
        let analysis = analyze_bias(&data).unwrap();
        // Should recommend no changes
        assert!(analysis
            .recommendations
            .iter()
            .any(|r| r.contains("reasonable") || r.contains("No significant")));
    }

    #[test]
    fn test_suggested_adjustment_overconfident() {
        // When mean_predicted > actual_rate, adjustment < 1
        let data = make_data(&[
            (0.9, false, "t"),
            (0.9, false, "t"),
            (0.9, false, "t"),
            (0.9, true, "t"),
            (0.9, false, "t"),
        ]);
        let analysis = analyze_bias(&data).unwrap();
        if let Some(r) = analysis.by_proc_type.first() {
            assert!(r.suggested_adjustment < 1.0);
        }
    }

    #[test]
    fn test_significance_requires_n20() {
        // Even with large bias, if n < 20, not significant
        let data: Vec<CalibrationData> = (0..10)
            .map(|_| CalibrationData {
                predicted: 0.9,
                actual: false,
                proc_type: Some("test".to_string()),
                ..Default::default()
            })
            .collect();
        let analysis = analyze_bias(&data).unwrap();
        for r in &analysis.by_proc_type {
            assert!(!r.significant);
        }
    }

    #[test]
    fn test_no_proc_type_uses_unknown() {
        let data: Vec<CalibrationData> = (0..5)
            .map(|i| CalibrationData {
                predicted: 0.5,
                actual: i < 3,
                proc_type: None,
                ..Default::default()
            })
            .collect();
        let analysis = analyze_bias(&data).unwrap();
        if !analysis.by_proc_type.is_empty() {
            assert!(analysis.by_proc_type.iter().any(|r| r.stratum == "unknown"));
        }
    }
}
