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
    let overall_actual: f64 =
        data.iter().filter(|d| d.actual).count() as f64 / data.len() as f64;
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
        if result.significant && result.bias.abs() > 0.15 {
            if result.bias > 0.0 {
                recs.push(format!(
                    "Overconfident in {} range (bias={:.2}). Model may need calibration.",
                    result.stratum, result.bias
                ));
            }
        }
    }

    if recs.is_empty() {
        recs.push("Model calibration looks reasonable. No significant biases detected.".to_string());
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
}
