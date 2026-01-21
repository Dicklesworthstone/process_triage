//! Calibration report generation.
//!
//! Produces comprehensive calibration reports in multiple formats:
//! - ASCII for terminal display
//! - JSON for programmatic consumption
//! - HTML for human-readable sharing (planned)

use super::{
    bias::{analyze_bias, BiasAnalysis},
    curve::CalibrationCurve,
    metrics::{compute_metrics, CalibrationMetrics},
    CalibrationData, CalibrationError, CalibrationQuality,
};
use serde::{Deserialize, Serialize};

/// A complete calibration report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationReport {
    /// Overall calibration quality assessment.
    pub quality: CalibrationQuality,
    /// Computed metrics.
    pub metrics: CalibrationMetrics,
    /// Calibration curve data.
    pub curve: CalibrationCurve,
    /// Bias analysis results.
    pub bias: BiasAnalysis,
    /// Summary text.
    pub summary: String,
}

impl CalibrationReport {
    /// Generate a calibration report from data.
    pub fn from_data(
        data: &[CalibrationData],
        num_bins: usize,
        threshold: f64,
    ) -> Result<Self, CalibrationError> {
        let metrics = compute_metrics(data, threshold)?;
        let curve = CalibrationCurve::from_data(data, num_bins);
        let bias = analyze_bias(data)?;
        let quality = CalibrationQuality::from_metrics(metrics.ece, metrics.brier_score);
        let summary = generate_summary(&metrics, &bias, quality);

        Ok(CalibrationReport {
            quality,
            metrics,
            curve,
            bias,
            summary,
        })
    }

    /// Generate ASCII report for terminal display.
    pub fn ascii_report(&self, curve_width: usize, curve_height: usize) -> String {
        let mut output = String::new();

        // Header
        output.push_str("╔════════════════════════════════════════════════════════════╗\n");
        output.push_str("║              CALIBRATION ANALYSIS REPORT                   ║\n");
        output.push_str("╚════════════════════════════════════════════════════════════╝\n\n");

        // Quality badge
        let quality_badge = match self.quality {
            CalibrationQuality::Excellent => "[★★★★] EXCELLENT",
            CalibrationQuality::Good => "[★★★☆] GOOD",
            CalibrationQuality::Fair => "[★★☆☆] FAIR",
            CalibrationQuality::Poor => "[★☆☆☆] POOR",
        };
        output.push_str(&format!("Overall Quality: {}\n\n", quality_badge));

        // Metrics section
        output.push_str("─── Metrics ───────────────────────────────────────────────\n");
        output.push_str(&format!(
            "  Brier Score:  {:.4}  (0=perfect, 1=worst)\n",
            self.metrics.brier_score
        ));
        output.push_str(&format!(
            "  Log Loss:     {:.4}  (lower is better)\n",
            self.metrics.log_loss
        ));
        output.push_str(&format!(
            "  ECE:          {:.4}  (expected calibration error)\n",
            self.metrics.ece
        ));
        output.push_str(&format!(
            "  MCE:          {:.4}  (max calibration error)\n",
            self.metrics.mce
        ));
        output.push_str(&format!(
            "  AUC-ROC:      {:.4}  (0.5=random, 1.0=perfect)\n",
            self.metrics.auc_roc
        ));
        output.push('\n');

        // Classification metrics
        output.push_str("─── Classification (at threshold) ─────────────────────────\n");
        output.push_str(&format!("  Precision:    {:.4}\n", self.metrics.precision));
        output.push_str(&format!("  Recall:       {:.4}\n", self.metrics.recall));
        output.push_str(&format!("  F1 Score:     {:.4}\n", self.metrics.f1_score));
        output.push('\n');

        // Sample counts
        output.push_str("─── Data Summary ──────────────────────────────────────────\n");
        output.push_str(&format!(
            "  Total Samples:    {}\n",
            self.metrics.sample_count
        ));
        output.push_str(&format!(
            "  Positive (true):  {} ({:.1}%)\n",
            self.metrics.positive_count,
            100.0 * self.metrics.positive_count as f64 / self.metrics.sample_count as f64
        ));
        output.push_str(&format!(
            "  Negative (false): {} ({:.1}%)\n",
            self.metrics.negative_count,
            100.0 * self.metrics.negative_count as f64 / self.metrics.sample_count as f64
        ));
        output.push('\n');

        // Calibration curve
        output.push_str("─── Calibration Curve ─────────────────────────────────────\n");
        output.push_str(&self.curve.ascii_curve(curve_width, curve_height));
        output.push('\n');

        // Bias analysis
        if !self.bias.by_proc_type.is_empty() {
            output.push_str("─── Bias by Process Type ──────────────────────────────────\n");
            for result in &self.bias.by_proc_type {
                let sig = if result.significant { "*" } else { "" };
                output.push_str(&format!(
                    "  {:<20} n={:<5} pred={:.2}  actual={:.2}  bias={:+.2}{}\n",
                    result.stratum,
                    result.sample_count,
                    result.mean_predicted,
                    result.actual_rate,
                    result.bias,
                    sig
                ));
            }
            output.push('\n');
        }

        // Recommendations
        output.push_str("─── Recommendations ───────────────────────────────────────\n");
        for rec in &self.bias.recommendations {
            output.push_str(&format!("  • {}\n", rec));
        }
        output.push('\n');

        // Summary
        output.push_str("─── Summary ───────────────────────────────────────────────\n");
        output.push_str(&format!("  {}\n", self.summary));

        output
    }

    /// Generate JSON report.
    pub fn json_report(&self) -> Result<String, CalibrationError> {
        serde_json::to_string_pretty(self)
            .map_err(|e| CalibrationError::IoError(e.to_string()))
    }
}

/// Generate a human-readable summary.
fn generate_summary(
    metrics: &CalibrationMetrics,
    bias: &BiasAnalysis,
    quality: CalibrationQuality,
) -> String {
    let quality_desc = match quality {
        CalibrationQuality::Excellent => {
            "Model calibration is excellent. Predictions closely match reality."
        }
        CalibrationQuality::Good => {
            "Model calibration is good. Minor adjustments may improve accuracy."
        }
        CalibrationQuality::Fair => {
            "Model calibration is fair. Consider reviewing priors and evidence weights."
        }
        CalibrationQuality::Poor => {
            "Model calibration is poor. Significant recalibration recommended."
        }
    };

    let bias_desc = if bias.overall_bias.abs() < 0.05 {
        "No significant overall bias detected."
    } else if bias.overall_bias > 0.0 {
        "Model tends to be overconfident (predicts higher than actual rates)."
    } else {
        "Model tends to be underconfident (predicts lower than actual rates)."
    };

    let auc_desc = if metrics.auc_roc > 0.9 {
        "Discrimination ability is excellent."
    } else if metrics.auc_roc > 0.8 {
        "Discrimination ability is good."
    } else if metrics.auc_roc > 0.7 {
        "Discrimination ability is fair."
    } else {
        "Discrimination ability needs improvement."
    };

    format!("{} {} {}", quality_desc, bias_desc, auc_desc)
}

/// Signature-specific calibration tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureCalibrationData {
    /// Signature ID that matched.
    pub signature_id: String,
    /// Signature category (e.g., "test_runner", "dev_server").
    pub category: String,
    /// Match confidence score (0.0 to 1.0).
    pub match_confidence: f64,
    /// Predicted abandonment probability from fast-path.
    pub predicted_prob: f64,
    /// Actual outcome: was it truly abandoned?
    pub actual_abandoned: bool,
    /// Human decision if reviewed (kill=true, spare=false).
    pub human_decision: Option<bool>,
    /// Timestamp of the prediction.
    pub timestamp: i64,
    /// Process ID for reference.
    pub pid: u32,
    /// Process command (redacted).
    pub command: String,
}

/// Calibration analysis for a specific signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureCalibration {
    /// Signature ID.
    pub signature_id: String,
    /// Number of matches.
    pub match_count: usize,
    /// Mean match confidence.
    pub mean_confidence: f64,
    /// Calibration metrics for this signature's predictions.
    pub metrics: Option<CalibrationMetrics>,
    /// Confusion matrix: true positives, false positives, etc.
    pub confusion: ConfusionMatrix,
    /// Whether this signature should be flagged for review.
    pub needs_review: bool,
    /// Suggested confidence threshold adjustment.
    pub suggested_threshold: Option<f64>,
}

/// Confusion matrix for classification evaluation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConfusionMatrix {
    pub true_positives: usize,
    pub false_positives: usize,
    pub true_negatives: usize,
    pub false_negatives: usize,
}

impl ConfusionMatrix {
    pub fn precision(&self) -> f64 {
        let denom = self.true_positives + self.false_positives;
        if denom == 0 {
            0.0
        } else {
            self.true_positives as f64 / denom as f64
        }
    }

    pub fn recall(&self) -> f64 {
        let denom = self.true_positives + self.false_negatives;
        if denom == 0 {
            0.0
        } else {
            self.true_positives as f64 / denom as f64
        }
    }

    pub fn f1(&self) -> f64 {
        let p = self.precision();
        let r = self.recall();
        if p + r == 0.0 {
            0.0
        } else {
            2.0 * p * r / (p + r)
        }
    }

    pub fn accuracy(&self) -> f64 {
        let total =
            self.true_positives + self.false_positives + self.true_negatives + self.false_negatives;
        if total == 0 {
            0.0
        } else {
            (self.true_positives + self.true_negatives) as f64 / total as f64
        }
    }
}

/// Analyze calibration for signature matches.
pub fn analyze_signature_calibration(
    data: &[SignatureCalibrationData],
    threshold: f64,
) -> Vec<SignatureCalibration> {
    use std::collections::HashMap;

    let mut by_signature: HashMap<String, Vec<&SignatureCalibrationData>> = HashMap::new();
    for d in data {
        by_signature
            .entry(d.signature_id.clone())
            .or_default()
            .push(d);
    }

    by_signature
        .into_iter()
        .map(|(signature_id, samples)| {
            let match_count = samples.len();
            let mean_confidence =
                samples.iter().map(|s| s.match_confidence).sum::<f64>() / match_count as f64;

            // Build confusion matrix
            let mut confusion = ConfusionMatrix::default();
            for s in &samples {
                let predicted_positive = s.predicted_prob >= threshold;
                match (predicted_positive, s.actual_abandoned) {
                    (true, true) => confusion.true_positives += 1,
                    (true, false) => confusion.false_positives += 1,
                    (false, true) => confusion.false_negatives += 1,
                    (false, false) => confusion.true_negatives += 1,
                }
            }

            // Compute metrics if enough samples
            let metrics = if match_count >= 10 {
                let cal_data: Vec<CalibrationData> = samples
                    .iter()
                    .map(|s| CalibrationData {
                        predicted: s.predicted_prob,
                        actual: s.actual_abandoned,
                        proc_type: Some(s.category.clone()),
                        ..Default::default()
                    })
                    .collect();
                compute_metrics(&cal_data, threshold).ok()
            } else {
                None
            };

            // Flag for review if precision or recall is low
            let needs_review = confusion.precision() < 0.7 || confusion.recall() < 0.7;

            // Suggest threshold adjustment based on data
            let suggested_threshold = compute_optimal_threshold(&samples);

            SignatureCalibration {
                signature_id,
                match_count,
                mean_confidence,
                metrics,
                confusion,
                needs_review,
                suggested_threshold,
            }
        })
        .collect()
}

/// Compute optimal threshold using Youden's J statistic.
fn compute_optimal_threshold(data: &[&SignatureCalibrationData]) -> Option<f64> {
    if data.len() < 20 {
        return None;
    }

    let positives: usize = data.iter().filter(|d| d.actual_abandoned).count();
    let negatives = data.len() - positives;

    if positives == 0 || negatives == 0 {
        return None;
    }

    // Try thresholds from 0.1 to 0.9
    let mut best_threshold = 0.5;
    let mut best_j = f64::NEG_INFINITY;

    for i in 1..10 {
        let threshold = i as f64 / 10.0;
        let mut tp = 0;
        let mut fp = 0;

        for d in data {
            let pred_pos = d.predicted_prob >= threshold;
            match (pred_pos, d.actual_abandoned) {
                (true, true) => tp += 1,
                (true, false) => fp += 1,
                _ => {}
            }
        }

        let tpr = tp as f64 / positives as f64; // sensitivity
        let fpr = fp as f64 / negatives as f64; // 1 - specificity
        let j = tpr - fpr; // Youden's J

        if j > best_j {
            best_j = j;
            best_threshold = threshold;
        }
    }

    Some(best_threshold)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_data(pairs: &[(f64, bool)]) -> Vec<CalibrationData> {
        pairs
            .iter()
            .map(|&(predicted, actual)| CalibrationData {
                predicted,
                actual,
                ..Default::default()
            })
            .collect()
    }

    #[test]
    fn test_calibration_report() {
        let data = make_data(&[
            (0.9, true),
            (0.8, true),
            (0.7, true),
            (0.6, true),
            (0.5, true),
            (0.4, false),
            (0.3, false),
            (0.2, false),
            (0.1, false),
            (0.05, false),
        ]);

        let report = CalibrationReport::from_data(&data, 10, 0.5).unwrap();
        assert!(matches!(
            report.quality,
            CalibrationQuality::Good | CalibrationQuality::Excellent
        ));
    }

    #[test]
    fn test_ascii_report_generation() {
        let data = make_data(&[
            (0.9, true),
            (0.8, true),
            (0.3, false),
            (0.2, false),
            (0.9, true),
            (0.8, true),
            (0.3, false),
            (0.2, false),
            (0.7, true),
            (0.1, false),
        ]);

        let report = CalibrationReport::from_data(&data, 10, 0.5).unwrap();
        let ascii = report.ascii_report(40, 10);
        assert!(ascii.contains("CALIBRATION ANALYSIS REPORT"));
        assert!(ascii.contains("Brier Score"));
    }

    #[test]
    fn test_confusion_matrix() {
        let mut cm = ConfusionMatrix {
            true_positives: 80,
            false_positives: 20,
            true_negatives: 70,
            false_negatives: 30,
        };
        assert!((cm.precision() - 0.8).abs() < 0.01);
        assert!((cm.recall() - 0.727).abs() < 0.01);
        assert!((cm.accuracy() - 0.75).abs() < 0.01);
    }
}
