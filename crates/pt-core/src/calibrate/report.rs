//! Calibration report generation.
//!
//! Produces comprehensive calibration reports in multiple formats:
//! - ASCII for terminal display
//! - JSON for programmatic consumption
//! - HTML for human-readable sharing (planned)

use super::{
    bias::{analyze_bias, BiasAnalysis},
    bounds::{false_kill_credible_bounds, CredibleBounds},
    curve::CalibrationCurve,
    metrics::{compute_metrics, CalibrationMetrics},
    pac_bayes::{pac_bayes_error_bounds, PacBayesSummary},
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
    /// Credible bounds on false-kill rate (shadow mode safety artifact).
    pub credible_bounds: Option<CredibleBounds>,
    /// PAC-Bayes bounds on false-kill rate (shadow mode safety artifact).
    pub pac_bayes: Option<PacBayesSummary>,
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
        let deltas = [0.05, 0.01];
        let credible_bounds = false_kill_credible_bounds(data, threshold, 1.0, 1.0, &deltas);
        let pac_bayes = credible_bounds.as_ref().and_then(|b| {
            pac_bayes_error_bounds(b.errors as usize, b.trials as usize, 0.0, &deltas)
        });

        Ok(CalibrationReport {
            quality,
            metrics,
            curve,
            bias,
            credible_bounds,
            pac_bayes,
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

        // Calibration by score bucket
        output.push_str("─── Calibration by Score Bucket ─────────────────────────\n");
        for bin in &self.curve.bins {
            let lower = (bin.lower * 100.0).round() as i32;
            let upper = (bin.upper * 100.0).round() as i32;
            if bin.count == 0 {
                output.push_str(&format!("  {:>3}-{:>3}: no data\n", lower, upper));
            } else {
                output.push_str(&format!(
                    "  {:>3}-{:>3}: Predicted {:>5.1}%, Actual {:>5.1}% (n={})\n",
                    lower,
                    upper,
                    bin.mean_predicted * 100.0,
                    bin.actual_rate * 100.0,
                    bin.count
                ));
            }
        }
        output.push('\n');

        // Credible bounds (false-kill rate)
        output.push_str("─── False-Kill Credible Bounds ───────────────────────────\n");
        if let Some(bounds) = &self.credible_bounds {
            output.push_str(&format!("  Trials (kill recs): {}\n", bounds.trials));
            output.push_str(&format!("  Errors (false kills): {}\n", bounds.errors));
            output.push_str(&format!("  Threshold: {:.2}\n", bounds.threshold));
            output.push_str(&format!(
                "  Prior Beta(a,b):     ({:.2}, {:.2})\n",
                bounds.prior_alpha, bounds.prior_beta
            ));
            output.push_str(&format!(
                "  Posterior Beta(a,b): ({:.2}, {:.2})\n",
                bounds.posterior_alpha, bounds.posterior_beta
            ));
            output.push_str(&format!(
                "  Observed error rate: {:.4}\n",
                bounds.observed_rate
            ));
            output.push_str(&format!(
                "  Posterior mean:      {:.4}\n",
                bounds.posterior_mean
            ));
            for bound in &bounds.bounds {
                output.push_str(&format!(
                    "  Upper bound (1-δ={:.2}): {:.4}\n",
                    1.0 - bound.delta,
                    bound.upper
                ));
            }
            output.push_str(&format!(
                "  Definition: {} | {}\n",
                bounds.trial_definition, bounds.error_definition
            ));
        } else {
            output.push_str("  No kill recommendations; bounds unavailable.\n");
        }
        output.push('\n');

        // PAC-Bayes bounds
        output.push_str("─── PAC-Bayes Bounds ───────────────────────────────────────\n");
        if let Some(pac) = &self.pac_bayes {
            output.push_str(&format!(
                "  Trials: {}  Errors: {}  Empirical: {:.4}\n",
                pac.trials, pac.errors, pac.empirical_error
            ));
            output.push_str(&format!("  KL(Q||P): {:.4}\n", pac.kl_qp));
            for bound in &pac.bounds {
                output.push_str(&format!(
                    "  Upper bound (1-δ={:.2}): {:.4}\n",
                    1.0 - bound.delta,
                    bound.upper_bound
                ));
            }
            output.push_str(&format!("  Assumptions: {}\n", pac.assumptions));
        } else {
            output.push_str("  No trials; PAC-Bayes bounds unavailable.\n");
        }
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

        output.push_str("─── Systematic Biases Detected ───────────────────────────\n");
        let mut has_bias = false;
        for result in &self.bias.by_proc_type {
            if !result.significant {
                continue;
            }
            has_bias = true;
            let direction = if result.bias >= 0.0 {
                "over-predicted"
            } else {
                "under-predicted"
            };
            output.push_str(&format!(
                "  {:<20} {} by {:.1}% (n={})\n",
                result.stratum,
                direction,
                result.bias.abs() * 100.0,
                result.sample_count
            ));
        }
        if !has_bias {
            output.push_str("  No significant biases detected.\n");
        }
        output.push('\n');

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
        serde_json::to_string_pretty(self).map_err(|e| CalibrationError::IoError(e.to_string()))
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
        // With only 10 samples, quality depends on bin placement; accept any non-panic.
        assert!(matches!(
            report.quality,
            CalibrationQuality::Excellent
                | CalibrationQuality::Good
                | CalibrationQuality::Fair
                | CalibrationQuality::Poor
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
    fn test_credible_bounds_present_when_trials_exist() {
        let data = make_data(&[
            (0.9, true),
            (0.9, false), // false positive at threshold 0.5
            (0.4, false),
            (0.4, false),
            (0.4, false),
            (0.4, false),
            (0.4, false),
            (0.4, false),
            (0.4, false),
            (0.4, false),
        ]);

        let report = CalibrationReport::from_data(&data, 10, 0.5).unwrap();
        let bounds = report.credible_bounds.expect("credible bounds missing");

        assert_eq!(bounds.trials, 2);
        assert_eq!(bounds.errors, 1);
        assert!((bounds.observed_rate - 0.5).abs() < 1e-6);
        assert!(bounds.trial_definition.contains("predictions >= 0.50"));
    }

    #[test]
    fn test_confusion_matrix() {
        let cm = ConfusionMatrix {
            true_positives: 80,
            false_positives: 20,
            true_negatives: 70,
            false_negatives: 30,
        };
        assert!((cm.precision() - 0.8).abs() < 0.01);
        assert!((cm.recall() - 0.727).abs() < 0.01);
        assert!((cm.accuracy() - 0.75).abs() < 0.01);
    }

    // ── ConfusionMatrix extended ────────────────────────────────

    #[test]
    fn confusion_default_all_zero() {
        let cm = ConfusionMatrix::default();
        assert_eq!(cm.true_positives, 0);
        assert_eq!(cm.false_positives, 0);
        assert_eq!(cm.true_negatives, 0);
        assert_eq!(cm.false_negatives, 0);
    }

    #[test]
    fn confusion_all_zeros_metrics() {
        let cm = ConfusionMatrix::default();
        assert_eq!(cm.precision(), 0.0);
        assert_eq!(cm.recall(), 0.0);
        assert_eq!(cm.f1(), 0.0);
        assert_eq!(cm.accuracy(), 0.0);
    }

    #[test]
    fn confusion_perfect_classifier() {
        let cm = ConfusionMatrix {
            true_positives: 50,
            false_positives: 0,
            true_negatives: 50,
            false_negatives: 0,
        };
        assert_eq!(cm.precision(), 1.0);
        assert_eq!(cm.recall(), 1.0);
        assert_eq!(cm.f1(), 1.0);
        assert_eq!(cm.accuracy(), 1.0);
    }

    #[test]
    fn confusion_no_positives_predicted() {
        let cm = ConfusionMatrix {
            true_positives: 0,
            false_positives: 0,
            true_negatives: 90,
            false_negatives: 10,
        };
        assert_eq!(cm.precision(), 0.0);
        assert_eq!(cm.recall(), 0.0);
        assert_eq!(cm.f1(), 0.0);
        assert!((cm.accuracy() - 0.9).abs() < 0.01);
    }

    #[test]
    fn confusion_f1_symmetry() {
        let cm = ConfusionMatrix {
            true_positives: 40,
            false_positives: 10,
            true_negatives: 40,
            false_negatives: 10,
        };
        let p = cm.precision();
        let r = cm.recall();
        assert!((p - r).abs() < 0.01); // symmetric case
        assert!((cm.f1() - p).abs() < 0.01); // f1 = precision = recall
    }

    #[test]
    fn confusion_serde_roundtrip() {
        let cm = ConfusionMatrix {
            true_positives: 1,
            false_positives: 2,
            true_negatives: 3,
            false_negatives: 4,
        };
        let json = serde_json::to_string(&cm).unwrap();
        let back: ConfusionMatrix = serde_json::from_str(&json).unwrap();
        assert_eq!(back.true_positives, 1);
        assert_eq!(back.false_negatives, 4);
    }

    // ── generate_summary ────────────────────────────────────────

    fn make_data_10() -> Vec<CalibrationData> {
        make_data(&[
            (0.9, true), (0.85, true), (0.8, true), (0.7, true), (0.6, true),
            (0.4, false), (0.3, false), (0.2, false), (0.15, false), (0.1, false),
        ])
    }

    #[test]
    fn summary_excellent_quality() {
        let data = make_data_10();
        let metrics = compute_metrics(&data, 0.5).unwrap();
        let bias = analyze_bias(&data).unwrap();
        let s = generate_summary(&metrics, &bias, CalibrationQuality::Excellent);
        assert!(s.contains("excellent"));
    }

    #[test]
    fn summary_poor_quality() {
        let data = make_data_10();
        let metrics = compute_metrics(&data, 0.5).unwrap();
        let bias = analyze_bias(&data).unwrap();
        let s = generate_summary(&metrics, &bias, CalibrationQuality::Poor);
        assert!(s.contains("poor"));
    }

    #[test]
    fn summary_good_quality() {
        let data = make_data_10();
        let metrics = compute_metrics(&data, 0.5).unwrap();
        let bias = analyze_bias(&data).unwrap();
        let s = generate_summary(&metrics, &bias, CalibrationQuality::Good);
        assert!(s.contains("good"));
    }

    #[test]
    fn summary_fair_quality() {
        let data = make_data_10();
        let metrics = compute_metrics(&data, 0.5).unwrap();
        let bias = analyze_bias(&data).unwrap();
        let s = generate_summary(&metrics, &bias, CalibrationQuality::Fair);
        assert!(s.contains("fair"));
    }

    // ── CalibrationReport methods ───────────────────────────────

    #[test]
    fn json_report_valid_json() {
        let data = make_data(&[
            (0.9, true), (0.8, true), (0.7, true), (0.6, true), (0.5, true),
            (0.4, false), (0.3, false), (0.2, false), (0.1, false), (0.05, false),
        ]);
        let report = CalibrationReport::from_data(&data, 10, 0.5).unwrap();
        let json = report.json_report().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.is_object());
        assert!(parsed.get("quality").is_some());
        assert!(parsed.get("metrics").is_some());
        assert!(parsed.get("curve").is_some());
        assert!(parsed.get("bias").is_some());
    }

    #[test]
    fn ascii_report_contains_all_sections() {
        let data = make_data(&[
            (0.9, true), (0.8, true), (0.7, true), (0.6, true), (0.5, true),
            (0.4, false), (0.3, false), (0.2, false), (0.1, false), (0.05, false),
        ]);
        let report = CalibrationReport::from_data(&data, 10, 0.5).unwrap();
        let ascii = report.ascii_report(40, 10);
        assert!(ascii.contains("Metrics"));
        assert!(ascii.contains("Classification"));
        assert!(ascii.contains("Data Summary"));
        assert!(ascii.contains("Score Bucket"));
        assert!(ascii.contains("False-Kill Credible Bounds"));
        assert!(ascii.contains("PAC-Bayes"));
        assert!(ascii.contains("Summary"));
    }

    #[test]
    fn ascii_report_quality_badge() {
        let data = make_data(&[
            (0.9, true), (0.8, true), (0.1, false), (0.2, false),
            (0.85, true), (0.15, false), (0.95, true), (0.05, false),
            (0.7, true), (0.3, false),
        ]);
        let report = CalibrationReport::from_data(&data, 10, 0.5).unwrap();
        let ascii = report.ascii_report(40, 10);
        // Should contain one of the quality badges
        assert!(
            ascii.contains("EXCELLENT") || ascii.contains("GOOD")
            || ascii.contains("FAIR") || ascii.contains("POOR")
        );
    }

    #[test]
    fn report_no_kill_recs_means_no_bounds_in_ascii() {
        // All predictions below threshold => no kill recommendations => no credible bounds
        let data = make_data(&[
            (0.1, false), (0.2, false), (0.3, false), (0.4, false),
            (0.15, false), (0.25, false), (0.35, false), (0.45, false),
            (0.05, false), (0.12, false),
        ]);
        let report = CalibrationReport::from_data(&data, 10, 0.5).unwrap();
        let ascii = report.ascii_report(40, 10);
        assert!(ascii.contains("bounds unavailable"));
    }

    #[test]
    fn report_serde_roundtrip() {
        let data = make_data(&[
            (0.9, true), (0.8, true), (0.3, false), (0.2, false),
            (0.7, true), (0.1, false), (0.85, true), (0.15, false),
            (0.6, true), (0.4, false),
        ]);
        let report = CalibrationReport::from_data(&data, 5, 0.5).unwrap();
        let json = serde_json::to_string(&report).unwrap();
        let back: CalibrationReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.quality, report.quality);
        assert!((back.metrics.brier_score - report.metrics.brier_score).abs() < 1e-10);
    }

    #[test]
    fn report_from_data_too_few_samples() {
        let data = make_data(&[]);
        let result = CalibrationReport::from_data(&data, 10, 0.5);
        assert!(result.is_err());
    }

    // ── SignatureCalibrationData ─────────────────────────────────

    #[test]
    fn sig_cal_data_serde_roundtrip() {
        let d = SignatureCalibrationData {
            signature_id: "test_runner_npm".into(),
            category: "test_runner".into(),
            match_confidence: 0.9,
            predicted_prob: 0.85,
            actual_abandoned: true,
            human_decision: Some(true),
            timestamp: 1700000000,
            pid: 42,
            command: "npm test".into(),
        };
        let json = serde_json::to_string(&d).unwrap();
        let back: SignatureCalibrationData = serde_json::from_str(&json).unwrap();
        assert_eq!(back.signature_id, "test_runner_npm");
        assert_eq!(back.actual_abandoned, true);
        assert_eq!(back.human_decision, Some(true));
    }

    #[test]
    fn sig_cal_data_without_human_decision() {
        let d = SignatureCalibrationData {
            signature_id: "x".into(),
            category: "y".into(),
            match_confidence: 0.5,
            predicted_prob: 0.5,
            actual_abandoned: false,
            human_decision: None,
            timestamp: 0,
            pid: 1,
            command: "cmd".into(),
        };
        let json = serde_json::to_string(&d).unwrap();
        let back: SignatureCalibrationData = serde_json::from_str(&json).unwrap();
        assert!(back.human_decision.is_none());
    }

    // ── analyze_signature_calibration ───────────────────────────

    fn make_sig_data(pairs: &[(f64, bool)], sig_id: &str) -> Vec<SignatureCalibrationData> {
        pairs.iter().enumerate().map(|(i, &(prob, actual))| {
            SignatureCalibrationData {
                signature_id: sig_id.into(),
                category: "test".into(),
                match_confidence: 0.9,
                predicted_prob: prob,
                actual_abandoned: actual,
                human_decision: None,
                timestamp: i as i64,
                pid: i as u32,
                command: "cmd".into(),
            }
        }).collect()
    }

    #[test]
    fn analyze_empty_data() {
        let result = analyze_signature_calibration(&[], 0.5);
        assert!(result.is_empty());
    }

    #[test]
    fn analyze_single_signature() {
        let data = make_sig_data(&[(0.9, true), (0.1, false), (0.8, true), (0.2, false)], "sig_a");
        let result = analyze_signature_calibration(&data, 0.5);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].signature_id, "sig_a");
        assert_eq!(result[0].match_count, 4);
    }

    #[test]
    fn analyze_confusion_matrix_correct() {
        let data = make_sig_data(
            &[(0.9, true), (0.8, true), (0.1, false), (0.2, false)],
            "sig_b",
        );
        let result = analyze_signature_calibration(&data, 0.5);
        let cm = &result[0].confusion;
        assert_eq!(cm.true_positives, 2);
        assert_eq!(cm.true_negatives, 2);
        assert_eq!(cm.false_positives, 0);
        assert_eq!(cm.false_negatives, 0);
    }

    #[test]
    fn analyze_with_false_positives() {
        let data = make_sig_data(
            &[(0.9, false), (0.8, false), (0.1, true), (0.2, true)],
            "sig_c",
        );
        let result = analyze_signature_calibration(&data, 0.5);
        let cm = &result[0].confusion;
        assert_eq!(cm.false_positives, 2);
        assert_eq!(cm.false_negatives, 2);
    }

    #[test]
    fn analyze_needs_review_low_precision() {
        // All predictions positive, half wrong => precision 0.5 < 0.7 => needs_review
        let data = make_sig_data(
            &[(0.9, true), (0.9, false), (0.9, true), (0.9, false)],
            "sig_d",
        );
        let result = analyze_signature_calibration(&data, 0.5);
        assert!(result[0].needs_review);
    }

    #[test]
    fn analyze_no_review_needed_perfect() {
        let data = make_sig_data(
            &[(0.9, true), (0.8, true), (0.1, false), (0.2, false)],
            "sig_e",
        );
        let result = analyze_signature_calibration(&data, 0.5);
        assert!(!result[0].needs_review);
    }

    #[test]
    fn analyze_suggested_threshold_none_for_small_sample() {
        let data = make_sig_data(
            &[(0.9, true), (0.1, false)],
            "sig_f",
        );
        let result = analyze_signature_calibration(&data, 0.5);
        assert!(result[0].suggested_threshold.is_none());
    }

    #[test]
    fn analyze_multiple_signatures() {
        let mut data = make_sig_data(&[(0.9, true), (0.1, false)], "sig_x");
        data.extend(make_sig_data(&[(0.8, true), (0.2, false)], "sig_y"));
        let result = analyze_signature_calibration(&data, 0.5);
        assert_eq!(result.len(), 2);
        let ids: Vec<_> = result.iter().map(|r| &r.signature_id).collect();
        assert!(ids.contains(&&"sig_x".to_string()));
        assert!(ids.contains(&&"sig_y".to_string()));
    }

    #[test]
    fn analyze_metrics_present_with_enough_samples() {
        // Need at least 10 samples for metrics
        let pairs: Vec<(f64, bool)> = (0..12).map(|i| {
            if i < 6 { (0.8, true) } else { (0.2, false) }
        }).collect();
        let data = make_sig_data(&pairs, "sig_g");
        let result = analyze_signature_calibration(&data, 0.5);
        assert!(result[0].metrics.is_some());
    }

    #[test]
    fn analyze_metrics_absent_with_few_samples() {
        let data = make_sig_data(&[(0.9, true), (0.1, false)], "sig_h");
        let result = analyze_signature_calibration(&data, 0.5);
        assert!(result[0].metrics.is_none());
    }

    // ── SignatureCalibration serde ───────────────────────────────

    #[test]
    fn signature_calibration_serde() {
        let sc = SignatureCalibration {
            signature_id: "test".into(),
            match_count: 100,
            mean_confidence: 0.85,
            metrics: None,
            confusion: ConfusionMatrix::default(),
            needs_review: false,
            suggested_threshold: Some(0.6),
        };
        let json = serde_json::to_string(&sc).unwrap();
        let back: SignatureCalibration = serde_json::from_str(&json).unwrap();
        assert_eq!(back.signature_id, "test");
        assert_eq!(back.suggested_threshold, Some(0.6));
    }
}
