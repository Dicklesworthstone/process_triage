//! Calibration metrics computation.
//!
//! Provides statistical metrics for evaluating calibration quality:
//! - Brier Score
//! - Log Loss
//! - Expected Calibration Error (ECE)
//! - AUC-ROC
//! - Precision/Recall/F1

use super::{CalibrationData, CalibrationError};
use serde::{Deserialize, Serialize};

/// Computed calibration metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationMetrics {
    /// Brier score (mean squared error of probabilities).
    /// Range: 0 (perfect) to 1 (worst).
    pub brier_score: f64,

    /// Log loss (cross-entropy).
    /// Lower is better.
    pub log_loss: f64,

    /// Expected Calibration Error.
    /// Weighted average of per-bin calibration errors.
    pub ece: f64,

    /// Maximum Calibration Error.
    /// Largest per-bin calibration error.
    pub mce: f64,

    /// Area under ROC curve.
    /// Range: 0.5 (random) to 1.0 (perfect discrimination).
    pub auc_roc: f64,

    /// Precision (true positives / predicted positives).
    pub precision: f64,

    /// Recall (true positives / actual positives).
    pub recall: f64,

    /// F1 score (harmonic mean of precision and recall).
    pub f1_score: f64,

    /// Number of samples used for computation.
    pub sample_count: usize,

    /// Number of positive samples.
    pub positive_count: usize,

    /// Number of negative samples.
    pub negative_count: usize,
}

impl Default for CalibrationMetrics {
    fn default() -> Self {
        Self {
            brier_score: 0.0,
            log_loss: 0.0,
            ece: 0.0,
            mce: 0.0,
            auc_roc: 0.5,
            precision: 0.0,
            recall: 0.0,
            f1_score: 0.0,
            sample_count: 0,
            positive_count: 0,
            negative_count: 0,
        }
    }
}

/// Compute all calibration metrics from data.
pub fn compute_metrics(
    data: &[CalibrationData],
    threshold: f64,
) -> Result<CalibrationMetrics, CalibrationError> {
    if data.is_empty() {
        return Err(CalibrationError::NoData);
    }

    let n = data.len();
    if n < 10 {
        return Err(CalibrationError::InsufficientData {
            count: n,
            min_required: 10,
        });
    }

    // Validate probabilities
    for d in data {
        if d.predicted < 0.0 || d.predicted > 1.0 {
            return Err(CalibrationError::InvalidProbability(d.predicted));
        }
    }

    let positive_count = data.iter().filter(|d| d.actual).count();
    let negative_count = n - positive_count;

    // Brier score
    let brier_score = brier_score(data);

    // Log loss
    let log_loss = log_loss(data);

    // ECE and MCE
    let (ece, mce) = calibration_error(data, 10);

    // AUC-ROC
    let auc_roc = auc_roc(data);

    // Precision, Recall, F1
    let (precision, recall, f1_score) = precision_recall_f1(data, threshold);

    Ok(CalibrationMetrics {
        brier_score,
        log_loss,
        ece,
        mce,
        auc_roc,
        precision,
        recall,
        f1_score,
        sample_count: n,
        positive_count,
        negative_count,
    })
}

/// Compute Brier score (mean squared error).
fn brier_score(data: &[CalibrationData]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let sum: f64 = data
        .iter()
        .map(|d| {
            let y = if d.actual { 1.0 } else { 0.0 };
            (d.predicted - y).powi(2)
        })
        .sum();
    sum / data.len() as f64
}

/// Compute log loss (cross-entropy).
fn log_loss(data: &[CalibrationData]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let eps = 1e-15; // Avoid log(0)
    let sum: f64 = data
        .iter()
        .map(|d| {
            let p = d.predicted.clamp(eps, 1.0 - eps);
            if d.actual {
                -p.ln()
            } else {
                -(1.0 - p).ln()
            }
        })
        .sum();
    sum / data.len() as f64
}

/// Compute Expected and Maximum Calibration Error.
fn calibration_error(data: &[CalibrationData], num_bins: usize) -> (f64, f64) {
    if data.is_empty() || num_bins == 0 {
        return (0.0, 0.0);
    }

    let mut bins: Vec<Vec<&CalibrationData>> = vec![Vec::new(); num_bins];

    // Assign to bins based on predicted probability
    for d in data {
        let bin_idx = ((d.predicted * num_bins as f64) as usize).min(num_bins - 1);
        bins[bin_idx].push(d);
    }

    let n = data.len() as f64;
    let mut ece: f64 = 0.0;
    let mut mce: f64 = 0.0;

    for bin in &bins {
        if bin.is_empty() {
            continue;
        }
        let bin_size = bin.len() as f64;
        let avg_pred: f64 = bin.iter().map(|d| d.predicted).sum::<f64>() / bin_size;
        let actual_rate: f64 = bin.iter().filter(|d| d.actual).count() as f64 / bin_size;
        let error = (avg_pred - actual_rate).abs();
        ece += (bin_size / n) * error;
        mce = mce.max(error);
    }

    (ece, mce)
}

/// Compute AUC-ROC using trapezoidal rule.
fn auc_roc(data: &[CalibrationData]) -> f64 {
    if data.is_empty() {
        return 0.5;
    }

    let positive_count = data.iter().filter(|d| d.actual).count();
    let negative_count = data.len() - positive_count;

    if positive_count == 0 || negative_count == 0 {
        return 0.5;
    }

    // Sort by predicted probability descending
    let mut sorted: Vec<_> = data.iter().collect();
    sorted.sort_by(|a, b| {
        b.predicted
            .partial_cmp(&a.predicted)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // Compute AUC using trapezoidal rule
    let mut auc = 0.0;
    let mut tp = 0.0;
    let mut fp = 0.0;
    let mut prev_tp = 0.0;
    let mut prev_fp = 0.0;

    for d in sorted {
        if d.actual {
            tp += 1.0;
        } else {
            fp += 1.0;
        }
        // Add trapezoid area
        auc += (fp - prev_fp) * (tp + prev_tp) / 2.0;
        prev_tp = tp;
        prev_fp = fp;
    }

    auc / (positive_count as f64 * negative_count as f64)
}

/// Compute precision, recall, and F1 score at a given threshold.
fn precision_recall_f1(data: &[CalibrationData], threshold: f64) -> (f64, f64, f64) {
    if data.is_empty() {
        return (0.0, 0.0, 0.0);
    }

    let mut tp = 0;
    let mut fp = 0;
    let mut fn_ = 0;

    for d in data {
        let predicted_positive = d.predicted >= threshold;
        match (predicted_positive, d.actual) {
            (true, true) => tp += 1,
            (true, false) => fp += 1,
            (false, true) => fn_ += 1,
            (false, false) => {}
        }
    }

    let precision = if tp + fp > 0 {
        tp as f64 / (tp + fp) as f64
    } else {
        0.0
    };

    let recall = if tp + fn_ > 0 {
        tp as f64 / (tp + fn_) as f64
    } else {
        0.0
    };

    let f1 = if precision + recall > 0.0 {
        2.0 * precision * recall / (precision + recall)
    } else {
        0.0
    };

    (precision, recall, f1)
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
    fn test_brier_score_perfect() {
        let data = make_data(&[(1.0, true), (0.0, false), (1.0, true), (0.0, false)]);
        let brier = brier_score(&data);
        assert!((brier - 0.0).abs() < 1e-10);
    }

    #[test]
    fn test_brier_score_worst() {
        let data = make_data(&[(0.0, true), (1.0, false)]);
        let brier = brier_score(&data);
        assert!((brier - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_auc_perfect() {
        let data = make_data(&[(0.9, true), (0.8, true), (0.3, false), (0.2, false)]);
        let auc = auc_roc(&data);
        assert!((auc - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_compute_metrics() {
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
        let metrics = compute_metrics(&data, 0.5).unwrap();
        assert!(metrics.auc_roc > 0.9);
        assert!(metrics.brier_score < 0.3);
    }
}
