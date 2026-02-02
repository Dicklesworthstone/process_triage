//! Calibration analysis engine for shadow mode data.
//!
//! Computes model calibration metrics, generates calibration curves, detects
//! systematic biases, and provides actionable recommendations for prior tuning.
//!
//! # Metrics
//!
//! - **Brier Score**: Mean squared error of probability predictions (0 = perfect, 1 = worst)
//! - **Log Loss**: Cross-entropy of predictions (lower is better)
//! - **Expected Calibration Error (ECE)**: Weighted average of per-bin calibration errors
//! - **AUC-ROC**: Area under ROC curve (discrimination ability, 0.5 = random, 1.0 = perfect)
//! - **Precision/Recall/F1**: Standard classification metrics
//!
//! # Usage
//!
//! ```ignore
//! use pt_core::calibrate::{CalibrationEngine, CalibrationData};
//!
//! let data = vec![
//!     CalibrationData { predicted: 0.9, actual: true, ..Default::default() },
//!     CalibrationData { predicted: 0.2, actual: false, ..Default::default() },
//! ];
//! let engine = CalibrationEngine::new(&data);
//! let report = engine.compute_report()?;
//! println!("{}", report.ascii_curve());
//! ```

pub mod metrics;
pub mod curve;
pub mod bias;
pub mod report;
pub mod queries;
pub mod bounds;
pub mod pac_bayes;
pub mod trend;
pub mod tuning;
pub mod empirical_bayes;
pub mod hierarchical;
pub mod ppc;
pub mod validation;

pub use metrics::*;
pub use curve::*;
pub use bias::*;
pub use report::*;
pub use queries::*;
pub use bounds::*;
pub use pac_bayes::*;
pub use validation::*;

use serde::{Deserialize, Serialize};

/// A single calibration observation pairing a prediction with ground truth.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationData {
    /// Predicted probability of abandonment (0.0 to 1.0).
    pub predicted: f64,
    /// Ground truth: was this actually abandoned?
    pub actual: bool,
    /// Optional process type/category for stratified analysis.
    #[serde(default)]
    pub proc_type: Option<String>,
    /// Optional score (0-100+) for additional analysis.
    #[serde(default)]
    pub score: Option<f64>,
    /// Optional timestamp for time-windowed analysis.
    #[serde(default)]
    pub timestamp: Option<i64>,
    /// Optional host ID for multi-host analysis.
    #[serde(default)]
    pub host_id: Option<String>,
}

impl Default for CalibrationData {
    fn default() -> Self {
        Self {
            predicted: 0.0,
            actual: false,
            proc_type: None,
            score: None,
            timestamp: None,
            host_id: None,
        }
    }
}

/// Calibration quality level based on metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CalibrationQuality {
    /// Excellent calibration (ECE < 0.05, Brier < 0.1)
    Excellent,
    /// Good calibration (ECE < 0.1, Brier < 0.2)
    Good,
    /// Fair calibration (ECE < 0.15, Brier < 0.25)
    Fair,
    /// Poor calibration (ECE >= 0.15 or Brier >= 0.25)
    Poor,
}

impl std::fmt::Display for CalibrationQuality {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CalibrationQuality::Excellent => write!(f, "excellent"),
            CalibrationQuality::Good => write!(f, "good"),
            CalibrationQuality::Fair => write!(f, "fair"),
            CalibrationQuality::Poor => write!(f, "poor"),
        }
    }
}

impl CalibrationQuality {
    /// Determine quality from ECE and Brier score.
    pub fn from_metrics(ece: f64, brier: f64) -> Self {
        if ece < 0.05 && brier < 0.1 {
            CalibrationQuality::Excellent
        } else if ece < 0.1 && brier < 0.2 {
            CalibrationQuality::Good
        } else if ece < 0.15 && brier < 0.25 {
            CalibrationQuality::Fair
        } else {
            CalibrationQuality::Poor
        }
    }
}

/// Error type for calibration operations.
#[derive(Debug, Clone)]
pub enum CalibrationError {
    /// No data provided for analysis.
    NoData,
    /// Insufficient labeled data for reliable metrics.
    InsufficientData { count: usize, min_required: usize },
    /// Invalid probability value (outside [0,1]).
    InvalidProbability(f64),
    /// IO error (for report generation).
    IoError(String),
}

impl std::fmt::Display for CalibrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CalibrationError::NoData => write!(f, "No calibration data provided"),
            CalibrationError::InsufficientData { count, min_required } => {
                write!(
                    f,
                    "Insufficient data: {} samples (minimum {} required)",
                    count, min_required
                )
            }
            CalibrationError::InvalidProbability(p) => {
                write!(f, "Invalid probability value: {} (must be in [0,1])", p)
            }
            CalibrationError::IoError(msg) => write!(f, "IO error: {}", msg),
        }
    }
}

impl std::error::Error for CalibrationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calibration_quality_levels() {
        assert_eq!(
            CalibrationQuality::from_metrics(0.03, 0.08),
            CalibrationQuality::Excellent
        );
        assert_eq!(
            CalibrationQuality::from_metrics(0.08, 0.15),
            CalibrationQuality::Good
        );
        assert_eq!(
            CalibrationQuality::from_metrics(0.12, 0.22),
            CalibrationQuality::Fair
        );
        assert_eq!(
            CalibrationQuality::from_metrics(0.20, 0.30),
            CalibrationQuality::Poor
        );
    }

    #[test]
    fn test_calibration_data_default() {
        let data = CalibrationData::default();
        assert_eq!(data.predicted, 0.0);
        assert!(!data.actual);
        assert!(data.proc_type.is_none());
    }
}
