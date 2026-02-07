//! Calibration curve generation.
//!
//! Generates reliability diagrams and calibration curves for visualization.

use super::CalibrationData;
use serde::{Deserialize, Serialize};

/// A single point on a calibration curve.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationBin {
    /// Bin lower bound (inclusive).
    pub lower: f64,
    /// Bin upper bound (exclusive, except last bin).
    pub upper: f64,
    /// Mean predicted probability in this bin.
    pub mean_predicted: f64,
    /// Actual positive rate in this bin.
    pub actual_rate: f64,
    /// Number of samples in this bin.
    pub count: usize,
    /// Calibration error for this bin.
    pub error: f64,
}

/// A calibration curve (reliability diagram data).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationCurve {
    /// Number of bins used.
    pub num_bins: usize,
    /// The bins.
    pub bins: Vec<CalibrationBin>,
    /// Overall ECE.
    pub ece: f64,
    /// Overall MCE.
    pub mce: f64,
}

impl CalibrationCurve {
    /// Generate a calibration curve from data.
    pub fn from_data(data: &[CalibrationData], num_bins: usize) -> Self {
        let num_bins = num_bins.max(1);
        let bin_width = 1.0 / num_bins as f64;

        let mut bins: Vec<Vec<&CalibrationData>> = vec![Vec::new(); num_bins];

        // Assign to bins
        for d in data {
            let bin_idx = ((d.predicted / bin_width) as usize).min(num_bins - 1);
            bins[bin_idx].push(d);
        }

        let n = data.len() as f64;
        let mut ece = 0.0;
        let mut mce = 0.0f64;

        let curve_bins: Vec<CalibrationBin> = bins
            .into_iter()
            .enumerate()
            .map(|(i, bin)| {
                let lower = i as f64 * bin_width;
                let upper = (i + 1) as f64 * bin_width;
                let count = bin.len();

                if count == 0 {
                    CalibrationBin {
                        lower,
                        upper,
                        mean_predicted: (lower + upper) / 2.0,
                        actual_rate: 0.0,
                        count: 0,
                        error: 0.0,
                    }
                } else {
                    let mean_predicted: f64 =
                        bin.iter().map(|d| d.predicted).sum::<f64>() / count as f64;
                    let actual_rate: f64 =
                        bin.iter().filter(|d| d.actual).count() as f64 / count as f64;
                    let error = (mean_predicted - actual_rate).abs();

                    // Update ECE and MCE
                    ece += (count as f64 / n) * error;
                    mce = mce.max(error);

                    CalibrationBin {
                        lower,
                        upper,
                        mean_predicted,
                        actual_rate,
                        count,
                        error,
                    }
                }
            })
            .collect();

        CalibrationCurve {
            num_bins,
            bins: curve_bins,
            ece,
            mce,
        }
    }

    /// Generate ASCII representation of the calibration curve.
    pub fn ascii_curve(&self, width: usize, height: usize) -> String {
        let mut output = String::new();

        // Header
        output.push_str(&format!(
            "Calibration Curve (ECE={:.4}, MCE={:.4})\n",
            self.ece, self.mce
        ));
        output.push_str(&"─".repeat(width + 4));
        output.push('\n');

        // Create grid
        let mut grid = vec![vec![' '; width]; height];

        // Draw diagonal (perfect calibration)
        #[allow(clippy::needless_range_loop)]
        for i in 0..width.min(height) {
            let y = height - 1 - (i * height / width);
            if y < height {
                grid[y][i] = '·';
            }
        }

        // Plot actual data points
        for bin in &self.bins {
            if bin.count == 0 {
                continue;
            }
            let x = ((bin.mean_predicted * (width - 1) as f64) as usize).min(width - 1);
            let y = height - 1 - ((bin.actual_rate * (height - 1) as f64) as usize).min(height - 1);
            grid[y][x] = '●';
        }

        // Render grid with Y-axis
        for (i, row) in grid.iter().enumerate() {
            let y_val = 1.0 - (i as f64 / (height - 1) as f64);
            output.push_str(&format!("{:.1}│", y_val));
            for c in row {
                output.push(*c);
            }
            output.push('\n');
        }

        // X-axis
        output.push_str("   └");
        output.push_str(&"─".repeat(width));
        output.push('\n');
        output.push_str("    0");
        output.push_str(&" ".repeat(width / 2 - 2));
        output.push_str("0.5");
        output.push_str(&" ".repeat(width / 2 - 2));
        output.push_str("1.0\n");
        output.push_str("          Predicted Probability\n");

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calibration_curve_generation() {
        let data: Vec<CalibrationData> = (0..100)
            .map(|i| {
                let p = i as f64 / 100.0;
                CalibrationData {
                    predicted: p,
                    actual: p > 0.5,
                    ..Default::default()
                }
            })
            .collect();

        let curve = CalibrationCurve::from_data(&data, 10);
        assert_eq!(curve.num_bins, 10);
        assert_eq!(curve.bins.len(), 10);
    }

    #[test]
    fn test_ascii_output() {
        let data: Vec<CalibrationData> = vec![
            CalibrationData {
                predicted: 0.1,
                actual: false,
                ..Default::default()
            },
            CalibrationData {
                predicted: 0.9,
                actual: true,
                ..Default::default()
            },
        ];
        let curve = CalibrationCurve::from_data(&data, 10);
        let ascii = curve.ascii_curve(40, 10);
        assert!(!ascii.is_empty());
        assert!(ascii.contains("Calibration Curve"));
    }

    // ── CalibrationBin ────────────────────────────────────────────────

    #[test]
    fn bin_serde_roundtrip() {
        let bin = CalibrationBin {
            lower: 0.0,
            upper: 0.1,
            mean_predicted: 0.05,
            actual_rate: 0.0,
            count: 10,
            error: 0.05,
        };
        let json = serde_json::to_string(&bin).unwrap();
        let back: CalibrationBin = serde_json::from_str(&json).unwrap();
        assert_eq!(back.count, 10);
        assert!((back.error - 0.05).abs() < 1e-9);
    }

    // ── from_data edge cases ──────────────────────────────────────────

    #[test]
    fn empty_data_yields_empty_bins() {
        let curve = CalibrationCurve::from_data(&[], 5);
        assert_eq!(curve.num_bins, 5);
        assert_eq!(curve.bins.len(), 5);
        for bin in &curve.bins {
            assert_eq!(bin.count, 0);
            assert_eq!(bin.error, 0.0);
        }
        assert_eq!(curve.ece, 0.0);
        assert_eq!(curve.mce, 0.0);
    }

    #[test]
    fn single_sample() {
        let data = vec![CalibrationData {
            predicted: 0.7,
            actual: true,
            ..Default::default()
        }];
        let curve = CalibrationCurve::from_data(&data, 10);
        let occupied: Vec<_> = curve.bins.iter().filter(|b| b.count > 0).collect();
        assert_eq!(occupied.len(), 1);
        assert_eq!(occupied[0].count, 1);
        assert!((occupied[0].actual_rate - 1.0).abs() < 1e-9);
    }

    #[test]
    fn num_bins_clamped_to_one() {
        let data = vec![CalibrationData {
            predicted: 0.5,
            actual: true,
            ..Default::default()
        }];
        let curve = CalibrationCurve::from_data(&data, 0);
        assert_eq!(curve.num_bins, 1);
        assert_eq!(curve.bins.len(), 1);
    }

    #[test]
    fn perfectly_calibrated_ece_zero() {
        // All samples predicted 0.5, half are true — well-calibrated
        let mut data = Vec::new();
        for i in 0..100 {
            data.push(CalibrationData {
                predicted: 0.5,
                actual: i < 50,
                ..Default::default()
            });
        }
        let curve = CalibrationCurve::from_data(&data, 10);
        // All samples in one bin; mean_predicted ~ 0.5, actual_rate ~ 0.5
        assert!(curve.ece < 0.01, "ECE should be near-zero: {}", curve.ece);
    }

    #[test]
    fn completely_miscalibrated_high_ece() {
        // Predict 0.9 but actual rate = 0%
        let data: Vec<CalibrationData> = (0..50)
            .map(|_| CalibrationData {
                predicted: 0.9,
                actual: false,
                ..Default::default()
            })
            .collect();
        let curve = CalibrationCurve::from_data(&data, 10);
        assert!(curve.ece > 0.5, "ECE should be high: {}", curve.ece);
        assert!(curve.mce > 0.5, "MCE should be high: {}", curve.mce);
    }

    #[test]
    fn mce_is_max_bin_error() {
        // Two groups: well-calibrated low + badly calibrated high
        let mut data = Vec::new();
        // Well-calibrated: predict 0.1, actual 10%
        for i in 0..100 {
            data.push(CalibrationData {
                predicted: 0.1,
                actual: i < 10,
                ..Default::default()
            });
        }
        // Badly calibrated: predict 0.9, actual 0%
        for _ in 0..20 {
            data.push(CalibrationData {
                predicted: 0.9,
                actual: false,
                ..Default::default()
            });
        }
        let curve = CalibrationCurve::from_data(&data, 10);
        // MCE should reflect the bad bin (~0.9 error)
        assert!(curve.mce > 0.7, "MCE should reflect bad bin: {}", curve.mce);
        // ECE should be moderate (weighted by bin size)
        assert!(curve.ece > 0.0);
    }

    #[test]
    fn bins_cover_full_range() {
        let data: Vec<CalibrationData> = (0..100)
            .map(|i| CalibrationData {
                predicted: i as f64 / 100.0,
                actual: i > 50,
                ..Default::default()
            })
            .collect();
        let curve = CalibrationCurve::from_data(&data, 10);
        // First bin starts at 0, last bin ends at 1.0
        assert!((curve.bins[0].lower - 0.0).abs() < 1e-9);
        assert!((curve.bins[9].upper - 1.0).abs() < 1e-9);
    }

    #[test]
    fn bins_non_overlapping() {
        let data = vec![CalibrationData {
            predicted: 0.5,
            actual: true,
            ..Default::default()
        }];
        let curve = CalibrationCurve::from_data(&data, 5);
        for i in 1..curve.bins.len() {
            assert!(
                (curve.bins[i].lower - curve.bins[i - 1].upper).abs() < 1e-9,
                "bins should be contiguous"
            );
        }
    }

    // ── CalibrationCurve serde ────────────────────────────────────────

    #[test]
    fn curve_serde_roundtrip() {
        let data: Vec<CalibrationData> = (0..50)
            .map(|i| CalibrationData {
                predicted: i as f64 / 50.0,
                actual: i > 25,
                ..Default::default()
            })
            .collect();
        let curve = CalibrationCurve::from_data(&data, 5);
        let json = serde_json::to_string(&curve).unwrap();
        let back: CalibrationCurve = serde_json::from_str(&json).unwrap();
        assert_eq!(back.num_bins, 5);
        assert_eq!(back.bins.len(), 5);
        assert!((back.ece - curve.ece).abs() < 1e-9);
    }

    // ── ascii_curve format ────────────────────────────────────────────

    #[test]
    fn ascii_curve_contains_ece_mce() {
        let data = vec![CalibrationData {
            predicted: 0.5,
            actual: true,
            ..Default::default()
        }];
        let curve = CalibrationCurve::from_data(&data, 5);
        let ascii = curve.ascii_curve(30, 8);
        assert!(ascii.contains("ECE="));
        assert!(ascii.contains("MCE="));
    }

    #[test]
    fn ascii_curve_contains_axis_labels() {
        let data = vec![CalibrationData {
            predicted: 0.5,
            actual: true,
            ..Default::default()
        }];
        let curve = CalibrationCurve::from_data(&data, 5);
        let ascii = curve.ascii_curve(30, 8);
        assert!(ascii.contains("Predicted Probability"));
    }
}
