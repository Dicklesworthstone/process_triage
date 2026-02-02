//! Generic time-to-threshold prediction with uncertainty intervals.
//!
//! Shared utility for computing "when will metric X exceed threshold T?"
//! from a trend estimate with slope uncertainty. Handles edge cases
//! conservatively and avoids misleading long-horizon forecasts.

use serde::{Deserialize, Serialize};

/// Input for a threshold prediction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdInput {
    /// Current metric value.
    pub current_value: f64,
    /// Estimated slope (units per second).
    pub slope: f64,
    /// Standard error of the slope.
    pub slope_se: f64,
    /// Threshold to predict crossing of.
    pub threshold: f64,
    /// Minimum samples backing the slope estimate.
    pub sample_count: usize,
    /// Minimum samples required for a prediction.
    pub min_samples: usize,
    /// Maximum horizon in seconds (predictions beyond this → capped).
    pub max_horizon_secs: f64,
    /// Confidence level for the interval (e.g., 0.90 for 90%).
    pub confidence_level: f64,
}

impl Default for ThresholdInput {
    fn default() -> Self {
        Self {
            current_value: 0.0,
            slope: 0.0,
            slope_se: 0.0,
            threshold: 1.0,
            sample_count: 0,
            min_samples: 5,
            max_horizon_secs: 30.0 * 86400.0, // 30 days
            confidence_level: 0.90,
        }
    }
}

/// Status of a threshold prediction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThresholdStatus {
    /// Valid prediction produced.
    Ok,
    /// Threshold already exceeded.
    AlreadyExceeded,
    /// Slope uncertainty spans zero; direction ambiguous.
    Unknown,
    /// Trend moves away from threshold (will never reach it).
    Diverging,
    /// Not enough data to produce a reliable prediction.
    InsufficientData,
    /// ETA exceeds maximum horizon.
    BeyondHorizon,
}

impl std::fmt::Display for ThresholdStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ok => write!(f, "ok"),
            Self::AlreadyExceeded => write!(f, "already_exceeded"),
            Self::Unknown => write!(f, "unknown"),
            Self::Diverging => write!(f, "diverging"),
            Self::InsufficientData => write!(f, "insufficient_data"),
            Self::BeyondHorizon => write!(f, "beyond_horizon"),
        }
    }
}

/// Result of a threshold prediction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdPrediction {
    /// Status code.
    pub status: ThresholdStatus,
    /// Point estimate of seconds until threshold (None if not Ok).
    pub eta_secs: Option<f64>,
    /// Lower bound of the ETA interval (optimistic / sooner).
    pub eta_low_secs: Option<f64>,
    /// Upper bound of the ETA interval (pessimistic / later).
    pub eta_high_secs: Option<f64>,
    /// The confidence level used.
    pub confidence_level: f64,
    /// Human-readable summary.
    pub summary: String,
}

/// Z-scores for common confidence levels.
fn z_for_confidence(level: f64) -> f64 {
    // Approximate; covers common cases.
    if level >= 0.99 {
        2.576
    } else if level >= 0.95 {
        1.960
    } else if level >= 0.90 {
        1.645
    } else if level >= 0.80 {
        1.282
    } else {
        1.0
    }
}

/// Predict time to threshold crossing.
///
/// Uses linear extrapolation: eta = (threshold - current) / slope,
/// with interval derived from slope ± z * slope_se.
pub fn predict_threshold(input: &ThresholdInput) -> ThresholdPrediction {
    let cl = input.confidence_level;

    // Insufficient data check.
    if input.sample_count < input.min_samples {
        return ThresholdPrediction {
            status: ThresholdStatus::InsufficientData,
            eta_secs: None,
            eta_low_secs: None,
            eta_high_secs: None,
            confidence_level: cl,
            summary: format!(
                "Insufficient data: {} samples (need {})",
                input.sample_count, input.min_samples
            ),
        };
    }

    let gap = input.threshold - input.current_value;

    // Already exceeded?
    if gap <= 0.0 {
        return ThresholdPrediction {
            status: ThresholdStatus::AlreadyExceeded,
            eta_secs: Some(0.0),
            eta_low_secs: Some(0.0),
            eta_high_secs: Some(0.0),
            confidence_level: cl,
            summary: format!(
                "Already at {:.4}, threshold {:.4} exceeded",
                input.current_value, input.threshold
            ),
        };
    }

    let z = z_for_confidence(cl);
    let slope_low = input.slope - z * input.slope_se;
    let slope_high = input.slope + z * input.slope_se;

    // If slope interval spans zero, direction is ambiguous.
    if slope_low <= 0.0 && slope_high >= 0.0 {
        return ThresholdPrediction {
            status: ThresholdStatus::Unknown,
            eta_secs: None,
            eta_low_secs: None,
            eta_high_secs: None,
            confidence_level: cl,
            summary: "Trend direction ambiguous (slope CI spans zero)".to_string(),
        };
    }

    // Slope is entirely negative → diverging from threshold.
    if input.slope <= 0.0 {
        return ThresholdPrediction {
            status: ThresholdStatus::Diverging,
            eta_secs: None,
            eta_low_secs: None,
            eta_high_secs: None,
            confidence_level: cl,
            summary: "Trend moves away from threshold".to_string(),
        };
    }

    // Point estimate.
    let eta = gap / input.slope;

    // Interval: faster arrival with high slope, slower with low slope.
    // slope_high > slope_low > 0 at this point.
    let eta_low = gap / slope_high; // Optimistic (sooner).
    let eta_high = if slope_low > 0.0 {
        gap / slope_low // Pessimistic (later).
    } else {
        input.max_horizon_secs // Capped.
    };

    // Beyond horizon?
    if eta > input.max_horizon_secs {
        return ThresholdPrediction {
            status: ThresholdStatus::BeyondHorizon,
            eta_secs: Some(eta),
            eta_low_secs: Some(eta_low),
            eta_high_secs: Some(eta_high.min(input.max_horizon_secs)),
            confidence_level: cl,
            summary: format!(
                "ETA {:.0}s exceeds {:.0}s horizon",
                eta, input.max_horizon_secs
            ),
        };
    }

    ThresholdPrediction {
        status: ThresholdStatus::Ok,
        eta_secs: Some(eta),
        eta_low_secs: Some(eta_low),
        eta_high_secs: Some(eta_high.min(input.max_horizon_secs)),
        confidence_level: cl,
        summary: format!(
            "ETA {:.0}s [{:.0}s, {:.0}s] at {:.0}% confidence",
            eta,
            eta_low,
            eta_high.min(input.max_horizon_secs),
            cl * 100.0
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_prediction() {
        let input = ThresholdInput {
            current_value: 100.0,
            slope: 10.0,
            slope_se: 1.0,
            threshold: 200.0,
            sample_count: 20,
            ..Default::default()
        };
        let pred = predict_threshold(&input);
        assert_eq!(pred.status, ThresholdStatus::Ok);
        assert!((pred.eta_secs.unwrap() - 10.0).abs() < 0.01); // 100/10 = 10s
        assert!(pred.eta_low_secs.unwrap() < pred.eta_secs.unwrap());
        assert!(pred.eta_high_secs.unwrap() > pred.eta_secs.unwrap());
    }

    #[test]
    fn test_already_exceeded() {
        let input = ThresholdInput {
            current_value: 250.0,
            slope: 10.0,
            slope_se: 1.0,
            threshold: 200.0,
            sample_count: 20,
            ..Default::default()
        };
        let pred = predict_threshold(&input);
        assert_eq!(pred.status, ThresholdStatus::AlreadyExceeded);
        assert_eq!(pred.eta_secs, Some(0.0));
    }

    #[test]
    fn test_diverging() {
        let input = ThresholdInput {
            current_value: 100.0,
            slope: -5.0,
            slope_se: 0.1,
            threshold: 200.0,
            sample_count: 20,
            ..Default::default()
        };
        let pred = predict_threshold(&input);
        assert_eq!(pred.status, ThresholdStatus::Diverging);
        assert!(pred.eta_secs.is_none());
    }

    #[test]
    fn test_ambiguous_slope() {
        let input = ThresholdInput {
            current_value: 100.0,
            slope: 0.5,
            slope_se: 2.0, // CI spans zero.
            threshold: 200.0,
            sample_count: 20,
            ..Default::default()
        };
        let pred = predict_threshold(&input);
        assert_eq!(pred.status, ThresholdStatus::Unknown);
    }

    #[test]
    fn test_insufficient_data() {
        let input = ThresholdInput {
            current_value: 100.0,
            slope: 10.0,
            slope_se: 1.0,
            threshold: 200.0,
            sample_count: 2,
            min_samples: 5,
            ..Default::default()
        };
        let pred = predict_threshold(&input);
        assert_eq!(pred.status, ThresholdStatus::InsufficientData);
    }

    #[test]
    fn test_beyond_horizon() {
        let input = ThresholdInput {
            current_value: 100.0,
            slope: 0.001,
            slope_se: 0.0001,
            threshold: 200.0,
            sample_count: 20,
            max_horizon_secs: 1000.0,
            ..Default::default()
        };
        let pred = predict_threshold(&input);
        assert_eq!(pred.status, ThresholdStatus::BeyondHorizon);
        // eta = 100/0.001 = 100_000s > 1000s horizon
        assert!(pred.eta_secs.unwrap() > 1000.0);
    }

    #[test]
    fn test_deterministic() {
        let input = ThresholdInput {
            current_value: 50.0,
            slope: 5.0,
            slope_se: 0.5,
            threshold: 100.0,
            sample_count: 30,
            ..Default::default()
        };
        let p1 = predict_threshold(&input);
        let p2 = predict_threshold(&input);
        assert_eq!(p1.eta_secs, p2.eta_secs);
        assert_eq!(p1.eta_low_secs, p2.eta_low_secs);
        assert_eq!(p1.eta_high_secs, p2.eta_high_secs);
    }

    #[test]
    fn test_zero_se_gives_point_interval() {
        let input = ThresholdInput {
            current_value: 0.0,
            slope: 1.0,
            slope_se: 0.0,
            threshold: 100.0,
            sample_count: 20,
            ..Default::default()
        };
        let pred = predict_threshold(&input);
        assert_eq!(pred.status, ThresholdStatus::Ok);
        assert!((pred.eta_secs.unwrap() - 100.0).abs() < 0.01);
        // With SE=0, low and high should equal point estimate.
        assert!((pred.eta_low_secs.unwrap() - 100.0).abs() < 0.01);
        assert!((pred.eta_high_secs.unwrap() - 100.0).abs() < 0.01);
    }

    #[test]
    fn test_confidence_level_affects_interval() {
        let base = ThresholdInput {
            current_value: 50.0,
            slope: 5.0,
            slope_se: 1.0,
            threshold: 100.0,
            sample_count: 30,
            ..Default::default()
        };

        let narrow = predict_threshold(&ThresholdInput {
            confidence_level: 0.80,
            ..base.clone()
        });
        let wide = predict_threshold(&ThresholdInput {
            confidence_level: 0.99,
            ..base.clone()
        });

        // Wider confidence → wider interval (higher eta_high).
        assert!(
            wide.eta_high_secs.unwrap() >= narrow.eta_high_secs.unwrap(),
            "99% interval should be wider than 80%"
        );
    }
}
