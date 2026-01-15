//! Bayes factor utilities for evidence computation and explainability.
//!
//! This module provides unified utilities for working with Bayes factors across
//! all model families in pt-math. It supports:
//! - Converting log Bayes factors to e-values (overflow-safe)
//! - Computing evidence in bits for MDL interpretation
//! - Evidence strength labeling (Jeffreys scale)
//!
//! # Background
//!
//! A Bayes factor BF_{1,0} = P(data|H1) / P(data|H0) measures the relative
//! evidence for H1 vs H0. In log domain: log_bf = log P(data|H1) - log P(data|H0).
//!
//! The Bayes factor can serve as an e-value for sequential testing:
//! under H0, E[BF] = 1, enabling optional stopping and FDR control.

/// Maximum log Bayes factor before clamping to avoid overflow.
/// exp(709) ≈ 8.2e307 is near f64::MAX.
pub const LOG_BF_MAX: f64 = 700.0;

/// Minimum log Bayes factor before clamping to avoid underflow.
pub const LOG_BF_MIN: f64 = -700.0;

/// Convert log Bayes factor to e-value with overflow-safe handling.
///
/// An e-value is a non-negative random variable with E[e] <= 1 under the null.
/// Bayes factors are valid e-values, allowing optional stopping and
/// e-value based FDR control.
///
/// # Overflow handling
/// - Clamps log_bf to [LOG_BF_MIN, LOG_BF_MAX] before exponentiation
/// - Returns 0.0 for log_bf = -inf
/// - Returns f64::MAX for log_bf = +inf (capped)
///
/// # Arguments
/// * `log_bf` - Log Bayes factor (can be any real number or ±inf)
///
/// # Returns
/// e-value in [0, exp(LOG_BF_MAX)] or NaN if input is NaN
pub fn e_value_from_log_bf(log_bf: f64) -> f64 {
    if log_bf.is_nan() {
        return f64::NAN;
    }
    if log_bf == f64::NEG_INFINITY {
        return 0.0;
    }
    if log_bf == f64::INFINITY {
        return f64::MAX;
    }

    // Clamp to safe range and exponentiate
    let clamped = log_bf.clamp(LOG_BF_MIN, LOG_BF_MAX);
    clamped.exp()
}

/// Convert log Bayes factor to e-value, returning None if overflow would occur.
///
/// This is a stricter version that signals when the e-value would be
/// unreliable due to extreme log_bf values.
///
/// # Returns
/// - Some(e_value) if |log_bf| <= LOG_BF_MAX
/// - None if |log_bf| > LOG_BF_MAX (would overflow/underflow)
/// - None if log_bf is NaN
pub fn try_e_value_from_log_bf(log_bf: f64) -> Option<f64> {
    if log_bf.is_nan() || log_bf.abs() > LOG_BF_MAX {
        return None;
    }
    Some(log_bf.exp())
}

/// Convert log Bayes factor to evidence in bits (MDL interpretation).
///
/// In the MDL (Minimum Description Length) interpretation:
/// - ΔL = L(data|H0) - L(data|H1) = log_bf / ln(2)
/// - Positive ΔL: H1 compresses data better by ΔL bits
/// - Negative ΔL: H0 compresses data better by |ΔL| bits
///
/// # Arguments
/// * `log_bf` - Log Bayes factor in nats (natural log units)
///
/// # Returns
/// Evidence in bits (log base 2). Returns NaN if input is NaN.
pub fn delta_bits(log_bf: f64) -> f64 {
    if log_bf.is_nan() {
        return f64::NAN;
    }
    log_bf / std::f64::consts::LN_2
}

/// Evidence strength on the Jeffreys scale.
///
/// Provides a human-readable interpretation of |log_bf|.
/// Note: The raw log_bf is always preserved for computations;
/// labels are for presentation only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceStrength {
    /// |log_bf| < ln(1) = 0: No evidence
    None,
    /// ln(1) <= |log_bf| < ln(3.2) ≈ 1.16: Barely worth mentioning
    Anecdotal,
    /// ln(3.2) <= |log_bf| < ln(10) ≈ 2.30: Substantial
    Substantial,
    /// ln(10) <= |log_bf| < ln(32) ≈ 3.47: Strong
    Strong,
    /// ln(32) <= |log_bf| < ln(100) ≈ 4.61: Very strong
    VeryStrong,
    /// |log_bf| >= ln(100) ≈ 4.61: Decisive
    Decisive,
}

impl EvidenceStrength {
    /// Classify evidence strength from log Bayes factor.
    ///
    /// Uses absolute value of log_bf; direction is determined separately
    /// by the sign of log_bf.
    pub fn from_log_bf(log_bf: f64) -> Self {
        if log_bf.is_nan() {
            return EvidenceStrength::None;
        }

        let abs_log_bf = log_bf.abs();

        // Jeffreys scale thresholds (in nats)
        const LN_3_2: f64 = 1.163_150_809_678_64; // ln(3.2)
        const LN_32: f64 = 3.465_735_902_799_727;  // ln(32)
        const LN_100: f64 = 4.605_170_185_988_092; // ln(100)
        let ln_10 = std::f64::consts::LN_10;

        if abs_log_bf < LN_3_2 {
            if abs_log_bf < f64::EPSILON {
                EvidenceStrength::None
            } else {
                EvidenceStrength::Anecdotal
            }
        } else if abs_log_bf < ln_10 {
            EvidenceStrength::Substantial
        } else if abs_log_bf < LN_32 {
            EvidenceStrength::Strong
        } else if abs_log_bf < LN_100 {
            EvidenceStrength::VeryStrong
        } else {
            EvidenceStrength::Decisive
        }
    }

    /// Return a short label for display.
    pub fn label(&self) -> &'static str {
        match self {
            EvidenceStrength::None => "none",
            EvidenceStrength::Anecdotal => "anecdotal",
            EvidenceStrength::Substantial => "substantial",
            EvidenceStrength::Strong => "strong",
            EvidenceStrength::VeryStrong => "very strong",
            EvidenceStrength::Decisive => "decisive",
        }
    }
}

impl std::fmt::Display for EvidenceStrength {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Direction of evidence (which hypothesis is favored).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceDirection {
    /// log_bf > 0: Evidence favors H1
    FavorsH1,
    /// log_bf < 0: Evidence favors H0
    FavorsH0,
    /// log_bf = 0: Neutral (no preference)
    Neutral,
}

impl EvidenceDirection {
    /// Determine direction from log Bayes factor.
    pub fn from_log_bf(log_bf: f64) -> Self {
        if log_bf.is_nan() || log_bf.abs() < f64::EPSILON {
            EvidenceDirection::Neutral
        } else if log_bf > 0.0 {
            EvidenceDirection::FavorsH1
        } else {
            EvidenceDirection::FavorsH0
        }
    }
}

/// Complete evidence summary for a Bayes factor computation.
///
/// This struct packages all the information needed for evidence ledger
/// attribution and galaxy-brain explainability.
#[derive(Debug, Clone)]
pub struct EvidenceSummary {
    /// Log Bayes factor in nats (raw value, always preserved).
    pub log_bf: f64,
    /// E-value (exp(log_bf), clamped for safety).
    pub e_value: f64,
    /// Evidence in bits (ΔL for MDL interpretation).
    pub delta_bits: f64,
    /// Evidence strength on Jeffreys scale.
    pub strength: EvidenceStrength,
    /// Which hypothesis is favored.
    pub direction: EvidenceDirection,
}

impl EvidenceSummary {
    /// Create an evidence summary from a log Bayes factor.
    pub fn from_log_bf(log_bf: f64) -> Self {
        EvidenceSummary {
            log_bf,
            e_value: e_value_from_log_bf(log_bf),
            delta_bits: delta_bits(log_bf),
            strength: EvidenceStrength::from_log_bf(log_bf),
            direction: EvidenceDirection::from_log_bf(log_bf),
        }
    }

    /// Check if evidence is significant at the given strength threshold.
    pub fn is_significant(&self, min_strength: EvidenceStrength) -> bool {
        self.strength as u8 >= min_strength as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx_eq(a: f64, b: f64, tol: f64) -> bool {
        if a.is_nan() && b.is_nan() {
            return true;
        }
        if a.is_nan() || b.is_nan() {
            return false;
        }
        (a - b).abs() <= tol
    }

    // =======================================================================
    // e_value_from_log_bf tests
    // =======================================================================

    #[test]
    fn e_value_zero_log_bf() {
        // BF = 1 when log_bf = 0
        let e = e_value_from_log_bf(0.0);
        assert!(approx_eq(e, 1.0, 1e-12));
    }

    #[test]
    fn e_value_positive_log_bf() {
        // log_bf = ln(10) => e = 10
        let log_bf = 10.0f64.ln();
        let e = e_value_from_log_bf(log_bf);
        assert!(approx_eq(e, 10.0, 1e-10));
    }

    #[test]
    fn e_value_negative_log_bf() {
        // log_bf = -ln(2) => e = 0.5
        let log_bf = -2.0f64.ln();
        let e = e_value_from_log_bf(log_bf);
        assert!(approx_eq(e, 0.5, 1e-12));
    }

    #[test]
    fn e_value_overflow_clamped() {
        // Very large positive log_bf should not overflow
        let e = e_value_from_log_bf(1000.0);
        assert!(e.is_finite());
        assert!(e > 1e300);
    }

    #[test]
    fn e_value_underflow_to_zero() {
        // Very negative log_bf should clamp near zero, not underflow
        let e = e_value_from_log_bf(-1000.0);
        assert!(e >= 0.0);
        assert!(e < 1e-300);
    }

    #[test]
    fn e_value_neg_infinity() {
        let e = e_value_from_log_bf(f64::NEG_INFINITY);
        assert!(approx_eq(e, 0.0, 1e-12));
    }

    #[test]
    fn e_value_pos_infinity() {
        let e = e_value_from_log_bf(f64::INFINITY);
        assert_eq!(e, f64::MAX);
    }

    #[test]
    fn e_value_nan() {
        let e = e_value_from_log_bf(f64::NAN);
        assert!(e.is_nan());
    }

    // =======================================================================
    // try_e_value_from_log_bf tests
    // =======================================================================

    #[test]
    fn try_e_value_normal() {
        let e = try_e_value_from_log_bf(2.0);
        assert!(e.is_some());
        assert!(approx_eq(e.unwrap(), 2.0f64.exp(), 1e-12));
    }

    #[test]
    fn try_e_value_overflow_returns_none() {
        assert!(try_e_value_from_log_bf(800.0).is_none());
        assert!(try_e_value_from_log_bf(-800.0).is_none());
    }

    #[test]
    fn try_e_value_nan_returns_none() {
        assert!(try_e_value_from_log_bf(f64::NAN).is_none());
    }

    // =======================================================================
    // delta_bits tests
    // =======================================================================

    #[test]
    fn delta_bits_zero() {
        let bits = delta_bits(0.0);
        assert!(approx_eq(bits, 0.0, 1e-12));
    }

    #[test]
    fn delta_bits_one_nat() {
        // 1 nat = 1/ln(2) ≈ 1.443 bits
        let bits = delta_bits(1.0);
        assert!(approx_eq(bits, 1.0 / std::f64::consts::LN_2, 1e-10));
    }

    #[test]
    fn delta_bits_ln_2() {
        // ln(2) nats = 1 bit exactly
        let bits = delta_bits(std::f64::consts::LN_2);
        assert!(approx_eq(bits, 1.0, 1e-12));
    }

    #[test]
    fn delta_bits_negative() {
        let bits = delta_bits(-std::f64::consts::LN_2);
        assert!(approx_eq(bits, -1.0, 1e-12));
    }

    #[test]
    fn delta_bits_nan() {
        let bits = delta_bits(f64::NAN);
        assert!(bits.is_nan());
    }

    // =======================================================================
    // EvidenceStrength tests
    // =======================================================================

    #[test]
    fn evidence_strength_none() {
        let s = EvidenceStrength::from_log_bf(0.0);
        assert_eq!(s, EvidenceStrength::None);
    }

    #[test]
    fn evidence_strength_anecdotal() {
        // ln(2) ≈ 0.69 < ln(3.2) ≈ 1.16
        let s = EvidenceStrength::from_log_bf(0.69);
        assert_eq!(s, EvidenceStrength::Anecdotal);
    }

    #[test]
    fn evidence_strength_substantial() {
        // ln(5) ≈ 1.61: between ln(3.2) and ln(10)
        let s = EvidenceStrength::from_log_bf(5.0f64.ln());
        assert_eq!(s, EvidenceStrength::Substantial);
    }

    #[test]
    fn evidence_strength_strong() {
        // ln(15) ≈ 2.71: between ln(10) and ln(32)
        let s = EvidenceStrength::from_log_bf(15.0f64.ln());
        assert_eq!(s, EvidenceStrength::Strong);
    }

    #[test]
    fn evidence_strength_very_strong() {
        // ln(50) ≈ 3.91: between ln(32) and ln(100)
        let s = EvidenceStrength::from_log_bf(50.0f64.ln());
        assert_eq!(s, EvidenceStrength::VeryStrong);
    }

    #[test]
    fn evidence_strength_decisive() {
        // ln(1000) ≈ 6.91 > ln(100)
        let s = EvidenceStrength::from_log_bf(1000.0f64.ln());
        assert_eq!(s, EvidenceStrength::Decisive);
    }

    #[test]
    fn evidence_strength_uses_absolute_value() {
        // Negative log_bf should give same strength
        let s_pos = EvidenceStrength::from_log_bf(100.0f64.ln());
        let s_neg = EvidenceStrength::from_log_bf(-100.0f64.ln());
        assert_eq!(s_pos, s_neg);
    }

    #[test]
    fn evidence_strength_label() {
        assert_eq!(EvidenceStrength::Decisive.label(), "decisive");
        assert_eq!(EvidenceStrength::Strong.label(), "strong");
    }

    // =======================================================================
    // EvidenceDirection tests
    // =======================================================================

    #[test]
    fn evidence_direction_favors_h1() {
        let d = EvidenceDirection::from_log_bf(1.0);
        assert_eq!(d, EvidenceDirection::FavorsH1);
    }

    #[test]
    fn evidence_direction_favors_h0() {
        let d = EvidenceDirection::from_log_bf(-1.0);
        assert_eq!(d, EvidenceDirection::FavorsH0);
    }

    #[test]
    fn evidence_direction_neutral() {
        let d = EvidenceDirection::from_log_bf(0.0);
        assert_eq!(d, EvidenceDirection::Neutral);
    }

    // =======================================================================
    // EvidenceSummary tests
    // =======================================================================

    #[test]
    fn evidence_summary_positive() {
        let log_bf = 100.0f64.ln(); // ~4.6
        let summary = EvidenceSummary::from_log_bf(log_bf);

        assert!(approx_eq(summary.log_bf, log_bf, 1e-12));
        assert!(approx_eq(summary.e_value, 100.0, 1e-10));
        assert!(summary.delta_bits > 6.0); // ~6.6 bits
        assert_eq!(summary.strength, EvidenceStrength::Decisive);
        assert_eq!(summary.direction, EvidenceDirection::FavorsH1);
    }

    #[test]
    fn evidence_summary_negative() {
        let log_bf = -10.0f64.ln(); // ~-2.3
        let summary = EvidenceSummary::from_log_bf(log_bf);

        assert!(approx_eq(summary.e_value, 0.1, 1e-10));
        assert!(summary.delta_bits < -3.0); // ~-3.3 bits
        assert_eq!(summary.strength, EvidenceStrength::Strong);
        assert_eq!(summary.direction, EvidenceDirection::FavorsH0);
    }

    #[test]
    fn evidence_summary_is_significant() {
        let summary = EvidenceSummary::from_log_bf(50.0f64.ln());
        assert!(summary.is_significant(EvidenceStrength::Substantial));
        assert!(summary.is_significant(EvidenceStrength::VeryStrong));
        assert!(!summary.is_significant(EvidenceStrength::Decisive));
    }

    // =======================================================================
    // Symmetry and consistency tests
    // =======================================================================

    #[test]
    fn log_bf_symmetry() {
        // log_bf(H1, H0) = -log_bf(H0, H1)
        let log_bf_12 = 3.0;
        let log_bf_21 = -log_bf_12;

        let e1 = e_value_from_log_bf(log_bf_12);
        let e2 = e_value_from_log_bf(log_bf_21);

        // e1 * e2 = 1
        assert!(approx_eq(e1 * e2, 1.0, 1e-10));
    }

    #[test]
    fn delta_bits_symmetry() {
        let log_bf = 2.5;
        let bits_pos = delta_bits(log_bf);
        let bits_neg = delta_bits(-log_bf);

        assert!(approx_eq(bits_pos, -bits_neg, 1e-12));
    }
}
