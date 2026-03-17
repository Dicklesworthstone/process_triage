//! Log-domain posterior normalization and odds utilities.
//!
//! These helpers turn unnormalized log-probabilities into normalized log posteriors
//! and stable probability vectors. They are intended to be used by pt-core inference
//! so that normalization and odds logic is centralized and numerically robust.

use super::stable::{log_sum_exp, log_sum_exp_array};

/// Normalize a vector of log-probabilities into log posteriors.
///
/// Returns a vector of log-probabilities that sum to 1 in probability space.
pub fn normalize_log_probs(logp: &[f64]) -> Vec<f64> {
    if logp.is_empty() {
        return Vec::new();
    }
    if logp.iter().any(|v| v.is_nan()) {
        return vec![f64::NAN; logp.len()];
    }
    let z = log_sum_exp(logp);
    if z.is_nan() {
        return vec![f64::NAN; logp.len()];
    }
    if z == f64::NEG_INFINITY {
        return vec![f64::NEG_INFINITY; logp.len()];
    }
    logp.iter().map(|v| v - z).collect()
}

/// Zero-allocation normalize for fixed-size arrays.
///
/// Identical semantics to [`normalize_log_probs`] but returns a
/// stack-allocated array, avoiding the per-call `Vec` heap allocation.
/// The 4-class posterior model calls this on every process candidate,
/// so eliminating the allocation is measurable at scale (10K+ processes).
pub fn normalize_log_probs_array<const N: usize>(logp: &[f64; N]) -> [f64; N] {
    if logp.iter().any(|v| v.is_nan()) {
        return [f64::NAN; N];
    }
    let z = log_sum_exp_array(logp);
    if z.is_nan() {
        return [f64::NAN; N];
    }
    if z == f64::NEG_INFINITY {
        return [f64::NEG_INFINITY; N];
    }
    let mut out = [0.0; N];
    for i in 0..N {
        out[i] = logp[i] - z;
    }
    out
}

/// Compute posterior probabilities from normalized log posteriors.
pub fn posterior_probs(log_posterior: &[f64]) -> Vec<f64> {
    if log_posterior.is_empty() {
        return Vec::new();
    }
    if log_posterior.iter().any(|v| v.is_nan()) {
        return vec![f64::NAN; log_posterior.len()];
    }
    log_posterior.iter().map(|v| v.exp()).collect()
}

/// Compute log-odds between two classes from normalized log posteriors.
pub fn log_odds(log_posterior: &[f64], idx_a: usize, idx_b: usize) -> f64 {
    if idx_a >= log_posterior.len() || idx_b >= log_posterior.len() {
        return f64::NAN;
    }
    log_posterior[idx_a] - log_posterior[idx_b]
}

/// Stable softmax returning probabilities directly from log-probabilities.
pub fn stable_softmax(logp: &[f64]) -> Vec<f64> {
    if logp.is_empty() {
        return Vec::new();
    }
    if logp.iter().any(|v| v.is_nan()) {
        return vec![f64::NAN; logp.len()];
    }
    let z = log_sum_exp(logp);
    if z.is_nan() {
        return vec![f64::NAN; logp.len()];
    }
    if z == f64::NEG_INFINITY {
        return vec![0.0; logp.len()];
    }
    logp.iter().map(|v| (*v - z).exp()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx_eq(a: f64, b: f64, tol: f64) -> bool {
        if a.is_nan() || b.is_nan() {
            return false;
        }
        (a - b).abs() <= tol
    }

    #[test]
    fn normalize_log_probs_basic() {
        let logp = [0.0, 0.0];
        let out = normalize_log_probs(&logp);
        assert!(approx_eq(out[0].exp(), 0.5, 1e-12));
        assert!(approx_eq(out[1].exp(), 0.5, 1e-12));
    }

    #[test]
    fn normalize_log_probs_shift_invariant() {
        let logp1 = [1.0, 2.0, 3.0];
        let logp2 = [11.0, 12.0, 13.0];
        let n1 = normalize_log_probs(&logp1);
        let n2 = normalize_log_probs(&logp2);
        for (a, b) in n1.iter().zip(n2.iter()) {
            assert!(approx_eq(*a, *b, 1e-12));
        }
    }

    #[test]
    fn posterior_probs_sum_to_one() {
        let logp = [0.0, -1.0, -2.0];
        let log_post = normalize_log_probs(&logp);
        let probs = posterior_probs(&log_post);
        let sum: f64 = probs.iter().sum();
        assert!(approx_eq(sum, 1.0, 1e-12));
    }

    #[test]
    fn log_odds_matches_difference() {
        let log_post = [-0.2, -1.3];
        let odds = log_odds(&log_post, 0, 1);
        assert!(approx_eq(odds, 1.1, 1e-12));
    }

    // ── Array-based (zero-alloc) tests ────────────────────────────────

    #[test]
    fn normalize_log_probs_array_basic() {
        let logp = [0.0, 0.0];
        let out = super::normalize_log_probs_array(&logp);
        assert!(approx_eq(out[0].exp(), 0.5, 1e-12));
        assert!(approx_eq(out[1].exp(), 0.5, 1e-12));
    }

    #[test]
    fn normalize_log_probs_array_matches_vec_version() {
        let logp = [-0.356, -1.609, -2.302, -3.912];
        let vec_result = normalize_log_probs(&logp);
        let arr_result = super::normalize_log_probs_array(&logp);
        for i in 0..4 {
            assert!(approx_eq(vec_result[i], arr_result[i], 1e-14));
        }
    }

    #[test]
    fn normalize_log_probs_array_shift_invariant() {
        let logp1 = [1.0, 2.0, 3.0, 4.0];
        let logp2 = [101.0, 102.0, 103.0, 104.0];
        let n1 = super::normalize_log_probs_array(&logp1);
        let n2 = super::normalize_log_probs_array(&logp2);
        for i in 0..4 {
            assert!(approx_eq(n1[i], n2[i], 1e-12));
        }
    }

    #[test]
    fn normalize_log_probs_array_nan_propagates() {
        let logp = [0.0, f64::NAN, -1.0, -2.0];
        let out = super::normalize_log_probs_array(&logp);
        assert!(out.iter().all(|v| v.is_nan()));
    }

    #[test]
    fn normalize_log_probs_array_all_neg_inf() {
        let logp = [f64::NEG_INFINITY; 4];
        let out = super::normalize_log_probs_array(&logp);
        assert!(out.iter().all(|v| *v == f64::NEG_INFINITY));
    }

    #[test]
    fn normalize_log_probs_array_posteriors_sum_to_one() {
        let logp = [-0.356, -1.609, -2.302, -3.912];
        let log_post = super::normalize_log_probs_array(&logp);
        let sum: f64 = log_post.iter().map(|v| v.exp()).sum();
        assert!(approx_eq(sum, 1.0, 1e-12));
    }

    #[test]
    fn stable_softmax_handles_extremes() {
        let logp = [0.0, -1000.0, -2000.0];
        let probs = stable_softmax(&logp);
        assert!(probs[0] > 0.999_999);
        assert!(probs[1] < 1e-6);
        assert!(probs[2] < 1e-6);
        let sum: f64 = probs.iter().sum();
        assert!(approx_eq(sum, 1.0, 1e-12));
    }
}
