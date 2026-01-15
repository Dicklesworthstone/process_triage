//! Log-domain posterior normalization and odds utilities.
//!
//! These helpers turn unnormalized log-probabilities into normalized log posteriors
//! and stable probability vectors. They are intended to be used by pt-core inference
//! so that normalization and odds logic is centralized and numerically robust.

use super::stable::log_sum_exp;

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
