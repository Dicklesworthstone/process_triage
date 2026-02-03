//! PAC-Bayes bounds for calibration error rates.
//!
//! Implements a conservative McAllester-style PAC-Bayes bound for a Bernoulli
//! error rate. This is used to report safety bounds on false-kill rate from
//! shadow-mode observations.

use serde::{Deserialize, Serialize};

/// Single PAC-Bayes bound at confidence 1-δ.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacBayesBound {
    /// Tail probability δ.
    pub delta: f64,
    /// KL(Q||P) term supplied by caller.
    pub kl_qp: f64,
    /// Empirical error rate (k/n).
    pub empirical_error: f64,
    /// Derived c value for the inequality.
    pub c: f64,
    /// Upper bound on true error rate.
    pub upper_bound: f64,
}

/// PAC-Bayes summary for a Bernoulli error rate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacBayesSummary {
    pub trials: usize,
    pub errors: usize,
    pub empirical_error: f64,
    pub kl_qp: f64,
    pub bounds: Vec<PacBayesBound>,
    pub assumptions: String,
    pub window: String,
}

/// Compute PAC-Bayes upper bounds on error rate using McAllester-style inequality.
///
/// The inequality used:
///   KL(ê || e) <= (KL(Q||P) + ln((2*sqrt(n))/δ)) / n
pub fn pac_bayes_error_bounds(
    errors: usize,
    trials: usize,
    kl_qp: f64,
    deltas: &[f64],
) -> Option<PacBayesSummary> {
    if trials == 0 {
        return None;
    }
    if kl_qp.is_nan() || kl_qp < 0.0 {
        return None;
    }

    let empirical = errors as f64 / trials as f64;
    let n = trials as f64;
    let mut bounds = Vec::new();

    for &delta in deltas {
        if !(0.0 < delta && delta < 1.0) {
            continue;
        }
        let c = (kl_qp + (2.0 * n.sqrt()).ln() - delta.ln()) / n;
        if !c.is_finite() {
            continue;
        }
        let upper = kl_bernoulli_upper(empirical, c);
        bounds.push(PacBayesBound {
            delta,
            kl_qp,
            empirical_error: empirical,
            c,
            upper_bound: upper,
        });
    }

    Some(PacBayesSummary {
        trials,
        errors,
        empirical_error: empirical,
        kl_qp,
        bounds,
        assumptions: "McAllester PAC-Bayes bound on Bernoulli error; KL(Q||P) supplied; classifier treated as fixed; applies to false-kill rate over shadow-mode trials."
            .to_string(),
        window: "all_data".to_string(),
    })
}

fn kl_bernoulli(p: f64, q: f64) -> f64 {
    let eps = 1e-12;
    let p = p.clamp(0.0, 1.0);
    let q = q.clamp(eps, 1.0 - eps);
    if p == 0.0 {
        return (1.0 - p) * ((1.0 - p) / (1.0 - q)).ln();
    }
    if p == 1.0 {
        return (p / q).ln();
    }
    p * (p / q).ln() + (1.0 - p) * ((1.0 - p) / (1.0 - q)).ln()
}

/// Solve for the maximum q in [p,1] such that KL(p||q) <= c.
fn kl_bernoulli_upper(p: f64, c: f64) -> f64 {
    if c <= 0.0 {
        return p.clamp(0.0, 1.0);
    }
    let p = p.clamp(0.0, 1.0);
    if p >= 1.0 {
        return 1.0;
    }

    let mut lo = p;
    let mut hi = 1.0 - 1e-12;
    for _ in 0..80 {
        let mid = (lo + hi) * 0.5;
        let kl = kl_bernoulli(p, mid);
        if kl > c {
            hi = mid;
        } else {
            lo = mid;
        }
    }
    lo
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pac_bayes_bound_is_above_empirical() {
        let summary = pac_bayes_error_bounds(5, 100, 0.0, &[0.05]).expect("summary");
        assert_eq!(summary.trials, 100);
        assert_eq!(summary.errors, 5);
        let bound = &summary.bounds[0];
        assert!(bound.upper_bound >= summary.empirical_error);
        assert!(bound.upper_bound <= 1.0);
    }

    #[test]
    fn pac_bayes_bound_tighter_for_larger_delta() {
        let summary = pac_bayes_error_bounds(2, 50, 0.0, &[0.05, 0.2]).expect("summary");
        let b05 = summary
            .bounds
            .iter()
            .find(|b| (b.delta - 0.05).abs() < 1e-9);
        let b20 = summary.bounds.iter().find(|b| (b.delta - 0.2).abs() < 1e-9);
        assert!(b05.is_some());
        assert!(b20.is_some());
        let b05 = b05.unwrap();
        let b20 = b20.unwrap();
        assert!(b05.upper_bound >= b20.upper_bound);
    }
}
