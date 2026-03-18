//! Pre-computed log-domain constants for hot-path inference.
//!
//! During a triage session the Bayesian priors are fixed, so every
//! `log_beta_pdf(x, α, β)` call pays for three `log_gamma` evaluations
//! that return the same value. Pre-computing these constants once per
//! session eliminates ~12 of the ~16 `log_gamma` calls per process in
//! the posterior hot path.

use super::stable::{log_beta, log_gamma};

/// Pre-computed `log_beta(α, β)` for a Beta prior.
///
/// The posterior computation calls `log_beta_pdf(x, α, β)` which
/// internally computes `(α-1)*ln(x) + (β-1)*ln(1-x) - log_beta(α, β)`.
/// Since `α` and `β` come from the session priors and do not change,
/// the `log_beta(α, β)` term can be computed once and reused.
#[derive(Debug, Clone, Copy)]
pub struct CachedBetaPrior {
    pub alpha: f64,
    pub beta: f64,
    /// Pre-computed `log_beta(alpha, beta)`.
    pub log_beta_val: f64,
}

impl CachedBetaPrior {
    /// Create a new cached Beta prior.
    pub fn new(alpha: f64, beta: f64) -> Self {
        Self {
            alpha,
            beta,
            log_beta_val: log_beta(alpha, beta),
        }
    }

    /// Compute `log_beta_pdf(x)` using the cached normalizing constant.
    ///
    /// This avoids the 3 `log_gamma` calls that `log_beta` would make,
    /// reducing per-call cost from ~45ns to ~10ns for typical parameters.
    #[inline]
    pub fn log_pdf(&self, x: f64) -> f64 {
        if x.is_nan() || self.alpha.is_nan() || self.beta.is_nan() {
            return f64::NAN;
        }
        if self.alpha <= 0.0 || self.beta <= 0.0 {
            return f64::NAN;
        }
        if !(0.0..=1.0).contains(&x) {
            return f64::NEG_INFINITY;
        }
        if x == 0.0 {
            if self.alpha < 1.0 {
                return f64::INFINITY;
            }
            if self.alpha > 1.0 {
                return f64::NEG_INFINITY;
            }
            // alpha == 1.0: log_beta(1, β) == self.log_beta_val
            return -self.log_beta_val;
        }
        if x == 1.0 {
            if self.beta < 1.0 {
                return f64::INFINITY;
            }
            if self.beta > 1.0 {
                return f64::NEG_INFINITY;
            }
            // beta == 1.0: log_beta(α, 1) == self.log_beta_val
            return -self.log_beta_val;
        }
        let log_x = x.ln();
        let log_one_minus = (-x).ln_1p();
        (self.alpha - 1.0) * log_x + (self.beta - 1.0) * log_one_minus - self.log_beta_val
    }
}

/// Pre-computed `log_gamma(α)` for a Gamma prior.
///
/// The Gamma PDF `α*ln(β) - log_gamma(α) + (α-1)*ln(t) - β*t` has
/// a fixed `log_gamma(α)` term when `α` comes from session priors.
#[derive(Debug, Clone, Copy)]
pub struct CachedGammaPrior {
    pub shape: f64,
    pub rate: f64,
    /// Pre-computed `log_gamma(shape)`.
    pub log_gamma_shape: f64,
    /// Pre-computed `shape * ln(rate)`.
    pub shape_ln_rate: f64,
}

impl CachedGammaPrior {
    /// Create a new cached Gamma prior.
    pub fn new(shape: f64, rate: f64) -> Self {
        Self {
            shape,
            rate,
            log_gamma_shape: log_gamma(shape),
            shape_ln_rate: shape * rate.ln(),
        }
    }

    /// Compute `gamma_log_pdf(t)` using cached constants.
    #[inline]
    pub fn log_pdf(&self, t: f64) -> f64 {
        if t.is_nan() || self.shape.is_nan() || self.rate.is_nan() {
            return f64::NAN;
        }
        if self.shape <= 0.0 || self.rate <= 0.0 {
            return f64::NAN;
        }
        if t < 0.0 {
            return f64::NEG_INFINITY;
        }
        if t == 0.0 {
            if self.shape < 1.0 {
                return f64::INFINITY;
            } else if self.shape == 1.0 {
                return self.rate.ln();
            } else {
                return f64::NEG_INFINITY;
            }
        }
        self.shape_ln_rate - self.log_gamma_shape + (self.shape - 1.0) * t.ln() - self.rate * t
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::math::beta::log_beta_pdf;
    use crate::math::gamma::gamma_log_pdf;

    fn approx_eq(a: f64, b: f64, tol: f64) -> bool {
        if a.is_nan() && b.is_nan() {
            return true;
        }
        if a.is_infinite() && b.is_infinite() {
            return a.is_sign_positive() == b.is_sign_positive();
        }
        (a - b).abs() <= tol
    }

    // ── CachedBetaPrior tests ───────────────────────────────────────

    #[test]
    fn cached_beta_matches_direct() {
        for (alpha, beta) in [(2.0, 5.0), (0.5, 0.5), (1.0, 1.0), (10.0, 3.0)] {
            let cached = CachedBetaPrior::new(alpha, beta);
            for x in [0.01, 0.1, 0.25, 0.5, 0.75, 0.9, 0.99] {
                let direct = log_beta_pdf(x, alpha, beta);
                let fast = cached.log_pdf(x);
                assert!(
                    approx_eq(direct, fast, 1e-12),
                    "Mismatch at x={x}, α={alpha}, β={beta}: direct={direct}, cached={fast}"
                );
            }
        }
    }

    #[test]
    fn cached_beta_boundary_zero() {
        let cached = CachedBetaPrior::new(2.0, 5.0);
        let direct = log_beta_pdf(0.0, 2.0, 5.0);
        assert!(approx_eq(cached.log_pdf(0.0), direct, 1e-12));
    }

    #[test]
    fn cached_beta_boundary_one() {
        let cached = CachedBetaPrior::new(5.0, 2.0);
        let direct = log_beta_pdf(1.0, 5.0, 2.0);
        assert!(approx_eq(cached.log_pdf(1.0), direct, 1e-12));
    }

    #[test]
    fn cached_beta_nan_handling() {
        let cached = CachedBetaPrior::new(2.0, 5.0);
        assert!(cached.log_pdf(f64::NAN).is_nan());
    }

    #[test]
    fn cached_beta_out_of_range() {
        let cached = CachedBetaPrior::new(2.0, 5.0);
        assert_eq!(cached.log_pdf(-0.1), f64::NEG_INFINITY);
        assert_eq!(cached.log_pdf(1.5), f64::NEG_INFINITY);
    }

    // ── CachedGammaPrior tests ──────────────────────────────────────

    #[test]
    fn cached_gamma_matches_direct() {
        for (shape, rate) in [(2.0, 1.0), (0.5, 2.0), (1.0, 3.0), (5.0, 0.5)] {
            let cached = CachedGammaPrior::new(shape, rate);
            for t in [0.01, 0.1, 0.5, 1.0, 2.0, 5.0, 10.0] {
                let direct = gamma_log_pdf(t, shape, rate);
                let fast = cached.log_pdf(t);
                assert!(
                    approx_eq(direct, fast, 1e-12),
                    "Mismatch at t={t}, α={shape}, β={rate}: direct={direct}, cached={fast}"
                );
            }
        }
    }

    #[test]
    fn cached_gamma_boundary_zero() {
        // shape < 1: +inf
        let c1 = CachedGammaPrior::new(0.5, 1.0);
        assert!(c1.log_pdf(0.0).is_infinite() && c1.log_pdf(0.0).is_sign_positive());

        // shape = 1: ln(rate)
        let c2 = CachedGammaPrior::new(1.0, 2.0);
        assert!(approx_eq(c2.log_pdf(0.0), 2.0f64.ln(), 1e-12));

        // shape > 1: -inf
        let c3 = CachedGammaPrior::new(2.0, 1.0);
        assert!(c3.log_pdf(0.0).is_infinite() && c3.log_pdf(0.0).is_sign_negative());
    }

    #[test]
    fn cached_gamma_nan_handling() {
        let cached = CachedGammaPrior::new(2.0, 1.0);
        assert!(cached.log_pdf(f64::NAN).is_nan());
    }

    #[test]
    fn cached_gamma_negative_t() {
        let cached = CachedGammaPrior::new(2.0, 1.0);
        assert_eq!(cached.log_pdf(-1.0), f64::NEG_INFINITY);
    }
}
