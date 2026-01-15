//! Beta distribution utilities for Bayesian updates.
//!
//! Provides PDF, CDF, and inverse CDF, plus mean/variance helpers.
//! The CDF uses the regularized incomplete beta function with
//! a continued-fraction approximation (Numerical Recipes).

use super::stable::log_beta;

const BETACF_MAX_ITERS: usize = 200;
const BETACF_EPS: f64 = 3.0e-7;
const BETACF_FPMIN: f64 = 1.0e-30;

/// Mean of Beta(alpha, beta) = alpha / (alpha + beta).
pub fn beta_mean(alpha: f64, beta: f64) -> f64 {
    if alpha.is_nan() || beta.is_nan() || alpha <= 0.0 || beta <= 0.0 {
        return f64::NAN;
    }
    alpha / (alpha + beta)
}

/// Variance of Beta(alpha, beta).
pub fn beta_var(alpha: f64, beta: f64) -> f64 {
    if alpha.is_nan() || beta.is_nan() || alpha <= 0.0 || beta <= 0.0 {
        return f64::NAN;
    }
    let sum = alpha + beta;
    (alpha * beta) / (sum * sum * (sum + 1.0))
}

/// Log of the Beta PDF at x.
pub fn log_beta_pdf(x: f64, alpha: f64, beta: f64) -> f64 {
    if x.is_nan() || alpha.is_nan() || beta.is_nan() {
        return f64::NAN;
    }
    if alpha <= 0.0 || beta <= 0.0 {
        return f64::NAN;
    }
    if x < 0.0 || x > 1.0 {
        return f64::NEG_INFINITY;
    }
    if x == 0.0 {
        if alpha < 1.0 {
            return f64::INFINITY;
        }
        if alpha > 1.0 {
            return f64::NEG_INFINITY;
        }
        return -log_beta(1.0, beta);
    }
    if x == 1.0 {
        if beta < 1.0 {
            return f64::INFINITY;
        }
        if beta > 1.0 {
            return f64::NEG_INFINITY;
        }
        return -log_beta(alpha, 1.0);
    }
    let log_x = x.ln();
    let log_one_minus = (-x).ln_1p();
    (alpha - 1.0) * log_x + (beta - 1.0) * log_one_minus - log_beta(alpha, beta)
}

/// Beta PDF at x.
pub fn beta_pdf(x: f64, alpha: f64, beta: f64) -> f64 {
    let log_pdf = log_beta_pdf(x, alpha, beta);
    if log_pdf.is_nan() {
        return f64::NAN;
    }
    if log_pdf == f64::INFINITY {
        return f64::INFINITY;
    }
    if log_pdf == f64::NEG_INFINITY {
        return 0.0;
    }
    log_pdf.exp()
}

/// Regularized incomplete beta function I_x(a,b).
pub fn beta_cdf(x: f64, alpha: f64, beta: f64) -> f64 {
    if x.is_nan() || alpha.is_nan() || beta.is_nan() {
        return f64::NAN;
    }
    if alpha <= 0.0 || beta <= 0.0 {
        return f64::NAN;
    }
    if x <= 0.0 {
        return 0.0;
    }
    if x >= 1.0 {
        return 1.0;
    }
    let ln_beta = log_beta(alpha, beta);
    let bt = (alpha * x.ln() + beta * (1.0 - x).ln() - ln_beta).exp();
    let threshold = (alpha + 1.0) / (alpha + beta + 2.0);
    if x < threshold {
        bt * betacf(alpha, beta, x) / alpha
    } else {
        1.0 - bt * betacf(beta, alpha, 1.0 - x) / beta
    }
}

/// Inverse CDF (quantile) for Beta(alpha, beta).
pub fn beta_inv_cdf(p: f64, alpha: f64, beta: f64) -> f64 {
    if p.is_nan() || alpha.is_nan() || beta.is_nan() {
        return f64::NAN;
    }
    if alpha <= 0.0 || beta <= 0.0 {
        return f64::NAN;
    }
    if p <= 0.0 {
        return 0.0;
    }
    if p >= 1.0 {
        return 1.0;
    }

    let mut low = 0.0;
    let mut high = 1.0;
    let mut mid = 0.5;
    let tol = 1e-10;
    for _ in 0..200 {
        mid = 0.5 * (low + high);
        let cdf = beta_cdf(mid, alpha, beta);
        if cdf.is_nan() {
            return f64::NAN;
        }
        let delta = cdf - p;
        if delta.abs() < tol {
            return mid;
        }
        if delta < 0.0 {
            low = mid;
        } else {
            high = mid;
        }
    }
    mid
}

fn betacf(alpha: f64, beta: f64, x: f64) -> f64 {
    let qab = alpha + beta;
    let qap = alpha + 1.0;
    let qam = alpha - 1.0;
    let mut c = 1.0;
    let mut d = 1.0 - qab * x / qap;
    if d.abs() < BETACF_FPMIN {
        d = BETACF_FPMIN;
    }
    d = 1.0 / d;
    let mut h = d;

    for m in 1..=BETACF_MAX_ITERS {
        let m_f = m as f64;
        let m2 = 2.0 * m_f;
        let aa = m_f * (beta - m_f) * x / ((qam + m2) * (alpha + m2));
        d = 1.0 + aa * d;
        if d.abs() < BETACF_FPMIN {
            d = BETACF_FPMIN;
        }
        c = 1.0 + aa / c;
        if c.abs() < BETACF_FPMIN {
            c = BETACF_FPMIN;
        }
        d = 1.0 / d;
        h *= d * c;

        let aa = -(alpha + m_f) * (qab + m_f) * x / ((alpha + m2) * (qap + m2));
        d = 1.0 + aa * d;
        if d.abs() < BETACF_FPMIN {
            d = BETACF_FPMIN;
        }
        c = 1.0 + aa / c;
        if c.abs() < BETACF_FPMIN {
            c = BETACF_FPMIN;
        }
        d = 1.0 / d;
        let del = d * c;
        h *= del;
        if (del - 1.0).abs() < BETACF_EPS {
            break;
        }
    }

    h
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
    fn mean_and_var_match_closed_form() {
        let mean = beta_mean(2.0, 5.0);
        let var = beta_var(2.0, 5.0);
        assert!(approx_eq(mean, 2.0 / 7.0, 1e-12));
        assert!(approx_eq(var, 10.0 / 392.0, 1e-12));
    }

    #[test]
    fn pdf_uniform_is_one() {
        let pdf = beta_pdf(0.33, 1.0, 1.0);
        assert!(approx_eq(pdf, 1.0, 1e-12));
    }

    #[test]
    fn pdf_known_value_beta_2_5() {
        let pdf = beta_pdf(0.2, 2.0, 5.0);
        assert!(approx_eq(pdf, 2.4576, 1e-6));
    }

    #[test]
    fn pdf_symmetry() {
        let a = 2.3;
        let b = 4.7;
        let x = 0.27;
        let left = beta_pdf(x, a, b);
        let right = beta_pdf(1.0 - x, b, a);
        assert!(approx_eq(left, right, 1e-10));
    }

    #[test]
    fn log_pdf_matches_pdf() {
        let x = 0.4;
        let a = 1.2;
        let b = 3.4;
        let pdf = beta_pdf(x, a, b);
        let log_pdf = log_beta_pdf(x, a, b);
        assert!(approx_eq(pdf.ln(), log_pdf, 1e-10));
    }

    #[test]
    fn cdf_uniform_matches_identity() {
        let x = 0.42;
        let cdf = beta_cdf(x, 1.0, 1.0);
        assert!(approx_eq(cdf, x, 1e-6));
    }

    #[test]
    fn cdf_monotone() {
        let cdf1 = beta_cdf(0.2, 2.0, 5.0);
        let cdf2 = beta_cdf(0.7, 2.0, 5.0);
        assert!(cdf1 < cdf2);
    }

    #[test]
    fn inv_cdf_uniform() {
        let p = 0.73;
        let x = beta_inv_cdf(p, 1.0, 1.0);
        assert!(approx_eq(x, p, 1e-6));
    }

    #[test]
    fn inv_cdf_inverts_cdf() {
        let p = 0.25;
        let a = 2.0;
        let b = 5.0;
        let x = beta_inv_cdf(p, a, b);
        let cdf = beta_cdf(x, a, b);
        assert!(approx_eq(cdf, p, 1e-6));
    }

    #[test]
    fn log_pdf_edge_behavior_at_zero() {
        let log_pdf = log_beta_pdf(0.0, 0.5, 2.0);
        assert!(log_pdf.is_infinite() && log_pdf.is_sign_positive());

        let log_pdf2 = log_beta_pdf(0.0, 2.0, 2.0);
        assert!(log_pdf2.is_infinite() && log_pdf2.is_sign_negative());
    }
}
