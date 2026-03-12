//! Normal distribution utilities.
//!
//! Provides PDF, CDF, and quantile functions for the standard normal distribution.

use std::f64::consts::PI;

/// Standard normal PDF: f(x) = (1/sqrt(2*pi)) * exp(-0.5 * x^2)
pub fn normal_pdf(x: f64) -> f64 {
    let prefactor = (2.0 * PI).sqrt().recip();
    prefactor * (-0.5 * x * x).exp()
}

/// Standard normal CDF: P(X <= x)
///
/// Uses a high-precision rational approximation.
pub fn normal_cdf(x: f64) -> f64 {
    if x.is_nan() {
        return f64::NAN;
    }
    if x == f64::INFINITY {
        return 1.0;
    }
    if x == f64::NEG_INFINITY {
        return 0.0;
    }

    // Using the error function: CDF(x) = 0.5 * (1 + erf(x / sqrt(2)))
    0.5 * (1.0 + erf(x / 2.0f64.sqrt()))
}

/// Standard normal quantile function (probit).
///
/// Converts a probability p in [0, 1] to the corresponding x such that
/// P(X <= x) = p. Uses Abramowitz and Stegun approximation.
pub fn normal_quantile(p: f64) -> f64 {
    if p.is_nan() {
        return f64::NAN;
    }
    if p <= 0.0 {
        return f64::NEG_INFINITY;
    }
    if p >= 1.0 {
        return f64::INFINITY;
    }
    if (p - 0.5).abs() < 1e-10 {
        return 0.0;
    }

    // Abramowitz and Stegun approximation 26.2.23
    let (t, sign) = if p < 0.5 {
        ((-2.0 * p.ln()).sqrt(), -1.0)
    } else {
        ((-2.0 * (1.0 - p).ln()).sqrt(), 1.0)
    };

    let c0 = 2.515517;
    let c1 = 0.802853;
    let c2 = 0.010328;
    let d1 = 1.432788;
    let d2 = 0.189269;
    let d3 = 0.001308;

    let approx = t - (c0 + c1 * t + c2 * t * t) / (1.0 + d1 * t + d2 * t * t + d3 * t * t * t);
    approx * sign
}

/// Error function erf(x).
///
/// Uses a rational approximation with maximum error 1.5e-7.
fn erf(x: f64) -> f64 {
    if x < 0.0 {
        return -erf(-x);
    }

    // Abramowitz and Stegun 7.1.26
    let a1 = 0.254829592;
    let a2 = -0.284496736;
    let a3 = 1.421413741;
    let a4 = -1.453152027;
    let a5 = 1.061405429;
    let p = 0.3275911;

    let t = 1.0 / (1.0 + p * x);
    1.0 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * (-x * x).exp()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx_eq(a: f64, b: f64, tol: f64) -> bool {
        (a - b).abs() <= tol
    }

    #[test]
    fn test_normal_pdf() {
        assert!(approx_eq(normal_pdf(0.0), 0.39894228, 1e-6));
        assert!(approx_eq(normal_pdf(1.0), 0.24197072, 1e-6));
    }

    #[test]
    fn test_normal_cdf() {
        assert!(approx_eq(normal_cdf(0.0), 0.5, 1e-6));
        assert!(approx_eq(normal_cdf(1.96), 0.975, 1e-3));
        assert!(approx_eq(normal_cdf(-1.96), 0.025, 1e-3));
    }

    #[test]
    fn test_normal_quantile() {
        assert!(approx_eq(normal_quantile(0.5), 0.0, 1e-6));
        assert!(approx_eq(normal_quantile(0.975), 1.96, 1e-2));
        assert!(approx_eq(normal_quantile(0.025), -1.96, 1e-2));
    }

    #[test]
    fn test_quantile_inverts_cdf() {
        let p = 0.75;
        let x = normal_quantile(p);
        let p2 = normal_cdf(x);
        assert!(approx_eq(p, p2, 1e-3));
    }
}
