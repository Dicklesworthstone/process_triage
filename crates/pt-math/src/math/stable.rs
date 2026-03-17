//! Numerically stable primitives for log-domain Bayesian math.

use std::f64::consts::PI;

const LOG_SQRT_2PI: f64 = 0.918_938_533_204_672_8; // 0.5 * ln(2*pi)
const LANCZOS_G: f64 = 7.0;
#[allow(clippy::excessive_precision)] // These are published numerical constants
const LANCZOS_COEFFS: [f64; 9] = [
    0.999_999_999_999_809_93,
    676.520_368_121_885_1,
    -1_259.139_216_722_402_8,
    771.323_428_777_653_1,
    -176.615_029_162_140_59,
    12.507_343_278_686_905,
    -0.138_571_095_265_720_12,
    9.984_369_578_019_571_6e-6,
    1.505_632_735_149_311_6e-7,
];

/// Stable log(sum(exp(values))).
///
/// Returns NEG_INFINITY for empty input or all -inf inputs.
pub fn log_sum_exp(values: &[f64]) -> f64 {
    if values.is_empty() {
        return f64::NEG_INFINITY;
    }
    if values.iter().any(|v| v.is_nan()) {
        return f64::NAN;
    }
    let max = values.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    if max == f64::NEG_INFINITY {
        return f64::NEG_INFINITY;
    }
    if max == f64::INFINITY {
        return f64::INFINITY;
    }
    let mut sum = 0.0;
    for v in values {
        sum += (*v - max).exp();
    }
    max + sum.ln()
}

/// Zero-allocation log-sum-exp for fixed-size arrays.
///
/// Semantically identical to [`log_sum_exp`] but avoids slice overhead
/// and enables the compiler to unroll the loops for small N (e.g., N=4).
#[inline]
pub fn log_sum_exp_array<const N: usize>(values: &[f64; N]) -> f64 {
    let mut max = f64::NEG_INFINITY;
    for v in values {
        if v.is_nan() {
            return f64::NAN;
        }
        if *v > max {
            max = *v;
        }
    }
    if max == f64::NEG_INFINITY {
        return f64::NEG_INFINITY;
    }
    if max == f64::INFINITY {
        return f64::INFINITY;
    }
    let mut sum = 0.0;
    for v in values {
        sum += (*v - max).exp();
    }
    max + sum.ln()
}

/// Stable log(exp(a) + exp(b)).
pub fn log_add_exp(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        return f64::NAN;
    }
    if a == f64::NEG_INFINITY {
        return b;
    }
    if b == f64::NEG_INFINITY {
        return a;
    }
    if a == f64::INFINITY || b == f64::INFINITY {
        return f64::INFINITY;
    }
    let m = a.max(b);
    let diff = (a - b).abs();
    m + (-diff).exp().ln_1p()
}

/// Stable log(exp(a) - exp(b)). Requires a > b for real-valued result.
pub fn log_sub_exp(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        return f64::NAN;
    }
    if a.is_infinite() && b.is_infinite() {
        if a.is_sign_positive() && b.is_sign_positive() {
            return f64::NAN;
        }
        if a.is_sign_negative() && b.is_sign_negative() {
            return f64::NEG_INFINITY;
        }
    }
    if b == f64::NEG_INFINITY {
        return a;
    }
    if a == b {
        return f64::NEG_INFINITY;
    }
    if a < b {
        return f64::NAN;
    }
    if a == f64::INFINITY {
        return f64::INFINITY;
    }
    a + (-(b - a).exp_m1()).ln()
}

/// Natural log of the Gamma function (log |Gamma(z)|).
///
/// Uses a Lanczos approximation with reflection for z < 0.5.
pub fn log_gamma(z: f64) -> f64 {
    if z.is_nan() {
        return f64::NAN;
    }
    if z == f64::INFINITY {
        return f64::INFINITY;
    }
    if z == f64::NEG_INFINITY {
        return f64::NAN;
    }
    if z <= 0.0 {
        let z_round = z.round();
        if (z - z_round).abs() < 1e-15 {
            return f64::NAN;
        }
    }
    if z < 0.5 {
        let sin_pi = (PI * z).sin();
        if sin_pi == 0.0 {
            return f64::NAN;
        }
        return PI.ln() - sin_pi.abs().ln() - log_gamma(1.0 - z);
    }

    let z_minus = z - 1.0;
    let mut x = LANCZOS_COEFFS[0];
    for (i, coeff) in LANCZOS_COEFFS.iter().enumerate().skip(1) {
        x += coeff / (z_minus + i as f64);
    }
    let t = z_minus + LANCZOS_G + 0.5;
    LOG_SQRT_2PI + (z_minus + 0.5) * t.ln() - t + x.ln()
}

/// Alias for log_gamma, matching typical lgamma naming.
pub fn lgamma(x: f64) -> f64 {
    log_gamma(x)
}

/// log Beta(a, b) = log Gamma(a) + log Gamma(b) - log Gamma(a+b).
pub fn log_beta(a: f64, b: f64) -> f64 {
    log_gamma(a) + log_gamma(b) - log_gamma(a + b)
}

/// log(n!) using the Gamma function.
pub fn log_factorial(n: u64) -> f64 {
    if n <= 1 {
        return 0.0;
    }
    log_gamma((n as f64) + 1.0)
}

/// log binomial coefficient: log(n choose k).
pub fn log_binomial(n: u64, k: u64) -> f64 {
    if k > n {
        return f64::NEG_INFINITY;
    }
    if k == 0 || k == n {
        return 0.0;
    }
    log_factorial(n) - log_factorial(k) - log_factorial(n - k)
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
    fn log_sum_exp_basic() {
        let v = [0.0, 0.0];
        let out = log_sum_exp(&v);
        assert!(approx_eq(out, 2.0f64.ln(), 1e-12));
    }

    #[test]
    fn log_sum_exp_dominance() {
        let v = [-1000.0, 0.0];
        let out = log_sum_exp(&v);
        assert!(approx_eq(out, 0.0, 1e-12));
    }

    #[test]
    fn log_sum_exp_all_neg_inf() {
        let v = [f64::NEG_INFINITY, f64::NEG_INFINITY];
        let out = log_sum_exp(&v);
        assert!(out.is_infinite() && out.is_sign_negative());
    }

    #[test]
    fn log_add_exp_matches_lse() {
        let a = 1.234;
        let b = -0.75;
        let out = log_add_exp(a, b);
        let lse = log_sum_exp(&[a, b]);
        assert!(approx_eq(out, lse, 1e-12));
    }

    #[test]
    fn log_sub_exp_basic() {
        let a = 2.0;
        let b = 1.0;
        let out = log_sub_exp(a, b);
        let expected = (a.exp() - b.exp()).ln();
        assert!(approx_eq(out, expected, 1e-12));
    }

    #[test]
    fn log_gamma_known_values() {
        let lg1 = log_gamma(1.0);
        assert!(approx_eq(lg1, 0.0, 1e-12));

        let lg_half = log_gamma(0.5);
        let expected = 0.5 * PI.ln();
        assert!(approx_eq(lg_half, expected, 1e-10));

        let lg5 = log_gamma(5.0); // Gamma(5)=24
        assert!(approx_eq(lg5, 24.0f64.ln(), 1e-10));
    }

    #[test]
    fn log_beta_factorial_binomial() {
        let lb = log_beta(1.0, 1.0);
        assert!(approx_eq(lb, 0.0, 1e-12));

        let lf = log_factorial(5);
        assert!(approx_eq(lf, 120.0f64.ln(), 1e-12));

        let lbin = log_binomial(5, 2);
        assert!(approx_eq(lbin, 10.0f64.ln(), 1e-12));
    }

    #[test]
    fn log_sum_exp_nan_propagates() {
        let out = log_sum_exp(&[0.0, f64::NAN]);
        assert!(out.is_nan());
    }

    #[test]
    fn log_add_exp_infinity_rules() {
        let out = log_add_exp(f64::INFINITY, 1.0);
        assert!(out.is_infinite() && out.is_sign_positive());

        let out2 = log_add_exp(f64::NEG_INFINITY, 2.0);
        assert!(approx_eq(out2, 2.0, 1e-12));
    }

    #[test]
    fn log_sub_exp_invalid_cases() {
        let out = log_sub_exp(1.0, 2.0);
        assert!(out.is_nan());

        let out2 = log_sub_exp(2.0, 2.0);
        assert!(out2.is_infinite() && out2.is_sign_negative());
    }

    #[test]
    fn log_gamma_negative_integer_is_nan() {
        let out = log_gamma(-2.0);
        assert!(out.is_nan());
    }

    // ── log_sum_exp_array tests ─────────────────────────────────────

    #[test]
    fn log_sum_exp_array_matches_slice_version() {
        let vals = [-0.356, -1.609, -2.302, -3.912];
        let slice_result = log_sum_exp(&vals);
        let array_result = log_sum_exp_array(&vals);
        assert!(approx_eq(slice_result, array_result, 1e-14));
    }

    #[test]
    fn log_sum_exp_array_basic() {
        let vals = [0.0, 0.0];
        let out = log_sum_exp_array(&vals);
        assert!(approx_eq(out, 2.0f64.ln(), 1e-12));
    }

    #[test]
    fn log_sum_exp_array_dominance() {
        let vals = [-1000.0, 0.0, -2000.0, -3000.0];
        let out = log_sum_exp_array(&vals);
        assert!(approx_eq(out, 0.0, 1e-12));
    }

    #[test]
    fn log_sum_exp_array_nan_propagates() {
        let vals = [0.0, f64::NAN, -1.0, -2.0];
        let out = log_sum_exp_array(&vals);
        assert!(out.is_nan());
    }

    #[test]
    fn log_sum_exp_array_all_neg_inf() {
        let vals = [f64::NEG_INFINITY; 4];
        let out = log_sum_exp_array(&vals);
        assert!(out == f64::NEG_INFINITY);
    }
}
