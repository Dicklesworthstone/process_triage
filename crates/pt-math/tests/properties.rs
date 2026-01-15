//! Property-based tests for pt-math numerical functions.
//!
//! Uses proptest to verify mathematical properties hold across many random inputs.

use proptest::prelude::*;
use pt_math::{log_add_exp, log_beta, log_binomial, log_factorial, log_gamma, log_sub_exp, log_sum_exp};

/// Tolerance for floating point comparisons.
const TOL: f64 = 1e-10;

/// Extended tolerance for log_gamma where Lanczos approximation has some error.
const LGAMMA_TOL: f64 = 1e-8;

/// Helper to check approximate equality.
fn approx_eq(a: f64, b: f64, tol: f64) -> bool {
    if a.is_nan() && b.is_nan() {
        return true;
    }
    if a.is_nan() || b.is_nan() {
        return false;
    }
    if a.is_infinite() && b.is_infinite() {
        return a.signum() == b.signum();
    }
    if a.is_infinite() || b.is_infinite() {
        return false;
    }
    (a - b).abs() <= tol.max(tol * a.abs().max(b.abs()))
}

// ============================================================================
// log_sum_exp properties
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// log_sum_exp is commutative: order doesn't matter.
    #[test]
    fn log_sum_exp_commutative(a in -100.0..100.0f64, b in -100.0..100.0f64) {
        let ab = log_sum_exp(&[a, b]);
        let ba = log_sum_exp(&[b, a]);
        prop_assert!(approx_eq(ab, ba, TOL), "lse([{},{}])={} != lse([{},{}])={}", a, b, ab, b, a, ba);
    }

    /// log_sum_exp is associative: grouping doesn't matter.
    #[test]
    fn log_sum_exp_associative(a in -50.0..50.0f64, b in -50.0..50.0f64, c in -50.0..50.0f64) {
        // log_sum_exp([a, b, c]) should equal log_sum_exp([log_sum_exp([a, b]), c])
        let direct = log_sum_exp(&[a, b, c]);
        let grouped_ab = log_sum_exp(&[log_sum_exp(&[a, b]), c]);
        let grouped_bc = log_sum_exp(&[a, log_sum_exp(&[b, c])]);
        prop_assert!(approx_eq(direct, grouped_ab, TOL),
            "lse([{},{},{}])={} != lse([lse([{},{}]),{}])={}", a, b, c, direct, a, b, c, grouped_ab);
        prop_assert!(approx_eq(direct, grouped_bc, TOL),
            "lse([{},{},{}])={} != lse([{},lse([{},{}])])={}", a, b, c, direct, a, b, c, grouped_bc);
    }

    /// log_sum_exp dominance: the max value dominates when differences are large.
    #[test]
    fn log_sum_exp_dominance(max_val in -50.0..50.0f64) {
        // When other values are much smaller, result ≈ max_val
        let small = max_val - 100.0;
        let result = log_sum_exp(&[max_val, small, small - 10.0]);
        prop_assert!(approx_eq(result, max_val, TOL),
            "lse([{},{},{}])={} not ≈ {}", max_val, small, small-10.0, result, max_val);
    }

    /// log_sum_exp numerical stability: no overflow with large values.
    #[test]
    fn log_sum_exp_no_overflow(a in 500.0..700.0f64, b in 500.0..700.0f64) {
        let result = log_sum_exp(&[a, b]);
        prop_assert!(!result.is_nan(), "lse([{},{}]) should not be NaN", a, b);
        prop_assert!(result.is_finite() || result.is_sign_positive(),
            "lse([{},{}])={} should be finite or +inf", a, b, result);
        // Result should be >= max(a, b)
        prop_assert!(result >= a.max(b) - TOL, "lse result {} should be >= max({},{})={}", result, a, b, a.max(b));
    }

    /// log_sum_exp numerical stability: no underflow with very negative values.
    #[test]
    fn log_sum_exp_no_underflow(a in -700.0..-500.0f64, b in -700.0..-500.0f64) {
        let result = log_sum_exp(&[a, b]);
        prop_assert!(!result.is_nan(), "lse([{},{}]) should not be NaN", a, b);
        prop_assert!(result.is_finite() || result == f64::NEG_INFINITY,
            "lse([{},{}])={} should be finite or -inf", a, b, result);
    }
}

// ============================================================================
// log_add_exp properties (same as log_sum_exp for 2 elements)
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// log_add_exp matches log_sum_exp for 2 elements.
    #[test]
    fn log_add_exp_matches_log_sum_exp(a in -100.0..100.0f64, b in -100.0..100.0f64) {
        let lae = log_add_exp(a, b);
        let lse = log_sum_exp(&[a, b]);
        prop_assert!(approx_eq(lae, lse, TOL), "log_add_exp({},{})={} != log_sum_exp({})={}", a, b, lae, lse, lse);
    }

    /// log_add_exp is commutative.
    #[test]
    fn log_add_exp_commutative(a in -100.0..100.0f64, b in -100.0..100.0f64) {
        let ab = log_add_exp(a, b);
        let ba = log_add_exp(b, a);
        prop_assert!(approx_eq(ab, ba, TOL), "lae({},{})={} != lae({},{})={}", a, b, ab, b, a, ba);
    }
}

// ============================================================================
// log_sub_exp properties
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// log_sub_exp correctness: exp(result) = exp(a) - exp(b).
    #[test]
    fn log_sub_exp_correctness(a in -50.0..50.0f64, diff in 0.01..50.0f64) {
        let b = a - diff; // Ensure a > b
        let result = log_sub_exp(a, b);
        if result.is_finite() {
            let expected = (a.exp() - b.exp()).ln();
            if expected.is_finite() {
                prop_assert!(approx_eq(result, expected, TOL),
                    "lse({},{})={} != ln(exp({})-exp({}))={}", a, b, result, a, b, expected);
            }
        }
    }

    /// log_sub_exp returns NaN when a < b.
    #[test]
    fn log_sub_exp_invalid_returns_nan(b in -50.0..50.0f64, diff in 0.01..50.0f64) {
        let a = b - diff; // a < b
        let result = log_sub_exp(a, b);
        prop_assert!(result.is_nan(), "lse({},{}) should be NaN when a < b, got {}", a, b, result);
    }

    /// log_sub_exp returns NEG_INFINITY when a == b.
    #[test]
    fn log_sub_exp_equal_returns_neg_inf(a in -100.0..100.0f64) {
        let result = log_sub_exp(a, a);
        prop_assert!(result == f64::NEG_INFINITY, "lse({},{}) should be -inf, got {}", a, a, result);
    }
}

// ============================================================================
// log_gamma properties
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// log_gamma recurrence: log_gamma(z+1) = log_gamma(z) + ln(z).
    #[test]
    fn log_gamma_recurrence(z in 1.0..100.0f64) {
        let lg_z = log_gamma(z);
        let lg_z1 = log_gamma(z + 1.0);
        let expected = lg_z + z.ln();
        prop_assert!(approx_eq(lg_z1, expected, LGAMMA_TOL),
            "lg({}+1)={} != lg({}) + ln({}) = {}", z, lg_z1, z, z, expected);
    }

    /// log_gamma at positive integers: log_gamma(n) = log((n-1)!).
    #[test]
    fn log_gamma_factorial(n in 2u64..20) {
        let lg = log_gamma(n as f64);
        let expected = log_factorial(n - 1);
        prop_assert!(approx_eq(lg, expected, LGAMMA_TOL),
            "lg({})={} != log(({}-1)!)={}", n, lg, n, expected);
    }

    /// log_gamma is positive for z > 2 (since Gamma(z) > 1 for z > 2).
    #[test]
    fn log_gamma_positive_for_large_z(z in 2.1..1000.0f64) {
        let result = log_gamma(z);
        prop_assert!(result > 0.0, "lg({})={} should be positive", z, result);
    }

    /// log_gamma handles negative non-integers via reflection.
    #[test]
    fn log_gamma_negative_non_integers(z in 0.1..0.9f64) {
        let neg_z = -z; // z in (-0.9, -0.1)
        let result = log_gamma(neg_z);
        prop_assert!(result.is_finite(), "lg({})={} should be finite", neg_z, result);
    }
}

// ============================================================================
// log_beta properties
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// log_beta is symmetric: B(a,b) = B(b,a).
    #[test]
    fn log_beta_symmetric(a in 0.1..50.0f64, b in 0.1..50.0f64) {
        let ab = log_beta(a, b);
        let ba = log_beta(b, a);
        prop_assert!(approx_eq(ab, ba, LGAMMA_TOL), "log_beta({},{})={} != log_beta({},{})={}", a, b, ab, b, a, ba);
    }

    /// log_beta relation to log_gamma: log_beta(a,b) = log_gamma(a) + log_gamma(b) - log_gamma(a+b).
    #[test]
    fn log_beta_formula(a in 0.1..50.0f64, b in 0.1..50.0f64) {
        let lb = log_beta(a, b);
        let expected = log_gamma(a) + log_gamma(b) - log_gamma(a + b);
        prop_assert!(approx_eq(lb, expected, TOL),
            "log_beta({},{})={} != lg({})+lg({})-lg({})={}", a, b, lb, a, b, a+b, expected);
    }

    /// log_beta special case: B(1,1) = 1, so log_beta(1,1) = 0.
    #[test]
    fn log_beta_one_one(_dummy in 0..1i32) {
        let result = log_beta(1.0, 1.0);
        prop_assert!(approx_eq(result, 0.0, LGAMMA_TOL), "log_beta(1,1)={} should be 0", result);
    }
}

// ============================================================================
// log_binomial properties
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// log_binomial is symmetric: C(n,k) = C(n,n-k).
    #[test]
    fn log_binomial_symmetric(n in 1u64..50, k_frac in 0.0..1.0f64) {
        let k = ((n as f64) * k_frac) as u64;
        if k <= n {
            let lbn_k = log_binomial(n, k);
            let lbn_nk = log_binomial(n, n - k);
            prop_assert!(approx_eq(lbn_k, lbn_nk, TOL),
                "log_binomial({},{})={} != log_binomial({},{})={}", n, k, lbn_k, n, n-k, lbn_nk);
        }
    }

    /// Pascal's identity: C(n,k) = C(n-1,k-1) + C(n-1,k).
    #[test]
    fn log_binomial_pascal(n in 2u64..30, k_frac in 0.1..0.9f64) {
        let k = 1 + ((n as f64 - 2.0) * k_frac) as u64;
        if k >= 1 && k < n {
            let lhs = log_binomial(n, k).exp();
            let rhs = log_binomial(n - 1, k - 1).exp() + log_binomial(n - 1, k).exp();
            prop_assert!(approx_eq(lhs, rhs, TOL * 10.0),
                "C({},{})={} != C({},{}) + C({},{}) = {}", n, k, lhs, n-1, k-1, n-1, k, rhs);
        }
    }

    /// log_binomial boundary: C(n,0) = C(n,n) = 1, so log = 0.
    #[test]
    fn log_binomial_boundaries(n in 0u64..100) {
        let lb0 = log_binomial(n, 0);
        let lbn = log_binomial(n, n);
        prop_assert!(approx_eq(lb0, 0.0, TOL), "log_binomial({},0)={} should be 0", n, lb0);
        prop_assert!(approx_eq(lbn, 0.0, TOL), "log_binomial({},{})={} should be 0", n, n, lbn);
    }

    /// log_binomial returns NEG_INFINITY when k > n.
    #[test]
    fn log_binomial_invalid(n in 0u64..50, extra in 1u64..10) {
        let k = n + extra;
        let result = log_binomial(n, k);
        prop_assert!(result == f64::NEG_INFINITY,
            "log_binomial({},{})={} should be -inf when k > n", n, k, result);
    }
}

// ============================================================================
// log_factorial properties
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// log_factorial matches log_gamma(n+1).
    #[test]
    fn log_factorial_matches_log_gamma(n in 0u64..100) {
        let lf = log_factorial(n);
        let lg = log_gamma((n as f64) + 1.0);
        prop_assert!(approx_eq(lf, lg, LGAMMA_TOL),
            "log_factorial({})={} != log_gamma({})={}", n, lf, n+1, lg);
    }

    /// log_factorial is monotonically increasing for n > 0.
    #[test]
    fn log_factorial_monotonic(n in 1u64..99) {
        let lf_n = log_factorial(n);
        let lf_n1 = log_factorial(n + 1);
        prop_assert!(lf_n1 > lf_n, "log_factorial({})={} should be > log_factorial({})={}", n+1, lf_n1, n, lf_n);
    }
}

// ============================================================================
// Edge case tests
// ============================================================================

#[test]
fn edge_case_empty_log_sum_exp() {
    let result = log_sum_exp(&[]);
    assert!(result == f64::NEG_INFINITY, "lse([]) should be -inf");
}

#[test]
fn edge_case_nan_propagation() {
    assert!(log_sum_exp(&[1.0, f64::NAN]).is_nan());
    assert!(log_add_exp(1.0, f64::NAN).is_nan());
    assert!(log_sub_exp(f64::NAN, 0.0).is_nan());
    assert!(log_gamma(f64::NAN).is_nan());
}

#[test]
fn edge_case_infinity_handling() {
    assert!(log_sum_exp(&[f64::INFINITY, 1.0]) == f64::INFINITY);
    assert!(log_add_exp(f64::INFINITY, 1.0) == f64::INFINITY);
    assert!(log_gamma(f64::INFINITY) == f64::INFINITY);
}

#[test]
fn edge_case_log_gamma_negative_integers() {
    // Gamma is undefined at negative integers (poles)
    assert!(log_gamma(0.0).is_nan());
    assert!(log_gamma(-1.0).is_nan());
    assert!(log_gamma(-2.0).is_nan());
    assert!(log_gamma(-10.0).is_nan());
}

#[test]
fn known_values_log_gamma() {
    // Gamma(1) = 1, so log_gamma(1) = 0
    assert!((log_gamma(1.0) - 0.0).abs() < 1e-12);

    // Gamma(2) = 1, so log_gamma(2) = 0
    assert!((log_gamma(2.0) - 0.0).abs() < 1e-12);

    // Gamma(0.5) = sqrt(pi), so log_gamma(0.5) = 0.5 * ln(pi)
    let expected = 0.5 * std::f64::consts::PI.ln();
    assert!((log_gamma(0.5) - expected).abs() < 1e-10);

    // Gamma(5) = 24, so log_gamma(5) = ln(24)
    assert!((log_gamma(5.0) - 24.0_f64.ln()).abs() < 1e-10);
}

#[test]
fn known_values_log_binomial() {
    // C(5,2) = 10
    assert!((log_binomial(5, 2) - 10.0_f64.ln()).abs() < 1e-12);

    // C(10,5) = 252
    assert!((log_binomial(10, 5) - 252.0_f64.ln()).abs() < 1e-10);

    // C(20,10) = 184756
    assert!((log_binomial(20, 10) - 184756.0_f64.ln()).abs() < 1e-8);
}
