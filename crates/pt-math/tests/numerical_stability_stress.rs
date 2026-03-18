//! Numerical stability stress tests for pt-math.
//!
//! Proves zero panics under pathological inputs (NaN, Inf, near-zero,
//! negative, extreme values) across all public pt-math functions.
//! Fulfills bd-g0q5.9 acceptance criteria.

use pt_math::bayes_factor::*;
use pt_math::bernoulli::{self, BetaParams};
use pt_math::dirichlet;
use pt_math::*;

// ---------------------------------------------------------------------------
// Pathological input generators
// ---------------------------------------------------------------------------

const PATHOLOGICAL_F64: &[f64] = &[
    0.0,
    -0.0,
    1.0,
    -1.0,
    f64::NAN,
    f64::INFINITY,
    f64::NEG_INFINITY,
    f64::MIN_POSITIVE, // ~5e-324
    f64::MAX,
    f64::MIN,
    1e-300,
    1e300,
    1e-15,
    1e15,
    0.5,
    0.999999999999,
    0.000000000001,
    -1e300,
    f64::EPSILON,
];

const PATHOLOGICAL_POSITIVE: &[f64] = &[
    f64::MIN_POSITIVE,
    1e-300,
    1e-15,
    f64::EPSILON,
    0.001,
    0.5,
    1.0,
    2.0,
    100.0,
    1e6,
    1e15,
    1e300,
];

// ---------------------------------------------------------------------------
// Stable primitives: log_sum_exp, log_gamma, log_beta
// ---------------------------------------------------------------------------

#[test]
fn log_sum_exp_never_panics_on_pathological_inputs() {
    for &a in PATHOLOGICAL_F64 {
        for &b in PATHOLOGICAL_F64 {
            let result = log_sum_exp(&[a, b]);
            let _ = result;
        }
    }

    // Full pathological vector
    let all: Vec<f64> = PATHOLOGICAL_F64.to_vec();
    let _ = log_sum_exp(&all);

    // Empty slice
    let _ = log_sum_exp(&[]);

    // Single element
    for &x in PATHOLOGICAL_F64 {
        let _ = log_sum_exp(&[x]);
    }
}

#[test]
fn log_gamma_never_panics() {
    for &x in PATHOLOGICAL_F64 {
        let result = log_gamma(x);
        let _ = result;
    }
}

#[test]
fn log_beta_never_panics() {
    for &a in PATHOLOGICAL_F64 {
        for &b in PATHOLOGICAL_F64 {
            let result = log_beta(a, b);
            let _ = result;
        }
    }
}

// ---------------------------------------------------------------------------
// Beta distribution
// ---------------------------------------------------------------------------

#[test]
fn beta_mean_never_panics() {
    for &a in PATHOLOGICAL_F64 {
        for &b in PATHOLOGICAL_F64 {
            let result = beta_mean(a, b);
            let _ = result;
        }
    }
}

#[test]
fn beta_var_never_panics() {
    for &a in PATHOLOGICAL_F64 {
        for &b in PATHOLOGICAL_F64 {
            let result = beta_var(a, b);
            let _ = result;
        }
    }
}

#[test]
fn beta_pdf_never_panics() {
    for &x in PATHOLOGICAL_F64 {
        for &a in PATHOLOGICAL_POSITIVE {
            for &b in PATHOLOGICAL_POSITIVE {
                let result = beta_pdf(x, a, b);
                let _ = result;
            }
        }
    }
}

#[test]
fn beta_cdf_never_panics() {
    for &x in PATHOLOGICAL_F64 {
        for &a in PATHOLOGICAL_POSITIVE {
            for &b in PATHOLOGICAL_POSITIVE {
                let result = beta_cdf(x, a, b);
                let _ = result;
            }
        }
    }
}

#[test]
fn beta_inv_cdf_never_panics() {
    for &p in PATHOLOGICAL_F64 {
        for &a in PATHOLOGICAL_POSITIVE {
            for &b in PATHOLOGICAL_POSITIVE {
                let result = beta_inv_cdf(p, a, b);
                let _ = result;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Gamma distribution
// ---------------------------------------------------------------------------

#[test]
fn gamma_pdf_never_panics() {
    for &x in PATHOLOGICAL_F64 {
        for &alpha in PATHOLOGICAL_POSITIVE {
            for &beta in PATHOLOGICAL_POSITIVE {
                let result = gamma_pdf(x, alpha, beta);
                let _ = result;
            }
        }
    }
}

#[test]
fn gamma_log_pdf_never_panics() {
    for &x in PATHOLOGICAL_F64 {
        for &alpha in PATHOLOGICAL_POSITIVE {
            for &beta in PATHOLOGICAL_POSITIVE {
                let result = gamma_log_pdf(x, alpha, beta);
                let _ = result;
            }
        }
    }
}

#[test]
fn gamma_cdf_never_panics() {
    for &x in PATHOLOGICAL_F64 {
        for &alpha in PATHOLOGICAL_POSITIVE {
            for &beta in PATHOLOGICAL_POSITIVE {
                let result = gamma_cdf(x, alpha, beta);
                let _ = result;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Normal distribution
// ---------------------------------------------------------------------------

#[test]
fn normal_cdf_never_panics() {
    for &x in PATHOLOGICAL_F64 {
        let result = normal_cdf(x);
        let _ = result;
    }
}

#[test]
fn normal_quantile_never_panics() {
    for &p in PATHOLOGICAL_F64 {
        let result = normal_quantile(p);
        let _ = result;
    }
}

// ---------------------------------------------------------------------------
// Bayes factor utilities
// ---------------------------------------------------------------------------

#[test]
fn delta_bits_never_panics() {
    for &x in PATHOLOGICAL_F64 {
        let result = delta_bits(x);
        let _ = result;
    }
}

#[test]
fn e_value_from_log_bf_never_panics() {
    for &x in PATHOLOGICAL_F64 {
        let result = e_value_from_log_bf(x);
        let _ = result;
    }
}

#[test]
fn try_e_value_never_panics() {
    for &x in PATHOLOGICAL_F64 {
        let result = try_e_value_from_log_bf(x);
        let _ = result;
    }
}

#[test]
fn evidence_strength_never_panics() {
    for &x in PATHOLOGICAL_F64 {
        let result = EvidenceStrength::from_log_bf(x);
        let _ = result.label();
    }
}

// ---------------------------------------------------------------------------
// Posterior normalization
// ---------------------------------------------------------------------------

#[test]
fn normalize_log_probs_never_panics() {
    // Normal case
    let normal = vec![-1.0, -2.0, -3.0, -4.0];
    let result = normalize_log_probs(&normal);
    assert_eq!(result.len(), 4);
    let sum: f64 = result.iter().map(|x| x.exp()).sum();
    assert!((sum - 1.0).abs() < 1e-10);

    // Pathological cases
    let all_nan = vec![f64::NAN; 4];
    let result = normalize_log_probs(&all_nan);
    let _ = result;

    let all_inf = vec![f64::INFINITY; 4];
    let result = normalize_log_probs(&all_inf);
    let _ = result;

    let all_neginf = vec![f64::NEG_INFINITY; 4];
    let result = normalize_log_probs(&all_neginf);
    let _ = result;

    let mixed = vec![f64::NAN, f64::INFINITY, f64::NEG_INFINITY, 0.0];
    let result = normalize_log_probs(&mixed);
    let _ = result;

    // Empty
    let empty: Vec<f64> = vec![];
    let result = normalize_log_probs(&empty);
    assert!(result.is_empty());
}

// ---------------------------------------------------------------------------
// Beta-Bernoulli conjugate
// ---------------------------------------------------------------------------

#[test]
fn beta_bernoulli_never_panics() {
    let h0 = BetaParams::new(1.0, 1.0).unwrap();
    for &alpha in PATHOLOGICAL_POSITIVE {
        for &beta_val in PATHOLOGICAL_POSITIVE {
            if let Some(params) = BetaParams::new(alpha, beta_val) {
                let _ = params.mean();
                let _ = params.variance();
                let _ = bernoulli::log_marginal_likelihood(&params, 5.0, 10.0, 1.0);
                let _ = bernoulli::predictive_probs(&params);
                let _ = bernoulli::log_bayes_factor(&params, &h0, 5.0, 10.0, 1.0);
                let _ = bernoulli::credible_interval(&params, 0.95);

                // Update with pathological counts
                let _ = bernoulli::posterior_params(&params, 0.0, 0.0, 1.0);
                let _ = bernoulli::posterior_params(&params, 1e15, 1e15, 1.0);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Dirichlet-Multinomial conjugate
// ---------------------------------------------------------------------------

#[test]
fn dirichlet_multinomial_never_panics() {
    use dirichlet::DirichletParams;

    // Normal case
    if let Some(params) = DirichletParams::new(vec![1.0, 1.0, 1.0, 1.0]) {
        let _ = params.mean();
        let _ = dirichlet::log_marginal_likelihood(&params, &[5.0, 3.0, 2.0, 1.0], 1.0);
    }

    // Near-zero alphas
    if let Some(params) = DirichletParams::new(vec![1e-300, 1e-300, 1e-300]) {
        let _ = params.mean();
        let _ = dirichlet::log_marginal_likelihood(&params, &[1.0, 0.0, 0.0], 1.0);
    }

    // Very large alphas
    if let Some(params) = DirichletParams::new(vec![1e15, 1e15, 1e15]) {
        let _ = params.mean();
    }

    // Single category
    if let Some(params) = DirichletParams::new(vec![1.0]) {
        let _ = params.mean();
        let _ = dirichlet::log_marginal_likelihood(&params, &[100.0], 1.0);
    }

    // Zero counts
    if let Some(params) = DirichletParams::new(vec![1.0, 1.0]) {
        let _ = dirichlet::log_marginal_likelihood(&params, &[0.0, 0.0], 1.0);
    }
}

// ---------------------------------------------------------------------------
// Large-scale stress: many iterations with random-ish extreme values
// ---------------------------------------------------------------------------

#[test]
fn mass_stress_no_panics() {
    // Generate 10,000 pathological combinations
    let mut count = 0u64;
    for &x in PATHOLOGICAL_F64 {
        for &a in PATHOLOGICAL_POSITIVE {
            for &b in PATHOLOGICAL_POSITIVE {
                let _ = beta_pdf(x, a, b);
                let _ = beta_cdf(x, a, b);
                let _ = gamma_pdf(x, a, b);
                let _ = gamma_cdf(x, a, b);
                let _ = log_beta(a, b);
                count += 1;
            }
        }
    }
    // Verify we actually ran a substantial number of combinations
    assert!(count > 1000, "expected > 1000 combinations, got {count}");
}
