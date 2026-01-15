//! Beta-Binomial conjugate model for count-based evidence terms.
//!
//! This module provides posterior updates and predictive distributions for
//! count data (e.g., CPU occupancy - k busy ticks out of n total ticks).
//!
//! The model uses:
//! - Prior: `p ~ Beta(α, β)`
//! - Likelihood: `k | p ~ Binomial(n, p)` for count observations
//! - Posterior: `p | k,n ~ Beta(α + η·k, β + η·(n-k))`
//!
//! Where `η ∈ (0,1]` is a Safe-Bayes tempering factor to reduce overconfidence
//! when samples are correlated (e.g., CPU tick samples from the same scheduling window).
//!
//! The posterior predictive for a new observation window of size `n2` follows
//! the Beta-Binomial distribution.

use super::stable::log_beta;
use super::bernoulli::BetaParams;

/// Compute posterior parameters after observing k successes in n trials.
///
/// Uses η-tempering: posterior = Beta(α + η·k, β + η·(n-k))
///
/// This is identical to the Beta-Bernoulli case but documented separately
/// for clarity when working with count data.
///
/// # Arguments
/// * `prior` - Prior Beta parameters
/// * `k` - Number of successes (can be fractional for effective counts)
/// * `n` - Number of trials (can be fractional for effective counts)
/// * `eta` - Tempering factor in (0, 1]; use 1.0 for standard updates
///
/// # Returns
/// Posterior BetaParams, or None if inputs are invalid.
pub fn posterior_params(prior: &BetaParams, k: f64, n: f64, eta: f64) -> Option<BetaParams> {
    // Delegate to bernoulli since the update is identical
    super::bernoulli::posterior_params(prior, k, n, eta)
}

/// Compute the posterior predictive mean E[p | data].
///
/// For Beta(α', β') posterior: E[p] = α' / (α' + β')
pub fn predictive_mean(posterior: &BetaParams) -> f64 {
    posterior.mean()
}

/// Compute the posterior predictive variance Var[p | data].
pub fn predictive_variance(posterior: &BetaParams) -> f64 {
    posterior.variance()
}

/// Compute log marginal likelihood (evidence) for observed counts.
///
/// This is the probability of observing k successes in n trials under the prior:
///
/// P(k | n, α, β) = C(n, k) · B(α + η·k, β + η·(n-k)) / B(α, β)
///
/// In log form:
/// log P = log C(n, k) + log B(α + η·k, β + η·(n-k)) - log B(α, β)
///
/// This includes the binomial coefficient, unlike the Bernoulli case.
///
/// # Arguments
/// * `prior` - Prior Beta parameters
/// * `k` - Number of successes
/// * `n` - Number of trials
/// * `eta` - Tempering factor in (0, 1]
///
/// # Returns
/// Log marginal likelihood, or NAN for invalid inputs.
///
/// # Note
/// This function supports fractional k and n for effective sample size adjustments.
/// When using fractional values, the "binomial coefficient" is computed using
/// log Gamma functions which naturally extend to real numbers.
pub fn log_marginal_likelihood(prior: &BetaParams, k: f64, n: f64, eta: f64) -> f64 {
    // Validate inputs
    if k.is_nan() || n.is_nan() || eta.is_nan() {
        return f64::NAN;
    }
    if eta <= 0.0 || eta > 1.0 {
        return f64::NAN;
    }
    if k < 0.0 || n < 0.0 || k > n {
        return f64::NAN;
    }

    let post_alpha = prior.alpha + eta * k;
    let post_beta = prior.beta + eta * (n - k);

    // Validate posterior params
    if post_alpha <= 0.0 || post_beta <= 0.0 {
        return f64::NAN;
    }

    // Log binomial coefficient: log C(n, k) = log n! - log k! - log (n-k)!
    // Using lgamma for fractional support
    let log_binom = log_binom_coef(n, k);

    log_binom + log_beta(post_alpha, post_beta) - log_beta(prior.alpha, prior.beta)
}

/// Compute log binomial coefficient supporting fractional arguments.
///
/// log C(n, k) = lgamma(n+1) - lgamma(k+1) - lgamma(n-k+1)
///
/// For integer n, k this equals log(n! / (k! (n-k)!)).
fn log_binom_coef(n: f64, k: f64) -> f64 {
    use super::stable::log_gamma;

    if n < 0.0 || k < 0.0 || k > n {
        return f64::NEG_INFINITY;
    }
    if n == 0.0 && k == 0.0 {
        return 0.0; // C(0,0) = 1
    }

    log_gamma(n + 1.0) - log_gamma(k + 1.0) - log_gamma(n - k + 1.0)
}

/// Compute the log probability mass function for the Beta-Binomial distribution.
///
/// Given posterior Beta(α', β'), the predictive probability of observing
/// k2 successes in n2 future trials is:
///
/// P(k2 | n2, α', β') = C(n2, k2) · B(α' + k2, β' + (n2-k2)) / B(α', β')
///
/// # Arguments
/// * `posterior` - Posterior Beta parameters
/// * `k2` - Number of successes in new observation
/// * `n2` - Number of trials in new observation
pub fn log_predictive_pmf(posterior: &BetaParams, k2: f64, n2: f64) -> f64 {
    if k2.is_nan() || n2.is_nan() {
        return f64::NAN;
    }
    if k2 < 0.0 || n2 < 0.0 || k2 > n2 {
        return f64::NAN;
    }

    let log_binom = log_binom_coef(n2, k2);
    let alpha_new = posterior.alpha + k2;
    let beta_new = posterior.beta + (n2 - k2);

    log_binom + log_beta(alpha_new, beta_new) - log_beta(posterior.alpha, posterior.beta)
}

/// Compute the Beta-Binomial predictive mean for n2 future trials.
///
/// E[k2 | n2, α', β'] = n2 · α' / (α' + β')
pub fn predictive_count_mean(posterior: &BetaParams, n2: f64) -> f64 {
    n2 * posterior.mean()
}

/// Compute the Beta-Binomial predictive variance for n2 future trials.
///
/// Var[k2 | n2, α', β'] = n2 · (α'β' / (α'+β')²) · ((α'+β'+n2) / (α'+β'+1))
pub fn predictive_count_variance(posterior: &BetaParams, n2: f64) -> f64 {
    let alpha = posterior.alpha;
    let beta = posterior.beta;
    let sum = alpha + beta;

    n2 * (alpha * beta / (sum * sum)) * ((sum + n2) / (sum + 1.0))
}

/// Compute credible interval for the probability parameter.
///
/// Delegates to the Beta distribution inverse CDF.
pub fn credible_interval(posterior: &BetaParams, level: f64) -> (f64, f64) {
    super::bernoulli::credible_interval(posterior, level)
}

/// Compute the log Bayes factor comparing two hypotheses.
///
/// BF = P(data | H1) / P(data | H0)
pub fn log_bayes_factor(
    prior_h1: &BetaParams,
    prior_h0: &BetaParams,
    k: f64,
    n: f64,
    eta: f64,
) -> f64 {
    let log_ml_h1 = log_marginal_likelihood(prior_h1, k, n, eta);
    let log_ml_h0 = log_marginal_likelihood(prior_h0, k, n, eta);

    if log_ml_h1.is_nan() || log_ml_h0.is_nan() {
        return f64::NAN;
    }

    log_ml_h1 - log_ml_h0
}

/// Compute the effective sample size from the observed data.
///
/// With η-tempering, ESS = η · n
pub fn effective_sample_size(n: f64, eta: f64) -> f64 {
    eta * n
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
    // log_binom_coef tests
    // =======================================================================

    #[test]
    fn log_binom_coef_known_values() {
        // C(5, 2) = 10
        assert!(approx_eq(log_binom_coef(5.0, 2.0), 10.0f64.ln(), 1e-10));

        // C(10, 5) = 252
        assert!(approx_eq(log_binom_coef(10.0, 5.0), 252.0f64.ln(), 1e-10));

        // C(n, 0) = 1
        assert!(approx_eq(log_binom_coef(100.0, 0.0), 0.0, 1e-10));

        // C(n, n) = 1
        assert!(approx_eq(log_binom_coef(100.0, 100.0), 0.0, 1e-10));

        // C(0, 0) = 1
        assert!(approx_eq(log_binom_coef(0.0, 0.0), 0.0, 1e-10));
    }

    #[test]
    fn log_binom_coef_symmetry() {
        let n = 10.0;
        for k in 0..=10 {
            let k_f = k as f64;
            let left = log_binom_coef(n, k_f);
            let right = log_binom_coef(n, n - k_f);
            assert!(approx_eq(left, right, 1e-10), "C({}, {}) != C({}, {})", n, k_f, n, n - k_f);
        }
    }

    #[test]
    fn log_binom_coef_pascal() {
        // C(n, k) = C(n-1, k-1) + C(n-1, k)
        for n in 2..=10 {
            for k in 1..n {
                let n_f = n as f64;
                let k_f = k as f64;

                let lhs = log_binom_coef(n_f, k_f).exp();
                let rhs = log_binom_coef(n_f - 1.0, k_f - 1.0).exp()
                    + log_binom_coef(n_f - 1.0, k_f).exp();
                assert!(approx_eq(lhs, rhs, 1e-8),
                    "Pascal identity failed: C({},{}) = {} != {}", n, k, lhs, rhs);
            }
        }
    }

    // =======================================================================
    // posterior_params tests
    // =======================================================================

    #[test]
    fn posterior_params_standard_update() {
        let prior = BetaParams::uniform();
        let post = posterior_params(&prior, 30.0, 50.0, 1.0).unwrap();

        // Beta(1,1) + 30 successes, 20 failures -> Beta(31, 21)
        assert!(approx_eq(post.alpha, 31.0, 1e-12));
        assert!(approx_eq(post.beta, 21.0, 1e-12));
    }

    #[test]
    fn posterior_params_tempered() {
        let prior = BetaParams::uniform();
        let post_full = posterior_params(&prior, 40.0, 50.0, 1.0).unwrap();
        let post_tempered = posterior_params(&prior, 40.0, 50.0, 0.5).unwrap();

        // η=0.5 should give half the update
        assert!(approx_eq(post_tempered.alpha, 1.0 + 0.5 * 40.0, 1e-12));
        assert!(approx_eq(post_tempered.beta, 1.0 + 0.5 * 10.0, 1e-12));

        // Tempered should be less extreme
        assert!(post_tempered.mean() < post_full.mean());
    }

    // =======================================================================
    // log_marginal_likelihood tests
    // =======================================================================

    #[test]
    fn log_marginal_includes_binom_coef() {
        let prior = BetaParams::uniform();

        // For Beta(1,1) prior:
        // log P(k=2 | n=5) = log C(5,2) + log B(1+2, 1+3) - log B(1,1)
        //                 = log(10) + log B(3,4) - 0
        let log_ml = log_marginal_likelihood(&prior, 2.0, 5.0, 1.0);

        // B(3,4) = Γ(3)Γ(4)/Γ(7) = 2!·3!/6! = 2·6/720 = 1/60
        // log P = log(10) + log(1/60) = log(10/60) = log(1/6)
        let expected = (1.0 / 6.0f64).ln();
        assert!(approx_eq(log_ml, expected, 1e-8));
    }

    #[test]
    fn log_marginal_no_data() {
        let prior = BetaParams::new(2.0, 3.0).unwrap();
        let log_ml = log_marginal_likelihood(&prior, 0.0, 0.0, 1.0);
        // C(0,0) = 1, B(2,3)/B(2,3) = 1, so log = 0
        assert!(approx_eq(log_ml, 0.0, 1e-12));
    }

    #[test]
    fn log_marginal_all_successes() {
        let prior = BetaParams::uniform();
        let n = 10.0;

        // k=n: C(n,n) = 1
        // log P = log(1) + log B(1+n, 1) - log B(1,1)
        //       = log B(11, 1) = lgamma(11) + lgamma(1) - lgamma(12)
        //       = log(10!) - log(11!) = -log(11)
        let log_ml = log_marginal_likelihood(&prior, n, n, 1.0);
        let expected = -11.0f64.ln();
        assert!(approx_eq(log_ml, expected, 1e-8));
    }

    #[test]
    fn log_marginal_invalid_inputs() {
        let prior = BetaParams::uniform();

        assert!(log_marginal_likelihood(&prior, -1.0, 5.0, 1.0).is_nan());
        assert!(log_marginal_likelihood(&prior, 6.0, 5.0, 1.0).is_nan());
        assert!(log_marginal_likelihood(&prior, 2.0, 5.0, 0.0).is_nan());
        assert!(log_marginal_likelihood(&prior, f64::NAN, 5.0, 1.0).is_nan());
    }

    // =======================================================================
    // log_predictive_pmf tests
    // =======================================================================

    #[test]
    fn log_predictive_pmf_sums_to_one() {
        let posterior = BetaParams::new(3.0, 5.0).unwrap();
        let n2 = 10.0;

        let mut sum = 0.0;
        for k2 in 0..=10 {
            let log_p = log_predictive_pmf(&posterior, k2 as f64, n2);
            sum += log_p.exp();
        }

        assert!(approx_eq(sum, 1.0, 1e-8),
            "Predictive PMF doesn't sum to 1: {}", sum);
    }

    #[test]
    fn log_predictive_pmf_mode_near_mean() {
        let posterior = BetaParams::new(8.0, 4.0).unwrap();
        let n2 = 20.0;

        // Find the mode
        let mut max_log_p = f64::NEG_INFINITY;
        let mut mode_k = 0;
        for k2 in 0..=20 {
            let log_p = log_predictive_pmf(&posterior, k2 as f64, n2);
            if log_p > max_log_p {
                max_log_p = log_p;
                mode_k = k2;
            }
        }

        // Mode should be near the mean
        let mean = predictive_count_mean(&posterior, n2);
        assert!((mode_k as f64 - mean).abs() < 3.0,
            "Mode {} too far from mean {}", mode_k, mean);
    }

    #[test]
    fn log_predictive_pmf_invalid_inputs() {
        let posterior = BetaParams::uniform();

        assert!(log_predictive_pmf(&posterior, -1.0, 5.0).is_nan());
        assert!(log_predictive_pmf(&posterior, 6.0, 5.0).is_nan());
        assert!(log_predictive_pmf(&posterior, f64::NAN, 5.0).is_nan());
    }

    // =======================================================================
    // predictive_count_mean/variance tests
    // =======================================================================

    #[test]
    fn predictive_count_mean_scales_with_n2() {
        let posterior = BetaParams::new(3.0, 7.0).unwrap();

        let mean_10 = predictive_count_mean(&posterior, 10.0);
        let mean_20 = predictive_count_mean(&posterior, 20.0);

        // Mean should scale linearly with n2
        assert!(approx_eq(mean_20, 2.0 * mean_10, 1e-12));
    }

    #[test]
    fn predictive_count_variance_formula() {
        let posterior = BetaParams::new(2.0, 3.0).unwrap();
        let n2 = 10.0;

        let var = predictive_count_variance(&posterior, n2);

        // Manual calculation: n2 * (αβ/(α+β)²) * ((α+β+n2)/(α+β+1))
        // = 10 * (6/25) * (15/6) = 10 * 0.24 * 2.5 = 6.0
        assert!(approx_eq(var, 6.0, 1e-10));
    }

    #[test]
    fn predictive_count_variance_exceeds_binomial() {
        // Beta-Binomial has higher variance than Binomial due to uncertainty in p
        let posterior = BetaParams::new(5.0, 5.0).unwrap();
        let n2 = 100.0;
        let p = posterior.mean(); // 0.5

        let betabinom_var = predictive_count_variance(&posterior, n2);
        let binom_var = n2 * p * (1.0 - p); // npq

        // Beta-Binomial variance > Binomial variance
        assert!(betabinom_var > binom_var,
            "Beta-Binomial var {} should exceed Binomial var {}", betabinom_var, binom_var);
    }

    // =======================================================================
    // log_bayes_factor tests
    // =======================================================================

    #[test]
    fn log_bayes_factor_equal_priors() {
        let prior = BetaParams::uniform();
        let log_bf = log_bayes_factor(&prior, &prior, 5.0, 10.0, 1.0);
        assert!(approx_eq(log_bf, 0.0, 1e-12));
    }

    #[test]
    fn log_bayes_factor_favors_matching_prior() {
        let h_high = BetaParams::new(9.0, 1.0).unwrap(); // Prior favoring p≈0.9
        let h_low = BetaParams::new(1.0, 9.0).unwrap(); // Prior favoring p≈0.1

        // Observe 45 successes in 50 trials (90% success rate)
        let log_bf = log_bayes_factor(&h_high, &h_low, 45.0, 50.0, 1.0);

        // Should strongly favor h_high
        assert!(log_bf > 5.0, "log BF = {} should be >> 0", log_bf);
    }

    // =======================================================================
    // effective_sample_size tests
    // =======================================================================

    #[test]
    fn effective_sample_size_full() {
        assert!(approx_eq(effective_sample_size(100.0, 1.0), 100.0, 1e-12));
    }

    #[test]
    fn effective_sample_size_tempered() {
        assert!(approx_eq(effective_sample_size(100.0, 0.5), 50.0, 1e-12));
    }

    // =======================================================================
    // Golden value tests
    // =======================================================================

    #[test]
    fn golden_beta_1_1_k0_n10() {
        let prior = BetaParams::uniform();
        let log_ml = log_marginal_likelihood(&prior, 0.0, 10.0, 1.0);

        // C(10,0) = 1
        // B(1, 11) / B(1, 1) = Γ(1)Γ(11)/Γ(12) / 1 = 10!/11! = 1/11
        let expected = (1.0 / 11.0f64).ln();
        assert!(approx_eq(log_ml, expected, 1e-8));
    }

    #[test]
    fn golden_beta_1_1_k5_n10() {
        let prior = BetaParams::uniform();
        let log_ml = log_marginal_likelihood(&prior, 5.0, 10.0, 1.0);

        // C(10,5) = 252
        // B(6, 6) / B(1, 1) = 5!5!/11! = 14400/39916800 = 1/2772
        // log P = log(252) + log(1/2772) = log(252/2772) = log(1/11)
        let expected = (1.0 / 11.0f64).ln();
        assert!(approx_eq(log_ml, expected, 1e-8));
    }

    #[test]
    fn golden_beta_1_1_marginal_uniform() {
        // For Beta(1,1) prior (uniform), P(k | n) = 1/(n+1) for all k
        // This is a well-known result for the uniform prior
        let prior = BetaParams::uniform();
        let n = 10.0;

        for k in 0..=10 {
            let log_ml = log_marginal_likelihood(&prior, k as f64, n, 1.0);
            let expected = (1.0 / 11.0f64).ln();
            assert!(approx_eq(log_ml, expected, 1e-8),
                "k={}: log P = {} != {}", k, log_ml, expected);
        }
    }

    // =======================================================================
    // Robustness tests
    // =======================================================================

    #[test]
    fn robustness_large_n() {
        let prior = BetaParams::uniform();
        let n = 10000.0;
        let k = 5000.0;

        let log_ml = log_marginal_likelihood(&prior, k, n, 1.0);
        let post = posterior_params(&prior, k, n, 1.0).unwrap();

        assert!(!log_ml.is_nan());
        assert!(!log_ml.is_infinite());
        assert!(approx_eq(post.mean(), 0.5, 0.001));
    }

    #[test]
    fn robustness_small_prior() {
        let prior = BetaParams::new(0.01, 0.01).unwrap();
        let log_ml = log_marginal_likelihood(&prior, 5.0, 10.0, 1.0);

        assert!(!log_ml.is_nan());
    }

    #[test]
    fn robustness_eta_near_zero() {
        let prior = BetaParams::uniform();
        let post_full = posterior_params(&prior, 50.0, 100.0, 1.0).unwrap();
        let post_tempered = posterior_params(&prior, 50.0, 100.0, 0.01).unwrap();

        // With η ≈ 0, posterior should be close to prior
        assert!((post_tempered.alpha - prior.alpha).abs() < 1.0,
            "Tempered alpha {} should be close to prior {}", post_tempered.alpha, prior.alpha);
        assert!((post_tempered.beta - prior.beta).abs() < 1.0,
            "Tempered beta {} should be close to prior {}", post_tempered.beta, prior.beta);

        // Full update should be more extreme
        assert!((post_full.alpha - prior.alpha).abs() > (post_tempered.alpha - prior.alpha).abs());
    }
}
