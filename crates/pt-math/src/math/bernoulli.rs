//! Beta-Bernoulli conjugate model for binary evidence terms.
//!
//! This module provides posterior updates and predictive distributions for
//! binary observations (e.g., orphan status, TTY present, network activity).
//!
//! The model uses:
//! - Prior: `p ~ Beta(α, β)`
//! - Likelihood: `x | p ~ Bernoulli(p)` for binary observations
//! - Posterior after k successes in n trials: `p | data ~ Beta(α + η·k, β + η·(n-k))`
//!
//! Where `η ∈ (0,1]` is a Safe-Bayes tempering factor to reduce overconfidence
//! under model misspecification or correlated samples.

use super::stable::log_beta;

/// Parameters for a Beta distribution used in Beta-Bernoulli conjugate updates.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BetaParams {
    /// Shape parameter alpha (successes + prior)
    pub alpha: f64,
    /// Shape parameter beta (failures + prior)
    pub beta: f64,
}

impl BetaParams {
    /// Create new Beta parameters with validation.
    ///
    /// Returns None if parameters are invalid (non-positive or NaN).
    pub fn new(alpha: f64, beta: f64) -> Option<Self> {
        if alpha.is_nan() || beta.is_nan() || alpha <= 0.0 || beta <= 0.0 {
            return None;
        }
        Some(Self { alpha, beta })
    }

    /// Create Beta(1, 1) uniform prior.
    pub fn uniform() -> Self {
        Self { alpha: 1.0, beta: 1.0 }
    }

    /// Create a Jeffreys prior Beta(0.5, 0.5).
    pub fn jeffreys() -> Self {
        Self { alpha: 0.5, beta: 0.5 }
    }

    /// Posterior mean E[p] = α / (α + β).
    pub fn mean(&self) -> f64 {
        self.alpha / (self.alpha + self.beta)
    }

    /// Posterior variance Var[p] = αβ / ((α+β)²(α+β+1)).
    pub fn variance(&self) -> f64 {
        let sum = self.alpha + self.beta;
        (self.alpha * self.beta) / (sum * sum * (sum + 1.0))
    }
}

/// Compute posterior parameters after observing k successes in n trials.
///
/// Uses η-tempering: posterior = Beta(α + η·k, β + η·(n-k))
///
/// # Arguments
/// * `prior` - Prior Beta parameters
/// * `k` - Number of successes (can be fractional for effective counts)
/// * `n` - Number of trials (can be fractional for effective counts)
/// * `eta` - Tempering factor in (0, 1]; use 1.0 for standard updates
///
/// # Returns
/// Posterior BetaParams, or None if inputs are invalid.
///
/// # Example
/// ```
/// use pt_math::bernoulli::{BetaParams, posterior_params};
///
/// let prior = BetaParams::uniform();
/// let posterior = posterior_params(&prior, 7.0, 10.0, 1.0).unwrap();
/// assert!((posterior.mean() - 0.667).abs() < 0.01); // ~(1+7)/(2+10)
/// ```
pub fn posterior_params(prior: &BetaParams, k: f64, n: f64, eta: f64) -> Option<BetaParams> {
    // Validate inputs
    if k.is_nan() || n.is_nan() || eta.is_nan() {
        return None;
    }
    if eta <= 0.0 || eta > 1.0 {
        return None;
    }
    if k < 0.0 || n < 0.0 || k > n {
        return None;
    }

    let new_alpha = prior.alpha + eta * k;
    let new_beta = prior.beta + eta * (n - k);

    BetaParams::new(new_alpha, new_beta)
}

/// Compute predictive probabilities P(x=0|data) and P(x=1|data).
///
/// For a Beta(α', β') posterior, the predictive for the next observation is:
/// - P(x=1) = α' / (α' + β')
/// - P(x=0) = β' / (α' + β')
///
/// # Returns
/// Tuple (p0, p1) where p0 + p1 = 1.
pub fn predictive_probs(posterior: &BetaParams) -> (f64, f64) {
    let sum = posterior.alpha + posterior.beta;
    let p1 = posterior.alpha / sum;
    let p0 = posterior.beta / sum;
    (p0, p1)
}

/// Compute log predictive probability for a specific outcome.
///
/// # Arguments
/// * `posterior` - Posterior Beta parameters
/// * `x` - Outcome (0 or 1)
///
/// # Returns
/// Log probability of observing x given the posterior.
pub fn log_predictive(posterior: &BetaParams, x: u8) -> f64 {
    let sum = posterior.alpha + posterior.beta;
    match x {
        0 => posterior.beta.ln() - sum.ln(),
        1 => posterior.alpha.ln() - sum.ln(),
        _ => f64::NAN,
    }
}

/// Compute log marginal likelihood (evidence) for observed data.
///
/// This is the probability of observing k successes in n trials under the prior:
/// P(k, n | α, β) = B(α + η·k, β + η·(n-k)) / B(α, β)
///
/// In log form:
/// log P = log B(α + η·k, β + η·(n-k)) - log B(α, β)
///
/// This term is used for Bayes factor computation and evidence ledger attribution.
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
/// # Example
/// ```
/// use pt_math::bernoulli::{BetaParams, log_marginal_likelihood};
///
/// let prior = BetaParams::uniform();
/// let log_ml = log_marginal_likelihood(&prior, 5.0, 10.0, 1.0);
/// // For Beta(1,1) prior: log P = log B(6, 6) - log B(1, 1)
/// // = log(Γ(6)Γ(6)/Γ(12)) - log(1) = log(5!·5!/11!) ≈ -7.93
/// assert!((log_ml - (-7.93)).abs() < 0.01);
/// ```
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

    log_beta(post_alpha, post_beta) - log_beta(prior.alpha, prior.beta)
}

/// Compute the log Bayes factor comparing two hypotheses.
///
/// BF = P(data | H1) / P(data | H0)
/// log BF = log_marginal(H1) - log_marginal(H0)
///
/// # Arguments
/// * `prior_h1` - Prior under hypothesis H1
/// * `prior_h0` - Prior under hypothesis H0
/// * `k` - Number of successes
/// * `n` - Number of trials
/// * `eta` - Tempering factor
///
/// # Returns
/// Log Bayes factor. Positive values favor H1, negative favor H0.
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

/// Compute credible interval for the probability parameter.
///
/// Uses the Beta CDF inverse (quantile function) to compute bounds.
///
/// # Arguments
/// * `posterior` - Posterior Beta parameters
/// * `level` - Credible level in (0, 1), e.g., 0.95 for 95% CI
///
/// # Returns
/// Tuple (lower, upper) bounds of the credible interval.
pub fn credible_interval(posterior: &BetaParams, level: f64) -> (f64, f64) {
    use super::beta::beta_inv_cdf;

    if level.is_nan() || level <= 0.0 || level >= 1.0 {
        return (f64::NAN, f64::NAN);
    }

    let tail = (1.0 - level) / 2.0;
    let lower = beta_inv_cdf(tail, posterior.alpha, posterior.beta);
    let upper = beta_inv_cdf(1.0 - tail, posterior.alpha, posterior.beta);

    (lower, upper)
}

/// Compute the effective sample size from posterior parameters.
///
/// For Beta(α, β), effective sample size is α + β - prior concentration.
/// With uniform prior Beta(1,1), ESS = α + β - 2.
pub fn effective_sample_size(posterior: &BetaParams, prior: &BetaParams) -> f64 {
    (posterior.alpha + posterior.beta) - (prior.alpha + prior.beta)
}

/// Batch update: compute posterior from multiple independent observations.
///
/// This is equivalent to calling posterior_params once with summed counts.
pub fn batch_update(prior: &BetaParams, observations: &[(f64, f64)], eta: f64) -> Option<BetaParams> {
    let mut total_k = 0.0;
    let mut total_n = 0.0;

    for &(k, n) in observations {
        if k.is_nan() || n.is_nan() || k < 0.0 || n < 0.0 || k > n {
            return None;
        }
        total_k += k;
        total_n += n;
    }

    posterior_params(prior, total_k, total_n, eta)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx_eq(a: f64, b: f64, tol: f64) -> bool {
        if a.is_nan() && b.is_nan() {
            return true; // Both NaN is considered equal for testing
        }
        if a.is_nan() || b.is_nan() {
            return false;
        }
        (a - b).abs() <= tol
    }

    // =======================================================================
    // BetaParams tests
    // =======================================================================

    #[test]
    fn beta_params_new_valid() {
        let p = BetaParams::new(2.0, 3.0);
        assert!(p.is_some());
        let p = p.unwrap();
        assert_eq!(p.alpha, 2.0);
        assert_eq!(p.beta, 3.0);
    }

    #[test]
    fn beta_params_new_invalid() {
        assert!(BetaParams::new(0.0, 1.0).is_none());
        assert!(BetaParams::new(-1.0, 1.0).is_none());
        assert!(BetaParams::new(1.0, 0.0).is_none());
        assert!(BetaParams::new(f64::NAN, 1.0).is_none());
    }

    #[test]
    fn beta_params_uniform() {
        let p = BetaParams::uniform();
        assert_eq!(p.alpha, 1.0);
        assert_eq!(p.beta, 1.0);
        assert!(approx_eq(p.mean(), 0.5, 1e-12));
    }

    #[test]
    fn beta_params_jeffreys() {
        let p = BetaParams::jeffreys();
        assert_eq!(p.alpha, 0.5);
        assert_eq!(p.beta, 0.5);
        assert!(approx_eq(p.mean(), 0.5, 1e-12));
    }

    #[test]
    fn beta_params_mean_and_variance() {
        let p = BetaParams::new(2.0, 5.0).unwrap();
        assert!(approx_eq(p.mean(), 2.0 / 7.0, 1e-12));
        // Var = 2*5 / (7^2 * 8) = 10 / 392
        assert!(approx_eq(p.variance(), 10.0 / 392.0, 1e-12));
    }

    // =======================================================================
    // posterior_params tests
    // =======================================================================

    #[test]
    fn posterior_params_standard_update() {
        let prior = BetaParams::uniform();
        let post = posterior_params(&prior, 7.0, 10.0, 1.0).unwrap();
        // Beta(1,1) + 7 successes, 3 failures -> Beta(8, 4)
        assert!(approx_eq(post.alpha, 8.0, 1e-12));
        assert!(approx_eq(post.beta, 4.0, 1e-12));
        // Mean should be 8/12 = 2/3
        assert!(approx_eq(post.mean(), 2.0 / 3.0, 1e-12));
    }

    #[test]
    fn posterior_params_tempered_update() {
        let prior = BetaParams::uniform();
        let post_full = posterior_params(&prior, 10.0, 10.0, 1.0).unwrap();
        let post_tempered = posterior_params(&prior, 10.0, 10.0, 0.5).unwrap();

        // Full update: Beta(1+10, 1+0) = Beta(11, 1)
        assert!(approx_eq(post_full.alpha, 11.0, 1e-12));
        assert!(approx_eq(post_full.beta, 1.0, 1e-12));

        // Tempered update: Beta(1+5, 1+0) = Beta(6, 1)
        assert!(approx_eq(post_tempered.alpha, 6.0, 1e-12));
        assert!(approx_eq(post_tempered.beta, 1.0, 1e-12));

        // Tempered should be less extreme
        assert!(post_tempered.mean() < post_full.mean());
    }

    #[test]
    fn posterior_params_no_data() {
        let prior = BetaParams::new(2.0, 3.0).unwrap();
        let post = posterior_params(&prior, 0.0, 0.0, 1.0).unwrap();
        assert!(approx_eq(post.alpha, prior.alpha, 1e-12));
        assert!(approx_eq(post.beta, prior.beta, 1e-12));
    }

    #[test]
    fn posterior_params_invalid_inputs() {
        let prior = BetaParams::uniform();

        // Invalid eta
        assert!(posterior_params(&prior, 1.0, 2.0, 0.0).is_none());
        assert!(posterior_params(&prior, 1.0, 2.0, 1.5).is_none());

        // k > n
        assert!(posterior_params(&prior, 5.0, 3.0, 1.0).is_none());

        // Negative values
        assert!(posterior_params(&prior, -1.0, 2.0, 1.0).is_none());
        assert!(posterior_params(&prior, 1.0, -2.0, 1.0).is_none());

        // NaN
        assert!(posterior_params(&prior, f64::NAN, 2.0, 1.0).is_none());
    }

    // =======================================================================
    // predictive_probs tests
    // =======================================================================

    #[test]
    fn predictive_probs_uniform() {
        let post = BetaParams::uniform();
        let (p0, p1) = predictive_probs(&post);
        assert!(approx_eq(p0, 0.5, 1e-12));
        assert!(approx_eq(p1, 0.5, 1e-12));
        assert!(approx_eq(p0 + p1, 1.0, 1e-12));
    }

    #[test]
    fn predictive_probs_after_data() {
        let post = BetaParams::new(8.0, 4.0).unwrap();
        let (p0, p1) = predictive_probs(&post);
        assert!(approx_eq(p0, 4.0 / 12.0, 1e-12));
        assert!(approx_eq(p1, 8.0 / 12.0, 1e-12));
        assert!(approx_eq(p0 + p1, 1.0, 1e-12));
    }

    #[test]
    fn predictive_probs_sum_to_one() {
        for alpha in [0.1, 0.5, 1.0, 2.0, 10.0] {
            for beta in [0.1, 0.5, 1.0, 2.0, 10.0] {
                let post = BetaParams::new(alpha, beta).unwrap();
                let (p0, p1) = predictive_probs(&post);
                assert!(approx_eq(p0 + p1, 1.0, 1e-12),
                    "α={}, β={}: p0+p1={}", alpha, beta, p0 + p1);
            }
        }
    }

    // =======================================================================
    // log_predictive tests
    // =======================================================================

    #[test]
    fn log_predictive_matches_probs() {
        let post = BetaParams::new(3.0, 7.0).unwrap();
        let (p0, p1) = predictive_probs(&post);

        let log_p0 = log_predictive(&post, 0);
        let log_p1 = log_predictive(&post, 1);

        assert!(approx_eq(log_p0.exp(), p0, 1e-12));
        assert!(approx_eq(log_p1.exp(), p1, 1e-12));
    }

    #[test]
    fn log_predictive_invalid_outcome() {
        let post = BetaParams::uniform();
        assert!(log_predictive(&post, 2).is_nan());
        assert!(log_predictive(&post, 255).is_nan());
    }

    // =======================================================================
    // log_marginal_likelihood tests
    // =======================================================================

    #[test]
    fn log_marginal_uniform_prior() {
        let prior = BetaParams::uniform();

        // For Beta(1,1) prior with k successes in n trials:
        // P(k|n) = B(1+k, 1+(n-k)) / B(1,1) = B(1+k, 1+(n-k))
        // = k!(n-k)! / (n+1)!

        // k=0, n=1: B(1,2)/B(1,1) = Γ(1)Γ(2)/Γ(3) = 0.5
        let log_ml = log_marginal_likelihood(&prior, 0.0, 1.0, 1.0);
        assert!(approx_eq(log_ml, 0.5f64.ln(), 1e-10));

        // k=1, n=1: B(2,1)/B(1,1) = 0.5
        let log_ml = log_marginal_likelihood(&prior, 1.0, 1.0, 1.0);
        assert!(approx_eq(log_ml, 0.5f64.ln(), 1e-10));

        // k=5, n=10: B(6,6)/B(1,1) = 5!5!/11! ≈ 3.607e-4
        let log_ml = log_marginal_likelihood(&prior, 5.0, 10.0, 1.0);
        let expected = (120.0 * 120.0 / 39916800.0f64).ln(); // 5!*5!/11! ≈ -7.93
        assert!(approx_eq(log_ml, expected, 1e-6));
    }

    #[test]
    fn log_marginal_no_data() {
        let prior = BetaParams::new(2.0, 3.0).unwrap();
        let log_ml = log_marginal_likelihood(&prior, 0.0, 0.0, 1.0);
        // B(2,3)/B(2,3) = 1, so log = 0
        assert!(approx_eq(log_ml, 0.0, 1e-12));
    }

    #[test]
    fn log_marginal_tempering_reduces_evidence() {
        let prior = BetaParams::uniform();

        // Strong evidence: 9 successes in 10 trials
        let log_ml_full = log_marginal_likelihood(&prior, 9.0, 10.0, 1.0);
        let log_ml_tempered = log_marginal_likelihood(&prior, 9.0, 10.0, 0.5);

        // Tempered should have less extreme evidence (closer to 0)
        // With η=0.5, effective data is 4.5 successes in 5 trials
        assert!(log_ml_tempered.abs() < log_ml_full.abs());
    }

    #[test]
    fn log_marginal_invalid_inputs() {
        let prior = BetaParams::uniform();

        assert!(log_marginal_likelihood(&prior, -1.0, 2.0, 1.0).is_nan());
        assert!(log_marginal_likelihood(&prior, 5.0, 3.0, 1.0).is_nan());
        assert!(log_marginal_likelihood(&prior, 1.0, 2.0, 0.0).is_nan());
        assert!(log_marginal_likelihood(&prior, f64::NAN, 2.0, 1.0).is_nan());
    }

    // =======================================================================
    // log_bayes_factor tests
    // =======================================================================

    #[test]
    fn log_bayes_factor_equal_priors() {
        let prior = BetaParams::uniform();
        let log_bf = log_bayes_factor(&prior, &prior, 5.0, 10.0, 1.0);
        // Same prior -> BF = 1 -> log BF = 0
        assert!(approx_eq(log_bf, 0.0, 1e-12));
    }

    #[test]
    fn log_bayes_factor_different_priors() {
        let h1 = BetaParams::new(10.0, 1.0).unwrap(); // Prior favoring p≈0.9
        let h0 = BetaParams::new(1.0, 10.0).unwrap(); // Prior favoring p≈0.1

        // Observe 9 successes in 10 trials
        let log_bf = log_bayes_factor(&h1, &h0, 9.0, 10.0, 1.0);

        // Data strongly supports H1, so log BF should be positive
        assert!(log_bf > 0.0);
    }

    // =======================================================================
    // credible_interval tests
    // =======================================================================

    #[test]
    fn credible_interval_symmetric_posterior() {
        let post = BetaParams::uniform();
        let (lo, hi) = credible_interval(&post, 0.95);

        // Symmetric around 0.5
        assert!(approx_eq(lo, 0.025, 1e-3));
        assert!(approx_eq(hi, 0.975, 1e-3));
    }

    #[test]
    fn credible_interval_contains_mean() {
        let post = BetaParams::new(8.0, 4.0).unwrap();
        let mean = post.mean();

        for level in [0.5, 0.9, 0.95, 0.99] {
            let (lo, hi) = credible_interval(&post, level);
            assert!(lo < mean && mean < hi,
                "level={}: [{}, {}] should contain mean {}", level, lo, hi, mean);
        }
    }

    #[test]
    fn credible_interval_invalid_level() {
        let post = BetaParams::uniform();

        let (lo, hi) = credible_interval(&post, 0.0);
        assert!(lo.is_nan() && hi.is_nan());

        let (lo, hi) = credible_interval(&post, 1.0);
        assert!(lo.is_nan() && hi.is_nan());

        let (lo, hi) = credible_interval(&post, f64::NAN);
        assert!(lo.is_nan() && hi.is_nan());
    }

    // =======================================================================
    // effective_sample_size tests
    // =======================================================================

    #[test]
    fn effective_sample_size_calculation() {
        let prior = BetaParams::uniform();
        let post = posterior_params(&prior, 7.0, 10.0, 1.0).unwrap();
        let ess = effective_sample_size(&post, &prior);
        assert!(approx_eq(ess, 10.0, 1e-12));
    }

    #[test]
    fn effective_sample_size_tempered() {
        let prior = BetaParams::uniform();
        let post = posterior_params(&prior, 7.0, 10.0, 0.5).unwrap();
        let ess = effective_sample_size(&post, &prior);
        // With η=0.5, ESS should be 5.0
        assert!(approx_eq(ess, 5.0, 1e-12));
    }

    // =======================================================================
    // batch_update tests
    // =======================================================================

    #[test]
    fn batch_update_equivalent_to_single() {
        let prior = BetaParams::uniform();

        // Single update with 7 successes in 10 trials
        let single = posterior_params(&prior, 7.0, 10.0, 1.0).unwrap();

        // Batch update with same total
        let batch = batch_update(&prior, &[(3.0, 5.0), (4.0, 5.0)], 1.0).unwrap();

        assert!(approx_eq(single.alpha, batch.alpha, 1e-12));
        assert!(approx_eq(single.beta, batch.beta, 1e-12));
    }

    #[test]
    fn batch_update_empty() {
        let prior = BetaParams::uniform();
        let post = batch_update(&prior, &[], 1.0).unwrap();
        assert!(approx_eq(post.alpha, prior.alpha, 1e-12));
        assert!(approx_eq(post.beta, prior.beta, 1e-12));
    }

    // =======================================================================
    // Golden value tests from known references
    // =======================================================================

    #[test]
    fn golden_beta_1_1_k0_n1() {
        // Beta(1,1) prior, observe 0 successes in 1 trial
        let prior = BetaParams::uniform();
        let post = posterior_params(&prior, 0.0, 1.0, 1.0).unwrap();

        // Posterior: Beta(1, 2)
        assert!(approx_eq(post.alpha, 1.0, 1e-12));
        assert!(approx_eq(post.beta, 2.0, 1e-12));

        // Predictive mean: 1/3
        assert!(approx_eq(post.mean(), 1.0 / 3.0, 1e-12));
    }

    #[test]
    fn golden_beta_1_1_k1_n1() {
        // Beta(1,1) prior, observe 1 success in 1 trial
        let prior = BetaParams::uniform();
        let post = posterior_params(&prior, 1.0, 1.0, 1.0).unwrap();

        // Posterior: Beta(2, 1)
        assert!(approx_eq(post.alpha, 2.0, 1e-12));
        assert!(approx_eq(post.beta, 1.0, 1e-12));

        // Predictive mean: 2/3
        assert!(approx_eq(post.mean(), 2.0 / 3.0, 1e-12));
    }

    #[test]
    fn golden_beta_1_1_k0_n10() {
        let prior = BetaParams::uniform();
        let post = posterior_params(&prior, 0.0, 10.0, 1.0).unwrap();

        // Posterior: Beta(1, 11)
        assert!(approx_eq(post.alpha, 1.0, 1e-12));
        assert!(approx_eq(post.beta, 11.0, 1e-12));
        assert!(approx_eq(post.mean(), 1.0 / 12.0, 1e-12));
    }

    #[test]
    fn golden_beta_1_1_k5_n10() {
        let prior = BetaParams::uniform();
        let post = posterior_params(&prior, 5.0, 10.0, 1.0).unwrap();

        // Posterior: Beta(6, 6)
        assert!(approx_eq(post.alpha, 6.0, 1e-12));
        assert!(approx_eq(post.beta, 6.0, 1e-12));
        assert!(approx_eq(post.mean(), 0.5, 1e-12));
    }

    #[test]
    fn golden_beta_1_1_k10_n10() {
        let prior = BetaParams::uniform();
        let post = posterior_params(&prior, 10.0, 10.0, 1.0).unwrap();

        // Posterior: Beta(11, 1)
        assert!(approx_eq(post.alpha, 11.0, 1e-12));
        assert!(approx_eq(post.beta, 1.0, 1e-12));
        assert!(approx_eq(post.mean(), 11.0 / 12.0, 1e-12));
    }

    // =======================================================================
    // Monotonicity property tests
    // =======================================================================

    #[test]
    fn monotonicity_increasing_k_increases_p1() {
        let prior = BetaParams::uniform();
        let n = 10.0;

        let mut prev_mean = 0.0;
        for k in 0..=10 {
            let post = posterior_params(&prior, k as f64, n, 1.0).unwrap();
            let (_, p1) = predictive_probs(&post);
            assert!(p1 >= prev_mean, "k={}: p1={} should be >= {}", k, p1, prev_mean);
            prev_mean = p1;
        }
    }

    // =======================================================================
    // Extreme regime tests (robustness)
    // =======================================================================

    #[test]
    fn extreme_large_n() {
        let prior = BetaParams::uniform();
        let n = 10000.0;
        let k = 5000.0;

        let post = posterior_params(&prior, k, n, 1.0).unwrap();
        let log_ml = log_marginal_likelihood(&prior, k, n, 1.0);

        // Should not overflow/NaN
        assert!(!post.alpha.is_nan());
        assert!(!post.beta.is_nan());
        assert!(!log_ml.is_nan());

        // Mean should be close to k/n
        assert!(approx_eq(post.mean(), 0.5, 0.01));
    }

    #[test]
    fn extreme_small_alpha_beta() {
        let prior = BetaParams::new(0.01, 0.01).unwrap();
        let post = posterior_params(&prior, 1.0, 2.0, 1.0).unwrap();

        // Should not NaN
        assert!(!post.alpha.is_nan());
        assert!(!post.beta.is_nan());
    }

    #[test]
    fn extreme_eta_near_zero() {
        let prior = BetaParams::uniform();
        let post = posterior_params(&prior, 100.0, 100.0, 0.001).unwrap();

        // With η ≈ 0, posterior should be close to prior
        assert!((post.alpha - prior.alpha).abs() < 0.2);
        assert!((post.beta - prior.beta).abs() < 0.2);
    }
}
