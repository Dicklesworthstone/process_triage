//! Dirichlet-Multinomial conjugate model for categorical evidence terms.
//!
//! This module provides posterior updates and predictive distributions for
//! categorical data (e.g., process states R/S/D/Z/T, command categories).
//!
//! The model uses:
//! - Prior: `p = (p_1..p_K) ~ Dirichlet(α_1..α_K)`
//! - Likelihood: `n = (n_1..n_K) | p ~ Multinomial(N, p)` where `N = Σ_i n_i`
//! - Posterior: `p | n ~ Dirichlet(α_i + η·n_i)`
//!
//! Where `η ∈ (0,1]` is a Safe-Bayes tempering factor to reduce overconfidence
//! when categorical samples are correlated or sparse.

use super::stable::log_gamma;

/// Parameters for a Dirichlet distribution used in Dirichlet-Multinomial conjugate updates.
#[derive(Debug, Clone, PartialEq)]
pub struct DirichletParams {
    /// Concentration parameters (all must be > 0)
    pub alpha: Vec<f64>,
}

impl DirichletParams {
    /// Create new Dirichlet parameters with validation.
    ///
    /// Returns None if any parameter is non-positive, NaN, or if the vector is empty.
    pub fn new(alpha: Vec<f64>) -> Option<Self> {
        if alpha.is_empty() {
            return None;
        }
        for &a in &alpha {
            if a.is_nan() || a <= 0.0 {
                return None;
            }
        }
        Some(Self { alpha })
    }

    /// Create a symmetric Dirichlet with all α_i = value.
    pub fn symmetric(k: usize, value: f64) -> Option<Self> {
        if k == 0 || value.is_nan() || value <= 0.0 {
            return None;
        }
        Some(Self { alpha: vec![value; k] })
    }

    /// Create a uniform Dirichlet prior with all α_i = 1.
    pub fn uniform(k: usize) -> Option<Self> {
        Self::symmetric(k, 1.0)
    }

    /// Create a Jeffreys prior with all α_i = 0.5.
    pub fn jeffreys(k: usize) -> Option<Self> {
        Self::symmetric(k, 0.5)
    }

    /// Number of categories K.
    pub fn k(&self) -> usize {
        self.alpha.len()
    }

    /// Sum of all concentration parameters: α_0 = Σ_i α_i.
    pub fn concentration(&self) -> f64 {
        self.alpha.iter().sum()
    }

    /// Mean of the Dirichlet distribution: E[p_i] = α_i / α_0.
    pub fn mean(&self) -> Vec<f64> {
        let sum = self.concentration();
        self.alpha.iter().map(|a| a / sum).collect()
    }

    /// Variance of component i: Var[p_i] = α_i(α_0 - α_i) / (α_0²(α_0+1)).
    pub fn variance(&self, i: usize) -> f64 {
        if i >= self.alpha.len() {
            return f64::NAN;
        }
        let sum = self.concentration();
        let a_i = self.alpha[i];
        (a_i * (sum - a_i)) / (sum * sum * (sum + 1.0))
    }
}

/// Compute posterior parameters after observing counts.
///
/// Uses η-tempering: posterior_i = α_i + η·n_i
///
/// # Arguments
/// * `prior` - Prior Dirichlet parameters
/// * `counts` - Observed counts for each category (must have same length as prior)
/// * `eta` - Tempering factor in (0, 1]; use 1.0 for standard updates
///
/// # Returns
/// Posterior DirichletParams, or None if inputs are invalid.
pub fn posterior_params(
    prior: &DirichletParams,
    counts: &[f64],
    eta: f64,
) -> Option<DirichletParams> {
    // Validate inputs
    if counts.len() != prior.k() {
        return None;
    }
    if eta.is_nan() || eta <= 0.0 || eta > 1.0 {
        return None;
    }
    for &c in counts {
        if c.is_nan() || c < 0.0 {
            return None;
        }
    }

    let new_alpha: Vec<f64> = prior
        .alpha
        .iter()
        .zip(counts.iter())
        .map(|(&a, &n)| a + eta * n)
        .collect();

    DirichletParams::new(new_alpha)
}

/// Compute predictive probabilities for the next observation.
///
/// P(x = i | data) = α'_i / Σ_j α'_j
///
/// # Returns
/// Vector of probabilities summing to 1.
pub fn predictive_probs(posterior: &DirichletParams) -> Vec<f64> {
    posterior.mean()
}

/// Compute log predictive probability for a specific category.
///
/// # Arguments
/// * `posterior` - Posterior Dirichlet parameters
/// * `i` - Category index (0-based)
///
/// # Returns
/// Log probability of observing category i.
pub fn log_predictive(posterior: &DirichletParams, i: usize) -> f64 {
    if i >= posterior.k() {
        return f64::NAN;
    }
    let sum = posterior.concentration();
    posterior.alpha[i].ln() - sum.ln()
}

/// Compute log of the multivariate beta function.
///
/// log B(α) = Σ_i lgamma(α_i) - lgamma(Σ_i α_i)
pub fn log_multivariate_beta(alpha: &[f64]) -> f64 {
    if alpha.is_empty() {
        return f64::NAN;
    }
    for &a in alpha {
        if a.is_nan() || a <= 0.0 {
            return f64::NAN;
        }
    }

    let sum: f64 = alpha.iter().sum();
    let log_sum_gamma: f64 = alpha.iter().map(|&a| log_gamma(a)).sum();

    log_sum_gamma - log_gamma(sum)
}

/// Compute log marginal likelihood (evidence) for observed counts.
///
/// P(n | α) = [N! / Π_i n_i!] * B(α + η·n) / B(α)
///
/// In log form:
/// log P = log N! - Σ_i log n_i! + log B(α + η·n) - log B(α)
///
/// # Arguments
/// * `prior` - Prior Dirichlet parameters
/// * `counts` - Observed counts for each category
/// * `eta` - Tempering factor in (0, 1]
///
/// # Returns
/// Log marginal likelihood, or NAN for invalid inputs.
pub fn log_marginal_likelihood(prior: &DirichletParams, counts: &[f64], eta: f64) -> f64 {
    // Validate inputs
    if counts.len() != prior.k() {
        return f64::NAN;
    }
    if eta.is_nan() || eta <= 0.0 || eta > 1.0 {
        return f64::NAN;
    }
    for &c in counts {
        if c.is_nan() || c < 0.0 {
            return f64::NAN;
        }
    }

    // Total count N
    let n_total: f64 = counts.iter().sum();

    // Multinomial coefficient: log(N! / Π_i n_i!)
    let log_multinomial = log_gamma(n_total + 1.0)
        - counts.iter().map(|&n| log_gamma(n + 1.0)).sum::<f64>();

    // Posterior alpha values
    let post_alpha: Vec<f64> = prior
        .alpha
        .iter()
        .zip(counts.iter())
        .map(|(&a, &n)| a + eta * n)
        .collect();

    // Check all posterior values are valid
    for &a in &post_alpha {
        if a <= 0.0 {
            return f64::NAN;
        }
    }

    // log B(α + η·n) - log B(α)
    let log_b_post = log_multivariate_beta(&post_alpha);
    let log_b_prior = log_multivariate_beta(&prior.alpha);

    log_multinomial + log_b_post - log_b_prior
}

/// Compute the log Bayes factor comparing two hypotheses.
///
/// BF = P(data | H1) / P(data | H0)
pub fn log_bayes_factor(
    prior_h1: &DirichletParams,
    prior_h0: &DirichletParams,
    counts: &[f64],
    eta: f64,
) -> f64 {
    let log_ml_h1 = log_marginal_likelihood(prior_h1, counts, eta);
    let log_ml_h0 = log_marginal_likelihood(prior_h0, counts, eta);

    if log_ml_h1.is_nan() || log_ml_h0.is_nan() {
        return f64::NAN;
    }

    log_ml_h1 - log_ml_h0
}

/// Compute the effective sample size from the observed data.
///
/// With η-tempering, ESS = η · N
pub fn effective_sample_size(counts: &[f64], eta: f64) -> f64 {
    let n_total: f64 = counts.iter().sum();
    eta * n_total
}

/// Compute the log probability mass function for the Dirichlet-Multinomial.
///
/// Given posterior Dirichlet(α'), the predictive probability of observing
/// counts n2 in a future sample is:
///
/// P(n2 | α') = [N2! / Π_i n2_i!] * B(α' + n2) / B(α')
pub fn log_predictive_pmf(posterior: &DirichletParams, counts: &[f64]) -> f64 {
    // This is the same formula as log_marginal_likelihood with eta=1
    log_marginal_likelihood(posterior, counts, 1.0)
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

    fn vec_approx_eq(a: &[f64], b: &[f64], tol: f64) -> bool {
        if a.len() != b.len() {
            return false;
        }
        a.iter().zip(b.iter()).all(|(&x, &y)| approx_eq(x, y, tol))
    }

    // =======================================================================
    // DirichletParams tests
    // =======================================================================

    #[test]
    fn dirichlet_params_new_valid() {
        let p = DirichletParams::new(vec![1.0, 2.0, 3.0]);
        assert!(p.is_some());
        let p = p.unwrap();
        assert_eq!(p.k(), 3);
        assert!(approx_eq(p.concentration(), 6.0, 1e-12));
    }

    #[test]
    fn dirichlet_params_new_invalid() {
        assert!(DirichletParams::new(vec![]).is_none());
        assert!(DirichletParams::new(vec![0.0, 1.0]).is_none());
        assert!(DirichletParams::new(vec![-1.0, 1.0]).is_none());
        assert!(DirichletParams::new(vec![f64::NAN, 1.0]).is_none());
    }

    #[test]
    fn dirichlet_params_symmetric() {
        let p = DirichletParams::symmetric(5, 2.0).unwrap();
        assert_eq!(p.k(), 5);
        assert!(approx_eq(p.concentration(), 10.0, 1e-12));
        for &a in &p.alpha {
            assert!(approx_eq(a, 2.0, 1e-12));
        }
    }

    #[test]
    fn dirichlet_params_uniform() {
        let p = DirichletParams::uniform(3).unwrap();
        assert_eq!(p.alpha, vec![1.0, 1.0, 1.0]);
    }

    #[test]
    fn dirichlet_params_jeffreys() {
        let p = DirichletParams::jeffreys(3).unwrap();
        assert_eq!(p.alpha, vec![0.5, 0.5, 0.5]);
    }

    #[test]
    fn dirichlet_params_mean() {
        let p = DirichletParams::new(vec![1.0, 2.0, 3.0]).unwrap();
        let mean = p.mean();
        assert!(vec_approx_eq(&mean, &[1.0/6.0, 2.0/6.0, 3.0/6.0], 1e-12));
    }

    #[test]
    fn dirichlet_params_variance() {
        let p = DirichletParams::new(vec![2.0, 3.0, 5.0]).unwrap();
        // Var[p_0] = 2 * (10-2) / (100 * 11) = 16/1100
        assert!(approx_eq(p.variance(0), 16.0/1100.0, 1e-12));
    }

    // =======================================================================
    // posterior_params tests
    // =======================================================================

    #[test]
    fn posterior_params_standard_update() {
        let prior = DirichletParams::uniform(3).unwrap();
        let counts = vec![5.0, 3.0, 2.0];
        let post = posterior_params(&prior, &counts, 1.0).unwrap();

        assert!(vec_approx_eq(&post.alpha, &[6.0, 4.0, 3.0], 1e-12));
    }

    #[test]
    fn posterior_params_tempered() {
        let prior = DirichletParams::uniform(3).unwrap();
        let counts = vec![10.0, 0.0, 0.0];
        let post_full = posterior_params(&prior, &counts, 1.0).unwrap();
        let post_tempered = posterior_params(&prior, &counts, 0.5).unwrap();

        // Full: [11, 1, 1]
        assert!(vec_approx_eq(&post_full.alpha, &[11.0, 1.0, 1.0], 1e-12));
        // Tempered: [6, 1, 1]
        assert!(vec_approx_eq(&post_tempered.alpha, &[6.0, 1.0, 1.0], 1e-12));

        // Tempered mean should be less extreme
        assert!(post_tempered.mean()[0] < post_full.mean()[0]);
    }

    #[test]
    fn posterior_params_no_data() {
        let prior = DirichletParams::new(vec![2.0, 3.0, 5.0]).unwrap();
        let counts = vec![0.0, 0.0, 0.0];
        let post = posterior_params(&prior, &counts, 1.0).unwrap();

        assert!(vec_approx_eq(&post.alpha, &prior.alpha, 1e-12));
    }

    #[test]
    fn posterior_params_invalid_inputs() {
        let prior = DirichletParams::uniform(3).unwrap();

        // Wrong length
        assert!(posterior_params(&prior, &[1.0, 2.0], 1.0).is_none());
        // Invalid eta
        assert!(posterior_params(&prior, &[1.0, 2.0, 3.0], 0.0).is_none());
        assert!(posterior_params(&prior, &[1.0, 2.0, 3.0], 1.5).is_none());
        // Negative counts
        assert!(posterior_params(&prior, &[-1.0, 2.0, 3.0], 1.0).is_none());
        // NaN
        assert!(posterior_params(&prior, &[f64::NAN, 2.0, 3.0], 1.0).is_none());
    }

    // =======================================================================
    // predictive_probs tests
    // =======================================================================

    #[test]
    fn predictive_probs_uniform() {
        let post = DirichletParams::uniform(4).unwrap();
        let probs = predictive_probs(&post);
        assert!(vec_approx_eq(&probs, &[0.25, 0.25, 0.25, 0.25], 1e-12));
    }

    #[test]
    fn predictive_probs_sum_to_one() {
        let post = DirichletParams::new(vec![2.0, 3.0, 5.0, 7.0]).unwrap();
        let probs = predictive_probs(&post);
        let sum: f64 = probs.iter().sum();
        assert!(approx_eq(sum, 1.0, 1e-12));
    }

    #[test]
    fn predictive_probs_in_range() {
        let post = DirichletParams::new(vec![0.1, 1.0, 10.0]).unwrap();
        let probs = predictive_probs(&post);
        for p in probs {
            assert!(p >= 0.0 && p <= 1.0);
        }
    }

    // =======================================================================
    // log_predictive tests
    // =======================================================================

    #[test]
    fn log_predictive_matches_probs() {
        let post = DirichletParams::new(vec![2.0, 3.0, 5.0]).unwrap();
        let probs = predictive_probs(&post);

        for (i, &p) in probs.iter().enumerate() {
            let log_p = log_predictive(&post, i);
            assert!(approx_eq(log_p.exp(), p, 1e-12));
        }
    }

    #[test]
    fn log_predictive_invalid_index() {
        let post = DirichletParams::uniform(3).unwrap();
        assert!(log_predictive(&post, 5).is_nan());
    }

    // =======================================================================
    // log_multivariate_beta tests
    // =======================================================================

    #[test]
    fn log_multivariate_beta_k2_matches_beta() {
        // B(a, b) = Γ(a)Γ(b)/Γ(a+b)
        // log B([2, 3]) should equal lgamma(2) + lgamma(3) - lgamma(5)
        use super::super::stable::log_beta;

        let log_mb = log_multivariate_beta(&[2.0, 3.0]);
        let log_b = log_beta(2.0, 3.0);

        assert!(approx_eq(log_mb, log_b, 1e-10));
    }

    #[test]
    fn log_multivariate_beta_symmetric() {
        // B([1, 1, 1]) = Γ(1)³/Γ(3) = 1/2
        let log_mb = log_multivariate_beta(&[1.0, 1.0, 1.0]);
        assert!(approx_eq(log_mb, 0.5f64.ln(), 1e-10));
    }

    #[test]
    fn log_multivariate_beta_invalid() {
        assert!(log_multivariate_beta(&[]).is_nan());
        assert!(log_multivariate_beta(&[0.0, 1.0]).is_nan());
        assert!(log_multivariate_beta(&[-1.0, 1.0]).is_nan());
    }

    // =======================================================================
    // log_marginal_likelihood tests
    // =======================================================================

    #[test]
    fn log_marginal_uniform_prior_k3() {
        let prior = DirichletParams::uniform(3).unwrap();
        let counts = vec![1.0, 1.0, 1.0];

        // log P = log(3!) - 3*log(1!) + log B([2,2,2]) - log B([1,1,1])
        // = log(6) - 0 + (3*lgamma(2) - lgamma(6)) - (3*lgamma(1) - lgamma(3))
        // = log(6) + (0 - log(120)) - (0 - log(2))
        // = log(6) - log(120) + log(2) = log(6*2/120) = log(0.1)
        let log_ml = log_marginal_likelihood(&prior, &counts, 1.0);
        assert!(approx_eq(log_ml, 0.1f64.ln(), 1e-8));
    }

    #[test]
    fn log_marginal_no_data() {
        let prior = DirichletParams::new(vec![2.0, 3.0, 5.0]).unwrap();
        let counts = vec![0.0, 0.0, 0.0];
        let log_ml = log_marginal_likelihood(&prior, &counts, 1.0);
        // B(α)/B(α) = 1, N! / Π n_i! = 1
        assert!(approx_eq(log_ml, 0.0, 1e-12));
    }

    #[test]
    fn log_marginal_tempering() {
        let prior = DirichletParams::uniform(3).unwrap();
        let counts = vec![8.0, 1.0, 1.0];

        let log_ml_full = log_marginal_likelihood(&prior, &counts, 1.0);
        let log_ml_tempered = log_marginal_likelihood(&prior, &counts, 0.5);

        // Tempered should be different (effect depends on data)
        assert!((log_ml_full - log_ml_tempered).abs() > 0.1);
    }

    #[test]
    fn log_marginal_invalid_inputs() {
        let prior = DirichletParams::uniform(3).unwrap();

        assert!(log_marginal_likelihood(&prior, &[1.0, 2.0], 1.0).is_nan());
        assert!(log_marginal_likelihood(&prior, &[1.0, 2.0, 3.0], 0.0).is_nan());
        assert!(log_marginal_likelihood(&prior, &[-1.0, 2.0, 3.0], 1.0).is_nan());
    }

    // =======================================================================
    // log_bayes_factor tests
    // =======================================================================

    #[test]
    fn log_bayes_factor_equal_priors() {
        let prior = DirichletParams::uniform(3).unwrap();
        let counts = vec![5.0, 3.0, 2.0];
        let log_bf = log_bayes_factor(&prior, &prior, &counts, 1.0);
        assert!(approx_eq(log_bf, 0.0, 1e-12));
    }

    #[test]
    fn log_bayes_factor_favors_matching_prior() {
        let h_skewed = DirichletParams::new(vec![10.0, 1.0, 1.0]).unwrap();
        let h_uniform = DirichletParams::uniform(3).unwrap();

        // Observe data heavily skewed toward category 0
        let counts = vec![90.0, 5.0, 5.0];
        let log_bf = log_bayes_factor(&h_skewed, &h_uniform, &counts, 1.0);

        // h_skewed should be favored
        assert!(log_bf > 0.0);
    }

    // =======================================================================
    // effective_sample_size tests
    // =======================================================================

    #[test]
    fn effective_sample_size_full() {
        let counts = vec![10.0, 20.0, 30.0];
        assert!(approx_eq(effective_sample_size(&counts, 1.0), 60.0, 1e-12));
    }

    #[test]
    fn effective_sample_size_tempered() {
        let counts = vec![10.0, 20.0, 30.0];
        assert!(approx_eq(effective_sample_size(&counts, 0.5), 30.0, 1e-12));
    }

    // =======================================================================
    // Permutation invariance tests
    // =======================================================================

    #[test]
    fn permutation_invariance() {
        let prior = DirichletParams::uniform(3).unwrap();

        let counts1 = vec![5.0, 3.0, 2.0];
        let counts2 = vec![3.0, 2.0, 5.0];
        let counts3 = vec![2.0, 5.0, 3.0];

        let log_ml1 = log_marginal_likelihood(&prior, &counts1, 1.0);
        let log_ml2 = log_marginal_likelihood(&prior, &counts2, 1.0);
        let log_ml3 = log_marginal_likelihood(&prior, &counts3, 1.0);

        // Same total counts with uniform prior => same marginal
        assert!(approx_eq(log_ml1, log_ml2, 1e-10));
        assert!(approx_eq(log_ml2, log_ml3, 1e-10));
    }

    // =======================================================================
    // Robustness tests
    // =======================================================================

    #[test]
    fn robustness_large_counts() {
        let prior = DirichletParams::uniform(5).unwrap();
        let counts = vec![1000.0, 2000.0, 3000.0, 4000.0, 5000.0];

        let log_ml = log_marginal_likelihood(&prior, &counts, 1.0);
        let post = posterior_params(&prior, &counts, 1.0).unwrap();

        assert!(!log_ml.is_nan());
        assert!(!log_ml.is_infinite());
        assert!(!post.mean().iter().any(|x| x.is_nan()));
    }

    #[test]
    fn robustness_small_prior() {
        let prior = DirichletParams::new(vec![0.01, 0.01, 0.01]).unwrap();
        let counts = vec![1.0, 0.0, 0.0];

        let log_ml = log_marginal_likelihood(&prior, &counts, 1.0);
        assert!(!log_ml.is_nan());
    }

    #[test]
    fn robustness_many_categories() {
        let prior = DirichletParams::uniform(20).unwrap();
        let counts: Vec<f64> = (0..20).map(|i| i as f64).collect();

        let log_ml = log_marginal_likelihood(&prior, &counts, 1.0);
        assert!(!log_ml.is_nan());
        assert!(!log_ml.is_infinite());
    }

    // =======================================================================
    // Golden value tests
    // =======================================================================

    #[test]
    fn golden_uniform_k2_is_beta() {
        // For K=2, Dirichlet-Multinomial reduces to Beta-Binomial
        // P(n | α) with K=2 should match Beta-Binomial with same α
        let prior = DirichletParams::uniform(2).unwrap();
        let counts = vec![3.0, 7.0];

        let log_ml_dir = log_marginal_likelihood(&prior, &counts, 1.0);

        // Beta-Binomial with Beta(1,1) prior, k=3, n=10
        // P = C(10,3) * B(4, 8) / B(1, 1)
        // = 120 * (3!7!/11!) = 120 * 6*5040/39916800 = 120/1320 = 1/11
        let expected = (1.0 / 11.0f64).ln();
        assert!(approx_eq(log_ml_dir, expected, 1e-8));
    }
}
