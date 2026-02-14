//! Composite-hypothesis testing tools (mixture SPRT / GLR).
//!
//! This module provides composite-hypothesis testing mechanisms for cases where
//! the simple-vs-simple SPRT assumption is insufficient:
//!
//! - **Mixture SPRT**: When the alternative H1 is a mixture over conjugate parameters
//!   rather than a point hypothesis.
//! - **GLR (Generalized Likelihood Ratio)**: Uses maximum likelihood under composite
//!   hypotheses.
//!
//! These tools emit e-values that can be used with e-FDR and alpha-investing for
//! sequential testing with multiple process candidates.
//!
//! # Background
//!
//! Standard SPRT assumes H0: θ = θ_0 vs H1: θ = θ_1 (simple vs simple).
//! In process triage, the alternative "abandoned" is actually a composite hypothesis
//! with uncertainty over exact parameters.
//!
//! Mixture SPRT averages over the parameter uncertainty:
//! ```text
//! Λ_n = Π_{i=1}^n [∫ p(x_i|θ) dG(θ)] / p(x_i|θ_0)
//! ```
//! where G is a prior/mixture distribution over the alternative parameters.
//!
//! This produces valid e-values: E\[Λ_n\] ≤ 1 under H0, enabling optional stopping.

use pt_math::bayes_factor::{e_value_from_log_bf, EvidenceStrength, EvidenceSummary};
use serde::Serialize;
use thiserror::Error;

/// Errors raised during composite-hypothesis testing.
#[derive(Debug, Error)]
pub enum CompositeTestError {
    #[error("invalid log-likelihood: {message}")]
    InvalidLogLikelihood { message: String },
    #[error("insufficient observations: need at least {min}, got {got}")]
    InsufficientObservations { min: usize, got: usize },
    #[error("numerical overflow in GLR computation")]
    NumericalOverflow,
}

/// Result of a mixture-SPRT test.
#[derive(Debug, Clone, Serialize)]
pub struct MixtureSprtResult {
    /// Cumulative log-likelihood ratio (mixture SPRT statistic).
    pub log_lambda: f64,
    /// E-value (exp of log_lambda, clamped for safety).
    pub e_value: f64,
    /// Evidence strength on Jeffreys scale.
    pub strength: EvidenceStrength,
    /// Number of observations used.
    pub n_observations: usize,
    /// Whether upper boundary (favor H1) is crossed.
    pub crossed_upper: bool,
    /// Whether lower boundary (favor H0) is crossed.
    pub crossed_lower: bool,
    /// The decision threshold used (log scale).
    pub log_threshold: f64,
    /// Per-observation log-likelihood contributions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub increments: Option<Vec<f64>>,
}

impl MixtureSprtResult {
    /// Check if a decision boundary has been crossed.
    pub fn decision_reached(&self) -> bool {
        self.crossed_upper || self.crossed_lower
    }

    /// Get the evidence summary for this test.
    pub fn evidence_summary(&self) -> EvidenceSummary {
        EvidenceSummary::from_log_bf(self.log_lambda)
    }
}

/// Result of a GLR (Generalized Likelihood Ratio) test.
#[derive(Debug, Clone, Serialize)]
pub struct GlrResult {
    /// Log GLR statistic: log[max_{θ∈Θ_1} p(x|θ)] - log[max_{θ∈Θ_0} p(x|θ)].
    pub log_glr: f64,
    /// Conservative e-value (Ville's inequality bound).
    pub e_value: f64,
    /// Evidence strength.
    pub strength: EvidenceStrength,
    /// MLE parameter under H0.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mle_h0: Option<f64>,
    /// MLE parameter under H1.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mle_h1: Option<f64>,
    /// Whether GLR exceeds threshold.
    pub exceeds_threshold: bool,
    /// The threshold used.
    pub threshold: f64,
}

/// Configuration for mixture-SPRT tests.
#[derive(Debug, Clone)]
pub struct MixtureSprtConfig {
    /// Upper threshold for deciding H1 (in log-odds scale).
    /// Default: ln(19) ≈ 2.94 (corresponds to 95% posterior odds).
    pub log_upper_threshold: f64,
    /// Lower threshold for deciding H0 (in log-odds scale).
    /// Default: -ln(19) ≈ -2.94.
    pub log_lower_threshold: f64,
    /// Whether to track per-observation increments.
    pub track_increments: bool,
    /// Minimum observations before allowing a decision.
    pub min_observations: usize,
}

impl Default for MixtureSprtConfig {
    fn default() -> Self {
        let ln_19 = 19.0f64.ln(); // ~2.944
        Self {
            log_upper_threshold: ln_19,
            log_lower_threshold: -ln_19,
            track_increments: false,
            min_observations: 1,
        }
    }
}

impl MixtureSprtConfig {
    /// Create config from error probabilities α (Type I) and β (Type II).
    ///
    /// Uses Wald's approximations:
    /// - Upper threshold ≈ ln((1-β)/α)
    /// - Lower threshold ≈ ln(β/(1-α))
    pub fn from_error_rates(alpha: f64, beta: f64) -> Self {
        let upper = ((1.0 - beta) / alpha).ln();
        let lower = (beta / (1.0 - alpha)).ln();
        Self {
            log_upper_threshold: upper,
            log_lower_threshold: lower,
            ..Default::default()
        }
    }

    /// Create symmetric config from a single significance level.
    pub fn symmetric(alpha: f64) -> Self {
        Self::from_error_rates(alpha, alpha)
    }
}

/// Configuration for GLR tests.
#[derive(Debug, Clone)]
pub struct GlrConfig {
    /// Threshold for GLR (linear scale, not log).
    /// Default: 10.0 (strong evidence).
    pub threshold: f64,
    /// Whether to use Bartlett correction for chi-squared approximation.
    pub use_bartlett_correction: bool,
}

impl Default for GlrConfig {
    fn default() -> Self {
        Self {
            threshold: 10.0,
            use_bartlett_correction: false,
        }
    }
}

/// Mixture-SPRT state for sequential testing.
///
/// Maintains the running log-likelihood ratio for a sequence of observations.
#[derive(Debug, Clone)]
pub struct MixtureSprtState {
    /// Cumulative log-likelihood ratio.
    pub log_lambda: f64,
    /// Number of observations processed.
    pub n_observations: usize,
    /// Per-observation increments (if tracking enabled).
    pub increments: Vec<f64>,
    /// Configuration.
    config: MixtureSprtConfig,
}

impl MixtureSprtState {
    /// Create new SPRT state with given config.
    pub fn new(config: MixtureSprtConfig) -> Self {
        Self {
            log_lambda: 0.0,
            n_observations: 0,
            increments: Vec::new(),
            config,
        }
    }

    /// Create with default configuration.
    pub fn default_config() -> Self {
        Self::new(MixtureSprtConfig::default())
    }

    /// Update the SPRT state with a new observation's log-likelihood ratio.
    ///
    /// # Arguments
    /// * `log_lik_h1` - Log-likelihood of observation under H1 (or mixture marginal)
    /// * `log_lik_h0` - Log-likelihood of observation under H0
    ///
    /// Returns true if a boundary has been crossed.
    pub fn update(&mut self, log_lik_h1: f64, log_lik_h0: f64) -> bool {
        let increment = log_lik_h1 - log_lik_h0;

        // Guard against NaN/Inf propagation
        if increment.is_nan() {
            return self.decision_reached();
        }

        self.log_lambda += increment;
        self.n_observations += 1;

        if self.config.track_increments {
            self.increments.push(increment);
        }

        self.decision_reached()
    }

    /// Update with a batch of observations.
    pub fn update_batch(&mut self, log_liks_h1: &[f64], log_liks_h0: &[f64]) -> bool {
        debug_assert_eq!(log_liks_h1.len(), log_liks_h0.len());

        for (ll1, ll0) in log_liks_h1.iter().zip(log_liks_h0.iter()) {
            if self.update(*ll1, *ll0) {
                return true;
            }
        }
        false
    }

    /// Check if upper boundary (favor H1) is crossed.
    pub fn crossed_upper(&self) -> bool {
        self.n_observations >= self.config.min_observations
            && self.log_lambda >= self.config.log_upper_threshold
    }

    /// Check if lower boundary (favor H0) is crossed.
    pub fn crossed_lower(&self) -> bool {
        self.n_observations >= self.config.min_observations
            && self.log_lambda <= self.config.log_lower_threshold
    }

    /// Check if any decision boundary has been crossed.
    pub fn decision_reached(&self) -> bool {
        self.crossed_upper() || self.crossed_lower()
    }

    /// Get the current e-value.
    pub fn e_value(&self) -> f64 {
        e_value_from_log_bf(self.log_lambda)
    }

    /// Get the result snapshot.
    pub fn result(&self) -> MixtureSprtResult {
        MixtureSprtResult {
            log_lambda: self.log_lambda,
            e_value: self.e_value(),
            strength: EvidenceStrength::from_log_bf(self.log_lambda),
            n_observations: self.n_observations,
            crossed_upper: self.crossed_upper(),
            crossed_lower: self.crossed_lower(),
            log_threshold: self.config.log_upper_threshold,
            increments: if self.config.track_increments {
                Some(self.increments.clone())
            } else {
                None
            },
        }
    }

    /// Reset the state for a new sequence.
    pub fn reset(&mut self) {
        self.log_lambda = 0.0;
        self.n_observations = 0;
        self.increments.clear();
    }
}

/// Compute mixture-SPRT for Bernoulli observations with Beta priors.
///
/// H0: p = p0 (point hypothesis)
/// H1: p ~ Beta(α, β) (mixture/composite hypothesis)
///
/// The marginal likelihood under H1 is the Beta-Bernoulli:
/// P(x=1|H1) = α / (α + β)
/// P(x=0|H1) = β / (α + β)
///
/// # Arguments
/// * `observations` - Sequence of binary observations (true/false)
/// * `p0` - Probability under null hypothesis
/// * `alpha_h1` - Beta prior α parameter under H1
/// * `beta_h1` - Beta prior β parameter under H1
/// * `config` - SPRT configuration
pub fn mixture_sprt_bernoulli(
    observations: &[bool],
    p0: f64,
    alpha_h1: f64,
    beta_h1: f64,
    config: &MixtureSprtConfig,
) -> Result<MixtureSprtResult, CompositeTestError> {
    if p0 <= 0.0 || p0 >= 1.0 {
        return Err(CompositeTestError::InvalidLogLikelihood {
            message: format!("p0 must be in (0, 1), got {}", p0),
        });
    }
    if alpha_h1 <= 0.0 || beta_h1 <= 0.0 {
        return Err(CompositeTestError::InvalidLogLikelihood {
            message: format!(
                "Beta parameters must be positive: α={}, β={}",
                alpha_h1, beta_h1
            ),
        });
    }

    let mut state = MixtureSprtState::new(config.clone());

    // For Beta-Bernoulli, the marginal probabilities are:
    // P(X=1) = α/(α+β), P(X=0) = β/(α+β)
    let p1_success = alpha_h1 / (alpha_h1 + beta_h1);
    let p1_failure = beta_h1 / (alpha_h1 + beta_h1);

    for &obs in observations {
        let log_lik_h1 = if obs {
            p1_success.ln()
        } else {
            p1_failure.ln()
        };
        let log_lik_h0 = if obs { p0.ln() } else { (1.0 - p0).ln() };
        state.update(log_lik_h1, log_lik_h0);
    }

    Ok(state.result())
}

/// Compute mixture-SPRT with sequential Beta updates (proper Bayesian).
///
/// This version properly updates the Beta posterior after each observation,
/// giving correct sequential marginal likelihoods.
///
/// # Arguments
/// * `observations` - Sequence of binary observations
/// * `p0` - Probability under null hypothesis
/// * `prior_alpha` - Prior Beta α under H1
/// * `prior_beta` - Prior Beta β under H1
/// * `config` - SPRT configuration
pub fn mixture_sprt_beta_sequential(
    observations: &[bool],
    p0: f64,
    prior_alpha: f64,
    prior_beta: f64,
    config: &MixtureSprtConfig,
) -> Result<MixtureSprtResult, CompositeTestError> {
    if p0 <= 0.0 || p0 >= 1.0 {
        return Err(CompositeTestError::InvalidLogLikelihood {
            message: format!("p0 must be in (0, 1), got {}", p0),
        });
    }
    if prior_alpha <= 0.0 || prior_beta <= 0.0 {
        return Err(CompositeTestError::InvalidLogLikelihood {
            message: format!(
                "Beta parameters must be positive: α={}, β={}",
                prior_alpha, prior_beta
            ),
        });
    }

    let mut state = MixtureSprtState::new(config.clone());
    let mut alpha = prior_alpha;
    let mut beta = prior_beta;

    for &obs in observations {
        // Predictive probability under current posterior (Beta-Bernoulli)
        let pred_success = alpha / (alpha + beta);
        let pred_failure = beta / (alpha + beta);

        let log_lik_h1 = if obs {
            pred_success.ln()
        } else {
            pred_failure.ln()
        };
        let log_lik_h0 = if obs { p0.ln() } else { (1.0 - p0).ln() };

        state.update(log_lik_h1, log_lik_h0);

        // Update posterior
        if obs {
            alpha += 1.0;
        } else {
            beta += 1.0;
        }
    }

    Ok(state.result())
}

/// Compute GLR (Generalized Likelihood Ratio) for Bernoulli observations.
///
/// H0: p = p0 (fixed null)
/// H1: p ∈ (0, 1) (any value)
///
/// GLR = max_p P(data|p) / P(data|p0) = P(data|p̂) / P(data|p0)
/// where p̂ = k/n is the MLE.
///
/// # Arguments
/// * `successes` - Number of successes
/// * `n` - Total observations
/// * `p0` - Probability under null hypothesis
/// * `config` - GLR configuration
pub fn glr_bernoulli(
    successes: usize,
    n: usize,
    p0: f64,
    config: &GlrConfig,
) -> Result<GlrResult, CompositeTestError> {
    if n == 0 {
        return Err(CompositeTestError::InsufficientObservations { min: 1, got: 0 });
    }
    if p0 <= 0.0 || p0 >= 1.0 {
        return Err(CompositeTestError::InvalidLogLikelihood {
            message: format!("p0 must be in (0, 1), got {}", p0),
        });
    }

    let k = successes as f64;
    let n_f = n as f64;
    let p_mle = k / n_f;

    // Log-likelihood under H0
    let log_lik_h0 = k * p0.ln() + (n_f - k) * (1.0 - p0).ln();

    // Log-likelihood under MLE (handle edge cases)
    let log_lik_h1 = if p_mle <= 0.0 {
        (n_f - k) * 1.0f64.ln() // All failures
    } else if p_mle >= 1.0 {
        k * 1.0f64.ln() // All successes
    } else {
        k * p_mle.ln() + (n_f - k) * (1.0 - p_mle).ln()
    };

    let log_glr = log_lik_h1 - log_lik_h0;

    // Apply Bartlett correction if configured
    let corrected_log_glr = if config.use_bartlett_correction && n > 1 {
        // Bartlett correction factor for binomial: roughly 1 + 1/(2n)
        log_glr / (1.0 + 1.0 / (2.0 * n_f))
    } else {
        log_glr
    };

    // E-value from GLR (conservative, using Ville's inequality)
    // For GLR, e-value = GLR only under certain conditions
    // We use a conservative bound: e = exp(log_glr / 2) for chi-squared approximation
    let e_value = (corrected_log_glr / 2.0).exp().min(corrected_log_glr.exp());

    Ok(GlrResult {
        log_glr: corrected_log_glr,
        e_value,
        strength: EvidenceStrength::from_log_bf(corrected_log_glr),
        mle_h0: Some(p0),
        mle_h1: Some(p_mle),
        exceeds_threshold: corrected_log_glr.exp() > config.threshold,
        threshold: config.threshold,
    })
}

/// Compute mixture-SPRT for multi-class classification.
///
/// Given log-likelihoods for each class, compute the mixture SPRT comparing
/// a "bad" composite (abandoned + zombie) vs "good" composite (useful + useful_bad).
///
/// # Arguments
/// * `log_liks` - Log-likelihoods for [useful, useful_bad, abandoned, zombie]
/// * `prior_good` - Prior weight on good (useful + useful_bad)
/// * `prior_bad` - Prior weight on bad (abandoned + zombie)
/// * `weight_useful_bad` - Relative weight of useful_bad within "good" (default 0.3)
/// * `weight_zombie` - Relative weight of zombie within "bad" (default 0.2)
pub fn mixture_sprt_multiclass(
    log_liks: &[f64; 4],
    prior_good: f64,
    prior_bad: f64,
    weight_useful_bad: f64,
    weight_zombie: f64,
) -> Result<f64, CompositeTestError> {
    // Validate inputs
    for (i, &ll) in log_liks.iter().enumerate() {
        if ll.is_nan() {
            return Err(CompositeTestError::InvalidLogLikelihood {
                message: format!("log_lik[{}] is NaN", i),
            });
        }
    }

    // Weights within each composite
    let w_useful = 1.0 - weight_useful_bad;
    let w_useful_bad = weight_useful_bad;
    let w_abandoned = 1.0 - weight_zombie;
    let w_zombie = weight_zombie;

    // Log-sum-exp for mixture likelihoods
    let log_lik_good = log_sum_exp(&[
        log_liks[0] + w_useful.ln(),     // useful
        log_liks[1] + w_useful_bad.ln(), // useful_bad
    ]);

    let log_lik_bad = log_sum_exp(&[
        log_liks[2] + w_abandoned.ln(), // abandoned
        log_liks[3] + w_zombie.ln(),    // zombie
    ]);

    // Log Bayes factor: bad vs good
    let log_bf = log_lik_bad + prior_bad.ln() - log_lik_good - prior_good.ln();

    Ok(log_bf)
}

/// Numerically stable log-sum-exp.
fn log_sum_exp(values: &[f64]) -> f64 {
    if values.is_empty() {
        return f64::NEG_INFINITY;
    }

    let max_val = values.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    if max_val.is_infinite() && max_val < 0.0 {
        return f64::NEG_INFINITY;
    }

    let sum: f64 = values.iter().map(|&v| (v - max_val).exp()).sum();
    max_val + sum.ln()
}

/// Evidence aggregator for composite testing across multiple features.
///
/// Combines evidence from multiple independent tests into a single summary.
#[derive(Debug, Clone, Default)]
pub struct CompositeEvidenceAggregator {
    /// Sum of log Bayes factors.
    pub log_bf_sum: f64,
    /// Number of evidence terms combined.
    pub n_terms: usize,
    /// Individual term contributions.
    pub terms: Vec<(String, f64)>,
}

impl CompositeEvidenceAggregator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an evidence term.
    pub fn add_term(&mut self, name: &str, log_bf: f64) {
        if log_bf.is_finite() {
            self.log_bf_sum += log_bf;
            self.n_terms += 1;
            self.terms.push((name.to_string(), log_bf));
        }
    }

    /// Get the combined e-value.
    pub fn combined_e_value(&self) -> f64 {
        e_value_from_log_bf(self.log_bf_sum)
    }

    /// Get evidence summary.
    pub fn summary(&self) -> EvidenceSummary {
        EvidenceSummary::from_log_bf(self.log_bf_sum)
    }

    /// Get the top N contributing terms (by absolute magnitude).
    pub fn top_terms(&self, n: usize) -> Vec<(String, f64)> {
        let mut sorted = self.terms.clone();
        sorted.sort_by(|a, b| {
            b.1.abs()
                .partial_cmp(&a.1.abs())
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        sorted.into_iter().take(n).collect()
    }
}

/// Outcome of composite-hypothesis testing integration.
#[derive(Debug, Clone, Serialize)]
pub struct CompositeTestOutcome {
    /// Whether composite testing was applied.
    pub applied: bool,
    /// Reason for applying (or not).
    pub reason: String,
    /// Mixture-SPRT result if computed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mixture_sprt: Option<MixtureSprtResult>,
    /// GLR result if computed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub glr: Option<GlrResult>,
    /// Combined e-value for e-FDR integration.
    pub e_value: f64,
    /// Evidence strength.
    pub strength: EvidenceStrength,
    /// Whether evidence suggests simple SPRT is adequate.
    pub simple_sprt_adequate: bool,
}

impl Default for CompositeTestOutcome {
    fn default() -> Self {
        Self {
            applied: false,
            reason: String::new(),
            mixture_sprt: None,
            glr: None,
            e_value: 1.0,
            strength: EvidenceStrength::None,
            simple_sprt_adequate: true,
        }
    }
}

/// Check if composite testing is needed based on evidence characteristics.
///
/// Returns true if:
/// - Evidence is ambiguous (no clear winner)
/// - Parameter uncertainty is high
/// - Simple SPRT might give misleading results
pub fn needs_composite_test(
    log_bf_simple: f64,
    posterior_entropy: f64,
    param_uncertainty: f64,
) -> bool {
    // Thresholds for triggering composite testing
    const ENTROPY_THRESHOLD: f64 = 1.0; // nats
    const UNCERTAINTY_THRESHOLD: f64 = 0.3;
    const AMBIGUOUS_BF_RANGE: f64 = 1.5; // |log_bf| < this is ambiguous

    let is_ambiguous = log_bf_simple.abs() < AMBIGUOUS_BF_RANGE;
    let high_entropy = posterior_entropy > ENTROPY_THRESHOLD;
    let high_uncertainty = param_uncertainty > UNCERTAINTY_THRESHOLD;

    is_ambiguous && (high_entropy || high_uncertainty)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx_eq(a: f64, b: f64, tol: f64) -> bool {
        (a - b).abs() <= tol
    }

    // =========================================================================
    // MixtureSprtConfig tests
    // =========================================================================

    #[test]
    fn test_config_default_thresholds() {
        let config = MixtureSprtConfig::default();
        // ln(19) ≈ 2.944
        assert!(approx_eq(config.log_upper_threshold, 19.0f64.ln(), 0.01));
        assert!(approx_eq(config.log_lower_threshold, -19.0f64.ln(), 0.01));
    }

    #[test]
    fn test_config_from_error_rates() {
        let config = MixtureSprtConfig::from_error_rates(0.05, 0.20);
        // Upper: ln(0.8/0.05) = ln(16) ≈ 2.77
        assert!(config.log_upper_threshold > 2.0);
        // Lower: ln(0.2/0.95) ≈ -1.56
        assert!(config.log_lower_threshold < 0.0);
    }

    #[test]
    fn test_config_symmetric() {
        let config = MixtureSprtConfig::symmetric(0.05);
        assert!(approx_eq(
            config.log_upper_threshold,
            -config.log_lower_threshold,
            0.01
        ));
    }

    // =========================================================================
    // MixtureSprtState tests
    // =========================================================================

    #[test]
    fn test_state_initial() {
        let state = MixtureSprtState::default_config();
        assert!(approx_eq(state.log_lambda, 0.0, 1e-12));
        assert_eq!(state.n_observations, 0);
        assert!(!state.decision_reached());
    }

    #[test]
    fn test_state_update_positive() {
        let mut state = MixtureSprtState::default_config();
        // H1 more likely: log_lik_h1 > log_lik_h0
        state.update(-1.0, -2.0); // increment = 1.0
        assert!(approx_eq(state.log_lambda, 1.0, 1e-12));
        assert_eq!(state.n_observations, 1);
    }

    #[test]
    fn test_state_update_negative() {
        let mut state = MixtureSprtState::default_config();
        // H0 more likely: log_lik_h1 < log_lik_h0
        state.update(-2.0, -1.0); // increment = -1.0
        assert!(approx_eq(state.log_lambda, -1.0, 1e-12));
    }

    #[test]
    fn test_state_crosses_upper() {
        let config = MixtureSprtConfig {
            log_upper_threshold: 2.0,
            log_lower_threshold: -2.0,
            ..Default::default()
        };
        let mut state = MixtureSprtState::new(config);

        // Add evidence favoring H1
        for _ in 0..3 {
            state.update(0.0, -1.0); // increment = 1.0 each
        }

        assert!(state.log_lambda >= 2.0);
        assert!(state.crossed_upper());
        assert!(!state.crossed_lower());
        assert!(state.decision_reached());
    }

    #[test]
    fn test_state_crosses_lower() {
        let config = MixtureSprtConfig {
            log_upper_threshold: 2.0,
            log_lower_threshold: -2.0,
            ..Default::default()
        };
        let mut state = MixtureSprtState::new(config);

        // Add evidence favoring H0
        for _ in 0..3 {
            state.update(-1.0, 0.0); // increment = -1.0 each
        }

        assert!(state.log_lambda <= -2.0);
        assert!(!state.crossed_upper());
        assert!(state.crossed_lower());
        assert!(state.decision_reached());
    }

    #[test]
    fn test_state_min_observations() {
        let config = MixtureSprtConfig {
            log_upper_threshold: 1.0,
            min_observations: 5,
            ..Default::default()
        };
        let mut state = MixtureSprtState::new(config);

        // Even if threshold crossed, need min observations
        state.update(0.0, -2.0); // log_lambda = 2.0 > threshold
        assert!(state.log_lambda > 1.0);
        assert!(!state.decision_reached()); // only 1 observation

        // Add more observations
        for _ in 0..4 {
            state.update(0.0, 0.0);
        }
        assert!(state.decision_reached()); // now 5 observations
    }

    #[test]
    fn test_state_reset() {
        let mut state = MixtureSprtState::default_config();
        state.update(0.0, -1.0);
        state.update(0.0, -1.0);
        assert_eq!(state.n_observations, 2);

        state.reset();
        assert_eq!(state.n_observations, 0);
        assert!(approx_eq(state.log_lambda, 0.0, 1e-12));
    }

    #[test]
    fn test_state_tracks_increments() {
        let config = MixtureSprtConfig {
            track_increments: true,
            ..Default::default()
        };
        let mut state = MixtureSprtState::new(config);

        state.update(0.0, -1.0);
        state.update(-0.5, 0.0);

        let result = state.result();
        let increments = result.increments.unwrap();
        assert_eq!(increments.len(), 2);
        assert!(approx_eq(increments[0], 1.0, 1e-12));
        assert!(approx_eq(increments[1], -0.5, 1e-12));
    }

    // =========================================================================
    // mixture_sprt_bernoulli tests
    // =========================================================================

    #[test]
    fn test_mixture_sprt_bernoulli_all_successes() {
        let observations = vec![true, true, true, true, true];
        let p0 = 0.5; // Null: fair coin
        let alpha_h1 = 4.0; // Prior favoring success
        let beta_h1 = 1.0;

        let result = mixture_sprt_bernoulli(
            &observations,
            p0,
            alpha_h1,
            beta_h1,
            &MixtureSprtConfig::default(),
        )
        .unwrap();

        // All successes should favor H1 (biased toward success)
        assert!(result.log_lambda > 0.0);
        assert!(result.e_value > 1.0);
    }

    #[test]
    fn test_mixture_sprt_bernoulli_all_failures() {
        let observations = vec![false, false, false, false, false];
        let p0 = 0.5;
        let alpha_h1 = 4.0; // Prior favoring success
        let beta_h1 = 1.0;

        let result = mixture_sprt_bernoulli(
            &observations,
            p0,
            alpha_h1,
            beta_h1,
            &MixtureSprtConfig::default(),
        )
        .unwrap();

        // All failures when H1 favors success -> evidence for H0
        assert!(result.log_lambda < 0.0);
    }

    #[test]
    fn test_mixture_sprt_bernoulli_invalid_p0() {
        let result = mixture_sprt_bernoulli(&[true], 0.0, 1.0, 1.0, &MixtureSprtConfig::default());
        assert!(result.is_err());

        let result = mixture_sprt_bernoulli(&[true], 1.0, 1.0, 1.0, &MixtureSprtConfig::default());
        assert!(result.is_err());
    }

    #[test]
    fn test_mixture_sprt_bernoulli_invalid_beta_params() {
        let result = mixture_sprt_bernoulli(&[true], 0.5, 0.0, 1.0, &MixtureSprtConfig::default());
        assert!(result.is_err());

        let result = mixture_sprt_bernoulli(&[true], 0.5, 1.0, -1.0, &MixtureSprtConfig::default());
        assert!(result.is_err());
    }

    // =========================================================================
    // mixture_sprt_beta_sequential tests
    // =========================================================================

    #[test]
    fn test_mixture_sprt_sequential_updates_posterior() {
        let observations = vec![true, true, false, true];
        let p0 = 0.5;

        let result = mixture_sprt_beta_sequential(
            &observations,
            p0,
            1.0,
            1.0,
            &MixtureSprtConfig::default(),
        )
        .unwrap();

        // Should have processed all observations
        assert_eq!(result.n_observations, 4);
        // With uniform prior and mixed data, result should be moderate
        assert!(result.log_lambda.abs() < 5.0);
    }

    // =========================================================================
    // glr_bernoulli tests
    // =========================================================================

    #[test]
    fn test_glr_mle_matches_null() {
        // If MLE equals null, GLR should be 1 (log_glr = 0)
        let result = glr_bernoulli(5, 10, 0.5, &GlrConfig::default()).unwrap();
        assert!(approx_eq(result.log_glr, 0.0, 0.01));
        assert!(approx_eq(result.mle_h1.unwrap(), 0.5, 0.01));
    }

    #[test]
    fn test_glr_mle_differs_from_null() {
        // MLE (0.8) differs from null (0.5)
        let result = glr_bernoulli(8, 10, 0.5, &GlrConfig::default()).unwrap();
        assert!(result.log_glr > 0.0); // MLE fits better than null
        assert!(approx_eq(result.mle_h1.unwrap(), 0.8, 0.01));
    }

    #[test]
    fn test_glr_all_successes() {
        let result = glr_bernoulli(10, 10, 0.5, &GlrConfig::default()).unwrap();
        assert!(result.log_glr > 0.0);
        assert!(approx_eq(result.mle_h1.unwrap(), 1.0, 0.01));
    }

    #[test]
    fn test_glr_all_failures() {
        let result = glr_bernoulli(0, 10, 0.5, &GlrConfig::default()).unwrap();
        assert!(result.log_glr > 0.0); // MLE (0) differs from null (0.5)
        assert!(approx_eq(result.mle_h1.unwrap(), 0.0, 0.01));
    }

    #[test]
    fn test_glr_exceeds_threshold() {
        let config = GlrConfig {
            threshold: 2.0,
            ..Default::default()
        };
        // Strong evidence against null
        let result = glr_bernoulli(9, 10, 0.5, &config).unwrap();
        assert!(result.exceeds_threshold);
    }

    #[test]
    fn test_glr_insufficient_observations() {
        let result = glr_bernoulli(0, 0, 0.5, &GlrConfig::default());
        assert!(result.is_err());
    }

    // =========================================================================
    // log_sum_exp tests
    // =========================================================================

    #[test]
    fn test_log_sum_exp_single() {
        assert!(approx_eq(log_sum_exp(&[2.0]), 2.0, 1e-12));
    }

    #[test]
    fn test_log_sum_exp_equal() {
        // log(e^1 + e^1) = log(2e) = 1 + ln(2)
        let result = log_sum_exp(&[1.0, 1.0]);
        assert!(approx_eq(result, 1.0 + 2.0f64.ln(), 1e-10));
    }

    #[test]
    fn test_log_sum_exp_large_difference() {
        // log(e^100 + e^0) ≈ 100 (the small term is negligible)
        let result = log_sum_exp(&[100.0, 0.0]);
        assert!(approx_eq(result, 100.0, 1e-10));
    }

    #[test]
    fn test_log_sum_exp_empty() {
        assert_eq!(log_sum_exp(&[]), f64::NEG_INFINITY);
    }

    // =========================================================================
    // mixture_sprt_multiclass tests
    // =========================================================================

    #[test]
    fn test_multiclass_equal_likelihoods() {
        let log_liks = [0.0, 0.0, 0.0, 0.0];
        let result = mixture_sprt_multiclass(&log_liks, 0.5, 0.5, 0.3, 0.2).unwrap();
        // With equal priors and likelihoods, log_bf should be near 0
        assert!(result.abs() < 0.1);
    }

    #[test]
    fn test_multiclass_favors_bad() {
        // Strong evidence for abandoned/zombie
        let log_liks = [-10.0, -10.0, 0.0, 0.0]; // bad classes have higher likelihood
        let result = mixture_sprt_multiclass(&log_liks, 0.5, 0.5, 0.3, 0.2).unwrap();
        assert!(result > 0.0); // Favors bad
    }

    #[test]
    fn test_multiclass_favors_good() {
        // Strong evidence for useful
        let log_liks = [0.0, 0.0, -10.0, -10.0]; // good classes have higher likelihood
        let result = mixture_sprt_multiclass(&log_liks, 0.5, 0.5, 0.3, 0.2).unwrap();
        assert!(result < 0.0); // Favors good
    }

    // =========================================================================
    // CompositeEvidenceAggregator tests
    // =========================================================================

    #[test]
    fn test_aggregator_empty() {
        let agg = CompositeEvidenceAggregator::new();
        assert_eq!(agg.n_terms, 0);
        assert!(approx_eq(agg.log_bf_sum, 0.0, 1e-12));
        assert!(approx_eq(agg.combined_e_value(), 1.0, 1e-12));
    }

    #[test]
    fn test_aggregator_add_terms() {
        let mut agg = CompositeEvidenceAggregator::new();
        agg.add_term("cpu", 1.0);
        agg.add_term("runtime", 2.0);
        agg.add_term("orphan", -0.5);

        assert_eq!(agg.n_terms, 3);
        assert!(approx_eq(agg.log_bf_sum, 2.5, 1e-12));
    }

    #[test]
    fn test_aggregator_top_terms() {
        let mut agg = CompositeEvidenceAggregator::new();
        agg.add_term("small", 0.1);
        agg.add_term("large", 5.0);
        agg.add_term("negative_large", -4.0);
        agg.add_term("medium", 2.0);

        let top = agg.top_terms(2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].0, "large");
        assert_eq!(top[1].0, "negative_large");
    }

    // =========================================================================
    // needs_composite_test tests
    // =========================================================================

    #[test]
    fn test_needs_composite_ambiguous() {
        // Ambiguous BF + high entropy -> needs composite
        assert!(needs_composite_test(0.5, 1.5, 0.1));
    }

    #[test]
    fn test_needs_composite_clear_evidence() {
        // Clear BF -> doesn't need composite even with high entropy
        assert!(!needs_composite_test(3.0, 1.5, 0.4));
    }

    #[test]
    fn test_needs_composite_low_entropy() {
        // Ambiguous BF but low entropy and uncertainty -> doesn't need
        assert!(!needs_composite_test(0.5, 0.3, 0.1));
    }
}
