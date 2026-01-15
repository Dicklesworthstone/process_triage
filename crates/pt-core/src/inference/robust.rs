//! Robust Bayes: imprecise priors and Safe-Bayes tempering.
//!
//! This module implements Plan §4.9 / §2(L)/§2(X): **Robust Bayes** mechanisms
//! that keep the system conservative under model misspecification and drift.
//!
//! # Components
//!
//! 1. **Imprecise priors / credal sets**: Priors specified as intervals rather
//!    than point estimates. Decision rules only take destructive actions if
//!    robust across the credal set.
//!
//! 2. **Safe-Bayes tempering**: Fractional posterior updates via η ∈ (0,1]:
//!    ```text
//!    posterior_η(θ|x) ∝ π(θ) · p(x|θ)^η
//!    ```
//!    For conjugate Beta-Binomial: `α ← α + η·k`, `β ← β + η·(n-k)`.
//!
//! # Example
//!
//! ```rust
//! use pt_core::inference::robust::{CredalSet, TemperedPosterior, RobustConfig, RobustGate};
//!
//! // Imprecise prior: P(useful) ∈ [0.6, 0.9]
//! let credal = CredalSet::interval(0.6, 0.9);
//!
//! // Tempered posterior with η=0.8
//! let tempered = TemperedPosterior::beta_binomial(2.0, 2.0, 8, 2, 0.8);
//!
//! // Check if action is robust
//! let config = RobustConfig::default();
//! let gate = RobustGate::new(config);
//! let robust = gate.is_action_robust(&credal, 0.7);
//! ```

use serde::Serialize;
use thiserror::Error;

/// Configuration for robust Bayes mechanisms.
#[derive(Debug, Clone)]
pub struct RobustConfig {
    /// Default tempering parameter η ∈ (0, 1].
    pub default_eta: f64,
    /// Minimum η allowed (floor for tempering).
    pub min_eta: f64,
    /// η reduction factor when PPC fails.
    pub eta_ppc_reduction: f64,
    /// η reduction factor when drift is detected.
    pub eta_drift_reduction: f64,
    /// Credal width expansion factor under drift.
    pub drift_credal_expansion: f64,
    /// Minimum posterior required for any action (worst-case bound).
    pub min_robust_posterior: f64,
    /// Use log-domain arithmetic for stability.
    pub use_log_domain: bool,
}

impl Default for RobustConfig {
    fn default() -> Self {
        Self {
            default_eta: 1.0,
            min_eta: 0.5,
            eta_ppc_reduction: 0.1,
            eta_drift_reduction: 0.15,
            drift_credal_expansion: 1.2,
            min_robust_posterior: 0.7,
            use_log_domain: true,
        }
    }
}

impl RobustConfig {
    /// Conservative configuration for high-stakes decisions.
    pub fn conservative() -> Self {
        Self {
            default_eta: 0.9,
            min_eta: 0.6,
            eta_ppc_reduction: 0.15,
            eta_drift_reduction: 0.2,
            drift_credal_expansion: 1.5,
            min_robust_posterior: 0.85,
            use_log_domain: true,
        }
    }

    /// Strict configuration with minimal tempering.
    pub fn strict() -> Self {
        Self {
            default_eta: 1.0,
            min_eta: 0.8,
            eta_ppc_reduction: 0.05,
            eta_drift_reduction: 0.1,
            drift_credal_expansion: 1.1,
            min_robust_posterior: 0.9,
            use_log_domain: true,
        }
    }
}

/// A credal set representing imprecise probabilities.
///
/// For P(C), instead of a point estimate, we have an interval [lower, upper].
#[derive(Debug, Clone, Copy, Serialize)]
pub struct CredalSet {
    /// Lower bound of the probability interval.
    pub lower: f64,
    /// Upper bound of the probability interval.
    pub upper: f64,
}

impl CredalSet {
    /// Create a credal set from an interval.
    pub fn interval(lower: f64, upper: f64) -> Self {
        let lower = lower.clamp(0.0, 1.0);
        let upper = upper.clamp(lower, 1.0);
        Self { lower, upper }
    }

    /// Create a precise (point) prior.
    pub fn point(p: f64) -> Self {
        let p = p.clamp(0.0, 1.0);
        Self { lower: p, upper: p }
    }

    /// Create from a center and half-width.
    pub fn symmetric(center: f64, half_width: f64) -> Self {
        let lower = (center - half_width).max(0.0);
        let upper = (center + half_width).min(1.0);
        Self::interval(lower, upper)
    }

    /// Width of the interval (measure of imprecision).
    pub fn width(&self) -> f64 {
        self.upper - self.lower
    }

    /// Center of the interval.
    pub fn center(&self) -> f64 {
        (self.lower + self.upper) / 2.0
    }

    /// Whether this is a precise (point) probability.
    pub fn is_precise(&self) -> bool {
        (self.upper - self.lower).abs() < 1e-10
    }

    /// Expand the credal set by a factor (for conservatism under drift).
    pub fn expand(&self, factor: f64) -> Self {
        let center = self.center();
        let half_width = self.width() / 2.0 * factor;
        Self::symmetric(center, half_width)
    }

    /// Check if a probability is within the credal set.
    pub fn contains(&self, p: f64) -> bool {
        p >= self.lower - 1e-10 && p <= self.upper + 1e-10
    }

    /// Intersect two credal sets.
    pub fn intersect(&self, other: &CredalSet) -> Option<CredalSet> {
        let lower = self.lower.max(other.lower);
        let upper = self.upper.min(other.upper);
        if lower <= upper + 1e-10 {
            Some(CredalSet::interval(lower, upper))
        } else {
            None
        }
    }

    /// Union (hull) of two credal sets.
    pub fn hull(&self, other: &CredalSet) -> CredalSet {
        CredalSet::interval(self.lower.min(other.lower), self.upper.max(other.upper))
    }
}

impl Default for CredalSet {
    fn default() -> Self {
        // Uninformative: full interval
        Self::interval(0.0, 1.0)
    }
}

/// Tempered posterior for Safe-Bayes updates.
///
/// Uses fractional sufficient statistics: instead of full Bayesian update,
/// we use `posterior_η ∝ prior × likelihood^η` where η ∈ (0,1].
#[derive(Debug, Clone, Serialize)]
pub struct TemperedPosterior {
    /// Effective alpha parameter (prior + η × successes).
    pub alpha: f64,
    /// Effective beta parameter (prior + η × failures).
    pub beta: f64,
    /// Tempering parameter η used.
    pub eta: f64,
    /// Number of observations.
    pub n: usize,
    /// Number of successes (events of interest).
    pub k: usize,
    /// Original prior alpha.
    pub prior_alpha: f64,
    /// Original prior beta.
    pub prior_beta: f64,
}

impl TemperedPosterior {
    /// Create a tempered Beta-Binomial posterior.
    ///
    /// Standard update: α' = α + k, β' = β + (n-k)
    /// Tempered update: α' = α + η·k, β' = β + η·(n-k)
    pub fn beta_binomial(
        prior_alpha: f64,
        prior_beta: f64,
        n: usize,
        k: usize,
        eta: f64,
    ) -> Self {
        let eta = eta.clamp(0.0, 1.0);
        let k = k.min(n);

        let alpha = prior_alpha + eta * k as f64;
        let beta = prior_beta + eta * (n - k) as f64;

        Self {
            alpha,
            beta,
            eta,
            n,
            k,
            prior_alpha,
            prior_beta,
        }
    }

    /// Create a standard (non-tempered) posterior.
    pub fn standard(prior_alpha: f64, prior_beta: f64, n: usize, k: usize) -> Self {
        Self::beta_binomial(prior_alpha, prior_beta, n, k, 1.0)
    }

    /// Posterior mean E[θ] = α / (α + β).
    pub fn mean(&self) -> f64 {
        self.alpha / (self.alpha + self.beta)
    }

    /// Posterior mode (MAP estimate).
    pub fn mode(&self) -> f64 {
        if self.alpha > 1.0 && self.beta > 1.0 {
            (self.alpha - 1.0) / (self.alpha + self.beta - 2.0)
        } else if self.alpha <= 1.0 && self.beta > 1.0 {
            0.0
        } else if self.alpha > 1.0 && self.beta <= 1.0 {
            1.0
        } else {
            // Both <= 1: uniform prior, return mean
            self.mean()
        }
    }

    /// Posterior variance.
    pub fn variance(&self) -> f64 {
        let n = self.alpha + self.beta;
        self.alpha * self.beta / (n * n * (n + 1.0))
    }

    /// Posterior standard deviation.
    pub fn std_dev(&self) -> f64 {
        self.variance().sqrt()
    }

    /// Credible interval [lower, upper] for given coverage.
    ///
    /// Uses symmetric quantile-based interval.
    pub fn credible_interval(&self, coverage: f64) -> (f64, f64) {
        let tail = (1.0 - coverage) / 2.0;
        let lower = self.quantile(tail);
        let upper = self.quantile(1.0 - tail);
        (lower, upper)
    }

    /// Approximate quantile using Wilson-Hilferty transformation.
    fn quantile(&self, p: f64) -> f64 {
        // For Beta distribution, use normal approximation for central quantiles
        let mean = self.mean();
        let std = self.std_dev();

        // Standard normal quantile (probit)
        let z = normal_quantile(p);

        // Transform back
        (mean + z * std).clamp(0.0, 1.0)
    }

    /// Effective sample size (how much data the tempered posterior represents).
    pub fn effective_sample_size(&self) -> f64 {
        self.eta * self.n as f64
    }

    /// Compare to a standard posterior and return the tempering effect.
    pub fn tempering_effect(&self) -> f64 {
        let standard = Self::standard(self.prior_alpha, self.prior_beta, self.n, self.k);
        (self.mean() - standard.mean()).abs()
    }
}

/// Errors from robust Bayes operations.
#[derive(Debug, Error)]
pub enum RobustError {
    #[error("invalid eta: {eta}, must be in (0, 1]")]
    InvalidEta { eta: f64 },

    #[error("invalid credal set: lower={lower} > upper={upper}")]
    InvalidCredal { lower: f64, upper: f64 },

    #[error("empty credal intersection")]
    EmptyIntersection,

    #[error("decision not robust: worst-case posterior {worst_case:.4} < threshold {threshold:.4}")]
    NotRobust { worst_case: f64, threshold: f64 },
}

/// Result of robust gating check.
#[derive(Debug, Clone, Serialize)]
pub struct RobustResult {
    /// Whether the decision is robust.
    pub is_robust: bool,
    /// Worst-case posterior (lower bound).
    pub worst_case_posterior: f64,
    /// Best-case posterior (upper bound).
    pub best_case_posterior: f64,
    /// Current tempering parameter.
    pub eta: f64,
    /// Credal width used.
    pub credal_width: f64,
    /// Reason for decision.
    pub reason: String,
}

/// Evidence for decision-core integration.
#[derive(Debug, Clone, Serialize)]
pub struct RobustEvidence {
    /// Current tempering parameter.
    pub eta: f64,
    /// Whether tempering was applied (η < 1).
    pub tempering_active: bool,
    /// Credal set width (imprecision).
    pub credal_width: f64,
    /// Worst-case posterior.
    pub worst_case: f64,
    /// Decision robustness.
    pub is_robust: bool,
    /// Effective sample size after tempering.
    pub effective_n: f64,
}

/// Gate for robust decision making.
pub struct RobustGate {
    config: RobustConfig,
    eta: f64,
    ppc_failures: usize,
    drift_detected: bool,
}

impl RobustGate {
    /// Create a new robust gate.
    pub fn new(config: RobustConfig) -> Self {
        let eta = config.default_eta;
        Self {
            config,
            eta,
            ppc_failures: 0,
            drift_detected: false,
        }
    }

    /// Current tempering parameter.
    pub fn eta(&self) -> f64 {
        self.eta
    }

    /// Reset eta to default.
    pub fn reset_eta(&mut self) {
        self.eta = self.config.default_eta;
        self.ppc_failures = 0;
        self.drift_detected = false;
    }

    /// Signal PPC failure - reduces η.
    pub fn signal_ppc_failure(&mut self) {
        self.ppc_failures += 1;
        self.eta = (self.eta - self.config.eta_ppc_reduction).max(self.config.min_eta);
    }

    /// Signal drift detection - reduces η.
    pub fn signal_drift(&mut self) {
        self.drift_detected = true;
        self.eta = (self.eta - self.config.eta_drift_reduction).max(self.config.min_eta);
    }

    /// Clear drift signal.
    pub fn clear_drift(&mut self) {
        self.drift_detected = false;
    }

    /// Check if an action is robust given a credal set and posterior.
    pub fn is_action_robust(&self, credal: &CredalSet, posterior: f64) -> RobustResult {
        // Expand credal set if drift is detected
        let credal = if self.drift_detected {
            credal.expand(self.config.drift_credal_expansion)
        } else {
            *credal
        };

        // Worst-case: lower bound of credal × posterior
        // For P(action is correct | data) = P(C|x), worst case over P(C) prior
        let worst_case = credal.lower * posterior;
        let best_case = credal.upper * posterior;

        let is_robust = worst_case >= self.config.min_robust_posterior;
        let reason = if is_robust {
            format!(
                "Decision robust: worst-case {:.4} >= {:.4}",
                worst_case, self.config.min_robust_posterior
            )
        } else {
            format!(
                "Decision NOT robust: worst-case {:.4} < {:.4}",
                worst_case, self.config.min_robust_posterior
            )
        };

        RobustResult {
            is_robust,
            worst_case_posterior: worst_case,
            best_case_posterior: best_case,
            eta: self.eta,
            credal_width: credal.width(),
            reason,
        }
    }

    /// Compute tempered posterior for given observations.
    pub fn tempered_posterior(
        &self,
        prior_alpha: f64,
        prior_beta: f64,
        n: usize,
        k: usize,
    ) -> TemperedPosterior {
        TemperedPosterior::beta_binomial(prior_alpha, prior_beta, n, k, self.eta)
    }

    /// Get evidence for decision core.
    pub fn evidence(&self, credal: &CredalSet, posterior: f64, n: usize) -> RobustEvidence {
        let result = self.is_action_robust(credal, posterior);

        RobustEvidence {
            eta: self.eta,
            tempering_active: self.eta < 1.0 - 1e-10,
            credal_width: credal.width(),
            worst_case: result.worst_case_posterior,
            is_robust: result.is_robust,
            effective_n: self.eta * n as f64,
        }
    }
}

impl Default for RobustGate {
    fn default() -> Self {
        Self::new(RobustConfig::default())
    }
}

/// Compute worst-case expected loss over a credal set.
///
/// Given loss matrix L[action, class] and credal priors P(class) ∈ [l_c, u_c],
/// find max_{P ∈ credal} E_P[L[a, C]].
pub fn worst_case_expected_loss(
    loss_row: &[f64],        // L[action, class] for each class
    credal_sets: &[CredalSet], // Credal set for each class probability
) -> f64 {
    if loss_row.len() != credal_sets.len() {
        return f64::INFINITY;
    }

    // Worst case: assign highest probability to highest loss classes
    let mut indexed: Vec<(usize, f64)> = loss_row.iter().enumerate().map(|(i, &l)| (i, l)).collect();
    indexed.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    let mut worst_loss = 0.0;
    let mut remaining_prob = 1.0;

    for (idx, loss) in indexed {
        let credal = &credal_sets[idx];
        // Assign as much probability as possible to this class
        let assign = credal.upper.min(remaining_prob);
        worst_loss += assign * loss;
        remaining_prob -= assign;

        if remaining_prob <= 1e-10 {
            break;
        }
    }

    worst_loss
}

/// Compute best-case expected loss over a credal set.
pub fn best_case_expected_loss(
    loss_row: &[f64],
    credal_sets: &[CredalSet],
) -> f64 {
    if loss_row.len() != credal_sets.len() {
        return f64::INFINITY;
    }

    // Best case: assign highest probability to lowest loss classes
    let mut indexed: Vec<(usize, f64)> = loss_row.iter().enumerate().map(|(i, &l)| (i, l)).collect();
    indexed.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

    let mut best_loss = 0.0;
    let mut remaining_prob = 1.0;

    for (idx, loss) in indexed {
        let credal = &credal_sets[idx];
        // Assign as much probability as possible to this class
        let assign = credal.upper.min(remaining_prob);
        best_loss += assign * loss;
        remaining_prob -= assign;

        if remaining_prob <= 1e-10 {
            break;
        }
    }

    best_loss
}

/// Select optimal η using prequential validation.
///
/// Returns the η that minimizes cumulative log-loss on held-out predictions.
pub fn select_eta_prequential(
    prior_alpha: f64,
    prior_beta: f64,
    observations: &[(usize, usize)], // (n, k) pairs
    eta_candidates: &[f64],
) -> f64 {
    if observations.is_empty() || eta_candidates.is_empty() {
        return 1.0;
    }

    let mut best_eta = 1.0;
    let mut best_loss = f64::INFINITY;

    for &eta in eta_candidates {
        let mut cumulative_loss = 0.0;
        let mut alpha = prior_alpha;
        let mut beta = prior_beta;

        for &(n, k) in observations {
            // Predictive probability before seeing data
            let p_pred = alpha / (alpha + beta);

            // Log-loss
            let k_rate = k as f64 / n.max(1) as f64;
            let loss = if k_rate > 0.0 {
                -k_rate * p_pred.max(1e-10).ln()
            } else {
                -(1.0 - k_rate) * (1.0 - p_pred).max(1e-10).ln()
            };
            cumulative_loss += loss;

            // Tempered update
            alpha += eta * k as f64;
            beta += eta * (n - k) as f64;
        }

        if cumulative_loss < best_loss {
            best_loss = cumulative_loss;
            best_eta = eta;
        }
    }

    best_eta
}

/// Approximate standard normal quantile (probit function).
fn normal_quantile(p: f64) -> f64 {
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
    let t = if p < 0.5 {
        (-2.0 * p.ln()).sqrt()
    } else {
        (-2.0 * (1.0 - p).ln()).sqrt()
    };

    let c0 = 2.515517;
    let c1 = 0.802853;
    let c2 = 0.010328;
    let d1 = 1.432788;
    let d2 = 0.189269;
    let d3 = 0.001308;

    let approx = t - (c0 + c1 * t + c2 * t * t) / (1.0 + d1 * t + d2 * t * t + d3 * t * t * t);

    if p < 0.5 {
        -approx
    } else {
        approx
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credal_set_interval() {
        let c = CredalSet::interval(0.3, 0.7);
        assert!((c.lower - 0.3).abs() < 1e-10);
        assert!((c.upper - 0.7).abs() < 1e-10);
        assert!((c.width() - 0.4).abs() < 1e-10);
        assert!((c.center() - 0.5).abs() < 1e-10);
    }

    #[test]
    fn test_credal_set_point() {
        let c = CredalSet::point(0.5);
        assert!(c.is_precise());
        assert!((c.width()).abs() < 1e-10);
    }

    #[test]
    fn test_credal_set_symmetric() {
        let c = CredalSet::symmetric(0.5, 0.2);
        assert!((c.lower - 0.3).abs() < 1e-10);
        assert!((c.upper - 0.7).abs() < 1e-10);
    }

    #[test]
    fn test_credal_set_expand() {
        let c = CredalSet::interval(0.4, 0.6);
        let expanded = c.expand(2.0);
        assert!((expanded.width() - 0.4).abs() < 1e-10); // 0.2 * 2 = 0.4
    }

    #[test]
    fn test_credal_contains() {
        let c = CredalSet::interval(0.3, 0.7);
        assert!(c.contains(0.5));
        assert!(c.contains(0.3));
        assert!(c.contains(0.7));
        assert!(!c.contains(0.2));
        assert!(!c.contains(0.8));
    }

    #[test]
    fn test_credal_intersect() {
        let c1 = CredalSet::interval(0.2, 0.6);
        let c2 = CredalSet::interval(0.4, 0.8);
        let intersection = c1.intersect(&c2).unwrap();
        assert!((intersection.lower - 0.4).abs() < 1e-10);
        assert!((intersection.upper - 0.6).abs() < 1e-10);
    }

    #[test]
    fn test_credal_no_intersect() {
        let c1 = CredalSet::interval(0.1, 0.3);
        let c2 = CredalSet::interval(0.5, 0.7);
        assert!(c1.intersect(&c2).is_none());
    }

    #[test]
    fn test_credal_hull() {
        let c1 = CredalSet::interval(0.2, 0.4);
        let c2 = CredalSet::interval(0.6, 0.8);
        let hull = c1.hull(&c2);
        assert!((hull.lower - 0.2).abs() < 1e-10);
        assert!((hull.upper - 0.8).abs() < 1e-10);
    }

    #[test]
    fn test_tempered_posterior_standard() {
        let tp = TemperedPosterior::standard(2.0, 2.0, 10, 7);
        assert!((tp.alpha - 9.0).abs() < 1e-10); // 2 + 7
        assert!((tp.beta - 5.0).abs() < 1e-10); // 2 + 3
        assert!((tp.eta - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_tempered_posterior_tempered() {
        let tp = TemperedPosterior::beta_binomial(2.0, 2.0, 10, 7, 0.5);
        assert!((tp.alpha - 5.5).abs() < 1e-10); // 2 + 0.5*7
        assert!((tp.beta - 3.5).abs() < 1e-10); // 2 + 0.5*3
        assert!((tp.eta - 0.5).abs() < 1e-10);
    }

    #[test]
    fn test_tempered_posterior_mean() {
        let tp = TemperedPosterior::standard(2.0, 2.0, 10, 7);
        let mean = tp.mean();
        assert!((mean - 9.0 / 14.0).abs() < 1e-10);
    }

    #[test]
    fn test_tempered_posterior_effective_n() {
        let tp = TemperedPosterior::beta_binomial(2.0, 2.0, 10, 7, 0.5);
        assert!((tp.effective_sample_size() - 5.0).abs() < 1e-10);
    }

    #[test]
    fn test_robust_gate_default() {
        let gate = RobustGate::default();
        assert!((gate.eta() - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_robust_gate_ppc_failure() {
        let mut gate = RobustGate::new(RobustConfig::default());
        gate.signal_ppc_failure();
        assert!(gate.eta() < 1.0);
    }

    #[test]
    fn test_robust_gate_drift() {
        let mut gate = RobustGate::new(RobustConfig::default());
        gate.signal_drift();
        assert!(gate.eta() < 1.0);
        assert!(gate.drift_detected);
    }

    #[test]
    fn test_robust_gate_min_eta() {
        let mut gate = RobustGate::new(RobustConfig {
            min_eta: 0.5,
            eta_ppc_reduction: 0.2,
            ..Default::default()
        });

        for _ in 0..10 {
            gate.signal_ppc_failure();
        }

        assert!((gate.eta() - 0.5).abs() < 1e-10);
    }

    #[test]
    fn test_is_action_robust() {
        let gate = RobustGate::new(RobustConfig {
            min_robust_posterior: 0.7,
            ..Default::default()
        });

        // High posterior, narrow credal
        let credal = CredalSet::interval(0.9, 1.0);
        let result = gate.is_action_robust(&credal, 0.9);
        assert!(result.is_robust); // 0.9 * 0.9 = 0.81 > 0.7

        // Low credal lower bound
        let credal_wide = CredalSet::interval(0.5, 0.9);
        let result2 = gate.is_action_robust(&credal_wide, 0.9);
        assert!(!result2.is_robust); // 0.5 * 0.9 = 0.45 < 0.7
    }

    #[test]
    fn test_worst_case_expected_loss() {
        // Two classes, losses [1.0, 0.0] (class 0 is bad, class 1 is good)
        let losses = [1.0, 0.0];
        let credals = [
            CredalSet::interval(0.1, 0.3), // P(class 0) ∈ [0.1, 0.3]
            CredalSet::interval(0.7, 0.9), // P(class 1) ∈ [0.7, 0.9]
        ];

        let worst = worst_case_expected_loss(&losses, &credals);
        // Worst case: max P(class 0) = 0.3, loss = 0.3 * 1.0 + 0.7 * 0.0 = 0.3
        assert!((worst - 0.3).abs() < 1e-10);
    }

    #[test]
    fn test_best_case_expected_loss() {
        let losses = [1.0, 0.0];
        let credals = [
            CredalSet::interval(0.1, 0.3),
            CredalSet::interval(0.7, 0.9),
        ];

        let best = best_case_expected_loss(&losses, &credals);
        // Best case: assign max to lowest loss (class 1), so P(class 1) = 0.9
        // Loss = 0.1 * 1.0 + 0.9 * 0.0 = 0.1
        assert!((best - 0.1).abs() < 1e-10);
    }

    #[test]
    fn test_select_eta_prequential() {
        let observations = vec![(10, 7), (10, 8), (10, 6)];
        let candidates = vec![0.5, 0.7, 0.9, 1.0];

        let eta = select_eta_prequential(2.0, 2.0, &observations, &candidates);
        // Should return some valid eta
        assert!(eta > 0.0 && eta <= 1.0);
    }

    #[test]
    fn test_config_presets() {
        let conservative = RobustConfig::conservative();
        assert!(conservative.default_eta < 1.0);
        assert!(conservative.min_robust_posterior > 0.7);

        let strict = RobustConfig::strict();
        assert!(strict.min_eta > 0.5);
    }

    #[test]
    fn test_robust_evidence() {
        let gate = RobustGate::default();
        let credal = CredalSet::interval(0.8, 0.9);
        let evidence = gate.evidence(&credal, 0.85, 100);

        assert!((evidence.eta - 1.0).abs() < 1e-10);
        assert!(!evidence.tempering_active);
        assert!((evidence.credal_width - 0.1).abs() < 1e-10);
    }

    #[test]
    fn test_tempered_variance() {
        let tp = TemperedPosterior::standard(2.0, 2.0, 10, 5);
        let var = tp.variance();
        // Beta(7, 7): var = 7*7 / (14*14*15) = 49/2940
        assert!((var - 49.0 / 2940.0).abs() < 1e-10);
    }

    #[test]
    fn test_tempered_credible_interval() {
        let tp = TemperedPosterior::standard(10.0, 10.0, 0, 0);
        let (lower, upper) = tp.credible_interval(0.95);
        assert!(lower < 0.5);
        assert!(upper > 0.5);
        assert!(lower < upper);
    }

    #[test]
    fn test_normal_quantile() {
        let z50 = normal_quantile(0.5);
        assert!(z50.abs() < 1e-6);

        let z975 = normal_quantile(0.975);
        assert!((z975 - 1.96).abs() < 0.01);

        let z025 = normal_quantile(0.025);
        assert!((z025 + 1.96).abs() < 0.01);
    }

    #[test]
    fn test_credal_clamps() {
        // Test that out-of-bounds values are clamped
        let c = CredalSet::interval(-0.5, 1.5);
        assert!((c.lower - 0.0).abs() < 1e-10);
        assert!((c.upper - 1.0).abs() < 1e-10);

        // Test inverted bounds
        let c2 = CredalSet::interval(0.8, 0.2);
        assert!(c2.lower <= c2.upper);
    }

    #[test]
    fn test_tempered_mode() {
        // Strong evidence for success
        let tp = TemperedPosterior::standard(2.0, 2.0, 100, 80);
        let mode = tp.mode();
        assert!(mode > 0.7); // Should be close to 80/100

        // Uniform prior, no data
        let tp2 = TemperedPosterior::standard(1.0, 1.0, 0, 0);
        let mode2 = tp2.mode();
        assert!((mode2 - 0.5).abs() < 1e-10);
    }
}
