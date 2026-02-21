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

/// Configuration for minimax (least-favorable prior) gating.
#[derive(Debug, Clone)]
pub struct MinimaxConfig {
    /// Whether minimax gating is enabled.
    pub enabled: bool,
    /// Maximum allowed worst-case expected loss.
    pub max_worst_case_loss: f64,
}

impl Default for MinimaxConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_worst_case_loss: 0.25,
        }
    }
}

impl MinimaxConfig {
    /// Disable minimax gating (fallback to baseline behavior).
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Default::default()
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
    pub fn beta_binomial(prior_alpha: f64, prior_beta: f64, n: usize, k: usize, eta: f64) -> Self {
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

    /// Posterior mean E\[θ\] = α / (α + β).
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

    #[error(
        "decision not robust: worst-case posterior {worst_case:.4} < threshold {threshold:.4}"
    )]
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

/// Result of minimax expected-loss gating.
#[derive(Debug, Clone, Serialize)]
pub struct MinimaxResult {
    /// Whether the action passes the minimax gate.
    pub is_safe: bool,
    /// Whether minimax gating was enabled.
    pub enabled: bool,
    /// Worst-case expected loss over the credal set.
    pub worst_case_loss: f64,
    /// Best-case expected loss over the credal set.
    pub best_case_loss: f64,
    /// Loss threshold used for gating.
    pub threshold: f64,
    /// Human-readable reason for the decision.
    pub reason: String,
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

// =============================================================================
// Minimax / Least-Favorable Prior Gating
// =============================================================================

/// The least-favorable prior distribution over classes.
///
/// This is the prior in the credal set that maximizes expected loss for a given action.
#[derive(Debug, Clone, Serialize)]
pub struct LeastFavorablePrior {
    /// Probability assigned to each class under the least-favorable prior.
    pub class_probs: Vec<f64>,
    /// Names/labels for each class (for explainability).
    pub class_names: Vec<String>,
    /// The expected loss under this prior.
    pub expected_loss: f64,
    /// Description of why this prior is least favorable.
    pub description: String,
}

impl LeastFavorablePrior {
    /// Compute the least-favorable prior for a given loss row and credal sets.
    ///
    /// The least-favorable prior assigns maximum probability to high-loss classes
    /// while respecting the credal constraints.
    pub fn compute(loss_row: &[f64], credal_sets: &[CredalSet], class_names: &[&str]) -> Self {
        if loss_row.len() != credal_sets.len() || loss_row.len() != class_names.len() {
            return Self {
                class_probs: vec![],
                class_names: vec![],
                expected_loss: f64::INFINITY,
                description: "Invalid input dimensions".to_string(),
            };
        }

        // 1. Start with minimum required probability for each class
        let mut probs: Vec<f64> = credal_sets.iter().map(|c| c.lower).collect();
        let current_sum: f64 = probs.iter().sum();
        let mut remaining_prob = (1.0 - current_sum).max(0.0);

        // 2. Sort classes by loss (highest first)
        let mut indexed: Vec<(usize, f64)> =
            loss_row.iter().enumerate().map(|(i, &l)| (i, l)).collect();
        indexed.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        // 3. Greedily assign remaining probability to highest-loss classes
        let mut high_loss_classes = Vec::new();

        for (idx, _class_loss) in &indexed {
            let credal = &credal_sets[*idx];
            let capacity = credal.upper - credal.lower;
            let assign = capacity.min(remaining_prob);
            probs[*idx] += assign;
            remaining_prob -= assign;

            if assign > 0.0 {
                high_loss_classes.push(class_names[*idx].to_string());
            }

            if remaining_prob <= 1e-10 {
                break;
            }
        }

        // Compute expected loss from the final probabilities
        let loss: f64 = loss_row.iter().zip(probs.iter()).map(|(l, p)| l * p).sum();

        let description = if high_loss_classes.is_empty() {
            "No high-loss classes identified".to_string()
        } else if high_loss_classes.len() == 1 {
            format!(
                "Concentrates probability on {} (highest loss)",
                high_loss_classes[0]
            )
        } else {
            format!(
                "Concentrates probability on high-loss classes: {}",
                high_loss_classes.join(", ")
            )
        };

        Self {
            class_probs: probs,
            class_names: class_names.iter().map(|s| s.to_string()).collect(),
            expected_loss: loss,
            description,
        }
    }
}

/// Analysis of decision stability across the credal set.
#[derive(Debug, Clone, Serialize)]
pub struct DecisionStabilityAnalysis {
    /// Whether the optimal action is stable across all priors in the credal set.
    pub is_stable: bool,
    /// The regret gap: worst-case loss - best-case loss.
    pub regret_gap: f64,
    /// Threshold shift: how much would the threshold need to change to flip the decision?
    pub threshold_shift: Option<f64>,
    /// Actions that are optimal under some prior in the credal set.
    pub viable_actions: Vec<String>,
    /// Human-readable explanation.
    pub explanation: String,
}

impl DecisionStabilityAnalysis {
    /// Analyze decision stability for multiple actions across credal priors.
    ///
    /// # Arguments
    /// * `action_losses` - Vector of (action_name, loss_row) pairs
    /// * `credal_sets` - Credal set for each class
    /// * `threshold` - Decision threshold for action safety
    pub fn analyze(
        action_losses: &[(&str, &[f64])],
        credal_sets: &[CredalSet],
        threshold: f64,
    ) -> Self {
        if action_losses.is_empty() {
            return Self {
                is_stable: true,
                regret_gap: 0.0,
                threshold_shift: None,
                viable_actions: vec![],
                explanation: "No actions to analyze".to_string(),
            };
        }

        // Compute worst-case and best-case losses for each action
        let mut worst_cases: Vec<(&str, f64)> = Vec::new();
        let mut best_cases: Vec<(&str, f64)> = Vec::new();

        for (name, losses) in action_losses {
            let worst = worst_case_expected_loss(losses, credal_sets);
            let best = best_case_expected_loss(losses, credal_sets);
            worst_cases.push((name, worst));
            best_cases.push((name, best));
        }

        // Find actions that are optimal under some prior
        // An action is viable if its best-case is better than others' worst-case
        let mut viable_actions = Vec::new();
        let global_best_worst = worst_cases
            .iter()
            .map(|(_, w)| *w)
            .fold(f64::INFINITY, f64::min);

        for ((name, _worst), (_, best)) in worst_cases.iter().zip(best_cases.iter()) {
            // Action is viable if it could be optimal under some prior
            if *best <= global_best_worst + 1e-10 {
                viable_actions.push(name.to_string());
            }
        }

        // Decision is stable if only one action is viable
        let is_stable = viable_actions.len() <= 1;

        // Compute regret gap
        let min_worst = worst_cases
            .iter()
            .map(|(_, w)| *w)
            .fold(f64::INFINITY, f64::min);
        let min_best = best_cases
            .iter()
            .map(|(_, b)| *b)
            .fold(f64::INFINITY, f64::min);
        let regret_gap = min_worst - min_best;

        // Compute threshold shift needed to flip the decision
        let threshold_shift = if min_worst > threshold {
            // Currently blocked; how much would threshold need to increase?
            Some(min_worst - threshold)
        } else if min_worst < threshold - regret_gap {
            // Currently safe by a margin; how much could threshold decrease?
            Some(threshold - min_worst)
        } else {
            None
        };

        let explanation = if is_stable {
            if viable_actions.is_empty() {
                "No viable actions under credal constraints".to_string()
            } else {
                format!(
                    "Decision stable: {} is optimal across all priors (regret gap: {:.4})",
                    viable_actions[0], regret_gap
                )
            }
        } else {
            format!(
                "Decision unstable: {} actions are viable under different priors (regret gap: {:.4})",
                viable_actions.len(),
                regret_gap
            )
        };

        Self {
            is_stable,
            regret_gap,
            threshold_shift,
            viable_actions,
            explanation,
        }
    }
}

/// Evidence from minimax gating for decision-core integration.
#[derive(Debug, Clone, Serialize)]
pub struct MinimaxEvidence {
    /// Whether minimax gating is enabled.
    pub enabled: bool,
    /// Worst-case expected loss.
    pub worst_case_loss: f64,
    /// Best-case expected loss.
    pub best_case_loss: f64,
    /// Regret gap (worst - best).
    pub regret_gap: f64,
    /// Whether the decision passed the minimax gate.
    pub passed_gate: bool,
    /// Least-favorable prior class probabilities (for audit).
    pub lfp_probs: Option<Vec<f64>>,
    /// Decision stability indicator.
    pub is_stable: bool,
}

/// Minimax gate for conservative decision-making under prior uncertainty.
///
/// Unlike `RobustGate` which focuses on posterior robustness, `MinimaxGate`
/// focuses on expected loss robustness: it only allows actions whose worst-case
/// expected loss (over all priors in the credal set) is acceptable.
pub struct MinimaxGate {
    config: MinimaxConfig,
    /// Cached least-favorable prior from last computation.
    last_lfp: Option<LeastFavorablePrior>,
    /// Cached stability analysis from last computation.
    last_stability: Option<DecisionStabilityAnalysis>,
}

impl MinimaxGate {
    /// Create a new minimax gate.
    pub fn new(config: MinimaxConfig) -> Self {
        Self {
            config,
            last_lfp: None,
            last_stability: None,
        }
    }

    /// Check if an action is safe under minimax criteria.
    pub fn is_safe(&self, loss_row: &[f64], credal_sets: &[CredalSet]) -> MinimaxResult {
        minimax_expected_loss_gate(loss_row, credal_sets, &self.config)
    }

    /// Compute and cache the least-favorable prior for a given action.
    pub fn compute_lfp(
        &mut self,
        loss_row: &[f64],
        credal_sets: &[CredalSet],
        class_names: &[&str],
    ) -> &LeastFavorablePrior {
        let lfp = LeastFavorablePrior::compute(loss_row, credal_sets, class_names);
        self.last_lfp = Some(lfp);
        self.last_lfp.as_ref().unwrap()
    }

    /// Analyze decision stability across multiple actions.
    pub fn analyze_stability(
        &mut self,
        action_losses: &[(&str, &[f64])],
        credal_sets: &[CredalSet],
    ) -> &DecisionStabilityAnalysis {
        let stability = DecisionStabilityAnalysis::analyze(
            action_losses,
            credal_sets,
            self.config.max_worst_case_loss,
        );
        self.last_stability = Some(stability);
        self.last_stability.as_ref().unwrap()
    }

    /// Get the last computed least-favorable prior (if any).
    pub fn last_lfp(&self) -> Option<&LeastFavorablePrior> {
        self.last_lfp.as_ref()
    }

    /// Get the last computed stability analysis (if any).
    pub fn last_stability(&self) -> Option<&DecisionStabilityAnalysis> {
        self.last_stability.as_ref()
    }

    /// Get evidence for decision-core integration.
    pub fn evidence(&self, loss_row: &[f64], credal_sets: &[CredalSet]) -> MinimaxEvidence {
        let result = self.is_safe(loss_row, credal_sets);
        let regret_gap = result.worst_case_loss - result.best_case_loss;

        MinimaxEvidence {
            enabled: self.config.enabled,
            worst_case_loss: result.worst_case_loss,
            best_case_loss: result.best_case_loss,
            regret_gap,
            passed_gate: result.is_safe,
            lfp_probs: self.last_lfp.as_ref().map(|lfp| lfp.class_probs.clone()),
            is_stable: self
                .last_stability
                .as_ref()
                .map(|s| s.is_stable)
                .unwrap_or(true),
        }
    }

    /// Reset cached state.
    pub fn reset(&mut self) {
        self.last_lfp = None;
        self.last_stability = None;
    }

    /// Get current configuration.
    pub fn config(&self) -> &MinimaxConfig {
        &self.config
    }

    /// Update configuration.
    pub fn set_config(&mut self, config: MinimaxConfig) {
        self.config = config;
        self.reset();
    }
}

impl Default for MinimaxGate {
    fn default() -> Self {
        Self::new(MinimaxConfig::default())
    }
}

/// Apply minimax expected-loss gating for a single action.
pub fn minimax_expected_loss_gate(
    loss_row: &[f64],
    credal_sets: &[CredalSet],
    config: &MinimaxConfig,
) -> MinimaxResult {
    let worst_case = worst_case_expected_loss(loss_row, credal_sets);
    let best_case = best_case_expected_loss(loss_row, credal_sets);

    if !config.enabled {
        return MinimaxResult {
            is_safe: true,
            enabled: false,
            worst_case_loss: worst_case,
            best_case_loss: best_case,
            threshold: config.max_worst_case_loss,
            reason: "Minimax gate disabled; fallback to baseline decision".to_string(),
        };
    }

    let is_safe = worst_case <= config.max_worst_case_loss;
    let reason = if is_safe {
        format!(
            "Minimax gate passed: worst-case loss {:.4} <= {:.4}",
            worst_case, config.max_worst_case_loss
        )
    } else {
        format!(
            "Minimax gate failed: worst-case loss {:.4} > {:.4}",
            worst_case, config.max_worst_case_loss
        )
    };

    MinimaxResult {
        is_safe,
        enabled: true,
        worst_case_loss: worst_case,
        best_case_loss: best_case,
        threshold: config.max_worst_case_loss,
        reason,
    }
}

/// Compute worst-case expected loss over a credal set.
///
/// Given loss matrix L[action, class] and credal priors P(class) ∈ [l_c, u_c],
/// find max_{P ∈ credal} E_P[L[a, C]].
pub fn worst_case_expected_loss(
    loss_row: &[f64],          // L[action, class] for each class
    credal_sets: &[CredalSet], // Credal set for each class probability
) -> f64 {
    if loss_row.len() != credal_sets.len() {
        return f64::INFINITY;
    }
    if !is_feasible_credal_simplex(credal_sets) {
        return f64::INFINITY;
    }

    // 1. Start with minimum required probability for each class
    let mut probs: Vec<f64> = credal_sets.iter().map(|c| c.lower).collect();
    let current_sum: f64 = probs.iter().sum();
    let mut remaining_prob = (1.0 - current_sum).max(0.0);

    // 2. Sort classes by loss (highest first for worst case)
    // We store indices to update the correct probabilities
    let mut indexed: Vec<(usize, f64)> =
        loss_row.iter().enumerate().map(|(i, &l)| (i, l)).collect();
    indexed.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    // 3. Greedily assign remaining probability to highest loss classes
    // respecting upper bounds
    for (idx, _) in indexed {
        let credal = &credal_sets[idx];
        let capacity = credal.upper - credal.lower;
        let assign = capacity.min(remaining_prob);
        probs[idx] += assign;
        remaining_prob -= assign;

        if remaining_prob <= 1e-10 {
            break;
        }
    }

    // 4. Compute expected loss
    loss_row.iter().zip(probs.iter()).map(|(l, p)| l * p).sum()
}

/// Compute best-case expected loss over a credal set.
pub fn best_case_expected_loss(loss_row: &[f64], credal_sets: &[CredalSet]) -> f64 {
    if loss_row.len() != credal_sets.len() {
        return f64::INFINITY;
    }
    if !is_feasible_credal_simplex(credal_sets) {
        return f64::INFINITY;
    }

    // 1. Start with minimum required probability for each class
    let mut probs: Vec<f64> = credal_sets.iter().map(|c| c.lower).collect();
    let current_sum: f64 = probs.iter().sum();
    let mut remaining_prob = (1.0 - current_sum).max(0.0);

    // 2. Sort classes by loss (lowest first for best case)
    let mut indexed: Vec<(usize, f64)> =
        loss_row.iter().enumerate().map(|(i, &l)| (i, l)).collect();
    indexed.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

    // 3. Greedily assign remaining probability to lowest loss classes
    for (idx, _) in indexed {
        let credal = &credal_sets[idx];
        let capacity = credal.upper - credal.lower;
        let assign = capacity.min(remaining_prob);
        probs[idx] += assign;
        remaining_prob -= assign;

        if remaining_prob <= 1e-10 {
            break;
        }
    }

    // 4. Compute expected loss
    loss_row.iter().zip(probs.iter()).map(|(l, p)| l * p).sum()
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

        for &(n, k_raw) in observations {
            // Guard invalid summaries (k > n) to avoid usize underflow in (n - k).
            let k = k_raw.min(n);
            // Predictive probability before seeing data
            let p_pred = alpha / (alpha + beta);

            // Cross-entropy log-loss: -k_rate * ln(p) - (1-k_rate) * ln(1-p)
            let k_rate = k as f64 / n.max(1) as f64;
            let loss =
                -k_rate * p_pred.max(1e-10).ln() - (1.0 - k_rate) * (1.0 - p_pred).max(1e-10).ln();
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

fn is_feasible_credal_simplex(credal_sets: &[CredalSet]) -> bool {
    // Feasibility for interval probabilities:
    // Σ lower_i <= 1 <= Σ upper_i
    let lower_sum: f64 = credal_sets.iter().map(|c| c.lower).sum();
    let upper_sum: f64 = credal_sets.iter().map(|c| c.upper).sum();
    let eps = 1e-10;
    lower_sum <= 1.0 + eps && upper_sum + eps >= 1.0
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
        let credals = [CredalSet::interval(0.1, 0.3), CredalSet::interval(0.7, 0.9)];

        let best = best_case_expected_loss(&losses, &credals);
        // Best case: assign max to lowest loss (class 1), so P(class 1) = 0.9
        // Loss = 0.1 * 1.0 + 0.9 * 0.0 = 0.1
        assert!((best - 0.1).abs() < 1e-10);
    }

    #[test]
    fn test_minimax_gate_blocks_on_worst_case() {
        let losses = [0.1, 1.0];
        let credals = [CredalSet::interval(0.0, 0.9), CredalSet::interval(0.1, 1.0)];
        let config = MinimaxConfig {
            enabled: true,
            max_worst_case_loss: 0.5,
        };

        let result = minimax_expected_loss_gate(&losses, &credals, &config);
        assert!(!result.is_safe);
        assert!(result.worst_case_loss > config.max_worst_case_loss);
        assert!(result.reason.contains("failed"));
    }

    #[test]
    fn test_minimax_gate_disabled_allows() {
        let losses = [0.1, 1.0];
        let credals = [CredalSet::interval(0.0, 0.9), CredalSet::interval(0.1, 1.0)];
        let config = MinimaxConfig::disabled();

        let result = minimax_expected_loss_gate(&losses, &credals, &config);
        assert!(result.is_safe);
        assert!(!result.enabled);
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
    fn test_select_eta_prequential_clamps_invalid_k_gt_n() {
        let observations = vec![(5, 7), (0, 3), (10, 6)];
        let candidates = vec![0.5, 1.0];
        let eta = select_eta_prequential(2.0, 2.0, &observations, &candidates);
        assert!(eta.is_finite());
        assert!(candidates.contains(&eta));
    }

    #[test]
    fn test_expected_loss_returns_infinity_for_infeasible_credal_simplex() {
        let losses = [1.0, 0.0];
        let infeasible = [CredalSet::interval(0.0, 0.4), CredalSet::interval(0.0, 0.4)];

        let worst = worst_case_expected_loss(&losses, &infeasible);
        let best = best_case_expected_loss(&losses, &infeasible);

        assert!(worst.is_infinite());
        assert!(best.is_infinite());
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

    // =========================================================================
    // Minimax Gate Tests (nao.20)
    // =========================================================================

    #[test]
    fn test_least_favorable_prior_simple() {
        // Two classes: useful (loss=0) and abandoned (loss=1)
        let losses = [0.0, 1.0];
        let credals = [
            CredalSet::interval(0.6, 0.9), // P(useful)
            CredalSet::interval(0.1, 0.4), // P(abandoned)
        ];
        let class_names = ["useful", "abandoned"];

        let lfp = LeastFavorablePrior::compute(&losses, &credals, &class_names);

        // LFP should maximize probability on highest-loss class (abandoned)
        // P(abandoned) should be at upper bound = 0.4
        assert!((lfp.class_probs[1] - 0.4).abs() < 1e-10);
        assert!((lfp.class_probs[0] - 0.6).abs() < 1e-10);
        assert!((lfp.expected_loss - 0.4).abs() < 1e-10);
        assert!(lfp.description.contains("abandoned"));
    }

    #[test]
    fn test_least_favorable_prior_four_classes() {
        // Four classes with varying losses
        let losses = [0.0, 0.3, 0.8, 1.0]; // useful, useful_bad, abandoned, zombie
        let credals = [
            CredalSet::interval(0.2, 0.5),
            CredalSet::interval(0.2, 0.4),
            CredalSet::interval(0.2, 0.4),
            CredalSet::interval(0.0, 0.2),
        ];
        let class_names = ["useful", "useful_bad", "abandoned", "zombie"];

        let lfp = LeastFavorablePrior::compute(&losses, &credals, &class_names);

        // LFP should be valid distribution (sums to 1)
        let sum: f64 = lfp.class_probs.iter().sum();
        assert!(
            (sum - 1.0).abs() < 1e-10,
            "Probs should sum to 1, got {}",
            sum
        );

        // Expected loss should be computable
        let expected: f64 = lfp
            .class_probs
            .iter()
            .zip(losses.iter())
            .map(|(p, l)| p * l)
            .sum();
        assert!((lfp.expected_loss - expected).abs() < 1e-10);

        // High-loss classes should get priority
        assert!(lfp.class_probs[3] >= lfp.class_probs[0]); // zombie >= useful
    }

    #[test]
    fn test_minimax_gate_struct() {
        let config = MinimaxConfig {
            enabled: true,
            max_worst_case_loss: 0.3,
        };
        let gate = MinimaxGate::new(config);

        let losses = [0.0, 1.0];
        let credals = [CredalSet::interval(0.7, 0.9), CredalSet::interval(0.1, 0.3)];

        let result = gate.is_safe(&losses, &credals);
        // Worst case: 0.3 * 1.0 = 0.3, which equals threshold
        assert!(result.is_safe);
    }

    #[test]
    fn test_minimax_gate_compute_lfp() {
        let mut gate = MinimaxGate::default();

        let losses = [0.1, 0.5, 0.9];
        let credals = [
            CredalSet::interval(0.2, 0.5),
            CredalSet::interval(0.2, 0.4),
            CredalSet::interval(0.2, 0.4),
        ];
        let class_names = ["class_a", "class_b", "class_c"];

        let lfp = gate.compute_lfp(&losses, &credals, &class_names);

        assert!(lfp.expected_loss > 0.0);
        assert!(!lfp.class_probs.is_empty());

        // Should be cached
        assert!(gate.last_lfp().is_some());
    }

    #[test]
    fn test_decision_stability_stable() {
        // Two actions where Keep is clearly better
        let keep_losses = [0.0, 0.0, 0.1, 0.1];
        let kill_losses = [1.0, 0.5, 0.0, 0.0];
        let credals = [
            CredalSet::interval(0.6, 0.8),   // useful
            CredalSet::interval(0.1, 0.2),   // useful_bad
            CredalSet::interval(0.05, 0.15), // abandoned
            CredalSet::interval(0.0, 0.1),   // zombie
        ];

        let action_losses: Vec<(&str, &[f64])> =
            vec![("keep", &keep_losses[..]), ("kill", &kill_losses[..])];

        let analysis = DecisionStabilityAnalysis::analyze(&action_losses, &credals, 0.5);

        assert!(analysis.is_stable);
        assert!(analysis.viable_actions.contains(&"keep".to_string()));
        assert!(analysis.explanation.contains("stable"));
    }

    #[test]
    fn test_decision_stability_unstable() {
        // Two actions where the optimal depends on the prior
        let action_a_losses = [0.2, 0.8];
        let action_b_losses = [0.8, 0.2];
        let credals = [
            CredalSet::interval(0.3, 0.7), // class 0
            CredalSet::interval(0.3, 0.7), // class 1
        ];

        let action_losses: Vec<(&str, &[f64])> = vec![
            ("action_a", &action_a_losses[..]),
            ("action_b", &action_b_losses[..]),
        ];

        let analysis = DecisionStabilityAnalysis::analyze(&action_losses, &credals, 1.0);

        // With symmetric credal sets and symmetric losses, both actions should be viable
        assert!(!analysis.is_stable || analysis.viable_actions.len() > 1);
        assert!(analysis.regret_gap > 0.0);
    }

    #[test]
    fn test_minimax_gate_analyze_stability() {
        let mut gate = MinimaxGate::default();

        let keep_losses = [0.0, 0.1];
        let kill_losses = [1.0, 0.0];
        let credals = [CredalSet::interval(0.4, 0.6), CredalSet::interval(0.4, 0.6)];

        let action_losses: Vec<(&str, &[f64])> =
            vec![("keep", &keep_losses[..]), ("kill", &kill_losses[..])];

        let stability = gate.analyze_stability(&action_losses, &credals);

        assert!(!stability.viable_actions.is_empty());
        assert!(stability.regret_gap >= 0.0);

        // Should be cached
        assert!(gate.last_stability().is_some());
    }

    #[test]
    fn test_minimax_evidence() {
        let mut gate = MinimaxGate::new(MinimaxConfig {
            enabled: true,
            max_worst_case_loss: 0.5,
        });

        let losses = [0.0, 0.8];
        let credals = [CredalSet::interval(0.6, 0.8), CredalSet::interval(0.2, 0.4)];

        // First compute LFP so it gets cached
        gate.compute_lfp(&losses, &credals, &["class_a", "class_b"]);

        let evidence = gate.evidence(&losses, &credals);

        assert!(evidence.enabled);
        assert!(evidence.worst_case_loss >= evidence.best_case_loss);
        assert!(
            (evidence.regret_gap - (evidence.worst_case_loss - evidence.best_case_loss)).abs()
                < 1e-10
        );
        assert!(evidence.lfp_probs.is_some());
    }

    #[test]
    fn test_minimax_gate_reset() {
        let mut gate = MinimaxGate::default();

        let losses = [0.0, 1.0];
        let credals = [CredalSet::interval(0.5, 0.5), CredalSet::interval(0.5, 0.5)];

        gate.compute_lfp(&losses, &credals, &["a", "b"]);
        assert!(gate.last_lfp().is_some());

        gate.reset();
        assert!(gate.last_lfp().is_none());
        assert!(gate.last_stability().is_none());
    }

    #[test]
    fn test_minimax_flips_decision_on_lfp() {
        // Scenario where the naive expected loss (using point estimates) would choose Kill,
        // but the least-favorable prior analysis shows Keep is safer.

        // Point estimate: P(useful)=0.3, P(abandoned)=0.7
        // Keep losses: [0.0, 0.5] -> E[loss] = 0.0*0.3 + 0.5*0.7 = 0.35
        // Kill losses: [1.0, 0.0] -> E[loss] = 1.0*0.3 + 0.0*0.7 = 0.30 (Kill seems better)

        // But with credal sets P(useful) ∈ [0.2, 0.5], P(abandoned) ∈ [0.5, 0.8]:
        // Kill worst case: P(useful)=0.5 -> E[loss] = 1.0*0.5 + 0.0*0.5 = 0.5
        // Keep worst case: P(abandoned)=0.8 -> E[loss] = 0.0*0.2 + 0.5*0.8 = 0.4

        let keep_losses = [0.0, 0.5];
        let kill_losses = [1.0, 0.0];
        let credals = [
            CredalSet::interval(0.2, 0.5), // useful
            CredalSet::interval(0.5, 0.8), // abandoned
        ];

        let keep_worst = worst_case_expected_loss(&keep_losses, &credals);
        let kill_worst = worst_case_expected_loss(&kill_losses, &credals);

        // Under minimax, Keep is safer
        assert!(
            keep_worst < kill_worst,
            "Keep worst-case {} should be less than Kill worst-case {}",
            keep_worst,
            kill_worst
        );
    }

    #[test]
    fn test_decision_stability_threshold_shift() {
        let keep_losses = [0.1, 0.1];
        let credals = [CredalSet::interval(0.4, 0.6), CredalSet::interval(0.4, 0.6)];

        let action_losses: Vec<(&str, &[f64])> = vec![("keep", &keep_losses[..])];

        // Threshold below worst-case loss
        let analysis_blocked = DecisionStabilityAnalysis::analyze(&action_losses, &credals, 0.05);
        assert!(analysis_blocked.threshold_shift.is_some());

        // Threshold above worst-case loss
        let analysis_safe = DecisionStabilityAnalysis::analyze(&action_losses, &credals, 0.5);
        assert!(analysis_safe.threshold_shift.is_some() || analysis_safe.is_stable);
    }

    #[test]
    fn test_least_favorable_prior_invalid_input() {
        // Mismatched dimensions
        let losses = [0.0, 1.0];
        let credals = [CredalSet::interval(0.5, 0.5)]; // Only one credal
        let class_names = ["a", "b"];

        let lfp = LeastFavorablePrior::compute(&losses, &credals, &class_names);
        assert!(lfp.expected_loss.is_infinite());
        assert!(lfp.description.contains("Invalid"));
    }

    #[test]
    fn test_minimax_gate_config_update() {
        let mut gate = MinimaxGate::new(MinimaxConfig {
            enabled: true,
            max_worst_case_loss: 0.3,
        });

        let losses = [0.0, 0.5];
        let credals = [CredalSet::interval(0.4, 0.6), CredalSet::interval(0.4, 0.6)];

        // Initially safe
        let result1 = gate.is_safe(&losses, &credals);
        assert!(result1.is_safe); // worst = 0.3 <= 0.3

        // Update config with tighter threshold
        gate.set_config(MinimaxConfig {
            enabled: true,
            max_worst_case_loss: 0.2,
        });

        let result2 = gate.is_safe(&losses, &credals);
        assert!(!result2.is_safe); // worst = 0.3 > 0.2
    }
}
