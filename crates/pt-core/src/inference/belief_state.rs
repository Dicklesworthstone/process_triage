//! Belief-state update utilities for POMDP-style sequential decisions.
//!
//! This module implements lightweight belief-state tracking for the 4-class process model:
//! - Useful: Active, doing productive work
//! - UsefulBad: Active but consuming excessive resources
//! - Abandoned: No longer needed but still consuming resources
//! - Zombie: Defunct/dead process state
//!
//! The POMDP belief update equation:
//!   b_{t+1}(S) ∝ P(x_{t+1} | S) · Σ_{S'} P(S | S') · b_t(S')
//!
//! Where:
//! - b_t(S) is the belief probability for state S at time t
//! - P(S | S') is the transition model (how states evolve)
//! - P(x_{t+1} | S) is the observation likelihood (evidence given state)

use serde::Serialize;
use thiserror::Error;

/// Number of states in the POMDP model.
pub const NUM_STATES: usize = 4;

/// Error types for belief state operations.
#[derive(Debug, Error)]
pub enum BeliefStateError {
    #[error("Invalid probability distribution: does not sum to 1.0 (sum={0})")]
    InvalidDistribution(f64),

    #[error("Probability out of range [0, 1]: {0}")]
    ProbabilityOutOfRange(f64),

    #[error("Log probability is NaN or positive infinity")]
    InvalidLogProbability,

    #[error("Empty observation sequence")]
    EmptyObservations,

    #[error("Numerical underflow during belief update")]
    NumericalUnderflow,

    #[error("Invalid transition matrix: row {0} does not sum to 1.0")]
    InvalidTransitionRow(usize),
}

/// Result type for belief state operations.
pub type Result<T> = std::result::Result<T, BeliefStateError>;

/// Process state for the 4-class POMDP model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessState {
    /// Active process doing productive work.
    Useful = 0,
    /// Active but consuming excessive resources (CPU hog, memory leak).
    UsefulBad = 1,
    /// No longer needed but still consuming resources.
    Abandoned = 2,
    /// Defunct/zombie process state.
    Zombie = 3,
}

impl ProcessState {
    /// All possible states in order.
    pub const ALL: [ProcessState; NUM_STATES] = [
        ProcessState::Useful,
        ProcessState::UsefulBad,
        ProcessState::Abandoned,
        ProcessState::Zombie,
    ];

    /// Convert from index to state.
    pub fn from_index(idx: usize) -> Option<ProcessState> {
        match idx {
            0 => Some(ProcessState::Useful),
            1 => Some(ProcessState::UsefulBad),
            2 => Some(ProcessState::Abandoned),
            3 => Some(ProcessState::Zombie),
            _ => None,
        }
    }

    /// Convert state to index.
    pub fn to_index(self) -> usize {
        self as usize
    }

    /// Check if this is a "bad" state (candidate for action).
    pub fn is_actionable(self) -> bool {
        matches!(
            self,
            ProcessState::UsefulBad | ProcessState::Abandoned | ProcessState::Zombie
        )
    }

    /// Human-readable description.
    pub fn description(self) -> &'static str {
        match self {
            ProcessState::Useful => "Active and productive",
            ProcessState::UsefulBad => "Active but resource-heavy",
            ProcessState::Abandoned => "No longer needed",
            ProcessState::Zombie => "Defunct process",
        }
    }
}

impl std::fmt::Display for ProcessState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProcessState::Useful => write!(f, "Useful"),
            ProcessState::UsefulBad => write!(f, "UsefulBad"),
            ProcessState::Abandoned => write!(f, "Abandoned"),
            ProcessState::Zombie => write!(f, "Zombie"),
        }
    }
}

/// Belief state: probability distribution over the 4 states.
///
/// Maintains both linear and log-domain representations for numerical stability.
#[derive(Debug, Clone, Serialize)]
pub struct BeliefState {
    /// Probability for each state (sums to 1.0).
    pub probs: [f64; NUM_STATES],
    /// Log probabilities for numerical stability.
    pub log_probs: [f64; NUM_STATES],
}

impl BeliefState {
    /// Create a belief state from probabilities.
    pub fn from_probs(probs: [f64; NUM_STATES]) -> Result<Self> {
        // Validate probabilities
        for &p in &probs {
            if !(0.0..=1.0).contains(&p) {
                return Err(BeliefStateError::ProbabilityOutOfRange(p));
            }
        }

        let sum: f64 = probs.iter().sum();
        if (sum - 1.0).abs() > 1e-6 {
            return Err(BeliefStateError::InvalidDistribution(sum));
        }

        // Compute log probabilities
        let log_probs = probs.map(|p| if p > 0.0 { p.ln() } else { f64::NEG_INFINITY });

        Ok(Self { probs, log_probs })
    }

    /// Create a belief state from log probabilities.
    pub fn from_log_probs(log_probs: [f64; NUM_STATES]) -> Result<Self> {
        // Validate log probabilities
        for &lp in &log_probs {
            if lp.is_nan() || lp > 0.0 {
                return Err(BeliefStateError::InvalidLogProbability);
            }
        }

        // Use log-sum-exp for numerical stability
        let max_log = log_probs.iter().cloned().fold(f64::NEG_INFINITY, f64::max);

        if max_log == f64::NEG_INFINITY {
            return Err(BeliefStateError::NumericalUnderflow);
        }

        let sum_exp: f64 = log_probs.iter().map(|&lp| (lp - max_log).exp()).sum();
        let log_normalizer = max_log + sum_exp.ln();

        // Normalize
        let normalized_log_probs = log_probs.map(|lp| lp - log_normalizer);
        let probs = normalized_log_probs.map(|lp| lp.exp());

        Ok(Self {
            probs,
            log_probs: normalized_log_probs,
        })
    }

    /// Create a uniform belief state.
    pub fn uniform() -> Self {
        let p = 1.0 / NUM_STATES as f64;
        Self {
            probs: [p; NUM_STATES],
            log_probs: [p.ln(); NUM_STATES],
        }
    }

    /// Create a belief concentrated on a single state.
    pub fn certain(state: ProcessState) -> Self {
        let mut probs = [0.0; NUM_STATES];
        probs[state.to_index()] = 1.0;

        let mut log_probs = [f64::NEG_INFINITY; NUM_STATES];
        log_probs[state.to_index()] = 0.0;

        Self { probs, log_probs }
    }

    /// Get the most likely state.
    pub fn argmax(&self) -> ProcessState {
        let (idx, _) = self
            .probs
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .unwrap();
        ProcessState::from_index(idx).unwrap()
    }

    /// Get the probability of the most likely state.
    pub fn max_prob(&self) -> f64 {
        self.probs.iter().cloned().fold(0.0, f64::max)
    }

    /// Get the probability for a specific state.
    pub fn prob(&self, state: ProcessState) -> f64 {
        self.probs[state.to_index()]
    }

    /// Get the log probability for a specific state.
    pub fn log_prob(&self, state: ProcessState) -> f64 {
        self.log_probs[state.to_index()]
    }

    /// Compute the entropy of the belief distribution (in nats).
    pub fn entropy(&self) -> f64 {
        -self
            .probs
            .iter()
            .zip(self.log_probs.iter())
            .map(|(&p, &lp)| if p > 0.0 { p * lp } else { 0.0 })
            .sum::<f64>()
    }

    /// Check if the belief is concentrated (low entropy).
    pub fn is_concentrated(&self, threshold: f64) -> bool {
        self.max_prob() >= threshold
    }

    /// Compute probability mass on actionable states.
    pub fn actionable_mass(&self) -> f64 {
        ProcessState::ALL
            .iter()
            .filter(|s| s.is_actionable())
            .map(|&s| self.prob(s))
            .sum()
    }
}

impl Default for BeliefState {
    fn default() -> Self {
        Self::uniform()
    }
}

/// Transition model: P(S_next | S_current).
///
/// Row i, column j = P(S_j | S_i), i.e., probability of transitioning
/// from state i to state j.
#[derive(Debug, Clone, Serialize)]
pub struct TransitionModel {
    /// Transition probability matrix [from][to].
    pub matrix: [[f64; NUM_STATES]; NUM_STATES],
    /// Optional description of this model.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl TransitionModel {
    /// Create a transition model from a matrix.
    pub fn new(matrix: [[f64; NUM_STATES]; NUM_STATES]) -> Result<Self> {
        // Validate each row sums to 1.0
        for (i, row) in matrix.iter().enumerate() {
            let sum: f64 = row.iter().sum();
            if (sum - 1.0).abs() > 1e-6 {
                return Err(BeliefStateError::InvalidTransitionRow(i));
            }
        }

        Ok(Self {
            matrix,
            description: None,
        })
    }

    /// Create an identity transition model (no state changes).
    pub fn identity() -> Self {
        let mut matrix = [[0.0; NUM_STATES]; NUM_STATES];
        #[allow(clippy::needless_range_loop)]
        for i in 0..NUM_STATES {
            matrix[i][i] = 1.0;
        }
        Self {
            matrix,
            description: Some("Identity (no transitions)".to_string()),
        }
    }

    /// Create a default lifecycle transition model.
    pub fn default_lifecycle() -> Self {
        Self {
            matrix: [
                [0.90, 0.05, 0.05, 0.00],
                [0.10, 0.80, 0.10, 0.00],
                [0.00, 0.00, 0.90, 0.10],
                [0.00, 0.00, 0.00, 1.00],
            ],
            description: Some("Default process lifecycle model".to_string()),
        }
    }

    /// Get the transition probability P(to | from).
    pub fn prob(&self, from: ProcessState, to: ProcessState) -> f64 {
        self.matrix[from.to_index()][to.to_index()]
    }

    /// Apply transition to a belief state (prediction step).
    pub fn predict(&self, belief: &BeliefState) -> Result<BeliefState> {
        let mut new_probs = [0.0; NUM_STATES];

        for (next_idx, new_prob) in new_probs.iter_mut().enumerate() {
            for (curr_idx, &curr_prob) in belief.probs.iter().enumerate() {
                *new_prob += self.matrix[curr_idx][next_idx] * curr_prob;
            }
        }

        BeliefState::from_probs(new_probs)
    }
}

impl Default for TransitionModel {
    fn default() -> Self {
        Self::default_lifecycle()
    }
}

/// Observation likelihood: P(observation | state).
#[derive(Debug, Clone, Serialize)]
pub struct ObservationLikelihood {
    /// Log-likelihoods for each state.
    pub log_likelihoods: [f64; NUM_STATES],
    /// Optional description of this observation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl ObservationLikelihood {
    /// Create from log-likelihoods.
    pub fn from_log_likelihoods(log_likelihoods: [f64; NUM_STATES]) -> Result<Self> {
        for &ll in &log_likelihoods {
            if ll.is_nan() {
                return Err(BeliefStateError::InvalidLogProbability);
            }
        }

        Ok(Self {
            log_likelihoods,
            description: None,
        })
    }

    /// Create from likelihoods (will be converted to log).
    pub fn from_likelihoods(likelihoods: [f64; NUM_STATES]) -> Result<Self> {
        let log_likelihoods = likelihoods.map(|l| if l > 0.0 { l.ln() } else { f64::NEG_INFINITY });

        Ok(Self {
            log_likelihoods,
            description: None,
        })
    }

    /// Create a uniform (uninformative) observation.
    pub fn uniform() -> Self {
        Self {
            log_likelihoods: [0.0; NUM_STATES],
            description: Some("Uniform (uninformative)".to_string()),
        }
    }

    /// Get the log-likelihood for a state.
    pub fn log_likelihood(&self, state: ProcessState) -> f64 {
        self.log_likelihoods[state.to_index()]
    }

    /// Add a description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }
}

/// Configuration for belief updates.
#[derive(Debug, Clone, Serialize)]
pub struct BeliefUpdateConfig {
    /// Minimum probability to prevent underflow.
    pub min_prob: f64,
    /// Whether to apply smoothing.
    pub smoothing: bool,
    /// Smoothing parameter (Dirichlet alpha).
    pub smoothing_alpha: f64,
}

impl Default for BeliefUpdateConfig {
    fn default() -> Self {
        Self {
            min_prob: 1e-10,
            smoothing: false,
            smoothing_alpha: 0.001,
        }
    }
}

/// Result of a belief update.
#[derive(Debug, Clone, Serialize)]
pub struct BeliefUpdateResult {
    /// Updated belief state.
    pub belief: BeliefState,
    /// Log-likelihood of the observation under the prior.
    pub log_evidence: f64,
    /// Change in entropy from prior to posterior.
    pub entropy_change: f64,
    /// Most likely state after update.
    pub map_state: ProcessState,
    /// Confidence in the MAP state.
    pub map_confidence: f64,
}

/// Update belief state given a transition model and observation.
pub fn update_belief(
    belief: &BeliefState,
    transition: &TransitionModel,
    observation: &ObservationLikelihood,
    config: &BeliefUpdateConfig,
) -> Result<BeliefUpdateResult> {
    let prior_entropy = belief.entropy();

    // Step 1: Prediction - apply transition model
    let predicted = transition.predict(belief)?;

    // Step 2: Update - multiply by observation likelihood (in log space)
    let mut log_updated = [0.0; NUM_STATES];
    #[allow(clippy::needless_range_loop)]
    for i in 0..NUM_STATES {
        log_updated[i] = predicted.log_probs[i] + observation.log_likelihoods[i];
    }

    // Compute log-evidence for diagnostics
    let max_log = log_updated
        .iter()
        .cloned()
        .fold(f64::NEG_INFINITY, f64::max);
    let log_evidence = if max_log == f64::NEG_INFINITY {
        f64::NEG_INFINITY
    } else {
        let sum_exp: f64 = log_updated.iter().map(|&lp| (lp - max_log).exp()).sum();
        max_log + sum_exp.ln()
    };

    // Step 3: Normalize
    let mut posterior = BeliefState::from_log_probs(log_updated)?;

    // Apply smoothing if configured
    if config.smoothing {
        let alpha = config.smoothing_alpha;
        let mut smoothed = [0.0; NUM_STATES];
        let total = NUM_STATES as f64 * alpha + 1.0;
        for i in 0..NUM_STATES {
            smoothed[i] = (posterior.probs[i] + alpha) / total;
        }
        let sum: f64 = smoothed.iter().sum();
        for p in &mut smoothed {
            *p /= sum;
        }
        posterior = BeliefState::from_probs(smoothed)?;
    }

    // Apply minimum probability floor
    let mut floored = posterior.probs;
    let mut needs_renorm = false;
    for p in &mut floored {
        if *p < config.min_prob && *p > 0.0 {
            *p = config.min_prob;
            needs_renorm = true;
        }
    }
    if needs_renorm {
        let sum: f64 = floored.iter().sum();
        for p in &mut floored {
            *p /= sum;
        }
        posterior = BeliefState::from_probs(floored)?;
    }

    let posterior_entropy = posterior.entropy();
    let map_state = posterior.argmax();
    let map_confidence = posterior.max_prob();

    Ok(BeliefUpdateResult {
        belief: posterior,
        log_evidence,
        entropy_change: posterior_entropy - prior_entropy,
        map_state,
        map_confidence,
    })
}

/// Update belief through a sequence of observations.
pub fn update_belief_batch(
    initial: &BeliefState,
    transition: &TransitionModel,
    observations: &[ObservationLikelihood],
    config: &BeliefUpdateConfig,
) -> Result<Vec<BeliefUpdateResult>> {
    if observations.is_empty() {
        return Err(BeliefStateError::EmptyObservations);
    }

    let mut results = Vec::with_capacity(observations.len());
    let mut current = initial.clone();

    for obs in observations {
        let result = update_belief(&current, transition, obs, config)?;
        current = result.belief.clone();
        results.push(result);
    }

    Ok(results)
}

/// Compute KL divergence between two belief states.
pub fn belief_kl_divergence(p: &BeliefState, q: &BeliefState) -> f64 {
    p.probs
        .iter()
        .zip(q.probs.iter())
        .map(|(&pi, &qi)| {
            if pi > 0.0 && qi > 0.0 {
                pi * (pi / qi).ln()
            } else if pi > 0.0 {
                f64::INFINITY
            } else {
                0.0
            }
        })
        .sum()
}

/// Compute Jensen-Shannon divergence between two belief states.
pub fn belief_js_divergence(p: &BeliefState, q: &BeliefState) -> f64 {
    let m_probs: [f64; NUM_STATES] = std::array::from_fn(|i| 0.5 * (p.probs[i] + q.probs[i]));
    let m = BeliefState::from_probs(m_probs).unwrap_or_else(|_| BeliefState::uniform());
    0.5 * belief_kl_divergence(p, &m) + 0.5 * belief_kl_divergence(q, &m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_state_indices() {
        assert_eq!(ProcessState::Useful.to_index(), 0);
        assert_eq!(ProcessState::UsefulBad.to_index(), 1);
        assert_eq!(ProcessState::Abandoned.to_index(), 2);
        assert_eq!(ProcessState::Zombie.to_index(), 3);

        for (i, state) in ProcessState::ALL.iter().enumerate() {
            assert_eq!(ProcessState::from_index(i), Some(*state));
        }
        assert_eq!(ProcessState::from_index(4), None);
    }

    #[test]
    fn test_process_state_actionable() {
        assert!(!ProcessState::Useful.is_actionable());
        assert!(ProcessState::UsefulBad.is_actionable());
        assert!(ProcessState::Abandoned.is_actionable());
        assert!(ProcessState::Zombie.is_actionable());
    }

    #[test]
    fn test_belief_state_from_probs() {
        let belief = BeliefState::from_probs([0.4, 0.3, 0.2, 0.1]).unwrap();
        assert!((belief.probs.iter().sum::<f64>() - 1.0).abs() < 1e-10);
        assert_eq!(belief.argmax(), ProcessState::Useful);
    }

    #[test]
    fn test_belief_state_invalid_probs() {
        let result = BeliefState::from_probs([0.5, 0.5, 0.5, 0.5]);
        assert!(matches!(
            result,
            Err(BeliefStateError::InvalidDistribution(_))
        ));

        let result = BeliefState::from_probs([1.5, -0.5, 0.0, 0.0]);
        assert!(matches!(
            result,
            Err(BeliefStateError::ProbabilityOutOfRange(_))
        ));
    }

    #[test]
    fn test_belief_state_uniform() {
        let belief = BeliefState::uniform();
        let expected = 1.0 / NUM_STATES as f64;
        for &p in &belief.probs {
            assert!((p - expected).abs() < 1e-10);
        }
    }

    #[test]
    fn test_belief_state_certain() {
        let belief = BeliefState::certain(ProcessState::Abandoned);
        assert_eq!(belief.prob(ProcessState::Abandoned), 1.0);
        assert_eq!(belief.prob(ProcessState::Useful), 0.0);
        assert_eq!(belief.argmax(), ProcessState::Abandoned);
    }

    #[test]
    fn test_belief_state_entropy() {
        let uniform = BeliefState::uniform();
        let max_entropy = (NUM_STATES as f64).ln();
        assert!((uniform.entropy() - max_entropy).abs() < 1e-10);

        let certain = BeliefState::certain(ProcessState::Useful);
        assert!(certain.entropy().abs() < 1e-10);
    }

    #[test]
    fn test_belief_state_from_log_probs() {
        let log_probs = [-0.916, -1.204, -1.609, -2.303];
        let belief = BeliefState::from_log_probs(log_probs).unwrap();
        assert!((belief.probs.iter().sum::<f64>() - 1.0).abs() < 1e-6);
    }

    #[test]
    fn test_belief_actionable_mass() {
        let belief = BeliefState::from_probs([0.6, 0.1, 0.2, 0.1]).unwrap();
        assert!((belief.actionable_mass() - 0.4).abs() < 1e-10);
    }

    #[test]
    fn test_transition_model_identity() {
        let tm = TransitionModel::identity();
        let belief = BeliefState::from_probs([0.7, 0.1, 0.1, 0.1]).unwrap();
        let predicted = tm.predict(&belief).unwrap();

        for i in 0..NUM_STATES {
            assert!((predicted.probs[i] - belief.probs[i]).abs() < 1e-10);
        }
    }

    #[test]
    fn test_transition_model_default_lifecycle() {
        let tm = TransitionModel::default_lifecycle();
        assert!(tm.prob(ProcessState::Useful, ProcessState::Useful) >= 0.8);
        assert_eq!(tm.prob(ProcessState::Zombie, ProcessState::Zombie), 1.0);
        assert_eq!(tm.prob(ProcessState::Zombie, ProcessState::Useful), 0.0);
    }

    #[test]
    fn test_transition_model_predict() {
        let tm = TransitionModel::default_lifecycle();
        let belief = BeliefState::certain(ProcessState::Useful);
        let predicted = tm.predict(&belief).unwrap();

        assert!(predicted.prob(ProcessState::Useful) > 0.5);
        assert!(predicted.prob(ProcessState::UsefulBad) > 0.0);
    }

    #[test]
    fn test_observation_likelihood_uniform() {
        let obs = ObservationLikelihood::uniform();
        for ll in &obs.log_likelihoods {
            assert_eq!(*ll, 0.0);
        }
    }

    #[test]
    fn test_observation_likelihood_from_likelihoods() {
        let obs = ObservationLikelihood::from_likelihoods([0.1, 0.2, 0.3, 0.4]).unwrap();
        assert!((obs.log_likelihoods[0] - 0.1_f64.ln()).abs() < 1e-10);
    }

    #[test]
    fn test_update_belief_basic() {
        let prior = BeliefState::uniform();
        let transition = TransitionModel::identity();
        let observation = ObservationLikelihood::from_likelihoods([0.8, 0.1, 0.05, 0.05]).unwrap();
        let config = BeliefUpdateConfig::default();

        let result = update_belief(&prior, &transition, &observation, &config).unwrap();
        assert_eq!(result.map_state, ProcessState::Useful);
        assert!(result.map_confidence > 0.5);
    }

    #[test]
    fn test_update_belief_with_transition() {
        let prior = BeliefState::certain(ProcessState::Useful);
        let transition = TransitionModel::default_lifecycle();
        let observation = ObservationLikelihood::uniform();
        let config = BeliefUpdateConfig::default();

        let result = update_belief(&prior, &transition, &observation, &config).unwrap();
        assert!(result.belief.prob(ProcessState::Useful) < 1.0);
        assert!(result.belief.prob(ProcessState::UsefulBad) > 0.0);
    }

    #[test]
    fn test_update_belief_entropy_decreases_with_information() {
        let prior = BeliefState::uniform();
        let transition = TransitionModel::identity();
        let observation =
            ObservationLikelihood::from_likelihoods([0.01, 0.01, 0.97, 0.01]).unwrap();
        let config = BeliefUpdateConfig::default();

        let result = update_belief(&prior, &transition, &observation, &config).unwrap();
        assert!(result.entropy_change < 0.0);
    }

    #[test]
    fn test_update_belief_batch() {
        let initial = BeliefState::uniform();
        let transition = TransitionModel::default_lifecycle();
        let config = BeliefUpdateConfig::default();

        let observations = vec![
            ObservationLikelihood::from_likelihoods([0.6, 0.3, 0.05, 0.05]).unwrap(),
            ObservationLikelihood::from_likelihoods([0.3, 0.5, 0.15, 0.05]).unwrap(),
            ObservationLikelihood::from_likelihoods([0.1, 0.3, 0.5, 0.1]).unwrap(),
        ];

        let results = update_belief_batch(&initial, &transition, &observations, &config).unwrap();
        assert_eq!(results.len(), 3);
        assert!(
            results[2].belief.prob(ProcessState::Abandoned)
                > results[0].belief.prob(ProcessState::Abandoned)
        );
    }

    #[test]
    fn test_update_belief_batch_empty() {
        let initial = BeliefState::uniform();
        let transition = TransitionModel::identity();
        let config = BeliefUpdateConfig::default();

        let result = update_belief_batch(&initial, &transition, &[], &config);
        assert!(matches!(result, Err(BeliefStateError::EmptyObservations)));
    }

    #[test]
    fn test_belief_kl_divergence() {
        let p = BeliefState::from_probs([0.9, 0.05, 0.025, 0.025]).unwrap();
        let q = BeliefState::uniform();

        let kl = belief_kl_divergence(&p, &q);
        assert!(kl > 0.0);

        let kl_same = belief_kl_divergence(&p, &p);
        assert!(kl_same.abs() < 1e-10);
    }

    #[test]
    fn test_belief_js_divergence() {
        let p = BeliefState::from_probs([0.9, 0.05, 0.025, 0.025]).unwrap();
        let q = BeliefState::uniform();

        let js = belief_js_divergence(&p, &q);
        assert!(js >= 0.0);
        assert!(js <= 2.0_f64.ln() + 1e-6);

        let js_reverse = belief_js_divergence(&q, &p);
        assert!((js - js_reverse).abs() < 1e-10);

        let js_same = belief_js_divergence(&p, &p);
        assert!(js_same.abs() < 1e-10);
    }

    #[test]
    fn test_belief_update_smoothing() {
        let prior = BeliefState::certain(ProcessState::Useful);
        let transition = TransitionModel::identity();
        let observation =
            ObservationLikelihood::from_likelihoods([0.001, 0.001, 0.997, 0.001]).unwrap();

        let mut config = BeliefUpdateConfig::default();
        config.smoothing = true;
        config.smoothing_alpha = 0.1;

        let result = update_belief(&prior, &transition, &observation, &config).unwrap();
        for &p in &result.belief.probs {
            assert!(p > 0.0);
        }
    }

    #[test]
    fn test_belief_update_min_prob_floor() {
        let prior = BeliefState::uniform();
        let transition = TransitionModel::identity();
        let observation =
            ObservationLikelihood::from_likelihoods([0.001, 0.001, 0.997, 0.001]).unwrap();

        let mut config = BeliefUpdateConfig::default();
        config.min_prob = 1e-6;

        let result = update_belief(&prior, &transition, &observation, &config).unwrap();
        for &p in &result.belief.probs {
            assert!(
                p >= config.min_prob,
                "prob {} < min_prob {}",
                p,
                config.min_prob
            );
        }
    }

    #[test]
    fn test_transition_model_invalid_row() {
        let matrix = [
            [0.5, 0.5, 0.0, 0.0],
            [0.3, 0.3, 0.3, 0.3],
            [0.25, 0.25, 0.25, 0.25],
            [0.0, 0.0, 0.0, 1.0],
        ];

        let result = TransitionModel::new(matrix);
        assert!(matches!(
            result,
            Err(BeliefStateError::InvalidTransitionRow(1))
        ));
    }

    #[test]
    fn test_process_state_display() {
        assert_eq!(format!("{}", ProcessState::Useful), "Useful");
        assert_eq!(format!("{}", ProcessState::UsefulBad), "UsefulBad");
        assert_eq!(format!("{}", ProcessState::Abandoned), "Abandoned");
        assert_eq!(format!("{}", ProcessState::Zombie), "Zombie");
    }

    #[test]
    fn test_concentrated_belief() {
        let concentrated = BeliefState::from_probs([0.95, 0.02, 0.02, 0.01]).unwrap();
        let spread = BeliefState::uniform();

        assert!(concentrated.is_concentrated(0.9));
        assert!(!spread.is_concentrated(0.9));
    }
}
