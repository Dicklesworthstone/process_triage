//! Hidden Semi-Markov Model (HSMM) feature extractor.
//!
//! This module implements Plan §2(F)/§4.5's hidden semi-Markov chain framing
//! for process state estimation. Unlike a standard HMM where dwell times are
//! geometrically distributed, HSMM explicitly models state durations using
//! Gamma distributions.
//!
//! # Model
//!
//! - Hidden states: `S_t ∈ {Useful, UsefulBad, Abandoned, Zombie}`
//! - State durations: `D_S ~ Gamma(α_{D,S}, β_{D,S})`
//! - Transitions: When leaving state i, transition to state j with probability `π_{ij}`
//!
//! This module produces duration/regime summary features that the closed-form
//! decision core can consume. It does *not* replace the conjugate Naive Bayes core.
//!
//! # Example
//!
//! ```ignore
//! use pt_core::inference::hsmm::{HsmmConfig, HsmmAnalyzer, HsmmState};
//!
//! let config = HsmmConfig::default();
//! let mut analyzer = HsmmAnalyzer::new(config);
//!
//! // Process a sequence of observations (e.g., log CPU, log IO, etc.)
//! let observations = vec![
//!     vec![0.1, 0.2],  // time t=0
//!     vec![0.15, 0.25], // time t=1
//!     vec![0.8, 0.1],   // time t=2
//! ];
//! let result = analyzer.analyze(&observations)?;
//!
//! println!("Most likely state sequence: {:?}", result.state_sequence);
//! println!("Current state: {:?}", result.current_state);
//! ```

use crate::inference::ledger::{Classification, Confidence, Direction};
use serde::{Deserialize, Serialize};
use std::fmt;

/// The four hidden states representing process classification categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HsmmState {
    /// Process is useful and functioning normally.
    Useful,
    /// Process is useful but consuming excessive resources.
    UsefulBad,
    /// Process appears to be abandoned by the user.
    Abandoned,
    /// Process is stuck/unresponsive (zombie-like behavior).
    Zombie,
}

impl HsmmState {
    /// Number of states in the model.
    pub const NUM_STATES: usize = 4;

    /// All states in order.
    pub const ALL: [HsmmState; 4] = [
        HsmmState::Useful,
        HsmmState::UsefulBad,
        HsmmState::Abandoned,
        HsmmState::Zombie,
    ];

    /// Get the index of this state (for matrix operations).
    pub fn index(&self) -> usize {
        match self {
            HsmmState::Useful => 0,
            HsmmState::UsefulBad => 1,
            HsmmState::Abandoned => 2,
            HsmmState::Zombie => 3,
        }
    }

    /// Create a state from an index.
    pub fn from_index(idx: usize) -> Option<Self> {
        match idx {
            0 => Some(HsmmState::Useful),
            1 => Some(HsmmState::UsefulBad),
            2 => Some(HsmmState::Abandoned),
            3 => Some(HsmmState::Zombie),
            _ => None,
        }
    }

    /// Get human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            HsmmState::Useful => "useful",
            HsmmState::UsefulBad => "useful_bad",
            HsmmState::Abandoned => "abandoned",
            HsmmState::Zombie => "zombie",
        }
    }

    /// Map to the decision core Classification type.
    pub fn to_classification(&self) -> Classification {
        match self {
            HsmmState::Useful => Classification::Useful,
            HsmmState::UsefulBad => Classification::UsefulBad,
            HsmmState::Abandoned => Classification::Abandoned,
            HsmmState::Zombie => Classification::Zombie,
        }
    }
}

impl fmt::Display for HsmmState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Gamma duration parameters for a state.
///
/// Represents the prior/posterior distribution of time spent in a state
/// before transitioning out: `D ~ Gamma(shape, rate)`.
///
/// - Mean duration: shape / rate
/// - Variance: shape / rate²
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct GammaDuration {
    /// Shape parameter (α > 0).
    pub shape: f64,
    /// Rate parameter (β > 0).
    pub rate: f64,
}

impl GammaDuration {
    /// Create new Gamma duration parameters.
    pub fn new(shape: f64, rate: f64) -> Self {
        Self { shape, rate }
    }

    /// Mean of the duration distribution: E[D] = α/β.
    pub fn mean(&self) -> f64 {
        self.shape / self.rate
    }

    /// Variance of the duration: Var[D] = α/β².
    pub fn variance(&self) -> f64 {
        self.shape / (self.rate * self.rate)
    }

    /// Standard deviation.
    pub fn std_dev(&self) -> f64 {
        self.variance().sqrt()
    }

    /// Mode of the distribution (for shape >= 1).
    pub fn mode(&self) -> Option<f64> {
        if self.shape >= 1.0 {
            Some((self.shape - 1.0) / self.rate)
        } else {
            None
        }
    }

    /// Coefficient of variation (CV = std/mean).
    pub fn cv(&self) -> f64 {
        1.0 / self.shape.sqrt()
    }

    /// Compute the hazard rate at duration d.
    ///
    /// For Gamma(α, β), the hazard function is:
    /// h(d) = f(d) / S(d) where f is the PDF and S is survival.
    ///
    /// For large d, h(d) → β (constant hazard).
    /// For small d with α > 1, hazard increases; with α < 1, hazard decreases.
    pub fn hazard_rate(&self, duration: f64) -> f64 {
        if duration <= 0.0 {
            return if self.shape <= 1.0 {
                f64::INFINITY
            } else {
                0.0
            };
        }

        // Use the approximation: for Gamma, h(d) ≈ β for large d
        // More precise calculation uses incomplete gamma functions
        // For simplicity, use the approximation h(d) ≈ β * (d*β)^(α-1) / Γ(α) * exp(-βd) / S(d)
        // For practical purposes, use the asymptotic rate
        let x = self.rate * duration;
        if x > 20.0 {
            // Asymptotic: h(d) → β
            self.rate
        } else {
            // For smaller durations, hazard depends on shape
            // h(d) = f(d)/S(d) where f is Gamma PDF
            // Use approximation based on incomplete gamma ratio
            let gamma_ratio = self.shape / (1.0 + x / self.shape);
            self.rate * gamma_ratio
        }
    }

    /// Update posterior given observed duration.
    ///
    /// Conjugate update for Gamma prior observing n durations with total sum D:
    /// Posterior: Gamma(α + n*shape_obs, β + D)
    ///
    /// For simplicity, we use a moment-matching approach.
    pub fn update_with_duration(&self, observed_duration: f64) -> Self {
        // Pseudo-observation update: treat as if we observed one sample
        // Simple update: weighted average of prior and observation
        let prior_weight = self.shape;
        let obs_weight = 1.0;
        let total_weight = prior_weight + obs_weight;

        let new_mean = (prior_weight * self.mean() + obs_weight * observed_duration) / total_weight;
        let new_shape = self.shape + 1.0;
        let new_rate = new_shape / new_mean;

        Self::new(new_shape, new_rate)
    }

    /// Evaluate the log-PDF at duration d.
    pub fn log_pdf(&self, d: f64) -> f64 {
        if d <= 0.0 {
            return f64::NEG_INFINITY;
        }

        // log f(d; α, β) = α*log(β) - log(Γ(α)) + (α-1)*log(d) - β*d
        let log_gamma_alpha = ln_gamma(self.shape);
        self.shape * self.rate.ln() - log_gamma_alpha + (self.shape - 1.0) * d.ln() - self.rate * d
    }

    /// Evaluate the survival function S(d) = P(D > d).
    ///
    /// Uses the regularized upper incomplete gamma function.
    pub fn survival(&self, d: f64) -> f64 {
        if d <= 0.0 {
            return 1.0;
        }

        // S(d) = 1 - F(d) = Q(α, βd) = Γ(α, βd) / Γ(α)
        // Use approximation for incomplete gamma
        upper_incomplete_gamma_ratio(self.shape, self.rate * d)
    }
}

impl Default for GammaDuration {
    fn default() -> Self {
        // Default: mean duration of 100 time units with moderate uncertainty
        Self::new(2.0, 0.02)
    }
}

/// Configuration for the HSMM feature extractor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmmConfig {
    /// Duration prior parameters for each state [shape, rate].
    pub duration_priors: [GammaDuration; 4],

    /// Transition probabilities when leaving state i.
    /// Entry [i][j] = P(next state = j | leaving state i).
    /// Diagonal entries should be 0 (no self-transitions in HSMM).
    pub transition_probs: [[f64; 4]; 4],

    /// Initial state probabilities.
    pub initial_probs: [f64; 4],

    /// Emission model: feature weights for each state.
    /// Used to compute P(observation | state).
    pub emission_means: [[f64; 4]; 4], // [state][feature]

    /// Emission model: feature variances.
    pub emission_vars: [[f64; 4]; 4],

    /// Number of features in observations.
    pub num_features: usize,

    /// Minimum probability to avoid numerical underflow.
    pub min_probability: f64,

    /// Whether to normalize state posteriors at each step.
    pub normalize_posteriors: bool,
}

impl Default for HsmmConfig {
    fn default() -> Self {
        Self {
            // Duration priors: different expected dwell times per state
            duration_priors: [
                GammaDuration::new(3.0, 0.01),  // Useful: mean 300, moderate variance
                GammaDuration::new(2.0, 0.02),  // UsefulBad: mean 100, higher variance
                GammaDuration::new(2.0, 0.005), // Abandoned: mean 400, stays longer
                GammaDuration::new(5.0, 0.05),  // Zombie: mean 100, low variance (stuck)
            ],

            // Transition probabilities (rows must sum to 1, diagonal = 0)
            transition_probs: [
                [0.0, 0.3, 0.5, 0.2], // From Useful
                [0.4, 0.0, 0.4, 0.2], // From UsefulBad
                [0.2, 0.1, 0.0, 0.7], // From Abandoned
                [0.3, 0.2, 0.5, 0.0], // From Zombie (rare escape to useful states)
            ],

            // Initial probabilities (most processes start useful)
            initial_probs: [0.7, 0.15, 0.1, 0.05],

            // Emission means for 4 features: [cpu_log, io_log, mem_frac, age_log]
            emission_means: [
                [0.3, 0.3, 0.2, 0.5],  // Useful: moderate activity
                [0.7, 0.5, 0.6, 0.5],  // UsefulBad: high resource use
                [0.1, 0.05, 0.3, 0.8], // Abandoned: low activity, old
                [0.0, 0.0, 0.2, 0.9],  // Zombie: no activity, very old
            ],

            // Emission variances
            emission_vars: [
                [0.1, 0.1, 0.1, 0.2],    // Useful: some variance
                [0.15, 0.15, 0.15, 0.2], // UsefulBad
                [0.05, 0.05, 0.1, 0.1],  // Abandoned: tighter
                [0.02, 0.02, 0.1, 0.05], // Zombie: very tight
            ],

            num_features: 4,
            min_probability: 1e-10,
            normalize_posteriors: true,
        }
    }
}

impl HsmmConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), HsmmError> {
        // Check duration priors
        for (i, prior) in self.duration_priors.iter().enumerate() {
            if prior.shape <= 0.0 || prior.rate <= 0.0 {
                return Err(HsmmError::InvalidConfig(format!(
                    "Duration prior {} has non-positive parameters",
                    i
                )));
            }
        }

        // Check transition matrix
        for (i, row) in self.transition_probs.iter().enumerate() {
            // Diagonal should be 0 (no self-transitions)
            if row[i].abs() > 1e-6 {
                return Err(HsmmError::InvalidConfig(format!(
                    "Transition matrix diagonal [{},{}] should be 0, got {}",
                    i, i, row[i]
                )));
            }

            // Row should sum to 1 (excluding diagonal)
            let sum: f64 = row.iter().sum();
            if (sum - 1.0).abs() > 1e-6 {
                return Err(HsmmError::InvalidConfig(format!(
                    "Transition row {} sums to {}, expected 1.0",
                    i, sum
                )));
            }
        }

        // Check initial probabilities
        let init_sum: f64 = self.initial_probs.iter().sum();
        if (init_sum - 1.0).abs() > 1e-6 {
            return Err(HsmmError::InvalidConfig(format!(
                "Initial probabilities sum to {}, expected 1.0",
                init_sum
            )));
        }

        Ok(())
    }

    /// Create a configuration tuned for short-lived processes.
    pub fn short_lived() -> Self {
        Self {
            duration_priors: [
                GammaDuration::new(2.0, 0.05), // Useful: mean 40
                GammaDuration::new(1.5, 0.1),  // UsefulBad: mean 15
                GammaDuration::new(2.0, 0.02), // Abandoned: mean 100
                GammaDuration::new(3.0, 0.1),  // Zombie: mean 30
            ],
            ..Default::default()
        }
    }

    /// Create a configuration tuned for long-running services.
    pub fn long_running() -> Self {
        Self {
            duration_priors: [
                GammaDuration::new(4.0, 0.001), // Useful: mean 4000
                GammaDuration::new(2.0, 0.005), // UsefulBad: mean 400
                GammaDuration::new(3.0, 0.002), // Abandoned: mean 1500
                GammaDuration::new(5.0, 0.01),  // Zombie: mean 500
            ],
            initial_probs: [0.85, 0.1, 0.03, 0.02], // Services more likely useful
            ..Default::default()
        }
    }
}

/// Errors from HSMM processing.
#[derive(Debug, Clone)]
pub enum HsmmError {
    /// Configuration is invalid.
    InvalidConfig(String),
    /// Observation dimension mismatch.
    DimensionMismatch { expected: usize, got: usize },
    /// No observations provided.
    NoObservations,
    /// Numerical instability detected.
    NumericalInstability(String),
}

impl fmt::Display for HsmmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HsmmError::InvalidConfig(msg) => write!(f, "Invalid HSMM config: {}", msg),
            HsmmError::DimensionMismatch { expected, got } => {
                write!(f, "Dimension mismatch: expected {}, got {}", expected, got)
            }
            HsmmError::NoObservations => write!(f, "No observations provided"),
            HsmmError::NumericalInstability(msg) => write!(f, "Numerical instability: {}", msg),
        }
    }
}

impl std::error::Error for HsmmError {}

/// A detected state transition (regime switch).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSwitch {
    /// Time index of the switch.
    pub time_index: usize,
    /// State before the switch.
    pub from_state: HsmmState,
    /// State after the switch.
    pub to_state: HsmmState,
    /// Confidence in this switch detection.
    pub confidence: f64,
    /// Duration in the previous state.
    pub previous_duration: usize,
}

/// Duration statistics for a state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DurationStats {
    /// The state these stats describe.
    pub state: HsmmState,
    /// Posterior duration parameters.
    pub posterior: GammaDuration,
    /// Total time observed in this state.
    pub total_duration: usize,
    /// Number of entries into this state.
    pub num_entries: usize,
    /// Current dwell time (if currently in this state).
    pub current_dwell: Option<usize>,
    /// Hazard rate at current dwell time.
    pub current_hazard: f64,
}

/// Result from HSMM analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmmResult {
    /// Most likely state at each time step (Viterbi path).
    pub state_sequence: Vec<HsmmState>,
    /// State posteriors at each time step [time][state].
    pub state_posteriors: Vec<[f64; 4]>,
    /// Current (final) most likely state.
    pub current_state: HsmmState,
    /// Probability of the current state.
    pub current_state_prob: f64,
    /// Duration statistics per state.
    pub duration_stats: [DurationStats; 4],
    /// Detected state switches.
    pub switches: Vec<StateSwitch>,
    /// Number of observations processed.
    pub num_observations: usize,
    /// Log-likelihood of the observation sequence.
    pub log_likelihood: f64,
    /// Entropy of final state distribution (uncertainty measure).
    pub state_entropy: f64,
    /// Stability score (how consistent the state assignments are).
    pub stability_score: f64,
}

impl HsmmResult {
    /// Get the dominant state (most time spent).
    pub fn dominant_state(&self) -> HsmmState {
        let mut max_time = 0;
        let mut dominant = HsmmState::Useful;
        for stats in &self.duration_stats {
            if stats.total_duration > max_time {
                max_time = stats.total_duration;
                dominant = stats.state;
            }
        }
        dominant
    }

    /// Get the fraction of time in each state.
    pub fn state_fractions(&self) -> [f64; 4] {
        let total: usize = self.duration_stats.iter().map(|s| s.total_duration).sum();
        if total == 0 {
            return [0.25; 4];
        }
        let total_f = total as f64;
        [
            self.duration_stats[0].total_duration as f64 / total_f,
            self.duration_stats[1].total_duration as f64 / total_f,
            self.duration_stats[2].total_duration as f64 / total_f,
            self.duration_stats[3].total_duration as f64 / total_f,
        ]
    }

    /// Check if the process appears stuck in a terminal state.
    pub fn is_stuck(&self) -> bool {
        match self.current_state {
            HsmmState::Abandoned | HsmmState::Zombie => {
                // Check if we've been in this state for a while with high probability
                let stats = &self.duration_stats[self.current_state.index()];
                if let Some(dwell) = stats.current_dwell {
                    let expected = stats.posterior.mean() as usize;
                    dwell > expected && self.current_state_prob > 0.8
                } else {
                    false
                }
            }
            _ => false,
        }
    }
}

/// HSMM feature extractor.
#[derive(Debug, Clone)]
pub struct HsmmAnalyzer {
    config: HsmmConfig,
    /// State posteriors [state].
    state_probs: [f64; 4],
    /// Duration in current most likely state.
    current_duration: usize,
    /// Current most likely state.
    current_state: HsmmState,
    /// Duration posteriors per state.
    duration_posteriors: [GammaDuration; 4],
    /// Accumulated log-likelihood.
    log_likelihood: f64,
    /// History of state posteriors.
    posterior_history: Vec<[f64; 4]>,
    /// Detected switches.
    switches: Vec<StateSwitch>,
    /// Time spent in each state.
    state_durations: [usize; 4],
    /// Number of entries into each state.
    state_entries: [usize; 4],
    /// Number of observations processed.
    num_observations: usize,
}

impl HsmmAnalyzer {
    /// Create a new HSMM analyzer.
    pub fn new(config: HsmmConfig) -> Result<Self, HsmmError> {
        config.validate()?;

        let state_probs = config.initial_probs;
        let duration_posteriors = config.duration_priors;

        // Find initial most likely state
        let current_state = Self::argmax_state(&state_probs);

        Ok(Self {
            config,
            state_probs,
            current_duration: 0,
            current_state,
            duration_posteriors,
            log_likelihood: 0.0,
            posterior_history: Vec::new(),
            switches: Vec::new(),
            state_durations: [0; 4],
            state_entries: [1, 0, 0, 0], // Start in most likely state
            num_observations: 0,
        })
    }

    /// Reset the analyzer to initial state.
    pub fn reset(&mut self) {
        self.state_probs = self.config.initial_probs;
        self.current_duration = 0;
        self.current_state = Self::argmax_state(&self.state_probs);
        self.duration_posteriors = self.config.duration_priors;
        self.log_likelihood = 0.0;
        self.posterior_history.clear();
        self.switches.clear();
        self.state_durations = [0; 4];
        self.state_entries = [1, 0, 0, 0];
        self.num_observations = 0;
    }

    /// Find the state with maximum probability.
    fn argmax_state(probs: &[f64; 4]) -> HsmmState {
        let mut max_idx = 0;
        let mut max_val = probs[0];
        for (i, &p) in probs.iter().enumerate().skip(1) {
            if p > max_val {
                max_val = p;
                max_idx = i;
            }
        }
        HsmmState::from_index(max_idx).unwrap_or(HsmmState::Useful)
    }

    /// Compute emission probability P(observation | state).
    fn emission_prob(&self, observation: &[f64], state: HsmmState) -> f64 {
        let s = state.index();
        let mut log_prob = 0.0;

        let num_features = observation.len().min(self.config.num_features);
        #[allow(clippy::needless_range_loop)]
        for f in 0..num_features {
            let mean = self.config.emission_means[s][f];
            let var = self.config.emission_vars[s][f];
            let diff = observation[f] - mean;

            // Gaussian log-likelihood
            log_prob += -0.5
                * (diff * diff / var
                    + var.ln()
                    + std::f64::consts::LN_2
                    + std::f64::consts::PI.ln());
        }

        log_prob.exp().max(self.config.min_probability)
    }

    /// Compute duration probability P(d | state).
    fn duration_prob(&self, duration: usize, state: HsmmState) -> f64 {
        let s = state.index();
        let d = duration as f64;
        self.duration_posteriors[s]
            .survival(d)
            .max(self.config.min_probability)
    }

    /// Process a single observation.
    pub fn update(&mut self, observation: &[f64]) -> Result<[f64; 4], HsmmError> {
        if observation.len() < self.config.num_features {
            return Err(HsmmError::DimensionMismatch {
                expected: self.config.num_features,
                got: observation.len(),
            });
        }

        let prev_state = self.current_state;
        self.num_observations += 1;
        self.current_duration += 1;

        // Compute emission likelihoods
        let mut emissions = [0.0; 4];
        #[allow(clippy::needless_range_loop)]
        for s in 0..4 {
            emissions[s] = self.emission_prob(observation, HsmmState::from_index(s).unwrap());
        }

        // Compute duration factors
        let mut duration_factors = [0.0; 4];
        #[allow(clippy::needless_range_loop)]
        for s in 0..4 {
            if s == self.current_state.index() {
                // Probability of staying (survival)
                duration_factors[s] = self.duration_prob(self.current_duration, self.current_state);
            } else {
                // Probability of transitioning from current state
                let trans_prob = self.config.transition_probs[self.current_state.index()][s];
                // Duration hazard for leaving current state
                let hazard = self.duration_posteriors[self.current_state.index()]
                    .hazard_rate(self.current_duration as f64);
                duration_factors[s] = trans_prob * hazard.min(1.0);
            }
        }

        // Combine: new_prob[s] ∝ emission[s] * (stay_prob * old[s] + Σ_i trans_prob[i→s] * old[i])
        let mut new_probs = [0.0; 4];
        for s in 0..4 {
            // Contribution from staying in state s
            let stay_contrib = if s == self.current_state.index() {
                self.state_probs[s] * duration_factors[s]
            } else {
                0.0
            };

            // Contribution from transitioning into state s
            let trans_contrib = if s != self.current_state.index() {
                self.state_probs[self.current_state.index()] * duration_factors[s]
            } else {
                0.0
            };

            new_probs[s] = emissions[s] * (stay_contrib + trans_contrib);
        }

        // Normalize
        let sum: f64 = new_probs.iter().sum();
        if sum > self.config.min_probability {
            for p in new_probs.iter_mut() {
                *p /= sum;
            }
            self.log_likelihood += sum.ln();
        } else {
            // Numerical underflow - reset to uniform
            new_probs = [0.25; 4];
        }

        // Enforce minimum probability
        for p in new_probs.iter_mut() {
            *p = p.max(self.config.min_probability);
        }

        // Re-normalize after min enforcement
        let sum: f64 = new_probs.iter().sum();
        for p in new_probs.iter_mut() {
            *p /= sum;
        }

        self.state_probs = new_probs;

        // Update current state
        let new_state = Self::argmax_state(&self.state_probs);

        // Detect state switch
        if new_state != prev_state && self.num_observations > 1 {
            // Record switch
            self.switches.push(StateSwitch {
                time_index: self.num_observations - 1,
                from_state: prev_state,
                to_state: new_state,
                confidence: self.state_probs[new_state.index()],
                previous_duration: self.current_duration,
            });

            // Update duration posterior for the state we're leaving
            let prev_idx = prev_state.index();
            self.duration_posteriors[prev_idx] = self.duration_posteriors[prev_idx]
                .update_with_duration(self.current_duration as f64);

            // Reset duration counter
            self.current_duration = 0;
            self.state_entries[new_state.index()] += 1;
        }

        // Track time in states
        self.state_durations[new_state.index()] += 1;
        self.current_state = new_state;

        // Store history
        self.posterior_history.push(new_probs);

        Ok(new_probs)
    }

    /// Process a batch of observations.
    pub fn update_batch(&mut self, observations: &[Vec<f64>]) -> Result<Vec<[f64; 4]>, HsmmError> {
        let mut results = Vec::with_capacity(observations.len());
        for obs in observations {
            results.push(self.update(obs)?);
        }
        Ok(results)
    }

    /// Get the current state probabilities.
    pub fn state_probs(&self) -> &[f64; 4] {
        &self.state_probs
    }

    /// Get summary result.
    pub fn summarize(&self) -> Result<HsmmResult, HsmmError> {
        if self.num_observations == 0 {
            return Err(HsmmError::NoObservations);
        }

        // Build Viterbi-like sequence from posteriors
        let state_sequence: Vec<HsmmState> = self
            .posterior_history
            .iter()
            .map(Self::argmax_state)
            .collect();

        // Compute state entropy
        let state_entropy: f64 = -self
            .state_probs
            .iter()
            .filter(|&&p| p > 1e-10)
            .map(|&p| p * p.ln())
            .sum::<f64>();

        // Compute stability score
        let stability_score = self.compute_stability();

        // Build duration stats
        let duration_stats = [
            DurationStats {
                state: HsmmState::Useful,
                posterior: self.duration_posteriors[0],
                total_duration: self.state_durations[0],
                num_entries: self.state_entries[0],
                current_dwell: if self.current_state == HsmmState::Useful {
                    Some(self.current_duration)
                } else {
                    None
                },
                current_hazard: if self.current_state == HsmmState::Useful {
                    self.duration_posteriors[0].hazard_rate(self.current_duration as f64)
                } else {
                    0.0
                },
            },
            DurationStats {
                state: HsmmState::UsefulBad,
                posterior: self.duration_posteriors[1],
                total_duration: self.state_durations[1],
                num_entries: self.state_entries[1],
                current_dwell: if self.current_state == HsmmState::UsefulBad {
                    Some(self.current_duration)
                } else {
                    None
                },
                current_hazard: if self.current_state == HsmmState::UsefulBad {
                    self.duration_posteriors[1].hazard_rate(self.current_duration as f64)
                } else {
                    0.0
                },
            },
            DurationStats {
                state: HsmmState::Abandoned,
                posterior: self.duration_posteriors[2],
                total_duration: self.state_durations[2],
                num_entries: self.state_entries[2],
                current_dwell: if self.current_state == HsmmState::Abandoned {
                    Some(self.current_duration)
                } else {
                    None
                },
                current_hazard: if self.current_state == HsmmState::Abandoned {
                    self.duration_posteriors[2].hazard_rate(self.current_duration as f64)
                } else {
                    0.0
                },
            },
            DurationStats {
                state: HsmmState::Zombie,
                posterior: self.duration_posteriors[3],
                total_duration: self.state_durations[3],
                num_entries: self.state_entries[3],
                current_dwell: if self.current_state == HsmmState::Zombie {
                    Some(self.current_duration)
                } else {
                    None
                },
                current_hazard: if self.current_state == HsmmState::Zombie {
                    self.duration_posteriors[3].hazard_rate(self.current_duration as f64)
                } else {
                    0.0
                },
            },
        ];

        Ok(HsmmResult {
            state_sequence,
            state_posteriors: self.posterior_history.clone(),
            current_state: self.current_state,
            current_state_prob: self.state_probs[self.current_state.index()],
            duration_stats,
            switches: self.switches.clone(),
            num_observations: self.num_observations,
            log_likelihood: self.log_likelihood,
            state_entropy,
            stability_score,
        })
    }

    /// Compute stability score (how consistent state assignments are).
    fn compute_stability(&self) -> f64 {
        if self.posterior_history.len() < 2 {
            return 1.0;
        }

        // Stability = 1 - (average probability mass change between steps)
        let mut total_change = 0.0;
        for i in 1..self.posterior_history.len() {
            let prev = &self.posterior_history[i - 1];
            let curr = &self.posterior_history[i];
            let change: f64 = prev
                .iter()
                .zip(curr.iter())
                .map(|(a, b)| (a - b).abs())
                .sum::<f64>()
                / 2.0; // Normalize to [0, 1]
            total_change += change;
        }

        let avg_change = total_change / (self.posterior_history.len() - 1) as f64;
        1.0 - avg_change.min(1.0)
    }
}

/// Evidence from HSMM for integration with the decision core.
#[derive(Debug, Clone, Serialize)]
pub struct HsmmEvidence {
    /// Whether the HSMM analysis is enabled/valid.
    pub enabled: bool,
    /// Most likely current state.
    pub current_state: HsmmState,
    /// Probability of current state.
    pub current_state_prob: f64,
    /// State probabilities [useful, useful_bad, abandoned, zombie].
    pub state_probs: [f64; 4],
    /// Fraction of time in each state.
    pub state_fractions: [f64; 4],
    /// Number of state switches detected.
    pub num_switches: usize,
    /// Current duration in state (hazard indicator).
    pub current_duration: usize,
    /// Hazard rate for leaving current state.
    pub current_hazard: f64,
    /// Whether process appears stuck in terminal state.
    pub is_stuck: bool,
    /// Stability score (0-1, higher = more stable).
    pub stability: f64,
    /// Log Bayes factor for abandonment.
    pub log_bf_abandoned: f64,
    /// Suggested classification.
    pub suggested_classification: Classification,
    /// Confidence in classification.
    pub confidence: Confidence,
    /// Direction of evidence.
    pub direction: Direction,
}

impl HsmmEvidence {
    /// Create evidence from HSMM result.
    pub fn from_result(result: &HsmmResult, config: &HsmmConfig) -> Self {
        let state_fractions = result.state_fractions();
        let current_hazard = result.duration_stats[result.current_state.index()].current_hazard;

        // Compute log Bayes factor for abandoned vs useful
        // log BF = log(P(abandoned) / P(useful))
        let p_abandoned = result.state_posteriors.last().map(|p| p[2]).unwrap_or(0.1);
        let p_useful = result.state_posteriors.last().map(|p| p[0]).unwrap_or(0.7);
        let log_bf_abandoned = if p_useful > 1e-10 {
            (p_abandoned / p_useful).ln()
        } else {
            10.0 // Very high if useful is near zero
        };

        // Determine confidence
        let confidence = if result.current_state_prob > 0.9 {
            Confidence::High
        } else if result.current_state_prob > 0.7 {
            Confidence::Medium
        } else {
            Confidence::Low
        };

        // Determine direction
        let direction = match result.current_state {
            HsmmState::Abandoned | HsmmState::Zombie => Direction::TowardPredicted,
            HsmmState::Useful => Direction::TowardReference,
            HsmmState::UsefulBad => Direction::Neutral,
        };

        Self {
            enabled: true,
            current_state: result.current_state,
            current_state_prob: result.current_state_prob,
            state_probs: *result
                .state_posteriors
                .last()
                .unwrap_or(&config.initial_probs),
            state_fractions,
            num_switches: result.switches.len(),
            current_duration: result.duration_stats[result.current_state.index()]
                .current_dwell
                .unwrap_or(0),
            current_hazard,
            is_stuck: result.is_stuck(),
            stability: result.stability_score,
            log_bf_abandoned,
            suggested_classification: result.current_state.to_classification(),
            confidence,
            direction,
        }
    }

    /// Create disabled/empty evidence.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            current_state: HsmmState::Useful,
            current_state_prob: 0.0,
            state_probs: [0.25; 4],
            state_fractions: [0.25; 4],
            num_switches: 0,
            current_duration: 0,
            current_hazard: 0.0,
            is_stuck: false,
            stability: 0.0,
            log_bf_abandoned: 0.0,
            suggested_classification: Classification::Useful,
            confidence: Confidence::Low,
            direction: Direction::Neutral,
        }
    }

    /// Get log Bayes factor for triage decision.
    pub fn log_bf_for_triage(&self) -> f64 {
        if !self.enabled {
            return 0.0;
        }

        // Combine state evidence with stability and stuck indicators
        let base_bf = self.log_bf_abandoned;

        // Boost if stuck in terminal state
        let stuck_factor = if self.is_stuck { 1.0 } else { 0.0 };

        // Instability adds uncertainty (reduces magnitude)
        let instability_discount = 1.0 - self.stability;

        base_bf * (1.0 - instability_discount * 0.3) + stuck_factor
    }
}

/// Batch analyzer for processing multiple sequences.
#[derive(Debug)]
pub struct BatchHsmmAnalyzer {
    config: HsmmConfig,
}

impl BatchHsmmAnalyzer {
    /// Create a new batch analyzer.
    pub fn new(config: HsmmConfig) -> Result<Self, HsmmError> {
        config.validate()?;
        Ok(Self { config })
    }

    /// Analyze a single sequence.
    pub fn analyze(&self, observations: &[Vec<f64>]) -> Result<HsmmResult, HsmmError> {
        let mut analyzer = HsmmAnalyzer::new(self.config.clone())?;
        analyzer.update_batch(observations)?;
        analyzer.summarize()
    }

    /// Analyze multiple sequences.
    pub fn analyze_batch(&self, sequences: &[Vec<Vec<f64>>]) -> Vec<Result<HsmmResult, HsmmError>> {
        sequences.iter().map(|seq| self.analyze(seq)).collect()
    }
}

// Helper functions for Gamma distribution calculations

/// Log-gamma function (Stirling's approximation for large values).
fn ln_gamma(x: f64) -> f64 {
    if x <= 0.0 {
        return f64::INFINITY;
    }

    if x < 0.5 {
        // Use reflection formula
        std::f64::consts::PI.ln() - (std::f64::consts::PI * x).sin().ln() - ln_gamma(1.0 - x)
    } else if x < 7.0 {
        // Use recursion to get to larger values
        let mut xx = x;
        let mut result = 0.0;
        while xx < 7.0 {
            result -= xx.ln();
            xx += 1.0;
        }
        result + ln_gamma(xx)
    } else {
        // Stirling's approximation
        let x2 = x * x;
        (x - 0.5) * x.ln() - x + 0.5 * (2.0 * std::f64::consts::PI).ln() + 1.0 / (12.0 * x)
            - 1.0 / (360.0 * x2 * x)
            + 1.0 / (1260.0 * x2 * x2 * x)
    }
}

/// Upper incomplete gamma function ratio Q(a, x) = Γ(a, x) / Γ(a).
/// This is the survival function for Gamma distribution.
fn upper_incomplete_gamma_ratio(a: f64, x: f64) -> f64 {
    if x <= 0.0 {
        return 1.0;
    }
    if a <= 0.0 {
        return 0.0;
    }

    // For small x, use series expansion
    // For large x, use continued fraction
    if x < a + 1.0 {
        // Use series: Q(a,x) = 1 - P(a,x) where P uses series
        1.0 - lower_incomplete_gamma_series(a, x)
    } else {
        // Use continued fraction for Q directly
        upper_incomplete_gamma_cf(a, x)
    }
}

/// Lower incomplete gamma ratio using series expansion.
fn lower_incomplete_gamma_series(a: f64, x: f64) -> f64 {
    let max_iter = 100;
    let eps = 1e-10;

    let mut sum = 1.0 / a;
    let mut term = 1.0 / a;

    for n in 1..max_iter {
        term *= x / (a + n as f64);
        sum += term;
        if term.abs() < eps * sum.abs() {
            break;
        }
    }

    sum * (-x + a * x.ln() - ln_gamma(a)).exp()
}

/// Upper incomplete gamma ratio using continued fraction.
fn upper_incomplete_gamma_cf(a: f64, x: f64) -> f64 {
    let max_iter = 100;
    let eps = 1e-10;

    let mut b = x + 1.0 - a;
    let mut c = 1.0 / eps;
    let mut d = 1.0 / b;
    let mut h = d;

    for i in 1..max_iter {
        let an = -(i as f64) * (i as f64 - a);
        b += 2.0;
        d = an * d + b;
        if d.abs() < eps {
            d = eps;
        }
        c = b + an / c;
        if c.abs() < eps {
            c = eps;
        }
        d = 1.0 / d;
        let del = d * c;
        h *= del;
        if (del - 1.0).abs() < eps {
            break;
        }
    }

    (a * x.ln() - x - ln_gamma(a)).exp() * h
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx_eq(a: f64, b: f64, tol: f64) -> bool {
        (a - b).abs() <= tol
    }

    #[test]
    fn test_hsmm_state_properties() {
        assert_eq!(HsmmState::NUM_STATES, 4);
        assert_eq!(HsmmState::Useful.index(), 0);
        assert_eq!(HsmmState::UsefulBad.index(), 1);
        assert_eq!(HsmmState::Abandoned.index(), 2);
        assert_eq!(HsmmState::Zombie.index(), 3);

        // Round-trip
        for s in HsmmState::ALL {
            assert_eq!(HsmmState::from_index(s.index()), Some(s));
        }
    }

    #[test]
    fn test_gamma_duration_basics() {
        let gd = GammaDuration::new(2.0, 0.02);
        assert!(approx_eq(gd.mean(), 100.0, 1e-6));
        assert!(approx_eq(gd.variance(), 5000.0, 1e-6));

        // CV = 1/sqrt(shape)
        assert!(approx_eq(gd.cv(), 1.0 / 2.0_f64.sqrt(), 1e-6));
    }

    #[test]
    fn test_gamma_duration_mode() {
        let gd = GammaDuration::new(3.0, 0.1);
        assert_eq!(gd.mode(), Some(20.0)); // (3-1)/0.1 = 20

        let gd2 = GammaDuration::new(0.5, 0.1);
        assert_eq!(gd2.mode(), None); // shape < 1
    }

    #[test]
    fn test_gamma_duration_survival() {
        let gd = GammaDuration::new(2.0, 0.02);

        // S(0) should be 1
        assert!(approx_eq(gd.survival(0.0), 1.0, 1e-6));

        // S(t) should decrease with t
        assert!(gd.survival(100.0) < 1.0);
        assert!(gd.survival(200.0) < gd.survival(100.0));
    }

    #[test]
    fn test_gamma_duration_update() {
        let prior = GammaDuration::new(2.0, 0.02);
        let posterior = prior.update_with_duration(150.0);

        // Shape should increase
        assert!(posterior.shape > prior.shape);
        // Mean should shift toward observed value
        // Prior mean = 100, observed = 150, so posterior mean should be between
        let post_mean = posterior.mean();
        assert!(post_mean > prior.mean());
        assert!(post_mean < 150.0);
    }

    #[test]
    fn test_config_validation() {
        let config = HsmmConfig::default();
        assert!(config.validate().is_ok());

        let config2 = HsmmConfig::short_lived();
        assert!(config2.validate().is_ok());

        let config3 = HsmmConfig::long_running();
        assert!(config3.validate().is_ok());
    }

    #[test]
    fn test_config_invalid_transition() {
        let mut config = HsmmConfig::default();
        config.transition_probs[0][0] = 0.5; // Non-zero diagonal
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_invalid_row_sum() {
        let mut config = HsmmConfig::default();
        config.transition_probs[0][1] = 0.1; // Row won't sum to 1
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_analyzer_creation() {
        let config = HsmmConfig::default();
        let analyzer = HsmmAnalyzer::new(config);
        assert!(analyzer.is_ok());
    }

    #[test]
    fn test_analyzer_single_update() {
        let config = HsmmConfig::default();
        let mut analyzer = HsmmAnalyzer::new(config).unwrap();

        let obs = vec![0.2, 0.3, 0.1, 0.4];
        let probs = analyzer.update(&obs).unwrap();

        // Probabilities should sum to 1
        let sum: f64 = probs.iter().sum();
        assert!(approx_eq(sum, 1.0, 1e-6));

        // All should be non-negative
        for &p in &probs {
            assert!(p >= 0.0);
        }
    }

    #[test]
    fn test_analyzer_batch_update() {
        let config = HsmmConfig::default();
        let mut analyzer = HsmmAnalyzer::new(config).unwrap();

        let observations = vec![
            vec![0.2, 0.3, 0.1, 0.4],
            vec![0.25, 0.35, 0.15, 0.45],
            vec![0.3, 0.4, 0.2, 0.5],
        ];

        let results = analyzer.update_batch(&observations).unwrap();
        assert_eq!(results.len(), 3);

        // Each result should be valid probabilities
        for probs in results {
            let sum: f64 = probs.iter().sum();
            assert!(approx_eq(sum, 1.0, 1e-6));
        }
    }

    #[test]
    fn test_analyzer_summarize() {
        let config = HsmmConfig::default();
        let mut analyzer = HsmmAnalyzer::new(config).unwrap();

        let observations = vec![
            vec![0.2, 0.3, 0.1, 0.4],
            vec![0.25, 0.35, 0.15, 0.45],
            vec![0.3, 0.4, 0.2, 0.5],
        ];

        analyzer.update_batch(&observations).unwrap();
        let result = analyzer.summarize().unwrap();

        assert_eq!(result.num_observations, 3);
        assert_eq!(result.state_sequence.len(), 3);
        assert!(result.stability_score >= 0.0 && result.stability_score <= 1.0);
    }

    #[test]
    fn test_state_detection_useful() {
        let mut config = HsmmConfig::default();
        // Make "useful" state very likely for these observations
        config.emission_means[0] = [0.3, 0.3, 0.2, 0.3]; // Useful
        config.emission_vars = [[0.01; 4]; 4]; // Tight variances

        let mut analyzer = HsmmAnalyzer::new(config).unwrap();

        // Observations matching "useful" profile
        for _ in 0..20 {
            analyzer.update(&[0.3, 0.3, 0.2, 0.3]).unwrap();
        }

        let result = analyzer.summarize().unwrap();
        assert_eq!(result.current_state, HsmmState::Useful);
        assert!(result.current_state_prob > 0.5);
    }

    #[test]
    fn test_state_detection_abandoned() {
        let mut config = HsmmConfig::default();
        // Make "abandoned" state very likely for low-activity, old processes
        config.emission_means[2] = [0.05, 0.02, 0.3, 0.9]; // Abandoned
        config.emission_vars = [[0.01; 4]; 4]; // Tight

        let mut analyzer = HsmmAnalyzer::new(config).unwrap();

        // Observations matching "abandoned" profile
        for _ in 0..30 {
            analyzer.update(&[0.05, 0.02, 0.3, 0.9]).unwrap();
        }

        let result = analyzer.summarize().unwrap();
        assert_eq!(result.current_state, HsmmState::Abandoned);
    }

    #[test]
    fn test_state_switch_detection() {
        let mut config = HsmmConfig::default();
        config.emission_vars = [[0.01; 4]; 4]; // Tight for clear separation

        let mut analyzer = HsmmAnalyzer::new(config).unwrap();

        // Start with "useful" observations
        for _ in 0..10 {
            analyzer.update(&[0.3, 0.3, 0.2, 0.5]).unwrap();
        }

        // Switch to "zombie" observations
        for _ in 0..10 {
            analyzer.update(&[0.0, 0.0, 0.2, 0.95]).unwrap();
        }

        let result = analyzer.summarize().unwrap();

        // Should detect at least one switch
        assert!(!result.switches.is_empty(), "Should detect state switches");
    }

    #[test]
    fn test_duration_stats() {
        let config = HsmmConfig::default();
        let mut analyzer = HsmmAnalyzer::new(config).unwrap();

        for _ in 0..10 {
            analyzer.update(&[0.3, 0.3, 0.2, 0.5]).unwrap();
        }

        let result = analyzer.summarize().unwrap();

        // Total duration across all states should equal num_observations
        let total: usize = result.duration_stats.iter().map(|s| s.total_duration).sum();
        assert_eq!(total, 10);
    }

    #[test]
    fn test_hsmm_evidence() {
        let config = HsmmConfig::default();
        let mut analyzer = HsmmAnalyzer::new(config.clone()).unwrap();

        for _ in 0..10 {
            analyzer.update(&[0.3, 0.3, 0.2, 0.5]).unwrap();
        }

        let result = analyzer.summarize().unwrap();
        let evidence = HsmmEvidence::from_result(&result, &config);

        assert!(evidence.enabled);
        assert!(evidence.log_bf_abandoned.is_finite());
        assert!(evidence.stability >= 0.0 && evidence.stability <= 1.0);
    }

    #[test]
    fn test_hsmm_evidence_disabled() {
        let evidence = HsmmEvidence::disabled();
        assert!(!evidence.enabled);
        assert!(approx_eq(evidence.log_bf_for_triage(), 0.0, 1e-10));
    }

    #[test]
    fn test_batch_analyzer() {
        let config = HsmmConfig::default();
        let batch = BatchHsmmAnalyzer::new(config).unwrap();

        let seq = vec![
            vec![0.3, 0.3, 0.2, 0.5],
            vec![0.35, 0.35, 0.25, 0.55],
            vec![0.4, 0.4, 0.3, 0.6],
        ];

        let result = batch.analyze(&seq).unwrap();
        assert_eq!(result.num_observations, 3);
    }

    #[test]
    fn test_state_fractions() {
        let config = HsmmConfig::default();
        let mut analyzer = HsmmAnalyzer::new(config).unwrap();

        for _ in 0..20 {
            analyzer.update(&[0.3, 0.3, 0.2, 0.5]).unwrap();
        }

        let result = analyzer.summarize().unwrap();
        let fractions = result.state_fractions();

        // Fractions should sum to 1
        let sum: f64 = fractions.iter().sum();
        assert!(approx_eq(sum, 1.0, 1e-6));
    }

    #[test]
    fn test_reset() {
        let config = HsmmConfig::default();
        let mut analyzer = HsmmAnalyzer::new(config.clone()).unwrap();

        for _ in 0..10 {
            analyzer.update(&[0.3, 0.3, 0.2, 0.5]).unwrap();
        }

        assert_eq!(analyzer.num_observations, 10);

        analyzer.reset();

        assert_eq!(analyzer.num_observations, 0);
        assert_eq!(analyzer.state_probs, config.initial_probs);
    }

    #[test]
    fn test_log_gamma() {
        // Known values: ln(Γ(1)) = 0, ln(Γ(2)) = 0
        assert!(approx_eq(ln_gamma(1.0), 0.0, 1e-6));
        assert!(approx_eq(ln_gamma(2.0), 0.0, 1e-6));

        // ln(Γ(3)) = ln(2!) = ln(2) ≈ 0.693
        assert!(approx_eq(ln_gamma(3.0), 2.0_f64.ln(), 1e-4));

        // ln(Γ(4)) = ln(3!) = ln(6) ≈ 1.79
        assert!(approx_eq(ln_gamma(4.0), 6.0_f64.ln(), 1e-4));
    }

    #[test]
    fn test_upper_incomplete_gamma() {
        // Q(1, 0) = 1 (survival at 0)
        assert!(approx_eq(upper_incomplete_gamma_ratio(1.0, 0.0), 1.0, 1e-6));

        // For exponential (shape=1, rate=1): Q(1, x) = exp(-x)
        let x: f64 = 1.0;
        let expected = (-x).exp();
        assert!(approx_eq(
            upper_incomplete_gamma_ratio(1.0, x),
            expected,
            0.01
        ));
    }

    #[test]
    fn test_deterministic_outputs() {
        let config = HsmmConfig::default();

        let observations = vec![
            vec![0.3, 0.3, 0.2, 0.5],
            vec![0.35, 0.35, 0.25, 0.55],
            vec![0.4, 0.4, 0.3, 0.6],
        ];

        // Run twice
        let mut analyzer1 = HsmmAnalyzer::new(config.clone()).unwrap();
        analyzer1.update_batch(&observations).unwrap();
        let result1 = analyzer1.summarize().unwrap();

        let mut analyzer2 = HsmmAnalyzer::new(config).unwrap();
        analyzer2.update_batch(&observations).unwrap();
        let result2 = analyzer2.summarize().unwrap();

        // Results should be identical
        assert_eq!(result1.current_state, result2.current_state);
        assert!(approx_eq(
            result1.current_state_prob,
            result2.current_state_prob,
            1e-10
        ));
        assert_eq!(result1.state_sequence, result2.state_sequence);
    }

    #[test]
    fn test_is_stuck_detection() {
        let mut config = HsmmConfig::default();
        // Configure zombie state to be easily detected: very specific profile
        config.emission_means[0] = [0.5, 0.5, 0.3, 0.3]; // Useful: active
        config.emission_means[1] = [0.8, 0.7, 0.6, 0.4]; // UsefulBad: high resources
        config.emission_means[2] = [0.1, 0.1, 0.3, 0.7]; // Abandoned: low activity, old
        config.emission_means[3] = [0.0, 0.0, 0.1, 0.99]; // Zombie: zero activity, very old
        config.emission_vars = [[0.005; 4]; 4]; // Very tight variances
        config.duration_priors[3] = GammaDuration::new(2.0, 0.5); // Mean duration 4
        config.initial_probs = [0.25, 0.25, 0.25, 0.25]; // Equal initial probs

        let mut analyzer = HsmmAnalyzer::new(config).unwrap();

        // Push into zombie state and stay there longer than expected
        for _ in 0..20 {
            analyzer.update(&[0.0, 0.0, 0.1, 0.99]).unwrap();
        }

        let result = analyzer.summarize().unwrap();

        // Should be in zombie state
        assert_eq!(result.current_state, HsmmState::Zombie);
        // And should be detected as stuck (duration > expected)
        assert!(result.is_stuck());
    }

    #[test]
    fn test_no_observations_error() {
        let config = HsmmConfig::default();
        let analyzer = HsmmAnalyzer::new(config).unwrap();

        let result = analyzer.summarize();
        assert!(matches!(result, Err(HsmmError::NoObservations)));
    }

    #[test]
    fn test_dimension_mismatch_error() {
        let config = HsmmConfig::default();
        let mut analyzer = HsmmAnalyzer::new(config).unwrap();

        // Too few features
        let result = analyzer.update(&[0.1, 0.2]);
        assert!(matches!(result, Err(HsmmError::DimensionMismatch { .. })));
    }

    // ── HsmmState serde ───────────────────────────────────────────────

    #[test]
    fn hsmm_state_serde_roundtrip() {
        for s in HsmmState::ALL {
            let json = serde_json::to_string(&s).unwrap();
            let back: HsmmState = serde_json::from_str(&json).unwrap();
            assert_eq!(back, s);
        }
    }

    #[test]
    fn hsmm_state_serde_snake_case() {
        let json = serde_json::to_string(&HsmmState::UsefulBad).unwrap();
        assert_eq!(json, "\"useful_bad\"");
    }

    #[test]
    fn hsmm_state_display() {
        assert_eq!(HsmmState::Useful.to_string(), "useful");
        assert_eq!(HsmmState::UsefulBad.to_string(), "useful_bad");
        assert_eq!(HsmmState::Abandoned.to_string(), "abandoned");
        assert_eq!(HsmmState::Zombie.to_string(), "zombie");
    }

    #[test]
    fn hsmm_state_from_index_out_of_bounds() {
        assert!(HsmmState::from_index(4).is_none());
        assert!(HsmmState::from_index(99).is_none());
    }

    #[test]
    fn hsmm_state_to_classification_roundtrip() {
        for s in HsmmState::ALL {
            let cls = s.to_classification();
            assert_eq!(cls.label(), s.name());
        }
    }

    // ── GammaDuration extras ──────────────────────────────────────────

    #[test]
    fn gamma_duration_default() {
        let gd = GammaDuration::default();
        assert!(gd.shape > 0.0);
        assert!(gd.rate > 0.0);
        assert!(gd.mean() > 0.0);
    }

    #[test]
    fn gamma_duration_serde_roundtrip() {
        let gd = GammaDuration::new(3.0, 0.05);
        let json = serde_json::to_string(&gd).unwrap();
        let back: GammaDuration = serde_json::from_str(&json).unwrap();
        assert!(approx_eq(back.shape, 3.0, 1e-9));
        assert!(approx_eq(back.rate, 0.05, 1e-9));
    }

    #[test]
    fn gamma_duration_std_dev() {
        let gd = GammaDuration::new(4.0, 0.1);
        let expected_var: f64 = 4.0 / (0.1 * 0.1); // = 400
        assert!(approx_eq(gd.std_dev(), expected_var.sqrt(), 1e-6));
    }

    #[test]
    fn gamma_duration_log_pdf_negative_or_zero_returns_neg_inf() {
        let gd = GammaDuration::new(2.0, 0.5);
        assert_eq!(gd.log_pdf(0.0), f64::NEG_INFINITY);
        assert_eq!(gd.log_pdf(-1.0), f64::NEG_INFINITY);
    }

    #[test]
    fn gamma_duration_log_pdf_positive() {
        let gd = GammaDuration::new(2.0, 1.0);
        let lpdf = gd.log_pdf(1.0);
        // For Gamma(2,1), f(1) = 1 * exp(-1) = e^-1, so log = -1
        assert!(approx_eq(lpdf, -1.0, 0.01));
    }

    #[test]
    fn gamma_duration_hazard_rate_zero() {
        // shape > 1: hazard at 0 should be 0
        let gd = GammaDuration::new(3.0, 0.1);
        assert_eq!(gd.hazard_rate(0.0), 0.0);

        // shape <= 1: hazard at 0 should be infinity
        let gd2 = GammaDuration::new(0.5, 0.1);
        assert_eq!(gd2.hazard_rate(0.0), f64::INFINITY);
    }

    #[test]
    fn gamma_duration_hazard_rate_asymptotic() {
        let gd = GammaDuration::new(2.0, 0.5);
        // For very large d, hazard → rate
        let h = gd.hazard_rate(1000.0);
        assert!(approx_eq(h, 0.5, 0.01));
    }

    #[test]
    fn gamma_duration_mode_at_boundary() {
        // shape exactly 1: mode = 0
        let gd = GammaDuration::new(1.0, 0.1);
        assert_eq!(gd.mode(), Some(0.0));
    }

    #[test]
    fn gamma_duration_survival_negative_returns_one() {
        let gd = GammaDuration::new(2.0, 0.5);
        assert!(approx_eq(gd.survival(-1.0), 1.0, 1e-9));
    }

    // ── HsmmConfig extras ─────────────────────────────────────────────

    #[test]
    fn hsmm_config_serde_roundtrip() {
        let config = HsmmConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: HsmmConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.num_features, 4);
        assert!(back.normalize_posteriors);
    }

    #[test]
    fn hsmm_config_short_lived_vs_default() {
        let short = HsmmConfig::short_lived();
        let default = HsmmConfig::default();
        // Short-lived useful has shorter mean duration
        assert!(short.duration_priors[0].mean() < default.duration_priors[0].mean());
    }

    #[test]
    fn hsmm_config_long_running_vs_default() {
        let long = HsmmConfig::long_running();
        let default = HsmmConfig::default();
        // Long-running useful has longer mean duration
        assert!(long.duration_priors[0].mean() > default.duration_priors[0].mean());
        // Long-running starts more likely as useful
        assert!(long.initial_probs[0] > default.initial_probs[0]);
    }

    #[test]
    fn hsmm_config_invalid_duration_prior() {
        let mut config = HsmmConfig::default();
        config.duration_priors[1] = GammaDuration::new(-1.0, 0.1);
        assert!(config.validate().is_err());
    }

    #[test]
    fn hsmm_config_invalid_initial_probs() {
        let mut config = HsmmConfig::default();
        config.initial_probs = [0.5, 0.5, 0.5, 0.5]; // Sum = 2.0
        assert!(config.validate().is_err());
    }

    // ── HsmmError display ─────────────────────────────────────────────

    #[test]
    fn hsmm_error_display_all_variants() {
        let e1 = HsmmError::InvalidConfig("bad".to_string());
        assert!(e1.to_string().contains("Invalid HSMM config"));

        let e2 = HsmmError::DimensionMismatch {
            expected: 4,
            got: 2,
        };
        assert!(e2.to_string().contains("expected 4"));
        assert!(e2.to_string().contains("got 2"));

        let e3 = HsmmError::NoObservations;
        assert!(e3.to_string().contains("No observations"));

        let e4 = HsmmError::NumericalInstability("overflow".to_string());
        assert!(e4.to_string().contains("Numerical instability"));
    }

    #[test]
    fn hsmm_error_is_std_error() {
        let err = HsmmError::NoObservations;
        let _: &dyn std::error::Error = &err;
    }

    // ── StateSwitch serde ─────────────────────────────────────────────

    #[test]
    fn state_switch_serde_roundtrip() {
        let sw = StateSwitch {
            time_index: 5,
            from_state: HsmmState::Useful,
            to_state: HsmmState::Abandoned,
            confidence: 0.85,
            previous_duration: 10,
        };
        let json = serde_json::to_string(&sw).unwrap();
        let back: StateSwitch = serde_json::from_str(&json).unwrap();
        assert_eq!(back.time_index, 5);
        assert_eq!(back.from_state, HsmmState::Useful);
        assert_eq!(back.to_state, HsmmState::Abandoned);
    }

    // ── DurationStats serde ───────────────────────────────────────────

    #[test]
    fn duration_stats_serde_roundtrip() {
        let ds = DurationStats {
            state: HsmmState::Zombie,
            posterior: GammaDuration::new(5.0, 0.05),
            total_duration: 42,
            num_entries: 3,
            current_dwell: Some(10),
            current_hazard: 0.05,
        };
        let json = serde_json::to_string(&ds).unwrap();
        let back: DurationStats = serde_json::from_str(&json).unwrap();
        assert_eq!(back.state, HsmmState::Zombie);
        assert_eq!(back.total_duration, 42);
    }

    // ── HsmmResult extras ─────────────────────────────────────────────

    #[test]
    fn hsmm_result_dominant_state_from_analysis() {
        let config = HsmmConfig::default();
        let mut analyzer = HsmmAnalyzer::new(config).unwrap();

        for _ in 0..20 {
            analyzer.update(&[0.3, 0.3, 0.2, 0.5]).unwrap();
        }

        let result = analyzer.summarize().unwrap();
        // Dominant state should be the one with most total_duration
        let dom = result.dominant_state();
        let max_dur = result
            .duration_stats
            .iter()
            .map(|s| s.total_duration)
            .max()
            .unwrap();
        assert_eq!(result.duration_stats[dom.index()].total_duration, max_dur);
    }

    #[test]
    fn hsmm_result_serde_roundtrip() {
        let config = HsmmConfig::default();
        let mut analyzer = HsmmAnalyzer::new(config).unwrap();

        for _ in 0..5 {
            analyzer.update(&[0.3, 0.3, 0.2, 0.5]).unwrap();
        }

        let result = analyzer.summarize().unwrap();
        let json = serde_json::to_string(&result).unwrap();
        let back: HsmmResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.num_observations, 5);
        assert_eq!(back.state_sequence.len(), 5);
    }

    // ── HsmmEvidence log_bf ───────────────────────────────────────────

    #[test]
    fn hsmm_evidence_log_bf_for_triage() {
        let config = HsmmConfig::default();
        let mut analyzer = HsmmAnalyzer::new(config.clone()).unwrap();

        for _ in 0..10 {
            analyzer.update(&[0.05, 0.02, 0.3, 0.9]).unwrap(); // abandoned-like
        }

        let result = analyzer.summarize().unwrap();
        let evidence = HsmmEvidence::from_result(&result, &config);
        // Should be finite
        assert!(evidence.log_bf_for_triage().is_finite());
    }

    // ── Batch analyzer error ──────────────────────────────────────────

    #[test]
    fn batch_analyzer_empty_observations() {
        let config = HsmmConfig::default();
        let batch = BatchHsmmAnalyzer::new(config).unwrap();
        let result = batch.analyze(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn batch_analyzer_dimension_mismatch() {
        let config = HsmmConfig::default();
        let batch = BatchHsmmAnalyzer::new(config).unwrap();
        let result = batch.analyze(&[vec![0.1, 0.2]]); // 2 features, needs 4
        assert!(result.is_err());
    }
}
