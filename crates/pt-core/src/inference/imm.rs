//! Interacting Multiple Model (IMM) filter for regime-switching state estimation.
//!
//! IMM maintains a bank of Kalman filters, each representing a different "regime"
//! or mode of operation (e.g., idle, active, stuck). The algorithm uses a Markov
//! transition matrix to model regime switching and produces:
//! - Mode (regime) probabilities at each time step
//! - Combined state estimates across all modes
//! - Regime change detection indicators
//!
//! # Algorithm Overview
//!
//! At each time step:
//! 1. **Mixing**: Compute mixed initial conditions for each filter based on
//!    mode probabilities and transition matrix
//! 2. **Filtering**: Run Kalman filter update for each mode
//! 3. **Mode Probability Update**: Update mode probabilities using likelihoods
//! 4. **Combination**: Combine state estimates weighted by mode probabilities
//!
//! # Example
//!
//! ```ignore
//! use pt_core::inference::imm::{ImmConfig, ImmAnalyzer, Regime};
//!
//! // Define 3-regime model: Idle, Active, Stuck
//! let config = ImmConfig::three_regime_default();
//! let mut analyzer = ImmAnalyzer::new(config)?;
//!
//! // Process observations
//! for obs in observations {
//!     let result = analyzer.update(obs)?;
//!     println!("Mode probs: {:?}", result.mode_probabilities);
//!     if result.regime_change_detected {
//!         println!("Regime change to {:?}", result.most_likely_regime);
//!     }
//! }
//! ```

use std::fmt;

use crate::inference::ledger::{Classification, Confidence, Direction};

/// Regime states for process behavior modeling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Regime {
    /// Low activity, stable state
    Idle,
    /// Normal/expected activity levels
    Active,
    /// Elevated activity, potentially problematic
    Elevated,
    /// Process appears stuck or unresponsive
    Stuck,
    /// Custom regime with numeric identifier
    Custom(u8),
}

impl Regime {
    /// Returns the index of this regime for matrix indexing.
    pub fn index(&self) -> usize {
        match self {
            Regime::Idle => 0,
            Regime::Active => 1,
            Regime::Elevated => 2,
            Regime::Stuck => 3,
            Regime::Custom(i) => *i as usize,
        }
    }

    /// Creates a regime from an index.
    pub fn from_index(idx: usize) -> Self {
        match idx {
            0 => Regime::Idle,
            1 => Regime::Active,
            2 => Regime::Elevated,
            3 => Regime::Stuck,
            i => Regime::Custom(i as u8),
        }
    }

    /// Returns a human-readable name for this regime.
    pub fn name(&self) -> &'static str {
        match self {
            Regime::Idle => "idle",
            Regime::Active => "active",
            Regime::Elevated => "elevated",
            Regime::Stuck => "stuck",
            Regime::Custom(_) => "custom",
        }
    }
}

impl fmt::Display for Regime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Errors that can occur during IMM processing.
#[derive(Debug, Clone)]
pub enum ImmError {
    /// Configuration is invalid
    InvalidConfig(String),
    /// Transition matrix rows don't sum to 1
    InvalidTransitionMatrix(String),
    /// Numerical instability detected
    NumericalInstability(String),
    /// Dimension mismatch in matrices
    DimensionMismatch { expected: usize, got: usize },
    /// No observations processed yet
    NoObservations,
}

impl fmt::Display for ImmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ImmError::InvalidConfig(msg) => write!(f, "Invalid IMM config: {}", msg),
            ImmError::InvalidTransitionMatrix(msg) => {
                write!(f, "Invalid transition matrix: {}", msg)
            }
            ImmError::NumericalInstability(msg) => write!(f, "Numerical instability: {}", msg),
            ImmError::DimensionMismatch { expected, got } => {
                write!(f, "Dimension mismatch: expected {}, got {}", expected, got)
            }
            ImmError::NoObservations => write!(f, "No observations processed yet"),
        }
    }
}

impl std::error::Error for ImmError {}

/// Configuration for the IMM filter.
#[derive(Debug, Clone)]
pub struct ImmConfig {
    /// Number of modes/regimes
    pub num_modes: usize,
    /// Mode transition probability matrix (row-stochastic)
    /// Entry [i][j] = P(mode_j at t | mode_i at t-1)
    pub transition_matrix: Vec<Vec<f64>>,
    /// Initial mode probabilities
    pub initial_mode_probs: Vec<f64>,
    /// Process noise variance for each mode
    pub process_noise: Vec<f64>,
    /// Measurement noise variance (shared across modes)
    pub measurement_noise: f64,
    /// State transition coefficient for each mode (typically close to 1.0)
    pub state_transition: Vec<f64>,
    /// Threshold for detecting regime changes (probability jump)
    pub regime_change_threshold: f64,
    /// Minimum probability to consider a mode "active"
    pub min_mode_probability: f64,
    /// Enable adaptive process noise estimation
    pub adaptive_noise: bool,
    /// Smoothing factor for mode probability updates (0-1, higher = more smoothing)
    pub probability_smoothing: f64,
}

impl Default for ImmConfig {
    fn default() -> Self {
        Self::two_regime_default()
    }
}

impl ImmConfig {
    /// Creates a default two-regime (idle/active) configuration.
    pub fn two_regime_default() -> Self {
        Self {
            num_modes: 2,
            // Transition matrix favoring staying in current state
            transition_matrix: vec![
                vec![0.95, 0.05], // Idle: 95% stay idle, 5% become active
                vec![0.10, 0.90], // Active: 10% become idle, 90% stay active
            ],
            initial_mode_probs: vec![0.7, 0.3],
            process_noise: vec![0.01, 0.1], // Low noise when idle, higher when active
            measurement_noise: 0.1,
            state_transition: vec![0.95, 0.98], // Slight decay when idle, persistence when active
            regime_change_threshold: 0.3,
            min_mode_probability: 0.01,
            adaptive_noise: false,
            probability_smoothing: 0.1,
        }
    }

    /// Creates a default three-regime (idle/active/stuck) configuration.
    pub fn three_regime_default() -> Self {
        Self {
            num_modes: 3,
            transition_matrix: vec![
                vec![0.90, 0.08, 0.02], // Idle
                vec![0.05, 0.90, 0.05], // Active
                vec![0.02, 0.08, 0.90], // Stuck
            ],
            initial_mode_probs: vec![0.5, 0.45, 0.05],
            process_noise: vec![0.01, 0.1, 0.001], // Very low noise when stuck
            measurement_noise: 0.1,
            state_transition: vec![0.95, 0.98, 0.999], // Near-constant when stuck
            regime_change_threshold: 0.25,
            min_mode_probability: 0.01,
            adaptive_noise: false,
            probability_smoothing: 0.1,
        }
    }

    /// Creates a four-regime (idle/active/elevated/stuck) configuration.
    pub fn four_regime_default() -> Self {
        Self {
            num_modes: 4,
            transition_matrix: vec![
                vec![0.85, 0.10, 0.04, 0.01], // Idle
                vec![0.08, 0.82, 0.08, 0.02], // Active
                vec![0.02, 0.10, 0.83, 0.05], // Elevated
                vec![0.01, 0.04, 0.05, 0.90], // Stuck
            ],
            initial_mode_probs: vec![0.4, 0.4, 0.15, 0.05],
            process_noise: vec![0.01, 0.1, 0.5, 0.001],
            measurement_noise: 0.1,
            state_transition: vec![0.95, 0.98, 0.99, 0.999],
            regime_change_threshold: 0.2,
            min_mode_probability: 0.01,
            adaptive_noise: false,
            probability_smoothing: 0.1,
        }
    }

    /// Validates the configuration.
    pub fn validate(&self) -> Result<(), ImmError> {
        if self.num_modes == 0 {
            return Err(ImmError::InvalidConfig("num_modes must be > 0".into()));
        }

        if self.transition_matrix.len() != self.num_modes {
            return Err(ImmError::DimensionMismatch {
                expected: self.num_modes,
                got: self.transition_matrix.len(),
            });
        }

        for (i, row) in self.transition_matrix.iter().enumerate() {
            if row.len() != self.num_modes {
                return Err(ImmError::DimensionMismatch {
                    expected: self.num_modes,
                    got: row.len(),
                });
            }
            let sum: f64 = row.iter().sum();
            if (sum - 1.0).abs() > 1e-6 {
                return Err(ImmError::InvalidTransitionMatrix(format!(
                    "Row {} sums to {}, expected 1.0",
                    i, sum
                )));
            }
        }

        if self.initial_mode_probs.len() != self.num_modes {
            return Err(ImmError::DimensionMismatch {
                expected: self.num_modes,
                got: self.initial_mode_probs.len(),
            });
        }

        let prob_sum: f64 = self.initial_mode_probs.iter().sum();
        if (prob_sum - 1.0).abs() > 1e-6 {
            return Err(ImmError::InvalidConfig(format!(
                "Initial mode probs sum to {}, expected 1.0",
                prob_sum
            )));
        }

        if self.process_noise.len() != self.num_modes {
            return Err(ImmError::DimensionMismatch {
                expected: self.num_modes,
                got: self.process_noise.len(),
            });
        }

        if self.state_transition.len() != self.num_modes {
            return Err(ImmError::DimensionMismatch {
                expected: self.num_modes,
                got: self.state_transition.len(),
            });
        }

        if self.measurement_noise <= 0.0 {
            return Err(ImmError::InvalidConfig(
                "measurement_noise must be > 0".into(),
            ));
        }

        Ok(())
    }
}

/// State of a single Kalman filter within the IMM bank.
#[derive(Debug, Clone)]
pub struct ModeFilterState {
    /// State estimate
    pub state: f64,
    /// State covariance (uncertainty)
    pub covariance: f64,
    /// Last innovation (measurement residual)
    pub innovation: f64,
    /// Innovation covariance
    pub innovation_cov: f64,
    /// Mode likelihood from last update
    pub likelihood: f64,
}

impl ModeFilterState {
    /// Creates a new filter state with given initial values.
    pub fn new(state: f64, covariance: f64) -> Self {
        Self {
            state,
            covariance,
            innovation: 0.0,
            innovation_cov: 1.0,
            likelihood: 1.0,
        }
    }
}

/// Overall state of the IMM filter.
#[derive(Debug, Clone)]
pub struct ImmState {
    /// Per-mode filter states
    pub mode_states: Vec<ModeFilterState>,
    /// Current mode probabilities
    pub mode_probabilities: Vec<f64>,
    /// Combined state estimate
    pub combined_state: f64,
    /// Combined state covariance
    pub combined_covariance: f64,
    /// Number of observations processed
    pub num_observations: usize,
    /// Previous mode probabilities (for change detection)
    pub prev_mode_probabilities: Vec<f64>,
}

impl ImmState {
    /// Creates initial state from config.
    pub fn from_config(config: &ImmConfig, initial_state: f64) -> Self {
        let mode_states = (0..config.num_modes)
            .map(|_| ModeFilterState::new(initial_state, 1.0))
            .collect();

        Self {
            mode_states,
            mode_probabilities: config.initial_mode_probs.clone(),
            combined_state: initial_state,
            combined_covariance: 1.0,
            num_observations: 0,
            prev_mode_probabilities: config.initial_mode_probs.clone(),
        }
    }

    /// Returns the index of the most likely mode.
    pub fn most_likely_mode(&self) -> usize {
        self.mode_probabilities
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(i, _)| i)
            .unwrap_or(0)
    }
}

/// Result from a single IMM update step.
#[derive(Debug, Clone)]
pub struct ImmUpdateResult {
    /// Current mode probabilities after update
    pub mode_probabilities: Vec<f64>,
    /// Most likely regime
    pub most_likely_regime: Regime,
    /// Probability of the most likely regime
    pub max_mode_probability: f64,
    /// Combined (weighted) state estimate
    pub combined_state: f64,
    /// Combined state uncertainty
    pub combined_covariance: f64,
    /// Per-mode state estimates
    pub mode_states: Vec<f64>,
    /// Per-mode likelihoods
    pub mode_likelihoods: Vec<f64>,
    /// Whether a regime change was detected
    pub regime_change_detected: bool,
    /// Magnitude of probability shift (for change detection)
    pub probability_shift: f64,
    /// Previous most likely regime (if changed)
    pub previous_regime: Option<Regime>,
    /// Observation that was processed
    pub observation: f64,
    /// Innovation (prediction error) for combined estimate
    pub innovation: f64,
}

/// Summary result from batch IMM analysis.
#[derive(Debug, Clone)]
pub struct ImmResult {
    /// Final mode probabilities
    pub final_mode_probabilities: Vec<f64>,
    /// Most likely final regime
    pub most_likely_regime: Regime,
    /// Time-weighted mode probabilities (average over all observations)
    pub average_mode_probabilities: Vec<f64>,
    /// Number of regime changes detected
    pub num_regime_changes: usize,
    /// Timestamps/indices of detected regime changes
    pub regime_change_points: Vec<usize>,
    /// Sequence of most likely regimes at each step
    pub regime_sequence: Vec<Regime>,
    /// Final combined state estimate
    pub final_state: f64,
    /// Final state uncertainty
    pub final_covariance: f64,
    /// Total observations processed
    pub num_observations: usize,
    /// Average innovation magnitude (prediction accuracy)
    pub avg_innovation_magnitude: f64,
    /// Regime stability score (1.0 = very stable, 0.0 = chaotic switching)
    pub regime_stability: f64,
}

/// Evidence features for integration with the inference ledger.
#[derive(Debug, Clone)]
pub struct ImmEvidence {
    /// Log Bayes factor for regime change
    pub regime_change_log_bf: f64,
    /// Confidence in current regime assignment
    pub regime_confidence: Confidence,
    /// Suggested classification based on current regime
    pub suggested_classification: Classification,
    /// Direction of regime shift (if any)
    pub direction: Direction,
    /// Current regime probabilities
    pub mode_probabilities: Vec<f64>,
    /// Most likely regime
    pub regime: Regime,
    /// Regime stability score (0-1, higher = more stable)
    pub stability: f64,
}

impl ImmEvidence {
    /// Returns a log Bayes factor suitable for evidence combination.
    /// Positive values suggest problematic process state.
    pub fn log_bf_for_triage(&self) -> f64 {
        // Combine regime change evidence with regime type evidence
        let regime_factor = match self.regime {
            Regime::Idle => -1.0,    // Idle is typically good
            Regime::Active => 0.0,   // Active is neutral
            Regime::Elevated => 1.0, // Elevated suggests problems
            Regime::Stuck => 2.0,    // Stuck strongly suggests problems
            Regime::Custom(_) => 0.0,
        };

        // Instability adds to concern
        let instability_factor = (1.0 - self.stability) * 0.5;

        self.regime_change_log_bf + regime_factor + instability_factor
    }
}

/// The main IMM analyzer that maintains filter state and processes observations.
#[derive(Debug, Clone)]
pub struct ImmAnalyzer {
    config: ImmConfig,
    state: ImmState,
    /// Running sum of mode probabilities for averaging
    prob_accumulator: Vec<f64>,
    /// Running sum of innovation magnitudes
    innovation_accumulator: f64,
    /// Detected regime changes
    regime_changes: Vec<usize>,
    /// Sequence of regimes
    regime_sequence: Vec<Regime>,
}

impl ImmAnalyzer {
    /// Creates a new IMM analyzer with the given configuration.
    pub fn new(config: ImmConfig) -> Result<Self, ImmError> {
        config.validate()?;

        let state = ImmState::from_config(&config, 0.0);
        let prob_accumulator = vec![0.0; config.num_modes];

        Ok(Self {
            config,
            state,
            prob_accumulator,
            innovation_accumulator: 0.0,
            regime_changes: Vec::new(),
            regime_sequence: Vec::new(),
        })
    }

    /// Creates a new IMM analyzer with a custom initial state.
    pub fn with_initial_state(config: ImmConfig, initial_state: f64) -> Result<Self, ImmError> {
        config.validate()?;

        let state = ImmState::from_config(&config, initial_state);
        let prob_accumulator = vec![0.0; config.num_modes];

        Ok(Self {
            config,
            state,
            prob_accumulator,
            innovation_accumulator: 0.0,
            regime_changes: Vec::new(),
            regime_sequence: Vec::new(),
        })
    }

    /// Returns the current state.
    pub fn state(&self) -> &ImmState {
        &self.state
    }

    /// Returns the configuration.
    pub fn config(&self) -> &ImmConfig {
        &self.config
    }

    /// Resets the analyzer to initial state.
    pub fn reset(&mut self) {
        self.state = ImmState::from_config(&self.config, 0.0);
        self.prob_accumulator = vec![0.0; self.config.num_modes];
        self.innovation_accumulator = 0.0;
        self.regime_changes.clear();
        self.regime_sequence.clear();
    }

    /// Processes a single observation and updates the filter state.
    #[allow(clippy::needless_range_loop)]
    pub fn update(&mut self, observation: f64) -> Result<ImmUpdateResult, ImmError> {
        let n = self.config.num_modes;

        // Store previous state for change detection
        self.state.prev_mode_probabilities = self.state.mode_probabilities.clone();
        let prev_most_likely = self.state.most_likely_mode();

        // Step 1: Mixing - compute mixed initial conditions
        let mut mixed_states = Vec::with_capacity(n);
        let mut mixed_covariances = Vec::with_capacity(n);

        for j in 0..n {
            // Compute mixing probabilities: P(mode_i at t-1 | mode_j at t)
            let mut mixing_probs = vec![0.0; n];
            let mut c_bar = 0.0;

            for i in 0..n {
                c_bar += self.config.transition_matrix[i][j] * self.state.mode_probabilities[i];
            }

            if c_bar > 1e-10 {
                for i in 0..n {
                    mixing_probs[i] = self.config.transition_matrix[i][j]
                        * self.state.mode_probabilities[i]
                        / c_bar;
                }
            } else {
                // Fallback to uniform if c_bar is too small
                for prob in mixing_probs.iter_mut() {
                    *prob = 1.0 / n as f64;
                }
            }

            // Compute mixed state and covariance for mode j
            let mut x_mixed = 0.0;
            for i in 0..n {
                x_mixed += mixing_probs[i] * self.state.mode_states[i].state;
            }

            let mut p_mixed = 0.0;
            for i in 0..n {
                let diff = self.state.mode_states[i].state - x_mixed;
                p_mixed += mixing_probs[i] * (self.state.mode_states[i].covariance + diff * diff);
            }

            mixed_states.push(x_mixed);
            mixed_covariances.push(p_mixed);
        }

        // Step 2: Filtering - run Kalman update for each mode
        let mut mode_likelihoods = vec![0.0; n];

        for j in 0..n {
            let a = self.config.state_transition[j];
            let q = self.config.process_noise[j];
            let r = self.config.measurement_noise;

            // Prediction step
            let x_pred = a * mixed_states[j];
            let p_pred = a * a * mixed_covariances[j] + q;

            // Update step
            let innovation = observation - x_pred;
            let s = p_pred + r; // Innovation covariance

            // Kalman gain
            let k = p_pred / s;

            // Updated state
            let x_upd = x_pred + k * innovation;
            let p_upd = (1.0 - k) * p_pred;

            // Mode likelihood (Gaussian)
            let likelihood = (-0.5
                * (innovation * innovation / s
                    + s.ln()
                    + std::f64::consts::LN_2
                    + std::f64::consts::PI.ln()))
            .exp();

            self.state.mode_states[j] = ModeFilterState {
                state: x_upd,
                covariance: p_upd,
                innovation,
                innovation_cov: s,
                likelihood,
            };

            mode_likelihoods[j] = likelihood;
        }

        // Step 3: Mode probability update
        let mut new_mode_probs = vec![0.0; n];
        let mut total_likelihood = 0.0;

        for j in 0..n {
            // Predicted mode probability
            let mut c_j = 0.0;
            for i in 0..n {
                c_j += self.config.transition_matrix[i][j] * self.state.mode_probabilities[i];
            }
            new_mode_probs[j] = mode_likelihoods[j] * c_j;
            total_likelihood += new_mode_probs[j];
        }

        // Normalize
        if total_likelihood > 1e-300 {
            for prob in new_mode_probs.iter_mut() {
                *prob /= total_likelihood;
            }
        } else {
            // Numerical underflow - reset to uniform
            for prob in new_mode_probs.iter_mut() {
                *prob = 1.0 / n as f64;
            }
        }

        // Apply smoothing if configured
        if self.config.probability_smoothing > 0.0 {
            let alpha = self.config.probability_smoothing;
            for j in 0..n {
                new_mode_probs[j] = alpha * self.state.prev_mode_probabilities[j]
                    + (1.0 - alpha) * new_mode_probs[j];
            }
            // Re-normalize after smoothing
            let sum: f64 = new_mode_probs.iter().sum();
            for prob in new_mode_probs.iter_mut() {
                *prob /= sum;
            }
        }

        // Enforce minimum probability
        let min_p = self.config.min_mode_probability;
        let mut needs_renorm = false;
        for prob in new_mode_probs.iter_mut() {
            if *prob < min_p {
                *prob = min_p;
                needs_renorm = true;
            }
        }
        if needs_renorm {
            let sum: f64 = new_mode_probs.iter().sum();
            for prob in new_mode_probs.iter_mut() {
                *prob /= sum;
            }
        }

        self.state.mode_probabilities = new_mode_probs.clone();

        // Step 4: Combination - weighted average of mode estimates
        let mut combined_state = 0.0;
        for j in 0..n {
            combined_state += new_mode_probs[j] * self.state.mode_states[j].state;
        }

        let mut combined_covariance = 0.0;
        for j in 0..n {
            let diff = self.state.mode_states[j].state - combined_state;
            combined_covariance +=
                new_mode_probs[j] * (self.state.mode_states[j].covariance + diff * diff);
        }

        self.state.combined_state = combined_state;
        self.state.combined_covariance = combined_covariance;
        self.state.num_observations += 1;

        // Detect regime changes
        let current_most_likely = self.state.most_likely_mode();
        let max_prob_shift: f64 = self
            .state
            .mode_probabilities
            .iter()
            .zip(self.state.prev_mode_probabilities.iter())
            .map(|(a, b)| (a - b).abs())
            .fold(0.0, f64::max);

        let regime_change_detected = (current_most_likely != prev_most_likely)
            || (max_prob_shift > self.config.regime_change_threshold);

        let previous_regime = if current_most_likely != prev_most_likely {
            self.regime_changes.push(self.state.num_observations);
            Some(Regime::from_index(prev_most_likely))
        } else {
            None
        };

        // Update accumulators
        for (acc, prob) in self.prob_accumulator.iter_mut().zip(new_mode_probs.iter()) {
            *acc += prob;
        }
        let innovation = observation - combined_state;
        self.innovation_accumulator += innovation.abs();

        // Track regime sequence
        self.regime_sequence
            .push(Regime::from_index(current_most_likely));

        Ok(ImmUpdateResult {
            mode_probabilities: new_mode_probs,
            most_likely_regime: Regime::from_index(current_most_likely),
            max_mode_probability: self.state.mode_probabilities[current_most_likely],
            combined_state,
            combined_covariance,
            mode_states: self.state.mode_states.iter().map(|s| s.state).collect(),
            mode_likelihoods,
            regime_change_detected,
            probability_shift: max_prob_shift,
            previous_regime,
            observation,
            innovation,
        })
    }

    /// Processes a batch of observations.
    pub fn update_batch(&mut self, observations: &[f64]) -> Result<Vec<ImmUpdateResult>, ImmError> {
        let mut results = Vec::with_capacity(observations.len());
        for &obs in observations {
            results.push(self.update(obs)?);
        }
        Ok(results)
    }

    /// Returns summary statistics for all processed observations.
    pub fn summarize(&self) -> Result<ImmResult, ImmError> {
        if self.state.num_observations == 0 {
            return Err(ImmError::NoObservations);
        }

        let n = self.state.num_observations as f64;

        // Average mode probabilities
        let average_mode_probabilities: Vec<f64> =
            self.prob_accumulator.iter().map(|&acc| acc / n).collect();

        // Regime stability: based on how often regime changes occur
        // and how concentrated the mode probability distribution is
        let change_rate = self.regime_changes.len() as f64 / n;
        let prob_entropy: f64 = -self
            .state
            .mode_probabilities
            .iter()
            .filter(|&&p| p > 1e-10)
            .map(|&p| p * p.ln())
            .sum::<f64>();
        let max_entropy = (self.config.num_modes as f64).ln();
        let concentration = 1.0 - (prob_entropy / max_entropy).min(1.0);

        // Stability combines low change rate and high concentration
        let regime_stability = (1.0 - change_rate.min(1.0)) * 0.5 + concentration * 0.5;

        Ok(ImmResult {
            final_mode_probabilities: self.state.mode_probabilities.clone(),
            most_likely_regime: Regime::from_index(self.state.most_likely_mode()),
            average_mode_probabilities,
            num_regime_changes: self.regime_changes.len(),
            regime_change_points: self.regime_changes.clone(),
            regime_sequence: self.regime_sequence.clone(),
            final_state: self.state.combined_state,
            final_covariance: self.state.combined_covariance,
            num_observations: self.state.num_observations,
            avg_innovation_magnitude: self.innovation_accumulator / n,
            regime_stability,
        })
    }

    /// Generates evidence for the inference ledger.
    pub fn to_evidence(&self) -> Result<ImmEvidence, ImmError> {
        let result = self.summarize()?;

        // Compute log Bayes factor for regime change
        // Compare most likely mode probability to second most likely
        let mut sorted_probs = self.state.mode_probabilities.clone();
        sorted_probs.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));

        let log_bf = if sorted_probs.len() >= 2 && sorted_probs[1] > 1e-10 {
            (sorted_probs[0] / sorted_probs[1]).ln()
        } else {
            10.0 // Strong evidence for single mode
        };

        // Determine confidence based on max probability
        let max_prob = sorted_probs[0];
        let confidence = if max_prob > 0.9 {
            Confidence::High
        } else if max_prob > 0.7 {
            Confidence::Medium
        } else {
            Confidence::Low
        };

        // Classify based on most likely regime
        // Map regime states to process triage classifications
        let most_likely = Regime::from_index(self.state.most_likely_mode());
        let classification = match most_likely {
            Regime::Idle => Classification::Useful, // Idle processes are typically useful
            Regime::Active => Classification::Useful, // Active processes are working
            Regime::Elevated => Classification::UsefulBad, // Elevated may be resource hogs
            Regime::Stuck => Classification::Abandoned, // Stuck processes are likely abandoned
            Regime::Custom(_) => Classification::Useful, // Default to useful for custom
        };

        // Direction based on recent regime changes
        // TowardPredicted = evidence supports the classification
        // TowardReference = evidence suggests different classification
        let direction = if self.regime_changes.is_empty() {
            Direction::Neutral
        } else {
            // Check if trending towards problematic states
            let recent_regime = most_likely;
            match recent_regime {
                Regime::Elevated | Regime::Stuck => Direction::TowardPredicted,
                Regime::Idle => Direction::TowardReference,
                _ => Direction::Neutral,
            }
        };

        Ok(ImmEvidence {
            regime_change_log_bf: log_bf,
            regime_confidence: confidence,
            suggested_classification: classification,
            direction,
            mode_probabilities: self.state.mode_probabilities.clone(),
            regime: most_likely,
            stability: result.regime_stability,
        })
    }
}

/// Batch analyzer for processing multiple time series with IMM.
#[derive(Debug)]
pub struct BatchImmAnalyzer {
    config: ImmConfig,
}

impl BatchImmAnalyzer {
    /// Creates a new batch analyzer with the given configuration.
    pub fn new(config: ImmConfig) -> Result<Self, ImmError> {
        config.validate()?;
        Ok(Self { config })
    }

    /// Analyzes a single time series and returns the summary result.
    pub fn analyze(&self, observations: &[f64]) -> Result<ImmResult, ImmError> {
        let mut analyzer = ImmAnalyzer::new(self.config.clone())?;
        analyzer.update_batch(observations)?;
        analyzer.summarize()
    }

    /// Analyzes a single time series with a custom initial state.
    pub fn analyze_with_initial(
        &self,
        observations: &[f64],
        initial_state: f64,
    ) -> Result<ImmResult, ImmError> {
        let mut analyzer = ImmAnalyzer::with_initial_state(self.config.clone(), initial_state)?;
        analyzer.update_batch(observations)?;
        analyzer.summarize()
    }

    /// Analyzes multiple time series and returns results for each.
    pub fn analyze_batch(&self, series: &[Vec<f64>]) -> Vec<Result<ImmResult, ImmError>> {
        series.iter().map(|s| self.analyze(s)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_validation() {
        let config = ImmConfig::two_regime_default();
        assert!(config.validate().is_ok());

        let config = ImmConfig::three_regime_default();
        assert!(config.validate().is_ok());

        let config = ImmConfig::four_regime_default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_invalid_config_detection() {
        let mut config = ImmConfig::two_regime_default();
        config.num_modes = 0;
        assert!(config.validate().is_err());

        let mut config = ImmConfig::two_regime_default();
        config.transition_matrix[0][0] = 0.5; // Row won't sum to 1
        assert!(config.validate().is_err());

        let mut config = ImmConfig::two_regime_default();
        config.initial_mode_probs = vec![0.3, 0.3]; // Doesn't sum to 1
        assert!(config.validate().is_err());

        let mut config = ImmConfig::two_regime_default();
        config.measurement_noise = 0.0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_basic_imm_update() {
        let config = ImmConfig::two_regime_default();
        let mut analyzer = ImmAnalyzer::new(config).unwrap();

        // Process a few observations
        let result = analyzer.update(1.0).unwrap();
        assert_eq!(result.mode_probabilities.len(), 2);
        assert!((result.mode_probabilities.iter().sum::<f64>() - 1.0).abs() < 1e-6);

        let result = analyzer.update(1.1).unwrap();
        assert_eq!(result.mode_probabilities.len(), 2);
    }

    #[test]
    fn test_regime_detection_idle() {
        let config = ImmConfig::two_regime_default();
        let mut analyzer = ImmAnalyzer::new(config).unwrap();

        // Constant low values should favor idle regime
        for _ in 0..50 {
            analyzer.update(0.1).unwrap();
        }

        let result = analyzer.summarize().unwrap();
        assert_eq!(result.most_likely_regime, Regime::Idle);
        assert!(result.final_mode_probabilities[0] > 0.5); // Idle probability > 0.5
    }

    #[test]
    fn test_regime_detection_active() {
        let mut config = ImmConfig::two_regime_default();
        // Adjust to make active regime more likely with high variance/innovation
        // Active mode has high process noise, idle has very low
        config.process_noise = vec![0.0001, 2.0];
        // Start with more neutral priors
        config.initial_mode_probs = vec![0.5, 0.5];
        // Lower smoothing to respond faster
        config.probability_smoothing = 0.0;
        let mut analyzer = ImmAnalyzer::new(config).unwrap();

        // Large, variable jumps that the high-variance Active model fits better
        // These innovations are too large for the low-noise Idle model
        let observations: Vec<f64> = (0..100)
            .map(|i| {
                // Alternating big jumps that can't be explained by low process noise
                if i % 2 == 0 {
                    10.0
                } else {
                    -5.0
                }
            })
            .collect();

        for obs in observations {
            analyzer.update(obs).unwrap();
        }

        let result = analyzer.summarize().unwrap();
        // With such high variance data, Active (high process noise) should be favored
        // Check that Active probability is higher than Idle
        assert!(
            result.final_mode_probabilities[1] > result.final_mode_probabilities[0],
            "Active probability ({}) should be higher than Idle ({}) for high-variance data",
            result.final_mode_probabilities[1],
            result.final_mode_probabilities[0]
        );
    }

    #[test]
    fn test_regime_switching_detection() {
        let config = ImmConfig::two_regime_default();
        let mut analyzer = ImmAnalyzer::new(config).unwrap();

        // Start with idle behavior
        for _ in 0..20 {
            analyzer.update(0.1).unwrap();
        }

        // Switch to active behavior
        for i in 0..30 {
            analyzer.update(2.0 + (i as f64 * 0.2).sin()).unwrap();
        }

        let result = analyzer.summarize().unwrap();
        assert!(result.num_regime_changes > 0, "Should detect regime change");
        assert!(!result.regime_change_points.is_empty());
    }

    #[test]
    fn test_three_regime_model() {
        let config = ImmConfig::three_regime_default();
        let mut analyzer = ImmAnalyzer::new(config).unwrap();

        // Process observations
        for i in 0..30 {
            analyzer.update((i as f64) * 0.1).unwrap();
        }

        let result = analyzer.summarize().unwrap();
        assert_eq!(result.final_mode_probabilities.len(), 3);
        assert_eq!(result.average_mode_probabilities.len(), 3);
    }

    #[test]
    fn test_stuck_regime_detection() {
        let mut config = ImmConfig::three_regime_default();
        // Make stuck regime have very low process noise (constant state)
        config.process_noise = vec![0.1, 0.5, 0.0001];
        config.state_transition = vec![0.9, 0.95, 0.9999];
        let mut analyzer = ImmAnalyzer::new(config).unwrap();

        // Constant value (stuck behavior)
        for _ in 0..100 {
            analyzer.update(5.0).unwrap();
        }

        let result = analyzer.summarize().unwrap();
        // Should favor stuck regime (index 2)
        assert!(
            result.final_mode_probabilities[2] > result.final_mode_probabilities[0],
            "Stuck regime should have higher probability than idle for constant input"
        );
    }

    #[test]
    fn test_evidence_generation() {
        let config = ImmConfig::two_regime_default();
        let mut analyzer = ImmAnalyzer::new(config).unwrap();

        for _ in 0..20 {
            analyzer.update(0.5).unwrap();
        }

        let evidence = analyzer.to_evidence().unwrap();
        assert!(evidence.regime_change_log_bf.is_finite());
        assert!(evidence.stability >= 0.0 && evidence.stability <= 1.0);
        assert_eq!(evidence.mode_probabilities.len(), 2);
    }

    #[test]
    fn test_batch_analyzer() {
        let config = ImmConfig::two_regime_default();
        let batch_analyzer = BatchImmAnalyzer::new(config).unwrap();

        let observations: Vec<f64> = (0..30).map(|i| (i as f64) * 0.1).collect();
        let result = batch_analyzer.analyze(&observations).unwrap();

        assert_eq!(result.num_observations, 30);
        assert!(!result.regime_sequence.is_empty());
    }

    #[test]
    fn test_numerical_stability() {
        let config = ImmConfig::two_regime_default();
        let mut analyzer = ImmAnalyzer::new(config).unwrap();

        // Test with extreme values
        analyzer.update(1e10).unwrap();
        analyzer.update(1e-10).unwrap();
        analyzer.update(0.0).unwrap();

        let result = analyzer.summarize().unwrap();
        assert!(result.final_state.is_finite());
        assert!(result.final_covariance.is_finite());

        // Mode probabilities should still sum to 1
        let prob_sum: f64 = result.final_mode_probabilities.iter().sum();
        assert!((prob_sum - 1.0).abs() < 1e-6);
    }

    #[test]
    fn test_regime_from_index_roundtrip() {
        for idx in 0..10 {
            let regime = Regime::from_index(idx);
            assert_eq!(regime.index(), idx);
        }
    }

    #[test]
    fn test_reset() {
        let config = ImmConfig::two_regime_default();
        let mut analyzer = ImmAnalyzer::new(config.clone()).unwrap();

        // Process some observations
        for _ in 0..10 {
            analyzer.update(1.0).unwrap();
        }

        assert_eq!(analyzer.state().num_observations, 10);

        // Reset
        analyzer.reset();

        assert_eq!(analyzer.state().num_observations, 0);
        assert_eq!(
            analyzer.state().mode_probabilities,
            config.initial_mode_probs
        );
    }

    #[test]
    fn test_innovation_tracking() {
        let config = ImmConfig::two_regime_default();
        let mut analyzer = ImmAnalyzer::new(config).unwrap();

        let result = analyzer.update(10.0).unwrap();
        // Innovation should be non-zero for first observation (predicting from 0)
        assert!(result.innovation.abs() > 0.0);
    }

    #[test]
    fn test_mode_likelihoods_positive() {
        let config = ImmConfig::two_regime_default();
        let mut analyzer = ImmAnalyzer::new(config).unwrap();

        let result = analyzer.update(1.0).unwrap();
        for likelihood in result.mode_likelihoods {
            assert!(likelihood >= 0.0, "Likelihood must be non-negative");
        }
    }

    #[test]
    fn test_combined_state_consistency() {
        let config = ImmConfig::two_regime_default();
        let mut analyzer = ImmAnalyzer::new(config).unwrap();

        for i in 0..20 {
            let obs = (i as f64) * 0.5;
            let result = analyzer.update(obs).unwrap();

            // Combined state should be weighted average of mode states
            let expected: f64 = result
                .mode_states
                .iter()
                .zip(result.mode_probabilities.iter())
                .map(|(s, p)| s * p)
                .sum();

            assert!(
                (result.combined_state - expected).abs() < 1e-10,
                "Combined state should be weighted average of mode states"
            );
        }
    }
}
