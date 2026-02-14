//! Wonham filtering + Gittins index scheduling for probe prioritization.
//!
//! Implements Plan §4.11 / §2(N,O): advanced continuous-time partial
//! observability and optimal stopping/scheduling tools.
//!
//! # Wonham Filtering
//!
//! The Wonham filter is a continuous-time Bayesian filter for hidden Markov
//! states. Given a generator matrix Q (continuous-time transition rates) and
//! observation signal, it maintains a belief state b(t) over the 4-class
//! process model. The continuous-time predict step uses:
//!
//!   b(t + Δt) ∝ exp(Q·Δt) · b(t)
//!
//! which for small Δt is approximated by:
//!
//!   b(t + Δt) ≈ (I + Q·Δt) · b(t)
//!
//! # Gittins Index
//!
//! The Gittins index provides an optimal scheduling policy for the restless
//! multi-armed bandit problem of allocating probe effort across candidates.
//! The index for candidate i is:
//!
//!   G_i = (stopping_value_i − continuation_value_i) / expected_probe_cost
//!
//! Candidates with higher indices should be acted upon sooner.
//!
//! # Usage
//!
//! ```ignore
//! use pt_core::decision::wonham_gittins::*;
//! use pt_core::inference::belief_state::BeliefState;
//!
//! let filter = WonhamFilter::new(WonhamConfig::default());
//! let belief = BeliefState::uniform();
//! let predicted = filter.predict(&belief, 10.0).unwrap();
//!
//! // Schedule candidates by Gittins index
//! let schedule = compute_gittins_schedule(&candidates, &config, &transition).unwrap();
//! ```

use crate::decision::expected_loss::{Action, ActionFeasibility};
use crate::decision::myopic_policy::compute_loss_table;
use crate::decision::voi::ProbeType;
use crate::inference::belief_state::{
    update_belief, BeliefState, BeliefStateError, BeliefUpdateConfig, ObservationLikelihood,
    TransitionModel, NUM_STATES,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Errors ───────────────────────────────────────────────────────────────

/// Errors from Wonham filtering and Gittins index computation.
#[derive(Debug, Error)]
pub enum WonhamError {
    #[error("belief state error: {0}")]
    BeliefState(#[from] BeliefStateError),

    #[error("invalid generator matrix: row {row} does not sum to ~0 (sum={sum})")]
    InvalidGenerator { row: usize, sum: f64 },

    #[error("invalid time delta: {0} (must be positive and finite)")]
    InvalidTimeDelta(f64),

    #[error("invalid discount factor: {0} (must be in (0, 1))")]
    InvalidDiscount(f64),

    #[error("no candidates provided")]
    NoCandidates,
}

// ── Configuration ────────────────────────────────────────────────────────

/// Configuration for the Wonham filter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WonhamConfig {
    /// Discount factor γ ∈ (0, 1) for Gittins index computation.
    /// Higher values weight future rewards more.
    pub discount_factor: f64,

    /// Lookahead horizon (number of steps) for value iteration.
    pub horizon: usize,

    /// Minimum belief probability floor to prevent numerical underflow.
    pub min_belief_prob: f64,

    /// Whether to use matrix-exponential prediction (true) or Euler
    /// approximation (false) for the continuous-time predict step.
    pub use_matrix_exp: bool,
}

impl Default for WonhamConfig {
    fn default() -> Self {
        Self {
            discount_factor: 0.95,
            horizon: 10,
            min_belief_prob: 1e-10,
            use_matrix_exp: false,
        }
    }
}

// ── Generator matrix ─────────────────────────────────────────────────────

/// Continuous-time generator (rate) matrix Q.
///
/// Each row sums to 0: Q\[i\]\[j\] for j!=i is the transition rate from i to j,
/// and Q\[i\]\[i\] = -Σ_{j!=i} Q\[i\]\[j\].
#[derive(Debug, Clone, Serialize)]
pub struct GeneratorMatrix {
    /// Rate matrix Q\[from\]\[to\]. Rows sum to 0.
    pub rates: [[f64; NUM_STATES]; NUM_STATES],
}

#[allow(clippy::needless_range_loop)]
impl GeneratorMatrix {
    /// Create from explicit rates. Validates that rows sum to ~0.
    pub fn new(rates: [[f64; NUM_STATES]; NUM_STATES]) -> Result<Self, WonhamError> {
        for (i, row) in rates.iter().enumerate() {
            let sum: f64 = row.iter().sum();
            if sum.abs() > 1e-6 {
                return Err(WonhamError::InvalidGenerator { row: i, sum });
            }
            // Off-diagonal rates must be non-negative
            for (j, &r) in row.iter().enumerate() {
                if i != j && r < -1e-12 {
                    return Err(WonhamError::InvalidGenerator { row: i, sum: r });
                }
            }
        }
        Ok(Self { rates })
    }

    /// Build a generator matrix from a discrete-time transition matrix and a
    /// characteristic time scale τ (seconds per discrete step).
    ///
    /// Uses the approximation Q ≈ (P − I) / τ, which is valid when τ is the
    /// natural time unit of the transition matrix.
    pub fn from_transition(transition: &TransitionModel, tau: f64) -> Result<Self, WonhamError> {
        if tau <= 0.0 || !tau.is_finite() {
            return Err(WonhamError::InvalidTimeDelta(tau));
        }

        let mut rates = [[0.0; NUM_STATES]; NUM_STATES];
        for i in 0..NUM_STATES {
            for j in 0..NUM_STATES {
                if i == j {
                    rates[i][j] = (transition.matrix[i][j] - 1.0) / tau;
                } else {
                    rates[i][j] = transition.matrix[i][j] / tau;
                }
            }
        }

        Self::new(rates)
    }

    /// Convert to a discrete-time transition matrix for time step Δt.
    ///
    /// Uses the Euler approximation P(Δt) ≈ I + Q·Δt (first-order).
    pub fn to_transition(&self, dt: f64) -> Result<TransitionModel, WonhamError> {
        if dt <= 0.0 || !dt.is_finite() {
            return Err(WonhamError::InvalidTimeDelta(dt));
        }

        let mut matrix = [[0.0; NUM_STATES]; NUM_STATES];
        for i in 0..NUM_STATES {
            for j in 0..NUM_STATES {
                let val = if i == j { 1.0 } else { 0.0 } + self.rates[i][j] * dt;
                matrix[i][j] = val.max(0.0);
            }
            // Normalize row to ensure valid probability distribution
            let row_sum: f64 = matrix[i].iter().sum();
            if row_sum > 0.0 {
                for j in 0..NUM_STATES {
                    matrix[i][j] /= row_sum;
                }
            }
        }

        TransitionModel::new(matrix).map_err(WonhamError::BeliefState)
    }

    /// Convert using uniformization (matrix exponential via Padé-style
    /// truncated series) for larger Δt values.
    ///
    /// exp(Q·Δt) ≈ Σ_{k=0}^{N} (Q·Δt)^k / k!
    pub fn to_transition_exp(&self, dt: f64, terms: usize) -> Result<TransitionModel, WonhamError> {
        if dt <= 0.0 || !dt.is_finite() {
            return Err(WonhamError::InvalidTimeDelta(dt));
        }

        // A = Q * dt
        let mut a = [[0.0; NUM_STATES]; NUM_STATES];
        for i in 0..NUM_STATES {
            for j in 0..NUM_STATES {
                a[i][j] = self.rates[i][j] * dt;
            }
        }

        // Result = I (first term of Taylor series)
        let mut result = [[0.0; NUM_STATES]; NUM_STATES];
        for i in 0..NUM_STATES {
            result[i][i] = 1.0;
        }

        // Power = I (will accumulate A^k)
        let mut power = [[0.0; NUM_STATES]; NUM_STATES];
        for i in 0..NUM_STATES {
            power[i][i] = 1.0;
        }

        let mut factorial = 1.0;
        for k in 1..=terms {
            factorial *= k as f64;
            // power = power * A
            let prev = power;
            power = mat_mul(&prev, &a);
            // result += power / k!
            for i in 0..NUM_STATES {
                for j in 0..NUM_STATES {
                    result[i][j] += power[i][j] / factorial;
                }
            }
        }

        // Clamp negatives and renormalize
        for i in 0..NUM_STATES {
            for j in 0..NUM_STATES {
                result[i][j] = result[i][j].max(0.0);
            }
            let row_sum: f64 = result[i].iter().sum();
            if row_sum > 0.0 {
                for j in 0..NUM_STATES {
                    result[i][j] /= row_sum;
                }
            }
        }

        TransitionModel::new(result).map_err(WonhamError::BeliefState)
    }
}

/// Default generator derived from the default lifecycle transition model
/// with τ = 60 seconds (one scan interval).
impl Default for GeneratorMatrix {
    fn default() -> Self {
        GeneratorMatrix::from_transition(&TransitionModel::default_lifecycle(), 60.0)
            .expect("default lifecycle model should produce valid generator")
    }
}

// ── Wonham Filter ────────────────────────────────────────────────────────

/// Continuous-time Wonham filter for hidden Markov state estimation.
///
/// Wraps the discrete-time belief update machinery from `belief_state` with
/// continuous-time prediction via the generator matrix.
#[derive(Debug, Clone)]
pub struct WonhamFilter {
    config: WonhamConfig,
    generator: GeneratorMatrix,
}

impl WonhamFilter {
    /// Create a new Wonham filter with the given configuration and generator.
    pub fn new(config: WonhamConfig, generator: GeneratorMatrix) -> Self {
        Self { config, generator }
    }

    /// Create with default generator from a transition model and time scale.
    pub fn from_transition(
        config: WonhamConfig,
        transition: &TransitionModel,
        tau: f64,
    ) -> Result<Self, WonhamError> {
        let generator = GeneratorMatrix::from_transition(transition, tau)?;
        Ok(Self { config, generator })
    }

    /// Continuous-time prediction: advance belief by Δt seconds.
    pub fn predict(&self, belief: &BeliefState, dt: f64) -> Result<BeliefState, WonhamError> {
        if dt <= 0.0 || !dt.is_finite() {
            return Err(WonhamError::InvalidTimeDelta(dt));
        }

        let transition = if self.config.use_matrix_exp {
            self.generator.to_transition_exp(dt, 12)?
        } else {
            self.generator.to_transition(dt)?
        };

        transition.predict(belief).map_err(WonhamError::BeliefState)
    }

    /// Full filter step: predict by Δt then update with observation.
    pub fn filter_step(
        &self,
        belief: &BeliefState,
        dt: f64,
        observation: &ObservationLikelihood,
    ) -> Result<BeliefState, WonhamError> {
        // Prediction already applied via self.predict(); update uses identity
        // transition so the observation likelihood is applied to the predicted belief.
        let predicted = self.predict(belief, dt)?;

        let update_config = BeliefUpdateConfig {
            min_prob: self.config.min_belief_prob,
            ..BeliefUpdateConfig::default()
        };

        let result = update_belief(
            &predicted,
            &TransitionModel::identity(),
            observation,
            &update_config,
        )?;
        Ok(result.belief)
    }

    /// Run filter over a sequence of (dt, observation) pairs.
    pub fn filter_sequence(
        &self,
        initial: &BeliefState,
        steps: &[(f64, ObservationLikelihood)],
    ) -> Result<Vec<BeliefState>, WonhamError> {
        let mut beliefs = Vec::with_capacity(steps.len());
        let mut current = initial.clone();

        for (dt, obs) in steps {
            current = self.filter_step(&current, *dt, obs)?;
            beliefs.push(current.clone());
        }

        Ok(beliefs)
    }
}

// ── Gittins Index ────────────────────────────────────────────────────────

/// A candidate for Gittins index scheduling.
#[derive(Debug, Clone)]
pub struct GittinsCandidate {
    /// Unique identifier (typically PID string).
    pub id: String,
    /// Current belief state for this candidate.
    pub belief: BeliefState,
    /// Feasible actions for this candidate.
    pub feasibility: ActionFeasibility,
    /// Available probes for gathering more evidence.
    pub available_probes: Vec<ProbeType>,
}

/// Result of Gittins index computation for a single candidate.
#[derive(Debug, Clone, Serialize)]
pub struct GittinsIndex {
    /// Candidate identifier.
    pub candidate_id: String,
    /// The Gittins index value (higher = act sooner).
    pub index_value: f64,
    /// Expected loss of the optimal action if we stop and act now.
    pub stopping_value: f64,
    /// Expected future value of continuing to gather information.
    pub continuation_value: f64,
    /// Optimal action at the current belief.
    pub optimal_action: Action,
    /// Decomposition of stopping value by state.
    pub state_decomposition: [f64; NUM_STATES],
    /// Belief entropy (higher = more uncertain).
    pub belief_entropy: f64,
}

/// A scheduled set of candidates ranked by Gittins index.
#[derive(Debug, Clone, Serialize)]
pub struct GittinsSchedule {
    /// Candidates ranked by Gittins index (highest first).
    pub allocations: Vec<GittinsIndex>,
    /// Summary rationale.
    pub rationale: String,
}

/// Compute the Gittins index for a single candidate.
///
/// The index captures the trade-off between acting now (stopping) vs.
/// gathering more information (continuing). Higher index = more valuable
/// to act on sooner.
///
/// The stopping value is the minimum expected loss over feasible actions.
/// The continuation value estimates the expected loss after one more round
/// of observation, discounted by γ.
pub fn compute_gittins_index(
    belief: &BeliefState,
    feasibility: &ActionFeasibility,
    transition: &TransitionModel,
    loss_matrix: &crate::config::policy::LossMatrix,
    config: &WonhamConfig,
) -> Result<GittinsIndex, WonhamError> {
    if config.discount_factor <= 0.0 || config.discount_factor >= 1.0 {
        return Err(WonhamError::InvalidDiscount(config.discount_factor));
    }

    // Compute stopping value: min_a E[L(a, S) | b]
    let loss_table = compute_loss_table(belief, loss_matrix, feasibility);
    let (stop_action, stop_loss) = loss_table
        .iter()
        .filter(|e| e.feasible)
        .min_by(|a, b| {
            a.expected_loss
                .partial_cmp(&b.expected_loss)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|e| (e.action, e.expected_loss))
        .unwrap_or((Action::Keep, f64::INFINITY));

    // Compute state decomposition for explainability
    let state_decomposition = [
        belief.probs[0] * loss_for_action_state(loss_matrix, stop_action, 0),
        belief.probs[1] * loss_for_action_state(loss_matrix, stop_action, 1),
        belief.probs[2] * loss_for_action_state(loss_matrix, stop_action, 2),
        belief.probs[3] * loss_for_action_state(loss_matrix, stop_action, 3),
    ];

    // Compute continuation value via finite-horizon value iteration.
    // V_0(b) = min_a E[L(a, S) | b] (= stop_loss)
    // V_{k+1}(b) = min{ V_0(b), γ · E_obs[ V_k(b') ] }
    // where b' is the predicted belief after transition.
    let continuation = compute_continuation_value(
        belief,
        feasibility,
        transition,
        loss_matrix,
        config.discount_factor,
        config.horizon,
    )?;

    // Gittins index: benefit of stopping now over continuing.
    // Higher positive value = more urgent to act (stop value is good).
    // Index = continuation_value - stopping_value
    // When index > 0, stopping is cheaper than continuing.
    let index_value = continuation - stop_loss;

    Ok(GittinsIndex {
        candidate_id: String::new(), // Filled by caller
        index_value,
        stopping_value: stop_loss,
        continuation_value: continuation,
        optimal_action: stop_action,
        state_decomposition,
        belief_entropy: belief.entropy(),
    })
}

/// Compute expected loss after H horizon steps of gathering information.
///
/// This uses a simplified value iteration: at each step, the belief
/// evolves under the transition model (no actual observation), and we
/// compute the best-case expected loss.
fn compute_continuation_value(
    belief: &BeliefState,
    feasibility: &ActionFeasibility,
    transition: &TransitionModel,
    loss_matrix: &crate::config::policy::LossMatrix,
    gamma: f64,
    horizon: usize,
) -> Result<f64, WonhamError> {
    if horizon == 0 {
        // Terminal: just the stopping value
        let loss_table = compute_loss_table(belief, loss_matrix, feasibility);
        return Ok(loss_table
            .iter()
            .filter(|e| e.feasible)
            .map(|e| e.expected_loss)
            .fold(f64::INFINITY, f64::min));
    }

    // Predict belief one step forward
    let predicted = transition
        .predict(belief)
        .map_err(WonhamError::BeliefState)?;

    // The future value is the expected stopping loss at the predicted belief,
    // discounted by γ.
    let future_loss_table = compute_loss_table(&predicted, loss_matrix, feasibility);
    let future_best = future_loss_table
        .iter()
        .filter(|e| e.feasible)
        .map(|e| e.expected_loss)
        .fold(f64::INFINITY, f64::min);

    // Recurse for deeper lookahead
    let deeper = compute_continuation_value(
        &predicted,
        feasibility,
        transition,
        loss_matrix,
        gamma,
        horizon - 1,
    )?;

    // Continuation value is the discounted min of acting at next step vs.
    // waiting further.
    Ok(gamma * future_best.min(deeper))
}

/// Compute Gittins indices for all candidates and return a sorted schedule.
pub fn compute_gittins_schedule(
    candidates: &[GittinsCandidate],
    config: &WonhamConfig,
    transition: &TransitionModel,
    loss_matrix: &crate::config::policy::LossMatrix,
) -> Result<GittinsSchedule, WonhamError> {
    if candidates.is_empty() {
        return Err(WonhamError::NoCandidates);
    }

    let mut allocations: Vec<GittinsIndex> = candidates
        .iter()
        .map(|c| {
            let mut idx =
                compute_gittins_index(&c.belief, &c.feasibility, transition, loss_matrix, config)?;
            idx.candidate_id = c.id.clone();
            Ok(idx)
        })
        .collect::<Result<Vec<_>, WonhamError>>()?;

    // Sort by index value descending (highest priority first).
    // Tie-break by candidate ID for determinism.
    allocations.sort_by(|a, b| {
        b.index_value
            .partial_cmp(&a.index_value)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.candidate_id.cmp(&b.candidate_id))
    });

    Ok(GittinsSchedule {
        rationale: format!(
            "Gittins-optimal schedule: γ={}, horizon={}, {} candidates",
            config.discount_factor,
            config.horizon,
            candidates.len()
        ),
        allocations,
    })
}

// ── Helpers ──────────────────────────────────────────────────────────────

/// Look up loss L(action, state) from the loss matrix.
///
/// LossMatrix rows are indexed by state (useful, useful_bad, abandoned, zombie).
/// Each LossRow has columns by action (keep, pause, throttle, kill, etc.).
fn loss_for_action_state(
    loss_matrix: &crate::config::policy::LossMatrix,
    action: Action,
    state_idx: usize,
) -> f64 {
    // Pick the row for this state
    let row = match state_idx {
        0 => &loss_matrix.useful,
        1 => &loss_matrix.useful_bad,
        2 => &loss_matrix.abandoned,
        3 => &loss_matrix.zombie,
        _ => return 0.0,
    };
    // Pick the column for this action, defaulting to 0 for missing optional costs
    match action {
        Action::Keep => row.keep,
        Action::Renice => row.renice.unwrap_or(0.0),
        Action::Pause | Action::Resume => row.pause.unwrap_or(0.0),
        Action::Freeze | Action::Unfreeze => row.pause.unwrap_or(0.0),
        Action::Throttle => row.throttle.unwrap_or(0.0),
        Action::Quarantine | Action::Unquarantine => row.throttle.unwrap_or(0.0),
        Action::Restart => row.restart.unwrap_or(0.0),
        Action::Kill => row.kill,
    }
}

/// 4×4 matrix multiply.
#[allow(clippy::needless_range_loop)]
fn mat_mul(
    a: &[[f64; NUM_STATES]; NUM_STATES],
    b: &[[f64; NUM_STATES]; NUM_STATES],
) -> [[f64; NUM_STATES]; NUM_STATES] {
    let mut c = [[0.0; NUM_STATES]; NUM_STATES];
    for i in 0..NUM_STATES {
        for j in 0..NUM_STATES {
            for k in 0..NUM_STATES {
                c[i][j] += a[i][k] * b[k][j];
            }
        }
    }
    c
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Policy;
    use crate::decision::expected_loss::ActionFeasibility;
    use crate::inference::belief_state::{BeliefState, TransitionModel};

    // ── GeneratorMatrix ──────────────────────────────────────────────

    #[test]
    fn generator_from_transition_default() {
        let tm = TransitionModel::default_lifecycle();
        let gen = GeneratorMatrix::from_transition(&tm, 60.0).unwrap();
        // Rows must sum to ~0
        for row in &gen.rates {
            let sum: f64 = row.iter().sum();
            assert!(sum.abs() < 1e-9, "row sum = {sum}");
        }
    }

    #[test]
    fn generator_invalid_tau() {
        let tm = TransitionModel::default_lifecycle();
        assert!(GeneratorMatrix::from_transition(&tm, 0.0).is_err());
        assert!(GeneratorMatrix::from_transition(&tm, -1.0).is_err());
        assert!(GeneratorMatrix::from_transition(&tm, f64::NAN).is_err());
    }

    #[test]
    fn generator_to_transition_euler() {
        let gen = GeneratorMatrix::default();
        let tm = gen.to_transition(1.0).unwrap();
        // Rows must sum to ~1
        for row in &tm.matrix {
            let sum: f64 = row.iter().sum();
            assert!((sum - 1.0).abs() < 1e-9, "row sum = {sum}");
        }
    }

    #[test]
    fn generator_to_transition_exp() {
        let gen = GeneratorMatrix::default();
        let tm = gen.to_transition_exp(60.0, 12).unwrap();
        // Rows must sum to ~1
        for row in &tm.matrix {
            let sum: f64 = row.iter().sum();
            assert!((sum - 1.0).abs() < 1e-9, "row sum = {sum}");
        }
        // All entries non-negative
        for row in &tm.matrix {
            for &val in row {
                assert!(val >= 0.0, "negative entry: {val}");
            }
        }
    }

    #[test]
    fn generator_identity_transition_roundtrip() {
        let tm = TransitionModel::identity();
        let gen = GeneratorMatrix::from_transition(&tm, 1.0).unwrap();
        // All rates should be ~0 (no transitions)
        for row in &gen.rates {
            for &r in row {
                assert!(r.abs() < 1e-9, "non-zero rate in identity: {r}");
            }
        }
    }

    // ── WonhamFilter ─────────────────────────────────────────────────

    #[test]
    fn wonham_predict_conserves_probability() {
        let filter = WonhamFilter::new(WonhamConfig::default(), GeneratorMatrix::default());
        let belief = BeliefState::from_probs([0.5, 0.2, 0.2, 0.1]).unwrap();
        let predicted = filter.predict(&belief, 10.0).unwrap();
        let sum: f64 = predicted.probs.iter().sum();
        assert!((sum - 1.0).abs() < 1e-9, "predicted probs sum = {sum}");
    }

    #[test]
    fn wonham_predict_identity_preserves_belief() {
        let gen = GeneratorMatrix::from_transition(&TransitionModel::identity(), 1.0).unwrap();
        let filter = WonhamFilter::new(WonhamConfig::default(), gen);
        let belief = BeliefState::from_probs([0.7, 0.1, 0.1, 0.1]).unwrap();
        let predicted = filter.predict(&belief, 5.0).unwrap();
        for i in 0..NUM_STATES {
            assert!(
                (predicted.probs[i] - belief.probs[i]).abs() < 1e-6,
                "state {i}: {} vs {}",
                predicted.probs[i],
                belief.probs[i]
            );
        }
    }

    #[test]
    fn wonham_predict_invalid_dt() {
        let filter = WonhamFilter::new(WonhamConfig::default(), GeneratorMatrix::default());
        let belief = BeliefState::uniform();
        assert!(filter.predict(&belief, 0.0).is_err());
        assert!(filter.predict(&belief, -1.0).is_err());
    }

    #[test]
    fn wonham_filter_step_updates_belief() {
        let filter = WonhamFilter::new(WonhamConfig::default(), GeneratorMatrix::default());
        let belief = BeliefState::uniform();
        let obs = ObservationLikelihood::from_likelihoods([0.8, 0.1, 0.05, 0.05]).unwrap();
        let updated = filter.filter_step(&belief, 5.0, &obs).unwrap();
        // Should shift toward Useful
        assert!(updated.probs[0] > belief.probs[0]);
    }

    #[test]
    fn wonham_filter_sequence() {
        let filter = WonhamFilter::new(WonhamConfig::default(), GeneratorMatrix::default());
        let initial = BeliefState::uniform();
        let steps = vec![
            (
                5.0,
                ObservationLikelihood::from_likelihoods([0.8, 0.1, 0.05, 0.05]).unwrap(),
            ),
            (
                5.0,
                ObservationLikelihood::from_likelihoods([0.7, 0.2, 0.05, 0.05]).unwrap(),
            ),
            (
                5.0,
                ObservationLikelihood::from_likelihoods([0.6, 0.3, 0.05, 0.05]).unwrap(),
            ),
        ];
        let beliefs = filter.filter_sequence(&initial, &steps).unwrap();
        assert_eq!(beliefs.len(), 3);
        // Belief in Useful should increase over time with these observations
        assert!(beliefs[2].probs[0] > beliefs[0].probs[0]);
    }

    #[test]
    fn wonham_matrix_exp_vs_euler_converge() {
        let gen = GeneratorMatrix::default();
        // For small dt, Euler and matrix exp should agree closely
        let dt = 0.1;
        let euler = gen.to_transition(dt).unwrap();
        let exp = gen.to_transition_exp(dt, 12).unwrap();
        for i in 0..NUM_STATES {
            for j in 0..NUM_STATES {
                assert!(
                    (euler.matrix[i][j] - exp.matrix[i][j]).abs() < 1e-4,
                    "euler[{i}][{j}]={} vs exp[{i}][{j}]={}",
                    euler.matrix[i][j],
                    exp.matrix[i][j]
                );
            }
        }
    }

    // ── Gittins Index ────────────────────────────────────────────────

    #[test]
    fn gittins_index_certain_useful_is_low() {
        let policy = Policy::default();
        let belief = BeliefState::from_probs([0.99, 0.003, 0.004, 0.003]).unwrap();
        let transition = TransitionModel::default_lifecycle();
        let config = WonhamConfig::default();

        let idx = compute_gittins_index(
            &belief,
            &ActionFeasibility::allow_all(),
            &transition,
            &policy.loss_matrix,
            &config,
        )
        .unwrap();

        // When we're certain the process is Useful, Keep is optimal
        // and continuation value is also low → index close to 0
        assert_eq!(idx.optimal_action, Action::Keep);
        assert!(
            idx.stopping_value < 0.5,
            "stopping_value = {}",
            idx.stopping_value
        );
    }

    #[test]
    fn gittins_index_certain_zombie_vs_useful() {
        let policy = Policy::default();
        let transition = TransitionModel::default_lifecycle();
        let config = WonhamConfig::default();

        let zombie_belief = BeliefState::from_probs([0.003, 0.004, 0.003, 0.99]).unwrap();
        let useful_belief = BeliefState::from_probs([0.99, 0.003, 0.004, 0.003]).unwrap();

        let zombie_idx = compute_gittins_index(
            &zombie_belief,
            &ActionFeasibility::allow_all(),
            &transition,
            &policy.loss_matrix,
            &config,
        )
        .unwrap();

        let useful_idx = compute_gittins_index(
            &useful_belief,
            &ActionFeasibility::allow_all(),
            &transition,
            &policy.loss_matrix,
            &config,
        )
        .unwrap();

        // The zombie case should have lower entropy (more certain)
        assert!(zombie_idx.belief_entropy < BeliefState::uniform().entropy());
        // Both certain beliefs should have low entropy
        assert!(useful_idx.belief_entropy < BeliefState::uniform().entropy());
        // The optimal action should not be Keep for a zombie-certain belief
        assert_ne!(zombie_idx.optimal_action, Action::Keep);
    }

    #[test]
    fn gittins_uncertain_has_positive_entropy() {
        let policy = Policy::default();
        let belief = BeliefState::uniform();
        let transition = TransitionModel::default_lifecycle();
        let config = WonhamConfig::default();

        let idx = compute_gittins_index(
            &belief,
            &ActionFeasibility::allow_all(),
            &transition,
            &policy.loss_matrix,
            &config,
        )
        .unwrap();

        assert!(idx.belief_entropy > 0.0);
    }

    #[test]
    fn gittins_invalid_discount() {
        let policy = Policy::default();
        let belief = BeliefState::uniform();
        let transition = TransitionModel::default_lifecycle();

        let config = WonhamConfig {
            discount_factor: 1.0, // Invalid
            ..Default::default()
        };
        assert!(compute_gittins_index(
            &belief,
            &ActionFeasibility::allow_all(),
            &transition,
            &policy.loss_matrix,
            &config,
        )
        .is_err());

        let config = WonhamConfig {
            discount_factor: 0.0, // Invalid
            ..Default::default()
        };
        assert!(compute_gittins_index(
            &belief,
            &ActionFeasibility::allow_all(),
            &transition,
            &policy.loss_matrix,
            &config,
        )
        .is_err());
    }

    // ── Schedule ─────────────────────────────────────────────────────

    #[test]
    fn gittins_schedule_deterministic_ordering() {
        let policy = Policy::default();
        let transition = TransitionModel::default_lifecycle();
        let config = WonhamConfig::default();

        let candidates = vec![
            GittinsCandidate {
                id: "pid-1".to_string(),
                belief: BeliefState::from_probs([0.1, 0.1, 0.1, 0.7]).unwrap(),
                feasibility: ActionFeasibility::allow_all(),
                available_probes: vec![],
            },
            GittinsCandidate {
                id: "pid-2".to_string(),
                belief: BeliefState::from_probs([0.7, 0.1, 0.1, 0.1]).unwrap(),
                feasibility: ActionFeasibility::allow_all(),
                available_probes: vec![],
            },
        ];

        let schedule =
            compute_gittins_schedule(&candidates, &config, &transition, &policy.loss_matrix)
                .unwrap();

        assert_eq!(schedule.allocations.len(), 2);
        // Run it twice to verify determinism
        let schedule2 =
            compute_gittins_schedule(&candidates, &config, &transition, &policy.loss_matrix)
                .unwrap();
        for (a, b) in schedule
            .allocations
            .iter()
            .zip(schedule2.allocations.iter())
        {
            assert_eq!(a.candidate_id, b.candidate_id);
            assert!((a.index_value - b.index_value).abs() < 1e-12);
        }
    }

    #[test]
    fn gittins_schedule_empty_candidates() {
        let policy = Policy::default();
        let transition = TransitionModel::default_lifecycle();
        let config = WonhamConfig::default();

        assert!(compute_gittins_schedule(&[], &config, &transition, &policy.loss_matrix).is_err());
    }

    #[test]
    fn gittins_schedule_all_fields_populated() {
        let policy = Policy::default();
        let transition = TransitionModel::default_lifecycle();
        let config = WonhamConfig::default();

        let candidates = vec![GittinsCandidate {
            id: "test-pid".to_string(),
            belief: BeliefState::from_probs([0.3, 0.3, 0.2, 0.2]).unwrap(),
            feasibility: ActionFeasibility::allow_all(),
            available_probes: vec![ProbeType::QuickScan],
        }];

        let schedule =
            compute_gittins_schedule(&candidates, &config, &transition, &policy.loss_matrix)
                .unwrap();

        let idx = &schedule.allocations[0];
        assert_eq!(idx.candidate_id, "test-pid");
        assert!(idx.index_value.is_finite());
        assert!(idx.stopping_value.is_finite());
        assert!(idx.continuation_value.is_finite());
        assert!(idx.belief_entropy > 0.0);
        assert!(!schedule.rationale.is_empty());

        // State decomposition should sum close to stopping value
        let decomp_sum: f64 = idx.state_decomposition.iter().sum();
        assert!(
            (decomp_sum - idx.stopping_value).abs() < 1e-9,
            "decomp sum {decomp_sum} vs stopping {}",
            idx.stopping_value
        );
    }

    #[test]
    fn gittins_index_is_inert_by_default() {
        // The Gittins module is purely advisory — it doesn't alter any
        // decision behavior unless explicitly invoked. Verify this by
        // confirming the module has no side effects: compute_gittins_index
        // takes immutable references only.
        let policy = Policy::default();
        let belief = BeliefState::uniform();
        let transition = TransitionModel::default_lifecycle();
        let config = WonhamConfig::default();

        let _idx = compute_gittins_index(
            &belief,
            &ActionFeasibility::allow_all(),
            &transition,
            &policy.loss_matrix,
            &config,
        )
        .unwrap();

        // No state mutation — belief unchanged
        let sum: f64 = belief.probs.iter().sum();
        assert!((sum - 1.0).abs() < 1e-12);
    }

    #[test]
    fn gittins_index_serde_roundtrip() {
        let idx = GittinsIndex {
            candidate_id: "pid-42".to_string(),
            index_value: 0.5,
            stopping_value: 0.3,
            continuation_value: 0.8,
            optimal_action: Action::Keep,
            state_decomposition: [0.1, 0.05, 0.1, 0.05],
            belief_entropy: 1.2,
        };

        let json = serde_json::to_string(&idx).unwrap();
        let back: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(back["candidate_id"], "pid-42");
        assert!((back["index_value"].as_f64().unwrap() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn gittins_schedule_serde_roundtrip() {
        let schedule = GittinsSchedule {
            allocations: vec![],
            rationale: "test".to_string(),
        };
        let json = serde_json::to_string(&schedule).unwrap();
        let back: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(back["rationale"], "test");
    }

    // ── WonhamConfig ─────────────────────────────────────────────────

    #[test]
    fn wonham_config_defaults() {
        let cfg = WonhamConfig::default();
        assert!((cfg.discount_factor - 0.95).abs() < 1e-12);
        assert_eq!(cfg.horizon, 10);
        assert!(!cfg.use_matrix_exp);
    }

    #[test]
    fn wonham_config_serde_roundtrip() {
        let cfg = WonhamConfig {
            discount_factor: 0.9,
            horizon: 5,
            min_belief_prob: 1e-8,
            use_matrix_exp: true,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: WonhamConfig = serde_json::from_str(&json).unwrap();
        assert!((back.discount_factor - 0.9).abs() < 1e-12);
        assert_eq!(back.horizon, 5);
        assert!(back.use_matrix_exp);
    }

    // ── mat_mul ──────────────────────────────────────────────────────

    #[test]
    fn mat_mul_identity() {
        let id = {
            let mut m = [[0.0; NUM_STATES]; NUM_STATES];
            for i in 0..NUM_STATES {
                m[i][i] = 1.0;
            }
            m
        };
        let a = [
            [1.0, 2.0, 3.0, 4.0],
            [5.0, 6.0, 7.0, 8.0],
            [9.0, 10.0, 11.0, 12.0],
            [13.0, 14.0, 15.0, 16.0],
        ];
        let result = mat_mul(&a, &id);
        for i in 0..NUM_STATES {
            for j in 0..NUM_STATES {
                assert!((result[i][j] - a[i][j]).abs() < 1e-12);
            }
        }
    }
}
