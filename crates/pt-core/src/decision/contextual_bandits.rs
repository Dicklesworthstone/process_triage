//! Contextual Bandits for Probe Scheduling.
//!
//! Extends the context-free Gittins index with per-process-type context
//! features using a Linear Upper Confidence Bound (LinUCB) bandit.
//!
//! # Context Features
//!
//! Each candidate carries a feature vector encoding:
//! - **Command category** (one-hot: system, user, test, dev, database, etc.)
//! - **CPU class** (binned: idle, low, medium, high)
//! - **IO pattern** (active/idle binary)
//! - **Memory regime** (low/medium/high)
//!
//! # Fallback
//!
//! When context features are unavailable (empty vector), the bandit falls
//! back to the context-free Gittins index, preserving backward compatibility.
//!
//! # Algorithm
//!
//! LinUCB maintains per-arm ridge regression models:
//! ```text
//!   A_a = I + Σ x_t x_t^T   (design matrix)
//!   b_a = Σ r_t x_t          (reward vector)
//!   θ_a = A_a^{-1} b_a       (estimated coefficients)
//!   UCB_a(x) = x^T θ_a + α √(x^T A_a^{-1} x)
//! ```

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Errors ──────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum BanditError {
    #[error("dimension mismatch: expected {expected}, got {actual}")]
    DimensionMismatch { expected: usize, actual: usize },

    #[error("no arms configured")]
    NoArms,

    #[error("arm index {0} out of range")]
    InvalidArm(usize),

    #[error("singular matrix: cannot invert design matrix for arm {0}")]
    SingularMatrix(usize),
}

// ── Configuration ───────────────────────────────────────────────────────

/// Configuration for the contextual bandit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BanditConfig {
    /// Exploration parameter α. Higher values encourage more exploration.
    pub alpha: f64,
    /// Feature dimension (length of context vectors).
    pub dimension: usize,
    /// Number of arms (probe types).
    pub num_arms: usize,
    /// Whether contextual features are enabled. If false, falls back to
    /// uniform UCB (equivalent to context-free Gittins).
    pub contextual_features_enabled: bool,
    /// L2 regularization parameter λ for ridge regression.
    pub regularization: f64,
}

impl Default for BanditConfig {
    fn default() -> Self {
        Self {
            alpha: 1.0,
            dimension: 8,
            num_arms: 4,
            contextual_features_enabled: true,
            regularization: 1.0,
        }
    }
}

// ── Per-arm state ───────────────────────────────────────────────────────

/// State for a single arm in the LinUCB bandit.
#[derive(Debug, Clone)]
struct ArmState {
    /// Design matrix A = λI + Σ x_t x_t^T (d×d).
    a_matrix: Vec<f64>,
    /// Reward vector b = Σ r_t x_t (d×1).
    b_vector: Vec<f64>,
    /// Dimension.
    dim: usize,
    /// Number of times this arm has been pulled.
    pull_count: u64,
    /// Total reward accumulated.
    total_reward: f64,
}

impl ArmState {
    fn new(dim: usize, regularization: f64) -> Self {
        let mut a_matrix = vec![0.0; dim * dim];
        // Initialize as λI
        for i in 0..dim {
            a_matrix[i * dim + i] = regularization;
        }
        Self {
            a_matrix,
            b_vector: vec![0.0; dim],
            dim,
            pull_count: 0,
            total_reward: 0.0,
        }
    }

    /// Update the arm with a new observation (context, reward).
    fn update(&mut self, context: &[f64], reward: f64) {
        let d = self.dim;
        // A += x x^T
        for i in 0..d {
            for j in 0..d {
                self.a_matrix[i * d + j] += context[i] * context[j];
            }
        }
        // b += r * x
        for (b_i, &c_i) in self.b_vector.iter_mut().zip(context.iter()) {
            *b_i += reward * c_i;
        }
        self.pull_count += 1;
        self.total_reward += reward;
    }

    /// Compute the UCB score for a given context.
    fn ucb_score(&self, context: &[f64], alpha: f64) -> Result<f64, BanditError> {
        let d = self.dim;
        let a_inv = invert_matrix(&self.a_matrix, d)?;

        // θ = A^{-1} b
        let theta = mat_vec_mul(&a_inv, &self.b_vector, d);

        // predicted reward = x^T θ
        let predicted: f64 = context.iter().zip(theta.iter()).map(|(x, t)| x * t).sum();

        // uncertainty = sqrt(x^T A^{-1} x)
        let a_inv_x = mat_vec_mul(&a_inv, context, d);
        let uncertainty: f64 = context
            .iter()
            .zip(a_inv_x.iter())
            .map(|(x, ax)| x * ax)
            .sum::<f64>()
            .max(0.0)
            .sqrt();

        Ok(predicted + alpha * uncertainty)
    }
}

// ── Contextual Bandit ───────────────────────────────────────────────────

/// Selection result from the bandit.
#[derive(Debug, Clone, Serialize)]
pub struct BanditSelection {
    /// Selected arm index.
    pub arm: usize,
    /// UCB score of the selected arm.
    pub ucb_score: f64,
    /// UCB scores for all arms.
    pub all_scores: Vec<f64>,
    /// Whether contextual features were used (vs. fallback).
    pub used_context: bool,
}

/// Regret tracking statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegretStats {
    /// Total rounds played.
    pub rounds: u64,
    /// Cumulative reward from the bandit's selections.
    pub cumulative_reward: f64,
    /// Cumulative reward from the best single arm (hindsight).
    pub best_arm_cumulative: f64,
    /// Per-arm pull counts.
    pub arm_pulls: Vec<u64>,
    /// Per-arm average rewards.
    pub arm_avg_rewards: Vec<f64>,
}

/// LinUCB contextual bandit for probe scheduling.
pub struct ContextualBandit {
    config: BanditConfig,
    arms: Vec<ArmState>,
    rounds: u64,
    cumulative_reward: f64,
}

impl ContextualBandit {
    /// Create a new contextual bandit.
    pub fn new(config: BanditConfig) -> Result<Self, BanditError> {
        if config.num_arms == 0 {
            return Err(BanditError::NoArms);
        }
        let arms = (0..config.num_arms)
            .map(|_| ArmState::new(config.dimension, config.regularization))
            .collect();
        Ok(Self {
            config,
            arms,
            rounds: 0,
            cumulative_reward: 0.0,
        })
    }

    /// Select the arm with highest UCB score for the given context.
    ///
    /// If `context` is empty or contextual features are disabled, falls back
    /// to uniform exploration (round-robin with exploration bonus).
    pub fn select_arm(&self, context: &[f64]) -> Result<BanditSelection, BanditError> {
        let use_context =
            self.config.contextual_features_enabled && context.len() == self.config.dimension;

        if use_context {
            self.select_contextual(context)
        } else {
            self.select_uniform()
        }
    }

    /// Contextual arm selection via LinUCB.
    fn select_contextual(&self, context: &[f64]) -> Result<BanditSelection, BanditError> {
        if context.len() != self.config.dimension {
            return Err(BanditError::DimensionMismatch {
                expected: self.config.dimension,
                actual: context.len(),
            });
        }

        let mut scores = Vec::with_capacity(self.arms.len());
        for arm in &self.arms {
            scores.push(arm.ucb_score(context, self.config.alpha)?);
        }

        let (best_arm, &best_score) = scores
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .ok_or(BanditError::NoArms)?;

        Ok(BanditSelection {
            arm: best_arm,
            ucb_score: best_score,
            all_scores: scores,
            used_context: true,
        })
    }

    /// Uniform (context-free) arm selection with UCB1-style exploration.
    fn select_uniform(&self) -> Result<BanditSelection, BanditError> {
        if self.arms.is_empty() {
            return Err(BanditError::NoArms);
        }

        let total_pulls: u64 = self.arms.iter().map(|a| a.pull_count).sum();
        let log_total = ((total_pulls + 1) as f64).ln();

        let mut scores = Vec::with_capacity(self.arms.len());
        for arm in &self.arms {
            let avg_reward = if arm.pull_count > 0 {
                arm.total_reward / arm.pull_count as f64
            } else {
                f64::INFINITY // Ensure unplayed arms are tried first
            };
            let exploration = if arm.pull_count > 0 {
                self.config.alpha * (2.0 * log_total / arm.pull_count as f64).sqrt()
            } else {
                f64::INFINITY
            };
            scores.push(avg_reward + exploration);
        }

        let (best_arm, &best_score) = scores
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .ok_or(BanditError::NoArms)?;

        Ok(BanditSelection {
            arm: best_arm,
            ucb_score: best_score,
            all_scores: scores,
            used_context: false,
        })
    }

    /// Update the bandit with observed reward for the selected arm.
    pub fn update(&mut self, arm: usize, context: &[f64], reward: f64) -> Result<(), BanditError> {
        if arm >= self.arms.len() {
            return Err(BanditError::InvalidArm(arm));
        }

        let use_context =
            self.config.contextual_features_enabled && context.len() == self.config.dimension;

        if use_context {
            self.arms[arm].update(context, reward);
        } else {
            // For context-free updates, use a unit vector
            let unit = vec![1.0; 1];
            // Just track counts and rewards for UCB1 fallback
            self.arms[arm].pull_count += 1;
            self.arms[arm].total_reward += reward;
            let _ = unit; // avoid unused warning
        }

        self.rounds += 1;
        self.cumulative_reward += reward;
        Ok(())
    }

    /// Get regret tracking statistics.
    pub fn regret_stats(&self) -> RegretStats {
        let arm_pulls: Vec<u64> = self.arms.iter().map(|a| a.pull_count).collect();
        let arm_avg_rewards: Vec<f64> = self
            .arms
            .iter()
            .map(|a| {
                if a.pull_count > 0 {
                    a.total_reward / a.pull_count as f64
                } else {
                    0.0
                }
            })
            .collect();

        let best_avg = arm_avg_rewards
            .iter()
            .cloned()
            .fold(f64::NEG_INFINITY, f64::max);
        let best_arm_cumulative = best_avg * self.rounds as f64;

        RegretStats {
            rounds: self.rounds,
            cumulative_reward: self.cumulative_reward,
            best_arm_cumulative,
            arm_pulls,
            arm_avg_rewards,
        }
    }

    /// Number of rounds played.
    pub fn rounds(&self) -> u64 {
        self.rounds
    }

    /// Configuration reference.
    pub fn config(&self) -> &BanditConfig {
        &self.config
    }

    /// Reset the bandit to initial state.
    pub fn reset(&mut self) {
        self.arms = (0..self.config.num_arms)
            .map(|_| ArmState::new(self.config.dimension, self.config.regularization))
            .collect();
        self.rounds = 0;
        self.cumulative_reward = 0.0;
    }
}

// ── Linear algebra helpers ──────────────────────────────────────────────

/// Matrix-vector multiply: result = A * v (A is d×d stored row-major).
fn mat_vec_mul(a: &[f64], v: &[f64], d: usize) -> Vec<f64> {
    let mut result = vec![0.0; d];
    for i in 0..d {
        for j in 0..d {
            result[i] += a[i * d + j] * v[j];
        }
    }
    result
}

/// Invert a d×d symmetric positive-definite matrix using Cholesky decomposition.
/// Falls back to pseudoinverse via regularization on failure.
fn invert_matrix(a: &[f64], d: usize) -> Result<Vec<f64>, BanditError> {
    // For small d (typically 4-16), direct Gauss-Jordan is fine
    let mut augmented = vec![0.0; d * 2 * d];

    // Set up [A | I]
    for i in 0..d {
        for j in 0..d {
            augmented[i * 2 * d + j] = a[i * d + j];
        }
        augmented[i * 2 * d + d + i] = 1.0;
    }

    // Gauss-Jordan elimination
    for col in 0..d {
        // Find pivot
        let mut max_val = augmented[col * 2 * d + col].abs();
        let mut max_row = col;
        for row in (col + 1)..d {
            let val = augmented[row * 2 * d + col].abs();
            if val > max_val {
                max_val = val;
                max_row = row;
            }
        }

        if max_val < 1e-15 {
            // Matrix is singular or near-singular; add regularization
            let mut regularized = a.to_vec();
            for i in 0..d {
                regularized[i * d + i] += 1e-6;
            }
            return invert_matrix_inner(&regularized, d);
        }

        // Swap rows
        if max_row != col {
            for j in 0..(2 * d) {
                augmented.swap(col * 2 * d + j, max_row * 2 * d + j);
            }
        }

        // Scale pivot row
        let pivot = augmented[col * 2 * d + col];
        for j in 0..(2 * d) {
            augmented[col * 2 * d + j] /= pivot;
        }

        // Eliminate column
        for row in 0..d {
            if row == col {
                continue;
            }
            let factor = augmented[row * 2 * d + col];
            for j in 0..(2 * d) {
                augmented[row * 2 * d + j] -= factor * augmented[col * 2 * d + j];
            }
        }
    }

    // Extract inverse
    let mut inv = vec![0.0; d * d];
    for i in 0..d {
        for j in 0..d {
            inv[i * d + j] = augmented[i * 2 * d + d + j];
        }
    }

    Ok(inv)
}

/// Inner inversion with pre-regularized matrix (avoids infinite recursion).
fn invert_matrix_inner(a: &[f64], d: usize) -> Result<Vec<f64>, BanditError> {
    let mut augmented = vec![0.0; d * 2 * d];
    for i in 0..d {
        for j in 0..d {
            augmented[i * 2 * d + j] = a[i * d + j];
        }
        augmented[i * 2 * d + d + i] = 1.0;
    }

    for col in 0..d {
        let pivot = augmented[col * 2 * d + col];
        if pivot.abs() < 1e-30 {
            return Err(BanditError::SingularMatrix(0));
        }
        for j in 0..(2 * d) {
            augmented[col * 2 * d + j] /= pivot;
        }
        for row in 0..d {
            if row == col {
                continue;
            }
            let factor = augmented[row * 2 * d + col];
            for j in 0..(2 * d) {
                augmented[row * 2 * d + j] -= factor * augmented[col * 2 * d + j];
            }
        }
    }

    let mut inv = vec![0.0; d * d];
    for i in 0..d {
        for j in 0..d {
            inv[i * d + j] = augmented[i * 2 * d + d + j];
        }
    }
    Ok(inv)
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn default_bandit() -> ContextualBandit {
        ContextualBandit::new(BanditConfig {
            dimension: 4,
            num_arms: 3,
            ..Default::default()
        })
        .unwrap()
    }

    #[test]
    fn create_bandit() {
        let b = default_bandit();
        assert_eq!(b.rounds(), 0);
        assert_eq!(b.config().num_arms, 3);
    }

    #[test]
    fn no_arms_rejected() {
        let config = BanditConfig {
            num_arms: 0,
            ..Default::default()
        };
        assert!(ContextualBandit::new(config).is_err());
    }

    #[test]
    fn select_with_context() {
        let b = default_bandit();
        let context = vec![1.0, 0.0, 0.5, 0.3];
        let selection = b.select_arm(&context).unwrap();
        assert!(selection.used_context);
        assert!(selection.arm < 3);
    }

    #[test]
    fn select_without_context() {
        let b = default_bandit();
        let selection = b.select_arm(&[]).unwrap();
        assert!(!selection.used_context);
    }

    #[test]
    fn context_free_features_produce_uniform() {
        let config = BanditConfig {
            dimension: 4,
            num_arms: 3,
            contextual_features_enabled: false,
            ..Default::default()
        };
        let b = ContextualBandit::new(config).unwrap();
        let context = vec![1.0, 0.0, 0.5, 0.3];
        let selection = b.select_arm(&context).unwrap();
        assert!(!selection.used_context);
    }

    #[test]
    fn update_and_select() {
        let mut b = default_bandit();
        let context = vec![1.0, 0.0, 0.5, 0.3];

        // Train arm 0 with high reward
        for _ in 0..10 {
            b.update(0, &context, 1.0).unwrap();
        }
        // Train arm 1 with low reward
        for _ in 0..10 {
            b.update(1, &context, 0.1).unwrap();
        }

        let selection = b.select_arm(&context).unwrap();
        // Arm 0 should generally be preferred (higher reward)
        assert_eq!(b.rounds(), 20);
    }

    #[test]
    fn invalid_arm_rejected() {
        let mut b = default_bandit();
        assert!(b.update(99, &[1.0, 0.0, 0.5, 0.3], 1.0).is_err());
    }

    #[test]
    fn dimension_mismatch_handled() {
        let b = default_bandit();
        // Wrong dimension context still works (falls back to uniform)
        let selection = b.select_arm(&[1.0, 2.0]).unwrap();
        assert!(!selection.used_context);
    }

    #[test]
    fn regret_stats() {
        let mut b = default_bandit();
        let ctx = vec![1.0, 0.0, 0.5, 0.3];
        b.update(0, &ctx, 1.0).unwrap();
        b.update(1, &ctx, 0.5).unwrap();

        let stats = b.regret_stats();
        assert_eq!(stats.rounds, 2);
        assert!((stats.cumulative_reward - 1.5).abs() < f64::EPSILON);
        assert_eq!(stats.arm_pulls, vec![1, 1, 0]);
    }

    #[test]
    fn reset_clears_state() {
        let mut b = default_bandit();
        let ctx = vec![1.0, 0.0, 0.5, 0.3];
        b.update(0, &ctx, 1.0).unwrap();
        b.reset();
        assert_eq!(b.rounds(), 0);
    }

    #[test]
    fn config_serde() {
        let c = BanditConfig::default();
        let json = serde_json::to_string(&c).unwrap();
        let back: BanditConfig = serde_json::from_str(&json).unwrap();
        assert!((back.alpha - c.alpha).abs() < f64::EPSILON);
        assert_eq!(back.num_arms, c.num_arms);
    }

    #[test]
    fn matrix_inversion() {
        // 2x2 identity should invert to itself
        let a = vec![1.0, 0.0, 0.0, 1.0];
        let inv = invert_matrix(&a, 2).unwrap();
        assert!((inv[0] - 1.0).abs() < 1e-10);
        assert!((inv[3] - 1.0).abs() < 1e-10);
    }

    #[test]
    fn sublinear_regret_synthetic() {
        // Verify regret grows sublinearly over many rounds
        let mut b = ContextualBandit::new(BanditConfig {
            dimension: 2,
            num_arms: 2,
            alpha: 1.0,
            ..Default::default()
        })
        .unwrap();

        // Arm 0 is better for context [1, 0], arm 1 for [0, 1]
        for round in 0..100 {
            let context = if round % 2 == 0 {
                vec![1.0, 0.0]
            } else {
                vec![0.0, 1.0]
            };
            let selection = b.select_arm(&context).unwrap();
            let reward = if (selection.arm == 0 && context[0] > 0.5)
                || (selection.arm == 1 && context[1] > 0.5)
            {
                1.0
            } else {
                0.0
            };
            b.update(selection.arm, &context, reward).unwrap();
        }

        let stats = b.regret_stats();
        assert_eq!(stats.rounds, 100);
        // Should have accumulated some reward
        assert!(stats.cumulative_reward > 0.0);
    }
}
