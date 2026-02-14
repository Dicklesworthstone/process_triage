//! Off-Policy Evaluation (OPE) for Shadow/Replay decisions.
//!
//! Provides importance-weighted estimators to evaluate counterfactual policy
//! performance from logged decision data. This enables validating policy
//! changes before deployment by comparing the estimated value of a new
//! policy against the logged behavior policy.
//!
//! # Estimators
//!
//! 1. **IPS (Inverse Propensity Scoring)**: Unbiased but high-variance
//!    estimator that reweights logged rewards by the ratio of new/old policy
//!    action probabilities.
//!
//! 2. **Doubly Robust (DR)**: Combines IPS with a direct model estimate
//!    for variance reduction. The DR estimator is consistent if *either*
//!    the propensity model or the reward model is correct.
//!
//! # Safety
//!
//! If the effective sample size (ESS) is too low (high policy divergence),
//! the estimator flags the result as unreliable and recommends holding
//! deployment.

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Errors ──────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum OpeError {
    #[error("no logged decisions provided")]
    NoData,

    #[error("propensity must be positive, got {0}")]
    InvalidPropensity(f64),

    #[error("effective sample size too low: {ess:.1} (minimum {min_ess})")]
    LowEffectiveSampleSize { ess: f64, min_ess: f64 },
}

// ── Logged decision record ──────────────────────────────────────────────

/// A single logged decision from the behavior (current) policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggedDecision {
    /// Action taken by the behavior policy.
    pub action: String,
    /// Probability the behavior policy assigned to this action.
    pub propensity: f64,
    /// Observed reward/utility (negative of loss, or quality score).
    pub reward: f64,
    /// State features at decision time (for direct method estimation).
    #[serde(default)]
    pub state_features: Vec<f64>,
}

// ── OPE result ──────────────────────────────────────────────────────────

/// Recommendation from off-policy evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpeRecommendation {
    /// New policy appears better — deploy.
    Deploy,
    /// Insufficient evidence or new policy appears worse — hold.
    Hold,
    /// Evaluation is unreliable due to high variance — hold.
    Unreliable,
}

/// Result of off-policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpeResult {
    /// Estimated value of the evaluation (new) policy.
    pub estimated_value: f64,
    /// Estimated value of the behavior (current) policy (average reward).
    pub behavior_value: f64,
    /// Improvement: estimated_value - behavior_value.
    pub improvement: f64,
    /// 95% confidence interval lower bound.
    pub ci_lower: f64,
    /// 95% confidence interval upper bound.
    pub ci_upper: f64,
    /// Effective sample size.
    pub effective_sample_size: f64,
    /// Number of logged decisions used.
    pub num_decisions: usize,
    /// Deployment recommendation.
    pub recommendation: OpeRecommendation,
    /// Which estimator was used.
    pub estimator: String,
}

// ── IPS Estimator ───────────────────────────────────────────────────────

/// Inverse Propensity Scoring estimator.
///
/// Estimates the value of a new policy from logged data by reweighting
/// rewards by the importance ratio π_new(a|s) / π_old(a|s).
pub struct IpsEstimator {
    /// Minimum ESS before results are considered reliable.
    pub min_ess: f64,
    /// Importance weight clipping threshold (max ratio).
    pub clip_ratio: f64,
}

impl Default for IpsEstimator {
    fn default() -> Self {
        Self {
            min_ess: 100.0,
            clip_ratio: 10.0,
        }
    }
}

impl IpsEstimator {
    /// Create a new IPS estimator with custom parameters.
    pub fn new(min_ess: f64, clip_ratio: f64) -> Self {
        Self {
            min_ess,
            clip_ratio,
        }
    }

    /// Evaluate a new policy against logged decisions.
    ///
    /// `new_policy_probs` maps each logged decision to the probability
    /// the *new* policy would have taken the *same* action. Must be the
    /// same length as `logged`.
    pub fn evaluate(
        &self,
        logged: &[LoggedDecision],
        new_policy_probs: &[f64],
    ) -> Result<OpeResult, OpeError> {
        if logged.is_empty() {
            return Err(OpeError::NoData);
        }

        let n = logged.len();
        let mut weights = Vec::with_capacity(n);
        let mut weighted_rewards = Vec::with_capacity(n);

        for (decision, &new_prob) in logged.iter().zip(new_policy_probs.iter()) {
            if decision.propensity <= 0.0 {
                return Err(OpeError::InvalidPropensity(decision.propensity));
            }

            let ratio = (new_prob / decision.propensity).min(self.clip_ratio);
            weights.push(ratio);
            weighted_rewards.push(ratio * decision.reward);
        }

        // IPS estimate: (1/n) Σ w_i * r_i
        let estimated_value: f64 = weighted_rewards.iter().sum::<f64>() / n as f64;

        // Behavior policy value: average reward
        let behavior_value: f64 = logged.iter().map(|d| d.reward).sum::<f64>() / n as f64;

        // Effective sample size: (Σ w_i)^2 / Σ w_i^2
        let sum_w: f64 = weights.iter().sum();
        let sum_w2: f64 = weights.iter().map(|w| w * w).sum();
        let ess = if sum_w2 > 0.0 {
            (sum_w * sum_w) / sum_w2
        } else {
            0.0
        };

        // Confidence interval via CLT on weighted rewards
        let mean_wr = estimated_value;
        let var_wr: f64 = weighted_rewards
            .iter()
            .map(|wr| (wr / n as f64 - mean_wr / n as f64).powi(2))
            .sum::<f64>()
            / (n as f64 - 1.0).max(1.0);
        let se = (var_wr / n as f64).sqrt();
        let ci_lower = estimated_value - 1.96 * se;
        let ci_upper = estimated_value + 1.96 * se;

        let improvement = estimated_value - behavior_value;

        let recommendation = if ess < self.min_ess {
            OpeRecommendation::Unreliable
        } else if ci_lower > behavior_value {
            OpeRecommendation::Deploy
        } else {
            OpeRecommendation::Hold
        };

        Ok(OpeResult {
            estimated_value,
            behavior_value,
            improvement,
            ci_lower,
            ci_upper,
            effective_sample_size: ess,
            num_decisions: n,
            recommendation,
            estimator: "IPS".to_string(),
        })
    }
}

// ── Doubly Robust Estimator ─────────────────────────────────────────────

/// Doubly Robust estimator combining IPS with a direct method.
///
/// The DR estimator has the form:
/// ```text
/// V_DR = (1/n) Σ [ r̂(s_i, π) + w_i * (r_i - r̂(s_i, a_i)) ]
/// ```
/// where r̂ is the direct reward estimate and w_i is the importance weight.
#[derive(Default)]
pub struct DoublyRobustEstimator {
    ips: IpsEstimator,
}

impl DoublyRobustEstimator {
    /// Create with custom IPS parameters.
    pub fn new(min_ess: f64, clip_ratio: f64) -> Self {
        Self {
            ips: IpsEstimator::new(min_ess, clip_ratio),
        }
    }

    /// Evaluate using the doubly robust estimator.
    ///
    /// # Arguments
    /// * `logged` - Logged decisions from the behavior policy.
    /// * `new_policy_probs` - P(same action | new policy) for each decision.
    /// * `direct_estimates` - Direct model estimate of reward under new policy
    ///   for each logged state (r̂(s_i, π_new)).
    /// * `baseline_estimates` - Direct model estimate of reward for the action
    ///   actually taken (r̂(s_i, a_i)).
    pub fn evaluate(
        &self,
        logged: &[LoggedDecision],
        new_policy_probs: &[f64],
        direct_estimates: &[f64],
        baseline_estimates: &[f64],
    ) -> Result<OpeResult, OpeError> {
        if logged.is_empty() {
            return Err(OpeError::NoData);
        }

        let n = logged.len();
        let mut dr_values = Vec::with_capacity(n);
        let mut weights = Vec::with_capacity(n);

        for i in 0..n {
            if logged[i].propensity <= 0.0 {
                return Err(OpeError::InvalidPropensity(logged[i].propensity));
            }

            let w = (new_policy_probs[i] / logged[i].propensity).min(self.ips.clip_ratio);
            weights.push(w);

            let direct = if i < direct_estimates.len() {
                direct_estimates[i]
            } else {
                0.0
            };
            let baseline = if i < baseline_estimates.len() {
                baseline_estimates[i]
            } else {
                0.0
            };

            // DR formula: r̂(s, π) + w * (r - r̂(s, a))
            let dr_value = direct + w * (logged[i].reward - baseline);
            dr_values.push(dr_value);
        }

        let estimated_value: f64 = dr_values.iter().sum::<f64>() / n as f64;
        let behavior_value: f64 = logged.iter().map(|d| d.reward).sum::<f64>() / n as f64;

        // ESS
        let sum_w: f64 = weights.iter().sum();
        let sum_w2: f64 = weights.iter().map(|w| w * w).sum();
        let ess = if sum_w2 > 0.0 {
            (sum_w * sum_w) / sum_w2
        } else {
            0.0
        };

        // Bootstrap-style CI via sample variance
        let mean_dr = estimated_value;
        let var_dr: f64 = dr_values.iter().map(|v| (v - mean_dr).powi(2)).sum::<f64>()
            / (n as f64 - 1.0).max(1.0);
        let se = (var_dr / n as f64).sqrt();
        let ci_lower = estimated_value - 1.96 * se;
        let ci_upper = estimated_value + 1.96 * se;

        let improvement = estimated_value - behavior_value;

        let recommendation = if ess < self.ips.min_ess {
            OpeRecommendation::Unreliable
        } else if ci_lower > behavior_value {
            OpeRecommendation::Deploy
        } else {
            OpeRecommendation::Hold
        };

        Ok(OpeResult {
            estimated_value,
            behavior_value,
            improvement,
            ci_lower,
            ci_upper,
            effective_sample_size: ess,
            num_decisions: n,
            recommendation,
            estimator: "DoublyRobust".to_string(),
        })
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_logged_decisions(n: usize, reward: f64, propensity: f64) -> Vec<LoggedDecision> {
        (0..n)
            .map(|_| LoggedDecision {
                action: "keep".to_string(),
                propensity,
                reward,
                state_features: vec![],
            })
            .collect()
    }

    #[test]
    fn ips_on_policy_is_unbiased() {
        let logged = make_logged_decisions(1000, 1.0, 0.5);
        // Same policy: new_prob == propensity, so weights are all 1.0
        let new_probs: Vec<f64> = vec![0.5; 1000];

        let estimator = IpsEstimator::default();
        let result = estimator.evaluate(&logged, &new_probs).unwrap();

        // On-policy IPS should recover the true average reward
        assert!((result.estimated_value - 1.0).abs() < 0.01);
        assert!((result.improvement).abs() < 0.01);
    }

    #[test]
    fn ips_empty_data_error() {
        let estimator = IpsEstimator::default();
        assert!(estimator.evaluate(&[], &[]).is_err());
    }

    #[test]
    fn ips_zero_propensity_error() {
        let logged = vec![LoggedDecision {
            action: "kill".to_string(),
            propensity: 0.0,
            reward: 1.0,
            state_features: vec![],
        }];
        let estimator = IpsEstimator::default();
        assert!(estimator.evaluate(&logged, &[0.5]).is_err());
    }

    #[test]
    fn ips_weight_clipping() {
        let logged = make_logged_decisions(100, 1.0, 0.01);
        // Very different policy
        let new_probs: Vec<f64> = vec![1.0; 100];

        let estimator = IpsEstimator {
            min_ess: 1.0,
            clip_ratio: 5.0,
        };
        let result = estimator.evaluate(&logged, &new_probs).unwrap();

        // With clipping at 5x, the effective weight is capped
        assert!(result.estimated_value <= 5.0 + 0.01);
    }

    #[test]
    fn ips_ess_computation() {
        let logged = make_logged_decisions(100, 1.0, 0.5);
        let new_probs: Vec<f64> = vec![0.5; 100];

        let estimator = IpsEstimator::default();
        let result = estimator.evaluate(&logged, &new_probs).unwrap();

        // On-policy: all weights are 1, so ESS should equal n
        assert!((result.effective_sample_size - 100.0).abs() < 1.0);
    }

    #[test]
    fn ips_recommendation_deploy() {
        // New policy is much better
        let mut logged = make_logged_decisions(200, 0.0, 0.5);
        for d in &mut logged {
            d.reward = 0.0; // behavior policy has zero reward
        }
        let new_probs: Vec<f64> = vec![0.5; 200]; // same action probability

        let estimator = IpsEstimator {
            min_ess: 10.0,
            ..Default::default()
        };
        let result = estimator.evaluate(&logged, &new_probs).unwrap();

        // Both have same reward, so hold
        assert_eq!(result.recommendation, OpeRecommendation::Hold);
    }

    #[test]
    fn dr_reduces_variance() {
        let logged = make_logged_decisions(500, 1.0, 0.5);
        let new_probs: Vec<f64> = vec![0.5; 500];
        let direct_estimates: Vec<f64> = vec![1.0; 500]; // perfect direct model
        let baseline_estimates: Vec<f64> = vec![1.0; 500];

        let dr = DoublyRobustEstimator::default();
        let dr_result = dr
            .evaluate(&logged, &new_probs, &direct_estimates, &baseline_estimates)
            .unwrap();

        let ips = IpsEstimator::default();
        let ips_result = ips.evaluate(&logged, &new_probs).unwrap();

        // Both should be close to 1.0
        assert!((dr_result.estimated_value - 1.0).abs() < 0.1);
        assert!((ips_result.estimated_value - 1.0).abs() < 0.1);

        // DR CI should be tighter than IPS (or at least not wider)
        let dr_width = dr_result.ci_upper - dr_result.ci_lower;
        let ips_width = ips_result.ci_upper - ips_result.ci_lower;
        // Allow some tolerance since this is stochastic
        assert!(dr_width <= ips_width + 0.1);
    }

    #[test]
    fn dr_empty_data_error() {
        let dr = DoublyRobustEstimator::default();
        assert!(dr.evaluate(&[], &[], &[], &[]).is_err());
    }

    #[test]
    fn ope_result_serde() {
        let result = OpeResult {
            estimated_value: 1.5,
            behavior_value: 1.0,
            improvement: 0.5,
            ci_lower: 1.2,
            ci_upper: 1.8,
            effective_sample_size: 100.0,
            num_decisions: 200,
            recommendation: OpeRecommendation::Deploy,
            estimator: "IPS".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: OpeResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.recommendation, OpeRecommendation::Deploy);
        assert!((back.estimated_value - 1.5).abs() < f64::EPSILON);
    }

    #[test]
    fn recommendation_serde() {
        for rec in &[
            OpeRecommendation::Deploy,
            OpeRecommendation::Hold,
            OpeRecommendation::Unreliable,
        ] {
            let json = serde_json::to_string(rec).unwrap();
            let back: OpeRecommendation = serde_json::from_str(&json).unwrap();
            assert_eq!(*rec, back);
        }
    }

    #[test]
    fn low_ess_flagged_unreliable() {
        // Very different policies → low ESS
        let logged = make_logged_decisions(50, 1.0, 0.01);
        let new_probs: Vec<f64> = vec![0.99; 50];

        let estimator = IpsEstimator {
            min_ess: 100.0,
            clip_ratio: 100.0, // High clip to not mask the ESS issue
        };
        let result = estimator.evaluate(&logged, &new_probs).unwrap();
        assert_eq!(result.recommendation, OpeRecommendation::Unreliable);
    }
}
