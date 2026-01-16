//! Time-to-decision bound utilities (T_max).
//!
//! Computes a stopping time based on VOI decay and overhead budgets, and
//! provides a conservative fallback action when uncertainty persists.

use crate::config::policy::DecisionTimeBound;
use crate::decision::expected_loss::Action;
use serde::{Deserialize, Serialize};

/// Input for computing T_max.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TMaxInput {
    /// Initial VOI estimate at time zero.
    pub voi_initial: f64,
    /// Optional override for overhead budget (seconds).
    pub overhead_budget_seconds: Option<u64>,
}

/// Output of T_max computation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TMaxDecision {
    pub t_max_seconds: u64,
    pub budget_seconds: u64,
    pub voi_decay_half_life_seconds: u64,
    pub voi_floor: f64,
    pub reason: String,
}

/// Output when applying the time bound to an in-flight decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeBoundOutcome {
    pub stop_probing: bool,
    pub fallback_action: Option<Action>,
    pub reason: String,
}

/// Compute the time-to-decision bound T_max.
pub fn compute_t_max(config: &DecisionTimeBound, input: &TMaxInput) -> TMaxDecision {
    let budget = input
        .overhead_budget_seconds
        .unwrap_or(config.overhead_budget_seconds)
        .max(1);

    let voi_initial = input.voi_initial.max(0.0);
    let voi_floor = config.voi_floor.max(0.0);
    let half_life = config.voi_decay_half_life_seconds.max(1) as f64;

    let t_voi = if voi_floor <= 0.0 {
        config.max_seconds as f64
    } else if voi_initial <= voi_floor {
        0.0
    } else {
        half_life * (voi_initial / voi_floor).log2()
    };

    let t_voi_sec = t_voi.ceil().max(0.0) as u64;
    let base = config.min_seconds.max(t_voi_sec);
    let t_max = base.min(config.max_seconds).min(budget);

    TMaxDecision {
        t_max_seconds: t_max,
        budget_seconds: budget,
        voi_decay_half_life_seconds: config.voi_decay_half_life_seconds,
        voi_floor: config.voi_floor,
        reason: format!(
            "T_max set to {}s (min={}, max={}, budget={}, voi_half_life={}, voi_floor={})",
            t_max,
            config.min_seconds,
            config.max_seconds,
            budget,
            config.voi_decay_half_life_seconds,
            config.voi_floor
        ),
    }
}

/// Apply the time bound to an in-flight decision.
pub fn apply_time_bound(
    config: &DecisionTimeBound,
    elapsed_seconds: u64,
    t_max_seconds: u64,
    is_uncertain: bool,
) -> TimeBoundOutcome {
    if !config.enabled {
        return TimeBoundOutcome {
            stop_probing: false,
            fallback_action: None,
            reason: "time bound disabled".to_string(),
        };
    }

    if elapsed_seconds < t_max_seconds {
        return TimeBoundOutcome {
            stop_probing: false,
            fallback_action: None,
            reason: format!("elapsed {}s < T_max {}s", elapsed_seconds, t_max_seconds),
        };
    }

    let fallback_action = if is_uncertain {
        Some(resolve_fallback_action(config))
    } else {
        None
    };

    TimeBoundOutcome {
        stop_probing: true,
        fallback_action,
        reason: format!(
            "elapsed {}s >= T_max {}s; {}",
            elapsed_seconds,
            t_max_seconds,
            if is_uncertain {
                "fallback action applied"
            } else {
                "decision confident; no fallback"
            }
        ),
    }
}

/// Resolve the fallback action from policy.
pub fn resolve_fallback_action(config: &DecisionTimeBound) -> Action {
    match config.fallback_action.as_str() {
        "keep" => Action::Keep,
        "renice" => Action::Renice,
        "pause" => Action::Pause,
        "freeze" => Action::Freeze,
        "throttle" => Action::Throttle,
        "quarantine" => Action::Quarantine,
        _ => Action::Pause,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> DecisionTimeBound {
        DecisionTimeBound {
            enabled: true,
            min_seconds: 60,
            max_seconds: 600,
            voi_decay_half_life_seconds: 120,
            voi_floor: 0.01,
            overhead_budget_seconds: 180,
            fallback_action: "pause".to_string(),
        }
    }

    #[test]
    fn test_t_max_respects_budget() {
        let cfg = config();
        let input = TMaxInput {
            voi_initial: 1.0,
            overhead_budget_seconds: Some(90),
        };
        let decision = compute_t_max(&cfg, &input);
        assert!(decision.t_max_seconds <= 90);
    }

    #[test]
    fn test_apply_time_bound_fallback() {
        let cfg = config();
        let input = TMaxInput {
            voi_initial: 0.5,
            overhead_budget_seconds: Some(120),
        };
        let tmax = compute_t_max(&cfg, &input);
        let outcome = apply_time_bound(&cfg, tmax.t_max_seconds, tmax.t_max_seconds, true);
        assert!(outcome.stop_probing);
        assert_eq!(outcome.fallback_action, Some(Action::Pause));
    }

    #[test]
    fn test_fallback_action_mapping() {
        let mut cfg = config();
        cfg.fallback_action = "throttle".to_string();
        assert_eq!(resolve_fallback_action(&cfg), Action::Throttle);
    }
}
