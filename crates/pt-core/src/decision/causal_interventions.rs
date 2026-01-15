//! Causal intervention outcome models (Beta-Bernoulli).

use crate::config::priors::{BetaParams, InterventionPriors, Priors};
use crate::decision::Action;
use serde::Serialize;

/// Process class labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessClass {
    Useful,
    UsefulBad,
    Abandoned,
    Zombie,
}

/// Expected recovery probability per class for an action.
#[derive(Debug, Clone, Serialize)]
pub struct RecoveryTable {
    pub action: Action,
    pub useful: Option<f64>,
    pub useful_bad: Option<f64>,
    pub abandoned: Option<f64>,
    pub zombie: Option<f64>,
}

/// Compute expected recovery probability from a Beta prior.
pub fn expected_recovery(beta: &BetaParams) -> f64 {
    let denom = beta.alpha + beta.beta;
    if denom <= 0.0 {
        return f64::NAN;
    }
    beta.alpha / denom
}

/// Update Beta parameters with observed outcomes.
pub fn update_beta(
    params: &BetaParams,
    successes: f64,
    trials: f64,
    eta: f64,
) -> BetaParams {
    let n = trials.max(0.0);
    let s = successes.max(0.0).min(n);
    let eta = if eta.is_finite() && eta > 0.0 { eta.min(1.0) } else { 1.0 };
    BetaParams {
        alpha: params.alpha + eta * s,
        beta: params.beta + eta * (n - s),
    }
}

/// Get per-class recovery table for an action if configured.
pub fn recovery_table(priors: &Priors, action: Action) -> Option<RecoveryTable> {
    let interventions = priors.causal_interventions.as_ref()?;
    let table = match action {
        Action::Pause => build_table(action, interventions.pause.as_ref()),
        Action::Throttle => build_table(action, interventions.throttle.as_ref()),
        Action::Kill => build_table(action, interventions.kill.as_ref()),
        Action::Restart => build_table(action, interventions.restart.as_ref()),
        Action::Keep => None,
    };
    table
}

/// Get expected recovery probability for a specific action/class.
pub fn recovery_for_class(
    priors: &Priors,
    action: Action,
    class: ProcessClass,
) -> Option<f64> {
    let interventions = priors.causal_interventions.as_ref()?;
    let priors = match action {
        Action::Pause => interventions.pause.as_ref(),
        Action::Throttle => interventions.throttle.as_ref(),
        Action::Kill => interventions.kill.as_ref(),
        Action::Restart => interventions.restart.as_ref(),
        Action::Keep => None,
    }?;
    let beta = match class {
        ProcessClass::Useful => priors.useful.as_ref(),
        ProcessClass::UsefulBad => priors.useful_bad.as_ref(),
        ProcessClass::Abandoned => priors.abandoned.as_ref(),
        ProcessClass::Zombie => priors.zombie.as_ref(),
    }?;
    Some(expected_recovery(beta))
}

fn build_table(action: Action, priors: Option<&InterventionPriors>) -> Option<RecoveryTable> {
    let priors = priors?;
    Some(RecoveryTable {
        action,
        useful: priors.useful.as_ref().map(expected_recovery),
        useful_bad: priors.useful_bad.as_ref().map(expected_recovery),
        abandoned: priors.abandoned.as_ref().map(expected_recovery),
        zombie: priors.zombie.as_ref().map(expected_recovery),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::priors::{Classes, ClassPriors, GammaParams};

    #[test]
    fn expected_recovery_matches_mean() {
        let beta = BetaParams { alpha: 2.0, beta: 6.0 };
        assert!((expected_recovery(&beta) - 0.25).abs() <= 1e-12);
    }

    #[test]
    fn update_beta_applies_eta() {
        let beta = BetaParams { alpha: 1.0, beta: 1.0 };
        let updated = update_beta(&beta, 3.0, 5.0, 1.0);
        assert!((updated.alpha - 4.0).abs() <= 1e-12);
        assert!((updated.beta - 3.0).abs() <= 1e-12);
    }

    #[test]
    fn update_beta_clamps_successes_to_trials() {
        let beta = BetaParams { alpha: 1.0, beta: 1.0 };
        let updated = update_beta(&beta, 10.0, 2.0, 1.0);
        assert!((updated.alpha - 3.0).abs() <= 1e-12);
        assert!((updated.beta - 1.0).abs() <= 1e-12);
    }

    #[test]
    fn recovery_table_returns_none_without_priors() {
        let priors = Priors {
            schema_version: "1.0.0".to_string(),
            description: None,
            created_at: None,
            updated_at: None,
            host_profile: None,
            classes: Classes {
                useful: default_class(),
                useful_bad: default_class(),
                abandoned: default_class(),
                zombie: default_class(),
            },
            hazard_regimes: vec![],
            semi_markov: None,
            change_point: None,
            causal_interventions: None,
            command_categories: None,
            state_flags: None,
            hierarchical: None,
            robust_bayes: None,
            error_rate: None,
            bocpd: None,
        };
        assert!(recovery_table(&priors, Action::Pause).is_none());
    }

    fn default_class() -> ClassPriors {
        ClassPriors {
            prior_prob: 0.25,
            cpu_beta: BetaParams { alpha: 1.0, beta: 1.0 },
            runtime_gamma: Some(GammaParams { shape: 1.0, rate: 1.0 }),
            orphan_beta: BetaParams { alpha: 1.0, beta: 1.0 },
            tty_beta: BetaParams { alpha: 1.0, beta: 1.0 },
            net_beta: BetaParams { alpha: 1.0, beta: 1.0 },
            io_active_beta: None,
            hazard_gamma: None,
            competing_hazards: None,
        }
    }
}
