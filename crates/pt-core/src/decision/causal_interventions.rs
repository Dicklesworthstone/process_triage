//! Causal intervention outcome models (Beta-Bernoulli).

use crate::config::priors::{BetaParams, CausalInterventions, InterventionPriors, Priors};
use crate::decision::Action;
use crate::inference::ClassScores;
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

/// Expected recovery probability for an action.
#[derive(Debug, Clone, Serialize)]
pub struct RecoveryExpectation {
    pub action: Action,
    pub probability: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub std_dev: Option<f64>,
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

/// Observed intervention outcome used to update priors.
#[derive(Debug, Clone, Serialize)]
pub struct InterventionOutcome {
    pub action: Action,
    pub class: ProcessClass,
    pub recovered: bool,
    /// Optional weight for aggregated observations (defaults to 1.0 in callers).
    pub weight: f64,
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
pub fn update_beta(params: &BetaParams, successes: f64, trials: f64, eta: f64) -> BetaParams {
    let n = trials.max(0.0);
    let s = successes.max(0.0).min(n);
    let eta = if eta.is_finite() && eta > 0.0 {
        eta
    } else {
        1.0
    };
    BetaParams {
        alpha: params.alpha + eta * s,
        beta: params.beta + eta * (n - s),
        comment: None,
    }
}

/// Apply an observed outcome to causal intervention priors.
pub fn apply_outcome(
    interventions: &CausalInterventions,
    outcome: &InterventionOutcome,
    eta: f64,
) -> CausalInterventions {
    let mut updated = interventions.clone();
    let target = match outcome.action {
        Action::Pause => &mut updated.pause,
        Action::Throttle => &mut updated.throttle,
        Action::Kill => &mut updated.kill,
        Action::Restart => &mut updated.restart,
        Action::Keep
        | Action::Renice
        | Action::Resume
        | Action::Freeze
        | Action::Unfreeze
        | Action::Quarantine
        | Action::Unquarantine => {
            return updated; // No causal priors yet
        }
    };
    if let Some(priors) = target.as_ref() {
        let refreshed = update_intervention_priors(priors, outcome, eta);
        *target = Some(refreshed);
    }
    updated
}

/// Apply a batch of outcomes to priors, returning updated priors.
pub fn apply_outcomes(priors: &Priors, outcomes: &[InterventionOutcome], eta: f64) -> Priors {
    let mut updated = priors.clone();
    let Some(interventions) = priors.causal_interventions.as_ref() else {
        return updated;
    };
    let mut current = interventions.clone();
    for outcome in outcomes {
        current = apply_outcome(&current, outcome, eta);
    }
    updated.causal_interventions = Some(current);
    updated
}

/// Get per-class recovery table for an action if configured.
pub fn recovery_table(priors: &Priors, action: Action) -> Option<RecoveryTable> {
    let interventions = priors.causal_interventions.as_ref()?;
    let table = match action {
        Action::Pause => build_table(action, interventions.pause.as_ref()),
        Action::Throttle => build_table(action, interventions.throttle.as_ref()),
        Action::Kill => build_table(action, interventions.kill.as_ref()),
        Action::Restart => build_table(action, interventions.restart.as_ref()),
        Action::Keep
        | Action::Renice
        | Action::Resume
        | Action::Freeze
        | Action::Unfreeze
        | Action::Quarantine
        | Action::Unquarantine => None,
    };
    table
}

/// Compute expected recovery probability for an action given the class posterior.
pub fn expected_recovery_for_action(
    priors: &Priors,
    posterior: &ClassScores,
    action: Action,
) -> Option<f64> {
    expected_recovery_stats_for_action(priors, posterior, action).map(|stats| stats.0)
}

/// Compute expected recovery probabilities for all configured actions.
pub fn expected_recovery_by_action(
    priors: &Priors,
    posterior: &ClassScores,
) -> Vec<RecoveryExpectation> {
    let actions = [
        Action::Pause,
        Action::Throttle,
        Action::Restart,
        Action::Kill,
    ];
    let mut expectations = Vec::new();
    for action in actions {
        if let Some((probability, std_dev)) =
            expected_recovery_stats_for_action(priors, posterior, action)
        {
            expectations.push(RecoveryExpectation {
                action,
                probability,
                std_dev,
            });
        }
    }
    expectations
}

/// Get expected recovery probability for a specific action/class.
pub fn recovery_for_class(priors: &Priors, action: Action, class: ProcessClass) -> Option<f64> {
    let interventions = priors.causal_interventions.as_ref()?;
    let priors = match action {
        Action::Pause => interventions.pause.as_ref(),
        Action::Throttle => interventions.throttle.as_ref(),
        Action::Kill => interventions.kill.as_ref(),
        Action::Restart => interventions.restart.as_ref(),
        Action::Keep
        | Action::Renice
        | Action::Resume
        | Action::Freeze
        | Action::Unfreeze
        | Action::Quarantine
        | Action::Unquarantine => None,
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

fn beta_variance(beta: &BetaParams) -> Option<f64> {
    let denom = beta.alpha + beta.beta;
    if denom <= 0.0 || !denom.is_finite() {
        return None;
    }
    let numerator = beta.alpha * beta.beta;
    let variance = numerator / (denom * denom * (denom + 1.0));
    if variance.is_finite() {
        Some(variance)
    } else {
        None
    }
}

fn expected_recovery_stats_for_action(
    priors: &Priors,
    posterior: &ClassScores,
    action: Action,
) -> Option<(f64, Option<f64>)> {
    let table = recovery_table(priors, action)?;
    let useful = table.useful?;
    let useful_bad = table.useful_bad?;
    let abandoned = table.abandoned?;
    let zombie = table.zombie?;

    let mean = posterior.useful * useful
        + posterior.useful_bad * useful_bad
        + posterior.abandoned * abandoned
        + posterior.zombie * zombie;

    let interventions = priors.causal_interventions.as_ref()?;
    let priors = match action {
        Action::Pause => interventions.pause.as_ref(),
        Action::Throttle => interventions.throttle.as_ref(),
        Action::Kill => interventions.kill.as_ref(),
        Action::Restart => interventions.restart.as_ref(),
        Action::Keep
        | Action::Renice
        | Action::Resume
        | Action::Freeze
        | Action::Unfreeze
        | Action::Quarantine
        | Action::Unquarantine => None,
    }?;

    let useful_var = priors.useful.as_ref().and_then(beta_variance);
    let useful_bad_var = priors.useful_bad.as_ref().and_then(beta_variance);
    let abandoned_var = priors.abandoned.as_ref().and_then(beta_variance);
    let zombie_var = priors.zombie.as_ref().and_then(beta_variance);

    let std_dev = match (useful_var, useful_bad_var, abandoned_var, zombie_var) {
        (Some(u_var), Some(ub_var), Some(a_var), Some(z_var)) => {
            let second_moment = posterior.useful * (u_var + useful * useful)
                + posterior.useful_bad * (ub_var + useful_bad * useful_bad)
                + posterior.abandoned * (a_var + abandoned * abandoned)
                + posterior.zombie * (z_var + zombie * zombie);
            let mut variance: f64 = second_moment - mean * mean;
            if variance < 0.0 && variance > -1e-12 {
                variance = 0.0;
            }
            if variance >= 0.0 {
                Some(variance.sqrt())
            } else {
                None
            }
        }
        _ => None,
    };

    Some((mean, std_dev))
}

fn update_intervention_priors(
    priors: &InterventionPriors,
    outcome: &InterventionOutcome,
    eta: f64,
) -> InterventionPriors {
    let successes = if outcome.recovered {
        outcome.weight.max(0.0)
    } else {
        0.0
    };
    let trials = outcome.weight.max(0.0);
    let updated = |value: &Option<BetaParams>| {
        value
            .as_ref()
            .map(|beta| update_beta(beta, successes, trials, eta))
    };
    match outcome.class {
        ProcessClass::Useful => InterventionPriors {
            useful: updated(&priors.useful),
            useful_bad: priors.useful_bad.clone(),
            abandoned: priors.abandoned.clone(),
            zombie: priors.zombie.clone(),
        },
        ProcessClass::UsefulBad => InterventionPriors {
            useful: priors.useful.clone(),
            useful_bad: updated(&priors.useful_bad),
            abandoned: priors.abandoned.clone(),
            zombie: priors.zombie.clone(),
        },
        ProcessClass::Abandoned => InterventionPriors {
            useful: priors.useful.clone(),
            useful_bad: priors.useful_bad.clone(),
            abandoned: updated(&priors.abandoned),
            zombie: priors.zombie.clone(),
        },
        ProcessClass::Zombie => InterventionPriors {
            useful: priors.useful.clone(),
            useful_bad: priors.useful_bad.clone(),
            abandoned: priors.abandoned.clone(),
            zombie: updated(&priors.zombie),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::priors::{ClassParams, ClassPriors, GammaParams};
    use crate::inference::ClassScores;

    #[test]
    fn expected_recovery_matches_mean() {
        let beta = BetaParams {
            alpha: 2.0,
            beta: 6.0,
            comment: None,
        };
        assert!((expected_recovery(&beta) - 0.25).abs() <= 1e-12);
    }

    #[test]
    fn update_beta_applies_eta() {
        let beta = BetaParams {
            alpha: 1.0,
            beta: 1.0,
            comment: None,
        };
        let updated = update_beta(&beta, 3.0, 5.0, 1.0);
        assert!((updated.alpha - 4.0).abs() <= 1e-12);
        assert!((updated.beta - 3.0).abs() <= 1e-12);
    }

    #[test]
    fn update_beta_clamps_successes_to_trials() {
        let beta = BetaParams {
            alpha: 1.0,
            beta: 1.0,
            comment: None,
        };
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
            classes: ClassPriors {
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

    #[test]
    fn expected_recovery_for_action_combines_posteriors() {
        let priors = Priors {
            schema_version: "1.0.0".to_string(),
            description: None,
            created_at: None,
            updated_at: None,
            host_profile: None,
            classes: ClassPriors {
                useful: default_class(),
                useful_bad: default_class(),
                abandoned: default_class(),
                zombie: default_class(),
            },
            hazard_regimes: vec![],
            semi_markov: None,
            change_point: None,
            causal_interventions: Some(CausalInterventions {
                pause: Some(InterventionPriors {
                    useful: Some(BetaParams {
                        alpha: 9.0,
                        beta: 1.0,
                        comment: None,
                    }),
                    useful_bad: Some(BetaParams {
                        alpha: 1.0,
                        beta: 1.0,
                        comment: None,
                    }),
                    abandoned: Some(BetaParams {
                        alpha: 2.0,
                        beta: 6.0,
                        comment: None,
                    }),
                    zombie: Some(BetaParams {
                        alpha: 1.0,
                        beta: 9.0,
                        comment: None,
                    }),
                }),
                throttle: None,
                kill: None,
                restart: None,
            }),
            command_categories: None,
            state_flags: None,
            hierarchical: None,
            robust_bayes: None,
            error_rate: None,
            bocpd: None,
        };
        let posterior = ClassScores {
            useful: 0.5,
            useful_bad: 0.2,
            abandoned: 0.2,
            zombie: 0.1,
        };
        let expected =
            expected_recovery_for_action(&priors, &posterior, Action::Pause).expect("recovery");
        let manual = 0.5 * 0.9 + 0.2 * 0.5 + 0.2 * (2.0 / 8.0) + 0.1 * 0.1;
        assert!((expected - manual).abs() <= 1e-12);
    }

    #[test]
    fn expected_recovery_by_action_includes_std_dev() {
        let priors = Priors {
            schema_version: "1.0.0".to_string(),
            description: None,
            created_at: None,
            updated_at: None,
            host_profile: None,
            classes: ClassPriors {
                useful: default_class(),
                useful_bad: default_class(),
                abandoned: default_class(),
                zombie: default_class(),
            },
            hazard_regimes: vec![],
            semi_markov: None,
            change_point: None,
            causal_interventions: Some(CausalInterventions {
                pause: Some(InterventionPriors {
                    useful: Some(BetaParams {
                        alpha: 2.0,
                        beta: 2.0,
                        comment: None,
                    }),
                    useful_bad: Some(BetaParams {
                        alpha: 2.0,
                        beta: 2.0,
                        comment: None,
                    }),
                    abandoned: Some(BetaParams {
                        alpha: 2.0,
                        beta: 2.0,
                        comment: None,
                    }),
                    zombie: Some(BetaParams {
                        alpha: 2.0,
                        beta: 2.0,
                        comment: None,
                    }),
                }),
                throttle: None,
                kill: None,
                restart: None,
            }),
            command_categories: None,
            state_flags: None,
            hierarchical: None,
            robust_bayes: None,
            error_rate: None,
            bocpd: None,
        };
        let posterior = ClassScores {
            useful: 0.25,
            useful_bad: 0.25,
            abandoned: 0.25,
            zombie: 0.25,
        };
        let expectations = expected_recovery_by_action(&priors, &posterior);
        let pause = expectations
            .iter()
            .find(|e| e.action == Action::Pause)
            .expect("pause");
        assert!(pause.std_dev.is_some());
    }

    #[test]
    fn apply_outcome_updates_matching_class() {
        let interventions = CausalInterventions {
            pause: Some(InterventionPriors {
                useful: Some(BetaParams::new(1.0, 1.0)),
                useful_bad: None,
                abandoned: None,
                zombie: None,
            }),
            throttle: None,
            kill: None,
            restart: None,
        };
        let outcome = InterventionOutcome {
            action: Action::Pause,
            class: ProcessClass::Useful,
            recovered: true,
            weight: 1.0,
        };
        let updated = apply_outcome(&interventions, &outcome, 1.0);
        let updated_beta = updated.pause.and_then(|p| p.useful).expect("beta");
        assert!((updated_beta.alpha - 2.0).abs() <= 1e-12);
        assert!((updated_beta.beta - 1.0).abs() <= 1e-12);
    }

    #[test]
    fn apply_outcomes_updates_priors() {
        let priors = Priors {
            schema_version: "1.0.0".to_string(),
            description: None,
            created_at: None,
            updated_at: None,
            host_profile: None,
            classes: ClassPriors {
                useful: default_class(),
                useful_bad: default_class(),
                abandoned: default_class(),
                zombie: default_class(),
            },
            hazard_regimes: vec![],
            semi_markov: None,
            change_point: None,
            causal_interventions: Some(CausalInterventions {
                pause: Some(InterventionPriors {
                    useful: Some(BetaParams::new(1.0, 1.0)),
                    useful_bad: None,
                    abandoned: None,
                    zombie: None,
                }),
                throttle: None,
                kill: None,
                restart: None,
            }),
            command_categories: None,
            state_flags: None,
            hierarchical: None,
            robust_bayes: None,
            error_rate: None,
            bocpd: None,
        };
        let outcomes = vec![
            // Pause
            InterventionOutcome {
                action: Action::Pause,
                class: ProcessClass::Useful,
                recovered: true,
                weight: 1.0,
            },
            // Throttle
            InterventionOutcome {
                action: Action::Throttle,
                class: ProcessClass::Useful,
                recovered: false,
                weight: 1.0,
            },
            // Kill
            InterventionOutcome {
                action: Action::Kill,
                class: ProcessClass::Useful,
                recovered: false,
                weight: 1.0,
            },
            // Restart
            InterventionOutcome {
                action: Action::Restart,
                class: ProcessClass::Useful,
                recovered: false,
                weight: 1.0,
            },
        ];
        let updated = apply_outcomes(&priors, &outcomes, 1.0);
        let updated_beta = updated
            .causal_interventions
            .and_then(|c| c.pause)
            .and_then(|p| p.useful)
            .expect("beta");
        assert!((updated_beta.alpha - 2.0).abs() <= 1e-12);
        assert!((updated_beta.beta - 1.0).abs() <= 1e-12);
    }

    fn default_class() -> ClassParams {
        ClassParams {
            prior_prob: 0.25,
            cpu_beta: BetaParams {
                alpha: 1.0,
                beta: 1.0,
                comment: None,
            },
            runtime_gamma: Some(GammaParams {
                shape: 1.0,
                rate: 1.0,
                comment: None,
            }),
            orphan_beta: BetaParams {
                alpha: 1.0,
                beta: 1.0,
                comment: None,
            },
            tty_beta: BetaParams {
                alpha: 1.0,
                beta: 1.0,
                comment: None,
            },
            net_beta: BetaParams {
                alpha: 1.0,
                beta: 1.0,
                comment: None,
            },
            io_active_beta: None,
            hazard_gamma: None,
            competing_hazards: None,
        }
    }
}
