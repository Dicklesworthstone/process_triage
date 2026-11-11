//! Process-attributed pressure costs and legacy load multiplier utilities.

use crate::config::policy::{LoadAwareDecision, LossMatrix, LossRow, Policy, PressureLossConfig};
use crate::decision::expected_loss::{
    decide_action, expected_loss_for_action, Action, ActionFeasibility, DecisionError,
    DecisionOutcome, DisabledAction,
};
use crate::decision::pressure_regime::ResourceSeverity;
use crate::inference::ClassScores;
use serde::{Deserialize, Serialize};

/// Shares attributed to the exact process incarnation being considered.
///
/// CPU is windowed CPU cores consumed / observed online CPUs. Memory is RSS /
/// system RAM (not unique reclaimable memory). I/O requires a comparable,
/// same-window denominator. Missing evidence remains `None`, never observed zero.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct ResourceShares {
    pub cpu: Option<f64>,
    pub memory: Option<f64>,
    pub io: Option<f64>,
}

/// Observations supplied by a shared collector, not inferred from process labels.
#[derive(Debug, Clone, Default)]
pub struct PressureContext {
    pub severity: ResourceSeverity,
    pub shares: ResourceShares,
    pub unavailable: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct ResourcePressureCost {
    pub cpu: f64,
    pub memory: f64,
    pub io: f64,
}

impl ResourcePressureCost {
    fn total(self) -> f64 {
        self.cpu + self.memory + self.io
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PressureDecisionStatus {
    Disabled,
    ZeroWeight,
    ZeroPressure,
    NoAttributablePressure,
    Applied,
}

#[derive(Debug, Clone, Serialize)]
pub struct PressureActionCost {
    pub action: Action,
    pub base_loss: Option<f64>,
    pub pressure_cost: f64,
    pub pressure_by_resource: ResourcePressureCost,
    pub adjusted_loss: Option<f64>,
    pub eligible: bool,
    pub excluded_reason: Option<String>,
}

/// Auditable decomposition of the same model used by decisions and probe VOI.
#[derive(Debug, Clone, Serialize)]
pub struct PressureDecisionReport {
    pub enabled: bool,
    pub applied: bool,
    pub changed: bool,
    pub status: PressureDecisionStatus,
    pub scope: &'static str,
    pub severity: ResourceSeverity,
    pub shares: ResourceShares,
    pub model: PressureLossConfig,
    pub evidence_only_action: Action,
    pub chosen_action: Action,
    /// Keep's additive cost, in loss units rather than a probability.
    pub pressure_burden: f64,
    /// Estimated reduction in pressure cost from the chosen action versus Keep.
    pub modeled_pressure_relief: f64,
    pub actions: Vec<PressureActionCost>,
    pub unavailable: Vec<String>,
    pub assumptions: Vec<&'static str>,
}

/// Use these policy and feasibility inputs for subsequent sequential/VOI logic.
/// Recomputing that logic from the original policy would discard pressure costs
/// and, more seriously, its evidence-only destructive-action eligibility gate.
#[derive(Debug, Clone)]
pub struct PressureDecisionInputs {
    pub policy: Policy,
    pub feasibility: ActionFeasibility,
    pub decision: DecisionOutcome,
    pub report: PressureDecisionReport,
}

/// Add a class-independent pressure cost to each action's loss column.
///
/// This leaves class posteriors and evidence-only decisioning unchanged. A Kill
/// or Restart may compete under pressure only when that exact action already
/// won without pressure. Existing feasibility exclusions can only be tightened.
/// Disabled, zero-pressure and unattributable cases return the exact baseline.
pub fn prepare_pressure_decision(
    posterior: &ClassScores,
    policy: &Policy,
    feasibility: &ActionFeasibility,
    context: &PressureContext,
) -> Result<PressureDecisionInputs, DecisionError> {
    let baseline = decide_action(posterior, policy, feasibility)?;
    let evidence_only_action = baseline.optimal_action;
    let context = checked_context(context);
    let model = &policy.load_aware.pressure;
    if policy.load_aware.enabled {
        if let Some((field, message)) = model.validation_error() {
            return Err(DecisionError::InvalidLossMatrix {
                message: format!("load_aware.pressure.{field} {message}"),
            });
        }
    }

    let status = if !policy.load_aware.enabled {
        PressureDecisionStatus::Disabled
    } else if model.kappa == 0.0 {
        PressureDecisionStatus::ZeroWeight
    } else if context.severity.cpu == 0.0
        && context.severity.memory == 0.0
        && context.severity.io == 0.0
    {
        PressureDecisionStatus::ZeroPressure
    } else if pressure_cost(Action::Keep, model, &context).total() == 0.0 {
        PressureDecisionStatus::NoAttributablePressure
    } else {
        PressureDecisionStatus::Applied
    };
    let applied = status == PressureDecisionStatus::Applied;
    let mut adjusted_policy = policy.clone();
    let mut adjusted_feasibility = feasibility.clone();
    let decision = if applied {
        if !pressure_cost(Action::Keep, model, &context)
            .total()
            .is_finite()
        {
            return Err(DecisionError::InvalidLossMatrix {
                message: "additive pressure cost overflowed; reduce load_aware.pressure.kappa"
                    .to_string(),
            });
        }
        for action in [Action::Kill, Action::Restart] {
            if action != evidence_only_action && adjusted_feasibility.is_allowed(action) {
                adjusted_feasibility.disabled.push(DisabledAction {
                    action,
                    reason: format!(
                        "pressure cannot justify {action:?}; evidence-only winner is {evidence_only_action:?}"
                    ),
                });
            }
        }
        for row in [
            &mut adjusted_policy.loss_matrix.useful,
            &mut adjusted_policy.loss_matrix.useful_bad,
            &mut adjusted_policy.loss_matrix.abandoned,
            &mut adjusted_policy.loss_matrix.zombie,
        ] {
            let cost = |action| pressure_cost(action, model, &context).total();
            row.keep += cost(Action::Keep);
            row.renice = row.renice.map(|v| v + cost(Action::Renice));
            row.pause = row.pause.map(|v| v + cost(Action::Pause));
            row.throttle = row.throttle.map(|v| v + cost(Action::Throttle));
            row.cap_memory = row.cap_memory.map(|v| v + cost(Action::CapMemory));
            row.kill += cost(Action::Kill);
            row.restart = row.restart.map(|v| v + cost(Action::Restart));
        }
        decide_action(posterior, &adjusted_policy, &adjusted_feasibility)?
    } else {
        baseline
    };

    let actions = Action::ALL
        .into_iter()
        .map(|action| {
            let by_resource = if applied {
                pressure_cost(action, model, &context)
            } else {
                ResourcePressureCost::default()
            };
            let excluded_reason = decision
                .rationale
                .disabled_actions
                .iter()
                .find(|d| d.action == action)
                .map(|d| d.reason.clone());
            PressureActionCost {
                action,
                base_loss: expected_loss_for_action(action, posterior, &policy.loss_matrix).ok(),
                pressure_cost: by_resource.total(),
                pressure_by_resource: by_resource,
                adjusted_loss: expected_loss_for_action(
                    action,
                    posterior,
                    &adjusted_policy.loss_matrix,
                )
                .ok(),
                eligible: excluded_reason.is_none(),
                excluded_reason,
            }
        })
        .collect();
    let report = PressureDecisionReport {
        enabled: policy.load_aware.enabled,
        applied,
        changed: decision.optimal_action != evidence_only_action,
        status,
        scope: "process",
        severity: context.severity,
        shares: context.shares,
        model: model.clone(),
        evidence_only_action,
        chosen_action: decision.optimal_action,
        pressure_burden: if applied {
            pressure_cost(Action::Keep, model, &context).total()
        } else {
            0.0
        },
        modeled_pressure_relief: if applied {
            pressure_cost(Action::Keep, model, &context).total()
                - pressure_cost(decision.optimal_action, model, &context).total()
        } else {
            0.0
        },
        actions,
        unavailable: context.unavailable,
        assumptions: vec![
            "Relief fractions are policy heuristics, not measured recovery guarantees.",
            "CPU credit covers only the observed process, never its parent, agent, or cgroup peers.",
            "RSS can contain shared pages; it is not a unique reclaimable-memory estimate.",
            "Only an observed owned-leaf memory.high cap receives reversible memory-pressure credit; this is a reclaim heuristic, not promised freed bytes. Pending I/O can outlive a stop.",
        ],
    };
    Ok(PressureDecisionInputs {
        policy: adjusted_policy,
        feasibility: adjusted_feasibility,
        decision,
        report,
    })
}

/// Convenience entry point when no subsequent sequential/VOI decision is needed.
pub fn decide_action_with_pressure(
    posterior: &ClassScores,
    policy: &Policy,
    feasibility: &ActionFeasibility,
    context: &PressureContext,
) -> Result<(DecisionOutcome, PressureDecisionReport), DecisionError> {
    let prepared = prepare_pressure_decision(posterior, policy, feasibility, context)?;
    Ok((prepared.decision, prepared.report))
}

fn pressure_cost(
    action: Action,
    model: &PressureLossConfig,
    context: &PressureContext,
) -> ResourcePressureCost {
    let cpu_relief = match action {
        Action::Renice => model.renice_cpu_relief,
        Action::Pause | Action::Freeze => model.pause_cpu_relief,
        Action::Throttle | Action::Quarantine => model.throttle_cpu_relief,
        Action::Kill => 1.0,
        _ => 0.0,
    };
    let other_relief = if action == Action::Kill { 1.0 } else { 0.0 };
    let memory_relief = if action == Action::CapMemory {
        model.cap_memory_relief
    } else {
        other_relief
    };
    ResourcePressureCost {
        cpu: context.severity.cpu
            * context.shares.cpu.unwrap_or(0.0)
            * (1.0 - cpu_relief)
            * model.kappa,
        memory: context.severity.memory
            * context.shares.memory.unwrap_or(0.0)
            * (1.0 - memory_relief)
            * model.kappa,
        io: context.severity.io
            * context.shares.io.unwrap_or(0.0)
            * (1.0 - other_relief)
            * model.kappa,
    }
}

/// Invalid/missing observations contribute no cost and remain explicit gaps.
/// A broken pressure collector must not prevent evidence-only triage.
fn checked_context(context: &PressureContext) -> PressureContext {
    let mut checked = context.clone();
    for (name, severity, share) in [
        ("cpu", &mut checked.severity.cpu, &mut checked.shares.cpu),
        (
            "memory",
            &mut checked.severity.memory,
            &mut checked.shares.memory,
        ),
        ("io", &mut checked.severity.io, &mut checked.shares.io),
    ] {
        if !severity.is_finite() || !(0.0..=1.0).contains(severity) {
            checked.unavailable.push(format!(
                "{name} severity unavailable: expected a finite value in [0, 1]"
            ));
            *severity = 0.0;
        }
        if share.is_some_and(|value| !value.is_finite() || !(0.0..=1.0).contains(&value)) {
            *share = None;
            checked.unavailable.push(format!(
                "{name} attribution invalid: expected a finite process share in [0, 1]"
            ));
        }
        if share.is_none() {
            checked.unavailable.push(format!(
                "{name} attribution unavailable; no {name} pressure cost applied"
            ));
        }
    }
    if !checked.severity.fd.is_finite() || !(0.0..=1.0).contains(&checked.severity.fd) {
        checked.severity.fd = 0.0;
        checked
            .unavailable
            .push("fd severity unavailable: invalid observation".to_string());
    } else if checked.severity.fd > 0.0 {
        checked.unavailable.push(
            "fd attribution and action relief unavailable; no fd pressure cost applied".to_string(),
        );
    }
    checked
}

/// Observed system signals used to compute load score.
#[derive(Debug, Clone)]
pub struct LoadSignals {
    pub queue_len: usize,
    pub load1: Option<f64>,
    pub cores: Option<u32>,
    pub memory_used_fraction: Option<f64>,
    pub psi_avg10: Option<f64>,
}

/// Computed adjustment derived from load signals.
#[derive(Debug, Clone)]
pub struct LoadAdjustment {
    pub load_score: f64,
    pub keep_multiplier: f64,
    pub reversible_multiplier: f64,
    pub risky_multiplier: f64,
}

impl LoadSignals {
    /// Build load signals from system_state JSON and queue length.
    pub fn from_system_state(system_state: &serde_json::Value, queue_len: usize) -> Self {
        let load1 = system_state
            .get("load")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|v| v.as_f64());

        let cores = system_state
            .get("cores")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);

        let (used_gb, total_gb) = system_state
            .get("memory")
            .and_then(|mem| {
                let used = mem.get("used_gb").and_then(|v| v.as_f64())?;
                let total = mem.get("total_gb").and_then(|v| v.as_f64())?;
                Some((used, total))
            })
            .unwrap_or((0.0, 0.0));

        let memory_used_fraction = if total_gb > 0.0 {
            Some((used_gb / total_gb).clamp(0.0, 1.0))
        } else {
            None
        };

        let psi_avg10 = system_state.get("psi").map(|psi| {
            let cpu = psi.get("cpu").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let mem = psi.get("memory").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let io = psi.get("io").and_then(|v| v.as_f64()).unwrap_or(0.0);
            cpu.max(mem).max(io)
        });

        Self {
            queue_len,
            load1,
            cores,
            memory_used_fraction,
            psi_avg10,
        }
    }
}

/// Compute load adjustment from signals and policy configuration.
pub fn compute_load_adjustment(
    config: &LoadAwareDecision,
    signals: &LoadSignals,
) -> Option<LoadAdjustment> {
    if !config.enabled {
        return None;
    }

    let queue_score = if config.queue_high > 0 {
        (signals.queue_len as f64 / config.queue_high as f64).min(1.0)
    } else {
        0.0
    };

    let load_score = match (signals.load1, signals.cores) {
        (Some(load1), Some(cores)) if cores > 0 && config.load_per_core_high > 0.0 => {
            (load1 / (cores as f64 * config.load_per_core_high)).min(1.0)
        }
        _ => 0.0,
    };

    let memory_score = match signals.memory_used_fraction {
        Some(frac) if config.memory_used_fraction_high > 0.0 => {
            (frac / config.memory_used_fraction_high).min(1.0)
        }
        _ => 0.0,
    };

    let psi_score = match signals.psi_avg10 {
        Some(psi) if config.psi_avg10_high > 0.0 => (psi / config.psi_avg10_high).min(1.0),
        _ => 0.0,
    };

    let weight_sum =
        config.weights.queue + config.weights.load + config.weights.memory + config.weights.psi;
    if weight_sum <= 0.0 {
        return None;
    }

    let load_score = ((config.weights.queue * queue_score)
        + (config.weights.load * load_score)
        + (config.weights.memory * memory_score)
        + (config.weights.psi * psi_score))
        / weight_sum;

    let keep_multiplier = 1.0 + load_score * (config.multipliers.keep_max - 1.0).max(0.0);
    let reversible_multiplier =
        1.0 - load_score * (1.0 - config.multipliers.reversible_min).max(0.0);
    let risky_multiplier = 1.0 + load_score * (config.multipliers.risky_max - 1.0).max(0.0);

    Some(LoadAdjustment {
        load_score,
        keep_multiplier,
        reversible_multiplier,
        risky_multiplier,
    })
}

/// Apply a load adjustment to the loss matrix.
pub fn apply_load_to_loss_matrix(loss: &LossMatrix, adjustment: &LoadAdjustment) -> LossMatrix {
    LossMatrix {
        useful: apply_load_to_loss_row(loss.useful.clone(), adjustment),
        useful_bad: apply_load_to_loss_row(loss.useful_bad.clone(), adjustment),
        abandoned: apply_load_to_loss_row(loss.abandoned.clone(), adjustment),
        zombie: apply_load_to_loss_row(loss.zombie.clone(), adjustment),
    }
}

fn apply_load_to_loss_row(row: LossRow, adjustment: &LoadAdjustment) -> LossRow {
    LossRow {
        keep: row.keep * adjustment.keep_multiplier,
        pause: row.pause.map(|v| v * adjustment.reversible_multiplier),
        throttle: row.throttle.map(|v| v * adjustment.reversible_multiplier),
        cap_memory: row.cap_memory.map(|v| v * adjustment.reversible_multiplier),
        renice: row.renice.map(|v| v * adjustment.reversible_multiplier),
        kill: row.kill * adjustment.risky_multiplier,
        restart: row.restart.map(|v| v * adjustment.risky_multiplier),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::policy::{LoadAwareDecision, LossMatrix, LossRow};
    use proptest::prelude::*;

    fn pressure_policy() -> Policy {
        let mut policy = Policy::default();
        policy.load_aware.enabled = true;
        policy
    }

    fn useful_hog() -> ClassScores {
        ClassScores {
            useful: 0.10,
            useful_bad: 0.85,
            abandoned: 0.04,
            zombie: 0.01,
        }
    }

    fn cpu_context(severity: f64, share: Option<f64>) -> PressureContext {
        PressureContext {
            severity: ResourceSeverity {
                cpu: severity,
                ..ResourceSeverity::default()
            },
            shares: ResourceShares {
                cpu: share,
                ..ResourceShares::default()
            },
            unavailable: Vec::new(),
        }
    }

    fn same_json(left: &impl Serialize, right: &impl Serialize) {
        assert_eq!(
            serde_json::to_value(left).unwrap(),
            serde_json::to_value(right).unwrap()
        );
    }

    #[test]
    fn additive_pressure_can_deprioritize_legitimate_resource_hog() {
        let policy = pressure_policy();
        let prepared = prepare_pressure_decision(
            &useful_hog(),
            &policy,
            &ActionFeasibility::allow_all(),
            &cpu_context(1.0, Some(0.2)),
        )
        .unwrap();
        assert_eq!(prepared.report.evidence_only_action, Action::Keep);
        assert_eq!(prepared.decision.optimal_action, Action::Renice);
        assert!(prepared.report.changed);
        assert_eq!(prepared.report.scope, "process");
        assert!((prepared.report.pressure_burden - 0.2).abs() < 1e-12);
        assert!((prepared.report.modeled_pressure_relief - 0.1).abs() < 1e-12);
        assert!(!prepared.feasibility.is_allowed(Action::Kill));
        assert!(!prepared.feasibility.is_allowed(Action::Restart));
        same_json(&prepared.decision.rationale.posterior, &Some(useful_hog()));
        for row in &prepared.report.actions {
            if let (Some(base), Some(total)) = (row.base_loss, row.adjusted_loss) {
                assert!((base + row.pressure_cost - total).abs() < 1e-10);
            }
        }
    }

    #[test]
    fn larger_attributed_pressure_can_favor_pause_without_authorizing_kill() {
        let prepared = prepare_pressure_decision(
            &useful_hog(),
            &pressure_policy(),
            &ActionFeasibility::allow_all(),
            &cpu_context(1.0, Some(0.4)),
        )
        .unwrap();
        assert_eq!(prepared.report.evidence_only_action, Action::Keep);
        assert_eq!(prepared.decision.optimal_action, Action::Pause);
        assert!((prepared.report.modeled_pressure_relief - 0.4).abs() < 1e-12);
        assert!(!prepared.feasibility.is_allowed(Action::Kill));
        assert!(!prepared.feasibility.is_allowed(Action::Restart));
    }

    #[test]
    fn inactive_pressure_preserves_entire_baseline_and_inputs() {
        let mut policy = pressure_policy();
        let feasibility = ActionFeasibility::allow_all();
        let cases = [
            (true, 1.0, cpu_context(0.0, Some(1.0))),
            (true, 1.0, cpu_context(1.0, Some(0.0))),
            (true, 1.0, cpu_context(1.0, None)),
            (true, 0.0, cpu_context(1.0, Some(1.0))),
            (false, 1.0, cpu_context(1.0, Some(1.0))),
        ];
        for (enabled, kappa, context) in cases {
            policy.load_aware.enabled = enabled;
            policy.load_aware.pressure.kappa = kappa;
            let baseline = decide_action(&useful_hog(), &policy, &feasibility).unwrap();
            let prepared =
                prepare_pressure_decision(&useful_hog(), &policy, &feasibility, &context).unwrap();
            same_json(&prepared.decision, &baseline);
            same_json(&prepared.policy, &policy);
            same_json(&prepared.feasibility, &feasibility);
            assert!(!prepared.report.applied);
            assert!(!prepared.report.changed);
            assert_eq!(prepared.report.pressure_burden, 0.0);
        }
    }

    #[test]
    fn malformed_observations_are_reported_without_inventing_activity() {
        let policy = pressure_policy();
        let feasibility = ActionFeasibility::allow_all();
        for share in [f64::NAN, f64::INFINITY, -0.1, 1.1] {
            let prepared = prepare_pressure_decision(
                &useful_hog(),
                &policy,
                &feasibility,
                &cpu_context(1.0, Some(share)),
            )
            .unwrap();
            assert!(!prepared.report.applied);
            assert_eq!(prepared.report.shares.cpu, None);
            assert_eq!(prepared.report.shares.io, None);
            assert!(prepared
                .report
                .unavailable
                .iter()
                .any(|r| r.contains("cpu attribution invalid")));
            same_json(
                &prepared.decision,
                &decide_action(&useful_hog(), &policy, &feasibility).unwrap(),
            );
        }
        let prepared = prepare_pressure_decision(
            &useful_hog(),
            &policy,
            &feasibility,
            &cpu_context(f64::NAN, Some(1.0)),
        )
        .unwrap();
        assert!(!prepared.report.applied);
        assert!(prepared
            .report
            .unavailable
            .iter()
            .any(|r| r.contains("cpu severity unavailable")));
    }

    #[test]
    fn memory_pressure_only_credits_the_memory_cap_not_pauses_or_cpu_controls() {
        let context = PressureContext {
            severity: ResourceSeverity {
                memory: 1.0,
                io: 1.0,
                ..ResourceSeverity::default()
            },
            shares: ResourceShares {
                memory: Some(0.9),
                io: None,
                cpu: None,
            },
            unavailable: vec!["No comparable same-window I/O denominator".to_string()],
        };
        let prepared = prepare_pressure_decision(
            &useful_hog(),
            &pressure_policy(),
            &ActionFeasibility::allow_all(),
            &context,
        )
        .unwrap();
        assert!(prepared.report.applied);
        assert_eq!(prepared.decision.optimal_action, Action::Keep);
        assert_eq!(prepared.report.modeled_pressure_relief, 0.0);
        for row in &prepared.report.actions {
            assert_eq!(row.pressure_by_resource.io, 0.0);
            if row.action == Action::CapMemory {
                assert!((row.pressure_by_resource.memory - 0.81).abs() < 1e-12);
            } else if row.action.is_reversible() {
                assert_eq!(row.pressure_by_resource.memory, 0.9);
            }
        }
    }

    #[test]
    fn memory_cap_changes_no_default_decision_without_attributed_memory_pressure() {
        let policy = pressure_policy();
        let mut before = policy.clone();
        for row in [
            &mut before.loss_matrix.useful,
            &mut before.loss_matrix.useful_bad,
            &mut before.loss_matrix.abandoned,
            &mut before.loss_matrix.zombie,
        ] {
            row.cap_memory = None;
        }
        for useful in 0..=10 {
            for useful_bad in 0..=10 - useful {
                for abandoned in 0..=10 - useful - useful_bad {
                    let posterior = ClassScores {
                        useful: f64::from(useful) / 10.0,
                        useful_bad: f64::from(useful_bad) / 10.0,
                        abandoned: f64::from(abandoned) / 10.0,
                        zombie: f64::from(10 - useful - useful_bad - abandoned) / 10.0,
                    };
                    let feasibility = ActionFeasibility::allow_all();
                    for context in [
                        PressureContext::default(),
                        cpu_context(1.0, Some(0.8)),
                        PressureContext {
                            severity: ResourceSeverity {
                                memory: 1.0,
                                ..Default::default()
                            },
                            ..Default::default()
                        },
                    ] {
                        let original =
                            prepare_pressure_decision(&posterior, &before, &feasibility, &context)
                                .unwrap();
                        let current =
                            prepare_pressure_decision(&posterior, &policy, &feasibility, &context)
                                .unwrap();
                        assert_eq!(
                            current.decision.optimal_action, original.decision.optimal_action,
                            "posterior {posterior:?}, context {context:?}"
                        );
                        assert_ne!(current.decision.optimal_action, Action::CapMemory);
                    }
                }
            }
        }
    }

    #[test]
    fn attributed_memory_hog_can_receive_cap_without_authorizing_termination() {
        let policy = pressure_policy();
        let posterior = ClassScores {
            useful: 0.05,
            useful_bad: 0.95,
            abandoned: 0.0,
            zombie: 0.0,
        };
        let context = PressureContext {
            severity: ResourceSeverity {
                memory: 1.0,
                ..Default::default()
            },
            shares: ResourceShares {
                memory: Some(0.9),
                ..Default::default()
            },
            unavailable: Vec::new(),
        };
        let result = prepare_pressure_decision(
            &posterior,
            &policy,
            &ActionFeasibility::allow_all(),
            &context,
        )
        .unwrap();
        assert_eq!(result.report.evidence_only_action, Action::Keep);
        assert_eq!(result.decision.optimal_action, Action::CapMemory);
        assert!((result.report.modeled_pressure_relief - 0.09).abs() < 1e-12);
        assert!(!result.feasibility.is_allowed(Action::Kill));
        assert!(!result.feasibility.is_allowed(Action::Restart));
        let refusal = ActionFeasibility {
            disabled: vec![DisabledAction {
                action: Action::CapMemory,
                reason: "no observed owned leaf cgroup".into(),
            }],
        };
        let blocked = prepare_pressure_decision(&posterior, &policy, &refusal, &context).unwrap();
        assert_eq!(blocked.decision.optimal_action, Action::Keep);
        assert!(blocked
            .report
            .actions
            .iter()
            .any(|row| row.action == Action::CapMemory
                && !row.eligible
                && row.excluded_reason.as_deref() == Some("no observed owned leaf cgroup")));
        let healthy = ClassScores {
            useful: 1.0,
            useful_bad: 0.0,
            abandoned: 0.0,
            zombie: 0.0,
        };
        assert_eq!(
            prepare_pressure_decision(&healthy, &policy, &ActionFeasibility::allow_all(), &context)
                .unwrap()
                .decision
                .optimal_action,
            Action::Keep
        );
        let mut disabled_policy = policy;
        disabled_policy.load_aware.enabled = false;
        assert_eq!(
            prepare_pressure_decision(
                &posterior,
                &disabled_policy,
                &ActionFeasibility::allow_all(),
                &context
            )
            .unwrap()
            .decision
            .optimal_action,
            Action::Keep
        );
    }

    #[test]
    fn invalid_cpu_observation_does_not_discard_valid_memory_attribution() {
        let context = PressureContext {
            severity: ResourceSeverity {
                cpu: 1.0,
                memory: 1.0,
                ..ResourceSeverity::default()
            },
            shares: ResourceShares {
                cpu: Some(f64::NAN),
                memory: Some(0.9),
                io: None,
            },
            unavailable: Vec::new(),
        };
        let prepared = prepare_pressure_decision(
            &useful_hog(),
            &pressure_policy(),
            &ActionFeasibility::allow_all(),
            &context,
        )
        .unwrap();
        assert!(prepared.report.applied);
        assert_eq!(prepared.report.shares.cpu, None);
        assert_eq!(prepared.report.shares.memory, Some(0.9));
        assert_eq!(prepared.report.pressure_burden, 0.9);
        assert_eq!(prepared.decision.optimal_action, Action::Keep);
        assert!(!prepared.feasibility.is_allowed(Action::Kill));
        assert!(prepared
            .report
            .unavailable
            .iter()
            .any(|reason| reason.contains("cpu attribution invalid")));
    }

    #[test]
    fn preexisting_exclusions_and_missing_loss_entries_survive_pressure() {
        let mut policy = pressure_policy();
        policy.loss_matrix.useful.pause = None;
        let feasibility = ActionFeasibility {
            disabled: vec![DisabledAction {
                action: Action::Renice,
                reason: "thread-wide action unavailable".to_string(),
            }],
        };
        let prepared = prepare_pressure_decision(
            &useful_hog(),
            &policy,
            &feasibility,
            &cpu_context(1.0, Some(0.4)),
        )
        .unwrap();
        for action in [
            Action::Renice,
            Action::Pause,
            Action::Freeze,
            Action::Kill,
            Action::Restart,
        ] {
            let row = prepared
                .report
                .actions
                .iter()
                .find(|row| row.action == action)
                .unwrap();
            assert!(!row.eligible, "{action:?} must remain excluded");
            assert!(row.excluded_reason.is_some());
            assert!(!prepared
                .decision
                .expected_loss
                .iter()
                .any(|row| row.action == action));
        }
        assert_eq!(
            prepared.feasibility.disabled[0].reason,
            "thread-wide action unavailable"
        );
    }

    #[test]
    fn only_the_exact_evidence_only_destructive_winner_remains_eligible() {
        let posterior = ClassScores {
            useful: 0.0,
            useful_bad: 0.0,
            abandoned: 1.0,
            zombie: 0.0,
        };
        let policy = pressure_policy();
        let prepared = prepare_pressure_decision(
            &posterior,
            &policy,
            &ActionFeasibility::allow_all(),
            &cpu_context(1.0, Some(1.0)),
        )
        .unwrap();
        assert_eq!(prepared.report.evidence_only_action, Action::Kill);
        assert!(prepared.feasibility.is_allowed(Action::Kill));
        assert!(!prepared.feasibility.is_allowed(Action::Restart));

        let mut restart_policy = policy;
        restart_policy.loss_matrix.abandoned.restart = Some(0.01);
        let prepared = prepare_pressure_decision(
            &posterior,
            &restart_policy,
            &ActionFeasibility::allow_all(),
            &cpu_context(1.0, Some(1.0)),
        )
        .unwrap();
        assert_eq!(prepared.report.evidence_only_action, Action::Restart);
        assert!(prepared.feasibility.is_allowed(Action::Restart));
        assert!(!prepared.feasibility.is_allowed(Action::Kill));
        assert_eq!(prepared.decision.optimal_action, Action::Restart);
    }

    #[test]
    fn sequential_probe_logic_uses_the_same_pressure_policy_and_gate() {
        use crate::decision::sequential::decide_sequential;
        use crate::decision::voi::ProbeCostModel;
        let prepared = prepare_pressure_decision(
            &useful_hog(),
            &pressure_policy(),
            &ActionFeasibility::allow_all(),
            &cpu_context(1.0, Some(0.2)),
        )
        .unwrap();
        let (sequential, _) = decide_sequential(
            &useful_hog(),
            &prepared.policy,
            &prepared.feasibility,
            &ProbeCostModel::default(),
            None,
        )
        .unwrap();
        assert_eq!(sequential.action_now, Action::Renice);
        assert_eq!(sequential.action_now, prepared.decision.optimal_action);
        assert!(!prepared.feasibility.is_allowed(Action::Kill));
        assert!(!prepared.feasibility.is_allowed(Action::Restart));
    }

    #[test]
    fn invalid_pressure_model_is_rejected_when_enabled() {
        let mut policy = pressure_policy();
        policy.load_aware.pressure.renice_cpu_relief = 1.1;
        assert!(prepare_pressure_decision(
            &useful_hog(),
            &policy,
            &ActionFeasibility::allow_all(),
            &cpu_context(1.0, Some(0.4)),
        )
        .is_err());
    }

    proptest! {
        #[test]
        fn pressure_never_introduces_a_destructive_winner(
            weights in prop::array::uniform4(0.001f64..1.0),
            severity in 0.0f64..1.0,
            share in 0.0f64..1.0,
            memory_severity in 0.0f64..1.0,
            memory_share in 0.0f64..1.0,
            kappa in 0.0f64..1000.0,
        ) {
            let sum: f64 = weights.iter().sum();
            let posterior = ClassScores {
                useful: weights[0]/sum, useful_bad: weights[1]/sum,
                abandoned: weights[2]/sum, zombie: weights[3]/sum,
            };
            let mut policy = pressure_policy();
            policy.load_aware.pressure.kappa = kappa;
            let mut context = cpu_context(severity, Some(share));
            context.severity.memory = memory_severity;
            context.shares.memory = Some(memory_share);
            let prepared = prepare_pressure_decision(
                &posterior, &policy, &ActionFeasibility::allow_all(), &context,
            ).unwrap();
            if matches!(prepared.decision.optimal_action, Action::Kill | Action::Restart) {
                prop_assert_eq!(prepared.decision.optimal_action, prepared.report.evidence_only_action);
            }
            if prepared.report.applied {
                for action in [Action::Kill, Action::Restart] {
                    prop_assert_eq!(prepared.feasibility.is_allowed(action), action == prepared.report.evidence_only_action);
                }
            }
        }

        #[test]
        fn increasing_pressure_or_share_never_favors_keep_over_reversible_actions(
            severity_a in 0.0f64..1.0, severity_b in 0.0f64..1.0,
            share_a in 0.0f64..1.0, share_b in 0.0f64..1.0,
        ) {
            let policy = pressure_policy();
            let feasibility = ActionFeasibility::allow_all();
            let low = prepare_pressure_decision(&useful_hog(), &policy, &feasibility,
                &cpu_context(severity_a.min(severity_b), Some(share_a.min(share_b)))).unwrap();
            let high = prepare_pressure_decision(&useful_hog(), &policy, &feasibility,
                &cpu_context(severity_a.max(severity_b), Some(share_a.max(share_b)))).unwrap();
            let loss = |result: &PressureDecisionInputs, action| {
                result.report.actions.iter().find(|row| row.action == action).unwrap().adjusted_loss.unwrap()
            };
            for action in [Action::Renice, Action::Pause, Action::Freeze, Action::Throttle, Action::Quarantine] {
                let low_margin = loss(&low, Action::Keep) - loss(&low, action);
                let high_margin = loss(&high, Action::Keep) - loss(&high, action);
                prop_assert!(high_margin + 1e-12 >= low_margin);
            }
        }

        #[test]
        fn zero_pressure_retains_the_exact_evidence_only_decision(
            weights in prop::array::uniform4(0.001f64..1.0), share in 0.0f64..1.0,
        ) {
            let sum: f64 = weights.iter().sum();
            let posterior = ClassScores {
                useful: weights[0]/sum, useful_bad: weights[1]/sum,
                abandoned: weights[2]/sum, zombie: weights[3]/sum,
            };
            let policy = pressure_policy();
            let feasibility = ActionFeasibility::allow_all();
            let baseline = decide_action(&posterior, &policy, &feasibility).unwrap();
            let prepared = prepare_pressure_decision(
                &posterior, &policy, &feasibility, &cpu_context(0.0, Some(share)),
            ).unwrap();
            prop_assert_eq!(serde_json::to_value(&prepared.decision).unwrap(), serde_json::to_value(&baseline).unwrap());
        }
    }

    #[test]
    fn test_load_adjustment_zero_load() {
        let cfg = LoadAwareDecision {
            enabled: true,
            ..LoadAwareDecision::default()
        };
        let signals = LoadSignals {
            queue_len: 0,
            load1: Some(0.0),
            cores: Some(8),
            memory_used_fraction: Some(0.0),
            psi_avg10: Some(0.0),
        };
        let adj = compute_load_adjustment(&cfg, &signals).expect("adjustment");
        assert!((adj.load_score - 0.0).abs() < 1e-6);
        assert!((adj.keep_multiplier - 1.0).abs() < 1e-6);
        assert!((adj.reversible_multiplier - 1.0).abs() < 1e-6);
        assert!((adj.risky_multiplier - 1.0).abs() < 1e-6);
    }

    #[test]
    fn test_load_adjustment_high_load_saturates() {
        let cfg = LoadAwareDecision {
            enabled: true,
            ..LoadAwareDecision::default()
        };
        let signals = LoadSignals {
            queue_len: 10_000,
            load1: Some(10_000.0),
            cores: Some(1),
            memory_used_fraction: Some(1.0),
            psi_avg10: Some(100.0),
        };
        let adj = compute_load_adjustment(&cfg, &signals).expect("adjustment");
        assert!((adj.load_score - 1.0).abs() < 1e-6);
        assert!((adj.keep_multiplier - cfg.multipliers.keep_max).abs() < 1e-6);
        assert!((adj.reversible_multiplier - cfg.multipliers.reversible_min).abs() < 1e-6);
        assert!((adj.risky_multiplier - cfg.multipliers.risky_max).abs() < 1e-6);
    }

    #[test]
    fn test_apply_load_to_loss_matrix() {
        let loss = LossMatrix {
            useful: LossRow {
                cap_memory: None,
                keep: 10.0,
                pause: Some(4.0),
                throttle: Some(6.0),
                renice: Some(3.0),
                kill: 100.0,
                restart: Some(50.0),
            },
            useful_bad: LossRow {
                cap_memory: None,
                keep: 10.0,
                pause: Some(4.0),
                throttle: Some(6.0),
                renice: Some(3.0),
                kill: 100.0,
                restart: Some(50.0),
            },
            abandoned: LossRow {
                cap_memory: None,
                keep: 10.0,
                pause: Some(4.0),
                throttle: Some(6.0),
                renice: Some(3.0),
                kill: 100.0,
                restart: Some(50.0),
            },
            zombie: LossRow {
                cap_memory: None,
                keep: 10.0,
                pause: Some(4.0),
                throttle: Some(6.0),
                renice: Some(3.0),
                kill: 100.0,
                restart: Some(50.0),
            },
        };

        let adjustment = LoadAdjustment {
            load_score: 0.5,
            keep_multiplier: 1.2,
            reversible_multiplier: 0.8,
            risky_multiplier: 1.5,
        };
        let adjusted = apply_load_to_loss_matrix(&loss, &adjustment);

        let epsilon = 1e-10;
        assert!((adjusted.useful.keep - 12.0).abs() < epsilon);
        assert!((adjusted.useful.pause.unwrap() - 3.2).abs() < epsilon);
        assert!((adjusted.useful.renice.unwrap() - 2.4).abs() < epsilon);
        assert!((adjusted.useful.kill - 150.0).abs() < epsilon);
        assert!((adjusted.useful.restart.unwrap() - 75.0).abs() < epsilon);
    }
}
