//! False Discovery Rate (FDR) control for kill-set selection.
//!
//! Implements e-value selection for callers with valid e-values, and a distinct
//! posterior-risk gate for executable plans. Posterior probabilities are never
//! converted into fabricated e-values.
//!
//! See: Plan §5.8 / §4.32

use serde::Serialize;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use thiserror::Error;

/// FDR control method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum FdrMethod {
    /// e-value Benjamini-Hochberg (assumes independence or PRDS).
    EBh,
    /// e-value Benjamini-Yekutieli (conservative, handles arbitrary dependence).
    #[default]
    EBy,
    /// No FDR control (select all with e-value > 1).
    None,
}

/// Target identity for a candidate process.
#[derive(Debug, Clone, Serialize)]
pub struct TargetIdentity {
    /// Process ID.
    pub pid: i32,
    /// Stable start ID (pid + start_time + boot_id).
    pub start_id: String,
    /// User ID owning the process.
    pub uid: u32,
}

/// Per-candidate selection result with diagnostics.
#[derive(Debug, Clone, Serialize)]
pub struct CandidateSelection {
    /// Target identity tuple (for TOCTOU safety).
    pub target: TargetIdentity,
    /// E-value for this candidate (Bayes factor H1/H0).
    pub e_value: f64,
    /// Derived p-value (min(1, 1/e_value)).
    pub p_value: f64,
    /// Rank in descending e-value order (1-indexed).
    pub rank: usize,
    /// Selection threshold used for this rank.
    pub threshold: f64,
    /// Whether this candidate was selected.
    pub selected: bool,
}

/// FDR selection result for a batch of candidates.
#[derive(Debug, Clone, Serialize)]
pub struct FdrSelectionResult {
    /// Target alpha level used.
    pub alpha: f64,
    /// FDR control method applied.
    pub method: FdrMethod,
    /// BY correction factor c(m) if applicable.
    pub correction_factor: Option<f64>,
    /// Total number of candidates evaluated.
    pub m_candidates: usize,
    /// Number of candidates selected.
    pub selected_k: usize,
    /// Selection threshold at the boundary.
    pub selection_threshold: f64,
    /// Per-candidate selection details (sorted by e_value descending).
    pub candidates: Vec<CandidateSelection>,
    /// Identity tuples of selected candidates.
    pub selected_ids: Vec<TargetIdentity>,
}

/// Errors during FDR selection.
#[derive(Debug, Error)]
pub enum FdrError {
    #[error("alpha must be in (0, 1], got {alpha}")]
    InvalidAlpha { alpha: f64 },
    #[error("e-values must be non-negative")]
    NegativeEvalue,
    #[error("no candidates provided")]
    NoCandidates,
}

/// Input candidate for FDR selection.
#[derive(Debug, Clone)]
pub struct FdrCandidate {
    /// Target identity tuple.
    pub target: TargetIdentity,
    /// E-value (Bayes factor H1/H0).
    pub e_value: f64,
}

/// Select candidates using e-value based FDR control.
///
/// # Arguments
/// * `candidates` - Candidates with e-values (Bayes factors)
/// * `alpha` - Target FDR level (e.g., 0.05)
/// * `method` - FDR control method (eBH, eBY, None)
///
/// # Returns
/// Selection result with per-candidate diagnostics.
pub fn select_fdr(
    candidates: &[FdrCandidate],
    alpha: f64,
    method: FdrMethod,
) -> Result<FdrSelectionResult, FdrError> {
    // Validate inputs
    if alpha <= 0.0 || alpha > 1.0 {
        return Err(FdrError::InvalidAlpha { alpha });
    }
    if candidates.is_empty() {
        return Err(FdrError::NoCandidates);
    }
    for c in candidates {
        if c.e_value < 0.0 {
            return Err(FdrError::NegativeEvalue);
        }
    }

    let m = candidates.len();

    // Sort indices by e_value descending
    let mut sorted_indices: Vec<usize> = (0..m).collect();
    sorted_indices.sort_by(|&a, &b| {
        candidates[b]
            .e_value
            .partial_cmp(&candidates[a].e_value)
            .unwrap_or(Ordering::Equal)
    });

    // Compute BY correction factor c(m) = sum_{j=1..m} 1/j
    let correction = match method {
        FdrMethod::EBy => {
            let c_m: f64 = (1..=m).map(|j| 1.0 / j as f64).sum();
            Some(c_m)
        }
        _ => None,
    };

    // Effective alpha after correction
    let effective_alpha = match method {
        FdrMethod::EBy => alpha / correction.unwrap(),
        FdrMethod::EBh | FdrMethod::None => alpha,
    };

    // Find largest k where e_(k) >= m / (effective_alpha * k)
    // This is the eBH rule: e_(k) >= m / (alpha * k)
    let selected_k = match method {
        FdrMethod::None => {
            // Select all with e > 1
            sorted_indices
                .iter()
                .filter(|&&i| candidates[i].e_value > 1.0)
                .count()
        }
        FdrMethod::EBh | FdrMethod::EBy => {
            let mut k = 0;
            for (rank_0, &idx) in sorted_indices.iter().enumerate() {
                let rank = rank_0 + 1; // 1-indexed
                let threshold = (m as f64) / (effective_alpha * rank as f64);
                if candidates[idx].e_value >= threshold {
                    k = rank;
                }
            }
            k
        }
    };

    // Compute the selection threshold at the boundary
    let selection_threshold = if selected_k > 0 {
        (m as f64) / (effective_alpha * selected_k as f64)
    } else {
        f64::INFINITY
    };

    // Build per-candidate results
    let mut candidate_results = Vec::with_capacity(m);
    let mut selected_ids = Vec::new();

    for (rank_0, &idx) in sorted_indices.iter().enumerate() {
        let rank = rank_0 + 1;
        let e_val = candidates[idx].e_value;
        let p_val = if e_val > 0.0 {
            (1.0 / e_val).min(1.0)
        } else {
            1.0
        };
        let threshold = (m as f64) / (effective_alpha * rank as f64);
        let selected = rank <= selected_k;

        let selection = CandidateSelection {
            target: candidates[idx].target.clone(),
            e_value: e_val,
            p_value: p_val,
            rank,
            threshold,
            selected,
        };

        if selected {
            selected_ids.push(candidates[idx].target.clone());
        }

        candidate_results.push(selection);
    }

    Ok(FdrSelectionResult {
        alpha,
        method,
        correction_factor: correction,
        m_candidates: m,
        selected_k,
        selection_threshold,
        candidates: candidate_results,
        selected_ids,
    })
}

/// Compute the BY correction factor c(m) = sum_{j=1..m} 1/j.
///
/// This is the harmonic number H_m, used to control FDR under
/// arbitrary dependence structures.
pub fn by_correction_factor(m: usize) -> f64 {
    (1..=m).map(|j| 1.0 / j as f64).sum()
}

/// Posterior-risk decision for one actual process incarnation. Repeated actions
/// on the same target cannot dilute the reported risk or count as independent
/// evidence. This does not establish that the posterior is calibrated.
#[derive(Debug, Clone, Serialize)]
pub struct PlanFdrDecision {
    pub target: pt_common::ProcessIdentity,
    pub action_ids: Vec<String>,
    pub posterior_null_probability: Option<f64>,
    pub selected: bool,
    pub reason: String,
}

/// What the single-host executable-plan gate actually enforced.
#[derive(Debug, Clone, Serialize)]
pub struct PlanFdrReport {
    pub enabled: bool,
    pub requested_method: String,
    pub applied_method: Option<String>,
    pub status: String,
    /// Invalid nonfinite policy values stay JSON-serializable as unavailable.
    pub alpha: Option<f64>,
    pub null_classes: Vec<String>,
    pub candidate_targets: usize,
    pub selected_targets: usize,
    pub blocked_targets: usize,
    pub selected_action_ids: Vec<String>,
    /// Includes stage-pause actions paired with a refused kill.
    pub blocked_action_ids: Vec<String>,
    pub expected_fdr: Option<f64>,
    pub min_candidates: Option<u32>,
    pub selection_scope: String,
    pub limitation: String,
    pub unavailable_reason: Option<String>,
    pub decisions: Vec<PlanFdrDecision>,
}

struct PlanFdrTarget {
    target: pt_common::ProcessIdentity,
    action_indices: Vec<usize>,
    posterior: Option<crate::inference::ClassScores>,
    unavailable_reason: Option<String>,
}

fn plan_fdr_identity_valid(target: &pt_common::ProcessIdentity) -> bool {
    if target.pid.0 <= 1 || target.quality != pt_common::IdentityQuality::Full {
        return false;
    }
    let mut parts = target.start_id.0.split(':');
    matches!(parts.next(), Some(boot) if !boot.is_empty() && !matches!(boot, "unknown" | "synthetic"))
        && parts
            .next()
            .and_then(|part| part.parse::<u64>().ok())
            .is_some()
        && parts.next().and_then(|part| part.parse::<u32>().ok()) == Some(target.pid.0)
        && parts.next().is_none()
}

fn posterior_null_probability(
    posterior: Option<crate::inference::ClassScores>,
    null_classes: &[String],
) -> Result<f64, &'static str> {
    let posterior = posterior.ok_or("kill target has no recorded class posterior")?;
    let values = [
        posterior.useful,
        posterior.useful_bad,
        posterior.abandoned,
        posterior.zombie,
    ];
    if values
        .iter()
        .any(|value| !value.is_finite() || !(0.0..=1.0).contains(value))
        || (values.iter().sum::<f64>() - 1.0).abs() > 1e-9
    {
        return Err("kill target posterior must contain finite normalized probabilities");
    }
    let mut risk = 0.0;
    for class in null_classes {
        risk += match class.as_str() {
            "useful" => posterior.useful,
            "useful_bad" => posterior.useful_bad,
            "abandoned" => posterior.abandoned,
            "zombie" => posterior.zombie,
            _ => return Err("unknown posterior null class"),
        };
    }
    // Only the accepted normalization roundoff can put a class sum over one.
    Ok(risk.min(1.0))
}

/// Enforce a posterior-risk limit on the actual remaining direct kill actions.
///
/// Each accepted target has posterior null probability <= alpha. Consequently
/// every nonempty execution subset also has mean posterior null probability <=
/// alpha: failed prechecks, cancellation, parallel failures and manual selection
/// cannot remove low-risk targets that were subsidizing a riskier kill. A largest
/// mean-risk prefix would not have that property. This is a model-based estimate;
/// no frequentist or anytime-valid FDR guarantee is claimed.
///
/// Callers must run this after final action selection and at apply time against
/// both the recorded and current policy. Already blocked actions remain blocked.
/// `min_candidates` is advisory here, never a way to bypass the limit on a small
/// execution subset. Zombie-parent reaping uses Restart, not Kill, and is outside
/// this direct-kill gate; a Kill carrying a child's posterior is refused.
pub fn apply_plan_fdr_gate(
    plan: &mut crate::plan::Plan,
    policy: &crate::config::Policy,
) -> PlanFdrReport {
    use crate::config::policy::FdrMethod as PolicyMethod;
    use crate::decision::Action;
    use crate::plan::ActionRouting;

    let config = &policy.fdr_control;
    let enabled = config.enabled && config.method != PolicyMethod::None;
    let null_classes: Vec<String> = if config.lfdr_null.is_empty() {
        vec!["useful".into(), "useful_bad".into()]
    } else {
        config
            .lfdr_null
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    };
    let mut report = PlanFdrReport {
        enabled,
        requested_method: config.method.as_str().to_string(),
        applied_method: (enabled && config.method == PolicyMethod::Bayesian)
            .then(|| "subset_safe_bayes_expected_fdr".to_string()),
        status: if enabled { "enforced" } else { "disabled" }.to_string(),
        alpha: config.alpha.is_finite().then_some(config.alpha),
        null_classes,
        candidate_targets: 0,
        selected_targets: 0,
        blocked_targets: 0,
        selected_action_ids: Vec::new(),
        blocked_action_ids: Vec::new(),
        expected_fdr: None,
        min_candidates: config.min_candidates,
        selection_scope: "each direct kill target; remains valid for arbitrary execution subsets".into(),
        limitation: "Posterior expected false-discovery estimate only; depends on the model and does not establish calibration or a frequentist/anytime-valid FDR guarantee. Minimum candidate count does not disable execution checks.".into(),
        unavailable_reason: None,
        decisions: Vec::new(),
    };
    if enabled {
        report.unavailable_reason = if !config.alpha.is_finite()
            || !(0.0..=1.0).contains(&config.alpha)
        {
            Some("FDR alpha must be finite and in [0, 1]".into())
        } else if report.null_classes.iter().any(|class| {
            !matches!(
                class.as_str(),
                "useful" | "useful_bad" | "abandoned" | "zombie"
            )
        }) {
            Some("FDR null classes must name useful, useful_bad, abandoned or zombie".into())
        } else {
            match config.method {
                PolicyMethod::Bh | PolicyMethod::By => Some(format!(
                    "FDR method {} requires valid p-values or e-values; the saved plan contains class posteriors, which are not such evidence",
                    config.method.as_str()
                )),
                PolicyMethod::AlphaInvesting => Some("Alpha-investing requires valid sequential evidence and durable alpha-wealth state; neither is supplied by a saved class posterior".into()),
                PolicyMethod::Bayesian | PolicyMethod::None => None,
            }
        };
        if report.unavailable_reason.is_some() {
            report.status = "unavailable".into();
            report.applied_method = None;
        }
    }

    let mut action_id_counts = HashMap::new();
    for action in &plan.actions {
        *action_id_counts
            .entry(action.action_id.as_str())
            .or_insert(0usize) += 1;
    }
    let mut targets: BTreeMap<(u32, String, u32), PlanFdrTarget> = BTreeMap::new();
    for (index, action) in plan
        .actions
        .iter()
        .enumerate()
        .filter(|(_, action)| action.action == Action::Kill && !action.blocked)
    {
        let target = &action.target;
        let entry = targets
            .entry((target.pid.0, target.start_id.0.clone(), target.uid))
            .or_insert_with(|| PlanFdrTarget {
                target: target.clone(),
                action_indices: Vec::new(),
                posterior: action.rationale.posterior,
                unavailable_reason: None,
            });
        entry.action_indices.push(index);
        let reason = if !plan_fdr_identity_valid(target) {
            Some("kill target requires a full, consistent process identity")
        } else if entry.target != *target || entry.posterior != action.rationale.posterior {
            Some("duplicate kill target has conflicting identity or posterior evidence")
        } else if action_id_counts.get(action.action_id.as_str()) != Some(&1) {
            Some("kill action ID is ambiguous in the saved plan")
        } else if !matches!(
            action.routing,
            ActionRouting::Direct | ActionRouting::DStateLowConfidence
        ) || action.original_zombie_target.is_some()
            || action.supervisor_restart.is_some()
        {
            Some("a routed child's posterior cannot authorize killing its parent or supervisor")
        } else {
            None
        };
        if let Some(reason) = reason {
            entry.unavailable_reason = Some(reason.into());
        }
    }
    let mut pid_counts = HashMap::new();
    for target in targets.values() {
        *pid_counts.entry(target.target.pid.0).or_insert(0usize) += 1;
    }
    report.candidate_targets = targets.len();
    let mut rejected_indices = BTreeSet::new();
    let mut selected_risk = 0.0;
    for mut target in targets.into_values() {
        if pid_counts[&target.target.pid.0] > 1 {
            target.unavailable_reason =
                Some("multiple process incarnations or owners share the same kill PID".into());
        }
        let risk = posterior_null_probability(target.posterior, &report.null_classes);
        let reason = if !enabled {
            None
        } else if let Some(reason) = &report.unavailable_reason {
            Some(reason.clone())
        } else if let Some(reason) = target.unavailable_reason {
            Some(reason)
        } else {
            match &risk {
                Err(reason) => Some((*reason).to_string()),
                Ok(risk) if *risk > config.alpha => Some(format!(
                    "posterior null probability {risk:.6} exceeds alpha {:.6}; another target cannot subsidize this kill",
                    config.alpha
                )),
                Ok(_) => None,
            }
        };
        let selected = reason.is_none();
        let action_ids: Vec<_> = target
            .action_indices
            .iter()
            .map(|&index| plan.actions[index].action_id.clone())
            .collect();
        if selected {
            report.selected_targets += 1;
            report
                .selected_action_ids
                .extend(action_ids.iter().cloned());
            selected_risk += risk.as_ref().copied().unwrap_or(0.0);
        } else {
            report.blocked_targets += 1;
            rejected_indices.extend(target.action_indices);
        }
        report.decisions.push(PlanFdrDecision {
            target: target.target,
            action_ids,
            posterior_null_probability: risk.ok(),
            selected,
            reason: reason.unwrap_or_else(|| {
                if enabled {
                    "recorded posterior null probability is within the per-target limit".into()
                } else {
                    "posterior-risk control is disabled by policy".into()
                }
            }),
        });
    }
    if enabled && report.unavailable_reason.is_none() && report.selected_targets > 0 {
        report.expected_fdr = Some(selected_risk / report.selected_targets as f64);
    }
    if enabled && report.candidate_targets == 0 && report.unavailable_reason.is_none() {
        report.status = "no_kill_actions".into();
    }
    let rejected_targets: HashSet<_> = rejected_indices
        .iter()
        .map(|&index| plan.actions[index].target.clone())
        .collect();
    for (index, action) in plan.actions.iter().enumerate() {
        if action.action == Action::Pause
            && !action.blocked
            && rejected_targets.contains(&action.target)
        {
            rejected_indices.insert(index);
        }
    }
    for index in rejected_indices {
        plan.actions[index].blocked = true;
        report
            .blocked_action_ids
            .push(plan.actions[index].action_id.clone());
    }
    let blocked_ids: BTreeSet<_> = plan
        .actions
        .iter()
        .filter(|action| action.blocked)
        .map(|action| action.action_id.as_str())
        .collect();
    plan.pre_toggled
        .retain(|id| !blocked_ids.contains(id.as_str()));
    plan.gates_summary.blocked_candidates = plan
        .gates_summary
        .blocked_candidates
        .saturating_add(report.blocked_targets);
    plan.gates_summary.pre_toggled_actions = plan.pre_toggled.len();
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan_kill(pid: u32, risk: f64) -> crate::plan::PlanAction {
        use crate::plan::{ActionConfidence, ActionRationale, ActionRouting, ActionTimeouts};
        crate::plan::PlanAction {
            action_id: format!("kill-{pid}"),
            target: pt_common::ProcessIdentity::new(
                pid,
                pt_common::StartId::from_linux("boot", 100, pid),
                1000,
            ),
            action: crate::decision::Action::Kill,
            order: 0,
            stage: 0,
            timeouts: ActionTimeouts::default(),
            pre_checks: Vec::new(),
            rationale: ActionRationale {
                expected_loss: Some(1.0),
                expected_recovery: None,
                expected_recovery_stddev: None,
                posterior_odds_abandoned_vs_useful: None,
                sprt_boundary: None,
                posterior: Some(crate::inference::ClassScores {
                    useful: risk,
                    useful_bad: 0.0,
                    abandoned: 1.0 - risk,
                    zombie: 0.0,
                }),
                memory_mb: None,
                has_known_signature: None,
                category: None,
            },
            on_success: Vec::new(),
            on_failure: Vec::new(),
            blocked: false,
            routing: ActionRouting::Direct,
            confidence: ActionConfidence::Normal,
            original_zombie_target: None,
            d_state_diagnostics: None,
            supervisor_restart: None,
            memory_cap: None,
        }
    }

    fn plan_with(actions: Vec<crate::plan::PlanAction>) -> crate::plan::Plan {
        crate::plan::Plan {
            plan_id: "plan-fdr-test".into(),
            session_id: "session-fdr-test".into(),
            generated_at: "2026-11-23T00:00:00Z".into(),
            policy_id: None,
            policy_version: "1.0.0".into(),
            pre_toggled: actions
                .iter()
                .map(|action| action.action_id.clone())
                .collect(),
            gates_summary: crate::plan::GatesSummary {
                total_candidates: actions.len(),
                blocked_candidates: 0,
                pre_toggled_actions: actions.len(),
            },
            actions,
        }
    }

    #[test]
    fn plan_fdr_never_subsidizes_a_risky_kill_with_a_safer_target() {
        let policy = crate::config::Policy::default();
        let mut plan = plan_with(vec![plan_kill(10, 0.001), plan_kill(11, 0.099)]);
        // The pair averages exactly alpha, but a failed first kill would leave
        // only a 9.9%-risk success. Only the individually bounded target passes.
        let report = apply_plan_fdr_gate(&mut plan, &policy);
        assert_eq!(
            report.applied_method.as_deref(),
            Some("subset_safe_bayes_expected_fdr")
        );
        assert_eq!(report.selected_action_ids, vec!["kill-10"]);
        assert_eq!(report.blocked_action_ids, vec!["kill-11"]);
        assert_eq!(report.selected_targets, 1);
        assert_eq!(report.expected_fdr, Some(0.001));
        assert_eq!(plan.pre_toggled, vec!["kill-10"]);

        let mut subset = plan_with(vec![plan_kill(11, 0.099)]);
        assert_eq!(
            apply_plan_fdr_gate(&mut subset, &policy).selected_targets,
            0
        );
    }

    #[test]
    fn plan_fdr_all_accepted_execution_subsets_satisfy_the_model_budget() {
        let policy = crate::config::Policy::default();
        let mut plan = plan_with(
            (0..12)
                .map(|i| plan_kill(100 + i, f64::from(i) / 100.0))
                .collect(),
        );
        let report = apply_plan_fdr_gate(&mut plan, &policy);
        let risks: Vec<_> = report
            .decisions
            .iter()
            .filter(|row| row.selected)
            .map(|row| row.posterior_null_probability.unwrap())
            .collect();
        assert_eq!(risks.len(), 6);
        for subset in 1usize..(1 << risks.len()) {
            let selected: Vec<_> = risks
                .iter()
                .enumerate()
                .filter(|(i, _)| subset & (1 << i) != 0)
                .map(|(_, risk)| *risk)
                .collect();
            assert!(
                selected.iter().sum::<f64>() / selected.len() as f64 <= policy.fdr_control.alpha
            );
        }
    }

    #[test]
    fn plan_fdr_blocks_staged_pause_without_touching_unrelated_or_zombie_remedies() {
        use crate::decision::Action;
        let policy = crate::config::Policy::default();
        let mut kill = plan_kill(10, 0.8);
        kill.stage = 1;
        let mut pause = kill.clone();
        pause.action_id = "pause-10".into();
        pause.action = Action::Pause;
        pause.stage = 0;
        let mut renice = plan_kill(11, 0.9);
        renice.action = Action::Renice;
        let mut zombie = plan_kill(12, 0.9);
        zombie.action = Action::Restart;
        zombie.routing = crate::plan::ActionRouting::ZombieToParent;
        zombie.original_zombie_target = Some(plan_kill(13, 0.0).target);
        let mut plan = plan_with(vec![pause, kill, renice, zombie]);
        let report = apply_plan_fdr_gate(&mut plan, &policy);
        assert_eq!(report.blocked_action_ids, vec!["pause-10", "kill-10"]);
        assert_eq!(report.candidate_targets, 1);
        assert!(!plan.actions[2].blocked);
        assert!(!plan.actions[3].blocked);
        assert_eq!(plan.gates_summary.blocked_candidates, 1);
        assert_eq!(plan.gates_summary.pre_toggled_actions, 2);
        let again = apply_plan_fdr_gate(&mut plan, &policy);
        assert_eq!(again.candidate_targets, 0);
        assert_eq!(plan.gates_summary.blocked_candidates, 1);
        assert!(plan.actions[0].blocked && plan.actions[1].blocked);

        // Saved plans cannot leave an orphan pause executable by changing its
        // stage or action order relative to a refused kill.
        for stage in [0, 1, 2] {
            let kill = plan_kill(10, 0.8);
            let mut pause = kill.clone();
            pause.action_id = "pause-10".into();
            pause.action = Action::Pause;
            pause.stage = stage;
            let mut plan = plan_with(vec![kill, pause]);
            plan.gates_summary.blocked_candidates = usize::MAX;
            let report = apply_plan_fdr_gate(&mut plan, &policy);
            assert_eq!(report.blocked_action_ids, vec!["kill-10", "pause-10"]);
            assert!(plan.actions.iter().all(|action| action.blocked));
            assert_eq!(plan.gates_summary.blocked_candidates, usize::MAX);
        }
    }

    #[test]
    fn plan_fdr_rejects_missing_invalid_or_unbound_posteriors() {
        use crate::inference::ClassScores;
        let policy = crate::config::Policy::default();
        let cases = [
            None,
            Some(ClassScores {
                useful: 0.0,
                useful_bad: 0.0,
                abandoned: 0.8,
                zombie: 0.0,
            }),
            Some(ClassScores {
                useful: f64::NAN,
                useful_bad: 0.0,
                abandoned: 1.0,
                zombie: 0.0,
            }),
            Some(ClassScores {
                useful: f64::INFINITY,
                useful_bad: 0.0,
                abandoned: 1.0,
                zombie: 0.0,
            }),
            Some(ClassScores {
                useful: -0.01,
                useful_bad: 0.0,
                abandoned: 1.01,
                zombie: 0.0,
            }),
        ];
        for posterior in cases {
            let mut action = plan_kill(10, 0.0);
            action.rationale.posterior = posterior;
            let mut plan = plan_with(vec![action]);
            let report = apply_plan_fdr_gate(&mut plan, &policy);
            assert_eq!(report.selected_targets, 0);
            assert_eq!(report.blocked_targets, 1);
            assert!(report.decisions[0].posterior_null_probability.is_none());
            serde_json::to_string(&report).expect("unavailable evidence remains serializable");
        }
        for neighbor in 0..5 {
            let mut action = plan_kill(10, 0.0);
            match neighbor {
                0 => action.target.quality = pt_common::IdentityQuality::PidOnly,
                1 => action.target.start_id = pt_common::StartId::from_linux("boot", 100, 11),
                2 => action.target.start_id = pt_common::StartId::from_linux("unknown", 100, 10),
                3 => action.routing = crate::plan::ActionRouting::ZombieToParent,
                _ => action.original_zombie_target = Some(plan_kill(11, 0.0).target),
            }
            let mut plan = plan_with(vec![action]);
            assert_eq!(apply_plan_fdr_gate(&mut plan, &policy).selected_targets, 0);
        }
    }

    #[test]
    fn plan_fdr_deduplicates_targets_and_refuses_conflicting_evidence() {
        let policy = crate::config::Policy::default();
        let action = plan_kill(10, 0.01);
        let mut duplicate = action.clone();
        duplicate.action_id = "kill-10-second".into();
        let mut plan = plan_with(vec![action.clone(), duplicate.clone()]);
        let report = apply_plan_fdr_gate(&mut plan, &policy);
        assert_eq!(report.candidate_targets, 1);
        assert_eq!(report.selected_targets, 1);
        assert_eq!(report.selected_action_ids.len(), 2);
        assert_eq!(report.expected_fdr, Some(0.01));
        for neighbor in 0..5 {
            let mut changed = duplicate.clone();
            match neighbor {
                0 => changed.rationale.posterior = plan_kill(10, 0.02).rationale.posterior,
                1 => changed.target.sid = Some(50),
                2 => changed.target.start_id = pt_common::StartId::from_linux("boot", 101, 10),
                3 => changed.target.uid = 1001,
                _ => changed.action_id = action.action_id.clone(),
            }
            let mut plan = plan_with(vec![action.clone(), changed]);
            let report = apply_plan_fdr_gate(&mut plan, &policy);
            assert_eq!(report.selected_targets, 0, "neighbor {neighbor}");
            assert!(plan.actions.iter().all(|action| action.blocked));
        }
    }

    #[test]
    fn plan_fdr_honors_null_classes_without_double_counting() {
        let mut policy = crate::config::Policy::default();
        let mut action = plan_kill(10, 0.01);
        action.rationale.posterior = Some(crate::inference::ClassScores {
            useful: 0.01,
            useful_bad: 0.09,
            abandoned: 0.9,
            zombie: 0.0,
        });
        let mut default_null = plan_with(vec![action.clone()]);
        assert_eq!(
            apply_plan_fdr_gate(&mut default_null, &policy).selected_targets,
            0
        );
        policy.fdr_control.lfdr_null = vec!["useful".into(), "useful".into()];
        let mut useful_only = plan_with(vec![action]);
        let report = apply_plan_fdr_gate(&mut useful_only, &policy);
        assert_eq!(report.null_classes, vec!["useful"]);
        assert_eq!(report.selected_targets, 1);
        assert_eq!(report.expected_fdr, Some(0.01));
    }

    #[test]
    fn plan_fdr_explicit_statistical_methods_require_their_own_evidence() {
        use crate::config::policy::FdrMethod as PolicyMethod;
        let mut policy = crate::config::Policy::default();
        for method in [
            PolicyMethod::Bh,
            PolicyMethod::By,
            PolicyMethod::AlphaInvesting,
        ] {
            policy.fdr_control.method = method;
            let mut plan = plan_with(vec![plan_kill(10, 0.0)]);
            let report = apply_plan_fdr_gate(&mut plan, &policy);
            assert_eq!(report.status, "unavailable");
            assert!(report.applied_method.is_none());
            assert!(report.unavailable_reason.is_some());
            assert_eq!(report.selected_targets, 0);
            assert!(plan.actions[0].blocked);
        }
    }

    #[test]
    fn plan_fdr_disabled_and_none_preserve_kills_but_small_batches_do_not_bypass() {
        let mut policy = crate::config::Policy::default();
        policy.fdr_control.min_candidates = Some(100);
        let mut small = plan_with(vec![plan_kill(10, 0.8)]);
        assert_eq!(apply_plan_fdr_gate(&mut small, &policy).selected_targets, 0);
        policy.fdr_control.enabled = false;
        let mut disabled = plan_with(vec![plan_kill(10, 0.8)]);
        assert_eq!(
            apply_plan_fdr_gate(&mut disabled, &policy).status,
            "disabled"
        );
        assert!(!disabled.actions[0].blocked);
        policy.fdr_control.enabled = true;
        policy.fdr_control.method = crate::config::policy::FdrMethod::None;
        let mut none = plan_with(vec![plan_kill(10, 0.8)]);
        assert_eq!(apply_plan_fdr_gate(&mut none, &policy).selected_targets, 1);
        assert!(!none.actions[0].blocked);
    }

    #[test]
    fn plan_fdr_invalid_configuration_fails_closed_and_zero_alpha_is_exact() {
        let mut policy = crate::config::Policy::default();
        for alpha in [f64::NAN, f64::INFINITY, -0.1, 1.1] {
            policy.fdr_control.alpha = alpha;
            let mut plan = plan_with(vec![plan_kill(10, 0.0)]);
            let report = apply_plan_fdr_gate(&mut plan, &policy);
            assert_eq!(report.status, "unavailable");
            assert!(plan.actions[0].blocked);
            serde_json::to_string(&report).expect("invalid config still gives structured refusal");
        }
        policy.fdr_control.alpha = 0.0;
        let mut zero = plan_with(vec![plan_kill(10, 0.0), plan_kill(11, 1e-12)]);
        assert_eq!(
            apply_plan_fdr_gate(&mut zero, &policy).selected_action_ids,
            vec!["kill-10"]
        );
        policy.fdr_control.lfdr_null = vec!["usefull".into()];
        let mut invalid_class = plan_with(vec![plan_kill(10, 0.0)]);
        assert_eq!(
            apply_plan_fdr_gate(&mut invalid_class, &policy).status,
            "unavailable"
        );
        assert!(invalid_class.actions[0].blocked);
    }

    fn make_candidate(pid: i32, e_value: f64) -> FdrCandidate {
        FdrCandidate {
            target: TargetIdentity {
                pid,
                start_id: format!("{}-12345-boot123", pid),
                uid: 1000,
            },
            e_value,
        }
    }

    #[test]
    fn test_ebh_simple_selection() {
        // e-values: [10, 5, 2, 0.5]
        // m = 4, alpha = 0.1
        // Thresholds at ranks 1,2,3,4: 40, 20, 13.33, 10
        // e_(1)=10 < 40: not selected at k=1
        // e_(2)=5 < 20: not selected at k=2
        // e_(3)=2 < 13.33: not selected at k=3
        // e_(4)=0.5 < 10: not selected at k=4
        // So k=0
        let candidates = vec![
            make_candidate(1, 10.0),
            make_candidate(2, 5.0),
            make_candidate(3, 2.0),
            make_candidate(4, 0.5),
        ];
        let result = select_fdr(&candidates, 0.1, FdrMethod::EBh).unwrap();
        assert_eq!(result.selected_k, 0);
    }

    #[test]
    fn test_ebh_high_evidence_selection() {
        // e-values: [100, 50, 20, 1]
        // m = 4, alpha = 0.1
        // Thresholds at ranks 1,2,3,4: 40, 20, 13.33, 10
        // e_(1)=100 >= 40: can select k>=1
        // e_(2)=50 >= 20: can select k>=2
        // e_(3)=20 >= 13.33: can select k>=3
        // e_(4)=1 < 10: cannot extend to k=4
        // So k=3
        let candidates = vec![
            make_candidate(1, 100.0),
            make_candidate(2, 50.0),
            make_candidate(3, 20.0),
            make_candidate(4, 1.0),
        ];
        let result = select_fdr(&candidates, 0.1, FdrMethod::EBh).unwrap();
        assert_eq!(result.selected_k, 3);
        assert_eq!(result.selected_ids.len(), 3);
        // Verify correct PIDs selected (sorted by e-value)
        let selected_pids: Vec<i32> = result.selected_ids.iter().map(|t| t.pid).collect();
        assert_eq!(selected_pids, vec![1, 2, 3]);
    }

    #[test]
    fn test_eby_is_more_conservative() {
        // Same e-values but with BY correction
        let candidates = vec![
            make_candidate(1, 100.0),
            make_candidate(2, 50.0),
            make_candidate(3, 20.0),
            make_candidate(4, 1.0),
        ];

        let ebh = select_fdr(&candidates, 0.1, FdrMethod::EBh).unwrap();
        let eby = select_fdr(&candidates, 0.1, FdrMethod::EBy).unwrap();

        // BY should select same or fewer
        assert!(eby.selected_k <= ebh.selected_k);
        assert!(eby.correction_factor.is_some());
        // c(4) = 1 + 1/2 + 1/3 + 1/4 ≈ 2.083
        let c4 = by_correction_factor(4);
        assert!((c4 - 2.083).abs() < 0.01);
    }

    #[test]
    fn test_deterministic_ordering() {
        // Selection should be deterministic for same inputs
        let candidates = vec![
            make_candidate(3, 15.0),
            make_candidate(1, 50.0),
            make_candidate(2, 30.0),
        ];

        let result1 = select_fdr(&candidates, 0.1, FdrMethod::EBh).unwrap();
        let result2 = select_fdr(&candidates, 0.1, FdrMethod::EBh).unwrap();

        assert_eq!(result1.selected_k, result2.selected_k);
        assert_eq!(result1.candidates.len(), result2.candidates.len());
        for (c1, c2) in result1.candidates.iter().zip(result2.candidates.iter()) {
            assert_eq!(c1.rank, c2.rank);
            assert_eq!(c1.selected, c2.selected);
        }
    }

    #[test]
    fn test_monotonicity() {
        // Increasing any e-value should never decrease k
        let base = vec![
            make_candidate(1, 50.0),
            make_candidate(2, 30.0),
            make_candidate(3, 10.0),
        ];
        let base_result = select_fdr(&base, 0.1, FdrMethod::EBh).unwrap();

        // Increase one e-value
        let increased = vec![
            make_candidate(1, 100.0), // Doubled
            make_candidate(2, 30.0),
            make_candidate(3, 10.0),
        ];
        let inc_result = select_fdr(&increased, 0.1, FdrMethod::EBh).unwrap();

        assert!(inc_result.selected_k >= base_result.selected_k);
    }

    #[test]
    fn test_invalid_alpha() {
        let candidates = vec![make_candidate(1, 10.0)];
        assert!(select_fdr(&candidates, 0.0, FdrMethod::EBh).is_err());
        assert!(select_fdr(&candidates, -0.1, FdrMethod::EBh).is_err());
        assert!(select_fdr(&candidates, 1.5, FdrMethod::EBh).is_err());
    }

    #[test]
    fn test_empty_candidates() {
        assert!(select_fdr(&[], 0.1, FdrMethod::EBh).is_err());
    }

    #[test]
    fn test_negative_evalue() {
        let candidates = vec![make_candidate(1, -1.0)];
        assert!(select_fdr(&candidates, 0.1, FdrMethod::EBh).is_err());
    }

    #[test]
    fn test_none_method_selects_evalue_gt_1() {
        let candidates = vec![
            make_candidate(1, 2.0), // > 1, selected
            make_candidate(2, 1.5), // > 1, selected
            make_candidate(3, 0.8), // < 1, not selected
            make_candidate(4, 0.1), // < 1, not selected
        ];
        let result = select_fdr(&candidates, 0.1, FdrMethod::None).unwrap();
        assert_eq!(result.selected_k, 2);
    }

    #[test]
    fn test_by_correction_factor_computation() {
        // c(1) = 1
        assert!((by_correction_factor(1) - 1.0).abs() < 1e-10);
        // c(2) = 1 + 0.5 = 1.5
        assert!((by_correction_factor(2) - 1.5).abs() < 1e-10);
        // c(3) = 1 + 0.5 + 0.333... ≈ 1.833
        assert!((by_correction_factor(3) - 1.833333).abs() < 0.001);
        // c(10) ≈ 2.928
        assert!((by_correction_factor(10) - 2.928968).abs() < 0.001);
    }

    #[test]
    fn test_p_value_derivation() {
        let candidates = vec![
            make_candidate(1, 10.0), // p = 0.1
            make_candidate(2, 2.0),  // p = 0.5
            make_candidate(3, 0.5),  // p = 1.0 (capped)
        ];
        let result = select_fdr(&candidates, 0.5, FdrMethod::EBh).unwrap();

        // Check p-values in sorted order
        assert!((result.candidates[0].p_value - 0.1).abs() < 1e-10);
        assert!((result.candidates[1].p_value - 0.5).abs() < 1e-10);
        assert!((result.candidates[2].p_value - 1.0).abs() < 1e-10);
    }
}
