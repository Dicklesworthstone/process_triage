//! Action plan generation from decision outputs.
//!
//! Converts per-candidate decision results into a deterministic, resumable plan.

use crate::config::Policy;
use crate::decision::{Action, DecisionOutcome, SprtBoundary};
use chrono::Utc;
use pt_common::{ProcessIdentity, SessionId};
use serde::Serialize;

/// Decision bundle input to the planner.
#[derive(Debug, Clone)]
pub struct DecisionBundle {
    pub session_id: SessionId,
    pub policy: Policy,
    pub candidates: Vec<DecisionCandidate>,
    pub generated_at: Option<String>,
}

/// Per-candidate decision input to the planner.
#[derive(Debug, Clone)]
pub struct DecisionCandidate {
    pub identity: ProcessIdentity,
    pub ppid: Option<u32>,
    pub decision: DecisionOutcome,
    pub blocked_reasons: Vec<String>,
    pub stage_pause_before_kill: bool,
}

/// Action plan output.
#[derive(Debug, Clone, Serialize)]
pub struct Plan {
    pub plan_id: String,
    pub session_id: String,
    pub generated_at: String,
    pub policy_id: Option<String>,
    pub policy_version: String,
    pub actions: Vec<PlanAction>,
    pub pre_toggled: Vec<String>,
    pub gates_summary: GatesSummary,
}

/// High-level gate summary for the plan.
#[derive(Debug, Clone, Serialize)]
pub struct GatesSummary {
    pub total_candidates: usize,
    pub blocked_candidates: usize,
    pub pre_toggled_actions: usize,
}

/// A single action in a plan.
#[derive(Debug, Clone, Serialize)]
pub struct PlanAction {
    pub action_id: String,
    pub target: ProcessIdentity,
    pub action: Action,
    pub order: u32,
    pub stage: u8,
    pub timeouts: ActionTimeouts,
    pub pre_checks: Vec<PreCheck>,
    pub rationale: ActionRationale,
    pub on_success: Vec<ActionHook>,
    pub on_failure: Vec<ActionHook>,
    pub blocked: bool,
}

/// Action timeouts for staged execution.
#[derive(Debug, Clone, Serialize)]
pub struct ActionTimeouts {
    pub preflight_ms: u64,
    pub execute_ms: u64,
    pub verify_ms: u64,
}

impl Default for ActionTimeouts {
    fn default() -> Self {
        Self {
            preflight_ms: 2_000,
            execute_ms: 10_000,
            verify_ms: 5_000,
        }
    }
}

/// Preconditions that must be revalidated at apply time.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PreCheck {
    VerifyIdentity,
    CheckNotProtected,
    CheckSessionSafety,
    CheckDataLossGate,
    CheckSupervisor,
}

/// Structured action rationale.
#[derive(Debug, Clone, Serialize)]
pub struct ActionRationale {
    pub expected_loss: Option<f64>,
    pub expected_recovery: Option<f64>,
    pub expected_recovery_stddev: Option<f64>,
    pub posterior_odds_abandoned_vs_useful: Option<f64>,
    pub sprt_boundary: Option<SprtBoundary>,
}

/// Simple action hook for success/failure paths.
#[derive(Debug, Clone, Serialize)]
pub struct ActionHook {
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// Generate a deterministic action plan from a decision bundle.
pub fn generate_plan(bundle: &DecisionBundle) -> Plan {
    let generated_at = bundle
        .generated_at
        .clone()
        .unwrap_or_else(|| Utc::now().to_rfc3339());

    let mut actions = Vec::new();
    let mut pre_toggled = Vec::new();
    let mut blocked_candidates = 0;

    for candidate in &bundle.candidates {
        let blocked = !candidate.blocked_reasons.is_empty();
        if blocked {
            blocked_candidates += 1;
        }

        let mut action_sequence = Vec::new();
        if candidate.decision.optimal_action == Action::Kill && candidate.stage_pause_before_kill {
            action_sequence.push((Action::Pause, 0));
            action_sequence.push((Action::Kill, 1));
        } else if candidate.decision.optimal_action != Action::Keep {
            action_sequence.push((candidate.decision.optimal_action, 0));
        } else {
            continue;
        }

        for (action, stage) in action_sequence {
            let action_id = action_id_for(action, &candidate.identity, stage);
            if !blocked {
                pre_toggled.push(action_id.clone());
            }

            let expected_loss = loss_for_action(&candidate.decision, action);
            let (expected_recovery, expected_recovery_stddev) =
                recovery_stats_for_action(&candidate.decision, action);
            let rationale = ActionRationale {
                expected_loss,
                expected_recovery,
                expected_recovery_stddev,
                posterior_odds_abandoned_vs_useful: candidate
                    .decision
                    .posterior_odds_abandoned_vs_useful,
                sprt_boundary: candidate.decision.sprt_boundary.clone(),
            };

            actions.push(PlanAction {
                action_id,
                target: candidate.identity.clone(),
                action,
                order: 0,
                stage,
                timeouts: ActionTimeouts::default(),
                pre_checks: pre_checks_for(action),
                rationale,
                on_success: vec![],
                on_failure: vec![ActionHook {
                    action: "report_failure".to_string(),
                    details: None,
                }],
                blocked,
            });
        }
    }

    actions.sort_by(|a, b| {
        let key_a = sort_key(bundle, a);
        let key_b = sort_key(bundle, b);
        key_a.cmp(&key_b)
    });

    for (idx, action) in actions.iter_mut().enumerate() {
        action.order = idx as u32;
    }

    let plan_id = plan_id_for(&bundle.session_id, bundle.policy.policy_id.as_deref(), actions.len());

    Plan {
        plan_id,
        session_id: bundle.session_id.0.clone(),
        generated_at,
        policy_id: bundle.policy.policy_id.clone(),
        policy_version: bundle.policy.schema_version.clone(),
        actions,
        pre_toggled: pre_toggled.clone(),
        gates_summary: GatesSummary {
            total_candidates: bundle.candidates.len(),
            blocked_candidates,
            pre_toggled_actions: pre_toggled.len(),
        },
    }
}

fn pre_checks_for(action: Action) -> Vec<PreCheck> {
    let mut checks = vec![
        PreCheck::VerifyIdentity,
        PreCheck::CheckNotProtected,
        PreCheck::CheckSessionSafety,
    ];
    match action {
        Action::Kill | Action::Restart => {
            checks.push(PreCheck::CheckDataLossGate);
            checks.push(PreCheck::CheckSupervisor);
        }
        Action::Pause | Action::Throttle => {
            checks.push(PreCheck::CheckSupervisor);
        }
        Action::Keep => {}
    }
    checks
}

fn loss_for_action(decision: &DecisionOutcome, action: Action) -> Option<f64> {
    decision
        .expected_loss
        .iter()
        .find(|e| e.action == action)
        .map(|e| e.loss)
}

fn recovery_stats_for_action(
    decision: &DecisionOutcome,
    action: Action,
) -> (Option<f64>, Option<f64>) {
    match decision.recovery_expectations.as_ref() {
        Some(expectations) => expectations
            .iter()
            .find(|entry| entry.action == action)
            .map(|entry| (Some(entry.probability), entry.std_dev))
            .unwrap_or((None, None)),
        None => (None, None),
    }
}

fn plan_id_for(session_id: &SessionId, policy_id: Option<&str>, action_count: usize) -> String {
    let key = format!(
        "{}:{}:{}",
        session_id.0,
        policy_id.unwrap_or("unknown"),
        action_count
    );
    let hash = fnv1a64(key.as_bytes());
    format!("plan-{hash:016x}")
}

fn action_id_for(action: Action, identity: &ProcessIdentity, stage: u8) -> String {
    let key = format!(
        "{}:{}:{}:{}:{}",
        action_str(action),
        identity.pid.0,
        identity.start_id.0,
        identity.uid,
        stage
    );
    let hash = fnv1a64(key.as_bytes());
    format!("act-{hash:016x}")
}

fn action_str(action: Action) -> &'static str {
    match action {
        Action::Keep => "keep",
        Action::Pause => "pause",
        Action::Throttle => "throttle",
        Action::Restart => "restart",
        Action::Kill => "kill",
    }
}

fn sort_key(bundle: &DecisionBundle, action: &PlanAction) -> (u8, u32, u8, i64, String, String) {
    let tier = action_tier(action.action);
    let group = bundle
        .candidates
        .iter()
        .find(|c| c.identity.pid == action.target.pid)
        .and_then(|c| c.identity.pgid)
        .unwrap_or(action.target.pid.0);
    let benefit = bundle
        .candidates
        .iter()
        .find(|c| c.identity.pid == action.target.pid)
        .and_then(|c| {
            loss_for_action(&c.decision, Action::Keep).map(|keep_loss| {
                loss_for_action(&c.decision, action.action)
                    .unwrap_or(keep_loss)
                    .mul_add(-1.0, keep_loss)
            })
        })
        .unwrap_or(0.0);
    let benefit_key = (benefit * 1_000_000.0).round() as i64;
    let identity_key = format!("{}:{}:{}", action.target.pid.0, action.target.uid, action.target.start_id.0);
    (tier, group, action.stage, -benefit_key, identity_key, action.action_id.clone())
}

fn action_tier(action: Action) -> u8 {
    match action {
        Action::Keep => 0,
        Action::Pause => 1,
        Action::Throttle => 1,
        Action::Restart => 2,
        Action::Kill => 3,
    }
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::{DecisionOutcome, ExpectedLoss};
    use pt_common::{ProcessId, StartId};

    fn decision_with_action(action: Action, keep_loss: f64, action_loss: f64) -> DecisionOutcome {
        DecisionOutcome {
            expected_loss: vec![
                ExpectedLoss {
                    action: Action::Keep,
                    loss: keep_loss,
                },
                ExpectedLoss {
                    action,
                    loss: action_loss,
                },
            ],
            optimal_action: action,
            sprt_boundary: None,
            posterior_odds_abandoned_vs_useful: None,
            recovery_expectations: None,
            rationale: crate::decision::DecisionRationale {
                chosen_action: action,
                tie_break: false,
                disabled_actions: vec![],
            },
        }
    }

    fn identity(pid: u32) -> ProcessIdentity {
        ProcessIdentity {
            pid: ProcessId(pid),
            start_id: StartId(format!("boot:{pid}:{pid}")),
            uid: 1000,
            pgid: Some(pid + 10),
            sid: None,
            quality: pt_common::IdentityQuality::Full,
        }
    }

    #[test]
    fn action_id_is_stable() {
        let id = identity(42);
        let a1 = action_id_for(Action::Pause, &id, 0);
        let a2 = action_id_for(Action::Pause, &id, 0);
        assert_eq!(a1, a2);
    }

    #[test]
    fn pre_toggled_excludes_blocked() {
        let bundle = DecisionBundle {
            session_id: SessionId("pt-20260115-120000-abcd".to_string()),
            policy: Policy::default(),
            generated_at: Some("2026-01-15T12:00:00Z".to_string()),
            candidates: vec![
                DecisionCandidate {
                    identity: identity(10),
                    ppid: None,
                    decision: decision_with_action(Action::Pause, 10.0, 1.0),
                    blocked_reasons: vec![],
                    stage_pause_before_kill: false,
                },
                DecisionCandidate {
                    identity: identity(20),
                    ppid: None,
                    decision: decision_with_action(Action::Pause, 10.0, 1.0),
                    blocked_reasons: vec!["policy blocked".to_string()],
                    stage_pause_before_kill: false,
                },
            ],
        };
        let plan = generate_plan(&bundle);
        assert_eq!(plan.pre_toggled.len(), 1);
    }

    #[test]
    fn staging_inserts_pause_before_kill() {
        let bundle = DecisionBundle {
            session_id: SessionId("pt-20260115-120000-abcd".to_string()),
            policy: Policy::default(),
            generated_at: Some("2026-01-15T12:00:00Z".to_string()),
            candidates: vec![DecisionCandidate {
                identity: identity(30),
                ppid: None,
                decision: decision_with_action(Action::Kill, 100.0, 1.0),
                blocked_reasons: vec![],
                stage_pause_before_kill: true,
            }],
        };
        let plan = generate_plan(&bundle);
        assert_eq!(plan.actions.len(), 2);
        assert_eq!(plan.actions[0].action, Action::Pause);
        assert_eq!(plan.actions[1].action, Action::Kill);
    }

    #[test]
    fn deterministic_ordering() {
        let mut bundle = DecisionBundle {
            session_id: SessionId("pt-20260115-120000-abcd".to_string()),
            policy: Policy::default(),
            generated_at: Some("2026-01-15T12:00:00Z".to_string()),
            candidates: vec![
                DecisionCandidate {
                    identity: identity(2),
                    ppid: None,
                    decision: decision_with_action(Action::Pause, 10.0, 1.0),
                    blocked_reasons: vec![],
                    stage_pause_before_kill: false,
                },
                DecisionCandidate {
                    identity: identity(1),
                    ppid: None,
                    decision: decision_with_action(Action::Pause, 10.0, 2.0),
                    blocked_reasons: vec![],
                    stage_pause_before_kill: false,
                },
            ],
        };
        let plan1 = generate_plan(&bundle);
        bundle.candidates.reverse();
        let plan2 = generate_plan(&bundle);
        let ids1: Vec<String> = plan1.actions.iter().map(|a| a.action_id.clone()).collect();
        let ids2: Vec<String> = plan2.actions.iter().map(|a| a.action_id.clone()).collect();
        assert_eq!(ids1, ids2);
    }
}
