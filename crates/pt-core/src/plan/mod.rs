//! Action plan generation from decision outputs.
//!
//! Converts per-candidate decision results into a deterministic, resumable plan.
//!
//! # Special Process State Handling
//!
//! ## Zombie (Z-state)
//! Zombie processes are already dead and cannot be killed. The planner routes
//! actions targeting zombies to their parent process or supervisor instead.
//!
//! ## D-state (Uninterruptible Sleep)
//! D-state processes may ignore SIGKILL while waiting on kernel I/O. The planner
//! marks any kill-like actions as low-confidence and surfaces diagnostics.

use crate::collect::ProcessState;
use crate::config::Policy;
use crate::decision::{Action, DecisionOutcome, SprtBoundary};
use chrono::Utc;
use pt_common::{ProcessIdentity, SessionId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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
    /// Current process state (Z, D, etc.) for special handling.
    pub process_state: Option<ProcessState>,
    /// Parent process identity for zombie routing.
    pub parent_identity: Option<ProcessIdentity>,
    /// D-state diagnostics if process is in uninterruptible sleep.
    pub d_state_diagnostics: Option<DStateDiagnostics>,
}

/// Diagnostics for D-state (uninterruptible sleep) processes.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct DStateDiagnostics {
    /// Kernel function where process is blocked (from /proc/[pid]/wchan).
    pub wchan: Option<String>,
    /// I/O read bytes at time of detection.
    pub io_read_bytes: Option<u64>,
    /// I/O write bytes at time of detection.
    pub io_write_bytes: Option<u64>,
    /// Time spent in D-state (if known).
    pub d_state_duration_ms: Option<u64>,
}

/// Action plan output.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
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
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct GatesSummary {
    pub total_candidates: usize,
    pub blocked_candidates: usize,
    pub pre_toggled_actions: usize,
}

/// A single action in a plan.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
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
    /// How the action was routed (direct, zombie-to-parent, etc.).
    #[serde(default, skip_serializing_if = "is_direct_routing")]
    pub routing: ActionRouting,
    /// Confidence level for this action.
    #[serde(default, skip_serializing_if = "is_normal_confidence")]
    pub confidence: ActionConfidence,
    /// Original target if this action was rerouted from a zombie.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_zombie_target: Option<ProcessIdentity>,
    /// D-state diagnostics if targeting a D-state process.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d_state_diagnostics: Option<DStateDiagnostics>,
}



fn is_direct_routing(routing: &ActionRouting) -> bool {
    *routing == ActionRouting::Direct
}

fn is_normal_confidence(confidence: &ActionConfidence) -> bool {
    *confidence == ActionConfidence::Normal
}

/// Action timeouts for staged execution.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PreCheck {
    VerifyIdentity,
    CheckNotProtected,
    CheckSessionSafety,
    CheckDataLossGate,
    CheckSupervisor,
    CheckAgentSupervision,
    /// Verify process is still in expected state (not zombie/D-state if expecting killable).
    VerifyProcessState,
}

/// Why an action was routed differently than the direct target.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum ActionRouting {
    /// Direct action on the target process.
    #[default]
    Direct,
    /// Zombie: routed to parent process.
    ZombieToParent,
    /// Zombie: routed to supervisor (systemd, docker, etc.).
    ZombieToSupervisor,
    /// Zombie: investigate only (no viable parent/supervisor).
    ZombieInvestigateOnly,
    /// D-state: low confidence, may not succeed.
    DStateLowConfidence,
}

/// Confidence level for action success.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum ActionConfidence {
    /// Normal confidence - action should succeed.
    #[default]
    Normal,
    /// Low confidence - action may fail due to process state (D-state).
    Low,
    /// Very low - action is unlikely to succeed.
    VeryLow,
}

/// Structured action rationale.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ActionRationale {
    pub expected_loss: Option<f64>,
    pub expected_recovery: Option<f64>,
    pub expected_recovery_stddev: Option<f64>,
    pub posterior_odds_abandoned_vs_useful: Option<f64>,
    pub sprt_boundary: Option<SprtBoundary>,
    // Extended fields for context
    pub posterior: Option<crate::inference::ClassScores>,
    pub memory_mb: Option<f64>,
    pub has_known_signature: Option<bool>,
    pub category: Option<String>,
}

/// Simple action hook for success/failure paths.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ActionHook {
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// Generate a deterministic action plan from a decision bundle.
///
/// Handles special process states:
/// - **Zombie (Z)**: Routes kill/restart actions to parent process or supervisor.
///   Cannot kill a zombie directly; must get parent to reap it.
/// - **D-state (D)**: Marks actions as low-confidence since process may ignore signals.
///   Includes diagnostics (wchan, I/O counters) for debugging.
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

        // Check for zombie state - route to parent/supervisor instead
        if candidate.process_state == Some(ProcessState::Zombie) {
            if let Some(zombie_actions) = plan_zombie_actions(candidate, blocked) {
                for plan_action in zombie_actions {
                    if !blocked && !plan_action.blocked {
                        pre_toggled.push(plan_action.action_id.clone());
                    }
                    actions.push(plan_action);
                }
            }
            continue;
        }

        // Check for D-state - mark as low-confidence
        let is_d_state = candidate.process_state == Some(ProcessState::DiskSleep);

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
                posterior: candidate.decision.rationale.posterior,
                memory_mb: candidate.decision.rationale.memory_mb,
                has_known_signature: candidate.decision.rationale.has_known_signature,
                category: candidate.decision.rationale.category.clone(),
            };

            // Determine confidence and routing for D-state
            let (confidence, routing, d_state_diag) = if is_d_state {
                let confidence = if action == Action::Kill || action == Action::Restart {
                    ActionConfidence::Low
                } else {
                    ActionConfidence::Normal
                };
                (
                    confidence,
                    ActionRouting::DStateLowConfidence,
                    candidate.d_state_diagnostics.clone(),
                )
            } else {
                (ActionConfidence::Normal, ActionRouting::Direct, None)
            };

            let mut pre_checks = pre_checks_for(action);
            // Add state verification only for actions likely to fail in D-state
            if is_d_state && matches!(action, Action::Kill | Action::Restart) {
                pre_checks.push(PreCheck::VerifyProcessState);
            }

            actions.push(PlanAction {
                action_id,
                target: candidate.identity.clone(),
                action,
                order: 0,
                stage,
                timeouts: ActionTimeouts::default(),
                pre_checks,
                rationale,
                on_success: vec![],
                on_failure: vec![ActionHook {
                    action: "report_failure".to_string(),
                    details: if is_d_state {
                        Some("process was in D-state (uninterruptible sleep)".to_string())
                    } else {
                        None
                    },
                }],
                blocked,
                routing,
                confidence,
                original_zombie_target: None,
                d_state_diagnostics: d_state_diag,
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

    let plan_id = plan_id_for(
        &bundle.session_id,
        bundle.policy.policy_id.as_deref(),
        actions.len(),
    );

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

/// Plan actions for a zombie process.
///
/// Zombies cannot be killed directly - they are already dead. Instead, we must:
/// 1. If parent identity is known, signal/restart the parent to reap the zombie
/// 2. If process is supervised, use supervisor to restart the service
/// 3. If neither is available, emit an "investigate only" action
///
/// Returns None if no action is appropriate (e.g., decision was Keep).
fn plan_zombie_actions(candidate: &DecisionCandidate, blocked: bool) -> Option<Vec<PlanAction>> {
    let original_action = candidate.decision.optimal_action;

    // If decision is Keep, no action needed
    if original_action == Action::Keep {
        return None;
    }

    // For zombies, we cannot perform direct kill/restart - route to parent or supervisor
    let is_destructive = matches!(original_action, Action::Kill | Action::Restart);

    let expected_loss = loss_for_action(&candidate.decision, original_action);
    let (expected_recovery, expected_recovery_stddev) =
        recovery_stats_for_action(&candidate.decision, original_action);
    let base_rationale = ActionRationale {
        expected_loss,
        expected_recovery,
        expected_recovery_stddev,
        posterior_odds_abandoned_vs_useful: candidate.decision.posterior_odds_abandoned_vs_useful,
        sprt_boundary: candidate.decision.sprt_boundary.clone(),
        posterior: candidate.decision.rationale.posterior,
        memory_mb: candidate.decision.rationale.memory_mb,
        has_known_signature: candidate.decision.rationale.has_known_signature,
        category: candidate.decision.rationale.category.clone(),
    };

    let mut actions = Vec::new();

    if is_destructive {
        // Try to route to parent
        if let Some(ref parent_identity) = candidate.parent_identity {
            // Signal the parent to reap the zombie
            // For Kill -> signal parent with SIGCHLD or restart it
            // For Restart -> restart the parent
            // Regardless of original action, restart parent to force zombie reap
            let parent_action = Action::Restart;

            let action_id = action_id_for(parent_action, parent_identity, 0);

            actions.push(PlanAction {
                action_id,
                target: parent_identity.clone(),
                action: parent_action,
                order: 0,
                stage: 0,
                timeouts: ActionTimeouts::default(),
                pre_checks: vec![
                    PreCheck::VerifyIdentity,
                    PreCheck::CheckNotProtected,
                    PreCheck::CheckSessionSafety,
                    PreCheck::CheckDataLossGate,
                    PreCheck::CheckSupervisor,
                    PreCheck::CheckAgentSupervision,
                ],
                rationale: base_rationale.clone(),
                on_success: vec![ActionHook {
                    action: "zombie_reaped".to_string(),
                    details: Some(format!(
                        "parent restart should reap zombie PID {}",
                        candidate.identity.pid.0
                    )),
                }],
                on_failure: vec![ActionHook {
                    action: "report_failure".to_string(),
                    details: Some("failed to restart parent of zombie".to_string()),
                }],
                blocked,
                routing: ActionRouting::ZombieToParent,
                confidence: ActionConfidence::Normal,
                original_zombie_target: Some(candidate.identity.clone()),
                d_state_diagnostics: None,
            });
        } else {
            // No parent identity available - emit investigate-only action
            // This is an informational action that doesn't execute anything
            // but makes it clear we can't help without more info
            let action_id = action_id_for(Action::Keep, &candidate.identity, 0);

            actions.push(PlanAction {
                action_id,
                target: candidate.identity.clone(),
                action: Action::Keep, // Keep (investigate) - we cannot act on this
                order: 0,
                stage: 0,
                timeouts: ActionTimeouts::default(),
                pre_checks: vec![PreCheck::VerifyIdentity],
                rationale: base_rationale,
                on_success: vec![],
                on_failure: vec![],
                blocked: true, // Always blocked - investigation only
                routing: ActionRouting::ZombieInvestigateOnly,
                confidence: ActionConfidence::VeryLow,
                original_zombie_target: None,
                d_state_diagnostics: None,
            });
        }
    } else {
        // Non-destructive actions (Pause, Renice, Throttle) don't make sense for zombies
        // Zombies are already dead - they consume no resources except a process table entry
        // Emit a Keep action to indicate we're doing nothing
        let action_id = action_id_for(Action::Keep, &candidate.identity, 0);

        actions.push(PlanAction {
            action_id,
            target: candidate.identity.clone(),
            action: Action::Keep,
            order: 0,
            stage: 0,
            timeouts: ActionTimeouts::default(),
            pre_checks: vec![PreCheck::VerifyIdentity],
            rationale: base_rationale,
            on_success: vec![],
            on_failure: vec![],
            blocked: true,
            routing: ActionRouting::ZombieInvestigateOnly,
            confidence: ActionConfidence::VeryLow,
            original_zombie_target: None,
            d_state_diagnostics: None,
        });
    }

    Some(actions)
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
            checks.push(PreCheck::CheckAgentSupervision);
        }
        Action::Pause
        | Action::Throttle
        | Action::Renice
        | Action::Freeze
        | Action::Unfreeze
        | Action::Quarantine => {
            checks.push(PreCheck::CheckSupervisor);
            checks.push(PreCheck::CheckAgentSupervision);
        }
        // Resume/Unquarantine only need identity verification
        Action::Resume | Action::Unquarantine => {}
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
        Action::Renice => "renice",
        Action::Pause => "pause",
        Action::Resume => "resume",
        Action::Throttle => "throttle",
        Action::Restart => "restart",
        Action::Kill => "kill",
        Action::Freeze => "freeze",
        Action::Unfreeze => "unfreeze",
        Action::Quarantine => "quarantine",
        Action::Unquarantine => "unquarantine",
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
    let identity_key = format!(
        "{}:{}:{}",
        action.target.pid.0, action.target.uid, action.target.start_id.0
    );
    (
        tier,
        group,
        action.stage,
        -benefit_key,
        identity_key,
        action.action_id.clone(),
    )
}

fn action_tier(action: Action) -> u8 {
    match action {
        Action::Keep => 0,
        Action::Renice => 1,
        Action::Pause => 1,
        Action::Resume => 1, // Same tier as Pause (reversible)
        Action::Throttle => 1,
        Action::Freeze => 1,       // Reversible via Unfreeze
        Action::Unfreeze => 1,     // Same tier as Freeze (reversible)
        Action::Quarantine => 1,   // Reversible via Unquarantine
        Action::Unquarantine => 1, // Same tier as Quarantine (reversible)
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
                used_recovery_preference: false,
                posterior: None,
                memory_mb: None,
                has_known_signature: None,
                category: None,
            },
            risk_sensitive: None,
            dro: None,
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

    /// Helper to create a candidate with optional state info
    fn candidate(pid: u32, action: Action, keep_loss: f64, action_loss: f64) -> DecisionCandidate {
        DecisionCandidate {
            identity: identity(pid),
            ppid: None,
            decision: decision_with_action(action, keep_loss, action_loss),
            blocked_reasons: vec![],
            stage_pause_before_kill: false,
            process_state: None,
            parent_identity: None,
            d_state_diagnostics: None,
        }
    }

    #[test]
    fn pre_toggled_excludes_blocked() {
        let bundle = DecisionBundle {
            session_id: SessionId("pt-20260115-120000-abcd".to_string()),
            policy: Policy::default(),
            generated_at: Some("2026-01-15T12:00:00Z".to_string()),
            candidates: vec![candidate(10, Action::Pause, 10.0, 1.0), {
                let mut c = candidate(20, Action::Pause, 10.0, 1.0);
                c.blocked_reasons = vec!["policy blocked".to_string()];
                c
            }],
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
            candidates: vec![{
                let mut c = candidate(30, Action::Kill, 100.0, 1.0);
                c.stage_pause_before_kill = true;
                c
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
                candidate(2, Action::Pause, 10.0, 1.0),
                candidate(1, Action::Pause, 10.0, 2.0),
            ],
        };
        let plan1 = generate_plan(&bundle);
        bundle.candidates.reverse();
        let plan2 = generate_plan(&bundle);
        let ids1: Vec<String> = plan1.actions.iter().map(|a| a.action_id.clone()).collect();
        let ids2: Vec<String> = plan2.actions.iter().map(|a| a.action_id.clone()).collect();
        assert_eq!(ids1, ids2);
    }

    // =========================================================================
    // Zombie (Z-state) Process Tests
    // =========================================================================

    #[test]
    fn zombie_kill_routes_to_parent() {
        let parent_id = identity(100);
        let bundle = DecisionBundle {
            session_id: SessionId("pt-20260115-120000-abcd".to_string()),
            policy: Policy::default(),
            generated_at: Some("2026-01-15T12:00:00Z".to_string()),
            candidates: vec![{
                let mut c = candidate(42, Action::Kill, 100.0, 1.0);
                c.process_state = Some(ProcessState::Zombie);
                c.parent_identity = Some(parent_id.clone());
                c
            }],
        };
        let plan = generate_plan(&bundle);

        // Should have one action targeting the parent, not the zombie
        assert_eq!(plan.actions.len(), 1);
        let action = &plan.actions[0];
        assert_eq!(action.target.pid, parent_id.pid);
        assert_eq!(action.action, Action::Restart);
        assert_eq!(action.routing, ActionRouting::ZombieToParent);
        assert!(action.original_zombie_target.is_some());
        assert_eq!(action.original_zombie_target.as_ref().unwrap().pid.0, 42);
        assert!(action.pre_checks.contains(&PreCheck::CheckAgentSupervision));
    }

    #[test]
    fn zombie_without_parent_emits_investigate_only() {
        let bundle = DecisionBundle {
            session_id: SessionId("pt-20260115-120000-abcd".to_string()),
            policy: Policy::default(),
            generated_at: Some("2026-01-15T12:00:00Z".to_string()),
            candidates: vec![{
                let mut c = candidate(42, Action::Kill, 100.0, 1.0);
                c.process_state = Some(ProcessState::Zombie);
                c.parent_identity = None; // No parent available
                c
            }],
        };
        let plan = generate_plan(&bundle);

        assert_eq!(plan.actions.len(), 1);
        let action = &plan.actions[0];
        assert_eq!(action.target.pid.0, 42);
        assert_eq!(action.action, Action::Keep); // Investigation only
        assert_eq!(action.routing, ActionRouting::ZombieInvestigateOnly);
        assert!(action.blocked); // Always blocked for investigate-only
        assert_eq!(action.confidence, ActionConfidence::VeryLow);
    }

    #[test]
    fn zombie_pause_converted_to_keep() {
        // Pause on a zombie doesn't make sense - it's already dead
        let bundle = DecisionBundle {
            session_id: SessionId("pt-20260115-120000-abcd".to_string()),
            policy: Policy::default(),
            generated_at: Some("2026-01-15T12:00:00Z".to_string()),
            candidates: vec![{
                let mut c = candidate(42, Action::Pause, 10.0, 1.0);
                c.process_state = Some(ProcessState::Zombie);
                c
            }],
        };
        let plan = generate_plan(&bundle);

        assert_eq!(plan.actions.len(), 1);
        let action = &plan.actions[0];
        assert_eq!(action.action, Action::Keep);
        assert_eq!(action.routing, ActionRouting::ZombieInvestigateOnly);
        assert!(action.blocked);
    }

    #[test]
    fn zombie_never_gets_direct_kill() {
        // Acceptance criteria: "Zombie targets never receive a direct kill action"
        let parent_id = identity(100);
        let bundle = DecisionBundle {
            session_id: SessionId("pt-20260115-120000-abcd".to_string()),
            policy: Policy::default(),
            generated_at: Some("2026-01-15T12:00:00Z".to_string()),
            candidates: vec![{
                let mut c = candidate(42, Action::Kill, 100.0, 1.0);
                c.process_state = Some(ProcessState::Zombie);
                c.parent_identity = Some(parent_id);
                c
            }],
        };
        let plan = generate_plan(&bundle);

        // No action should target the zombie PID with Kill
        for action in &plan.actions {
            if action.target.pid.0 == 42 {
                assert_ne!(action.action, Action::Kill, "zombie got direct kill!");
            }
        }
    }

    // =========================================================================
    // D-state (Uninterruptible Sleep) Process Tests
    // =========================================================================

    #[test]
    fn d_state_kill_marked_low_confidence() {
        let bundle = DecisionBundle {
            session_id: SessionId("pt-20260115-120000-abcd".to_string()),
            policy: Policy::default(),
            generated_at: Some("2026-01-15T12:00:00Z".to_string()),
            candidates: vec![{
                let mut c = candidate(42, Action::Kill, 100.0, 1.0);
                c.process_state = Some(ProcessState::DiskSleep);
                c.d_state_diagnostics = Some(DStateDiagnostics {
                    wchan: Some("nfs_wait_client_init".to_string()),
                    io_read_bytes: Some(1024),
                    io_write_bytes: Some(512),
                    d_state_duration_ms: Some(5000),
                });
                c
            }],
        };
        let plan = generate_plan(&bundle);

        assert_eq!(plan.actions.len(), 1);
        let action = &plan.actions[0];
        assert_eq!(action.action, Action::Kill);
        assert_eq!(action.confidence, ActionConfidence::Low);
        assert_eq!(action.routing, ActionRouting::DStateLowConfidence);
        assert!(action.d_state_diagnostics.is_some());

        let diag = action.d_state_diagnostics.as_ref().unwrap();
        assert_eq!(diag.wchan.as_deref(), Some("nfs_wait_client_init"));
    }

    #[test]
    fn d_state_pause_normal_confidence() {
        // Pause should still work on D-state (just won't have effect until it wakes)
        let bundle = DecisionBundle {
            session_id: SessionId("pt-20260115-120000-abcd".to_string()),
            policy: Policy::default(),
            generated_at: Some("2026-01-15T12:00:00Z".to_string()),
            candidates: vec![{
                let mut c = candidate(42, Action::Pause, 10.0, 1.0);
                c.process_state = Some(ProcessState::DiskSleep);
                c
            }],
        };
        let plan = generate_plan(&bundle);

        assert_eq!(plan.actions.len(), 1);
        let action = &plan.actions[0];
        assert_eq!(action.action, Action::Pause);
        assert_eq!(action.confidence, ActionConfidence::Normal); // Not low for pause
        assert_eq!(action.routing, ActionRouting::DStateLowConfidence);
    }

    #[test]
    fn d_state_pause_does_not_require_state_precheck() {
        let bundle = DecisionBundle {
            session_id: SessionId("pt-20260115-120000-abcd".to_string()),
            policy: Policy::default(),
            generated_at: Some("2026-01-15T12:00:00Z".to_string()),
            candidates: vec![{
                let mut c = candidate(42, Action::Pause, 10.0, 1.0);
                c.process_state = Some(ProcessState::DiskSleep);
                c
            }],
        };
        let plan = generate_plan(&bundle);

        let action = &plan.actions[0];
        assert!(!action.pre_checks.contains(&PreCheck::VerifyProcessState));
    }

    #[test]
    fn d_state_includes_verify_process_state_precheck() {
        let bundle = DecisionBundle {
            session_id: SessionId("pt-20260115-120000-abcd".to_string()),
            policy: Policy::default(),
            generated_at: Some("2026-01-15T12:00:00Z".to_string()),
            candidates: vec![{
                let mut c = candidate(42, Action::Kill, 100.0, 1.0);
                c.process_state = Some(ProcessState::DiskSleep);
                c
            }],
        };
        let plan = generate_plan(&bundle);

        let action = &plan.actions[0];
        assert!(action.pre_checks.contains(&PreCheck::VerifyProcessState));
    }

    #[test]
    fn normal_process_direct_routing() {
        let bundle = DecisionBundle {
            session_id: SessionId("pt-20260115-120000-abcd".to_string()),
            policy: Policy::default(),
            generated_at: Some("2026-01-15T12:00:00Z".to_string()),
            candidates: vec![{
                let mut c = candidate(42, Action::Kill, 100.0, 1.0);
                c.process_state = Some(ProcessState::Running); // Normal state
                c
            }],
        };
        let plan = generate_plan(&bundle);

        assert_eq!(plan.actions.len(), 1);
        let action = &plan.actions[0];
        assert_eq!(action.action, Action::Kill);
        assert_eq!(action.routing, ActionRouting::Direct);
        assert_eq!(action.confidence, ActionConfidence::Normal);
        assert!(action.d_state_diagnostics.is_none());
    }

    #[test]
    fn kill_includes_agent_supervision_precheck() {
        let bundle = DecisionBundle {
            session_id: SessionId("pt-20260115-120000-abcd".to_string()),
            policy: Policy::default(),
            generated_at: Some("2026-01-15T12:00:00Z".to_string()),
            candidates: vec![candidate(42, Action::Kill, 100.0, 1.0)],
        };
        let plan = generate_plan(&bundle);

        let action = &plan.actions[0];
        assert!(action.pre_checks.contains(&PreCheck::CheckAgentSupervision));
    }

    #[test]
    fn pause_includes_agent_supervision_precheck() {
        let bundle = DecisionBundle {
            session_id: SessionId("pt-20260115-120000-abcd".to_string()),
            policy: Policy::default(),
            generated_at: Some("2026-01-15T12:00:00Z".to_string()),
            candidates: vec![candidate(42, Action::Pause, 10.0, 1.0)],
        };
        let plan = generate_plan(&bundle);

        let action = &plan.actions[0];
        assert!(action.pre_checks.contains(&PreCheck::CheckAgentSupervision));
    }
}
