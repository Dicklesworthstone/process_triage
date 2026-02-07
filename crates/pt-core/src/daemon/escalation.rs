//! Escalation orchestration for daemon trigger responses.
//!
//! When triggers fire, the daemon needs to decide:
//! 1. Is an escalation already in cooldown?
//! 2. Can we acquire the per-user lock (no competing manual/agent run)?
//! 3. If not, defer and write an inbox item instead.
//!
//! This module provides the decision logic and outcome types. Actual
//! lock acquisition and scan execution are injected for testability.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use super::triggers::FiredTrigger;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Escalation configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationConfig {
    /// Minimum seconds between escalations (global cooldown).
    pub min_interval_secs: u64,
    /// Whether non-destructive auto-mitigation (pause/throttle) is allowed.
    pub allow_auto_mitigation: bool,
    /// Maximum number of deep scan targets per escalation.
    pub max_deep_scan_targets: u32,
}

impl Default for EscalationConfig {
    fn default() -> Self {
        Self {
            min_interval_secs: 300,
            allow_auto_mitigation: false,
            max_deep_scan_targets: 10,
        }
    }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Escalation outcome status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationStatus {
    /// Escalation ran to completion (scan + plan generated).
    Completed,
    /// Escalation deferred (lock contention, cooldown, etc.).
    Deferred,
    /// Escalation failed (error during scan/plan).
    Failed,
}

/// Reason for deferral.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeferReason {
    /// Another pt run holds the lock.
    LockContention,
    /// Too soon since last escalation.
    Cooldown,
}

/// Result of an escalation attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationOutcome {
    pub status: EscalationStatus,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

/// State tracking for escalation decisions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationState {
    pub last_escalation_at: Option<String>,
    pub total_escalations: u32,
    pub total_deferrals: u32,
    pub consecutive_deferrals: u32,
}

impl Default for EscalationState {
    fn default() -> Self {
        Self::new()
    }
}

impl EscalationState {
    pub fn new() -> Self {
        Self {
            last_escalation_at: None,
            total_escalations: 0,
            total_deferrals: 0,
            consecutive_deferrals: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Decision logic
// ---------------------------------------------------------------------------

/// Check if escalation should proceed based on cooldown.
pub fn check_cooldown(config: &EscalationConfig, state: &EscalationState) -> Option<DeferReason> {
    if let Some(ref last) = state.last_escalation_at {
        if let Ok(last_dt) = DateTime::parse_from_rfc3339(last) {
            let last_utc = last_dt.with_timezone(&Utc);
            let elapsed = Utc::now().signed_duration_since(last_utc);
            if elapsed < Duration::seconds(config.min_interval_secs as i64) {
                return Some(DeferReason::Cooldown);
            }
        }
    }
    None
}

/// Decide whether to escalate, defer, or skip.
///
/// The `try_lock` callback attempts to acquire the per-user lock.
/// Returns `true` if the lock was acquired, `false` if contended.
pub fn decide_escalation<L>(
    config: &EscalationConfig,
    state: &mut EscalationState,
    _triggers: &[FiredTrigger],
    try_lock: L,
) -> EscalationOutcome
where
    L: FnOnce() -> bool,
{
    // Check cooldown.
    if let Some(reason) = check_cooldown(config, state) {
        state.total_deferrals += 1;
        state.consecutive_deferrals += 1;
        return EscalationOutcome {
            status: EscalationStatus::Deferred,
            reason: format!("{:?}", reason),
            session_id: None,
        };
    }

    // Try to acquire lock.
    if !try_lock() {
        state.total_deferrals += 1;
        state.consecutive_deferrals += 1;
        return EscalationOutcome {
            status: EscalationStatus::Deferred,
            reason: format!("{:?}", DeferReason::LockContention),
            session_id: None,
        };
    }

    // Lock acquired — escalation proceeds.
    state.last_escalation_at = Some(Utc::now().to_rfc3339());
    state.total_escalations += 1;
    state.consecutive_deferrals = 0;

    EscalationOutcome {
        status: EscalationStatus::Completed,
        reason: "escalation completed".to_string(),
        session_id: None, // Caller fills in after creating the session.
    }
}

/// Build an inbox item summary from fired triggers.
pub fn build_inbox_summary(triggers: &[FiredTrigger]) -> String {
    if triggers.is_empty() {
        return "No triggers fired".to_string();
    }
    let parts: Vec<String> = triggers
        .iter()
        .map(|t| format!("{:?}: {}", t.kind, t.description))
        .collect();
    format!("Daemon triggered escalation: {}", parts.join("; "))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::triggers::TriggerKind;

    fn trigger(kind: TriggerKind) -> FiredTrigger {
        FiredTrigger {
            kind,
            description: format!("{:?} fired", kind),
            current_value: 10.0,
            ewma_value: 8.0,
            threshold: 4.0,
            sustained_ticks: 3,
        }
    }

    #[test]
    fn test_decide_escalation_success() {
        let config = EscalationConfig::default();
        let mut state = EscalationState::new();
        let triggers = vec![trigger(TriggerKind::SustainedLoad)];

        let outcome = decide_escalation(&config, &mut state, &triggers, || true);
        assert_eq!(outcome.status, EscalationStatus::Completed);
        assert_eq!(state.total_escalations, 1);
        assert_eq!(state.consecutive_deferrals, 0);
    }

    #[test]
    fn test_decide_escalation_lock_contention() {
        let config = EscalationConfig::default();
        let mut state = EscalationState::new();
        let triggers = vec![trigger(TriggerKind::SustainedLoad)];

        let outcome = decide_escalation(&config, &mut state, &triggers, || false);
        assert_eq!(outcome.status, EscalationStatus::Deferred);
        assert!(outcome.reason.contains("LockContention"));
        assert_eq!(state.total_deferrals, 1);
    }

    #[test]
    fn test_cooldown_enforcement() {
        let config = EscalationConfig {
            min_interval_secs: 3600, // 1 hour
            ..Default::default()
        };
        let mut state = EscalationState::new();
        let triggers = vec![trigger(TriggerKind::SustainedLoad)];

        // First escalation succeeds.
        let r1 = decide_escalation(&config, &mut state, &triggers, || true);
        assert_eq!(r1.status, EscalationStatus::Completed);

        // Immediately after: cooldown defers.
        let r2 = decide_escalation(&config, &mut state, &triggers, || true);
        assert_eq!(r2.status, EscalationStatus::Deferred);
        assert!(r2.reason.contains("Cooldown"));
    }

    #[test]
    fn test_consecutive_deferrals() {
        let config = EscalationConfig::default();
        let mut state = EscalationState::new();
        let triggers = vec![trigger(TriggerKind::SustainedLoad)];

        // 3 lock contentions.
        for _ in 0..3 {
            decide_escalation(&config, &mut state, &triggers, || false);
        }
        assert_eq!(state.consecutive_deferrals, 3);
        assert_eq!(state.total_deferrals, 3);

        // Success resets consecutive counter.
        decide_escalation(&config, &mut state, &triggers, || true);
        assert_eq!(state.consecutive_deferrals, 0);
        assert_eq!(state.total_deferrals, 3); // Total still 3
    }

    #[test]
    fn test_inbox_summary() {
        let triggers = vec![
            trigger(TriggerKind::SustainedLoad),
            trigger(TriggerKind::MemoryPressure),
        ];
        let summary = build_inbox_summary(&triggers);
        assert!(summary.contains("SustainedLoad"));
        assert!(summary.contains("MemoryPressure"));
    }

    #[test]
    fn test_empty_inbox_summary() {
        let summary = build_inbox_summary(&[]);
        assert_eq!(summary, "No triggers fired");
    }

    #[test]
    fn test_state_serialization() {
        let mut state = EscalationState::new();
        state.total_escalations = 5;
        state.total_deferrals = 2;

        let json = serde_json::to_string(&state).unwrap();
        let restored: EscalationState = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.total_escalations, 5);
    }

    #[test]
    fn test_config_defaults() {
        let config = EscalationConfig::default();
        assert_eq!(config.min_interval_secs, 300);
        assert!(!config.allow_auto_mitigation);
        assert_eq!(config.max_deep_scan_targets, 10);
    }
}
