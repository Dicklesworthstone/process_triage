//! Dormant monitoring daemon core loop.
//!
//! Implements the library-side primitives for `ptd` (Plan §3.7):
//!
//! - **Triggers**: EWMA-based baseline tracking with sustained-window rules
//!   and cooldown/backoff to prevent flapping.
//! - **Escalation**: orchestrates scan → infer → plan pipeline, writes inbox
//!   items, respects per-user lock contention.
//! - **Core loop**: tick-based event loop with overhead budgeting.
//!
//! This module is intentionally *library-only*. The actual daemon binary /
//! systemd integration lives in CLI/service layer code.

pub mod escalation;
pub mod triggers;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the daemon core loop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// Interval between metric collection ticks (seconds).
    pub tick_interval_secs: u64,
    /// Maximum CPU% the daemon may consume (self-limiting).
    pub max_cpu_percent: f64,
    /// Maximum RSS (MB) the daemon may consume.
    pub max_rss_mb: u64,
    /// Trigger configuration.
    pub triggers: triggers::TriggerConfig,
    /// Escalation configuration.
    pub escalation: escalation::EscalationConfig,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            tick_interval_secs: 60,
            max_cpu_percent: 2.0,
            max_rss_mb: 64,
            triggers: triggers::TriggerConfig::default(),
            escalation: escalation::EscalationConfig::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Daemon state
// ---------------------------------------------------------------------------

/// Instantaneous system metrics collected each tick.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TickMetrics {
    pub timestamp: String,
    pub load_avg_1: f64,
    pub load_avg_5: f64,
    pub memory_used_mb: u64,
    pub memory_total_mb: u64,
    pub swap_used_mb: u64,
    pub process_count: u32,
    pub orphan_count: u32,
}

/// A daemon event for telemetry / audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonEvent {
    pub timestamp: String,
    pub event_type: DaemonEventType,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaemonEventType {
    Started,
    Stopped,
    TickCompleted,
    TriggerFired,
    TriggerCooldown,
    EscalationStarted,
    EscalationCompleted,
    EscalationDeferred,
    LockContention,
    OverheadBudgetExceeded,
    ConfigReloaded,
}

/// Running state of the daemon core loop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonState {
    pub started_at: String,
    pub tick_count: u64,
    pub last_tick_at: Option<String>,
    pub last_escalation_at: Option<String>,
    pub escalation_count: u32,
    pub deferred_count: u32,
    /// Recent events for audit.
    pub recent_events: VecDeque<DaemonEvent>,
}

impl DaemonState {
    pub fn new() -> Self {
        Self {
            started_at: Utc::now().to_rfc3339(),
            tick_count: 0,
            last_tick_at: None,
            last_escalation_at: None,
            escalation_count: 0,
            deferred_count: 0,
            recent_events: VecDeque::with_capacity(100),
        }
    }

    pub fn record_event(&mut self, event_type: DaemonEventType, detail: &str) {
        let event = DaemonEvent {
            timestamp: Utc::now().to_rfc3339(),
            event_type,
            detail: detail.to_string(),
        };
        if self.recent_events.len() >= 100 {
            self.recent_events.pop_front();
        }
        self.recent_events.push_back(event);
    }
}

// ---------------------------------------------------------------------------
// Core loop (synchronous, testable)
// ---------------------------------------------------------------------------

/// Outcome of a single daemon tick.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TickOutcome {
    pub tick_number: u64,
    pub triggers_fired: Vec<triggers::FiredTrigger>,
    pub escalation: Option<escalation::EscalationOutcome>,
    pub events: Vec<DaemonEvent>,
}

/// Process one daemon tick.
///
/// This is the core testable unit — it takes metrics, evaluates triggers,
/// and decides whether to escalate. The actual metric collection and
/// escalation execution are injected via callbacks for testability.
pub fn process_tick<E>(
    config: &DaemonConfig,
    state: &mut DaemonState,
    trigger_state: &mut triggers::TriggerState,
    metrics: &TickMetrics,
    escalate_fn: &mut E,
) -> TickOutcome
where
    E: FnMut(
        &escalation::EscalationConfig,
        &[triggers::FiredTrigger],
    ) -> escalation::EscalationOutcome,
{
    state.tick_count += 1;
    let tick_number = state.tick_count;
    state.last_tick_at = Some(metrics.timestamp.clone());

    let mut events = Vec::new();

    // 1) Evaluate triggers.
    let fired = triggers::evaluate_triggers(&config.triggers, trigger_state, metrics);

    for t in &fired {
        state.record_event(DaemonEventType::TriggerFired, &t.description);
        events.push(DaemonEvent {
            timestamp: metrics.timestamp.clone(),
            event_type: DaemonEventType::TriggerFired,
            detail: t.description.clone(),
        });
    }

    // 2) Escalate if any triggers fired.
    let escalation = if !fired.is_empty() {
        let outcome = escalate_fn(&config.escalation, &fired);

        match outcome.status {
            escalation::EscalationStatus::Completed => {
                state.escalation_count += 1;
                state.last_escalation_at = Some(metrics.timestamp.clone());
                state.record_event(DaemonEventType::EscalationCompleted, "escalation completed");
                events.push(DaemonEvent {
                    timestamp: metrics.timestamp.clone(),
                    event_type: DaemonEventType::EscalationCompleted,
                    detail: "escalation completed".to_string(),
                });
            }
            escalation::EscalationStatus::Deferred => {
                state.deferred_count += 1;
                state.record_event(DaemonEventType::EscalationDeferred, &outcome.reason);
                events.push(DaemonEvent {
                    timestamp: metrics.timestamp.clone(),
                    event_type: DaemonEventType::EscalationDeferred,
                    detail: outcome.reason.clone(),
                });
            }
            escalation::EscalationStatus::Failed => {
                state.record_event(DaemonEventType::EscalationDeferred, &outcome.reason);
            }
        }

        Some(outcome)
    } else {
        None
    };

    state.record_event(
        DaemonEventType::TickCompleted,
        &format!("tick {}", tick_number),
    );

    TickOutcome {
        tick_number,
        triggers_fired: fired,
        escalation,
        events,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_metrics(load: f64, mem_used: u64, orphans: u32) -> TickMetrics {
        TickMetrics {
            timestamp: Utc::now().to_rfc3339(),
            load_avg_1: load,
            load_avg_5: load * 0.8,
            memory_used_mb: mem_used,
            memory_total_mb: 8192,
            swap_used_mb: 0,
            process_count: 200,
            orphan_count: orphans,
        }
    }

    #[test]
    fn test_tick_no_triggers() {
        let config = DaemonConfig::default();
        let mut state = DaemonState::new();
        let mut trig_state = triggers::TriggerState::new(&config.triggers);

        let metrics = test_metrics(1.0, 2000, 5);
        let outcome = process_tick(
            &config,
            &mut state,
            &mut trig_state,
            &metrics,
            &mut |_, _| escalation::EscalationOutcome {
                status: escalation::EscalationStatus::Completed,
                reason: String::new(),
                session_id: None,
            },
        );

        assert_eq!(outcome.tick_number, 1);
        assert!(outcome.triggers_fired.is_empty());
        assert!(outcome.escalation.is_none());
        assert_eq!(state.tick_count, 1);
    }

    #[test]
    fn test_tick_with_trigger_and_escalation() {
        let mut config = DaemonConfig::default();
        config.triggers.load_threshold = 2.0;
        config.triggers.sustained_ticks = 1; // Fire immediately
        let mut state = DaemonState::new();
        let mut trig_state = triggers::TriggerState::new(&config.triggers);

        let metrics = test_metrics(10.0, 2000, 5); // High load
        let outcome = process_tick(
            &config,
            &mut state,
            &mut trig_state,
            &metrics,
            &mut |_, _| escalation::EscalationOutcome {
                status: escalation::EscalationStatus::Completed,
                reason: "test escalation".to_string(),
                session_id: Some("test-session".to_string()),
            },
        );

        assert!(!outcome.triggers_fired.is_empty());
        assert!(outcome.escalation.is_some());
        assert_eq!(state.escalation_count, 1);
    }

    #[test]
    fn test_tick_deferred_escalation() {
        let mut config = DaemonConfig::default();
        config.triggers.load_threshold = 2.0;
        config.triggers.sustained_ticks = 1;
        let mut state = DaemonState::new();
        let mut trig_state = triggers::TriggerState::new(&config.triggers);

        let metrics = test_metrics(10.0, 2000, 5);
        let outcome = process_tick(
            &config,
            &mut state,
            &mut trig_state,
            &metrics,
            &mut |_, _| escalation::EscalationOutcome {
                status: escalation::EscalationStatus::Deferred,
                reason: "lock held".to_string(),
                session_id: None,
            },
        );

        assert!(outcome.escalation.is_some());
        assert_eq!(state.deferred_count, 1);
        assert_eq!(state.escalation_count, 0);
    }

    #[test]
    fn test_state_event_ring() {
        let mut state = DaemonState::new();
        for i in 0..150 {
            state.record_event(DaemonEventType::TickCompleted, &format!("tick {}", i));
        }
        assert_eq!(state.recent_events.len(), 100);
    }

    #[test]
    fn test_multiple_ticks() {
        let config = DaemonConfig::default();
        let mut state = DaemonState::new();
        let mut trig_state = triggers::TriggerState::new(&config.triggers);

        for _ in 0..5 {
            let metrics = test_metrics(1.0, 2000, 5);
            process_tick(
                &config,
                &mut state,
                &mut trig_state,
                &metrics,
                &mut |_, _| escalation::EscalationOutcome {
                    status: escalation::EscalationStatus::Completed,
                    reason: String::new(),
                    session_id: None,
                },
            );
        }
        assert_eq!(state.tick_count, 5);
    }

    #[test]
    fn test_config_serialization() {
        let config = DaemonConfig::default();
        let json = serde_json::to_string_pretty(&config).unwrap();
        let restored: DaemonConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.tick_interval_secs, 60);
    }
}
