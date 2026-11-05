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
#[cfg(feature = "metrics")]
pub mod metrics;
pub mod triggers;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

use crate::collect::pressure::PressureSnapshot;
use crate::decision::mem_pressure::{
    MemPressureConfig, MemPressureMonitor, MemorySignals, PressureAction, PressureEvaluation,
    PressureMode,
};

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
    /// Notification escalation ladder configuration.
    #[serde(default)]
    pub notification_ladder: crate::decision::escalation::EscalationConfig,
    /// Notification delivery configuration.
    #[serde(default)]
    pub notifications: DaemonNotificationsConfig,
    /// Memory/PSI pressure response. It generates review plans, never actions.
    #[serde(default)]
    pub memory_pressure: MemPressureConfig,
}

/// Notification delivery settings for the daemon.
///
/// The ladder decides *what* level/channels are appropriate; this config
/// decides which channels are actually delivered in this environment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonNotificationsConfig {
    /// Enable notification delivery (inbox items are still written separately).
    pub enabled: bool,
    /// Best-effort desktop notifications (Linux/macOS).
    pub desktop: bool,
    /// Execute a command when a notification is emitted (best-effort).
    #[serde(default)]
    pub notify_cmd: Option<String>,
    /// Extra args for notify_cmd.
    #[serde(default)]
    pub notify_arg: Vec<String>,
}

impl Default for DaemonNotificationsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            desktop: true,
            notify_cmd: None,
            notify_arg: Vec::new(),
        }
    }
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            tick_interval_secs: 60,
            max_cpu_percent: 2.0,
            max_rss_mb: 64,
            triggers: triggers::TriggerConfig::default(),
            escalation: escalation::EscalationConfig::default(),
            notification_ladder: crate::decision::escalation::EscalationConfig::default(),
            notifications: DaemonNotificationsConfig::default(),
            memory_pressure: MemPressureConfig::default(),
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
    /// The actual pressure reading, including unavailable sensors. Older callers
    /// without a reading cannot supply CPU capacity or memory-pressure recovery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pressure: Option<PressureSnapshot>,
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
    EscalationFailed,
    LockContention,
    OverheadBudgetExceeded,
    ConfigReloaded,
    LoadEvidenceUnavailable,
    MemoryPressureChanged,
    MemoryPressureUnavailable,
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
    /// Retained hysteresis state survives daemon restarts and missing readings.
    #[serde(default)]
    pub memory_pressure: MemPressureMonitor,
    /// Most recent sensor output; missing values remain explicit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_pressure: Option<PressureSnapshot>,
    /// None when this tick could not establish a valid pressure observation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_memory_pressure: Option<PressureEvaluation>,
    /// Retain a warning's plan request when lock contention or cooldown defers it.
    #[serde(default)]
    pub memory_pressure_plan_pending: bool,
}

impl Default for DaemonState {
    fn default() -> Self {
        Self::new()
    }
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
            memory_pressure: MemPressureMonitor::default(),
            last_pressure: None,
            last_memory_pressure: None,
            memory_pressure_plan_pending: false,
        }
    }

    /// Record the cheap pressure observation even if the daemon's own overhead
    /// budget prevents it from generating a plan on this tick.
    pub fn observe_memory_pressure(&mut self, config: &DaemonConfig, metrics: &TickMetrics) {
        self.memory_pressure
            .reconfigure(config.memory_pressure.clone());
        self.last_pressure = metrics.pressure.clone();
        let signals = metrics
            .pressure
            .as_ref()
            .and_then(MemorySignals::from_pressure_snapshot);
        let was_available = self.last_memory_pressure.is_some();
        let evaluation = self.memory_pressure.observe(signals.as_ref());
        if let Some(evaluation) = &evaluation {
            if evaluation.mode == PressureMode::Normal {
                self.memory_pressure_plan_pending = false;
            } else if matches!(
                evaluation.action,
                PressureAction::GeneratePlan | PressureAction::UrgentPlan
            ) {
                self.memory_pressure_plan_pending = true;
            }
            if evaluation.transitioned {
                self.record_event(
                    DaemonEventType::MemoryPressureChanged,
                    &evaluation.explanation,
                );
            }
        } else if was_available || self.tick_count <= 1 {
            self.record_event(
                DaemonEventType::MemoryPressureUnavailable,
                "memory-pressure evidence unavailable; retained the previous mode",
            );
        }
        self.last_memory_pressure = evaluation;
    }

    /// Pressure can increase polling cadence, never slow the configured base
    /// cadence or create a zero-duration busy loop.
    pub fn next_tick_interval_secs(&self, config: &DaemonConfig) -> u64 {
        let base = config.tick_interval_secs.max(1);
        let requested = self.memory_pressure.scan_interval_secs();
        if requested.is_finite() && requested > 0.0 {
            (requested.ceil() as u64).max(1).min(base)
        } else {
            base
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_pressure: Option<PressureEvaluation>,
    /// Polling interval selected for the next tick, in seconds.
    #[serde(default)]
    pub next_tick_interval_secs: u64,
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
    let previous_load_error = trigger_state.load_unavailable_reason.clone();
    let mut fired = triggers::evaluate_triggers(&config.triggers, trigger_state, metrics);
    if trigger_state.load_unavailable_reason != previous_load_error {
        if let Some(reason) = &trigger_state.load_unavailable_reason {
            let detail = format!("load trigger unavailable: {reason}; no load escalation");
            state.record_event(DaemonEventType::LoadEvidenceUnavailable, &detail);
            events.push(DaemonEvent {
                timestamp: metrics.timestamp.clone(),
                event_type: DaemonEventType::LoadEvidenceUnavailable,
                detail,
            });
        }
    }
    state.observe_memory_pressure(config, metrics);
    if let Some(evaluation) = &state.last_memory_pressure {
        if evaluation.transitioned {
            events.push(DaemonEvent {
                timestamp: metrics.timestamp.clone(),
                event_type: DaemonEventType::MemoryPressureChanged,
                detail: evaluation.explanation.clone(),
            });
        }
        if state.memory_pressure_plan_pending && evaluation.mode != PressureMode::Normal {
            // The richer observation replaces a same-tick utilization trigger;
            // the existing escalation callback still enforces cooldown and lock.
            fired.retain(|trigger| trigger.kind != triggers::TriggerKind::MemoryPressure);
            fired.push(triggers::FiredTrigger {
                kind: triggers::TriggerKind::MemoryPressure,
                description: evaluation.explanation.clone(),
                current_value: evaluation.utilization,
                ewma_value: trigger_state.memory_ewma,
                threshold: match evaluation.mode {
                    PressureMode::Emergency => config.memory_pressure.emergency_threshold,
                    _ => config.memory_pressure.warning_threshold,
                },
                sustained_ticks: u32::try_from(state.memory_pressure.sustained_samples())
                    .unwrap_or(u32::MAX),
                provenance_context: Vec::new(),
                memory_pressure: Some(evaluation.clone()),
            });
        }
    }

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
                if fired
                    .iter()
                    .any(|trigger| trigger.memory_pressure.is_some())
                {
                    state.memory_pressure_plan_pending = false;
                }
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
                state.record_event(DaemonEventType::EscalationFailed, &outcome.reason);
                events.push(DaemonEvent {
                    timestamp: metrics.timestamp.clone(),
                    event_type: DaemonEventType::EscalationFailed,
                    detail: outcome.reason.clone(),
                });
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
        memory_pressure: state.last_memory_pressure.clone(),
        next_tick_interval_secs: state.next_tick_interval_secs(config),
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
            pressure: None,
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
                provenance_summary: None,
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
        config.triggers.load_threshold = Some(2.0);
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
                provenance_summary: None,
            },
        );

        assert!(!outcome.triggers_fired.is_empty());
        assert!(outcome.escalation.is_some());
        assert_eq!(state.escalation_count, 1);
    }

    #[test]
    fn test_tick_deferred_escalation() {
        let mut config = DaemonConfig::default();
        config.triggers.load_threshold = Some(2.0);
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
                provenance_summary: None,
            },
        );

        assert!(outcome.escalation.is_some());
        assert_eq!(state.deferred_count, 1);
        assert_eq!(state.escalation_count, 0);
    }

    #[test]
    fn test_tick_failed_escalation_emits_failed_event() {
        let mut config = DaemonConfig::default();
        config.triggers.load_threshold = Some(2.0);
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
                status: escalation::EscalationStatus::Failed,
                reason: "escalation failed".to_string(),
                session_id: None,
                provenance_summary: None,
            },
        );

        assert!(outcome.escalation.is_some());
        assert_eq!(state.deferred_count, 0);
        assert_eq!(state.escalation_count, 0);
        assert!(outcome
            .events
            .iter()
            .any(|event| event.event_type == DaemonEventType::EscalationFailed));
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
                    provenance_summary: None,
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

    fn pressure_metrics(utilization_percent: u64, psi: Option<f64>, at_secs: u64) -> TickMetrics {
        use crate::collect::pressure::{MemInfo, PsiLine, PsiResource};

        let mut metrics = test_metrics(1.0, 8192 * utilization_percent / 100, 0);
        metrics.pressure = Some(PressureSnapshot {
            sampled_at_ms: at_secs * 1000,
            cpus: 4,
            cpu: None,
            memory: psi.map(|avg10| PsiResource {
                some: Some(PsiLine {
                    avg10,
                    avg60: avg10,
                    avg300: avg10,
                    total_us: 10_000,
                }),
                full: None,
            }),
            io: None,
            irq: None,
            load: None,
            meminfo: Some(MemInfo {
                total: Some(1_000_000),
                available: Some(10_000 * (100 - utilization_percent)),
                ..Default::default()
            }),
            vmstat: None,
            file_handles: None,
            unavailable: Vec::new(),
        });
        metrics
    }

    fn advance_reading(metrics: &mut TickMetrics) {
        metrics.pressure.as_mut().unwrap().sampled_at_ms += 60_000;
    }

    fn load_metrics(load: f64, cpus: u32) -> TickMetrics {
        use crate::collect::pressure::LoadAvg;

        let mut metrics = pressure_metrics(40, None, 1000);
        let pressure = metrics.pressure.as_mut().unwrap();
        pressure.cpus = cpus;
        pressure.load = Some(LoadAvg {
            one: load,
            five: load,
            fifteen: load,
            runnable: Some(1),
            total: Some(200),
        });
        metrics
    }

    #[test]
    fn observed_load_capacity_controls_the_escalation_callback() {
        for (cpus, expected_escalations) in [(2, 1), (64, 0)] {
            let config = DaemonConfig::default();
            let mut state = DaemonState::new();
            let mut triggers = triggers::TriggerState::new(&config.triggers);
            let mut metrics = load_metrics(10.0, cpus);
            let mut callbacks = 0;
            let mut plan = |config: &escalation::EscalationConfig,
                            fired: &[triggers::FiredTrigger]| {
                callbacks += 1;
                assert!(!config.allow_auto_mitigation);
                assert_eq!(fired.len(), 1);
                assert_eq!(fired[0].kind, triggers::TriggerKind::SustainedLoad);
                assert_eq!(fired[0].current_value, 10.0);
                assert_eq!(fired[0].threshold, 4.0);
                assert!(fired[0].description.contains("online_cpus=2"));
                escalation::EscalationOutcome {
                    status: escalation::EscalationStatus::Completed,
                    reason: fired[0].description.clone(),
                    session_id: Some("load-review-plan".to_string()),
                    provenance_summary: None,
                }
            };

            for tick in 1..=4 {
                let outcome = process_tick(&config, &mut state, &mut triggers, &metrics, &mut plan);
                if tick < 3 {
                    assert!(outcome.escalation.is_none());
                }
                advance_reading(&mut metrics);
            }
            assert_eq!(callbacks, expected_escalations);
            assert_eq!(state.escalation_count, expected_escalations);
        }
    }

    #[test]
    fn unavailable_load_evidence_is_reported_once_per_outage() {
        let config = DaemonConfig::default();
        let mut state = DaemonState::new();
        let mut triggers = triggers::TriggerState::new(&config.triggers);
        let missing = test_metrics(1000.0, 2000, 0);
        let mut plan = |_: &escalation::EscalationConfig, _: &[triggers::FiredTrigger]| {
            panic!("missing CPU capacity must never trigger a load plan")
        };
        for tick in 0..3 {
            let outcome = process_tick(&config, &mut state, &mut triggers, &missing, &mut plan);
            let errors: Vec<_> = outcome
                .events
                .iter()
                .filter(|event| event.event_type == DaemonEventType::LoadEvidenceUnavailable)
                .collect();
            assert_eq!(errors.len(), usize::from(tick == 0));
            if let Some(error) = errors.first() {
                assert!(error
                    .detail
                    .contains("CPU capacity observation unavailable"));
            }
        }
        assert_eq!(
            state
                .recent_events
                .iter()
                .filter(|event| event.event_type == DaemonEventType::LoadEvidenceUnavailable)
                .count(),
            1
        );

        let observed = load_metrics(3.0, 2);
        process_tick(&config, &mut state, &mut triggers, &observed, &mut plan);
        assert!(triggers.load_unavailable_reason.is_none());
        let failed_again = process_tick(&config, &mut state, &mut triggers, &missing, &mut plan);
        assert!(failed_again
            .events
            .iter()
            .any(|event| event.event_type == DaemonEventType::LoadEvidenceUnavailable));
    }

    #[test]
    fn psi_pressure_reaches_escalation_and_preserves_its_cooldown() {
        let config = DaemonConfig::default();
        let mut state = DaemonState::new();
        let mut triggers = triggers::TriggerState::new(&config.triggers);
        let mut escalation = escalation::EscalationState::new();
        let mut metrics = pressure_metrics(40, Some(75.0), 1000);
        let mut plan = |config: &escalation::EscalationConfig, fired: &[triggers::FiredTrigger]| {
            assert!(!config.allow_auto_mitigation);
            assert_eq!(fired.len(), 1);
            assert_eq!(fired[0].kind, triggers::TriggerKind::MemoryPressure);
            let pressure = fired[0].memory_pressure.as_ref().unwrap();
            assert_eq!(pressure.mode, PressureMode::Emergency);
            assert_eq!(pressure.psi_some10, Some(75.0));
            escalation::decide_escalation(config, &mut escalation, fired, || true)
        };

        let first = process_tick(&config, &mut state, &mut triggers, &metrics, &mut plan);
        assert!(
            first.escalation.is_none(),
            "one PSI spike must not escalate"
        );
        advance_reading(&mut metrics);
        let second = process_tick(&config, &mut state, &mut triggers, &metrics, &mut plan);
        assert_eq!(
            second.escalation.unwrap().status,
            escalation::EscalationStatus::Completed
        );
        assert_eq!(second.next_tick_interval_secs, 15);
        advance_reading(&mut metrics);
        let third = process_tick(&config, &mut state, &mut triggers, &metrics, &mut plan);
        let deferred = third.escalation.unwrap();
        assert_eq!(deferred.status, escalation::EscalationStatus::Deferred);
        assert!(deferred.reason.contains("Cooldown"));
        assert_eq!(state.escalation_count, 1);
        assert_eq!(state.deferred_count, 1);
    }

    #[test]
    fn pressure_warning_retries_a_deferred_plan_without_requiring_a_new_episode() {
        let config = DaemonConfig::default();
        let mut state = DaemonState::new();
        let mut triggers = triggers::TriggerState::new(&config.triggers);
        let mut escalation = escalation::EscalationState::new();
        let mut metrics = pressure_metrics(40, Some(25.0), 1000);
        let mut lock_available = false;
        let mut plan = |config: &escalation::EscalationConfig, fired: &[triggers::FiredTrigger]| {
            let outcome =
                escalation::decide_escalation(config, &mut escalation, fired, || lock_available);
            lock_available = true;
            outcome
        };

        process_tick(&config, &mut state, &mut triggers, &metrics, &mut plan);
        advance_reading(&mut metrics);
        let blocked = process_tick(&config, &mut state, &mut triggers, &metrics, &mut plan);
        assert_eq!(
            blocked.escalation.unwrap().status,
            escalation::EscalationStatus::Deferred
        );
        assert!(state.memory_pressure_plan_pending);
        assert_eq!(blocked.next_tick_interval_secs, 30);
        advance_reading(&mut metrics);
        let retried = process_tick(&config, &mut state, &mut triggers, &metrics, &mut plan);
        assert_eq!(
            retried.escalation.unwrap().status,
            escalation::EscalationStatus::Completed
        );
        assert!(!state.memory_pressure_plan_pending);
        advance_reading(&mut metrics);
        let stable = process_tick(&config, &mut state, &mut triggers, &metrics, &mut plan);
        assert!(stable.escalation.is_none());
    }

    #[test]
    fn daemon_restart_and_missing_sensors_cannot_clear_memory_pressure() {
        let config = DaemonConfig::default();
        let mut state = DaemonState::new();
        let mut emergency = pressure_metrics(40, Some(75.0), 1000);
        state.observe_memory_pressure(&config, &emergency);
        advance_reading(&mut emergency);
        state.observe_memory_pressure(&config, &emergency);
        let bytes = serde_json::to_vec(&state).unwrap();
        let mut state: DaemonState = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(state.memory_pressure.mode(), PressureMode::Emergency);

        let mut missing = pressure_metrics(40, None, 1120);
        state.observe_memory_pressure(&config, &missing);
        assert!(state.last_memory_pressure.is_none());
        assert_eq!(state.next_tick_interval_secs(&config), 15);
        missing.pressure.as_mut().unwrap().meminfo = None;
        advance_reading(&mut missing);
        state.observe_memory_pressure(&config, &missing);
        assert!(state.last_memory_pressure.is_none());
        assert_eq!(state.memory_pressure.mode(), PressureMode::Emergency);

        let mut normal = pressure_metrics(40, Some(1.0), 1240);
        state.observe_memory_pressure(&config, &normal);
        assert_eq!(state.memory_pressure.mode(), PressureMode::Emergency);
        advance_reading(&mut normal);
        state.observe_memory_pressure(&config, &normal);
        assert_eq!(state.memory_pressure.mode(), PressureMode::Normal);
        assert_eq!(state.next_tick_interval_secs(&config), 60);
        assert!(!state.memory_pressure_plan_pending);
    }

    #[test]
    fn pressure_cadence_never_slows_the_base_or_creates_a_busy_loop() {
        let mut config = DaemonConfig {
            tick_interval_secs: 5,
            ..Default::default()
        };
        let mut state = DaemonState::new();
        let mut metrics = pressure_metrics(97, Some(75.0), 1000);
        state.observe_memory_pressure(&config, &metrics);
        advance_reading(&mut metrics);
        state.observe_memory_pressure(&config, &metrics);
        assert_eq!(state.next_tick_interval_secs(&config), 5);

        config.memory_pressure.emergency_interval_secs = 0.0;
        advance_reading(&mut metrics);
        state.observe_memory_pressure(&config, &metrics);
        assert_eq!(state.next_tick_interval_secs(&config), 5);
        config.tick_interval_secs = 0;
        assert_eq!(state.next_tick_interval_secs(&config), 1);
    }

    #[test]
    fn pressure_plan_keeps_auto_mitigation_disabled() {
        let mut config = DaemonConfig::default();
        config.memory_pressure.transition_count = 1;
        config.memory_pressure.auto_apply = true;
        let mut state = DaemonState::new();
        let mut triggers = triggers::TriggerState::new(&config.triggers);
        let outcome = process_tick(
            &config,
            &mut state,
            &mut triggers,
            &pressure_metrics(40, Some(75.0), 1000),
            &mut |config, _| {
                assert!(!config.allow_auto_mitigation);
                escalation::EscalationOutcome {
                    status: escalation::EscalationStatus::Completed,
                    reason: "review plan generated".to_string(),
                    session_id: Some("pressure-plan".to_string()),
                    provenance_summary: None,
                }
            },
        );
        assert_eq!(
            outcome.escalation.unwrap().session_id.as_deref(),
            Some("pressure-plan")
        );
    }
}
