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
    /// Reduce the daemon's sampling frequency when its own overhead is too high.
    #[serde(default)]
    pub overhead_backoff: OverheadBackoffConfig,
}

/// Polling backoff after a daemon CPU or RSS budget violation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OverheadBackoffConfig {
    /// Maximum backed-off interval. A slower configured base interval takes
    /// precedence, so a budget violation can never make the daemon poll faster.
    pub max_interval_secs: u64,
    /// Consecutive ticks within budget before halving the backed-off interval.
    /// Zero is treated as one tick.
    pub healthy_ticks_before_recovery: u32,
}

impl Default for OverheadBackoffConfig {
    fn default() -> Self {
        Self {
            max_interval_secs: 300,
            healthy_ticks_before_recovery: 3,
        }
    }
}

/// Persisted overhead delay and the current consecutive recovery observations.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct OverheadBackoffState {
    /// Zero means normal polling; otherwise this interval overrides the faster
    /// memory-pressure cadence, subject to the current configuration's bounds.
    pub interval_secs: u64,
    /// Exposed in status. The daemon resets this after restart or a missing
    /// overhead observation, because neither establishes continued recovery.
    pub healthy_ticks: u32,
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
            overhead_backoff: OverheadBackoffConfig::default(),
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
    /// Live monotonic sampling time; deliberately not restored from a saved tick.
    #[serde(skip)]
    pub pressure_observed_at: Option<std::time::Instant>,
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
    OverheadBackoffChanged,
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
    /// Persistent self-limiting delay, independent of the host pressure state.
    #[serde(default)]
    pub overhead_backoff: OverheadBackoffState,
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
            overhead_backoff: OverheadBackoffState::default(),
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

    /// Observe the daemon's own budget exactly once per collection tick, before
    /// deciding whether planning is allowed. A breach doubles the delay, up to
    /// the configured cap. Recovery requires consecutive within-budget ticks
    /// and halves the delay one step at a time.
    ///
    /// The first delay is measured from at least the configured base interval:
    /// a host emergency must not make an over-budget daemon poll more often.
    /// Existing state is bounded on every observation so config reloads and
    /// persisted out-of-range intervals cannot bypass the cap.
    /// Pass `false` only after observing that the daemon is within budget; if
    /// overhead evidence is unavailable, interrupt recovery instead.
    pub fn observe_overhead_budget(&mut self, config: &DaemonConfig, budget_exceeded: bool) {
        let base = config.tick_interval_secs.max(1);
        let cap = config.overhead_backoff.max_interval_secs.max(base);
        let recovery_ticks = config.overhead_backoff.healthy_ticks_before_recovery.max(1);
        let previous_interval = self.next_tick_interval_secs(config);
        let previous_backoff = self.overhead_backoff.interval_secs;
        let mut recovered = false;
        if self.overhead_backoff.interval_secs > 0 {
            self.overhead_backoff.interval_secs =
                self.overhead_backoff.interval_secs.clamp(base, cap);
        }
        if self.overhead_backoff.healthy_ticks >= recovery_ticks {
            // A valid streak is always shorter than the threshold: reaching it
            // consumes the streak. Do not trust stale or out-of-range state.
            self.overhead_backoff.healthy_ticks = 0;
        }

        if budget_exceeded {
            self.overhead_backoff.interval_secs = self
                .overhead_backoff
                .interval_secs
                .max(base)
                .saturating_mul(2)
                .min(cap);
            self.overhead_backoff.healthy_ticks = 0;
        } else if self.overhead_backoff.interval_secs > 0 {
            self.overhead_backoff.healthy_ticks =
                self.overhead_backoff.healthy_ticks.saturating_add(1);
            if self.overhead_backoff.healthy_ticks >= recovery_ticks {
                let reduced = self.overhead_backoff.interval_secs / 2;
                self.overhead_backoff.interval_secs = if reduced > base { reduced } else { 0 };
                self.overhead_backoff.healthy_ticks = 0;
                recovered = true;
            }
        } else {
            self.overhead_backoff.healthy_ticks = 0;
        }

        if self.overhead_backoff.interval_secs != previous_backoff {
            let reason = if budget_exceeded {
                "overhead budget exceeded"
            } else if self.overhead_backoff.interval_secs == 0 {
                "within-budget recovery completed"
            } else if recovered {
                "consecutive within-budget observations"
            } else {
                "configured overhead backoff limit"
            };
            self.record_event(
                DaemonEventType::OverheadBackoffChanged,
                &format!(
                    "poll interval {}s -> {}s: {}",
                    previous_interval,
                    self.next_tick_interval_secs(config),
                    reason
                ),
            );
        }
    }

    /// Restart downtime and missing overhead samples break the consecutive
    /// healthy streak without discarding an active self-limiting delay.
    pub fn interrupt_overhead_recovery(&mut self) {
        self.overhead_backoff.healthy_ticks = 0;
    }

    /// Pressure can increase polling cadence only while overhead backoff is
    /// inactive. Every interval is at least one second and bounded arithmetic
    /// prevents extreme configuration or persisted values from overflowing.
    pub fn next_tick_interval_secs(&self, config: &DaemonConfig) -> u64 {
        let base = config.tick_interval_secs.max(1);
        if self.overhead_backoff.interval_secs > 0 {
            return self
                .overhead_backoff
                .interval_secs
                .clamp(base, config.overhead_backoff.max_interval_secs.max(base));
        }
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
                current_value: Some(evaluation.utilization),
                ewma_value: Some(trigger_state.memory_ewma),
                threshold: Some(match evaluation.mode {
                    PressureMode::Emergency => config.memory_pressure.emergency_threshold,
                    _ => config.memory_pressure.warning_threshold,
                }),
                sustained_ticks: u32::try_from(state.memory_pressure.sustained_samples())
                    .unwrap_or(u32::MAX),
                provenance_context: Vec::new(),
                memory_pressure: Some(evaluation.clone()),
                pressure_regime: None,
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
                trigger_state.pressure.acknowledge(&fired);
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
            pressure_observed_at: None,
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

    #[test]
    fn overhead_backoff_doubles_until_capped() {
        let config = DaemonConfig::default();
        let mut state = DaemonState::new();
        assert_eq!(state.next_tick_interval_secs(&config), 60);

        for expected in [120, 240, 300, 300, 300] {
            state.observe_overhead_budget(&config, true);
            assert_eq!(state.next_tick_interval_secs(&config), expected);
            assert_eq!(state.overhead_backoff.healthy_ticks, 0);
        }
        assert_eq!(
            state
                .recent_events
                .iter()
                .filter(|event| event.event_type == DaemonEventType::OverheadBackoffChanged)
                .count(),
            3,
            "a sustained violation at the cap must not emit duplicate delay changes"
        );
    }

    #[test]
    fn overhead_backoff_recovers_gradually_after_consecutive_healthy_ticks() {
        let config = DaemonConfig {
            overhead_backoff: OverheadBackoffConfig {
                max_interval_secs: 480,
                healthy_ticks_before_recovery: 3,
            },
            ..Default::default()
        };
        let mut state = DaemonState::new();
        state.observe_overhead_budget(&config, true);
        state.observe_overhead_budget(&config, true);
        for _ in 0..2 {
            state.observe_overhead_budget(&config, false);
            assert_eq!(state.next_tick_interval_secs(&config), 240);
        }
        state.observe_overhead_budget(&config, true);
        assert_eq!(state.next_tick_interval_secs(&config), 480);
        assert_eq!(state.overhead_backoff.healthy_ticks, 0);

        for (before, after) in [(480, 240), (240, 120), (120, 60)] {
            for _ in 0..2 {
                state.observe_overhead_budget(&config, false);
                assert_eq!(state.next_tick_interval_secs(&config), before);
            }
            state.observe_overhead_budget(&config, false);
            assert_eq!(state.next_tick_interval_secs(&config), after);
            assert_eq!(state.overhead_backoff.healthy_ticks, 0);
        }
        assert_eq!(state.overhead_backoff.interval_secs, 0);
        state.observe_overhead_budget(&config, false);
        assert_eq!(state.overhead_backoff.healthy_ticks, 0);
    }

    #[test]
    fn overhead_backoff_survives_restart_without_reusing_recovery_streak() {
        let config = DaemonConfig::default();
        let mut state = DaemonState::new();
        state.observe_overhead_budget(&config, true);
        state.observe_overhead_budget(&config, false);
        state.observe_overhead_budget(&config, false);
        let saved = serde_json::to_value(&state).unwrap();
        assert_eq!(saved["overhead_backoff"]["healthy_ticks"], 2);

        let mut restored: DaemonState = serde_json::from_value(saved).unwrap();
        assert_eq!(restored.next_tick_interval_secs(&config), 120);
        assert_eq!(restored.overhead_backoff.healthy_ticks, 2);
        restored.interrupt_overhead_recovery();
        assert_eq!(restored.overhead_backoff.healthy_ticks, 0);
        for _ in 0..2 {
            restored.observe_overhead_budget(&config, false);
            assert_eq!(restored.next_tick_interval_secs(&config), 120);
        }
        restored.observe_overhead_budget(&config, false);
        assert_eq!(restored.next_tick_interval_secs(&config), 60);
    }

    #[test]
    fn overhead_backoff_defaults_allow_existing_config_and_state() {
        let mut config = serde_json::to_value(DaemonConfig::default()).unwrap();
        config.as_object_mut().unwrap().remove("overhead_backoff");
        let config: DaemonConfig = serde_json::from_value(config).unwrap();
        assert_eq!(config.overhead_backoff.max_interval_secs, 300);
        assert_eq!(config.overhead_backoff.healthy_ticks_before_recovery, 3);

        let partial: OverheadBackoffConfig =
            serde_json::from_str(r#"{"healthy_ticks_before_recovery":5}"#).unwrap();
        assert_eq!(partial.max_interval_secs, 300);
        assert_eq!(partial.healthy_ticks_before_recovery, 5);

        let mut state = serde_json::to_value(DaemonState::new()).unwrap();
        state.as_object_mut().unwrap().remove("overhead_backoff");
        let state: DaemonState = serde_json::from_value(state).unwrap();
        assert_eq!(state.overhead_backoff.interval_secs, 0);
        assert_eq!(state.next_tick_interval_secs(&config), 60);
    }

    #[test]
    fn overhead_backoff_reconfiguration_bounds_the_existing_delay() {
        let mut config = DaemonConfig::default();
        let mut state = DaemonState::new();
        state.observe_overhead_budget(&config, true);
        state.observe_overhead_budget(&config, true);
        assert_eq!(state.next_tick_interval_secs(&config), 240);

        config.tick_interval_secs = 30;
        config.overhead_backoff.max_interval_secs = 90;
        config.overhead_backoff.healthy_ticks_before_recovery = 2;
        assert_eq!(state.next_tick_interval_secs(&config), 90);
        state.observe_overhead_budget(&config, false);
        assert_eq!(state.overhead_backoff.interval_secs, 90);
        state.observe_overhead_budget(&config, false);
        assert_eq!(state.next_tick_interval_secs(&config), 45);
        state.observe_overhead_budget(&config, false);
        state.observe_overhead_budget(&config, false);
        assert_eq!(state.overhead_backoff.interval_secs, 0);
        assert_eq!(state.next_tick_interval_secs(&config), 30);

        config.tick_interval_secs = 180;
        state.observe_overhead_budget(&config, true);
        assert_eq!(state.next_tick_interval_secs(&config), 180);
    }

    #[test]
    fn overhead_backoff_handles_zero_and_extreme_values_without_overflow() {
        let mut config = DaemonConfig {
            tick_interval_secs: 0,
            overhead_backoff: OverheadBackoffConfig {
                max_interval_secs: 0,
                healthy_ticks_before_recovery: 0,
            },
            ..Default::default()
        };
        let mut state = DaemonState::new();
        state.observe_overhead_budget(&config, true);
        assert_eq!(state.next_tick_interval_secs(&config), 1);
        state.observe_overhead_budget(&config, false);
        assert_eq!(state.next_tick_interval_secs(&config), 1);
        assert_eq!(state.overhead_backoff.interval_secs, 0);

        config.tick_interval_secs = u64::MAX;
        config.overhead_backoff.max_interval_secs = u64::MAX;
        for _ in 0..3 {
            state.observe_overhead_budget(&config, true);
            assert_eq!(state.next_tick_interval_secs(&config), u64::MAX);
        }

        config = DaemonConfig::default();
        let mut saved = serde_json::to_value(&state).unwrap();
        saved["overhead_backoff"]["healthy_ticks"] = serde_json::json!(u32::MAX);
        let mut restored: DaemonState = serde_json::from_value(saved).unwrap();
        assert_eq!(restored.next_tick_interval_secs(&config), 300);
        restored.observe_overhead_budget(&config, false);
        assert_eq!(restored.overhead_backoff.interval_secs, 300);
        assert_eq!(restored.overhead_backoff.healthy_ticks, 1);
    }

    #[test]
    fn overhead_backoff_overrides_emergency_cadence_without_clearing_pressure() {
        let config = DaemonConfig::default();
        let mut state = DaemonState::new();
        let mut metrics = pressure_metrics(40, Some(75.0), 1000);
        state.observe_memory_pressure(&config, &metrics);
        advance_reading(&mut metrics);
        state.observe_memory_pressure(&config, &metrics);
        assert_eq!(state.memory_pressure.mode(), PressureMode::Emergency);
        assert_eq!(state.next_tick_interval_secs(&config), 15);

        state.observe_overhead_budget(&config, true);
        assert_eq!(state.next_tick_interval_secs(&config), 120);
        for _ in 0..2 {
            advance_reading(&mut metrics);
            state.observe_memory_pressure(&config, &metrics);
            state.observe_overhead_budget(&config, false);
            assert_eq!(state.next_tick_interval_secs(&config), 120);
        }
        state.observe_overhead_budget(&config, false);
        assert_eq!(state.next_tick_interval_secs(&config), 15);
        assert_eq!(state.memory_pressure.mode(), PressureMode::Emergency);
        assert!(state.memory_pressure_plan_pending);
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

    fn typed_pressure_metrics(
        started_at: std::time::Instant,
        elapsed_secs: u64,
        cpu: (f64, u64),
        io: (f64, u64),
    ) -> TickMetrics {
        use crate::collect::pressure::{LoadAvg, PsiLine, PsiResource};

        let mut metrics = pressure_metrics(40, Some(0.0), 1000 + elapsed_secs);
        metrics.pressure_observed_at =
            Some(started_at + std::time::Duration::from_secs(elapsed_secs));
        let psi = |(average, total_us)| PsiResource {
            some: Some(PsiLine {
                avg10: average,
                avg60: average,
                avg300: average,
                total_us,
            }),
            full: None,
        };
        let pressure = metrics.pressure.as_mut().unwrap();
        pressure.cpu = Some(psi(cpu));
        pressure.io = Some(psi(io));
        pressure.load = Some(LoadAvg {
            one: 1.0,
            five: 1.0,
            fifteen: 1.0,
            runnable: Some(1),
            total: Some(200),
        });
        metrics
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
                assert_eq!(fired[0].current_value, Some(10.0));
                assert_eq!(fired[0].threshold, Some(4.0));
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
    fn typed_pressure_episodes_share_planning_and_retry_until_delivery_completes() {
        use crate::decision::pressure_regime::{RegimeKind, Severity};

        let config = DaemonConfig::default();
        let mut state = DaemonState::new();
        let mut triggers = triggers::TriggerState::new(&config.triggers);
        let started_at = std::time::Instant::now();
        let mut callbacks = 0;

        for tick in 0..7 {
            // The counters agree with the 40% CPU and 20% I/O stalls in each
            // real one-second monotonic interval, not only the PSI averages.
            let metrics = typed_pressure_metrics(
                started_at,
                tick,
                (40.0, 1_000_000 + tick * 400_000),
                (20.0, 1_000_000 + tick * 200_000),
            );
            let outcome = process_tick(
                &config,
                &mut state,
                &mut triggers,
                &metrics,
                &mut |escalation_config, fired| {
                    assert!(!escalation_config.allow_auto_mitigation);
                    assert_eq!(fired.len(), 2, "both regimes use one planning call");
                    let mut kinds = Vec::new();
                    for trigger in fired {
                        assert_eq!(trigger.kind, triggers::TriggerKind::PressureRegime);
                        assert_eq!(trigger.sustained_ticks, 3);
                        assert!(trigger.current_value.is_none());
                        assert!(trigger.memory_pressure.is_none());
                        let regime = trigger.pressure_regime.as_ref().unwrap();
                        assert_eq!(regime.severity, Severity::Crit);
                        kinds.push(regime.kind);
                    }
                    kinds.sort();
                    assert_eq!(kinds, [RegimeKind::CpuContention, RegimeKind::IoBound]);
                    let status = match callbacks {
                        0 => escalation::EscalationStatus::Deferred,
                        1 => escalation::EscalationStatus::Failed,
                        2 => escalation::EscalationStatus::Completed,
                        _ => panic!("a delivered active episode must not create another plan"),
                    };
                    callbacks += 1;
                    escalation::EscalationOutcome {
                        status,
                        reason: format!("review-plan delivery attempt {callbacks}"),
                        session_id: (status == escalation::EscalationStatus::Completed)
                            .then(|| "typed-pressure-review".to_string()),
                        provenance_summary: None,
                    }
                },
            );

            match tick {
                0 | 1 => {
                    assert!(outcome.triggers_fired.is_empty());
                    assert!(outcome.escalation.is_none());
                    assert!(triggers.pressure.pending.is_empty());
                }
                2 | 3 => {
                    let expected = if tick == 2 {
                        escalation::EscalationStatus::Deferred
                    } else {
                        escalation::EscalationStatus::Failed
                    };
                    assert_eq!(outcome.escalation.as_ref().unwrap().status, expected);
                    assert_eq!(triggers.pressure.pending.len(), 2);
                    assert_eq!(state.escalation_count, 0);
                }
                4 => {
                    assert_eq!(
                        outcome.escalation.as_ref().unwrap().status,
                        escalation::EscalationStatus::Completed
                    );
                    assert!(triggers.pressure.pending.is_empty());
                    assert_eq!(state.escalation_count, 1);
                }
                _ => {
                    assert!(outcome.triggers_fired.is_empty());
                    assert!(outcome.escalation.is_none());
                    assert!(triggers.pressure.pending.is_empty());
                    assert_eq!(triggers.pressure.active.len(), 2);
                }
            }
        }
        assert_eq!(callbacks, 3);
        assert_eq!(state.deferred_count, 1);
        assert_eq!(state.escalation_count, 1);
    }

    #[test]
    fn typed_pressure_requires_fresh_confirmation_and_observed_recovery_between_plans() {
        use crate::decision::pressure_regime::RegimeKind;

        let config = DaemonConfig::default();
        let mut state = DaemonState::new();
        let mut triggers = triggers::TriggerState::new(&config.triggers);
        let started_at = std::time::Instant::now();
        let readings = [
            Some(40),
            Some(40),
            None,
            Some(40),
            Some(40),
            Some(40),
            Some(0),
            Some(0),
            None,
            Some(0),
            Some(0),
            Some(0),
            Some(40),
            Some(40),
            Some(40),
        ];
        let mut cpu_total_us = 1_000_000;
        let mut planned_ticks = Vec::new();
        for (tick, reading) in readings.into_iter().enumerate() {
            cpu_total_us += reading.unwrap_or(0) * 10_000;
            let mut metrics = typed_pressure_metrics(
                started_at,
                tick as u64,
                (reading.unwrap_or(0) as f64, cpu_total_us),
                (0.0, 1_000_000),
            );
            if reading.is_none() {
                metrics.pressure = None;
            }
            let outcome = process_tick(
                &config,
                &mut state,
                &mut triggers,
                &metrics,
                &mut |escalation_config, fired| {
                    assert!(!escalation_config.allow_auto_mitigation);
                    assert_eq!(fired.len(), 1);
                    assert_eq!(fired[0].kind, triggers::TriggerKind::PressureRegime);
                    assert_eq!(
                        fired[0].pressure_regime.as_ref().unwrap().kind,
                        RegimeKind::CpuContention
                    );
                    planned_ticks.push(tick);
                    escalation::EscalationOutcome {
                        status: escalation::EscalationStatus::Completed,
                        reason: "review plan delivered".to_string(),
                        session_id: Some(format!("pressure-episode-{tick}")),
                        provenance_summary: None,
                    }
                },
            );
            assert_eq!(outcome.escalation.is_some(), matches!(tick, 5 | 14));
            assert_eq!(
                triggers
                    .pressure
                    .active
                    .contains_key(&RegimeKind::CpuContention),
                matches!(tick, 5..=10 | 14),
                "missing data must interrupt confirmation and recovery at tick {tick}"
            );
        }
        assert_eq!(planned_ticks, [5, 14]);
        assert_eq!(state.escalation_count, 2);
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
