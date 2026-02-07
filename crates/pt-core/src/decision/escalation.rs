//! Escalation and notification system for dormant daemon mode.
//!
//! Evaluates triggers (memory pressure, CPU pressure, orphan spikes),
//! rate-limits notifications, and renders redaction-safe notification
//! payloads with actionable review commands.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedTriggerState {
    first_seen_at: f64,
    last_seen_at: f64,
    last_sent_at: Option<f64>,
    last_sent_level: Option<EscalationLevel>,
}

/// Persisted state for the escalation manager.
///
/// Stored by the daemon so notification escalation survives restarts.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PersistedEscalationState {
    #[serde(default)]
    states: HashMap<String, PersistedTriggerState>,
    #[serde(default)]
    notification_log: Vec<f64>,
}

/// A trigger condition that may generate a notification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationTrigger {
    /// Unique trigger ID for dedup/cooldown.
    pub trigger_id: String,
    /// Stable dedupe key (process identity + finding type). Defaults to trigger_id.
    #[serde(default)]
    pub dedupe_key: String,
    /// Type of trigger.
    pub trigger_type: TriggerType,
    /// Severity level.
    pub severity: Severity,
    /// Confidence (0-1) if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
    /// Human-readable summary (redaction-safe).
    pub summary: String,
    /// Timestamp when the trigger was detected.
    pub detected_at: f64,
    /// Associated session ID.
    pub session_id: Option<String>,
}

/// Types of escalation triggers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TriggerType {
    /// Sustained memory pressure.
    MemoryPressure,
    /// Sustained CPU pressure.
    CpuPressure,
    /// Orphan/zombie spike.
    OrphanSpike,
    /// Repeated high-risk candidates.
    HighRiskCandidates,
    /// Fleet-level alert.
    FleetAlert,
    /// Resource threshold exceeded.
    ThresholdExceeded,
}

impl std::fmt::Display for TriggerType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MemoryPressure => write!(f, "memory_pressure"),
            Self::CpuPressure => write!(f, "cpu_pressure"),
            Self::OrphanSpike => write!(f, "orphan_spike"),
            Self::HighRiskCandidates => write!(f, "high_risk_candidates"),
            Self::FleetAlert => write!(f, "fleet_alert"),
            Self::ThresholdExceeded => write!(f, "threshold_exceeded"),
        }
    }
}

/// Severity levels for notifications.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Warning => write!(f, "warning"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

/// Notification channel type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NotificationChannel {
    /// Durable local inbox (always available).
    Inbox,
    Desktop,
    Email,
    Sms,
    PagerDuty,
    Webhook,
}

/// Escalation ladder level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationLevel {
    L1,
    L2,
    L3,
    L4,
}

/// A rendered notification ready for delivery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    /// Severity.
    pub severity: Severity,
    /// Escalation level.
    pub level: EscalationLevel,
    /// Channels to deliver on (best-effort; delivery layer may not support all).
    pub channels: Vec<NotificationChannel>,
    /// Title line.
    pub title: String,
    /// Body text (redaction-safe).
    pub body: String,
    /// Review command for humans.
    pub human_review_cmd: Option<String>,
    /// Review command for agents.
    pub agent_review_cmd: Option<String>,
    /// Session ID for reference.
    pub session_id: Option<String>,
    /// Timestamp.
    pub created_at: f64,
    /// Whether this is a bundled notification (multiple triggers).
    pub bundled: bool,
    /// Number of triggers bundled.
    pub trigger_count: usize,
    /// Stable dedupe key for the notification bundle.
    pub dedupe_key: String,
}

/// Configuration for the escalation system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationConfig {
    /// Per-trigger cooldown in seconds.
    pub trigger_cooldown_secs: f64,
    /// Global max notifications per hour.
    pub max_notifications_per_hour: usize,
    /// Time window for bundling (seconds).
    pub bundle_window_secs: f64,
    /// Minimum severity to send notifications.
    pub min_severity: Severity,

    /// Level 2 delay (seconds) since first_seen.
    pub level2_after_secs: f64,
    /// Level 3 delay (seconds) since first_seen.
    pub level3_after_secs: f64,
    /// Level 4 delay (seconds) since first_seen.
    pub level4_after_secs: f64,

    /// Minimum confidence to allow escalation to Level 2+ (if confidence is present).
    /// If confidence is None, escalation is allowed based on severity alone.
    pub min_confidence_for_escalation: f64,
}

impl Default for EscalationConfig {
    fn default() -> Self {
        Self {
            trigger_cooldown_secs: 300.0, // 5 minutes
            max_notifications_per_hour: 10,
            bundle_window_secs: 60.0,
            min_severity: Severity::Warning,
            level2_after_secs: 3600.0,        // 1 hour
            level3_after_secs: 24.0 * 3600.0, // 24 hours
            level4_after_secs: 48.0 * 3600.0, // 48 hours
            min_confidence_for_escalation: 0.7,
        }
    }
}

#[derive(Debug, Clone)]
struct TriggerState {
    first_seen_at: f64,
    last_seen_at: f64,
    last_sent_at: Option<f64>,
    last_sent_level: Option<EscalationLevel>,
}

/// Manages escalation state and rate limiting.
#[derive(Debug, Clone)]
pub struct EscalationManager {
    config: EscalationConfig,
    /// State per dedupe_key.
    states: HashMap<String, TriggerState>,
    /// Notification timestamps for global rate limiting.
    notification_log: Vec<f64>,
    /// Pending triggers since last flush (keyed by dedupe_key).
    pending_triggers: HashMap<String, EscalationTrigger>,
}

impl EscalationManager {
    pub fn new(config: EscalationConfig) -> Self {
        Self {
            config,
            states: HashMap::new(),
            notification_log: Vec::new(),
            pending_triggers: HashMap::new(),
        }
    }

    pub fn from_persisted(config: EscalationConfig, persisted: PersistedEscalationState) -> Self {
        let mut states = HashMap::new();
        for (k, v) in persisted.states {
            states.insert(
                k,
                TriggerState {
                    first_seen_at: v.first_seen_at,
                    last_seen_at: v.last_seen_at,
                    last_sent_at: v.last_sent_at,
                    last_sent_level: v.last_sent_level,
                },
            );
        }
        Self {
            config,
            states,
            notification_log: persisted.notification_log,
            pending_triggers: HashMap::new(),
        }
    }

    pub fn persisted_state(&self) -> PersistedEscalationState {
        let mut states = HashMap::new();
        for (k, v) in &self.states {
            states.insert(
                k.clone(),
                PersistedTriggerState {
                    first_seen_at: v.first_seen_at,
                    last_seen_at: v.last_seen_at,
                    last_sent_at: v.last_sent_at,
                    last_sent_level: v.last_sent_level,
                },
            );
        }
        PersistedEscalationState {
            states,
            notification_log: self.notification_log.clone(),
        }
    }

    /// Drop all escalation state for a dedupe key.
    ///
    /// Use this when a notification is acknowledged so we do not keep escalating.
    pub fn forget_key(&mut self, dedupe_key: &str) {
        self.states.remove(dedupe_key);
        self.pending_triggers.remove(dedupe_key);
    }

    pub fn has_key(&self, dedupe_key: &str) -> bool {
        self.states.contains_key(dedupe_key)
    }

    /// Submit a trigger. Returns true if it was accepted (not rate-limited).
    pub fn submit_trigger(&mut self, trigger: EscalationTrigger) -> bool {
        // Check severity threshold.
        if trigger.severity < self.config.min_severity {
            return false;
        }

        let dedupe_key = if trigger.dedupe_key.is_empty() {
            trigger.trigger_id.clone()
        } else {
            trigger.dedupe_key.clone()
        };

        let st = self
            .states
            .entry(dedupe_key.clone())
            .or_insert(TriggerState {
                first_seen_at: trigger.detected_at,
                last_seen_at: trigger.detected_at,
                last_sent_at: None,
                last_sent_level: None,
            });
        st.last_seen_at = trigger.detected_at;

        // Keep the most recent trigger details for the dedupe_key.
        self.pending_triggers.insert(dedupe_key, trigger);
        true
    }

    /// Flush pending triggers into notifications.
    /// Call this periodically (e.g., after each scan cycle).
    pub fn flush(&mut self, now: f64) -> Vec<Notification> {
        if self.pending_triggers.is_empty() {
            return vec![];
        }

        // Check global rate limit.
        self.notification_log.retain(|&ts| now - ts < 3600.0);
        let remaining_budget = self
            .config
            .max_notifications_per_hour
            .saturating_sub(self.notification_log.len());
        if remaining_budget == 0 {
            self.pending_triggers.clear();
            return vec![];
        }

        let mut drain: Vec<(String, EscalationTrigger)> = self.pending_triggers.drain().collect();
        // Sort pending by severity (critical first) for deterministic bundling.
        drain.sort_by(|a, b| b.1.severity.cmp(&a.1.severity));

        // Determine which triggers should emit a notification now (respect cooldown per level,
        // but allow higher-level escalation even within the cooldown window).
        let mut emit: Vec<(String, EscalationTrigger, EscalationLevel)> = Vec::new();
        for (key, t) in drain {
            let st = match self.states.get(&key) {
                Some(s) => s.clone(),
                None => continue,
            };
            let desired = desired_level(&self.config, &t, &st, now);

            let should_emit = match (st.last_sent_at, st.last_sent_level) {
                (None, None) => true,
                (Some(last_ts), Some(last_level)) => {
                    if desired > last_level {
                        true
                    } else if desired == last_level {
                        now - last_ts >= self.config.trigger_cooldown_secs
                    } else {
                        // Don't de-escalate notifications automatically.
                        false
                    }
                }
                _ => true,
            };

            if should_emit {
                emit.push((key, t, desired));
            }
        }

        if emit.is_empty() {
            return vec![];
        }

        // Consume one budget unit for this flush. If we ever want multiple notifications per
        // flush, we'd need to account budget per emitted notification.
        self.notification_log.push(now);

        if emit.len() == 1 {
            let (key, t, level) = emit.remove(0);
            self.update_state_sent(&key, now, level);
            return vec![render_notification(&t, level, false, 1, now)];
        }

        // Bundle all into one notification.
        let Some(max_severity) = emit.iter().map(|(_, t, _)| t.severity).max() else {
            return vec![];
        };
        let session_id = emit.iter().find_map(|(_, t, _)| t.session_id.clone());
        let max_level = emit
            .iter()
            .map(|(_, _, l)| *l)
            .max()
            .unwrap_or(EscalationLevel::L1);
        let summaries: Vec<String> = emit
            .iter()
            .map(|(_, t, level)| {
                format!("- [{}/{}] {}", t.severity, level_string(*level), t.summary)
            })
            .collect();

        let count = emit.len();
        let mut bundle_keys: Vec<String> = emit.iter().map(|(k, _, _)| k.clone()).collect();
        bundle_keys.sort();
        let dedupe_key = bundle_dedupe_key(&bundle_keys);
        for (key, _, level) in emit {
            self.update_state_sent(&key, now, level);
        }

        vec![Notification {
            severity: max_severity,
            level: max_level,
            channels: channels_for_level(max_level),
            title: format!("Process Triage: {} alerts", count),
            body: summaries.join("\n"),
            human_review_cmd: session_id
                .as_ref()
                .map(|sid| format!("pt review --session {}", sid)),
            agent_review_cmd: session_id
                .as_ref()
                .map(|sid| format!("pt agent plan --session {}", sid)),
            session_id,
            created_at: now,
            bundled: true,
            trigger_count: count,
            dedupe_key,
        }]
    }

    /// Number of pending triggers.
    pub fn pending_count(&self) -> usize {
        self.pending_triggers.len()
    }

    /// Total notifications sent.
    pub fn total_sent(&self) -> usize {
        self.notification_log.len()
    }

    /// Prune old rate-limit state.
    pub fn prune(&mut self, now: f64) {
        self.notification_log.retain(|&ts| now - ts < 3600.0);
        // Drop trigger states after they haven't been seen for a long time.
        // This keeps the map bounded in long-running daemon mode.
        let stale_after = 7.0 * 24.0 * 3600.0; // 7 days
        self.states
            .retain(|_, st| now - st.last_seen_at < stale_after);
    }
}

fn bundle_dedupe_key(keys: &[String]) -> String {
    if keys.is_empty() {
        return "bundle:empty".to_string();
    }

    // FNV-1a 64-bit (simple, dependency-free, stable across platforms).
    let mut hash: u64 = 0xcbf29ce484222325;
    for k in keys {
        for b in k.as_bytes() {
            hash ^= u64::from(*b);
            hash = hash.wrapping_mul(0x00000100000001B3);
        }
        // Separator.
        hash ^= 0xff;
        hash = hash.wrapping_mul(0x00000100000001B3);
    }

    format!("bundle:{:016x}", hash)
}

fn desired_level(
    config: &EscalationConfig,
    trigger: &EscalationTrigger,
    state: &TriggerState,
    now: f64,
) -> EscalationLevel {
    let age = now - state.first_seen_at;
    let confidence_ok = trigger
        .confidence
        .map(|c| c >= config.min_confidence_for_escalation)
        .unwrap_or(true);

    // Severity can override confidence gating.
    let severity_override = trigger.severity >= Severity::Critical;

    if age >= config.level4_after_secs && (confidence_ok || severity_override) {
        EscalationLevel::L4
    } else if age >= config.level3_after_secs && (confidence_ok || severity_override) {
        EscalationLevel::L3
    } else if age >= config.level2_after_secs && (confidence_ok || severity_override) {
        EscalationLevel::L2
    } else {
        EscalationLevel::L1
    }
}

fn channels_for_level(level: EscalationLevel) -> Vec<NotificationChannel> {
    match level {
        EscalationLevel::L1 => vec![NotificationChannel::Inbox, NotificationChannel::Desktop],
        EscalationLevel::L2 => vec![
            NotificationChannel::Inbox,
            NotificationChannel::Desktop,
            NotificationChannel::Email,
        ],
        EscalationLevel::L3 => vec![
            NotificationChannel::Inbox,
            NotificationChannel::Desktop,
            NotificationChannel::Email,
            NotificationChannel::Webhook,
            NotificationChannel::PagerDuty,
            NotificationChannel::Sms,
        ],
        EscalationLevel::L4 => vec![
            NotificationChannel::Inbox,
            NotificationChannel::Desktop,
            NotificationChannel::Email,
            NotificationChannel::Webhook,
            NotificationChannel::PagerDuty,
            NotificationChannel::Sms,
        ],
    }
}

fn level_string(level: EscalationLevel) -> &'static str {
    match level {
        EscalationLevel::L1 => "L1",
        EscalationLevel::L2 => "L2",
        EscalationLevel::L3 => "L3",
        EscalationLevel::L4 => "L4",
    }
}

impl EscalationManager {
    fn update_state_sent(&mut self, dedupe_key: &str, now: f64, level: EscalationLevel) {
        if let Some(st) = self.states.get_mut(dedupe_key) {
            st.last_sent_at = Some(now);
            st.last_sent_level = Some(level);
        }
    }
}

fn render_notification(
    trigger: &EscalationTrigger,
    level: EscalationLevel,
    bundled: bool,
    count: usize,
    created_at: f64,
) -> Notification {
    let title = format!(
        "Process Triage [{}]: {}",
        trigger.severity, trigger.trigger_type
    );
    Notification {
        severity: trigger.severity,
        level,
        channels: channels_for_level(level),
        title,
        body: trigger.summary.clone(),
        human_review_cmd: trigger
            .session_id
            .as_ref()
            .map(|sid| format!("pt review --session {}", sid)),
        agent_review_cmd: trigger
            .session_id
            .as_ref()
            .map(|sid| format!("pt agent plan --session {}", sid)),
        session_id: trigger.session_id.clone(),
        created_at,
        bundled,
        trigger_count: count,
        dedupe_key: if trigger.dedupe_key.is_empty() {
            trigger.trigger_id.clone()
        } else {
            trigger.dedupe_key.clone()
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_trigger(id: &str, severity: Severity, ts: f64) -> EscalationTrigger {
        EscalationTrigger {
            trigger_id: id.to_string(),
            dedupe_key: id.to_string(),
            trigger_type: TriggerType::MemoryPressure,
            severity,
            confidence: Some(0.95),
            summary: format!("Test trigger {}", id),
            detected_at: ts,
            session_id: Some("pt-20260201-120000-abcd".to_string()),
        }
    }

    #[test]
    fn test_single_trigger() {
        let mut mgr = EscalationManager::new(EscalationConfig::default());
        assert!(mgr.submit_trigger(make_trigger("t1", Severity::Warning, 1000.0)));
        let notifs = mgr.flush(1000.0);
        assert_eq!(notifs.len(), 1);
        assert!(!notifs[0].bundled);
        assert!(notifs[0].human_review_cmd.is_some());
        assert_eq!(notifs[0].level, EscalationLevel::L1);
        assert_eq!(notifs[0].created_at, 1000.0);
    }

    #[test]
    fn test_single_notification_created_at_uses_flush_time() {
        let mut mgr = EscalationManager::new(EscalationConfig::default());
        assert!(mgr.submit_trigger(make_trigger("t1", Severity::Warning, 1000.0)));
        let notifs = mgr.flush(1500.0);
        assert_eq!(notifs.len(), 1);
        assert_eq!(notifs[0].created_at, 1500.0);
    }

    #[test]
    fn test_cooldown() {
        let mut mgr = EscalationManager::new(EscalationConfig {
            trigger_cooldown_secs: 300.0,
            ..Default::default()
        });
        assert!(mgr.submit_trigger(make_trigger("t1", Severity::Warning, 1000.0)));
        mgr.flush(1000.0);

        // Same trigger within cooldown → rejected.
        assert!(mgr.submit_trigger(make_trigger("t1", Severity::Warning, 1100.0)));
        let notifs = mgr.flush(1100.0);
        assert!(notifs.is_empty());

        // After cooldown → accepted.
        assert!(mgr.submit_trigger(make_trigger("t1", Severity::Warning, 1400.0)));
        let notifs = mgr.flush(1400.0);
        assert_eq!(notifs.len(), 1);
    }

    #[test]
    fn test_severity_filter() {
        let mut mgr = EscalationManager::new(EscalationConfig {
            min_severity: Severity::Warning,
            ..Default::default()
        });
        // Info is below threshold.
        assert!(!mgr.submit_trigger(make_trigger("t1", Severity::Info, 1000.0)));
        assert_eq!(mgr.pending_count(), 0);

        // Warning is at threshold.
        assert!(mgr.submit_trigger(make_trigger("t2", Severity::Warning, 1000.0)));
        assert_eq!(mgr.pending_count(), 1);
    }

    #[test]
    fn test_bundling() {
        let mut mgr = EscalationManager::new(EscalationConfig::default());
        mgr.submit_trigger(make_trigger("t1", Severity::Warning, 1000.0));
        mgr.submit_trigger(make_trigger("t2", Severity::Critical, 1000.0));
        mgr.submit_trigger(make_trigger("t3", Severity::Warning, 1000.0));

        let notifs = mgr.flush(1000.0);
        assert_eq!(notifs.len(), 1);
        assert!(notifs[0].bundled);
        assert_eq!(notifs[0].trigger_count, 3);
        assert_eq!(notifs[0].severity, Severity::Critical); // Max severity
    }

    #[test]
    fn test_global_rate_limit() {
        let mut mgr = EscalationManager::new(EscalationConfig {
            max_notifications_per_hour: 2,
            trigger_cooldown_secs: 0.0,
            ..Default::default()
        });

        mgr.submit_trigger(make_trigger("t1", Severity::Warning, 1000.0));
        mgr.flush(1000.0);

        mgr.submit_trigger(make_trigger("t2", Severity::Warning, 1001.0));
        mgr.flush(1001.0);

        // Third should be rate limited.
        mgr.submit_trigger(make_trigger("t3", Severity::Critical, 1002.0));
        let notifs = mgr.flush(1002.0);
        assert!(notifs.is_empty());
        assert_eq!(mgr.total_sent(), 2);
    }

    #[test]
    fn test_rate_limit_resets_after_hour() {
        let mut mgr = EscalationManager::new(EscalationConfig {
            max_notifications_per_hour: 1,
            trigger_cooldown_secs: 0.0,
            ..Default::default()
        });

        mgr.submit_trigger(make_trigger("t1", Severity::Warning, 1000.0));
        mgr.flush(1000.0);

        // After an hour, budget resets.
        mgr.submit_trigger(make_trigger("t2", Severity::Warning, 5000.0));
        let notifs = mgr.flush(5000.0);
        assert_eq!(notifs.len(), 1);
    }

    #[test]
    fn test_notification_contains_commands() {
        let mut mgr = EscalationManager::new(EscalationConfig::default());
        mgr.submit_trigger(make_trigger("t1", Severity::Critical, 1000.0));
        let notifs = mgr.flush(1000.0);

        let n = &notifs[0];
        assert!(n.human_review_cmd.as_ref().unwrap().contains("pt review"));
        assert!(n
            .agent_review_cmd
            .as_ref()
            .unwrap()
            .contains("pt agent plan"));
        assert!(n.session_id.is_some());
    }

    #[test]
    fn test_flush_empty() {
        let mut mgr = EscalationManager::new(EscalationConfig::default());
        let notifs = mgr.flush(1000.0);
        assert!(notifs.is_empty());
    }

    #[test]
    fn test_prune() {
        let mut mgr = EscalationManager::new(EscalationConfig {
            trigger_cooldown_secs: 100.0,
            ..Default::default()
        });
        mgr.submit_trigger(make_trigger("t1", Severity::Warning, 1000.0));
        mgr.flush(1000.0);

        mgr.prune(5000.0); // >3600s after notification
        assert_eq!(mgr.total_sent(), 0); // Pruned notification log.
    }

    #[test]
    fn test_different_trigger_ids_no_cooldown() {
        let mut mgr = EscalationManager::new(EscalationConfig {
            trigger_cooldown_secs: 300.0,
            ..Default::default()
        });
        assert!(mgr.submit_trigger(make_trigger("t1", Severity::Warning, 1000.0)));
        mgr.flush(1000.0);

        // Different trigger ID → no cooldown.
        assert!(mgr.submit_trigger(make_trigger("t2", Severity::Warning, 1001.0)));
    }

    #[test]
    fn test_time_based_escalation_levels() {
        let mut mgr = EscalationManager::new(EscalationConfig {
            trigger_cooldown_secs: 0.0,
            level2_after_secs: 10.0,
            level3_after_secs: 20.0,
            level4_after_secs: 30.0,
            ..Default::default()
        });

        mgr.submit_trigger(make_trigger("t1", Severity::Warning, 0.0));
        let n1 = mgr.flush(0.0);
        assert_eq!(n1.len(), 1);
        assert_eq!(n1[0].level, EscalationLevel::L1);

        // Same trigger later: escalates to L2
        mgr.submit_trigger(make_trigger("t1", Severity::Warning, 12.0));
        let n2 = mgr.flush(12.0);
        assert_eq!(n2.len(), 1);
        assert_eq!(n2[0].level, EscalationLevel::L2);

        mgr.submit_trigger(make_trigger("t1", Severity::Warning, 25.0));
        let n3 = mgr.flush(25.0);
        assert_eq!(n3.len(), 1);
        assert_eq!(n3[0].level, EscalationLevel::L3);

        mgr.submit_trigger(make_trigger("t1", Severity::Warning, 31.0));
        let n4 = mgr.flush(31.0);
        assert_eq!(n4.len(), 1);
        assert_eq!(n4[0].level, EscalationLevel::L4);
    }

    #[test]
    fn test_persisted_state_roundtrip() {
        let mut mgr = EscalationManager::new(EscalationConfig::default());
        mgr.submit_trigger(make_trigger("t1", Severity::Warning, 1000.0));
        let _ = mgr.flush(1000.0);

        let persisted = mgr.persisted_state();
        let mgr2 = EscalationManager::from_persisted(EscalationConfig::default(), persisted);
        // We can't access internals directly, but flush should not panic and
        // the manager should retain its send log.
        assert!(mgr2.total_sent() >= 1);
    }
}
