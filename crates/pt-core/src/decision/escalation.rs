//! Escalation and notification system for dormant daemon mode.
//!
//! Evaluates triggers (memory pressure, CPU pressure, orphan spikes),
//! rate-limits notifications, and renders redaction-safe notification
//! payloads with actionable review commands.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A trigger condition that may generate a notification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationTrigger {
    /// Unique trigger ID for dedup/cooldown.
    pub trigger_id: String,
    /// Type of trigger.
    pub trigger_type: TriggerType,
    /// Severity level.
    pub severity: Severity,
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
    Desktop,
    Email,
    Webhook,
}

/// A rendered notification ready for delivery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    /// Severity.
    pub severity: Severity,
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
}

impl Default for EscalationConfig {
    fn default() -> Self {
        Self {
            trigger_cooldown_secs: 300.0, // 5 minutes
            max_notifications_per_hour: 10,
            bundle_window_secs: 60.0,
            min_severity: Severity::Warning,
        }
    }
}

/// Manages escalation state and rate limiting.
#[derive(Debug, Clone)]
pub struct EscalationManager {
    config: EscalationConfig,
    /// Last notification time per trigger_id.
    last_notified: HashMap<String, f64>,
    /// Notification timestamps for global rate limiting.
    notification_log: Vec<f64>,
    /// Pending triggers waiting for bundle window.
    pending_triggers: Vec<EscalationTrigger>,
}

impl EscalationManager {
    pub fn new(config: EscalationConfig) -> Self {
        Self {
            config,
            last_notified: HashMap::new(),
            notification_log: Vec::new(),
            pending_triggers: Vec::new(),
        }
    }

    /// Submit a trigger. Returns true if it was accepted (not rate-limited).
    pub fn submit_trigger(&mut self, trigger: EscalationTrigger) -> bool {
        // Check severity threshold.
        if trigger.severity < self.config.min_severity {
            return false;
        }

        // Check per-trigger cooldown.
        if let Some(&last) = self.last_notified.get(&trigger.trigger_id) {
            if trigger.detected_at - last < self.config.trigger_cooldown_secs {
                return false;
            }
        }

        self.pending_triggers.push(trigger);
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

        // Sort pending by severity (critical first).
        self.pending_triggers
            .sort_by(|a, b| b.severity.cmp(&a.severity));

        let mut notifications = Vec::new();

        // Try to bundle triggers within the bundle window.
        let drain: Vec<EscalationTrigger> = self.pending_triggers.drain(..).collect();

        if drain.len() == 1 {
            let t = &drain[0];
            let notif = render_notification(t, false, 1);
            self.last_notified.insert(t.trigger_id.clone(), now);
            self.notification_log.push(now);
            notifications.push(notif);
        } else {
            // Bundle all into one notification.
            let max_severity = drain.iter().map(|t| t.severity).max().unwrap();
            let session_id = drain.iter().find_map(|t| t.session_id.clone());
            let summaries: Vec<String> = drain
                .iter()
                .map(|t| format!("- [{}] {}", t.severity, t.summary))
                .collect();

            let count = drain.len();
            for t in &drain {
                self.last_notified.insert(t.trigger_id.clone(), now);
            }
            self.notification_log.push(now);

            notifications.push(Notification {
                severity: max_severity,
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
            });
        }

        notifications
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
        let cooldown = self.config.trigger_cooldown_secs;
        self.last_notified
            .retain(|_, &mut ts| now - ts < cooldown * 2.0);
    }
}

fn render_notification(trigger: &EscalationTrigger, bundled: bool, count: usize) -> Notification {
    let title = format!(
        "Process Triage [{}]: {}",
        trigger.severity, trigger.trigger_type
    );
    Notification {
        severity: trigger.severity,
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
        created_at: trigger.detected_at,
        bundled,
        trigger_count: count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_trigger(id: &str, severity: Severity, ts: f64) -> EscalationTrigger {
        EscalationTrigger {
            trigger_id: id.to_string(),
            trigger_type: TriggerType::MemoryPressure,
            severity,
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
        assert!(!mgr.submit_trigger(make_trigger("t1", Severity::Warning, 1100.0)));

        // After cooldown → accepted.
        assert!(mgr.submit_trigger(make_trigger("t1", Severity::Warning, 1400.0)));
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
}
