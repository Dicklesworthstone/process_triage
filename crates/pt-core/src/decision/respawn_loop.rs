//! Respawn loop detection and event persistence.
//!
//! Detects repeated kill→respawn cycles for process identities across sessions
//! and provides planning adjustments: down-weight kill contribution for processes
//! that always respawn, and recommend supervisor-level actions instead.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A record of a kill→respawn event for a process identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RespawnEvent {
    /// Fingerprint matching the process (e.g., command pattern hash).
    pub identity_key: String,
    /// Optional supervisor unit (e.g., systemd service name).
    pub supervisor_unit: Option<String>,
    /// Optional cgroup path.
    pub cgroup: Option<String>,
    /// Timestamp of the kill action (epoch seconds).
    pub kill_ts: f64,
    /// Timestamp when respawn was detected (epoch seconds).
    pub respawn_ts: f64,
    /// Delay between kill and respawn in seconds.
    pub respawn_delay_secs: f64,
    /// Session ID where the kill was issued.
    pub session_id: Option<String>,
}

/// Configuration for respawn loop detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RespawnLoopConfig {
    /// Minimum repeated respawns to declare a loop.
    pub min_respawns: usize,
    /// Maximum time window (seconds) within which respawns count as a loop.
    pub window_secs: f64,
    /// Maximum delay (seconds) between kill and respawn to consider as respawn.
    pub max_respawn_delay_secs: f64,
    /// Kill utility discount factor for respawning processes (0.0 to 1.0).
    /// Applied as: effective_kill_utility *= (1 - discount * loop_count / max_loops)
    pub kill_discount_factor: f64,
    /// Maximum loop count for discount saturation.
    pub max_loops_for_discount: usize,
}

impl Default for RespawnLoopConfig {
    fn default() -> Self {
        Self {
            min_respawns: 2,
            window_secs: 3600.0,
            max_respawn_delay_secs: 30.0,
            kill_discount_factor: 0.8,
            max_loops_for_discount: 5,
        }
    }
}

/// Summary of detected respawn loop for a process identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RespawnLoopDetection {
    /// Process identity key.
    pub identity_key: String,
    /// Number of kill→respawn cycles in the window.
    pub loop_count: usize,
    /// Whether this qualifies as a loop (count >= min_respawns).
    pub is_loop: bool,
    /// Average respawn delay (seconds).
    pub avg_respawn_delay_secs: f64,
    /// Recommended action.
    pub recommendation: RespawnRecommendation,
    /// Kill utility discount (0.0 = full discount, 1.0 = no discount).
    pub kill_utility_multiplier: f64,
}

/// Recommended action for a respawn loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RespawnRecommendation {
    /// Normal kill is fine (no loop detected).
    KillOk,
    /// Warn about respawn pattern but proceed with kill.
    WarnRespawn,
    /// Suggest supervisor stop instead of kill.
    SupervisorStop,
    /// Suggest disabling the supervisor unit entirely.
    SupervisorDisable,
}

impl std::fmt::Display for RespawnRecommendation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KillOk => write!(f, "kill_ok"),
            Self::WarnRespawn => write!(f, "warn_respawn"),
            Self::SupervisorStop => write!(f, "supervisor_stop"),
            Self::SupervisorDisable => write!(f, "supervisor_disable"),
        }
    }
}

/// Tracks respawn events and detects loops.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RespawnTracker {
    /// All recorded respawn events, keyed by identity_key.
    events: HashMap<String, Vec<RespawnEvent>>,
}

impl RespawnTracker {
    pub fn new() -> Self {
        Self {
            events: HashMap::new(),
        }
    }

    /// Record a respawn event.
    pub fn record_event(&mut self, event: RespawnEvent) {
        self.events
            .entry(event.identity_key.clone())
            .or_default()
            .push(event);
    }

    /// Record a kill→respawn pair.
    pub fn record_respawn(
        &mut self,
        identity_key: String,
        supervisor_unit: Option<String>,
        cgroup: Option<String>,
        kill_ts: f64,
        respawn_ts: f64,
        session_id: Option<String>,
    ) {
        let delay = respawn_ts - kill_ts;
        self.record_event(RespawnEvent {
            identity_key,
            supervisor_unit,
            cgroup,
            kill_ts,
            respawn_ts,
            respawn_delay_secs: delay.max(0.0),
            session_id,
        });
    }

    /// Detect respawn loop for a given identity.
    pub fn detect_loop(
        &self,
        identity_key: &str,
        config: &RespawnLoopConfig,
        now: f64,
    ) -> RespawnLoopDetection {
        let events = match self.events.get(identity_key) {
            Some(evts) => evts,
            None => {
                return RespawnLoopDetection {
                    identity_key: identity_key.to_string(),
                    loop_count: 0,
                    is_loop: false,
                    avg_respawn_delay_secs: 0.0,
                    recommendation: RespawnRecommendation::KillOk,
                    kill_utility_multiplier: 1.0,
                };
            }
        };

        // Filter events within the time window and with acceptable delay.
        let recent: Vec<&RespawnEvent> = events
            .iter()
            .filter(|e| {
                (now - e.kill_ts) <= config.window_secs
                    && e.respawn_delay_secs <= config.max_respawn_delay_secs
            })
            .collect();

        let loop_count = recent.len();
        let is_loop = loop_count >= config.min_respawns;

        let avg_delay = if recent.is_empty() {
            0.0
        } else {
            recent.iter().map(|e| e.respawn_delay_secs).sum::<f64>() / recent.len() as f64
        };

        let has_supervisor = events.iter().any(|e| e.supervisor_unit.is_some());

        let recommendation = if !is_loop {
            RespawnRecommendation::KillOk
        } else if loop_count >= config.max_loops_for_discount && has_supervisor {
            RespawnRecommendation::SupervisorDisable
        } else if has_supervisor {
            RespawnRecommendation::SupervisorStop
        } else {
            RespawnRecommendation::WarnRespawn
        };

        let discount = if is_loop {
            let ratio = (loop_count as f64 / config.max_loops_for_discount as f64).min(1.0);
            1.0 - config.kill_discount_factor * ratio
        } else {
            1.0
        };

        RespawnLoopDetection {
            identity_key: identity_key.to_string(),
            loop_count,
            is_loop,
            avg_respawn_delay_secs: avg_delay,
            recommendation,
            kill_utility_multiplier: discount,
        }
    }

    /// Get all identities with detected loops.
    pub fn all_loops(&self, config: &RespawnLoopConfig, now: f64) -> Vec<RespawnLoopDetection> {
        self.events
            .keys()
            .map(|key| self.detect_loop(key, config, now))
            .filter(|d| d.is_loop)
            .collect()
    }

    /// Number of tracked identities.
    pub fn identity_count(&self) -> usize {
        self.events.len()
    }

    /// Total event count.
    pub fn event_count(&self) -> usize {
        self.events.values().map(|v| v.len()).sum()
    }

    /// Prune events older than the window.
    pub fn prune(&mut self, config: &RespawnLoopConfig, now: f64) {
        for events in self.events.values_mut() {
            events.retain(|e| (now - e.kill_ts) <= config.window_secs);
        }
        self.events.retain(|_, v| !v.is_empty());
    }
}

/// Apply respawn loop discount to a kill utility score.
pub fn discount_kill_utility(base_utility: f64, detection: &RespawnLoopDetection) -> f64 {
    base_utility * detection.kill_utility_multiplier
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tracker_with_respawns(n: usize, delay: f64) -> (RespawnTracker, f64) {
        let mut tracker = RespawnTracker::new();
        let base_ts = 1000.0;
        for i in 0..n {
            let kill_ts = base_ts + i as f64 * 60.0;
            tracker.record_respawn(
                "nginx".to_string(),
                Some("nginx.service".to_string()),
                None,
                kill_ts,
                kill_ts + delay,
                Some("pt-session-1".to_string()),
            );
        }
        let now = base_ts + n as f64 * 60.0;
        (tracker, now)
    }

    #[test]
    fn test_no_events() {
        let tracker = RespawnTracker::new();
        let config = RespawnLoopConfig::default();
        let det = tracker.detect_loop("unknown", &config, 1000.0);
        assert!(!det.is_loop);
        assert_eq!(det.loop_count, 0);
        assert_eq!(det.recommendation, RespawnRecommendation::KillOk);
        assert_eq!(det.kill_utility_multiplier, 1.0);
    }

    #[test]
    fn test_single_respawn_no_loop() {
        let (tracker, now) = make_tracker_with_respawns(1, 2.0);
        let config = RespawnLoopConfig::default();
        let det = tracker.detect_loop("nginx", &config, now);
        assert!(!det.is_loop);
        assert_eq!(det.loop_count, 1);
        assert_eq!(det.recommendation, RespawnRecommendation::KillOk);
    }

    #[test]
    fn test_detects_loop() {
        let (tracker, now) = make_tracker_with_respawns(3, 2.0);
        let config = RespawnLoopConfig::default();
        let det = tracker.detect_loop("nginx", &config, now);
        assert!(det.is_loop);
        assert_eq!(det.loop_count, 3);
        assert_eq!(det.recommendation, RespawnRecommendation::SupervisorStop);
        assert!(det.kill_utility_multiplier < 1.0);
    }

    #[test]
    fn test_supervisor_disable_at_max() {
        let (tracker, now) = make_tracker_with_respawns(5, 2.0);
        let config = RespawnLoopConfig::default();
        let det = tracker.detect_loop("nginx", &config, now);
        assert!(det.is_loop);
        assert_eq!(det.recommendation, RespawnRecommendation::SupervisorDisable);
        // At max loops, discount should be at maximum.
        let expected = 1.0 - 0.8; // kill_discount_factor
        assert!((det.kill_utility_multiplier - expected).abs() < 0.01);
    }

    #[test]
    fn test_warn_without_supervisor() {
        let mut tracker = RespawnTracker::new();
        for i in 0..3 {
            tracker.record_respawn(
                "rogue_process".to_string(),
                None, // No supervisor
                None,
                1000.0 + i as f64 * 60.0,
                1002.0 + i as f64 * 60.0,
                None,
            );
        }
        let config = RespawnLoopConfig::default();
        let det = tracker.detect_loop("rogue_process", &config, 1200.0);
        assert!(det.is_loop);
        assert_eq!(det.recommendation, RespawnRecommendation::WarnRespawn);
    }

    #[test]
    fn test_slow_respawn_ignored() {
        let (tracker, now) = make_tracker_with_respawns(3, 60.0); // 60s delay
        let config = RespawnLoopConfig {
            max_respawn_delay_secs: 30.0,
            ..Default::default()
        };
        let det = tracker.detect_loop("nginx", &config, now);
        assert!(!det.is_loop); // Delays too long
        assert_eq!(det.loop_count, 0);
    }

    #[test]
    fn test_old_events_outside_window() {
        let mut tracker = RespawnTracker::new();
        // Events from long ago.
        for i in 0..5 {
            tracker.record_respawn(
                "old_proc".to_string(),
                Some("old.service".to_string()),
                None,
                100.0 + i as f64 * 60.0,
                102.0 + i as f64 * 60.0,
                None,
            );
        }
        let config = RespawnLoopConfig {
            window_secs: 3600.0,
            ..Default::default()
        };
        let det = tracker.detect_loop("old_proc", &config, 100000.0);
        assert!(!det.is_loop); // All events outside window.
    }

    #[test]
    fn test_prune_removes_old() {
        let (mut tracker, _) = make_tracker_with_respawns(5, 2.0);
        assert_eq!(tracker.event_count(), 5);
        let config = RespawnLoopConfig {
            window_secs: 60.0,
            ..Default::default()
        };
        tracker.prune(&config, 100000.0);
        assert_eq!(tracker.event_count(), 0);
        assert_eq!(tracker.identity_count(), 0);
    }

    #[test]
    fn test_discount_kill_utility() {
        let det = RespawnLoopDetection {
            identity_key: "test".to_string(),
            loop_count: 3,
            is_loop: true,
            avg_respawn_delay_secs: 2.0,
            recommendation: RespawnRecommendation::SupervisorStop,
            kill_utility_multiplier: 0.52,
        };
        let discounted = discount_kill_utility(100.0, &det);
        assert!((discounted - 52.0).abs() < 0.1);
    }

    #[test]
    fn test_all_loops() {
        let mut tracker = RespawnTracker::new();
        // nginx loops
        for i in 0..3 {
            tracker.record_respawn(
                "nginx".to_string(),
                Some("nginx.service".to_string()),
                None,
                1000.0 + i as f64 * 60.0,
                1002.0 + i as f64 * 60.0,
                None,
            );
        }
        // single event for redis (no loop)
        tracker.record_respawn(
            "redis".to_string(),
            Some("redis.service".to_string()),
            None,
            1000.0,
            1002.0,
            None,
        );
        let config = RespawnLoopConfig::default();
        let loops = tracker.all_loops(&config, 1200.0);
        assert_eq!(loops.len(), 1);
        assert_eq!(loops[0].identity_key, "nginx");
    }

    #[test]
    fn test_avg_delay() {
        let mut tracker = RespawnTracker::new();
        tracker.record_respawn("svc".to_string(), None, None, 100.0, 102.0, None);
        tracker.record_respawn("svc".to_string(), None, None, 200.0, 206.0, None);
        let config = RespawnLoopConfig::default();
        let det = tracker.detect_loop("svc", &config, 300.0);
        assert!((det.avg_respawn_delay_secs - 4.0).abs() < 0.01); // (2+6)/2
    }
}
