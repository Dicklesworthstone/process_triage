//! Memory pressure response state machine for dormant daemon mode.
//!
//! Monitors memory utilization signals and transitions between Normal,
//! Warning, and Emergency modes. Generates plan proposals and notifications
//! without taking destructive action by default.

use serde::{Deserialize, Serialize};

/// Memory pressure state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PressureMode {
    /// Normal operation.
    Normal,
    /// Elevated pressure; increased scan cadence.
    Warning,
    /// Critical pressure; immediate scan and urgent notification.
    Emergency,
}

impl std::fmt::Display for PressureMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Normal => write!(f, "normal"),
            Self::Warning => write!(f, "warning"),
            Self::Emergency => write!(f, "emergency"),
        }
    }
}

/// Memory utilization signals for pressure evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemorySignals {
    /// Total system memory in bytes.
    pub total_bytes: u64,
    /// Used memory in bytes.
    pub used_bytes: u64,
    /// Available memory in bytes (may differ from total - used).
    pub available_bytes: u64,
    /// Swap used in bytes.
    pub swap_used_bytes: u64,
    /// Swap total in bytes.
    pub swap_total_bytes: u64,
    /// PSI memory pressure (some10, if available, 0-100).
    pub psi_some10: Option<f64>,
    /// Timestamp (epoch seconds).
    pub timestamp: f64,
}

impl MemorySignals {
    /// Build a reading only when memory capacity and availability were observed.
    /// Missing `/proc` evidence must not become a zero-utilization sample.
    pub fn from_pressure_snapshot(
        snapshot: &crate::collect::pressure::PressureSnapshot,
    ) -> Option<Self> {
        let memory = snapshot.meminfo?;
        let total_bytes = memory.total?;
        let available_bytes = memory.available?;
        let signals = Self {
            total_bytes,
            used_bytes: total_bytes.saturating_sub(available_bytes),
            available_bytes,
            swap_used_bytes: memory.swap_used().unwrap_or(0),
            swap_total_bytes: memory.swap_total.unwrap_or(0),
            psi_some10: snapshot
                .memory
                .and_then(|psi| psi.some)
                .map(|psi| psi.avg10),
            timestamp: snapshot.sampled_at_ms as f64 / 1000.0,
        };
        signals.is_valid().then_some(signals)
    }

    fn is_valid(&self) -> bool {
        self.total_bytes > 0
            && self.available_bytes <= self.total_bytes
            && self.timestamp.is_finite()
            && self.timestamp >= 0.0
            && self
                .psi_some10
                .is_none_or(|psi| psi.is_finite() && (0.0..=100.0).contains(&psi))
    }

    /// Memory utilization as a fraction (0.0 to 1.0).
    pub fn utilization(&self) -> f64 {
        if self.total_bytes == 0 {
            return 0.0;
        }
        (1.0 - (self.available_bytes as f64 / self.total_bytes as f64)).clamp(0.0, 1.0)
    }

    /// Swap utilization as a fraction.
    pub fn swap_utilization(&self) -> f64 {
        if self.swap_total_bytes == 0 {
            return 0.0;
        }
        (self.swap_used_bytes as f64 / self.swap_total_bytes as f64).clamp(0.0, 1.0)
    }
}

/// Configuration for memory pressure response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct MemPressureConfig {
    /// Memory utilization threshold for Warning mode (fraction).
    pub warning_threshold: f64,
    /// Memory utilization threshold for Emergency mode (fraction).
    pub emergency_threshold: f64,
    /// PSI threshold for Warning mode (percent).
    pub psi_warning_threshold: f64,
    /// PSI threshold for Emergency mode (percent).
    pub psi_emergency_threshold: f64,
    /// Scan interval in Normal mode (seconds).
    pub normal_interval_secs: f64,
    /// Scan interval in Warning mode (seconds).
    pub warning_interval_secs: f64,
    /// Scan interval in Emergency mode (seconds).
    pub emergency_interval_secs: f64,
    /// Number of consecutive signals required for transition.
    pub transition_count: usize,
    /// Whether auto-apply is enabled (default: false).
    pub auto_apply: bool,
}

impl Default for MemPressureConfig {
    fn default() -> Self {
        Self {
            warning_threshold: 0.80,
            emergency_threshold: 0.95,
            psi_warning_threshold: 20.0,
            psi_emergency_threshold: 60.0,
            normal_interval_secs: 60.0,
            warning_interval_secs: 30.0,
            emergency_interval_secs: 15.0,
            transition_count: 2,
            auto_apply: false,
        }
    }
}

/// Action proposed by the pressure response system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PressureAction {
    /// Continue normal scanning.
    Continue,
    /// Increase scan cadence.
    IncreaseCadence,
    /// Generate a mitigation plan and notify.
    GeneratePlan,
    /// Send urgent notification with immediate plan.
    UrgentPlan,
}

/// Result of a pressure evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PressureEvaluation {
    /// Current mode.
    pub mode: PressureMode,
    /// Previous mode (if changed).
    pub previous_mode: Option<PressureMode>,
    /// Whether a transition occurred.
    pub transitioned: bool,
    /// Recommended action.
    pub action: PressureAction,
    /// Recommended scan interval (seconds).
    pub scan_interval_secs: f64,
    /// Memory utilization at evaluation.
    pub utilization: f64,
    /// Observed memory PSI (some avg10), when supported by this host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub psi_some10: Option<f64>,
    /// False when utilization supports escalation but a previously observed PSI
    /// sensor is unavailable; such a reading cannot establish recovery.
    #[serde(default)]
    pub evidence_complete: bool,
    /// Human-readable explanation.
    pub explanation: String,
}

/// Memory pressure state machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemPressureMonitor {
    config: MemPressureConfig,
    current_mode: PressureMode,
    /// Consecutive signals at each level.
    warning_count: usize,
    emergency_count: usize,
    normal_count: usize,
    /// Last evaluation timestamp.
    last_eval_ts: Option<f64>,
    /// Total transitions.
    transition_count: u64,
    /// Once PSI is observable on this host, losing it cannot prove recovery.
    #[serde(default)]
    psi_observed: bool,
}

impl Default for MemPressureMonitor {
    fn default() -> Self {
        Self::new(MemPressureConfig::default())
    }
}

impl MemPressureMonitor {
    pub fn new(config: MemPressureConfig) -> Self {
        Self {
            config,
            current_mode: PressureMode::Normal,
            warning_count: 0,
            emergency_count: 0,
            normal_count: 0,
            last_eval_ts: None,
            transition_count: 0,
            psi_observed: false,
        }
    }

    /// Apply changed thresholds without forgetting an existing pressure episode.
    /// Consecutive readings under the old thresholds do not count under the new ones.
    pub fn reconfigure(&mut self, config: MemPressureConfig) {
        if self.config != config {
            self.config = config;
            self.reset_observation_counts();
        }
    }

    /// Observe an optional live reading. Unreadable or invalid evidence breaks a
    /// consecutive-sample streak, but never clears an elevated pressure mode.
    pub fn observe(&mut self, signals: Option<&MemorySignals>) -> Option<PressureEvaluation> {
        let Some(signals) = signals.filter(|signals| signals.is_valid()) else {
            self.reset_observation_counts();
            return None;
        };
        if self
            .last_eval_ts
            .is_some_and(|last| signals.timestamp <= last)
        {
            self.reset_observation_counts();
            return None;
        }
        self.last_eval_ts = Some(signals.timestamp);
        let missing_psi = self.psi_observed && signals.psi_some10.is_none();
        // A failed optional PSI read must not suppress an emergency established
        // independently by MemAvailable, but absence is never a normal PSI value.
        if missing_psi && self.classify_signal(signals) == PressureMode::Normal {
            self.reset_observation_counts();
            return None;
        }
        self.psi_observed |= signals.psi_some10.is_some();
        let mut evaluation = self.evaluate(signals);
        evaluation.evidence_complete = !missing_psi;
        if missing_psi {
            evaluation.explanation.push_str(
                "; memory PSI unavailable: utilization supports escalation, recovery requires PSI",
            );
        }
        Some(evaluation)
    }

    fn reset_observation_counts(&mut self) {
        self.warning_count = 0;
        self.emergency_count = 0;
        self.normal_count = 0;
    }

    /// Evaluate memory signals and return the pressure response.
    pub fn evaluate(&mut self, signals: &MemorySignals) -> PressureEvaluation {
        let util = signals.utilization();
        self.last_eval_ts = Some(signals.timestamp);

        let signal_level = self.classify_signal(signals);

        // Update counters.
        match signal_level {
            PressureMode::Emergency => {
                self.emergency_count = self.emergency_count.saturating_add(1);
                // Emergency readings also establish sustained warning-level
                // pressure; oscillation around the upper threshold is not normal.
                self.warning_count = self.warning_count.saturating_add(1);
                self.normal_count = 0;
            }
            PressureMode::Warning => {
                self.warning_count = self.warning_count.saturating_add(1);
                self.emergency_count = 0;
                self.normal_count = 0;
            }
            PressureMode::Normal => {
                self.normal_count = self.normal_count.saturating_add(1);
                self.warning_count = 0;
                self.emergency_count = 0;
            }
        }

        // Determine transitions.
        let previous_mode = self.current_mode;
        let new_mode = self.compute_transition();

        let transitioned = new_mode != previous_mode;
        if transitioned {
            self.current_mode = new_mode;
            self.transition_count = self.transition_count.saturating_add(1);
        }

        let action = match (new_mode, transitioned) {
            (PressureMode::Emergency, _) => PressureAction::UrgentPlan,
            (PressureMode::Warning, true) => PressureAction::GeneratePlan,
            (PressureMode::Warning, false) => PressureAction::IncreaseCadence,
            (PressureMode::Normal, _) => PressureAction::Continue,
        };

        let interval = self.scan_interval_secs();

        let explanation = format!(
            "Memory {:.0}%{} → {} mode{}",
            util * 100.0,
            signals
                .psi_some10
                .map(|psi| format!(", PSI some avg10 {psi:.1}%"))
                .unwrap_or_default(),
            new_mode,
            if transitioned {
                format!(" (was {})", previous_mode)
            } else {
                String::new()
            },
        );

        PressureEvaluation {
            mode: new_mode,
            previous_mode: if transitioned {
                Some(previous_mode)
            } else {
                None
            },
            transitioned,
            action,
            scan_interval_secs: interval,
            utilization: util,
            psi_some10: signals.psi_some10,
            evidence_complete: true,
            explanation,
        }
    }

    fn classify_signal(&self, signals: &MemorySignals) -> PressureMode {
        let util = signals.utilization();
        let psi = signals.psi_some10.unwrap_or(0.0);

        if util >= self.config.emergency_threshold || psi >= self.config.psi_emergency_threshold {
            PressureMode::Emergency
        } else if util >= self.config.warning_threshold || psi >= self.config.psi_warning_threshold
        {
            PressureMode::Warning
        } else {
            PressureMode::Normal
        }
    }

    fn compute_transition(&self) -> PressureMode {
        let threshold = self.config.transition_count.max(1);

        // Escalation requires consecutive signals.
        if self.emergency_count >= threshold {
            return PressureMode::Emergency;
        }
        if self.warning_count >= threshold && self.current_mode == PressureMode::Normal {
            return PressureMode::Warning;
        }
        // De-escalation also requires consecutive normal signals.
        if self.normal_count >= threshold && self.current_mode != PressureMode::Normal {
            return PressureMode::Normal;
        }

        self.current_mode
    }

    /// Current mode.
    pub fn mode(&self) -> PressureMode {
        self.current_mode
    }

    /// Cadence for the retained mode, including when a later reading is missing.
    pub fn scan_interval_secs(&self) -> f64 {
        match self.current_mode {
            PressureMode::Normal => self.config.normal_interval_secs,
            PressureMode::Warning => self.config.warning_interval_secs,
            PressureMode::Emergency => self.config.emergency_interval_secs,
        }
    }

    /// Consecutive readings supporting the retained mode. This can be zero while
    /// hysteresis waits for enough lower-pressure readings to establish recovery.
    pub fn sustained_samples(&self) -> usize {
        match self.current_mode {
            PressureMode::Normal => self.normal_count,
            PressureMode::Warning => self.warning_count,
            PressureMode::Emergency => self.emergency_count,
        }
    }

    /// Total transition count.
    pub fn transitions(&self) -> u64 {
        self.transition_count
    }

    /// Whether auto-apply is enabled.
    pub fn auto_apply_enabled(&self) -> bool {
        self.config.auto_apply
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_signals(util_pct: f64, ts: f64) -> MemorySignals {
        let total = 16_000_000_000u64;
        let available = ((1.0 - util_pct / 100.0) * total as f64) as u64;
        MemorySignals {
            total_bytes: total,
            used_bytes: total - available,
            available_bytes: available,
            swap_used_bytes: 0,
            swap_total_bytes: 4_000_000_000,
            psi_some10: None,
            timestamp: ts,
        }
    }

    #[test]
    fn test_starts_normal() {
        let mon = MemPressureMonitor::new(MemPressureConfig::default());
        assert_eq!(mon.mode(), PressureMode::Normal);
    }

    #[test]
    fn test_stays_normal_below_threshold() {
        let mut mon = MemPressureMonitor::new(MemPressureConfig::default());
        let eval = mon.evaluate(&make_signals(50.0, 1000.0));
        assert_eq!(eval.mode, PressureMode::Normal);
        assert!(!eval.transitioned);
        assert_eq!(eval.action, PressureAction::Continue);
    }

    #[test]
    fn test_transition_to_warning() {
        let config = MemPressureConfig {
            transition_count: 2,
            warning_threshold: 0.80,
            ..Default::default()
        };
        let mut mon = MemPressureMonitor::new(config);

        // First signal → not enough for transition.
        let eval1 = mon.evaluate(&make_signals(85.0, 1000.0));
        assert_eq!(eval1.mode, PressureMode::Normal);
        assert!(!eval1.transitioned);

        // Second consecutive signal → transition.
        let eval2 = mon.evaluate(&make_signals(85.0, 1060.0));
        assert_eq!(eval2.mode, PressureMode::Warning);
        assert!(eval2.transitioned);
        assert_eq!(eval2.action, PressureAction::GeneratePlan);
    }

    #[test]
    fn test_transition_to_emergency() {
        let config = MemPressureConfig {
            transition_count: 2,
            ..Default::default()
        };
        let mut mon = MemPressureMonitor::new(config);

        mon.evaluate(&make_signals(96.0, 1000.0));
        let eval = mon.evaluate(&make_signals(97.0, 1015.0));
        assert_eq!(eval.mode, PressureMode::Emergency);
        assert!(eval.transitioned);
        assert_eq!(eval.action, PressureAction::UrgentPlan);
    }

    #[test]
    fn test_de_escalation() {
        let config = MemPressureConfig {
            transition_count: 2,
            ..Default::default()
        };
        let mut mon = MemPressureMonitor::new(config);

        // Escalate to warning.
        mon.evaluate(&make_signals(85.0, 1000.0));
        mon.evaluate(&make_signals(85.0, 1060.0));
        assert_eq!(mon.mode(), PressureMode::Warning);

        // De-escalate to normal.
        mon.evaluate(&make_signals(50.0, 1120.0));
        let eval = mon.evaluate(&make_signals(50.0, 1180.0));
        assert_eq!(eval.mode, PressureMode::Normal);
        assert!(eval.transitioned);
    }

    #[test]
    fn test_scan_interval_by_mode() {
        let config = MemPressureConfig {
            transition_count: 1,
            normal_interval_secs: 300.0,
            warning_interval_secs: 60.0,
            emergency_interval_secs: 15.0,
            ..Default::default()
        };
        let mut mon = MemPressureMonitor::new(config);

        let normal = mon.evaluate(&make_signals(50.0, 1000.0));
        assert_eq!(normal.scan_interval_secs, 300.0);

        let warning = mon.evaluate(&make_signals(85.0, 1300.0));
        assert_eq!(warning.scan_interval_secs, 60.0);

        let emergency = mon.evaluate(&make_signals(96.0, 1360.0));
        assert_eq!(emergency.scan_interval_secs, 15.0);
    }

    #[test]
    fn test_psi_triggers_warning() {
        let config = MemPressureConfig {
            transition_count: 1,
            psi_warning_threshold: 20.0,
            ..Default::default()
        };
        let mut mon = MemPressureMonitor::new(config);

        let mut signals = make_signals(50.0, 1000.0); // Low memory util
        signals.psi_some10 = Some(25.0); // But high PSI
        let eval = mon.evaluate(&signals);
        assert_eq!(eval.mode, PressureMode::Warning);
    }

    #[test]
    fn test_auto_apply_default_off() {
        let mon = MemPressureMonitor::new(MemPressureConfig::default());
        assert!(!mon.auto_apply_enabled());
    }

    #[test]
    fn test_transition_count_tracked() {
        let config = MemPressureConfig {
            transition_count: 1,
            ..Default::default()
        };
        let mut mon = MemPressureMonitor::new(config);

        mon.evaluate(&make_signals(85.0, 1000.0)); // → Warning
        mon.evaluate(&make_signals(50.0, 1060.0)); // → Normal
        mon.evaluate(&make_signals(96.0, 1120.0)); // → Emergency
        assert_eq!(mon.transitions(), 3);
    }

    #[test]
    fn test_interrupted_escalation() {
        let config = MemPressureConfig {
            transition_count: 2,
            ..Default::default()
        };
        let mut mon = MemPressureMonitor::new(config);

        // One warning signal, then normal → counter resets.
        mon.evaluate(&make_signals(85.0, 1000.0));
        mon.evaluate(&make_signals(50.0, 1060.0));
        mon.evaluate(&make_signals(85.0, 1120.0));

        // Only 1 consecutive warning, not 2 → stays normal.
        assert_eq!(mon.mode(), PressureMode::Normal);
    }

    #[test]
    fn unavailable_readings_break_streaks_and_never_establish_recovery() {
        let mut monitor = MemPressureMonitor::default();

        monitor.observe(Some(&make_signals(97.0, 1000.0)));
        assert!(monitor.observe(None).is_none());
        monitor.observe(Some(&make_signals(97.0, 1060.0)));
        assert_eq!(monitor.mode(), PressureMode::Normal);
        monitor.observe(Some(&make_signals(97.0, 1120.0)));
        assert_eq!(monitor.mode(), PressureMode::Emergency);

        monitor.observe(Some(&make_signals(40.0, 1180.0)));
        assert!(monitor.observe(None).is_none());
        monitor.observe(Some(&make_signals(40.0, 1240.0)));
        assert_eq!(monitor.mode(), PressureMode::Emergency);
        monitor.observe(Some(&make_signals(40.0, 1300.0)));
        assert_eq!(monitor.mode(), PressureMode::Normal);
    }

    #[test]
    fn observed_psi_cannot_disappear_and_count_as_recovery() {
        let mut monitor = MemPressureMonitor::default();
        let mut signals = make_signals(40.0, 1000.0);
        signals.psi_some10 = Some(75.0);
        monitor.observe(Some(&signals));
        signals.timestamp += 60.0;
        let emergency = monitor.observe(Some(&signals)).unwrap();
        assert_eq!(emergency.mode, PressureMode::Emergency);
        assert_eq!(emergency.psi_some10, Some(75.0));

        signals.psi_some10 = None;
        for _ in 0..3 {
            signals.timestamp += 60.0;
            assert!(monitor.observe(Some(&signals)).is_none());
            assert_eq!(monitor.mode(), PressureMode::Emergency);
        }
        signals.psi_some10 = Some(1.0);
        signals.timestamp += 60.0;
        monitor.observe(Some(&signals));
        assert_eq!(monitor.mode(), PressureMode::Emergency);
        signals.timestamp += 60.0;
        monitor.observe(Some(&signals));
        assert_eq!(monitor.mode(), PressureMode::Normal);
    }

    #[test]
    fn missing_psi_cannot_suppress_an_observed_utilization_emergency() {
        let mut monitor = MemPressureMonitor::default();
        let mut normal = make_signals(40.0, 1000.0);
        normal.psi_some10 = Some(1.0);
        monitor.observe(Some(&normal));

        monitor.observe(Some(&make_signals(99.0, 1060.0)));
        let emergency = monitor.observe(Some(&make_signals(99.0, 1120.0))).unwrap();
        assert_eq!(emergency.mode, PressureMode::Emergency);
        assert!(!emergency.evidence_complete);
        assert!(emergency.explanation.contains("PSI unavailable"));

        for timestamp in [1180.0, 1240.0] {
            assert!(monitor
                .observe(Some(&make_signals(40.0, timestamp)))
                .is_none());
            assert_eq!(monitor.mode(), PressureMode::Emergency);
        }
        normal.timestamp = 1300.0;
        monitor.observe(Some(&normal));
        normal.timestamp = 1360.0;
        monitor.observe(Some(&normal));
        assert_eq!(monitor.mode(), PressureMode::Normal);
    }

    #[test]
    fn repeated_or_older_samples_cannot_satisfy_sustained_pressure() {
        let mut monitor = MemPressureMonitor::default();
        monitor.observe(Some(&make_signals(99.0, 1060.0)));
        assert!(monitor.observe(Some(&make_signals(99.0, 1060.0))).is_none());
        assert!(monitor.observe(Some(&make_signals(99.0, 1000.0))).is_none());
        monitor.observe(Some(&make_signals(99.0, 1120.0)));
        assert_eq!(monitor.mode(), PressureMode::Normal);
        monitor.observe(Some(&make_signals(99.0, 1180.0)));
        assert_eq!(monitor.mode(), PressureMode::Emergency);
    }

    #[test]
    fn oscillating_high_pressure_still_establishes_a_warning() {
        let mut monitor = MemPressureMonitor::default();
        monitor.observe(Some(&make_signals(94.0, 1000.0)));
        let warning = monitor.observe(Some(&make_signals(96.0, 1060.0))).unwrap();
        assert_eq!(warning.mode, PressureMode::Warning);
        monitor.observe(Some(&make_signals(94.0, 1120.0)));
        monitor.observe(Some(&make_signals(96.0, 1180.0)));
        assert_eq!(monitor.mode(), PressureMode::Warning);
        monitor.observe(Some(&make_signals(96.0, 1240.0)));
        assert_eq!(monitor.mode(), PressureMode::Emergency);
    }

    #[test]
    fn invalid_capacity_or_psi_cannot_clear_pressure() {
        let mut monitor = MemPressureMonitor::new(MemPressureConfig {
            transition_count: 1,
            ..Default::default()
        });
        monitor.observe(Some(&make_signals(97.0, 1000.0)));
        let normal = make_signals(40.0, 1060.0);
        let invalid = [
            MemorySignals {
                total_bytes: 0,
                ..normal.clone()
            },
            MemorySignals {
                available_bytes: normal.total_bytes + 1,
                ..normal.clone()
            },
            MemorySignals {
                psi_some10: Some(f64::NAN),
                ..normal.clone()
            },
            MemorySignals {
                psi_some10: Some(101.0),
                ..normal
            },
        ];
        for reading in invalid {
            assert!(monitor.observe(Some(&reading)).is_none());
            assert_eq!(monitor.mode(), PressureMode::Emergency);
        }
    }

    #[test]
    fn persisted_monitor_retains_pressure_and_recovery_evidence() {
        let mut monitor = MemPressureMonitor::default();
        monitor.observe(Some(&make_signals(97.0, 1000.0)));
        monitor.observe(Some(&make_signals(97.0, 1060.0)));
        let bytes = serde_json::to_vec(&monitor).unwrap();
        let mut restored: MemPressureMonitor = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(restored.mode(), PressureMode::Emergency);
        assert_eq!(restored.scan_interval_secs(), 15.0);
        restored.observe(None);
        restored.observe(Some(&make_signals(40.0, 1120.0)));
        assert_eq!(restored.mode(), PressureMode::Emergency);
        restored.observe(Some(&make_signals(40.0, 1180.0)));
        assert_eq!(restored.mode(), PressureMode::Normal);
    }

    #[test]
    fn reconfiguration_retains_mode_but_resets_old_threshold_streaks() {
        let mut monitor = MemPressureMonitor::default();
        monitor.observe(Some(&make_signals(97.0, 1000.0)));
        monitor.observe(Some(&make_signals(97.0, 1060.0)));
        monitor.observe(Some(&make_signals(40.0, 1120.0)));
        monitor.reconfigure(MemPressureConfig {
            warning_threshold: 0.75,
            ..Default::default()
        });
        monitor.observe(Some(&make_signals(40.0, 1180.0)));
        assert_eq!(monitor.mode(), PressureMode::Emergency);
        monitor.observe(Some(&make_signals(40.0, 1240.0)));
        assert_eq!(monitor.mode(), PressureMode::Normal);
    }

    #[test]
    fn zero_transition_count_still_requires_an_observed_pressure_signal() {
        let mut monitor = MemPressureMonitor::new(MemPressureConfig {
            transition_count: 0,
            ..Default::default()
        });
        let evaluation = monitor.observe(Some(&make_signals(40.0, 1000.0))).unwrap();
        assert_eq!(evaluation.mode, PressureMode::Normal);
    }

    #[test]
    fn test_utilization_clamps_when_available_exceeds_total() {
        let signals = MemorySignals {
            total_bytes: 100,
            used_bytes: 0,
            available_bytes: 150,
            swap_used_bytes: 0,
            swap_total_bytes: 100,
            psi_some10: None,
            timestamp: 0.0,
        };

        assert_eq!(signals.utilization(), 0.0);
    }

    #[test]
    fn test_swap_utilization_clamps_above_one() {
        let signals = MemorySignals {
            total_bytes: 100,
            used_bytes: 100,
            available_bytes: 0,
            swap_used_bytes: 250,
            swap_total_bytes: 100,
            psi_some10: None,
            timestamp: 0.0,
        };

        assert_eq!(signals.swap_utilization(), 1.0);
    }
}
