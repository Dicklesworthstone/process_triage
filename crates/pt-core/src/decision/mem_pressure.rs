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
    /// Memory utilization as a fraction (0.0 to 1.0).
    pub fn utilization(&self) -> f64 {
        if self.total_bytes == 0 {
            return 0.0;
        }
        1.0 - (self.available_bytes as f64 / self.total_bytes as f64)
    }

    /// Swap utilization as a fraction.
    pub fn swap_utilization(&self) -> f64 {
        if self.swap_total_bytes == 0 {
            return 0.0;
        }
        self.swap_used_bytes as f64 / self.swap_total_bytes as f64
    }
}

/// Configuration for memory pressure response.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
            normal_interval_secs: 300.0,
            warning_interval_secs: 60.0,
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
    /// Human-readable explanation.
    pub explanation: String,
}

/// Memory pressure state machine.
#[derive(Debug, Clone)]
pub struct MemPressureMonitor {
    config: MemPressureConfig,
    current_mode: PressureMode,
    /// Consecutive signals at each level.
    warning_count: usize,
    emergency_count: usize,
    normal_count: usize,
    /// Last evaluation timestamp.
    last_eval_ts: f64,
    /// Total transitions.
    transition_count: u64,
}

impl MemPressureMonitor {
    pub fn new(config: MemPressureConfig) -> Self {
        Self {
            config,
            current_mode: PressureMode::Normal,
            warning_count: 0,
            emergency_count: 0,
            normal_count: 0,
            last_eval_ts: 0.0,
            transition_count: 0,
        }
    }

    /// Evaluate memory signals and return the pressure response.
    pub fn evaluate(&mut self, signals: &MemorySignals) -> PressureEvaluation {
        let util = signals.utilization();
        self.last_eval_ts = signals.timestamp;

        let signal_level = self.classify_signal(signals);

        // Update counters.
        match signal_level {
            PressureMode::Emergency => {
                self.emergency_count += 1;
                self.warning_count = 0;
                self.normal_count = 0;
            }
            PressureMode::Warning => {
                self.warning_count += 1;
                self.emergency_count = 0;
                self.normal_count = 0;
            }
            PressureMode::Normal => {
                self.normal_count += 1;
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
            self.transition_count += 1;
        }

        let action = match (new_mode, transitioned) {
            (PressureMode::Emergency, _) => PressureAction::UrgentPlan,
            (PressureMode::Warning, true) => PressureAction::GeneratePlan,
            (PressureMode::Warning, false) => PressureAction::IncreaseCadence,
            (PressureMode::Normal, _) => PressureAction::Continue,
        };

        let interval = match new_mode {
            PressureMode::Normal => self.config.normal_interval_secs,
            PressureMode::Warning => self.config.warning_interval_secs,
            PressureMode::Emergency => self.config.emergency_interval_secs,
        };

        let explanation = format!(
            "Memory {:.0}% → {} mode{}",
            util * 100.0,
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
        let threshold = self.config.transition_count;

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
}
