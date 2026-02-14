//! Calibration Meta-Controller.
//!
//! Continuous monitoring of decision calibration quality via ECE and Brier
//! scores over sliding windows at multiple timescales. When calibration
//! degrades past configured thresholds, the monitor signals that adaptive
//! decision modules should switch to conservative mode.
//!
//! # Multi-timescale Windows
//!
//! - **Short** (100 decisions): detects sudden miscalibration
//! - **Medium** (500 decisions): detects moderate drift
//! - **Long** (2000 decisions): detects slow calibration degradation
//!
//! The monitor triggers on the *worst* score across all timescales.

use serde::{Deserialize, Serialize};

// ── Configuration ───────────────────────────────────────────────────────

/// Configuration for the calibration monitor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationMonitorConfig {
    /// ECE threshold above which calibration is considered degraded.
    pub ece_threshold: f64,
    /// Brier score degradation fraction (relative to baseline) that triggers alarm.
    /// E.g., 0.25 means a 25% increase from baseline Brier score triggers.
    pub brier_degradation_fraction: f64,
    /// Short window size (number of recent decisions).
    pub short_window: usize,
    /// Medium window size.
    pub medium_window: usize,
    /// Long window size.
    pub long_window: usize,
    /// Whether auto-trigger of conservative mode is enabled.
    /// If false, calibration health is reported but no mode switch occurs.
    pub auto_trigger_enabled: bool,
}

impl Default for CalibrationMonitorConfig {
    fn default() -> Self {
        Self {
            ece_threshold: 0.10,
            brier_degradation_fraction: 0.25,
            short_window: 100,
            medium_window: 500,
            long_window: 2000,
            auto_trigger_enabled: true,
        }
    }
}

// ── Observation record ──────────────────────────────────────────────────

/// A single calibration observation: predicted probability paired with outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationObservation {
    /// Predicted probability of the positive class (e.g., "abandoned").
    pub predicted: f64,
    /// Whether the positive outcome actually occurred.
    pub actual: bool,
}

// ── Health output ───────────────────────────────────────────────────────

/// Calibration health assessment at a single timescale.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowHealth {
    /// Window name ("short", "medium", "long").
    pub window_name: String,
    /// Window size (configured).
    pub window_size: usize,
    /// Number of observations actually in this window.
    pub observation_count: usize,
    /// Expected Calibration Error for this window.
    pub ece: f64,
    /// Brier score for this window.
    pub brier: f64,
    /// Whether this window's metrics exceed thresholds.
    pub degraded: bool,
}

/// Overall calibration health emitted to the evidence ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationHealth {
    /// Per-window health assessments.
    pub windows: Vec<WindowHealth>,
    /// Whether any window shows degradation.
    pub calibration_degraded: bool,
    /// Whether conservative mode should be engaged.
    pub recommend_conservative: bool,
    /// Total observations recorded.
    pub total_observations: usize,
    /// Baseline Brier score (computed from first `long_window` observations).
    pub baseline_brier: Option<f64>,
}

// ── Monitor ─────────────────────────────────────────────────────────────

/// Calibration meta-controller: monitors decision calibration and signals
/// when adaptive behavior should be disabled.
pub struct CalibrationMonitor {
    config: CalibrationMonitorConfig,
    /// Circular buffer of observations (newest at end).
    observations: Vec<CalibrationObservation>,
    /// Baseline Brier score computed once we have enough long-window data.
    baseline_brier: Option<f64>,
    /// Whether conservative mode is currently triggered.
    degraded: bool,
}

impl CalibrationMonitor {
    /// Create a new calibration monitor.
    pub fn new(config: CalibrationMonitorConfig) -> Self {
        let capacity = config.long_window * 2;
        Self {
            config,
            observations: Vec::with_capacity(capacity),
            baseline_brier: None,
            degraded: false,
        }
    }

    /// Record a new calibration observation and update health state.
    pub fn record(&mut self, obs: CalibrationObservation) -> CalibrationHealth {
        self.observations.push(obs);

        // Trim to keep at most 2x long_window observations
        let max_len = self.config.long_window * 2;
        if self.observations.len() > max_len {
            let drain = self.observations.len() - max_len;
            self.observations.drain(..drain);
        }

        // Establish baseline from first full long window
        if self.baseline_brier.is_none() && self.observations.len() >= self.config.long_window {
            let long_slice = &self.observations[..self.config.long_window];
            self.baseline_brier = Some(compute_brier(long_slice));
        }

        self.assess()
    }

    /// Assess calibration health across all windows.
    fn assess(&mut self) -> CalibrationHealth {
        let windows = vec![
            self.assess_window("short", self.config.short_window),
            self.assess_window("medium", self.config.medium_window),
            self.assess_window("long", self.config.long_window),
        ];

        let any_degraded = windows.iter().any(|w| w.degraded);

        if self.config.auto_trigger_enabled {
            self.degraded = any_degraded;
        }

        CalibrationHealth {
            calibration_degraded: any_degraded,
            recommend_conservative: any_degraded && self.config.auto_trigger_enabled,
            total_observations: self.observations.len(),
            baseline_brier: self.baseline_brier,
            windows,
        }
    }

    /// Assess a single window.
    fn assess_window(&self, name: &str, window_size: usize) -> WindowHealth {
        let n = self.observations.len();
        if n == 0 {
            return WindowHealth {
                window_name: name.to_string(),
                window_size,
                observation_count: 0,
                ece: 0.0,
                brier: 0.0,
                degraded: false,
            };
        }

        let start = n.saturating_sub(window_size);
        let slice = &self.observations[start..];

        let ece = compute_ece(slice, 10);
        let brier = compute_brier(slice);

        let brier_degraded = self.baseline_brier.is_some_and(|baseline| {
            if baseline < 1e-10 {
                brier > 0.01
            } else {
                (brier - baseline) / baseline > self.config.brier_degradation_fraction
            }
        });

        let degraded = (ece > self.config.ece_threshold || brier_degraded) && slice.len() >= 10;

        WindowHealth {
            window_name: name.to_string(),
            window_size,
            observation_count: slice.len(),
            ece,
            brier,
            degraded,
        }
    }

    /// Whether conservative mode is currently triggered.
    pub fn is_degraded(&self) -> bool {
        self.degraded
    }

    /// Get the most recent health assessment.
    pub fn health(&self) -> CalibrationHealth {
        let windows = vec![
            self.assess_window("short", self.config.short_window),
            self.assess_window("medium", self.config.medium_window),
            self.assess_window("long", self.config.long_window),
        ];

        let any_degraded = windows.iter().any(|w| w.degraded);

        CalibrationHealth {
            calibration_degraded: any_degraded,
            recommend_conservative: any_degraded && self.config.auto_trigger_enabled,
            total_observations: self.observations.len(),
            baseline_brier: self.baseline_brier,
            windows,
        }
    }

    /// Total observations recorded.
    pub fn observation_count(&self) -> usize {
        self.observations.len()
    }

    /// Reset the monitor, clearing all observations and baseline.
    pub fn reset(&mut self) {
        self.observations.clear();
        self.baseline_brier = None;
        self.degraded = false;
    }

    /// Configuration reference.
    pub fn config(&self) -> &CalibrationMonitorConfig {
        &self.config
    }
}

// ── Metric computation ──────────────────────────────────────────────────

/// Compute Brier score: mean squared error of probability predictions.
fn compute_brier(observations: &[CalibrationObservation]) -> f64 {
    if observations.is_empty() {
        return 0.0;
    }
    let sum: f64 = observations
        .iter()
        .map(|o| {
            let y = if o.actual { 1.0 } else { 0.0 };
            (o.predicted - y).powi(2)
        })
        .sum();
    sum / observations.len() as f64
}

/// Compute Expected Calibration Error with `num_bins` equal-width bins.
fn compute_ece(observations: &[CalibrationObservation], num_bins: usize) -> f64 {
    if observations.is_empty() || num_bins == 0 {
        return 0.0;
    }

    let n = observations.len() as f64;
    let bin_width = 1.0 / num_bins as f64;

    let mut ece = 0.0;

    for bin_idx in 0..num_bins {
        let lo = bin_idx as f64 * bin_width;
        let hi = lo + bin_width;

        let bin_obs: Vec<&CalibrationObservation> = observations
            .iter()
            .filter(|o| {
                o.predicted >= lo
                    && (o.predicted < hi || (bin_idx == num_bins - 1 && o.predicted <= hi))
            })
            .collect();

        if bin_obs.is_empty() {
            continue;
        }

        let bin_n = bin_obs.len() as f64;
        let avg_pred: f64 = bin_obs.iter().map(|o| o.predicted).sum::<f64>() / bin_n;
        let avg_actual: f64 = bin_obs
            .iter()
            .map(|o| if o.actual { 1.0 } else { 0.0 })
            .sum::<f64>()
            / bin_n;

        ece += (bin_n / n) * (avg_pred - avg_actual).abs();
    }

    ece
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn well_calibrated_obs(n: usize) -> Vec<CalibrationObservation> {
        // Generate well-calibrated observations where predicted ≈ actual frequency
        // within each ECE bin. Use deterministic pattern: for predicted p,
        // set actual=true for the first p*group_size items in each group.
        let group_size = 10;
        (0..n)
            .map(|i| {
                let group = i / group_size;
                let within = i % group_size;
                // Predicted probability cycles through bins
                let p = ((group % 10) as f64 + 0.5) / 10.0;
                // Actual is true for the first p*group_size items
                let threshold = (p * group_size as f64).round() as usize;
                CalibrationObservation {
                    predicted: p,
                    actual: within < threshold,
                }
            })
            .collect()
    }

    fn miscalibrated_obs(n: usize) -> Vec<CalibrationObservation> {
        // Systematically miscalibrated: high predictions but low actual rate
        (0..n)
            .map(|_| CalibrationObservation {
                predicted: 0.9,
                actual: false,
            })
            .collect()
    }

    #[test]
    fn new_monitor_is_not_degraded() {
        let m = CalibrationMonitor::new(CalibrationMonitorConfig::default());
        assert!(!m.is_degraded());
        assert_eq!(m.observation_count(), 0);
    }

    #[test]
    fn brier_perfect_predictions() {
        let obs = vec![
            CalibrationObservation {
                predicted: 1.0,
                actual: true,
            },
            CalibrationObservation {
                predicted: 0.0,
                actual: false,
            },
        ];
        let brier = compute_brier(&obs);
        assert!((brier - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn brier_worst_predictions() {
        let obs = vec![
            CalibrationObservation {
                predicted: 0.0,
                actual: true,
            },
            CalibrationObservation {
                predicted: 1.0,
                actual: false,
            },
        ];
        let brier = compute_brier(&obs);
        assert!((brier - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn ece_empty_returns_zero() {
        assert!((compute_ece(&[], 10) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn well_calibrated_does_not_trigger() {
        let config = CalibrationMonitorConfig {
            short_window: 10,
            medium_window: 50,
            long_window: 100,
            ..Default::default()
        };
        let mut m = CalibrationMonitor::new(config);

        for obs in well_calibrated_obs(200) {
            m.record(obs);
        }

        // Well-calibrated data should have low ECE
        let health = m.health();
        assert!(!health.calibration_degraded);
    }

    #[test]
    fn miscalibrated_triggers_degradation() {
        let config = CalibrationMonitorConfig {
            short_window: 10,
            medium_window: 50,
            long_window: 100,
            ece_threshold: 0.10,
            auto_trigger_enabled: true,
            ..Default::default()
        };
        let mut m = CalibrationMonitor::new(config);

        // First fill baseline with reasonable data
        for obs in well_calibrated_obs(100) {
            m.record(obs);
        }

        // Then inject miscalibrated data
        for obs in miscalibrated_obs(50) {
            m.record(obs);
        }

        assert!(m.is_degraded());
    }

    #[test]
    fn auto_trigger_disabled_reports_but_doesnt_trigger() {
        let config = CalibrationMonitorConfig {
            short_window: 10,
            medium_window: 50,
            long_window: 100,
            auto_trigger_enabled: false,
            ..Default::default()
        };
        let mut m = CalibrationMonitor::new(config);

        for obs in miscalibrated_obs(200) {
            m.record(obs);
        }

        // Should report degradation but not trigger conservative mode
        let health = m.health();
        assert!(!health.recommend_conservative);
        assert!(!m.is_degraded());
    }

    #[test]
    fn reset_clears_state() {
        let config = CalibrationMonitorConfig {
            short_window: 10,
            medium_window: 50,
            long_window: 100,
            ..Default::default()
        };
        let mut m = CalibrationMonitor::new(config);

        for obs in miscalibrated_obs(200) {
            m.record(obs);
        }

        m.reset();
        assert!(!m.is_degraded());
        assert_eq!(m.observation_count(), 0);
    }

    #[test]
    fn circular_buffer_trims() {
        let config = CalibrationMonitorConfig {
            long_window: 50,
            ..Default::default()
        };
        let mut m = CalibrationMonitor::new(config);

        for obs in well_calibrated_obs(200) {
            m.record(obs);
        }

        // Should keep at most 2x long_window = 100
        assert!(m.observation_count() <= 100);
    }

    #[test]
    fn config_serde_roundtrip() {
        let c = CalibrationMonitorConfig::default();
        let json = serde_json::to_string(&c).unwrap();
        let back: CalibrationMonitorConfig = serde_json::from_str(&json).unwrap();
        assert!((back.ece_threshold - c.ece_threshold).abs() < f64::EPSILON);
        assert_eq!(back.short_window, c.short_window);
    }

    #[test]
    fn health_serde() {
        let health = CalibrationHealth {
            windows: vec![],
            calibration_degraded: false,
            recommend_conservative: false,
            total_observations: 0,
            baseline_brier: None,
        };
        let json = serde_json::to_string(&health).unwrap();
        let back: CalibrationHealth = serde_json::from_str(&json).unwrap();
        assert!(!back.calibration_degraded);
    }

    #[test]
    fn window_health_reports_observation_count() {
        let config = CalibrationMonitorConfig {
            short_window: 10,
            medium_window: 50,
            long_window: 100,
            ..Default::default()
        };
        let mut m = CalibrationMonitor::new(config);

        for obs in well_calibrated_obs(30) {
            m.record(obs);
        }

        let health = m.health();
        // Short window should have 10 obs, medium 30 (all), long 30 (all)
        assert_eq!(health.windows[0].observation_count, 10);
        assert_eq!(health.windows[1].observation_count, 30);
        assert_eq!(health.windows[2].observation_count, 30);
    }

    #[test]
    fn default_config_values() {
        let c = CalibrationMonitorConfig::default();
        assert!((c.ece_threshold - 0.10).abs() < f64::EPSILON);
        assert!((c.brier_degradation_fraction - 0.25).abs() < f64::EPSILON);
        assert_eq!(c.short_window, 100);
        assert_eq!(c.medium_window, 500);
        assert_eq!(c.long_window, 2000);
        assert!(c.auto_trigger_enabled);
    }
}
