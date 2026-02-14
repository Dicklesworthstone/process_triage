//! Unified Drift Detection Membrane.
//!
//! Composes BOCPD + Wasserstein + IMM into a single `DriftMembrane` that
//! guards all decision modules. When multiple detectors agree on a regime
//! change, the membrane triggers global safe-mode. An e-process confirmation
//! step prevents false-positive safe-mode triggers.
//!
//! # Architecture
//!
//! ```text
//! observations ──▶ [BOCPD] ──▶ ┐
//!                               ├──▶ DriftMembrane ──▶ regime + safe_mode flag
//! observations ──▶ [IMM]  ──▶  ┤
//!                               │
//! distributions ─▶ [Wass] ──▶  ┘
//! ```
//!
//! # Safe-Mode Semantics
//!
//! When `is_safe_mode()` returns `true`, decision modules should:
//! - Increase kill thresholds (require higher posterior confidence)
//! - Prefer reversible actions (pause, throttle) over irreversible (kill)
//! - Emit warnings in evidence ledger
//!
//! Safe-mode is **sticky**: once triggered it remains active until an explicit
//! `reset()` call, preventing oscillation.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::bocpd::{BocpdConfig, BocpdDetector};
use super::imm::{ImmAnalyzer, ImmConfig, ImmError};
use super::wasserstein::{DriftSeverity, WassersteinConfig, WassersteinDetector};

// ── Errors ──────────────────────────────────────────────────────────────

/// Errors from drift membrane operations.
#[derive(Debug, Error)]
pub enum MembraneError {
    #[error("IMM error: {0}")]
    Imm(#[from] ImmError),

    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("membrane not initialized: call tick() at least once")]
    NotInitialized,
}

// ── Configuration ───────────────────────────────────────────────────────

/// Configuration for the composite drift membrane.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembraneConfig {
    /// Weight for BOCPD change-point signal (0.0–1.0).
    pub bocpd_weight: f64,
    /// Weight for Wasserstein drift signal (0.0–1.0).
    pub wasserstein_weight: f64,
    /// Weight for IMM regime-change signal (0.0–1.0).
    pub imm_weight: f64,

    /// Composite score threshold to trigger safe-mode (0.0–1.0).
    pub safe_mode_threshold: f64,

    /// BOCPD change-point probability above which the detector votes "drift".
    pub bocpd_change_threshold: f64,
    /// Wasserstein severity at or above which the detector votes "drift".
    pub wasserstein_severity_threshold: DriftSeverity,
    /// IMM regime-change probability shift above which the detector votes "drift".
    pub imm_shift_threshold: f64,

    /// E-process confirmation: number of consecutive ticks the composite score
    /// must remain above threshold before safe-mode triggers.
    /// This prevents transient spikes from causing unnecessary safe-mode.
    pub eprocess_confirmation_ticks: u32,

    /// Whether the membrane is enabled. If false, `is_safe_mode()` always
    /// returns false and `tick()` is a no-op.
    pub enabled: bool,
}

impl Default for MembraneConfig {
    fn default() -> Self {
        Self {
            bocpd_weight: 0.4,
            wasserstein_weight: 0.35,
            imm_weight: 0.25,
            safe_mode_threshold: 0.6,
            bocpd_change_threshold: 0.5,
            wasserstein_severity_threshold: DriftSeverity::Moderate,
            imm_shift_threshold: 0.3,
            eprocess_confirmation_ticks: 3,
            enabled: true,
        }
    }
}

impl MembraneConfig {
    /// Validate configuration parameters.
    pub fn validate(&self) -> Result<(), MembraneError> {
        let weight_sum = self.bocpd_weight + self.wasserstein_weight + self.imm_weight;
        if (weight_sum - 1.0).abs() > 0.01 {
            return Err(MembraneError::InvalidConfig(format!(
                "detector weights must sum to ~1.0, got {weight_sum:.3}"
            )));
        }
        if !(0.0..=1.0).contains(&self.safe_mode_threshold) {
            return Err(MembraneError::InvalidConfig(
                "safe_mode_threshold must be in [0, 1]".into(),
            ));
        }
        Ok(())
    }
}

// ── Regime identification ───────────────────────────────────────────────

/// Global regime as detected by the membrane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembraneRegime {
    /// Operating within expected parameters.
    Nominal,
    /// Some drift detected but below safe-mode threshold.
    Drifting,
    /// Major regime change detected — safe-mode triggered.
    RegimeChange,
}

// ── Tick output ─────────────────────────────────────────────────────────

/// Output of a single membrane tick.
#[derive(Debug, Clone, Serialize)]
pub struct MembraneTick {
    /// Current regime assessment.
    pub regime: MembraneRegime,
    /// Whether safe-mode is active.
    pub safe_mode: bool,

    /// Composite drift score (0.0 = no drift, 1.0 = maximal drift).
    pub composite_score: f64,
    /// Consecutive ticks the composite score has been above threshold.
    pub confirmation_count: u32,

    /// BOCPD detector vote (0.0 = no change, 1.0 = definite change).
    pub bocpd_signal: f64,
    /// Wasserstein detector vote (0.0 = no drift, 1.0 = severe drift).
    pub wasserstein_signal: f64,
    /// IMM detector vote (0.0 = stable regime, 1.0 = regime shift).
    pub imm_signal: f64,

    /// Total tick count since last reset.
    pub tick_count: u64,
}

/// Evidence record for the inference ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembraneEvidence {
    pub regime: MembraneRegime,
    pub safe_mode: bool,
    pub composite_score: f64,
    pub bocpd_signal: f64,
    pub wasserstein_signal: f64,
    pub imm_signal: f64,
}

impl From<&MembraneTick> for MembraneEvidence {
    fn from(tick: &MembraneTick) -> Self {
        Self {
            regime: tick.regime,
            safe_mode: tick.safe_mode,
            composite_score: tick.composite_score,
            bocpd_signal: tick.bocpd_signal,
            wasserstein_signal: tick.wasserstein_signal,
            imm_signal: tick.imm_signal,
        }
    }
}

// ── Observation input ───────────────────────────────────────────────────

/// Input for a single membrane tick. Callers provide raw observations and
/// optional distribution samples for the Wasserstein detector.
pub struct MembraneObservation {
    /// Scalar observation value for BOCPD and IMM (e.g., CPU usage, latency).
    pub value: f64,
    /// Baseline distribution samples for Wasserstein detector.
    /// If empty, Wasserstein signal defaults to 0.
    pub baseline_samples: Vec<f64>,
    /// Current distribution samples for Wasserstein detector.
    /// If empty, Wasserstein signal defaults to 0.
    pub current_samples: Vec<f64>,
}

// ── Composite membrane ─────────────────────────────────────────────────

/// Composite drift membrane combining BOCPD, Wasserstein, and IMM detectors.
///
/// The membrane maintains internal detector state and produces a unified
/// drift assessment on each `tick()`. Safe-mode is sticky once triggered.
pub struct CompositeDriftMembrane {
    config: MembraneConfig,
    bocpd: BocpdDetector,
    imm: ImmAnalyzer,
    wasserstein: WassersteinDetector,

    // State
    safe_mode: bool,
    confirmation_count: u32,
    tick_count: u64,
    last_tick: Option<MembraneTick>,
}

impl CompositeDriftMembrane {
    /// Create a new composite drift membrane with default sub-detector configs.
    pub fn new(config: MembraneConfig) -> Result<Self, MembraneError> {
        config.validate()?;
        let bocpd = BocpdDetector::default_detector();
        let imm = ImmAnalyzer::new(ImmConfig::two_regime_default())?;
        let wasserstein = WassersteinDetector::new(WassersteinConfig::for_cpu());

        Ok(Self {
            config,
            bocpd,
            imm,
            wasserstein,
            safe_mode: false,
            confirmation_count: 0,
            tick_count: 0,
            last_tick: None,
        })
    }

    /// Create with custom sub-detector configurations.
    pub fn with_detectors(
        config: MembraneConfig,
        bocpd_config: BocpdConfig,
        imm_config: ImmConfig,
        wasserstein_config: WassersteinConfig,
    ) -> Result<Self, MembraneError> {
        config.validate()?;
        let bocpd = BocpdDetector::new(bocpd_config);
        let imm = ImmAnalyzer::new(imm_config)?;
        let wasserstein = WassersteinDetector::new(wasserstein_config);

        Ok(Self {
            config,
            bocpd,
            imm,
            wasserstein,
            safe_mode: false,
            confirmation_count: 0,
            tick_count: 0,
            last_tick: None,
        })
    }

    /// Process a single observation through all detectors and update membrane state.
    pub fn tick(&mut self, obs: &MembraneObservation) -> Result<MembraneTick, MembraneError> {
        if !self.config.enabled {
            let tick = MembraneTick {
                regime: MembraneRegime::Nominal,
                safe_mode: false,
                composite_score: 0.0,
                confirmation_count: 0,
                bocpd_signal: 0.0,
                wasserstein_signal: 0.0,
                imm_signal: 0.0,
                tick_count: self.tick_count,
            };
            self.tick_count += 1;
            self.last_tick = Some(tick.clone());
            return Ok(tick);
        }

        // 1. BOCPD update
        let bocpd_result = self.bocpd.update(obs.value);
        let bocpd_signal = bocpd_result.change_point_probability;

        // 2. IMM update
        let imm_result = self.imm.update(obs.value)?;
        let imm_signal = imm_result.probability_shift;

        // 3. Wasserstein detector (only if samples provided)
        let wasserstein_signal =
            if !obs.baseline_samples.is_empty() && !obs.current_samples.is_empty() {
                let drift_result = self
                    .wasserstein
                    .detect_drift(&obs.baseline_samples, &obs.current_samples);
                severity_to_signal(&drift_result.severity)
            } else {
                0.0
            };

        // 4. Compute weighted composite score
        let composite_score = self.config.bocpd_weight * bocpd_signal.min(1.0)
            + self.config.wasserstein_weight * wasserstein_signal
            + self.config.imm_weight * imm_signal.min(1.0);
        let composite_score = composite_score.clamp(0.0, 1.0);

        // 5. E-process confirmation
        if composite_score >= self.config.safe_mode_threshold {
            self.confirmation_count += 1;
        } else {
            // Reset confirmation counter if score drops, but don't clear safe_mode
            self.confirmation_count = 0;
        }

        // 6. Safe-mode is sticky once triggered
        if !self.safe_mode && self.confirmation_count >= self.config.eprocess_confirmation_ticks {
            self.safe_mode = true;
        }

        // 7. Determine regime
        let regime = if self.safe_mode {
            MembraneRegime::RegimeChange
        } else if composite_score > self.config.safe_mode_threshold * 0.5 {
            MembraneRegime::Drifting
        } else {
            MembraneRegime::Nominal
        };

        self.tick_count += 1;

        let tick = MembraneTick {
            regime,
            safe_mode: self.safe_mode,
            composite_score,
            confirmation_count: self.confirmation_count,
            bocpd_signal: bocpd_signal.min(1.0),
            wasserstein_signal,
            imm_signal: imm_signal.min(1.0),
            tick_count: self.tick_count,
        };

        self.last_tick = Some(tick.clone());
        Ok(tick)
    }

    /// Whether the membrane is currently in safe-mode.
    pub fn is_safe_mode(&self) -> bool {
        self.safe_mode
    }

    /// Current regime assessment. Returns `Nominal` if no ticks have occurred.
    pub fn regime(&self) -> MembraneRegime {
        self.last_tick
            .as_ref()
            .map(|t| t.regime)
            .unwrap_or(MembraneRegime::Nominal)
    }

    /// Last tick result, if available.
    pub fn last_tick(&self) -> Option<&MembraneTick> {
        self.last_tick.as_ref()
    }

    /// Total number of ticks processed.
    pub fn tick_count(&self) -> u64 {
        self.tick_count
    }

    /// Configuration reference.
    pub fn config(&self) -> &MembraneConfig {
        &self.config
    }

    /// Reset membrane to initial state: clears safe-mode, all detector
    /// state, and counters. Use after confirmed recovery from a regime change.
    pub fn reset(&mut self) -> Result<(), MembraneError> {
        self.bocpd.reset();
        self.imm.reset();
        self.safe_mode = false;
        self.confirmation_count = 0;
        self.tick_count = 0;
        self.last_tick = None;
        Ok(())
    }

    /// Extract evidence for the inference ledger.
    pub fn to_evidence(&self) -> Option<MembraneEvidence> {
        self.last_tick.as_ref().map(MembraneEvidence::from)
    }
}

/// Convert drift severity to a 0–1 signal.
fn severity_to_signal(severity: &DriftSeverity) -> f64 {
    match severity {
        DriftSeverity::None => 0.0,
        DriftSeverity::Minor => 0.25,
        DriftSeverity::Moderate => 0.5,
        DriftSeverity::Significant => 0.75,
        DriftSeverity::Severe => 1.0,
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_membrane() -> CompositeDriftMembrane {
        CompositeDriftMembrane::new(MembraneConfig::default()).unwrap()
    }

    fn stable_obs() -> MembraneObservation {
        MembraneObservation {
            value: 50.0,
            baseline_samples: vec![48.0, 50.0, 52.0, 49.0, 51.0],
            current_samples: vec![49.0, 51.0, 50.0, 48.0, 52.0],
        }
    }

    fn drift_obs() -> MembraneObservation {
        MembraneObservation {
            value: 200.0,
            baseline_samples: vec![48.0, 50.0, 52.0, 49.0, 51.0],
            current_samples: vec![190.0, 200.0, 210.0, 195.0, 205.0],
        }
    }

    #[test]
    fn initial_state_is_nominal() {
        let m = make_membrane();
        assert_eq!(m.regime(), MembraneRegime::Nominal);
        assert!(!m.is_safe_mode());
        assert_eq!(m.tick_count(), 0);
    }

    #[test]
    fn stable_observations_stay_nominal() {
        let mut m = make_membrane();
        for _ in 0..20 {
            let tick = m.tick(&stable_obs()).unwrap();
            assert!(!tick.safe_mode);
        }
        assert_eq!(m.regime(), MembraneRegime::Nominal);
    }

    #[test]
    fn config_validation_rejects_bad_weights() {
        let config = MembraneConfig {
            bocpd_weight: 0.5,
            wasserstein_weight: 0.5,
            imm_weight: 0.5,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn config_validation_accepts_good_weights() {
        let config = MembraneConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn safe_mode_is_sticky() {
        let mut m = make_membrane();
        // Force safe mode by manipulating internal state
        m.safe_mode = true;
        let tick = m.tick(&stable_obs()).unwrap();
        assert!(tick.safe_mode);
        assert_eq!(tick.regime, MembraneRegime::RegimeChange);
    }

    #[test]
    fn reset_clears_safe_mode() {
        let mut m = make_membrane();
        m.safe_mode = true;
        m.reset().unwrap();
        assert!(!m.is_safe_mode());
        assert_eq!(m.tick_count(), 0);
    }

    #[test]
    fn disabled_membrane_always_nominal() {
        let config = MembraneConfig {
            enabled: false,
            ..Default::default()
        };
        let mut m = CompositeDriftMembrane::new(config).unwrap();
        for _ in 0..10 {
            let tick = m.tick(&drift_obs()).unwrap();
            assert!(!tick.safe_mode);
            assert_eq!(tick.regime, MembraneRegime::Nominal);
        }
    }

    #[test]
    fn evidence_conversion() {
        let mut m = make_membrane();
        assert!(m.to_evidence().is_none());
        m.tick(&stable_obs()).unwrap();
        let ev = m.to_evidence().unwrap();
        assert!(!ev.safe_mode);
    }

    #[test]
    fn tick_count_increments() {
        let mut m = make_membrane();
        for i in 0..5 {
            m.tick(&stable_obs()).unwrap();
            assert_eq!(m.tick_count(), i + 1);
        }
    }

    #[test]
    fn eprocess_confirmation_requires_consecutive_ticks() {
        let config = MembraneConfig {
            eprocess_confirmation_ticks: 3,
            ..Default::default()
        };
        let mut m = CompositeDriftMembrane::new(config).unwrap();
        // One drift tick alone shouldn't trigger safe mode
        m.tick(&drift_obs()).unwrap();
        assert!(!m.is_safe_mode());
    }

    #[test]
    fn empty_samples_skip_wasserstein() {
        let mut m = make_membrane();
        let obs = MembraneObservation {
            value: 50.0,
            baseline_samples: vec![],
            current_samples: vec![],
        };
        let tick = m.tick(&obs).unwrap();
        assert!((tick.wasserstein_signal - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn severity_to_signal_mapping() {
        assert!((severity_to_signal(&DriftSeverity::None) - 0.0).abs() < f64::EPSILON);
        assert!((severity_to_signal(&DriftSeverity::Minor) - 0.25).abs() < f64::EPSILON);
        assert!((severity_to_signal(&DriftSeverity::Moderate) - 0.5).abs() < f64::EPSILON);
        assert!((severity_to_signal(&DriftSeverity::Significant) - 0.75).abs() < f64::EPSILON);
        assert!((severity_to_signal(&DriftSeverity::Severe) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn composite_score_clamped() {
        let mut m = make_membrane();
        let tick = m.tick(&stable_obs()).unwrap();
        assert!(tick.composite_score >= 0.0);
        assert!(tick.composite_score <= 1.0);
    }

    #[test]
    fn default_config_values() {
        let c = MembraneConfig::default();
        assert!((c.bocpd_weight - 0.4).abs() < f64::EPSILON);
        assert!((c.wasserstein_weight - 0.35).abs() < f64::EPSILON);
        assert!((c.imm_weight - 0.25).abs() < f64::EPSILON);
        assert!(c.enabled);
    }

    #[test]
    fn membrane_serde_config() {
        let c = MembraneConfig::default();
        let json = serde_json::to_string(&c).unwrap();
        let back: MembraneConfig = serde_json::from_str(&json).unwrap();
        assert!((back.bocpd_weight - c.bocpd_weight).abs() < f64::EPSILON);
    }

    #[test]
    fn membrane_regime_serde() {
        for regime in &[
            MembraneRegime::Nominal,
            MembraneRegime::Drifting,
            MembraneRegime::RegimeChange,
        ] {
            let json = serde_json::to_string(regime).unwrap();
            let back: MembraneRegime = serde_json::from_str(&json).unwrap();
            assert_eq!(*regime, back);
        }
    }
}
