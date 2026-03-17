//! Mondrian Conformal Risk Control for Robot Mode.
//!
//! Wraps [`ConformalClassifier`] with a calibration store, health monitoring,
//! drift detection, and small-sample correction to provide rigorous FDR
//! control for automated robot-mode triage actions.
//!
//! # Safety Guarantee
//!
//! If the process distribution is exchangeable with the calibration set,
//! the conformal prediction set `C(x)` satisfies:
//!
//! ```text
//! P(Y ∈ C(X)) ≥ 1 - α
//! ```
//!
//! In robot mode, a kill action is **blocked** if `"useful"` is in the
//! prediction set — meaning there is insufficient evidence to rule out
//! the process being useful.
//!
//! # Calibration
//!
//! Calibration pairs `(posterior, ground_truth)` are collected from human
//! reviews.  The [`CalibrationStore`] persists these and feeds them into
//! the classifier.

use crate::inference::conformal::{ConformalClassifier, ConformalConfig};
use serde::{Deserialize, Serialize};

/// The four process classes used in triage.
pub const CLASSES: &[&str] = &["useful", "useful_bad", "abandoned", "zombie"];

// ── Calibration Store ─────────────────────────────────────────────────

/// A single calibration sample: posterior probabilities + human verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationSample {
    /// Posterior probability for each class at decision time.
    pub posteriors: ClassPosteriors,
    /// Human-assigned ground truth class.
    pub ground_truth: String,
}

/// Posterior probabilities for the four triage classes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassPosteriors {
    pub useful: f64,
    pub useful_bad: f64,
    pub abandoned: f64,
    pub zombie: f64,
}

impl ClassPosteriors {
    /// Convert to the `(class, prob)` format expected by the classifier.
    pub fn as_pairs(&self) -> Vec<(String, f64)> {
        vec![
            ("useful".to_string(), self.useful),
            ("useful_bad".to_string(), self.useful_bad),
            ("abandoned".to_string(), self.abandoned),
            ("zombie".to_string(), self.zombie),
        ]
    }
}

/// Persists calibration pairs for conformal prediction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationStore {
    samples: Vec<CalibrationSample>,
    max_samples: usize,
}

impl CalibrationStore {
    /// Create a new store with the given maximum capacity.
    pub fn new(max_samples: usize) -> Self {
        Self {
            samples: Vec::new(),
            max_samples,
        }
    }

    /// Record a human review outcome.
    pub fn record(&mut self, posteriors: ClassPosteriors, ground_truth: &str) {
        self.samples.push(CalibrationSample {
            posteriors,
            ground_truth: ground_truth.to_string(),
        });
        // Evict oldest samples beyond capacity (FIFO).
        while self.samples.len() > self.max_samples {
            self.samples.remove(0);
        }
    }

    /// Number of calibration samples.
    pub fn len(&self) -> usize {
        self.samples.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// All samples (for serialization / inspection).
    pub fn samples(&self) -> &[CalibrationSample] {
        &self.samples
    }
}

// ── Calibration Health ────────────────────────────────────────────────

/// Health status of the calibration set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationHealth {
    /// Total calibration samples.
    pub n_samples: usize,
    /// Minimum samples required for reliable prediction.
    pub min_required: usize,
    /// Whether we have enough samples.
    pub sufficient: bool,
    /// Per-class sample counts.
    pub class_counts: Vec<(String, usize)>,
    /// Minimum per-class count (Mondrian needs per-class calibration).
    pub min_class_count: usize,
    /// Overall health level.
    pub level: HealthLevel,
}

/// Calibration health level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthLevel {
    /// Insufficient data — conformal gate disabled.
    Insufficient,
    /// Marginal data — predictions are valid but wide.
    Marginal,
    /// Adequate data — reliable predictions.
    Good,
}

// ── Drift Detection ───────────────────────────────────────────────────

/// Result of checking whether the current distribution has drifted
/// from the calibration set (exchangeability check).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftCheck {
    /// Whether significant drift was detected.
    pub drift_detected: bool,
    /// Empirical error rate on the most recent window.
    pub recent_error_rate: f64,
    /// Expected error rate (alpha).
    pub expected_error_rate: f64,
    /// Ratio of recent to expected (> 2.0 is concerning).
    pub error_ratio: f64,
    /// Number of recent samples used for the check.
    pub window_size: usize,
}

// ── Robot Gate ─────────────────────────────────────────────────────────

/// Configuration for the conformal robot gate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformalRobotConfig {
    /// Miscoverage rate alpha (default 0.05 for 95% coverage).
    pub alpha: f64,
    /// Maximum calibration window size.
    pub max_calibration_samples: usize,
    /// Minimum samples before the gate is active.
    pub min_samples: usize,
    /// Use Mondrian (class-conditional) conformal prediction.
    pub mondrian: bool,
    /// Window size for recent-error drift detection.
    pub drift_window: usize,
    /// Error ratio threshold above which drift is flagged.
    pub drift_threshold: f64,
    /// Apply small-sample correction to p-values.
    pub small_sample_correction: bool,
}

impl Default for ConformalRobotConfig {
    fn default() -> Self {
        Self {
            alpha: 0.05,
            max_calibration_samples: 1000,
            min_samples: 20,
            mondrian: true,
            drift_window: 50,
            drift_threshold: 2.0,
            small_sample_correction: true,
        }
    }
}

/// Conformal robot gate: blocks automated kills when the prediction set
/// includes "useful".
pub struct ConformalRobotGate {
    config: ConformalRobotConfig,
    classifier: ConformalClassifier,
    store: CalibrationStore,
    /// Recent prediction outcomes for drift detection.
    recent_outcomes: Vec<bool>,
}

impl ConformalRobotGate {
    /// Create a new gate.
    pub fn new(config: ConformalRobotConfig) -> Self {
        let classifier_config = ConformalConfig {
            alpha: config.alpha,
            max_window_size: config.max_calibration_samples,
            min_samples: config.min_samples,
            blocked: false,
            block_size: 10,
            mondrian: config.mondrian,
        };
        let store = CalibrationStore::new(config.max_calibration_samples);
        Self {
            config,
            classifier: ConformalClassifier::new(classifier_config),
            store,
            recent_outcomes: Vec::new(),
        }
    }

    /// Record a calibration sample from a human review.
    pub fn record_review(&mut self, posteriors: ClassPosteriors, ground_truth: &str) {
        let pairs = posteriors.as_pairs();
        self.classifier.calibrate(ground_truth, &pairs);
        self.store.record(posteriors, ground_truth);
    }

    /// Check whether a robot-mode kill is allowed given the posteriors.
    ///
    /// Returns a [`RobotGateResult`] with the prediction set, confidence
    /// certificate, and whether the action is allowed.
    pub fn check_action(&self, posteriors: &ClassPosteriors) -> RobotGateResult {
        let health = self.calibration_health();

        // If insufficient calibration data, block (conservative).
        if health.level == HealthLevel::Insufficient {
            return RobotGateResult {
                allowed: false,
                prediction_set: PredictionSetSnapshot {
                    classes: CLASSES.iter().map(|s| s.to_string()).collect(),
                    p_values: Vec::new(),
                    most_likely: String::new(),
                    coverage: 1.0 - self.config.alpha,
                    n_calibration: health.n_samples,
                    valid: false,
                },
                certificate: ConfidenceCertificate {
                    alpha: self.config.alpha,
                    coverage: 1.0 - self.config.alpha,
                    n_calibration: health.n_samples,
                    health_level: health.level,
                    useful_in_set: true,
                    correction_applied: false,
                },
                reason: format!(
                    "Insufficient calibration data ({} samples, {} required)",
                    health.n_samples, health.min_required
                ),
            };
        }

        let pairs = posteriors.as_pairs();
        let raw_set = self.classifier.predict(&pairs);

        // Convert to our serializable snapshot.
        let mut pred_set = PredictionSetSnapshot {
            classes: raw_set.classes,
            p_values: raw_set.p_values,
            most_likely: raw_set.most_likely,
            coverage: raw_set.coverage,
            n_calibration: raw_set.n_calibration,
            valid: raw_set.valid,
        };

        // Apply small-sample correction: widen prediction sets when
        // calibration data is scarce (< 100 samples).
        if self.config.small_sample_correction && health.n_samples < 100 {
            apply_small_sample_correction(&mut pred_set, health.n_samples, &self.config);
        }

        let useful_in_set = pred_set.classes.contains(&"useful".to_string());

        let certificate = ConfidenceCertificate {
            alpha: self.config.alpha,
            coverage: 1.0 - self.config.alpha,
            n_calibration: health.n_samples,
            health_level: health.level,
            useful_in_set,
            correction_applied: self.config.small_sample_correction && health.n_samples < 100,
        };

        let allowed = !useful_in_set;
        let reason = if useful_in_set {
            format!(
                "Conformal prediction set includes 'useful' at alpha={:.3} \
                 with {} calibration samples — cannot rule out useful process",
                self.config.alpha, health.n_samples
            )
        } else {
            format!(
                "Process excluded from 'useful' prediction set at alpha={:.3} \
                 ({} calibration samples) — safe for automated action",
                self.config.alpha, health.n_samples
            )
        };

        RobotGateResult {
            allowed,
            prediction_set: pred_set,
            certificate,
            reason,
        }
    }

    /// Record whether a recent prediction was correct (for drift detection).
    pub fn record_outcome(&mut self, correct: bool) {
        self.recent_outcomes.push(correct);
        let max = self.config.drift_window * 2;
        while self.recent_outcomes.len() > max {
            self.recent_outcomes.remove(0);
        }
    }

    /// Check calibration health.
    pub fn calibration_health(&self) -> CalibrationHealth {
        let n = self.store.len();
        let min_required = self.config.min_samples;

        let mut class_counts: Vec<(String, usize)> = CLASSES
            .iter()
            .map(|c| {
                let count = self
                    .store
                    .samples()
                    .iter()
                    .filter(|s| s.ground_truth == *c)
                    .count();
                (c.to_string(), count)
            })
            .collect();
        class_counts.sort_by(|a, b| a.0.cmp(&b.0));

        let min_class_count = class_counts.iter().map(|(_, c)| *c).min().unwrap_or(0);

        let level = if n < min_required {
            HealthLevel::Insufficient
        } else if self.config.mondrian && min_class_count < 5 {
            // Mondrian needs per-class samples; very few = marginal.
            HealthLevel::Marginal
        } else if n < 100 {
            HealthLevel::Marginal
        } else {
            HealthLevel::Good
        };

        CalibrationHealth {
            n_samples: n,
            min_required,
            sufficient: n >= min_required,
            class_counts,
            min_class_count,
            level,
        }
    }

    /// Check for calibration drift (exchangeability violation).
    pub fn check_drift(&self) -> DriftCheck {
        let window = self.config.drift_window.min(self.recent_outcomes.len());
        if window == 0 {
            return DriftCheck {
                drift_detected: false,
                recent_error_rate: 0.0,
                expected_error_rate: self.config.alpha,
                error_ratio: 0.0,
                window_size: 0,
            };
        }

        let recent = &self.recent_outcomes[self.recent_outcomes.len() - window..];
        let errors = recent.iter().filter(|&&c| !c).count();
        let recent_error_rate = errors as f64 / window as f64;
        let expected = self.config.alpha;
        let error_ratio = if expected > 0.0 {
            recent_error_rate / expected
        } else {
            0.0
        };

        DriftCheck {
            drift_detected: error_ratio > self.config.drift_threshold,
            recent_error_rate,
            expected_error_rate: expected,
            error_ratio,
            window_size: window,
        }
    }

    /// Number of calibration samples.
    pub fn n_calibration_samples(&self) -> usize {
        self.store.len()
    }
}

/// Serializable snapshot of a conformal prediction set for audit/logging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PredictionSetSnapshot {
    /// Classes in the prediction set.
    pub classes: Vec<String>,
    /// p-values for each class.
    pub p_values: Vec<(String, f64)>,
    /// Most likely class.
    pub most_likely: String,
    /// Nominal coverage (1 - alpha).
    pub coverage: f64,
    /// Number of calibration samples.
    pub n_calibration: usize,
    /// Whether the prediction set is valid.
    pub valid: bool,
}

/// Result of a robot gate check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RobotGateResult {
    /// Whether the automated action is allowed.
    pub allowed: bool,
    /// The conformal prediction set.
    pub prediction_set: PredictionSetSnapshot,
    /// Confidence certificate for audit.
    pub certificate: ConfidenceCertificate,
    /// Human-readable reason.
    pub reason: String,
}

/// Confidence certificate attached to every robot action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceCertificate {
    /// Miscoverage rate.
    pub alpha: f64,
    /// Nominal coverage (1 - alpha).
    pub coverage: f64,
    /// Number of calibration samples used.
    pub n_calibration: usize,
    /// Calibration health at decision time.
    pub health_level: HealthLevel,
    /// Whether "useful" was in the prediction set.
    pub useful_in_set: bool,
    /// Whether small-sample correction was applied.
    pub correction_applied: bool,
}

/// Apply small-sample correction to p-values.
///
/// With few calibration samples, the discrete p-value formula
/// `(1 + count) / (n + 1)` can be over-confident. We apply a
/// continuity correction that effectively widens the prediction set
/// for very small n.
///
/// Correction: add all classes whose p-value exceeds `alpha * (1 - 1/sqrt(n))`
/// instead of `alpha`. This shrinks the effective alpha, widening the set.
fn apply_small_sample_correction(
    pred_set: &mut PredictionSetSnapshot,
    n_samples: usize,
    config: &ConformalRobotConfig,
) {
    if n_samples == 0 {
        return;
    }
    let correction_factor = 1.0 - 1.0 / (n_samples as f64).sqrt();
    let effective_alpha = config.alpha * correction_factor;

    // Re-check which classes should be in the set with the corrected alpha.
    pred_set.classes = pred_set
        .p_values
        .iter()
        .filter(|(_, p)| *p > effective_alpha)
        .map(|(c, _)| c.clone())
        .collect();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_posteriors(
        useful: f64,
        useful_bad: f64,
        abandoned: f64,
        zombie: f64,
    ) -> ClassPosteriors {
        ClassPosteriors {
            useful,
            useful_bad,
            abandoned,
            zombie,
        }
    }

    fn build_calibrated_gate(n: usize) -> ConformalRobotGate {
        let config = ConformalRobotConfig {
            min_samples: 10,
            mondrian: false,
            small_sample_correction: false,
            ..Default::default()
        };
        let mut gate = ConformalRobotGate::new(config);

        // Generate calibration data: mostly abandoned processes with
        // clear posteriors so the classifier learns the pattern.
        for i in 0..n {
            let (posteriors, truth) = if i % 5 == 0 {
                // 20% are useful
                (sample_posteriors(0.8, 0.05, 0.1, 0.05), "useful")
            } else if i % 5 == 1 {
                // 20% are useful_bad
                (sample_posteriors(0.1, 0.7, 0.15, 0.05), "useful_bad")
            } else {
                // 60% are abandoned
                (sample_posteriors(0.05, 0.05, 0.85, 0.05), "abandoned")
            };
            gate.record_review(posteriors, truth);
        }
        gate
    }

    // ── CalibrationStore ──────────────────────────────────────────────

    #[test]
    fn store_records_samples() {
        let mut store = CalibrationStore::new(100);
        store.record(sample_posteriors(0.5, 0.2, 0.2, 0.1), "useful");
        assert_eq!(store.len(), 1);
        assert!(!store.is_empty());
    }

    #[test]
    fn store_evicts_oldest_at_capacity() {
        let mut store = CalibrationStore::new(3);
        store.record(sample_posteriors(0.5, 0.2, 0.2, 0.1), "useful");
        store.record(sample_posteriors(0.1, 0.1, 0.7, 0.1), "abandoned");
        store.record(sample_posteriors(0.1, 0.1, 0.1, 0.7), "zombie");
        store.record(sample_posteriors(0.1, 0.7, 0.1, 0.1), "useful_bad");
        assert_eq!(store.len(), 3);
        // First sample (useful) should have been evicted.
        assert_eq!(store.samples()[0].ground_truth, "abandoned");
    }

    // ── CalibrationHealth ─────────────────────────────────────────────

    #[test]
    fn health_insufficient_when_empty() {
        let gate = ConformalRobotGate::new(ConformalRobotConfig::default());
        let health = gate.calibration_health();
        assert_eq!(health.level, HealthLevel::Insufficient);
        assert!(!health.sufficient);
    }

    #[test]
    fn health_good_with_enough_samples() {
        let gate = build_calibrated_gate(200);
        let health = gate.calibration_health();
        assert_eq!(health.level, HealthLevel::Good);
        assert!(health.sufficient);
        assert_eq!(health.n_samples, 200);
    }

    #[test]
    fn health_marginal_with_few_samples() {
        let config = ConformalRobotConfig {
            min_samples: 10,
            mondrian: false,
            ..Default::default()
        };
        let mut gate = ConformalRobotGate::new(config);
        for _ in 0..30 {
            gate.record_review(sample_posteriors(0.1, 0.1, 0.7, 0.1), "abandoned");
        }
        let health = gate.calibration_health();
        assert_eq!(health.level, HealthLevel::Marginal);
    }

    // ── Robot Gate ────────────────────────────────────────────────────

    #[test]
    fn blocks_action_with_insufficient_calibration() {
        let gate = ConformalRobotGate::new(ConformalRobotConfig::default());
        let result = gate.check_action(&sample_posteriors(0.05, 0.05, 0.85, 0.05));
        assert!(!result.allowed);
        assert!(result.reason.contains("Insufficient"));
    }

    #[test]
    fn allows_action_for_clearly_abandoned_process() {
        let gate = build_calibrated_gate(200);
        // Process with very high abandoned posterior.
        let result = gate.check_action(&sample_posteriors(0.01, 0.02, 0.95, 0.02));
        assert!(
            result.allowed,
            "expected allowed for abandoned process, got: {}",
            result.reason
        );
        assert!(!result.certificate.useful_in_set);
    }

    #[test]
    fn blocks_action_for_likely_useful_process() {
        let gate = build_calibrated_gate(200);
        // Process with high useful posterior.
        let result = gate.check_action(&sample_posteriors(0.85, 0.05, 0.05, 0.05));
        assert!(
            !result.allowed,
            "expected blocked for useful process, got: {}",
            result.reason
        );
        assert!(result.certificate.useful_in_set);
    }

    #[test]
    fn certificate_includes_calibration_info() {
        let gate = build_calibrated_gate(50);
        let result = gate.check_action(&sample_posteriors(0.01, 0.01, 0.95, 0.03));
        assert_eq!(result.certificate.n_calibration, 50);
        assert!((result.certificate.alpha - 0.05).abs() < f64::EPSILON);
        assert!((result.certificate.coverage - 0.95).abs() < f64::EPSILON);
    }

    // ── Small-Sample Correction ───────────────────────────────────────

    #[test]
    fn small_sample_correction_widens_prediction_set() {
        let config_no_correction = ConformalRobotConfig {
            min_samples: 10,
            mondrian: false,
            small_sample_correction: false,
            ..Default::default()
        };
        let config_with_correction = ConformalRobotConfig {
            min_samples: 10,
            mondrian: false,
            small_sample_correction: true,
            ..Default::default()
        };

        let mut gate_no = ConformalRobotGate::new(config_no_correction);
        let mut gate_yes = ConformalRobotGate::new(config_with_correction);

        // Same calibration data for both.
        for _ in 0..30 {
            let p = sample_posteriors(0.1, 0.1, 0.7, 0.1);
            gate_no.record_review(p.clone(), "abandoned");
            gate_yes.record_review(p, "abandoned");
        }

        let posteriors = sample_posteriors(0.15, 0.1, 0.65, 0.1);
        let r_no = gate_no.check_action(&posteriors);
        let r_yes = gate_yes.check_action(&posteriors);

        // With correction, the prediction set should be at least as large.
        assert!(
            r_yes.prediction_set.classes.len() >= r_no.prediction_set.classes.len(),
            "correction should widen set: no={}, yes={}",
            r_no.prediction_set.classes.len(),
            r_yes.prediction_set.classes.len()
        );
    }

    // ── Drift Detection ───────────────────────────────────────────────

    #[test]
    fn no_drift_when_no_outcomes() {
        let gate = ConformalRobotGate::new(ConformalRobotConfig::default());
        let drift = gate.check_drift();
        assert!(!drift.drift_detected);
        assert_eq!(drift.window_size, 0);
    }

    #[test]
    fn no_drift_when_errors_match_alpha() {
        let mut gate = ConformalRobotGate::new(ConformalRobotConfig {
            alpha: 0.10,
            drift_window: 100,
            drift_threshold: 2.0,
            ..Default::default()
        });
        // 10% error rate matches alpha=0.10.
        for i in 0..100 {
            gate.record_outcome(i % 10 != 0);
        }
        let drift = gate.check_drift();
        assert!(!drift.drift_detected);
        assert!((drift.error_ratio - 1.0).abs() < 0.2);
    }

    #[test]
    fn drift_detected_when_errors_exceed_threshold() {
        let mut gate = ConformalRobotGate::new(ConformalRobotConfig {
            alpha: 0.05,
            drift_window: 50,
            drift_threshold: 2.0,
            ..Default::default()
        });
        // 30% error rate >> alpha=0.05 (ratio = 6.0).
        for i in 0..50 {
            gate.record_outcome(i % 3 != 0); // ~33% errors
        }
        let drift = gate.check_drift();
        assert!(drift.drift_detected);
        assert!(drift.error_ratio > 2.0);
    }

    // ── ClassPosteriors ───────────────────────────────────────────────

    #[test]
    fn posteriors_as_pairs_has_four_classes() {
        let p = sample_posteriors(0.4, 0.3, 0.2, 0.1);
        let pairs = p.as_pairs();
        assert_eq!(pairs.len(), 4);
        assert_eq!(pairs[0].0, "useful");
        assert!((pairs[0].1 - 0.4).abs() < f64::EPSILON);
    }
}
