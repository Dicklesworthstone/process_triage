//! Model validation framework for shadow mode.
//!
//! Tracks predictions against explicit human verdicts to evaluate model accuracy.
//! Process exit causes are retained for diagnosis, but do not by themselves
//! establish whether a process was abandoned or useful.
//!
//! # Ground Truth Sources
//!
//! - **Human verdict**: Explicit kill or spare judgment, independent of the model
//! - **Unlabeled outcome**: Normal exit, crash, external/OOM kill, shutdown,
//!   disappearance, or expiration without a human verdict
//!
//! # Feedback Loop
//!
//! Validation results feed into:
//! - Calibration metrics (Brier, ECE, AUC-ROC)
//! - Bias detection by process category
//! - Prior adjustment recommendations
//! - Signature review flagging

use chrono::{DateTime, Utc};
use pt_telemetry::shadow::{EventType, Observation, ProcessEvent};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::{HashMap, HashSet};

use super::{
    bias::{analyze_bias, BiasAnalysis},
    metrics::{compute_metrics, CalibrationMetrics},
    report::CalibrationReport,
    CalibrationData, CalibrationError, CalibrationQuality,
};

/// Labels of each class (confirmed abandoned / confirmed not) needed before a report
/// computes calibration metrics.
pub const MIN_LABELS_PER_CLASS: usize = 5;

/// An explicit human verdict or an observed process outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GroundTruth {
    /// Explicit human kill verdict, not inferred from a successful action.
    UserKilled,
    /// Explicit human spare verdict, not inferred from continued execution.
    UserSpared,
    /// Process exited normally (exit code 0).
    NormalExit,
    /// Process crashed (non-zero exit, signal).
    Crash,
    /// Process was killed by another tool or OOM killer.
    ExternalKill,
    /// System shutdown terminated the process.
    SystemShutdown,
    /// Process is still running (no resolution yet).
    StillRunning,
    /// Tracking window expired without resolution.
    Expired,
    /// The process disappeared between observations and how it ended was not seen:
    /// it may have finished its work, been killed by its user, or crashed. Says
    /// nothing about abandonment, so it never counts as a label.
    Vanished,
}

impl GroundTruth {
    /// A supported abandonment label, when independent evidence supplies one.
    ///
    /// An external kill (including OOM), crash or shutdown can end either useful
    /// or abandoned work. Even exit code zero says only how the process ended.
    /// Keep those outcomes unknown instead of turning them into training labels.
    pub fn abandonment_label(&self) -> Option<bool> {
        match self {
            Self::UserKilled => Some(true),
            Self::UserSpared => Some(false),
            Self::NormalExit
            | Self::Crash
            | Self::ExternalKill
            | Self::SystemShutdown
            | Self::StillRunning
            | Self::Expired
            | Self::Vanished => None,
        }
    }

    /// Whether an explicit verdict supports abandonment. False also includes
    /// unknown outcomes; use `abandonment_label` when a negative label is needed.
    pub fn is_abandoned(&self) -> bool {
        self.abandonment_label() == Some(true)
    }

    /// Whether the abandonment judgment is resolved, not merely the process exit.
    pub fn is_resolved(&self) -> bool {
        self.abandonment_label().is_some()
    }
}

/// A tracked prediction paired with its eventual outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationRecord {
    /// Unique identity hash for the process (from shadow recorder).
    pub identity_hash: String,
    /// PID at the time of prediction.
    pub pid: u32,
    /// Predicted probability of abandonment (0.0 to 1.0).
    pub predicted_abandoned: f64,
    /// Recommended action from the model.
    pub recommended_action: String,
    /// Process category (e.g., "test_runner", "dev_server").
    #[serde(default)]
    pub proc_type: Option<String>,
    /// Command basename.
    pub comm: String,
    /// Timestamp of the prediction.
    pub predicted_at: DateTime<Utc>,
    /// Recorded verdict or process outcome (None if not yet observed).
    #[serde(default)]
    pub ground_truth: Option<GroundTruth>,
    /// Time the outcome was recorded, including outcomes without a label.
    #[serde(default)]
    pub resolved_at: Option<DateTime<Utc>>,
    /// Process exit code if available.
    #[serde(default)]
    pub exit_code: Option<i32>,
    /// Signal that terminated the process, if any.
    #[serde(default)]
    pub exit_signal: Option<i32>,
    /// Source of the outcome (e.g., "user", "shadow:missing").
    #[serde(default)]
    pub outcome_source: Option<String>,
    /// Host ID for multi-host analysis.
    #[serde(default)]
    pub host_id: Option<String>,
}

impl ValidationRecord {
    /// Convert only supported labels to calibration data. An observed exit cause
    /// without a verdict remains available in this record, but is not training data.
    pub fn to_calibration_data(&self) -> Option<CalibrationData> {
        let actual = self.ground_truth?.abandonment_label()?;
        Some(CalibrationData {
            predicted: self.predicted_abandoned,
            actual,
            proc_type: self.proc_type.clone(),
            score: Some(self.predicted_abandoned * 100.0),
            timestamp: Some(self.predicted_at.timestamp()),
            host_id: self.host_id.clone(),
        })
    }
}

/// Per-category validation summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryValidation {
    /// Category name (e.g., "test_runner").
    pub category: String,
    /// Total predictions in this category.
    pub total: usize,
    /// Predictions with supported labels.
    pub resolved: usize,
    /// True positives (predicted abandoned, actually abandoned).
    pub true_positives: usize,
    /// False positives (predicted abandoned, actually useful).
    pub false_positives: usize,
    /// True negatives (predicted useful, actually useful).
    pub true_negatives: usize,
    /// False negatives (predicted useful, actually abandoned).
    pub false_negatives: usize,
    /// Accuracy rate.
    pub accuracy: f64,
    /// Precision for kill recommendations.
    pub precision: f64,
    /// Recall for kill recommendations.
    pub recall: f64,
}

/// Aggregated validation report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationReport {
    /// Time range of analyzed data.
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
    /// Total predictions tracked.
    pub total_predictions: usize,
    /// Predictions with supported abandonment labels.
    pub resolved_predictions: usize,
    /// Predictions still pending.
    pub pending_predictions: usize,
    /// Resolved outcomes that confirm abandonment / that refute it.
    #[serde(default)]
    pub positive_labels: usize,
    #[serde(default)]
    pub negative_labels: usize,
    /// Recorded outcomes without a supported abandonment label, including
    /// known exit causes and processes that vanished between shadow samples.
    #[serde(default)]
    pub unlabeled_outcomes: usize,
    /// Overall calibration metrics (from supported labels). `None` until both classes
    /// have at least `MIN_LABELS_PER_CLASS` labels: with one class only, calibration
    /// figures are meaningless.
    pub metrics: Option<CalibrationMetrics>,
    /// Overall calibration quality.
    pub quality: Option<CalibrationQuality>,
    /// Per-category breakdowns.
    pub by_category: Vec<CategoryValidation>,
    /// Bias analysis.
    pub bias: Option<BiasAnalysis>,
    /// Most common false positives (predicted kill, actually useful).
    pub top_false_positives: Vec<FalseOutcome>,
    /// Most common false negatives (predicted useful, actually abandoned).
    pub top_false_negatives: Vec<FalseOutcome>,
    /// Prior adjustment recommendations.
    pub recommendations: Vec<PriorAdjustment>,
}

/// A false prediction for reporting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FalseOutcome {
    /// Process command pattern.
    pub pattern: String,
    /// Number of times this pattern was misclassified.
    pub count: usize,
    /// Mean predicted probability.
    pub mean_predicted: f64,
    /// Category.
    pub category: Option<String>,
}

/// A recommended prior adjustment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriorAdjustment {
    /// What to adjust (e.g., category prior, evidence weight).
    pub target: String,
    /// Current value.
    pub current: f64,
    /// Suggested value.
    pub suggested: f64,
    /// Rationale.
    pub reason: String,
    /// Confidence in the recommendation (based on sample size).
    pub confidence: f64,
}

/// The validation engine that tracks predictions and computes reports.
#[derive(Debug)]
pub struct ValidationEngine {
    records: Vec<ValidationRecord>,
    /// Classification threshold for kill recommendations.
    threshold: f64,
}

impl ValidationEngine {
    /// Create a new validation engine with the given threshold.
    pub fn new(threshold: f64) -> Self {
        Self {
            records: Vec::new(),
            threshold,
        }
    }

    /// Create from existing records (e.g., loaded from storage).
    pub fn from_records(records: Vec<ValidationRecord>, threshold: f64) -> Self {
        Self { records, threshold }
    }

    /// Record a new prediction for tracking.
    #[allow(clippy::too_many_arguments)]
    pub fn track_prediction(
        &mut self,
        identity_hash: String,
        pid: u32,
        predicted_abandoned: f64,
        recommended_action: String,
        proc_type: Option<String>,
        comm: String,
        host_id: Option<String>,
    ) {
        self.records.push(ValidationRecord {
            identity_hash,
            pid,
            predicted_abandoned,
            recommended_action,
            proc_type,
            comm,
            predicted_at: Utc::now(),
            ground_truth: None,
            resolved_at: None,
            exit_code: None,
            exit_signal: None,
            outcome_source: None,
            host_id,
        });
    }

    /// Record a ground truth outcome for a previously tracked prediction.
    ///
    /// Matches by identity_hash. If multiple predictions exist for the same
    /// identity, resolves the most recent unresolved one.
    pub fn record_outcome(
        &mut self,
        identity_hash: &str,
        ground_truth: GroundTruth,
        exit_code: Option<i32>,
        exit_signal: Option<i32>,
    ) -> bool {
        self.record_outcome_with_source(identity_hash, ground_truth, exit_code, exit_signal, None)
    }

    /// Record a ground truth outcome with an optional source label.
    pub fn record_outcome_with_source(
        &mut self,
        identity_hash: &str,
        ground_truth: GroundTruth,
        exit_code: Option<i32>,
        exit_signal: Option<i32>,
        outcome_source: Option<String>,
    ) -> bool {
        // Find the most recent unresolved prediction for this identity.
        let found = self
            .records
            .iter_mut()
            .rev()
            .find(|r| r.identity_hash == identity_hash && r.ground_truth.is_none());

        if let Some(record) = found {
            record.ground_truth = Some(ground_truth);
            record.resolved_at = Some(Utc::now());
            record.exit_code = exit_code;
            record.exit_signal = exit_signal;
            if outcome_source.is_some() {
                record.outcome_source = outcome_source;
            }
            true
        } else {
            false
        }
    }

    /// Record outcome by PID (less reliable due to PID reuse, but useful as fallback).
    pub fn record_outcome_by_pid(
        &mut self,
        pid: u32,
        ground_truth: GroundTruth,
        exit_code: Option<i32>,
        exit_signal: Option<i32>,
    ) -> bool {
        self.record_outcome_by_pid_with_source(pid, ground_truth, exit_code, exit_signal, None)
    }

    /// Record outcome by PID with an optional source label.
    pub fn record_outcome_by_pid_with_source(
        &mut self,
        pid: u32,
        ground_truth: GroundTruth,
        exit_code: Option<i32>,
        exit_signal: Option<i32>,
        outcome_source: Option<String>,
    ) -> bool {
        let found = self
            .records
            .iter_mut()
            .rev()
            .find(|r| r.pid == pid && r.ground_truth.is_none());

        if let Some(record) = found {
            record.ground_truth = Some(ground_truth);
            record.resolved_at = Some(Utc::now());
            record.exit_code = exit_code;
            record.exit_signal = exit_signal;
            if outcome_source.is_some() {
                record.outcome_source = outcome_source;
            }
            true
        } else {
            false
        }
    }

    /// Get all records.
    pub fn records(&self) -> &[ValidationRecord] {
        &self.records
    }

    /// Get records with supported abandonment labels only.
    pub fn resolved_records(&self) -> Vec<&ValidationRecord> {
        self.records
            .iter()
            .filter(|r| r.ground_truth.is_some_and(|gt| gt.is_resolved()))
            .collect()
    }

    /// Get pending (unresolved) records.
    pub fn pending_records(&self) -> Vec<&ValidationRecord> {
        self.records
            .iter()
            .filter(|r| r.ground_truth.is_none())
            .collect()
    }

    /// Build a validation engine from shadow-mode observations.
    ///
    /// The prediction calibrated is P(abandoned or zombie), the quantity pt displays
    /// as its score and gates robot kills on (not P(abandoned) alone).
    /// Only the first valid human verdict for a process incarnation may supply a
    /// label. Later predictions may already incorporate that verdict in their
    /// learned prior, even when no prediction existed before the first verdict.
    /// Legacy explicit verdicts carried by exit-event hints follow the same rule.
    pub fn from_shadow_observations(observations: &[Observation], threshold: f64) -> Self {
        let predicted = |obs: &Observation| {
            f64::from(obs.belief.p_abandoned + obs.belief.p_zombie).clamp(0.0, 1.0)
        };
        let mut engine = ValidationEngine::new(threshold);
        let mut ordered = Vec::new();
        for obs in observations {
            if obs
                .events
                .iter()
                .any(|event| event.event_type == EventType::HumanVerdict)
            {
                // Verdict observations have no prediction. Even an invalid verdict
                // must not turn their default belief into a calibration sample.
                for event in &obs.events {
                    if event.event_type == EventType::HumanVerdict
                        && event.timestamp <= obs.timestamp
                    {
                        ordered.push((event.timestamp, 0, obs, Some(event)));
                    }
                }
            } else {
                let exit_event = obs
                    .events
                    .iter()
                    .find(|event| event.event_type == EventType::ProcessExit);
                let at = exit_event.map_or(obs.timestamp, |event| event.timestamp);
                if at <= obs.timestamp {
                    let order = if exit_event.is_some_and(is_explicit_shadow_verdict) {
                        0
                    } else {
                        1
                    };
                    ordered.push((at, order, obs, exit_event));
                }
            }
        }
        // Replay by event time even when a verdict was flushed after a newer
        // prediction. Verdicts precede equal-time predictions: a label must be
        // strictly later than the prediction it evaluates.
        ordered.sort_by_key(|(at, order, _, _)| (*at, *order));
        let mut latest_predictions = HashMap::new();
        let mut verdict_identities = HashSet::new();

        for (_, _, obs, event) in ordered {
            let key = (obs.identity_hash.clone(), obs.pid);
            if let Some((event, (ground_truth, exit_code, exit_signal, outcome_source))) =
                event.and_then(|event| map_explicit_verdict(event).map(|outcome| (event, outcome)))
            {
                if obs.identity_hash.is_empty() || !verdict_identities.insert(key.clone()) {
                    continue;
                }
                // Reserve the incarnation before looking for a prior prediction.
                // A repeated label must never evaluate an in-sample prediction
                // that learned from the first label.
                let Some(&index) = latest_predictions.get(&key) else {
                    continue;
                };
                let record: &mut ValidationRecord = &mut engine.records[index];
                if record.predicted_at >= event.timestamp
                    || record.predicted_at >= obs.timestamp
                    || record.ground_truth.is_some_and(|truth| truth.is_resolved())
                {
                    continue;
                }
                record.ground_truth = Some(ground_truth);
                record.resolved_at = Some(event.timestamp);
                record.exit_code = exit_code.or(record.exit_code);
                record.exit_signal = exit_signal.or(record.exit_signal);
                record.outcome_source = outcome_source;
                continue;
            }
            if event.is_some_and(|event| event.event_type == EventType::HumanVerdict) {
                // Malformed/unsupported verdicts are neither labels nor predictions.
                continue;
            }

            if let Some(exit_event) = event {
                if !engine.has_unresolved_identity(&obs.identity_hash, obs.pid) {
                    let comm = extract_comm_from_events(&obs.events)
                        .unwrap_or_else(|| "unknown".to_string());
                    engine.upsert_prediction(
                        obs.identity_hash.clone(),
                        obs.pid,
                        predicted(obs),
                        obs.belief.recommendation.clone(),
                        None,
                        comm,
                        None,
                        obs.timestamp,
                    );
                }

                let (ground_truth, exit_code, exit_signal, outcome_source) =
                    map_exit_event(exit_event);
                if let Some(record) = engine.records.iter_mut().rev().find(|record| {
                    record.identity_hash == obs.identity_hash
                        && record.pid == obs.pid
                        && record.ground_truth.is_none()
                }) {
                    record.ground_truth = Some(ground_truth);
                    record.resolved_at = Some(exit_event.timestamp);
                    record.exit_code = exit_code;
                    record.exit_signal = exit_signal;
                    record.outcome_source = outcome_source;
                }
                continue;
            }

            let comm =
                extract_comm_from_events(&obs.events).unwrap_or_else(|| "unknown".to_string());
            let index = engine.upsert_prediction(
                obs.identity_hash.clone(),
                obs.pid,
                predicted(obs),
                obs.belief.recommendation.clone(),
                None,
                comm,
                None,
                obs.timestamp,
            );
            latest_predictions.insert(key, index);
        }

        engine
    }

    /// Convert supported labels to calibration data.
    fn to_calibration_data(&self) -> Vec<CalibrationData> {
        self.records
            .iter()
            .filter_map(|r| r.to_calibration_data())
            .collect()
    }

    fn has_unresolved_identity(&self, identity_hash: &str, pid: u32) -> bool {
        self.records
            .iter()
            .rev()
            .any(|r| r.identity_hash == identity_hash && r.pid == pid && r.ground_truth.is_none())
    }

    #[allow(clippy::too_many_arguments)]
    fn upsert_prediction(
        &mut self,
        identity_hash: String,
        pid: u32,
        predicted_abandoned: f64,
        recommended_action: String,
        proc_type: Option<String>,
        comm: String,
        host_id: Option<String>,
        predicted_at: DateTime<Utc>,
    ) -> usize {
        if let Some((index, record)) = self.records.iter_mut().enumerate().rev().find(|(_, r)| {
            r.identity_hash == identity_hash && r.pid == pid && r.ground_truth.is_none()
        }) {
            record.pid = pid;
            record.predicted_abandoned = predicted_abandoned;
            record.recommended_action = recommended_action;
            record.proc_type = proc_type;
            record.comm = comm;
            record.predicted_at = predicted_at;
            record.host_id = host_id;
            return index;
        }

        self.records.push(ValidationRecord {
            identity_hash,
            pid,
            predicted_abandoned,
            recommended_action,
            proc_type,
            comm,
            predicted_at,
            ground_truth: None,
            resolved_at: None,
            exit_code: None,
            exit_signal: None,
            outcome_source: None,
            host_id,
        });
        self.records.len() - 1
    }

    /// Generate a full validation report.
    pub fn compute_report(&self) -> Result<ValidationReport, CalibrationError> {
        let cal_data = self.to_calibration_data();
        let resolved = self.resolved_records();
        let pending = self.pending_records();

        let (from, to) = if self.records.is_empty() {
            (Utc::now(), Utc::now())
        } else {
            let min_t = self.records.iter().map(|r| r.predicted_at).min().unwrap();
            let max_t = self.records.iter().map(|r| r.predicted_at).max().unwrap();
            (min_t, max_t)
        };

        let positive_labels = cal_data.iter().filter(|d| d.actual).count();
        let negative_labels = cal_data.len() - positive_labels;
        let both_classes =
            positive_labels >= MIN_LABELS_PER_CLASS && negative_labels >= MIN_LABELS_PER_CLASS;
        let unlabeled_outcomes = self
            .records
            .iter()
            .filter(|r| r.ground_truth.is_some_and(|gt| !gt.is_resolved()))
            .count();

        let metrics = if both_classes && cal_data.len() >= 10 {
            compute_metrics(&cal_data, self.threshold).ok()
        } else {
            None
        };

        let quality = metrics
            .as_ref()
            .map(|m| CalibrationQuality::from_metrics(m.ece, m.brier_score));

        let bias = if both_classes && cal_data.len() >= 20 {
            analyze_bias(&cal_data).ok()
        } else {
            None
        };

        let by_category = self.compute_category_validation(&resolved);
        let (top_false_positives, top_false_negatives) = self.compute_false_outcomes(&resolved);
        let recommendations = self.compute_prior_adjustments(&bias, &by_category);

        Ok(ValidationReport {
            from,
            to,
            total_predictions: self.records.len(),
            resolved_predictions: resolved.len(),
            pending_predictions: pending.len(),
            positive_labels,
            negative_labels,
            unlabeled_outcomes,
            metrics,
            quality,
            by_category,
            bias,
            top_false_positives,
            top_false_negatives,
            recommendations,
        })
    }

    /// Generate a full calibration report from supported labels, requiring the
    /// same minimum representation of both classes as the structured report.
    pub fn calibration_report(&self) -> Result<CalibrationReport, CalibrationError> {
        let cal_data = self.to_calibration_data();
        if cal_data.is_empty() {
            return Err(CalibrationError::NoData);
        }
        let positive_labels = cal_data.iter().filter(|datum| datum.actual).count();
        let negative_labels = cal_data.len() - positive_labels;
        let minority_labels = positive_labels.min(negative_labels);
        if minority_labels < MIN_LABELS_PER_CLASS {
            return Err(CalibrationError::InsufficientData {
                count: minority_labels,
                min_required: MIN_LABELS_PER_CLASS,
            });
        }
        CalibrationReport::from_data(&cal_data, 10, self.threshold)
    }

    fn compute_category_validation(
        &self,
        resolved: &[&ValidationRecord],
    ) -> Vec<CategoryValidation> {
        let mut by_cat: HashMap<String, Vec<&ValidationRecord>> = HashMap::new();
        for r in resolved {
            let cat = r.proc_type.clone().unwrap_or_else(|| "unknown".to_string());
            by_cat.entry(cat).or_default().push(r);
        }

        let mut results: Vec<CategoryValidation> = by_cat
            .into_iter()
            .map(|(category, records)| {
                let total = self
                    .records
                    .iter()
                    .filter(|r| {
                        r.proc_type.as_deref() == Some(category.as_str())
                            || (r.proc_type.is_none() && category == "unknown")
                    })
                    .count();

                let mut tp = 0usize;
                let mut fp = 0usize;
                let mut tn = 0usize;
                let mut fn_ = 0usize;

                for r in &records {
                    let predicted_kill = r.predicted_abandoned >= self.threshold;
                    let actually_abandoned = r.ground_truth.is_some_and(|gt| gt.is_abandoned());

                    match (predicted_kill, actually_abandoned) {
                        (true, true) => tp += 1,
                        (true, false) => fp += 1,
                        (false, false) => tn += 1,
                        (false, true) => fn_ += 1,
                    }
                }

                let resolved_count = records.len();
                let total_classified = tp + fp + tn + fn_;
                let accuracy = if total_classified > 0 {
                    (tp + tn) as f64 / total_classified as f64
                } else {
                    0.0
                };
                let precision = if tp + fp > 0 {
                    tp as f64 / (tp + fp) as f64
                } else {
                    0.0
                };
                let recall = if tp + fn_ > 0 {
                    tp as f64 / (tp + fn_) as f64
                } else {
                    0.0
                };

                CategoryValidation {
                    category,
                    total,
                    resolved: resolved_count,
                    true_positives: tp,
                    false_positives: fp,
                    true_negatives: tn,
                    false_negatives: fn_,
                    accuracy,
                    precision,
                    recall,
                }
            })
            .collect();

        results.sort_by_key(|b| std::cmp::Reverse(b.resolved));
        results
    }

    fn compute_false_outcomes(
        &self,
        resolved: &[&ValidationRecord],
    ) -> (Vec<FalseOutcome>, Vec<FalseOutcome>) {
        let mut fp_patterns: HashMap<String, (usize, f64, Option<String>)> = HashMap::new();
        let mut fn_patterns: HashMap<String, (usize, f64, Option<String>)> = HashMap::new();

        for r in resolved {
            let predicted_kill = r.predicted_abandoned >= self.threshold;
            let actually_abandoned = r.ground_truth.is_some_and(|gt| gt.is_abandoned());

            if predicted_kill && !actually_abandoned {
                let entry =
                    fp_patterns
                        .entry(r.comm.clone())
                        .or_insert((0, 0.0, r.proc_type.clone()));
                entry.0 += 1;
                entry.1 += r.predicted_abandoned;
            } else if !predicted_kill && actually_abandoned {
                let entry =
                    fn_patterns
                        .entry(r.comm.clone())
                        .or_insert((0, 0.0, r.proc_type.clone()));
                entry.0 += 1;
                entry.1 += r.predicted_abandoned;
            }
        }

        let mut fps: Vec<FalseOutcome> = fp_patterns
            .into_iter()
            .map(|(pattern, (count, sum_pred, cat))| FalseOutcome {
                pattern,
                count,
                mean_predicted: sum_pred / count as f64,
                category: cat,
            })
            .collect();
        fps.sort_by_key(|b| std::cmp::Reverse(b.count));
        fps.truncate(10);

        let mut fns: Vec<FalseOutcome> = fn_patterns
            .into_iter()
            .map(|(pattern, (count, sum_pred, cat))| FalseOutcome {
                pattern,
                count,
                mean_predicted: sum_pred / count as f64,
                category: cat,
            })
            .collect();
        fns.sort_by_key(|b| std::cmp::Reverse(b.count));
        fns.truncate(10);

        (fps, fns)
    }

    fn compute_prior_adjustments(
        &self,
        bias: &Option<BiasAnalysis>,
        categories: &[CategoryValidation],
    ) -> Vec<PriorAdjustment> {
        let mut adjustments = Vec::new();

        // Generate adjustments from bias analysis.
        if let Some(bias) = bias {
            for result in &bias.by_proc_type {
                if result.significant && result.sample_count >= 30 {
                    let confidence = 1.0 - (1.0 / result.sample_count as f64).sqrt();
                    adjustments.push(PriorAdjustment {
                        target: format!("prior.{}.abandoned", result.stratum),
                        current: result.mean_predicted,
                        suggested: result.actual_rate,
                        reason: format!(
                            "Bias of {:+.3} detected for '{}' (n={}). Model {} this category.",
                            result.bias,
                            result.stratum,
                            result.sample_count,
                            if result.bias > 0.0 {
                                "overestimates abandonment in"
                            } else {
                                "underestimates abandonment in"
                            }
                        ),
                        confidence,
                    });
                }
            }
        }

        // Generate adjustments from categories with poor precision.
        for cat in categories {
            if cat.resolved >= 20 && cat.precision < 0.5 && cat.false_positives > 0 {
                let confidence = 1.0 - (1.0 / cat.resolved as f64).sqrt();
                adjustments.push(PriorAdjustment {
                    target: format!("threshold.{}", cat.category),
                    current: self.threshold,
                    suggested: self.threshold + 0.1,
                    reason: format!(
                        "Low precision ({:.2}) for '{}' (FP={}, TP={}). Consider raising threshold.",
                        cat.precision, cat.category, cat.false_positives, cat.true_positives,
                    ),
                    confidence,
                });
            }
        }

        adjustments.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        adjustments
    }
}

fn extract_comm_from_events(events: &[ProcessEvent]) -> Option<String> {
    let mut preferred: Option<String> = None;

    for event in events {
        if let Some(details) = &event.details {
            if let Ok(value) = serde_json::from_str::<JsonValue>(details) {
                if let Some(comm) = value.get("comm").and_then(|v| v.as_str()) {
                    let comm = comm.to_string();
                    if event.event_type == EventType::EvidenceSnapshot {
                        return Some(comm);
                    }
                    preferred = Some(comm);
                }
            }
        }
    }

    preferred
}

/// Whether an event carries an explicit human verdict that must survive a
/// prediction-window limit. Both formats share one process-incarnation guard:
/// a first verdict with no preceding prediction still excludes later predictions
/// from evaluation against repeated labels. Event time and identity checks are
/// applied separately when replaying the observations.
pub fn is_explicit_shadow_verdict(event: &ProcessEvent) -> bool {
    map_explicit_verdict(event).is_some()
}

fn map_explicit_verdict(
    event: &ProcessEvent,
) -> Option<(GroundTruth, Option<i32>, Option<i32>, Option<String>)> {
    match event.event_type {
        EventType::HumanVerdict => Some((
            map_human_verdict(event)?,
            None,
            None,
            Some("human:agent_label".to_string()),
        )),
        EventType::ProcessExit => {
            let outcome = map_exit_event(event);
            outcome.0.is_resolved().then_some(outcome)
        }
        _ => None,
    }
}

fn map_human_verdict(event: &ProcessEvent) -> Option<GroundTruth> {
    let details = serde_json::from_str::<JsonValue>(event.details.as_deref()?).ok()?;
    if details.get("source")?.as_str()? != "agent_label" {
        return None;
    }
    match details.get("verdict")?.as_str()? {
        "kill" => Some(GroundTruth::UserKilled),
        "spare" => Some(GroundTruth::UserSpared),
        _ => None,
    }
}

fn map_exit_event(event: &ProcessEvent) -> (GroundTruth, Option<i32>, Option<i32>, Option<String>) {
    let mut exit_code: Option<i32> = None;
    let mut exit_signal: Option<i32> = None;
    let mut outcome_source: Option<String> = None;
    let mut ground_truth: Option<GroundTruth> = None;

    if let Some(details) = &event.details {
        if let Ok(value) = serde_json::from_str::<JsonValue>(details) {
            if let Some(code) = value.get("exit_code").and_then(|v| v.as_i64()) {
                exit_code = Some(code as i32);
            }
            if let Some(sig) = value.get("exit_signal").and_then(|v| v.as_i64()) {
                exit_signal = Some(sig as i32);
            }
            if let Some(hint) = value.get("outcome_hint").and_then(|v| v.as_str()) {
                ground_truth = map_outcome_hint(hint);
                outcome_source = Some(format!("shadow:hint:{}", hint));
            } else if let Some(reason) = value.get("reason").and_then(|v| v.as_str()) {
                outcome_source = Some(format!("shadow:{}", reason));
            }
        }
    }

    if ground_truth.is_none() {
        let crashed = exit_signal.is_some() || exit_code.is_some_and(|code| code != 0);
        ground_truth = Some(match exit_code {
            _ if crashed => {
                if outcome_source.is_none() {
                    outcome_source = Some("shadow:exit_status".to_string());
                }
                GroundTruth::Crash
            }
            Some(_) => GroundTruth::NormalExit,
            // Gone, with no exit status: the shadow recorder only sees that a process
            // is missing from the next scan. That used to read as a normal exit, which
            // made every resolved shadow label "not abandoned".
            None => GroundTruth::Vanished,
        });
    }

    (
        ground_truth.unwrap_or(GroundTruth::Vanished),
        exit_code,
        exit_signal,
        outcome_source,
    )
}

fn map_outcome_hint(hint: &str) -> Option<GroundTruth> {
    match hint {
        "user_killed" | "user_kill" => Some(GroundTruth::UserKilled),
        "user_spared" | "user_spare" => Some(GroundTruth::UserSpared),
        "normal_exit" => Some(GroundTruth::NormalExit),
        "external_kill" => Some(GroundTruth::ExternalKill),
        "system_shutdown" => Some(GroundTruth::SystemShutdown),
        "crash" => Some(GroundTruth::Crash),
        "still_running" => Some(GroundTruth::StillRunning),
        "expired" => Some(GroundTruth::Expired),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use pt_telemetry::shadow::{BeliefState, ProcessEvent, StateSnapshot};

    fn make_engine_with_data() -> ValidationEngine {
        let mut engine = ValidationEngine::new(0.5);

        // Track some predictions.
        engine.track_prediction(
            "hash_a".into(),
            100,
            0.9,
            "kill".into(),
            Some("test_runner".into()),
            "jest".into(),
            None,
        );
        engine.track_prediction(
            "hash_b".into(),
            200,
            0.3,
            "keep".into(),
            Some("dev_server".into()),
            "next".into(),
            None,
        );
        engine.track_prediction(
            "hash_c".into(),
            300,
            0.8,
            "kill".into(),
            Some("test_runner".into()),
            "pytest".into(),
            None,
        );
        engine.track_prediction(
            "hash_d".into(),
            400,
            0.2,
            "keep".into(),
            Some("dev_server".into()),
            "vite".into(),
            None,
        );
        engine.track_prediction(
            "hash_e".into(),
            500,
            0.7,
            "kill".into(),
            Some("test_runner".into()),
            "bun".into(),
            None,
        );

        // Record explicit verdicts for the known classification outcomes.
        engine.record_outcome("hash_a", GroundTruth::UserKilled, None, None);
        engine.record_outcome("hash_b", GroundTruth::UserSpared, None, None);
        engine.record_outcome("hash_c", GroundTruth::UserSpared, None, None); // false positive
        engine.record_outcome("hash_d", GroundTruth::UserKilled, None, None); // false negative

        // hash_e left unresolved

        engine
    }

    #[test]
    fn test_track_and_resolve() {
        let engine = make_engine_with_data();
        assert_eq!(engine.records().len(), 5);
        assert_eq!(engine.resolved_records().len(), 4);
        assert_eq!(engine.pending_records().len(), 1);
    }

    #[test]
    fn test_ground_truth_is_abandoned() {
        assert!(GroundTruth::UserKilled.is_abandoned());
        assert!(!GroundTruth::ExternalKill.is_abandoned());
        assert!(!GroundTruth::NormalExit.is_abandoned());
        assert!(!GroundTruth::Crash.is_abandoned());
        assert!(!GroundTruth::UserSpared.is_abandoned());
        assert!(!GroundTruth::StillRunning.is_abandoned());
    }

    #[test]
    fn test_ground_truth_is_resolved() {
        assert!(GroundTruth::UserKilled.is_resolved());
        assert!(GroundTruth::UserSpared.is_resolved());
        assert!(!GroundTruth::NormalExit.is_resolved());
        assert!(!GroundTruth::StillRunning.is_resolved());
        assert!(!GroundTruth::Expired.is_resolved());
    }

    #[test]
    fn test_to_calibration_data() {
        let engine = make_engine_with_data();
        let cal_data: Vec<CalibrationData> = engine
            .records()
            .iter()
            .filter_map(|r| r.to_calibration_data())
            .collect();

        assert_eq!(cal_data.len(), 4);
        // hash_a: predicted 0.9, actual=true (UserKilled is abandoned)
        assert!((cal_data[0].predicted - 0.9).abs() < 1e-9);
        assert!(cal_data[0].actual);
        // hash_b: predicted 0.3, actual=false (explicit spare verdict)
        assert!((cal_data[1].predicted - 0.3).abs() < 1e-9);
        assert!(!cal_data[1].actual);
    }

    #[test]
    fn test_record_outcome_by_identity_hash() {
        let mut engine = ValidationEngine::new(0.5);
        engine.track_prediction(
            "hash_x".into(),
            999,
            0.85,
            "kill".into(),
            None,
            "worker".into(),
            None,
        );

        assert!(engine.record_outcome("hash_x", GroundTruth::UserKilled, None, None));
        assert!(!engine.record_outcome("hash_x", GroundTruth::NormalExit, None, None));
        // Already resolved, second call returns false.
    }

    #[test]
    fn test_record_outcome_by_pid() {
        let mut engine = ValidationEngine::new(0.5);
        engine.track_prediction(
            "hash_y".into(),
            42,
            0.6,
            "kill".into(),
            None,
            "proc".into(),
            None,
        );

        assert!(engine.record_outcome_by_pid(42, GroundTruth::Crash, Some(1), None));
        assert!(engine.resolved_records().is_empty());
        assert_eq!(engine.records()[0].exit_code, Some(1));
        assert!(engine.records()[0].to_calibration_data().is_none());
    }

    #[test]
    fn test_compute_report_small_dataset() {
        let engine = make_engine_with_data();
        let report = engine.compute_report().unwrap();

        assert_eq!(report.total_predictions, 5);
        assert_eq!(report.resolved_predictions, 4);
        assert_eq!(report.pending_predictions, 1);
        // Too few samples for full metrics (need 10)
        assert!(report.metrics.is_none());
    }

    #[test]
    fn test_compute_report_with_enough_data() {
        let mut engine = ValidationEngine::new(0.5);

        // Generate 20 predictions with outcomes.
        for i in 0..20 {
            let prob = (i as f64) / 20.0;
            let actual_abandoned = prob > 0.5;
            let hash = format!("hash_{}", i);
            let gt = if actual_abandoned {
                GroundTruth::UserKilled
            } else {
                GroundTruth::UserSpared
            };

            engine.track_prediction(
                hash.clone(),
                i as u32 + 1000,
                prob,
                "keep".into(),
                Some("test".into()),
                "proc".into(),
                None,
            );
            engine.record_outcome(&hash, gt, None, None);
        }

        let report = engine.compute_report().unwrap();
        assert!(report.metrics.is_some());
        assert!(report.quality.is_some());
        assert!(report.bias.is_some());
    }

    #[test]
    fn test_category_validation() {
        let engine = make_engine_with_data();
        let report = engine.compute_report().unwrap();

        // Should have test_runner and dev_server categories.
        assert!(!report.by_category.is_empty());
        let tr = report
            .by_category
            .iter()
            .find(|c| c.category == "test_runner");
        assert!(tr.is_some());
        let tr = tr.unwrap();
        // hash_a: TP (predicted kill, actually abandoned)
        // hash_c: FP (predicted kill, actually useful)
        assert_eq!(tr.true_positives, 1);
        assert_eq!(tr.false_positives, 1);
    }

    #[test]
    fn test_false_outcomes_detected() {
        let engine = make_engine_with_data();
        let report = engine.compute_report().unwrap();

        // hash_c (pytest) is a false positive: predicted kill but explicit spare.
        assert!(!report.top_false_positives.is_empty());
        let fp = &report.top_false_positives[0];
        assert_eq!(fp.pattern, "pytest");
        assert_eq!(fp.count, 1);

        // hash_d (vite) is a false negative: predicted keep but explicit kill.
        assert!(!report.top_false_negatives.is_empty());
        let fn_ = &report.top_false_negatives[0];
        assert_eq!(fn_.pattern, "vite");
        assert_eq!(fn_.count, 1);
    }

    #[test]
    fn test_from_shadow_observations_upserts_predictions() {
        let now = Utc::now();
        let obs1 = Observation {
            timestamp: now,
            pid: 10,
            identity_hash: "hash_shadow".to_string(),
            state: StateSnapshot::default(),
            events: vec![ProcessEvent {
                timestamp: now,
                event_type: EventType::EvidenceSnapshot,
                details: Some(serde_json::json!({"comm": "sleep"}).to_string()),
            }],
            belief: BeliefState {
                p_abandoned: 0.1,
                p_legitimate: 0.9,
                p_zombie: 0.0,
                p_useful_but_bad: 0.0,
                recommendation: "keep".to_string(),
                ..BeliefState::default()
            },
        };

        let obs2 = Observation {
            timestamp: now + Duration::seconds(5),
            pid: 10,
            identity_hash: "hash_shadow".to_string(),
            state: StateSnapshot::default(),
            events: vec![ProcessEvent {
                timestamp: now + Duration::seconds(5),
                event_type: EventType::EvidenceSnapshot,
                details: Some(serde_json::json!({"comm": "sleep"}).to_string()),
            }],
            belief: BeliefState {
                p_abandoned: 0.85,
                p_legitimate: 0.1,
                p_zombie: 0.05,
                p_useful_but_bad: 0.0,
                recommendation: "kill".to_string(),
                ..BeliefState::default()
            },
        };

        let engine = ValidationEngine::from_shadow_observations(&[obs1, obs2], 0.5);
        assert_eq!(engine.pending_records().len(), 1);
        let record = engine.pending_records()[0];
        // The latest observation wins, and it predicts P(abandoned or zombie).
        assert!((record.predicted_abandoned - 0.9).abs() < 1e-6);
    }

    #[test]
    fn test_from_shadow_observations_resolves_exit() {
        let now = Utc::now();
        let obs1 = Observation {
            timestamp: now,
            pid: 11,
            identity_hash: "hash_exit".to_string(),
            state: StateSnapshot::default(),
            events: vec![ProcessEvent {
                timestamp: now,
                event_type: EventType::EvidenceSnapshot,
                details: Some(serde_json::json!({"comm": "worker"}).to_string()),
            }],
            belief: BeliefState {
                p_abandoned: 0.8,
                p_legitimate: 0.2,
                p_zombie: 0.0,
                p_useful_but_bad: 0.0,
                recommendation: "kill".to_string(),
                ..BeliefState::default()
            },
        };

        let obs2 = Observation {
            timestamp: now + Duration::seconds(12),
            pid: 11,
            identity_hash: "hash_exit".to_string(),
            state: StateSnapshot::default(),
            events: vec![ProcessEvent {
                timestamp: now + Duration::seconds(12),
                event_type: EventType::ProcessExit,
                details: Some(
                    serde_json::json!({
                        "reason": "missing",
                        "comm": "worker"
                    })
                    .to_string(),
                ),
            }],
            belief: BeliefState {
                p_abandoned: 0.8,
                p_legitimate: 0.2,
                p_zombie: 0.0,
                p_useful_but_bad: 0.0,
                recommendation: "kill".to_string(),
                ..BeliefState::default()
            },
        };

        let engine = ValidationEngine::from_shadow_observations(&[obs1, obs2], 0.5);
        // Missing from the next scan, exit unseen: closed, but not a label. (It used
        // to resolve as NormalExit, i.e. "not abandoned", for every shadow outcome.)
        assert!(engine.resolved_records().is_empty());
        assert!(engine.pending_records().is_empty());
        let record = &engine.records()[0];
        assert_eq!(record.ground_truth, Some(GroundTruth::Vanished));
        assert_eq!(record.comm, "worker");
        assert_eq!(record.outcome_source.as_deref(), Some("shadow:missing"));
        let report = engine.compute_report().unwrap();
        assert_eq!(report.unlabeled_outcomes, 1);
        assert_eq!((report.positive_labels, report.negative_labels), (0, 0));
    }

    #[test]
    fn shadow_prediction_is_abandoned_or_zombie() {
        let now = Utc::now();
        let obs = Observation {
            timestamp: now,
            pid: 12,
            identity_hash: "hash_z".to_string(),
            state: StateSnapshot::default(),
            events: vec![],
            belief: BeliefState {
                p_abandoned: 0.5,
                p_legitimate: 0.2,
                p_zombie: 0.3,
                p_useful_but_bad: 0.0,
                recommendation: "kill".to_string(),
                ..BeliefState::default()
            },
        };
        let engine = ValidationEngine::from_shadow_observations(&[obs], 0.5);
        let record = &engine.pending_records()[0];
        assert!((record.predicted_abandoned - 0.8).abs() < 1e-6);
    }

    fn human_label_prediction(
        at: DateTime<Utc>,
        pid: u32,
        identity: &str,
        probability: f32,
    ) -> Observation {
        Observation {
            timestamp: at,
            pid,
            identity_hash: identity.to_string(),
            state: StateSnapshot::default(),
            events: vec![ProcessEvent {
                timestamp: at,
                event_type: EventType::EvidenceSnapshot,
                details: Some(serde_json::json!({"comm": "test-worker"}).to_string()),
            }],
            belief: BeliefState {
                p_abandoned: probability,
                p_legitimate: 1.0 - probability,
                p_zombie: 0.0,
                p_useful_but_bad: 0.0,
                recommendation: "review".to_string(),
                ..BeliefState::default()
            },
        }
    }

    fn human_label_observation(
        at: DateTime<Utc>,
        pid: u32,
        identity: &str,
        verdict: &str,
    ) -> Observation {
        Observation {
            timestamp: at,
            pid,
            identity_hash: identity.to_string(),
            state: StateSnapshot::default(),
            events: vec![ProcessEvent {
                timestamp: at,
                event_type: EventType::HumanVerdict,
                details: Some(
                    serde_json::json!({
                        "verdict": verdict,
                        "source": "agent_label",
                        "comm": "test-worker"
                    })
                    .to_string(),
                ),
            }],
            belief: BeliefState {
                p_abandoned: 0.0,
                p_legitimate: 0.0,
                p_zombie: 0.0,
                p_useful_but_bad: 0.0,
                recommendation: "human_verdict".to_string(),
                ..BeliefState::default()
            },
        }
    }

    fn hinted_exit_observation(
        at: DateTime<Utc>,
        pid: u32,
        identity: &str,
        hint: &str,
    ) -> Observation {
        let mut observation = human_label_prediction(at, pid, identity, 0.1);
        observation.events = vec![ProcessEvent {
            timestamp: at,
            event_type: EventType::ProcessExit,
            details: Some(serde_json::json!({"outcome_hint": hint}).to_string()),
        }];
        observation
    }

    #[test]
    fn human_verdicts_label_latest_earlier_prediction_of_each_class() {
        let at = Utc::now() - Duration::days(2);
        for (verdict, expected) in [
            ("kill", GroundTruth::UserKilled),
            ("spare", GroundTruth::UserSpared),
        ] {
            let older = human_label_prediction(at, 100, "worker", 0.1);
            let mut latest = human_label_prediction(at + Duration::seconds(1), 100, "worker", 0.6);
            latest.belief.p_zombie = 0.2;
            latest.belief.p_legitimate = 0.2;
            let label = human_label_observation(at + Duration::seconds(2), 100, "worker", verdict);
            let engine = ValidationEngine::from_shadow_observations(&[label, older, latest], 0.5);
            assert_eq!(engine.records().len(), 1);
            let record = &engine.records()[0];
            assert_eq!(record.ground_truth, Some(expected));
            assert!((record.predicted_abandoned - 0.8).abs() < 1e-6);
            assert_eq!(record.predicted_at, at + Duration::seconds(1));
            assert_eq!(record.resolved_at, Some(at + Duration::seconds(2)));
            assert_eq!(record.outcome_source.as_deref(), Some("human:agent_label"));
            assert_eq!(record.comm, "test-worker");
            assert_eq!(record.recommended_action, "review");
        }
    }

    #[test]
    fn human_verdicts_require_an_earlier_exact_process_prediction() {
        let at = Utc::now();
        let label = human_label_observation(at, 100, "worker", "kill");
        let cases = [
            Vec::new(),
            vec![human_label_prediction(at, 100, "worker", 0.8)],
            vec![human_label_prediction(
                at + Duration::seconds(1),
                100,
                "worker",
                0.8,
            )],
            vec![human_label_prediction(
                at - Duration::seconds(1),
                100,
                "previous-incarnation",
                0.8,
            )],
            vec![human_label_prediction(
                at - Duration::seconds(1),
                101,
                "worker",
                0.8,
            )],
        ];
        for mut observations in cases {
            let predictions = observations.len();
            observations.push(label.clone());
            let engine = ValidationEngine::from_shadow_observations(&observations, 0.5);
            assert!(engine.resolved_records().is_empty());
            assert_eq!(
                engine.records().len(),
                predictions,
                "verdict must not create a prediction"
            );
        }
    }

    #[test]
    fn repeated_human_verdicts_do_not_overwrite_or_multiply_labels() {
        let at = Utc::now();
        let prediction = human_label_prediction(at, 100, "worker", 0.8);
        let label = human_label_observation(at + Duration::seconds(1), 100, "worker", "kill");
        let later_prediction =
            human_label_prediction(at + Duration::seconds(2), 100, "worker", 0.2);
        let repeated = human_label_observation(at + Duration::seconds(3), 100, "worker", "spare");
        let engine = ValidationEngine::from_shadow_observations(
            &[prediction, label.clone(), later_prediction, repeated, label],
            0.5,
        );
        assert_eq!(engine.records().len(), 2);
        assert_eq!(engine.resolved_records().len(), 1);
        assert_eq!(
            engine.resolved_records()[0].ground_truth,
            Some(GroundTruth::UserKilled)
        );
        assert_eq!(
            engine.resolved_records()[0].resolved_at,
            Some(at + Duration::seconds(1))
        );
        assert_eq!(engine.pending_records().len(), 1);
        assert_eq!(
            engine.pending_records()[0].predicted_at,
            at + Duration::seconds(2)
        );
    }

    #[test]
    fn first_verdict_without_prior_prediction_excludes_later_in_sample_labels() {
        let at = Utc::now();
        for prediction_delay in [Duration::zero(), Duration::seconds(1)] {
            for repeated_verdict in ["kill", "spare"] {
                for first in [
                    human_label_observation(at, 100, "worker", "kill"),
                    hinted_exit_observation(at, 100, "worker", "user_killed"),
                ] {
                    let hint = if repeated_verdict == "kill" {
                        "user_kill"
                    } else {
                        "user_spare"
                    };
                    for repeated in [
                        human_label_observation(
                            at + Duration::seconds(2),
                            100,
                            "worker",
                            repeated_verdict,
                        ),
                        hinted_exit_observation(at + Duration::seconds(2), 100, "worker", hint),
                    ] {
                        let prediction =
                            human_label_prediction(at + prediction_delay, 100, "worker", 0.9);
                        let engine = ValidationEngine::from_shadow_observations(
                            &[repeated, prediction, first.clone()],
                            0.5,
                        );
                        assert_eq!(engine.records().len(), 1);
                        assert_eq!(engine.pending_records().len(), 1);
                        assert!(engine.resolved_records().is_empty());
                        assert!(engine.records()[0].to_calibration_data().is_none());
                        assert_eq!(engine.records()[0].predicted_at, at + prediction_delay);
                    }
                }
            }
        }
    }

    #[test]
    fn late_verdict_storage_uses_event_time_without_labeling_later_predictions() {
        let at = Utc::now();
        let prediction = human_label_prediction(at, 100, "worker", 0.8);
        let equal_time = human_label_prediction(at + Duration::seconds(1), 100, "worker", 0.5);
        let later = human_label_prediction(at + Duration::seconds(2), 100, "worker", 0.2);
        let mut label = human_label_observation(at + Duration::seconds(1), 100, "worker", "spare");
        label.timestamp = at + Duration::seconds(10);
        let engine = ValidationEngine::from_shadow_observations(
            &[later, label, prediction, equal_time],
            0.5,
        );
        assert_eq!(engine.resolved_records().len(), 1);
        let labeled = engine.resolved_records()[0];
        assert_eq!(labeled.predicted_at, at);
        assert!((labeled.predicted_abandoned - 0.8).abs() < 1e-6);
        assert_eq!(labeled.resolved_at, Some(at + Duration::seconds(1)));
        assert_eq!(engine.pending_records().len(), 1);
        assert_eq!(
            engine.pending_records()[0].predicted_at,
            at + Duration::seconds(2)
        );
    }

    #[test]
    fn human_verdict_can_upgrade_an_unknown_outcome_but_not_invent_a_prediction() {
        let at = Utc::now();
        let prediction = human_label_prediction(at, 100, "worker", 0.8);
        let mut exit = human_label_prediction(at + Duration::seconds(1), 100, "worker", 0.1);
        exit.events = vec![ProcessEvent {
            timestamp: exit.timestamp,
            event_type: EventType::ProcessExit,
            details: Some(serde_json::json!({"reason": "missing"}).to_string()),
        }];
        let label = human_label_observation(at + Duration::seconds(2), 100, "worker", "kill");
        let engine = ValidationEngine::from_shadow_observations(
            &[prediction, exit.clone(), label.clone()],
            0.5,
        );
        assert_eq!(engine.records().len(), 1);
        assert_eq!(
            engine.records()[0].ground_truth,
            Some(GroundTruth::UserKilled)
        );
        assert_eq!(engine.records()[0].predicted_at, at);
        assert_eq!(
            engine.records()[0].resolved_at,
            Some(at + Duration::seconds(2))
        );

        // An exit-only historical row carries a cached belief, not a separately
        // recorded prediction. It may be shown as an outcome but earns no label.
        let exit_only = ValidationEngine::from_shadow_observations(&[exit, label], 0.5);
        assert!(exit_only.resolved_records().is_empty());
        assert_eq!(
            exit_only.records()[0].ground_truth,
            Some(GroundTruth::Vanished)
        );
        assert_eq!(
            exit_only.records()[0].resolved_at,
            Some(at + Duration::seconds(1))
        );
    }

    #[test]
    fn invalid_human_verdicts_never_supply_predictions_or_labels() {
        let at = Utc::now();
        for invalid in 0..6 {
            let prediction = human_label_prediction(at, 100, "worker", 0.8);
            let mut label =
                human_label_observation(at + Duration::seconds(1), 100, "worker", "kill");
            match invalid {
                0 => label.events[0].details = None,
                1 => label.events[0].details = Some("malformed".to_string()),
                2 => {
                    label.events[0].details = Some(
                        serde_json::json!({"verdict": "kill", "source": "automatic"}).to_string(),
                    )
                }
                3 => {
                    label.events[0].details = Some(
                        serde_json::json!({"verdict": "review", "source": "agent_label"})
                            .to_string(),
                    )
                }
                4 => label.events[0].timestamp = at + Duration::seconds(2),
                5 => label.identity_hash.clear(),
                _ => unreachable!(),
            }
            let engine = ValidationEngine::from_shadow_observations(&[prediction, label], 0.5);
            assert_eq!(engine.records().len(), 1, "case {invalid}");
            assert!(engine.resolved_records().is_empty(), "case {invalid}");
            assert_eq!(engine.pending_records().len(), 1, "case {invalid}");
        }
    }

    #[test]
    fn human_verdict_preserves_an_existing_explicit_outcome() {
        let at = Utc::now();
        let prediction = human_label_prediction(at, 100, "worker", 0.8);
        let mut exit = human_label_prediction(at + Duration::seconds(1), 100, "worker", 0.1);
        exit.events = vec![ProcessEvent {
            timestamp: exit.timestamp,
            event_type: EventType::ProcessExit,
            details: Some(serde_json::json!({"outcome_hint": "user_spared"}).to_string()),
        }];
        let label = human_label_observation(at + Duration::seconds(2), 100, "worker", "kill");
        let engine = ValidationEngine::from_shadow_observations(&[prediction, exit, label], 0.5);
        assert_eq!(engine.records().len(), 1);
        assert_eq!(
            engine.records()[0].ground_truth,
            Some(GroundTruth::UserSpared)
        );
        assert_eq!(
            engine.records()[0].resolved_at,
            Some(at + Duration::seconds(1))
        );
    }

    #[test]
    fn human_and_legacy_verdicts_share_one_label_per_incarnation_in_both_orders() {
        let at = Utc::now();
        for human_first in [true, false] {
            let prediction = human_label_prediction(at, 100, "worker", 0.8);
            let human = human_label_observation(
                at + Duration::seconds(if human_first { 1 } else { 2 }),
                100,
                "worker",
                "kill",
            );
            let hint = hinted_exit_observation(
                at + Duration::seconds(if human_first { 2 } else { 1 }),
                100,
                "worker",
                "user_spared",
            );
            let duplicate_hint =
                hinted_exit_observation(at + Duration::seconds(3), 100, "worker", "user_kill");
            let repeated_hint =
                hinted_exit_observation(at + Duration::seconds(4), 100, "worker", "user_spare");
            let engine = ValidationEngine::from_shadow_observations(
                &[
                    repeated_hint,
                    human,
                    prediction,
                    duplicate_hint,
                    hint.clone(),
                    hint,
                ],
                0.5,
            );
            assert_eq!(engine.records().len(), 1);
            assert_eq!(engine.resolved_records().len(), 1);
            let record = &engine.records()[0];
            assert_eq!(
                record.ground_truth,
                Some(if human_first {
                    GroundTruth::UserKilled
                } else {
                    GroundTruth::UserSpared
                })
            );
            assert_eq!(record.predicted_at, at);
            assert_eq!(record.resolved_at, Some(at + Duration::seconds(1)));
            assert!((record.predicted_abandoned - 0.8).abs() < 1e-6);
        }
    }

    #[test]
    fn repeated_hinted_exits_do_not_add_calibration_samples() {
        let at = Utc::now();
        let prediction = human_label_prediction(at, 100, "worker", 0.8);
        let first =
            hinted_exit_observation(at + Duration::seconds(1), 100, "worker", "user_killed");
        let repeated =
            hinted_exit_observation(at + Duration::seconds(2), 100, "worker", "user_spared");
        let later_prediction =
            human_label_prediction(at + Duration::seconds(3), 100, "worker", 0.2);
        let repeated_after_training =
            hinted_exit_observation(at + Duration::seconds(4), 100, "worker", "user_kill");
        let engine = ValidationEngine::from_shadow_observations(
            &[
                prediction,
                first,
                repeated,
                later_prediction,
                repeated_after_training,
            ],
            0.5,
        );
        assert_eq!(engine.records().len(), 2);
        assert_eq!(engine.resolved_records().len(), 1);
        assert_eq!(
            engine.resolved_records()[0].ground_truth,
            Some(GroundTruth::UserKilled)
        );
        assert_eq!(
            engine.resolved_records()[0].resolved_at,
            Some(at + Duration::seconds(1))
        );
        assert_eq!(engine.pending_records().len(), 1);
        assert_eq!(
            engine.pending_records()[0].predicted_at,
            at + Duration::seconds(3)
        );
    }

    #[test]
    fn hinted_exit_verdicts_require_an_earlier_real_prediction() {
        let at = Utc::now();
        let label = hinted_exit_observation(at, 100, "worker", "user_killed");
        let cases = [
            Vec::new(),
            vec![human_label_prediction(at, 100, "worker", 0.8)],
            vec![human_label_prediction(
                at + Duration::seconds(1),
                100,
                "worker",
                0.8,
            )],
            vec![human_label_prediction(
                at - Duration::seconds(1),
                100,
                "previous-incarnation",
                0.8,
            )],
            vec![human_label_prediction(
                at - Duration::seconds(1),
                101,
                "worker",
                0.8,
            )],
            vec![hinted_exit_observation(
                at - Duration::seconds(1),
                100,
                "worker",
                "normal_exit",
            )],
        ];
        for mut observations in cases {
            let predictions = observations.len();
            observations.push(label.clone());
            let engine = ValidationEngine::from_shadow_observations(&observations, 0.5);
            assert!(engine.resolved_records().is_empty());
            assert_eq!(
                engine.records().len(),
                predictions,
                "an exit hint must not manufacture a prediction"
            );
        }
    }

    #[test]
    fn exit_status_decides_normal_exit_or_crash() {
        let event = |details: serde_json::Value| ProcessEvent {
            timestamp: Utc::now(),
            event_type: EventType::ProcessExit,
            details: Some(details.to_string()),
        };
        assert_eq!(
            map_exit_event(&event(serde_json::json!({"exit_code": 0}))).0,
            GroundTruth::NormalExit
        );
        assert_eq!(
            map_exit_event(&event(serde_json::json!({"exit_code": 2}))).0,
            GroundTruth::Crash
        );
        assert_eq!(
            map_exit_event(&event(serde_json::json!({"exit_signal": 9}))).0,
            GroundTruth::Crash
        );
        assert_eq!(
            map_exit_event(&event(serde_json::json!({"reason": "missing"}))).0,
            GroundTruth::Vanished
        );
    }

    fn shadow_exit_observation(
        identity: &str,
        probability: f32,
        details: serde_json::Value,
    ) -> Observation {
        let now = Utc::now();
        Observation {
            timestamp: now,
            pid: 100,
            identity_hash: identity.to_string(),
            state: StateSnapshot::default(),
            events: vec![ProcessEvent {
                timestamp: now,
                event_type: EventType::ProcessExit,
                details: Some(details.to_string()),
            }],
            belief: BeliefState {
                p_abandoned: probability,
                p_legitimate: 1.0 - probability,
                p_zombie: 0.0,
                p_useful_but_bad: 0.0,
                recommendation: if probability >= 0.5 { "kill" } else { "keep" }.to_string(),
                ..BeliefState::default()
            },
        }
    }

    #[test]
    fn shadow_exit_causes_remain_unlabeled() {
        let cases = [
            (
                "oom",
                serde_json::json!({
                    "outcome_hint": "external_kill", "reason": "oom", "exit_signal": 9
                }),
                GroundTruth::ExternalKill,
            ),
            (
                "external_kill",
                serde_json::json!({"outcome_hint": "external_kill"}),
                GroundTruth::ExternalKill,
            ),
            (
                "signal",
                serde_json::json!({"exit_signal": 9}),
                GroundTruth::Crash,
            ),
            (
                "nonzero_exit",
                serde_json::json!({"exit_code": 1}),
                GroundTruth::Crash,
            ),
            (
                "shutdown",
                serde_json::json!({"outcome_hint": "system_shutdown", "exit_code": 0}),
                GroundTruth::SystemShutdown,
            ),
            (
                "normal_exit",
                serde_json::json!({"exit_code": 0}),
                GroundTruth::NormalExit,
            ),
            (
                "missing",
                serde_json::json!({"reason": "missing"}),
                GroundTruth::Vanished,
            ),
        ];
        let observations: Vec<_> = cases
            .iter()
            .enumerate()
            .map(|(i, (identity, details, _))| {
                shadow_exit_observation(
                    identity,
                    if i % 2 == 0 { 0.9 } else { 0.1 },
                    details.clone(),
                )
            })
            .collect();
        let engine = ValidationEngine::from_shadow_observations(&observations, 0.5);
        for (identity, _, outcome) in &cases {
            let record = engine
                .records()
                .iter()
                .find(|record| record.identity_hash == *identity)
                .unwrap();
            assert_eq!(record.ground_truth, Some(*outcome));
            assert!(record.resolved_at.is_some());
            assert!(record.to_calibration_data().is_none(), "{identity}");
        }
        let oom = engine
            .records()
            .iter()
            .find(|record| record.identity_hash == "oom")
            .unwrap();
        assert_eq!(oom.exit_signal, Some(9));
        assert_eq!(
            oom.outcome_source.as_deref(),
            Some("shadow:hint:external_kill")
        );
        let report = engine.compute_report().unwrap();
        assert_eq!(report.total_predictions, cases.len());
        assert_eq!(report.unlabeled_outcomes, cases.len());
        assert_eq!(report.resolved_predictions, 0);
        assert_eq!(report.pending_predictions, 0);
        assert_eq!((report.positive_labels, report.negative_labels), (0, 0));
        assert!(report.metrics.is_none());
        assert!(report.quality.is_none());
        assert!(report.bias.is_none());
        assert!(report.by_category.is_empty());
        assert!(report.top_false_positives.is_empty());
        assert!(report.top_false_negatives.is_empty());
        assert!(report.recommendations.is_empty());
        assert!(matches!(
            engine.calibration_report(),
            Err(CalibrationError::NoData)
        ));
    }

    #[test]
    fn ambiguous_outcomes_do_not_change_labeled_reports() {
        let mut observations = Vec::new();
        for i in 0..10 {
            // Include genuine false positives and false negatives so excluding
            // unknown exits cannot accidentally erase the supported errors.
            for (identity, probability, hint) in [
                (format!("kill_{i}"), 0.2, "user_killed"),
                (format!("spare_{i}"), 0.8, "user_spared"),
            ] {
                let exit = shadow_exit_observation(
                    &identity,
                    probability,
                    serde_json::json!({"outcome_hint": hint}),
                );
                observations.push(human_label_prediction(
                    exit.timestamp - Duration::seconds(1),
                    exit.pid,
                    &identity,
                    probability,
                ));
                observations.push(exit);
            }
        }
        let baseline = ValidationEngine::from_shadow_observations(&observations, 0.5)
            .compute_report()
            .unwrap();
        assert_eq!(
            (baseline.positive_labels, baseline.negative_labels),
            (10, 10)
        );
        assert!((baseline.metrics.as_ref().unwrap().brier_score - 0.64).abs() < 1e-6);
        assert_eq!(baseline.by_category[0].false_positives, 10);
        assert_eq!(baseline.by_category[0].false_negatives, 10);
        assert!(!baseline.recommendations.is_empty());

        for (i, hint) in ["external_kill", "crash", "system_shutdown", "normal_exit"]
            .iter()
            .enumerate()
        {
            for j in 0..20 {
                observations.push(shadow_exit_observation(
                    &format!("unknown_{i}_{j}"),
                    if i == 0 { 0.9 } else { 0.1 },
                    serde_json::json!({"outcome_hint": hint}),
                ));
            }
        }
        let report = ValidationEngine::from_shadow_observations(&observations, 0.5)
            .compute_report()
            .unwrap();
        assert_eq!(report.total_predictions, 100);
        assert_eq!(report.resolved_predictions, 20);
        assert_eq!(report.unlabeled_outcomes, 80);
        assert_eq!((report.positive_labels, report.negative_labels), (10, 10));
        assert_eq!(report.by_category[0].total, 100);
        assert_eq!(report.by_category[0].resolved, 20);
        assert_eq!(report.by_category[0].false_positives, 10);
        assert_eq!(report.by_category[0].false_negatives, 10);
        let baseline = serde_json::to_value(&baseline).unwrap();
        let report = serde_json::to_value(&report).unwrap();
        for field in [
            "metrics",
            "quality",
            "bias",
            "top_false_positives",
            "top_false_negatives",
            "recommendations",
        ] {
            assert_eq!(report[field], baseline[field], "{field}");
        }
    }

    /// With one class only, calibration figures are meaningless: no metrics.
    #[test]
    fn report_needs_labels_of_both_classes() {
        let mut engine = ValidationEngine::new(0.5);
        for i in 0..30 {
            let hash = format!("neg_{i}");
            engine.track_prediction(
                hash.clone(),
                i,
                0.9,
                "kill".into(),
                None,
                "proc".into(),
                None,
            );
            engine.record_outcome(&hash, GroundTruth::UserSpared, None, None);
        }
        let report = engine.compute_report().unwrap();
        assert_eq!((report.positive_labels, report.negative_labels), (0, 30));
        assert!(report.metrics.is_none());
        assert!(report.bias.is_none());
    }

    // --- GroundTruth serde roundtrip ---

    #[test]
    fn ground_truth_serde_all_variants() {
        let variants = [
            GroundTruth::UserKilled,
            GroundTruth::UserSpared,
            GroundTruth::NormalExit,
            GroundTruth::Crash,
            GroundTruth::ExternalKill,
            GroundTruth::SystemShutdown,
            GroundTruth::StillRunning,
            GroundTruth::Expired,
            GroundTruth::Vanished,
        ];
        for gt in &variants {
            let json = serde_json::to_string(gt).unwrap();
            let deser: GroundTruth = serde_json::from_str(&json).unwrap();
            assert_eq!(*gt, deser);
        }
    }

    #[test]
    fn ground_truth_is_abandoned_complete() {
        // Verify exhaustively which are abandoned
        assert!(GroundTruth::UserKilled.is_abandoned());
        assert!(!GroundTruth::ExternalKill.is_abandoned());
        assert!(!GroundTruth::UserSpared.is_abandoned());
        assert!(!GroundTruth::NormalExit.is_abandoned());
        assert!(!GroundTruth::Crash.is_abandoned());
        assert!(!GroundTruth::SystemShutdown.is_abandoned());
        assert!(!GroundTruth::StillRunning.is_abandoned());
        assert!(!GroundTruth::Expired.is_abandoned());
        assert!(!GroundTruth::Vanished.is_abandoned());
    }

    #[test]
    fn ground_truth_is_resolved_complete() {
        assert!(GroundTruth::UserKilled.is_resolved());
        assert!(GroundTruth::UserSpared.is_resolved());
        assert!(!GroundTruth::NormalExit.is_resolved());
        assert!(!GroundTruth::Crash.is_resolved());
        assert!(!GroundTruth::ExternalKill.is_resolved());
        assert!(!GroundTruth::SystemShutdown.is_resolved());
        assert!(!GroundTruth::StillRunning.is_resolved());
        assert!(!GroundTruth::Expired.is_resolved());
        assert!(!GroundTruth::Vanished.is_resolved());
    }

    // --- ValidationRecord serde ---

    #[test]
    fn validation_record_serde_roundtrip() {
        let record = ValidationRecord {
            identity_hash: "hash_test".to_string(),
            pid: 12345,
            predicted_abandoned: 0.85,
            recommended_action: "kill".to_string(),
            proc_type: Some("test_runner".to_string()),
            comm: "jest".to_string(),
            predicted_at: Utc::now(),
            ground_truth: Some(GroundTruth::UserKilled),
            resolved_at: Some(Utc::now()),
            exit_code: Some(0),
            exit_signal: None,
            outcome_source: Some("user".to_string()),
            host_id: Some("host1".to_string()),
        };
        let json = serde_json::to_string(&record).unwrap();
        let deser: ValidationRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.identity_hash, "hash_test");
        assert_eq!(deser.pid, 12345);
        assert!((deser.predicted_abandoned - 0.85).abs() < 1e-9);
        assert_eq!(deser.ground_truth, Some(GroundTruth::UserKilled));
        assert_eq!(deser.outcome_source.as_deref(), Some("user"));
        assert_eq!(deser.host_id.as_deref(), Some("host1"));
    }

    #[test]
    fn validation_record_to_calibration_data_unresolved() {
        let record = ValidationRecord {
            identity_hash: "hash_unr".to_string(),
            pid: 100,
            predicted_abandoned: 0.5,
            recommended_action: "kill".to_string(),
            proc_type: None,
            comm: "proc".to_string(),
            predicted_at: Utc::now(),
            ground_truth: None, // unresolved
            resolved_at: None,
            exit_code: None,
            exit_signal: None,
            outcome_source: None,
            host_id: None,
        };
        assert!(record.to_calibration_data().is_none());
    }

    #[test]
    fn validation_record_to_calibration_data_still_running() {
        let record = ValidationRecord {
            identity_hash: "hash_sr".to_string(),
            pid: 101,
            predicted_abandoned: 0.6,
            recommended_action: "kill".to_string(),
            proc_type: None,
            comm: "proc".to_string(),
            predicted_at: Utc::now(),
            ground_truth: Some(GroundTruth::StillRunning),
            resolved_at: None,
            exit_code: None,
            exit_signal: None,
            outcome_source: None,
            host_id: None,
        };
        // StillRunning is not resolved, so no calibration data
        assert!(record.to_calibration_data().is_none());
    }

    // --- CategoryValidation serde ---

    #[test]
    fn category_validation_serde_roundtrip() {
        let cv = CategoryValidation {
            category: "test_runner".to_string(),
            total: 50,
            resolved: 40,
            true_positives: 15,
            false_positives: 5,
            true_negatives: 15,
            false_negatives: 5,
            accuracy: 0.75,
            precision: 0.75,
            recall: 0.75,
        };
        let json = serde_json::to_string(&cv).unwrap();
        let deser: CategoryValidation = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.category, "test_runner");
        assert_eq!(deser.true_positives, 15);
    }

    // --- FalseOutcome serde ---

    #[test]
    fn false_outcome_serde_roundtrip() {
        let fo = FalseOutcome {
            pattern: "pytest".to_string(),
            count: 3,
            mean_predicted: 0.82,
            category: Some("test_runner".to_string()),
        };
        let json = serde_json::to_string(&fo).unwrap();
        let deser: FalseOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.pattern, "pytest");
        assert_eq!(deser.count, 3);
    }

    // --- PriorAdjustment serde ---

    #[test]
    fn prior_adjustment_serde_roundtrip() {
        let pa = PriorAdjustment {
            target: "prior.test_runner.abandoned".to_string(),
            current: 0.5,
            suggested: 0.3,
            reason: "Model overestimates".to_string(),
            confidence: 0.85,
        };
        let json = serde_json::to_string(&pa).unwrap();
        let deser: PriorAdjustment = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.target, "prior.test_runner.abandoned");
        assert!((deser.confidence - 0.85).abs() < 1e-9);
    }

    // --- map_outcome_hint coverage ---

    #[test]
    fn map_outcome_hint_all_variants() {
        assert_eq!(
            map_outcome_hint("user_killed"),
            Some(GroundTruth::UserKilled)
        );
        assert_eq!(map_outcome_hint("user_kill"), Some(GroundTruth::UserKilled));
        assert_eq!(
            map_outcome_hint("user_spared"),
            Some(GroundTruth::UserSpared)
        );
        assert_eq!(
            map_outcome_hint("user_spare"),
            Some(GroundTruth::UserSpared)
        );
        assert_eq!(
            map_outcome_hint("normal_exit"),
            Some(GroundTruth::NormalExit)
        );
        assert_eq!(
            map_outcome_hint("external_kill"),
            Some(GroundTruth::ExternalKill)
        );
        assert_eq!(
            map_outcome_hint("system_shutdown"),
            Some(GroundTruth::SystemShutdown)
        );
        assert_eq!(map_outcome_hint("crash"), Some(GroundTruth::Crash));
        assert_eq!(
            map_outcome_hint("still_running"),
            Some(GroundTruth::StillRunning)
        );
        assert_eq!(map_outcome_hint("expired"), Some(GroundTruth::Expired));
        assert_eq!(map_outcome_hint("unknown_hint"), None);
    }

    // --- map_exit_event coverage ---

    #[test]
    fn map_exit_event_with_outcome_hint() {
        let event = ProcessEvent {
            timestamp: Utc::now(),
            event_type: EventType::ProcessExit,
            details: Some(
                serde_json::json!({
                    "outcome_hint": "user_killed",
                    "exit_code": 137
                })
                .to_string(),
            ),
        };
        let (gt, exit_code, _signal, source) = map_exit_event(&event);
        assert_eq!(gt, GroundTruth::UserKilled);
        assert_eq!(exit_code, Some(137));
        assert!(source.unwrap().contains("hint:user_killed"));
    }

    #[test]
    fn map_exit_event_signal_implies_crash() {
        let event = ProcessEvent {
            timestamp: Utc::now(),
            event_type: EventType::ProcessExit,
            details: Some(serde_json::json!({"exit_signal": 9}).to_string()),
        };
        let (gt, _code, signal, source) = map_exit_event(&event);
        assert_eq!(gt, GroundTruth::Crash);
        assert_eq!(signal, Some(9));
        assert_eq!(source.as_deref(), Some("shadow:exit_status"));
    }

    #[test]
    fn map_exit_event_nonzero_exit_implies_crash() {
        let event = ProcessEvent {
            timestamp: Utc::now(),
            event_type: EventType::ProcessExit,
            details: Some(serde_json::json!({"exit_code": 1}).to_string()),
        };
        let (gt, code, _signal, _source) = map_exit_event(&event);
        assert_eq!(gt, GroundTruth::Crash);
        assert_eq!(code, Some(1));
    }

    #[test]
    fn map_exit_event_zero_exit_is_normal() {
        let event = ProcessEvent {
            timestamp: Utc::now(),
            event_type: EventType::ProcessExit,
            details: Some(serde_json::json!({"exit_code": 0}).to_string()),
        };
        let (gt, code, _signal, _source) = map_exit_event(&event);
        assert_eq!(gt, GroundTruth::NormalExit);
        assert_eq!(code, Some(0));
    }

    #[test]
    fn map_exit_event_no_details() {
        let event = ProcessEvent {
            timestamp: Utc::now(),
            event_type: EventType::ProcessExit,
            details: None,
        };
        let (gt, code, signal, _source) = map_exit_event(&event);
        // Nothing observed about the exit: not evidence of a normal exit.
        assert_eq!(gt, GroundTruth::Vanished);
        assert!(code.is_none());
        assert!(signal.is_none());
    }

    #[test]
    fn map_exit_event_with_reason_only() {
        let event = ProcessEvent {
            timestamp: Utc::now(),
            event_type: EventType::ProcessExit,
            details: Some(serde_json::json!({"reason": "oom"}).to_string()),
        };
        let (gt, _code, _signal, source) = map_exit_event(&event);
        // No exit_code or signal: the outcome is unknown, not a normal exit.
        assert_eq!(gt, GroundTruth::Vanished);
        assert_eq!(source.as_deref(), Some("shadow:oom"));
    }

    // --- Engine construction and accessors ---

    #[test]
    fn engine_from_records() {
        let records = vec![ValidationRecord {
            identity_hash: "h1".to_string(),
            pid: 1,
            predicted_abandoned: 0.7,
            recommended_action: "kill".to_string(),
            proc_type: None,
            comm: "sleep".to_string(),
            predicted_at: Utc::now(),
            ground_truth: Some(GroundTruth::UserKilled),
            resolved_at: Some(Utc::now()),
            exit_code: None,
            exit_signal: None,
            outcome_source: None,
            host_id: None,
        }];
        let engine = ValidationEngine::from_records(records, 0.5);
        assert_eq!(engine.records().len(), 1);
        assert_eq!(engine.resolved_records().len(), 1);
        assert!(engine.pending_records().is_empty());
    }

    #[test]
    fn engine_pending_records() {
        let mut engine = ValidationEngine::new(0.5);
        engine.track_prediction("h1".into(), 1, 0.8, "kill".into(), None, "p1".into(), None);
        engine.track_prediction("h2".into(), 2, 0.3, "keep".into(), None, "p2".into(), None);
        assert_eq!(engine.pending_records().len(), 2);
        engine.record_outcome("h1", GroundTruth::UserKilled, None, None);
        assert_eq!(engine.pending_records().len(), 1);
    }

    // --- record_outcome_with_source ---

    #[test]
    fn record_outcome_with_source_sets_source() {
        let mut engine = ValidationEngine::new(0.5);
        engine.track_prediction(
            "h1".into(),
            1,
            0.9,
            "kill".into(),
            None,
            "proc".into(),
            None,
        );
        let found = engine.record_outcome_with_source(
            "h1",
            GroundTruth::UserKilled,
            None,
            None,
            Some("manual_confirm".to_string()),
        );
        assert!(found);
        assert_eq!(
            engine.records()[0].outcome_source.as_deref(),
            Some("manual_confirm")
        );
    }

    #[test]
    fn record_outcome_with_source_not_found() {
        let mut engine = ValidationEngine::new(0.5);
        let found = engine.record_outcome_with_source(
            "nonexistent",
            GroundTruth::NormalExit,
            None,
            None,
            None,
        );
        assert!(!found);
    }

    // --- record_outcome_by_pid_with_source ---

    #[test]
    fn record_outcome_by_pid_with_source_sets_source() {
        let mut engine = ValidationEngine::new(0.5);
        engine.track_prediction(
            "h1".into(),
            42,
            0.6,
            "kill".into(),
            None,
            "proc".into(),
            None,
        );
        let found = engine.record_outcome_by_pid_with_source(
            42,
            GroundTruth::Crash,
            Some(1),
            None,
            Some("shadow:exit".to_string()),
        );
        assert!(found);
        assert_eq!(
            engine.records()[0].outcome_source.as_deref(),
            Some("shadow:exit")
        );
    }

    #[test]
    fn record_outcome_by_pid_not_found() {
        let mut engine = ValidationEngine::new(0.5);
        let found = engine.record_outcome_by_pid(999, GroundTruth::NormalExit, None, None);
        assert!(!found);
    }

    // --- extract_comm_from_events ---

    #[test]
    fn extract_comm_prefers_evidence_snapshot() {
        let events = vec![
            ProcessEvent {
                timestamp: Utc::now(),
                event_type: EventType::ProcessExit,
                details: Some(serde_json::json!({"comm": "exit_comm"}).to_string()),
            },
            ProcessEvent {
                timestamp: Utc::now(),
                event_type: EventType::EvidenceSnapshot,
                details: Some(serde_json::json!({"comm": "snapshot_comm"}).to_string()),
            },
        ];
        let comm = extract_comm_from_events(&events);
        assert_eq!(comm, Some("snapshot_comm".to_string()));
    }

    #[test]
    fn extract_comm_falls_back_to_other_event() {
        let events = vec![ProcessEvent {
            timestamp: Utc::now(),
            event_type: EventType::ProcessExit,
            details: Some(serde_json::json!({"comm": "fallback_comm"}).to_string()),
        }];
        let comm = extract_comm_from_events(&events);
        assert_eq!(comm, Some("fallback_comm".to_string()));
    }

    #[test]
    fn extract_comm_no_comm_field() {
        let events = vec![ProcessEvent {
            timestamp: Utc::now(),
            event_type: EventType::ProcessExit,
            details: Some(serde_json::json!({"pid": 42}).to_string()),
        }];
        let comm = extract_comm_from_events(&events);
        assert!(comm.is_none());
    }

    #[test]
    fn extract_comm_empty_events() {
        let comm = extract_comm_from_events(&[]);
        assert!(comm.is_none());
    }

    // --- compute_report edge cases ---

    #[test]
    fn compute_report_empty_engine() {
        let engine = ValidationEngine::new(0.5);
        let report = engine.compute_report().unwrap();
        assert_eq!(report.total_predictions, 0);
        assert_eq!(report.resolved_predictions, 0);
        assert!(report.metrics.is_none());
    }

    #[test]
    fn calibration_report_no_data_errors() {
        let engine = ValidationEngine::new(0.5);
        let result = engine.calibration_report();
        assert!(matches!(result, Err(CalibrationError::NoData)));
    }

    #[test]
    fn calibration_report_requires_five_supported_labels_in_each_class() {
        for (positive_labels, negative_labels) in [(10, 0), (9, 1), (0, 10), (1, 9), (5, 5)] {
            let mut engine = ValidationEngine::new(0.5);
            for index in 0..positive_labels + negative_labels {
                let identity = format!("labeled_{index}");
                let positive = index < positive_labels;
                engine.track_prediction(
                    identity.clone(),
                    index as u32,
                    if positive { 0.9 } else { 0.1 },
                    "review".into(),
                    None,
                    "worker".into(),
                    None,
                );
                assert!(engine.record_outcome(
                    &identity,
                    if positive {
                        GroundTruth::UserKilled
                    } else {
                        GroundTruth::UserSpared
                    },
                    None,
                    None,
                ));
            }

            let minority_labels = positive_labels.min(negative_labels);
            if minority_labels < MIN_LABELS_PER_CLASS {
                assert!(matches!(
                    engine.calibration_report(),
                    Err(CalibrationError::InsufficientData { count, min_required })
                        if count == minority_labels && min_required == MIN_LABELS_PER_CLASS
                ));
                assert!(engine.compute_report().unwrap().metrics.is_none());
            } else {
                let report = engine.calibration_report().unwrap();
                assert_eq!(
                    report.metrics.sample_count,
                    positive_labels + negative_labels
                );
                assert_eq!(report.metrics.positive_count, positive_labels);
                assert_eq!(report.metrics.negative_count, negative_labels);
                assert!((report.metrics.brier_score - 0.01).abs() < 1e-10);
                assert!(engine.compute_report().unwrap().metrics.is_some());
            }
        }
    }

    #[test]
    fn validation_record_host_id_in_calibration_data() {
        let record = ValidationRecord {
            identity_hash: "h_host".to_string(),
            pid: 50,
            predicted_abandoned: 0.9,
            recommended_action: "kill".to_string(),
            proc_type: None,
            comm: "p".to_string(),
            predicted_at: Utc::now(),
            ground_truth: Some(GroundTruth::UserKilled),
            resolved_at: Some(Utc::now()),
            exit_code: None,
            exit_signal: None,
            outcome_source: None,
            host_id: Some("node-3".to_string()),
        };
        let cal = record.to_calibration_data().unwrap();
        assert_eq!(cal.host_id.as_deref(), Some("node-3"));
        assert!(cal.actual); // UserKilled is abandoned
    }
}
