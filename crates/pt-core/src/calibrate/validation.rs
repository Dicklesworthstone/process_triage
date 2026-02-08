//! Model validation framework for shadow mode.
//!
//! Tracks predictions against ground truth outcomes to evaluate model accuracy.
//! When a process eventually terminates (user kill, natural exit, crash, etc.),
//! this module compares the prediction with the actual outcome.
//!
//! # Ground Truth Sources
//!
//! - **User action**: Confirmed kill (validates prediction) or spare (rejects it)
//! - **Natural exit**: Normal completion after expected lifetime
//! - **Crash**: Non-zero exit code or signal
//! - **Timeout**: Process exceeded maximum tracking window without resolution
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
use std::collections::HashMap;

use super::{
    bias::{analyze_bias, BiasAnalysis},
    metrics::{compute_metrics, CalibrationMetrics},
    report::CalibrationReport,
    CalibrationData, CalibrationError, CalibrationQuality,
};

/// How a process actually terminated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GroundTruth {
    /// User confirmed kill via pt (prediction validated).
    UserKilled,
    /// User explicitly spared the process (prediction rejected for kill recs).
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
}

impl GroundTruth {
    /// Whether this ground truth indicates the process was truly abandoned.
    ///
    /// Conservative: only `UserKilled` and `ExternalKill` count as confirmed
    /// abandoned. `Crash` is ambiguous (could be a bug in a useful process).
    pub fn is_abandoned(&self) -> bool {
        matches!(self, GroundTruth::UserKilled | GroundTruth::ExternalKill)
    }

    /// Whether this outcome is resolved (not pending).
    pub fn is_resolved(&self) -> bool {
        !matches!(self, GroundTruth::StillRunning | GroundTruth::Expired)
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
    /// Ground truth outcome (None if not yet resolved).
    #[serde(default)]
    pub ground_truth: Option<GroundTruth>,
    /// Timestamp of resolution (None if not yet resolved).
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
    /// Convert to CalibrationData if resolved.
    pub fn to_calibration_data(&self) -> Option<CalibrationData> {
        let gt = self.ground_truth?;
        if !gt.is_resolved() {
            return None;
        }
        Some(CalibrationData {
            predicted: self.predicted_abandoned,
            actual: gt.is_abandoned(),
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
    /// Resolved predictions.
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
    /// Predictions with resolved outcomes.
    pub resolved_predictions: usize,
    /// Predictions still pending.
    pub pending_predictions: usize,
    /// Overall calibration metrics (from resolved data).
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

    /// Get resolved records only.
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
    pub fn from_shadow_observations(observations: &[Observation], threshold: f64) -> Self {
        let mut engine = ValidationEngine::new(threshold);
        let mut ordered: Vec<&Observation> = observations.iter().collect();
        ordered.sort_by_key(|a| a.timestamp);

        for obs in ordered {
            let exit_event = obs
                .events
                .iter()
                .find(|event| event.event_type == EventType::ProcessExit);

            if let Some(exit_event) = exit_event {
                if !engine.has_unresolved_identity(&obs.identity_hash) {
                    let comm = extract_comm_from_events(&obs.events)
                        .unwrap_or_else(|| "unknown".to_string());
                    engine.upsert_prediction(
                        obs.identity_hash.clone(),
                        obs.pid,
                        obs.belief.p_abandoned as f64,
                        obs.belief.recommendation.clone(),
                        None,
                        comm,
                        None,
                        obs.timestamp,
                    );
                }

                let (ground_truth, exit_code, exit_signal, outcome_source) =
                    map_exit_event(exit_event);
                engine.record_outcome_with_source(
                    &obs.identity_hash,
                    ground_truth,
                    exit_code,
                    exit_signal,
                    outcome_source,
                );
                continue;
            }

            let comm =
                extract_comm_from_events(&obs.events).unwrap_or_else(|| "unknown".to_string());
            engine.upsert_prediction(
                obs.identity_hash.clone(),
                obs.pid,
                obs.belief.p_abandoned as f64,
                obs.belief.recommendation.clone(),
                None,
                comm,
                None,
                obs.timestamp,
            );
        }

        engine
    }

    /// Convert resolved records to calibration data.
    fn to_calibration_data(&self) -> Vec<CalibrationData> {
        self.records
            .iter()
            .filter_map(|r| r.to_calibration_data())
            .collect()
    }

    fn has_unresolved_identity(&self, identity_hash: &str) -> bool {
        self.records
            .iter()
            .rev()
            .any(|r| r.identity_hash == identity_hash && r.ground_truth.is_none())
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
    ) {
        if let Some(record) = self
            .records
            .iter_mut()
            .rev()
            .find(|r| r.identity_hash == identity_hash && r.ground_truth.is_none())
        {
            record.pid = pid;
            record.predicted_abandoned = predicted_abandoned;
            record.recommended_action = recommended_action;
            record.proc_type = proc_type;
            record.comm = comm;
            record.predicted_at = predicted_at;
            record.host_id = host_id;
            return;
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

        let metrics = if cal_data.len() >= 10 {
            compute_metrics(&cal_data, self.threshold).ok()
        } else {
            None
        };

        let quality = metrics
            .as_ref()
            .map(|m| CalibrationQuality::from_metrics(m.ece, m.brier_score));

        let bias = if cal_data.len() >= 20 {
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
            metrics,
            quality,
            by_category,
            bias,
            top_false_positives,
            top_false_negatives,
            recommendations,
        })
    }

    /// Generate a full calibration report from resolved data.
    pub fn calibration_report(&self) -> Result<CalibrationReport, CalibrationError> {
        let cal_data = self.to_calibration_data();
        if cal_data.is_empty() {
            return Err(CalibrationError::NoData);
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
                        r.proc_type.as_deref() == Some(&category)
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
        if exit_signal.is_some() || exit_code.unwrap_or(0) != 0 {
            ground_truth = Some(GroundTruth::Crash);
            if outcome_source.is_none() {
                outcome_source = Some("shadow:exit_status".to_string());
            }
        } else {
            ground_truth = Some(GroundTruth::NormalExit);
        }
    }

    (
        ground_truth.unwrap_or(GroundTruth::NormalExit),
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

        // Record outcomes.
        engine.record_outcome("hash_a", GroundTruth::UserKilled, None, None);
        engine.record_outcome("hash_b", GroundTruth::NormalExit, None, Some(0));
        engine.record_outcome("hash_c", GroundTruth::NormalExit, None, Some(0)); // false positive
        engine.record_outcome("hash_d", GroundTruth::ExternalKill, None, None); // false negative
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
        assert!(GroundTruth::ExternalKill.is_abandoned());
        assert!(!GroundTruth::NormalExit.is_abandoned());
        assert!(!GroundTruth::Crash.is_abandoned());
        assert!(!GroundTruth::UserSpared.is_abandoned());
        assert!(!GroundTruth::StillRunning.is_abandoned());
    }

    #[test]
    fn test_ground_truth_is_resolved() {
        assert!(GroundTruth::UserKilled.is_resolved());
        assert!(GroundTruth::NormalExit.is_resolved());
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
        // hash_b: predicted 0.3, actual=false (NormalExit is not abandoned)
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
        let resolved = engine.resolved_records();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].exit_code, Some(1));
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
                GroundTruth::NormalExit
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

        // hash_c (pytest) is a false positive: predicted kill but NormalExit.
        assert!(!report.top_false_positives.is_empty());
        let fp = &report.top_false_positives[0];
        assert_eq!(fp.pattern, "pytest");
        assert_eq!(fp.count, 1);

        // hash_d (vite) is a false negative: predicted keep but ExternalKill.
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
                p_abandoned: 0.9,
                recommendation: "kill".to_string(),
                ..BeliefState::default()
            },
        };

        let engine = ValidationEngine::from_shadow_observations(&[obs1, obs2], 0.5);
        assert_eq!(engine.pending_records().len(), 1);
        let record = engine.pending_records()[0];
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
                recommendation: "kill".to_string(),
                ..BeliefState::default()
            },
        };

        let engine = ValidationEngine::from_shadow_observations(&[obs1, obs2], 0.5);
        let resolved = engine.resolved_records();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].ground_truth, Some(GroundTruth::NormalExit));
        assert_eq!(resolved[0].comm, "worker");
        assert_eq!(
            resolved[0].outcome_source.as_deref(),
            Some("shadow:missing")
        );
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
        assert!(GroundTruth::ExternalKill.is_abandoned());
        assert!(!GroundTruth::UserSpared.is_abandoned());
        assert!(!GroundTruth::NormalExit.is_abandoned());
        assert!(!GroundTruth::Crash.is_abandoned());
        assert!(!GroundTruth::SystemShutdown.is_abandoned());
        assert!(!GroundTruth::StillRunning.is_abandoned());
        assert!(!GroundTruth::Expired.is_abandoned());
    }

    #[test]
    fn ground_truth_is_resolved_complete() {
        assert!(GroundTruth::UserKilled.is_resolved());
        assert!(GroundTruth::UserSpared.is_resolved());
        assert!(GroundTruth::NormalExit.is_resolved());
        assert!(GroundTruth::Crash.is_resolved());
        assert!(GroundTruth::ExternalKill.is_resolved());
        assert!(GroundTruth::SystemShutdown.is_resolved());
        assert!(!GroundTruth::StillRunning.is_resolved());
        assert!(!GroundTruth::Expired.is_resolved());
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
        assert_eq!(gt, GroundTruth::NormalExit);
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
        // No exit_code or signal, defaults to NormalExit
        assert_eq!(gt, GroundTruth::NormalExit);
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
        assert!(result.is_err());
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
