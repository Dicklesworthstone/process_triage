//! Independent review and paired probability evaluation of private recordings.
//!
//! Labels bind to the complete captured input, not merely a PID or command
//! pattern. Both configurations use the shared production scorer. This module
//! evaluates P(abandoned or zombie), never final action recommendations, and
//! cannot train a model or execute a process action.

use super::snapshot::{
    replay_scores, ReplayError, ReplayScoreResult, ReplayScoreStatus, ReplayScoringReport,
    ReplaySnapshot,
};
use crate::calibrate::{
    compute_metrics, CalibrationCurve, CalibrationData, CalibrationError, CalibrationMetrics,
    MIN_LABELS_PER_CLASS,
};
use crate::collect::ProcessRecord;
use crate::config::Policy;
use crate::scoring::Scorer;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use thiserror::Error;

const REVIEW_SCHEMA_VERSION: &str = "1.0.0";
const EVALUATION_SCHEMA_VERSION: &str = "1.0.0";

#[derive(Debug, Error)]
pub enum ReplayEvaluationError {
    #[error("replay review I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("replay review JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid replay review: {0}")]
    InvalidReview(String),
    #[error("invalid replay evaluation: {0}")]
    InvalidEvaluation(String),
    #[error(transparent)]
    Replay(#[from] ReplayError),
    #[error(transparent)]
    Calibration(#[from] CalibrationError),
}

/// An operator declaration, not proof that a host was excluded from training.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewSplit {
    Training,
    Holdout,
}

/// The binary event scored here is abandonment or zombie state. These are not
/// four-class labels and do not authorize any action on the recorded process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewVerdict {
    /// The process is not abandoned or a zombie, including useful-but-bad work.
    Useful,
    /// The process is abandoned or a zombie.
    Abandoned,
}

/// One census row for independent human review. Command text is deliberately
/// retained as a review aid, so the review file is private, not a redacted export.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessReview {
    pub pid: u32,
    pub start_id: String,
    pub uid: u32,
    #[serde(deserialize_with = "Option::deserialize")]
    pub pgid: Option<u32>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub sid: Option<u32>,
    pub comm: String,
    pub cmd: String,
    #[serde(deserialize_with = "Option::deserialize")]
    pub verdict: Option<ReviewVerdict>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub reviewer: Option<String>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub reviewed_at: Option<String>,
    #[serde(deserialize_with = "Option::deserialize")]
    pub rationale: Option<String>,
}

impl ProcessReview {
    fn unreviewed(process: &ProcessRecord) -> Self {
        Self {
            pid: process.pid.0,
            start_id: process.start_id.to_string(),
            uid: process.uid,
            pgid: process.pgid,
            sid: process.sid,
            comm: process.comm.clone(),
            cmd: process.cmd.clone(),
            verdict: None,
            reviewer: None,
            reviewed_at: None,
            rationale: None,
        }
    }

    fn matches_record(&self, process: &ProcessRecord) -> bool {
        self.pid == process.pid.0
            && self.start_id == process.start_id.0
            && self.uid == process.uid
            && self.pgid == process.pgid
            && self.sid == process.sid
            && self.comm == process.comm
            && self.cmd == process.cmd
    }
}

/// A complete review template bound to one canonical, deserialized snapshot.
/// An explicit null verdict remains unlabeled and never becomes a negative.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewLabels {
    pub schema_version: String,
    pub snapshot_sha256: String,
    pub snapshot_name: String,
    pub host_id: String,
    pub split: ReviewSplit,
    pub created_at: String,
    pub processes: Vec<ProcessReview>,
}

impl ReviewLabels {
    /// Save a new private file. Existing files and symlinks are never overwritten;
    /// a failed write is retained for inspection rather than removed silently.
    pub fn save_new_private(&self, path: &Path) -> Result<(), ReplayEvaluationError> {
        use std::io::Write;

        self.validate_structure()?;
        let json = serde_json::to_vec_pretty(self)?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        file.write_all(&json)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        Ok(())
    }

    fn validate_structure(&self) -> Result<(), ReplayEvaluationError> {
        if self.schema_version != REVIEW_SCHEMA_VERSION {
            return Err(ReplayEvaluationError::InvalidReview(format!(
                "unsupported review schema {}; expected {REVIEW_SCHEMA_VERSION}",
                self.schema_version
            )));
        }
        if self.snapshot_sha256.len() != 64
            || !self
                .snapshot_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(ReplayEvaluationError::InvalidReview(
                "snapshot_sha256 must be a lowercase SHA-256 digest".to_string(),
            ));
        }
        if self.host_id.trim().is_empty() {
            return Err(ReplayEvaluationError::InvalidReview(
                "host_id must identify the declared review cohort".to_string(),
            ));
        }
        parse_review_time(&self.created_at, "created_at")?;
        let mut seen = HashSet::new();
        for process in &self.processes {
            if !seen.insert(process.pid) {
                return Err(ReplayEvaluationError::InvalidReview(format!(
                    "duplicate review row for PID {}",
                    process.pid
                )));
            }
            if process.start_id.is_empty() {
                return Err(ReplayEvaluationError::InvalidReview(format!(
                    "empty recorded start identity for PID {}",
                    process.pid
                )));
            }
            if process.verdict.is_some() {
                if process
                    .reviewer
                    .as_ref()
                    .is_none_or(|reviewer| reviewer.trim().is_empty())
                    || process
                        .rationale
                        .as_ref()
                        .is_none_or(|rationale| rationale.trim().is_empty())
                {
                    return Err(ReplayEvaluationError::InvalidReview(format!(
                        "reviewed PID {} requires a reviewer and an independent evidence rationale",
                        process.pid
                    )));
                }
                let reviewed_at = process.reviewed_at.as_ref().ok_or_else(|| {
                    ReplayEvaluationError::InvalidReview(format!(
                        "reviewed PID {} requires reviewed_at",
                        process.pid
                    ))
                })?;
                parse_review_time(reviewed_at, "reviewed_at")?;
            } else if process.reviewer.is_some()
                || process.reviewed_at.is_some()
                || process.rationale.is_some()
            {
                return Err(ReplayEvaluationError::InvalidReview(format!(
                    "unlabeled PID {} must leave verdict and review provenance null",
                    process.pid
                )));
            }
        }
        Ok(())
    }
}

fn parse_review_time(value: &str, field: &str) -> Result<DateTime<Utc>, ReplayEvaluationError> {
    DateTime::parse_from_rfc3339(value)
        .map(|time| time.with_timezone(&Utc))
        .map_err(|error| {
            ReplayEvaluationError::InvalidReview(format!("{field} must be RFC 3339: {error}"))
        })
}

fn canonical_sha256(value: &impl Serialize) -> Result<String, ReplayEvaluationError> {
    let mut value = serde_json::to_value(value)?;
    crate::session::snapshot_persist::canonicalize_json(&mut value);
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&value)?)))
}

fn validate_census(snapshot: &ReplaySnapshot) -> Result<(), ReplayEvaluationError> {
    if snapshot.processes.is_empty()
        || snapshot.scan_metadata.process_count != snapshot.processes.len()
    {
        return Err(ReplayEvaluationError::InvalidEvaluation(
            "snapshot must retain a nonempty complete recorded census".to_string(),
        ));
    }
    let mut seen = HashSet::new();
    for process in &snapshot.processes {
        if !seen.insert(process.pid.0) {
            return Err(ReplayEvaluationError::InvalidEvaluation(format!(
                "snapshot has duplicate PID {}",
                process.pid.0
            )));
        }
    }
    Ok(())
}

/// Prepare every captured identity for review without assigning any verdict.
/// This is a private review aid; no model prediction supplies a label.
pub fn make_review_template(
    snapshot: &ReplaySnapshot,
    host_id: &str,
    split: ReviewSplit,
) -> Result<ReviewLabels, ReplayEvaluationError> {
    validate_census(snapshot)?;
    let labels = ReviewLabels {
        schema_version: REVIEW_SCHEMA_VERSION.to_string(),
        snapshot_sha256: canonical_sha256(snapshot)?,
        snapshot_name: snapshot.name.clone(),
        host_id: host_id.to_string(),
        split,
        created_at: Utc::now().to_rfc3339(),
        processes: snapshot
            .processes
            .iter()
            .map(ProcessReview::unreviewed)
            .collect(),
    };
    labels.validate_structure()?;
    Ok(labels)
}

/// Read a private review file. Its capture and identities are checked again
/// against the actual snapshot by `evaluate_pair` before either model is scored.
pub fn read_review_labels(path: &Path) -> Result<ReviewLabels, ReplayEvaluationError> {
    let labels: ReviewLabels = serde_json::from_slice(&std::fs::read(path)?)?;
    labels.validate_structure()?;
    Ok(labels)
}

fn validate_labels<'a>(
    snapshot: &ReplaySnapshot,
    labels: &'a ReviewLabels,
) -> Result<BTreeMap<u32, &'a ProcessReview>, ReplayEvaluationError> {
    validate_census(snapshot)?;
    labels.validate_structure()?;
    if labels.snapshot_sha256 != canonical_sha256(snapshot)?
        || labels.snapshot_name != snapshot.name
    {
        return Err(ReplayEvaluationError::InvalidReview(
            "review belongs to a different capture; snapshot digest or name does not match"
                .to_string(),
        ));
    }
    if labels.processes.len() != snapshot.processes.len() {
        return Err(ReplayEvaluationError::InvalidReview(
            "review must retain exactly one row for every recorded process, including unlabeled rows"
                .to_string(),
        ));
    }
    let by_pid: BTreeMap<_, _> = labels
        .processes
        .iter()
        .map(|process| (process.pid, process))
        .collect();
    for process in &snapshot.processes {
        if !by_pid
            .get(&process.pid.0)
            .is_some_and(|review| review.matches_record(process))
        {
            return Err(ReplayEvaluationError::InvalidReview(format!(
                "missing or mismatched identity or command text for recorded PID {}",
                process.pid.0
            )));
        }
    }
    Ok(by_pid)
}

/// Population counts for one configuration, before restricting to paired labels.
#[derive(Debug, Clone, Serialize)]
pub struct EvaluationSide {
    pub configuration_sha256: String,
    pub evaluated_at: String,
    pub population_size: usize,
    pub scored_count: usize,
    pub protected_count: usize,
    pub too_young_count: usize,
    pub unavailable_count: usize,
    pub reviewed_scored_count: usize,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct EvaluationCoverage {
    pub population_size: usize,
    pub reviewed_count: usize,
    pub unlabeled_count: usize,
    pub useful_count: usize,
    pub abandoned_count: usize,
    pub paired_count: usize,
    pub paired_useful_count: usize,
    pub paired_abandoned_count: usize,
    /// Reviewed rows scored only by the baseline: candidate coverage was lost.
    pub baseline_only_count: usize,
    /// Reviewed rows scored only by the candidate: absent from paired metrics.
    pub candidate_only_count: usize,
    pub neither_scored_count: usize,
}

/// Descriptive probability metrics from the existing calibration engine.
/// No threshold-based precision/recall is presented as an action metric.
#[derive(Debug, Clone, Serialize)]
pub struct ProbabilityMetrics {
    pub brier_score: f64,
    pub log_loss: f64,
    pub ece: f64,
    pub mce: f64,
    pub auc_roc: f64,
    pub curve: CalibrationCurve,
}

impl ProbabilityMetrics {
    fn from_calibration(metrics: CalibrationMetrics, data: &[CalibrationData]) -> Self {
        Self {
            brier_score: metrics.brier_score,
            log_loss: metrics.log_loss,
            ece: metrics.ece,
            mce: metrics.mce,
            auc_roc: metrics.auc_roc,
            curve: CalibrationCurve::from_data(data, 10),
        }
    }
}

/// Candidate minus baseline on exactly the same reviewed process identities.
#[derive(Debug, Clone, Serialize)]
pub struct ProbabilityMetricDelta {
    pub brier_score: f64,
    pub log_loss: f64,
    pub ece: f64,
    pub mce: f64,
    pub auc_roc: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct PairedProbabilityMetrics {
    pub sample_count: usize,
    pub useful_count: usize,
    pub abandoned_count: usize,
    pub baseline: ProbabilityMetrics,
    pub candidate: ProbabilityMetrics,
    pub candidate_minus_baseline: ProbabilityMetricDelta,
}

#[derive(Debug, Clone, Serialize)]
pub struct PairedProcessScore {
    pub pid: u32,
    pub start_id: String,
    pub uid: u32,
    pub comm: String,
    pub verdict: Option<ReviewVerdict>,
    pub baseline_status: ReplayScoreStatus,
    pub baseline_reason: Option<String>,
    pub baseline_probability: Option<f64>,
    pub candidate_status: ReplayScoreStatus,
    pub candidate_reason: Option<String>,
    pub candidate_probability: Option<f64>,
    /// Eligible for the common metric sample; metrics still require class support.
    pub paired_sample: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PairedEvaluationReport {
    pub schema_version: String,
    pub engine_version: &'static str,
    pub snapshot_sha256: String,
    pub labels_sha256: String,
    pub snapshot_name: String,
    pub recorded_at: String,
    pub evaluated_at: String,
    pub host_id: String,
    pub split: ReviewSplit,
    pub scoring_only: bool,
    pub baseline: EvaluationSide,
    pub candidate: EvaluationSide,
    pub coverage: EvaluationCoverage,
    pub paired_metrics: Option<PairedProbabilityMetrics>,
    pub metrics_unavailable_reason: Option<String>,
    pub processes: Vec<PairedProcessScore>,
    pub warnings: Vec<String>,
    pub limitations: Vec<String>,
}

fn configuration_fingerprint(
    scorer: &Scorer,
    policy: &Policy,
) -> Result<String, ReplayEvaluationError> {
    let content = serde_json::json!({
        "priors": scorer.priors,
        "policy": policy,
        "fast_path": scorer.fast_path,
        "signatures": scorer.signatures.signatures(),
        "decisions": scorer.decisions.evaluation_snapshot()?,
    });
    canonical_sha256(&content)
}

fn summarize_side(
    report: &ReplayScoringReport,
    configuration_sha256: String,
    reviewed_scored_count: usize,
    evaluated_at: &str,
) -> EvaluationSide {
    EvaluationSide {
        configuration_sha256,
        evaluated_at: evaluated_at.to_string(),
        population_size: report.population_size,
        scored_count: report.scored_count,
        protected_count: report.protected_count,
        too_young_count: report.too_young_count,
        unavailable_count: report.unavailable_count,
        reviewed_scored_count,
    }
}

fn recorded_probability(row: &ReplayScoreResult) -> Result<Option<f64>, ReplayEvaluationError> {
    if row.status != ReplayScoreStatus::Scored {
        return Ok(None);
    }
    let probability = row
        .posterior
        .as_ref()
        .map(|posterior| posterior.abandonment_probability())
        .filter(|probability| probability.is_finite() && (0.0..=1.0).contains(probability));
    if probability.is_none() {
        return Err(ReplayEvaluationError::InvalidEvaluation(format!(
            "shared scorer returned an invalid probability for PID {}",
            row.pid
        )));
    }
    Ok(probability)
}

fn paired_probability_metrics(
    baseline: &[CalibrationData],
    candidate: &[CalibrationData],
) -> Result<PairedProbabilityMetrics, ReplayEvaluationError> {
    let baseline_metrics = ProbabilityMetrics::from_calibration(
        compute_metrics(baseline, 0.5)?,
        baseline,
    );
    let candidate_metrics = ProbabilityMetrics::from_calibration(
        compute_metrics(candidate, 0.5)?,
        candidate,
    );
    let abandoned_count = baseline.iter().filter(|datum| datum.actual).count();
    let candidate_minus_baseline = ProbabilityMetricDelta {
        brier_score: candidate_metrics.brier_score - baseline_metrics.brier_score,
        log_loss: candidate_metrics.log_loss - baseline_metrics.log_loss,
        ece: candidate_metrics.ece - baseline_metrics.ece,
        mce: candidate_metrics.mce - baseline_metrics.mce,
        auc_roc: candidate_metrics.auc_roc - baseline_metrics.auc_roc,
    };
    Ok(PairedProbabilityMetrics {
        sample_count: baseline.len(),
        useful_count: baseline.len() - abandoned_count,
        abandoned_count,
        baseline: baseline_metrics,
        candidate: candidate_metrics,
        candidate_minus_baseline,
    })
}

/// Score one immutable capture under both loaded configurations in this call.
/// Only independently reviewed identities scored by both enter either metric
/// sample. Changed coverage remains visible even when paired losses improve.
pub fn evaluate_pair(
    snapshot: &ReplaySnapshot,
    labels: &ReviewLabels,
    baseline_scorer: &Scorer,
    baseline_policy: &Policy,
    candidate_scorer: &Scorer,
    candidate_policy: &Policy,
) -> Result<PairedEvaluationReport, ReplayEvaluationError> {
    let by_pid = validate_labels(snapshot, labels)?;
    let baseline_fingerprint = configuration_fingerprint(baseline_scorer, baseline_policy)?;
    let candidate_fingerprint = configuration_fingerprint(candidate_scorer, candidate_policy)?;
    let evaluated_at = Utc::now();
    let baseline_scorer = baseline_scorer.clone().with_evaluation_time(evaluated_at);
    let candidate_scorer = candidate_scorer.clone().with_evaluation_time(evaluated_at);
    let baseline = replay_scores(snapshot, &baseline_scorer, baseline_policy)?;
    let candidate = replay_scores(snapshot, &candidate_scorer, candidate_policy)?;
    if baseline.processes.len() != snapshot.processes.len()
        || candidate.processes.len() != snapshot.processes.len()
    {
        return Err(ReplayEvaluationError::InvalidEvaluation(
            "shared scoring did not retain the complete recorded census".to_string(),
        ));
    }
    let mut coverage = EvaluationCoverage {
        population_size: snapshot.processes.len(),
        ..Default::default()
    };
    let mut baseline_data = Vec::new();
    let mut candidate_data = Vec::new();
    let mut processes = Vec::with_capacity(snapshot.processes.len());
    for ((process, baseline_row), candidate_row) in snapshot
        .processes
        .iter()
        .zip(&baseline.processes)
        .zip(&candidate.processes)
    {
        for row in [baseline_row, candidate_row] {
            if row.pid != process.pid.0
                || row.start_id != process.start_id.0
                || row.uid != process.uid
            {
                return Err(ReplayEvaluationError::InvalidEvaluation(format!(
                    "shared scoring changed the identity or order of PID {}",
                    process.pid.0
                )));
            }
        }
        let review = by_pid[&process.pid.0];
        let baseline_probability = recorded_probability(baseline_row)?;
        let candidate_probability = recorded_probability(candidate_row)?;
        let paired_sample = review.verdict.is_some()
            && baseline_probability.is_some()
            && candidate_probability.is_some();
        if let Some(verdict) = review.verdict {
            coverage.reviewed_count += 1;
            match verdict {
                ReviewVerdict::Useful => coverage.useful_count += 1,
                ReviewVerdict::Abandoned => coverage.abandoned_count += 1,
            }
            match (baseline_probability, candidate_probability) {
                (Some(baseline), Some(candidate)) => {
                    coverage.paired_count += 1;
                    let actual = verdict == ReviewVerdict::Abandoned;
                    if actual {
                        coverage.paired_abandoned_count += 1;
                    } else {
                        coverage.paired_useful_count += 1;
                    }
                    let datum = |predicted| CalibrationData {
                        predicted,
                        actual,
                        proc_type: None,
                        score: Some(predicted * 100.0),
                        timestamp: None,
                        host_id: Some(labels.host_id.clone()),
                    };
                    baseline_data.push(datum(baseline));
                    candidate_data.push(datum(candidate));
                }
                (Some(_), None) => coverage.baseline_only_count += 1,
                (None, Some(_)) => coverage.candidate_only_count += 1,
                (None, None) => coverage.neither_scored_count += 1,
            }
        } else {
            coverage.unlabeled_count += 1;
        }
        processes.push(PairedProcessScore {
            pid: process.pid.0,
            start_id: process.start_id.to_string(),
            uid: process.uid,
            comm: process.comm.clone(),
            verdict: review.verdict,
            baseline_status: baseline_row.status,
            baseline_reason: baseline_row.reason.clone(),
            baseline_probability,
            candidate_status: candidate_row.status,
            candidate_reason: candidate_row.reason.clone(),
            candidate_probability,
            paired_sample,
        });
    }

    let supported = coverage.paired_useful_count >= MIN_LABELS_PER_CLASS
        && coverage.paired_abandoned_count >= MIN_LABELS_PER_CLASS;
    let (paired_metrics, metrics_unavailable_reason) = if supported {
        (
            Some(paired_probability_metrics(&baseline_data, &candidate_data)?),
            None,
        )
    } else {
        (
            None,
            Some(format!(
                "paired metrics require at least {MIN_LABELS_PER_CLASS} reviewed useful and {MIN_LABELS_PER_CLASS} reviewed abandoned identities scored by both configurations; found {} useful and {} abandoned",
                coverage.paired_useful_count, coverage.paired_abandoned_count
            )),
        )
    };
    let mut warnings = Vec::new();
    if coverage.baseline_only_count > 0 {
        warnings.push(format!(
            "Candidate coverage dropped: {} reviewed identities scored by the baseline are not scored by the candidate. Paired losses exclude these identities and cannot establish an overall improvement.",
            coverage.baseline_only_count
        ));
    }
    if coverage.candidate_only_count > 0 || coverage.neither_scored_count > 0 {
        warnings.push(format!(
            "Paired coverage is incomplete: {} reviewed identities are candidate-only and {} are unscored by both configurations.",
            coverage.candidate_only_count, coverage.neither_scored_count
        ));
    }
    if coverage.unlabeled_count > 0 {
        warnings.push(format!(
            "{} recorded identities remain unlabeled and do not contribute a positive or negative outcome.",
            coverage.unlabeled_count
        ));
    }
    let evaluated_at = evaluated_at.to_rfc3339();
    let baseline_side = summarize_side(
        &baseline,
        baseline_fingerprint,
        coverage.paired_count + coverage.baseline_only_count,
        &evaluated_at,
    );
    let candidate_side = summarize_side(
        &candidate,
        candidate_fingerprint,
        coverage.paired_count + coverage.candidate_only_count,
        &evaluated_at,
    );
    Ok(PairedEvaluationReport {
        schema_version: EVALUATION_SCHEMA_VERSION.to_string(),
        engine_version: env!("CARGO_PKG_VERSION"),
        snapshot_sha256: labels.snapshot_sha256.clone(),
        labels_sha256: canonical_sha256(labels)?,
        snapshot_name: snapshot.name.clone(),
        recorded_at: snapshot.context.recorded_at.clone(),
        evaluated_at,
        host_id: labels.host_id.clone(),
        split: labels.split,
        scoring_only: true,
        baseline: baseline_side,
        candidate: candidate_side,
        coverage,
        paired_metrics,
        metrics_unavailable_reason,
        processes,
        warnings,
        limitations: vec![
            "Probability evaluation only: no final action decisions, kill/review precision, zombie-routing metric, execution or automatic training."
                .to_string(),
            "Both configurations use one shared evaluation time for learned-verdict decay. Historical predictions or training configurations are not reconstructed."
                .to_string(),
            "Host and training/holdout split are operator declarations. Label independence and exclusion from training are not verified."
                .to_string(),
            "Paired metrics cover only reviewed identities scored by both configurations. Unlabeled and unscored processes are retained in coverage and must not be interpreted as correct negatives."
                .to_string(),
            "Descriptive metrics on one reviewed capture do not establish empirical safety, generalization, an FDR guarantee or an independently calibrated model."
                .to_string(),
            "Captured placement and derived provenance are reused; raw collectors and provenance classifiers are not rerun."
                .to_string(),
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::cgroup::CgroupRole;
    use crate::config::Priors;
    use crate::decision::decision_store::{DecisionStore, Verdict};
    use crate::inference::{Evidence, FastPathConfig};
    use crate::mock_process::{MockProcessBuilder, MockScanBuilder};
    use crate::replay::{
        record_snapshot, DeepSignalRecord, ReplayProcessInputs, ReplayScoringContext,
    };
    use crate::supervision::signature::{SignatureDatabase, SupervisorSignature};
    use crate::supervision::SupervisorCategory;
    use pt_common::{IdentityQuality, ProcessIdentity};
    use std::collections::{BTreeSet, HashMap};
    use std::path::PathBuf;

    fn scorer() -> Scorer {
        Scorer::new(
            Priors::default(),
            DecisionStore::default(),
            SignatureDatabase::new(),
            FastPathConfig::disabled(),
        )
    }

    fn policy() -> Policy {
        let mut policy = Policy::default();
        policy.guardrails.min_process_age_seconds = 0;
        policy.guardrails.builtin_protection = false;
        policy.guardrails.protected_users.clear();
        policy.guardrails.protected_patterns.clear();
        policy.guardrails.never_kill_pid.clear();
        policy.guardrails.never_kill_ppid.clear();
        policy
    }

    /// Synthetic observations exercise evaluator contracts only, not fleet quality.
    fn snapshot(count: u32) -> ReplaySnapshot {
        let scorer = scorer();
        let processes = (100..100 + count)
            .map(|pid| {
                MockProcessBuilder::new()
                    .pid(pid)
                    .ppid(7)
                    .pgid(pid)
                    .sid(pid)
                    .uid(1000)
                    .user("alice")
                    .comm("worker")
                    .cmd("worker --job")
                    .elapsed_secs(7200)
                    .build()
            })
            .collect::<Vec<_>>();
        let scan = MockScanBuilder::new()
            .platform(std::env::consts::OS)
            .with_processes(processes)
            .build();
        let mut snapshot = record_snapshot(&scan, Some("evaluation-contract-fixture")).unwrap();
        let inputs = snapshot
            .processes
            .iter()
            .map(|process| {
                let observations = scorer.recorded_observations(process, None);
                #[cfg(target_os = "linux")]
                let observations = {
                    let mut observations = observations;
                    observations.provenance = Some(crate::scoring::derive_provenance_adjustment(
                        process.pid.0,
                        &crate::scoring::ProvenanceInferenceBundle {
                            resource_graph: crate::collect::SharedResourceGraph::default(),
                            lineages: HashMap::new(),
                            children: HashMap::new(),
                            network_errors: HashMap::new(),
                        },
                    ));
                    observations
                };
                (
                    process.pid.0,
                    ReplayProcessInputs {
                        identity: ProcessIdentity::full(
                            process.pid.0,
                            process.start_id.clone(),
                            process.uid,
                            process.pgid,
                            process.sid,
                            IdentityQuality::Full,
                        ),
                        cgroup_role: Some(CgroupRole::LoginSession),
                        observations: Some(observations),
                        unavailable_reason: None,
                    },
                )
            })
            .collect();
        snapshot.scoring_context = Some(ReplayScoringContext {
            schema_version: 1,
            platform: std::env::consts::OS.to_string(),
            requested_window_ms: 0,
            invoker_chain: BTreeSet::new(),
            processes: inputs,
        });
        snapshot
    }

    fn review(row: &mut ProcessReview, verdict: ReviewVerdict) {
        row.verdict = Some(verdict);
        row.reviewer = Some("contract-test-reviewer".to_string());
        row.reviewed_at = Some("2026-11-09T00:00:00Z".to_string());
        row.rationale = Some("Synthetic label for evaluator contract arithmetic only".to_string());
    }

    fn balanced_labels(snapshot: &ReplaySnapshot) -> ReviewLabels {
        let mut labels =
            make_review_template(snapshot, "contract-host", ReviewSplit::Holdout).unwrap();
        for (index, process) in labels.processes.iter_mut().enumerate() {
            review(
                process,
                if index % 2 == 0 {
                    ReviewVerdict::Useful
                } else {
                    ReviewVerdict::Abandoned
                },
            );
        }
        labels
    }

    fn evidence_dir(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "pt-replay-evaluation-{name}-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&path).unwrap();
        eprintln!("retained replay evaluation evidence: {}", path.display());
        path
    }

    #[test]
    fn review_template_preserves_every_identity_without_inventing_labels() {
        let snapshot = snapshot(3);
        let labels =
            make_review_template(&snapshot, "declared-host", ReviewSplit::Training).unwrap();
        assert_eq!(labels.processes.len(), snapshot.processes.len());
        assert_eq!(labels.host_id, "declared-host");
        assert_eq!(labels.split, ReviewSplit::Training);
        assert_eq!(labels.snapshot_sha256.len(), 64);
        for (review, recorded) in labels.processes.iter().zip(&snapshot.processes) {
            assert!(review.matches_record(recorded));
            assert!(review.verdict.is_none());
            assert!(review.reviewer.is_none());
            assert!(review.reviewed_at.is_none());
            assert!(review.rationale.is_none());
        }
        let model = scorer();
        let report =
            evaluate_pair(&snapshot, &labels, &model, &policy(), &model, &policy()).unwrap();
        assert_eq!(report.coverage.population_size, 3);
        assert_eq!(report.coverage.unlabeled_count, 3);
        assert_eq!(report.coverage.reviewed_count, 0);
        assert!(report.paired_metrics.is_none());
        assert!(report.metrics_unavailable_reason.is_some());
        assert!(report.processes.iter().all(|row| !row.paired_sample));
    }

    #[test]
    fn capture_binding_is_canonical_and_covers_observations_not_just_pids() {
        let mut snapshot = snapshot(2);
        snapshot.deep_signals = HashMap::from([
            (
                100,
                DeepSignalRecord {
                    net_active: Some(true),
                    io_active: None,
                },
            ),
            (
                101,
                DeepSignalRecord {
                    net_active: None,
                    io_active: Some(false),
                },
            ),
        ]);
        let labels = balanced_labels(&snapshot);
        let mut reordered: ReplaySnapshot =
            serde_json::from_slice(&serde_json::to_vec_pretty(&snapshot).unwrap()).unwrap();
        reordered.deep_signals = [101, 100]
            .into_iter()
            .map(|pid| (pid, snapshot.deep_signals[&pid].clone()))
            .collect();
        assert_eq!(
            canonical_sha256(&snapshot).unwrap(),
            canonical_sha256(&reordered).unwrap()
        );
        assert!(validate_labels(&reordered, &labels).is_ok());

        reordered.processes[0].cpu_percent = 51.0;
        assert!(matches!(
            validate_labels(&reordered, &labels),
            Err(ReplayEvaluationError::InvalidReview(_))
        ));
        let mut changed = snapshot.clone();
        changed
            .scoring_context
            .as_mut()
            .unwrap()
            .invoker_chain
            .insert(100);
        assert!(validate_labels(&changed, &labels).is_err());
        let mut changed = snapshot;
        changed.context.recorded_at = "2026-01-01T00:00:00Z".to_string();
        assert!(validate_labels(&changed, &labels).is_err());
    }

    #[test]
    fn review_rejects_missing_extra_duplicate_and_changed_identity_rows() {
        let snapshot = snapshot(2);
        let labels = balanced_labels(&snapshot);
        let reject = |changed: ReviewLabels| {
            assert!(matches!(
                validate_labels(&snapshot, &changed),
                Err(ReplayEvaluationError::InvalidReview(_))
            ));
        };

        let mut changed = labels.clone();
        changed.processes.pop();
        reject(changed);
        let mut changed = labels.clone();
        let mut extra = changed.processes[0].clone();
        extra.pid = 999;
        changed.processes.push(extra);
        reject(changed);
        let mut changed = labels.clone();
        changed.processes[1] = changed.processes[0].clone();
        reject(changed);
        for field in ["pid", "start_id", "uid", "pgid", "sid", "comm", "cmd"] {
            let mut changed = labels.clone();
            let row = &mut changed.processes[0];
            match field {
                "pid" => row.pid += 500,
                "start_id" => row.start_id.push_str("-reused"),
                "uid" => row.uid += 1,
                "pgid" => row.pgid = None,
                "sid" => row.sid = None,
                "comm" => row.comm.push_str("-edited"),
                "cmd" => row.cmd.push_str(" --edited"),
                _ => unreachable!(),
            }
            reject(changed);
        }
        let mut reordered = labels;
        reordered.processes.reverse();
        assert!(validate_labels(&snapshot, &reordered).is_ok());
    }

    #[test]
    fn reviewed_verdict_requires_complete_provenance_and_explicit_nullable_keys() {
        let snapshot = snapshot(1);
        let labels = balanced_labels(&snapshot);
        for field in ["reviewer", "reviewed_at", "rationale"] {
            let mut changed = labels.clone();
            let row = &mut changed.processes[0];
            match field {
                "reviewer" => row.reviewer = Some("  ".to_string()),
                "reviewed_at" => row.reviewed_at = Some("yesterday".to_string()),
                "rationale" => row.rationale = None,
                _ => unreachable!(),
            }
            assert!(changed.validate_structure().is_err());
        }
        let mut changed = labels.clone();
        changed.processes[0].verdict = None;
        assert!(changed.validate_structure().is_err());
        let serialized = serde_json::to_value(&labels).unwrap();
        for field in ["pgid", "sid", "verdict", "reviewer", "reviewed_at", "rationale"] {
            let mut incomplete = serialized.clone();
            incomplete["processes"][0]
                .as_object_mut()
                .unwrap()
                .remove(field);
            assert!(
                serde_json::from_value::<ReviewLabels>(incomplete).is_err(),
                "{field}"
            );
        }
        let mut unsupported = serialized;
        unsupported["processes"][0]["verdict"] = serde_json::json!("review_ok");
        assert!(serde_json::from_value::<ReviewLabels>(unsupported).is_err());
    }

    #[test]
    fn private_review_persistence_roundtrips_and_refuses_existing_destinations() {
        let dir = evidence_dir("private-save");
        let path = dir.join("review.json");
        let labels = make_review_template(&snapshot(2), "host", ReviewSplit::Holdout).unwrap();
        labels.save_new_private(&path).unwrap();
        let before = std::fs::read(&path).unwrap();
        let restored = read_review_labels(&path).unwrap();
        assert_eq!(restored.snapshot_sha256, labels.snapshot_sha256);
        assert_eq!(restored.processes.len(), 2);
        assert!(matches!(
            labels.save_new_private(&path),
            Err(ReplayEvaluationError::Io(_))
        ));
        assert_eq!(std::fs::read(&path).unwrap(), before);

        #[cfg(unix)]
        {
            use std::os::unix::fs::{symlink, PermissionsExt};
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o077,
                0
            );
            let link = dir.join("review-link.json");
            symlink(&path, &link).unwrap();
            assert!(labels.save_new_private(&link).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), before);
        }
    }

    #[test]
    fn paired_losses_use_known_probabilities_and_preserve_minimum_support() {
        let baseline = (0..10)
            .map(|index| CalibrationData {
                predicted: 0.5,
                actual: index < 5,
                ..Default::default()
            })
            .collect::<Vec<_>>();
        let candidate = baseline
            .iter()
            .map(|datum| CalibrationData {
                predicted: if datum.actual { 0.8 } else { 0.2 },
                ..datum.clone()
            })
            .collect::<Vec<_>>();
        let metrics = paired_probability_metrics(&baseline, &candidate).unwrap();
        assert_eq!(metrics.sample_count, 10);
        assert_eq!((metrics.useful_count, metrics.abandoned_count), (5, 5));
        assert!((metrics.baseline.brier_score - 0.25).abs() < 1e-12);
        assert!((metrics.candidate.brier_score - 0.04).abs() < 1e-12);
        assert!((metrics.candidate_minus_baseline.brier_score + 0.21).abs() < 1e-12);
        assert!((metrics.baseline.log_loss - 2.0_f64.ln()).abs() < 1e-12);
        assert!((metrics.candidate.log_loss + 0.8_f64.ln()).abs() < 1e-12);
        assert!((metrics.baseline.auc_roc - 0.5).abs() < 1e-12);
        assert!((metrics.candidate.auc_roc - 1.0).abs() < 1e-12);
        assert_eq!(
            metrics
                .baseline
                .curve
                .bins
                .iter()
                .map(|bin| bin.count)
                .sum::<usize>(),
            10
        );
        assert!(matches!(
            paired_probability_metrics(&baseline[..9], &candidate[..9]),
            Err(ReplayEvaluationError::Calibration(
                CalibrationError::InsufficientData { .. }
            ))
        ));
    }

    #[test]
    fn policy_coverage_loss_never_turns_missing_reviewed_processes_into_negatives() {
        let mut snapshot = snapshot(12);
        let unavailable = snapshot
            .scoring_context
            .as_mut()
            .unwrap()
            .processes
            .get_mut(&110)
            .unwrap();
        unavailable.cgroup_role = None;
        unavailable.observations = None;
        unavailable.unavailable_reason = Some("captured identity was unavailable".to_string());
        let mut labels = balanced_labels(&snapshot);
        labels.processes[11] = ProcessReview::unreviewed(&snapshot.processes[11]);
        let model = scorer();
        let baseline_policy = policy();
        let mut candidate_policy = policy();
        candidate_policy.guardrails.never_kill_pid.push(100);
        let report = evaluate_pair(
            &snapshot,
            &labels,
            &model,
            &baseline_policy,
            &model,
            &candidate_policy,
        )
        .unwrap();
        assert_eq!(report.processes.len(), 12);
        assert_eq!(report.coverage.population_size, 12);
        assert_eq!(report.coverage.reviewed_count, 11);
        assert_eq!(report.coverage.unlabeled_count, 1);
        assert_eq!(report.coverage.paired_count, 9);
        assert_eq!(report.coverage.baseline_only_count, 1);
        assert_eq!(report.coverage.neither_scored_count, 1);
        assert_eq!(report.baseline.scored_count, 11);
        assert_eq!(report.candidate.scored_count, 10);
        assert_eq!(report.baseline.reviewed_scored_count, 10);
        assert_eq!(report.candidate.reviewed_scored_count, 9);
        assert_eq!(
            report.processes[0].candidate_status,
            ReplayScoreStatus::Protected
        );
        assert!(!report.processes[0].paired_sample);
        assert_eq!(
            report.processes[10].baseline_status,
            ReplayScoreStatus::Unavailable
        );
        assert!(report.paired_metrics.is_none());
        assert!(report.warnings[0].starts_with("Candidate coverage dropped:"));

        candidate_policy.guardrails.min_process_age_seconds = u64::MAX;
        let dropped = evaluate_pair(
            &snapshot,
            &labels,
            &model,
            &baseline_policy,
            &model,
            &candidate_policy,
        )
        .unwrap();
        assert_eq!(dropped.coverage.paired_count, 0);
        assert_eq!(dropped.coverage.baseline_only_count, 10);
        assert_eq!(dropped.processes.len(), 12);
        assert!(dropped.paired_metrics.is_none());
    }

    #[test]
    fn one_class_cannot_claim_calibration_despite_ten_reviewed_samples() {
        let snapshot = snapshot(10);
        let mut labels = balanced_labels(&snapshot);
        for row in &mut labels.processes {
            review(row, ReviewVerdict::Useful);
        }
        let model = scorer();
        let report =
            evaluate_pair(&snapshot, &labels, &model, &policy(), &model, &policy()).unwrap();
        assert_eq!(report.coverage.paired_count, 10);
        assert_eq!(report.coverage.paired_abandoned_count, 0);
        assert!(report.paired_metrics.is_none());
        assert!(report
            .metrics_unavailable_reason
            .unwrap()
            .contains("10 useful and 0 abandoned"));
    }

    #[test]
    fn same_loaded_models_use_one_decay_clock_and_have_exactly_equal_predictions() {
        let snapshot = snapshot(10);
        let labels = balanced_labels(&snapshot);
        let mut model = scorer();
        for _ in 0..10 {
            model
                .decisions
                .record("worker", "worker --job", Verdict::Kill);
        }
        let now = Utc::now();
        let early = model
            .clone()
            .with_evaluation_time(now - chrono::Duration::days(1));
        let late = model.with_evaluation_time(now + chrono::Duration::days(1800));
        let process = &snapshot.processes[0];
        let observations = snapshot.scoring_context.as_ref().unwrap().processes[&process.pid.0]
            .observations
            .as_ref()
            .unwrap();
        let early_count = early
            .score_recorded(process, Evidence::from_snapshot(process), observations.clone())
            .unwrap()
            .learned_prior
            .unwrap()
            .effective_sample_count;
        let late_count = late
            .score_recorded(process, Evidence::from_snapshot(process), observations.clone())
            .unwrap()
            .learned_prior
            .unwrap()
            .effective_sample_count;
        assert!(early_count > late_count);

        let report =
            evaluate_pair(&snapshot, &labels, &early, &policy(), &late, &policy()).unwrap();
        assert_eq!(
            report.baseline.configuration_sha256,
            report.candidate.configuration_sha256
        );
        assert_eq!(report.evaluated_at, report.baseline.evaluated_at);
        assert_eq!(report.evaluated_at, report.candidate.evaluated_at);
        for row in &report.processes {
            assert!(row.paired_sample);
            assert_eq!(row.baseline_probability, row.candidate_probability);
        }
        let metrics = report.paired_metrics.unwrap();
        assert_eq!(metrics.candidate_minus_baseline.brier_score, 0.0);
        assert_eq!(metrics.candidate_minus_baseline.log_loss, 0.0);
        assert_eq!(metrics.candidate_minus_baseline.ece, 0.0);
    }

    #[test]
    fn fingerprints_cover_loaded_priors_policy_signatures_and_learned_counts() {
        let original = scorer();
        let policy = policy();
        let fingerprint = configuration_fingerprint(&original, &policy).unwrap();
        let mut changed = original.clone();
        changed.priors.classes.useful.cpu_beta.alpha += 1.0;
        assert_ne!(
            configuration_fingerprint(&changed, &policy).unwrap(),
            fingerprint
        );
        let mut changed_policy = policy.clone();
        changed_policy.guardrails.min_process_age_seconds += 1;
        assert_ne!(
            configuration_fingerprint(&original, &changed_policy).unwrap(),
            fingerprint
        );
        let mut changed = original.clone();
        changed
            .signatures
            .add(
                SupervisorSignature::new("review-fixture", SupervisorCategory::Other)
                    .with_process_patterns(vec!["^worker$"]),
            )
            .unwrap();
        assert_ne!(
            configuration_fingerprint(&changed, &policy).unwrap(),
            fingerprint
        );
        let mut changed = original.clone();
        changed
            .decisions
            .record("worker", "worker --job", Verdict::Spare);
        assert_ne!(
            configuration_fingerprint(&changed, &policy).unwrap(),
            fingerprint
        );
        let mut changed = original;
        changed.fast_path.enabled = !changed.fast_path.enabled;
        assert_ne!(
            configuration_fingerprint(&changed, &policy).unwrap(),
            fingerprint
        );
    }
}
