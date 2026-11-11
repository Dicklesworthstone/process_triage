//! Core snapshot types, recording, loading, and replay.

use crate::collect::cgroup::CgroupRole;
use crate::collect::protected::{ProtectedFilter, ProtectedMatch};
use crate::collect::{ProcessRecord, ScanMetadata, ScanResult};
use crate::config::priors::Priors;
use crate::config::Policy;
use crate::decision::expected_loss::{Action, ActionFeasibility};
use crate::decision::myopic_policy::compute_loss_table;
use crate::inference::posterior::{compute_posterior, ClassScores, Evidence};
use crate::inference::EvidenceLedger;
use crate::scoring::{Scorer, ScoringObservations};
use pt_common::{IdentityQuality, ProcessIdentity};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;
use std::time::Duration;
use thiserror::Error;

/// Schema version for replay snapshot files.
pub const REPLAY_SCHEMA_VERSION: &str = "1.1.0";

/// Errors that can occur during replay operations.
#[derive(Debug, Error)]
pub enum ReplayError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("snapshot schema version {found} is not compatible (expected {expected})")]
    IncompatibleSchema { found: String, expected: String },

    #[error("snapshot has no processes")]
    EmptySnapshot,

    #[error("inference error for PID {pid}: {message}")]
    Inference { pid: u32, message: String },

    #[error("incomplete or incompatible replay scoring context: {0}")]
    ScoringContext(String),
}

// ── Snapshot types ──────────────────────────────────────────────────────

/// A recorded process census with optional explicit scoring observations.
///
/// Inventory-only snapshots support mathematical demonstrations. Shared scoring
/// requires the complete context produced by `capture_snapshot`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplaySnapshot {
    /// Schema version for compatibility checking.
    pub schema_version: String,

    /// Human-readable name for this snapshot.
    pub name: String,

    /// Description of the scenario this snapshot represents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// System context at time of recording.
    pub context: SystemContext,

    /// Metadata about the original scan.
    pub scan_metadata: ReplayMetadata,

    /// Process records from the scan.
    pub processes: Vec<ProcessRecord>,

    /// Optional deep signal data per PID.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub deep_signals: HashMap<u32, DeepSignalRecord>,

    /// Explicit observations for shared scoring. Older inventory-only snapshots
    /// remain loadable, but cannot be used by `replay_scores`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scoring_context: Option<ReplayScoringContext>,
}

/// Observations captured for one process, including explicitly unavailable data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayProcessInputs {
    pub identity: ProcessIdentity,
    pub cgroup_role: Option<CgroupRole>,
    pub observations: Option<ScoringObservations>,
    pub unavailable_reason: Option<String>,
}

/// A complete inventory of scoring observations for one recorded census.
///
/// Protected and young processes retain rows but may have no expensive probes.
/// A later, broader policy cannot turn those missing probes into idle evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayScoringContext {
    pub schema_version: u32,
    pub platform: String,
    pub requested_window_ms: u64,
    pub invoker_chain: BTreeSet<u32>,
    pub processes: BTreeMap<u32, ReplayProcessInputs>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayScoreStatus {
    Scored,
    Protected,
    TooYoung,
    Unavailable,
}

/// One retained denominator row. No action recommendation is generated.
#[derive(Debug, Clone, Serialize)]
pub struct ReplayScoreResult {
    pub pid: u32,
    pub start_id: String,
    pub uid: u32,
    pub comm: String,
    pub status: ReplayScoreStatus,
    pub reason: Option<String>,
    pub protection: Option<ProtectedMatch>,
    pub posterior: Option<ClassScores>,
    pub ledger: Option<EvidenceLedger>,
    pub prior_source: Option<String>,
    pub signature: Option<String>,
}

/// Shared-scoring output, deliberately separate from an executable plan.
#[derive(Debug, Clone, Serialize)]
pub struct ReplayScoringReport {
    pub snapshot_name: String,
    pub recorded_at: String,
    pub evaluated_at: String,
    pub scoring_only: bool,
    pub configuration_scope: &'static str,
    pub requested_window_ms: u64,
    pub population_size: usize,
    pub scored_count: usize,
    pub protected_count: usize,
    pub too_young_count: usize,
    pub unavailable_count: usize,
    pub processes: Vec<ReplayScoreResult>,
    pub limitations: Vec<String>,
}

/// System context at time of snapshot creation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemContext {
    /// Hashed hostname (for privacy).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname_hash: Option<String>,

    /// Boot ID (for start_id validation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_id: Option<String>,

    /// ISO-8601 timestamp of snapshot creation.
    pub recorded_at: String,

    /// Platform identifier.
    pub platform: String,

    /// Total system memory in bytes (for context).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_memory_bytes: Option<u64>,

    /// Number of CPU cores.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_count: Option<u32>,
}

/// Metadata about the original scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayMetadata {
    /// Original scan type.
    pub scan_type: String,

    /// Original scan duration.
    pub duration_ms: u64,

    /// Total process count.
    pub process_count: usize,

    /// Warnings from the original scan.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Deep scan signals for a single process (optional enrichment).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeepSignalRecord {
    /// Whether the process has active network connections.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub net_active: Option<bool>,

    /// Whether the process is performing disk I/O.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub io_active: Option<bool>,
}

/// Result of replaying inference for a single process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayInferenceResult {
    /// Process ID.
    pub pid: u32,

    /// Command name.
    pub comm: String,

    /// Full command line.
    pub cmd: String,

    /// Process state.
    pub state: String,

    /// Posterior class probabilities.
    pub posterior: ClassScores,

    /// Classification label (highest posterior class).
    pub classification: String,

    /// Recommended action.
    pub recommended_action: Action,

    /// Expected loss of the recommended action.
    pub expected_loss: f64,

    /// Evidence terms used in computation.
    pub evidence_terms: Vec<String>,
}

// ── Recording ───────────────────────────────────────────────────────────

/// Record a live scan result into a replay snapshot.
///
/// The `name` parameter provides a human-readable label; if None, a
/// timestamp-based name is generated.
pub fn record_snapshot(
    scan: &ScanResult,
    name: Option<&str>,
) -> Result<ReplaySnapshot, ReplayError> {
    if scan.processes.is_empty() {
        return Err(ReplayError::EmptySnapshot);
    }

    let now = chrono::Utc::now().to_rfc3339();
    let snapshot_name = name
        .map(|n| n.to_string())
        .unwrap_or_else(|| format!("snapshot-{}", chrono::Utc::now().format("%Y%m%d-%H%M%S")));

    Ok(ReplaySnapshot {
        schema_version: REPLAY_SCHEMA_VERSION.to_string(),
        name: snapshot_name,
        description: None,
        context: SystemContext {
            hostname_hash: None,
            boot_id: scan.metadata.boot_id.clone(),
            recorded_at: now,
            platform: scan.metadata.platform.clone(),
            total_memory_bytes: None,
            cpu_count: None,
        },
        scan_metadata: ReplayMetadata {
            scan_type: scan.metadata.scan_type.clone(),
            duration_ms: scan.metadata.duration_ms,
            process_count: scan.processes.len(),
            warnings: scan.metadata.warnings.clone(),
        },
        processes: scan.processes.clone(),
        deep_signals: HashMap::new(),
        scoring_context: None,
    })
}

fn snapshot_identity(process: &ProcessRecord) -> ProcessIdentity {
    let quality = if process.start_id.0.starts_with("unknown:")
        || process.start_id.0.starts_with("synthetic:")
    {
        IdentityQuality::NoBootId
    } else {
        IdentityQuality::Full
    };
    ProcessIdentity::full(
        process.pid.0,
        process.start_id.clone(),
        process.uid,
        process.pgid,
        process.sid,
        quality,
    )
}

/// Capture the inputs used by shared scoring without executing process actions.
///
/// Placement is collected once per record. Expensive activity/provenance probes
/// run only for the capture policy's eligible population, with one shared window.
/// Identity checks bracket observation collection; failed and unprobed rows are
/// retained explicitly. The resulting file is private and still needs redaction.
pub fn capture_snapshot(
    scan: &ScanResult,
    name: Option<&str>,
    scorer: &mut Scorer,
    policy: &Policy,
    window: Duration,
) -> Result<ReplaySnapshot, ReplayError> {
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (scan, name, scorer, policy, window);
        Err(ReplayError::ScoringContext(
            "identity-bound capture is unsupported on this platform".to_string(),
        ))
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use crate::action::{IdentityProvider, LiveIdentityProvider};

        let mut snapshot = record_snapshot(scan, name)?;
        if scan.metadata.platform != std::env::consts::OS {
            return Err(ReplayError::ScoringContext(
                "capture platform differs from the scan platform".to_string(),
            ));
        }
        let filter = ProtectedFilter::from_guardrails(&policy.guardrails)
            .map_err(|error| ReplayError::ScoringContext(error.to_string()))?;
        let provider = LiveIdentityProvider::new();
        let invoker_chain = crate::collect::protected::invoker_chain_pids(&scan.processes);
        let mut inputs = BTreeMap::new();
        for process in &scan.processes {
            let identity = snapshot_identity(process);
            let mut input = ReplayProcessInputs {
                identity,
                cgroup_role: None,
                observations: None,
                unavailable_reason: None,
            };
            if !matches!(provider.revalidate(&input.identity), Ok(true)) {
                input.unavailable_reason =
                    Some("process identity was unavailable before capture".to_string());
            } else {
                let role = crate::collect::read_cgroup_role(process.pid.0);
                if matches!(provider.revalidate(&input.identity), Ok(true)) {
                    input.cgroup_role = Some(role);
                } else {
                    input.unavailable_reason =
                        Some("process identity changed during placement capture".to_string());
                }
            }
            if inputs.insert(process.pid.0, input).is_some() {
                return Err(ReplayError::ScoringContext(format!(
                    "duplicate PID {} in recorded census",
                    process.pid.0
                )));
            }
        }
        let filtered = filter.filter_with_observations(
            &scan.processes,
            &invoker_chain,
            |process| {
                inputs
                    .get(&process.pid.0)
                    .and_then(|input| input.cgroup_role)
                    .unwrap_or(CgroupRole::Unknown)
            },
            |_| None,
        );
        let passed: HashSet<u32> = filtered.passed.iter().map(|process| process.pid.0).collect();
        let eligible: Vec<&ProcessRecord> = scan
            .processes
            .iter()
            .filter(|process| {
                passed.contains(&process.pid.0)
                    && process.pid.0 > 1
                    && process.elapsed.as_secs() >= policy.guardrails.min_process_age_seconds
                    && inputs
                        .get(&process.pid.0)
                        .is_some_and(|input| input.cgroup_role.is_some())
            })
            .collect();

        scorer.collect_activity(&eligible, window);
        scorer.collect_provenance(&eligible);
        let eligible_pids: HashSet<u32> = eligible.iter().map(|process| process.pid.0).collect();
        for process in &scan.processes {
            let input = inputs
                .get_mut(&process.pid.0)
                .expect("each census identity was inserted");
            if input.cgroup_role.is_none() {
                continue;
            }
            if !eligible_pids.contains(&process.pid.0) {
                input.unavailable_reason = Some(
                    "scoring probes were not collected for this capture-policy-protected or young process"
                        .to_string(),
                );
                continue;
            }
            let desktop = crate::scoring::desktop_app_unit_for(process);
            let observations = scorer.recorded_observations(process, desktop);
            if matches!(provider.revalidate(&input.identity), Ok(true)) {
                input.observations = Some(observations);
            } else {
                input.cgroup_role = None;
                input.unavailable_reason =
                    Some("process identity changed during scoring capture".to_string());
            }
        }
        snapshot.scoring_context = Some(ReplayScoringContext {
            schema_version: 1,
            platform: std::env::consts::OS.to_string(),
            requested_window_ms: u64::try_from(window.as_millis()).unwrap_or(u64::MAX),
            invoker_chain: invoker_chain.into_iter().collect(),
            processes: inputs,
        });
        Ok(snapshot)
    }
}

/// Reject omitted context instead of treating a recording as fresh live data.
/// Explicit capture failures are valid rows; they stay unavailable in the report.
fn validate_scoring_context(snapshot: &ReplaySnapshot) -> Result<&ReplayScoringContext, ReplayError> {
    let context = snapshot.scoring_context.as_ref().ok_or_else(|| {
        ReplayError::ScoringContext(
            "inventory-only snapshot; capture again with scan --record-replay".to_string(),
        )
    })?;
    if context.schema_version != 1
        || context.platform != std::env::consts::OS
        || snapshot.context.platform != context.platform
    {
        return Err(ReplayError::ScoringContext(
            "scoring context version or platform does not match this evaluator".to_string(),
        ));
    }
    if context.processes.len() != snapshot.processes.len()
        || snapshot.scan_metadata.process_count != snapshot.processes.len()
    {
        return Err(ReplayError::ScoringContext(
            "scoring context must retain exactly the complete recorded census".to_string(),
        ));
    }
    let mut seen = HashSet::new();
    for process in &snapshot.processes {
        if !seen.insert(process.pid.0) {
            return Err(ReplayError::ScoringContext(format!(
                "duplicate PID {} in recorded census",
                process.pid.0
            )));
        }
        let input = context.processes.get(&process.pid.0).ok_or_else(|| {
            ReplayError::ScoringContext(format!("missing context for PID {}", process.pid.0))
        })?;
        if input.identity != snapshot_identity(process) {
            return Err(ReplayError::ScoringContext(format!(
                "recorded context belongs to a different incarnation of PID {}",
                process.pid.0
            )));
        }
        let Some(observations) = &input.observations else {
            if input
                .unavailable_reason
                .as_ref()
                .is_none_or(|reason| reason.trim().is_empty())
            {
                return Err(ReplayError::ScoringContext(format!(
                    "missing scoring observations without an explanation for PID {}",
                    process.pid.0
                )));
            }
            continue;
        };
        if input.cgroup_role.is_none()
            || input.unavailable_reason.is_some()
            || !observations.matches_record(process)
        {
            return Err(ReplayError::ScoringContext(format!(
                "invalid scoring observations for PID {}",
                process.pid.0
            )));
        }
        match (&observations.activity, context.requested_window_ms) {
            (None, 0) => {}
            (Some(activity), window)
                if window > 0 && activity.requested_window_ms == window => {}
            _ => {
                return Err(ReplayError::ScoringContext(format!(
                    "missing or inconsistent activity window for PID {}",
                    process.pid.0
                )));
            }
        }
        #[cfg(target_os = "linux")]
        if observations.provenance.is_none() {
            return Err(ReplayError::ScoringContext(format!(
                "missing captured provenance for PID {}",
                process.pid.0
            )));
        }
    }
    Ok(context)
}

/// Replay captured inputs through the production scorer and protection filter.
///
/// All processes retain rows, including protected, young and unavailable ones.
/// This evaluates current priors/signatures/human verdicts at the current time;
/// it is not a historical action decision, a calibrated quality metric, or a plan.
/// No live process, cgroup, service manager or activity collector is consulted.
pub fn replay_scores(
    snapshot: &ReplaySnapshot,
    scorer: &Scorer,
    policy: &Policy,
) -> Result<ReplayScoringReport, ReplayError> {
    let context = validate_scoring_context(snapshot)?;
    let filter = ProtectedFilter::from_guardrails(&policy.guardrails)
        .map_err(|error| ReplayError::ScoringContext(error.to_string()))?;
    let invoker_chain = context.invoker_chain.iter().copied().collect();
    let filtered = filter.filter_with_observations(
        &snapshot.processes,
        &invoker_chain,
        |process| {
            context.processes[&process.pid.0]
                .cgroup_role
                .unwrap_or(CgroupRole::Unknown)
        },
        |_| None,
    );
    let mut protected: HashMap<u32, ProtectedMatch> = filtered
        .filtered
        .into_iter()
        .map(|entry| (entry.pid, entry))
        .collect();
    let mut processes = Vec::with_capacity(snapshot.processes.len());
    for process in &snapshot.processes {
        let input = &context.processes[&process.pid.0];
        let mut row = ReplayScoreResult {
            pid: process.pid.0,
            start_id: process.start_id.to_string(),
            uid: process.uid,
            comm: process.comm.clone(),
            status: ReplayScoreStatus::Unavailable,
            reason: input.unavailable_reason.clone(),
            protection: None,
            posterior: None,
            ledger: None,
            prior_source: None,
            signature: None,
        };
        if input.cgroup_role.is_none() {
            // An identity failure cannot supply even an apparent safe placement.
            processes.push(row);
            continue;
        }
        if let Some(protection) = protected.remove(&process.pid.0) {
            row.status = ReplayScoreStatus::Protected;
            row.reason = protection.notes.clone();
            row.protection = Some(protection);
        } else if process.pid.0 <= 1
            || process.elapsed.as_secs() < policy.guardrails.min_process_age_seconds
        {
            row.status = ReplayScoreStatus::TooYoung;
            row.reason = Some("not eligible under the current minimum-age/identity policy".to_string());
        } else if let Some(observations) = &input.observations {
            match scorer.score_recorded(
                process,
                build_evidence(process, snapshot.deep_signals.get(&process.pid.0)),
                observations.clone(),
            ) {
                Some(score) => {
                    row.status = ReplayScoreStatus::Scored;
                    row.reason = None;
                    row.posterior = Some(score.posterior.posterior);
                    row.prior_source = Some(score.prior_source);
                    row.signature = score.signature.map(|matched| matched.signature.name.clone());
                    row.ledger = Some(score.ledger);
                }
                None => {
                    row.reason =
                        Some("shared scorer could not compute a valid posterior".to_string());
                }
            }
        }
        processes.push(row);
    }
    let count = |status| processes.iter().filter(|row| row.status == status).count();
    Ok(ReplayScoringReport {
        snapshot_name: snapshot.name.clone(),
        recorded_at: snapshot.context.recorded_at.clone(),
        evaluated_at: chrono::Utc::now().to_rfc3339(),
        scoring_only: true,
        configuration_scope: "current_configuration_and_current_learned_verdict_decay",
        requested_window_ms: context.requested_window_ms,
        population_size: snapshot.processes.len(),
        scored_count: count(ReplayScoreStatus::Scored),
        protected_count: count(ReplayScoreStatus::Protected),
        too_young_count: count(ReplayScoreStatus::TooYoung),
        unavailable_count: count(ReplayScoreStatus::Unavailable),
        processes,
        limitations: vec![
            "Scoring only: no action decisions, tree safety, live prechecks, kill/review metrics or execution."
                .to_string(),
            "Current configured priors, signatures and learned-verdict decay are evaluated; historical configuration is not reconstructed."
                .to_string(),
            "Stored placement and derived provenance terms are replayed; raw collectors and provenance classifiers are not rerun."
                .to_string(),
            "Supervisor restart eligibility requires fresh live validation; services remain protected during scoring replay."
                .to_string(),
        ],
    })
}

// ── Loading ─────────────────────────────────────────────────────────────

/// Load a replay snapshot from a JSON file.
pub fn load_snapshot(path: &Path) -> Result<ReplaySnapshot, ReplayError> {
    let content = std::fs::read_to_string(path)?;
    let snapshot: ReplaySnapshot = serde_json::from_str(&content)?;

    // Version compatibility check (major version must match)
    let major = snapshot
        .schema_version
        .split('.')
        .next()
        .unwrap_or("0")
        .parse::<u32>()
        .unwrap_or(0);
    let expected_major = REPLAY_SCHEMA_VERSION
        .split('.')
        .next()
        .unwrap_or("0")
        .parse::<u32>()
        .unwrap_or(0);

    if major != expected_major {
        return Err(ReplayError::IncompatibleSchema {
            found: snapshot.schema_version,
            expected: REPLAY_SCHEMA_VERSION.to_string(),
        });
    }

    Ok(snapshot)
}

impl ReplaySnapshot {
    /// Save a new private capture without overwriting an existing file or symlink.
    ///
    /// Captures retain command lines and identities for faithful replay. They are
    /// not redacted exports: callers must review/redact them before sharing.
    /// Unix captures are created with at most owner read/write permissions.
    pub fn save_new_private(&self, path: &Path) -> Result<(), ReplayError> {
        use std::io::Write;

        // Serialize before creating the destination so serialization errors do not
        // leave an empty capture. An I/O failure retains any partial file as evidence.
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

    /// Save the snapshot to a JSON file.
    pub fn save(&self, path: &Path) -> Result<(), ReplayError> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Reconstruct a ScanResult from the snapshot for integration with
    /// the existing pipeline.
    pub fn to_scan_result(&self) -> ScanResult {
        ScanResult {
            processes: self.processes.clone(),
            metadata: ScanMetadata {
                scan_type: format!("replay:{}", self.scan_metadata.scan_type),
                platform: self.context.platform.clone(),
                boot_id: self.context.boot_id.clone(),
                started_at: self.context.recorded_at.clone(),
                duration_ms: 0,
                process_count: self.processes.len(),
                warnings: vec![format!("Replayed from snapshot: {}", self.name)],
            },
        }
    }

    /// Apply anonymization: hash command lines, replace usernames.
    pub fn anonymize(&mut self) {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        for proc in &mut self.processes {
            // Hash the full command line
            let mut hasher = DefaultHasher::new();
            proc.cmd.hash(&mut hasher);
            proc.cmd = format!("<hashed:{:016x}>", hasher.finish());

            // Replace username
            proc.user = "user".to_string();
        }

        // Hashing commands destroys signature/learned-pattern fidelity, and the
        // derived context can retain paths and service names. Never preserve a
        // partially anonymized context that could be mistaken for faithful replay.
        self.scoring_context = None;

        // Hash hostname
        if let Some(ref h) = self.context.hostname_hash {
            let mut hasher = DefaultHasher::new();
            h.hash(&mut hasher);
            self.context.hostname_hash = Some(format!("{:016x}", hasher.finish()));
        }
    }
}

// ── Replay inference ────────────────────────────────────────────────────

/// Mathematical simulation of a snapshot with an unconstrained action set.
///
/// This older demonstration API does not implement production protection,
/// signatures, learned priors or final action safety. Its actions cannot be used
/// as executable recommendations or production decision-quality measurements.
/// Use `replay_scores` for captured observations and the shared production scorer.
pub fn replay_inference(
    snapshot: &ReplaySnapshot,
    priors: &Priors,
    policy: &Policy,
) -> Result<Vec<ReplayInferenceResult>, ReplayError> {
    let feasibility = ActionFeasibility::allow_all();
    let mut results = Vec::with_capacity(snapshot.processes.len());

    for proc in &snapshot.processes {
        let deep = snapshot.deep_signals.get(&proc.pid.0);

        // Build evidence from the process record + optional deep signals
        let evidence = build_evidence(proc, deep);

        // Compute posterior
        let posterior =
            compute_posterior(priors, &evidence).map_err(|e| ReplayError::Inference {
                pid: proc.pid.0,
                message: e.to_string(),
            })?;

        // Determine action via myopic policy
        let decision =
            decide_from_belief_for_replay(&posterior.posterior, &policy.loss_matrix, &feasibility);

        let classification = classify(&posterior.posterior);
        let evidence_labels: Vec<String> = posterior
            .evidence_terms
            .iter()
            .map(|t| t.feature.clone())
            .collect();

        results.push(ReplayInferenceResult {
            pid: proc.pid.0,
            comm: proc.comm.clone(),
            cmd: proc.cmd.clone(),
            state: proc.state.to_string(),
            posterior: posterior.posterior,
            classification,
            recommended_action: decision.0,
            expected_loss: decision.1,
            evidence_terms: evidence_labels,
        });
    }

    Ok(results)
}

/// Use the same snapshot evidence mapping as live scoring.
fn build_evidence(proc: &ProcessRecord, deep: Option<&DeepSignalRecord>) -> Evidence {
    Evidence {
        net: deep.and_then(|signal| signal.net_active),
        io_active: deep.and_then(|signal| signal.io_active),
        ..Evidence::from_snapshot(proc)
    }
}

/// Classify a posterior into its highest-probability class label.
fn classify(posterior: &ClassScores) -> String {
    let scores = [
        ("useful", posterior.useful),
        ("useful_bad", posterior.useful_bad),
        ("abandoned", posterior.abandoned),
        ("zombie", posterior.zombie),
    ];

    scores
        .iter()
        .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
        .map(|(name, _)| name.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Determine optimal action from posterior using the myopic policy.
///
/// Returns (action, expected_loss).
fn decide_from_belief_for_replay(
    posterior: &ClassScores,
    loss_matrix: &crate::config::policy::LossMatrix,
    feasibility: &ActionFeasibility,
) -> (Action, f64) {
    use crate::inference::belief_state::BeliefState;

    let belief = BeliefState::from_probs([
        posterior.useful,
        posterior.useful_bad,
        posterior.abandoned,
        posterior.zombie,
    ]);

    match belief {
        Ok(b) => {
            let table = compute_loss_table(&b, loss_matrix, feasibility);
            table
                .iter()
                .filter(|e| e.feasible)
                .min_by(|a, b| {
                    a.expected_loss
                        .partial_cmp(&b.expected_loss)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .map(|e| (e.action, e.expected_loss))
                .unwrap_or((Action::Keep, f64::INFINITY))
        }
        Err(_) => (Action::Keep, f64::INFINITY),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock_process::{MockProcessBuilder, MockScanBuilder};
    use std::time::Duration;

    fn replay_scorer() -> Scorer {
        Scorer::new(
            Priors::default(),
            crate::decision::decision_store::DecisionStore::default(),
            crate::supervision::signature::SignatureDatabase::with_defaults(),
            crate::inference::FastPathConfig::disabled(),
        )
    }

    fn scoring_fixture(processes: Vec<ProcessRecord>, scorer: &Scorer) -> ReplaySnapshot {
        let scan = MockScanBuilder::new()
            .platform(std::env::consts::OS)
            .with_processes(processes)
            .build();
        let mut snapshot = record_snapshot(&scan, Some("scoring-fixture")).unwrap();
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
                            ..Default::default()
                        },
                    ));
                    observations
                };
                (
                    process.pid.0,
                    ReplayProcessInputs {
                        identity: snapshot_identity(process),
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

    fn scoring_process(pid: u32, comm: &str, age: u64) -> ProcessRecord {
        MockProcessBuilder::new()
            .pid(pid)
            .ppid(7)
            .uid(1000)
            .user("alice")
            .comm(comm)
            .cmd(format!("{comm} --job"))
            .elapsed_secs(age)
            .build()
    }

    #[test]
    fn scoring_replay_retains_protected_young_and_unavailable_denominators() {
        let scorer = replay_scorer();
        let mut policy = Policy::default();
        policy.guardrails.min_process_age_seconds = 60;
        let mut snapshot = scoring_fixture(
            vec![
                scoring_process(101, "worker", 7200),
                scoring_process(102, "sshd", 7200),
                scoring_process(103, "worker-young", 0),
                scoring_process(104, "worker-unavailable", 7200),
                scoring_process(105, "worker-invoker", 7200),
            ],
            &scorer,
        );
        let context = snapshot.scoring_context.as_mut().unwrap();
        context.invoker_chain.insert(105);
        let unavailable = context.processes.get_mut(&104).unwrap();
        unavailable.cgroup_role = None;
        unavailable.observations = None;
        unavailable.unavailable_reason = Some("identity changed during capture".to_string());

        let restored: ReplaySnapshot =
            serde_json::from_slice(&serde_json::to_vec(&snapshot).unwrap()).unwrap();
        let report = replay_scores(&restored, &scorer, &policy).unwrap();
        assert_eq!(report.population_size, 5);
        assert_eq!(report.scored_count, 1);
        assert_eq!(report.protected_count, 2);
        assert_eq!(report.too_young_count, 1);
        assert_eq!(report.unavailable_count, 1);
        assert_eq!(report.processes.len(), 5);
        assert!(report.processes[0].ledger.is_some());
        assert!(report.processes[1..].iter().all(|row| row.posterior.is_none()));
        assert!(report.scoring_only);
        assert!(!serde_json::to_string(&report)
            .unwrap()
            .contains("\"recommended_action\""));
    }

    #[test]
    fn scoring_replay_uses_shared_signature_and_human_prior_precedence() {
        use crate::decision::decision_store::Verdict;
        use crate::supervision::signature::{SignatureDatabase, SignaturePriors, SupervisorSignature};
        use crate::supervision::SupervisorCategory;

        let mut signatures = SignatureDatabase::new();
        signatures
            .add(
                SupervisorSignature::new("recorded-worker", SupervisorCategory::Other)
                    .with_process_patterns(vec!["^worker$"])
                    .with_priors(SignaturePriors::likely_abandoned()),
            )
            .unwrap();
        let mut scorer = replay_scorer();
        scorer.signatures = signatures;
        let snapshot = scoring_fixture(vec![scoring_process(201, "worker", 7200)], &scorer);
        let policy = Policy::default();
        let signed = replay_scores(&snapshot, &scorer, &policy).unwrap();
        assert_eq!(signed.processes[0].prior_source.as_deref(), Some("signature"));
        assert_eq!(
            signed.processes[0].signature.as_deref(),
            Some("recorded-worker")
        );
        for _ in 0..12 {
            scorer.decisions.record("worker", "worker --job", Verdict::Spare);
        }
        let learned = replay_scores(&snapshot, &scorer, &policy).unwrap();
        assert_eq!(learned.processes[0].prior_source.as_deref(), Some("user"));
        assert!(
            learned.processes[0].posterior.unwrap().abandonment_probability()
                < signed.processes[0].posterior.unwrap().abandonment_probability()
        );
    }

    #[test]
    fn scoring_replay_rejects_incomplete_stale_and_wrong_platform_context() {
        let scorer = replay_scorer();
        let policy = Policy::default();
        let original = scoring_fixture(vec![scoring_process(301, "worker", 7200)], &scorer);
        let rejects = |snapshot: &ReplaySnapshot| {
            assert!(matches!(
                replay_scores(snapshot, &scorer, &policy),
                Err(ReplayError::ScoringContext(_))
            ));
        };

        let mut changed = original.clone();
        changed.scoring_context = None;
        rejects(&changed);

        let mut changed = original.clone();
        changed.scoring_context.as_mut().unwrap().processes.remove(&301);
        rejects(&changed);

        let mut changed = original.clone();
        changed
            .scoring_context
            .as_mut()
            .unwrap()
            .processes
            .get_mut(&301)
            .unwrap()
            .identity
            .uid += 1;
        rejects(&changed);

        let mut changed = original.clone();
        changed.scoring_context.as_mut().unwrap().requested_window_ms = 500;
        rejects(&changed);

        let mut changed = original.clone();
        changed.scoring_context.as_mut().unwrap().platform = "another-platform".to_string();
        rejects(&changed);

        let mut changed = original.clone();
        changed
            .scoring_context
            .as_mut()
            .unwrap()
            .processes
            .get_mut(&301)
            .unwrap()
            .observations = None;
        rejects(&changed);

        #[cfg(target_os = "linux")]
        {
            let mut changed = original.clone();
            changed
                .scoring_context
                .as_mut()
                .unwrap()
                .processes
                .get_mut(&301)
                .unwrap()
                .observations
                .as_mut()
                .unwrap()
                .provenance = None;
            rejects(&changed);
        }

        let mut changed = original;
        changed.anonymize();
        assert!(changed.scoring_context.is_none());
        rejects(&changed);
    }

    #[test]
    fn broader_replay_policy_cannot_invent_uncollected_scoring_inputs() {
        let scorer = replay_scorer();
        let mut snapshot = scoring_fixture(vec![scoring_process(401, "worker", 10)], &scorer);
        let input = snapshot
            .scoring_context
            .as_mut()
            .unwrap()
            .processes
            .get_mut(&401)
            .unwrap();
        input.observations = None;
        input.unavailable_reason = Some("not sampled under capture policy".to_string());
        let mut policy = Policy::default();
        let excluded = replay_scores(&snapshot, &scorer, &policy).unwrap();
        assert_eq!(excluded.too_young_count, 1);
        policy.guardrails.min_process_age_seconds = 0;
        let broadened = replay_scores(&snapshot, &scorer, &policy).unwrap();
        assert_eq!(broadened.population_size, 1);
        assert_eq!(broadened.unavailable_count, 1);
        assert_eq!(broadened.scored_count, 0);
    }

    #[test]
    fn replay_snapshot_evidence_keeps_zero_age_and_dead_state_semantics() {
        let process = MockProcessBuilder::new()
            .pid(501)
            .elapsed_secs(0)
            .state(crate::collect::ProcessState::Dead)
            .build();
        let evidence = build_evidence(&process, None);
        assert_eq!(evidence.runtime_seconds, None);
        assert_eq!(evidence.state_flag, Some(6));
    }

    #[test]
    fn test_record_and_load_snapshot() {
        let scan = MockScanBuilder::new()
            .with_zombie(1234)
            .with_orphan(5678, "node")
            .build();

        let snapshot = record_snapshot(&scan, Some("test-snapshot")).unwrap();
        assert_eq!(snapshot.name, "test-snapshot");
        assert_eq!(snapshot.processes.len(), 2);
        assert_eq!(snapshot.schema_version, REPLAY_SCHEMA_VERSION);

        // Round-trip through JSON
        let json = serde_json::to_string_pretty(&snapshot).unwrap();
        let loaded: ReplaySnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.processes.len(), 2);
        assert_eq!(loaded.name, "test-snapshot");
    }

    #[test]
    fn test_record_empty_scan_fails() {
        let scan = ScanResult {
            processes: vec![],
            metadata: ScanMetadata {
                scan_type: "quick".to_string(),
                platform: "linux".to_string(),
                boot_id: None,
                started_at: "2026-01-01T00:00:00Z".to_string(),
                duration_ms: 0,
                process_count: 0,
                warnings: vec![],
            },
        };

        let result = record_snapshot(&scan, None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ReplayError::EmptySnapshot));
    }

    #[test]
    fn test_to_scan_result() {
        let scan = MockScanBuilder::new().with_zombie(100).build();
        let snapshot = record_snapshot(&scan, Some("test")).unwrap();
        let reconstructed = snapshot.to_scan_result();

        assert_eq!(reconstructed.processes.len(), 1);
        assert!(reconstructed.metadata.scan_type.starts_with("replay:"));
    }

    #[test]
    fn test_anonymize() {
        let scan = MockScanBuilder::new()
            .with_process(
                MockProcessBuilder::new()
                    .pid(42)
                    .comm("secret-tool")
                    .cmd("secret-tool --api-key=XXXX")
                    .build(),
            )
            .build();

        let mut snapshot = record_snapshot(&scan, Some("anon-test")).unwrap();
        let original_cmd = snapshot.processes[0].cmd.clone();
        snapshot.anonymize();

        assert_ne!(snapshot.processes[0].cmd, original_cmd);
        assert!(snapshot.processes[0].cmd.starts_with("<hashed:"));
        assert_eq!(snapshot.processes[0].user, "user");
    }

    #[test]
    fn test_replay_inference_basic() {
        let scan = MockScanBuilder::new()
            .with_zombie(1234)
            .with_orphan(5678, "node")
            .build();

        let snapshot = record_snapshot(&scan, Some("inference-test")).unwrap();
        let priors = Priors::default();
        let policy = Policy::default();

        let results = replay_inference(&snapshot, &priors, &policy).unwrap();
        assert_eq!(results.len(), 2);

        // Each result should have valid classification
        for r in &results {
            assert!(!r.classification.is_empty());
            assert!(!r.evidence_terms.is_empty());
            assert!(r.expected_loss.is_finite());
        }
    }

    #[test]
    fn test_replay_deterministic() {
        let scan = MockScanBuilder::new()
            .with_zombie(100)
            .with_orphan(200, "node")
            .build();

        let snapshot = record_snapshot(&scan, Some("determ-test")).unwrap();
        let priors = Priors::default();
        let policy = Policy::default();

        let results1 = replay_inference(&snapshot, &priors, &policy).unwrap();
        let results2 = replay_inference(&snapshot, &priors, &policy).unwrap();

        // Results must be identical
        assert_eq!(results1.len(), results2.len());
        for (r1, r2) in results1.iter().zip(results2.iter()) {
            assert_eq!(r1.pid, r2.pid);
            assert_eq!(r1.classification, r2.classification);
            assert_eq!(r1.recommended_action, r2.recommended_action);
            assert!((r1.expected_loss - r2.expected_loss).abs() < 1e-12);
        }
    }

    #[test]
    fn test_build_evidence_with_deep_signals() {
        let proc = MockProcessBuilder::new()
            .pid(42)
            .cpu_percent(50.0)
            .elapsed(Duration::from_secs(3600))
            .build();

        let deep = DeepSignalRecord {
            net_active: Some(true),
            io_active: Some(false),
        };

        let evidence = build_evidence(&proc, Some(&deep));
        assert!(evidence.cpu.is_some());
        assert_eq!(evidence.runtime_seconds, Some(3600.0));
        assert_eq!(evidence.net, Some(true));
        assert_eq!(evidence.io_active, Some(false));
    }

    #[test]
    fn test_classify_labels() {
        assert_eq!(
            classify(&ClassScores {
                useful: 0.8,
                useful_bad: 0.1,
                abandoned: 0.05,
                zombie: 0.05,
            }),
            "useful"
        );
        assert_eq!(
            classify(&ClassScores {
                useful: 0.05,
                useful_bad: 0.05,
                abandoned: 0.1,
                zombie: 0.8,
            }),
            "zombie"
        );
    }

    #[test]
    fn test_save_and_load_file() {
        let scan = MockScanBuilder::new().with_zombie(42).build();
        let snapshot = record_snapshot(&scan, Some("file-test")).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test_snapshot.json");

        snapshot.save(&path).unwrap();
        let loaded = load_snapshot(&path).unwrap();

        assert_eq!(loaded.name, "file-test");
        assert_eq!(loaded.processes.len(), 1);
    }
}
