//! Core snapshot types, recording, loading, and replay.

use crate::collect::{ProcessRecord, ProcessState, ScanMetadata, ScanResult};
use crate::config::priors::Priors;
use crate::config::Policy;
use crate::decision::expected_loss::{Action, ActionFeasibility};
use crate::decision::myopic_policy::compute_loss_table;
use crate::inference::posterior::{compute_posterior, ClassScores, CpuEvidence, Evidence};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use thiserror::Error;

/// Schema version for replay snapshot files.
pub const REPLAY_SCHEMA_VERSION: &str = "1.0.0";

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
}

// ── Snapshot types ──────────────────────────────────────────────────────

/// Complete replay snapshot containing all data needed to replay through
/// the inference/decision pipeline.
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

        // Hash hostname
        if let Some(ref h) = self.context.hostname_hash {
            let mut hasher = DefaultHasher::new();
            h.hash(&mut hasher);
            self.context.hostname_hash = Some(format!("{:016x}", hasher.finish()));
        }
    }
}

// ── Replay inference ────────────────────────────────────────────────────

/// Replay a snapshot through the inference/decision pipeline.
///
/// For each process in the snapshot, constructs evidence, computes the
/// posterior, and determines the recommended action. Returns deterministic
/// results that can be compared against expected outcomes.
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

/// Build Evidence struct from a ProcessRecord and optional deep signals.
fn build_evidence(proc: &ProcessRecord, deep: Option<&DeepSignalRecord>) -> Evidence {
    let cpu = if proc.cpu_percent >= 0.0 {
        Some(CpuEvidence::Fraction {
            occupancy: (proc.cpu_percent / 100.0).clamp(0.0, 1.0),
        })
    } else {
        None
    };

    let state_flag = match proc.state {
        ProcessState::Running => Some(0),
        ProcessState::Sleeping => Some(1),
        ProcessState::DiskSleep => Some(2),
        ProcessState::Zombie => Some(3),
        ProcessState::Stopped => Some(4),
        ProcessState::Idle => Some(5),
        _ => None,
    };

    Evidence {
        cpu,
        runtime_seconds: Some(proc.elapsed.as_secs_f64()),
        orphan: Some(proc.is_orphan()),
        tty: Some(proc.has_tty()),
        net: deep.and_then(|d| d.net_active),
        io_active: deep.and_then(|d| d.io_active),
        state_flag,
        command_category: None,
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
