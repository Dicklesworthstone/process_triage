//! Session snapshot persistence with schema validation, redaction, and integrity.
//!
//! Provides atomic writes of individual session artifacts (inventory, inference,
//! plan) and validated reads with version compatibility checks.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use super::{
    SessionContext, SessionError, SessionHandle, SessionManifest, SnapshotProvenanceRef,
    SNAPSHOT_SCHEMA_VERSION,
};
use pt_common::ProvenanceGraphSnapshot;

/// Subdirectory names for artifact types.
const INVENTORY_FILE: &str = "scan/inventory.json";
const INFERENCE_FILE: &str = "inference/results.json";
const PLAN_FILE: &str = "decision/plan.json";
const META_FILE: &str = "run_metadata.json";
const PROVENANCE_FILE: &str = "scan/provenance.json";
const PROVENANCE_AUDIT_FILE: &str = "scan/provenance_audit.json";

/// Redaction sentinel for sensitive strings.
const REDACTED: &str = "<REDACTED>";

/// SHA-256 hex digest length.
const SHA256_HEX_LEN: usize = 64;

// ---------------------------------------------------------------------------
// Artifact envelope
// ---------------------------------------------------------------------------

/// Versioned envelope wrapping any persisted artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactEnvelope<T> {
    /// Schema version for forward/backward compat checks.
    pub schema_version: String,
    /// Session that produced this artifact.
    pub session_id: String,
    /// RFC-3339 timestamp of artifact creation.
    pub generated_at: String,
    /// Host that produced the artifact.
    pub host_id: String,
    /// SHA-256 hex digest of the inner payload JSON.
    pub integrity_sha256: String,
    /// The actual payload.
    pub payload: T,
}

impl<T: Serialize> ArtifactEnvelope<T> {
    /// Create a new envelope with integrity computed at persistence time.
    pub fn new(session_id: &str, host_id: &str, payload: T) -> Self {
        Self {
            schema_version: SNAPSHOT_SCHEMA_VERSION.to_string(),
            session_id: session_id.to_string(),
            generated_at: chrono::Utc::now().to_rfc3339(),
            host_id: host_id.to_string(),
            integrity_sha256: String::new(),
            payload,
        }
    }
}

// ---------------------------------------------------------------------------
// Inventory artifact
// ---------------------------------------------------------------------------

/// Persisted process identity record (redaction-safe).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PersistedProcess {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub start_id: String,
    /// Display command (may be redacted).
    pub comm: String,
    /// Full command line (may be redacted).
    pub cmd: String,
    pub state: String,
    pub start_time_unix: i64,
    pub elapsed_secs: u64,
    /// Identity quality tag for revalidation safety.
    pub identity_quality: String,
}

/// Inventory artifact: all scanned processes for the session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InventoryArtifact {
    pub total_system_processes: u64,
    pub protected_filtered: u64,
    pub record_count: usize,
    pub records: Vec<PersistedProcess>,
}

// ---------------------------------------------------------------------------
// Inference artifact
// ---------------------------------------------------------------------------

/// Persisted inference result for one process.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PersistedInference {
    pub pid: u32,
    pub start_id: String,
    pub classification: String,
    pub posterior_useful: f64,
    pub posterior_useful_bad: f64,
    pub posterior_abandoned: f64,
    pub posterior_zombie: f64,
    pub confidence: String,
    pub recommended_action: String,
    pub score: u32,
    /// Exact JSON emitted by the scorer at observation time. This retains the
    /// historical likelihood terms and priors without rescoring a live PID.
    /// Older snapshots omit the field; missing evidence is never reconstructed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_ledger: Option<serde_json::Value>,

    // ── Provenance context (bd-c4d1) ─────────────────────────────
    /// Blast-radius risk level from provenance graph (low/medium/high/critical).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blast_radius_risk_level: Option<String>,
    /// Total processes/resources affected if killed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blast_radius_total_affected: Option<usize>,
    /// Provenance evidence completeness [0, 1].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance_evidence_completeness: Option<f64>,
    /// Provenance score terms that contributed to the posterior.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provenance_score_terms: Vec<String>,
    /// Net log-odds shift from provenance features.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance_log_odds_shift: Option<f64>,
}

/// Inference artifact: inference results for all candidates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceArtifact {
    pub candidate_count: usize,
    pub candidates: Vec<PersistedInference>,
}

// ---------------------------------------------------------------------------
// Plan artifact
// ---------------------------------------------------------------------------

/// Persisted plan action for one process.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PersistedPlanAction {
    pub pid: u32,
    pub start_id: String,
    pub action: String,
    pub expected_loss: f64,
    pub rationale: String,
}

/// Plan artifact: the generated action plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanArtifact {
    pub action_count: usize,
    pub kill_count: usize,
    pub review_count: usize,
    pub spare_count: usize,
    pub actions: Vec<PersistedPlanAction>,
}

// ---------------------------------------------------------------------------
// Run metadata
// ---------------------------------------------------------------------------

/// Run metadata capturing tool versions, config hashes, and host info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunMetadata {
    pub pt_version: String,
    pub schema_version: String,
    pub host_id: String,
    pub hostname: String,
    pub os_family: String,
    pub os_arch: String,
    pub cores: u32,
    pub memory_total_gb: f64,
    /// SHA-256 of the active priors config.
    pub priors_hash: String,
    /// SHA-256 of the active policy config.
    pub policy_hash: String,
    /// Arbitrary extra tags for provenance.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tags: BTreeMap<String, String>,
}

/// Provenance artifact: canonical graph snapshot for a session.
pub type ProvenanceArtifact = ProvenanceGraphSnapshot;

/// Audit sidecar describing how provenance was persisted for local replay.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvenancePersistenceAudit {
    pub schema_version: String,
    pub artifact_path: String,
    pub generated_at: String,
    pub provenance_schema_version: String,
    pub privacy_version: String,
    pub integrity_sha256: String,
    pub node_count: usize,
    pub edge_count: usize,
    pub evidence_count: usize,
    pub redacted_evidence_count: usize,
    pub missing_or_conflicted_evidence_count: usize,
    pub warning_count: usize,
    pub consent_required_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub persisted_sections: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redacted_sections: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub omitted_sections: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub migration_notes: Vec<String>,
}

impl ProvenancePersistenceAudit {
    fn from_envelope(envelope: &ArtifactEnvelope<ProvenanceArtifact>) -> Self {
        let payload = &envelope.payload;
        let mut redacted_sections = Vec::new();
        let mut omitted_sections = Vec::new();

        if payload
            .nodes
            .iter()
            .any(|node| node.redaction != pt_common::ProvenanceRedactionState::None)
        {
            redacted_sections.push("graph.nodes".to_string());
        }
        if payload
            .edges
            .iter()
            .any(|edge| edge.redaction != pt_common::ProvenanceRedactionState::None)
        {
            redacted_sections.push("graph.edges".to_string());
        }
        if payload.summary.redacted_evidence_count > 0 {
            redacted_sections.push("graph.evidence".to_string());
        }
        if payload.summary.missing_or_conflicted_evidence_count > 0 {
            omitted_sections.push("graph.evidence.missing_or_conflicted".to_string());
        }
        Self {
            schema_version: SNAPSHOT_SCHEMA_VERSION.to_string(),
            artifact_path: PROVENANCE_FILE.to_string(),
            generated_at: envelope.generated_at.clone(),
            provenance_schema_version: payload.schema_version.clone(),
            privacy_version: payload.privacy.version.clone(),
            integrity_sha256: envelope.integrity_sha256.clone(),
            node_count: payload.summary.node_count,
            edge_count: payload.summary.edge_count,
            evidence_count: payload.summary.evidence_count,
            redacted_evidence_count: payload.summary.redacted_evidence_count,
            missing_or_conflicted_evidence_count: payload
                .summary
                .missing_or_conflicted_evidence_count,
            warning_count: payload.warnings.len(),
            consent_required_count: payload.privacy.consent_required_count(),
            persisted_sections: vec![
                "graph.nodes".to_string(),
                "graph.edges".to_string(),
                "graph.evidence".to_string(),
                "graph.summary".to_string(),
                "graph.warnings".to_string(),
                "privacy.policy".to_string(),
            ],
            redacted_sections,
            omitted_sections,
            migration_notes: Vec::new(),
        }
    }

    pub fn snapshot_ref(&self) -> SnapshotProvenanceRef {
        SnapshotProvenanceRef {
            path: self.artifact_path.clone(),
            provenance_schema_version: self.provenance_schema_version.clone(),
            privacy_version: self.privacy_version.clone(),
            integrity_sha256: self.integrity_sha256.clone(),
            node_count: self.node_count,
            edge_count: self.edge_count,
            evidence_count: self.evidence_count,
            redacted_evidence_count: self.redacted_evidence_count,
            missing_or_conflicted_evidence_count: self.missing_or_conflicted_evidence_count,
            warning_count: self.warning_count,
            audit_path: PROVENANCE_AUDIT_FILE.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

/// Redaction policy for snapshot persistence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RedactionPolicy {
    /// Keep all strings as-is (for local-only storage).
    None,
    /// Redact command lines that match sensitive patterns.
    #[default]
    Standard,
    /// Redact all command lines unconditionally.
    Full,
}

/// Sensitive substrings that trigger redaction under `Standard` policy.
const SENSITIVE_PATTERNS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "api-key",
    "aws_secret",
    "private_key",
    "credential",
    "auth_token",
    "bearer ",
    "-----begin",
];

/// Apply redaction policy to a command string.
pub fn redact_cmd(cmd: &str, policy: RedactionPolicy) -> String {
    match policy {
        RedactionPolicy::None => cmd.to_string(),
        RedactionPolicy::Full => REDACTED.to_string(),
        RedactionPolicy::Standard => {
            let lower = cmd.to_lowercase();
            if SENSITIVE_PATTERNS.iter().any(|p| lower.contains(p)) {
                REDACTED.to_string()
            } else {
                cmd.to_string()
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Persist / load helpers
// ---------------------------------------------------------------------------

/// Persist an artifact envelope atomically to a file inside a session dir.
fn persist_artifact<T: serde::de::DeserializeOwned + Serialize>(
    handle: &SessionHandle,
    rel_path: &str,
    mut envelope: ArtifactEnvelope<T>,
) -> Result<PathBuf, SessionError> {
    let path = handle.dir.join(rel_path);
    envelope.integrity_sha256 = payload_sha256(&envelope.payload, &path)?;
    super::write_json_pretty(&path, &envelope)?;
    Ok(path)
}

fn persist_audit<T: Serialize>(
    handle: &SessionHandle,
    rel_path: &str,
    payload: &T,
) -> Result<PathBuf, SessionError> {
    let path = handle.dir.join(rel_path);
    super::write_json_pretty(&path, payload)?;
    Ok(path)
}

/// Load and validate an artifact envelope from a session directory.
fn load_artifact<T: serde::de::DeserializeOwned + Serialize>(
    handle: &SessionHandle,
    rel_path: &str,
) -> Result<ArtifactEnvelope<T>, SessionError> {
    let path = handle.dir.join(rel_path);
    let content = std::fs::read_to_string(&path).map_err(|e| SessionError::Io {
        path: path.clone(),
        source: e,
    })?;
    let envelope: ArtifactEnvelope<T> =
        serde_json::from_str(&content).map_err(|e| SessionError::Json {
            path: path.clone(),
            source: e,
        })?;
    validate_artifact(envelope, &path)
}

fn validate_artifact<T: Serialize>(
    envelope: ArtifactEnvelope<T>,
    path: &Path,
) -> Result<ArtifactEnvelope<T>, SessionError> {
    // Validate schema version compatibility.
    if !pt_common::schema::is_compatible(&envelope.schema_version) {
        return Err(SessionError::Json {
            path: path.to_path_buf(),
            source: serde_json::Error::io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "incompatible schema version: {} (expected {})",
                    envelope.schema_version, SNAPSHOT_SCHEMA_VERSION
                ),
            )),
        });
    }

    // Validate integrity hash.
    let payload_json = canonical_payload_bytes(&envelope.payload, path)?;
    let computed = sha256_hex(&payload_json);
    if computed != envelope.integrity_sha256 {
        return Err(SessionError::Json {
            path: path.to_path_buf(),
            source: serde_json::Error::io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "integrity check failed: payload SHA-256 mismatch",
            )),
        });
    }

    Ok(envelope)
}

/// Load an artifact envelope but skip integrity validation.
///
/// Useful as a compatibility escape hatch while evolving persistence formats.
fn load_artifact_unchecked<T: serde::de::DeserializeOwned + Serialize>(
    handle: &SessionHandle,
    rel_path: &str,
) -> Result<ArtifactEnvelope<T>, SessionError> {
    let path = handle.dir.join(rel_path);
    let content = std::fs::read_to_string(&path).map_err(|e| SessionError::Io {
        path: path.clone(),
        source: e,
    })?;
    let envelope: ArtifactEnvelope<T> =
        serde_json::from_str(&content).map_err(|e| SessionError::Json {
            path: path.clone(),
            source: e,
        })?;

    // Validate schema version compatibility.
    if !pt_common::schema::is_compatible(&envelope.schema_version) {
        return Err(SessionError::Json {
            path,
            source: serde_json::Error::io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "incompatible schema version: {} (expected {})",
                    envelope.schema_version, SNAPSHOT_SCHEMA_VERSION
                ),
            )),
        });
    }

    Ok(envelope)
}

fn load_audit<T: serde::de::DeserializeOwned>(
    handle: &SessionHandle,
    rel_path: &str,
) -> Result<T, SessionError> {
    let path = handle.dir.join(rel_path);
    let content = std::fs::read_to_string(&path).map_err(|e| SessionError::Io {
        path: path.clone(),
        source: e,
    })?;
    serde_json::from_str(&content).map_err(|e| SessionError::Json { path, source: e })
}

fn payload_sha256<T: serde::de::DeserializeOwned + Serialize>(
    payload: &T,
    path: &Path,
) -> Result<String, SessionError> {
    let payload_json = canonical_payload_bytes(payload, path)?;
    Ok(sha256_hex(&payload_json))
}

fn canonical_payload_bytes<T: Serialize>(
    payload: &T,
    path: &Path,
) -> Result<Vec<u8>, SessionError> {
    let mut value = serde_json::to_value(payload).map_err(|e| SessionError::Json {
        path: path.to_path_buf(),
        source: e,
    })?;
    canonicalize_json(&mut value);
    serde_json::to_vec(&value).map_err(|e| SessionError::Json {
        path: path.to_path_buf(),
        source: e,
    })
}

pub(crate) fn canonicalize_json(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            // Rebuild object with sorted keys, recursively canonicalizing children.
            let mut keys: Vec<String> = map.keys().cloned().collect();
            keys.sort();
            let mut new_map = serde_json::Map::with_capacity(map.len());
            for k in keys {
                if let Some(mut v) = map.remove(&k) {
                    canonicalize_json(&mut v);
                    new_map.insert(k, v);
                }
            }
            *map = new_map;
        }
        serde_json::Value::Array(arr) => {
            for v in arr {
                canonicalize_json(v);
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Write the inventory artifact for a session.
pub fn persist_inventory(
    handle: &SessionHandle,
    session_id: &str,
    host_id: &str,
    artifact: InventoryArtifact,
) -> Result<PathBuf, SessionError> {
    let envelope = ArtifactEnvelope::new(session_id, host_id, artifact);
    persist_artifact(handle, INVENTORY_FILE, envelope)
}

/// Write the inference artifact for a session.
pub fn persist_inference(
    handle: &SessionHandle,
    session_id: &str,
    host_id: &str,
    artifact: InferenceArtifact,
) -> Result<PathBuf, SessionError> {
    validate_inference_ledgers(&artifact, &handle.dir.join(INFERENCE_FILE))?;
    let envelope = ArtifactEnvelope::new(session_id, host_id, artifact);
    persist_artifact(handle, INFERENCE_FILE, envelope)
}

/// Write the plan artifact for a session.
pub fn persist_plan(
    handle: &SessionHandle,
    session_id: &str,
    host_id: &str,
    artifact: PlanArtifact,
) -> Result<PathBuf, SessionError> {
    let envelope = ArtifactEnvelope::new(session_id, host_id, artifact);
    persist_artifact(handle, PLAN_FILE, envelope)
}

/// Write run metadata for a session.
pub fn persist_run_metadata(
    handle: &SessionHandle,
    session_id: &str,
    host_id: &str,
    metadata: RunMetadata,
) -> Result<PathBuf, SessionError> {
    let envelope = ArtifactEnvelope::new(session_id, host_id, metadata);
    persist_artifact(handle, META_FILE, envelope)
}

/// Write provenance graph for a session.
pub fn persist_provenance(
    handle: &SessionHandle,
    session_id: &str,
    host_id: &str,
    artifact: ProvenanceArtifact,
) -> Result<PathBuf, SessionError> {
    let envelope = ArtifactEnvelope::new(session_id, host_id, artifact);
    let path = persist_artifact(handle, PROVENANCE_FILE, envelope)?;
    let persisted = load_artifact_unchecked::<ProvenanceArtifact>(handle, PROVENANCE_FILE)?;
    let audit = ProvenancePersistenceAudit::from_envelope(&persisted);
    persist_audit(handle, PROVENANCE_AUDIT_FILE, &audit)?;
    Ok(path)
}

/// Load the inventory artifact with validation.
pub fn load_inventory(
    handle: &SessionHandle,
) -> Result<ArtifactEnvelope<InventoryArtifact>, SessionError> {
    load_artifact(handle, INVENTORY_FILE)
}

/// The exact session evidence used to label a recorded process. These files
/// are read from one pinned session directory, with bounded no-follow reads.
pub struct RecordedLabelInventory {
    pub manifest: SessionManifest,
    pub context: SessionContext,
    pub inventory: ArtifactEnvelope<InventoryArtifact>,
}

/// Load intact local evidence for retrospective human feedback. Unlike display
/// readers, this refuses redirected or concurrently replaced evidence before
/// any label or learned prior is written. Callers must also check session/host
/// consistency and the target's command and birth identity.
#[cfg(unix)]
pub fn load_label_inventory(
    handle: &SessionHandle,
) -> Result<RecordedLabelInventory, SessionError> {
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    fn evidence_error(path: &Path, message: &str) -> SessionError {
        SessionError::Io {
            path: path.to_path_buf(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, message),
        }
    }

    fn open_at(
        parent: &std::fs::File,
        name: &str,
        directory: bool,
        path: &Path,
    ) -> Result<std::fs::File, SessionError> {
        let name = std::ffi::CString::new(name)
            .map_err(|_| evidence_error(path, "invalid recorded evidence filename"))?;
        let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
        // SAFETY: parent is live, name is NUL-terminated, and the descriptor is
        // transferred into File exactly once after a successful openat.
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                flags | if directory { libc::O_DIRECTORY } else { 0 },
            )
        };
        if fd < 0 {
            return Err(SessionError::Io {
                path: path.to_path_buf(),
                source: std::io::Error::last_os_error(),
            });
        }
        Ok(unsafe { std::fs::File::from_raw_fd(fd) })
    }

    fn metadata(file: &std::fs::File, path: &Path) -> Result<std::fs::Metadata, SessionError> {
        file.metadata().map_err(|source| SessionError::Io {
            path: path.to_path_buf(),
            source,
        })
    }

    fn same_file(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
        a.dev() == b.dev()
            && a.ino() == b.ino()
            && a.len() == b.len()
            && a.mtime() == b.mtime()
            && a.mtime_nsec() == b.mtime_nsec()
            && a.ctime() == b.ctime()
            && a.ctime_nsec() == b.ctime_nsec()
    }

    fn read_file(
        directory: &std::fs::File,
        name: &str,
        path: &Path,
        max_bytes: u64,
    ) -> Result<Vec<u8>, SessionError> {
        let file = open_at(directory, name, false, path)?;
        let before = metadata(&file, path)?;
        if !before.is_file() || before.len() > max_bytes {
            return Err(evidence_error(
                path,
                "label evidence must be a bounded regular file",
            ));
        }
        let mut bytes = Vec::new();
        (&file)
            .take(max_bytes + 1)
            .read_to_end(&mut bytes)
            .map_err(|source| SessionError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        let after = metadata(&file, path)?;
        let current = metadata(&open_at(directory, name, false, path)?, path)?;
        if !same_file(&before, &after)
            || !same_file(&after, &current)
            || bytes.len() as u64 != before.len()
            || !current.is_file()
        {
            return Err(evidence_error(
                path,
                "recorded label evidence changed while reading",
            ));
        }
        Ok(bytes)
    }

    // Validate even handles assembled by callers rather than SessionStore.
    if !handle.id.0.is_ascii()
        || pt_common::SessionId::parse(&handle.id.0).is_none()
        || handle.dir.file_name().and_then(|name| name.to_str()) != Some(handle.id.0.as_str())
    {
        return Err(evidence_error(
            &handle.dir,
            "invalid recorded session identity",
        ));
    }
    let root_path = handle
        .dir
        .parent()
        .ok_or_else(|| evidence_error(&handle.dir, "recorded session lacks a store directory"))?;
    let root = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root_path)
        .map_err(|source| SessionError::Io {
            path: root_path.to_path_buf(),
            source,
        })?;
    let session = open_at(&root, &handle.id.0, true, &handle.dir)?;
    let scan_path = handle.dir.join("scan");
    let scan = open_at(&session, "scan", true, &scan_path)?;
    let manifest_path = handle.manifest_path();
    let context_path = handle.context_path();
    let inventory_path = handle.dir.join(INVENTORY_FILE);
    let manifest_bytes = read_file(&session, "manifest.json", &manifest_path, 1024 * 1024)?;
    let context_bytes = read_file(&session, "context.json", &context_path, 1024 * 1024)?;
    let inventory_bytes = read_file(&scan, "inventory.json", &inventory_path, 64 * 1024 * 1024)?;
    for (parent, name, pinned, path) in [
        (&root, handle.id.0.as_str(), &session, &handle.dir),
        (&session, "scan", &scan, &scan_path),
    ] {
        let before = metadata(pinned, path)?;
        let current = metadata(&open_at(parent, name, true, path)?, path)?;
        if before.dev() != current.dev() || before.ino() != current.ino() {
            return Err(evidence_error(
                path,
                "recorded session directory changed while reading",
            ));
        }
    }
    let manifest =
        serde_json::from_slice(&manifest_bytes).map_err(|source| SessionError::Json {
            path: manifest_path,
            source,
        })?;
    let context = serde_json::from_slice(&context_bytes).map_err(|source| SessionError::Json {
        path: context_path,
        source,
    })?;
    let inventory =
        serde_json::from_slice(&inventory_bytes).map_err(|source| SessionError::Json {
            path: inventory_path.clone(),
            source,
        })?;
    Ok(RecordedLabelInventory {
        manifest,
        context,
        inventory: validate_artifact(inventory, &inventory_path)?,
    })
}

#[cfg(not(unix))]
pub fn load_label_inventory(
    handle: &SessionHandle,
) -> Result<RecordedLabelInventory, SessionError> {
    Err(SessionError::Io {
        path: handle.dir.clone(),
        source: std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "recorded labels require no-follow session reads on a supported Unix platform",
        ),
    })
}

/// Load the inventory artifact but skip integrity validation.
pub fn load_inventory_unchecked(
    handle: &SessionHandle,
) -> Result<ArtifactEnvelope<InventoryArtifact>, SessionError> {
    load_artifact_unchecked(handle, INVENTORY_FILE)
}

/// Load the inference artifact with validation.
pub fn load_inference(
    handle: &SessionHandle,
) -> Result<ArtifactEnvelope<InferenceArtifact>, SessionError> {
    let envelope: ArtifactEnvelope<InferenceArtifact> = load_artifact(handle, INFERENCE_FILE)?;
    validate_inference_ledgers(&envelope.payload, &handle.dir.join(INFERENCE_FILE))?;
    Ok(envelope)
}

/// Preserve a recorded ledger as JSON instead of reconstructing floating-point
/// log terms. A nested null can represent an unbounded term; a null or scalar
/// ledger cannot represent recorded evidence or round-trip through Option.
fn validate_inference_ledgers(
    artifact: &InferenceArtifact,
    path: &Path,
) -> Result<(), SessionError> {
    for candidate in &artifact.candidates {
        if candidate
            .evidence_ledger
            .as_ref()
            .is_some_and(|ledger| !ledger.is_object())
        {
            return Err(SessionError::Json {
                path: path.to_path_buf(),
                source: serde_json::Error::io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "recorded evidence ledger for PID {} must be an object",
                        candidate.pid
                    ),
                )),
            });
        }
    }
    Ok(())
}

/// Load the inference artifact but skip integrity validation.
pub fn load_inference_unchecked(
    handle: &SessionHandle,
) -> Result<ArtifactEnvelope<InferenceArtifact>, SessionError> {
    load_artifact_unchecked(handle, INFERENCE_FILE)
}

/// Historical explanation inputs. These are recorded values, never a rescore of
/// a live PID or a reconstruction using the reader's current configuration.
#[derive(Debug)]
pub struct RecordedExplanationSnapshot {
    pub candidates: BTreeMap<u32, serde_json::Value>,
    pub protected: BTreeMap<u32, RecordedProtection>,
    pub source: serde_json::Value,
    pub activity_window_ms: Option<u64>,
}

#[derive(Debug)]
pub struct RecordedProtection {
    pub rule: String,
    /// Older plans recorded exclusion rules by PID alone.
    pub start_id: Option<pt_common::StartId>,
}

fn valid_recorded_start_id(pid: u32, start_id: &str) -> bool {
    pt_common::StartId::is_observation_for(start_id, pid)
}

fn valid_recorded_posterior(values: &[f64]) -> bool {
    values.iter().all(|value| (0.0..=1.0).contains(value))
        && (values.iter().sum::<f64>() - 1.0).abs() <= 1e-6
}

/// The inventory and scoring results from one historical observation.
pub type RecordedSnapshotPair = (
    ArtifactEnvelope<InventoryArtifact>,
    ArtifactEnvelope<InferenceArtifact>,
);

/// Read the two checksummed artifacts as one observation. A process may have
/// no inference, but every inference must identify exactly one inventory row.
pub fn load_recorded_snapshot_pair(handle: &SessionHandle) -> Result<RecordedSnapshotPair, String> {
    let inventory =
        load_inventory(handle).map_err(|error| format!("recorded inventory: {error}"))?;
    let inference =
        load_inference(handle).map_err(|error| format!("recorded inference: {error}"))?;
    if inventory.session_id != handle.id.0 || inference.session_id != handle.id.0 {
        return Err("recorded snapshot session ID mismatch".into());
    }
    if inventory.host_id.trim().is_empty() || inventory.host_id != inference.host_id {
        return Err(
            "recorded snapshot host ID mismatch: inventory and inference host IDs differ".into(),
        );
    }
    for (name, timestamp) in [
        ("inventory", &inventory.generated_at),
        ("inference", &inference.generated_at),
    ] {
        chrono::DateTime::parse_from_rfc3339(timestamp)
            .map_err(|_| format!("recorded {name} has an invalid timestamp"))?;
    }
    if inventory.payload.record_count != inventory.payload.records.len()
        || inference.payload.candidate_count != inference.payload.candidates.len()
    {
        return Err("recorded snapshot count mismatch".into());
    }
    let mut identities = BTreeMap::new();
    for process in &inventory.payload.records {
        if !valid_recorded_start_id(process.pid, &process.start_id) {
            return Err(format!(
                "recorded PID {} has an invalid process birth identity",
                process.pid
            ));
        }
        if identities
            .insert(process.pid, process.start_id.as_str())
            .is_some()
        {
            return Err("recorded inventory has duplicate process identities".into());
        }
    }
    let mut scored = std::collections::BTreeSet::new();
    for candidate in &inference.payload.candidates {
        if identities.get(&candidate.pid).copied() != Some(candidate.start_id.as_str()) {
            return Err(format!(
                "recorded PID {} inference does not match its inventory",
                candidate.pid
            ));
        }
        if !scored.insert(candidate.pid) {
            return Err(format!(
                "recorded inference has ambiguous duplicate PID {}",
                candidate.pid
            ));
        }
        if candidate.pid == 0
            || !valid_recorded_posterior(&[
                candidate.posterior_useful,
                candidate.posterior_useful_bad,
                candidate.posterior_abandoned,
                candidate.posterior_zombie,
            ])
        {
            return Err(format!(
                "recorded PID {} has an invalid PID or posterior",
                candidate.pid
            ));
        }
    }
    Ok((inventory, inference))
}

fn recorded_protection(
    summary: &serde_json::Value,
    candidates: &BTreeMap<u32, serde_json::Value>,
) -> Result<BTreeMap<u32, RecordedProtection>, String> {
    let rules: BTreeMap<u32, String> = summary
        .get("protected_by_pid")
        .map(|rules| serde_json::from_value(rules.clone()))
        .transpose()
        .map_err(|error| format!("invalid recorded protection rules: {error}"))?
        .unwrap_or_default();
    let start_ids: Option<BTreeMap<u32, pt_common::StartId>> = summary
        .get("protected_start_ids")
        .map(|ids| serde_json::from_value(ids.clone()))
        .transpose()
        .map_err(|error| format!("invalid recorded protection identities: {error}"))?;
    if start_ids
        .as_ref()
        .is_some_and(|ids| !ids.keys().eq(rules.keys()))
    {
        return Err("recorded protection rules and identities disagree".into());
    }
    rules
        .into_iter()
        .map(|(pid, rule)| {
            if rule.is_empty() || candidates.contains_key(&pid) {
                return Err(format!(
                    "invalid or conflicting recorded protection for PID {pid}"
                ));
            }
            let start_id = start_ids.as_ref().and_then(|ids| ids.get(&pid)).cloned();
            if start_id
                .as_ref()
                .is_some_and(|id| !valid_recorded_start_id(pid, &id.0))
            {
                return Err(format!(
                    "invalid recorded protection identity for PID {pid}"
                ));
            }
            Ok((pid, RecordedProtection { rule, start_id }))
        })
        .collect()
}

fn index_explanation_candidates(
    candidates: Vec<serde_json::Value>,
) -> Result<BTreeMap<u32, serde_json::Value>, String> {
    let mut indexed = BTreeMap::new();
    for candidate in candidates {
        let pid = candidate["pid"]
            .as_u64()
            .and_then(|pid| u32::try_from(pid).ok())
            .filter(|pid| *pid > 0)
            .ok_or("recorded candidate has an invalid PID")?;
        let start_id = candidate["start_id"]
            .as_str()
            .ok_or("recorded candidate has no process birth identity")?;
        if !valid_recorded_start_id(pid, start_id) {
            return Err(format!(
                "recorded PID {pid} has an invalid process birth identity"
            ));
        }
        if candidate["uid"]
            .as_u64()
            .is_none_or(|uid| uid > u64::from(u32::MAX))
        {
            return Err(format!("recorded PID {pid} has an invalid owner identity"));
        }
        let probabilities: Option<Vec<f64>> = ["useful", "useful_bad", "abandoned", "zombie"]
            .iter()
            .map(|class| candidate["posterior"][*class].as_f64())
            .collect();
        if probabilities
            .as_ref()
            .is_none_or(|values| !valid_recorded_posterior(values))
        {
            return Err(format!("recorded PID {pid} has an invalid posterior"));
        }
        if indexed.insert(pid, candidate).is_some() {
            return Err(format!(
                "recorded inference has ambiguous duplicate PID {pid}"
            ));
        }
    }
    Ok(indexed)
}

/// Prefer the rich canonical plan so final policy/tree/goal decisions and exact
/// ledgers agree with the approved document. Snapshot-only sessions use the
/// existing checksummed inventory/inference pair, including its saved ledger
/// when available. Older snapshots explicitly lack that evidence.
/// A corrupt available artifact is an error, never permission to inspect a new
/// process that happens to have the same PID.
pub fn load_recorded_explanation_snapshot(
    handle: &SessionHandle,
) -> Result<RecordedExplanationSnapshot, String> {
    let mut plan_source = None;
    match std::fs::read(handle.dir.join(PLAN_FILE)) {
        Ok(bytes) => {
            let plan: serde_json::Value = serde_json::from_slice(&bytes)
                .map_err(|error| format!("invalid recorded plan: {error}"))?;
            if plan["session_id"].as_str() != Some(handle.id.0.as_str()) {
                return Err("recorded plan session ID mismatch".into());
            }
            let source = serde_json::json!({
                "artifact": PLAN_FILE,
                "session_id": plan["session_id"],
                "sha256": sha256_hex(&bytes),
                "observed_at": plan["generated_at"],
                "host_id": plan["host_id"],
            });
            if let Some(candidates) = plan.get("candidates") {
                let candidates = candidates
                    .as_array()
                    .ok_or("recorded plan candidates must be an array")?;
                let candidates = index_explanation_candidates(candidates.clone())?;
                return Ok(RecordedExplanationSnapshot {
                    protected: recorded_protection(&plan["summary"], &candidates)?,
                    candidates,
                    source,
                    activity_window_ms: plan["args"]["window_ms"].as_u64(),
                });
            }
            plan_source = Some(source);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("cannot read recorded plan: {error}")),
    }

    // An older action-only plan can still be inspected, but contains no recorded
    // inference. Do not substitute its action rationale for a full posterior.
    let inference_path = handle.dir.join(INFERENCE_FILE);
    match std::fs::metadata(&inference_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return plan_source
                .map(|source| RecordedExplanationSnapshot {
                    candidates: BTreeMap::new(),
                    protected: BTreeMap::new(),
                    source,
                    activity_window_ms: None,
                })
                .ok_or_else(|| {
                    "no recorded session inference found; use --live for a new observation".into()
                });
        }
        Err(error) => return Err(format!("cannot inspect recorded inference: {error}")),
        Ok(_) => {}
    }
    let (inventory, inference) = load_recorded_snapshot_pair(handle)?;
    let records: BTreeMap<_, _> = inventory
        .payload
        .records
        .iter()
        .map(|p| (p.pid, p))
        .collect();
    let candidates = inference
        .payload
        .candidates
        .iter()
        .map(|candidate| {
            let process = records[&candidate.pid];
            let mut recorded = serde_json::json!({
                "pid": candidate.pid,
                "start_id": candidate.start_id,
                "uid": process.uid,
                "ppid": process.ppid,
                "command_short": process.comm,
                "command": process.cmd,
                "state": process.state,
                "start_time_unix": process.start_time_unix,
                "identity_quality": process.identity_quality,
                "age_seconds": process.elapsed_secs,
                "classification": candidate.classification,
                "confidence": candidate.confidence,
                "posterior": {
                    "useful": candidate.posterior_useful,
                    "useful_bad": candidate.posterior_useful_bad,
                    "abandoned": candidate.posterior_abandoned,
                    "zombie": candidate.posterior_zombie,
                },
                "score": candidate.score,
                "recommended_action": candidate.recommended_action,
            });
            if let Some(ledger) = &candidate.evidence_ledger {
                recorded["evidence_ledger"] = ledger.clone();
            }
            if let Some(level) = &candidate.blast_radius_risk_level {
                recorded["blast_radius_risk_level"] = serde_json::json!(level);
            }
            if let Some(affected) = candidate.blast_radius_total_affected {
                recorded["blast_radius_total_affected"] = serde_json::json!(affected);
            }
            if let Some(completeness) = candidate.provenance_evidence_completeness {
                recorded["provenance_evidence_completeness"] = serde_json::json!(completeness);
            }
            if !candidate.provenance_score_terms.is_empty() {
                recorded["provenance_score_terms"] =
                    serde_json::json!(candidate.provenance_score_terms);
            }
            if let Some(shift) = candidate.provenance_log_odds_shift {
                recorded["provenance_log_odds_shift"] = serde_json::json!(shift);
            }
            (candidate.pid, recorded)
        })
        .collect();
    Ok(RecordedExplanationSnapshot {
        candidates,
        protected: BTreeMap::new(),
        source: serde_json::json!({
            "artifact": INFERENCE_FILE,
            "session_id": inference.session_id,
            "integrity_sha256": inference.integrity_sha256,
            "inventory_integrity_sha256": inventory.integrity_sha256,
            "observed_at": inference.generated_at,
            "host_id": inference.host_id,
            "total_system_processes": inventory.payload.total_system_processes,
            "protected_filtered": inventory.payload.protected_filtered,
        }),
        activity_window_ms: None,
    })
}

/// Load the plan artifact with validation.
pub fn load_plan(handle: &SessionHandle) -> Result<ArtifactEnvelope<PlanArtifact>, SessionError> {
    load_artifact(handle, PLAN_FILE)
}

/// Load run metadata with validation.
pub fn load_run_metadata(
    handle: &SessionHandle,
) -> Result<ArtifactEnvelope<RunMetadata>, SessionError> {
    load_artifact(handle, META_FILE)
}

/// Load the provenance artifact with validation.
pub fn load_provenance(
    handle: &SessionHandle,
) -> Result<ArtifactEnvelope<ProvenanceArtifact>, SessionError> {
    load_artifact(handle, PROVENANCE_FILE)
}

/// Load the provenance artifact but skip integrity validation.
pub fn load_provenance_unchecked(
    handle: &SessionHandle,
) -> Result<ArtifactEnvelope<ProvenanceArtifact>, SessionError> {
    load_artifact_unchecked(handle, PROVENANCE_FILE)
}

/// Load the provenance persistence audit sidecar.
pub fn load_provenance_audit(
    handle: &SessionHandle,
) -> Result<ProvenancePersistenceAudit, SessionError> {
    load_audit(handle, PROVENANCE_AUDIT_FILE)
}

/// Check which artifacts are present in a session directory.
pub fn list_artifacts(handle: &SessionHandle) -> Vec<String> {
    let mut present = Vec::new();
    for (name, rel) in [
        ("inventory", INVENTORY_FILE),
        ("inference", INFERENCE_FILE),
        ("plan", PLAN_FILE),
        ("run_metadata", META_FILE),
        ("provenance", PROVENANCE_FILE),
        ("provenance_audit", PROVENANCE_AUDIT_FILE),
    ] {
        if handle.dir.join(rel).exists() {
            present.push(name.to_string());
        }
    }
    present
}

// ---------------------------------------------------------------------------
// SHA-256 (minimal, no external crate dependency)
// ---------------------------------------------------------------------------

/// Compute SHA-256 hex digest of bytes.
///
/// Uses a minimal implementation to avoid pulling in a heavy crypto crate
/// just for integrity hashing of small JSON payloads.
fn sha256_hex(data: &[u8]) -> String {
    let hash = sha256(data);
    let mut hex = String::with_capacity(SHA256_HEX_LEN);
    for byte in &hash {
        hex.push_str(&format!("{:02x}", byte));
    }
    hex
}

/// Minimal SHA-256 (FIPS 180-4). Not constant-time — fine for integrity, not crypto.
fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    // Padding
    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    // Process blocks
    // Padding above makes `msg.len()` a multiple of 64, so the remainder is empty.
    for chunk in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut result = [0u8; 32];
    for (i, val) in h.iter().enumerate() {
        result[i * 4..i * 4 + 4].copy_from_slice(&val.to_be_bytes());
    }
    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use pt_common::{
        ProcessId, ProvenanceConfidence, ProvenanceEdge, ProvenanceEdgeId, ProvenanceEdgeKind,
        ProvenanceEvidence, ProvenanceEvidenceId, ProvenanceEvidenceKind, ProvenanceGraphSnapshot,
        ProvenanceNode, ProvenanceNodeId, ProvenanceNodeKind, ProvenanceObservationStatus,
        ProvenanceProcessRef, ProvenanceRedactionState, StartId, PROVENANCE_SCHEMA_VERSION,
    };
    use tempfile::TempDir;

    fn make_handle(tmp: &TempDir) -> SessionHandle {
        let dir = tmp.path().join("pt-20260201-120000-abcd");
        std::fs::create_dir_all(dir.join("scan")).unwrap();
        std::fs::create_dir_all(dir.join("inference")).unwrap();
        std::fs::create_dir_all(dir.join("decision")).unwrap();
        SessionHandle {
            id: pt_common::SessionId("pt-20260201-120000-abcd".to_string()),
            dir,
        }
    }

    fn sample_inventory() -> InventoryArtifact {
        InventoryArtifact {
            total_system_processes: 300,
            protected_filtered: 50,
            record_count: 2,
            records: vec![
                PersistedProcess {
                    pid: 1234,
                    ppid: 1,
                    uid: 1000,
                    start_id: "boot1:12345:1234".to_string(),
                    comm: "node".to_string(),
                    cmd: "node server.js".to_string(),
                    state: "S".to_string(),
                    start_time_unix: 1700000000,
                    elapsed_secs: 86400,
                    identity_quality: "Full".to_string(),
                },
                PersistedProcess {
                    pid: 5678,
                    ppid: 1234,
                    uid: 1000,
                    start_id: "boot1:12346:5678".to_string(),
                    comm: "worker".to_string(),
                    cmd: "node worker.js".to_string(),
                    state: "S".to_string(),
                    start_time_unix: 1700000100,
                    elapsed_secs: 86300,
                    identity_quality: "Full".to_string(),
                },
            ],
        }
    }

    fn sample_inference() -> InferenceArtifact {
        InferenceArtifact {
            candidate_count: 1,
            candidates: vec![PersistedInference {
                pid: 1234,
                start_id: "boot1:12345:1234".to_string(),
                classification: "abandoned".to_string(),
                posterior_useful: 0.05,
                posterior_useful_bad: 0.02,
                posterior_abandoned: 0.90,
                posterior_zombie: 0.03,
                confidence: "high".to_string(),
                recommended_action: "kill".to_string(),
                score: 92,
                evidence_ledger: None,
                blast_radius_risk_level: None,
                blast_radius_total_affected: None,
                provenance_evidence_completeness: None,
                provenance_score_terms: Vec::new(),
                provenance_log_odds_shift: None,
            }],
        }
    }

    fn sample_plan() -> PlanArtifact {
        PlanArtifact {
            action_count: 1,
            kill_count: 1,
            review_count: 0,
            spare_count: 0,
            actions: vec![PersistedPlanAction {
                pid: 1234,
                start_id: "boot1:12345:1234".to_string(),
                action: "kill".to_string(),
                expected_loss: 0.12,
                rationale: "P(abandoned)=0.90, low blast radius".to_string(),
            }],
        }
    }

    #[test]
    fn snapshot_ledger_preserves_recorded_wire_evidence_and_detects_tampering() {
        use crate::inference::{compute_posterior, CpuEvidence, Evidence, EvidenceLedger};

        let tmp = TempDir::new().unwrap();
        let handle = make_handle(&tmp);
        let evidence = Evidence {
            cpu: Some(CpuEvidence::Fraction { occupancy: 0.001 }),
            runtime_seconds: Some(86400.0),
            orphan: Some(true),
            tty: Some(false),
            ..Evidence::default()
        };
        let posterior =
            compute_posterior(&crate::config::priors::Priors::default(), &evidence).unwrap();
        let mut ledger = serde_json::to_value(EvidenceLedger::from_posterior_result(
            &posterior,
            Some(1234),
            None,
        ))
        .unwrap();
        // Wire-format evidence can contain null for a non-finite log term, and
        // future scorer fields must survive without deserializing into today's
        // typed ledger or recomputing its numbers.
        ledger["future_evidence"] = serde_json::json!({
            "log_likelihood": null,
            "precise_term": 1.2345678901234567,
            "small_term": 1.0e-200,
            "negative_zero": -0.0,
        });
        let mut inference = sample_inference();
        let candidate = &mut inference.candidates[0];
        candidate.posterior_useful = posterior.posterior.useful;
        candidate.posterior_useful_bad = posterior.posterior.useful_bad;
        candidate.posterior_abandoned = posterior.posterior.abandoned;
        candidate.posterior_zombie = posterior.posterior.zombie;
        candidate.score = posterior.posterior.suspicion_score();
        candidate.evidence_ledger = Some(ledger.clone());
        persist_inventory(&handle, &handle.id.0, "host1", sample_inventory()).unwrap();
        let path = persist_inference(&handle, &handle.id.0, "host1", inference).unwrap();

        let loaded = load_inference(&handle).unwrap();
        assert_eq!(
            loaded.payload.candidates[0].evidence_ledger,
            Some(ledger.clone())
        );
        let saved = load_recorded_explanation_snapshot(&handle).unwrap();
        assert_eq!(saved.candidates[&1234]["evidence_ledger"], ledger);
        assert_eq!(
            saved.candidates[&1234]["posterior"],
            serde_json::json!(posterior.posterior)
        );
        assert_eq!(saved.source["session_id"], handle.id.0);
        assert_eq!(saved.source["total_system_processes"], 300);
        assert_eq!(saved.source["protected_filtered"], 50);
        assert!(!handle.dir.join(PLAN_FILE).exists());

        let mut corrupted: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        corrupted["payload"]["candidates"][0]["evidence_ledger"]["why_summary"] =
            serde_json::json!("a rewritten explanation");
        std::fs::write(path, serde_json::to_vec(&corrupted).unwrap()).unwrap();
        assert!(load_recorded_explanation_snapshot(&handle)
            .unwrap_err()
            .contains("integrity check failed"));
    }

    #[test]
    fn snapshot_ledger_requires_an_object_without_replacing_valid_evidence() {
        let tmp = TempDir::new().unwrap();
        let handle = make_handle(&tmp);
        let mut inference = sample_inference();
        inference.candidates[0].evidence_ledger =
            Some(serde_json::json!({"why_summary": "original observation"}));
        let path = persist_inference(&handle, &handle.id.0, "host1", inference.clone()).unwrap();
        let original = std::fs::read(&path).unwrap();
        for invalid in [
            serde_json::Value::Null,
            serde_json::json!([]),
            serde_json::json!("discarded evidence"),
            serde_json::json!(42),
        ] {
            inference.candidates[0].evidence_ledger = Some(invalid);
            assert!(
                persist_inference(&handle, &handle.id.0, "host1", inference.clone())
                    .unwrap_err()
                    .to_string()
                    .contains("must be an object")
            );
            assert_eq!(std::fs::read(&path).unwrap(), original);
        }

        // Even an integrity-valid envelope from another writer must meet the
        // same shape contract when it is loaded.
        let envelope = ArtifactEnvelope::new(&handle.id.0, "host1", inference);
        persist_artifact(&handle, INFERENCE_FILE, envelope).unwrap();
        assert!(load_inference(&handle)
            .unwrap_err()
            .to_string()
            .contains("must be an object"));
    }

    #[test]
    fn snapshot_ledger_is_optional_for_legacy_integrity_and_explanations() {
        let tmp = TempDir::new().unwrap();
        let handle = make_handle(&tmp);
        persist_inventory(&handle, &handle.id.0, "host1", sample_inventory()).unwrap();
        let path = persist_inference(&handle, &handle.id.0, "host1", sample_inference()).unwrap();
        let old_bytes = std::fs::read(&path).unwrap();
        let old_envelope: serde_json::Value = serde_json::from_slice(&old_bytes).unwrap();
        assert!(old_envelope["payload"]["candidates"][0]
            .get("evidence_ledger")
            .is_none());
        let loaded = load_inference(&handle).unwrap();
        assert!(loaded.payload.candidates[0].evidence_ledger.is_none());
        assert_eq!(serde_json::to_value(loaded).unwrap(), old_envelope);
        let saved = load_recorded_explanation_snapshot(&handle).unwrap();
        assert!(saved.candidates[&1234].get("evidence_ledger").is_none());
        assert_eq!(std::fs::read(path).unwrap(), old_bytes);
    }

    #[test]
    fn recorded_explanations_prefer_final_plan_without_rescoring() {
        let tmp = TempDir::new().unwrap();
        let handle = make_handle(&tmp);
        persist_inventory(&handle, &handle.id.0, "host1", sample_inventory()).unwrap();
        persist_inference(&handle, &handle.id.0, "host1", sample_inference()).unwrap();
        let candidate = serde_json::json!({
            "pid": 1234, "start_id": "boot1:12345:1234", "uid": 1000,
            "posterior": {"useful": 0.01, "useful_bad": 0.01, "abandoned": 0.97, "zombie": 0.01},
            "score": 98, "recommended_action": "review",
            "evidence_ledger": {"why_summary": "recorded explanation", "precise_term": 1.23456789012345},
        });
        let plan = serde_json::json!({
            "session_id": handle.id.0, "host_id": "host1",
            "generated_at": "2026-01-01T00:00:00Z", "args": {"window_ms": 750},
            "candidates": [candidate.clone()],
        });
        let bytes = serde_json::to_vec(&plan).unwrap();
        std::fs::write(handle.dir.join(PLAN_FILE), &bytes).unwrap();
        let saved = load_recorded_explanation_snapshot(&handle).unwrap();
        assert_eq!(saved.candidates[&1234], candidate);
        assert_eq!(saved.source["sha256"], sha256_hex(&bytes));
        assert_eq!(saved.source["observed_at"], "2026-01-01T00:00:00Z");
        assert_eq!(saved.activity_window_ms, Some(750));

        // Valid compact data must never hide a corrupt canonical plan.
        std::fs::write(handle.dir.join(PLAN_FILE), b"{interrupted").unwrap();
        assert!(load_recorded_explanation_snapshot(&handle)
            .unwrap_err()
            .contains("invalid recorded plan"));
    }

    #[test]
    fn unavailable_birth_can_join_artifacts_only_within_its_recorded_observation() {
        let tmp = TempDir::new().unwrap();
        let handle = make_handle(&tmp);
        let mut inventory = sample_inventory();
        let mut inference = sample_inference();
        let pid = inventory.records[0].pid;
        let tag = pt_common::StartId::unverified(pid);
        inventory.records[0].start_id = tag.0.clone();
        inference.candidates[0].start_id = tag.0;
        persist_inventory(&handle, &handle.id.0, "host1", inventory).unwrap();
        persist_inference(&handle, &handle.id.0, "host1", inference.clone()).unwrap();
        assert!(load_recorded_snapshot_pair(&handle).is_ok());

        inference.candidates[0].start_id = pt_common::StartId::unverified(pid).0;
        persist_inference(&handle, &handle.id.0, "host1", inference).unwrap();
        assert!(load_recorded_snapshot_pair(&handle).is_err());
    }

    #[test]
    fn recorded_protection_validates_birth_id_and_handles_pid_only_plans() {
        let candidates = BTreeMap::new();
        let mut summary = serde_json::json!({"protected_by_pid": {"12": "builtin.invoker_chain"}});
        let legacy = recorded_protection(&summary, &candidates).unwrap();
        assert_eq!(legacy[&12].rule, "builtin.invoker_chain");
        assert!(legacy[&12].start_id.is_none());
        for invalid in [
            serde_json::json!({}),
            serde_json::json!({"12":"boot:100:11"}),
            serde_json::json!({"12":"invalid"}),
            serde_json::json!({"12":"boot:100:12", "13":"boot:101:13"}),
        ] {
            summary["protected_start_ids"] = invalid;
            assert!(recorded_protection(&summary, &candidates).is_err());
        }
        summary["protected_start_ids"] = serde_json::json!({"12":"boot:100:12"});
        let saved = recorded_protection(&summary, &candidates).unwrap();
        assert_eq!(saved[&12].start_id.as_ref().unwrap().0, "boot:100:12");
        assert!(
            recorded_protection(&summary, &BTreeMap::from([(12, serde_json::Value::Null)]))
                .is_err()
        );
    }

    #[test]
    fn recorded_snapshot_projection_retains_observed_identity_and_provenance() {
        let tmp = TempDir::new().unwrap();
        let handle = make_handle(&tmp);
        let mut inventory = sample_inventory();
        inventory.records[0].start_time_unix = 1700000123;
        inventory.records[0].identity_quality = "QuickScan".to_string();
        let mut inference = sample_inference();
        let candidate = &mut inference.candidates[0];
        candidate.blast_radius_risk_level = Some("low".to_string());
        candidate.blast_radius_total_affected = Some(0);
        candidate.provenance_evidence_completeness = Some(0.625);
        candidate.provenance_score_terms = vec!["shared_resource".to_string()];
        candidate.provenance_log_odds_shift = Some(0.0);
        let inventory_path = persist_inventory(&handle, &handle.id.0, "host1", inventory).unwrap();
        let inference_path = persist_inference(&handle, &handle.id.0, "host1", inference).unwrap();
        let inventory_bytes = std::fs::read(&inventory_path).unwrap();
        let inference_bytes = std::fs::read(&inference_path).unwrap();
        let inventory: serde_json::Value = serde_json::from_slice(&inventory_bytes).unwrap();
        let inference: serde_json::Value = serde_json::from_slice(&inference_bytes).unwrap();

        let saved = load_recorded_explanation_snapshot(&handle).unwrap();
        let candidate = &saved.candidates[&1234];
        for field in ["start_time_unix", "identity_quality"] {
            assert_eq!(
                candidate.get(field),
                inventory["payload"]["records"][0].get(field),
                "{field}"
            );
            assert!(candidate.get(field).is_some(), "{field}");
        }
        for field in [
            "blast_radius_risk_level",
            "blast_radius_total_affected",
            "provenance_evidence_completeness",
            "provenance_score_terms",
            "provenance_log_odds_shift",
        ] {
            assert_eq!(
                candidate.get(field),
                inference["payload"]["candidates"][0].get(field),
                "{field}"
            );
            assert!(candidate.get(field).is_some(), "{field}");
        }
        // Explicit zero observations are retained, not mistaken for unknowns.
        assert_eq!(candidate["blast_radius_total_affected"], 0);
        assert_eq!(candidate["provenance_log_odds_shift"], 0.0);
        assert_eq!(std::fs::read(inventory_path).unwrap(), inventory_bytes);
        assert_eq!(std::fs::read(inference_path).unwrap(), inference_bytes);
        assert!(!handle.dir.join(PLAN_FILE).exists());
    }

    #[test]
    fn recorded_explanations_validate_snapshot_identity_and_integrity() {
        let tmp = TempDir::new().unwrap();
        let handle = make_handle(&tmp);
        persist_inventory(&handle, &handle.id.0, "host1", sample_inventory()).unwrap();
        persist_inference(&handle, &handle.id.0, "host1", sample_inference()).unwrap();
        let saved = load_recorded_explanation_snapshot(&handle).unwrap();
        assert_eq!(saved.candidates[&1234]["command"], "node server.js");
        assert_eq!(saved.candidates[&1234]["posterior"]["abandoned"], 0.90);
        for field in [
            "evidence_ledger",
            "blast_radius_risk_level",
            "blast_radius_total_affected",
            "provenance_evidence_completeness",
            "provenance_score_terms",
            "provenance_log_odds_shift",
        ] {
            assert!(saved.candidates[&1234].get(field).is_none(), "{field}");
        }
        assert!(saved.activity_window_ms.is_none());

        let mut duplicate_inventory = sample_inventory();
        duplicate_inventory.records[1].pid = 1234;
        duplicate_inventory.records[1].start_id = "boot1:99999:1234".into();
        persist_inventory(&handle, &handle.id.0, "host1", duplicate_inventory).unwrap();
        assert!(load_recorded_explanation_snapshot(&handle)
            .unwrap_err()
            .contains("duplicate process identities"));
        persist_inventory(&handle, &handle.id.0, "host1", sample_inventory()).unwrap();

        let mut wrong_identity = sample_inference();
        wrong_identity.candidates[0].start_id = "boot1:99999:1234".into();
        persist_inference(&handle, &handle.id.0, "host1", wrong_identity).unwrap();
        assert!(load_recorded_explanation_snapshot(&handle)
            .unwrap_err()
            .contains("does not match its inventory"));

        persist_inference(&handle, &handle.id.0, "other-host", sample_inference()).unwrap();
        assert!(load_recorded_explanation_snapshot(&handle)
            .unwrap_err()
            .contains("host IDs differ"));
        persist_inference(&handle, "other-session", "host1", sample_inference()).unwrap();
        assert!(load_recorded_explanation_snapshot(&handle)
            .unwrap_err()
            .contains("session ID mismatch"));

        let mut duplicate = sample_inference();
        duplicate.candidates.push(duplicate.candidates[0].clone());
        duplicate.candidate_count = 2;
        persist_inference(&handle, &handle.id.0, "host1", duplicate).unwrap();
        assert!(load_recorded_explanation_snapshot(&handle)
            .unwrap_err()
            .contains("duplicate PID"));

        persist_inference(&handle, &handle.id.0, "host1", sample_inference()).unwrap();
        let path = handle.dir.join(INFERENCE_FILE);
        let mut corrupted: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        corrupted["payload"]["candidates"][0]["score"] = serde_json::json!(0);
        std::fs::write(path, serde_json::to_vec(&corrupted).unwrap()).unwrap();
        assert!(load_recorded_explanation_snapshot(&handle).is_err());
    }

    #[test]
    fn recorded_explanations_refuse_invalid_rich_candidates() {
        let tmp = TempDir::new().unwrap();
        let handle = make_handle(&tmp);
        let candidate = serde_json::json!({
            "pid": 1234, "start_id": "boot1:12345:1234", "uid": 1000,
            "posterior": {"useful": 0.05, "useful_bad": 0.02, "abandoned": 0.9, "zombie": 0.03},
        });
        let valid = serde_json::json!({"session_id": handle.id.0, "candidates": [candidate]});
        for (field, value) in [
            ("start_id", serde_json::json!("boot1:12345:5678")),
            ("uid", serde_json::json!(-1)),
            (
                "posterior",
                serde_json::json!({"useful": 1.0, "useful_bad": 1.0, "abandoned": 1.0, "zombie": 1.0}),
            ),
        ] {
            let mut invalid = valid.clone();
            invalid["candidates"][0][field] = value;
            std::fs::write(
                handle.dir.join(PLAN_FILE),
                serde_json::to_vec(&invalid).unwrap(),
            )
            .unwrap();
            assert!(
                load_recorded_explanation_snapshot(&handle).is_err(),
                "{field}"
            );
        }
        let mut foreign = valid;
        foreign["session_id"] = serde_json::json!("different-session");
        std::fs::write(
            handle.dir.join(PLAN_FILE),
            serde_json::to_vec(&foreign).unwrap(),
        )
        .unwrap();
        assert!(load_recorded_explanation_snapshot(&handle)
            .unwrap_err()
            .contains("session ID mismatch"));
    }

    fn sample_metadata() -> RunMetadata {
        RunMetadata {
            pt_version: "2.1.0".to_string(),
            schema_version: SNAPSHOT_SCHEMA_VERSION.to_string(),
            host_id: "devbox1".to_string(),
            hostname: "devbox1.local".to_string(),
            os_family: "linux".to_string(),
            os_arch: "x86_64".to_string(),
            cores: 16,
            memory_total_gb: 64.0,
            priors_hash: "abc123".to_string(),
            policy_hash: "def456".to_string(),
            tags: BTreeMap::new(),
        }
    }

    fn sample_provenance() -> ProvenanceArtifact {
        let evidence_id = ProvenanceEvidenceId::new(
            ProvenanceEvidenceKind::Procfs,
            "procfs:pid=1234:start=boot1:12345:1234",
        );
        let process_id =
            ProvenanceNodeId::new(ProvenanceNodeKind::Process, "process:1234:boot1:12345:1234");
        let workspace_id =
            ProvenanceNodeId::new(ProvenanceNodeKind::Workspace, "workspace:/repo/worktree");
        let edge_id = ProvenanceEdgeId::new(
            ProvenanceEdgeKind::AttachedToWorkspace,
            &process_id,
            &workspace_id,
        );

        ProvenanceGraphSnapshot::new(
            "2026-03-15T01:00:00Z".to_string(),
            Some("pt-20260201-120000-abcd".to_string()),
            Some("devbox1".to_string()),
            vec![
                ProvenanceNode {
                    id: process_id.clone(),
                    kind: ProvenanceNodeKind::Process,
                    label: "pytest".to_string(),
                    confidence: ProvenanceConfidence::High,
                    redaction: ProvenanceRedactionState::None,
                    evidence_ids: vec![evidence_id.clone()],
                    attributes: BTreeMap::from([
                        ("pid".to_string(), serde_json::json!(1234)),
                        ("state".to_string(), serde_json::json!("S")),
                    ]),
                },
                ProvenanceNode {
                    id: workspace_id.clone(),
                    kind: ProvenanceNodeKind::Workspace,
                    label: "/repo/worktree".to_string(),
                    confidence: ProvenanceConfidence::Medium,
                    redaction: ProvenanceRedactionState::Partial,
                    evidence_ids: vec![evidence_id.clone()],
                    attributes: BTreeMap::from([(
                        "repo_root".to_string(),
                        serde_json::json!("/repo"),
                    )]),
                },
            ],
            vec![ProvenanceEdge {
                id: edge_id,
                kind: ProvenanceEdgeKind::AttachedToWorkspace,
                from: process_id,
                to: workspace_id,
                confidence: ProvenanceConfidence::Medium,
                redaction: ProvenanceRedactionState::Partial,
                evidence_ids: vec![evidence_id.clone()],
                derived_from_edge_ids: Vec::new(),
                attributes: BTreeMap::from([(
                    "reason".to_string(),
                    serde_json::json!("cwd_under_workspace"),
                )]),
            }],
            vec![ProvenanceEvidence {
                id: evidence_id,
                kind: ProvenanceEvidenceKind::Procfs,
                source: "/proc/1234/stat".to_string(),
                observed_at: "2026-03-15T01:00:00Z".to_string(),
                status: ProvenanceObservationStatus::Observed,
                confidence: ProvenanceConfidence::High,
                redaction: ProvenanceRedactionState::None,
                process: Some(ProvenanceProcessRef {
                    pid: ProcessId(1234),
                    start_id: StartId("boot1:12345:1234".to_string()),
                }),
                attributes: BTreeMap::from([(
                    "collector".to_string(),
                    serde_json::json!("procfs"),
                )]),
            }],
            Vec::new(),
        )
    }

    #[test]
    fn test_sha256_known_vector() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let digest = sha256_hex(b"");
        assert_eq!(
            digest,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_abc() {
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let digest = sha256_hex(b"abc");
        assert_eq!(
            digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_persist_load_inventory() {
        let tmp = TempDir::new().unwrap();
        let handle = make_handle(&tmp);
        let inv = sample_inventory();

        let path = persist_inventory(&handle, "test-session", "host1", inv.clone()).unwrap();
        assert!(path.exists());

        let loaded = load_inventory(&handle).unwrap();
        assert_eq!(loaded.payload.record_count, 2);
        assert_eq!(loaded.payload.records.len(), 2);
        assert_eq!(loaded.payload.records[0].pid, 1234);
        assert_eq!(loaded.session_id, "test-session");
    }

    #[test]
    fn test_persist_load_inference() {
        let tmp = TempDir::new().unwrap();
        let handle = make_handle(&tmp);
        let inf = sample_inference();

        persist_inference(&handle, "s1", "h1", inf).unwrap();
        let loaded = load_inference(&handle).unwrap();
        assert_eq!(loaded.payload.candidate_count, 1);
        assert!((loaded.payload.candidates[0].posterior_abandoned - 0.90).abs() < 0.01);
    }

    #[test]
    fn test_persist_load_plan() {
        let tmp = TempDir::new().unwrap();
        let handle = make_handle(&tmp);
        let plan = sample_plan();

        persist_plan(&handle, "s1", "h1", plan).unwrap();
        let loaded = load_plan(&handle).unwrap();
        assert_eq!(loaded.payload.kill_count, 1);
        assert_eq!(loaded.payload.actions[0].action, "kill");
    }

    #[test]
    fn test_persist_load_metadata() {
        let tmp = TempDir::new().unwrap();
        let handle = make_handle(&tmp);
        let meta = sample_metadata();

        persist_run_metadata(&handle, "s1", "h1", meta).unwrap();
        let loaded = load_run_metadata(&handle).unwrap();
        assert_eq!(loaded.payload.pt_version, "2.1.0");
        assert_eq!(loaded.payload.cores, 16);
    }

    #[test]
    fn test_persist_load_provenance() {
        let tmp = TempDir::new().unwrap();
        let handle = make_handle(&tmp);
        let graph = sample_provenance();

        let path = persist_provenance(&handle, "s1", "h1", graph.clone()).unwrap();
        assert!(path.exists());

        let loaded = load_provenance(&handle).unwrap();
        assert_eq!(loaded.schema_version, SNAPSHOT_SCHEMA_VERSION);
        assert_eq!(loaded.payload.schema_version, PROVENANCE_SCHEMA_VERSION);
        assert_eq!(loaded.payload.summary.node_count, 2);
        assert_eq!(loaded.payload.summary.edge_count, 1);
        assert_eq!(loaded.payload.summary.evidence_count, 1);
        assert_eq!(loaded.payload.nodes[0].evidence_ids.len(), 1);
        assert_eq!(loaded.payload, graph);

        let audit = load_provenance_audit(&handle).unwrap();
        assert_eq!(audit.provenance_schema_version, PROVENANCE_SCHEMA_VERSION);
        assert_eq!(audit.node_count, 2);
        assert_eq!(audit.warning_count, 0);
        assert_eq!(audit.integrity_sha256, loaded.integrity_sha256);
        assert!(audit.omitted_sections.is_empty());
        assert!(audit
            .persisted_sections
            .contains(&"graph.nodes".to_string()));
        assert!(audit.redacted_sections.contains(&"graph.nodes".to_string()));
        assert!(audit.redacted_sections.contains(&"graph.edges".to_string()));
    }

    #[test]
    fn test_provenance_snapshot_ref_tracks_replay_metadata() {
        let tmp = TempDir::new().unwrap();
        let handle = make_handle(&tmp);

        persist_provenance(&handle, "s1", "h1", sample_provenance()).unwrap();
        let audit = load_provenance_audit(&handle).unwrap();
        let reference = audit.snapshot_ref();

        assert_eq!(reference.path, PROVENANCE_FILE);
        assert_eq!(reference.audit_path, PROVENANCE_AUDIT_FILE);
        assert_eq!(
            reference.provenance_schema_version,
            PROVENANCE_SCHEMA_VERSION
        );
        assert_eq!(reference.privacy_version, "1.0.0");
        assert_eq!(reference.node_count, 2);
        assert_eq!(reference.warning_count, 0);
        assert_eq!(reference.missing_or_conflicted_evidence_count, 0);
        assert_eq!(reference.integrity_sha256.len(), SHA256_HEX_LEN);
    }

    #[test]
    fn test_integrity_check_detects_tampering() {
        let tmp = TempDir::new().unwrap();
        let handle = make_handle(&tmp);
        let inv = sample_inventory();

        persist_inventory(&handle, "s1", "h1", inv).unwrap();

        // Tamper with the file: change a PID in the stored JSON.
        let path = handle.dir.join(INVENTORY_FILE);
        let mut content = std::fs::read_to_string(&path).unwrap();
        content = content.replace("1234", "9999");
        std::fs::write(&path, &content).unwrap();

        let result = load_inventory(&handle);
        assert!(result.is_err(), "Should detect integrity mismatch");
    }

    #[test]
    fn test_redaction_none() {
        let cmd = format!(
            "node --{}={} server.js",
            ["secret", "marker"].join("-"),
            "value"
        );
        assert_eq!(redact_cmd(cmd.as_str(), RedactionPolicy::None), cmd);
    }

    #[test]
    fn test_redaction_full() {
        let cmd = "node server.js";
        assert_eq!(redact_cmd(cmd, RedactionPolicy::Full), REDACTED);
    }

    #[test]
    fn test_redaction_standard_sensitive() {
        let password_cmd = ["app --pass", "word=value"].concat();
        let api_key_cmd = ["export API_", "KEY=value"].concat();
        assert_eq!(
            redact_cmd(password_cmd.as_str(), RedactionPolicy::Standard),
            REDACTED
        );
        assert_eq!(
            redact_cmd(api_key_cmd.as_str(), RedactionPolicy::Standard),
            REDACTED
        );
        assert_eq!(
            redact_cmd("curl -H 'Bearer xyz'", RedactionPolicy::Standard),
            REDACTED
        );
    }

    #[test]
    fn test_redaction_standard_safe() {
        let cmd = "node server.js --port 3000";
        assert_eq!(redact_cmd(cmd, RedactionPolicy::Standard), cmd);
    }

    #[test]
    fn test_list_artifacts() {
        let tmp = TempDir::new().unwrap();
        let handle = make_handle(&tmp);

        assert!(list_artifacts(&handle).is_empty());

        persist_inventory(&handle, "s1", "h1", sample_inventory()).unwrap();
        let present = list_artifacts(&handle);
        assert_eq!(present, vec!["inventory"]);

        persist_plan(&handle, "s1", "h1", sample_plan()).unwrap();
        let present = list_artifacts(&handle);
        assert!(present.contains(&"inventory".to_string()));
        assert!(present.contains(&"plan".to_string()));

        persist_provenance(&handle, "s1", "h1", sample_provenance()).unwrap();
        let present = list_artifacts(&handle);
        assert!(present.contains(&"provenance".to_string()));
        assert!(present.contains(&"provenance_audit".to_string()));
    }

    #[test]
    fn test_envelope_schema_version() {
        let tmp = TempDir::new().unwrap();
        let handle = make_handle(&tmp);
        persist_inventory(&handle, "s1", "h1", sample_inventory()).unwrap();
        let loaded = load_inventory(&handle).unwrap();
        assert_eq!(loaded.schema_version, SNAPSHOT_SCHEMA_VERSION);
    }

    #[test]
    fn test_envelope_host_and_session() {
        let tmp = TempDir::new().unwrap();
        let handle = make_handle(&tmp);
        persist_inference(&handle, "my-session", "my-host", sample_inference()).unwrap();
        let loaded = load_inference(&handle).unwrap();
        assert_eq!(loaded.session_id, "my-session");
        assert_eq!(loaded.host_id, "my-host");
    }
}
