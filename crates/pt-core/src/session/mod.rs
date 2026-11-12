//! Session persistence and resumability primitives.
//!
//! This module implements the core pieces of the session model from
//! `specs/session-model.md`:
//! - Resolve session root dir via XDG + env overrides
//! - Create/open session directories
//! - Persist `manifest.json` + `context.json` + optional `capabilities.json`
//! - Update session state history in an append-only manner
//!
//! NOTE: Higher-level commands (agent plan/apply/verify, etc.) build on these
//! primitives. This module intentionally avoids any TUI assumptions.

pub mod compare;
pub mod diff;
#[cfg(test)]
mod diff_tests;
pub mod fleet;
pub mod lifecycle;
pub mod resume;
#[cfg(test)]
mod resume_tests;
pub mod snapshot_persist;
pub mod typestate;
pub mod verify;

use chrono::{DateTime, Duration, Utc};
use pt_common::{schema::SCHEMA_VERSION, ProcessId, SessionId, StartId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

const ENV_DATA_DIR: &str = "PROCESS_TRIAGE_DATA";

const DIR_NAME: &str = "process_triage";
const SESSIONS_DIR_NAME: &str = "sessions";

const MANIFEST_FILE: &str = "manifest.json";
const CONTEXT_FILE: &str = "context.json";
const CAPABILITIES_FILE: &str = "capabilities.json";

const SCAN_DIR: &str = "scan";
const INFERENCE_DIR: &str = "inference";
const DECISION_DIR: &str = "decision";
const ACTION_DIR: &str = "action";
const TELEMETRY_DIR: &str = "telemetry";
const LOGS_DIR: &str = "logs";
const EXPORTS_DIR: &str = "exports";

const SCAN_PROBES_DIR: &str = "scan/probes";
const SNAPSHOT_FILE: &str = "scan/snapshot.json";

/// Schema version for session snapshots.
pub const SNAPSHOT_SCHEMA_VERSION: &str = "1.0.0";

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("failed to resolve XDG data dir (set {ENV_DATA_DIR} or XDG_DATA_HOME)")]
    DataDirUnavailable,

    #[error("session not found: {session_id}")]
    NotFound { session_id: String },

    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse JSON at {path}: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Created,
    Scanning,
    Planned,
    Executing,
    Completed,
    Cancelled,
    Failed,
    Archived,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionMode {
    Interactive,
    RobotPlan,
    RobotApply,
    DaemonAlert,
    ScanOnly,
    Export,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SnapshotConfigFile {
    pub path: Option<String>,
    pub hash: Option<String>,
    pub schema_version: String,
    pub using_defaults: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SnapshotConfig {
    pub config_dir: String,
    pub priors: SnapshotConfigFile,
    pub policy: SnapshotConfigFile,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SnapshotScanSummary {
    pub total_processes: u64,
    pub protected_filtered: u64,
    pub candidates_evaluated: u64,
    pub scan_duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SnapshotHost {
    pub hostname: String,
    pub cores: u32,
    pub memory_total_gb: f64,
    pub memory_used_gb: f64,
    pub load_avg: Vec<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SnapshotProcess {
    pub pid: ProcessId,
    pub ppid: ProcessId,
    pub uid: u32,
    pub start_id: StartId,
    pub comm: String,
    pub cmd: String,
    pub state: crate::collect::ProcessState,
    pub start_time_unix: i64,
    pub elapsed_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SnapshotInventory {
    pub total: u64,
    pub sampled: bool,
    pub sample_size: Option<u32>,
    pub records: Vec<SnapshotProcess>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SnapshotInferenceCandidate {
    pub pid: ProcessId,
    pub score: u32,
    pub classification: String,
    pub recommended_action: String,
    pub posterior: crate::inference::ClassScores,
    pub confidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SnapshotInferenceSummary {
    pub candidate_count: usize,
    pub candidates: Vec<SnapshotInferenceCandidate>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SnapshotPlanRef {
    pub path: String,
    pub candidates: usize,
    pub kill_recommendations: usize,
    pub review_recommendations: usize,
    pub spare_recommendations: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SnapshotProvenanceRef {
    pub path: String,
    pub provenance_schema_version: String,
    pub privacy_version: String,
    pub integrity_sha256: String,
    pub node_count: usize,
    pub edge_count: usize,
    pub evidence_count: usize,
    pub redacted_evidence_count: usize,
    pub missing_or_conflicted_evidence_count: usize,
    pub warning_count: usize,
    pub audit_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SessionSnapshot {
    pub schema_version: String,
    pub session_id: String,
    pub generated_at: String,
    pub host_id: String,
    pub pt_version: String,
    pub host: SnapshotHost,
    pub config: SnapshotConfig,
    pub scan: SnapshotScanSummary,
    pub inventory: SnapshotInventory,
    pub inference: SnapshotInferenceSummary,
    pub plan: SnapshotPlanRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<SnapshotProvenanceRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransition {
    pub state: SessionState,
    pub ts: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionTiming {
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionManifest {
    pub schema_version: String,
    pub session_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_session_id: Option<String>,
    pub state: SessionState,
    pub state_history: Vec<StateTransition>,
    pub mode: SessionMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub timing: SessionTiming,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl SessionManifest {
    pub fn new(
        session_id: &SessionId,
        parent_session_id: Option<&SessionId>,
        mode: SessionMode,
        label: Option<String>,
    ) -> Self {
        let now = Utc::now().to_rfc3339();
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            session_id: session_id.0.clone(),
            parent_session_id: parent_session_id.map(|id| id.0.clone()),
            state: SessionState::Created,
            state_history: vec![StateTransition {
                state: SessionState::Created,
                ts: now.clone(),
            }],
            mode,
            label,
            timing: SessionTiming {
                created_at: now,
                updated_at: None,
            },
            error: None,
        }
    }

    pub fn record_state(&mut self, state: SessionState) {
        let now = Utc::now().to_rfc3339();
        self.state = state;
        self.state_history.push(StateTransition {
            state,
            ts: now.clone(),
        });
        self.timing.updated_at = Some(now);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionContext {
    pub schema_version: String,
    pub session_id: String,
    pub generated_at: String,
    pub host_id: String,
    pub run_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub os: SessionOs,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionOs {
    pub family: String,
    pub arch: String,
}

impl SessionContext {
    pub fn new(
        session_id: &SessionId,
        host_id: String,
        run_id: String,
        label: Option<String>,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            session_id: session_id.0.clone(),
            generated_at: Utc::now().to_rfc3339(),
            host_id,
            run_id,
            label,
            os: SessionOs {
                family: std::env::consts::OS.to_string(),
                arch: std::env::consts::ARCH.to_string(),
            },
        }
    }
}

/// Summary of a session for listing purposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    pub session_id: String,
    pub created_at: String,
    pub state: SessionState,
    pub mode: SessionMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub host_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidates_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actions_count: Option<u32>,
    pub path: PathBuf,
}

/// Options for listing sessions.
#[derive(Debug, Default)]
pub struct ListSessionsOptions {
    /// Maximum number of sessions to return.
    pub limit: Option<u32>,
    /// Filter by state.
    pub state: Option<SessionState>,
    /// Only return sessions older than this duration (for cleanup).
    pub older_than: Option<Duration>,
}

/// An original journal record, including failure details and repeated attempts.
/// A saved status is historical evidence, not a fresh verification of an effect.
#[derive(Debug, Serialize)]
pub struct ActionHistoryEntry {
    pub session_id: String,
    pub journal_line: u64,
    pub outcome: serde_json::Value,
}

#[derive(Debug, Default, Serialize)]
pub struct ActionHistory {
    pub actions: Vec<ActionHistoryEntry>,
    pub total_count: u64,
    pub sessions_examined: usize,
    pub truncated: bool,
}

/// Bound retained raw journal payloads independently of the requested row limit.
pub const ACTION_HISTORY_BYTE_LIMIT: usize = 16 * 1024 * 1024;

/// Result of a cleanup operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleanupResult {
    pub removed_count: u32,
    pub removed_sessions: Vec<String>,
    pub preserved_count: u32,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct SessionStore {
    sessions_root: PathBuf,
}

impl SessionStore {
    pub fn from_env() -> Result<Self, SessionError> {
        Ok(Self {
            sessions_root: resolve_sessions_root()?,
        })
    }

    /// Store rooted at an explicit data directory (what `PROCESS_TRIAGE_DATA` selects),
    /// without reading or mutating process-global environment.
    pub fn at_data_dir(data_dir: &Path) -> Self {
        Self {
            sessions_root: data_dir.join(SESSIONS_DIR_NAME),
        }
    }

    pub fn sessions_root(&self) -> &Path {
        &self.sessions_root
    }

    pub fn session_dir(&self, session_id: &SessionId) -> PathBuf {
        self.sessions_root.join(&session_id.0)
    }

    pub fn create(&self, manifest: &SessionManifest) -> Result<SessionHandle, SessionError> {
        create_session_directory(&self.sessions_root)?;

        let session_id = SessionId(manifest.session_id.clone());
        let dir = self.session_dir(&session_id);
        create_session_directory(&dir)?;

        // Create canonical subdirs upfront (makes later phases simpler).
        for rel in [
            SCAN_DIR,
            SCAN_PROBES_DIR,
            INFERENCE_DIR,
            DECISION_DIR,
            ACTION_DIR,
            TELEMETRY_DIR,
            LOGS_DIR,
            EXPORTS_DIR,
        ] {
            let p = dir.join(rel);
            create_session_directory(&p)?;
        }

        let handle = SessionHandle {
            id: session_id,
            dir,
        };
        handle.write_manifest(manifest)?;
        self.auto_gc();
        Ok(handle)
    }

    /// Enforce the session retention policy (`PROCESS_TRIAGE_RETENTION` days,
    /// default 7; `0`/`off`/`never` disables). Best-effort and throttled to once per
    /// hour via a marker file, so it adds nothing measurable to normal runs.
    ///
    /// Before this existed nothing ever removed sessions: a dev box accumulated
    /// 3 017 session dirs (289 MB) from one test burst.
    fn auto_gc(&self) {
        let Some(retention) = retention_from_env(std::env::var("PROCESS_TRIAGE_RETENTION").ok())
        else {
            return;
        };
        let marker = self.sessions_root.join(".last_gc");
        let recently_ran = std::fs::metadata(&marker)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age < std::time::Duration::from_secs(3600));
        if recently_ran {
            return;
        }
        let _ = std::fs::write(&marker, b"");
        if let Ok(result) = self.cleanup_sessions(retention) {
            if result.removed_count > 0 {
                tracing::debug!(
                    removed = result.removed_count,
                    preserved = result.preserved_count,
                    "session retention cleanup"
                );
            }
        }
    }

    pub fn open(&self, session_id: &SessionId) -> Result<SessionHandle, SessionError> {
        let dir = self.session_dir(session_id);
        if !dir.exists() {
            return Err(SessionError::NotFound {
                session_id: session_id.0.clone(),
            });
        }
        Ok(SessionHandle {
            id: session_id.clone(),
            dir,
        })
    }

    /// Read recorded action attempts without consulting or executing a plan.
    /// Sessions are newest-created first, with reverse journal order inside each
    /// session. This deliberately does not invent timestamps for blocked or
    /// skipped records, which may have no execution time. Only `limit` records
    /// are retained, but all selected journals are validated and counted.
    pub fn action_history(
        &self,
        session_id: Option<&SessionId>,
        limit: usize,
    ) -> Result<ActionHistory, SessionError> {
        let mut sessions = Vec::new();
        if let Some(session_id) = session_id {
            self.open(session_id)?;
            sessions.push(session_id.clone());
        } else {
            let entries = match std::fs::read_dir(&self.sessions_root) {
                Ok(entries) => entries,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(ActionHistory::default());
                }
                Err(source) => {
                    return Err(SessionError::Io {
                        path: self.sessions_root.clone(),
                        source,
                    });
                }
            };
            for entry in entries {
                let entry = entry.map_err(|source| SessionError::Io {
                    path: self.sessions_root.clone(),
                    source,
                })?;
                if let Some(id) = entry.file_name().to_str().and_then(SessionId::parse) {
                    sessions.push(id);
                }
            }
        }

        // Unlike list_sessions, discovery here never loads a plan or reads each
        // complete journal merely to count it before reading it a second time.
        let mut ordered = Vec::with_capacity(sessions.len());
        for id in sessions {
            let dir = self.session_dir(&id);
            for path in [&self.sessions_root, &dir] {
                let metadata =
                    std::fs::symlink_metadata(path).map_err(|source| SessionError::Io {
                        path: path.clone(),
                        source,
                    })?;
                if !metadata.is_dir() {
                    return Err(history_data_error(path, "expected a real session directory"));
                }
            }
            let path = dir.join(MANIFEST_FILE);
            let file = open_history_file(&path)?;
            if file
                .metadata()
                .map_err(|source| SessionError::Io {
                    path: path.clone(),
                    source,
                })?
                .len()
                > MAX_HISTORY_RECORD_BYTES
            {
                return Err(history_data_error(&path, "session manifest exceeds 1 MiB"));
            }
            let manifest: SessionManifest = serde_json::from_reader(std::io::Read::take(
                file,
                MAX_HISTORY_RECORD_BYTES,
            ))
            .map_err(|source| SessionError::Json {
                path: path.clone(),
                source,
            })?;
            if manifest.session_id != id.0 {
                return Err(history_data_error(
                    &path,
                    "manifest session identity differs",
                ));
            }
            let created_at = DateTime::parse_from_rfc3339(&manifest.timing.created_at).map_err(
                |error| history_data_error(&path, &format!("invalid creation time: {error}")),
            )?;
            ordered.push((created_at, id));
        }
        ordered.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.0.cmp(&b.1.0)));

        let mut history = ActionHistory::default();
        let mut retained_bytes = 0;
        let mut selection_complete = false;
        for (_, id) in ordered {
            let action_dir = self.session_dir(&id).join(ACTION_DIR);
            match std::fs::symlink_metadata(&action_dir) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    history.sessions_examined += 1;
                    continue;
                }
                Err(source) => {
                    return Err(SessionError::Io {
                        path: action_dir,
                        source,
                    });
                }
                Ok(metadata) if !metadata.is_dir() => {
                    return Err(history_data_error(
                        &action_dir,
                        "expected a real action directory",
                    ));
                }
                Ok(_) => {}
            }
            let path = action_dir.join("outcomes.jsonl");
            let file = match open_history_file(&path) {
                Ok(file) => file,
                Err(SessionError::Io { source, .. })
                    if source.kind() == std::io::ErrorKind::NotFound =>
                {
                    history.sessions_examined += 1;
                    continue;
                }
                Err(error) => return Err(error),
            };
            let (entries, count, bytes) = read_action_history_journal(
                file,
                &path,
                &id,
                if selection_complete {
                    0
                } else {
                    limit.saturating_sub(history.actions.len())
                },
                ACTION_HISTORY_BYTE_LIMIT.saturating_sub(retained_bytes),
            )?;
            // Once a newer session's records were omitted by either bound,
            // including records from older sessions would break the ordering.
            selection_complete |= count > entries.len() as u64;
            retained_bytes += bytes;
            history.actions.extend(entries);
            history.total_count += count;
            history.sessions_examined += 1;
        }
        history.truncated = history.total_count > history.actions.len() as u64;
        Ok(history)
    }

    /// List sessions with optional filtering.
    ///
    /// Returns sessions sorted by creation time (newest first).
    pub fn list_sessions(
        &self,
        options: &ListSessionsOptions,
    ) -> Result<Vec<SessionSummary>, SessionError> {
        let mut summaries = Vec::new();

        // If sessions root doesn't exist, return empty list
        if !self.sessions_root.exists() {
            return Ok(summaries);
        }

        let entries = std::fs::read_dir(&self.sessions_root).map_err(|e| SessionError::Io {
            path: self.sessions_root.clone(),
            source: e,
        })?;

        let now = Utc::now();

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            // Directory name should be the session ID
            let dir_name = match path.file_name().and_then(|n| n.to_str()) {
                Some(name) => name.to_string(),
                None => continue,
            };

            // Validate session ID format (pt-YYYYMMDD-HHMMSS-XXXX)
            if !dir_name.starts_with("pt-") || dir_name.len() < 20 {
                continue;
            }

            let manifest_path = path.join(MANIFEST_FILE);
            if !manifest_path.exists() {
                continue;
            }

            // Read manifest
            let content = match std::fs::read_to_string(&manifest_path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            let manifest: SessionManifest = match serde_json::from_str(&content) {
                Ok(m) => m,
                Err(_) => continue,
            };

            // Apply state filter
            if let Some(state_filter) = &options.state {
                if manifest.state != *state_filter {
                    continue;
                }
            }

            // Apply older_than filter. A session whose age cannot be established is
            // not "older than" anything: an unparsable created_at used to pass this
            // filter, so retention cleanup deleted such a session at any age. Without
            // a timestamp, the manifest's modification time is the age.
            if let Some(older_than) = &options.older_than {
                let created_utc = DateTime::parse_from_rfc3339(&manifest.timing.created_at)
                    .map(|created| created.with_timezone(&Utc))
                    .ok()
                    .or_else(|| {
                        std::fs::metadata(&manifest_path)
                            .and_then(|m| m.modified())
                            .ok()
                            .map(DateTime::<Utc>::from)
                    });
                match created_utc {
                    Some(created) if now.signed_duration_since(created) >= *older_than => {}
                    _ => continue,
                }
            }

            // Try to read context for host_id
            let context_path = path.join(CONTEXT_FILE);
            let host_id = std::fs::read_to_string(&context_path)
                .ok()
                .and_then(|c| serde_json::from_str::<SessionContext>(&c).ok())
                .map(|ctx| ctx.host_id);

            // Count candidates and actions from session artifacts (optional)
            let candidates_count = count_candidates(&path);
            let actions_count = count_actions(&path);

            summaries.push(SessionSummary {
                session_id: manifest.session_id,
                created_at: manifest.timing.created_at,
                state: manifest.state,
                mode: manifest.mode,
                label: manifest.label,
                host_id,
                candidates_count,
                actions_count,
                path,
            });
        }

        // Sort by created_at (newest first)
        summaries.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        // Apply limit
        if let Some(limit) = options.limit {
            summaries.truncate(limit as usize);
        }

        Ok(summaries)
    }

    /// Remove sessions older than `older_than`.
    ///
    /// Retain executing sessions and every session with reversal artifacts,
    /// including incomplete or unreadable artifacts. A reversible controller can
    /// outlive the ordinary retention window; its original settings and ownership
    /// receipt must survive too. Cleanup shares the execution-policy lock with
    /// action preparation, undo and canonical plan writes.
    pub fn cleanup_sessions(&self, older_than: Duration) -> Result<CleanupResult, SessionError> {
        let mut result = CleanupResult {
            removed_count: 0,
            removed_sessions: Vec::new(),
            preserved_count: 0,
            errors: Vec::new(),
        };
        match std::fs::symlink_metadata(&self.sessions_root) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(result),
            Err(source) => {
                return Err(SessionError::Io {
                    path: self.sessions_root.clone(),
                    source,
                });
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(SessionError::Io {
                    path: self.sessions_root.clone(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "session retention root is not a real directory",
                    ),
                });
            }
            Ok(_) => {}
        }
        let cleanup_lock = SessionCleanupLock::acquire(&self.sessions_root).map_err(|source| {
            SessionError::Io {
                path: self.sessions_root.clone(),
                source,
            }
        })?;
        let options = ListSessionsOptions {
            older_than: Some(older_than),
            ..Default::default()
        };

        let sessions = self.list_sessions(&options)?;

        for session in sessions {
            cleanup_lock
                .revalidate()
                .map_err(|source| SessionError::Io {
                    path: self.sessions_root.clone(),
                    source,
                })?;
            // The list is a discovery snapshot. Read the current manifest and
            // reversal metadata while holding the same lock as their writers.
            if retention_requires_preservation(&session.path, &session.session_id, older_than) {
                result.preserved_count += 1;
                continue;
            }
            cleanup_lock
                .revalidate()
                .map_err(|source| SessionError::Io {
                    path: self.sessions_root.clone(),
                    source,
                })?;
            if retention_has_reversal_artifacts(&session.path) {
                result.preserved_count += 1;
                continue;
            }

            // Remove the session directory
            match std::fs::remove_dir_all(&session.path) {
                Ok(_) => {
                    result.removed_count += 1;
                    result.removed_sessions.push(session.session_id);
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // Already removed, treat as success
                    result.removed_count += 1;
                    result.removed_sessions.push(session.session_id);
                }
                Err(e) => {
                    result.errors.push(format!("{}: {}", session.session_id, e));
                }
            }
        }

        Ok(result)
    }
}

const MAX_HISTORY_RECORD_BYTES: u64 = 1024 * 1024;

fn history_data_error(path: &Path, message: &str) -> SessionError {
    SessionError::Io {
        path: path.to_path_buf(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, message),
    }
}

fn open_history_file(path: &Path) -> Result<std::fs::File, SessionError> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let file = options.open(path).map_err(|source| SessionError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let metadata = file.metadata().map_err(|source| SessionError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(history_data_error(path, "expected a regular history file"));
    }
    Ok(file)
}

fn read_action_history_journal(
    file: std::fs::File,
    path: &Path,
    session_id: &SessionId,
    limit: usize,
    byte_limit: usize,
) -> Result<(Vec<ActionHistoryEntry>, u64, usize), SessionError> {
    use std::io::{BufRead, Read};
    let length = file
        .metadata()
        .map_err(|source| SessionError::Io {
            path: path.to_path_buf(),
            source,
        })?
        .len();
    // A concurrent append cannot make the query chase an ever-growing journal.
    let mut reader = std::io::BufReader::new(file.take(length));
    let mut latest = std::collections::VecDeque::new();
    let mut line = Vec::new();
    let mut line_number = 0_u64;
    let mut count = 0_u64;
    let mut retained_bytes = 0;
    loop {
        line.clear();
        let bytes = (&mut reader)
            .take(MAX_HISTORY_RECORD_BYTES + 1)
            .read_until(b'\n', &mut line)
            .map_err(|source| SessionError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        if bytes == 0 {
            break;
        }
        line_number += 1;
        if bytes as u64 > MAX_HISTORY_RECORD_BYTES {
            return Err(history_data_error(
                path,
                &format!("journal line {line_number} exceeds 1 MiB"),
            ));
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let outcome: serde_json::Value = serde_json::from_slice(&line).map_err(|error| {
            history_data_error(path, &format!("journal line {line_number}: {error}"))
        })?;
        // Validate the execution-record contract without dropping additional
        // refusal reasons, guardrail diagnostics, or future audit fields.
        serde_json::from_value::<crate::verify::SavedActionOutcome>(outcome.clone()).map_err(
            |error| history_data_error(path, &format!("journal line {line_number}: {error}")),
        )?;
        count += 1;
        if limit > 0 {
            latest.push_back((
                ActionHistoryEntry {
                    session_id: session_id.0.clone(),
                    journal_line: line_number,
                    outcome,
                },
                bytes,
            ));
            retained_bytes += bytes;
            while latest.len() > limit || retained_bytes > byte_limit {
                if let Some((_, removed_bytes)) = latest.pop_front() {
                    retained_bytes -= removed_bytes;
                }
            }
        }
    }
    if reader.get_ref().limit() != 0 {
        return Err(history_data_error(
            path,
            "journal was truncated while being read",
        ));
    }
    Ok((
        latest.into_iter().rev().map(|(entry, _)| entry).collect(),
        count,
        retained_bytes,
    ))
}

/// This lock uses the same stable inode and flock protocol as main's
/// `.execution-policy-lock`. It is never removed or truncated by retention.
struct SessionCleanupLock {
    #[cfg(unix)]
    file: std::fs::File,
    #[cfg(unix)]
    path: PathBuf,
    #[cfg(unix)]
    directory: std::fs::File,
    #[cfg(unix)]
    sessions_root: PathBuf,
}

impl SessionCleanupLock {
    #[cfg(unix)]
    fn acquire(sessions_root: &Path) -> std::io::Result<Self> {
        use std::os::{fd::AsRawFd, unix::fs::OpenOptionsExt};
        let data_directory = sessions_root
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "session root has no execution data directory",
                )
            })?;
        let path = data_directory.join(".execution-policy-lock");
        let directory = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(sessions_root)?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&path)?;
        // SAFETY: file owns a live descriptor; flock only acquires its advisory lock.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let lock = Self {
            file,
            path,
            directory,
            sessions_root: sessions_root.to_path_buf(),
        };
        lock.revalidate()?;
        Ok(lock)
    }

    #[cfg(not(unix))]
    fn acquire(_sessions_root: &Path) -> std::io::Result<Self> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "session retention requires the shared execution-policy file lock",
        ))
    }

    #[cfg(unix)]
    fn revalidate(&self) -> std::io::Result<()> {
        use std::os::unix::fs::MetadataExt;
        let opened = self.file.metadata()?;
        let current = std::fs::symlink_metadata(&self.path)?;
        let opened_directory = self.directory.metadata()?;
        let current_directory = std::fs::symlink_metadata(&self.sessions_root)?;
        // SAFETY: geteuid only reads the caller's effective credentials.
        let uid = unsafe { libc::geteuid() };
        if !opened.is_file()
            || !current.is_file()
            || opened.nlink() != 1
            || opened.uid() != uid
            || current.uid() != uid
            || current.mode() & 0o022 != 0
            || opened.dev() != current.dev()
            || opened.ino() != current.ino()
            || !current_directory.is_dir()
            || opened_directory.dev() != current_directory.dev()
            || opened_directory.ino() != current_directory.ino()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "execution-policy lock identity, ownership or permissions changed",
            ));
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn revalidate(&self) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "session retention requires the shared execution-policy file lock",
        ))
    }
}

impl Drop for SessionCleanupLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            // SAFETY: this guard still owns the descriptor acquired above.
            unsafe {
                libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
}

/// Absence is the only evidence that permits ordinary retention. Even an empty
/// directory can be a crash-interrupted prepare; a malformed file or lookup
/// failure must not erase the only path to the original controller settings.
fn retention_has_reversal_artifacts(session_path: &Path) -> bool {
    let action_path = session_path.join(ACTION_DIR);
    match std::fs::symlink_metadata(&action_path) {
        Ok(metadata) if !metadata.is_dir() => return true,
        Err(error) => return error.kind() != std::io::ErrorKind::NotFound,
        Ok(_) => {}
    }
    match std::fs::symlink_metadata(action_path.join("reversals")) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        _ => true,
    }
}

fn retention_requires_preservation(
    session_path: &Path,
    expected_session_id: &str,
    older_than: Duration,
) -> bool {
    if retention_has_reversal_artifacts(session_path) {
        return true;
    }
    let inspect = || -> Option<bool> {
        use std::io::Read;
        if session_path.file_name()?.to_str()? != expected_session_id {
            return None;
        }
        let directory_metadata = std::fs::symlink_metadata(session_path).ok()?;
        if !directory_metadata.is_dir() {
            return None;
        }
        let manifest_path = session_path.join(MANIFEST_FILE);
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
        }
        let file = options.open(&manifest_path).ok()?;
        let metadata = file.metadata().ok()?;
        const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
        if !metadata.is_file() || metadata.len() > MAX_MANIFEST_BYTES {
            return None;
        }
        let mut content = Vec::new();
        file.take(MAX_MANIFEST_BYTES + 1)
            .read_to_end(&mut content)
            .ok()?;
        if content.len() as u64 > MAX_MANIFEST_BYTES {
            return None;
        }
        let manifest: SessionManifest = serde_json::from_slice(&content).ok()?;
        if manifest.session_id != expected_session_id {
            return None;
        }
        if manifest.state == SessionState::Executing {
            return Some(true);
        }
        let created = DateTime::parse_from_rfc3339(&manifest.timing.created_at)
            .map(|value| value.with_timezone(&Utc))
            .ok()
            .or_else(|| metadata.modified().ok().map(DateTime::<Utc>::from))?;
        if Utc::now().signed_duration_since(created) < older_than {
            return Some(true);
        }
        let current_directory = std::fs::symlink_metadata(session_path).ok()?;
        let current_manifest = std::fs::symlink_metadata(&manifest_path).ok()?;
        if !current_directory.is_dir() || !current_manifest.is_file() {
            return None;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if current_directory.dev() != directory_metadata.dev()
                || current_directory.ino() != directory_metadata.ino()
                || current_manifest.dev() != metadata.dev()
                || current_manifest.ino() != metadata.ino()
                || current_manifest.mtime() != metadata.mtime()
                || current_manifest.mtime_nsec() != metadata.mtime_nsec()
            {
                return None;
            }
        }
        Some(retention_has_reversal_artifacts(session_path))
    };
    inspect().unwrap_or(true)
}

#[derive(Debug, Clone)]
pub struct SessionHandle {
    pub id: SessionId,
    pub dir: PathBuf,
}

impl SessionHandle {
    pub fn manifest_path(&self) -> PathBuf {
        self.dir.join(MANIFEST_FILE)
    }

    pub fn context_path(&self) -> PathBuf {
        self.dir.join(CONTEXT_FILE)
    }

    pub fn capabilities_path(&self) -> PathBuf {
        self.dir.join(CAPABILITIES_FILE)
    }

    pub fn snapshot_path(&self) -> PathBuf {
        self.dir.join(SNAPSHOT_FILE)
    }

    pub fn read_manifest(&self) -> Result<SessionManifest, SessionError> {
        let path = self.manifest_path();
        let content = std::fs::read_to_string(&path).map_err(|e| SessionError::Io {
            path: path.clone(),
            source: e,
        })?;
        serde_json::from_str(&content).map_err(|e| SessionError::Json { path, source: e })
    }

    pub fn read_context(&self) -> Result<SessionContext, SessionError> {
        let path = self.context_path();
        let content = std::fs::read_to_string(&path).map_err(|e| SessionError::Io {
            path: path.clone(),
            source: e,
        })?;
        serde_json::from_str(&content).map_err(|e| SessionError::Json { path, source: e })
    }

    pub fn write_manifest(&self, manifest: &SessionManifest) -> Result<(), SessionError> {
        write_json_pretty(&self.manifest_path(), manifest)
    }

    pub fn write_context(&self, ctx: &SessionContext) -> Result<(), SessionError> {
        write_json_pretty(&self.context_path(), ctx)
    }

    pub fn write_capabilities_json(&self, raw_json: &str) -> Result<(), SessionError> {
        // Best-effort: if invalid JSON, still store as a JSON string wrapper to keep file parseable.
        let value: serde_json::Value = match serde_json::from_str(raw_json) {
            Ok(v) => v,
            Err(_) => serde_json::json!({ "raw": raw_json }),
        };
        write_json_pretty(&self.capabilities_path(), &value)
    }

    pub fn write_snapshot(&self, snapshot: &SessionSnapshot) -> Result<(), SessionError> {
        write_json_pretty(&self.snapshot_path(), snapshot)
    }

    pub fn update_state(&self, new_state: SessionState) -> Result<SessionManifest, SessionError> {
        let mut manifest = self.read_manifest()?;
        manifest.record_state(new_state);
        self.write_manifest(&manifest)?;
        Ok(manifest)
    }
}

/// Count candidates from plan.json if it exists.
fn count_candidates(session_dir: &Path) -> Option<u32> {
    let plan_path = session_dir.join(DECISION_DIR).join("plan.json");
    if !plan_path.exists() {
        return None;
    }
    let content = std::fs::read_to_string(&plan_path).ok()?;
    let value: serde_json::Value = serde_json::from_str(&content).ok()?;
    value
        .get("candidates")
        .and_then(|c| c.as_array())
        .map(|arr| arr.len() as u32)
        .or_else(|| {
            value
                .get("summary")
                .and_then(|s| s.get("candidates_returned"))
                .and_then(|v| v.as_u64())
                .map(|v| v as u32)
        })
        .or_else(|| {
            value
                .get("gates_summary")
                .and_then(|g| g.get("total_candidates"))
                .and_then(|v| v.as_u64())
                .map(|v| v as u32)
        })
        .or_else(|| {
            value
                .get("actions")
                .and_then(|a| a.as_array())
                .map(|arr| arr.len() as u32)
        })
}

/// Count actions from outcomes.jsonl if it exists.
fn count_actions(session_dir: &Path) -> Option<u32> {
    let outcomes_path = session_dir.join(ACTION_DIR).join("outcomes.jsonl");
    if !outcomes_path.exists() {
        return None;
    }
    let content = std::fs::read_to_string(&outcomes_path).ok()?;
    let count = content.lines().filter(|l| !l.trim().is_empty()).count();
    Some(count as u32)
}

/// Default session retention in days (README: `PROCESS_TRIAGE_RETENTION`, default 7).
const DEFAULT_RETENTION_DAYS: i64 = 7;

/// Parse `PROCESS_TRIAGE_RETENTION` (whole days). `None` disables automatic cleanup.
fn retention_from_env(value: Option<String>) -> Option<Duration> {
    match value.as_deref().map(str::trim) {
        None | Some("") => Some(Duration::days(DEFAULT_RETENTION_DAYS)),
        Some(v) if matches!(v.to_ascii_lowercase().as_str(), "0" | "off" | "never") => None,
        Some(v) => Some(Duration::days(
            v.parse::<i64>()
                .ok()
                .filter(|d| *d > 0)
                .unwrap_or(DEFAULT_RETENTION_DAYS),
        )),
    }
}

fn resolve_sessions_root() -> Result<PathBuf, SessionError> {
    // 1) Explicit override: PROCESS_TRIAGE_DATA
    if let Ok(dir) = std::env::var(ENV_DATA_DIR) {
        return Ok(PathBuf::from(dir).join(SESSIONS_DIR_NAME));
    }

    // 2) XDG_DATA_HOME
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        return Ok(PathBuf::from(xdg).join(DIR_NAME).join(SESSIONS_DIR_NAME));
    }

    // 3) Platform default (dirs)
    if let Some(base) = dirs::data_dir() {
        return Ok(base.join(DIR_NAME).join(SESSIONS_DIR_NAME));
    }

    Err(SessionError::DataDirUnavailable)
}

/// Atomically publish a complete JSON artifact and synchronize its directory.
///
/// Failures before rename leave an existing artifact untouched. A directory-sync
/// failure after rename is reported, but the complete new artifact may already
/// be visible; callers must not interpret an error as a rollback. Failed private
/// temporary files are retained rather than deleting possible recovery evidence.
pub fn write_json_pretty<T: Serialize>(path: &Path, value: &T) -> Result<(), SessionError> {
    let content = serde_json::to_vec_pretty(value).map_err(|e| SessionError::Json {
        path: path.to_path_buf(),
        source: e,
    })?;
    // Randomness prevents same-process writers from sharing a temporary path;
    // exclusive creation, rather than randomness, enforces collision safety.
    let temporary = format!(".pt-json-{}.tmp", uuid::Uuid::new_v4());
    write_json_bytes(path, &content, temporary.as_ref(), std::fs::File::sync_all)
}

fn session_io(path: &Path, source: std::io::Error) -> SessionError {
    SessionError::Io {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(unix)]
fn artifact_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[cfg(unix)]
fn artifact_name(name: &std::ffi::OsStr) -> Result<std::ffi::CString, std::io::Error> {
    use std::os::unix::ffi::OsStrExt;
    if name.is_empty() || Path::new(name).file_name() != Some(name) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "artifact name must be one normal path component",
        ));
    }
    std::ffi::CString::new(name.as_bytes())
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))
}

/// Hold the parent inode throughout creation, synchronization and rename. Path
/// revalidation detects moved directories; descriptor-relative operations never
/// follow a replacement directory or a temporary-file symlink.
#[cfg(unix)]
struct JsonDirectory {
    path: PathBuf,
    handle: std::fs::File,
}

#[cfg(unix)]
impl JsonDirectory {
    fn open(path: &Path) -> Result<Self, SessionError> {
        use std::os::unix::fs::OpenOptionsExt;
        let handle = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|error| session_io(path, error))?;
        let directory = Self {
            path: path.to_path_buf(),
            handle,
        };
        directory.revalidate()?;
        Ok(directory)
    }

    fn create(path: &Path) -> Result<Self, SessionError> {
        Self::create_with_sync(path, &std::fs::File::sync_all)
    }

    fn create_with_sync(
        path: &Path,
        synchronize: &impl Fn(&std::fs::File) -> std::io::Result<()>,
    ) -> Result<Self, SessionError> {
        use std::os::fd::AsRawFd;
        match Self::open(path) {
            Ok(directory) => {
                // A concurrent creator, or an earlier attempt whose sync failed,
                // can leave a visible directory with an unpersisted parent entry.
                // Existence alone must not skip this part of publication.
                directory.sync_parent_entry(synchronize)?;
                return Ok(directory);
            }
            Err(SessionError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let name = path.file_name().ok_or_else(|| {
            session_io(
                path,
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "directory has no name"),
            )
        })?;
        let name = artifact_name(name).map_err(|error| session_io(path, error))?;
        let parent = Self::create_with_sync(artifact_parent(path), synchronize)?;
        parent.revalidate()?;
        // SAFETY: the live directory descriptor and NUL-terminated name remain
        // valid for this call; mkdirat creates only this one private child.
        let created = unsafe { libc::mkdirat(parent.handle.as_raw_fd(), name.as_ptr(), 0o700) };
        if created != 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(session_io(path, error));
            }
        }
        parent.revalidate()?;
        let directory = Self::open(path)?;
        // Synchronize the directory inode and the entry linking it to its
        // parent, including a concurrent creator's entry. Every new ancestor
        // is handled by the same path before an artifact can report success.
        synchronize(&directory.handle).map_err(|error| session_io(path, error))?;
        synchronize(&parent.handle).map_err(|error| session_io(&parent.path, error))?;
        parent.revalidate()?;
        directory.revalidate()?;
        Ok(directory)
    }

    fn sync_parent_entry(
        &self,
        synchronize: &impl Fn(&std::fs::File) -> std::io::Result<()>,
    ) -> Result<(), SessionError> {
        use std::os::fd::{AsRawFd, FromRawFd};
        self.revalidate()?;
        let path = self.path.join("..");
        // SAFETY: the directory descriptor remains live. Resolving '..' from
        // that inode also handles '.' and filesystem roots without guessing a
        // parent from the spelling of a relative path.
        let fd = unsafe {
            libc::openat(
                self.handle.as_raw_fd(),
                c"..".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(session_io(&path, std::io::Error::last_os_error()));
        }
        // SAFETY: ownership of the new descriptor is transferred exactly once.
        let parent = unsafe { std::fs::File::from_raw_fd(fd) };
        synchronize(&parent).map_err(|error| session_io(&path, error))?;
        self.revalidate()
    }

    fn revalidate(&self) -> Result<(), SessionError> {
        use std::os::unix::fs::MetadataExt;
        let saved = self
            .handle
            .metadata()
            .map_err(|error| session_io(&self.path, error))?;
        let current =
            std::fs::symlink_metadata(&self.path).map_err(|error| session_io(&self.path, error))?;
        if !current.is_dir() || saved.dev() != current.dev() || saved.ino() != current.ino() {
            return Err(session_io(
                &self.path,
                std::io::Error::other("artifact directory identity changed"),
            ));
        }
        Ok(())
    }

    fn create_temporary(&self, name: &std::ffi::OsStr) -> Result<std::fs::File, SessionError> {
        use std::os::fd::{AsRawFd, FromRawFd};
        self.revalidate()?;
        let path = self.path.join(name);
        let name = artifact_name(name).map_err(|error| session_io(&path, error))?;
        // SAFETY: openat borrows the live directory fd and valid C string. The
        // returned descriptor is exclusively owned by the File constructed below.
        let fd = unsafe {
            libc::openat(
                self.handle.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600 as libc::mode_t,
            )
        };
        if fd < 0 {
            return Err(session_io(&path, std::io::Error::last_os_error()));
        }
        // SAFETY: fd is a newly opened, valid descriptor transferred exactly once.
        Ok(unsafe { std::fs::File::from_raw_fd(fd) })
    }

    fn rename(
        &self,
        temporary: &std::ffi::OsStr,
        destination: &std::ffi::OsStr,
        file: &std::fs::File,
    ) -> Result<(), SessionError> {
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::fs::MetadataExt;
        self.revalidate()?;
        let source = artifact_name(temporary)
            .map_err(|error| session_io(&self.path.join(temporary), error))?;
        let target = artifact_name(destination)
            .map_err(|error| session_io(&self.path.join(destination), error))?;
        let saved = file
            .metadata()
            .map_err(|error| session_io(&self.path.join(temporary), error))?;
        // SAFETY: the name and directory descriptor remain live. O_NOFOLLOW
        // refuses a substituted symlink; O_NONBLOCK avoids waiting on a FIFO.
        let fd = unsafe {
            libc::openat(
                self.handle.as_raw_fd(),
                source.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            return Err(session_io(
                &self.path.join(temporary),
                std::io::Error::new(
                    error.kind(),
                    format!("artifact temporary identity changed or unreadable: {error}"),
                ),
            ));
        }
        // SAFETY: this newly opened descriptor is transferred exactly once.
        let current_file = unsafe { std::fs::File::from_raw_fd(fd) };
        let current = current_file
            .metadata()
            .map_err(|error| session_io(&self.path.join(temporary), error))?;
        if !current.is_file()
            || current.dev() != saved.dev()
            || current.ino() != saved.ino()
            || current.nlink() != 1
        {
            return Err(session_io(
                &self.path.join(temporary),
                std::io::Error::other("artifact temporary identity changed"),
            ));
        }
        // SAFETY: both names are single NUL-terminated components relative to
        // the same live directory descriptor; renameat never follows the target.
        let result = unsafe {
            libc::renameat(
                self.handle.as_raw_fd(),
                source.as_ptr(),
                self.handle.as_raw_fd(),
                target.as_ptr(),
            )
        };
        if result != 0 {
            return Err(session_io(
                &self.path.join(destination),
                std::io::Error::last_os_error(),
            ));
        }
        Ok(())
    }
}

#[cfg(unix)]
fn create_session_directory(path: &Path) -> Result<(), SessionError> {
    JsonDirectory::create(path).map(|_| ())
}

#[cfg(not(unix))]
fn create_session_directory(path: &Path) -> Result<(), SessionError> {
    Err(session_io(
        path,
        std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "durable session publication requires Unix directory synchronization",
        ),
    ))
}

// The synchronization operation is explicit so failure tests can exercise the
// complete publication protocol, without weakening production synchronization.
#[cfg(unix)]
fn write_json_bytes(
    path: &Path,
    content: &[u8],
    temporary: &std::ffi::OsStr,
    synchronize: impl Fn(&std::fs::File) -> std::io::Result<()>,
) -> Result<(), SessionError> {
    use std::io::Write;
    let destination = path.file_name().ok_or_else(|| {
        session_io(
            path,
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "artifact has no filename"),
        )
    })?;
    artifact_name(destination).map_err(|error| session_io(path, error))?;
    let directory = JsonDirectory::create(artifact_parent(path))?;
    let temporary_path = directory.path.join(temporary);
    let mut file = directory.create_temporary(temporary)?;
    file.write_all(content)
        .map_err(|error| session_io(&temporary_path, error))?;
    synchronize(&file).map_err(|error| session_io(&temporary_path, error))?;
    directory.rename(temporary, destination, &file)?;
    synchronize(&directory.handle).map_err(|error| {
        session_io(
            &directory.path,
            std::io::Error::new(
                error.kind(),
                format!(
                    "artifact {} was renamed, but directory synchronization failed: {error}",
                    path.display()
                ),
            ),
        )
    })?;
    directory.revalidate()
}

#[cfg(not(unix))]
fn write_json_bytes(
    path: &Path,
    _content: &[u8],
    _temporary: &std::ffi::OsStr,
    _synchronize: impl Fn(&std::fs::File) -> std::io::Result<()>,
) -> Result<(), SessionError> {
    create_session_directory(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pt_common::SessionId;

    // ── SessionState serde ──────────────────────────────────────────

    #[test]
    fn session_state_serde_roundtrip() {
        for state in [
            SessionState::Created,
            SessionState::Scanning,
            SessionState::Planned,
            SessionState::Executing,
            SessionState::Completed,
            SessionState::Cancelled,
            SessionState::Failed,
            SessionState::Archived,
        ] {
            let json = serde_json::to_string(&state).unwrap();
            let back: SessionState = serde_json::from_str(&json).unwrap();
            assert_eq!(state, back);
        }
    }

    #[test]
    fn session_state_snake_case() {
        assert_eq!(
            serde_json::to_string(&SessionState::Created).unwrap(),
            r#""created""#
        );
        assert_eq!(
            serde_json::to_string(&SessionState::Scanning).unwrap(),
            r#""scanning""#
        );
        assert_eq!(
            serde_json::to_string(&SessionState::Completed).unwrap(),
            r#""completed""#
        );
    }

    // ── SessionMode serde ───────────────────────────────────────────

    #[test]
    fn session_mode_serde_roundtrip() {
        for mode in [
            SessionMode::Interactive,
            SessionMode::RobotPlan,
            SessionMode::RobotApply,
            SessionMode::DaemonAlert,
            SessionMode::ScanOnly,
            SessionMode::Export,
        ] {
            let json = serde_json::to_string(&mode).unwrap();
            let back: SessionMode = serde_json::from_str(&json).unwrap();
            assert_eq!(mode, back);
        }
    }

    #[test]
    fn session_mode_snake_case() {
        assert_eq!(
            serde_json::to_string(&SessionMode::RobotPlan).unwrap(),
            r#""robot_plan""#
        );
        assert_eq!(
            serde_json::to_string(&SessionMode::DaemonAlert).unwrap(),
            r#""daemon_alert""#
        );
        assert_eq!(
            serde_json::to_string(&SessionMode::ScanOnly).unwrap(),
            r#""scan_only""#
        );
    }

    // ── SessionManifest ─────────────────────────────────────────────

    #[test]
    fn manifest_new_sets_created_state() {
        let sid = SessionId("pt-20260115-120000-abcd".to_string());
        let m = SessionManifest::new(&sid, None, SessionMode::Interactive, None);
        assert_eq!(m.session_id, "pt-20260115-120000-abcd");
        assert_eq!(m.state, SessionState::Created);
        assert!(m.parent_session_id.is_none());
        assert_eq!(m.mode, SessionMode::Interactive);
        assert!(m.label.is_none());
        assert!(m.error.is_none());
        assert_eq!(m.schema_version, pt_common::SCHEMA_VERSION);
    }

    #[test]
    fn manifest_new_has_initial_state_history() {
        let sid = SessionId("pt-test".to_string());
        let m = SessionManifest::new(&sid, None, SessionMode::ScanOnly, None);
        assert_eq!(m.state_history.len(), 1);
        assert_eq!(m.state_history[0].state, SessionState::Created);
        assert!(!m.state_history[0].ts.is_empty());
    }

    #[test]
    fn manifest_new_with_parent_and_label() {
        let sid = SessionId("pt-child".to_string());
        let parent = SessionId("pt-parent".to_string());
        let m = SessionManifest::new(
            &sid,
            Some(&parent),
            SessionMode::RobotApply,
            Some("test run".to_string()),
        );
        assert_eq!(m.parent_session_id.as_deref(), Some("pt-parent"));
        assert_eq!(m.label.as_deref(), Some("test run"));
    }

    #[test]
    fn manifest_record_state_appends_history() {
        let sid = SessionId("pt-test".to_string());
        let mut m = SessionManifest::new(&sid, None, SessionMode::Interactive, None);
        m.record_state(SessionState::Scanning);
        assert_eq!(m.state, SessionState::Scanning);
        assert_eq!(m.state_history.len(), 2);
        assert_eq!(m.state_history[1].state, SessionState::Scanning);
        assert!(m.timing.updated_at.is_some());
    }

    #[test]
    fn manifest_record_state_multiple() {
        let sid = SessionId("pt-test".to_string());
        let mut m = SessionManifest::new(&sid, None, SessionMode::Interactive, None);
        m.record_state(SessionState::Scanning);
        m.record_state(SessionState::Planned);
        m.record_state(SessionState::Executing);
        m.record_state(SessionState::Completed);
        assert_eq!(m.state, SessionState::Completed);
        assert_eq!(m.state_history.len(), 5);
    }

    #[test]
    fn manifest_timing_created_at_set() {
        let sid = SessionId("pt-test".to_string());
        let m = SessionManifest::new(&sid, None, SessionMode::Interactive, None);
        assert!(!m.timing.created_at.is_empty());
        assert!(m.timing.updated_at.is_none());
    }

    #[test]
    fn manifest_serde_roundtrip() {
        let sid = SessionId("pt-test".to_string());
        let m = SessionManifest::new(&sid, None, SessionMode::Interactive, None);
        let json = serde_json::to_string(&m).unwrap();
        let back: SessionManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(m.session_id, back.session_id);
        assert_eq!(m.state, back.state);
        assert_eq!(m.mode, back.mode);
    }

    // ── SessionContext ──────────────────────────────────────────────

    #[test]
    fn context_new_sets_fields() {
        let sid = SessionId("pt-test".to_string());
        let ctx = SessionContext::new(&sid, "host1".to_string(), "run1".to_string(), None);
        assert_eq!(ctx.session_id, "pt-test");
        assert_eq!(ctx.host_id, "host1");
        assert_eq!(ctx.run_id, "run1");
        assert!(ctx.label.is_none());
        assert!(!ctx.generated_at.is_empty());
        assert_eq!(ctx.schema_version, pt_common::SCHEMA_VERSION);
        assert!(!ctx.os.family.is_empty());
        assert!(!ctx.os.arch.is_empty());
    }

    #[test]
    fn context_new_with_label() {
        let sid = SessionId("pt-test".to_string());
        let ctx = SessionContext::new(
            &sid,
            "h".to_string(),
            "r".to_string(),
            Some("my run".to_string()),
        );
        assert_eq!(ctx.label.as_deref(), Some("my run"));
    }

    #[test]
    fn context_serde_roundtrip() {
        let sid = SessionId("pt-test".to_string());
        let ctx = SessionContext::new(&sid, "host".to_string(), "run".to_string(), None);
        let json = serde_json::to_string(&ctx).unwrap();
        let back: SessionContext = serde_json::from_str(&json).unwrap();
        assert_eq!(ctx.session_id, back.session_id);
        assert_eq!(ctx.host_id, back.host_id);
    }

    // ── ListSessionsOptions ─────────────────────────────────────────

    #[test]
    fn list_sessions_options_defaults() {
        let opts = ListSessionsOptions::default();
        assert!(opts.limit.is_none());
        assert!(opts.state.is_none());
        assert!(opts.older_than.is_none());
    }

    // ── CleanupResult ───────────────────────────────────────────────

    #[test]
    fn cleanup_result_serde_roundtrip() {
        let result = CleanupResult {
            removed_count: 3,
            removed_sessions: vec!["s1".to_string(), "s2".to_string(), "s3".to_string()],
            preserved_count: 1,
            errors: vec![],
        };
        let json = serde_json::to_string(&result).unwrap();
        let back: CleanupResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result.removed_count, back.removed_count);
        assert_eq!(result.removed_sessions.len(), back.removed_sessions.len());
    }

    // ── SessionError ────────────────────────────────────────────────

    #[test]
    fn session_error_display() {
        let e = SessionError::DataDirUnavailable;
        let msg = format!("{}", e);
        assert!(msg.contains("XDG"));

        let e = SessionError::NotFound {
            session_id: "pt-123".to_string(),
        };
        let msg = format!("{}", e);
        assert!(msg.contains("pt-123"));
    }

    // ── SnapshotConfigFile ──────────────────────────────────────────

    #[test]
    fn snapshot_config_file_serde() {
        let scf = SnapshotConfigFile {
            path: Some("/etc/priors.json".to_string()),
            hash: Some("abc123".to_string()),
            schema_version: "1.0".to_string(),
            using_defaults: false,
        };
        let json = serde_json::to_string(&scf).unwrap();
        let back: SnapshotConfigFile = serde_json::from_str(&json).unwrap();
        assert_eq!(scf.path, back.path);
        assert!(!back.using_defaults);
    }

    // ── SessionStore with tempdir ───────────────────────────────────

    fn make_store(dir: &std::path::Path) -> SessionStore {
        // Use the production data-dir/sessions layout so parallel fixtures do
        // not accidentally share their parent's execution-policy lock.
        SessionStore::at_data_dir(dir)
    }

    #[test]
    fn store_create_and_open_session() {
        let tmp = tempfile::tempdir().unwrap();
        let store = make_store(tmp.path());
        let sid = SessionId("pt-20260115-120000-abcd".to_string());
        let manifest = SessionManifest::new(&sid, None, SessionMode::Interactive, None);
        let handle = store.create(&manifest).unwrap();
        assert!(handle.dir.exists());
        assert!(handle.manifest_path().exists());

        // Verify subdirectories are created
        assert!(handle.dir.join("scan").exists());
        assert!(handle.dir.join("inference").exists());
        assert!(handle.dir.join("decision").exists());
        assert!(handle.dir.join("action").exists());
        assert!(handle.dir.join("telemetry").exists());
        assert!(handle.dir.join("logs").exists());
        assert!(handle.dir.join("exports").exists());

        // Can re-open
        let handle2 = store.open(&sid).unwrap();
        assert_eq!(handle.dir, handle2.dir);
    }

    #[test]
    fn action_history_byte_budget_keeps_the_latest_complete_attempts() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("outcomes.jsonl");
        let row = |pid| {
            format!("{{\"action_id\":\"a\",\"pid\":{pid},\"status\":\"failed\"}}\n")
        };
        let first = row(1);
        std::fs::write(&path, format!("{}{}{}", first, row(2), row(3))).unwrap();
        let id = SessionId::new();
        let (entries, count, bytes) = read_action_history_journal(
            open_history_file(&path).unwrap(),
            &path,
            &id,
            10_000,
            first.len() * 2,
        )
        .unwrap();
        assert_eq!(count, 3);
        assert_eq!(entries.len(), 2);
        assert_eq!(bytes, first.len() * 2);
        assert_eq!(entries[0].outcome["pid"], 3);
        assert_eq!(entries[1].outcome["pid"], 2);
    }

    #[test]
    fn store_open_nonexistent() {
        let tmp = tempfile::tempdir().unwrap();
        let store = make_store(tmp.path());
        let sid = SessionId("pt-nonexistent".to_string());
        let result = store.open(&sid);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(SessionError::NotFound { ref session_id }) if session_id == "pt-nonexistent"
        ));
    }

    #[test]
    fn handle_read_write_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let store = make_store(tmp.path());
        let sid = SessionId("pt-20260115-120000-test".to_string());
        let manifest =
            SessionManifest::new(&sid, None, SessionMode::RobotPlan, Some("test".to_string()));
        let handle = store.create(&manifest).unwrap();
        let read_back = handle.read_manifest().unwrap();
        assert_eq!(read_back.session_id, "pt-20260115-120000-test");
        assert_eq!(read_back.mode, SessionMode::RobotPlan);
        assert_eq!(read_back.label.as_deref(), Some("test"));
    }

    #[test]
    fn handle_read_write_context() {
        let tmp = tempfile::tempdir().unwrap();
        let store = make_store(tmp.path());
        let sid = SessionId("pt-20260115-120000-ctx".to_string());
        let manifest = SessionManifest::new(&sid, None, SessionMode::Interactive, None);
        let handle = store.create(&manifest).unwrap();
        let ctx = SessionContext::new(&sid, "host".to_string(), "run".to_string(), None);
        handle.write_context(&ctx).unwrap();
        assert!(handle.context_path().exists());

        let back = handle.read_context().unwrap();
        assert_eq!(back.host_id, "host");
    }

    #[test]
    fn handle_write_capabilities_valid_json() {
        let tmp = tempfile::tempdir().unwrap();
        let store = make_store(tmp.path());
        let sid = SessionId("pt-20260115-120000-cap".to_string());
        let manifest = SessionManifest::new(&sid, None, SessionMode::Interactive, None);
        let handle = store.create(&manifest).unwrap();
        handle
            .write_capabilities_json(r#"{"can_kill":true}"#)
            .unwrap();
        assert!(handle.capabilities_path().exists());
        let content = std::fs::read_to_string(handle.capabilities_path()).unwrap();
        let v: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(v["can_kill"], true);
    }

    #[test]
    fn handle_write_capabilities_invalid_json_wraps() {
        let tmp = tempfile::tempdir().unwrap();
        let store = make_store(tmp.path());
        let sid = SessionId("pt-20260115-120000-bad".to_string());
        let manifest = SessionManifest::new(&sid, None, SessionMode::Interactive, None);
        let handle = store.create(&manifest).unwrap();
        handle.write_capabilities_json("not json at all").unwrap();
        let content = std::fs::read_to_string(handle.capabilities_path()).unwrap();
        let v: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(v["raw"], "not json at all");
    }

    #[test]
    fn handle_update_state() {
        let tmp = tempfile::tempdir().unwrap();
        let store = make_store(tmp.path());
        let sid = SessionId("pt-20260115-120000-upd".to_string());
        let manifest = SessionManifest::new(&sid, None, SessionMode::Interactive, None);
        let handle = store.create(&manifest).unwrap();
        let updated = handle.update_state(SessionState::Scanning).unwrap();
        assert_eq!(updated.state, SessionState::Scanning);
        assert_eq!(updated.state_history.len(), 2);

        // Read back from disk confirms persistence
        let read_back = handle.read_manifest().unwrap();
        assert_eq!(read_back.state, SessionState::Scanning);
    }

    #[test]
    fn handle_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let store = make_store(tmp.path());
        let sid = SessionId("pt-20260115-120000-pth".to_string());
        let manifest = SessionManifest::new(&sid, None, SessionMode::Interactive, None);
        let handle = store.create(&manifest).unwrap();
        assert!(handle.manifest_path().ends_with("manifest.json"));
        assert!(handle.context_path().ends_with("context.json"));
        assert!(handle.capabilities_path().ends_with("capabilities.json"));
        assert!(handle.snapshot_path().ends_with("scan/snapshot.json"));
    }

    #[test]
    fn store_sessions_root() {
        let tmp = tempfile::tempdir().unwrap();
        let store = make_store(tmp.path());
        assert_eq!(store.sessions_root(), tmp.path().join("sessions"));
    }

    #[test]
    fn store_session_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let store = make_store(tmp.path());
        let sid = SessionId("pt-test".to_string());
        assert_eq!(store.session_dir(&sid), tmp.path().join("sessions/pt-test"));
    }

    // ── list_sessions ───────────────────────────────────────────────

    #[test]
    fn list_sessions_empty_root() {
        let tmp = tempfile::tempdir().unwrap();
        let store = make_store(tmp.path());
        let result = store
            .list_sessions(&ListSessionsOptions::default())
            .unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn list_sessions_nonexistent_root() {
        let store = make_store(Path::new("/tmp/nonexistent-pt-test-root-12345"));
        let result = store
            .list_sessions(&ListSessionsOptions::default())
            .unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn list_sessions_finds_created_sessions() {
        let tmp = tempfile::tempdir().unwrap();
        let store = make_store(tmp.path());

        let sid1 = SessionId("pt-20260115-120000-aaaa".to_string());
        let m1 = SessionManifest::new(&sid1, None, SessionMode::Interactive, None);
        store.create(&m1).unwrap();

        let sid2 = SessionId("pt-20260115-120001-bbbb".to_string());
        let m2 = SessionManifest::new(&sid2, None, SessionMode::RobotPlan, None);
        store.create(&m2).unwrap();

        let result = store
            .list_sessions(&ListSessionsOptions::default())
            .unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn list_sessions_with_limit() {
        let tmp = tempfile::tempdir().unwrap();
        let store = make_store(tmp.path());

        for i in 0..5 {
            let sid = SessionId(format!("pt-20260115-12000{}-{:04}", i, i));
            let m = SessionManifest::new(&sid, None, SessionMode::Interactive, None);
            store.create(&m).unwrap();
        }

        let opts = ListSessionsOptions {
            limit: Some(3),
            ..Default::default()
        };
        let result = store.list_sessions(&opts).unwrap();
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn list_sessions_filter_by_state() {
        let tmp = tempfile::tempdir().unwrap();
        let store = make_store(tmp.path());

        let sid1 = SessionId("pt-20260115-120000-aaaa".to_string());
        let m1 = SessionManifest::new(&sid1, None, SessionMode::Interactive, None);
        let h1 = store.create(&m1).unwrap();
        h1.update_state(SessionState::Completed).unwrap();

        let sid2 = SessionId("pt-20260115-120001-bbbb".to_string());
        let m2 = SessionManifest::new(&sid2, None, SessionMode::Interactive, None);
        store.create(&m2).unwrap(); // stays Created

        let opts = ListSessionsOptions {
            state: Some(SessionState::Completed),
            ..Default::default()
        };
        let result = store.list_sessions(&opts).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].session_id, "pt-20260115-120000-aaaa");
    }

    #[test]
    fn list_sessions_skips_non_session_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let store = make_store(tmp.path());

        // Create a dir that doesn't match session format
        std::fs::create_dir_all(store.sessions_root()).unwrap();
        std::fs::create_dir(store.sessions_root().join("random-dir")).unwrap();
        // Create a dir too short to be session ID
        std::fs::create_dir(store.sessions_root().join("pt-short")).unwrap();

        let result = store
            .list_sessions(&ListSessionsOptions::default())
            .unwrap();
        assert!(result.is_empty());
    }

    // ── cleanup_sessions ────────────────────────────────────────────

    /// Retention safety tests keep every fixture and never call a deletion path.
    fn retained_retention_fixture() -> PathBuf {
        let directory = tempfile::tempdir().unwrap().keep();
        std::fs::create_dir(directory.join("sessions")).unwrap();
        directory
    }

    #[test]
    fn retention_preserves_empty_partial_and_malformed_reversal_artifacts() {
        for kind in 0..3 {
            let directory = retained_retention_fixture();
            let session = directory.join("sessions/pt-retained");
            let action = session.join(ACTION_DIR);
            std::fs::create_dir_all(&action).unwrap();
            assert!(!retention_has_reversal_artifacts(&session));
            let reversals = action.join("reversals");
            match kind {
                0 => std::fs::create_dir(&reversals).unwrap(),
                1 => {
                    std::fs::create_dir(&reversals).unwrap();
                    std::fs::write(reversals.join("incomplete.tmp"), b"{\"version\":").unwrap();
                }
                _ => std::fs::write(&reversals, b"not a directory or valid receipt").unwrap(),
            }
            assert!(retention_has_reversal_artifacts(&session));
            assert!(std::fs::symlink_metadata(&reversals).is_ok());
        }
    }

    #[test]
    fn retention_preserves_on_actual_metadata_lookup_errors() {
        let directory = retained_retention_fixture();
        let not_a_directory = directory.join("not-a-directory");
        std::fs::write(&not_a_directory, b"retained").unwrap();
        assert!(std::fs::symlink_metadata(not_a_directory.join(ACTION_DIR)).is_err());
        assert!(retention_has_reversal_artifacts(&not_a_directory));
        assert_eq!(std::fs::read(&not_a_directory).unwrap(), b"retained");
    }

    #[cfg(unix)]
    #[test]
    fn retention_preserves_dangling_or_redirected_reversal_locations() {
        use std::os::unix::fs::symlink;
        let directory = retained_retention_fixture();
        let session = directory.join("sessions/pt-retained");
        let action = session.join(ACTION_DIR);
        std::fs::create_dir_all(&action).unwrap();
        symlink(directory.join("missing-receipt"), action.join("reversals")).unwrap();
        assert!(retention_has_reversal_artifacts(&session));
        std::fs::rename(&action, session.join("retained-action")).unwrap();
        symlink(directory.join("missing-action"), &action).unwrap();
        assert!(retention_has_reversal_artifacts(&session));
        assert!(std::fs::symlink_metadata(&action)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[cfg(unix)]
    #[test]
    fn retention_lock_contends_with_the_real_execution_policy_flock_without_deleting() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;
        let directory = retained_retention_fixture();
        let root = directory.join("sessions");
        let path = directory.join(".execution-policy-lock");
        let other = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        std::fs::write(&path, b"active executor").unwrap();
        // SAFETY: other owns this descriptor for the complete external lock lifetime.
        assert_eq!(
            unsafe { libc::flock(other.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0
        );
        let error = match SessionCleanupLock::acquire(&root) {
            Ok(_) => panic!("retention must not acquire an active execution lock"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
        assert_eq!(std::fs::read(&path).unwrap(), b"active executor");
        // SAFETY: this is the same owned descriptor which acquired the lock.
        assert_eq!(unsafe { libc::flock(other.as_raw_fd(), libc::LOCK_UN) }, 0);
        {
            let guard = SessionCleanupLock::acquire(&root).unwrap();
            guard.revalidate().unwrap();
            // SAFETY: other remains open, independently from the retention descriptor.
            assert_ne!(
                unsafe { libc::flock(other.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
                0
            );
            assert_eq!(
                std::io::Error::last_os_error().kind(),
                std::io::ErrorKind::WouldBlock
            );
        }
        let guard = SessionCleanupLock::acquire(&root).unwrap();
        guard.revalidate().unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"active executor");
        assert!(root.exists());
    }

    #[cfg(unix)]
    #[test]
    fn retention_lock_refuses_symlink_and_replaced_lock_inodes() {
        use std::os::unix::fs::symlink;
        let directory = retained_retention_fixture();
        let outside = directory.join("outside");
        std::fs::write(&outside, b"unchanged").unwrap();
        symlink(&outside, directory.join(".execution-policy-lock")).unwrap();
        assert!(SessionCleanupLock::acquire(&directory.join("sessions")).is_err());
        assert_eq!(std::fs::read(&outside).unwrap(), b"unchanged");

        let directory = retained_retention_fixture();
        let path = directory.join(".execution-policy-lock");
        let guard = SessionCleanupLock::acquire(&directory.join("sessions")).unwrap();
        let retained = directory.join("retained-lock");
        std::fs::rename(&path, &retained).unwrap();
        std::fs::write(&path, b"replacement").unwrap();
        assert!(guard.revalidate().is_err());
        assert!(retained.exists());
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement");

        let directory = retained_retention_fixture();
        let root = directory.join("sessions");
        let guard = SessionCleanupLock::acquire(&root).unwrap();
        let retained_root = directory.join("retained-sessions");
        std::fs::rename(&root, &retained_root).unwrap();
        std::fs::create_dir(&root).unwrap();
        assert!(guard.revalidate().is_err());
        assert!(retained_root.exists());
        assert!(root.exists());
    }

    #[cfg(unix)]
    #[test]
    fn retention_lock_storage_failure_does_not_touch_session_artifacts() {
        let directory = retained_retention_fixture();
        let artifact = directory.join("sessions/retained-artifact");
        std::fs::write(&artifact, b"receipt evidence").unwrap();
        std::fs::create_dir(directory.join(".execution-policy-lock")).unwrap();
        assert!(SessionCleanupLock::acquire(&directory.join("sessions")).is_err());
        assert_eq!(std::fs::read(&artifact).unwrap(), b"receipt evidence");
    }

    #[test]
    fn retention_rechecks_current_manifest_state_age_and_errors() {
        let directory = retained_retention_fixture();
        let id = SessionId("pt-20260101-000000-kept".to_string());
        let session = directory.join("sessions").join(&id.0);
        std::fs::create_dir_all(session.join(ACTION_DIR)).unwrap();
        let mut manifest = SessionManifest::new(&id, None, SessionMode::RobotApply, None);
        manifest.state = SessionState::Completed;
        manifest.timing.created_at = (Utc::now() - Duration::days(30)).to_rfc3339();
        let path = session.join(MANIFEST_FILE);
        std::fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        assert!(!retention_requires_preservation(
            &session,
            &id.0,
            Duration::days(7)
        ));
        // A discovery summary can still say Completed while execution has begun.
        manifest.state = SessionState::Executing;
        std::fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        assert!(retention_requires_preservation(
            &session,
            &id.0,
            Duration::days(7)
        ));
        manifest.state = SessionState::Completed;
        manifest.timing.created_at = Utc::now().to_rfc3339();
        std::fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        assert!(retention_requires_preservation(
            &session,
            &id.0,
            Duration::days(7)
        ));
        std::fs::write(&path, b"partial manifest").unwrap();
        assert!(retention_requires_preservation(
            &session,
            &id.0,
            Duration::days(7)
        ));
        assert_eq!(std::fs::read(&path).unwrap(), b"partial manifest");
    }

    #[test]
    fn cleanup_preserves_executing_sessions() {
        let tmp = tempfile::tempdir().unwrap();
        let store = make_store(tmp.path());

        let sid = SessionId("pt-20260101-000000-exec".to_string());
        let m = SessionManifest::new(&sid, None, SessionMode::Interactive, None);
        let h = store.create(&m).unwrap();
        h.update_state(SessionState::Executing).unwrap();

        let result = store.cleanup_sessions(Duration::zero()).unwrap();
        assert_eq!(result.preserved_count, 1);
        assert_eq!(result.removed_count, 0);
        assert!(store.session_dir(&sid).exists());
    }

    #[test]
    fn cleanup_removes_stale_planned_and_scanning_sessions() {
        let tmp = tempfile::tempdir().unwrap();
        let store = make_store(tmp.path());
        for (suffix, state) in [
            ("plan", SessionState::Planned),
            ("scan", SessionState::Scanning),
        ] {
            let sid = SessionId(format!("pt-20260101-000000-{suffix}"));
            let m = SessionManifest::new(&sid, None, SessionMode::RobotPlan, None);
            store.create(&m).unwrap().update_state(state).unwrap();
        }
        let result = store.cleanup_sessions(Duration::zero()).unwrap();
        assert_eq!(result.removed_count, 2);
        assert_eq!(result.preserved_count, 0);
    }

    /// A manifest whose created_at does not parse is aged by the manifest's mtime: a
    /// fresh one is kept (it used to be deleted at any age), an old one is removed.
    #[test]
    fn cleanup_ages_sessions_with_unparsable_created_at_by_manifest_mtime() {
        let tmp = tempfile::tempdir().unwrap();
        let store = make_store(tmp.path());
        let mut paths = Vec::new();
        for suffix in ["fres", "stal"] {
            let sid = SessionId(format!("pt-20260101-000000-{suffix}"));
            let mut m = SessionManifest::new(&sid, None, SessionMode::RobotPlan, None);
            m.timing.created_at = "not a timestamp".to_string();
            let handle = store.create(&m).unwrap();
            paths.push(handle.dir.join(MANIFEST_FILE));
        }
        let ten_days_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(864_000);
        std::fs::File::options()
            .write(true)
            .open(&paths[1])
            .unwrap()
            .set_modified(ten_days_ago)
            .unwrap();

        let result = store.cleanup_sessions(Duration::days(7)).unwrap();
        assert_eq!(
            result.removed_sessions,
            vec!["pt-20260101-000000-stal".to_string()]
        );
        assert!(paths[0].exists(), "fresh session kept");
        assert!(!paths[1].exists(), "stale session removed");
    }

    #[test]
    fn retention_env_parsing() {
        assert_eq!(retention_from_env(None), Some(Duration::days(7)));
        assert_eq!(retention_from_env(Some("".into())), Some(Duration::days(7)));
        assert_eq!(
            retention_from_env(Some("30".into())),
            Some(Duration::days(30))
        );
        assert_eq!(retention_from_env(Some("0".into())), None);
        assert_eq!(retention_from_env(Some("off".into())), None);
        assert_eq!(
            retention_from_env(Some("junk".into())),
            Some(Duration::days(7))
        );
    }

    #[test]
    fn create_runs_throttled_auto_gc_without_touching_fresh_sessions() {
        let tmp = tempfile::tempdir().unwrap();
        let store = make_store(tmp.path());
        let sid = SessionId("pt-20260101-000000-new1".to_string());
        let m = SessionManifest::new(&sid, None, SessionMode::RobotPlan, None);
        store.create(&m).unwrap();
        assert!(store.session_dir(&sid).exists(), "fresh session kept");
        assert!(
            store.sessions_root().join(".last_gc").exists(),
            "gc marker written"
        );
        let listed = store
            .list_sessions(&ListSessionsOptions::default())
            .unwrap();
        assert_eq!(listed.len(), 1, "marker file is not listed as a session");
    }

    #[test]
    fn cleanup_removes_completed_sessions() {
        let tmp = tempfile::tempdir().unwrap();
        let store = make_store(tmp.path());

        let sid = SessionId("pt-20260101-000000-done".to_string());
        let m = SessionManifest::new(&sid, None, SessionMode::Interactive, None);
        let h = store.create(&m).unwrap();
        h.update_state(SessionState::Completed).unwrap();

        let result = store.cleanup_sessions(Duration::zero()).unwrap();
        assert_eq!(result.removed_count, 1);
        assert!(!store.session_dir(&sid).exists());
    }

    // ── count_candidates / count_actions ─────────────────────────────

    #[test]
    fn count_candidates_none_when_no_plan() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(count_candidates(tmp.path()).is_none());
    }

    #[test]
    fn count_candidates_from_candidates_array() {
        let tmp = tempfile::tempdir().unwrap();
        let decision_dir = tmp.path().join("decision");
        std::fs::create_dir_all(&decision_dir).unwrap();
        let plan = serde_json::json!({
            "candidates": [{"pid": 1}, {"pid": 2}, {"pid": 3}]
        });
        std::fs::write(decision_dir.join("plan.json"), plan.to_string()).unwrap();
        assert_eq!(count_candidates(tmp.path()), Some(3));
    }

    #[test]
    fn count_actions_none_when_no_outcomes() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(count_actions(tmp.path()).is_none());
    }

    #[test]
    fn count_actions_counts_lines() {
        let tmp = tempfile::tempdir().unwrap();
        let action_dir = tmp.path().join("action");
        std::fs::create_dir_all(&action_dir).unwrap();
        std::fs::write(
            action_dir.join("outcomes.jsonl"),
            "{\"action\":\"kill\"}\n{\"action\":\"spare\"}\n",
        )
        .unwrap();
        assert_eq!(count_actions(tmp.path()), Some(2));
    }

    #[test]
    fn count_actions_skips_empty_lines() {
        let tmp = tempfile::tempdir().unwrap();
        let action_dir = tmp.path().join("action");
        std::fs::create_dir_all(&action_dir).unwrap();
        std::fs::write(
            action_dir.join("outcomes.jsonl"),
            "{\"a\":1}\n\n{\"a\":2}\n  \n",
        )
        .unwrap();
        assert_eq!(count_actions(tmp.path()), Some(2));
    }

    // ── write_json_pretty ────────────────

    #[test]
    fn write_json_pretty_creates_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("test.json");
        let value = serde_json::json!({"hello": "world"});
        write_json_pretty(&path, &value).unwrap();
        assert!(path.exists());
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("hello"));
        assert!(content.contains("world"));
    }

    #[test]
    fn write_json_pretty_creates_parent_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("a").join("b").join("test.json");
        write_json_pretty(&path, &serde_json::json!({"ok": true})).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn write_json_pretty_no_temp_file_left() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("clean.json");
        write_json_pretty(&path, &serde_json::json!({})).unwrap();
        // No .tmp files should remain
        let entries: Vec<_> = std::fs::read_dir(tmp.path()).unwrap().collect();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].as_ref().unwrap().file_name().to_str().unwrap() == "clean.json");
    }

    #[cfg(unix)]
    #[test]
    fn write_json_pretty_concurrent_readers_observe_complete_artifacts() {
        use std::sync::Barrier;
        let directory = tempfile::tempdir().unwrap().keep();
        let path = directory.join("snapshot.json");
        let value = |writer: usize, generation: usize| {
            serde_json::json!({
                "writer": writer,
                "generation": generation,
                "payload": format!("{writer}:{generation}:").repeat(4096),
            })
        };
        write_json_pretty(&path, &value(0, 0)).unwrap();
        const WRITERS: usize = 4;
        let barrier = Barrier::new(WRITERS + 1);
        std::thread::scope(|scope| {
            let mut writers = Vec::new();
            for writer in 1..=WRITERS {
                let (path, barrier) = (&path, &barrier);
                writers.push(scope.spawn(move || {
                    barrier.wait();
                    for generation in 0..4 {
                        write_json_pretty(path, &value(writer, generation)).unwrap();
                    }
                }));
            }
            barrier.wait();
            loop {
                let observed: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
                let writer = observed["writer"].as_u64().unwrap() as usize;
                let generation = observed["generation"].as_u64().unwrap() as usize;
                assert!(writer <= WRITERS && generation < 4);
                assert_eq!(observed, value(writer, generation));
                if writers
                    .iter()
                    .all(std::thread::ScopedJoinHandle::is_finished)
                {
                    break;
                }
                std::thread::yield_now();
            }
            for writer in writers {
                writer.join().unwrap();
            }
        });
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn write_json_pretty_preserves_artifact_when_serialization_fails() {
        struct Invalid;
        impl Serialize for Invalid {
            fn serialize<S: serde::Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
                Err(serde::ser::Error::custom(
                    "deliberate serialization failure",
                ))
            }
        }
        let directory = tempfile::tempdir().unwrap().keep();
        let path = directory.join("snapshot.json");
        let original = b"{\"generation\":1}\n";
        std::fs::write(&path, original).unwrap();
        assert!(matches!(
            write_json_pretty(&path, &Invalid),
            Err(SessionError::Json { .. })
        ));
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);
        let absent_parent = directory.join("absent/nested");
        assert!(write_json_pretty(&absent_parent.join("snapshot.json"), &Invalid).is_err());
        assert!(!absent_parent.exists());
    }

    #[cfg(unix)]
    #[test]
    fn write_json_pretty_does_not_follow_old_temporary_or_destination_symlinks() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap().keep();
        let outside = directory.join("outside.json");
        let path = directory.join("snapshot.json");
        let legacy = directory.join(format!("snapshot.json.tmp.{}", std::process::id()));
        std::fs::write(&outside, b"retain the referent").unwrap();
        symlink(&outside, &legacy).unwrap();
        symlink(&outside, &path).unwrap();
        let replacement = serde_json::json!({"published": true});
        write_json_pretty(&path, &replacement).unwrap();
        assert_eq!(std::fs::read(&outside).unwrap(), b"retain the referent");
        assert_eq!(std::fs::read_link(&legacy).unwrap(), outside);
        assert!(std::fs::symlink_metadata(&path).unwrap().is_file());
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&std::fs::read(&path).unwrap()).unwrap(),
            replacement
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_json_bytes_refuses_existing_temporary_files_and_symlinks() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap().keep();
        let path = directory.join("snapshot.json");
        let outside = directory.join("outside.json");
        let original = b"{\"generation\":1}\n";
        std::fs::write(&path, original).unwrap();
        std::fs::write(&outside, b"retain the outside file").unwrap();
        std::fs::write(directory.join("existing.tmp"), b"retain the temporary file").unwrap();
        symlink(&outside, directory.join("symlink.tmp")).unwrap();
        std::fs::hard_link(&outside, directory.join("hardlink.tmp")).unwrap();
        std::fs::create_dir(directory.join("directory.tmp")).unwrap();
        for name in [
            "existing.tmp",
            "symlink.tmp",
            "hardlink.tmp",
            "directory.tmp",
        ] {
            let result = write_json_bytes(
                &path,
                b"{\"generation\":2}",
                name.as_ref(),
                std::fs::File::sync_all,
            );
            assert!(
                matches!(result, Err(SessionError::Io { source, .. }) if source.kind() == std::io::ErrorKind::AlreadyExists)
            );
            assert_eq!(std::fs::read(&path).unwrap(), original);
        }
        assert_eq!(std::fs::read(&outside).unwrap(), b"retain the outside file");
        assert_eq!(
            std::fs::read(directory.join("existing.tmp")).unwrap(),
            b"retain the temporary file"
        );
        assert_eq!(
            std::fs::read_link(directory.join("symlink.tmp")).unwrap(),
            outside
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn write_json_bytes_preserves_original_on_file_sync_error() {
        let directory = tempfile::tempdir().unwrap().keep();
        let path = directory.join("snapshot.json");
        let original = b"{\"generation\":1}\n";
        let replacement = b"{\"generation\":2}";
        std::fs::write(&path, original).unwrap();
        let device = std::fs::File::open("/dev/null").unwrap();
        let failure_kind = device.sync_all().unwrap_err().kind();
        let syncs = std::cell::Cell::new(0);
        let result = write_json_bytes(&path, replacement, "retained.tmp".as_ref(), |file| {
            assert!(file.metadata()?.is_file());
            syncs.set(syncs.get() + 1);
            // A real failing fsync exercises the same publication error path as
            // a storage failure, without depending on a writable faulting mount.
            device.sync_all()
        });
        assert!(
            matches!(result, Err(SessionError::Io { path: failed, source })
            if failed == directory.join("retained.tmp") && source.kind() == failure_kind)
        );
        assert_eq!(syncs.get(), 1);
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert_eq!(
            std::fs::read(directory.join("retained.tmp")).unwrap(),
            replacement
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn write_json_bytes_reports_directory_sync_error_after_publication() {
        let directory = tempfile::tempdir().unwrap().keep();
        let path = directory.join("snapshot.json");
        std::fs::write(&path, b"{\"generation\":1}").unwrap();
        let replacement = b"{\"generation\":2}";
        let device = std::fs::File::open("/dev/null").unwrap();
        let failure_kind = device.sync_all().unwrap_err().kind();
        let syncs = std::cell::Cell::new(0);
        let result = write_json_bytes(&path, replacement, "complete.tmp".as_ref(), |file| {
            syncs.set(syncs.get() + 1);
            if file.metadata()?.is_dir() {
                device.sync_all()
            } else {
                file.sync_all()
            }
        });
        let error = result.unwrap_err();
        assert!(error
            .to_string()
            .contains("was renamed, but directory synchronization failed"));
        assert!(matches!(error, SessionError::Io { path: failed, source }
            if failed == directory && source.kind() == failure_kind));
        assert_eq!(syncs.get(), 2);
        assert_eq!(std::fs::read(&path).unwrap(), replacement);
        assert!(!directory.join("complete.tmp").exists());
    }

    #[cfg(unix)]
    #[test]
    fn write_json_bytes_retains_complete_temporary_on_rename_failure() {
        let directory = tempfile::tempdir().unwrap().keep();
        let path = directory.join("snapshot.json");
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("retained"), b"existing directory content").unwrap();
        let replacement = b"{\"generation\":2}";
        assert!(write_json_bytes(
            &path,
            replacement,
            "complete.tmp".as_ref(),
            std::fs::File::sync_all
        )
        .is_err());
        assert_eq!(
            std::fs::read(path.join("retained")).unwrap(),
            b"existing directory content"
        );
        assert_eq!(
            std::fs::read(directory.join("complete.tmp")).unwrap(),
            replacement
        );
    }

    #[cfg(unix)]
    #[test]
    fn write_json_bytes_refuses_a_substituted_parent_directory() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap().keep();
        let directory = root.join("artifacts");
        let retained = root.join("retained-artifacts");
        let redirect = root.join("redirect");
        std::fs::create_dir(&directory).unwrap();
        std::fs::create_dir(&redirect).unwrap();
        let path = directory.join("snapshot.json");
        let original = b"{\"generation\":1}";
        std::fs::write(&path, original).unwrap();
        let replacement = b"{\"generation\":2}";
        let result = write_json_bytes(&path, replacement, "retained.tmp".as_ref(), |file| {
            file.sync_all()?;
            std::fs::rename(&directory, &retained)?;
            symlink(&redirect, &directory)
        });
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("directory identity changed"));
        assert_eq!(
            std::fs::read(retained.join("snapshot.json")).unwrap(),
            original
        );
        assert_eq!(
            std::fs::read(retained.join("retained.tmp")).unwrap(),
            replacement
        );
        assert_eq!(std::fs::read_dir(&redirect).unwrap().count(), 0);
        assert!(
            write_json_pretty(&directory.join("another.json"), &serde_json::json!({})).is_err()
        );
        assert_eq!(std::fs::read_dir(&redirect).unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn write_json_bytes_refuses_a_substituted_temporary_file() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap().keep();
        let path = directory.join("snapshot.json");
        let outside = directory.join("outside.json");
        let temporary = directory.join("complete.tmp");
        let retained = directory.join("retained.tmp");
        let original = b"{\"generation\":1}";
        let replacement = b"{\"generation\":2}";
        std::fs::write(&path, original).unwrap();
        std::fs::write(&outside, b"retain the referent").unwrap();
        let result = write_json_bytes(&path, replacement, "complete.tmp".as_ref(), |file| {
            file.sync_all()?;
            std::fs::rename(&temporary, &retained)?;
            symlink(&outside, &temporary)
        });
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("temporary identity changed"));
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert_eq!(std::fs::read(&retained).unwrap(), replacement);
        assert_eq!(std::fs::read(&outside).unwrap(), b"retain the referent");
        assert_eq!(std::fs::read_link(&temporary).unwrap(), outside);
    }

    #[cfg(unix)]
    #[test]
    fn write_json_bytes_binds_publication_to_the_written_inode() {
        let directory = tempfile::tempdir().unwrap().keep();
        let path = directory.join("snapshot.json");
        let temporary = directory.join("complete.tmp");
        let retained = directory.join("retained.tmp");
        let original = b"{\"generation\":1}";
        let replacement = b"{\"generation\":2}";
        let substituted = b"{\"unexpected\":true}";
        std::fs::write(&path, original).unwrap();
        let result = write_json_bytes(&path, replacement, "complete.tmp".as_ref(), |file| {
            file.sync_all()?;
            std::fs::rename(&temporary, &retained)?;
            std::fs::write(&temporary, substituted)
        });
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("temporary identity changed"));
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert_eq!(std::fs::read(&retained).unwrap(), replacement);
        assert_eq!(std::fs::read(&temporary).unwrap(), substituted);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn session_directory_retry_syncs_an_existing_parent_entry() {
        use std::os::unix::fs::MetadataExt;
        let root = tempfile::tempdir().unwrap().keep();
        let path = root.join("new-session");
        let root_metadata = std::fs::metadata(&root).unwrap();
        let device = std::fs::File::open("/dev/null").unwrap();
        let failure_kind = device.sync_all().unwrap_err().kind();
        let fail_parent_sync = |file: &std::fs::File| {
            let metadata = file.metadata()?;
            if metadata.dev() == root_metadata.dev() && metadata.ino() == root_metadata.ino() {
                device.sync_all()
            } else {
                file.sync_all()
            }
        };
        assert!(
            matches!(JsonDirectory::create_with_sync(&path, &fail_parent_sync),
            Err(SessionError::Io { source, .. }) if source.kind() == failure_kind)
        );
        assert!(path.is_dir());
        // Retry must still fail: visible directory creation is not proof that
        // the entry in its parent has reached durable storage.
        assert!(
            matches!(JsonDirectory::create_with_sync(&path, &fail_parent_sync),
            Err(SessionError::Io { source, .. }) if source.kind() == failure_kind)
        );
        let parent_syncs = std::cell::Cell::new(0);
        JsonDirectory::create_with_sync(&path.join("."), &|file| {
            let metadata = file.metadata()?;
            assert_eq!(
                (metadata.dev(), metadata.ino()),
                (root_metadata.dev(), root_metadata.ino())
            );
            parent_syncs.set(parent_syncs.get() + 1);
            file.sync_all()
        })
        .unwrap();
        assert_eq!(parent_syncs.get(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn write_json_pretty_creates_private_artifacts_with_non_utf8_names() {
        use std::os::unix::{ffi::OsStrExt, fs::PermissionsExt};
        let directory = tempfile::tempdir().unwrap().keep();
        let parent = directory.join("new/nested");
        let path = parent.join(std::ffi::OsStr::from_bytes(b"snapshot-\xff.json"));
        let value = serde_json::json!({"published": true});
        write_json_pretty(&path, &value).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&std::fs::read(&path).unwrap()).unwrap(),
            value
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(&parent).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(directory.join("new"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    // ── SnapshotHost / SnapshotScanSummary ──────────────────────────

    #[test]
    fn snapshot_host_serde() {
        let h = SnapshotHost {
            hostname: "test-host".to_string(),
            cores: 8,
            memory_total_gb: 32.0,
            memory_used_gb: 16.5,
            load_avg: vec![1.0, 2.0, 3.0],
        };
        let json = serde_json::to_string(&h).unwrap();
        let back: SnapshotHost = serde_json::from_str(&json).unwrap();
        assert_eq!(back.hostname, "test-host");
        assert_eq!(back.cores, 8);
    }

    #[test]
    fn snapshot_scan_summary_serde() {
        let s = SnapshotScanSummary {
            total_processes: 500,
            protected_filtered: 100,
            candidates_evaluated: 50,
            scan_duration_ms: 1200,
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: SnapshotScanSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(back.total_processes, 500);
    }

    #[test]
    fn snapshot_provenance_ref_serde() {
        let provenance = SnapshotProvenanceRef {
            path: "scan/provenance.json".to_string(),
            provenance_schema_version: "1.0.0".to_string(),
            privacy_version: "1.0.0".to_string(),
            integrity_sha256: "abcd".repeat(16),
            node_count: 2,
            edge_count: 1,
            evidence_count: 3,
            redacted_evidence_count: 1,
            missing_or_conflicted_evidence_count: 2,
            warning_count: 1,
            audit_path: "scan/provenance_audit.json".to_string(),
        };
        let json = serde_json::to_string(&provenance).unwrap();
        let back: SnapshotProvenanceRef = serde_json::from_str(&json).unwrap();
        assert_eq!(back.path, "scan/provenance.json");
        assert_eq!(back.provenance_schema_version, "1.0.0");
        assert_eq!(back.node_count, 2);
        assert_eq!(back.redacted_evidence_count, 1);
        assert_eq!(back.missing_or_conflicted_evidence_count, 2);
        assert_eq!(back.warning_count, 1);
        assert_eq!(back.audit_path, "scan/provenance_audit.json");
    }

    // ── SessionSummary ──────────────────────────────────────────────

    #[test]
    fn session_summary_serde_skip_none() {
        let s = SessionSummary {
            session_id: "pt-test".to_string(),
            created_at: "2026-01-15T00:00:00Z".to_string(),
            state: SessionState::Created,
            mode: SessionMode::Interactive,
            label: None,
            host_id: None,
            candidates_count: None,
            actions_count: None,
            path: PathBuf::from("/tmp/test"),
        };
        let json = serde_json::to_string(&s).unwrap();
        assert!(!json.contains("label"));
        assert!(!json.contains("candidates_count"));
        assert!(!json.contains("actions_count"));
    }

    // ── StateTransition ─────────────────────────────────────────────

    #[test]
    fn state_transition_serde() {
        let t = StateTransition {
            state: SessionState::Scanning,
            ts: "2026-01-15T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&t).unwrap();
        let back: StateTransition = serde_json::from_str(&json).unwrap();
        assert_eq!(back.state, SessionState::Scanning);
    }
}
