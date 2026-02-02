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
pub mod resume;
pub mod snapshot_persist;

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

    pub fn sessions_root(&self) -> &Path {
        &self.sessions_root
    }

    pub fn session_dir(&self, session_id: &SessionId) -> PathBuf {
        self.sessions_root.join(&session_id.0)
    }

    pub fn create(&self, manifest: &SessionManifest) -> Result<SessionHandle, SessionError> {
        std::fs::create_dir_all(&self.sessions_root).map_err(|e| SessionError::Io {
            path: self.sessions_root.clone(),
            source: e,
        })?;

        let session_id = SessionId(manifest.session_id.clone());
        let dir = self.session_dir(&session_id);
        std::fs::create_dir_all(&dir).map_err(|e| SessionError::Io {
            path: dir.clone(),
            source: e,
        })?;

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
            std::fs::create_dir_all(&p).map_err(|e| SessionError::Io { path: p, source: e })?;
        }

        let handle = SessionHandle {
            id: session_id,
            dir,
        };
        handle.write_manifest(manifest)?;
        Ok(handle)
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

            // Apply older_than filter
            if let Some(older_than) = &options.older_than {
                if let Ok(created) = DateTime::parse_from_rfc3339(&manifest.timing.created_at) {
                    let created_utc = created.with_timezone(&Utc);
                    if now.signed_duration_since(created_utc) < *older_than {
                        continue;
                    }
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

    /// Remove old sessions while preserving telemetry and audit data.
    ///
    /// Sessions in the following states are preserved regardless of age:
    /// - Executing (may be in progress)
    /// - Planned (awaiting approval)
    pub fn cleanup_sessions(&self, older_than: Duration) -> Result<CleanupResult, SessionError> {
        let options = ListSessionsOptions {
            older_than: Some(older_than),
            ..Default::default()
        };

        let sessions = self.list_sessions(&options)?;
        let mut result = CleanupResult {
            removed_count: 0,
            removed_sessions: Vec::new(),
            preserved_count: 0,
            errors: Vec::new(),
        };

        for session in sessions {
            // Preserve sessions that might be in use
            if matches!(
                session.state,
                SessionState::Executing | SessionState::Planned | SessionState::Scanning
            ) {
                result.preserved_count += 1;
                continue;
            }

            // Remove the session directory
            if let Err(e) = std::fs::remove_dir_all(&session.path) {
                result.errors.push(format!("{}: {}", session.session_id, e));
            } else {
                result.removed_count += 1;
                result.removed_sessions.push(session.session_id);
            }
        }

        Ok(result)
    }
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
        write_json_pretty_atomic(&self.snapshot_path(), snapshot)
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

fn write_json_pretty<T: Serialize>(path: &Path, value: &T) -> Result<(), SessionError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| SessionError::Io {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }
    let content = serde_json::to_string_pretty(value).map_err(|e| SessionError::Json {
        path: path.to_path_buf(),
        source: e,
    })?;
    std::fs::write(path, content).map_err(|e| SessionError::Io {
        path: path.to_path_buf(),
        source: e,
    })
}

fn write_json_pretty_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), SessionError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| SessionError::Io {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }
    let content = serde_json::to_vec_pretty(value).map_err(|e| SessionError::Json {
        path: path.to_path_buf(),
        source: e,
    })?;
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("snapshot.json");
    let tmp_path = path.with_file_name(format!("{}.tmp.{}", file_name, std::process::id()));
    {
        use std::io::Write;
        let mut file = std::fs::File::create(&tmp_path).map_err(|e| SessionError::Io {
            path: tmp_path.clone(),
            source: e,
        })?;
        file.write_all(&content).map_err(|e| SessionError::Io {
            path: tmp_path.clone(),
            source: e,
        })?;
        let _ = file.sync_all();
    }
    std::fs::rename(&tmp_path, path).map_err(|e| SessionError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    Ok(())
}
