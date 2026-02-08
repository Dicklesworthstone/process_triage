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
        SessionStore {
            sessions_root: dir.to_path_buf(),
        }
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
    fn store_open_nonexistent() {
        let tmp = tempfile::tempdir().unwrap();
        let store = make_store(tmp.path());
        let sid = SessionId("pt-nonexistent".to_string());
        let result = store.open(&sid);
        assert!(result.is_err());
        match result.unwrap_err() {
            SessionError::NotFound { session_id } => assert_eq!(session_id, "pt-nonexistent"),
            other => panic!("expected NotFound, got {:?}", other),
        }
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
    fn handle_write_context() {
        let tmp = tempfile::tempdir().unwrap();
        let store = make_store(tmp.path());
        let sid = SessionId("pt-20260115-120000-ctx".to_string());
        let manifest = SessionManifest::new(&sid, None, SessionMode::Interactive, None);
        let handle = store.create(&manifest).unwrap();
        let ctx = SessionContext::new(&sid, "host".to_string(), "run".to_string(), None);
        handle.write_context(&ctx).unwrap();
        assert!(handle.context_path().exists());

        let content = std::fs::read_to_string(handle.context_path()).unwrap();
        let back: SessionContext = serde_json::from_str(&content).unwrap();
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
        assert_eq!(store.sessions_root(), tmp.path());
    }

    #[test]
    fn store_session_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let store = make_store(tmp.path());
        let sid = SessionId("pt-test".to_string());
        assert_eq!(store.session_dir(&sid), tmp.path().join("pt-test"));
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
        std::fs::create_dir(tmp.path().join("random-dir")).unwrap();
        // Create a dir too short to be session ID
        std::fs::create_dir(tmp.path().join("pt-short")).unwrap();

        let result = store
            .list_sessions(&ListSessionsOptions::default())
            .unwrap();
        assert!(result.is_empty());
    }

    // ── cleanup_sessions ────────────────────────────────────────────

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

    // ── write_json_pretty / write_json_pretty_atomic ────────────────

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
    fn write_json_pretty_atomic_creates_file() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("atomic.json");
        let value = serde_json::json!({"atomic": true});
        write_json_pretty_atomic(&path, &value).unwrap();
        assert!(path.exists());
        let content = std::fs::read_to_string(&path).unwrap();
        let back: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(back["atomic"], true);
    }

    #[test]
    fn write_json_pretty_atomic_no_temp_file_left() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("clean.json");
        write_json_pretty_atomic(&path, &serde_json::json!({})).unwrap();
        // No .tmp files should remain
        let entries: Vec<_> = std::fs::read_dir(tmp.path()).unwrap().collect();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].as_ref().unwrap().file_name().to_str().unwrap() == "clean.json");
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
