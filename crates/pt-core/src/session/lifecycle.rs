//! Session lifecycle management for multi-step agent workflows.
//!
//! Adds TTL-based session lifecycle on top of the core `SessionStore` /
//! `SessionHandle` primitives:
//!
//! - **Create** a session with an optional TTL and agent metadata.
//! - **Status** query with TTL expiry check.
//! - **Extend** the TTL of an active session.
//! - **End** a session (marks it completed, writes a final summary).
//! - **Expire** sessions whose TTL has elapsed.
//!
//! This module is intentionally *library-only* (no CLI concerns). The
//! `pt agent sessions` command and any future `pt session *` commands
//! compose these primitives.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::{
    ListSessionsOptions, SessionError, SessionHandle, SessionManifest, SessionMode, SessionState,
    SessionStore,
};
use pt_common::SessionId;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Metadata about the agent that owns a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMetadata {
    pub agent_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    /// Arbitrary key/value pairs for agent-specific context.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, String>,
}

/// Options for creating a managed session.
#[derive(Debug, Clone)]
pub struct CreateSessionOptions {
    pub mode: SessionMode,
    pub label: Option<String>,
    pub parent_session_id: Option<SessionId>,
    /// Time-to-live in seconds. `None` means no automatic expiry.
    pub ttl_seconds: Option<u64>,
    /// Optional agent metadata to persist alongside the session.
    pub agent_metadata: Option<AgentMetadata>,
}

/// Lifecycle metadata persisted as `lifecycle.json` inside the session dir.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleInfo {
    pub session_id: String,
    pub created_at: String,
    /// Absolute expiry timestamp (if TTL was set).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    /// Original TTL in seconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
    /// Number of times the TTL has been extended.
    pub extend_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_metadata: Option<AgentMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_reason: Option<String>,
}

/// Status of a managed session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStatus {
    pub session_id: String,
    pub state: SessionState,
    pub mode: SessionMode,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub is_expired: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_seconds: Option<i64>,
    pub extend_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_metadata: Option<AgentMetadata>,
    pub state_history_len: usize,
}

/// Summary returned when a session is ended.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndSessionSummary {
    pub session_id: String,
    pub final_state: SessionState,
    pub duration_seconds: i64,
    pub state_transitions: usize,
    pub ended_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Result of an expire sweep.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpireResult {
    pub expired_count: u32,
    pub expired_sessions: Vec<String>,
    pub errors: Vec<String>,
}

const LIFECYCLE_FILE: &str = "lifecycle.json";

// ---------------------------------------------------------------------------
// Core operations
// ---------------------------------------------------------------------------

/// Create a new managed session with optional TTL and agent metadata.
pub fn create_session(
    store: &SessionStore,
    options: &CreateSessionOptions,
) -> Result<(SessionId, SessionHandle), SessionError> {
    let session_id = SessionId::new();
    let manifest = SessionManifest::new(
        &session_id,
        options.parent_session_id.as_ref(),
        options.mode,
        options.label.clone(),
    );
    let handle = store.create(&manifest)?;

    let now = Utc::now();
    let expires_at = options
        .ttl_seconds
        .map(|ttl| {
            seconds_to_duration(ttl, &handle.dir).map(|duration| (now + duration).to_rfc3339())
        })
        .transpose()?;

    let lifecycle = LifecycleInfo {
        session_id: session_id.0.clone(),
        created_at: now.to_rfc3339(),
        expires_at,
        ttl_seconds: options.ttl_seconds,
        extend_count: 0,
        agent_metadata: options.agent_metadata.clone(),
        ended_at: None,
        end_reason: None,
    };
    write_lifecycle(&handle, &lifecycle)?;

    Ok((session_id, handle))
}

/// Query the status of a session, including TTL expiry.
pub fn session_status(handle: &SessionHandle) -> Result<SessionStatus, SessionError> {
    let manifest = handle.read_manifest()?;
    let lifecycle = read_lifecycle(handle)?;
    let now = Utc::now();

    let (is_expired, remaining) = match &lifecycle.expires_at {
        Some(exp_str) => match DateTime::parse_from_rfc3339(exp_str) {
            Ok(exp) => {
                let exp_utc = exp.with_timezone(&Utc);
                let remaining = exp_utc.signed_duration_since(now).num_seconds();
                (remaining <= 0, Some(remaining.max(0)))
            }
            Err(_) => (false, None),
        },
        None => (false, None),
    };

    Ok(SessionStatus {
        session_id: manifest.session_id,
        state: manifest.state,
        mode: manifest.mode,
        created_at: manifest.timing.created_at,
        label: manifest.label,
        is_expired,
        expires_at: lifecycle.expires_at,
        remaining_seconds: remaining,
        extend_count: lifecycle.extend_count,
        agent_metadata: lifecycle.agent_metadata,
        state_history_len: manifest.state_history.len(),
    })
}

/// Extend the TTL of an active session by `additional_seconds`.
///
/// Returns the new expiry timestamp. Fails if the session has already ended
/// or if no TTL was originally set.
pub fn extend_session(
    handle: &SessionHandle,
    additional_seconds: u64,
) -> Result<String, SessionError> {
    let manifest = handle.read_manifest()?;
    if is_terminal(manifest.state) {
        return Err(SessionError::Io {
            path: handle.dir.clone(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("cannot extend session in {:?} state", manifest.state),
            ),
        });
    }

    let mut lifecycle = read_lifecycle(handle)?;
    if lifecycle.ttl_seconds.is_none() {
        return Err(SessionError::Io {
            path: handle.dir.clone(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "cannot extend session without an existing TTL",
            ),
        });
    }
    let now = Utc::now();

    // Extend from the later of now or current expiry.
    let base = lifecycle
        .expires_at
        .as_ref()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc))
        .filter(|dt| *dt > now)
        .unwrap_or(now);

    let extension = seconds_to_duration(additional_seconds, &handle.dir)?;
    let new_expiry = base + extension;
    let new_expiry_str = new_expiry.to_rfc3339();

    lifecycle.expires_at = Some(new_expiry_str.clone());
    lifecycle.ttl_seconds = Some(
        lifecycle
            .ttl_seconds
            .and_then(|ttl| ttl.checked_add(additional_seconds))
            .ok_or_else(|| SessionError::Io {
                path: handle.dir.clone(),
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "ttl extension overflow",
                ),
            })?,
    );
    lifecycle.extend_count += 1;
    write_lifecycle(handle, &lifecycle)?;

    Ok(new_expiry_str)
}

/// End a session, recording the final state and reason.
pub fn end_session(
    handle: &SessionHandle,
    reason: Option<&str>,
) -> Result<EndSessionSummary, SessionError> {
    let manifest = handle.read_manifest()?;
    let now = Utc::now();
    let mut state_transitions = manifest.state_history.len();

    // Determine final state.
    let final_state = if is_terminal(manifest.state) {
        manifest.state
    } else {
        SessionState::Completed
    };

    // Update manifest state.
    if !is_terminal(manifest.state) {
        handle.update_state(final_state)?;
        state_transitions += 1;
    }

    // Update lifecycle.
    let mut lifecycle = read_lifecycle(handle)?;
    lifecycle.ended_at = Some(now.to_rfc3339());
    lifecycle.end_reason = reason.map(|s| s.to_string());
    write_lifecycle(handle, &lifecycle)?;

    // Compute duration.
    let created = DateTime::parse_from_rfc3339(&manifest.timing.created_at)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or(now);
    let duration_seconds = now.signed_duration_since(created).num_seconds();

    Ok(EndSessionSummary {
        session_id: manifest.session_id,
        final_state,
        duration_seconds,
        state_transitions,
        ended_at: now.to_rfc3339(),
        reason: reason.map(|s| s.to_string()),
    })
}

/// Expire all sessions whose TTL has elapsed, transitioning them to `Failed`.
///
/// Only considers sessions that are not already in a terminal state.
pub fn expire_sessions(store: &SessionStore) -> Result<ExpireResult, SessionError> {
    let options = ListSessionsOptions::default();
    let sessions = store.list_sessions(&options)?;
    let now = Utc::now();

    let mut result = ExpireResult {
        expired_count: 0,
        expired_sessions: Vec::new(),
        errors: Vec::new(),
    };

    for summary in sessions {
        if is_terminal(summary.state) {
            continue;
        }

        let sid = SessionId(summary.session_id.clone());
        let handle = match store.open(&sid) {
            Ok(h) => h,
            Err(e) => {
                result.errors.push(format!("{}: {}", summary.session_id, e));
                continue;
            }
        };

        let lifecycle = match read_lifecycle(&handle) {
            Ok(l) => l,
            Err(_) => continue, // No lifecycle file = no TTL management
        };

        let expired = lifecycle
            .expires_at
            .as_ref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|exp| exp.with_timezone(&Utc) <= now)
            .unwrap_or(false);

        if expired {
            match handle.update_state(SessionState::Failed) {
                Ok(_) => {
                    // Record end in lifecycle.
                    let mut lc = lifecycle;
                    lc.ended_at = Some(now.to_rfc3339());
                    lc.end_reason = Some("ttl_expired".to_string());
                    let _ = write_lifecycle(&handle, &lc);

                    result.expired_count += 1;
                    result.expired_sessions.push(summary.session_id);
                }
                Err(e) => {
                    result.errors.push(format!("{}: {}", summary.session_id, e));
                }
            }
        }
    }

    Ok(result)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn is_terminal(state: SessionState) -> bool {
    matches!(
        state,
        SessionState::Completed
            | SessionState::Cancelled
            | SessionState::Failed
            | SessionState::Archived
    )
}

fn lifecycle_path(handle: &SessionHandle) -> std::path::PathBuf {
    handle.dir.join(LIFECYCLE_FILE)
}

fn seconds_to_duration(seconds: u64, path: &std::path::Path) -> Result<Duration, SessionError> {
    let seconds_i64 = i64::try_from(seconds).map_err(|_| SessionError::Io {
        path: path.to_path_buf(),
        source: std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("ttl_seconds {} exceeds supported range", seconds),
        ),
    })?;
    Ok(Duration::seconds(seconds_i64))
}

fn write_lifecycle(handle: &SessionHandle, info: &LifecycleInfo) -> Result<(), SessionError> {
    let path = lifecycle_path(handle);
    let content = serde_json::to_string_pretty(info).map_err(|e| SessionError::Json {
        path: path.clone(),
        source: e,
    })?;
    std::fs::write(&path, content).map_err(|e| SessionError::Io { path, source: e })
}

fn read_lifecycle(handle: &SessionHandle) -> Result<LifecycleInfo, SessionError> {
    let path = lifecycle_path(handle);
    let content = std::fs::read_to_string(&path).map_err(|e| SessionError::Io {
        path: path.clone(),
        source: e,
    })?;
    serde_json::from_str(&content).map_err(|e| SessionError::Json { path, source: e })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    use std::ffi::OsString;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    struct TestStore {
        _guard: MutexGuard<'static, ()>,
        _tmp: TempDir,
        store: SessionStore,
        prev_data: Option<OsString>,
    }

    impl Drop for TestStore {
        fn drop(&mut self) {
            match &self.prev_data {
                Some(v) => std::env::set_var("PROCESS_TRIAGE_DATA", v),
                None => std::env::remove_var("PROCESS_TRIAGE_DATA"),
            }
        }
    }

    fn test_store() -> TestStore {
        let guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
        let prev_data = std::env::var_os("PROCESS_TRIAGE_DATA");

        let tmp = TempDir::new().unwrap();
        std::env::set_var("PROCESS_TRIAGE_DATA", tmp.path());
        let store = SessionStore::from_env().unwrap();

        TestStore {
            _guard: guard,
            _tmp: tmp,
            store,
            prev_data,
        }
    }

    fn default_options() -> CreateSessionOptions {
        CreateSessionOptions {
            mode: SessionMode::RobotPlan,
            label: Some("test-session".to_string()),
            parent_session_id: None,
            ttl_seconds: Some(3600),
            agent_metadata: Some(AgentMetadata {
                agent_name: "test-agent".to_string(),
                agent_version: Some("1.0.0".to_string()),
                purpose: Some("testing".to_string()),
                extra: HashMap::new(),
            }),
        }
    }

    #[test]
    fn test_create_and_status() {
        let ts = test_store();
        let store = &ts.store;
        let opts = default_options();
        let (sid, handle) = create_session(store, &opts).unwrap();

        assert!(!sid.0.is_empty());

        let status = session_status(&handle).unwrap();
        assert_eq!(status.state, SessionState::Created);
        assert!(!status.is_expired);
        assert!(status.remaining_seconds.unwrap() > 3500);
        assert_eq!(status.extend_count, 0);
        assert_eq!(
            status.agent_metadata.as_ref().unwrap().agent_name,
            "test-agent"
        );
    }

    #[test]
    fn test_create_no_ttl() {
        let ts = test_store();
        let store = &ts.store;
        let mut opts = default_options();
        opts.ttl_seconds = None;

        let (_sid, handle) = create_session(store, &opts).unwrap();
        let status = session_status(&handle).unwrap();

        assert!(!status.is_expired);
        assert!(status.expires_at.is_none());
        assert!(status.remaining_seconds.is_none());
    }

    #[test]
    fn test_extend_session() {
        let ts = test_store();
        let store = &ts.store;
        let opts = default_options();
        let (_sid, handle) = create_session(store, &opts).unwrap();

        let status_before = session_status(&handle).unwrap();
        let remaining_before = status_before.remaining_seconds.unwrap();

        let _new_expiry = extend_session(&handle, 1800).unwrap();

        let status_after = session_status(&handle).unwrap();
        let remaining_after = status_after.remaining_seconds.unwrap();

        assert!(remaining_after > remaining_before + 1700);
        assert_eq!(status_after.extend_count, 1);
    }

    #[test]
    fn test_extend_without_ttl_fails() {
        let ts = test_store();
        let store = &ts.store;
        let mut opts = default_options();
        opts.ttl_seconds = None;

        let (_sid, handle) = create_session(store, &opts).unwrap();
        let result = extend_session(&handle, 600);
        assert!(result.is_err());
    }

    #[test]
    fn test_extend_completed_session_fails() {
        let ts = test_store();
        let store = &ts.store;
        let opts = default_options();
        let (_sid, handle) = create_session(store, &opts).unwrap();

        end_session(&handle, Some("done")).unwrap();

        let result = extend_session(&handle, 1800);
        assert!(result.is_err());
    }

    #[test]
    fn test_end_session() {
        let ts = test_store();
        let store = &ts.store;
        let opts = default_options();
        let (_sid, handle) = create_session(store, &opts).unwrap();

        let summary = end_session(&handle, Some("workflow complete")).unwrap();
        assert_eq!(summary.final_state, SessionState::Completed);
        assert!(summary.duration_seconds >= 0);
        assert_eq!(summary.state_transitions, 2);
        assert_eq!(summary.reason.as_deref(), Some("workflow complete"));

        let status = session_status(&handle).unwrap();
        assert_eq!(status.state, SessionState::Completed);
    }

    #[test]
    fn test_end_already_terminal() {
        let ts = test_store();
        let store = &ts.store;
        let opts = default_options();
        let (_sid, handle) = create_session(store, &opts).unwrap();

        handle.update_state(SessionState::Failed).unwrap();

        let summary = end_session(&handle, Some("already failed")).unwrap();
        assert_eq!(summary.final_state, SessionState::Failed);
    }

    #[test]
    fn test_expire_sessions() {
        let ts = test_store();
        let store = &ts.store;

        // Create a session with 0-second TTL (already expired).
        let mut opts = default_options();
        opts.ttl_seconds = Some(0);
        let (sid1, _h1) = create_session(store, &opts).unwrap();

        // Create a session with long TTL (not expired).
        opts.ttl_seconds = Some(86400);
        let (sid2, _h2) = create_session(store, &opts).unwrap();

        // Small delay to ensure the 0-second TTL is past.
        std::thread::sleep(std::time::Duration::from_millis(10));

        let result = expire_sessions(store).unwrap();
        assert_eq!(result.expired_count, 1);
        assert!(result.expired_sessions.contains(&sid1.0));
        assert!(!result.expired_sessions.contains(&sid2.0));
    }

    #[test]
    fn test_lifecycle_roundtrip() {
        let ts = test_store();
        let store = &ts.store;
        let opts = default_options();
        let (_sid, handle) = create_session(store, &opts).unwrap();

        let info = read_lifecycle(&handle).unwrap();
        assert_eq!(info.extend_count, 0);
        assert!(info.expires_at.is_some());
        assert!(info.ended_at.is_none());

        // Verify JSON roundtrip.
        let json = serde_json::to_string_pretty(&info).unwrap();
        let restored: LifecycleInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.session_id, info.session_id);
    }

    #[test]
    fn test_multiple_extends() {
        let ts = test_store();
        let store = &ts.store;
        let opts = default_options();
        let (_sid, handle) = create_session(store, &opts).unwrap();

        extend_session(&handle, 600).unwrap();
        extend_session(&handle, 600).unwrap();
        extend_session(&handle, 600).unwrap();

        let status = session_status(&handle).unwrap();
        assert_eq!(status.extend_count, 3);
        // Original 3600 + 3*600 = 5400 seconds remaining (approximately).
        assert!(status.remaining_seconds.unwrap() > 5300);
    }

    #[test]
    fn test_session_with_parent() {
        let ts = test_store();
        let store = &ts.store;
        let opts = default_options();
        let (parent_id, _parent_handle) = create_session(store, &opts).unwrap();

        let child_opts = CreateSessionOptions {
            parent_session_id: Some(parent_id.clone()),
            ..default_options()
        };
        let (_child_id, child_handle) = create_session(store, &child_opts).unwrap();

        let manifest = child_handle.read_manifest().unwrap();
        assert_eq!(
            manifest.parent_session_id.as_deref(),
            Some(parent_id.0.as_str())
        );
    }

    #[test]
    fn test_no_agent_metadata() {
        let ts = test_store();
        let store = &ts.store;
        let mut opts = default_options();
        opts.agent_metadata = None;

        let (_sid, handle) = create_session(store, &opts).unwrap();
        let status = session_status(&handle).unwrap();
        assert!(status.agent_metadata.is_none());
    }

    #[test]
    fn test_create_session_huge_ttl_fails() {
        let ts = test_store();
        let store = &ts.store;
        let mut opts = default_options();
        opts.ttl_seconds = Some(u64::MAX);

        let result = create_session(store, &opts);
        assert!(result.is_err());
    }

    #[test]
    fn test_extend_huge_ttl_fails() {
        let ts = test_store();
        let store = &ts.store;
        let opts = default_options();
        let (_sid, handle) = create_session(store, &opts).unwrap();

        let result = extend_session(&handle, u64::MAX);
        assert!(result.is_err());
    }
}
