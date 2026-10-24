//! IPC and socket-based supervision detection.
//!
//! Detects supervision through socket connections to known supervisor IPC paths.

use super::types::{EvidenceType, SupervisionEvidence, SupervisorCategory};
#[cfg(target_os = "linux")]
use crate::collect::network::{has_inet_socket_inode, parse_proc_net_unix};
#[cfg(target_os = "linux")]
use crate::collect::proc_parsers::read_required_proc_stat;
use crate::collect::proc_parsers::StatReadError;
#[cfg(target_os = "linux")]
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;
#[cfg(target_os = "linux")]
use std::sync::{Arc, Mutex};
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};
use thiserror::Error;

/// Errors from IPC detection.
#[derive(Debug, Error)]
pub enum IpcError {
    #[error("I/O error reading {path} for PID {pid}: {source}")]
    IoError {
        pid: u32,
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Process {0} not found")]
    ProcessNotFound(u32),

    #[error("Permission denied reading /proc/{0}/fd")]
    PermissionDenied(u32),

    #[error("Invalid IPC evidence at {path} for PID {pid}: {reason}")]
    Parse {
        pid: u32,
        path: String,
        reason: String,
    },

    #[error("IPC identity evidence failed: {0}")]
    Identity(#[from] StatReadError),

    #[error("Process {0} changed while reading IPC evidence")]
    ProcessChanged(u32),

    #[error("IPC evidence for PID {0} is unsupported on this platform")]
    Unsupported(u32),

    #[error("IPC protocol or socket namespace is unknown for PID {pid}, inode {inode}")]
    UnclassifiedSocket { pid: u32, inode: u64 },
}

/// Pattern for detecting supervisor IPC sockets.
#[derive(Debug, Clone)]
pub struct IpcPattern {
    /// Name of the supervisor.
    pub supervisor_name: String,
    /// Category of supervisor.
    pub category: SupervisorCategory,
    /// Path pattern (prefix match).
    pub path_prefix: String,
    /// Whether this is an abstract socket (starts with @).
    pub is_abstract: bool,
    /// Confidence weight.
    pub confidence: f64,
}

impl IpcPattern {
    /// Create a new IPC pattern for a file path.
    pub fn path(
        name: impl Into<String>,
        category: SupervisorCategory,
        prefix: impl Into<String>,
        confidence: f64,
    ) -> Self {
        Self {
            supervisor_name: name.into(),
            category,
            path_prefix: prefix.into(),
            is_abstract: false,
            confidence,
        }
    }

    /// Create a pattern for an abstract socket.
    pub fn abstract_socket(
        name: impl Into<String>,
        category: SupervisorCategory,
        prefix: impl Into<String>,
        confidence: f64,
    ) -> Self {
        Self {
            supervisor_name: name.into(),
            category,
            path_prefix: prefix.into(),
            is_abstract: true,
            confidence,
        }
    }
}

/// Result of IPC-based supervision detection.
#[derive(Debug, Clone)]
pub struct IpcResult {
    /// Whether supervision was detected via IPC.
    pub is_supervised: bool,
    /// Detected supervisor name (if any).
    pub supervisor_name: Option<String>,
    /// Detected supervisor category (if any).
    pub category: Option<SupervisorCategory>,
    /// Confidence score.
    pub confidence: f64,
    /// Evidence found.
    pub evidence: Vec<SupervisionEvidence>,
    /// Socket paths that matched.
    pub matched_sockets: Vec<String>,
}

impl IpcResult {
    /// Create a result indicating no supervision detected.
    pub fn not_supervised() -> Self {
        Self {
            is_supervised: false,
            supervisor_name: None,
            category: None,
            confidence: 0.0,
            evidence: vec![],
            matched_sockets: vec![],
        }
    }

    /// Create a result indicating supervision detected.
    pub fn supervised(
        name: String,
        category: SupervisorCategory,
        confidence: f64,
        evidence: Vec<SupervisionEvidence>,
        matched_sockets: Vec<String>,
    ) -> Self {
        Self {
            is_supervised: true,
            supervisor_name: Some(name),
            category: Some(category),
            confidence,
            evidence,
            matched_sockets,
        }
    }
}

/// Database of IPC patterns for supervision detection.
#[derive(Debug, Clone, Default)]
pub struct IpcDatabase {
    patterns: Vec<IpcPattern>,
}

impl IpcDatabase {
    /// Create a new empty database.
    pub fn new() -> Self {
        Self { patterns: vec![] }
    }

    /// Create with default patterns.
    pub fn with_defaults() -> Self {
        let mut db = Self::new();
        db.add_default_patterns();
        db
    }

    /// Add a pattern.
    pub fn add(&mut self, pattern: IpcPattern) {
        self.patterns.push(pattern);
    }

    /// Add all default patterns.
    pub fn add_default_patterns(&mut self) {
        // VS Code IPC sockets
        // Typical paths: /run/user/<uid>/vscode-ipc-*, /tmp/vscode-*
        self.add(IpcPattern::path(
            "vscode",
            SupervisorCategory::Ide,
            "/run/user/",
            0.80,
        )); // Will check for vscode in path
        self.add(IpcPattern::path(
            "vscode",
            SupervisorCategory::Ide,
            "/tmp/vscode-",
            0.85,
        ));

        // Claude agent sockets
        self.add(IpcPattern::path(
            "claude",
            SupervisorCategory::Agent,
            "/tmp/claude-",
            0.90,
        ));
        self.add(IpcPattern::path(
            "claude",
            SupervisorCategory::Agent,
            "/run/user/",
            0.80,
        )); // Will check for claude in path

        // Codex agent sockets
        self.add(IpcPattern::path(
            "codex",
            SupervisorCategory::Agent,
            "/tmp/codex-",
            0.90,
        ));

        // JetBrains IDE sockets
        self.add(IpcPattern::path(
            "jetbrains",
            SupervisorCategory::Ide,
            "/tmp/.java_pid",
            0.70,
        ));

        // tmux sockets
        self.add(IpcPattern::path(
            "tmux",
            SupervisorCategory::Terminal,
            "/tmp/tmux-",
            0.30,
        ));

        // Systemd user sockets
        self.add(IpcPattern::path(
            "systemd",
            SupervisorCategory::Orchestrator,
            "/run/user/",
            0.60,
        )); // Will check for systemd in path

        // Abstract sockets (Linux)
        self.add(IpcPattern::abstract_socket(
            "dbus",
            SupervisorCategory::Other,
            "/tmp/dbus-",
            0.50,
        ));
    }

    /// Find matching patterns for a socket path.
    pub fn find_matches(&self, socket_path: &str) -> Vec<&IpcPattern> {
        self.patterns
            .iter()
            .filter(|p| {
                if p.is_abstract {
                    socket_path
                        .strip_prefix('@')
                        .is_some_and(|rest| rest.starts_with(&p.path_prefix))
                } else {
                    socket_path.starts_with(&p.path_prefix)
                        && self.path_contains_supervisor_name(socket_path, &p.supervisor_name)
                }
            })
            .collect()
    }

    /// Check if path contains supervisor name (for generic prefixes like /run/user/).
    fn path_contains_supervisor_name(&self, path: &str, name: &str) -> bool {
        // For specific prefixes (like /tmp/vscode-), always match
        if !path.starts_with("/run/user/") && !path.starts_with("/tmp/") {
            return true;
        }

        // For generic prefixes, check if supervisor name appears in path
        let lower_path = path.to_lowercase();
        let lower_name = name.to_lowercase();
        lower_path.contains(&lower_name)
    }
}

/// Read socket paths connected by a process.
#[cfg(target_os = "linux")]
pub fn read_socket_paths(pid: u32) -> Result<Vec<String>, IpcError> {
    read_socket_paths_with_refresh(pid, false)
}

#[cfg(target_os = "linux")]
fn read_socket_paths_with_refresh(pid: u32, refresh: bool) -> Result<Vec<String>, IpcError> {
    let before = read_required_proc_stat(pid)?;
    let fd_dir = format!("/proc/{}/fd", pid);
    let entries = fs::read_dir(&fd_dir).map_err(|source| IpcError::IoError {
        pid,
        path: fd_dir.clone(),
        source,
    })?;

    let mut sockets = Vec::new();
    let mut socket_inodes = Vec::new();

    for entry in entries {
        let entry = entry.map_err(|source| IpcError::IoError {
            pid,
            path: fd_dir.clone(),
            source,
        })?;
        // Read the symlink target
        let target = fs::read_link(entry.path()).map_err(|source| IpcError::IoError {
            pid,
            path: entry.path().display().to_string(),
            source,
        })?;
        let target_str = target.to_str().ok_or_else(|| IpcError::Parse {
            pid,
            path: entry.path().display().to_string(),
            reason: "invalid descriptor-link UTF-8".to_string(),
        })?;

        // A socket descriptor: its bound path (if any) is in /proc/net/unix.
        if let Some(value) = target_str.strip_prefix("socket:[") {
            let inode = value
                .strip_suffix(']')
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or_else(|| IpcError::Parse {
                    pid,
                    path: entry.path().display().to_string(),
                    reason: "invalid socket inode link".to_string(),
                })?;
            socket_inodes.push(inode);
            continue;
        }

        // Check for Unix socket paths
        if target_str.starts_with('/') || target_str.starts_with('@') {
            sockets.push(target_str.to_string());
        }
    }

    if !socket_inodes.is_empty() {
        let mut table = unix_socket_paths_by_inode(pid, refresh)?;
        if !refresh
            && socket_inodes
                .iter()
                .any(|inode| table.get(inode).is_none_or(|path| path.is_none()))
        {
            table = unix_socket_paths_by_inode(pid, true)?;
        }
        for inode in socket_inodes {
            if let Some(path) = table.get(&inode) {
                if let Some(path) = path {
                    sockets.push(path.clone());
                }
            } else if !has_inet_socket_inode(pid, inode).map_err(|source| IpcError::IoError {
                pid,
                path: format!("/proc/{pid}/net TCP/UDP tables"),
                source,
            })? {
                return Err(IpcError::UnclassifiedSocket { pid, inode });
            }
        }
    }

    let after = read_required_proc_stat(pid)?;
    if after.starttime != before.starttime {
        return Err(IpcError::ProcessChanged(pid));
    }

    Ok(sockets)
}

/// How long one parse of /proc/net/unix is reused.
#[cfg(target_os = "linux")]
const UNIX_TABLE_TTL: Duration = Duration::from_secs(2);

/// A successful table in one observed network namespace. Cached positives can
/// conservatively block; the analyzer refreshes before admitting a negative.
#[cfg(target_os = "linux")]
struct CachedUnixSocketPaths {
    namespace: (u64, u64),
    parsed_at: Instant,
    table: Arc<HashMap<u64, Option<String>>>,
}

#[cfg(target_os = "linux")]
fn unix_socket_paths_by_inode(
    pid: u32,
    refresh: bool,
) -> Result<Arc<HashMap<u64, Option<String>>>, IpcError> {
    static CACHE: Mutex<Option<CachedUnixSocketPaths>> = Mutex::new(None);
    let namespace_path = format!("/proc/{pid}/ns/net");
    let namespace = fs::metadata(&namespace_path).map_err(|source| IpcError::IoError {
        pid,
        path: namespace_path.clone(),
        source,
    })?;
    let namespace = (namespace.dev(), namespace.ino());
    let mut cached = CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(entry) = cached.as_ref() {
        if !refresh && entry.namespace == namespace && entry.parsed_at.elapsed() < UNIX_TABLE_TTL {
            return Ok(Arc::clone(&entry.table));
        }
    }
    let table_path = format!("/proc/{pid}/net/unix");
    let table: HashMap<u64, Option<String>> = parse_proc_net_unix(&table_path)
        .map_err(|source| IpcError::IoError {
            pid,
            path: table_path,
            source,
        })?
        .into_iter()
        .map(|socket| (socket.inode, socket.path.filter(|path| !path.is_empty())))
        .collect();
    let after_namespace = fs::metadata(&namespace_path).map_err(|source| IpcError::IoError {
        pid,
        path: namespace_path,
        source,
    })?;
    if (after_namespace.dev(), after_namespace.ino()) != namespace {
        return Err(IpcError::ProcessChanged(pid));
    }
    let table = Arc::new(table);
    *cached = Some(CachedUnixSocketPaths {
        namespace,
        parsed_at: Instant::now(),
        table: Arc::clone(&table),
    });
    Ok(table)
}

#[cfg(not(target_os = "linux"))]
pub fn read_socket_paths(pid: u32) -> Result<Vec<String>, IpcError> {
    Err(IpcError::Unsupported(pid))
}

/// Analyzer for IPC-based supervision detection.
pub struct IpcAnalyzer {
    database: IpcDatabase,
}

impl IpcAnalyzer {
    /// Create a new analyzer with default patterns.
    pub fn new() -> Self {
        Self {
            database: IpcDatabase::with_defaults(),
        }
    }

    /// Create an analyzer with a custom database.
    pub fn with_database(database: IpcDatabase) -> Self {
        Self { database }
    }

    /// Analyze a process for supervision via IPC.
    pub fn analyze(&self, pid: u32) -> Result<IpcResult, IpcError> {
        let sockets = read_socket_paths(pid)?;
        let result = self.analyze_sockets(&sockets);
        #[cfg(target_os = "linux")]
        if !result.is_supervised {
            // A cached positive can conservatively block; absence needs a fresh table.
            let sockets = read_socket_paths_with_refresh(pid, true)?;
            return Ok(self.analyze_sockets(&sockets));
        }
        Ok(result)
    }

    /// Analyze a list of socket paths.
    pub fn analyze_sockets(&self, sockets: &[String]) -> IpcResult {
        let mut best_match: Option<(&IpcPattern, &str)> = None;
        let mut all_evidence = Vec::new();
        let mut matched_sockets = Vec::new();

        for socket in sockets {
            let matches = self.database.find_matches(socket);
            for pattern in matches {
                all_evidence.push(SupervisionEvidence {
                    evidence_type: EvidenceType::Socket,
                    description: format!(
                        "Socket {} matches {} supervision pattern",
                        socket, pattern.supervisor_name
                    ),
                    weight: pattern.confidence,
                });
                matched_sockets.push(socket.clone());

                let is_better = match &best_match {
                    Some((best_pattern, _)) => pattern.confidence > best_pattern.confidence,
                    None => true,
                };

                if is_better {
                    best_match = Some((pattern, socket));
                }
            }
        }

        if let Some((pattern, _)) = best_match {
            IpcResult::supervised(
                pattern.supervisor_name.clone(),
                pattern.category,
                pattern.confidence,
                all_evidence,
                matched_sockets,
            )
        } else {
            IpcResult::not_supervised()
        }
    }
}

impl Default for IpcAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience function to check a single process.
pub fn detect_ipc_supervision(pid: u32) -> Result<IpcResult, IpcError> {
    let analyzer = IpcAnalyzer::new();
    analyzer.analyze(pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A unix socket this process binds is found through the shared inode table, and
    /// repeated lookups within the TTL reuse one parse.
    #[cfg(target_os = "linux")]
    #[test]
    fn bound_socket_path_found_through_shared_table() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pt-ipc-test.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        // The cache may hold a table from before the bind; let it expire.
        std::thread::sleep(UNIX_TABLE_TTL + Duration::from_millis(50));

        let sockets = read_socket_paths(std::process::id()).unwrap();
        let wanted = path.to_string_lossy().to_string();
        assert!(sockets.contains(&wanted), "{wanted} not in {sockets:?}");

        let first = unix_socket_paths_by_inode(std::process::id(), false).unwrap();
        let second = unix_socket_paths_by_inode(std::process::id(), false).unwrap();
        assert!(Arc::ptr_eq(&first, &second), "parsed twice within the TTL");

        // A bind after the warm table must not disappear into cached absence.
        let later = dir.path().join("pt-later.sock");
        let _later_listener = std::os::unix::net::UnixListener::bind(&later).unwrap();
        assert!(read_socket_paths(std::process::id())
            .unwrap()
            .contains(&later.to_string_lossy().to_string()));
        let error = unix_socket_paths_by_inode(u32::MAX, true).unwrap_err();
        assert!(matches!(error, IpcError::IoError { pid, .. } if pid == u32::MAX));
    }

    #[test]
    fn test_ipc_database_defaults() {
        let db = IpcDatabase::with_defaults();
        assert!(!db.patterns.is_empty());
    }

    #[test]
    fn test_ipc_database_find_matches_vscode() {
        let db = IpcDatabase::with_defaults();
        let matches = db.find_matches("/tmp/vscode-ipc-12345.sock");
        assert!(!matches.is_empty());
        assert_eq!(matches[0].supervisor_name, "vscode");
    }

    #[test]
    fn test_ipc_database_find_matches_claude() {
        let db = IpcDatabase::with_defaults();
        let matches = db.find_matches("/tmp/claude-session-abc123");
        assert!(!matches.is_empty());
        assert_eq!(matches[0].supervisor_name, "claude");
    }

    #[test]
    fn test_ipc_database_no_match() {
        let db = IpcDatabase::with_defaults();
        let matches = db.find_matches("/var/run/random.sock");
        assert!(matches.is_empty());
    }

    #[test]
    fn test_ipc_analyzer_no_match() {
        let analyzer = IpcAnalyzer::new();
        let result = analyzer.analyze_sockets(&["/var/run/other.sock".to_string()]);

        assert!(!result.is_supervised);
        assert!(result.evidence.is_empty());
    }

    #[test]
    fn test_ipc_analyzer_match() {
        let analyzer = IpcAnalyzer::new();
        let result = analyzer.analyze_sockets(&["/tmp/vscode-ipc-12345.sock".to_string()]);

        assert!(result.is_supervised);
        assert_eq!(result.supervisor_name, Some("vscode".to_string()));
        assert_eq!(result.category, Some(SupervisorCategory::Ide));
    }

    #[test]
    fn test_ipc_result_not_supervised() {
        let result = IpcResult::not_supervised();
        assert!(!result.is_supervised);
        assert!(result.supervisor_name.is_none());
    }

    #[test]
    fn test_ipc_database_find_matches_abstract_dbus() {
        let db = IpcDatabase::with_defaults();
        let matches = db.find_matches("@/tmp/dbus-session-12345");
        assert!(!matches.is_empty());
        assert_eq!(matches[0].supervisor_name, "dbus");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_read_socket_paths_current_process() {
        let pid = std::process::id();
        // This may fail with permission denied for non-root, that's OK
        let _ = read_socket_paths(pid);
    }
}
