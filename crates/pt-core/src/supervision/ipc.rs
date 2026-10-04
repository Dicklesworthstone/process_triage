//! IPC and socket-based supervision detection.
//!
//! Detects supervision through socket connections to known supervisor IPC paths.

use super::types::{EvidenceType, SupervisionEvidence, SupervisorCategory};
#[cfg(target_os = "linux")]
use crate::collect::network::parse_proc_net_unix;
#[cfg(target_os = "linux")]
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(target_os = "linux")]
use std::sync::{Arc, Mutex};
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};
use thiserror::Error;

/// Errors from IPC detection.
#[derive(Debug, Error)]
pub enum IpcError {
    #[error("I/O error reading /proc/{pid}/fd: {source}")]
    IoError {
        pid: u32,
        #[source]
        source: std::io::Error,
    },

    #[error("Process {0} not found")]
    ProcessNotFound(u32),

    #[error("Permission denied reading /proc/{0}/fd")]
    PermissionDenied(u32),
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
    let fd_dir = format!("/proc/{}/fd", pid);
    let fd_path = Path::new(&fd_dir);

    if !fd_path.exists() {
        return Err(IpcError::ProcessNotFound(pid));
    }

    let entries = fs::read_dir(fd_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            IpcError::PermissionDenied(pid)
        } else {
            IpcError::IoError { pid, source: e }
        }
    })?;

    let mut sockets = Vec::new();
    let mut socket_inodes = Vec::new();

    for entry in entries.flatten() {
        // Read the symlink target
        if let Ok(target) = fs::read_link(entry.path()) {
            let target_str = target.to_string_lossy();

            // A socket descriptor: its bound path (if any) is in /proc/net/unix.
            if let Some(inode) = target_str
                .strip_prefix("socket:[")
                .and_then(|s| s.strip_suffix(']'))
                .and_then(|s| s.parse::<u64>().ok())
            {
                socket_inodes.push(inode);
                continue;
            }

            // Check for Unix socket paths
            if target_str.starts_with('/') || target_str.starts_with('@') {
                sockets.push(target_str.to_string());
            }
        }
    }

    if !socket_inodes.is_empty() {
        let table = unix_socket_paths_by_inode();
        sockets.extend(
            socket_inodes
                .iter()
                .filter_map(|inode| table.get(inode).cloned()),
        );
    }

    Ok(sockets)
}

/// How long one parse of /proc/net/unix is reused.
#[cfg(target_os = "linux")]
const UNIX_TABLE_TTL: Duration = Duration::from_secs(2);

/// Bound path of every unix socket, by inode, from /proc/net/unix. Supervision
/// detection asks for it once per candidate; re-parsing the whole table each time made
/// a plan O(candidates x sockets), which on a busy build host (tens of thousands of
/// sockets, every /proc/<pid>/fd readable as root) ran past test timeouts. One parse is
/// shared for `UNIX_TABLE_TTL`, so a long-running daemon still sees fresh data.
#[cfg(target_os = "linux")]
fn unix_socket_paths_by_inode() -> Arc<HashMap<u64, String>> {
    static CACHE: Mutex<Option<(Instant, Arc<HashMap<u64, String>>)>> = Mutex::new(None);
    let mut cached = CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some((parsed_at, table)) = cached.as_ref() {
        if parsed_at.elapsed() < UNIX_TABLE_TTL {
            return Arc::clone(table);
        }
    }
    let table: HashMap<u64, String> = parse_proc_net_unix("/proc/net/unix")
        .unwrap_or_default()
        .into_iter()
        .filter_map(|socket| {
            socket
                .path
                .filter(|path| !path.is_empty())
                .map(|path| (socket.inode, path))
        })
        .collect();
    let table = Arc::new(table);
    *cached = Some((Instant::now(), Arc::clone(&table)));
    table
}

#[cfg(not(target_os = "linux"))]
pub fn read_socket_paths(_pid: u32) -> Result<Vec<String>, IpcError> {
    Ok(vec![])
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
        Ok(self.analyze_sockets(&sockets))
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

        let first = unix_socket_paths_by_inode();
        let second = unix_socket_paths_by_inode();
        assert!(Arc::ptr_eq(&first, &second), "parsed twice within the TTL");
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
