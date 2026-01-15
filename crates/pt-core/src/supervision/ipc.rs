//! IPC and socket-based supervision detection.
//!
//! Detects supervision through socket connections to known supervisor IPC paths.

use super::types::{EvidenceType, SupervisionEvidence, SupervisorCategory};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
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
            "@/tmp/dbus-",
            0.50,
        ));
    }

    /// Find matching patterns for a socket path.
    pub fn find_matches(&self, socket_path: &str) -> Vec<&IpcPattern> {
        self.patterns
            .iter()
            .filter(|p| {
                if p.is_abstract {
                    socket_path.starts_with('@') && socket_path[1..].starts_with(&p.path_prefix)
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

    for entry in entries.flatten() {
        // Read the symlink target
        if let Ok(target) = fs::read_link(entry.path()) {
            let target_str = target.to_string_lossy();

            // Check if it's a socket
            if target_str.starts_with("socket:[") {
                // It's a socket, but we can't easily get the path from here
                // We'd need to parse /proc/net/unix
                continue;
            }

            // Check for Unix socket paths
            if target_str.starts_with('/') || target_str.starts_with('@') {
                sockets.push(target_str.to_string());
            }
        }
    }

    // Also parse /proc/net/unix for this process's sockets
    if let Ok(unix_sockets) = read_unix_sockets(pid) {
        sockets.extend(unix_sockets);
    }

    Ok(sockets)
}

#[cfg(not(target_os = "linux"))]
pub fn read_socket_paths(_pid: u32) -> Result<Vec<String>, IpcError> {
    Ok(vec![])
}

/// Parse /proc/net/unix to find sockets for a specific process.
#[cfg(target_os = "linux")]
fn read_unix_sockets(pid: u32) -> Result<Vec<String>, std::io::Error> {
    // Get inodes from /proc/<pid>/fd
    let fd_dir = format!("/proc/{}/fd", pid);
    let mut socket_inodes = HashSet::new();

    if let Ok(entries) = fs::read_dir(&fd_dir) {
        for entry in entries.flatten() {
            if let Ok(target) = fs::read_link(entry.path()) {
                let target_str = target.to_string_lossy();
                if target_str.starts_with("socket:[") {
                    // Extract inode number
                    if let Some(inode_str) = target_str
                        .strip_prefix("socket:[")
                        .and_then(|s| s.strip_suffix(']'))
                    {
                        if let Ok(inode) = inode_str.parse::<u64>() {
                            socket_inodes.insert(inode);
                        }
                    }
                }
            }
        }
    }

    if socket_inodes.is_empty() {
        return Ok(vec![]);
    }

    // Parse /proc/net/unix
    let content = fs::read_to_string("/proc/net/unix")?;
    let mut paths = Vec::new();

    for line in content.lines().skip(1) {
        // Skip header
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 7 {
            // Format: Num RefCount Protocol Flags Type St Inode Path
            if let Ok(inode) = fields[6].parse::<u64>() {
                if socket_inodes.contains(&inode) {
                    // Path is optional, fields[7] if present
                    if fields.len() > 7 {
                        paths.push(fields[7].to_string());
                    }
                }
            }
        }
    }

    Ok(paths)
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

                if best_match.is_none() || pattern.confidence > best_match.unwrap().0.confidence {
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

    #[cfg(target_os = "linux")]
    #[test]
    fn test_read_socket_paths_current_process() {
        let pid = std::process::id();
        // This may fail with permission denied for non-root, that's OK
        let _ = read_socket_paths(pid);
    }
}
