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
    /// Whether any matched socket identifies a human-supervised context,
    /// independently of the highest-confidence diagnostic match.
    pub human_supervised: bool,
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
            human_supervised: false,
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
            human_supervised: category.requires_human_confirmation(),
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
    read_socket_paths_with_refresh(pid, false, None)
}

#[cfg(target_os = "linux")]
fn read_socket_paths_with_refresh(
    pid: u32,
    refresh: bool,
    scan: Option<&ScanUnixSocketPaths>,
) -> Result<Vec<String>, IpcError> {
    let before = read_required_proc_stat(pid)?;
    let scan_namespace = match scan {
        Some(snapshot) => {
            let (namespace, handle) = open_network_namespace(pid)?;
            Some((snapshot, namespace, handle))
        }
        None => None,
    };
    let expected_namespace = scan_namespace.as_ref().map(|(_, namespace, _)| *namespace);
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
        let mut table = match scan_namespace {
            Some((snapshot, namespace, handle)) => snapshot.table_for(pid, namespace, handle)?,
            None => unix_socket_paths_by_inode(pid, refresh)?,
        };
        if scan.is_none()
            && !refresh
            && socket_inodes
                .iter()
                .any(|inode| table.get(inode).is_none_or(|path| path.is_none()))
        {
            table = unix_socket_paths_by_inode(pid, true)?;
        }
        // An unnamed Unix socket can acquire a supervisor path without changing
        // its inode. Refresh those uncertain entries before admitting a negative,
        // but retain the original scan view for every other inode. In particular,
        // a missing inode must not become trusted merely because an unrelated
        // unnamed descriptor triggered this read.
        let unnamed = if let Some(snapshot) = scan.filter(|_| {
            socket_inodes
                .iter()
                .any(|inode| matches!(table.get(inode), Some(None)))
        }) {
            #[cfg(test)]
            snapshot
                .table_reads
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            #[cfg(not(test))]
            let _ = snapshot;
            Some(unix_socket_paths_by_inode(pid, true)?)
        } else {
            None
        };
        for inode in socket_inodes {
            let observed = match table.get(&inode) {
                Some(None) if unnamed.is_some() => {
                    unnamed.as_ref().and_then(|view| view.get(&inode))
                }
                observed => observed,
            };
            if let Some(path) = observed {
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

    if let Some(namespace) = expected_namespace {
        check_network_namespace(pid, namespace)?;
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

#[cfg(target_os = "linux")]
type NetworkNamespace = (u64, u64);

#[cfg(target_os = "linux")]
type UnixSocketPaths = HashMap<u64, Option<String>>;

/// Scan evidence is scoped to the detector, never the action-time global cache.
/// Keep each namespace open so its inode cannot be recycled while a view is used.
#[cfg(target_os = "linux")]
#[derive(Default)]
struct ScanUnixSocketPaths {
    tables: Mutex<HashMap<NetworkNamespace, ScanUnixSocketTable>>,
    #[cfg(test)]
    table_reads: std::sync::atomic::AtomicUsize,
}

#[cfg(target_os = "linux")]
struct ScanUnixSocketTable {
    _namespace: fs::File,
    table: Arc<UnixSocketPaths>,
}

#[cfg(target_os = "linux")]
impl ScanUnixSocketPaths {
    fn table_for(
        &self,
        pid: u32,
        namespace: NetworkNamespace,
        handle: fs::File,
    ) -> Result<Arc<UnixSocketPaths>, IpcError> {
        check_network_namespace(pid, namespace)?;
        let mut tables = self
            .tables
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(entry) = tables.get(&namespace) {
            return Ok(Arc::clone(&entry.table));
        }
        #[cfg(test)]
        self.table_reads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let table = read_unix_socket_paths(pid)?;
        check_network_namespace(pid, namespace)?;
        tables.insert(
            namespace,
            ScanUnixSocketTable {
                _namespace: handle,
                table: Arc::clone(&table),
            },
        );
        Ok(table)
    }
}

#[cfg(target_os = "linux")]
fn open_network_namespace(pid: u32) -> Result<(NetworkNamespace, fs::File), IpcError> {
    let path = format!("/proc/{pid}/ns/net");
    let failure = |source| IpcError::IoError {
        pid,
        path: path.clone(),
        source,
    };
    let handle = fs::File::open(&path).map_err(failure)?;
    let metadata = handle.metadata().map_err(failure)?;
    Ok(((metadata.dev(), metadata.ino()), handle))
}

#[cfg(target_os = "linux")]
fn check_network_namespace(pid: u32, expected: NetworkNamespace) -> Result<(), IpcError> {
    let path = format!("/proc/{pid}/ns/net");
    let metadata = fs::metadata(&path).map_err(|source| IpcError::IoError { pid, path, source })?;
    if (metadata.dev(), metadata.ino()) != expected {
        return Err(IpcError::ProcessChanged(pid));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_unix_socket_paths(pid: u32) -> Result<Arc<UnixSocketPaths>, IpcError> {
    let path = format!("/proc/{pid}/net/unix");
    let table = parse_proc_net_unix(&path)
        .map_err(|source| IpcError::IoError { pid, path, source })?
        .into_iter()
        .map(|socket| (socket.inode, socket.path.filter(|path| !path.is_empty())))
        .collect();
    Ok(Arc::new(table))
}

/// A successful table in one observed network namespace. Cached positives can
/// conservatively block; the analyzer refreshes before admitting a negative.
#[cfg(target_os = "linux")]
struct CachedUnixSocketPaths {
    namespace: NetworkNamespace,
    parsed_at: Instant,
    table: Arc<UnixSocketPaths>,
}

#[cfg(target_os = "linux")]
fn unix_socket_paths_by_inode(pid: u32, refresh: bool) -> Result<Arc<UnixSocketPaths>, IpcError> {
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
    let table = read_unix_socket_paths(pid)?;
    check_network_namespace(pid, namespace)?;
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
    #[cfg(target_os = "linux")]
    scan: Option<ScanUnixSocketPaths>,
}

impl IpcAnalyzer {
    /// Create a new analyzer with default patterns.
    pub fn new() -> Self {
        Self {
            database: IpcDatabase::with_defaults(),
            #[cfg(target_os = "linux")]
            scan: None,
        }
    }

    /// Reuse one strict Unix-socket view per network namespace during a read-only
    /// scan. Descriptors and process/namespace identities are still read live;
    /// sockets absent from that view must be classified or reported as unknown.
    /// Known unnamed sockets are refreshed because a later bind can name them.
    /// Create a new analyzer for every scan or watch refresh; views do not expire.
    /// Never use this constructor for action-time authorization.
    pub fn for_scan() -> Self {
        Self {
            database: IpcDatabase::with_defaults(),
            #[cfg(target_os = "linux")]
            scan: Some(ScanUnixSocketPaths::default()),
        }
    }

    /// Create an analyzer with a custom database.
    pub fn with_database(database: IpcDatabase) -> Self {
        Self {
            database,
            #[cfg(target_os = "linux")]
            scan: None,
        }
    }

    /// Analyze a process for supervision via IPC.
    pub fn analyze(&self, pid: u32) -> Result<IpcResult, IpcError> {
        #[cfg(target_os = "linux")]
        if let Some(snapshot) = self.scan.as_ref() {
            let sockets = read_socket_paths_with_refresh(pid, false, Some(snapshot))?;
            return Ok(self.analyze_sockets(&sockets));
        }
        let sockets = read_socket_paths(pid)?;
        let result = self.analyze_sockets(&sockets);
        #[cfg(target_os = "linux")]
        if !result.is_supervised {
            // A cached positive can conservatively block; absence needs a fresh table.
            let sockets = read_socket_paths_with_refresh(pid, true, None)?;
            return Ok(self.analyze_sockets(&sockets));
        }
        Ok(result)
    }

    /// Analyze a list of socket paths.
    pub fn analyze_sockets(&self, sockets: &[String]) -> IpcResult {
        let mut best_match: Option<(&IpcPattern, &str)> = None;
        let mut all_evidence = Vec::new();
        let mut matched_sockets = Vec::new();
        let mut human_supervised = false;

        for socket in sockets {
            let matches = self.database.find_matches(socket);
            for pattern in matches {
                human_supervised |= pattern.category.requires_human_confirmation();
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
            let mut result = IpcResult::supervised(
                pattern.supervisor_name.clone(),
                pattern.category,
                pattern.confidence,
                all_evidence,
                matched_sockets,
            );
            result.human_supervised = human_supervised;
            result
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

    #[cfg(target_os = "linux")]
    mod scan_tests {
        use super::*;
        use std::os::fd::{AsRawFd, OwnedFd};
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::net::{UnixDatagram, UnixListener};
        use std::path::Path;
        use std::process::{Child, Command, Stdio};
        use std::sync::atomic::Ordering;

        struct SocketChild(Child);

        impl SocketChild {
            fn new(path: &Path) -> Self {
                let socket: OwnedFd = UnixListener::bind(path).unwrap().into();
                Self::with_socket(socket, Stdio::null())
            }

            fn with_socket(socket: OwnedFd, stderr: Stdio) -> Self {
                Self(
                    Command::new("sleep")
                        .arg("60")
                        .stdin(Stdio::from(socket))
                        .stdout(Stdio::null())
                        .stderr(stderr)
                        .spawn()
                        .unwrap(),
                )
            }

            fn pid(&self) -> u32 {
                self.0.id()
            }
        }

        #[test]
        fn scan_refreshes_a_known_unnamed_socket_after_late_bind() {
            let socket = UnixDatagram::unbound().unwrap();
            let child = SocketChild::with_socket(socket.try_clone().unwrap().into(), Stdio::null());
            let scan = IpcAnalyzer::for_scan();
            assert!(!scan.analyze(child.pid()).unwrap().is_supervised);
            let snapshot = scan.scan.as_ref().unwrap();
            let original_tables: Vec<_> = snapshot
                .tables
                .lock()
                .unwrap()
                .values()
                .map(|entry| Arc::clone(&entry.table))
                .collect();
            assert_eq!(snapshot.table_reads.load(Ordering::Relaxed), 2);

            let directory = tempfile::Builder::new()
                .prefix("vscode-")
                .tempdir_in("/tmp")
                .unwrap();
            let path = directory.path().join("late.sock");
            let path_bytes = path.as_os_str().as_bytes();
            // SAFETY: zero initializes the sockaddr including its terminated path.
            let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
            address.sun_family = libc::AF_UNIX as libc::sa_family_t;
            assert!(path_bytes.len() < address.sun_path.len());
            for (out, byte) in address.sun_path.iter_mut().zip(path_bytes) {
                *out = *byte as libc::c_char;
            }
            // SAFETY: address is a fully initialized sockaddr_un with a bounded,
            // NUL-terminated pathname; the live owned datagram descriptor is valid.
            let bound = unsafe {
                libc::bind(
                    socket.as_raw_fd(),
                    std::ptr::from_ref(&address).cast(),
                    std::mem::size_of_val(&address) as libc::socklen_t,
                )
            };
            assert_eq!(
                bound,
                0,
                "late bind failed: {}",
                std::io::Error::last_os_error()
            );
            let observed = scan.analyze(child.pid()).unwrap();
            assert!(observed.is_supervised);
            assert_eq!(observed.supervisor_name.as_deref(), Some("vscode"));
            assert_eq!(snapshot.table_reads.load(Ordering::Relaxed), 3);
            let tables = snapshot.tables.lock().unwrap();
            assert_eq!(tables.len(), original_tables.len());
            assert!(tables.values().all(|entry| original_tables
                .iter()
                .any(|original| Arc::ptr_eq(original, &entry.table))));
            assert!(original_tables
                .iter()
                .all(|table| !table.values().any(|name| name.as_deref() == path.to_str())));
        }

        #[test]
        fn unnamed_refresh_does_not_admit_a_previously_missing_inode() {
            let unnamed = UnixDatagram::unbound().unwrap();
            let original =
                SocketChild::with_socket(unnamed.try_clone().unwrap().into(), Stdio::null());
            let scan = IpcAnalyzer::for_scan();
            assert!(!scan.analyze(original.pid()).unwrap().is_supervised);
            let directory = tempfile::Builder::new()
                .prefix("vscode-")
                .tempdir_in("/tmp")
                .unwrap();
            let new_socket: OwnedFd = UnixListener::bind(directory.path().join("new.sock"))
                .unwrap()
                .into();
            let mixed = SocketChild::with_socket(
                unnamed.try_clone().unwrap().into(),
                Stdio::from(new_socket),
            );
            assert!(matches!(
                scan.analyze(mixed.pid()),
                Err(IpcError::UnclassifiedSocket { pid, .. }) if pid == mixed.pid()
            ));
            assert!(
                IpcAnalyzer::new()
                    .analyze(mixed.pid())
                    .unwrap()
                    .is_supervised
            );
        }

        impl Drop for SocketChild {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        #[test]
        fn scan_reuses_one_strict_table_for_unsupervised_candidates() {
            let directory = tempfile::tempdir().unwrap();
            let children: Vec<_> = (0..8)
                .map(|index| SocketChild::new(&directory.path().join(format!("{index}.sock"))))
                .collect();
            let scan = IpcAnalyzer::for_scan();
            let live = IpcAnalyzer::new();
            for child in &children {
                let observed = scan.analyze(child.pid()).unwrap();
                assert!(!observed.is_supervised);
                // Both modes inspect the same real, stable descriptors. Reusing
                // negative scan evidence must not change their classification.
                let current = live.analyze(child.pid()).unwrap();
                assert_eq!(observed.is_supervised, current.is_supervised);
                assert_eq!(observed.matched_sockets, current.matched_sockets);
                assert!(!scan.analyze(child.pid()).unwrap().is_supervised);
            }
            let snapshot = scan.scan.as_ref().unwrap();
            assert_eq!(snapshot.table_reads.load(Ordering::Relaxed), 1);
            assert_eq!(snapshot.tables.lock().unwrap().len(), 1);
            assert!(live.scan.is_none());
        }

        #[test]
        fn scan_refuses_new_unix_inodes_while_live_and_new_scan_refresh() {
            let directory = tempfile::tempdir().unwrap();
            let original = SocketChild::new(&directory.path().join("original.sock"));
            let scan = IpcAnalyzer::for_scan();
            assert!(!scan.analyze(original.pid()).unwrap().is_supervised);

            let supervised_directory = tempfile::Builder::new()
                .prefix("vscode-")
                .tempdir_in("/tmp")
                .unwrap();
            let supervised = SocketChild::new(&supervised_directory.path().join("ipc.sock"));
            assert!(matches!(
                scan.analyze(supervised.pid()),
                Err(IpcError::UnclassifiedSocket { pid, .. }) if pid == supervised.pid()
            ));
            assert_eq!(
                scan.scan
                    .as_ref()
                    .unwrap()
                    .table_reads
                    .load(Ordering::Relaxed),
                1
            );

            // A scan view must never leak into action-time detection, and a
            // subsequent watch refresh must get a new view rather than a TTL hit.
            for analyzer in [IpcAnalyzer::new(), IpcAnalyzer::for_scan()] {
                let observed = analyzer.analyze(supervised.pid()).unwrap();
                assert!(observed.is_supervised);
                assert_eq!(observed.supervisor_name.as_deref(), Some("vscode"));
            }
        }

        #[test]
        fn scan_preserves_namespace_and_process_read_failures() {
            let directory = tempfile::tempdir().unwrap();
            let mut child = SocketChild::new(&directory.path().join("child.sock"));
            let pid = child.pid();
            let scan = IpcAnalyzer::for_scan();
            assert!(!scan.analyze(pid).unwrap().is_supervised);
            let snapshot = scan.scan.as_ref().unwrap();
            let (namespace, handle) = open_network_namespace(pid).unwrap();
            let other_namespace = (namespace.0, namespace.1 ^ 1);
            assert!(matches!(
                snapshot.table_for(pid, other_namespace, handle),
                Err(IpcError::ProcessChanged(changed)) if changed == pid
            ));
            assert_eq!(snapshot.table_reads.load(Ordering::Relaxed), 1);
            assert_eq!(snapshot.tables.lock().unwrap().len(), 1);

            child.0.kill().unwrap();
            child.0.wait().unwrap();
            assert!(matches!(
                scan.analyze(pid),
                Err(IpcError::Identity(StatReadError::Read { pid: failed, .. })) if failed == pid
            ));
            assert!(matches!(
                open_network_namespace(pid),
                Err(IpcError::IoError { pid: failed, .. }) if failed == pid
            ));
            assert_eq!(snapshot.table_reads.load(Ordering::Relaxed), 1);
        }
    }

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
    fn orchestrator_socket_cannot_mask_human_supervision() {
        let analyzer = IpcAnalyzer::new();
        let systemd = "/run/user/1000/systemd/private".to_string();
        let tmux = "/tmp/tmux-1000/default".to_string();
        for sockets in [
            vec![systemd.clone(), tmux.clone()],
            vec![tmux, systemd.clone()],
        ] {
            let result = analyzer.analyze_sockets(&sockets);
            assert_eq!(result.category, Some(SupervisorCategory::Orchestrator));
            assert_eq!(result.supervisor_name.as_deref(), Some("systemd"));
            assert_eq!(result.confidence, 0.60);
            assert!(result.human_supervised, "{result:?}");
            assert_eq!(result.matched_sockets.len(), 2);
            assert_eq!(result.evidence.len(), 2);
        }

        let orchestrator = analyzer.analyze_sockets(&[systemd]);
        assert!(orchestrator.is_supervised);
        assert!(!orchestrator.human_supervised);
        assert!(!analyzer.analyze_sockets(&[]).human_supervised);
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
