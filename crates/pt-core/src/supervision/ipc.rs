//! IPC and socket-based supervision detection.
//!
//! Detects supervision through socket connections to known supervisor IPC paths.

use super::types::{EvidenceType, SupervisionEvidence, SupervisorCategory};
#[cfg(target_os = "linux")]
use crate::collect::network::{
    has_inet_socket_inode, parse_proc_net_unix, read_inet_socket_inodes,
    read_network_process_identity, read_task_network_inventory, revalidate_network_observation,
    NetworkNamespace as ObservedNetworkNamespace, NETWORK_MAX_DESCRIPTORS, NETWORK_MAX_TASKS,
};
#[cfg(target_os = "linux")]
use crate::collect::proc_parsers::read_required_proc_stat;
use crate::collect::proc_parsers::StatReadError;
#[cfg(target_os = "linux")]
use std::collections::{HashMap, HashSet};
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;
#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::sync::{Arc, Mutex, OnceLock};
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
    let process_dir = PathBuf::from(format!("/proc/{pid}"));
    let sockets =
        inspect_socket_inventory(pid, &process_dir, |socket_inodes, namespace, handle| {
            let mut sockets = Vec::new();
            if !socket_inodes.is_empty() {
                let mut table = match scan {
                    Some(snapshot) => snapshot.table_for(pid, namespace, handle)?,
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
                // TCP/UDP descriptors are not in the Unix table. Resolve them
                // through one scan-scoped namespace inventory, rather than
                // reparsing every protocol table for each descriptor. Live
                // action checks intentionally continue to collect fresh proof.
                let mut inet = None;
                for &inode in socket_inodes {
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
                    } else {
                        let known_inet = if let Some(snapshot) = scan {
                            if inet.is_none() {
                                inet = Some(snapshot.inet_table_for(pid, namespace, handle)?);
                            }
                            inet.as_ref().is_some_and(|table| table.contains(&inode))
                        } else {
                            has_inet_socket_inode(pid, inode).map_err(|source| {
                                IpcError::IoError {
                                    pid,
                                    path: format!("/proc/{pid}/net TCP/UDP tables"),
                                    source,
                                }
                            })?
                        };
                        if !known_inet {
                            return Err(IpcError::UnclassifiedSocket { pid, inode });
                        }
                    }
                }
            }
            sockets.sort_unstable();
            sockets.dedup();
            Ok(sockets)
        })?;
    let after = read_required_proc_stat(pid)?;
    if after.starttime != before.starttime {
        return Err(IpcError::ProcessChanged(pid));
    }

    Ok(sockets)
}

/// Resolve sockets only while the complete thread group has two matching
/// inventories. A worker may unshare its file table without changing the leader,
/// so neither an empty leader table nor an unchanged leader birth proves absence.
/// The namespace stays held open across resolution and revalidation. This walks
/// only procfs descriptor links; it never opens or stats their target paths.
#[cfg(target_os = "linux")]
fn inspect_socket_inventory(
    pid: u32,
    process_dir: &Path,
    inspect: impl FnOnce(&HashSet<u64>, NetworkNamespace, &fs::File) -> Result<Vec<String>, IpcError>,
) -> Result<Vec<String>, IpcError> {
    let failure = |source| IpcError::IoError {
        pid,
        path: process_dir.display().to_string(),
        source,
    };
    let identity = read_network_process_identity(process_dir, pid).map_err(failure)?;
    let handle = fs::File::open(process_dir.join("ns/net")).map_err(failure)?;
    let metadata = handle.metadata().map_err(failure)?;
    let namespace = ObservedNetworkNamespace {
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    let inventory = read_task_network_inventory(
        process_dir,
        namespace,
        NETWORK_MAX_TASKS,
        NETWORK_MAX_DESCRIPTORS,
    )
    .map_err(failure)?;
    let paths = inspect(
        &inventory.socket_inodes,
        (namespace.device, namespace.inode),
        &handle,
    )?;
    revalidate_network_observation(process_dir, pid, namespace, identity, &inventory)
        .map_err(failure)?;
    Ok(paths)
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
    tables: Mutex<HashMap<NetworkNamespace, Arc<ScanUnixSocketTable>>>,
    #[cfg(test)]
    table_reads: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    inet_table_reads: std::sync::atomic::AtomicUsize,
}

#[cfg(target_os = "linux")]
type ObservedInetSocketInodes = Result<Arc<HashSet<u64>>, (std::io::ErrorKind, String)>;

#[cfg(target_os = "linux")]
struct ScanUnixSocketTable {
    _namespace: fs::File,
    table: Arc<UnixSocketPaths>,
    inet: OnceLock<ObservedInetSocketInodes>,
}

#[cfg(target_os = "linux")]
impl ScanUnixSocketPaths {
    fn table_for(
        &self,
        pid: u32,
        namespace: NetworkNamespace,
        handle: &fs::File,
    ) -> Result<Arc<UnixSocketPaths>, IpcError> {
        Ok(Arc::clone(&self.entry_for(pid, namespace, handle)?.table))
    }

    fn entry_for(
        &self,
        pid: u32,
        namespace: NetworkNamespace,
        handle: &fs::File,
    ) -> Result<Arc<ScanUnixSocketTable>, IpcError> {
        check_network_namespace(pid, namespace)?;
        let mut tables = self
            .tables
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(entry) = tables.get(&namespace) {
            return Ok(Arc::clone(entry));
        }
        #[cfg(test)]
        self.table_reads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let table = read_unix_socket_paths(pid)?;
        check_network_namespace(pid, namespace)?;
        let namespace_handle = handle.try_clone().map_err(|source| IpcError::IoError {
            pid,
            path: format!("/proc/{pid}/ns/net"),
            source,
        })?;
        let entry = Arc::new(ScanUnixSocketTable {
            _namespace: namespace_handle,
            table,
            inet: OnceLock::new(),
        });
        tables.insert(namespace, Arc::clone(&entry));
        Ok(entry)
    }

    fn inet_table_for(
        &self,
        pid: u32,
        namespace: NetworkNamespace,
        handle: &fs::File,
    ) -> Result<Arc<HashSet<u64>>, IpcError> {
        let entry = self.entry_for(pid, namespace, handle)?;
        let observed = entry.inet.get_or_init(|| {
            #[cfg(test)]
            self.inet_table_reads
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            // Cache failures too: one malformed namespace must not trigger the
            // same expensive parse for every candidate. Namespace changes poison
            // this view instead of saving tables under the wrong namespace key.
            read_inet_socket_inodes(pid)
                .and_then(|table| {
                    check_network_namespace(pid, namespace)
                        .map_err(|error| std::io::Error::other(error.to_string()))?;
                    Ok(Arc::new(table))
                })
                .map_err(|error| (error.kind(), error.to_string()))
        });
        check_network_namespace(pid, namespace)?;
        match observed {
            Ok(table) => Ok(Arc::clone(table)),
            Err((kind, reason)) => Err(IpcError::IoError {
                pid,
                path: format!("/proc/{pid}/net TCP/UDP tables"),
                source: std::io::Error::new(*kind, reason.clone()),
            }),
        }
    }
}

#[cfg(all(target_os = "linux", test))]
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

    /// Reuse strict socket views per network namespace during a read-only
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
    mod inventory_tests {
        use super::*;

        fn write_stat(path: &Path, pid: u32, birth: u64) {
            fs::write(
                path,
                format!(
                    "{pid} (ipc-fixture) S 1 100 100 0 0 0 0 0 0 0 0 0 0 0 20 0 1 0 {birth} 4096 1\n"
                ),
            )
            .unwrap();
        }

        fn add_task(process: &Path, tid: u32, sockets: &[u64]) -> PathBuf {
            let task = process.join("task").join(tid.to_string());
            fs::create_dir_all(task.join("fd")).unwrap();
            fs::create_dir_all(task.join("ns")).unwrap();
            fs::hard_link(process.join("ns/net"), task.join("ns/net")).unwrap();
            write_stat(&task.join("stat"), tid, 12345);
            for (index, inode) in sockets.iter().enumerate() {
                std::os::unix::fs::symlink(
                    format!("socket:[{inode}]"),
                    task.join("fd").join(index.to_string()),
                )
                .unwrap();
            }
            task
        }

        fn fixture_process(root: &Path) -> PathBuf {
            let process = root.join("100");
            fs::create_dir_all(process.join("ns")).unwrap();
            fs::write(process.join("ns/net"), "held namespace").unwrap();
            write_stat(&process.join("stat"), 100, 12345);
            add_task(&process, 100, &[]);
            std::os::unix::fs::symlink("task/100/fd", process.join("fd")).unwrap();
            process
        }

        #[test]
        fn complete_inventory_includes_private_worker_sockets_once() {
            let root = tempfile::tempdir().unwrap();
            let process = fixture_process(root.path());
            let worker = add_task(&process, 101, &[41, 42]);
            add_task(&process, 102, &[42]);
            std::os::unix::fs::symlink("/tmp/vscode-ordinary-file", worker.join("fd/2")).unwrap();
            assert_eq!(fs::read_dir(process.join("fd")).unwrap().count(), 0);

            let paths = inspect_socket_inventory(100, &process, |inodes, namespace, handle| {
                assert_eq!(inodes, &HashSet::from([41, 42]));
                let metadata = handle.metadata().unwrap();
                assert_eq!(namespace, (metadata.dev(), metadata.ino()));
                Ok(vec!["/tmp/vscode-private-worker.sock".to_string()])
            })
            .unwrap();
            let result = IpcAnalyzer::new().analyze_sockets(&paths);
            assert!(result.human_supervised);
            assert_eq!(result.supervisor_name.as_deref(), Some("vscode"));
        }

        #[test]
        fn incomplete_worker_evidence_never_reaches_negative_resolution() {
            for problem in [
                "fd",
                "stat",
                "namespace",
                "different_namespace",
                "malformed_fd",
            ] {
                let root = tempfile::tempdir().unwrap();
                let process = fixture_process(root.path());
                let worker = add_task(&process, 101, &[42]);
                match problem {
                    "fd" => {
                        fs::rename(worker.join("fd"), root.path().join("saved-fd")).unwrap();
                        fs::write(worker.join("fd"), "not a directory").unwrap();
                    }
                    "stat" => {
                        fs::write(worker.join("stat"), "unreadable identity").unwrap();
                    }
                    "namespace" => {
                        fs::rename(worker.join("ns/net"), root.path().join("saved-net")).unwrap();
                    }
                    "different_namespace" => {
                        fs::rename(worker.join("ns/net"), root.path().join("saved-net")).unwrap();
                        fs::write(worker.join("ns/net"), "different namespace").unwrap();
                    }
                    "malformed_fd" => {
                        std::os::unix::fs::symlink("socket:[invalid]", worker.join("fd/1"))
                            .unwrap();
                    }
                    _ => unreachable!(),
                }
                let error = inspect_socket_inventory(100, &process, |_, _, _| {
                    panic!("{problem}: incomplete worker must not resolve as unsupervised")
                })
                .unwrap_err();
                assert!(matches!(error, IpcError::IoError { pid: 100, .. }));
            }
        }

        #[test]
        fn task_socket_and_namespace_changes_refuse_negative_results() {
            for change in [
                "socket",
                "worker_birth",
                "worker_replaced",
                "worker_missing",
                "worker_joined",
                "leader_birth",
                "leader_namespace",
                "worker_namespace",
            ] {
                let root = tempfile::tempdir().unwrap();
                let process = fixture_process(root.path());
                let worker = add_task(&process, 101, &[42]);
                let result = inspect_socket_inventory(100, &process, |inodes, _, _| {
                    assert_eq!(inodes, &HashSet::from([42]));
                    match change {
                        "socket" => {
                            fs::rename(worker.join("fd/0"), root.path().join("saved-fd")).unwrap();
                            std::os::unix::fs::symlink("socket:[43]", worker.join("fd/0")).unwrap();
                        }
                        "worker_birth" => write_stat(&worker.join("stat"), 101, 99999),
                        "worker_replaced" => {
                            fs::rename(&worker, root.path().join("saved-worker")).unwrap();
                            add_task(&process, 101, &[42]);
                        }
                        "worker_missing" => {
                            fs::rename(&worker, root.path().join("saved-worker")).unwrap();
                        }
                        "worker_joined" => {
                            add_task(&process, 102, &[43]);
                        }
                        "leader_birth" => write_stat(&process.join("stat"), 100, 99999),
                        "leader_namespace" | "worker_namespace" => {
                            let subject = if change == "leader_namespace" {
                                &process
                            } else {
                                &worker
                            };
                            fs::rename(subject.join("ns/net"), root.path().join("saved-net"))
                                .unwrap();
                            fs::write(subject.join("ns/net"), "different namespace").unwrap();
                        }
                        _ => unreachable!(),
                    }
                    Ok(Vec::new())
                });
                assert!(result.is_err(), "{change} admitted a negative IPC result");
            }
        }
    }

    #[cfg(target_os = "linux")]
    mod scan_tests {
        use super::*;
        use std::os::fd::{AsRawFd, OwnedFd};
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::net::{UnixDatagram, UnixListener};
        use std::path::Path;
        use std::process::{Child, Command, Stdio};
        use std::sync::atomic::Ordering;

        pub(super) struct SocketChild(Child);

        impl SocketChild {
            pub(super) fn new(path: &Path) -> Self {
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

            pub(super) fn pid(&self) -> u32 {
                self.0.id()
            }
        }

        #[test]
        fn ordinary_files_with_supervisor_names_are_not_socket_evidence() {
            let directory = tempfile::Builder::new()
                .prefix("vscode-")
                .tempdir_in("/tmp")
                .unwrap();
            let file = fs::File::create(directory.path().join("ordinary-file")).unwrap();
            let child = SocketChild::with_socket(file.into(), Stdio::null());
            for analyzer in [IpcAnalyzer::new(), IpcAnalyzer::for_scan()] {
                let result = analyzer.analyze(child.pid()).unwrap();
                assert!(!result.is_supervised);
                assert!(result.matched_sockets.is_empty());
            }
        }

        #[test]
        fn private_worker_socket_child() {
            use std::io::{BufRead, Write};

            let Some(path) = std::env::var_os("PT_IPC_PRIVATE_WORKER_SOCKET") else {
                return;
            };
            let (ready_send, ready_receive) = std::sync::mpsc::channel();
            let (release_send, release_receive) = std::sync::mpsc::channel();
            let worker = std::thread::spawn(move || {
                // SAFETY: only this owned fixture thread receives a separate
                // descriptor table; no existing descriptor is closed or changed.
                assert_eq!(
                    unsafe { libc::unshare(libc::CLONE_FILES) },
                    0,
                    "cannot unshare fixture descriptor table: {}",
                    std::io::Error::last_os_error()
                );
                let socket = UnixListener::bind(path).unwrap();
                // SAFETY: gettid only reads this live thread's kernel identity.
                let tid = unsafe { libc::syscall(libc::SYS_gettid) } as u32;
                ready_send.send((tid, socket.as_raw_fd())).unwrap();
                release_receive
                    .recv_timeout(Duration::from_secs(30))
                    .unwrap();
                drop(socket);
            });
            let (tid, fd) = ready_receive.recv_timeout(Duration::from_secs(10)).unwrap();
            println!("\nPT_IPC_WORKER_READY {tid} {fd}");
            std::io::stdout().flush().unwrap();
            let mut command = String::new();
            std::io::stdin().lock().read_line(&mut command).unwrap();
            release_send.send(()).unwrap();
            worker.join().unwrap();
        }

        #[test]
        fn live_and_scan_detection_find_a_private_worker_supervisor_socket() {
            use std::io::{BufRead, BufReader, Write};

            let directory = tempfile::Builder::new()
                .prefix("vscode-")
                .tempdir_in("/tmp")
                .unwrap();
            let path = directory.path().join("worker.sock");
            let mut child = SocketChild(
                Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "supervision::ipc::tests::scan_tests::private_worker_socket_child",
                        "--nocapture",
                        "--test-threads=1",
                    ])
                    .env("PT_IPC_PRIVATE_WORKER_SOCKET", &path)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::inherit())
                    .spawn()
                    .unwrap(),
            );
            let stdout = child.0.stdout.take().unwrap();
            let (ready_send, ready_receive) = std::sync::mpsc::channel();
            let output = std::thread::spawn(move || {
                for line in BufReader::new(stdout).lines() {
                    let line = line.unwrap();
                    if let Some(ready) = line.strip_prefix("PT_IPC_WORKER_READY ") {
                        let (tid, fd) = ready.split_once(' ').unwrap();
                        ready_send
                            .send((tid.parse::<u32>().unwrap(), fd.parse::<u32>().unwrap()))
                            .unwrap();
                    }
                }
            });
            let (tid, fd) = ready_receive.recv_timeout(Duration::from_secs(10)).unwrap();
            let pid = child.pid();
            assert_ne!(tid, pid);
            let worker_socket = fs::read_link(format!("/proc/{pid}/task/{tid}/fd/{fd}")).unwrap();
            assert!(worker_socket.to_string_lossy().starts_with("socket:["));
            assert_ne!(
                fs::read_link(format!("/proc/{pid}/fd/{fd}")).ok(),
                Some(worker_socket),
                "the fixture must keep its supervisor socket out of the leader table"
            );
            for analyzer in [IpcAnalyzer::new(), IpcAnalyzer::for_scan()] {
                let observed = analyzer.analyze(pid).unwrap();
                assert!(observed.is_supervised);
                assert!(observed.human_supervised);
                assert_eq!(observed.supervisor_name.as_deref(), Some("vscode"));
                assert_eq!(
                    observed.matched_sockets,
                    vec![path.to_str().unwrap().to_string()]
                );
            }
            child.0.stdin.take().unwrap().write_all(b"done\n").unwrap();
            assert!(child.0.wait().unwrap().success());
            output.join().unwrap();
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
        fn scan_reuses_one_inet_inventory_across_candidates_and_descriptors() {
            let children: Vec<_> = (0..12)
                .map(|_| {
                    let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
                    SocketChild::with_socket(tcp.into(), Stdio::from(OwnedFd::from(udp)))
                })
                .collect();
            let scan = IpcAnalyzer::for_scan();
            let live = IpcAnalyzer::new();
            for child in &children {
                for _ in 0..2 {
                    let observed = scan.analyze(child.pid()).unwrap();
                    let current = live.analyze(child.pid()).unwrap();
                    assert!(!observed.is_supervised);
                    assert_eq!(observed.is_supervised, current.is_supervised);
                    assert_eq!(observed.matched_sockets, current.matched_sockets);
                }
            }
            let snapshot = scan.scan.as_ref().unwrap();
            assert_eq!(snapshot.table_reads.load(Ordering::Relaxed), 1);
            assert_eq!(snapshot.inet_table_reads.load(Ordering::Relaxed), 1);
            let tables = snapshot.tables.lock().unwrap();
            assert_eq!(tables.len(), 1);
            assert!(tables
                .values()
                .all(|entry| entry.inet.get().unwrap().is_ok()));
            assert!(live.scan.is_none());
        }

        #[test]
        fn scan_refuses_new_inet_inodes_while_live_and_new_scan_refresh() {
            let original = SocketChild::with_socket(
                std::net::TcpListener::bind("127.0.0.1:0").unwrap().into(),
                Stdio::null(),
            );
            let scan = IpcAnalyzer::for_scan();
            assert!(!scan.analyze(original.pid()).unwrap().is_supervised);

            let new_sockets: [OwnedFd; 2] = [
                std::net::TcpListener::bind("127.0.0.1:0").unwrap().into(),
                std::net::UdpSocket::bind("127.0.0.1:0").unwrap().into(),
            ];
            for socket in new_sockets {
                let child = SocketChild::with_socket(socket, Stdio::null());
                assert!(matches!(
                    scan.analyze(child.pid()),
                    Err(IpcError::UnclassifiedSocket { pid, .. }) if pid == child.pid()
                ));
                for analyzer in [IpcAnalyzer::new(), IpcAnalyzer::for_scan()] {
                    assert!(!analyzer.analyze(child.pid()).unwrap().is_supervised);
                }
            }
            assert_eq!(
                scan.scan
                    .as_ref()
                    .unwrap()
                    .inet_table_reads
                    .load(Ordering::Relaxed),
                1
            );
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
                snapshot.table_for(pid, other_namespace, &handle),
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

    /// A unix socket an owned child holds is found through the shared inode table, and
    /// repeated lookups within the TTL reuse one parse.
    #[cfg(target_os = "linux")]
    #[test]
    fn bound_socket_path_found_through_shared_table() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pt-ipc-test.sock");
        let child = scan_tests::SocketChild::new(&path);
        // The cache may hold a table from before the bind; let it expire.
        std::thread::sleep(UNIX_TABLE_TTL + Duration::from_millis(50));

        let sockets = read_socket_paths(child.pid()).unwrap();
        let wanted = path.to_string_lossy().to_string();
        assert!(sockets.contains(&wanted), "{wanted} not in {sockets:?}");

        let first = unix_socket_paths_by_inode(child.pid(), false).unwrap();
        let second = unix_socket_paths_by_inode(child.pid(), false).unwrap();
        assert!(Arc::ptr_eq(&first, &second), "parsed twice within the TTL");

        // A bind after the warm table must not disappear into cached absence.
        let later = dir.path().join("pt-later.sock");
        let later_child = scan_tests::SocketChild::new(&later);
        assert!(read_socket_paths(later_child.pid())
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
