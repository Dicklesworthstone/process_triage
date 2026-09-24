//! Common types for process scanning and collection.
//!
//! These types represent the structured output of scan operations,
//! designed for serialization to telemetry and feeding into inference.

use pt_common::{ProcessId, StartId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use super::container::ContainerInfo;

/// Process state from ps output.
///
/// Maps to standard Unix process states:
/// - R: Running or runnable
/// - S: Interruptible sleep (waiting for event)
/// - D: Uninterruptible sleep (usually I/O)
/// - Z: Zombie (terminated but not reaped)
/// - T: Stopped (by job control or trace)
/// - I: Idle (kernel thread, Linux)
/// - X: Dead (should never be seen)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ProcessState {
    Running,
    Sleeping,
    DiskSleep,
    Zombie,
    Stopped,
    Idle,
    Dead,
    Unknown,
}

impl ProcessState {
    /// Parse process state from single character.
    pub fn from_char(c: char) -> Self {
        match c {
            'R' => ProcessState::Running,
            'S' => ProcessState::Sleeping,
            'D' => ProcessState::DiskSleep,
            'Z' => ProcessState::Zombie,
            'T' | 't' => ProcessState::Stopped,
            'I' => ProcessState::Idle,
            'X' | 'x' => ProcessState::Dead,
            _ => ProcessState::Unknown,
        }
    }

    /// Whether this state indicates an active process.
    pub fn is_active(&self) -> bool {
        matches!(
            self,
            ProcessState::Running | ProcessState::Sleeping | ProcessState::DiskSleep
        )
    }

    /// Whether this state indicates a zombie process.
    pub fn is_zombie(&self) -> bool {
        matches!(self, ProcessState::Zombie)
    }

    /// Whether this state indicates uninterruptible sleep (D-state).
    ///
    /// D-state processes are typically waiting on kernel I/O and may not
    /// respond to signals including SIGKILL. Special handling is required.
    pub fn is_disksleep(&self) -> bool {
        matches!(self, ProcessState::DiskSleep)
    }

    /// Whether this state requires special handling for kill actions.
    ///
    /// Both zombie and D-state processes cannot be reliably killed:
    /// - Zombies are already dead, only the parent can reap them
    /// - D-state processes may ignore SIGKILL while in kernel I/O wait
    pub fn is_unkillable(&self) -> bool {
        matches!(self, ProcessState::Zombie | ProcessState::DiskSleep)
    }
}

impl std::fmt::Display for ProcessState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ProcessState::Running => "R",
            ProcessState::Sleeping => "S",
            ProcessState::DiskSleep => "D",
            ProcessState::Zombie => "Z",
            ProcessState::Stopped => "T",
            ProcessState::Idle => "I",
            ProcessState::Dead => "X",
            ProcessState::Unknown => "?",
        };
        write!(f, "{}", s)
    }
}

/// A single process record from a scan.
///
/// Contains all fields collected during a quick or deep scan.
/// Optional fields may be unavailable on some platforms or permission levels.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ProcessRecord {
    // === Core identity ===
    /// Process ID.
    pub pid: ProcessId,

    /// Parent process ID.
    pub ppid: ProcessId,

    /// User ID.
    pub uid: u32,

    /// Username (resolved from UID).
    pub user: String,

    /// Process group ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pgid: Option<u32>,

    /// Session ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<u32>,

    // === Identity for TOCTOU protection ===
    /// Start ID for PID reuse detection.
    pub start_id: StartId,

    // === Command info ===
    /// Command name (basename only).
    pub comm: String,

    /// Full command line.
    pub cmd: String,

    // === State and resources ===
    /// Current process state.
    pub state: ProcessState,

    /// CPU usage percentage (instantaneous).
    pub cpu_percent: f64,

    /// Resident set size in bytes.
    pub rss_bytes: u64,

    /// Virtual memory size in bytes.
    pub vsz_bytes: u64,

    // === Terminal ===
    /// Controlling terminal (None if no TTY).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tty: Option<String>,

    // === Timing ===
    /// Process start time (Unix timestamp).
    pub start_time_unix: i64,

    /// Elapsed time since process start.
    pub elapsed: Duration,

    // === Provenance ===
    /// Source of this record (quick_scan, deep_scan, etc.).
    pub source: String,

    // === Container ===
    /// Container information (if running in a container).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_info: Option<ContainerInfo>,
}

impl ProcessRecord {
    /// Check if process has a controlling terminal.
    pub fn has_tty(&self) -> bool {
        self.tty.is_some()
    }

    /// Check if process is orphaned: reparented to init/launchd (PID 1) after its
    /// original parent died.
    ///
    /// `ppid == 1` alone is wrong: every daemon and (on macOS) every GUI app is a
    /// direct child of init/launchd. Those are started as their own session leader
    /// (`setsid`, so `sid == pid`); a genuinely orphaned process keeps the session of
    /// the shell/job that spawned it (`sid != pid`). On the 2026-09-24 fleet scan the
    /// old definition rated Chrome, Spotify, Zed and login shells "abandoned".
    ///
    /// macOS `ps` reports `sess` as 0 for every process, so there the process-group
    /// leadership (`pgid == pid`, which launchd also establishes) is used instead.
    pub fn is_orphan(&self) -> bool {
        if self.ppid.0 != 1 {
            return false;
        }
        let own_leader = match (self.sid, self.pgid) {
            (Some(sid), _) if sid != 0 => sid == self.pid.0,
            (_, Some(pgid)) if pgid != 0 => pgid == self.pid.0,
            _ => false,
        };
        !own_leader
    }

    /// Get elapsed time in seconds.
    pub fn elapsed_seconds(&self) -> u64 {
        self.elapsed.as_secs()
    }
}

/// Result of a scan operation.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ScanResult {
    /// Collected process records.
    pub processes: Vec<ProcessRecord>,

    /// Scan metadata.
    pub metadata: ScanMetadata,
}

/// Metadata about a scan operation.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ScanMetadata {
    /// Scan type (quick, deep).
    pub scan_type: String,

    /// Platform identifier.
    pub platform: String,

    /// Boot ID if available (for start_id validation).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boot_id: Option<String>,

    /// Timestamp when scan started (ISO-8601).
    pub started_at: String,

    /// Duration of the scan.
    pub duration_ms: u64,

    /// Number of processes collected.
    pub process_count: usize,

    /// Any warnings encountered during scan.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(pid: u32, ppid: u32, sid: Option<u32>) -> ProcessRecord {
        ProcessRecord {
            pid: ProcessId(pid),
            ppid: ProcessId(ppid),
            uid: 501,
            user: "u".to_string(),
            pgid: sid,
            sid,
            start_id: StartId::from_linux("b", 1, pid),
            comm: "x".to_string(),
            cmd: "x".to_string(),
            state: ProcessState::Sleeping,
            cpu_percent: 0.0,
            rss_bytes: 0,
            vsz_bytes: 0,
            tty: None,
            start_time_unix: 0,
            elapsed: std::time::Duration::from_secs(7200),
            source: "test".to_string(),
            container_info: None,
        }
    }

    #[test]
    fn orphan_requires_lost_session_not_just_ppid_1() {
        // launchd/init-started app or daemon: its own session leader -> not orphaned.
        assert!(!record(1920, 1, Some(1920)).is_orphan());
        // Reparented after its shell died: still in the old session -> orphaned.
        assert!(record(4058817, 1, Some(4000000)).is_orphan());
        // Unknown session: fall back to the parent check.
        assert!(record(77, 1, None).is_orphan());
        assert!(!record(77, 500, Some(10)).is_orphan());
        // macOS: sess is always 0, use process-group leadership.
        let mut app = record(2548, 1, Some(0));
        app.pgid = Some(2548);
        assert!(!app.is_orphan());
        let mut job = record(3100, 1, Some(0));
        job.pgid = Some(3000);
        assert!(job.is_orphan());
    }

    #[test]
    fn test_process_state_from_char() {
        assert_eq!(ProcessState::from_char('R'), ProcessState::Running);
        assert_eq!(ProcessState::from_char('S'), ProcessState::Sleeping);
        assert_eq!(ProcessState::from_char('D'), ProcessState::DiskSleep);
        assert_eq!(ProcessState::from_char('Z'), ProcessState::Zombie);
        assert_eq!(ProcessState::from_char('T'), ProcessState::Stopped);
        assert_eq!(ProcessState::from_char('I'), ProcessState::Idle);
        assert_eq!(ProcessState::from_char('?'), ProcessState::Unknown);
    }

    #[test]
    fn test_process_state_display() {
        assert_eq!(ProcessState::Running.to_string(), "R");
        assert_eq!(ProcessState::Zombie.to_string(), "Z");
    }

    #[test]
    fn test_process_state_is_active() {
        assert!(ProcessState::Running.is_active());
        assert!(ProcessState::Sleeping.is_active());
        assert!(!ProcessState::Zombie.is_active());
        assert!(!ProcessState::Stopped.is_active());
    }

    #[test]
    fn test_process_state_is_zombie() {
        assert!(ProcessState::Zombie.is_zombie());
        assert!(!ProcessState::Running.is_zombie());
    }

    #[test]
    fn test_process_state_is_disksleep() {
        assert!(ProcessState::DiskSleep.is_disksleep());
        assert!(!ProcessState::Running.is_disksleep());
        assert!(!ProcessState::Zombie.is_disksleep());
        assert!(!ProcessState::Sleeping.is_disksleep());
    }

    #[test]
    fn test_process_state_is_unkillable() {
        // Both zombie and D-state are unkillable
        assert!(ProcessState::Zombie.is_unkillable());
        assert!(ProcessState::DiskSleep.is_unkillable());
        // Other states can be killed
        assert!(!ProcessState::Running.is_unkillable());
        assert!(!ProcessState::Sleeping.is_unkillable());
        assert!(!ProcessState::Stopped.is_unkillable());
    }
}
