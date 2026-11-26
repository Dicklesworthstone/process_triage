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
    /// Kernel state used for scoring and planning, with its observed D-state
    /// channel when available. A later leader wait can tighten feasibility for
    /// a nonterminal process. Terminal snapshots retain their existing routing.
    pub fn decision_state<'a>(
        &self,
        activity: Option<&'a ProcessActivity>,
    ) -> (ProcessState, Option<&'a str>) {
        if !matches!(self.state, ProcessState::Zombie | ProcessState::Dead) {
            if let Some(wait) = activity
                .and_then(|sample| sample.leader_wait_for(self))
                .filter(|wait| wait.state.is_disksleep())
            {
                return (wait.state, wait.wchan.as_deref());
            }
        }
        (self.state, None)
    }

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

/// Resident and swapped memory at the end of an activity window.
///
/// These are the kernel's inexpensive status counters, not proportional or
/// uniquely reclaimable memory. Swap excludes shared-memory swap usage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProcessMemoryUsage {
    pub rss_bytes: u64,
    pub rss_anon_bytes: u64,
    pub rss_file_bytes: u64,
    pub rss_shmem_bytes: u64,
    pub swap_bytes: u64,
    pub threads: u32,
}

/// Instantaneous Linux thread-group leader observation. Sleeping here says
/// nothing about what the other threads are doing or how long this wait lasted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LeaderWait {
    pub state: ProcessState,
    pub class: WaitClass,
    pub wchan: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WaitClass {
    Runnable,
    WaitingForChild,
    PipeRead,
    UnixSocketRead,
    Timer,
    EventLoop,
    Uninterruptible,
    Other,
}

impl LeaderWait {
    /// Classify only matching state observations bracketing the channel read.
    /// A kernel 0 can mean a hidden symbol, so it never proves a runnable task.
    pub(crate) fn from_sample(
        before: ProcessState,
        after: ProcessState,
        channel: Option<&str>,
    ) -> Option<Self> {
        if before != after {
            return None;
        }
        let wchan = channel.map(str::trim).filter(|symbol| {
            !symbol.is_empty()
                && *symbol != "0"
                && symbol.len() <= 128
                && symbol
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
        });
        let class = match after {
            ProcessState::Running if wchan.is_none() => WaitClass::Runnable,
            ProcessState::DiskSleep => WaitClass::Uninterruptible,
            ProcessState::Sleeping => match wchan? {
                "do_wait" | "kernel_wait4" | "kernel_waitid" | "__do_wait" => {
                    WaitClass::WaitingForChild
                }
                "pipe_read" | "anon_pipe_read" => WaitClass::PipeRead,
                "unix_stream_read_generic" | "unix_stream_data_wait" => WaitClass::UnixSocketRead,
                "hrtimer_nanosleep" | "do_nanosleep" => WaitClass::Timer,
                "ep_poll" | "do_epoll_wait" | "do_select" | "do_poll" | "do_sys_poll"
                | "poll_schedule_timeout" | "poll_schedule_timeout.constprop.0" => {
                    WaitClass::EventLoop
                }
                _ => WaitClass::Other,
            },
            _ => return None,
        };
        Some(Self {
            state: after,
            class,
            wchan: wchan.map(str::to_owned),
        })
    }
}

/// Pressure diagnostics observed alongside CPU and storage-I/O activity.
///
/// Scheduler and block-I/O delay counters cover the thread-group leader only;
/// they must not be interpreted as the sum of all threads. Unknown or disabled
/// kernel accounting stays null with an explanation instead of looking idle.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct ProcessPressureActivity {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leader_wait: Option<LeaderWait>,
    pub major_faults: Option<u64>,
    pub major_faults_per_second: Option<f64>,
    pub stat_window_seconds: Option<f64>,
    pub leader_run_queue_wait_percent: Option<f64>,
    pub scheduler_window_seconds: Option<f64>,
    pub leader_blkio_delay_percent: Option<f64>,
    pub memory: Option<ProcessMemoryUsage>,
    pub faults_error: Option<String>,
    pub scheduler_error: Option<String>,
    pub blkio_error: Option<String>,
    pub memory_error: Option<String>,
}

impl ProcessPressureActivity {
    pub(crate) fn unavailable(reason: &str) -> Self {
        Self {
            faults_error: Some(reason.to_string()),
            scheduler_error: Some(reason.to_string()),
            blkio_error: Some(reason.to_string()),
            memory_error: Some(reason.to_string()),
            ..Self::default()
        }
    }
}

/// CPU occupancy relative to the capacity observed for this thread group.
///
/// Raw CPU percentages retain the one-core = 100% convention. Inference uses
/// this separately recorded observation so a busy quota-limited process is not
/// mistaken for an idle one. Missing or changing capacity is not zero activity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CpuOccupancy {
    Observed {
        occupancy: f64,
        effective_cores: f64,
        effective_parallelism: f64,
        online_cores: u32,
        affinity_cores: u32,
        quota_cores: Option<f64>,
        threads: u32,
    },
    Unavailable {
        reason: String,
    },
}

/// Recent CPU, storage-I/O and pressure activity for one process incarnation.
///
/// Missing measurements remain null, with a reason; they never mean that the
/// process was idle. CPU percentages use the same one-core = 100% convention as
/// `ps`, so a multithreaded process may exceed 100%.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ProcessActivity {
    pub pid: u32,
    pub start_id: StartId,
    pub uid: u32,
    /// `procfs_window`, or an explicitly identified native-ps fallback.
    pub source: String,
    pub requested_window_ms: u64,
    pub cpu_percent: Option<f64>,
    pub cpu_ticks: Option<u64>,
    pub cpu_window_seconds: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_occupancy: Option<CpuOccupancy>,
    pub io_window_seconds: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub io_read_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub io_write_bytes: Option<u64>,
    pub read_bytes_per_second: Option<f64>,
    pub write_bytes_per_second: Option<f64>,
    /// Whether storage bytes moved during this window, not during the lifetime.
    pub io_active: Option<bool>,
    pub cpu_error: Option<String>,
    pub io_error: Option<String>,
    /// Diagnostic measurements; these do not independently authorize actions.
    #[serde(default)]
    pub pressure: Option<ProcessPressureActivity>,
}

impl ProcessActivity {
    /// Read wait evidence only for its measured incarnation and sampling source.
    pub fn leader_wait_for(&self, process: &ProcessRecord) -> Option<&LeaderWait> {
        if self.source != "procfs_window" || self.requested_window_ms == 0 || !self.matches_record(process) {
            return None;
        }
        let wait = self.pressure.as_ref()?.leader_wait.as_ref()?;
        Some(wait).filter(|wait| {
            LeaderWait::from_sample(wait.state, wait.state, wait.wchan.as_deref()).as_ref() == Some(*wait)
        })
    }

    /// CPU input used by scoring and explain/replay surfaces. A requested Linux
    /// window requires recorded capacity; only the explicit native-ps fallback
    /// retains the legacy one-core fraction on unsupported platforms.
    pub fn cpu_occupancy_fraction(&self) -> Option<f64> {
        match self.source.as_str() {
            "procfs_window" => self.normalized_cpu_occupancy(),
            "ps_lifetime_fallback" => self
                .cpu_percent
                .filter(|percent| percent.is_finite() && *percent >= 0.0)
                .map(|percent| (percent / 100.0).clamp(0.0, 1.0)),
            _ => None,
        }
    }

    /// Validate the recorded denominator before admitting it to inference.
    /// Replay never fills missing capacity from the machine running the replay.
    pub(crate) fn normalized_cpu_occupancy(&self) -> Option<f64> {
        if self.source != "procfs_window"
            || self.requested_window_ms == 0
            || self.cpu_error.is_some()
            || !self.cpu_window_seconds.is_some_and(|seconds| {
                seconds.is_finite()
                    && seconds > 0.0
                    && seconds >= self.requested_window_ms as f64 / 1000.0
            })
        {
            return None;
        }
        let CpuOccupancy::Observed {
            occupancy,
            effective_cores,
            effective_parallelism,
            online_cores,
            affinity_cores,
            quota_cores,
            threads,
        } = self.cpu_occupancy.as_ref()?
        else {
            return None;
        };
        if *online_cores == 0
            || *affinity_cores == 0
            || *threads == 0
            || quota_cores.is_some_and(|cores| !cores.is_finite() || cores <= 0.0)
        {
            return None;
        }
        let capacity = f64::from((*online_cores).min(*affinity_cores))
            .min(quota_cores.unwrap_or(f64::INFINITY));
        let parallelism = capacity.min(f64::from(*threads));
        let percent = self
            .cpu_percent
            .filter(|percent| percent.is_finite() && *percent >= 0.0)?;
        let normalized = (percent / 100.0 / parallelism).clamp(0.0, 1.0);
        (*effective_cores == capacity
            && *effective_parallelism == parallelism
            && occupancy.is_finite()
            && (*occupancy - normalized).abs() <= 1e-12)
            .then_some(normalized)
    }

    pub(crate) fn unavailable(
        process: &ProcessRecord,
        window: Duration,
        reason: impl Into<String>,
    ) -> Self {
        let reason = reason.into();
        Self {
            pid: process.pid.0,
            start_id: process.start_id.clone(),
            uid: process.uid,
            source: if cfg!(target_os = "linux") {
                "procfs_window"
            } else {
                "ps_lifetime_fallback"
            }
            .to_string(),
            requested_window_ms: u64::try_from(window.as_millis()).unwrap_or(u64::MAX),
            cpu_percent: None,
            cpu_ticks: None,
            cpu_window_seconds: None,
            cpu_occupancy: None,
            io_window_seconds: None,
            io_read_bytes: None,
            io_write_bytes: None,
            read_bytes_per_second: None,
            write_bytes_per_second: None,
            io_active: None,
            cpu_error: Some(reason.clone()),
            io_error: Some(reason.clone()),
            pressure: Some(ProcessPressureActivity::unavailable(&reason)),
        }
    }

    pub(crate) fn matches_record(&self, process: &ProcessRecord) -> bool {
        self.pid == process.pid.0 && self.start_id == process.start_id && self.uid == process.uid
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
    fn leader_wait_distinguishes_known_symbols_hidden_channels_and_state_changes() {
        use ProcessState::{DiskSleep, Running, Sleeping};
        for (symbol, class) in [
            ("do_wait", WaitClass::WaitingForChild),
            ("anon_pipe_read", WaitClass::PipeRead),
            ("unix_stream_data_wait", WaitClass::UnixSocketRead),
            ("hrtimer_nanosleep", WaitClass::Timer),
            ("ep_poll", WaitClass::EventLoop),
            ("futex_wait_queue", WaitClass::Other),
        ] {
            let sample = LeaderWait::from_sample(Sleeping, Sleeping, Some(symbol)).unwrap();
            assert_eq!(sample.class, class);
            assert_eq!(sample.wchan.as_deref(), Some(symbol));
        }
        for channel in [None, Some("0"), Some(""), Some("invalid symbol")] {
            assert!(LeaderWait::from_sample(Sleeping, Sleeping, channel).is_none());
            let blocked = LeaderWait::from_sample(DiskSleep, DiskSleep, channel).unwrap();
            assert_eq!(blocked.class, WaitClass::Uninterruptible);
            assert!(blocked.wchan.is_none());
        }
        assert!(LeaderWait::from_sample(Sleeping, DiskSleep, Some("io_schedule")).is_none());
        assert!(LeaderWait::from_sample(Running, Running, Some("pipe_read")).is_none());
        assert_eq!(LeaderWait::from_sample(Running, Running, None).unwrap().class, WaitClass::Runnable);
    }

    #[test]
    fn wait_evidence_is_bound_to_the_incarnation_and_sampling_source() {
        let process = record(120, 1, Some(1));
        let mut sample = ProcessActivity::unavailable(&process, Duration::from_secs(1), "fixture");
        sample.source = "procfs_window".into();
        sample.pressure.as_mut().unwrap().leader_wait =
            LeaderWait::from_sample(ProcessState::DiskSleep, ProcessState::DiskSleep, Some("io_schedule"));
        assert!(sample.leader_wait_for(&process).is_some());
        let mut reused = process.clone();
        reused.start_id = StartId::from_linux("b", 2, 120);
        assert!(sample.leader_wait_for(&reused).is_none());
        sample.source = "ps_lifetime_fallback".into();
        assert!(sample.leader_wait_for(&process).is_none());
        let legacy: ProcessPressureActivity = serde_json::from_str("{}").unwrap();
        assert!(legacy.leader_wait.is_none());
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
