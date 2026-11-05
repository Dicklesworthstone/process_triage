//! Renice (priority adjustment) action execution.
//!
//! Implements process priority adjustment using setpriority(2) with:
//! - TOCTOU safety via identity revalidation
//! - Linux task enumeration and per-thread identity/priority verification
//! - Graceful handling of permission denied
//! - Reversal metadata capture for undo operations

use super::executor::{ActionError, ActionRunner};
use crate::decision::Action;
use crate::plan::PlanAction;
use serde::{Deserialize, Serialize};
#[cfg(all(unix, not(target_os = "linux")))]
use tracing::warn;
use tracing::{debug, info};

/// Default nice value to apply (positive = lower priority).
pub const DEFAULT_NICE_VALUE: i32 = 10;

/// Maximum nice value allowed (19 = lowest priority).
pub const MAX_NICE_VALUE: i32 = 19;

/// Renice action runner configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReniceConfig {
    /// Nice value to set (0-19 for unprivileged, -20 to 19 for root).
    pub nice_value: i32,
    /// Whether to clamp nice values to valid range instead of erroring.
    pub clamp_to_range: bool,
    /// Whether to record previous nice value for reversal.
    pub capture_reversal: bool,
}

impl Default for ReniceConfig {
    fn default() -> Self {
        Self {
            nice_value: DEFAULT_NICE_VALUE,
            clamp_to_range: true,
            capture_reversal: true,
        }
    }
}

/// Captured state for reversal of renice action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReniceReversalMetadata {
    /// PID of the reniced process.
    pub pid: u32,

    /// Previous nice value before renice was applied.
    pub previous_nice: i32,

    /// New nice value that was applied.
    pub applied_nice: i32,

    /// Timestamp when renice was applied.
    pub applied_at: String,

    /// Process incarnation captured with the thread priorities on Linux.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<pt_common::ProcessIdentity>,

    /// Exact Linux thread priorities. A leader's nice value is not a process-wide snapshot.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub threads: Vec<ReniceThreadReversal>,
}

/// Identity-bound prior state of one Linux thread, for exact restoration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReniceThreadReversal {
    pub tid: u32,
    pub start_ticks: u64,
    pub uid: u32,
    pub previous_nice: i32,
    pub applied_nice: i32,
}

/// Result of a renice operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReniceResult {
    /// Whether the renice was successful.
    pub success: bool,

    /// New effective nice value.
    pub effective_nice: Option<i32>,

    /// Reversal metadata if captured.
    pub reversal: Option<ReniceReversalMetadata>,

    /// Error message if failed.
    pub error: Option<String>,
}

/// Renice action runner using setpriority(2).
#[derive(Debug)]
pub struct ReniceActionRunner {
    config: ReniceConfig,
}

impl ReniceActionRunner {
    pub fn new(config: ReniceConfig) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(ReniceConfig::default())
    }

    /// Get the nice value to use, clamped if configured.
    fn effective_nice_value(&self) -> i32 {
        if self.config.clamp_to_range {
            self.config.nice_value.clamp(-20, MAX_NICE_VALUE)
        } else {
            self.config.nice_value
        }
    }

    /// Set process priority using setpriority(2).
    #[cfg(unix)]
    fn set_priority(&self, pid: u32, nice_value: i32) -> Result<(), ActionError> {
        // A zero ID means the caller, not an absent/invalid target.
        if pid == 0 || pid > i32::MAX as u32 {
            return Err(ActionError::Failed(
                "invalid priority target PID/TID".into(),
            ));
        }
        if !(-20..=MAX_NICE_VALUE).contains(&nice_value) {
            return Err(ActionError::Failed("invalid priority value".into()));
        }
        super::signal::ensure_action_pid_namespace()?;
        // PRIO_PROCESS = 0
        let result =
            unsafe { libc::setpriority(libc::PRIO_PROCESS, pid as libc::id_t, nice_value) };

        if result == 0 {
            return Ok(());
        }

        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::ESRCH) => Err(ActionError::ProcessNotFound),
            Some(libc::EPERM) => Err(ActionError::PermissionDenied),
            Some(libc::EINVAL) => Err(ActionError::Failed("invalid priority value".to_string())),
            Some(libc::EACCES) => Err(ActionError::PermissionDenied),
            _ => Err(ActionError::Failed(err.to_string())),
        }
    }

    /// Get current nice value from /proc/[pid]/stat.
    #[cfg(all(target_os = "linux", test))]
    fn get_nice_value(&self, pid: u32) -> Option<i32> {
        let stat_path = format!("/proc/{pid}/stat");
        let content_bytes = std::fs::read(stat_path).ok()?;
        let content = String::from_utf8_lossy(&content_bytes);

        // Format: pid (comm) state ...
        // Field 19 (0-indexed from start, or field 17 after comm+state) is nice
        let comm_end = content.rfind(')')?;
        let after_comm = content.get(comm_end + 2..)?;
        let fields: Vec<&str> = after_comm.split_whitespace().collect();

        // Fields after (comm) state:
        // 0=state, 1=ppid, 2=pgrp, 3=session, 4=tty_nr, 5=tpgid,
        // 6=flags, 7=minflt, 8=cminflt, 9=majflt, 10=cmajflt,
        // 11=utime, 12=stime, 13=cutime, 14=cstime, 15=priority, 16=nice
        // So nice is at index 16 after the state field
        fields.get(16)?.parse::<i32>().ok()
    }

    /// Current nice value via getpriority(2).
    #[cfg(target_os = "macos")]
    fn get_nice_value(&self, pid: u32) -> Option<i32> {
        // getpriority can legitimately return -1, so errors are told apart by errno.
        // SAFETY: plain libc calls on a pid; errno is thread-local.
        unsafe {
            *libc::__error() = 0;
            let value = libc::getpriority(libc::PRIO_PROCESS, pid as libc::id_t);
            if value == -1 && *libc::__error() != 0 {
                None
            } else {
                Some(value)
            }
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn get_nice_value(&self, _pid: u32) -> Option<i32> {
        None
    }

    /// Capture a stable, identity-bound snapshot of every Linux thread.
    /// Restoration refuses new or reused threads for which no prior state was captured.
    #[cfg(target_os = "linux")]
    pub fn capture_reversal_metadata(&self, pid: u32) -> Option<ReniceReversalMetadata> {
        linux_threads::capture(self, pid).ok()
    }

    /// Capture the process-level priority on platforms with process-level nice semantics.
    #[cfg(all(unix, not(target_os = "linux")))]
    pub fn capture_reversal_metadata(&self, pid: u32) -> Option<ReniceReversalMetadata> {
        let previous_nice = self.get_nice_value(pid)?;
        let applied_nice = self.effective_nice_value();

        debug!(
            pid,
            previous_nice, applied_nice, "capturing renice reversal metadata"
        );

        Some(ReniceReversalMetadata {
            pid,
            previous_nice,
            applied_nice,
            applied_at: chrono::Utc::now().to_rfc3339(),
            identity: None,
            threads: Vec::new(),
        })
    }

    #[cfg(not(unix))]
    pub fn capture_reversal_metadata(&self, _pid: u32) -> Option<ReniceReversalMetadata> {
        None
    }

    /// Restore exact Linux thread priorities, revalidating each captured incarnation.
    /// Raising priority can require CAP_SYS_NICE or a suitable RLIMIT_NICE.
    #[cfg(target_os = "linux")]
    pub fn restore_from_metadata(
        &self,
        metadata: &ReniceReversalMetadata,
    ) -> Result<(), ActionError> {
        linux_threads::restore(&linux_threads::LiveTasks(self), metadata)
    }

    /// Restore the process-level priority on other Unix platforms.
    #[cfg(all(unix, not(target_os = "linux")))]
    pub fn restore_from_metadata(
        &self,
        metadata: &ReniceReversalMetadata,
    ) -> Result<(), ActionError> {
        info!(
            pid = metadata.pid,
            previous_nice = metadata.previous_nice,
            "restoring nice value from reversal metadata"
        );

        self.set_priority(metadata.pid, metadata.previous_nice)?;

        // Verify restoration
        if let Some(current) = self.get_nice_value(metadata.pid) {
            if current != metadata.previous_nice {
                warn!(
                    pid = metadata.pid,
                    expected = metadata.previous_nice,
                    actual = current,
                    "nice value restoration mismatch"
                );
                return Err(ActionError::Failed(format!(
                    "nice value restoration mismatch: expected {}, got {}",
                    metadata.previous_nice, current
                )));
            }
        }

        info!(
            pid = metadata.pid,
            nice = metadata.previous_nice,
            "successfully restored nice value"
        );
        Ok(())
    }

    #[cfg(not(unix))]
    pub fn restore_from_metadata(
        &self,
        _metadata: &ReniceReversalMetadata,
    ) -> Result<(), ActionError> {
        Err(ActionError::Failed(
            "renice restoration not supported on this platform".to_string(),
        ))
    }

    /// Linux nice values belong to threads, including threads other than the leader.
    #[cfg(target_os = "linux")]
    fn execute_renice(&self, action: &PlanAction) -> Result<(), ActionError> {
        linux_threads::apply(
            &linux_threads::LiveTasks(self),
            &action.target,
            self.effective_nice_value(),
        )
    }

    /// Execute a process-level priority change on other Unix platforms.
    #[cfg(all(unix, not(target_os = "linux")))]
    fn execute_renice(&self, action: &PlanAction) -> Result<(), ActionError> {
        let pid = action.target.pid.0;
        let nice_value = self.effective_nice_value();

        debug!(pid, nice_value, "executing renice action");

        let previous = self.get_nice_value(pid);
        // Capture previous nice value for logging (reversal metadata can be captured separately)
        if self.config.capture_reversal {
            if let Some(previous) = previous {
                debug!(
                    pid,
                    previous_nice = previous,
                    new_nice = nice_value,
                    "renice: capturing prior state"
                );
            }
        }

        // Renice only ever LOWERS priority. A process already at or below the target
        // priority (nice >= target) is left alone: setting the target would raise its
        // priority, which is not what this action means and fails with EACCES for
        // unprivileged users (observed on a host whose sessions run at nice -4 while
        // pt ran under `nice`).
        if previous.is_some_and(|p| p >= nice_value) {
            info!(pid, previous_nice = ?previous, nice_value, "renice: already at or below target priority");
            return Ok(());
        }

        self.set_priority(pid, nice_value)?;

        info!(pid, nice_value, "renice action applied successfully");
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn verify_renice(&self, action: &PlanAction) -> Result<(), ActionError> {
        linux_threads::verify(
            &linux_threads::LiveTasks(self),
            &action.target,
            self.effective_nice_value(),
        )
    }

    /// Verify a process-level priority change on other Unix platforms.
    #[cfg(all(unix, not(target_os = "linux")))]
    fn verify_renice(&self, action: &PlanAction) -> Result<(), ActionError> {
        let pid = action.target.pid.0;
        let expected = self.effective_nice_value();

        // Give it a moment for the change to take effect
        std::thread::sleep(std::time::Duration::from_millis(10));

        Self::verify_observed_priority(self.get_nice_value(pid), expected)
    }

    #[cfg(all(unix, any(not(target_os = "linux"), test)))]
    fn verify_observed_priority(actual: Option<i32>, expected: i32) -> Result<(), ActionError> {
        match actual {
            // At or below the target priority (never raised by execute_renice).
            Some(actual) if actual >= expected => Ok(()),
            Some(actual) => Err(ActionError::Failed(format!(
                "nice value mismatch: expected {expected}, got {actual}"
            ))),
            None => Err(ActionError::Failed(
                "unable to observe process priority; renice is unverified".to_string(),
            )),
        }
    }
}

#[cfg(target_os = "linux")]
mod linux_threads {
    use super::*;
    use crate::action::executor::IdentityProvider;
    use pt_common::{ProcessIdentity, StartId};

    const MAX_PASSES: usize = 4;
    const MAX_THREADS: usize = 65_536;

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(super) struct TaskPriority {
        pub tid: u32,
        pub start_ticks: u64,
        pub uid: u32,
        pub nice: i32,
    }

    impl TaskPriority {
        fn same_task(&self, other: &Self) -> bool {
            self.tid == other.tid && self.start_ticks == other.start_ticks && self.uid == other.uid
        }
    }

    // Keep observation and mutation separable so disappearance, reuse and partial
    // failures can be exercised without signaling unrelated host processes.
    pub(super) trait TaskOps {
        fn revalidate(&self, target: &ProcessIdentity) -> Result<(), ActionError>;
        fn tids(&self, pid: u32) -> Result<Vec<u32>, ActionError>;
        fn read(&self, pid: u32, tid: u32) -> Result<Option<TaskPriority>, ActionError>;
        fn set(&self, tid: u32, nice: i32) -> Result<(), ActionError>;
    }

    pub(super) struct LiveTasks<'a>(pub &'a ReniceActionRunner);

    impl TaskOps for LiveTasks<'_> {
        fn revalidate(&self, target: &ProcessIdentity) -> Result<(), ActionError> {
            if target.pid.0 == 0 || !target.can_safely_revalidate() {
                return Err(ActionError::IdentityMismatch);
            }
            if super::super::signal::LiveIdentityProvider::new().revalidate(target)? {
                Ok(())
            } else {
                Err(ActionError::IdentityMismatch)
            }
        }

        fn tids(&self, pid: u32) -> Result<Vec<u32>, ActionError> {
            let entries = std::fs::read_dir(format!("/proc/{pid}/task")).map_err(|error| {
                ActionError::Failed(format!("cannot enumerate threads of {pid}: {error}"))
            })?;
            let mut tids = Vec::new();
            for entry in entries {
                let entry = entry.map_err(|error| {
                    ActionError::Failed(format!("incomplete thread enumeration for {pid}: {error}"))
                })?;
                let tid = entry
                    .file_name()
                    .to_str()
                    .and_then(|name| name.parse::<u32>().ok())
                    .filter(|tid| *tid > 0 && *tid <= i32::MAX as u32)
                    .ok_or_else(|| {
                        ActionError::Failed(format!("invalid thread entry for {pid}"))
                    })?;
                tids.push(tid);
                if tids.len() > MAX_THREADS {
                    return Err(ActionError::Failed(
                        "thread enumeration exceeds the renice safety bound".into(),
                    ));
                }
            }
            tids.sort_unstable();
            Ok(tids)
        }

        fn read(&self, pid: u32, tid: u32) -> Result<Option<TaskPriority>, ActionError> {
            let read = |name: &str| -> Result<Option<Vec<u8>>, ActionError> {
                let path = format!("/proc/{pid}/task/{tid}/{name}");
                match std::fs::read(&path) {
                    Ok(bytes) => Ok(Some(bytes)),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                    Err(error) => Err(ActionError::Failed(format!(
                        "cannot read thread evidence {path}: {error}"
                    ))),
                }
            };
            let Some(status) = read("status")? else {
                return Ok(None);
            };
            let Some(stat) = read("stat")? else {
                return Ok(None);
            };
            // comm can contain non-UTF-8 bytes and parentheses. Only numeric
            // fields outside comm participate in priority/identity checks.
            parse_task(
                pid,
                tid,
                &String::from_utf8_lossy(&stat),
                &String::from_utf8_lossy(&status),
            )
            .map(Some)
        }

        fn set(&self, tid: u32, nice: i32) -> Result<(), ActionError> {
            self.0.set_priority(tid, nice)
        }
    }

    fn parse_task(
        pid: u32,
        tid: u32,
        stat: &str,
        status: &str,
    ) -> Result<TaskPriority, ActionError> {
        let invalid = || {
            ActionError::Failed(format!(
                "incomplete or invalid identity/priority evidence for thread {tid}"
            ))
        };
        let open = stat.find('(').ok_or_else(invalid)?;
        let close = stat
            .rfind(')')
            .filter(|close| *close > open)
            .ok_or_else(invalid)?;
        if stat[..open].trim().parse::<u32>().ok() != Some(tid) {
            return Err(ActionError::IdentityMismatch);
        }
        let fields: Vec<_> = stat[close + 1..].split_whitespace().collect();
        let nice = fields
            .get(16)
            .and_then(|value| value.parse::<i32>().ok())
            .filter(|nice| (-20..=MAX_NICE_VALUE).contains(nice))
            .ok_or_else(invalid)?;
        let start_ticks = fields
            .get(19)
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(invalid)?;
        let status_id = |key: &str| -> Result<u32, ActionError> {
            let mut matches = status.lines().filter_map(|line| line.strip_prefix(key));
            let id = matches
                .next()
                .and_then(|line| line.split_whitespace().next())
                .and_then(|value| value.parse().ok())
                .ok_or_else(invalid)?;
            if matches.next().is_some() {
                return Err(invalid());
            }
            Ok(id)
        };
        if status_id("Tgid:")? != pid || status_id("Pid:")? != tid {
            return Err(ActionError::IdentityMismatch);
        }
        Ok(TaskPriority {
            tid,
            start_ticks,
            uid: status_id("Uid:")?,
            nice,
        })
    }

    struct Snapshot {
        tasks: Vec<TaskPriority>,
        complete: bool,
    }

    fn snapshot(ops: &impl TaskOps, target: &ProcessIdentity) -> Result<Snapshot, ActionError> {
        ops.revalidate(target)?;
        let tids = ops.tids(target.pid.0)?;
        if tids.is_empty() || tids.len() > MAX_THREADS {
            return Err(ActionError::Failed(
                "no complete bounded thread census is available".into(),
            ));
        }
        let mut tasks = Vec::with_capacity(tids.len());
        for tid in &tids {
            if let Some(task) = ops.read(target.pid.0, *tid)? {
                if task.tid != *tid || task.uid != target.uid {
                    return Err(ActionError::IdentityMismatch);
                }
                tasks.push(task);
            }
        }
        ops.revalidate(target)?;
        let complete = tasks.len() == tids.len() && ops.tids(target.pid.0)? == tids;
        Ok(Snapshot { tasks, complete })
    }

    fn same_tasks(left: &[TaskPriority], right: &[TaskPriority]) -> bool {
        left.len() == right.len() && left.iter().zip(right).all(|(a, b)| a.same_task(b))
    }

    fn partial_error(operation: &str, writes: &[u32], error: ActionError) -> ActionError {
        if writes.is_empty() {
            return error;
        }
        let tids: Vec<_> = writes.iter().take(8).map(u32::to_string).collect();
        ActionError::Failed(format!(
            "{operation} incomplete: {error}; {} thread priority write(s) already succeeded (TIDs {}{}); changes were not rolled back",
            writes.len(), tids.join(", "), if writes.len() > 8 { ", ..." } else { "" }
        ))
    }

    pub(super) fn apply(
        ops: &impl TaskOps,
        target: &ProcessIdentity,
        nice: i32,
    ) -> Result<(), ActionError> {
        let mut writes = Vec::new();
        let result = (|| {
            if !(-20..=MAX_NICE_VALUE).contains(&nice) {
                return Err(ActionError::Failed("invalid priority value".into()));
            }
            for _ in 0..MAX_PASSES {
                let before = snapshot(ops, target)?;
                for task in &before.tasks {
                    ops.revalidate(target)?;
                    let Some(current) = ops.read(target.pid.0, task.tid)? else {
                        continue;
                    };
                    if !task.same_task(&current) {
                        return Err(ActionError::IdentityMismatch);
                    }
                    // Never raise a thread that already has a lower priority,
                    // even when another thread in this process needs renicing.
                    if current.nice >= nice {
                        continue;
                    }
                    // Linux provides no pidfd variant of setpriority. Check the
                    // thread incarnation immediately before and after the numeric
                    // TID syscall; never present that check as an atomic guarantee.
                    match ops.set(current.tid, nice) {
                        Err(ActionError::ProcessNotFound)
                            if ops.read(target.pid.0, current.tid)?.is_none() =>
                        {
                            continue
                        }
                        other => other?,
                    }
                    writes.push(current.tid);
                    debug!(
                        pid = target.pid.0,
                        tid = current.tid,
                        previous_nice = current.nice,
                        nice,
                        "thread renice applied"
                    );
                    let after = ops.read(target.pid.0, current.tid)?.ok_or_else(|| {
                        ActionError::Failed(format!(
                            "thread {} disappeared before priority readback",
                            current.tid
                        ))
                    })?;
                    if !current.same_task(&after) {
                        return Err(ActionError::IdentityMismatch);
                    }
                    if after.nice < nice {
                        return Err(ActionError::Failed(format!("thread {} priority readback mismatch: expected at least {nice}, got {}", current.tid, after.nice)));
                    }
                }
                let after = snapshot(ops, target)?;
                if before.complete
                    && after.complete
                    && same_tasks(&before.tasks, &after.tasks)
                    && after.tasks.iter().all(|task| task.nice >= nice)
                {
                    info!(
                        pid = target.pid.0,
                        threads = after.tasks.len(),
                        writes = writes.len(),
                        nice,
                        "all observed threads reniced and verified"
                    );
                    return Ok(());
                }
            }
            Err(ActionError::Failed(format!("thread membership or priority did not settle within {MAX_PASSES} renice passes; all-thread result is unverified")))
        })();
        result.map_err(|error| partial_error("renice", &writes, error))
    }

    pub(super) fn verify(
        ops: &impl TaskOps,
        target: &ProcessIdentity,
        nice: i32,
    ) -> Result<(), ActionError> {
        let mut previous = snapshot(ops, target)?;
        for _ in 0..MAX_PASSES {
            let current = snapshot(ops, target)?;
            if previous.complete && current.complete && same_tasks(&previous.tasks, &current.tasks)
            {
                if let Some(task) = current.tasks.iter().find(|task| task.nice < nice) {
                    return Err(ActionError::Failed(format!("thread {} remains at nice {}, expected at least {nice}; all-thread renice is unverified", task.tid, task.nice)));
                }
                return Ok(());
            }
            previous = current;
        }
        Err(ActionError::Failed(
            "thread membership did not settle for all-thread renice verification".into(),
        ))
    }

    pub(super) fn capture(
        runner: &ReniceActionRunner,
        pid: u32,
    ) -> Result<ReniceReversalMetadata, ActionError> {
        super::super::signal::ensure_action_pid_namespace()?;
        let ops = LiveTasks(runner);
        let leader = ops.read(pid, pid)?.ok_or(ActionError::ProcessNotFound)?;
        let boot_id =
            std::fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(|error| {
                ActionError::Failed(format!("cannot capture renice boot identity: {error}"))
            })?;
        let target = ProcessIdentity::new(
            pid,
            StartId::from_linux(boot_id.trim(), leader.start_ticks, pid),
            leader.uid,
        );
        let before = snapshot(&ops, &target)?;
        let after = snapshot(&ops, &target)?;
        if !before.complete || !after.complete || before.tasks != after.tasks {
            return Err(ActionError::Failed(
                "thread state changed during renice reversal capture".into(),
            ));
        }
        let nice = runner.effective_nice_value();
        if !(-20..=MAX_NICE_VALUE).contains(&nice) {
            return Err(ActionError::Failed("invalid priority value".into()));
        }
        let previous_nice = after
            .tasks
            .iter()
            .find(|task| task.tid == pid)
            .ok_or(ActionError::ProcessNotFound)?
            .nice;
        Ok(ReniceReversalMetadata {
            pid,
            previous_nice,
            applied_nice: previous_nice.max(nice),
            applied_at: chrono::Utc::now().to_rfc3339(),
            identity: Some(target),
            threads: after
                .tasks
                .into_iter()
                .map(|task| ReniceThreadReversal {
                    tid: task.tid,
                    start_ticks: task.start_ticks,
                    uid: task.uid,
                    previous_nice: task.nice,
                    applied_nice: task.nice.max(nice),
                })
                .collect(),
        })
    }

    pub(super) fn restore(
        ops: &impl TaskOps,
        metadata: &ReniceReversalMetadata,
    ) -> Result<(), ActionError> {
        let target = metadata
            .identity
            .as_ref()
            .filter(|target| target.pid.0 == metadata.pid)
            .ok_or_else(|| {
                ActionError::Failed("renice reversal lacks a matching process identity".into())
            })?;
        if metadata.threads.is_empty() || metadata.threads.len() > MAX_THREADS {
            return Err(ActionError::Failed(
                "renice reversal lacks a bounded set of per-thread priorities".into(),
            ));
        }
        let mut saved_by_tid = std::collections::BTreeMap::new();
        for saved in &metadata.threads {
            if saved.tid == 0
                || saved.tid > i32::MAX as u32
                || saved.uid != target.uid
                || !(-20..=MAX_NICE_VALUE).contains(&saved.previous_nice)
                || !(saved.previous_nice..=MAX_NICE_VALUE).contains(&saved.applied_nice)
                || saved_by_tid.insert(saved.tid, saved).is_some()
            {
                return Err(ActionError::Failed(
                    "invalid or duplicate per-thread renice reversal state".into(),
                ));
            }
        }
        let mut writes = Vec::new();
        let result = (|| {
            let before = snapshot(ops, target)?;
            if !before.complete {
                return Err(ActionError::Failed(
                    "thread census changed before renice restoration".into(),
                ));
            }
            // Refuse unknown or reused live threads before making any changes.
            // Threads that exited need no restoration; new threads have no saved priority.
            for task in &before.tasks {
                let saved = saved_by_tid.get(&task.tid).ok_or_else(|| {
                    ActionError::Failed(format!(
                        "no prior priority recorded for thread {}",
                        task.tid
                    ))
                })?;
                if saved.start_ticks != task.start_ticks || saved.uid != task.uid {
                    return Err(ActionError::IdentityMismatch);
                }
            }
            for task in &before.tasks {
                let saved = saved_by_tid
                    .get(&task.tid)
                    .ok_or(ActionError::IdentityMismatch)?;
                ops.revalidate(target)?;
                let current = ops
                    .read(target.pid.0, task.tid)?
                    .ok_or(ActionError::ProcessNotFound)?;
                if !task.same_task(&current) {
                    return Err(ActionError::IdentityMismatch);
                }
                if current.nice == saved.previous_nice {
                    continue;
                }
                if current.nice != saved.applied_nice {
                    return Err(ActionError::Failed(format!(
                        "thread {} priority changed since renice; refusing to overwrite it",
                        task.tid
                    )));
                }
                ops.set(task.tid, saved.previous_nice)?;
                writes.push(task.tid);
                let after = ops
                    .read(target.pid.0, task.tid)?
                    .ok_or(ActionError::ProcessNotFound)?;
                if !task.same_task(&after) {
                    return Err(ActionError::IdentityMismatch);
                }
                if after.nice != saved.previous_nice {
                    return Err(ActionError::Failed(format!(
                        "thread {} priority restoration is unverified",
                        task.tid
                    )));
                }
            }
            let after = snapshot(ops, target)?;
            if !after.complete
                || !same_tasks(&before.tasks, &after.tasks)
                || after.tasks.iter().any(|task| {
                    saved_by_tid
                        .get(&task.tid)
                        .is_none_or(|saved| task.nice != saved.previous_nice)
                })
            {
                return Err(ActionError::Failed(
                    "all-thread priority restoration could not be verified".into(),
                ));
            }
            Ok(())
        })();
        result.map_err(|error| partial_error("renice restoration", &writes, error))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::cell::{Cell, RefCell};
        use std::collections::BTreeMap;

        struct FakeTasks {
            tasks: RefCell<BTreeMap<u32, TaskPriority>>,
            writes: RefCell<Vec<(u32, i32)>>,
            reads: RefCell<BTreeMap<u32, usize>>,
            fail_set: Option<u32>,
            fail_read: Option<u32>,
            reuse_on_read: Option<(u32, usize)>,
            add_after_write: Cell<bool>,
            churn: bool,
            censuses: Cell<usize>,
        }

        impl FakeTasks {
            fn new(priorities: &[(u32, i32)]) -> Self {
                Self {
                    tasks: RefCell::new(
                        priorities
                            .iter()
                            .map(|(tid, nice)| {
                                (
                                    *tid,
                                    TaskPriority {
                                        tid: *tid,
                                        start_ticks: u64::from(*tid) * 2,
                                        uid: 1000,
                                        nice: *nice,
                                    },
                                )
                            })
                            .collect(),
                    ),
                    writes: RefCell::new(Vec::new()),
                    reads: RefCell::new(BTreeMap::new()),
                    fail_set: None,
                    fail_read: None,
                    reuse_on_read: None,
                    add_after_write: Cell::new(false),
                    churn: false,
                    censuses: Cell::new(0),
                }
            }
            fn target() -> ProcessIdentity {
                ProcessIdentity::new(100, StartId::from_linux("boot", 200, 100), 1000)
            }
            fn saved(&self, nice: i32) -> ReniceReversalMetadata {
                ReniceReversalMetadata {
                    pid: 100,
                    previous_nice: self.tasks.borrow()[&100].nice,
                    applied_nice: nice,
                    applied_at: "2026-01-21T00:00:00Z".into(),
                    identity: Some(Self::target()),
                    threads: self
                        .tasks
                        .borrow()
                        .values()
                        .map(|task| ReniceThreadReversal {
                            tid: task.tid,
                            start_ticks: task.start_ticks,
                            uid: task.uid,
                            previous_nice: task.nice,
                            applied_nice: task.nice.max(nice),
                        })
                        .collect(),
                }
            }
        }

        impl TaskOps for FakeTasks {
            fn revalidate(&self, target: &ProcessIdentity) -> Result<(), ActionError> {
                if target.matches(&Self::target()) {
                    Ok(())
                } else {
                    Err(ActionError::IdentityMismatch)
                }
            }
            fn tids(&self, _: u32) -> Result<Vec<u32>, ActionError> {
                self.censuses.set(self.censuses.get() + 1);
                if self.churn {
                    let tid = 1000 + self.censuses.get() as u32;
                    self.tasks.borrow_mut().insert(
                        tid,
                        TaskPriority {
                            tid,
                            start_ticks: u64::from(tid),
                            uid: 1000,
                            nice: 19,
                        },
                    );
                }
                Ok(self.tasks.borrow().keys().copied().collect())
            }
            fn read(&self, _: u32, tid: u32) -> Result<Option<TaskPriority>, ActionError> {
                if self.fail_read == Some(tid) {
                    return Err(ActionError::Failed(
                        "thread evidence permission denied".into(),
                    ));
                }
                let mut reads = self.reads.borrow_mut();
                let count = reads.entry(tid).or_default();
                *count += 1;
                if self.reuse_on_read == Some((tid, *count)) {
                    self.tasks.borrow_mut().get_mut(&tid).unwrap().start_ticks += 1;
                }
                Ok(self.tasks.borrow().get(&tid).cloned())
            }
            fn set(&self, tid: u32, nice: i32) -> Result<(), ActionError> {
                if self.fail_set == Some(tid) {
                    return Err(ActionError::PermissionDenied);
                }
                self.tasks
                    .borrow_mut()
                    .get_mut(&tid)
                    .ok_or(ActionError::ProcessNotFound)?
                    .nice = nice;
                self.writes.borrow_mut().push((tid, nice));
                if self.add_after_write.replace(false) {
                    self.tasks.borrow_mut().insert(
                        400,
                        TaskPriority {
                            tid: 400,
                            start_ticks: 800,
                            uid: 1000,
                            nice: 0,
                        },
                    );
                }
                Ok(())
            }
        }

        #[test]
        fn renice_rejects_thread_reuse_before_and_after_priority_write() {
            for read_number in [2, 3] {
                let mut ops = FakeTasks::new(&[(100, 0), (200, 0)]);
                ops.reuse_on_read = Some((100, read_number));
                let error = apply(&ops, &FakeTasks::target(), 10).unwrap_err();
                assert_eq!(ops.writes.borrow().len(), read_number - 2);
                if read_number == 2 {
                    assert!(matches!(error, ActionError::IdentityMismatch));
                } else {
                    assert!(error
                        .to_string()
                        .contains("1 thread priority write(s) already succeeded"));
                    assert!(error.to_string().contains("identity mismatch"));
                }
                assert_eq!(
                    ops.tasks.borrow()[&200].nice,
                    0,
                    "do not continue after identity failure"
                );
            }
        }

        #[test]
        fn renice_partial_permission_failure_preserves_successful_write_count() {
            let mut ops = FakeTasks::new(&[(100, 0), (200, 0), (300, 0)]);
            ops.fail_set = Some(200);
            let error = apply(&ops, &FakeTasks::target(), 10)
                .unwrap_err()
                .to_string();
            assert!(error.contains("permission denied"));
            assert!(error.contains("1 thread priority write(s) already succeeded (TIDs 100)"));
            assert!(error.contains("changes were not rolled back"));
            assert_eq!(*ops.writes.borrow(), vec![(100, 10)]);
            assert_eq!(ops.tasks.borrow()[&300].nice, 0);
        }

        #[test]
        fn renice_refuses_unreadable_threads_and_invalid_targets_before_writes() {
            let mut ops = FakeTasks::new(&[(100, 0), (200, 0)]);
            ops.fail_read = Some(200);
            assert!(apply(&ops, &FakeTasks::target(), 10)
                .unwrap_err()
                .to_string()
                .contains("evidence permission denied"));
            assert!(ops.writes.borrow().is_empty());
            ops.fail_read = None;
            let mut target = FakeTasks::target();
            target.start_id = StartId::from_linux("boot", 201, 100);
            assert!(matches!(
                apply(&ops, &target, 10),
                Err(ActionError::IdentityMismatch)
            ));
            assert!(apply(&ops, &FakeTasks::target(), 100).is_err());
            assert!(ops.writes.borrow().is_empty());
        }

        #[test]
        fn renice_catches_new_threads_and_bounds_persistent_churn() {
            let ops = FakeTasks::new(&[(100, 10), (200, 0), (300, 19)]);
            ops.add_after_write.set(true);
            apply(&ops, &FakeTasks::target(), 10)
                .expect("new worker should be caught on next pass");
            assert_eq!(*ops.writes.borrow(), vec![(200, 10), (400, 10)]);
            assert_eq!(
                ops.tasks.borrow()[&300].nice,
                19,
                "never raise an already-lower priority"
            );
            verify(&ops, &FakeTasks::target(), 10).expect("all workers verified");

            let mut churn = FakeTasks::new(&[(100, 0), (200, 0)]);
            churn.churn = true;
            let error = apply(&churn, &FakeTasks::target(), 10)
                .unwrap_err()
                .to_string();
            assert!(error.contains("did not settle"));
            assert!(error.contains("already succeeded"));
            assert!(churn.censuses.get() <= MAX_PASSES * 4);
        }

        #[test]
        fn renice_verification_includes_workers() {
            let ops = FakeTasks::new(&[(100, 10), (200, 0)]);
            let error = verify(&ops, &FakeTasks::target(), 10)
                .unwrap_err()
                .to_string();
            assert!(error.contains("thread 200 remains at nice 0"));
            assert!(
                ops.writes.borrow().is_empty(),
                "verification must not mutate the process"
            );
        }

        #[test]
        fn reversal_restores_each_threads_exact_priority() {
            let ops = FakeTasks::new(&[(100, 0), (200, 5), (300, 19)]);
            let before = ops.tasks.borrow().clone();
            let saved = ops.saved(10);
            apply(&ops, &FakeTasks::target(), 10).unwrap();
            restore(&ops, &saved).unwrap();
            assert_eq!(*ops.tasks.borrow(), before);
            assert!(!ops.writes.borrow().iter().any(|(tid, _)| *tid == 300));
            let roundtrip: ReniceReversalMetadata =
                serde_json::from_str(&serde_json::to_string(&saved).unwrap()).unwrap();
            assert_eq!(roundtrip.threads[1].previous_nice, 5);
            assert_eq!(roundtrip.threads[2].applied_nice, 19);
        }

        #[test]
        fn reversal_refuses_unbound_reused_and_unknown_threads() {
            let ops = FakeTasks::new(&[(100, 10), (200, 10)]);
            let saved = ops.saved(10);
            let mut missing = saved.clone();
            missing.identity = None;
            assert!(restore(&ops, &missing).is_err());
            missing = saved.clone();
            missing.threads.pop();
            assert!(restore(&ops, &missing)
                .unwrap_err()
                .to_string()
                .contains("no prior priority"));
            let mut reused = saved;
            reused.threads[1].start_ticks += 1;
            assert!(matches!(
                restore(&ops, &reused),
                Err(ActionError::IdentityMismatch)
            ));
            assert!(ops.writes.borrow().is_empty());
        }

        #[test]
        fn thread_parser_requires_membership_birth_and_priority_evidence() {
            let stat = "200 (worker (name)) S 1 1 1 0 0 0 0 0 0 0 0 0 0 0 20 5 2 0 400";
            let status = "Tgid:\t100\nPid:\t200\nUid:\t1000 1000 1000 1000\n";
            let task = parse_task(100, 200, stat, status).unwrap();
            assert_eq!((task.nice, task.start_ticks, task.uid), (5, 400, 1000));
            assert!(parse_task(101, 200, stat, status).is_err());
            assert!(parse_task(100, 201, stat, status).is_err());
            assert!(parse_task(100, 200, "200 (worker) S 1", status).is_err());
            assert!(parse_task(100, 200, &stat.replace("20 5 2", "20 unknown 2"), status).is_err());
            assert!(parse_task(100, 200, stat, "Tgid: 100\nPid: 200\n").is_err());
        }

        #[test]
        fn renice_owned_multithread_process() {
            use std::io::{BufRead, Read, Write};
            use std::process::{Command, Stdio};
            const MODE: &str = "PT_RENICE_MULTITHREAD_FIXTURE";
            const READY: &str = "PT_RENICE_THREADS_READY:";
            if std::env::var_os(MODE).is_some() {
                let runner = ReniceActionRunner::with_defaults();
                let tid = unsafe { libc::syscall(libc::SYS_gettid) } as u32;
                let initial = runner.get_nice_value(tid).expect("fixture thread nice");
                assert!(
                    initial < 18,
                    "fixture requires room to lower priority without privileges"
                );
                let target = initial + 2;
                let (ready_tx, ready_rx) = std::sync::mpsc::channel();
                for nice in [initial, initial + 1, 19] {
                    let ready_tx = ready_tx.clone();
                    std::thread::spawn(move || {
                        let tid = unsafe { libc::syscall(libc::SYS_gettid) } as u32;
                        ReniceActionRunner::with_defaults()
                            .set_priority(tid, nice)
                            .expect("owned worker priority");
                        ready_tx.send(()).unwrap();
                        loop {
                            std::thread::park();
                        }
                    });
                }
                for _ in 0..3 {
                    ready_rx
                        .recv_timeout(std::time::Duration::from_secs(5))
                        .expect("owned worker readiness");
                }
                // Reproduce the former early-success bug: the leader is already
                // niced, while workers still retain higher scheduling priority.
                runner
                    .set_priority(std::process::id(), target)
                    .expect("owned leader priority");
                println!("{READY}{target}");
                std::io::stdout().flush().unwrap();
                let _ = std::io::stdin().read(&mut [0u8; 1]);
                return;
            }

            struct OwnedChild {
                child: std::process::Child,
                reader: Option<std::thread::JoinHandle<()>>,
            }
            impl Drop for OwnedChild {
                fn drop(&mut self) {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    if let Some(reader) = self.reader.take() {
                        let _ = reader.join();
                    }
                }
            }
            let mut owned = OwnedChild {
                child: Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "action::renice::linux_threads::tests::renice_owned_multithread_process",
                        "--nocapture",
                        "--test-threads=1",
                    ])
                    .env(MODE, "1")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .spawn()
                    .expect("owned multithread fixture"),
                reader: None,
            };
            let output = owned.child.stdout.take().unwrap();
            let (ready_tx, ready_rx) = std::sync::mpsc::channel();
            owned.reader = Some(std::thread::spawn(move || {
                for line in std::io::BufReader::new(output).lines() {
                    match line {
                        Ok(line) => {
                            if let Some((_, value)) = line.split_once(READY) {
                                let _ = ready_tx.send(
                                    value
                                        .trim()
                                        .parse::<i32>()
                                        .map_err(|error| error.to_string()),
                                );
                            }
                        }
                        Err(error) => {
                            let _ = ready_tx.send(Err(error.to_string()));
                            break;
                        }
                    }
                }
            }));
            let target_nice = ready_rx
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("fixture readiness deadline")
                .expect("fixture readiness");
            let runner = ReniceActionRunner::new(ReniceConfig {
                nice_value: target_nice,
                ..ReniceConfig::default()
            });
            let pid = owned.child.id();
            let before = runner
                .capture_reversal_metadata(pid)
                .expect("complete owned thread snapshot");
            assert!(before.threads.len() >= 4);
            assert_eq!(before.previous_nice, target_nice);
            assert!(before
                .threads
                .iter()
                .any(|thread| thread.previous_nice < target_nice));
            assert!(before
                .threads
                .iter()
                .any(|thread| thread.previous_nice == 19));
            let mut action: PlanAction = serde_json::from_value(serde_json::json!({
                "action_id": "owned-renice", "target": before.identity.as_ref().unwrap(), "action": "renice",
                "order": 0, "stage": 1, "timeouts": crate::plan::ActionTimeouts::default(),
                "pre_checks": [], "rationale": {}, "on_success": [], "on_failure": [], "blocked": false,
            })).expect("owned action");
            assert!(
                runner.verify(&action).is_err(),
                "leader-only priority must not satisfy verification"
            );
            let identity = action.target.clone();
            action.target.start_id = StartId::from_linux("wrong-boot", 0, pid);
            assert!(matches!(
                runner.execute(&action),
                Err(ActionError::IdentityMismatch)
            ));
            let unchanged = runner.capture_reversal_metadata(pid).unwrap();
            assert_eq!(
                before
                    .threads
                    .iter()
                    .map(|task| (task.tid, task.previous_nice))
                    .collect::<Vec<_>>(),
                unchanged
                    .threads
                    .iter()
                    .map(|task| (task.tid, task.previous_nice))
                    .collect::<Vec<_>>()
            );
            action.target = identity;
            runner.execute(&action).expect("renice every owned worker");
            runner.verify(&action).expect("verify every owned worker");
            let after = runner.capture_reversal_metadata(pid).unwrap();
            assert_eq!(after.threads.len(), before.threads.len());
            for prior in &before.threads {
                let current = after
                    .threads
                    .iter()
                    .find(|thread| thread.tid == prior.tid)
                    .unwrap();
                assert_eq!(current.start_ticks, prior.start_ticks);
                assert_eq!(current.previous_nice, prior.previous_nice.max(target_nice));
            }
        }
    }
}

#[cfg(unix)]
impl ActionRunner for ReniceActionRunner {
    fn execute(&self, action: &PlanAction) -> Result<(), ActionError> {
        match action.action {
            Action::Renice => self.execute_renice(action),
            Action::Keep => Ok(()),
            Action::Pause
            | Action::Resume
            | Action::Kill
            | Action::Throttle
            | Action::Restart
            | Action::Freeze
            | Action::Unfreeze
            | Action::Quarantine
            | Action::Unquarantine => Err(ActionError::Failed(format!(
                "{:?} requires signal/cgroup support, not renice",
                action.action
            ))),
        }
    }

    fn verify(&self, action: &PlanAction) -> Result<(), ActionError> {
        match action.action {
            Action::Renice => self.verify_renice(action),
            Action::Keep => Ok(()),
            Action::Pause
            | Action::Resume
            | Action::Kill
            | Action::Throttle
            | Action::Restart
            | Action::Freeze
            | Action::Unfreeze
            | Action::Quarantine
            | Action::Unquarantine => Ok(()),
        }
    }
}

#[cfg(not(unix))]
impl ActionRunner for ReniceActionRunner {
    fn execute(&self, _action: &PlanAction) -> Result<(), ActionError> {
        Err(ActionError::Failed(
            "renice not supported on this platform".to_string(),
        ))
    }

    fn verify(&self, _action: &PlanAction) -> Result<(), ActionError> {
        Err(ActionError::Failed(
            "renice not supported on this platform".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renice_config_defaults() {
        let config = ReniceConfig::default();
        assert_eq!(config.nice_value, DEFAULT_NICE_VALUE);
        assert!(config.clamp_to_range);
    }

    #[test]
    fn effective_nice_value_clamped() {
        let runner = ReniceActionRunner::new(ReniceConfig {
            nice_value: 100,
            clamp_to_range: true,
            capture_reversal: false,
        });
        assert_eq!(runner.effective_nice_value(), MAX_NICE_VALUE);

        let runner = ReniceActionRunner::new(ReniceConfig {
            nice_value: -100,
            clamp_to_range: true,
            capture_reversal: false,
        });
        assert_eq!(runner.effective_nice_value(), -20);
    }

    #[test]
    fn effective_nice_value_unclamped() {
        let runner = ReniceActionRunner::new(ReniceConfig {
            nice_value: 100,
            clamp_to_range: false,
            capture_reversal: false,
        });
        assert_eq!(runner.effective_nice_value(), 100);
    }

    #[test]
    fn renice_config_with_capture_reversal() {
        let config = ReniceConfig {
            nice_value: 5,
            clamp_to_range: true,
            capture_reversal: true,
        };
        assert_eq!(config.nice_value, 5);
        assert!(config.capture_reversal);
    }

    #[cfg(unix)]
    mod unix_tests {
        use super::*;
        use std::process::Command;

        struct ChildGuard(std::process::Child);

        impl Drop for ChildGuard {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        #[test]
        fn runner_can_be_created() {
            let runner = ReniceActionRunner::with_defaults();
            assert_eq!(runner.config.nice_value, DEFAULT_NICE_VALUE);
        }

        #[test]
        fn verification_requires_observed_priority_at_or_below_target() {
            // Higher nice means lower priority. Equality and a pre-existing
            // lower priority are valid; missing evidence and higher priority are not.
            for (observed, target) in [(Some(10), 10), (Some(19), 10), (Some(-20), -20)] {
                assert!(ReniceActionRunner::verify_observed_priority(observed, target).is_ok());
            }
            for (observed, target) in [(Some(9), 10), (Some(-20), -19), (None, 10)] {
                assert!(matches!(
                    ReniceActionRunner::verify_observed_priority(observed, target),
                    Err(ActionError::Failed(_))
                ));
            }
        }

        #[test]
        #[cfg(target_os = "linux")]
        fn get_nice_value_for_self() {
            let runner = ReniceActionRunner::with_defaults();
            let pid = std::process::id();
            let nice = runner.get_nice_value(pid);
            // Our process should have a nice value (typically 0)
            assert!(nice.is_some());
        }

        #[test]
        fn can_renice_child_process() {
            // Spawn a sleep process
            let child = Command::new("sleep")
                .arg("60")
                .spawn()
                .expect("failed to spawn sleep");

            let pid = child.id();
            let _guard = ChildGuard(child);
            let runner = ReniceActionRunner::with_defaults();

            // Renice it - this may fail with PermissionDenied in some environments
            // (e.g., containers, certain security profiles, or systems with strict resource limits)
            let renice_result = runner.set_priority(pid, 15);
            match &renice_result {
                Ok(_) => {
                    // Verify the new nice value
                    #[cfg(target_os = "linux")]
                    {
                        std::thread::sleep(std::time::Duration::from_millis(50));
                        let nice = runner.get_nice_value(pid);
                        assert_eq!(nice, Some(15), "expected nice value 15");
                    }
                }
                Err(ActionError::PermissionDenied) => {
                    // Skip verification in environments without renice permissions
                    eprintln!(
                        "Note: Skipping renice verification - insufficient permissions in this environment"
                    );
                }
                Err(e) => {
                    panic!("renice failed with unexpected error: {:?}", e);
                }
            }
        }

        #[test]
        fn renice_nonexistent_process_fails() {
            let runner = ReniceActionRunner::with_defaults();
            let result = runner.set_priority(999_999_999, 10);
            assert!(result.is_err());
        }

        #[test]
        #[cfg(target_os = "linux")]
        fn capture_reversal_metadata_for_owned_child() {
            let runner = ReniceActionRunner::with_defaults();
            let child = Command::new("sleep")
                .arg("60")
                .spawn()
                .expect("owned child");
            let pid = child.id();
            let _guard = ChildGuard(child);

            let metadata = runner.capture_reversal_metadata(pid);
            assert!(metadata.is_some(), "should capture reversal metadata");

            let meta = metadata.unwrap();
            assert_eq!(meta.pid, pid);
            assert_eq!(
                meta.applied_nice,
                meta.previous_nice.max(DEFAULT_NICE_VALUE)
            );
            assert!(meta.identity.is_some());
            assert_eq!(meta.threads.len(), 1);
            assert_eq!(meta.threads[0].previous_nice, meta.previous_nice);
            // Previous nice should be captured (typically 0 for normal processes)
            eprintln!(
                "Captured reversal metadata: previous_nice={}, applied_nice={}",
                meta.previous_nice, meta.applied_nice
            );
        }

        #[test]
        fn renice_result_serialization() {
            let result = ReniceResult {
                success: true,
                effective_nice: Some(10),
                reversal: Some(ReniceReversalMetadata {
                    pid: 1234,
                    previous_nice: 0,
                    applied_nice: 10,
                    applied_at: "2026-01-21T00:00:00Z".to_string(),
                    identity: None,
                    threads: Vec::new(),
                }),
                error: None,
            };

            let json = serde_json::to_string(&result).expect("serialization");
            assert!(json.contains("success"));
            assert!(json.contains("effective_nice"));
            assert!(json.contains("reversal"));
            assert!(json.contains("previous_nice"));
        }

        #[test]
        fn renice_reversal_metadata_serialization() {
            let metadata = ReniceReversalMetadata {
                pid: 5678,
                previous_nice: 5,
                applied_nice: 15,
                applied_at: "2026-01-21T12:00:00Z".to_string(),
                identity: None,
                threads: Vec::new(),
            };

            let json = serde_json::to_string(&metadata).expect("serialization");
            let deserialized: ReniceReversalMetadata =
                serde_json::from_str(&json).expect("deserialization");

            assert_eq!(deserialized.pid, 5678);
            assert_eq!(deserialized.previous_nice, 5);
            assert_eq!(deserialized.applied_nice, 15);
        }
    }
}
