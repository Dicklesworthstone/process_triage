//! Signal-based action execution.
//!
//! Implements the actual signal delivery for pause/resume/kill actions with:
//! - TOCTOU safety via identity revalidation
//! - Staged escalation (SIGTERM → SIGKILL)
//! - Process group awareness
//! - Outcome verification

use super::executor::{ActionError, ActionRunner};
use crate::decision::Action;
use crate::plan::PlanAction;
use std::thread;
use std::time::{Duration, Instant};

/// Procfs identities and numeric-PID syscalls must refer to the same namespace.
/// A container can inherit an ancestor namespace's procfs mount: in that case
/// even a matching start time in `/proc/PID` does not identify `kill(PID)` or
/// `pidfd_open(PID)` in the caller's namespace. Do not cache this check; a mount
/// namespace or its procfs mount can change while the process is running.
pub(super) fn ensure_action_pid_namespace() -> Result<(), ActionError> {
    #[cfg(target_os = "linux")]
    {
        let proc_self = std::fs::read_link("/proc/self").map_err(|error| {
            ActionError::Failed(format!(
                "cannot establish action PID namespace from /proc/self: {error}"
            ))
        })?;
        let status = std::fs::read_to_string("/proc/self/status").map_err(|error| {
            ActionError::Failed(format!(
                "cannot establish action PID namespace from /proc/self/status: {error}"
            ))
        })?;
        validate_procfs_pid_namespace(std::process::id(), &proc_self, &status)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_procfs_pid_namespace(
    caller_pid: u32,
    proc_self: &std::path::Path,
    status: &str,
) -> Result<(), ActionError> {
    let observed = proc_self
        .to_str()
        .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|pid| *pid > 0)
        .ok_or_else(|| {
            ActionError::Failed(
                "cannot establish action PID namespace: invalid /proc/self link".into(),
            )
        })?;
    if observed != caller_pid {
        return Err(ActionError::Failed(format!(
            "refusing action: procfs PID namespace differs from the caller (/proc/self={observed}, caller={caller_pid})"
        )));
    }
    // Numeric PIDs can coincide across nested namespaces after PID wraparound.
    // NSpid starts in the procfs mount's namespace and lists each nested PID;
    // only a single observed PID proves the mount uses the caller's namespace.
    let mut namespace_lines = status
        .lines()
        .filter_map(|line| line.strip_prefix("NSpid:"));
    let mut pids = namespace_lines
        .next()
        .ok_or_else(|| {
            ActionError::Failed("cannot establish action PID namespace: NSpid is missing".into())
        })?
        .split_whitespace();
    if namespace_lines.next().is_some()
        || pids.next().and_then(|pid| pid.parse::<u32>().ok()) != Some(caller_pid)
        || pids.next().is_some()
    {
        return Err(ActionError::Failed(
            "refusing action: procfs PID namespace is ambiguous or differs from the caller (NSpid)"
                .into(),
        ));
    }
    Ok(())
}

/// Convert a resolved process/group ID without admitting kill(2)'s special
/// broadcast targets. PID 0 targets the caller's group, and negating PGID 1
/// produces -1 (all signalable processes), not a process-group-only operation.
/// PID 1 itself is protected infrastructure and is never an action target.
#[cfg(any(unix, test))]
fn signal_syscall_target(target_id: u32, use_group: bool) -> Result<i32, ActionError> {
    if target_id <= 1 {
        return Err(ActionError::Failed(format!(
            "refusing signal to protected {} {}",
            if use_group { "process group" } else { "PID" },
            target_id
        )));
    }
    let target = i32::try_from(target_id)
        .map_err(|_| ActionError::Failed(format!("PID {target_id} exceeds i32 range")))?;
    Ok(if use_group { -target } else { target })
}

/// A job-control stopped target cannot handle a pending SIGTERM until resumed.
/// Tracing stops belong to the debugger, and one process's state cannot justify
/// resuming every member of its process group. Linux distinguishes these stops
/// as `T` and `t`; other collectors do not yet provide that distinction.
#[cfg(any(unix, test))]
fn should_resume_after_sigterm(state: Option<char>, use_group: bool) -> bool {
    cfg!(target_os = "linux") && !use_group && state == Some('T')
}

/// A phase budget from the approved plan. Elapsed time is measured monotonically;
/// using a duration instead of adding to Instant also accepts large saved budgets
/// without overflowing the platform's clock representation.
struct SignalDeadline {
    started: Instant,
    budget: Duration,
}

impl SignalDeadline {
    fn new(timeout_ms: u64) -> Self {
        Self {
            started: Instant::now(),
            budget: Duration::from_millis(timeout_ms),
        }
    }

    fn remaining(&self) -> Result<Duration, ActionError> {
        self.budget
            .checked_sub(self.started.elapsed())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(ActionError::Timeout)
    }
}

/// Signal action runner configuration.
#[derive(Debug, Clone)]
pub struct SignalConfig {
    /// Grace period after SIGTERM before escalating to SIGKILL.
    pub term_grace_ms: u64,
    /// Polling interval when waiting for process to exit.
    pub poll_interval_ms: u64,
    /// Maximum time to wait for process state change after signal. A saved
    /// action's verify_ms may impose a shorter observation budget.
    pub verify_timeout_ms: u64,
    /// Whether to send signals to process groups (negative PID).
    pub use_process_groups: bool,
}

impl Default for SignalConfig {
    fn default() -> Self {
        Self {
            term_grace_ms: 5_000,
            poll_interval_ms: 100,
            verify_timeout_ms: 10_000,
            use_process_groups: false,
        }
    }
}

/// Signal-based action runner.
#[derive(Debug)]
pub struct SignalActionRunner {
    config: SignalConfig,
    /// How the last signal was delivered: "pidfd", "kill" or "kill_group".
    last_path: std::sync::Mutex<Option<&'static str>>,
    /// A successful SIGTERM/SIGKILL delivery, even if later verification fails.
    kill_signal_delivered: std::sync::atomic::AtomicBool,
}

impl SignalActionRunner {
    pub fn new(config: SignalConfig) -> Self {
        Self {
            config,
            last_path: std::sync::Mutex::new(None),
            kill_signal_delivered: std::sync::atomic::AtomicBool::new(false),
        }
    }

    fn note_path(&self, path: &'static str) {
        *self.last_path.lock().unwrap_or_else(|e| e.into_inner()) = Some(path);
    }

    /// How the most recent signal was delivered ("pidfd", "kill", "kill_group"),
    /// clearing it; `None` if no signal was sent since the last call.
    pub fn take_signal_path(&self) -> Option<&'static str> {
        self.last_path
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
    }

    /// Consume actual destructive-signal delivery evidence for budget accounting.
    pub fn take_kill_signal_delivered(&self) -> bool {
        self.kill_signal_delivered
            .swap(false, std::sync::atomic::Ordering::Relaxed)
    }

    #[cfg(unix)]
    fn note_delivered_signal(&self, signal: i32) {
        if matches!(signal, libc::SIGTERM | libc::SIGKILL) {
            self.kill_signal_delivered
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(SignalConfig::default())
    }

    fn resolve_group_target(&self, pid: u32, pgid: Option<u32>) -> (u32, bool) {
        let pgid = pgid.filter(|pgid| *pgid > 0);
        let use_group = self.config.use_process_groups && pgid.is_some();
        let target = if use_group { pgid.unwrap() } else { pid };
        (target, use_group)
    }

    /// Send a signal to a process (or process group when `use_group` is true).
    ///
    /// `target_id` is the resolved target: either the PID itself or the PGID,
    /// as returned by [`resolve_group_target`].
    #[cfg(unix)]
    fn send_signal(&self, target_id: u32, signal: i32, use_group: bool) -> Result<(), ActionError> {
        let target_pid = signal_syscall_target(target_id, use_group)?;
        ensure_action_pid_namespace()?;
        self.note_path(if use_group { "kill_group" } else { "kill" });

        let result = unsafe { libc::kill(target_pid, signal) };
        if result == 0 {
            self.note_delivered_signal(signal);
            return Ok(());
        }

        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::ESRCH) => Err(ActionError::ProcessNotFound),
            Some(libc::EPERM) => Err(ActionError::PermissionDenied),
            Some(libc::EINVAL) => Err(ActionError::Failed("invalid signal".to_string())),
            _ => Err(ActionError::Failed(err.to_string())),
        }
    }

    /// Open a pidfd pinned to the planned process (Linux >= 5.3), if available.
    ///
    /// `Ok(None)` means pidfds are unsupported here (fall back to `kill(2)`).
    #[cfg(target_os = "linux")]
    fn pinned_pidfd(&self, action: &PlanAction) -> Result<Option<PidFd>, ActionError> {
        ensure_action_pid_namespace()?;
        let pid = action.target.pid.0;
        let Some(fd) = PidFd::open(pid)? else {
            return Ok(None);
        };
        // The pidfd now refers to whatever process holds `pid` right now. Confirm it
        // is the planned one (exact start ticks). If the pid was reused after the
        // open, /proc shows the newcomer and we refuse; if it is reused after this
        // check, signals sent through the pidfd fail with ESRCH instead of hitting
        // the newcomer.
        match self.read_starttime(pid) {
            Some(current) if ids_match_starttime(&action.target.start_id.0, current) => {
                self.note_path("pidfd");
                Ok(Some(fd))
            }
            Some(_) => Err(ActionError::IdentityMismatch),
            None => Err(ActionError::ProcessNotFound),
        }
    }

    /// Check if a process exists.
    #[cfg(unix)]
    fn process_exists(&self, pid: u32) -> bool {
        let result = unsafe { libc::kill(pid as i32, 0) };
        if result == 0 {
            return true;
        }
        let err = std::io::Error::last_os_error();
        // EPERM means process exists but we can't signal it
        err.raw_os_error() == Some(libc::EPERM)
    }

    /// Get process state.
    #[cfg(target_os = "linux")]
    fn get_process_state(&self, pid: u32) -> Option<char> {
        let stat_path = format!("/proc/{pid}/stat");
        let content_bytes = std::fs::read(stat_path).ok()?;
        let content = String::from_utf8_lossy(&content_bytes);
        // Format: pid (comm) state ...
        let comm_end = content.rfind(')')?;
        let after_comm = content.get(comm_end + 2..)?;
        after_comm.chars().next()
    }

    #[cfg(target_os = "macos")]
    fn get_process_state(&self, pid: u32) -> Option<char> {
        crate::collect::read_process_snapshot(pid).map(|info| info.state)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn get_process_state(&self, _pid: u32) -> Option<char> {
        None
    }

    /// Read the starttime field for PID-reuse detection.
    #[cfg(target_os = "linux")]
    fn read_starttime(&self, pid: u32) -> Option<u64> {
        let stat_path = format!("/proc/{pid}/stat");
        let content_bytes = std::fs::read(stat_path).ok()?;
        let content = String::from_utf8_lossy(&content_bytes);
        let comm_end = content.rfind(')')?;
        let after_comm = content.get(comm_end + 2..)?;
        let fields: Vec<&str> = after_comm.split_whitespace().collect();
        // Field 19 (0-indexed from after comm) is starttime
        fields.get(19)?.parse::<u64>().ok()
    }

    /// Exact start time in microseconds (the value macOS start ids carry).
    #[cfg(target_os = "macos")]
    fn read_starttime(&self, pid: u32) -> Option<u64> {
        crate::collect::macos::read_bsd_info(pid).map(|info| info.start_us)
    }

    /// Wait for a process to reach a target state or exit.
    fn wait_for_state_change(
        &self,
        pid: u32,
        expect_exit: bool,
        expect_stopped: Option<bool>,
        timeout: Duration,
    ) -> Result<(), ActionError> {
        let start = Instant::now();
        let poll_interval = Duration::from_millis(self.config.poll_interval_ms.max(1));

        while start.elapsed() < timeout {
            if expect_exit {
                if !self.process_exists(pid) {
                    return Ok(());
                }
                // A zombie counts as "exited" (we terminated it, even if the parent
                // hasn't reaped it yet).
                if let Some('Z') = self.get_process_state(pid) {
                    return Ok(());
                }
            }

            if let Some(stopped) = expect_stopped {
                if let Some(state) = self.get_process_state(pid) {
                    // 'T' = stopped (traced or stopped), 't' = tracing stop
                    let is_stopped = state == 'T' || state == 't';
                    if is_stopped == stopped {
                        return Ok(());
                    }
                }
            }

            // A coarse polling interval must not extend the approved deadline.
            thread::sleep(poll_interval.min(timeout.saturating_sub(start.elapsed())));
        }

        Err(ActionError::Timeout)
    }

    /// Observe the full configured TERM grace period when the plan permits it.
    /// A shorter execution budget is a timeout, never permission to escalate to
    /// KILL early. `false` means the full grace expired with time left to escalate.
    #[cfg(unix)]
    fn wait_for_term_grace(
        &self,
        pid: u32,
        deadline: &SignalDeadline,
    ) -> Result<bool, ActionError> {
        let remaining = deadline.remaining()?;
        let grace = Duration::from_millis(self.config.term_grace_ms);
        match self.wait_for_state_change(pid, true, None, grace.min(remaining)) {
            Ok(()) => Ok(true),
            Err(ActionError::Timeout) => {
                if remaining <= grace {
                    return Err(ActionError::Timeout);
                }
                deadline.remaining()?;
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    fn verification_timeout(&self, action: &PlanAction) -> Duration {
        Duration::from_millis(self.config.verify_timeout_ms.min(action.timeouts.verify_ms))
    }

    /// Execute a pause action (SIGSTOP).
    #[cfg(unix)]
    fn execute_pause(&self, action: &PlanAction) -> Result<(), ActionError> {
        let deadline = SignalDeadline::new(action.timeouts.execute_ms);
        deadline.remaining()?;
        let pid = action.target.pid.0;
        let (target, use_group) = self.resolve_group_target(pid, action.target.pgid);

        #[cfg(target_os = "linux")]
        if !use_group {
            if let Some(pidfd) = self.pinned_pidfd(action)? {
                deadline.remaining()?;
                return pidfd.send(libc::SIGSTOP);
            }
        }
        // Without a pidfd (macOS, or a Linux kernel before 5.3), re-check the
        // start identity right before the plain kill(2).
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if !use_group {
            self.check_identity_now(action)?;
        }
        deadline.remaining()?;
        self.send_signal(target, libc::SIGSTOP, use_group)?;
        Ok(())
    }

    /// Re-check start identity immediately before fallback signaling, including
    /// escalation when a Linux pidfd is unavailable.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn check_identity_now(&self, action: &PlanAction) -> Result<(), ActionError> {
        match self.read_starttime(action.target.pid.0) {
            Some(current) if ids_match_starttime(&action.target.start_id.0, current) => Ok(()),
            Some(_) => Err(ActionError::IdentityMismatch),
            None => Err(ActionError::ProcessNotFound),
        }
    }

    /// Execute a kill action (SIGTERM → SIGKILL).
    #[cfg(unix)]
    fn execute_kill(&self, action: &PlanAction) -> Result<(), ActionError> {
        let deadline = SignalDeadline::new(action.timeouts.execute_ms);
        deadline.remaining()?;
        let pid = action.target.pid.0;
        let (target, use_group) = self.resolve_group_target(pid, action.target.pgid);
        let resume_stopped = should_resume_after_sigterm(self.get_process_state(pid), use_group);

        // Linux: TERM, any CONT needed for graceful shutdown, and KILL all go
        // through one pidfd pinned to the verified process. Never resume a
        // replacement process if the target exits between these signals.
        #[cfg(target_os = "linux")]
        if !use_group {
            if let Some(pidfd) = self.pinned_pidfd(action)? {
                deadline.remaining()?;
                pidfd.send(libc::SIGTERM)?;
                self.note_delivered_signal(libc::SIGTERM);
                if resume_stopped {
                    deadline.remaining()?;
                    match pidfd.send(libc::SIGCONT) {
                        Ok(()) => {}
                        Err(ActionError::ProcessNotFound) => return Ok(()),
                        Err(error) => return Err(error),
                    }
                }
                return if self.wait_for_term_grace(pid, &deadline)? {
                    Ok(())
                } else {
                    deadline.remaining()?;
                    match pidfd.send(libc::SIGKILL) {
                        Ok(()) => {
                            self.note_delivered_signal(libc::SIGKILL);
                            Ok(())
                        }
                        // Exited between the grace timeout and SIGKILL: done.
                        Err(ActionError::ProcessNotFound) => Ok(()),
                        other => other,
                    }
                };
            }
        }

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if !use_group {
            self.check_identity_now(action)?;
        }

        // Stage 1: SIGTERM
        deadline.remaining()?;
        self.send_signal(target, libc::SIGTERM, use_group)?;

        if resume_stopped {
            // Without a pidfd, revalidate immediately before the additional
            // signal just as for TERM and KILL. CONT always targets this one
            // process, never an unverified group or a tracing-stop subject.
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            self.check_identity_now(action)?;
            deadline.remaining()?;
            match self.send_signal(pid, libc::SIGCONT, false) {
                Ok(()) => {}
                Err(ActionError::ProcessNotFound) => return Ok(()),
                Err(error) => return Err(error),
            }
        }

        // Wait for graceful termination
        if self.wait_for_term_grace(pid, &deadline)? {
            return Ok(());
        }

        // Stage 2: SIGKILL (only if process still exists)
        // TOCTOU window: the process may have exited and its PID may have been
        // reused between the grace-period timeout and the SIGKILL below.
        // Re-validate the starttime to guard against killing a replacement process.
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if self.process_exists(pid) {
            self.check_identity_now(action)?;
        }

        if self.process_exists(pid) {
            deadline.remaining()?;
            self.send_signal(target, libc::SIGKILL, use_group)?;
        }

        Ok(())
    }

    /// Zombie routed to its parent (`ActionRouting::ZombieToParent`): ask the parent
    /// to reap with SIGCHLD. Harmless (the default disposition is ignore); the zombie
    /// itself is never signaled and the parent is never killed or restarted here.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub fn nudge_parent_to_reap(&self, action: &PlanAction) -> Result<(), ActionError> {
        let deadline = SignalDeadline::new(action.timeouts.execute_ms);
        deadline.remaining()?;
        #[cfg(target_os = "linux")]
        if let Some(pidfd) = self.pinned_pidfd(action)? {
            deadline.remaining()?;
            return pidfd.send(libc::SIGCHLD);
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        self.check_identity_now(action)?;
        deadline.remaining()?;
        self.send_signal(action.target.pid.0, libc::SIGCHLD, false)
    }

    /// The routed zombie is gone (reaped), or a different process now holds its pid.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub fn verify_zombie_reaped(&self, action: &PlanAction) -> Result<(), ActionError> {
        let Some(zombie) = action.original_zombie_target.as_ref() else {
            return Ok(());
        };
        let pid = zombie.pid.0;
        let reaped = || {
            self.get_process_state(pid) != Some('Z')
                || self
                    .read_starttime(pid)
                    .is_some_and(|st| !ids_match_starttime(&zombie.start_id.0, st))
        };
        let start = Instant::now();
        let timeout = self.verification_timeout(action);
        while start.elapsed() < timeout {
            if reaped() {
                return Ok(());
            }
            let poll_interval = Duration::from_millis(self.config.poll_interval_ms.max(1));
            thread::sleep(poll_interval.min(timeout.saturating_sub(start.elapsed())));
        }
        Err(ActionError::Failed(format!(
            "zombie {pid} persists: parent {} did not reap it on SIGCHLD; \
             restart or stop the parent to clear it",
            action.target.pid.0
        )))
    }

    /// Verify a pause action succeeded.
    #[cfg(unix)]
    fn verify_pause(&self, action: &PlanAction) -> Result<(), ActionError> {
        let pid = action.target.pid.0;
        let timeout = self.verification_timeout(action);
        self.wait_for_state_change(pid, false, Some(true), timeout)
    }

    /// Verify a kill action succeeded.
    #[cfg(unix)]
    fn verify_kill(&self, action: &PlanAction) -> Result<(), ActionError> {
        let pid = action.target.pid.0;
        let timeout = self.verification_timeout(action);
        self.wait_for_state_change(pid, true, None, timeout)
    }

    /// Execute a resume action (SIGCONT) - raw version.
    #[cfg(unix)]
    pub fn resume(&self, pid: u32, use_group: bool, pgid: Option<u32>) -> Result<(), ActionError> {
        let pgid = pgid.filter(|pgid| *pgid > 0);
        let use_group = use_group && pgid.is_some();
        let target = if use_group { pgid.unwrap() } else { pid };
        self.send_signal(target, libc::SIGCONT, use_group)
    }

    /// Verify a resume action succeeded - raw version.
    pub fn verify_resume_raw(&self, pid: u32) -> Result<(), ActionError> {
        let timeout = Duration::from_millis(self.config.verify_timeout_ms);
        // Process should not be stopped anymore
        self.wait_for_state_change(pid, false, Some(false), timeout)
    }

    /// Execute a resume action (SIGCONT) from PlanAction.
    #[cfg(unix)]
    fn execute_resume(&self, action: &PlanAction) -> Result<(), ActionError> {
        let deadline = SignalDeadline::new(action.timeouts.execute_ms);
        deadline.remaining()?;
        let pid = action.target.pid.0;
        let (target, use_group) = self.resolve_group_target(pid, action.target.pgid);

        #[cfg(target_os = "linux")]
        if !use_group {
            if let Some(pidfd) = self.pinned_pidfd(action)? {
                deadline.remaining()?;
                return pidfd.send(libc::SIGCONT);
            }
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if !use_group {
            self.check_identity_now(action)?;
        }
        deadline.remaining()?;
        self.send_signal(target, libc::SIGCONT, use_group)?;
        Ok(())
    }

    /// Verify a resume action succeeded.
    #[cfg(unix)]
    fn verify_resume(&self, action: &PlanAction) -> Result<(), ActionError> {
        let pid = action.target.pid.0;
        let timeout = self.verification_timeout(action);
        // Process should not be stopped anymore
        self.wait_for_state_change(pid, false, Some(false), timeout)
    }
}

#[cfg(unix)]
impl ActionRunner for SignalActionRunner {
    fn revalidate(
        &self,
        action: &PlanAction,
        provider: &dyn super::executor::IdentityProvider,
    ) -> Result<bool, ActionError> {
        provider.revalidate(&action.target)
    }

    fn execute(&self, action: &PlanAction) -> Result<(), ActionError> {
        match action.action {
            Action::Pause => self.execute_pause(action),
            Action::Resume => self.execute_resume(action),
            Action::Kill => self.execute_kill(action),
            Action::Keep => Ok(()),
            Action::Throttle => {
                // Throttle requires cgroup operations, not signals
                Err(ActionError::Failed(
                    "throttle requires cgroup support".to_string(),
                ))
            }
            Action::Restart => {
                // Restart requires supervisor awareness
                Err(ActionError::Failed(
                    "restart requires supervisor support".to_string(),
                ))
            }
            Action::Renice => {
                // Renice requires setpriority operations, not signals
                Err(ActionError::Failed(
                    "renice requires setpriority support".to_string(),
                ))
            }
            Action::Freeze | Action::Unfreeze => {
                // Freeze/Unfreeze require cgroup v2 freezer operations
                Err(ActionError::Failed(
                    "freeze/unfreeze requires cgroup v2 freezer support".to_string(),
                ))
            }
            Action::Quarantine | Action::Unquarantine => {
                // Quarantine requires cgroup cpuset operations
                Err(ActionError::Failed(
                    "quarantine requires cgroup cpuset support".to_string(),
                ))
            }
        }
    }

    fn verify(&self, action: &PlanAction) -> Result<(), ActionError> {
        match action.action {
            Action::Pause => self.verify_pause(action),
            Action::Resume => self.verify_resume(action),
            Action::Kill => self.verify_kill(action),
            Action::Keep => Ok(()),
            Action::Throttle
            | Action::Restart
            | Action::Renice
            | Action::Freeze
            | Action::Unfreeze
            | Action::Quarantine
            | Action::Unquarantine => Ok(()),
        }
    }
}

#[cfg(not(unix))]
impl ActionRunner for SignalActionRunner {
    fn execute(&self, _action: &PlanAction) -> Result<(), ActionError> {
        Err(ActionError::Failed(
            "signals not supported on this platform".to_string(),
        ))
    }

    fn verify(&self, _action: &PlanAction) -> Result<(), ActionError> {
        Err(ActionError::Failed(
            "signals not supported on this platform".to_string(),
        ))
    }
}

/// Live identity provider that validates against /proc.
#[cfg(target_os = "linux")]
pub struct LiveIdentityProvider {
    boot_id: &'static str,
}

#[cfg(target_os = "linux")]
impl LiveIdentityProvider {
    pub fn new() -> Self {
        use std::sync::OnceLock;
        static BOOT_ID: OnceLock<String> = OnceLock::new();
        let boot_id = BOOT_ID.get_or_init(|| {
            std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .ok()
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|| "unknown".to_string())
        });
        Self { boot_id }
    }

    /// Read start_id from /proc/[pid]/stat.
    fn read_start_id(&self, pid: u32) -> Option<String> {
        let stat_path = format!("/proc/{pid}/stat");
        let content_bytes = std::fs::read(&stat_path).ok()?;
        let content = String::from_utf8_lossy(&content_bytes);
        let comm_end = content.rfind(')')?;
        let after_comm = content.get(comm_end + 2..)?;
        let fields: Vec<&str> = after_comm.split_whitespace().collect();
        // Field 19 (0-indexed from after comm) is starttime
        let starttime = fields.get(19)?.parse::<u64>().ok()?;

        Some(format!("{}:{starttime}:{pid}", self.boot_id))
    }

    /// Read uid from /proc/[pid]/status.
    fn read_uid(&self, pid: u32) -> Option<u32> {
        let status_path = format!("/proc/{pid}/status");
        let content_bytes = std::fs::read(&status_path).ok()?;
        let content = String::from_utf8_lossy(&content_bytes);
        for line in content.lines() {
            if line.starts_with("Uid:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                // Real UID is the first value after "Uid:"
                return parts.get(1)?.parse().ok();
            }
        }
        None
    }
}

#[cfg(target_os = "linux")]
impl Default for LiveIdentityProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "linux")]
impl super::executor::IdentityProvider for LiveIdentityProvider {
    fn revalidate(&self, target: &pt_common::ProcessIdentity) -> Result<bool, ActionError> {
        ensure_action_pid_namespace()?;
        let pid = target.pid.0;

        // Check if process exists
        let stat_path = format!("/proc/{pid}/stat");
        if !std::path::Path::new(&stat_path).exists() {
            return Ok(false); // Process gone
        }

        // Validate start_id
        if let Some(current_start_id) = self.read_start_id(pid) {
            // start_id format might differ; check starttime portion
            if !ids_match(&target.start_id.0, &current_start_id) {
                return Ok(false); // PID was reused
            }
        } else {
            return Ok(false); // Can't read identity
        }

        // Validate UID
        if let Some(current_uid) = self.read_uid(pid) {
            if current_uid != target.uid {
                return Ok(false); // UID mismatch
            }
        } else {
            return Ok(false); // Can't read UID; identity cannot be confirmed
        }

        Ok(true)
    }
}

/// Live identity provider for macOS: exact start time (microseconds) and uid from
/// `proc_pidinfo`, the same source the scan records in start ids.
#[cfg(target_os = "macos")]
#[derive(Debug, Default)]
pub struct LiveIdentityProvider;

#[cfg(target_os = "macos")]
impl LiveIdentityProvider {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(target_os = "macos")]
impl super::executor::IdentityProvider for LiveIdentityProvider {
    fn revalidate(&self, target: &pt_common::ProcessIdentity) -> Result<bool, ActionError> {
        let pid = target.pid.0;
        let Some(info) = crate::collect::macos::read_bsd_info(pid) else {
            return Ok(false); // gone, or identity cannot be confirmed
        };
        let (_, expected_start, expected_pid) = parse_start_id(&target.start_id.0);
        Ok(expected_start == Some(info.start_us)
            && expected_pid.is_none_or(|p| p == pid)
            && info.uid == target.uid)
    }
}

/// A pidfd (Linux >= 5.3): a file descriptor pinned to one specific process.
/// Signals sent through it can never reach a process that later reuses the PID.
#[cfg(target_os = "linux")]
#[derive(Debug)]
struct PidFd(libc::c_int);

#[cfg(target_os = "linux")]
impl PidFd {
    /// `Ok(None)` when the kernel lacks pidfd support.
    fn open(pid: u32) -> Result<Option<Self>, ActionError> {
        let target = signal_syscall_target(pid, false)?;
        // SAFETY: plain syscall with integer arguments; the returned fd is owned below.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, target as libc::pid_t, 0) };
        if fd >= 0 {
            return Ok(Some(PidFd(fd as libc::c_int)));
        }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::ESRCH) => Err(ActionError::ProcessNotFound),
            Some(libc::ENOSYS) => Ok(None),
            _ => Err(ActionError::Failed(format!("pidfd_open({pid}): {err}"))),
        }
    }

    fn send(&self, signal: i32) -> Result<(), ActionError> {
        // SAFETY: valid owned fd; null siginfo is allowed; flags must be 0.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.0,
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        if rc == 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::ESRCH) => Err(ActionError::ProcessNotFound),
            Some(libc::EPERM) => Err(ActionError::PermissionDenied),
            _ => Err(ActionError::Failed(format!("pidfd_send_signal: {err}"))),
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for PidFd {
    fn drop(&mut self) {
        // SAFETY: we own this fd and close it exactly once.
        unsafe {
            libc::close(self.0);
        }
    }
}

/// Values of a `boot_id:start_ticks:pid` start id that are known (not placeholders).
#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn parse_start_id(id: &str) -> (Option<&str>, Option<u64>, Option<u32>) {
    let parts: Vec<&str> = id.split(':').collect();
    let known = |s: &str| !s.is_empty() && !matches!(s, "unknown" | "synthetic");
    match parts.as_slice() {
        [ticks] => (None, ticks.parse().ok(), None),
        [boot, ticks, pid] => (
            Some(*boot).filter(|b| known(b)),
            ticks.parse().ok(),
            pid.parse().ok(),
        ),
        _ => (None, None, None),
    }
}

/// Check whether a plan's start_id identifies the same process as the live one.
///
/// Both boot ids (when known), pids (when present) and start ticks must agree
/// exactly. Plans record exact /proc start ticks on Linux, so the old +-150-tick
/// tolerance (for ps-estimated ids) only widened the PID-reuse window, and the old
/// check ignored the boot id entirely.
#[cfg(any(target_os = "linux", test))]
fn ids_match(expected: &str, current: &str) -> bool {
    if expected == current {
        return true;
    }
    let (e_boot, e_ticks, e_pid) = parse_start_id(expected);
    let (c_boot, c_ticks, c_pid) = parse_start_id(current);
    if let (Some(a), Some(b)) = (e_boot, c_boot) {
        if a != b {
            return false;
        }
    }
    if let (Some(a), Some(b)) = (e_pid, c_pid) {
        if a != b {
            return false;
        }
    }
    matches!((e_ticks, c_ticks), (Some(a), Some(b)) if a == b)
}

/// Check whether a start_id string matches a raw starttime value (u64).
///
/// Used for lightweight revalidation where we have the numeric starttime
/// from the OS but the original identity stores a composite start_id string.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn ids_match_starttime(start_id: &str, current_starttime: u64) -> bool {
    fn extract_starttime(id: &str) -> Option<u64> {
        let parts: Vec<&str> = id.split(':').collect();
        let st = match parts.len() {
            1 => parts[0],
            3 => parts[1],
            _ => return None,
        };
        st.parse::<u64>().ok()
    }

    // Exact: start ids carry the kernel's start ticks (Linux) or the exact start time in
    // microseconds from proc_pidinfo (macOS); a tolerance only widens PID reuse.
    extract_starttime(start_id) == Some(current_starttime)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_syscall_target_rejects_broadcast_and_init_values() {
        for use_group in [false, true] {
            for invalid in [0, 1, i32::MAX as u32 + 1, u32::MAX] {
                assert!(
                    signal_syscall_target(invalid, use_group).is_err(),
                    "target={invalid}, group={use_group}"
                );
            }
        }

        // A child may have inherited init's process group. Even an explicit
        // group-signaling configuration must not turn that PGID into kill(-1).
        let runner = SignalActionRunner::new(SignalConfig {
            use_process_groups: true,
            ..Default::default()
        });
        let (target, use_group) = runner.resolve_group_target(42, Some(1));
        assert!(use_group);
        assert!(signal_syscall_target(target, use_group).is_err());
    }

    #[test]
    fn signal_syscall_target_preserves_valid_process_and_group_ranges() {
        for id in [2, 3, 42, 65_535, i32::MAX as u32] {
            let process = signal_syscall_target(id, false).unwrap();
            let group = signal_syscall_target(id, true).unwrap();
            assert_eq!(process, id as i32);
            assert_eq!(group, -(id as i32));
            assert!(process >= 2);
            assert!(group <= -2);
        }
    }

    #[test]
    fn graceful_kill_does_not_resume_tracing_stops_or_groups() {
        assert_eq!(
            should_resume_after_sigterm(Some('T'), false),
            cfg!(target_os = "linux")
        );
        assert!(!should_resume_after_sigterm(Some('T'), true));
        for state in [None, Some('t'), Some('R'), Some('S'), Some('Z')] {
            assert!(!should_resume_after_sigterm(state, false), "{state:?}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn action_namespace_validation_rejects_ancestor_procfs_and_unknown_links() {
        use std::path::Path;

        let status = "Name:\tpt-core\nNSpid:\t42\n";
        assert!(validate_procfs_pid_namespace(42, Path::new("42"), status).is_ok());
        let mismatch = validate_procfs_pid_namespace(42, Path::new("9876"), status).unwrap_err();
        assert!(mismatch.to_string().contains("PID namespace differs"));
        for invalid in ["", "0", "-1", "+42", "42/task/42", "/proc/42", "4294967296"] {
            assert!(
                validate_procfs_pid_namespace(42, Path::new(invalid), status).is_err(),
                "{invalid}"
            );
        }
        assert!(validate_procfs_pid_namespace(0, Path::new("42"), status).is_err());
        for status in [
            "",
            "NSpid:\n",
            "NSpid:\t42 42\n",
            "NSpid:\t42 5\n",
            "NSpid:\twrong\n",
            "NSpid:\t42\nNSpid:\t42\n",
        ] {
            assert!(
                validate_procfs_pid_namespace(42, Path::new("42"), status).is_err(),
                "{status}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn live_identity_namespace_refusal_precedes_missing_target_lookup() {
        use super::super::executor::IdentityProvider;
        use pt_common::{ProcessIdentity, StartId};

        // No action is executed and this PID cannot be allocated by Linux. The
        // test runs in both ordinary and ancestor-procfs containers: mismatched
        // procfs must be an explicit namespace error, not a "process gone" result.
        let target = ProcessIdentity::new(u32::MAX, StartId::from_linux("test", 1, u32::MAX), 0);
        let result = LiveIdentityProvider::new().revalidate(&target);
        let proc_pid: u32 = std::fs::read_link("/proc/self")
            .unwrap()
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let namespace_pids: Vec<_> = status
            .lines()
            .find_map(|line| line.strip_prefix("NSpid:"))
            .unwrap()
            .split_whitespace()
            .collect();
        if proc_pid == std::process::id() && namespace_pids.len() == 1 {
            assert!(matches!(result, Ok(false)));
        } else {
            let error =
                result.expect_err("namespace mismatch must refuse before reading target identity");
            assert!(error.to_string().contains("PID namespace"), "{error}");
        }
    }

    #[test]
    fn signal_config_defaults() {
        let config = SignalConfig::default();
        assert_eq!(config.term_grace_ms, 5_000);
        assert_eq!(config.poll_interval_ms, 100);
        assert_eq!(config.verify_timeout_ms, 10_000);
        assert!(!config.use_process_groups);
    }

    #[test]
    fn ids_match_direct() {
        assert!(ids_match("abc:123:456", "abc:123:456"));
    }

    #[test]
    fn ids_match_requires_same_boot_and_pid() {
        // Same ticks after a reboot, or on another pid, is a different process.
        assert!(!ids_match("abc:123:456", "def:123:456"));
        assert!(!ids_match("abc:123:456", "abc:123:789"));
        // Unknown/synthetic boot ids do not veto a match.
        assert!(ids_match("unknown:123:456", "abc:123:456"));
    }

    #[test]
    fn ids_match_different() {
        assert!(!ids_match("abc:123:456", "abc:999:456"));
    }

    #[test]
    fn ids_match_is_exact_on_ticks() {
        // Start ticks come from /proc: any difference means a different process.
        assert!(!ids_match("abc:10000:456", "abc:10001:456"));
        assert!(!ids_match("abc:10000:456", "abc:10150:456"));
        assert!(ids_match("abc:10000:456", "abc:10000:456"));
    }

    /// pidfd-pinned signaling: open a pidfd for a live child, send it a signal and
    /// check the kernel delivered it; after the child is reaped, the same pidfd must
    /// report ESRCH instead of reaching whatever reuses the pid.
    #[cfg(target_os = "linux")]
    #[test]
    fn pidfd_signals_only_the_pinned_process() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep");
        let pid = child.id();
        let Some(fd) = PidFd::open(pid).expect("pidfd_open") else {
            let _ = child.kill();
            let _ = child.wait();
            return; // kernel without pidfd support
        };
        fd.send(libc::SIGTERM).expect("signal via pidfd");
        let status = child.wait().expect("wait child");
        assert!(!status.success(), "child should have died from SIGTERM");
        assert!(matches!(
            fd.send(libc::SIGTERM),
            Err(ActionError::ProcessNotFound)
        ));
    }

    #[cfg(unix)]
    mod unix_tests {
        use super::*;
        use std::process::Command;

        #[test]
        fn runner_can_be_created() {
            let runner = SignalActionRunner::with_defaults();
            assert_eq!(runner.config.term_grace_ms, 5_000);
        }

        #[test]
        fn process_exists_for_self() {
            let runner = SignalActionRunner::with_defaults();
            let pid = std::process::id();
            assert!(runner.process_exists(pid));
        }

        #[test]
        fn process_not_exists_for_invalid() {
            let runner = SignalActionRunner::with_defaults();
            // Very high PID unlikely to exist
            assert!(!runner.process_exists(999_999_999));
        }

        #[test]
        #[cfg(target_os = "linux")]
        fn get_process_state_for_self() {
            let runner = SignalActionRunner::with_defaults();
            let pid = std::process::id();
            let state = runner.get_process_state(pid);
            assert!(state.is_some());
            // Running process should be in R (running) or S (sleeping) state
            let s = state.unwrap();
            assert!(s == 'R' || s == 'S' || s == 'D');
        }

        #[test]
        fn can_pause_and_resume_child() {
            // Spawn a sleep process
            let mut child = Command::new("sleep")
                .arg("60")
                .spawn()
                .expect("failed to spawn sleep");

            let pid = child.id();
            let runner = SignalActionRunner::with_defaults();

            // Pause it
            let pause_result = runner.send_signal(pid, libc::SIGSTOP, false);
            assert!(pause_result.is_ok(), "pause failed: {:?}", pause_result);

            // Verify stopped (on Linux)
            #[cfg(target_os = "linux")]
            {
                std::thread::sleep(Duration::from_millis(100));
                let state = runner.get_process_state(pid);
                assert_eq!(state, Some('T'), "expected stopped state");
            }

            // Resume it
            let resume_result = runner.resume(pid, false, None);
            assert!(resume_result.is_ok(), "resume failed: {:?}", resume_result);

            // Kill and cleanup
            let _ = child.kill();
            let _ = child.wait();
        }

        #[test]
        fn can_kill_child() {
            // Spawn a sleep process
            let mut child = Command::new("sleep")
                .arg("60")
                .spawn()
                .expect("failed to spawn sleep");

            let pid = child.id();
            let runner = SignalActionRunner::new(SignalConfig {
                term_grace_ms: 100, // Short grace for test
                poll_interval_ms: 10,
                verify_timeout_ms: 1_000,
                use_process_groups: false,
            });

            // Kill it (SIGTERM)
            let kill_result = runner.send_signal(pid, libc::SIGTERM, false);
            assert!(kill_result.is_ok(), "kill failed: {:?}", kill_result);

            // Wait for exit
            let status = child.wait().expect("wait failed");
            assert!(!status.success() || status.code().is_none());
        }

        #[test]
        fn delivered_kill_is_retained_after_verification_timeout() {
            let mut child = Command::new("sleep")
                .arg("60")
                .spawn()
                .expect("spawn owned sleep");
            let pid = child.id();
            let runner = SignalActionRunner::new(SignalConfig {
                verify_timeout_ms: 0,
                ..SignalConfig::default()
            });
            assert!(!runner.take_kill_signal_delivered());
            runner.send_signal(pid, libc::SIGTERM, false).unwrap();
            // A zero observation window deliberately cannot certify the effect.
            let observation = runner.wait_for_state_change(pid, true, None, Duration::ZERO);
            assert!(matches!(observation, Err(ActionError::Timeout)));
            child.wait().expect("reap signaled child");
            assert!(runner.take_kill_signal_delivered());
            assert!(!runner.take_kill_signal_delivered());
            // No delivery is credited when the syscall itself refuses a target.
            assert!(runner.send_signal(u32::MAX, libc::SIGTERM, false).is_err());
            assert!(!runner.take_kill_signal_delivered());
        }
    }

    #[cfg(target_os = "linux")]
    mod linux_tests {
        use super::*;
        use crate::action::executor::IdentityProvider;
        use std::os::unix::process::{CommandExt, ExitStatusExt};

        struct OwnedSignalChild(std::process::Child);

        impl Drop for OwnedSignalChild {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        /// The shell stops itself only after installing its handler. Its open
        /// stdin pipe keeps `read` blocked after CONT without any descendant
        /// process or busy loop, including when TERM is deliberately ignored.
        fn stopped_term_child(
            marker: &std::path::Path,
            ignore_term: bool,
            own_group: bool,
        ) -> (OwnedSignalChild, PlanAction) {
            let script = if ignore_term {
                "trap '' TERM\nkill -STOP \"$$\"\nwhile :; do read -r line || exit; done"
            } else {
                "trap 'printf \"term handled\\n\" > \"$1\"; exit 0' TERM\nkill -STOP \"$$\"\nwhile :; do read -r line || exit; done"
            };
            let mut command = std::process::Command::new("sh");
            command
                .arg("-c")
                .arg(script)
                .arg("pt-signal-test")
                .arg(marker)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            if own_group {
                // Any group-directed test signal must stay within this owned
                // child's group, never the test runner's inherited group.
                command.process_group(0);
            }
            let child = OwnedSignalChild(command.spawn().expect("spawn owned TERM handler"));
            let pid = child.0.id();
            SignalActionRunner::with_defaults()
                .wait_for_state_change(pid, false, Some(true), Duration::from_secs(5))
                .expect("child installed TERM handler and stopped");
            let provider = LiveIdentityProvider::new();
            let target = pt_common::ProcessIdentity {
                pid: pt_common::ProcessId(pid),
                start_id: pt_common::StartId(provider.read_start_id(pid).expect("child start ID")),
                uid: provider.read_uid(pid).expect("child UID"),
                pgid: own_group.then_some(pid),
                sid: None,
                quality: pt_common::IdentityQuality::Full,
            };
            let action = serde_json::from_value(serde_json::json!({
                "action_id": "owned-signal-test",
                "target": target,
                "action": "kill",
                "order": 0,
                "stage": 0,
                "timeouts": crate::plan::ActionTimeouts::default(),
                "pre_checks": [],
                "rationale": {},
                "on_success": [],
                "on_failure": [],
                "blocked": false,
            }))
            .expect("valid kill PlanAction");
            (child, action)
        }

        #[test]
        fn stopped_kill_runs_sigterm_handler_before_escalation() {
            let dir = tempfile::tempdir().expect("marker directory");
            let marker = dir.path().join("term-handled");
            let (mut child, action) = stopped_term_child(&marker, false, false);
            let runner = SignalActionRunner::with_defaults();

            runner.execute(&action).expect("terminate stopped child");
            runner.verify(&action).expect("child exited");
            let status = child.0.wait().expect("reap owned child");
            assert!(
                status.success(),
                "TERM handler should exit cleanly: {status}"
            );
            assert_eq!(std::fs::read_to_string(&marker).unwrap(), "term handled\n");
            assert!(runner.take_kill_signal_delivered());
        }

        #[test]
        fn stopped_kill_escalates_when_sigterm_is_ignored() {
            let dir = tempfile::tempdir().expect("marker directory");
            let marker = dir.path().join("term-handled");
            let (mut child, action) = stopped_term_child(&marker, true, false);
            let runner = SignalActionRunner::new(SignalConfig {
                term_grace_ms: 100,
                poll_interval_ms: 10,
                ..SignalConfig::default()
            });

            runner
                .execute(&action)
                .expect("terminate TERM-ignoring child");
            runner
                .verify(&action)
                .expect("child exited after escalation");
            let status = child.0.wait().expect("reap owned child");
            assert_eq!(status.signal(), Some(libc::SIGKILL));
            assert!(!marker.exists());
            assert!(runner.take_kill_signal_delivered());
        }

        #[test]
        fn exhausted_plan_execution_budget_sends_no_signals() {
            let dir = tempfile::tempdir().expect("marker directory");
            let marker = dir.path().join("term-handled");
            let (child, mut action) = stopped_term_child(&marker, false, false);
            let runner = SignalActionRunner::with_defaults();
            action.timeouts.execute_ms = 0;

            for kind in [Action::Kill, Action::Pause, Action::Resume] {
                action.action = kind;
                assert!(matches!(runner.execute(&action), Err(ActionError::Timeout)));
                assert_eq!(runner.get_process_state(child.0.id()), Some('T'));
                assert!(!runner.take_kill_signal_delivered());
                assert!(runner.take_signal_path().is_none());
            }
            assert!(matches!(
                runner.nudge_parent_to_reap(&action),
                Err(ActionError::Timeout)
            ));
            assert!(!marker.exists());
        }

        #[test]
        fn short_plan_budget_never_accelerates_sigkill() {
            for own_group in [false, true] {
                let dir = tempfile::tempdir().expect("marker directory");
                let marker = dir.path().join("term-handled");
                let (mut child, mut action) = stopped_term_child(&marker, true, own_group);
                let runner = SignalActionRunner::new(SignalConfig {
                    term_grace_ms: 5_000,
                    poll_interval_ms: 5_000,
                    use_process_groups: own_group,
                    ..SignalConfig::default()
                });
                action.timeouts.execute_ms = 30;

                let started = Instant::now();
                assert!(matches!(runner.execute(&action), Err(ActionError::Timeout)));
                assert!(
                    started.elapsed() < Duration::from_secs(2),
                    "polling must be bounded by the saved execution budget"
                );
                assert!(child.0.try_wait().unwrap().is_none(), "no early SIGKILL");
                assert_eq!(
                    runner.get_process_state(child.0.id()) == Some('T'),
                    own_group,
                    "only the individually verified process may be resumed"
                );
                assert!(runner.take_kill_signal_delivered(), "TERM still counts");
                assert!(!marker.exists());
            }
        }

        #[test]
        fn short_plan_budget_still_allows_graceful_exit() {
            let dir = tempfile::tempdir().expect("marker directory");
            let marker = dir.path().join("term-handled");
            let (mut child, mut action) = stopped_term_child(&marker, false, false);
            let runner = SignalActionRunner::new(SignalConfig {
                poll_interval_ms: 1,
                ..SignalConfig::default()
            });
            action.timeouts.execute_ms = 1_000;

            runner
                .execute(&action)
                .expect("TERM handler exits in budget");
            runner.verify(&action).expect("observe graceful exit");
            assert!(child.0.wait().unwrap().success());
            assert_eq!(std::fs::read_to_string(&marker).unwrap(), "term handled\n");
            assert!(runner.take_kill_signal_delivered());
        }

        #[test]
        fn verification_honors_plan_budget_and_caps_polling() {
            let dir = tempfile::tempdir().expect("marker directory");
            let marker = dir.path().join("term-handled");
            let (child, mut action) = stopped_term_child(&marker, false, false);
            let runner = SignalActionRunner::new(SignalConfig {
                poll_interval_ms: 5_000,
                ..SignalConfig::default()
            });
            action.timeouts.verify_ms = 25;

            for kind in [Action::Kill, Action::Resume] {
                action.action = kind;
                let started = Instant::now();
                assert!(matches!(runner.verify(&action), Err(ActionError::Timeout)));
                assert!(started.elapsed() < Duration::from_secs(2));
                assert_eq!(runner.get_process_state(child.0.id()), Some('T'));
            }
            action.action = Action::Pause;
            runner
                .verify(&action)
                .expect("observe already stopped child");
            action.timeouts.verify_ms = 0;
            assert!(matches!(runner.verify(&action), Err(ActionError::Timeout)));
            assert!(!runner.take_kill_signal_delivered());
        }

        #[test]
        fn verification_retains_stricter_runner_budget() {
            let dir = tempfile::tempdir().expect("marker directory");
            let marker = dir.path().join("term-handled");
            let (_child, mut action) = stopped_term_child(&marker, false, false);
            let runner = SignalActionRunner::new(SignalConfig {
                verify_timeout_ms: 25,
                poll_interval_ms: 5_000,
                ..SignalConfig::default()
            });
            action.timeouts.verify_ms = u64::MAX;

            let started = Instant::now();
            assert!(matches!(runner.verify(&action), Err(ActionError::Timeout)));
            assert!(started.elapsed() < Duration::from_secs(2));
        }

        #[test]
        fn stopped_kill_does_not_resume_an_unverified_process_group() {
            let dir = tempfile::tempdir().expect("marker directory");
            let marker = dir.path().join("term-handled");
            let (mut child, action) = stopped_term_child(&marker, false, true);
            let runner = SignalActionRunner::new(SignalConfig {
                term_grace_ms: 100,
                poll_interval_ms: 10,
                use_process_groups: true,
                ..SignalConfig::default()
            });

            runner.execute(&action).expect("terminate owned group");
            runner.verify(&action).expect("group leader exited");
            assert_eq!(child.0.wait().unwrap().signal(), Some(libc::SIGKILL));
            assert!(
                !marker.exists(),
                "a leader's state must not authorize group CONT"
            );
        }

        #[test]
        fn stopped_kill_does_not_signal_a_changed_identity() {
            let dir = tempfile::tempdir().expect("marker directory");
            let marker = dir.path().join("term-handled");
            let (child, mut action) = stopped_term_child(&marker, false, false);
            let runner = SignalActionRunner::with_defaults();
            let pid = child.0.id();
            let other_start = runner.read_starttime(pid).unwrap() + 1;
            action.target.start_id = pt_common::StartId(format!("unknown:{other_start}:{pid}"));

            assert!(matches!(
                runner.execute(&action),
                Err(ActionError::IdentityMismatch)
            ));
            assert_eq!(runner.get_process_state(pid), Some('T'));
            assert!(!runner.take_kill_signal_delivered());
            assert!(!marker.exists());
        }

        #[test]
        fn live_identity_provider_validates_self() {
            let provider = LiveIdentityProvider::new();
            let pid = std::process::id();

            // Get our start_id
            let start_id = provider.read_start_id(pid).expect("read start_id");
            let uid = provider.read_uid(pid).expect("read uid");

            let identity = pt_common::ProcessIdentity {
                pid: pt_common::ProcessId(pid),
                start_id: pt_common::StartId(start_id),
                uid,
                pgid: None,
                sid: None,
                quality: pt_common::IdentityQuality::Full,
            };

            let valid = provider.revalidate(&identity).expect("revalidate");
            assert!(valid, "self should validate");
        }

        #[test]
        fn live_identity_provider_rejects_wrong_uid() {
            let provider = LiveIdentityProvider::new();
            let pid = std::process::id();

            let start_id = provider.read_start_id(pid).expect("read start_id");
            let uid = provider.read_uid(pid).expect("read uid");

            let identity = pt_common::ProcessIdentity {
                pid: pt_common::ProcessId(pid),
                start_id: pt_common::StartId(start_id),
                uid: uid + 1, // Wrong UID
                pgid: None,
                sid: None,
                quality: pt_common::IdentityQuality::Full,
            };

            let valid = provider.revalidate(&identity).expect("revalidate");
            assert!(!valid, "wrong uid should not validate");
        }

        #[test]
        fn live_identity_provider_rejects_nonexistent() {
            let provider = LiveIdentityProvider::new();

            let identity = pt_common::ProcessIdentity {
                pid: pt_common::ProcessId(999_999_999),
                start_id: pt_common::StartId("fake".to_string()),
                uid: 1000,
                pgid: None,
                sid: None,
                quality: pt_common::IdentityQuality::Full,
            };

            let valid = provider.revalidate(&identity).expect("revalidate");
            assert!(!valid, "nonexistent should not validate");
        }

        #[test]
        fn test_zombie_detection() {
            use std::process::Command;

            struct OwnedChild(std::process::Child);
            impl Drop for OwnedChild {
                fn drop(&mut self) {
                    let _ = self.0.wait();
                }
            }
            // Spawn a process that exits immediately
            // It will become a zombie because we hold the handle and don't wait() yet
            let mut child = OwnedChild(Command::new("true").spawn().expect("failed to spawn true"));

            let pid = child.0.id();
            let runner = SignalActionRunner::with_defaults();

            // Observe this owned child's actual exit without reaping it. Fixture
            // startup is not a signal-runner latency measurement; the original
            // 500 ms effect-verification deadline below remains unchanged.
            // SAFETY: siginfo_t is a C integer/union record with a valid zero
            // representation. waitid fills its child-status fields on success.
            let mut exit_info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            loop {
                // SAFETY: pid is our still-unreaped direct child. WNOWAIT leaves
                // the exited child available for the real /proc and runner checks.
                let result = unsafe {
                    libc::waitid(
                        libc::P_PID,
                        pid,
                        &mut exit_info,
                        libc::WEXITED | libc::WNOWAIT,
                    )
                };
                if result == 0 {
                    break;
                }
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::Interrupted {
                    let _ = child.0.wait();
                    panic!("observe owned child exit without reaping: {error}");
                }
            }
            // SAFETY: successful WEXITED waitid initialized child-status fields.
            assert_eq!(unsafe { exit_info.si_pid() }, pid as libc::pid_t);
            assert_eq!(exit_info.si_code, libc::CLD_EXITED);
            // SAFETY: CLD_EXITED makes si_status the child's actual exit status.
            assert_eq!(unsafe { exit_info.si_status() }, 0);
            assert_eq!(runner.get_process_state(pid), Some('Z'));
            assert!(runner.process_exists(pid), "owned zombie still exists");

            // Verify wait_for_state_change considers it exited
            // Without the fix, this would timeout because process_exists() is true for zombies
            let result = runner.wait_for_state_change(
                pid,
                true, // expect_exit
                None,
                Duration::from_millis(500),
            );

            assert!(result.is_ok(), "Zombie should be considered exited");

            // Cleanup
            assert!(child.0.wait().expect("reap the owned zombie").success());
        }
    }
}
