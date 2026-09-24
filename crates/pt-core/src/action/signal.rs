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

/// Signal action runner configuration.
#[derive(Debug, Clone)]
pub struct SignalConfig {
    /// Grace period after SIGTERM before escalating to SIGKILL.
    pub term_grace_ms: u64,
    /// Polling interval when waiting for process to exit.
    pub poll_interval_ms: u64,
    /// Maximum time to wait for process state change after signal.
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
}

impl SignalActionRunner {
    pub fn new(config: SignalConfig) -> Self {
        Self { config }
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
        if target_id > i32::MAX as u32 {
            return Err(ActionError::Failed(format!(
                "PID {} exceeds i32 range",
                target_id
            )));
        }

        let target_pid = if use_group {
            -(target_id as i32) // Negative PID targets process group
        } else {
            target_id as i32
        };

        let result = unsafe { libc::kill(target_pid, signal) };
        if result == 0 {
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

    #[cfg(target_os = "macos")]
    fn read_starttime(&self, pid: u32) -> Option<u64> {
        crate::collect::read_process_snapshot(pid).map(|info| info.start_time_unix)
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
        let poll_interval = Duration::from_millis(self.config.poll_interval_ms);

        while start.elapsed() < timeout {
            if expect_exit {
                if !self.process_exists(pid) {
                    return Ok(());
                }
                // On Linux, consider a zombie process as "exited" for our purposes
                // (we successfully terminated it, even if parent hasn't reaped it)
                #[cfg(target_os = "linux")]
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

            thread::sleep(poll_interval);
        }

        Err(ActionError::Timeout)
    }

    /// Execute a pause action (SIGSTOP).
    #[cfg(unix)]
    fn execute_pause(&self, action: &PlanAction) -> Result<(), ActionError> {
        let pid = action.target.pid.0;
        let (target, use_group) = self.resolve_group_target(pid, action.target.pgid);

        #[cfg(target_os = "linux")]
        if !use_group {
            if let Some(pidfd) = self.pinned_pidfd(action)? {
                return pidfd.send(libc::SIGSTOP);
            }
        }
        self.send_signal(target, libc::SIGSTOP, use_group)?;
        Ok(())
    }

    /// Execute a kill action (SIGTERM → SIGKILL).
    #[cfg(unix)]
    fn execute_kill(&self, action: &PlanAction) -> Result<(), ActionError> {
        let pid = action.target.pid.0;
        let (target, use_group) = self.resolve_group_target(pid, action.target.pgid);

        // Linux: SIGTERM and the SIGKILL escalation both go through one pidfd pinned
        // to the verified process, closing the PID-reuse window completely.
        #[cfg(target_os = "linux")]
        if !use_group {
            if let Some(pidfd) = self.pinned_pidfd(action)? {
                pidfd.send(libc::SIGTERM)?;
                let grace = Duration::from_millis(self.config.term_grace_ms);
                return match self.wait_for_state_change(pid, true, None, grace) {
                    Ok(()) => Ok(()),
                    Err(ActionError::Timeout) => match pidfd.send(libc::SIGKILL) {
                        // Exited between the grace timeout and SIGKILL: done.
                        Err(ActionError::ProcessNotFound) => Ok(()),
                        other => other,
                    },
                    Err(e) => Err(e),
                };
            }
        }

        // Stage 1: SIGTERM
        self.send_signal(target, libc::SIGTERM, use_group)?;

        // Wait for graceful termination
        let grace = Duration::from_millis(self.config.term_grace_ms);
        match self.wait_for_state_change(pid, true, None, grace) {
            Ok(()) => return Ok(()),
            Err(ActionError::Timeout) => {
                // Escalate to SIGKILL
            }
            Err(e) => return Err(e),
        }

        // Stage 2: SIGKILL (only if process still exists)
        // TOCTOU window: the process may have exited and its PID may have been
        // reused between the grace-period timeout and the SIGKILL below.
        // Re-validate the starttime to guard against killing a replacement process.
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if self.process_exists(pid) {
            if let Some(current_starttime) = self.read_starttime(pid) {
                let start_id = &action.target.start_id.0;
                if !ids_match_starttime(start_id, current_starttime) {
                    return Err(ActionError::IdentityMismatch);
                }
            }
            // If we can't read starttime, the process is likely gone — SIGKILL
            // will harmlessly fail with ESRCH.
        }

        if self.process_exists(pid) {
            self.send_signal(target, libc::SIGKILL, use_group)?;
        }

        Ok(())
    }

    /// Verify a pause action succeeded.
    #[cfg(unix)]
    fn verify_pause(&self, action: &PlanAction) -> Result<(), ActionError> {
        let pid = action.target.pid.0;
        let timeout = Duration::from_millis(self.config.verify_timeout_ms);
        self.wait_for_state_change(pid, false, Some(true), timeout)
    }

    /// Verify a kill action succeeded.
    #[cfg(unix)]
    fn verify_kill(&self, action: &PlanAction) -> Result<(), ActionError> {
        let pid = action.target.pid.0;
        let timeout = Duration::from_millis(self.config.verify_timeout_ms);
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
        let pid = action.target.pid.0;
        let (target, use_group) = self.resolve_group_target(pid, action.target.pgid);

        self.send_signal(target, libc::SIGCONT, use_group)?;
        Ok(())
    }

    /// Verify a resume action succeeded.
    #[cfg(unix)]
    fn verify_resume(&self, action: &PlanAction) -> Result<(), ActionError> {
        let pid = action.target.pid.0;
        let timeout = Duration::from_millis(self.config.verify_timeout_ms);
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

/// A pidfd (Linux >= 5.3): a file descriptor pinned to one specific process.
/// Signals sent through it can never reach a process that later reuses the PID.
#[cfg(target_os = "linux")]
#[derive(Debug)]
struct PidFd(libc::c_int);

#[cfg(target_os = "linux")]
impl PidFd {
    /// `Ok(None)` when the kernel lacks pidfd support.
    fn open(pid: u32) -> Result<Option<Self>, ActionError> {
        // SAFETY: plain syscall with integer arguments; the returned fd is owned below.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
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

    if let Some(expected) = extract_starttime(start_id) {
        #[cfg(target_os = "linux")]
        {
            // Exact: plan start ids carry the kernel's start ticks (see ids_match).
            expected == current_starttime
        }
        #[cfg(target_os = "macos")]
        {
            // macOS starttime is in seconds - allow 2s jitter
            expected.abs_diff(current_starttime) <= 2
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            expected == current_starttime
        }
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    }

    #[cfg(target_os = "linux")]
    mod linux_tests {
        use super::*;
        use crate::action::executor::IdentityProvider;

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

            // Spawn a process that exits immediately
            // It will become a zombie because we hold the handle and don't wait() yet
            let mut child = Command::new("true").spawn().expect("failed to spawn true");

            let pid = child.id();
            let runner = SignalActionRunner::with_defaults();

            // Wait for it to become a zombie
            let start = Instant::now();
            loop {
                if start.elapsed() > Duration::from_secs(2) {
                    // Fallback cleanup if it never becomes Z (unlikely)
                    let _ = child.wait();
                    panic!("Process did not become zombie in time");
                }
                if let Some('Z') = runner.get_process_state(pid) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }

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
            let _ = child.wait();
        }
    }
}
