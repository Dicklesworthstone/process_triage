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

    /// Send a signal to a process.
    #[cfg(unix)]
    fn send_signal(&self, pid: u32, signal: i32, use_group: bool) -> Result<(), ActionError> {
        let target_pid = if use_group {
            -(pid as i32) // Negative PID targets process group
        } else {
            pid as i32
        };

        let result = unsafe { libc::kill(target_pid, signal) };
        if result == 0 {
            return Ok(());
        }

        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::ESRCH) => Err(ActionError::Failed("process not found".to_string())),
            Some(libc::EPERM) => Err(ActionError::PermissionDenied),
            Some(libc::EINVAL) => Err(ActionError::Failed("invalid signal".to_string())),
            _ => Err(ActionError::Failed(err.to_string())),
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

    /// Get process state from /proc/[pid]/stat.
    #[cfg(target_os = "linux")]
    fn get_process_state(&self, pid: u32) -> Option<char> {
        let stat_path = format!("/proc/{pid}/stat");
        let content = std::fs::read_to_string(stat_path).ok()?;
        // Format: pid (comm) state ...
        let comm_end = content.rfind(')')?;
        let after_comm = content.get(comm_end + 2..)?;
        after_comm.chars().next()
    }

    #[cfg(not(target_os = "linux"))]
    fn get_process_state(&self, _pid: u32) -> Option<char> {
        None
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

        self.send_signal(target, libc::SIGSTOP, use_group)?;
        Ok(())
    }

    /// Execute a kill action (SIGTERM → SIGKILL).
    #[cfg(unix)]
    fn execute_kill(&self, action: &PlanAction) -> Result<(), ActionError> {
        let pid = action.target.pid.0;
        let (target, use_group) = self.resolve_group_target(pid, action.target.pgid);

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
        let content = std::fs::read_to_string(&stat_path).ok()?;
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
        let content = std::fs::read_to_string(&status_path).ok()?;
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
        }

        Ok(true)
    }
}

/// Check if two start_ids match (handle format variations).
fn ids_match(expected: &str, current: &str) -> bool {
    // Direct match
    if expected == current {
        return true;
    }

    // Extract starttime portion and compare
    // Format may be: "boot_id:starttime:pid" or just "starttime" or "boot:starttime:pid"
    fn extract_starttime(id: &str) -> Option<&str> {
        let parts: Vec<&str> = id.split(':').collect();
        match parts.len() {
            1 => Some(parts[0]),
            3 => Some(parts[1]),
            _ => None,
        }
    }

    match (extract_starttime(expected), extract_starttime(current)) {
        (Some(e), Some(c)) => {
            // Try integer comparison with fuzzy window (to handle ps rounding)
            if let (Ok(e_ticks), Ok(c_ticks)) = (e.parse::<u64>(), c.parse::<u64>()) {
                // If diff is within 1 second (100Hz = 100 ticks), treat as match
                // We use 150 to be safe against rounding + small drift
                let diff = e_ticks.abs_diff(c_ticks);
                if diff <= 150 {
                    return true;
                }
            }
            // Fallback to exact string match
            e == c
        }
        _ => false,
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
    fn ids_match_starttime_only() {
        assert!(ids_match("abc:123:456", "def:123:789"));
    }

    #[test]
    fn ids_match_different() {
        assert!(!ids_match("abc:123:456", "abc:999:456"));
    }

    #[test]
    fn ids_match_fuzzy() {
        // Within 1 second (100 ticks)
        assert!(ids_match("abc:10000:456", "abc:10050:456"));
        // Within 1.5 seconds (150 ticks)
        assert!(ids_match("abc:10000:456", "abc:10150:456"));
        // Too far (200 ticks)
        assert!(!ids_match("abc:10000:456", "abc:10200:456"));
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
