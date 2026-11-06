//! Cgroup v2 freeze/unfreeze action execution.
//!
//! Implements process freezing using cgroup v2 freezer with:
//! - TOCTOU safety via identity revalidation
//! - Bounded verification of completed transitions via cgroup.events
//! - Support for same-cgroup blast radius control
//!
//! The cgroup freezer is more robust than SIGSTOP because:
//! - Works at cgroup level (entire process tree)
//! - No userspace signal handler required
//! - Cleaner state management via cgroup.events

use super::executor::{ActionError, ActionRunner};
use crate::collect::cgroup::{collect_cgroup_details, CgroupVersion};
use crate::decision::Action;
use crate::plan::PlanAction;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};
use tracing::{debug, trace};

/// Freeze action runner configuration.
#[derive(Debug, Clone)]
pub struct FreezeConfig {
    /// Whether to verify cgroup v2 availability before executing.
    pub verify_capability: bool,
    /// Maximum time in milliseconds to wait for a completed freezer transition.
    /// The action's verification timeout may impose a shorter deadline.
    pub propagation_timeout_ms: u64,
}

impl Default for FreezeConfig {
    fn default() -> Self {
        Self {
            verify_capability: true,
            propagation_timeout_ms: 100,
        }
    }
}

/// Freeze action runner using cgroup v2 freezer.
#[derive(Debug)]
pub struct FreezeActionRunner {
    config: FreezeConfig,
}

impl FreezeActionRunner {
    pub fn new(config: FreezeConfig) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(FreezeConfig::default())
    }

    /// Write freeze state to cgroup.freeze.
    ///
    /// `frozen=true` freezes the cgroup, `frozen=false` unfreezes it.
    fn write_freeze_state(&self, freeze_path: &str, frozen: bool) -> Result<(), ActionError> {
        let value = if frozen { "1" } else { "0" };

        trace!(path = freeze_path, value = value, "writing freeze state");

        fs::write(freeze_path, value).map_err(|e| match e.kind() {
            std::io::ErrorKind::PermissionDenied => ActionError::PermissionDenied,
            _ => ActionError::Failed(format!("cannot write {}: {}", freeze_path, e)),
        })
    }

    /// Execute a freeze action.
    #[cfg(target_os = "linux")]
    fn execute_freeze(&self, action: &PlanAction) -> Result<(), ActionError> {
        let pid = action.target.pid.0;
        let checked_path = super::dispatch::ensure_cgroup_target(&action.target)?;
        debug!(pid = pid, "executing freeze");

        let freeze_path = format!("/sys/fs/cgroup{checked_path}/cgroup.freeze");
        self.write_freeze_state(&freeze_path, true)
    }

    /// Execute an unfreeze action.
    #[cfg(target_os = "linux")]
    fn execute_unfreeze(&self, action: &PlanAction) -> Result<(), ActionError> {
        let pid = action.target.pid.0;
        let checked_path = super::dispatch::ensure_cgroup_target(&action.target)?;
        debug!(pid = pid, "executing unfreeze");

        let freeze_path = format!("/sys/fs/cgroup{checked_path}/cgroup.freeze");
        self.write_freeze_state(&freeze_path, false)
    }

    /// Verify a freeze action succeeded.
    #[cfg(target_os = "linux")]
    fn verify_freeze(&self, action: &PlanAction) -> Result<(), ActionError> {
        self.verify_frozen_state(action, true)
    }

    /// Verify an unfreeze action succeeded.
    #[cfg(target_os = "linux")]
    fn verify_unfreeze(&self, action: &PlanAction) -> Result<(), ActionError> {
        self.verify_frozen_state(action, false)
    }

    #[cfg(target_os = "linux")]
    fn verify_frozen_state(&self, action: &PlanAction, frozen: bool) -> Result<(), ActionError> {
        let pid = action.target.pid.0;
        let checked_path = super::dispatch::ensure_cgroup_target(&action.target)?;
        let events_path = format!("/sys/fs/cgroup{checked_path}/cgroup.events");
        let timeout = Duration::from_millis(
            self.config
                .propagation_timeout_ms
                .min(action.timeouts.verify_ms),
        );

        // cgroup.freeze records the request. Only cgroup.events reports that
        // freezing has completed, or that an ancestor no longer keeps it frozen.
        wait_for_frozen_state(Path::new(&events_path), frozen, timeout)?;

        // Waiting opens another identity/membership race. Recheck the complete
        // guard and require the target to remain in the cgroup we just observed.
        if super::dispatch::ensure_cgroup_target(&action.target)? != checked_path {
            return Err(ActionError::Failed(
                "cannot verify freezer transition after cgroup membership changed".to_string(),
            ));
        }

        debug!(pid, frozen, "freezer transition verified");
        Ok(())
    }
}

/// Read the completed state, refusing missing, ambiguous, or malformed evidence.
fn parse_frozen_event(content: &str) -> Result<bool, ActionError> {
    let mut frozen = None;
    for line in content.lines() {
        let mut fields = line.split_whitespace();
        if fields.next() != Some("frozen") {
            continue;
        }
        let state = match (fields.next(), fields.next()) {
            (Some("0"), None) => false,
            (Some("1"), None) => true,
            _ => {
                return Err(ActionError::Failed(
                    "malformed frozen field in cgroup.events".to_string(),
                ));
            }
        };
        if frozen.replace(state).is_some() {
            return Err(ActionError::Failed(
                "duplicate frozen field in cgroup.events".to_string(),
            ));
        }
    }
    frozen.ok_or_else(|| ActionError::Failed("missing frozen field in cgroup.events".to_string()))
}

fn read_frozen_event(events_path: &Path) -> Result<bool, ActionError> {
    let content = fs::read_to_string(events_path).map_err(|error| {
        ActionError::Failed(format!("cannot read {}: {error}", events_path.display()))
    })?;
    parse_frozen_event(&content)
}

/// Observe immediately, then poll without sleeping beyond the remaining budget.
/// A zero timeout permits one observation but never waits for a transition.
fn wait_for_frozen_state(
    events_path: &Path,
    frozen: bool,
    timeout: Duration,
) -> Result<(), ActionError> {
    let started = Instant::now();
    loop {
        if read_frozen_event(events_path)? == frozen {
            return Ok(());
        }
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(ActionError::Timeout);
        }
        std::thread::sleep(remaining.min(Duration::from_millis(10)));
        if started.elapsed() >= timeout {
            return Err(ActionError::Timeout);
        }
    }
}

#[cfg(target_os = "linux")]
impl ActionRunner for FreezeActionRunner {
    fn execute(&self, action: &PlanAction) -> Result<(), ActionError> {
        match action.action {
            Action::Freeze => self.execute_freeze(action),
            Action::Unfreeze => self.execute_unfreeze(action),
            Action::Keep => Ok(()),
            Action::Pause
            | Action::Resume
            | Action::Kill
            | Action::Throttle
            | Action::Restart
            | Action::Renice
            | Action::Quarantine
            | Action::Unquarantine => Err(ActionError::Failed(format!(
                "{:?} requires signal/setpriority support, not cgroup freeze",
                action.action
            ))),
        }
    }

    fn verify(&self, action: &PlanAction) -> Result<(), ActionError> {
        match action.action {
            Action::Freeze => self.verify_freeze(action),
            Action::Unfreeze => self.verify_unfreeze(action),
            Action::Keep => Ok(()),
            Action::Pause
            | Action::Resume
            | Action::Kill
            | Action::Throttle
            | Action::Restart
            | Action::Renice
            | Action::Quarantine
            | Action::Unquarantine => Ok(()),
        }
    }
}

#[cfg(not(target_os = "linux"))]
impl ActionRunner for FreezeActionRunner {
    fn execute(&self, _action: &PlanAction) -> Result<(), ActionError> {
        Err(ActionError::Failed(
            "cgroup freeze not supported on this platform".to_string(),
        ))
    }

    fn verify(&self, _action: &PlanAction) -> Result<(), ActionError> {
        Err(ActionError::Failed(
            "cgroup freeze not supported on this platform".to_string(),
        ))
    }
}

/// Check if cgroup v2 freeze is available for a process.
///
/// Returns `true` when the target passes the direct runner's safety checks and
/// its cgroup supports the freezer. Write permission is checked at execution.
#[cfg(target_os = "linux")]
pub fn is_freeze_available(pid: u32) -> bool {
    let Some(identity) = super::dispatch::read_cgroup_identity(pid) else {
        return false;
    };
    if super::dispatch::ensure_cgroup_target(&identity).is_err() {
        return false;
    }
    let details = match collect_cgroup_details(pid) {
        Some(d) => d,
        None => return false,
    };

    // Require cgroup v2
    if details.version != CgroupVersion::V2 && details.version != CgroupVersion::Hybrid {
        return false;
    }

    // Check for unified path and freeze file
    if let Some(ref unified_path) = details.unified_path {
        let freeze_path = format!("/sys/fs/cgroup{}/cgroup.freeze", unified_path);
        Path::new(&freeze_path).exists()
    } else {
        false
    }
}

#[cfg(not(target_os = "linux"))]
pub fn is_freeze_available(_pid: u32) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn freeze_config_defaults() {
        let config = FreezeConfig::default();
        assert!(config.verify_capability);
        assert_eq!(config.propagation_timeout_ms, 100);
    }

    #[test]
    fn runner_can_be_created() {
        let runner = FreezeActionRunner::with_defaults();
        assert!(runner.config.verify_capability);
    }

    #[test]
    fn frozen_event_accepts_completed_states_and_other_fields() {
        assert!(parse_frozen_event("populated 1\nfrozen 1\n").unwrap());
        assert!(!parse_frozen_event("frozen\t0\npopulated 1\nfuture_event 2\n").unwrap());
    }

    #[test]
    fn frozen_event_rejects_missing_malformed_and_duplicate_fields() {
        for content in [
            "",
            "populated 1\n",
            "frozen\n",
            "frozen 2\n",
            "frozen true\n",
            "frozen 01\n",
            "frozen 1 extra\n",
            "frozen 0\nfrozen 1\n",
            "frozen 1\nfrozen 1\n",
        ] {
            assert!(
                matches!(parse_frozen_event(content), Err(ActionError::Failed(_))),
                "invalid freezer evidence accepted: {content:?}"
            );
        }
    }

    #[test]
    fn freezer_request_does_not_prove_transition_completion() {
        let dir = tempfile::tempdir().unwrap();
        let freeze_path = dir.path().join("cgroup.freeze");
        let events_path = dir.path().join("cgroup.events");
        for (request, events, expected) in [
            ("1\n", "populated 1\nfrozen 0\n", true),
            ("0\n", "populated 1\nfrozen 1\n", false),
        ] {
            // A completed write only records intent. In particular an ancestor
            // may keep the target frozen after its own freeze request is cleared.
            fs::write(&freeze_path, request).unwrap();
            fs::write(&events_path, events).unwrap();
            assert!(matches!(
                wait_for_frozen_state(&events_path, expected, Duration::ZERO),
                Err(ActionError::Timeout)
            ));
        }
    }

    #[test]
    fn freezer_completion_is_observed_without_a_fixed_delay() {
        let dir = tempfile::tempdir().unwrap();
        let events_path = dir.path().join("cgroup.events");
        for frozen in [true, false] {
            fs::write(
                &events_path,
                format!("populated 1\nfrozen {}\n", u8::from(frozen)),
            )
            .unwrap();
            assert!(wait_for_frozen_state(&events_path, frozen, Duration::ZERO).is_ok());
        }
    }

    #[test]
    fn freezer_completion_polls_until_each_transition() {
        let dir = tempfile::tempdir().unwrap();
        let events_path = dir.path().join("cgroup.events");
        let transition_delay = Duration::from_millis(20);
        for frozen in [true, false] {
            fs::write(
                &events_path,
                format!("populated 1\nfrozen {}\n", u8::from(!frozen)),
            )
            .unwrap();
            let pending_path = dir.path().join("completed.events");
            fs::write(
                &pending_path,
                format!("populated 1\nfrozen {}\n", u8::from(frozen)),
            )
            .unwrap();
            let destination = events_path.clone();
            let started = Instant::now();
            let writer = std::thread::spawn(move || {
                std::thread::sleep(transition_delay);
                // Replace the complete fixture atomically; readers must never
                // accept a truncated frozen field as evidence of completion.
                fs::rename(pending_path, destination).unwrap();
            });
            let result = wait_for_frozen_state(&events_path, frozen, Duration::from_secs(2));
            let elapsed = started.elapsed();
            writer.join().unwrap();
            assert!(result.is_ok(), "transition not observed: {result:?}");
            assert!(
                elapsed >= transition_delay,
                "returned before the transition"
            );
        }
    }

    #[test]
    fn freezer_completion_times_out_while_still_pending() {
        let dir = tempfile::tempdir().unwrap();
        let events_path = dir.path().join("cgroup.events");
        fs::write(&events_path, "populated 1\nfrozen 0\n").unwrap();
        let timeout = Duration::from_millis(5);
        let started = Instant::now();
        assert!(matches!(
            wait_for_frozen_state(&events_path, true, timeout),
            Err(ActionError::Timeout)
        ));
        assert!(started.elapsed() >= timeout);
    }

    #[test]
    fn freezer_completion_fails_closed_on_unavailable_or_invalid_events() {
        let dir = tempfile::tempdir().unwrap();
        let events_path = dir.path().join("cgroup.events");
        for path in [events_path.as_path(), dir.path()] {
            assert!(matches!(
                wait_for_frozen_state(path, false, Duration::ZERO),
                Err(ActionError::Failed(_))
            ));
        }
        for content in ["populated 1\n", "frozen 0 extra\n", "frozen 1\nfrozen 0\n"] {
            fs::write(&events_path, content).unwrap();
            assert!(matches!(
                wait_for_frozen_state(&events_path, false, Duration::ZERO),
                Err(ActionError::Failed(_))
            ));
        }
    }

    #[cfg(target_os = "linux")]
    mod linux_tests {
        use super::*;

        #[test]
        fn check_freeze_availability_for_self() {
            let pid = std::process::id();
            // This will be true on modern Linux with cgroup v2
            let available = is_freeze_available(pid);
            crate::test_log!(
                INFO,
                "freeze availability check",
                pid = pid,
                available = available
            );
            // Don't assert - availability depends on system configuration
        }

        #[test]
        fn read_frozen_event_for_self() {
            let pid = std::process::id();
            if let Some(path) = collect_cgroup_details(pid).and_then(|details| details.unified_path)
            {
                let events_path = format!("/sys/fs/cgroup{path}/cgroup.events");
                match read_frozen_event(Path::new(&events_path)) {
                    Ok(frozen) => {
                        crate::test_log!(INFO, "freeze state read", pid = pid, frozen = frozen);
                        // Our test process should not be frozen
                        assert!(!frozen, "test process should not be frozen");
                    }
                    Err(e) => {
                        crate::test_log!(
                            INFO,
                            "cannot read completed freezer state",
                            error = e.to_string().as_str()
                        );
                    }
                }
            }
        }
    }
}
