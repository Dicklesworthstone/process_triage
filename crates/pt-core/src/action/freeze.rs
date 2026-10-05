//! Cgroup v2 freeze/unfreeze action execution.
//!
//! Implements process freezing using cgroup v2 freezer with:
//! - TOCTOU safety via identity revalidation
//! - Verification via cgroup.freeze state readback
//! - Support for same-cgroup blast radius control
//!
//! The cgroup freezer is more robust than SIGSTOP because:
//! - Works at cgroup level (entire process tree)
//! - No signal delivery required (works on D-state processes)
//! - Cleaner state management via cgroup.events

use super::executor::{ActionError, ActionRunner};
use crate::collect::cgroup::{collect_cgroup_details, CgroupVersion};
use crate::decision::Action;
use crate::plan::PlanAction;
use std::fs;
use std::path::Path;
use tracing::{debug, trace};

/// Freeze action runner configuration.
#[derive(Debug, Clone)]
pub struct FreezeConfig {
    /// Whether to verify cgroup v2 availability before executing.
    pub verify_capability: bool,
    /// Timeout in milliseconds for freeze state to propagate.
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

    /// Get the cgroup freeze file path for a process.
    ///
    /// Returns the path to `/sys/fs/cgroup{unified_path}/cgroup.freeze`
    /// if the process is in a cgroup v2 hierarchy.
    fn get_freeze_path(&self, pid: u32) -> Result<String, ActionError> {
        let details = collect_cgroup_details(pid)
            .ok_or_else(|| ActionError::Failed(format!("cannot read cgroup for PID {pid}")))?;

        // Require cgroup v2 (unified hierarchy)
        if details.version != CgroupVersion::V2 && details.version != CgroupVersion::Hybrid {
            return Err(ActionError::Failed(format!(
                "cgroup freeze requires v2, got {:?}",
                details.version
            )));
        }

        let unified_path = details
            .unified_path
            .ok_or_else(|| ActionError::Failed("no unified cgroup path found".to_string()))?;

        let freeze_path = format!("/sys/fs/cgroup{}/cgroup.freeze", unified_path);

        // Verify the freeze file exists
        if !Path::new(&freeze_path).exists() {
            return Err(ActionError::Failed(format!(
                "cgroup.freeze not found at {}",
                freeze_path
            )));
        }

        Ok(freeze_path)
    }

    /// Read the current freeze state from cgroup.freeze.
    ///
    /// Returns `true` if frozen, `false` if running.
    fn read_freeze_state(&self, freeze_path: &str) -> Result<bool, ActionError> {
        let content = fs::read_to_string(freeze_path)
            .map_err(|e| ActionError::Failed(format!("cannot read {}: {}", freeze_path, e)))?;

        match content.trim() {
            "1" => Ok(true),
            "0" => Ok(false),
            other => Err(ActionError::Failed(format!(
                "unexpected cgroup.freeze value: '{}'",
                other
            ))),
        }
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
        super::dispatch::ensure_exclusive_cgroup(pid)?;
        debug!(pid = pid, "executing freeze");

        let freeze_path = self.get_freeze_path(pid)?;
        self.write_freeze_state(&freeze_path, true)
    }

    /// Execute an unfreeze action.
    #[cfg(target_os = "linux")]
    fn execute_unfreeze(&self, action: &PlanAction) -> Result<(), ActionError> {
        let pid = action.target.pid.0;
        super::dispatch::ensure_exclusive_cgroup(pid)?;
        debug!(pid = pid, "executing unfreeze");

        let freeze_path = self.get_freeze_path(pid)?;
        self.write_freeze_state(&freeze_path, false)
    }

    /// Verify a freeze action succeeded.
    #[cfg(target_os = "linux")]
    fn verify_freeze(&self, action: &PlanAction) -> Result<(), ActionError> {
        let pid = action.target.pid.0;

        // Give it a moment for the freeze state to propagate
        std::thread::sleep(std::time::Duration::from_millis(
            self.config.propagation_timeout_ms,
        ));

        let freeze_path = self.get_freeze_path(pid)?;
        let is_frozen = self.read_freeze_state(&freeze_path)?;

        if is_frozen {
            debug!(pid = pid, "freeze verified");
            Ok(())
        } else {
            Err(ActionError::Failed(format!(
                "process {} not frozen after freeze action",
                pid
            )))
        }
    }

    /// Verify an unfreeze action succeeded.
    #[cfg(target_os = "linux")]
    fn verify_unfreeze(&self, action: &PlanAction) -> Result<(), ActionError> {
        let pid = action.target.pid.0;

        // Give it a moment for the unfreeze state to propagate
        std::thread::sleep(std::time::Duration::from_millis(
            self.config.propagation_timeout_ms,
        ));

        let freeze_path = self.get_freeze_path(pid)?;
        let is_frozen = self.read_freeze_state(&freeze_path)?;

        if !is_frozen {
            debug!(pid = pid, "unfreeze verified");
            Ok(())
        } else {
            Err(ActionError::Failed(format!(
                "process {} still frozen after unfreeze action",
                pid
            )))
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
/// Returns `true` if the process's cgroup supports the freezer.
#[cfg(target_os = "linux")]
pub fn is_freeze_available(pid: u32) -> bool {
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
        fn get_freeze_path_for_self() {
            let runner = FreezeActionRunner::with_defaults();
            let pid = std::process::id();

            match runner.get_freeze_path(pid) {
                Ok(path) => {
                    crate::test_log!(
                        INFO,
                        "freeze path resolved",
                        pid = pid,
                        path = path.as_str()
                    );
                    assert!(path.ends_with("/cgroup.freeze"));
                }
                Err(e) => {
                    crate::test_log!(
                        INFO,
                        "freeze path not available",
                        pid = pid,
                        error = e.to_string().as_str()
                    );
                    // Expected on non-cgroup-v2 systems
                }
            }
        }

        #[test]
        fn read_freeze_state_for_self() {
            let runner = FreezeActionRunner::with_defaults();
            let pid = std::process::id();

            let path_result = runner.get_freeze_path(pid);
            if let Ok(path) = path_result {
                match runner.read_freeze_state(&path) {
                    Ok(frozen) => {
                        crate::test_log!(INFO, "freeze state read", pid = pid, frozen = frozen);
                        // Our test process should not be frozen
                        assert!(!frozen, "test process should not be frozen");
                    }
                    Err(e) => {
                        crate::test_log!(
                            INFO,
                            "cannot read freeze state",
                            error = e.to_string().as_str()
                        );
                    }
                }
            }
        }
    }
}
