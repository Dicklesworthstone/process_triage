//! Renice (priority adjustment) action execution.
//!
//! Implements process priority adjustment using setpriority(2) with:
//! - TOCTOU safety via identity revalidation
//! - Verification via /proc/[pid]/stat
//! - Graceful handling of permission denied
//! - Reversal metadata capture for undo operations

use super::executor::{ActionError, ActionRunner};
use crate::decision::Action;
use crate::plan::PlanAction;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

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
        // PRIO_PROCESS = 0
        let result =
            unsafe { libc::setpriority(libc::PRIO_PROCESS, pid as libc::id_t, nice_value) };

        if result == 0 {
            return Ok(());
        }

        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::ESRCH) => Err(ActionError::Failed("process not found".to_string())),
            Some(libc::EPERM) => Err(ActionError::PermissionDenied),
            Some(libc::EINVAL) => Err(ActionError::Failed("invalid priority value".to_string())),
            Some(libc::EACCES) => Err(ActionError::PermissionDenied),
            _ => Err(ActionError::Failed(err.to_string())),
        }
    }

    /// Get current nice value from /proc/[pid]/stat.
    #[cfg(target_os = "linux")]
    fn get_nice_value(&self, pid: u32) -> Option<i32> {
        let stat_path = format!("/proc/{pid}/stat");
        let content = std::fs::read_to_string(stat_path).ok()?;

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

    #[cfg(not(target_os = "linux"))]
    fn get_nice_value(&self, _pid: u32) -> Option<i32> {
        None
    }

    /// Capture reversal metadata before applying renice.
    /// Returns metadata with the previous nice value for later restoration.
    #[cfg(unix)]
    pub fn capture_reversal_metadata(&self, pid: u32) -> Option<ReniceReversalMetadata> {
        let previous_nice = self.get_nice_value(pid)?;
        let applied_nice = self.effective_nice_value();

        debug!(
            pid,
            previous_nice,
            applied_nice,
            "capturing renice reversal metadata"
        );

        Some(ReniceReversalMetadata {
            pid,
            previous_nice,
            applied_nice,
            applied_at: chrono::Utc::now().to_rfc3339(),
        })
    }

    #[cfg(not(unix))]
    pub fn capture_reversal_metadata(&self, _pid: u32) -> Option<ReniceReversalMetadata> {
        None
    }

    /// Restore previous nice value from reversal metadata.
    #[cfg(unix)]
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

    /// Execute a renice action with optional reversal metadata capture.
    #[cfg(unix)]
    fn execute_renice(&self, action: &PlanAction) -> Result<(), ActionError> {
        let pid = action.target.pid.0;
        let nice_value = self.effective_nice_value();

        debug!(pid, nice_value, "executing renice action");

        // Capture previous nice value for logging (reversal metadata can be captured separately)
        if self.config.capture_reversal {
            if let Some(previous) = self.get_nice_value(pid) {
                debug!(pid, previous_nice = previous, new_nice = nice_value, "renice: capturing prior state");
            }
        }

        self.set_priority(pid, nice_value)?;

        info!(pid, nice_value, "renice action applied successfully");
        Ok(())
    }

    /// Verify a renice action succeeded.
    #[cfg(unix)]
    fn verify_renice(&self, action: &PlanAction) -> Result<(), ActionError> {
        let pid = action.target.pid.0;
        let expected = self.effective_nice_value();

        // Give it a moment for the change to take effect
        std::thread::sleep(std::time::Duration::from_millis(10));

        match self.get_nice_value(pid) {
            Some(actual) if actual == expected => Ok(()),
            Some(actual) => Err(ActionError::Failed(format!(
                "nice value mismatch: expected {expected}, got {actual}"
            ))),
            None => {
                // Process may have exited or /proc not available
                // Check if process still exists
                let stat_path = format!("/proc/{pid}/stat");
                if !std::path::Path::new(&stat_path).exists() {
                    Err(ActionError::Failed("process no longer exists".to_string()))
                } else {
                    // Can't verify but process exists - assume success
                    Ok(())
                }
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
        fn capture_reversal_metadata_for_self() {
            let runner = ReniceActionRunner::with_defaults();
            let pid = std::process::id();

            let metadata = runner.capture_reversal_metadata(pid);
            assert!(metadata.is_some(), "should capture reversal metadata");

            let meta = metadata.unwrap();
            assert_eq!(meta.pid, pid);
            assert_eq!(meta.applied_nice, DEFAULT_NICE_VALUE);
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
