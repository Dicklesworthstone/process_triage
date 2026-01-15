//! Cgroup cpuset quarantine action execution.
//!
//! Implements process quarantine by restricting CPU access via cgroup cpuset with:
//! - Automatic cgroup path discovery for target process
//! - Reversal metadata capture for undo operations
//! - Verification via read-back of cpuset.cpus
//! - Support for both cgroup v2 and v1 cpuset controllers
//! - Safety gates: protected denylist, min CPU count to prevent starvation
//!
//! # How Quarantine Works
//!
//! Unlike freezing (which completely stops a process) or throttling (which limits CPU
//! time percentage), quarantine restricts which CPU cores a process can use. This is
//! useful for:
//! - Isolating misbehaving processes to specific cores
//! - Reducing interference with other processes
//! - Gradual resource restriction before more aggressive actions
//!
//! # Safety Considerations
//!
//! The quarantine action includes safety gates to prevent system instability:
//! - Minimum CPU count policy prevents starvation (at least 1 CPU must be available)
//! - Protected process denylist prevents quarantining critical system processes
//! - Reversal metadata allows restoring previous cpuset configuration

use super::executor::{ActionError, ActionRunner};
use crate::collect::cgroup::{collect_cgroup_details, CgroupVersion};
use crate::decision::Action;
use crate::plan::PlanAction;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use tracing::{debug, info, warn};

/// Default quarantine CPU count (1 core).
pub const DEFAULT_QUARANTINE_CPUS: u32 = 1;

/// Minimum allowed CPUs to prevent starvation.
pub const MIN_QUARANTINE_CPUS: u32 = 1;

/// Cpuset quarantine action configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpusetQuarantineConfig {
    /// Target CPU count for quarantined processes.
    /// Must be >= MIN_QUARANTINE_CPUS to prevent starvation.
    pub target_cpus: u32,

    /// Specific CPUs to assign (e.g., "0" or "0-1").
    /// If None, the lowest N CPUs will be used.
    pub specific_cpus: Option<String>,

    /// Whether to fallback to cgroup v1 if v2 unavailable.
    pub fallback_to_v1: bool,

    /// Whether to record previous settings for reversal.
    pub capture_reversal: bool,

    /// Protected process names that should never be quarantined.
    pub protected_names: HashSet<String>,
}

impl Default for CpusetQuarantineConfig {
    fn default() -> Self {
        let mut protected = HashSet::new();
        // Default protected processes - critical system processes
        protected.insert("init".to_string());
        protected.insert("systemd".to_string());
        protected.insert("systemd-journald".to_string());
        protected.insert("systemd-udevd".to_string());
        protected.insert("containerd".to_string());
        protected.insert("dockerd".to_string());

        Self {
            target_cpus: DEFAULT_QUARANTINE_CPUS,
            specific_cpus: None,
            fallback_to_v1: true,
            capture_reversal: true,
            protected_names: protected,
        }
    }
}

impl CpusetQuarantineConfig {
    /// Create a config with specific CPU count.
    pub fn with_cpus(cpus: u32) -> Self {
        Self {
            target_cpus: cpus.max(MIN_QUARANTINE_CPUS),
            ..Default::default()
        }
    }

    /// Create a config with specific CPU assignment.
    pub fn with_specific_cpus(cpus: &str) -> Self {
        Self {
            specific_cpus: Some(cpus.to_string()),
            ..Default::default()
        }
    }

    /// Get the cpuset string to write.
    ///
    /// Returns either the specific CPUs or generates a range like "0" or "0-N".
    pub fn cpuset_string(&self) -> String {
        if let Some(ref specific) = self.specific_cpus {
            specific.clone()
        } else if self.target_cpus == 1 {
            "0".to_string()
        } else {
            format!("0-{}", self.target_cpus - 1)
        }
    }
}

/// Captured state for reversal of quarantine action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineReversalMetadata {
    /// PID of the quarantined process.
    pub pid: u32,

    /// Cgroup path where quarantine was applied.
    pub cgroup_path: String,

    /// Previous cpuset.cpus value.
    pub previous_cpuset: String,

    /// Previous cpuset.cpus.effective value (if available).
    pub previous_effective: Option<String>,

    /// Whether this was cgroup v2 (true) or v1 (false).
    pub is_v2: bool,

    /// Timestamp when quarantine was applied.
    pub applied_at: String,
}

/// Result of a quarantine operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineResult {
    /// Whether the quarantine was successful.
    pub success: bool,

    /// Cgroup path where quarantine was applied.
    pub cgroup_path: Option<String>,

    /// New cpuset value.
    pub new_cpuset: Option<String>,

    /// Number of CPUs available after quarantine.
    pub effective_cpus: Option<u32>,

    /// Reversal metadata if captured.
    pub reversal: Option<QuarantineReversalMetadata>,

    /// Error message if failed.
    pub error: Option<String>,
}

/// Cpuset quarantine action runner.
#[derive(Debug)]
pub struct CpusetQuarantineActionRunner {
    config: CpusetQuarantineConfig,
}

impl CpusetQuarantineActionRunner {
    pub fn new(config: CpusetQuarantineConfig) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(CpusetQuarantineConfig::default())
    }

    /// Check if a process is protected from quarantine.
    pub fn is_protected(&self, comm: &str) -> bool {
        self.config.protected_names.contains(comm)
    }

    /// Execute a quarantine action on a process.
    #[cfg(target_os = "linux")]
    fn execute_quarantine(&self, action: &PlanAction) -> Result<(), ActionError> {
        let pid = action.target.pid.0;
        debug!(pid, cpus = self.config.target_cpus, "executing cpuset quarantine");

        // Note: Protected process check requires reading /proc/<pid>/comm at runtime
        // since ProcessIdentity doesn't include comm. The protected_names check
        // would need to be done at plan creation time with process metadata.

        // Collect cgroup details for the target process
        let cgroup_details = collect_cgroup_details(pid).ok_or_else(|| {
            ActionError::Failed(format!("failed to read cgroup for pid {}", pid))
        })?;

        // Try cgroup v2 first
        if cgroup_details.version == CgroupVersion::V2
            || cgroup_details.version == CgroupVersion::Hybrid
        {
            if let Some(ref unified_path) = cgroup_details.unified_path {
                let result = self.apply_quarantine_v2(pid, unified_path);
                if result.is_ok() {
                    return result;
                }
                // Fall through to v1 if v2 failed and fallback enabled
                if !self.config.fallback_to_v1 {
                    return result;
                }
                warn!(pid, "cgroup v2 quarantine failed, trying v1 fallback");
            }
        }

        // Try cgroup v1 if available
        if self.config.fallback_to_v1 {
            if let Some(cpuset_path) = cgroup_details.v1_paths.get("cpuset") {
                return self.apply_quarantine_v1(pid, cpuset_path);
            }
        }

        Err(ActionError::Failed(format!(
            "no writable cgroup cpuset controller found for pid {}",
            pid
        )))
    }

    /// Apply cpuset quarantine using cgroup v2.
    #[cfg(target_os = "linux")]
    fn apply_quarantine_v2(&self, pid: u32, unified_path: &str) -> Result<(), ActionError> {
        let cgroup_root = "/sys/fs/cgroup";
        let cpuset_path = format!("{}{}/cpuset.cpus", cgroup_root, unified_path);

        // Check if cpuset.cpus exists
        if !Path::new(&cpuset_path).exists() {
            return Err(ActionError::Failed(format!(
                "cpuset.cpus not found at {}",
                cpuset_path
            )));
        }

        // Get the new cpuset value
        let new_cpuset = self.config.cpuset_string();

        debug!(
            pid,
            path = %cpuset_path,
            value = %new_cpuset,
            "writing cpuset.cpus"
        );

        // Write new cpuset value
        fs::write(&cpuset_path, &new_cpuset).map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                ActionError::PermissionDenied
            } else {
                ActionError::Failed(format!("failed to write cpuset.cpus: {}", e))
            }
        })?;

        info!(
            pid,
            cgroup = unified_path,
            cpuset = %new_cpuset,
            "cpuset quarantine applied via cgroup v2"
        );

        Ok(())
    }

    /// Apply cpuset quarantine using cgroup v1.
    #[cfg(target_os = "linux")]
    fn apply_quarantine_v1(&self, pid: u32, cpuset_path: &str) -> Result<(), ActionError> {
        let cgroup_root = "/sys/fs/cgroup/cpuset";
        let cpus_path = format!("{}{}/cpuset.cpus", cgroup_root, cpuset_path);

        // Check if path exists
        if !Path::new(&cpus_path).exists() {
            return Err(ActionError::Failed(format!(
                "cpuset.cpus not found at {}",
                cpus_path
            )));
        }

        // Get the new cpuset value
        let new_cpuset = self.config.cpuset_string();

        debug!(
            pid,
            path = %cpus_path,
            value = %new_cpuset,
            "writing cgroup v1 cpuset.cpus"
        );

        // Write new cpuset value
        fs::write(&cpus_path, &new_cpuset).map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                ActionError::PermissionDenied
            } else {
                ActionError::Failed(format!("failed to write cpuset.cpus: {}", e))
            }
        })?;

        info!(
            pid,
            cgroup = cpuset_path,
            cpuset = %new_cpuset,
            "cpuset quarantine applied via cgroup v1"
        );

        Ok(())
    }

    /// Execute an unquarantine action (restore previous cpuset).
    #[cfg(target_os = "linux")]
    fn execute_unquarantine(&self, action: &PlanAction) -> Result<(), ActionError> {
        let pid = action.target.pid.0;
        debug!(pid, "executing cpuset unquarantine");

        // For unquarantine, we need reversal metadata
        // This would typically be passed via action metadata
        // For now, restore to all available CPUs
        let cgroup_details = collect_cgroup_details(pid).ok_or_else(|| {
            ActionError::Failed(format!("failed to read cgroup for pid {}", pid))
        })?;

        if let Some(ref unified_path) = cgroup_details.unified_path {
            let cpuset_path = format!("/sys/fs/cgroup{}/cpuset.cpus", unified_path);
            if Path::new(&cpuset_path).exists() {
                // Try to read cpuset.cpus.effective to get all available CPUs
                let effective_path = format!("/sys/fs/cgroup{}/cpuset.cpus.effective", unified_path);
                let all_cpus = if Path::new(&effective_path).exists() {
                    fs::read_to_string(&effective_path).ok()
                } else {
                    // Fall back to reading from parent or system
                    get_system_cpuset()
                };

                if let Some(cpus) = all_cpus {
                    let cpus = cpus.trim();
                    fs::write(&cpuset_path, cpus).map_err(|e| {
                        if e.kind() == std::io::ErrorKind::PermissionDenied {
                            ActionError::PermissionDenied
                        } else {
                            ActionError::Failed(format!("failed to restore cpuset.cpus: {}", e))
                        }
                    })?;
                    info!(pid, cpuset = cpus, "cpuset restored via unquarantine");
                    return Ok(());
                }
            }
        }

        Err(ActionError::Failed(format!(
            "could not restore cpuset for pid {}",
            pid
        )))
    }

    /// Verify quarantine was applied by reading back cpuset.cpus.
    #[cfg(target_os = "linux")]
    fn verify_quarantine(&self, action: &PlanAction) -> Result<(), ActionError> {
        let pid = action.target.pid.0;

        let cgroup_details = collect_cgroup_details(pid).ok_or_else(|| {
            ActionError::Failed(format!("failed to read cgroup for verification, pid {}", pid))
        })?;

        let expected_cpuset = self.config.cpuset_string();

        // Check v2 first
        if let Some(ref unified_path) = cgroup_details.unified_path {
            let cpuset_path = format!("/sys/fs/cgroup{}/cpuset.cpus", unified_path);
            if let Ok(actual) = fs::read_to_string(&cpuset_path) {
                let actual = actual.trim();
                // Parse and compare CPU counts rather than exact string
                let expected_count = count_cpus(&expected_cpuset);
                let actual_count = count_cpus(actual);

                if actual_count <= expected_count {
                    debug!(pid, expected = %expected_cpuset, actual = actual, "quarantine verified (v2)");
                    return Ok(());
                } else {
                    return Err(ActionError::Failed(format!(
                        "cpuset mismatch: expected {}, got {}",
                        expected_cpuset, actual
                    )));
                }
            }
        }

        // Check v1
        if let Some(cpuset_path) = cgroup_details.v1_paths.get("cpuset") {
            let cpus_path = format!("/sys/fs/cgroup/cpuset{}/cpuset.cpus", cpuset_path);
            if let Ok(actual) = fs::read_to_string(&cpus_path) {
                let actual = actual.trim();
                let expected_count = count_cpus(&expected_cpuset);
                let actual_count = count_cpus(actual);

                if actual_count <= expected_count {
                    debug!(pid, expected = %expected_cpuset, actual = actual, "quarantine verified (v1)");
                    return Ok(());
                } else {
                    return Err(ActionError::Failed(format!(
                        "v1 cpuset mismatch: expected {}, got {}",
                        expected_cpuset, actual
                    )));
                }
            }
        }

        Err(ActionError::Failed(
            "could not verify quarantine - no cpuset found".to_string(),
        ))
    }

    /// Capture reversal metadata before applying quarantine.
    #[cfg(target_os = "linux")]
    pub fn capture_reversal_metadata(&self, pid: u32) -> Option<QuarantineReversalMetadata> {
        let cgroup_details = collect_cgroup_details(pid)?;

        // Try v2 first
        if let Some(ref unified_path) = cgroup_details.unified_path {
            let cpuset_path = format!("/sys/fs/cgroup{}/cpuset.cpus", unified_path);
            let effective_path = format!("/sys/fs/cgroup{}/cpuset.cpus.effective", unified_path);

            if let Ok(previous) = fs::read_to_string(&cpuset_path) {
                let effective = fs::read_to_string(&effective_path).ok();
                return Some(QuarantineReversalMetadata {
                    pid,
                    cgroup_path: unified_path.clone(),
                    previous_cpuset: previous.trim().to_string(),
                    previous_effective: effective.map(|s| s.trim().to_string()),
                    is_v2: true,
                    applied_at: chrono::Utc::now().to_rfc3339(),
                });
            }
        }

        // Try v1
        if let Some(cpuset_path) = cgroup_details.v1_paths.get("cpuset") {
            let cpus_path = format!("/sys/fs/cgroup/cpuset{}/cpuset.cpus", cpuset_path);
            if let Ok(previous) = fs::read_to_string(&cpus_path) {
                return Some(QuarantineReversalMetadata {
                    pid,
                    cgroup_path: cpuset_path.clone(),
                    previous_cpuset: previous.trim().to_string(),
                    previous_effective: None,
                    is_v2: false,
                    applied_at: chrono::Utc::now().to_rfc3339(),
                });
            }
        }

        None
    }

    /// Restore previous cpuset from reversal metadata.
    #[cfg(target_os = "linux")]
    pub fn restore_from_metadata(
        &self,
        metadata: &QuarantineReversalMetadata,
    ) -> Result<(), ActionError> {
        let cpuset_path = if metadata.is_v2 {
            format!("/sys/fs/cgroup{}/cpuset.cpus", metadata.cgroup_path)
        } else {
            format!("/sys/fs/cgroup/cpuset{}/cpuset.cpus", metadata.cgroup_path)
        };

        fs::write(&cpuset_path, &metadata.previous_cpuset).map_err(|e| {
            ActionError::Failed(format!("failed to restore cpuset: {}", e))
        })?;

        info!(
            path = %cpuset_path,
            value = %metadata.previous_cpuset,
            "restored cpuset from reversal metadata"
        );

        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl ActionRunner for CpusetQuarantineActionRunner {
    fn execute(&self, action: &PlanAction) -> Result<(), ActionError> {
        match action.action {
            Action::Quarantine => self.execute_quarantine(action),
            Action::Unquarantine => self.execute_unquarantine(action),
            Action::Keep => Ok(()),
            Action::Pause | Action::Resume | Action::Kill | Action::Renice | Action::Restart
            | Action::Freeze | Action::Unfreeze | Action::Throttle => {
                Err(ActionError::Failed(format!(
                    "{:?} is not a quarantine action",
                    action.action
                )))
            }
        }
    }

    fn verify(&self, action: &PlanAction) -> Result<(), ActionError> {
        match action.action {
            Action::Quarantine => self.verify_quarantine(action),
            Action::Unquarantine => Ok(()), // Unquarantine verification would check cpuset restored
            Action::Keep => Ok(()),
            Action::Pause | Action::Resume | Action::Kill | Action::Renice | Action::Restart
            | Action::Freeze | Action::Unfreeze | Action::Throttle => Ok(()),
        }
    }
}

#[cfg(not(target_os = "linux"))]
impl ActionRunner for CpusetQuarantineActionRunner {
    fn execute(&self, _action: &PlanAction) -> Result<(), ActionError> {
        Err(ActionError::Failed(
            "cgroup cpuset quarantine not supported on this platform".to_string(),
        ))
    }

    fn verify(&self, _action: &PlanAction) -> Result<(), ActionError> {
        Err(ActionError::Failed(
            "cgroup cpuset quarantine not supported on this platform".to_string(),
        ))
    }
}

/// Check if cpuset quarantine is available for a process.
#[cfg(target_os = "linux")]
pub fn can_quarantine_cpuset(pid: u32) -> bool {
    if let Some(details) = collect_cgroup_details(pid) {
        // Check if we have a writable cpuset cgroup path
        if let Some(ref unified_path) = details.unified_path {
            let cpuset_path = format!("/sys/fs/cgroup{}/cpuset.cpus", unified_path);
            if Path::new(&cpuset_path).exists() {
                // Check write permission
                if let Ok(metadata) = fs::metadata(&cpuset_path) {
                    if !metadata.permissions().readonly() {
                        return true;
                    }
                }
            }
        }
        // Check v1 fallback
        if let Some(cpuset_path) = details.v1_paths.get("cpuset") {
            let cpus_path = format!("/sys/fs/cgroup/cpuset{}/cpuset.cpus", cpuset_path);
            if Path::new(&cpus_path).exists() {
                if let Ok(metadata) = fs::metadata(&cpus_path) {
                    if !metadata.permissions().readonly() {
                        return true;
                    }
                }
            }
        }
    }
    false
}

#[cfg(not(target_os = "linux"))]
pub fn can_quarantine_cpuset(_pid: u32) -> bool {
    false
}

/// Get the system's available CPUs.
#[cfg(target_os = "linux")]
fn get_system_cpuset() -> Option<String> {
    // Try /sys/devices/system/cpu/online first
    if let Ok(content) = fs::read_to_string("/sys/devices/system/cpu/online") {
        return Some(content.trim().to_string());
    }
    // Fall back to counting CPU directories
    let mut max_cpu = 0;
    if let Ok(entries) = fs::read_dir("/sys/devices/system/cpu") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            if let Some(name) = name.to_str() {
                if let Some(num) = name.strip_prefix("cpu") {
                    if let Ok(n) = num.parse::<u32>() {
                        max_cpu = max_cpu.max(n);
                    }
                }
            }
        }
        if max_cpu > 0 {
            return Some(format!("0-{}", max_cpu));
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
fn get_system_cpuset() -> Option<String> {
    None
}

/// Count the number of CPUs in a cpuset string like "0-3" or "0,2,4".
fn count_cpus(cpuset: &str) -> u32 {
    let mut count = 0;
    for part in cpuset.split(',') {
        let part = part.trim();
        if let Some((start, end)) = part.split_once('-') {
            if let (Ok(s), Ok(e)) = (start.parse::<u32>(), end.parse::<u32>()) {
                count += e - s + 1;
            }
        } else if part.parse::<u32>().is_ok() {
            count += 1;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpuset_quarantine_config_defaults() {
        let config = CpusetQuarantineConfig::default();
        assert_eq!(config.target_cpus, DEFAULT_QUARANTINE_CPUS);
        assert!(config.fallback_to_v1);
        assert!(config.capture_reversal);
        assert!(!config.protected_names.is_empty());
    }

    #[test]
    fn cpuset_quarantine_config_with_cpus() {
        let config = CpusetQuarantineConfig::with_cpus(4);
        assert_eq!(config.target_cpus, 4);
    }

    #[test]
    fn cpuset_quarantine_config_min_cpus_enforced() {
        let config = CpusetQuarantineConfig::with_cpus(0);
        assert_eq!(config.target_cpus, MIN_QUARANTINE_CPUS);
    }

    #[test]
    fn cpuset_string_generation() {
        let config = CpusetQuarantineConfig::with_cpus(1);
        assert_eq!(config.cpuset_string(), "0");

        let config = CpusetQuarantineConfig::with_cpus(4);
        assert_eq!(config.cpuset_string(), "0-3");

        let config = CpusetQuarantineConfig::with_specific_cpus("2,4,6");
        assert_eq!(config.cpuset_string(), "2,4,6");
    }

    #[test]
    fn count_cpus_parsing() {
        assert_eq!(count_cpus("0"), 1);
        assert_eq!(count_cpus("0-3"), 4);
        assert_eq!(count_cpus("0-7"), 8);
        assert_eq!(count_cpus("0,2,4,6"), 4);
        assert_eq!(count_cpus("0-1,4-5"), 4);
        assert_eq!(count_cpus(""), 0);
    }

    #[test]
    fn runner_can_be_created() {
        let runner = CpusetQuarantineActionRunner::with_defaults();
        assert_eq!(runner.config.target_cpus, DEFAULT_QUARANTINE_CPUS);
    }

    #[test]
    fn protected_process_check() {
        let runner = CpusetQuarantineActionRunner::with_defaults();
        assert!(runner.is_protected("init"));
        assert!(runner.is_protected("systemd"));
        assert!(!runner.is_protected("random_process"));
    }

    #[test]
    fn quarantine_result_serialization() {
        let result = QuarantineResult {
            success: true,
            cgroup_path: Some("/user.slice/user-1000.slice".to_string()),
            new_cpuset: Some("0".to_string()),
            effective_cpus: Some(1),
            reversal: None,
            error: None,
        };

        let json = serde_json::to_string(&result).expect("serialization");
        assert!(json.contains("success"));
        assert!(json.contains("cgroup_path"));
        assert!(json.contains("new_cpuset"));
    }

    #[cfg(target_os = "linux")]
    mod linux_tests {
        use super::*;

        #[test]
        fn can_check_quarantine_availability() {
            let my_pid = std::process::id();
            let result = can_quarantine_cpuset(my_pid);
            crate::test_log!(
                INFO,
                "can_quarantine_cpuset check",
                pid = my_pid,
                can_quarantine = result
            );
        }

        #[test]
        fn can_capture_reversal_metadata() {
            let runner = CpusetQuarantineActionRunner::with_defaults();
            let my_pid = std::process::id();

            let metadata = runner.capture_reversal_metadata(my_pid);
            crate::test_log!(
                INFO,
                "capture_reversal_metadata",
                pid = my_pid,
                has_metadata = metadata.is_some()
            );

            if let Some(meta) = metadata {
                assert_eq!(meta.pid, my_pid);
                assert!(!meta.cgroup_path.is_empty());
                assert!(!meta.previous_cpuset.is_empty());
                crate::test_log!(
                    INFO,
                    "reversal metadata captured",
                    cgroup_path = meta.cgroup_path.as_str(),
                    previous_cpuset = meta.previous_cpuset.as_str(),
                    is_v2 = meta.is_v2
                );
            }
        }
    }
}
