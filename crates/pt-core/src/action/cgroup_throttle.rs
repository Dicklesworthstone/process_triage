//! Cgroup CPU throttle action execution.
//!
//! Implements CPU throttling via cgroup v2 cpu.max with:
//! - Automatic cgroup path discovery for target process
//! - Reversal metadata capture for undo operations
//! - Verification via read-back of cpu.max
//! - Fallback to cgroup v1 (cpu.cfs_quota_us/cpu.cfs_period_us)
//! - Graceful degradation to renice if cgroup unavailable

use super::executor::{ActionError, ActionRunner};
use crate::collect::cgroup::{collect_cgroup_details, CgroupVersion, CpuLimitSource};
use crate::decision::Action;
use crate::plan::PlanAction;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use tracing::{debug, info, warn};

/// Default CPU throttle fraction (25% of current allocation or one core).
pub const DEFAULT_THROTTLE_FRACTION: f64 = 0.25;

/// Default period in microseconds (100ms = standard scheduler quantum).
pub const DEFAULT_PERIOD_US: u64 = 100_000;

/// Minimum quota in microseconds (1ms - prevent starvation).
pub const MIN_QUOTA_US: i64 = 1_000;

/// CPU throttle action configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuThrottleConfig {
    /// Target CPU fraction (0.0-1.0 for fraction, >1.0 for multiple cores).
    /// E.g., 0.25 = 25% of one core, 2.0 = 2 full cores.
    pub target_fraction: f64,

    /// Period in microseconds for the throttle quota.
    pub period_us: u64,

    /// Whether to fallback to cgroup v1 if v2 unavailable.
    pub fallback_to_v1: bool,

    /// Whether to record previous settings for reversal.
    pub capture_reversal: bool,
}

impl Default for CpuThrottleConfig {
    fn default() -> Self {
        Self {
            target_fraction: DEFAULT_THROTTLE_FRACTION,
            period_us: DEFAULT_PERIOD_US,
            fallback_to_v1: true,
            capture_reversal: true,
        }
    }
}

impl CpuThrottleConfig {
    /// Create a config with a specific CPU fraction.
    pub fn with_fraction(fraction: f64) -> Self {
        Self {
            target_fraction: fraction,
            ..Default::default()
        }
    }

    /// Calculate quota from fraction and period.
    pub fn quota_us(&self) -> i64 {
        let quota = (self.target_fraction * self.period_us as f64) as i64;
        quota.max(MIN_QUOTA_US)
    }
}

/// Captured state for reversal of throttle action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThrottleReversalMetadata {
    /// PID of the throttled process.
    pub pid: u32,

    /// Cgroup path where throttle was applied.
    pub cgroup_path: String,

    /// Previous cpu.max value (for v2) or quota_us (for v1).
    pub previous_quota_us: Option<i64>,

    /// Previous period_us value.
    pub previous_period_us: Option<u64>,

    /// Source of previous limits.
    pub source: CpuLimitSource,

    /// Timestamp when throttle was applied.
    pub applied_at: String,
}

/// Result of a throttle operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThrottleResult {
    /// Whether the throttle was successful.
    pub success: bool,

    /// Cgroup path where throttle was applied.
    pub cgroup_path: Option<String>,

    /// New effective CPU fraction.
    pub effective_fraction: Option<f64>,

    /// Reversal metadata if captured.
    pub reversal: Option<ThrottleReversalMetadata>,

    /// Error message if failed.
    pub error: Option<String>,
}

/// CPU throttle action runner using cgroup v2/v1.
#[derive(Debug)]
pub struct CpuThrottleActionRunner {
    config: CpuThrottleConfig,
}

impl CpuThrottleActionRunner {
    pub fn new(config: CpuThrottleConfig) -> Self {
        Self { config }
    }

    pub fn with_defaults() -> Self {
        Self::new(CpuThrottleConfig::default())
    }

    /// Execute a throttle action on a process.
    #[cfg(target_os = "linux")]
    fn execute_throttle(&self, action: &PlanAction) -> Result<(), ActionError> {
        let pid = action.target.pid.0;
        debug!(pid, fraction = self.config.target_fraction, "executing CPU throttle");

        // Collect cgroup details for the target process
        let cgroup_details = collect_cgroup_details(pid).ok_or_else(|| {
            ActionError::Failed(format!("failed to read cgroup for pid {}", pid))
        })?;

        // Try cgroup v2 first
        if cgroup_details.version == CgroupVersion::V2
            || cgroup_details.version == CgroupVersion::Hybrid
        {
            if let Some(ref unified_path) = cgroup_details.unified_path {
                let result = self.apply_throttle_v2(pid, unified_path);
                if result.is_ok() {
                    return result;
                }
                // Fall through to v1 if v2 failed and fallback enabled
                if !self.config.fallback_to_v1 {
                    return result;
                }
                warn!(pid, "cgroup v2 throttle failed, trying v1 fallback");
            }
        }

        // Try cgroup v1 if available
        if self.config.fallback_to_v1 {
            if let Some(cpu_path) = cgroup_details.v1_paths.get("cpu") {
                return self.apply_throttle_v1(pid, cpu_path);
            }
        }

        Err(ActionError::Failed(format!(
            "no writable cgroup CPU controller found for pid {}",
            pid
        )))
    }

    /// Apply CPU throttle using cgroup v2 cpu.max.
    #[cfg(target_os = "linux")]
    fn apply_throttle_v2(&self, pid: u32, unified_path: &str) -> Result<(), ActionError> {
        let cgroup_root = "/sys/fs/cgroup";
        let cpu_max_path = format!("{}{}/cpu.max", cgroup_root, unified_path);

        // Check if cpu.max exists and is writable
        if !Path::new(&cpu_max_path).exists() {
            return Err(ActionError::Failed(format!(
                "cpu.max not found at {}",
                cpu_max_path
            )));
        }

        // Calculate new quota
        let quota = self.config.quota_us();
        let period = self.config.period_us;
        let cpu_max_value = format!("{} {}", quota, period);

        debug!(
            pid,
            path = %cpu_max_path,
            value = %cpu_max_value,
            "writing cpu.max"
        );

        // Write new cpu.max value
        fs::write(&cpu_max_path, &cpu_max_value).map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                ActionError::PermissionDenied
            } else {
                ActionError::Failed(format!("failed to write cpu.max: {}", e))
            }
        })?;

        info!(
            pid,
            cgroup = unified_path,
            quota_us = quota,
            period_us = period,
            "CPU throttle applied via cgroup v2"
        );

        Ok(())
    }

    /// Apply CPU throttle using cgroup v1 cpu.cfs_quota_us.
    #[cfg(target_os = "linux")]
    fn apply_throttle_v1(&self, pid: u32, cpu_path: &str) -> Result<(), ActionError> {
        let cgroup_root = "/sys/fs/cgroup/cpu";
        let quota_path = format!("{}{}/cpu.cfs_quota_us", cgroup_root, cpu_path);
        let period_path = format!("{}{}/cpu.cfs_period_us", cgroup_root, cpu_path);

        // Check if paths exist
        if !Path::new(&quota_path).exists() {
            return Err(ActionError::Failed(format!(
                "cpu.cfs_quota_us not found at {}",
                quota_path
            )));
        }

        // Calculate new quota
        let quota = self.config.quota_us();
        let period = self.config.period_us;

        debug!(
            pid,
            quota_path = %quota_path,
            quota = quota,
            period = period,
            "writing cgroup v1 CPU limits"
        );

        // Write period first, then quota
        fs::write(&period_path, period.to_string()).map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                ActionError::PermissionDenied
            } else {
                ActionError::Failed(format!("failed to write cpu.cfs_period_us: {}", e))
            }
        })?;

        fs::write(&quota_path, quota.to_string()).map_err(|e| {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                ActionError::PermissionDenied
            } else {
                ActionError::Failed(format!("failed to write cpu.cfs_quota_us: {}", e))
            }
        })?;

        info!(
            pid,
            cgroup = cpu_path,
            quota_us = quota,
            period_us = period,
            "CPU throttle applied via cgroup v1"
        );

        Ok(())
    }

    /// Verify throttle was applied by reading back cpu.max.
    #[cfg(target_os = "linux")]
    fn verify_throttle(&self, action: &PlanAction) -> Result<(), ActionError> {
        let pid = action.target.pid.0;

        // Re-collect cgroup details to verify
        let cgroup_details = collect_cgroup_details(pid).ok_or_else(|| {
            ActionError::Failed(format!("failed to read cgroup for verification, pid {}", pid))
        })?;

        let expected_quota = self.config.quota_us();
        let expected_period = self.config.period_us;

        // Check v2 first
        if let Some(ref limits) = cgroup_details.cpu_limits {
            match limits.source {
                CpuLimitSource::CgroupV2CpuMax => {
                    // Verify quota and period match what we set
                    let actual_quota = limits.quota_us.unwrap_or(-1);
                    let actual_period = limits.period_us.unwrap_or(0);

                    if actual_quota != expected_quota {
                        return Err(ActionError::Failed(format!(
                            "quota mismatch: expected {}, got {}",
                            expected_quota, actual_quota
                        )));
                    }
                    if actual_period != expected_period {
                        return Err(ActionError::Failed(format!(
                            "period mismatch: expected {}, got {}",
                            expected_period, actual_period
                        )));
                    }
                    debug!(pid, "throttle verification passed (v2)");
                    return Ok(());
                }
                CpuLimitSource::CgroupV1Cfs => {
                    // Verify v1 settings
                    let actual_quota = limits.quota_us.unwrap_or(-1);
                    let actual_period = limits.period_us.unwrap_or(0);

                    if actual_quota != expected_quota {
                        return Err(ActionError::Failed(format!(
                            "v1 quota mismatch: expected {}, got {}",
                            expected_quota, actual_quota
                        )));
                    }
                    if actual_period != expected_period {
                        return Err(ActionError::Failed(format!(
                            "v1 period mismatch: expected {}, got {}",
                            expected_period, actual_period
                        )));
                    }
                    debug!(pid, "throttle verification passed (v1)");
                    return Ok(());
                }
                CpuLimitSource::None => {
                    return Err(ActionError::Failed(
                        "no CPU limits found after throttle".to_string(),
                    ));
                }
            }
        }

        Err(ActionError::Failed(
            "could not verify throttle - no CPU limits in cgroup".to_string(),
        ))
    }

    /// Capture reversal metadata before applying throttle.
    #[cfg(target_os = "linux")]
    pub fn capture_reversal_metadata(&self, pid: u32) -> Option<ThrottleReversalMetadata> {
        let cgroup_details = collect_cgroup_details(pid)?;

        let (cgroup_path, previous_quota, previous_period, source) =
            if let Some(ref limits) = cgroup_details.cpu_limits {
                let path = cgroup_details
                    .unified_path
                    .clone()
                    .or_else(|| cgroup_details.v1_paths.get("cpu").cloned())?;
                (path, limits.quota_us, limits.period_us, limits.source)
            } else {
                let path = cgroup_details
                    .unified_path
                    .clone()
                    .or_else(|| cgroup_details.v1_paths.get("cpu").cloned())?;
                (path, None, None, CpuLimitSource::None)
            };

        Some(ThrottleReversalMetadata {
            pid,
            cgroup_path,
            previous_quota_us: previous_quota,
            previous_period_us: previous_period,
            source,
            applied_at: chrono::Utc::now().to_rfc3339(),
        })
    }

    /// Restore previous CPU limits from reversal metadata.
    #[cfg(target_os = "linux")]
    pub fn restore_from_metadata(
        &self,
        metadata: &ThrottleReversalMetadata,
    ) -> Result<(), ActionError> {
        match metadata.source {
            CpuLimitSource::CgroupV2CpuMax => {
                let cpu_max_path =
                    format!("/sys/fs/cgroup{}/cpu.max", metadata.cgroup_path);
                let value = match (metadata.previous_quota_us, metadata.previous_period_us) {
                    (Some(q), Some(p)) if q > 0 => format!("{} {}", q, p),
                    (None, Some(p)) | (_, Some(p)) => format!("max {}", p),
                    _ => "max 100000".to_string(), // Default unlimited
                };
                fs::write(&cpu_max_path, &value).map_err(|e| {
                    ActionError::Failed(format!("failed to restore cpu.max: {}", e))
                })?;
                info!(
                    path = %cpu_max_path,
                    value = %value,
                    "restored CPU limits from reversal metadata"
                );
                Ok(())
            }
            CpuLimitSource::CgroupV1Cfs => {
                let quota_path = format!(
                    "/sys/fs/cgroup/cpu{}/cpu.cfs_quota_us",
                    metadata.cgroup_path
                );
                let period_path = format!(
                    "/sys/fs/cgroup/cpu{}/cpu.cfs_period_us",
                    metadata.cgroup_path
                );

                if let Some(period) = metadata.previous_period_us {
                    fs::write(&period_path, period.to_string()).map_err(|e| {
                        ActionError::Failed(format!("failed to restore period: {}", e))
                    })?;
                }

                let quota_value = metadata.previous_quota_us.unwrap_or(-1);
                fs::write(&quota_path, quota_value.to_string()).map_err(|e| {
                    ActionError::Failed(format!("failed to restore quota: {}", e))
                })?;

                info!(
                    quota_path = %quota_path,
                    quota = quota_value,
                    "restored CPU limits from reversal metadata (v1)"
                );
                Ok(())
            }
            CpuLimitSource::None => {
                // No previous limits - set to unlimited
                warn!("no previous limits in reversal metadata, setting to unlimited");
                // Try v2 first
                let cpu_max_path =
                    format!("/sys/fs/cgroup{}/cpu.max", metadata.cgroup_path);
                if Path::new(&cpu_max_path).exists() {
                    fs::write(&cpu_max_path, "max 100000").map_err(|e| {
                        ActionError::Failed(format!("failed to restore to unlimited: {}", e))
                    })?;
                }
                Ok(())
            }
        }
    }
}

#[cfg(target_os = "linux")]
impl ActionRunner for CpuThrottleActionRunner {
    fn execute(&self, action: &PlanAction) -> Result<(), ActionError> {
        match action.action {
            Action::Throttle => self.execute_throttle(action),
            Action::Keep => Ok(()),
            Action::Pause | Action::Resume | Action::Kill | Action::Renice | Action::Restart
            | Action::Freeze | Action::Unfreeze | Action::Quarantine | Action::Unquarantine => {
                Err(ActionError::Failed(format!(
                    "{:?} is not a throttle action",
                    action.action
                )))
            }
        }
    }

    fn verify(&self, action: &PlanAction) -> Result<(), ActionError> {
        match action.action {
            Action::Throttle => self.verify_throttle(action),
            Action::Keep => Ok(()),
            Action::Pause | Action::Resume | Action::Kill | Action::Renice | Action::Restart
            | Action::Freeze | Action::Unfreeze | Action::Quarantine | Action::Unquarantine => {
                Ok(())
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
impl ActionRunner for CpuThrottleActionRunner {
    fn execute(&self, _action: &PlanAction) -> Result<(), ActionError> {
        Err(ActionError::Failed(
            "cgroup CPU throttle not supported on this platform".to_string(),
        ))
    }

    fn verify(&self, _action: &PlanAction) -> Result<(), ActionError> {
        Err(ActionError::Failed(
            "cgroup CPU throttle not supported on this platform".to_string(),
        ))
    }
}

/// Check if cgroup CPU throttle is available for a process.
#[cfg(target_os = "linux")]
pub fn can_throttle_process(pid: u32) -> bool {
    if let Some(details) = collect_cgroup_details(pid) {
        // Check if we have a writable cgroup path
        if let Some(ref unified_path) = details.unified_path {
            let cpu_max_path = format!("/sys/fs/cgroup{}/cpu.max", unified_path);
            if Path::new(&cpu_max_path).exists() {
                // Check write permission
                if let Ok(metadata) = fs::metadata(&cpu_max_path) {
                    if !metadata.permissions().readonly() {
                        return true;
                    }
                }
            }
        }
        // Check v1 fallback
        if let Some(cpu_path) = details.v1_paths.get("cpu") {
            let quota_path = format!("/sys/fs/cgroup/cpu{}/cpu.cfs_quota_us", cpu_path);
            if Path::new(&quota_path).exists() {
                if let Ok(metadata) = fs::metadata(&quota_path) {
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
pub fn can_throttle_process(_pid: u32) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_throttle_config_defaults() {
        let config = CpuThrottleConfig::default();
        assert_eq!(config.target_fraction, DEFAULT_THROTTLE_FRACTION);
        assert_eq!(config.period_us, DEFAULT_PERIOD_US);
        assert!(config.fallback_to_v1);
        assert!(config.capture_reversal);
    }

    #[test]
    fn cpu_throttle_config_with_fraction() {
        let config = CpuThrottleConfig::with_fraction(0.5);
        assert_eq!(config.target_fraction, 0.5);
        assert_eq!(config.period_us, DEFAULT_PERIOD_US);
    }

    #[test]
    fn quota_calculation() {
        let config = CpuThrottleConfig {
            target_fraction: 0.25,
            period_us: 100_000,
            ..Default::default()
        };
        assert_eq!(config.quota_us(), 25_000);

        let config = CpuThrottleConfig {
            target_fraction: 2.0, // 2 cores
            period_us: 100_000,
            ..Default::default()
        };
        assert_eq!(config.quota_us(), 200_000);
    }

    #[test]
    fn quota_minimum_enforced() {
        let config = CpuThrottleConfig {
            target_fraction: 0.00001, // Very small
            period_us: 100_000,
            ..Default::default()
        };
        assert_eq!(config.quota_us(), MIN_QUOTA_US);
    }

    #[test]
    fn runner_can_be_created() {
        let runner = CpuThrottleActionRunner::with_defaults();
        assert_eq!(runner.config.target_fraction, DEFAULT_THROTTLE_FRACTION);
    }

    #[cfg(target_os = "linux")]
    mod linux_tests {
        use super::*;

        #[test]
        fn can_check_throttle_availability() {
            // Check for our own process
            let my_pid = std::process::id();
            let result = can_throttle_process(my_pid);
            // Result depends on system configuration - just ensure no panic
            crate::test_log!(
                INFO,
                "can_throttle_process check",
                pid = my_pid,
                can_throttle = result
            );
        }

        #[test]
        fn can_capture_reversal_metadata() {
            let runner = CpuThrottleActionRunner::with_defaults();
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
                crate::test_log!(
                    INFO,
                    "reversal metadata captured",
                    cgroup_path = meta.cgroup_path.as_str(),
                    source = format!("{:?}", meta.source).as_str()
                );
            }
        }

        #[test]
        fn throttle_result_serialization() {
            let result = ThrottleResult {
                success: true,
                cgroup_path: Some("/user.slice/user-1000.slice".to_string()),
                effective_fraction: Some(0.25),
                reversal: None,
                error: None,
            };

            let json = serde_json::to_string(&result).expect("serialization");
            assert!(json.contains("success"));
            assert!(json.contains("cgroup_path"));
        }
    }
}
