//! Cgroup CPU throttle action execution.
//!
//! Implements CPU throttling via cgroup v2 cpu.max with:
//! - Automatic cgroup path discovery for target process
//! - Reversal metadata capture for undo operations
//! - Verification via read-back of cpu.max
//! - Hybrid v1 fallback with separate controller isolation checks
//! - Explicit refusal when safe cgroup mutation is unavailable

use super::executor::{ActionError, ActionRunner};
use crate::collect::cgroup::{collect_cgroup_details, CpuLimitSource};
use crate::decision::Action;
use crate::plan::PlanAction;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info};

/// Default maximum CPU bandwidth (25% of one core).
pub const DEFAULT_THROTTLE_FRACTION: f64 = 0.25;

/// Default period in microseconds (100ms = standard scheduler quantum).
pub const DEFAULT_PERIOD_US: u64 = 100_000;

/// Minimum quota in microseconds (1ms - prevent starvation).
pub const MIN_QUOTA_US: i64 = 1_000;

/// Scheduler bandwidth periods are limited to 1ms through 1s.
const MIN_PERIOD_US: u64 = 1_000;
const MAX_PERIOD_US: u64 = 1_000_000;

/// CPU throttle action configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuThrottleConfig {
    /// Maximum CPU fraction (0.0-1.0 for fraction, >1.0 for multiple cores).
    /// E.g., 0.25 = 25% of one core, 2.0 = 2 full cores.
    /// An existing stricter limit is preserved.
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

    /// Calculate the nominal quota from fraction and period.
    /// Execution separately refuses invalid or unrepresentable configurations;
    /// it never rounds an unrepresentable requested cap up to this minimum.
    pub fn quota_us(&self) -> i64 {
        let quota = (self.target_fraction * self.period_us as f64) as i64;
        quota.max(MIN_QUOTA_US)
    }

    fn validated_limit(&self) -> Result<CpuBandwidthLimit, ActionError> {
        if !self.target_fraction.is_finite() || self.target_fraction <= 0.0 {
            return Err(ActionError::Failed(
                "CPU throttle fraction must be finite and positive".to_string(),
            ));
        }
        let quota = self.target_fraction * self.period_us as f64;
        if !quota.is_finite() || quota < MIN_QUOTA_US as f64 || quota >= i64::MAX as f64 {
            return Err(ActionError::Failed(
                "CPU throttle cap cannot be represented by a valid scheduler quota".to_string(),
            ));
        }
        CpuBandwidthLimit::new(quota as i64, self.period_us)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CpuBandwidthLimit {
    /// -1 is the kernel's unlimited sentinel.
    quota_us: i64,
    period_us: u64,
}

impl CpuBandwidthLimit {
    fn new(quota_us: i64, period_us: u64) -> Result<Self, ActionError> {
        if (quota_us != -1 && quota_us < MIN_QUOTA_US)
            || !(MIN_PERIOD_US..=MAX_PERIOD_US).contains(&period_us)
        {
            return Err(ActionError::Failed(
                "invalid CPU quota or scheduler period".to_string(),
            ));
        }
        Ok(Self {
            quota_us,
            period_us,
        })
    }

    fn within(self, maximum: Self) -> bool {
        self.quota_us > 0
            && (self.quota_us as u128) * u128::from(maximum.period_us)
                <= (maximum.quota_us as u128) * u128::from(self.period_us)
    }
}

/// Check a finite controller limit against the requested maximum bandwidth.
/// Invalid observations/configuration are errors; a valid unlimited limit (-1)
/// is an observed failure to meet the cap, not missing evidence.
pub(crate) fn quota_within_limit(
    current_quota: i64,
    current_period: u64,
    config: &CpuThrottleConfig,
) -> Result<bool, ActionError> {
    let current = CpuBandwidthLimit::new(current_quota, current_period)?;
    Ok(current.within(config.validated_limit()?))
}

/// Captured state for reversal of throttle action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThrottleReversalMetadata {
    /// PID of the throttled process.
    pub pid: u32,

    /// Exact process incarnation whose previous limits were captured.
    pub identity: pt_common::ProcessIdentity,

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
        self.config.validated_limit()?;
        let pid = action.target.pid.0;
        let checked_path = super::dispatch::ensure_cgroup_target(&action.target)?;
        debug!(
            pid,
            fraction = self.config.target_fraction,
            "executing CPU throttle"
        );

        // Collect cgroup details for the target process
        let cgroup_details = collect_cgroup_details(pid)
            .ok_or_else(|| ActionError::Failed(format!("failed to read cgroup for pid {}", pid)))?;
        if cgroup_details.unified_path.as_deref() != Some(checked_path.as_str()) {
            return Err(ActionError::Failed(
                "refusing throttle after cgroup membership changed".to_string(),
            ));
        }

        let v2_directory = PathBuf::from(format!("/sys/fs/cgroup{checked_path}"));
        let v1_path = self
            .config
            .fallback_to_v1
            .then(|| cgroup_details.v1_paths.get("cpu"))
            .flatten();
        let v1_directory = v1_path.map(|path| PathBuf::from(format!("/sys/fs/cgroup/cpu{path}")));
        let (directory, is_v2) = select_cpu_controller(&v2_directory, v1_directory.as_deref())?;
        self.apply_throttle_at(&directory, is_v2, || {
            self.revalidate_membership(
                action,
                &checked_path,
                if is_v2 {
                    None
                } else {
                    v1_path.map(String::as_str)
                },
            )
        })
    }

    /// Recheck the planned incarnation and isolation in every affected hierarchy.
    #[cfg(target_os = "linux")]
    fn revalidate_membership(
        &self,
        action: &PlanAction,
        unified_path: &str,
        v1_cpu_path: Option<&str>,
    ) -> Result<(), ActionError> {
        if super::dispatch::ensure_cgroup_target(&action.target)? != unified_path {
            return Err(ActionError::Failed(
                "refusing throttle after cgroup membership changed".to_string(),
            ));
        }
        if let Some(expected) = v1_cpu_path {
            let details = collect_cgroup_details(action.target.pid.0).ok_or_else(|| {
                ActionError::Failed("cannot revalidate CPU controller membership".to_string())
            })?;
            if details.v1_paths.get("cpu").map(String::as_str) != Some(expected) {
                return Err(ActionError::Failed(
                    "refusing throttle after v1 CPU membership changed".to_string(),
                ));
            }
            super::dispatch::ensure_exclusive_cgroup_path(
                action.target.pid.0,
                Path::new(&format!("/sys/fs/cgroup/cpu{expected}")),
            )?;
        }
        Ok(())
    }

    /// Tighten a controller without increasing a pre-existing bandwidth limit.
    /// v1 keeps its period and changes only quota, avoiding a partial two-file
    /// update that could transiently increase bandwidth.
    #[cfg(target_os = "linux")]
    fn apply_throttle_at(
        &self,
        directory: &Path,
        is_v2: bool,
        revalidate: impl Fn() -> Result<(), ActionError>,
    ) -> Result<(), ActionError> {
        let maximum = self.config.validated_limit()?;
        revalidate()?;
        let current = read_cpu_limit(directory, is_v2)?;
        let desired = if current.within(maximum) {
            current
        } else if is_v2 {
            maximum
        } else {
            let quota = (maximum.quota_us as u128) * u128::from(current.period_us)
                / u128::from(maximum.period_us);
            let quota = i64::try_from(quota).map_err(|_| {
                ActionError::Failed(
                    "CPU quota is not representable at the current period".to_string(),
                )
            })?;
            // Never round up to the minimum: that would exceed the requested cap.
            CpuBandwidthLimit::new(quota, current.period_us)?
        };
        revalidate()?;
        if read_cpu_limit(directory, is_v2)? != current {
            return Err(ActionError::Failed(
                "CPU limits changed before applying throttle".to_string(),
            ));
        }
        if desired != current {
            let (path, value) = if is_v2 {
                (
                    directory.join("cpu.max"),
                    format!("{} {}", desired.quota_us, desired.period_us),
                )
            } else {
                (
                    directory.join("cpu.cfs_quota_us"),
                    desired.quota_us.to_string(),
                )
            };
            fs::write(&path, value).map_err(|error| {
                if error.kind() == std::io::ErrorKind::PermissionDenied {
                    ActionError::PermissionDenied
                } else {
                    ActionError::Failed(format!("cannot write {}: {error}", path.display()))
                }
            })?;
        }
        revalidate()?;
        let observed = read_cpu_limit(directory, is_v2)?;
        if observed != desired || !observed.within(maximum) {
            return Err(ActionError::Failed(
                "CPU throttle readback does not match the selected cap".to_string(),
            ));
        }
        revalidate()?;
        info!(
            cgroup = %directory.display(),
            quota_us = observed.quota_us,
            period_us = observed.period_us,
            changed = desired != current,
            is_v2,
            "CPU bandwidth cap verified"
        );
        Ok(())
    }

    /// Verify the live CPU bandwidth is no greater than the requested maximum.
    #[cfg(target_os = "linux")]
    fn verify_throttle(&self, action: &PlanAction) -> Result<(), ActionError> {
        let pid = action.target.pid.0;
        let checked_path = super::dispatch::ensure_cgroup_target(&action.target)?;

        // Re-collect cgroup details to verify
        let cgroup_details = collect_cgroup_details(pid).ok_or_else(|| {
            ActionError::Failed(format!(
                "failed to read cgroup for verification, pid {}",
                pid
            ))
        })?;

        if cgroup_details.unified_path.as_deref() != Some(checked_path.as_str()) {
            return Err(ActionError::Failed(
                "cannot verify throttle after cgroup membership changed".to_string(),
            ));
        }
        let v2_directory = PathBuf::from(format!("/sys/fs/cgroup{checked_path}"));
        let v1_path = self
            .config
            .fallback_to_v1
            .then(|| cgroup_details.v1_paths.get("cpu"))
            .flatten();
        let v1_directory = v1_path.map(|path| PathBuf::from(format!("/sys/fs/cgroup/cpu{path}")));
        let (directory, is_v2) = select_cpu_controller(&v2_directory, v1_directory.as_deref())?;
        let v1_path = if is_v2 {
            None
        } else {
            v1_path.map(String::as_str)
        };
        self.revalidate_membership(action, &checked_path, v1_path)?;
        let observed = read_cpu_limit(&directory, is_v2)?;
        if !quota_within_limit(observed.quota_us, observed.period_us, &self.config)? {
            return Err(ActionError::Failed(
                "CPU bandwidth remains above the requested throttle cap".to_string(),
            ));
        }
        if read_cpu_limit(&directory, is_v2)? != observed {
            return Err(ActionError::Failed(
                "CPU limits changed during throttle verification".to_string(),
            ));
        }
        self.revalidate_membership(action, &checked_path, v1_path)
    }

    /// Capture reversal metadata before applying throttle.
    #[cfg(target_os = "linux")]
    pub fn capture_reversal_metadata(&self, pid: u32) -> Option<ThrottleReversalMetadata> {
        let identity = super::dispatch::read_cgroup_identity(pid)?;
        let cgroup_details = collect_cgroup_details(pid)?;

        let (cgroup_path, previous_quota, previous_period, source) =
            if let Some(ref limits) = cgroup_details.cpu_limits {
                let path = match limits.source {
                    CpuLimitSource::CgroupV2CpuMax => cgroup_details.unified_path.clone()?,
                    CpuLimitSource::CgroupV1Cfs => cgroup_details.v1_paths.get("cpu").cloned()?,
                    CpuLimitSource::None => cgroup_details.unified_path.clone()?,
                };
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
            identity,
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
        if metadata.pid != metadata.identity.pid.0 {
            return Err(ActionError::IdentityMismatch);
        }
        let checked_path = super::dispatch::ensure_cgroup_target(&metadata.identity)?;
        match metadata.source {
            CpuLimitSource::CgroupV2CpuMax => {
                if checked_path != metadata.cgroup_path {
                    return Err(ActionError::Failed(
                        "refusing throttle reversal after cgroup membership changed".to_string(),
                    ));
                }
                let cpu_max_path = format!("/sys/fs/cgroup{}/cpu.max", metadata.cgroup_path);
                let value = match (metadata.previous_quota_us, metadata.previous_period_us) {
                    (Some(q), Some(p)) if q > 0 && p > 0 => format!("{} {}", q, p),
                    (None, Some(p)) if p > 0 => format!("max {}", p),
                    _ => {
                        return Err(ActionError::Failed(
                            "refusing reversal without the recorded previous CPU limits"
                                .to_string(),
                        ));
                    }
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
                let current_cpu_path = collect_cgroup_details(metadata.pid)
                    .and_then(|details| details.v1_paths.get("cpu").cloned());
                if current_cpu_path.as_deref() != Some(metadata.cgroup_path.as_str()) {
                    return Err(ActionError::Failed(
                        "refusing throttle reversal after CPU controller membership changed"
                            .to_string(),
                    ));
                }
                super::dispatch::ensure_exclusive_cgroup_path(
                    metadata.pid,
                    Path::new(&format!("/sys/fs/cgroup/cpu{}", metadata.cgroup_path)),
                )?;
                let quota_path = format!(
                    "/sys/fs/cgroup/cpu{}/cpu.cfs_quota_us",
                    metadata.cgroup_path
                );
                let period_path = format!(
                    "/sys/fs/cgroup/cpu{}/cpu.cfs_period_us",
                    metadata.cgroup_path
                );

                let period = metadata
                    .previous_period_us
                    .filter(|period| *period > 0)
                    .ok_or_else(|| {
                        ActionError::Failed(
                            "refusing reversal without the recorded previous period".to_string(),
                        )
                    })?;
                // The v1 collector represents the kernel's unlimited sentinel
                // (-1) as None, while retaining its controller source and period.
                let quota_value = metadata.previous_quota_us.unwrap_or(-1);
                if quota_value != -1 && quota_value <= 0 {
                    return Err(ActionError::Failed(
                        "invalid recorded previous quota".to_string(),
                    ));
                }
                fs::write(&period_path, period.to_string())
                    .map_err(|e| ActionError::Failed(format!("failed to restore period: {}", e)))?;
                fs::write(&quota_path, quota_value.to_string())
                    .map_err(|e| ActionError::Failed(format!("failed to restore quota: {}", e)))?;

                info!(
                    quota_path = %quota_path,
                    quota = quota_value,
                    "restored CPU limits from reversal metadata (v1)"
                );
                Ok(())
            }
            CpuLimitSource::None => Err(ActionError::Failed(
                "refusing reversal without the recorded previous CPU limits".to_string(),
            )),
        }
    }
}

#[cfg(target_os = "linux")]
impl ActionRunner for CpuThrottleActionRunner {
    fn execute(&self, action: &PlanAction) -> Result<(), ActionError> {
        match action.action {
            Action::Throttle => self.execute_throttle(action),
            Action::Keep => Ok(()),
            Action::Pause
            | Action::Resume
            | Action::Kill
            | Action::Renice
            | Action::Restart
            | Action::Freeze
            | Action::Unfreeze
            | Action::Quarantine
            | Action::Unquarantine => Err(ActionError::Failed(format!(
                "{:?} is not a throttle action",
                action.action
            ))),
        }
    }

    fn verify(&self, action: &PlanAction) -> Result<(), ActionError> {
        match action.action {
            Action::Throttle => self.verify_throttle(action),
            Action::Keep => Ok(()),
            Action::Pause
            | Action::Resume
            | Action::Kill
            | Action::Renice
            | Action::Restart
            | Action::Freeze
            | Action::Unfreeze
            | Action::Quarantine
            | Action::Unquarantine => Ok(()),
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
    let Some(identity) = super::dispatch::read_cgroup_identity(pid) else {
        return false;
    };
    if super::dispatch::ensure_cgroup_target(&identity).is_err() {
        return false;
    }
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

/// Choose v1 only when the v2 controller is absent. A present but unreadable,
/// invalid or unwritable v2 limit is never a reason to mutate another hierarchy.
#[cfg(target_os = "linux")]
fn select_cpu_controller(
    v2_directory: &Path,
    v1_directory: Option<&Path>,
) -> Result<(PathBuf, bool), ActionError> {
    let v2_path = v2_directory.join("cpu.max");
    match fs::metadata(&v2_path) {
        Ok(_) => return Ok((v2_directory.to_path_buf(), true)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(ActionError::Failed(format!(
                "cannot inspect {}: {error}",
                v2_path.display()
            )));
        }
    }
    let directory = v1_directory
        .ok_or_else(|| ActionError::Failed("no cgroup CPU controller is available".to_string()))?;
    let quota_path = directory.join("cpu.cfs_quota_us");
    fs::metadata(&quota_path).map_err(|error| {
        ActionError::Failed(format!("cannot inspect {}: {error}", quota_path.display()))
    })?;
    Ok((directory.to_path_buf(), false))
}

#[cfg(target_os = "linux")]
fn read_cpu_control(path: &Path) -> Result<String, ActionError> {
    fs::read_to_string(path)
        .map_err(|error| ActionError::Failed(format!("cannot read {}: {error}", path.display())))
}

fn parse_cpu_limit(
    quota: &str,
    period: &str,
    is_v2: bool,
) -> Result<CpuBandwidthLimit, ActionError> {
    let quota = quota.trim();
    let period = period.trim();
    let invalid = || ActionError::Failed("invalid CPU bandwidth controller evidence".to_string());
    if period.is_empty() || !period.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid());
    }
    let period = period.parse().map_err(|_| invalid())?;
    let quota = if (is_v2 && quota == "max") || (!is_v2 && quota == "-1") {
        -1
    } else {
        if quota.is_empty() || !quota.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid());
        }
        quota.parse().map_err(|_| invalid())?
    };
    CpuBandwidthLimit::new(quota, period)
}

#[cfg(target_os = "linux")]
fn read_cpu_limit(directory: &Path, is_v2: bool) -> Result<CpuBandwidthLimit, ActionError> {
    if is_v2 {
        let content = read_cpu_control(&directory.join("cpu.max"))?;
        let mut fields = content.split_whitespace();
        let quota = fields
            .next()
            .ok_or_else(|| ActionError::Failed("CPU quota is missing".to_string()))?;
        let period = fields
            .next()
            .ok_or_else(|| ActionError::Failed("CPU period is missing".to_string()))?;
        if fields.next().is_some() {
            return Err(ActionError::Failed(
                "unexpected fields in CPU bandwidth controller evidence".to_string(),
            ));
        }
        parse_cpu_limit(quota, period, true)
    } else {
        let period_path = directory.join("cpu.cfs_period_us");
        let period = read_cpu_control(&period_path)?;
        let quota = read_cpu_control(&directory.join("cpu.cfs_quota_us"))?;
        if read_cpu_control(&period_path)?.trim() != period.trim() {
            return Err(ActionError::Failed(
                "CPU period changed while reading the v1 bandwidth limit".to_string(),
            ));
        }
        parse_cpu_limit(&quota, &period, false)
    }
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
        assert!(config.validated_limit().is_err());
    }

    #[test]
    fn cpu_quota_bound_accepts_equivalent_and_stricter_limits() {
        let config = CpuThrottleConfig::default();
        for (quota, period) in [
            (10_000, 100_000),
            (25_000, 100_000),
            (50_000, 200_000),
            (1_000, 1_000_000),
        ] {
            assert!(quota_within_limit(quota, period, &config).unwrap());
        }
        for (quota, period) in [
            (-1, 100_000),
            (25_001, 100_000),
            (50_000, 100_000),
            (i64::MAX, 1_000_000),
        ] {
            assert!(!quota_within_limit(quota, period, &config).unwrap());
        }
    }

    #[test]
    fn cpu_quota_bound_refuses_invalid_limits_and_configuration() {
        let config = CpuThrottleConfig::default();
        for (quota, period) in [
            (0, 100_000),
            (-2, 100_000),
            (999, 100_000),
            (25_000, 0),
            (25_000, 999),
            (25_000, 1_000_001),
        ] {
            assert!(quota_within_limit(quota, period, &config).is_err());
        }
        for fraction in [0.0, -0.25, f64::NAN, f64::INFINITY, f64::MAX, 0.00001] {
            assert!(quota_within_limit(
                10_000,
                100_000,
                &CpuThrottleConfig::with_fraction(fraction)
            )
            .is_err());
        }
        for period_us in [0, 999, 1_000_001] {
            let invalid = CpuThrottleConfig {
                period_us,
                ..Default::default()
            };
            assert!(quota_within_limit(10_000, 100_000, &invalid).is_err());
        }
    }

    #[test]
    fn cpu_controller_parser_requires_complete_valid_evidence() {
        for (quota, period, is_v2) in [
            ("max", "100000", true),
            ("-1", "100000", false),
            ("25000", "100000", true),
        ] {
            assert!(parse_cpu_limit(quota, period, is_v2).is_ok());
        }
        for (quota, period, is_v2) in [
            ("", "100000", true),
            ("bad", "100000", true),
            ("+25000", "100000", true),
            ("-1", "100000", true),
            ("max", "100000", false),
            ("25000", "100000 extra", false),
            ("25000", "+100000", true),
            ("9223372036854775808", "100000", true),
        ] {
            assert!(parse_cpu_limit(quota, period, is_v2).is_err());
        }
    }

    #[test]
    fn runner_can_be_created() {
        let runner = CpuThrottleActionRunner::with_defaults();
        assert_eq!(runner.config.target_fraction, DEFAULT_THROTTLE_FRACTION);
    }

    #[cfg(target_os = "linux")]
    mod linux_tests {
        use super::*;

        fn controller_fixture(is_v2: bool, quota: &str, period: &str) -> tempfile::TempDir {
            let fixture = tempfile::tempdir().unwrap();
            if is_v2 {
                fs::write(
                    fixture.path().join("cpu.max"),
                    format!("{quota} {period}\n"),
                )
                .unwrap();
            } else {
                fs::write(
                    fixture.path().join("cpu.cfs_quota_us"),
                    format!("{quota}\n"),
                )
                .unwrap();
                fs::write(
                    fixture.path().join("cpu.cfs_period_us"),
                    format!("{period}\n"),
                )
                .unwrap();
            }
            fixture
        }

        #[test]
        fn throttle_preserves_existing_ten_percent_and_equivalent_caps_exactly() {
            let runner = CpuThrottleActionRunner::with_defaults();
            for is_v2 in [true, false] {
                for (quota, period) in [
                    ("10000", "100000"),
                    ("20000", "200000"),
                    ("50000", "200000"),
                ] {
                    let fixture = controller_fixture(is_v2, quota, period);
                    runner
                        .apply_throttle_at(fixture.path(), is_v2, || Ok(()))
                        .unwrap();
                    if is_v2 {
                        assert_eq!(
                            fs::read_to_string(fixture.path().join("cpu.max")).unwrap(),
                            format!("{quota} {period}\n")
                        );
                    } else {
                        assert_eq!(
                            fs::read_to_string(fixture.path().join("cpu.cfs_quota_us")).unwrap(),
                            format!("{quota}\n")
                        );
                        assert_eq!(
                            fs::read_to_string(fixture.path().join("cpu.cfs_period_us")).unwrap(),
                            format!("{period}\n")
                        );
                    }
                }
            }
        }

        #[test]
        fn throttle_tightens_unlimited_and_weaker_v2_caps_to_the_default_maximum() {
            let runner = CpuThrottleActionRunner::with_defaults();
            for quota in ["max", "50000", "100000"] {
                let fixture = controller_fixture(true, quota, "100000");
                runner
                    .apply_throttle_at(fixture.path(), true, || Ok(()))
                    .unwrap();
                assert_eq!(
                    fs::read_to_string(fixture.path().join("cpu.max")).unwrap(),
                    "25000 100000"
                );
            }
        }

        #[test]
        fn throttle_v1_changes_only_quota_at_the_existing_period_and_rounds_down() {
            let runner = CpuThrottleActionRunner::with_defaults();
            for (quota, period, expected) in [
                ("-1", "200000", "50000"),
                ("200000", "200000", "50000"),
                ("333333", "333333", "83333"),
            ] {
                let fixture = controller_fixture(false, quota, period);
                runner
                    .apply_throttle_at(fixture.path(), false, || Ok(()))
                    .unwrap();
                assert_eq!(
                    fs::read_to_string(fixture.path().join("cpu.cfs_quota_us")).unwrap(),
                    expected
                );
                assert_eq!(
                    fs::read_to_string(fixture.path().join("cpu.cfs_period_us")).unwrap(),
                    format!("{period}\n")
                );
                let observed = read_cpu_limit(fixture.path(), false).unwrap();
                assert!(
                    quota_within_limit(observed.quota_us, observed.period_us, &runner.config)
                        .unwrap()
                );
            }
        }

        #[test]
        fn throttle_v1_refuses_an_unrepresentable_cap_without_changing_either_file() {
            let runner = CpuThrottleActionRunner::with_defaults();
            let fixture = controller_fixture(false, "1000", "2000");
            assert!(runner
                .apply_throttle_at(fixture.path(), false, || Ok(()))
                .is_err());
            assert_eq!(
                fs::read_to_string(fixture.path().join("cpu.cfs_quota_us")).unwrap(),
                "1000\n"
            );
            assert_eq!(
                fs::read_to_string(fixture.path().join("cpu.cfs_period_us")).unwrap(),
                "2000\n"
            );
        }

        #[test]
        fn throttle_refuses_invalid_configuration_before_mutating_a_valid_limit() {
            for fraction in [f64::NAN, f64::INFINITY, -1.0, 0.0, 0.00001] {
                let runner =
                    CpuThrottleActionRunner::new(CpuThrottleConfig::with_fraction(fraction));
                let fixture = controller_fixture(true, "10000", "100000");
                assert!(runner
                    .apply_throttle_at(fixture.path(), true, || Ok(()))
                    .is_err());
                assert_eq!(
                    fs::read_to_string(fixture.path().join("cpu.max")).unwrap(),
                    "10000 100000\n"
                );
            }
        }

        #[test]
        fn throttle_refuses_invalid_or_missing_controller_evidence_before_mutation() {
            let runner = CpuThrottleActionRunner::with_defaults();
            for content in [
                "",
                "max",
                "bad 100000",
                "25000 0",
                "25000 100000 extra",
                "999 100000",
            ] {
                let fixture = tempfile::tempdir().unwrap();
                let path = fixture.path().join("cpu.max");
                fs::write(&path, content).unwrap();
                assert!(runner
                    .apply_throttle_at(fixture.path(), true, || Ok(()))
                    .is_err());
                assert_eq!(fs::read_to_string(path).unwrap(), content);
            }
            let fixture = tempfile::tempdir().unwrap();
            let quota_path = fixture.path().join("cpu.cfs_quota_us");
            fs::write(&quota_path, "-1\n").unwrap();
            assert!(runner
                .apply_throttle_at(fixture.path(), false, || Ok(()))
                .is_err());
            assert_eq!(fs::read_to_string(quota_path).unwrap(), "-1\n");
            assert!(!fixture.path().join("cpu.cfs_period_us").exists());
        }

        #[test]
        fn throttle_fallback_requires_an_absent_v2_controller() {
            let runner = CpuThrottleActionRunner::with_defaults();
            let v1 = controller_fixture(false, "-1", "100000");
            for unreadable in [false, true] {
                let v2 = tempfile::tempdir().unwrap();
                if unreadable {
                    fs::create_dir(v2.path().join("cpu.max")).unwrap();
                } else {
                    fs::write(v2.path().join("cpu.max"), "malformed").unwrap();
                }
                let (selected, is_v2) = select_cpu_controller(v2.path(), Some(v1.path())).unwrap();
                assert!(is_v2);
                assert!(runner
                    .apply_throttle_at(&selected, is_v2, || Ok(()))
                    .is_err());
                assert_eq!(
                    fs::read_to_string(v1.path().join("cpu.cfs_quota_us")).unwrap(),
                    "-1\n"
                );
                assert_eq!(
                    fs::read_to_string(v1.path().join("cpu.cfs_period_us")).unwrap(),
                    "100000\n"
                );
            }
            let absent_v2 = tempfile::tempdir().unwrap();
            let (selected, is_v2) =
                select_cpu_controller(absent_v2.path(), Some(v1.path())).unwrap();
            assert!(!is_v2);
            runner
                .apply_throttle_at(&selected, is_v2, || Ok(()))
                .unwrap();
            assert_eq!(
                fs::read_to_string(v1.path().join("cpu.cfs_quota_us")).unwrap(),
                "25000"
            );
            assert_eq!(
                fs::read_to_string(v1.path().join("cpu.cfs_period_us")).unwrap(),
                "100000\n"
            );
        }

        #[test]
        fn throttle_preserves_a_concurrent_stricter_limit_instead_of_overwriting_it() {
            let runner = CpuThrottleActionRunner::with_defaults();
            let fixture = controller_fixture(true, "max", "100000");
            let checks = std::cell::Cell::new(0);
            let path = fixture.path().join("cpu.max");
            let result = runner.apply_throttle_at(fixture.path(), true, || {
                checks.set(checks.get() + 1);
                if checks.get() == 2 {
                    // A different controller owner tightens the limit after the
                    // initial snapshot and before our mutation.
                    fs::write(&path, "1000 100000").unwrap();
                }
                Ok(())
            });
            assert!(result.is_err());
            assert_eq!(fs::read_to_string(path).unwrap(), "1000 100000");
        }

        #[test]
        fn throttle_requires_identity_before_mutation_and_before_success() {
            let runner = CpuThrottleActionRunner::with_defaults();
            for failure_check in [1, 3] {
                let fixture = controller_fixture(true, "max", "100000");
                let checks = std::cell::Cell::new(0);
                let result = runner.apply_throttle_at(fixture.path(), true, || {
                    checks.set(checks.get() + 1);
                    if checks.get() == failure_check {
                        Err(ActionError::IdentityMismatch)
                    } else {
                        Ok(())
                    }
                });
                assert!(matches!(result, Err(ActionError::IdentityMismatch)));
                assert_eq!(
                    fs::read_to_string(fixture.path().join("cpu.max")).unwrap(),
                    if failure_check == 1 {
                        "max 100000\n"
                    } else {
                        "25000 100000"
                    }
                );
            }
        }

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
