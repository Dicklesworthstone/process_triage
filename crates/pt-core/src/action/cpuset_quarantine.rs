//! Cgroup cpuset quarantine action execution.
//!
//! Implements process quarantine by restricting CPU access via cgroup cpuset with:
//! - Automatic cgroup path discovery for target process
//! - Reversal metadata capture for undo operations
//! - Verification of both requested and effective CPU identities
//! - Cgroup v2 and isolated hybrid v1 cpuset controllers
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
//! - Explicit reversal metadata restores the previous cpuset configuration;
//!   a bare Unquarantine action cannot reconstruct it and is refused

use super::executor::{ActionError, ActionRunner};
use crate::collect::cgroup::collect_cgroup_details;
use crate::decision::Action;
use crate::plan::PlanAction;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
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
    /// If None, the lowest N currently effective CPUs will be used.
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

    /// Select a nonempty cpuset from the target's currently effective CPUs.
    ///
    /// Explicit assignments must be available; count-based assignments use at
    /// most the CPUs already granted to the target and never broaden its set.
    pub fn cpuset_string(&self, available: &str) -> Result<String, ActionError> {
        select_cpuset(
            self.target_cpus,
            self.specific_cpus.as_deref(),
            &CpuSet::parse(available)?,
        )
        .map(|cpus| cpus.as_list())
    }
}

/// Captured state for reversal of quarantine action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineReversalMetadata {
    /// PID of the quarantined process.
    pub pid: u32,

    /// Exact process incarnation whose previous CPU set was captured.
    pub identity: pt_common::ProcessIdentity,

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
    // ActionExecutor executes and verifies one action at a time. Retaining the
    // exact last assignment avoids deriving expectations from mutable readback.
    applied: Mutex<Option<AppliedQuarantine>>,
}

#[derive(Debug, Clone)]
struct CpusetScope {
    unified_path: String,
    controller_path: String,
    is_v2: bool,
}

impl CpusetScope {
    fn directory(&self) -> PathBuf {
        let root = if self.is_v2 {
            "/sys/fs/cgroup"
        } else {
            "/sys/fs/cgroup/cpuset"
        };
        PathBuf::from(format!("{root}{}", self.controller_path))
    }

    fn effective_name(&self) -> &'static str {
        if self.is_v2 {
            "cpuset.cpus.effective"
        } else {
            "cpuset.effective_cpus"
        }
    }

    #[cfg(target_os = "linux")]
    fn revalidate(&self, identity: &pt_common::ProcessIdentity) -> Result<(), ActionError> {
        let checked_path = super::dispatch::ensure_cgroup_target(identity)?;
        if checked_path != self.unified_path {
            return Err(ActionError::Failed(
                "refusing quarantine after cgroup membership changed".to_string(),
            ));
        }
        if !self.is_v2 {
            let current_path = collect_cgroup_details(identity.pid.0)
                .and_then(|details| details.v1_paths.get("cpuset").cloned());
            if current_path.as_deref() != Some(self.controller_path.as_str()) {
                return Err(ActionError::Failed(
                    "refusing quarantine after cpuset controller membership changed".to_string(),
                ));
            }
        }
        super::dispatch::ensure_exclusive_cgroup_path(identity.pid.0, &self.directory())
    }
}

#[derive(Debug, Clone)]
struct AppliedQuarantine {
    action_id: String,
    identity: pt_common::ProcessIdentity,
    scope: CpusetScope,
    cpus: CpuSet,
}

impl CpusetQuarantineActionRunner {
    pub fn new(config: CpusetQuarantineConfig) -> Self {
        Self {
            config,
            applied: Mutex::new(None),
        }
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
        let mut applied = self.applied.lock().map_err(|_| {
            ActionError::Failed("quarantine execution record is unavailable".to_string())
        })?;
        *applied = None;
        let pid = action.target.pid.0;
        let checked_path = super::dispatch::ensure_cgroup_target(&action.target)?;
        debug!(
            pid,
            cpus = self.config.target_cpus,
            "executing cpuset quarantine"
        );

        let comm = fs::read_to_string(format!("/proc/{pid}/comm"))
            .map_err(|error| ActionError::Failed(format!("cannot read target name: {error}")))?;
        if self.is_protected(comm.trim()) {
            return Err(ActionError::Failed(
                "refusing quarantine for a configured protected process name".to_string(),
            ));
        }

        // Collect cgroup details for the target process
        let cgroup_details = collect_cgroup_details(pid)
            .ok_or_else(|| ActionError::Failed(format!("failed to read cgroup for pid {}", pid)))?;
        if cgroup_details.unified_path.as_deref() != Some(checked_path.as_str()) {
            return Err(ActionError::Failed(
                "refusing quarantine after cgroup membership changed".to_string(),
            ));
        }

        let v2_directory = PathBuf::from(format!("/sys/fs/cgroup{checked_path}"));
        let v1_path = self
            .config
            .fallback_to_v1
            .then(|| cgroup_details.v1_paths.get("cpuset"))
            .flatten();
        let v1_directory =
            v1_path.map(|path| PathBuf::from(format!("/sys/fs/cgroup/cpuset{path}")));
        let (_, is_v2) = select_cpuset_controller(&v2_directory, v1_directory.as_deref())?;
        let controller_path = if is_v2 {
            checked_path.clone()
        } else {
            warn!(
                pid,
                "cgroup v2 cpuset unavailable, using isolated v1 controller"
            );
            v1_path
                .cloned()
                .ok_or_else(|| ActionError::Failed("missing v1 cpuset membership".to_string()))?
        };
        let scope = CpusetScope {
            unified_path: checked_path,
            controller_path,
            is_v2,
        };
        *applied = Some(self.apply_quarantine(action, scope)?);
        Ok(())
    }

    /// Apply quarantine using the selected controller's actual effective CPUs.
    #[cfg(target_os = "linux")]
    fn apply_quarantine(
        &self,
        action: &PlanAction,
        scope: CpusetScope,
    ) -> Result<AppliedQuarantine, ActionError> {
        scope.revalidate(&action.target)?;
        let directory = scope.directory();
        let cpus_path = directory.join("cpuset.cpus");
        let available = read_cpuset_file(&directory.join(scope.effective_name()))?;
        let cpus = select_cpuset(
            self.config.target_cpus,
            self.config.specific_cpus.as_deref(),
            &available,
        )?;
        let new_cpuset = cpus.as_list();

        // Recheck the process incarnation and both controller memberships after
        // reading availability, immediately before the cgroup-wide write.
        scope.revalidate(&action.target)?;
        let pid = action.target.pid.0;

        debug!(
            pid,
            path = %cpus_path.display(),
            value = %new_cpuset,
            "writing cpuset.cpus"
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
            cgroup = %scope.controller_path,
            is_v2 = scope.is_v2,
            cpuset = %new_cpuset,
            "cpuset quarantine assignment written"
        );

        Ok(AppliedQuarantine {
            action_id: action.action_id.clone(),
            identity: action.target.clone(),
            scope,
            cpus,
        })
    }

    /// Execute an unquarantine action (restore previous cpuset).
    #[cfg(target_os = "linux")]
    fn execute_unquarantine(&self, action: &PlanAction) -> Result<(), ActionError> {
        super::dispatch::ensure_cgroup_target(&action.target)?;
        Err(ActionError::Failed(
            "unquarantine requires the recorded previous cpuset; restore from reversal metadata"
                .to_string(),
        ))
    }

    /// Verify the exact assignment and a nonempty effective subset on the same
    /// process incarnation and controller used by this runner's last execution.
    #[cfg(target_os = "linux")]
    fn verify_quarantine(&self, action: &PlanAction) -> Result<(), ActionError> {
        let applied = self.applied.lock().map_err(|_| {
            ActionError::Failed("quarantine execution record is unavailable".to_string())
        })?;
        let record = applied.as_ref().ok_or_else(|| {
            ActionError::Failed(
                "cannot verify quarantine without an executed assignment".to_string(),
            )
        })?;
        if record.action_id != action.action_id || record.identity != action.target {
            return Err(ActionError::IdentityMismatch);
        }
        record.scope.revalidate(&action.target)?;
        verify_cpuset_files(
            &record.scope.directory(),
            record.scope.effective_name(),
            &record.cpus,
        )?;
        record.scope.revalidate(&action.target)?;
        debug!(
            pid = action.target.pid.0,
            cpuset = %record.cpus.as_list(),
            "quarantine requested and effective CPUs verified"
        );
        Ok(())
    }

    /// Capture reversal metadata before applying quarantine.
    #[cfg(target_os = "linux")]
    pub fn capture_reversal_metadata(&self, pid: u32) -> Option<QuarantineReversalMetadata> {
        let identity = super::dispatch::read_cgroup_identity(pid)?;
        let cgroup_details = collect_cgroup_details(pid)?;

        // Try v2 first
        if let Some(ref unified_path) = cgroup_details.unified_path {
            let cpuset_path = format!("/sys/fs/cgroup{}/cpuset.cpus", unified_path);
            let effective_path = format!("/sys/fs/cgroup{}/cpuset.cpus.effective", unified_path);

            if let Ok(previous) = fs::read_to_string(&cpuset_path) {
                let effective = fs::read_to_string(&effective_path).ok();
                return Some(QuarantineReversalMetadata {
                    pid,
                    identity,
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
                    identity,
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
        if metadata.pid != metadata.identity.pid.0 {
            return Err(ActionError::IdentityMismatch);
        }
        let checked_path = super::dispatch::ensure_cgroup_target(&metadata.identity)?;
        if !metadata.is_v2 || checked_path != metadata.cgroup_path {
            return Err(ActionError::Failed(
                "refusing cpuset reversal without unchanged cgroup v2 membership".to_string(),
            ));
        }
        let cpuset_path = if metadata.is_v2 {
            format!("/sys/fs/cgroup{}/cpuset.cpus", metadata.cgroup_path)
        } else {
            format!("/sys/fs/cgroup/cpuset{}/cpuset.cpus", metadata.cgroup_path)
        };

        restore_cpuset_assignment(Path::new(&cpuset_path), &metadata.previous_cpuset)?;

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
            Action::Pause
            | Action::Resume
            | Action::Kill
            | Action::Renice
            | Action::Restart
            | Action::Freeze
            | Action::Unfreeze
            | Action::Throttle => Err(ActionError::Failed(format!(
                "{:?} is not a quarantine action",
                action.action
            ))),
        }
    }

    fn verify(&self, action: &PlanAction) -> Result<(), ActionError> {
        match action.action {
            Action::Quarantine => self.verify_quarantine(action),
            Action::Unquarantine => Err(ActionError::Failed(
                "cannot verify unquarantine without the recorded previous cpuset".to_string(),
            )),
            Action::Keep => Ok(()),
            Action::Pause
            | Action::Resume
            | Action::Kill
            | Action::Renice
            | Action::Restart
            | Action::Freeze
            | Action::Unfreeze
            | Action::Throttle => Ok(()),
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
    let Some(identity) = super::dispatch::read_cgroup_identity(pid) else {
        return false;
    };
    super::dispatch::cgroup_action_feasibility(&identity).is_allowed(Action::Quarantine)
}

#[cfg(not(target_os = "linux"))]
pub fn can_quarantine_cpuset(_pid: u32) -> bool {
    false
}

/// Planning and execution select the same hierarchy. Present but broken v2
/// controls must not silently redirect an action into a different v1 hierarchy.
#[cfg(target_os = "linux")]
fn select_cpuset_controller(
    v2_directory: &Path,
    v1_directory: Option<&Path>,
) -> Result<(PathBuf, bool), ActionError> {
    let cpus_path = v2_directory.join("cpuset.cpus");
    if cpus_path.try_exists().map_err(|error| {
        ActionError::Failed(format!("cannot inspect {}: {error}", cpus_path.display()))
    })? {
        return Ok((v2_directory.to_path_buf(), true));
    }
    let directory = v1_directory.ok_or_else(|| {
        ActionError::Failed("no cgroup cpuset controller is available".to_string())
    })?;
    let cpus_path = directory.join("cpuset.cpus");
    fs::metadata(&cpus_path).map_err(|error| {
        ActionError::Failed(format!("cannot inspect {}: {error}", cpus_path.display()))
    })?;
    Ok((directory.to_path_buf(), false))
}

#[cfg(target_os = "linux")]
pub(super) fn check_quarantine_capability(
    pid: u32,
    comm: &str,
    v2_directory: &Path,
    v1_directory: Option<&Path>,
) -> Result<(), ActionError> {
    let config = CpusetQuarantineConfig::default();
    if config.protected_names.contains(comm) {
        return Err(ActionError::Failed(
            "refusing quarantine for a configured protected process name".to_string(),
        ));
    }
    let (directory, is_v2) = select_cpuset_controller(v2_directory, v1_directory)?;
    if !is_v2 {
        super::dispatch::ensure_exclusive_cgroup_path(pid, &directory)?;
    }
    let cpus_path = directory.join("cpuset.cpus");
    super::dispatch::check_controller_access(&cpus_path)?;
    let previous = fs::read_to_string(&cpus_path).map_err(|error| {
        ActionError::Failed(format!("cannot read {}: {error}", cpus_path.display()))
    })?;
    // Empty assignments inherit CPUs and are valid reversal evidence. Effective
    // CPUs must still form a nonempty set accepted by the execution selector.
    if !previous.trim().is_empty() {
        CpuSet::parse(&previous)?;
    }
    let available = read_cpuset_file(&directory.join(if is_v2 {
        "cpuset.cpus.effective"
    } else {
        "cpuset.effective_cpus"
    }))?;
    select_cpuset(
        config.target_cpus,
        config.specific_cpus.as_deref(),
        &available,
    )?;
    Ok(())
}

// Bound control-file reads and parsing work without imposing a CPU-ID limit or
// expanding a potentially enormous range into individual CPUs.
const MAX_CPUSET_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CpuSet {
    // Sorted, nonoverlapping inclusive intervals; always nonempty.
    ranges: Vec<(u32, u32)>,
}

impl CpuSet {
    pub(crate) fn parse(input: &str) -> Result<Self, ActionError> {
        if input.len() > MAX_CPUSET_BYTES {
            return Err(ActionError::Failed(
                "CPU list exceeds the size limit".to_string(),
            ));
        }
        let input = input.trim();
        if input.is_empty() {
            return Err(ActionError::Failed(
                "empty CPU list cannot establish quarantine".to_string(),
            ));
        }
        let parse_id = |value: &str| {
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(ActionError::Failed("invalid CPU list token".to_string()));
            }
            value
                .parse::<u32>()
                .map_err(|_| ActionError::Failed("CPU ID is out of range".to_string()))
        };
        let mut ranges = Vec::new();
        for part in input.split(',') {
            let (start, end) = match part.split_once('-') {
                Some((start, end)) => (parse_id(start)?, parse_id(end)?),
                None => {
                    let cpu = parse_id(part)?;
                    (cpu, cpu)
                }
            };
            if start > end {
                return Err(ActionError::Failed("descending CPU range".to_string()));
            }
            ranges.push((start, end));
        }
        ranges.sort_unstable();
        let mut merged: Vec<(u32, u32)> = Vec::with_capacity(ranges.len());
        for (start, end) in ranges {
            if let Some(last) = merged.last_mut() {
                if start <= last.1.saturating_add(1) {
                    last.1 = last.1.max(end);
                    continue;
                }
            }
            merged.push((start, end));
        }
        Ok(Self { ranges: merged })
    }

    fn is_subset_of(&self, other: &Self) -> bool {
        let mut outer = other.ranges.iter().peekable();
        for &(start, end) in &self.ranges {
            while outer.peek().is_some_and(|&&(_, upper)| upper < start) {
                outer.next();
            }
            if !outer
                .peek()
                .is_some_and(|&&(lower, upper)| lower <= start && end <= upper)
            {
                return false;
            }
        }
        true
    }

    pub(crate) fn first(&self, count: u32) -> Self {
        let mut remaining = u64::from(count);
        let mut ranges = Vec::new();
        for &(start, end) in &self.ranges {
            if remaining == 0 {
                break;
            }
            let length = u64::from(end) - u64::from(start) + 1;
            let take = remaining.min(length);
            // take <= end-start+1, so the resulting endpoint fits in u32.
            ranges.push((start, (u64::from(start) + take - 1) as u32));
            remaining -= take;
        }
        Self { ranges }
    }

    pub(crate) fn as_list(&self) -> String {
        self.ranges
            .iter()
            .map(|&(start, end)| {
                if start == end {
                    start.to_string()
                } else {
                    format!("{start}-{end}")
                }
            })
            .collect::<Vec<_>>()
            .join(",")
    }
}

fn select_cpuset(
    target_cpus: u32,
    specific_cpus: Option<&str>,
    available: &CpuSet,
) -> Result<CpuSet, ActionError> {
    if let Some(specific) = specific_cpus {
        let requested = CpuSet::parse(specific)?;
        if !requested.is_subset_of(available) {
            return Err(ActionError::Failed(format!(
                "requested CPUs {} are not within the target's effective CPUs {}",
                requested.as_list(),
                available.as_list()
            )));
        }
        Ok(requested)
    } else if target_cpus < MIN_QUARANTINE_CPUS {
        Err(ActionError::Failed(
            "quarantine requires at least one CPU".to_string(),
        ))
    } else {
        Ok(available.first(target_cpus))
    }
}

fn read_cpuset_file(path: &Path) -> Result<CpuSet, ActionError> {
    let mut content = String::new();
    fs::File::open(path)
        .and_then(|file| {
            file.take(MAX_CPUSET_BYTES as u64 + 1)
                .read_to_string(&mut content)
        })
        .map_err(|error| ActionError::Failed(format!("cannot read {}: {error}", path.display())))?;
    CpuSet::parse(&content).map_err(|error| {
        ActionError::Failed(format!(
            "invalid CPU evidence at {}: {error}",
            path.display()
        ))
    })
}

fn verify_cpuset_readback(
    expected: &CpuSet,
    configured: &CpuSet,
    effective: &CpuSet,
) -> Result<(), ActionError> {
    if configured != expected {
        return Err(ActionError::Failed(format!(
            "cpuset mismatch: wrote {}, observed {}",
            expected.as_list(),
            configured.as_list()
        )));
    }
    // Empty or entirely unavailable v2 assignments inherit the parent's CPUs.
    // Require actual CPU identities, not just an equal or smaller CPU count.
    if !effective.is_subset_of(expected) {
        return Err(ActionError::Failed(format!(
            "effective CPUs {} escape quarantine assignment {}",
            effective.as_list(),
            expected.as_list()
        )));
    }
    Ok(())
}

fn verify_cpuset_files(
    directory: &Path,
    effective_name: &str,
    expected: &CpuSet,
) -> Result<(), ActionError> {
    let configured = read_cpuset_file(&directory.join("cpuset.cpus"))?;
    let effective = read_cpuset_file(&directory.join(effective_name))?;
    verify_cpuset_readback(expected, &configured, &effective)
}

fn restore_cpuset_assignment(path: &Path, previous: &str) -> Result<(), ActionError> {
    // Empty cpuset.cpus means inheritance, but a zero-byte write does not reach
    // the kernfs controller handler. A newline supplies the nonempty write that
    // clears an explicit assignment; it also preserves nonempty CPU-list values.
    let value = format!("{}\n", previous.trim());
    fs::write(path, value)
        .map_err(|error| ActionError::Failed(format!("failed to restore cpuset: {error}")))?;
    let restored = fs::read_to_string(path)
        .map_err(|error| ActionError::Failed(format!("cannot verify restored cpuset: {error}")))?;
    if restored.trim() != previous.trim() {
        return Err(ActionError::Failed(
            "restored cpuset does not match reversal metadata".to_string(),
        ));
    }
    Ok(())
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
    fn cpuset_selection_uses_available_cpu_identities() {
        let config = CpusetQuarantineConfig::with_cpus(1);
        assert_eq!(config.cpuset_string("8-11,16").unwrap(), "8");

        let config = CpusetQuarantineConfig::with_cpus(4);
        assert_eq!(config.cpuset_string("2-3,8-9,16").unwrap(), "2-3,8-9");
        assert_eq!(config.cpuset_string("8-9").unwrap(), "8-9");

        let config = CpusetQuarantineConfig::with_specific_cpus("2,4,6");
        assert_eq!(config.cpuset_string("0-7").unwrap(), "2,4,6");
        assert!(config.cpuset_string("4-9").is_err());
    }

    #[test]
    fn cpuset_selection_refuses_invalid_or_empty_assignments() {
        let zero = CpusetQuarantineConfig {
            target_cpus: 0,
            ..Default::default()
        };
        assert!(zero.cpuset_string("0-3").is_err());
        for input in ["", "  ", "5-2", "0-3,broken", "1,,2", "4294967296"] {
            assert!(CpusetQuarantineConfig::with_specific_cpus(input)
                .cpuset_string("0-7")
                .is_err());
            assert!(CpusetQuarantineConfig::default()
                .cpuset_string(input)
                .is_err());
        }
        assert_eq!(
            CpusetQuarantineConfig::with_cpus(u32::MAX)
                .cpuset_string("8-9")
                .unwrap(),
            "8-9"
        );
    }

    #[test]
    fn cpuset_parser_normalizes_without_expanding_ranges() {
        assert_eq!(
            CpuSet::parse("4-6,0-3,3-4,9,9\n").unwrap().as_list(),
            "0-6,9"
        );
        assert_eq!(CpuSet::parse("5-5").unwrap().as_list(), "5");
        let full = CpuSet::parse("0-4294967295").unwrap();
        assert_eq!(full.ranges, vec![(0, u32::MAX)]);
        assert_eq!(full.first(2).as_list(), "0-1");
        assert_eq!(full.first(u32::MAX).as_list(), "0-4294967294");
        let last = CpuSet::parse("4294967295").unwrap();
        assert_eq!(last.first(u32::MAX), last);
        assert!(last.is_subset_of(&full));
    }

    #[test]
    fn cpuset_parser_rejects_malformed_and_oversized_evidence() {
        for input in [
            "",
            "\n",
            ",",
            "0,",
            ",1",
            "0,,1",
            "1-",
            "-1",
            "1-2-3",
            "3-1",
            "+1",
            "0, 1",
            "0-1,unknown",
            "4294967296",
            "0-4294967296",
        ] {
            assert!(CpuSet::parse(input).is_err(), "accepted {input:?}");
        }
        assert!(CpuSet::parse(&"0".repeat(MAX_CPUSET_BYTES + 1)).is_err());
    }

    #[test]
    fn cpuset_subset_compares_ranges_not_counts() {
        let available = CpuSet::parse("1-3,8-10,20").unwrap();
        for subset in ["1", "2-3,8,20", "1-3,8-10,20"] {
            assert!(CpuSet::parse(subset).unwrap().is_subset_of(&available));
        }
        for other in ["0", "4", "1-8", "3-8", "1-3,8-11", "21"] {
            assert!(!CpuSet::parse(other).unwrap().is_subset_of(&available));
        }
    }

    #[test]
    fn selection_matches_independent_small_set_oracle() {
        for mask in 1u32..256 {
            let available_ids: Vec<u32> = (0..8).filter(|cpu| mask & (1 << cpu) != 0).collect();
            let input = available_ids
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(",");
            let available = CpuSet::parse(&input).unwrap();
            for count in 0..=9 {
                let selected = select_cpuset(count, None, &available);
                if count == 0 {
                    assert!(selected.is_err());
                    continue;
                }
                let actual = selected.unwrap();
                let actual_ids: Vec<u32> = actual
                    .ranges
                    .iter()
                    .flat_map(|&(start, end)| start..=end)
                    .collect();
                let expected = available_ids
                    .iter()
                    .copied()
                    .take(count as usize)
                    .collect::<Vec<_>>();
                assert_eq!(actual_ids, expected);
            }
            for requested_mask in 1u32..256 {
                let requested = (0..8)
                    .filter(|cpu| requested_mask & (1 << cpu) != 0)
                    .map(|cpu| cpu.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                let selected = select_cpuset(1, Some(&requested), &available);
                assert_eq!(selected.is_ok(), requested_mask & !mask == 0);
            }
        }
    }

    #[test]
    fn quarantine_readback_requires_exact_assignment_and_effective_subset() {
        let expected = CpuSet::parse("8-9").unwrap();
        let canonical = CpuSet::parse("9,8").unwrap();
        let offline_subset = CpuSet::parse("9").unwrap();
        assert!(verify_cpuset_readback(&expected, &canonical, &offline_subset).is_ok());
        assert!(verify_cpuset_readback(&expected, &expected, &expected).is_ok());
        for (configured, effective) in [
            ("0-1", "0-1"),  // Equal counts, wrong CPUs.
            ("8", "8"),      // A different configured assignment, even if stricter.
            ("8-9", "0"),    // Fewer CPUs can still be the wrong CPUs.
            ("8-9", "0-15"), // Inheritance when requested CPUs become unavailable.
        ] {
            assert!(verify_cpuset_readback(
                &expected,
                &CpuSet::parse(configured).unwrap(),
                &CpuSet::parse(effective).unwrap(),
            )
            .is_err());
        }
    }

    #[test]
    fn quarantine_file_verification_refuses_inheritance_and_missing_evidence() {
        let directory = tempfile::tempdir().unwrap();
        let configured = directory.path().join("cpuset.cpus");
        let effective = directory.path().join("cpuset.cpus.effective");
        let expected = CpuSet::parse("8-9").unwrap();
        assert!(verify_cpuset_files(directory.path(), "cpuset.cpus.effective", &expected).is_err());
        fs::write(&configured, "8-9\n").unwrap();
        assert!(verify_cpuset_files(directory.path(), "cpuset.cpus.effective", &expected).is_err());
        fs::write(&effective, "9\n").unwrap();
        assert!(verify_cpuset_files(directory.path(), "cpuset.cpus.effective", &expected).is_ok());

        for content in ["", "0-15\n", "8-9,invalid\n"] {
            fs::write(&effective, content).unwrap();
            assert!(
                verify_cpuset_files(directory.path(), "cpuset.cpus.effective", &expected).is_err()
            );
        }
        fs::write(&effective, "8-9\n").unwrap();
        fs::write(&configured, "\n").unwrap();
        assert!(verify_cpuset_files(directory.path(), "cpuset.cpus.effective", &expected).is_err());

        fs::write(&configured, "8-9\n").unwrap();
        // A v1 receipt must not accidentally verify against the v2 effective file.
        assert!(verify_cpuset_files(directory.path(), "cpuset.effective_cpus", &expected).is_err());
        fs::write(directory.path().join("cpuset.effective_cpus"), "8\n").unwrap();
        assert!(verify_cpuset_files(directory.path(), "cpuset.effective_cpus", &expected).is_ok());
    }

    #[test]
    fn cpuset_file_reader_bounds_size_and_refuses_unreadable_content() {
        let directory = tempfile::tempdir().unwrap();
        assert!(read_cpuset_file(directory.path()).is_err());
        let path = directory.path().join("cpus");
        fs::write(&path, b"8,\xff").unwrap();
        assert!(read_cpuset_file(&path).is_err());
        fs::write(&path, "0,".repeat(MAX_CPUSET_BYTES)).unwrap();
        assert!(read_cpuset_file(&path).is_err());
    }

    #[test]
    fn cpuset_restoration_writes_inherited_and_explicit_assignments() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("cpuset.cpus");
        fs::write(&path, "8\n").unwrap();

        // Exercise the production restoration write/readback helper. Checking
        // the bytes (not trimmed text) detects the zero-byte kernfs-write bug.
        restore_cpuset_assignment(&path, "").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"\n");

        restore_cpuset_assignment(&path, "4,8-9").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"4,8-9\n");
        restore_cpuset_assignment(&path, " 4,8-9\n").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"4,8-9\n");
        assert!(restore_cpuset_assignment(directory.path(), "").is_err());
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

        fn quarantine_action() -> PlanAction {
            PlanAction {
                action_id: "test-quarantine".to_string(),
                target: pt_common::ProcessIdentity::new(
                    123,
                    pt_common::StartId("test-boot:123:456".to_string()),
                    1000,
                ),
                action: Action::Quarantine,
                order: 0,
                stage: 0,
                timeouts: Default::default(),
                pre_checks: vec![],
                rationale: crate::plan::ActionRationale {
                    expected_loss: None,
                    expected_recovery: None,
                    expected_recovery_stddev: None,
                    posterior_odds_abandoned_vs_useful: None,
                    sprt_boundary: None,
                    posterior: None,
                    memory_mb: None,
                    has_known_signature: None,
                    category: None,
                },
                on_success: vec![],
                on_failure: vec![],
                blocked: false,
                routing: Default::default(),
                confidence: Default::default(),
                original_zombie_target: None,
                d_state_diagnostics: None,
                supervisor_restart: None,
            }
        }

        #[test]
        fn quarantine_verification_requires_matching_execution() {
            let runner = CpusetQuarantineActionRunner::with_defaults();
            let action = quarantine_action();
            let missing = runner.verify(&action).unwrap_err().to_string();
            assert!(missing.contains("without an executed assignment"));
            *runner.applied.lock().unwrap() = Some(AppliedQuarantine {
                action_id: action.action_id.clone(),
                identity: action.target.clone(),
                scope: CpusetScope {
                    unified_path: "/test-only".to_string(),
                    controller_path: "/test-only".to_string(),
                    is_v2: true,
                },
                cpus: CpuSet::parse("8").unwrap(),
            });
            for field in ["action", "birth", "pid", "uid", "quality"] {
                let mut changed = action.clone();
                match field {
                    "action" => changed.action_id.push_str("-different"),
                    "birth" => changed.target.start_id.0.push_str("-different"),
                    "pid" => changed.target.pid.0 += 1,
                    "uid" => changed.target.uid += 1,
                    "quality" => changed.target.quality = pt_common::IdentityQuality::PidOnly,
                    _ => unreachable!(),
                }
                assert!(
                    matches!(runner.verify(&changed), Err(ActionError::IdentityMismatch)),
                    "accepted mismatched {field}"
                );
            }

            // A new refused execution cannot retain a prior successful receipt.
            let mut protected = action.clone();
            protected.target.pid.0 = 1;
            assert!(runner.execute(&protected).is_err());
            assert!(runner.applied.lock().unwrap().is_none());
            assert!(runner
                .verify(&action)
                .unwrap_err()
                .to_string()
                .contains("without an executed assignment"));
        }

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
                let root = if meta.is_v2 {
                    "/sys/fs/cgroup"
                } else {
                    "/sys/fs/cgroup/cpuset"
                };
                let actual =
                    fs::read_to_string(format!("{root}{}/cpuset.cpus", meta.cgroup_path)).unwrap();
                // Empty is a legitimate inherited pre-action setting; capture
                // must retain it exactly rather than inventing explicit CPUs.
                assert_eq!(meta.previous_cpuset, actual.trim());
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
