//! Planned, reversible memory throttling through an exclusive cgroup-v2 leaf.
//!
//! Only `memory.high` is written. The requested value, original controller value,
//! process incarnation and kernel cgroup identity are all bound into the plan.
//! A configured cap is not evidence that memory was reclaimed: the kernel may
//! exceed this soft boundary, and measured relief remains a separate observation.

use super::executor::ActionError;
use super::reversal::ReversalScope;
use pt_common::{IdentityQuality, ProcessIdentity};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[cfg(target_os = "linux")]
use {
    super::executor::ActionRunner,
    super::reversal::{PreparedReversal, ReversalJournal, ReversalStatus, ReversalValue},
    crate::decision::Action,
    crate::plan::{ActionRouting, PlanAction},
    std::{
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        os::{fd::AsRawFd, unix::fs::MetadataExt, unix::fs::OpenOptionsExt},
        path::{Path, PathBuf},
        sync::{Arc, Mutex},
    },
};

/// Never propose a soft memory limit smaller than 64 MiB.
pub const MIN_MEMORY_CAP_BYTES: u64 = 64 * 1024 * 1024;

/// Exact request reviewed by the operator. `None` for the original high value
/// means the kernel's `max` sentinel, not an unavailable observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemoryCapPlan {
    pub target: ProcessIdentity,
    pub scope: ReversalScope,
    pub limit_bytes: u64,
    pub observed_high_bytes: Option<u64>,
    pub observed_current_bytes: u64,
    pub observed_low_bytes: u64,
    pub observed_min_bytes: u64,
    pub page_size_bytes: u64,
}

impl MemoryCapPlan {
    /// Validate the immutable plan without collecting or changing live state.
    pub fn validate(&self, target: &ProcessIdentity) -> Result<(), ActionError> {
        let path = &self.scope.cgroup_path;
        let mut birth = target.start_id.0.split(':');
        if self.target != *target
            || target.quality != IdentityQuality::Full
            || target.pid.0 <= 1
            || !uuid::Uuid::parse_str(&self.scope.boot_id)
                .is_ok_and(|id| id.to_string() == self.scope.boot_id)
            || birth.next() != Some(self.scope.boot_id.as_str())
            || !birth
                .next()
                .is_some_and(|ticks| ticks.parse::<u64>().is_ok_and(|ticks| ticks > 0))
            || !birth
                .next()
                .is_some_and(|pid| pid.parse::<u32>() == Ok(target.pid.0))
            || birth.next().is_some()
            || !path.starts_with('/')
            || path == "/"
            || path.len() > 4096
            || path.chars().any(char::is_control)
            || path[1..]
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            || self.scope.inode == 0
            || self.scope.mount_id == 0
            || self.scope.mount_namespace_inode == 0
            || self.scope.cgroup_namespace_inode == 0
        {
            return Err(failed(
                "memory cap requires the complete original process and cgroup identity",
            ));
        }
        let expected = choose_limit(
            self.observed_current_bytes,
            self.observed_high_bytes,
            self.observed_low_bytes,
            self.observed_min_bytes,
            self.page_size_bytes,
        )?;
        if self.limit_bytes != expected {
            return Err(failed(
                "memory cap differs from its bounded, page-aligned planned limit",
            ));
        }
        Ok(())
    }
}

fn failed(message: impl Into<String>) -> ActionError {
    ActionError::Failed(message.into())
}

fn align_up(value: u64, page: u64) -> Result<u64, ActionError> {
    if !page.is_power_of_two() || !(4096..=1_048_576).contains(&page) {
        return Err(failed("unsupported or unavailable kernel page size"));
    }
    value
        .checked_add(page - 1)
        .map(|rounded| rounded / page * page)
        .ok_or_else(|| failed("memory limit cannot be represented in whole pages"))
}

fn choose_limit(
    current: u64,
    high: Option<u64>,
    low: u64,
    min: u64,
    page: u64,
) -> Result<u64, ActionError> {
    let fraction = u64::try_from((u128::from(current) * 9).div_ceil(10))
        .map_err(|_| failed("memory charge is not representable"))?;
    let requested = align_up(fraction.max(MIN_MEMORY_CAP_BYTES).max(low).max(min), page)?;
    if requested >= current || high.is_some_and(|high| requested >= high) {
        return Err(failed(
            "memory.high already limits this workload, or its charge is below the protected cap floor",
        ));
    }
    Ok(requested)
}

/// Plan a conservative soft cap using only a current kernel observation.
/// Shared, protected, non-delegated, old-kernel and non-Linux targets refuse.
#[cfg(target_os = "linux")]
pub fn plan_memory_cap(target: &ProcessIdentity) -> Result<MemoryCapPlan, ActionError> {
    ensure_nonblocking_kernel()?;
    ensure_cap_state(target)?;
    let checked_path = super::dispatch::ensure_cgroup_target(target)?;
    let scope = LiveScope::open(target, &checked_path)?;
    let page_size_bytes = page_size()?;
    let controls = read_controls(&scope.pinned())?;
    let plan = MemoryCapPlan {
        target: target.clone(),
        scope: scope.binding.clone(),
        limit_bytes: choose_limit(
            controls.current,
            controls.high,
            controls.low,
            controls.min,
            page_size_bytes,
        )?,
        observed_high_bytes: controls.high,
        observed_current_bytes: controls.current,
        observed_low_bytes: controls.low,
        observed_min_bytes: controls.min,
        page_size_bytes,
    };
    // Opening read/write establishes effective permission without writing,
    // creating, truncating, moving or otherwise changing anything.
    open_high(&scope.pinned(), false)?;
    scope.revalidate(target, &plan.scope)?;
    validate_prewrite_controls(&scope.pinned(), &plan)?;
    ensure_cap_state(target)?;
    scope.revalidate(target, &plan.scope)?;
    plan.validate(target)?;
    Ok(plan)
}

#[cfg(not(target_os = "linux"))]
pub fn plan_memory_cap(_target: &ProcessIdentity) -> Result<MemoryCapPlan, ActionError> {
    Err(failed("memory.high requires Linux cgroup v2"))
}

/// Observe the exact planned scope without replaying or restoring the action.
/// `None` is an observed unlimited value; it is not a failed observation.
#[cfg(target_os = "linux")]
pub fn observe_memory_cap(
    target: &ProcessIdentity,
    plan: &MemoryCapPlan,
) -> Result<Option<u64>, ActionError> {
    plan.validate(target)?;
    let scope = LiveScope::open(target, &plan.scope.cgroup_path)?;
    scope.revalidate(target, &plan.scope)?;
    let observed = read_high(&scope.pinned())?;
    scope.revalidate(target, &plan.scope)?;
    if read_high(&scope.pinned())? != observed {
        return Err(failed("memory.high changed during observation"));
    }
    scope.revalidate(target, &plan.scope)?;
    Ok(observed)
}

#[cfg(target_os = "linux")]
pub(crate) fn validate_live_scope(
    target: &ProcessIdentity,
    plan: &MemoryCapPlan,
) -> Result<(), ActionError> {
    plan.validate(target)?;
    LiveScope::open(target, &plan.scope.cgroup_path)?.revalidate(target, &plan.scope)
}

#[cfg(not(target_os = "linux"))]
pub fn observe_memory_cap(
    _target: &ProcessIdentity,
    _plan: &MemoryCapPlan,
) -> Result<Option<u64>, ActionError> {
    Err(failed("memory.high observation requires Linux cgroup v2"))
}

#[cfg(target_os = "linux")]
fn page_size() -> Result<u64, ActionError> {
    // SAFETY: sysconf only reads the system page-size configuration.
    let page = u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
        .map_err(|_| failed("kernel page size unavailable"))?;
    align_up(0, page)?;
    Ok(page)
}

#[cfg(target_os = "linux")]
fn cap_state_eligible(state: char) -> bool {
    matches!(state, 'R' | 'S' | 'T' | 'I')
}

#[cfg(target_os = "linux")]
fn ensure_cap_state(target: &ProcessIdentity) -> Result<(), ActionError> {
    let stat = crate::collect::proc_parsers::parse_proc_stat(target.pid.0)
        .ok_or(ActionError::ProcessNotFound)?;
    if stat.pid != target.pid.0 || !cap_state_eligible(stat.state) {
        return Err(failed(
            "memory cap requires a live runnable, sleeping, stopped or idle target; blocked, traced and dead states refuse",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn supports_nonblocking_high(release: &str) -> bool {
    let mut fields = release.trim().split('.');
    let major = fields.next().and_then(|value| value.parse::<u32>().ok());
    let minor = fields.next().and_then(|value| value.parse::<u32>().ok());
    matches!((major, minor), (Some(major), Some(minor)) if major > 6 || (major == 6 && minor >= 16))
}

#[cfg(target_os = "linux")]
pub(crate) fn ensure_nonblocking_kernel() -> Result<(), ActionError> {
    let release = fs::read_to_string("/proc/sys/kernel/osrelease").map_err(|error| {
        failed(format!(
            "cannot establish nonblocking memory.high support: {error}"
        ))
    })?;
    // Linux v6.16 documents O_NONBLOCK for memory.high; v6.15 does not.
    // Older/backported kernels are conservatively unavailable because the flag
    // cannot be probed safely without potentially doing synchronous reclaim.
    // https://www.kernel.org/doc/html/v6.16/admin-guide/cgroup-v2.html
    if !supports_nonblocking_high(&release) {
        return Err(failed(
            "memory cap requires Linux 6.16+ nonblocking memory.high writes",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct LiveScope {
    directory: PathBuf,
    handle: File,
    binding: ReversalScope,
}

#[cfg(target_os = "linux")]
impl LiveScope {
    fn open(target: &ProcessIdentity, cgroup_path: &str) -> Result<Self, ActionError> {
        let observed_path = super::dispatch::ensure_cgroup_target(target)?;
        if observed_path != cgroup_path {
            return Err(failed("target moved from its planned memory cgroup"));
        }
        let directory = PathBuf::from(format!("/sys/fs/cgroup{cgroup_path}"));
        let handle = open_directory(&directory)?;
        check_owner(&handle, target.uid)?;
        let binding = ReversalScope::capture(cgroup_path, &handle)?;
        let scope = Self {
            directory,
            handle,
            binding,
        };
        scope.revalidate(target, &scope.binding)?;
        Ok(scope)
    }

    fn pinned(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.handle.as_raw_fd()))
    }

    fn revalidate(
        &self,
        target: &ProcessIdentity,
        expected: &ReversalScope,
    ) -> Result<(), ActionError> {
        if super::dispatch::ensure_cgroup_target(target)? != expected.cgroup_path {
            return Err(failed(
                "target changed cgroup during memory control observation",
            ));
        }
        let current = open_directory(&self.directory)?;
        check_owner(&current, target.uid)?;
        if ReversalScope::capture(&expected.cgroup_path, &current)? != *expected
            || ReversalScope::capture(&expected.cgroup_path, &self.handle)? != *expected
        {
            return Err(failed(
                "memory cgroup directory, mount, namespace or boot changed",
            ));
        }
        let namespace = fs::metadata(format!("/proc/{}/ns/cgroup", target.pid.0))
            .map_err(|error| failed(format!("cannot identify target cgroup namespace: {error}")))?;
        if namespace.dev() != expected.cgroup_namespace_device
            || namespace.ino() != expected.cgroup_namespace_inode
        {
            return Err(failed(
                "target and observer have different cgroup namespaces",
            ));
        }
        super::dispatch::ensure_exclusive_cgroup_path(target.pid.0, &self.pinned())
    }
}

#[cfg(target_os = "linux")]
fn open_directory(path: &Path) -> Result<File, ActionError> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| failed(format!("cannot open memory cgroup: {error}")))
}

#[cfg(target_os = "linux")]
fn check_owner(handle: &File, uid: u32) -> Result<(), ActionError> {
    let metadata = handle
        .metadata()
        .map_err(|error| failed(error.to_string()))?;
    if !metadata.is_dir() || metadata.uid() != uid {
        return Err(failed(
            "memory cap requires a cgroup directory owned by the target user",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_high(directory: &Path, truncate: bool) -> Result<File, ActionError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .truncate(truncate)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(directory.join("memory.high"))
        .map_err(|error| failed(format!("memory.high requires read/write access: {error}")))?;
    if !file
        .metadata()
        .map_err(|error| failed(error.to_string()))?
        .is_file()
    {
        return Err(failed(
            "memory.high is not a regular kernel controller file",
        ));
    }
    Ok(file)
}

#[cfg(target_os = "linux")]
pub(crate) fn parse_memory_value(text: &str) -> Result<Option<u64>, ActionError> {
    let value = text.trim();
    if value == "max" {
        return Ok(None);
    }
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(failed("malformed memory controller value"));
    }
    value
        .parse::<u64>()
        .map(Some)
        .map_err(|_| failed("memory controller value overflow"))
}

#[cfg(target_os = "linux")]
fn read_memory_value(directory: &Path, name: &str) -> Result<Option<u64>, ActionError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(directory.join(name))
        .map_err(|error| failed(format!("cannot read {name}: {error}")))?;
    if !file
        .metadata()
        .map_err(|error| failed(error.to_string()))?
        .is_file()
    {
        return Err(failed(format!("{name} is not a regular kernel file")));
    }
    let mut text = String::new();
    file.take(129)
        .read_to_string(&mut text)
        .map_err(|error| failed(format!("cannot read {name}: {error}")))?;
    if text.len() > 128 {
        return Err(failed(format!(
            "{name} exceeds the bounded controller size"
        )));
    }
    parse_memory_value(&text)
}

#[cfg(target_os = "linux")]
pub(crate) fn read_high(directory: &Path) -> Result<Option<u64>, ActionError> {
    read_memory_value(directory, "memory.high")
}

#[cfg(target_os = "linux")]
pub(crate) fn write_memory_high(directory: &Path, limit: Option<u64>) -> Result<(), ActionError> {
    let value = limit.map_or_else(|| "max\n".to_string(), |limit| format!("{limit}\n"));
    open_high(directory, true)?
        .write_all(value.as_bytes())
        .map_err(|error| failed(format!("cannot write nonblocking memory.high: {error}")))
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy)]
struct Controls {
    current: u64,
    high: Option<u64>,
    low: u64,
    min: u64,
}

#[cfg(target_os = "linux")]
fn read_controls(directory: &Path) -> Result<Controls, ActionError> {
    let numeric = |name| {
        read_memory_value(directory, name)?.ok_or_else(|| {
            failed(format!(
                "{name} is unlimited or unavailable; no bounded memory cap is safe"
            ))
        })
    };
    Ok(Controls {
        current: numeric("memory.current")?,
        high: read_high(directory)?,
        low: numeric("memory.low")?,
        min: numeric("memory.min")?,
    })
}

#[cfg(target_os = "linux")]
fn validate_prewrite_controls(directory: &Path, plan: &MemoryCapPlan) -> Result<(), ActionError> {
    let current = read_controls(directory)?;
    if current.high != plan.observed_high_bytes
        || current.low != plan.observed_low_bytes
        || current.min != plan.observed_min_bytes
    {
        return Err(failed(
            "memory limits or protections changed since planning; obtain a new plan",
        ));
    }
    // A stale plan must not impose an unexpectedly large reduction after the
    // workload grew. Preserve at least 90% of the currently observed charge,
    // just as the original plan does, without silently recomputing its limit.
    if u128::from(plan.limit_bytes) * 10 < u128::from(current.current) * 9 {
        return Err(failed(
            "memory charge grew beyond the planned intervention budget; replan",
        ));
    }
    Ok(())
}

/// Memory protection must still be honored when undo restores a finite value.
#[cfg(target_os = "linux")]
pub(crate) fn check_restore_floor(
    directory: &Path,
    original: Option<u64>,
) -> Result<(), ActionError> {
    if let Some(original) = original {
        for name in ["memory.low", "memory.min"] {
            let protection = read_memory_value(directory, name)?.ok_or_else(|| {
                failed("memory protection changed to unlimited; cannot restore finite high")
            })?;
            if original < protection {
                return Err(failed(
                    "original memory.high is below a current memory protection",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
pub struct MemoryCapActionRunner {
    reversal_journal: Option<Arc<ReversalJournal>>,
    applied: Mutex<Option<AppliedMemoryCap>>,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct AppliedMemoryCap {
    action_id: String,
    plan: MemoryCapPlan,
    scope: LiveScope,
    receipt: PreparedReversal,
}

#[cfg(target_os = "linux")]
impl MemoryCapActionRunner {
    pub fn with_defaults() -> Self {
        Self::default()
    }

    pub fn with_reversal_journal(mut self, journal: Arc<ReversalJournal>) -> Self {
        self.reversal_journal = Some(journal);
        self
    }

    fn execute_cap(&self, action: &PlanAction) -> Result<AppliedMemoryCap, ActionError> {
        if action.action != Action::CapMemory
            || action.routing != ActionRouting::Direct
            || action.original_zombie_target.is_some()
            || action.supervisor_restart.is_some()
        {
            return Err(failed("memory cap requires a direct planned action"));
        }
        let plan = action
            .memory_cap
            .as_ref()
            .ok_or_else(|| failed("memory cap is missing its planned limit and scope"))?;
        plan.validate(&action.target)?;
        ensure_nonblocking_kernel()?;
        if page_size()? != plan.page_size_bytes {
            return Err(failed(
                "kernel page size differs from the planned memory cap",
            ));
        }
        let journal = self
            .reversal_journal
            .as_ref()
            .ok_or_else(|| failed("memory cap requires a durable undo journal before execution"))?;
        let scope = LiveScope::open(&action.target, &plan.scope.cgroup_path)?;
        let receipt = apply_at(
            &scope.pinned(),
            plan,
            || scope.revalidate(&action.target, &plan.scope),
            || {
                ensure_cap_state(&action.target)?;
                scope.revalidate(&action.target, &plan.scope)
            },
            || {
                journal
                    .prepare(
                        action,
                        &plan.scope.cgroup_path,
                        &scope.handle,
                        ReversalValue::MemoryHigh {
                            limit_bytes: plan.observed_high_bytes,
                        },
                        ReversalValue::MemoryHigh {
                            limit_bytes: Some(plan.limit_bytes),
                        },
                        0,
                    )
                    .map(Some)
            },
        )?
        .ok_or_else(|| failed("memory cap execution has no durable receipt"))?;
        Ok(AppliedMemoryCap {
            action_id: action.action_id.clone(),
            plan: plan.clone(),
            scope,
            receipt,
        })
    }
}

/// The actual controller path, shared with fixture tests. A receipt must be
/// prepared successfully before any write. Scope guards surround all observations.
#[cfg(target_os = "linux")]
fn apply_at(
    directory: &Path,
    plan: &MemoryCapPlan,
    revalidate: impl Fn() -> Result<(), ActionError>,
    before_write: impl Fn() -> Result<(), ActionError>,
    prepare: impl FnOnce() -> Result<Option<PreparedReversal>, ActionError>,
) -> Result<Option<PreparedReversal>, ActionError> {
    plan.validate(&plan.target)?;
    revalidate()?;
    validate_prewrite_controls(directory, plan)?;
    open_high(directory, false)?;
    before_write()?;
    let receipt = prepare()?;
    let execution = (|| {
        revalidate()?;
        validate_prewrite_controls(directory, plan)?;
        before_write()?;
        write_memory_high(directory, Some(plan.limit_bytes))?;
        revalidate()?;
        for _ in 0..2 {
            if read_high(directory)? != Some(plan.limit_bytes) {
                return Err(failed(
                    "memory.high readback differs from the exact planned cap",
                ));
            }
            revalidate()?;
        }
        Ok(())
    })();
    match &receipt {
        Some(receipt) => receipt.finish(execution, ReversalStatus::Applied)?,
        None => execution?,
    }
    Ok(receipt)
}

#[cfg(target_os = "linux")]
impl ActionRunner for MemoryCapActionRunner {
    fn execute(&self, action: &PlanAction) -> Result<(), ActionError> {
        let mut applied = self
            .applied
            .lock()
            .map_err(|_| failed("memory cap execution record unavailable"))?;
        *applied = None;
        *applied = Some(self.execute_cap(action)?);
        Ok(())
    }

    fn verify(&self, action: &PlanAction) -> Result<(), ActionError> {
        let applied = self
            .applied
            .lock()
            .map_err(|_| failed("memory cap execution record unavailable"))?;
        let applied = applied
            .as_ref()
            .ok_or_else(|| failed("cannot verify a memory cap without its execution record"))?;
        if action.action != Action::CapMemory
            || action.action_id != applied.action_id
            || action.target != applied.plan.target
            || action.memory_cap.as_ref() != Some(&applied.plan)
            || action.routing != ActionRouting::Direct
            || action.original_zombie_target.is_some()
            || action.supervisor_restart.is_some()
        {
            return Err(ActionError::IdentityMismatch);
        }
        let result = (|| {
            for _ in 0..2 {
                applied
                    .scope
                    .revalidate(&action.target, &applied.plan.scope)?;
                if read_high(&applied.scope.pinned())? != Some(applied.plan.limit_bytes) {
                    return Err(failed("executed memory.high cap is no longer present"));
                }
            }
            applied
                .scope
                .revalidate(&action.target, &applied.plan.scope)
        })();
        applied.receipt.finish(result, ReversalStatus::Verified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pt_common::{ProcessId, StartId};

    fn plan() -> MemoryCapPlan {
        let boot = "11111111-2222-4333-8444-555555555555";
        let target = ProcessIdentity {
            pid: ProcessId(123),
            start_id: StartId::from_linux(boot, 100, 123),
            uid: 1000,
            pgid: Some(123),
            sid: Some(123),
            quality: IdentityQuality::Full,
        };
        let current = 200 * 1024 * 1024;
        MemoryCapPlan {
            target,
            scope: ReversalScope {
                cgroup_path: "/user.slice/owned/workload".to_string(),
                device: 1,
                inode: 2,
                mount_id: 3,
                boot_id: boot.to_string(),
                mount_namespace_device: 4,
                mount_namespace_inode: 5,
                cgroup_namespace_device: 6,
                cgroup_namespace_inode: 7,
            },
            limit_bytes: 180 * 1024 * 1024,
            observed_high_bytes: None,
            observed_current_bytes: current,
            observed_low_bytes: 0,
            observed_min_bytes: 0,
            page_size_bytes: 4096,
        }
    }

    #[test]
    fn memory_cap_plans_preserve_protection_and_tighter_existing_limits() {
        let mib = 1024 * 1024;
        assert_eq!(
            choose_limit(200 * mib, None, 0, 0, 4096).unwrap(),
            180 * mib
        );
        assert_eq!(
            choose_limit(200 * mib, None, 190 * mib, 0, 4096).unwrap(),
            190 * mib
        );
        assert_eq!(
            choose_limit(200 * mib, None, 0, 195 * mib, 4096).unwrap(),
            195 * mib
        );
        for high in [0, 100 * mib, 180 * mib] {
            assert!(choose_limit(200 * mib, Some(high), 0, 0, 4096).is_err());
        }
        for current in [0, mib, MIN_MEMORY_CAP_BYTES] {
            assert!(choose_limit(current, None, 0, 0, 4096).is_err());
        }
        assert!(choose_limit(200 * mib, None, 200 * mib, 0, 4096).is_err());
        assert!(choose_limit(u64::MAX, None, u64::MAX, 0, 4096).is_err());
        assert!(choose_limit(200 * mib, None, 0, 0, 0).is_err());
        assert_eq!(
            choose_limit(200 * mib + 1, None, 0, 0, 4096).unwrap(),
            180 * mib + 4096
        );
    }

    #[test]
    fn memory_cap_plan_rejects_rebinding_and_modified_requests() {
        let original = plan();
        original.validate(&original.target).unwrap();
        let mut target = original.target.clone();
        target.uid += 1;
        assert!(original.validate(&target).is_err());
        for change in ["cap", "boot", "path", "scope", "page", "floor"] {
            let mut changed = original.clone();
            match change {
                "cap" => changed.limit_bytes -= 4096,
                "boot" => changed.scope.boot_id = "unknown".into(),
                "path" => changed.scope.cgroup_path = "/owned/../system.slice".into(),
                "scope" => changed.scope.inode = 0,
                "page" => changed.page_size_bytes = 0,
                _ => changed.observed_min_bytes = changed.limit_bytes + 4096,
            }
            assert!(changed.validate(&changed.target).is_err(), "{change}");
        }
        let encoded = serde_json::to_string(&original).unwrap();
        assert_eq!(
            serde_json::from_str::<MemoryCapPlan>(&encoded).unwrap(),
            original
        );
    }

    #[cfg(target_os = "linux")]
    fn fixture(plan: &MemoryCapPlan) -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        for (name, value) in [
            ("memory.high", "max\n".to_string()),
            ("memory.current", plan.observed_current_bytes.to_string()),
            ("memory.low", plan.observed_low_bytes.to_string()),
            ("memory.min", plan.observed_min_bytes.to_string()),
            ("memory.max", "max\n".to_string()),
            ("cgroup.procs", "123\n".to_string()),
        ] {
            fs::write(temp.path().join(name), value).unwrap();
        }
        temp
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn memory_cap_nonblocking_support_and_values_fail_closed() {
        for release in ["6.16.0", "6.18.1-custom", "7.0.0"] {
            assert!(supports_nonblocking_high(release));
        }
        for release in ["6.15.99", "5.15.0", "6.unknown", "", "-1.16.0"] {
            assert!(!supports_nonblocking_high(release));
        }
        assert_eq!(parse_memory_value("max\n").unwrap(), None);
        assert_eq!(parse_memory_value("1024\n").unwrap(), Some(1024));
        for value in ["", "-1", "+1", "1 2", "max 1", "18446744073709551616"] {
            assert!(parse_memory_value(value).is_err(), "{value}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn memory_cap_fixture_writes_only_soft_cap_and_requires_receipt_preparation() {
        let plan = plan();
        let temp = fixture(&plan);
        assert!(apply_at(
            temp.path(),
            &plan,
            || Ok(()),
            || Ok(()),
            || Err(failed("journal unavailable"))
        )
        .is_err());
        assert_eq!(read_high(temp.path()).unwrap(), None);
        apply_at(temp.path(), &plan, || Ok(()), || Ok(()), || Ok(None)).unwrap();
        assert_eq!(read_high(temp.path()).unwrap(), Some(plan.limit_bytes));
        assert_eq!(
            fs::read_to_string(temp.path().join("memory.max")).unwrap(),
            "max\n"
        );
        // Usage remains above high: control verification must not claim reclaim.
        assert_eq!(
            read_controls(temp.path()).unwrap().current,
            plan.observed_current_bytes
        );
        write_memory_high(temp.path(), None).unwrap();
        assert_eq!(read_high(temp.path()).unwrap(), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn memory_cap_fixture_refuses_stale_protection_scope_and_membership() {
        let plan = plan();
        for (name, value) in [
            ("memory.high", "123456789"),
            ("memory.low", "1"),
            ("memory.min", "1"),
            ("memory.current", "1073741824"),
        ] {
            let temp = fixture(&plan);
            fs::write(temp.path().join(name), value).unwrap();
            let old = read_high(temp.path()).unwrap();
            assert!(
                apply_at(temp.path(), &plan, || Ok(()), || Ok(()), || Ok(None)).is_err(),
                "{name}"
            );
            assert_eq!(read_high(temp.path()).unwrap(), old);
        }
        let temp = fixture(&plan);
        let calls = std::cell::Cell::new(0);
        assert!(apply_at(
            temp.path(),
            &plan,
            || {
                calls.set(calls.get() + 1);
                if calls.get() == 2 {
                    Err(ActionError::IdentityMismatch)
                } else {
                    Ok(())
                }
            },
            || Ok(()),
            || Ok(None)
        )
        .is_err());
        assert_eq!(read_high(temp.path()).unwrap(), None);
        fs::write(temp.path().join("cgroup.procs"), "123\n456\n").unwrap();
        assert!(apply_at(
            temp.path(),
            &plan,
            || super::super::dispatch::ensure_exclusive_cgroup_path(123, temp.path()),
            || Ok(()),
            || Ok(None)
        )
        .is_err());
        assert_eq!(read_high(temp.path()).unwrap(), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn memory_cap_fixture_refuses_controller_symlinks_and_new_protections_on_undo() {
        use std::os::unix::fs::symlink;
        let plan = plan();
        let temp = fixture(&plan);
        let linked = tempfile::tempdir().unwrap();
        symlink(
            temp.path().join("memory.high"),
            linked.path().join("memory.high"),
        )
        .unwrap();
        assert!(read_high(linked.path()).is_err());
        assert!(write_memory_high(linked.path(), Some(plan.limit_bytes)).is_err());
        fs::write(temp.path().join("memory.min"), "250000000\n").unwrap();
        assert!(check_restore_floor(temp.path(), Some(200000000)).is_err());
        assert!(check_restore_floor(temp.path(), None).is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn memory_cap_checks_live_state_again_after_preparing_its_receipt() {
        for state in ['R', 'S', 'T', 'I'] {
            assert!(cap_state_eligible(state));
        }
        for state in ['D', 'Z', 'X', 'x', 't', '?'] {
            assert!(!cap_state_eligible(state));
        }
        let plan = plan();
        let temp = fixture(&plan);
        let state = std::cell::Cell::new('S');
        assert!(apply_at(
            temp.path(),
            &plan,
            || Ok(()),
            || if cap_state_eligible(state.get()) {
                Ok(())
            } else {
                Err(failed("state changed"))
            },
            || {
                state.set('D');
                Ok(None)
            },
        )
        .is_err());
        assert_eq!(read_high(temp.path()).unwrap(), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn memory_cap_live_probe_never_changes_the_invokers_cgroup() {
        let pid = std::process::id();
        let target = super::super::dispatch::read_cgroup_identity(pid).unwrap();
        let before = fs::read_to_string("/proc/self/cgroup").unwrap();
        assert!(super::super::dispatch::ensure_cgroup_target(&target).is_err());
        assert!(plan_memory_cap(&target).is_err());
        assert_eq!(fs::read_to_string("/proc/self/cgroup").unwrap(), before);
    }
}
