//! Verification of canonical action plans against saved execution evidence.
//!
//! Recommendations are not execution evidence. Respawn attribution requires the
//! executed target's owner, full command, parent and execution clock.

pub mod relief;
pub mod relief_store;
pub mod resource_prediction;

use crate::action::reversal::{RestorationObservation, RestorationValue};
use crate::collect::{ProcessRecord, ProcessState};
use crate::decision::Action;
use crate::plan::{Plan, PlanAction};
use chrono::{DateTime, Utc};
use pt_common::ProcessIdentity;
use resource_prediction::ValidatedResourcePredictions;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// One persisted action/outcomes.jsonl record. Unsuccessful records may omit
/// execution evidence; successful records are validated against Plan.actions.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SavedActionOutcome {
    pub action_id: String,
    pub pid: u32,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<Action>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<ProcessIdentity>,
    /// Supervisor scope actually used by a service restart, separate from a
    /// potentially edited plan and from zombie-parent reaping.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supervisor_restart: Option<crate::action::SystemdUserServiceBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_identity: Option<ProcessIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executed_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_clock: Option<ExecutionClock>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_ms: Option<u64>,
}

/// Linux boot-relative execution cutoff, in the same units as /proc starttime.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExecutionClock {
    pub boot_id: String,
    pub ticks: u64,
}

/// Capture immediately before execution, never when verifying a saved action.
pub fn capture_execution_clock() -> Option<ExecutionClock> {
    #[cfg(target_os = "linux")]
    {
        let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
        let boot_id = boot_id.trim().to_string();
        if boot_id.is_empty() {
            return None;
        }
        let mut time = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: clock_gettime writes to the valid stack-allocated timespec.
        if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut time) } != 0 {
            return None;
        }
        // SAFETY: sysconf reads this process-independent clock configuration.
        let hz = u64::try_from(unsafe { libc::sysconf(libc::_SC_CLK_TCK) })
            .ok()
            .filter(|hz| *hz > 0)?;
        let seconds = u64::try_from(time.tv_sec).ok()?;
        let nanos = u64::try_from(time.tv_nsec).ok()?;
        let ticks = seconds
            .checked_mul(hz)?
            .checked_add(nanos.checked_mul(hz)? / 1_000_000_000)?;
        Some(ExecutionClock { boot_id, ticks })
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[derive(Debug, Serialize)]
pub struct VerificationReport {
    pub schema_version: String,
    pub session_id: String,
    pub verification: VerificationWindow,
    pub action_outcomes: Vec<ActionOutcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_summary: Option<ResourceSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub follow_up_needed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommendations: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct VerificationWindow {
    pub requested_at: String,
    pub completed_at: String,
    pub overall_status: String,
}

#[derive(Debug, Serialize)]
pub struct ActionOutcome {
    pub action_id: String,
    pub target: VerifyTarget,
    pub action: String,
    pub outcome: VerifyOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_to_death_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_resources_freed: Option<ExpectedResourcesFreed>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub respawn_detected: Option<RespawnDetected>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// An intentional restoration independently observed during this verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restoration: Option<RestorationObservation>,
}

#[derive(Debug, Serialize)]
pub struct VerifyTarget {
    pub pid: u32,
    pub start_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmd_short: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmd_full: Option<String>,
    pub uid: u32,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VerifyOutcome {
    ConfirmedDead,
    ConfirmedStopped,
    /// A reversible action's current postcondition was independently observed.
    ConfirmedEffect,
    /// The latest completed undo's original controller state was freshly observed.
    ConfirmedRestored,
    /// Undo evidence or its current original state could not be independently verified.
    RestorationUnverified,
    /// Current evidence establishes that the reversible postcondition is unmet.
    EffectNotObserved,
    StillRunning,
    Respawned,
    PidReused,
    Unsupported,
}

/// Fresh action-specific evidence, distinct from a saved execution status.
///
/// An observer must only read state and bind every observation to `PlanAction.target`.
/// It must not replay an action or infer an effect from a saved success record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionPostcondition {
    Satisfied { detail: String },
    NotSatisfied { detail: String },
    Unavailable { reason: String },
    IdentityChanged,
    Restored { observation: RestorationObservation },
    RestorationUnverified { reason: String },
}

/// Observe the postconditions used by the default production apply runner.
///
/// Linux nice values belong to threads: use the existing stable, identity-bound
/// thread snapshot, not the leader's priority alone. Capturing reversal metadata
/// reads current priorities; it neither changes them nor restores anything.
/// Controller observations bind both process identity and cgroup membership around
/// their reads. Verifying a configured effect does not establish resource relief.
pub fn observe_live_postcondition(action: &PlanAction) -> ActionPostcondition {
    #[cfg(target_os = "linux")]
    if action.action == Action::Pause {
        return crate::action::dispatch::observe_pause_postcondition(&action.target);
    }
    if action.action == Action::CapMemory {
        let Some(plan) = action.memory_cap.as_ref() else {
            return ActionPostcondition::Unavailable {
                reason: "Memory cap has no saved limit and scope binding".to_string(),
            };
        };
        return match crate::action::memory_cap::observe_memory_cap(&action.target, plan) {
            Ok(observed) if observed == Some(plan.limit_bytes) => ActionPostcondition::Satisfied {
                detail: format!(
                    "The original isolated cgroup has the planned memory.high = {} bytes. This soft cap does not establish memory reclaimed or workload health",
                    plan.limit_bytes,
                ),
            },
            Ok(observed) => ActionPostcondition::NotSatisfied {
                detail: format!(
                    "Observed memory.high = {}, expected {} bytes in the planned cgroup",
                    observed.map_or_else(|| "max".to_string(), |bytes| bytes.to_string()),
                    plan.limit_bytes,
                ),
            },
            Err(crate::action::ActionError::IdentityMismatch) => ActionPostcondition::IdentityChanged,
            Err(error) => ActionPostcondition::Unavailable { reason: error.to_string() },
        };
    }
    if action.action == Action::Restart && action.routing == crate::plan::ActionRouting::Supervisor
    {
        #[cfg(target_os = "linux")]
        {
            return match crate::action::supervisor::verify_systemd_user_restart(action) {
                Ok(()) => ActionPostcondition::Satisfied {
                    detail: "The bound user service has a new invocation and live MainPID; the \
                             original incarnation is gone. This does not establish application \
                             health or resource relief"
                        .to_string(),
                },
                Err(error) => ActionPostcondition::Unavailable {
                    reason: error.to_string(),
                },
            };
        }
        #[cfg(not(target_os = "linux"))]
        {
            return ActionPostcondition::Unavailable {
                reason: "Systemd user-service verification requires Linux".to_string(),
            };
        }
    }
    #[cfg(target_os = "linux")]
    if matches!(
        action.action,
        Action::Freeze | Action::Unfreeze | Action::Throttle | Action::Quarantine
    ) {
        use crate::action::LiveIdentityProvider;

        return observe_bound_cgroup(
            action,
            &LiveIdentityProvider::new(),
            || std::fs::read_to_string(format!("/proc/{}/cgroup", action.target.pid.0)),
            |membership| {
                observe_cgroup_files(
                    action.action,
                    action.target.pid.0,
                    membership,
                    std::path::Path::new("/sys/fs/cgroup"),
                )
                .unwrap_or_else(|reason| ActionPostcondition::Unavailable { reason })
            },
        );
    }
    if action.action != Action::Renice {
        return ActionPostcondition::Unavailable {
            reason: "No live observation is implemented for this action's postcondition"
                .to_string(),
        };
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use crate::action::{IdentityProvider, LiveIdentityProvider, ReniceActionRunner};

        if !action.target.can_safely_revalidate() {
            return ActionPostcondition::Unavailable {
                reason: "The planned identity cannot be safely revalidated".to_string(),
            };
        }
        let identity = LiveIdentityProvider::new();
        let revalidate = || match identity.revalidate(&action.target) {
            Ok(true) => Ok(()),
            Ok(false) => Err("The planned identity is absent, changed, or unreadable".to_string()),
            Err(error) => Err(format!("Cannot revalidate the planned identity: {error}")),
        };
        if let Err(reason) = revalidate() {
            return ActionPostcondition::Unavailable { reason };
        }
        let observed =
            ReniceActionRunner::with_defaults().capture_reversal_metadata(action.target.pid.0);
        if let Err(reason) = revalidate() {
            return ActionPostcondition::Unavailable { reason };
        }
        match observed {
            Some(observed) => renice_postcondition(&action.target, &observed),
            None => ActionPostcondition::Unavailable {
                reason: "Could not obtain a complete, stable priority observation for the planned process"
                    .to_string(),
            },
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        ActionPostcondition::Unavailable {
            reason: "Live priority verification is unsupported on this platform".to_string(),
        }
    }
}

/// Keep a successful controller read from surviving process exit, PID reuse or
/// migration to another cgroup during observation. This function only reads.
#[cfg(target_os = "linux")]
fn observe_bound_cgroup(
    action: &PlanAction,
    identity: &dyn crate::action::IdentityProvider,
    mut read_membership: impl FnMut() -> std::io::Result<String>,
    observe: impl FnOnce(&str) -> ActionPostcondition,
) -> ActionPostcondition {
    if !action.target.can_safely_revalidate() {
        return ActionPostcondition::Unavailable {
            reason: "The planned identity cannot be safely revalidated".to_string(),
        };
    }
    let revalidate = || match identity.revalidate(&action.target) {
        Ok(true) => Ok(()),
        Ok(false) => Err("The planned identity is absent, changed, or unreadable".to_string()),
        Err(error) => Err(format!("Cannot revalidate the planned identity: {error}")),
    };
    if let Err(reason) = revalidate() {
        return ActionPostcondition::Unavailable { reason };
    }
    let before = match read_membership() {
        Ok(membership) => membership,
        Err(error) => {
            return ActionPostcondition::Unavailable {
                reason: format!("Cannot read the target's cgroup membership: {error}"),
            };
        }
    };
    let observation = observe(&before);
    let after = read_membership();
    if let Err(reason) = revalidate() {
        return ActionPostcondition::Unavailable { reason };
    }
    match after {
        Ok(after) if after == before => observation,
        Ok(_) => ActionPostcondition::Unavailable {
            reason: "The target's cgroup membership changed during observation".to_string(),
        },
        Err(error) => ActionPostcondition::Unavailable {
            reason: format!("Cannot recheck the target's cgroup membership: {error}"),
        },
    }
}

/// Resolve only kernel membership paths beneath the same controller mounts used
/// by the action runners. A namespace-relative `..` path cannot be safely mapped.
#[cfg(target_os = "linux")]
fn controller_directory(
    membership: &str,
    root: &std::path::Path,
    controller: Option<&str>,
) -> Result<Option<std::path::PathBuf>, String> {
    use std::path::Component;

    let mut selected = None;
    for line in membership.lines() {
        let mut fields = line.splitn(3, ':');
        let hierarchy = fields
            .next()
            .and_then(|field| field.parse::<u32>().ok())
            .ok_or("Invalid cgroup hierarchy in membership evidence")?;
        let controllers = fields.next().ok_or("Missing cgroup controllers")?;
        let path = fields.next().ok_or("Missing cgroup membership path")?;
        let matches = match controller {
            None => hierarchy == 0 && controllers.is_empty(),
            Some(controller) => controllers.split(',').any(|name| name == controller),
        };
        if !matches {
            continue;
        }
        if selected.is_some() {
            return Err("Ambiguous duplicate controller membership".to_string());
        }
        let path = std::path::Path::new(path);
        if !path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
        {
            return Err(
                "Cgroup membership cannot be mapped safely to its controller mount".to_string(),
            );
        }
        let relative = path
            .strip_prefix("/")
            .map_err(|error| format!("Invalid cgroup membership path: {error}"))?;
        selected = Some(match controller {
            Some(controller) => root.join(controller).join(relative),
            None => root.join(relative),
        });
    }
    Ok(selected)
}

#[cfg(target_os = "linux")]
fn read_controller_file(path: &std::path::Path) -> Result<String, String> {
    std::fs::read_to_string(path)
        .map_err(|error| format!("Cannot read {}: {error}", path.display()))
}

/// A cgroup namespace and the mounted filesystem can have different roots. The
/// selected directory must actually contain the target in our PID namespace;
/// checking the same pathname twice alone would not establish this binding.
#[cfg(target_os = "linux")]
fn observe_controller_directory(
    pid: u32,
    directory: &std::path::Path,
    observe: impl FnOnce() -> Result<ActionPostcondition, String>,
) -> Result<ActionPostcondition, String> {
    let check_membership = || {
        let content = read_controller_file(&directory.join("cgroup.procs"))?;
        let mut target_present = false;
        for line in content.lines() {
            let member = line
                .trim()
                .parse::<u32>()
                .ok()
                .filter(|member| *member > 0)
                .ok_or_else(|| format!("Invalid cgroup.procs at {}", directory.display()))?;
            target_present |= member == pid;
        }
        if target_present {
            Ok(())
        } else {
            Err(format!(
                "Controller directory {} does not contain target PID {pid}",
                directory.display()
            ))
        }
    };
    check_membership()?;
    let result = observe();
    check_membership()?;
    result
}

/// Observe the default runner's actual controller settings without replaying it.
/// Missing v2 interfaces may use the same hybrid v1 controller as execution;
/// unreadable or malformed v2 evidence must not silently fall back to another.
#[cfg(target_os = "linux")]
fn observe_cgroup_files(
    action: Action,
    pid: u32,
    membership: &str,
    root: &std::path::Path,
) -> Result<ActionPostcondition, String> {
    let unified = controller_directory(membership, root, None)?;
    if matches!(action, Action::Freeze | Action::Unfreeze) {
        let directory = unified.ok_or("No unified cgroup freezer membership is available")?;
        return observe_controller_directory(pid, &directory, || {
            let state = crate::action::freeze::read_freezer_state(&directory)
                .map_err(|error| error.to_string())?;
            let expected = action == Action::Freeze;
            let detail = format!(
                "Observed cgroup {}: freeze requested={}, effectively frozen={}; expected both {}. This verifies freezer state, not resource relief",
                directory.display(),
                state.requested,
                state.frozen,
                expected,
            );
            Ok(if state.requested == expected && state.frozen == expected {
                ActionPostcondition::Satisfied { detail }
            } else {
                ActionPostcondition::NotSatisfied { detail }
            })
        });
    }

    let (controller, filename) = match action {
        Action::Throttle => ("cpu", "cpu.max"),
        Action::Quarantine => ("cpuset", "cpuset.cpus"),
        _ => return Err("No controller postcondition is defined for this action".to_string()),
    };
    if let Some(directory) = unified {
        let path = directory.join(filename);
        match std::fs::metadata(&path) {
            Ok(_) => {
                return observe_controller_directory(pid, &directory, || match action {
                    Action::Throttle => throttle_postcondition(&read_controller_file(&path)?),
                    Action::Quarantine => observe_quarantine(
                        || read_controller_file(&path),
                        || read_controller_file(&directory.join("cpuset.cpus.effective")),
                    ),
                    _ => unreachable!(),
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("Cannot read {}: {error}", path.display())),
        }
    }

    let directory = controller_directory(membership, root, Some(controller))?
        .ok_or_else(|| format!("No readable {controller} controller is available"))?;
    observe_controller_directory(pid, &directory, || match action {
        Action::Throttle => {
            observe_v1_throttle(|filename| read_controller_file(&directory.join(filename)))
        }
        Action::Quarantine => observe_quarantine(
            || read_controller_file(&directory.join("cpuset.cpus")),
            || read_controller_file(&directory.join("cpuset.effective_cpus")),
        ),
        _ => unreachable!(),
    })
}

/// V1 exposes quota and period separately. Bracket the quota read with period
/// reads so a concurrent period update cannot fabricate a stronger limit.
#[cfg(target_os = "linux")]
fn observe_v1_throttle(
    mut read: impl FnMut(&str) -> Result<String, String>,
) -> Result<ActionPostcondition, String> {
    let period = read("cpu.cfs_period_us")?;
    let quota = read("cpu.cfs_quota_us")?;
    let quota_after = read("cpu.cfs_quota_us")?;
    let after = read("cpu.cfs_period_us")?;
    if period.trim() != after.trim() || quota.trim() != quota_after.trim() {
        return Err("CPU quota or period changed during controller observation".to_string());
    }
    // The v1 unlimited sentinel has the same meaning as v2's `max`.
    let quota = if quota.trim() == "-1" {
        "max"
    } else {
        quota.trim()
    };
    throttle_postcondition(&format!("{} {}", quota, period.trim()))
}

#[cfg(target_os = "linux")]
fn throttle_postcondition(content: &str) -> Result<ActionPostcondition, String> {
    let mut fields = content.split_whitespace();
    let quota = match fields.next() {
        Some("max") => -1,
        Some(value) => value
            .parse::<i64>()
            .ok()
            .filter(|quota| *quota > 0)
            .ok_or("Invalid CPU quota in controller evidence")?,
        None => return Err("Missing CPU quota in controller evidence".to_string()),
    };
    let period = fields
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|period| *period > 0)
        .ok_or("Invalid CPU period in controller evidence")?;
    if fields.next().is_some() {
        return Err("Unexpected extra fields in CPU controller evidence".to_string());
    }
    let expected = crate::action::CpuThrottleConfig::default();
    let matches = crate::action::cgroup_throttle::quota_within_limit(quota, period, &expected)
        .map_err(|error| error.to_string())?;
    let detail = format!(
        "Observed CPU quota {} per {period} us; expected no more bandwidth than {} per {} us from the default runner. This verifies the configured limit, not measured CPU relief",
        if quota == -1 {
            "unlimited".to_string()
        } else {
            quota.to_string()
        },
        expected.quota_us(),
        expected.period_us,
    );
    Ok(if matches {
        ActionPostcondition::Satisfied { detail }
    } else {
        ActionPostcondition::NotSatisfied { detail }
    })
}

#[cfg(target_os = "linux")]
fn observe_quarantine(
    mut read_configured: impl FnMut() -> Result<String, String>,
    mut read_effective: impl FnMut() -> Result<String, String>,
) -> Result<ActionPostcondition, String> {
    let configured = read_configured()?;
    let effective = read_effective()?;
    let effective_after = read_effective()?;
    let configured_after = read_configured()?;
    if configured.trim() != configured_after.trim() || effective.trim() != effective_after.trim() {
        return Err("CPU confinement changed during controller observation".to_string());
    }
    quarantine_postcondition(&configured, &effective)
}

#[cfg(target_os = "linux")]
fn quarantine_postcondition(
    configured: &str,
    effective: &str,
) -> Result<ActionPostcondition, String> {
    use crate::action::cpuset_quarantine::CpuSet;

    if configured.trim().is_empty() || effective.trim().is_empty() {
        return Ok(ActionPostcondition::NotSatisfied {
            detail: "An empty configured or effective CPU set does not establish quarantine"
                .to_string(),
        });
    }
    let requested = CpuSet::parse(configured).map_err(|error| error.to_string())?;
    let effective = CpuSet::parse(effective).map_err(|error| error.to_string())?;
    let limit = crate::action::DEFAULT_QUARANTINE_CPUS;
    let matches = requested == effective && effective.first(limit) == effective;
    let detail = format!(
        "Observed configured CPUs {}, effective CPUs {}; expected the same nonempty set of at most {limit} CPU(s) from the default runner. This verifies CPU confinement, not resource relief",
        requested.as_list(),
        effective.as_list(),
    );
    Ok(if matches {
        ActionPostcondition::Satisfied { detail }
    } else {
        ActionPostcondition::NotSatisfied { detail }
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn renice_postcondition(
    target: &ProcessIdentity,
    observed: &crate::action::ReniceReversalMetadata,
) -> ActionPostcondition {
    use crate::action::{DEFAULT_NICE_VALUE, MAX_NICE_VALUE};

    if observed.pid != target.pid.0 {
        return ActionPostcondition::IdentityChanged;
    }
    #[cfg(target_os = "linux")]
    {
        let Some(identity) = observed.identity.as_ref() else {
            return ActionPostcondition::Unavailable {
                reason: "The priority snapshot has no process identity".to_string(),
            };
        };
        if identity.pid != target.pid
            || identity.start_id != target.start_id
            || identity.uid != target.uid
        {
            return ActionPostcondition::IdentityChanged;
        }
        let mut seen = HashSet::new();
        if observed.threads.is_empty()
            || observed.threads.iter().any(|thread| {
                thread.tid == 0
                    || thread.uid != target.uid
                    || !seen.insert(thread.tid)
                    || !(-20..=MAX_NICE_VALUE).contains(&thread.previous_nice)
            })
            || !seen.contains(&target.pid.0)
        {
            return ActionPostcondition::Unavailable {
                reason: "The priority snapshot has an incomplete or invalid thread census"
                    .to_string(),
            };
        }
        if let Some(thread) = observed
            .threads
            .iter()
            .find(|thread| thread.previous_nice < DEFAULT_NICE_VALUE)
        {
            return ActionPostcondition::NotSatisfied {
                detail: format!(
                    "Thread {} remains at nice {}; expected at least {DEFAULT_NICE_VALUE} on every current thread",
                    thread.tid, thread.previous_nice,
                ),
            };
        }
        ActionPostcondition::Satisfied {
            detail: format!(
                "Observed all {} current threads at nice >= {DEFAULT_NICE_VALUE}; this verifies priority, not resource relief",
                observed.threads.len(),
            ),
        }
    }
    #[cfg(target_os = "macos")]
    {
        if !(-20..=MAX_NICE_VALUE).contains(&observed.previous_nice) {
            ActionPostcondition::Unavailable {
                reason: "The observed process priority is invalid".to_string(),
            }
        } else if observed.previous_nice < DEFAULT_NICE_VALUE {
            ActionPostcondition::NotSatisfied {
                detail: format!(
                    "Observed nice {}; expected at least {DEFAULT_NICE_VALUE}",
                    observed.previous_nice,
                ),
            }
        } else {
            ActionPostcondition::Satisfied {
                detail: format!(
                    "Observed nice {}; expected at least {DEFAULT_NICE_VALUE}; this verifies priority, not resource relief",
                    observed.previous_nice,
                ),
            }
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ExpectedResourcesFreed {
    /// Saved private-clean plus private-dirty forecast, in MiB; not measured relief.
    pub memory_mb: f64,
}

#[derive(Debug, Serialize)]
pub struct RespawnDetected {
    /// The replacement child, distinct from the parent that spawned it.
    pub pid: u32,
    pub cmd_full: String,
    pub start_time_unix: i64,
    pub parent_pid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_cmd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_start_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ResourceSummary {
    /// Saved private-memory forecasts for unique executed targets confirmed dead.
    /// This is a planning forecast in MiB, not a measured resource delta.
    pub expected_freed_mb: f64,
    pub expected_mb: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shortfall_reason: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("invalid action plan: {0}")]
    InvalidPlan(String),
    #[error("invalid saved action outcomes: {0}")]
    InvalidOutcomes(String),
    #[error("invalid execution timestamp: {0}")]
    InvalidTimestamp(String),
    #[error("invalid saved resource predictions: {0}")]
    InvalidResourcePredictions(String),
}

pub fn parse_agent_plan(content: &str) -> Result<Plan, VerifyError> {
    let plan: Plan = serde_json::from_str(content)
        .map_err(|error| VerifyError::InvalidPlan(error.to_string()))?;
    let mut seen = HashSet::new();
    for action in &plan.actions {
        if action.action_id.is_empty() || !seen.insert(&action.action_id) {
            return Err(VerifyError::InvalidPlan(
                "empty or duplicate action_id".to_string(),
            ));
        }
        if action.target.pid.0 == 0 || action.target.start_id.0.is_empty() {
            return Err(VerifyError::InvalidPlan(
                "missing target identity".to_string(),
            ));
        }
        if action.action == Action::CapMemory {
            let cap = action.memory_cap.as_ref().ok_or_else(|| {
                VerifyError::InvalidPlan(
                    "memory cap is missing its planned limit and scope".to_string(),
                )
            })?;
            cap.validate(&action.target).map_err(|error| {
                VerifyError::InvalidPlan(format!("invalid memory cap binding: {error}"))
            })?;
            if action.routing != crate::plan::ActionRouting::Direct
                || action.original_zombie_target.is_some()
                || action.supervisor_restart.is_some()
            {
                return Err(VerifyError::InvalidPlan(
                    "memory cap requires a direct target without zombie or supervisor rerouting"
                        .to_string(),
                ));
            }
        } else if action.memory_cap.is_some() {
            return Err(VerifyError::InvalidPlan(
                "memory cap binding is attached to a different action".to_string(),
            ));
        }
    }
    Ok(plan)
}

pub fn parse_action_outcomes(content: &str) -> Result<Vec<SavedActionOutcome>, VerifyError> {
    content
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| {
            serde_json::from_str(line).map_err(|error| {
                VerifyError::InvalidOutcomes(format!("line {}: {error}", index + 1))
            })
        })
        .collect()
}

fn is_failed_attempt(status: &str) -> bool {
    matches!(
        status,
        "failed"
            | "timeout"
            | "permission_denied"
            | "process_not_found"
            | "identity_mismatch"
            | "identity_check_failed"
            | "unsupported_platform"
    )
}

/// Bind actual successful executions to the canonical action and identity.
/// Later skipped resume records cannot erase a previous successful execution.
pub fn executed_plan_actions<'a>(
    plan: &'a Plan,
    saved: &'a [SavedActionOutcome],
) -> Result<Vec<(&'a PlanAction, &'a SavedActionOutcome)>, VerifyError> {
    let recorded = recorded_plan_actions(plan, saved)?;
    validate_execution_timestamps(saved, Utc::now())?;
    Ok(recorded
        .into_iter()
        .filter(|(_, outcome)| outcome.status == "success")
        .collect())
}

/// Retain the latest substantive attempt per action. A later valid success
/// resolves that action's failure; skipped/dry-run records resolve nothing.
fn recorded_plan_actions<'a>(
    plan: &'a Plan,
    saved: &'a [SavedActionOutcome],
) -> Result<Vec<(&'a PlanAction, &'a SavedActionOutcome)>, VerifyError> {
    let actions: HashMap<_, _> = plan
        .actions
        .iter()
        .map(|action| (action.action_id.as_str(), action))
        .collect();
    let mut latest: HashMap<&str, &SavedActionOutcome> = HashMap::new();
    for outcome in saved {
        if matches!(
            outcome.status.as_str(),
            "dry_run"
                | "shadow"
                | "skipped"
                | "precheck_blocked"
                | "blocked_by_plan"
                | "blocked_by_constraints"
                | "blocked_by_policy"
                | "already_completed"
        ) {
            continue;
        }
        if outcome.status != "success" && !is_failed_attempt(&outcome.status) {
            return Err(VerifyError::InvalidOutcomes(format!(
                "{} has unknown execution status {}",
                outcome.action_id, outcome.status
            )));
        }
        let Some(action) = actions.get(outcome.action_id.as_str()) else {
            return Err(VerifyError::InvalidOutcomes(format!(
                "{} action {} is absent from the plan",
                outcome.status, outcome.action_id
            )));
        };
        if outcome.status == "success" && outcome.action != Some(action.action) {
            return Err(VerifyError::InvalidOutcomes(format!(
                "{} successful execution action kind {:?} does not match plan action {:?}",
                outcome.action_id, outcome.action, action.action
            )));
        }
        if action.action == Action::Keep {
            continue;
        }
        if is_failed_attempt(&outcome.status) {
            if outcome.pid != action.target.pid.0
                || outcome
                    .target
                    .as_ref()
                    .is_some_and(|target| !target.matches(&action.target))
            {
                return Err(VerifyError::InvalidOutcomes(format!(
                    "{} failed attempt target does not match the plan",
                    outcome.action_id
                )));
            }
            latest.insert(&outcome.action_id, outcome);
            continue;
        }
        if action.blocked {
            return Err(VerifyError::InvalidOutcomes(format!(
                "successful action {} contradicts the plan's blocked action",
                outcome.action_id
            )));
        }
        if action.routing == crate::plan::ActionRouting::Supervisor {
            crate::action::supervisor::restart_binding_for_action(action).map_err(|error| {
                VerifyError::InvalidOutcomes(format!(
                    "{} has an invalid supervisor restart route: {error}",
                    outcome.action_id
                ))
            })?;
            if outcome.supervisor_restart != action.supervisor_restart {
                return Err(VerifyError::InvalidOutcomes(format!(
                    "{} executed supervisor binding does not match the plan",
                    outcome.action_id
                )));
            }
        } else if outcome.supervisor_restart.is_some() || action.supervisor_restart.is_some() {
            return Err(VerifyError::InvalidOutcomes(format!(
                "{} has supervisor evidence without a supervisor restart route",
                outcome.action_id
            )));
        }
        let target = outcome.target.as_ref().ok_or_else(|| {
            VerifyError::InvalidOutcomes(format!(
                "{} lacks executed target identity",
                outcome.action_id
            ))
        })?;
        if outcome.pid != action.target.pid.0
            || !target.matches(&action.target)
            || !target.can_safely_revalidate()
        {
            return Err(VerifyError::InvalidOutcomes(format!(
                "{} executed target does not match the plan",
                outcome.action_id
            )));
        }
        let executed_at = outcome.executed_at.ok_or_else(|| {
            VerifyError::InvalidOutcomes(format!("{} lacks execution timestamp", outcome.action_id))
        })?;
        if action.action == Action::Kill
            && (outcome
                .command
                .as_deref()
                .map(normalize_cmd)
                .is_none_or(|cmd| cmd.is_empty())
                || outcome.parent_pid.is_none_or(|pid| pid == 0))
        {
            return Err(VerifyError::InvalidOutcomes(format!(
                "{} lacks full command or parent execution evidence",
                outcome.action_id
            )));
        }
        if let Some(parent) = &outcome.parent_identity {
            if Some(parent.pid.0) != outcome.parent_pid || !parent.can_safely_revalidate() {
                return Err(VerifyError::InvalidOutcomes(format!(
                    "{} has inconsistent parent identity",
                    outcome.action_id
                )));
            }
        }
        if let Some(clock) = &outcome.execution_clock {
            if clock.boot_id.is_empty() {
                return Err(VerifyError::InvalidOutcomes(format!(
                    "{} has an empty execution boot identity",
                    outcome.action_id
                )));
            }
            let mut start_parts = target.start_id.0.rsplitn(3, ':');
            let start_pid = start_parts.next().and_then(|part| part.parse::<u32>().ok());
            let start_ticks = start_parts.next().and_then(|part| part.parse::<u64>().ok());
            let start_boot = start_parts.next();
            if start_pid != Some(target.pid.0)
                || start_boot != Some(clock.boot_id.as_str())
                || start_ticks.is_none_or(|ticks| ticks > clock.ticks)
            {
                return Err(VerifyError::InvalidOutcomes(format!(
                    "{} has execution clock inconsistent with its target",
                    outcome.action_id
                )));
            }
        } else if cfg!(target_os = "linux") && action.action == Action::Kill {
            return Err(VerifyError::InvalidOutcomes(format!(
                "{} lacks boot-tick execution evidence for respawn verification",
                outcome.action_id
            )));
        }
        let previous = latest.get(outcome.action_id.as_str());
        if previous.is_none_or(|previous| {
            is_failed_attempt(&previous.status)
                || previous.executed_at.is_none_or(|at| executed_at >= at)
        }) {
            latest.insert(&outcome.action_id, outcome);
        }
    }
    Ok(plan
        .actions
        .iter()
        .filter_map(|action| {
            latest
                .get(action.action_id.as_str())
                .map(|&outcome| (action, outcome))
        })
        .collect())
}

/// Find a replacement for one executed kill, using the same matcher in both
/// verification and --check-respawn. Missing or ambiguous evidence never matches.
pub fn detect_respawn(
    action: &PlanAction,
    executed: &SavedActionOutcome,
    current: &[ProcessRecord],
) -> Option<RespawnDetected> {
    find_respawn_with_birth_order(action, executed, current, std::cmp::Ordering::Greater)
}

fn find_respawn_with_birth_order(
    action: &PlanAction,
    executed: &SavedActionOutcome,
    current: &[ProcessRecord],
    required_order: std::cmp::Ordering,
) -> Option<RespawnDetected> {
    if action.action != Action::Kill
        || action.blocked
        || executed.status != "success"
        || executed.action != Some(action.action)
        || executed.action_id != action.action_id
        || executed.pid != action.target.pid.0
        || !executed.target.as_ref()?.matches(&action.target)
    {
        return None;
    }
    let command = normalize_cmd(executed.command.as_deref()?);
    if command.is_empty() {
        return None;
    }
    let parent_pid = executed.parent_pid?;
    let parent = current.iter().find(|process| process.pid.0 == parent_pid);
    if let Some(identity) = &executed.parent_identity {
        let parent = parent?;
        if parent.pid != identity.pid
            || parent.uid != identity.uid
            || parent.start_id != identity.start_id
        {
            return None;
        }
    }
    let executed_at = executed.executed_at?;
    let replacement = current
        .iter()
        .filter(|process| {
            process.uid == action.target.uid
                && process.ppid.0 == parent_pid
                && !process.state.is_zombie()
                && process.start_id != action.target.start_id
                && normalize_cmd(&process.cmd) == command
                && execution_birth_order(process, executed, executed_at) == Some(required_order)
        })
        .max_by_key(|process| (process.start_time_unix, process.pid.0))?;
    Some(RespawnDetected {
        pid: replacement.pid.0,
        cmd_full: replacement.cmd.clone(),
        start_time_unix: replacement.start_time_unix,
        parent_pid,
        parent_cmd: parent.map(|process| process.cmd.clone()),
        parent_start_id: parent.map(|process| process.start_id.0.clone()),
    })
}

fn execution_birth_order(
    process: &ProcessRecord,
    executed: &SavedActionOutcome,
    executed_at: DateTime<Utc>,
) -> Option<std::cmp::Ordering> {
    if let Some(clock) = &executed.execution_clock {
        let mut parts = process.start_id.0.rsplitn(3, ':');
        let pid = parts.next().and_then(|part| part.parse::<u32>().ok());
        let ticks = parts.next().and_then(|part| part.parse::<u64>().ok());
        let boot = parts.next();
        if pid != Some(process.pid.0) || boot != Some(clock.boot_id.as_str()) {
            return None;
        }
        return Some(ticks?.cmp(&clock.ticks));
    }
    // The remaining platforms expose whole seconds. Equality is ambiguous;
    // require a strictly later second instead of treating a preexisting peer as
    // a respawn. Linux's boot-tick path above handles later births in one second.
    Some(process.start_time_unix.cmp(&executed_at.timestamp()))
}

fn validate_execution_timestamps(
    saved: &[SavedActionOutcome],
    completed_at: DateTime<Utc>,
) -> Result<(), VerifyError> {
    for execution in saved
        .iter()
        .filter(|execution| execution.status == "success" || is_failed_attempt(&execution.status))
    {
        if execution.executed_at.is_some_and(|at| at > completed_at) {
            return Err(VerifyError::InvalidTimestamp(format!(
                "{} execution occurs after verification",
                execution.action_id
            )));
        }
    }
    Ok(())
}

pub fn verify_plan(
    plan: &Plan,
    saved: &[SavedActionOutcome],
    current: &[ProcessRecord],
    requested_at: DateTime<Utc>,
    completed_at: DateTime<Utc>,
) -> Result<VerificationReport, VerifyError> {
    verify_plan_with_postconditions(
        plan,
        saved,
        current,
        requested_at,
        completed_at,
        |_| ActionPostcondition::Unavailable {
            reason: "No fresh action-specific observation was supplied".to_string(),
        },
        None,
    )
}

/// Verify saved successful executions against current, identity-bound evidence.
///
/// Process snapshots prove Kill/Pause/Resume states. A paused process may also
/// have a durable, independently observed restoration. Priority and controller
/// actions need separate current observations, injected to keep fixture replay pure.
/// Missing, failed and planning-only execution records never invoke the observer.
pub fn verify_plan_with_postconditions(
    plan: &Plan,
    saved: &[SavedActionOutcome],
    current: &[ProcessRecord],
    requested_at: DateTime<Utc>,
    completed_at: DateTime<Utc>,
    mut observe: impl FnMut(&PlanAction) -> ActionPostcondition,
    resource_predictions: Option<&ValidatedResourcePredictions>,
) -> Result<VerificationReport, VerifyError> {
    let recorded = recorded_plan_actions(plan, saved)?;
    validate_execution_timestamps(saved, completed_at)?;
    let resource_predictions = resource_predictions
        .map(|predictions| predictions.snapshot().validate(plan))
        .transpose()
        .map_err(VerifyError::InvalidResourcePredictions)?;
    let prediction_generated_at = resource_predictions
        .as_ref()
        .and_then(|predictions| {
            DateTime::parse_from_rfc3339(&predictions.snapshot().generated_at).ok()
        })
        .map(|time| time.with_timezone(&Utc));
    let by_pid: HashMap<_, _> = current
        .iter()
        .map(|process| (process.pid.0, process))
        .collect();
    let mut outcomes = Vec::new();
    // A staged plan may mention the same incarnation more than once. Totals
    // require complete, consistent saved forecasts and count each target once.
    let mut kill_memory: HashMap<(u32, String, u32), (Option<u64>, bool)> = HashMap::new();
    let mut recommendations = Vec::new();
    let mut any_failed = false;
    let mut any_success = false;

    for (action, execution) in recorded {
        if is_failed_attempt(&execution.status) {
            any_failed = true;
            recommendations.push(format!(
                "PID {} apply attempt failed; inspect the saved outcome before retrying",
                action.target.pid.0
            ));
            let command = execution
                .command
                .as_ref()
                .filter(|command| !command.trim().is_empty());
            outcomes.push(ActionOutcome {
                action_id: action.action_id.clone(),
                target: VerifyTarget {
                    pid: action.target.pid.0,
                    start_id: action.target.start_id.0.clone(),
                    uid: action.target.uid,
                    cmd_short: command
                        .and_then(|command| command.split_whitespace().next().map(str::to_string)),
                    cmd_full: command.cloned(),
                },
                action: action.action.as_str().to_string(),
                outcome: VerifyOutcome::Unsupported,
                time_to_death_ms: None,
                expected_resources_freed: None,
                respawn_detected: None,
                expected: Some("successful_execution".to_string()),
                actual: Some("failed_attempt".to_string()),
                verified: Some(false),
                note: Some(format!(
                    "Apply recorded a {} attempt; its effects and respawns are not established",
                    execution.status
                )),
                restoration: None,
            });
            continue;
        }
        let mut restoration = None;
        let memory_prediction = resource_predictions
            .as_ref()
            .and_then(|predictions| predictions.for_action(action))
            .and_then(|prediction| prediction.memory.as_ref());
        let forecast_precedes_execution = prediction_generated_at
            .as_ref()
            .zip(execution.executed_at.as_ref())
            .is_some_and(|(generated, executed)| generated <= executed);
        let expected_memory_bytes = if action.action == Action::Kill && forecast_precedes_execution
        {
            memory_prediction.map(|memory| memory.bytes)
        } else {
            None
        };
        let current_target = by_pid.get(&action.target.pid.0).copied();
        let respawn = detect_respawn(action, execution, current);
        let ambiguous_respawn = if respawn.is_none() {
            find_respawn_with_birth_order(action, execution, current, std::cmp::Ordering::Equal)
        } else {
            None
        };
        let (outcome, actual, mut note) = if respawn.is_some() {
            (VerifyOutcome::Respawned, "respawned", None)
        } else if let Some(possible) = &ambiguous_respawn {
            (
                VerifyOutcome::Unsupported,
                "ambiguous_respawn",
                Some(format!(
                    "Matching PID {} from parent {} was born in the execution clock's same tick or second; its birth cannot be ordered against the kill",
                    possible.pid, possible.parent_pid
                )),
            )
        } else {
            match (action.action, current_target) {
                (Action::Restart, _)
                    if action.routing == crate::plan::ActionRouting::Supervisor =>
                {
                    // The old PID is expected to disappear. Neither its absence,
                    // reuse nor a saved success can prove the new service state.
                    match observe(action) {
                        ActionPostcondition::Satisfied { detail } => (
                            VerifyOutcome::ConfirmedEffect,
                            "supervisor_restart_verified",
                            Some(detail),
                        ),
                        ActionPostcondition::NotSatisfied { detail } => (
                            VerifyOutcome::EffectNotObserved,
                            "supervisor_restart_not_observed",
                            Some(detail),
                        ),
                        ActionPostcondition::Unavailable { reason } => (
                            VerifyOutcome::Unsupported,
                            "observation_unavailable",
                            Some(reason),
                        ),
                        ActionPostcondition::IdentityChanged => (
                            VerifyOutcome::Unsupported,
                            "supervisor_binding_changed",
                            Some("The service binding changed during observation".to_string()),
                        ),
                        ActionPostcondition::Restored { .. } => (
                            VerifyOutcome::RestorationUnverified,
                            "restoration_unverified",
                            Some(
                                "Cgroup restoration evidence cannot verify a supervisor restart"
                                    .to_string(),
                            ),
                        ),
                        ActionPostcondition::RestorationUnverified { reason } => (
                            VerifyOutcome::RestorationUnverified,
                            "restoration_unverified",
                            Some(reason),
                        ),
                    }
                }
                (
                    Action::Kill
                    | Action::Pause
                    | Action::Resume
                    | Action::Renice
                    | Action::Freeze
                    | Action::Unfreeze
                    | Action::Throttle
                    | Action::CapMemory
                    | Action::Quarantine,
                    Some(process),
                ) if process.start_id != action.target.start_id
                    || process.uid != action.target.uid =>
                {
                    (VerifyOutcome::PidReused, "pid_reused", None)
                }
                (Action::Kill, None) => (VerifyOutcome::ConfirmedDead, "not_found", None),
                (Action::Kill, Some(process)) if process.state.is_zombie() => {
                    (VerifyOutcome::ConfirmedDead, "zombie", None)
                }
                (Action::Pause, Some(process))
                    if !matches!(
                        process.state,
                        ProcessState::Zombie | ProcessState::Dead | ProcessState::Unknown
                    ) =>
                {
                    // An intentional undo supersedes the old stopped-state
                    // expectation. Inspect it even if the snapshot is stopped:
                    // the process may have been stopped again after restoration,
                    // or may already have been stopped before our original action.
                    match observe(action) {
                        ActionPostcondition::Restored { observation }
                            if observation.action_id == action.action_id
                                && matches!(
                                    &observation.original_value,
                                    RestorationValue::JobControl { .. }
                                ) =>
                        {
                            let detail = format!(
                                "The recorded original job-control state was independently observed at {}; undo {} restored execution attempt {}. The original pause history is retained; this is not evidence of resource relief",
                                observation.observed_at,
                                observation.restore_id,
                                observation.attempt_id,
                            );
                            restoration = Some(observation);
                            (
                                VerifyOutcome::ConfirmedRestored,
                                "restoration_verified",
                                Some(detail),
                            )
                        }
                        ActionPostcondition::Restored { .. } => (
                            VerifyOutcome::RestorationUnverified,
                            "restoration_unverified",
                            Some(
                                "Restoration observation does not match this pause and job-control state"
                                    .to_string(),
                            ),
                        ),
                        ActionPostcondition::RestorationUnverified { reason } => (
                            VerifyOutcome::RestorationUnverified,
                            "restoration_unverified",
                            Some(reason),
                        ),
                        ActionPostcondition::IdentityChanged => (
                            VerifyOutcome::PidReused,
                            "identity_changed",
                            Some("The process identity changed during pause observation".to_string()),
                        ),
                        ActionPostcondition::Satisfied { detail } => (
                            VerifyOutcome::ConfirmedStopped,
                            "stopped",
                            Some(detail),
                        ),
                        ActionPostcondition::NotSatisfied { detail } => (
                            VerifyOutcome::EffectNotObserved,
                            "pause_postcondition_not_observed",
                            Some(detail),
                        ),
                        // Without restoration evidence, preserve snapshot-only
                        // verification when no live observer is available,
                        // including pure offline replay.
                        _ if process.state == ProcessState::Stopped => {
                            (VerifyOutcome::ConfirmedStopped, "stopped", None)
                        }
                        _ => (VerifyOutcome::StillRunning, "still_running", None),
                    }
                }
                (Action::Resume, Some(process))
                    if matches!(
                        process.state,
                        ProcessState::Running
                            | ProcessState::Sleeping
                            | ProcessState::DiskSleep
                            | ProcessState::Idle
                    ) =>
                {
                    (
                        VerifyOutcome::ConfirmedEffect,
                        "resumed",
                        Some(format!(
                            "The same process is in state {}; it is no longer stopped. This does not establish useful work or resource relief",
                            process.state,
                        )),
                    )
                }
                (Action::Resume, Some(process)) if process.state == ProcessState::Stopped => (
                    VerifyOutcome::EffectNotObserved,
                    "still_stopped",
                    Some("The executed target is still stopped".to_string()),
                ),
                (
                    Action::Renice
                    | Action::Freeze
                    | Action::Unfreeze
                    | Action::Throttle
                    | Action::CapMemory
                    | Action::Quarantine,
                    Some(process),
                ) if !matches!(
                    process.state,
                    ProcessState::Zombie | ProcessState::Dead | ProcessState::Unknown
                ) =>
                {
                    match observe(action) {
                        ActionPostcondition::Satisfied { detail } => (
                            VerifyOutcome::ConfirmedEffect,
                            match action.action {
                                Action::Renice => "priority_verified",
                                Action::Freeze => "freeze_verified",
                                Action::Unfreeze => "thaw_verified",
                                Action::Throttle => "cpu_limit_verified",
                                Action::CapMemory => "memory_high_verified",
                                Action::Quarantine => "cpu_confinement_verified",
                                _ => unreachable!(),
                            },
                            Some(detail),
                        ),
                        ActionPostcondition::NotSatisfied { detail } => (
                            VerifyOutcome::EffectNotObserved,
                            match action.action {
                                Action::Renice => "priority_not_adjusted",
                                Action::Freeze => "not_frozen",
                                Action::Unfreeze => "still_frozen",
                                Action::Throttle => "cpu_limit_not_adjusted",
                                Action::CapMemory => "memory_high_not_adjusted",
                                Action::Quarantine => "cpu_confinement_not_adjusted",
                                _ => unreachable!(),
                            },
                            Some(detail),
                        ),
                        ActionPostcondition::Unavailable { reason } => (
                            VerifyOutcome::Unsupported,
                            "observation_unavailable",
                            Some(reason),
                        ),
                        ActionPostcondition::IdentityChanged => (
                            VerifyOutcome::PidReused,
                            "identity_changed",
                            Some(
                                "The process identity changed during postcondition observation"
                                    .to_string(),
                            ),
                        ),
                        ActionPostcondition::Restored { observation }
                            if observation.action_id == action.action_id
                                && matches!(
                                    (action.action, &observation.original_value),
                                    (
                                        Action::Freeze | Action::Unfreeze,
                                        RestorationValue::Freeze { .. }
                                    ) | (Action::Throttle, RestorationValue::CpuMax { .. })
                                        | (Action::CapMemory, RestorationValue::MemoryHigh { .. })
                                        | (Action::Quarantine, RestorationValue::Cpuset { .. })
                                        | (
                                            Action::Renice,
                                            RestorationValue::ThreadPriorities { .. }
                                        )
                                ) =>
                        {
                            let detail = format!(
                                "The recorded original state was independently observed at {}; undo {} restored execution attempt {}. The original action history is retained; this is not evidence of resource relief",
                                observation.observed_at,
                                observation.restore_id,
                                observation.attempt_id,
                            );
                            restoration = Some(observation);
                            (
                                VerifyOutcome::ConfirmedRestored,
                                "restoration_verified",
                                Some(detail),
                            )
                        }
                        ActionPostcondition::Restored { .. } => (
                            VerifyOutcome::RestorationUnverified,
                            "restoration_unverified",
                            Some(
                                "Restoration observation does not match this action and control"
                                    .to_string(),
                            ),
                        ),
                        ActionPostcondition::RestorationUnverified { reason } => (
                            VerifyOutcome::RestorationUnverified,
                            "restoration_unverified",
                            Some(reason),
                        ),
                    }
                }
                (Action::Kill | Action::Pause, Some(_)) => {
                    (VerifyOutcome::StillRunning, "still_running", None)
                }
                _ => (
                    VerifyOutcome::Unsupported,
                    "not_verified",
                    Some(
                        "The current process scan cannot establish this action's effect"
                            .to_string(),
                    ),
                ),
            }
        };
        let verified = matches!(
            outcome,
            VerifyOutcome::ConfirmedDead
                | VerifyOutcome::ConfirmedStopped
                | VerifyOutcome::ConfirmedEffect
                | VerifyOutcome::ConfirmedRestored
        );
        any_success |= verified;
        any_failed |= !verified;
        if action.action == Action::Kill
            && memory_prediction.is_some()
            && !forecast_precedes_execution
        {
            let reason = "Saved private-memory forecast does not precede the recorded execution; its recovery estimate is unavailable";
            note = Some(match note {
                Some(previous) => format!("{previous}. {reason}"),
                None => reason.to_string(),
            });
        }
        if action.action == Action::Kill {
            kill_memory
                .entry((
                    action.target.pid.0,
                    action.target.start_id.0.clone(),
                    action.target.uid,
                ))
                .and_modify(|(bytes, confirmed)| {
                    if *bytes != expected_memory_bytes {
                        *bytes = None;
                    }
                    *confirmed &= verified;
                })
                .or_insert((expected_memory_bytes, verified));
        }
        if let Some(respawn) = &respawn {
            recommendations.push(format!(
                "PID {} respawned as {}; inspect spawner PID {} ({}) before another kill",
                action.target.pid.0,
                respawn.pid,
                respawn.parent_pid,
                respawn
                    .parent_cmd
                    .as_deref()
                    .unwrap_or("command unavailable")
            ));
        } else if outcome == VerifyOutcome::PidReused {
            recommendations.push(format!(
                "PID {} reused; regenerate plan before taking action",
                action.target.pid.0
            ));
        } else if outcome == VerifyOutcome::StillRunning {
            recommendations.push(format!(
                "PID {} still active; investigate the executed action",
                action.target.pid.0
            ));
        } else if outcome == VerifyOutcome::EffectNotObserved {
            recommendations.push(format!(
                "PID {} does not satisfy the requested action effect; inspect its current state before retrying",
                action.target.pid.0,
            ));
        } else if outcome == VerifyOutcome::RestorationUnverified {
            recommendations.push(format!(
                "PID {} has unverified restoration evidence; inspect the durable undo receipt and current controller state before taking further action",
                action.target.pid.0,
            ));
        }
        let command = execution
            .command
            .as_ref()
            .filter(|command| !command.is_empty());
        outcomes.push(ActionOutcome {
            action_id: action.action_id.clone(),
            target: VerifyTarget {
                pid: action.target.pid.0,
                start_id: action.target.start_id.0.clone(),
                uid: action.target.uid,
                cmd_short: command
                    .and_then(|command| command.split_whitespace().next().map(str::to_string)),
                cmd_full: command.cloned(),
            },
            action: action.action.as_str().to_string(),
            outcome,
            time_to_death_ms: None,
            expected_resources_freed: if verified && action.action == Action::Kill {
                expected_memory_bytes.map(|bytes| ExpectedResourcesFreed {
                    memory_mb: bytes as f64 / (1024.0 * 1024.0),
                })
            } else {
                None
            },
            respawn_detected: respawn,
            expected: Some(
                if restoration.is_some() {
                    match action.action {
                        Action::Pause => "recorded_original_job_control_state",
                        Action::Renice => "recorded_original_thread_priorities",
                        _ => "recorded_original_controller_state",
                    }
                } else {
                    match action.action {
                        Action::Kill => "terminated",
                        Action::Pause => "stopped",
                        Action::Resume => "not_stopped",
                        Action::Renice => "default_nice_priority_on_every_current_thread",
                        Action::Freeze => "cgroup_freeze_requested_and_completed",
                        Action::Unfreeze => "cgroup_thaw_requested_and_completed",
                        Action::Throttle => "default_cpu_bandwidth_ceiling",
                        Action::CapMemory => "exact_planned_memory_high_soft_cap",
                        Action::Quarantine => "nonempty_effective_cpu_confinement",
                        Action::Restart
                            if action.routing == crate::plan::ActionRouting::Supervisor =>
                        {
                            "new_live_main_pid_and_invocation_in_bound_user_service"
                        }
                        _ => "effect_requires_additional_evidence",
                    }
                }
                .to_string(),
            ),
            actual: Some(actual.to_string()),
            verified: Some(verified),
            note,
            restoration,
        });
    }
    let overall_status = if any_success && any_failed {
        "partial_success"
    } else if any_failed {
        "failure"
    } else {
        "success"
    };
    let resource_summary = if kill_memory.is_empty() {
        None
    } else {
        kill_memory
            .values()
            .try_fold((0_u128, 0_u128), |(expected, freed), (bytes, confirmed)| {
                let bytes = u128::from((*bytes)?);
                Some((
                    expected.checked_add(bytes)?,
                    freed.checked_add(if *confirmed { bytes } else { 0 })?,
                ))
            })
            .map(|(expected, freed)| ResourceSummary {
                expected_mb: expected as f64 / (1024.0 * 1024.0),
                expected_freed_mb: freed as f64 / (1024.0 * 1024.0),
                shortfall_reason: (freed < expected)
                    .then(|| "some executed kills remain active or respawned".to_string()),
            })
    };
    Ok(VerificationReport {
        schema_version: pt_common::SCHEMA_VERSION.to_string(),
        session_id: plan.session_id.clone(),
        verification: VerificationWindow {
            requested_at: requested_at.to_rfc3339(),
            completed_at: completed_at.to_rfc3339(),
            overall_status: overall_status.to_string(),
        },
        action_outcomes: outcomes,
        resource_summary,
        follow_up_needed: Some(any_failed),
        recommendations: (!recommendations.is_empty()).then_some(recommendations),
    })
}

fn normalize_cmd(command: &str) -> String {
    command.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::{
        ActionConfidence, ActionRationale, ActionRouting, ActionTimeouts, GatesSummary,
    };
    use pt_common::{ProcessId, StartId};
    use std::time::Duration;

    fn make_proc(pid: u32, uid: u32, cmd: &str, start: i64, state: ProcessState) -> ProcessRecord {
        ProcessRecord {
            pid: ProcessId(pid),
            ppid: ProcessId(10),
            uid,
            user: "test".to_string(),
            pgid: None,
            sid: None,
            start_id: StartId(format!("boot:{}:{}", start * 100, pid)),
            comm: cmd.split_whitespace().next().unwrap_or("").to_string(),
            cmd: cmd.to_string(),
            state,
            cpu_percent: 0.0,
            rss_bytes: 0,
            vsz_bytes: 0,
            tty: None,
            start_time_unix: start,
            elapsed: Duration::from_secs(60),
            source: "unit fixture".to_string(),
            container_info: None,
        }
    }

    fn make_action(pid: u32, action: Action) -> PlanAction {
        PlanAction {
            action_id: format!("act-{pid}"),
            target: ProcessIdentity::new(pid, StartId(format!("boot:500:{pid}")), 1000),
            action,
            order: 0,
            stage: 0,
            timeouts: ActionTimeouts::default(),
            pre_checks: vec![],
            rationale: ActionRationale {
                expected_loss: None,
                expected_recovery: None,
                expected_recovery_stddev: None,
                posterior_odds_abandoned_vs_useful: None,
                sprt_boundary: None,
                posterior: None,
                memory_mb: Some(100.0),
                has_known_signature: None,
                category: None,
            },
            on_success: vec![],
            on_failure: vec![],
            blocked: false,
            routing: ActionRouting::Direct,
            confidence: ActionConfidence::Normal,
            original_zombie_target: None,
            d_state_diagnostics: None,
            supervisor_restart: None,
            memory_cap: None,
        }
    }

    fn make_plan(actions: Vec<PlanAction>) -> Plan {
        Plan {
            plan_id: "plan-test".to_string(),
            session_id: "session-test".to_string(),
            generated_at: "1970-01-01T00:00:01Z".to_string(),
            policy_id: None,
            policy_version: "test".to_string(),
            pre_toggled: vec![],
            gates_summary: GatesSummary {
                total_candidates: actions.len(),
                blocked_candidates: 0,
                pre_toggled_actions: 0,
            },
            actions,
        }
    }

    fn memory_cap_action() -> PlanAction {
        let mut action = make_action(123, Action::CapMemory);
        let boot = "11111111-2222-4333-8444-555555555555";
        action.target.start_id = StartId::from_linux(boot, 500, 123);
        action.memory_cap = Some(crate::action::MemoryCapPlan {
            target: action.target.clone(),
            scope: crate::action::reversal::ReversalScope {
                cgroup_path: "/owned-leaf".to_string(),
                device: 1,
                inode: 2,
                mount_id: 3,
                boot_id: boot.to_string(),
                mount_namespace_device: 4,
                mount_namespace_inode: 5,
                cgroup_namespace_device: 4,
                cgroup_namespace_inode: 6,
            },
            limit_bytes: 180 * 1024 * 1024,
            observed_high_bytes: None,
            observed_current_bytes: 200 * 1024 * 1024,
            observed_low_bytes: 0,
            observed_min_bytes: 0,
            page_size_bytes: 4096,
        });
        action
    }

    #[test]
    fn canonical_plan_rejects_missing_modified_and_misrouted_memory_caps() {
        let action = memory_cap_action();
        let valid = make_plan(vec![action]);
        let decoded = parse_agent_plan(&serde_json::to_string(&valid).unwrap()).unwrap();
        assert_eq!(decoded.actions[0].memory_cap, valid.actions[0].memory_cap);
        for defect in [
            "missing",
            "limit",
            "identity",
            "route",
            "zombie",
            "other_action",
        ] {
            let mut changed = valid.clone();
            let action = &mut changed.actions[0];
            match defect {
                "missing" => action.memory_cap = None,
                "limit" => action.memory_cap.as_mut().unwrap().limit_bytes = 1,
                "identity" => action.memory_cap.as_mut().unwrap().target.uid += 1,
                "route" => action.routing = ActionRouting::ZombieToParent,
                "zombie" => action.original_zombie_target = Some(action.target.clone()),
                _ => action.action = Action::Kill,
            }
            let error = parse_agent_plan(&serde_json::to_string(&changed).unwrap()).unwrap_err();
            assert!(
                error.to_string().contains("memory cap"),
                "{defect}: {error}"
            );
        }
    }

    #[test]
    fn memory_cap_verification_distinguishes_configuration_from_memory_recovery() {
        let action = memory_cap_action();
        let saved = execution(&action);
        let mut current = make_proc(123, 1000, "worker", 5, ProcessState::Sleeping);
        current.start_id = action.target.start_id.clone();
        let plan = make_plan(vec![action]);
        for (observation, expected, actual) in [
            (
                ActionPostcondition::Satisfied {
                    detail: "planned soft cap observed; usage may still exceed it".to_string(),
                },
                VerifyOutcome::ConfirmedEffect,
                "memory_high_verified",
            ),
            (
                ActionPostcondition::NotSatisfied {
                    detail: "memory.high is now max".to_string(),
                },
                VerifyOutcome::EffectNotObserved,
                "memory_high_not_adjusted",
            ),
            (
                ActionPostcondition::Unavailable {
                    reason: "cgroup changed".to_string(),
                },
                VerifyOutcome::Unsupported,
                "observation_unavailable",
            ),
        ] {
            let report = verify_plan_with_postconditions(
                &plan,
                std::slice::from_ref(&saved),
                std::slice::from_ref(&current),
                DateTime::from_timestamp(30, 0).unwrap(),
                DateTime::from_timestamp(31, 0).unwrap(),
                |_| observation.clone(),
                None,
            )
            .unwrap();
            let outcome = &report.action_outcomes[0];
            assert_eq!(outcome.action, "cap_memory");
            assert_eq!(outcome.outcome, expected);
            assert_eq!(outcome.actual.as_deref(), Some(actual));
            assert!(outcome.expected_resources_freed.is_none());
            assert!(report.resource_summary.is_none());
        }
    }

    /// Unit fixtures exercise the parser/matcher; they are not live kill proof.
    fn execution(action: &PlanAction) -> SavedActionOutcome {
        SavedActionOutcome {
            action_id: action.action_id.clone(),
            pid: action.target.pid.0,
            status: "success".to_string(),
            action: Some(action.action),
            target: Some(action.target.clone()),
            supervisor_restart: action.supervisor_restart.clone(),
            command: Some("node app --port 3000".to_string()),
            parent_pid: Some(10),
            parent_identity: None,
            executed_at: Some(DateTime::from_timestamp(10, 0).unwrap()),
            execution_clock: Some(ExecutionClock {
                boot_id: "boot".to_string(),
                ticks: 1000,
            }),
            time_ms: Some(50),
        }
    }

    fn failed_attempt(action: &PlanAction) -> SavedActionOutcome {
        // A failed record can identify the canonical action/PID without asserting
        // execution evidence; missing fields must never invent a successful effect.
        serde_json::from_value(serde_json::json!({
            "action_id": action.action_id,
            "pid": action.target.pid.0,
            "status": "failed",
            "error": "unit fixture: runner returned an error",
            "time_ms": 50,
        }))
        .unwrap()
    }

    fn report(
        plan: &Plan,
        saved: &[SavedActionOutcome],
        current: &[ProcessRecord],
    ) -> VerificationReport {
        verify_plan(
            plan,
            saved,
            current,
            DateTime::from_timestamp(30, 0).unwrap(),
            DateTime::from_timestamp(31, 0).unwrap(),
        )
        .unwrap()
    }

    fn private_predictions(plan: &Plan, measured: &[(usize, u64)]) -> ValidatedResourcePredictions {
        use crate::verify::resource_prediction::{
            ActionResourcePrediction, PrivateMemoryPrediction, ResourcePredictionSnapshot,
            RESOURCE_PREDICTION_SCHEMA_VERSION,
        };
        ResourcePredictionSnapshot {
            schema_version: RESOURCE_PREDICTION_SCHEMA_VERSION,
            session_id: plan.session_id.clone(),
            plan_id: plan.plan_id.clone(),
            generated_at: "1970-01-01T00:00:09Z".into(),
            actions: measured
                .iter()
                .map(|&(index, bytes)| {
                    let action = &plan.actions[index];
                    ActionResourcePrediction {
                        action_id: action.action_id.clone(),
                        action: action.action,
                        target: action.target.clone(),
                        memory: Some(PrivateMemoryPrediction::new(bytes, 0, None, 1_000).unwrap()),
                        cpu: None,
                        file_descriptors: None,
                        disk: None,
                        unavailable: Vec::new(),
                    }
                })
                .collect(),
        }
        .validate(plan)
        .unwrap()
    }

    fn forecast_report(
        plan: &Plan,
        saved: &[SavedActionOutcome],
        current: &[ProcessRecord],
        predictions: &ValidatedResourcePredictions,
    ) -> VerificationReport {
        verify_plan_with_postconditions(
            plan,
            saved,
            current,
            DateTime::from_timestamp(30, 0).unwrap(),
            DateTime::from_timestamp(31, 0).unwrap(),
            |_| panic!("Kill verification uses process observations"),
            Some(predictions),
        )
        .unwrap()
    }

    #[cfg(target_os = "linux")]
    fn supervisor_restart_action() -> PlanAction {
        let mut action = make_action(123, Action::Restart);
        // SAFETY: geteuid only reads the test process's credentials.
        let uid = unsafe { libc::geteuid() };
        action.target.uid = uid;
        action.routing = ActionRouting::Supervisor;
        action.supervisor_restart = Some(crate::action::SystemdUserServiceBinding {
            target: action.target.clone(),
            unit: "worker-proof.service".into(),
            control_group: format!(
                "/user.slice/user-{uid}.slice/user@{uid}.service/worker-proof.service"
            ),
            invocation_id: "1234567890abcdef1234567890abcdef".into(),
        });
        action
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn supervisor_restart_needs_recorded_scope_and_fresh_replacement_proof() {
        let action = supervisor_restart_action();
        let saved = execution(&action);
        let plan = make_plan(vec![action.clone()]);
        let absent = report(&plan, std::slice::from_ref(&saved), &[]);
        assert_eq!(
            absent.action_outcomes[0].outcome,
            VerifyOutcome::Unsupported
        );
        assert_eq!(absent.action_outcomes[0].verified, Some(false));
        for (observation, expected) in [
            (
                ActionPostcondition::Satisfied {
                    detail: "new invocation and live replacement".into(),
                },
                VerifyOutcome::ConfirmedEffect,
            ),
            (
                ActionPostcondition::NotSatisfied {
                    detail: "original invocation is unchanged".into(),
                },
                VerifyOutcome::EffectNotObserved,
            ),
            (
                ActionPostcondition::Unavailable {
                    reason: "manager bus is unavailable".into(),
                },
                VerifyOutcome::Unsupported,
            ),
            (
                ActionPostcondition::IdentityChanged,
                VerifyOutcome::Unsupported,
            ),
        ] {
            let mut calls = 0;
            let report = verify_plan_with_postconditions(
                &plan,
                std::slice::from_ref(&saved),
                &[],
                DateTime::from_timestamp(30, 0).unwrap(),
                DateTime::from_timestamp(31, 0).unwrap(),
                |_| {
                    calls += 1;
                    observation.clone()
                },
                None,
            )
            .unwrap();
            assert_eq!(
                calls, 1,
                "missing old PID must not skip service observation"
            );
            assert_eq!(report.action_outcomes[0].outcome, expected);
            assert!(report.action_outcomes[0].expected_resources_freed.is_none());
            assert!(report.resource_summary.is_none());
        }
        for case in 0..2 {
            let mut changed = saved.clone();
            if case == 0 {
                changed.supervisor_restart = None;
            } else {
                changed.supervisor_restart.as_mut().unwrap().invocation_id =
                    "abcdef0123456789abcdef0123456789".into();
            }
            assert!(verify_plan(
                &plan,
                &[changed],
                &[],
                DateTime::from_timestamp(30, 0).unwrap(),
                DateTime::from_timestamp(31, 0).unwrap()
            )
            .is_err());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn failed_restart_and_zero_budget_cannot_claim_verified_recovery() {
        let mut action = supervisor_restart_action();
        let failed = failed_attempt(&action);
        let report = verify_plan_with_postconditions(
            &make_plan(vec![action.clone()]),
            &[failed],
            &[],
            DateTime::from_timestamp(30, 0).unwrap(),
            DateTime::from_timestamp(31, 0).unwrap(),
            |_| panic!("failed attempts are not recovery evidence"),
            None,
        )
        .unwrap();
        assert_eq!(report.action_outcomes[0].verified, Some(false));
        action.timeouts.verify_ms = 0;
        assert!(
            matches!(observe_live_postcondition(&action), ActionPostcondition::Unavailable { reason } if reason.contains("budget exhausted"))
        );
    }

    #[test]
    fn canonical_plan_parse_ignores_report_recommendations_but_requires_actions_contract() {
        let plan = make_plan(vec![make_action(123, Action::Kill)]);
        let mut value = serde_json::to_value(&plan).unwrap();
        value["candidates"] = serde_json::json!([{ "pid": 456, "recommended_action": "review" }]);
        let parsed = parse_agent_plan(&value.to_string()).unwrap();
        assert_eq!(parsed.actions[0].target.start_id.0, "boot:500:123");
        assert_eq!(parsed.actions.len(), 1);
        assert!(parse_agent_plan(r#"{"session_id":"s","candidates":[]}"#).is_err());
        for invalid in ["", "{not valid}"] {
            assert!(parse_agent_plan(invalid).is_err());
        }
        let mut duplicated = plan.clone();
        duplicated.actions.push(duplicated.actions[0].clone());
        assert!(parse_agent_plan(&serde_json::to_string(&duplicated).unwrap()).is_err());
    }

    #[test]
    fn outcomes_jsonl_is_strict_and_binds_the_executed_identity() {
        let action = make_action(123, Action::Kill);
        let saved = execution(&action);
        let json = format!("{}\n\n", serde_json::to_string(&saved).unwrap());
        let parsed = parse_action_outcomes(&json).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(
            parsed[0].target.as_ref().unwrap().start_id,
            action.target.start_id
        );
        assert!(parse_action_outcomes(&format!("{json}not-json")).is_err());
        let plan = make_plan(vec![action]);
        for field in [
            "pid",
            "uid",
            "start_id",
            "target",
            "time",
            "command",
            "parent",
            "clock_boot",
            "clock_before_target",
        ] {
            let mut invalid = saved.clone();
            match field {
                "pid" => invalid.pid = 999,
                "uid" => invalid.target.as_mut().unwrap().uid = 999,
                "start_id" => {
                    invalid.target.as_mut().unwrap().start_id = StartId("boot:501:123".to_string())
                }
                "target" => invalid.target = None,
                "time" => invalid.executed_at = None,
                "command" => invalid.command = Some("   ".to_string()),
                "parent" => invalid.parent_pid = None,
                "clock_boot" => {
                    invalid.execution_clock.as_mut().unwrap().boot_id = "another-boot".to_string()
                }
                "clock_before_target" => invalid.execution_clock.as_mut().unwrap().ticks = 499,
                _ => unreachable!(),
            }
            assert!(executed_plan_actions(&plan, &[invalid]).is_err(), "{field}");
        }
        if cfg!(target_os = "linux") {
            let mut invalid = saved;
            invalid.execution_clock = None;
            assert!(executed_plan_actions(&plan, &[invalid]).is_err());
        }
    }

    #[test]
    fn successful_outcomes_require_matching_action_kind_before_keep_or_completion() {
        for kind in [Action::Keep, Action::Pause, Action::Kill] {
            let action = make_action(123, kind);
            let plan = make_plan(vec![action.clone()]);
            let success = execution(&action);
            let matched = executed_plan_actions(&plan, std::slice::from_ref(&success)).unwrap();
            assert_eq!(matched.len(), usize::from(kind != Action::Keep));
            for recorded_kind in [None, Some(Action::Renice)] {
                let mut invalid = success.clone();
                invalid.action = recorded_kind;
                let error = executed_plan_actions(&plan, &[invalid]).unwrap_err();
                assert!(
                    error.to_string().contains("action kind"),
                    "{kind:?}: {error}"
                );
            }
            let mut wire = serde_json::to_value(&success).unwrap();
            wire.as_object_mut().unwrap().remove("action");
            let missing = parse_action_outcomes(&wire.to_string()).unwrap();
            assert!(missing[0].action.is_none());
            assert!(executed_plan_actions(&plan, &missing).is_err());

            // A record with no successful effect does not need or invent a kind.
            let failed = failed_attempt(&action);
            assert!(failed.action.is_none());
            assert!(executed_plan_actions(&plan, std::slice::from_ref(&failed))
                .unwrap()
                .is_empty());
            for status in ["skipped", "dry_run", "already_completed"] {
                let mut skipped = failed.clone();
                skipped.status = status.to_string();
                assert!(executed_plan_actions(&plan, &[skipped]).unwrap().is_empty());
            }
        }

        let pause = make_action(123, Action::Pause);
        let saved_pause = execution(&pause);
        let mut changed = pause;
        changed.action = Action::Kill;
        let error = executed_plan_actions(&make_plan(vec![changed]), &[saved_pause]).unwrap_err();
        assert!(error.to_string().contains("action kind"));
    }

    #[test]
    fn review_unexecuted_blocked_and_dry_run_choices_are_not_verified() {
        let mut review_only = serde_json::to_value(make_plan(vec![])).unwrap();
        review_only["candidates"] = serde_json::json!([{
            "pid": 789, "uid": 1000, "command": "node app --port 3000",
            "recommended_action": "review"
        }]);
        let reviewed = parse_agent_plan(&review_only.to_string()).unwrap();
        let current = vec![make_proc(
            789,
            1000,
            "node app --port 3000",
            5,
            ProcessState::Running,
        )];
        let verification = report(&reviewed, &[], &current);
        assert!(verification.action_outcomes.is_empty());
        assert_eq!(verification.verification.overall_status, "success");
        assert_eq!(verification.follow_up_needed, Some(false));

        let plan = make_plan(vec![
            make_action(123, Action::Kill),
            make_action(456, Action::Kill),
        ]);
        let mut not_executed = execution(&plan.actions[0]);
        for status in [
            "dry_run",
            "shadow",
            "skipped",
            "precheck_blocked",
            "blocked_by_plan",
            "blocked_by_constraints",
            "blocked_by_policy",
            "already_completed",
        ] {
            not_executed.status = status.to_string();
            let verified = report(&plan, std::slice::from_ref(&not_executed), &[]);
            assert!(verified.action_outcomes.is_empty());
            assert_eq!(verified.verification.overall_status, "success");
            assert_eq!(verified.follow_up_needed, Some(false));
        }
        let success = execution(&plan.actions[0]);
        not_executed.status = "already_completed".to_string();
        let verified = report(&plan, &[success, not_executed], &[]);
        assert_eq!(verified.action_outcomes.len(), 1);
        assert_eq!(verified.action_outcomes[0].target.pid, 123);
        assert_eq!(verified.action_outcomes[0].target.start_id, "boot:500:123");
        let mut unknown = execution(&plan.actions[0]);
        unknown.action_id = "not-in-plan".to_string();
        assert!(executed_plan_actions(&plan, &[unknown]).is_err());
        let mut blocked = plan.clone();
        blocked.actions[0].blocked = true;
        let injected = execution(&blocked.actions[0]);
        assert!(executed_plan_actions(&blocked, std::slice::from_ref(&injected)).is_err());
        let replacement = make_proc(999, 1000, "node app --port 3000", 20, ProcessState::Running);
        assert!(detect_respawn(&blocked.actions[0], &injected, &[replacement]).is_none());
    }

    #[test]
    fn failed_attempts_remain_visible_without_claiming_effects_or_resource_relief() {
        let plan = make_plan(vec![memory_cap_action(), make_action(456, Action::Kill)]);
        for status in [
            "failed",
            "timeout",
            "permission_denied",
            "process_not_found",
            "identity_mismatch",
            "identity_check_failed",
            "unsupported_platform",
        ] {
            let saved: Vec<_> = plan
                .actions
                .iter()
                .enumerate()
                .map(|(index, action)| {
                    let mut failed = if index == 0 {
                        failed_attempt(action)
                    } else {
                        execution(action)
                    };
                    failed.status = status.to_string();
                    failed
                })
                .collect();
            let replacement =
                make_proc(999, 1000, "node app --port 3000", 20, ProcessState::Running);
            let verified = report(&plan, &saved, &[replacement]);
            assert_eq!(verified.action_outcomes.len(), 2, "{status}");
            assert_eq!(verified.verification.overall_status, "failure", "{status}");
            assert_eq!(verified.follow_up_needed, Some(true), "{status}");
            assert!(executed_plan_actions(&plan, &saved).unwrap().is_empty());
            for ((action, saved_attempt), outcome) in plan
                .actions
                .iter()
                .zip(&saved)
                .zip(&verified.action_outcomes)
            {
                assert_eq!(outcome.action_id, action.action_id);
                assert_eq!(outcome.target.pid, action.target.pid.0);
                assert_eq!(outcome.target.uid, action.target.uid);
                assert_eq!(outcome.target.start_id, action.target.start_id.0);
                assert_eq!(outcome.action, action.action.as_str());
                assert_eq!(outcome.outcome, VerifyOutcome::Unsupported);
                assert_eq!(outcome.actual.as_deref(), Some("failed_attempt"));
                assert_eq!(outcome.verified, Some(false));
                assert!(outcome.respawn_detected.is_none());
                assert!(outcome.expected_resources_freed.is_none());
                assert!(outcome.time_to_death_ms.is_none());
                assert_eq!(outcome.target.cmd_full, saved_attempt.command);
                assert!(outcome.note.as_ref().unwrap().contains("not established"));
                assert!(outcome.note.as_ref().unwrap().contains(status));
            }
            assert!(verified.resource_summary.is_none());
            let json = serde_json::to_value(&verified).unwrap();
            assert_eq!(json["action_outcomes"][0]["action"], "cap_memory");
            assert_eq!(json["action_outcomes"][0]["outcome"], "unsupported");
            assert_eq!(json["action_outcomes"][0]["actual"], "failed_attempt");
            assert!(json["action_outcomes"][0].get("respawn_detected").is_none());
        }
    }

    #[test]
    fn mixed_failed_and_successful_actions_report_partial_success() {
        let plan = make_plan(vec![
            make_action(123, Action::Kill),
            make_action(456, Action::Kill),
            make_action(789, Action::Kill),
        ]);
        let saved = vec![
            failed_attempt(&plan.actions[1]),
            execution(&plan.actions[0]),
        ];
        let predictions = private_predictions(
            &plan,
            &[
                (0, 100 * 1024 * 1024),
                (1, 200 * 1024 * 1024),
                (2, 300 * 1024 * 1024),
            ],
        );
        let verified = forecast_report(&plan, &saved, &[], &predictions);
        assert_eq!(verified.action_outcomes.len(), 2);
        assert_eq!(verified.verification.overall_status, "partial_success");
        assert_eq!(verified.follow_up_needed, Some(true));
        let successful = &verified.action_outcomes[0];
        assert_eq!(successful.target.pid, 123);
        assert_eq!(successful.outcome, VerifyOutcome::ConfirmedDead);
        assert_eq!(successful.verified, Some(true));
        let failed = &verified.action_outcomes[1];
        assert_eq!(failed.target.pid, 456);
        assert_eq!(failed.actual.as_deref(), Some("failed_attempt"));
        assert_eq!(failed.outcome, VerifyOutcome::Unsupported);
        assert_eq!(failed.verified, Some(false));
        assert!(failed.expected_resources_freed.is_none());
        assert!(failed.respawn_detected.is_none());
        let summary = verified.resource_summary.unwrap();
        assert_eq!(summary.expected_mb, 100.0);
        assert_eq!(summary.expected_freed_mb, 100.0);
    }

    #[test]
    fn append_only_retries_resolve_only_the_same_action_and_neutral_resume_preserves_them() {
        let action = make_action(123, Action::Kill);
        let failure = failed_attempt(&action);
        let success = execution(&action);
        let mut identity_error = failure.clone();
        identity_error.status = "identity_check_failed".to_string();
        let mut resumed = failure.clone();
        resumed.status = "already_completed".to_string();
        let mut skipped = failure.clone();
        skipped.status = "skipped".to_string();
        let mut dry_run = failure.clone();
        dry_run.status = "dry_run".to_string();
        let plan = make_plan(vec![action]);
        for (case, records, expected_verified) in [
            (
                "failed_then_resume",
                vec![
                    failure.clone(),
                    resumed.clone(),
                    skipped.clone(),
                    dry_run.clone(),
                ],
                false,
            ),
            (
                "failed_then_valid_success",
                vec![failure.clone(), success.clone(), resumed.clone()],
                true,
            ),
            (
                "success_then_failed_retry",
                vec![success.clone(), failure.clone(), resumed.clone()],
                false,
            ),
            (
                "success_then_identity_check_error",
                vec![success.clone(), identity_error, resumed.clone()],
                false,
            ),
            (
                "repeated_failures_then_success",
                vec![failure.clone(), failure.clone(), success.clone(), skipped],
                true,
            ),
        ] {
            let verified = report(&plan, &records, &[]);
            assert_eq!(verified.action_outcomes.len(), 1, "{case}");
            let outcome = &verified.action_outcomes[0];
            assert_eq!(outcome.target.pid, 123, "{case}");
            assert_eq!(outcome.verified, Some(expected_verified), "{case}");
            assert_eq!(
                verified.verification.overall_status,
                if expected_verified {
                    "success"
                } else {
                    "failure"
                },
                "{case}"
            );
            assert_eq!(
                verified.follow_up_needed,
                Some(!expected_verified),
                "{case}"
            );
            assert_eq!(
                executed_plan_actions(&plan, &records).unwrap().len(),
                usize::from(expected_verified),
                "{case}"
            );
            if expected_verified {
                assert_eq!(outcome.outcome, VerifyOutcome::ConfirmedDead, "{case}");
                assert_eq!(outcome.actual.as_deref(), Some("not_found"), "{case}");
            } else {
                assert_eq!(outcome.outcome, VerifyOutcome::Unsupported, "{case}");
                assert_eq!(outcome.actual.as_deref(), Some("failed_attempt"), "{case}");
                assert!(outcome.expected_resources_freed.is_none(), "{case}");
                assert!(outcome.respawn_detected.is_none(), "{case}");
                assert!(verified.resource_summary.is_none());
            }
        }
    }

    #[test]
    fn failed_attempts_require_the_canonical_action_and_target() {
        let action = make_action(123, Action::Kill);
        let failed = failed_attempt(&action);
        let plan = make_plan(vec![action]);
        for field in [
            "unknown_action",
            "unknown_status",
            "pid",
            "optional_identity",
        ] {
            let mut invalid = failed.clone();
            match field {
                "unknown_action" => invalid.action_id = "not-in-plan".to_string(),
                "unknown_status" => invalid.status = "unrecognized_failure".to_string(),
                "pid" => invalid.pid = 999,
                "optional_identity" => {
                    let mut identity = plan.actions[0].target.clone();
                    identity.uid = 999;
                    invalid.target = Some(identity);
                }
                _ => unreachable!(),
            }
            assert!(
                executed_plan_actions(&plan, std::slice::from_ref(&invalid)).is_err(),
                "{field}"
            );
            assert!(
                executed_plan_actions(&plan, &[invalid.clone(), execution(&plan.actions[0])])
                    .is_err(),
                "a later success cannot hide {field}"
            );
            assert!(
                verify_plan(
                    &plan,
                    &[invalid],
                    &[],
                    DateTime::from_timestamp(30, 0).unwrap(),
                    DateTime::from_timestamp(31, 0).unwrap(),
                )
                .is_err(),
                "{field}"
            );
        }
    }

    #[test]
    fn respawn_match_reports_replacement_and_verified_spawner() {
        let action = make_action(123, Action::Kill);
        let mut saved = execution(&action);
        let parent = make_proc(10, 1000, "sh respawner.sh", 1, ProcessState::Sleeping);
        saved.parent_identity = Some(ProcessIdentity::new(
            10,
            parent.start_id.clone(),
            parent.uid,
        ));
        let replacement = make_proc(
            456,
            1000,
            " node   app --port 3000 ",
            20,
            ProcessState::Running,
        );
        let current = vec![replacement, parent];
        let matched = detect_respawn(&action, &saved, &current).unwrap();
        assert_eq!(matched.pid, 456);
        assert_eq!(matched.parent_pid, 10);
        assert_eq!(matched.parent_cmd.as_deref(), Some("sh respawner.sh"));
        assert_eq!(matched.parent_start_id.as_deref(), Some("boot:100:10"));
        let verified = report(&make_plan(vec![action]), &[saved], &current);
        assert_eq!(
            verified.action_outcomes[0].outcome,
            VerifyOutcome::Respawned
        );
        assert_eq!(verified.action_outcomes[0].verified, Some(false));
        assert!(verified.recommendations.unwrap()[0].contains("spawner PID 10"));
    }

    #[test]
    fn respawn_rejects_near_identical_wrong_owner_parent_command_and_preexisting_process() {
        let action = make_action(123, Action::Kill);
        let saved = execution(&action);
        let positive = make_proc(456, 1000, "node app --port 3000", 20, ProcessState::Running);
        assert!(detect_respawn(&action, &saved, std::slice::from_ref(&positive)).is_some());
        for recorded_kind in [None, Some(Action::Pause)] {
            let mut wrong_kind = saved.clone();
            wrong_kind.action = recorded_kind;
            assert!(
                detect_respawn(&action, &wrong_kind, std::slice::from_ref(&positive)).is_none()
            );
        }
        for field in [
            "uid",
            "parent",
            "substring",
            "preexisting",
            "same_tick",
            "zombie",
            "boot",
        ] {
            let mut negative = positive.clone();
            match field {
                "uid" => negative.uid = 1001,
                "parent" => negative.ppid = ProcessId(11),
                "substring" => negative.cmd = "node app --port 30000".to_string(),
                "preexisting" => negative.start_id = StartId("boot:900:456".to_string()),
                "same_tick" => negative.start_id = StartId("boot:1000:456".to_string()),
                "zombie" => negative.state = ProcessState::Zombie,
                "boot" => negative.start_id = StartId("different-boot:2000:456".to_string()),
                _ => unreachable!(),
            }
            assert!(
                detect_respawn(&action, &saved, &[negative]).is_none(),
                "{field}"
            );
        }
        let mut absent_time = saved.clone();
        absent_time.executed_at = None;
        assert!(detect_respawn(&action, &absent_time, &[positive]).is_none());
    }

    #[test]
    fn boot_ticks_detect_later_birth_within_same_wall_second() {
        let action = make_action(123, Action::Kill);
        let mut saved = execution(&action);
        saved.execution_clock.as_mut().unwrap().ticks = 1050;
        saved.executed_at = Some(DateTime::from_timestamp(10, 500_000_000).unwrap());
        let mut replacement =
            make_proc(456, 1000, "node app --port 3000", 10, ProcessState::Running);
        replacement.start_id = StartId("boot:1051:456".to_string());
        assert!(detect_respawn(&action, &saved, std::slice::from_ref(&replacement)).is_some());
        replacement.start_id = StartId("boot:1049:456".to_string());
        assert!(detect_respawn(&action, &saved, &[replacement]).is_none());
        saved.execution_clock = None;
        let mut later_second =
            make_proc(456, 1000, "node app --port 3000", 11, ProcessState::Running);
        assert!(detect_respawn(&action, &saved, std::slice::from_ref(&later_second)).is_some());
        later_second.start_time_unix = 9;
        assert!(detect_respawn(&action, &saved, &[later_second]).is_none());
    }

    #[test]
    fn same_tick_matching_birth_is_unknown_while_later_and_unrelated_births_keep_their_oracles() {
        let action = make_action(123, Action::Kill);
        let mut saved = execution(&action);
        let parent = make_proc(10, 1000, "sh respawner.sh", 1, ProcessState::Sleeping);
        saved.parent_identity = Some(ProcessIdentity::new(
            10,
            parent.start_id.clone(),
            parent.uid,
        ));
        let plan = make_plan(vec![action]);
        for (variant, expected_outcome, expected_actual, verified) in [
            (
                "same_tick",
                VerifyOutcome::Unsupported,
                "ambiguous_respawn",
                false,
            ),
            ("later_tick", VerifyOutcome::Respawned, "respawned", false),
            (
                "older_tick",
                VerifyOutcome::ConfirmedDead,
                "not_found",
                true,
            ),
            (
                "different_uid",
                VerifyOutcome::ConfirmedDead,
                "not_found",
                true,
            ),
            (
                "different_parent",
                VerifyOutcome::ConfirmedDead,
                "not_found",
                true,
            ),
            ("substring", VerifyOutcome::ConfirmedDead, "not_found", true),
        ] {
            let mut candidate =
                make_proc(456, 1000, "node app --port 3000", 10, ProcessState::Running);
            match variant {
                "same_tick" => {}
                "later_tick" => candidate.start_id = StartId("boot:1001:456".to_string()),
                "older_tick" => {
                    candidate.start_id = StartId("boot:999:456".to_string());
                    candidate.start_time_unix = 9;
                }
                "different_uid" => candidate.uid = 1001,
                "different_parent" => candidate.ppid = ProcessId(11),
                "substring" => candidate.cmd = "node app --port 30000".to_string(),
                _ => unreachable!(),
            }
            let current = vec![candidate, parent.clone()];
            let strict = detect_respawn(&plan.actions[0], &saved, &current);
            assert_eq!(strict.is_some(), variant == "later_tick", "{variant}");
            let verification = report(&plan, std::slice::from_ref(&saved), &current);
            let outcome = &verification.action_outcomes[0];
            assert_eq!(outcome.outcome, expected_outcome, "{variant}");
            assert_eq!(
                outcome.actual.as_deref(),
                Some(expected_actual),
                "{variant}"
            );
            assert_eq!(outcome.verified, Some(verified), "{variant}");
            assert_eq!(verification.follow_up_needed, Some(!verified), "{variant}");
            if variant == "same_tick" {
                assert!(outcome.respawn_detected.is_none());
                assert!(outcome.note.as_ref().unwrap().contains("cannot be ordered"));
                assert_eq!(verification.verification.overall_status, "failure");
                assert!(verification.resource_summary.is_none());
            }
        }
    }

    #[test]
    fn same_second_birth_is_ambiguous_without_boot_ticks_and_preserves_parent_gates() {
        let action = make_action(123, Action::Kill);
        let mut saved = execution(&action);
        saved.execution_clock = None;
        let parent = make_proc(10, 1000, "sh respawner.sh", 1, ProcessState::Sleeping);
        saved.parent_identity = Some(ProcessIdentity::new(
            10,
            parent.start_id.clone(),
            parent.uid,
        ));
        let candidate = make_proc(456, 1000, "node app --port 3000", 10, ProcessState::Running);
        let current = vec![candidate.clone(), parent.clone()];
        assert!(detect_respawn(&action, &saved, &current).is_none());
        assert!(find_respawn_with_birth_order(
            &action,
            &saved,
            &current,
            std::cmp::Ordering::Equal
        )
        .is_some());
        let mut reused_parent = parent;
        reused_parent.start_id = StartId("boot:200:10".to_string());
        assert!(find_respawn_with_birth_order(
            &action,
            &saved,
            &[candidate.clone(), reused_parent],
            std::cmp::Ordering::Equal
        )
        .is_none());
        if cfg!(target_os = "linux") {
            assert!(verify_plan(
                &make_plan(vec![action]),
                &[saved],
                &current,
                DateTime::from_timestamp(30, 0).unwrap(),
                DateTime::from_timestamp(31, 0).unwrap()
            )
            .is_err());
        } else {
            let verified = report(&make_plan(vec![action]), &[saved], &current);
            assert_eq!(
                verified.action_outcomes[0].actual.as_deref(),
                Some("ambiguous_respawn")
            );
            assert_eq!(verified.action_outcomes[0].verified, Some(false));
        }
    }

    #[test]
    fn respawn_rejects_reused_or_unavailable_parent_identity() {
        let action = make_action(123, Action::Kill);
        let mut saved = execution(&action);
        let parent = make_proc(10, 1000, "sh respawner.sh", 1, ProcessState::Sleeping);
        saved.parent_identity = Some(ProcessIdentity::new(10, parent.start_id.clone(), 1000));
        let child = make_proc(456, 1000, "node app --port 3000", 20, ProcessState::Running);
        assert!(detect_respawn(&action, &saved, std::slice::from_ref(&child)).is_none());
        let mut reused = parent;
        reused.start_id = StartId("boot:200:10".to_string());
        assert!(detect_respawn(&action, &saved, &[child, reused]).is_none());
    }

    #[test]
    fn executed_kill_verifies_absence_zombie_and_identity_reuse() {
        let action = make_action(123, Action::Kill);
        let saved = execution(&action);
        let plan = make_plan(vec![action]);
        let dead = report(&plan, std::slice::from_ref(&saved), &[]);
        assert_eq!(
            dead.action_outcomes[0].outcome,
            VerifyOutcome::ConfirmedDead
        );
        assert_eq!(dead.action_outcomes[0].verified, Some(true));
        assert!(dead.action_outcomes[0].respawn_detected.is_none());
        for (state, start_id, uid, expected) in [
            (
                ProcessState::Zombie,
                "boot:500:123",
                1000,
                VerifyOutcome::ConfirmedDead,
            ),
            (
                ProcessState::Running,
                "boot:500:123",
                1000,
                VerifyOutcome::StillRunning,
            ),
            (
                ProcessState::Running,
                "other:500:123",
                1000,
                VerifyOutcome::PidReused,
            ),
            (
                ProcessState::Running,
                "boot:500:123",
                1001,
                VerifyOutcome::PidReused,
            ),
        ] {
            let mut process = make_proc(123, uid, "node app --port 3000", 5, state);
            process.start_id = StartId(start_id.to_string());
            let verified = report(&plan, std::slice::from_ref(&saved), &[process]);
            assert_eq!(verified.action_outcomes[0].outcome, expected);
        }
    }

    #[test]
    fn same_pid_birth_order_distinguishes_reuse_ambiguity_and_respawn() {
        let action = make_action(123, Action::Kill);
        let saved = execution(&action);
        let plan = make_plan(vec![action]);
        for (ticks, expected, actual) in [
            (999, VerifyOutcome::PidReused, "pid_reused"),
            (1000, VerifyOutcome::Unsupported, "ambiguous_respawn"),
            (1001, VerifyOutcome::Respawned, "respawned"),
        ] {
            let mut process = make_proc(
                123,
                1000,
                "node app --port 3000",
                ticks / 100,
                ProcessState::Running,
            );
            process.start_id = StartId(format!("boot:{ticks}:123"));
            let verified = report(&plan, std::slice::from_ref(&saved), &[process]);
            let outcome = &verified.action_outcomes[0];
            assert_eq!(outcome.outcome, expected);
            assert_eq!(outcome.actual.as_deref(), Some(actual));
            assert_eq!(outcome.verified, Some(false));
            assert_eq!(
                outcome.respawn_detected.is_some(),
                expected == VerifyOutcome::Respawned
            );
            assert!(verified.resource_summary.is_none());
        }
    }

    #[test]
    fn executed_pause_verifies_stopped_but_absence_and_unsupported_effects_are_not_success() {
        for (action_kind, state, present, expected) in [
            (
                Action::Pause,
                ProcessState::Stopped,
                true,
                VerifyOutcome::ConfirmedStopped,
            ),
            (
                Action::Pause,
                ProcessState::Running,
                true,
                VerifyOutcome::StillRunning,
            ),
            (
                Action::Pause,
                ProcessState::Stopped,
                false,
                VerifyOutcome::Unsupported,
            ),
            (
                Action::Restart,
                ProcessState::Running,
                false,
                VerifyOutcome::Unsupported,
            ),
            (
                Action::Renice,
                ProcessState::Running,
                true,
                VerifyOutcome::Unsupported,
            ),
        ] {
            let action = make_action(123, action_kind);
            let saved = execution(&action);
            let mut process = make_proc(123, 1000, "node app --port 3000", 5, state);
            process.start_id = action.target.start_id.clone();
            let current = if present { vec![process] } else { vec![] };
            let verified = report(&make_plan(vec![action]), &[saved], &current);
            assert_eq!(verified.action_outcomes[0].outcome, expected);
            assert_eq!(
                verified.action_outcomes[0].verified,
                Some(expected == VerifyOutcome::ConfirmedStopped)
            );
            assert!(verified.resource_summary.is_none());
        }
    }

    #[test]
    fn renice_requires_fresh_postconditions_and_retains_unknown_or_changed_evidence() {
        let action = make_action(123, Action::Renice);
        let saved = execution(&action);
        let current = make_proc(123, 1000, "worker", 5, ProcessState::Sleeping);
        let plan = make_plan(vec![action]);
        assert_eq!(
            report(
                &plan,
                std::slice::from_ref(&saved),
                std::slice::from_ref(&current)
            )
            .action_outcomes[0]
                .outcome,
            VerifyOutcome::Unsupported,
            "a saved success and live process do not prove priority"
        );
        for (observation, expected, actual, success) in [
            (
                ActionPostcondition::Satisfied {
                    detail: "every current thread is at nice 10".into(),
                },
                VerifyOutcome::ConfirmedEffect,
                "priority_verified",
                true,
            ),
            (
                ActionPostcondition::NotSatisfied {
                    detail: "worker thread remains at nice 0".into(),
                },
                VerifyOutcome::EffectNotObserved,
                "priority_not_adjusted",
                false,
            ),
            (
                ActionPostcondition::Unavailable {
                    reason: "thread census is unreadable".into(),
                },
                VerifyOutcome::Unsupported,
                "observation_unavailable",
                false,
            ),
            (
                ActionPostcondition::IdentityChanged,
                VerifyOutcome::PidReused,
                "identity_changed",
                false,
            ),
        ] {
            let mut calls = 0;
            let verified = verify_plan_with_postconditions(
                &plan,
                std::slice::from_ref(&saved),
                std::slice::from_ref(&current),
                DateTime::from_timestamp(30, 0).unwrap(),
                DateTime::from_timestamp(31, 0).unwrap(),
                |observed_action| {
                    calls += 1;
                    assert_eq!(observed_action.target, plan.actions[0].target);
                    observation.clone()
                },
                None,
            )
            .unwrap();
            assert_eq!(calls, 1);
            let outcome = &verified.action_outcomes[0];
            assert_eq!(outcome.outcome, expected);
            assert_eq!(outcome.actual.as_deref(), Some(actual));
            assert_eq!(outcome.verified, Some(success));
            assert!(outcome.note.is_some());
            assert!(outcome.expected_resources_freed.is_none());
            assert_eq!(verified.follow_up_needed, Some(!success));
            assert_eq!(
                verified.verification.overall_status,
                if success { "success" } else { "failure" }
            );
            assert!(verified.resource_summary.is_none());
        }
    }

    fn restored_observation(action: &PlanAction) -> RestorationObservation {
        RestorationObservation {
            attempt_id: "00000000-0000-4000-8000-000000000001".into(),
            restore_id: "00000000-0000-4000-8000-000000000002".into(),
            action_id: action.action_id.clone(),
            original_value: match action.action {
                Action::Pause => RestorationValue::JobControl { stopped: false },
                Action::Throttle => RestorationValue::CpuMax {
                    quota_us: -1,
                    period_us: 100_000,
                },
                Action::CapMemory => RestorationValue::MemoryHigh { limit_bytes: None },
                Action::Unfreeze => RestorationValue::Freeze { requested: true },
                Action::Quarantine => RestorationValue::Cpuset {
                    cpus: String::new(),
                },
                Action::Renice => RestorationValue::ThreadPriorities {
                    threads: vec![crate::action::renice::ReniceThreadReversal {
                        tid: action.target.pid.0,
                        start_ticks: 100,
                        uid: action.target.uid,
                        previous_nice: 0,
                        applied_nice: 10,
                    }],
                },
                _ => RestorationValue::Freeze { requested: false },
            },
            recorded_restored_at: "1970-01-01T00:00:20Z".into(),
            observed_at: "1970-01-01T00:00:30Z".into(),
        }
    }

    #[test]
    fn confirmed_restoration_preserves_action_history_and_earns_no_relief_credit() {
        for action_kind in [
            Action::Pause,
            Action::Renice,
            Action::Freeze,
            Action::Unfreeze,
            Action::Throttle,
            Action::CapMemory,
            Action::Quarantine,
        ] {
            let action = make_action(123, action_kind);
            let saved = execution(&action);
            let saved_before = serde_json::to_value(&saved).unwrap();
            let observation = restored_observation(&action);
            let current = make_proc(123, 1000, "worker", 5, ProcessState::Sleeping);
            let result = verify_plan_with_postconditions(
                &make_plan(vec![action]),
                std::slice::from_ref(&saved),
                &[current],
                DateTime::from_timestamp(30, 0).unwrap(),
                DateTime::from_timestamp(31, 0).unwrap(),
                |_| ActionPostcondition::Restored {
                    observation: observation.clone(),
                },
                None,
            )
            .unwrap();
            let outcome = &result.action_outcomes[0];
            assert_eq!(outcome.outcome, VerifyOutcome::ConfirmedRestored);
            assert_eq!(outcome.verified, Some(true));
            assert_eq!(outcome.action, action_kind.as_str());
            assert_eq!(
                outcome.expected.as_deref(),
                Some(match action_kind {
                    Action::Pause => "recorded_original_job_control_state",
                    Action::Renice => "recorded_original_thread_priorities",
                    _ => "recorded_original_controller_state",
                })
            );
            assert_eq!(outcome.actual.as_deref(), Some("restoration_verified"));
            assert_eq!(outcome.restoration.as_ref(), Some(&observation));
            assert!(outcome.expected_resources_freed.is_none());
            assert!(result.resource_summary.is_none());
            assert_eq!(result.verification.overall_status, "success");
            assert_eq!(result.follow_up_needed, Some(false));
            assert_eq!(serde_json::to_value(&saved).unwrap(), saved_before);
        }
    }

    #[test]
    fn unverified_restoration_retains_original_expectation_and_failure() {
        for reason in [
            "latest restore is pending",
            "latest restore failed",
            "original controller value changed",
            "scope identity changed",
            "another session owns this controller",
            "receipt is malformed",
        ] {
            let action = make_action(123, Action::Freeze);
            let saved = execution(&action);
            let result = verify_plan_with_postconditions(
                &make_plan(vec![action]),
                &[saved],
                &[make_proc(123, 1000, "worker", 5, ProcessState::Sleeping)],
                DateTime::from_timestamp(30, 0).unwrap(),
                DateTime::from_timestamp(31, 0).unwrap(),
                |_| ActionPostcondition::RestorationUnverified {
                    reason: reason.to_string(),
                },
                None,
            )
            .unwrap();
            let outcome = &result.action_outcomes[0];
            assert_eq!(outcome.outcome, VerifyOutcome::RestorationUnverified);
            assert_eq!(outcome.verified, Some(false));
            assert_eq!(
                outcome.expected.as_deref(),
                Some("cgroup_freeze_requested_and_completed")
            );
            assert_eq!(outcome.actual.as_deref(), Some("restoration_unverified"));
            assert_eq!(outcome.note.as_deref(), Some(reason));
            assert!(outcome.restoration.is_none());
            assert_eq!(result.verification.overall_status, "failure");
            assert_eq!(result.follow_up_needed, Some(true));
        }
    }

    #[test]
    fn pause_live_observation_overrides_stale_snapshot_state() {
        let action = make_action(123, Action::Pause);
        let saved = execution(&action);
        let current = make_proc(123, 1000, "worker", 5, ProcessState::Stopped);
        let plan = make_plan(vec![action]);
        for detail in [
            "current process is running",
            "a debugger owns the current tracing stop",
            "current process state is unreadable",
        ] {
            let verified = verify_plan_with_postconditions(
                &plan,
                std::slice::from_ref(&saved),
                std::slice::from_ref(&current),
                DateTime::from_timestamp(30, 0).unwrap(),
                DateTime::from_timestamp(31, 0).unwrap(),
                |_| ActionPostcondition::NotSatisfied {
                    detail: detail.to_string(),
                },
                None,
            )
            .unwrap();
            let outcome = &verified.action_outcomes[0];
            assert_eq!(outcome.outcome, VerifyOutcome::EffectNotObserved);
            assert_eq!(outcome.verified, Some(false));
            assert_eq!(outcome.note.as_deref(), Some(detail));
            assert_eq!(verified.verification.overall_status, "failure");
        }
    }

    #[test]
    fn pause_restoration_is_checked_even_when_the_current_snapshot_is_stopped() {
        let action = make_action(123, Action::Pause);
        let saved = execution(&action);
        let current = make_proc(123, 1000, "worker", 5, ProcessState::Stopped);
        let mut observation = restored_observation(&action);
        observation.original_value = RestorationValue::JobControl { stopped: true };
        let plan = make_plan(vec![action]);
        let verified = verify_plan_with_postconditions(
            &plan,
            std::slice::from_ref(&saved),
            std::slice::from_ref(&current),
            DateTime::from_timestamp(30, 0).unwrap(),
            DateTime::from_timestamp(31, 0).unwrap(),
            |_| ActionPostcondition::Restored {
                observation: observation.clone(),
            },
            None,
        )
        .unwrap();
        assert_eq!(
            verified.action_outcomes[0].outcome,
            VerifyOutcome::ConfirmedRestored
        );
        assert_eq!(verified.action_outcomes[0].restoration, Some(observation));

        let refused = verify_plan_with_postconditions(
            &plan,
            &[saved],
            &[current],
            DateTime::from_timestamp(30, 0).unwrap(),
            DateTime::from_timestamp(31, 0).unwrap(),
            |_| ActionPostcondition::RestorationUnverified {
                reason: "a later external stop does not belong to this pause".into(),
            },
            None,
        )
        .unwrap();
        assert_eq!(
            refused.action_outcomes[0].outcome,
            VerifyOutcome::RestorationUnverified
        );
        assert_eq!(refused.action_outcomes[0].verified, Some(false));
        assert_eq!(refused.verification.overall_status, "failure");
        assert!(refused.action_outcomes[0].restoration.is_none());
    }

    #[test]
    fn restoration_observations_cannot_cross_actions_or_controller_types() {
        for case in ["action_id", "control", "renice", "quarantine", "pause"] {
            let action_kind = match case {
                "renice" => Action::Renice,
                "quarantine" => Action::Quarantine,
                "pause" => Action::Pause,
                _ => Action::Freeze,
            };
            let action = make_action(123, action_kind);
            let saved = execution(&action);
            let mut observation = restored_observation(&action);
            match case {
                "action_id" => observation.action_id = "unrelated-action".into(),
                "control" => {
                    observation.original_value = RestorationValue::CpuMax {
                        quota_us: -1,
                        period_us: 100_000,
                    }
                }
                "renice" | "quarantine" | "pause" => {
                    observation.original_value = RestorationValue::Freeze { requested: false };
                }
                _ => {}
            }
            let result = verify_plan_with_postconditions(
                &make_plan(vec![action]),
                &[saved],
                &[make_proc(123, 1000, "worker", 5, ProcessState::Sleeping)],
                DateTime::from_timestamp(30, 0).unwrap(),
                DateTime::from_timestamp(31, 0).unwrap(),
                |_| ActionPostcondition::Restored {
                    observation: observation.clone(),
                },
                None,
            )
            .unwrap();
            assert_eq!(
                result.action_outcomes[0].outcome,
                VerifyOutcome::RestorationUnverified,
                "{case}"
            );
            assert_eq!(result.action_outcomes[0].verified, Some(false), "{case}");
            assert!(result.action_outcomes[0].restoration.is_none(), "{case}");
        }
    }

    #[test]
    fn newer_failed_execution_is_not_hidden_by_an_older_restoration() {
        let action = make_action(123, Action::Throttle);
        let saved = vec![execution(&action), failed_attempt(&action)];
        let result = verify_plan_with_postconditions(
            &make_plan(vec![action]),
            &saved,
            &[make_proc(123, 1000, "worker", 5, ProcessState::Sleeping)],
            DateTime::from_timestamp(30, 0).unwrap(),
            DateTime::from_timestamp(31, 0).unwrap(),
            |_| panic!("failed execution must not consult restoration history"),
            None,
        )
        .unwrap();
        assert_eq!(
            result.action_outcomes[0].actual.as_deref(),
            Some("failed_attempt")
        );
        assert_eq!(result.action_outcomes[0].verified, Some(false));
        assert!(result.action_outcomes[0].restoration.is_none());
        assert_eq!(result.verification.overall_status, "failure");
    }

    #[test]
    fn controller_effects_require_fresh_observations_of_the_executed_identity() {
        for action_kind in [
            Action::Freeze,
            Action::Unfreeze,
            Action::Throttle,
            Action::Quarantine,
        ] {
            let action = make_action(123, action_kind);
            let saved = execution(&action);
            let current = make_proc(123, 1000, "worker", 5, ProcessState::Sleeping);
            let plan = make_plan(vec![action]);
            let without_evidence = report(
                &plan,
                std::slice::from_ref(&saved),
                std::slice::from_ref(&current),
            );
            assert_eq!(without_evidence.action_outcomes[0].verified, Some(false));

            for (observation, expected) in [
                (
                    ActionPostcondition::Satisfied {
                        detail: "current kernel state matches".into(),
                    },
                    VerifyOutcome::ConfirmedEffect,
                ),
                (
                    ActionPostcondition::NotSatisfied {
                        detail: "current kernel state differs".into(),
                    },
                    VerifyOutcome::EffectNotObserved,
                ),
                (
                    ActionPostcondition::Unavailable {
                        reason: "controller unreadable".into(),
                    },
                    VerifyOutcome::Unsupported,
                ),
                (
                    ActionPostcondition::IdentityChanged,
                    VerifyOutcome::PidReused,
                ),
            ] {
                let result = verify_plan_with_postconditions(
                    &plan,
                    std::slice::from_ref(&saved),
                    std::slice::from_ref(&current),
                    DateTime::from_timestamp(30, 0).unwrap(),
                    DateTime::from_timestamp(31, 0).unwrap(),
                    |observed| {
                        assert_eq!(observed.target, plan.actions[0].target);
                        observation.clone()
                    },
                    None,
                )
                .unwrap();
                let outcome = &result.action_outcomes[0];
                assert_eq!(outcome.outcome, expected, "{action_kind:?}");
                assert_eq!(
                    outcome.verified,
                    Some(expected == VerifyOutcome::ConfirmedEffect)
                );
                assert!(outcome.expected_resources_freed.is_none());
                assert!(result.resource_summary.is_none());
            }

            for case in ["birth", "uid", "gone", "zombie", "failed", "dry_run"] {
                let mut current = vec![current.clone()];
                let mut saved = saved.clone();
                match case {
                    "birth" => current[0].start_id = StartId("boot:501:123".into()),
                    "uid" => current[0].uid += 1,
                    "gone" => current.clear(),
                    "zombie" => current[0].state = ProcessState::Zombie,
                    "failed" | "dry_run" => saved.status = case.into(),
                    _ => unreachable!(),
                }
                let result = verify_plan_with_postconditions(
                    &plan,
                    &[saved],
                    &current,
                    DateTime::from_timestamp(30, 0).unwrap(),
                    DateTime::from_timestamp(31, 0).unwrap(),
                    |_| panic!("controller observer called for {action_kind:?}, {case}"),
                    None,
                )
                .unwrap();
                assert!(result
                    .action_outcomes
                    .iter()
                    .all(|outcome| outcome.verified == Some(false)));
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn controller_file_observations_distinguish_requested_effective_and_unknown_states() {
        use std::fs;

        let fixture = tempfile::tempdir().unwrap();
        let leaf = fixture.path().join("worker");
        fs::create_dir(&leaf).unwrap();
        fs::write(leaf.join("cgroup.procs"), "123\n456\n").unwrap();
        let observe = |action| observe_cgroup_files(action, 123, "0::/worker\n", fixture.path());

        fs::write(leaf.join("cgroup.freeze"), "1\n").unwrap();
        fs::write(leaf.join("cgroup.events"), "populated 1\nfrozen 0\n").unwrap();
        assert!(matches!(
            observe(Action::Freeze).unwrap(),
            ActionPostcondition::NotSatisfied { .. }
        ));
        fs::write(leaf.join("cgroup.events"), "populated 1\nfrozen 1\n").unwrap();
        assert!(matches!(
            observe(Action::Freeze).unwrap(),
            ActionPostcondition::Satisfied { .. }
        ));
        fs::write(leaf.join("cgroup.freeze"), "0\n").unwrap();
        assert!(
            matches!(
                observe(Action::Unfreeze).unwrap(),
                ActionPostcondition::NotSatisfied { .. }
            ),
            "an ancestor can keep the cgroup effectively frozen after a local thaw request"
        );
        fs::write(leaf.join("cgroup.events"), "populated 1\nfrozen 0\n").unwrap();
        assert!(matches!(
            observe(Action::Unfreeze).unwrap(),
            ActionPostcondition::Satisfied { .. }
        ));
        fs::write(leaf.join("cgroup.events"), "populated 1\n").unwrap();
        assert!(observe(Action::Unfreeze).is_err());

        for limit in [
            "25000 100000",
            "10000 100000",
            "25000 200000",
            "50000 200000",
        ] {
            fs::write(leaf.join("cpu.max"), limit).unwrap();
            assert!(
                matches!(
                    observe(Action::Throttle).unwrap(),
                    ActionPostcondition::Satisfied { .. }
                ),
                "stricter or equivalent cap must remain valid: {limit}"
            );
        }
        for limit in ["max 100000", "100000 100000", "50000 100000"] {
            fs::write(leaf.join("cpu.max"), limit).unwrap();
            assert!(
                matches!(
                    observe(Action::Throttle).unwrap(),
                    ActionPostcondition::NotSatisfied { .. }
                ),
                "{limit}"
            );
        }
        for invalid in [
            "",
            "25000",
            "25000 0",
            "0 100000",
            "-1 100000",
            "25000 100000 extra",
            "n/a 100000",
        ] {
            assert!(throttle_postcondition(invalid).is_err(), "{invalid}");
        }

        fs::write(leaf.join("cpuset.cpus"), "7\n").unwrap();
        assert!(
            observe(Action::Quarantine).is_err(),
            "missing effective evidence is unknown"
        );
        fs::write(leaf.join("cpuset.cpus.effective"), "7\n").unwrap();
        assert!(matches!(
            observe(Action::Quarantine).unwrap(),
            ActionPostcondition::Satisfied { .. }
        ));
        for (requested, effective) in [
            ("", "7"),
            ("7", ""),
            ("7", "8"),
            ("7", "7-8"),
            ("7-8", "7-8"),
        ] {
            assert!(
                matches!(
                    quarantine_postcondition(requested, effective).unwrap(),
                    ActionPostcondition::NotSatisfied { .. }
                ),
                "{requested:?}, {effective:?}"
            );
        }
        assert!(matches!(
            quarantine_postcondition("7,7", "7").unwrap(),
            ActionPostcondition::Satisfied { .. }
        ));
        assert!(matches!(
            quarantine_postcondition("0-4294967295", "0-4294967295").unwrap(),
            ActionPostcondition::NotSatisfied { .. }
        ));
        for invalid in ["7,bad", "8-7", "7-8-9"] {
            assert!(quarantine_postcondition(invalid, "7").is_err(), "{invalid}");
            assert!(quarantine_postcondition("7", invalid).is_err(), "{invalid}");
        }
        for members in ["456\n", "", "123\nbad\n", "123\n0\n"] {
            fs::write(leaf.join("cgroup.procs"), members).unwrap();
            assert!(
                observe(Action::Quarantine).is_err(),
                "matching controller values in a wrong or unreadable group cannot verify the target: {members:?}"
            );
        }
        fs::write(leaf.join("cgroup.procs"), "123\n").unwrap();
        assert!(
            observe_controller_directory(123, &leaf, || {
                fs::write(leaf.join("cgroup.procs"), "456\n").unwrap();
                Ok(ActionPostcondition::Satisfied {
                    detail: "matching settings".into(),
                })
            })
            .is_err(),
            "migration during a controller read invalidates its result"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn hybrid_controller_observation_requires_real_fallback_evidence() {
        use std::fs;

        let fixture = tempfile::tempdir().unwrap();
        fs::create_dir_all(fixture.path().join("worker")).unwrap();
        let cpu = fixture.path().join("cpu/worker");
        let cpuset = fixture.path().join("cpuset/worker");
        fs::create_dir_all(&cpu).unwrap();
        fs::create_dir_all(&cpuset).unwrap();
        for directory in [&cpu, &cpuset, &fixture.path().join("worker")] {
            fs::write(directory.join("cgroup.procs"), "123\n").unwrap();
        }
        let membership = "0::/worker\n2:cpu,cpuacct:/worker\n3:cpuset:/worker\n";
        fs::write(cpu.join("cpu.cfs_quota_us"), "25000\n").unwrap();
        fs::write(cpu.join("cpu.cfs_period_us"), "100000\n").unwrap();
        assert!(matches!(
            observe_cgroup_files(Action::Throttle, 123, membership, fixture.path()).unwrap(),
            ActionPostcondition::Satisfied { .. }
        ));
        fs::write(cpu.join("cpu.cfs_quota_us"), "-1\n").unwrap();
        assert!(matches!(
            observe_cgroup_files(Action::Throttle, 123, membership, fixture.path()).unwrap(),
            ActionPostcondition::NotSatisfied { .. }
        ));
        fs::write(cpuset.join("cpuset.cpus"), "9\n").unwrap();
        fs::write(cpuset.join("cpuset.effective_cpus"), "9\n").unwrap();
        assert!(matches!(
            observe_cgroup_files(Action::Quarantine, 123, membership, fixture.path()).unwrap(),
            ActionPostcondition::Satisfied { .. }
        ));

        fs::write(fixture.path().join("worker/cpu.max"), "malformed").unwrap();
        assert!(
            observe_cgroup_files(Action::Throttle, 123, membership, fixture.path()).is_err(),
            "malformed v2 evidence must not be hidden by a valid v1 fallback"
        );
        for membership in [
            "",
            "0::/worker\n0::/other",
            "0::relative",
            "0::/../worker",
            "not:a:membership",
        ] {
            assert!(
                observe_cgroup_files(Action::Throttle, 123, membership, fixture.path()).is_err(),
                "{membership}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn v1_throttle_observation_rejects_mixed_generation_limits() {
        for (quota_after, period_after) in [
            ("200000", "600000"),
            ("100000", "600000"),
            ("200000", "100000"),
        ] {
            let mut reads = [
                ("cpu.cfs_period_us", "100000"),
                ("cpu.cfs_quota_us", "100000"),
                ("cpu.cfs_quota_us", quota_after),
                ("cpu.cfs_period_us", period_after),
            ]
            .into_iter();
            // Neither 100000/100000 nor a later 200000/600000 meets the 25%
            // ceiling, but combining the old quota with the new period would.
            let result = observe_v1_throttle(|filename| {
                let (expected, value) = reads.next().unwrap();
                assert_eq!(filename, expected);
                Ok(value.to_string())
            });
            assert!(result.is_err());
            assert!(reads.next().is_none());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn quarantine_observation_rejects_changing_controller_values() {
        for (configured_after, effective_after) in [("8", "8"), ("8", "7"), ("7", "8")] {
            let mut configured = ["7", configured_after].into_iter();
            let mut effective = ["7", effective_after].into_iter();
            assert!(observe_quarantine(
                || Ok(configured.next().unwrap().to_string()),
                || Ok(effective.next().unwrap().to_string()),
            )
            .is_err());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn controller_observation_discards_results_after_identity_or_membership_changes() {
        use crate::action::{ActionError, IdentityProvider, StaticIdentityProvider};
        use std::cell::Cell;

        struct ChangingIdentity(Cell<usize>);
        impl IdentityProvider for ChangingIdentity {
            fn revalidate(&self, _: &ProcessIdentity) -> Result<bool, ActionError> {
                let checks = self.0.get();
                self.0.set(checks + 1);
                Ok(checks == 0)
            }
        }
        let action = make_action(123, Action::Throttle);
        let observed = || ActionPostcondition::Satisfied {
            detail: "matching limit".into(),
        };
        assert!(matches!(
            observe_bound_cgroup(
                &action,
                &ChangingIdentity(Cell::new(0)),
                || Ok("0::/worker\n".into()),
                |_| observed(),
            ),
            ActionPostcondition::Unavailable { .. }
        ));

        let identity = StaticIdentityProvider::default().with_identity(action.target.clone());
        let mut reads = 0;
        let result = observe_bound_cgroup(
            &action,
            &identity,
            || {
                reads += 1;
                Ok(if reads == 1 {
                    "0::/worker\n"
                } else {
                    "0::/different\n"
                }
                .into())
            },
            |_| observed(),
        );
        assert!(matches!(result, ActionPostcondition::Unavailable { .. }));
        assert_eq!(reads, 2);

        assert_eq!(
            observe_bound_cgroup(
                &action,
                &identity,
                || Ok("0::/worker\n".into()),
                |_| observed()
            ),
            observed()
        );
        assert!(matches!(
            observe_bound_cgroup(
                &action,
                &identity,
                || Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
                |_| panic!("must not observe without membership")
            ),
            ActionPostcondition::Unavailable { .. }
        ));
    }

    #[test]
    fn postcondition_observer_never_runs_for_unexecuted_failed_or_unbound_subjects() {
        for case in [
            "none",
            "dry_run",
            "shadow",
            "skipped",
            "failed",
            "absent",
            "birth",
            "uid",
            "zombie",
            "dead",
            "unknown",
            "unsupported_restore",
        ] {
            let action = make_action(
                123,
                if case == "unsupported_restore" {
                    Action::Unquarantine
                } else {
                    Action::Renice
                },
            );
            let mut saved = vec![execution(&action)];
            let mut current = vec![make_proc(123, 1000, "worker", 5, ProcessState::Sleeping)];
            match case {
                "none" => saved.clear(),
                "dry_run" | "shadow" | "skipped" | "failed" => saved[0].status = case.into(),
                "absent" => current.clear(),
                "birth" => current[0].start_id = StartId("boot:501:123".into()),
                "uid" => current[0].uid += 1,
                "zombie" => current[0].state = ProcessState::Zombie,
                "dead" => current[0].state = ProcessState::Dead,
                "unknown" => current[0].state = ProcessState::Unknown,
                "unsupported_restore" => {}
                _ => unreachable!(),
            }
            let verified = verify_plan_with_postconditions(
                &make_plan(vec![action]),
                &saved,
                &current,
                DateTime::from_timestamp(30, 0).unwrap(),
                DateTime::from_timestamp(31, 0).unwrap(),
                |_| panic!("observer called for {case}"),
                None,
            )
            .unwrap();
            let unexecuted = matches!(case, "none" | "dry_run" | "shadow" | "skipped");
            assert_eq!(
                verified.action_outcomes.len(),
                if unexecuted { 0 } else { 1 },
                "{case}"
            );
            assert!(
                verified
                    .action_outcomes
                    .iter()
                    .all(|outcome| outcome.verified == Some(false)),
                "{case}"
            );
            if matches!(case, "birth" | "uid") {
                assert_eq!(
                    verified.action_outcomes[0].outcome,
                    VerifyOutcome::PidReused
                );
            }
        }
        let action = make_action(123, Action::Renice);
        let mut saved = execution(&action);
        saved.target.as_mut().unwrap().uid += 1;
        assert!(verify_plan_with_postconditions(
            &make_plan(vec![action]),
            &[saved],
            &[make_proc(123, 1000, "worker", 5, ProcessState::Sleeping)],
            DateTime::from_timestamp(30, 0).unwrap(),
            DateTime::from_timestamp(31, 0).unwrap(),
            |_| panic!("observer called for an invalid saved execution identity"),
            None,
        )
        .is_err());
    }

    #[test]
    fn resume_verification_requires_a_matching_live_nonstopped_state() {
        for state in [
            ProcessState::Running,
            ProcessState::Sleeping,
            ProcessState::DiskSleep,
            ProcessState::Idle,
            ProcessState::Stopped,
            ProcessState::Zombie,
            ProcessState::Dead,
            ProcessState::Unknown,
        ] {
            let action = make_action(123, Action::Resume);
            let saved = execution(&action);
            let process = make_proc(123, 1000, "worker", 5, state);
            let verified = report(&make_plan(vec![action]), &[saved], &[process]);
            let expected = match state {
                ProcessState::Running
                | ProcessState::Sleeping
                | ProcessState::DiskSleep
                | ProcessState::Idle => VerifyOutcome::ConfirmedEffect,
                ProcessState::Stopped => VerifyOutcome::EffectNotObserved,
                _ => VerifyOutcome::Unsupported,
            };
            assert_eq!(verified.action_outcomes[0].outcome, expected, "{state}");
            assert_eq!(
                verified.action_outcomes[0].verified,
                Some(expected == VerifyOutcome::ConfirmedEffect)
            );
            assert!(verified.action_outcomes[0]
                .expected_resources_freed
                .is_none());
        }
        let action = make_action(123, Action::Resume);
        let saved = execution(&action);
        let plan = make_plan(vec![action]);
        assert_eq!(
            report(&plan, std::slice::from_ref(&saved), &[]).action_outcomes[0].verified,
            Some(false)
        );
        for process in [
            make_proc(123, 1001, "replacement", 5, ProcessState::Running),
            make_proc(123, 1000, "replacement", 6, ProcessState::Running),
        ] {
            assert_eq!(
                report(&plan, std::slice::from_ref(&saved), &[process]).action_outcomes[0].outcome,
                VerifyOutcome::PidReused
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn renice_priority_evidence_covers_workers_not_only_the_leader() {
        use crate::action::renice::ReniceThreadReversal;
        let target = make_action(123, Action::Renice).target;
        let mut observed = crate::action::ReniceReversalMetadata {
            pid: 123,
            previous_nice: 10,
            applied_nice: 10,
            applied_at: String::new(),
            identity: Some(target.clone()),
            threads: vec![
                ReniceThreadReversal {
                    tid: 123,
                    start_ticks: 500,
                    uid: 1000,
                    previous_nice: 10,
                    applied_nice: 10,
                },
                ReniceThreadReversal {
                    tid: 124,
                    start_ticks: 501,
                    uid: 1000,
                    previous_nice: 0,
                    applied_nice: 10,
                },
            ],
        };
        assert!(matches!(
            renice_postcondition(&target, &observed),
            ActionPostcondition::NotSatisfied { .. }
        ));
        observed.threads[1].previous_nice = 19;
        assert!(matches!(
            renice_postcondition(&target, &observed),
            ActionPostcondition::Satisfied { .. }
        ));
        for case in [
            "identity",
            "missing_identity",
            "empty",
            "missing_leader",
            "duplicate",
            "uid",
            "invalid_nice",
        ] {
            let mut invalid = observed.clone();
            match case {
                "identity" => {
                    invalid.identity.as_mut().unwrap().start_id = StartId("boot:999:123".into())
                }
                "missing_identity" => invalid.identity = None,
                "empty" => invalid.threads.clear(),
                "missing_leader" => invalid.threads[0].tid = 125,
                "duplicate" => invalid.threads[1].tid = 123,
                "uid" => invalid.threads[1].uid += 1,
                "invalid_nice" => invalid.threads[1].previous_nice = 20,
                _ => unreachable!(),
            }
            assert!(
                matches!(
                    renice_postcondition(&target, &invalid),
                    ActionPostcondition::Unavailable { .. } | ActionPostcondition::IdentityChanged
                ),
                "{case}"
            );
        }
    }

    #[test]
    fn expected_resources_and_partial_status_are_truthfully_labeled() {
        let plan = make_plan(vec![
            make_action(123, Action::Kill),
            make_action(456, Action::Kill),
        ]);
        let saved: Vec<_> = plan.actions.iter().map(execution).collect();
        let mut current = make_proc(456, 1000, "node app --port 3000", 5, ProcessState::Running);
        current.start_id = plan.actions[1].target.start_id.clone();
        let predictions =
            private_predictions(&plan, &[(0, 100 * 1024 * 1024), (1, 100 * 1024 * 1024)]);
        let verified = forecast_report(&plan, &saved, &[current], &predictions);
        assert_eq!(verified.verification.overall_status, "partial_success");
        let summary = verified.resource_summary.as_ref().unwrap();
        assert_eq!(summary.expected_mb, 200.0);
        assert_eq!(summary.expected_freed_mb, 100.0);
        assert!(summary.shortfall_reason.is_some());
        assert_eq!(
            verified.action_outcomes[0]
                .expected_resources_freed
                .as_ref()
                .unwrap()
                .memory_mb,
            100.0
        );
        assert!(verified.action_outcomes[1]
            .expected_resources_freed
            .is_none());
        let json = serde_json::to_value(&verified).unwrap();
        assert!(json["resource_summary"].get("memory_freed_mb").is_none());
        assert!(json["action_outcomes"][0].get("resources_freed").is_none());
        assert_eq!(
            json["action_outcomes"][0]["target"]["start_id"],
            "boot:500:123"
        );
        assert_eq!(json["schema_version"], pt_common::SCHEMA_VERSION);
        assert_eq!(json["session_id"], "session-test");
    }

    #[test]
    fn saved_private_forecast_replaces_neither_rss_nor_a_missing_measurement_with_zero() {
        for bytes in [0, 1_024, 32 * 1024 * 1024 + 4_096] {
            let mut action = make_action(123, Action::Kill);
            action.rationale.memory_mb = Some(9_999.0);
            let saved = execution(&action);
            let plan = make_plan(vec![action]);
            let predictions = private_predictions(&plan, &[(0, bytes)]);
            let mut current = make_proc(123, 1000, "worker", 5, ProcessState::Zombie);
            current.rss_bytes = u64::MAX;
            let verified = forecast_report(
                &plan,
                std::slice::from_ref(&saved),
                &[current],
                &predictions,
            );
            let expected = bytes as f64 / (1024.0 * 1024.0);
            let summary = verified.resource_summary.unwrap();
            assert_eq!(summary.expected_mb, expected);
            assert_eq!(summary.expected_freed_mb, expected);
            assert_eq!(
                verified.action_outcomes[0]
                    .expected_resources_freed
                    .as_ref()
                    .unwrap()
                    .memory_mb,
                expected
            );
            let unknown = report(&plan, &[saved], &[]);
            assert!(unknown.resource_summary.is_none());
            assert!(unknown.action_outcomes[0]
                .expected_resources_freed
                .is_none());
        }
    }

    #[test]
    fn partial_forecasts_keep_known_action_values_without_inventing_a_total() {
        let plan = make_plan(vec![
            make_action(123, Action::Kill),
            make_action(456, Action::Kill),
        ]);
        let saved: Vec<_> = plan.actions.iter().map(execution).collect();
        let predictions = private_predictions(&plan, &[(0, 16 * 1024 * 1024)]);
        let verified = forecast_report(&plan, &saved, &[], &predictions);
        assert_eq!(verified.verification.overall_status, "success");
        assert!(verified.resource_summary.is_none());
        assert_eq!(
            verified.action_outcomes[0]
                .expected_resources_freed
                .as_ref()
                .unwrap()
                .memory_mb,
            16.0
        );
        assert!(verified.action_outcomes[1]
            .expected_resources_freed
            .is_none());
    }

    #[test]
    fn repeated_kill_targets_are_counted_once_and_conflicting_or_missing_values_are_unknown() {
        let first = make_action(123, Action::Kill);
        let mut second = first.clone();
        second.action_id.push_str("-second-stage");
        second.order = 1;
        let plan = make_plan(vec![first, second]);
        let saved: Vec<_> = plan.actions.iter().map(execution).collect();
        for (measurements, expected) in [
            (
                vec![(0, 32 * 1024 * 1024), (1, 32 * 1024 * 1024)],
                Some(32.0),
            ),
            (vec![(0, 32 * 1024 * 1024), (1, 64 * 1024 * 1024)], None),
            (vec![(0, 32 * 1024 * 1024)], None),
        ] {
            let predictions = private_predictions(&plan, &measurements);
            let verified = forecast_report(&plan, &saved, &[], &predictions);
            assert_eq!(
                verified
                    .resource_summary
                    .as_ref()
                    .map(|summary| summary.expected_mb),
                expected
            );
            assert_eq!(
                verified
                    .resource_summary
                    .as_ref()
                    .map(|summary| summary.expected_freed_mb),
                expected
            );
        }
        for change in ["birth", "owner"] {
            let mut distinct = plan.clone();
            if change == "birth" {
                distinct.actions[1].target.start_id = StartId("boot:600:123".into());
            } else {
                distinct.actions[1].target.uid += 1;
            }
            let saved: Vec<_> = distinct.actions.iter().map(execution).collect();
            let predictions =
                private_predictions(&distinct, &[(0, 32 * 1024 * 1024), (1, 32 * 1024 * 1024)]);
            let verified = forecast_report(&distinct, &saved, &[], &predictions);
            assert_eq!(
                verified.resource_summary.unwrap().expected_freed_mb,
                64.0,
                "{change}"
            );
        }
    }

    #[test]
    fn forecasts_created_after_execution_are_unknown_and_foreign_plans_are_rejected() {
        let plan = make_plan(vec![make_action(123, Action::Kill)]);
        let saved = execution(&plan.actions[0]);
        let predictions = private_predictions(&plan, &[(0, 64 * 1024 * 1024)]);
        let mut late = predictions.snapshot().clone();
        late.generated_at = "1970-01-01T00:00:11Z".into();
        let late = late.validate(&plan).unwrap();
        let verified = forecast_report(&plan, std::slice::from_ref(&saved), &[], &late);
        assert_eq!(
            verified.action_outcomes[0].outcome,
            VerifyOutcome::ConfirmedDead
        );
        assert_eq!(verified.action_outcomes[0].verified, Some(true));
        assert!(verified.resource_summary.is_none());
        assert!(verified.action_outcomes[0]
            .expected_resources_freed
            .is_none());
        assert!(verified.action_outcomes[0]
            .note
            .as_deref()
            .unwrap()
            .contains("does not precede"));

        let mut foreign = plan.clone();
        foreign.plan_id = "different-plan".into();
        assert!(matches!(
            verify_plan_with_postconditions(
                &foreign,
                &[saved],
                &[],
                DateTime::from_timestamp(30, 0).unwrap(),
                DateTime::from_timestamp(31, 0).unwrap(),
                |_| panic!("invalid prediction binding must fail before observation"),
                Some(&predictions),
            ),
            Err(VerifyError::InvalidResourcePredictions(_))
        ));
    }

    #[test]
    fn future_execution_timestamp_is_refused() {
        let action = make_action(123, Action::Kill);
        let mut saved = execution(&action);
        saved.executed_at = Some(DateTime::from_timestamp(100, 0).unwrap());
        assert!(matches!(
            verify_plan(
                &make_plan(vec![action]),
                &[saved],
                &[],
                DateTime::from_timestamp(30, 0).unwrap(),
                DateTime::from_timestamp(31, 0).unwrap()
            ),
            Err(VerifyError::InvalidTimestamp(_))
        ));
        let action = make_action(123, Action::Kill);
        let mut future = execution(&action);
        future.executed_at = Some(DateTime::from_timestamp(100, 0).unwrap());
        let failed_retry = failed_attempt(&action);
        assert!(matches!(
            verify_plan(
                &make_plan(vec![action]),
                &[future, failed_retry],
                &[],
                DateTime::from_timestamp(30, 0).unwrap(),
                DateTime::from_timestamp(31, 0).unwrap()
            ),
            Err(VerifyError::InvalidTimestamp(_))
        ));
        let action = make_action(123, Action::Kill);
        let mut future = execution(&action);
        future.executed_at = Some(Utc::now() + chrono::Duration::days(1));
        assert!(matches!(
            executed_plan_actions(&make_plan(vec![action]), &[future]),
            Err(VerifyError::InvalidTimestamp(_))
        ));
    }

    #[test]
    fn canonical_report_preserves_wire_identity_status_and_optional_fields() {
        let action = make_action(123, Action::Kill);
        let saved = execution(&action);
        let verified = report(&make_plan(vec![action]), &[saved], &[]);
        let target = &verified.action_outcomes[0].target;
        assert_eq!(target.pid, 123);
        assert_eq!(target.uid, 1000);
        assert_eq!(target.start_id, "boot:500:123");
        assert_eq!(target.cmd_short.as_deref(), Some("node"));
        assert_eq!(target.cmd_full.as_deref(), Some("node app --port 3000"));
        assert_eq!(
            verified.verification.requested_at,
            "1970-01-01T00:00:30+00:00"
        );
        assert_eq!(
            verified.verification.completed_at,
            "1970-01-01T00:00:31+00:00"
        );
        assert_eq!(verified.verification.overall_status, "success");
        assert_eq!(verified.follow_up_needed, Some(false));
        assert!(verified.recommendations.is_none());
        assert!(verified.resource_summary.is_none());
        let json = serde_json::to_value(&verified).unwrap();
        assert!(json.get("recommendations").is_none());
        assert!(json.get("resource_summary").is_none());
        for optional in [
            "respawn_detected",
            "time_to_death_ms",
            "note",
            "restoration",
            "expected_resources_freed",
        ] {
            assert!(json["action_outcomes"][0].get(optional).is_none());
        }
        assert_eq!(json["action_outcomes"][0]["outcome"], "confirmed_dead");
        assert_eq!(json["action_outcomes"][0]["expected"], "terminated");
        assert_eq!(json["action_outcomes"][0]["actual"], "not_found");
        for (outcome, wire) in [
            (VerifyOutcome::ConfirmedDead, "confirmed_dead"),
            (VerifyOutcome::ConfirmedStopped, "confirmed_stopped"),
            (VerifyOutcome::ConfirmedEffect, "confirmed_effect"),
            (VerifyOutcome::ConfirmedRestored, "confirmed_restored"),
            (
                VerifyOutcome::RestorationUnverified,
                "restoration_unverified",
            ),
            (VerifyOutcome::EffectNotObserved, "effect_not_observed"),
            (VerifyOutcome::StillRunning, "still_running"),
            (VerifyOutcome::Respawned, "respawned"),
            (VerifyOutcome::PidReused, "pid_reused"),
            (VerifyOutcome::Unsupported, "unsupported"),
        ] {
            assert_eq!(serde_json::to_value(outcome).unwrap(), wire);
        }
    }

    #[test]
    fn running_and_reused_executed_targets_have_actionable_failure_reports() {
        let action = make_action(123, Action::Kill);
        let saved = execution(&action);
        let plan = make_plan(vec![action]);
        let mut current = make_proc(123, 1000, "node app --port 3000", 5, ProcessState::Running);
        for (start_id, expected, reason) in [
            ("boot:500:123", VerifyOutcome::StillRunning, "still active"),
            ("different-boot:500:123", VerifyOutcome::PidReused, "reused"),
        ] {
            current.start_id = StartId(start_id.to_string());
            let verified = report(
                &plan,
                std::slice::from_ref(&saved),
                std::slice::from_ref(&current),
            );
            assert_eq!(verified.action_outcomes[0].outcome, expected);
            assert_eq!(verified.verification.overall_status, "failure");
            assert_eq!(verified.follow_up_needed, Some(true));
            assert!(verified
                .recommendations
                .as_ref()
                .unwrap()
                .iter()
                .any(|recommendation| {
                    recommendation.contains("PID 123") && recommendation.contains(reason)
                }));
            assert!(verified.resource_summary.is_none());
            assert!(verified.action_outcomes[0]
                .expected_resources_freed
                .is_none());
        }
    }

    #[test]
    fn rss_never_substitutes_for_a_missing_saved_private_memory_forecast() {
        for memory in [
            None,
            Some(0.0),
            Some(1_000_000.0),
            Some(-1.0),
            Some(f64::NAN),
            Some(f64::INFINITY),
        ] {
            let mut action = make_action(123, Action::Kill);
            action.rationale.memory_mb = memory;
            let saved = execution(&action);
            let verified = report(&make_plan(vec![action]), &[saved], &[]);
            assert!(verified.resource_summary.is_none());
            assert!(verified.action_outcomes[0]
                .expected_resources_freed
                .is_none());
        }
    }

    #[test]
    fn saved_timestamp_and_parent_identity_failures_are_visible() {
        let action = make_action(123, Action::Kill);
        let mut saved = execution(&action);
        let mut wire = serde_json::to_value(&saved).unwrap();
        wire["executed_at"] = serde_json::json!("not-a-timestamp");
        let error = parse_action_outcomes(&wire.to_string()).unwrap_err();
        assert!(error.to_string().contains("line 1"));
        assert!(error.to_string().contains("invalid saved action outcomes"));
        saved.parent_identity = Some(ProcessIdentity::new(
            11,
            StartId("boot:100:11".to_string()),
            1000,
        ));
        let error = executed_plan_actions(&make_plan(vec![action]), &[saved]).unwrap_err();
        assert!(error.to_string().contains("inconsistent parent identity"));
        assert_eq!(
            VerifyError::InvalidPlan("bad schema".to_string()).to_string(),
            "invalid action plan: bad schema"
        );
        assert_eq!(
            VerifyError::InvalidTimestamp("future".to_string()).to_string(),
            "invalid execution timestamp: future"
        );
    }

    #[test]
    fn normalize_cmd_preserves_arguments() {
        assert_eq!(
            normalize_cmd("  node\t app  --port 3000\n"),
            "node app --port 3000"
        );
        assert_ne!(
            normalize_cmd("node app --port 3000"),
            normalize_cmd("node app --port 30000")
        );
        assert_eq!(normalize_cmd("  "), "");
    }
}
