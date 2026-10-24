//! Verification of canonical action plans against saved execution evidence.
//!
//! Recommendations are not execution evidence. Respawn attribution requires the
//! executed target's owner, full command, parent and execution clock.

use crate::collect::{ProcessRecord, ProcessState};
use crate::decision::Action;
use crate::plan::{Plan, PlanAction};
use chrono::{DateTime, Utc};
use pt_common::ProcessIdentity;
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
    StillRunning,
    Respawned,
    PidReused,
    Unsupported,
}

#[derive(Debug, Serialize)]
pub struct ExpectedResourcesFreed {
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
    /// Expected footprint of executed kills whose target is confirmed dead.
    /// This is an estimate from the plan, not a measured resource delta.
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
    let recorded = recorded_plan_actions(plan, saved)?;
    validate_execution_timestamps(saved, completed_at)?;
    let by_pid: HashMap<_, _> = current
        .iter()
        .map(|process| (process.pid.0, process))
        .collect();
    let mut outcomes = Vec::new();
    let mut expected_mb = 0.0;
    let mut expected_freed_mb = 0.0;
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
                action: format!("{:?}", action.action).to_lowercase(),
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
            });
            continue;
        }
        let expected_mem = if action.action == Action::Kill {
            action
                .rationale
                .memory_mb
                .filter(|memory| memory.is_finite() && *memory >= 0.0)
                .unwrap_or(0.0)
        } else {
            0.0
        };
        expected_mb += expected_mem;
        let current_target = by_pid.get(&action.target.pid.0).copied();
        let respawn = detect_respawn(action, execution, current);
        let ambiguous_respawn = if respawn.is_none() {
            find_respawn_with_birth_order(action, execution, current, std::cmp::Ordering::Equal)
        } else {
            None
        };
        let (outcome, actual, note) = if respawn.is_some() {
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
                (Action::Kill | Action::Pause, Some(process))
                    if process.start_id != action.target.start_id
                        || process.uid != action.target.uid =>
                {
                    (VerifyOutcome::PidReused, "pid_reused", None)
                }
                (Action::Kill, None) => (VerifyOutcome::ConfirmedDead, "not_found", None),
                (Action::Kill, Some(process)) if process.state.is_zombie() => {
                    (VerifyOutcome::ConfirmedDead, "zombie", None)
                }
                (Action::Pause, Some(process)) if process.state == ProcessState::Stopped => {
                    (VerifyOutcome::ConfirmedStopped, "stopped", None)
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
            VerifyOutcome::ConfirmedDead | VerifyOutcome::ConfirmedStopped
        );
        any_success |= verified;
        any_failed |= !verified;
        if verified && action.action == Action::Kill {
            expected_freed_mb += expected_mem;
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
            action: format!("{:?}", action.action).to_lowercase(),
            outcome,
            time_to_death_ms: None,
            expected_resources_freed: if verified && action.action == Action::Kill {
                Some(ExpectedResourcesFreed {
                    memory_mb: expected_mem,
                })
            } else {
                None
            },
            respawn_detected: respawn,
            expected: Some(
                match action.action {
                    Action::Kill => "terminated",
                    Action::Pause => "stopped",
                    _ => "effect_requires_additional_evidence",
                }
                .to_string(),
            ),
            actual: Some(actual.to_string()),
            verified: Some(verified),
            note,
        });
    }
    let overall_status = if any_success && any_failed {
        "partial_success"
    } else if any_failed {
        "failure"
    } else {
        "success"
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
        resource_summary: Some(ResourceSummary {
            expected_freed_mb: round_to_tenth(expected_freed_mb),
            expected_mb: round_to_tenth(expected_mb),
            shortfall_reason: (expected_freed_mb + f64::EPSILON < expected_mb)
                .then(|| "some executed kills remain active or respawned".to_string()),
        }),
        follow_up_needed: Some(any_failed),
        recommendations: (!recommendations.is_empty()).then_some(recommendations),
    })
}

fn normalize_cmd(command: &str) -> String {
    command.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn round_to_tenth(value: f64) -> f64 {
    (value * 10.0).round() / 10.0
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

    /// Unit fixtures exercise the parser/matcher; they are not live kill proof.
    fn execution(action: &PlanAction) -> SavedActionOutcome {
        SavedActionOutcome {
            action_id: action.action_id.clone(),
            pid: action.target.pid.0,
            status: "success".to_string(),
            action: Some(action.action),
            target: Some(action.target.clone()),
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
        let plan = make_plan(vec![
            make_action(123, Action::Kill),
            make_action(456, Action::Kill),
        ]);
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
            let summary = verified.resource_summary.as_ref().unwrap();
            assert_eq!(summary.expected_mb, 0.0);
            assert_eq!(summary.expected_freed_mb, 0.0);
            let json = serde_json::to_value(&verified).unwrap();
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
        let verified = report(&plan, &saved, &[]);
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
                assert_eq!(verified.resource_summary.unwrap().expected_freed_mb, 0.0);
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
                assert_eq!(
                    verification.resource_summary.unwrap().expected_freed_mb,
                    0.0
                );
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
            assert_eq!(
                verified
                    .resource_summary
                    .as_ref()
                    .unwrap()
                    .expected_freed_mb,
                0.0
            );
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
            assert_eq!(verified.resource_summary.unwrap().expected_freed_mb, 0.0);
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
        let verified = report(&plan, &saved, &[current]);
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
        let summary = verified.resource_summary.as_ref().unwrap();
        assert_eq!(summary.expected_mb, 100.0);
        assert_eq!(summary.expected_freed_mb, 100.0);
        assert!(summary.shortfall_reason.is_none());
        let json = serde_json::to_value(&verified).unwrap();
        assert!(json.get("recommendations").is_none());
        assert!(json["resource_summary"].get("shortfall_reason").is_none());
        for optional in ["respawn_detected", "time_to_death_ms", "note"] {
            assert!(json["action_outcomes"][0].get(optional).is_none());
        }
        assert_eq!(json["action_outcomes"][0]["outcome"], "confirmed_dead");
        assert_eq!(json["action_outcomes"][0]["expected"], "terminated");
        assert_eq!(json["action_outcomes"][0]["actual"], "not_found");
        for (outcome, wire) in [
            (VerifyOutcome::ConfirmedDead, "confirmed_dead"),
            (VerifyOutcome::ConfirmedStopped, "confirmed_stopped"),
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
            assert_eq!(
                verified
                    .resource_summary
                    .as_ref()
                    .unwrap()
                    .expected_freed_mb,
                0.0
            );
            assert!(verified.action_outcomes[0]
                .expected_resources_freed
                .is_none());
        }
    }

    #[test]
    fn absent_invalid_expected_memory_does_not_invent_resource_relief() {
        for memory in [None, Some(-1.0), Some(f64::NAN), Some(f64::INFINITY)] {
            let mut action = make_action(123, Action::Kill);
            action.rationale.memory_mb = memory;
            let saved = execution(&action);
            let verified = report(&make_plan(vec![action]), &[saved], &[]);
            let summary = verified.resource_summary.unwrap();
            assert_eq!(summary.expected_mb, 0.0);
            assert_eq!(summary.expected_freed_mb, 0.0);
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
    fn normalize_cmd_preserves_arguments_and_rounding_is_stable() {
        assert_eq!(
            normalize_cmd("  node\t app  --port 3000\n"),
            "node app --port 3000"
        );
        assert_ne!(
            normalize_cmd("node app --port 3000"),
            normalize_cmd("node app --port 30000")
        );
        assert_eq!(normalize_cmd("  "), "");
        for (input, expected) in [(0.0, 0.0), (1.24, 1.2), (1.25, 1.3), (999.99, 1000.0)] {
            assert!((round_to_tenth(input) - expected).abs() < f64::EPSILON);
        }
    }
}
