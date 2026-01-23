//! Agent verification utilities.
//!
//! Verifies action outcomes by comparing plan candidates against a fresh scan.
//! Intended for `pt-core agent verify`.

use crate::collect::{ProcessRecord, ProcessState};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct AgentPlan {
    pub session_id: String,
    #[serde(default)]
    pub generated_at: Option<String>,
    #[serde(default)]
    pub candidates: Vec<PlanCandidate>,
}

#[derive(Debug, Deserialize)]
pub struct PlanCandidate {
    pub pid: u32,
    pub uid: u32,
    #[serde(default)]
    pub cmd_short: String,
    #[serde(default, rename = "cmd_full")]
    pub cmd_full: String,
    #[serde(default)]
    pub start_id: Option<String>,
    #[serde(default, rename = "recommended_action")]
    pub recommended_action: String,
    #[serde(default)]
    pub blast_radius: Option<BlastRadius>,
}

#[derive(Debug, Deserialize, Default)]
pub struct BlastRadius {
    #[serde(default)]
    pub memory_mb: f64,
    #[serde(default)]
    pub cpu_pct: f64,
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
    pub target: VerifyTarget,
    pub action: String,
    pub outcome: VerifyOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_to_death_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources_freed: Option<ResourceFreed>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmd_short: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmd_full: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum VerifyOutcome {
    ConfirmedDead,
    ConfirmedStopped,
    StillRunning,
    Respawned,
    PidReused,
    Cascaded,
    Timeout,
}

#[derive(Debug, Serialize)]
pub struct ResourceFreed {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_mb: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_pct: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct RespawnDetected {
    pub pid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmd_full: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time_unix: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct ResourceSummary {
    pub memory_freed_mb: f64,
    pub expected_mb: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shortfall_reason: Option<String>,
}

#[derive(Debug)]
pub enum VerifyError {
    InvalidPlan(String),
    InvalidTimestamp(String),
}

#[derive(Debug, Clone)]
enum PlanStartId {
    Legacy { pid: u32, start_time: u64 },
    Full { raw: String, pid: u32 },
    Unknown,
}

pub fn parse_agent_plan(content: &str) -> Result<AgentPlan, VerifyError> {
    serde_json::from_str(content).map_err(|e| VerifyError::InvalidPlan(e.to_string()))
}

pub fn verify_plan(
    plan: &AgentPlan,
    current: &[ProcessRecord],
    requested_at: DateTime<Utc>,
    completed_at: DateTime<Utc>,
) -> VerificationReport {
    let mut by_pid: HashMap<u32, &ProcessRecord> = HashMap::new();
    let mut by_cmd: HashMap<(u32, String), Vec<&ProcessRecord>> = HashMap::new();

    for proc in current {
        by_pid.insert(proc.pid.0, proc);
        let key = (proc.uid, normalize_cmd(&proc.cmd));
        by_cmd.entry(key).or_default().push(proc);
    }
    for list in by_cmd.values_mut() {
        list.sort_by_key(|p| std::cmp::Reverse(p.start_time_unix));
    }

    let plan_ts = plan
        .generated_at
        .as_ref()
        .and_then(|ts| DateTime::parse_from_rfc3339(ts).ok())
        .map(|dt| dt.with_timezone(&Utc));

    let mut outcomes = Vec::new();
    let mut expected_mb = 0.0;
    let mut freed_mb = 0.0;
    let mut recommendations = Vec::new();
    let mut any_failed = false;
    let mut any_success = false;

    for candidate in &plan.candidates {
        if candidate.recommended_action == "keep" {
            continue;
        }

        let start_id = candidate.start_id.as_deref().unwrap_or("");
        let parsed_start = parse_plan_start_id(start_id);
        let current_proc = by_pid.get(&candidate.pid).copied();
        let command_key = normalize_cmd(candidate_command(candidate));
        let cmd_lookup_key = (candidate.uid, command_key.clone());

        let action = candidate.recommended_action.clone();
        let expected = expected_outcome(&action);

        let expected_mem = candidate
            .blast_radius
            .as_ref()
            .map(|b| b.memory_mb)
            .unwrap_or(0.0);

        if action == "kill" || action == "restart" {
            expected_mb += expected_mem;
        }

        let (outcome, actual, respawn) = match current_proc {
            Some(proc) => {
                if !start_id_matches(parsed_start.clone(), proc)
                    && matches_pid(&parsed_start, proc.pid.0)
                {
                    (VerifyOutcome::PidReused, "pid_reused".to_string(), None)
                } else {
                    match action.as_str() {
                        "pause" | "freeze" => {
                            if proc.state == ProcessState::Stopped {
                                (VerifyOutcome::ConfirmedStopped, "stopped".to_string(), None)
                            } else {
                                (VerifyOutcome::StillRunning, "still_running".to_string(), None)
                            }
                        }
                        "kill" | "restart" => {
                            if proc.state == ProcessState::Zombie {
                                (VerifyOutcome::ConfirmedDead, "zombie".to_string(), None)
                            } else {
                                (VerifyOutcome::StillRunning, "still_running".to_string(), None)
                            }
                        }
                        _ => (VerifyOutcome::StillRunning, "still_running".to_string(), None),
                    }
                }
            }
            None => {
                if let Some(respawn) = detect_respawn(&by_cmd, &cmd_lookup_key, plan_ts) {
                    (
                        VerifyOutcome::Respawned,
                        "respawned".to_string(),
                        Some(respawn),
                    )
                } else {
                    (VerifyOutcome::ConfirmedDead, "not_found".to_string(), None)
                }
            }
        };

        let verified = matches!(
            outcome,
            VerifyOutcome::ConfirmedDead | VerifyOutcome::ConfirmedStopped
        );
        if verified {
            any_success = true;
        } else {
            any_failed = true;
        }

        if verified && (action == "kill" || action == "restart") {
            freed_mb += expected_mem;
        }

        if matches!(outcome, VerifyOutcome::Respawned | VerifyOutcome::StillRunning) {
            recommendations.push(format!(
                "PID {} ({}) still active; consider supervisor stop or deeper investigation",
                candidate.pid,
                candidate.cmd_short
            ));
        }
        if matches!(outcome, VerifyOutcome::PidReused) {
            recommendations.push(format!(
                "PID {} reused; regenerate plan before taking action",
                candidate.pid
            ));
        }

        outcomes.push(ActionOutcome {
            target: VerifyTarget {
                pid: candidate.pid,
                cmd_short: if candidate.cmd_short.is_empty() {
                    None
                } else {
                    Some(candidate.cmd_short.clone())
                },
                cmd_full: if candidate.cmd_full.is_empty() {
                    None
                } else {
                    Some(candidate.cmd_full.clone())
                },
                uid: Some(candidate.uid),
            },
            action: action.clone(),
            outcome: outcome.clone(),
            time_to_death_ms: None,
            resources_freed: if verified && (action == "kill" || action == "restart") {
                Some(ResourceFreed {
                    memory_mb: Some(expected_mem),
                    cpu_pct: candidate.blast_radius.as_ref().map(|b| b.cpu_pct),
                })
            } else {
                None
            },
            respawn_detected: respawn,
            expected: Some(expected),
            actual: Some(actual),
            verified: Some(verified),
            note: None,
        });
    }

    let overall_status = if outcomes.is_empty() {
        "success"
    } else if any_success && any_failed {
        "partial_success"
    } else if any_success {
        "success"
    } else {
        "failure"
    };

    let shortfall_reason = if freed_mb + f64::EPSILON < expected_mb {
        Some("some targets still running or respawned".to_string())
    } else {
        None
    };

    VerificationReport {
        schema_version: pt_common::SCHEMA_VERSION.to_string(),
        session_id: plan.session_id.clone(),
        verification: VerificationWindow {
            requested_at: requested_at.to_rfc3339(),
            completed_at: completed_at.to_rfc3339(),
            overall_status: overall_status.to_string(),
        },
        action_outcomes: outcomes,
        resource_summary: Some(ResourceSummary {
            memory_freed_mb: round_to_tenth(freed_mb),
            expected_mb: round_to_tenth(expected_mb),
            shortfall_reason,
        }),
        follow_up_needed: Some(any_failed),
        recommendations: if recommendations.is_empty() {
            None
        } else {
            Some(recommendations)
        },
    }
}

fn normalize_cmd(cmd: &str) -> String {
    cmd.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn candidate_command(candidate: &PlanCandidate) -> &str {
    if !candidate.cmd_full.is_empty() {
        &candidate.cmd_full
    } else {
        &candidate.cmd_short
    }
}

fn expected_outcome(action: &str) -> String {
    match action {
        "pause" | "freeze" => "stopped".to_string(),
        "kill" | "restart" => "terminated".to_string(),
        _ => "unknown".to_string(),
    }
}

fn parse_plan_start_id(raw: &str) -> PlanStartId {
    let mut parts = raw.split(':');
    let first = match parts.next() {
        Some(v) => v,
        None => return PlanStartId::Unknown,
    };
    let second = match parts.next() {
        Some(v) => v,
        None => return PlanStartId::Unknown,
    };
    if let (Ok(pid), Ok(start_time)) = (first.parse::<u32>(), second.parse::<u64>()) {
        if parts.next().is_none() {
            return PlanStartId::Legacy { pid, start_time };
        }
    }
    if let Some(third) = parts.next() {
        if parts.next().is_none() && Uuid::parse_str(first).is_ok() {
            if let Ok(pid) = third.parse::<u32>() {
                return PlanStartId::Full {
                    raw: raw.to_string(),
                    pid,
                };
            }
        }
    }
    PlanStartId::Unknown
}

fn start_id_matches(parsed: PlanStartId, proc: &ProcessRecord) -> bool {
    match parsed {
        PlanStartId::Legacy { pid, start_time } => {
            let proc_start = if proc.start_time_unix < 0 {
                return false;
            } else {
                proc.start_time_unix as u64
            };
            proc.pid.0 == pid && proc_start == start_time
        }
        PlanStartId::Full { raw, .. } => proc.start_id.0 == raw,
        PlanStartId::Unknown => true,
    }
}

fn matches_pid(parsed: &PlanStartId, pid: u32) -> bool {
    match parsed {
        PlanStartId::Legacy { pid: parsed_pid, .. } => *parsed_pid == pid,
        PlanStartId::Full { pid: parsed_pid, .. } => *parsed_pid == pid,
        PlanStartId::Unknown => true,
    }
}

fn detect_respawn(
    by_cmd: &HashMap<(u32, String), Vec<&ProcessRecord>>,
    key: &(u32, String),
    plan_ts: Option<DateTime<Utc>>,
) -> Option<RespawnDetected> {
    let list = by_cmd.get(key)?;
    let candidate = list.first()?;
    if let Some(ts) = plan_ts {
        let plan_unix = ts.timestamp();
        if candidate.start_time_unix < plan_unix {
            return None;
        }
    }
    Some(RespawnDetected {
        pid: candidate.pid.0,
        cmd_full: Some(candidate.cmd.clone()),
        start_time_unix: Some(candidate.start_time_unix),
    })
}

fn round_to_tenth(value: f64) -> f64 {
    (value * 10.0).round() / 10.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::ProcessRecord;
    use pt_common::{ProcessId, StartId};
    use std::time::Duration;

    fn make_proc(pid: u32, uid: u32, cmd: &str, start: i64, state: ProcessState) -> ProcessRecord {
        ProcessRecord {
            pid: ProcessId(pid),
            ppid: ProcessId(1),
            uid,
            user: "test".to_string(),
            pgid: None,
            sid: None,
            start_id: StartId(format!("boot:{}:{}", start, pid)),
            comm: cmd.to_string(),
            cmd: cmd.to_string(),
            state,
            cpu_percent: 0.0,
            rss_bytes: 0,
            vsz_bytes: 0,
            tty: None,
            start_time_unix: start,
            elapsed: Duration::from_secs(60),
            source: "test".to_string(),
            container_info: None,
        }
    }

    #[test]
    fn verify_detects_respawn() {
        let plan = AgentPlan {
            session_id: "pt-20260115-000000-abcd".to_string(),
            generated_at: Some("1970-01-01T00:00:10Z".to_string()),
            candidates: vec![PlanCandidate {
                pid: 123,
                uid: 1000,
                cmd_short: "node".to_string(),
                cmd_full: "node dev".to_string(),
                start_id: Some("123:5".to_string()),
                recommended_action: "kill".to_string(),
                blast_radius: Some(BlastRadius {
                    memory_mb: 100.0,
                    cpu_pct: 1.0,
                }),
            }],
        };

        // Current process has DIFFERENT PID (456) but SAME CMD and LATER start time (20 > 10)
        let current = vec![make_proc(456, 1000, "node dev", 20, ProcessState::Running)];
        let report = verify_plan(&plan, &current, Utc::now(), Utc::now());

        assert_eq!(report.action_outcomes.len(), 1);
        assert!(matches!(
            report.action_outcomes[0].outcome,
            VerifyOutcome::Respawned
        ));
    }
}
