//! Agent verification utilities.
//!
//! Verifies action outcomes by comparing plan candidates against a fresh scan.
//! Intended for `pt-core agent verify`.

use crate::collect::{ProcessRecord, ProcessState};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
                                (
                                    VerifyOutcome::StillRunning,
                                    "still_running".to_string(),
                                    None,
                                )
                            }
                        }
                        "kill" | "restart" => {
                            if proc.state == ProcessState::Zombie {
                                (VerifyOutcome::ConfirmedDead, "zombie".to_string(), None)
                            } else {
                                (
                                    VerifyOutcome::StillRunning,
                                    "still_running".to_string(),
                                    None,
                                )
                            }
                        }
                        _ => (
                            VerifyOutcome::StillRunning,
                            "still_running".to_string(),
                            None,
                        ),
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

        if matches!(
            outcome,
            VerifyOutcome::Respawned | VerifyOutcome::StillRunning
        ) {
            recommendations.push(format!(
                "PID {} ({}) still active; consider supervisor stop or deeper investigation",
                candidate.pid, candidate.cmd_short
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
    let parts: Vec<&str> = raw.split(':').collect();
    match parts.len() {
        2 => {
            if let (Ok(pid), Ok(start_time)) = (parts[0].parse::<u32>(), parts[1].parse::<u64>()) {
                return PlanStartId::Legacy { pid, start_time };
            }
        }
        3 => {
            if let (Ok(_start_time), Ok(pid)) = (parts[1].parse::<u64>(), parts[2].parse::<u32>()) {
                return PlanStartId::Full {
                    raw: raw.to_string(),
                    pid,
                };
            }
        }
        _ => {}
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
        PlanStartId::Legacy {
            pid: parsed_pid, ..
        } => *parsed_pid == pid,
        PlanStartId::Full {
            pid: parsed_pid, ..
        } => *parsed_pid == pid,
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

    fn make_proc_with_start_id(
        pid: u32,
        uid: u32,
        cmd: &str,
        start: i64,
        state: ProcessState,
        start_id: &str,
    ) -> ProcessRecord {
        let mut proc = make_proc(pid, uid, cmd, start, state);
        proc.start_id = StartId(start_id.to_string());
        proc
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

    #[test]
    fn verify_detects_pid_reuse_with_non_uuid_start_id() {
        let plan = AgentPlan {
            session_id: "pt-20260115-000000-abcd".to_string(),
            generated_at: Some("1970-01-01T00:00:10Z".to_string()),
            candidates: vec![PlanCandidate {
                pid: 321,
                uid: 1000,
                cmd_short: "sleep".to_string(),
                cmd_full: "sleep 10".to_string(),
                start_id: Some("unknown:100:321".to_string()),
                recommended_action: "kill".to_string(),
                blast_radius: None,
            }],
        };

        let current = vec![make_proc_with_start_id(
            321,
            1000,
            "sleep 10",
            100,
            ProcessState::Running,
            "other:100:321",
        )];

        let report = verify_plan(&plan, &current, Utc::now(), Utc::now());
        assert_eq!(report.action_outcomes.len(), 1);
        assert!(matches!(
            report.action_outcomes[0].outcome,
            VerifyOutcome::PidReused
        ));
    }

    // ── parse_agent_plan ────────────────────────────────────────────

    #[test]
    fn parse_agent_plan_valid_json() {
        let json = r#"{"session_id":"s1","candidates":[{"pid":1,"uid":0,"cmd_short":"cat","recommended_action":"kill"}]}"#;
        let plan = parse_agent_plan(json).unwrap();
        assert_eq!(plan.session_id, "s1");
        assert_eq!(plan.candidates.len(), 1);
        assert_eq!(plan.candidates[0].pid, 1);
        assert!(plan.generated_at.is_none());
    }

    #[test]
    fn parse_agent_plan_minimal() {
        let json = r#"{"session_id":"s2"}"#;
        let plan = parse_agent_plan(json).unwrap();
        assert_eq!(plan.session_id, "s2");
        assert!(plan.candidates.is_empty());
    }

    #[test]
    fn parse_agent_plan_invalid_json() {
        let result = parse_agent_plan("{not valid}");
        assert!(result.is_err());
        match result.unwrap_err() {
            VerifyError::InvalidPlan(msg) => assert!(!msg.is_empty()),
            other => panic!("expected InvalidPlan, got {:?}", other),
        }
    }

    #[test]
    fn parse_agent_plan_empty_string() {
        assert!(parse_agent_plan("").is_err());
    }

    #[test]
    fn parse_agent_plan_with_all_fields() {
        let json = r#"{
            "session_id":"s3",
            "generated_at":"2026-01-15T00:00:00Z",
            "candidates":[{
                "pid":42,"uid":1000,
                "cmd_short":"node","cmd_full":"node server.js",
                "start_id":"boot:100:42",
                "recommended_action":"kill",
                "blast_radius":{"memory_mb":256.5,"cpu_pct":3.2}
            }]
        }"#;
        let plan = parse_agent_plan(json).unwrap();
        assert_eq!(plan.generated_at.as_deref(), Some("2026-01-15T00:00:00Z"));
        let c = &plan.candidates[0];
        assert_eq!(c.pid, 42);
        assert_eq!(c.uid, 1000);
        assert_eq!(c.cmd_full, "node server.js");
        assert_eq!(c.start_id.as_deref(), Some("boot:100:42"));
        let br = c.blast_radius.as_ref().unwrap();
        assert!((br.memory_mb - 256.5).abs() < f64::EPSILON);
        assert!((br.cpu_pct - 3.2).abs() < f64::EPSILON);
    }

    // ── normalize_cmd ───────────────────────────────────────────────

    #[test]
    fn normalize_cmd_collapses_whitespace() {
        assert_eq!(
            normalize_cmd("node   server.js   --port  3000"),
            "node server.js --port 3000"
        );
    }

    #[test]
    fn normalize_cmd_already_normalized() {
        assert_eq!(normalize_cmd("cat file.txt"), "cat file.txt");
    }

    #[test]
    fn normalize_cmd_empty() {
        assert_eq!(normalize_cmd(""), "");
    }

    #[test]
    fn normalize_cmd_leading_trailing_spaces() {
        assert_eq!(normalize_cmd("  ls  -la  "), "ls -la");
    }

    #[test]
    fn normalize_cmd_tabs_and_newlines() {
        assert_eq!(normalize_cmd("cat\t\tfile\n"), "cat file");
    }

    // ── candidate_command ───────────────────────────────────────────

    #[test]
    fn candidate_command_prefers_cmd_full() {
        let c = PlanCandidate {
            pid: 1,
            uid: 0,
            cmd_short: "node".to_string(),
            cmd_full: "node server.js".to_string(),
            start_id: None,
            recommended_action: "kill".to_string(),
            blast_radius: None,
        };
        assert_eq!(candidate_command(&c), "node server.js");
    }

    #[test]
    fn candidate_command_falls_back_to_cmd_short() {
        let c = PlanCandidate {
            pid: 1,
            uid: 0,
            cmd_short: "node".to_string(),
            cmd_full: "".to_string(),
            start_id: None,
            recommended_action: "kill".to_string(),
            blast_radius: None,
        };
        assert_eq!(candidate_command(&c), "node");
    }

    #[test]
    fn candidate_command_both_empty() {
        let c = PlanCandidate {
            pid: 1,
            uid: 0,
            cmd_short: "".to_string(),
            cmd_full: "".to_string(),
            start_id: None,
            recommended_action: "kill".to_string(),
            blast_radius: None,
        };
        assert_eq!(candidate_command(&c), "");
    }

    // ── expected_outcome ────────────────────────────────────────────

    #[test]
    fn expected_outcome_pause() {
        assert_eq!(expected_outcome("pause"), "stopped");
    }

    #[test]
    fn expected_outcome_freeze() {
        assert_eq!(expected_outcome("freeze"), "stopped");
    }

    #[test]
    fn expected_outcome_kill() {
        assert_eq!(expected_outcome("kill"), "terminated");
    }

    #[test]
    fn expected_outcome_restart() {
        assert_eq!(expected_outcome("restart"), "terminated");
    }

    #[test]
    fn expected_outcome_unknown_action() {
        assert_eq!(expected_outcome("monitor"), "unknown");
        assert_eq!(expected_outcome(""), "unknown");
    }

    // ── parse_plan_start_id ─────────────────────────────────────────

    #[test]
    fn parse_plan_start_id_legacy_two_part() {
        match parse_plan_start_id("42:1000") {
            PlanStartId::Legacy { pid, start_time } => {
                assert_eq!(pid, 42);
                assert_eq!(start_time, 1000);
            }
            other => panic!("expected Legacy, got {:?}", other),
        }
    }

    #[test]
    fn parse_plan_start_id_full_three_part() {
        match parse_plan_start_id("boot:5000:99") {
            PlanStartId::Full { raw, pid } => {
                assert_eq!(raw, "boot:5000:99");
                assert_eq!(pid, 99);
            }
            other => panic!("expected Full, got {:?}", other),
        }
    }

    #[test]
    fn parse_plan_start_id_unknown_empty() {
        assert!(matches!(parse_plan_start_id(""), PlanStartId::Unknown));
    }

    #[test]
    fn parse_plan_start_id_unknown_single_part() {
        assert!(matches!(
            parse_plan_start_id("just-a-string"),
            PlanStartId::Unknown
        ));
    }

    #[test]
    fn parse_plan_start_id_unknown_four_parts() {
        assert!(matches!(
            parse_plan_start_id("a:b:c:d"),
            PlanStartId::Unknown
        ));
    }

    #[test]
    fn parse_plan_start_id_two_part_non_numeric() {
        assert!(matches!(
            parse_plan_start_id("abc:def"),
            PlanStartId::Unknown
        ));
    }

    #[test]
    fn parse_plan_start_id_three_part_non_numeric_middle() {
        // Middle part must be parseable as u64
        assert!(matches!(
            parse_plan_start_id("boot:abc:42"),
            PlanStartId::Unknown
        ));
    }

    #[test]
    fn parse_plan_start_id_three_part_non_numeric_pid() {
        assert!(matches!(
            parse_plan_start_id("boot:5000:abc"),
            PlanStartId::Unknown
        ));
    }

    // ── start_id_matches ────────────────────────────────────────────

    #[test]
    fn start_id_matches_legacy_match() {
        let proc = make_proc(42, 0, "cat", 1000, ProcessState::Running);
        let parsed = PlanStartId::Legacy {
            pid: 42,
            start_time: 1000,
        };
        assert!(start_id_matches(parsed, &proc));
    }

    #[test]
    fn start_id_matches_legacy_pid_mismatch() {
        let proc = make_proc(42, 0, "cat", 1000, ProcessState::Running);
        let parsed = PlanStartId::Legacy {
            pid: 99,
            start_time: 1000,
        };
        assert!(!start_id_matches(parsed, &proc));
    }

    #[test]
    fn start_id_matches_legacy_start_time_mismatch() {
        let proc = make_proc(42, 0, "cat", 1000, ProcessState::Running);
        let parsed = PlanStartId::Legacy {
            pid: 42,
            start_time: 999,
        };
        assert!(!start_id_matches(parsed, &proc));
    }

    #[test]
    fn start_id_matches_legacy_negative_start_time() {
        let proc = make_proc(42, 0, "cat", -1, ProcessState::Running);
        let parsed = PlanStartId::Legacy {
            pid: 42,
            start_time: 0,
        };
        assert!(!start_id_matches(parsed, &proc));
    }

    #[test]
    fn start_id_matches_full_match() {
        let proc =
            make_proc_with_start_id(99, 0, "cat", 5000, ProcessState::Running, "boot:5000:99");
        let parsed = PlanStartId::Full {
            raw: "boot:5000:99".to_string(),
            pid: 99,
        };
        assert!(start_id_matches(parsed, &proc));
    }

    #[test]
    fn start_id_matches_full_mismatch() {
        let proc =
            make_proc_with_start_id(99, 0, "cat", 5000, ProcessState::Running, "other:5000:99");
        let parsed = PlanStartId::Full {
            raw: "boot:5000:99".to_string(),
            pid: 99,
        };
        assert!(!start_id_matches(parsed, &proc));
    }

    #[test]
    fn start_id_matches_unknown_always_true() {
        let proc = make_proc(42, 0, "cat", 1000, ProcessState::Running);
        assert!(start_id_matches(PlanStartId::Unknown, &proc));
    }

    // ── matches_pid ─────────────────────────────────────────────────

    #[test]
    fn matches_pid_legacy_match() {
        let parsed = PlanStartId::Legacy {
            pid: 42,
            start_time: 100,
        };
        assert!(matches_pid(&parsed, 42));
    }

    #[test]
    fn matches_pid_legacy_mismatch() {
        let parsed = PlanStartId::Legacy {
            pid: 42,
            start_time: 100,
        };
        assert!(!matches_pid(&parsed, 99));
    }

    #[test]
    fn matches_pid_full_match() {
        let parsed = PlanStartId::Full {
            raw: "boot:100:42".to_string(),
            pid: 42,
        };
        assert!(matches_pid(&parsed, 42));
    }

    #[test]
    fn matches_pid_full_mismatch() {
        let parsed = PlanStartId::Full {
            raw: "boot:100:42".to_string(),
            pid: 42,
        };
        assert!(!matches_pid(&parsed, 99));
    }

    #[test]
    fn matches_pid_unknown_always_true() {
        assert!(matches_pid(&PlanStartId::Unknown, 0));
        assert!(matches_pid(&PlanStartId::Unknown, u32::MAX));
    }

    // ── round_to_tenth ──────────────────────────────────────────────

    #[test]
    fn round_to_tenth_exact() {
        assert!((round_to_tenth(1.0) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn round_to_tenth_rounds_down() {
        assert!((round_to_tenth(1.24) - 1.2).abs() < f64::EPSILON);
    }

    #[test]
    fn round_to_tenth_rounds_up() {
        assert!((round_to_tenth(1.25) - 1.3).abs() < f64::EPSILON);
    }

    #[test]
    fn round_to_tenth_zero() {
        assert!((round_to_tenth(0.0) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn round_to_tenth_large() {
        assert!((round_to_tenth(999.99) - 1000.0).abs() < f64::EPSILON);
    }

    // ── BlastRadius defaults ────────────────────────────────────────

    #[test]
    fn blast_radius_default() {
        let br = BlastRadius::default();
        assert!((br.memory_mb - 0.0).abs() < f64::EPSILON);
        assert!((br.cpu_pct - 0.0).abs() < f64::EPSILON);
    }

    // ── VerifyOutcome serialization ─────────────────────────────────

    #[test]
    fn verify_outcome_serde_snake_case() {
        let json = serde_json::to_string(&VerifyOutcome::ConfirmedDead).unwrap();
        assert_eq!(json, r#""confirmed_dead""#);
        let json = serde_json::to_string(&VerifyOutcome::ConfirmedStopped).unwrap();
        assert_eq!(json, r#""confirmed_stopped""#);
        let json = serde_json::to_string(&VerifyOutcome::StillRunning).unwrap();
        assert_eq!(json, r#""still_running""#);
        let json = serde_json::to_string(&VerifyOutcome::Respawned).unwrap();
        assert_eq!(json, r#""respawned""#);
        let json = serde_json::to_string(&VerifyOutcome::PidReused).unwrap();
        assert_eq!(json, r#""pid_reused""#);
        let json = serde_json::to_string(&VerifyOutcome::Cascaded).unwrap();
        assert_eq!(json, r#""cascaded""#);
        let json = serde_json::to_string(&VerifyOutcome::Timeout).unwrap();
        assert_eq!(json, r#""timeout""#);
    }

    // ── VerifyError display ─────────────────────────────────────────

    #[test]
    fn verify_error_debug_format() {
        let e = VerifyError::InvalidPlan("bad json".into());
        let dbg = format!("{:?}", e);
        assert!(dbg.contains("InvalidPlan"));
        assert!(dbg.contains("bad json"));

        let e = VerifyError::InvalidTimestamp("bad ts".into());
        let dbg = format!("{:?}", e);
        assert!(dbg.contains("InvalidTimestamp"));
    }

    // ── detect_respawn ──────────────────────────────────────────────

    #[test]
    fn detect_respawn_found_with_later_start() {
        let procs = vec![make_proc(456, 1000, "node app", 200, ProcessState::Running)];
        let mut by_cmd: HashMap<(u32, String), Vec<&ProcessRecord>> = HashMap::new();
        for p in &procs {
            by_cmd
                .entry((p.uid, normalize_cmd(&p.cmd)))
                .or_default()
                .push(p);
        }
        let key = (1000_u32, "node app".to_string());
        let plan_ts = DateTime::parse_from_rfc3339("1970-01-01T00:00:10Z")
            .ok()
            .map(|dt| dt.with_timezone(&Utc));
        let result = detect_respawn(&by_cmd, &key, plan_ts);
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.pid, 456);
        assert_eq!(r.start_time_unix, Some(200));
    }

    #[test]
    fn detect_respawn_not_found_different_cmd() {
        let procs = vec![make_proc(
            456,
            1000,
            "python app",
            200,
            ProcessState::Running,
        )];
        let mut by_cmd: HashMap<(u32, String), Vec<&ProcessRecord>> = HashMap::new();
        for p in &procs {
            by_cmd
                .entry((p.uid, normalize_cmd(&p.cmd)))
                .or_default()
                .push(p);
        }
        let key = (1000_u32, "node app".to_string());
        assert!(detect_respawn(&by_cmd, &key, None).is_none());
    }

    #[test]
    fn detect_respawn_start_before_plan_ts() {
        let procs = vec![make_proc(456, 1000, "node app", 5, ProcessState::Running)];
        let mut by_cmd: HashMap<(u32, String), Vec<&ProcessRecord>> = HashMap::new();
        for p in &procs {
            by_cmd
                .entry((p.uid, normalize_cmd(&p.cmd)))
                .or_default()
                .push(p);
        }
        let key = (1000_u32, "node app".to_string());
        let plan_ts = DateTime::parse_from_rfc3339("1970-01-01T00:00:10Z")
            .ok()
            .map(|dt| dt.with_timezone(&Utc));
        // start_time_unix=5 < plan_unix=10, so no respawn detected
        assert!(detect_respawn(&by_cmd, &key, plan_ts).is_none());
    }

    #[test]
    fn detect_respawn_no_plan_ts_returns_any_match() {
        let procs = vec![make_proc(456, 1000, "node app", 5, ProcessState::Running)];
        let mut by_cmd: HashMap<(u32, String), Vec<&ProcessRecord>> = HashMap::new();
        for p in &procs {
            by_cmd
                .entry((p.uid, normalize_cmd(&p.cmd)))
                .or_default()
                .push(p);
        }
        let key = (1000_u32, "node app".to_string());
        // Without plan_ts, any matching cmd is considered respawn
        let result = detect_respawn(&by_cmd, &key, None);
        assert!(result.is_some());
    }

    // ── verify_plan integration tests ───────────────────────────────

    fn make_plan(candidates: Vec<PlanCandidate>) -> AgentPlan {
        AgentPlan {
            session_id: "test-session".to_string(),
            generated_at: Some("1970-01-01T00:00:10Z".to_string()),
            candidates,
        }
    }

    fn make_candidate(pid: u32, uid: u32, action: &str) -> PlanCandidate {
        PlanCandidate {
            pid,
            uid,
            cmd_short: format!("cmd{}", pid),
            cmd_full: format!("cmd{} --flag", pid),
            start_id: Some(format!("boot:5:{}", pid)),
            recommended_action: action.to_string(),
            blast_radius: Some(BlastRadius {
                memory_mb: 100.0,
                cpu_pct: 2.0,
            }),
        }
    }

    #[test]
    fn verify_plan_keep_action_skipped() {
        let plan = make_plan(vec![make_candidate(1, 1000, "keep")]);
        let current = vec![make_proc(1, 1000, "cmd1 --flag", 5, ProcessState::Running)];
        let report = verify_plan(&plan, &current, Utc::now(), Utc::now());
        assert!(report.action_outcomes.is_empty());
        assert_eq!(report.verification.overall_status, "success");
    }

    #[test]
    fn verify_plan_confirmed_dead_not_found() {
        let plan = make_plan(vec![make_candidate(999, 1000, "kill")]);
        // PID 999 not in current → confirmed dead
        let current: Vec<ProcessRecord> = vec![];
        let report = verify_plan(&plan, &current, Utc::now(), Utc::now());
        assert_eq!(report.action_outcomes.len(), 1);
        assert!(matches!(
            report.action_outcomes[0].outcome,
            VerifyOutcome::ConfirmedDead
        ));
        assert_eq!(
            report.action_outcomes[0].actual.as_deref(),
            Some("not_found")
        );
        assert_eq!(report.action_outcomes[0].verified, Some(true));
        assert_eq!(report.verification.overall_status, "success");
    }

    #[test]
    fn verify_plan_still_running_kill_action() {
        let plan = make_plan(vec![make_candidate(42, 1000, "kill")]);
        // PID 42 still running with matching start_id
        let current = vec![make_proc_with_start_id(
            42,
            1000,
            "cmd42 --flag",
            5,
            ProcessState::Running,
            "boot:5:42",
        )];
        let report = verify_plan(&plan, &current, Utc::now(), Utc::now());
        assert_eq!(report.action_outcomes.len(), 1);
        assert!(matches!(
            report.action_outcomes[0].outcome,
            VerifyOutcome::StillRunning
        ));
        assert_eq!(report.action_outcomes[0].verified, Some(false));
        assert_eq!(report.verification.overall_status, "failure");
        assert_eq!(report.follow_up_needed, Some(true));
    }

    #[test]
    fn verify_plan_kill_zombie_is_confirmed_dead() {
        let plan = make_plan(vec![make_candidate(42, 1000, "kill")]);
        let current = vec![make_proc_with_start_id(
            42,
            1000,
            "cmd42 --flag",
            5,
            ProcessState::Zombie,
            "boot:5:42",
        )];
        let report = verify_plan(&plan, &current, Utc::now(), Utc::now());
        assert_eq!(report.action_outcomes.len(), 1);
        assert!(matches!(
            report.action_outcomes[0].outcome,
            VerifyOutcome::ConfirmedDead
        ));
        assert_eq!(report.action_outcomes[0].verified, Some(true));
    }

    #[test]
    fn verify_plan_pause_stopped_is_confirmed_stopped() {
        let plan = make_plan(vec![make_candidate(42, 1000, "pause")]);
        let current = vec![make_proc_with_start_id(
            42,
            1000,
            "cmd42 --flag",
            5,
            ProcessState::Stopped,
            "boot:5:42",
        )];
        let report = verify_plan(&plan, &current, Utc::now(), Utc::now());
        assert_eq!(report.action_outcomes.len(), 1);
        assert!(matches!(
            report.action_outcomes[0].outcome,
            VerifyOutcome::ConfirmedStopped
        ));
        assert_eq!(
            report.action_outcomes[0].expected.as_deref(),
            Some("stopped")
        );
        assert_eq!(report.action_outcomes[0].verified, Some(true));
    }

    #[test]
    fn verify_plan_freeze_not_stopped_is_still_running() {
        let plan = make_plan(vec![make_candidate(42, 1000, "freeze")]);
        let current = vec![make_proc_with_start_id(
            42,
            1000,
            "cmd42 --flag",
            5,
            ProcessState::Running,
            "boot:5:42",
        )];
        let report = verify_plan(&plan, &current, Utc::now(), Utc::now());
        assert!(matches!(
            report.action_outcomes[0].outcome,
            VerifyOutcome::StillRunning
        ));
    }

    #[test]
    fn verify_plan_restart_still_running() {
        let plan = make_plan(vec![make_candidate(42, 1000, "restart")]);
        let current = vec![make_proc_with_start_id(
            42,
            1000,
            "cmd42 --flag",
            5,
            ProcessState::Running,
            "boot:5:42",
        )];
        let report = verify_plan(&plan, &current, Utc::now(), Utc::now());
        assert!(matches!(
            report.action_outcomes[0].outcome,
            VerifyOutcome::StillRunning
        ));
        assert_eq!(
            report.action_outcomes[0].expected.as_deref(),
            Some("terminated")
        );
    }

    #[test]
    fn verify_plan_unknown_action_is_still_running() {
        let plan = make_plan(vec![make_candidate(42, 1000, "investigate")]);
        let current = vec![make_proc_with_start_id(
            42,
            1000,
            "cmd42 --flag",
            5,
            ProcessState::Running,
            "boot:5:42",
        )];
        let report = verify_plan(&plan, &current, Utc::now(), Utc::now());
        assert!(matches!(
            report.action_outcomes[0].outcome,
            VerifyOutcome::StillRunning
        ));
        assert_eq!(
            report.action_outcomes[0].expected.as_deref(),
            Some("unknown")
        );
    }

    #[test]
    fn verify_plan_empty_candidates() {
        let plan = make_plan(vec![]);
        let report = verify_plan(&plan, &[], Utc::now(), Utc::now());
        assert!(report.action_outcomes.is_empty());
        assert_eq!(report.verification.overall_status, "success");
        assert_eq!(report.follow_up_needed, Some(false));
    }

    #[test]
    fn verify_plan_partial_success() {
        let plan = make_plan(vec![
            make_candidate(1, 1000, "kill"),
            make_candidate(2, 1000, "kill"),
        ]);
        // PID 1 not found (confirmed dead), PID 2 still running
        let current = vec![make_proc_with_start_id(
            2,
            1000,
            "cmd2 --flag",
            5,
            ProcessState::Running,
            "boot:5:2",
        )];
        let report = verify_plan(&plan, &current, Utc::now(), Utc::now());
        assert_eq!(report.action_outcomes.len(), 2);
        assert!(matches!(
            report.action_outcomes[0].outcome,
            VerifyOutcome::ConfirmedDead
        ));
        assert!(matches!(
            report.action_outcomes[1].outcome,
            VerifyOutcome::StillRunning
        ));
        assert_eq!(report.verification.overall_status, "partial_success");
    }

    #[test]
    fn verify_plan_resource_summary_tracking() {
        let plan = make_plan(vec![
            make_candidate(1, 1000, "kill"), // 100 MB expected, will be freed
            make_candidate(2, 1000, "kill"), // 100 MB expected, won't be freed
        ]);
        // PID 1 gone (freed), PID 2 still running (not freed)
        let current = vec![make_proc_with_start_id(
            2,
            1000,
            "cmd2 --flag",
            5,
            ProcessState::Running,
            "boot:5:2",
        )];
        let report = verify_plan(&plan, &current, Utc::now(), Utc::now());
        let summary = report.resource_summary.as_ref().unwrap();
        assert!((summary.expected_mb - 200.0).abs() < f64::EPSILON);
        assert!((summary.memory_freed_mb - 100.0).abs() < f64::EPSILON);
        assert!(summary.shortfall_reason.is_some());
    }

    #[test]
    fn verify_plan_resource_summary_all_freed() {
        let plan = make_plan(vec![make_candidate(1, 1000, "kill")]);
        let current: Vec<ProcessRecord> = vec![]; // PID 1 gone
        let report = verify_plan(&plan, &current, Utc::now(), Utc::now());
        let summary = report.resource_summary.as_ref().unwrap();
        assert!((summary.expected_mb - 100.0).abs() < f64::EPSILON);
        assert!((summary.memory_freed_mb - 100.0).abs() < f64::EPSILON);
        assert!(summary.shortfall_reason.is_none());
    }

    #[test]
    fn verify_plan_pause_does_not_count_expected_mb() {
        let plan = make_plan(vec![make_candidate(1, 1000, "pause")]);
        let current = vec![make_proc_with_start_id(
            1,
            1000,
            "cmd1 --flag",
            5,
            ProcessState::Stopped,
            "boot:5:1",
        )];
        let report = verify_plan(&plan, &current, Utc::now(), Utc::now());
        let summary = report.resource_summary.as_ref().unwrap();
        // pause action doesn't add to expected_mb
        assert!((summary.expected_mb - 0.0).abs() < f64::EPSILON);
        assert!((summary.memory_freed_mb - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn verify_plan_resources_freed_on_confirmed_kill() {
        let plan = make_plan(vec![make_candidate(1, 1000, "kill")]);
        let current: Vec<ProcessRecord> = vec![];
        let report = verify_plan(&plan, &current, Utc::now(), Utc::now());
        let outcome = &report.action_outcomes[0];
        let rf = outcome.resources_freed.as_ref().unwrap();
        assert!((rf.memory_mb.unwrap() - 100.0).abs() < f64::EPSILON);
        assert!((rf.cpu_pct.unwrap() - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn verify_plan_no_resources_freed_when_still_running() {
        let plan = make_plan(vec![make_candidate(42, 1000, "kill")]);
        let current = vec![make_proc_with_start_id(
            42,
            1000,
            "cmd42 --flag",
            5,
            ProcessState::Running,
            "boot:5:42",
        )];
        let report = verify_plan(&plan, &current, Utc::now(), Utc::now());
        assert!(report.action_outcomes[0].resources_freed.is_none());
    }

    #[test]
    fn verify_plan_recommendations_for_still_running() {
        let plan = make_plan(vec![make_candidate(42, 1000, "kill")]);
        let current = vec![make_proc_with_start_id(
            42,
            1000,
            "cmd42 --flag",
            5,
            ProcessState::Running,
            "boot:5:42",
        )];
        let report = verify_plan(&plan, &current, Utc::now(), Utc::now());
        let recs = report.recommendations.as_ref().unwrap();
        assert!(recs
            .iter()
            .any(|r| r.contains("PID 42") && r.contains("still active")));
    }

    #[test]
    fn verify_plan_recommendations_for_pid_reused() {
        let plan = AgentPlan {
            session_id: "s".to_string(),
            generated_at: Some("1970-01-01T00:00:10Z".to_string()),
            candidates: vec![PlanCandidate {
                pid: 42,
                uid: 1000,
                cmd_short: "sleep".to_string(),
                cmd_full: "sleep 100".to_string(),
                start_id: Some("boot:5:42".to_string()),
                recommended_action: "kill".to_string(),
                blast_radius: None,
            }],
        };
        let current = vec![make_proc_with_start_id(
            42,
            1000,
            "sleep 100",
            5,
            ProcessState::Running,
            "other:5:42",
        )];
        let report = verify_plan(&plan, &current, Utc::now(), Utc::now());
        let recs = report.recommendations.as_ref().unwrap();
        assert!(recs
            .iter()
            .any(|r| r.contains("PID 42") && r.contains("reused")));
    }

    #[test]
    fn verify_plan_no_recommendations_on_success() {
        let plan = make_plan(vec![make_candidate(1, 1000, "kill")]);
        let current: Vec<ProcessRecord> = vec![];
        let report = verify_plan(&plan, &current, Utc::now(), Utc::now());
        assert!(report.recommendations.is_none());
    }

    #[test]
    fn verify_plan_target_has_cmd_short_and_full() {
        let plan = make_plan(vec![make_candidate(1, 1000, "kill")]);
        let current: Vec<ProcessRecord> = vec![];
        let report = verify_plan(&plan, &current, Utc::now(), Utc::now());
        let target = &report.action_outcomes[0].target;
        assert_eq!(target.pid, 1);
        assert_eq!(target.cmd_short.as_deref(), Some("cmd1"));
        assert_eq!(target.cmd_full.as_deref(), Some("cmd1 --flag"));
        assert_eq!(target.uid, Some(1000));
    }

    #[test]
    fn verify_plan_target_empty_cmd_is_none() {
        let plan = make_plan(vec![PlanCandidate {
            pid: 1,
            uid: 1000,
            cmd_short: "".to_string(),
            cmd_full: "".to_string(),
            start_id: None,
            recommended_action: "kill".to_string(),
            blast_radius: None,
        }]);
        let current: Vec<ProcessRecord> = vec![];
        let report = verify_plan(&plan, &current, Utc::now(), Utc::now());
        let target = &report.action_outcomes[0].target;
        assert!(target.cmd_short.is_none());
        assert!(target.cmd_full.is_none());
    }

    #[test]
    fn verify_plan_session_id_propagated() {
        let plan = AgentPlan {
            session_id: "my-unique-session".to_string(),
            generated_at: None,
            candidates: vec![],
        };
        let report = verify_plan(&plan, &[], Utc::now(), Utc::now());
        assert_eq!(report.session_id, "my-unique-session");
    }

    #[test]
    fn verify_plan_schema_version_set() {
        let plan = make_plan(vec![]);
        let report = verify_plan(&plan, &[], Utc::now(), Utc::now());
        assert_eq!(report.schema_version, pt_common::SCHEMA_VERSION);
    }

    #[test]
    fn verify_plan_verification_window_timestamps() {
        let req = DateTime::parse_from_rfc3339("2026-01-15T10:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let comp = DateTime::parse_from_rfc3339("2026-01-15T10:00:05Z")
            .unwrap()
            .with_timezone(&Utc);
        let plan = make_plan(vec![]);
        let report = verify_plan(&plan, &[], req, comp);
        assert!(report.verification.requested_at.contains("2026-01-15"));
        assert!(report.verification.completed_at.contains("2026-01-15"));
    }

    #[test]
    fn verify_plan_no_blast_radius_zero_memory() {
        let plan = make_plan(vec![PlanCandidate {
            pid: 1,
            uid: 1000,
            cmd_short: "proc".to_string(),
            cmd_full: "proc".to_string(),
            start_id: Some("boot:5:1".to_string()),
            recommended_action: "kill".to_string(),
            blast_radius: None,
        }]);
        let current: Vec<ProcessRecord> = vec![];
        let report = verify_plan(&plan, &current, Utc::now(), Utc::now());
        let summary = report.resource_summary.as_ref().unwrap();
        assert!((summary.expected_mb - 0.0).abs() < f64::EPSILON);
    }

    // ── serialization round-trips ───────────────────────────────────

    #[test]
    fn verification_report_serializes_to_json() {
        let plan = make_plan(vec![make_candidate(1, 1000, "kill")]);
        let current: Vec<ProcessRecord> = vec![];
        let report = verify_plan(&plan, &current, Utc::now(), Utc::now());
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"schema_version\""));
        assert!(json.contains("\"session_id\""));
        assert!(json.contains("\"action_outcomes\""));
        assert!(json.contains("\"confirmed_dead\""));
    }

    #[test]
    fn verification_report_skip_none_fields() {
        let plan = make_plan(vec![make_candidate(1, 1000, "kill")]);
        let current: Vec<ProcessRecord> = vec![];
        let report = verify_plan(&plan, &current, Utc::now(), Utc::now());
        let json = serde_json::to_string(&report).unwrap();
        // No recommendations when all success
        assert!(!json.contains("\"recommendations\""));
        // respawn_detected is None for confirmed dead
        assert!(!json.contains("\"respawn_detected\""));
    }

    #[test]
    fn action_outcome_respawn_detected_serializes() {
        let plan = AgentPlan {
            session_id: "s".to_string(),
            generated_at: Some("1970-01-01T00:00:10Z".to_string()),
            candidates: vec![PlanCandidate {
                pid: 123,
                uid: 1000,
                cmd_short: "node".to_string(),
                cmd_full: "node server".to_string(),
                start_id: Some("123:5".to_string()),
                recommended_action: "kill".to_string(),
                blast_radius: None,
            }],
        };
        let current = vec![make_proc(
            456,
            1000,
            "node server",
            20,
            ProcessState::Running,
        )];
        let report = verify_plan(&plan, &current, Utc::now(), Utc::now());
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"respawn_detected\""));
        assert!(json.contains("\"pid\":456"));
    }

    #[test]
    fn resource_freed_serializes() {
        let rf = ResourceFreed {
            memory_mb: Some(512.3),
            cpu_pct: None,
        };
        let json = serde_json::to_string(&rf).unwrap();
        assert!(json.contains("512.3"));
        assert!(!json.contains("cpu_pct"));
    }

    #[test]
    fn resource_summary_serializes() {
        let rs = ResourceSummary {
            memory_freed_mb: 100.0,
            expected_mb: 200.0,
            shortfall_reason: Some("targets running".to_string()),
        };
        let json = serde_json::to_string(&rs).unwrap();
        assert!(json.contains("100.0"));
        assert!(json.contains("200.0"));
        assert!(json.contains("targets running"));
    }

    #[test]
    fn resource_summary_no_shortfall() {
        let rs = ResourceSummary {
            memory_freed_mb: 100.0,
            expected_mb: 100.0,
            shortfall_reason: None,
        };
        let json = serde_json::to_string(&rs).unwrap();
        assert!(!json.contains("shortfall_reason"));
    }
}
