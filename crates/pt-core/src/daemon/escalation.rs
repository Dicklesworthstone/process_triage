//! Escalation orchestration for daemon trigger responses.
//!
//! When triggers fire, the daemon needs to decide:
//! 1. Is an escalation already in cooldown?
//! 2. Can we acquire the per-user lock (no competing manual/agent run)?
//! 3. If not, defer and write an inbox item instead.
//!
//! This module provides the decision logic and outcome types. Actual
//! lock acquisition and scan execution are injected for testability.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use super::triggers::FiredTrigger;
use crate::collect::tool_runner::{ToolConfig, ToolOutput, ToolRunner, ToolSpec};

/// Each quick/deep planner invocation is bounded, including its output pipes.
/// The CLI's explicit `--timeout` can override this default.
pub const PLAN_TIMEOUT_SECS: u64 = 60;

/// A completed planner response, suitable for publishing a review request.
#[derive(Debug, PartialEq, Eq)]
pub struct DaemonEscalationResult {
    pub session_id: String,
    pub candidates_found: u32,
}

/// Run the real planner without letting a stalled child stop daemon monitoring.
/// Only a complete successful plan may acknowledge a pending pressure episode.
pub fn run_planner(
    spec: &ToolSpec,
    expected_session: Option<&str>,
) -> Result<DaemonEscalationResult, String> {
    let timeout = spec
        .timeout
        .unwrap_or(std::time::Duration::from_secs(PLAN_TIMEOUT_SECS));
    let runner = ToolRunner::new(ToolConfig {
        default_timeout: timeout,
        // The generic collector's five-second cumulative budget is not a
        // planning budget. Retain the full requested deadline for this child.
        budget_ms: u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
        // The daemon already runs at low priority, inherited by the child.
        use_nice: false,
        ..ToolConfig::default()
    });
    let output = runner
        .run(spec)
        .map_err(|error| format!("daemon planner failed: {error}"))?;
    parse_planner_output(&output, expected_session)
}

fn parse_planner_output(
    output: &ToolOutput,
    expected_session: Option<&str>,
) -> Result<DaemonEscalationResult, String> {
    if output.timed_out {
        return Err("daemon planner timed out; the pressure episode remains pending".into());
    }
    if output.truncated {
        return Err("daemon planner output was truncated; no review plan was accepted".into());
    }
    if !matches!(output.exit_code, Some(0 | 1)) {
        let diagnostic: String = output.stderr_str().chars().take(1024).collect();
        return Err(format!(
            "daemon planner exited with {:?}: {}",
            output.exit_code,
            diagnostic.trim()
        ));
    }
    let document: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("invalid daemon planner JSON: {error}"))?;
    if document["command"].as_str() != Some("agent plan")
        || !document["error"].is_null()
        || (!document["status"].is_null() && document["status"].as_str() != Some("ok"))
    {
        return Err("daemon child did not return a successful agent plan".into());
    }
    let plan: crate::plan::Plan = serde_json::from_value(document.clone())
        .map_err(|error| format!("daemon response has no complete saved plan: {error}"))?;
    if pt_common::SessionId::parse(&plan.session_id).is_none()
        || expected_session.is_some_and(|expected| expected != plan.session_id)
    {
        return Err("daemon planner returned an invalid or different session identity".into());
    }
    let candidates = document["candidates"]
        .as_array()
        .ok_or("daemon plan has no candidate inventory")?;
    let candidates_found =
        u32::try_from(candidates.len()).map_err(|_| "daemon candidate count exceeds u32")?;
    let scanned = document["summary"]["total_processes_scanned"]
        .as_u64()
        .ok_or("daemon plan has no process census")?;
    if document["summary"]["candidates_returned"].as_u64() != Some(u64::from(candidates_found))
        || scanned < u64::from(candidates_found)
        || output.exit_code != Some(i32::from(candidates_found > 0))
    {
        return Err("daemon plan has inconsistent candidate counts or exit status".into());
    }
    Ok(DaemonEscalationResult {
        session_id: plan.session_id,
        candidates_found,
    })
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Escalation configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationConfig {
    /// Minimum seconds between escalations (global cooldown).
    pub min_interval_secs: u64,
    /// Whether non-destructive auto-mitigation (pause/throttle) is allowed.
    pub allow_auto_mitigation: bool,
    /// Maximum number of deep scan targets per escalation.
    pub max_deep_scan_targets: u32,
}

impl Default for EscalationConfig {
    fn default() -> Self {
        Self {
            min_interval_secs: 300,
            allow_auto_mitigation: false,
            max_deep_scan_targets: 10,
        }
    }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Escalation outcome status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationStatus {
    /// Escalation ran to completion (scan + plan generated).
    Completed,
    /// Escalation deferred (lock contention, cooldown, etc.).
    Deferred,
    /// Escalation failed (error during scan/plan).
    Failed,
}

/// Reason for deferral.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeferReason {
    /// Another pt run holds the lock.
    LockContention,
    /// Too soon since last escalation.
    Cooldown,
}

/// Result of an escalation attempt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationOutcome {
    pub status: EscalationStatus,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Provenance summary for the escalation scan (when completed).
    ///
    /// Contains aggregate provenance metrics: how many candidates had
    /// provenance evidence, blast-radius distribution, and any evidence
    /// gaps that reduced confidence in the escalation plan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance_summary: Option<EscalationProvenanceSummary>,
}

/// Aggregate provenance summary for a daemon escalation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationProvenanceSummary {
    /// How many candidates had provenance evidence available.
    pub candidates_with_evidence: usize,
    /// How many candidates had no provenance evidence.
    pub candidates_without_evidence: usize,
    /// Blast-radius risk distribution across candidates.
    pub risk_distribution: RiskDistribution,
    /// Whether any candidate was blocked from auto-mitigation due to
    /// high blast radius.
    pub any_blocked_by_blast_radius: bool,
    /// Evidence completeness across all candidates (0.0 to 1.0).
    pub mean_evidence_completeness: f64,
}

/// Distribution of blast-radius risk levels across candidates.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RiskDistribution {
    pub low: usize,
    pub medium: usize,
    pub high: usize,
    pub critical: usize,
    pub unknown: usize,
}

/// State tracking for escalation decisions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationState {
    pub last_escalation_at: Option<String>,
    pub total_escalations: u32,
    pub total_deferrals: u32,
    pub consecutive_deferrals: u32,
}

impl Default for EscalationState {
    fn default() -> Self {
        Self::new()
    }
}

impl EscalationState {
    pub fn new() -> Self {
        Self {
            last_escalation_at: None,
            total_escalations: 0,
            total_deferrals: 0,
            consecutive_deferrals: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Decision logic
// ---------------------------------------------------------------------------

/// Check if escalation should proceed based on cooldown.
pub fn check_cooldown(config: &EscalationConfig, state: &EscalationState) -> Option<DeferReason> {
    if let Some(ref last) = state.last_escalation_at {
        if let Ok(last_dt) = DateTime::parse_from_rfc3339(last) {
            let last_utc = last_dt.with_timezone(&Utc);
            let elapsed = Utc::now().signed_duration_since(last_utc);
            if elapsed < Duration::seconds(config.min_interval_secs as i64) {
                return Some(DeferReason::Cooldown);
            }
        }
    }
    None
}

/// Decide whether to escalate, defer, or skip.
///
/// The `try_lock` callback attempts to acquire the per-user lock.
/// Returns `true` if the lock was acquired, `false` if contended.
pub fn decide_escalation<L>(
    config: &EscalationConfig,
    state: &mut EscalationState,
    _triggers: &[FiredTrigger],
    try_lock: L,
) -> EscalationOutcome
where
    L: FnOnce() -> bool,
{
    // Check cooldown.
    if let Some(reason) = check_cooldown(config, state) {
        state.total_deferrals += 1;
        state.consecutive_deferrals += 1;
        return EscalationOutcome {
            status: EscalationStatus::Deferred,
            reason: format!("{:?}", reason),
            session_id: None,
            provenance_summary: None,
        };
    }

    // Try to acquire lock.
    if !try_lock() {
        state.total_deferrals += 1;
        state.consecutive_deferrals += 1;
        return EscalationOutcome {
            status: EscalationStatus::Deferred,
            reason: format!("{:?}", DeferReason::LockContention),
            session_id: None,
            provenance_summary: None,
        };
    }

    // Lock acquired — escalation proceeds.
    state.last_escalation_at = Some(Utc::now().to_rfc3339());
    state.total_escalations += 1;
    state.consecutive_deferrals = 0;

    EscalationOutcome {
        status: EscalationStatus::Completed,
        reason: "escalation completed".to_string(),
        session_id: None,         // Caller fills in after creating the session.
        provenance_summary: None, // Caller populates after scan completes.
    }
}

/// Build an inbox item summary from fired triggers.
pub fn build_inbox_summary(triggers: &[FiredTrigger]) -> String {
    if triggers.is_empty() {
        return "No triggers fired".to_string();
    }
    let parts: Vec<String> = triggers
        .iter()
        .map(|t| format!("{:?}: {}", t.kind, t.description))
        .collect();
    format!("Daemon triggered escalation: {}", parts.join("; "))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::triggers::TriggerKind;

    fn planner_document(candidate_count: usize) -> serde_json::Value {
        serde_json::json!({
            "command": "agent plan",
            "session_id": "pt-20261112-123456-abcd",
            "plan_id": "daemon-planner-test",
            "generated_at": "2026-11-12T12:34:56Z",
            "policy_id": null,
            "policy_version": "1.0.0",
            "actions": [],
            "pre_toggled": [],
            "gates_summary": {
                "total_candidates": candidate_count,
                "blocked_candidates": 0,
                "pre_toggled_actions": 0,
            },
            "summary": {
                "total_processes_scanned": 42,
                "candidates_returned": candidate_count,
            },
            "candidates": (0..candidate_count)
                .map(|index| serde_json::json!({"pid": index + 100}))
                .collect::<Vec<_>>(),
        })
    }

    fn planner_output(candidate_count: usize) -> ToolOutput {
        ToolOutput {
            command: "pt-core".into(),
            args: Vec::new(),
            stdout: serde_json::to_vec(&planner_document(candidate_count)).unwrap(),
            stderr: Vec::new(),
            exit_code: Some(i32::from(candidate_count > 0)),
            truncated: false,
            duration: std::time::Duration::from_millis(1),
            timed_out: false,
        }
    }

    #[test]
    fn planner_accepts_only_complete_clean_and_candidate_results() {
        for count in [0, 1, 3] {
            let result =
                parse_planner_output(&planner_output(count), Some("pt-20261112-123456-abcd"))
                    .unwrap();
            assert_eq!(result.session_id, "pt-20261112-123456-abcd");
            assert_eq!(result.candidates_found, count as u32);
        }
    }

    #[test]
    fn planner_refuses_failed_incomplete_and_mismatched_responses() {
        for exit_code in [None, Some(2), Some(3), Some(4), Some(6), Some(10), Some(20)] {
            let mut output = planner_output(0);
            output.exit_code = exit_code;
            assert!(parse_planner_output(&output, None).is_err());
        }
        let mut output = planner_output(0);
        output.timed_out = true;
        assert!(parse_planner_output(&output, None)
            .unwrap_err()
            .contains("timed out"));
        output.timed_out = false;
        output.truncated = true;
        assert!(parse_planner_output(&output, None)
            .unwrap_err()
            .contains("truncated"));
        assert!(
            parse_planner_output(&planner_output(0), Some("pt-20261112-123456-efgh"))
                .unwrap_err()
                .contains("session identity")
        );

        for (field, invalid) in [
            ("command", serde_json::json!("agent status")),
            ("session_id", serde_json::json!("../another-session")),
            ("error", serde_json::json!("scan failed")),
            ("status", serde_json::json!("error")),
            ("status", serde_json::json!(7)),
            ("actions", serde_json::Value::Null),
            ("candidates", serde_json::Value::Null),
            ("summary", serde_json::json!({"candidates_returned": 0})),
            (
                "summary",
                serde_json::json!({"total_processes_scanned": 0, "candidates_returned": 1}),
            ),
        ] {
            let mut document = planner_document(0);
            document[field] = invalid;
            let mut output = planner_output(0);
            output.stdout = serde_json::to_vec(&document).unwrap();
            assert!(
                parse_planner_output(&output, None).is_err(),
                "accepted invalid field {field}"
            );
        }
        for (count, exit_code) in [(0, 1), (1, 0)] {
            let mut output = planner_output(count);
            output.exit_code = Some(exit_code);
            assert!(parse_planner_output(&output, None).is_err());
        }
        let output = ToolOutput {
            stdout: br#"{"session_id":"pt-20261112-123456-abcd","status":"error"}"#.to_vec(),
            ..planner_output(0)
        };
        assert!(parse_planner_output(&output, None).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn bounded_planner_runs_real_children_and_rejects_failed_or_stalled_ones() {
        use std::time::{Duration as StdDuration, Instant};
        for (count, exit_code) in [(0, 0), (1, 1), (1, 20)] {
            // JSON is a literal argv value, never interpolated shell source.
            let spec = ToolSpec::new(
                "/bin/sh",
                vec![
                    "-c".into(),
                    "printf '%s' \"$1\"; exit \"$2\"".into(),
                    "daemon-planner-fixture".into(),
                    planner_document(count).to_string(),
                    exit_code.to_string(),
                ],
            )
            .with_timeout(StdDuration::from_secs(5));
            let result = run_planner(&spec, None);
            if exit_code == 20 {
                assert!(result.unwrap_err().contains("Some(20)"));
            } else {
                assert_eq!(result.unwrap().candidates_found, count as u32);
                let truncated = spec.with_max_output(16);
                assert!(run_planner(&truncated, None)
                    .unwrap_err()
                    .contains("truncated"));
            }
        }
        // exec gives the runner direct ownership of this disposable sleeper;
        // timeout cleanup cannot affect another process or leave a shell child.
        let sleeper = ToolSpec::new("/bin/sh", vec!["-c".into(), "exec sleep 30".into()])
            .with_timeout(StdDuration::from_millis(100));
        let started = Instant::now();
        assert!(run_planner(&sleeper, None)
            .unwrap_err()
            .contains("timed out"));
        assert!(started.elapsed() < StdDuration::from_secs(5));
    }

    fn trigger(kind: TriggerKind) -> FiredTrigger {
        FiredTrigger {
            kind,
            description: format!("{:?} fired", kind),
            current_value: Some(10.0),
            ewma_value: Some(8.0),
            threshold: Some(4.0),
            sustained_ticks: 3,
            provenance_context: Vec::new(),
            memory_pressure: None,
            pressure_regime: None,
        }
    }

    #[test]
    fn test_decide_escalation_success() {
        let config = EscalationConfig::default();
        let mut state = EscalationState::new();
        let triggers = vec![trigger(TriggerKind::SustainedLoad)];

        let outcome = decide_escalation(&config, &mut state, &triggers, || true);
        assert_eq!(outcome.status, EscalationStatus::Completed);
        assert_eq!(state.total_escalations, 1);
        assert_eq!(state.consecutive_deferrals, 0);
    }

    #[test]
    fn test_decide_escalation_lock_contention() {
        let config = EscalationConfig::default();
        let mut state = EscalationState::new();
        let triggers = vec![trigger(TriggerKind::SustainedLoad)];

        let outcome = decide_escalation(&config, &mut state, &triggers, || false);
        assert_eq!(outcome.status, EscalationStatus::Deferred);
        assert!(outcome.reason.contains("LockContention"));
        assert_eq!(state.total_deferrals, 1);
    }

    #[test]
    fn test_cooldown_enforcement() {
        let config = EscalationConfig {
            min_interval_secs: 3600, // 1 hour
            ..Default::default()
        };
        let mut state = EscalationState::new();
        let triggers = vec![trigger(TriggerKind::SustainedLoad)];

        // First escalation succeeds.
        let r1 = decide_escalation(&config, &mut state, &triggers, || true);
        assert_eq!(r1.status, EscalationStatus::Completed);

        // Immediately after: cooldown defers.
        let r2 = decide_escalation(&config, &mut state, &triggers, || true);
        assert_eq!(r2.status, EscalationStatus::Deferred);
        assert!(r2.reason.contains("Cooldown"));
    }

    #[test]
    fn test_consecutive_deferrals() {
        let config = EscalationConfig::default();
        let mut state = EscalationState::new();
        let triggers = vec![trigger(TriggerKind::SustainedLoad)];

        // 3 lock contentions.
        for _ in 0..3 {
            decide_escalation(&config, &mut state, &triggers, || false);
        }
        assert_eq!(state.consecutive_deferrals, 3);
        assert_eq!(state.total_deferrals, 3);

        // Success resets consecutive counter.
        decide_escalation(&config, &mut state, &triggers, || true);
        assert_eq!(state.consecutive_deferrals, 0);
        assert_eq!(state.total_deferrals, 3); // Total still 3
    }

    #[test]
    fn test_inbox_summary() {
        let triggers = vec![
            trigger(TriggerKind::SustainedLoad),
            trigger(TriggerKind::MemoryPressure),
        ];
        let summary = build_inbox_summary(&triggers);
        assert!(summary.contains("SustainedLoad"));
        assert!(summary.contains("MemoryPressure"));
    }

    #[test]
    fn test_empty_inbox_summary() {
        let summary = build_inbox_summary(&[]);
        assert_eq!(summary, "No triggers fired");
    }

    #[test]
    fn test_state_serialization() {
        let mut state = EscalationState::new();
        state.total_escalations = 5;
        state.total_deferrals = 2;

        let json = serde_json::to_string(&state).unwrap();
        let restored: EscalationState = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.total_escalations, 5);
    }

    #[test]
    fn test_config_defaults() {
        let config = EscalationConfig::default();
        assert_eq!(config.min_interval_secs, 300);
        assert!(!config.allow_auto_mitigation);
        assert_eq!(config.max_deep_scan_targets, 10);
    }
}
