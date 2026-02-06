//! Pre-execution plan verification library.
//!
//! Provides read-only verification of an action plan against the current
//! system state, reporting staleness without executing anything. This
//! complements `resume.rs` (which verifies *and* executes) by offering a
//! safe, side-effect-free check that agents can run before committing to
//! `pt agent apply`.
//!
//! Key capabilities:
//! - Verify each planned action's process identity still matches.
//! - Detect PID reuse, UID change, process exit.
//! - Produce a structured `VerificationReport` with per-action verdicts.
//! - Compute an overall "plan freshness" score.

use chrono::Utc;
use serde::{Deserialize, Serialize};

use super::resume::{
    revalidate_identity, CurrentIdentity, RevalidationIdentity, RevalidationOutcome,
};
use super::snapshot_persist::{PersistedPlanAction, PlanArtifact};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Verdict for a single planned action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionVerdict {
    /// Identity matches — safe to proceed.
    Valid,
    /// Process no longer exists.
    ProcessGone,
    /// PID reused by a different process.
    PidReused,
    /// UID changed (ownership change).
    UidChanged,
    /// Process exists but is no longer alive (zombie/dead).
    ProcessDead,
}

/// Verification result for a single planned action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionVerification {
    pub pid: u32,
    pub start_id: String,
    pub action: String,
    pub verdict: ActionVerdict,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Overall verification report for a plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    pub session_id: String,
    pub verified_at: String,
    pub total_actions: usize,
    pub valid_count: usize,
    pub gone_count: usize,
    pub reused_count: usize,
    pub uid_changed_count: usize,
    pub dead_count: usize,
    /// Fraction of actions that are still valid (0.0–1.0).
    pub freshness: f64,
    /// `true` if all actions are valid.
    pub plan_is_fresh: bool,
    pub actions: Vec<ActionVerification>,
}

/// Options for plan verification.
#[derive(Debug, Clone)]
pub struct VerifyOptions {
    /// UID to assume for planned actions (from the original scan context).
    pub default_uid: u32,
}

// ---------------------------------------------------------------------------
// Core verification
// ---------------------------------------------------------------------------

/// Verify a persisted plan against current system state.
///
/// The `lookup_fn` retrieves the current identity for a PID (or `None` if
/// the process no longer exists). This is the same callback shape used by
/// `resume::resume_plan`, enabling consistent identity checks.
pub fn verify_plan<L>(
    session_id: &str,
    plan: &PlanArtifact,
    options: &VerifyOptions,
    lookup_fn: L,
) -> VerificationReport
where
    L: Fn(u32) -> Option<CurrentIdentity>,
{
    let mut actions = Vec::with_capacity(plan.actions.len());
    let mut valid = 0usize;
    let mut gone = 0usize;
    let mut reused = 0usize;
    let mut uid_changed = 0usize;
    let mut dead = 0usize;

    for pa in &plan.actions {
        let planned_id = RevalidationIdentity {
            pid: pa.pid,
            start_id: pa.start_id.clone(),
            uid: options.default_uid,
        };

        let current = lookup_fn(pa.pid);
        let (verdict, detail) = classify(&planned_id, current.as_ref());

        match verdict {
            ActionVerdict::Valid => valid += 1,
            ActionVerdict::ProcessGone => gone += 1,
            ActionVerdict::PidReused => reused += 1,
            ActionVerdict::UidChanged => uid_changed += 1,
            ActionVerdict::ProcessDead => dead += 1,
        }

        actions.push(ActionVerification {
            pid: pa.pid,
            start_id: pa.start_id.clone(),
            action: pa.action.clone(),
            verdict,
            detail,
        });
    }

    let total = plan.actions.len();
    let freshness = if total == 0 {
        1.0
    } else {
        valid as f64 / total as f64
    };

    VerificationReport {
        session_id: session_id.to_string(),
        verified_at: Utc::now().to_rfc3339(),
        total_actions: total,
        valid_count: valid,
        gone_count: gone,
        reused_count: reused,
        uid_changed_count: uid_changed,
        dead_count: dead,
        freshness,
        plan_is_fresh: valid == total,
        actions,
    }
}

/// Verify a plan from raw action data (not from a `PlanArtifact`).
pub fn verify_actions<L>(
    session_id: &str,
    actions: &[(u32, String, String)], // (pid, start_id, action)
    default_uid: u32,
    lookup_fn: L,
) -> VerificationReport
where
    L: Fn(u32) -> Option<CurrentIdentity>,
{
    let persisted: Vec<PersistedPlanAction> = actions
        .iter()
        .map(|(pid, start_id, action)| PersistedPlanAction {
            pid: *pid,
            start_id: start_id.clone(),
            action: action.clone(),
            expected_loss: 0.0,
            rationale: String::new(),
        })
        .collect();

    let artifact = PlanArtifact {
        action_count: persisted.len(),
        kill_count: persisted.iter().filter(|a| a.action == "kill").count(),
        review_count: persisted.iter().filter(|a| a.action == "review").count(),
        spare_count: persisted.iter().filter(|a| a.action == "spare").count(),
        actions: persisted,
    };

    let options = VerifyOptions { default_uid };
    verify_plan(session_id, &artifact, &options, lookup_fn)
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

fn classify(
    planned: &RevalidationIdentity,
    current: Option<&CurrentIdentity>,
) -> (ActionVerdict, Option<String>) {
    let result = revalidate_identity(planned, current);

    if result.valid {
        return (ActionVerdict::Valid, None);
    }

    match result.reason {
        RevalidationOutcome::ProcessGone => {
            // Distinguish "truly gone" vs "exists but dead".
            if let Some(cur) = current {
                if !cur.alive {
                    return (
                        ActionVerdict::ProcessDead,
                        Some(format!("PID {} exists but is no longer alive", planned.pid)),
                    );
                }
            }
            (
                ActionVerdict::ProcessGone,
                Some(format!("PID {} no longer exists", planned.pid)),
            )
        }
        RevalidationOutcome::PidReused => {
            let new_start = current.map(|c| c.start_id.as_str()).unwrap_or("unknown");
            (
                ActionVerdict::PidReused,
                Some(format!(
                    "PID {} reused: expected start_id={}, found={}",
                    planned.pid, planned.start_id, new_start
                )),
            )
        }
        RevalidationOutcome::UidChanged => {
            let new_uid = current.map(|c| c.uid).unwrap_or(0);
            (
                ActionVerdict::UidChanged,
                Some(format!(
                    "PID {} UID changed: expected={}, found={}",
                    planned.pid, planned.uid, new_uid
                )),
            )
        }
        RevalidationOutcome::Match => {
            // Shouldn't reach here since result.valid was false, but handle gracefully.
            (ActionVerdict::Valid, None)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_plan(pids: &[u32]) -> PlanArtifact {
        let actions: Vec<PersistedPlanAction> = pids
            .iter()
            .map(|&pid| PersistedPlanAction {
                pid,
                start_id: format!("boot1:{}:{}", pid * 100, pid),
                action: "kill".to_string(),
                expected_loss: 0.1,
                rationale: "test".to_string(),
            })
            .collect();
        PlanArtifact {
            action_count: actions.len(),
            kill_count: actions.len(),
            review_count: 0,
            spare_count: 0,
            actions,
        }
    }

    fn alive(pid: u32) -> CurrentIdentity {
        CurrentIdentity {
            pid,
            start_id: format!("boot1:{}:{}", pid * 100, pid),
            uid: 1000,
            alive: true,
        }
    }

    fn opts() -> VerifyOptions {
        VerifyOptions { default_uid: 1000 }
    }

    #[test]
    fn test_all_valid() {
        let plan = make_plan(&[1, 2, 3]);
        let report = verify_plan("s1", &plan, &opts(), |pid| Some(alive(pid)));

        assert_eq!(report.total_actions, 3);
        assert_eq!(report.valid_count, 3);
        assert!(report.plan_is_fresh);
        assert!((report.freshness - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_process_gone() {
        let plan = make_plan(&[1, 2]);
        let report = verify_plan("s2", &plan, &opts(), |pid| {
            if pid == 2 {
                None
            } else {
                Some(alive(pid))
            }
        });

        assert_eq!(report.valid_count, 1);
        assert_eq!(report.gone_count, 1);
        assert!(!report.plan_is_fresh);
        assert!((report.freshness - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_pid_reused() {
        let plan = make_plan(&[1, 2]);
        let report = verify_plan("s3", &plan, &opts(), |pid| {
            if pid == 2 {
                Some(CurrentIdentity {
                    pid: 2,
                    start_id: "boot2:999:2".to_string(),
                    uid: 1000,
                    alive: true,
                })
            } else {
                Some(alive(pid))
            }
        });

        assert_eq!(report.valid_count, 1);
        assert_eq!(report.reused_count, 1);
        let reused_action = report.actions.iter().find(|a| a.pid == 2).unwrap();
        assert_eq!(reused_action.verdict, ActionVerdict::PidReused);
        assert!(reused_action.detail.as_ref().unwrap().contains("reused"));
    }

    #[test]
    fn test_uid_changed() {
        let plan = make_plan(&[1]);
        let report = verify_plan("s4", &plan, &opts(), |_pid| {
            Some(CurrentIdentity {
                pid: 1,
                start_id: "boot1:100:1".to_string(),
                uid: 0, // Changed to root
                alive: true,
            })
        });

        assert_eq!(report.uid_changed_count, 1);
        assert_eq!(report.valid_count, 0);
    }

    #[test]
    fn test_process_dead() {
        let plan = make_plan(&[1]);
        let report = verify_plan("s5", &plan, &opts(), |_pid| {
            Some(CurrentIdentity {
                pid: 1,
                start_id: "boot1:100:1".to_string(),
                uid: 1000,
                alive: false,
            })
        });

        assert_eq!(report.dead_count, 1);
        assert_eq!(report.valid_count, 0);
    }

    #[test]
    fn test_mixed_verdicts() {
        let plan = make_plan(&[1, 2, 3, 4, 5]);
        let report = verify_plan("s6", &plan, &opts(), |pid| match pid {
            1 => Some(alive(1)), // Valid
            2 => None,           // Gone
            3 => Some(CurrentIdentity {
                // PID reused
                pid: 3,
                start_id: "different:0:3".to_string(),
                uid: 1000,
                alive: true,
            }),
            4 => Some(CurrentIdentity {
                // UID changed
                pid: 4,
                start_id: "boot1:400:4".to_string(),
                uid: 0,
                alive: true,
            }),
            5 => Some(CurrentIdentity {
                // Dead
                pid: 5,
                start_id: "boot1:500:5".to_string(),
                uid: 1000,
                alive: false,
            }),
            _ => None,
        });

        assert_eq!(report.valid_count, 1);
        assert_eq!(report.gone_count, 1);
        assert_eq!(report.reused_count, 1);
        assert_eq!(report.uid_changed_count, 1);
        assert_eq!(report.dead_count, 1);
        assert!((report.freshness - 0.2).abs() < f64::EPSILON);
        assert!(!report.plan_is_fresh);
    }

    #[test]
    fn test_empty_plan() {
        let plan = make_plan(&[]);
        let report = verify_plan("s7", &plan, &opts(), |_| None);

        assert_eq!(report.total_actions, 0);
        assert!(report.plan_is_fresh);
        assert!((report.freshness - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_verify_actions_shorthand() {
        let actions = vec![
            (1u32, "boot1:100:1".to_string(), "kill".to_string()),
            (2u32, "boot1:200:2".to_string(), "kill".to_string()),
        ];
        let report = verify_actions("s8", &actions, 1000, |pid| Some(alive(pid)));

        assert_eq!(report.total_actions, 2);
        assert_eq!(report.valid_count, 2);
        assert!(report.plan_is_fresh);
    }

    #[test]
    fn test_report_serialization() {
        let plan = make_plan(&[1]);
        let report = verify_plan("s9", &plan, &opts(), |pid| Some(alive(pid)));

        let json = serde_json::to_string_pretty(&report).unwrap();
        let restored: VerificationReport = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.session_id, "s9");
        assert_eq!(restored.valid_count, 1);
        assert!(restored.plan_is_fresh);
    }
}
