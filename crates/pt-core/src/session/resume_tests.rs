//! Integration-style tests for session resumability.
//!
//! Tests the full resume workflow: serialization, deserialization, state
//! validation, PID reuse detection, corrupted state handling, and
//! cross-version compatibility.

#[cfg(test)]
mod tests {
    use crate::session::resume::*;
    use crate::session::snapshot_persist::*;
    use tempfile::TempDir;

    // -- Helpers --

    fn planned(pid: u32, action: &str) -> PlannedAction {
        PlannedAction {
            identity: RevalidationIdentity {
                pid,
                start_id: format!("boot1:{}:{}", pid * 100, pid),
                uid: 1000,
            },
            action: action.to_string(),
            expected_loss: 0.1,
            rationale: "test rationale".to_string(),
        }
    }

    fn alive_identity(pid: u32) -> CurrentIdentity {
        CurrentIdentity {
            pid,
            start_id: format!("boot1:{}:{}", pid * 100, pid),
            uid: 1000,
            alive: true,
        }
    }

    // -- Scenario: Clean resume (all PIDs still exist) --

    #[test]
    fn scenario_clean_resume() {
        let actions = vec![planned(1, "kill"), planned(2, "kill"), planned(3, "pause")];
        let mut plan = ExecutionPlan::new("session-1", actions);

        let result = resume_plan(
            &mut plan,
            |pid| Some(alive_identity(pid)),
            |_| Ok(()),
        );

        assert_eq!(result.newly_applied, 3);
        assert_eq!(result.previously_applied, 0);
        assert_eq!(result.skipped_identity_mismatch, 0);
        assert_eq!(result.skipped_process_gone, 0);
        assert_eq!(result.failed, 0);
        assert!(plan.is_complete());
    }

    // -- Scenario: PID reuse detected --

    #[test]
    fn scenario_pid_reuse_detected() {
        let actions = vec![planned(1, "kill"), planned(2, "kill")];
        let mut plan = ExecutionPlan::new("session-2", actions);

        // PID 2 has been reused by a different process (different start_id).
        let result = resume_plan(
            &mut plan,
            |pid| {
                if pid == 2 {
                    Some(CurrentIdentity {
                        pid: 2,
                        start_id: "boot2:999:2".to_string(), // Different!
                        uid: 1000,
                        alive: true,
                    })
                } else {
                    Some(alive_identity(pid))
                }
            },
            |_| Ok(()),
        );

        assert_eq!(result.newly_applied, 1); // PID 1 applied
        assert_eq!(result.skipped_identity_mismatch, 1); // PID 2 rejected

        // Verify the mismatch entry.
        let mismatch = result
            .entries
            .iter()
            .find(|e| e.identity.pid == 2)
            .unwrap();
        assert_eq!(mismatch.status, ExecutionStatus::IdentityMismatch);
    }

    // -- Scenario: Process exited (no longer exists) --

    #[test]
    fn scenario_process_exited() {
        let actions = vec![planned(1, "kill"), planned(2, "kill")];
        let mut plan = ExecutionPlan::new("session-3", actions);

        // PID 2 no longer exists.
        let result = resume_plan(
            &mut plan,
            |pid| {
                if pid == 2 {
                    None // Process gone
                } else {
                    Some(alive_identity(pid))
                }
            },
            |_| Ok(()),
        );

        assert_eq!(result.newly_applied, 1);
        assert_eq!(result.skipped_process_gone, 1);

        let gone = result
            .entries
            .iter()
            .find(|e| e.identity.pid == 2)
            .unwrap();
        assert_eq!(gone.status, ExecutionStatus::Skipped);
    }

    // -- Scenario: Partial execution then resume --

    #[test]
    fn scenario_partial_then_resume() {
        let actions = vec![planned(1, "kill"), planned(2, "kill"), planned(3, "kill")];
        let mut plan = ExecutionPlan::new("session-4", actions);

        // First run: execute 1 and 2, fail on 3.
        let r1 = resume_plan(
            &mut plan,
            |pid| Some(alive_identity(pid)),
            |a| {
                if a.identity.pid == 3 {
                    Err("permission denied".to_string())
                } else {
                    Ok(())
                }
            },
        );
        assert_eq!(r1.newly_applied, 2);
        assert_eq!(r1.failed, 1);
        assert!(!plan.is_complete()); // PID 3 failed, still pending

        // Second run: retry, now PID 3 succeeds.
        let r2 = resume_plan(
            &mut plan,
            |pid| Some(alive_identity(pid)),
            |_| Ok(()),
        );
        assert_eq!(r2.previously_applied, 2);
        assert_eq!(r2.newly_applied, 1);
        assert!(plan.is_complete());
    }

    // -- Scenario: Idempotent resume (nothing to do) --

    #[test]
    fn scenario_idempotent_resume() {
        let actions = vec![planned(1, "kill")];
        let mut plan = ExecutionPlan::new("session-5", actions);

        resume_plan(
            &mut plan,
            |pid| Some(alive_identity(pid)),
            |_| Ok(()),
        );
        assert!(plan.is_complete());

        // Resume again: nothing should happen.
        let r2 = resume_plan(
            &mut plan,
            |pid| Some(alive_identity(pid)),
            |_| panic!("should not execute anything"),
        );
        assert_eq!(r2.previously_applied, 1);
        assert_eq!(r2.newly_applied, 0);
    }

    // -- Scenario: UID changed (ownership change) --

    #[test]
    fn scenario_uid_changed() {
        let actions = vec![planned(1, "kill")];
        let mut plan = ExecutionPlan::new("session-6", actions);

        let result = resume_plan(
            &mut plan,
            |_pid| {
                Some(CurrentIdentity {
                    pid: 1,
                    start_id: "boot1:100:1".to_string(),
                    uid: 0, // Changed to root!
                    alive: true,
                })
            },
            |_| Ok(()),
        );

        assert_eq!(result.skipped_identity_mismatch, 1);
        assert_eq!(result.newly_applied, 0);
    }

    // -- Scenario: Plan serialization roundtrip --

    #[test]
    fn scenario_plan_serialization() {
        let actions = vec![planned(1, "kill"), planned(2, "pause")];
        let mut plan = ExecutionPlan::new("session-7", actions);

        // Execute first action.
        plan.record(ExecutionEntry {
            identity: RevalidationIdentity {
                pid: 1,
                start_id: "boot1:100:1".to_string(),
                uid: 1000,
            },
            action: "kill".to_string(),
            status: ExecutionStatus::Applied,
            timestamp: "2026-01-15T10:00:00Z".to_string(),
            error: None,
        });

        // Serialize and deserialize.
        let json = serde_json::to_string_pretty(&plan).unwrap();
        let restored: ExecutionPlan = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.session_id, "session-7");
        assert_eq!(restored.actions.len(), 2);
        assert_eq!(restored.log.len(), 1);
        assert_eq!(restored.applied_set().len(), 1);
        assert_eq!(restored.pending_actions().len(), 1);
        assert_eq!(restored.pending_actions()[0].identity.pid, 2);
    }

    // -- Scenario: Corrupted plan JSON --

    #[test]
    fn scenario_corrupted_state() {
        let bad_json = r#"{ "session_id": "x", "actions": [ }"#;
        let result: Result<ExecutionPlan, _> = serde_json::from_str(bad_json);
        assert!(result.is_err(), "Should reject malformed JSON");
    }

    // -- Scenario: Dead process (alive=false) --

    #[test]
    fn scenario_dead_process() {
        let actions = vec![planned(1, "kill")];
        let mut plan = ExecutionPlan::new("session-8", actions);

        let result = resume_plan(
            &mut plan,
            |_pid| {
                Some(CurrentIdentity {
                    pid: 1,
                    start_id: "boot1:100:1".to_string(),
                    uid: 1000,
                    alive: false,
                })
            },
            |_| Ok(()),
        );

        assert_eq!(result.skipped_process_gone, 1);
        assert_eq!(result.newly_applied, 0);
    }

    // -- Scenario: Mixed outcomes --

    #[test]
    fn scenario_mixed_outcomes() {
        let actions = vec![
            planned(1, "kill"),  // Will succeed
            planned(2, "kill"),  // PID reused
            planned(3, "kill"),  // Process gone
            planned(4, "kill"),  // Will fail
            planned(5, "kill"),  // Will succeed
        ];
        let mut plan = ExecutionPlan::new("session-9", actions);

        let result = resume_plan(
            &mut plan,
            |pid| match pid {
                1 | 4 | 5 => Some(alive_identity(pid)),
                2 => Some(CurrentIdentity {
                    pid: 2,
                    start_id: "reused:0:2".to_string(),
                    uid: 1000,
                    alive: true,
                }),
                3 => None,
                _ => None,
            },
            |a| {
                if a.identity.pid == 4 {
                    Err("signal failed".to_string())
                } else {
                    Ok(())
                }
            },
        );

        assert_eq!(result.newly_applied, 2);       // PIDs 1, 5
        assert_eq!(result.skipped_identity_mismatch, 1); // PID 2
        assert_eq!(result.skipped_process_gone, 1);       // PID 3
        assert_eq!(result.failed, 1);                     // PID 4
    }

    // -- Scenario: Snapshot artifact persistence + resume --

    #[test]
    fn scenario_persist_plan_then_resume() {
        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("pt-20260201-120000-test");
        std::fs::create_dir_all(dir.join("decision")).unwrap();

        let handle = crate::session::SessionHandle {
            id: pt_common::SessionId("pt-20260201-120000-test".to_string()),
            dir,
        };

        // Persist a plan artifact.
        let plan_artifact = PlanArtifact {
            action_count: 2,
            kill_count: 2,
            review_count: 0,
            spare_count: 0,
            actions: vec![
                PersistedPlanAction {
                    pid: 1,
                    start_id: "boot1:100:1".to_string(),
                    action: "kill".to_string(),
                    expected_loss: 0.1,
                    rationale: "abandoned".to_string(),
                },
                PersistedPlanAction {
                    pid: 2,
                    start_id: "boot1:200:2".to_string(),
                    action: "kill".to_string(),
                    expected_loss: 0.15,
                    rationale: "zombie".to_string(),
                },
            ],
        };

        persist_plan(&handle, "s-test", "h1", plan_artifact).unwrap();

        // Load and convert to ExecutionPlan.
        let loaded = load_plan(&handle).unwrap();
        let exec_actions: Vec<PlannedAction> = loaded
            .payload
            .actions
            .iter()
            .map(|a| PlannedAction {
                identity: RevalidationIdentity {
                    pid: a.pid,
                    start_id: a.start_id.clone(),
                    uid: 1000,
                },
                action: a.action.clone(),
                expected_loss: a.expected_loss,
                rationale: a.rationale.clone(),
            })
            .collect();

        let mut exec_plan = ExecutionPlan::new("s-test", exec_actions);
        assert_eq!(exec_plan.pending_actions().len(), 2);

        // Resume with matching identities.
        let result = resume_plan(
            &mut exec_plan,
            |pid| {
                Some(CurrentIdentity {
                    pid,
                    start_id: format!("boot1:{}:{}", pid * 100, pid),
                    uid: 1000,
                    alive: true,
                })
            },
            |_| Ok(()),
        );

        assert_eq!(result.newly_applied, 2);
        assert!(exec_plan.is_complete());
    }
}
