//! Integration-style tests for the differential session workflow.
//!
//! Tests the full pipeline: snapshot persistence → diff → comparison reports,
//! exercising scenarios from the test plan: no changes, new stuck processes,
//! recovery, PID reuse, worsening over time, and mixed deltas.

#[cfg(test)]
mod tests {
    use crate::session::compare::*;
    use crate::session::diff::*;
    use crate::session::snapshot_persist::*;

    // -- Helpers --

    fn proc(pid: u32, start_id: &str, comm: &str, cmd: &str, elapsed: u64) -> PersistedProcess {
        PersistedProcess {
            pid,
            ppid: 1,
            uid: 1000,
            start_id: start_id.to_string(),
            comm: comm.to_string(),
            cmd: cmd.to_string(),
            state: "S".to_string(),
            start_time_unix: 1700000000,
            elapsed_secs: elapsed,
            identity_quality: "Full".to_string(),
        }
    }

    fn inf(
        pid: u32,
        start_id: &str,
        class: &str,
        score: u32,
        action: &str,
        p_abandoned: f64,
    ) -> PersistedInference {
        PersistedInference {
            pid,
            start_id: start_id.to_string(),
            classification: class.to_string(),
            posterior_useful: 1.0 - p_abandoned - 0.05,
            posterior_useful_bad: 0.03,
            posterior_abandoned: p_abandoned,
            posterior_zombie: 0.02,
            confidence: if score > 70 { "high" } else { "medium" }.to_string(),
            recommended_action: action.to_string(),
            score,
        }
    }

    // -- Scenario: No changes --

    #[test]
    fn scenario_no_changes() {
        let procs = vec![
            proc(100, "b1:100:100", "node", "node server.js", 3600),
            proc(200, "b1:200:200", "python", "python app.py", 7200),
        ];
        let infs = vec![
            inf(100, "b1:100:100", "useful", 15, "keep", 0.05),
            inf(200, "b1:200:200", "useful", 20, "keep", 0.08),
        ];

        let diff = compute_diff("s1", "s2", &procs, &infs, &procs, &infs, &DiffConfig::default());
        assert_eq!(diff.summary.new_count, 0);
        assert_eq!(diff.summary.resolved_count, 0);
        assert_eq!(diff.summary.changed_count, 0);
        assert_eq!(diff.summary.unchanged_count, 2);

        let report = generate_comparison_report(&diff, &infs, &infs);
        assert_eq!(report.drift_summary.overall_trend, TrendDirection::Stable);
        assert!(report.recurring_offenders.is_empty());
    }

    // -- Scenario: New stuck test process --

    #[test]
    fn scenario_new_stuck_test() {
        let old_procs = vec![proc(100, "b1:100:100", "node", "node server.js", 3600)];
        let old_infs = vec![inf(100, "b1:100:100", "useful", 15, "keep", 0.05)];

        let new_procs = vec![
            proc(100, "b1:100:100", "node", "node server.js", 4500),
            proc(300, "b1:300:300", "npm", "npm test", 1800), // New, stuck
        ];
        let new_infs = vec![
            inf(100, "b1:100:100", "useful", 15, "keep", 0.05),
            inf(300, "b1:300:300", "abandoned", 72, "kill", 0.85),
        ];

        let diff = compute_diff(
            "s1", "s2", &old_procs, &old_infs, &new_procs, &new_infs, &DiffConfig::default(),
        );
        assert_eq!(diff.summary.new_count, 1);
        let new_entry = diff.deltas.iter().find(|d| d.kind == DeltaKind::New).unwrap();
        assert_eq!(new_entry.pid, 300);
        assert!(new_entry.new_inference.is_some());
        assert_eq!(new_entry.new_inference.as_ref().unwrap().classification, "abandoned");
    }

    // -- Scenario: Recovery (previously flagged process recovers) --

    #[test]
    fn scenario_recovery() {
        let procs = vec![proc(100, "b1:100:100", "node", "node server.js", 3600)];
        let old_infs = vec![inf(100, "b1:100:100", "abandoned", 75, "kill", 0.85)];
        let new_infs = vec![inf(100, "b1:100:100", "useful", 20, "keep", 0.08)];

        let diff = compute_diff(
            "s1", "s2", &procs, &old_infs, &procs, &new_infs, &DiffConfig::default(),
        );
        assert_eq!(diff.summary.changed_count, 1);
        let changed = diff.deltas.iter().find(|d| d.kind == DeltaKind::Changed).unwrap();
        assert!(changed.improved);
        assert!(!changed.worsened);
        assert!(changed.classification_changed);

        let report = generate_comparison_report(&diff, &old_infs, &new_infs);
        assert_eq!(report.drift_summary.improved_count, 1);
        assert_eq!(report.drift_summary.overall_trend, TrendDirection::Decreasing);
    }

    // -- Scenario: PID reuse after reboot --

    #[test]
    fn scenario_pid_reuse() {
        let old_procs = vec![proc(100, "boot1:100:100", "npm", "npm test", 86400)];
        let old_infs = vec![inf(100, "boot1:100:100", "abandoned", 90, "kill", 0.95)];

        // Same PID but different start_id after reboot.
        let new_procs = vec![proc(100, "boot2:100:100", "nginx", "nginx -g daemon off", 60)];
        let new_infs = vec![inf(100, "boot2:100:100", "useful", 5, "keep", 0.02)];

        let diff = compute_diff(
            "s1", "s2", &old_procs, &old_infs, &new_procs, &new_infs, &DiffConfig::default(),
        );
        // Should treat as different processes: one resolved, one new.
        assert_eq!(diff.summary.resolved_count, 1);
        assert_eq!(diff.summary.new_count, 1);
        assert_eq!(diff.summary.changed_count, 0);
    }

    // -- Scenario: Worsening over time --

    #[test]
    fn scenario_worsening() {
        let procs = vec![
            proc(100, "b1:100:100", "jest", "jest --watchAll", 3600),
            proc(200, "b1:200:200", "webpack", "webpack --watch", 7200),
        ];
        let old_infs = vec![
            inf(100, "b1:100:100", "useful_bad", 45, "review", 0.3),
            inf(200, "b1:200:200", "useful", 25, "keep", 0.1),
        ];
        let new_infs = vec![
            inf(100, "b1:100:100", "abandoned", 82, "kill", 0.88),
            inf(200, "b1:200:200", "abandoned", 70, "kill", 0.75),
        ];

        let diff = compute_diff(
            "s1", "s2", &procs, &old_infs, &procs, &new_infs, &DiffConfig::default(),
        );
        assert_eq!(diff.summary.changed_count, 2);
        assert!(diff.deltas.iter().all(|d| d.worsened));

        let report = generate_comparison_report(&diff, &old_infs, &new_infs);
        assert_eq!(report.drift_summary.worsened_count, 2);
        assert_eq!(report.drift_summary.overall_trend, TrendDirection::Increasing);
        // Both should be recurring offenders since they went from review/keep to kill.
        assert_eq!(report.recurring_offenders.len(), 2);
    }

    // -- Scenario: Mixed delta (some new, some resolved, some changed, some unchanged) --

    #[test]
    fn scenario_mixed_delta() {
        let old_procs = vec![
            proc(1, "a:1:1", "srv1", "srv1", 1000),    // Will be unchanged
            proc(2, "a:2:2", "srv2", "srv2", 2000),    // Will be resolved
            proc(3, "a:3:3", "test", "test", 3000),    // Will worsen
        ];
        let old_infs = vec![
            inf(1, "a:1:1", "useful", 10, "keep", 0.05),
            inf(2, "a:2:2", "useful", 15, "keep", 0.08),
            inf(3, "a:3:3", "useful_bad", 40, "review", 0.3),
        ];

        let new_procs = vec![
            proc(1, "a:1:1", "srv1", "srv1", 1900),    // Unchanged
            proc(3, "a:3:3", "test", "test", 3900),    // Worsened
            proc(4, "a:4:4", "new_srv", "new_srv", 100), // New
        ];
        let new_infs = vec![
            inf(1, "a:1:1", "useful", 12, "keep", 0.06),
            inf(3, "a:3:3", "abandoned", 85, "kill", 0.9),
            inf(4, "a:4:4", "useful", 8, "keep", 0.03),
        ];

        let diff = compute_diff(
            "s1", "s2", &old_procs, &old_infs, &new_procs, &new_infs, &DiffConfig::default(),
        );
        assert_eq!(diff.summary.new_count, 1);
        assert_eq!(diff.summary.resolved_count, 1);
        assert_eq!(diff.summary.changed_count, 1);
        assert_eq!(diff.summary.unchanged_count, 1);

        // Verify ordering: new → changed → unchanged → resolved
        assert_eq!(diff.deltas[0].kind, DeltaKind::New);
        assert_eq!(diff.deltas[1].kind, DeltaKind::Changed);
        assert_eq!(diff.deltas[2].kind, DeltaKind::Unchanged);
        assert_eq!(diff.deltas[3].kind, DeltaKind::Resolved);

        let report = generate_comparison_report(&diff, &old_infs, &new_infs);
        assert_eq!(report.recurring_offenders.len(), 1);
        assert_eq!(report.recurring_offenders[0].pid, 3);
    }

    // -- Scenario: Large-scale diff performance --

    #[test]
    fn scenario_large_scale() {
        // 1000 processes, 10% change rate.
        let old_procs: Vec<_> = (0..1000)
            .map(|i| proc(i, &format!("b1:{}:{}", i, i), "srv", "srv", 1000))
            .collect();
        let old_infs: Vec<_> = (0..1000)
            .map(|i| inf(i, &format!("b1:{}:{}", i, i), "useful", 10 + (i % 30) as u32, "keep", 0.05))
            .collect();

        // 900 unchanged, 50 resolved (950-999), 50 new (1000-1049)
        let mut new_procs: Vec<_> = (0..950)
            .map(|i| proc(i, &format!("b1:{}:{}", i, i), "srv", "srv", 2000))
            .collect();
        for i in 1000..1050 {
            new_procs.push(proc(i, &format!("b1:{}:{}", i, i), "new", "new", 100));
        }
        let mut new_infs: Vec<_> = (0..950)
            .map(|i| inf(i, &format!("b1:{}:{}", i, i), "useful", 10 + (i % 30) as u32, "keep", 0.05))
            .collect();
        for i in 1000..1050 {
            new_infs.push(inf(i, &format!("b1:{}:{}", i, i), "useful", 15, "keep", 0.05));
        }

        let diff = compute_diff(
            "s1", "s2", &old_procs, &old_infs, &new_procs, &new_infs, &DiffConfig::default(),
        );
        assert_eq!(diff.summary.new_count, 50);
        assert_eq!(diff.summary.resolved_count, 50);
        assert_eq!(diff.summary.total_old, 1000);
        assert_eq!(diff.summary.total_new, 1000);
    }

    // -- Scenario: Symmetry property (diff(A,A) = empty) --

    #[test]
    fn property_symmetry_self_diff() {
        let procs = vec![
            proc(1, "a", "srv1", "srv1", 100),
            proc(2, "b", "srv2", "srv2", 200),
            proc(3, "c", "srv3", "srv3", 300),
        ];
        let infs = vec![
            inf(1, "a", "useful", 10, "keep", 0.05),
            inf(2, "b", "abandoned", 80, "kill", 0.9),
            inf(3, "c", "useful_bad", 50, "review", 0.4),
        ];

        let diff = compute_diff("s1", "s1", &procs, &infs, &procs, &infs, &DiffConfig::default());
        assert_eq!(diff.summary.new_count, 0);
        assert_eq!(diff.summary.resolved_count, 0);
        assert_eq!(diff.summary.changed_count, 0);
        assert_eq!(diff.summary.unchanged_count, 3);
    }

    // -- Scenario: Snapshot persistence roundtrip + diff --

    #[test]
    fn scenario_persist_and_diff() {
        use tempfile::TempDir;

        let tmp = TempDir::new().unwrap();
        let dir_a = tmp.path().join("session-a");
        let dir_b = tmp.path().join("session-b");
        for d in [&dir_a, &dir_b] {
            std::fs::create_dir_all(d.join("scan")).unwrap();
            std::fs::create_dir_all(d.join("inference")).unwrap();
        }

        let handle_a = crate::session::SessionHandle {
            id: pt_common::SessionId("pt-20260201-100000-aaaa".to_string()),
            dir: dir_a,
        };
        let handle_b = crate::session::SessionHandle {
            id: pt_common::SessionId("pt-20260201-110000-bbbb".to_string()),
            dir: dir_b,
        };

        // Persist session A
        let inv_a = InventoryArtifact {
            total_system_processes: 100,
            protected_filtered: 10,
            record_count: 2,
            records: vec![
                PersistedProcess {
                    pid: 1,
                    ppid: 0,
                    uid: 1000,
                    start_id: "b1:1:1".to_string(),
                    comm: "srv".to_string(),
                    cmd: "srv".to_string(),
                    state: "S".to_string(),
                    start_time_unix: 1700000000,
                    elapsed_secs: 100,
                    identity_quality: "Full".to_string(),
                },
                PersistedProcess {
                    pid: 2,
                    ppid: 0,
                    uid: 1000,
                    start_id: "b1:2:2".to_string(),
                    comm: "old".to_string(),
                    cmd: "old".to_string(),
                    state: "S".to_string(),
                    start_time_unix: 1700000000,
                    elapsed_secs: 200,
                    identity_quality: "Full".to_string(),
                },
            ],
        };
        let inf_a = InferenceArtifact {
            candidate_count: 2,
            candidates: vec![
                PersistedInference {
                    pid: 1,
                    start_id: "b1:1:1".to_string(),
                    classification: "useful".to_string(),
                    posterior_useful: 0.9,
                    posterior_useful_bad: 0.03,
                    posterior_abandoned: 0.05,
                    posterior_zombie: 0.02,
                    confidence: "medium".to_string(),
                    recommended_action: "keep".to_string(),
                    score: 10,
                },
                PersistedInference {
                    pid: 2,
                    start_id: "b1:2:2".to_string(),
                    classification: "abandoned".to_string(),
                    posterior_useful: 0.05,
                    posterior_useful_bad: 0.03,
                    posterior_abandoned: 0.9,
                    posterior_zombie: 0.02,
                    confidence: "high".to_string(),
                    recommended_action: "kill".to_string(),
                    score: 80,
                },
            ],
        };

        persist_inventory(&handle_a, "sa", "h1", inv_a).unwrap();
        persist_inference(&handle_a, "sa", "h1", inf_a).unwrap();

        // Persist session B (process 2 resolved, process 3 new)
        let inv_b = InventoryArtifact {
            total_system_processes: 100,
            protected_filtered: 10,
            record_count: 2,
            records: vec![
                PersistedProcess {
                    pid: 1,
                    ppid: 0,
                    uid: 1000,
                    start_id: "b1:1:1".to_string(),
                    comm: "srv".to_string(),
                    cmd: "srv".to_string(),
                    state: "S".to_string(),
                    start_time_unix: 1700000000,
                    elapsed_secs: 1000,
                    identity_quality: "Full".to_string(),
                },
                PersistedProcess {
                    pid: 3,
                    ppid: 0,
                    uid: 1000,
                    start_id: "b1:3:3".to_string(),
                    comm: "new".to_string(),
                    cmd: "new".to_string(),
                    state: "S".to_string(),
                    start_time_unix: 1700000900,
                    elapsed_secs: 100,
                    identity_quality: "Full".to_string(),
                },
            ],
        };
        let inf_b = InferenceArtifact {
            candidate_count: 2,
            candidates: vec![
                PersistedInference {
                    pid: 1,
                    start_id: "b1:1:1".to_string(),
                    classification: "useful".to_string(),
                    posterior_useful: 0.89,
                    posterior_useful_bad: 0.03,
                    posterior_abandoned: 0.06,
                    posterior_zombie: 0.02,
                    confidence: "medium".to_string(),
                    recommended_action: "keep".to_string(),
                    score: 12,
                },
                PersistedInference {
                    pid: 3,
                    start_id: "b1:3:3".to_string(),
                    classification: "useful".to_string(),
                    posterior_useful: 0.92,
                    posterior_useful_bad: 0.03,
                    posterior_abandoned: 0.03,
                    posterior_zombie: 0.02,
                    confidence: "medium".to_string(),
                    recommended_action: "keep".to_string(),
                    score: 8,
                },
            ],
        };

        persist_inventory(&handle_b, "sb", "h1", inv_b).unwrap();
        persist_inference(&handle_b, "sb", "h1", inf_b).unwrap();

        // Load and diff.
        let loaded_a_inv = load_inventory(&handle_a).unwrap();
        let loaded_a_inf = load_inference(&handle_a).unwrap();
        let loaded_b_inv = load_inventory(&handle_b).unwrap();
        let loaded_b_inf = load_inference(&handle_b).unwrap();

        let diff = compute_diff(
            "sa",
            "sb",
            &loaded_a_inv.payload.records,
            &loaded_a_inf.payload.candidates,
            &loaded_b_inv.payload.records,
            &loaded_b_inf.payload.candidates,
            &DiffConfig::default(),
        );

        assert_eq!(diff.summary.new_count, 1);
        assert_eq!(diff.summary.resolved_count, 1);
        assert_eq!(diff.summary.unchanged_count, 1);

        // Generate comparison report.
        let report = generate_comparison_report(
            &diff,
            &loaded_a_inf.payload.candidates,
            &loaded_b_inf.payload.candidates,
        );
        assert_eq!(report.old_session_id, "sa");
        assert_eq!(report.new_session_id, "sb");
    }
}
