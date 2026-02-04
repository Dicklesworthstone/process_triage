use pt_core::decision::goal_optimizer::{
    optimize_dp, optimize_greedy, optimize_greedy_with_preferences, optimize_ilp,
    reoptimize_on_change, AlternativePlan, GoalAchievement, OptCandidate, PreferenceModel,
    ResourceGoal,
};
use pt_core::decision::goal_parser::{parse_goal, Goal};
use pt_core::decision::goal_plan::{optimize_goal_plan, PlanCandidate, PlanConstraints};

#[test]
fn memory_pressure_risk_budget_prefers_low_risk_set() {
    let candidates = vec![
        PlanCandidate {
            pid: 1,
            expected_contribution: 5.0,
            confidence: 0.95,
            risk: 1.0,
            is_protected: false,
            uid: 1000,
            label: "A".to_string(),
        },
        PlanCandidate {
            pid: 2,
            expected_contribution: 3.0,
            confidence: 0.9,
            risk: 1.0,
            is_protected: false,
            uid: 1000,
            label: "B".to_string(),
        },
        PlanCandidate {
            pid: 3,
            expected_contribution: 8.0,
            confidence: 0.6,
            risk: 10.0,
            is_protected: false,
            uid: 1000,
            label: "C".to_string(),
        },
    ];

    let constraints = PlanConstraints {
        goal_target: 10.0,
        max_total_risk: 3.0,
        ..Default::default()
    };

    let plans = optimize_goal_plan(&candidates, &constraints);
    assert!(!plans.is_empty());

    let matched = plans.iter().any(|plan| {
        let pids: Vec<u32> = plan.actions.iter().map(|a| a.pid).collect();
        pids.contains(&1) && pids.contains(&2) && !pids.contains(&3) && !plan.goal_achievable
    });
    assert!(matched, "expected a plan that picks A+B and reports shortfall");
}

#[test]
fn dp_minimize_kills_prefers_single_candidate() {
    let candidates = vec![
        OptCandidate {
            id: "A".to_string(),
            expected_loss: 1.0,
            contributions: vec![2.0],
            blocked: false,
            block_reason: None,
        },
        OptCandidate {
            id: "B".to_string(),
            expected_loss: 1.0,
            contributions: vec![2.0],
            blocked: false,
            block_reason: None,
        },
        OptCandidate {
            id: "C".to_string(),
            expected_loss: 1.5,
            contributions: vec![5.0],
            blocked: false,
            block_reason: None,
        },
    ];

    let goals = vec![ResourceGoal {
        resource: "memory_gb".to_string(),
        target: 5.0,
        weight: 1.0,
    }];

    let result = optimize_dp(&candidates, &goals, 1.0);
    assert!(result.feasible);
    assert_eq!(result.selected.len(), 1);
    assert_eq!(result.selected[0].id, "C");
}

#[test]
fn ilp_minimize_kills_prefers_single_candidate() {
    let candidates = vec![
        OptCandidate {
            id: "A".to_string(),
            expected_loss: 1.0,
            contributions: vec![2.0],
            blocked: false,
            block_reason: None,
        },
        OptCandidate {
            id: "B".to_string(),
            expected_loss: 1.0,
            contributions: vec![2.0],
            blocked: false,
            block_reason: None,
        },
        OptCandidate {
            id: "C".to_string(),
            expected_loss: 1.5,
            contributions: vec![5.0],
            blocked: false,
            block_reason: None,
        },
    ];

    let goals = vec![ResourceGoal {
        resource: "memory_gb".to_string(),
        target: 5.0,
        weight: 1.0,
    }];

    let result = optimize_ilp(&candidates, &goals);
    assert_eq!(result.algorithm, "ilp_branch_bound");
    assert!(result.feasible);
    assert_eq!(result.selected.len(), 1);
    assert_eq!(result.selected[0].id, "C");
}

#[test]
fn ilp_infeasible_falls_back() {
    let candidates = vec![
        OptCandidate {
            id: "A".to_string(),
            expected_loss: 1.0,
            contributions: vec![2.0],
            blocked: false,
            block_reason: None,
        },
        OptCandidate {
            id: "B".to_string(),
            expected_loss: 1.0,
            contributions: vec![3.0],
            blocked: false,
            block_reason: None,
        },
    ];

    let goals = vec![ResourceGoal {
        resource: "memory_gb".to_string(),
        target: 10.0,
        weight: 1.0,
    }];

    let result = optimize_ilp(&candidates, &goals);
    assert!(result.algorithm.contains("infeasible"));
    assert!(!result.feasible);
    assert!(result.goal_achievement[0].shortfall > 0.0);
}

#[test]
fn confidence_threshold_filters_candidates() {
    let candidates = vec![
        PlanCandidate {
            pid: 10,
            expected_contribution: 2.0,
            confidence: 0.99,
            risk: 0.5,
            is_protected: false,
            uid: 1000,
            label: "high".to_string(),
        },
        PlanCandidate {
            pid: 11,
            expected_contribution: 10.0,
            confidence: 0.8,
            risk: 0.5,
            is_protected: false,
            uid: 1000,
            label: "low".to_string(),
        },
    ];

    let constraints = PlanConstraints {
        goal_target: 2.0,
        min_confidence: 0.95,
        ..Default::default()
    };

    let plans = optimize_goal_plan(&candidates, &constraints);
    assert!(!plans.is_empty());
    for plan in plans {
        assert!(plan.actions.iter().all(|a| a.pid == 10));
    }
}

#[test]
fn greedy_prefers_higher_efficiency_candidate() {
    let candidates = vec![
        OptCandidate {
            id: "A".to_string(),
            expected_loss: 5.0,
            contributions: vec![5.0],
            blocked: false,
            block_reason: None,
        },
        OptCandidate {
            id: "B".to_string(),
            expected_loss: 0.5,
            contributions: vec![1.98],
            blocked: false,
            block_reason: None,
        },
    ];

    let goals = vec![ResourceGoal {
        resource: "memory_gb".to_string(),
        target: 1.5,
        weight: 1.0,
    }];

    let result = optimize_greedy(&candidates, &goals);
    assert!(!result.selected.is_empty());
    assert_eq!(result.selected[0].id, "B");
}

#[test]
fn infeasible_goal_reports_shortfall() {
    let candidates = vec![
        OptCandidate {
            id: "A".to_string(),
            expected_loss: 1.0,
            contributions: vec![2.0],
            blocked: false,
            block_reason: None,
        },
        OptCandidate {
            id: "B".to_string(),
            expected_loss: 1.0,
            contributions: vec![3.0],
            blocked: false,
            block_reason: None,
        },
    ];

    let goals = vec![ResourceGoal {
        resource: "memory_gb".to_string(),
        target: 10.0,
        weight: 1.0,
    }];

    let result = optimize_greedy(&candidates, &goals);
    assert!(!result.feasible);
    assert_eq!(result.goal_achievement.len(), 1);
    assert!(result.goal_achievement[0].shortfall > 0.0);
}

#[test]
fn composite_goal_parser_accepts_and() {
    let goal = parse_goal("free 4GB RAM AND release port 3000").unwrap();
    match goal {
        Goal::And(parts) => assert_eq!(parts.len(), 2),
        _ => panic!("expected AND goal"),
    }
}

#[test]
fn alternatives_include_tradeoff_variants() {
    let candidates = vec![
        OptCandidate {
            id: "A".to_string(),
            expected_loss: 0.2,
            contributions: vec![150.0],
            blocked: false,
            block_reason: None,
        },
        OptCandidate {
            id: "B".to_string(),
            expected_loss: 0.4,
            contributions: vec![120.0],
            blocked: false,
            block_reason: None,
        },
        OptCandidate {
            id: "C".to_string(),
            expected_loss: 0.6,
            contributions: vec![110.0],
            blocked: false,
            block_reason: None,
        },
    ];

    let goals = vec![ResourceGoal {
        resource: "memory_mb".to_string(),
        target: 200.0,
        weight: 1.0,
    }];

    let result = optimize_greedy(&candidates, &goals);
    assert!(!result.alternatives.is_empty());
    assert!(result
        .alternatives
        .iter()
        .any(|alt| alt.action_count != result.selected.len()));
}

#[test]
fn pareto_frontier_excludes_dominated_sets() {
    let candidates = vec![
        OptCandidate {
            id: "A".to_string(),
            expected_loss: 1.0,
            contributions: vec![5.0],
            blocked: false,
            block_reason: None,
        },
        OptCandidate {
            id: "B".to_string(),
            expected_loss: 2.0,
            contributions: vec![6.0],
            blocked: false,
            block_reason: None,
        },
        OptCandidate {
            id: "C".to_string(),
            expected_loss: 3.0,
            contributions: vec![6.0],
            blocked: false,
            block_reason: None,
        },
    ];

    let goals = vec![ResourceGoal {
        resource: "memory_mb".to_string(),
        target: 1.0,
        weight: 1.0,
    }];

    let result = optimize_greedy(&candidates, &goals);
    let pareto: Vec<_> = result
        .alternatives
        .iter()
        .filter(|alt| alt.description.starts_with("Pareto:"))
        .collect();

    assert!(!pareto.is_empty(), "expected Pareto alternatives");

    let losses: Vec<f64> = pareto.iter().map(|alt| alt.total_loss).collect();
    let mut sorted = losses.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    assert_eq!(losses, sorted, "Pareto alternatives should be sorted by loss");

    let dominated_c = pareto.iter().any(|alt| {
        alt.action_count == 1
            && (alt.total_loss - 3.0).abs() < 1e-6
            && alt.goal_achievement[0].achieved >= 6.0 - 1e-6
    });
    assert!(!dominated_c, "dominated set should not be on Pareto frontier");
}

#[test]
fn telemetry_emits_objective_and_convergence() {
    let candidates = vec![
        OptCandidate {
            id: "A".to_string(),
            expected_loss: 1.0,
            contributions: vec![3.0],
            blocked: false,
            block_reason: None,
        },
        OptCandidate {
            id: "B".to_string(),
            expected_loss: 2.0,
            contributions: vec![4.0],
            blocked: false,
            block_reason: None,
        },
    ];

    let goals = vec![ResourceGoal {
        resource: "memory_mb".to_string(),
        target: 3.0,
        weight: 1.0,
    }];

    let result = optimize_greedy(&candidates, &goals);
    assert!(result.log_events.iter().any(|e| {
        e.event == "objective_eval" && e.candidate_id.is_some() && e.loss.is_some()
    }));
    assert!(result.log_events.iter().any(|e| {
        e.event == "converged" && e.total_loss.is_some()
    }));
}

#[test]
fn telemetry_emits_pareto_points() {
    let candidates = vec![
        OptCandidate {
            id: "A".to_string(),
            expected_loss: 0.5,
            contributions: vec![2.0],
            blocked: false,
            block_reason: None,
        },
        OptCandidate {
            id: "B".to_string(),
            expected_loss: 1.0,
            contributions: vec![4.0],
            blocked: false,
            block_reason: None,
        },
    ];

    let goals = vec![ResourceGoal {
        resource: "memory_mb".to_string(),
        target: 2.0,
        weight: 1.0,
    }];

    let result = optimize_greedy(&candidates, &goals);
    assert!(result
        .log_events
        .iter()
        .any(|e| e.event == "pareto_point"));
}

#[test]
fn telemetry_emits_constraint_prune() {
    let candidates = vec![OptCandidate {
        id: "A".to_string(),
        expected_loss: 1.0,
        contributions: vec![1.0],
        blocked: false,
        block_reason: None,
    }];

    let goals = vec![ResourceGoal {
        resource: "memory_mb".to_string(),
        target: 10.0,
        weight: 1.0,
    }];

    let result = optimize_ilp(&candidates, &goals);
    assert!(result
        .log_events
        .iter()
        .any(|e| e.event == "constraint_prune"));
}

#[test]
fn reoptimize_skips_when_no_change() {
    let candidates = vec![
        OptCandidate {
            id: "A".to_string(),
            expected_loss: 1.0,
            contributions: vec![3.0],
            blocked: false,
            block_reason: None,
        },
        OptCandidate {
            id: "B".to_string(),
            expected_loss: 2.0,
            contributions: vec![4.0],
            blocked: false,
            block_reason: None,
        },
    ];
    let goals = vec![ResourceGoal {
        resource: "memory_mb".to_string(),
        target: 3.0,
        weight: 1.0,
    }];
    let previous = optimize_greedy(&candidates, &goals);
    let decision = reoptimize_on_change(&previous, &candidates, &candidates, &goals);
    assert!(!decision.reoptimized);
    assert_eq!(decision.reason, "no_change");
}

#[test]
fn reoptimize_when_selected_missing() {
    let prev_candidates = vec![
        OptCandidate {
            id: "A".to_string(),
            expected_loss: 1.0,
            contributions: vec![3.0],
            blocked: false,
            block_reason: None,
        },
        OptCandidate {
            id: "B".to_string(),
            expected_loss: 2.0,
            contributions: vec![4.0],
            blocked: false,
            block_reason: None,
        },
    ];
    let goals = vec![ResourceGoal {
        resource: "memory_mb".to_string(),
        target: 3.0,
        weight: 1.0,
    }];
    let previous = optimize_greedy(&prev_candidates, &goals);
    let new_candidates = vec![OptCandidate {
        id: "B".to_string(),
        expected_loss: 2.0,
        contributions: vec![4.0],
        blocked: false,
        block_reason: None,
    }];
    let decision = reoptimize_on_change(&previous, &prev_candidates, &new_candidates, &goals);
    assert!(decision.reoptimized);
    assert_eq!(decision.reason, "selected_missing");
}

#[test]
fn reoptimize_on_churn_threshold() {
    let prev_candidates = vec![
        OptCandidate {
            id: "A".to_string(),
            expected_loss: 1.0,
            contributions: vec![3.0],
            blocked: false,
            block_reason: None,
        },
        OptCandidate {
            id: "B".to_string(),
            expected_loss: 2.0,
            contributions: vec![4.0],
            blocked: false,
            block_reason: None,
        },
        OptCandidate {
            id: "C".to_string(),
            expected_loss: 3.0,
            contributions: vec![5.0],
            blocked: false,
            block_reason: None,
        },
        OptCandidate {
            id: "D".to_string(),
            expected_loss: 4.0,
            contributions: vec![6.0],
            blocked: false,
            block_reason: None,
        },
        OptCandidate {
            id: "E".to_string(),
            expected_loss: 5.0,
            contributions: vec![7.0],
            blocked: false,
            block_reason: None,
        },
    ];
    let goals = vec![ResourceGoal {
        resource: "memory_mb".to_string(),
        target: 3.0,
        weight: 1.0,
    }];
    let previous = optimize_greedy(&prev_candidates, &goals);
    let mut new_candidates = prev_candidates.clone();
    new_candidates.push(OptCandidate {
        id: "F".to_string(),
        expected_loss: 6.0,
        contributions: vec![8.0],
        blocked: false,
        block_reason: None,
    });
    new_candidates.push(OptCandidate {
        id: "G".to_string(),
        expected_loss: 7.0,
        contributions: vec![9.0],
        blocked: false,
        block_reason: None,
    });
    let decision = reoptimize_on_change(&previous, &prev_candidates, &new_candidates, &goals);
    assert!(decision.reoptimized);
    assert_eq!(decision.reason, "churn_threshold");
}

#[test]
fn preference_update_moves_toward_choice() {
    let mut model = PreferenceModel {
        risk_tolerance: 0.1,
        learning_rate: 0.5,
    };
    let alternatives = vec![
        AlternativePlan {
            description: "low".to_string(),
            action_count: 1,
            total_loss: 1.0,
            goal_achievement: vec![GoalAchievement {
                resource: "memory_mb".to_string(),
                target: 1.0,
                achieved: 1.0,
                shortfall: 0.0,
                met: true,
            }],
        },
        AlternativePlan {
            description: "high".to_string(),
            action_count: 1,
            total_loss: 3.0,
            goal_achievement: vec![GoalAchievement {
                resource: "memory_mb".to_string(),
                target: 1.0,
                achieved: 1.0,
                shortfall: 0.0,
                met: true,
            }],
        },
    ];

    let update = model.update_from_choice(&alternatives[1], &alternatives);
    assert!(update.updated > update.prior);
}

#[test]
fn preference_influences_selection() {
    let candidates = vec![
        OptCandidate {
            id: "A".to_string(),
            expected_loss: 5.0,
            contributions: vec![15.0],
            blocked: false,
            block_reason: None,
        },
        OptCandidate {
            id: "B".to_string(),
            expected_loss: 1.0,
            contributions: vec![2.0],
            blocked: false,
            block_reason: None,
        },
    ];
    let goals = vec![ResourceGoal {
        resource: "memory_mb".to_string(),
        target: 2.0,
        weight: 1.0,
    }];
    let aggressive = PreferenceModel {
        risk_tolerance: 1.0,
        learning_rate: 0.2,
    };
    let conservative = PreferenceModel {
        risk_tolerance: 0.0,
        learning_rate: 0.2,
    };

    let result_aggressive = optimize_greedy_with_preferences(&candidates, &goals, &aggressive);
    let result_conservative = optimize_greedy_with_preferences(&candidates, &goals, &conservative);

    assert_eq!(result_aggressive.selected[0].id, "A");
    assert_eq!(result_conservative.selected[0].id, "B");
}
