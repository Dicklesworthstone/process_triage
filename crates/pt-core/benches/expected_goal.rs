//! Criterion benchmarks for expected-loss decisioning, goal contribution estimation,
//! and goal string parsing.
//!
//! Benchmarks `decide_action`, `decide_action_with_recovery`, `apply_risk_sensitive_control`,
//! `apply_dro_control`, `estimate_memory_contribution`, `estimate_cpu_contribution`,
//! `estimate_port_contribution`, `estimate_fd_contribution`, `parse_goal`, and
//! `Goal::canonical` — decision-pipeline and goal-optimizer hotpaths.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use pt_core::config::policy::Policy;
use pt_core::config::priors::{
    BetaParams, CausalInterventions, ClassParams, ClassPriors, InterventionPriors, Priors,
};
use pt_core::decision::cvar::CvarTrigger;
use pt_core::decision::dro::DroTrigger;
use pt_core::decision::expected_loss::{
    apply_dro_control, apply_risk_sensitive_control, decide_action, decide_action_with_recovery,
    ActionFeasibility,
};
use pt_core::decision::goal_contribution::{
    estimate_cpu_contribution, estimate_fd_contribution, estimate_memory_contribution,
    estimate_port_contribution, ContributionCandidate,
};
use pt_core::decision::goal_parser::{parse_goal, Goal};
use pt_core::inference::ClassScores;

// ── Helpers ──────────────────────────────────────────────────────────

fn uniform_posterior() -> ClassScores {
    ClassScores {
        useful: 0.25,
        useful_bad: 0.25,
        abandoned: 0.25,
        zombie: 0.25,
    }
}

fn confident_useful() -> ClassScores {
    ClassScores {
        useful: 0.92,
        useful_bad: 0.04,
        abandoned: 0.02,
        zombie: 0.02,
    }
}

fn confident_zombie() -> ClassScores {
    ClassScores {
        useful: 0.01,
        useful_bad: 0.02,
        abandoned: 0.02,
        zombie: 0.95,
    }
}

fn ambiguous_posterior() -> ClassScores {
    ClassScores {
        useful: 0.30,
        useful_bad: 0.15,
        abandoned: 0.40,
        zombie: 0.15,
    }
}

fn test_priors() -> Priors {
    let class_params = ClassParams {
        prior_prob: 0.25,
        cpu_beta: BetaParams::new(1.0, 1.0),
        runtime_gamma: None,
        orphan_beta: BetaParams::new(1.0, 1.0),
        tty_beta: BetaParams::new(1.0, 1.0),
        net_beta: BetaParams::new(1.0, 1.0),
        io_active_beta: None,
        hazard_gamma: None,
        competing_hazards: None,
    };

    Priors {
        schema_version: "1.0.0".to_string(),
        description: None,
        created_at: None,
        updated_at: None,
        host_profile: None,
        classes: ClassPriors {
            useful: class_params.clone(),
            useful_bad: class_params.clone(),
            abandoned: class_params.clone(),
            zombie: class_params,
        },
        hazard_regimes: vec![],
        semi_markov: None,
        change_point: None,
        causal_interventions: Some(CausalInterventions {
            pause: Some(InterventionPriors {
                useful: Some(BetaParams::new(8.0, 2.0)),
                useful_bad: Some(BetaParams::new(3.0, 7.0)),
                abandoned: Some(BetaParams::new(2.0, 8.0)),
                zombie: Some(BetaParams::new(1.0, 9.0)),
            }),
            throttle: Some(InterventionPriors {
                useful: Some(BetaParams::new(7.0, 3.0)),
                useful_bad: Some(BetaParams::new(4.0, 6.0)),
                abandoned: Some(BetaParams::new(3.0, 7.0)),
                zombie: Some(BetaParams::new(2.0, 8.0)),
            }),
            kill: Some(InterventionPriors {
                useful: Some(BetaParams::new(1.0, 9.0)),
                useful_bad: Some(BetaParams::new(5.0, 5.0)),
                abandoned: Some(BetaParams::new(8.0, 2.0)),
                zombie: Some(BetaParams::new(9.0, 1.0)),
            }),
            restart: Some(InterventionPriors {
                useful: Some(BetaParams::new(6.0, 4.0)),
                useful_bad: Some(BetaParams::new(5.0, 5.0)),
                abandoned: Some(BetaParams::new(4.0, 6.0)),
                zombie: Some(BetaParams::new(3.0, 7.0)),
            }),
        }),
        command_categories: None,
        state_flags: None,
        hierarchical: None,
        robust_bayes: None,
        error_rate: None,
        bocpd: None,
    }
}

fn simple_candidate() -> ContributionCandidate {
    ContributionCandidate {
        pid: 1234,
        rss_bytes: 500_000_000,
        uss_bytes: None,
        cpu_frac: 0.15,
        fd_count: 40,
        bound_ports: vec![3000],
        respawn_probability: 0.0,
        has_shared_memory: false,
        child_count: 0,
    }
}

fn complex_candidate() -> ContributionCandidate {
    ContributionCandidate {
        pid: 5678,
        rss_bytes: 2_000_000_000,
        uss_bytes: Some(1_200_000_000),
        cpu_frac: 0.75,
        fd_count: 200,
        bound_ports: vec![8080, 8443, 9090],
        respawn_probability: 0.6,
        has_shared_memory: true,
        child_count: 5,
    }
}

// ── Expected loss benchmarks ─────────────────────────────────────────

fn bench_decide_action(c: &mut Criterion) {
    let mut group = c.benchmark_group("expected_loss/decide_action");

    let policy = Policy::default();
    let feasibility = ActionFeasibility::allow_all();

    for (name, posterior) in [
        ("uniform", uniform_posterior()),
        ("confident_useful", confident_useful()),
        ("confident_zombie", confident_zombie()),
        ("ambiguous", ambiguous_posterior()),
    ] {
        group.bench_with_input(
            BenchmarkId::new("all_actions", name),
            &posterior,
            |b, post| {
                b.iter(|| {
                    let outcome =
                        decide_action(black_box(post), black_box(&policy), black_box(&feasibility))
                            .unwrap();
                    black_box(outcome.optimal_action);
                })
            },
        );
    }

    // With zombie feasibility constraint
    let zombie_feasibility = ActionFeasibility::from_process_state(true, false, None);
    group.bench_with_input(
        BenchmarkId::new("zombie_constrained", "confident_zombie"),
        &confident_zombie(),
        |b, post| {
            b.iter(|| {
                let outcome = decide_action(
                    black_box(post),
                    black_box(&policy),
                    black_box(&zombie_feasibility),
                )
                .unwrap();
                black_box(outcome.optimal_action);
            })
        },
    );

    // With D-state feasibility constraint
    let dsleep_feasibility = ActionFeasibility::from_process_state(false, true, Some("nfs_wait"));
    group.bench_with_input(
        BenchmarkId::new("dsleep_constrained", "ambiguous"),
        &ambiguous_posterior(),
        |b, post| {
            b.iter(|| {
                let outcome = decide_action(
                    black_box(post),
                    black_box(&policy),
                    black_box(&dsleep_feasibility),
                )
                .unwrap();
                black_box(outcome.optimal_action);
            })
        },
    );

    group.finish();
}

fn bench_decide_action_with_recovery(c: &mut Criterion) {
    let mut group = c.benchmark_group("expected_loss/decide_with_recovery");

    let policy = Policy::default();
    let priors = test_priors();
    let feasibility = ActionFeasibility::allow_all();

    for (name, posterior) in [
        ("uniform", uniform_posterior()),
        ("confident_useful", confident_useful()),
        ("ambiguous", ambiguous_posterior()),
    ] {
        for tolerance in [0.01, 0.05, 0.2] {
            group.bench_with_input(
                BenchmarkId::new(format!("{}_tol{:.2}", name, tolerance), name),
                &posterior,
                |b, post| {
                    b.iter(|| {
                        let outcome = decide_action_with_recovery(
                            black_box(post),
                            black_box(&policy),
                            black_box(&feasibility),
                            black_box(&priors),
                            black_box(tolerance),
                        )
                        .unwrap();
                        black_box(outcome.optimal_action);
                    })
                },
            );
        }
    }

    group.finish();
}

fn bench_risk_sensitive_control(c: &mut Criterion) {
    let mut group = c.benchmark_group("expected_loss/risk_sensitive");

    let policy = Policy::default();
    let feasibility = ActionFeasibility::allow_all();

    let triggers = [
        (
            "no_trigger",
            CvarTrigger {
                robot_mode: false,
                low_confidence: false,
                high_blast_radius: false,
                explicit_conservative: false,
                blast_radius_mb: None,
            },
        ),
        (
            "robot_mode",
            CvarTrigger {
                robot_mode: true,
                low_confidence: false,
                high_blast_radius: false,
                explicit_conservative: false,
                blast_radius_mb: None,
            },
        ),
        (
            "high_blast",
            CvarTrigger {
                robot_mode: false,
                low_confidence: false,
                high_blast_radius: true,
                explicit_conservative: false,
                blast_radius_mb: Some(8192.0),
            },
        ),
        (
            "multi_trigger",
            CvarTrigger {
                robot_mode: true,
                low_confidence: true,
                high_blast_radius: true,
                explicit_conservative: false,
                blast_radius_mb: Some(4096.0),
            },
        ),
    ];

    for (name, trigger) in &triggers {
        let posterior = ambiguous_posterior();
        let outcome = decide_action(&posterior, &policy, &feasibility).unwrap();

        group.bench_with_input(BenchmarkId::new("apply", *name), trigger, |b, trig| {
            b.iter(|| {
                let result = apply_risk_sensitive_control(
                    black_box(outcome.clone()),
                    black_box(&posterior),
                    black_box(&policy),
                    black_box(trig),
                    black_box(0.95),
                );
                black_box(result.optimal_action);
            })
        });
    }

    group.finish();
}

fn bench_dro_control(c: &mut Criterion) {
    let mut group = c.benchmark_group("expected_loss/dro_control");

    let policy = Policy::default();
    let feasibility = ActionFeasibility::allow_all();

    let triggers = [
        ("no_trigger", DroTrigger::none()),
        (
            "ppc_failure",
            DroTrigger {
                ppc_failure: true,
                ..DroTrigger::none()
            },
        ),
        (
            "drift",
            DroTrigger {
                drift_detected: true,
                wasserstein_divergence: Some(0.3),
                ..DroTrigger::none()
            },
        ),
        (
            "multi_trigger",
            DroTrigger {
                ppc_failure: true,
                drift_detected: true,
                wasserstein_divergence: Some(0.5),
                eta_tempering_reduced: true,
                explicit_conservative: false,
                low_model_confidence: true,
            },
        ),
    ];

    for (name, trigger) in &triggers {
        let posterior = ambiguous_posterior();
        let outcome = decide_action(&posterior, &policy, &feasibility).unwrap();

        group.bench_with_input(BenchmarkId::new("apply", *name), trigger, |b, trig| {
            b.iter(|| {
                let result = apply_dro_control(
                    black_box(outcome.clone()),
                    black_box(&posterior),
                    black_box(&policy),
                    black_box(trig),
                    black_box(0.15),
                );
                black_box(result.optimal_action);
            })
        });
    }

    group.finish();
}

// ── Goal contribution benchmarks ─────────────────────────────────────

fn bench_estimate_memory(c: &mut Criterion) {
    let mut group = c.benchmark_group("goal_contrib/memory");

    let candidates = [
        ("simple", simple_candidate()),
        ("complex", complex_candidate()),
        (
            "shared_no_uss",
            ContributionCandidate {
                has_shared_memory: true,
                respawn_probability: 0.3,
                ..simple_candidate()
            },
        ),
        (
            "with_uss",
            ContributionCandidate {
                uss_bytes: Some(300_000_000),
                ..simple_candidate()
            },
        ),
    ];

    for (name, candidate) in &candidates {
        group.bench_with_input(BenchmarkId::new("estimate", *name), candidate, |b, cand| {
            b.iter(|| {
                let contrib = estimate_memory_contribution(black_box(cand));
                black_box(contrib.expected);
            })
        });
    }

    group.finish();
}

fn bench_estimate_cpu(c: &mut Criterion) {
    let mut group = c.benchmark_group("goal_contrib/cpu");

    for (name, candidate) in [
        ("simple", simple_candidate()),
        ("complex", complex_candidate()),
        (
            "high_respawn",
            ContributionCandidate {
                respawn_probability: 0.9,
                cpu_frac: 0.5,
                ..simple_candidate()
            },
        ),
    ] {
        group.bench_with_input(BenchmarkId::new("estimate", name), &candidate, |b, cand| {
            b.iter(|| {
                let contrib = estimate_cpu_contribution(black_box(cand));
                black_box(contrib.expected);
            })
        });
    }

    group.finish();
}

fn bench_estimate_port(c: &mut Criterion) {
    let mut group = c.benchmark_group("goal_contrib/port");

    let candidate = simple_candidate();
    group.bench_function(BenchmarkId::new("holds_port", "3000"), |b| {
        b.iter(|| {
            let contrib = estimate_port_contribution(black_box(&candidate), black_box(3000));
            black_box(contrib.expected);
        })
    });

    group.bench_function(BenchmarkId::new("no_port", "8080"), |b| {
        b.iter(|| {
            let contrib = estimate_port_contribution(black_box(&candidate), black_box(8080));
            black_box(contrib.expected);
        })
    });

    let respawn_cand = ContributionCandidate {
        respawn_probability: 0.7,
        ..simple_candidate()
    };
    group.bench_function(BenchmarkId::new("holds_with_respawn", "3000"), |b| {
        b.iter(|| {
            let contrib = estimate_port_contribution(black_box(&respawn_cand), black_box(3000));
            black_box(contrib.expected);
        })
    });

    group.finish();
}

fn bench_estimate_fd(c: &mut Criterion) {
    let mut group = c.benchmark_group("goal_contrib/fd");

    for (name, candidate) in [
        ("simple", simple_candidate()),
        ("complex", complex_candidate()),
        (
            "many_children",
            ContributionCandidate {
                child_count: 20,
                fd_count: 100,
                ..simple_candidate()
            },
        ),
    ] {
        group.bench_with_input(BenchmarkId::new("estimate", name), &candidate, |b, cand| {
            b.iter(|| {
                let contrib = estimate_fd_contribution(black_box(cand));
                black_box(contrib.expected);
            })
        });
    }

    group.finish();
}

// ── Goal parser benchmarks ───────────────────────────────────────────

fn bench_parse_goal(c: &mut Criterion) {
    let mut group = c.benchmark_group("goal_parser/parse");

    let inputs = [
        ("memory_gb", "free 4GB RAM"),
        ("memory_mb", "free 500MB memory"),
        ("cpu_free", "free 20% CPU"),
        ("cpu_reduce", "reduce CPU below 50%"),
        ("port", "release port 3000"),
        ("fds", "free 100 FDs"),
        ("file_descriptors", "free 50 file descriptors"),
        ("and_composition", "free 4GB RAM AND release port 3000"),
        ("or_composition", "free 2GB RAM OR free 20% CPU"),
        (
            "triple_and",
            "free 4GB RAM AND release port 8080 AND free 100 FDs",
        ),
    ];

    for (name, input) in &inputs {
        group.bench_with_input(BenchmarkId::new("parse", *name), *input, |b, inp| {
            b.iter(|| {
                let goal = parse_goal(black_box(inp)).unwrap();
                black_box(&goal);
            })
        });
    }

    group.finish();
}

fn bench_goal_canonical(c: &mut Criterion) {
    let mut group = c.benchmark_group("goal_parser/canonical");

    let goals: Vec<(&str, Goal)> = vec![
        ("simple", parse_goal("free 4GB RAM").unwrap()),
        (
            "and_2",
            parse_goal("free 4GB RAM AND release port 3000").unwrap(),
        ),
        (
            "and_3",
            parse_goal("free 4GB RAM AND release port 8080 AND free 100 FDs").unwrap(),
        ),
        ("or_2", parse_goal("free 2GB RAM OR free 20% CPU").unwrap()),
    ];

    for (name, goal) in &goals {
        group.bench_with_input(BenchmarkId::new("canonical", *name), goal, |b, g| {
            b.iter(|| {
                let s = black_box(g).canonical();
                black_box(s.len());
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_decide_action,
    bench_decide_action_with_recovery,
    bench_risk_sensitive_control,
    bench_dro_control,
    bench_estimate_memory,
    bench_estimate_cpu,
    bench_estimate_port,
    bench_estimate_fd,
    bench_parse_goal,
    bench_goal_canonical
);
criterion_main!(benches);
