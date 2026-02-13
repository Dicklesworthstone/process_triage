//! Criterion benchmarks for causal interventions, load-aware tuning, and martingale gates.
//!
//! Benchmarks `expected_recovery`, `update_beta`, `expected_recovery_by_action`,
//! `compute_load_adjustment`, `apply_load_to_loss_matrix`, `resolve_alpha`,
//! and `apply_martingale_gates` — decision-pipeline hotpaths.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use pt_core::config::policy::{LoadAwareDecision, Policy};
use pt_core::config::priors::{
    BetaParams, CausalInterventions, ClassParams, ClassPriors, GammaParams, InterventionPriors,
    Priors,
};
use pt_core::decision::causal_interventions::{
    apply_outcome, expected_recovery, expected_recovery_by_action, InterventionOutcome,
    ProcessClass,
};
use pt_core::decision::fdr_selection::TargetIdentity;
use pt_core::decision::load_aware::{
    apply_load_to_loss_matrix, compute_load_adjustment, LoadAdjustment, LoadSignals,
};
use pt_core::decision::martingale_gates::{
    apply_martingale_gates, resolve_alpha, MartingaleGateCandidate, MartingaleGateConfig,
};
use pt_core::inference::martingale::{MartingaleAnalyzer, MartingaleConfig};
use pt_core::inference::ClassScores;

// ── Helpers ──────────────────────────────────────────────────────────

fn default_class() -> ClassParams {
    ClassParams {
        prior_prob: 0.25,
        cpu_beta: BetaParams::new(1.0, 1.0),
        runtime_gamma: Some(GammaParams {
            shape: 1.0,
            rate: 1.0,
            comment: None,
        }),
        orphan_beta: BetaParams::new(1.0, 1.0),
        tty_beta: BetaParams::new(1.0, 1.0),
        net_beta: BetaParams::new(1.0, 1.0),
        io_active_beta: None,
        hazard_gamma: None,
        competing_hazards: None,
    }
}

fn test_priors() -> Priors {
    Priors {
        schema_version: "1.0.0".to_string(),
        description: None,
        created_at: None,
        updated_at: None,
        host_profile: None,
        classes: ClassPriors {
            useful: default_class(),
            useful_bad: default_class(),
            abandoned: default_class(),
            zombie: default_class(),
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

fn high_evalue_result() -> pt_core::inference::martingale::MartingaleResult {
    let mut analyzer = MartingaleAnalyzer::new(MartingaleConfig::default());
    for _ in 0..20 {
        analyzer.update(0.8);
    }
    analyzer.summary()
}

fn low_evalue_result() -> pt_core::inference::martingale::MartingaleResult {
    let mut analyzer = MartingaleAnalyzer::new(MartingaleConfig::default());
    for _ in 0..5 {
        analyzer.update(0.01);
    }
    analyzer.summary()
}

// ── Causal intervention benchmarks ──────────────────────────────────

fn bench_expected_recovery(c: &mut Criterion) {
    let mut group = c.benchmark_group("causal/expected_recovery");

    for (name, alpha, beta_val) in [
        ("uniform", 1.0, 1.0),
        ("high_success", 9.0, 1.0),
        ("low_success", 1.0, 9.0),
        ("concentrated", 50.0, 50.0),
    ] {
        let beta = BetaParams::new(alpha, beta_val);
        group.bench_with_input(BenchmarkId::new("compute", name), &beta, |b, beta| {
            b.iter(|| {
                black_box(expected_recovery(black_box(beta)));
            })
        });
    }

    group.finish();
}

fn bench_expected_recovery_by_action(c: &mut Criterion) {
    let mut group = c.benchmark_group("causal/recovery_by_action");

    let priors = test_priors();

    for (name, posterior) in [
        (
            "uniform",
            ClassScores {
                useful: 0.25,
                useful_bad: 0.25,
                abandoned: 0.25,
                zombie: 0.25,
            },
        ),
        (
            "confident_useful",
            ClassScores {
                useful: 0.90,
                useful_bad: 0.05,
                abandoned: 0.03,
                zombie: 0.02,
            },
        ),
        (
            "confident_zombie",
            ClassScores {
                useful: 0.02,
                useful_bad: 0.03,
                abandoned: 0.05,
                zombie: 0.90,
            },
        ),
        (
            "ambiguous",
            ClassScores {
                useful: 0.30,
                useful_bad: 0.20,
                abandoned: 0.35,
                zombie: 0.15,
            },
        ),
    ] {
        group.bench_with_input(
            BenchmarkId::new("all_actions", name),
            &posterior,
            |b, post| {
                b.iter(|| {
                    let expectations =
                        expected_recovery_by_action(black_box(&priors), black_box(post));
                    black_box(expectations.len());
                })
            },
        );
    }

    group.finish();
}

fn bench_apply_outcome(c: &mut Criterion) {
    let mut group = c.benchmark_group("causal/apply_outcome");

    let priors = test_priors();
    let interventions = priors.causal_interventions.as_ref().unwrap();

    for (name, action, class, recovered) in [
        (
            "pause_useful_success",
            pt_core::decision::Action::Pause,
            ProcessClass::Useful,
            true,
        ),
        (
            "pause_zombie_failure",
            pt_core::decision::Action::Pause,
            ProcessClass::Zombie,
            false,
        ),
        (
            "kill_abandoned_success",
            pt_core::decision::Action::Kill,
            ProcessClass::Abandoned,
            true,
        ),
        (
            "restart_useful_bad_failure",
            pt_core::decision::Action::Restart,
            ProcessClass::UsefulBad,
            false,
        ),
    ] {
        let outcome = InterventionOutcome {
            action,
            class,
            recovered,
            weight: 1.0,
        };
        group.bench_function(BenchmarkId::new("update", name), |b| {
            b.iter(|| {
                let updated = apply_outcome(
                    black_box(interventions),
                    black_box(&outcome),
                    black_box(1.0),
                );
                black_box(&updated);
            })
        });
    }

    group.finish();
}

// ── Load-aware benchmarks ───────────────────────────────────────────

fn bench_compute_load_adjustment(c: &mut Criterion) {
    let mut group = c.benchmark_group("load_aware/compute_adjustment");

    let config = LoadAwareDecision {
        enabled: true,
        ..LoadAwareDecision::default()
    };

    let scenarios = [
        (
            "idle",
            LoadSignals {
                queue_len: 0,
                load1: Some(0.1),
                cores: Some(8),
                memory_used_fraction: Some(0.1),
                psi_avg10: Some(0.0),
            },
        ),
        (
            "moderate",
            LoadSignals {
                queue_len: 50,
                load1: Some(4.0),
                cores: Some(8),
                memory_used_fraction: Some(0.6),
                psi_avg10: Some(10.0),
            },
        ),
        (
            "heavy",
            LoadSignals {
                queue_len: 200,
                load1: Some(16.0),
                cores: Some(4),
                memory_used_fraction: Some(0.95),
                psi_avg10: Some(50.0),
            },
        ),
        (
            "saturated",
            LoadSignals {
                queue_len: 1000,
                load1: Some(100.0),
                cores: Some(2),
                memory_used_fraction: Some(1.0),
                psi_avg10: Some(100.0),
            },
        ),
        (
            "partial_signals",
            LoadSignals {
                queue_len: 100,
                load1: None,
                cores: None,
                memory_used_fraction: Some(0.8),
                psi_avg10: None,
            },
        ),
    ];

    for (name, signals) in &scenarios {
        group.bench_with_input(BenchmarkId::new("compute", *name), signals, |b, sig| {
            b.iter(|| {
                let adj = compute_load_adjustment(black_box(&config), black_box(sig));
                black_box(adj);
            })
        });
    }

    group.finish();
}

fn bench_apply_load_to_loss_matrix(c: &mut Criterion) {
    let mut group = c.benchmark_group("load_aware/apply_to_matrix");

    let policy = Policy::default();

    let adjustments = [
        (
            "no_load",
            LoadAdjustment {
                load_score: 0.0,
                keep_multiplier: 1.0,
                reversible_multiplier: 1.0,
                risky_multiplier: 1.0,
            },
        ),
        (
            "moderate",
            LoadAdjustment {
                load_score: 0.5,
                keep_multiplier: 1.25,
                reversible_multiplier: 0.8,
                risky_multiplier: 1.5,
            },
        ),
        (
            "extreme",
            LoadAdjustment {
                load_score: 1.0,
                keep_multiplier: 1.5,
                reversible_multiplier: 0.5,
                risky_multiplier: 2.0,
            },
        ),
    ];

    for (name, adj) in &adjustments {
        group.bench_with_input(BenchmarkId::new("apply", *name), adj, |b, adjustment| {
            b.iter(|| {
                let adjusted = apply_load_to_loss_matrix(
                    black_box(&policy.loss_matrix),
                    black_box(adjustment),
                );
                black_box(adjusted.useful.kill);
            })
        });
    }

    group.finish();
}

// ── Martingale gate benchmarks ──────────────────────────────────────

fn bench_resolve_alpha(c: &mut Criterion) {
    let mut group = c.benchmark_group("martingale/resolve_alpha");

    let policy = Policy::default();
    group.bench_function("policy_default", |b| {
        b.iter(|| {
            let (alpha, source) = resolve_alpha(black_box(&policy), None).unwrap();
            black_box((alpha, source));
        })
    });

    group.finish();
}

fn bench_apply_martingale_gates(c: &mut Criterion) {
    let mut group = c.benchmark_group("martingale/apply_gates");

    let policy = Policy::default();
    let config = MartingaleGateConfig::default();

    // Build candidate sets of various sizes
    let make_candidates = |n: usize| -> Vec<MartingaleGateCandidate> {
        (0..n)
            .map(|i| {
                let result = if i % 3 == 0 {
                    high_evalue_result()
                } else {
                    low_evalue_result()
                };
                MartingaleGateCandidate {
                    target: TargetIdentity {
                        pid: i as i32,
                        start_id: format!("{i}-start-boot0"),
                        uid: 1000,
                    },
                    result,
                }
            })
            .collect()
    };

    for n in [1, 5, 10, 25] {
        let candidates = make_candidates(n);
        group.bench_with_input(BenchmarkId::new("mixed", n), &candidates, |b, cands| {
            b.iter(|| {
                let summary = apply_martingale_gates(
                    black_box(cands),
                    black_box(&policy),
                    black_box(&config),
                    None,
                )
                .unwrap();
                black_box(summary.results.len());
            })
        });
    }

    // All high-e-value candidates
    for n in [5, 10] {
        let candidates: Vec<MartingaleGateCandidate> = (0..n)
            .map(|i| MartingaleGateCandidate {
                target: TargetIdentity {
                    pid: i as i32,
                    start_id: format!("{i}-start-boot0"),
                    uid: 1000,
                },
                result: high_evalue_result(),
            })
            .collect();

        group.bench_with_input(BenchmarkId::new("all_high", n), &candidates, |b, cands| {
            b.iter(|| {
                let summary = apply_martingale_gates(
                    black_box(cands),
                    black_box(&policy),
                    black_box(&config),
                    None,
                )
                .unwrap();
                black_box(summary.results.len());
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_expected_recovery,
    bench_expected_recovery_by_action,
    bench_apply_outcome,
    bench_compute_load_adjustment,
    bench_apply_load_to_loss_matrix,
    bench_resolve_alpha,
    bench_apply_martingale_gates
);
criterion_main!(benches);
