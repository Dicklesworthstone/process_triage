//! Criterion benchmarks for time-bound stopping, DRO robustness, and dependency-loss scaling.
//!
//! Benchmarks `compute_t_max`, `apply_time_bound`, `compute_wasserstein_dro`,
//! `decide_with_dro`, `compute_impact_score`, `compute_inflation`, and
//! `compute_dependency_scaling` — risk-gating and loss-scaling hotpaths.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use pt_core::collect::{CriticalFile, CriticalFileCategory, DetectionStrength};
use pt_core::config::policy::DecisionTimeBound;
use pt_core::config::Policy;
use pt_core::decision::dependency_loss::{
    compute_dependency_scaling, CriticalFileInflation, DependencyFactors, DependencyScaling,
};
use pt_core::decision::dro::{compute_adaptive_epsilon, compute_wasserstein_dro, decide_with_dro, DroTrigger};
use pt_core::decision::expected_loss::Action;
use pt_core::decision::time_bound::{apply_time_bound, compute_t_max, TMaxInput};
use pt_core::inference::ClassScores;

// ── Time-bound benchmarks ───────────────────────────────────────────

fn bench_compute_t_max(c: &mut Criterion) {
    let mut group = c.benchmark_group("time_bound/compute_t_max");

    let config = DecisionTimeBound::default();

    for (name, voi_initial) in [
        ("zero_voi", 0.0),
        ("low_voi", 0.005),
        ("mid_voi", 0.1),
        ("high_voi", 10.0),
    ] {
        let input = TMaxInput {
            voi_initial,
            overhead_budget_seconds: None,
        };

        group.bench_with_input(BenchmarkId::new("default", name), &input, |b, inp| {
            b.iter(|| {
                let decision = compute_t_max(black_box(&config), black_box(inp));
                black_box(decision.t_max_seconds);
            })
        });
    }

    // With budget override
    for budget in [30u64, 120, 600] {
        let input = TMaxInput {
            voi_initial: 1.0,
            overhead_budget_seconds: Some(budget),
        };

        group.bench_with_input(
            BenchmarkId::new("budget_override", budget),
            &input,
            |b, inp| {
                b.iter(|| {
                    let decision = compute_t_max(black_box(&config), black_box(inp));
                    black_box(decision.t_max_seconds);
                })
            },
        );
    }

    group.finish();
}

fn bench_apply_time_bound(c: &mut Criterion) {
    let mut group = c.benchmark_group("time_bound/apply_time_bound");

    let config = DecisionTimeBound::default();

    for (name, elapsed, t_max, uncertain) in [
        ("early", 30, 120, true),
        ("at_limit", 120, 120, true),
        ("past_limit_uncertain", 180, 120, true),
        ("past_limit_certain", 180, 120, false),
    ] {
        group.bench_function(BenchmarkId::new("check", name), |b| {
            b.iter(|| {
                let outcome = apply_time_bound(
                    black_box(&config),
                    black_box(elapsed),
                    black_box(t_max),
                    black_box(uncertain),
                );
                black_box(outcome.stop_probing);
            })
        });
    }

    group.finish();
}

// ── DRO benchmarks ──────────────────────────────────────────────────

fn abandoned_posterior() -> ClassScores {
    ClassScores {
        useful: 0.05,
        useful_bad: 0.03,
        abandoned: 0.85,
        zombie: 0.07,
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

fn bench_compute_wasserstein_dro(c: &mut Criterion) {
    let mut group = c.benchmark_group("dro/compute_wasserstein_dro");

    let policy = Policy::default();

    for (name, posterior) in [
        ("abandoned", abandoned_posterior()),
        ("ambiguous", ambiguous_posterior()),
    ] {
        for epsilon in [0.0, 0.05, 0.2, 0.5] {
            group.bench_with_input(
                BenchmarkId::new(format!("{}_e{:.2}", name, epsilon), name),
                &posterior,
                |b, post| {
                    b.iter(|| {
                        let result = compute_wasserstein_dro(
                            Action::Kill,
                            black_box(post),
                            black_box(&policy.loss_matrix),
                            epsilon,
                        );
                        black_box(result.unwrap().robust_loss);
                    })
                },
            );
        }
    }

    group.finish();
}

fn bench_decide_with_dro(c: &mut Criterion) {
    let mut group = c.benchmark_group("dro/decide_with_dro");

    let policy = Policy::default();
    let feasible = vec![
        Action::Keep,
        Action::Renice,
        Action::Pause,
        Action::Throttle,
        Action::Restart,
        Action::Kill,
    ];

    for (name, posterior) in [
        ("abandoned", abandoned_posterior()),
        ("ambiguous", ambiguous_posterior()),
    ] {
        for epsilon in [0.05, 0.3] {
            group.bench_with_input(
                BenchmarkId::new(format!("{}_e{:.2}", name, epsilon), name),
                &posterior,
                |b, post| {
                    b.iter(|| {
                        let result = decide_with_dro(
                            black_box(post),
                            black_box(&policy),
                            black_box(&feasible),
                            epsilon,
                            Action::Kill,
                            "benchmark",
                        );
                        black_box(result.unwrap().robust_action);
                    })
                },
            );
        }
    }

    group.finish();
}

fn bench_adaptive_epsilon(c: &mut Criterion) {
    let mut group = c.benchmark_group("dro/adaptive_epsilon");

    let base = 0.1;
    let max = 0.5;

    let triggers = [
        ("none", DroTrigger::none()),
        (
            "ppc",
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
            "multi",
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
        group.bench_with_input(BenchmarkId::new("compute", *name), trigger, |b, t| {
            b.iter(|| {
                black_box(compute_adaptive_epsilon(black_box(base), black_box(t), max));
            })
        });
    }

    group.finish();
}

// ── Dependency loss scaling benchmarks ──────────────────────────────

fn bench_dependency_impact_score(c: &mut Criterion) {
    let mut group = c.benchmark_group("dep_loss/impact_score");

    let scaling = DependencyScaling::default();

    let scenarios = [
        (
            "isolated",
            DependencyFactors::new(0, 0, 0, 0, 0),
        ),
        (
            "moderate",
            DependencyFactors::new(3, 5, 1, 10, 2),
        ),
        (
            "heavy",
            DependencyFactors::new(20, 50, 10, 100, 20),
        ),
        (
            "overflow",
            DependencyFactors::new(200, 500, 100, 1000, 200),
        ),
    ];

    for (name, factors) in &scenarios {
        group.bench_with_input(BenchmarkId::new("compute", *name), factors, |b, f| {
            b.iter(|| {
                black_box(scaling.compute_impact_score(black_box(f)));
            })
        });
    }

    group.finish();
}

fn bench_dependency_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("dep_loss/compute_scaling");

    let factors = DependencyFactors::new(5, 10, 2, 20, 3);

    for base_loss in [10.0, 100.0, 1000.0] {
        group.bench_with_input(
            BenchmarkId::new("scaling", format!("loss_{}", base_loss as u32)),
            &base_loss,
            |b, &loss| {
                b.iter(|| {
                    let result = compute_dependency_scaling(black_box(loss), black_box(&factors), None);
                    black_box(result.scaled_kill_loss);
                })
            },
        );
    }

    group.finish();
}

fn bench_critical_file_inflation(c: &mut Criterion) {
    let mut group = c.benchmark_group("dep_loss/critical_file_inflation");

    let config = CriticalFileInflation::default();

    let make_file = |cat: CriticalFileCategory, str: DetectionStrength| CriticalFile {
        fd: 42,
        path: "/test/path".to_string(),
        category: cat,
        strength: str,
        rule_id: "bench-rule".to_string(),
    };

    let scenarios: Vec<(&str, Vec<CriticalFile>)> = vec![
        ("empty", vec![]),
        (
            "single_hard",
            vec![make_file(CriticalFileCategory::SqliteWal, DetectionStrength::Hard)],
        ),
        (
            "single_soft",
            vec![make_file(CriticalFileCategory::OpenWrite, DetectionStrength::Soft)],
        ),
        (
            "mixed_5",
            vec![
                make_file(CriticalFileCategory::GitLock, DetectionStrength::Hard),
                make_file(CriticalFileCategory::GitRebase, DetectionStrength::Hard),
                make_file(CriticalFileCategory::DatabaseWrite, DetectionStrength::Soft),
                make_file(CriticalFileCategory::OpenWrite, DetectionStrength::Soft),
                make_file(CriticalFileCategory::CargoLock, DetectionStrength::Soft),
            ],
        ),
        (
            "many_hard_20",
            (0..20)
                .map(|_| make_file(CriticalFileCategory::SystemPackageLock, DetectionStrength::Hard))
                .collect(),
        ),
    ];

    for (name, files) in &scenarios {
        group.bench_with_input(BenchmarkId::new("compute", *name), files, |b, f| {
            b.iter(|| {
                black_box(config.compute_inflation(black_box(f)));
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_compute_t_max,
    bench_apply_time_bound,
    bench_compute_wasserstein_dro,
    bench_decide_with_dro,
    bench_adaptive_epsilon,
    bench_dependency_impact_score,
    bench_dependency_scaling,
    bench_critical_file_inflation
);
criterion_main!(benches);
