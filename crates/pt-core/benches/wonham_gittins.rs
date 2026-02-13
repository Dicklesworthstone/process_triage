//! Criterion benchmarks for Wonham filtering and Gittins index scheduling.
//!
//! Benchmarks the hotpaths used to maintain continuous-time belief states
//! and compute optimal scheduling indices for probe prioritization.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use pt_core::config::Policy;
use pt_core::decision::expected_loss::ActionFeasibility;
use pt_core::decision::wonham_gittins::{
    compute_gittins_index, compute_gittins_schedule, GeneratorMatrix, GittinsCandidate,
    WonhamConfig, WonhamFilter,
};
use pt_core::inference::belief_state::{BeliefState, ObservationLikelihood, TransitionModel};

// ── Belief fixtures ─────────────────────────────────────────────────────

fn abandoned_belief() -> BeliefState {
    BeliefState::from_probs([0.05, 0.03, 0.85, 0.07]).unwrap()
}

fn ambiguous_belief() -> BeliefState {
    BeliefState::from_probs([0.30, 0.15, 0.40, 0.15]).unwrap()
}

fn confident_belief() -> BeliefState {
    BeliefState::from_probs([0.95, 0.02, 0.02, 0.01]).unwrap()
}

fn zombie_belief() -> BeliefState {
    BeliefState::from_probs([0.02, 0.01, 0.05, 0.92]).unwrap()
}

// ── Generator Matrix ────────────────────────────────────────────────────

fn bench_generator_construction(c: &mut Criterion) {
    let transition = TransitionModel::default_lifecycle();
    let mut group = c.benchmark_group("wonham/generator");

    group.bench_function("from_transition_tau60", |b| {
        b.iter(|| {
            let g = GeneratorMatrix::from_transition(black_box(&transition), black_box(60.0));
            black_box(g.unwrap());
        })
    });

    let gen = GeneratorMatrix::default();

    group.bench_function("to_transition_euler", |b| {
        b.iter(|| {
            let t = gen.to_transition(black_box(30.0));
            black_box(t.unwrap());
        })
    });

    group.bench_function("to_transition_exp_12terms", |b| {
        b.iter(|| {
            let t = gen.to_transition_exp(black_box(30.0), black_box(12));
            black_box(t.unwrap());
        })
    });

    for dt in [1.0, 30.0, 120.0] {
        group.bench_with_input(
            BenchmarkId::new("to_transition_exp_varied_dt", dt as u64),
            &dt,
            |b, &dt| {
                b.iter(|| {
                    let t = gen.to_transition_exp(black_box(dt), 12);
                    black_box(t.unwrap());
                })
            },
        );
    }

    group.finish();
}

// ── Wonham Filter ───────────────────────────────────────────────────────

fn bench_wonham_predict(c: &mut Criterion) {
    let filter = WonhamFilter::new(WonhamConfig::default(), GeneratorMatrix::default());
    let filter_exp = WonhamFilter::new(
        WonhamConfig {
            use_matrix_exp: true,
            ..WonhamConfig::default()
        },
        GeneratorMatrix::default(),
    );

    let mut group = c.benchmark_group("wonham/predict");

    for (name, belief) in [
        ("abandoned", abandoned_belief()),
        ("ambiguous", ambiguous_belief()),
        ("confident", confident_belief()),
        ("zombie", zombie_belief()),
    ] {
        group.bench_with_input(
            BenchmarkId::new("euler", name),
            &belief,
            |b, belief| {
                b.iter(|| {
                    let p = filter.predict(black_box(belief), black_box(30.0));
                    black_box(p.unwrap());
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new("matrix_exp", name),
            &belief,
            |b, belief| {
                b.iter(|| {
                    let p = filter_exp.predict(black_box(belief), black_box(30.0));
                    black_box(p.unwrap());
                })
            },
        );
    }

    group.finish();
}

fn bench_wonham_filter_step(c: &mut Criterion) {
    let filter = WonhamFilter::new(WonhamConfig::default(), GeneratorMatrix::default());

    // Observation that mildly suggests abandoned (high idle likelihood)
    let obs = ObservationLikelihood::from_likelihoods([0.2, 0.3, 0.8, 0.6]).unwrap();

    let mut group = c.benchmark_group("wonham/filter_step");

    for (name, belief) in [
        ("abandoned", abandoned_belief()),
        ("ambiguous", ambiguous_belief()),
        ("confident", confident_belief()),
    ] {
        group.bench_with_input(BenchmarkId::new("step", name), &belief, |b, belief| {
            b.iter(|| {
                let r = filter.filter_step(black_box(belief), black_box(30.0), black_box(&obs));
                black_box(r.unwrap());
            })
        });
    }

    group.finish();
}

fn bench_wonham_filter_sequence(c: &mut Criterion) {
    let filter = WonhamFilter::new(WonhamConfig::default(), GeneratorMatrix::default());

    let make_steps = |n: usize| -> Vec<(f64, ObservationLikelihood)> {
        (0..n)
            .map(|i| {
                let t = 10.0 + (i % 5) as f64 * 5.0;
                let obs = ObservationLikelihood::from_likelihoods([
                    0.2 + (i % 3) as f64 * 0.1,
                    0.3,
                    0.7 - (i % 4) as f64 * 0.05,
                    0.5,
                ])
                .unwrap();
                (t, obs)
            })
            .collect()
    };

    let mut group = c.benchmark_group("wonham/filter_sequence");

    for n in [5, 10, 30] {
        let steps = make_steps(n);
        group.bench_with_input(BenchmarkId::new("steps", n), &steps, |b, steps| {
            b.iter(|| {
                let r = filter.filter_sequence(black_box(&ambiguous_belief()), black_box(steps));
                black_box(r.unwrap());
            })
        });
    }

    group.finish();
}

// ── Gittins Index ───────────────────────────────────────────────────────

fn bench_gittins_index(c: &mut Criterion) {
    let policy = Policy::default();
    let transition = TransitionModel::default_lifecycle();
    let feasibility = ActionFeasibility::allow_all();

    let mut group = c.benchmark_group("wonham/gittins_index");

    for (name, belief) in [
        ("abandoned", abandoned_belief()),
        ("ambiguous", ambiguous_belief()),
        ("confident", confident_belief()),
        ("zombie", zombie_belief()),
    ] {
        // Default horizon (10)
        group.bench_with_input(
            BenchmarkId::new("h10", name),
            &belief,
            |b, belief| {
                b.iter(|| {
                    let config = WonhamConfig::default();
                    let r = compute_gittins_index(
                        black_box(belief),
                        black_box(&feasibility),
                        black_box(&transition),
                        black_box(&policy.loss_matrix),
                        black_box(&config),
                    );
                    black_box(r.unwrap());
                })
            },
        );

        // Short horizon (3)
        group.bench_with_input(
            BenchmarkId::new("h3", name),
            &belief,
            |b, belief| {
                b.iter(|| {
                    let config = WonhamConfig {
                        horizon: 3,
                        ..WonhamConfig::default()
                    };
                    let r = compute_gittins_index(
                        black_box(belief),
                        black_box(&feasibility),
                        black_box(&transition),
                        black_box(&policy.loss_matrix),
                        black_box(&config),
                    );
                    black_box(r.unwrap());
                })
            },
        );
    }

    group.finish();
}

fn bench_gittins_schedule(c: &mut Criterion) {
    let policy = Policy::default();
    let transition = TransitionModel::default_lifecycle();

    let make_candidates = |n: usize| -> Vec<GittinsCandidate> {
        (0..n)
            .map(|i| {
                let useful = (10 + (i % 60)) as f64 / 100.0;
                let useful_bad = ((i % 15) + 1) as f64 / 100.0;
                let abandoned = (85.0 - useful * 100.0 - useful_bad * 100.0).max(5.0) / 100.0;
                let zombie = (1.0 - useful - useful_bad - abandoned).max(0.01);

                GittinsCandidate {
                    id: format!("pid_{}", i),
                    belief: BeliefState::from_probs([useful, useful_bad, abandoned, zombie])
                        .unwrap(),
                    feasibility: ActionFeasibility::allow_all(),
                    available_probes: vec![],
                }
            })
            .collect()
    };

    let mut group = c.benchmark_group("wonham/gittins_schedule");

    for n in [5, 10, 25, 50] {
        let candidates = make_candidates(n);
        let config = WonhamConfig::default();

        group.bench_with_input(
            BenchmarkId::new("h10", n),
            &candidates,
            |b, candidates| {
                b.iter(|| {
                    let sched = compute_gittins_schedule(
                        black_box(candidates),
                        black_box(&config),
                        black_box(&transition),
                        black_box(&policy.loss_matrix),
                    );
                    black_box(sched.unwrap().allocations.len());
                })
            },
        );
    }

    // Short horizon for large candidate set
    let candidates = make_candidates(50);
    let short_config = WonhamConfig {
        horizon: 3,
        ..WonhamConfig::default()
    };
    group.bench_with_input(
        BenchmarkId::new("h3", 50),
        &candidates,
        |b, candidates| {
            b.iter(|| {
                let sched = compute_gittins_schedule(
                    black_box(candidates),
                    black_box(&short_config),
                    black_box(&transition),
                    black_box(&policy.loss_matrix),
                );
                black_box(sched.unwrap().allocations.len());
            })
        },
    );

    group.finish();
}

criterion_group!(
    benches,
    bench_generator_construction,
    bench_wonham_predict,
    bench_wonham_filter_step,
    bench_wonham_filter_sequence,
    bench_gittins_index,
    bench_gittins_schedule
);
criterion_main!(benches);
