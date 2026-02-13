//! Criterion benchmarks for the myopic policy decision path in `pt-core`.
//!
//! Benchmarks `decide_action`, `decide_from_belief`, and `compute_loss_table`
//! which are called for every process candidate during triage.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use pt_core::config::Policy;
use pt_core::decision::expected_loss::{ActionFeasibility, DecisionOutcome};
use pt_core::decision::myopic_policy::{compute_loss_table, decide_from_belief, MyopicDecision};
use pt_core::decision::{decide_action, Action};
use pt_core::inference::belief_state::BeliefState;
use pt_core::inference::ClassScores;

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

fn useful_posterior() -> ClassScores {
    ClassScores {
        useful: 0.80,
        useful_bad: 0.10,
        abandoned: 0.05,
        zombie: 0.05,
    }
}

fn bench_decide_action(c: &mut Criterion) {
    let policy = Policy::default();
    let feasibility = ActionFeasibility::allow_all();

    let mut group = c.benchmark_group("decision/decide_action");

    for (name, posterior) in [
        ("abandoned", abandoned_posterior()),
        ("ambiguous", ambiguous_posterior()),
        ("useful", useful_posterior()),
    ] {
        group.bench_with_input(BenchmarkId::new("single", name), &posterior, |b, post| {
            b.iter(|| {
                let result: Result<DecisionOutcome, _> =
                    decide_action(black_box(post), black_box(&policy), &feasibility);
                black_box(result.unwrap().optimal_action);
            })
        });
    }

    // Batch: decide for 1000 varied candidates
    let posteriors: Vec<ClassScores> = (0..1000)
        .map(|i| {
            let useful = (30 + (i % 60)) as f64 / 100.0;
            let useful_bad = ((i % 20) + 1) as f64 / 100.0;
            let abandoned = (100.0 - useful * 100.0 - useful_bad * 100.0 - 5.0).max(1.0) / 100.0;
            let zombie = 1.0 - useful - useful_bad - abandoned;
            ClassScores {
                useful,
                useful_bad,
                abandoned,
                zombie: zombie.max(0.001),
            }
        })
        .collect();

    group.bench_with_input(BenchmarkId::new("batch", 1000), &posteriors, |b, posts| {
        b.iter(|| {
            let mut kills = 0u32;
            for post in posts.iter() {
                if let Ok(outcome) = decide_action(post, &policy, &feasibility) {
                    if outcome.optimal_action == Action::Kill {
                        kills += 1;
                    }
                }
            }
            black_box(kills);
        })
    });

    group.finish();
}

fn bench_myopic_decide_from_belief(c: &mut Criterion) {
    let policy = Policy::default();
    let feasibility = ActionFeasibility::allow_all();

    let mut group = c.benchmark_group("decision/myopic_decide_from_belief");

    for (name, probs) in [
        ("abandoned", [0.05, 0.03, 0.85, 0.07]),
        ("ambiguous", [0.30, 0.15, 0.40, 0.15]),
        ("useful", [0.80, 0.10, 0.05, 0.05]),
    ] {
        let belief = BeliefState::from_probs(probs).unwrap();

        group.bench_with_input(BenchmarkId::new("single", name), &belief, |b, bel| {
            b.iter(|| {
                let result: Result<MyopicDecision, _> =
                    decide_from_belief(black_box(bel), black_box(&policy), &feasibility);
                black_box(result.unwrap().optimal_action);
            })
        });
    }

    group.finish();
}

fn bench_compute_loss_table(c: &mut Criterion) {
    let policy = Policy::default();
    let feasibility = ActionFeasibility::allow_all();

    let belief = BeliefState::from_probs([0.10, 0.05, 0.75, 0.10]).unwrap();

    let mut group = c.benchmark_group("decision/compute_loss_table");

    group.bench_function("full_table", |b| {
        b.iter(|| {
            let table = compute_loss_table(
                black_box(&belief),
                black_box(&policy.loss_matrix),
                &feasibility,
            );
            black_box(table.len());
        })
    });

    // With zombie feasibility constraints (some actions disabled)
    let constrained = ActionFeasibility::from_process_state(true, false, None);
    group.bench_function("zombie_constrained", |b| {
        b.iter(|| {
            let table = compute_loss_table(
                black_box(&belief),
                black_box(&policy.loss_matrix),
                &constrained,
            );
            black_box(table.len());
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_decide_action,
    bench_myopic_decide_from_belief,
    bench_compute_loss_table
);
criterion_main!(benches);
