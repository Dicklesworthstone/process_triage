//! Criterion benchmarks for goal optimizer hot paths in `pt-core`.
//!
//! Benchmarks `optimize_greedy` and `optimize_dp` at varying candidate set
//! sizes to characterise scaling behaviour.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use pt_core::decision::goal_optimizer::{
    local_search_improve, optimize_dp, optimize_greedy, OptCandidate, ResourceGoal,
};

fn make_goals(n: usize) -> Vec<ResourceGoal> {
    (0..n)
        .map(|i| ResourceGoal {
            resource: format!("resource_{}", i),
            target: 500.0 + (i as f64) * 100.0,
            weight: 1.0,
        })
        .collect()
}

fn make_candidates(n: usize, goal_count: usize) -> Vec<OptCandidate> {
    (0..n)
        .map(|i| OptCandidate {
            id: format!("pid_{}", i),
            expected_loss: ((i % 20) + 1) as f64 * 0.05,
            contributions: (0..goal_count)
                .map(|g| ((i + g) % 15 + 1) as f64 * 10.0)
                .collect(),
            blocked: false,
            block_reason: None,
        })
        .collect()
}

fn bench_optimize_greedy(c: &mut Criterion) {
    let mut group = c.benchmark_group("goal_optimizer/greedy");

    for n in [10, 30, 100] {
        let goals = make_goals(1);
        let candidates = make_candidates(n, 1);

        group.bench_with_input(
            BenchmarkId::new("single_goal", n),
            &(&candidates, &goals),
            |b, (cands, gs)| {
                b.iter(|| {
                    let result = optimize_greedy(black_box(cands), black_box(gs));
                    black_box(result.total_loss);
                })
            },
        );
    }

    // Multi-goal variant
    for n in [10, 30, 100] {
        let goals = make_goals(3);
        let candidates = make_candidates(n, 3);

        group.bench_with_input(
            BenchmarkId::new("multi_goal_3", n),
            &(&candidates, &goals),
            |b, (cands, gs)| {
                b.iter(|| {
                    let result = optimize_greedy(black_box(cands), black_box(gs));
                    black_box(result.total_loss);
                })
            },
        );
    }

    group.finish();
}

fn bench_optimize_dp(c: &mut Criterion) {
    let mut group = c.benchmark_group("goal_optimizer/dp");

    // DP is intended for small candidate sets (N ≤ 30).
    for n in [5, 10, 20, 30] {
        let goals = make_goals(1);
        let candidates = make_candidates(n, 1);

        group.bench_with_input(
            BenchmarkId::new("single_goal", n),
            &(&candidates, &goals),
            |b, (cands, gs)| {
                b.iter(|| {
                    let result = optimize_dp(black_box(cands), black_box(gs), 1.0);
                    black_box(result.total_loss);
                })
            },
        );
    }

    group.finish();
}

fn bench_local_search(c: &mut Criterion) {
    let mut group = c.benchmark_group("goal_optimizer/local_search");

    for n in [30, 100] {
        let goals = make_goals(1);
        let candidates = make_candidates(n, 1);

        group.bench_with_input(
            BenchmarkId::new("improve_greedy", n),
            &(&candidates, &goals),
            |b, (cands, gs)| {
                b.iter(|| {
                    let mut result = optimize_greedy(cands, gs);
                    local_search_improve(&mut result, black_box(cands), black_box(gs), 50);
                    black_box(result.total_loss);
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_optimize_greedy,
    bench_optimize_dp,
    bench_local_search
);
criterion_main!(benches);
