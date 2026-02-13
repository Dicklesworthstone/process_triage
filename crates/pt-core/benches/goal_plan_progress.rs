//! Criterion benchmarks for goal-aware plan optimization and post-action progress measurement.
//!
//! Benchmarks `optimize_goal_plan` (greedy selection across three plan variants)
//! and `measure_progress` (observed vs expected delta classification)
//! — goal-optimizer hotpaths.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use pt_core::decision::goal_plan::{optimize_goal_plan, PlanCandidate, PlanConstraints};
use pt_core::decision::goal_progress::{
    measure_progress, ActionOutcome, GoalMetric, MetricSnapshot, ProgressConfig,
};

// ── Helpers ──────────────────────────────────────────────────────────

fn make_candidates(n: usize) -> Vec<PlanCandidate> {
    (0..n)
        .map(|i| PlanCandidate {
            pid: i as u32 + 1,
            expected_contribution: 50.0 + (i as f64 * 30.0) % 200.0,
            confidence: 0.5 + (i as f64 * 0.07) % 0.45,
            risk: 0.5 + (i as f64 * 0.3) % 3.0,
            is_protected: i % 7 == 0 && i > 0, // ~1 in 7 protected
            uid: 1000 + (i as u32 / 3),
            label: format!("proc-{}", i),
        })
        .collect()
}

fn make_before() -> MetricSnapshot {
    MetricSnapshot {
        available_memory_bytes: 2_000_000_000,
        total_cpu_frac: 0.8,
        occupied_ports: vec![3000, 8080, 9090],
        total_fds: 5000,
        timestamp: 1000.0,
    }
}

fn make_outcomes(n: usize, expected_each: f64) -> Vec<ActionOutcome> {
    (0..n)
        .map(|i| ActionOutcome {
            pid: i as u32 + 1,
            label: format!("proc-{}", i),
            success: i % 5 != 0,          // 80% success
            respawn_detected: i % 4 == 0, // 25% respawn
            expected_contribution: expected_each,
        })
        .collect()
}

// ── Goal plan benchmarks ─────────────────────────────────────────────

fn bench_optimize_goal_plan(c: &mut Criterion) {
    let mut group = c.benchmark_group("goal_plan/optimize");

    // Vary number of candidates
    for n in [5, 10, 25, 50] {
        let candidates = make_candidates(n);
        let constraints = PlanConstraints {
            goal_target: 500.0,
            ..Default::default()
        };

        group.bench_with_input(
            BenchmarkId::new("candidates", n),
            &candidates,
            |b, cands| {
                b.iter(|| {
                    let plans = optimize_goal_plan(black_box(cands), black_box(&constraints));
                    black_box(plans.len());
                })
            },
        );
    }

    // Vary goal target (easy vs hard)
    let candidates = make_candidates(20);
    for target in [100.0, 500.0, 2000.0, 10000.0] {
        let constraints = PlanConstraints {
            goal_target: target,
            ..Default::default()
        };

        group.bench_with_input(
            BenchmarkId::new("target", target as u32),
            &candidates,
            |b, cands| {
                b.iter(|| {
                    let plans = optimize_goal_plan(black_box(cands), black_box(&constraints));
                    black_box(plans.len());
                })
            },
        );
    }

    group.finish();
}

fn bench_optimize_constrained(c: &mut Criterion) {
    let mut group = c.benchmark_group("goal_plan/constrained");

    let candidates = make_candidates(30);

    // Tight risk budget
    group.bench_function("tight_risk", |b| {
        let constraints = PlanConstraints {
            goal_target: 500.0,
            max_total_risk: 2.0,
            ..Default::default()
        };
        b.iter(|| {
            let plans = optimize_goal_plan(black_box(&candidates), black_box(&constraints));
            black_box(plans.len());
        })
    });

    // Few actions allowed
    group.bench_function("max_actions_3", |b| {
        let constraints = PlanConstraints {
            goal_target: 500.0,
            max_actions: 3,
            ..Default::default()
        };
        b.iter(|| {
            let plans = optimize_goal_plan(black_box(&candidates), black_box(&constraints));
            black_box(plans.len());
        })
    });

    // Same-UID filter
    group.bench_function("same_uid", |b| {
        let constraints = PlanConstraints {
            goal_target: 500.0,
            same_uid: Some(1000),
            ..Default::default()
        };
        b.iter(|| {
            let plans = optimize_goal_plan(black_box(&candidates), black_box(&constraints));
            black_box(plans.len());
        })
    });

    // High confidence threshold
    group.bench_function("high_confidence", |b| {
        let constraints = PlanConstraints {
            goal_target: 500.0,
            min_confidence: 0.8,
            ..Default::default()
        };
        b.iter(|| {
            let plans = optimize_goal_plan(black_box(&candidates), black_box(&constraints));
            black_box(plans.len());
        })
    });

    group.finish();
}

// ── Goal progress benchmarks ─────────────────────────────────────────

fn bench_measure_progress(c: &mut Criterion) {
    let mut group = c.benchmark_group("goal_progress/measure");

    let config = ProgressConfig::default();
    let before = make_before();

    // Memory: good outcome
    let after_good = MetricSnapshot {
        available_memory_bytes: 3_000_000_000,
        total_cpu_frac: 0.5,
        occupied_ports: vec![8080],
        total_fds: 4500,
        timestamp: 1010.0,
    };

    for (name, metric, target_port, after, outcomes) in [
        (
            "memory_good",
            GoalMetric::Memory,
            None,
            after_good.clone(),
            make_outcomes(3, 300_000_000.0),
        ),
        (
            "cpu_good",
            GoalMetric::Cpu,
            None,
            after_good.clone(),
            make_outcomes(3, 0.1),
        ),
        (
            "port_released",
            GoalMetric::Port,
            Some(3000u16),
            after_good.clone(),
            make_outcomes(1, 1.0),
        ),
        (
            "fd_good",
            GoalMetric::FileDescriptors,
            None,
            after_good.clone(),
            make_outcomes(3, 150.0),
        ),
    ] {
        group.bench_function(BenchmarkId::new("metric", name), |b| {
            b.iter(|| {
                let report = measure_progress(
                    black_box(metric),
                    black_box(target_port),
                    black_box(&before),
                    black_box(&after),
                    black_box(outcomes.clone()),
                    black_box(&config),
                    None,
                );
                black_box(report.classification);
            })
        });
    }

    // Vary outcome count
    for n in [1, 5, 10, 20] {
        let after = MetricSnapshot {
            available_memory_bytes: 3_000_000_000,
            ..make_before()
        };
        let outcomes = make_outcomes(n, 1_000_000_000.0 / n as f64);

        group.bench_with_input(BenchmarkId::new("outcomes", n), &outcomes, |b, outs| {
            b.iter(|| {
                let report = measure_progress(
                    GoalMetric::Memory,
                    None,
                    black_box(&before),
                    black_box(&after),
                    black_box(outs.clone()),
                    black_box(&config),
                    None,
                );
                black_box(report.classification);
            })
        });
    }

    // Discrepancy scenarios
    let no_change = MetricSnapshot {
        available_memory_bytes: 2_000_000_000,
        ..make_before()
    };
    let overperform = MetricSnapshot {
        available_memory_bytes: 5_000_000_000,
        ..make_before()
    };

    for (name, after, outcomes) in [
        ("no_effect", no_change, make_outcomes(3, 1_000_000_000.0)),
        (
            "overperformance",
            overperform,
            make_outcomes(3, 500_000_000.0),
        ),
    ] {
        group.bench_function(BenchmarkId::new("discrepancy", name), |b| {
            b.iter(|| {
                let report = measure_progress(
                    GoalMetric::Memory,
                    None,
                    black_box(&before),
                    black_box(&after),
                    black_box(outcomes.clone()),
                    black_box(&config),
                    None,
                );
                black_box(report.classification);
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_optimize_goal_plan,
    bench_optimize_constrained,
    bench_measure_progress
);
criterion_main!(benches);
