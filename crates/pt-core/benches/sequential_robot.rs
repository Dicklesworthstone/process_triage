//! Criterion benchmarks for sequential stopping and robot constraint checking.
//!
//! Benchmarks `decide_sequential`, `prioritize_by_esn`, and
//! `ConstraintChecker::check_candidate` — decision-orchestration hotpaths.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use pt_core::config::policy::RobotMode;
use pt_core::config::Policy;
use pt_core::decision::expected_loss::ActionFeasibility;
use pt_core::decision::robot_constraints::{
    ConstraintChecker, RobotCandidate, RuntimeRobotConstraints,
};
use pt_core::decision::sequential::{decide_sequential, prioritize_by_esn, EsnCandidate};
use pt_core::decision::voi::{ProbeCostModel, ProbeType};
use pt_core::inference::ClassScores;

// ── Posteriors ───────────────────────────────────────────────────────────

fn uncertain_posterior() -> ClassScores {
    ClassScores {
        useful: 0.4,
        useful_bad: 0.1,
        abandoned: 0.4,
        zombie: 0.1,
    }
}

fn confident_useful_posterior() -> ClassScores {
    ClassScores {
        useful: 0.95,
        useful_bad: 0.02,
        abandoned: 0.02,
        zombie: 0.01,
    }
}

fn confident_zombie_posterior() -> ClassScores {
    ClassScores {
        useful: 0.01,
        useful_bad: 0.01,
        abandoned: 0.03,
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

// ── Sequential stopping benchmarks ──────────────────────────────────────

fn bench_decide_sequential(c: &mut Criterion) {
    let mut group = c.benchmark_group("sequential/decide_sequential");

    let policy = Policy::default();
    let cost_model = ProbeCostModel::default();
    let feasibility = ActionFeasibility::allow_all();

    for (name, posterior) in [
        ("uncertain", uncertain_posterior()),
        ("confident_useful", confident_useful_posterior()),
        ("confident_zombie", confident_zombie_posterior()),
        ("ambiguous", ambiguous_posterior()),
    ] {
        // All probes available
        group.bench_with_input(
            BenchmarkId::new("all_probes", name),
            &posterior,
            |b, post| {
                b.iter(|| {
                    let (decision, _ledger) = decide_sequential(
                        black_box(post),
                        black_box(&policy),
                        black_box(&feasibility),
                        black_box(&cost_model),
                        None,
                    )
                    .unwrap();
                    black_box(decision.should_probe);
                })
            },
        );

        // Single probe available
        group.bench_with_input(
            BenchmarkId::new("single_probe", name),
            &posterior,
            |b, post| {
                b.iter(|| {
                    let (decision, _ledger) = decide_sequential(
                        black_box(post),
                        black_box(&policy),
                        black_box(&feasibility),
                        black_box(&cost_model),
                        Some(&[ProbeType::QuickScan]),
                    )
                    .unwrap();
                    black_box(decision.should_probe);
                })
            },
        );
    }

    group.finish();
}

fn bench_prioritize_by_esn(c: &mut Criterion) {
    let mut group = c.benchmark_group("sequential/prioritize_by_esn");

    let policy = Policy::default();
    let cost_model = ProbeCostModel::default();
    let feasibility = ActionFeasibility::allow_all();

    let posteriors = [
        uncertain_posterior(),
        confident_useful_posterior(),
        confident_zombie_posterior(),
        ambiguous_posterior(),
    ];

    for n in [5, 10, 20] {
        let candidates: Vec<EsnCandidate> = (0..n)
            .map(|i| {
                EsnCandidate::new(
                    format!("pid-{}", i),
                    posteriors[i % posteriors.len()],
                    feasibility.clone(),
                    vec![ProbeType::QuickScan, ProbeType::DeepScan],
                )
            })
            .collect();

        group.bench_with_input(
            BenchmarkId::new("mixed", n),
            &candidates,
            |b, cands| {
                b.iter(|| {
                    let ranked = prioritize_by_esn(
                        black_box(cands),
                        black_box(&policy),
                        black_box(&cost_model),
                    )
                    .unwrap();
                    black_box(ranked.len());
                })
            },
        );
    }

    group.finish();
}

// ── Robot constraint checking benchmarks ─────────────────────────────────

fn enabled_robot_mode() -> RobotMode {
    RobotMode {
        enabled: true,
        min_posterior: 0.95,
        min_confidence: None,
        max_blast_radius_mb: 1024.0,
        max_kills: 10,
        require_known_signature: false,
        require_policy_snapshot: None,
        allow_categories: Vec::new(),
        exclude_categories: Vec::new(),
        require_human_for_supervised: true,
    }
}

fn strict_robot_mode() -> RobotMode {
    RobotMode {
        enabled: true,
        min_posterior: 0.99,
        min_confidence: None,
        max_blast_radius_mb: 512.0,
        max_kills: 3,
        require_known_signature: true,
        require_policy_snapshot: Some(true),
        allow_categories: vec!["test".to_string(), "dev".to_string()],
        exclude_categories: vec!["daemon".to_string(), "system".to_string()],
        require_human_for_supervised: true,
    }
}

fn bench_check_candidate(c: &mut Criterion) {
    let mut group = c.benchmark_group("robot/check_candidate");

    // Allowed candidate (passes all checks)
    let passing_candidate = RobotCandidate::new()
        .with_posterior(0.98)
        .with_memory_mb(500.0)
        .with_known_signature(true)
        .with_policy_snapshot(true)
        .with_category("test")
        .with_kill_action(true);

    // Failing candidate (fails multiple checks)
    let failing_candidate = RobotCandidate::new()
        .with_posterior(0.50)
        .with_memory_mb(2000.0)
        .with_known_signature(false)
        .with_policy_snapshot(false)
        .with_category("daemon")
        .with_kill_action(true)
        .with_supervised(true);

    for (mode_name, robot_mode) in [
        ("default", enabled_robot_mode()),
        ("strict", strict_robot_mode()),
    ] {
        let constraints = RuntimeRobotConstraints::from_policy(&robot_mode)
            .with_max_total_blast_radius_mb(Some(4096.0));
        let checker = ConstraintChecker::new(constraints);

        group.bench_with_input(
            BenchmarkId::new(format!("{}_pass", mode_name), mode_name),
            &passing_candidate,
            |b, cand| {
                b.iter(|| {
                    let result = checker.check_candidate(black_box(cand));
                    black_box(result.allowed);
                })
            },
        );

        group.bench_with_input(
            BenchmarkId::new(format!("{}_fail", mode_name), mode_name),
            &failing_candidate,
            |b, cand| {
                b.iter(|| {
                    let result = checker.check_candidate(black_box(cand));
                    black_box(result.violations.len());
                })
            },
        );
    }

    group.finish();
}

fn bench_check_candidate_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("robot/check_candidate_batch");

    let constraints = RuntimeRobotConstraints::from_policy(&enabled_robot_mode())
        .with_max_total_blast_radius_mb(Some(10000.0));

    for n in [10, 25, 50] {
        let candidates: Vec<RobotCandidate> = (0..n)
            .map(|i| {
                let posterior = 0.90 + (i % 10) as f64 * 0.01;
                let memory_mb = 50.0 + (i % 20) as f64 * 30.0;
                let is_kill = i % 3 == 0;
                RobotCandidate::new()
                    .with_posterior(posterior)
                    .with_memory_mb(memory_mb)
                    .with_known_signature(i % 4 != 0)
                    .with_kill_action(is_kill)
            })
            .collect();

        group.bench_with_input(
            BenchmarkId::new("batch", n),
            &candidates,
            |b, cands| {
                b.iter(|| {
                    let checker = ConstraintChecker::new(constraints.clone());
                    let mut allowed = 0u32;
                    for cand in black_box(cands) {
                        let result = checker.check_candidate(cand);
                        if result.allowed {
                            allowed += 1;
                            if cand.is_kill_action {
                                checker.record_action(
                                    (cand.memory_mb.unwrap_or(0.0) * 1024.0 * 1024.0) as u64,
                                    true,
                                );
                            }
                        }
                    }
                    black_box(allowed);
                })
            },
        );
    }

    group.finish();
}

fn bench_constraint_summary(c: &mut Criterion) {
    let mut group = c.benchmark_group("robot/constraint_summary");

    for (name, robot_mode) in [
        ("default", enabled_robot_mode()),
        ("strict", strict_robot_mode()),
    ] {
        let constraints = RuntimeRobotConstraints::from_policy(&robot_mode)
            .with_max_total_blast_radius_mb(Some(4096.0));

        group.bench_with_input(
            BenchmarkId::new("summary", name),
            &constraints,
            |b, cons| {
                b.iter(|| {
                    let summary = black_box(cons).active_constraints_summary();
                    black_box(summary.len());
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_decide_sequential,
    bench_prioritize_by_esn,
    bench_check_candidate,
    bench_check_candidate_batch,
    bench_constraint_summary
);
criterion_main!(benches);
