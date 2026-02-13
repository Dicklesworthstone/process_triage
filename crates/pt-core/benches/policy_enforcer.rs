//! Criterion benchmarks for policy enforcement hot paths in `pt-core`.
//!
//! Benchmarks `PolicyEnforcer::check_action` with varying candidate profiles
//! and policy complexity.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use pt_core::config::Policy;
use pt_core::decision::{Action, PolicyEnforcer, ProcessCandidate};

fn simple_candidate(pid: i32) -> ProcessCandidate {
    ProcessCandidate {
        pid,
        ppid: 1,
        cmdline: format!("/usr/bin/node app-{}.js", pid),
        user: Some("appuser".to_string()),
        group: Some("appgroup".to_string()),
        category: Some("application".to_string()),
        age_seconds: 7200,
        posterior: Some(0.92),
        memory_mb: Some(256.0),
        has_known_signature: true,
        open_write_fds: Some(2),
        has_locked_files: Some(false),
        has_active_tty: Some(false),
        seconds_since_io: Some(600),
        cwd_deleted: Some(false),
        process_state: None,
        wchan: None,
        critical_files: vec![],
    }
}

fn bench_check_action_single(c: &mut Criterion) {
    let policy = Policy::default();
    let enforcer = PolicyEnforcer::new(&policy, None).expect("default policy should compile");

    let mut group = c.benchmark_group("policy_enforcer/check_action");

    // Baseline: allowed kill
    let candidate = simple_candidate(1234);
    group.bench_function("allowed_kill", |b| {
        b.iter(|| {
            let result =
                enforcer.check_action(black_box(&candidate), black_box(Action::Kill), false);
            black_box(result.allowed);
        })
    });

    // Robot mode kill
    group.bench_function("robot_mode_kill", |b| {
        b.iter(|| {
            let result =
                enforcer.check_action(black_box(&candidate), black_box(Action::Kill), true);
            black_box(result.allowed);
        })
    });

    // Non-destructive action (Keep)
    group.bench_function("keep_action", |b| {
        b.iter(|| {
            let result =
                enforcer.check_action(black_box(&candidate), black_box(Action::Keep), false);
            black_box(result.allowed);
        })
    });

    group.finish();
}

fn bench_check_action_batch(c: &mut Criterion) {
    let policy = Policy::default();
    let enforcer = PolicyEnforcer::new(&policy, None).expect("default policy should compile");

    let candidates: Vec<ProcessCandidate> = (0..1000)
        .map(|i| {
            let mut c = simple_candidate(1000 + i);
            c.cmdline = format!("/usr/bin/worker-{}", i);
            c.posterior = Some(0.5 + ((i % 50) as f64) * 0.01);
            c.memory_mb = Some(((i % 200) + 50) as f64);
            c.age_seconds = ((i % 100) + 1) as u64 * 60;
            c.has_known_signature = i % 3 != 0;
            c
        })
        .collect();

    let mut group = c.benchmark_group("policy_enforcer/batch");

    group.bench_with_input(
        BenchmarkId::new("check_1k_kills", 1000),
        &candidates,
        |b, cands| {
            b.iter(|| {
                let mut allowed = 0u32;
                for cand in cands.iter() {
                    let result = enforcer.check_action(cand, Action::Kill, false);
                    if result.allowed {
                        allowed += 1;
                    }
                }
                black_box(allowed);
            })
        },
    );

    group.finish();
}

criterion_group!(benches, bench_check_action_single, bench_check_action_batch);
criterion_main!(benches);
