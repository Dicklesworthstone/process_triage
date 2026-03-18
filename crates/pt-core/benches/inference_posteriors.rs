//! Criterion benchmarks for the Bayesian posterior hot path in `pt-core`.
//!
//! These benchmarks intentionally avoid scanning real processes so they can run
//! deterministically in CI and on developer machines.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use pt_core::config::Priors;
use pt_core::inference::posterior::{compute_posterior, CpuEvidence, Evidence};

fn example_evidence_idle_orphan() -> Evidence {
    Evidence {
        cpu: Some(CpuEvidence::Fraction { occupancy: 0.01 }),
        runtime_seconds: Some(172_800.0), // 2 days
        orphan: Some(true),
        tty: Some(false),
        net: Some(false),
        io_active: Some(false),
        state_flag: None,
        command_category: None,
        queue_saturated: None,
    }
}

fn example_evidence_active_tty_net() -> Evidence {
    Evidence {
        cpu: Some(CpuEvidence::Fraction { occupancy: 0.40 }),
        runtime_seconds: Some(900.0), // 15 minutes
        orphan: Some(false),
        tty: Some(true),
        net: Some(true),
        io_active: Some(true),
        state_flag: None,
        command_category: None,
        queue_saturated: None,
    }
}

fn bench_compute_posterior(c: &mut Criterion) {
    let priors = Priors::default();

    let mut group = c.benchmark_group("posterior");

    for (name, evidence) in [
        ("idle_orphan", example_evidence_idle_orphan()),
        ("active_tty_net", example_evidence_active_tty_net()),
    ] {
        group.bench_with_input(
            BenchmarkId::new("compute_posterior", name),
            &evidence,
            |b, ev| {
                b.iter(|| {
                    let result = compute_posterior(black_box(&priors), black_box(ev))
                        .expect("posterior should compute");
                    black_box(result.log_odds_abandoned_useful);
                })
            },
        );
    }

    // A coarse "macro-ish" benchmark: run posterior computation for 10k synthetic processes.
    // This is not a /proc scan benchmark; it approximates inference throughput under load.
    let base = example_evidence_idle_orphan();
    let mut evidences = Vec::with_capacity(10_000);
    for i in 0..10_000u32 {
        let mut e = base.clone();
        // Keep inputs varied to reduce constant-folding and capture mixed branches.
        e.orphan = Some(i % 2 == 0);
        e.tty = Some(i % 3 == 0);
        e.net = Some(i % 5 == 0);
        e.io_active = Some(i % 7 == 0);
        // Some model components require strictly-positive runtime.
        e.runtime_seconds = Some(((i + 1) as f64) * 13.0);
        if let Some(CpuEvidence::Fraction { occupancy }) = &mut e.cpu {
            // Avoid exact 0/1, which can be numerically awkward for Beta likelihoods.
            *occupancy = (((i % 100) as f64) + 0.5) / 100.0;
        }
        evidences.push(e);
    }

    group.bench_function("compute_posterior_10k", |b| {
        b.iter(|| {
            let mut acc = 0.0f64;
            for ev in evidences.iter() {
                let result = compute_posterior(&priors, ev).expect("posterior should compute");
                acc += result.log_odds_abandoned_useful;
            }
            black_box(acc);
        })
    });

    group.finish();
}

criterion_group!(benches, bench_compute_posterior);
criterion_main!(benches);
