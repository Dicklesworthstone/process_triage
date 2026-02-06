//! Criterion benchmarks for `pt-core` session diff computation.
//!
//! These benchmarks avoid scanning real processes so they can run deterministically
//! in CI and on developer machines.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pt_core::session::diff::{compute_diff, DiffConfig};
use pt_core::session::snapshot_persist::{PersistedInference, PersistedProcess};

fn make_process(pid: u32, start_id: String, elapsed_secs: u64) -> PersistedProcess {
    PersistedProcess {
        pid,
        ppid: 1,
        uid: 1000,
        start_id,
        comm: "proc".to_string(),
        cmd: "proc --synthetic".to_string(),
        state: "S".to_string(),
        start_time_unix: 1_700_000_000,
        elapsed_secs,
        identity_quality: "full".to_string(),
    }
}

fn make_inference(proc: &PersistedProcess, classification: &str, score: u32) -> PersistedInference {
    PersistedInference {
        pid: proc.pid,
        start_id: proc.start_id.clone(),
        classification: classification.to_string(),
        posterior_useful: 0.01,
        posterior_useful_bad: 0.02,
        posterior_abandoned: 0.90,
        posterior_zombie: 0.07,
        confidence: "high".to_string(),
        recommended_action: "kill".to_string(),
        score,
    }
}

fn bench_compute_diff(c: &mut Criterion) {
    // Baseline: 10k processes.
    let mut old_procs = Vec::with_capacity(10_000);
    let mut old_infs = Vec::with_capacity(10_000);
    for i in 0..10_000u32 {
        let start_id = format!("boot:tick:{i}");
        let p = make_process(i + 1000, start_id, 3600 + (i as u64));
        let class = if i % 2 == 0 { "abandoned" } else { "useful" };
        let score = 20 + (i % 80);
        old_infs.push(make_inference(&p, class, score));
        old_procs.push(p);
    }

    // Current: keep 9.5k baseline processes (drop first 500), add 500 new.
    let mut new_procs = Vec::with_capacity(10_000);
    let mut new_infs = Vec::with_capacity(10_000);

    // Keep baseline processes i=500..9999.
    for i in 500..10_000u32 {
        let start_id = format!("boot:tick:{i}");
        let p = make_process(i + 1000, start_id, 3600 + (i as u64) + 5);

        // Introduce score drift + occasional classification changes.
        let mut class = if i % 2 == 0 { "abandoned" } else { "useful" };
        let mut score = 20 + (i % 80);

        // Every 10th kept process drifts enough to be "changed" under default threshold (5).
        if i % 10 == 0 {
            score = score.saturating_add(10);
        }

        // Every 200th kept process flips classification.
        if i % 200 == 0 {
            class = "zombie";
        }

        new_infs.push(make_inference(&p, class, score));
        new_procs.push(p);
    }

    // Add 500 new processes i=10_000..10_499.
    for i in 10_000..10_500u32 {
        let start_id = format!("boot:tick:{i}");
        let p = make_process(i + 1000, start_id, 120);
        new_infs.push(make_inference(&p, "abandoned", 60));
        new_procs.push(p);
    }

    let config = DiffConfig::default();

    let mut group = c.benchmark_group("session_diff");
    group.bench_function("compute_diff_10k", |b| {
        b.iter(|| {
            let diff = compute_diff(
                black_box("pt-baseline"),
                black_box("pt-current"),
                black_box(&old_procs),
                black_box(&old_infs),
                black_box(&new_procs),
                black_box(&new_infs),
                black_box(&config),
            );
            black_box(diff.summary.changed_count);
        })
    });
    group.finish();
}

criterion_group!(benches, bench_compute_diff);
criterion_main!(benches);
