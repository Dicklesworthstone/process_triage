//! Criterion benchmarks for daemon trigger evaluation hot paths.
//!
//! Focuses on `daemon::triggers::evaluate_triggers`, which runs every daemon
//! tick and should remain cheap under steady-state, bursty, and mixed loads.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use pt_core::daemon::triggers::{evaluate_triggers, TriggerConfig, TriggerState};
use pt_core::daemon::TickMetrics;

fn tick(
    load_avg_1: f64,
    memory_used_mb: u64,
    memory_total_mb: u64,
    orphan_count: u32,
) -> TickMetrics {
    TickMetrics {
        timestamp: "2026-01-01T00:00:00Z".to_string(),
        load_avg_1,
        load_avg_5: load_avg_1 * 0.8,
        memory_used_mb,
        memory_total_mb,
        swap_used_mb: 0,
        process_count: 512,
        orphan_count,
    }
}

fn steady_stream(n: usize) -> Vec<TickMetrics> {
    (0..n)
        .map(|i| {
            let load = 1.4 + (i % 5) as f64 * 0.05;
            let mem_used = 4_000 + (i % 64) as u64;
            let orphans = 4 + (i % 3) as u32;
            tick(load, mem_used, 16_000, orphans)
        })
        .collect()
}

fn burst_stream(n: usize) -> Vec<TickMetrics> {
    (0..n)
        .map(|i| {
            let phase = i % 40;
            if phase < 8 {
                // Above thresholds for sustained-trigger/cooldown behavior.
                tick(8.5, 15_000, 16_000, 80)
            } else {
                tick(1.1, 3_800, 16_000, 2)
            }
        })
        .collect()
}

fn mixed_stream(n: usize) -> Vec<TickMetrics> {
    (0..n)
        .map(|i| {
            let x = (i as u64)
                .wrapping_mul(1_664_525)
                .wrapping_add(1_013_904_223);
            let load = 0.5 + ((x % 1_100) as f64 / 100.0);
            let mem_used = 2_500 + (x % 13_000);
            let orphans = (x % 120) as u32;
            tick(load, mem_used, 16_000, orphans)
        })
        .collect()
}

fn run_stream(config: &TriggerConfig, stream: &[TickMetrics]) -> usize {
    let mut state = TriggerState::new(config);
    let mut fired_total = 0usize;
    for metrics in stream {
        fired_total += evaluate_triggers(config, &mut state, metrics).len();
    }
    fired_total
}

fn bench_single_tick(c: &mut Criterion) {
    let config = TriggerConfig::default();
    let metrics = tick(2.1, 5_500, 16_000, 10);

    let mut group = c.benchmark_group("daemon_triggers/single_tick");
    group.bench_function("evaluate_triggers_fresh_state", |b| {
        b.iter(|| {
            let mut state = TriggerState::new(&config);
            let fired = evaluate_triggers(black_box(&config), &mut state, black_box(&metrics));
            black_box(fired.len());
        });
    });

    group.bench_function("evaluate_triggers_hot_state", |b| {
        let mut state = TriggerState::new(&config);
        b.iter(|| {
            let fired = evaluate_triggers(black_box(&config), &mut state, black_box(&metrics));
            black_box(fired.len());
        });
    });
    group.finish();
}

fn bench_streams(c: &mut Criterion) {
    let config = TriggerConfig::default();
    let mut group = c.benchmark_group("daemon_triggers/streams");

    for n in [1_000usize, 10_000usize] {
        let steady = steady_stream(n);
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::new("steady", n), &steady, |b, stream| {
            b.iter(|| black_box(run_stream(black_box(&config), black_box(stream))));
        });

        let burst = burst_stream(n);
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::new("burst", n), &burst, |b, stream| {
            b.iter(|| black_box(run_stream(black_box(&config), black_box(stream))));
        });

        let mixed = mixed_stream(n);
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::new("mixed", n), &mixed, |b, stream| {
            b.iter(|| black_box(run_stream(black_box(&config), black_box(stream))));
        });
    }

    group.finish();
}

criterion_group!(benches, bench_single_tick, bench_streams);
criterion_main!(benches);
