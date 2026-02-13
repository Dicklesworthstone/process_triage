//! Criterion benchmarks for memory pressure monitoring, rate limiting, and respawn loop detection.
//!
//! Benchmarks `MemPressureMonitor::evaluate`, `MemorySignals::utilization`,
//! `SlidingWindowRateLimiter::check`, `RespawnTracker::detect_loop`,
//! `RespawnTracker::all_loops`, and `discount_kill_utility`
//! — runtime safety-gating hotpaths.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use pt_core::decision::mem_pressure::{MemPressureConfig, MemPressureMonitor, MemorySignals};
use pt_core::decision::rate_limit::{RateLimitConfig, SlidingWindowRateLimiter};
use pt_core::decision::respawn_loop::{discount_kill_utility, RespawnLoopConfig, RespawnTracker};

// ── Helpers ──────────────────────────────────────────────────────────

fn idle_signals(ts: f64) -> MemorySignals {
    MemorySignals {
        total_bytes: 16_000_000_000,
        used_bytes: 4_000_000_000,
        available_bytes: 12_000_000_000,
        swap_used_bytes: 0,
        swap_total_bytes: 8_000_000_000,
        psi_some10: Some(0.0),
        timestamp: ts,
    }
}

fn moderate_signals(ts: f64) -> MemorySignals {
    MemorySignals {
        total_bytes: 16_000_000_000,
        used_bytes: 12_000_000_000,
        available_bytes: 4_000_000_000,
        swap_used_bytes: 2_000_000_000,
        swap_total_bytes: 8_000_000_000,
        psi_some10: Some(15.0),
        timestamp: ts,
    }
}

fn emergency_signals(ts: f64) -> MemorySignals {
    MemorySignals {
        total_bytes: 16_000_000_000,
        used_bytes: 15_500_000_000,
        available_bytes: 500_000_000,
        swap_used_bytes: 7_500_000_000,
        swap_total_bytes: 8_000_000_000,
        psi_some10: Some(60.0),
        timestamp: ts,
    }
}

fn no_psi_signals(ts: f64) -> MemorySignals {
    MemorySignals {
        total_bytes: 16_000_000_000,
        used_bytes: 10_000_000_000,
        available_bytes: 6_000_000_000,
        swap_used_bytes: 1_000_000_000,
        swap_total_bytes: 8_000_000_000,
        psi_some10: None,
        timestamp: ts,
    }
}

// ── Memory pressure benchmarks ───────────────────────────────────────

fn bench_utilization(c: &mut Criterion) {
    let mut group = c.benchmark_group("mem_pressure/utilization");

    for (name, signals) in [
        ("idle", idle_signals(0.0)),
        ("moderate", moderate_signals(0.0)),
        ("emergency", emergency_signals(0.0)),
    ] {
        group.bench_with_input(BenchmarkId::new("compute", name), &signals, |b, sig| {
            b.iter(|| {
                let util = black_box(sig).utilization();
                let swap = black_box(sig).swap_utilization();
                black_box((util, swap));
            })
        });
    }

    group.finish();
}

fn bench_evaluate(c: &mut Criterion) {
    let mut group = c.benchmark_group("mem_pressure/evaluate");

    let config = MemPressureConfig::default();

    // Single evaluation at different signal levels
    for (name, make_signal) in [
        ("idle", idle_signals as fn(f64) -> MemorySignals),
        ("moderate", moderate_signals as fn(f64) -> MemorySignals),
        ("emergency", emergency_signals as fn(f64) -> MemorySignals),
        ("no_psi", no_psi_signals as fn(f64) -> MemorySignals),
    ] {
        group.bench_function(BenchmarkId::new("single", name), |b| {
            b.iter(|| {
                let mut monitor = MemPressureMonitor::new(config.clone());
                let eval = monitor.evaluate(black_box(&make_signal(1.0)));
                black_box(eval.mode);
            })
        });
    }

    // Transition sequence: idle → moderate → emergency → idle
    group.bench_function("transition_sequence", |b| {
        b.iter(|| {
            let mut monitor = MemPressureMonitor::new(config.clone());
            let _ = monitor.evaluate(black_box(&idle_signals(1.0)));
            let _ = monitor.evaluate(black_box(&moderate_signals(2.0)));
            let _ = monitor.evaluate(black_box(&emergency_signals(3.0)));
            let eval = monitor.evaluate(black_box(&idle_signals(4.0)));
            black_box(eval.transitioned);
        })
    });

    // Steady-state: 10 evaluations at same level
    group.bench_function("steady_10", |b| {
        b.iter(|| {
            let mut monitor = MemPressureMonitor::new(config.clone());
            for i in 0..10 {
                let eval = monitor.evaluate(black_box(&moderate_signals(i as f64)));
                black_box(eval.mode);
            }
        })
    });

    group.finish();
}

// ── Rate limit benchmarks ────────────────────────────────────────────

fn bench_rate_limit_check(c: &mut Criterion) {
    let mut group = c.benchmark_group("rate_limit/check");

    let configs = [
        ("default", RateLimitConfig::default_conservative()),
        (
            "tight",
            RateLimitConfig {
                max_per_run: 3,
                max_per_minute: Some(2),
                max_per_hour: Some(10),
                max_per_day: Some(50),
            },
        ),
        (
            "loose",
            RateLimitConfig {
                max_per_run: 100,
                max_per_minute: None,
                max_per_hour: None,
                max_per_day: None,
            },
        ),
    ];

    for (name, config) in &configs {
        let limiter = SlidingWindowRateLimiter::new(config.clone(), None::<&str>).unwrap();

        // Fresh check (no kills recorded)
        group.bench_with_input(BenchmarkId::new("fresh", *name), &limiter, |b, lim| {
            b.iter(|| {
                let result = lim.check(black_box(false)).unwrap();
                black_box(result.allowed);
            })
        });

        // Force mode
        group.bench_with_input(BenchmarkId::new("force", *name), &limiter, |b, lim| {
            b.iter(|| {
                let result = lim.check(black_box(true)).unwrap();
                black_box(result.allowed);
            })
        });
    }

    group.finish();
}

fn bench_rate_limit_check_with_override(c: &mut Criterion) {
    let mut group = c.benchmark_group("rate_limit/check_override");

    let limiter =
        SlidingWindowRateLimiter::new(RateLimitConfig::default_conservative(), None::<&str>)
            .unwrap();

    for override_val in [None, Some(5), Some(50)] {
        let label = match override_val {
            None => "none".to_string(),
            Some(v) => format!("override_{}", v),
        };
        group.bench_function(BenchmarkId::new("check", &label), |b| {
            b.iter(|| {
                let result = limiter
                    .check_with_override(black_box(false), black_box(override_val))
                    .unwrap();
                black_box(result.allowed);
            })
        });
    }

    group.finish();
}

fn bench_rate_limit_record_cycle(c: &mut Criterion) {
    let mut group = c.benchmark_group("rate_limit/record_cycle");

    // Benchmark check → record → check cycle (in-memory only)
    for n_kills in [1, 5, 10] {
        group.bench_function(BenchmarkId::new("kills", n_kills), |b| {
            b.iter(|| {
                let limiter = SlidingWindowRateLimiter::new(
                    RateLimitConfig {
                        max_per_run: 100,
                        max_per_minute: Some(50),
                        max_per_hour: Some(200),
                        max_per_day: Some(500),
                    },
                    None::<&str>,
                )
                .unwrap();
                for _ in 0..n_kills {
                    let _ = limiter.record_kill();
                }
                let result = limiter.check(black_box(false)).unwrap();
                black_box(result.allowed);
            })
        });
    }

    group.finish();
}

// ── Respawn loop benchmarks ──────────────────────────────────────────

fn bench_detect_loop(c: &mut Criterion) {
    let mut group = c.benchmark_group("respawn_loop/detect_loop");

    let config = RespawnLoopConfig::default();

    // No events: detect on empty tracker
    group.bench_function("empty", |b| {
        let tracker = RespawnTracker::new();
        b.iter(|| {
            let detection = tracker.detect_loop(
                black_box("nginx-1234"),
                black_box(&config),
                black_box(100.0),
            );
            black_box(detection.is_loop);
        })
    });

    // Few events: 3 respawns within window
    for n in [3, 5, 10, 20] {
        group.bench_function(BenchmarkId::new("events", n), |b| {
            let mut tracker = RespawnTracker::new();
            for i in 0..n {
                tracker.record_respawn(
                    "nginx-1234".to_string(),
                    Some("nginx.service".to_string()),
                    None,
                    (i * 10) as f64,     // kill_ts
                    (i * 10 + 2) as f64, // respawn_ts (2s delay)
                    None,
                );
            }
            let now = (n * 10 + 5) as f64;
            b.iter(|| {
                let detection = tracker.detect_loop(
                    black_box("nginx-1234"),
                    black_box(&config),
                    black_box(now),
                );
                black_box(detection.is_loop);
            })
        });
    }

    group.finish();
}

fn bench_all_loops(c: &mut Criterion) {
    let mut group = c.benchmark_group("respawn_loop/all_loops");

    let config = RespawnLoopConfig::default();

    for n_identities in [5, 10, 25] {
        let mut tracker = RespawnTracker::new();
        for id in 0..n_identities {
            let key = format!("proc-{}", id);
            let events = if id % 3 == 0 { 8 } else { 2 }; // Some loop, some not
            for e in 0..events {
                tracker.record_respawn(
                    key.clone(),
                    Some(format!("svc-{}.service", id)),
                    None,
                    (e * 10) as f64,
                    (e * 10 + 1) as f64,
                    None,
                );
            }
        }
        let now = 200.0;

        group.bench_with_input(
            BenchmarkId::new("identities", n_identities),
            &tracker,
            |b, t| {
                b.iter(|| {
                    let loops = t.all_loops(black_box(&config), black_box(now));
                    black_box(loops.len());
                })
            },
        );
    }

    group.finish();
}

fn bench_discount_kill_utility(c: &mut Criterion) {
    let mut group = c.benchmark_group("respawn_loop/discount_utility");

    let config = RespawnLoopConfig::default();

    // Detection from a looping process
    let mut tracker = RespawnTracker::new();
    for i in 0..10 {
        tracker.record_respawn(
            "loop-proc".to_string(),
            None,
            None,
            (i * 5) as f64,
            (i * 5 + 1) as f64,
            None,
        );
    }
    let loop_detection = tracker.detect_loop("loop-proc", &config, 60.0);

    // Detection from a non-looping process
    let mut tracker2 = RespawnTracker::new();
    tracker2.record_respawn("single-proc".to_string(), None, None, 0.0, 1.0, None);
    let no_loop_detection = tracker2.detect_loop("single-proc", &config, 10.0);

    for (name, detection) in [
        ("looping", &loop_detection),
        ("not_looping", &no_loop_detection),
    ] {
        for base_utility in [1.0, 10.0, 100.0] {
            group.bench_with_input(
                BenchmarkId::new(format!("{}_{}", name, base_utility as u32), name),
                detection,
                |b, det| {
                    b.iter(|| {
                        let discounted =
                            discount_kill_utility(black_box(base_utility), black_box(det));
                        black_box(discounted);
                    })
                },
            );
        }
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_utilization,
    bench_evaluate,
    bench_rate_limit_check,
    bench_rate_limit_check_with_override,
    bench_rate_limit_record_cycle,
    bench_detect_loop,
    bench_all_loops,
    bench_discount_kill_utility
);
criterion_main!(benches);
