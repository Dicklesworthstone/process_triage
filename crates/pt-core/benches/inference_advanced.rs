//! Criterion benchmarks for advanced inference modules: HSMM state analysis,
//! robust Bayesian inference (credal sets, tempering, minimax gates), and
//! compound Poisson burst detection.
//!
//! Benchmarks `HsmmAnalyzer` (update/batch/summarize), `RobustGate`
//! (tempered posterior, credal sets, PPC/drift tempering), `MinimaxGate`
//! (worst-case loss, LFP, stability), and `CompoundPoissonAnalyzer`
//! (observe/analyze/evidence) — inference-engine hotpaths.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use pt_core::inference::compound_poisson::{
    BurstEvent, CompoundPoissonAnalyzer, CompoundPoissonConfig,
};
use pt_core::inference::hsmm::{HsmmAnalyzer, HsmmConfig};
use pt_core::inference::robust::{CredalSet, MinimaxConfig, MinimaxGate, RobustConfig, RobustGate};

// ── Helpers ──────────────────────────────────────────────────────────

fn make_observations(n: usize, features: usize) -> Vec<Vec<f64>> {
    (0..n)
        .map(|i| {
            (0..features)
                .map(|f| 0.1 + (i as f64 * 0.3 + f as f64 * 0.7) % 2.0)
                .collect()
        })
        .collect()
}

fn make_burst_events(n: usize) -> Vec<BurstEvent> {
    (0..n)
        .map(|i| BurstEvent::new(i as f64 * 5.0, 10.0 + (i as f64 * 3.7) % 50.0, None))
        .collect()
}

fn make_credal_sets(n: usize) -> Vec<CredalSet> {
    (0..n)
        .map(|i| {
            let center = 0.1 + (i as f64 * 0.2) % 0.8;
            let half = 0.05 + (i as f64 * 0.02) % 0.1;
            CredalSet::symmetric(center, half)
        })
        .collect()
}

// ── HSMM benchmarks ────────────────────────────────────────────────

fn bench_hsmm_update(c: &mut Criterion) {
    let mut group = c.benchmark_group("hsmm/update");
    let config = HsmmConfig::short_lived();
    let features = config.num_features;

    // Single observation update
    group.bench_function("single", |b| {
        let obs = vec![0.5; features];
        b.iter(|| {
            let mut analyzer = HsmmAnalyzer::new(config.clone()).unwrap();
            let probs = analyzer.update(black_box(&obs)).unwrap();
            black_box(probs);
        })
    });

    // Sequential updates
    for n in [5, 20, 50] {
        let observations = make_observations(n, features);
        group.bench_function(BenchmarkId::new("sequential", n), |b| {
            b.iter(|| {
                let mut analyzer = HsmmAnalyzer::new(config.clone()).unwrap();
                for obs in &observations {
                    let _ = analyzer.update(black_box(obs));
                }
                black_box(analyzer.state_probs());
            })
        });
    }

    group.finish();
}

fn bench_hsmm_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("hsmm/batch");
    let config = HsmmConfig::short_lived();
    let features = config.num_features;

    for n in [10, 50, 100] {
        let observations = make_observations(n, features);
        group.bench_with_input(
            BenchmarkId::new("observations", n),
            &observations,
            |b, obs| {
                b.iter(|| {
                    let mut analyzer = HsmmAnalyzer::new(config.clone()).unwrap();
                    let posteriors = analyzer.update_batch(black_box(obs)).unwrap();
                    black_box(posteriors.len());
                })
            },
        );
    }

    group.finish();
}

fn bench_hsmm_summarize(c: &mut Criterion) {
    let mut group = c.benchmark_group("hsmm/summarize");

    for (name, config) in [
        ("short_lived", HsmmConfig::short_lived()),
        ("long_running", HsmmConfig::long_running()),
    ] {
        let features = config.num_features;
        let observations = make_observations(30, features);
        let mut analyzer = HsmmAnalyzer::new(config).unwrap();
        for obs in &observations {
            let _ = analyzer.update(obs);
        }

        group.bench_function(BenchmarkId::new("config", name), |b| {
            b.iter(|| {
                let result = analyzer.summarize().unwrap();
                black_box(result.stability_score);
            })
        });
    }

    group.finish();
}

// ── Robust inference benchmarks ─────────────────────────────────────

fn bench_robust_tempered_posterior(c: &mut Criterion) {
    let mut group = c.benchmark_group("robust/tempered_posterior");

    for (name, config) in [
        ("default", RobustConfig::default()),
        ("conservative", RobustConfig::conservative()),
        ("strict", RobustConfig::strict()),
    ] {
        let gate = RobustGate::new(config);
        group.bench_function(BenchmarkId::new("config", name), |b| {
            b.iter(|| {
                let tp = gate.tempered_posterior(
                    black_box(1.0),
                    black_box(1.0),
                    black_box(50),
                    black_box(30),
                );
                black_box(tp.mean());
            })
        });
    }

    // Vary sample size
    let gate = RobustGate::new(RobustConfig::default());
    for n in [10, 50, 200, 1000] {
        let k = n * 6 / 10; // 60% success rate
        group.bench_function(BenchmarkId::new("n", n), |b| {
            b.iter(|| {
                let tp = gate.tempered_posterior(
                    black_box(1.0),
                    black_box(1.0),
                    black_box(n),
                    black_box(k),
                );
                black_box(tp.variance());
            })
        });
    }

    group.finish();
}

fn bench_robust_credal_ops(c: &mut Criterion) {
    let mut group = c.benchmark_group("robust/credal_ops");

    let a = CredalSet::symmetric(0.5, 0.15);
    let b = CredalSet::symmetric(0.6, 0.1);

    group.bench_function("intersect", |b_bench| {
        b_bench.iter(|| {
            let result = a.intersect(black_box(&b));
            black_box(result);
        })
    });

    group.bench_function("hull", |b_bench| {
        b_bench.iter(|| {
            let result = a.hull(black_box(&b));
            black_box(result.width());
        })
    });

    group.bench_function("expand", |b_bench| {
        b_bench.iter(|| {
            let result = a.expand(black_box(1.5));
            black_box(result.width());
        })
    });

    // Robustness check
    let gate = RobustGate::new(RobustConfig::default());
    group.bench_function("is_action_robust", |b_bench| {
        let credal = CredalSet::symmetric(0.7, 0.1);
        b_bench.iter(|| {
            let result = gate.is_action_robust(black_box(&credal), black_box(0.7));
            black_box(result.is_robust);
        })
    });

    group.finish();
}

fn bench_robust_eta_tempering(c: &mut Criterion) {
    let mut group = c.benchmark_group("robust/eta_tempering");

    // PPC failure tempering
    group.bench_function("ppc_signal_cycle", |b| {
        b.iter(|| {
            let mut gate = RobustGate::new(RobustConfig::default());
            for _ in 0..5 {
                gate.signal_ppc_failure();
            }
            black_box(gate.eta());
            gate.reset_eta();
            black_box(gate.eta());
        })
    });

    // Drift tempering
    group.bench_function("drift_signal_cycle", |b| {
        b.iter(|| {
            let mut gate = RobustGate::new(RobustConfig::default());
            for _ in 0..5 {
                gate.signal_drift();
            }
            black_box(gate.eta());
            gate.clear_drift();
            black_box(gate.eta());
        })
    });

    group.finish();
}

fn bench_minimax_gate(c: &mut Criterion) {
    let mut group = c.benchmark_group("robust/minimax");

    let config = MinimaxConfig {
        enabled: true,
        max_worst_case_loss: 10.0,
    };

    // Varying number of classes
    for n_classes in [2, 4, 8] {
        let loss_row: Vec<f64> = (0..n_classes).map(|i| 1.0 + i as f64 * 2.0).collect();
        let credal_sets = make_credal_sets(n_classes);

        group.bench_function(BenchmarkId::new("is_safe", n_classes), |b| {
            let gate = MinimaxGate::new(config.clone());
            b.iter(|| {
                let result = gate.is_safe(black_box(&loss_row), black_box(&credal_sets));
                black_box(result.is_safe);
            })
        });
    }

    // LFP computation
    for n_classes in [2, 4] {
        let loss_row: Vec<f64> = (0..n_classes).map(|i| 1.0 + i as f64 * 3.0).collect();
        let credal_sets = make_credal_sets(n_classes);
        let class_names: Vec<&str> = (0..n_classes)
            .map(|i| match i {
                0 => "useful",
                1 => "abandoned",
                2 => "zombie",
                _ => "other",
            })
            .collect();

        group.bench_function(BenchmarkId::new("lfp", n_classes), |b| {
            b.iter(|| {
                let mut gate = MinimaxGate::new(config.clone());
                let lfp = gate.compute_lfp(
                    black_box(&loss_row),
                    black_box(&credal_sets),
                    black_box(&class_names),
                );
                black_box(lfp.expected_loss);
            })
        });
    }

    // Stability analysis
    group.bench_function("stability_2_actions", |b| {
        let credal_sets = make_credal_sets(3);
        let action_losses: Vec<(&str, Vec<f64>)> = vec![
            ("kill", vec![0.0, 5.0, 1.0]),
            ("spare", vec![3.0, 0.0, 8.0]),
        ];
        let refs: Vec<(&str, &[f64])> = action_losses
            .iter()
            .map(|(name, losses)| (*name, losses.as_slice()))
            .collect();
        b.iter(|| {
            let mut gate = MinimaxGate::new(config.clone());
            let stability = gate.analyze_stability(black_box(&refs), black_box(&credal_sets));
            black_box(stability.is_stable);
        })
    });

    group.finish();
}

// ── Compound Poisson benchmarks ─────────────────────────────────────

fn bench_cp_observe(c: &mut Criterion) {
    let mut group = c.benchmark_group("compound_poisson/observe");
    let config = CompoundPoissonConfig::default();

    // Single event observation
    group.bench_function("single", |b| {
        b.iter(|| {
            let mut analyzer = CompoundPoissonAnalyzer::new(config.clone());
            analyzer.observe(black_box(BurstEvent::new(1.0, 25.0, None)));
            black_box(analyzer.event_count());
        })
    });

    // Batch observation
    for n in [10, 50, 100, 500] {
        let events = make_burst_events(n);
        group.bench_with_input(BenchmarkId::new("batch", n), &events, |b, evts| {
            b.iter(|| {
                let mut analyzer = CompoundPoissonAnalyzer::new(config.clone());
                analyzer.observe_batch(black_box(evts));
                black_box(analyzer.event_count());
            })
        });
    }

    group.finish();
}

fn bench_cp_analyze(c: &mut Criterion) {
    let mut group = c.benchmark_group("compound_poisson/analyze");
    let config = CompoundPoissonConfig::default();

    for n in [10, 50, 100] {
        let events = make_burst_events(n);
        let mut analyzer = CompoundPoissonAnalyzer::new(config.clone());
        analyzer.observe_batch(&events);

        group.bench_function(BenchmarkId::new("events", n), |b| {
            b.iter(|| {
                let result = analyzer.analyze();
                black_box(result.burstiness_score);
            })
        });
    }

    group.finish();
}

fn bench_cp_evidence(c: &mut Criterion) {
    let mut group = c.benchmark_group("compound_poisson/evidence");
    let config = CompoundPoissonConfig::default();

    for n in [10, 50, 100] {
        let events = make_burst_events(n);
        let mut analyzer = CompoundPoissonAnalyzer::new(config.clone());
        analyzer.observe_batch(&events);

        group.bench_function(BenchmarkId::new("events", n), |b| {
            b.iter(|| {
                let evidence = analyzer.generate_evidence(black_box(0.5));
                black_box(evidence.is_bursty);
            })
        });
    }

    group.finish();
}

fn bench_cp_regime(c: &mut Criterion) {
    let mut group = c.benchmark_group("compound_poisson/regime");

    let config = CompoundPoissonConfig {
        enable_regimes: true,
        num_regimes: 3,
        min_events: 5,
        ..CompoundPoissonConfig::default()
    };

    // Events with regime annotations
    for n in [20, 50] {
        let events: Vec<BurstEvent> = (0..n)
            .map(|i| BurstEvent::with_regime(i as f64 * 3.0, 15.0 + (i as f64 * 2.3) % 40.0, i % 3))
            .collect();

        group.bench_function(BenchmarkId::new("events", n), |b| {
            b.iter(|| {
                let mut analyzer = CompoundPoissonAnalyzer::new(config.clone());
                analyzer.observe_batch(black_box(&events));
                let result = analyzer.analyze();
                black_box(result.dominant_regime);
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_hsmm_update,
    bench_hsmm_batch,
    bench_hsmm_summarize,
    bench_robust_tempered_posterior,
    bench_robust_credal_ops,
    bench_robust_eta_tempering,
    bench_minimax_gate,
    bench_cp_observe,
    bench_cp_analyze,
    bench_cp_evidence,
    bench_cp_regime
);
criterion_main!(benches);
