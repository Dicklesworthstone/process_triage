//! Criterion benchmarks for `pt-math`.
//!
//! Focus on pure numerical kernels that show up in inference loops.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use pt_math::math::beta::{beta_inv_cdf, log_beta_pdf};
use pt_math::math::posterior::{normalize_log_probs, normalize_log_probs_array};
use pt_math::math::precomputed::{CachedBetaPrior, CachedGammaPrior};
use pt_math::math::stable::{log_gamma, log_sum_exp, log_sum_exp_array};

fn bench_beta_kernels(c: &mut Criterion) {
    let mut group = c.benchmark_group("beta");

    // Typical-ish parameter regimes for classification features.
    for (name, alpha, beta) in [
        ("uniform", 1.0, 1.0),
        ("skew_low", 2.0, 8.0),
        ("skew_high", 8.0, 2.0),
        ("confident", 50.0, 5.0),
    ] {
        group.bench_with_input(
            BenchmarkId::new("log_beta_pdf", name),
            &(alpha, beta),
            |b, &(a, bta)| {
                b.iter(|| {
                    let x = 0.37_f64;
                    black_box(log_beta_pdf(black_box(x), black_box(a), black_box(bta)));
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("beta_inv_cdf", name),
            &(alpha, beta),
            |b, &(a, bta)| {
                b.iter(|| {
                    let p = 0.95_f64;
                    black_box(beta_inv_cdf(black_box(p), black_box(a), black_box(bta)));
                });
            },
        );
    }

    group.finish();
}

fn bench_posterior_hot_path(c: &mut Criterion) {
    let mut group = c.benchmark_group("posterior_hot_path");

    // Typical 4-class log-probabilities from a posterior computation.
    let logp4: [f64; 4] = [-0.356, -1.609, -2.302, -3.912];

    // log_sum_exp: slice vs array
    group.bench_function("log_sum_exp/slice_4", |b| {
        b.iter(|| black_box(log_sum_exp(black_box(&logp4))));
    });
    group.bench_function("log_sum_exp/array_4", |b| {
        b.iter(|| black_box(log_sum_exp_array(black_box(&logp4))));
    });

    // normalize_log_probs: Vec vs array
    group.bench_function("normalize/vec_4", |b| {
        b.iter(|| {
            let result = normalize_log_probs(black_box(&logp4));
            black_box(result);
        });
    });
    group.bench_function("normalize/array_4", |b| {
        b.iter(|| {
            let result = normalize_log_probs_array(black_box(&logp4));
            black_box(result);
        });
    });

    // Batch: normalize 10K 4-class posteriors (simulates full scan)
    let batch: Vec<[f64; 4]> = (0..10_000u32)
        .map(|i| {
            let u = -((i % 50 + 1) as f64 / 50.0).ln();
            let ub = -((i % 30 + 1) as f64 / 30.0).ln();
            let a = -((i % 80 + 1) as f64 / 80.0).ln();
            let z = -((i % 15 + 1) as f64 / 15.0).ln();
            [u, ub, a, z]
        })
        .collect();

    group.bench_function("normalize_10k/vec", |b| {
        b.iter(|| {
            for logp in batch.iter() {
                black_box(normalize_log_probs(black_box(logp)));
            }
        });
    });
    group.bench_function("normalize_10k/array", |b| {
        b.iter(|| {
            for logp in batch.iter() {
                black_box(normalize_log_probs_array(black_box(logp)));
            }
        });
    });

    // log_gamma throughput (called ~16× per process in full posterior)
    group.bench_function("log_gamma/single", |b| {
        b.iter(|| black_box(log_gamma(black_box(5.0))));
    });
    group.bench_function("log_gamma/batch_160k", |b| {
        b.iter(|| {
            let mut sum = 0.0;
            for i in 0..160_000u32 {
                sum += log_gamma(black_box((i % 100 + 1) as f64 * 0.1));
            }
            black_box(sum);
        });
    });

    group.finish();
}

fn bench_cached_priors(c: &mut Criterion) {
    let mut group = c.benchmark_group("cached_priors");

    // Compare direct vs cached Beta PDF (the CPU evidence likelihood)
    let alpha = 5.0;
    let beta_param = 3.0;
    let cached_beta = CachedBetaPrior::new(alpha, beta_param);

    group.bench_function("beta_log_pdf/direct", |b| {
        b.iter(|| {
            black_box(log_beta_pdf(
                black_box(0.37),
                black_box(alpha),
                black_box(beta_param),
            ));
        });
    });
    group.bench_function("beta_log_pdf/cached", |b| {
        b.iter(|| {
            black_box(cached_beta.log_pdf(black_box(0.37)));
        });
    });

    // Compare direct vs cached Gamma PDF (the runtime evidence likelihood)
    let shape = 2.5;
    let rate = 0.001;
    let cached_gamma = CachedGammaPrior::new(shape, rate);

    group.bench_function("gamma_log_pdf/direct", |b| {
        b.iter(|| {
            black_box(pt_math::gamma_log_pdf(
                black_box(172800.0),
                black_box(shape),
                black_box(rate),
            ));
        });
    });
    group.bench_function("gamma_log_pdf/cached", |b| {
        b.iter(|| {
            black_box(cached_gamma.log_pdf(black_box(172800.0)));
        });
    });

    // Simulate full CPU evidence computation: 4 classes × 10K processes
    let priors = [
        CachedBetaPrior::new(5.0, 3.0), // useful
        CachedBetaPrior::new(2.0, 6.0), // useful_bad
        CachedBetaPrior::new(1.0, 5.0), // abandoned
        CachedBetaPrior::new(1.5, 4.0), // zombie
    ];

    group.bench_function("cpu_evidence_40k/direct", |b| {
        b.iter(|| {
            let mut sum = 0.0;
            for i in 0..10_000u32 {
                let x = ((i % 100) as f64 + 0.5) / 100.0;
                for p in &priors {
                    sum += log_beta_pdf(black_box(x), p.alpha, p.beta);
                }
            }
            black_box(sum);
        });
    });
    group.bench_function("cpu_evidence_40k/cached", |b| {
        b.iter(|| {
            let mut sum = 0.0;
            for i in 0..10_000u32 {
                let x = ((i % 100) as f64 + 0.5) / 100.0;
                for p in &priors {
                    sum += p.log_pdf(black_box(x));
                }
            }
            black_box(sum);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_beta_kernels,
    bench_posterior_hot_path,
    bench_cached_priors
);
criterion_main!(benches);
