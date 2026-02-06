//! Criterion benchmarks for `pt-math`.
//!
//! Focus on pure numerical kernels that show up in inference loops.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use pt_math::math::beta::{beta_inv_cdf, log_beta_pdf};

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

criterion_group!(benches, bench_beta_kernels);
criterion_main!(benches);

