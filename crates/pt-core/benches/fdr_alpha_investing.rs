//! Criterion benchmarks for FDR selection and alpha-investing safety budget.
//!
//! Benchmarks `select_fdr` (eBH/eBY/None methods at various candidate counts),
//! `by_correction_factor`, and `AlphaInvestingPolicy::alpha_spend_for_wealth`
//! — kill-set gating hotpaths.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use pt_core::decision::alpha_investing::AlphaInvestingPolicy;
use pt_core::decision::fdr_selection::{
    by_correction_factor, select_fdr, FdrCandidate, FdrMethod, TargetIdentity,
};

fn make_candidate(pid: i32, e_value: f64) -> FdrCandidate {
    FdrCandidate {
        target: TargetIdentity {
            pid,
            start_id: format!("{}-12345-boot0", pid),
            uid: 1000,
        },
        e_value,
    }
}

/// Generate candidates with a mix of high and low e-values.
fn make_mixed_candidates(n: usize) -> Vec<FdrCandidate> {
    (0..n)
        .map(|i| {
            // Alternate between strong evidence and weak
            let e_value = if i % 3 == 0 {
                50.0 + (i as f64) * 2.0 // Strong evidence
            } else if i % 3 == 1 {
                5.0 + (i as f64) * 0.5 // Moderate
            } else {
                0.5 + (i as f64) * 0.01 // Weak
            };
            make_candidate(i as i32, e_value)
        })
        .collect()
}

/// Generate candidates with uniformly high e-values.
fn make_high_evidence_candidates(n: usize) -> Vec<FdrCandidate> {
    (0..n)
        .map(|i| make_candidate(i as i32, 100.0 - (i as f64) * 0.5))
        .collect()
}

fn bench_select_fdr(c: &mut Criterion) {
    let mut group = c.benchmark_group("fdr/select_fdr");

    for n in [5, 20, 50, 200] {
        let mixed = make_mixed_candidates(n);
        let high = make_high_evidence_candidates(n);

        for (name, candidates) in [("mixed", &mixed), ("high", &high)] {
            for method in [FdrMethod::EBh, FdrMethod::EBy, FdrMethod::None] {
                let method_str = match method {
                    FdrMethod::EBh => "ebh",
                    FdrMethod::EBy => "eby",
                    FdrMethod::None => "none",
                };
                group.bench_with_input(
                    BenchmarkId::new(
                        format!("{}_{}", name, method_str),
                        n,
                    ),
                    candidates,
                    |b, cands| {
                        b.iter(|| {
                            let result = select_fdr(
                                black_box(cands),
                                black_box(0.05),
                                method,
                            );
                            black_box(result.unwrap().selected_k);
                        })
                    },
                );
            }
        }
    }

    group.finish();
}

fn bench_by_correction_factor(c: &mut Criterion) {
    let mut group = c.benchmark_group("fdr/by_correction");

    for m in [5, 20, 50, 200, 1000] {
        group.bench_with_input(BenchmarkId::new("harmonic", m), &m, |b, &m| {
            b.iter(|| {
                black_box(by_correction_factor(black_box(m)));
            })
        });
    }

    group.finish();
}

fn bench_alpha_spend_for_wealth(c: &mut Criterion) {
    let mut group = c.benchmark_group("alpha/spend_for_wealth");

    let policy = AlphaInvestingPolicy {
        w0: 0.05,
        alpha_spend: 0.02,
        alpha_earn: 0.01,
    };

    for (name, wealth) in [
        ("zero", 0.0),
        ("low", 0.01),
        ("normal", 0.05),
        ("high", 1.0),
    ] {
        group.bench_with_input(
            BenchmarkId::new("compute", name),
            &wealth,
            |b, &w| {
                b.iter(|| {
                    black_box(policy.alpha_spend_for_wealth(black_box(w)));
                })
            },
        );
    }

    group.finish();
}

fn bench_fdr_alpha_sweep(c: &mut Criterion) {
    let mut group = c.benchmark_group("fdr/alpha_sweep");

    let candidates = make_mixed_candidates(50);

    for alpha in [0.01, 0.05, 0.10, 0.20] {
        group.bench_with_input(
            BenchmarkId::new("eby_n50", format!("a{:.2}", alpha)),
            &alpha,
            |b, &a| {
                b.iter(|| {
                    let result = select_fdr(
                        black_box(&candidates),
                        black_box(a),
                        FdrMethod::EBy,
                    );
                    black_box(result.unwrap().selected_k);
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_select_fdr,
    bench_by_correction_factor,
    bench_alpha_spend_for_wealth,
    bench_fdr_alpha_sweep
);
criterion_main!(benches);
