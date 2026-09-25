#[cfg(target_os = "linux")]
use criterion::{black_box, criterion_group, criterion_main, Criterion};
#[cfg(target_os = "linux")]
use pt_core::collect::{deep_scan, DeepScanOptions};
#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
fn bench_deep_scan_wait_free(c: &mut Criterion) {
    let mut group = c.benchmark_group("deep_scan");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(10);

    let options_sync = DeepScanOptions {
        pids: Vec::new(),
        skip_inaccessible: true,
        include_environ: false,
        use_wait_free: false,
        progress: None,
    };

    let options_async = DeepScanOptions {
        pids: Vec::new(),
        skip_inaccessible: true,
        include_environ: false,
        use_wait_free: true,
        progress: None,
    };

    group.bench_function("sync", |b| {
        b.iter(|| {
            let _ = deep_scan(black_box(&options_sync));
        })
    });

    group.bench_function("async_io_uring", |b| {
        b.iter(|| {
            let _ = deep_scan(black_box(&options_async));
        })
    });

    group.finish();
}

#[cfg(target_os = "linux")]
criterion_group!(benches, bench_deep_scan_wait_free);
#[cfg(target_os = "linux")]
criterion_main!(benches);

// Deep scan (and its wait-free prober) is Linux-only.
#[cfg(not(target_os = "linux"))]
fn main() {}
