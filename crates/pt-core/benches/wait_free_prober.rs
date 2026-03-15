use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pt_core::collect::{deep_scan, DeepScanOptions};
use std::time::Duration;

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

criterion_group!(benches, bench_deep_scan_wait_free);
criterion_main!(benches);
