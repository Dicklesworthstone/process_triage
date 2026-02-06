//! Criterion benchmarks for synthetic quick-scan parsing.
//!
//! The real quick scan (`quick_scan`) shells out to `ps`, which is inherently
//! non-deterministic in CI. This benchmark parses a deterministic, synthetic
//! `ps`-like output string instead.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pt_core::collect::parse_ps_output_synthetic_linux;

fn build_synthetic_ps_output_10k() -> String {
    // Header is optional; parser should skip it if present.
    let mut out = String::from("PID PPID UID USER PGID SID STATE %CPU RSS VSZ TTY LSTART ETIMES COMM ARGS\n");

    for i in 0..10_000u32 {
        let pid = 1000 + i;
        let ppid = 1;
        let uid = 1000;
        let pgid = pid;
        let sid = pid;
        let state = if i % 3 == 0 { "S" } else { "R" };
        let cpu = ((i % 100) as f64) / 10.0;
        let rss = 10_000 + (i % 1000); // KB
        let vsz = 50_000 + (i % 5000); // KB
        let tty = "?";
        let etimes = 3600 + (i as u64);

        // Fields must match the expected positions in `parse_ps_line_*`:
        // pid ppid uid user pgid sid state %cpu rss vsz tty lstart(5 fields) etimes comm args...
        out.push_str(&format!(
            "{pid} {ppid} {uid} user {pgid} {sid} {state} {cpu:.1} {rss} {vsz} {tty} Tue Jan 1 00:00:00 2026 {etimes} proc proc --synthetic {pid}\n"
        ));
    }

    out
}

fn bench_quick_scan_parse(c: &mut Criterion) {
    let input = build_synthetic_ps_output_10k();

    let mut group = c.benchmark_group("quick_scan");
    group.bench_function("parse_ps_output_synthetic_10k", |b| {
        b.iter(|| {
            let procs = parse_ps_output_synthetic_linux(black_box(&input))
                .expect("synthetic ps output should parse");
            black_box(procs.len());
        })
    });
    group.finish();
}

criterion_group!(benches, bench_quick_scan_parse);
criterion_main!(benches);

