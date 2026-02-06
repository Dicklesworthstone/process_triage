//! Criterion benchmarks for hot-path parsers in `pt-core`.
//!
//! These benchmarks intentionally avoid touching real `/proc` so they can run
//! deterministically in CI and on developer machines.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use pt_core::collect::parse_proc_stat_content;
use pt_core::collect::proc_parsers::parse_io_content;

fn bench_parse_proc_stat_content(c: &mut Criterion) {
    // Minimum viable `/proc/<pid>/stat` content for fields accessed in parse_proc_stat_content.
    // Format: pid (comm) state ppid pgrp session tty_nr tpgid flags ... utime stime ... nice num_threads ... starttime vsize rss
    let stat = "12345 (bash) S 1 2 3 4 5 0 0 0 0 0 100 200 0 0 20 1 4 0 123456 1000000 1024";
    let stat_with_spaces =
        "12345 (node dev server) S 1 2 3 4 5 0 0 0 0 0 100 200 0 0 20 1 4 0 123456 1000000 1024";

    let mut group = c.benchmark_group("collect_parsers");

    for (name, s) in [
        ("simple_comm", stat),
        ("spaces_in_comm", stat_with_spaces),
    ] {
        group.bench_with_input(
            BenchmarkId::new("parse_proc_stat_content", name),
            &s,
            |b, input| {
                b.iter(|| {
                    let parsed = parse_proc_stat_content(black_box(input))
                        .expect("stat should parse");
                    black_box(parsed);
                });
            },
        );
    }

    group.finish();
}

fn bench_parse_io_content(c: &mut Criterion) {
    // Representative `/proc/<pid>/io` excerpt.
    let io = "\
rchar: 123456
wchar: 234567
syscr: 345
syscw: 456
read_bytes: 7890
write_bytes: 8901
cancelled_write_bytes: 0
";

    c.bench_function("collect_parsers/parse_io_content", |b| {
        b.iter(|| {
            let parsed = parse_io_content(black_box(io)).expect("io should parse");
            black_box(parsed);
        })
    });
}

criterion_group!(benches, bench_parse_proc_stat_content, bench_parse_io_content);
criterion_main!(benches);
