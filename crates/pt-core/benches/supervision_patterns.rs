//! Criterion benchmarks for supervision signature matching, command normalization,
//! pattern candidate generation, and pattern statistics tracking.
//!
//! Benchmarks `SignatureDatabase` (match_process/best_match/find_by_*),
//! `CommandNormalizer` (normalize/generate_candidates), and `PatternStats`
//! (record_match/acceptance_rate/lifecycle) — supervision-engine hotpaths.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use pt_core::supervision::pattern_persistence::{
    AllPatternStats, DisabledPatterns, PatternLifecycle, PatternStats,
};
use pt_core::supervision::pattern_learning::CommandNormalizer;
use pt_core::supervision::signature::ProcessMatchContext;
use pt_core::supervision::SignatureDatabase;
use std::collections::HashMap;

// ── Helpers ──────────────────────────────────────────────────────────

fn make_signature_database() -> SignatureDatabase {
    SignatureDatabase::new()
}

fn make_match_context<'a>(
    comm: &'a str,
    cmdline: &'a str,
    parent: Option<&'a str>,
    env: Option<&'a HashMap<String, String>>,
) -> ProcessMatchContext<'a> {
    let mut ctx = ProcessMatchContext::with_comm(comm).cmdline(cmdline);
    if let Some(p) = parent {
        ctx = ctx.parent_comm(p);
    }
    if let Some(e) = env {
        ctx = ctx.env_vars(e);
    }
    ctx
}

// ── SignatureDatabase benchmarks ────────────────────────────────────

fn bench_database_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("supervision/database");

    group.bench_function("new", |b| {
        b.iter(|| {
            let db = SignatureDatabase::new();
            black_box(db.len());
        })
    });

    group.finish();
}

fn bench_match_process(c: &mut Criterion) {
    let mut group = c.benchmark_group("supervision/match_process");
    let db = make_signature_database();

    // Common process names
    let processes = [
        ("systemd", "/usr/lib/systemd/systemd --system", None),
        ("node", "/usr/bin/node /app/server.js", None),
        ("python3", "/usr/bin/python3 -m pytest tests/", None),
        ("nginx", "nginx: master process /usr/sbin/nginx", None),
        ("java", "/usr/bin/java -jar app.jar", None),
        ("containerd-shim", "containerd-shim -namespace moby", Some("containerd")),
        ("unknown_proc", "/custom/binary --flag", None),
    ];

    for (comm, cmdline, parent) in &processes {
        let ctx = make_match_context(comm, cmdline, *parent, None);
        group.bench_function(
            BenchmarkId::new("process", *comm),
            |b| {
                b.iter(|| {
                    let matches = db.match_process(black_box(&ctx));
                    black_box(matches.len());
                })
            },
        );
    }

    group.finish();
}

fn bench_best_match(c: &mut Criterion) {
    let mut group = c.benchmark_group("supervision/best_match");
    let db = make_signature_database();

    for (comm, cmdline) in [
        ("systemd", "/usr/lib/systemd/systemd"),
        ("node", "/usr/bin/node test.js"),
        ("nginx", "nginx: worker process"),
        ("unknown", "/tmp/mystery"),
    ] {
        let ctx = make_match_context(comm, cmdline, None, None);
        group.bench_function(BenchmarkId::new("process", comm), |b| {
            b.iter(|| {
                let best = db.best_match(black_box(&ctx));
                black_box(best.is_some());
            })
        });
    }

    group.finish();
}

fn bench_find_by_name(c: &mut Criterion) {
    let mut group = c.benchmark_group("supervision/find_by");
    let db = make_signature_database();

    // find_by_process_name
    for name in ["systemd", "docker", "node", "unknown_proc"] {
        group.bench_function(BenchmarkId::new("process_name", name), |b| {
            b.iter(|| {
                let results = db.find_by_process_name(black_box(name));
                black_box(results.len());
            })
        });
    }

    // find_by_parent_name
    for parent in ["containerd", "systemd", "init"] {
        group.bench_function(BenchmarkId::new("parent_name", parent), |b| {
            b.iter(|| {
                let results = db.find_by_parent_name(black_box(parent));
                black_box(results.len());
            })
        });
    }

    group.finish();
}

fn bench_match_with_env(c: &mut Criterion) {
    let mut group = c.benchmark_group("supervision/match_with_env");
    let db = make_signature_database();

    // Process with environment variables (Docker-like)
    let env: HashMap<String, String> = [
        ("DOCKER_HOST".to_string(), "unix:///var/run/docker.sock".to_string()),
        ("HOME".to_string(), "/root".to_string()),
        ("PATH".to_string(), "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin".to_string()),
    ].into_iter().collect();

    let ctx = ProcessMatchContext::with_comm("containerd")
        .cmdline("/usr/bin/containerd")
        .env_vars(&env);

    group.bench_function("docker_env", |b| {
        b.iter(|| {
            let matches = db.match_process(black_box(&ctx));
            black_box(matches.len());
        })
    });

    // Process without env (faster path)
    let ctx_no_env = ProcessMatchContext::with_comm("containerd")
        .cmdline("/usr/bin/containerd");

    group.bench_function("no_env", |b| {
        b.iter(|| {
            let matches = db.match_process(black_box(&ctx_no_env));
            black_box(matches.len());
        })
    });

    group.finish();
}

// ── CommandNormalizer benchmarks ─────────────────────────────────────

fn bench_normalize_process_name(c: &mut Criterion) {
    let mut group = c.benchmark_group("supervision/normalize_name");
    let normalizer = CommandNormalizer::new();

    let names = [
        "node",
        "python3.11",
        "gunicorn-worker-3",
        "java",
        "[kworker/0:1-events]",
        "containerd-shim-runc-v2",
    ];

    for name in &names {
        group.bench_function(BenchmarkId::new("name", *name), |b| {
            b.iter(|| {
                let normalized = normalizer.normalize_process_name(black_box(name));
                black_box(normalized);
            })
        });
    }

    group.finish();
}

fn bench_generate_candidates(c: &mut Criterion) {
    let mut group = c.benchmark_group("supervision/generate_candidates");
    let normalizer = CommandNormalizer::new();

    let commands = [
        ("node", "/usr/bin/node /home/user/project/server.js --port 3000"),
        ("python3", "/usr/bin/python3 -m pytest tests/ -v --timeout=30"),
        ("java", "/usr/bin/java -Xmx4g -jar /opt/app/application.jar --spring.profiles.active=prod"),
        ("nginx", "nginx: master process /usr/sbin/nginx -c /etc/nginx/nginx.conf"),
        ("bash", "/bin/bash -c 'while true; do sleep 1; done'"),
    ];

    for (name, cmdline) in &commands {
        group.bench_function(BenchmarkId::new("command", *name), |b| {
            b.iter(|| {
                let candidates = normalizer.generate_candidates(
                    black_box(name),
                    black_box(cmdline),
                );
                black_box(candidates.len());
            })
        });
    }

    // Long command line
    let long_cmdline = format!(
        "/usr/bin/java {} -jar app.jar",
        (0..50).map(|i| format!("-Dprop{}=value{}", i, i)).collect::<Vec<_>>().join(" ")
    );
    group.bench_function("long_cmdline", |b| {
        b.iter(|| {
            let candidates = normalizer.generate_candidates(
                black_box("java"),
                black_box(&long_cmdline),
            );
            black_box(candidates.len());
        })
    });

    group.finish();
}

// ── PatternStats benchmarks ─────────────────────────────────────────

fn bench_pattern_stats(c: &mut Criterion) {
    let mut group = c.benchmark_group("supervision/pattern_stats");

    // Record matches
    for n in [10, 50, 100] {
        group.bench_function(BenchmarkId::new("record_match", n), |b| {
            b.iter(|| {
                let mut stats = PatternStats::default();
                for i in 0..n {
                    stats.record_match(black_box(i % 3 != 0)); // ~67% acceptance
                }
                black_box(stats.acceptance_rate());
            })
        });
    }

    // Acceptance rate computation
    group.bench_function("acceptance_rate", |b| {
        let mut stats = PatternStats::default();
        for i in 0..50 {
            stats.record_match(i % 2 == 0);
        }
        b.iter(|| {
            let rate = stats.acceptance_rate();
            black_box(rate);
        })
    });

    // Lifecycle suggestion
    group.bench_function("suggested_lifecycle", |b| {
        let mut stats = PatternStats::default();
        for i in 0..30 {
            stats.record_match(i % 3 != 0);
        }
        b.iter(|| {
            let lifecycle = stats.suggested_lifecycle();
            black_box(lifecycle);
        })
    });

    group.finish();
}

fn bench_all_pattern_stats(c: &mut Criterion) {
    let mut group = c.benchmark_group("supervision/all_stats");

    // Record matches across multiple patterns
    for n_patterns in [5, 20, 50] {
        group.bench_function(BenchmarkId::new("record", n_patterns), |b| {
            b.iter(|| {
                let mut all = AllPatternStats::default();
                for p in 0..n_patterns {
                    let name = format!("pattern-{}", p);
                    for i in 0..10 {
                        all.record_match(&name, i % 2 == 0);
                    }
                }
                black_box(all.get("pattern-0"));
            })
        });
    }

    // Lookup
    group.bench_function("get", |b| {
        let mut all = AllPatternStats::default();
        for p in 0..20 {
            all.record_match(&format!("pattern-{}", p), true);
        }
        b.iter(|| {
            let stats = all.get(black_box("pattern-10"));
            black_box(stats.is_some());
        })
    });

    group.finish();
}

fn bench_disabled_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("supervision/disabled_patterns");

    for n in [5, 20, 50] {
        let mut disabled = DisabledPatterns::default();
        for i in 0..n {
            disabled.disable(&format!("pattern-{}", i), Some("testing"));
        }

        group.bench_function(BenchmarkId::new("is_disabled_hit", n), |b| {
            b.iter(|| {
                let result = disabled.is_disabled(black_box("pattern-5"));
                black_box(result);
            })
        });

        group.bench_function(BenchmarkId::new("is_disabled_miss", n), |b| {
            b.iter(|| {
                let result = disabled.is_disabled(black_box("not-disabled"));
                black_box(result);
            })
        });
    }

    group.finish();
}

fn bench_pattern_lifecycle(c: &mut Criterion) {
    let mut group = c.benchmark_group("supervision/lifecycle");

    for (confidence, matches) in [(0.3, 5u32), (0.7, 20), (0.95, 100)] {
        group.bench_function(
            BenchmarkId::new("from_stats", format!("c{}_m{}", (confidence * 100.0) as u32, matches)),
            |b| {
                b.iter(|| {
                    let lc = PatternLifecycle::from_stats(
                        black_box(confidence),
                        black_box(matches),
                    );
                    black_box(lc.is_active());
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_database_construction,
    bench_match_process,
    bench_best_match,
    bench_find_by_name,
    bench_match_with_env,
    bench_normalize_process_name,
    bench_generate_candidates,
    bench_pattern_stats,
    bench_all_pattern_stats,
    bench_disabled_patterns,
    bench_pattern_lifecycle
);
criterion_main!(benches);
