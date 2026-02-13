//! Criterion benchmarks for escalation management, fleet registry, fleet pattern
//! correlation, and fleet FDR coordination.
//!
//! Benchmarks `EscalationManager` (submit/flush/prune/persist), `FleetRegistry`
//! (register/heartbeat/check), `correlate_fleet_patterns`, and
//! `FleetFdrCoordinator` (submit_e_value/rebalance/pool_evidence/compute_fdr)
//! — safety-gating and fleet-coordination hotpaths.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use pt_core::decision::escalation::{
    EscalationConfig, EscalationManager, EscalationTrigger, Severity, TriggerType,
};
use pt_core::decision::fleet_fdr::{FleetFdrConfig, FleetFdrCoordinator};
use pt_core::decision::fleet_pattern::{
    correlate_fleet_patterns, FleetPatternConfig, PatternObservation,
};
use pt_core::decision::fleet_registry::{
    FleetRegistry, FleetRegistryConfig, Heartbeat, HostCapabilities, HostRole,
};

// ── Helpers ──────────────────────────────────────────────────────────

fn make_trigger(id: usize, severity: Severity, ts: f64) -> EscalationTrigger {
    let trigger_type = match id % 6 {
        0 => TriggerType::MemoryPressure,
        1 => TriggerType::CpuPressure,
        2 => TriggerType::OrphanSpike,
        3 => TriggerType::HighRiskCandidates,
        4 => TriggerType::FleetAlert,
        _ => TriggerType::ThresholdExceeded,
    };
    EscalationTrigger {
        trigger_id: format!("trigger-{}", id),
        dedupe_key: format!("key-{}", id),
        trigger_type,
        severity,
        confidence: Some(0.7 + (id as f64 * 0.03) % 0.3),
        summary: format!("Test trigger {}", id),
        detected_at: ts,
        session_id: None,
    }
}

fn make_capabilities(idx: usize) -> HostCapabilities {
    HostCapabilities {
        cores: 4 + (idx as u32 % 12),
        memory_gb: 8.0 + (idx as f64 * 4.0) % 56.0,
        pt_version: "2.0.3".to_string(),
        features: vec!["deep".to_string()],
    }
}

fn make_observations(n_hosts: usize, n_patterns: usize) -> Vec<PatternObservation> {
    let mut obs = Vec::new();
    for h in 0..n_hosts {
        for p in 0..n_patterns {
            obs.push(PatternObservation {
                host_id: format!("host-{}", h),
                pattern_key: format!("pattern-{}", p),
                instance_count: 3 + (h + p) % 10,
                avg_cpu: 0.05 + (p as f64 * 0.1) % 0.9,
                avg_rss_bytes: 100_000_000 + ((h * p) as u64 % 500_000_000),
                earliest_spawn_ts: 1000.0 + (h as f64 * 10.0),
                latest_spawn_ts: 1050.0 + (h as f64 * 10.0),
                abandoned_fraction: 0.3 + (p as f64 * 0.1) % 0.6,
                deploy_sha: if p % 3 == 0 {
                    Some("abc1234".to_string())
                } else {
                    None
                },
            });
        }
    }
    obs
}

// ── Escalation benchmarks ───────────────────────────────────────────

fn bench_escalation_submit(c: &mut Criterion) {
    let mut group = c.benchmark_group("escalation/submit");
    let config = EscalationConfig::default();

    // Single trigger submission
    group.bench_function("single", |b| {
        b.iter(|| {
            let mut mgr = EscalationManager::new(config.clone());
            let trigger = make_trigger(0, Severity::Warning, 100.0);
            let accepted = mgr.submit_trigger(black_box(trigger));
            black_box(accepted);
        })
    });

    // Batch submission (varying count)
    for n in [5, 10, 25] {
        group.bench_function(BenchmarkId::new("batch", n), |b| {
            let triggers: Vec<_> = (0..n)
                .map(|i| make_trigger(i, Severity::Warning, 100.0 + i as f64))
                .collect();
            b.iter(|| {
                let mut mgr = EscalationManager::new(config.clone());
                for t in &triggers {
                    mgr.submit_trigger(black_box(t.clone()));
                }
                black_box(mgr.pending_count());
            })
        });
    }

    // Dedupe: re-submit same key
    group.bench_function("dedupe_reject", |b| {
        let mut mgr = EscalationManager::new(config.clone());
        let trigger = make_trigger(0, Severity::Warning, 100.0);
        mgr.submit_trigger(trigger.clone());
        b.iter(|| {
            let accepted = mgr.submit_trigger(black_box(trigger.clone()));
            black_box(accepted);
        })
    });

    group.finish();
}

fn bench_escalation_flush(c: &mut Criterion) {
    let mut group = c.benchmark_group("escalation/flush");
    let config = EscalationConfig::default();

    // Flush with pending triggers
    for n in [1, 5, 10] {
        group.bench_function(BenchmarkId::new("pending", n), |b| {
            b.iter(|| {
                let mut mgr = EscalationManager::new(config.clone());
                for i in 0..n {
                    mgr.submit_trigger(make_trigger(i, Severity::Warning, 100.0 + i as f64));
                }
                let notifications = mgr.flush(black_box(200.0));
                black_box(notifications.len());
            })
        });
    }

    // Flush with mixed severities
    group.bench_function("mixed_severity", |b| {
        b.iter(|| {
            let mut mgr = EscalationManager::new(config.clone());
            mgr.submit_trigger(make_trigger(0, Severity::Info, 100.0));
            mgr.submit_trigger(make_trigger(1, Severity::Warning, 101.0));
            mgr.submit_trigger(make_trigger(2, Severity::Critical, 102.0));
            let notifications = mgr.flush(black_box(200.0));
            black_box(notifications.len());
        })
    });

    group.finish();
}

fn bench_escalation_persist(c: &mut Criterion) {
    let mut group = c.benchmark_group("escalation/persist");
    let config = EscalationConfig::default();

    // Round-trip: persist → restore
    for n in [5, 15] {
        group.bench_function(BenchmarkId::new("roundtrip", n), |b| {
            let mut mgr = EscalationManager::new(config.clone());
            for i in 0..n {
                mgr.submit_trigger(make_trigger(i, Severity::Warning, 100.0 + i as f64));
            }
            let _ = mgr.flush(200.0);
            b.iter(|| {
                let state = mgr.persisted_state();
                let restored = EscalationManager::from_persisted(config.clone(), state);
                black_box(restored.total_sent());
            })
        });
    }

    group.finish();
}

fn bench_escalation_prune(c: &mut Criterion) {
    let mut group = c.benchmark_group("escalation/prune");
    let config = EscalationConfig::default();

    for n in [10, 25] {
        group.bench_function(BenchmarkId::new("triggers", n), |b| {
            b.iter(|| {
                let mut mgr = EscalationManager::new(config.clone());
                for i in 0..n {
                    mgr.submit_trigger(make_trigger(i, Severity::Warning, i as f64));
                }
                let _ = mgr.flush(50.0);
                mgr.prune(black_box(100_000.0));
                black_box(mgr.pending_count());
            })
        });
    }

    group.finish();
}

// ── Fleet registry benchmarks ───────────────────────────────────────

fn bench_registry_register(c: &mut Criterion) {
    let mut group = c.benchmark_group("fleet_registry/register");
    let config = FleetRegistryConfig::default();

    // Single registration
    group.bench_function("single", |b| {
        b.iter(|| {
            let mut reg = FleetRegistry::new(config.clone());
            let _ = reg.register(
                "host-0".to_string(),
                "web-0.example.com".to_string(),
                vec!["10.0.0.1".to_string()],
                make_capabilities(0),
                HostRole::Member,
                black_box(1000.0),
                None,
            );
            black_box(reg.fleet_size());
        })
    });

    // Batch registration
    for n in [5, 10, 25] {
        group.bench_function(BenchmarkId::new("batch", n), |b| {
            b.iter(|| {
                let mut reg = FleetRegistry::new(config.clone());
                for i in 0..n {
                    let _ = reg.register(
                        format!("host-{}", i),
                        format!("web-{}.example.com", i),
                        vec![format!("10.0.0.{}", i + 1)],
                        make_capabilities(i),
                        if i == 0 {
                            HostRole::Coordinator
                        } else {
                            HostRole::Member
                        },
                        black_box(1000.0),
                        None,
                    );
                }
                black_box(reg.fleet_size());
            })
        });
    }

    group.finish();
}

fn bench_registry_heartbeat(c: &mut Criterion) {
    let mut group = c.benchmark_group("fleet_registry/heartbeat");
    let config = FleetRegistryConfig::default();

    for n_hosts in [5, 15] {
        let mut reg = FleetRegistry::new(config.clone());
        for i in 0..n_hosts {
            let _ = reg.register(
                format!("host-{}", i),
                format!("web-{}.example.com", i),
                vec![format!("10.0.0.{}", i + 1)],
                make_capabilities(i),
                HostRole::Member,
                1000.0,
                None,
            );
        }

        group.bench_with_input(BenchmarkId::new("hosts", n_hosts), &reg, |b, registry| {
            b.iter(|| {
                let mut reg = registry.clone();
                for i in 0..n_hosts {
                    let hb = Heartbeat {
                        host_id: format!("host-{}", i),
                        timestamp: 1010.0,
                        process_count: Some(50 + i),
                        active_kills: Some(i % 3),
                    };
                    let _ = reg.heartbeat(black_box(&hb));
                }
                black_box(reg.active_host_count());
            })
        });
    }

    group.finish();
}

fn bench_registry_check_heartbeats(c: &mut Criterion) {
    let mut group = c.benchmark_group("fleet_registry/check_heartbeats");
    let config = FleetRegistryConfig::default();

    for n_hosts in [10, 25] {
        let mut reg = FleetRegistry::new(config.clone());
        for i in 0..n_hosts {
            let _ = reg.register(
                format!("host-{}", i),
                format!("web-{}.example.com", i),
                vec![format!("10.0.0.{}", i + 1)],
                make_capabilities(i),
                HostRole::Member,
                1000.0,
                None,
            );
            // Stagger heartbeats: some will be degraded/offline
            let hb = Heartbeat {
                host_id: format!("host-{}", i),
                timestamp: 1000.0 + (i as f64 * 5.0),
                process_count: None,
                active_kills: None,
            };
            let _ = reg.heartbeat(&hb);
        }

        group.bench_with_input(BenchmarkId::new("hosts", n_hosts), &reg, |b, registry| {
            b.iter(|| {
                let mut reg = registry.clone();
                reg.check_heartbeats(black_box(2000.0));
                black_box(reg.active_host_count());
            })
        });
    }

    group.finish();
}

// ── Fleet pattern benchmarks ────────────────────────────────────────

fn bench_correlate_fleet_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("fleet_pattern/correlate");
    let config = FleetPatternConfig::default();

    // Vary fleet size × pattern count
    for (n_hosts, n_patterns) in [(3, 2), (5, 5), (10, 10), (20, 5)] {
        let obs = make_observations(n_hosts, n_patterns);

        group.bench_with_input(
            BenchmarkId::new("grid", format!("{}h_{}p", n_hosts, n_patterns)),
            &obs,
            |b, observations| {
                b.iter(|| {
                    let alerts =
                        correlate_fleet_patterns(black_box(observations), black_box(&config));
                    black_box(alerts.len());
                })
            },
        );
    }

    // All same deploy SHA → deploy correlation
    group.bench_function("deploy_correlated", |b| {
        let obs: Vec<_> = (0..10)
            .map(|h| PatternObservation {
                host_id: format!("host-{}", h),
                pattern_key: "leaky-svc".to_string(),
                instance_count: 5,
                avg_cpu: 0.3,
                avg_rss_bytes: 200_000_000,
                earliest_spawn_ts: 1000.0,
                latest_spawn_ts: 1005.0,
                abandoned_fraction: 0.8,
                deploy_sha: Some("deadbeef".to_string()),
            })
            .collect();
        b.iter(|| {
            let alerts = correlate_fleet_patterns(black_box(&obs), black_box(&config));
            black_box(alerts.len());
        })
    });

    // No correlations expected
    group.bench_function("no_correlation", |b| {
        let obs: Vec<_> = (0..3)
            .map(|h| PatternObservation {
                host_id: format!("host-{}", h),
                pattern_key: format!("unique-{}", h),
                instance_count: 1,
                avg_cpu: 0.01,
                avg_rss_bytes: 10_000_000,
                earliest_spawn_ts: 1000.0 + h as f64 * 1000.0,
                latest_spawn_ts: 1001.0 + h as f64 * 1000.0,
                abandoned_fraction: 0.1,
                deploy_sha: None,
            })
            .collect();
        b.iter(|| {
            let alerts = correlate_fleet_patterns(black_box(&obs), black_box(&config));
            black_box(alerts.len());
        })
    });

    group.finish();
}

// ── Fleet FDR benchmarks ────────────────────────────────────────────

fn bench_fdr_submit(c: &mut Criterion) {
    let mut group = c.benchmark_group("fleet_fdr/submit");
    let config = FleetFdrConfig::default();

    // Single submit
    group.bench_function("single", |b| {
        b.iter(|| {
            let mut coord = FleetFdrCoordinator::new(config.clone());
            coord.register_host("host-0", 50);
            let result = coord.submit_e_value(black_box("host-0"), black_box(2.5));
            black_box(result.approved);
        })
    });

    // Multiple hosts submitting
    for n_hosts in [5, 10, 20] {
        group.bench_function(BenchmarkId::new("hosts", n_hosts), |b| {
            b.iter(|| {
                let mut coord = FleetFdrCoordinator::new(config.clone());
                for i in 0..n_hosts {
                    coord.register_host(&format!("host-{}", i), 30 + i * 5);
                }
                for i in 0..n_hosts {
                    let e_val = 1.5 + (i as f64 * 0.3);
                    coord.submit_e_value(black_box(&format!("host-{}", i)), black_box(e_val));
                }
                black_box(coord.compute_fleet_fdr());
            })
        });
    }

    group.finish();
}

fn bench_fdr_rebalance(c: &mut Criterion) {
    let mut group = c.benchmark_group("fleet_fdr/rebalance");
    let config = FleetFdrConfig::default();

    for n_hosts in [5, 15, 30] {
        let mut coord = FleetFdrCoordinator::new(config.clone());
        for i in 0..n_hosts {
            coord.register_host(&format!("host-{}", i), 20 + i * 3);
            // Some hosts already submitted
            if i % 2 == 0 {
                coord.submit_e_value(&format!("host-{}", i), 1.5 + i as f64 * 0.1);
            }
        }

        group.bench_with_input(
            BenchmarkId::new("hosts", n_hosts),
            &coord,
            |b, coordinator| {
                b.iter(|| {
                    let mut c = coordinator.clone();
                    c.rebalance();
                    black_box(c.compute_fleet_fdr());
                })
            },
        );
    }

    group.finish();
}

fn bench_fdr_pool_evidence(c: &mut Criterion) {
    let mut group = c.benchmark_group("fleet_fdr/pool_evidence");
    let config = FleetFdrConfig::default();

    for n_hosts in [3, 8, 15] {
        let mut coord = FleetFdrCoordinator::new(config.clone());
        for i in 0..n_hosts {
            coord.register_host(&format!("host-{}", i), 40);
        }

        let host_evidence: Vec<(String, f64)> = (0..n_hosts)
            .map(|i| (format!("host-{}", i), 2.0 + i as f64 * 0.5))
            .collect();
        let refs: Vec<(&str, f64)> = host_evidence
            .iter()
            .map(|(h, v)| (h.as_str(), *v))
            .collect();

        group.bench_function(BenchmarkId::new("hosts", n_hosts), |b| {
            b.iter(|| {
                let pooled = coord.pool_evidence(black_box("pattern-leak"), black_box(&refs));
                black_box(pooled.combined_e_value);
            })
        });
    }

    group.finish();
}

fn bench_fdr_compute(c: &mut Criterion) {
    let mut group = c.benchmark_group("fleet_fdr/compute_fdr");

    let config = FleetFdrConfig::default();

    for n_hosts in [5, 15, 30] {
        let mut coord = FleetFdrCoordinator::new(config.clone());
        for i in 0..n_hosts {
            coord.register_host(&format!("host-{}", i), 25);
            // Submit varying e-values
            for j in 0..3 {
                coord.submit_e_value(
                    &format!("host-{}", i),
                    1.0 + (j as f64 * 0.5) + (i as f64 * 0.1),
                );
            }
        }

        group.bench_with_input(
            BenchmarkId::new("hosts", n_hosts),
            &coord,
            |b, coordinator| {
                b.iter(|| {
                    let fdr = coordinator.compute_fleet_fdr();
                    black_box(fdr);
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_escalation_submit,
    bench_escalation_flush,
    bench_escalation_persist,
    bench_escalation_prune,
    bench_registry_register,
    bench_registry_heartbeat,
    bench_registry_check_heartbeats,
    bench_correlate_fleet_patterns,
    bench_fdr_submit,
    bench_fdr_rebalance,
    bench_fdr_pool_evidence,
    bench_fdr_compute
);
criterion_main!(benches);
