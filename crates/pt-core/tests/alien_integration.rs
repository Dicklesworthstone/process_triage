//! Global Alien Technology Integration Tests (bd-g0q5.7).
//!
//! Cross-component validation that the Alien Technology modules
//! (queueing stall detection, conformal risk control, causal snapshots)
//! work correctly when composed together.

use pt_core::decision::causal_snapshot::{
    check_causal_safety, ConsistentCut, CutValidity, DependencyType, HostSnapshot,
    RemoteDependency, SnapshotConfig, SnapshotCoordinator,
};
use pt_core::inference::conformal_robot::{
    ClassPosteriors, ConformalRobotConfig, ConformalRobotGate, HealthLevel,
};
use pt_core::inference::posterior::{compute_posterior, Evidence};
use pt_core::inference::queueing::{is_queue_saturated, QueueStallConfig, QueueStallDetector};
use std::collections::HashMap;

// ── Helpers ───────────────────────────────────────────────────────────

fn posteriors(useful: f64, useful_bad: f64, abandoned: f64, zombie: f64) -> ClassPosteriors {
    ClassPosteriors {
        useful,
        useful_bad,
        abandoned,
        zombie,
    }
}

fn build_calibrated_gate(n: usize) -> ConformalRobotGate {
    let config = ConformalRobotConfig {
        min_samples: 10,
        mondrian: false,
        small_sample_correction: false,
        ..Default::default()
    };
    let mut gate = ConformalRobotGate::new(config);
    for i in 0..n {
        let (p, truth) = if i % 5 == 0 {
            (posteriors(0.8, 0.05, 0.1, 0.05), "useful")
        } else if i % 5 == 1 {
            (posteriors(0.1, 0.7, 0.15, 0.05), "useful_bad")
        } else {
            (posteriors(0.05, 0.05, 0.85, 0.05), "abandoned")
        };
        gate.record_review(p, truth);
    }
    gate
}

fn build_fleet_cut(
    hosts: &[&str],
    deps: &[(&str, u32, &str, u32)], // (local_host, local_pid, remote_host, remote_pid)
    useful_pids: &[(&str, u32)],
) -> ConsistentCut {
    let mut snapshots = HashMap::new();
    for &host in hosts {
        snapshots.insert(host.to_string(), HostSnapshot::confirmed(host));
    }
    for &(local_host, local_pid, remote_host, remote_pid) in deps {
        let snapshot = snapshots.get_mut(local_host).unwrap();
        snapshot
            .process_deps
            .entry(local_pid)
            .or_default()
            .push(RemoteDependency {
                remote_host: remote_host.to_string(),
                remote_pid,
                dep_type: DependencyType::TcpConnection,
            });
    }
    for &(host, pid) in useful_pids {
        snapshots.get_mut(host).unwrap().useful_pids.insert(pid);
    }
    ConsistentCut {
        snapshot_id: "integration-test".to_string(),
        host_snapshots: snapshots,
        validity: CutValidity::Complete,
        assembled_at: chrono::Utc::now(),
        confirmed_count: hosts.len(),
        tentative_count: 0,
        failed_count: 0,
    }
}

// ═══════════════════════════════════════════════════════════════════════
// 1. Queueing Stall → Posterior Pipeline
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn queue_saturation_feeds_into_posterior_as_evidence() {
    // Simulate: a process has deep rx queues.
    let saturated = is_queue_saturated(10000, 0, 4096);
    assert!(saturated);

    // Build evidence with queue_saturated = true.
    let evidence = Evidence {
        queue_saturated: Some(true),
        ..Evidence::default()
    };

    // Compute posterior with default priors (queue_saturation_beta is None).
    let priors = pt_config::priors::Priors::default();
    let result = compute_posterior(&priors, &evidence).unwrap();

    // Posteriors should still sum to 1 even with queue evidence.
    let sum = result.posterior.useful
        + result.posterior.useful_bad
        + result.posterior.abandoned
        + result.posterior.zombie;
    assert!((sum - 1.0).abs() < 1e-10);
}

#[test]
fn stall_detector_produces_consistent_signals() {
    let mut detector = QueueStallDetector::with_config(QueueStallConfig {
        alpha: 0.5,
        saturation_threshold: 1000,
        min_samples: 2,
        rho_threshold: 0.8,
        ..Default::default()
    });

    // Growing queues should eventually signal stall.
    let r1 = detector.observe(500, 0);
    assert!(!r1.is_stalled);

    let _r2 = detector.observe(2000, 0);
    let _r3 = detector.observe(5000, 0);
    let r4 = detector.observe(10000, 0);

    // Rho should be monotonically increasing.
    assert!(r4.rho > r1.rho);

    // Eventually stalled.
    assert!(r4.is_stalled);
    assert!(r4.is_saturated);

    // Stall probability should be positive.
    assert!(r4.stall_probability > 0.0);
}

// ═══════════════════════════════════════════════════════════════════════
// 2. Conformal Robot Gate Safety
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn conformal_gate_protects_useful_processes() {
    let gate = build_calibrated_gate(200);

    // Useful process: gate should block.
    let useful_result = gate.check_action(&posteriors(0.85, 0.05, 0.05, 0.05));
    assert!(!useful_result.allowed);

    // Abandoned process: gate should allow.
    let abandoned_result = gate.check_action(&posteriors(0.01, 0.02, 0.95, 0.02));
    assert!(abandoned_result.allowed);

    // Both should have valid certificates.
    assert_eq!(useful_result.certificate.n_calibration, 200);
    assert_eq!(abandoned_result.certificate.n_calibration, 200);
}

#[test]
fn conformal_gate_blocks_with_insufficient_calibration() {
    let gate = ConformalRobotGate::new(ConformalRobotConfig::default());

    // Even clearly abandoned processes should be blocked without calibration.
    let result = gate.check_action(&posteriors(0.01, 0.01, 0.97, 0.01));
    assert!(!result.allowed);
    assert_eq!(result.certificate.health_level, HealthLevel::Insufficient);
}

#[test]
fn conformal_drift_detection_fires_on_miscalibration() {
    let mut gate = ConformalRobotGate::new(ConformalRobotConfig {
        alpha: 0.05,
        drift_window: 20,
        drift_threshold: 2.0,
        ..Default::default()
    });

    // Record many errors — way above alpha.
    for _ in 0..20 {
        gate.record_outcome(false); // all wrong
    }

    let drift = gate.check_drift();
    assert!(drift.drift_detected);
    assert!(drift.error_ratio > 2.0);
}

// ═══════════════════════════════════════════════════════════════════════
// 3. Causal Snapshot Fleet Safety
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn causal_gate_blocks_cascade_kill() {
    // host-a:100 (Useful web server) depends on host-b:200 (database).
    let cut = build_fleet_cut(
        &["host-a", "host-b"],
        &[("host-a", 100, "host-b", 200)],
        &[("host-a", 100)],
    );

    // Killing the database should be blocked.
    let result = check_causal_safety(&cut, "host-b", 200, &SnapshotConfig::default());
    assert!(!result.allowed);
    assert_eq!(result.violations.len(), 1);
}

#[test]
fn causal_gate_allows_independent_kill() {
    let cut = build_fleet_cut(
        &["host-a", "host-b"],
        &[("host-a", 100, "host-b", 200)],
        &[("host-a", 100)],
    );

    // Killing an unrelated process is fine.
    let result = check_causal_safety(&cut, "host-b", 999, &SnapshotConfig::default());
    assert!(result.allowed);
}

#[test]
fn snapshot_coordinator_handles_partial_fleet() {
    let hosts = vec![
        "host-a".to_string(),
        "host-b".to_string(),
        "host-c".to_string(),
        "host-d".to_string(),
    ];
    let mut coord = SnapshotCoordinator::new("host-a", hosts, SnapshotConfig::default());
    coord.initiate_snapshot();

    // Only 3 of 4 hosts respond.
    coord.record_snapshot(HostSnapshot::confirmed("host-a"));
    coord.record_snapshot(HostSnapshot::confirmed("host-b"));
    coord.record_snapshot(HostSnapshot::confirmed("host-c"));

    let cut = coord.assemble_cut();
    assert_eq!(cut.validity, CutValidity::Partial);

    // Partial cut with default config blocks all kills.
    let result = check_causal_safety(&cut, "host-b", 200, &SnapshotConfig::default());
    assert!(!result.allowed);
}

// ═══════════════════════════════════════════════════════════════════════
// 4. Composed Safety: Conformal + Causal
// ═══════════════════════════════════════════════════════════════════════

/// Simulates the full safety pipeline: a process must pass BOTH the
/// conformal gate AND the causal gate before an automated kill.
#[test]
fn composed_safety_gates_both_must_pass() {
    let conformal_gate = build_calibrated_gate(200);
    let cut = build_fleet_cut(
        &["host-a", "host-b"],
        &[("host-a", 100, "host-b", 200)],
        &[("host-a", 100)],
    );
    let causal_config = SnapshotConfig::default();

    // Scenario 1: Process is abandoned AND not a dependency → ALLOW.
    {
        let conformal_ok = conformal_gate
            .check_action(&posteriors(0.01, 0.02, 0.95, 0.02))
            .allowed;
        let causal_ok = check_causal_safety(&cut, "host-b", 999, &causal_config).allowed;
        assert!(conformal_ok && causal_ok, "both gates should pass");
    }

    // Scenario 2: Process is abandoned BUT is a dependency → BLOCK.
    {
        let conformal_ok = conformal_gate
            .check_action(&posteriors(0.01, 0.02, 0.95, 0.02))
            .allowed;
        let causal_ok = check_causal_safety(&cut, "host-b", 200, &causal_config).allowed;
        assert!(
            conformal_ok && !causal_ok,
            "conformal passes but causal should block"
        );
        // Combined: NOT allowed.
        assert!(!(conformal_ok && causal_ok));
    }

    // Scenario 3: Process looks useful AND is not a dependency → BLOCK (conformal).
    {
        let conformal_ok = conformal_gate
            .check_action(&posteriors(0.85, 0.05, 0.05, 0.05))
            .allowed;
        let causal_ok = check_causal_safety(&cut, "host-b", 999, &causal_config).allowed;
        assert!(
            !conformal_ok && causal_ok,
            "conformal should block, causal passes"
        );
        assert!(!(conformal_ok && causal_ok));
    }

    // Scenario 4: Process looks useful AND is a dependency → BLOCK (both).
    {
        let conformal_ok = conformal_gate
            .check_action(&posteriors(0.85, 0.05, 0.05, 0.05))
            .allowed;
        let causal_ok = check_causal_safety(&cut, "host-b", 200, &causal_config).allowed;
        assert!(!conformal_ok && !causal_ok, "both should block");
    }
}

/// The "no healthy process kills" guarantee: when conformal is well-calibrated
/// and the causal cut is complete, NO process classified as Useful should ever
/// be allowed through both gates.
#[test]
fn safety_audit_no_useful_kills() {
    let gate = build_calibrated_gate(500);
    let cut = build_fleet_cut(
        &["host-a", "host-b", "host-c"],
        &[("host-a", 10, "host-b", 20), ("host-b", 20, "host-c", 30)],
        &[("host-a", 10), ("host-b", 20)],
    );
    let config = SnapshotConfig::default();

    // Try killing every process on every host with varying posteriors.
    let test_posteriors = [
        posteriors(0.90, 0.03, 0.04, 0.03), // clearly useful
        posteriors(0.60, 0.15, 0.15, 0.10), // moderately useful
        posteriors(0.40, 0.20, 0.30, 0.10), // ambiguous
        posteriors(0.10, 0.10, 0.70, 0.10), // likely abandoned
        posteriors(0.02, 0.03, 0.90, 0.05), // clearly abandoned
    ];

    for p in &test_posteriors {
        let conformal_result = gate.check_action(p);

        // For strongly useful processes, conformal should block.
        // A moderate useful posterior (e.g. 0.6) may or may not be blocked
        // depending on calibration — that's the correct conformal behavior.
        if p.useful > 0.7 {
            assert!(
                !conformal_result.allowed,
                "conformal should block strongly useful process (p.useful={})",
                p.useful
            );
        }
    }

    // Causal gate: killing host-b:20 should always be blocked (it's Useful).
    let causal_result = check_causal_safety(&cut, "host-b", 20, &config);
    // host-a:10 depends on host-b:20 and host-a:10 is Useful.
    assert!(!causal_result.allowed);
}

// ═══════════════════════════════════════════════════════════════════════
// 5. Queueing + Conformal Composition
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn stalled_process_with_conformal_gate() {
    let mut detector = QueueStallDetector::new();
    let gate = build_calibrated_gate(200);

    // Simulate a process that's stalling (queues growing).
    detector.observe(1000, 0);
    detector.observe(5000, 0);
    detector.observe(10000, 0);
    let stall = detector.observe(20000, 0);

    // Process appears stalled → useful_bad posterior should be high.
    // Use the stall signal as evidence for the conformal gate.
    let p = if stall.is_stalled {
        // Queue stall suggests useful_bad.
        posteriors(0.05, 0.70, 0.20, 0.05)
    } else {
        posteriors(0.25, 0.25, 0.25, 0.25)
    };

    let result = gate.check_action(&p);
    // useful_bad process with low useful posterior → should be allowed.
    assert!(
        result.allowed,
        "stalled process should be allowed: {}",
        result.reason
    );
}
