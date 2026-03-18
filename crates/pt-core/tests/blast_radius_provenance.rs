//! Canonical graph-fixture regressions and user-visible blast-radius
//! diagnostics (bd-g0rn).
//!
//! Proves that blast-radius outputs stay stable and explainable as the
//! provenance graph evolves. Covers direct impact, indirect impact,
//! continuity deltas, and composed diagnostics.

use pt_common::{
    LockMechanism, RawResourceEvidence, ResourceCollectionMethod, ResourceDetails, ResourceKind,
    ResourceState,
};
use pt_core::collect::provenance_continuity::{
    compute_provenance_delta, pid_continuity, summarize_delta, PidContinuity,
};
use pt_core::collect::shared_resource_graph::SharedResourceGraph;
use pt_core::decision::direct_impact::{compute_direct_impact, DirectImpactConfig};
use pt_core::decision::indirect_impact::{compute_indirect_impact, IndirectImpactConfig};

// ── Fixtures ──────────────────────────────────────────────────────────

fn lock_ev(pid: u32, path: &str) -> RawResourceEvidence {
    RawResourceEvidence {
        kind: ResourceKind::Lockfile,
        key: path.to_string(),
        owner_pid: pid,
        collection_method: ResourceCollectionMethod::ProcFd,
        state: ResourceState::Active,
        details: ResourceDetails::Lockfile {
            path: path.to_string(),
            mechanism: LockMechanism::Existence,
        },
        observed_at: "2026-03-17T00:00:00Z".to_string(),
    }
}

fn listener_ev(pid: u32, port: u16) -> RawResourceEvidence {
    RawResourceEvidence {
        kind: ResourceKind::Listener,
        key: format!("tcp:{port}"),
        owner_pid: pid,
        collection_method: ResourceCollectionMethod::ProcNet,
        state: ResourceState::Active,
        details: ResourceDetails::Listener {
            protocol: "tcp".to_string(),
            port,
            bind_address: "0.0.0.0".to_string(),
        },
        observed_at: "2026-03-17T00:00:00Z".to_string(),
    }
}

/// Canonical "web stack" fixture:
/// - nginx (PID 100): listener on :80, :443
/// - app (PID 200): shares /run/app.lock with nginx, listener on :3000
/// - db (PID 300): listener on :5432, shares /run/db.lock with app
/// - worker (PID 400): shares /run/app.lock with nginx+app
/// - orphan (PID 500): solo lock, no connections
fn web_stack_graph() -> SharedResourceGraph {
    SharedResourceGraph::from_evidence(&[
        (
            100,
            vec![
                listener_ev(100, 80),
                listener_ev(100, 443),
                lock_ev(100, "/run/app.lock"),
            ],
        ),
        (
            200,
            vec![
                listener_ev(200, 3000),
                lock_ev(200, "/run/app.lock"),
                lock_ev(200, "/run/db.lock"),
            ],
        ),
        (
            300,
            vec![listener_ev(300, 5432), lock_ev(300, "/run/db.lock")],
        ),
        (400, vec![lock_ev(400, "/run/app.lock")]),
        (500, vec![lock_ev(500, "/tmp/orphan.lock")]),
    ])
}

// ═══════════════════════════════════════════════════════════════════════
// 1. Graph Fixture Stability
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn web_stack_resource_counts_stable() {
    let graph = web_stack_graph();
    // 5 unique resources: tcp:80, tcp:443, tcp:3000, tcp:5432,
    // /run/app.lock, /run/db.lock, /tmp/orphan.lock = 7
    assert_eq!(graph.resources.len(), 7);

    // nginx shares app.lock with app and worker.
    assert_eq!(graph.co_holders(100).len(), 2); // 200, 400
                                                // app shares with nginx, worker (via app.lock) and db (via db.lock).
    assert_eq!(graph.co_holders(200).len(), 3); // 100, 300, 400
                                                // db shares with app only.
    assert_eq!(graph.co_holders(300).len(), 1); // 200
                                                // worker shares with nginx and app.
    assert_eq!(graph.co_holders(400).len(), 2); // 100, 200
                                                // orphan shares with nobody.
    assert_eq!(graph.co_holders(500).len(), 0);
}

#[test]
fn contested_resources_in_web_stack() {
    let graph = web_stack_graph();
    let contested = graph.contested_resources();
    // /run/app.lock has 3 active holders → contested.
    // /run/db.lock has 2 active holders → contested.
    assert_eq!(contested.len(), 2);
}

// ═══════════════════════════════════════════════════════════════════════
// 2. Direct Impact Diagnostics
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn direct_impact_ranking_matches_intuition() {
    let graph = web_stack_graph();
    let config = DirectImpactConfig::default();

    // App server (PID 200) should have highest direct impact
    // (3 co-holders + listener + contested resources).
    let impact_app = compute_direct_impact(200, &graph, None, &[], &config);
    let impact_orphan = compute_direct_impact(500, &graph, None, &[], &config);
    let impact_db = compute_direct_impact(300, &graph, None, &[], &config);

    assert!(
        impact_app.score > impact_orphan.score,
        "app={} should exceed orphan={}",
        impact_app.score,
        impact_orphan.score,
    );
    assert!(
        impact_app.score > impact_db.score,
        "app={} should exceed db={}",
        impact_app.score,
        impact_db.score,
    );
}

#[test]
fn direct_impact_summary_is_human_readable() {
    let graph = web_stack_graph();
    let result = compute_direct_impact(200, &graph, None, &[], &DirectImpactConfig::default());
    // Summary should mention shared resources and listeners.
    assert!(
        result.summary.contains("shares"),
        "summary: {}",
        result.summary
    );
    assert!(
        result.summary.contains("listener"),
        "summary: {}",
        result.summary
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 3. Indirect Impact Diagnostics
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn indirect_impact_captures_transitive_chain() {
    let graph = web_stack_graph();
    let config = IndirectImpactConfig {
        max_hops: 2,
        ..Default::default()
    };

    // db (300) → shares db.lock with app (200) → shares app.lock with nginx (100), worker (400).
    let result = compute_indirect_impact(300, &graph, 1.0, &config);

    // Direct: 200 (app via db.lock).
    assert_eq!(result.direct_affected, 1);
    // Transitive: 200 + (100, 400 via app.lock) = 3.
    assert_eq!(result.transitive_affected, 3);
}

#[test]
fn indirect_impact_orphan_has_no_reach() {
    let graph = web_stack_graph();
    let result = compute_indirect_impact(500, &graph, 1.0, &IndirectImpactConfig::default());
    assert_eq!(result.direct_affected, 0);
    assert_eq!(result.transitive_affected, 0);
    assert!(result.adjusted_score < 0.01);
}

#[test]
fn incomplete_evidence_inflates_indirect_score() {
    let graph = web_stack_graph();
    let config = IndirectImpactConfig::default();

    let full = compute_indirect_impact(300, &graph, 1.0, &config);
    let partial = compute_indirect_impact(300, &graph, 0.2, &config);

    assert!(
        partial.adjusted_score > full.adjusted_score,
        "partial={} should exceed full={}",
        partial.adjusted_score,
        full.adjusted_score,
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 4. Continuity Delta Diagnostics
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn delta_detects_worker_joining_web_stack() {
    // Previous: web stack without worker.
    let prev = SharedResourceGraph::from_evidence(&[
        (
            100,
            vec![listener_ev(100, 80), lock_ev(100, "/run/app.lock")],
        ),
        (
            200,
            vec![listener_ev(200, 3000), lock_ev(200, "/run/app.lock")],
        ),
    ]);

    // Current: worker joins.
    let curr = SharedResourceGraph::from_evidence(&[
        (
            100,
            vec![listener_ev(100, 80), lock_ev(100, "/run/app.lock")],
        ),
        (
            200,
            vec![listener_ev(200, 3000), lock_ev(200, "/run/app.lock")],
        ),
        (400, vec![lock_ev(400, "/run/app.lock")]),
    ]);

    let delta = compute_provenance_delta(&prev, &curr);
    assert!(delta.new_pids.contains(&400));
    // nginx and app blast radius should increase (new co-holder).
    assert!(!delta.blast_radius_increased.is_empty());

    let summary = summarize_delta(&delta);
    assert!(summary.contains("new process"), "summary: {summary}");
    assert!(
        summary.contains("growing blast radius"),
        "summary: {summary}"
    );
}

#[test]
fn delta_detects_db_exiting() {
    let prev = web_stack_graph();
    // Current: db exits.
    let curr = SharedResourceGraph::from_evidence(&[
        (
            100,
            vec![listener_ev(100, 80), lock_ev(100, "/run/app.lock")],
        ),
        (
            200,
            vec![
                listener_ev(200, 3000),
                lock_ev(200, "/run/app.lock"),
                lock_ev(200, "/run/db.lock"),
            ],
        ),
        (400, vec![lock_ev(400, "/run/app.lock")]),
        (500, vec![lock_ev(500, "/tmp/orphan.lock")]),
    ]);

    let delta = compute_provenance_delta(&prev, &curr);
    assert!(delta.exited_pids.contains(&300));
    // app should have decreased blast radius (lost db co-holder).
    assert!(!delta.blast_radius_decreased.is_empty());
}

#[test]
fn pid_continuity_tracks_resource_changes() {
    let prev = SharedResourceGraph::from_evidence(&[(100, vec![lock_ev(100, "/a.lock")])]);
    let curr = SharedResourceGraph::from_evidence(&[(
        100,
        vec![lock_ev(100, "/a.lock"), lock_ev(100, "/b.lock")],
    )]);

    match pid_continuity(100, &prev, &curr) {
        PidContinuity::Continuing {
            resources_gained,
            resources_lost,
            ..
        } => {
            assert_eq!(resources_gained, 1);
            assert_eq!(resources_lost, 0);
        }
        other => panic!("expected Continuing, got {other:?}"),
    }
}

// ═══════════════════════════════════════════════════════════════════════
// 5. Composed Diagnostics: Direct + Indirect + Delta
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn full_diagnostic_pipeline_for_web_stack() {
    let graph = web_stack_graph();

    // Direct impact for all processes.
    let di_config = DirectImpactConfig::default();
    let ii_config = IndirectImpactConfig::default();

    let pids = [100, 200, 300, 400, 500];
    for &pid in &pids {
        let direct = compute_direct_impact(pid, &graph, None, &[], &di_config);
        let indirect = compute_indirect_impact(pid, &graph, 1.0, &ii_config);

        // Scores should be finite and bounded.
        assert!(
            direct.score >= 0.0 && direct.score <= 1.0,
            "PID {pid} direct"
        );
        assert!(
            indirect.adjusted_score >= 0.0 && indirect.adjusted_score <= 1.0,
            "PID {pid} indirect"
        );

        // Summary should be non-empty.
        assert!(!direct.summary.is_empty());

        // Blast radius should reference the correct PID.
        assert_eq!(direct.blast_radius.target_pid, pid);
    }
}

#[test]
fn serde_roundtrip_for_all_result_types() {
    let graph = web_stack_graph();
    let di = compute_direct_impact(200, &graph, None, &[], &DirectImpactConfig::default());
    let ii = compute_indirect_impact(200, &graph, 0.8, &IndirectImpactConfig::default());

    // Direct impact roundtrip.
    let json_di = serde_json::to_string(&di).unwrap();
    let _: pt_core::decision::DirectImpactResult = serde_json::from_str(&json_di).unwrap();

    // Indirect impact roundtrip.
    let json_ii = serde_json::to_string(&ii).unwrap();
    let _: pt_core::decision::IndirectImpactResult = serde_json::from_str(&json_ii).unwrap();
}
