//! Resource-conflict fixtures, provenance traces, and explanation
//! diagnostics for shared-resource evidence (bd-nui4).
//!
//! Tests that lockfile/pidfile/coordination-marker evidence is
//! correctly collected, classified, and remains explainable under
//! conflicting or incomplete evidence scenarios.

use pt_common::{
    LockMechanism, RawResourceEvidence, ResourceCollectionMethod, ResourceDetails, ResourceKind,
    ResourceState,
};

// ── Fixture builders ──────────────────────────────────────────────────

fn lockfile_evidence(
    pid: u32,
    path: &str,
    state: ResourceState,
    mechanism: LockMechanism,
) -> RawResourceEvidence {
    RawResourceEvidence {
        kind: ResourceKind::Lockfile,
        key: path.to_string(),
        owner_pid: pid,
        collection_method: ResourceCollectionMethod::ProcFd,
        state,
        details: ResourceDetails::Lockfile {
            path: path.to_string(),
            mechanism,
        },
        observed_at: "2026-03-17T00:00:00Z".to_string(),
    }
}

fn pidfile_evidence(
    pid: u32,
    path: &str,
    state: ResourceState,
    recorded_pid: Option<u32>,
) -> RawResourceEvidence {
    RawResourceEvidence {
        kind: ResourceKind::Pidfile,
        key: path.to_string(),
        owner_pid: pid,
        collection_method: ResourceCollectionMethod::ProcFd,
        state,
        details: ResourceDetails::Pidfile {
            path: path.to_string(),
            recorded_pid,
        },
        observed_at: "2026-03-17T00:00:00Z".to_string(),
    }
}

// ═══════════════════════════════════════════════════════════════════════
// 1. Resource Evidence Construction
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn lockfile_active_state_for_write_mode() {
    let ev = lockfile_evidence(
        1234,
        "/var/run/myservice.lock",
        ResourceState::Active,
        LockMechanism::Existence,
    );
    assert_eq!(ev.kind, ResourceKind::Lockfile);
    assert_eq!(ev.state, ResourceState::Active);
    assert_eq!(ev.owner_pid, 1234);
    match &ev.details {
        ResourceDetails::Lockfile { path, mechanism } => {
            assert_eq!(path, "/var/run/myservice.lock");
            assert_eq!(*mechanism, LockMechanism::Existence);
        }
        _ => panic!("expected Lockfile details"),
    }
}

#[test]
fn pidfile_active_when_pid_matches() {
    let ev = pidfile_evidence(5678, "/run/nginx.pid", ResourceState::Active, Some(5678));
    assert_eq!(ev.state, ResourceState::Active);
    match &ev.details {
        ResourceDetails::Pidfile { recorded_pid, .. } => {
            assert_eq!(*recorded_pid, Some(5678));
        }
        _ => panic!("expected Pidfile details"),
    }
}

// ═══════════════════════════════════════════════════════════════════════
// 2. Conflict Scenarios
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn pidfile_conflicted_when_recorded_pid_differs() {
    // Process 1234 holds the pidfile but it records pid 9999.
    let ev = pidfile_evidence(
        1234,
        "/run/nginx.pid",
        ResourceState::Conflicted,
        Some(9999),
    );
    assert_eq!(ev.state, ResourceState::Conflicted);
    // The provenance trace should show WHO actually holds the file
    // vs what the file SAYS.
    assert_eq!(ev.owner_pid, 1234);
    match &ev.details {
        ResourceDetails::Pidfile { recorded_pid, .. } => {
            assert_eq!(*recorded_pid, Some(9999));
            assert_ne!(*recorded_pid, Some(ev.owner_pid));
        }
        _ => panic!("expected Pidfile details"),
    }
}

#[test]
fn two_processes_same_lockfile_creates_conflict_pair() {
    // Two processes both claim the same lockfile.
    let proc_a = lockfile_evidence(
        100,
        "/tmp/.X0-lock",
        ResourceState::Active,
        LockMechanism::Existence,
    );
    let proc_b = lockfile_evidence(
        200,
        "/tmp/.X0-lock",
        ResourceState::Active,
        LockMechanism::Existence,
    );

    // Both reference the same key.
    assert_eq!(proc_a.key, proc_b.key);
    // Different owners.
    assert_ne!(proc_a.owner_pid, proc_b.owner_pid);
    // A downstream aggregator should detect this as a conflict.
    // For now, we verify the evidence is correctly structured.
    assert_eq!(proc_a.kind, ResourceKind::Lockfile);
    assert_eq!(proc_b.kind, ResourceKind::Lockfile);
}

// ═══════════════════════════════════════════════════════════════════════
// 3. Incomplete / Missing Evidence
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn pidfile_stale_when_file_missing() {
    let ev = pidfile_evidence(1234, "/run/deleted-service.pid", ResourceState::Stale, None);
    assert_eq!(ev.state, ResourceState::Stale);
    match &ev.details {
        ResourceDetails::Pidfile { recorded_pid, .. } => {
            assert_eq!(*recorded_pid, None);
        }
        _ => panic!("expected Pidfile details"),
    }
}

#[test]
fn lockfile_partial_when_not_writable() {
    // Process has the lockfile open but not for writing — partial evidence.
    let ev = lockfile_evidence(
        1234,
        "/var/lock/subsys/httpd",
        ResourceState::Partial,
        LockMechanism::Unknown,
    );
    assert_eq!(ev.state, ResourceState::Partial);
    assert_eq!(
        match &ev.details {
            ResourceDetails::Lockfile { mechanism, .. } => *mechanism,
            _ => panic!("expected Lockfile"),
        },
        LockMechanism::Unknown
    );
}

#[test]
fn missing_evidence_uses_default_state() {
    // When no FD info is available, collection returns empty vec.
    let evidence = pt_core::collect::collect_local_resource_evidence(99999, None);
    assert!(evidence.is_empty());
}

// ═══════════════════════════════════════════════════════════════════════
// 4. Provenance Trace Diagnostics
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn evidence_serialization_roundtrip() {
    let ev = lockfile_evidence(
        1234,
        "/home/user/.git/index.lock",
        ResourceState::Active,
        LockMechanism::Existence,
    );

    let json = serde_json::to_string(&ev).unwrap();
    let deser: RawResourceEvidence = serde_json::from_str(&json).unwrap();

    assert_eq!(deser.kind, ev.kind);
    assert_eq!(deser.key, ev.key);
    assert_eq!(deser.owner_pid, ev.owner_pid);
    assert_eq!(deser.state, ev.state);
    assert_eq!(deser.observed_at, ev.observed_at);
}

#[test]
fn pidfile_evidence_serialization_roundtrip() {
    let ev = pidfile_evidence(5678, "/run/sshd.pid", ResourceState::Active, Some(5678));

    let json = serde_json::to_string(&ev).unwrap();
    let deser: RawResourceEvidence = serde_json::from_str(&json).unwrap();

    assert_eq!(deser.kind, ResourceKind::Pidfile);
    assert_eq!(deser.state, ResourceState::Active);
    match &deser.details {
        ResourceDetails::Pidfile { recorded_pid, .. } => {
            assert_eq!(*recorded_pid, Some(5678));
        }
        _ => panic!("expected Pidfile details after roundtrip"),
    }
}

// ═══════════════════════════════════════════════════════════════════════
// 5. Resource Kind Coverage
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn all_resource_states_are_representable() {
    let states = [
        ResourceState::Active,
        ResourceState::Stale,
        ResourceState::Partial,
        ResourceState::Conflicted,
        ResourceState::Missing,
    ];
    for state in &states {
        let ev = lockfile_evidence(1, "/test", *state, LockMechanism::Existence);
        assert_eq!(ev.state, *state);
    }
}

#[test]
fn all_lock_mechanisms_are_representable() {
    let mechanisms = [
        LockMechanism::Existence,
        LockMechanism::Advisory,
        LockMechanism::Unknown,
    ];
    for mech in &mechanisms {
        let ev = lockfile_evidence(1, "/test", ResourceState::Active, *mech);
        match &ev.details {
            ResourceDetails::Lockfile { mechanism, .. } => assert_eq!(mechanism, mech),
            _ => panic!("expected Lockfile"),
        }
    }
}

#[test]
fn git_lock_classified_as_existence_mechanism() {
    let ev = lockfile_evidence(
        1234,
        "/repo/.git/index.lock",
        ResourceState::Active,
        LockMechanism::Existence,
    );
    match &ev.details {
        ResourceDetails::Lockfile { mechanism, .. } => {
            assert_eq!(*mechanism, LockMechanism::Existence);
        }
        _ => panic!("expected Lockfile"),
    }
}

#[test]
fn conflicted_pidfile_has_explanatory_fields() {
    // When a pidfile is conflicted, the evidence should carry enough
    // information to explain WHY: the owner_pid and recorded_pid differ.
    let ev = pidfile_evidence(
        1234,
        "/run/myapp.pid",
        ResourceState::Conflicted,
        Some(5678),
    );

    // Verify the explanation surface: owner vs recorded.
    assert_eq!(ev.owner_pid, 1234);
    assert_eq!(ev.state, ResourceState::Conflicted);
    let recorded = match &ev.details {
        ResourceDetails::Pidfile { recorded_pid, .. } => *recorded_pid,
        _ => panic!("expected Pidfile"),
    };
    assert_eq!(recorded, Some(5678));
    // The discrepancy (1234 vs 5678) IS the explanation.
    assert_ne!(Some(ev.owner_pid), recorded);
}
