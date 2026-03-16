//! End-to-end integration tests for runtime ownership provenance.
//!
//! Exercises the full pipeline: lineage_collector → normalize_lineage,
//! covering shell-owned, agent-owned, supervised, orphaned, and init-child
//! scenarios with fixture data and live PID tests.

mod support;

use pt_common::{
    normalize_lineage, AncestorEntry, LineageCollectionMethod, NormalizedLineage, OwnershipState,
    ProvenanceConfidence, RawLineageEvidence, SupervisorEvidence, SupervisorKind, TtyEvidence,
};

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

fn shell_owned_fixture() -> RawLineageEvidence {
    RawLineageEvidence {
        pid: 12345,
        ppid: 1000,
        pgid: 12345,
        sid: 1000,
        uid: 1000,
        user: Some("developer".to_string()),
        tty: Some(TtyEvidence {
            device: "/dev/pts/5".to_string(),
            has_controlling_tty: true,
            is_session_leader: false,
            is_pgid_leader: true,
        }),
        supervisor: None,
        ancestors: vec![
            AncestorEntry {
                pid: 1000,
                comm: "zsh".to_string(),
                uid: 1000,
            },
            AncestorEntry {
                pid: 999,
                comm: "tmux: server".to_string(),
                uid: 1000,
            },
            AncestorEntry {
                pid: 500,
                comm: "sshd".to_string(),
                uid: 0,
            },
            AncestorEntry {
                pid: 1,
                comm: "systemd".to_string(),
                uid: 0,
            },
        ],
        collection_method: LineageCollectionMethod::Synthetic,
        observed_at: "2026-03-16T00:00:00Z".to_string(),
    }
}

fn agent_owned_fixture() -> RawLineageEvidence {
    RawLineageEvidence {
        pid: 23456,
        ppid: 20000,
        pgid: 20000,
        sid: 15000,
        uid: 1000,
        user: Some("developer".to_string()),
        tty: Some(TtyEvidence {
            device: "/dev/pts/2".to_string(),
            has_controlling_tty: true,
            is_session_leader: false,
            is_pgid_leader: false,
        }),
        supervisor: None,
        ancestors: vec![
            AncestorEntry {
                pid: 20000,
                comm: "claude".to_string(),
                uid: 1000,
            },
            AncestorEntry {
                pid: 15000,
                comm: "bash".to_string(),
                uid: 1000,
            },
            AncestorEntry {
                pid: 14000,
                comm: "tmux: server".to_string(),
                uid: 1000,
            },
            AncestorEntry {
                pid: 1,
                comm: "systemd".to_string(),
                uid: 0,
            },
        ],
        collection_method: LineageCollectionMethod::Synthetic,
        observed_at: "2026-03-16T00:00:00Z".to_string(),
    }
}

fn systemd_service_fixture() -> RawLineageEvidence {
    RawLineageEvidence {
        pid: 34567,
        ppid: 1,
        pgid: 34567,
        sid: 34567,
        uid: 0,
        user: Some("root".to_string()),
        tty: None,
        supervisor: Some(SupervisorEvidence {
            kind: SupervisorKind::Systemd,
            unit_name: Some("nginx.service".to_string()),
            auto_restart: Some(true),
            confidence: ProvenanceConfidence::High,
        }),
        ancestors: vec![AncestorEntry {
            pid: 1,
            comm: "systemd".to_string(),
            uid: 0,
        }],
        collection_method: LineageCollectionMethod::Procfs,
        observed_at: "2026-03-16T00:00:00Z".to_string(),
    }
}

fn orphaned_fixture() -> RawLineageEvidence {
    RawLineageEvidence {
        pid: 45678,
        ppid: 1,
        pgid: 45678,
        sid: 45678,
        uid: 1000,
        user: Some("developer".to_string()),
        tty: None,
        supervisor: None,
        ancestors: vec![],
        collection_method: LineageCollectionMethod::Procfs,
        observed_at: "2026-03-16T00:00:00Z".to_string(),
    }
}

fn detached_no_tty_fixture() -> RawLineageEvidence {
    RawLineageEvidence {
        pid: 56789,
        ppid: 800,
        pgid: 56789,
        sid: 800,
        uid: 1000,
        user: Some("developer".to_string()),
        tty: None,
        supervisor: None,
        ancestors: vec![
            AncestorEntry {
                pid: 800,
                comm: "bash".to_string(),
                uid: 1000,
            },
            AncestorEntry {
                pid: 1,
                comm: "systemd".to_string(),
                uid: 0,
            },
        ],
        collection_method: LineageCollectionMethod::Procfs,
        observed_at: "2026-03-16T00:00:00Z".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Scenario: process owned by a shell (interactive user)
// ---------------------------------------------------------------------------

#[test]
fn shell_owned_process_has_tty_and_known_shell_ancestor() {
    let evidence = shell_owned_fixture();
    let result = normalize_lineage(&evidence);

    // zsh is the closest ancestor (index 0), so ShellOwned wins
    match &result.ownership {
        OwnershipState::ShellOwned {
            shell_pid,
            shell_comm,
        } => {
            assert_eq!(*shell_pid, 1000);
            assert_eq!(shell_comm, "zsh");
        }
        other => panic!("expected ShellOwned(zsh), got {other:?}"),
    }

    assert!(!result.is_orphaned);
    assert!(result.session.has_tty);
    assert_eq!(result.confidence, ProvenanceConfidence::High);
}

// ---------------------------------------------------------------------------
// Scenario: process owned by a coding agent
// ---------------------------------------------------------------------------

#[test]
fn agent_owned_process_finds_claude_ancestor() {
    let evidence = agent_owned_fixture();
    let result = normalize_lineage(&evidence);

    match &result.ownership {
        OwnershipState::AgentOwned {
            agent_pid,
            agent_comm,
        } => {
            assert_eq!(*agent_pid, 20000);
            assert_eq!(agent_comm, "claude");
        }
        other => panic!("expected AgentOwned, got {other:?}"),
    }

    assert!(!result.is_orphaned);
    assert_eq!(result.confidence, ProvenanceConfidence::High);
}

// ---------------------------------------------------------------------------
// Scenario: systemd-managed service
// ---------------------------------------------------------------------------

#[test]
fn systemd_service_is_supervised_not_orphaned() {
    let evidence = systemd_service_fixture();
    let result = normalize_lineage(&evidence);

    match &result.ownership {
        OwnershipState::Supervised { supervisor } => {
            assert_eq!(supervisor.kind, SupervisorKind::Systemd);
            assert_eq!(supervisor.unit_name.as_deref(), Some("nginx.service"));
            assert_eq!(supervisor.auto_restart, Some(true));
        }
        other => panic!("expected Supervised(systemd), got {other:?}"),
    }

    assert!(!result.is_orphaned); // has supervisor
    assert!(!result.session.has_tty); // services don't have TTYs
    assert_eq!(result.confidence, ProvenanceConfidence::High);
}

// ---------------------------------------------------------------------------
// Scenario: orphaned process (PPID=1, no supervisor, no ancestors)
// ---------------------------------------------------------------------------

#[test]
fn orphaned_process_has_degraded_confidence() {
    let evidence = orphaned_fixture();
    let result = normalize_lineage(&evidence);

    assert_eq!(result.ownership, OwnershipState::Orphaned);
    assert!(result.is_orphaned);
    assert!(!result.session.has_tty);
    // Degraded because we can't determine if this is a genuine orphan
    // or just a process we can't read ancestors for
    assert!(result.confidence > ProvenanceConfidence::High);
    assert!(!result.downgrade_reasons.is_empty());
}

// ---------------------------------------------------------------------------
// Scenario: detached process with no TTY but known parent
// ---------------------------------------------------------------------------

#[test]
fn detached_process_without_tty_still_finds_shell_ancestor() {
    let evidence = detached_no_tty_fixture();
    let result = normalize_lineage(&evidence);

    match &result.ownership {
        OwnershipState::ShellOwned {
            shell_pid,
            shell_comm,
        } => {
            assert_eq!(*shell_pid, 800);
            assert_eq!(shell_comm, "bash");
        }
        other => panic!("expected ShellOwned, got {other:?}"),
    }

    assert!(!result.is_orphaned);
    assert!(!result.session.has_tty); // detached
}

// ---------------------------------------------------------------------------
// Scenario: user boundary crossing (sudo/su)
// ---------------------------------------------------------------------------

#[test]
fn user_boundary_crossing_detected_across_ancestor_chain() {
    let mut evidence = shell_owned_fixture();
    // First ancestor (zsh) runs as a different UID
    evidence.ancestors[0].uid = 0; // root shell → user process

    let result = normalize_lineage(&evidence);
    assert!(result.crossed_user_boundary);
}

// ---------------------------------------------------------------------------
// Scenario: session leader detection
// ---------------------------------------------------------------------------

#[test]
fn session_leader_detected_from_tty_evidence() {
    let mut evidence = shell_owned_fixture();
    evidence.pid = evidence.sid; // Make PID == SID (session leader)
    if let Some(ref mut tty) = evidence.tty {
        tty.is_session_leader = true;
    }

    let result = normalize_lineage(&evidence);
    assert!(result.session.is_session_leader);
}

// ---------------------------------------------------------------------------
// Scenario: provenance node IDs are stable
// ---------------------------------------------------------------------------

#[test]
fn supervisor_and_session_node_ids_are_deterministic() {
    let evidence = systemd_service_fixture();
    let r1 = normalize_lineage(&evidence);
    let r2 = normalize_lineage(&evidence);

    assert_eq!(r1.supervisor_node_id(), r2.supervisor_node_id());
    assert_eq!(r1.session_node_id(), r2.session_node_id());

    let sup_id = r1.supervisor_node_id().expect("has supervisor");
    assert!(sup_id.0.starts_with("pn_supervisor_"));

    let sess_id = r1.session_node_id();
    assert!(sess_id.0.starts_with("pn_session_"));
}

// ---------------------------------------------------------------------------
// Scenario: JSON round-trip preserves ownership classification
// ---------------------------------------------------------------------------

#[test]
fn ownership_classification_survives_json_round_trip() {
    let fixtures = vec![
        shell_owned_fixture(),
        agent_owned_fixture(),
        systemd_service_fixture(),
        orphaned_fixture(),
        detached_no_tty_fixture(),
    ];

    for evidence in fixtures {
        let result = normalize_lineage(&evidence);
        let json = serde_json::to_string(&result).expect("serialize");
        let parsed: NormalizedLineage = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(parsed.ownership, result.ownership);
        assert_eq!(parsed.confidence, result.confidence);
        assert_eq!(parsed.is_orphaned, result.is_orphaned);
        assert_eq!(parsed.crossed_user_boundary, result.crossed_user_boundary);
        assert_eq!(parsed.session.has_tty, result.session.has_tty);
    }
}

// ---------------------------------------------------------------------------
// Scenario: live lineage collection for this process
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[test]
fn live_lineage_collection_for_test_process() {
    use pt_core::collect::collect_lineage_for_pid;

    let pid = std::process::id();
    let evidence = collect_lineage_for_pid(pid);
    let result = normalize_lineage(&evidence);

    assert_eq!(evidence.pid, pid);
    assert!(evidence.ppid > 0);
    assert!(!evidence.ancestors.is_empty());

    // We should be running under some form of ownership
    assert_ne!(result.ownership, OwnershipState::Unknown);

    // Our lineage should end at PID 1
    let last = evidence.ancestors.last().expect("has ancestors");
    assert_eq!(last.pid, 1);
}
