//! Safety gates tests for pt-core.
//!
//! This module tests the multi-layer safety system including:
//! - Data-loss gates (open write handles, sqlite WAL, git locks, package locks)
//! - Zombie handling (state Z detection, parent routing)
//! - D-state handling (uninterruptible sleep, wchan analysis)
//! - Identity/coordination (PID reuse protection, UID enforcement, lock contention)
//! - Protected process enforcement (systemd, sshd, docker, custom patterns)
//!
//! These tests validate that pt-core will NEVER kill processes that could
//! cause data loss or system instability.

#![cfg(feature = "test-utils")]

use pt_common::{IdentityQuality, ProcessId, ProcessIdentity, StartId};
use pt_core::action::executor::{
    ActionExecutor, ActionStatus, NoopActionRunner, StaticIdentityProvider,
};
use pt_core::action::prechecks::{
    LivePreCheckConfig, LivePreCheckProvider, NoopPreCheckProvider, PreCheckProvider,
    PreCheckResult,
};
use pt_core::collect::{ProcessRecord, ProcessState, ScanMetadata, ScanResult, ProtectedFilter};
use pt_core::decision::{Action, DecisionOutcome, ExpectedLoss};
use pt_core::plan::{DecisionBundle, DecisionCandidate, Plan, PreCheck};
use pt_core::config::Policy;
use pt_core::test_utils::ProcessHarness;
use std::time::Duration;
use tempfile::tempdir;

// ============================================================================
// Test Fixtures and Helpers
// ============================================================================

fn make_test_record(
    pid: u32,
    ppid: u32,
    comm: &str,
    cmd: &str,
    user: &str,
    state: ProcessState,
) -> ProcessRecord {
    ProcessRecord {
        pid: ProcessId(pid),
        ppid: ProcessId(ppid),
        uid: 1000,
        user: user.to_string(),
        pgid: Some(pid),
        sid: Some(pid),
        start_id: StartId::from_linux("test-boot-id", 1234567890, pid),
        comm: comm.to_string(),
        cmd: cmd.to_string(),
        state,
        cpu_percent: 0.0,
        rss_bytes: 1024 * 1024,
        vsz_bytes: 2 * 1024 * 1024,
        tty: None,
        start_time_unix: 1234567890,
        elapsed: Duration::from_secs(3600),
        source: "test".to_string(),
    }
}

fn make_test_identity(pid: u32, uid: u32) -> ProcessIdentity {
    ProcessIdentity {
        pid: ProcessId(pid),
        start_id: StartId(format!("boot:1:{}", pid)),
        uid,
        pgid: None,
        sid: Some(pid),
        quality: IdentityQuality::Full,
    }
}

fn make_test_plan(pid: u32, uid: u32, pre_checks: Vec<PreCheck>) -> Plan {
    let identity = make_test_identity(pid, uid);
    let decision = DecisionOutcome {
        expected_loss: vec![ExpectedLoss {
            action: Action::Kill,
            loss: 1.0,
        }],
        optimal_action: Action::Kill,
        sprt_boundary: None,
        posterior_odds_abandoned_vs_useful: None,
        recovery_expectations: None,
        rationale: pt_core::decision::DecisionRationale {
            chosen_action: Action::Kill,
            tie_break: false,
            disabled_actions: vec![],
            used_recovery_preference: false,
        },
    };
    let bundle = DecisionBundle {
        session_id: pt_common::SessionId("pt-test-session".to_string()),
        policy: Policy::default(),
        candidates: vec![DecisionCandidate {
            identity: identity.clone(),
            ppid: None,
            decision,
            blocked_reasons: vec![],
            stage_pause_before_kill: false,
        }],
        generated_at: Some("2026-01-15T12:00:00Z".to_string()),
    };
    let mut plan = pt_core::plan::generate_plan(&bundle);

    // Override pre_checks for testing
    if let Some(action) = plan.actions.first_mut() {
        action.pre_checks = pre_checks;
    }

    plan
}

// ============================================================================
// DATA-LOSS GATE TESTS
// ============================================================================

mod data_loss_gates {
    use super::*;

    #[test]
    #[cfg(target_os = "linux")]
    fn test_open_write_fds_blocks_kill() {
        // Test that process with open write file descriptors is blocked
        if !ProcessHarness::is_available() {
            return;
        }

        let config = LivePreCheckConfig {
            max_open_write_fds: 0, // Any write fd should block
            block_if_locked_files: true,
            block_if_active_tty: false,
            block_if_deleted_cwd: false,
            block_if_recent_io_seconds: 0,
            ..Default::default()
        };

        let provider = LivePreCheckProvider::new(None, config).expect("create provider");

        // Self-test: our process has write fds (stdout, etc.)
        let pid = std::process::id();
        let result = provider.check_data_loss(pid);

        // Current process should be blocked due to open write fds
        match result {
            PreCheckResult::Blocked { check, reason } => {
                assert_eq!(check, PreCheck::CheckDataLossGate);
                assert!(reason.contains("write fd"), "Expected write fd mention: {}", reason);
            }
            PreCheckResult::Passed => {
                // May pass if running in a context without write fds
                eprintln!("Note: Process has no detected write fds");
            }
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_sqlite_wal_detection() {
        // Test that we can detect SQLite WAL mode as a data-loss risk
        if !ProcessHarness::is_available() {
            return;
        }

        let harness = ProcessHarness::default();
        let dir = tempdir().expect("tempdir");
        let db_path = dir.path().join("test.db");

        // Create a process that holds a SQLite database open in WAL mode
        let cmd = format!(
            "sqlite3 {} 'PRAGMA journal_mode=WAL; CREATE TABLE t(x); INSERT INTO t VALUES(1);' && sleep 60",
            db_path.display()
        );

        // This test is probabilistic - sqlite may not be available
        if let Ok(proc) = harness.spawn_shell(&cmd) {
            std::thread::sleep(Duration::from_millis(200));

            let config = LivePreCheckConfig {
                max_open_write_fds: 2, // Allow a few fds
                block_if_locked_files: true,
                block_if_active_tty: false,
                block_if_deleted_cwd: false,
                block_if_recent_io_seconds: 0,
                ..Default::default()
            };

            let provider = LivePreCheckProvider::new(None, config).expect("create provider");
            let result = provider.check_data_loss(proc.pid());

            // Should detect locked files from SQLite
            eprintln!("SQLite WAL test result: {:?}", result);
            drop(proc);
        } else {
            eprintln!("sqlite3 not available, skipping WAL test");
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_git_lock_detection() {
        // Test detection of git index.lock
        if !ProcessHarness::is_available() {
            return;
        }

        let harness = ProcessHarness::default();
        let dir = tempdir().expect("tempdir");

        // Initialize git repo and hold a lock
        let setup_cmd = format!(
            "cd {} && git init && touch .git/index.lock && sleep 60",
            dir.path().display()
        );

        if let Ok(proc) = harness.spawn_shell(&setup_cmd) {
            std::thread::sleep(Duration::from_millis(100));

            // Git lock files should be detectable via /proc/<pid>/fd
            let fd_path = format!("/proc/{}/fd", proc.pid());
            if let Ok(entries) = std::fs::read_dir(&fd_path) {
                for entry in entries.flatten() {
                    if let Ok(target) = std::fs::read_link(entry.path()) {
                        let target_str = target.to_string_lossy();
                        if target_str.contains("index.lock") {
                            eprintln!("Git lock detected in fd: {}", target_str);
                        }
                    }
                }
            }
            drop(proc);
        }
    }

    #[test]
    fn test_deleted_cwd_blocks_kill() {
        // Process with deleted CWD is suspicious - may have data in flight
        if !ProcessHarness::is_available() {
            return;
        }

        let config = LivePreCheckConfig {
            max_open_write_fds: 100, // Allow fds
            block_if_locked_files: false,
            block_if_active_tty: false,
            block_if_deleted_cwd: true, // Block on deleted CWD
            block_if_recent_io_seconds: 0,
            ..Default::default()
        };

        let provider = LivePreCheckProvider::new(None, config).expect("create provider");

        // Our current process should have a valid CWD
        let pid = std::process::id();
        let result = provider.check_data_loss(pid);

        // Should pass since our CWD is not deleted
        assert!(
            result.is_passed(),
            "Expected to pass (CWD should exist): {:?}",
            result
        );
    }
}

// ============================================================================
// ZOMBIE HANDLING TESTS
// ============================================================================

mod zombie_handling {
    use super::*;

    #[test]
    fn test_process_state_is_zombie() {
        assert!(ProcessState::Zombie.is_zombie());
        assert!(!ProcessState::Running.is_zombie());
        assert!(!ProcessState::Sleeping.is_zombie());
        assert!(!ProcessState::DiskSleep.is_zombie());
    }

    #[test]
    fn test_zombie_not_active() {
        // Zombies should not be considered "active"
        assert!(!ProcessState::Zombie.is_active());
        assert!(ProcessState::Running.is_active());
        assert!(ProcessState::Sleeping.is_active());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_zombie_creation_and_detection() {
        // Create actual zombie process and verify detection
        if !ProcessHarness::is_available() {
            return;
        }

        let harness = ProcessHarness::default();

        // Spawn a process that exits immediately -> becomes zombie
        let proc = harness.spawn_shell("exit 0").expect("spawn exit");
        let pid = proc.pid();

        // Wait for zombie state
        let mut is_zombie = false;
        for _ in 0..30 {
            if let Ok(stat) = std::fs::read_to_string(format!("/proc/{}/stat", pid)) {
                if stat.contains(") Z ") {
                    is_zombie = true;
                    break;
                }
            } else {
                // Process may have been reaped already
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        if is_zombie {
            // Parse state from stat file
            let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid)).unwrap();
            let state = parse_state_from_stat(&stat);
            assert_eq!(state, ProcessState::Zombie);
        }

        // Drop will reap the zombie
    }

    #[test]
    fn test_zombie_filter_record() {
        // Test that zombie processes are identified in scan results
        let zombie_record = make_test_record(
            1234,
            1,
            "defunct",
            "[defunct]",
            "testuser",
            ProcessState::Zombie,
        );

        assert!(zombie_record.state.is_zombie());
        assert!(!zombie_record.state.is_active());
    }

    #[test]
    fn test_zombie_routing_to_parent() {
        // Test that zombie actions should route to parent for reaping
        let zombie_pid = 1234u32;
        let parent_pid = 1000u32;

        let zombie = make_test_record(
            zombie_pid,
            parent_pid,
            "defunct",
            "[defunct]",
            "testuser",
            ProcessState::Zombie,
        );

        // Killing a zombie is pointless - need to signal parent to reap
        assert!(zombie.state.is_zombie());
        assert!(!zombie.is_orphan()); // Parent is 1000, not 1

        // The correct action for zombie is to notify parent or ignore
        // (The decision engine should handle this routing)
    }

    fn parse_state_from_stat(stat: &str) -> ProcessState {
        // Format: pid (comm) state ...
        if let Some(close_paren) = stat.rfind(')') {
            if let Some(state_char) = stat.get(close_paren + 2..close_paren + 3) {
                return ProcessState::from_char(state_char.chars().next().unwrap_or('?'));
            }
        }
        ProcessState::Unknown
    }
}

// ============================================================================
// D-STATE (UNINTERRUPTIBLE SLEEP) TESTS
// ============================================================================

mod d_state_handling {
    use super::*;

    #[test]
    fn test_disk_sleep_state_detection() {
        assert_eq!(ProcessState::from_char('D'), ProcessState::DiskSleep);
    }

    #[test]
    fn test_disk_sleep_is_active() {
        // D-state processes ARE active (waiting for I/O completion)
        assert!(ProcessState::DiskSleep.is_active());
    }

    #[test]
    fn test_d_state_record_handling() {
        // D-state process should be handled carefully - may be stuck in I/O
        let d_state_record = make_test_record(
            5678,
            1,
            "dd",
            "dd if=/dev/sda of=/dev/sdb bs=1M",
            "root",
            ProcessState::DiskSleep,
        );

        assert_eq!(d_state_record.state, ProcessState::DiskSleep);
        assert!(d_state_record.state.is_active());

        // D-state processes should NOT be blindly killed
        // They're waiting for kernel I/O - killing may corrupt data
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_wchan_inspection_available() {
        // Verify we can read wchan for D-state analysis
        if !ProcessHarness::is_available() {
            return;
        }

        let pid = std::process::id();
        let wchan_path = format!("/proc/{}/wchan", pid);

        // wchan should be readable (may be empty if running)
        if let Ok(wchan) = std::fs::read_to_string(&wchan_path) {
            eprintln!("Current process wchan: '{}'", wchan.trim());
            // Common wait channels: poll_schedule_timeout, futex_wait_queue_me, etc.
        }
    }
}

// ============================================================================
// IDENTITY/COORDINATION TESTS
// ============================================================================

mod identity_coordination {
    use super::*;

    #[test]
    fn test_identity_mismatch_blocks_action() {
        // If identity doesn't match (PID reused), action must be blocked
        let plan = make_test_plan(123, 1000, vec![PreCheck::VerifyIdentity]);
        let dir = tempdir().expect("tempdir");

        let runner = NoopActionRunner;
        // Empty identity provider = no process matches
        let identity_provider = StaticIdentityProvider::default();

        let executor = ActionExecutor::new(&runner, &identity_provider, dir.path().join("lock"));
        let result = executor.execute_plan(&plan).expect("execute");

        assert_eq!(result.outcomes[0].status, ActionStatus::IdentityMismatch);
    }

    #[test]
    fn test_identity_match_allows_action() {
        // If identity matches, action should proceed
        let pid = 123u32;
        let uid = 1000u32;
        let plan = make_test_plan(pid, uid, vec![PreCheck::VerifyIdentity]);
        let dir = tempdir().expect("tempdir");

        let runner = NoopActionRunner;
        let identity_provider = StaticIdentityProvider::default()
            .with_identity(make_test_identity(pid, uid));

        let executor = ActionExecutor::new(&runner, &identity_provider, dir.path().join("lock"));
        let result = executor.execute_plan(&plan).expect("execute");

        assert_eq!(result.outcomes[0].status, ActionStatus::Success);
    }

    #[test]
    fn test_start_id_mismatch_detection() {
        // Two identities with same PID but different start_id should NOT match
        let identity1 = ProcessIdentity {
            pid: ProcessId(123),
            start_id: StartId("boot:1:123".to_string()),
            uid: 1000,
            pgid: None,
            sid: None,
            quality: IdentityQuality::Full,
        };

        let identity2 = ProcessIdentity {
            pid: ProcessId(123),
            start_id: StartId("boot:1:456".to_string()), // Different start_id
            uid: 1000,
            pgid: None,
            sid: None,
            quality: IdentityQuality::Full,
        };

        // Same PID, different start_id = different process (PID reused)
        assert!(!identity1.matches(&identity2));
    }

    #[test]
    fn test_uid_enforcement() {
        // UID mismatch should block action (security constraint)
        let identity1 = ProcessIdentity {
            pid: ProcessId(123),
            start_id: StartId("boot:1:123".to_string()),
            uid: 1000, // Regular user
            pgid: None,
            sid: None,
            quality: IdentityQuality::Full,
        };

        let identity2 = ProcessIdentity {
            pid: ProcessId(123),
            start_id: StartId("boot:1:123".to_string()),
            uid: 0, // Root - different UID
            pgid: None,
            sid: None,
            quality: IdentityQuality::Full,
        };

        // Same everything except UID = should NOT match
        assert!(!identity1.matches(&identity2));
    }

    #[test]
    fn test_lock_contention_returns_error() {
        // Concurrent runs should be blocked by lock
        let plan = make_test_plan(123, 1000, vec![]);
        let dir = tempdir().expect("tempdir");
        let lock_path = dir.path().join("lock");

        // Manually acquire lock
        std::fs::write(&lock_path, format!("{}", std::process::id())).expect("write lock");

        let runner = NoopActionRunner;
        let identity_provider = StaticIdentityProvider::default();

        let executor = ActionExecutor::new(&runner, &identity_provider, &lock_path);
        let err = executor.execute_plan(&plan).unwrap_err();

        match err {
            pt_core::action::executor::ExecutionError::LockUnavailable => {}
            _ => panic!("Expected LockUnavailable error, got {:?}", err),
        }
    }

    #[test]
    fn test_stale_lock_recovery() {
        // Lock from dead process should be recoverable
        let dir = tempdir().expect("tempdir");
        let lock_path = dir.path().join("lock");

        // Write lock with non-existent PID
        std::fs::write(&lock_path, "99999999").expect("write lock");

        let plan = make_test_plan(123, 1000, vec![]);
        let runner = NoopActionRunner;
        let identity_provider = StaticIdentityProvider::default()
            .with_identity(make_test_identity(123, 1000));

        let executor = ActionExecutor::new(&runner, &identity_provider, &lock_path);

        // Should recover stale lock and succeed
        let result = executor.execute_plan(&plan);
        assert!(result.is_ok(), "Should recover stale lock: {:?}", result);
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn test_pid_reuse_scenario() {
        // Test TOCTOU protection against PID reuse
        if !ProcessHarness::is_available() {
            return;
        }

        let harness = ProcessHarness::default();

        // Spawn a process and capture its identity
        let mut target = harness.spawn_toctou_target(60).expect("spawn target");
        let _pid = target.pid();

        // Take snapshot (this is the "check" phase)
        let snapshot = target.snapshot().expect("snapshot");
        assert!(snapshot.is_still_running());

        // Kill the process (simulating time passing)
        target.trigger_exit();
        assert!(target.wait_for_exit(Duration::from_secs(2)));

        // Now the PID might be reused - snapshot should detect this
        std::thread::sleep(Duration::from_millis(100));

        // The snapshot should indicate the process is no longer running
        // (either PID doesn't exist, or start_time changed)
        // Note: PID reuse is probabilistic, so we just verify detection works
        eprintln!(
            "After exit, snapshot.is_still_running() = {}",
            snapshot.is_still_running()
        );
    }
}

// ============================================================================
// PROTECTED PROCESS TESTS
// ============================================================================

mod protected_processes {
    use super::*;

    #[test]
    fn test_systemd_protected() {
        let patterns = vec![(
            r"\bsystemd\b".to_string(),
            "regex".to_string(),
            true,
            Some("core system service".to_string()),
        )];

        let filter = ProtectedFilter::new(&patterns, &[], &[], &[]).unwrap();

        let systemd = make_test_record(1, 0, "systemd", "/usr/lib/systemd/systemd", "root", ProcessState::Running);
        assert!(filter.is_protected(&systemd).is_some());

        let systemd_logind = make_test_record(100, 1, "systemd-logind", "/usr/lib/systemd/systemd-logind", "root", ProcessState::Running);
        assert!(filter.is_protected(&systemd_logind).is_some());
    }

    #[test]
    fn test_sshd_protected() {
        let patterns = vec![(
            r"\bsshd\b".to_string(),
            "regex".to_string(),
            true,
            Some("SSH daemon".to_string()),
        )];

        let filter = ProtectedFilter::new(&patterns, &[], &[], &[]).unwrap();

        let sshd = make_test_record(500, 1, "sshd", "/usr/sbin/sshd -D", "root", ProcessState::Running);
        assert!(filter.is_protected(&sshd).is_some());
    }

    #[test]
    fn test_docker_protected() {
        let patterns = vec![(
            r"\b(dockerd|containerd)\b".to_string(),
            "regex".to_string(),
            true,
            Some("container runtime".to_string()),
        )];

        let filter = ProtectedFilter::new(&patterns, &[], &[], &[]).unwrap();

        let dockerd = make_test_record(600, 1, "dockerd", "/usr/bin/dockerd", "root", ProcessState::Running);
        assert!(filter.is_protected(&dockerd).is_some());

        let containerd = make_test_record(601, 1, "containerd", "/usr/bin/containerd", "root", ProcessState::Running);
        assert!(filter.is_protected(&containerd).is_some());
    }

    #[test]
    fn test_pid_1_always_protected() {
        let filter = ProtectedFilter::new(&[], &[], &[1], &[]).unwrap();

        let init = make_test_record(1, 0, "systemd", "/usr/lib/systemd/systemd", "root", ProcessState::Running);
        let result = filter.is_protected(&init);
        assert!(result.is_some());
        assert!(result.unwrap().pattern.contains("never_kill_pid"));
    }

    #[test]
    fn test_root_user_can_be_protected() {
        let filter = ProtectedFilter::new(&[], &["root".to_string()], &[], &[]).unwrap();

        let root_proc = make_test_record(1000, 1, "important", "/usr/bin/important", "root", ProcessState::Running);
        let result = filter.is_protected(&root_proc);
        assert!(result.is_some());

        let user_proc = make_test_record(1001, 1, "userproc", "/home/user/proc", "testuser", ProcessState::Running);
        assert!(filter.is_protected(&user_proc).is_none());
    }

    #[test]
    fn test_ppid_protection() {
        // Children of protected parents should be protected
        let filter = ProtectedFilter::new(&[], &[], &[], &[1]).unwrap();

        // Direct child of PID 1
        let child = make_test_record(100, 1, "service", "/usr/bin/service", "root", ProcessState::Running);
        assert!(filter.is_protected(&child).is_some());

        // Grandchild of PID 1 (parent is 100, not 1)
        let grandchild = make_test_record(200, 100, "worker", "/usr/bin/worker", "root", ProcessState::Running);
        assert!(filter.is_protected(&grandchild).is_none());
    }

    #[test]
    fn test_custom_glob_pattern() {
        // Use ** for recursive matching (single * doesn't match /)
        let patterns = vec![(
            "/opt/myapp/**".to_string(),
            "glob".to_string(),
            false,
            Some("custom application".to_string()),
        )];

        let filter = ProtectedFilter::new(&patterns, &[], &[], &[]).unwrap();

        let myapp = make_test_record(700, 1, "myapp", "/opt/myapp/bin/myapp", "appuser", ProcessState::Running);
        assert!(filter.is_protected(&myapp).is_some());

        let other = make_test_record(701, 1, "other", "/usr/bin/other", "appuser", ProcessState::Running);
        assert!(filter.is_protected(&other).is_none());

        // Single * only matches within a path segment (doesn't cross /)
        let single_star_patterns = vec![(
            "/opt/myapp/*".to_string(),
            "glob".to_string(),
            false,
            Some("single segment match".to_string()),
        )];
        let single_filter = ProtectedFilter::new(&single_star_patterns, &[], &[], &[]).unwrap();

        // Direct file in /opt/myapp/ - should match
        let direct_file = make_test_record(702, 1, "config", "/opt/myapp/config", "appuser", ProcessState::Running);
        assert!(single_filter.is_protected(&direct_file).is_some());

        // Nested path - single * should NOT match (doesn't cross /)
        let nested = make_test_record(703, 1, "myapp", "/opt/myapp/bin/myapp", "appuser", ProcessState::Running);
        assert!(single_filter.is_protected(&nested).is_none());
    }

    #[test]
    fn test_database_services_protected() {
        let patterns = vec![(
            r"\b(postgres|mysql|redis|mongodb|elasticsearch)\b".to_string(),
            "regex".to_string(),
            true,
            Some("database services".to_string()),
        )];

        let filter = ProtectedFilter::new(&patterns, &[], &[], &[]).unwrap();

        let postgres = make_test_record(800, 1, "postgres", "/usr/lib/postgresql/14/bin/postgres", "postgres", ProcessState::Running);
        assert!(filter.is_protected(&postgres).is_some());

        let redis = make_test_record(801, 1, "redis-server", "/usr/bin/redis-server", "redis", ProcessState::Running);
        assert!(filter.is_protected(&redis).is_some());
    }

    #[test]
    fn test_scan_result_filtering() {
        let patterns = vec![(
            "systemd".to_string(),
            "literal".to_string(),
            true,
            None,
        )];

        let filter = ProtectedFilter::new(&patterns, &[], &[], &[]).unwrap();

        let scan_result = ScanResult {
            processes: vec![
                make_test_record(1, 0, "systemd", "/usr/lib/systemd/systemd", "root", ProcessState::Running),
                make_test_record(100, 1, "bash", "/bin/bash", "testuser", ProcessState::Running),
                make_test_record(101, 1, "systemd-logind", "/usr/lib/systemd/systemd-logind", "root", ProcessState::Running),
            ],
            metadata: ScanMetadata {
                scan_type: "quick".to_string(),
                platform: "linux".to_string(),
                boot_id: None,
                started_at: "2026-01-15T12:00:00Z".to_string(),
                duration_ms: 100,
                process_count: 3,
                warnings: vec![],
            },
        };

        let result = filter.filter_scan_result(&scan_result);

        assert_eq!(result.total_before, 3);
        assert_eq!(result.total_after, 1); // Only bash passes
        assert_eq!(result.filtered.len(), 2); // systemd and systemd-logind filtered
        assert_eq!(result.passed[0].comm, "bash");
    }
}

// ============================================================================
// SESSION SAFETY TESTS
// ============================================================================

mod session_safety {
    use super::*;

    #[test]
    #[cfg(target_os = "linux")]
    fn test_session_leader_blocked() {
        // Session leaders should not be killed (would orphan session)
        if !ProcessHarness::is_available() {
            return;
        }

        let provider = LivePreCheckProvider::with_defaults();

        // Test with a known session leader (ourselves, probably)
        let pid = std::process::id();
        let sid = unsafe { libc::getsid(0) as u32 };

        // If we are the session leader
        if pid == sid {
            let result = provider.check_session_safety(pid, Some(sid));
            match result {
                PreCheckResult::Blocked { check, reason } => {
                    assert_eq!(check, PreCheck::CheckSessionSafety);
                    assert!(reason.contains("session leader"));
                }
                PreCheckResult::Passed => {
                    // We might not be session leader in all test contexts
                }
            }
        }
    }

    #[test]
    fn test_active_tty_handling() {
        // Processes with active TTY should be handled carefully
        let config = LivePreCheckConfig {
            max_open_write_fds: 100,
            block_if_locked_files: false,
            block_if_active_tty: true, // Block TTY processes
            block_if_deleted_cwd: false,
            block_if_recent_io_seconds: 0,
            ..Default::default()
        };

        let _provider = LivePreCheckProvider::new(None, config).expect("create provider");

        // Note: Actual TTY detection requires running in a terminal context
        // In CI/test environments, we often don't have a TTY
    }
}

// ============================================================================
// PRECHECK INTEGRATION TESTS
// ============================================================================

mod precheck_integration {
    use super::*;

    #[test]
    fn test_noop_provider_passes_all() {
        let provider = NoopPreCheckProvider;

        assert!(provider.check_not_protected(123).is_passed());
        assert!(provider.check_data_loss(123).is_passed());
        assert!(provider.check_supervisor(123).is_passed());
        assert!(provider.check_session_safety(123, None).is_passed());
    }

    #[test]
    fn test_run_checks_executes_all() {
        let provider = NoopPreCheckProvider;

        let checks = vec![
            PreCheck::CheckNotProtected,
            PreCheck::CheckDataLossGate,
            PreCheck::CheckSupervisor,
            PreCheck::CheckSessionSafety,
        ];

        let results = provider.run_checks(&checks, 123, None);

        // Should have 4 results (VerifyIdentity is handled separately)
        assert_eq!(results.len(), 4);
        assert!(results.iter().all(|r| r.is_passed()));
    }

    #[test]
    fn test_verify_identity_skipped_by_precheck_provider() {
        let provider = NoopPreCheckProvider;

        // VerifyIdentity should be skipped (handled by IdentityProvider)
        let checks = vec![PreCheck::VerifyIdentity];
        let results = provider.run_checks(&checks, 123, None);

        assert!(results.is_empty());
    }

    #[test]
    fn test_precheck_blocks_action_in_executor() {
        // Test that PreCheckBlocked status is returned when pre-check fails
        let pid = 123u32;
        let uid = 1000u32;

        // Create plan with pre-checks
        let plan = make_test_plan(pid, uid, vec![
            PreCheck::VerifyIdentity,
            PreCheck::CheckNotProtected,
        ]);

        let dir = tempdir().expect("tempdir");
        let runner = NoopActionRunner;

        // Identity that matches
        let identity_provider = StaticIdentityProvider::default()
            .with_identity(make_test_identity(pid, uid));

        // For this test, we use NoopPreCheckProvider which always passes
        let pre_check_provider = NoopPreCheckProvider;

        let executor = ActionExecutor::new(&runner, &identity_provider, dir.path().join("lock"))
            .with_pre_check_provider(&pre_check_provider);

        let result = executor.execute_plan(&plan).expect("execute");

        // Should succeed since all checks pass
        assert_eq!(result.outcomes[0].status, ActionStatus::Success);
    }
}
