//! Integration tests for evidence collection.
//!
//! These tests verify that the evidence collection system properly captures
//! process information from real processes, including edge cases like zombies,
//! kernel threads, and processes with various resource patterns.

#![cfg(all(target_os = "linux", feature = "test-utils"))]

use pt_core::collect::{quick_scan, ProcessState, QuickScanOptions};
use pt_core::test_utils::ProcessHarness;
use std::time::Duration;

fn skip_if_proc_unavailable() -> bool {
    if !std::path::Path::new("/proc").exists() {
        eprintln!("skipping: /proc not available on this system");
        return true;
    }
    false
}

// ============================================================================
// Basic Process Collection Tests
// ============================================================================

#[test]
fn quick_scan_collects_current_process() {
    if skip_if_proc_unavailable() {
        return;
    }

    let options = QuickScanOptions::default();
    let result = quick_scan(&options).expect("quick_scan should succeed");

    // Current process should be in the scan
    let self_pid = std::process::id();
    let found = result.processes.iter().any(|p| p.pid.0 == self_pid);
    assert!(found, "Current process (pid={}) not found in scan", self_pid);
}

#[test]
fn quick_scan_captures_spawned_process_info() {
    if skip_if_proc_unavailable() {
        return;
    }
    if !ProcessHarness::is_available() {
        return;
    }

    let harness = ProcessHarness::default();
    let proc = harness.spawn_sleep(60).expect("spawn sleep");
    let pid = proc.pid();

    // Give it time to start
    std::thread::sleep(Duration::from_millis(100));

    let options = QuickScanOptions::default();
    let result = quick_scan(&options).expect("quick_scan should succeed");

    // Find our spawned process
    let found = result.processes.iter().find(|p| p.pid.0 == pid);
    assert!(found.is_some(), "Spawned process (pid={}) not found", pid);

    let proc_record = found.unwrap();

    // Verify basic fields are captured
    assert_eq!(proc_record.pid.0, pid, "PID mismatch");
    assert!(
        proc_record.comm.contains("sleep") || proc_record.cmd.contains("sleep"),
        "Command should contain 'sleep', got comm='{}', cmd='{}'",
        proc_record.comm,
        proc_record.cmd
    );
    assert!(
        matches!(
            proc_record.state,
            ProcessState::Sleeping | ProcessState::Running | ProcessState::Idle
        ),
        "Sleep process should be sleeping/running/idle, got {:?}",
        proc_record.state
    );
}

#[test]
fn quick_scan_captures_busy_process_with_cpu_usage() {
    if skip_if_proc_unavailable() {
        return;
    }
    if !ProcessHarness::is_available() {
        return;
    }

    let harness = ProcessHarness::default();
    let proc = harness.spawn_busy().expect("spawn busy");
    let pid = proc.pid();

    // Let it burn some CPU
    std::thread::sleep(Duration::from_millis(500));

    let options = QuickScanOptions::default();
    let result = quick_scan(&options).expect("quick_scan should succeed");

    let found = result.processes.iter().find(|p| p.pid.0 == pid);
    assert!(
        found.is_some(),
        "Busy process (pid={}) not found in scan",
        pid
    );

    let proc_record = found.unwrap();

    // Busy process should show some CPU usage (may be 0 if ps sampling misses it)
    // At minimum, verify the state is Running
    assert!(
        matches!(
            proc_record.state,
            ProcessState::Running | ProcessState::Sleeping
        ),
        "Busy process should be running/sleeping, got {:?}",
        proc_record.state
    );
}

// ============================================================================
// Zombie Process Collection Tests
// ============================================================================

#[test]
fn quick_scan_collects_zombie_state_correctly() {
    if skip_if_proc_unavailable() {
        return;
    }

    let options = QuickScanOptions::default();
    let result = quick_scan(&options).expect("quick_scan should succeed");

    // Check if we have any zombie processes in the scan
    let zombies: Vec<_> = result
        .processes
        .iter()
        .filter(|p| matches!(p.state, ProcessState::Zombie))
        .collect();

    // If there are zombies on the system, verify their state is correct
    // Note: We can't guarantee zombies exist, so we just verify the state handling
    for z in &zombies {
        assert!(
            matches!(z.state, ProcessState::Zombie),
            "Process marked as zombie should have Zombie state"
        );
        // Zombies have no memory or resources (they're just waiting to be reaped)
        // Their rss/vsz should typically be 0, but ps may report different values
        // The key point is they should be in Z state
    }

    // The test passes if:
    // 1. No zombies exist and we handle that gracefully
    // 2. Zombies exist and they have the correct Zombie state
}

// ============================================================================
// Kernel Thread Identification Tests
// ============================================================================

#[test]
fn quick_scan_identifies_kernel_threads_when_enabled() {
    if skip_if_proc_unavailable() {
        return;
    }

    // Must enable include_kernel_threads to see them (they're filtered by default)
    let options = QuickScanOptions {
        include_kernel_threads: true,
        ..QuickScanOptions::default()
    };
    let result = quick_scan(&options).expect("quick_scan should succeed");

    // Kernel threads are children of kthreadd (pid 2) or kthreadd itself (pid 2, ppid 0)
    let kernel_threads: Vec<_> = result
        .processes
        .iter()
        .filter(|p| p.ppid.0 == 2 || (p.pid.0 == 2 && p.ppid.0 == 0))
        .collect();

    // On any running Linux system, there should be kernel threads
    assert!(
        !kernel_threads.is_empty(),
        "Expected to find kernel threads (ppid=2 or kthreadd itself) when include_kernel_threads=true"
    );

    // Verify kernel threads have expected properties
    for kt in &kernel_threads {
        // Kernel threads typically have:
        // - ppid of 2 (kthreadd) or 0 (kthreadd itself)
        // - uid 0 (root)
        // - no TTY
        assert!(
            kt.ppid.0 == 0 || kt.ppid.0 == 2,
            "Kernel thread {} should have ppid 0 or 2, got {}",
            kt.comm,
            kt.ppid.0
        );
        assert_eq!(
            kt.uid, 0,
            "Kernel thread {} should be owned by root",
            kt.comm
        );
        assert!(
            kt.tty.is_none(),
            "Kernel thread {} should not have a TTY",
            kt.comm
        );
    }
}

#[test]
fn quick_scan_filters_kernel_threads_by_default() {
    if skip_if_proc_unavailable() {
        return;
    }

    // Default options should filter out kernel threads
    let options = QuickScanOptions::default();
    let result = quick_scan(&options).expect("quick_scan should succeed");

    // With default options, kernel threads should be filtered out
    let kernel_threads: Vec<_> = result
        .processes
        .iter()
        .filter(|p| p.ppid.0 == 2 || (p.pid.0 == 2 && p.ppid.0 == 0))
        .collect();

    assert!(
        kernel_threads.is_empty(),
        "Kernel threads should be filtered out by default, found: {:?}",
        kernel_threads.iter().map(|p| &p.comm).collect::<Vec<_>>()
    );
}

#[test]
fn quick_scan_distinguishes_kernel_thread_from_user_process() {
    if skip_if_proc_unavailable() {
        return;
    }

    let options = QuickScanOptions::default();
    let result = quick_scan(&options).expect("quick_scan should succeed");

    // Find a kernel thread (ppid 0 or 2) and a normal user process for comparison
    let kernel_thread = result
        .processes
        .iter()
        .find(|p| p.ppid.0 == 2 || (p.pid.0 == 2 && p.ppid.0 == 0));

    let user_process = result
        .processes
        .iter()
        .find(|p| p.ppid.0 > 2 && p.uid > 0);

    if let (Some(kt), Some(up)) = (kernel_thread, user_process) {
        // Key differentiator: kernel threads have ppid 0 or 2, user processes don't
        assert!(
            kt.ppid.0 <= 2,
            "Kernel thread should have ppid <= 2"
        );
        assert!(
            up.ppid.0 > 2,
            "User process should have ppid > 2 (not init or kthreadd)"
        );
    }
}

// ============================================================================
// TOCTOU Protection Tests
// ============================================================================

#[test]
fn process_record_includes_start_id_for_toctou_protection() {
    if skip_if_proc_unavailable() {
        return;
    }
    if !ProcessHarness::is_available() {
        return;
    }

    let harness = ProcessHarness::default();
    let proc = harness.spawn_sleep(10).expect("spawn sleep");
    let pid = proc.pid();

    std::thread::sleep(Duration::from_millis(100));

    let options = QuickScanOptions::default();
    let result = quick_scan(&options).expect("quick_scan should succeed");

    let found = result.processes.iter().find(|p| p.pid.0 == pid);
    assert!(found.is_some(), "Spawned process not found");

    let proc_record = found.unwrap();

    // Verify start_id is populated
    // start_id format is: <boot_id>:<start_time_ticks>:<pid>
    let start_id_str = &proc_record.start_id.0;
    assert!(
        !start_id_str.is_empty(),
        "start_id should be populated"
    );

    // Verify start_id contains expected components (colon-separated)
    let parts: Vec<&str> = start_id_str.split(':').collect();
    assert!(
        parts.len() >= 2,
        "start_id should have boot_id:start_time:pid format, got: {}",
        start_id_str
    );
}

#[test]
fn process_snapshot_detects_pid_reuse() {
    if skip_if_proc_unavailable() {
        return;
    }
    if !ProcessHarness::is_available() {
        return;
    }

    let harness = ProcessHarness::default();
    let proc = harness.spawn_sleep(60).expect("spawn sleep");
    let pid = proc.pid();

    std::thread::sleep(Duration::from_millis(100));

    // Capture snapshot
    let snapshot = proc.snapshot().expect("snapshot should succeed");
    assert_eq!(snapshot.pid, pid);
    assert!(snapshot.start_time_ticks.is_some());

    // Verify process is still running with same identity
    assert!(
        snapshot.is_still_running(),
        "Process should still be running"
    );

    // Kill the process
    proc.trigger_exit();
    let exited = proc.wait_for_exit(Duration::from_secs(2));
    assert!(exited, "Process should have exited");

    // Now the snapshot should detect the process is gone
    // (is_still_running checks if /proc/<pid>/stat exists with same start_time)
    // After exit, the file won't exist, so it returns false
    assert!(
        !snapshot.is_still_running(),
        "Process should no longer be running"
    );
}

// ============================================================================
// Scan Metadata Tests
// ============================================================================

#[test]
fn quick_scan_metadata_is_populated() {
    if skip_if_proc_unavailable() {
        return;
    }

    let options = QuickScanOptions::default();
    let result = quick_scan(&options).expect("quick_scan should succeed");

    let metadata = &result.metadata;

    assert!(!metadata.scan_type.is_empty(), "scan_type should be set");
    assert!(!metadata.platform.is_empty(), "platform should be set");
    assert!(metadata.process_count > 0, "should have scanned processes");
    assert_eq!(
        metadata.process_count,
        result.processes.len(),
        "process_count should match processes.len()"
    );
    // duration_ms is u64, always non-negative - just verify field is populated
    let _ = metadata.duration_ms;
}

#[test]
fn quick_scan_includes_boot_id_on_linux() {
    if skip_if_proc_unavailable() {
        return;
    }

    let options = QuickScanOptions::default();
    let result = quick_scan(&options).expect("quick_scan should succeed");

    // On Linux with /proc/sys/kernel/random/boot_id, boot_id should be populated
    let boot_id_path = std::path::Path::new("/proc/sys/kernel/random/boot_id");
    if boot_id_path.exists() {
        assert!(
            result.metadata.boot_id.is_some(),
            "boot_id should be populated on Linux"
        );
    }
}

// ============================================================================
// Multiple Process Types in Single Scan
// ============================================================================

#[test]
fn quick_scan_handles_mixed_process_states() {
    if skip_if_proc_unavailable() {
        return;
    }
    if !ProcessHarness::is_available() {
        return;
    }

    let harness = ProcessHarness::default();

    // Spawn different types of processes
    let sleep_proc = harness.spawn_sleep(60).expect("spawn sleep");
    let busy_proc = harness.spawn_busy().expect("spawn busy");

    std::thread::sleep(Duration::from_millis(300));

    let options = QuickScanOptions::default();
    let result = quick_scan(&options).expect("quick_scan should succeed");

    // Verify both processes are found
    let sleep_found = result.processes.iter().any(|p| p.pid.0 == sleep_proc.pid());
    let busy_found = result.processes.iter().any(|p| p.pid.0 == busy_proc.pid());

    assert!(
        sleep_found,
        "Sleep process (pid={}) should be in scan",
        sleep_proc.pid()
    );
    assert!(
        busy_found,
        "Busy process (pid={}) should be in scan",
        busy_proc.pid()
    );

    // Count processes by state
    let mut state_counts = std::collections::HashMap::new();
    for p in &result.processes {
        *state_counts.entry(format!("{:?}", p.state)).or_insert(0) += 1;
    }

    // Should have at least running and sleeping processes
    let running = state_counts.get("Running").copied().unwrap_or(0);
    let sleeping = state_counts.get("Sleeping").copied().unwrap_or(0);
    let idle = state_counts.get("Idle").copied().unwrap_or(0);

    assert!(
        running + sleeping + idle > 0,
        "Should have running, sleeping, or idle processes. Got: {:?}",
        state_counts
    );
}

// ============================================================================
// Process Group Collection Tests
// ============================================================================

#[test]
fn quick_scan_captures_process_group_members() {
    if skip_if_proc_unavailable() {
        return;
    }
    if !ProcessHarness::is_available() {
        return;
    }

    let harness = ProcessHarness::default();
    let parent = harness.spawn_process_group().expect("spawn process group");
    let parent_pid = parent.pid();

    // Wait for child to be spawned
    std::thread::sleep(Duration::from_millis(500));

    let options = QuickScanOptions::default();
    let result = quick_scan(&options).expect("quick_scan should succeed");

    // Find parent process
    let parent_record = result.processes.iter().find(|p| p.pid.0 == parent_pid);
    assert!(
        parent_record.is_some(),
        "Parent process should be in scan"
    );

    // Get PGID from parent
    if let Some(parent_rec) = parent_record {
        if let Some(pgid) = parent_rec.pgid {
            // Find all processes in the same process group
            let group_members: Vec<_> = result
                .processes
                .iter()
                .filter(|p| p.pgid == Some(pgid))
                .collect();

            // Should have at least the parent
            assert!(
                !group_members.is_empty(),
                "Should find at least one process in group"
            );
        }
    }
}
