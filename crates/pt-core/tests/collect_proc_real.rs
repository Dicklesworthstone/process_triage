#![cfg(feature = "test-utils")]

use pt_core::collect;
use pt_core::test_utils::ProcessHarness;

#[test]
fn test_proc_io_real() {
    if !ProcessHarness::is_available() {
        println!("Skipping Linux-only test");
        return;
    }
    let harness = ProcessHarness::default();
    // Spawn a process that does IO (echo)
    let proc = harness
        .spawn_shell("echo hello > /dev/null")
        .expect("spawn");

    // Give it time to run
    std::thread::sleep(std::time::Duration::from_millis(50));

    #[cfg(target_os = "linux")]
    {
        // On Linux, parse_io should return something or None (if permissions)
        let io = collect::parse_io(proc.pid());
        if let Some(stats) = io {
            // It might be 0 if the kernel hasn't flushed stats or if echo was too fast,
            // but the call shouldn't panic.
            // Also depends on if we can read /proc/<pid>/io (requires ptrace usually).
            // If we spawned it, we own it, so we should be able to read it.
            // However, IO stats might be delayed.
            // We just verify it doesn't crash.
            println!("IO Stats: {:?}", stats);
        }
    }
}

#[test]
fn test_proc_schedstat_real() {
    if !ProcessHarness::is_available() {
        return;
    }
    let harness = ProcessHarness::default();
    let proc = harness.spawn_busy().expect("spawn busy");

    std::thread::sleep(std::time::Duration::from_millis(100));

    #[cfg(target_os = "linux")]
    {
        let stats = collect::parse_schedstat(proc.pid());
        if let Some(s) = stats {
            // Busy loop should have CPU time
            assert!(s.cpu_time_ns > 0);
        }
    }
}

#[test]
fn test_proc_fd_real() {
    if !ProcessHarness::is_available() {
        return;
    }
    let harness = ProcessHarness::default();
    // Spawn sleep; stdio may be devices, pipes, or other fd types
    // depending on the test environment (direct TTY vs CI)
    let proc = harness.spawn_sleep(10).expect("spawn");

    #[cfg(target_os = "linux")]
    {
        let info = collect::parse_fd(proc.pid());
        if let Some(info) = info {
            // stdin/stdout/stderr should always be present
            assert!(info.count >= 3, "Expected at least 3 FDs (stdio)");
            // Verify we collected type information (may be devices, pipes, sockets, etc.)
            let total_typed: usize = info.by_type.values().sum();
            assert!(total_typed > 0, "Expected FDs to be classified by type");
            println!("FD info: count={}, by_type={:?}", info.count, info.by_type);
        }
    }
}

#[test]
fn test_proc_statm_real() {
    if !ProcessHarness::is_available() {
        return;
    }
    let harness = ProcessHarness::default();
    let proc = harness.spawn_sleep(1).expect("spawn");

    #[cfg(target_os = "linux")]
    {
        let mem = collect::parse_statm(proc.pid());
        if let Some(m) = mem {
            assert!(m.size > 0);
            assert!(m.resident > 0);
        }
    }
}
