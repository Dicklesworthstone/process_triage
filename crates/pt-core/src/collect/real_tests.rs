//! No-mock integration tests for evidence collection.
//!
//! These tests use real processes spawned by ProcessHarness and read live /proc
//! data where available. They skip gracefully on unsupported platforms.

#![cfg(target_os = "linux")]

use crate::collect::{
    collect_cgroup_details, deep_scan, quick_scan, DeepScanOptions, QuickScanOptions,
};
use crate::test_utils::ProcessHarness;

#[cfg(target_os = "linux")]
#[test]
fn test_quick_scan_real_pid() {
    if !ProcessHarness::is_available() {
        return;
    }
    let harness = ProcessHarness::default();
    let _timer = crate::test_utils::TestTimer::new("quick_scan_real_pid");
    // Use 30 second sleep to ensure process is still running after scan
    // (ps -p doesn't work reliably with -e, so we do a full scan)
    let proc = harness.spawn_shell("sleep 30").expect("spawn sleep");

    // Run full scan and filter results manually
    // (ps -p doesn't work reliably with -e on all systems)
    let options = QuickScanOptions::default();
    let result = quick_scan(&options).expect("quick_scan");

    assert!(
        result.processes.iter().any(|p| p.pid.0 == proc.pid()),
        "quick_scan should include spawned pid {}",
        proc.pid()
    );
    assert!(proc.is_running());
}

#[cfg(target_os = "linux")]
#[test]
fn test_deep_scan_real_pid() {
    if !ProcessHarness::is_available() {
        return;
    }
    let harness = ProcessHarness::default();
    let _timer = crate::test_utils::TestTimer::new("deep_scan_real_pid");
    // Use 30 second sleep to ensure process is still running after scan
    let proc = harness.spawn_shell("sleep 30").expect("spawn sleep");

    let options = DeepScanOptions {
        pids: vec![proc.pid()],
        skip_inaccessible: true,
        include_environ: false,
        progress: None,
    };
    let result = deep_scan(&options).expect("deep_scan");

    let record = result
        .processes
        .iter()
        .find(|p| p.pid.0 == proc.pid())
        .expect("deep_scan record for pid");

    assert!(!record.comm.is_empty());
    assert!(!record.start_id.0.is_empty());
    assert!(proc.is_running());
}

#[cfg(target_os = "linux")]
#[test]
fn test_cgroup_details_real_pid() {
    if !ProcessHarness::is_available() {
        return;
    }
    let harness = ProcessHarness::default();
    let _timer = crate::test_utils::TestTimer::new("cgroup_details_real_pid");
    // Use 30 second sleep to ensure process is still running after scan
    let proc = harness.spawn_shell("sleep 30").expect("spawn sleep");

    let details = collect_cgroup_details(proc.pid()).expect("cgroup details");
    assert!(
        details.provenance.cgroup_file.contains(&format!("/proc/{}/cgroup", proc.pid())),
        "expected provenance to include cgroup file path"
    );
    assert!(proc.is_running());
}
