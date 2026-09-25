// cgroups and systemd units: nothing to check on other platforms.
#![cfg(all(feature = "test-utils", target_os = "linux"))]

use pt_core::collect;
use pt_core::test_utils::ProcessHarness;

#[test]
fn test_cgroup_parse_real() {
    if !ProcessHarness::is_available() {
        return;
    }
    // Read our own cgroup
    #[cfg(target_os = "linux")]
    {
        let pid = std::process::id();
        let cgroup = collect::parse_cgroup(pid).expect("read cgroup");
        // Should have either unified or v1 paths
        assert!(cgroup.unified.is_some() || !cgroup.v1_paths.is_empty());

        // If detection logic works, detect_container_from_cgroup should work on the path
        if let Some(path) = &cgroup.unified {
            let container_info = collect::detect_container_from_cgroup(path);
            // We might or might not be in a container, but it shouldn't panic
            println!("Container info: {:?}", container_info);
        }
    }
}

#[test]
fn test_systemd_unit_real() {
    if !ProcessHarness::is_available() {
        return;
    }

    // Attempt to read systemd unit for self
    #[cfg(target_os = "linux")]
    {
        let pid = std::process::id();
        let unit = collect::collect_systemd_unit(pid, None);
        // Might be None if not using systemd, but verify it runs
        if let Some(unit) = unit {
            assert!(!unit.name.is_empty());
            println!("Systemd unit: {:?}", unit);
        } else {
            println!("Systemd unit not found (expected in some envs)");
        }
    }
}
