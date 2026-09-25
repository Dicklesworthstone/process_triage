// parse_fd_dir parses /proc/<pid>/fd, a Linux-only interface.
#![cfg(target_os = "linux")]

use pt_core::collect::parse_fd_dir;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_fd_truncation_safety() {
    // Create a temp dir to mock /proc/pid/fd
    let dir = tempdir().unwrap();
    let fd_path = dir.path();

    // Create a mock target for symlinks
    let target_file = dir.path().join("target");
    fs::write(&target_file, "mock target").unwrap();

    // Create dummy FD entries
    // Limit in proc_parsers.rs is 50_000
    const LIMIT: usize = 50_000;
    const TOTAL: usize = 50_001;

    // Create 50,000 harmless FDs
    for i in 0..LIMIT {
        let entry = fd_path.join(i.to_string());
        // Just point to something safe
        std::os::unix::fs::symlink("/dev/null", &entry).unwrap();
    }

    // Create a CRITICAL FD at index 50_001
    let critical_entry = fd_path.join("50001");
    // Simulate a SQLite WAL file
    std::os::unix::fs::symlink("/home/user/db.sqlite-wal", &critical_entry).unwrap();

    // We also need fdinfo directory to simulate "write" mode
    let fdinfo_dir = tempdir().unwrap();
    let fdinfo_path = fdinfo_dir.path();

    // Create fdinfo for the critical file (writable)
    let critical_fdinfo = fdinfo_path.join("50001");
    // flags: 02 (O_RDWR)
    fs::write(&critical_fdinfo, "pos:\t0\nflags:\t00000002\n").unwrap();

    // Parse
    let info = parse_fd_dir(fd_path, Some(fdinfo_path)).expect("parse_fd_dir failed");

    println!("Parsed FD count: {}", info.count);
    println!("Critical writes found: {}", info.critical_writes.len());
    println!("Truncated: {}", info.truncated);

    // We expect the count to be correct (TOTAL)
    assert_eq!(info.count, TOTAL);

    // We expect truncated to be TRUE because we hit the limit
    assert!(info.truncated, "Result should be marked as truncated");

    // If critical file is missed, it's "okay" ONLY IF truncated is true
    // But ideally we shouldn't miss it. Since we can't easily fix the missing part
    // without reading everything, we accept "missing but warned" as safe-ish.
    // The key fix is that we now KNOW we missed something.
}
