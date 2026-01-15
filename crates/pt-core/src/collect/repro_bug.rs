
#[cfg(test)]
mod reproduction_test {
    use super::*;
    use std::fs;
    use std::path::Path;
    use tempfile::tempdir;

    #[test]
    fn test_parse_fd_dir_with_garbage_filename() {
        // Create a temp dir simulating /proc/pid/fd
        let dir = tempdir().unwrap();
        let fd_path = dir.path();

        // Create a valid FD "1"
        fs::File::create(fd_path.join("1")).unwrap();

        // Create a garbage entry "foo" (should be ignored)
        fs::File::create(fd_path.join("foo")).unwrap();

        // Parse
        let info = parse_fd_dir(fd_path, None).unwrap();

        // Only the numeric entry should be counted.
        assert_eq!(info.count, 1, "Count should ignore non-numeric entries");

        // No spurious fd=0 should be recorded.
        let has_fd_0 = info.open_files.iter().any(|f| f.fd == 0);
        assert!(!has_fd_0, "Non-numeric entries must not map to fd=0");
    }
}
