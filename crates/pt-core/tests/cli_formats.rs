//! CLI output format tests for pt-core.
//!
//! These tests verify that output formats work correctly and produce
//! valid, parseable output.

use assert_cmd::cargo::cargo_bin_cmd;
use assert_cmd::Command;
use predicates::prelude::*;

/// Get a Command for pt-core binary.
fn pt_core() -> Command {
    cargo_bin_cmd!("pt-core")
}

mod replay_recording {
    use super::*;

    // Retain captures for inspection; these tests never delete capture evidence.
    fn capture_dir() -> std::path::PathBuf {
        tempfile::tempdir().expect("capture directory").keep()
    }

    #[test]
    fn quick_scan_records_the_exact_live_inventory_for_native_replay() {
        let path = capture_dir().join("scan.json");
        let output = pt_core()
            .args(["scan", "--format", "json", "--robot", "--record-replay"])
            .arg(&path)
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        let displayed: serde_json::Value = serde_json::from_slice(&output).expect("scan JSON");
        let snapshot = pt_core::replay::load_snapshot(&path).expect("native snapshot loader");
        assert!(
            !snapshot.processes.is_empty(),
            "a live scan must contain processes"
        );
        assert_eq!(
            serde_json::to_value(&snapshot.processes).expect("recorded inventory"),
            displayed["scan"]["processes"]
        );
        assert_eq!(
            snapshot.scan_metadata.process_count,
            snapshot.processes.len()
        );
        assert_eq!(
            Some(snapshot.context.platform.as_str()),
            displayed["scan"]["metadata"]["platform"].as_str()
        );
        let restored = snapshot.to_scan_result();
        assert_eq!(
            serde_json::to_value(&restored.processes).expect("restored inventory"),
            displayed["scan"]["processes"]
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path)
                .expect("capture metadata")
                .permissions()
                .mode();
            assert_eq!(
                mode & 0o077,
                0,
                "capture must not expose raw commands to other users"
            );
        }
    }

    #[test]
    fn replay_recording_preserves_an_existing_capture() {
        let path = capture_dir().join("existing.json");
        let original = b"useful earlier capture\n";
        std::fs::write(&path, original).expect("existing capture");
        pt_core()
            .args(["scan", "--format", "json", "--robot", "--record-replay"])
            .arg(&path)
            .assert()
            .code(21)
            .stderr(predicate::str::contains("replay recording failed"));
        assert_eq!(
            std::fs::read(&path).expect("preserved capture"),
            original.as_slice()
        );
    }

    #[test]
    fn deep_scan_cannot_silently_ignore_replay_recording() {
        let path = capture_dir().join("unsupported.json");
        pt_core()
            .args(["scan", "--deep", "--record-replay"])
            .arg(&path)
            .assert()
            .failure()
            .stderr(predicate::str::contains("cannot be used with"));
        assert!(
            !path.exists(),
            "an unsupported recording must not create a file"
        );
    }

    #[cfg(unix)]
    #[test]
    fn replay_recording_never_follows_an_existing_symlink() {
        let dir = capture_dir();
        let target = dir.join("valuable.json");
        let link = dir.join("capture.json");
        let original = b"useful work behind a symlink\n";
        std::fs::write(&target, original).expect("target capture");
        std::os::unix::fs::symlink(&target, &link).expect("capture symlink");
        pt_core()
            .args(["scan", "--format", "json", "--robot", "--record-replay"])
            .arg(&link)
            .assert()
            .code(21);
        assert_eq!(
            std::fs::read(&target).expect("preserved target"),
            original.as_slice()
        );
        assert!(std::fs::symlink_metadata(&link)
            .expect("preserved link")
            .file_type()
            .is_symlink());
    }
}

// ============================================================================
// Global Format Option Tests
// ============================================================================

mod format_option {
    use super::*;

    #[test]
    fn json_format_accepted() {
        pt_core()
            .args(["--format", "json", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn toon_format_accepted() {
        pt_core()
            .args(["--format", "toon", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn short_format_flag_accepted() {
        pt_core().args(["-f", "json", "--help"]).assert().success();
    }

    #[test]
    fn md_format_accepted() {
        pt_core()
            .args(["--format", "md", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn jsonl_format_accepted() {
        pt_core()
            .args(["--format", "jsonl", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn summary_format_accepted() {
        pt_core()
            .args(["--format", "summary", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn invalid_format_rejected() {
        pt_core()
            .args(["--format", "xml"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("error"));
    }
}

// ============================================================================
// Version Output Format Tests
// ============================================================================

mod version_output {
    use super::*;

    #[test]
    fn version_output_contains_name() {
        pt_core()
            .arg("--version")
            .assert()
            .success()
            .stdout(predicate::str::contains("pt-core"));
    }

    #[test]
    fn version_output_contains_version_number() {
        pt_core()
            .arg("--version")
            .assert()
            .success()
            .stdout(predicate::str::is_match(r"\d+\.\d+\.\d+").unwrap());
    }
}

// ============================================================================
// Help Output Format Tests
// ============================================================================

mod help_output {
    use super::*;

    #[test]
    fn help_output_is_formatted() {
        pt_core()
            .arg("--help")
            .assert()
            .success()
            .stdout(predicate::str::contains("Usage:"))
            .stdout(predicate::str::contains("Options:"))
            .stdout(predicate::str::contains("Commands:"));
    }

    #[test]
    fn subcommand_help_is_formatted() {
        pt_core()
            .args(["agent", "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Usage:"))
            .stdout(predicate::str::contains("Commands:"));
    }
}

// ============================================================================
// Global Options Compatibility Tests
// ============================================================================

mod global_options {
    use super::*;

    #[test]
    fn verbose_flag_accepted() {
        pt_core().args(["-v", "--help"]).assert().success();
    }

    #[test]
    fn multiple_verbose_flags_accepted() {
        pt_core().args(["-vvv", "--help"]).assert().success();
    }

    #[test]
    fn quiet_flag_accepted() {
        pt_core().args(["-q", "--help"]).assert().success();
    }

    #[test]
    fn no_color_flag_accepted() {
        pt_core().args(["--no-color", "--help"]).assert().success();
    }

    #[test]
    fn robot_flag_accepted() {
        pt_core().args(["--robot", "--help"]).assert().success();
    }

    #[test]
    fn dry_run_flag_accepted() {
        pt_core().args(["--dry-run", "--help"]).assert().success();
    }

    #[test]
    fn shadow_flag_accepted() {
        pt_core().args(["--shadow", "--help"]).assert().success();
    }

    #[test]
    fn standalone_flag_accepted() {
        pt_core()
            .args(["--standalone", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn timeout_accepts_number() {
        pt_core()
            .args(["--timeout", "30", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn config_accepts_path() {
        pt_core()
            .args(["--config", "/tmp/test", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn capabilities_accepts_path() {
        pt_core()
            .args(["--capabilities", "/tmp/caps.json", "--help"])
            .assert()
            .success();
    }
}

// ============================================================================
// Command-specific Option Tests
// ============================================================================

mod command_options {
    use super::*;

    #[test]
    fn scan_samples_accepts_number() {
        pt_core()
            .args(["scan", "--samples", "5", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn scan_interval_accepts_number() {
        pt_core()
            .args(["scan", "--interval", "1000", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn deep_scan_pids_accepts_list() {
        pt_core()
            .args(["deep-scan", "--pids", "1,2,3", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn agent_plan_threshold_accepts_float() {
        pt_core()
            .args(["agent", "plan", "--threshold", "0.85", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn agent_plan_max_candidates_accepts_number() {
        pt_core()
            .args(["agent", "plan", "--max-candidates", "50", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn agent_plan_only_accepts_valid_values() {
        pt_core()
            .args(["agent", "plan", "--only", "kill", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn query_sessions_limit_accepts_number() {
        pt_core()
            .args(["query", "sessions", "--limit", "25", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn query_telemetry_range_accepts_string() {
        pt_core()
            .args(["query", "telemetry", "--range", "7d", "--help"])
            .assert()
            .success();
    }
}

// ============================================================================
// Combined Options Tests
// ============================================================================

mod combined_options {
    use super::*;

    #[test]
    fn multiple_global_options_work() {
        pt_core()
            .args(["-v", "--format", "json", "--no-color", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn global_options_with_subcommand() {
        pt_core()
            .args(["--format", "json", "-v", "scan", "--help"])
            .assert()
            .success();
    }

    #[test]
    fn subcommand_options_with_global_options() {
        pt_core()
            .args(["--format", "json", "scan", "--samples", "5", "--help"])
            .assert()
            .success();
    }
}
