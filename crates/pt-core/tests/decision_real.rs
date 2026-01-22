#![cfg(feature = "test-utils")]

use pt_core::config::Policy;
use pt_core::decision::{Action, PolicyEnforcer, ProcessCandidate};
use std::fs;

// We need to bring in temp_dir from test_utils.
// Note: In integration tests, we need to make sure we can access it.
// `pt_core::test_utils` is public if feature is enabled.

#[test]
fn test_policy_load_and_enforce_real() {
    // Only run if features enabled (or just use standard tempfile if not)
    // We'll use the one from test_utils to verify the bead requirement.

    #[cfg(feature = "test-tempdir")]
    let tmp = pt_core::test_utils::temp_dir();

    #[cfg(not(feature = "test-tempdir"))]
    let tmp = tempfile::tempdir().expect("tempdir");

    let policy_path = tmp.path().join("policy.json");

    let policy_content = r#"{
        "schema_version": "1.0.0",
        "loss_matrix": {
            "useful": {"keep": 0, "kill": 100},
            "useful_bad": {"keep": 10, "kill": 20},
            "abandoned": {"keep": 30, "kill": 1},
            "zombie": {"keep": 50, "kill": 1}
        },
        "guardrails": {
            "protected_patterns": [
                {"pattern": "important_service", "kind": "literal"}
            ],
            "never_kill_ppid": [],
            "max_kills_per_run": 5,
            "min_process_age_seconds": 3600
        },
        "robot_mode": {
            "enabled": true,
            "min_posterior": 0.90,
            "max_blast_radius_mb": 1000.0,
            "max_kills": 2,
            "require_known_signature": false
        },
        "fdr_control": {
            "enabled": false,
            "method": "bh",
            "alpha": 0.05
        },
        "data_loss_gates": {
            "block_if_open_write_fds": true,
            "block_if_locked_files": true,
            "block_if_active_tty": true
        }
    }"#;
    fs::write(&policy_path, policy_content).expect("write policy");

    // Load policy from file (real IO)
    let policy_json = fs::read_to_string(&policy_path).expect("read policy");
    let policy: Policy = serde_json::from_str(&policy_json).expect("parse policy");

    let enforcer = PolicyEnforcer::new(&policy, None).expect("create enforcer");

    // Test enforcement
    let candidate = ProcessCandidate {
        pid: 123,
        ppid: 1,
        cmdline: "/usr/bin/important_service".to_string(),
        user: None,
        group: None,
        category: None,
        age_seconds: 7200,
        posterior: Some(0.95),
        memory_mb: Some(100.0),
        has_known_signature: false,
        open_write_fds: None,
        has_locked_files: None,
        has_active_tty: None,
        seconds_since_io: None,
        cwd_deleted: None,
        process_state: None,
        wchan: None,
        critical_files: Vec::new(),
    };

    let result = enforcer.check_action(&candidate, Action::Kill, true); // robot_mode=true

    assert!(!result.allowed, "Should be blocked by protected pattern");
    let violation = result.violation.unwrap();
    // ViolationKind is an enum, debug print it
    assert!(format!("{:?}", violation.kind).contains("ProtectedPattern"));
}
