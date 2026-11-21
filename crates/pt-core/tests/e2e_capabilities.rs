//! CLI E2E tests for agent capabilities manifest generation and cache behavior.
//!
//! Validates:
//! - Capabilities JSON schema has all required top-level fields
//! - OS, tools, permissions, data_sources, supervisors, actions substructure
//! - `--check-action` flag for specific action queries
//! - Cache hit behavior (second run within TTL uses cached detected_at)
//! - Exit codes for success and error paths
//! - Output consistency and determinism
//!
//! See: bd-3t22

use assert_cmd::cargo::cargo_bin_cmd;
use assert_cmd::Command;
use serde_json::Value;
use std::sync::OnceLock;
use std::time::Duration;
use tempfile::TempDir;

// ============================================================================
// Helpers
// ============================================================================

fn isolated_cache_dir() -> &'static std::path::Path {
    static CACHE_DIR: OnceLock<TempDir> = OnceLock::new();
    CACHE_DIR
        .get_or_init(|| TempDir::new().expect("create isolated capabilities cache dir"))
        .path()
}

/// Get a Command for pt-core binary.
fn pt_core() -> Command {
    let mut cmd = cargo_bin_cmd!("pt-core");
    cmd.timeout(Duration::from_secs(60));
    cmd.env("XDG_CACHE_HOME", isolated_cache_dir());
    cmd
}

/// Run `pt-core --format json agent capabilities` and return parsed JSON.
fn capabilities_json() -> Value {
    let output = pt_core()
        .args(["--format", "json", "agent", "capabilities"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    serde_json::from_slice(&output).expect("parse capabilities JSON")
}

// ============================================================================
// Schema Validation: Top-Level Fields
// ============================================================================

#[test]
fn test_capabilities_has_required_top_level_fields() {
    let json = capabilities_json();

    let required_fields = [
        "schema_version",
        "session_id",
        "generated_at",
        "os",
        "tools",
        "permissions",
        "data_sources",
        "supervisors",
        "actions",
        "features",
        "detected_at",
    ];

    for field in required_fields {
        assert!(
            json.get(field).is_some(),
            "capabilities output missing required field '{}'",
            field
        );
    }
}

#[test]
fn test_capabilities_schema_version_is_semver() {
    let json = capabilities_json();
    let sv = json["schema_version"]
        .as_str()
        .expect("schema_version should be a string");

    // Should look like semver (major.minor.patch)
    let parts: Vec<&str> = sv.split('.').collect();
    assert!(
        parts.len() >= 2,
        "schema_version '{}' should be semver-like (x.y or x.y.z)",
        sv
    );

    // Each part should be numeric
    for (i, part) in parts.iter().enumerate() {
        assert!(
            part.parse::<u32>().is_ok(),
            "schema_version part {} ('{}') should be numeric in '{}'",
            i,
            part,
            sv
        );
    }
}

#[test]
fn test_capabilities_session_id_format() {
    let json = capabilities_json();
    let sid = json["session_id"]
        .as_str()
        .expect("session_id should be a string");

    // Session ID should be non-empty and contain a prefix
    assert!(!sid.is_empty(), "session_id should not be empty");
    assert!(
        sid.contains("pt-"),
        "session_id '{}' should contain 'pt-' prefix",
        sid
    );
}

#[test]
fn test_capabilities_generated_at_is_valid_timestamp() {
    let json = capabilities_json();
    let ts = json["generated_at"]
        .as_str()
        .expect("generated_at should be a string");

    // Should be RFC3339 parseable
    assert!(
        chrono::DateTime::parse_from_rfc3339(ts).is_ok(),
        "generated_at '{}' should be valid RFC3339 timestamp",
        ts
    );
}

#[test]
fn test_capabilities_detected_at_is_valid_timestamp() {
    let json = capabilities_json();
    let ts = json["detected_at"]
        .as_str()
        .expect("detected_at should be a string");

    assert!(
        chrono::DateTime::parse_from_rfc3339(ts).is_ok(),
        "detected_at '{}' should be valid RFC3339 timestamp",
        ts
    );
}

// ============================================================================
// Schema Validation: OS Section
// ============================================================================

#[test]
fn test_capabilities_os_structure() {
    let json = capabilities_json();
    let os = json.get("os").expect("os should exist");

    // Required subfields
    assert!(os.get("family").is_some(), "os should have 'family'");
    assert!(os.get("arch").is_some(), "os should have 'arch'");
    assert!(
        os.get("in_container").is_some(),
        "os should have 'in_container'"
    );

    // Family should be a non-empty string
    let family = os["family"].as_str().expect("family should be string");
    assert!(!family.is_empty(), "os.family should not be empty");

    // Arch should be a non-empty string
    let arch = os["arch"].as_str().expect("arch should be string");
    assert!(!arch.is_empty(), "os.arch should not be empty");

    // in_container should be boolean
    assert!(
        os["in_container"].is_boolean(),
        "os.in_container should be boolean"
    );

    eprintln!(
        "[INFO] OS: family={} arch={} container={}",
        family, arch, os["in_container"]
    );
}

// ============================================================================
// Schema Validation: Tools Section
// ============================================================================

#[test]
fn test_capabilities_tools_structure() {
    let json = capabilities_json();
    let tools = json.get("tools").expect("tools should exist");
    let tools_obj = tools.as_object().expect("tools should be an object");

    // Expected tool names
    let expected_tools = [
        "ps",
        "lsof",
        "ss",
        "netstat",
        "perf",
        "strace",
        "dtrace",
        "bpftrace",
        "systemctl",
        "docker",
        "podman",
        "nice",
        "renice",
        "ionice",
    ];

    for tool_name in expected_tools {
        assert!(
            tools_obj.contains_key(tool_name),
            "tools should contain '{}'",
            tool_name
        );

        let tool = &tools_obj[tool_name];
        assert!(
            tool.get("available").is_some(),
            "tool '{}' should have 'available' field",
            tool_name
        );
        assert!(
            tool["available"].is_boolean(),
            "tool '{}' available should be boolean",
            tool_name
        );
        assert!(
            tool.get("works").is_some(),
            "tool '{}' should have 'works' field",
            tool_name
        );
        assert!(
            tool["works"].is_boolean(),
            "tool '{}' works should be boolean",
            tool_name
        );
    }

    // ps should be available on any system
    assert!(
        tools_obj["ps"]["available"].as_bool().unwrap_or(false),
        "'ps' should be available on this system"
    );
    assert!(
        tools_obj["ps"]["works"].as_bool().unwrap_or(false),
        "'ps' should work on this system"
    );

    eprintln!("[INFO] Tools: {} defined, ps=available", tools_obj.len());
}

#[test]
fn test_capabilities_unavailable_tools_have_reason() {
    let json = capabilities_json();
    let tools = json["tools"].as_object().expect("tools object");

    for (name, tool) in tools {
        if !tool["available"].as_bool().unwrap_or(true) {
            assert!(
                tool.get("reason").is_some(),
                "unavailable tool '{}' should have a 'reason' field",
                name
            );
            let reason = tool["reason"].as_str().expect("reason should be string");
            assert!(
                !reason.is_empty(),
                "unavailable tool '{}' reason should not be empty",
                name
            );
        }
    }
}

// ============================================================================
// Schema Validation: Permissions Section
// ============================================================================

#[test]
fn test_capabilities_permissions_structure() {
    let json = capabilities_json();
    let perms = json.get("permissions").expect("permissions should exist");

    let required = [
        "effective_uid",
        "is_root",
        "can_sudo",
        "can_read_others_procs",
        "can_signal_others",
    ];

    for field in required {
        assert!(
            perms.get(field).is_some(),
            "permissions should have '{}'",
            field
        );
    }

    // Boolean fields
    assert!(perms["is_root"].is_boolean(), "is_root should be boolean");
    assert!(perms["can_sudo"].is_boolean(), "can_sudo should be boolean");
    assert!(
        perms["can_read_others_procs"].is_boolean(),
        "can_read_others_procs should be boolean"
    );
    assert!(
        perms["can_signal_others"].is_boolean(),
        "can_signal_others should be boolean"
    );

    // UID should be a number
    assert!(
        perms["effective_uid"].is_number(),
        "effective_uid should be a number"
    );

    eprintln!(
        "[INFO] Permissions: uid={} root={}",
        perms["effective_uid"], perms["is_root"]
    );
}

// ============================================================================
// Schema Validation: Data Sources Section
// ============================================================================

#[test]
fn test_capabilities_data_sources_structure() {
    let json = capabilities_json();
    let ds = json.get("data_sources").expect("data_sources should exist");

    let required = [
        "procfs",
        "sysfs",
        "perf_events",
        "ebpf",
        "schedstat",
        "cgroup_v1",
        "cgroup_v2",
    ];

    for field in required {
        assert!(
            ds.get(field).is_some(),
            "data_sources should have '{}'",
            field
        );
        assert!(
            ds[field].is_boolean(),
            "data_sources.{} should be boolean",
            field
        );
    }

    // On Linux, procfs should be available
    if cfg!(target_os = "linux") {
        assert!(
            ds["procfs"].as_bool().unwrap_or(false),
            "procfs should be available on Linux"
        );
    }
}

// ============================================================================
// Schema Validation: Supervisors Section
// ============================================================================

#[test]
fn test_capabilities_supervisors_structure() {
    let json = capabilities_json();
    let sups = json.get("supervisors").expect("supervisors should exist");

    let required = [
        "systemd",
        "launchd",
        "pm2",
        "supervisord",
        "docker_daemon",
        "podman",
        "kubernetes",
    ];

    for field in required {
        assert!(
            sups.get(field).is_some(),
            "supervisors should have '{}'",
            field
        );
        assert!(
            sups[field].is_boolean(),
            "supervisors.{} should be boolean",
            field
        );
    }
}

// ============================================================================
// Schema Validation: Actions Section
// ============================================================================

#[test]
fn test_capabilities_actions_structure() {
    let json = capabilities_json();
    let actions = json.get("actions").expect("actions should exist");

    let required = [
        "kill",
        "pause",
        "renice",
        "ionice",
        "cgroup_freeze",
        "cgroup_throttle",
        "cpuset_quarantine",
    ];

    for field in required {
        assert!(
            actions.get(field).is_some(),
            "actions should have '{}'",
            field
        );
        assert!(
            actions[field].is_boolean(),
            "actions.{} should be boolean",
            field
        );
    }

    // Kill action availability depends on permissions; just verify it's a boolean
    assert!(
        actions["kill"].is_boolean(),
        "kill action should be a boolean value"
    );
}

// ============================================================================
// Schema Validation: Features Section
// ============================================================================

#[test]
fn test_capabilities_features_structure() {
    let json = capabilities_json();
    let features = json.get("features").expect("features should exist");

    assert!(
        features.get("deep_scan").is_some(),
        "features should have 'deep_scan'"
    );
    assert!(
        features["deep_scan"].is_boolean(),
        "features.deep_scan should be boolean"
    );

    assert!(
        features.get("maximal_scan").is_some(),
        "features should have 'maximal_scan'"
    );
    assert!(
        features["maximal_scan"].is_boolean(),
        "features.maximal_scan should be boolean"
    );
}

// ============================================================================
// Check-Action Flag
// ============================================================================

#[test]
fn test_check_action_supported_action() {
    // "sigterm" (mapped to kill) should be supported on any system
    let output = pt_core()
        .args([
            "--format",
            "json",
            "agent",
            "capabilities",
            "--check-action",
            "sigterm",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).expect("parse JSON");

    assert_eq!(
        json["action"].as_str(),
        Some("sigterm"),
        "check-action response should echo the queried action"
    );
    assert!(
        json.get("supported").is_some(),
        "check-action response should have 'supported' field"
    );
    assert!(
        json["supported"].is_boolean(),
        "supported should be boolean"
    );
}

#[test]
fn test_check_action_unsupported_action_fails() {
    // An invalid/unsupported action should fail
    pt_core()
        .args([
            "--format",
            "json",
            "agent",
            "capabilities",
            "--check-action",
            "nonexistent_action_xyz",
        ])
        .assert()
        .failure();
}

#[test]
fn test_check_action_common_actions() {
    // Test several common action types
    let common_actions = ["sigterm", "sigkill", "sigstop", "sigcont", "nice", "renice"];

    for action in common_actions {
        let result = pt_core()
            .args([
                "--format",
                "json",
                "agent",
                "capabilities",
                "--check-action",
                action,
            ])
            .output()
            .expect("run command");

        // Should not hang or crash (may fail gracefully for unsupported)
        let stdout = String::from_utf8_lossy(&result.stdout);
        if result.status.success() {
            let json: Value = serde_json::from_str(stdout.trim()).expect("parse success JSON");
            assert_eq!(
                json["action"].as_str(),
                Some(action),
                "response should echo action '{}'",
                action
            );
        }

        eprintln!(
            "[INFO] check-action '{}': exit={}",
            action,
            result.status.code().unwrap_or(-1)
        );
    }
}

// ============================================================================
// Cache Behavior (via CLI)
// ============================================================================

#[test]
fn test_capabilities_cache_hit_returns_same_detected_at() {
    // Dedicated cache directory avoids cold-start races with parallel tests.
    let cache_dir = TempDir::new().expect("dedicated capabilities cache dir");
    let run_once = || -> Value {
        let output = pt_core()
            .env("XDG_CACHE_HOME", cache_dir.path())
            .args(["--format", "json", "agent", "capabilities"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        serde_json::from_slice(&output).expect("parse capabilities JSON")
    };

    // First run populates cache; second run within TTL should use cached result.
    let json1 = run_once();
    let json2 = run_once();

    let detected_at_1 = json1["detected_at"].as_str().expect("detected_at 1");
    let detected_at_2 = json2["detected_at"].as_str().expect("detected_at 2");

    // If cache is working, detected_at should be the same (cached result).
    // Note: session_id and generated_at will differ (generated per invocation),
    // but detected_at comes from the cached capabilities.
    assert_eq!(
        detected_at_1, detected_at_2,
        "detected_at should match on cache hit (run1='{}' run2='{}')",
        detected_at_1, detected_at_2
    );

    // session_id should differ (new session per invocation)
    let sid1 = json1["session_id"].as_str().unwrap();
    let sid2 = json2["session_id"].as_str().unwrap();
    assert_ne!(sid1, sid2, "session_id should differ across invocations");

    eprintln!(
        "[INFO] Cache: detected_at={} (same both runs), sid1={} sid2={}",
        detected_at_1, sid1, sid2
    );
}

#[test]
fn test_capabilities_generated_at_is_per_invocation() {
    // generated_at should be fresh on each invocation (not cached)
    let json1 = capabilities_json();

    // Small delay to ensure different timestamps
    std::thread::sleep(std::time::Duration::from_millis(50));

    let json2 = capabilities_json();

    let ts1 = json1["generated_at"].as_str().unwrap();
    let ts2 = json2["generated_at"].as_str().unwrap();

    // generated_at should be different (fresh per invocation)
    // or at least both should be valid timestamps
    let dt1 = chrono::DateTime::parse_from_rfc3339(ts1).expect("parse ts1");
    let dt2 = chrono::DateTime::parse_from_rfc3339(ts2).expect("parse ts2");

    // Second timestamp should be >= first
    assert!(
        dt2 >= dt1,
        "generated_at should advance: {} vs {}",
        ts1,
        ts2
    );
}

// ============================================================================
// Exit Codes
// ============================================================================

#[test]
fn test_capabilities_success_exit_code() {
    pt_core()
        .args(["--format", "json", "agent", "capabilities"])
        .assert()
        .success()
        .code(0);
}

#[test]
fn test_capabilities_exitcode_format() {
    // --format exitcode should produce no stdout (exit code only)
    let output = pt_core()
        .args(["--format", "exitcode", "agent", "capabilities"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert!(
        output.is_empty(),
        "exitcode format should produce no stdout (got {} bytes)",
        output.len()
    );
}

// ============================================================================
// Output Size Characteristics
// ============================================================================

#[test]
fn test_capabilities_output_reasonable_size() {
    let output = pt_core()
        .args(["--format", "json", "agent", "capabilities"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let size = output.len();

    // Capabilities output should be meaningful but bounded
    assert!(
        size > 200,
        "capabilities output should be > 200 bytes (got {})",
        size
    );
    assert!(
        size < 50000,
        "capabilities output should be < 50KB (got {})",
        size
    );

    eprintln!("[INFO] Capabilities output: {} bytes", size);
}
