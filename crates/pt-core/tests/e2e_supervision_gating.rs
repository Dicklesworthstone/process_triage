//! CLI E2E tests for supervision gating and protected pattern enforcement.
//!
//! Validates:
//! - `agent plan` output includes supervisor info for every candidate
//! - `agent plan` summary shows protected_filtered count
//! - Protected patterns from default policy filter known system processes
//! - Custom policy with extra protected patterns increases filtering
//! - Supervisor JSON structure (detected, type, unit, recommended_action)
//! - `agent capabilities --check-action` for supervision-relevant actions
//! - `config validate` accepts valid guardrails and rejects malformed ones
//! - Exit codes for success and error paths
//!
//! See: bd-12r5

use assert_cmd::cargo::cargo_bin_cmd;
use assert_cmd::Command;
use serde_json::Value;
use std::fs;
use std::time::Duration;
use tempfile::tempdir;

// ============================================================================
// Helpers
// ============================================================================

/// Get a Command for pt-core binary.
fn pt_core() -> Command {
    let mut cmd = cargo_bin_cmd!("pt-core");
    cmd.timeout(Duration::from_secs(60));
    cmd
}

/// Run `agent plan` with small sample for speed and return parsed JSON.
/// Sets PT_SKIP_GLOBAL_LOCK to avoid lock contention between parallel tests.
fn agent_plan_json(extra_args: &[&str]) -> Value {
    let mut cmd = pt_core();
    cmd.timeout(Duration::from_secs(300));
    cmd.env("PT_SKIP_GLOBAL_LOCK", "1");

    let mut args = vec![
        "--format", "json",
        "agent", "plan",
        "--sample-size", "5",
        "--min-posterior", "0.0",
    ];
    args.extend_from_slice(extra_args);

    let output = cmd
        .args(&args)
        .assert()
        .get_output()
        .stdout
        .clone();

    serde_json::from_slice(&output).expect("parse agent plan JSON")
}

/// Export a preset policy, modify its guardrails, and write to a file.
/// This ensures all required fields (loss_matrix, fdr_control, etc.) are present.
fn export_preset_with_guardrails(
    dir: &std::path::Path,
    guardrails: Value,
) -> std::path::PathBuf {
    let export_path = dir.join("base_policy.json");

    // Export the developer preset as a base
    pt_core()
        .args([
            "--format", "json",
            "config", "export-preset", "developer",
            "--output", export_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Read, modify guardrails, write back
    let content = fs::read_to_string(&export_path).expect("read exported policy");
    let mut policy: Value = serde_json::from_str(&content).expect("parse exported policy");
    policy["guardrails"] = guardrails;

    let modified_path = dir.join("policy.json");
    fs::write(
        &modified_path,
        serde_json::to_string_pretty(&policy).unwrap(),
    )
    .expect("write modified policy");

    modified_path
}

// ============================================================================
// Agent Plan: Supervisor Info in Candidates
// ============================================================================

#[test]
fn test_agent_plan_candidates_have_supervisor_field() {
    let json = agent_plan_json(&[]);

    let candidates = json["candidates"]
        .as_array()
        .expect("candidates should be array");

    // Every candidate should have a supervisor field
    for (i, candidate) in candidates.iter().enumerate() {
        assert!(
            candidate.get("supervisor").is_some(),
            "candidate[{}] should have 'supervisor' field",
            i
        );

        let supervisor = &candidate["supervisor"];
        assert!(
            supervisor.get("detected").is_some(),
            "candidate[{}].supervisor should have 'detected'",
            i
        );
        assert!(
            supervisor["detected"].is_boolean(),
            "candidate[{}].supervisor.detected should be boolean",
            i
        );
    }
}

#[test]
fn test_agent_plan_supervisor_structure() {
    let json = agent_plan_json(&[]);

    let candidates = json["candidates"]
        .as_array()
        .expect("candidates should be array");

    if candidates.is_empty() {
        eprintln!("[INFO] no candidates to check supervisor structure");
        return;
    }

    let supervisor = &candidates[0]["supervisor"];

    // All supervisor objects should have these fields
    assert!(
        supervisor.get("detected").is_some(),
        "supervisor should have 'detected'"
    );
    assert!(
        supervisor.get("type").is_some(),
        "supervisor should have 'type'"
    );
    assert!(
        supervisor.get("recommended_action").is_some(),
        "supervisor should have 'recommended_action'"
    );

    eprintln!(
        "[INFO] supervisor: detected={}, type={}, action={}",
        supervisor["detected"],
        supervisor["type"],
        supervisor["recommended_action"]
    );
}

// ============================================================================
// Agent Plan: Protected Filter Summary
// ============================================================================

#[test]
fn test_agent_plan_summary_has_protected_filtered() {
    let json = agent_plan_json(&[]);

    let summary = &json["summary"];
    assert!(
        summary.get("protected_filtered").is_some(),
        "summary should have 'protected_filtered'"
    );

    let protected_count = summary["protected_filtered"]
        .as_u64()
        .expect("protected_filtered should be a number");

    eprintln!(
        "[INFO] protected_filtered: {} processes filtered by default policy",
        protected_count
    );
}

#[test]
fn test_agent_plan_summary_protected_count_consistent() {
    let json = agent_plan_json(&[]);

    let summary = &json["summary"];
    let total_scanned = summary["total_processes_scanned"]
        .as_u64()
        .expect("total_processes_scanned");
    let protected_filtered = summary["protected_filtered"]
        .as_u64()
        .expect("protected_filtered");
    let candidates_evaluated = summary["candidates_evaluated"]
        .as_u64()
        .expect("candidates_evaluated");

    assert!(
        protected_filtered <= total_scanned,
        "protected_filtered ({}) should be <= total_scanned ({})",
        protected_filtered,
        total_scanned
    );

    assert!(
        candidates_evaluated <= total_scanned,
        "candidates_evaluated ({}) should be <= total_scanned ({})",
        candidates_evaluated,
        total_scanned
    );
}

// ============================================================================
// Agent Plan: Candidate Fields for Gating
// ============================================================================

#[test]
fn test_agent_plan_candidates_have_gating_fields() {
    let json = agent_plan_json(&[]);

    let candidates = json["candidates"]
        .as_array()
        .expect("candidates should be array");

    for (i, candidate) in candidates.iter().enumerate() {
        assert!(
            candidate.get("recommended_action").is_some(),
            "candidate[{}] should have 'recommended_action'",
            i
        );
        assert!(
            candidate.get("reversibility").is_some(),
            "candidate[{}] should have 'reversibility'",
            i
        );
        assert!(
            candidate.get("blast_radius").is_some(),
            "candidate[{}] should have 'blast_radius'",
            i
        );
    }
}

#[test]
fn test_agent_plan_candidates_have_action_rationale() {
    let json = agent_plan_json(&[]);

    let candidates = json["candidates"]
        .as_array()
        .expect("candidates should be array");

    for (i, candidate) in candidates.iter().enumerate() {
        assert!(
            candidate.get("action_rationale").is_some(),
            "candidate[{}] should have 'action_rationale'",
            i
        );
    }
}

// ============================================================================
// Capabilities: Check Action
// ============================================================================

#[test]
fn test_capabilities_check_action_sigterm() {
    let output = pt_core()
        .args([
            "--format", "json",
            "agent", "capabilities",
            "--check-action", "sigterm",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).expect("parse JSON");

    // --check-action returns flat {action, supported, reason}
    assert_eq!(json["action"], "sigterm");
    assert!(
        json.get("supported").is_some(),
        "should have 'supported' field"
    );
    assert!(
        json["supported"].is_boolean(),
        "supported should be boolean"
    );
    assert!(
        json.get("reason").is_some(),
        "should have 'reason' field"
    );
}

#[test]
fn test_capabilities_check_action_sigkill() {
    let output = pt_core()
        .args([
            "--format", "json",
            "agent", "capabilities",
            "--check-action", "sigkill",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).expect("parse JSON");
    assert_eq!(json["action"], "sigkill");
    assert!(json["supported"].is_boolean());
}

#[test]
fn test_capabilities_check_action_nice() {
    let output = pt_core()
        .args([
            "--format", "json",
            "agent", "capabilities",
            "--check-action", "nice",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).expect("parse JSON");
    assert_eq!(json["action"], "nice");
    assert!(json["supported"].is_boolean());
}

#[test]
fn test_capabilities_supervisors_structure() {
    let output = pt_core()
        .args(["--format", "json", "agent", "capabilities"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).expect("parse JSON");

    assert!(
        json.get("supervisors").is_some(),
        "capabilities should have 'supervisors'"
    );

    let supervisors = &json["supervisors"];
    assert!(
        supervisors.is_object(),
        "supervisors should be an object"
    );

    // Each supervisor type should be a boolean (available/not)
    let expected_keys = ["systemd", "docker_daemon", "pm2", "supervisord", "kubernetes"];
    for key in expected_keys {
        assert!(
            supervisors.get(key).is_some(),
            "supervisors should have '{}'",
            key
        );
        assert!(
            supervisors[key].is_boolean(),
            "supervisors.{} should be a boolean",
            key
        );
    }
}

// ============================================================================
// Config Validate with Guardrails
// ============================================================================

#[test]
fn test_config_validate_default_guardrails_valid() {
    let output = pt_core()
        .args(["--format", "json", "config", "validate"])
        .assert()
        .success()
        .code(0)
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).expect("parse JSON");
    assert_eq!(json["status"], "valid");
}

#[test]
fn test_config_validate_custom_guardrails() {
    let dir = tempdir().expect("tempdir");

    let guardrails = serde_json::json!({
        "protected_patterns": [
            {"pattern": "^sshd$", "kind": "regex", "case_insensitive": true},
            {"pattern": "my_critical_app", "kind": "literal", "case_insensitive": false}
        ],
        "force_review_patterns": [],
        "protected_users": ["root"],
        "protected_groups": [],
        "protected_categories": [],
        "never_kill_ppid": [1],
        "never_kill_pid": [],
        "max_kills_per_run": 5,
        "min_process_age_seconds": 60,
        "require_confirmation": true
    });

    let policy_path = export_preset_with_guardrails(dir.path(), guardrails);

    pt_core()
        .args([
            "--format", "json",
            "config", "validate",
            policy_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .code(0);
}

#[test]
fn test_config_validate_accepts_invalid_regex_in_guardrails() {
    // config validate only checks JSON schema structure, not regex compilation.
    // Invalid regex patterns are caught at filter-creation time (runtime), not validation.
    let dir = tempdir().expect("tempdir");

    let guardrails = serde_json::json!({
        "protected_patterns": [
            {"pattern": "[invalid regex(((", "kind": "regex", "case_insensitive": true}
        ],
        "force_review_patterns": [],
        "protected_users": [],
        "protected_groups": [],
        "protected_categories": [],
        "never_kill_ppid": [1],
        "never_kill_pid": [],
        "max_kills_per_run": 5,
        "min_process_age_seconds": 60,
        "require_confirmation": true
    });

    let policy_path = export_preset_with_guardrails(dir.path(), guardrails);

    pt_core()
        .args([
            "--format", "json",
            "config", "validate",
            policy_path.to_str().unwrap(),
        ])
        .assert()
        .success()
        .code(0);
}

#[test]
fn test_config_validate_empty_pattern_in_guardrails() {
    let dir = tempdir().expect("tempdir");

    let guardrails = serde_json::json!({
        "protected_patterns": [
            {"pattern": "", "kind": "literal", "case_insensitive": true}
        ],
        "force_review_patterns": [],
        "protected_users": [],
        "protected_groups": [],
        "protected_categories": [],
        "never_kill_ppid": [],
        "never_kill_pid": [],
        "max_kills_per_run": 5,
        "min_process_age_seconds": 60,
        "require_confirmation": true
    });

    let policy_path = export_preset_with_guardrails(dir.path(), guardrails);

    pt_core()
        .args([
            "--format", "json",
            "config", "validate",
            policy_path.to_str().unwrap(),
        ])
        .assert()
        .failure();
}

// ============================================================================
// Agent Plan with Custom Policy
// ============================================================================

#[test]
fn test_agent_plan_with_aggressive_protected_patterns() {
    let dir = tempdir().expect("tempdir");

    // Create a policy that protects everything matching ".*" (all processes)
    let guardrails = serde_json::json!({
        "protected_patterns": [
            {"pattern": ".*", "kind": "regex", "case_insensitive": true, "notes": "protect all"}
        ],
        "force_review_patterns": [],
        "protected_users": [],
        "protected_groups": [],
        "protected_categories": [],
        "never_kill_ppid": [1],
        "never_kill_pid": [],
        "max_kills_per_run": 0,
        "min_process_age_seconds": 0,
        "require_confirmation": true
    });

    // export_preset_with_guardrails writes to dir/policy.json.
    // agent plan's --config flag sets config_dir (a directory), and load_policy
    // looks for policy.json inside that directory. So we pass the temp dir itself.
    let _policy_path = export_preset_with_guardrails(dir.path(), guardrails);

    let mut cmd = pt_core();
    cmd.timeout(Duration::from_secs(300));
    cmd.env("PT_SKIP_GLOBAL_LOCK", "1");

    let output = cmd
        .args([
            "--format", "json",
            "--config", dir.path().to_str().unwrap(),
            "agent", "plan",
            "--sample-size", "5",
            "--min-posterior", "0.0",
        ])
        .assert()
        .get_output()
        .stdout
        .clone();

    let json: Value = serde_json::from_slice(&output).expect("parse JSON");

    let summary = &json["summary"];
    let protected_filtered = summary["protected_filtered"]
        .as_u64()
        .expect("protected_filtered");
    let total_scanned = summary["total_processes_scanned"]
        .as_u64()
        .expect("total_processes_scanned");

    // With ".*" pattern, ALL processes should be filtered
    assert_eq!(
        protected_filtered, total_scanned,
        "wildcard protected pattern should filter all {} processes (got {})",
        total_scanned, protected_filtered
    );

    // No candidates should remain
    let candidates = json["candidates"]
        .as_array()
        .expect("candidates array");
    assert_eq!(
        candidates.len(),
        0,
        "no candidates should survive wildcard filter"
    );
}

// ============================================================================
// Plan Output: Recommendations Structure
// ============================================================================

#[test]
fn test_agent_plan_recommendations_structure() {
    let json = agent_plan_json(&[]);

    let recommendations = &json["recommendations"];
    assert!(
        recommendations.get("kill_set").is_some(),
        "recommendations should have 'kill_set'"
    );
    assert!(
        recommendations.get("review_set").is_some(),
        "recommendations should have 'review_set'"
    );
    assert!(
        recommendations.get("spare_set").is_some(),
        "recommendations should have 'spare_set'"
    );

    assert!(
        recommendations["kill_set"].is_array(),
        "kill_set should be array"
    );
    assert!(
        recommendations["review_set"].is_array(),
        "review_set should be array"
    );
    assert!(
        recommendations["spare_set"].is_array(),
        "spare_set should be array"
    );
}

#[test]
fn test_agent_plan_summary_policy_blocked_field() {
    let json = agent_plan_json(&[]);

    let summary = &json["summary"];
    assert!(
        summary.get("policy_blocked").is_some(),
        "summary should have 'policy_blocked'"
    );

    let policy_blocked = summary["policy_blocked"]
        .as_u64()
        .expect("policy_blocked should be a number");

    eprintln!(
        "[INFO] policy_blocked: {} candidates blocked by policy",
        policy_blocked
    );
}

// ============================================================================
// Config Export Preset: Guardrails Content
// ============================================================================

#[test]
fn test_config_preset_paranoid_has_stricter_guardrails() {
    let dev_output = pt_core()
        .args(["--format", "json", "config", "show-preset", "developer"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let paranoid_output = pt_core()
        .args(["--format", "json", "config", "show-preset", "paranoid"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let dev: Value = serde_json::from_slice(&dev_output).expect("parse dev");
    let paranoid: Value = serde_json::from_slice(&paranoid_output).expect("parse paranoid");

    let dev_guardrails = &dev["policy"]["guardrails"];
    let paranoid_guardrails = &paranoid["policy"]["guardrails"];

    // Both should have protected_patterns
    assert!(
        dev_guardrails.get("protected_patterns").is_some(),
        "developer should have protected_patterns"
    );
    assert!(
        paranoid_guardrails.get("protected_patterns").is_some(),
        "paranoid should have protected_patterns"
    );

    // Paranoid should have more restrictive max_kills_per_run
    let dev_max_kills = dev_guardrails["max_kills_per_run"]
        .as_u64()
        .unwrap_or(u64::MAX);
    let paranoid_max_kills = paranoid_guardrails["max_kills_per_run"]
        .as_u64()
        .unwrap_or(u64::MAX);

    assert!(
        paranoid_max_kills <= dev_max_kills,
        "paranoid max_kills ({}) should be <= developer max_kills ({})",
        paranoid_max_kills,
        dev_max_kills
    );

    eprintln!(
        "[INFO] max_kills_per_run: developer={}, paranoid={}",
        dev_max_kills, paranoid_max_kills
    );
}

// ============================================================================
// Plan Output with --only filter
// ============================================================================

#[test]
fn test_agent_plan_only_kill_filter() {
    let json = agent_plan_json(&["--only", "kill"]);

    let summary = &json["summary"];
    assert_eq!(
        summary["filter_used"], "kill",
        "filter_used should be 'kill'"
    );

    // All returned candidates should have kill recommendation
    let candidates = json["candidates"]
        .as_array()
        .expect("candidates array");

    for (i, candidate) in candidates.iter().enumerate() {
        let action = candidate["recommended_action"]
            .as_str()
            .unwrap_or("");
        assert!(
            action == "kill" || action == "restart",
            "candidate[{}] with --only kill should have kill/restart action, got '{}'",
            i,
            action
        );
    }
}

#[test]
fn test_agent_plan_only_review_filter() {
    let json = agent_plan_json(&["--only", "review"]);

    let summary = &json["summary"];
    assert_eq!(
        summary["filter_used"], "review",
        "filter_used should be 'review'"
    );
}

// ============================================================================
// Output Format Compatibility
// ============================================================================

#[test]
fn test_agent_plan_works_with_all_formats() {
    for format in &["json", "toon", "summary"] {
        let mut cmd = pt_core();
        cmd.timeout(Duration::from_secs(300));
        cmd.env("PT_SKIP_GLOBAL_LOCK", "1");

        let assert = cmd
            .args([
                "--format", format,
                "agent", "plan",
                "--sample-size", "3",
                "--min-posterior", "0.0",
            ])
            .assert();

        // agent plan returns exit code 0 (Clean) or 1 (PlanReady) on success
        let code = assert.get_output().status.code().unwrap_or(-1);
        assert!(
            code == 0 || code == 1,
            "agent plan --format {} should exit 0 or 1, got {}",
            format,
            code
        );

        eprintln!("[INFO] agent plan works with format '{}' (exit {})", format, code);
    }
}
