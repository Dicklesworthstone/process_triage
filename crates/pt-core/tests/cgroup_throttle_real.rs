//! Integration tests for cgroup CPU throttle action.
//!
//! These tests require:
//! - Linux with cgroup v2 support
//! - PT_TEST_CGROUP_PARENT: a preexisting writable delegated parent whose CPU
//!   controller is already enabled; only new owned leaves are mutated.
//!
//! Without that prerequisite the live capability is explicitly unavailable.

#![cfg(all(feature = "test-utils", target_os = "linux"))]

use pt_common::{IdentityQuality, ProcessId, ProcessIdentity, StartId};
use pt_core::action::executor::ActionRunner;
use pt_core::action::{
    can_throttle_process, CpuThrottleActionRunner, CpuThrottleConfig, DEFAULT_PERIOD_US,
    DEFAULT_THROTTLE_FRACTION, MIN_QUOTA_US,
};
use pt_core::collect::cgroup::{collect_cgroup_details, CgroupVersion};
use pt_core::decision::Action as PlanActionType;
use pt_core::plan::{ActionConfidence, ActionRationale, ActionRouting, ActionTimeouts, PlanAction};
use pt_core::test_utils::OwnedCgroupFixture;
use std::fs;
use std::time::Duration;

fn empty_rationale() -> ActionRationale {
    ActionRationale {
        expected_loss: None,
        expected_recovery: None,
        expected_recovery_stddev: None,
        posterior_odds_abandoned_vs_useful: None,
        sprt_boundary: None,
        posterior: None,
        memory_mb: None,
        has_known_signature: None,
        category: None,
    }
}

// ============================================================================
// Configuration and calculation tests (no cgroup access needed)
// ============================================================================

#[test]
fn test_config_defaults() {
    let config = CpuThrottleConfig::default();
    assert_eq!(config.target_fraction, DEFAULT_THROTTLE_FRACTION);
    assert_eq!(config.period_us, DEFAULT_PERIOD_US);
    assert!(config.fallback_to_v1);
    assert!(config.capture_reversal);
}

#[test]
fn test_config_with_fraction() {
    let config = CpuThrottleConfig::with_fraction(0.5);
    assert_eq!(config.target_fraction, 0.5);
    assert_eq!(config.period_us, DEFAULT_PERIOD_US);
}

#[test]
fn test_quota_calculation_standard() {
    let config = CpuThrottleConfig {
        target_fraction: 0.25,
        period_us: 100_000,
        ..Default::default()
    };
    // 25% of 100ms = 25ms = 25000us
    assert_eq!(config.quota_us(), 25_000);
}

#[test]
fn test_quota_calculation_multiple_cores() {
    let config = CpuThrottleConfig {
        target_fraction: 2.0, // 2 cores
        period_us: 100_000,
        ..Default::default()
    };
    // 200% of 100ms = 200ms = 200000us
    assert_eq!(config.quota_us(), 200_000);
}

#[test]
fn test_quota_minimum_enforced() {
    let config = CpuThrottleConfig {
        target_fraction: 0.000001, // Very small
        period_us: 100_000,
        ..Default::default()
    };
    // Should be clamped to MIN_QUOTA_US
    assert_eq!(config.quota_us(), MIN_QUOTA_US);
}

#[test]
fn test_runner_creation() {
    let runner = CpuThrottleActionRunner::with_defaults();
    // Just verify it can be created
    let _ = runner;
}

// ============================================================================
// Cgroup detection tests (read-only, no write access needed)
// ============================================================================

#[test]
fn test_can_throttle_self() {
    let my_pid = std::process::id();
    let result = can_throttle_process(my_pid);
    // Just verify the function works - result depends on system configuration
    pt_core::test_log!(
        INFO,
        "can_throttle_process check",
        pid = my_pid,
        can_throttle = result
    );
}

#[test]
fn test_collect_cgroup_details_self() {
    let my_pid = std::process::id();
    let details = collect_cgroup_details(my_pid);
    assert!(details.is_some(), "Should be able to read cgroup for self");

    let details = details.unwrap();
    pt_core::test_log!(
        INFO,
        "cgroup details",
        pid = my_pid,
        version = format!("{:?}", details.version).as_str(),
        unified_path = details.unified_path.as_deref().unwrap_or("none")
    );
}

#[test]
fn test_reversal_metadata_capture() {
    let runner = CpuThrottleActionRunner::with_defaults();
    let my_pid = std::process::id();

    let metadata = runner.capture_reversal_metadata(my_pid);
    pt_core::test_log!(
        INFO,
        "reversal metadata capture",
        pid = my_pid,
        has_metadata = metadata.is_some()
    );

    if let Some(meta) = metadata {
        assert_eq!(meta.pid, my_pid);
        assert!(!meta.cgroup_path.is_empty());
        pt_core::test_log!(
            INFO,
            "reversal metadata",
            cgroup_path = meta.cgroup_path.as_str(),
            source = format!("{:?}", meta.source).as_str(),
            previous_quota = format!("{:?}", meta.previous_quota_us).as_str()
        );
    }
}

// ============================================================================
// Live throttle tests (require cgroup write access)
// ============================================================================

#[test]
fn test_throttle_spawned_process() {
    let Some(fixture) = OwnedCgroupFixture::new().expect("safe delegated cgroup setup") else {
        return;
    };
    let pid = fixture.target.pid();

    pt_core::test_log!(INFO, "throttle test starting", pid = pid);

    assert!(
        can_throttle_process(pid),
        "owned exclusive leaf must be throttleable"
    );
    let before = OwnedCgroupFixture::controls(&fixture.leaf);
    let sibling_before = OwnedCgroupFixture::controls(&fixture.sibling_leaf);

    // Capture original state
    let runner = CpuThrottleActionRunner::with_defaults();
    let reversal = runner
        .capture_reversal_metadata(pid)
        .expect("actual reversal metadata");
    pt_core::test_log!(
        INFO,
        "captured reversal metadata",
        pid = pid,
        has_reversal = true
    );

    // Create throttle action
    let action = PlanAction {
        action_id: "test-throttle".to_string(),
        action: PlanActionType::Throttle,
        target: fixture.identity.clone(),
        order: 0,
        stage: 0,
        timeouts: ActionTimeouts::default(),
        pre_checks: vec![],
        rationale: empty_rationale(),
        on_success: vec![],
        on_failure: vec![],
        blocked: false,
        routing: ActionRouting::Direct,
        confidence: ActionConfidence::Normal,
        original_zombie_target: None,
        d_state_diagnostics: None,
    };

    // Execute throttle
    let result = runner.execute(&action);
    assert!(result.is_ok(), "throttle failed: {:?}", result);
    pt_core::test_log!(INFO, "throttle executed successfully", pid = pid);

    // Verify throttle was applied
    std::thread::sleep(Duration::from_millis(50));
    let verify = runner.verify(&action);
    assert!(verify.is_ok(), "throttle verification failed: {:?}", verify);
    pt_core::test_log!(INFO, "throttle verified successfully", pid = pid);

    // Verify CPU limits were changed
    let details = collect_cgroup_details(pid).expect("collect cgroup details");
    let limits = details.cpu_limits.expect("actual CPU limits");
    assert_eq!(limits.quota_us, Some(25_000));
    assert_eq!(limits.period_us, Some(100_000));
    let quota = fs::read_to_string(fixture.leaf.join("cpu.max")).unwrap();
    assert_eq!(quota.trim(), "25000 100000");
    fixture.assert_isolated();
    fixture.record("throttled");
    assert_eq!(
        OwnedCgroupFixture::controls(&fixture.sibling_leaf),
        sibling_before
    );

    // Test reversal
    let restore_result = runner.restore_from_metadata(&reversal);
    assert!(
        restore_result.is_ok(),
        "reversal failed: {:?}",
        restore_result
    );
    fixture.record("restored");
    assert_eq!(OwnedCgroupFixture::controls(&fixture.leaf), before);
    assert_eq!(
        OwnedCgroupFixture::controls(&fixture.sibling_leaf),
        sibling_before
    );
    fixture.assert_isolated();
    pt_core::test_log!(INFO, "reversal successful", pid = pid);
    let mut stale_reversal = reversal.clone();
    stale_reversal.identity.start_id =
        StartId(format!("{}-stale", stale_reversal.identity.start_id.0));
    let result = runner.restore_from_metadata(&stale_reversal);
    assert!(
        matches!(result, Err(pt_core::action::ActionError::IdentityMismatch)),
        "stale reversal admitted: {result:?}"
    );
    fixture.record("stale-reversal-refused");
    assert_eq!(OwnedCgroupFixture::controls(&fixture.leaf), before);
    assert_eq!(
        OwnedCgroupFixture::controls(&fixture.sibling_leaf),
        sibling_before
    );
    fixture.assert_isolated();

    // Actual stale identity and shared membership must leave both owned tasks
    // and both controllers unchanged, rather than becoming successful writes.
    let mut stale = action.clone();
    stale.target.start_id = StartId(format!("{}-stale", stale.target.start_id.0));
    let result = runner.execute(&stale);
    assert!(
        matches!(result, Err(pt_core::action::ActionError::IdentityMismatch)),
        "stale identity admitted: {result:?}"
    );
    fixture.record("stale-refused");
    assert_eq!(OwnedCgroupFixture::controls(&fixture.leaf), before);
    assert_eq!(
        OwnedCgroupFixture::controls(&fixture.sibling_leaf),
        sibling_before
    );
    fixture.assert_isolated();
    let descendant = fixture
        .leaf
        .join(format!("empty-owned-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&descendant).expect("create retained empty owned descendant");
    assert!(fs::read_to_string(descendant.join("cgroup.procs"))
        .unwrap()
        .trim()
        .is_empty());
    let result = runner.execute(&action);
    assert!(
        result
            .as_ref()
            .is_err_and(|error| error.to_string().contains("descendants")),
        "nonleaf cgroup admitted: {result:?}"
    );
    assert!(!can_throttle_process(pid));
    fixture.record("descendant-refused");
    assert_eq!(OwnedCgroupFixture::controls(&fixture.leaf), before);
    assert_eq!(
        OwnedCgroupFixture::controls(&fixture.sibling_leaf),
        sibling_before
    );
    fixture.assert_alive();
    fs::write(
        fixture.leaf.join("cgroup.procs"),
        fixture.sibling.pid().to_string(),
    )
    .expect("move only owned sibling into owned leaf");
    let mut members: Vec<u32> = fs::read_to_string(fixture.leaf.join("cgroup.procs"))
        .unwrap()
        .lines()
        .map(|line| line.parse().unwrap())
        .collect();
    members.sort_unstable();
    let mut expected = vec![pid, fixture.sibling.pid()];
    expected.sort_unstable();
    assert_eq!(members, expected);
    let result = runner.execute(&action);
    assert!(
        result
            .as_ref()
            .is_err_and(|error| error.to_string().contains("shared")),
        "shared cgroup admitted: {result:?}"
    );
    assert!(!can_throttle_process(pid));
    fixture.record("shared-refused");
    assert_eq!(OwnedCgroupFixture::controls(&fixture.leaf), before);
    assert_eq!(
        OwnedCgroupFixture::controls(&fixture.sibling_leaf),
        sibling_before
    );
    fixture.assert_alive();
}

#[test]
fn test_throttle_permission_denied() {
    // Root privileges cannot override the PID1 guard. Observe its existing
    // controls before and after; this test must never restore an unknown quota.
    let init_pid = 1u32;

    let runner = CpuThrottleActionRunner::with_defaults();
    let path = collect_cgroup_details(init_pid)
        .expect("actual init cgroup")
        .unified_path
        .expect("actual init unified path");
    let directory = std::path::Path::new("/sys/fs/cgroup").join(path.trim_start_matches('/'));
    let controls = || {
        ["cpu.max", "cgroup.freeze"]
            .into_iter()
            .map(|name| {
                let bytes = match fs::read(directory.join(name)) {
                    Ok(bytes) => Some(bytes),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                    Err(error) => panic!("cannot observe existing init {name}: {error}"),
                };
                (name.to_string(), bytes)
            })
            .collect::<Vec<_>>()
    };
    let before = controls();
    let artifacts =
        std::env::temp_dir().join(format!("pt-cgroup-init-refusal-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&artifacts).expect("retain init refusal observations");
    eprintln!(
        "Retained protected init observations: {}",
        artifacts.display()
    );
    for (name, bytes) in &before {
        if let Some(bytes) = bytes {
            fs::write(artifacts.join(format!("before-{name}")), bytes).unwrap();
        }
    }
    fs::write(
        artifacts.join("before-observation.json"),
        serde_json::to_vec_pretty(&before).unwrap(),
    )
    .unwrap();

    let action = PlanAction {
        action_id: "test-throttle-init".to_string(),
        action: PlanActionType::Throttle,
        target: OwnedCgroupFixture::read_identity(init_pid).expect("actual init identity"),
        order: 0,
        stage: 0,
        timeouts: ActionTimeouts::default(),
        pre_checks: vec![],
        rationale: empty_rationale(),
        on_success: vec![],
        on_failure: vec![],
        blocked: false,
        routing: ActionRouting::Direct,
        confidence: ActionConfidence::Normal,
        original_zombie_target: None,
        d_state_diagnostics: None,
    };

    // This should fail (either permission denied or protected)
    let result = runner.execute(&action);
    pt_core::test_log!(
        INFO,
        "throttle init result",
        error = format!("{:?}", result).as_str()
    );

    // We expect this to fail - either permission denied or process not found
    assert!(result.is_err(), "throttling init should fail");
    assert!(result.unwrap_err().to_string().contains("protected PID 1"));
    assert!(!can_throttle_process(init_pid));
    assert_eq!(controls(), before);
    let mut freeze = action.clone();
    let freezer = pt_core::action::FreezeActionRunner::with_defaults();
    for action_type in [PlanActionType::Freeze, PlanActionType::Unfreeze] {
        freeze.action = action_type;
        let result = freezer.execute(&freeze);
        assert!(
            result
                .as_ref()
                .is_err_and(|error| error.to_string().contains("protected PID 1")),
            "protected freezer mutation admitted: {result:?}"
        );
        assert_eq!(controls(), before);
    }
    for (name, bytes) in controls() {
        if let Some(bytes) = bytes {
            fs::write(artifacts.join(format!("after-{name}")), bytes).unwrap();
        }
    }
    fs::write(
        artifacts.join("after-observation.json"),
        serde_json::to_vec_pretty(&controls()).unwrap(),
    )
    .unwrap();
    fs::write(
        artifacts.join("identity.json"),
        serde_json::to_vec_pretty(&action.target).unwrap(),
    )
    .unwrap();
}

#[test]
fn test_throttle_nonexistent_process() {
    let runner = CpuThrottleActionRunner::with_defaults();

    let action = PlanAction {
        action_id: "test-throttle-nonexistent".to_string(),
        action: PlanActionType::Throttle,
        target: ProcessIdentity {
            pid: ProcessId(999_999_999),
            start_id: StartId("mock".to_string()),
            uid: 1000,
            pgid: None,
            sid: None,
            quality: IdentityQuality::Full,
        },
        order: 0,
        stage: 0,
        timeouts: ActionTimeouts::default(),
        pre_checks: vec![],
        rationale: empty_rationale(),
        on_success: vec![],
        on_failure: vec![],
        blocked: false,
        routing: ActionRouting::Direct,
        confidence: ActionConfidence::Normal,
        original_zombie_target: None,
        d_state_diagnostics: None,
    };

    let result = runner.execute(&action);
    assert!(
        result.is_err(),
        "throttling nonexistent process should fail"
    );
    pt_core::test_log!(
        INFO,
        "throttle nonexistent result",
        error = format!("{:?}", result).as_str()
    );
}

#[test]
fn test_throttle_wrong_action_type() {
    let runner = CpuThrottleActionRunner::with_defaults();

    // Try to use throttle runner for a Kill action
    let action = PlanAction {
        action_id: "test-wrong-action".to_string(),
        action: PlanActionType::Kill, // Wrong action type
        target: ProcessIdentity {
            pid: ProcessId(std::process::id()),
            start_id: StartId("mock".to_string()),
            uid: 1000,
            pgid: None,
            sid: None,
            quality: IdentityQuality::Full,
        },
        order: 0,
        stage: 0,
        timeouts: ActionTimeouts::default(),
        pre_checks: vec![],
        rationale: empty_rationale(),
        on_success: vec![],
        on_failure: vec![],
        blocked: false,
        routing: ActionRouting::Direct,
        confidence: ActionConfidence::Normal,
        original_zombie_target: None,
        d_state_diagnostics: None,
    };

    let result = runner.execute(&action);
    assert!(
        result.is_err(),
        "kill action on throttle runner should fail"
    );
}

#[test]
fn test_throttle_keep_action_noop() {
    let runner = CpuThrottleActionRunner::with_defaults();

    // Keep action should be a no-op
    let action = PlanAction {
        action_id: "test-keep".to_string(),
        action: PlanActionType::Keep,
        target: ProcessIdentity {
            pid: ProcessId(std::process::id()),
            start_id: StartId("mock".to_string()),
            uid: 1000,
            pgid: None,
            sid: None,
            quality: IdentityQuality::Full,
        },
        order: 0,
        stage: 0,
        timeouts: ActionTimeouts::default(),
        pre_checks: vec![],
        rationale: empty_rationale(),
        on_success: vec![],
        on_failure: vec![],
        blocked: false,
        routing: ActionRouting::Direct,
        confidence: ActionConfidence::Normal,
        original_zombie_target: None,
        d_state_diagnostics: None,
    };

    let result = runner.execute(&action);
    assert!(result.is_ok(), "Keep action should succeed as no-op");
}

// ============================================================================
// Cgroup version detection tests
// ============================================================================

#[test]
fn test_cgroup_version_detection() {
    let my_pid = std::process::id();
    let details = collect_cgroup_details(my_pid);

    if let Some(details) = details {
        pt_core::test_log!(
            INFO,
            "cgroup version",
            version = format!("{:?}", details.version).as_str()
        );

        match details.version {
            CgroupVersion::V2 => {
                assert!(
                    details.unified_path.is_some(),
                    "v2 should have unified path"
                );
            }
            CgroupVersion::V1 => {
                assert!(
                    !details.v1_paths.is_empty(),
                    "v1 should have controller paths"
                );
            }
            CgroupVersion::Hybrid => {
                assert!(
                    details.unified_path.is_some() || !details.v1_paths.is_empty(),
                    "hybrid should have some paths"
                );
            }
            CgroupVersion::Unknown => {
                // This is valid on some systems
            }
        }
    }
}
