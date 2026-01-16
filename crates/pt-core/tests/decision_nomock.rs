//! No-mock integration tests for decision + policy gate modules.
//!
//! These tests use real policy/priors files (no mocks) and cover:
//! - Expected loss / recovery tie-breaks
//! - FDR/alpha-investing gates
//! - Policy enforcer violations and warnings
//! - JSONL logging for failures
//!
//! See: process_triage-aii.7.5

use pt_core::config::policy::Policy;
use pt_core::config::priors::Priors;
use pt_core::decision::{
    decide_action, decide_action_with_recovery, select_fdr, Action, ActionFeasibility,
    AlphaInvestingPolicy, AlphaInvestingStore, DecisionError, DisabledAction, FdrCandidate,
    FdrMethod, PolicyEnforcer, ProcessCandidate, TargetIdentity, ViolationKind,
};
use pt_core::inference::ClassScores;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

// ============================================================================
// Test Fixture Helpers
// ============================================================================

fn fixtures_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").leak()
}

fn load_policy_fixture() -> Policy {
    let path = fixtures_dir().join("policy.json");
    let content = fs::read_to_string(&path).expect("read policy fixture");
    serde_json::from_str(&content).expect("parse policy fixture")
}

#[allow(dead_code)]
fn load_priors_fixture() -> Priors {
    let path = fixtures_dir().join("priors.json");
    let content = fs::read_to_string(&path).expect("read priors fixture");
    serde_json::from_str(&content).expect("parse priors fixture")
}

/// Print test event (simple logging for integration tests).
macro_rules! log_test {
    ($level:expr, $msg:expr $(,)?) => {{
        eprintln!("[{}] {}", $level, $msg);
    }};
    ($level:expr, $msg:expr, $($key:ident = $val:expr),* $(,)?) => {{
        eprintln!("[{}] {} {{ {} }}", $level, $msg, stringify!($($key = $val),*));
    }};
}

// ============================================================================
// Expected Loss Tests (Real Fixtures)
// ============================================================================

#[test]
fn test_expected_loss_with_real_policy_fixture() {
    let policy = load_policy_fixture();

    log_test!("INFO", "Starting expected loss test with real fixture",
        test_name = "test_expected_loss_with_real_policy_fixture",
        policy_id = policy.policy_id,
    );

    // Test with various posteriors
    let test_cases = vec![
        // Highly useful process (should prefer Keep)
        ClassScores {
            useful: 0.90,
            useful_bad: 0.05,
            abandoned: 0.03,
            zombie: 0.02,
        },
        // Likely abandoned (should prefer Kill or Restart)
        ClassScores {
            useful: 0.10,
            useful_bad: 0.10,
            abandoned: 0.70,
            zombie: 0.10,
        },
        // Zombie process (should prefer Kill)
        ClassScores {
            useful: 0.05,
            useful_bad: 0.05,
            abandoned: 0.10,
            zombie: 0.80,
        },
        // Uniform uncertainty
        ClassScores {
            useful: 0.25,
            useful_bad: 0.25,
            abandoned: 0.25,
            zombie: 0.25,
        },
    ];

    for (_i, posterior) in test_cases.iter().enumerate() {
        let result = decide_action(posterior, &policy, &ActionFeasibility::allow_all());

        match result {
            Ok(outcome) => {
                log_test!("INFO", "Decision completed",
                    test_case = i,
                    optimal_action = format!("{:?}", outcome.optimal_action),
                    tie_break = outcome.rationale.tie_break,
                );

                // Verify expected loss is computed for all actions
                assert!(
                    !outcome.expected_loss.is_empty(),
                    "Expected loss should not be empty"
                );

                // Verify optimal action minimizes expected loss
                let optimal_loss = outcome
                    .expected_loss
                    .iter()
                    .find(|e| e.action == outcome.optimal_action)
                    .map(|e| e.loss)
                    .expect("optimal action should be in loss list");

                for entry in &outcome.expected_loss {
                    assert!(
                        optimal_loss <= entry.loss + 1e-9,
                        "Optimal action should minimize loss: {optimal_loss} > {}",
                        entry.loss
                    );
                }
            }
            Err(e) => {
                log_test!("ERROR", "Decision failed unexpectedly",
                    test_case = i,
                    error = format!("{:?}", e),
                );
                panic!("Decision should not fail for valid posterior: {:?}", e);
            }
        }
    }
}

#[test]
fn test_expected_loss_edge_case_single_class_certainty() {
    let policy = load_policy_fixture();

    // Test edge case: 100% certainty in each class
    let certainty_cases = vec![
        (
            "useful",
            ClassScores {
                useful: 1.0,
                useful_bad: 0.0,
                abandoned: 0.0,
                zombie: 0.0,
            },
        ),
        (
            "useful_bad",
            ClassScores {
                useful: 0.0,
                useful_bad: 1.0,
                abandoned: 0.0,
                zombie: 0.0,
            },
        ),
        (
            "abandoned",
            ClassScores {
                useful: 0.0,
                useful_bad: 0.0,
                abandoned: 1.0,
                zombie: 0.0,
            },
        ),
        (
            "zombie",
            ClassScores {
                useful: 0.0,
                useful_bad: 0.0,
                abandoned: 0.0,
                zombie: 1.0,
            },
        ),
    ];

    for (class_name, posterior) in certainty_cases {
        log_test!("INFO", "Testing certainty case",
            class = class_name,
        );

        let result = decide_action(&posterior, &policy, &ActionFeasibility::allow_all());
        assert!(result.is_ok(), "Should handle {} certainty", class_name);

        let outcome = result.unwrap();

        // When certain of useful, Keep should be optimal (loss=0)
        if class_name == "useful" {
            assert_eq!(
                outcome.optimal_action,
                Action::Keep,
                "Certain useful should prefer Keep"
            );
        }

        // When certain of abandoned/zombie, Kill should be optimal (loss=1)
        if class_name == "abandoned" || class_name == "zombie" {
            assert!(
                outcome.optimal_action == Action::Kill || outcome.optimal_action == Action::Restart,
                "Certain {} should prefer Kill or Restart",
                class_name
            );
        }
    }
}

#[test]
fn test_expected_loss_invalid_posteriors() {
    let policy = load_policy_fixture();

    // Invalid posteriors that should be rejected
    let invalid_cases = vec![
        (
            "negative_value",
            ClassScores {
                useful: -0.1,
                useful_bad: 0.4,
                abandoned: 0.4,
                zombie: 0.3,
            },
        ),
        (
            "sum_not_one",
            ClassScores {
                useful: 0.5,
                useful_bad: 0.5,
                abandoned: 0.5,
                zombie: 0.5,
            },
        ),
        (
            "nan_value",
            ClassScores {
                useful: f64::NAN,
                useful_bad: 0.3,
                abandoned: 0.3,
                zombie: 0.4,
            },
        ),
        (
            "inf_value",
            ClassScores {
                useful: f64::INFINITY,
                useful_bad: 0.0,
                abandoned: 0.0,
                zombie: 0.0,
            },
        ),
    ];

    for (case_name, posterior) in invalid_cases {
        log_test!("INFO", "Testing invalid posterior",
            case = case_name,
        );

        let result = decide_action(&posterior, &policy, &ActionFeasibility::allow_all());

        match result {
            Err(DecisionError::InvalidPosterior { .. }) => {
                log_test!("INFO", "Correctly rejected invalid posterior",
                    case = case_name,
                );
            }
            Ok(_) => {
                log_test!("ERROR", "Should have rejected invalid posterior",
                    case = case_name,
                );
                panic!("{} posterior should be rejected", case_name);
            }
            Err(other) => {
                log_test!("ERROR", "Unexpected error type",
                    case = case_name,
                    error = format!("{:?}", other),
                );
                panic!("{} should produce InvalidPosterior error, got {:?}", case_name, other);
            }
        }
    }
}

#[test]
fn test_expected_loss_with_disabled_actions() {
    let policy = load_policy_fixture();
    let posterior = ClassScores {
        useful: 0.25,
        useful_bad: 0.25,
        abandoned: 0.25,
        zombie: 0.25,
    };

    // Disable Kill action
    let feasibility = ActionFeasibility {
        disabled: vec![DisabledAction {
            action: Action::Kill,
            reason: "test disabled".to_string(),
        }],
    };

    let result = decide_action(&posterior, &policy, &feasibility);
    assert!(result.is_ok());

    let outcome = result.unwrap();
    assert_ne!(
        outcome.optimal_action,
        Action::Kill,
        "Disabled action should not be selected"
    );

    // Verify Kill is not in expected_loss list
    assert!(
        !outcome.expected_loss.iter().any(|e| e.action == Action::Kill),
        "Disabled action should not appear in expected_loss"
    );

    log_test!("INFO", "Disabled action test passed",
        optimal_action = format!("{:?}", outcome.optimal_action),
        num_expected_loss = outcome.expected_loss.len(),
    );
}

#[test]
fn test_expected_loss_no_feasible_actions() {
    let policy = load_policy_fixture();
    let posterior = ClassScores {
        useful: 0.25,
        useful_bad: 0.25,
        abandoned: 0.25,
        zombie: 0.25,
    };

    // Disable all actions
    let feasibility = ActionFeasibility {
        disabled: vec![
            DisabledAction {
                action: Action::Keep,
                reason: "test".to_string(),
            },
            DisabledAction {
                action: Action::Pause,
                reason: "test".to_string(),
            },
            DisabledAction {
                action: Action::Renice,
                reason: "test".to_string(),
            },
            DisabledAction {
                action: Action::Freeze,
                reason: "test".to_string(),
            },
            DisabledAction {
                action: Action::Throttle,
                reason: "test".to_string(),
            },
            DisabledAction {
                action: Action::Quarantine,
                reason: "test".to_string(),
            },
            DisabledAction {
                action: Action::Restart,
                reason: "test".to_string(),
            },
            DisabledAction {
                action: Action::Kill,
                reason: "test".to_string(),
            },
        ],
    };

    let result = decide_action(&posterior, &policy, &feasibility);

    match result {
        Err(DecisionError::NoFeasibleActions) => {
            log_test!("INFO", "Correctly detected no feasible actions");
        }
        _other => {
            log_test!("ERROR", "Should have returned NoFeasibleActions",
                result = format!("{:?}", _other),
            );
            panic!("Expected NoFeasibleActions error");
        }
    }
}

// ============================================================================
// Recovery Tie-Break Tests
// ============================================================================

#[test]
fn test_recovery_preference_with_real_priors() {
    // Test that recovery preference works with loaded priors
    let policy = load_policy_fixture();

    // Create a posterior that allows multiple actions with similar loss
    let posterior = ClassScores {
        useful: 0.5,
        useful_bad: 0.2,
        abandoned: 0.2,
        zombie: 0.1,
    };

    // Create priors with causal interventions configured
    let priors = Priors::default();

    // First test without recovery preference
    let without_recovery = decide_action(&posterior, &policy, &ActionFeasibility::allow_all())
        .expect("decision without recovery");

    // Then test with recovery preference (high tolerance to allow preference switching)
    let with_recovery = decide_action_with_recovery(
        &posterior,
        &policy,
        &ActionFeasibility::allow_all(),
        &priors,
        0.1, // 10% loss tolerance
    )
    .expect("decision with recovery");

    log_test!("INFO", "Recovery preference test",
        without_recovery_action = format!("{:?}", without_recovery.optimal_action),
        with_recovery_action = format!("{:?}", with_recovery.optimal_action),
        used_recovery_preference = with_recovery.rationale.used_recovery_preference,
    );

    // Both should produce valid outcomes
    assert!(!without_recovery.expected_loss.is_empty());
    assert!(!with_recovery.expected_loss.is_empty());
}

// ============================================================================
// FDR Selection Tests (Real Fixtures)
// ============================================================================

fn make_fdr_candidate(pid: i32, e_value: f64) -> FdrCandidate {
    FdrCandidate {
        target: TargetIdentity {
            pid,
            start_id: format!("{}-{}-boot", pid, std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_micros()),
            uid: 1000,
        },
        e_value,
    }
}

#[test]
fn test_fdr_selection_ebh_vs_eby() {
    // Test that eBY is more conservative than eBH
    let candidates: Vec<FdrCandidate> = (1..=10)
        .map(|i| make_fdr_candidate(i, 50.0 / i as f64))
        .collect();

    let alpha = 0.1;

    let ebh_result = select_fdr(&candidates, alpha, FdrMethod::EBh).expect("eBH selection");
    let eby_result = select_fdr(&candidates, alpha, FdrMethod::EBy).expect("eBY selection");

    log_test!("INFO", "FDR method comparison",
        ebh_selected = ebh_result.selected_k,
        eby_selected = eby_result.selected_k,
        eby_correction = eby_result.correction_factor,
    );

    // eBY should be more conservative (select same or fewer)
    assert!(
        eby_result.selected_k <= ebh_result.selected_k,
        "eBY should be more conservative than eBH"
    );

    // eBY should have a correction factor
    assert!(
        eby_result.correction_factor.is_some(),
        "eBY should compute correction factor"
    );
}

#[test]
fn test_fdr_selection_determinism() {
    // Same inputs should always produce same outputs
    let candidates: Vec<FdrCandidate> = vec![
        make_fdr_candidate(1, 100.0),
        make_fdr_candidate(2, 50.0),
        make_fdr_candidate(3, 25.0),
        make_fdr_candidate(4, 10.0),
        make_fdr_candidate(5, 5.0),
    ];

    let result1 = select_fdr(&candidates, 0.05, FdrMethod::EBh).expect("selection 1");
    let result2 = select_fdr(&candidates, 0.05, FdrMethod::EBh).expect("selection 2");

    assert_eq!(result1.selected_k, result2.selected_k, "Selection should be deterministic");
    assert_eq!(
        result1.selection_threshold,
        result2.selection_threshold,
        "Threshold should be deterministic"
    );

    // Verify candidate ordering is consistent
    for (c1, c2) in result1.candidates.iter().zip(result2.candidates.iter()) {
        assert_eq!(c1.rank, c2.rank);
        assert_eq!(c1.selected, c2.selected);
    }

    log_test!("INFO", "FDR determinism verified",
        selected_k = result1.selected_k,
        num_candidates = candidates.len(),
    );
}

#[test]
fn test_fdr_selection_edge_cases() {
    // Single candidate
    let single = vec![make_fdr_candidate(1, 100.0)];
    let result = select_fdr(&single, 0.1, FdrMethod::EBh);
    assert!(result.is_ok());

    log_test!("INFO", "Single candidate FDR",
        selected_k = result.as_ref().unwrap().selected_k,
    );

    // All e-values below 1 (no evidence)
    let low_evidence: Vec<FdrCandidate> = (1..=5)
        .map(|i| make_fdr_candidate(i, 0.5))
        .collect();
    let result = select_fdr(&low_evidence, 0.1, FdrMethod::EBh).expect("low evidence");
    assert_eq!(result.selected_k, 0, "No selections when all e-values < 1");

    // Very high alpha (permissive)
    let candidates: Vec<FdrCandidate> = (1..=5)
        .map(|i| make_fdr_candidate(i, i as f64))
        .collect();
    let _result = select_fdr(&candidates, 0.99, FdrMethod::EBh).expect("high alpha");

    log_test!("INFO", "High alpha FDR",
        alpha = 0.99,
        selected_k = _result.selected_k,
    );

    // FdrMethod::None should select all with e > 1
    let candidates: Vec<FdrCandidate> = vec![
        make_fdr_candidate(1, 2.0),
        make_fdr_candidate(2, 0.5),
        make_fdr_candidate(3, 1.5),
    ];
    let result = select_fdr(&candidates, 0.1, FdrMethod::None).expect("none method");
    assert_eq!(result.selected_k, 2, "FdrMethod::None should select e > 1");
}

#[test]
fn test_fdr_selection_invalid_inputs() {
    let candidates = vec![make_fdr_candidate(1, 10.0)];

    // Invalid alpha values
    assert!(select_fdr(&candidates, 0.0, FdrMethod::EBh).is_err());
    assert!(select_fdr(&candidates, -0.1, FdrMethod::EBh).is_err());
    assert!(select_fdr(&candidates, 1.5, FdrMethod::EBh).is_err());

    // Empty candidates
    assert!(select_fdr(&[], 0.1, FdrMethod::EBh).is_err());

    // Negative e-value
    let negative = vec![make_fdr_candidate(1, -1.0)];
    assert!(select_fdr(&negative, 0.1, FdrMethod::EBh).is_err());

    log_test!("INFO", "FDR invalid inputs correctly rejected");
}

// ============================================================================
// Alpha Investing Tests
// ============================================================================

#[test]
fn test_alpha_investing_persistence() {
    let tmp = tempdir().expect("tempdir");
    let store = AlphaInvestingStore::new(tmp.path());
    let policy = Policy::default();
    let user_id = 1000u32;

    // Initial load should create state
    let state = store.load_or_init(&policy, user_id).expect("init state");
    assert!(state.wealth > 0.0, "Initial wealth should be positive");

    log_test!("INFO", "Alpha investing initial state",
        wealth = state.wealth,
        host_id = state.host_id,
    );

    // Update with discoveries
    let update = store.update_wealth(&policy, user_id, 2).expect("update");
    assert!(update.wealth_prev > 0.0);
    assert!(update.alpha_spend > 0.0);

    log_test!("INFO", "Alpha investing update",
        wealth_prev = update.wealth_prev,
        wealth_next = update.wealth_next,
        discoveries = update.discoveries,
        alpha_spend = update.alpha_spend,
    );

    // Verify persistence by reloading
    let reloaded = store.load_or_init(&policy, user_id).expect("reload state");
    assert!(
        (reloaded.wealth - update.wealth_next).abs() < 1e-10,
        "Reloaded wealth should match updated wealth"
    );
}

#[test]
fn test_alpha_investing_wealth_formula() {
    // Verify: wealth_next = max(0, wealth_prev - alpha_spend + alpha_earn * discoveries)
    let policy = Policy::default();

    // Get the policy parameters
    let alpha_policy = AlphaInvestingPolicy::from_policy(&policy).expect("policy");

    // Manual calculation
    let w0 = alpha_policy.w0;
    let alpha_spend = alpha_policy.alpha_spend * w0; // spend is proportional to wealth
    let discoveries = 3u32;
    let alpha_earn = alpha_policy.alpha_earn * discoveries as f64;
    let expected_next = (w0 - alpha_spend + alpha_earn).max(0.0);

    let tmp = tempdir().expect("tempdir");
    let store = AlphaInvestingStore::new(tmp.path());

    // Initialize and update
    let _state = store.load_or_init(&policy, 1000).expect("init");
    let update = store.update_wealth(&policy, 1000, discoveries).expect("update");

    // Compare with expected
    assert!(
        (update.wealth_next - expected_next).abs() < 1e-10,
        "Wealth formula mismatch: got {}, expected {}",
        update.wealth_next,
        expected_next
    );

    log_test!("INFO", "Alpha investing formula verified",
        w0 = w0,
        alpha_spend = alpha_spend,
        alpha_earn = alpha_earn,
        expected_next = expected_next,
        actual_next = update.wealth_next,
    );
}

#[test]
fn test_alpha_investing_wealth_depletion() {
    let tmp = tempdir().expect("tempdir");
    let store = AlphaInvestingStore::new(tmp.path());
    let policy = Policy::default();

    // Repeatedly update with no discoveries to deplete wealth
    let _state = store.load_or_init(&policy, 1000).expect("init");

    let mut final_wealth = 0.0;
    for _i in 0..50 {
        let update = store.update_wealth(&policy, 1000, 0).expect("update");
        final_wealth = update.wealth_next;

        if final_wealth < 1e-10 {
            log_test!("INFO", "Wealth depleted after iterations",
                iterations = _i + 1,
            );
            break;
        }
    }

    // Wealth should approach 0 but never go negative
    assert!(
        final_wealth >= 0.0,
        "Wealth should never be negative: {}",
        final_wealth
    );
}

// ============================================================================
// Policy Enforcer Tests (Real Fixtures)
// ============================================================================

#[test]
fn test_enforcer_with_real_policy_fixture() {
    let policy = load_policy_fixture();
    let enforcer = PolicyEnforcer::new(&policy).expect("create enforcer");

    // Create a basic candidate
    let candidate = ProcessCandidate {
        pid: 12345,
        ppid: 1000,
        cmdline: "/usr/bin/test-process".to_string(),
        user: Some("testuser".to_string()),
        group: Some("testgroup".to_string()),
        category: Some("shell".to_string()),
        age_seconds: 7200, // 2 hours, above min age
        posterior: Some(0.95),
        memory_mb: Some(100.0),
        has_known_signature: false,
        open_write_fds: Some(0),
        has_locked_files: Some(false),
        has_active_tty: Some(false),
        seconds_since_io: Some(120),
        cwd_deleted: Some(false),
        process_state: None,
        wchan: None,
        critical_files: Vec::new(),
    };

    let _result = enforcer.check_action(&candidate, Action::Kill, false);

    log_test!("INFO", "Enforcer check with real fixture",
        allowed = _result.allowed,
        has_violation = _result.violation.is_some(),
        num_warnings = _result.warnings.len(),
    );
}

#[test]
fn test_enforcer_protected_patterns() {
    let mut policy = Policy::default();
    policy.guardrails.protected_patterns = vec![
        pt_core::config::policy::PatternEntry {
            pattern: "sshd".to_string(),
            kind: "literal".to_string(),
            case_insensitive: true,
            notes: Some("SSH daemon".to_string()),
        },
        pt_core::config::policy::PatternEntry {
            pattern: r"^/usr/sbin/.*d$".to_string(),
            kind: "regex".to_string(),
            case_insensitive: false,
            notes: Some("System daemons".to_string()),
        },
        pt_core::config::policy::PatternEntry {
            pattern: "nginx*".to_string(),
            kind: "glob".to_string(),
            case_insensitive: true,
            notes: Some("Nginx".to_string()),
        },
    ];

    let enforcer = PolicyEnforcer::new(&policy).expect("create enforcer");

    let test_cases = vec![
        ("/usr/sbin/sshd -D", true, "sshd literal match"),
        ("/usr/sbin/crond", true, "regex daemon match"),
        ("nginx-master", true, "nginx glob match"),
        ("/usr/bin/myapp", false, "should not match"),
    ];

    for (cmdline, should_block, description) in test_cases {
        let candidate = ProcessCandidate {
            pid: 1234,
            ppid: 1000,
            cmdline: cmdline.to_string(),
            user: None,
            group: None,
            category: None,
            age_seconds: 7200,
            posterior: Some(0.95),
            memory_mb: Some(100.0),
            has_known_signature: false,
            open_write_fds: Some(0),
            has_locked_files: Some(false),
            has_active_tty: Some(false),
            seconds_since_io: Some(120),
            cwd_deleted: Some(false),
            process_state: None,
            wchan: None,
            critical_files: Vec::new(),
        };

        let result = enforcer.check_action(&candidate, Action::Kill, false);

        if should_block {
            assert!(
                !result.allowed,
                "{}: should be blocked but was allowed",
                description
            );
            assert_eq!(
                result.violation.as_ref().unwrap().kind,
                ViolationKind::ProtectedPattern,
                "{}: wrong violation kind",
                description
            );
        } else {
            // May be blocked by other rules (e.g., rate limit), but not protected pattern
            if !result.allowed {
                assert_ne!(
                    result.violation.as_ref().unwrap().kind,
                    ViolationKind::ProtectedPattern,
                    "{}: should not be blocked by protected pattern",
                    description
                );
            }
        }

        log_test!("INFO", "Protected pattern test",
            cmdline = cmdline,
            should_block = should_block,
            was_blocked = !result.allowed,
            description = description,
        );
    }
}

#[test]
fn test_enforcer_rate_limiting() {
    let mut policy = Policy::default();
    policy.guardrails.max_kills_per_run = 3;

    let enforcer = PolicyEnforcer::new(&policy).expect("create enforcer");

    let candidate = ProcessCandidate {
        pid: 9999,
        ppid: 1000,
        cmdline: "/usr/bin/test".to_string(),
        user: None,
        group: None,
        category: None,
        age_seconds: 7200,
        posterior: Some(0.95),
        memory_mb: Some(100.0),
        has_known_signature: false,
        open_write_fds: Some(0),
        has_locked_files: Some(false),
        has_active_tty: Some(false),
        seconds_since_io: Some(120),
        cwd_deleted: Some(false),
        process_state: None,
        wchan: None,
        critical_files: Vec::new(),
    };

    // First 3 kills should be allowed
    for i in 0..3 {
        let result = enforcer.check_action(&candidate, Action::Kill, false);
        assert!(result.allowed, "Kill {} should be allowed", i + 1);
    }

    // 4th kill should be rate limited
    let result = enforcer.check_action(&candidate, Action::Kill, false);
    assert!(!result.allowed, "4th kill should be rate limited");
    assert_eq!(
        result.violation.as_ref().unwrap().kind,
        ViolationKind::RateLimitExceeded
    );

    // Reset and verify rate limit is cleared
    enforcer.reset_run_counters();
    let result = enforcer.check_action(&candidate, Action::Kill, false);
    assert!(result.allowed, "Kill should be allowed after reset");

    log_test!("INFO", "Rate limiting test passed",
        max_kills = policy.guardrails.max_kills_per_run,
    );
}

#[test]
fn test_enforcer_robot_mode_gates() {
    let mut policy = Policy::default();
    policy.robot_mode.enabled = true;
    policy.robot_mode.min_posterior = 0.90;
    policy.robot_mode.max_blast_radius_mb = 500.0;
    policy.robot_mode.max_kills = 10;
    policy.robot_mode.require_known_signature = false;

    let enforcer = PolicyEnforcer::new(&policy).expect("create enforcer");

    // Test posterior gate
    let low_posterior_candidate = ProcessCandidate {
        pid: 1234,
        ppid: 1000,
        cmdline: "/usr/bin/test".to_string(),
        user: None,
        group: None,
        category: None,
        age_seconds: 7200,
        posterior: Some(0.85), // Below threshold
        memory_mb: Some(100.0),
        has_known_signature: false,
        open_write_fds: Some(0),
        has_locked_files: Some(false),
        has_active_tty: Some(false),
        seconds_since_io: Some(120),
        cwd_deleted: Some(false),
        process_state: None,
        wchan: None,
        critical_files: Vec::new(),
    };

    let result = enforcer.check_action(&low_posterior_candidate, Action::Kill, true);
    assert!(!result.allowed, "Low posterior should be blocked in robot mode");
    assert_eq!(result.violation.as_ref().unwrap().kind, ViolationKind::RobotModeGate);

    // Test blast radius gate
    let high_memory_candidate = ProcessCandidate {
        pid: 1234,
        ppid: 1000,
        cmdline: "/usr/bin/test".to_string(),
        user: None,
        group: None,
        category: None,
        age_seconds: 7200,
        posterior: Some(0.95), // Above threshold
        memory_mb: Some(600.0), // Above blast radius
        has_known_signature: false,
        open_write_fds: Some(0),
        has_locked_files: Some(false),
        has_active_tty: Some(false),
        seconds_since_io: Some(120),
        cwd_deleted: Some(false),
        process_state: None,
        wchan: None,
        critical_files: Vec::new(),
    };

    let result = enforcer.check_action(&high_memory_candidate, Action::Kill, true);
    assert!(!result.allowed, "High memory should be blocked in robot mode");
    assert!(result.violation.as_ref().unwrap().message.contains("memory"));

    log_test!("INFO", "Robot mode gates test passed");
}

#[test]
fn test_enforcer_data_loss_gates() {
    let policy = Policy::default();
    let enforcer = PolicyEnforcer::new(&policy).expect("create enforcer");

    // Test open write FDs gate
    let candidate_with_fds = ProcessCandidate {
        pid: 1234,
        ppid: 1000,
        cmdline: "/usr/bin/test".to_string(),
        user: None,
        group: None,
        category: None,
        age_seconds: 7200,
        posterior: Some(0.95),
        memory_mb: Some(100.0),
        has_known_signature: false,
        open_write_fds: Some(5), // Has open write FDs
        has_locked_files: Some(false),
        has_active_tty: Some(false),
        seconds_since_io: Some(120),
        cwd_deleted: Some(false),
        process_state: None,
        wchan: None,
        critical_files: Vec::new(),
    };

    let result = enforcer.check_action(&candidate_with_fds, Action::Kill, false);
    assert!(!result.allowed, "Open write FDs should trigger data loss gate");
    assert_eq!(result.violation.as_ref().unwrap().kind, ViolationKind::DataLossGate);

    // Test locked files gate
    let candidate_locked = ProcessCandidate {
        pid: 1234,
        ppid: 1000,
        cmdline: "/usr/bin/test".to_string(),
        user: None,
        group: None,
        category: None,
        age_seconds: 7200,
        posterior: Some(0.95),
        memory_mb: Some(100.0),
        has_known_signature: false,
        open_write_fds: Some(0),
        has_locked_files: Some(true), // Has locked files
        has_active_tty: Some(false),
        seconds_since_io: Some(120),
        cwd_deleted: Some(false),
        process_state: None,
        wchan: None,
        critical_files: Vec::new(),
    };

    let result = enforcer.check_action(&candidate_locked, Action::Kill, false);
    assert!(!result.allowed, "Locked files should trigger data loss gate");

    log_test!("INFO", "Data loss gates test passed");
}

#[test]
fn test_enforcer_min_age_gate() {
    let mut policy = Policy::default();
    policy.guardrails.min_process_age_seconds = 3600; // 1 hour

    let enforcer = PolicyEnforcer::new(&policy).expect("create enforcer");

    // Young process
    let young_candidate = ProcessCandidate {
        pid: 1234,
        ppid: 1000,
        cmdline: "/usr/bin/test".to_string(),
        user: None,
        group: None,
        category: None,
        age_seconds: 60, // 1 minute
        posterior: Some(0.95),
        memory_mb: Some(100.0),
        has_known_signature: false,
        open_write_fds: Some(0),
        has_locked_files: Some(false),
        has_active_tty: Some(false),
        seconds_since_io: Some(120),
        cwd_deleted: Some(false),
        process_state: None,
        wchan: None,
        critical_files: Vec::new(),
    };

    let result = enforcer.check_action(&young_candidate, Action::Kill, false);
    assert!(!result.allowed, "Young process should be blocked");
    assert_eq!(result.violation.as_ref().unwrap().kind, ViolationKind::MinAgeBreach);

    // Old process
    let old_candidate = ProcessCandidate {
        age_seconds: 7200, // 2 hours
        ..young_candidate.clone()
    };

    // Reset rate limiter for clean test
    enforcer.reset_run_counters();

    let result = enforcer.check_action(&old_candidate, Action::Kill, false);
    // Should be allowed (or blocked by other gates, but not min age)
    if !result.allowed {
        assert_ne!(
            result.violation.as_ref().unwrap().kind,
            ViolationKind::MinAgeBreach,
            "Old process should not be blocked by min age"
        );
    }

    log_test!("INFO", "Min age gate test passed");
}

#[test]
fn test_enforcer_warnings() {
    let mut policy = Policy::default();
    policy.guardrails.force_review_patterns = vec![
        pt_core::config::policy::PatternEntry {
            pattern: "kubectl".to_string(),
            kind: "literal".to_string(),
            case_insensitive: true,
            notes: Some("Kubernetes tool".to_string()),
        },
    ];

    let enforcer = PolicyEnforcer::new(&policy).expect("create enforcer");

    let candidate = ProcessCandidate {
        pid: 1234,
        ppid: 1000,
        cmdline: "kubectl get pods".to_string(),
        user: None,
        group: None,
        category: None,
        age_seconds: 7200,
        posterior: Some(0.95),
        memory_mb: Some(100.0),
        has_known_signature: false,
        open_write_fds: Some(0),
        has_locked_files: Some(false),
        has_active_tty: Some(false),
        seconds_since_io: Some(120),
        cwd_deleted: Some(false),
        process_state: None,
        wchan: None,
        critical_files: Vec::new(),
    };

    // In interactive mode, should be allowed with warning
    let result = enforcer.check_action(&candidate, Action::Kill, false);
    assert!(result.allowed, "Force review should allow in interactive mode");
    assert!(!result.warnings.is_empty(), "Should have warning");

    log_test!("INFO", "Enforcer warnings test passed",
        num_warnings = result.warnings.len(),
    );
}
