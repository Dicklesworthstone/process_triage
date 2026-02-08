//! No-mock integration tests for the sliding window rate limiter.
//!
//! These tests exercise rate limiting through both the direct SlidingWindowRateLimiter API
//! and the PolicyEnforcer integration layer, covering:
//!
//! - Multi-window rate limiting (per-run, per-minute, per-hour, per-day)
//! - Warning threshold progression (80% of limit)
//! - Persistence and recovery across sessions
//! - Force override behavior
//! - PolicyEnforcer integration with rate limits
//! - Check-and-record atomicity
//! - Edge cases: zero limits, boundary transitions, state corruption recovery
//!
//! See: process_triage-8z2, process_triage-dvi

use pt_core::config::Policy;
use pt_core::decision::rate_limit::{RateLimitConfig, RateLimitWindow, SlidingWindowRateLimiter};
use pt_core::decision::{Action, PolicyEnforcer, ProcessCandidate, ViolationKind};
use tempfile::tempdir;

// ============================================================================
// Test Helpers
// ============================================================================

/// Build a minimal ProcessCandidate for enforcer tests (not protected, killable).
fn killable_candidate() -> ProcessCandidate {
    ProcessCandidate {
        pid: 9999,
        ppid: 1000,
        cmdline: "/usr/bin/some-test-process --flag".to_string(),
        user: Some("testuser".to_string()),
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
    }
}

/// Build a Policy with specific rate limit settings and minimal protected patterns.
fn policy_with_rate_limits(
    per_run: u32,
    per_minute: Option<u32>,
    per_hour: Option<u32>,
    per_day: Option<u32>,
) -> Policy {
    let mut policy = Policy::default();
    policy.guardrails.max_kills_per_run = per_run;
    policy.guardrails.max_kills_per_minute = per_minute;
    policy.guardrails.max_kills_per_hour = per_hour;
    policy.guardrails.max_kills_per_day = per_day;
    // Clear protected patterns that might interfere with tests
    policy.guardrails.protected_users = Vec::new();
    policy.guardrails.never_kill_ppid = Vec::new();
    policy.guardrails.protected_categories = Vec::new();
    policy.guardrails.min_process_age_seconds = 0;
    policy
}

// ============================================================================
// Direct SlidingWindowRateLimiter Tests
// ============================================================================

mod sliding_window {
    use super::*;

    #[test]
    fn per_run_limit_blocks_at_exact_boundary() {
        let config = RateLimitConfig {
            max_per_run: 3,
            max_per_minute: None,
            max_per_hour: None,
            max_per_day: None,
        };
        let limiter = SlidingWindowRateLimiter::new(config, None::<&str>).unwrap();

        // Record exactly at the limit
        for _ in 0..3 {
            let result = limiter.check(false).unwrap();
            assert!(result.allowed, "Should be allowed before reaching limit");
            limiter.record_kill().unwrap();
        }

        // Next check should be blocked
        let result = limiter.check(false).unwrap();
        assert!(!result.allowed, "Should be blocked at limit");
        assert_eq!(
            result.block_reason.as_ref().unwrap().window,
            RateLimitWindow::Run
        );
        assert_eq!(result.block_reason.as_ref().unwrap().current, 3);
        assert_eq!(result.block_reason.as_ref().unwrap().limit, 3);
    }

    #[test]
    fn per_minute_limit_blocks_before_per_run() {
        let config = RateLimitConfig {
            max_per_run: 100,
            max_per_minute: Some(2),
            max_per_hour: None,
            max_per_day: None,
        };
        let limiter = SlidingWindowRateLimiter::new(config, None::<&str>).unwrap();

        limiter.record_kill().unwrap();
        limiter.record_kill().unwrap();

        let result = limiter.check(false).unwrap();
        assert!(!result.allowed, "Should be blocked by per-minute limit");
        assert_eq!(
            result.block_reason.as_ref().unwrap().window,
            RateLimitWindow::Minute
        );
    }

    #[test]
    fn warning_threshold_fires_at_80_percent() {
        let config = RateLimitConfig {
            max_per_run: 10,
            max_per_minute: None,
            max_per_hour: None,
            max_per_day: None,
        };
        let limiter = SlidingWindowRateLimiter::new(config, None::<&str>).unwrap();

        // Record 7 kills (70%) — no warning
        for _ in 0..7 {
            limiter.record_kill().unwrap();
        }
        let result = limiter.check(false).unwrap();
        assert!(result.allowed);
        assert!(result.warning.is_none(), "70% should not trigger warning");

        // Record 8th kill (80%) — warning
        limiter.record_kill().unwrap();
        let result = limiter.check(false).unwrap();
        assert!(result.allowed, "80% should still allow kills");
        assert!(result.warning.is_some(), "80% should trigger warning");
        let w = result.warning.unwrap();
        assert_eq!(w.window, RateLimitWindow::Run);
        assert_eq!(w.current, 8);
        assert_eq!(w.limit, 10);
        assert!(
            w.percent_used >= 79.0 && w.percent_used <= 81.0,
            "Expected ~80%, got {}",
            w.percent_used
        );
    }

    #[test]
    fn warning_message_includes_window_and_counts() {
        let config = RateLimitConfig {
            max_per_run: 5,
            max_per_minute: None,
            max_per_hour: None,
            max_per_day: None,
        };
        let limiter = SlidingWindowRateLimiter::new(config, None::<&str>).unwrap();

        // 80% of 5 = 4.0, ceil = 4
        for _ in 0..4 {
            limiter.record_kill().unwrap();
        }
        let result = limiter.check(false).unwrap();
        assert!(result.warning.is_some());
        let msg = &result.warning.unwrap().message;
        assert!(
            msg.contains("4/5"),
            "Warning should contain count/limit: {}",
            msg
        );
        assert!(
            msg.contains("run"),
            "Warning should mention window: {}",
            msg
        );
    }

    #[test]
    fn force_override_allows_past_limit() {
        let config = RateLimitConfig {
            max_per_run: 1,
            max_per_minute: None,
            max_per_hour: None,
            max_per_day: None,
        };
        let limiter = SlidingWindowRateLimiter::new(config, None::<&str>).unwrap();

        limiter.record_kill().unwrap();

        // Normal check is blocked
        let result = limiter.check(false).unwrap();
        assert!(!result.allowed);

        // Force override is allowed and flagged
        let result = limiter.check(true).unwrap();
        assert!(result.allowed, "Force override should allow");
        assert!(result.forced, "Should be flagged as forced");
    }

    #[test]
    fn force_override_still_reports_block_details() {
        let config = RateLimitConfig {
            max_per_run: 1,
            max_per_minute: None,
            max_per_hour: None,
            max_per_day: None,
        };
        let limiter = SlidingWindowRateLimiter::new(config, None::<&str>).unwrap();

        limiter.record_kill().unwrap();

        let result = limiter.check(true).unwrap();
        assert!(result.allowed);
        assert!(result.forced);
        // block_reason is cleared when allowed
        assert!(
            result.block_reason.is_none(),
            "block_reason should be None when allowed"
        );
    }

    #[test]
    fn check_and_record_is_atomic() {
        let config = RateLimitConfig {
            max_per_run: 3,
            max_per_minute: None,
            max_per_hour: None,
            max_per_day: None,
        };
        let limiter = SlidingWindowRateLimiter::new(config, None::<&str>).unwrap();

        // Atomic check-and-record: should be allowed
        let result = limiter.check_and_record(false, None).unwrap();
        assert!(result.allowed);
        // Count at check time is 0 (not yet incremented)
        assert_eq!(result.counts.run, 0);

        // After atomic op, count should be 1
        assert_eq!(limiter.current_run_count().unwrap(), 1);

        // Two more atomic ops
        let _ = limiter.check_and_record(false, None).unwrap();
        let _ = limiter.check_and_record(false, None).unwrap();

        // Fourth should be blocked and NOT recorded
        let result = limiter.check_and_record(false, None).unwrap();
        assert!(!result.allowed);
        assert_eq!(
            limiter.current_run_count().unwrap(),
            3,
            "Blocked kills should not increment counter"
        );
    }

    #[test]
    fn override_per_run_reduces_effective_limit() {
        let config = RateLimitConfig {
            max_per_run: 10,
            max_per_minute: None,
            max_per_hour: None,
            max_per_day: None,
        };
        let limiter = SlidingWindowRateLimiter::new(config, None::<&str>).unwrap();

        for _ in 0..5 {
            limiter.record_kill().unwrap();
        }

        // Override to 5: should be blocked
        let result = limiter.check_with_override(false, Some(5)).unwrap();
        assert!(!result.allowed, "Override of 5 should block at count 5");

        // No override: should still be allowed (global limit is 10)
        let result = limiter.check(false).unwrap();
        assert!(result.allowed, "Without override, should be allowed");
    }

    #[test]
    fn override_cannot_exceed_global_limit() {
        let config = RateLimitConfig {
            max_per_run: 5,
            max_per_minute: None,
            max_per_hour: None,
            max_per_day: None,
        };
        let limiter = SlidingWindowRateLimiter::new(config, None::<&str>).unwrap();

        for _ in 0..5 {
            limiter.record_kill().unwrap();
        }

        // Override to 100 should still be blocked by global limit of 5
        let result = limiter.check_with_override(false, Some(100)).unwrap();
        assert!(!result.allowed, "Override should not exceed global limit");
    }

    #[test]
    fn reset_run_counter_clears_per_run_only() {
        let config = RateLimitConfig {
            max_per_run: 3,
            max_per_minute: None,
            max_per_hour: None,
            max_per_day: None,
        };
        let limiter = SlidingWindowRateLimiter::new(config, None::<&str>).unwrap();

        limiter.record_kill().unwrap();
        limiter.record_kill().unwrap();
        assert_eq!(limiter.current_run_count().unwrap(), 2);

        limiter.reset_run_counter().unwrap();
        assert_eq!(limiter.current_run_count().unwrap(), 0);

        // Time-based counters retain the kills
        let counts = limiter.get_counts().unwrap();
        assert_eq!(counts.run, 0);
        assert_eq!(counts.minute, 2, "Per-minute count should survive reset");
    }

    #[test]
    fn counts_struct_serializes_correctly() {
        let config = RateLimitConfig {
            max_per_run: 100,
            max_per_minute: None,
            max_per_hour: None,
            max_per_day: None,
        };
        let limiter = SlidingWindowRateLimiter::new(config, None::<&str>).unwrap();

        limiter.record_kill().unwrap();
        let counts = limiter.get_counts().unwrap();

        let json = serde_json::to_string(&counts).unwrap();
        assert!(json.contains("\"run\":1"), "JSON: {}", json);
        assert!(json.contains("\"minute\":1"), "JSON: {}", json);
        assert!(json.contains("\"hour\":1"), "JSON: {}", json);
        assert!(json.contains("\"day\":1"), "JSON: {}", json);
    }

    #[test]
    fn default_conservative_config_values() {
        let config = RateLimitConfig::default_conservative();
        assert_eq!(config.max_per_run, 5);
        assert_eq!(config.max_per_minute, Some(2));
        assert_eq!(config.max_per_hour, Some(20));
        assert_eq!(config.max_per_day, Some(100));
    }
}

// ============================================================================
// Persistence and Recovery Tests
// ============================================================================

mod persistence {
    use super::*;

    #[test]
    fn state_persists_across_limiter_instances() {
        let dir = tempdir().unwrap();
        let state_path = dir.path().join("rate_limit_state.json");

        // First instance: record kills
        {
            let config = RateLimitConfig {
                max_per_run: 100,
                max_per_minute: Some(10),
                max_per_hour: Some(50),
                max_per_day: Some(200),
            };
            let limiter = SlidingWindowRateLimiter::new(config, Some(&state_path)).unwrap();
            for _ in 0..5 {
                limiter.record_kill().unwrap();
            }
            let counts = limiter.get_counts().unwrap();
            assert_eq!(counts.run, 5);
            assert_eq!(counts.minute, 5);
        }

        // Second instance: should load persisted state
        {
            let config = RateLimitConfig {
                max_per_run: 100,
                max_per_minute: Some(10),
                max_per_hour: Some(50),
                max_per_day: Some(200),
            };
            let limiter = SlidingWindowRateLimiter::new(config, Some(&state_path)).unwrap();
            let counts = limiter.get_counts().unwrap();

            // Per-run resets on new instance
            assert_eq!(counts.run, 0, "Per-run should reset on new instance");
            // Per-minute, per-hour, per-day should persist
            assert_eq!(
                counts.minute, 5,
                "Per-minute should persist across instances"
            );
            assert_eq!(counts.hour, 5, "Per-hour should persist across instances");
            assert_eq!(counts.day, 5, "Per-day should persist across instances");
        }
    }

    #[test]
    fn persisted_state_enforces_limits_on_new_instance() {
        let dir = tempdir().unwrap();
        let state_path = dir.path().join("rate_limit_state.json");

        // First instance: use up per-minute limit
        {
            let config = RateLimitConfig {
                max_per_run: 100,
                max_per_minute: Some(3),
                max_per_hour: None,
                max_per_day: None,
            };
            let limiter = SlidingWindowRateLimiter::new(config, Some(&state_path)).unwrap();
            for _ in 0..3 {
                limiter.record_kill().unwrap();
            }
        }

        // Second instance: should still be blocked by per-minute limit
        {
            let config = RateLimitConfig {
                max_per_run: 100,
                max_per_minute: Some(3),
                max_per_hour: None,
                max_per_day: None,
            };
            let limiter = SlidingWindowRateLimiter::new(config, Some(&state_path)).unwrap();
            let result = limiter.check(false).unwrap();
            assert!(
                !result.allowed,
                "Per-minute limit should persist across instances"
            );
            assert_eq!(
                result.block_reason.as_ref().unwrap().window,
                RateLimitWindow::Minute
            );
        }
    }

    #[test]
    fn missing_state_file_starts_fresh() {
        let dir = tempdir().unwrap();
        let state_path = dir.path().join("nonexistent_state.json");

        let config = RateLimitConfig {
            max_per_run: 10,
            max_per_minute: None,
            max_per_hour: None,
            max_per_day: None,
        };
        let limiter = SlidingWindowRateLimiter::new(config, Some(&state_path)).unwrap();
        let counts = limiter.get_counts().unwrap();
        assert_eq!(counts.run, 0);
        assert_eq!(counts.minute, 0);
        assert_eq!(counts.hour, 0);
        assert_eq!(counts.day, 0);
    }

    #[test]
    fn corrupted_state_file_recovers_gracefully() {
        let dir = tempdir().unwrap();
        let state_path = dir.path().join("corrupted_state.json");

        // Write invalid JSON
        std::fs::write(&state_path, "{ this is not valid json }}}").unwrap();

        let config = RateLimitConfig {
            max_per_run: 10,
            max_per_minute: None,
            max_per_hour: None,
            max_per_day: None,
        };
        // Should not panic; falls back to default state
        let limiter = SlidingWindowRateLimiter::new(config, Some(&state_path)).unwrap();
        let counts = limiter.get_counts().unwrap();
        assert_eq!(counts.run, 0, "Should start fresh on corruption");
        assert_eq!(counts.minute, 0);
    }

    #[test]
    fn empty_state_file_recovers_gracefully() {
        let dir = tempdir().unwrap();
        let state_path = dir.path().join("empty_state.json");

        std::fs::write(&state_path, "").unwrap();

        let config = RateLimitConfig {
            max_per_run: 10,
            max_per_minute: None,
            max_per_hour: None,
            max_per_day: None,
        };
        let limiter = SlidingWindowRateLimiter::new(config, Some(&state_path)).unwrap();
        let counts = limiter.get_counts().unwrap();
        assert_eq!(counts.run, 0);
    }

    #[test]
    fn no_state_path_works_without_persistence() {
        let config = RateLimitConfig {
            max_per_run: 5,
            max_per_minute: None,
            max_per_hour: None,
            max_per_day: None,
        };
        let limiter = SlidingWindowRateLimiter::new(config, None::<&str>).unwrap();

        for _ in 0..3 {
            limiter.record_kill().unwrap();
        }

        let counts = limiter.get_counts().unwrap();
        assert_eq!(counts.run, 3);
        // No file was created
    }

    #[test]
    fn state_file_creates_parent_directories() {
        let dir = tempdir().unwrap();
        let state_path = dir.path().join("nested").join("deep").join("state.json");

        let config = RateLimitConfig {
            max_per_run: 10,
            max_per_minute: None,
            max_per_hour: None,
            max_per_day: None,
        };
        let limiter = SlidingWindowRateLimiter::new(config, Some(&state_path)).unwrap();
        limiter.record_kill().unwrap();

        assert!(state_path.exists(), "State file should be created");
    }
}

// ============================================================================
// PolicyEnforcer Integration Tests
// ============================================================================

mod enforcer_integration {
    use super::*;

    #[test]
    fn enforcer_blocks_at_per_run_limit() {
        let policy = policy_with_rate_limits(3, None, None, None);
        let enforcer = PolicyEnforcer::new(&policy, None).unwrap();
        let candidate = killable_candidate();

        // First 3 kills should be allowed
        for i in 0..3 {
            let result = enforcer.check_action(&candidate, Action::Kill, false);
            assert!(result.allowed, "Kill {} should be allowed", i + 1);
            enforcer.record_kill().unwrap();
        }

        // 4th should be blocked by rate limit
        let result = enforcer.check_action(&candidate, Action::Kill, false);
        assert!(!result.allowed, "4th kill should be blocked");
        assert_eq!(
            result.violation.as_ref().unwrap().kind,
            ViolationKind::RateLimitExceeded
        );
    }

    #[test]
    fn enforcer_reset_clears_run_counter() {
        let policy = policy_with_rate_limits(2, None, None, None);
        let enforcer = PolicyEnforcer::new(&policy, None).unwrap();
        let candidate = killable_candidate();

        // Use up the limit
        for _ in 0..2 {
            let result = enforcer.check_action(&candidate, Action::Kill, false);
            assert!(result.allowed);
            enforcer.record_kill().unwrap();
        }

        // Should be blocked
        let result = enforcer.check_action(&candidate, Action::Kill, false);
        assert!(!result.allowed);

        // Reset and verify
        enforcer.reset_run_counters();
        let result = enforcer.check_action(&candidate, Action::Kill, false);
        assert!(result.allowed, "Should be allowed after reset");
    }

    #[test]
    fn enforcer_rate_limit_applies_only_to_kill_actions() {
        let policy = policy_with_rate_limits(1, None, None, None);
        let enforcer = PolicyEnforcer::new(&policy, None).unwrap();
        let candidate = killable_candidate();

        // Use up the kill limit
        enforcer.record_kill().unwrap();

        // Kill should be blocked
        let result = enforcer.check_action(&candidate, Action::Kill, false);
        assert!(!result.allowed);

        // Keep action should still be allowed (not destructive)
        let result = enforcer.check_action(&candidate, Action::Keep, false);
        assert!(result.allowed, "Keep should not be rate limited");
    }

    #[test]
    fn enforcer_with_persistent_state() {
        let dir = tempdir().unwrap();
        let state_path = dir.path().join("enforcer_state.json");
        let candidate = killable_candidate();

        // First enforcer: record kills
        {
            let policy = policy_with_rate_limits(100, Some(3), None, None);
            let enforcer = PolicyEnforcer::new(&policy, Some(state_path.as_path())).unwrap();
            for _ in 0..3 {
                let result = enforcer.check_action(&candidate, Action::Kill, false);
                assert!(result.allowed);
                enforcer.record_kill().unwrap();
            }
        }

        // Second enforcer: per-minute limit should persist
        {
            let policy = policy_with_rate_limits(100, Some(3), None, None);
            let enforcer = PolicyEnforcer::new(&policy, Some(state_path.as_path())).unwrap();

            // Per-run counter is fresh but per-minute is persisted
            assert_eq!(enforcer.current_run_kill_count(), 0);

            let result = enforcer.check_action(&candidate, Action::Kill, false);
            assert!(
                !result.allowed,
                "Per-minute limit should persist across enforcer instances"
            );
            assert_eq!(
                result.violation.as_ref().unwrap().kind,
                ViolationKind::RateLimitExceeded
            );
        }
    }

    #[test]
    fn enforcer_warning_propagates_to_check_result() {
        let policy = policy_with_rate_limits(10, None, None, None);
        let enforcer = PolicyEnforcer::new(&policy, None).unwrap();
        let candidate = killable_candidate();

        // 80% = 8 kills
        for _ in 0..8 {
            enforcer.record_kill().unwrap();
        }

        let result = enforcer.check_action(&candidate, Action::Kill, false);
        assert!(result.allowed, "Should still be allowed at 80%");
        assert!(
            !result.warnings.is_empty(),
            "Should have rate limit warning at 80%"
        );
        assert!(
            result.warnings[0].contains("rate limit") || result.warnings[0].contains("approaching"),
            "Warning should mention rate limit: {}",
            result.warnings[0]
        );
    }

    #[test]
    fn enforcer_violation_message_is_actionable() {
        let policy = policy_with_rate_limits(2, None, None, None);
        let enforcer = PolicyEnforcer::new(&policy, None).unwrap();
        let candidate = killable_candidate();

        enforcer.record_kill().unwrap();
        enforcer.record_kill().unwrap();

        let result = enforcer.check_action(&candidate, Action::Kill, false);
        assert!(!result.allowed);

        let violation = result.violation.unwrap();
        assert_eq!(violation.kind, ViolationKind::RateLimitExceeded);
        assert!(
            violation.message.contains("rate limit"),
            "Message should mention rate limit: {}",
            violation.message
        );
        // Violation should include a rule reference
        assert!(
            !violation.rule.is_empty(),
            "Rule should be specified: {}",
            violation.rule
        );
    }

    #[test]
    fn enforcer_tracks_current_run_count() {
        let policy = policy_with_rate_limits(10, None, None, None);
        let enforcer = PolicyEnforcer::new(&policy, None).unwrap();

        assert_eq!(enforcer.current_run_kill_count(), 0);

        enforcer.record_kill().unwrap();
        assert_eq!(enforcer.current_run_kill_count(), 1);

        enforcer.record_kill().unwrap();
        enforcer.record_kill().unwrap();
        assert_eq!(enforcer.current_run_kill_count(), 3);

        enforcer.reset_run_counters();
        assert_eq!(enforcer.current_run_kill_count(), 0);
    }
}

// ============================================================================
// Multi-Window Interaction Tests
// ============================================================================

mod multi_window {
    use super::*;

    #[test]
    fn strictest_window_blocks_first() {
        // per_run=100, per_minute=2: per-minute should block first
        let config = RateLimitConfig {
            max_per_run: 100,
            max_per_minute: Some(2),
            max_per_hour: Some(50),
            max_per_day: Some(200),
        };
        let limiter = SlidingWindowRateLimiter::new(config, None::<&str>).unwrap();

        limiter.record_kill().unwrap();
        limiter.record_kill().unwrap();

        let result = limiter.check(false).unwrap();
        assert!(!result.allowed);
        assert_eq!(
            result.block_reason.as_ref().unwrap().window,
            RateLimitWindow::Minute,
            "Per-minute should be the strictest and block first"
        );
    }

    #[test]
    fn per_run_blocks_before_time_windows_when_strictest() {
        // per_run=1, per_minute=100: per-run should block first
        let config = RateLimitConfig {
            max_per_run: 1,
            max_per_minute: Some(100),
            max_per_hour: Some(200),
            max_per_day: Some(500),
        };
        let limiter = SlidingWindowRateLimiter::new(config, None::<&str>).unwrap();

        limiter.record_kill().unwrap();

        let result = limiter.check(false).unwrap();
        assert!(!result.allowed);
        assert_eq!(
            result.block_reason.as_ref().unwrap().window,
            RateLimitWindow::Run,
            "Per-run should block before per-minute when it's stricter"
        );
    }

    #[test]
    fn all_windows_track_independently() {
        let config = RateLimitConfig {
            max_per_run: 100,
            max_per_minute: None,
            max_per_hour: None,
            max_per_day: None,
        };
        let limiter = SlidingWindowRateLimiter::new(config, None::<&str>).unwrap();

        for _ in 0..5 {
            limiter.record_kill().unwrap();
        }

        let counts = limiter.get_counts().unwrap();
        assert_eq!(counts.run, 5);
        assert_eq!(counts.minute, 5, "Minute window should track all kills");
        assert_eq!(counts.hour, 5, "Hour window should track all kills");
        assert_eq!(counts.day, 5, "Day window should track all kills");
    }

    #[test]
    fn disabled_windows_do_not_block() {
        // Only per-run enabled
        let config = RateLimitConfig {
            max_per_run: 100,
            max_per_minute: None,
            max_per_hour: None,
            max_per_day: None,
        };
        let limiter = SlidingWindowRateLimiter::new(config, None::<&str>).unwrap();

        // Record many kills — should not be blocked by time windows
        for _ in 0..50 {
            limiter.record_kill().unwrap();
        }

        let result = limiter.check(false).unwrap();
        assert!(
            result.allowed,
            "Only per-run should block; disabled windows should not"
        );
    }
}

// ============================================================================
// Edge Cases
// ============================================================================

mod edge_cases {
    use super::*;

    #[test]
    fn zero_kills_allowed_blocks_immediately() {
        // NOTE: This tests the implementation's response to a 0-limit config.
        // The enforcer/system would normally not set this, but it should be handled.
        let config = RateLimitConfig {
            max_per_run: 0,
            max_per_minute: None,
            max_per_hour: None,
            max_per_day: None,
        };
        let limiter = SlidingWindowRateLimiter::new(config, None::<&str>).unwrap();

        let result = limiter.check(false).unwrap();
        assert!(!result.allowed, "Zero limit should block immediately");
    }

    #[test]
    fn single_kill_limit() {
        let config = RateLimitConfig {
            max_per_run: 1,
            max_per_minute: None,
            max_per_hour: None,
            max_per_day: None,
        };
        let limiter = SlidingWindowRateLimiter::new(config, None::<&str>).unwrap();

        let result = limiter.check(false).unwrap();
        assert!(result.allowed, "First kill with limit=1 should be allowed");

        limiter.record_kill().unwrap();

        let result = limiter.check(false).unwrap();
        assert!(
            !result.allowed,
            "Second kill with limit=1 should be blocked"
        );
    }

    #[test]
    fn very_large_limit() {
        let config = RateLimitConfig {
            max_per_run: u32::MAX,
            max_per_minute: None,
            max_per_hour: None,
            max_per_day: None,
        };
        let limiter = SlidingWindowRateLimiter::new(config, None::<&str>).unwrap();

        // Should handle large limits without overflow
        for _ in 0..100 {
            limiter.record_kill().unwrap();
        }

        let result = limiter.check(false).unwrap();
        assert!(result.allowed, "Should be far from u32::MAX limit");
    }

    #[test]
    fn multiple_resets_are_idempotent() {
        let config = RateLimitConfig {
            max_per_run: 5,
            max_per_minute: None,
            max_per_hour: None,
            max_per_day: None,
        };
        let limiter = SlidingWindowRateLimiter::new(config, None::<&str>).unwrap();

        limiter.record_kill().unwrap();
        limiter.reset_run_counter().unwrap();
        limiter.reset_run_counter().unwrap();
        limiter.reset_run_counter().unwrap();

        assert_eq!(limiter.current_run_count().unwrap(), 0);
    }

    #[test]
    fn config_accessor_returns_original_config() {
        let config = RateLimitConfig {
            max_per_run: 42,
            max_per_minute: Some(7),
            max_per_hour: Some(99),
            max_per_day: None,
        };
        let limiter = SlidingWindowRateLimiter::new(config, None::<&str>).unwrap();
        let retrieved = limiter.config();

        assert_eq!(retrieved.max_per_run, 42);
        assert_eq!(retrieved.max_per_minute, Some(7));
        assert_eq!(retrieved.max_per_hour, Some(99));
        assert_eq!(retrieved.max_per_day, None);
    }

    #[test]
    fn guardrails_integration_maps_fields_correctly() {
        let mut policy = Policy::default();
        policy.guardrails.max_kills_per_run = 15;
        policy.guardrails.max_kills_per_minute = Some(3);
        policy.guardrails.max_kills_per_hour = Some(25);
        policy.guardrails.max_kills_per_day = Some(150);

        let config = RateLimitConfig::from_guardrails(&policy.guardrails);
        assert_eq!(config.max_per_run, 15);
        assert_eq!(config.max_per_minute, Some(3));
        assert_eq!(config.max_per_hour, Some(25));
        assert_eq!(config.max_per_day, Some(150));
    }
}
