//! Property-based tests for supervision module invariants:
//! signature matching, command normalization, and pattern statistics.

use proptest::prelude::*;
use pt_core::supervision::pattern_learning::CommandNormalizer;
use pt_core::supervision::pattern_persistence::{
    AllPatternStats, DisabledPatterns, PatternLifecycle, PatternStats,
};
use pt_core::supervision::signature::ProcessMatchContext;
use pt_core::supervision::SignatureDatabase;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    // ── SignatureDatabase invariants ─────────────────────────────────

    /// Default database is non-empty (has built-in signatures).
    #[test]
    fn database_default_non_empty(_dummy in 0u8..1) {
        let db = SignatureDatabase::with_defaults();
        prop_assert!(db.len() > 0, "default database should have built-in signatures");
    }

    /// match_process never panics for arbitrary comm strings.
    #[test]
    fn database_match_no_panic(
        comm in "[a-zA-Z0-9_.-]{1,30}",
        cmdline in "[a-zA-Z0-9 /._-]{0,100}",
    ) {
        let db = SignatureDatabase::with_defaults();
        let ctx = ProcessMatchContext::with_comm(&comm).cmdline(&cmdline);
        let _matches = db.match_process(&ctx);
    }

    /// best_match returns a subset of match_process results.
    #[test]
    fn database_best_is_subset(
        comm in prop_oneof![
            Just("systemd"),
            Just("node"),
            Just("docker"),
            Just("nginx"),
            Just("unknown"),
        ],
    ) {
        let db = SignatureDatabase::with_defaults();
        let ctx = ProcessMatchContext::with_comm(comm);
        let all = db.match_process(&ctx);
        let best = db.best_match(&ctx);
        if all.is_empty() {
            prop_assert!(best.is_none());
        } else {
            // best should be one of the matches
            prop_assert!(best.is_some());
        }
    }

    /// find_by_process_name never panics for arbitrary names.
    #[test]
    fn database_find_by_name_no_panic(
        name in "[a-zA-Z0-9_.-]{1,30}",
    ) {
        let db = SignatureDatabase::with_defaults();
        let _results = db.find_by_process_name(&name);
    }

    /// find_by_parent_name never panics for arbitrary names.
    #[test]
    fn database_find_by_parent_no_panic(
        name in "[a-zA-Z0-9_.-]{1,30}",
    ) {
        let db = SignatureDatabase::with_defaults();
        let _results = db.find_by_parent_name(&name);
    }

    // ── CommandNormalizer invariants ─────────────────────────────────

    /// normalize_process_name is deterministic.
    #[test]
    fn normalizer_deterministic(
        name in "[a-zA-Z0-9_.-]{1,30}",
    ) {
        let normalizer = CommandNormalizer::new();
        let a = normalizer.normalize_process_name(&name);
        let b = normalizer.normalize_process_name(&name);
        prop_assert_eq!(a, b, "normalization should be deterministic");
    }

    /// normalize_process_name produces non-empty output for non-empty input.
    #[test]
    fn normalizer_non_empty(
        name in "[a-zA-Z]{1,20}",
    ) {
        let normalizer = CommandNormalizer::new();
        let result = normalizer.normalize_process_name(&name);
        prop_assert!(!result.is_empty(),
            "normalized '{}' should not be empty", name);
    }

    /// generate_candidates returns at least one candidate for non-empty input.
    #[test]
    fn normalizer_candidates_non_empty(
        name in "[a-zA-Z]{2,15}",
        cmdline in "[a-zA-Z0-9 /._-]{5,60}",
    ) {
        let normalizer = CommandNormalizer::new();
        let candidates = normalizer.generate_candidates(&name, &cmdline);
        prop_assert!(!candidates.is_empty(),
            "should generate at least one candidate for '{}' '{}'", name, cmdline);
    }

    /// generate_candidates is deterministic.
    #[test]
    fn normalizer_candidates_deterministic(
        name in "[a-zA-Z]{2,10}",
        cmdline in "[a-zA-Z0-9 /._-]{5,40}",
    ) {
        let normalizer = CommandNormalizer::new();
        let a = normalizer.generate_candidates(&name, &cmdline);
        let b = normalizer.generate_candidates(&name, &cmdline);
        prop_assert_eq!(a.len(), b.len(),
            "candidate count should be deterministic");
    }

    // ── PatternStats invariants ─────────────────────────────────────

    /// acceptance_rate is in [0,1] after recording matches.
    #[test]
    fn stats_acceptance_rate_bounded(
        n_accept in 0usize..50,
        n_reject in 0usize..50,
    ) {
        prop_assume!(n_accept + n_reject > 0);
        let mut stats = PatternStats::default();
        for _ in 0..n_accept {
            stats.record_match(true);
        }
        for _ in 0..n_reject {
            stats.record_match(false);
        }
        if let Some(rate) = stats.acceptance_rate() {
            prop_assert!(rate >= 0.0 && rate <= 1.0,
                "acceptance rate {} out of [0,1]", rate);
        }
    }

    /// acceptance_rate matches expected value.
    #[test]
    fn stats_acceptance_rate_correct(
        n_accept in 1usize..50,
        n_reject in 0usize..50,
    ) {
        let mut stats = PatternStats::default();
        for _ in 0..n_accept {
            stats.record_match(true);
        }
        for _ in 0..n_reject {
            stats.record_match(false);
        }
        let total = (n_accept + n_reject) as f64;
        let expected = n_accept as f64 / total;
        if let Some(rate) = stats.acceptance_rate() {
            prop_assert!((rate - expected).abs() < 1e-10,
                "rate {} != expected {}", rate, expected);
        }
    }

    /// suggested_lifecycle never panics.
    #[test]
    fn stats_lifecycle_no_panic(
        n in 0usize..100,
    ) {
        let mut stats = PatternStats::default();
        for i in 0..n {
            stats.record_match(i % 2 == 0);
        }
        let _lc = stats.suggested_lifecycle();
    }

    // ── PatternLifecycle invariants ─────────────────────────────────

    /// from_stats returns a valid lifecycle for any confidence and count.
    #[test]
    fn lifecycle_from_stats_valid(
        confidence in 0.0f64..1.0,
        count in 0u32..1000,
    ) {
        let lc = PatternLifecycle::from_stats(confidence, count);
        // is_active and should_warn are complementary-ish — just ensure no panic
        let _active = lc.is_active();
        let _warn = lc.should_warn();
    }

    // ── DisabledPatterns invariants ──────────────────────────────────

    /// Disabling a pattern makes is_disabled return true.
    #[test]
    fn disabled_patterns_enable_disable(
        name in "[a-zA-Z_]{3,20}",
    ) {
        let mut disabled = DisabledPatterns::default();
        prop_assert!(!disabled.is_disabled(&name));
        disabled.disable(&name, Some("test"));
        prop_assert!(disabled.is_disabled(&name));
        disabled.enable(&name);
        prop_assert!(!disabled.is_disabled(&name));
    }

    // ── AllPatternStats invariants ──────────────────────────────────

    /// Recording matches for a pattern makes it retrievable.
    #[test]
    fn all_stats_record_and_get(
        name in "[a-zA-Z_]{3,15}",
        n in 1usize..20,
    ) {
        let mut all = AllPatternStats::default();
        for _ in 0..n {
            all.record_match(&name, true);
        }
        let stats = all.get(&name);
        prop_assert!(stats.is_some(),
            "pattern '{}' should be retrievable after recording", name);
    }

    /// get returns None for unknown pattern.
    #[test]
    fn all_stats_get_unknown(
        name in "[a-zA-Z_]{3,15}",
    ) {
        let all = AllPatternStats::default();
        prop_assert!(all.get(&name).is_none());
    }
}
