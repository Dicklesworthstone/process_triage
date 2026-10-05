//! Integration tests for fleet learning transfer: bundle roundtrip, merge
//! strategies, baseline normalization, diff, validation, signature conflicts,
//! redaction, determinism, and dry-run semantics.

use std::collections::BTreeMap;

use pt_config::priors::{BetaParams, Priors};
use pt_core::fleet::transfer::{
    compute_bundle_checksum, compute_diff, export_bundle, merge_beta_params, merge_priors,
    merge_priors_weighted, normalize_baseline, resolve_signature_conflicts, validate_bundle,
    BaselineStats, MergeStrategy, TransferBundle, TRANSFER_SCHEMA_VERSION,
};
use pt_core::supervision::pattern_persistence::{
    ConflictResolution, PatternSource, PersistedPattern, PersistedSchema,
};
use pt_core::supervision::signature::{SignaturePatterns, SupervisorSignature};
use pt_core::supervision::SupervisorCategory;

// ── Helpers ───────────────────────────────────────────────────────────────

fn default_priors() -> Priors {
    Priors::default()
}

fn make_baseline(procs: u64, host_type: &str) -> BaselineStats {
    BaselineStats {
        total_processes_seen: procs,
        observation_window_hours: 48.0,
        class_distribution: {
            let mut m = BTreeMap::new();
            m.insert("useful".to_string(), 0.7);
            m.insert("zombie".to_string(), 0.05);
            m
        },
        mean_cpu_utilization: 55.0,
        host_type: Some(host_type.to_string()),
    }
}

fn make_sig(name: &str, confidence: f64) -> SupervisorSignature {
    SupervisorSignature {
        name: name.to_string(),
        category: SupervisorCategory::Other,
        patterns: SignaturePatterns {
            process_names: vec![format!("^{}$", name)],
            ..Default::default()
        },
        confidence_weight: confidence,
        notes: None,
        builtin: false,
        priors: Default::default(),
        expectations: Default::default(),
        priority: 100,
    }
}

fn make_persisted_schema(sigs: Vec<(&str, f64)>) -> PersistedSchema {
    PersistedSchema {
        schema_version: 2,
        patterns: sigs
            .into_iter()
            .map(|(name, conf)| {
                let mut sig = make_sig(name, conf);
                sig.confidence_weight = conf;
                PersistedPattern::new(sig, PatternSource::Custom)
            })
            .collect(),
        metadata: None,
    }
}

// ===========================================================================
// 1. Bundle Roundtrip
// ===========================================================================

#[test]
fn bundle_roundtrip_json_with_priors_and_baseline() {
    let priors = default_priors();
    let baseline = make_baseline(10000, "server");
    let bundle =
        export_bundle(Some(&priors), None, Some(&baseline), "host-a", Some("prod")).unwrap();

    let json = serde_json::to_string(&bundle).unwrap();
    let reloaded: TransferBundle = serde_json::from_str(&json).unwrap();

    assert_eq!(reloaded.schema_version, TRANSFER_SCHEMA_VERSION);
    assert_eq!(reloaded.source_host_id, "host-a");
    assert_eq!(reloaded.source_host_profile.as_deref(), Some("prod"));
    assert!(reloaded.priors.is_some());
    assert!(reloaded.baseline_stats.is_some());
    assert!(!reloaded.checksum.is_empty());

    // Validate passes on reloaded bundle.
    let warnings = validate_bundle(&reloaded).unwrap();
    assert!(warnings.iter().all(|w| w.code != "empty_bundle"));
}

#[test]
fn bundle_roundtrip_json_with_signatures() {
    let sigs = make_persisted_schema(vec![("sig_alpha", 0.9), ("sig_beta", 0.6)]);
    let bundle = export_bundle(None, Some(&sigs), None, "host-b", None).unwrap();

    let json = serde_json::to_string(&bundle).unwrap();
    let reloaded: TransferBundle = serde_json::from_str(&json).unwrap();

    assert!(reloaded.signatures.is_some());
    assert_eq!(reloaded.signatures.as_ref().unwrap().patterns.len(), 2);
    validate_bundle(&reloaded).unwrap();
}

#[test]
fn bundle_roundtrip_full_payload() {
    let priors = default_priors();
    let sigs = make_persisted_schema(vec![("full_sig", 0.75)]);
    let baseline = make_baseline(3000, "workstation");
    let bundle = export_bundle(
        Some(&priors),
        Some(&sigs),
        Some(&baseline),
        "host-c",
        Some("dev"),
    )
    .unwrap();

    let json = serde_json::to_string_pretty(&bundle).unwrap();
    let reloaded: TransferBundle = serde_json::from_str(&json).unwrap();

    assert!(reloaded.priors.is_some());
    assert!(reloaded.signatures.is_some());
    assert!(reloaded.baseline_stats.is_some());
    validate_bundle(&reloaded).unwrap();
}

// ===========================================================================
// 2. Merge Strategies
// ===========================================================================

#[test]
fn merge_strategy_weighted_produces_intermediate_values() {
    let local = default_priors();
    let mut incoming = default_priors();
    incoming.classes.useful.cpu_beta = BetaParams::new(20.0, 80.0);

    let result = merge_priors(&local, &incoming, MergeStrategy::Weighted).unwrap();
    // Weighted average: between local and incoming.
    let local_alpha = local.classes.useful.cpu_beta.alpha;
    let incoming_alpha = 20.0;
    assert!(result.classes.useful.cpu_beta.alpha > local_alpha.min(incoming_alpha));
    assert!(result.classes.useful.cpu_beta.alpha < local_alpha.max(incoming_alpha));
}

#[test]
fn merge_strategy_replace_uses_incoming() {
    let local = default_priors();
    let mut incoming = default_priors();
    incoming.classes.zombie.prior_prob = 0.99;
    incoming.classes.useful.prior_prob = 0.005;
    incoming.classes.useful_bad.prior_prob = 0.003;
    incoming.classes.abandoned.prior_prob = 0.002;

    let result = merge_priors(&local, &incoming, MergeStrategy::Replace).unwrap();
    assert!((result.classes.zombie.prior_prob - 0.99).abs() < 1e-9);
}

#[test]
fn merge_strategy_keep_local_ignores_incoming() {
    let local = default_priors();
    let local_useful_prob = local.classes.useful.prior_prob;
    let mut incoming = default_priors();
    incoming.classes.useful.prior_prob = 0.001;
    incoming.classes.useful_bad.prior_prob = 0.001;
    incoming.classes.abandoned.prior_prob = 0.001;
    incoming.classes.zombie.prior_prob = 0.997;

    let result = merge_priors(&local, &incoming, MergeStrategy::KeepLocal).unwrap();
    assert!((result.classes.useful.prior_prob - local_useful_prob).abs() < 1e-9);
}

#[test]
fn merge_weighted_priors_always_sum_to_one() {
    let local = default_priors();
    let mut incoming = default_priors();
    incoming.classes.useful.prior_prob = 0.3;
    incoming.classes.useful_bad.prior_prob = 0.3;
    incoming.classes.abandoned.prior_prob = 0.3;
    incoming.classes.zombie.prior_prob = 0.1;

    for (wl, wi) in [(0.1, 0.9), (0.5, 0.5), (0.9, 0.1), (1.0, 0.0), (0.0, 1.0)] {
        let result =
            merge_priors_weighted(&local, &incoming, MergeStrategy::Weighted, wl, wi).unwrap();
        let sum = result.classes.useful.prior_prob
            + result.classes.useful_bad.prior_prob
            + result.classes.abandoned.prior_prob
            + result.classes.zombie.prior_prob;
        assert!(
            (sum - 1.0).abs() < 1e-6,
            "sum={} for weights ({}, {})",
            sum,
            wl,
            wi
        );
    }
}

// ===========================================================================
// 3. BetaParams Merge
// ===========================================================================

#[test]
fn beta_merge_weighted_correctness() {
    let a = BetaParams::new(4.0, 16.0); // mean=0.2
    let b = BetaParams::new(16.0, 4.0); // mean=0.8
    let m = merge_beta_params(&a, &b, 0.5, 0.5).unwrap();
    assert!((m.alpha - 10.0).abs() < 1e-9);
    assert!((m.beta - 10.0).abs() < 1e-9);
    assert!((m.mean() - 0.5).abs() < 1e-9);
}

#[test]
fn beta_merge_preserves_total_pseudo_obs() {
    let a = BetaParams::new(3.0, 7.0);
    let b = BetaParams::new(5.0, 5.0);
    let m = merge_beta_params(&a, &b, 1.0, 1.0).unwrap();
    // (3+5)/2=4, (7+5)/2=6, total=10 which equals (10+10)/2
    assert!((m.alpha + m.beta - 10.0).abs() < 1e-9);
}

#[test]
fn beta_merge_full_weight_on_one_side() {
    let a = BetaParams::new(2.0, 8.0);
    let b = BetaParams::new(100.0, 100.0);
    let m = merge_beta_params(&a, &b, 1.0, 0.0).unwrap();
    assert!((m.alpha - 2.0).abs() < 1e-9);
    assert!((m.beta - 8.0).abs() < 1e-9);
}

// ===========================================================================
// 4. Baseline Normalization
// ===========================================================================

#[test]
fn normalize_server_to_workstation_downscales() {
    let mut priors = default_priors();
    let original_alpha = priors.classes.useful.cpu_beta.alpha;

    let source = make_baseline(10000, "server");
    let target = make_baseline(2000, "workstation");

    normalize_baseline(&mut priors, &source, &target);

    // Scale = 2000/10000 = 0.2
    let expected = original_alpha * 0.2;
    assert!(
        (priors.classes.useful.cpu_beta.alpha - expected).abs() < 1e-6,
        "expected {}, got {}",
        expected,
        priors.classes.useful.cpu_beta.alpha,
    );
}

#[test]
fn normalize_identity_transform_is_noop() {
    let original = default_priors();
    let mut priors = original.clone();
    let stats = make_baseline(5000, "server");

    normalize_baseline(&mut priors, &stats, &stats);

    assert!(
        (priors.classes.useful.cpu_beta.alpha - original.classes.useful.cpu_beta.alpha).abs()
            < 1e-9
    );
    assert!(
        (priors.classes.zombie.orphan_beta.beta - original.classes.zombie.orphan_beta.beta).abs()
            < 1e-9
    );
}

#[test]
fn normalize_missing_stats_is_noop() {
    let original = default_priors();
    let mut priors = original.clone();
    let zero_stats = BaselineStats {
        total_processes_seen: 0,
        observation_window_hours: 0.0,
        class_distribution: BTreeMap::new(),
        mean_cpu_utilization: 0.0,
        host_type: None,
    };
    let good_stats = make_baseline(5000, "server");

    normalize_baseline(&mut priors, &zero_stats, &good_stats);
    assert!(
        (priors.classes.useful.cpu_beta.alpha - original.classes.useful.cpu_beta.alpha).abs()
            < 1e-9
    );
}

#[test]
fn normalize_clamps_extreme_ratios() {
    let mut priors = default_priors();
    let original_alpha = priors.classes.useful.cpu_beta.alpha;

    let source = make_baseline(1, "tiny");
    let target = make_baseline(10_000_000, "huge");

    normalize_baseline(&mut priors, &source, &target);

    // Clamped to 10.0x.
    assert!(
        (priors.classes.useful.cpu_beta.alpha - original_alpha * 10.0).abs() < 1e-6,
        "should clamp to 10x: expected {}, got {}",
        original_alpha * 10.0,
        priors.classes.useful.cpu_beta.alpha,
    );
}

// ===========================================================================
// 5. Diff Computation
// ===========================================================================

#[test]
fn diff_identical_priors_no_changes() {
    let priors = default_priors();
    let bundle = export_bundle(Some(&priors), None, None, "h1", None).unwrap();
    let diff = compute_diff(Some(&priors), None, &bundle, None);
    assert!(diff.priors_changes.is_empty());
}

#[test]
fn diff_detects_changed_class_priors() {
    let local = default_priors();
    let mut incoming = default_priors();
    incoming.classes.useful.prior_prob = 0.99;
    incoming.classes.useful_bad.prior_prob = 0.005;
    incoming.classes.abandoned.prior_prob = 0.004;
    incoming.classes.zombie.prior_prob = 0.001;

    let bundle = export_bundle(Some(&incoming), None, None, "h2", None).unwrap();
    let diff = compute_diff(Some(&local), None, &bundle, None);

    assert!(!diff.priors_changes.is_empty());
    assert!(diff
        .priors_changes
        .iter()
        .any(|c| c.class == "useful" && c.field == "prior_prob"));
    assert!(diff.priors_changes.iter().all(|c| c.merged_value.is_none()));
}

#[test]
fn diff_detects_added_signature() {
    let local_sigs = make_persisted_schema(vec![("existing_sig", 0.8)]);
    let incoming_sigs = make_persisted_schema(vec![("existing_sig", 0.8), ("new_sig", 0.6)]);

    let bundle = export_bundle(None, Some(&incoming_sigs), None, "h3", None).unwrap();
    let diff = compute_diff(None, Some(&local_sigs), &bundle, None);

    assert!(diff.signature_changes.iter().any(|c| c.name == "new_sig"
        && matches!(
            c.change_type,
            pt_core::fleet::transfer::SignatureChangeType::Added
        )));
}

#[test]
fn diff_detects_removed_signature() {
    let local_sigs = make_persisted_schema(vec![("sig_a", 0.8), ("sig_b", 0.7)]);
    let incoming_sigs = make_persisted_schema(vec![("sig_a", 0.8)]);

    let bundle = export_bundle(None, Some(&incoming_sigs), None, "h4", None).unwrap();
    let diff = compute_diff(None, Some(&local_sigs), &bundle, None);

    assert!(diff.signature_changes.iter().any(|c| c.name == "sig_b"
        && matches!(
            c.change_type,
            pt_core::fleet::transfer::SignatureChangeType::Removed
        )));
}

#[test]
fn diff_detects_updated_signature_confidence() {
    let local_sigs = make_persisted_schema(vec![("sig_x", 0.5)]);
    let incoming_sigs = make_persisted_schema(vec![("sig_x", 0.9)]);

    let bundle = export_bundle(None, Some(&incoming_sigs), None, "h5", None).unwrap();
    let diff = compute_diff(None, Some(&local_sigs), &bundle, None);

    assert!(diff.signature_changes.iter().any(|c| c.name == "sig_x"
        && matches!(
            c.change_type,
            pt_core::fleet::transfer::SignatureChangeType::Updated
        )));
}

#[test]
fn diff_unchanged_signature_marked_as_such() {
    let sigs = make_persisted_schema(vec![("same_sig", 0.8)]);
    let bundle = export_bundle(None, Some(&sigs), None, "h6", None).unwrap();
    let diff = compute_diff(None, Some(&sigs), &bundle, None);

    assert!(diff.signature_changes.iter().any(|c| c.name == "same_sig"
        && matches!(
            c.change_type,
            pt_core::fleet::transfer::SignatureChangeType::Unchanged
        )));
}

// ===========================================================================
// 6. Validation
// ===========================================================================

#[test]
fn validate_checksum_mismatch_errors() {
    let priors = default_priors();
    let mut bundle = export_bundle(Some(&priors), None, None, "h1", None).unwrap();
    bundle.checksum =
        "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    let err = validate_bundle(&bundle).unwrap_err();
    assert!(err.to_string().contains("checksum"));
}

#[test]
fn validate_future_major_version_errors() {
    let priors = default_priors();
    let mut bundle = export_bundle(Some(&priors), None, None, "h1", None).unwrap();
    bundle.schema_version = "2.0.0".to_string();
    // An intentionally changed schema fixture needs its canonical checksum.
    bundle.checksum = compute_bundle_checksum(&bundle).unwrap();
    let err = validate_bundle(&bundle).unwrap_err();
    assert!(err.to_string().contains("unsupported"));
}

#[test]
fn validate_minor_version_bump_warns() {
    let priors = default_priors();
    let mut bundle = export_bundle(Some(&priors), None, None, "h1", None).unwrap();
    bundle.schema_version = "1.1.0".to_string();
    // This planted version change is not a captured positive CLI export.
    bundle.checksum = compute_bundle_checksum(&bundle).unwrap();

    let warnings = validate_bundle(&bundle).unwrap();
    assert!(warnings.iter().any(|w| w.code == "schema_version_mismatch"));
    let supplied_checksum = bundle.checksum.clone();
    bundle
        .priors
        .as_mut()
        .unwrap()
        .classes
        .useful
        .cpu_beta
        .alpha += 1.0;
    let error = validate_bundle(&bundle).unwrap_err();
    assert!(error.to_string().contains("checksum mismatch"));
    assert_eq!(bundle.checksum, supplied_checksum);
}

#[test]
fn validate_empty_bundle_warns() {
    let bundle = export_bundle(None, None, None, "h1", None).unwrap();
    let warnings = validate_bundle(&bundle).unwrap();
    assert!(warnings.iter().any(|w| w.code == "empty_bundle"));
}

// ===========================================================================
// 7. Signature Conflict Resolution
// ===========================================================================

#[test]
fn signature_conflict_keep_existing() {
    let local = make_persisted_schema(vec![("conflict_sig", 0.5)]);
    let incoming = make_persisted_schema(vec![("conflict_sig", 0.9)]);

    let (result, conflicts) =
        resolve_signature_conflicts(&local, &incoming, ConflictResolution::KeepExisting);
    assert_eq!(conflicts.len(), 1);
    // Should still have 0.5.
    let p = result
        .patterns
        .iter()
        .find(|p| p.signature.name == "conflict_sig")
        .unwrap();
    assert!((p.signature.confidence_weight - 0.5).abs() < 1e-9);
}

#[test]
fn signature_conflict_replace_with_imported() {
    let local = make_persisted_schema(vec![("conflict_sig", 0.5)]);
    let incoming = make_persisted_schema(vec![("conflict_sig", 0.9)]);

    let (result, conflicts) =
        resolve_signature_conflicts(&local, &incoming, ConflictResolution::ReplaceWithImported);
    assert_eq!(conflicts.len(), 1);
    let p = result
        .patterns
        .iter()
        .find(|p| p.signature.name == "conflict_sig")
        .unwrap();
    assert!((p.signature.confidence_weight - 0.9).abs() < 1e-9);
}

#[test]
fn signature_conflict_keep_higher_confidence() {
    let local = make_persisted_schema(vec![("hi_conf", 0.9)]);
    let incoming = make_persisted_schema(vec![("hi_conf", 0.3)]);

    let (result, _) =
        resolve_signature_conflicts(&local, &incoming, ConflictResolution::KeepHigherConfidence);
    let p = result
        .patterns
        .iter()
        .find(|p| p.signature.name == "hi_conf")
        .unwrap();
    assert!((p.signature.confidence_weight - 0.9).abs() < 1e-9);
}

#[test]
fn signature_new_patterns_always_added() {
    let local = make_persisted_schema(vec![("existing", 0.8)]);
    let incoming = make_persisted_schema(vec![("brand_new", 0.7)]);

    let (result, conflicts) =
        resolve_signature_conflicts(&local, &incoming, ConflictResolution::KeepExisting);
    assert!(conflicts.is_empty());
    assert_eq!(result.patterns.len(), 2);
}

// ===========================================================================
// 8. Redaction (host ID not leaked)
// ===========================================================================

#[test]
fn exported_bundle_uses_provided_host_id() {
    let priors = default_priors();
    let bundle = export_bundle(Some(&priors), None, None, "hmac-hashed-id-abc", None).unwrap();
    let json = serde_json::to_string(&bundle).unwrap();
    // The raw host ID is whatever was passed in; the caller is responsible for
    // hashing it.  Verify we don't leak anything *beyond* what was provided.
    assert!(json.contains("hmac-hashed-id-abc"));
    assert!(!json.contains("real-hostname"));
}

// ===========================================================================
// 9. Determinism
// ===========================================================================

#[test]
fn deterministic_same_input_same_checksum() {
    let priors = default_priors();
    let sigs = make_persisted_schema(vec![("det_sig", 0.8)]);
    let baseline = make_baseline(5000, "server");

    // Construct with fixed timestamp.
    let mut b1 = TransferBundle {
        schema_version: TRANSFER_SCHEMA_VERSION.to_string(),
        exported_at: "2026-01-01T00:00:00Z".to_string(),
        source_host_id: "h1".to_string(),
        source_host_profile: Some("test".to_string()),
        priors: Some(priors.clone()),
        signatures: Some(sigs.clone()),
        baseline_stats: Some(baseline.clone()),
        checksum: String::new(),
    };
    let j1 = serde_json::to_vec(&b1).unwrap();
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&j1);
    b1.checksum = hex::encode(hasher.finalize());

    let mut b2 = TransferBundle {
        schema_version: TRANSFER_SCHEMA_VERSION.to_string(),
        exported_at: "2026-01-01T00:00:00Z".to_string(),
        source_host_id: "h1".to_string(),
        source_host_profile: Some("test".to_string()),
        priors: Some(priors),
        signatures: Some(sigs),
        baseline_stats: Some(baseline),
        checksum: String::new(),
    };
    let j2 = serde_json::to_vec(&b2).unwrap();
    let mut hasher2 = Sha256::new();
    hasher2.update(&j2);
    b2.checksum = hex::encode(hasher2.finalize());

    assert_eq!(b1.checksum, b2.checksum);
}

// ===========================================================================
// 10. Dry-Run Semantics (no side effects)
// ===========================================================================

#[test]
fn dry_run_diff_does_not_mutate_inputs() {
    let local = default_priors();
    let local_clone = local.clone();

    let mut incoming = default_priors();
    incoming.classes.zombie.prior_prob = 0.5;
    incoming.classes.useful.prior_prob = 0.2;
    incoming.classes.useful_bad.prior_prob = 0.2;
    incoming.classes.abandoned.prior_prob = 0.1;
    let bundle = export_bundle(Some(&incoming), None, None, "h1", None).unwrap();

    // Compute diff (dry run).
    let _diff = compute_diff(Some(&local), None, &bundle, None);

    // Local priors should be unchanged.
    assert!((local.classes.useful.prior_prob - local_clone.classes.useful.prior_prob).abs() < 1e-9);
    assert!((local.classes.zombie.prior_prob - local_clone.classes.zombie.prior_prob).abs() < 1e-9);
}

#[test]
fn merge_does_not_mutate_inputs() {
    let local = default_priors();
    let local_prob = local.classes.useful.prior_prob;
    let incoming = default_priors();

    let _result = merge_priors(&local, &incoming, MergeStrategy::Weighted).unwrap();

    assert!((local.classes.useful.prior_prob - local_prob).abs() < 1e-9);
}

// ===========================================================================
// 11. MergeStrategy parsing
// ===========================================================================

#[test]
fn merge_strategy_parse_all_variants() {
    assert_eq!(
        "weighted".parse::<MergeStrategy>().unwrap(),
        MergeStrategy::Weighted
    );
    assert_eq!(
        "replace".parse::<MergeStrategy>().unwrap(),
        MergeStrategy::Replace
    );
    assert_eq!(
        "keep-local".parse::<MergeStrategy>().unwrap(),
        MergeStrategy::KeepLocal
    );
}

#[test]
fn merge_strategy_parse_invalid() {
    assert!("invalid".parse::<MergeStrategy>().is_err());
    assert!("".parse::<MergeStrategy>().is_err());
    assert!("WEIGHTED".parse::<MergeStrategy>().is_err());
}

#[test]
fn merge_strategy_default_is_weighted() {
    assert_eq!(MergeStrategy::default(), MergeStrategy::Weighted);
}

// ===========================================================================
// 12. Edge Cases
// ===========================================================================

#[test]
fn export_bundle_only_signatures() {
    let sigs = make_persisted_schema(vec![("only_sig", 0.8)]);
    let bundle = export_bundle(None, Some(&sigs), None, "h1", None).unwrap();
    assert!(bundle.priors.is_none());
    assert!(bundle.signatures.is_some());
    // Should still warn about no priors but not error.
    let warnings = validate_bundle(&bundle).unwrap();
    assert!(warnings.is_empty() || warnings.iter().all(|w| w.code != "empty_bundle"));
}

#[test]
fn normalize_baseline_all_classes_scaled() {
    let mut priors = default_priors();
    let source = make_baseline(1000, "small");
    let target = make_baseline(3000, "large");

    let orig_zombie_alpha = priors.classes.zombie.cpu_beta.alpha;
    let orig_abandoned_beta = priors.classes.abandoned.orphan_beta.beta;

    normalize_baseline(&mut priors, &source, &target);

    // Scale = 3.0
    assert!((priors.classes.zombie.cpu_beta.alpha - orig_zombie_alpha * 3.0).abs() < 1e-6);
    assert!((priors.classes.abandoned.orphan_beta.beta - orig_abandoned_beta * 3.0).abs() < 1e-6);
}
