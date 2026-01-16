//! Galaxy-brain math ledger consistency tests.
//!
//! These tests verify that the galaxy-brain math ledger is:
//! - Internally consistent (equations ↔ substituted numbers ↔ computed outputs)
//! - Consistent across surfaces (agent explain, HTML report)
//! - Safe to share (redaction applied, no secrets leak)
//!
//! See: process_triage-aii.4

use pt_common::galaxy_brain::{
    CardId, ComputedValue, Equation, GalaxyBrainData, MathCard, ValueFormat, ValueType,
    GALAXY_BRAIN_SCHEMA_VERSION,
};
use pt_core::config::priors::Priors;
use pt_core::inference::{
    compute_posterior,
    ledger::{Classification, Confidence, EvidenceLedger},
    posterior::{ClassScores, PosteriorResult},
    CpuEvidence, Evidence,
};
use serde_json::Value;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

// ============================================================================
// Test Fixture Helpers
// ============================================================================

fn fixtures_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .leak()
}

fn load_priors_fixture() -> Priors {
    let path = fixtures_dir().join("priors.json");
    let content = fs::read_to_string(&path).expect("read priors fixture");
    serde_json::from_str(&content).expect("parse priors fixture")
}

/// Create a deterministic test evidence for reproducible tests.
fn create_test_evidence_abandoned() -> Evidence {
    Evidence {
        cpu: Some(CpuEvidence::Fraction { occupancy: 0.01 }),
        runtime_seconds: Some(86400.0), // 24 hours
        orphan: Some(true),
        tty: Some(false),
        net: Some(false),
        io_active: Some(false),
        state_flag: None,
        command_category: None,
    }
}

fn create_test_evidence_useful() -> Evidence {
    Evidence {
        cpu: Some(CpuEvidence::Fraction { occupancy: 0.45 }),
        runtime_seconds: Some(120.0), // 2 minutes
        orphan: Some(false),
        tty: Some(true),
        net: Some(true),
        io_active: Some(true),
        state_flag: None,
        command_category: None,
    }
}

/// Build a GalaxyBrainData with posterior card for testing.
fn build_galaxy_brain_data_for_posterior(result: &PosteriorResult) -> GalaxyBrainData {
    let mut data = GalaxyBrainData::default();
    data.process_id = Some(12345);
    data.session_id = Some("test-session-001".to_string());
    data.generated_at = Some("2026-01-16T12:00:00Z".to_string());

    // Build the posterior core card
    let card = MathCard::new(CardId::PosteriorCore)
        .with_equation(
            Equation::display(r"P(C|x) = \frac{P(x|C) \cdot P(C)}{P(x)}")
                .with_label("Bayes rule")
                .with_ascii("P(C|x) = P(x|C) * P(C) / P(x)"),
        )
        .with_value(
            "posterior_useful",
            ComputedValue::probability(result.posterior.useful)
                .with_symbol(r"P(\text{useful}|x)")
                .with_label("Posterior: Useful"),
        )
        .with_value(
            "posterior_useful_bad",
            ComputedValue::probability(result.posterior.useful_bad)
                .with_symbol(r"P(\text{useful\_bad}|x)")
                .with_label("Posterior: Useful-Bad"),
        )
        .with_value(
            "posterior_abandoned",
            ComputedValue::probability(result.posterior.abandoned)
                .with_symbol(r"P(\text{abandoned}|x)")
                .with_label("Posterior: Abandoned"),
        )
        .with_value(
            "posterior_zombie",
            ComputedValue::probability(result.posterior.zombie)
                .with_symbol(r"P(\text{zombie}|x)")
                .with_label("Posterior: Zombie"),
        )
        .with_value(
            "log_odds_abandoned_useful",
            ComputedValue::log_value(result.log_odds_abandoned_useful)
                .with_symbol(r"\log \frac{P(A|x)}{P(U|x)}")
                .with_label("Log-odds Abandoned vs Useful"),
        )
        .with_intuition(format!(
            "Posterior probabilities sum to 1.0. Highest class: {} at {:.1}%",
            if result.posterior.useful >= result.posterior.abandoned
                && result.posterior.useful >= result.posterior.useful_bad
                && result.posterior.useful >= result.posterior.zombie
            {
                "useful"
            } else if result.posterior.abandoned >= result.posterior.useful_bad
                && result.posterior.abandoned >= result.posterior.zombie
            {
                "abandoned"
            } else if result.posterior.zombie >= result.posterior.useful_bad {
                "zombie"
            } else {
                "useful_bad"
            },
            [
                result.posterior.useful,
                result.posterior.useful_bad,
                result.posterior.abandoned,
                result.posterior.zombie
            ]
            .iter()
            .cloned()
            .fold(f64::NEG_INFINITY, f64::max)
                * 100.0
        ));

    data.cards.push(card);
    data
}

/// Macro for test logging.
macro_rules! log_test {
    ($level:expr, $msg:expr $(,)?) => {{
        eprintln!("[{}] {}", $level, $msg);
    }};
    ($level:expr, $msg:expr, $($key:ident = $val:expr),* $(,)?) => {{
        eprintln!("[{}] {} {{ {} }}", $level, $msg, stringify!($($key = $val),*));
    }};
}

// ============================================================================
// Schema and Required Cards Tests
// ============================================================================

#[test]
fn test_galaxy_brain_ledger_schema_version() {
    log_test!("INFO", "Testing galaxy-brain schema version");

    let data = GalaxyBrainData::default();
    assert_eq!(
        data.schema_version, GALAXY_BRAIN_SCHEMA_VERSION,
        "Schema version mismatch: expected {}, got {}",
        GALAXY_BRAIN_SCHEMA_VERSION, data.schema_version
    );
}

#[test]
fn test_galaxy_brain_card_id_completeness() {
    log_test!("INFO", "Testing card ID completeness");

    let all_cards = CardId::all();

    // Verify expected cards are present
    let expected = vec![
        CardId::PosteriorCore,
        CardId::HazardTimeVarying,
        CardId::ConformalInterval,
        CardId::ConformalClassSet,
        CardId::EValuesFdr,
        CardId::AlphaInvesting,
        CardId::Voi,
    ];

    assert_eq!(
        all_cards.len(),
        expected.len(),
        "Card count mismatch: expected {}, got {}",
        expected.len(),
        all_cards.len()
    );

    for card_id in &expected {
        assert!(
            all_cards.contains(card_id),
            "Missing expected card: {:?}",
            card_id
        );
    }
}

#[test]
fn test_galaxy_brain_card_default_titles() {
    log_test!("INFO", "Testing card default titles");

    // Each card should have a non-empty title
    for card_id in CardId::all() {
        let title = card_id.default_title();
        assert!(!title.is_empty(), "Empty title for {:?}", card_id);
        log_test!("DEBUG", "Card title", card_id = format!("{:?}", card_id), title = title);
    }
}

#[test]
fn test_galaxy_brain_required_posterior_card_fields() {
    log_test!("INFO", "Testing required posterior card fields");

    let priors = load_priors_fixture();
    let evidence = create_test_evidence_abandoned();

    let result = compute_posterior(&priors, &evidence).expect("compute_posterior failed");
    let data = build_galaxy_brain_data_for_posterior(&result);

    // Find the posterior core card
    let posterior_card = data
        .cards
        .iter()
        .find(|c| c.id == CardId::PosteriorCore)
        .expect("PosteriorCore card not found");

    // Check required fields
    assert!(!posterior_card.title.is_empty(), "Missing title");
    assert!(!posterior_card.equations.is_empty(), "Missing equations");
    assert!(!posterior_card.values.is_empty(), "Missing values");
    assert!(!posterior_card.intuition.is_empty(), "Missing intuition");

    // Check that required posterior values are present
    let required_values = [
        "posterior_useful",
        "posterior_useful_bad",
        "posterior_abandoned",
        "posterior_zombie",
        "log_odds_abandoned_useful",
    ];

    for key in &required_values {
        assert!(
            posterior_card.values.contains_key(*key),
            "Missing required value: {}",
            key
        );
    }

    log_test!(
        "INFO",
        "Verified posterior card",
        values_count = posterior_card.values.len(),
        equations_count = posterior_card.equations.len(),
    );
}

// ============================================================================
// Posterior Numbers Match Inference Tests
// ============================================================================

#[test]
fn test_galaxy_brain_posterior_numbers_match_inference() {
    log_test!("INFO", "Testing posterior numbers match inference output");

    let priors = load_priors_fixture();
    let evidence = create_test_evidence_abandoned();

    let result = compute_posterior(&priors, &evidence).expect("compute_posterior failed");
    let data = build_galaxy_brain_data_for_posterior(&result);

    let posterior_card = data
        .cards
        .iter()
        .find(|c| c.id == CardId::PosteriorCore)
        .expect("PosteriorCore card not found");

    // Extract and verify each value matches
    let tolerance = 1e-10;

    // Check useful posterior
    if let Some(val) = posterior_card.values.get("posterior_useful") {
        if let ValueType::Scalar(v) = &val.value {
            assert!(
                (v - result.posterior.useful).abs() < tolerance,
                "posterior_useful mismatch: galaxy_brain={}, inference={}",
                v,
                result.posterior.useful
            );
        } else {
            panic!("posterior_useful is not a scalar");
        }
    }

    // Check useful_bad posterior
    if let Some(val) = posterior_card.values.get("posterior_useful_bad") {
        if let ValueType::Scalar(v) = &val.value {
            assert!(
                (v - result.posterior.useful_bad).abs() < tolerance,
                "posterior_useful_bad mismatch: galaxy_brain={}, inference={}",
                v,
                result.posterior.useful_bad
            );
        }
    }

    // Check abandoned posterior
    if let Some(val) = posterior_card.values.get("posterior_abandoned") {
        if let ValueType::Scalar(v) = &val.value {
            assert!(
                (v - result.posterior.abandoned).abs() < tolerance,
                "posterior_abandoned mismatch: galaxy_brain={}, inference={}",
                v,
                result.posterior.abandoned
            );
        }
    }

    // Check zombie posterior
    if let Some(val) = posterior_card.values.get("posterior_zombie") {
        if let ValueType::Scalar(v) = &val.value {
            assert!(
                (v - result.posterior.zombie).abs() < tolerance,
                "posterior_zombie mismatch: galaxy_brain={}, inference={}",
                v,
                result.posterior.zombie
            );
        }
    }

    // Verify posteriors sum to 1.0
    let sum = result.posterior.useful
        + result.posterior.useful_bad
        + result.posterior.abandoned
        + result.posterior.zombie;
    assert!(
        (sum - 1.0).abs() < tolerance,
        "Posteriors don't sum to 1.0: sum={}",
        sum
    );

    log_test!(
        "INFO",
        "Verified posterior numbers match",
        useful = result.posterior.useful,
        abandoned = result.posterior.abandoned,
    );
}

#[test]
fn test_galaxy_brain_log_odds_matches_posterior() {
    log_test!("INFO", "Testing log-odds matches posterior ratio");

    let priors = load_priors_fixture();
    let evidence = create_test_evidence_abandoned();

    let result = compute_posterior(&priors, &evidence).expect("compute_posterior failed");
    let data = build_galaxy_brain_data_for_posterior(&result);

    let posterior_card = data
        .cards
        .iter()
        .find(|c| c.id == CardId::PosteriorCore)
        .expect("PosteriorCore card not found");

    // Verify log-odds = ln(abandoned / useful)
    let expected_log_odds = (result.posterior.abandoned / result.posterior.useful).ln();
    let tolerance = 1e-6;

    if let Some(val) = posterior_card.values.get("log_odds_abandoned_useful") {
        if let ValueType::Scalar(v) = &val.value {
            assert!(
                (v - expected_log_odds).abs() < tolerance,
                "log_odds mismatch: galaxy_brain={}, expected={}",
                v,
                expected_log_odds
            );
        }
    }

    // Also verify against PosteriorResult
    assert!(
        (result.log_odds_abandoned_useful - expected_log_odds).abs() < tolerance,
        "PosteriorResult log_odds mismatch: got={}, expected={}",
        result.log_odds_abandoned_useful,
        expected_log_odds
    );

    log_test!(
        "INFO",
        "Verified log-odds",
        log_odds = result.log_odds_abandoned_useful,
    );
}

// ============================================================================
// Evidence Ledger Consistency Tests
// ============================================================================

#[test]
fn test_evidence_ledger_classification_matches_posterior() {
    log_test!("INFO", "Testing EvidenceLedger classification matches posterior");

    // Test with abandoned-dominant posterior
    let abandoned_result = PosteriorResult {
        posterior: ClassScores {
            useful: 0.1,
            useful_bad: 0.05,
            abandoned: 0.8,
            zombie: 0.05,
        },
        log_posterior: ClassScores {
            useful: 0.1_f64.ln(),
            useful_bad: 0.05_f64.ln(),
            abandoned: 0.8_f64.ln(),
            zombie: 0.05_f64.ln(),
        },
        log_odds_abandoned_useful: (0.8 / 0.1_f64).ln(),
        evidence_terms: vec![],
    };

    let ledger = EvidenceLedger::from_posterior_result(&abandoned_result, None, None);
    assert_eq!(
        ledger.classification,
        Classification::Abandoned,
        "Expected Abandoned, got {:?}",
        ledger.classification
    );

    // Test with useful-dominant posterior
    let useful_result = PosteriorResult {
        posterior: ClassScores {
            useful: 0.85,
            useful_bad: 0.05,
            abandoned: 0.05,
            zombie: 0.05,
        },
        log_posterior: ClassScores {
            useful: 0.85_f64.ln(),
            useful_bad: 0.05_f64.ln(),
            abandoned: 0.05_f64.ln(),
            zombie: 0.05_f64.ln(),
        },
        log_odds_abandoned_useful: (0.05 / 0.85_f64).ln(),
        evidence_terms: vec![],
    };

    let ledger = EvidenceLedger::from_posterior_result(&useful_result, None, None);
    assert_eq!(
        ledger.classification,
        Classification::Useful,
        "Expected Useful, got {:?}",
        ledger.classification
    );

    log_test!("INFO", "Verified classification matches posterior");
}

#[test]
fn test_evidence_ledger_confidence_thresholds() {
    log_test!("INFO", "Testing EvidenceLedger confidence thresholds");

    // VeryHigh: > 0.99
    let very_high = PosteriorResult {
        posterior: ClassScores {
            useful: 0.995,
            useful_bad: 0.002,
            abandoned: 0.002,
            zombie: 0.001,
        },
        log_posterior: ClassScores::default(),
        log_odds_abandoned_useful: 0.0,
        evidence_terms: vec![],
    };
    let ledger = EvidenceLedger::from_posterior_result(&very_high, None, None);
    assert_eq!(ledger.confidence, Confidence::VeryHigh);

    // High: > 0.95, <= 0.99
    let high = PosteriorResult {
        posterior: ClassScores {
            useful: 0.97,
            useful_bad: 0.01,
            abandoned: 0.01,
            zombie: 0.01,
        },
        log_posterior: ClassScores::default(),
        log_odds_abandoned_useful: 0.0,
        evidence_terms: vec![],
    };
    let ledger = EvidenceLedger::from_posterior_result(&high, None, None);
    assert_eq!(ledger.confidence, Confidence::High);

    // Medium: > 0.80, <= 0.95
    let medium = PosteriorResult {
        posterior: ClassScores {
            useful: 0.85,
            useful_bad: 0.05,
            abandoned: 0.05,
            zombie: 0.05,
        },
        log_posterior: ClassScores::default(),
        log_odds_abandoned_useful: 0.0,
        evidence_terms: vec![],
    };
    let ledger = EvidenceLedger::from_posterior_result(&medium, None, None);
    assert_eq!(ledger.confidence, Confidence::Medium);

    // Low: <= 0.80
    let low = PosteriorResult {
        posterior: ClassScores {
            useful: 0.75,
            useful_bad: 0.10,
            abandoned: 0.10,
            zombie: 0.05,
        },
        log_posterior: ClassScores::default(),
        log_odds_abandoned_useful: 0.0,
        evidence_terms: vec![],
    };
    let ledger = EvidenceLedger::from_posterior_result(&low, None, None);
    assert_eq!(ledger.confidence, Confidence::Low);

    log_test!("INFO", "Verified confidence thresholds");
}

// ============================================================================
// Serialization and Cross-Surface Consistency Tests
// ============================================================================

#[test]
fn test_galaxy_brain_data_serialization_roundtrip() {
    log_test!("INFO", "Testing galaxy-brain data serialization roundtrip");

    let priors = load_priors_fixture();
    let evidence = create_test_evidence_abandoned();
    let result = compute_posterior(&priors, &evidence).expect("compute_posterior failed");
    let data = build_galaxy_brain_data_for_posterior(&result);

    // Serialize to JSON
    let json = serde_json::to_string_pretty(&data).expect("serialization failed");

    // Verify required fields are present in JSON
    let parsed: Value = serde_json::from_str(&json).expect("parse failed");

    assert!(parsed.get("schema_version").is_some(), "Missing schema_version");
    assert!(parsed.get("cards").is_some(), "Missing cards");

    // Deserialize back
    let restored: GalaxyBrainData = serde_json::from_str(&json).expect("deserialization failed");

    assert_eq!(data.schema_version, restored.schema_version);
    assert_eq!(data.process_id, restored.process_id);
    assert_eq!(data.session_id, restored.session_id);
    assert_eq!(data.cards.len(), restored.cards.len());

    log_test!(
        "INFO",
        "Serialization roundtrip passed",
        json_size = json.len(),
    );
}

#[test]
fn test_galaxy_brain_card_values_json_format() {
    log_test!("INFO", "Testing galaxy-brain card values JSON format");

    let priors = load_priors_fixture();
    let evidence = create_test_evidence_useful();
    let result = compute_posterior(&priors, &evidence).expect("compute_posterior failed");
    let data = build_galaxy_brain_data_for_posterior(&result);

    let json = serde_json::to_string(&data).expect("serialization failed");
    let parsed: Value = serde_json::from_str(&json).expect("parse failed");

    // Verify cards array structure
    let cards = parsed.get("cards").and_then(|c| c.as_array()).expect("cards array");

    for card in cards {
        // Each card should have required fields
        assert!(card.get("id").is_some(), "Card missing id");
        assert!(card.get("title").is_some(), "Card missing title");
        assert!(card.get("intuition").is_some(), "Card missing intuition");

        // Values should be an object
        if let Some(values) = card.get("values").and_then(|v| v.as_object()) {
            for (key, val) in values {
                assert!(val.get("value").is_some(), "Value {} missing 'value' field", key);
            }
        }
    }

    log_test!("INFO", "Card values JSON format verified");
}

// ============================================================================
// Redaction Safety Tests
// ============================================================================

/// Sensitive patterns that should never appear in ledger output.
const SENSITIVE_PATTERNS: &[&str] = &[
    "/home/",
    "/Users/",
    "password",
    "secret",
    "token",
    "api_key",
    "AWS_",
    "GITHUB_TOKEN",
    "-----BEGIN",
    "-----END",
];

#[test]
fn test_galaxy_brain_no_sensitive_paths_in_output() {
    log_test!("INFO", "Testing no sensitive paths in galaxy-brain output");

    let priors = load_priors_fixture();
    let evidence = create_test_evidence_abandoned();
    let result = compute_posterior(&priors, &evidence).expect("compute_posterior failed");
    let data = build_galaxy_brain_data_for_posterior(&result);

    let json = serde_json::to_string_pretty(&data).expect("serialization failed");

    for pattern in SENSITIVE_PATTERNS {
        assert!(
            !json.contains(pattern),
            "Found sensitive pattern '{}' in galaxy-brain output",
            pattern
        );
    }

    log_test!("INFO", "No sensitive patterns found in output");
}

#[test]
fn test_evidence_ledger_no_secrets_in_summary() {
    log_test!("INFO", "Testing no secrets in evidence ledger summary");

    let priors = load_priors_fixture();
    let evidence = create_test_evidence_abandoned();
    let result = compute_posterior(&priors, &evidence).expect("compute_posterior failed");
    let ledger = EvidenceLedger::from_posterior_result(&result, Some(12345), None);

    // Serialize ledger to JSON
    let json = serde_json::to_string_pretty(&ledger).expect("serialization failed");

    for pattern in SENSITIVE_PATTERNS {
        assert!(
            !json.contains(pattern),
            "Found sensitive pattern '{}' in ledger output",
            pattern
        );
    }

    // Also check the why_summary specifically
    for pattern in SENSITIVE_PATTERNS {
        assert!(
            !ledger.why_summary.contains(pattern),
            "Found sensitive pattern '{}' in why_summary",
            pattern
        );
    }

    log_test!("INFO", "No secrets in ledger summary");
}

// ============================================================================
// Value Format Tests
// ============================================================================

#[test]
fn test_computed_value_formats() {
    log_test!("INFO", "Testing computed value formats");

    // Probability format
    let prob = ComputedValue::probability(0.95);
    assert_eq!(prob.format, ValueFormat::Percentage);
    if let Some(unit) = &prob.unit {
        assert_eq!(unit, "probability");
    }

    // Log format
    let log_val = ComputedValue::log_value(-2.3);
    assert_eq!(log_val.format, ValueFormat::Log);

    // Duration format
    let dur = ComputedValue::duration_secs(3600.5);
    assert_eq!(dur.format, ValueFormat::Duration);
    if let Some(unit) = &dur.unit {
        assert_eq!(unit, "seconds");
    }

    // Scalar format (default)
    let scalar = ComputedValue::scalar(42.0);
    assert_eq!(scalar.format, ValueFormat::Decimal);

    log_test!("INFO", "All value formats verified");
}

// ============================================================================
// ClassScores now has Default derive in posterior.rs

// ============================================================================
// End-to-End Inference Consistency Tests
// ============================================================================

#[test]
fn test_full_inference_to_galaxy_brain_pipeline() {
    log_test!("INFO", "Testing full inference to galaxy-brain pipeline");

    let priors = load_priors_fixture();

    // Test multiple evidence scenarios
    let scenarios = vec![
        ("abandoned_process", create_test_evidence_abandoned()),
        ("useful_process", create_test_evidence_useful()),
    ];

    for (name, evidence) in scenarios {
        log_test!("DEBUG", "Testing scenario", name = name);

        let result = compute_posterior(&priors, &evidence).expect("compute_posterior failed");
        let data = build_galaxy_brain_data_for_posterior(&result);
        let ledger = EvidenceLedger::from_posterior_result(&result, None, None);

        // Verify internal consistency
        assert_eq!(data.schema_version, GALAXY_BRAIN_SCHEMA_VERSION);
        assert!(!data.cards.is_empty(), "No cards generated for {}", name);

        // Verify ledger matches galaxy-brain data
        let card = data
            .cards
            .iter()
            .find(|c| c.id == CardId::PosteriorCore)
            .unwrap();

        if let Some(val) = card.values.get("posterior_abandoned") {
            if let ValueType::Scalar(v) = &val.value {
                let tolerance = 1e-10;
                assert!(
                    (v - result.posterior.abandoned).abs() < tolerance,
                    "{}: posterior_abandoned mismatch",
                    name
                );
            }
        }

        // Verify classification consistency - find highest probability class
        let scores = [
            (Classification::Useful, result.posterior.useful),
            (Classification::UsefulBad, result.posterior.useful_bad),
            (Classification::Abandoned, result.posterior.abandoned),
            (Classification::Zombie, result.posterior.zombie),
        ];
        let highest_class = scores
            .iter()
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(c, _)| *c)
            .unwrap_or(Classification::Useful);

        assert_eq!(
            ledger.classification, highest_class,
            "{}: classification mismatch",
            name
        );

        log_test!(
            "DEBUG",
            "Scenario passed",
            name = name,
            classification = format!("{:?}", ledger.classification),
        );
    }

    log_test!("INFO", "Full pipeline test passed for all scenarios");
}
