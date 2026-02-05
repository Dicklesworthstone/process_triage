//! No-mock inference + ledger regression tests with fixture cases.
//!
//! Covers:
//! - Golden posterior outputs per fixture case
//! - Evidence ledger top contributors (ordering + weights)
//! - Property checks (normalization, monotonicity, stability)

use pt_core::config::priors::Priors;
use pt_core::inference::{compute_posterior, build_process_explanation, CpuEvidence, Evidence, EvidenceLedger};
use pt_core::inference::ClassScores;
use pt_common::{ProcessId, StartId};
use pt_core::collect::{ProcessRecord, ProcessState};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

const INPUT_FIXTURE: &str = "inference_cases_input.json";
const EXPECTED_FIXTURE: &str = "inference_cases_expected.json";

// ============================================================================
// Fixture structures
// ============================================================================

#[derive(Debug, Deserialize)]
struct FixturesInput {
    schema_version: String,
    cases: Vec<CaseInput>,
}

#[derive(Debug, Deserialize)]
struct CaseInput {
    case_id: String,
    evidence: EvidenceFixture,
}

#[derive(Debug, Deserialize)]
struct EvidenceFixture {
    cpu: Option<CpuEvidenceFixture>,
    runtime_seconds: Option<f64>,
    orphan: Option<bool>,
    tty: Option<bool>,
    net: Option<bool>,
    io_active: Option<bool>,
    state_flag: Option<usize>,
    command_category: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum CpuEvidenceFixture {
    Fraction { occupancy: f64 },
    Binomial { k: f64, n: f64, eta: Option<f64> },
}

#[derive(Debug, Serialize, Deserialize)]
struct FixturesExpected {
    schema_version: String,
    cases: Vec<CaseExpected>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CaseExpected {
    case_id: String,
    posterior: ClassScores,
    classification: String,
    confidence: String,
    top_evidence: Vec<EvidenceExpected>,
}

#[derive(Debug, Serialize, Deserialize)]
struct EvidenceExpected {
    feature: String,
    direction: String,
    strength: String,
    delta_bits: f64,
}

// ============================================================================
// Helpers
// ============================================================================

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("test")
        .join("fixtures")
        .join("pt-core")
}

fn load_priors_fixture() -> Priors {
    let path = fixtures_dir().join("priors.json");
    let content = fs::read_to_string(&path).expect("read priors fixture");
    serde_json::from_str(&content).expect("parse priors fixture")
}

fn load_input_fixture() -> FixturesInput {
    let path = fixtures_dir().join(INPUT_FIXTURE);
    let content = fs::read_to_string(&path).expect("read inference input fixture");
    serde_json::from_str(&content).expect("parse inference input fixture")
}

fn load_expected_fixture() -> FixturesExpected {
    let path = fixtures_dir().join(EXPECTED_FIXTURE);
    let content = fs::read_to_string(&path).expect("read inference expected fixture");
    serde_json::from_str(&content).expect("parse inference expected fixture")
}

fn to_evidence(fix: &EvidenceFixture) -> Evidence {
    let cpu = match &fix.cpu {
        Some(CpuEvidenceFixture::Fraction { occupancy }) => {
            Some(CpuEvidence::Fraction { occupancy: *occupancy })
        }
        Some(CpuEvidenceFixture::Binomial { k, n, eta }) => Some(CpuEvidence::Binomial {
            k: *k,
            n: *n,
            eta: *eta,
        }),
        None => None,
    };

    Evidence {
        cpu,
        runtime_seconds: fix.runtime_seconds,
        orphan: fix.orphan,
        tty: fix.tty,
        net: fix.net,
        io_active: fix.io_active,
        state_flag: fix.state_flag,
        command_category: fix.command_category,
    }
}

fn approx_eq(a: f64, b: f64, tol: f64) -> bool {
    (a - b).abs() <= tol
}

fn build_expected_case(case: &CaseInput, priors: &Priors) -> CaseExpected {
    let evidence = to_evidence(&case.evidence);
    let posterior_result = compute_posterior(priors, &evidence).expect("posterior");
    let ledger = EvidenceLedger::from_posterior_result(&posterior_result, None, None);

    let top_evidence = ledger
        .bayes_factors
        .iter()
        .take(3)
        .map(|bf| EvidenceExpected {
            feature: bf.feature.clone(),
            direction: bf.direction.clone(),
            strength: bf.strength.clone(),
            delta_bits: bf.delta_bits,
        })
        .collect();

    CaseExpected {
        case_id: case.case_id.clone(),
        posterior: posterior_result.posterior,
        classification: ledger.classification.label().to_string(),
        confidence: ledger.confidence.label().to_string(),
        top_evidence,
    }
}

fn update_expected_fixtures(input: &FixturesInput, priors: &Priors) {
    let expected = FixturesExpected {
        schema_version: input.schema_version.clone(),
        cases: input
            .cases
            .iter()
            .map(|case| build_expected_case(case, priors))
            .collect(),
    };

    let path = fixtures_dir().join(EXPECTED_FIXTURE);
    let payload = serde_json::to_string_pretty(&expected).expect("serialize expected fixture");
    fs::write(&path, payload).expect("write expected fixture");
}

fn assert_case_matches(expected: &CaseExpected, actual: &CaseExpected) {
    let tol = 1e-6;
    assert_eq!(expected.case_id, actual.case_id);
    assert!(approx_eq(expected.posterior.useful, actual.posterior.useful, tol));
    assert!(approx_eq(
        expected.posterior.useful_bad,
        actual.posterior.useful_bad,
        tol
    ));
    assert!(approx_eq(
        expected.posterior.abandoned,
        actual.posterior.abandoned,
        tol
    ));
    assert!(approx_eq(expected.posterior.zombie, actual.posterior.zombie, tol));
    assert_eq!(expected.classification, actual.classification);
    assert_eq!(expected.confidence, actual.confidence);
    assert_eq!(expected.top_evidence.len(), actual.top_evidence.len());

    for (exp, act) in expected.top_evidence.iter().zip(actual.top_evidence.iter()) {
        assert_eq!(exp.feature, act.feature);
        assert_eq!(exp.direction, act.direction);
        assert_eq!(exp.strength, act.strength);
        assert!(approx_eq(exp.delta_bits, act.delta_bits, 1e-5));
    }
}

fn make_process(cpu_percent: f64) -> ProcessRecord {
    ProcessRecord {
        pid: ProcessId(4242),
        ppid: ProcessId(1),
        uid: 1000,
        user: "testuser".to_string(),
        pgid: Some(4242),
        sid: Some(4242),
        start_id: StartId::from_linux("00000000-0000-0000-0000-000000000000", 123456, 4242),
        comm: "sleep".to_string(),
        cmd: "sleep 1000".to_string(),
        state: ProcessState::Sleeping,
        cpu_percent,
        rss_bytes: 1024 * 1024,
        vsz_bytes: 10 * 1024 * 1024,
        tty: None,
        start_time_unix: chrono::Utc::now().timestamp() - 3600,
        elapsed: std::time::Duration::from_secs(3600),
        source: "mock".to_string(),
        container_info: None,
    }
}

// ============================================================================
// Golden regression tests
// ============================================================================

#[test]
fn test_inference_fixture_golden_outputs() {
    let input = load_input_fixture();
    let priors = load_priors_fixture();

    if std::env::var("UPDATE_INFERENCE_FIXTURES").is_ok() {
        update_expected_fixtures(&input, &priors);
        return;
    }

    let expected = load_expected_fixture();
    assert_eq!(input.schema_version, expected.schema_version);
    assert_eq!(input.cases.len(), expected.cases.len());

    let expected_map: HashMap<String, CaseExpected> = expected
        .cases
        .into_iter()
        .map(|case| (case.case_id.clone(), case))
        .collect();

    for case in &input.cases {
        let actual = build_expected_case(case, &priors);
        let expected_case = expected_map.get(&case.case_id);
        assert!(
            expected_case.is_some(),
            "missing expected case {}",
            case.case_id
        );
        assert_case_matches(expected_case.unwrap(), &actual);
    }
}

// ============================================================================
// Property and stability checks
// ============================================================================

#[test]
fn test_posterior_normalization_for_fixtures() {
    let input = load_input_fixture();
    let priors = load_priors_fixture();

    for case in &input.cases {
        let evidence = to_evidence(&case.evidence);
        let result = compute_posterior(&priors, &evidence).expect("posterior");
        let sum = result.posterior.useful
            + result.posterior.useful_bad
            + result.posterior.abandoned
            + result.posterior.zombie;
        assert!(approx_eq(sum, 1.0, 1e-6), "posterior sum != 1 for {}", case.case_id);
        for value in [
            result.posterior.useful,
            result.posterior.useful_bad,
            result.posterior.abandoned,
            result.posterior.zombie,
        ] {
            assert!(value.is_finite(), "non-finite posterior for {}", case.case_id);
        }
    }
}

#[test]
fn test_monotonic_runtime_increases_abandoned() {
    let priors = load_priors_fixture();

    let short = Evidence {
        cpu: Some(CpuEvidence::Fraction { occupancy: 0.05 }),
        runtime_seconds: Some(600.0),
        orphan: Some(true),
        tty: Some(false),
        net: Some(false),
        io_active: Some(false),
        state_flag: None,
        command_category: None,
    };

    let long = Evidence {
        runtime_seconds: Some(3600.0 * 48.0),
        ..short.clone()
    };

    let short_result = compute_posterior(&priors, &short).expect("posterior short");
    let long_result = compute_posterior(&priors, &long).expect("posterior long");

    assert!(
        long_result.posterior.abandoned >= short_result.posterior.abandoned,
        "expected abandoned posterior to increase with runtime"
    );
}

#[test]
fn test_missing_evidence_graceful() {
    let priors = load_priors_fixture();
    let evidence = Evidence::default();
    let result = compute_posterior(&priors, &evidence).expect("posterior");

    for value in [
        result.posterior.useful,
        result.posterior.useful_bad,
        result.posterior.abandoned,
        result.posterior.zombie,
    ] {
        assert!(value.is_finite());
    }
}

#[test]
fn test_nan_evidence_rejected() {
    let priors = load_priors_fixture();
    let evidence = Evidence {
        cpu: Some(CpuEvidence::Fraction { occupancy: f64::NAN }),
        ..Evidence::default()
    };
    let err = compute_posterior(&priors, &evidence).unwrap_err();
    match err {
        pt_core::inference::PosteriorError::InvalidEvidence { field, .. } => {
            assert_eq!(field, "cpu.occupancy");
        }
        _ => {
            assert!(
                matches!(err, pt_core::inference::PosteriorError::InvalidEvidence { .. }),
                "unexpected error for nan evidence"
            );
        }
    }
}

#[test]
fn test_build_process_explanation_clamps_cpu() {
    let priors = load_priors_fixture();
    let proc = make_process(250.0);
    let explanation = build_process_explanation(&proc, &priors);

    assert!(explanation.get("error").is_none(), "expected clamp to avoid error");
}

#[test]
fn test_inference_log_fixture_schema() {
    let log_path = fixtures_dir().join("logs").join("inference_regression.jsonl");
    let contents = fs::read_to_string(&log_path).expect("read inference log fixture");

    for (idx, line) in contents.lines().enumerate() {
        let value: serde_json::Value = serde_json::from_str(line)
            .expect(&format!("invalid json at line {}", idx + 1));
        let obj = value
            .as_object()
            .expect(&format!("log line {} not object", idx + 1));

        for key in [
            "event",
            "timestamp",
            "phase",
            "case_id",
            "command",
            "exit_code",
            "duration_ms",
            "artifacts",
        ] {
            assert!(
                obj.contains_key(key),
                "log line {} missing {}",
                idx + 1,
                key
            );
        }

        assert!(obj.get("artifacts").unwrap().is_array());
    }
}
