use pt_core::inference::ledger::{Classification, EvidenceLedger};
use pt_core::inference::posterior::{ClassScores, PosteriorResult};

#[test]
fn test_ledger_classification_useful_bad() {
    let result = PosteriorResult {
        posterior: ClassScores {
            useful: 0.1,
            useful_bad: 0.8, 
            abandoned: 0.05,
            zombie: 0.05,
        },
        log_posterior: ClassScores {
            useful: (0.1f64).ln(),
            useful_bad: (0.8f64).ln(),
            abandoned: (0.05f64).ln(),
            zombie: (0.05f64).ln(),
        },
        log_odds_abandoned_useful: (0.05f64 / 0.1f64).ln(),
        evidence_terms: vec![],
    };

    let ledger = EvidenceLedger::from_posterior_result(&result, None, None);

    assert_eq!(ledger.classification, Classification::UsefulBad, 
        "Expected UsefulBad classification, got {:?}", ledger.classification);
}

#[test]
fn test_ledger_classification_zombie() {
    let result = PosteriorResult {
        posterior: ClassScores {
            useful: 0.05,
            useful_bad: 0.05,
            abandoned: 0.1,
            zombie: 0.8, 
        },
        log_posterior: ClassScores {
            useful: (0.05f64).ln(),
            useful_bad: (0.05f64).ln(),
            abandoned: (0.1f64).ln(),
            zombie: (0.8f64).ln(),
        },
        log_odds_abandoned_useful: (0.1f64 / 0.05f64).ln(),
        evidence_terms: vec![],
    };

    let ledger = EvidenceLedger::from_posterior_result(&result, None, None);

    assert_eq!(ledger.classification, Classification::Zombie, 
        "Expected Zombie classification, got {:?}", ledger.classification);
}
