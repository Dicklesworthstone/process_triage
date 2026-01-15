//! Decision theory utilities (expected loss, thresholds, FDR control).

pub mod expected_loss;
pub mod fdr_selection;

pub use expected_loss::{
    decide_action, Action, ActionFeasibility, DecisionError, DecisionOutcome, DecisionRationale,
    DisabledAction, ExpectedLoss, SprtBoundary,
};

pub use fdr_selection::{
    by_correction_factor, select_fdr, CandidateSelection, FdrCandidate, FdrError, FdrMethod,
    FdrSelectionResult, TargetIdentity,
};
