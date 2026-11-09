//! Process replay and simulation mode.
//!
//! Provides private live snapshots and shared-scoring replay for regression
//! analysis without inspecting the replay machine's processes. The shipped
//! `scan --record-replay` / `scan --replay-scores` commands preserve the census
//! denominator and reject incomplete scoring context. Replay scores do not
//! authorize actions or establish full production decision parity.
//!
//! The older `replay_inference` API below remains an unconstrained mathematical
//! demonstration, not the production decision or protection path.
//!
//! # Recording
//!
//! ```ignore
//! use pt_core::replay::{record_snapshot, ReplaySnapshot};
//! use pt_core::collect::quick_scan;
//!
//! let scan = quick_scan(Default::default())?;
//! let snapshot = record_snapshot(&scan, None)?;
//! snapshot.save("my_snapshot.json")?;
//! ```
//!
//! # Replay
//!
//! ```ignore
//! use pt_core::replay::{load_snapshot, replay_inference};
//! use pt_core::config::{Policy, Priors};
//!
//! let snapshot = load_snapshot("my_snapshot.json")?;
//! let results = replay_inference(&snapshot, &priors, &policy)?;
//! for r in &results {
//!     println!("{}: {} -> {:?}", r.pid, r.classification, r.recommended_action);
//! }
//! ```
//!
//! # Built-in Scenarios
//!
//! Pre-built scenarios for common testing and demonstration:
//!
//! ```ignore
//! use pt_core::replay::scenarios;
//!
//! let snapshot = scenarios::zombie_tree();
//! let snapshot = scenarios::memory_leak();
//! let snapshot = scenarios::mixed_workload();
//! ```

pub mod evaluation;
pub mod scenarios;
pub mod snapshot;

pub use evaluation::{
    evaluate_pair, make_review_template, read_review_labels, EvaluationCoverage,
    EvaluationSide, PairedEvaluationReport, PairedProbabilityMetrics, PairedProcessScore,
    ProbabilityMetricDelta, ProbabilityMetrics, ProcessReview, ReplayEvaluationError,
    ReviewLabels, ReviewSplit, ReviewVerdict,
};

pub use snapshot::{
    capture_snapshot, load_snapshot, record_snapshot, replay_inference, replay_scores,
    DeepSignalRecord, ReplayError, ReplayInferenceResult, ReplayMetadata, ReplayProcessInputs,
    ReplayScoreResult, ReplayScoreStatus, ReplayScoringContext, ReplayScoringReport, ReplaySnapshot,
    SystemContext,
};

pub use scenarios::{ci_build, dev_machine, memory_leak, mixed_workload, stuck_tests, zombie_tree};
