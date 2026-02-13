//! Process replay and simulation mode.
//!
//! Provides the ability to record live scan snapshots and replay them through
//! the inference/decision pipeline for deterministic testing, demonstration,
//! and bug reproduction.
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

pub mod scenarios;
pub mod snapshot;

pub use snapshot::{
    load_snapshot, record_snapshot, replay_inference, DeepSignalRecord, ReplayError,
    ReplayInferenceResult, ReplayMetadata, ReplaySnapshot, SystemContext,
};

pub use scenarios::{ci_build, dev_machine, memory_leak, mixed_workload, stuck_tests, zombie_tree};
