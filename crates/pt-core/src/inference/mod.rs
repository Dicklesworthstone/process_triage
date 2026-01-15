//! Inference engine modules.

pub mod posterior;

pub use posterior::{
    compute_posterior, ClassScores, CpuEvidence, Evidence, EvidenceTerm, PosteriorError,
    PosteriorResult,
};
