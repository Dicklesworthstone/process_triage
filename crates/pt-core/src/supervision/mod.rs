//! Process supervision detection.
//!
//! This module provides capabilities for detecting whether a process is being
//! supervised by an AI agent, IDE, CI system, or other automation tool.
//!
//! # Why Supervision Detection Matters
//!
//! Supervised processes should NEVER be auto-killed. Killing a supervised process
//! could corrupt an ongoing AI workflow, lose unsaved work, or break a CI pipeline.
//! This is a critical safety mechanism that distinguishes between "abandoned by user"
//! and "managed by automation".
//!
//! # Detection Methods
//!
//! - **Ancestry**: Parent or ancestor matches supervisor pattern
//! - **Environment**: Variables like CLAUDE_SESSION_ID, VSCODE_PID, etc.
//! - **Sockets**: Connected to known supervisor IPC paths
//! - **Locks**: PID files in known automation directories (future)
//! - **TTY**: Terminal attribution for tmux/screen sessions (future)
//!
//! # Example
//!
//! ```no_run
//! use pt_core::supervision::{SupervisionDetector, detect_supervision};
//!
//! // Quick check for a single process
//! let result = detect_supervision(1234).unwrap();
//! if result.is_supervised {
//!     println!(
//!         "Process is supervised by {:?} ({})",
//!         result.supervisor_type,
//!         result.supervisor_name.unwrap_or_default()
//!     );
//! }
//!
//! // More detailed analysis with combined detector
//! let mut detector = SupervisionDetector::new();
//! let result = detector.detect(1234).unwrap();
//! println!("Supervised: {}, Confidence: {}", result.is_supervised, result.confidence);
//! for evidence in &result.evidence {
//!     println!("  - {} (weight: {})", evidence.description, evidence.weight);
//! }
//! ```

mod ancestry;
mod environ;
mod ipc;
mod nohup;
mod orphan;
mod signature;
#[cfg(test)]
mod supervision_tests;
mod types;

pub use ancestry::{
    analyze_supervision, analyze_supervision_batch, AncestryAnalyzer, AncestryConfig,
    AncestryError, ProcessTreeCache,
};
pub use environ::{
    detect_environ_supervision, EnvPattern, EnvironAnalyzer, EnvironDatabase, EnvironError,
    EnvironResult,
};
pub use ipc::{
    detect_ipc_supervision, IpcAnalyzer, IpcDatabase, IpcError, IpcPattern, IpcResult,
};
pub use nohup::{
    check_signal_mask, detect_disown, detect_nohup, read_fd_info, read_signal_mask,
    BackgroundIntent, FdInfo, NohupAnalyzer, NohupError, NohupOutputActivity, NohupResult,
    SignalMask,
};
pub use orphan::{
    detect_container, detect_unexpected_reparenting, is_orphaned, NohupSummary, OrphanAnalyzer,
    OrphanError, OrphanResult, ReparentingReason, SupervisionSummary,
};
pub use signature::{
    SignatureDatabase, SignatureError, SignatureMetadata, SignaturePatterns, SignatureSchema,
    SupervisorSignature, SCHEMA_VERSION,
};
pub use types::{
    AncestryEntry, EvidenceType, SupervisionEvidence, SupervisionResult, SupervisorCategory,
    SupervisorDatabase, SupervisorPattern,
};

use thiserror::Error;

/// Errors from combined supervision detection.
#[derive(Debug, Error)]
pub enum DetectionError {
    #[error("Ancestry analysis failed: {0}")]
    Ancestry(#[from] AncestryError),

    #[error("Environment analysis failed: {0}")]
    Environment(#[from] EnvironError),

    #[error("IPC analysis failed: {0}")]
    Ipc(#[from] IpcError),

    #[error("Process {0} not found")]
    ProcessNotFound(u32),
}

/// Combined supervision detection result.
#[derive(Debug, Clone)]
pub struct CombinedResult {
    /// Whether supervision was detected.
    pub is_supervised: bool,
    /// Primary supervisor name (highest confidence).
    pub supervisor_name: Option<String>,
    /// Primary supervisor type.
    pub supervisor_type: Option<SupervisorCategory>,
    /// Combined confidence score (max of all methods).
    pub confidence: f64,
    /// All evidence from all detection methods.
    pub evidence: Vec<SupervisionEvidence>,
    /// Result from ancestry analysis.
    pub ancestry: Option<SupervisionResult>,
    /// Result from environment analysis.
    pub environ: Option<EnvironResult>,
    /// Result from IPC analysis.
    pub ipc: Option<IpcResult>,
}

impl CombinedResult {
    /// Create a result indicating no supervision detected.
    pub fn not_supervised() -> Self {
        Self {
            is_supervised: false,
            supervisor_name: None,
            supervisor_type: None,
            confidence: 0.0,
            evidence: vec![],
            ancestry: None,
            environ: None,
            ipc: None,
        }
    }
}

/// Combined supervision detector using all available methods.
pub struct SupervisionDetector {
    ancestry: AncestryAnalyzer,
    environ: EnvironAnalyzer,
    ipc: IpcAnalyzer,
}

impl SupervisionDetector {
    /// Create a new detector with default configurations.
    pub fn new() -> Self {
        Self {
            ancestry: AncestryAnalyzer::new(),
            environ: EnvironAnalyzer::new(),
            ipc: IpcAnalyzer::new(),
        }
    }

    /// Pre-populate the process tree cache for efficient batch analysis.
    #[cfg(target_os = "linux")]
    pub fn populate_cache(&mut self) -> Result<(), AncestryError> {
        self.ancestry.populate_cache()
    }

    #[cfg(not(target_os = "linux"))]
    pub fn populate_cache(&mut self) -> Result<(), AncestryError> {
        Ok(())
    }

    /// Detect supervision using all available methods.
    pub fn detect(&mut self, pid: u32) -> Result<CombinedResult, DetectionError> {
        let mut result = CombinedResult::not_supervised();
        let mut best_confidence = 0.0f64;
        let mut best_name: Option<String> = None;
        let mut best_type: Option<SupervisorCategory> = None;

        // Try ancestry analysis
        match self.ancestry.analyze(pid) {
            Ok(ancestry_result) => {
                if ancestry_result.is_supervised {
                    result.evidence.extend(ancestry_result.evidence.clone());
                    if ancestry_result.confidence > best_confidence {
                        best_confidence = ancestry_result.confidence;
                        best_name = ancestry_result.supervisor_name.clone();
                        best_type = ancestry_result.supervisor_type;
                    }
                }
                result.ancestry = Some(ancestry_result);
            }
            Err(AncestryError::ProcessNotFound(_)) => {
                return Err(DetectionError::ProcessNotFound(pid));
            }
            Err(_) => {
                // Other errors are non-fatal, continue with other methods
            }
        }

        // Try environment analysis
        match self.environ.analyze(pid) {
            Ok(environ_result) => {
                if environ_result.is_supervised {
                    result.evidence.extend(environ_result.evidence.clone());
                    if environ_result.confidence > best_confidence {
                        best_confidence = environ_result.confidence;
                        best_name = environ_result.supervisor_name.clone();
                        best_type = environ_result.category;
                    }
                }
                result.environ = Some(environ_result);
            }
            Err(EnvironError::ProcessNotFound(_)) => {
                // Already checked in ancestry, skip
            }
            Err(_) => {
                // Non-fatal, continue
            }
        }

        // Try IPC analysis
        match self.ipc.analyze(pid) {
            Ok(ipc_result) => {
                if ipc_result.is_supervised {
                    result.evidence.extend(ipc_result.evidence.clone());
                    if ipc_result.confidence > best_confidence {
                        best_confidence = ipc_result.confidence;
                        best_name = ipc_result.supervisor_name.clone();
                        best_type = ipc_result.category;
                    }
                }
                result.ipc = Some(ipc_result);
            }
            Err(IpcError::ProcessNotFound(_) | IpcError::PermissionDenied(_)) => {
                // Expected for many processes, non-fatal
            }
            Err(_) => {
                // Non-fatal, continue
            }
        }

        // Combine results
        result.is_supervised = best_confidence > 0.0;
        result.confidence = best_confidence;
        result.supervisor_name = best_name;
        result.supervisor_type = best_type;

        Ok(result)
    }
}

impl Default for SupervisionDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience function for detecting supervision with all methods.
pub fn detect_supervision(pid: u32) -> Result<CombinedResult, DetectionError> {
    let mut detector = SupervisionDetector::new();
    detector.detect(pid)
}

/// Detect supervision for multiple processes efficiently.
pub fn detect_supervision_batch(
    pids: &[u32],
) -> Result<Vec<(u32, CombinedResult)>, DetectionError> {
    let mut detector = SupervisionDetector::new();

    // Pre-populate cache for efficiency
    #[cfg(target_os = "linux")]
    detector.populate_cache()?;

    let mut results = Vec::with_capacity(pids.len());
    for &pid in pids {
        match detector.detect(pid) {
            Ok(result) => results.push((pid, result)),
            Err(DetectionError::ProcessNotFound(_)) => {
                // Process may have exited, skip it
                continue;
            }
            Err(e) => return Err(e),
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supervision_detector_new() {
        let detector = SupervisionDetector::new();
        // Just ensure it creates without panic
        let _ = detector;
    }

    #[test]
    fn test_combined_result_not_supervised() {
        let result = CombinedResult::not_supervised();
        assert!(!result.is_supervised);
        assert!(result.supervisor_name.is_none());
        assert!(result.evidence.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_detect_supervision_current_process() {
        let pid = std::process::id();
        let result = detect_supervision(pid);

        // Should succeed for current process
        assert!(result.is_ok());

        let result = result.unwrap();
        // May or may not be supervised depending on environment
        // Just check the structure is valid
        assert!(result.confidence >= 0.0);
        assert!(result.confidence <= 1.0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_detect_supervision_batch() {
        let pid = std::process::id();
        let results = detect_supervision_batch(&[pid]);

        assert!(results.is_ok());
        let results = results.unwrap();
        assert!(!results.is_empty());
    }
}
