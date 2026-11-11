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
//! - **Environment**: Variables like CLAUDECODE, CLAUDE_CODE_SESSION_ID, VSCODE_PID, etc.
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
mod app_supervision;
pub mod blast_radius;
#[cfg(target_os = "linux")]
mod container_supervision;
mod environ;
mod ipc;
pub mod narrative;
mod nohup;
mod orphan;
pub mod pattern_learning;
pub mod pattern_persistence;
pub mod session;
pub mod signature;
#[cfg(test)]
mod supervision_tests;
mod types;

pub use ancestry::{
    analyze_supervision, analyze_supervision_batch, AncestryAnalyzer, AncestryConfig,
    AncestryError, ProcessTreeCache,
};
pub use app_supervision::{
    detect_app_supervision, AlternativeAction, AppActionType, AppSupervisionAnalyzer,
    AppSupervisionError, AppSupervisionResult, AppSupervisorAction, AppSupervisorType,
};
#[cfg(target_os = "linux")]
pub use container_supervision::{
    detect_container_supervision, detect_container_supervision_with_actions, ContainerAction,
    ContainerActionType, ContainerSupervisionAnalyzer, ContainerSupervisionError,
    ContainerSupervisionResult,
};
pub use environ::{
    detect_environ_supervision, read_environ, EnvPattern, EnvironAnalyzer, EnvironDatabase,
    EnvironError, EnvironResult,
};
pub use ipc::{detect_ipc_supervision, IpcAnalyzer, IpcDatabase, IpcError, IpcPattern, IpcResult};
pub use nohup::{
    check_signal_mask, detect_disown, detect_nohup, read_fd_info, read_signal_mask,
    BackgroundIntent, FdInfo, NohupAnalyzer, NohupError, NohupOutputActivity, NohupResult,
    SignalMask,
};
pub use orphan::{
    detect_container, detect_unexpected_reparenting, is_orphaned, NohupSummary, OrphanAnalyzer,
    OrphanError, OrphanResult, ReparentingReason, SupervisionSummary,
};
pub use pattern_learning::{
    CommandNormalizer, DecisionAction, LearningError, PatternCandidate, PatternLearner,
    PatternObservation, SpecificityLevel,
};
pub use pattern_persistence::{
    migrate_schema, AllPatternStats, ConfidenceSnapshot, ConflictResolution, DisabledPatterns,
    ImportConflict, ImportResult, PatternLibrary, PatternLifecycle, PatternSource, PatternStats,
    PersistedPattern, PersistedSchema, PersistenceError, SchemaMetadata,
};
pub use session::{
    check_session_protection, is_in_protected_session, ScreenInfo, SessionAnalyzer, SessionConfig,
    SessionError, SessionEvidence, SessionProtectionType, SessionResult, SshConnectionInfo,
    TmuxInfo,
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

    #[error("Process {0} changed while reading supervision evidence")]
    ProcessChanged(u32),
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

/// Returns true if supervision should require human confirmation.
///
/// We treat AI agents, IDEs, CI, and terminal multiplexers as human-supervised
/// contexts that should never be auto-acted on in robot mode. The primary
/// supervisor is only a diagnostic ranking: a stronger or equal-confidence
/// orchestrator cannot cancel independent evidence requiring confirmation.
pub fn is_human_supervised(result: &CombinedResult) -> bool {
    let requires_confirmation = |supervised: bool, category: Option<SupervisorCategory>| {
        supervised && category.is_none_or(SupervisorCategory::requires_human_confirmation)
    };
    requires_confirmation(result.is_supervised, result.supervisor_type)
        || result.ancestry.as_ref().is_some_and(|ancestry| {
            ancestry.human_supervised
                || requires_confirmation(ancestry.is_supervised, ancestry.supervisor_type)
        })
        || result.environ.as_ref().is_some_and(|environ| {
            environ.human_supervised
                || requires_confirmation(environ.is_supervised, environ.category)
        })
        || result.ipc.as_ref().is_some_and(|ipc| {
            ipc.human_supervised || requires_confirmation(ipc.is_supervised, ipc.category)
        })
}

/// Combined supervision detector using all available methods.
pub struct SupervisionDetector {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    ancestry: AncestryAnalyzer,
    environ: EnvironAnalyzer,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
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

    /// Share strict IPC table observations within one read-only scan. Required
    /// per-process and namespace evidence stays live. Action-time authorization
    /// must use `new()` so negative IPC evidence is refreshed before acting.
    /// Construct a new detector for every scan or watch refresh; views do not expire.
    pub fn for_scan() -> Self {
        Self {
            ancestry: AncestryAnalyzer::new(),
            environ: EnvironAnalyzer::new(),
            ipc: IpcAnalyzer::for_scan(),
        }
    }

    /// Pre-populate observed identities; detection refreshes required evidence.
    #[cfg(target_os = "linux")]
    pub fn populate_cache(&mut self) -> Result<(), AncestryError> {
        self.ancestry.populate_cache()
    }

    #[cfg(not(target_os = "linux"))]
    pub fn populate_cache(&mut self) -> Result<(), AncestryError> {
        Ok(())
    }

    /// Detect supervision using all available methods.
    #[cfg(target_os = "linux")]
    pub fn detect(&mut self, pid: u32) -> Result<CombinedResult, DetectionError> {
        let before = ancestry::read_stat(pid).map_err(|error| match error {
            AncestryError::ProcessNotFound(missing) if missing == pid => {
                DetectionError::ProcessNotFound(pid)
            }
            other => DetectionError::Ancestry(other),
        })?;
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
            Err(AncestryError::ProcessNotFound(missing)) if missing == pid => {
                return Err(DetectionError::ProcessNotFound(pid));
            }
            Err(error) => return Err(error.into()),
        }

        // Try environment analysis
        let environ_result = self.environ.analyze(pid)?;
        if environ_result.is_supervised {
            result.evidence.extend(environ_result.evidence.clone());
            if environ_result.confidence > best_confidence {
                best_confidence = environ_result.confidence;
                best_name = environ_result.supervisor_name.clone();
                best_type = environ_result.category;
            }
        }
        result.environ = Some(environ_result);

        // Try IPC analysis
        let ipc_result = self.ipc.analyze(pid)?;
        if ipc_result.is_supervised {
            result.evidence.extend(ipc_result.evidence.clone());
            if ipc_result.confidence > best_confidence {
                best_confidence = ipc_result.confidence;
                best_name = ipc_result.supervisor_name.clone();
                best_type = ipc_result.category;
            }
        }
        result.ipc = Some(ipc_result);

        let after = ancestry::read_stat(pid)?;
        if after.starttime != before.starttime
            || after.ppid != before.ppid
            || after.comm != before.comm
        {
            return Err(DetectionError::ProcessChanged(pid));
        }

        // Combine results
        result.is_supervised = best_confidence > 0.0;
        result.confidence = best_confidence;
        result.supervisor_name = best_name;
        result.supervisor_type = best_type;

        Ok(result)
    }

    /// Detect supervision where ancestry and IPC evidence (/proc) do not exist.
    ///
    /// These platforms use the supported environment probe. Its failure is not
    /// evidence of an unsupervised process: propagate it to every planning and
    /// execution caller. Missing Linux-only probes remain outside this probe's
    /// scope, so readable environment evidence still succeeds on macOS.
    #[cfg(not(target_os = "linux"))]
    pub fn detect(&mut self, pid: u32) -> Result<CombinedResult, DetectionError> {
        environment_only_supervision(self.environ.analyze(pid))
    }
}

#[cfg(any(not(target_os = "linux"), test))]
fn environment_only_supervision(
    observation: Result<EnvironResult, EnvironError>,
) -> Result<CombinedResult, DetectionError> {
    let environ = observation?;
    let mut result = CombinedResult::not_supervised();
    if environ.is_supervised {
        result.evidence.extend(environ.evidence.clone());
        result.is_supervised = true;
        result.confidence = environ.confidence;
        result.supervisor_name = environ.supervisor_name.clone();
        result.supervisor_type = environ.category;
    }
    result.environ = Some(environ);
    Ok(result)
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

    fn combined_orchestrator() -> CombinedResult {
        let mut result = CombinedResult::not_supervised();
        result.is_supervised = true;
        result.supervisor_name = Some("systemd".to_string());
        result.supervisor_type = Some(SupervisorCategory::Orchestrator);
        result.confidence = 0.95;
        result.ancestry = Some(SupervisionResult::supervised_by_ancestry(
            SupervisorCategory::Orchestrator,
            "systemd".to_string(),
            pt_common::ProcessId(1),
            1,
            0.95,
            Vec::new(),
            Vec::new(),
        ));
        result
    }

    #[test]
    fn human_signals_survive_stronger_and_equal_orchestrator_evidence() {
        for (name, value) in [
            ("CLAUDECODE", "1"),
            ("CODEX_SESSION_ID", "owned-session"),
            ("VSCODE_PID", "42"),
            ("CI", "true"),
            ("TMUX", "/tmp/tmux-1000/default,42,0"),
        ] {
            let environment = std::collections::HashMap::from([(
                name.to_string(),
                value.to_string(),
            )]);
            let mut result = combined_orchestrator();
            result.environ = Some(EnvironAnalyzer::new().analyze_env(&environment));
            assert!(
                is_human_supervised(&result),
                "independent {name} evidence cannot be canceled: {result:?}"
            );
            assert_eq!(result.supervisor_type, Some(SupervisorCategory::Orchestrator));
            assert_eq!(result.confidence, 0.95);
        }
    }

    #[test]
    fn human_ipc_survives_an_orchestrator_environment() {
        let mut result = combined_orchestrator();
        let environment = std::collections::HashMap::from([(
            "XPC_SERVICE_NAME".to_string(),
            "com.example.service".to_string(),
        )]);
        result.environ = Some(EnvironAnalyzer::new().analyze_env(&environment));
        result.ipc = Some(IpcAnalyzer::new().analyze_sockets(&[
            "/run/user/1000/systemd/private".to_string(),
            "/tmp/tmux-1000/default".to_string(),
        ]));
        assert!(is_human_supervised(&result));
        assert_eq!(
            result.ipc.as_ref().unwrap().category,
            Some(SupervisorCategory::Orchestrator)
        );
        assert_eq!(result.supervisor_type, Some(SupervisorCategory::Orchestrator));
    }

    #[test]
    fn legacy_ancestry_human_categories_remain_protected() {
        let ancestry = SupervisionResult::supervised_by_ancestry(
            SupervisorCategory::Agent,
            "claude".to_string(),
            pt_common::ProcessId(42),
            1,
            0.95,
            Vec::new(),
            vec![AncestryEntry {
                pid: pt_common::ProcessId(42),
                comm: "claude".to_string(),
                cmdline: None,
            }],
        );
        let mut encoded = serde_json::to_value(ancestry).unwrap();
        encoded.as_object_mut().unwrap().remove("human_supervised");
        let decoded: SupervisionResult = serde_json::from_value(encoded).unwrap();
        assert!(!decoded.human_supervised);
        let mut result = combined_orchestrator();
        result.ancestry = Some(decoded);
        assert!(is_human_supervised(&result));
    }

    #[test]
    fn pure_orchestrators_preserve_supervisor_aware_routing() {
        let mut result = combined_orchestrator();
        let environment = std::collections::HashMap::from([(
            "XPC_SERVICE_NAME".to_string(),
            "com.example.service".to_string(),
        )]);
        result.environ = Some(EnvironAnalyzer::new().analyze_env(&environment));
        result.ipc = Some(
            IpcAnalyzer::new().analyze_sockets(&["/run/user/1000/systemd/private".to_string()]),
        );
        assert!(!is_human_supervised(&result));
        assert!(!is_human_supervised(&CombinedResult::not_supervised()));

        // A positive supervision result with no classified category still needs
        // confirmation; aggregation must not turn incomplete evidence into permission.
        result.supervisor_type = None;
        assert!(is_human_supervised(&result));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_detect_supervision_current_process() {
        let pid = std::process::id();
        let result = detect_supervision(pid);

        // Should succeed for current process
        assert!(result.is_ok());

        let result = result.unwrap();
        assert!(result.ancestry.is_some());
        assert!(result.environ.is_some());
        assert!(result.ipc.is_some());
        // May or may not be supervised depending on environment
        // Just check the structure is valid
        assert!(result.confidence >= 0.0);
        assert!(result.confidence <= 1.0);
    }

    #[test]
    fn environment_only_detection_preserves_probe_failures() {
        for error in [
            EnvironError::ProcessNotFound(1234),
            EnvironError::Unsupported(1234),
            EnvironError::Parse {
                pid: 1234,
                reason: "truncated evidence".to_string(),
            },
            EnvironError::IoError {
                pid: 1234,
                source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
            },
        ] {
            let expected = error.to_string();
            let observed = environment_only_supervision(Err(error)).unwrap_err();
            assert!(matches!(observed, DetectionError::Environment(_)));
            assert!(observed.to_string().contains(&expected));
        }
    }

    #[test]
    fn environment_only_detection_keeps_readable_negative_and_human_evidence() {
        let analyzer = EnvironAnalyzer::new();
        let negative = environment_only_supervision(Ok(
            analyzer.analyze_env(&std::collections::HashMap::new())
        ))
        .expect("an observed environment needs no Linux-only probes");
        assert!(!negative.is_supervised);
        assert!(!is_human_supervised(&negative));
        assert!(negative.environ.is_some());
        assert!(negative.ancestry.is_none());
        assert!(negative.ipc.is_none());

        for marker in ["CLAUDECODE", "CODEX_SESSION_ID", "VSCODE_PID", "TMUX"] {
            let environment = std::collections::HashMap::from([
                (
                    "XPC_SERVICE_NAME".to_string(),
                    "com.example.service".to_string(),
                ),
                (marker.to_string(), "present".to_string()),
            ]);
            let observed = environment_only_supervision(Ok(analyzer.analyze_env(&environment)))
                .expect("readable supervision evidence");
            assert!(observed.is_supervised, "{marker}: {observed:?}");
            assert!(is_human_supervised(&observed), "{marker}: {observed:?}");
            assert!(observed.environ.is_some());
        }
    }

    /// Missing Linux-only evidence is not an error when the supported macOS
    /// environment probe succeeds.
    #[cfg(target_os = "macos")]
    #[test]
    fn test_detect_supervision_current_process_macos() {
        let result = detect_supervision(std::process::id()).expect("detection on macOS");
        assert!(result.ancestry.is_none());
        assert!(result.ipc.is_none());
        assert!(result.environ.is_some());
        assert!(result.confidence >= 0.0 && result.confidence <= 1.0);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_missing_process_is_not_observed_unsupervised() {
        assert!(matches!(
            detect_supervision(u32::MAX),
            Err(DetectionError::Environment(_))
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_owned_agent_child_retains_human_supervision() {
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .env("CODEX_SESSION_ID", "pt-macos-supervision-regression")
            .spawn()
            .expect("spawn an owned process with known supervision evidence");
        let observed = detect_supervision(child.id());
        let _ = child.kill();
        let _ = child.wait();
        let observed = observed.expect("read the owned child's environment");
        assert!(is_human_supervised(&observed), "{observed:?}");
        assert!(observed
            .environ
            .as_ref()
            .unwrap()
            .matched_vars
            .iter()
            .any(|(key, _)| key == "CODEX_SESSION_ID"));
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
