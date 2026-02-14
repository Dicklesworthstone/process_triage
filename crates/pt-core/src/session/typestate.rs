//! Typestate Session Lifecycle.
//!
//! Encodes the session state machine at the type level so that impossible
//! transitions are caught at compile time. Each phase is a zero-sized marker
//! type, and `TypedSession<S>` can only be transitioned via methods that
//! consume the old phase and return the new one.
//!
//! # State Machine
//!
//! ```text
//! Created ──▶ Scanning ──▶ Planned ──▶ Executing ──▶ Completed
//!   │            │            │            │
//!   ▼            ▼            ▼            ▼
//! Failed       Failed      Failed       Failed
//!   │            │            │            │
//!   ▼            ▼            ▼            ▼
//! Cancelled   Cancelled   Cancelled    Cancelled
//! ```
//!
//! # Backward Compatibility
//!
//! The existing `SessionState` enum is preserved as the runtime representation.
//! `TypedSession<S>` wraps session data with a compile-time phase marker.
//! Conversion methods bridge between typestate and enum representations.

use std::marker::PhantomData;

use serde::{Deserialize, Serialize};

use super::SessionState;

// ── Phase marker traits ─────────────────────────────────────────────────

/// Marker trait for session phases. Sealed to prevent external implementation.
pub trait SessionPhase: sealed::Sealed {
    /// The corresponding runtime `SessionState` variant.
    fn runtime_state() -> SessionState;
    /// Human-readable phase name.
    fn name() -> &'static str;
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Created {}
    impl Sealed for super::Scanning {}
    impl Sealed for super::Planned {}
    impl Sealed for super::Executing {}
    impl Sealed for super::Completed {}
    impl Sealed for super::Failed {}
    impl Sealed for super::Cancelled {}
}

// ── Phase types ─────────────────────────────────────────────────────────

/// Session has been created but no work has started.
#[derive(Debug, Clone, Copy)]
pub struct Created;

/// Session is actively scanning processes.
#[derive(Debug, Clone, Copy)]
pub struct Scanning;

/// Session scan is complete, plan has been generated.
#[derive(Debug, Clone, Copy)]
pub struct Planned;

/// Session is executing planned actions.
#[derive(Debug, Clone, Copy)]
pub struct Executing;

/// Session has completed successfully.
#[derive(Debug, Clone, Copy)]
pub struct Completed;

/// Session has failed.
#[derive(Debug, Clone, Copy)]
pub struct Failed;

/// Session has been cancelled.
#[derive(Debug, Clone, Copy)]
pub struct Cancelled;

impl SessionPhase for Created {
    fn runtime_state() -> SessionState {
        SessionState::Created
    }
    fn name() -> &'static str {
        "created"
    }
}

impl SessionPhase for Scanning {
    fn runtime_state() -> SessionState {
        SessionState::Scanning
    }
    fn name() -> &'static str {
        "scanning"
    }
}

impl SessionPhase for Planned {
    fn runtime_state() -> SessionState {
        SessionState::Planned
    }
    fn name() -> &'static str {
        "planned"
    }
}

impl SessionPhase for Executing {
    fn runtime_state() -> SessionState {
        SessionState::Executing
    }
    fn name() -> &'static str {
        "executing"
    }
}

impl SessionPhase for Completed {
    fn runtime_state() -> SessionState {
        SessionState::Completed
    }
    fn name() -> &'static str {
        "completed"
    }
}

impl SessionPhase for Failed {
    fn runtime_state() -> SessionState {
        SessionState::Failed
    }
    fn name() -> &'static str {
        "failed"
    }
}

impl SessionPhase for Cancelled {
    fn runtime_state() -> SessionState {
        SessionState::Cancelled
    }
    fn name() -> &'static str {
        "cancelled"
    }
}

// ── Session data ────────────────────────────────────────────────────────

/// Core session data shared across all phases.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    /// Session identifier.
    pub session_id: String,
    /// Human-readable label.
    pub label: Option<String>,
    /// Creation timestamp (ISO-8601).
    pub created_at: String,
    /// Optional error message (populated on failure).
    pub error: Option<String>,
}

// ── Typed session ───────────────────────────────────────────────────────

/// A session with compile-time phase tracking.
///
/// The phase `S` determines which transitions are available. Invalid
/// transitions (e.g., `Completed` → `Scanning`) are compile errors.
#[derive(Debug)]
pub struct TypedSession<S: SessionPhase> {
    data: SessionData,
    _phase: PhantomData<S>,
}

impl<S: SessionPhase> TypedSession<S> {
    /// Access the underlying session data.
    pub fn data(&self) -> &SessionData {
        &self.data
    }

    /// Get the runtime state corresponding to this phase.
    pub fn runtime_state(&self) -> SessionState {
        S::runtime_state()
    }

    /// Get the phase name.
    pub fn phase_name(&self) -> &'static str {
        S::name()
    }

    /// Get the session ID.
    pub fn session_id(&self) -> &str {
        &self.data.session_id
    }
}

// ── Creation ────────────────────────────────────────────────────────────

impl TypedSession<Created> {
    /// Create a new session in the `Created` phase.
    pub fn new(session_id: String, label: Option<String>) -> Self {
        Self {
            data: SessionData {
                session_id,
                label,
                created_at: chrono::Utc::now().to_rfc3339(),
                error: None,
            },
            _phase: PhantomData,
        }
    }

    /// Transition: Created → Scanning.
    pub fn start_scan(self) -> TypedSession<Scanning> {
        TypedSession {
            data: self.data,
            _phase: PhantomData,
        }
    }

    /// Transition: Created → Failed.
    pub fn fail(self, error: String) -> TypedSession<Failed> {
        let mut data = self.data;
        data.error = Some(error);
        TypedSession {
            data,
            _phase: PhantomData,
        }
    }

    /// Transition: Created → Cancelled.
    pub fn cancel(self) -> TypedSession<Cancelled> {
        TypedSession {
            data: self.data,
            _phase: PhantomData,
        }
    }
}

// ── Scanning transitions ────────────────────────────────────────────────

impl TypedSession<Scanning> {
    /// Transition: Scanning → Planned.
    pub fn finish_scan(self) -> TypedSession<Planned> {
        TypedSession {
            data: self.data,
            _phase: PhantomData,
        }
    }

    /// Transition: Scanning → Failed.
    pub fn fail(self, error: String) -> TypedSession<Failed> {
        let mut data = self.data;
        data.error = Some(error);
        TypedSession {
            data,
            _phase: PhantomData,
        }
    }

    /// Transition: Scanning → Cancelled.
    pub fn cancel(self) -> TypedSession<Cancelled> {
        TypedSession {
            data: self.data,
            _phase: PhantomData,
        }
    }
}

// ── Planned transitions ─────────────────────────────────────────────────

impl TypedSession<Planned> {
    /// Transition: Planned → Executing.
    pub fn start_execution(self) -> TypedSession<Executing> {
        TypedSession {
            data: self.data,
            _phase: PhantomData,
        }
    }

    /// Transition: Planned → Failed.
    pub fn fail(self, error: String) -> TypedSession<Failed> {
        let mut data = self.data;
        data.error = Some(error);
        TypedSession {
            data,
            _phase: PhantomData,
        }
    }

    /// Transition: Planned → Cancelled.
    pub fn cancel(self) -> TypedSession<Cancelled> {
        TypedSession {
            data: self.data,
            _phase: PhantomData,
        }
    }
}

// ── Executing transitions ───────────────────────────────────────────────

impl TypedSession<Executing> {
    /// Transition: Executing → Completed.
    pub fn complete(self) -> TypedSession<Completed> {
        TypedSession {
            data: self.data,
            _phase: PhantomData,
        }
    }

    /// Transition: Executing → Failed.
    pub fn fail(self, error: String) -> TypedSession<Failed> {
        let mut data = self.data;
        data.error = Some(error);
        TypedSession {
            data,
            _phase: PhantomData,
        }
    }

    /// Transition: Executing → Cancelled.
    pub fn cancel(self) -> TypedSession<Cancelled> {
        TypedSession {
            data: self.data,
            _phase: PhantomData,
        }
    }
}

// ── Terminal states (no transitions out) ────────────────────────────────

impl TypedSession<Completed> {
    /// Access the completion data.
    pub fn completion_data(&self) -> &SessionData {
        &self.data
    }
}

impl TypedSession<Failed> {
    /// Get the error that caused the failure.
    pub fn error(&self) -> Option<&str> {
        self.data.error.as_deref()
    }
}

impl TypedSession<Cancelled> {
    /// Access the cancellation data.
    pub fn cancellation_data(&self) -> &SessionData {
        &self.data
    }
}

// ── Conversion from runtime state ───────────────────────────────────────

/// Error when attempting to convert from a runtime state that doesn't
/// match the expected typestate phase.
#[derive(Debug, thiserror::Error)]
#[error("state mismatch: expected {expected}, got {actual:?}")]
pub struct StateMismatchError {
    pub expected: &'static str,
    pub actual: SessionState,
}

/// Convert from runtime `SessionData` + `SessionState` to a `TypedSession`.
///
/// Returns the appropriate `TypedSession` variant wrapped in an enum for
/// runtime dispatch.
#[derive(Debug)]
pub enum AnyTypedSession {
    Created(TypedSession<Created>),
    Scanning(TypedSession<Scanning>),
    Planned(TypedSession<Planned>),
    Executing(TypedSession<Executing>),
    Completed(TypedSession<Completed>),
    Failed(TypedSession<Failed>),
    Cancelled(TypedSession<Cancelled>),
}

impl AnyTypedSession {
    /// Wrap session data with the appropriate phase marker.
    pub fn from_runtime(data: SessionData, state: SessionState) -> Self {
        match state {
            SessionState::Created => AnyTypedSession::Created(TypedSession {
                data,
                _phase: PhantomData,
            }),
            SessionState::Scanning => AnyTypedSession::Scanning(TypedSession {
                data,
                _phase: PhantomData,
            }),
            SessionState::Planned => AnyTypedSession::Planned(TypedSession {
                data,
                _phase: PhantomData,
            }),
            SessionState::Executing => AnyTypedSession::Executing(TypedSession {
                data,
                _phase: PhantomData,
            }),
            SessionState::Completed => AnyTypedSession::Completed(TypedSession {
                data,
                _phase: PhantomData,
            }),
            SessionState::Failed => AnyTypedSession::Failed(TypedSession {
                data,
                _phase: PhantomData,
            }),
            SessionState::Cancelled | SessionState::Archived => {
                AnyTypedSession::Cancelled(TypedSession {
                    data,
                    _phase: PhantomData,
                })
            }
        }
    }

    /// Get the runtime state.
    pub fn runtime_state(&self) -> SessionState {
        match self {
            AnyTypedSession::Created(s) => s.runtime_state(),
            AnyTypedSession::Scanning(s) => s.runtime_state(),
            AnyTypedSession::Planned(s) => s.runtime_state(),
            AnyTypedSession::Executing(s) => s.runtime_state(),
            AnyTypedSession::Completed(s) => s.runtime_state(),
            AnyTypedSession::Failed(s) => s.runtime_state(),
            AnyTypedSession::Cancelled(s) => s.runtime_state(),
        }
    }

    /// Get the session data regardless of phase.
    pub fn data(&self) -> &SessionData {
        match self {
            AnyTypedSession::Created(s) => s.data(),
            AnyTypedSession::Scanning(s) => s.data(),
            AnyTypedSession::Planned(s) => s.data(),
            AnyTypedSession::Executing(s) => s.data(),
            AnyTypedSession::Completed(s) => s.data(),
            AnyTypedSession::Failed(s) => s.data(),
            AnyTypedSession::Cancelled(s) => s.data(),
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_path_lifecycle() {
        let session = TypedSession::new("test-1".to_string(), Some("test".to_string()));
        assert_eq!(session.runtime_state(), SessionState::Created);
        assert_eq!(session.phase_name(), "created");

        let session = session.start_scan();
        assert_eq!(session.runtime_state(), SessionState::Scanning);

        let session = session.finish_scan();
        assert_eq!(session.runtime_state(), SessionState::Planned);

        let session = session.start_execution();
        assert_eq!(session.runtime_state(), SessionState::Executing);

        let session = session.complete();
        assert_eq!(session.runtime_state(), SessionState::Completed);
        assert_eq!(session.session_id(), "test-1");
    }

    #[test]
    fn fail_from_created() {
        let session = TypedSession::new("test-2".to_string(), None);
        let failed = session.fail("early error".to_string());
        assert_eq!(failed.runtime_state(), SessionState::Failed);
        assert_eq!(failed.error(), Some("early error"));
    }

    #[test]
    fn fail_from_scanning() {
        let session = TypedSession::new("test-3".to_string(), None);
        let scanning = session.start_scan();
        let failed = scanning.fail("scan error".to_string());
        assert_eq!(failed.error(), Some("scan error"));
    }

    #[test]
    fn fail_from_executing() {
        let session = TypedSession::new("test-4".to_string(), None);
        let executing = session.start_scan().finish_scan().start_execution();
        let failed = executing.fail("execution error".to_string());
        assert_eq!(failed.error(), Some("execution error"));
    }

    #[test]
    fn cancel_from_any_active_phase() {
        let s1 = TypedSession::new("c1".to_string(), None);
        let c1 = s1.cancel();
        assert_eq!(c1.runtime_state(), SessionState::Cancelled);

        let s2 = TypedSession::new("c2".to_string(), None);
        let c2 = s2.start_scan().cancel();
        assert_eq!(c2.runtime_state(), SessionState::Cancelled);

        let s3 = TypedSession::new("c3".to_string(), None);
        let c3 = s3.start_scan().finish_scan().cancel();
        assert_eq!(c3.runtime_state(), SessionState::Cancelled);

        let s4 = TypedSession::new("c4".to_string(), None);
        let c4 = s4.start_scan().finish_scan().start_execution().cancel();
        assert_eq!(c4.runtime_state(), SessionState::Cancelled);
    }

    #[test]
    fn session_data_preserved_across_transitions() {
        let session = TypedSession::new("data-test".to_string(), Some("my label".to_string()));
        let created_at = session.data().created_at.clone();

        let completed = session
            .start_scan()
            .finish_scan()
            .start_execution()
            .complete();

        assert_eq!(completed.data().session_id, "data-test");
        assert_eq!(completed.data().label, Some("my label".to_string()));
        assert_eq!(completed.data().created_at, created_at);
    }

    #[test]
    fn any_typed_session_runtime_dispatch() {
        let data = SessionData {
            session_id: "any-1".to_string(),
            label: None,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            error: None,
        };

        let any = AnyTypedSession::from_runtime(data.clone(), SessionState::Scanning);
        assert_eq!(any.runtime_state(), SessionState::Scanning);
        assert_eq!(any.data().session_id, "any-1");
    }

    #[test]
    fn any_typed_session_all_states() {
        let data = SessionData {
            session_id: "all".to_string(),
            label: None,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            error: None,
        };

        for state in &[
            SessionState::Created,
            SessionState::Scanning,
            SessionState::Planned,
            SessionState::Executing,
            SessionState::Completed,
            SessionState::Failed,
            SessionState::Cancelled,
            SessionState::Archived,
        ] {
            let any = AnyTypedSession::from_runtime(data.clone(), *state);
            // Archived maps to Cancelled
            let expected = if *state == SessionState::Archived {
                SessionState::Cancelled
            } else {
                *state
            };
            assert_eq!(any.runtime_state(), expected);
        }
    }

    #[test]
    fn phase_names() {
        assert_eq!(Created::name(), "created");
        assert_eq!(Scanning::name(), "scanning");
        assert_eq!(Planned::name(), "planned");
        assert_eq!(Executing::name(), "executing");
        assert_eq!(Completed::name(), "completed");
        assert_eq!(Failed::name(), "failed");
        assert_eq!(Cancelled::name(), "cancelled");
    }

    #[test]
    fn session_data_serde() {
        let data = SessionData {
            session_id: "serde-test".to_string(),
            label: Some("test".to_string()),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            error: None,
        };
        let json = serde_json::to_string(&data).unwrap();
        let back: SessionData = serde_json::from_str(&json).unwrap();
        assert_eq!(back.session_id, "serde-test");
    }
}
