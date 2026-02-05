//! Progress event emission system.
//!
//! Provides lightweight, structured progress events for TUI and agent CLI
//! consumers. Events are dispatched through an in-process event bus that
//! supports multiple subscribers and JSONL formatting.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::io::Write;
use std::sync::{mpsc, Arc, Mutex};

/// Standard progress event names.
pub mod event_names {
    pub const SESSION_STARTED: &str = "session_started";
    pub const SESSION_ENDED: &str = "session_ended";

    pub const QUICK_SCAN_STARTED: &str = "quick_scan_started";
    pub const QUICK_SCAN_PROGRESS: &str = "quick_scan_progress";
    pub const QUICK_SCAN_COMPLETE: &str = "quick_scan_complete";

    pub const DEEP_SCAN_STARTED: &str = "deep_scan_started";
    pub const DEEP_SCAN_PROGRESS: &str = "deep_scan_progress";
    pub const DEEP_SCAN_COMPLETE: &str = "deep_scan_complete";

    pub const INFERENCE_STARTED: &str = "inference_started";
    pub const INFERENCE_PROGRESS: &str = "inference_progress";
    pub const INFERENCE_COMPLETE: &str = "inference_complete";

    pub const DECISION_STARTED: &str = "decision_started";
    pub const DECISION_COMPLETE: &str = "decision_complete";

    pub const ACTION_STARTED: &str = "action_started";
    pub const ACTION_COMPLETE: &str = "action_complete";
    pub const ACTION_FAILED: &str = "action_failed";

    pub const PLAN_READY: &str = "plan_ready";
}

/// High-level pipeline phase for a progress event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Session,
    QuickScan,
    DeepScan,
    Infer,
    Decide,
    Plan,
    Apply,
    Ui,
    Verify,
    Report,
    Bundle,
}

/// Progress counters for a phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Progress {
    pub current: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
}

/// Structured progress event for CLI/TUI consumers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressEvent {
    pub event: String,
    pub timestamp: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub phase: Phase,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress: Option<Progress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elapsed_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub details: HashMap<String, Value>,
}

impl ProgressEvent {
    pub fn new(event: impl Into<String>, phase: Phase) -> Self {
        Self {
            event: event.into(),
            timestamp: Utc::now(),
            session_id: None,
            phase,
            progress: None,
            elapsed_ms: None,
            details: HashMap::new(),
        }
    }

    pub fn with_session_id(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    pub fn with_progress(mut self, current: u64, total: Option<u64>) -> Self {
        self.progress = Some(Progress { current, total });
        self
    }

    pub fn with_elapsed_ms(mut self, elapsed_ms: u64) -> Self {
        self.elapsed_ms = Some(elapsed_ms);
        self
    }

    pub fn with_detail(mut self, key: impl Into<String>, value: impl Serialize) -> Self {
        if let Ok(v) = serde_json::to_value(value) {
            self.details.insert(key.into(), v);
        }
        self
    }

    pub fn to_jsonl(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| {
            format!(
                r#"{{"error":"serialization_failed","event":"{}"}}"#,
                self.event
            )
        })
    }
}

/// Trait for emitting progress events.
pub trait ProgressEmitter: Send + Sync {
    fn emit(&self, event: ProgressEvent);
}

/// Broadcast event bus supporting multiple subscribers.
#[derive(Debug, Default)]
pub struct EventBus {
    senders: Mutex<Vec<mpsc::Sender<ProgressEvent>>>,
}

impl EventBus {
    pub fn new() -> Self {
        Self::default()
    }

    /// Subscribe to receive progress events.
    pub fn subscribe(&self) -> mpsc::Receiver<ProgressEvent> {
        let (tx, rx) = mpsc::channel();
        let mut senders = self.senders.lock().unwrap_or_else(|err| err.into_inner());
        senders.push(tx);
        rx
    }

    /// Emit a progress event to all subscribers.
    pub fn emit(&self, event: ProgressEvent) {
        let mut senders = self.senders.lock().unwrap_or_else(|err| err.into_inner());
        senders.retain(|sender| sender.send(event.clone()).is_ok());
    }
}

impl ProgressEmitter for EventBus {
    fn emit(&self, event: ProgressEvent) {
        self.emit(event);
    }
}

/// JSONL writer for progress events (CLI-friendly).
pub struct JsonlWriter<W: Write + Send> {
    writer: Mutex<W>,
}

impl<W: Write + Send> JsonlWriter<W> {
    pub fn new(writer: W) -> Self {
        Self {
            writer: Mutex::new(writer),
        }
    }
}

impl<W: Write + Send> ProgressEmitter for JsonlWriter<W> {
    fn emit(&self, event: ProgressEvent) {
        let line = event.to_jsonl();
        if let Ok(mut writer) = self.writer.lock() {
            let _ = writeln!(writer, "{}", line);
        }
    }
}

/// Fan-out progress emitter that forwards events to multiple emitters.
pub struct FanoutEmitter {
    emitters: Vec<Arc<dyn ProgressEmitter>>,
}

impl FanoutEmitter {
    pub fn new(emitters: Vec<Arc<dyn ProgressEmitter>>) -> Self {
        Self { emitters }
    }
}

impl ProgressEmitter for FanoutEmitter {
    fn emit(&self, event: ProgressEvent) {
        for emitter in &self.emitters {
            emitter.emit(event.clone());
        }
    }
}

/// Progress emitter that ensures a session ID is attached to each event.
pub struct SessionEmitter {
    session_id: String,
    inner: Arc<dyn ProgressEmitter>,
}

impl SessionEmitter {
    pub fn new(session_id: impl Into<String>, inner: Arc<dyn ProgressEmitter>) -> Self {
        Self {
            session_id: session_id.into(),
            inner,
        }
    }
}

impl ProgressEmitter for SessionEmitter {
    fn emit(&self, mut event: ProgressEvent) {
        if event.session_id.is_none() {
            event.session_id = Some(self.session_id.clone());
        }
        self.inner.emit(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn test_progress_event_jsonl() {
        let event = ProgressEvent::new(event_names::QUICK_SCAN_STARTED, Phase::QuickScan)
            .with_session_id("sess-1")
            .with_progress(1, Some(10))
            .with_elapsed_ms(5)
            .with_detail("pids_scanned", 1);
        let json = event.to_jsonl();
        assert!(json.contains(r#""event":"quick_scan_started""#));
        assert!(json.contains(r#""session_id":"sess-1""#));
    }

    #[test]
    fn test_event_bus_dispatch() {
        let bus = EventBus::new();
        let rx = bus.subscribe();
        bus.emit(ProgressEvent::new(
            event_names::SESSION_STARTED,
            Phase::Session,
        ));
        let received = rx.recv().expect("event should be delivered");
        assert_eq!(received.event, event_names::SESSION_STARTED);
    }

    #[test]
    fn test_session_emitter_attaches_session_id() {
        struct Capture {
            last: Mutex<Option<ProgressEvent>>,
        }

        impl Capture {
            fn new() -> Self {
                Self {
                    last: Mutex::new(None),
                }
            }
        }

        impl ProgressEmitter for Capture {
            fn emit(&self, event: ProgressEvent) {
                *self.last.lock().unwrap() = Some(event);
            }
        }

        let capture = Arc::new(Capture::new());
        let emitter = SessionEmitter::new("sess-123", capture.clone());
        emitter.emit(ProgressEvent::new(event_names::PLAN_READY, Phase::Plan));
        let recorded = capture.last.lock().unwrap().clone().expect("event");
        assert_eq!(recorded.session_id.as_deref(), Some("sess-123"));
    }
}
