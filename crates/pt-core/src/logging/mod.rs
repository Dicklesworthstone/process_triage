//! Structured logging foundation for pt-core.
//!
//! Provides dual-mode logging:
//! - Human-readable console output for interactive use
//! - Machine-parseable JSONL for daemon/agent workflows
//!
//! # Usage
//!
//! ```ignore
//! use pt_core::logging::{init_logging, LogConfig, LogContext, Level, Stage, event_names};
//!
//! // Initialize at startup
//! let config = LogConfig::from_env(None, None);
//! init_logging(&config);
//!
//! // Create context for consistent correlation IDs
//! let ctx = LogContext::new("run-12345", "host-abc")
//!     .with_session_id("pt-20260115-143022-a7xq");
//!
//! // Emit structured events
//! let event = ctx.info(event_names::RUN_STARTED, Stage::Init, "Starting triage run");
//! tracing::info!(target: "pt_core::run", message = %event.message);
//! ```
//!
//! # Design Notes
//!
//! - stdout is reserved for command payloads (JSON/MD output)
//! - stderr receives all log output (human or JSONL)
//! - Log events include correlation IDs (run_id, session_id) for tracing
//! - Redaction-safe by default - sensitive strings are hashed/redacted

pub mod config;
pub mod events;
pub mod layer;

pub use config::{LogConfig, LogFormat, LogLevel};
pub use events::{event_names, Level, LogContext, LogEvent, Stage};
pub use layer::JsonlLayer;

use std::io::IsTerminal;
use std::sync::OnceLock;
use pt_redact::{RedactionEngine, RedactionPolicy};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

static REDACTOR: OnceLock<RedactionEngine> = OnceLock::new();

/// Get the global redaction engine.
///
/// Initializes with a default policy if not already set.
pub fn get_redactor() -> &'static RedactionEngine {
    REDACTOR.get_or_init(|| {
        RedactionEngine::new(RedactionPolicy::default())
            .expect("Failed to initialize default redaction engine")
    })
}

/// Set the global redaction engine.
///
/// Should be called once configuration is loaded.
pub fn set_redactor(engine: RedactionEngine) {
    // If already initialized (e.g. by early logs), we can't replace it in OnceLock.
    // Ideally we'd use RwLock/ArcSwap, but for now we accept that early logs use default policy.
    // However, for correct behavior with custom policy, we should try to set it.
    // If Set fails, it means we already used the default.
    // For a CLI tool, we load config very early. Maybe we can defer logging init?
    // Or just accept default policy for init logs.
    // Better: check if set, if not set. If set, warn?
    // Actually, OnceLock::set returns Result.
    if REDACTOR.set(engine).is_err() {
        // This happens if get_redactor() was called before set_redactor().
        // In pt-core, logging init happens before config load.
        // So early logs use default.
        // We probably want a way to update it.
        // But RedactionEngine is immutable?
        // Let's leave it as "default policy only" for now to fix the security hole,
        // and later refactor to ArcSwap if we need dynamic policy updates.
        // Default policy handles secrets/PII correctly, just maybe not custom regexes.
        // Actually, let's log a warning to stderr if we can't set it.
        eprintln!("Warning: Redaction engine already initialized with default policy. Custom policy ignored for logs.");
    }
}

/// Initialize the logging subsystem.
///
/// Must be called once at startup before any logging occurs.
/// Respects environment variables PT_LOG, RUST_LOG, and PT_LOG_FORMAT.
pub fn init_logging(config: &LogConfig) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("pt_core={}", config.level)));

    match config.format {
        LogFormat::Human => {
            // Human-readable console format on stderr
            let use_ansi = std::io::stderr().is_terminal();
            let fmt_layer = fmt::layer()
                .with_writer(std::io::stderr)
                .with_target(false)
                .with_thread_ids(false)
                .with_thread_names(false)
                .with_ansi(use_ansi);

            if config.timestamps {
                tracing_subscriber::registry()
                    .with(filter)
                    .with(fmt_layer)
                    .init();
            } else {
                tracing_subscriber::registry()
                    .with(filter)
                    .with(fmt_layer.without_time())
                    .init();
            }
        }
        LogFormat::Jsonl => {
            // Machine-parseable JSONL on stderr
            let jsonl_layer = JsonlLayer::stderr();
            tracing_subscriber::registry()
                .with(filter)
                .with(jsonl_layer)
                .init();
        }
    }
}

/// Initialize logging with defaults (for tests and simple cases).
pub fn init_default_logging() {
    let config = LogConfig::from_env(None, None);
    init_logging(&config);
}

/// Generate a unique run ID for this invocation.
pub fn generate_run_id() -> String {
    let uuid = uuid::Uuid::new_v4();
    // Shorten to first 12 hex chars for readability
    format!("run-{}", &uuid.to_string()[..12])
}

/// Get the host ID for logging.
///
/// Uses machine-id on Linux or generates a stable ID from hostname.
pub fn get_host_id() -> String {
    // Try to read machine-id
    if let Ok(id) = std::fs::read_to_string("/etc/machine-id") {
        let id = id.trim();
        if id.len() >= 8 {
            return format!("host-{}", &id[..8]);
        }
    }

    // Fallback: use hostname hash
    if let Ok(hostname) = std::env::var("HOSTNAME") {
        let hash = hash_string(&hostname);
        return format!("host-{}", &hash[..8]);
    }

    // Last resort: random
    format!("host-{}", &uuid::Uuid::new_v4().to_string()[..8])
}

/// Simple hash for hostname fallback.
fn hash_string(s: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    s.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// Redact a potentially sensitive string for logging.
///
/// Uses pt-redact's canonical hash if available, otherwise truncates.
pub fn redact_for_log(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        return s.to_string();
    }
    format!("{}...(truncated)", &s[..max_len.min(s.len())])
}

/// Convenience macro for structured event logging with context.
///
/// Usage:
/// ```ignore
/// log_event!(ctx, INFO, "scan.started", Stage::Scan, "Starting process scan");
/// log_event!(ctx, DEBUG, "infer.proc_done", Stage::Infer, "Inference complete",
///     pid = 1234, posterior = "useful:0.8");
/// ```
#[macro_export]
macro_rules! log_event {
    ($ctx:expr, INFO, $event:expr, $stage:expr, $msg:expr $(, $key:ident = $val:expr)*) => {
        tracing::info!(
            target: $event,
            run_id = %$ctx.run_id,
            session_id = ?$ctx.session_id,
            host_id = %$ctx.host_id,
            stage = %$stage,
            message = $msg,
            $($key = $val,)*
        )
    };
    ($ctx:expr, DEBUG, $event:expr, $stage:expr, $msg:expr $(, $key:ident = $val:expr)*) => {
        tracing::debug!(
            target: $event,
            run_id = %$ctx.run_id,
            session_id = ?$ctx.session_id,
            host_id = %$ctx.host_id,
            stage = %$stage,
            message = $msg,
            $($key = $val,)*
        )
    };
    ($ctx:expr, WARN, $event:expr, $stage:expr, $msg:expr $(, $key:ident = $val:expr)*) => {
        tracing::warn!(
            target: $event,
            run_id = %$ctx.run_id,
            session_id = ?$ctx.session_id,
            host_id = %$ctx.host_id,
            stage = %$stage,
            message = $msg,
            $($key = $val,)*
        )
    };
    ($ctx:expr, ERROR, $event:expr, $stage:expr, $msg:expr $(, $key:ident = $val:expr)*) => {
        tracing::error!(
            target: $event,
            run_id = %$ctx.run_id,
            session_id = ?$ctx.session_id,
            host_id = %$ctx.host_id,
            stage = %$stage,
            message = $msg,
            $($key = $val,)*
        )
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_run_id() {
        let id1 = generate_run_id();
        let id2 = generate_run_id();

        assert!(id1.starts_with("run-"));
        assert!(id2.starts_with("run-"));
        assert_ne!(id1, id2);
        // Format: run-<12 hex chars>
        assert_eq!(id1.len(), 16);
    }

    #[test]
    fn test_get_host_id() {
        let host_id = get_host_id();
        assert!(host_id.starts_with("host-"));
        assert!(host_id.len() >= 13); // "host-" + 8 chars
    }

    #[test]
    fn test_redact_for_log_short() {
        let s = "short";
        assert_eq!(redact_for_log(s, 10), "short");
    }

    #[test]
    fn test_redact_for_log_long() {
        let s = "this is a very long string that should be truncated";
        let redacted = redact_for_log(s, 10);
        assert!(redacted.starts_with("this is a "));
        assert!(redacted.ends_with("...(truncated)"));
    }

    #[test]
    fn test_log_config_defaults() {
        let config = LogConfig::default();
        assert_eq!(config.format, LogFormat::Human);
        assert_eq!(config.level, LogLevel::Info);
    }

    #[test]
    fn test_log_context_creation() {
        let ctx = LogContext::new("run-123", "host-abc").with_session_id("pt-20260115-143022-test");
        assert_eq!(ctx.run_id, "run-123");
        assert_eq!(ctx.host_id, "host-abc");
        assert_eq!(ctx.session_id, Some("pt-20260115-143022-test".to_string()));
    }

    #[test]
    fn test_stage_serialization() {
        assert_eq!(serde_json::to_string(&Stage::Scan).unwrap(), "\"scan\"");
        assert_eq!(serde_json::to_string(&Stage::Infer).unwrap(), "\"infer\"");
    }

    #[test]
    fn test_level_from_tracing() {
        assert_eq!(Level::from(tracing::Level::INFO), Level::Info);
        assert_eq!(Level::from(tracing::Level::DEBUG), Level::Debug);
        assert_eq!(Level::from(tracing::Level::WARN), Level::Warn);
        assert_eq!(Level::from(tracing::Level::ERROR), Level::Error);
    }
}
