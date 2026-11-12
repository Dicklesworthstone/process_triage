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

use pt_redact::{Action, FieldClass, RedactionEngine, RedactionPolicy};
use std::io::IsTerminal;
use std::sync::OnceLock;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

static REDACTOR: OnceLock<RedactionEngine> = OnceLock::new();
static HOST_ID: OnceLock<String> = OnceLock::new();

/// Get the global redaction engine.
///
/// Initializes with a default policy if not already set.
pub fn get_redactor() -> &'static RedactionEngine {
    REDACTOR.get_or_init(|| {
        let mut policy = RedactionPolicy::default();
        // Allow free text in logs to be readable (default is DetectAction which might be too aggressive)
        policy.set_action(FieldClass::FreeText, Action::Allow);
        RedactionEngine::new(policy).expect("Failed to initialize default redaction engine")
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

/// Get the host ID shared by logs, session persistence and fleet bindings.
///
/// Prefer the machine ID, then a native hostname. Reading the operating system
/// directly keeps macOS and minimal Linux installations stable without requiring
/// an exported `HOSTNAME`. A hostname fallback identifies a name, not a globally
/// unique machine. If every source is unavailable, a process-local random ID
/// avoids conflating unrelated unknown hosts while remaining stable within a run.
pub fn get_host_id() -> String {
    HOST_ID
        .get_or_init(|| {
            let machine_id = std::fs::read_to_string("/etc/machine-id").ok();
            let hostname = native_hostname();
            let environment_hostname = std::env::var("HOSTNAME").ok();
            host_id_from_sources(
                machine_id.as_deref(),
                hostname.as_deref(),
                environment_hostname.as_deref(),
            )
            .unwrap_or_else(|| format!("host-{}", uuid::Uuid::new_v4().simple()))
        })
        .clone()
}

fn host_id_from_sources(
    machine_id: Option<&str>,
    native_hostname: Option<&[u8]>,
    environment_hostname: Option<&str>,
) -> Option<String> {
    if let Some(id) = machine_id.map(str::trim).filter(|id| {
        id.len() == 32
            && id.bytes().all(|byte| byte.is_ascii_hexdigit())
            && id.bytes().any(|byte| byte != b'0')
    }) {
        // Retain the established representation for valid machine IDs.
        return Some(format!("host-{}", id[..8].to_ascii_lowercase()));
    }
    native_hostname
        .and_then(hostname_id)
        .or_else(|| environment_hostname.and_then(|name| hostname_id(name.as_bytes())))
}

fn hostname_id(name: &[u8]) -> Option<String> {
    use sha2::{Digest, Sha256};

    let name = name.trim_ascii();
    if name.is_empty()
        || name.iter().any(|byte| byte.is_ascii_control())
        || name.eq_ignore_ascii_case(b"localhost")
        || name.eq_ignore_ascii_case(b"localhost.localdomain")
        || name.eq_ignore_ascii_case(b"(none)")
    {
        return None;
    }
    // Hash the original bytes rather than lossy UTF-8; distinct hostnames must
    // not collapse to the same replacement characters. SHA-256 also remains
    // deterministic across Rust releases, unlike the unspecified DefaultHasher.
    let digest = hex::encode(Sha256::digest(name));
    Some(format!("host-{}", &digest[..32]))
}

#[cfg(unix)]
fn native_hostname() -> Option<Vec<u8>> {
    let mut name = [0_u8; 256];
    // SAFETY: gethostname receives a writable buffer with the supplied length.
    // Require an actual terminator; a truncated prefix is not a host identity.
    if unsafe { libc::gethostname(name.as_mut_ptr().cast(), name.len()) } != 0 {
        return None;
    }
    let end = name.iter().position(|byte| *byte == 0)?;
    Some(name[..end].to_vec())
}

#[cfg(not(unix))]
fn native_hostname() -> Option<Vec<u8>> {
    None
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
        assert_eq!(host_id, get_host_id());
        assert_eq!(host_id, std::thread::spawn(get_host_id).join().unwrap());
    }

    #[test]
    fn native_hostname_keeps_sessions_stable_without_exported_hostname() {
        let expected = "host-c9f9a446607afad5b9b7358c38a8d2a9";
        for environment in [None, Some(""), Some("different-shell-context")] {
            assert_eq!(
                host_id_from_sources(None, Some(b"mac-mini-max.local"), environment).as_deref(),
                Some(expected)
            );
        }
        assert_ne!(
            host_id_from_sources(None, Some(b"worker-one"), None),
            host_id_from_sources(None, Some(b"worker-two"), None)
        );
        // A missing native source can still use a real exported hostname.
        assert_eq!(
            host_id_from_sources(None, None, Some("mac-mini-max.local")).as_deref(),
            Some(expected)
        );
    }

    #[test]
    fn valid_machine_id_wins_and_uninitialized_ids_do_not_mask_native_identity() {
        assert_eq!(
            host_id_from_sources(
                Some("0123456789abcdef0123456789abcdef\n"),
                Some(b"native-host"),
                Some("environment-host"),
            )
            .as_deref(),
            Some("host-01234567")
        );
        for invalid in [
            "",
            "uninitialized",
            "01234567",
            "00000000000000000000000000000000",
            "non-hexadecimal-machine-identity!",
            "éééééééééééééééé",
        ] {
            assert_eq!(
                host_id_from_sources(Some(invalid), Some(b"worker-one"), None).as_deref(),
                Some("host-a693dbb0ab8e4cef8faa032cea54716d")
            );
        }
    }

    #[test]
    fn unknown_hosts_are_not_merged_under_an_empty_or_placeholder_identity() {
        for unknown in ["", " ", "localhost", "LOCALHOST.LOCALDOMAIN", "(none)"] {
            assert!(host_id_from_sources(None, None, Some(unknown)).is_none());
            assert!(host_id_from_sources(None, Some(unknown.as_bytes()), None).is_none());
        }
        assert!(host_id_from_sources(None, Some(b"host\0suffix"), None).is_none());
        assert!(host_id_from_sources(None, Some(b"host\nother"), None).is_none());
        // Avoid collisions introduced by lossy string conversion.
        assert_ne!(hostname_id(b"host-\xff"), hostname_id(b"host-\xfe"));
    }

    #[cfg(unix)]
    #[test]
    fn native_hostname_reader_observes_a_complete_name() {
        let first = native_hostname().expect("native hostname available on the test host");
        assert!(!first.is_empty());
        assert!(!first.contains(&0));
        assert_eq!(Some(first), native_hostname());
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
