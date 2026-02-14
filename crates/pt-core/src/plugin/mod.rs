//! Plugin system for custom evidence sources and action hooks.
//!
//! Plugins are subprocess-based (no dynamic loading) and communicate via
//! JSON on stdin/stdout. They live in `~/.config/process_triage/plugins/`,
//! each in its own directory with a `plugin.toml` manifest.
//!
//! # Plugin types
//!
//! - **Evidence plugins**: provide additional per-process evidence for inference.
//!   They receive a list of PIDs and return per-class log-likelihoods.
//!
//! - **Action plugins**: execute custom actions (notifications, API calls).
//!   They receive action details and return a status.
//!
//! # Directory structure
//!
//! ```text
//! ~/.config/process_triage/plugins/
//! ├── prometheus-metrics/
//! │   ├── plugin.toml       # manifest
//! │   └── fetch_metrics.sh  # executable
//! └── slack-notify/
//!     ├── plugin.toml
//!     └── notify.py
//! ```
//!
//! # Safety
//!
//! - Plugins run as subprocesses with configurable timeouts
//! - Output size is capped to prevent memory exhaustion
//! - Plugins are auto-disabled after repeated failures
//! - Action plugins can only notify — they cannot kill or signal processes

pub mod action;
pub mod evidence;
pub mod manager;
pub mod manifest;

pub use manager::PluginManager;
pub use manifest::{
    load_manifest, ManifestError, PluginLimits, PluginManifest, PluginTimeouts, PluginType,
    ResolvedPlugin, PLUGIN_API_VERSION,
};

pub use evidence::{
    evidence_for_pid, parse_evidence_output, to_evidence_term, EvidencePluginError,
    EvidencePluginInput, EvidencePluginOutput, PluginEvidenceEntry, PluginLogLikelihoods,
};

pub use action::{
    parse_action_output, ActionPluginError, ActionPluginInput, ActionPluginOutput, ActionStatus,
};
