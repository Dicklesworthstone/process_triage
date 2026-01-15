//! Output format specifications.

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

/// Supported output formats for CLI commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    /// Token-efficient structured JSON (default for machine consumption)
    #[default]
    Json,

    /// Human-readable Markdown
    Md,

    /// Streaming JSON Lines for progress events
    Jsonl,

    /// One-line summary for quick status checks
    Summary,

    /// Key=value pairs for monitoring systems
    Metrics,

    /// Human-friendly narrative for chat/notifications
    Slack,

    /// Minimal output (exit code only)
    Exitcode,

    /// Structured natural language for agent-to-user communication
    Prose,
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Json => write!(f, "json"),
            OutputFormat::Md => write!(f, "md"),
            OutputFormat::Jsonl => write!(f, "jsonl"),
            OutputFormat::Summary => write!(f, "summary"),
            OutputFormat::Metrics => write!(f, "metrics"),
            OutputFormat::Slack => write!(f, "slack"),
            OutputFormat::Exitcode => write!(f, "exitcode"),
            OutputFormat::Prose => write!(f, "prose"),
        }
    }
}
