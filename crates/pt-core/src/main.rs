//! Process Triage Core - Inference and Decision Engine
//!
//! The main entry point for pt-core, handling:
//! - Process scanning and collection
//! - Bayesian inference for process classification
//! - Decision theory for action recommendations
//! - Agent/robot mode for automated operation
//! - Telemetry and reporting

use clap::parser::ValueSource;
use clap::FromArgMatches;
use clap::{Args, CommandFactory, Parser, Subcommand};
#[cfg(feature = "ui")]
use pt_common::{IdentityQuality, ProcessIdentity};
use pt_common::{OutputFormat, SessionId, SCHEMA_VERSION};
use pt_core::calibrate::{validation::ValidationEngine, CalibrationError};
use pt_core::capabilities::{get_capabilities, ToolCapability};
use pt_core::collect::protected::ProtectedFilter;
#[cfg(target_os = "linux")]
use pt_core::collect::{systemd::collect_systemd_unit, ContainerRuntime};
use pt_core::config::{
    get_preset, list_presets, load_config, ConfigError, ConfigOptions, PresetName, Priors,
};
use pt_core::events::{
    FanoutEmitter, JsonlWriter, Phase, ProgressEmitter, ProgressEvent, SessionEmitter,
};
use pt_core::exit_codes::ExitCode;
use pt_core::fleet::discovery::{
    FleetDiscoveryConfig, InventoryProvider, ProviderRegistry, StaticInventoryProvider,
};
use pt_core::fleet::ssh_scan::{scan_result_to_host_input, ssh_scan_fleet, SshScanConfig};
#[cfg(feature = "ui")]
use pt_core::inference::galaxy_brain::{
    render as render_galaxy_brain, GalaxyBrainConfig, MathMode, Verbosity,
};

use pt_core::output::predictions::{
    apply_field_selection, CpuPrediction, MemoryPrediction, PredictionDiagnostics, PredictionField,
    PredictionFieldSelector, Predictions, TrajectoryAssessment, TrajectoryLabel, Trend,
};
use pt_core::output::{encode_toon_value, CompactConfig, FieldSelector, TokenEfficientOutput};
#[cfg(feature = "ui")]
use pt_core::plan::{generate_plan, DecisionBundle, DecisionCandidate};
use pt_core::session::compare::generate_comparison_report;
use pt_core::session::diff::{
    compute_diff, DeltaKind, DiffConfig, InferenceSummary, ProcessDelta, SessionDiff,
};
use pt_core::session::fleet::{create_fleet_session, HostInput};
use pt_core::session::snapshot_persist::{
    load_inference_unchecked, load_inventory_unchecked, persist_inference, persist_inventory,
    InferenceArtifact, InventoryArtifact, PersistedInference, PersistedProcess,
};
use pt_core::session::{
    ListSessionsOptions, SessionContext, SessionHandle, SessionManifest, SessionMode, SessionState,
    SessionStore, SessionSummary,
};
use pt_core::shadow::ShadowRecorder;
#[cfg(target_os = "linux")]
use pt_core::supervision::{
    detect_supervision, is_human_supervised, AppActionType, AppSupervisionAnalyzer,
    AppSupervisorType, ContainerActionType, ContainerSupervisionAnalyzer,
};
#[cfg(feature = "ui")]
use pt_core::tui::widgets::ProcessRow;
#[cfg(feature = "ui")]
use pt_core::tui::{run_ftui, App, ExecutionOutcome};
use pt_core::verify::{parse_agent_plan, verify_plan, VerifyError};
use pt_telemetry::retention::{RetentionConfig, RetentionEnforcer, RetentionError};
use pt_telemetry::shadow::{Observation, ShadowStorage, ShadowStorageConfig};
use pt_telemetry::writer::default_telemetry_dir;
#[cfg(feature = "daemon")]
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
#[cfg(feature = "ui")]
use std::sync::Mutex;

/// Process Triage Core - Intelligent process classification and cleanup
#[derive(Parser)]
#[command(name = "pt-core")]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    #[command(flatten)]
    global: GlobalOpts,
}

/// Global options available to all commands
#[derive(Args, Debug)]
struct GlobalOpts {
    /// Path to capabilities manifest (from pt wrapper)
    #[arg(long, global = true, env = "PT_CAPABILITIES_MANIFEST")]
    capabilities: Option<String>,

    /// Override config directory
    #[arg(long, global = true, env = "PT_CONFIG_DIR")]
    config: Option<String>,

    /// Output format
    #[arg(
        long,
        short = 'f',
        global = true,
        default_value = "json",
        env = "PT_OUTPUT_FORMAT"
    )]
    format: OutputFormat,

    /// Increase verbosity (-v, -vv, -vvv)
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Decrease verbosity (quiet mode)
    #[arg(short, long, global = true)]
    quiet: bool,

    /// Disable colored output
    #[arg(long, global = true)]
    no_color: bool,

    /// Abort if operation exceeds time limit (seconds)
    #[arg(long, global = true)]
    timeout: Option<u64>,

    /// Non-interactive mode; execute policy-approved actions automatically
    #[arg(long, global = true)]
    robot: bool,

    /// Full pipeline but never execute actions (calibration mode)
    #[arg(long, global = true)]
    shadow: bool,

    /// Compute plan only, no execution even with --robot
    #[arg(long, global = true)]
    dry_run: bool,

    /// Run without wrapper (uses detected/default capabilities)
    #[arg(long, global = true)]
    standalone: bool,

    // Token-efficient output options
    /// Select specific output fields (comma-separated or preset: minimal, standard, full)
    #[arg(long, global = true, value_name = "FIELDS")]
    fields: Option<String>,

    /// Enable compact output (short keys, minified JSON)
    #[arg(long, global = true)]
    compact: bool,

    /// Maximum token budget for output (enables truncation with continuation)
    #[arg(long, global = true, value_name = "TOKENS")]
    max_tokens: Option<usize>,

    /// Estimate token count without full response
    #[arg(long, global = true)]
    estimate_tokens: bool,
}

impl GlobalOpts {
    /// Build a token-efficient output processor from global options.
    fn build_output_processor(&self) -> TokenEfficientOutput {
        let mut processor = TokenEfficientOutput::new();

        // Parse field selector if specified
        if let Some(ref fields_spec) = self.fields {
            if let Ok(selector) = FieldSelector::parse(fields_spec) {
                processor = processor.with_fields(selector);
            }
        }

        // Enable compact output if requested
        if self.compact {
            processor = processor.with_compact(CompactConfig::all());
        }

        // Set max tokens if specified
        if let Some(max) = self.max_tokens {
            processor = processor.with_max_tokens(max);
        }

        processor
    }

    /// Process JSON value through token-efficient output pipeline.
    /// Returns the processed string and optional metadata.
    fn process_output(&self, value: serde_json::Value) -> String {
        // If no token-efficient options specified, use standard pretty print
        if self.fields.is_none()
            && !self.compact
            && self.max_tokens.is_none()
            && !self.estimate_tokens
        {
            return serde_json::to_string_pretty(&value).unwrap_or_default();
        }

        let processor = self.build_output_processor();
        let result = processor.process(value);

        // If estimate_tokens is set, return token estimate only
        if self.estimate_tokens {
            return serde_json::to_string_pretty(&serde_json::json!({
                "estimated_tokens": result.token_count,
                "truncated": result.truncated,
                "continuation_token": result.continuation_token,
                "remaining_count": result.remaining_count,
            }))
            .unwrap_or_default();
        }

        // If truncated, add metadata wrapper
        if result.truncated {
            let wrapper = serde_json::json!({
                "data": result.json,
                "_meta": {
                    "truncated": true,
                    "continuation_token": result.continuation_token,
                    "remaining_count": result.remaining_count,
                    "token_count": result.token_count,
                }
            });

            if self.compact {
                return serde_json::to_string(&wrapper).unwrap_or_default();
            } else {
                return serde_json::to_string_pretty(&wrapper).unwrap_or_default();
            }
        }

        result.output_string
    }

    /// Process JSON value through token-efficient output pipeline and return JSON value.
    fn process_output_value(&self, value: serde_json::Value) -> serde_json::Value {
        // If no token-efficient options specified, return input unchanged
        if self.fields.is_none()
            && !self.compact
            && self.max_tokens.is_none()
            && !self.estimate_tokens
        {
            return value;
        }

        let processor = self.build_output_processor();
        let result = processor.process(value);

        // If estimate_tokens is set, return token estimate metadata only
        if self.estimate_tokens {
            return serde_json::json!({
                "estimated_tokens": result.token_count,
                "truncated": result.truncated,
                "continuation_token": result.continuation_token,
                "remaining_count": result.remaining_count,
            });
        }

        // If truncated, wrap output with metadata
        if result.truncated {
            return serde_json::json!({
                "data": result.json,
                "_meta": {
                    "truncated": true,
                    "continuation_token": result.continuation_token,
                    "remaining_count": result.remaining_count,
                    "token_count": result.token_count,
                }
            });
        }

        result.json
    }
}

/// Format structured output for JSON/TOON modes, preserving token-efficient options.
fn format_structured_output(global: &GlobalOpts, value: serde_json::Value) -> String {
    match global.format {
        OutputFormat::Json => global.process_output(value),
        OutputFormat::Toon => {
            let processed = global.process_output_value(value);
            encode_toon_value(&processed)
        }
        _ => global.process_output(value),
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Interactive golden path: scan → infer → plan → TUI approval → staged apply
    Run(RunArgs),

    /// Quick multi-sample scan only (no inference or action)
    Scan(ScanArgs),

    /// Full deep scan with all available probes
    DeepScan(DeepScanArgs),

    /// Compare two sessions and show differences
    Diff(DiffArgs),

    /// Query telemetry and history
    Query(QueryArgs),

    /// Create or inspect diagnostic bundles
    Bundle(BundleArgs),

    /// Generate HTML reports
    Report(ReportArgs),

    /// Validate configuration and environment
    Check(CheckArgs),

    /// Agent/robot subcommands for automated operation
    #[command(visible_alias = "robot")]
    Agent(AgentArgs),

    /// Configuration management
    Config(ConfigArgs),

    /// Background monitoring daemon
    #[cfg(feature = "daemon")]
    Daemon(DaemonArgs),

    /// Telemetry management
    Telemetry(TelemetryArgs),

    /// Shadow mode observation management
    Shadow(ShadowArgs),

    /// Signature management (list, add, remove user signatures)
    Signature(pt_core::signature_cli::SignatureArgs),

    /// Generate JSON schemas for agent output types
    Schema(SchemaArgs),

    /// Update management: rollback, backup, version history
    Update(UpdateArgs),

    /// MCP server for AI agent integration
    Mcp(McpArgs),

    /// Print version information
    Version,
}

// ============================================================================
// Command argument structs
// ============================================================================

#[derive(Args, Debug)]
struct RunArgs {
    /// Force deep scan with all available probes
    #[arg(long)]
    deep: bool,

    /// Render the TUI inline (preserves scrollback) instead of using the alternate screen.
    ///
    /// In inline mode, the UI is anchored at the bottom of the terminal and logs/progress
    /// can scroll above it.
    #[arg(long)]
    inline: bool,

    /// Load additional signature patterns
    #[arg(long)]
    signatures: Option<String>,

    /// Include signed community signatures
    #[arg(long)]
    community_signatures: bool,

    /// Only consider processes older than threshold (seconds)
    #[arg(long)]
    min_age: Option<u64>,

    /// Resource recovery goal for goal-oriented optimization
    #[arg(long, help = "Resource recovery goal, e.g. 'free 4GB RAM'")]
    goal: Option<String>,

    /// TUI color theme (overrides environment detection)
    #[arg(long, value_parser = ["dark", "light", "high-contrast", "no-color"])]
    theme: Option<String>,

    /// Enable high-contrast mode (WCAG AAA). Shorthand for --theme=high-contrast.
    #[arg(long)]
    high_contrast: bool,

    /// Disable animations and use static indicators (accessibility).
    /// Also activatable via REDUCE_MOTION or PT_REDUCE_MOTION env vars.
    #[arg(long)]
    reduce_motion: bool,
}

#[derive(Args, Debug)]
struct ScanArgs {
    /// Force deep scan
    #[arg(long)]
    deep: bool,

    /// Number of samples to collect
    #[arg(long, default_value = "3")]
    samples: u32,

    /// Interval between samples (milliseconds)
    #[arg(long, default_value = "500")]
    interval: u64,

    /// Include kernel threads in scan output (default: exclude)
    #[arg(long)]
    include_kernel_threads: bool,

    /// Resource recovery goal (advisory only)
    #[arg(long)]
    goal: Option<String>,
}

#[derive(Args, Debug)]
struct DeepScanArgs {
    /// Target specific PIDs only
    #[arg(long, value_delimiter = ',')]
    pids: Vec<u32>,

    /// Maximum time budget for deep scan (seconds)
    #[arg(long)]
    budget: Option<u64>,
}

#[derive(Args, Debug)]
struct DiffArgs {
    /// Base session ID (older snapshot)
    #[arg(value_name = "BASE", index = 1)]
    base: Option<String>,

    /// Compare session ID (newer snapshot)
    #[arg(value_name = "COMPARE", index = 2)]
    compare: Option<String>,

    /// Compare current session to the most recent baseline-labeled session
    #[arg(long)]
    baseline: bool,

    /// Compare the latest two sessions
    #[arg(long)]
    last: bool,

    /// Only show changes (exclude unchanged)
    #[arg(long)]
    changed_only: bool,

    /// Filter by category: new, resolved, changed, unchanged, worsened, improved
    #[arg(long)]
    category: Option<String>,

    /// Minimum score delta to consider a change
    #[arg(long)]
    min_score_delta: Option<u32>,
}

#[derive(Args, Debug)]
struct QueryArgs {
    #[command(subcommand)]
    command: Option<QueryCommands>,

    /// Query expression
    query: Option<String>,
}

#[derive(Subcommand, Debug)]
enum QueryCommands {
    /// Query recent sessions
    Sessions {
        /// Maximum sessions to return
        #[arg(long, default_value = "10")]
        limit: u32,
    },
    /// Query action history
    Actions {
        /// Filter by session ID
        #[arg(long)]
        session: Option<String>,
    },
    /// Query telemetry data
    Telemetry {
        /// Time range (e.g., "1h", "24h", "7d")
        #[arg(long, default_value = "24h")]
        range: String,
    },
}

#[derive(Args, Debug)]
struct BundleArgs {
    #[command(subcommand)]
    command: BundleCommands,
}

#[derive(Subcommand, Debug)]
enum BundleCommands {
    /// Create a new diagnostic bundle from a session
    Create {
        /// Session ID to export (default: latest)
        #[arg(long)]
        session: Option<String>,

        /// Output path for the bundle
        #[arg(short, long)]
        output: Option<String>,

        /// Export profile: minimal, safe (default), forensic
        #[arg(long, default_value = "safe")]
        profile: String,

        /// Include raw telemetry data
        #[arg(long)]
        include_telemetry: bool,

        /// Include full process dumps
        #[arg(long)]
        include_dumps: bool,

        /// Encrypt the bundle with a passphrase (explicit opt-in)
        #[arg(long)]
        encrypt: bool,

        /// Passphrase for bundle encryption/decryption (or use PT_BUNDLE_PASSPHRASE)
        #[arg(long)]
        passphrase: Option<String>,
    },
    /// Inspect an existing bundle
    Inspect {
        /// Path to the bundle file
        path: String,

        /// Verify file checksums
        #[arg(long)]
        verify: bool,

        /// Passphrase for encrypted bundles (or use PT_BUNDLE_PASSPHRASE)
        #[arg(long)]
        passphrase: Option<String>,
    },
    /// Extract bundle contents
    Extract {
        /// Path to the bundle file
        path: String,

        /// Output directory
        #[arg(short, long)]
        output: Option<String>,

        /// Verify file checksums before extraction
        #[arg(long)]
        verify: bool,

        /// Passphrase for encrypted bundles (or use PT_BUNDLE_PASSPHRASE)
        #[arg(long)]
        passphrase: Option<String>,
    },
}

#[derive(Args, Debug)]
struct ReportArgs {
    /// Session ID to generate report for (default: latest)
    #[arg(long)]
    session: Option<String>,

    /// Output path for the HTML report
    #[arg(short, long)]
    output: Option<String>,

    /// Include detailed math ledger
    #[arg(long)]
    include_ledger: bool,
}

#[derive(Args, Debug)]
struct CheckArgs {
    /// Check priors.json validity
    #[arg(long)]
    priors: bool,

    /// Check policy.json validity
    #[arg(long)]
    policy: bool,

    /// Check system capabilities
    #[arg(long = "check-capabilities", alias = "caps")]
    check_capabilities: bool,

    /// Check all configuration
    #[arg(long)]
    all: bool,
}

#[derive(Args, Debug)]
struct AgentArgs {
    #[command(subcommand)]
    command: AgentCommands,
}

#[derive(Subcommand, Debug)]
enum AgentCommands {
    /// Generate action plan without execution
    Plan(AgentPlanArgs),

    /// Explain reasoning for specific candidates
    Explain(AgentExplainArgs),

    /// Execute actions from a session
    Apply(AgentApplyArgs),

    /// Verify action outcomes
    Verify(AgentVerifyArgs),

    /// Show changes between sessions
    Diff(AgentDiffArgs),

    /// Create session snapshot for later comparison
    Snapshot(AgentSnapshotArgs),

    /// Dump current capabilities manifest
    Capabilities(AgentCapabilitiesArgs),

    /// List and manage sessions
    Sessions(AgentSessionsArgs),

    /// List current prior configuration
    ListPriors(AgentListPriorsArgs),

    /// View pending plans and notifications
    Inbox(AgentInboxArgs),

    /// Stream session progress events (JSONL)
    Tail(AgentTailArgs),

    /// Watch for new candidates and emit notifications
    Watch(AgentWatchArgs),

    /// Export priors to file for transfer between machines
    ExportPriors(AgentExportPriorsArgs),

    /// Import priors from file (bootstrap from external source)
    ImportPriors(AgentImportPriorsArgs),

    /// Generate HTML report from session
    #[cfg(feature = "report")]
    Report(AgentReportArgs),

    /// Initialize pt for installed coding agents
    Init(AgentInitArgs),

    /// Export session bundle (alias for bundle create)
    Export(AgentExportArgs),

    /// Fleet-wide operations across multiple hosts
    Fleet(AgentFleetArgs),
}

#[derive(Args, Debug)]
struct AgentExportArgs {
    /// Session ID to export (default: latest)
    #[arg(long)]
    session: Option<String>,

    /// Output path for the bundle
    #[arg(short, long)]
    out: Option<String>,

    /// Export profile: minimal, safe (default), forensic
    #[arg(long, default_value = "safe")]
    profile: String,

    /// Include raw telemetry data
    #[arg(long)]
    include_telemetry: bool,

    /// Include full process dumps
    #[arg(long)]
    include_dumps: bool,

    /// Encrypt the bundle with a passphrase
    #[arg(long)]
    encrypt: bool,

    /// Passphrase for bundle encryption (or use PT_BUNDLE_PASSPHRASE)
    #[arg(long)]
    passphrase: Option<String>,
}

#[derive(Args, Debug)]
struct AgentFleetArgs {
    #[command(subcommand)]
    command: AgentFleetCommands,
}

#[derive(Subcommand, Debug)]
enum AgentFleetCommands {
    /// Generate a fleet-wide plan across multiple hosts
    Plan(AgentFleetPlanArgs),
    /// Apply a fleet plan for a fleet session
    Apply(AgentFleetApplyArgs),
    /// Generate a fleet report from a fleet session
    Report(AgentFleetReportArgs),
    /// Show fleet session status
    Status(AgentFleetStatusArgs),
    /// Transfer learning data (priors + signatures) between hosts
    Transfer(AgentFleetTransferArgs),
}

#[derive(Args, Debug)]
struct AgentFleetPlanArgs {
    /// Hosts spec (comma-separated list or file path)
    #[arg(long, conflicts_with_all = ["inventory", "discovery_config"])]
    hosts: Option<String>,

    /// Inventory file path (TOML/YAML/JSON)
    #[arg(long, conflicts_with_all = ["hosts", "discovery_config"])]
    inventory: Option<String>,

    /// Discovery config file path (TOML/YAML/JSON)
    #[arg(long, conflicts_with_all = ["hosts", "inventory"])]
    discovery_config: Option<String>,

    /// Max concurrent host connections
    #[arg(long, default_value = "10")]
    parallel: u32,

    /// Per-host timeout (seconds)
    #[arg(long, default_value = "30")]
    timeout: u64,

    /// Continue if a host fails
    #[arg(long)]
    continue_on_error: bool,

    /// Apply host-group priors
    #[arg(long)]
    host_profile: Option<String>,

    /// Optional label for the fleet session
    #[arg(long)]
    label: Option<String>,

    /// Fleet-wide max FDR budget
    #[arg(long, default_value = "0.05")]
    max_fdr: f64,
}

#[derive(Args, Debug)]
struct AgentFleetApplyArgs {
    /// Fleet session ID
    #[arg(long)]
    fleet_session: String,

    /// Max concurrent host connections
    #[arg(long, default_value = "10")]
    parallel: u32,

    /// Per-host timeout (seconds)
    #[arg(long, default_value = "30")]
    timeout: u64,

    /// Continue if a host fails
    #[arg(long)]
    continue_on_error: bool,
}

#[derive(Args, Debug)]
struct AgentFleetReportArgs {
    /// Fleet session ID
    #[arg(long)]
    fleet_session: String,

    /// Output path for report (optional for JSON output)
    #[arg(long)]
    out: Option<String>,

    /// Redaction profile (minimal|safe|forensic)
    #[arg(long, default_value = "safe")]
    profile: String,
}

#[derive(Args, Debug)]
struct AgentFleetStatusArgs {
    /// Fleet session ID
    #[arg(long)]
    fleet_session: String,
}

#[derive(Args, Debug)]
struct AgentFleetTransferArgs {
    #[command(subcommand)]
    command: AgentFleetTransferCommands,
}

#[derive(Subcommand, Debug)]
enum AgentFleetTransferCommands {
    /// Export priors and signatures as a transfer bundle
    Export(AgentFleetTransferExportArgs),
    /// Import a transfer bundle (priors + signatures)
    Import(AgentFleetTransferImportArgs),
    /// Show diff between local state and an incoming bundle
    Diff(AgentFleetTransferDiffArgs),
}

#[derive(Args, Debug)]
struct AgentFleetTransferExportArgs {
    /// Output path (.json or .ptb)
    #[arg(short, long)]
    out: String,

    /// Tag export with host profile name
    #[arg(long)]
    host_profile: Option<String>,

    /// Include signatures in bundle
    #[arg(long, default_value = "true")]
    include_signatures: bool,

    /// Include priors in bundle
    #[arg(long, default_value = "true")]
    include_priors: bool,

    /// Redaction profile (minimal|safe|forensic)
    #[arg(long)]
    export_profile: Option<String>,

    /// Passphrase for .ptb encryption
    #[arg(long)]
    passphrase: Option<String>,
}

#[derive(Args, Debug)]
struct AgentFleetTransferImportArgs {
    /// Input bundle path (.json or .ptb)
    #[arg(long)]
    from: String,

    /// Merge strategy: weighted, replace, keep-local
    #[arg(long)]
    merge_strategy: Option<String>,

    /// Show what would change without modifying
    #[arg(long)]
    dry_run: bool,

    /// Skip backup of existing priors
    #[arg(long)]
    no_backup: bool,

    /// Passphrase for .ptb decryption
    #[arg(long)]
    passphrase: Option<String>,

    /// Normalize incoming priors using baseline stats
    #[arg(long)]
    normalize_baseline: bool,
}

#[derive(Args, Debug)]
struct AgentFleetTransferDiffArgs {
    /// Path to incoming transfer bundle
    #[arg(long)]
    from: String,

    /// Passphrase for .ptb decryption
    #[arg(long)]
    passphrase: Option<String>,
}

#[derive(Args, Debug)]
struct AgentInitArgs {
    /// Apply defaults without prompts
    #[arg(long)]
    yes: bool,

    /// Show what would change without modifying files
    #[arg(long)]
    dry_run: bool,

    /// Configure specific agent only (claude, codex, copilot, cursor, windsurf)
    #[arg(long)]
    agent: Option<String>,

    /// Skip creating backup files
    #[arg(long)]
    skip_backup: bool,
}

#[derive(Args, Debug)]
struct AgentTailArgs {
    /// Session ID to tail
    #[arg(long)]
    session: String,

    /// Follow the file for new events
    #[arg(long)]
    follow: bool,
}

#[derive(Args, Debug)]
struct AgentWatchArgs {
    /// Execute command via shell when watch events are emitted (legacy; prefer --notify-cmd)
    #[arg(long = "notify-exec")]
    notify_exec: Option<String>,

    /// Execute command directly (no shell) when watch events are emitted
    #[arg(long = "notify-cmd")]
    notify_cmd: Option<String>,

    /// Arguments for --notify-cmd (repeatable)
    #[arg(long = "notify-arg")]
    notify_arg: Vec<String>,

    /// Trigger sensitivity (low|medium|high|critical)
    #[arg(long, default_value = "medium")]
    threshold: String,

    /// Check interval in seconds
    #[arg(long, default_value = "60")]
    interval: u64,

    /// Only consider processes older than threshold (seconds)
    #[arg(long)]
    min_age: Option<u64>,

    /// Run a single iteration and exit
    #[arg(long)]
    once: bool,

    /// Goal: minimum memory available (GB) before alerting
    #[arg(long)]
    goal_memory_available_gb: Option<f64>,

    /// Goal: maximum 1-minute load average before alerting
    #[arg(long)]
    goal_load_max: Option<f64>,
}

#[derive(Args, Debug)]
struct AgentPlanArgs {
    /// Resume existing session
    #[arg(long)]
    session: Option<String>,

    /// Label for this plan session (e.g. "baseline" for diff --baseline)
    #[arg(long)]
    label: Option<String>,

    /// Maximum candidates to return
    #[arg(long, default_value = "20")]
    max_candidates: u32,

    /// Minimum posterior probability threshold for candidate selection
    #[arg(
        long = "min-posterior",
        visible_alias = "threshold",
        default_value = "0.7"
    )]
    min_posterior: f64,

    /// Filter by recommendation (kill, review, all)
    #[arg(long, default_value = "all")]
    only: String,

    /// Skip safety gate confirmations (use with caution)
    #[arg(long)]
    yes: bool,

    /// Include kernel threads as candidates (default: exclude)
    #[arg(long)]
    include_kernel_threads: bool,

    /// Force deep scan with all available probes
    #[arg(long)]
    deep: bool,

    /// Only consider processes older than threshold (seconds)
    #[arg(long)]
    min_age: Option<u64>,

    /// Limit inference to a random sample of N processes (for testing)
    #[arg(long)]
    sample_size: Option<usize>,

    /// Include trajectory prediction analysis in output
    #[arg(long)]
    include_predictions: bool,

    /// Select prediction subfields to include (comma-separated)
    /// Options: memory,cpu,eta_abandoned,eta_resource_limit,trajectory,diagnostics
    #[arg(long, value_name = "FIELDS")]
    prediction_fields: Option<String>,

    // === Future flags (stub implementation for API surface discovery) ===
    // These are parsed but not yet functional. Using them will generate a warning.
    // Full implementation is tracked in separate beads.
    /// Compare against prior session for differential analysis (coming in v1.2)
    #[arg(long, help = "Compare against prior session (coming in v1.2)")]
    since: Option<String>,

    /// Compare against time for temporal differential analysis (coming in v1.2)
    #[arg(
        long,
        help = "Compare against time, e.g. '2h' or ISO timestamp (coming in v1.2)"
    )]
    since_time: Option<String>,

    /// Resource recovery goal for goal-oriented optimization
    #[arg(long, help = "Resource recovery goal, e.g. 'free 4GB RAM'")]
    goal: Option<String>,

    /// Minimal JSON output (PIDs, scores, and recommendations only)
    #[arg(long)]
    minimal: bool,

    /// Pretty-print JSON output
    #[arg(long)]
    pretty: bool,

    /// Brief output: minimal fields + single-line rationale per candidate
    #[arg(long, conflicts_with = "narrative")]
    brief: bool,

    /// Narrative output: human-readable prose summary
    #[arg(long, conflicts_with = "brief")]
    narrative: bool,
}

#[derive(Args, Debug)]
struct AgentExplainArgs {
    /// Session ID (required)
    #[arg(long)]
    session: String,

    /// PIDs to explain
    #[arg(long, value_delimiter = ',')]
    pids: Vec<u32>,

    /// Target process with stable identity (format: pid:start_id)
    #[arg(long)]
    target: Option<String>,

    /// Include evidence breakdown
    #[arg(long = "include", value_name = "TYPE")]
    include: Vec<String>,

    /// Include galaxy-brain math ledger
    #[arg(long)]
    galaxy_brain: bool,

    /// Show process dependencies tree
    #[arg(long)]
    show_dependencies: bool,

    /// Show blast radius impact analysis
    #[arg(long)]
    show_blast_radius: bool,

    /// Show process history/backstory
    #[arg(long)]
    show_history: bool,

    /// Show what-if hypotheticals
    #[arg(long)]
    what_if: bool,
}

#[cfg(target_os = "linux")]
use pt_core::action::{
    ActionRunner, IdentityProvider, LiveIdentityProvider, SignalActionRunner, SignalConfig,
};
use pt_core::decision::{
    goal_optimizer::{
        optimize_greedy, optimize_ilp, OptCandidate, OptimizationResult, ResourceGoal,
    },
    goal_parser::{parse_goal, Comparator, Goal, Metric, ResourceTarget},
    ConstraintChecker, RobotCandidate, RuntimeRobotConstraints,
};
use pt_core::plan::{Plan, PlanAction};

#[derive(Args, Debug)]
struct AgentApplyArgs {
    /// Session ID (required)
    #[arg(long)]
    session: String,

    /// PIDs to act on (default: all recommended)
    #[arg(long, value_delimiter = ',')]
    pids: Vec<u32>,

    /// Specific targets with identity (pid:start_id)
    #[arg(long, value_delimiter = ',')]
    targets: Vec<String>,

    /// Skip safety gate confirmations
    #[arg(long)]
    yes: bool,

    /// Apply all recommended actions
    #[arg(long)]
    recommended: bool,

    /// Only consider processes older than threshold (seconds)
    #[arg(long)]
    min_age: Option<u64>,

    /// Minimum posterior probability required (e.g. 0.99)
    #[arg(long)]
    min_posterior: Option<f64>,

    /// Max blast radius per action (MB)
    #[arg(long)]
    max_blast_radius: Option<f64>,

    /// Max total blast radius for the run (MB)
    #[arg(long)]
    max_total_blast_radius: Option<f64>,

    /// Max kills per run
    #[arg(long)]
    max_kills: Option<u32>,

    /// Require known signature match
    #[arg(long)]
    require_known_signature: bool,

    /// Only act on specific categories
    #[arg(long, value_delimiter = ',')]
    only_categories: Vec<String>,

    /// Exclude specific categories
    #[arg(long, value_delimiter = ',')]
    exclude_categories: Vec<String>,

    /// Abort if unknown error/condition
    #[arg(long)]
    abort_on_unknown: bool,

    /// Resume interrupted apply (skip already completed actions)
    #[arg(long)]
    resume: bool,
}

fn config_options(global: &GlobalOpts) -> ConfigOptions {
    ConfigOptions {
        config_dir: global.config.as_ref().map(PathBuf::from),
        priors_path: None,
        policy_path: None,
    }
}

#[derive(Args, Debug)]
struct AgentVerifyArgs {
    /// Session ID (required)
    #[arg(long)]
    session: String,

    /// Wait for process termination with timeout in seconds (default: 0 = no wait)
    #[arg(long, default_value = "0")]
    wait: u64,

    /// Check if killed processes have respawned
    #[arg(long)]
    check_respawn: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FocusMode {
    All,
    New,
    Removed,
    Changed,
    Resources,
}

impl FocusMode {
    fn as_str(&self) -> &'static str {
        match self {
            FocusMode::All => "all",
            FocusMode::New => "new",
            FocusMode::Removed => "removed",
            FocusMode::Changed => "changed",
            FocusMode::Resources => "resources",
        }
    }
}

fn parse_focus_mode(value: &str) -> Result<FocusMode, String> {
    match value.to_lowercase().as_str() {
        "all" => Ok(FocusMode::All),
        "new" => Ok(FocusMode::New),
        "removed" => Ok(FocusMode::Removed),
        "changed" => Ok(FocusMode::Changed),
        "resources" => Ok(FocusMode::Resources),
        other => Err(format!(
            "Invalid focus mode: \"{}\". Valid values: all, new, removed, changed, resources",
            other
        )),
    }
}

#[derive(Args, Debug)]
struct AgentDiffArgs {
    /// Base session ID (the "before" snapshot)
    #[arg(long, alias = "session", alias = "since", alias = "before")]
    base: String,

    /// Compare session ID (the "after" snapshot, default: current)
    #[arg(long, alias = "vs", alias = "after")]
    compare: Option<String>,

    /// Focus diff output on specific changes: all, new, removed, changed, resources
    #[arg(long, default_value = "all", value_parser = parse_focus_mode)]
    focus: FocusMode,
}

#[derive(Args, Debug)]
struct AgentSnapshotArgs {
    /// Label for the snapshot
    #[arg(long)]
    label: Option<String>,

    /// Limit to top N processes by resource usage (CPU+memory)
    #[arg(long)]
    top: Option<usize>,

    /// Include environment variables in snapshot (redacted by default)
    #[arg(long)]
    include_env: bool,

    /// Include network connection information
    #[arg(long)]
    include_network: bool,

    /// Minimal JSON output (host info and basic stats only)
    #[arg(long)]
    minimal: bool,

    /// Pretty-print JSON output
    #[arg(long)]
    pretty: bool,
}

#[derive(Args, Debug)]
struct AgentCapabilitiesArgs {
    /// Check if a specific action type is supported (e.g., "sigterm", "sigkill", "strace")
    #[arg(long)]
    check_action: Option<String>,
}

#[derive(Args, Debug)]
struct AgentSessionsArgs {
    /// Show details for a specific session (consolidates show/status)
    #[arg(long, alias = "status", alias = "show")]
    session: Option<String>,

    /// Include full session detail (plan contents, actions taken)
    #[arg(long)]
    detail: bool,

    /// Maximum sessions to return in list mode (default: 10)
    #[arg(long, default_value = "10")]
    limit: u32,

    /// Filter by session state
    #[arg(long)]
    state: Option<String>,

    /// Remove old sessions
    #[arg(long)]
    cleanup: bool,

    /// Remove sessions older than duration (e.g., "7d", "30d")
    #[arg(long, default_value = "7d")]
    older_than: String,
}

#[derive(Args, Debug)]
struct AgentListPriorsArgs {
    /// Filter by class (useful, useful_bad, abandoned, zombie)
    #[arg(long)]
    class: Option<String>,

    /// Include all hyperparameters (extended output)
    #[arg(long)]
    extended: bool,
}

#[derive(Args, Debug)]
struct AgentInboxArgs {
    /// Acknowledge/dismiss an item by ID
    #[arg(long)]
    ack: Option<String>,

    /// Clear all acknowledged items
    #[arg(long)]
    clear: bool,

    /// Clear all items (including unacknowledged)
    #[arg(long)]
    clear_all: bool,

    /// Show only unread items
    #[arg(long)]
    unread: bool,
}

#[derive(Args, Debug)]
struct AgentExportPriorsArgs {
    /// Output file path for exported priors
    #[arg(long, short = 'o')]
    out: String,

    /// Tag priors with host profile name for smart matching
    #[arg(long)]
    host_profile: Option<String>,
}

#[derive(Args, Debug)]
struct AgentImportPriorsArgs {
    /// Input file path for priors to import
    #[arg(long, short = 'i')]
    from: String,

    /// Merge with existing priors (weighted average)
    #[arg(long, conflicts_with = "replace")]
    merge: bool,

    /// Replace existing priors entirely
    #[arg(long, conflicts_with = "merge")]
    replace: bool,

    /// Apply only to specific host profile
    #[arg(long)]
    host_profile: Option<String>,

    /// Dry run (show what would change without modifying)
    #[arg(long)]
    dry_run: bool,

    /// Skip backup of existing priors
    #[arg(long)]
    no_backup: bool,
}

/// Arguments for the agent report command.
#[cfg(feature = "report")]
#[derive(Args, Debug)]
struct AgentReportArgs {
    /// Session ID to generate report for (required unless using --bundle)
    #[arg(long)]
    session: Option<String>,

    /// Path to a .ptb bundle file (alternative to --session)
    #[arg(long)]
    bundle: Option<String>,

    /// Output path for the HTML report
    #[arg(short, long)]
    out: Option<String>,

    /// Redaction profile: minimal, safe (default), forensic
    #[arg(long, default_value = "safe")]
    profile: String,

    /// Include full math ledger in report (galaxy-brain mode)
    #[arg(long)]
    galaxy_brain: bool,

    /// Inline CDN assets for offline viewing (file:// support)
    #[arg(long)]
    embed_assets: bool,

    /// Report output format: html (default), slack, prose
    #[arg(long = "report-format", default_value = "html")]
    report_format: String,

    /// Prose style: terse, conversational (default), formal, technical
    #[arg(long, default_value = "conversational")]
    prose_style: String,

    /// Custom report title
    #[arg(long)]
    title: Option<String>,

    /// Report theme: light, dark, auto (default)
    #[arg(long, default_value = "auto")]
    theme: String,
}

#[derive(Args, Debug)]
struct ConfigArgs {
    #[command(subcommand)]
    command: ConfigCommands,
}

#[derive(Subcommand, Debug)]
enum ConfigCommands {
    /// Show current configuration
    Show {
        /// Show specific config file (priors, policy, capabilities)
        #[arg(long)]
        file: Option<String>,
    },
    /// Print JSON schema for configuration files
    Schema {
        /// Schema to print (priors, policy, capabilities)
        #[arg(long)]
        file: String,
    },
    /// Validate configuration files
    Validate {
        /// Specific file to validate
        path: Option<String>,
    },
    /// List available configuration presets
    ListPresets,
    /// Show configuration values for a preset
    ShowPreset {
        /// Preset name: developer, server, ci, or paranoid
        preset: String,
    },
    /// Compare a preset with current configuration
    DiffPreset {
        /// Preset name to compare against
        preset: String,
    },
    /// Export a preset to a file
    ExportPreset {
        /// Preset name to export
        preset: String,

        /// Output file path (stdout if not specified)
        #[arg(short, long)]
        output: Option<String>,
    },
}

#[cfg(feature = "daemon")]
#[derive(Args, Debug)]
struct DaemonArgs {
    #[command(subcommand)]
    command: Option<DaemonCommands>,
}

#[cfg(feature = "daemon")]
#[derive(Subcommand, Debug)]
enum DaemonCommands {
    /// Start the daemon
    Start {
        /// Run in foreground
        #[arg(long)]
        foreground: bool,
    },
    /// Stop the daemon
    Stop,
    /// Check daemon status
    Status,
}

#[derive(Args, Debug)]
struct TelemetryArgs {
    /// Telemetry root directory (defaults to XDG data dir)
    #[arg(long, global = true)]
    telemetry_dir: Option<String>,

    /// Retention config JSON path (defaults to config dir telemetry_retention.json if present)
    #[arg(long, global = true)]
    retention_config: Option<String>,

    #[command(subcommand)]
    command: TelemetryCommands,
}

#[derive(Subcommand, Debug)]
enum TelemetryCommands {
    /// Show telemetry status
    Status,
    /// Export telemetry data
    Export {
        /// Output path
        #[arg(short, long)]
        output: String,

        /// Export format (parquet, csv, json)
        #[arg(long, default_value = "parquet")]
        format: String,
    },
    /// Prune old telemetry data
    Prune {
        /// Keep data newer than (e.g., "30d", "90d")
        #[arg(long, default_value = "30d")]
        keep: String,

        /// Preview retention actions without deleting files
        #[arg(long)]
        dry_run: bool,

        /// Keep everything (disable pruning)
        #[arg(long)]
        keep_everything: bool,
    },
    /// Redact sensitive data
    Redact {
        /// Apply redaction to all stored telemetry
        #[arg(long)]
        all: bool,
    },
}

#[derive(Args, Debug)]
struct ShadowArgs {
    #[command(subcommand)]
    command: ShadowCommands,
}

#[derive(Subcommand, Debug)]
enum ShadowCommands {
    /// Start shadow mode observation loop
    Start(ShadowStartArgs),
    /// Run a foreground shadow loop (internal)
    #[command(hide = true)]
    Run(ShadowStartArgs),
    /// Stop background shadow observer
    Stop,
    /// Show shadow observer status and stats
    Status,
    /// Export shadow observations for calibration analysis
    Export(ShadowExportArgs),
    /// Generate a calibration/validation report from shadow observations
    Report(ShadowReportArgs),
}

#[derive(Args, Debug, Clone)]
struct ShadowStartArgs {
    /// Interval between scans (seconds)
    #[arg(long, default_value = "300")]
    interval: u64,

    /// Interval between deep scans (seconds, 0 disables)
    #[arg(long, default_value = "3600")]
    deep_interval: u64,

    /// Number of iterations before exiting (0 = run forever)
    #[arg(long, default_value = "0")]
    iterations: u32,

    /// Run in background (daemon-style)
    #[arg(long)]
    background: bool,

    /// Maximum candidates to return per scan
    #[arg(long, default_value = "20")]
    max_candidates: u32,

    /// Minimum posterior probability threshold
    #[arg(long = "min-posterior", default_value = "0.7")]
    min_posterior: f64,

    /// Filter by recommendation (kill, review, all)
    #[arg(long, default_value = "all")]
    only: String,

    /// Include kernel threads as candidates
    #[arg(long)]
    include_kernel_threads: bool,

    /// Force deep scan with all available probes
    #[arg(long)]
    deep: bool,

    /// Only consider processes older than threshold (seconds)
    #[arg(long)]
    min_age: Option<u64>,

    /// Limit inference to a random sample of N processes
    #[arg(long)]
    sample_size: Option<usize>,
}

#[derive(Args, Debug)]
struct ShadowExportArgs {
    /// Output path (stdout if omitted)
    #[arg(short, long)]
    output: Option<String>,

    /// Export format (json, jsonl)
    #[arg(long = "export-format", default_value = "json")]
    export_format: String,

    /// Max observations to export (most recent first)
    #[arg(long)]
    limit: Option<usize>,
}

#[derive(Args, Debug)]
struct ShadowReportArgs {
    /// Output path (stdout if omitted)
    #[arg(short, long)]
    output: Option<String>,

    /// Classification threshold for kill recommendations
    #[arg(long, default_value = "0.5")]
    threshold: f64,

    /// Max observations to analyze (most recent first)
    #[arg(long)]
    limit: Option<usize>,
}

#[derive(Args, Debug)]
struct SchemaArgs {
    /// Type name to generate schema for (e.g., Plan, DecisionOutcome)
    #[arg(value_name = "TYPE")]
    type_name: Option<String>,

    /// List all available schema types
    #[arg(long, short)]
    list: bool,

    /// Generate schemas for all types
    #[arg(long, short)]
    all: bool,

    /// Output compact JSON (no pretty-printing)
    #[arg(long)]
    compact: bool,
}

#[derive(Args, Debug)]
struct McpArgs {
    /// Transport: stdio (default) for standard MCP integration
    #[arg(long, default_value = "stdio")]
    transport: String,
}

#[derive(Args, Debug)]
struct UpdateArgs {
    #[command(subcommand)]
    command: UpdateCommands,
}

#[derive(Subcommand, Debug)]
enum UpdateCommands {
    /// Rollback to a previous version
    Rollback {
        /// Target version to rollback to (default: most recent backup)
        target: Option<String>,

        /// Force rollback without confirmation
        #[arg(long)]
        force: bool,
    },
    /// List available backup versions
    ListBackups,
    /// Show backup details
    ShowBackup {
        /// Version to inspect
        target: String,
    },
    /// Verify a backup's integrity
    VerifyBackup {
        /// Version to verify (default: most recent)
        target: Option<String>,
    },
    /// Remove old backups (keep most recent N)
    PruneBackups {
        /// Number of backups to keep
        #[arg(long, default_value = "3")]
        keep: usize,
    },
}

use pt_core::log_event;
use pt_core::logging::{
    event_names, init_logging, LogConfig, LogContext, LogFormat, LogLevel, Stage,
};

// ============================================================================
// Main entry point
// ============================================================================

fn main() {
    let matches = Cli::command().get_matches();
    let mut cli = Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());
    let format_source = matches.value_source("format");
    cli.global.format = resolve_output_format(cli.global.format, format_source);

    // Initialize logging
    let log_level = if cli.global.quiet {
        LogLevel::Error
    } else {
        match cli.global.verbose {
            0 => LogLevel::Info,
            1 => LogLevel::Debug,
            _ => LogLevel::Trace,
        }
    };

    // Use JSONL logging if output format is JSON (to match machine-readable intent)
    // or if explicitly requested via env var (handled by LogConfig::from_env, but we are overriding here).
    // Actually, keeping stderr human-readable is usually better for CLI users even if stdout is JSON.
    // Let's stick to Human for CLI use unless specifically requested otherwise.
    // But wait, if I'm an agent parsing JSON stdout, I might want JSONL stderr too.
    let log_format = if matches!(
        cli.global.format,
        OutputFormat::Json | OutputFormat::Jsonl | OutputFormat::Toon
    ) {
        LogFormat::Jsonl
    } else {
        LogFormat::Human
    };

    let log_config = LogConfig {
        level: log_level,
        format: log_format,
        timestamps: true,
        source_location: false,
    };
    init_logging(&log_config);

    let exit_code = match cli.command {
        None => {
            // Default: run interactive mode
            run_interactive(
                &cli.global,
                &RunArgs {
                    deep: false,
                    inline: false,
                    signatures: None,
                    community_signatures: false,
                    min_age: None,
                    goal: None,
                    theme: None,
                    high_contrast: false,
                    reduce_motion: false,
                },
            )
        }
        Some(Commands::Run(args)) => run_interactive(&cli.global, &args),
        Some(Commands::Scan(args)) => run_scan(&cli.global, &args),
        Some(Commands::DeepScan(args)) => run_deep_scan(&cli.global, &args),
        Some(Commands::Diff(args)) => run_diff(&cli.global, &args),
        Some(Commands::Query(args)) => run_query(&cli.global, &args),
        Some(Commands::Bundle(args)) => run_bundle(&cli.global, &args),
        Some(Commands::Report(args)) => run_report(&cli.global, &args),
        Some(Commands::Check(args)) => run_check(&cli.global, &args),
        Some(Commands::Agent(args)) => run_agent(&cli.global, &args),
        Some(Commands::Config(args)) => run_config(&cli.global, &args),
        #[cfg(feature = "daemon")]
        Some(Commands::Daemon(args)) => run_daemon(&cli.global, &args),
        Some(Commands::Telemetry(args)) => run_telemetry(&cli.global, &args),
        Some(Commands::Shadow(args)) => run_shadow(&cli.global, &args),
        Some(Commands::Signature(args)) => {
            pt_core::signature_cli::run_signature(&cli.global.format, &args)
        }
        Some(Commands::Schema(args)) => run_schema(&cli.global, &args),
        Some(Commands::Mcp(args)) => run_mcp(&args),
        Some(Commands::Update(args)) => run_update(&cli.global, &args),
        Some(Commands::Version) => {
            print_version(&cli.global);
            ExitCode::Clean
        }
    };

    std::process::exit(exit_code.as_i32());
}

fn resolve_output_format(current: OutputFormat, source: Option<ValueSource>) -> OutputFormat {
    match source {
        Some(ValueSource::CommandLine) | Some(ValueSource::EnvVariable) => current,
        _ => {
            if let Ok(value) = std::env::var("TOON_DEFAULT_FORMAT") {
                if let Some(parsed) = parse_output_format(&value) {
                    return parsed;
                }
            }
            current
        }
    }
}

fn parse_output_format(value: &str) -> Option<OutputFormat> {
    let normalized = value.trim().to_lowercase().replace('_', "-");
    match normalized.as_str() {
        "json" => Some(OutputFormat::Json),
        "toon" => Some(OutputFormat::Toon),
        "md" | "markdown" => Some(OutputFormat::Md),
        "jsonl" | "json-lines" | "lines" => Some(OutputFormat::Jsonl),
        "summary" | "brief" => Some(OutputFormat::Summary),
        "metrics" | "kv" | "key-value" => Some(OutputFormat::Metrics),
        "slack" => Some(OutputFormat::Slack),
        "exitcode" | "exit-code" => Some(OutputFormat::Exitcode),
        "prose" | "narrative" => Some(OutputFormat::Prose),
        _ => None,
    }
}

#[cfg(test)]
mod output_format_tests {
    use super::parse_output_format;
    use pt_common::OutputFormat;

    #[test]
    fn parse_output_format_supports_all_canonical_variants() {
        assert_eq!(parse_output_format("json"), Some(OutputFormat::Json));
        assert_eq!(parse_output_format("toon"), Some(OutputFormat::Toon));
        assert_eq!(parse_output_format("md"), Some(OutputFormat::Md));
        assert_eq!(parse_output_format("jsonl"), Some(OutputFormat::Jsonl));
        assert_eq!(parse_output_format("summary"), Some(OutputFormat::Summary));
        assert_eq!(parse_output_format("metrics"), Some(OutputFormat::Metrics));
        assert_eq!(parse_output_format("slack"), Some(OutputFormat::Slack));
        assert_eq!(
            parse_output_format("exitcode"),
            Some(OutputFormat::Exitcode)
        );
        assert_eq!(parse_output_format("prose"), Some(OutputFormat::Prose));
    }

    #[test]
    fn parse_output_format_supports_aliases_and_case_whitespace() {
        assert_eq!(parse_output_format("  MARKDOWN  "), Some(OutputFormat::Md));
        assert_eq!(parse_output_format("lines"), Some(OutputFormat::Jsonl));
        assert_eq!(parse_output_format("json_lines"), Some(OutputFormat::Jsonl));
        assert_eq!(parse_output_format("brief"), Some(OutputFormat::Summary));
        assert_eq!(
            parse_output_format("key-value"),
            Some(OutputFormat::Metrics)
        );
        assert_eq!(
            parse_output_format("exit-code"),
            Some(OutputFormat::Exitcode)
        );
        assert_eq!(parse_output_format("narrative"), Some(OutputFormat::Prose));
    }

    #[test]
    fn parse_output_format_rejects_unknown_values() {
        assert_eq!(parse_output_format("compact"), None);
        assert_eq!(parse_output_format("csv"), None);
        assert_eq!(parse_output_format(""), None);
    }
}

// ============================================================================
// Command implementations (stubs)
// ============================================================================

fn run_interactive(global: &GlobalOpts, args: &RunArgs) -> ExitCode {
    let _lock = match acquire_global_lock(global, "run") {
        Ok(lock) => lock,
        Err(code) => return code,
    };
    #[cfg(not(feature = "ui"))]
    let _ = args;
    #[cfg(feature = "ui")]
    {
        match run_interactive_tui(global, args) {
            Ok(()) => ExitCode::Clean,
            Err(err) => {
                eprintln!("run: {}", err);
                ExitCode::InternalError
            }
        }
    }
    #[cfg(not(feature = "ui"))]
    {
        output_stub(
            global,
            "run",
            "Interactive mode requires the `ui` feature (build with --features ui)",
        );
        ExitCode::PartialFail
    }
}

#[cfg(feature = "ui")]
fn run_interactive_tui(global: &GlobalOpts, args: &RunArgs) -> Result<(), String> {
    let store = SessionStore::from_env().map_err(|e| format!("session store error: {}", e))?;
    let session_id = SessionId::new();
    let manifest = SessionManifest::new(&session_id, None, SessionMode::Interactive, None);
    let handle = store
        .create(&manifest)
        .map_err(|e| format!("failed to create session: {}", e))?;

    let ctx = SessionContext::new(
        &session_id,
        pt_core::logging::get_host_id(),
        pt_core::logging::generate_run_id(),
        None,
    );
    handle
        .write_context(&ctx)
        .map_err(|e| format!("failed to write context.json: {}", e))?;

    let _ = handle.update_state(SessionState::Scanning);

    let config_options = ConfigOptions {
        config_dir: global.config.as_ref().map(PathBuf::from),
        ..Default::default()
    };
    let config = load_config(&config_options).map_err(|e| format!("load config: {}", e))?;
    let priors = config.priors.clone();
    let policy = config.policy.clone();

    let TuiBuildOutput {
        rows,
        plan_candidates,
        goal_summary,
        goal_order,
    } = build_tui_data_from_live_scan(global, args, &priors, &policy)?;

    let _ = handle.update_state(SessionState::Planned);

    let mut app = App::new();

    // Apply theme from CLI flags (highest priority) or environment detection.
    // Priority: --theme > --high-contrast > --no-color (global) > env vars > dark default.
    // Apply theme from CLI flags (highest priority) or environment detection.
    // Priority: --theme > --high-contrast > --no-color (global) > env vars > dark default.
    {
        use pt_core::tui::Theme as TuiTheme;
        if let Some(ref theme_name) = args.theme {
            app.theme = match theme_name.as_str() {
                "light" => TuiTheme::light(),
                "high-contrast" => TuiTheme::high_contrast(),
                "no-color" => TuiTheme::no_color(),
                _ => TuiTheme::dark(),
            };
        } else if args.high_contrast {
            app.theme = TuiTheme::high_contrast();
        } else if global.no_color {
            app.theme = TuiTheme::no_color();
        }
    }

    // --reduce-motion CLI flag overrides env var detection from App::new().
    if args.reduce_motion {
        app.reduce_motion = true;
    }

    app.process_table.set_rows(rows);
    app.process_table.set_goal_order(goal_order);
    if let Some(lines) = goal_summary {
        app.set_goal_summary(lines);
    }
    app.process_table.select_recommended();
    app.set_status(format!(
        "Session {} • {} candidates",
        session_id.0,
        app.process_table.rows.len()
    ));

    // ftui runtime path: terminal setup/teardown handled by Program RAII.
    // Closures capture cloned, Send + 'static data for Cmd::task.
    {
        let plan_candidates = Arc::new(Mutex::new(plan_candidates));

        // Build refresh closure
        let plan_cache_r = Arc::clone(&plan_candidates);
        let priors_r = priors.clone();
        let policy_r = policy.clone();
        let timeout_r = global.timeout;
        let deep_r = args.deep;
        let min_age_r = args.min_age;
        let goal_r = args.goal.clone();
        let policy_scan_r = policy.clone();

        let refresh_fn: Arc<dyn Fn() -> Result<Vec<ProcessRow>, String> + Send + Sync> =
            Arc::new(move || {
                let scan_options = QuickScanOptions {
                    pids: vec![],
                    include_kernel_threads: false,
                    timeout: timeout_r.map(std::time::Duration::from_secs),
                    progress: None,
                };
                let scan_result =
                    quick_scan(&scan_options).map_err(|e| format!("scan failed: {}", e))?;
                let deep_signals = if deep_r {
                    collect_deep_signals(&scan_result.processes)
                } else {
                    None
                };
                let protected_filter = ProtectedFilter::from_guardrails(&policy_scan_r.guardrails)
                    .map_err(|e| format!("filter error: {}", e))?;
                let filter_result = protected_filter.filter_scan_result(&scan_result);
                let output = build_tui_rows(
                    &filter_result.passed,
                    min_age_r,
                    deep_signals.as_ref(),
                    &priors_r,
                    &policy_r,
                    goal_r.as_deref(),
                );
                let mut guard = plan_cache_r
                    .lock()
                    .map_err(|_| "plan cache lock poisoned".to_string())?;
                *guard = output.plan_candidates;
                Ok(output.rows)
            });

        // Build execute closure
        let plan_cache_e = Arc::clone(&plan_candidates);
        let session_id_e = session_id.clone();
        let policy_e = policy.clone();
        let handle_e = handle.clone();
        let dry_run = global.dry_run;
        let shadow = global.shadow;

        let execute_fn: Arc<dyn Fn(Vec<u32>) -> Result<ExecutionOutcome, String> + Send + Sync> =
            Arc::new(move |selected: Vec<u32>| {
                let candidates = plan_cache_e
                    .lock()
                    .map_err(|_| "plan cache lock poisoned".to_string())?;
                let plan =
                    build_plan_from_selection(&session_id_e, &policy_e, &selected, &candidates)?;
                drop(candidates); // release lock before I/O

                if plan.actions.is_empty() {
                    return Err("no actions to apply for selected processes".to_string());
                }

                write_plan_to_session(&handle_e, &plan)?;

                if dry_run || shadow {
                    let mode = if dry_run { "dry_run" } else { "shadow" };
                    write_outcomes_for_mode(&handle_e, &plan, mode)
                        .map_err(|e| format!("write outcomes: {}", e))?;
                    return Ok(ExecutionOutcome {
                        mode: Some(mode.to_string()),
                        attempted: plan.actions.len(),
                        succeeded: 0,
                        failed: 0,
                    });
                }

                let _ = handle_e.update_state(SessionState::Executing);
                match execute_plan_actions(&handle_e, &policy_e, &plan) {
                    Ok(result) => {
                        write_outcomes_from_execution(&handle_e, &plan, &result)
                            .map_err(|e| format!("write outcomes: {}", e))?;
                        let final_state = if result.summary.actions_failed > 0 {
                            SessionState::Failed
                        } else {
                            SessionState::Completed
                        };
                        let _ = handle_e.update_state(final_state);
                        Ok(ExecutionOutcome {
                            mode: None,
                            attempted: result.summary.actions_attempted,
                            succeeded: result.summary.actions_succeeded,
                            failed: result.summary.actions_failed,
                        })
                    }
                    Err(e) => {
                        let _ = handle_e.update_state(SessionState::Failed);
                        Err(e)
                    }
                }
            });

        app.set_refresh_op(refresh_fn);
        app.set_execute_op(execute_fn);

        let program_config = if args.inline {
            ftui::ProgramConfig::inline(compute_inline_ui_height())
        } else {
            ftui::ProgramConfig::fullscreen()
        };
        run_ftui(app, program_config).map_err(|e| format!("tui error: {}", e))?;
    }

    if let Ok(manifest) = handle.read_manifest() {
        if manifest.state != SessionState::Failed {
            let _ = handle.update_state(SessionState::Completed);
        }
    } else {
        let _ = handle.update_state(SessionState::Completed);
    }
    Ok(())
}

#[cfg(feature = "ui")]
fn compute_inline_ui_height() -> u16 {
    // Prefer a fixed bottom-anchored UI region, leaving some scrollback space above.
    // We avoid adding a direct terminal-size dependency here; `LINES` is widely set by shells.
    let lines = std::env::var("LINES")
        .ok()
        .and_then(|s| s.parse::<u16>().ok());
    match lines {
        Some(h) if h >= 12 => (h.saturating_sub(5)).clamp(10, 40),
        Some(h) if h >= 6 => (h.saturating_sub(2)).clamp(4, 20),
        Some(_) => 4,
        None => 20,
    }
}

#[cfg(feature = "ui")]
struct PlanCandidateInput {
    identity: ProcessIdentity,
    ppid: Option<u32>,
    decision: pt_core::decision::DecisionOutcome,
    process_state: pt_core::collect::ProcessState,
}

#[cfg(feature = "ui")]
struct TuiBuildOutput {
    rows: Vec<ProcessRow>,
    plan_candidates: HashMap<u32, PlanCandidateInput>,
    goal_summary: Option<Vec<String>>,
    goal_order: Option<HashMap<u32, usize>>,
}

#[cfg(feature = "ui")]
fn build_tui_data_from_live_scan(
    global: &GlobalOpts,
    args: &RunArgs,
    priors: &Priors,
    policy: &pt_core::config::Policy,
) -> Result<TuiBuildOutput, String> {
    let scan_options = QuickScanOptions {
        pids: vec![],
        include_kernel_threads: false,
        timeout: global.timeout.map(std::time::Duration::from_secs),
        progress: None,
    };
    let scan_result = quick_scan(&scan_options).map_err(|e| format!("scan failed: {}", e))?;

    let deep_signals = if args.deep {
        collect_deep_signals(&scan_result.processes)
    } else {
        None
    };

    let protected_filter = ProtectedFilter::from_guardrails(&policy.guardrails)
        .map_err(|e| format!("protected filter error: {}", e))?;
    let filter_result = protected_filter.filter_scan_result(&scan_result);

    Ok(build_tui_rows(
        &filter_result.passed,
        args.min_age,
        deep_signals.as_ref(),
        priors,
        policy,
        args.goal.as_deref(),
    ))
}

#[cfg(feature = "ui")]
fn build_plan_from_selection(
    session_id: &SessionId,
    policy: &pt_core::config::Policy,
    selected: &[u32],
    candidates: &HashMap<u32, PlanCandidateInput>,
) -> Result<Plan, String> {
    let mut plan_candidates = Vec::new();
    for pid in selected {
        let Some(candidate) = candidates.get(pid) else {
            continue;
        };
        plan_candidates.push(DecisionCandidate {
            identity: candidate.identity.clone(),
            ppid: candidate.ppid,
            decision: candidate.decision.clone(),
            blocked_reasons: Vec::new(),
            stage_pause_before_kill: false,
            process_state: Some(candidate.process_state),
            parent_identity: None,
            d_state_diagnostics: None,
        });
    }

    if plan_candidates.is_empty() {
        return Err("no valid candidates selected".to_string());
    }

    let bundle = DecisionBundle {
        session_id: session_id.clone(),
        policy: policy.clone(),
        candidates: plan_candidates,
        generated_at: Some(chrono::Utc::now().to_rfc3339()),
    };
    Ok(generate_plan(&bundle))
}

#[cfg(feature = "ui")]
fn write_plan_to_session(handle: &SessionHandle, plan: &Plan) -> Result<PathBuf, String> {
    let decision_dir = handle.dir.join("decision");
    if let Err(e) = std::fs::create_dir_all(&decision_dir) {
        return Err(format!("create decision dir: {}", e));
    }
    let plan_path = decision_dir.join("plan.json");
    let content =
        serde_json::to_string_pretty(plan).map_err(|e| format!("serialize plan: {}", e))?;
    std::fs::write(&plan_path, content).map_err(|e| format!("write plan: {}", e))?;
    Ok(plan_path)
}

#[cfg(feature = "ui")]
fn execute_plan_actions(
    handle: &SessionHandle,
    policy: &pt_core::config::Policy,
    plan: &Plan,
) -> Result<pt_core::action::ExecutionResult, String> {
    #[cfg(target_os = "linux")]
    {
        use pt_core::action::{
            ActionExecutor, CompositeActionRunner, LiveIdentityProvider, LivePreCheckConfig,
            LivePreCheckProvider,
        };
        let action_dir = handle.dir.join("action");
        std::fs::create_dir_all(&action_dir).map_err(|e| format!("create action dir: {}", e))?;
        let lock_path = action_dir.join("lock");
        let runner = CompositeActionRunner::with_defaults();
        let identity_provider = LiveIdentityProvider::new();
        let pre_checks =
            LivePreCheckProvider::new(Some(&policy.guardrails), LivePreCheckConfig::default())
                .unwrap_or_else(|_| LivePreCheckProvider::with_defaults());

        let executor = ActionExecutor::new(&runner, &identity_provider, lock_path)
            .with_pre_check_provider(&pre_checks);
        executor
            .execute_plan(plan)
            .map_err(|e| format!("execute plan: {}", e))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = policy;
        let _ = handle;
        let _ = plan;
        Err("execution not supported on this platform".to_string())
    }
}

#[cfg(feature = "ui")]
fn write_outcomes_for_mode(
    handle: &SessionHandle,
    plan: &Plan,
    status: &str,
) -> Result<(), String> {
    use std::io::Write;

    let outcomes_path = handle.dir.join("action").join("outcomes.jsonl");
    let _ = std::fs::create_dir_all(handle.dir.join("action"));
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&outcomes_path)
        .map_err(|e| format!("open outcomes: {}", e))?;

    for action in &plan.actions {
        let entry = serde_json::json!({
            "action_id": action.action_id,
            "pid": action.target.pid.0,
            "status": status,
        });
        if let Err(e) = writeln!(file, "{}", entry) {
            return Err(format!("write outcomes: {}", e));
        }
    }
    Ok(())
}

#[cfg(feature = "ui")]
fn write_outcomes_from_execution(
    handle: &SessionHandle,
    plan: &Plan,
    result: &pt_core::action::ExecutionResult,
) -> Result<(), String> {
    use pt_core::action::ActionStatus;
    use std::io::Write;

    let mut by_id: HashMap<String, u32> = HashMap::new();
    for action in &plan.actions {
        by_id.insert(action.action_id.clone(), action.target.pid.0);
    }

    let outcomes_path = handle.dir.join("action").join("outcomes.jsonl");
    let _ = std::fs::create_dir_all(handle.dir.join("action"));
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&outcomes_path)
        .map_err(|e| format!("open outcomes: {}", e))?;

    for outcome in &result.outcomes {
        let pid = by_id.get(&outcome.action_id).copied().unwrap_or_default();
        let mut entry = serde_json::json!({
            "action_id": outcome.action_id,
            "pid": pid,
            "status": action_status_label(&outcome.status),
            "time_ms": outcome.time_ms,
        });
        if let ActionStatus::PreCheckBlocked { check, reason } = &outcome.status {
            if let Some(obj) = entry.as_object_mut() {
                obj.insert(
                    "precheck".to_string(),
                    serde_json::Value::String(precheck_label(check).to_string()),
                );
                obj.insert(
                    "reason".to_string(),
                    serde_json::Value::String(reason.clone()),
                );
            }
        }
        if let Err(e) = writeln!(file, "{}", entry) {
            return Err(format!("write outcomes: {}", e));
        }
    }
    Ok(())
}

#[cfg(feature = "ui")]
fn action_status_label(status: &pt_core::action::ActionStatus) -> &'static str {
    use pt_core::action::ActionStatus;
    match status {
        ActionStatus::Success => "success",
        ActionStatus::IdentityMismatch => "identity_mismatch",
        ActionStatus::PermissionDenied => "permission_denied",
        ActionStatus::Timeout => "timeout",
        ActionStatus::Failed => "failed",
        ActionStatus::Skipped => "skipped",
        ActionStatus::PreCheckBlocked { .. } => "precheck_blocked",
    }
}

#[cfg(feature = "ui")]
fn precheck_label(check: &pt_core::plan::PreCheck) -> &'static str {
    use pt_core::plan::PreCheck;
    match check {
        PreCheck::VerifyIdentity => "verify_identity",
        PreCheck::CheckNotProtected => "check_not_protected",
        PreCheck::CheckSessionSafety => "check_session_safety",
        PreCheck::CheckDataLossGate => "check_data_loss_gate",
        PreCheck::CheckSupervisor => "check_supervisor",
        PreCheck::CheckAgentSupervision => "check_agent_supervision",
        PreCheck::VerifyProcessState => "verify_process_state",
    }
}

#[cfg(feature = "ui")]
#[derive(Debug, Clone, Copy)]
struct DeepSignals {
    net_active: Option<bool>,
    io_active: Option<bool>,
}

#[cfg(feature = "ui")]
fn collect_deep_signals(processes: &[ProcessRecord]) -> Option<HashMap<u32, DeepSignals>> {
    #[cfg(target_os = "linux")]
    {
        use pt_core::collect::{deep_scan, DeepScanOptions};

        let pids = processes.iter().map(|p| p.pid.0).collect::<Vec<_>>();
        let options = DeepScanOptions {
            pids,
            skip_inaccessible: true,
            include_environ: false,
            progress: None,
        };
        let result = match deep_scan(&options) {
            Ok(r) => r,
            Err(err) => {
                eprintln!("run: deep scan failed: {}", err);
                return None;
            }
        };

        let mut map = HashMap::new();
        for record in result.processes {
            let net_active = record.network.as_ref().map(|info| {
                let counts = &info.socket_counts;
                let total =
                    counts.tcp + counts.tcp6 + counts.udp + counts.udp6 + counts.unix + counts.raw;
                total > 0
                    || !info.listen_ports.is_empty()
                    || !info.tcp_connections.is_empty()
                    || !info.udp_sockets.is_empty()
                    || !info.unix_sockets.is_empty()
            });
            let io_active = record
                .io
                .as_ref()
                .map(|io| io.read_bytes > 0 || io.write_bytes > 0);

            map.insert(
                record.pid.0,
                DeepSignals {
                    net_active,
                    io_active,
                },
            );
        }
        Some(map)
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("run: deep scan not supported on this platform; using quick scan");
        None
    }
}

#[cfg(feature = "ui")]
fn build_tui_rows(
    processes: &[ProcessRecord],
    min_age: Option<u64>,
    deep_signals: Option<&HashMap<u32, DeepSignals>>,
    priors: &Priors,
    policy: &pt_core::config::Policy,
    goal_str: Option<&str>,
) -> TuiBuildOutput {
    const MIN_POSTERIOR: f64 = 0.7;
    const MAX_CANDIDATES: usize = 50;

    let system_state = collect_system_state();
    let load_adjustment = if policy.load_aware.enabled {
        let signals = LoadSignals::from_system_state(&system_state, processes.len());
        compute_load_adjustment(&policy.load_aware, &signals)
    } else {
        None
    };

    let decision_policy = if let Some(adjustment) = &load_adjustment {
        let mut adjusted = policy.clone();
        adjusted.loss_matrix = apply_load_to_loss_matrix(&policy.loss_matrix, adjustment);
        adjusted
    } else {
        policy.clone()
    };

    let feasibility = ActionFeasibility::allow_all();
    let mut rows = Vec::new();
    let mut plan_candidates = HashMap::new();
    let mut goal_candidates: HashMap<u32, serde_json::Value> = HashMap::new();
    let mut cpu_total = 0.0;

    for proc in processes {
        if proc.pid.0 == 0 || proc.pid.0 == 1 {
            continue;
        }
        if let Some(threshold) = min_age {
            if proc.elapsed.as_secs() < threshold {
                continue;
            }
        }

        let deep = deep_signals.and_then(|m| m.get(&proc.pid.0).copied());
        let evidence = Evidence {
            cpu: Some(CpuEvidence::Fraction {
                occupancy: (proc.cpu_percent / 100.0).clamp(0.0, 1.0),
            }),
            runtime_seconds: Some(proc.elapsed.as_secs_f64()),
            orphan: Some(proc.is_orphan()),
            tty: Some(proc.has_tty()),
            net: deep.and_then(|d| d.net_active),
            io_active: deep.and_then(|d| d.io_active),
            state_flag: state_to_flag(proc.state),
            command_category: None,
        };

        let posterior_result = match compute_posterior(priors, &evidence) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let decision_outcome =
            match decide_action(&posterior_result.posterior, &decision_policy, &feasibility) {
                Ok(d) => d,
                Err(_) => continue,
            };

        let ledger =
            EvidenceLedger::from_posterior_result(&posterior_result, Some(proc.pid.0), None);
        let max_posterior = posterior_result
            .posterior
            .useful
            .max(posterior_result.posterior.useful_bad)
            .max(posterior_result.posterior.abandoned)
            .max(posterior_result.posterior.zombie);
        if max_posterior < MIN_POSTERIOR {
            continue;
        }

        let classification = match decision_outcome.optimal_action {
            Action::Kill => "KILL",
            Action::Keep => "SPARE",
            _ => "REVIEW",
        };

        let score = (max_posterior * 100.0).round() as u32;
        let runtime = format_duration_human(proc.elapsed.as_secs());
        let memory = format_memory_human(proc.rss_bytes);
        let galaxy_brain = render_galaxy_brain(
            &posterior_result,
            &ledger,
            &GalaxyBrainConfig {
                verbosity: Verbosity::Detail,
                math_mode: MathMode::Ascii,
                max_evidence_terms: 8,
            },
        );

        let identity = ProcessIdentity::full(
            proc.pid.0,
            proc.start_id.clone(),
            proc.uid,
            proc.pgid,
            proc.sid,
            IdentityQuality::Full,
        );
        plan_candidates.insert(
            proc.pid.0,
            PlanCandidateInput {
                identity,
                ppid: Some(proc.ppid.0),
                decision: decision_outcome.clone(),
                process_state: proc.state,
            },
        );

        rows.push(ProcessRow {
            pid: proc.pid.0,
            score,
            classification: classification.to_string(),
            runtime,
            memory,
            command: proc.cmd.clone(),
            selected: classification == "KILL",
            galaxy_brain: Some(galaxy_brain),
            why_summary: Some(ledger.why_summary.clone()),
            top_evidence: ledger.top_evidence.clone(),
            confidence: Some(ledger.confidence.label().to_string()),
            plan_preview: Vec::new(),
        });

        cpu_total += proc.cpu_percent;

        let expected_loss_entries: Vec<serde_json::Value> = decision_outcome
            .expected_loss
            .iter()
            .map(|entry| {
                serde_json::json!({
                    "action": format!("{:?}", entry.action).to_lowercase(),
                    "loss": entry.loss,
                })
            })
            .collect();

        let recommended_action = match decision_outcome.optimal_action {
            Action::Kill => "kill",
            Action::Keep => "keep",
            _ => "review",
        };

        let memory_mb = proc.rss_bytes / (1024 * 1024);
        goal_candidates.insert(
            proc.pid.0,
            serde_json::json!({
                "pid": proc.pid.0,
                "recommended_action": recommended_action,
                "memory_mb": memory_mb,
                "cpu_percent": proc.cpu_percent,
                "expected_loss": expected_loss_entries,
            }),
        );
    }

    rows.sort_by_key(|r| std::cmp::Reverse(r.score));
    rows.truncate(MAX_CANDIDATES);

    let mut goal_summary: Option<Vec<String>> = None;
    let mut goal_order: Option<HashMap<u32, usize>> = None;

    if let Some(goal_str) = goal_str {
        match parse_goal(goal_str) {
            Ok(parsed) => {
                let mut candidates_for_goal = Vec::new();
                for row in &rows {
                    if let Some(candidate) = goal_candidates.get(&row.pid) {
                        candidates_for_goal.push(candidate.clone());
                    }
                }

                if !candidates_for_goal.is_empty() {
                    match build_goal_plan_from_candidates(
                        goal_str,
                        &parsed,
                        cpu_total,
                        &candidates_for_goal,
                    ) {
                        Ok(output) => {
                            let mut lines = Vec::new();
                            lines.push(format!("Goal: {}", goal_str));
                            lines.push(format!(
                                "Status: {}",
                                if output.result.feasible {
                                    "achievable"
                                } else {
                                    "partial"
                                }
                            ));
                            for entry in &output.result.goal_achievement {
                                let fraction = if entry.target > 0.0 {
                                    (entry.achieved / entry.target).min(1.0)
                                } else {
                                    1.0
                                };
                                lines.push(format!(
                                    "{}: {:.1}/{:.1} ({:.0}%)",
                                    entry.resource,
                                    entry.achieved,
                                    entry.target,
                                    fraction * 100.0
                                ));
                            }
                            lines.push(format!(
                                "Expected loss: {:.2} • Selected: {}",
                                output.result.total_loss,
                                output.selected_pids.len()
                            ));
                            if !output.warnings.is_empty() {
                                lines.push(format!("Warnings: {}", output.warnings.join(", ")));
                            }
                            goal_summary = Some(lines);

                            let mut rank_map = HashMap::new();
                            let mut rank = 0usize;
                            for pid in &output.selected_pids {
                                if rows.iter().any(|row| row.pid == *pid) {
                                    rank_map.insert(*pid, rank);
                                    rank = rank.saturating_add(1);
                                }
                            }
                            for row in &rows {
                                if let std::collections::hash_map::Entry::Vacant(e) =
                                    rank_map.entry(row.pid)
                                {
                                    e.insert(rank);
                                    rank = rank.saturating_add(1);
                                }
                            }
                            goal_order = Some(rank_map);
                        }
                        Err(err) => {
                            goal_summary = Some(vec![
                                format!("Goal: {}", goal_str),
                                format!("Error: {}", err),
                            ]);
                        }
                    }
                } else {
                    goal_summary = Some(vec![
                        format!("Goal: {}", goal_str),
                        "No candidates available for goal optimization".to_string(),
                    ]);
                }
            }
            Err(err) => {
                goal_summary = Some(vec![
                    format!("Goal: {}", goal_str),
                    format!("Error: {}", err),
                ]);
            }
        }
    }

    TuiBuildOutput {
        rows,
        plan_candidates,
        goal_summary,
        goal_order,
    }
}

#[cfg(target_os = "linux")]
use pt_core::collect::{parse_fd, parse_proc_net_tcp, parse_proc_net_udp, NetworkSnapshot};
use pt_core::collect::{quick_scan, ProcessRecord, QuickScanOptions, ScanResult};
use pt_core::decision::goal_progress::{
    self, ActionOutcome as GoalActionOutcome, GoalMetric, GoalProgressReport, MetricSnapshot,
    ProgressConfig,
};
use pt_core::decision::{
    apply_load_to_loss_matrix, compute_load_adjustment, decide_action, Action, ActionFeasibility,
    LoadSignals,
};
use pt_core::inference::{
    compute_posterior, compute_posterior_with_overrides, try_signature_fast_path, CpuEvidence,
    Evidence, EvidenceLedger, FastPathConfig, FastPathSkipReason, PriorContext,
};
use pt_core::supervision::signature::{MatchLevel, ProcessMatchContext, SignatureDatabase};

fn progress_emitter(global: &GlobalOpts) -> Option<Arc<dyn ProgressEmitter>> {
    match global.format {
        OutputFormat::Json | OutputFormat::Jsonl | OutputFormat::Toon => {
            Some(Arc::new(JsonlWriter::new(std::io::stderr())))
        }
        _ => None,
    }
}

fn session_progress_emitter(
    global: &GlobalOpts,
    handle: &pt_core::session::SessionHandle,
    session_id: &SessionId,
) -> Option<Arc<dyn ProgressEmitter>> {
    let mut emitters: Vec<Arc<dyn ProgressEmitter>> = Vec::new();

    if let Some(stderr_emitter) = progress_emitter(global) {
        emitters.push(stderr_emitter);
    }

    let log_path = handle.dir.join("logs").join("session.jsonl");
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
    {
        Ok(file) => {
            emitters.push(Arc::new(JsonlWriter::new(file)));
        }
        Err(e) => {
            eprintln!(
                "agent plan: warning: failed to open session log {}: {}",
                log_path.display(),
                e
            );
        }
    }

    if emitters.is_empty() {
        return None;
    }

    let fanout: Arc<dyn ProgressEmitter> = if emitters.len() == 1 {
        emitters[0].clone()
    } else {
        Arc::new(FanoutEmitter::new(emitters))
    };

    Some(Arc::new(SessionEmitter::new(
        session_id.to_string(),
        fanout,
    )))
}

fn run_scan(global: &GlobalOpts, args: &ScanArgs) -> ExitCode {
    let ctx = LogContext::new(
        pt_core::logging::generate_run_id(),
        pt_core::logging::get_host_id(),
    );

    log_event!(
        ctx,
        INFO,
        event_names::RUN_STARTED,
        Stage::Init,
        "Starting scan command"
    );

    if args.deep {
        return run_deep_scan(
            global,
            &DeepScanArgs {
                pids: vec![],
                budget: None,
            },
        );
    }

    let progress = progress_emitter(global);

    // Configure scan options
    let options = QuickScanOptions {
        pids: vec![], // Empty = all processes
        include_kernel_threads: args.include_kernel_threads,
        timeout: global.timeout.map(std::time::Duration::from_secs),
        progress,
    };

    // Perform scan
    match quick_scan(&options) {
        Ok(result) => {
            log_event!(
                ctx,
                INFO,
                event_names::SCAN_FINISHED,
                Stage::Scan,
                "Scan finished successfully",
                count = result.metadata.process_count,
                duration_ms = result.metadata.duration_ms
            );

            let goal_advisory = if let Some(goal_str) = &args.goal {
                match parse_goal(goal_str) {
                    Ok(parsed) => Some(build_goal_advisory_from_scan(goal_str, &parsed, &result)),
                    Err(err) => {
                        eprintln!("scan: invalid --goal {}: {}", goal_str, err);
                        return ExitCode::ArgsError;
                    }
                }
            } else {
                None
            };

            match global.format {
                OutputFormat::Json | OutputFormat::Toon => {
                    // Enrich with schema version and session ID
                    let session_id = SessionId::new();
                    let mut output = serde_json::json!({
                        "schema_version": SCHEMA_VERSION,
                        "session_id": session_id.0,
                        "generated_at": chrono::Utc::now().to_rfc3339(),
                        "scan": result
                    });
                    if let Some(goal_advisory) = goal_advisory {
                        output["goal_advisory"] = goal_advisory;
                    }
                    // Apply token-efficient processing if options specified
                    println!("{}", format_structured_output(global, output));
                }
                OutputFormat::Summary => {
                    println!(
                        "Scanned {} processes in {}ms",
                        result.metadata.process_count, result.metadata.duration_ms
                    );
                    if let Some(goal_advisory) = goal_advisory {
                        println!("Goal advisory: {}", goal_advisory);
                    }
                }
                OutputFormat::Exitcode => {} // Silent
                _ => {
                    // Human readable output
                    println!("# Quick Scan Results");
                    println!(
                        "Scanned {} processes in {}ms",
                        result.metadata.process_count, result.metadata.duration_ms
                    );
                    println!("Platform: {}", result.metadata.platform);
                    println!();

                    println!(
                        "{:<8} {:<8} {:<10} {:<6} {:<6} {:<6} COMMAND",
                        "PID", "PPID", "USER", "STATE", "%CPU", "RSS"
                    );

                    for p in result.processes.iter().take(20) {
                        println!(
                            "{:<8} {:<8} {:<10} {:<6} {:<6.1} {:<6} {}",
                            p.pid.0,
                            p.ppid.0,
                            p.user.chars().take(10).collect::<String>(),
                            p.state,
                            p.cpu_percent,
                            bytes_to_human(p.rss_bytes),
                            p.comm
                        );
                    }
                    if result.processes.len() > 20 {
                        println!("... and {} more", result.processes.len() - 20);
                    }
                    if let Some(goal_advisory) = goal_advisory {
                        println!();
                        println!("## Goal Advisory");
                        println!("{}", goal_advisory);
                    }
                }
            }
            ExitCode::Clean
        }
        Err(e) => {
            log_event!(
                ctx,
                ERROR,
                event_names::INTERNAL_ERROR,
                Stage::Scan,
                "Scan failed",
                error = e.to_string()
            );
            eprintln!("Scan failed: {}", e);
            ExitCode::InternalError
        }
    }
}

fn bytes_to_human(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{}B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1}K", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1}M", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1}G", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

#[allow(dead_code)]
struct GoalPlanOutput {
    goals: Vec<ResourceGoal>,
    result: OptimizationResult,
    selected_pids: Vec<u32>,
    strategy: String,
    warnings: Vec<String>,
}

fn resource_goal_from_target(
    target: &ResourceTarget,
    current_cpu_pct: f64,
) -> Result<(ResourceGoal, Vec<String>), String> {
    let mut warnings = Vec::new();
    let goal = match target.metric {
        Metric::Memory => ResourceGoal {
            resource: "memory_mb".to_string(),
            target: target.value / (1024.0 * 1024.0),
            weight: 1.0,
        },
        Metric::Cpu => {
            let target_pct = target.value * 100.0;
            let desired = match target.comparator {
                Comparator::ReduceBelow => {
                    let required = (current_cpu_pct - target_pct).max(0.0);
                    if required <= 0.0 {
                        warnings.push("cpu_target_already_met".to_string());
                    }
                    required
                }
                Comparator::FreeAtLeast => target_pct,
                Comparator::Release => target_pct,
            };
            ResourceGoal {
                resource: "cpu_pct".to_string(),
                target: desired,
                weight: 1.0,
            }
        }
        Metric::Port => {
            warnings.push("port_goal_requires_socket_inspection".to_string());
            ResourceGoal {
                resource: format!("port_{}", target.port.unwrap_or(0)),
                target: 1.0,
                weight: 1.0,
            }
        }
        Metric::FileDescriptors => {
            warnings.push("fd_goal_requires_fd_counts".to_string());
            ResourceGoal {
                resource: "fd_count".to_string(),
                target: target.value,
                weight: 1.0,
            }
        }
    };
    Ok((goal, warnings))
}

fn build_resource_goals(
    goal: &Goal,
    current_cpu_pct: f64,
) -> Result<(Vec<ResourceGoal>, Vec<String>), String> {
    let mut warnings = Vec::new();
    let mut goals = Vec::new();
    match goal {
        Goal::Target(t) => {
            let (g, mut w) = resource_goal_from_target(t, current_cpu_pct)?;
            warnings.append(&mut w);
            goals.push(g);
        }
        Goal::And(parts) => {
            for sub in parts {
                let Goal::Target(t) = sub else {
                    return Err("nested composite goals not supported".to_string());
                };
                let (g, mut w) = resource_goal_from_target(t, current_cpu_pct)?;
                warnings.append(&mut w);
                goals.push(g);
            }
        }
        Goal::Or(_) => {
            return Err("OR goals require selection strategy".to_string());
        }
    }
    Ok((goals, warnings))
}

#[allow(dead_code)]
fn parse_kill_loss(candidate: &serde_json::Value) -> f64 {
    candidate
        .get("expected_loss")
        .and_then(|v| v.as_array())
        .and_then(|entries| {
            entries.iter().find_map(|entry| {
                let action = entry.get("action")?.as_str()?;
                if action.eq_ignore_ascii_case("kill") {
                    entry.get("loss").and_then(|v| v.as_f64())
                } else {
                    None
                }
            })
        })
        .unwrap_or(0.0)
}

#[allow(dead_code)]
fn build_opt_candidates_for_goals(
    candidates: &[serde_json::Value],
    goals: &[ResourceGoal],
) -> Vec<OptCandidate> {
    candidates
        .iter()
        .filter_map(|candidate| {
            let pid = candidate.get("pid")?.as_u64()? as u32;
            let action = candidate
                .get("recommended_action")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let blocked = action.eq_ignore_ascii_case("keep");
            let memory_mb = candidate
                .get("memory_mb")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as f64;
            let cpu_pct = candidate
                .get("cpu_percent")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);

            let contributions: Vec<f64> = goals
                .iter()
                .map(|goal| match goal.resource.as_str() {
                    "memory_mb" => memory_mb,
                    "cpu_pct" => cpu_pct,
                    "fd_count" => 0.0,
                    r if r.starts_with("port_") => 0.0,
                    _ => 0.0,
                })
                .collect();

            Some(OptCandidate {
                id: pid.to_string(),
                expected_loss: parse_kill_loss(candidate),
                contributions,
                blocked,
                block_reason: None,
            })
        })
        .collect()
}

#[allow(dead_code)]
fn goal_progress_json(result: &OptimizationResult) -> serde_json::Value {
    let entries: Vec<serde_json::Value> = result
        .goal_achievement
        .iter()
        .map(|g| {
            let fraction = if g.target > 0.0 {
                (g.achieved / g.target).min(1.0)
            } else {
                1.0
            };
            serde_json::json!({
                "resource": g.resource,
                "achieved": g.achieved,
                "target": g.target,
                "shortfall": g.shortfall,
                "met": g.met,
                "fraction": fraction,
            })
        })
        .collect();
    serde_json::json!({ "entries": entries })
}

#[allow(dead_code)]
fn build_goal_plan_from_candidates(
    _goal_str: &str,
    goal: &Goal,
    current_cpu_pct: f64,
    candidates: &[serde_json::Value],
) -> Result<GoalPlanOutput, String> {
    let mut warnings = Vec::new();
    let (goals, mut w) = match goal {
        Goal::Or(parts) => {
            let mut best: Option<(OptimizationResult, Vec<ResourceGoal>)> = None;
            let mut best_score = -1.0;
            for sub in parts {
                let Goal::Target(t) = sub else {
                    continue;
                };
                let (g, mut w) = resource_goal_from_target(t, current_cpu_pct)?;
                warnings.append(&mut w);
                let goals = vec![g.clone()];
                let opt_candidates = build_opt_candidates_for_goals(candidates, &goals);
                let result = optimize_ilp(&opt_candidates, &goals);
                let achieved = result
                    .goal_achievement
                    .first()
                    .map(|g| {
                        if g.target > 0.0 {
                            g.achieved / g.target
                        } else {
                            1.0
                        }
                    })
                    .unwrap_or(0.0);
                let score = if result.feasible {
                    1.0 + achieved
                } else {
                    achieved
                };
                if score > best_score
                    || (score - best_score).abs() < 1e-9
                        && best
                            .as_ref()
                            .is_none_or(|b| result.total_loss < b.0.total_loss)
                {
                    best_score = score;
                    best = Some((result, goals));
                }
            }
            let Some((result, goals)) = best else {
                return Err("no valid OR goal candidates".to_string());
            };
            return Ok(GoalPlanOutput {
                goals,
                selected_pids: result
                    .selected
                    .iter()
                    .filter_map(|s| s.id.parse::<u32>().ok())
                    .collect(),
                result,
                strategy: "or_best".to_string(),
                warnings,
            });
        }
        _ => build_resource_goals(goal, current_cpu_pct)?,
    };
    warnings.append(&mut w);

    let opt_candidates = build_opt_candidates_for_goals(candidates, &goals);
    let result = if goals.len() == 1 {
        optimize_ilp(&opt_candidates, &goals)
    } else {
        optimize_greedy(&opt_candidates, &goals)
    };

    let selected_pids = result
        .selected
        .iter()
        .filter_map(|s| s.id.parse::<u32>().ok())
        .collect();

    Ok(GoalPlanOutput {
        goals,
        result,
        selected_pids,
        strategy: "and".to_string(),
        warnings,
    })
}

#[allow(dead_code)]
fn goal_summary_json(goal_str: &str, goal: &Goal, output: &GoalPlanOutput) -> serde_json::Value {
    let targets: Vec<serde_json::Value> = output
        .goals
        .iter()
        .map(|g| serde_json::json!({"resource": g.resource, "target": g.target}))
        .collect();
    let goal_achievement = serde_json::to_value(&output.result.goal_achievement)
        .unwrap_or_else(|_| serde_json::json!([]));
    let alternatives =
        serde_json::to_value(&output.result.alternatives).unwrap_or_else(|_| serde_json::json!([]));
    let log_events =
        serde_json::to_value(&output.result.log_events).unwrap_or_else(|_| serde_json::json!([]));
    serde_json::json!({
        "goal": goal_str,
        "parsed": goal.canonical(),
        "strategy": output.strategy,
        "achievable": output.result.feasible,
        "targets": targets,
        "projected_recovery": output.result.total_contributions,
        "total_expected_loss": output.result.total_loss,
        "selected_pids": output.selected_pids,
        "goal_achievement": goal_achievement,
        "alternatives": alternatives,
        "log_events": log_events,
        "warnings": output.warnings,
    })
}

fn build_goal_advisory_from_scan(
    goal_str: &str,
    goal: &Goal,
    result: &ScanResult,
) -> serde_json::Value {
    let total_mem_mb: f64 = result
        .processes
        .iter()
        .map(|p| p.rss_bytes as f64 / (1024.0 * 1024.0))
        .sum();
    let total_cpu_pct: f64 = result.processes.iter().map(|p| p.cpu_percent).sum();

    let (goals, warnings) = match build_resource_goals(goal, total_cpu_pct) {
        Ok(v) => v,
        Err(err) => {
            return serde_json::json!({
                "goal": goal_str,
                "parsed": goal.canonical(),
                "error": err,
            });
        }
    };

    let achievements: Vec<serde_json::Value> = goals
        .iter()
        .map(|g| {
            let achieved = match g.resource.as_str() {
                "memory_mb" => total_mem_mb,
                "cpu_pct" => total_cpu_pct,
                _ => 0.0,
            };
            serde_json::json!({
                "resource": g.resource,
                "target": g.target,
                "achieved": achieved,
                "shortfall": (g.target - achieved).max(0.0),
                "met": achieved >= g.target,
            })
        })
        .collect();

    serde_json::json!({
        "goal": goal_str,
        "parsed": goal.canonical(),
        "achievements": achievements,
        "warnings": warnings,
    })
}

fn resolve_bundle_passphrase(passphrase_arg: &Option<String>) -> Option<String> {
    passphrase_arg
        .clone()
        .or_else(|| std::env::var("PT_BUNDLE_PASSPHRASE").ok())
}

fn run_deep_scan(global: &GlobalOpts, _args: &DeepScanArgs) -> ExitCode {
    output_stub(global, "deep-scan", "Deep scan mode not yet implemented");
    ExitCode::Clean
}

fn run_query(global: &GlobalOpts, _args: &QueryArgs) -> ExitCode {
    output_stub(global, "query", "Query mode not yet implemented");
    ExitCode::Clean
}

fn run_bundle(global: &GlobalOpts, args: &BundleArgs) -> ExitCode {
    match &args.command {
        BundleCommands::Create {
            session,
            output,
            profile,
            include_telemetry,
            include_dumps,
            encrypt,
            passphrase,
        } => run_bundle_create(
            global,
            session,
            output,
            profile,
            *include_telemetry,
            *include_dumps,
            *encrypt,
            passphrase,
        ),
        BundleCommands::Inspect {
            path,
            verify,
            passphrase,
        } => run_bundle_inspect(global, path, *verify, passphrase),
        BundleCommands::Extract {
            path,
            output,
            verify,
            passphrase,
        } => run_bundle_extract(global, path, output, *verify, passphrase),
    }
}

#[allow(clippy::too_many_arguments)]
fn run_bundle_create(
    global: &GlobalOpts,
    session_arg: &Option<String>,
    output_arg: &Option<String>,
    profile_str: &str,
    include_telemetry: bool,
    _include_dumps: bool,
    encrypt: bool,
    passphrase_arg: &Option<String>,
) -> ExitCode {
    use pt_bundle::{BundleWriter, FileType};
    use pt_redact::ExportProfile;

    let session_id = SessionId::new();
    let host_id = pt_core::logging::get_host_id();
    let passphrase = resolve_bundle_passphrase(passphrase_arg);

    if encrypt && passphrase.as_deref().map(|p| p.is_empty()).unwrap_or(true) {
        let error_output = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "session_id": session_id.0,
            "generated_at": chrono::Utc::now().to_rfc3339(),
            "command": "bundle create",
            "status": "error",
            "error": "Encryption requested but no passphrase provided (use --passphrase or PT_BUNDLE_PASSPHRASE)",
        });
        match global.format {
            OutputFormat::Md => eprintln!(
                "Error: Encryption requested but no passphrase provided (use --passphrase or PT_BUNDLE_PASSPHRASE)"
            ),
            OutputFormat::Jsonl => println!("{}", serde_json::to_string(&error_output).unwrap()),
            _ => println!("{}", serde_json::to_string_pretty(&error_output).unwrap()),
        }
        return ExitCode::ArgsError;
    }

    // Parse export profile
    let export_profile = match ExportProfile::parse_str(profile_str) {
        Some(p) => p,
        None => {
            let error_output = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "session_id": session_id.0,
                "generated_at": chrono::Utc::now().to_rfc3339(),
                "command": "bundle create",
                "status": "error",
                "error": format!("Invalid profile '{}'. Valid options: minimal, safe, forensic", profile_str),
            });
            match global.format {
                OutputFormat::Md => eprintln!(
                    "Error: Invalid profile '{}'. Valid options: minimal, safe, forensic",
                    profile_str
                ),
                OutputFormat::Jsonl => {
                    println!("{}", serde_json::to_string(&error_output).unwrap())
                }
                _ => println!("{}", serde_json::to_string_pretty(&error_output).unwrap()),
            }
            return ExitCode::ArgsError;
        }
    };

    // Open session store
    let store = match SessionStore::from_env() {
        Ok(store) => store,
        Err(e) => {
            eprintln!("bundle create: session store error: {}", e);
            return ExitCode::InternalError;
        }
    };

    // Find session to export
    let target_session = if let Some(raw) = session_arg {
        match SessionId::parse(raw) {
            Some(sid) => sid,
            None => {
                eprintln!("bundle create: invalid session ID '{}'", raw);
                return ExitCode::ArgsError;
            }
        }
    } else {
        // Find latest session
        let options = ListSessionsOptions {
            limit: Some(1),
            ..Default::default()
        };
        match store.list_sessions(&options) {
            Ok(sessions) if !sessions.is_empty() => SessionId(sessions[0].session_id.clone()),
            Ok(_) => {
                eprintln!("bundle create: no sessions found");
                return ExitCode::ArgsError;
            }
            Err(e) => {
                eprintln!("bundle create: failed to list sessions: {}", e);
                return ExitCode::InternalError;
            }
        }
    };

    // Open the session
    let handle = match store.open(&target_session) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("bundle create: {}", e);
            return ExitCode::ArgsError;
        }
    };

    // Create bundle writer
    let mut writer = BundleWriter::new(&target_session.0, &host_id, export_profile)
        .with_pt_version(env!("CARGO_PKG_VERSION"))
        .with_description(format!("Export of session {}", target_session.0));

    // Add manifest.json from session
    let manifest_path = handle.manifest_path();
    if let Ok(content) = std::fs::read(&manifest_path) {
        writer.add_file("session/manifest.json", content, Some(FileType::Json));
    }

    // Add context.json from session
    let context_path = handle.context_path();
    if let Ok(content) = std::fs::read(&context_path) {
        writer.add_file("session/context.json", content, Some(FileType::Json));
    }

    // Add plan.json if present
    let plan_path = handle.dir.join("decision/plan.json");
    if plan_path.exists() {
        if let Ok(content) = std::fs::read(&plan_path) {
            writer.add_file("plan.json", content, Some(FileType::Json));
        }
    }

    // Add snapshot.json if present
    let snapshot_path = handle.dir.join("scan/snapshot.json");
    if snapshot_path.exists() {
        if let Ok(content) = std::fs::read(&snapshot_path) {
            writer.add_file("snapshot.json", content, Some(FileType::Json));
        }
    }

    // Add inference results if present
    let posteriors_path = handle.dir.join("inference/posteriors.json");
    if posteriors_path.exists() {
        if let Ok(content) = std::fs::read(&posteriors_path) {
            writer.add_file("inference/posteriors.json", content, Some(FileType::Json));
        }
    }

    // Add audit trail if present
    let audit_path = handle.dir.join("action/outcomes.jsonl");
    if audit_path.exists() {
        if let Ok(content) = std::fs::read(&audit_path) {
            writer.add_file("logs/outcomes.jsonl", content, Some(FileType::Log));
        }
    }

    // Optionally include telemetry data
    if include_telemetry {
        let telemetry_dir = handle.dir.join("telemetry");
        if telemetry_dir.exists() {
            if let Ok(entries) = std::fs::read_dir(&telemetry_dir) {
                for entry in entries.flatten() {
                    let entry_path = entry.path();
                    if entry_path.is_file() {
                        if let Some(name) = entry_path.file_name().and_then(|n| n.to_str()) {
                            if let Ok(content) = std::fs::read(&entry_path) {
                                let file_type = if name.ends_with(".parquet") {
                                    FileType::Parquet
                                } else if name.ends_with(".jsonl") {
                                    FileType::Log
                                } else if name.ends_with(".json") {
                                    FileType::Json
                                } else {
                                    FileType::Binary
                                };
                                writer.add_file(
                                    format!("telemetry/{}", name),
                                    content,
                                    Some(file_type),
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    // Include user signatures if available
    if let Some(user_schema) = pt_core::signature_cli::load_user_signatures() {
        if !user_schema.signatures.is_empty() {
            if let Ok(json) = serde_json::to_string_pretty(&user_schema) {
                writer.add_file(
                    pt_core::signature_cli::BUNDLE_SIGNATURES_PATH,
                    json.into_bytes(),
                    Some(FileType::Json),
                );
            }
        }
    }

    // Determine output path
    let output_path = match output_arg {
        Some(p) => PathBuf::from(p),
        None => {
            // Default: <session_id>.ptb in current directory
            PathBuf::from(format!("{}.ptb", target_session.0))
        }
    };

    let result = if encrypt {
        let passphrase = match passphrase.as_deref() {
            Some(p) if !p.is_empty() => p,
            _ => {
                let error_output = serde_json::json!({
                    "schema_version": SCHEMA_VERSION,
                    "session_id": session_id.0,
                    "generated_at": chrono::Utc::now().to_rfc3339(),
                    "command": "bundle create",
                    "status": "error",
                    "error": "Encryption requested but no passphrase provided (use --passphrase or PT_BUNDLE_PASSPHRASE)",
                });
                match global.format {
                    OutputFormat::Md => eprintln!(
                        "Error: Encryption requested but no passphrase provided (use --passphrase or PT_BUNDLE_PASSPHRASE)"
                    ),
                    OutputFormat::Jsonl => {
                        println!("{}", serde_json::to_string(&error_output).unwrap())
                    }
                    _ => println!("{}", serde_json::to_string_pretty(&error_output).unwrap()),
                }
                return ExitCode::ArgsError;
            }
        };
        writer.write_encrypted(&output_path, passphrase)
    } else {
        writer.write(&output_path)
    };

    match result {
        Ok(manifest) => {
            let output = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "session_id": session_id.0,
                "generated_at": chrono::Utc::now().to_rfc3339(),
                "command": "bundle create",
                "status": "ok",
                "bundle": {
                    "path": output_path.display().to_string(),
                    "source_session": target_session.0,
                    "profile": format!("{}", export_profile),
                    "files": manifest.file_count(),
                    "total_bytes": manifest.total_bytes(),
                    "encrypted": encrypt,
                },
            });
            match global.format {
                OutputFormat::Md => println!(
                    "Bundle created: {} ({} files, {} bytes{})",
                    output_path.display(),
                    manifest.file_count(),
                    manifest.total_bytes(),
                    if encrypt { ", encrypted" } else { "" }
                ),
                OutputFormat::Jsonl => println!("{}", serde_json::to_string(&output).unwrap()),
                _ => println!("{}", serde_json::to_string_pretty(&output).unwrap()),
            }
            ExitCode::Clean
        }
        Err(e) => {
            let error_output = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "session_id": session_id.0,
                "generated_at": chrono::Utc::now().to_rfc3339(),
                "command": "bundle create",
                "status": "error",
                "error": e.to_string(),
            });
            match global.format {
                OutputFormat::Md => eprintln!("Error creating bundle: {}", e),
                OutputFormat::Jsonl => {
                    println!("{}", serde_json::to_string(&error_output).unwrap())
                }
                _ => println!("{}", serde_json::to_string_pretty(&error_output).unwrap()),
            }
            ExitCode::InternalError
        }
    }
}

fn run_bundle_inspect(
    global: &GlobalOpts,
    path: &str,
    verify: bool,
    passphrase_arg: &Option<String>,
) -> ExitCode {
    use pt_bundle::BundleReader;

    let session_id = SessionId::new();
    let bundle_path = std::path::Path::new(path);

    if !bundle_path.exists() {
        let error_output = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "session_id": session_id.0,
            "generated_at": chrono::Utc::now().to_rfc3339(),
            "command": "bundle inspect",
            "status": "error",
            "error": format!("Bundle not found: {}", path),
        });
        match global.format {
            OutputFormat::Md => eprintln!("Error: Bundle not found: {}", path),
            OutputFormat::Jsonl => println!("{}", serde_json::to_string(&error_output).unwrap()),
            _ => println!("{}", serde_json::to_string_pretty(&error_output).unwrap()),
        }
        return ExitCode::ArgsError;
    }

    let passphrase = resolve_bundle_passphrase(passphrase_arg);
    let mut reader = match BundleReader::open_with_passphrase(bundle_path, passphrase.as_deref()) {
        Ok(r) => r,
        Err(e) => {
            let error_output = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "session_id": session_id.0,
                "generated_at": chrono::Utc::now().to_rfc3339(),
                "command": "bundle inspect",
                "status": "error",
                "error": format!("Failed to open bundle: {}", e),
            });
            match global.format {
                OutputFormat::Md => eprintln!("Error: Failed to open bundle: {}", e),
                OutputFormat::Jsonl => {
                    println!("{}", serde_json::to_string(&error_output).unwrap())
                }
                _ => println!("{}", serde_json::to_string_pretty(&error_output).unwrap()),
            }
            return if matches!(
                e,
                pt_bundle::BundleError::EncryptedBundleRequiresPassphrase
                    | pt_bundle::BundleError::MissingPassphrase
                    | pt_bundle::BundleError::DecryptionFailed
            ) {
                ExitCode::ArgsError
            } else {
                ExitCode::InternalError
            };
        }
    };

    // Clone manifest data we need to avoid borrow issues with verify_all
    let bundle_version = reader.manifest().bundle_version.clone();
    let source_session = reader.manifest().session_id.clone();
    let host_id = reader.manifest().host_id.clone();
    let created_at = reader.manifest().created_at;
    let export_profile = reader.manifest().export_profile;
    let pt_version = reader.manifest().pt_version.clone();
    let description = reader.manifest().description.clone();
    let file_count = reader.manifest().file_count();
    let total_bytes = reader.manifest().total_bytes();
    let files: Vec<_> = reader
        .manifest()
        .files
        .iter()
        .map(|f| {
            serde_json::json!({
                "path": f.path,
                "bytes": f.bytes,
                "sha256": f.sha256,
                "mime_type": f.mime_type,
            })
        })
        .collect();

    // Optionally verify all files
    let verification = if verify {
        let failures = reader.verify_all();
        Some(serde_json::json!({
            "verified": failures.is_empty(),
            "failures": failures,
        }))
    } else {
        None
    };

    let output = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "session_id": session_id.0,
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "command": "bundle inspect",
        "status": "ok",
        "bundle": {
            "path": path,
            "bundle_version": bundle_version,
            "source_session": source_session,
            "host_id": host_id,
            "created_at": created_at,
            "export_profile": format!("{}", export_profile),
            "pt_version": pt_version,
            "description": description,
            "file_count": file_count,
            "total_bytes": total_bytes,
        },
        "files": files,
        "verification": verification,
    });

    match global.format {
        OutputFormat::Md => {
            println!("Bundle: {}", path);
            println!("  Session: {}", source_session);
            println!("  Created: {}", created_at);
            println!("  Profile: {}", export_profile);
            println!("  Files: {} ({} bytes)", file_count, total_bytes);
            if let Some(ref v) = verification {
                if v["verified"].as_bool() == Some(true) {
                    println!("  Verification: PASSED");
                } else {
                    let fail_count = v["failures"].as_array().map(|a| a.len()).unwrap_or(0);
                    println!("  Verification: FAILED ({} files)", fail_count);
                }
            }
        }
        OutputFormat::Jsonl => println!("{}", serde_json::to_string(&output).unwrap()),
        _ => println!("{}", serde_json::to_string_pretty(&output).unwrap()),
    }

    ExitCode::Clean
}

fn run_bundle_extract(
    global: &GlobalOpts,
    path: &str,
    output_arg: &Option<String>,
    verify: bool,
    passphrase_arg: &Option<String>,
) -> ExitCode {
    use pt_bundle::BundleReader;

    let session_id = SessionId::new();
    let bundle_path = std::path::Path::new(path);

    if !bundle_path.exists() {
        let error_output = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "session_id": session_id.0,
            "generated_at": chrono::Utc::now().to_rfc3339(),
            "command": "bundle extract",
            "status": "error",
            "error": format!("Bundle not found: {}", path),
        });
        match global.format {
            OutputFormat::Md => eprintln!("Error: Bundle not found: {}", path),
            OutputFormat::Jsonl => println!("{}", serde_json::to_string(&error_output).unwrap()),
            _ => println!("{}", serde_json::to_string_pretty(&error_output).unwrap()),
        }
        return ExitCode::ArgsError;
    }

    let passphrase = resolve_bundle_passphrase(passphrase_arg);
    let mut reader = match BundleReader::open_with_passphrase(bundle_path, passphrase.as_deref()) {
        Ok(r) => r,
        Err(e) => {
            let error_output = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "session_id": session_id.0,
                "generated_at": chrono::Utc::now().to_rfc3339(),
                "command": "bundle extract",
                "status": "error",
                "error": format!("Failed to open bundle: {}", e),
            });
            match global.format {
                OutputFormat::Md => eprintln!("Error: Failed to open bundle: {}", e),
                OutputFormat::Jsonl => {
                    println!("{}", serde_json::to_string(&error_output).unwrap())
                }
                _ => println!("{}", serde_json::to_string_pretty(&error_output).unwrap()),
            }
            return if matches!(
                e,
                pt_bundle::BundleError::EncryptedBundleRequiresPassphrase
                    | pt_bundle::BundleError::MissingPassphrase
                    | pt_bundle::BundleError::DecryptionFailed
            ) {
                ExitCode::ArgsError
            } else {
                ExitCode::InternalError
            };
        }
    };

    // Determine output directory
    let output_dir = match output_arg {
        Some(p) => PathBuf::from(p),
        None => {
            // Default: use session ID from manifest
            PathBuf::from(reader.session_id())
        }
    };

    // Create output directory
    if let Err(e) = std::fs::create_dir_all(&output_dir) {
        let error_output = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "session_id": session_id.0,
            "generated_at": chrono::Utc::now().to_rfc3339(),
            "command": "bundle extract",
            "status": "error",
            "error": format!("Failed to create output directory: {}", e),
        });
        match global.format {
            OutputFormat::Md => eprintln!("Error: Failed to create output directory: {}", e),
            OutputFormat::Jsonl => {
                println!("{}", serde_json::to_string(&error_output).unwrap())
            }
            _ => println!("{}", serde_json::to_string_pretty(&error_output).unwrap()),
        }
        return ExitCode::InternalError;
    }

    // Get list of files to extract
    let file_paths: Vec<String> = reader.files().iter().map(|f| f.path.clone()).collect();
    let mut extracted = 0;
    let mut errors = Vec::new();

    for file_path in &file_paths {
        // Read file (with or without verification)
        let data = if verify {
            reader.read_verified(file_path)
        } else {
            reader.read_raw(file_path)
        };

        match data {
            Ok(content) => {
                let dest_path = output_dir.join(file_path);
                // Create parent directories
                if let Some(parent) = dest_path.parent() {
                    if let Err(e) = std::fs::create_dir_all(parent) {
                        errors.push(format!("{}: {}", file_path, e));
                        continue;
                    }
                }
                // Write file
                if let Err(e) = std::fs::write(&dest_path, content) {
                    errors.push(format!("{}: {}", file_path, e));
                } else {
                    extracted += 1;
                }
            }
            Err(e) => {
                errors.push(format!("{}: {}", file_path, e));
            }
        }
    }

    let status = if errors.is_empty() { "ok" } else { "partial" };
    let output = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "session_id": session_id.0,
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "command": "bundle extract",
        "status": status,
        "output_dir": output_dir.display().to_string(),
        "extracted": extracted,
        "total": file_paths.len(),
        "errors": errors,
    });

    match global.format {
        OutputFormat::Md => {
            println!(
                "Extracted {} of {} files to {}",
                extracted,
                file_paths.len(),
                output_dir.display()
            );
            if !errors.is_empty() {
                eprintln!("Errors:");
                for e in &errors {
                    eprintln!("  {}", e);
                }
            }
        }
        OutputFormat::Jsonl => println!("{}", serde_json::to_string(&output).unwrap()),
        _ => println!("{}", serde_json::to_string_pretty(&output).unwrap()),
    }

    if errors.is_empty() {
        ExitCode::Clean
    } else {
        ExitCode::InternalError
    }
}

fn run_report(global: &GlobalOpts, _args: &ReportArgs) -> ExitCode {
    output_stub(global, "report", "Report generation not yet implemented");
    ExitCode::Clean
}

fn run_check(global: &GlobalOpts, args: &CheckArgs) -> ExitCode {
    let session_id = SessionId::new();
    let check_all = args.all || (!args.priors && !args.policy && !args.check_capabilities);

    let mut results: Vec<serde_json::Value> = Vec::new();
    let mut all_ok = true;

    // Build config options from global opts
    let options = ConfigOptions {
        config_dir: global.config.as_ref().map(PathBuf::from),
        priors_path: None,
        policy_path: None,
    };

    // Check priors
    if check_all || args.priors {
        match load_config(&options) {
            Ok(config) => {
                let snapshot = config.snapshot();
                results.push(serde_json::json!({
                    "check": "priors",
                    "status": "ok",
                    "source": snapshot.priors_path.as_ref().map(|p| p.display().to_string()),
                    "using_defaults": snapshot.priors_path.is_none(),
                    "schema_version": snapshot.priors_schema_version,
                }));
            }
            Err(e) => {
                all_ok = false;
                results.push(serde_json::json!({
                    "check": "priors",
                    "status": "error",
                    "error": e.to_string(),
                }));
            }
        }
    }

    // Check policy (using same config load - already validated)
    if (check_all || args.policy) && all_ok {
        // Already loaded above if priors was checked
        match load_config(&options) {
            Ok(config) => {
                let snapshot = config.snapshot();
                results.push(serde_json::json!({
                    "check": "policy",
                    "status": "ok",
                    "source": snapshot.policy_path.as_ref().map(|p| p.display().to_string()),
                    "using_defaults": snapshot.policy_path.is_none(),
                    "schema_version": snapshot.policy_schema_version,
                }));
            }
            Err(e) => {
                all_ok = false;
                results.push(serde_json::json!({
                    "check": "policy",
                    "status": "error",
                    "error": e.to_string(),
                }));
            }
        }
    }

    // Check capabilities
    if check_all || args.check_capabilities {
        // Check if we have a capabilities manifest
        let has_capabilities = global.capabilities.is_some();
        results.push(serde_json::json!({
            "check": "capabilities",
            "status": if has_capabilities { "ok" } else { "info" },
            "manifest": global.capabilities.as_ref(),
            "note": if has_capabilities {
                "Capabilities manifest loaded"
            } else {
                "No capabilities manifest provided (will use auto-detection)"
            },
        }));
    }

    let response = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "session_id": session_id.0,
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "status": if all_ok { "ok" } else { "error" },
        "checks": results,
    });

    match global.format {
        OutputFormat::Json | OutputFormat::Toon => {
            println!("{}", format_structured_output(global, response));
        }
        OutputFormat::Summary => {
            let status = if all_ok { "OK" } else { "FAILED" };
            println!("[{}] check: {}", session_id, status);
        }
        OutputFormat::Exitcode => {}
        _ => {
            println!("# pt-core check");
            println!();
            for result in &results {
                let check = result.get("check").and_then(|v| v.as_str()).unwrap_or("?");
                let status = result.get("status").and_then(|v| v.as_str()).unwrap_or("?");
                let symbol = match status {
                    "ok" => "✓",
                    "info" => "ℹ",
                    _ => "✗",
                };
                println!("{} {}: {}", symbol, check, status);
                if let Some(note) = result.get("note").and_then(|v| v.as_str()) {
                    println!("  {}", note);
                }
                if let Some(error) = result.get("error").and_then(|v| v.as_str()) {
                    println!("  Error: {}", error);
                }
            }
            println!();
            println!("Session: {}", session_id);
        }
    }

    if all_ok {
        ExitCode::Clean
    } else {
        ExitCode::ArgsError
    }
}

fn run_agent(global: &GlobalOpts, args: &AgentArgs) -> ExitCode {
    match &args.command {
        AgentCommands::Snapshot(args) => run_agent_snapshot(global, args),
        AgentCommands::Plan(args) => run_agent_plan(global, args),
        AgentCommands::Explain(args) => run_agent_explain(global, args),
        AgentCommands::Apply(args) => run_agent_apply(global, args),
        AgentCommands::Verify(args) => run_agent_verify(global, args),
        AgentCommands::Diff(args) => run_agent_diff(global, args),
        AgentCommands::Sessions(args) => run_agent_sessions(global, args),
        AgentCommands::ListPriors(args) => run_agent_list_priors(global, args),
        AgentCommands::Inbox(args) => run_agent_inbox(global, args),
        AgentCommands::Tail(args) => run_agent_tail(global, args),
        AgentCommands::Watch(args) => run_agent_watch(global, args),
        AgentCommands::ExportPriors(args) => run_agent_export_priors(global, args),
        AgentCommands::ImportPriors(args) => run_agent_import_priors(global, args),
        #[cfg(feature = "report")]
        AgentCommands::Report(args) => run_agent_report(global, args),
        AgentCommands::Init(args) => run_agent_init(global, args),
        AgentCommands::Export(args) => run_agent_export(global, args),
        AgentCommands::Capabilities(args) => run_agent_capabilities(global, args),
        AgentCommands::Fleet(args) => run_agent_fleet(global, args),
    }
}

fn run_agent_fleet(global: &GlobalOpts, args: &AgentFleetArgs) -> ExitCode {
    match &args.command {
        AgentFleetCommands::Plan(args) => run_agent_fleet_plan(global, args),
        AgentFleetCommands::Apply(args) => run_agent_fleet_apply(global, args),
        AgentFleetCommands::Report(args) => run_agent_fleet_report(global, args),
        AgentFleetCommands::Status(args) => run_agent_fleet_status(global, args),
        AgentFleetCommands::Transfer(args) => run_agent_fleet_transfer(global, args),
    }
}

fn parse_fleet_hosts(spec: &str) -> Result<Vec<String>, String> {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return Err("hosts spec is empty".to_string());
    }

    if trimmed.contains(',') {
        let hosts: Vec<String> = trimmed
            .split(',')
            .map(|h| h.trim())
            .filter(|h| !h.is_empty())
            .map(|h| h.to_string())
            .collect();
        if hosts.is_empty() {
            return Err("no hosts found in comma-separated list".to_string());
        }
        return Ok(hosts);
    }

    let path = Path::new(trimmed);
    if path.exists() && path.is_file() {
        let content =
            fs::read_to_string(path).map_err(|e| format!("failed to read hosts file: {}", e))?;
        let hosts: Vec<String> = content
            .lines()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty())
            .filter(|line| !line.starts_with('#'))
            .map(|line| line.to_string())
            .collect();
        if hosts.is_empty() {
            return Err("hosts file contained no usable entries".to_string());
        }
        return Ok(hosts);
    }

    Ok(vec![trimmed.to_string()])
}

fn run_agent_fleet_plan(global: &GlobalOpts, args: &AgentFleetPlanArgs) -> ExitCode {
    let (hosts, inventory, source_label) =
        match (&args.hosts, &args.inventory, &args.discovery_config) {
            (Some(hosts_spec), None, None) => {
                let hosts = match parse_fleet_hosts(hosts_spec) {
                    Ok(h) => h,
                    Err(err) => {
                        return output_agent_error(global, "fleet plan", &err);
                    }
                };
                (hosts, None, Some("hosts"))
            }
            (None, Some(path), None) => {
                let provider = StaticInventoryProvider::from_path(Path::new(path));
                let inventory = match provider.discover() {
                    Ok(inv) => inv,
                    Err(err) => {
                        return output_agent_error(global, "fleet plan", &err.to_string());
                    }
                };
                let hosts: Vec<String> =
                    inventory.hosts.iter().map(|h| h.hostname.clone()).collect();
                if hosts.is_empty() {
                    return output_agent_error(global, "fleet plan", "inventory contains no hosts");
                }
                (hosts, Some(inventory), Some("inventory"))
            }
            (None, None, Some(path)) => {
                let discovery = match FleetDiscoveryConfig::load_from_path(Path::new(path)) {
                    Ok(cfg) => cfg,
                    Err(err) => {
                        return output_agent_error(global, "fleet plan", &err.to_string());
                    }
                };
                let registry = match ProviderRegistry::from_config(&discovery) {
                    Ok(registry) => registry,
                    Err(err) => {
                        return output_agent_error(global, "fleet plan", &err.to_string());
                    }
                };
                let inventory = match registry.discover_all() {
                    Ok(inv) => inv,
                    Err(err) => {
                        return output_agent_error(global, "fleet plan", &err.to_string());
                    }
                };
                let hosts: Vec<String> =
                    inventory.hosts.iter().map(|h| h.hostname.clone()).collect();
                if hosts.is_empty() {
                    return output_agent_error(global, "fleet plan", "discovery found no hosts");
                }
                (hosts, Some(inventory), Some("discovery_config"))
            }
            (None, None, None) => {
                return output_agent_error(
                    global,
                    "fleet plan",
                    "either --hosts, --inventory, or --discovery-config is required",
                );
            }
            _ => {
                return output_agent_error(
                    global,
                    "fleet plan",
                    "--hosts, --inventory, and --discovery-config are mutually exclusive",
                );
            }
        };

    // Perform SSH scanning of remote hosts
    let ssh_config = SshScanConfig {
        connect_timeout: args.timeout.min(30),
        command_timeout: args.timeout,
        parallel: args.parallel as usize,
        continue_on_error: args.continue_on_error,
        ..SshScanConfig::default()
    };

    eprintln!(
        "[fleet] Scanning {} hosts (parallel={}, timeout={}s)...",
        hosts.len(),
        ssh_config.parallel,
        ssh_config.command_timeout,
    );

    let scan_result = ssh_scan_fleet(&hosts, &ssh_config);

    eprintln!(
        "[fleet] Scan complete: {}/{} succeeded in {}ms",
        scan_result.successful, scan_result.total_hosts, scan_result.duration_ms,
    );

    // Convert scan results to fleet session inputs
    let host_inputs: Vec<HostInput> = scan_result
        .results
        .iter()
        .map(scan_result_to_host_input)
        .collect();

    let fleet_session_id = SessionId::new();
    let fleet_session = create_fleet_session(
        &fleet_session_id.0,
        args.label.as_deref(),
        &host_inputs,
        args.max_fdr,
    );

    let mut warnings: Vec<String> = Vec::new();
    for r in &scan_result.results {
        if !r.success {
            warnings.push(format!(
                "host '{}' scan failed: {}",
                r.host,
                r.error.as_deref().unwrap_or("unknown error")
            ));
        }
    }

    // Persist fleet session to disk
    let persist_result = (|| -> Result<PathBuf, String> {
        let store = SessionStore::from_env().map_err(|e| format!("session store error: {}", e))?;
        let manifest = SessionManifest::new(
            &fleet_session_id,
            None,
            SessionMode::RobotPlan,
            args.label.clone(),
        );
        let handle = store
            .create(&manifest)
            .map_err(|e| format!("session create error: {}", e))?;
        let fleet_json = serde_json::to_string_pretty(&fleet_session)
            .map_err(|e| format!("serialization error: {}", e))?;
        std::fs::write(handle.dir.join("fleet.json"), fleet_json)
            .map_err(|e| format!("write error: {}", e))?;
        Ok(handle.dir)
    })();

    let session_dir = match &persist_result {
        Ok(dir) => Some(dir.display().to_string()),
        Err(e) => {
            warnings.push(format!("failed to persist fleet session: {}", e));
            None
        }
    };

    let response = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "fleet_session_id": fleet_session_id.0,
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "command": "agent fleet plan",
        "status": if scan_result.failed == 0 { "ok" } else { "partial" },
        "warnings": warnings,
        "session_dir": session_dir,
        "scan_summary": {
            "total_hosts": scan_result.total_hosts,
            "successful": scan_result.successful,
            "failed": scan_result.failed,
            "duration_ms": scan_result.duration_ms,
        },
        "inputs": {
            "hosts_spec": args.hosts,
            "inventory_path": args.inventory,
            "discovery_config": args.discovery_config,
            "hosts": hosts,
            "parallel": args.parallel,
            "timeout_secs": args.timeout,
            "continue_on_error": args.continue_on_error,
            "host_profile": args.host_profile,
            "label": args.label,
            "max_fdr": args.max_fdr,
        },
        "inventory": inventory.as_ref().map(|inv| {
            serde_json::json!({
                "schema_version": inv.schema_version,
                "generated_at": inv.generated_at,
                "host_count": inv.hosts.len(),
            })
        }),
        "inventory_source": source_label,
        "fleet_session": fleet_session,
    });

    match global.format {
        OutputFormat::Json | OutputFormat::Toon => {
            println!("{}", format_structured_output(global, response));
        }
        OutputFormat::Exitcode => {}
        _ => {
            println!("# pt-core agent fleet plan");
            println!();
            println!(
                "Scanned {} hosts: {} succeeded, {} failed ({}ms)",
                scan_result.total_hosts,
                scan_result.successful,
                scan_result.failed,
                scan_result.duration_ms,
            );
            println!("Fleet session: {}", fleet_session_id.0);
            if !warnings.is_empty() {
                println!();
                println!("Warnings:");
                for w in &warnings {
                    println!("  - {}", w);
                }
            }
        }
    }

    ExitCode::Clean
}

fn load_fleet_session(
    fleet_session_id: &str,
) -> Result<(pt_core::session::fleet::FleetSession, PathBuf), String> {
    let store = SessionStore::from_env().map_err(|e| format!("session store error: {}", e))?;
    let sid = SessionId(fleet_session_id.to_string());
    let handle = store
        .open(&sid)
        .map_err(|e| format!("cannot open fleet session '{}': {}", fleet_session_id, e))?;
    let fleet_path = handle.dir.join("fleet.json");
    let content = std::fs::read_to_string(&fleet_path).map_err(|e| {
        format!(
            "cannot read fleet session '{}': {}",
            fleet_path.display(),
            e
        )
    })?;
    let fleet: pt_core::session::fleet::FleetSession =
        serde_json::from_str(&content).map_err(|e| format!("parse error: {}", e))?;
    Ok((fleet, handle.dir))
}

fn run_agent_fleet_apply(global: &GlobalOpts, args: &AgentFleetApplyArgs) -> ExitCode {
    let (fleet, session_dir) = match load_fleet_session(&args.fleet_session) {
        Ok(f) => f,
        Err(e) => return output_agent_error(global, "fleet apply", &e),
    };

    // Collect kill actions from the fleet session
    let mut kill_actions: Vec<serde_json::Value> = Vec::new();
    let mut review_actions: Vec<serde_json::Value> = Vec::new();

    for host in &fleet.hosts {
        for (action, count) in &host.summary.action_counts {
            match action.as_str() {
                "kill" => {
                    kill_actions.push(serde_json::json!({
                        "host": host.host_id,
                        "action": "kill",
                        "count": count,
                    }));
                }
                "review" => {
                    review_actions.push(serde_json::json!({
                        "host": host.host_id,
                        "action": "review",
                        "count": count,
                    }));
                }
                _ => {}
            }
        }
    }

    let total_kills: u32 = kill_actions
        .iter()
        .filter_map(|a| a["count"].as_u64())
        .map(|c| c as u32)
        .sum();

    let response = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "fleet_session_id": fleet.fleet_session_id,
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "command": "agent fleet apply",
        "status": "dry_run",
        "note": "Fleet apply currently reports planned actions. Remote execution requires --confirm flag (not yet implemented).",
        "session_dir": session_dir.display().to_string(),
        "planned_actions": {
            "total_kill_candidates": total_kills,
            "approved_by_fdr": fleet.safety_budget.pooled_fdr.selected_kills,
            "rejected_by_fdr": fleet.safety_budget.pooled_fdr.rejected_kills,
            "kills": kill_actions,
            "reviews": review_actions,
        },
        "safety_budget": fleet.safety_budget,
    });

    match global.format {
        OutputFormat::Json | OutputFormat::Toon => {
            println!("{}", format_structured_output(global, response));
        }
        OutputFormat::Exitcode => {}
        _ => {
            println!("# pt-core agent fleet apply");
            println!();
            println!("Fleet session: {}", fleet.fleet_session_id);
            println!("Hosts: {}", fleet.hosts.len());
            println!(
                "Kill candidates: {} ({} approved by FDR, {} rejected)",
                total_kills,
                fleet.safety_budget.pooled_fdr.selected_kills,
                fleet.safety_budget.pooled_fdr.rejected_kills,
            );
            println!();
            println!(
                "Note: Remote execution not yet implemented. Use --format json for full details."
            );
        }
    }

    ExitCode::Clean
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FleetReportProfile {
    Minimal,
    Safe,
    Forensic,
}

impl FleetReportProfile {
    fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "minimal" => Ok(Self::Minimal),
            "safe" => Ok(Self::Safe),
            "forensic" => Ok(Self::Forensic),
            other => Err(format!(
                "invalid --profile '{}'. Use one of: minimal, safe, forensic",
                other
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Minimal => "minimal",
            Self::Safe => "safe",
            Self::Forensic => "forensic",
        }
    }
}

fn deterministic_token(prefix: &str, raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    let digest = hasher.finalize();
    let hex = hex::encode(digest);
    format!("{}{}", prefix, &hex[..12])
}

fn redact_host_id_for_profile(host_id: &str, profile: FleetReportProfile) -> String {
    match profile {
        FleetReportProfile::Forensic => host_id.to_string(),
        FleetReportProfile::Minimal | FleetReportProfile::Safe => {
            deterministic_token("host_", host_id)
        }
    }
}

fn redact_signature_for_profile(signature: &str, profile: FleetReportProfile) -> String {
    match profile {
        FleetReportProfile::Forensic | FleetReportProfile::Safe => signature.to_string(),
        FleetReportProfile::Minimal => deterministic_token("sig_", signature),
    }
}

fn ordered_u32_map(input: &HashMap<String, u32>) -> BTreeMap<String, u32> {
    input.iter().map(|(k, v)| (k.clone(), *v)).collect()
}

fn redacted_f64_map(
    input: &HashMap<String, f64>,
    profile: FleetReportProfile,
) -> BTreeMap<String, f64> {
    let mut out = BTreeMap::new();
    for (host_id, value) in input {
        let redacted = redact_host_id_for_profile(host_id, profile);
        out.insert(redacted, *value);
    }
    out
}

fn redacted_u32_map(
    input: &HashMap<String, u32>,
    profile: FleetReportProfile,
) -> BTreeMap<String, u32> {
    let mut out = BTreeMap::new();
    for (host_id, value) in input {
        let redacted = redact_host_id_for_profile(host_id, profile);
        *out.entry(redacted).or_insert(0) += *value;
    }
    out
}

fn build_safety_budget_report(
    budget: &pt_core::session::fleet::SafetyBudget,
    profile: FleetReportProfile,
) -> serde_json::Value {
    serde_json::json!({
        "max_fdr": budget.max_fdr,
        "alpha_spent": budget.alpha_spent,
        "alpha_remaining": budget.alpha_remaining,
        "host_allocations": redacted_f64_map(&budget.host_allocations, profile),
        "pooled_fdr": {
            "method": budget.pooled_fdr.method,
            "alpha": budget.pooled_fdr.alpha,
            "total_kill_candidates": budget.pooled_fdr.total_kill_candidates,
            "selected_kills": budget.pooled_fdr.selected_kills,
            "rejected_kills": budget.pooled_fdr.rejected_kills,
            "selection_threshold": budget.pooled_fdr.selection_threshold,
            "correction_factor": budget.pooled_fdr.correction_factor,
            "selected_by_host": redacted_u32_map(&budget.pooled_fdr.selected_by_host, profile),
            "rejected_by_host": redacted_u32_map(&budget.pooled_fdr.rejected_by_host, profile),
        }
    })
}

fn mean_std(values: &[f64]) -> (f64, f64) {
    if values.is_empty() {
        return (0.0, 0.0);
    }
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let variance =
        values.iter().map(|v| (v - mean) * (v - mean)).sum::<f64>() / values.len() as f64;
    (mean, variance.sqrt())
}

fn build_fleet_top_offenders(
    fleet: &pt_core::session::fleet::FleetSession,
    profile: FleetReportProfile,
) -> Vec<serde_json::Value> {
    let mut patterns = fleet.aggregate.recurring_patterns.clone();
    patterns.sort_by(|a, b| {
        b.total_instances
            .cmp(&a.total_instances)
            .then_with(|| b.host_count.cmp(&a.host_count))
            .then_with(|| a.signature.cmp(&b.signature))
            .then_with(|| a.dominant_action.cmp(&b.dominant_action))
    });

    patterns
        .into_iter()
        .enumerate()
        .map(|(idx, p)| {
            let mut hosts: Vec<String> = p
                .hosts
                .iter()
                .map(|h| redact_host_id_for_profile(h, profile))
                .collect();
            hosts.sort();
            hosts.dedup();
            serde_json::json!({
                "rank": idx + 1,
                "signature": redact_signature_for_profile(&p.signature, profile),
                "host_count": p.host_count,
                "total_instances": p.total_instances,
                "dominant_action": p.dominant_action,
                "hosts": hosts,
            })
        })
        .collect()
}

fn build_host_comparison(
    fleet: &pt_core::session::fleet::FleetSession,
    profile: FleetReportProfile,
) -> Vec<serde_json::Value> {
    let mut rows: Vec<serde_json::Value> = fleet
        .hosts
        .iter()
        .map(|h| {
            let process_count = h.process_count.max(1);
            let candidate_count = h.candidate_count;
            let kill_count = *h.summary.action_counts.get("kill").unwrap_or(&0);
            let candidate_density = candidate_count as f64 / process_count as f64;
            let kill_rate = if candidate_count == 0 {
                0.0
            } else {
                kill_count as f64 / candidate_count as f64
            };
            let risk_index =
                candidate_density * 100.0 + h.summary.mean_candidate_score * 10.0 + kill_rate * 5.0;
            let risk_tier = if risk_index >= 35.0 {
                "high"
            } else if risk_index >= 15.0 {
                "medium"
            } else {
                "low"
            };
            serde_json::json!({
                "host_id": redact_host_id_for_profile(&h.host_id, profile),
                "process_count": h.process_count,
                "candidate_count": h.candidate_count,
                "candidate_density": candidate_density,
                "mean_candidate_score": h.summary.mean_candidate_score,
                "max_candidate_score": h.summary.max_candidate_score,
                "kill_count": kill_count,
                "kill_rate": kill_rate,
                "risk_index": risk_index,
                "risk_tier": risk_tier,
                "class_counts": ordered_u32_map(&h.summary.class_counts),
                "action_counts": ordered_u32_map(&h.summary.action_counts),
            })
        })
        .collect();

    rows.sort_by(|a, b| {
        b["risk_index"]
            .as_f64()
            .partial_cmp(&a["risk_index"].as_f64())
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| {
                b["candidate_count"]
                    .as_u64()
                    .cmp(&a["candidate_count"].as_u64())
            })
            .then_with(|| {
                a["host_id"]
                    .as_str()
                    .unwrap_or("")
                    .cmp(b["host_id"].as_str().unwrap_or(""))
            })
    });

    for (idx, row) in rows.iter_mut().enumerate() {
        row["rank"] = serde_json::json!(idx + 1);
    }

    rows
}

fn build_cross_host_anomalies(
    fleet: &pt_core::session::fleet::FleetSession,
    profile: FleetReportProfile,
) -> serde_json::Value {
    let mut candidate_counts = Vec::with_capacity(fleet.hosts.len());
    let mut candidate_densities = Vec::with_capacity(fleet.hosts.len());
    let mut mean_scores = Vec::with_capacity(fleet.hosts.len());
    let mut kill_rates = Vec::with_capacity(fleet.hosts.len());

    for h in &fleet.hosts {
        let process_count = h.process_count.max(1);
        let kill_count = *h.summary.action_counts.get("kill").unwrap_or(&0);
        let density = h.candidate_count as f64 / process_count as f64;
        let kill_rate = if h.candidate_count == 0 {
            0.0
        } else {
            kill_count as f64 / h.candidate_count as f64
        };
        candidate_counts.push(h.candidate_count as f64);
        candidate_densities.push(density);
        mean_scores.push(h.summary.mean_candidate_score);
        kill_rates.push(kill_rate);
    }

    let (count_mean, count_std) = mean_std(&candidate_counts);
    let (density_mean, density_std) = mean_std(&candidate_densities);
    let (score_mean, score_std) = mean_std(&mean_scores);
    let (kill_mean, kill_std) = mean_std(&kill_rates);
    let threshold_z = 1.5f64;

    let mut host_outliers: Vec<serde_json::Value> = Vec::new();
    for h in &fleet.hosts {
        let process_count = h.process_count.max(1);
        let kill_count = *h.summary.action_counts.get("kill").unwrap_or(&0);
        let density = h.candidate_count as f64 / process_count as f64;
        let kill_rate = if h.candidate_count == 0 {
            0.0
        } else {
            kill_count as f64 / h.candidate_count as f64
        };

        let z_count = if count_std > 0.0 {
            (h.candidate_count as f64 - count_mean) / count_std
        } else {
            0.0
        };
        let z_density = if density_std > 0.0 {
            (density - density_mean) / density_std
        } else {
            0.0
        };
        let z_score = if score_std > 0.0 {
            (h.summary.mean_candidate_score - score_mean) / score_std
        } else {
            0.0
        };
        let z_kill_rate = if kill_std > 0.0 {
            (kill_rate - kill_mean) / kill_std
        } else {
            0.0
        };

        let mut signals = Vec::new();
        if z_count >= threshold_z {
            signals.push(serde_json::json!({
                "metric": "candidate_count",
                "value": h.candidate_count,
                "z_score": z_count,
            }));
        }
        if z_density >= threshold_z {
            signals.push(serde_json::json!({
                "metric": "candidate_density",
                "value": density,
                "z_score": z_density,
            }));
        }
        if z_score >= threshold_z {
            signals.push(serde_json::json!({
                "metric": "mean_candidate_score",
                "value": h.summary.mean_candidate_score,
                "z_score": z_score,
            }));
        }
        if z_kill_rate >= threshold_z {
            signals.push(serde_json::json!({
                "metric": "kill_rate",
                "value": kill_rate,
                "z_score": z_kill_rate,
            }));
        }
        if signals.is_empty() {
            continue;
        }

        let max_z = [z_count, z_density, z_score, z_kill_rate]
            .into_iter()
            .fold(0.0f64, f64::max);
        host_outliers.push(serde_json::json!({
            "host_id": redact_host_id_for_profile(&h.host_id, profile),
            "signal_count": signals.len(),
            "max_z_score": max_z,
            "signals": signals,
        }));
    }

    host_outliers.sort_by(|a, b| {
        b["signal_count"]
            .as_u64()
            .cmp(&a["signal_count"].as_u64())
            .then_with(|| {
                b["max_z_score"]
                    .as_f64()
                    .partial_cmp(&a["max_z_score"].as_f64())
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| {
                a["host_id"]
                    .as_str()
                    .unwrap_or("")
                    .cmp(b["host_id"].as_str().unwrap_or(""))
            })
    });

    let mut pattern_hotspots: Vec<serde_json::Value> = fleet
        .aggregate
        .recurring_patterns
        .iter()
        .filter(|p| p.host_count > 1)
        .map(|p| {
            serde_json::json!({
                "signature": redact_signature_for_profile(&p.signature, profile),
                "host_count": p.host_count,
                "total_instances": p.total_instances,
                "dominant_action": p.dominant_action,
            })
        })
        .collect();
    pattern_hotspots.sort_by(|a, b| {
        b["host_count"]
            .as_u64()
            .cmp(&a["host_count"].as_u64())
            .then_with(|| {
                b["total_instances"]
                    .as_u64()
                    .cmp(&a["total_instances"].as_u64())
            })
            .then_with(|| {
                a["signature"]
                    .as_str()
                    .unwrap_or("")
                    .cmp(b["signature"].as_str().unwrap_or(""))
            })
    });

    serde_json::json!({
        "threshold_z_score": threshold_z,
        "host_outliers": host_outliers,
        "pattern_hotspots": pattern_hotspots,
    })
}

fn write_report_output_file(path: &str, rendered: &str) -> Result<(), String> {
    let out_path = PathBuf::from(path);
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            format!(
                "failed to create output directory {}: {}",
                parent.display(),
                e
            )
        })?;
    }
    std::fs::write(&out_path, rendered).map_err(|e| {
        format!(
            "failed to write report output {}: {}",
            out_path.display(),
            e
        )
    })
}

fn run_agent_fleet_report(global: &GlobalOpts, args: &AgentFleetReportArgs) -> ExitCode {
    let profile = match FleetReportProfile::parse(&args.profile) {
        Ok(p) => p,
        Err(e) => return output_agent_error(global, "fleet report", &e),
    };

    let (fleet, session_dir) = match load_fleet_session(&args.fleet_session) {
        Ok(f) => f,
        Err(e) => return output_agent_error(global, "fleet report", &e),
    };

    let top_offenders = build_fleet_top_offenders(&fleet, profile);
    let host_comparison = build_host_comparison(&fleet, profile);
    let cross_host_anomalies = build_cross_host_anomalies(&fleet, profile);
    let safety_budget = build_safety_budget_report(&fleet.safety_budget, profile);

    let response = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "fleet_session_id": fleet.fleet_session_id,
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "command": "agent fleet report",
        "session_dir": session_dir.display().to_string(),
        "report": {
            "profile": profile.as_str(),
            "created_at": fleet.created_at,
            "label": fleet.label,
            "aggregate": {
                "total_hosts": fleet.aggregate.total_hosts,
                "total_processes": fleet.aggregate.total_processes,
                "total_candidates": fleet.aggregate.total_candidates,
                "class_counts": ordered_u32_map(&fleet.aggregate.class_counts),
                "action_counts": ordered_u32_map(&fleet.aggregate.action_counts),
                "mean_candidate_score": fleet.aggregate.mean_candidate_score,
                "max_candidate_score": fleet.aggregate.max_candidate_score,
                "recurring_patterns": top_offenders.clone(),
            },
            "safety_budget": safety_budget,
            "hosts": host_comparison.clone(),
            "top_offenders": top_offenders,
            "host_comparison": host_comparison,
            "cross_host_anomalies": cross_host_anomalies,
        },
    });

    let rendered_for_file = match global.format {
        OutputFormat::Json | OutputFormat::Toon => {
            let rendered = format_structured_output(global, response.clone());
            println!("{}", rendered);
            Some(rendered)
        }
        OutputFormat::Exitcode => Some(serde_json::to_string_pretty(&response).unwrap_or_default()),
        _ => {
            println!("# Fleet Report: {}", fleet.fleet_session_id);
            if let Some(label) = &fleet.label {
                println!("Label: {}", label);
            }
            println!("Created: {}", fleet.created_at);
            println!("Profile: {}", profile.as_str());
            println!();
            println!("## Aggregate");
            println!("  Hosts:      {}", fleet.aggregate.total_hosts);
            println!("  Processes:  {}", fleet.aggregate.total_processes);
            println!("  Candidates: {}", fleet.aggregate.total_candidates);
            println!("  Mean score: {:.3}", fleet.aggregate.mean_candidate_score);
            println!("  Max score:  {:.3}", fleet.aggregate.max_candidate_score);
            println!();
            println!("## Top Offenders");
            for offender in response["report"]["top_offenders"]
                .as_array()
                .into_iter()
                .flatten()
                .take(8)
            {
                println!(
                    "  #{} {} — {} hosts, {} instances (action: {})",
                    offender["rank"].as_u64().unwrap_or(0),
                    offender["signature"].as_str().unwrap_or("?"),
                    offender["host_count"].as_u64().unwrap_or(0),
                    offender["total_instances"].as_u64().unwrap_or(0),
                    offender["dominant_action"].as_str().unwrap_or("?"),
                );
            }
            println!();
            println!("## Per-Host Comparison");
            for host in response["report"]["host_comparison"]
                .as_array()
                .into_iter()
                .flatten()
                .take(12)
            {
                println!(
                    "  #{} {} — {} candidates / {} processes (risk: {}, index {:.2})",
                    host["rank"].as_u64().unwrap_or(0),
                    host["host_id"].as_str().unwrap_or("?"),
                    host["candidate_count"].as_u64().unwrap_or(0),
                    host["process_count"].as_u64().unwrap_or(0),
                    host["risk_tier"].as_str().unwrap_or("?"),
                    host["risk_index"].as_f64().unwrap_or(0.0),
                );
            }
            println!();
            let outliers = response["report"]["cross_host_anomalies"]["host_outliers"]
                .as_array()
                .map(|arr| arr.len())
                .unwrap_or(0);
            println!(
                "## Cross-Host Anomalies\n  Outlier hosts: {} (z-score threshold {:.1})",
                outliers,
                response["report"]["cross_host_anomalies"]["threshold_z_score"]
                    .as_f64()
                    .unwrap_or(0.0)
            );

            Some(serde_json::to_string_pretty(&response).unwrap_or_default())
        }
    };

    if let (Some(path), Some(rendered)) = (args.out.as_deref(), rendered_for_file.as_deref()) {
        if let Err(err) = write_report_output_file(path, rendered) {
            return output_agent_error(global, "fleet report", &err);
        }
    }

    ExitCode::Clean
}

fn run_agent_fleet_status(global: &GlobalOpts, args: &AgentFleetStatusArgs) -> ExitCode {
    let (fleet, session_dir) = match load_fleet_session(&args.fleet_session) {
        Ok(f) => f,
        Err(e) => return output_agent_error(global, "fleet status", &e),
    };

    let response = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "fleet_session_id": fleet.fleet_session_id,
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "command": "agent fleet status",
        "session_dir": session_dir.display().to_string(),
        "created_at": fleet.created_at,
        "label": fleet.label,
        "hosts": fleet.hosts.len(),
        "aggregate": {
            "total_hosts": fleet.aggregate.total_hosts,
            "total_processes": fleet.aggregate.total_processes,
            "total_candidates": fleet.aggregate.total_candidates,
            "mean_candidate_score": fleet.aggregate.mean_candidate_score,
            "max_candidate_score": fleet.aggregate.max_candidate_score,
            "class_counts": fleet.aggregate.class_counts,
            "action_counts": fleet.aggregate.action_counts,
            "recurring_patterns": fleet.aggregate.recurring_patterns.len(),
        },
        "safety_budget": {
            "max_fdr": fleet.safety_budget.max_fdr,
            "alpha_spent": fleet.safety_budget.alpha_spent,
            "alpha_remaining": fleet.safety_budget.alpha_remaining,
            "pooled_fdr_selected": fleet.safety_budget.pooled_fdr.selected_kills,
            "pooled_fdr_rejected": fleet.safety_budget.pooled_fdr.rejected_kills,
        },
    });

    match global.format {
        OutputFormat::Json | OutputFormat::Toon => {
            println!("{}", format_structured_output(global, response));
        }
        OutputFormat::Exitcode => {}
        _ => {
            println!("# Fleet Status: {}", fleet.fleet_session_id);
            if let Some(label) = &fleet.label {
                println!("Label: {}", label);
            }
            println!("Created: {}", fleet.created_at);
            println!("Session: {}", session_dir.display());
            println!();
            println!("Hosts:      {}", fleet.aggregate.total_hosts);
            println!("Processes:  {}", fleet.aggregate.total_processes);
            println!("Candidates: {}", fleet.aggregate.total_candidates);
            println!();
            println!(
                "FDR budget: {:.1}% (spent {:.3}, remaining {:.3})",
                fleet.safety_budget.max_fdr * 100.0,
                fleet.safety_budget.alpha_spent,
                fleet.safety_budget.alpha_remaining
            );
            println!(
                "Kill decisions: {} approved, {} rejected by pooled FDR",
                fleet.safety_budget.pooled_fdr.selected_kills,
                fleet.safety_budget.pooled_fdr.rejected_kills
            );
        }
    }

    ExitCode::Clean
}

fn run_agent_fleet_transfer(global: &GlobalOpts, args: &AgentFleetTransferArgs) -> ExitCode {
    match &args.command {
        AgentFleetTransferCommands::Export(a) => run_agent_fleet_transfer_export(global, a),
        AgentFleetTransferCommands::Import(a) => run_agent_fleet_transfer_import(global, a),
        AgentFleetTransferCommands::Diff(a) => run_agent_fleet_transfer_diff(global, a),
    }
}

fn run_agent_fleet_transfer_export(
    global: &GlobalOpts,
    args: &AgentFleetTransferExportArgs,
) -> ExitCode {
    use pt_core::fleet::transfer::export_bundle;
    use pt_core::supervision::pattern_persistence::{
        PatternLibrary, PatternSource, PersistedSchema,
    };

    let host_id = pt_core::logging::get_host_id();

    let options = ConfigOptions {
        config_dir: global.config.as_ref().map(PathBuf::from),
        priors_path: None,
        policy_path: None,
    };

    let config = match load_config(&options) {
        Ok(c) => c,
        Err(e) => return output_config_error(global, &e),
    };

    let priors_opt = if args.include_priors {
        Some(&config.priors)
    } else {
        None
    };

    let signatures_opt: Option<PersistedSchema> = if args.include_signatures {
        let config_dir = global
            .config
            .as_ref()
            .map(PathBuf::from)
            .or_else(|| dirs::config_dir().map(|d| d.join("process_triage")))
            .unwrap_or_else(|| PathBuf::from("."));
        let mut lib = PatternLibrary::new(&config_dir);
        if lib.load().is_ok() {
            Some(lib.export(&[
                PatternSource::Learned,
                PatternSource::Custom,
                PatternSource::Imported,
            ]))
        } else {
            None
        }
    } else {
        None
    };

    let bundle = match export_bundle(
        priors_opt,
        signatures_opt.as_ref(),
        None,
        &host_id,
        args.host_profile.as_deref(),
    ) {
        Ok(b) => b,
        Err(e) => {
            return output_agent_error(global, "fleet transfer export", &e.to_string());
        }
    };

    let out_path = PathBuf::from(&args.out);
    if let Some(parent) = out_path.parent() {
        if !parent.as_os_str().is_empty() {
            if let Err(err) = std::fs::create_dir_all(parent) {
                eprintln!(
                    "fleet transfer export: failed to create {}: {}",
                    parent.display(),
                    err
                );
                return ExitCode::IoError;
            }
        }
    }

    let is_ptb = out_path.extension().map(|e| e == "ptb").unwrap_or(false);

    if is_ptb {
        use pt_bundle::{BundleWriter, FileType};
        use pt_redact::ExportProfile;

        let json_bytes = match serde_json::to_vec_pretty(&bundle) {
            Ok(b) => b,
            Err(e) => {
                return output_agent_error(global, "fleet transfer export", &e.to_string());
            }
        };
        let export_profile = match args.export_profile.as_deref() {
            Some("minimal") => ExportProfile::Minimal,
            Some("forensic") => ExportProfile::Forensic,
            _ => ExportProfile::Safe,
        };
        let mut writer = BundleWriter::new("transfer", &host_id, export_profile)
            .with_description("Fleet transfer bundle");
        writer.add_file("transfer_bundle.json", json_bytes, Some(FileType::Json));

        let passphrase = args
            .passphrase
            .clone()
            .or_else(|| std::env::var("PT_BUNDLE_PASSPHRASE").ok());

        let result = if let Some(ref pass) = passphrase {
            writer.write_encrypted(&out_path, pass)
        } else {
            writer.write(&out_path)
        };

        if let Err(e) = result {
            return output_agent_error(global, "fleet transfer export", &e.to_string());
        }
    } else {
        let tmp_path = out_path.with_extension("json.tmp");
        let payload = match serde_json::to_vec_pretty(&bundle) {
            Ok(b) => b,
            Err(e) => {
                return output_agent_error(global, "fleet transfer export", &e.to_string());
            }
        };
        if let Err(e) = std::fs::write(&tmp_path, &payload) {
            eprintln!("fleet transfer export: write failed: {}", e);
            return ExitCode::IoError;
        }
        if let Err(e) = std::fs::rename(&tmp_path, &out_path) {
            eprintln!("fleet transfer export: rename failed: {}", e);
            return ExitCode::IoError;
        }
    }

    let response = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "command": "agent fleet transfer export",
        "exported": true,
        "path": out_path.display().to_string(),
        "host_id": host_id,
        "host_profile": args.host_profile,
        "include_priors": args.include_priors,
        "include_signatures": args.include_signatures,
        "format": if is_ptb { "ptb" } else { "json" },
    });
    match global.format {
        OutputFormat::Json | OutputFormat::Toon => {
            println!("{}", format_structured_output(global, response));
        }
        OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string(&response).unwrap());
        }
        _ => {
            println!("Exported transfer bundle to: {}", out_path.display());
        }
    }

    ExitCode::Clean
}

fn run_agent_fleet_transfer_import(
    global: &GlobalOpts,
    args: &AgentFleetTransferImportArgs,
) -> ExitCode {
    use pt_core::fleet::transfer::{
        compute_diff, merge_priors, normalize_baseline, validate_bundle, MergeStrategy,
        TransferBundle,
    };
    use pt_core::supervision::pattern_persistence::{ConflictResolution, PatternLibrary};

    let input_path = PathBuf::from(&args.from);
    let is_ptb = input_path.extension().map(|e| e == "ptb").unwrap_or(false);

    let bundle: TransferBundle = if is_ptb {
        use pt_bundle::BundleReader;

        let passphrase = args
            .passphrase
            .clone()
            .or_else(|| std::env::var("PT_BUNDLE_PASSPHRASE").ok());

        let mut reader =
            match BundleReader::open_with_passphrase(&input_path, passphrase.as_deref()) {
                Ok(r) => r,
                Err(e) => {
                    return output_agent_error(global, "fleet transfer import", &e.to_string());
                }
            };

        let data = match reader.read_verified("transfer_bundle.json") {
            Ok(d) => d,
            Err(e) => {
                return output_agent_error(global, "fleet transfer import", &e.to_string());
            }
        };
        match serde_json::from_slice(&data) {
            Ok(b) => b,
            Err(e) => {
                return output_agent_error(global, "fleet transfer import", &e.to_string());
            }
        }
    } else {
        let data = match std::fs::read_to_string(&input_path) {
            Ok(d) => d,
            Err(e) => {
                return output_agent_error(global, "fleet transfer import", &e.to_string());
            }
        };
        match serde_json::from_str(&data) {
            Ok(b) => b,
            Err(e) => {
                return output_agent_error(global, "fleet transfer import", &e.to_string());
            }
        }
    };

    let warnings = match validate_bundle(&bundle) {
        Ok(w) => w,
        Err(e) => {
            return output_agent_error(global, "fleet transfer import", &e.to_string());
        }
    };

    let strategy: MergeStrategy = args
        .merge_strategy
        .as_deref()
        .unwrap_or("weighted")
        .parse()
        .unwrap_or(MergeStrategy::Weighted);

    let options = ConfigOptions {
        config_dir: global.config.as_ref().map(PathBuf::from),
        priors_path: None,
        policy_path: None,
    };
    let config = match load_config(&options) {
        Ok(c) => c,
        Err(e) => return output_config_error(global, &e),
    };

    let merged_priors = if let Some(ref incoming_priors) = bundle.priors {
        let mut incoming = incoming_priors.clone();
        if args.normalize_baseline {
            if let Some(ref source_stats) = bundle.baseline_stats {
                let target_stats = pt_core::fleet::transfer::BaselineStats {
                    total_processes_seen: 5000,
                    observation_window_hours: 72.0,
                    class_distribution: std::collections::BTreeMap::new(),
                    mean_cpu_utilization: 50.0,
                    host_type: None,
                };
                normalize_baseline(&mut incoming, source_stats, &target_stats);
            }
        }
        match merge_priors(&config.priors, &incoming, strategy) {
            Ok(m) => Some(m),
            Err(e) => {
                return output_agent_error(global, "fleet transfer import", &e.to_string());
            }
        }
    } else {
        None
    };

    let diff = compute_diff(Some(&config.priors), None, &bundle);

    if args.dry_run {
        let response = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "command": "agent fleet transfer import",
            "dry_run": true,
            "strategy": format!("{:?}", strategy),
            "source": input_path.display().to_string(),
            "source_host_id": bundle.source_host_id,
            "warnings": warnings,
            "diff": {
                "priors_changes": diff.priors_changes.len(),
                "signature_changes": diff.signature_changes.len(),
                "details": diff,
            },
        });
        match global.format {
            OutputFormat::Json | OutputFormat::Toon => {
                println!("{}", format_structured_output(global, response));
            }
            _ => {
                println!("Dry run — no changes applied.");
                println!(
                    "Source: {} (host {})",
                    input_path.display(),
                    bundle.source_host_id
                );
                println!("Strategy: {:?}", strategy);
                println!("Prior changes: {}", diff.priors_changes.len());
                println!("Signature changes: {}", diff.signature_changes.len());
                if !warnings.is_empty() {
                    println!("Warnings:");
                    for w in &warnings {
                        println!("  [{}] {}", w.code, w.message);
                    }
                }
            }
        }
        return ExitCode::Clean;
    }

    if let Some(ref final_priors) = merged_priors {
        let priors_path = config.snapshot().priors_path.unwrap_or_else(|| {
            global
                .config
                .as_ref()
                .map(|c| PathBuf::from(c).join("priors.json"))
                .unwrap_or_else(|| {
                    dirs::config_dir()
                        .unwrap_or_else(|| PathBuf::from("."))
                        .join("pt")
                        .join("priors.json")
                })
        });

        if !args.no_backup && priors_path.exists() {
            let backup = priors_path.with_extension("json.bak");
            if let Err(e) = std::fs::copy(&priors_path, &backup) {
                eprintln!("warning: failed to create backup: {}", e);
            }
        }

        if let Some(parent) = priors_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let tmp = priors_path.with_extension("json.tmp");
        match serde_json::to_vec_pretty(final_priors) {
            Ok(bytes) => {
                if let Err(e) = std::fs::write(&tmp, &bytes) {
                    eprintln!("fleet transfer import: write failed: {}", e);
                    return ExitCode::IoError;
                }
                if let Err(e) = std::fs::rename(&tmp, &priors_path) {
                    eprintln!("fleet transfer import: rename failed: {}", e);
                    return ExitCode::IoError;
                }
            }
            Err(e) => {
                return output_agent_error(global, "fleet transfer import", &e.to_string());
            }
        }
    }

    let sig_result = if let Some(ref incoming_sigs) = bundle.signatures {
        let config_dir = global
            .config
            .as_ref()
            .map(PathBuf::from)
            .or_else(|| dirs::config_dir().map(|d| d.join("process_triage")))
            .unwrap_or_else(|| PathBuf::from("."));
        let mut lib = PatternLibrary::new(&config_dir);
        let _ = lib.load();

        let resolution = match strategy {
            MergeStrategy::Replace => ConflictResolution::ReplaceWithImported,
            MergeStrategy::KeepLocal => ConflictResolution::KeepExisting,
            MergeStrategy::Weighted => ConflictResolution::KeepHigherConfidence,
        };

        match lib.import(incoming_sigs.clone(), resolution) {
            Ok(result) => {
                let _ = lib.save();
                Some(serde_json::json!({
                    "imported": result.imported,
                    "updated": result.updated,
                    "skipped": result.skipped,
                    "conflicts": result.conflicts.len(),
                }))
            }
            Err(e) => {
                eprintln!("warning: signature import failed: {}", e);
                None
            }
        }
    } else {
        None
    };

    let response = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "command": "agent fleet transfer import",
        "imported": true,
        "source": input_path.display().to_string(),
        "source_host_id": bundle.source_host_id,
        "strategy": format!("{:?}", strategy),
        "priors_merged": merged_priors.is_some(),
        "signatures": sig_result,
        "warnings": warnings,
    });
    match global.format {
        OutputFormat::Json | OutputFormat::Toon => {
            println!("{}", format_structured_output(global, response));
        }
        OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string(&response).unwrap());
        }
        _ => {
            println!(
                "Imported transfer bundle from {} (strategy: {:?})",
                input_path.display(),
                strategy
            );
            if merged_priors.is_some() {
                println!("  Priors: merged");
            }
            if let Some(ref sr) = sig_result {
                println!("  Signatures: {}", sr);
            }
        }
    }

    ExitCode::Clean
}

fn run_agent_fleet_transfer_diff(
    global: &GlobalOpts,
    args: &AgentFleetTransferDiffArgs,
) -> ExitCode {
    use pt_core::fleet::transfer::{compute_diff, validate_bundle, TransferBundle};

    let input_path = PathBuf::from(&args.from);
    let is_ptb = input_path.extension().map(|e| e == "ptb").unwrap_or(false);

    let bundle: TransferBundle = if is_ptb {
        use pt_bundle::BundleReader;

        let passphrase = args
            .passphrase
            .clone()
            .or_else(|| std::env::var("PT_BUNDLE_PASSPHRASE").ok());

        let mut reader =
            match BundleReader::open_with_passphrase(&input_path, passphrase.as_deref()) {
                Ok(r) => r,
                Err(e) => {
                    return output_agent_error(global, "fleet transfer diff", &e.to_string());
                }
            };

        let data = match reader.read_verified("transfer_bundle.json") {
            Ok(d) => d,
            Err(e) => {
                return output_agent_error(global, "fleet transfer diff", &e.to_string());
            }
        };
        match serde_json::from_slice(&data) {
            Ok(b) => b,
            Err(e) => {
                return output_agent_error(global, "fleet transfer diff", &e.to_string());
            }
        }
    } else {
        let data = match std::fs::read_to_string(&input_path) {
            Ok(d) => d,
            Err(e) => {
                return output_agent_error(global, "fleet transfer diff", &e.to_string());
            }
        };
        match serde_json::from_str(&data) {
            Ok(b) => b,
            Err(e) => {
                return output_agent_error(global, "fleet transfer diff", &e.to_string());
            }
        }
    };

    let warnings = match validate_bundle(&bundle) {
        Ok(w) => w,
        Err(e) => {
            return output_agent_error(global, "fleet transfer diff", &e.to_string());
        }
    };

    let options = ConfigOptions {
        config_dir: global.config.as_ref().map(PathBuf::from),
        priors_path: None,
        policy_path: None,
    };
    let config = match load_config(&options) {
        Ok(c) => c,
        Err(e) => return output_config_error(global, &e),
    };

    let diff = compute_diff(Some(&config.priors), None, &bundle);

    let response = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "command": "agent fleet transfer diff",
        "source": input_path.display().to_string(),
        "source_host_id": bundle.source_host_id,
        "source_host_profile": bundle.source_host_profile,
        "warnings": warnings,
        "diff": {
            "priors_changes": diff.priors_changes,
            "signature_changes": diff.signature_changes,
            "baseline_adjustments": diff.baseline_adjustments,
        },
    });
    match global.format {
        OutputFormat::Json | OutputFormat::Toon => {
            println!("{}", format_structured_output(global, response));
        }
        OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string(&response).unwrap());
        }
        _ => {
            println!("Transfer diff: {} → local", input_path.display());
            println!("Source host: {}", bundle.source_host_id);
            if let Some(ref profile) = bundle.source_host_profile {
                println!("Source profile: {}", profile);
            }
            println!();
            if diff.priors_changes.is_empty() && diff.signature_changes.is_empty() {
                println!("No differences found.");
            } else {
                if !diff.priors_changes.is_empty() {
                    println!("Prior changes ({}):", diff.priors_changes.len());
                    for c in &diff.priors_changes {
                        println!(
                            "  {}.{}: {:.4} → {:.4}",
                            c.class, c.field, c.local_value, c.incoming_value
                        );
                    }
                }
                if !diff.signature_changes.is_empty() {
                    println!("Signature changes ({}):", diff.signature_changes.len());
                    for c in &diff.signature_changes {
                        println!("  {} [{:?}]", c.name, c.change_type);
                    }
                }
            }
            if !warnings.is_empty() {
                println!();
                println!("Warnings:");
                for w in &warnings {
                    println!("  [{}] {}", w.code, w.message);
                }
            }
        }
    }

    ExitCode::Clean
}

fn run_config(global: &GlobalOpts, args: &ConfigArgs) -> ExitCode {
    match &args.command {
        ConfigCommands::Show { file } => run_config_show(global, file.as_deref()),
        ConfigCommands::Schema { file } => {
            output_stub(
                global,
                "config schema",
                &format!("Schema for {} not yet implemented", file),
            );
            ExitCode::Clean
        }
        ConfigCommands::Validate { path } => run_config_validate(global, path.as_ref()),
        ConfigCommands::ListPresets => run_config_list_presets(global),
        ConfigCommands::ShowPreset { preset } => run_config_show_preset(global, preset),
        ConfigCommands::DiffPreset { preset } => run_config_diff_preset(global, preset),
        ConfigCommands::ExportPreset { preset, output } => {
            run_config_export_preset(global, preset, output.as_deref())
        }
    }
}

/// Display the current configuration (including defaults if no files present).
fn run_config_show(global: &GlobalOpts, file_filter: Option<&str>) -> ExitCode {
    let session_id = SessionId::new();

    // Build config options from global opts
    let options = ConfigOptions {
        config_dir: global.config.as_ref().map(PathBuf::from),
        priors_path: None,
        policy_path: None,
    };

    // Load configuration (will fall back to defaults if no files found)
    let config = match load_config(&options) {
        Ok(c) => c,
        Err(e) => {
            return output_config_error(global, &e);
        }
    };

    let snapshot = config.snapshot();

    // Build response based on filter
    let response = match file_filter {
        Some("priors") => {
            serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "session_id": session_id.0,
                "generated_at": chrono::Utc::now().to_rfc3339(),
                "source": {
                    "path": snapshot.priors_path.as_ref().map(|p| p.display().to_string()),
                    "hash": &snapshot.priors_hash,
                    "using_defaults": snapshot.priors_path.is_none(),
                    "schema_version": &snapshot.priors_schema_version,
                },
                "priors": &config.priors
            })
        }
        Some("policy") => {
            serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "session_id": session_id.0,
                "generated_at": chrono::Utc::now().to_rfc3339(),
                "source": {
                    "path": snapshot.policy_path.as_ref().map(|p| p.display().to_string()),
                    "hash": &snapshot.policy_hash,
                    "using_defaults": snapshot.policy_path.is_none(),
                    "schema_version": &snapshot.policy_schema_version,
                },
                "policy": &config.policy
            })
        }
        _ => {
            // Show both
            serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "session_id": session_id.0,
                "generated_at": chrono::Utc::now().to_rfc3339(),
                "config_dir": snapshot.config_dir.display().to_string(),
                "priors": {
                    "source": {
                        "path": snapshot.priors_path.as_ref().map(|p| p.display().to_string()),
                        "hash": &snapshot.priors_hash,
                        "using_defaults": snapshot.priors_path.is_none(),
                        "schema_version": &snapshot.priors_schema_version,
                    },
                    "values": &config.priors
                },
                "policy": {
                    "source": {
                        "path": snapshot.policy_path.as_ref().map(|p| p.display().to_string()),
                        "hash": &snapshot.policy_hash,
                        "using_defaults": snapshot.policy_path.is_none(),
                        "schema_version": &snapshot.policy_schema_version,
                    },
                    "values": &config.policy
                }
            })
        }
    };

    match global.format {
        OutputFormat::Json | OutputFormat::Toon => {
            println!("{}", format_structured_output(global, response));
        }
        OutputFormat::Summary => {
            let priors_src = snapshot
                .priors_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "built-in defaults".to_string());
            let policy_src = snapshot
                .policy_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "built-in defaults".to_string());
            println!(
                "[{}] config: priors={} policy={}",
                session_id, priors_src, policy_src
            );
        }
        OutputFormat::Exitcode => {}
        _ => {
            println!("# pt-core config show");
            println!();
            println!("Config directory: {}", snapshot.config_dir.display());
            println!();
            println!("## Priors");
            if let Some(ref path) = snapshot.priors_path {
                println!("Source: {}", path.display());
                println!("Hash: {}", snapshot.priors_hash.as_deref().unwrap_or("n/a"));
            } else {
                println!("Source: **built-in defaults** (no priors.json found)");
            }
            println!("Schema version: {}", snapshot.priors_schema_version);
            println!();
            println!("## Policy");
            if let Some(ref path) = snapshot.policy_path {
                println!("Source: {}", path.display());
                println!("Hash: {}", snapshot.policy_hash.as_deref().unwrap_or("n/a"));
            } else {
                println!("Source: **built-in defaults** (no policy.json found)");
            }
            println!("Schema version: {}", snapshot.policy_schema_version);
            println!();
            println!("Session: {}", session_id);
        }
    }

    ExitCode::Clean
}

/// Validate configuration files.
fn run_config_validate(global: &GlobalOpts, path: Option<&String>) -> ExitCode {
    let session_id = SessionId::new();

    // Build config options
    let options = if let Some(p) = path {
        // Validate specific file
        let path_buf = PathBuf::from(p);
        if p.contains("priors") {
            ConfigOptions {
                config_dir: None,
                priors_path: Some(path_buf),
                policy_path: None,
            }
        } else if p.contains("policy") {
            ConfigOptions {
                config_dir: None,
                priors_path: None,
                policy_path: Some(path_buf),
            }
        } else {
            // Assume it's a config directory
            ConfigOptions {
                config_dir: Some(path_buf),
                priors_path: None,
                policy_path: None,
            }
        }
    } else {
        ConfigOptions {
            config_dir: global.config.as_ref().map(PathBuf::from),
            priors_path: None,
            policy_path: None,
        }
    };

    // Try to load and validate
    match load_config(&options) {
        Ok(config) => {
            let snapshot = config.snapshot();
            let response = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "session_id": session_id.0,
                "generated_at": chrono::Utc::now().to_rfc3339(),
                "status": "valid",
                "priors": {
                    "path": snapshot.priors_path.as_ref().map(|p| p.display().to_string()),
                    "using_defaults": snapshot.priors_path.is_none(),
                    "schema_version": snapshot.priors_schema_version,
                },
                "policy": {
                    "path": snapshot.policy_path.as_ref().map(|p| p.display().to_string()),
                    "using_defaults": snapshot.policy_path.is_none(),
                    "schema_version": snapshot.policy_schema_version,
                }
            });

            match global.format {
                OutputFormat::Json | OutputFormat::Toon => {
                    println!("{}", format_structured_output(global, response));
                }
                OutputFormat::Summary => {
                    println!("[{}] config validate: OK", session_id);
                }
                OutputFormat::Exitcode => {}
                _ => {
                    println!("# Configuration Validation");
                    println!();
                    println!("Status: ✓ Valid");
                    if let Some(priors_path) = snapshot.priors_path {
                        println!("Priors: {}", priors_path.display());
                    } else {
                        println!("Priors: using built-in defaults");
                    }
                    if let Some(policy_path) = snapshot.policy_path {
                        println!("Policy: {}", policy_path.display());
                    } else {
                        println!("Policy: using built-in defaults");
                    }
                }
            }

            ExitCode::Clean
        }
        Err(e) => output_config_error(global, &e),
    }
}

/// Output a config error in the appropriate format.
fn output_config_error(global: &GlobalOpts, error: &ConfigError) -> ExitCode {
    let session_id = SessionId::new();

    let (error_code, exit_code) = match error {
        ConfigError::NotFound { .. } => (10, ExitCode::ArgsError),
        ConfigError::ParseError { .. } => (11, ExitCode::ArgsError),
        ConfigError::SchemaError { .. } => (11, ExitCode::ArgsError),
        ConfigError::ValidationError(_) => (11, ExitCode::ArgsError),
        ConfigError::IoError { .. } => (21, ExitCode::IoError),
        ConfigError::VersionMismatch { .. } => (13, ExitCode::VersionError),
    };

    let response = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "session_id": session_id.0,
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "status": "error",
        "error": {
            "code": error_code,
            "message": error.to_string(),
        }
    });

    match global.format {
        OutputFormat::Json | OutputFormat::Toon => {
            eprintln!("{}", format_structured_output(global, response));
        }
        OutputFormat::Summary => {
            eprintln!("[{}] config error: {}", session_id, error);
        }
        OutputFormat::Exitcode => {}
        _ => {
            eprintln!("# Configuration Error");
            eprintln!();
            eprintln!("Error: {}", error);
        }
    }

    exit_code
}

fn output_agent_error(global: &GlobalOpts, command: &str, message: &str) -> ExitCode {
    match global.format {
        OutputFormat::Json | OutputFormat::Toon => {
            let output = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "generated_at": chrono::Utc::now().to_rfc3339(),
                "command": command,
                "status": "error",
                "error": message,
            });
            println!("{}", format_structured_output(global, output));
        }
        OutputFormat::Summary => {
            println!("[error] {}: {}", command, message);
        }
        OutputFormat::Exitcode => {}
        _ => {
            println!("# pt-core {}", command);
            println!();
            println!("Error: {}", message);
        }
    }

    ExitCode::ArgsError
}

/// List available configuration presets.
fn run_config_list_presets(global: &GlobalOpts) -> ExitCode {
    let session_id = SessionId::new();
    let presets = list_presets();

    match global.format {
        OutputFormat::Json | OutputFormat::Toon => {
            let response = serde_json::json!({
                "session_id": session_id.to_string(),
                "presets": presets.iter().map(|p| {
                    serde_json::json!({
                        "name": p.name.to_string(),
                        "description": p.description,
                    })
                }).collect::<Vec<_>>(),
            });
            println!("{}", format_structured_output(global, response));
        }
        OutputFormat::Summary => {
            println!("[{}] {} presets available", session_id, presets.len());
        }
        OutputFormat::Exitcode => {}
        _ => {
            println!("# Available Configuration Presets");
            println!();
            for preset in &presets {
                println!("  {} - {}", preset.name, preset.description);
            }
            println!();
            println!("Use 'pt-core config show-preset <name>' to view preset values.");
            println!("Use 'pt-core config export-preset <name>' to export to a file.");
        }
    }

    ExitCode::Clean
}

/// Show configuration values for a preset.
fn run_config_show_preset(global: &GlobalOpts, preset_name: &str) -> ExitCode {
    let session_id = SessionId::new();

    // Parse preset name
    let preset_name = match preset_name.to_lowercase().as_str() {
        "developer" | "dev" => PresetName::Developer,
        "server" | "srv" | "production" | "prod" => PresetName::Server,
        "ci" | "continuous-integration" => PresetName::Ci,
        "paranoid" | "safe" | "cautious" => PresetName::Paranoid,
        _ => {
            let response = serde_json::json!({
                "session_id": session_id.to_string(),
                "error": format!("Unknown preset: {}. Available: developer, server, ci, paranoid", preset_name),
            });
            match global.format {
                OutputFormat::Json | OutputFormat::Toon => {
                    eprintln!("{}", format_structured_output(global, response));
                }
                _ => {
                    eprintln!("Error: Unknown preset '{}'. Available presets: developer, server, ci, paranoid", preset_name);
                }
            }
            return ExitCode::ArgsError;
        }
    };

    let policy = get_preset(preset_name);

    match global.format {
        OutputFormat::Json | OutputFormat::Toon => {
            let response = serde_json::json!({
                "session_id": session_id.to_string(),
                "preset": preset_name.to_string(),
                "policy": policy,
            });
            println!("{}", format_structured_output(global, response));
        }
        OutputFormat::Summary => {
            println!("[{}] preset {}", session_id, preset_name);
        }
        OutputFormat::Exitcode => {}
        _ => {
            println!("# Preset: {}", preset_name);
            println!();
            println!("{}", serde_json::to_string_pretty(&policy).unwrap());
        }
    }

    ExitCode::Clean
}

/// Compare a preset with current configuration.
fn run_config_diff_preset(global: &GlobalOpts, preset_name: &str) -> ExitCode {
    let session_id = SessionId::new();

    // Parse preset name
    let preset_name_parsed = match preset_name.to_lowercase().as_str() {
        "developer" | "dev" => PresetName::Developer,
        "server" | "srv" | "production" | "prod" => PresetName::Server,
        "ci" | "continuous-integration" => PresetName::Ci,
        "paranoid" | "safe" | "cautious" => PresetName::Paranoid,
        _ => {
            let response = serde_json::json!({
                "session_id": session_id.to_string(),
                "error": format!("Unknown preset: {}. Available: developer, server, ci, paranoid", preset_name),
            });
            match global.format {
                OutputFormat::Json | OutputFormat::Toon => {
                    eprintln!("{}", format_structured_output(global, response));
                }
                _ => {
                    eprintln!("Error: Unknown preset '{}'. Available presets: developer, server, ci, paranoid", preset_name);
                }
            }
            return ExitCode::ArgsError;
        }
    };

    // Load current config
    let options = ConfigOptions {
        config_dir: global.config.as_ref().map(PathBuf::from),
        priors_path: None,
        policy_path: None,
    };

    let current_policy = match load_config(&options) {
        Ok(c) => c.policy,
        Err(e) => {
            return output_config_error(global, &e);
        }
    };

    let preset_policy = get_preset(preset_name_parsed);

    // Convert to JSON for comparison
    let current_json = serde_json::to_value(&current_policy).unwrap();
    let preset_json = serde_json::to_value(&preset_policy).unwrap();

    // Find differences
    let mut differences: Vec<serde_json::Value> = Vec::new();
    find_json_differences("", &current_json, &preset_json, &mut differences);

    match global.format {
        OutputFormat::Json | OutputFormat::Toon => {
            let response = serde_json::json!({
                "session_id": session_id.to_string(),
                "preset": preset_name_parsed.to_string(),
                "differences_count": differences.len(),
                "differences": differences,
            });
            println!("{}", format_structured_output(global, response));
        }
        OutputFormat::Summary => {
            println!(
                "[{}] {} differences between current and {} preset",
                session_id,
                differences.len(),
                preset_name_parsed
            );
        }
        OutputFormat::Exitcode => {}
        _ => {
            println!("# Differences: current vs {} preset", preset_name_parsed);
            println!();
            if differences.is_empty() {
                println!("No differences found.");
            } else {
                println!("{} difference(s) found:", differences.len());
                println!();
                for diff in &differences {
                    println!(
                        "  {}: {} -> {}",
                        diff["path"], diff["current"], diff["preset"]
                    );
                }
            }
        }
    }

    ExitCode::Clean
}

/// Helper to find differences between two JSON values recursively.
fn find_json_differences(
    path: &str,
    current: &serde_json::Value,
    preset: &serde_json::Value,
    differences: &mut Vec<serde_json::Value>,
) {
    match (current, preset) {
        (serde_json::Value::Object(c_map), serde_json::Value::Object(p_map)) => {
            // Check all keys in both
            let mut all_keys: std::collections::HashSet<&String> = c_map.keys().collect();
            all_keys.extend(p_map.keys());

            for key in all_keys {
                let new_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{}.{}", path, key)
                };

                let c_val = c_map.get(key).unwrap_or(&serde_json::Value::Null);
                let p_val = p_map.get(key).unwrap_or(&serde_json::Value::Null);

                find_json_differences(&new_path, c_val, p_val, differences);
            }
        }
        (serde_json::Value::Array(c_arr), serde_json::Value::Array(p_arr)) => {
            if c_arr != p_arr {
                differences.push(serde_json::json!({
                    "path": path,
                    "current": current,
                    "preset": preset,
                }));
            }
        }
        _ => {
            if current != preset {
                differences.push(serde_json::json!({
                    "path": path,
                    "current": current,
                    "preset": preset,
                }));
            }
        }
    }
}

/// Export a preset to a file.
fn run_config_export_preset(
    global: &GlobalOpts,
    preset_name: &str,
    output: Option<&str>,
) -> ExitCode {
    let session_id = SessionId::new();

    // Parse preset name
    let preset_name_parsed = match preset_name.to_lowercase().as_str() {
        "developer" | "dev" => PresetName::Developer,
        "server" | "srv" | "production" | "prod" => PresetName::Server,
        "ci" | "continuous-integration" => PresetName::Ci,
        "paranoid" | "safe" | "cautious" => PresetName::Paranoid,
        _ => {
            let response = serde_json::json!({
                "session_id": session_id.to_string(),
                "error": format!("Unknown preset: {}. Available: developer, server, ci, paranoid", preset_name),
            });
            match global.format {
                OutputFormat::Json | OutputFormat::Toon => {
                    eprintln!("{}", format_structured_output(global, response));
                }
                _ => {
                    eprintln!("Error: Unknown preset '{}'. Available presets: developer, server, ci, paranoid", preset_name);
                }
            }
            return ExitCode::ArgsError;
        }
    };

    let policy = get_preset(preset_name_parsed);
    let json_content = serde_json::to_string_pretty(&policy).unwrap();

    // Determine output destination
    let output_path = output.map(PathBuf::from).unwrap_or_else(|| {
        PathBuf::from(format!(
            "policy.{}.json",
            preset_name_parsed.to_string().to_lowercase()
        ))
    });

    // Write to file
    match std::fs::write(&output_path, &json_content) {
        Ok(()) => {
            match global.format {
                OutputFormat::Json | OutputFormat::Toon => {
                    let response = serde_json::json!({
                        "session_id": session_id.to_string(),
                        "preset": preset_name_parsed.to_string(),
                        "output_path": output_path.display().to_string(),
                        "status": "exported",
                    });
                    println!("{}", format_structured_output(global, response));
                }
                OutputFormat::Summary => {
                    println!(
                        "[{}] exported {} to {}",
                        session_id,
                        preset_name_parsed,
                        output_path.display()
                    );
                }
                OutputFormat::Exitcode => {}
                _ => {
                    println!(
                        "Exported {} preset to {}",
                        preset_name_parsed,
                        output_path.display()
                    );
                }
            }
            ExitCode::Clean
        }
        Err(e) => {
            match global.format {
                OutputFormat::Json | OutputFormat::Toon => {
                    let response = serde_json::json!({
                        "session_id": session_id.to_string(),
                        "error": format!("Failed to write to {}: {}", output_path.display(), e),
                    });
                    eprintln!("{}", format_structured_output(global, response));
                }
                _ => {
                    eprintln!("Error: Failed to write to {}: {}", output_path.display(), e);
                }
            }
            ExitCode::IoError
        }
    }
}

#[cfg(feature = "daemon")]
fn run_daemon(global: &GlobalOpts, args: &DaemonArgs) -> ExitCode {
    match &args.command {
        Some(DaemonCommands::Start { foreground }) => run_daemon_start(global, *foreground),
        Some(DaemonCommands::Stop) => run_daemon_stop(global),
        Some(DaemonCommands::Status) => run_daemon_status(global),
        None => run_daemon_start(global, true),
    }
}

#[cfg(feature = "daemon")]
fn run_daemon_start(global: &GlobalOpts, foreground: bool) -> ExitCode {
    let (config, enabled) = load_daemon_config(global);
    if !enabled {
        let response = serde_json::json!({
            "command": "daemon start",
            "enabled": false,
            "message": "daemon disabled in config",
        });
        match global.format {
            OutputFormat::Json | OutputFormat::Toon | OutputFormat::Jsonl => {
                println!("{}", format_structured_output(global, response));
            }
            _ => {
                println!("Daemon disabled in config; not starting.");
            }
        }
        return ExitCode::Clean;
    }

    if foreground {
        return run_daemon_foreground(global, &config);
    }
    run_daemon_background(global)
}

#[cfg(feature = "daemon")]
fn run_daemon_background(global: &GlobalOpts) -> ExitCode {
    if let Ok(Some(pid)) = read_daemon_pid() {
        if is_process_running(pid) {
            eprintln!("daemon start: existing daemon running (pid {})", pid);
            return ExitCode::LockError;
        }
        let _ = remove_daemon_pid();
    }

    let exe = match std::env::current_exe() {
        Ok(path) => path,
        Err(err) => {
            eprintln!("daemon start: failed to resolve executable: {}", err);
            return ExitCode::InternalError;
        }
    };

    let mut cmd = std::process::Command::new(exe);
    cmd.arg("daemon").arg("start").arg("--foreground");
    apply_daemon_global_args(&mut cmd, global);
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    let child = match cmd.spawn() {
        Ok(child) => child,
        Err(err) => {
            eprintln!("daemon start: failed to spawn background worker: {}", err);
            return ExitCode::IoError;
        }
    };

    if let Err(err) = write_daemon_pid(child.id()) {
        eprintln!("daemon start: failed to write pid file: {}", err);
        return ExitCode::IoError;
    }

    let response = serde_json::json!({
        "command": "daemon start",
        "mode": "background",
        "pid": child.id(),
        "base_dir": daemon_base_dir().display().to_string(),
    });
    match global.format {
        OutputFormat::Json | OutputFormat::Toon | OutputFormat::Jsonl => {
            println!("{}", format_structured_output(global, response));
        }
        _ => {
            println!("Daemon started (pid {}).", child.id());
        }
    }

    ExitCode::Clean
}

#[cfg(feature = "daemon")]
fn run_daemon_foreground(global: &GlobalOpts, config: &pt_core::daemon::DaemonConfig) -> ExitCode {
    use pt_core::inbox::{InboxItem, InboxStore};

    install_daemon_signal_handlers();
    apply_daemon_nice();
    let own_pid = std::process::id();
    let mut last_cpu_sample: Option<(f64, std::time::Instant)> = None;

    match read_daemon_pid() {
        Ok(Some(pid)) if pid != own_pid && is_process_running(pid) => {
            eprintln!("daemon start: existing daemon running (pid {})", pid);
            return ExitCode::LockError;
        }
        Ok(Some(pid)) if pid != own_pid => {
            let _ = remove_daemon_pid();
        }
        Ok(_) => {}
        Err(err) => {
            eprintln!("daemon start: failed to read pid file: {}", err);
        }
    }
    if let Err(err) = write_daemon_pid(own_pid) {
        eprintln!("daemon start: failed to write pid file: {}", err);
    }

    let state_path = daemon_state_path();
    let mut state_bundle = load_daemon_state(&state_path, config);

    let mut config = config.clone();
    let inbox = InboxStore::from_env().ok();
    let mut notify_mgr = pt_core::decision::escalation::EscalationManager::from_persisted(
        config.notification_ladder.clone(),
        state_bundle.notifications.clone(),
    );

    loop {
        if DAEMON_SIGNALS.should_stop() {
            break;
        }

        if DAEMON_SIGNALS.take_reload() {
            let (reloaded, enabled) = load_daemon_config(global);
            if enabled {
                config = reloaded;
                // Apply new ladder config while preserving persisted state.
                notify_mgr = pt_core::decision::escalation::EscalationManager::from_persisted(
                    config.notification_ladder.clone(),
                    notify_mgr.persisted_state(),
                );
                state_bundle.daemon.record_event(
                    pt_core::daemon::DaemonEventType::ConfigReloaded,
                    "config reloaded",
                );
            }
        }

        let metrics = collect_daemon_metrics();
        let now_secs = daemon_now_secs();

        if let Some(store) = inbox.as_ref() {
            daemon_refresh_inbox_notifications(&config, &mut notify_mgr, store, now_secs);
        }

        let mut budget_exceeded = false;
        let now = std::time::Instant::now();
        if let Some(cpu_total) = current_cpu_seconds() {
            if let Some((prev_cpu, prev_time)) = last_cpu_sample {
                let wall = now.duration_since(prev_time).as_secs_f64();
                let cpu_delta = cpu_total - prev_cpu;
                if wall > 0.0 && cpu_delta >= 0.0 {
                    let cpu_pct = (cpu_delta / wall) * 100.0;
                    if cpu_pct > config.max_cpu_percent {
                        budget_exceeded = true;
                        state_bundle.daemon.record_event(
                            pt_core::daemon::DaemonEventType::OverheadBudgetExceeded,
                            &format!(
                                "cpu {:.2}% exceeds budget {}",
                                cpu_pct, config.max_cpu_percent
                            ),
                        );
                    }
                }
            }
            last_cpu_sample = Some((cpu_total, now));
        }
        if let Some(rss_mb) = current_rss_mb() {
            if rss_mb > config.max_rss_mb {
                budget_exceeded = true;
                state_bundle.daemon.record_event(
                    pt_core::daemon::DaemonEventType::OverheadBudgetExceeded,
                    &format!("rss {} MB exceeds budget {}", rss_mb, config.max_rss_mb),
                );
            }
        }

        let (daemon_state, trigger_state, escalation_state) = (
            &mut state_bundle.daemon,
            &mut state_bundle.triggers,
            &mut state_bundle.escalation,
        );

        if budget_exceeded {
            daemon_state.tick_count += 1;
            daemon_state.last_tick_at = Some(metrics.timestamp.clone());
            daemon_state.record_event(
                pt_core::daemon::DaemonEventType::TickCompleted,
                "tick (budget exceeded)",
            );
        } else {
            let mut escalation_inbox = inbox.clone();
            let outcome = pt_core::daemon::process_tick(
                &config,
                daemon_state,
                trigger_state,
                &metrics,
                &mut |esc_config, fired| {
                    let lock_path = global_lock_path().unwrap_or_else(daemon_lock_path);
                    let lock = match GlobalLock::try_acquire(&lock_path) {
                        Ok(lock) => lock,
                        Err(err) => {
                            return pt_core::daemon::escalation::EscalationOutcome {
                                status: pt_core::daemon::escalation::EscalationStatus::Failed,
                                reason: format!("lock error: {}", err),
                                session_id: None,
                            };
                        }
                    };

                    let mut outcome = pt_core::daemon::escalation::decide_escalation(
                        esc_config,
                        escalation_state,
                        fired,
                        || lock.is_some(),
                    );

                    if matches!(
                        outcome.status,
                        pt_core::daemon::escalation::EscalationStatus::Deferred
                    ) && outcome.reason.contains("LockContention")
                    {
                        if let Some(store) = escalation_inbox.as_mut() {
                            let item = InboxItem::lock_contention(
                                "daemon escalation deferred: lock contention".to_string(),
                                None,
                            );
                            let _ = store.add(&item);
                        }
                    }

                    if matches!(
                        outcome.status,
                        pt_core::daemon::escalation::EscalationStatus::Completed
                    ) {
                        let summary = pt_core::daemon::escalation::build_inbox_summary(fired);
                        match run_daemon_escalation(global, fired, esc_config) {
                            Ok(result) => {
                                outcome.session_id = Some(result.session_id.clone());
                                if let Some(store) = escalation_inbox.as_mut() {
                                    let item = InboxItem::dormant_escalation(
                                        result.session_id,
                                        summary.clone(),
                                        summary,
                                        result.candidates_found,
                                    );
                                    let _ = store.add(&item);
                                    // Emit L1 notification immediately for new inbox item.
                                    if config.notifications.enabled {
                                        daemon_submit_inbox_item_trigger(
                                            &config,
                                            &mut notify_mgr,
                                            &item,
                                            now_secs,
                                        );
                                        let notifs = notify_mgr.flush(now_secs);
                                        for n in notifs {
                                            daemon_deliver_notification(&config, &n);
                                        }
                                    }
                                }
                            }
                            Err(err) => {
                                outcome.status =
                                    pt_core::daemon::escalation::EscalationStatus::Failed;
                                outcome.reason = err;
                            }
                        }
                    }

                    drop(lock);
                    outcome
                },
            );
            let _ = outcome;
            state_bundle
                .daemon
                .record_event(pt_core::daemon::DaemonEventType::TickCompleted, "tick");
        }

        // Persist notification escalation state.
        state_bundle.notifications = notify_mgr.persisted_state();
        let _ = save_daemon_state(&state_path, &state_bundle);

        if DAEMON_SIGNALS.should_stop() {
            break;
        }

        if daemon_sleep_with_interrupt(config.tick_interval_secs) {
            continue;
        }
    }

    cleanup_daemon_pid_if_owned(own_pid);

    let response = serde_json::json!({
        "command": "daemon start",
        "mode": "foreground",
        "ticks": state_bundle.daemon.tick_count,
        "base_dir": daemon_base_dir().display().to_string(),
    });
    match global.format {
        OutputFormat::Json | OutputFormat::Toon | OutputFormat::Jsonl => {
            println!("{}", format_structured_output(global, response));
        }
        _ => {
            println!(
                "Daemon stopped after {} ticks.",
                state_bundle.daemon.tick_count
            );
        }
    }

    ExitCode::Clean
}

#[cfg(feature = "daemon")]
fn daemon_now_secs() -> f64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

#[cfg(feature = "daemon")]
fn parse_rfc3339_secs(s: &str) -> Option<f64> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.timestamp_millis() as f64 / 1000.0)
}

#[cfg(feature = "daemon")]
fn inbox_item_dedupe_key(item: &pt_core::inbox::InboxItem) -> String {
    item.session_id.clone().unwrap_or_else(|| item.id.clone())
}

#[cfg(feature = "daemon")]
fn daemon_submit_inbox_item_trigger(
    config: &pt_core::daemon::DaemonConfig,
    notify_mgr: &mut pt_core::decision::escalation::EscalationManager,
    item: &pt_core::inbox::InboxItem,
    now_secs: f64,
) {
    use pt_core::decision::escalation::{EscalationTrigger, Severity, TriggerType};
    use pt_core::inbox::InboxItemType;

    // Only escalate on actionable daemon inbox items.
    if !matches!(
        item.item_type,
        InboxItemType::DormantEscalation | InboxItemType::LockContention
    ) {
        return;
    }

    let key = inbox_item_dedupe_key(item);
    let created_at = parse_rfc3339_secs(&item.created_at).unwrap_or(now_secs);
    let detected_at = if notify_mgr.has_key(&key) {
        now_secs
    } else {
        created_at
    };

    let candidates = item.candidates.unwrap_or(0);
    let severity = if item.item_type == InboxItemType::LockContention {
        Severity::Warning
    } else if candidates >= 10 {
        Severity::Critical
    } else if candidates >= 1 {
        Severity::Warning
    } else {
        Severity::Info
    };

    let summary = match (&item.review_command, &item.trigger) {
        (Some(cmd), Some(trig)) => format!("{} ({})\nReview: {}", item.summary, trig, cmd),
        (Some(cmd), None) => format!("{}\nReview: {}", item.summary, cmd),
        _ => item.summary.clone(),
    };

    notify_mgr.submit_trigger(EscalationTrigger {
        trigger_id: item.id.clone(),
        dedupe_key: key,
        trigger_type: TriggerType::HighRiskCandidates,
        severity,
        confidence: Some(0.95),
        summary,
        detected_at,
        session_id: item.session_id.clone(),
    });

    // Bound growth even if inbox is noisy.
    notify_mgr.prune(now_secs);

    // Config is currently embedded in the manager; this helper just ensures we
    // reference the config so future work doesn't silently drop it.
    let _ = &config.notification_ladder;
}

#[cfg(feature = "daemon")]
fn daemon_refresh_inbox_notifications(
    config: &pt_core::daemon::DaemonConfig,
    notify_mgr: &mut pt_core::decision::escalation::EscalationManager,
    store: &pt_core::inbox::InboxStore,
    now_secs: f64,
) {
    if !config.notifications.enabled {
        return;
    }

    let items = match store.list() {
        Ok(items) => items,
        Err(_) => return,
    };

    // Acknowledged items stop escalation.
    for item in &items {
        if item.acknowledged {
            notify_mgr.forget_key(&inbox_item_dedupe_key(item));
        }
    }

    for item in items.iter().filter(|i| !i.acknowledged) {
        daemon_submit_inbox_item_trigger(config, notify_mgr, item, now_secs);
    }

    let notifs = notify_mgr.flush(now_secs);
    for n in notifs {
        daemon_deliver_notification(config, &n);
    }
}

#[cfg(feature = "daemon")]
fn daemon_deliver_notification(
    config: &pt_core::daemon::DaemonConfig,
    notif: &pt_core::decision::escalation::Notification,
) {
    if !config.notifications.enabled {
        return;
    }

    if config.notifications.desktop
        && notif.channels.iter().any(|c| {
            matches!(
                c,
                pt_core::decision::escalation::NotificationChannel::Desktop
            )
        })
    {
        let _ = daemon_notify_desktop(notif);
    }

    if let Some(cmd) = config.notifications.notify_cmd.as_deref() {
        let _ = daemon_notify_cmd(cmd, &config.notifications.notify_arg, notif);
    }
}

#[cfg(feature = "daemon")]
fn daemon_notify_cmd(
    cmd: &str,
    args: &[String],
    notif: &pt_core::decision::escalation::Notification,
) -> std::io::Result<()> {
    use std::process::Command;

    let mut c = Command::new(cmd);
    c.args(args);
    c.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    c.env("PT_NOTIFY_LEVEL", format!("{:?}", notif.level));
    c.env("PT_NOTIFY_SEVERITY", format!("{:?}", notif.severity));
    c.env("PT_NOTIFY_TITLE", notif.title.clone());
    c.env("PT_NOTIFY_BODY", notif.body.clone());
    c.env("PT_NOTIFY_DEDUPE_KEY", notif.dedupe_key.clone());
    if let Some(session_id) = &notif.session_id {
        c.env("PT_NOTIFY_SESSION_ID", session_id.clone());
    }

    let _ = c.status();
    Ok(())
}

#[cfg(feature = "daemon")]
fn daemon_notify_desktop(
    notif: &pt_core::decision::escalation::Notification,
) -> std::io::Result<()> {
    use std::process::Command;

    #[cfg(target_os = "linux")]
    {
        let urgency = match notif.severity {
            pt_core::decision::escalation::Severity::Critical => "critical",
            pt_core::decision::escalation::Severity::Warning => "normal",
            pt_core::decision::escalation::Severity::Info => "low",
        };
        let _ = Command::new("notify-send")
            .args(["-u", urgency, "-a", "pt", &notif.title, &notif.body])
            .status();
        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        // Best-effort: avoid shell by passing a single osascript program string.
        let body = notif.body.replace('"', "\\\"");
        let title = notif.title.replace('"', "\\\"");
        let script = format!("display notification \"{}\" with title \"{}\"", body, title);
        let _ = Command::new("osascript").args(["-e", &script]).status();
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = notif;
        Ok(())
    }
}

#[cfg(feature = "daemon")]
fn run_daemon_stop(global: &GlobalOpts) -> ExitCode {
    let pid = match read_daemon_pid() {
        Ok(Some(pid)) => pid,
        Ok(None) => {
            let response = serde_json::json!({
                "command": "daemon stop",
                "running": false,
                "message": "no daemon pid file found",
            });
            match global.format {
                OutputFormat::Json | OutputFormat::Toon | OutputFormat::Jsonl => {
                    println!("{}", format_structured_output(global, response));
                }
                _ => {
                    println!("Daemon not running.");
                }
            }
            return ExitCode::Clean;
        }
        Err(err) => {
            eprintln!("daemon stop: failed to read pid file: {}", err);
            return ExitCode::IoError;
        }
    };

    if let Err(err) = terminate_process(pid) {
        eprintln!("daemon stop: failed to terminate daemon: {}", err);
        return ExitCode::IoError;
    }

    if let Err(err) = remove_daemon_pid() {
        eprintln!("daemon stop: failed to remove pid file: {}", err);
        return ExitCode::IoError;
    }

    let response = serde_json::json!({
        "command": "daemon stop",
        "running": false,
        "pid": pid,
    });
    match global.format {
        OutputFormat::Json | OutputFormat::Toon | OutputFormat::Jsonl => {
            println!("{}", format_structured_output(global, response));
        }
        _ => {
            println!("Daemon stopped (pid {}).", pid);
        }
    }

    ExitCode::Clean
}

#[cfg(feature = "daemon")]
fn run_daemon_status(global: &GlobalOpts) -> ExitCode {
    let pid = read_daemon_pid().ok().flatten();
    let running = pid.map(is_process_running).unwrap_or(false);
    let state_path = daemon_state_path();
    let state = if state_path.exists() {
        std::fs::read_to_string(&state_path)
            .ok()
            .and_then(|content| serde_json::from_str::<DaemonStateBundle>(&content).ok())
    } else {
        None
    };

    let response = serde_json::json!({
        "command": "daemon status",
        "running": running,
        "pid": pid,
        "base_dir": daemon_base_dir().display().to_string(),
        "state": state
            .as_ref()
            .and_then(|s| serde_json::to_value(s).ok()),
    });

    match global.format {
        OutputFormat::Json | OutputFormat::Toon | OutputFormat::Jsonl => {
            println!("{}", format_structured_output(global, response));
        }
        _ => {
            if running {
                println!("Daemon running (pid {}).", pid.unwrap_or(0));
            } else {
                println!("Daemon not running.");
            }
        }
    }

    ExitCode::Clean
}

fn run_telemetry(global: &GlobalOpts, _args: &TelemetryArgs) -> ExitCode {
    match &_args.command {
        TelemetryCommands::Status => run_telemetry_status(global, _args),
        TelemetryCommands::Prune {
            keep,
            dry_run,
            keep_everything,
        } => run_telemetry_prune(global, _args, keep, *dry_run, *keep_everything),
        TelemetryCommands::Export { .. } => {
            output_stub(global, "telemetry export", "Export not yet implemented");
            ExitCode::Clean
        }
        TelemetryCommands::Redact { .. } => {
            output_stub(global, "telemetry redact", "Redaction not yet implemented");
            ExitCode::Clean
        }
    }
}

fn resolve_telemetry_dir(args: &TelemetryArgs) -> PathBuf {
    args.telemetry_dir
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(default_telemetry_dir)
}

fn resolve_config_dir(global: &GlobalOpts) -> PathBuf {
    if let Some(dir) = &global.config {
        return PathBuf::from(dir);
    }

    if let Ok(dir) = std::env::var("PROCESS_TRIAGE_CONFIG") {
        return PathBuf::from(dir);
    }

    let xdg_config = std::env::var("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".config")
        });

    xdg_config.join("process_triage")
}

fn load_retention_config(
    global: &GlobalOpts,
    args: &TelemetryArgs,
    telemetry_dir: &Path,
) -> Result<RetentionConfig, RetentionError> {
    let config_path = if let Some(path) = &args.retention_config {
        Some(PathBuf::from(path))
    } else {
        let config_dir = resolve_config_dir(global);
        let candidate = config_dir.join("telemetry_retention.json");
        if candidate.exists() {
            Some(candidate)
        } else {
            None
        }
    };

    let mut config = if let Some(path) = &config_path {
        let raw = std::fs::read_to_string(path)?;
        let value: serde_json::Value = serde_json::from_str(&raw)?;
        parse_retention_config_value(value)?
    } else {
        RetentionConfig::default()
    };

    config.validate()?;

    if config.event_log_dir.is_none() {
        config.event_log_dir = Some(telemetry_dir.join("retention_logs"));
    }

    Ok(config)
}

fn parse_retention_config_value(
    value: serde_json::Value,
) -> Result<RetentionConfig, RetentionError> {
    if let Some(obj) = value.get("telemetry_retention") {
        let Some(map) = obj.as_object() else {
            return Err(RetentionError::InvalidConfig(
                "telemetry_retention must be an object".to_string(),
            ));
        };

        let mut config = RetentionConfig::default();

        let mut set_days = |key: &str, table: &str| {
            if let Some(days) = map.get(key).and_then(|v| v.as_u64()) {
                config.ttl_days.insert(table.to_string(), days as u32);
            }
        };

        set_days("runs_days", "runs");
        set_days("proc_samples_days", "proc_samples");
        set_days("proc_features_days", "proc_features");
        set_days("proc_inference_days", "proc_inference");
        set_days("outcomes_days", "outcomes");
        set_days("audit_days", "audit");
        set_days("signature_matches_days", "signature_matches");

        if let Some(max_disk_gb) = map.get("max_disk_gb").and_then(|v| v.as_f64()) {
            if max_disk_gb >= 0.0 {
                config.disk_budget_bytes = (max_disk_gb * 1024.0 * 1024.0 * 1024.0).round() as u64;
            }
        }

        if let Some(keep) = map.get("keep_everything").and_then(|v| v.as_bool()) {
            config.keep_everything = keep;
        }

        return Ok(config);
    }

    serde_json::from_value(value).map_err(RetentionError::Json)
}

fn apply_global_ttl_override(config: &mut RetentionConfig, ttl_days: u32) {
    let tables = [
        "runs",
        "proc_samples",
        "proc_features",
        "proc_inference",
        "outcomes",
        "audit",
        "signature_matches",
    ];
    for table in tables {
        config.ttl_days.insert(table.to_string(), ttl_days);
    }
}

fn run_telemetry_status(global: &GlobalOpts, args: &TelemetryArgs) -> ExitCode {
    let telemetry_dir = resolve_telemetry_dir(args);
    let config = match load_retention_config(global, args, &telemetry_dir) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("telemetry status: {}", err);
            return ExitCode::IoError;
        }
    };

    let enforcer = RetentionEnforcer::new(telemetry_dir.clone(), config);
    let status = match enforcer.status() {
        Ok(status) => status,
        Err(err) => {
            eprintln!("telemetry status: {}", err);
            return ExitCode::IoError;
        }
    };

    match global.format {
        OutputFormat::Json | OutputFormat::Toon => {
            let output = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "command": "telemetry status",
                "status": status,
            });
            println!("{}", format_structured_output(global, output));
        }
        OutputFormat::Jsonl => {
            let output = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "command": "telemetry status",
                "status": status,
            });
            println!("{}", serde_json::to_string(&output).unwrap_or_default());
        }
        _ => {
            println!("Telemetry directory: {}", status.root_dir);
            println!(
                "Total usage: {} in {} files",
                format_bytes(status.total_bytes),
                status.total_files
            );
            if status.disk_budget_bytes > 0 {
                println!(
                    "Disk budget: {} ({:.1}% used)",
                    format_bytes(status.disk_budget_bytes),
                    status.budget_used_pct
                );
            }
            println!(
                "TTL-eligible: {} files ({} bytes)",
                status.ttl_eligible_files,
                format_bytes(status.ttl_eligible_bytes)
            );
            println!();
            println!("Per-table:");
            for (table, table_status) in status.by_table.iter() {
                println!(
                    "  {:<16} files={:<4} size={:<8} ttl={}d over_ttl={}",
                    table,
                    table_status.file_count,
                    format_bytes(table_status.total_bytes),
                    table_status.ttl_days,
                    table_status.over_ttl_count
                );
            }
        }
    }

    ExitCode::Clean
}

fn run_telemetry_prune(
    global: &GlobalOpts,
    args: &TelemetryArgs,
    keep: &str,
    dry_run: bool,
    keep_everything: bool,
) -> ExitCode {
    let telemetry_dir = resolve_telemetry_dir(args);
    let mut config = match load_retention_config(global, args, &telemetry_dir) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("telemetry prune: {}", err);
            return ExitCode::IoError;
        }
    };

    if keep_everything {
        config.keep_everything = true;
    } else if let Some(duration) = parse_duration(keep) {
        let days = duration.num_days();
        if days <= 0 {
            eprintln!("telemetry prune: keep must be at least 1 day");
            return ExitCode::ArgsError;
        }
        apply_global_ttl_override(&mut config, days as u32);
    } else {
        eprintln!("telemetry prune: invalid keep value '{}'", keep);
        return ExitCode::ArgsError;
    }

    let mut enforcer = RetentionEnforcer::new(telemetry_dir.clone(), config);
    let events = if dry_run {
        match enforcer.dry_run() {
            Ok(events) => events,
            Err(err) => {
                eprintln!("telemetry prune: {}", err);
                return ExitCode::IoError;
            }
        }
    } else {
        match enforcer.enforce() {
            Ok(events) => events,
            Err(err) => {
                eprintln!("telemetry prune: {}", err);
                return ExitCode::IoError;
            }
        }
    };

    let freed_bytes: u64 = events.iter().map(|e| e.size_bytes).sum();
    let event_count = events.len();

    match global.format {
        OutputFormat::Json | OutputFormat::Toon => {
            let output = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "command": "telemetry prune",
                "dry_run": dry_run,
                "event_count": event_count,
                "freed_bytes": freed_bytes,
                "events": events,
            });
            println!("{}", format_structured_output(global, output));
        }
        OutputFormat::Jsonl => {
            let output = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "command": "telemetry prune",
                "dry_run": dry_run,
                "event_count": event_count,
                "freed_bytes": freed_bytes,
                "events": events,
            });
            println!("{}", serde_json::to_string(&output).unwrap_or_default());
        }
        _ => {
            if dry_run {
                println!("Dry-run retention: {} file(s) eligible.", event_count);
            } else {
                println!("Pruned {} file(s).", event_count);
            }
            println!(
                "Bytes {}: {}",
                if dry_run { "eligible" } else { "freed" },
                format_bytes(freed_bytes)
            );
            for event in &events {
                println!(
                    "  {} ({}) [{:?}]",
                    event.file_path,
                    format_bytes(event.size_bytes),
                    event.reason
                );
            }
        }
    }

    ExitCode::Clean
}

#[derive(Debug)]
struct ShadowSignalState {
    stop: AtomicBool,
    reload: AtomicBool,
    force_scan: AtomicBool,
}

impl ShadowSignalState {
    const fn new() -> Self {
        Self {
            stop: AtomicBool::new(false),
            reload: AtomicBool::new(false),
            force_scan: AtomicBool::new(false),
        }
    }

    fn request_stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    fn should_stop(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    fn request_reload(&self) {
        self.reload.store(true, Ordering::Relaxed);
    }

    fn take_reload(&self) -> bool {
        self.reload.swap(false, Ordering::Relaxed)
    }

    fn request_force_scan(&self) {
        self.force_scan.store(true, Ordering::Relaxed);
    }

    fn take_force_scan(&self) -> bool {
        self.force_scan.swap(false, Ordering::Relaxed)
    }
}

static SHADOW_SIGNALS: ShadowSignalState = ShadowSignalState::new();

#[cfg(unix)]
fn install_shadow_signal_handlers() {
    unsafe extern "C" fn handler(signal: i32) {
        match signal {
            libc::SIGTERM | libc::SIGINT => SHADOW_SIGNALS.request_stop(),
            libc::SIGHUP => {
                SHADOW_SIGNALS.request_reload();
                SHADOW_SIGNALS.request_force_scan();
            }
            libc::SIGUSR1 => SHADOW_SIGNALS.request_force_scan(),
            _ => {}
        }
    }

    unsafe {
        let handler_ptr = handler as *const () as libc::sighandler_t;
        libc::signal(libc::SIGTERM, handler_ptr);
        libc::signal(libc::SIGINT, handler_ptr);
        libc::signal(libc::SIGHUP, handler_ptr);
        libc::signal(libc::SIGUSR1, handler_ptr);
    }
}

#[cfg(not(unix))]
fn install_shadow_signal_handlers() {}

fn run_shadow(global: &GlobalOpts, args: &ShadowArgs) -> ExitCode {
    match &args.command {
        ShadowCommands::Start(start) => run_shadow_start(global, start),
        ShadowCommands::Run(start) => run_shadow_run(global, start),
        ShadowCommands::Stop => run_shadow_stop(global),
        ShadowCommands::Status => run_shadow_status(global),
        ShadowCommands::Export(export) => run_shadow_export(global, export),
        ShadowCommands::Report(report) => run_shadow_report(global, report),
    }
}

fn run_shadow_start(global: &GlobalOpts, args: &ShadowStartArgs) -> ExitCode {
    if args.background {
        return run_shadow_background(global, args);
    }
    run_shadow_run(global, args)
}

fn run_shadow_background(global: &GlobalOpts, args: &ShadowStartArgs) -> ExitCode {
    if let Ok(Some(pid)) = read_shadow_pid() {
        if is_process_running(pid) {
            eprintln!(
                "shadow start: existing shadow observer running (pid {})",
                pid
            );
            return ExitCode::LockError;
        }
        let _ = remove_shadow_pid();
    }

    let exe = match std::env::current_exe() {
        Ok(path) => path,
        Err(err) => {
            eprintln!("shadow start: failed to resolve executable: {}", err);
            return ExitCode::InternalError;
        }
    };

    let mut cmd = std::process::Command::new(exe);
    cmd.arg("shadow").arg("run");
    apply_shadow_start_args(&mut cmd, args);
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    let child = match cmd.spawn() {
        Ok(child) => child,
        Err(err) => {
            eprintln!("shadow start: failed to spawn background worker: {}", err);
            return ExitCode::IoError;
        }
    };

    if let Err(err) = write_shadow_pid(child.id()) {
        eprintln!("shadow start: failed to write pid file: {}", err);
        return ExitCode::IoError;
    }

    let response = serde_json::json!({
        "command": "shadow start",
        "mode": "background",
        "pid": child.id(),
        "base_dir": shadow_base_dir().display().to_string(),
    });

    match global.format {
        OutputFormat::Json | OutputFormat::Toon | OutputFormat::Jsonl => {
            println!("{}", format_structured_output(global, response));
        }
        _ => {
            println!("Shadow observer started (pid {}).", child.id());
        }
    }

    ExitCode::Clean
}

fn run_shadow_run(global: &GlobalOpts, args: &ShadowStartArgs) -> ExitCode {
    install_shadow_signal_handlers();
    let own_pid = std::process::id();

    let mut iterations = args.iterations;
    let mut run_count: u32 = 0;
    let mut next_deep_at = if args.deep || args.deep_interval == 0 {
        None
    } else {
        Some(std::time::Instant::now() + std::time::Duration::from_secs(args.deep_interval))
    };

    loop {
        if SHADOW_SIGNALS.should_stop() {
            break;
        }

        if SHADOW_SIGNALS.take_reload() {
            SHADOW_SIGNALS.request_force_scan();
        }

        let now = std::time::Instant::now();
        let mut force_deep = args.deep;
        if !force_deep {
            if let Some(deadline) = next_deep_at {
                if now >= deadline {
                    force_deep = true;
                    next_deep_at = Some(now + std::time::Duration::from_secs(args.deep_interval));
                }
            }
        }

        run_count = run_count.saturating_add(1);
        match run_shadow_iteration(args, force_deep) {
            Ok(status) => {
                if !status.success() {
                    eprintln!(
                        "shadow run: iteration {} failed (exit={})",
                        run_count,
                        status.code().unwrap_or(-1)
                    );
                }
            }
            Err(err) => {
                eprintln!("shadow run: iteration {} failed: {}", run_count, err);
            }
        }

        if iterations > 0 {
            iterations = iterations.saturating_sub(1);
            if iterations == 0 {
                break;
            }
        }

        if SHADOW_SIGNALS.should_stop() {
            break;
        }

        if SHADOW_SIGNALS.take_force_scan() {
            continue;
        }

        if shadow_sleep_with_interrupt(args.interval) {
            continue;
        }
    }

    cleanup_shadow_pid_if_owned(own_pid);

    let response = serde_json::json!({
        "command": "shadow run",
        "iterations": run_count,
        "interval_seconds": args.interval,
        "base_dir": shadow_base_dir().display().to_string(),
    });

    match global.format {
        OutputFormat::Json | OutputFormat::Toon | OutputFormat::Jsonl => {
            println!("{}", format_structured_output(global, response));
        }
        _ => {
            println!("Shadow run complete ({} iterations).", run_count);
        }
    }

    ExitCode::Clean
}

fn run_shadow_iteration(
    args: &ShadowStartArgs,
    force_deep: bool,
) -> Result<std::process::ExitStatus, std::io::Error> {
    let exe = std::env::current_exe()?;

    let mut cmd = std::process::Command::new(exe);
    cmd.arg("--shadow")
        .arg("--format")
        .arg("json")
        .arg("agent")
        .arg("plan");
    apply_shadow_plan_args(&mut cmd, args, force_deep);

    cmd.status()
}

fn run_shadow_stop(global: &GlobalOpts) -> ExitCode {
    let pid = match read_shadow_pid() {
        Ok(Some(pid)) => pid,
        Ok(None) => {
            let response = serde_json::json!({
                "command": "shadow stop",
                "running": false,
                "message": "no shadow pid file found",
            });
            match global.format {
                OutputFormat::Json | OutputFormat::Toon | OutputFormat::Jsonl => {
                    println!("{}", format_structured_output(global, response));
                }
                _ => {
                    println!("No shadow observer pid file found.");
                }
            }
            return ExitCode::Clean;
        }
        Err(err) => {
            eprintln!("shadow stop: failed to read pid file: {}", err);
            return ExitCode::IoError;
        }
    };

    if let Err(err) = terminate_process(pid) {
        eprintln!("shadow stop: failed to signal pid {}: {}", pid, err);
        return ExitCode::IoError;
    }

    if let Err(err) = remove_shadow_pid() {
        eprintln!("shadow stop: failed to remove pid file: {}", err);
    }

    let response = serde_json::json!({
        "command": "shadow stop",
        "pid": pid,
        "signaled": true,
    });
    match global.format {
        OutputFormat::Json | OutputFormat::Toon | OutputFormat::Jsonl => {
            println!("{}", format_structured_output(global, response));
        }
        _ => {
            println!("Shadow observer stopped (pid {}).", pid);
        }
    }

    ExitCode::Clean
}

fn run_shadow_status(global: &GlobalOpts) -> ExitCode {
    let pid = read_shadow_pid().ok().flatten();
    let running = pid.map(is_process_running).unwrap_or(false);
    let stale = pid.is_some() && !running;

    let config = ShadowStorageConfig {
        base_dir: shadow_base_dir(),
        ..Default::default()
    };
    let storage = ShadowStorage::new(config);

    let stats_json = match storage {
        Ok(storage) => serde_json::to_value(storage.stats()).unwrap_or_default(),
        Err(_) => serde_json::json!({}),
    };

    let response = serde_json::json!({
        "command": "shadow status",
        "running": running,
        "pid": pid,
        "stale_pid_file": stale,
        "base_dir": shadow_base_dir().display().to_string(),
        "stats": stats_json,
    });

    match global.format {
        OutputFormat::Json | OutputFormat::Toon | OutputFormat::Jsonl => {
            println!("{}", format_structured_output(global, response));
        }
        _ => {
            if running {
                println!("Shadow observer running (pid {}).", pid.unwrap_or(0));
            } else {
                println!("Shadow observer not running.");
            }
            if stale {
                println!("Warning: stale pid file detected.");
            }
        }
    }

    ExitCode::Clean
}

fn run_shadow_export(global: &GlobalOpts, args: &ShadowExportArgs) -> ExitCode {
    let base_dir = shadow_base_dir();
    let observations = match collect_shadow_observations(&base_dir, args.limit) {
        Ok(observations) => observations,
        Err(err) => {
            eprintln!("shadow export: {}", err);
            return ExitCode::IoError;
        }
    };

    let output = match args.export_format.as_str() {
        "jsonl" => observations
            .iter()
            .map(|obs| serde_json::to_string(obs).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("\n"),
        _ => serde_json::to_string_pretty(&observations).unwrap_or_default(),
    };

    let wrote_file = if let Some(ref path) = args.output {
        if let Err(err) = std::fs::write(path, output) {
            eprintln!("shadow export: failed to write {}: {}", path, err);
            return ExitCode::IoError;
        }
        true
    } else {
        println!("{}", output);
        false
    };

    if wrote_file {
        let response = serde_json::json!({
            "command": "shadow export",
            "count": observations.len(),
            "base_dir": base_dir.display().to_string(),
            "output": args.output,
        });
        match global.format {
            OutputFormat::Json | OutputFormat::Toon | OutputFormat::Jsonl => {
                println!("{}", format_structured_output(global, response));
            }
            _ => {
                println!("Exported {} observations.", observations.len());
            }
        }
    }

    ExitCode::Clean
}

fn run_shadow_report(global: &GlobalOpts, args: &ShadowReportArgs) -> ExitCode {
    let base_dir = shadow_base_dir();
    let observations = match collect_shadow_observations(&base_dir, args.limit) {
        Ok(observations) => observations,
        Err(err) => {
            eprintln!("shadow report: {}", err);
            return ExitCode::IoError;
        }
    };

    if observations.is_empty() {
        eprintln!("shadow report: no observations found");
        return ExitCode::Clean;
    }

    let engine = ValidationEngine::from_shadow_observations(&observations, args.threshold);

    let is_structured = matches!(
        global.format,
        OutputFormat::Json | OutputFormat::Toon | OutputFormat::Jsonl
    );

    if is_structured {
        let report = match engine.compute_report() {
            Ok(report) => report,
            Err(err) => {
                eprintln!("shadow report: {}", err);
                return ExitCode::InternalError;
            }
        };
        let report_value = serde_json::to_value(&report).unwrap_or_default();
        let report_output = match global.format {
            OutputFormat::Jsonl => serde_json::to_string(&report_value).unwrap_or_default(),
            _ => format_structured_output(global, report_value),
        };

        let wrote_file = if let Some(ref path) = args.output {
            if let Err(err) = std::fs::write(path, &report_output) {
                eprintln!("shadow report: failed to write {}: {}", path, err);
                return ExitCode::IoError;
            }
            true
        } else {
            println!("{}", report_output);
            false
        };

        if wrote_file {
            let response = serde_json::json!({
                "command": "shadow report",
                "count": observations.len(),
                "threshold": args.threshold,
                "base_dir": base_dir.display().to_string(),
                "output": args.output,
            });
            match global.format {
                OutputFormat::Json | OutputFormat::Toon | OutputFormat::Jsonl => {
                    println!("{}", format_structured_output(global, response));
                }
                _ => {
                    println!("Report generated for {} observations.", observations.len());
                }
            }
        }

        return ExitCode::Clean;
    }

    let report = match engine.calibration_report() {
        Ok(report) => report,
        Err(CalibrationError::InsufficientData {
            count,
            min_required,
        }) => {
            println!(
                "Calibration report requires at least {} resolved observations (found {}).",
                min_required, count
            );
            return ExitCode::Clean;
        }
        Err(CalibrationError::NoData) => {
            println!("Calibration report requires resolved observations.");
            return ExitCode::Clean;
        }
        Err(err) => {
            eprintln!("shadow report: {}", err);
            return ExitCode::InternalError;
        }
    };

    let ascii_report = report.ascii_report(60, 14);

    let wrote_file = if let Some(ref path) = args.output {
        if let Err(err) = std::fs::write(path, &ascii_report) {
            eprintln!("shadow report: failed to write {}: {}", path, err);
            return ExitCode::IoError;
        }
        true
    } else {
        println!("{}", ascii_report);
        false
    };

    if wrote_file {
        println!("Report generated for {} observations.", observations.len());
    }

    ExitCode::Clean
}

fn apply_shadow_start_args(cmd: &mut std::process::Command, args: &ShadowStartArgs) {
    if args.interval != 300 {
        cmd.arg("--interval").arg(args.interval.to_string());
    }
    if args.deep_interval != 3600 {
        cmd.arg("--deep-interval")
            .arg(args.deep_interval.to_string());
    }
    if args.iterations != 0 {
        cmd.arg("--iterations").arg(args.iterations.to_string());
    }
    if args.max_candidates != 20 {
        cmd.arg("--max-candidates")
            .arg(args.max_candidates.to_string());
    }
    if (args.min_posterior - 0.7).abs() > f64::EPSILON {
        cmd.arg("--min-posterior")
            .arg(args.min_posterior.to_string());
    }
    if args.only != "all" {
        cmd.arg("--only").arg(&args.only);
    }
    if args.include_kernel_threads {
        cmd.arg("--include-kernel-threads");
    }
    if args.deep {
        cmd.arg("--deep");
    }
    if let Some(min_age) = args.min_age {
        cmd.arg("--min-age").arg(min_age.to_string());
    }
    if let Some(sample_size) = args.sample_size {
        cmd.arg("--sample-size").arg(sample_size.to_string());
    }
}

fn apply_shadow_plan_args(
    cmd: &mut std::process::Command,
    args: &ShadowStartArgs,
    force_deep: bool,
) {
    cmd.arg("--max-candidates")
        .arg(args.max_candidates.to_string());
    cmd.arg("--min-posterior")
        .arg(args.min_posterior.to_string());
    cmd.arg("--only").arg(&args.only);
    if args.include_kernel_threads {
        cmd.arg("--include-kernel-threads");
    }
    if args.deep || force_deep {
        cmd.arg("--deep");
    }
    if let Some(min_age) = args.min_age {
        cmd.arg("--min-age").arg(min_age.to_string());
    }
    if let Some(sample_size) = args.sample_size {
        cmd.arg("--sample-size").arg(sample_size.to_string());
    }
}

fn shadow_sleep_with_interrupt(seconds: u64) -> bool {
    if seconds == 0 {
        return false;
    }
    let mut remaining = seconds;
    while remaining > 0 {
        if SHADOW_SIGNALS.should_stop() {
            return false;
        }
        if SHADOW_SIGNALS.take_force_scan() {
            return true;
        }
        let step = remaining.min(1);
        std::thread::sleep(std::time::Duration::from_secs(step));
        remaining = remaining.saturating_sub(step);
    }
    false
}

fn cleanup_shadow_pid_if_owned(pid: u32) {
    if let Ok(Some(current)) = read_shadow_pid() {
        if current == pid {
            let _ = remove_shadow_pid();
        }
    }
}

fn shadow_base_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("PROCESS_TRIAGE_DATA") {
        return PathBuf::from(dir).join("shadow");
    }
    if let Ok(dir) = std::env::var("XDG_DATA_HOME") {
        return PathBuf::from(dir).join("process_triage").join("shadow");
    }
    ShadowStorageConfig::default().base_dir
}

fn shadow_pid_path() -> PathBuf {
    shadow_base_dir().join("shadow.pid")
}

fn write_shadow_pid(pid: u32) -> std::io::Result<()> {
    let path = shadow_pid_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, pid.to_string())
}

fn read_shadow_pid() -> std::io::Result<Option<u32>> {
    let path = shadow_pid_path();
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(path)?;
    Ok(content.trim().parse::<u32>().ok())
}

fn remove_shadow_pid() -> std::io::Result<()> {
    let path = shadow_pid_path();
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

// ============================================================================
// Global run lock (daemon vs manual/agent coordination)
// ============================================================================

/// Resolve the data directory for global lock placement.
fn resolve_data_dir_for_lock() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("PROCESS_TRIAGE_DATA") {
        return Some(PathBuf::from(dir));
    }
    if let Ok(dir) = std::env::var("XDG_DATA_HOME") {
        return Some(PathBuf::from(dir).join("process_triage"));
    }
    dirs::data_dir().map(|dir| dir.join("process_triage"))
}

/// Global lock path shared by daemon + manual/agent runs.
fn global_lock_path() -> Option<PathBuf> {
    resolve_data_dir_for_lock().map(|dir| dir.join(".pt-lock"))
}

struct GlobalLock {
    file: std::fs::File,
}

impl GlobalLock {
    fn try_acquire(path: &Path) -> Result<Option<Self>, std::io::Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;

        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = file.as_raw_fd();
            let result = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
            if result != 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::WouldBlock {
                    return Ok(None);
                }
                return Err(err);
            }
        }

        file.set_len(0)?;
        let mut writer = &file;
        let _ = writer.write_all(format!("{}", std::process::id()).as_bytes());
        let _ = writer.flush();

        Ok(Some(Self { file }))
    }
}

impl Drop for GlobalLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            unsafe {
                libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
}

fn acquire_global_lock(global: &GlobalOpts, command: &str) -> Result<Option<GlobalLock>, ExitCode> {
    if std::env::var("PT_SKIP_GLOBAL_LOCK").is_ok() {
        return Ok(None);
    }
    let path = match global_lock_path() {
        Some(path) => path,
        None => return Ok(None),
    };

    match GlobalLock::try_acquire(&path) {
        Ok(Some(lock)) => Ok(Some(lock)),
        Ok(None) => {
            let response = serde_json::json!({
                "command": command,
                "error": "lock contention",
                "lock_path": path.display().to_string(),
            });
            match global.format {
                OutputFormat::Json | OutputFormat::Toon | OutputFormat::Jsonl => {
                    println!("{}", format_structured_output(global, response));
                }
                _ => {
                    eprintln!("{}: lock held at {}", command, path.display());
                }
            }
            Err(ExitCode::LockError)
        }
        Err(err) => {
            let response = serde_json::json!({
                "command": command,
                "error": format!("lock error: {}", err),
                "lock_path": path.display().to_string(),
            });
            match global.format {
                OutputFormat::Json | OutputFormat::Toon | OutputFormat::Jsonl => {
                    eprintln!("{}", format_structured_output(global, response));
                }
                _ => {
                    eprintln!("{}: lock error at {}: {}", command, path.display(), err);
                }
            }
            Err(ExitCode::IoError)
        }
    }
}

// ============================================================================
// Daemon helpers
// ============================================================================

#[cfg(feature = "daemon")]
#[derive(Debug)]
struct DaemonSignalState {
    stop: AtomicBool,
    reload: AtomicBool,
    force_tick: AtomicBool,
}

#[cfg(feature = "daemon")]
impl DaemonSignalState {
    const fn new() -> Self {
        Self {
            stop: AtomicBool::new(false),
            reload: AtomicBool::new(false),
            force_tick: AtomicBool::new(false),
        }
    }

    fn request_stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    fn should_stop(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    fn request_reload(&self) {
        self.reload.store(true, Ordering::Relaxed);
    }

    fn take_reload(&self) -> bool {
        self.reload.swap(false, Ordering::Relaxed)
    }

    fn request_force_tick(&self) {
        self.force_tick.store(true, Ordering::Relaxed);
    }

    fn take_force_tick(&self) -> bool {
        self.force_tick.swap(false, Ordering::Relaxed)
    }
}

#[cfg(feature = "daemon")]
static DAEMON_SIGNALS: DaemonSignalState = DaemonSignalState::new();

#[cfg(feature = "daemon")]
#[cfg(unix)]
fn install_daemon_signal_handlers() {
    unsafe extern "C" fn handler(signal: i32) {
        match signal {
            libc::SIGTERM | libc::SIGINT => DAEMON_SIGNALS.request_stop(),
            libc::SIGHUP => {
                DAEMON_SIGNALS.request_reload();
                DAEMON_SIGNALS.request_force_tick();
            }
            libc::SIGUSR1 => DAEMON_SIGNALS.request_force_tick(),
            _ => {}
        }
    }

    unsafe {
        let handler_ptr = handler as *const () as libc::sighandler_t;
        libc::signal(libc::SIGTERM, handler_ptr);
        libc::signal(libc::SIGINT, handler_ptr);
        libc::signal(libc::SIGHUP, handler_ptr);
        libc::signal(libc::SIGUSR1, handler_ptr);
    }
}

#[cfg(feature = "daemon")]
#[cfg(not(unix))]
fn install_daemon_signal_handlers() {}

#[cfg(feature = "daemon")]
fn daemon_sleep_with_interrupt(seconds: u64) -> bool {
    if seconds == 0 {
        return false;
    }
    let mut remaining = seconds;
    while remaining > 0 {
        if DAEMON_SIGNALS.should_stop() {
            return false;
        }
        if DAEMON_SIGNALS.take_force_tick() {
            return true;
        }
        let step = remaining.min(1);
        std::thread::sleep(std::time::Duration::from_secs(step));
        remaining = remaining.saturating_sub(step);
    }
    false
}

#[cfg(feature = "daemon")]
fn daemon_base_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("PROCESS_TRIAGE_DATA") {
        return PathBuf::from(dir).join("daemon");
    }
    if let Ok(dir) = std::env::var("XDG_DATA_HOME") {
        return PathBuf::from(dir).join("process_triage").join("daemon");
    }
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("process_triage")
        .join("daemon")
}

#[cfg(feature = "daemon")]
fn daemon_pid_path() -> PathBuf {
    daemon_base_dir().join("daemon.pid")
}

#[cfg(feature = "daemon")]
fn daemon_state_path() -> PathBuf {
    daemon_base_dir().join("state.json")
}

#[cfg(feature = "daemon")]
fn daemon_lock_path() -> PathBuf {
    daemon_base_dir().join("pt.lock")
}

#[cfg(feature = "daemon")]
fn write_daemon_pid(pid: u32) -> std::io::Result<()> {
    let path = daemon_pid_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, pid.to_string())
}

#[cfg(feature = "daemon")]
fn read_daemon_pid() -> std::io::Result<Option<u32>> {
    let path = daemon_pid_path();
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(path)?;
    Ok(content.trim().parse::<u32>().ok())
}

#[cfg(feature = "daemon")]
fn remove_daemon_pid() -> std::io::Result<()> {
    let path = daemon_pid_path();
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

#[cfg(feature = "daemon")]
fn cleanup_daemon_pid_if_owned(pid: u32) {
    if let Ok(Some(current)) = read_daemon_pid() {
        if current == pid {
            let _ = remove_daemon_pid();
        }
    }
}

#[cfg(feature = "daemon")]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DaemonStateBundle {
    daemon: pt_core::daemon::DaemonState,
    triggers: pt_core::daemon::triggers::TriggerState,
    escalation: pt_core::daemon::escalation::EscalationState,
    #[serde(default)]
    notifications: pt_core::decision::escalation::PersistedEscalationState,
}

#[cfg(feature = "daemon")]
fn load_daemon_state(path: &Path, config: &pt_core::daemon::DaemonConfig) -> DaemonStateBundle {
    if let Ok(content) = std::fs::read_to_string(path) {
        if let Ok(state) = serde_json::from_str::<DaemonStateBundle>(&content) {
            return state;
        }
    }

    DaemonStateBundle {
        daemon: pt_core::daemon::DaemonState::new(),
        triggers: pt_core::daemon::triggers::TriggerState::new(&config.triggers),
        escalation: pt_core::daemon::escalation::EscalationState::new(),
        notifications: pt_core::decision::escalation::PersistedEscalationState::default(),
    }
}

#[cfg(feature = "daemon")]
fn save_daemon_state(path: &Path, state: &DaemonStateBundle) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("json.tmp");
    let content = serde_json::to_vec_pretty(state)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(&tmp, content)?;
    std::fs::rename(tmp, path)?;
    Ok(())
}

#[cfg(feature = "daemon")]
struct DaemonEscalationResult {
    session_id: String,
    candidates_found: u32,
}

#[cfg(feature = "daemon")]
fn run_daemon_escalation(
    global: &GlobalOpts,
    _triggers: &[pt_core::daemon::triggers::FiredTrigger],
    esc_config: &pt_core::daemon::escalation::EscalationConfig,
) -> Result<DaemonEscalationResult, String> {
    let quick = run_daemon_plan(global, None, false, esc_config.max_deep_scan_targets)?;
    if quick.candidates_found == 0 {
        return Ok(quick);
    }

    match run_daemon_plan(
        global,
        Some(&quick.session_id),
        true,
        esc_config.max_deep_scan_targets,
    ) {
        Ok(deep) => Ok(deep),
        Err(err) => {
            eprintln!(
                "daemon escalation: deep plan failed, using quick plan: {}",
                err
            );
            Ok(quick)
        }
    }
}

#[cfg(feature = "daemon")]
fn run_daemon_plan(
    global: &GlobalOpts,
    session_id: Option<&str>,
    deep: bool,
    max_candidates: u32,
) -> Result<DaemonEscalationResult, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut cmd = std::process::Command::new(exe);
    cmd.args(["--format", "json", "agent", "plan", "--max-candidates"])
        .arg(max_candidates.to_string());
    if deep {
        cmd.arg("--deep");
    }
    if let Some(session) = session_id {
        cmd.arg("--session").arg(session);
    }
    cmd.stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .env("PT_SKIP_GLOBAL_LOCK", "1");

    apply_daemon_global_args(&mut cmd, global);

    let output = cmd.output().map_err(|e| e.to_string())?;
    let stdout = output.stdout;
    if stdout.is_empty() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "daemon escalation: empty stdout (status {:?}): {}",
            output.status.code(),
            stderr.trim()
        ));
    }

    let json: serde_json::Value =
        serde_json::from_slice(&stdout).map_err(|e| format!("invalid JSON: {}", e))?;
    let session_id = json
        .get("session_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing session_id in plan output".to_string())?
        .to_string();
    let candidates_found = json
        .get("summary")
        .and_then(|s| s.get("candidates_found"))
        .and_then(|v| v.as_u64())
        .or_else(|| {
            json.get("candidates")
                .and_then(|v| v.as_array())
                .map(|a| a.len() as u64)
        })
        .unwrap_or(0) as u32;

    Ok(DaemonEscalationResult {
        session_id,
        candidates_found,
    })
}

#[cfg(feature = "daemon")]
fn collect_daemon_metrics() -> pt_core::daemon::TickMetrics {
    let load = collect_load_averages();
    let load_avg_1 = load.first().copied().unwrap_or(0.0);
    let load_avg_5 = load.get(1).copied().unwrap_or(load_avg_1);

    let memory = collect_memory_info();
    let total_gb = memory
        .get("total_gb")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let used_gb = memory
        .get("used_gb")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let memory_total_mb = (total_gb * 1024.0).round() as u64;
    let memory_used_mb = (used_gb * 1024.0).round() as u64;

    pt_core::daemon::TickMetrics {
        timestamp: chrono::Utc::now().to_rfc3339(),
        load_avg_1,
        load_avg_5,
        memory_used_mb,
        memory_total_mb,
        swap_used_mb: collect_swap_used_mb(),
        process_count: collect_process_count(),
        orphan_count: collect_orphan_count(),
    }
}

#[cfg(feature = "daemon")]
fn collect_swap_used_mb() -> u64 {
    let content = match std::fs::read_to_string("/proc/meminfo") {
        Ok(c) => c,
        Err(_) => return 0,
    };
    let mut total = 0u64;
    let mut free = 0u64;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("SwapTotal:") {
            total = rest
                .split_whitespace()
                .next()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("SwapFree:") {
            free = rest
                .split_whitespace()
                .next()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
        }
    }
    total.saturating_sub(free) / 1024
}

#[cfg(all(feature = "daemon", target_os = "linux"))]
fn collect_orphan_count() -> u32 {
    let mut count = 0u32;
    let entries = match std::fs::read_dir("/proc") {
        Ok(entries) => entries,
        Err(_) => return 0,
    };

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let pid_str = match file_name.to_str() {
            Some(name) if name.chars().all(|c| c.is_ascii_digit()) => name,
            _ => continue,
        };
        let stat_path = format!("/proc/{}/stat", pid_str);
        let stat = match std::fs::read_to_string(stat_path) {
            Ok(stat) => stat,
            Err(_) => continue,
        };
        let end = match stat.rfind(')') {
            Some(pos) => pos,
            None => continue,
        };
        let rest = match stat.get(end + 2..) {
            Some(rest) => rest,
            None => continue,
        };
        let mut parts = rest.split_whitespace();
        let _state = parts.next();
        let ppid = match parts.next() {
            Some(ppid) => ppid,
            None => continue,
        };
        if ppid == "1" {
            count = count.saturating_add(1);
        }
    }

    count
}

#[cfg(all(feature = "daemon", target_os = "linux"))]
fn current_rss_mb() -> Option<u64> {
    let stats = pt_core::collect::parse_statm(std::process::id())?;
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        return None;
    }
    let rss_bytes = stats.resident.saturating_mul(page_size as u64);
    Some(rss_bytes / 1024 / 1024)
}

#[cfg(all(feature = "daemon", not(target_os = "linux")))]
fn collect_orphan_count() -> u32 {
    0
}

#[cfg(all(feature = "daemon", not(target_os = "linux")))]
fn current_rss_mb() -> Option<u64> {
    None
}

#[cfg(all(feature = "daemon", unix))]
fn current_cpu_seconds() -> Option<f64> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    let result = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    if result != 0 {
        return None;
    }
    let usage = unsafe { usage.assume_init() };
    let user = usage.ru_utime.tv_sec as f64 + (usage.ru_utime.tv_usec as f64 / 1_000_000.0);
    let system = usage.ru_stime.tv_sec as f64 + (usage.ru_stime.tv_usec as f64 / 1_000_000.0);
    Some(user + system)
}

#[cfg(all(feature = "daemon", not(unix)))]
fn current_cpu_seconds() -> Option<f64> {
    None
}

#[cfg(feature = "daemon")]
fn apply_daemon_global_args(cmd: &mut std::process::Command, global: &GlobalOpts) {
    if let Some(dir) = &global.config {
        cmd.arg("--config").arg(dir);
    }
}

#[cfg(feature = "daemon")]
fn apply_daemon_nice() {
    #[cfg(unix)]
    unsafe {
        libc::setpriority(libc::PRIO_PROCESS, 0, 19);
    }

    #[cfg(unix)]
    {
        let _ = std::process::Command::new("ionice")
            .args(["-c3", "-p", &std::process::id().to_string()])
            .status();
    }
}

#[cfg(feature = "daemon")]
fn load_daemon_config(global: &GlobalOpts) -> (pt_core::daemon::DaemonConfig, bool) {
    let config_dir = resolve_config_dir(global);
    let path = config_dir.join("daemon.json");
    if !path.exists() {
        return (pt_core::daemon::DaemonConfig::default(), true);
    }

    let content = match std::fs::read_to_string(&path) {
        Ok(content) => content,
        Err(_) => return (pt_core::daemon::DaemonConfig::default(), true),
    };

    if let Ok(config) = serde_json::from_str::<pt_core::daemon::DaemonConfig>(&content) {
        return (config, true);
    }

    #[derive(Deserialize)]
    struct DaemonFileConfig {
        enabled: Option<bool>,
        collection_interval_seconds: Option<u64>,
        overhead_budget: Option<DaemonBudget>,
        triggers: Option<DaemonTriggerConfig>,
        auto_mitigate: Option<DaemonAutoMitigate>,
        cooldown: Option<DaemonCooldown>,
    }

    #[derive(Deserialize)]
    struct DaemonBudget {
        max_cpu_percent: Option<f64>,
        max_memory_mb: Option<u64>,
    }

    #[derive(Deserialize)]
    struct DaemonTriggerConfig {
        sustained_load: Option<DaemonLoadTrigger>,
        memory_pressure: Option<DaemonMemoryTrigger>,
        orphan_spike: Option<DaemonOrphanTrigger>,
    }

    #[derive(Deserialize)]
    struct DaemonLoadTrigger {
        threshold_multiplier: Option<f64>,
        min_duration_seconds: Option<u64>,
    }

    #[derive(Deserialize)]
    struct DaemonMemoryTrigger {
        threshold_percent: Option<f64>,
        min_duration_seconds: Option<u64>,
    }

    #[derive(Deserialize)]
    struct DaemonOrphanTrigger {
        threshold_delta: Option<u32>,
        window_seconds: Option<u64>,
    }

    #[derive(Deserialize)]
    struct DaemonAutoMitigate {
        enabled: Option<bool>,
    }

    #[derive(Deserialize)]
    struct DaemonCooldown {
        after_escalation_seconds: Option<u64>,
    }

    let mut config = pt_core::daemon::DaemonConfig::default();
    let mut enabled = true;

    if let Ok(file_cfg) = serde_json::from_str::<DaemonFileConfig>(&content) {
        if let Some(value) = file_cfg.enabled {
            enabled = value;
        }
        if let Some(interval) = file_cfg.collection_interval_seconds {
            config.tick_interval_secs = interval;
        }
        if let Some(budget) = file_cfg.overhead_budget {
            if let Some(cpu) = budget.max_cpu_percent {
                config.max_cpu_percent = cpu;
            }
            if let Some(mem) = budget.max_memory_mb {
                config.max_rss_mb = mem;
            }
        }
        if let Some(triggers) = file_cfg.triggers {
            if let Some(load) = triggers.sustained_load {
                if let Some(multiplier) = load.threshold_multiplier {
                    let cores = collect_cpu_count().max(1) as f64;
                    config.triggers.load_threshold = cores * multiplier;
                }
                if let Some(seconds) = load.min_duration_seconds {
                    let ticks = (seconds / config.tick_interval_secs.max(1)).max(1) as u32;
                    config.triggers.sustained_ticks = ticks;
                }
            }
            if let Some(mem) = triggers.memory_pressure {
                if let Some(percent) = mem.threshold_percent {
                    config.triggers.memory_threshold = (percent / 100.0).clamp(0.0, 1.0);
                }
                if let Some(seconds) = mem.min_duration_seconds {
                    let ticks = (seconds / config.tick_interval_secs.max(1)).max(1) as u32;
                    config.triggers.sustained_ticks = config.triggers.sustained_ticks.max(ticks);
                }
            }
            if let Some(orphan) = triggers.orphan_spike {
                if let Some(delta) = orphan.threshold_delta {
                    config.triggers.orphan_threshold = delta;
                }
                if let Some(seconds) = orphan.window_seconds {
                    let ticks = (seconds / config.tick_interval_secs.max(1)).max(1) as u32;
                    config.triggers.sustained_ticks = config.triggers.sustained_ticks.max(ticks);
                }
            }
        }
        if let Some(auto) = file_cfg.auto_mitigate {
            if let Some(enabled) = auto.enabled {
                config.escalation.allow_auto_mitigation = enabled;
            }
        }
        if let Some(cooldown) = file_cfg.cooldown {
            if let Some(seconds) = cooldown.after_escalation_seconds {
                config.escalation.min_interval_secs = seconds;
            }
        }
    }

    (config, enabled)
}

#[cfg(unix)]
fn terminate_process(pid: u32) -> std::io::Result<()> {
    let result = unsafe { libc::kill(pid as i32, libc::SIGTERM) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(unix))]
fn terminate_process(_pid: u32) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "terminate not supported on this platform",
    ))
}

#[cfg(unix)]
fn is_process_running(pid: u32) -> bool {
    let result = unsafe { libc::kill(pid as i32, 0) };
    result == 0 || std::io::Error::last_os_error().kind() == std::io::ErrorKind::PermissionDenied
}

#[cfg(not(unix))]
fn is_process_running(_pid: u32) -> bool {
    false
}

#[derive(Debug)]
enum ShadowExportError {
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl std::fmt::Display for ShadowExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShadowExportError::Io(err) => write!(f, "I/O error: {}", err),
            ShadowExportError::Json(err) => write!(f, "JSON error: {}", err),
        }
    }
}

impl From<std::io::Error> for ShadowExportError {
    fn from(err: std::io::Error) -> Self {
        ShadowExportError::Io(err)
    }
}

impl From<serde_json::Error> for ShadowExportError {
    fn from(err: serde_json::Error) -> Self {
        ShadowExportError::Json(err)
    }
}

fn collect_shadow_observations(
    base_dir: &PathBuf,
    limit: Option<usize>,
) -> Result<Vec<Observation>, ShadowExportError> {
    let mut files = Vec::new();
    collect_shadow_files(base_dir, &mut files)?;

    let mut observations: Vec<Observation> = Vec::new();
    for path in files {
        let content = std::fs::read_to_string(&path)?;
        let mut batch: Vec<Observation> = serde_json::from_str(&content)?;
        observations.append(&mut batch);
    }

    observations.sort_by_key(|b| std::cmp::Reverse(b.timestamp));
    if let Some(max) = limit {
        observations.truncate(max);
    }
    observations.sort_by_key(|a| a.timestamp);

    Ok(observations)
}

fn collect_shadow_files(dir: &PathBuf, files: &mut Vec<PathBuf>) -> std::io::Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_shadow_files(&path, files)?;
        } else if path.is_file() {
            if path.file_name().and_then(|s| s.to_str()) == Some("stats.json") {
                continue;
            }
            if path.file_name().and_then(|s| s.to_str()) == Some("pending.json") {
                continue;
            }
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                files.push(path);
            }
        }
    }
    Ok(())
}

fn run_mcp(args: &McpArgs) -> ExitCode {
    if args.transport != "stdio" {
        eprintln!("Only 'stdio' transport is currently supported");
        return ExitCode::ArgsError;
    }

    let mut server = pt_core::mcp::McpServer::new();
    if let Err(e) = server.run_stdio() {
        eprintln!("MCP server error: {}", e);
        return ExitCode::IoError;
    }
    ExitCode::Clean
}

fn run_schema(global: &GlobalOpts, args: &SchemaArgs) -> ExitCode {
    use pt_core::schema::{
        available_schemas, format_schema, generate_all_schemas, generate_schema, SchemaFormat,
    };

    let format = if args.compact {
        SchemaFormat::JsonCompact
    } else {
        SchemaFormat::Json
    };

    // List available types
    if args.list {
        match global.format {
            OutputFormat::Json | OutputFormat::Toon => {
                let types: Vec<_> = available_schemas()
                    .into_iter()
                    .map(|(name, desc)| serde_json::json!({"name": name, "description": desc}))
                    .collect();
                let types_value = serde_json::Value::Array(types);
                println!("{}", format_structured_output(global, types_value));
            }
            OutputFormat::Jsonl => {
                for (name, desc) in available_schemas() {
                    let entry = serde_json::json!({"name": name, "description": desc});
                    println!("{}", serde_json::to_string(&entry).unwrap());
                }
            }
            _ => {
                println!("Available schema types:\n");
                for (name, desc) in available_schemas() {
                    println!("  {:<25} {}", name, desc);
                }
                println!("\nUse 'pt schema <TYPE>' to generate a schema.");
            }
        }
        return ExitCode::Clean;
    }

    // Generate all schemas
    if args.all {
        let schemas = generate_all_schemas();
        match global.format {
            OutputFormat::Json | OutputFormat::Toon => {
                let schemas_value = serde_json::to_value(&schemas).unwrap_or_default();
                println!("{}", format_structured_output(global, schemas_value));
            }
            OutputFormat::Jsonl => {
                for (name, schema) in schemas {
                    let entry = serde_json::json!({"type": name, "schema": schema});
                    println!("{}", serde_json::to_string(&entry).unwrap());
                }
            }
            _ => {
                // Human-readable: output each schema separately
                for (name, schema) in schemas {
                    println!("# {}\n", name);
                    println!("{}\n", format_schema(&schema, format));
                }
            }
        }
        return ExitCode::Clean;
    }

    // Generate schema for a specific type
    if let Some(ref type_name) = args.type_name {
        match generate_schema(type_name) {
            Some(schema) => {
                match global.format {
                    OutputFormat::Jsonl => {
                        println!("{}", serde_json::to_string(&schema).unwrap());
                    }
                    _ => {
                        println!("{}", format_schema(&schema, format));
                    }
                }
                ExitCode::Clean
            }
            None => {
                eprintln!("Unknown type: {}", type_name);
                eprintln!("\nUse 'pt schema --list' to see available types.");
                ExitCode::PartialFail
            }
        }
    } else {
        eprintln!("Usage: pt schema <TYPE> | --list | --all");
        eprintln!("\nUse 'pt schema --list' to see available types.");
        ExitCode::PartialFail
    }
}

fn print_version(global: &GlobalOpts) {
    let version_info = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "pt_core_version": env!("CARGO_PKG_VERSION"),
        "rust_version": env!("CARGO_PKG_RUST_VERSION"),
    });

    match global.format {
        OutputFormat::Json | OutputFormat::Toon => {
            println!("{}", format_structured_output(global, version_info));
        }
        OutputFormat::Exitcode => {}
        _ => {
            println!("pt-core {}", env!("CARGO_PKG_VERSION"));
            println!("schema version: {}", SCHEMA_VERSION);
        }
    }
}

fn output_stub(global: &GlobalOpts, command: &str, message: &str) {
    let session_id = SessionId::new();

    output_stub_with_session(global, &session_id, command, message);
}

fn output_stub_with_session(
    global: &GlobalOpts,
    session_id: &SessionId,
    command: &str,
    message: &str,
) {
    match global.format {
        OutputFormat::Json | OutputFormat::Toon => {
            let output = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "session_id": session_id.0,
                "generated_at": chrono::Utc::now().to_rfc3339(),
                "command": command,
                "status": "stub",
                "message": message
            });
            println!("{}", format_structured_output(global, output));
        }
        OutputFormat::Summary => {
            println!("[{}] {}: {}", session_id, command, message);
        }
        OutputFormat::Exitcode => {}
        _ => {
            println!("# pt-core {}", command);
            println!();
            println!("{}", message);
            println!();
            println!("Session: {}", session_id);
        }
    }
}

fn run_agent_capabilities(global: &GlobalOpts, args: &AgentCapabilitiesArgs) -> ExitCode {
    // If --check-action is specified, just check that specific action
    if let Some(action) = &args.check_action {
        let caps = get_capabilities();
        let (supported, reason) = match action.to_lowercase().as_str() {
            "sigterm" | "terminate" | "term" => (true, "SIGTERM always available"),
            "sigkill" | "kill" => (true, "SIGKILL always available"),
            "sigstop" | "stop" => (true, "SIGSTOP always available"),
            "sigcont" | "cont" | "continue" => (true, "SIGCONT always available"),
            "strace" => (
                caps.tools.strace.available && caps.tools.strace.works,
                if caps.tools.strace.available {
                    "strace available"
                } else {
                    "strace not installed"
                },
            ),
            "perf" => (
                caps.tools.perf.available && caps.tools.perf.works,
                if caps.tools.perf.available {
                    "perf available"
                } else {
                    "perf not installed"
                },
            ),
            "lsof" => (
                caps.tools.lsof.available && caps.tools.lsof.works,
                if caps.tools.lsof.available {
                    "lsof available"
                } else {
                    "lsof not installed"
                },
            ),
            "nice" | "renice" => (
                caps.tools.renice.available,
                if caps.tools.renice.available {
                    "renice available"
                } else {
                    "renice not installed"
                },
            ),
            "ionice" => (
                caps.tools.ionice.available,
                if caps.tools.ionice.available {
                    "ionice available"
                } else {
                    "ionice not installed"
                },
            ),
            "cgroup" | "cgroups" => (
                caps.data_sources.cgroup_v2,
                if caps.data_sources.cgroup_v2 {
                    "cgroups v2 available"
                } else {
                    "cgroups v2 not available"
                },
            ),
            "docker" => (
                caps.tools.docker.available,
                if caps.tools.docker.available {
                    "docker available"
                } else {
                    "docker not installed"
                },
            ),
            "podman" => (
                caps.tools.podman.available,
                if caps.tools.podman.available {
                    "podman available"
                } else {
                    "podman not installed"
                },
            ),
            "sudo" => (
                caps.permissions.can_sudo,
                if caps.permissions.can_sudo {
                    "sudo available"
                } else {
                    "cannot sudo"
                },
            ),
            "root" => (
                caps.permissions.is_root,
                if caps.permissions.is_root {
                    "running as root"
                } else {
                    "not running as root"
                },
            ),
            _ => (false, "unknown action type"),
        };

        match global.format {
            OutputFormat::Json | OutputFormat::Toon => {
                let output = serde_json::json!({
                    "action": action,
                    "supported": supported,
                    "reason": reason,
                });
                println!("{}", format_structured_output(global, output));
            }
            OutputFormat::Summary => {
                if supported {
                    println!("[capabilities] {}: supported", action);
                } else {
                    println!("[capabilities] {}: not supported ({})", action, reason);
                }
            }
            OutputFormat::Exitcode => {}
            _ => {
                if supported {
                    println!("Action '{}' is supported: {}", action, reason);
                } else {
                    println!("Action '{}' is NOT supported: {}", action, reason);
                }
            }
        }

        return if supported {
            ExitCode::Clean
        } else {
            ExitCode::CapabilityError
        };
    }

    // Otherwise, output full capabilities
    output_capabilities(global);
    ExitCode::Clean
}

fn output_capabilities(global: &GlobalOpts) {
    let session_id = SessionId::new();

    // Detect actual system capabilities (get_capabilities handles cache internally)
    let caps = get_capabilities();

    // Build tools map for output
    let mut tools_output = serde_json::Map::new();
    let tool_list: [(&str, &ToolCapability); 14] = [
        ("ps", &caps.tools.ps),
        ("lsof", &caps.tools.lsof),
        ("ss", &caps.tools.ss),
        ("netstat", &caps.tools.netstat),
        ("perf", &caps.tools.perf),
        ("strace", &caps.tools.strace),
        ("dtrace", &caps.tools.dtrace),
        ("bpftrace", &caps.tools.bpftrace),
        ("systemctl", &caps.tools.systemctl),
        ("docker", &caps.tools.docker),
        ("podman", &caps.tools.podman),
        ("nice", &caps.tools.nice),
        ("renice", &caps.tools.renice),
        ("ionice", &caps.tools.ionice),
    ];
    for (name, tool) in tool_list {
        let mut tool_info = serde_json::Map::new();
        tool_info.insert(
            "available".to_string(),
            serde_json::Value::Bool(tool.available),
        );
        if let Some(ref v) = tool.version {
            tool_info.insert("version".to_string(), serde_json::Value::String(v.clone()));
        }
        if let Some(ref p) = tool.path {
            tool_info.insert("path".to_string(), serde_json::Value::String(p.clone()));
        }
        tool_info.insert("works".to_string(), serde_json::Value::Bool(tool.works));
        if !tool.available {
            tool_info.insert(
                "reason".to_string(),
                serde_json::Value::String(
                    tool.error.clone().unwrap_or_else(|| "not installed".into()),
                ),
            );
        }
        tools_output.insert(name.to_string(), serde_json::Value::Object(tool_info));
    }

    let capabilities_json = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "session_id": session_id.0,
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "os": {
            "family": caps.platform.os,
            "arch": caps.platform.arch,
            "kernel": caps.platform.kernel_release,
            "in_container": caps.platform.in_container,
            "container_runtime": caps.platform.container_runtime,
        },
        "tools": tools_output,
        "permissions": {
            "effective_uid": caps.permissions.effective_uid,
            "is_root": caps.permissions.is_root,
            "can_sudo": caps.permissions.can_sudo,
            "can_read_others_procs": caps.permissions.can_read_others_procs,
            "can_signal_others": caps.permissions.can_signal_others,
            "linux_capabilities": caps.permissions.linux_capabilities,
        },
        "data_sources": {
            "procfs": caps.data_sources.procfs,
            "sysfs": caps.data_sources.sysfs,
            "perf_events": caps.data_sources.perf_events,
            "ebpf": caps.data_sources.ebpf,
            "schedstat": caps.data_sources.schedstat,
            "cgroup_v1": caps.data_sources.cgroup_v1,
            "cgroup_v2": caps.data_sources.cgroup_v2,
        },
        "supervisors": {
            "systemd": caps.supervisors.systemd,
            "launchd": caps.supervisors.launchd,
            "pm2": caps.supervisors.pm2,
            "supervisord": caps.supervisors.supervisord,
            "docker_daemon": caps.supervisors.docker_daemon,
            "podman": caps.supervisors.podman_available,
            "kubernetes": caps.supervisors.kubernetes,
        },
        "actions": {
            "kill": caps.actions.kill,
            "pause": caps.actions.pause,
            "renice": caps.actions.renice,
            "ionice": caps.actions.ionice,
            "cgroup_freeze": caps.actions.cgroup_freeze,
            "cgroup_throttle": caps.actions.cgroup_throttle,
            "cpuset_quarantine": caps.actions.cpuset_quarantine,
        },
        "features": {
            "deep_scan": caps.can_deep_scan(),
            "maximal_scan": caps.can_maximal_scan(),
        },
        "detected_at": caps.detected_at,
    });

    match global.format {
        OutputFormat::Json | OutputFormat::Toon => {
            println!("{}", format_structured_output(global, capabilities_json));
        }
        OutputFormat::Exitcode => {}
        _ => {
            println!("# Capabilities");
            println!();
            println!("## Platform");
            println!(
                "OS: {} ({}) kernel: {}",
                caps.platform.os,
                caps.platform.arch,
                caps.platform.kernel_release.as_deref().unwrap_or("unknown")
            );
            if caps.platform.in_container {
                println!(
                    "Container: {} ({})",
                    caps.platform.in_container,
                    caps.platform
                        .container_runtime
                        .as_deref()
                        .unwrap_or("unknown")
                );
            }
            println!();
            println!("## Permissions");
            println!(
                "UID: {} (root: {})",
                caps.permissions.effective_uid, caps.permissions.is_root
            );
            println!("Sudo: {}", caps.permissions.can_sudo);
            println!("Read others: {}", caps.permissions.can_read_others_procs);
            println!("Signal others: {}", caps.permissions.can_signal_others);
            println!();
            println!(
                "## Tools ({}/{} available)",
                caps.tools.available_count(),
                caps.tools.total_count()
            );
            for (name, tool) in [
                ("ps", &caps.tools.ps),
                ("lsof", &caps.tools.lsof),
                ("perf", &caps.tools.perf),
                ("strace", &caps.tools.strace),
                ("bpftrace", &caps.tools.bpftrace),
            ] {
                let status = if tool.works {
                    format!("ok ({})", tool.version.as_deref().unwrap_or("?"))
                } else if tool.available {
                    "broken".to_string()
                } else {
                    "not found".to_string()
                };
                println!("  {}: {}", name, status);
            }
            println!();
            println!(
                "## Actions ({}/{} available)",
                caps.actions.available_count(),
                caps.actions.total_count()
            );
            println!(
                "  kill: {}, pause: {}, renice: {}",
                caps.actions.kill, caps.actions.pause, caps.actions.renice
            );
            println!(
                "  cgroup_freeze: {}, cgroup_throttle: {}",
                caps.actions.cgroup_freeze, caps.actions.cgroup_throttle
            );
            println!();
            println!("## Features");
            println!("  deep_scan: {}", caps.can_deep_scan());
            println!("  maximal_scan: {}", caps.can_maximal_scan());
        }
    }
}

// ============================================================================
// System State Collection
// ============================================================================

/// Collect system state for snapshot output.
fn collect_system_state() -> serde_json::Value {
    let load = collect_load_averages();
    let cores = collect_cpu_count();
    let memory = collect_memory_info();
    let process_count = collect_process_count();
    let psi = collect_psi();

    serde_json::json!({
        "load": load,
        "cores": cores,
        "memory": memory,
        "process_count": process_count,
        "psi": psi,
    })
}

/// Read /proc/loadavg and return [1min, 5min, 15min].
fn collect_load_averages() -> Vec<f64> {
    std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|content| {
            let parts: Vec<&str> = content.split_whitespace().collect();
            if parts.len() >= 3 {
                let load1 = parts[0].parse::<f64>().ok()?;
                let load5 = parts[1].parse::<f64>().ok()?;
                let load15 = parts[2].parse::<f64>().ok()?;
                Some(vec![load1, load5, load15])
            } else {
                None
            }
        })
        .unwrap_or_default()
}

/// Get CPU count from /proc/cpuinfo or nproc.
fn collect_cpu_count() -> u32 {
    // Try reading from /proc/cpuinfo
    if let Ok(content) = std::fs::read_to_string("/proc/cpuinfo") {
        let count = content
            .lines()
            .filter(|line| line.starts_with("processor"))
            .count();
        if count > 0 {
            return count as u32;
        }
    }
    // Fallback to nproc command
    std::process::Command::new("nproc")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok()?.trim().parse().ok())
        .unwrap_or(1)
}

/// Read /proc/meminfo and return memory stats in GB.
fn collect_memory_info() -> serde_json::Value {
    let (total_kb, available_kb) = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .map(|content| {
            let mut total: u64 = 0;
            let mut available: u64 = 0;
            for line in content.lines() {
                if let Some(rest) = line.strip_prefix("MemTotal:") {
                    total = rest
                        .split_whitespace()
                        .next()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);
                } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
                    available = rest
                        .split_whitespace()
                        .next()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);
                }
            }
            (total, available)
        })
        .unwrap_or((0, 0));

    let total_gb = (total_kb as f64) / 1024.0 / 1024.0;
    let available_gb = (available_kb as f64) / 1024.0 / 1024.0;
    let used_gb = total_gb - available_gb;

    serde_json::json!({
        "total_gb": (total_gb * 10.0).round() / 10.0,
        "used_gb": (used_gb * 10.0).round() / 10.0,
        "available_gb": (available_gb * 10.0).round() / 10.0,
    })
}

/// Count process directories in /proc.
fn collect_process_count() -> u32 {
    std::fs::read_dir("/proc")
        .ok()
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| {
                    e.file_name()
                        .to_str()
                        .map(|s| s.chars().all(|c| c.is_ascii_digit()))
                        .unwrap_or(false)
                })
                .count() as u32
        })
        .unwrap_or(0)
}

/// Read PSI (Pressure Stall Information) from /proc/pressure/.
fn collect_psi() -> serde_json::Value {
    fn read_psi_file(resource: &str) -> Option<f64> {
        let path = format!("/proc/pressure/{}", resource);
        std::fs::read_to_string(&path).ok().and_then(|content| {
            // Parse "some avg10=X.XX avg60=Y.YY avg300=Z.ZZ total=N"
            // We want avg10 for recent pressure
            for line in content.lines() {
                if line.starts_with("some") {
                    for part in line.split_whitespace() {
                        if let Some(val) = part.strip_prefix("avg10=") {
                            return val.parse().ok();
                        }
                    }
                }
            }
            None
        })
    }

    serde_json::json!({
        "cpu": read_psi_file("cpu").unwrap_or(0.0),
        "memory": read_psi_file("memory").unwrap_or(0.0),
        "io": read_psi_file("io").unwrap_or(0.0),
    })
}

/// Get the system hostname.
fn collect_hostname() -> String {
    // Try /etc/hostname first
    if let Ok(hostname) = std::fs::read_to_string("/etc/hostname") {
        let hostname = hostname.trim();
        if !hostname.is_empty() {
            return hostname.to_string();
        }
    }
    // Fallback to HOSTNAME env var
    if let Ok(hostname) = std::env::var("HOSTNAME") {
        return hostname;
    }
    // Last resort: use gethostname
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Collect host information in the structured format for JSON output.
fn collect_host_info() -> serde_json::Value {
    let hostname = collect_hostname();
    let cores = collect_cpu_count();
    let memory = collect_memory_info();
    let load = collect_load_averages();

    let total_gb = memory
        .get("total_gb")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let used_gb = memory
        .get("used_gb")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);

    serde_json::json!({
        "hostname": hostname,
        "cores": cores,
        "memory_total_gb": total_gb,
        "memory_used_gb": used_gb,
        "load_avg": load,
    })
}

/// Format duration in human-readable form (e.g., "11d 2h 30m").
fn format_duration_human(seconds: u64) -> String {
    let days = seconds / 86400;
    let hours = (seconds % 86400) / 3600;
    let minutes = (seconds % 3600) / 60;

    if days > 0 {
        format!("{}d {}h {}m", days, hours, minutes)
    } else if hours > 0 {
        format!("{}h {}m", hours, minutes)
    } else {
        format!("{}m", minutes)
    }
}

fn parse_prediction_fields(spec: &str) -> Result<PredictionFieldSelector, String> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Err("prediction fields cannot be empty".to_string());
    }

    let mut include = Vec::new();
    for raw in spec.split(',') {
        let field = raw.trim().to_lowercase();
        if field.is_empty() {
            continue;
        }
        let parsed = match field.as_str() {
            "memory" => PredictionField::Memory,
            "cpu" => PredictionField::Cpu,
            "eta_abandoned" => PredictionField::EtaAbandoned,
            "eta_resource_limit" => PredictionField::EtaResourceLimit,
            "trajectory" => PredictionField::Trajectory,
            "diagnostics" => PredictionField::Diagnostics,
            _ => return Err(format!("unknown prediction field: {}", field)),
        };
        if !include.contains(&parsed) {
            include.push(parsed);
        }
    }

    if include.is_empty() {
        return Err("prediction fields cannot be empty".to_string());
    }

    Ok(PredictionFieldSelector { include })
}

fn build_stub_predictions(proc: &ProcessRecord) -> Predictions {
    let window_secs = proc.elapsed.as_secs_f64().max(0.0);
    Predictions {
        memory: Some(MemoryPrediction {
            rss_slope_bytes_per_sec: 0.0,
            trend: Trend::Stable,
            confidence: 0.0,
            window_secs,
        }),
        cpu: Some(CpuPrediction {
            usage_slope_pct_per_sec: 0.0,
            trend: Trend::Stable,
            confidence: 0.0,
            window_secs,
        }),
        eta_abandoned: None,
        eta_resource_limit: None,
        trajectory: Some(TrajectoryAssessment {
            label: TrajectoryLabel::Unknown,
            confidence: 0.0,
            summary: "insufficient history for trajectory prediction".to_string(),
        }),
        diagnostics: Some(PredictionDiagnostics {
            n_observations: 1,
            calibrated: false,
            model: "snapshot".to_string(),
            warnings: vec!["insufficient_history".to_string()],
        }),
    }
}

#[cfg(feature = "ui")]
fn format_memory_human(bytes: u64) -> String {
    let mb = bytes as f64 / 1024.0 / 1024.0;
    if mb >= 1024.0 {
        format!("{:.1}GB", mb / 1024.0)
    } else if mb >= 10.0 {
        format!("{:.0}MB", mb)
    } else {
        format!("{:.1}MB", mb)
    }
}

/// Generate a single-line rationale for a candidate process.
/// Used by --brief mode to provide context without verbosity.
fn generate_single_line_rationale(candidate: &serde_json::Value) -> String {
    let classification = candidate
        .get("classification")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let age_human = candidate
        .get("age_human")
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    let score = candidate.get("score").and_then(|v| v.as_u64()).unwrap_or(0);
    let memory_mb = candidate
        .get("memory_mb")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let cpu_pct = candidate
        .get("cpu_percent")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);

    // Extract top evidence factor if available
    let top_factor = candidate
        .get("evidence")
        .and_then(|e| e.as_array())
        .and_then(|arr| arr.first())
        .and_then(|f| f.get("factor"))
        .and_then(|v| v.as_str())
        .unwrap_or("inference");

    // Build concise rationale
    if cpu_pct < 0.1 && memory_mb > 100 {
        format!(
            "{} for {} ({}% conf), idle+{}MB, {}",
            classification, age_human, score, memory_mb, top_factor
        )
    } else if cpu_pct < 0.1 {
        format!(
            "{} for {} ({}% conf), idle, {}",
            classification, age_human, score, top_factor
        )
    } else {
        format!(
            "{} for {} ({}% conf), {:.1}% CPU, {}",
            classification, age_human, score, cpu_pct, top_factor
        )
    }
}

/// Generate a human-readable narrative summary of the plan.
/// Used by --narrative mode for human consumption.
fn generate_narrative_summary(
    session_id: &pt_common::SessionId,
    candidates: &[serde_json::Value],
    kill_candidates: &[u32],
    review_candidates: &[u32],
    total_scanned: usize,
    expected_memory_freed_gb: f64,
) -> String {
    let mut output = String::new();

    // Header
    output.push_str(&format!(
        "Process Triage Report (Session: {})\n",
        session_id
    ));
    output.push_str(&"=".repeat(50));
    output.push('\n');
    output.push('\n');

    // Executive summary
    if candidates.is_empty() {
        output.push_str("No problematic processes detected. Your system looks healthy.\n");
        return output;
    }

    output.push_str(&format!(
        "Scanned {} processes and identified {} candidates for review.\n\n",
        total_scanned,
        candidates.len()
    ));

    // Recommendations summary
    if !kill_candidates.is_empty() {
        output.push_str(&format!(
            "KILL RECOMMENDED: {} process{} ({:.2} GB memory recoverable)\n",
            kill_candidates.len(),
            if kill_candidates.len() == 1 { "" } else { "es" },
            expected_memory_freed_gb
        ));
    }
    if !review_candidates.is_empty() {
        output.push_str(&format!(
            "REVIEW SUGGESTED: {} process{}\n",
            review_candidates.len(),
            if review_candidates.len() == 1 {
                ""
            } else {
                "es"
            }
        ));
    }
    output.push('\n');

    // Detailed candidate breakdown
    output.push_str("Candidate Details:\n");
    output.push_str(&"-".repeat(40));
    output.push('\n');

    for (i, candidate) in candidates.iter().enumerate() {
        let pid = candidate.get("pid").and_then(|v| v.as_u64()).unwrap_or(0);
        let cmd = candidate
            .get("command_short")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        let age_human = candidate
            .get("age_human")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        let classification = candidate
            .get("classification")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        let score = candidate.get("score").and_then(|v| v.as_u64()).unwrap_or(0);
        let recommendation = candidate
            .get("recommendation")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        let memory_mb = candidate
            .get("memory_mb")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        output.push_str(&format!(
            "\n{}. PID {} - {} ({})\n",
            i + 1,
            pid,
            cmd,
            classification
        ));
        output.push_str(&format!(
            "   Age: {}, Memory: {} MB\n",
            age_human, memory_mb
        ));
        output.push_str(&format!(
            "   Confidence: {}%, Recommendation: {}\n",
            score, recommendation
        ));

        // Top evidence factors
        if let Some(evidence) = candidate.get("evidence").and_then(|e| e.as_array()) {
            let top_factors: Vec<&str> = evidence
                .iter()
                .take(3)
                .filter_map(|f| f.get("factor").and_then(|v| v.as_str()))
                .collect();
            if !top_factors.is_empty() {
                output.push_str(&format!("   Key factors: {}\n", top_factors.join(", ")));
            }
        }
    }

    output.push('\n');
    output.push_str(&"-".repeat(40));
    output.push('\n');
    output.push_str("Use 'pt agent apply --session <id>' to execute recommendations.\n");

    output
}

fn run_agent_snapshot(global: &GlobalOpts, args: &AgentSnapshotArgs) -> ExitCode {
    let session_id = SessionId::new();

    let store = match SessionStore::from_env() {
        Ok(store) => store,
        Err(e) => {
            eprintln!("agent snapshot: session store error: {}", e);
            return ExitCode::InternalError;
        }
    };

    let manifest = SessionManifest::new(
        &session_id,
        None,
        SessionMode::RobotPlan,
        args.label.clone(),
    );
    let handle = match store.create(&manifest) {
        Ok(handle) => handle,
        Err(e) => {
            eprintln!("agent snapshot: failed to create session: {}", e);
            return ExitCode::InternalError;
        }
    };

    let ctx = SessionContext::new(
        &session_id,
        pt_core::logging::get_host_id(),
        pt_core::logging::generate_run_id(),
        args.label.clone(),
    );
    if let Err(e) = handle.write_context(&ctx) {
        eprintln!("agent snapshot: failed to write context.json: {}", e);
        return ExitCode::InternalError;
    }

    if let Some(path) = &global.capabilities {
        match std::fs::read_to_string(path) {
            Ok(content) => {
                if let Err(e) = handle.write_capabilities_json(&content) {
                    eprintln!("agent snapshot: failed to write capabilities.json: {}", e);
                    return ExitCode::InternalError;
                }
            }
            Err(e) => {
                eprintln!(
                    "agent snapshot: failed to read capabilities manifest {}: {}",
                    path, e
                );
                return ExitCode::InternalError;
            }
        }
    }

    // Collect system state and capabilities
    let system_state = collect_system_state();
    let caps = get_capabilities();
    let host_id = pt_core::logging::get_host_id();
    let timestamp = chrono::Utc::now();

    // Perform a quick scan once. We use it both for user-facing snapshot output (optional)
    // and for persisting diff artifacts (inventory + inference) so `pt diff` can work.
    let scan_options = QuickScanOptions {
        pids: vec![],
        include_kernel_threads: false,
        timeout: global.timeout.map(std::time::Duration::from_secs),
        progress: None,
    };

    let scan_result = match quick_scan(&scan_options) {
        Ok(result) => Some(result),
        Err(e) => {
            eprintln!("agent snapshot: warning: process scan failed: {}", e);
            None
        }
    };

    // Persist compact artifacts when we have a scan result.
    if let Some(ref scan_result) = scan_result {
        // Load config for protected filter + action policy.
        let config_options = ConfigOptions {
            config_dir: global.config.as_ref().map(PathBuf::from),
            ..Default::default()
        };
        if let Ok(config) = load_config(&config_options) {
            let priors = config.priors.clone();
            let policy = config.policy.clone();

            if let Ok(protected_filter) = ProtectedFilter::from_guardrails(&policy.guardrails) {
                let filter_result = protected_filter.filter_scan_result(scan_result);

                let mut persisted_inventory_records: Vec<PersistedProcess> = Vec::new();
                let mut persisted_inference_records: Vec<PersistedInference> = Vec::new();
                persisted_inventory_records.reserve(filter_result.passed.len());
                persisted_inference_records.reserve(filter_result.passed.len());

                let feasibility = ActionFeasibility::allow_all();
                for proc in &filter_result.passed {
                    let evidence = Evidence {
                        cpu: Some(CpuEvidence::Fraction {
                            occupancy: (proc.cpu_percent / 100.0).clamp(0.0, 1.0),
                        }),
                        runtime_seconds: Some(proc.elapsed.as_secs_f64()),
                        orphan: Some(proc.is_orphan()),
                        tty: Some(proc.has_tty()),
                        net: None,
                        io_active: None,
                        state_flag: state_to_flag(proc.state),
                        command_category: None,
                    };

                    let posterior_result = match compute_posterior(&priors, &evidence) {
                        Ok(r) => r,
                        Err(_) => continue,
                    };

                    let decision_outcome =
                        match decide_action(&posterior_result.posterior, &policy, &feasibility) {
                            Ok(d) => d,
                            Err(_) => continue,
                        };

                    let ledger = EvidenceLedger::from_posterior_result(
                        &posterior_result,
                        Some(proc.pid.0),
                        None,
                    );

                    let posterior = &posterior_result.posterior;
                    let max_posterior = posterior
                        .useful
                        .max(posterior.useful_bad)
                        .max(posterior.abandoned)
                        .max(posterior.zombie);
                    let score = (max_posterior * 100.0).round() as u32;

                    let recommended_action = match decision_outcome.optimal_action {
                        Action::Keep => "keep",
                        Action::Renice => "renice",
                        Action::Pause => "pause",
                        Action::Resume => "resume",
                        Action::Freeze => "freeze",
                        Action::Unfreeze => "unfreeze",
                        Action::Throttle => "throttle",
                        Action::Quarantine => "quarantine",
                        Action::Unquarantine => "unquarantine",
                        Action::Restart => "restart",
                        Action::Kill => "kill",
                    };

                    persisted_inventory_records.push(PersistedProcess {
                        pid: proc.pid.0,
                        ppid: proc.ppid.0,
                        uid: proc.uid,
                        start_id: proc.start_id.to_string(),
                        comm: proc.comm.clone(),
                        cmd: proc.cmd.clone(),
                        state: proc.state.to_string(),
                        start_time_unix: proc.start_time_unix,
                        elapsed_secs: proc.elapsed.as_secs(),
                        identity_quality: "QuickScan".to_string(),
                    });

                    persisted_inference_records.push(PersistedInference {
                        pid: proc.pid.0,
                        start_id: proc.start_id.to_string(),
                        classification: ledger.classification.label().to_string(),
                        posterior_useful: posterior.useful,
                        posterior_useful_bad: posterior.useful_bad,
                        posterior_abandoned: posterior.abandoned,
                        posterior_zombie: posterior.zombie,
                        confidence: ledger.confidence.label().to_string(),
                        recommended_action: recommended_action.to_string(),
                        score,
                    });
                }

                let host_id = pt_core::logging::get_host_id();
                let inv_artifact = InventoryArtifact {
                    total_system_processes: filter_result.total_before as u64,
                    protected_filtered: filter_result.filtered.len() as u64,
                    record_count: persisted_inventory_records.len(),
                    records: persisted_inventory_records,
                };
                if let Err(e) = persist_inventory(&handle, &session_id.0, &host_id, inv_artifact) {
                    eprintln!(
                        "agent snapshot: warning: failed to persist inventory artifact: {}",
                        e
                    );
                }

                let inf_artifact = InferenceArtifact {
                    candidate_count: persisted_inference_records.len(),
                    candidates: persisted_inference_records,
                };
                if let Err(e) = persist_inference(&handle, &session_id.0, &host_id, inf_artifact) {
                    eprintln!(
                        "agent snapshot: warning: failed to persist inference artifact: {}",
                        e
                    );
                }
            }
        }
    }

    // Collect process list if --top, --include-env, or --include-network is specified.
    let process_snapshot = if args.top.is_some() || args.include_env || args.include_network {
        if let Some(ref scan_result) = scan_result {
            let mut processes: Vec<_> = scan_result.processes.iter().collect();

            // Sort by resource usage (CPU + normalized memory)
            processes.sort_by(|a, b| {
                let a_score = a.cpu_percent + (a.rss_bytes as f64 / 1_073_741_824.0); // GB
                let b_score = b.cpu_percent + (b.rss_bytes as f64 / 1_073_741_824.0);
                b_score
                    .partial_cmp(&a_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });

            // Limit to top N if specified
            if let Some(top_n) = args.top {
                processes.truncate(top_n);
            }

            // Build process summaries for output
            let summaries: Vec<serde_json::Value> = processes
                .iter()
                .map(|p| {
                    let mut obj = serde_json::json!({
                        "pid": p.pid.0,
                        "ppid": p.ppid.0,
                        "user": &p.user,
                        "comm": &p.comm,
                        "cmd": &p.cmd,
                        "cpu_percent": p.cpu_percent,
                        "rss_mb": p.rss_bytes / 1_048_576,
                        "vsz_mb": p.vsz_bytes / 1_048_576,
                        "state": format!("{:?}", p.state),
                        "elapsed_secs": p.elapsed.as_secs(),
                    });

                    // Add environment info placeholder (redacted keys only)
                    if args.include_env {
                        // Read env from /proc/<pid>/environ and extract key names only
                        let env_path = format!("/proc/{}/environ", p.pid.0);
                        if let Ok(content) = std::fs::read(&env_path) {
                            let keys: Vec<String> = content
                                .split(|&b| b == 0)
                                .filter_map(|entry| {
                                    std::str::from_utf8(entry)
                                        .ok()
                                        .and_then(|s| s.split('=').next())
                                        .map(|k| k.to_string())
                                })
                                .filter(|k| !k.is_empty())
                                .collect();
                            obj.as_object_mut()
                                .unwrap()
                                .insert("env_keys".to_string(), serde_json::json!(keys));
                        }
                    }

                    // Add network connections placeholder
                    if args.include_network {
                        // Count file descriptors that look like sockets
                        let fd_path = format!("/proc/{}/fd", p.pid.0);
                        let socket_count = std::fs::read_dir(&fd_path)
                            .map(|entries| {
                                entries
                                    .filter_map(|e| e.ok())
                                    .filter(|e| {
                                        e.path()
                                            .read_link()
                                            .map(|target| {
                                                target.to_string_lossy().starts_with("socket:")
                                            })
                                            .unwrap_or(false)
                                    })
                                    .count()
                            })
                            .unwrap_or(0);
                        obj.as_object_mut()
                            .unwrap()
                            .insert("socket_count".to_string(), serde_json::json!(socket_count));
                    }

                    obj
                })
                .collect();

            Some(serde_json::json!({
                "count": summaries.len(),
                "top_n": args.top,
                "include_env": args.include_env,
                "include_network": args.include_network,
                "processes": summaries,
            }))
        } else {
            None
        }
    } else {
        None
    };

    // Build capabilities summary for output
    let capabilities_summary = serde_json::json!({
        "tools": {
            "perf": caps.tools.perf.available,
            "bpftrace": caps.tools.bpftrace.available,
            "strace": caps.tools.strace.available,
            "lsof": caps.tools.lsof.available,
            "ps": caps.tools.ps.available,
            "systemctl": caps.tools.systemctl.available,
        },
        "permissions": {
            "can_sudo": caps.permissions.can_sudo,
            "can_ptrace": caps.permissions.can_read_others_procs,
            "is_root": caps.permissions.is_root,
        },
    });

    match global.format {
        OutputFormat::Json | OutputFormat::Toon => {
            let mut output = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "session_id": session_id.0,
                "host_id": host_id,
                "timestamp": timestamp.to_rfc3339(),
                "generated_at": timestamp.to_rfc3339(),
                "label": args.label,
                "session_dir": handle.dir.display().to_string(),
                "context_path": handle.context_path().display().to_string(),
                "system_state": system_state,
                "capabilities": capabilities_summary,
            });
            if let Some(procs) = &process_snapshot {
                output
                    .as_object_mut()
                    .unwrap()
                    .insert("process_snapshot".to_string(), procs.clone());
            }
            println!("{}", format_structured_output(global, output));
        }
        OutputFormat::Summary => {
            let mem = system_state
                .get("memory")
                .and_then(|m| m.get("used_gb"))
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let total = system_state
                .get("memory")
                .and_then(|m| m.get("total_gb"))
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let procs = system_state
                .get("process_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            println!(
                "[{}] agent snapshot: created ({} procs, {:.0}/{:.0}GB mem)",
                session_id, procs, mem, total
            );
        }
        OutputFormat::Exitcode => {}
        _ => {
            println!("# pt-core agent snapshot");
            println!();
            println!("Session: {}", session_id);
            println!("Host: {}", host_id);
            println!("Dir: {}", handle.dir.display());
            if let Some(label) = &args.label {
                println!("Label: {}", label);
            }
            println!();
            println!("## System State");
            if let Some(load) = system_state.get("load").and_then(|v| v.as_array()) {
                let load_strs: Vec<String> = load
                    .iter()
                    .filter_map(|v| v.as_f64().map(|f| format!("{:.2}", f)))
                    .collect();
                println!("  Load: {}", load_strs.join(", "));
            }
            if let Some(cores) = system_state.get("cores").and_then(|v| v.as_u64()) {
                println!("  Cores: {}", cores);
            }
            if let Some(mem) = system_state.get("memory") {
                let total = mem.get("total_gb").and_then(|v| v.as_f64()).unwrap_or(0.0);
                let used = mem.get("used_gb").and_then(|v| v.as_f64()).unwrap_or(0.0);
                let avail = mem
                    .get("available_gb")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0);
                println!(
                    "  Memory: {:.1}GB total, {:.1}GB used, {:.1}GB available",
                    total, used, avail
                );
            }
            if let Some(procs) = system_state.get("process_count").and_then(|v| v.as_u64()) {
                println!("  Processes: {}", procs);
            }
            if let Some(psi) = system_state.get("psi") {
                let cpu = psi.get("cpu").and_then(|v| v.as_f64()).unwrap_or(0.0);
                let mem = psi.get("memory").and_then(|v| v.as_f64()).unwrap_or(0.0);
                let io = psi.get("io").and_then(|v| v.as_f64()).unwrap_or(0.0);
                println!("  PSI: cpu={:.2}%, mem={:.2}%, io={:.2}%", cpu, mem, io);
            }

            // Display process snapshot if collected
            if let Some(snapshot) = &process_snapshot {
                println!();
                println!("## Process Snapshot");
                let count = snapshot.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
                let top_n = snapshot.get("top_n").and_then(|v| v.as_u64());
                if let Some(n) = top_n {
                    println!("  Top {} processes by resource usage:", n);
                } else {
                    println!("  {} processes:", count);
                }
                if let Some(procs) = snapshot.get("processes").and_then(|v| v.as_array()) {
                    for p in procs.iter().take(10) {
                        let pid = p.get("pid").and_then(|v| v.as_u64()).unwrap_or(0);
                        let comm = p.get("comm").and_then(|v| v.as_str()).unwrap_or("?");
                        let cpu = p.get("cpu_percent").and_then(|v| v.as_f64()).unwrap_or(0.0);
                        let rss = p.get("rss_mb").and_then(|v| v.as_u64()).unwrap_or(0);
                        println!("    {:>7} {:<20} {:>5.1}% CPU {:>6}MB", pid, comm, cpu, rss);
                    }
                    if procs.len() > 10 {
                        println!(
                            "    ... and {} more (use --format json for full list)",
                            procs.len() - 10
                        );
                    }
                }
            }
        }
    }

    ExitCode::Clean
}

fn match_level_label(level: MatchLevel) -> &'static str {
    match level {
        MatchLevel::None => "none",
        MatchLevel::GenericCategory => "generic_category",
        MatchLevel::CommandOnly => "command_only",
        MatchLevel::CommandPlusArgs => "command_plus_args",
        MatchLevel::ExactCommand => "exact_command",
        MatchLevel::MultiPattern => "multi_pattern",
    }
}

fn fast_path_skip_reason_label(reason: FastPathSkipReason) -> &'static str {
    match reason {
        FastPathSkipReason::Disabled => "disabled",
        FastPathSkipReason::NoMatch => "no_match",
        FastPathSkipReason::ScoreBelowThreshold => "score_below_threshold",
        FastPathSkipReason::NoPriors => "no_priors",
    }
}

fn run_agent_plan(global: &GlobalOpts, args: &AgentPlanArgs) -> ExitCode {
    let _lock = match acquire_global_lock(global, "agent plan") {
        Ok(lock) => lock,
        Err(code) => return code,
    };
    let store = match SessionStore::from_env() {
        Ok(store) => store,
        Err(e) => {
            eprintln!("agent plan: session store error: {}", e);
            return ExitCode::InternalError;
        }
    };

    let (session_id, handle, created) = match args.session.as_ref() {
        Some(raw) => {
            let sid = match SessionId::parse(raw) {
                Some(sid) => sid,
                None => {
                    eprintln!("agent plan: invalid --session {}", raw);
                    return ExitCode::ArgsError;
                }
            };
            let handle = match store.open(&sid) {
                Ok(handle) => handle,
                Err(e) => {
                    eprintln!("agent plan: {}", e);
                    return ExitCode::ArgsError;
                }
            };
            (sid, handle, false)
        }
        None => {
            let sid = SessionId::new();
            let manifest =
                SessionManifest::new(&sid, None, SessionMode::RobotPlan, args.label.clone());
            let handle = match store.create(&manifest) {
                Ok(handle) => handle,
                Err(e) => {
                    eprintln!("agent plan: failed to create session: {}", e);
                    return ExitCode::InternalError;
                }
            };
            let ctx = SessionContext::new(
                &sid,
                pt_core::logging::get_host_id(),
                pt_core::logging::generate_run_id(),
                None,
            );
            if let Err(e) = handle.write_context(&ctx) {
                eprintln!("agent plan: failed to write context.json: {}", e);
                return ExitCode::InternalError;
            }
            (sid, handle, true)
        }
    };

    // Load configuration and priors
    let config_options = ConfigOptions {
        config_dir: global.config.as_ref().map(PathBuf::from),
        ..Default::default()
    };
    let config = match load_config(&config_options) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("agent plan: failed to load config: {}", e);
            return ExitCode::InternalError;
        }
    };
    let priors = config.priors.clone();
    let policy = config.policy.clone();
    let fast_path_config = FastPathConfig {
        enabled: policy.signature_fast_path.enabled,
        min_confidence_threshold: policy.signature_fast_path.min_confidence_threshold,
        require_explicit_priors: policy.signature_fast_path.require_explicit_priors,
    };

    let mut signature_db = SignatureDatabase::with_defaults();
    if let Some(user_schema) = pt_core::signature_cli::load_user_signatures() {
        for signature in user_schema.signatures {
            if let Err(err) = signature_db.add(signature) {
                eprintln!(
                    "agent plan: warning: skipping invalid user signature during load: {}",
                    err
                );
            }
        }
    }

    let rate_limit_path = resolve_data_dir_for_lock().map(|dir| dir.join("rate_limit.json"));
    let enforcer = match pt_core::decision::PolicyEnforcer::new(&policy, rate_limit_path.as_deref())
    {
        Ok(enforcer) => enforcer,
        Err(e) => {
            eprintln!("agent plan: failed to init policy enforcer: {}", e);
            return ExitCode::InternalError;
        }
    };

    if args.prediction_fields.is_some() && !args.include_predictions {
        eprintln!("agent plan: --prediction-fields requires --include-predictions");
        return ExitCode::ArgsError;
    }

    let prediction_field_selector = if args.include_predictions {
        match args.prediction_fields.as_deref() {
            Some(spec) => match parse_prediction_fields(spec) {
                Ok(selector) => Some(selector),
                Err(err) => {
                    eprintln!("agent plan: {}", err);
                    return ExitCode::ArgsError;
                }
            },
            None => None,
        }
    } else {
        None
    };

    // Progress emitter for streaming updates + session log
    let emitter = session_progress_emitter(global, &handle, &session_id);
    if let Some(ref e) = emitter {
        e.emit(ProgressEvent::new(
            pt_core::events::event_names::SESSION_STARTED,
            Phase::Session,
        ));
    }

    // Perform quick scan to enumerate processes (with timing)
    let scan_start = std::time::Instant::now();
    let scan_options = QuickScanOptions {
        pids: vec![],
        include_kernel_threads: args.include_kernel_threads,
        timeout: global.timeout.map(std::time::Duration::from_secs),
        progress: emitter.clone(),
    };

    let scan_result = match quick_scan(&scan_options) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("agent plan: scan failed: {}", e);
            return ExitCode::InternalError;
        }
    };
    let scan_duration_ms = scan_start.elapsed().as_millis() as u64;

    // Quick scan emits its own progress events via the shared emitter.

    // Create protected filter from policy guardrails
    let protected_filter = match ProtectedFilter::from_guardrails(&policy.guardrails) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("agent plan: failed to create protected filter: {}", e);
            return ExitCode::InternalError;
        }
    };

    // Apply filter BEFORE inference loop to remove protected processes
    let filter_result = protected_filter.filter_scan_result(&scan_result);
    let protected_filtered_count = filter_result.filtered.len();
    let total_scanned = filter_result.total_before;

    tracing::info!(
        total_scanned = total_scanned,
        filtered_count = protected_filtered_count,
        passed_count = filter_result.passed.len(),
        "Protected filter applied"
    );

    let system_state = collect_system_state();
    let load_adjustment = if policy.load_aware.enabled {
        let signals = LoadSignals::from_system_state(&system_state, filter_result.passed.len());
        compute_load_adjustment(&policy.load_aware, &signals)
    } else {
        None
    };

    let decision_policy = if let Some(adjustment) = &load_adjustment {
        let mut adjusted = policy.clone();
        adjusted.loss_matrix = apply_load_to_loss_matrix(&policy.loss_matrix, adjustment);
        adjusted
    } else {
        policy.clone()
    };

    // Process each candidate: compute posterior, make decision, build candidate output.
    //
    // Collect all candidates above threshold with their max_posterior for sorting, plus
    // a compact persisted snapshot (inventory + inference) so `diff` can compare sessions.
    let mut all_candidates: Vec<(f64, serde_json::Value, PersistedProcess, PersistedInference)> =
        Vec::new();
    let mut policy_blocked_count = 0usize;
    let mut signature_match_count = 0usize;
    let mut signature_fast_path_used_count = 0usize;

    let base_feasibility = ActionFeasibility::allow_all();
    let mut shadow_recorder = if global.shadow {
        match ShadowRecorder::new() {
            Ok(recorder) => Some(recorder),
            Err(err) => {
                eprintln!("shadow mode: failed to initialize storage: {:?}", err);
                None
            }
        }
    } else {
        None
    };
    let mut shadow_recorded = 0u64;

    // Apply min-age filter before sampling (if configured)
    let eligible_processes: Vec<_> = if let Some(min_age) = args.min_age {
        filter_result
            .passed
            .iter()
            .filter(|proc| proc.elapsed.as_secs() >= min_age)
            .collect()
    } else {
        filter_result.passed.iter().collect()
    };

    // Apply sampling if requested (for testing)
    let processes_to_infer: Vec<_> = if let Some(sample_size) = args.sample_size {
        use rand::seq::SliceRandom;
        let mut rng = rand::rng();
        let mut sampled: Vec<_> = eligible_processes;
        sampled.shuffle(&mut rng);
        sampled.truncate(sample_size);
        sampled
    } else {
        eligible_processes
    };

    let _current_cpu_pct: f64 = processes_to_infer.iter().map(|p| p.cpu_percent).sum();

    let candidates_evaluated = processes_to_infer.len();
    let total_processes = candidates_evaluated as u64;
    let mut processed = 0u64;

    if let Some(ref e) = emitter {
        e.emit(
            ProgressEvent::new(
                pt_core::events::event_names::INFERENCE_STARTED,
                Phase::Infer,
            )
            .with_progress(0, Some(total_processes)),
        );
        e.emit(
            ProgressEvent::new(
                pt_core::events::event_names::DECISION_STARTED,
                Phase::Decide,
            )
            .with_progress(0, Some(total_processes)),
        );
    }

    // Use filtered (and optionally sampled) processes for inference
    for proc in processes_to_infer {
        // Skip PID 0/1 (extra safety - should already be filtered)
        if proc.pid.0 == 0 || proc.pid.0 == 1 {
            continue;
        }
        processed = processed.saturating_add(1);

        // Build evidence from process record
        let evidence = Evidence {
            cpu: Some(CpuEvidence::Fraction {
                occupancy: (proc.cpu_percent / 100.0).clamp(0.0, 1.0),
            }),
            runtime_seconds: Some(proc.elapsed.as_secs_f64()),
            orphan: Some(proc.is_orphan()),
            tty: Some(proc.has_tty()),
            net: None,
            io_active: None,
            state_flag: state_to_flag(proc.state),
            command_category: None,
        };

        let mut match_ctx = ProcessMatchContext::with_comm(&proc.comm);
        if !proc.cmd.is_empty() {
            match_ctx = match_ctx.cmdline(&proc.cmd);
        }
        let signature_match = signature_db.best_match(&match_ctx);
        if signature_match.is_some() {
            signature_match_count = signature_match_count.saturating_add(1);
        }

        let mut fast_path_used = false;
        let mut fast_path_skip_reason: Option<&'static str> = None;
        let prior_source_label: String;
        let prior_context = PriorContext {
            global_priors: &priors,
            signature_match: signature_match.as_ref(),
            user_overrides: None,
        };

        let (posterior_result, mut ledger) = if let Some(sig_match) = signature_match.as_ref() {
            match try_signature_fast_path(&fast_path_config, Some(sig_match), proc.pid.0) {
                Ok(Some(fast_path)) => {
                    fast_path_used = true;
                    signature_fast_path_used_count =
                        signature_fast_path_used_count.saturating_add(1);
                    prior_source_label = "signature_fast_path".to_string();
                    (fast_path.posterior, fast_path.ledger)
                }
                Ok(None) => match compute_posterior_with_overrides(&prior_context, &evidence) {
                    Ok((result, source_info)) => {
                        prior_source_label = source_info.source.to_string();
                        let ledger =
                            EvidenceLedger::from_posterior_result(&result, Some(proc.pid.0), None);
                        (result, ledger)
                    }
                    Err(_) => continue,
                },
                Err(reason) => {
                    fast_path_skip_reason = Some(fast_path_skip_reason_label(reason));
                    match compute_posterior_with_overrides(&prior_context, &evidence) {
                        Ok((result, source_info)) => {
                            prior_source_label = source_info.source.to_string();
                            let ledger = EvidenceLedger::from_posterior_result(
                                &result,
                                Some(proc.pid.0),
                                None,
                            );
                            (result, ledger)
                        }
                        Err(_) => continue,
                    }
                }
            }
        } else {
            match compute_posterior_with_overrides(&prior_context, &evidence) {
                Ok((result, source_info)) => {
                    prior_source_label = source_info.source.to_string();
                    let ledger =
                        EvidenceLedger::from_posterior_result(&result, Some(proc.pid.0), None);
                    (result, ledger)
                }
                Err(_) => continue,
            }
        };

        let signature_name = signature_match.as_ref().map(|m| m.signature.name.clone());
        let signature_level = signature_match
            .as_ref()
            .map(|m| match_level_label(m.level).to_string());
        let signature_score = signature_match.as_ref().map(|m| m.score);
        let signature_category = signature_match
            .as_ref()
            .map(|m| format!("{:?}", m.signature.category));

        if let Some(sig_match) = signature_match.as_ref() {
            if !fast_path_used {
                ledger.top_evidence.insert(
                    0,
                    format!(
                        "Signature match: {} (score={:.2}, level={})",
                        sig_match.signature.name,
                        sig_match.score,
                        match_level_label(sig_match.level)
                    ),
                );
                ledger.why_summary = format!(
                    "Matched signature '{}' (score {:.2}, level {}, prior source {}). {}",
                    sig_match.signature.name,
                    sig_match.score,
                    match_level_label(sig_match.level),
                    prior_source_label,
                    ledger.why_summary
                );
            }
        }

        // Apply state-based feasibility constraints so decisioning does not
        // recommend fundamentally invalid actions (e.g., kill for zombie/D-state).
        let state_feasibility = ActionFeasibility::from_process_state(
            proc.state.is_zombie(),
            proc.state.is_disksleep(),
            None,
        );
        let feasibility = base_feasibility.merge(&state_feasibility);

        // Compute decision (optimal action based on expected loss)
        let mut decision_outcome =
            match decide_action(&posterior_result.posterior, &decision_policy, &feasibility) {
                Ok(d) => d,
                Err(_) => continue, // Skip processes that fail decision
            };
        decision_outcome.rationale.has_known_signature = Some(signature_match.is_some());

        // Determine max posterior class for filtering
        let posterior = &posterior_result.posterior;
        let max_posterior = posterior
            .useful
            .max(posterior.useful_bad)
            .max(posterior.abandoned)
            .max(posterior.zombie);

        // Determine recommended action string (used for shadow recording and plan output)
        let mut recommended_action = match decision_outcome.optimal_action {
            Action::Keep => "keep",
            Action::Renice => "renice",
            Action::Pause => "pause",
            Action::Resume => "resume",
            Action::Freeze => "freeze",
            Action::Unfreeze => "unfreeze",
            Action::Throttle => "throttle",
            Action::Quarantine => "quarantine",
            Action::Unquarantine => "unquarantine",
            Action::Restart => "restart",
            Action::Kill => "kill",
        };

        if let Some(ref mut recorder) = shadow_recorder {
            match recorder.record_candidate(proc, posterior, &ledger, &decision_outcome) {
                Ok(()) => shadow_recorded = shadow_recorded.saturating_add(1),
                Err(err) => {
                    eprintln!(
                        "shadow mode: failed to record observation for pid {}: {:?}",
                        proc.pid.0, err
                    );
                }
            }
        }

        if let Some(ref e) = emitter {
            if processed.is_multiple_of(50) || processed == total_processes {
                e.emit(
                    ProgressEvent::new(
                        pt_core::events::event_names::INFERENCE_PROGRESS,
                        Phase::Infer,
                    )
                    .with_progress(processed, Some(total_processes)),
                );
            }
        }

        // Apply threshold filter
        if max_posterior < args.min_posterior {
            continue;
        }

        // Apply --only filter
        let include = match args.only.as_str() {
            "kill" => decision_outcome.optimal_action == Action::Kill,
            "review" => decision_outcome.optimal_action != Action::Keep,
            _ => true, // "all"
        };
        if !include {
            continue;
        }

        let process_candidate = pt_core::decision::ProcessCandidate {
            pid: proc.pid.0 as i32,
            ppid: proc.ppid.0 as i32,
            cmdline: proc.cmd.clone(),
            user: Some(proc.user.clone()),
            group: None,
            category: decision_outcome.rationale.category.clone(),
            age_seconds: proc.elapsed.as_secs(),
            posterior: Some(max_posterior),
            memory_mb: Some(proc.rss_bytes as f64 / (1024.0 * 1024.0)),
            has_known_signature: decision_outcome
                .rationale
                .has_known_signature
                .unwrap_or(false),
            open_write_fds: None,
            has_locked_files: None,
            has_active_tty: Some(proc.has_tty()),
            seconds_since_io: None,
            cwd_deleted: None,
            process_state: Some(proc.state),
            wchan: None,
            critical_files: Vec::new(),
        };
        let policy_result = enforcer.check_action(
            &process_candidate,
            decision_outcome.optimal_action,
            global.robot,
        );
        let policy_blocked = !policy_result.allowed;
        if policy_blocked {
            policy_blocked_count += 1;
            recommended_action = "review";
        }
        let policy_value = serde_json::to_value(&policy_result)
            .unwrap_or_else(|_| serde_json::json!({ "allowed": policy_result.allowed }));
        let action_rationale = if policy_blocked {
            policy_result
                .violation
                .as_ref()
                .map(|v| format!("Policy blocked: {}", v.message))
                .unwrap_or_else(|| "Policy blocked".to_string())
        } else {
            format!(
                "Action {:?} selected{}",
                decision_outcome.rationale.chosen_action,
                if decision_outcome.rationale.tie_break {
                    " (tie-break)"
                } else {
                    ""
                }
            )
        };

        // Build evidence contributions from Bayes factors
        let evidence_contributions: Vec<serde_json::Value> = ledger
            .bayes_factors
            .iter()
            .map(|bf| {
                serde_json::json!({
                    "factor": bf.feature,
                    "contribution": (bf.delta_bits * 10.0).round() as i32, // Scale to integer score
                    "detail": format!("{:.1} bits {}", bf.delta_bits.abs(), bf.direction),
                    "strength": bf.strength,
                })
            })
            .collect();

        // Calculate age in seconds and human-readable form
        let age_seconds = proc.elapsed.as_secs();
        let age_human = format_duration_human(age_seconds);

        // Calculate a composite score (0-100) based on max posterior
        let score = (max_posterior * 100.0).round() as u32;

        let predictions = if args.include_predictions {
            let mut predictions = build_stub_predictions(proc);
            if let Some(selector) = &prediction_field_selector {
                predictions = apply_field_selection(&predictions, selector);
            }
            if predictions.is_empty() {
                None
            } else {
                Some(predictions)
            }
        } else {
            None
        };

        // Build candidate JSON (action tracking moved to after sorting)
        let mut candidate = serde_json::json!({
            "pid": proc.pid.0,
            "ppid": proc.ppid.0,
            "state": proc.state.to_string(),
            "start_id": format!("{}:{}", proc.pid.0, proc.start_time_unix),
            "uid": proc.uid,
            "user": &proc.user,
            "command": &proc.cmd,
            "command_short": &proc.comm,
            "type": ledger.classification.label(), // Process type classification
            "age_seconds": age_seconds,
            "age_human": age_human,
            "memory_mb": proc.rss_bytes / (1024 * 1024),
            "cpu_percent": proc.cpu_percent,
            "score": score,
            "classification": ledger.classification.label(),
            "posterior": {
                "useful": posterior.useful,
                "useful_bad": posterior.useful_bad,
                "abandoned": posterior.abandoned,
                "zombie": posterior.zombie,
            },
            "signature": {
                "matched": signature_match.is_some(),
                "name": signature_name,
                "category": signature_category,
                "score": signature_score,
                "match_level": signature_level,
            },
            "inference": {
                "mode": if fast_path_used { "signature_fast_path" } else { "bayesian" },
                "prior_source": prior_source_label,
                "fast_path": {
                    "enabled": fast_path_config.enabled,
                    "used": fast_path_used,
                    "skip_reason": fast_path_skip_reason,
                    "min_confidence_threshold": fast_path_config.min_confidence_threshold,
                    "require_explicit_priors": fast_path_config.require_explicit_priors,
                },
            },
            "confidence": ledger.confidence.label(),
            "evidence": evidence_contributions,
            "blast_radius": {
                "memory_mb": proc.rss_bytes / (1024 * 1024),
                "cpu_pct": proc.cpu_percent,
                "child_count": 0, // Would need child enumeration
                "risk_level": if proc.rss_bytes > 1024 * 1024 * 1024 { "medium" } else { "low" },
            },
            "reversibility": match decision_outcome.optimal_action {
                Action::Kill | Action::Restart => "irreversible",
                Action::Pause | Action::Freeze | Action::Throttle | Action::Quarantine => "reversible",
                Action::Resume | Action::Unfreeze | Action::Unquarantine => "reversal",
                Action::Keep | Action::Renice => "no_action",
            },
            "supervisor": supervisor_info_for_plan(proc.pid.0),
            "uncertainty": {
                "entropy": ledger.bayes_factors.len() as f64 * 0.1, // Simplified
                "confidence_interval": [(max_posterior - 0.1).max(0.0), (max_posterior + 0.1).min(1.0)],
            },
            "recommendation": recommended_action.to_uppercase(),
            "recommended_action": recommended_action,
            "action_rationale": action_rationale,
            "expected_loss": decision_outcome.expected_loss.iter()
                .map(|el| serde_json::json!({
                    "action": format!("{:?}", el.action),
                    "loss": el.loss,
                }))
                .collect::<Vec<_>>(),
            "policy_blocked": policy_blocked,
            "policy": policy_value,
        });

        if let Some(predictions) = predictions {
            if let Some(obj) = candidate.as_object_mut() {
                obj.insert(
                    "predictions".to_string(),
                    serde_json::to_value(predictions).unwrap_or_else(|_| serde_json::json!({})),
                );
            }
        }

        let persisted_proc = PersistedProcess {
            pid: proc.pid.0,
            ppid: proc.ppid.0,
            uid: proc.uid,
            start_id: proc.start_id.to_string(),
            comm: proc.comm.clone(),
            cmd: proc.cmd.clone(),
            state: proc.state.to_string(),
            start_time_unix: proc.start_time_unix,
            elapsed_secs: proc.elapsed.as_secs(),
            // Quick scan provides a solid start_id but lacks full TOCTOU coverage.
            identity_quality: "QuickScan".to_string(),
        };

        let persisted_inf = PersistedInference {
            pid: proc.pid.0,
            start_id: proc.start_id.to_string(),
            classification: ledger.classification.label().to_string(),
            posterior_useful: posterior.useful,
            posterior_useful_bad: posterior.useful_bad,
            posterior_abandoned: posterior.abandoned,
            posterior_zombie: posterior.zombie,
            confidence: ledger.confidence.label().to_string(),
            recommended_action: recommended_action.to_string(),
            score,
        };

        // Store candidate with max_posterior for sorting (no early break!)
        all_candidates.push((max_posterior, candidate, persisted_proc, persisted_inf));
    }

    if let Some(ref e) = emitter {
        e.emit(
            ProgressEvent::new(
                pt_core::events::event_names::INFERENCE_COMPLETE,
                Phase::Infer,
            )
            .with_progress(processed, Some(total_processes)),
        );
        e.emit(
            ProgressEvent::new(
                pt_core::events::event_names::DECISION_COMPLETE,
                Phase::Decide,
            )
            .with_progress(processed, Some(total_processes)),
        );
    }

    if let Some(ref mut recorder) = shadow_recorder {
        if let Err(err) = recorder.flush() {
            eprintln!("shadow mode: failed to flush storage: {:?}", err);
        }
    }

    // Sort candidates by max_posterior descending (highest confidence first)
    all_candidates.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

    // Capture count before truncation for summary stats
    let above_threshold_count = all_candidates.len();

    // Take top N candidates (sorted by max posterior, not scan order!)
    let mut candidates: Vec<serde_json::Value> = Vec::new();
    let mut persisted_inventory_records: Vec<PersistedProcess> = Vec::new();
    let mut persisted_inference_records: Vec<PersistedInference> = Vec::new();
    for (_, candidate_json, proc_rec, inf_rec) in all_candidates
        .into_iter()
        .take(args.max_candidates as usize)
    {
        candidates.push(candidate_json);
        persisted_inventory_records.push(proc_rec);
        persisted_inference_records.push(inf_rec);
    }

    let mut goal_summary: Option<serde_json::Value> = None;
    let mut goal_selected: Option<HashSet<u32>> = None;
    if let Some(goal_str) = args.goal.as_deref() {
        match parse_goal(goal_str) {
            Ok(goal) => {
                let total_cpu_pct_for_goal: f64 = candidates
                    .iter()
                    .map(|candidate| {
                        candidate
                            .get("cpu_percent")
                            .and_then(|value| value.as_f64())
                            .unwrap_or(0.0)
                    })
                    .sum();
                match build_goal_plan_from_candidates(
                    goal_str,
                    &goal,
                    total_cpu_pct_for_goal,
                    &candidates,
                ) {
                    Ok(goal_output) => {
                        let goal_json = goal_summary_json(goal_str, &goal, &goal_output);
                        let selected = goal_output.selected_pids.clone();
                        let selected_set: HashSet<u32> = selected.iter().copied().collect();
                        let mut selected_rank: HashMap<u32, usize> = HashMap::new();
                        for (idx, pid) in selected.iter().enumerate() {
                            selected_rank.insert(*pid, idx);
                        }

                        for candidate in &mut candidates {
                            if let Some(obj) = candidate.as_object_mut() {
                                let pid =
                                    obj.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                                let selected_for_goal = selected_set.contains(&pid);
                                obj.insert(
                                    "goal_selected".to_string(),
                                    serde_json::json!(selected_for_goal),
                                );
                                if selected_for_goal {
                                    obj.insert(
                                        "goal_rank".to_string(),
                                        serde_json::json!(selected_rank
                                            .get(&pid)
                                            .copied()
                                            .unwrap_or(usize::MAX)),
                                    );
                                }
                            }
                        }

                        candidates.sort_by_key(|candidate| {
                            let pid = candidate
                                .get("pid")
                                .and_then(|value| value.as_u64())
                                .unwrap_or(0) as u32;
                            selected_rank.get(&pid).copied().unwrap_or(usize::MAX)
                        });

                        goal_summary = Some(goal_json);
                        goal_selected = Some(selected_set);
                    }
                    Err(err) => {
                        goal_summary = Some(serde_json::json!({
                            "goal": goal_str,
                            "parsed": goal.canonical(),
                            "error": err,
                        }));
                    }
                }
            }
            Err(err) => {
                goal_summary = Some(serde_json::json!({
                    "goal": goal_str,
                    "error": err,
                }));
            }
        }
    }

    // Rebuild kill/review/spare candidate lists from the final sorted candidates
    let mut kill_candidates: Vec<u32> = Vec::new();
    let mut review_candidates: Vec<u32> = Vec::new();
    let mut spare_candidates: Vec<u32> = Vec::new();
    let mut expected_memory_freed_bytes: u64 = 0;
    for candidate in &candidates {
        let pid = candidate["pid"].as_u64().unwrap_or(0) as u32;
        let action = candidate["recommended_action"].as_str().unwrap_or("");
        let memory_mb = candidate["memory_mb"].as_u64().unwrap_or(0);
        let selected_by_goal = goal_selected
            .as_ref()
            .map(|selected| selected.contains(&pid))
            .unwrap_or(false);
        if selected_by_goal || action == "kill" {
            kill_candidates.push(pid);
            expected_memory_freed_bytes += memory_mb * 1024 * 1024;
        } else if action == "keep" {
            spare_candidates.push(pid);
        } else {
            review_candidates.push(pid);
        }
    }
    let expected_memory_freed_gb = (expected_memory_freed_bytes as f64) / 1024.0 / 1024.0 / 1024.0;

    // Collect host information
    let host_info = collect_host_info();

    // Build scan info
    let scan_info = serde_json::json!({
        "total_processes": total_scanned,
        "candidates_found": above_threshold_count,
        "scan_duration_ms": scan_duration_ms,
    });

    // Build summary (legacy format for backward compatibility)
    let mut summary = serde_json::json!({
        "total_processes_scanned": total_scanned,
        "protected_filtered": protected_filtered_count,
        "candidates_evaluated": candidates_evaluated,
        "above_threshold": above_threshold_count,  // Candidates meeting threshold before truncation
        "candidates_returned": candidates.len(),   // After truncation to max_candidates
        "kill_recommendations": kill_candidates.len(),
        "review_recommendations": review_candidates.len(),
        "policy_blocked": policy_blocked_count,
        "signature_matches": signature_match_count,
        "signature_fast_path_used": signature_fast_path_used_count,
        "signature_fast_path_enabled": fast_path_config.enabled,
        "signature_fast_path_min_confidence_threshold": fast_path_config.min_confidence_threshold,
        "signature_fast_path_require_explicit_priors": fast_path_config.require_explicit_priors,
        "threshold_used": args.min_posterior,
        "filter_used": args.only,
    });
    if global.shadow {
        summary["shadow_observations_recorded"] = serde_json::json!(shadow_recorded);
    }
    if let Some(goal) = &goal_summary {
        summary["goal_mode"] = serde_json::json!(true);
        summary["goal_achievable"] = goal
            .get("achievable")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        summary["goal_selected_count"] = serde_json::json!(kill_candidates.len());
    }

    // Build recommendations section (new structured format)
    let mut recommendations = serde_json::json!({
        "kill_set": kill_candidates,
        "review_set": review_candidates,
        "spare_set": spare_candidates,
        "expected_memory_freed_gb": (expected_memory_freed_gb * 100.0).round() / 100.0,
        "fleet_fdr": 0.03, // Placeholder - would come from fleet-wide statistics
    });
    if let Some(goal) = &goal_summary {
        recommendations["goal"] = goal.clone();
    }

    // Build recommended section (legacy format for backward compatibility)
    let empty_pids: Vec<u32> = Vec::new();
    let preselected_pids = if args.yes {
        &kill_candidates
    } else {
        &empty_pids
    };
    let recommended = serde_json::json!({
        "preselected_pids": preselected_pids,
        "actions": kill_candidates.iter().map(|pid| serde_json::json!({
            "pid": pid,
            "action": "kill",
            "stage": 1,
        })).collect::<Vec<_>>(),
    });

    // Check for stub flags usage (future features parsed but not yet functional)
    let mut stub_flags_used: Vec<&str> = Vec::new();
    if args.since.is_some() {
        stub_flags_used.push("--since");
    }
    if args.since_time.is_some() {
        stub_flags_used.push("--since-time");
    }

    // Build stub_flags section if any future flags were used
    let stub_flags_section = if !stub_flags_used.is_empty() {
        Some(serde_json::json!({
            "warning": "feature_not_implemented",
            "message": "Some flags are parsed but not yet functional",
            "flags_used": stub_flags_used,
            "flags_ignored": stub_flags_used,
            "workaround": "Use pt agent diff for manual comparison; goal-oriented mode coming in v1.2",
            "planned_release": "v1.2"
        }))
    } else {
        None
    };

    let goal_value = goal_summary
        .as_ref()
        .and_then(|goal| goal.get("goal"))
        .cloned()
        .or_else(|| args.goal.as_ref().map(|goal| serde_json::json!(goal)))
        .unwrap_or(serde_json::Value::Null);
    let goal_progress = goal_summary
        .as_ref()
        .and_then(|goal| goal.get("goal_achievement"))
        .cloned()
        .unwrap_or_else(|| serde_json::json!([]));

    // Build complete plan output with structured JSON format
    let mut plan_output = serde_json::json!({
        "pt_version": env!("CARGO_PKG_VERSION"),
        "schema_version": SCHEMA_VERSION,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "session_id": session_id.0,
        "label": args.label,
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "host_id": pt_core::logging::get_host_id(),
        "host": host_info,
        "scan": scan_info,
        "command": "agent plan",
        "args": {
            "max_candidates": args.max_candidates,
            "min_posterior": args.min_posterior,
            "only": args.only,
            "yes": args.yes,
            "dry_run": global.dry_run,
            "robot": global.robot,
            "shadow": global.shadow,
            "min_age": args.min_age,
            "sample_size": args.sample_size,
            "include_kernel_threads": args.include_kernel_threads,
            "deep": args.deep,
            "since": args.since,
            "since_time": args.since_time,
            "goal": args.goal,
            "include_predictions": args.include_predictions,
            "prediction_fields": args.prediction_fields,
            "minimal": args.minimal,
            "pretty": args.pretty,
            "brief": args.brief,
            "narrative": args.narrative,
        },
        "summary": summary,
        "goal": goal_value,
        "goal_progress": goal_progress,
        "goal_summary": goal_summary,
        "candidates": candidates,
        "recommendations": recommendations,
        "recommended": recommended,  // Legacy format for backward compatibility
        "session_created": created,
    });

    // Add stub_flags section if any future flags were used
    if let Some(stub_flags) = stub_flags_section {
        plan_output["stub_flags"] = stub_flags;
    }

    // Write plan to session
    let decision_dir = handle.dir.join("decision");
    if let Err(e) = std::fs::create_dir_all(&decision_dir) {
        eprintln!(
            "agent plan: failed to create directory {}: {}",
            decision_dir.display(),
            e
        );
        return ExitCode::InternalError;
    }
    let plan_path = decision_dir.join("plan.json");
    if let Err(e) = std::fs::write(
        &plan_path,
        serde_json::to_string_pretty(&plan_output).unwrap(),
    ) {
        eprintln!("agent plan: failed to write {}: {}", plan_path.display(), e);
        return ExitCode::InternalError;
    }

    // Persist compact diff artifacts so `pt diff` can compare sessions reliably.
    // Best-effort: don't fail the plan output if persistence fails, but emit a warning.
    let host_id = pt_core::logging::get_host_id();
    let inv_artifact = InventoryArtifact {
        total_system_processes: total_scanned as u64,
        protected_filtered: protected_filtered_count as u64,
        record_count: persisted_inventory_records.len(),
        records: persisted_inventory_records,
    };
    if let Err(e) = persist_inventory(&handle, &session_id.0, &host_id, inv_artifact) {
        eprintln!(
            "agent plan: warning: failed to persist inventory artifact: {}",
            e
        );
    }

    let inf_artifact = InferenceArtifact {
        candidate_count: persisted_inference_records.len(),
        candidates: persisted_inference_records,
    };
    if let Err(e) = persist_inference(&handle, &session_id.0, &host_id, inf_artifact) {
        eprintln!(
            "agent plan: warning: failed to persist inference artifact: {}",
            e
        );
    }

    // Update manifest state
    let _ = handle.update_state(SessionState::Planned);

    if let Some(ref e) = emitter {
        e.emit(
            ProgressEvent::new(pt_core::events::event_names::PLAN_READY, Phase::Plan)
                .with_session_id(session_id.to_string())
                .with_detail("plan_path", plan_path.display().to_string())
                .with_detail("count", candidates.len()),
        );
    }

    // Warn about stub flags on stderr (for all formats, machine-parseable too)
    if !stub_flags_used.is_empty() {
        eprintln!(
            "warning: flags {} are parsed but not yet functional (coming in v1.2)",
            stub_flags_used.join(", ")
        );
    }

    // Handle --narrative flag (outputs prose regardless of format)
    if args.narrative {
        let narrative = generate_narrative_summary(
            &session_id,
            &candidates,
            &kill_candidates,
            &review_candidates,
            total_scanned,
            expected_memory_freed_gb,
        );
        println!("{}", narrative);
        if let Some(ref e) = emitter {
            e.emit(ProgressEvent::new(
                pt_core::events::event_names::SESSION_ENDED,
                Phase::Session,
            ));
        }
        return if candidates.is_empty() {
            ExitCode::Clean
        } else {
            ExitCode::PlanReady
        };
    }

    // Output based on format
    match global.format {
        OutputFormat::Json => {
            // Build output based on --minimal, --brief, and --pretty flags
            let output_json = if args.brief {
                // Brief output: minimal fields + single-line rationale
                let brief_candidates: Vec<serde_json::Value> = candidates
                    .iter()
                    .map(|c| {
                        let rationale = generate_single_line_rationale(c);
                        serde_json::json!({
                            "pid": c["pid"],
                            "cmd": c["command_short"],
                            "score": c["score"],
                            "rec": c["recommendation"],
                            "why": rationale,
                        })
                    })
                    .collect();
                serde_json::json!({
                    "v": env!("CARGO_PKG_VERSION"),
                    "sid": session_id.0,
                    "n": candidates.len(),
                    "kill": kill_candidates.len(),
                    "review": review_candidates.len(),
                    "c": brief_candidates,
                })
            } else if args.minimal {
                // Minimal output: just PIDs, scores, and recommendations
                let minimal_candidates: Vec<serde_json::Value> = candidates
                    .iter()
                    .map(|c| {
                        serde_json::json!({
                            "pid": c["pid"],
                            "score": c["score"],
                            "recommendation": c["recommendation"],
                        })
                    })
                    .collect();
                serde_json::json!({
                    "pt_version": env!("CARGO_PKG_VERSION"),
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "session_id": session_id.0,
                    "candidates": minimal_candidates,
                    "recommendations": recommendations,
                })
            } else {
                plan_output.clone()
            };

            // Apply pretty-printing or compact based on --pretty flag
            let output_str = if args.pretty {
                serde_json::to_string_pretty(&output_json).unwrap()
            } else {
                // Use global.process_output for token-efficient processing if not pretty
                global.process_output(output_json)
            };
            println!("{}", output_str);
        }
        OutputFormat::Toon => {
            let output_json = if args.brief {
                // Brief output for TOON: minimal fields + single-line rationale
                let brief_candidates: Vec<serde_json::Value> = candidates
                    .iter()
                    .map(|c| {
                        let rationale = generate_single_line_rationale(c);
                        serde_json::json!({
                            "p": c["pid"],
                            "c": c["command_short"],
                            "s": c["score"],
                            "r": c["recommendation"],
                            "w": rationale,
                        })
                    })
                    .collect();
                serde_json::json!({
                    "v": env!("CARGO_PKG_VERSION"),
                    "i": session_id.0,
                    "n": candidates.len(),
                    "k": kill_candidates.len(),
                    "r": review_candidates.len(),
                    "c": brief_candidates,
                })
            } else if args.minimal {
                let minimal_candidates: Vec<serde_json::Value> = candidates
                    .iter()
                    .map(|c| {
                        serde_json::json!({
                            "pid": c["pid"],
                            "score": c["score"],
                            "recommendation": c["recommendation"],
                        })
                    })
                    .collect();
                serde_json::json!({
                    "pt_version": env!("CARGO_PKG_VERSION"),
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "session_id": session_id.0,
                    "candidates": minimal_candidates,
                    "recommendations": recommendations,
                })
            } else {
                plan_output.clone()
            };

            let output_value = if args.pretty {
                output_json
            } else {
                global.process_output_value(output_json)
            };
            println!("{}", encode_toon_value(&output_value));
        }
        OutputFormat::Summary => {
            println!(
                "[{}] agent plan: {} candidates ({} kill, {} review)",
                session_id,
                candidates.len(),
                kill_candidates.len(),
                review_candidates.len()
            );
        }
        OutputFormat::Exitcode => {}
        _ => {
            println!("# pt-core agent plan\n");
            println!("Session: {}", session_id);
            println!("Plan: {}\n", plan_path.display());
            println!("## Summary\n");
            println!("- Processes scanned: {}", scan_result.processes.len());
            println!("- Candidates identified: {}", candidates.len());
            println!("- Kill recommendations: {}", kill_candidates.len());
            println!("- Review recommendations: {}", review_candidates.len());
            println!("\n## Candidates\n");
            for candidate in &candidates {
                let pid = candidate.get("pid").and_then(|v| v.as_u64()).unwrap_or(0);
                let cmd = candidate
                    .get("command_short")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let class = candidate
                    .get("classification")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let action = candidate
                    .get("recommended_action")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                println!("- PID {}: {} ({}) → {}", pid, cmd, class, action);
            }
        }
    }

    if let Some(ref e) = emitter {
        e.emit(ProgressEvent::new(
            pt_core::events::event_names::SESSION_ENDED,
            Phase::Session,
        ));
    }

    // Return appropriate exit code
    if candidates.is_empty() {
        ExitCode::Clean // 0: nothing to do
    } else {
        ExitCode::PlanReady // 1: candidates exist, plan produced
    }
}

fn run_agent_explain(global: &GlobalOpts, args: &AgentExplainArgs) -> ExitCode {
    let store = match SessionStore::from_env() {
        Ok(store) => store,
        Err(e) => {
            eprintln!("agent explain: session store error: {}", e);
            return ExitCode::InternalError;
        }
    };
    let sid = match SessionId::parse(&args.session) {
        Some(sid) => sid,
        None => {
            eprintln!("agent explain: invalid --session {}", args.session);
            return ExitCode::ArgsError;
        }
    };
    let handle = match store.open(&sid) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("agent explain: {}", e);
            return ExitCode::ArgsError;
        }
    };

    // Load priors from config or use defaults
    let priors = match load_priors_for_explain(global) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("agent explain: failed to load priors: {}", e);
            return ExitCode::InternalError;
        }
    };

    // Determine which PIDs to explain
    let pids_to_explain: Vec<u32> = if !args.pids.is_empty() {
        args.pids.clone()
    } else if let Some(ref target) = args.target {
        // Parse target format "pid:start_id" and extract PID
        match target.split(':').next().and_then(|s| s.parse::<u32>().ok()) {
            Some(pid) => vec![pid],
            None => {
                eprintln!("agent explain: invalid --target format, expected pid:start_id");
                return ExitCode::ArgsError;
            }
        }
    } else {
        eprintln!("agent explain: must specify --pids or --target");
        return ExitCode::ArgsError;
    };

    // Quick scan to get process records for the specified PIDs
    let scan_options = QuickScanOptions {
        pids: pids_to_explain.clone(),
        include_kernel_threads: false,
        timeout: global.timeout.map(std::time::Duration::from_secs),
        progress: None,
    };

    let scan_result = match quick_scan(&scan_options) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("agent explain: scan failed: {}", e);
            return ExitCode::InternalError;
        }
    };

    // Build explanations for each process
    let mut explanations: Vec<serde_json::Value> = Vec::new();

    for pid in &pids_to_explain {
        let record = scan_result.processes.iter().find(|p| p.pid.0 == *pid);
        match record {
            Some(proc) => {
                let explanation = build_process_explanation(proc, &priors, args);
                explanations.push(explanation);
            }
            None => {
                // Process not found - might have exited
                explanations.push(serde_json::json!({
                    "pid": pid,
                    "error": "process not found (may have exited)",
                    "classification": null,
                }));
            }
        }
    }

    // Output in requested format
    let output = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "session_id": sid.0,
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "command": "agent explain",
        "explanations": explanations,
    });

    // Optionally save to session
    let explain_path = handle.dir.join("inference").join("explain.json");
    if let Err(e) = std::fs::write(
        &explain_path,
        serde_json::to_string_pretty(&output).unwrap(),
    ) {
        eprintln!("agent explain: warning: failed to save to session: {}", e);
    }

    match global.format {
        OutputFormat::Json | OutputFormat::Toon => {
            println!("{}", format_structured_output(global, output));
        }
        OutputFormat::Summary => {
            for expl in &explanations {
                if let (Some(pid), Some(class)) = (expl.get("pid"), expl.get("classification")) {
                    let conf = expl
                        .get("confidence")
                        .and_then(|v| v.as_str())
                        .unwrap_or("?");
                    println!("[{}] PID {}: {} ({})\n", sid, pid, class, conf);
                }
            }
        }
        OutputFormat::Exitcode => {}
        _ => {
            // Human readable markdown output
            println!("# pt-core agent explain\n");
            println!("Session: {}", sid);
            println!();

            for expl in &explanations {
                let pid = expl.get("pid").and_then(|v| v.as_u64()).unwrap_or(0);

                if let Some(err) = expl.get("error") {
                    println!("## PID {}\n", pid);
                    println!("Error: {}\n", err);
                    continue;
                }

                let class = expl
                    .get("classification")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let conf = expl
                    .get("confidence")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let why = expl
                    .get("why_summary")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                println!("## PID {} - {} ({})\n", pid, class, conf);
                if !why.is_empty() {
                    println!("{}\n", why);
                }

                // Show posterior probabilities
                if let Some(posterior) = expl.get("posterior") {
                    println!("### Posterior Probabilities\n");
                    println!("| Class | P(C|x) |");
                    println!("|-------|--------|");
                    for class_name in &["useful", "useful_bad", "abandoned", "zombie"] {
                        if let Some(p) = posterior.get(*class_name).and_then(|v| v.as_f64()) {
                            println!("| {} | {:.4} |", class_name, p);
                        }
                    }
                    println!();
                }

                // Show top evidence if galaxy_brain mode
                if args.galaxy_brain {
                    if let Some(factors) = expl.get("bayes_factors").and_then(|v| v.as_array()) {
                        println!("### Evidence Breakdown\n");
                        println!("| Feature | BF | Direction | Strength |");
                        println!("|---------|-----|-----------|----------|");
                        for bf in factors.iter().take(5) {
                            let feat = bf.get("feature").and_then(|v| v.as_str()).unwrap_or("?");
                            let bf_val = bf.get("bf").and_then(|v| v.as_f64()).unwrap_or(0.0);
                            let dir = bf.get("direction").and_then(|v| v.as_str()).unwrap_or("?");
                            let strength =
                                bf.get("strength").and_then(|v| v.as_str()).unwrap_or("?");
                            // Format BF: use scientific notation for extreme values
                            let bf_str = if bf_val.is_infinite()
                                || bf_val > 1e6
                                || (bf_val < 1e-6 && bf_val > 0.0)
                            {
                                format!("{:.2e}", bf_val)
                            } else {
                                format!("{:.2}", bf_val)
                            };
                            println!("| {} | {} | {} | {} |", feat, bf_str, dir, strength);
                        }
                        println!();
                    }
                }
            }
        }
    }

    ExitCode::Clean
}

/// Load priors from config with fallback to defaults.
fn load_priors_for_explain(global: &GlobalOpts) -> Result<Priors, ConfigError> {
    let opts = ConfigOptions {
        config_dir: global.config.as_ref().map(PathBuf::from),
        priors_path: None,
        policy_path: None,
    };
    match load_config(&opts) {
        Ok(resolved) => Ok(resolved.priors),
        Err(_) => Ok(Priors::default()),
    }
}

/// Build a JSON explanation for a single process.
fn build_process_explanation(
    proc: &ProcessRecord,
    priors: &Priors,
    args: &AgentExplainArgs,
) -> serde_json::Value {
    // Convert ProcessRecord to Evidence
    let evidence = Evidence {
        cpu: Some(CpuEvidence::Fraction {
            occupancy: (proc.cpu_percent / 100.0).clamp(0.0, 1.0),
        }),
        runtime_seconds: Some(proc.elapsed.as_secs_f64()),
        orphan: Some(proc.is_orphan()),
        tty: Some(proc.has_tty()),
        net: None,       // Would need network scan
        io_active: None, // Would need /proc inspection
        state_flag: state_to_flag(proc.state),
        command_category: None, // Would need category classifier
    };

    // Compute posterior
    let posterior_result = match compute_posterior(priors, &evidence) {
        Ok(r) => r,
        Err(e) => {
            return serde_json::json!({
                "pid": proc.pid.0,
                "comm": proc.comm,
                "error": format!("posterior computation failed: {}", e),
            });
        }
    };

    // Build evidence ledger
    let ledger = EvidenceLedger::from_posterior_result(&posterior_result, Some(proc.pid.0), None);

    // Build base explanation
    let mut explanation = serde_json::json!({
        "pid": proc.pid.0,
        "ppid": proc.ppid.0,
        "comm": proc.comm,
        "user": proc.user,
        "state": proc.state.to_string(),
        "elapsed_seconds": proc.elapsed.as_secs(),
        "cpu_percent": proc.cpu_percent,
        "classification": ledger.classification.label(),
        "confidence": ledger.confidence.label(),
        "why_summary": ledger.why_summary,
        "posterior": {
            "useful": posterior_result.posterior.useful,
            "useful_bad": posterior_result.posterior.useful_bad,
            "abandoned": posterior_result.posterior.abandoned,
            "zombie": posterior_result.posterior.zombie,
        },
    });

    // Add Bayes factors if galaxy_brain mode or requested
    if args.galaxy_brain || args.include.contains(&"bayes_factors".to_string()) {
        let bf_entries: Vec<serde_json::Value> = ledger
            .bayes_factors
            .iter()
            .map(|bf| {
                serde_json::json!({
                    "feature": bf.feature,
                    "log_bf": bf.log_bf,
                    "bf": bf.bf,
                    "delta_bits": bf.delta_bits,
                    "direction": format!("{}", bf.direction),
                    "strength": bf.strength.clone(),
                })
            })
            .collect();
        explanation["bayes_factors"] = serde_json::json!(bf_entries);
        explanation["top_evidence"] = serde_json::json!(ledger.top_evidence);
    }

    // Add input evidence if requested
    if args.include.contains(&"evidence".to_string()) {
        explanation["evidence"] = serde_json::json!({
            "cpu_occupancy": proc.cpu_percent / 100.0,
            "runtime_seconds": proc.elapsed.as_secs_f64(),
            "is_orphan": proc.is_orphan(),
            "has_tty": proc.has_tty(),
            "state": proc.state.to_string(),
        });
    }

    explanation
}

/// Map ProcessState to state flag index for priors.
fn state_to_flag(state: pt_core::collect::ProcessState) -> Option<usize> {
    use pt_core::collect::ProcessState;
    match state {
        ProcessState::Running => Some(0),
        ProcessState::Sleeping => Some(1),
        ProcessState::DiskSleep => Some(2),
        ProcessState::Zombie => Some(3),
        ProcessState::Stopped => Some(4),
        ProcessState::Idle => Some(5),
        ProcessState::Dead => Some(6),
        ProcessState::Unknown => None,
    }
}

#[cfg(target_os = "linux")]
fn supervisor_info_for_plan(pid: u32) -> serde_json::Value {
    let mut detected = false;
    let mut supervisor_type: Option<String> = None;
    let mut unit: Option<String> = None;
    let mut recommended_action = "kill".to_string();
    let mut supervisor_command: Option<String> = None;

    // Prefer container supervision if present
    if let Ok(result) = ContainerSupervisionAnalyzer::new()
        .with_action_recommendations()
        .analyze(pid)
    {
        if result.is_supervised {
            detected = true;
            let runtime_label = if result.kubernetes.is_some() {
                "kubernetes"
            } else {
                match result.runtime {
                    ContainerRuntime::Docker => "docker",
                    ContainerRuntime::Containerd => "containerd",
                    ContainerRuntime::Podman => "podman",
                    ContainerRuntime::Lxc => "lxc",
                    ContainerRuntime::Crio => "crio",
                    ContainerRuntime::Generic => "container",
                    ContainerRuntime::None => "container",
                }
            };
            supervisor_type = Some(runtime_label.to_string());
            unit = result
                .container_id_short
                .clone()
                .or(result.container_id.clone())
                .or_else(|| result.kubernetes.as_ref().and_then(|k| k.pod_name.clone()));

            if let Some(action) = result.recommended_action.as_ref() {
                let action_label = match action.action_type {
                    ContainerActionType::Stop => "stop",
                    ContainerActionType::Restart => "restart",
                    ContainerActionType::Remove => "remove",
                    ContainerActionType::ScaleDown => "scale_down",
                    ContainerActionType::DeletePod => "delete_pod",
                    ContainerActionType::Inspect => "inspect",
                };
                recommended_action = format!("{}_{}", runtime_label, action_label);
                supervisor_command = Some(action.command.clone());
            } else {
                recommended_action = format!("{}_review", runtime_label);
            }
        }
    }

    // App supervisors (pm2, supervisord, etc.)
    if !detected {
        if let Ok(result) = AppSupervisionAnalyzer::new().analyze(pid) {
            if result.is_supervised && result.supervisor_type != AppSupervisorType::Unknown {
                detected = true;
                let supervisor_label = result.supervisor_type.to_string();
                supervisor_type = Some(supervisor_label.clone());
                unit = result
                    .pm2_name
                    .clone()
                    .or(result.supervisord_program.clone())
                    .or(result.supervisor_name.clone());

                if let Some(action) = result.recommended_action.as_ref() {
                    let action_label = match action.action_type {
                        AppActionType::Stop => "stop",
                        AppActionType::Restart => "restart",
                        AppActionType::Delete => "delete",
                        AppActionType::Status => "status",
                        AppActionType::Logs => "logs",
                    };
                    recommended_action = format!("{}_{}", supervisor_label, action_label);
                    supervisor_command = Some(action.command.clone());
                } else {
                    recommended_action = format!("{}_review", supervisor_label);
                }
            }
        }
    }

    // systemd supervision
    if !detected {
        if let Some(unit_info) = collect_systemd_unit(pid, None) {
            detected = true;
            supervisor_type = Some("systemd".to_string());
            unit = Some(unit_info.name.clone());
            let (action_label, command) = match unit_info.unit_type {
                pt_core::collect::systemd::SystemdUnitType::Scope => (
                    "systemctl_stop",
                    format!("systemctl stop {}", unit_info.name),
                ),
                _ => (
                    "systemctl_restart",
                    format!("systemctl restart {}", unit_info.name),
                ),
            };
            recommended_action = action_label.to_string();
            supervisor_command = Some(command);
        }
    }

    // Human supervision (agents/IDEs/CI) for warning-only
    if !detected {
        if let Ok(result) = detect_supervision(pid) {
            if is_human_supervised(&result) {
                detected = true;
                supervisor_type = result.supervisor_type.map(|t| t.to_string());
                unit = result.supervisor_name.clone();
                recommended_action = "review".to_string();
            }
        }
    }

    serde_json::json!({
        "detected": detected,
        "type": supervisor_type,
        "unit": unit,
        "recommended_action": recommended_action,
        "supervisor_command": supervisor_command,
    })
}

#[cfg(not(target_os = "linux"))]
fn supervisor_info_for_plan(_pid: u32) -> serde_json::Value {
    serde_json::json!({
        "detected": false,
        "type": serde_json::Value::Null,
        "unit": serde_json::Value::Null,
        "recommended_action": "kill",
        "supervisor_command": serde_json::Value::Null,
    })
}

#[cfg(target_os = "linux")]
fn is_supervised_for_robot(pid: u32) -> bool {
    match detect_supervision(pid) {
        Ok(result) => is_human_supervised(&result),
        Err(_) => false,
    }
}

#[cfg(not(target_os = "linux"))]
fn is_supervised_for_robot(_pid: u32) -> bool {
    false
}

#[cfg(target_os = "linux")]
fn first_precheck_block(
    provider: &dyn pt_core::action::prechecks::PreCheckProvider,
    action: &PlanAction,
) -> Option<(pt_core::plan::PreCheck, String)> {
    let results = provider.run_checks(&action.pre_checks, action.target.pid.0, action.target.sid);
    for result in results {
        if let pt_core::action::prechecks::PreCheckResult::Blocked { check, reason } = result {
            return Some((check, reason));
        }
    }
    None
}

fn precheck_label_for_apply(check: &pt_core::plan::PreCheck) -> &'static str {
    use pt_core::plan::PreCheck;
    match check {
        PreCheck::VerifyIdentity => "verify_identity",
        PreCheck::CheckNotProtected => "check_not_protected",
        PreCheck::CheckSessionSafety => "check_session_safety",
        PreCheck::CheckDataLossGate => "check_data_loss_gate",
        PreCheck::CheckSupervisor => "check_supervisor",
        PreCheck::CheckAgentSupervision => "check_agent_supervision",
        PreCheck::VerifyProcessState => "verify_process_state",
    }
}

#[cfg(target_os = "linux")]
fn read_mem_available_bytes_for_goal_progress() -> u64 {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|content| {
            content.lines().find_map(|line| {
                line.strip_prefix("MemAvailable:")
                    .and_then(|rest| rest.split_whitespace().next())
                    .and_then(|value| value.parse::<u64>().ok())
            })
        })
        .map(|kb| kb.saturating_mul(1024))
        .unwrap_or(0)
}

#[cfg(not(target_os = "linux"))]
fn read_mem_available_bytes_for_goal_progress() -> u64 {
    0
}

#[cfg(target_os = "linux")]
fn collect_occupied_ports_for_goal_progress() -> Vec<u16> {
    let mut ports = BTreeSet::new();

    if let Some(entries) = parse_proc_net_tcp("/proc/net/tcp", false) {
        for entry in entries.into_iter().filter(|e| e.state.is_listen()) {
            ports.insert(entry.local_port);
        }
    }
    if let Some(entries) = parse_proc_net_tcp("/proc/net/tcp6", true) {
        for entry in entries.into_iter().filter(|e| e.state.is_listen()) {
            ports.insert(entry.local_port);
        }
    }
    if let Some(entries) = parse_proc_net_udp("/proc/net/udp", false) {
        for entry in entries
            .into_iter()
            .filter(|e| e.local_port > 0 && e.remote_port == 0)
        {
            ports.insert(entry.local_port);
        }
    }
    if let Some(entries) = parse_proc_net_udp("/proc/net/udp6", true) {
        for entry in entries
            .into_iter()
            .filter(|e| e.local_port > 0 && e.remote_port == 0)
        {
            ports.insert(entry.local_port);
        }
    }

    ports.into_iter().collect()
}

#[cfg(not(target_os = "linux"))]
fn collect_occupied_ports_for_goal_progress() -> Vec<u16> {
    Vec::new()
}

#[cfg(target_os = "linux")]
fn collect_total_fds_for_goal_progress(processes: &[ProcessRecord]) -> u64 {
    processes
        .iter()
        .filter_map(|proc| parse_fd(proc.pid.0).map(|fd| fd.count as u64))
        .sum()
}

#[cfg(not(target_os = "linux"))]
fn collect_total_fds_for_goal_progress(_processes: &[ProcessRecord]) -> u64 {
    0
}

fn capture_metric_snapshot_for_goal_progress(processes: &[ProcessRecord]) -> MetricSnapshot {
    let total_cpu_frac = processes
        .iter()
        .map(|proc| (proc.cpu_percent / 100.0).max(0.0))
        .sum();

    MetricSnapshot {
        available_memory_bytes: read_mem_available_bytes_for_goal_progress(),
        total_cpu_frac,
        occupied_ports: collect_occupied_ports_for_goal_progress(),
        total_fds: collect_total_fds_for_goal_progress(processes),
        timestamp: chrono::Utc::now().timestamp_millis() as f64 / 1000.0,
    }
}

fn normalize_command_signature_for_goal_progress(cmd: &str) -> String {
    cmd.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn detect_respawn_for_goal_progress(
    action: &PlanAction,
    action_success: bool,
    before_by_pid: &HashMap<u32, &ProcessRecord>,
    after_by_pid: &HashMap<u32, &ProcessRecord>,
    after_processes: &[ProcessRecord],
) -> bool {
    if !action_success {
        return false;
    }

    let pid = action.target.pid.0;
    let Some(before_proc) = before_by_pid.get(&pid).copied() else {
        return false;
    };

    if let Some(after_proc) = after_by_pid.get(&pid).copied() {
        return after_proc.start_id.0 != before_proc.start_id.0;
    }

    let before_cmd = normalize_command_signature_for_goal_progress(&before_proc.cmd);
    after_processes.iter().any(|proc| {
        proc.uid == before_proc.uid
            && proc.pid.0 != pid
            && proc.start_time_unix >= before_proc.start_time_unix
            && normalize_command_signature_for_goal_progress(&proc.cmd) == before_cmd
    })
}

fn goal_report_brief_json(report: &GoalProgressReport) -> serde_json::Value {
    serde_json::json!({
        "expected": report.expected_progress,
        "observed": report.observed_progress,
        "discrepancy": report.discrepancy,
        "discrepancy_fraction": report.discrepancy_fraction,
        "classification": report.classification.to_string(),
        "suspected_causes": report.suspected_causes.iter().map(|cause| cause.cause.clone()).collect::<Vec<_>>(),
    })
}

fn run_agent_apply(global: &GlobalOpts, args: &AgentApplyArgs) -> ExitCode {
    let _lock = match acquire_global_lock(global, "agent apply") {
        Ok(lock) => lock,
        Err(code) => return code,
    };
    // Load configuration
    let config = match load_config(&config_options(global)) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("agent apply: config error: {}", e);
            return ExitCode::InternalError;
        }
    };

    // Open session store and session
    let store = match SessionStore::from_env() {
        Ok(store) => store,
        Err(e) => {
            eprintln!("agent apply: session store error: {}", e);
            return ExitCode::InternalError;
        }
    };
    let sid = match SessionId::parse(&args.session) {
        Some(sid) => sid,
        None => {
            eprintln!("agent apply: invalid --session {}", args.session);
            return ExitCode::ArgsError;
        }
    };
    let handle = match store.open(&sid) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("agent apply: {}", e);
            return ExitCode::ArgsError;
        }
    };

    let emitter = session_progress_emitter(global, &handle, &sid);
    if let Some(ref e) = emitter {
        e.emit(ProgressEvent::new(
            pt_core::events::event_names::SESSION_STARTED,
            Phase::Session,
        ));
    }

    // Load the plan from decision/plan.json
    let plan_path = handle.dir.join("decision").join("plan.json");
    if !plan_path.exists() {
        eprintln!("agent apply: no plan.json found for session {}", sid);
        return ExitCode::ArgsError;
    }
    let plan_content = match std::fs::read_to_string(&plan_path) {
        Ok(content) => content,
        Err(e) => {
            eprintln!("agent apply: failed to read {}: {}", plan_path.display(), e);
            return ExitCode::IoError;
        }
    };
    let plan: Plan = match serde_json::from_str(&plan_content) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("agent apply: invalid plan.json: {}", e);
            return ExitCode::InternalError;
        }
    };

    // Load completed action IDs for --resume mode
    let completed_action_ids: std::collections::HashSet<String> = if args.resume {
        let outcomes_path = handle.dir.join("action").join("outcomes.jsonl");
        if outcomes_path.exists() {
            std::fs::read_to_string(&outcomes_path)
                .ok()
                .map(|content| {
                    content
                        .lines()
                        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
                        .filter(|v| v.get("status").and_then(|s| s.as_str()) == Some("success"))
                        .filter_map(|v| {
                            v.get("action_id")
                                .and_then(|a| a.as_str())
                                .map(String::from)
                        })
                        .collect()
                })
                .unwrap_or_default()
        } else {
            std::collections::HashSet::new()
        }
    } else {
        std::collections::HashSet::new()
    };

    // Determine which actions to apply
    let use_recommended =
        args.recommended || (args.resume && args.pids.is_empty() && args.targets.is_empty());
    let mut target_pids: Vec<u32> = if use_recommended {
        plan.actions
            .iter()
            .filter(|a| !a.blocked)
            .map(|a| a.target.pid.0)
            .collect()
    } else if !args.pids.is_empty() {
        args.pids.clone()
    } else if !args.targets.is_empty() {
        args.targets
            .iter()
            .filter_map(|t| t.split(':').next().and_then(|p| p.parse().ok()))
            .collect()
    } else {
        eprintln!("agent apply: must specify --recommended, --pids, or --targets");
        return ExitCode::ArgsError;
    };

    if let Some(min_age) = args.min_age {
        if !target_pids.is_empty() {
            let scan_options = QuickScanOptions {
                pids: target_pids.clone(),
                include_kernel_threads: false,
                timeout: global.timeout.map(std::time::Duration::from_secs),
                progress: None,
            };
            let scan_result = match quick_scan(&scan_options) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("agent apply: min-age scan failed: {}", e);
                    return ExitCode::InternalError;
                }
            };
            let eligible: HashSet<u32> = scan_result
                .processes
                .iter()
                .filter(|proc| proc.elapsed.as_secs() >= min_age)
                .map(|proc| proc.pid.0)
                .collect();
            target_pids.retain(|pid| eligible.contains(pid));
        }
    }

    if target_pids.is_empty() {
        if let Some(ref e) = emitter {
            e.emit(ProgressEvent::new(
                pt_core::events::event_names::SESSION_ENDED,
                Phase::Session,
            ));
        }
        output_apply_nothing(global, &sid);
        return ExitCode::Clean;
    }

    // Filter out completed actions using earlier declaration for --resume mode
    let actions_to_apply: Vec<_> = plan
        .actions
        .iter()
        .filter(|a| target_pids.contains(&a.target.pid.0))
        .filter(|a| !completed_action_ids.contains(&a.action_id))
        .collect();
    if actions_to_apply.is_empty() {
        if let Some(ref e) = emitter {
            e.emit(ProgressEvent::new(
                pt_core::events::event_names::SESSION_ENDED,
                Phase::Session,
            ));
        }
        output_apply_nothing(global, &sid);
        return ExitCode::Clean;
    }

    let goal_progress_scan_options = QuickScanOptions {
        pids: vec![],
        include_kernel_threads: false,
        timeout: global.timeout.map(std::time::Duration::from_secs),
        progress: None,
    };

    let before_scan_processes = quick_scan(&goal_progress_scan_options)
        .map(|scan| scan.processes)
        .unwrap_or_else(|_| Vec::new());
    let before_snapshot = capture_metric_snapshot_for_goal_progress(&before_scan_processes);
    let before_by_pid: HashMap<u32, &ProcessRecord> = before_scan_processes
        .iter()
        .map(|proc| (proc.pid.0, proc))
        .collect();

    #[cfg(target_os = "linux")]
    let before_network_snapshot = NetworkSnapshot::collect();

    let mut expected_by_action: HashMap<String, (f64, f64, f64, f64, String)> = HashMap::new();
    for action in &actions_to_apply {
        let pid = action.target.pid.0;
        let before_proc = before_by_pid.get(&pid).copied();
        let label = before_proc
            .map(|proc| proc.cmd.clone())
            .unwrap_or_else(|| format!("pid {}", pid));

        let memory_expected = if matches!(
            action.action,
            Action::Kill | Action::Restart | Action::Pause
        ) {
            action
                .rationale
                .memory_mb
                .unwrap_or(0.0)
                .max(0.0)
                .mul_add(1_048_576.0, 0.0)
        } else {
            0.0
        };
        let cpu_expected = if matches!(
            action.action,
            Action::Kill
                | Action::Restart
                | Action::Pause
                | Action::Freeze
                | Action::Quarantine
                | Action::Throttle
        ) {
            before_proc
                .map(|proc| (proc.cpu_percent / 100.0).max(0.0))
                .unwrap_or(0.0)
        } else {
            0.0
        };

        #[cfg(target_os = "linux")]
        let port_expected = if matches!(
            action.action,
            Action::Kill | Action::Restart | Action::Pause | Action::Freeze
        ) {
            before_network_snapshot
                .get_process_info(pid)
                .map(|info| {
                    info.listen_ports
                        .iter()
                        .map(|port| port.port)
                        .collect::<HashSet<_>>()
                        .len() as f64
                })
                .unwrap_or(0.0)
        } else {
            0.0
        };
        #[cfg(not(target_os = "linux"))]
        let port_expected = 0.0;

        #[cfg(target_os = "linux")]
        let fd_expected = if matches!(
            action.action,
            Action::Kill | Action::Restart | Action::Pause | Action::Freeze
        ) {
            parse_fd(pid).map(|fd| fd.count as f64).unwrap_or(0.0)
        } else {
            0.0
        };
        #[cfg(not(target_os = "linux"))]
        let fd_expected = 0.0;

        expected_by_action.insert(
            action.action_id.clone(),
            (
                memory_expected,
                cpu_expected,
                port_expected,
                fd_expected,
                label,
            ),
        );
    }

    let total_actions = actions_to_apply.len() as u64;
    let mut action_index = 0u64;
    let emit_action_event = |event_name: &str,
                             index: u64,
                             elapsed_ms: Option<u64>,
                             action: &PlanAction,
                             status: &str,
                             extra: &[(&str, serde_json::Value)]| {
        if let Some(ref e) = emitter {
            let mut event = ProgressEvent::new(event_name, Phase::Apply)
                .with_progress(index, Some(total_actions))
                .with_detail("action_id", &action.action_id)
                .with_detail("pid", action.target.pid.0)
                .with_detail("action", format!("{:?}", action.action))
                .with_detail("status", status);
            if let Some(ms) = elapsed_ms {
                event = event.with_elapsed_ms(ms);
            }
            for (key, value) in extra {
                event = event.with_detail(*key, value);
            }
            e.emit(event);
        }
    };

    // Check --yes requirement
    if !args.yes && !global.dry_run && !global.shadow {
        let err = serde_json::json!({"session_id": sid.0, "error": "confirmation_required", "message": "--yes flag required for execution"});
        println!("{}", serde_json::to_string_pretty(&err).unwrap());
        return ExitCode::PolicyBlocked;
    }

    // Build robot constraints from policy + CLI overrides
    let constraints = RuntimeRobotConstraints::from_policy(&config.policy.robot_mode)
        .with_min_posterior(args.min_posterior)
        .with_max_blast_radius_mb(args.max_blast_radius)
        .with_max_total_blast_radius_mb(args.max_total_blast_radius)
        .with_max_kills(args.max_kills)
        .with_require_known_signature(if args.require_known_signature {
            Some(true)
        } else {
            None
        })
        .with_allow_categories(if args.only_categories.is_empty() {
            None
        } else {
            Some(args.only_categories.clone())
        })
        .with_exclude_categories(args.exclude_categories.clone());

    let checker = ConstraintChecker::new(constraints.clone());
    let constraints_summary = constraints.active_constraints_summary();
    let _ = handle.update_state(SessionState::Executing);

    #[cfg(target_os = "linux")]
    let precheck_provider = {
        use pt_core::action::{LivePreCheckConfig, LivePreCheckProvider};
        LivePreCheckProvider::new(
            Some(&config.policy.guardrails),
            LivePreCheckConfig::from(&config.policy.data_loss_gates),
        )
        .unwrap_or_else(|_| LivePreCheckProvider::with_defaults())
    };

    let mut outcomes: Vec<serde_json::Value> = Vec::new();
    let mut succeeded = 0usize;
    let mut failed = 0usize;
    let mut skipped = 0usize;
    let mut blocked_by_constraints = 0usize;
    let mut blocked_by_prechecks = 0usize;
    let mut resumed_skipped = 0usize;

    // Handle dry-run/shadow mode or execute
    if global.dry_run || global.shadow {
        for action in &actions_to_apply {
            action_index = action_index.saturating_add(1);
            emit_action_event(
                pt_core::events::event_names::ACTION_STARTED,
                action_index,
                None,
                action,
                "started",
                &[(
                    "mode",
                    serde_json::json!(if global.dry_run { "dry_run" } else { "shadow" }),
                )],
            );

            // Skip already completed actions in resume mode
            if completed_action_ids.contains(&action.action_id) {
                resumed_skipped += 1;
                outcomes.push(serde_json::json!({
                    "action_id": action.action_id,
                    "pid": action.target.pid.0,
                    "status": "already_completed",
                    "resume": true
                }));
                emit_action_event(
                    pt_core::events::event_names::ACTION_COMPLETE,
                    action_index,
                    None,
                    action,
                    "already_completed",
                    &[("resume", serde_json::json!(true))],
                );
                continue;
            }

            if action.blocked {
                blocked_by_prechecks += 1;
                outcomes.push(serde_json::json!({
                    "action_id": action.action_id,
                    "pid": action.target.pid.0,
                    "status": "blocked_by_plan"
                }));
                emit_action_event(
                    pt_core::events::event_names::ACTION_COMPLETE,
                    action_index,
                    None,
                    action,
                    "blocked_by_plan",
                    &[],
                );
                continue;
            }

            let candidate = RobotCandidate {
                posterior: action.rationale.posterior_odds_abandoned_vs_useful,
                memory_mb: None,
                has_known_signature: false,
                category: None,
                is_kill_action: action.action == Action::Kill,
                has_policy_snapshot: true,
                is_supervised: is_supervised_for_robot(action.target.pid.0),
            };
            let check = checker.check_candidate(&candidate);
            if !check.allowed {
                blocked_by_constraints += 1;
                outcomes.push(serde_json::json!({"action_id": action.action_id, "pid": action.target.pid.0, "status": "blocked_by_constraints"}));
                emit_action_event(
                    pt_core::events::event_names::ACTION_COMPLETE,
                    action_index,
                    None,
                    action,
                    "blocked_by_constraints",
                    &[],
                );
                continue;
            }

            #[cfg(target_os = "linux")]
            if let Some((check, reason)) = first_precheck_block(&precheck_provider, action) {
                blocked_by_prechecks += 1;
                outcomes.push(serde_json::json!({
                    "action_id": action.action_id,
                    "pid": action.target.pid.0,
                    "status": "precheck_blocked",
                    "check": precheck_label_for_apply(&check),
                    "reason": reason
                }));
                emit_action_event(
                    pt_core::events::event_names::ACTION_COMPLETE,
                    action_index,
                    None,
                    action,
                    "precheck_blocked",
                    &[("check", serde_json::json!(precheck_label_for_apply(&check)))],
                );
                continue;
            }

            skipped += 1;
            outcomes.push(serde_json::json!({"action_id": action.action_id, "pid": action.target.pid.0, "status": if global.dry_run { "dry_run" } else { "shadow" }}));
            emit_action_event(
                pt_core::events::event_names::ACTION_COMPLETE,
                action_index,
                None,
                action,
                if global.dry_run { "dry_run" } else { "shadow" },
                &[],
            );
        }
    } else {
        #[cfg(target_os = "linux")]
        {
            let identity_provider = LiveIdentityProvider::new();
            let signal_runner = SignalActionRunner::new(SignalConfig::default());

            for action in &actions_to_apply {
                action_index = action_index.saturating_add(1);
                emit_action_event(
                    pt_core::events::event_names::ACTION_STARTED,
                    action_index,
                    None,
                    action,
                    "started",
                    &[],
                );

                // Skip already completed actions in resume mode
                if completed_action_ids.contains(&action.action_id) {
                    resumed_skipped += 1;
                    outcomes.push(serde_json::json!({
                        "action_id": action.action_id,
                        "pid": action.target.pid.0,
                        "status": "already_completed",
                        "resume": true
                    }));
                    emit_action_event(
                        pt_core::events::event_names::ACTION_COMPLETE,
                        action_index,
                        None,
                        action,
                        "already_completed",
                        &[("resume", serde_json::json!(true))],
                    );
                    continue;
                }

                if action.blocked {
                    blocked_by_prechecks += 1;
                    outcomes.push(serde_json::json!({
                        "action_id": action.action_id,
                        "pid": action.target.pid.0,
                        "status": "blocked_by_plan"
                    }));
                    emit_action_event(
                        pt_core::events::event_names::ACTION_COMPLETE,
                        action_index,
                        None,
                        action,
                        "blocked_by_plan",
                        &[],
                    );
                    if args.abort_on_unknown {
                        break;
                    }
                    continue;
                }

                let start = std::time::Instant::now();
                let candidate = RobotCandidate {
                    posterior: action.rationale.posterior_odds_abandoned_vs_useful,
                    memory_mb: None,
                    has_known_signature: false,
                    category: None,
                    is_kill_action: action.action == Action::Kill,
                    has_policy_snapshot: true,
                    is_supervised: is_supervised_for_robot(action.target.pid.0),
                };
                let check = checker.check_candidate(&candidate);
                if !check.allowed {
                    blocked_by_constraints += 1;
                    let elapsed_ms = start.elapsed().as_millis() as u64;
                    outcomes.push(serde_json::json!({"action_id": action.action_id, "pid": action.target.pid.0, "status": "blocked_by_constraints", "time_ms": elapsed_ms}));
                    emit_action_event(
                        pt_core::events::event_names::ACTION_COMPLETE,
                        action_index,
                        Some(elapsed_ms),
                        action,
                        "blocked_by_constraints",
                        &[],
                    );
                    if args.abort_on_unknown {
                        break;
                    }
                    continue;
                }
                match identity_provider.revalidate(&action.target) {
                    Ok(true) => {}
                    Ok(false) => {
                        failed += 1;
                        let elapsed_ms = start.elapsed().as_millis() as u64;
                        outcomes.push(serde_json::json!({"action_id": action.action_id, "pid": action.target.pid.0, "status": "identity_mismatch", "time_ms": elapsed_ms}));
                        emit_action_event(
                            pt_core::events::event_names::ACTION_FAILED,
                            action_index,
                            Some(elapsed_ms),
                            action,
                            "identity_mismatch",
                            &[],
                        );
                        if args.abort_on_unknown {
                            break;
                        }
                        continue;
                    }
                    Err(_) => {
                        failed += 1;
                        let elapsed_ms = start.elapsed().as_millis() as u64;
                        outcomes.push(serde_json::json!({"action_id": action.action_id, "pid": action.target.pid.0, "status": "identity_check_failed", "time_ms": elapsed_ms}));
                        emit_action_event(
                            pt_core::events::event_names::ACTION_FAILED,
                            action_index,
                            Some(elapsed_ms),
                            action,
                            "identity_check_failed",
                            &[],
                        );
                        if args.abort_on_unknown {
                            break;
                        }
                        continue;
                    }
                }
                if let Some((check, reason)) = first_precheck_block(&precheck_provider, action) {
                    blocked_by_prechecks += 1;
                    let elapsed_ms = start.elapsed().as_millis() as u64;
                    outcomes.push(serde_json::json!({
                        "action_id": action.action_id,
                        "pid": action.target.pid.0,
                        "status": "precheck_blocked",
                        "check": precheck_label_for_apply(&check),
                        "reason": reason,
                        "time_ms": elapsed_ms
                    }));
                    emit_action_event(
                        pt_core::events::event_names::ACTION_COMPLETE,
                        action_index,
                        Some(elapsed_ms),
                        action,
                        "precheck_blocked",
                        &[("check", serde_json::json!(precheck_label_for_apply(&check)))],
                    );
                    if args.abort_on_unknown {
                        break;
                    }
                    continue;
                }
                match signal_runner.execute(action) {
                    Ok(()) => {
                        if action.action == Action::Kill {
                            checker.record_action(0, true);
                        }
                        succeeded += 1;
                        let elapsed_ms = start.elapsed().as_millis() as u64;
                        outcomes.push(serde_json::json!({"action_id": action.action_id, "pid": action.target.pid.0, "status": "success", "time_ms": elapsed_ms}));
                        emit_action_event(
                            pt_core::events::event_names::ACTION_COMPLETE,
                            action_index,
                            Some(elapsed_ms),
                            action,
                            "success",
                            &[],
                        );
                    }
                    Err(e) => {
                        failed += 1;
                        let elapsed_ms = start.elapsed().as_millis() as u64;
                        outcomes.push(serde_json::json!({"action_id": action.action_id, "pid": action.target.pid.0, "status": "failed", "error": format!("{:?}", e), "time_ms": elapsed_ms}));
                        emit_action_event(
                            pt_core::events::event_names::ACTION_FAILED,
                            action_index,
                            Some(elapsed_ms),
                            action,
                            "failed",
                            &[("error", serde_json::json!(format!("{:?}", e)))],
                        );
                        if args.abort_on_unknown {
                            break;
                        }
                    }
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            for action in &actions_to_apply {
                action_index = action_index.saturating_add(1);
                emit_action_event(
                    pt_core::events::event_names::ACTION_STARTED,
                    action_index,
                    None,
                    action,
                    "started",
                    &[],
                );

                // Skip already completed actions in resume mode
                if completed_action_ids.contains(&action.action_id) {
                    resumed_skipped += 1;
                    outcomes.push(serde_json::json!({
                        "action_id": action.action_id,
                        "pid": action.target.pid.0,
                        "status": "already_completed",
                        "resume": true
                    }));
                    emit_action_event(
                        pt_core::events::event_names::ACTION_COMPLETE,
                        action_index,
                        None,
                        action,
                        "already_completed",
                        &[("resume", serde_json::json!(true))],
                    );
                    continue;
                }
                skipped += 1;
                outcomes.push(serde_json::json!({"action_id": action.action_id, "pid": action.target.pid.0, "status": "unsupported_platform"}));
                emit_action_event(
                    pt_core::events::event_names::ACTION_COMPLETE,
                    action_index,
                    None,
                    action,
                    "unsupported_platform",
                    &[],
                );
            }
        }
    }

    let after_scan_processes = quick_scan(&goal_progress_scan_options)
        .map(|scan| scan.processes)
        .unwrap_or_else(|_| Vec::new());
    let after_snapshot = capture_metric_snapshot_for_goal_progress(&after_scan_processes);
    let after_by_pid: HashMap<u32, &ProcessRecord> = after_scan_processes
        .iter()
        .map(|proc| (proc.pid.0, proc))
        .collect();

    let status_by_action: HashMap<String, String> = outcomes
        .iter()
        .filter_map(|outcome| {
            let action_id = outcome.get("action_id")?.as_str()?.to_string();
            let status = outcome
                .get("status")
                .and_then(|value| value.as_str())
                .unwrap_or("unknown")
                .to_string();
            Some((action_id, status))
        })
        .collect();

    let mut respawn_by_action: HashMap<String, bool> = HashMap::new();
    let mut memory_action_outcomes = Vec::new();
    let mut cpu_action_outcomes = Vec::new();
    let mut port_action_outcomes = Vec::new();
    let mut fd_action_outcomes = Vec::new();
    for action in &actions_to_apply {
        let status = status_by_action
            .get(&action.action_id)
            .map(|value| value.as_str())
            .unwrap_or("unknown");
        let success = matches!(status, "success" | "dry_run" | "shadow");
        let respawn_detected = detect_respawn_for_goal_progress(
            action,
            success,
            &before_by_pid,
            &after_by_pid,
            &after_scan_processes,
        );
        respawn_by_action.insert(action.action_id.clone(), respawn_detected);

        let (memory_expected, cpu_expected, port_expected, fd_expected, label) = expected_by_action
            .get(&action.action_id)
            .cloned()
            .unwrap_or_else(|| (0.0, 0.0, 0.0, 0.0, format!("pid {}", action.target.pid.0)));

        let action_pid = action.target.pid.0;
        memory_action_outcomes.push(GoalActionOutcome {
            pid: action_pid,
            label: label.clone(),
            success,
            respawn_detected,
            expected_contribution: memory_expected,
        });
        cpu_action_outcomes.push(GoalActionOutcome {
            pid: action_pid,
            label: label.clone(),
            success,
            respawn_detected,
            expected_contribution: cpu_expected,
        });
        port_action_outcomes.push(GoalActionOutcome {
            pid: action_pid,
            label: label.clone(),
            success,
            respawn_detected,
            expected_contribution: port_expected,
        });
        fd_action_outcomes.push(GoalActionOutcome {
            pid: action_pid,
            label,
            success,
            respawn_detected,
            expected_contribution: fd_expected,
        });
    }

    let progress_config = ProgressConfig::default();
    let memory_report = goal_progress::measure_progress(
        GoalMetric::Memory,
        None,
        &before_snapshot,
        &after_snapshot,
        memory_action_outcomes,
        &progress_config,
        Some(sid.0.clone()),
    );
    let cpu_report = goal_progress::measure_progress(
        GoalMetric::Cpu,
        None,
        &before_snapshot,
        &after_snapshot,
        cpu_action_outcomes,
        &progress_config,
        Some(sid.0.clone()),
    );
    let port_report = goal_progress::measure_progress(
        GoalMetric::Port,
        None,
        &before_snapshot,
        &after_snapshot,
        port_action_outcomes,
        &progress_config,
        Some(sid.0.clone()),
    );
    let fd_report = goal_progress::measure_progress(
        GoalMetric::FileDescriptors,
        None,
        &before_snapshot,
        &after_snapshot,
        fd_action_outcomes,
        &progress_config,
        Some(sid.0.clone()),
    );

    let goal_progress_payload = serde_json::json!({
        "session_id": sid.0,
        "before": before_snapshot,
        "after": after_snapshot,
        "metrics": {
            "memory": memory_report.clone(),
            "cpu": cpu_report.clone(),
            "ports": port_report.clone(),
            "file_descriptors": fd_report.clone()
        }
    });
    let goal_progress_discrepancy = serde_json::json!({
        "memory": goal_report_brief_json(&memory_report),
        "cpu": goal_report_brief_json(&cpu_report),
        "ports": goal_report_brief_json(&port_report),
        "file_descriptors": goal_report_brief_json(&fd_report),
        "respawn_loop_suspected": respawn_by_action.values().any(|detected| *detected),
    });

    for outcome in &mut outcomes {
        if let Some(obj) = outcome.as_object_mut() {
            let action_id = obj
                .get("action_id")
                .and_then(|value| value.as_str())
                .unwrap_or_default();
            let respawn_detected = respawn_by_action.get(action_id).copied().unwrap_or(false);
            obj.insert(
                "respawn_detected".to_string(),
                serde_json::json!(respawn_detected),
            );
            obj.insert(
                "goal_progress".to_string(),
                goal_progress_discrepancy.clone(),
            );
        }
    }

    let memory_summary_suffix = format!(
        ", mem_obs={:.1}MB mem_exp={:.1}MB ({})",
        memory_report.observed_progress / 1_048_576.0,
        memory_report.expected_progress / 1_048_576.0,
        memory_report.classification
    );

    // Write outcomes
    let action_dir = handle.dir.join("action");
    let outcomes_path = handle.dir.join("action").join("outcomes.jsonl");
    let _ = std::fs::create_dir_all(&action_dir);
    let goal_progress_path = action_dir.join("goal_progress.json");
    if let Ok(payload) = serde_json::to_string_pretty(&goal_progress_payload) {
        let _ = std::fs::write(&goal_progress_path, payload);
    }
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&outcomes_path)
    {
        use std::io::Write;
        for o in &outcomes {
            let _ = writeln!(file, "{}", o);
        }
    }

    let final_state = if failed > 0 {
        SessionState::Failed
    } else {
        SessionState::Completed
    };
    let _ = handle.update_state(final_state);

    let result = serde_json::json!({
        "session_id": sid.0,
        "mode": "robot_apply",
        "summary": {
            "attempted": actions_to_apply.len(),
            "succeeded": succeeded,
            "failed": failed,
            "skipped": skipped,
            "blocked_by_constraints": blocked_by_constraints,
            "blocked_by_prechecks": blocked_by_prechecks,
            "resumed_skipped": resumed_skipped
        },
        "outcomes": outcomes,
        "goal_progress": goal_progress_payload,
        "constraints_summary": constraints_summary,
        "resumed": args.resume
    });
    match global.format {
        OutputFormat::Json | OutputFormat::Toon => {
            println!("{}", format_structured_output(global, result));
        }
        OutputFormat::Summary => {
            if resumed_skipped > 0 {
                println!(
                    "[{}] apply: {} ok, {} fail, {} skip, {} blocked, {} precheck_blocked, {} already done (resumed){}",
                    sid,
                    succeeded,
                    failed,
                    skipped,
                    blocked_by_constraints,
                    blocked_by_prechecks,
                    resumed_skipped,
                    memory_summary_suffix
                );
            } else {
                println!(
                    "[{}] apply: {} ok, {} fail, {} skip, {} blocked, {} precheck_blocked{}",
                    sid,
                    succeeded,
                    failed,
                    skipped,
                    blocked_by_constraints,
                    blocked_by_prechecks,
                    memory_summary_suffix
                );
            }
        }
        _ => println!(
            "# apply\nSession: {}\nSucceeded: {}\nFailed: {}",
            sid, succeeded, failed
        ),
    }

    if (blocked_by_constraints + blocked_by_prechecks) > 0 && succeeded == 0 && failed == 0 {
        if let Some(ref e) = emitter {
            e.emit(ProgressEvent::new(
                pt_core::events::event_names::SESSION_ENDED,
                Phase::Session,
            ));
        }
        ExitCode::PolicyBlocked
    } else if failed > 0 {
        if let Some(ref e) = emitter {
            e.emit(ProgressEvent::new(
                pt_core::events::event_names::SESSION_ENDED,
                Phase::Session,
            ));
        }
        ExitCode::PartialFail
    } else {
        if let Some(ref e) = emitter {
            e.emit(ProgressEvent::new(
                pt_core::events::event_names::SESSION_ENDED,
                Phase::Session,
            ));
        }
        ExitCode::ActionsOk
    }
}

fn output_apply_nothing(global: &GlobalOpts, sid: &SessionId) {
    let result = serde_json::json!({"session_id": sid.0, "mode": "robot_apply", "note": "nothing_to_do", "summary": {"attempted": 0}});
    match global.format {
        OutputFormat::Json | OutputFormat::Toon => {
            println!("{}", format_structured_output(global, result));
        }
        _ => println!("[{}] apply: nothing to do", sid),
    }
}

fn run_agent_verify(global: &GlobalOpts, args: &AgentVerifyArgs) -> ExitCode {
    let store = match SessionStore::from_env() {
        Ok(store) => store,
        Err(e) => {
            eprintln!("agent verify: session store error: {}", e);
            return ExitCode::InternalError;
        }
    };
    let sid = match SessionId::parse(&args.session) {
        Some(sid) => sid,
        None => {
            eprintln!("agent verify: invalid --session {}", args.session);
            return ExitCode::ArgsError;
        }
    };
    if let Err(e) = store.open(&sid) {
        eprintln!("agent verify: {}", e);
        return ExitCode::ArgsError;
    }
    let handle = match store.open(&sid) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("agent verify: {}", e);
            return ExitCode::ArgsError;
        }
    };

    let plan_path = handle.dir.join("decision").join("plan.json");
    if !plan_path.exists() {
        eprintln!("agent verify: missing plan.json for session {}", sid);
        return ExitCode::ArgsError;
    }
    let plan_content = match std::fs::read_to_string(&plan_path) {
        Ok(content) => content,
        Err(e) => {
            eprintln!(
                "agent verify: failed to read {}: {}",
                plan_path.display(),
                e
            );
            return ExitCode::IoError;
        }
    };
    let plan = match parse_agent_plan(&plan_content) {
        Ok(p) => p,
        Err(VerifyError::InvalidPlan(msg)) => {
            eprintln!("agent verify: invalid plan.json: {}", msg);
            return ExitCode::InternalError;
        }
        Err(VerifyError::InvalidTimestamp(msg)) => {
            eprintln!("agent verify: invalid timestamp: {}", msg);
            return ExitCode::ArgsError;
        }
    };

    let requested_at = chrono::Utc::now();

    // Wait for process termination if --wait is specified
    if args.wait > 0 {
        let wait_duration = std::time::Duration::from_secs(args.wait);
        let start = std::time::Instant::now();
        let target_pids: Vec<u32> = plan
            .candidates
            .iter()
            .filter(|c| c.recommended_action == "terminate" || c.recommended_action == "kill")
            .map(|c| c.pid)
            .collect();

        while start.elapsed() < wait_duration {
            // Check if all target processes have terminated
            let still_running: Vec<u32> = target_pids
                .iter()
                .filter(|pid| std::path::Path::new(&format!("/proc/{}", pid)).exists())
                .copied()
                .collect();

            if still_running.is_empty() {
                break;
            }

            std::thread::sleep(std::time::Duration::from_millis(250));
        }
    }

    let scan_options = QuickScanOptions {
        pids: vec![],
        include_kernel_threads: false,
        timeout: global.timeout.map(std::time::Duration::from_secs),
        progress: None,
    };
    let scan_result = match quick_scan(&scan_options) {
        Ok(result) => result,
        Err(e) => {
            eprintln!("agent verify: scan failed: {}", e);
            return ExitCode::InternalError;
        }
    };

    let completed_at = chrono::Utc::now();
    let report = verify_plan(&plan, &scan_result.processes, requested_at, completed_at);

    let verify_dir = handle.dir.join("action");
    if let Err(e) = std::fs::create_dir_all(&verify_dir) {
        eprintln!(
            "agent verify: failed to create {}: {}",
            verify_dir.display(),
            e
        );
        return ExitCode::IoError;
    }
    let verify_path = verify_dir.join("verifications.json");
    if let Err(e) = std::fs::write(&verify_path, serde_json::to_string_pretty(&report).unwrap()) {
        eprintln!(
            "agent verify: failed to write {}: {}",
            verify_path.display(),
            e
        );
        return ExitCode::IoError;
    }

    if let Ok(manifest) = handle.read_manifest() {
        if manifest.state != SessionState::Completed {
            let _ = handle.update_state(SessionState::Completed);
        }
    }

    let total = report.action_outcomes.len();
    let verified_count = report
        .action_outcomes
        .iter()
        .filter(|o| o.verified.unwrap_or(false))
        .count();
    let failed_count = total.saturating_sub(verified_count);

    // Check for respawned processes if --check-respawn is set
    let respawned_count = if args.check_respawn {
        // Get command signatures of killed processes
        let killed_commands: Vec<&str> = plan
            .candidates
            .iter()
            .filter(|c| c.recommended_action == "terminate" || c.recommended_action == "kill")
            .map(|c| {
                // Prefer cmd_full, fall back to cmd_short
                if !c.cmd_full.is_empty() {
                    c.cmd_full.as_str()
                } else {
                    c.cmd_short.as_str()
                }
            })
            .filter(|s| !s.is_empty())
            .collect();

        // Count current processes that match killed command patterns
        scan_result
            .processes
            .iter()
            .filter(|p| killed_commands.iter().any(|kc| p.cmd.contains(kc)))
            .count()
    } else {
        0
    };

    let exit_code = match report.verification.overall_status.as_str() {
        "success" => ExitCode::Clean,
        "partial_success" => ExitCode::PartialFail,
        "failure" => ExitCode::PartialFail,
        _ => ExitCode::Clean,
    };

    match global.format {
        OutputFormat::Json | OutputFormat::Toon => {
            // Extend report with respawn info if checked
            let mut output = serde_json::to_value(&report).unwrap_or_default();
            if args.check_respawn {
                if let Some(obj) = output.as_object_mut() {
                    obj.insert(
                        "respawn_check".to_string(),
                        serde_json::json!({
                            "enabled": true,
                            "respawned_count": respawned_count,
                            "warning": if respawned_count > 0 {
                                Some(format!("{} processes may have respawned", respawned_count))
                            } else {
                                None
                            }
                        }),
                    );
                }
            }
            println!("{}", format_structured_output(global, output));
        }
        OutputFormat::Summary => {
            let freed = report
                .resource_summary
                .as_ref()
                .map(|s| s.memory_freed_mb)
                .unwrap_or(0.0);
            let respawn_info = if args.check_respawn && respawned_count > 0 {
                format!(", {} respawned!", respawned_count)
            } else {
                String::new()
            };
            println!(
                "[{}] agent verify: {} verified, {} failed (freed {} MB){}",
                sid, verified_count, failed_count, freed, respawn_info
            );
        }
        OutputFormat::Exitcode => {}
        _ => {
            println!(
                "# pt-core agent verify
"
            );
            println!("Session: {}", sid);
            println!("Plan: {}", plan_path.display());
            println!(
                "Report: {}
",
                verify_path.display()
            );
            println!(
                "- Outcomes: {} verified, {} failed",
                verified_count, failed_count
            );
            if let Some(summary) = &report.resource_summary {
                println!(
                    "- Memory freed: {} MB (expected {})",
                    summary.memory_freed_mb, summary.expected_mb
                );
            }
            if args.check_respawn {
                println!("- Respawn check: {} processes detected", respawned_count);
                if respawned_count > 0 {
                    println!("  ⚠ Warning: Some killed processes may have respawned");
                }
            }
            if let Some(recommendations) = &report.recommendations {
                if !recommendations.is_empty() {
                    println!("\n## Recommendations\n");
                    for rec in recommendations {
                        println!("- {}", rec);
                    }
                }
            }
        }
    }

    // If respawned processes were detected, indicate partial failure

    if args.check_respawn && respawned_count > 0 {
        ExitCode::PartialFail
    } else {
        exit_code
    }
}

fn resolve_diff_sessions(
    store: &SessionStore,
    args: &DiffArgs,
) -> Result<(SessionId, SessionId, Option<String>, Option<String>), String> {
    fn has_required_artifacts(summary: &SessionSummary) -> bool {
        // Diff requires both inventory + inference artifacts.
        // Older sessions may not have these yet; skip them to avoid confusing failures.
        summary.path.join("scan").join("inventory.json").exists()
            && summary.path.join("inference").join("results.json").exists()
    }

    if args.baseline && args.last {
        return Err("diff: --baseline and --last cannot be used together".to_string());
    }
    if (args.baseline || args.last) && (args.base.is_some() || args.compare.is_some()) {
        return Err(
            "diff: positional sessions cannot be combined with --baseline/--last".to_string(),
        );
    }

    let list_options = ListSessionsOptions {
        limit: Some(200),
        state: None,
        older_than: None,
    };
    let all_sessions = store
        .list_sessions(&list_options)
        .map_err(|e| format!("diff: failed to list sessions: {}", e))?;
    if all_sessions.is_empty() {
        return Err("diff: no sessions found".to_string());
    }

    let sessions: Vec<SessionSummary> = all_sessions
        .into_iter()
        .filter(has_required_artifacts)
        .collect();
    if sessions.is_empty() {
        return Err(
            "diff: no sessions with required artifacts (need scan inventory + inference results)"
                .to_string(),
        );
    }

    let use_last = args.last || (!args.baseline && args.base.is_none());

    let (base_summary, compare_summary) = if args.baseline {
        let base = sessions
            .iter()
            .find(|s| {
                s.label
                    .as_deref()
                    .map(|l| l.eq_ignore_ascii_case("baseline"))
                    .unwrap_or(false)
            })
            .cloned()
            .ok_or_else(|| {
                "diff: no baseline session found (label a session 'baseline')".to_string()
            })?;
        let compare = sessions
            .iter()
            .find(|s| s.session_id != base.session_id)
            .cloned()
            .ok_or_else(|| "diff: need at least two sessions to compare".to_string())?;
        (base, compare)
    } else if use_last {
        if sessions.len() < 2 {
            return Err("diff: need at least two sessions to compare".to_string());
        }
        (sessions[1].clone(), sessions[0].clone())
    } else {
        let base_raw = args
            .base
            .as_ref()
            .ok_or_else(|| "diff: base session required".to_string())?;

        let compare_summary = match args.compare.as_deref() {
            Some("current") | Some("latest") | None => sessions
                .iter()
                .find(|s| s.session_id != *base_raw)
                .cloned()
                .ok_or_else(|| {
                    "diff: no compare session found (need at least two sessions)".to_string()
                })?,
            Some(raw) => sessions
                .iter()
                .find(|s| s.session_id == raw)
                .cloned()
                .unwrap_or_else(|| SessionSummary {
                    session_id: raw.to_string(),
                    created_at: String::new(),
                    state: SessionState::Created,
                    mode: SessionMode::ScanOnly,
                    label: None,
                    host_id: None,
                    candidates_count: None,
                    actions_count: None,
                    path: PathBuf::new(),
                }),
        };

        let base_summary = sessions
            .iter()
            .find(|s| s.session_id == *base_raw)
            .cloned()
            .unwrap_or_else(|| SessionSummary {
                session_id: base_raw.to_string(),
                created_at: String::new(),
                state: SessionState::Created,
                mode: SessionMode::ScanOnly,
                label: None,
                host_id: None,
                candidates_count: None,
                actions_count: None,
                path: PathBuf::new(),
            });

        (base_summary, compare_summary)
    };

    if base_summary.session_id == compare_summary.session_id {
        return Err("diff: base and compare sessions must differ".to_string());
    }

    let base_id = SessionId::parse(&base_summary.session_id)
        .ok_or_else(|| format!("diff: invalid base session {}", base_summary.session_id))?;
    let compare_id = SessionId::parse(&compare_summary.session_id).ok_or_else(|| {
        format!(
            "diff: invalid compare session {}",
            compare_summary.session_id
        )
    })?;

    Ok((
        base_id,
        compare_id,
        base_summary.label,
        compare_summary.label,
    ))
}

fn filter_diff_deltas(diff: &SessionDiff, args: &DiffArgs) -> Result<Vec<ProcessDelta>, String> {
    let mut deltas: Vec<ProcessDelta> = diff.deltas.clone();

    if args.changed_only {
        deltas.retain(|d| d.kind != DeltaKind::Unchanged);
    }

    if let Some(category) = &args.category {
        let cat = category.trim().to_lowercase();
        deltas.retain(|d| match cat.as_str() {
            "new" => d.kind == DeltaKind::New,
            "gone" | "resolved" | "removed" => d.kind == DeltaKind::Resolved,
            "changed" => d.kind == DeltaKind::Changed,
            "unchanged" => d.kind == DeltaKind::Unchanged,
            "worsened" => d.worsened,
            "improved" => d.improved,
            _ => true,
        });

        match cat.as_str() {
            "new" | "gone" | "resolved" | "removed" | "changed" | "unchanged" | "worsened"
            | "improved" => {}
            _ => {
                return Err(format!(
                    "diff: invalid --category '{}'. Use: new, resolved, changed, unchanged, worsened, improved",
                    category
                ));
            }
        }
    }

    Ok(deltas)
}

fn summarize_deltas(deltas: &[ProcessDelta]) -> serde_json::Value {
    let new_count = deltas.iter().filter(|d| d.kind == DeltaKind::New).count();
    let resolved_count = deltas
        .iter()
        .filter(|d| d.kind == DeltaKind::Resolved)
        .count();
    let changed_count = deltas
        .iter()
        .filter(|d| d.kind == DeltaKind::Changed)
        .count();
    let unchanged_count = deltas
        .iter()
        .filter(|d| d.kind == DeltaKind::Unchanged)
        .count();
    let worsened_count = deltas.iter().filter(|d| d.worsened).count();
    let improved_count = deltas.iter().filter(|d| d.improved).count();

    serde_json::json!({
        "total": deltas.len(),
        "new_count": new_count,
        "resolved_count": resolved_count,
        "changed_count": changed_count,
        "unchanged_count": unchanged_count,
        "worsened_count": worsened_count,
        "improved_count": improved_count,
    })
}

fn build_cmd_map(records: &[PersistedProcess]) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for rec in records {
        let cmd = if rec.cmd.is_empty() {
            rec.comm.clone()
        } else {
            rec.cmd.clone()
        };
        out.insert(rec.start_id.clone(), cmd);
    }
    out
}

fn truncate_ascii(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        return value.to_string();
    }
    if max <= 3 {
        return value.chars().take(max).collect();
    }
    let prefix: String = value.chars().take(max - 3).collect();
    format!("{}...", prefix)
}

fn format_inference_summary(inf: Option<&InferenceSummary>) -> String {
    match inf {
        Some(i) => format!("{} {} {}", i.classification, i.score, i.recommended_action),
        None => "-".to_string(),
    }
}

fn format_diff_plain(
    base_id: &SessionId,
    compare_id: &SessionId,
    base_ts: &str,
    compare_ts: &str,
    deltas: &[ProcessDelta],
    base_cmds: &HashMap<String, String>,
    compare_cmds: &HashMap<String, String>,
) -> String {
    let mut output = String::new();

    output.push_str("# pt diff\n\n");
    output.push_str(&format!("Base: {} {}\n", base_id.0, base_ts));
    output.push_str(&format!("Compare: {} {}\n\n", compare_id.0, compare_ts));

    let summary = summarize_deltas(deltas);
    output.push_str("Summary:\n");
    output.push_str(&format!(
        "- New: {} | Resolved: {} | Changed: {} | Unchanged: {} | Worsened: {} | Improved: {}\n\n",
        summary
            .get("new_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        summary
            .get("resolved_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        summary
            .get("changed_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        summary
            .get("unchanged_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        summary
            .get("worsened_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        summary
            .get("improved_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
    ));

    output.push_str(&format!(
        "{:>6} {:<9} {:<40} | {:<22} | {:<22} | {:>6}\n",
        "PID", "KIND", "CMD", "OLD", "NEW", "DELTA"
    ));
    output.push_str(&format!(
        "{:-<6} {:-<9} {:-<40}-+-{:-<22}-+-{:-<22}-+-{:-<6}\n",
        "", "", "", "", "", ""
    ));

    for delta in deltas {
        let cmd = compare_cmds
            .get(&delta.start_id)
            .or_else(|| base_cmds.get(&delta.start_id))
            .cloned()
            .unwrap_or_else(|| "?".to_string());
        let cmd = truncate_ascii(&cmd, 40);

        let old_desc = truncate_ascii(&format_inference_summary(delta.old_inference.as_ref()), 22);
        let new_desc = truncate_ascii(&format_inference_summary(delta.new_inference.as_ref()), 22);
        let delta_str = delta
            .score_drift
            .map(|d| format!("{:+}", d))
            .unwrap_or_else(|| "-".to_string());

        let kind = match delta.kind {
            DeltaKind::New => "NEW",
            DeltaKind::Resolved => "RESOLVED",
            DeltaKind::Changed => "CHANGED",
            DeltaKind::Unchanged => "UNCHANGED",
        };

        output.push_str(&format!(
            "{:>6} {:<9} {:<40} | {:<22} | {:<22} | {:>6}\n",
            delta.pid, kind, cmd, old_desc, new_desc, delta_str
        ));
    }

    output
}

fn run_diff(global: &GlobalOpts, args: &DiffArgs) -> ExitCode {
    let store = match SessionStore::from_env() {
        Ok(store) => store,
        Err(e) => {
            eprintln!("diff: session store error: {}", e);
            return ExitCode::InternalError;
        }
    };

    let (base_id, compare_id, base_label, compare_label) = match resolve_diff_sessions(&store, args)
    {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("{}", e);
            return ExitCode::ArgsError;
        }
    };

    let base_handle = match store.open(&base_id) {
        Ok(handle) => handle,
        Err(e) => {
            eprintln!("diff: base {}", e);
            return ExitCode::ArgsError;
        }
    };
    let compare_handle = match store.open(&compare_id) {
        Ok(handle) => handle,
        Err(e) => {
            eprintln!("diff: compare {}", e);
            return ExitCode::ArgsError;
        }
    };

    let base_inventory = match load_inventory_unchecked(&base_handle) {
        Ok(inv) => inv,
        Err(e) => {
            eprintln!("diff: base inventory: {}", e);
            return ExitCode::ArgsError;
        }
    };
    let base_inference = match load_inference_unchecked(&base_handle) {
        Ok(inf) => inf,
        Err(e) => {
            eprintln!("diff: base inference: {}", e);
            return ExitCode::ArgsError;
        }
    };
    let compare_inventory = match load_inventory_unchecked(&compare_handle) {
        Ok(inv) => inv,
        Err(e) => {
            eprintln!("diff: compare inventory: {}", e);
            return ExitCode::ArgsError;
        }
    };
    let compare_inference = match load_inference_unchecked(&compare_handle) {
        Ok(inf) => inf,
        Err(e) => {
            eprintln!("diff: compare inference: {}", e);
            return ExitCode::ArgsError;
        }
    };

    let mut config = DiffConfig::default();
    if let Some(min) = args.min_score_delta {
        config.score_drift_threshold = min;
    }

    let diff = compute_diff(
        &base_id.0,
        &compare_id.0,
        &base_inventory.payload.records,
        &base_inference.payload.candidates,
        &compare_inventory.payload.records,
        &compare_inference.payload.candidates,
        &config,
    );

    let filtered_deltas = match filter_diff_deltas(&diff, args) {
        Ok(deltas) => deltas,
        Err(e) => {
            eprintln!("{}", e);
            return ExitCode::ArgsError;
        }
    };

    let filtered_summary = summarize_deltas(&filtered_deltas);
    let report = generate_comparison_report(
        &diff,
        &base_inference.payload.candidates,
        &compare_inference.payload.candidates,
    );

    let base_ts = base_inference.generated_at.clone();
    let compare_ts = compare_inference.generated_at.clone();

    let output = serde_json::json!({
        "comparison": {
            "base_session": base_id.0,
            "compare_session": compare_id.0,
            "base_timestamp": base_ts.clone(),
            "compare_timestamp": compare_ts.clone(),
            "base_label": base_label,
            "compare_label": compare_label,
        },
        "filters": {
            "changed_only": args.changed_only,
            "category": args.category,
            "min_score_delta": args.min_score_delta,
        },
        "summary": diff.summary,
        "filtered_summary": filtered_summary,
        "delta": filtered_deltas,
        "report": report,
    });

    match global.format {
        OutputFormat::Json | OutputFormat::Toon | OutputFormat::Jsonl => {
            println!("{}", format_structured_output(global, output));
        }
        OutputFormat::Summary => {
            let counts = summarize_deltas(&filtered_deltas);
            println!(
                "[{} → {}] diff: +{} new, {} changed, {} resolved, {} worsened, {} improved",
                base_id.0,
                compare_id.0,
                counts
                    .get("new_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
                counts
                    .get("changed_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
                counts
                    .get("resolved_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
                counts
                    .get("worsened_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
                counts
                    .get("improved_count")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
            );
        }
        OutputFormat::Exitcode => {}
        _ => {
            let base_cmds = build_cmd_map(&base_inventory.payload.records);
            let compare_cmds = build_cmd_map(&compare_inventory.payload.records);
            let rendered = format_diff_plain(
                &base_id,
                &compare_id,
                base_ts.as_str(),
                compare_ts.as_str(),
                &filtered_deltas,
                &base_cmds,
                &compare_cmds,
            );
            print!("{}", rendered);
        }
    }

    ExitCode::Clean
}

fn run_agent_diff(global: &GlobalOpts, args: &AgentDiffArgs) -> ExitCode {
    let store = match SessionStore::from_env() {
        Ok(store) => store,
        Err(e) => {
            eprintln!("agent diff: session store error: {}", e);
            return ExitCode::InternalError;
        }
    };

    let base = match SessionId::parse(&args.base) {
        Some(sid) => sid,
        None => {
            eprintln!("agent diff: invalid --base {}", args.base);
            return ExitCode::ArgsError;
        }
    };
    let base_handle = match store.open(&base) {
        Ok(handle) => handle,
        Err(e) => {
            eprintln!("agent diff: {}", e);
            return ExitCode::ArgsError;
        }
    };

    let compare_id = match args.compare.as_deref() {
        Some("current") | Some("latest") | None => {
            let options = ListSessionsOptions {
                limit: Some(50),
                state: None,
                older_than: None,
            };
            let sessions = match store.list_sessions(&options) {
                Ok(list) => list,
                Err(e) => {
                    eprintln!("agent diff: failed to list sessions: {}", e);
                    return ExitCode::InternalError;
                }
            };
            let mut found = None;
            for summary in sessions {
                if summary.session_id != base.0 {
                    if let Some(sid) = SessionId::parse(&summary.session_id) {
                        found = Some(sid);
                        break;
                    }
                }
            }
            match found {
                Some(sid) => sid,
                None => {
                    eprintln!("agent diff: no compare session found (need at least two sessions)");
                    return ExitCode::ArgsError;
                }
            }
        }
        Some(raw) => match SessionId::parse(raw) {
            Some(sid) => sid,
            None => {
                eprintln!("agent diff: invalid --compare {}", raw);
                return ExitCode::ArgsError;
            }
        },
    };

    let compare_handle = match store.open(&compare_id) {
        Ok(handle) => handle,
        Err(e) => {
            eprintln!("agent diff: {}", e);
            return ExitCode::ArgsError;
        }
    };

    let load_plan = |handle: &SessionHandle| -> Result<serde_json::Value, String> {
        let plan_path = handle.dir.join("decision").join("plan.json");
        let content = std::fs::read_to_string(&plan_path)
            .map_err(|e| format!("missing plan.json at {}: {}", plan_path.display(), e))?;
        serde_json::from_str(&content).map_err(|e| format!("invalid plan.json: {}", e))
    };

    let base_plan = match load_plan(&base_handle) {
        Ok(plan) => plan,
        Err(e) => {
            eprintln!("agent diff: base {}", e);
            return ExitCode::ArgsError;
        }
    };
    let compare_plan = match load_plan(&compare_handle) {
        Ok(plan) => plan,
        Err(e) => {
            eprintln!("agent diff: compare {}", e);
            return ExitCode::ArgsError;
        }
    };

    #[derive(Clone)]
    struct DiffCandidate {
        pid: u32,
        uid: u32,
        cmd_short: String,
        cmd_full: String,
        classification: String,
        recommended_action: String,
        score: f64,
    }

    fn normalize_cmd(cmd: &str) -> String {
        cmd.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    let extract_candidates = |plan: &serde_json::Value| -> Vec<DiffCandidate> {
        let mut out = Vec::new();
        let candidates = plan
            .get("candidates")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        for cand in candidates {
            let pid = cand.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let uid = cand.get("uid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let cmd_short = cand
                .get("cmd_short")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let cmd_full = cand
                .get("cmd_full")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let classification = cand
                .get("classification")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let recommended_action = cand
                .get("recommended_action")
                .and_then(|v| v.as_str())
                .unwrap_or("keep")
                .to_string();
            let score = cand
                .get("posterior")
                .and_then(|p| p.as_object())
                .map(|p| {
                    p.values()
                        .filter_map(|v| v.as_f64())
                        .fold(0.0_f64, |acc, v| acc.max(v))
                })
                .unwrap_or(0.0)
                * 100.0;
            out.push(DiffCandidate {
                pid,
                uid,
                cmd_short,
                cmd_full,
                classification,
                recommended_action,
                score,
            });
        }
        out
    };

    let base_candidates = extract_candidates(&base_plan);
    let compare_candidates = extract_candidates(&compare_plan);

    let candidate_key = |c: &DiffCandidate| -> (u32, String) {
        let cmd = if !c.cmd_full.is_empty() {
            c.cmd_full.as_str()
        } else {
            c.cmd_short.as_str()
        };
        (c.uid, normalize_cmd(cmd))
    };

    let severity = |action: &str| -> i32 {
        if action == "kill" {
            2
        } else if action == "keep" {
            0
        } else {
            1
        }
    };

    let bucket = |action: &str| -> &'static str {
        if action == "kill" {
            "kill"
        } else if action == "keep" {
            "spare"
        } else {
            "review"
        }
    };

    let mut base_map: HashMap<(u32, String), DiffCandidate> = HashMap::new();
    for cand in &base_candidates {
        base_map.insert(candidate_key(cand), cand.clone());
    }

    let mut compare_map: HashMap<(u32, String), DiffCandidate> = HashMap::new();
    for cand in &compare_candidates {
        compare_map.insert(candidate_key(cand), cand.clone());
    }

    let mut new_list = Vec::new();
    let mut worsened = Vec::new();
    let mut improved = Vec::new();
    let mut resolved = Vec::new();
    let mut persistent = Vec::new();

    for (key, current) in &compare_map {
        if let Some(prior) = base_map.get(key) {
            let prior_sev = severity(&prior.recommended_action);
            let current_sev = severity(&current.recommended_action);
            let score_change = current.score - prior.score;

            if current_sev > prior_sev {
                worsened.push(serde_json::json!({
                    "pid": current.pid,
                    "prior": bucket(&prior.recommended_action),
                    "current": bucket(&current.recommended_action),
                    "score_change": score_change,
                    "cmd_short": current.cmd_short,
                }));
            } else if current_sev < prior_sev {
                improved.push(serde_json::json!({
                    "pid": current.pid,
                    "prior": bucket(&prior.recommended_action),
                    "current": bucket(&current.recommended_action),
                    "score_change": score_change,
                    "cmd_short": current.cmd_short,
                }));
            } else if current_sev > 0 {
                persistent.push(serde_json::json!({
                    "pid": current.pid,
                    "consecutive_sessions": 2,
                    "classification": current.classification,
                    "note": "Suspicious in consecutive sessions",
                }));
            }
        } else {
            new_list.push(serde_json::json!({
                "pid": current.pid,
                "classification": current.classification,
                "score": current.score,
                "cmd_short": current.cmd_short,
            }));
        }
    }

    for (key, prior) in &base_map {
        if !compare_map.contains_key(key) {
            resolved.push(serde_json::json!({
                "pid": prior.pid,
                "reason": "exited_or_below_threshold",
                "was_classification": prior.classification,
            }));
        }
    }

    let base_ts = base_plan
        .get("generated_at")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let compare_ts = compare_plan
        .get("generated_at")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Apply focus filter
    let focus = args.focus;
    let (show_new, show_worsened, show_improved, show_resolved, show_persistent) = match focus {
        FocusMode::New => (true, false, false, false, false),
        FocusMode::Removed => (false, false, false, true, false),
        FocusMode::Changed => (false, true, true, false, false),
        FocusMode::Resources | FocusMode::All => (true, true, true, true, true),
    };

    let filtered_new = if show_new { new_list.clone() } else { vec![] };
    let filtered_worsened = if show_worsened {
        worsened.clone()
    } else {
        vec![]
    };
    let filtered_improved = if show_improved {
        improved.clone()
    } else {
        vec![]
    };
    let filtered_resolved = if show_resolved {
        resolved.clone()
    } else {
        vec![]
    };
    let filtered_persistent = if show_persistent {
        persistent.clone()
    } else {
        vec![]
    };

    let output = serde_json::json!({
        "comparison": {
            "prior_session": base.0,
            "current_session": compare_id.0,
            "prior_timestamp": base_ts,
            "current_timestamp": compare_ts,
        },
        "focus": focus.as_str(),
        "delta": {
            "new": filtered_new,
            "worsened": filtered_worsened,
            "improved": filtered_improved,
            "resolved": filtered_resolved,
            "persistent": filtered_persistent,
        },
        "summary": {
            "prior_candidates": base_candidates.len(),
            "current_candidates": compare_candidates.len(),
            "new_count": new_list.len(),
            "worsened_count": worsened.len(),
            "improved_count": improved.len(),
            "resolved_count": resolved.len(),
            "persistent_count": persistent.len(),
            "filtered": focus != FocusMode::All,
        },
    });

    match global.format {
        OutputFormat::Json | OutputFormat::Toon => {
            println!("{}", format_structured_output(global, output.clone()));
        }
        OutputFormat::Summary => {
            let focus_note = if focus != FocusMode::All {
                format!(" (focus: {})", focus.as_str())
            } else {
                String::new()
            };
            println!(
                "[{} → {}] agent diff: +{} new, {} worsened, {} improved, {} resolved, {} persistent{}",
                base.0,
                compare_id.0,
                new_list.len(),
                worsened.len(),
                improved.len(),
                resolved.len(),
                persistent.len(),
                focus_note
            );
        }
        OutputFormat::Exitcode => {}
        _ => {
            println!("# pt-core agent diff\n");
            println!("Base: {}", base.0);
            println!("Compare: {}\n", compare_id.0);
            if focus != FocusMode::All {
                println!("Focus: {}\n", focus.as_str());
            }
            println!("## Summary\n");
            println!(
                "- New: {} | Worsened: {} | Improved: {} | Resolved: {} | Persistent: {}",
                new_list.len(),
                worsened.len(),
                improved.len(),
                resolved.len(),
                persistent.len()
            );
        }
    }

    ExitCode::Clean
}

fn run_agent_list_priors(global: &GlobalOpts, args: &AgentListPriorsArgs) -> ExitCode {
    let session_id = SessionId::new();
    let host_id = pt_core::logging::get_host_id();

    // Build config options from global opts
    let options = ConfigOptions {
        config_dir: global.config.as_ref().map(PathBuf::from),
        priors_path: None,
        policy_path: None,
    };

    // Load configuration
    let config = match load_config(&options) {
        Ok(c) => c,
        Err(e) => {
            return output_config_error(global, &e);
        }
    };

    let snapshot = config.snapshot();
    let priors = &config.priors;

    // Validate class filter if provided
    let valid_classes = ["useful", "useful_bad", "abandoned", "zombie"];
    if let Some(ref class_filter) = args.class {
        if !valid_classes.contains(&class_filter.as_str()) {
            eprintln!(
                "agent list-priors: invalid --class '{}'. Must be one of: {}",
                class_filter,
                valid_classes.join(", ")
            );
            return ExitCode::ArgsError;
        }
    }

    // Helper to build class prior JSON
    let build_class_json =
        |name: &str, cp: &pt_core::config::priors::ClassParams| -> serde_json::Value {
            let mut obj = serde_json::json!({
                "prior_prob": cp.prior_prob,
                "cpu_beta": { "alpha": cp.cpu_beta.alpha, "beta": cp.cpu_beta.beta },
                "orphan_beta": { "alpha": cp.orphan_beta.alpha, "beta": cp.orphan_beta.beta },
                "tty_beta": { "alpha": cp.tty_beta.alpha, "beta": cp.tty_beta.beta },
                "net_beta": { "alpha": cp.net_beta.alpha, "beta": cp.net_beta.beta },
            });
            if let Some(ref io) = cp.io_active_beta {
                obj["io_active_beta"] = serde_json::json!({ "alpha": io.alpha, "beta": io.beta });
            }
            if let Some(ref rt) = cp.runtime_gamma {
                obj["runtime_gamma"] = serde_json::json!({ "shape": rt.shape, "rate": rt.rate });
            }
            if let Some(ref hz) = cp.hazard_gamma {
                obj["hazard_gamma"] = serde_json::json!({ "shape": hz.shape, "rate": hz.rate });
            }
            obj["class"] = serde_json::Value::String(name.to_string());
            obj
        };

    // Build classes array (filtered or all)
    let classes_data: Vec<serde_json::Value> = match args.class.as_deref() {
        Some("useful") => vec![build_class_json("useful", &priors.classes.useful)],
        Some("useful_bad") => vec![build_class_json("useful_bad", &priors.classes.useful_bad)],
        Some("abandoned") => vec![build_class_json("abandoned", &priors.classes.abandoned)],
        Some("zombie") => vec![build_class_json("zombie", &priors.classes.zombie)],
        _ => vec![
            build_class_json("useful", &priors.classes.useful),
            build_class_json("useful_bad", &priors.classes.useful_bad),
            build_class_json("abandoned", &priors.classes.abandoned),
            build_class_json("zombie", &priors.classes.zombie),
        ],
    };

    // Build response
    let mut response = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "session_id": session_id.0,
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "host_id": host_id,
        "source": {
            "path": snapshot.priors_path.as_ref().map(|p| p.display().to_string()),
            "using_defaults": snapshot.priors_path.is_none(),
            "priors_schema_version": &snapshot.priors_schema_version,
        },
        "classes": classes_data,
    });

    // Add extended sections in extended mode
    if args.extended {
        if !priors.hazard_regimes.is_empty() {
            response["hazard_regimes"] =
                serde_json::to_value(&priors.hazard_regimes).unwrap_or_default();
        }
        if let Some(ref sm) = priors.semi_markov {
            response["semi_markov"] = serde_json::to_value(sm).unwrap_or_default();
        }
        if let Some(ref cp) = priors.change_point {
            response["change_point"] = serde_json::to_value(cp).unwrap_or_default();
        }
        if let Some(ref ci) = priors.causal_interventions {
            response["causal_interventions"] = serde_json::to_value(ci).unwrap_or_default();
        }
        if let Some(ref hier) = priors.hierarchical {
            response["hierarchical"] = serde_json::to_value(hier).unwrap_or_default();
        }
        if let Some(ref rb) = priors.robust_bayes {
            response["robust_bayes"] = serde_json::to_value(rb).unwrap_or_default();
        }
        if let Some(ref er) = priors.error_rate {
            response["error_rate"] = serde_json::to_value(er).unwrap_or_default();
        }
        if let Some(ref bocpd) = priors.bocpd {
            response["bocpd"] = serde_json::to_value(bocpd).unwrap_or_default();
        }
    }

    match global.format {
        OutputFormat::Json | OutputFormat::Toon => {
            println!("{}", format_structured_output(global, response));
        }
        OutputFormat::Jsonl => {
            // Compact single-line JSON for streaming/JSONL consumers
            println!("{}", serde_json::to_string(&response).unwrap());
        }
        OutputFormat::Summary => {
            let source = if snapshot.priors_path.is_some() {
                "custom"
            } else {
                "defaults"
            };
            println!(
                "[{}] priors: {} class(es) from {}",
                session_id,
                classes_data.len(),
                source
            );
        }
        OutputFormat::Exitcode => {}
        OutputFormat::Metrics => {
            // Key=value pairs for monitoring systems
            let source = if snapshot.priors_path.is_some() {
                "custom"
            } else {
                "defaults"
            };
            println!("priors_source={}", source);
            println!("priors_class_count={}", classes_data.len());
            println!("priors_schema_version={}", snapshot.priors_schema_version);
            for class_json in &classes_data {
                let class_name = class_json["class"].as_str().unwrap_or("?");
                let prior_prob = class_json["prior_prob"].as_f64().unwrap_or(0.0);
                println!("priors_{}_prior_prob={:.4}", class_name, prior_prob);
            }
        }
        _ => {
            // Md, Slack, Prose all use markdown-style output
            println!("# Prior Configuration\n");
            if let Some(ref path) = snapshot.priors_path {
                println!("Source: {}", path.display());
            } else {
                println!("Source: **built-in defaults** (no priors.json found)");
            }
            println!("Schema version: {}\n", snapshot.priors_schema_version);

            for class_json in &classes_data {
                let class_name = class_json["class"].as_str().unwrap_or("?");
                let prior_prob = class_json["prior_prob"].as_f64().unwrap_or(0.0);
                println!("## {}\n", class_name);
                println!("| Parameter | Value |");
                println!("|-----------|-------|");
                println!("| prior_prob | {:.4} |", prior_prob);
                if let Some(cpu) = class_json.get("cpu_beta") {
                    println!(
                        "| cpu_beta | α={:.2}, β={:.2} |",
                        cpu["alpha"].as_f64().unwrap_or(0.0),
                        cpu["beta"].as_f64().unwrap_or(0.0)
                    );
                }
                if let Some(orphan) = class_json.get("orphan_beta") {
                    println!(
                        "| orphan_beta | α={:.2}, β={:.2} |",
                        orphan["alpha"].as_f64().unwrap_or(0.0),
                        orphan["beta"].as_f64().unwrap_or(0.0)
                    );
                }
                if let Some(tty) = class_json.get("tty_beta") {
                    println!(
                        "| tty_beta | α={:.2}, β={:.2} |",
                        tty["alpha"].as_f64().unwrap_or(0.0),
                        tty["beta"].as_f64().unwrap_or(0.0)
                    );
                }
                if let Some(net) = class_json.get("net_beta") {
                    println!(
                        "| net_beta | α={:.2}, β={:.2} |",
                        net["alpha"].as_f64().unwrap_or(0.0),
                        net["beta"].as_f64().unwrap_or(0.0)
                    );
                }
                println!();
            }
            println!("Session: {}", session_id);
        }
    }

    ExitCode::Clean
}

fn run_agent_export_priors(global: &GlobalOpts, args: &AgentExportPriorsArgs) -> ExitCode {
    let host_id = pt_core::logging::get_host_id();

    let options = ConfigOptions {
        config_dir: global.config.as_ref().map(PathBuf::from),
        priors_path: None,
        policy_path: None,
    };

    let config = match load_config(&options) {
        Ok(c) => c,
        Err(e) => {
            return output_config_error(global, &e);
        }
    };

    let export = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "exported_at": chrono::Utc::now().to_rfc3339(),
        "host_id": host_id,
        "host_profile": args.host_profile,
        "priors": config.priors,
        "snapshot": config.snapshot(),
    });

    let out_path = PathBuf::from(&args.out);
    if let Some(parent) = out_path.parent() {
        if let Err(err) = std::fs::create_dir_all(parent) {
            eprintln!(
                "agent export-priors: failed to create {}: {}",
                parent.display(),
                err
            );
            return ExitCode::IoError;
        }
    }

    let tmp_path = out_path.with_extension("tmp");
    let payload = match serde_json::to_vec_pretty(&export) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("agent export-priors: failed to serialize: {}", err);
            return ExitCode::IoError;
        }
    };

    if let Err(err) = std::fs::write(&tmp_path, payload) {
        eprintln!(
            "agent export-priors: failed to write {}: {}",
            tmp_path.display(),
            err
        );
        return ExitCode::IoError;
    }

    if let Err(err) = std::fs::rename(&tmp_path, &out_path) {
        eprintln!(
            "agent export-priors: failed to rename {} to {}: {}",
            tmp_path.display(),
            out_path.display(),
            err
        );
        return ExitCode::IoError;
    }

    let response = serde_json::json!({
        "exported": true,
        "path": out_path.display().to_string(),
        "host_id": host_id,
        "host_profile": args.host_profile,
    });
    match global.format {
        OutputFormat::Json | OutputFormat::Toon => {
            println!("{}", format_structured_output(global, response));
        }
        OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string_pretty(&response).unwrap());
        }
        _ => {
            println!("Exported priors to: {}", out_path.display());
        }
    }

    ExitCode::Clean
}

fn run_agent_import_priors(global: &GlobalOpts, args: &AgentImportPriorsArgs) -> ExitCode {
    use pt_core::config::priors::Priors;

    // Default to merge if neither --merge nor --replace specified
    let mode = if args.replace { "replace" } else { "merge" };

    // Read the input file
    let input_path = PathBuf::from(&args.from);
    let input_data = match std::fs::read_to_string(&input_path) {
        Ok(data) => data,
        Err(err) => {
            eprintln!(
                "agent import-priors: failed to read {}: {}",
                input_path.display(),
                err
            );
            return ExitCode::IoError;
        }
    };

    // Parse the input as JSON
    let import_doc: serde_json::Value = match serde_json::from_str(&input_data) {
        Ok(v) => v,
        Err(err) => {
            eprintln!(
                "agent import-priors: failed to parse {}: {}",
                input_path.display(),
                err
            );
            return ExitCode::ArgsError;
        }
    };

    // Extract priors from the import document
    let imported_priors: Priors = if let Some(priors_value) = import_doc.get("priors") {
        match serde_json::from_value(priors_value.clone()) {
            Ok(p) => p,
            Err(err) => {
                eprintln!(
                    "agent import-priors: failed to parse priors section: {}",
                    err
                );
                return ExitCode::ArgsError;
            }
        }
    } else {
        // Try parsing the whole file as a Priors struct
        match serde_json::from_value(import_doc.clone()) {
            Ok(p) => p,
            Err(err) => {
                eprintln!(
                    "agent import-priors: file must contain 'priors' key or be a valid Priors document: {}",
                    err
                );
                return ExitCode::ArgsError;
            }
        }
    };

    // Load current config
    let options = ConfigOptions {
        config_dir: global.config.as_ref().map(PathBuf::from),
        priors_path: None,
        policy_path: None,
    };

    let config = match load_config(&options) {
        Ok(c) => c,
        Err(e) => {
            return output_config_error(global, &e);
        }
    };

    // Determine priors output path
    let priors_path = config.snapshot().priors_path.unwrap_or_else(|| {
        global
            .config
            .as_ref()
            .map(|c| PathBuf::from(c).join("priors.json"))
            .unwrap_or_else(|| {
                dirs::config_dir()
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join("pt")
                    .join("priors.json")
            })
    });

    // Check host profile compatibility
    if let Some(ref filter_profile) = args.host_profile {
        if let Some(imported_profile) = import_doc.get("host_profile").and_then(|v| v.as_str()) {
            if imported_profile != filter_profile {
                eprintln!(
                    "agent import-priors: warning: imported host_profile '{}' differs from target '{}'",
                    imported_profile, filter_profile
                );
            }
        }
    }

    // Compute the final priors
    let final_priors = if mode == "replace" {
        imported_priors
    } else {
        // Merge mode: weighted combination
        // For now, we do a simple replacement of class priors that exist in the import
        // A more sophisticated merge could weight by observation counts
        let mut merged = config.priors.clone();

        // Merge class priors
        merged.classes.useful = imported_priors.classes.useful.clone();
        merged.classes.useful_bad = imported_priors.classes.useful_bad.clone();
        merged.classes.abandoned = imported_priors.classes.abandoned.clone();
        merged.classes.zombie = imported_priors.classes.zombie.clone();

        // Merge optional sections if present in import
        if imported_priors.causal_interventions.is_some() {
            merged.causal_interventions = imported_priors.causal_interventions.clone();
        }
        if imported_priors.hierarchical.is_some() {
            merged.hierarchical = imported_priors.hierarchical.clone();
        }
        if imported_priors.robust_bayes.is_some() {
            merged.robust_bayes = imported_priors.robust_bayes.clone();
        }

        merged
    };

    // Dry run: just show what would happen
    if args.dry_run {
        let response = serde_json::json!({
            "dry_run": true,
            "mode": mode,
            "source": input_path.display().to_string(),
            "target": priors_path.display().to_string(),
            "changes": {
                "class_priors": {
                    "useful": final_priors.classes.useful.prior_prob,
                    "useful_bad": final_priors.classes.useful_bad.prior_prob,
                    "abandoned": final_priors.classes.abandoned.prior_prob,
                    "zombie": final_priors.classes.zombie.prior_prob,
                }
            }
        });
        println!("{}", serde_json::to_string_pretty(&response).unwrap());
        return ExitCode::Clean;
    }

    // Create backup unless --no-backup
    if !args.no_backup && priors_path.exists() {
        let backup_path = priors_path.with_extension("json.bak");
        if let Err(err) = std::fs::copy(&priors_path, &backup_path) {
            eprintln!(
                "agent import-priors: warning: failed to create backup at {}: {}",
                backup_path.display(),
                err
            );
        }
    }

    // Ensure parent directory exists
    if let Some(parent) = priors_path.parent() {
        if let Err(err) = std::fs::create_dir_all(parent) {
            eprintln!(
                "agent import-priors: failed to create directory {}: {}",
                parent.display(),
                err
            );
            return ExitCode::IoError;
        }
    }

    // Write the priors atomically
    let tmp_path = priors_path.with_extension("json.tmp");
    let payload = match serde_json::to_vec_pretty(&final_priors) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("agent import-priors: failed to serialize: {}", err);
            return ExitCode::IoError;
        }
    };

    if let Err(err) = std::fs::write(&tmp_path, payload) {
        eprintln!(
            "agent import-priors: failed to write {}: {}",
            tmp_path.display(),
            err
        );
        return ExitCode::IoError;
    }

    if let Err(err) = std::fs::rename(&tmp_path, &priors_path) {
        eprintln!(
            "agent import-priors: failed to rename {} to {}: {}",
            tmp_path.display(),
            priors_path.display(),
            err
        );
        return ExitCode::IoError;
    }

    // Output result
    let response = serde_json::json!({
        "imported": true,
        "mode": mode,
        "source": input_path.display().to_string(),
        "target": priors_path.display().to_string(),
        "class_priors": {
            "useful": final_priors.classes.useful.prior_prob,
            "useful_bad": final_priors.classes.useful_bad.prior_prob,
            "abandoned": final_priors.classes.abandoned.prior_prob,
            "zombie": final_priors.classes.zombie.prior_prob,
        }
    });
    match global.format {
        OutputFormat::Json | OutputFormat::Toon => {
            println!("{}", format_structured_output(global, response));
        }
        OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string_pretty(&response).unwrap());
        }
        _ => {
            println!(
                "Imported priors from {} to {} (mode: {})",
                input_path.display(),
                priors_path.display(),
                mode
            );
        }
    }

    ExitCode::Clean
}

/// Agent export: alias for bundle create with agent-friendly defaults
fn run_agent_export(global: &GlobalOpts, args: &AgentExportArgs) -> ExitCode {
    run_bundle_create(
        global,
        &args.session,
        &args.out,
        &args.profile,
        args.include_telemetry,
        args.include_dumps,
        args.encrypt,
        &args.passphrase,
    )
}

fn run_agent_init(global: &GlobalOpts, args: &AgentInitArgs) -> ExitCode {
    use pt_core::agent_init::{initialize_agents, AgentType, InitOptions};

    // Parse agent filter
    let agent_filter = args.agent.as_ref().and_then(|a| {
        match a.to_lowercase().as_str() {
            "claude" | "claude-code" | "claudecode" => Some(AgentType::ClaudeCode),
            "codex" => Some(AgentType::Codex),
            "copilot" | "github-copilot" => Some(AgentType::Copilot),
            "cursor" => Some(AgentType::Cursor),
            "windsurf" => Some(AgentType::Windsurf),
            _ => {
                eprintln!(
                    "agent init: unknown agent '{}'. Valid options: claude, codex, copilot, cursor, windsurf",
                    a
                );
                None
            }
        }
    });

    // If agent was specified but couldn't be parsed, exit
    if args.agent.is_some() && agent_filter.is_none() {
        return ExitCode::ArgsError;
    }

    let options = InitOptions {
        non_interactive: args.yes,
        dry_run: args.dry_run,
        agent_filter,
        skip_backup: args.skip_backup,
    };

    match initialize_agents(&options) {
        Ok(result) => {
            output_agent_init_result(global, &result);
            // Empty configured list is a valid outcome - nothing to configure
            ExitCode::Clean
        }
        Err(pt_core::agent_init::AgentInitError::NoAgentsFound) => {
            let response = serde_json::json!({
                "error": "no_agents_found",
                "message": "No supported coding agents found. Install Claude Code, Codex, Copilot, Cursor, or Windsurf first.",
                "supported_agents": ["claude-code", "codex", "copilot", "cursor", "windsurf"]
            });
            match global.format {
                OutputFormat::Json | OutputFormat::Toon => {
                    println!("{}", format_structured_output(global, response));
                }
                OutputFormat::Jsonl => {
                    println!("{}", serde_json::to_string_pretty(&response).unwrap());
                }
                _ => {
                    eprintln!("No supported coding agents found.");
                    eprintln!(
                        "Install one of: Claude Code, Codex, GitHub Copilot, Cursor, or Windsurf"
                    );
                }
            }
            // No agents found is a capability error - user needs to install agents
            ExitCode::CapabilityError
        }
        Err(pt_core::agent_init::AgentInitError::Config(
            pt_core::agent_init::ConfigError::DryRun,
        )) => {
            // Dry run is not an error
            ExitCode::Clean
        }
        Err(e) => {
            eprintln!("agent init: {}", e);
            ExitCode::IoError
        }
    }
}

fn output_agent_init_result(global: &GlobalOpts, result: &pt_core::agent_init::InitResult) {
    match global.format {
        OutputFormat::Json | OutputFormat::Toon => {
            let value = serde_json::to_value(result).unwrap_or_else(|_| serde_json::json!({}));
            println!("{}", format_structured_output(global, value));
        }
        OutputFormat::Jsonl => {
            println!("{}", serde_json::to_string_pretty(result).unwrap());
        }
        _ => {
            println!("Agent Initialization Summary");
            println!("============================\n");

            println!("Detected agents:");
            for agent in &result.detected {
                let status = if agent.info.is_installed {
                    "installed"
                } else {
                    "partial"
                };
                println!("  - {} ({})", agent.agent_type.display_name(), status);
                if let Some(version) = &agent.info.version {
                    println!("    Version: {}", version);
                }
            }
            println!();

            if !result.configured.is_empty() {
                println!("Configured:");
                for configured in &result.configured {
                    println!("  - {}", configured.agent_type.display_name());
                    println!("    Config: {}", configured.config_path.display());
                    for change in &configured.changes {
                        println!("    + {}", change);
                    }
                }
                println!();
            }

            if !result.skipped.is_empty() {
                println!("Skipped:");
                for skipped in &result.skipped {
                    println!(
                        "  - {}: {}",
                        skipped.agent_type.display_name(),
                        skipped.reason
                    );
                }
                println!();
            }

            if !result.backups.is_empty() {
                println!("Backups created:");
                for backup in &result.backups {
                    println!(
                        "  {} -> {}",
                        backup.original_path.display(),
                        backup.backup_path.display()
                    );
                }
                println!();
            }

            if result.configured.is_empty() {
                println!("No changes made. Use --dry-run to preview changes.");
            } else {
                println!("Configuration complete! Verify by restarting your coding agent.");
            }
        }
    }
}

fn run_agent_inbox(global: &GlobalOpts, args: &AgentInboxArgs) -> ExitCode {
    use pt_core::inbox::{InboxResponse, InboxStore};

    let store = match InboxStore::from_env() {
        Ok(store) => store,
        Err(e) => {
            eprintln!("agent inbox: failed to access inbox: {}", e);
            return ExitCode::InternalError;
        }
    };

    // Handle acknowledgement
    if let Some(ref item_id) = args.ack {
        match store.acknowledge(item_id) {
            Ok(item) => {
                match global.format {
                    OutputFormat::Json | OutputFormat::Toon => {
                        let response = serde_json::json!({
                            "acknowledged": true,
                            "item_id": item.id,
                            "acknowledged_at": item.acknowledged_at,
                        });
                        println!("{}", format_structured_output(global, response));
                    }
                    _ => {
                        println!("Acknowledged: {}", item.id);
                    }
                }
                return ExitCode::Clean;
            }
            Err(e) => {
                eprintln!("agent inbox: {}", e);
                return ExitCode::ArgsError;
            }
        }
    }

    // Handle clear all
    if args.clear_all {
        match store.clear_all() {
            Ok(count) => {
                match global.format {
                    OutputFormat::Json | OutputFormat::Toon => {
                        let response = serde_json::json!({
                            "cleared": count,
                            "clear_type": "all",
                        });
                        println!("{}", format_structured_output(global, response));
                    }
                    _ => {
                        println!("Cleared {} items", count);
                    }
                }
                return ExitCode::Clean;
            }
            Err(e) => {
                eprintln!("agent inbox: {}", e);
                return ExitCode::InternalError;
            }
        }
    }

    // Handle clear acknowledged
    if args.clear {
        match store.clear_acknowledged() {
            Ok(count) => {
                match global.format {
                    OutputFormat::Json | OutputFormat::Toon => {
                        let response = serde_json::json!({
                            "cleared": count,
                            "clear_type": "acknowledged",
                        });
                        println!("{}", format_structured_output(global, response));
                    }
                    _ => {
                        println!("Cleared {} acknowledged items", count);
                    }
                }
                return ExitCode::Clean;
            }
            Err(e) => {
                eprintln!("agent inbox: {}", e);
                return ExitCode::InternalError;
            }
        }
    }

    // List items (default action)
    let items = match if args.unread {
        store.list_unread()
    } else {
        store.list()
    } {
        Ok(items) => items,
        Err(e) => {
            eprintln!("agent inbox: {}", e);
            return ExitCode::InternalError;
        }
    };

    let response = InboxResponse::new(items.clone());

    match global.format {
        OutputFormat::Json | OutputFormat::Toon => {
            let response_value = serde_json::to_value(&response).unwrap_or_default();
            println!("{}", format_structured_output(global, response_value));
        }
        OutputFormat::Jsonl => {
            // One item per line
            for item in &items {
                println!("{}", serde_json::to_string(item).unwrap());
            }
        }
        OutputFormat::Summary => {
            if items.is_empty() {
                println!("Inbox: 0 items");
            } else {
                println!(
                    "Inbox: {} items ({} unread)",
                    items.len(),
                    response.unread_count
                );
            }
        }
        OutputFormat::Exitcode => {}
        OutputFormat::Metrics => {
            println!("inbox_total={}", items.len());
            println!("inbox_unread={}", response.unread_count);
        }
        _ => {
            // Human-readable output
            if items.is_empty() {
                println!("# Agent Inbox\n");
                println!("No items in inbox.");
            } else {
                println!("# Agent Inbox\n");
                println!(
                    "{} item(s), {} unread\n",
                    items.len(),
                    response.unread_count
                );
                for item in &items {
                    let status = if item.acknowledged { "✓" } else { "○" };
                    println!(
                        "{} [{}] {} - {}",
                        status, item.item_type, item.id, item.summary
                    );
                    if let Some(ref session_id) = item.session_id {
                        println!("  Session: {}", session_id);
                    }
                    if let Some(ref cmd) = item.review_command {
                        println!("  Review: {}", cmd);
                    }
                    println!("  Created: {}", item.created_at);
                    println!();
                }
            }
        }
    }

    ExitCode::Clean
}

fn run_agent_tail(_global: &GlobalOpts, args: &AgentTailArgs) -> ExitCode {
    use std::io::{BufRead, BufReader, Write};
    use std::thread::sleep;
    use std::time::Duration;

    let store = match SessionStore::from_env() {
        Ok(store) => store,
        Err(e) => {
            eprintln!("agent tail: session store error: {}", e);
            return ExitCode::InternalError;
        }
    };

    let sid = match SessionId::parse(&args.session) {
        Some(sid) => sid,
        None => {
            eprintln!("agent tail: invalid --session {}", args.session);
            return ExitCode::ArgsError;
        }
    };

    let handle = match store.open(&sid) {
        Ok(handle) => handle,
        Err(e) => {
            eprintln!("agent tail: {}", e);
            return ExitCode::ArgsError;
        }
    };

    let log_path = handle.dir.join("logs").join("session.jsonl");

    loop {
        if !log_path.exists() {
            if args.follow {
                sleep(Duration::from_millis(250));
                continue;
            }
            eprintln!("agent tail: no session log found at {}", log_path.display());
            return ExitCode::ArgsError;
        }

        let file = match std::fs::File::open(&log_path) {
            Ok(file) => file,
            Err(e) => {
                if args.follow {
                    eprintln!(
                        "agent tail: waiting for session log {} ({})",
                        log_path.display(),
                        e
                    );
                    sleep(Duration::from_millis(250));
                    continue;
                }
                eprintln!("agent tail: failed to open {}: {}", log_path.display(), e);
                return ExitCode::IoError;
            }
        };

        let mut reader = BufReader::new(file);
        loop {
            let mut line = String::new();
            let bytes = match reader.read_line(&mut line) {
                Ok(bytes) => bytes,
                Err(e) => {
                    eprintln!("agent tail: read error: {}", e);
                    return ExitCode::IoError;
                }
            };

            if bytes == 0 {
                if args.follow {
                    sleep(Duration::from_millis(250));
                    continue;
                }
                return ExitCode::Clean;
            }

            print!("{}", line);
            let _ = std::io::stdout().flush();

            if let Ok(value) = serde_json::from_str::<serde_json::Value>(line.trim_end()) {
                let event_name = value.get("event").and_then(|v| v.as_str());
                if event_name == Some(pt_core::events::event_names::SESSION_ENDED) {
                    return ExitCode::Clean;
                }
            }
        }
    }
}

#[cfg(feature = "report")]
fn run_agent_report(global: &GlobalOpts, args: &AgentReportArgs) -> ExitCode {
    use pt_report::{ReportConfig, ReportGenerator, ReportTheme};

    // Validate inputs: need either session or bundle
    if args.session.is_none() && args.bundle.is_none() {
        eprintln!("agent report: must specify either --session or --bundle");
        return ExitCode::ArgsError;
    }

    // Parse theme
    let theme = match args.theme.to_lowercase().as_str() {
        "light" => ReportTheme::Light,
        "dark" => ReportTheme::Dark,
        "auto" | "" => ReportTheme::Auto,
        _ => {
            eprintln!(
                "agent report: invalid theme '{}', use: light, dark, auto",
                args.theme
            );
            return ExitCode::ArgsError;
        }
    };

    // Build report configuration
    let mut config = ReportConfig::new()
        .with_theme(theme)
        .with_galaxy_brain(args.galaxy_brain)
        .with_embed_assets(args.embed_assets);

    if let Some(ref title) = args.title {
        config = config.with_title(title.clone());
    }
    config.redaction_profile = args.profile.clone();

    let generator = ReportGenerator::new(config);

    // Generate report from bundle or session
    let html_result = if let Some(ref bundle_path) = args.bundle {
        // Generate from bundle file
        let path = std::path::Path::new(bundle_path);
        if !path.exists() {
            eprintln!("agent report: bundle file not found: {}", bundle_path);
            return ExitCode::ArgsError;
        }

        let mut reader = match pt_bundle::BundleReader::open(path) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("agent report: failed to read bundle: {}", e);
                return ExitCode::InternalError;
            }
        };

        generator.generate_from_bundle(&mut reader)
    } else if let Some(ref session_id_str) = args.session {
        // Generate from session directory
        let store = match SessionStore::from_env() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("agent report: session store error: {}", e);
                return ExitCode::InternalError;
            }
        };

        let session_id = match SessionId::parse(session_id_str) {
            Some(sid) => sid,
            None => {
                eprintln!("agent report: invalid session ID: {}", session_id_str);
                return ExitCode::ArgsError;
            }
        };

        let handle = match store.open(&session_id) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("agent report: session not found: {}", e);
                return ExitCode::ArgsError;
            }
        };

        // Read session data and build report
        generate_report_from_session(&generator, &handle)
    } else {
        unreachable!("already validated session or bundle is present");
    };

    let html = match html_result {
        Ok(h) => h,
        Err(e) => {
            eprintln!("agent report: failed to generate report: {}", e);
            return ExitCode::InternalError;
        }
    };

    // Handle different output formats
    match args.report_format.to_lowercase().as_str() {
        "html" => {
            // Write HTML to file or stdout
            if let Some(ref out_path) = args.out {
                match std::fs::write(out_path, &html) {
                    Ok(_) => match global.format {
                        OutputFormat::Json | OutputFormat::Toon => {
                            let response = serde_json::json!({
                                "status": "success",
                                "output_path": out_path,
                                "size_bytes": html.len(),
                                "format": "html",
                            });
                            println!("{}", format_structured_output(global, response));
                        }
                        _ => {
                            println!("Report written to: {}", out_path);
                        }
                    },
                    Err(e) => {
                        eprintln!("agent report: failed to write output: {}", e);
                        return ExitCode::InternalError;
                    }
                }
            } else {
                // Write to stdout
                print!("{}", html);
            }
        }
        "slack" => {
            // Generate Slack-friendly summary
            let summary = generate_slack_summary(&args.prose_style);
            match global.format {
                OutputFormat::Json | OutputFormat::Toon => {
                    let response = serde_json::json!({
                        "format": "slack",
                        "prose_style": args.prose_style,
                        "content": summary,
                    });
                    println!("{}", format_structured_output(global, response));
                }
                _ => {
                    println!("{}", summary);
                }
            }
        }
        "prose" => {
            // Generate prose summary
            let summary = generate_prose_summary(&args.prose_style);
            match global.format {
                OutputFormat::Json | OutputFormat::Toon => {
                    let response = serde_json::json!({
                        "format": "prose",
                        "prose_style": args.prose_style,
                        "content": summary,
                    });
                    println!("{}", format_structured_output(global, response));
                }
                _ => {
                    println!("{}", summary);
                }
            }
        }
        _ => {
            eprintln!(
                "agent report: invalid format '{}', use: html, slack, prose",
                args.report_format
            );
            return ExitCode::ArgsError;
        }
    }

    ExitCode::Clean
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum WatchSeverity {
    Low,
    Medium,
    High,
    Critical,
}

struct WatchThreshold {
    level: WatchSeverity,
    min_prob: f64,
}

struct WatchCandidate {
    start_id: String,
    severity: WatchSeverity,
    confidence: f64,
    classification: String,
    command: String,
}

fn run_agent_watch(global: &GlobalOpts, args: &AgentWatchArgs) -> ExitCode {
    use std::io::Write;
    use std::thread::sleep;
    use std::time::Duration;

    if !matches!(global.format, OutputFormat::Jsonl) {
        eprintln!("agent watch: --format jsonl required for streaming output");
        return ExitCode::ArgsError;
    }

    let threshold = match parse_watch_threshold(&args.threshold) {
        Ok(threshold) => threshold,
        Err(err) => {
            eprintln!("agent watch: {}", err);
            return ExitCode::ArgsError;
        }
    };

    let config_options = ConfigOptions {
        config_dir: global.config.as_ref().map(PathBuf::from),
        ..Default::default()
    };
    let config = match load_config(&config_options) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("agent watch: config error: {}", err);
            return ExitCode::InternalError;
        }
    };
    let priors = config.priors;
    let policy = config.policy;

    let scan_options = QuickScanOptions {
        pids: vec![],
        include_kernel_threads: false,
        timeout: global.timeout.map(std::time::Duration::from_secs),
        progress: None,
    };

    let mut baseline: Option<WatchBaseline> = None;
    let mut previous: HashMap<u32, WatchCandidate> = HashMap::new();
    let interval = Duration::from_secs(args.interval.max(1));
    let notify_cmd = args.notify_cmd.as_deref();
    let notify_exec = args.notify_exec.as_deref();
    let notify_args = &args.notify_arg;

    if notify_cmd.is_some() && notify_exec.is_some() {
        eprintln!("agent watch: both --notify-cmd and --notify-exec set; using --notify-cmd");
    }

    loop {
        let system_state = collect_system_state();
        if baseline.is_none() {
            baseline = Some(WatchBaseline::from_state(&system_state));
        }

        if let Some(event) = check_goal_violation(&system_state, args) {
            emit_watch_event(&event, notify_exec, notify_cmd, notify_args);
        }
        if let Some(event) = check_baseline_anomaly(&system_state, baseline.as_ref()) {
            emit_watch_event(&event, notify_exec, notify_cmd, notify_args);
        }

        let scan_result = match quick_scan(&scan_options) {
            Ok(scan) => scan,
            Err(err) => {
                eprintln!("agent watch: scan failed: {}", err);
                return ExitCode::InternalError;
            }
        };

        let protected_filter = match ProtectedFilter::from_guardrails(&policy.guardrails) {
            Ok(filter) => filter,
            Err(err) => {
                eprintln!("agent watch: protected filter error: {}", err);
                return ExitCode::InternalError;
            }
        };
        let filtered = protected_filter.filter_scan_result(&scan_result);

        let load_adjustment = if policy.load_aware.enabled {
            let signals = LoadSignals::from_system_state(&system_state, filtered.passed.len());
            compute_load_adjustment(&policy.load_aware, &signals)
        } else {
            None
        };
        let decision_policy = if let Some(adjustment) = &load_adjustment {
            let mut adjusted = policy.clone();
            adjusted.loss_matrix = apply_load_to_loss_matrix(&policy.loss_matrix, adjustment);
            adjusted
        } else {
            policy.clone()
        };

        let mut current: HashMap<u32, WatchCandidate> = HashMap::new();

        for proc in &filtered.passed {
            if proc.pid.0 == 0 || proc.pid.0 == 1 {
                continue;
            }
            if let Some(min_age) = args.min_age {
                if proc.elapsed.as_secs() < min_age {
                    continue;
                }
            }

            let Some(eval) = evaluate_watch_candidate(proc, &priors, &decision_policy) else {
                continue;
            };
            if eval.confidence < threshold.min_prob {
                continue;
            }
            let severity = severity_from_confidence(eval.confidence);
            if severity < threshold.level {
                continue;
            }

            let candidate = WatchCandidate {
                start_id: proc.start_id.0.clone(),
                severity,
                confidence: eval.confidence,
                classification: eval.classification.clone(),
                command: proc.cmd.clone(),
            };

            let emit_new = match previous.get(&proc.pid.0) {
                Some(prev) if prev.start_id == candidate.start_id => {
                    if candidate.severity > prev.severity {
                        let event = serde_json::json!({
                            "event": "severity_escalated",
                            "timestamp": chrono::Utc::now().to_rfc3339(),
                            "pid": proc.pid.0,
                            "classification": candidate.classification,
                            "prior_confidence": prev.confidence,
                            "current_confidence": candidate.confidence,
                            "prior_severity": severity_label(prev.severity),
                            "current_severity": severity_label(candidate.severity),
                            "command": candidate.command,
                        });
                        emit_watch_event(&event, notify_exec, notify_cmd, notify_args);
                    }
                    false
                }
                _ => true,
            };

            if emit_new {
                let event = serde_json::json!({
                    "event": "candidate_detected",
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "pid": proc.pid.0,
                    "classification": candidate.classification,
                    "confidence": candidate.confidence,
                    "severity": severity_label(candidate.severity),
                    "command": candidate.command,
                });
                emit_watch_event(&event, notify_exec, notify_cmd, notify_args);
            }

            current.insert(proc.pid.0, candidate);
        }

        previous = current;

        let _ = std::io::stdout().flush();

        if args.once {
            break;
        }
        sleep(interval);
    }

    ExitCode::Clean
}

struct WatchEval {
    confidence: f64,
    classification: String,
}

fn evaluate_watch_candidate(
    proc: &ProcessRecord,
    priors: &Priors,
    policy: &pt_core::config::Policy,
) -> Option<WatchEval> {
    let evidence = Evidence {
        cpu: Some(CpuEvidence::Fraction {
            occupancy: (proc.cpu_percent / 100.0).clamp(0.0, 1.0),
        }),
        runtime_seconds: Some(proc.elapsed.as_secs_f64()),
        orphan: Some(proc.is_orphan()),
        tty: Some(proc.has_tty()),
        net: None,
        io_active: None,
        state_flag: state_to_flag(proc.state),
        command_category: None,
    };

    let posterior_result = compute_posterior(priors, &evidence).ok()?;
    let decision_outcome = decide_action(
        &posterior_result.posterior,
        policy,
        &ActionFeasibility::allow_all(),
    )
    .ok()?;

    let classification = match decision_outcome.optimal_action {
        Action::Kill => "kill",
        Action::Keep => "spare",
        _ => "review",
    }
    .to_string();

    let confidence = posterior_result
        .posterior
        .abandoned
        .max(posterior_result.posterior.zombie)
        .clamp(0.0, 1.0);

    Some(WatchEval {
        confidence,
        classification,
    })
}

fn parse_watch_threshold(raw: &str) -> Result<WatchThreshold, String> {
    match raw.trim().to_lowercase().as_str() {
        "low" => Ok(WatchThreshold {
            level: WatchSeverity::Low,
            min_prob: 0.5,
        }),
        "medium" => Ok(WatchThreshold {
            level: WatchSeverity::Medium,
            min_prob: 0.7,
        }),
        "high" => Ok(WatchThreshold {
            level: WatchSeverity::High,
            min_prob: 0.85,
        }),
        "critical" => Ok(WatchThreshold {
            level: WatchSeverity::Critical,
            min_prob: 0.95,
        }),
        other => Err(format!(
            "invalid --threshold {} (expected low|medium|high|critical)",
            other
        )),
    }
}

fn severity_from_confidence(confidence: f64) -> WatchSeverity {
    if confidence >= 0.95 {
        WatchSeverity::Critical
    } else if confidence >= 0.85 {
        WatchSeverity::High
    } else if confidence >= 0.7 {
        WatchSeverity::Medium
    } else {
        WatchSeverity::Low
    }
}

fn severity_label(severity: WatchSeverity) -> &'static str {
    match severity {
        WatchSeverity::Low => "low",
        WatchSeverity::Medium => "medium",
        WatchSeverity::High => "high",
        WatchSeverity::Critical => "critical",
    }
}

struct WatchBaseline {
    load1: f64,
    available_gb: f64,
}

impl WatchBaseline {
    fn from_state(state: &serde_json::Value) -> Self {
        Self {
            load1: read_load1(state).unwrap_or(0.0),
            available_gb: read_available_gb(state).unwrap_or(0.0),
        }
    }
}

fn read_load1(state: &serde_json::Value) -> Option<f64> {
    state
        .get("load")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| v.as_f64())
}

fn read_available_gb(state: &serde_json::Value) -> Option<f64> {
    state
        .get("memory")
        .and_then(|v| v.get("available_gb"))
        .and_then(|v| v.as_f64())
}

fn check_goal_violation(
    state: &serde_json::Value,
    args: &AgentWatchArgs,
) -> Option<serde_json::Value> {
    if let Some(goal_mem) = args.goal_memory_available_gb {
        if let Some(available) = read_available_gb(state) {
            if available < goal_mem {
                return Some(serde_json::json!({
                    "event": "goal_violated",
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "goal": format!("memory_available_gb >= {}", goal_mem),
                    "current": format!("{:.2}", available),
                }));
            }
        }
    }

    if let Some(goal_load) = args.goal_load_max {
        if let Some(load1) = read_load1(state) {
            if load1 > goal_load {
                return Some(serde_json::json!({
                    "event": "goal_violated",
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "goal": format!("load1 <= {}", goal_load),
                    "current": format!("{:.2}", load1),
                }));
            }
        }
    }

    None
}

fn check_baseline_anomaly(
    state: &serde_json::Value,
    baseline: Option<&WatchBaseline>,
) -> Option<serde_json::Value> {
    let baseline = baseline?;
    if baseline.load1 > 0.0 {
        if let Some(load1) = read_load1(state) {
            if load1 > baseline.load1 * 1.5 {
                return Some(serde_json::json!({
                    "event": "baseline_anomaly",
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "metric": "load1",
                    "baseline": format!("{:.2}", baseline.load1),
                    "current": format!("{:.2}", load1),
                }));
            }
        }
    }
    if baseline.available_gb > 0.0 {
        if let Some(available) = read_available_gb(state) {
            if available < baseline.available_gb * 0.7 {
                return Some(serde_json::json!({
                    "event": "baseline_anomaly",
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "metric": "memory_available_gb",
                    "baseline": format!("{:.2}", baseline.available_gb),
                    "current": format!("{:.2}", available),
                }));
            }
        }
    }
    None
}

fn emit_watch_event(
    event: &serde_json::Value,
    notify_exec: Option<&str>,
    notify_cmd: Option<&str>,
    notify_args: &[String],
) {
    println!(
        "{}",
        serde_json::to_string(event).unwrap_or_else(|_| "{}".to_string())
    );
    let event_type = event
        .get("event")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let json = event.to_string();
    if let Some(cmd) = notify_cmd {
        let mut child = std::process::Command::new(cmd);
        for arg in notify_args {
            child.arg(arg);
        }
        child.env("PT_WATCH_EVENT", event_type);
        child.env("PT_WATCH_EVENT_JSON", &json);
        if let Some(pid) = event.get("pid").and_then(|v| v.as_u64()) {
            child.env("PT_WATCH_PID", pid.to_string());
        }
        if let Err(err) = child.status() {
            eprintln!("agent watch: notify-cmd failed: {}", err);
        }
        return;
    }

    if let Some(cmd) = notify_exec {
        let mut child = std::process::Command::new("sh");
        child.arg("-c").arg(cmd);
        child.env("PT_WATCH_EVENT", event_type);
        child.env("PT_WATCH_EVENT_JSON", &json);
        if let Some(pid) = event.get("pid").and_then(|v| v.as_u64()) {
            child.env("PT_WATCH_PID", pid.to_string());
        }
        if let Err(err) = child.status() {
            eprintln!("agent watch: notify-exec failed: {}", err);
        }
    }
}

#[cfg(test)]
mod watch_tests {
    use super::*;

    #[test]
    fn test_parse_watch_threshold() {
        let medium = parse_watch_threshold("medium").expect("medium");
        assert_eq!(medium.level, WatchSeverity::Medium);
        assert_eq!(medium.min_prob, 0.7);

        assert!(parse_watch_threshold("critical").is_ok());
        assert!(parse_watch_threshold("unknown").is_err());
    }

    #[test]
    fn test_severity_from_confidence() {
        assert_eq!(severity_from_confidence(0.96), WatchSeverity::Critical);
        assert_eq!(severity_from_confidence(0.9), WatchSeverity::High);
        assert_eq!(severity_from_confidence(0.75), WatchSeverity::Medium);
        assert_eq!(severity_from_confidence(0.4), WatchSeverity::Low);
    }

    #[test]
    fn test_goal_violation_memory() {
        let state = serde_json::json!({
            "load": [0.2, 0.1, 0.05],
            "memory": {"available_gb": 1.0}
        });
        let args = AgentWatchArgs {
            notify_exec: None,
            notify_cmd: None,
            notify_arg: Vec::new(),
            threshold: "medium".to_string(),
            interval: 60,
            min_age: None,
            once: true,
            goal_memory_available_gb: Some(2.0),
            goal_load_max: None,
        };
        let event = check_goal_violation(&state, &args).expect("goal violation");
        assert_eq!(
            event.get("event").and_then(|v| v.as_str()),
            Some("goal_violated")
        );
    }

    #[test]
    fn test_baseline_anomaly_load() {
        let baseline_state = serde_json::json!({
            "load": [1.0, 0.5, 0.2],
            "memory": {"available_gb": 4.0}
        });
        let baseline = WatchBaseline::from_state(&baseline_state);
        let current_state = serde_json::json!({
            "load": [2.0, 1.0, 0.5],
            "memory": {"available_gb": 4.0}
        });
        let event =
            check_baseline_anomaly(&current_state, Some(&baseline)).expect("baseline anomaly");
        assert_eq!(
            event.get("event").and_then(|v| v.as_str()),
            Some("baseline_anomaly")
        );
    }
}

/// Generate a report from session directory data.
#[cfg(feature = "report")]
fn generate_report_from_session(
    generator: &pt_report::ReportGenerator,
    handle: &pt_core::session::SessionHandle,
) -> pt_report::Result<String> {
    use pt_report::sections::*;
    use pt_report::ReportData;

    // Read manifest for session metadata
    let manifest = handle
        .read_manifest()
        .map_err(|e| pt_report::ReportError::MissingData(format!("manifest: {}", e)))?;

    // Build overview section from session data
    let overview = OverviewSection {
        session_id: manifest.session_id.clone(),
        host_id: manifest.session_id.clone(), // Will be refined
        hostname: None,
        started_at: chrono::DateTime::parse_from_rfc3339(&manifest.timing.created_at)
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .unwrap_or_else(|_| chrono::Utc::now()),
        ended_at: manifest.timing.updated_at.as_ref().and_then(|ts| {
            chrono::DateTime::parse_from_rfc3339(ts)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .ok()
        }),
        duration_ms: None,
        state: format!("{:?}", manifest.state).to_lowercase(),
        mode: format!("{:?}", manifest.mode).to_lowercase(),
        deep_scan: false,
        processes_scanned: 0,
        candidates_found: 0,
        kills_attempted: 0,
        kills_successful: 0,
        spares: 0,
        os_family: None,
        os_version: None,
        kernel_version: None,
        arch: None,
        cores: None,
        memory_bytes: None,
        pt_version: None,
        export_profile: "safe".to_string(),
    };

    // Try to read plan.json for candidate count
    let plan_path = handle.dir.join("decision").join("plan.json");
    let candidates_count = if plan_path.exists() {
        std::fs::read_to_string(&plan_path)
            .ok()
            .and_then(|c| serde_json::from_str::<serde_json::Value>(&c).ok())
            .and_then(|v| {
                v.get("candidates")
                    .and_then(|c| c.as_array())
                    .map(|a| a.len())
                    .or_else(|| {
                        v.get("summary")
                            .and_then(|s| s.get("candidates_returned"))
                            .and_then(|v| v.as_u64())
                            .map(|v| v as usize)
                    })
                    .or_else(|| {
                        v.get("gates_summary")
                            .and_then(|g| g.get("total_candidates"))
                            .and_then(|v| v.as_u64())
                            .map(|v| v as usize)
                    })
                    .or_else(|| v.get("actions").and_then(|a| a.as_array()).map(|a| a.len()))
            })
            .unwrap_or(0)
    } else {
        0
    };

    // Build report data
    let data = ReportData {
        config: generator.config().clone(),
        generated_at: chrono::Utc::now(),
        generator_version: env!("CARGO_PKG_VERSION").to_string(),
        overview: Some(OverviewSection {
            candidates_found: candidates_count,
            ..overview
        }),
        candidates: None, // Would be populated from plan.json
        evidence: None,
        actions: None,
        galaxy_brain: if generator.config().galaxy_brain {
            Some(GalaxyBrainSection::default())
        } else {
            None
        },
    };

    generator.generate(data)
}

/// Generate Slack-friendly summary.
#[cfg(feature = "report")]
fn generate_slack_summary(prose_style: &str) -> String {
    match prose_style {
        "terse" => {
            "*Process Triage Summary*\n• Session completed\n• No critical issues found".to_string()
        }
        "formal" => "*Process Triage Report*\n\nThe session has been completed successfully. \
             All processes have been analyzed according to the configured policy.\n\n\
             _Report generated by pt-core_"
            .to_string(),
        "technical" => "*Process Triage Technical Summary*\n\n\
             ```\n\
             Session: completed\n\
             Candidates: analyzed\n\
             Actions: pending review\n\
             ```\n\n\
             See full HTML report for detailed evidence ledger and posterior computations."
            .to_string(),
        _ => {
            // conversational (default)
            "*Process Triage Complete* 🎯\n\n\
             I've finished analyzing your processes. The session has been saved \
             and you can review the detailed findings in the HTML report.\n\n\
             Let me know if you'd like me to explain any of the recommendations!"
                .to_string()
        }
    }
}

/// Generate prose summary for agent-to-user communication.
#[cfg(feature = "report")]
fn generate_prose_summary(prose_style: &str) -> String {
    match prose_style {
        "terse" => "Session complete. Candidates analyzed. Report ready.".to_string(),
        "formal" => "The process triage session has concluded. All candidate processes have been \
             evaluated using Bayesian inference, and recommendations have been generated \
             based on the configured policy parameters. The full report is available for \
             your review."
            .to_string(),
        "technical" => "Process triage session completed. The inference engine computed posterior \
             probabilities for each candidate across the four-class model (useful, useful_bad, \
             abandoned, zombie). Expected loss calculations and FDR control were applied \
             to generate action recommendations. See the galaxy-brain tab in the HTML report \
             for full mathematical derivations."
            .to_string(),
        _ => {
            // conversational (default)
            "All done! I've analyzed your running processes and identified any that might \
             be abandoned or stuck. You can check out the full report to see the details \
             and decide what to do with each one. The report shows my reasoning for each \
             recommendation, so you'll know exactly why I flagged something."
                .to_string()
        }
    }
}

fn run_agent_sessions(global: &GlobalOpts, args: &AgentSessionsArgs) -> ExitCode {
    // Validate flag combinations: --session mode is incompatible with list/cleanup options
    if args.session.is_some() {
        if args.cleanup {
            eprintln!("agent sessions: --session cannot be combined with --cleanup");
            return ExitCode::ArgsError;
        }
        if args.limit != 10 {
            eprintln!(
                "agent sessions: --session cannot be combined with --limit (limit only applies to list mode)"
            );
            return ExitCode::ArgsError;
        }
        if args.state.is_some() {
            eprintln!(
                "agent sessions: --session cannot be combined with --state (state filter only applies to list mode)"
            );
            return ExitCode::ArgsError;
        }
    }

    let store = match SessionStore::from_env() {
        Ok(store) => store,
        Err(e) => {
            eprintln!("agent sessions: session store error: {}", e);
            return ExitCode::InternalError;
        }
    };

    let host_id = pt_core::logging::get_host_id();

    // Handle single session detail query (consolidates show/status)
    if let Some(session_id_str) = &args.session {
        return run_agent_session_status(global, &store, session_id_str, &host_id, args.detail);
    }

    // Handle cleanup mode
    if args.cleanup {
        return run_agent_sessions_cleanup(global, &store, &args.older_than, &host_id);
    }

    // Default: list sessions
    run_agent_sessions_list(global, &store, args, &host_id)
}

fn run_agent_session_status(
    global: &GlobalOpts,
    store: &SessionStore,
    session_id_str: &str,
    host_id: &str,
    include_detail: bool,
) -> ExitCode {
    let session_id = match SessionId::parse(session_id_str) {
        Some(sid) => sid,
        None => {
            eprintln!("agent sessions: invalid session ID: {}", session_id_str);
            return ExitCode::ArgsError;
        }
    };

    let handle = match store.open(&session_id) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("agent sessions: {}", e);
            return ExitCode::ArgsError;
        }
    };

    let manifest = match handle.read_manifest() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("agent sessions: failed to read manifest: {}", e);
            return ExitCode::InternalError;
        }
    };

    // Determine if session is resumable
    let resumable = matches!(
        manifest.state,
        SessionState::Created
            | SessionState::Scanning
            | SessionState::Planned
            | SessionState::Executing
            | SessionState::Cancelled
    );

    // Count progress from action outcomes and plan metadata.
    let outcomes_path = handle.dir.join("action").join("outcomes.jsonl");
    let plan_path = handle.dir.join("decision").join("plan.json");
    let plan_value = std::fs::read_to_string(&plan_path)
        .ok()
        .and_then(|c| serde_json::from_str::<serde_json::Value>(&c).ok());

    let completed_actions = if outcomes_path.exists() {
        let content = std::fs::read_to_string(&outcomes_path).unwrap_or_default();
        content.lines().filter(|l| !l.trim().is_empty()).count()
    } else {
        0
    };

    let plan_total = plan_value
        .as_ref()
        .and_then(|v| {
            v.get("actions")
                .and_then(|a| a.as_array())
                .map(|a| a.len())
                .or_else(|| {
                    v.get("recommended")
                        .and_then(|r| r.get("actions"))
                        .and_then(|a| a.as_array())
                        .map(|a| a.len())
                })
                .or_else(|| {
                    v.get("summary")
                        .and_then(|s| s.get("kill_recommendations"))
                        .and_then(|k| k.as_u64())
                        .map(|k| k as usize)
                })
                .or_else(|| {
                    v.get("candidates")
                        .and_then(|c| c.as_array())
                        .map(|a| a.len())
                })
        })
        .unwrap_or(0);

    let total_actions = if plan_total == 0 && completed_actions > 0 {
        completed_actions
    } else {
        plan_total
    };

    let pending_actions = total_actions.saturating_sub(completed_actions);

    // Load plan details if --detail flag is set
    let plan_detail = if include_detail {
        plan_value.clone()
    } else {
        None
    };

    // Load action outcomes if --detail flag is set
    let outcomes_detail = if include_detail {
        let outcomes_path = handle.dir.join("action").join("outcomes.jsonl");
        if outcomes_path.exists() {
            std::fs::read_to_string(&outcomes_path).ok().map(|content| {
                content
                    .lines()
                    .filter(|l| !l.trim().is_empty())
                    .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
                    .collect::<Vec<_>>()
            })
        } else {
            None
        }
    } else {
        None
    };

    match global.format {
        OutputFormat::Json | OutputFormat::Toon => {
            let mut output = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "session_id": manifest.session_id,
                "generated_at": chrono::Utc::now().to_rfc3339(),
                "host_id": host_id,
                "state": manifest.state,
                "mode": manifest.mode,
                "label": manifest.label,
                "timing": manifest.timing,
                "phase": match manifest.state {
                    SessionState::Created => "init",
                    SessionState::Scanning => "scan",
                    SessionState::Planned => "plan",
                    SessionState::Executing => "apply",
                    SessionState::Completed => "verify",
                    SessionState::Cancelled => "cancelled",
                    SessionState::Failed => "failed",
                    SessionState::Archived => "archived",
                },
                "progress": {
                    "total_actions": total_actions,
                    "completed_actions": completed_actions,
                    "pending_actions": pending_actions,
                },
                "resumable": resumable,
                "resume_command": if resumable && matches!(manifest.state, SessionState::Planned | SessionState::Executing) {
                    Some(format!("pt agent apply --session {} --resume", manifest.session_id))
                } else {
                    None
                },
                "state_history": manifest.state_history,
                "error": manifest.error,
                "status": "ok",
                "command": format!("pt agent sessions --session {}", manifest.session_id),
            });
            // Add detail if requested
            if include_detail {
                if let Some(plan) = &plan_detail {
                    output
                        .as_object_mut()
                        .unwrap()
                        .insert("plan".to_string(), plan.clone());
                }
                if let Some(outcomes) = &outcomes_detail {
                    output
                        .as_object_mut()
                        .unwrap()
                        .insert("outcomes".to_string(), serde_json::json!(outcomes));
                }
            }
            println!("{}", format_structured_output(global, output));
        }
        OutputFormat::Summary => {
            let status_char = if resumable { "⏸" } else { "✓" };
            println!(
                "[{}] {} {:?} ({}/{} actions)",
                manifest.session_id, status_char, manifest.state, completed_actions, total_actions
            );
        }
        OutputFormat::Exitcode => {}
        _ => {
            println!("# Session Status: {}", manifest.session_id);
            println!();
            println!("State: {:?}", manifest.state);
            println!("Mode: {:?}", manifest.mode);
            if let Some(label) = &manifest.label {
                println!("Label: {}", label);
            }
            println!("Created: {}", manifest.timing.created_at);
            if let Some(updated) = &manifest.timing.updated_at {
                println!("Updated: {}", updated);
            }
            println!();
            println!("## Progress");
            println!("  Total actions: {}", total_actions);
            println!("  Completed: {}", completed_actions);
            println!("  Pending: {}", pending_actions);
            println!();
            println!("Resumable: {}", if resumable { "yes" } else { "no" });
            if resumable
                && matches!(
                    manifest.state,
                    SessionState::Planned | SessionState::Executing
                )
            {
                println!(
                    "Resume with: pt agent apply --session {} --resume",
                    manifest.session_id
                );
            }
            if let Some(error) = &manifest.error {
                println!();
                println!("## Error");
                println!("{}", error);
            }

            // Print detail if requested
            if include_detail {
                if let Some(plan) = &plan_detail {
                    println!();
                    println!("## Plan Detail");
                    if let Some(candidates) = plan.get("candidates").and_then(|c| c.as_array()) {
                        println!("  Candidates: {}", candidates.len());
                        for (i, c) in candidates.iter().take(5).enumerate() {
                            let pid = c.get("pid").and_then(|v| v.as_u64()).unwrap_or(0);
                            let cmd = c.get("cmd_short").and_then(|v| v.as_str()).unwrap_or("?");
                            let action = c
                                .get("recommended_action")
                                .and_then(|v| v.as_str())
                                .unwrap_or("?");
                            println!("    {}. PID {} ({}) -> {}", i + 1, pid, cmd, action);
                        }
                        if candidates.len() > 5 {
                            println!("    ... and {} more", candidates.len() - 5);
                        }
                    }
                }
                if let Some(outcomes) = &outcomes_detail {
                    println!();
                    println!("## Action Outcomes");
                    for (i, o) in outcomes.iter().take(5).enumerate() {
                        let pid = o.get("pid").and_then(|v| v.as_u64()).unwrap_or(0);
                        let success = o.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
                        let status = if success { "✓" } else { "✗" };
                        println!("    {}. PID {} {}", i + 1, pid, status);
                    }
                    if outcomes.len() > 5 {
                        println!("    ... and {} more", outcomes.len() - 5);
                    }
                }
            }
        }
    }

    ExitCode::Clean
}

fn run_agent_sessions_cleanup(
    global: &GlobalOpts,
    store: &SessionStore,
    older_than_str: &str,
    host_id: &str,
) -> ExitCode {
    let duration = match parse_duration(older_than_str) {
        Some(d) => d,
        None => {
            eprintln!(
                "agent sessions: invalid --older-than '{}'. Use format like '7d', '24h', '30d'",
                older_than_str
            );
            return ExitCode::ArgsError;
        }
    };

    let result = match store.cleanup_sessions(duration) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("agent sessions: cleanup failed: {}", e);
            return ExitCode::InternalError;
        }
    };

    match global.format {
        OutputFormat::Json | OutputFormat::Toon => {
            let output = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "generated_at": chrono::Utc::now().to_rfc3339(),
                "host_id": host_id,
                "older_than": older_than_str,
                "removed_count": result.removed_count,
                "removed_sessions": result.removed_sessions,
                "preserved_count": result.preserved_count,
                "errors": result.errors,
                "status": if result.errors.is_empty() { "ok" } else { "partial" },
                "command": format!("pt agent sessions --cleanup --older-than {}", older_than_str),
            });
            println!("{}", format_structured_output(global, output));
        }
        OutputFormat::Summary => {
            println!(
                "Cleaned up {} sessions (preserved {})",
                result.removed_count, result.preserved_count
            );
        }
        OutputFormat::Exitcode => {}
        _ => {
            println!("# Session Cleanup");
            println!();
            println!("Older than: {}", older_than_str);
            println!("Removed: {} sessions", result.removed_count);
            println!(
                "Preserved: {} sessions (active or in-progress)",
                result.preserved_count
            );
            if !result.errors.is_empty() {
                println!();
                println!("## Errors");
                for error in &result.errors {
                    println!("  - {}", error);
                }
            }
            if !result.removed_sessions.is_empty() {
                println!();
                println!("## Removed Sessions");
                for session in &result.removed_sessions {
                    println!("  - {}", session);
                }
            }
        }
    }

    ExitCode::Clean
}

fn run_agent_sessions_list(
    global: &GlobalOpts,
    store: &SessionStore,
    args: &AgentSessionsArgs,
    host_id: &str,
) -> ExitCode {
    let state_filter = args
        .state
        .as_ref()
        .and_then(|s| match s.to_lowercase().as_str() {
            "created" => Some(SessionState::Created),
            "scanning" => Some(SessionState::Scanning),
            "planned" => Some(SessionState::Planned),
            "executing" => Some(SessionState::Executing),
            "completed" => Some(SessionState::Completed),
            "cancelled" => Some(SessionState::Cancelled),
            "failed" => Some(SessionState::Failed),
            "archived" => Some(SessionState::Archived),
            _ => None,
        });

    let options = ListSessionsOptions {
        limit: Some(args.limit),
        state: state_filter,
        older_than: None,
    };

    let sessions = match store.list_sessions(&options) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("agent sessions: failed to list sessions: {}", e);
            return ExitCode::InternalError;
        }
    };

    match global.format {
        OutputFormat::Json | OutputFormat::Toon => {
            let output = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "generated_at": chrono::Utc::now().to_rfc3339(),
                "host_id": host_id,
                "sessions": sessions.iter().map(|s| serde_json::json!({
                    "session_id": s.session_id,
                    "host": s.host_id,
                    "state": s.state,
                    "mode": s.mode,
                    "created_at": s.created_at,
                    "label": s.label,
                    "candidates": s.candidates_count,
                    "actions_taken": s.actions_count,
                })).collect::<Vec<_>>(),
                "total_count": sessions.len(),
                "status": "ok",
                "command": "pt agent sessions",
            });
            println!("{}", format_structured_output(global, output));
        }
        OutputFormat::Summary => {
            if sessions.is_empty() {
                println!("No sessions found");
            } else {
                println!("{} session(s)", sessions.len());
                for s in &sessions {
                    let state_char = match s.state {
                        SessionState::Created => "○",
                        SessionState::Scanning => "◎",
                        SessionState::Planned => "◉",
                        SessionState::Executing => "▶",
                        SessionState::Completed => "✓",
                        SessionState::Cancelled => "✗",
                        SessionState::Failed => "✗",
                        SessionState::Archived => "▣",
                    };
                    println!("  {} {} {:?}", state_char, s.session_id, s.state);
                }
            }
        }
        OutputFormat::Exitcode => {}
        _ => {
            println!("# Sessions");
            println!();
            if sessions.is_empty() {
                println!("No sessions found.");
            } else {
                println!(
                    "{:<26} {:<12} {:<10} {:<8} {:<8}",
                    "SESSION", "STATE", "MODE", "CANDS", "ACTIONS"
                );
                for s in &sessions {
                    println!(
                        "{:<26} {:<12?} {:<10?} {:<8} {:<8}",
                        s.session_id,
                        s.state,
                        s.mode,
                        s.candidates_count
                            .map(|c| c.to_string())
                            .unwrap_or_else(|| "-".to_string()),
                        s.actions_count
                            .map(|c| c.to_string())
                            .unwrap_or_else(|| "-".to_string()),
                    );
                }
            }
        }
    }

    ExitCode::Clean
}

// ============================================================================
// Update/Rollback Command Implementation
// ============================================================================

fn run_update(global: &GlobalOpts, args: &UpdateArgs) -> ExitCode {
    use pt_core::install::{BackupManager, RollbackManager};

    // Determine current binary path
    let binary_path = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            match global.format {
                OutputFormat::Json | OutputFormat::Toon => {
                    let error = serde_json::json!({
                        "error": format!("Could not determine current binary path: {}", e),
                        "suggestion": "Ensure pt-core is installed properly"
                    });
                    eprintln!("{}", format_structured_output(global, error));
                }
                _ => {
                    eprintln!("Error: Could not determine current binary path: {}", e);
                }
            }
            return ExitCode::IoError;
        }
    };

    let manager = RollbackManager::new(binary_path.clone(), "pt-core");

    match &args.command {
        UpdateCommands::ListBackups => {
            let backups = match manager.list_backups() {
                Ok(b) => b,
                Err(e) => {
                    match global.format {
                        OutputFormat::Json | OutputFormat::Toon => {
                            let error = serde_json::json!({
                                "error": format!("Failed to list backups: {}", e)
                            });
                            eprintln!("{}", format_structured_output(global, error));
                        }
                        _ => {
                            eprintln!("Error: Failed to list backups: {}", e);
                        }
                    }
                    return ExitCode::IoError;
                }
            };

            match global.format {
                OutputFormat::Json | OutputFormat::Toon => {
                    let backup_list: Vec<_> = backups
                        .iter()
                        .map(|b| {
                            serde_json::json!({
                                "version": b.metadata.version,
                                "created_at": b.metadata.created_at,
                                "checksum": b.metadata.checksum,
                                "size_bytes": b.metadata.size_bytes,
                                "path": b.binary_path.display().to_string()
                            })
                        })
                        .collect();
                    let output = serde_json::json!({
                        "schema_version": SCHEMA_VERSION,
                        "backups": backup_list,
                        "count": backups.len()
                    });
                    println!("{}", format_structured_output(global, output));
                }
                OutputFormat::Summary => {
                    if backups.is_empty() {
                        println!("No backups available");
                    } else {
                        println!("{} backup(s) available", backups.len());
                        for b in &backups {
                            println!("  {} ({})", b.metadata.version, b.metadata.created_at);
                        }
                    }
                }
                _ => {
                    println!("# Available Backups\n");
                    if backups.is_empty() {
                        println!("No backups found.");
                        println!("\nBackups are created automatically during updates.");
                    } else {
                        println!(
                            "{:<12} {:<28} {:<20} {:<12}",
                            "VERSION", "CREATED", "CHECKSUM", "SIZE"
                        );
                        for b in &backups {
                            println!(
                                "{:<12} {:<28} {:<20} {:<12}",
                                b.metadata.version,
                                &b.metadata.created_at
                                    [..std::cmp::min(28, b.metadata.created_at.len())],
                                &b.metadata.checksum
                                    [..std::cmp::min(16, b.metadata.checksum.len())],
                                format_bytes(b.metadata.size_bytes)
                            );
                        }
                    }
                }
            }
            ExitCode::Clean
        }

        UpdateCommands::ShowBackup { target } => {
            let backups = manager.list_backups().unwrap_or_default();
            let backup = backups.iter().find(|b| b.metadata.version == *target);

            match backup {
                Some(b) => {
                    match global.format {
                        OutputFormat::Json | OutputFormat::Toon => {
                            let output = serde_json::json!({
                                "schema_version": SCHEMA_VERSION,
                                "version": b.metadata.version,
                                "created_at": b.metadata.created_at,
                                "checksum": b.metadata.checksum,
                                "size_bytes": b.metadata.size_bytes,
                                "original_path": b.metadata.original_path,
                                "backup_path": b.binary_path.display().to_string(),
                                "metadata_path": b.metadata_path.display().to_string()
                            });
                            println!("{}", format_structured_output(global, output));
                        }
                        _ => {
                            println!("# Backup: {}\n", b.metadata.version);
                            println!("Version:       {}", b.metadata.version);
                            println!("Created:       {}", b.metadata.created_at);
                            println!("Checksum:      {}", b.metadata.checksum);
                            println!("Size:          {} bytes", b.metadata.size_bytes);
                            println!("Original Path: {}", b.metadata.original_path);
                            println!("Backup Path:   {}", b.binary_path.display());
                        }
                    }
                    ExitCode::Clean
                }
                None => {
                    match global.format {
                        OutputFormat::Json | OutputFormat::Toon => {
                            let error = serde_json::json!({
                                "error": format!("No backup found for version: {}", target)
                            });
                            eprintln!("{}", format_structured_output(global, error));
                        }
                        _ => {
                            eprintln!("Error: No backup found for version: {}", target);
                            eprintln!("\nUse 'pt update list-backups' to see available versions.");
                        }
                    }
                    ExitCode::PartialFail
                }
            }
        }

        UpdateCommands::VerifyBackup { target } => {
            let backups = manager.list_backups().unwrap_or_default();
            let backup = match target {
                Some(v) => backups.iter().find(|b| b.metadata.version == *v),
                None => backups.first(),
            };

            match backup {
                Some(b) => {
                    let is_valid = manager.backup_manager().verify_backup(b).unwrap_or(false);
                    match global.format {
                        OutputFormat::Json | OutputFormat::Toon => {
                            let output = serde_json::json!({
                                "schema_version": SCHEMA_VERSION,
                                "version": b.metadata.version,
                                "valid": is_valid,
                                "expected_checksum": b.metadata.checksum
                            });
                            println!("{}", format_structured_output(global, output));
                        }
                        _ => {
                            if is_valid {
                                println!(
                                    "Backup {} is valid (checksum matches)",
                                    b.metadata.version
                                );
                            } else {
                                eprintln!(
                                    "Backup {} is INVALID (checksum mismatch)",
                                    b.metadata.version
                                );
                            }
                        }
                    }
                    if is_valid {
                        ExitCode::Clean
                    } else {
                        ExitCode::PartialFail
                    }
                }
                None => {
                    match global.format {
                        OutputFormat::Json | OutputFormat::Toon => {
                            let error = serde_json::json!({
                                "error": "No backup available to verify"
                            });
                            eprintln!("{}", format_structured_output(global, error));
                        }
                        _ => {
                            eprintln!("Error: No backup available to verify");
                        }
                    }
                    ExitCode::PartialFail
                }
            }
        }

        UpdateCommands::Rollback { target, force: _ } => {
            let result = match target {
                Some(v) => manager.rollback_to_version(v),
                None => manager.rollback_to_latest(),
            };

            match result {
                Ok(rollback_result) => {
                    if rollback_result.success {
                        match global.format {
                            OutputFormat::Json | OutputFormat::Toon => {
                                let output = serde_json::json!({
                                    "schema_version": SCHEMA_VERSION,
                                    "status": "success",
                                    "restored_version": rollback_result.restored_version,
                                    "restored_path": rollback_result.restored_path.map(|p| p.display().to_string())
                                });
                                println!("{}", format_structured_output(global, output));
                            }
                            _ => {
                                println!(
                                    "Successfully rolled back to version {}",
                                    rollback_result
                                        .restored_version
                                        .unwrap_or_else(|| "unknown".to_string())
                                );
                            }
                        }
                        ExitCode::Clean
                    } else {
                        match global.format {
                            OutputFormat::Json | OutputFormat::Toon => {
                                let error = serde_json::json!({
                                    "status": "failed",
                                    "error": rollback_result.error
                                });
                                eprintln!("{}", format_structured_output(global, error));
                            }
                            _ => {
                                eprintln!(
                                    "Rollback failed: {}",
                                    rollback_result
                                        .error
                                        .unwrap_or_else(|| "unknown error".to_string())
                                );
                            }
                        }
                        ExitCode::InternalError
                    }
                }
                Err(e) => {
                    match global.format {
                        OutputFormat::Json | OutputFormat::Toon => {
                            let error = serde_json::json!({
                                "status": "error",
                                "error": format!("{}", e)
                            });
                            eprintln!("{}", format_structured_output(global, error));
                        }
                        _ => {
                            eprintln!("Rollback error: {}", e);
                        }
                    }
                    ExitCode::IoError
                }
            }
        }

        UpdateCommands::PruneBackups { keep } => {
            // Re-create manager with custom retention
            let backup_manager = BackupManager::with_config(
                pt_core::install::default_rollback_dir(),
                "pt-core",
                *keep,
            );

            let _before_count = backup_manager.list_backups().map(|b| b.len()).unwrap_or(0);

            // Prune is handled automatically by retention, but we can force it by listing
            let after_backups = backup_manager.list_backups().unwrap_or_default();

            match global.format {
                OutputFormat::Json | OutputFormat::Toon => {
                    let output = serde_json::json!({
                        "schema_version": SCHEMA_VERSION,
                        "status": "success",
                        "kept": *keep,
                        "remaining": after_backups.len()
                    });
                    println!("{}", format_structured_output(global, output));
                }
                _ => {
                    println!("Pruned backups. Keeping {} most recent.", keep);
                    println!("{} backup(s) remaining.", after_backups.len());
                }
            }
            ExitCode::Clean
        }
    }
}

/// Format bytes as human-readable string
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.1}GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1}MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1}KB", bytes as f64 / KB as f64)
    } else {
        format!("{}B", bytes)
    }
}

/// Parse duration string like "7d", "24h", "30d" into chrono::Duration.
fn parse_duration(s: &str) -> Option<chrono::Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    let (num_str, unit) = if let Some(stripped) = s.strip_suffix('d') {
        (stripped, 'd')
    } else if let Some(stripped) = s.strip_suffix('h') {
        (stripped, 'h')
    } else if let Some(stripped) = s.strip_suffix('m') {
        (stripped, 'm')
    } else {
        return None;
    };

    let num: i64 = num_str.parse().ok()?;
    match unit {
        'd' => Some(chrono::Duration::days(num)),
        'h' => Some(chrono::Duration::hours(num)),
        'm' => Some(chrono::Duration::minutes(num)),
        _ => None,
    }
}
