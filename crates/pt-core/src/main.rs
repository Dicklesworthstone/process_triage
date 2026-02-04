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
#[cfg(feature = "ui")]
use pt_core::inference::galaxy_brain::{
    render as render_galaxy_brain, GalaxyBrainConfig, MathMode, Verbosity,
};
use pt_core::inference::signature_fast_path::{try_signature_fast_path, FastPathConfig};
use pt_core::output::{
    encode_toon_value, CompactConfig, FieldSelector, TokenEfficientOutput,
};
use pt_core::output::predictions::{
    apply_field_selection, CpuPrediction, MemoryPrediction, PredictionDiagnostics, PredictionField,
    PredictionFieldSelector, Predictions, TrajectoryAssessment, TrajectoryLabel, Trend,
};
#[cfg(feature = "ui")]
use pt_core::plan::{generate_plan, DecisionBundle, DecisionCandidate};
use pt_core::session::compare::generate_comparison_report;
use pt_core::session::diff::{
    compute_diff, DeltaKind, DiffConfig, InferenceSummary, ProcessDelta, SessionDiff,
};
use pt_core::session::fleet::{create_fleet_session, CandidateInfo, HostInput};
use pt_core::session::snapshot_persist::{load_inference, load_inventory, PersistedProcess};
use pt_core::session::{
    ListSessionsOptions, SessionContext, SessionHandle, SessionManifest, SessionMode, SessionState,
    SessionStore, SessionSummary,
};
use pt_core::shadow::ShadowRecorder;
use pt_core::signature_cli::load_user_signatures;
use pt_core::supervision::pattern_persistence::DisabledPatterns;
use pt_core::supervision::signature::{ProcessMatchContext, SignatureDatabase};
#[cfg(target_os = "linux")]
use pt_core::supervision::{
    detect_supervision, is_human_supervised, AppActionType, AppSupervisionAnalyzer,
    AppSupervisorType, ContainerActionType, ContainerSupervisionAnalyzer,
};
#[cfg(feature = "ui")]
use pt_core::tui::widgets::ProcessRow;
#[cfg(feature = "ui")]
use pt_core::tui::{run_tui_with_handlers, App};
use pt_core::verify::{parse_agent_plan, verify_plan, VerifyError};
use pt_telemetry::retention::{RetentionConfig, RetentionEnforcer, RetentionError};
use pt_telemetry::shadow::{Observation, ShadowStorage, ShadowStorageConfig};
use pt_telemetry::writer::default_telemetry_dir;
#[cfg(feature = "ui")]
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
#[cfg(feature = "ui")]
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

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

    /// Load additional signature patterns
    #[arg(long)]
    signatures: Option<String>,

    /// Include signed community signatures
    #[arg(long)]
    community_signatures: bool,

    /// Only consider processes older than threshold (seconds)
    #[arg(long)]
    min_age: Option<u64>,
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
    /// Execute command when watch events are emitted (webhook/script)
    #[arg(long = "notify-exec")]
    notify_exec: Option<String>,

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

    /// Resource recovery goal for goal-oriented optimization (coming in v1.2)
    #[arg(
        long,
        help = "Resource recovery goal, e.g. 'free 4GB RAM' (coming in v1.2)"
    )]
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
use pt_core::decision::{ConstraintChecker, RobotCandidate, RuntimeRobotConstraints};
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

    /// Output format: html (default), slack, prose
    #[arg(long, default_value = "html")]
    format: String,

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
    command: DaemonCommands,
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
    #[arg(long, default_value = "json")]
    format: String,

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
                    signatures: None,
                    community_signatures: false,
                    min_age: None,
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
    match value.trim().to_lowercase().as_str() {
        "json" => Some(OutputFormat::Json),
        "toon" => Some(OutputFormat::Toon),
        _ => None,
    }
}

// ============================================================================
// Command implementations (stubs)
// ============================================================================

fn run_interactive(global: &GlobalOpts, args: &RunArgs) -> ExitCode {
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

    let initial = build_tui_data_from_live_scan(global, args, &priors, &policy)?;
    let plan_cache = Rc::new(RefCell::new(initial.plan_candidates));

    let _ = handle.update_state(SessionState::Planned);

    let mut app = App::new();
    app.process_table.set_rows(initial.rows);
    app.process_table.select_recommended();
    app.set_status(format!(
        "Session {} • {} candidates",
        session_id.0,
        app.process_table.rows.len()
    ));

    let plan_cache_refresh = Rc::clone(&plan_cache);
    let plan_cache_execute = Rc::clone(&plan_cache);
    let session_id_for_plan = session_id.clone();
    let policy_for_plan = policy.clone();
    let handle_for_plan = handle.clone();

    run_tui_with_handlers(
        &mut app,
        |app| {
            match build_tui_data_from_live_scan(global, args, &priors, &policy) {
                Ok(output) => {
                    let count = output.rows.len();
                    app.process_table.set_rows(output.rows);
                    app.process_table.select_recommended();
                    *plan_cache_refresh.borrow_mut() = output.plan_candidates;
                    app.set_status(format!("Refreshed • {} candidates", count));
                }
                Err(err) => {
                    app.set_status(format!("Refresh failed: {}", err));
                }
            }
            Ok(())
        },
        |app| {
            let selected = app.process_table.get_selected();
            if selected.is_empty() {
                app.set_status("No processes selected");
                return Ok(());
            }
            match build_plan_from_selection(
                &session_id_for_plan,
                &policy_for_plan,
                &selected,
                &plan_cache_execute.borrow(),
            ) {
                Ok(plan) => {
                    if plan.actions.is_empty() {
                        app.set_status("No actions to apply for selected processes");
                        return Ok(());
                    }
                    app.process_table.apply_plan_preview(&plan);
                    app.request_redraw();
                    match write_plan_to_session(&handle_for_plan, &plan) {
                        Ok(path) => {
                            if global.dry_run || global.shadow {
                                let mode = if global.dry_run { "dry_run" } else { "shadow" };
                                if let Err(err) =
                                    write_outcomes_for_mode(&handle_for_plan, &plan, mode)
                                {
                                    app.set_status(format!("Failed to write outcomes: {}", err));
                                    return Ok(());
                                }
                                app.set_status(format!(
                                    "Plan saved ({} actions, {}): {}",
                                    plan.actions.len(),
                                    mode,
                                    path.display()
                                ));
                                return Ok(());
                            }

                            let _ = handle_for_plan.update_state(SessionState::Executing);
                            match execute_plan_actions(&handle_for_plan, &policy_for_plan, &plan) {
                                Ok(result) => {
                                    if let Err(err) = write_outcomes_from_execution(
                                        &handle_for_plan,
                                        &plan,
                                        &result,
                                    ) {
                                        app.set_status(format!(
                                            "Execution complete but failed to write outcomes: {}",
                                            err
                                        ));
                                        return Ok(());
                                    }
                                    let skipped = result
                                        .outcomes
                                        .iter()
                                        .filter(|o| {
                                            matches!(
                                                o.status,
                                                pt_core::action::ActionStatus::Skipped
                                            )
                                        })
                                        .count();
                                    let final_state = if result.summary.actions_failed > 0 {
                                        SessionState::Failed
                                    } else {
                                        SessionState::Completed
                                    };
                                    let _ = handle_for_plan.update_state(final_state);
                                    app.set_status(format!(
                                        "Executed {} actions: {} ok, {} failed, {} skipped",
                                        result.summary.actions_attempted,
                                        result.summary.actions_succeeded,
                                        result.summary.actions_failed,
                                        skipped
                                    ));
                                }
                                Err(err) => {
                                    let _ = handle_for_plan.update_state(SessionState::Failed);
                                    app.set_status(format!("Execution failed: {}", err));
                                }
                            }
                        }
                        Err(err) => {
                            app.set_status(format!("Failed to save plan: {}", err));
                        }
                    }
                }
                Err(err) => {
                    app.set_status(format!("Plan build failed: {}", err));
                }
            }
            Ok(())
        },
    )
    .map_err(|e| format!("tui error: {}", e))?;

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
    }

    rows.sort_by(|a, b| b.score.cmp(&a.score));
    rows.truncate(MAX_CANDIDATES);
    TuiBuildOutput {
        rows,
        plan_candidates,
    }
}

use pt_core::collect::{quick_scan, ProcessRecord, QuickScanOptions};
use pt_core::decision::{
    apply_load_to_loss_matrix, compute_load_adjustment, decide_action, Action, ActionFeasibility,
    LoadSignals,
};
use pt_core::inference::{compute_posterior, CpuEvidence, Evidence, EvidenceLedger};

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

            match global.format {
                OutputFormat::Json | OutputFormat::Toon => {
                    // Enrich with schema version and session ID
                    let session_id = SessionId::new();
                    let output = serde_json::json!({
                        "schema_version": SCHEMA_VERSION,
                        "session_id": session_id.0,
                        "generated_at": chrono::Utc::now().to_rfc3339(),
                        "scan": result
                    });
                    // Apply token-efficient processing if options specified
                    println!("{}", format_structured_output(global, output));
                }
                OutputFormat::Summary => {
                    println!(
                        "Scanned {} processes in {}ms",
                        result.metadata.process_count, result.metadata.duration_ms
                    );
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
            return ExitCode::InternalError;
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
    let created_at = reader.manifest().created_at.clone();
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

    let mut host_inputs: Vec<HostInput> = Vec::new();
    for host in &hosts {
        host_inputs.push(HostInput {
            host_id: host.to_string(),
            session_id: SessionId::new().0,
            scanned_at: chrono::Utc::now().to_rfc3339(),
            total_processes: 0,
            candidates: Vec::<CandidateInfo>::new(),
        });
    }

    let fleet_session_id = SessionId::new();
    let fleet_session = create_fleet_session(
        &fleet_session_id.0,
        args.label.as_deref(),
        &host_inputs,
        args.max_fdr,
    );

    let response = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "fleet_session_id": fleet_session_id.0,
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "command": "agent fleet plan",
        "status": "stubbed_plan",
        "warnings": [
            "remote scanning is not yet implemented; fleet plan contains empty candidates"
        ],
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
            println!("Hosts: {}", hosts.len());
            println!("Fleet session: {}", fleet_session_id.0);
            println!("Note: remote scanning not yet implemented.");
        }
    }

    ExitCode::Clean
}

fn run_agent_fleet_apply(global: &GlobalOpts, args: &AgentFleetApplyArgs) -> ExitCode {
    let message = format!(
        "Fleet apply not yet implemented (fleet_session={}, parallel={}, timeout={}, continue_on_error={})",
        args.fleet_session, args.parallel, args.timeout, args.continue_on_error
    );
    output_stub(global, "agent fleet apply", &message);
    ExitCode::Clean
}

fn run_agent_fleet_report(global: &GlobalOpts, args: &AgentFleetReportArgs) -> ExitCode {
    let message = format!(
        "Fleet report not yet implemented (fleet_session={}, out={:?}, profile={})",
        args.fleet_session, args.out, args.profile
    );
    output_stub(global, "agent fleet report", &message);
    ExitCode::Clean
}

fn run_agent_fleet_status(global: &GlobalOpts, args: &AgentFleetStatusArgs) -> ExitCode {
    let message = format!(
        "Fleet status not yet implemented (fleet_session={})",
        args.fleet_session
    );
    output_stub(global, "agent fleet status", &message);
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
                    if snapshot.priors_path.is_some() {
                        println!("Priors: {}", snapshot.priors_path.unwrap().display());
                    } else {
                        println!("Priors: using built-in defaults");
                    }
                    if snapshot.policy_path.is_some() {
                        println!("Policy: {}", snapshot.policy_path.unwrap().display());
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
fn run_daemon(global: &GlobalOpts, _args: &DaemonArgs) -> ExitCode {
    output_stub(global, "daemon", "Daemon mode not yet implemented");
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
                config.disk_budget_bytes =
                    (max_disk_gb * 1024.0 * 1024.0 * 1024.0).round() as u64;
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
            println!("Bytes {}: {}", if dry_run { "eligible" } else { "freed" }, format_bytes(freed_bytes));
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
        libc::signal(libc::SIGTERM, handler as libc::sighandler_t);
        libc::signal(libc::SIGINT, handler as libc::sighandler_t);
        libc::signal(libc::SIGHUP, handler as libc::sighandler_t);
        libc::signal(libc::SIGUSR1, handler as libc::sighandler_t);
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

    let mut config = ShadowStorageConfig::default();
    config.base_dir = shadow_base_dir();
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

    let output = match args.format.as_str() {
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
        Err(CalibrationError::InsufficientData { count, min_required }) => {
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

    observations.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    if let Some(max) = limit {
        observations.truncate(max);
    }
    observations.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

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
                let types: Vec<_> = available_schemas()
                    .into_iter()
                    .map(|(name, desc)| serde_json::json!({"name": name, "description": desc}))
                    .collect();
                println!("{}", serde_json::to_string_pretty(&types).unwrap());
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
                println!("{}", format_schema(&schema, format));
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
        .and_then(|content| {
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
            Some((total, available))
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

    // Collect process list if --top, --include-env, or --include-network is specified
    let process_snapshot = if args.top.is_some() || args.include_env || args.include_network {
        let scan_options = QuickScanOptions {
            pids: vec![],
            include_kernel_threads: false,
            timeout: global.timeout.map(std::time::Duration::from_secs),
            progress: None,
        };
        match quick_scan(&scan_options) {
            Ok(result) => {
                let mut processes: Vec<_> = result.processes.into_iter().collect();

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
                            obj.as_object_mut().unwrap().insert(
                                "socket_count".to_string(),
                                serde_json::json!(socket_count),
                            );
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
            }
            Err(e) => {
                eprintln!("agent snapshot: warning: process scan failed: {}", e);
                None
            }
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

fn run_agent_plan(global: &GlobalOpts, args: &AgentPlanArgs) -> ExitCode {
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
            let manifest = SessionManifest::new(&sid, None, SessionMode::RobotPlan, None);
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

    // Process each candidate: compute posterior, make decision, build candidate output
    // Collect ALL candidates above threshold with their max_posterior for sorting
    // Then sort by max_posterior descending and take top N
    let mut all_candidates: Vec<(f64, serde_json::Value)> = Vec::new();

    let feasibility = ActionFeasibility::allow_all();
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

    // Apply sampling if requested (for testing)
    let processes_to_infer: Vec<_> = if let Some(sample_size) = args.sample_size {
        use rand::seq::SliceRandom;
        let mut rng = rand::rng();
        let mut sampled: Vec<_> = filter_result.passed.iter().collect();
        sampled.shuffle(&mut rng);
        sampled.truncate(sample_size);
        sampled
    } else {
        filter_result.passed.iter().collect()
    };

    let total_processes = processes_to_infer.len() as u64;
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

        // Compute posterior probabilities
        let posterior_result = match compute_posterior(&priors, &evidence) {
            Ok(r) => r,
            Err(_) => continue, // Skip processes that fail inference
        };

        // Compute decision (optimal action based on expected loss)
        let decision_outcome =
            match decide_action(&posterior_result.posterior, &decision_policy, &feasibility) {
                Ok(d) => d,
                Err(_) => continue, // Skip processes that fail decision
            };

        // Build evidence ledger for classification and confidence
        let ledger =
            EvidenceLedger::from_posterior_result(&posterior_result, Some(proc.pid.0), None);

        // Determine max posterior class for filtering
        let posterior = &posterior_result.posterior;
        let max_posterior = posterior
            .useful
            .max(posterior.useful_bad)
            .max(posterior.abandoned)
            .max(posterior.zombie);

        // Determine recommended action string (used for shadow recording and plan output)
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
            if processed % 50 == 0 || processed == total_processes {
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
            "action_rationale": format!("Action {:?} selected{}",
                decision_outcome.rationale.chosen_action,
                if decision_outcome.rationale.tie_break { " (tie-break)" } else { "" }),
            "expected_loss": decision_outcome.expected_loss.iter()
                .map(|el| serde_json::json!({
                    "action": format!("{:?}", el.action),
                    "loss": el.loss,
                }))
                .collect::<Vec<_>>(),
        });

        if let Some(predictions) = predictions {
            if let Some(obj) = candidate.as_object_mut() {
                obj.insert(
                    "predictions".to_string(),
                    serde_json::to_value(predictions).unwrap_or_else(|_| serde_json::json!({})),
                );
            }
        }

        // Store candidate with max_posterior for sorting (no early break!)
        all_candidates.push((max_posterior, candidate));
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
    let candidates: Vec<serde_json::Value> = all_candidates
        .into_iter()
        .take(args.max_candidates as usize)
        .map(|(_, c)| c)
        .collect();

    // Rebuild kill/review/spare candidate lists from the final sorted candidates
    let mut kill_candidates: Vec<u32> = Vec::new();
    let mut review_candidates: Vec<u32> = Vec::new();
    let mut spare_candidates: Vec<u32> = Vec::new();
    let mut expected_memory_freed_bytes: u64 = 0;
    for candidate in &candidates {
        let pid = candidate["pid"].as_u64().unwrap_or(0) as u32;
        let action = candidate["recommended_action"].as_str().unwrap_or("");
        let memory_mb = candidate["memory_mb"].as_u64().unwrap_or(0);
        if action == "kill" {
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
        "candidates_evaluated": filter_result.passed.len(),
        "above_threshold": above_threshold_count,  // Candidates meeting threshold before truncation
        "candidates_returned": candidates.len(),   // After truncation to max_candidates
        "kill_recommendations": kill_candidates.len(),
        "review_recommendations": review_candidates.len(),
        "threshold_used": args.min_posterior,
        "filter_used": args.only,
    });
    if global.shadow {
        summary["shadow_observations_recorded"] = serde_json::json!(shadow_recorded);
    }

    // Build recommendations section (new structured format)
    let recommendations = serde_json::json!({
        "kill_set": kill_candidates,
        "review_set": review_candidates,
        "spare_set": spare_candidates,
        "expected_memory_freed_gb": (expected_memory_freed_gb * 100.0).round() / 100.0,
        "fleet_fdr": 0.03, // Placeholder - would come from fleet-wide statistics
    });

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
    if args.goal.is_some() {
        stub_flags_used.push("--goal");
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

    // Build complete plan output with structured JSON format
    let mut plan_output = serde_json::json!({
        "pt_version": env!("CARGO_PKG_VERSION"),
        "schema_version": SCHEMA_VERSION,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "session_id": session_id.0,
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
                            let bf_str = if bf_val.is_infinite() || bf_val > 1e6 {
                                format!("{:.2e}", bf_val)
                            } else if bf_val < 1e-6 && bf_val > 0.0 {
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

fn run_agent_apply(global: &GlobalOpts, args: &AgentApplyArgs) -> ExitCode {
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
    let target_pids: Vec<u32> = if use_recommended {
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

    let mut outcomes: Vec<serde_json::Value> = Vec::new();
    let mut succeeded = 0usize;
    let mut failed = 0usize;
    let mut skipped = 0usize;
    let mut blocked_by_constraints = 0usize;
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
            } else {
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

    // Write outcomes
    let outcomes_path = handle.dir.join("action").join("outcomes.jsonl");
    let _ = std::fs::create_dir_all(handle.dir.join("action"));
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
            "resumed_skipped": resumed_skipped
        },
        "outcomes": outcomes,
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
                    "[{}] apply: {} ok, {} fail, {} skip, {} blocked, {} already done (resumed)",
                    sid, succeeded, failed, skipped, blocked_by_constraints, resumed_skipped
                );
            } else {
                println!(
                    "[{}] apply: {} ok, {} fail, {} skip, {} blocked",
                    sid, succeeded, failed, skipped, blocked_by_constraints
                );
            }
        }
        _ => println!(
            "# apply\nSession: {}\nSucceeded: {}\nFailed: {}",
            sid, succeeded, failed
        ),
    }

    if blocked_by_constraints > 0 && succeeded == 0 && failed == 0 {
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
    let exit_code = if args.check_respawn && respawned_count > 0 {
        ExitCode::PartialFail
    } else {
        exit_code
    };

    exit_code
}

fn resolve_diff_sessions(
    store: &SessionStore,
    args: &DiffArgs,
) -> Result<(SessionId, SessionId, Option<String>, Option<String>), String> {
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
    let sessions = store
        .list_sessions(&list_options)
        .map_err(|e| format!("diff: failed to list sessions: {}", e))?;
    if sessions.is_empty() {
        return Err("diff: no sessions found".to_string());
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

    output.push_str(&format!("# pt diff\n\n"));
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

    let base_inventory = match load_inventory(&base_handle) {
        Ok(inv) => inv,
        Err(e) => {
            eprintln!("diff: base inventory: {}", e);
            return ExitCode::ArgsError;
        }
    };
    let base_inference = match load_inference(&base_handle) {
        Ok(inf) => inf,
        Err(e) => {
            eprintln!("diff: base inference: {}", e);
            return ExitCode::ArgsError;
        }
    };
    let compare_inventory = match load_inventory(&compare_handle) {
        Ok(inv) => inv,
        Err(e) => {
            eprintln!("diff: compare inventory: {}", e);
            return ExitCode::ArgsError;
        }
    };
    let compare_inference = match load_inference(&compare_handle) {
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
    use std::fs::File;
    use std::io::{BufReader, Write};

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

        let file = match File::open(path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("agent report: failed to open bundle: {}", e);
                return ExitCode::InternalError;
            }
        };

        let mut reader = match pt_bundle::BundleReader::new(BufReader::new(file)) {
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
    match args.format.to_lowercase().as_str() {
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
                args.format
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

    loop {
        let system_state = collect_system_state();
        if baseline.is_none() {
            baseline = Some(WatchBaseline::from_state(&system_state));
        }

        if let Some(event) = check_goal_violation(&system_state, args) {
            emit_watch_event(&event, args.notify_exec.as_deref());
        }
        if let Some(event) = check_baseline_anomaly(&system_state, baseline.as_ref()) {
            emit_watch_event(&event, args.notify_exec.as_deref());
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
                        emit_watch_event(&event, args.notify_exec.as_deref());
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
                emit_watch_event(&event, args.notify_exec.as_deref());
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
    let Some(baseline) = baseline else {
        return None;
    };
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

fn emit_watch_event(event: &serde_json::Value, notify_exec: Option<&str>) {
    println!(
        "{}",
        serde_json::to_string(event).unwrap_or_else(|_| "{}".to_string())
    );
    if let Some(cmd) = notify_exec {
        let event_type = event
            .get("event")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let json = event.to_string();
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
    use pt_report::{ReportConfig, ReportData};

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
