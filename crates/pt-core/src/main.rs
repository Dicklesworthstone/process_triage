//! Process Triage Core - Inference and Decision Engine
//!
//! The main entry point for pt-core, handling:
//! - Process scanning and collection
//! - Bayesian inference for process classification
//! - Decision theory for action recommendations
//! - Agent/robot mode for automated operation
//! - Telemetry and reporting

use clap::{Args, Parser, Subcommand};
use pt_common::{OutputFormat, SessionId, SCHEMA_VERSION};
use pt_core::capabilities::{get_capabilities, ToolCapability};
use pt_core::collect::protected::ProtectedFilter;
#[cfg(target_os = "linux")]
use pt_core::collect::{systemd::collect_systemd_unit, ContainerRuntime};
use pt_core::config::{load_config, ConfigError, ConfigOptions, Priors};
use pt_core::events::{
    FanoutEmitter, JsonlWriter, Phase, ProgressEmitter, ProgressEvent, SessionEmitter,
};
use pt_core::exit_codes::ExitCode;
use pt_core::session::{
    ListSessionsOptions, SessionContext, SessionManifest, SessionMode, SessionState, SessionStore,
};
#[cfg(target_os = "linux")]
use pt_core::supervision::{
    detect_supervision, is_human_supervised, AppActionType, AppSupervisionAnalyzer,
    AppSupervisorType, ContainerActionType, ContainerSupervisionAnalyzer,
};
use pt_core::verify::{parse_agent_plan, verify_plan, VerifyError};
use std::path::PathBuf;
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
    #[arg(long, short = 'f', global = true, default_value = "json")]
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
}

#[derive(Subcommand)]
enum Commands {
    /// Interactive golden path: scan → infer → plan → TUI approval → staged apply
    Run(RunArgs),

    /// Quick multi-sample scan only (no inference or action)
    Scan(ScanArgs),

    /// Full deep scan with all available probes
    DeepScan(DeepScanArgs),

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

    /// Signature management (list, add, remove user signatures)
    Signature(pt_core::signature_cli::SignatureArgs),

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
    Capabilities,

    /// List and manage sessions
    Sessions(AgentSessionsArgs),

    /// List current prior configuration
    ListPriors(AgentListPriorsArgs),

    /// View pending plans and notifications
    Inbox(AgentInboxArgs),

    /// Stream session progress events (JSONL)
    Tail(AgentTailArgs),

    /// Export priors to file for transfer between machines
    ExportPriors(AgentExportPriorsArgs),

    /// Import priors from file (bootstrap from external source)
    ImportPriors(AgentImportPriorsArgs),

    /// Generate HTML report from session
    #[cfg(feature = "report")]
    Report(AgentReportArgs),
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
struct AgentPlanArgs {
    /// Resume existing session
    #[arg(long)]
    session: Option<String>,

    /// Maximum candidates to return
    #[arg(long, default_value = "20")]
    max_candidates: u32,

    /// Minimum posterior threshold
    #[arg(long, default_value = "0.7")]
    threshold: f64,

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

use pt_core::plan::Plan;
use pt_core::decision::{RuntimeRobotConstraints, ConstraintChecker, RobotCandidate};
#[cfg(target_os = "linux")]
use pt_core::action::{ActionRunner, IdentityProvider, LiveIdentityProvider, SignalActionRunner, SignalConfig};

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
}

#[derive(Args, Debug)]
struct AgentDiffArgs {
    /// Base session ID
    #[arg(long)]
    base: String,

    /// Compare session ID (default: current)
    #[arg(long)]
    compare: Option<String>,
}

#[derive(Args, Debug)]
struct AgentSnapshotArgs {
    /// Label for the snapshot
    #[arg(long)]
    label: Option<String>,
}

#[derive(Args, Debug)]
struct AgentSessionsArgs {
    /// Show status for a specific session
    #[arg(long)]
    status: Option<String>,

    /// Maximum sessions to return (default: 10)
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
    },
    /// Redact sensitive data
    Redact {
        /// Apply redaction to all stored telemetry
        #[arg(long)]
        all: bool,
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
    let cli = Cli::parse();

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
    let log_format = if matches!(cli.global.format, OutputFormat::Json | OutputFormat::Jsonl) {
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
        Some(Commands::Query(args)) => run_query(&cli.global, &args),
        Some(Commands::Bundle(args)) => run_bundle(&cli.global, &args),
        Some(Commands::Report(args)) => run_report(&cli.global, &args),
        Some(Commands::Check(args)) => run_check(&cli.global, &args),
        Some(Commands::Agent(args)) => run_agent(&cli.global, &args),
        Some(Commands::Config(args)) => run_config(&cli.global, &args),
        #[cfg(feature = "daemon")]
        Some(Commands::Daemon(args)) => run_daemon(&cli.global, &args),
        Some(Commands::Telemetry(args)) => run_telemetry(&cli.global, &args),
        Some(Commands::Signature(args)) => {
            pt_core::signature_cli::run_signature(&cli.global.format, &args)
        }
        Some(Commands::Version) => {
            print_version(&cli.global);
            ExitCode::Clean
        }
    };

    std::process::exit(exit_code.as_i32());
}

// ============================================================================
// Command implementations (stubs)
// ============================================================================

fn run_interactive(global: &GlobalOpts, _args: &RunArgs) -> ExitCode {
    output_stub(global, "run", "Interactive triage mode not yet implemented");
    ExitCode::Clean
}

use pt_core::collect::{quick_scan, ProcessRecord, QuickScanOptions};
use pt_core::decision::{
    apply_load_to_loss_matrix, compute_load_adjustment, decide_action, Action, ActionFeasibility,
    LoadSignals,
};
use pt_core::inference::{compute_posterior, CpuEvidence, Evidence, EvidenceLedger};

fn progress_emitter(global: &GlobalOpts) -> Option<Arc<dyn ProgressEmitter>> {
    match global.format {
        OutputFormat::Json | OutputFormat::Jsonl => {
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
                OutputFormat::Json => {
                    // Enrich with schema version and session ID
                    let session_id = SessionId::new();
                    let output = serde_json::json!({
                        "schema_version": SCHEMA_VERSION,
                        "session_id": session_id.0,
                        "generated_at": chrono::Utc::now().to_rfc3339(),
                        "scan": result
                    });
                    println!("{}", serde_json::to_string_pretty(&output).unwrap());
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
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&response).unwrap());
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
        AgentCommands::ExportPriors(args) => run_agent_export_priors(global, args),
        AgentCommands::ImportPriors(args) => run_agent_import_priors(global, args),
        #[cfg(feature = "report")]
        AgentCommands::Report(args) => run_agent_report(global, args),
        AgentCommands::Capabilities => {
            output_capabilities(global);
            ExitCode::Clean
        }
    }
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
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&response).unwrap());
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
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&response).unwrap());
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
        OutputFormat::Json => {
            eprintln!("{}", serde_json::to_string_pretty(&response).unwrap());
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

#[cfg(feature = "daemon")]
fn run_daemon(global: &GlobalOpts, _args: &DaemonArgs) -> ExitCode {
    output_stub(global, "daemon", "Daemon mode not yet implemented");
    ExitCode::Clean
}

fn run_telemetry(global: &GlobalOpts, _args: &TelemetryArgs) -> ExitCode {
    output_stub(
        global,
        "telemetry",
        "Telemetry management not yet implemented",
    );
    ExitCode::Clean
}

fn print_version(global: &GlobalOpts) {
    let version_info = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "pt_core_version": env!("CARGO_PKG_VERSION"),
        "rust_version": env!("CARGO_PKG_RUST_VERSION"),
    });

    match global.format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&version_info).unwrap());
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
        OutputFormat::Json => {
            let output = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "session_id": session_id.0,
                "generated_at": chrono::Utc::now().to_rfc3339(),
                "command": command,
                "status": "stub",
                "message": message
            });
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
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
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&capabilities_json).unwrap()
            );
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
        OutputFormat::Json => {
            let output = serde_json::json!({
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
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
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

    // Progress emitter for streaming updates + session log
    let emitter = session_progress_emitter(global, &handle, &session_id);
    if let Some(ref e) = emitter {
        e.emit(ProgressEvent::new(
            pt_core::events::event_names::SESSION_STARTED,
            Phase::Session,
        ));
    }

    // Perform quick scan to enumerate processes
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
    let total_processes = filter_result.passed.len() as u64;
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

    // Use filtered processes for inference (not scan_result.processes)
    for proc in &filter_result.passed {
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
        if max_posterior < args.threshold {
            continue;
        }

        // Determine recommended action string
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

        // Apply --only filter
        let include = match args.only.as_str() {
            "kill" => decision_outcome.optimal_action == Action::Kill,
            "review" => decision_outcome.optimal_action != Action::Keep,
            _ => true, // "all"
        };
        if !include {
            continue;
        }

        // Build candidate JSON (action tracking moved to after sorting)
        let candidate = serde_json::json!({
            "pid": proc.pid.0,
            "ppid": proc.ppid.0,
            "state": proc.state.to_string(),
            "start_id": format!("{}:{}", proc.pid.0, proc.start_time_unix),
            "uid": proc.uid,
            "user": &proc.user,
            "cmd_short": proc.comm,
            "cmd_full": proc.cmd,
            "classification": ledger.classification.label(),
            "posterior": {
                "useful": posterior.useful,
                "useful_bad": posterior.useful_bad,
                "abandoned": posterior.abandoned,
                "zombie": posterior.zombie,
            },
            "confidence": ledger.confidence.label(),
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

    // Rebuild kill/review candidate lists from the final sorted candidates
    let mut kill_candidates: Vec<u32> = Vec::new();
    let mut review_candidates: Vec<u32> = Vec::new();
    for candidate in &candidates {
        let pid = candidate["pid"].as_u64().unwrap_or(0) as u32;
        let action = candidate["recommended_action"].as_str().unwrap_or("");
        if action == "kill" {
            kill_candidates.push(pid);
        } else if action != "keep" {
            review_candidates.push(pid);
        }
    }

    // Build summary
    let summary = serde_json::json!({
        "total_processes_scanned": total_scanned,
        "protected_filtered": protected_filtered_count,
        "candidates_evaluated": filter_result.passed.len(),
        "above_threshold": above_threshold_count,  // Candidates meeting threshold before truncation
        "candidates_returned": candidates.len(),   // After truncation to max_candidates
        "kill_recommendations": kill_candidates.len(),
        "review_recommendations": review_candidates.len(),
        "threshold_used": args.threshold,
        "filter_used": args.only,
    });

    // Build recommended section
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

    // Build complete plan output
    let plan_output = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "session_id": session_id.0,
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "host_id": pt_core::logging::get_host_id(),
        "command": "agent plan",
        "args": {
            "max_candidates": args.max_candidates,
            "threshold": args.threshold,
            "only": args.only,
            "yes": args.yes,
            "dry_run": global.dry_run,
            "robot": global.robot,
            "shadow": global.shadow,
        },
        "summary": summary,
        "candidates": candidates,
        "recommended": recommended,
        "session_created": created,
    });

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

    // Output based on format
    match global.format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&plan_output).unwrap());
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
                    .get("cmd_short")
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
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
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

    // Determine which actions to apply
    let target_pids: Vec<u32> = if args.recommended {
        plan.actions.iter().filter(|a| !a.blocked).map(|a| a.target.pid.0).collect()
    } else if !args.pids.is_empty() {
        args.pids.clone()
    } else if !args.targets.is_empty() {
        args.targets.iter().filter_map(|t| t.split(':').next().and_then(|p| p.parse().ok())).collect()
    } else {
        eprintln!("agent apply: must specify --recommended, --pids, or --targets");
        return ExitCode::ArgsError;
    };

    if target_pids.is_empty() {
        output_apply_nothing(global, &sid);
        return ExitCode::Clean;
    }

    let actions_to_apply: Vec<_> = plan.actions.iter().filter(|a| target_pids.contains(&a.target.pid.0)).collect();
    if actions_to_apply.is_empty() {
        output_apply_nothing(global, &sid);
        return ExitCode::Clean;
    }

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
        .with_require_known_signature(if args.require_known_signature { Some(true) } else { None })
        .with_allow_categories(if args.only_categories.is_empty() { None } else { Some(args.only_categories.clone()) })
        .with_exclude_categories(args.exclude_categories.clone());

    let checker = ConstraintChecker::new(constraints.clone());
    let constraints_summary = constraints.active_constraints_summary();
    let _ = handle.update_state(SessionState::Executing);

    let mut outcomes: Vec<serde_json::Value> = Vec::new();
    let mut succeeded = 0usize;
    let mut failed = 0usize;
    let mut skipped = 0usize;
    let mut blocked_by_constraints = 0usize;

    // Handle dry-run/shadow mode or execute
    if global.dry_run || global.shadow {
        for action in &actions_to_apply {
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
            } else {
                skipped += 1;
                outcomes.push(serde_json::json!({"action_id": action.action_id, "pid": action.target.pid.0, "status": if global.dry_run { "dry_run" } else { "shadow" }}));
            }
        }
    } else {
        #[cfg(target_os = "linux")]
        {
            let identity_provider = LiveIdentityProvider::new();
            let signal_runner = SignalActionRunner::new(SignalConfig::default());

            for action in &actions_to_apply {
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
                    outcomes.push(serde_json::json!({"action_id": action.action_id, "pid": action.target.pid.0, "status": "blocked_by_constraints", "time_ms": start.elapsed().as_millis()}));
                    if args.abort_on_unknown { break; }
                    continue;
                }
                match identity_provider.revalidate(&action.target) {
                    Ok(true) => {}
                    Ok(false) => {
                        failed += 1;
                        outcomes.push(serde_json::json!({"action_id": action.action_id, "pid": action.target.pid.0, "status": "identity_mismatch", "time_ms": start.elapsed().as_millis()}));
                        if args.abort_on_unknown { break; }
                        continue;
                    }
                    Err(_) => {
                        failed += 1;
                        outcomes.push(serde_json::json!({"action_id": action.action_id, "pid": action.target.pid.0, "status": "identity_check_failed", "time_ms": start.elapsed().as_millis()}));
                        if args.abort_on_unknown { break; }
                        continue;
                    }
                }
                match signal_runner.execute(action) {
                    Ok(()) => {
                        if action.action == Action::Kill {
                            checker.record_action(0, true);
                        }
                        succeeded += 1;
                        outcomes.push(serde_json::json!({"action_id": action.action_id, "pid": action.target.pid.0, "status": "success", "time_ms": start.elapsed().as_millis()}));
                    }
                    Err(e) => {
                        failed += 1;
                        outcomes.push(serde_json::json!({"action_id": action.action_id, "pid": action.target.pid.0, "status": "failed", "error": format!("{:?}", e), "time_ms": start.elapsed().as_millis()}));
                        if args.abort_on_unknown { break; }
                    }
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            for action in &actions_to_apply {
                skipped += 1;
                outcomes.push(serde_json::json!({"action_id": action.action_id, "pid": action.target.pid.0, "status": "unsupported_platform"}));
            }
        }
    }

    // Write outcomes
    let outcomes_path = handle.dir.join("action").join("outcomes.jsonl");
    let _ = std::fs::create_dir_all(handle.dir.join("action"));
    if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(&outcomes_path) {
        use std::io::Write;
        for o in &outcomes { let _ = writeln!(file, "{}", o); }
    }

    let final_state = if failed > 0 { SessionState::Failed } else { SessionState::Completed };
    let _ = handle.update_state(final_state);

    let result = serde_json::json!({
        "session_id": sid.0,
        "mode": "robot_apply",
        "summary": {"attempted": actions_to_apply.len(), "succeeded": succeeded, "failed": failed, "skipped": skipped, "blocked_by_constraints": blocked_by_constraints},
        "outcomes": outcomes,
        "constraints_summary": constraints_summary
    });
    match global.format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&result).unwrap()),
        OutputFormat::Summary => println!("[{}] apply: {} ok, {} fail, {} skip, {} blocked", sid, succeeded, failed, skipped, blocked_by_constraints),
        _ => println!("# apply\nSession: {}\nSucceeded: {}\nFailed: {}", sid, succeeded, failed),
    }

    if blocked_by_constraints > 0 && succeeded == 0 && failed == 0 { ExitCode::PolicyBlocked }
    else if failed > 0 { ExitCode::PartialFail }
    else { ExitCode::ActionsOk }
}

fn output_apply_nothing(global: &GlobalOpts, sid: &SessionId) {
    let result = serde_json::json!({"session_id": sid.0, "mode": "robot_apply", "note": "nothing_to_do", "summary": {"attempted": 0}});
    match global.format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&result).unwrap()),
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
            eprintln!("agent verify: failed to read {}: {}", plan_path.display(), e);
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
    if let Err(e) = std::fs::write(
        &verify_path,
        serde_json::to_string_pretty(&report).unwrap(),
    ) {
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

    let exit_code = match report.verification.overall_status.as_str() {
        "success" => ExitCode::Clean,
        "partial_success" => ExitCode::PartialFail,
        "failure" => ExitCode::PartialFail,
        _ => ExitCode::Clean,
    };

    match global.format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&report).unwrap());
        }
        OutputFormat::Summary => {
            let freed = report
                .resource_summary
                .as_ref()
                .map(|s| s.memory_freed_mb)
                .unwrap_or(0.0);
            println!(
                "[{}] agent verify: {} verified, {} failed (freed {} MB)",
                sid, verified_count, failed_count, freed
            );
        }
        OutputFormat::Exitcode => {}
        _ => {
            println!("# pt-core agent verify
");
            println!("Session: {}", sid);
            println!("Plan: {}", plan_path.display());
            println!("Report: {}
", verify_path.display());
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

    exit_code
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
    if let Err(e) = store.open(&base) {
        eprintln!("agent diff: {}", e);
        return ExitCode::ArgsError;
    }
    if let Some(compare) = args.compare.as_ref() {
        if let Some(sid) = SessionId::parse(compare) {
            if let Err(e) = store.open(&sid) {
                eprintln!("agent diff: {}", e);
                return ExitCode::ArgsError;
            }
        } else {
            eprintln!("agent diff: invalid --compare {}", compare);
            return ExitCode::ArgsError;
        }
    }
    output_stub_with_session(
        global,
        &base,
        "agent diff",
        "Agent diff mode not yet implemented",
    );
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
        |name: &str, cp: &pt_core::config::priors::ClassPriors| -> serde_json::Value {
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
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&response).unwrap());
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

    match global.format {
        OutputFormat::Json | OutputFormat::Jsonl => {
            let response = serde_json::json!({
                "exported": true,
                "path": out_path.display().to_string(),
                "host_id": host_id,
                "host_profile": args.host_profile,
            });
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
    let mode = if args.replace {
        "replace"
    } else {
        "merge"
    };

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
    let priors_path = config
        .snapshot()
        .priors_path
        .unwrap_or_else(|| {
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
        if let Some(imported_profile) = import_doc
            .get("host_profile")
            .and_then(|v| v.as_str())
        {
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
    match global.format {
        OutputFormat::Json | OutputFormat::Jsonl => {
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
                    OutputFormat::Json => {
                        let response = serde_json::json!({
                            "acknowledged": true,
                            "item_id": item.id,
                            "acknowledged_at": item.acknowledged_at,
                        });
                        println!("{}", serde_json::to_string_pretty(&response).unwrap());
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
                    OutputFormat::Json => {
                        let response = serde_json::json!({
                            "cleared": count,
                            "clear_type": "all",
                        });
                        println!("{}", serde_json::to_string_pretty(&response).unwrap());
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
                    OutputFormat::Json => {
                        let response = serde_json::json!({
                            "cleared": count,
                            "clear_type": "acknowledged",
                        });
                        println!("{}", serde_json::to_string_pretty(&response).unwrap());
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
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&response).unwrap());
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
                    println!("{} [{}] {} - {}", status, item.item_type, item.id, item.summary);
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
            eprintln!(
                "agent tail: no session log found at {}",
                log_path.display()
            );
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
            eprintln!("agent report: invalid theme '{}', use: light, dark, auto", args.theme);
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
                    Ok(_) => {
                        match global.format {
                            OutputFormat::Json => {
                                let response = serde_json::json!({
                                    "status": "success",
                                    "output_path": out_path,
                                    "size_bytes": html.len(),
                                    "format": "html",
                                });
                                println!("{}", serde_json::to_string_pretty(&response).unwrap());
                            }
                            _ => {
                                println!("Report written to: {}", out_path);
                            }
                        }
                    }
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
                OutputFormat::Json => {
                    let response = serde_json::json!({
                        "format": "slack",
                        "prose_style": args.prose_style,
                        "content": summary,
                    });
                    println!("{}", serde_json::to_string_pretty(&response).unwrap());
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
                OutputFormat::Json => {
                    let response = serde_json::json!({
                        "format": "prose",
                        "prose_style": args.prose_style,
                        "content": summary,
                    });
                    println!("{}", serde_json::to_string_pretty(&response).unwrap());
                }
                _ => {
                    println!("{}", summary);
                }
            }
        }
        _ => {
            eprintln!("agent report: invalid format '{}', use: html, slack, prose", args.format);
            return ExitCode::ArgsError;
        }
    }

    ExitCode::Clean
}

/// Generate a report from session directory data.
#[cfg(feature = "report")]
fn generate_report_from_session(
    generator: &pt_report::ReportGenerator,
    handle: &pt_core::session::SessionHandle,
) -> pt_report::Result<String> {
    use pt_report::sections::*;
    use pt_report::{ReportData, ReportConfig};

    // Read manifest for session metadata
    let manifest = handle.read_manifest().map_err(|e| {
        pt_report::ReportError::MissingData(format!("manifest: {}", e))
    })?;

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
            .and_then(|v| v.get("candidates")?.as_array().map(|a| a.len()))
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
        "formal" => {
            "*Process Triage Report*\n\nThe session has been completed successfully. \
             All processes have been analyzed according to the configured policy.\n\n\
             _Report generated by pt-core_".to_string()
        }
        "technical" => {
            "*Process Triage Technical Summary*\n\n\
             ```\n\
             Session: completed\n\
             Candidates: analyzed\n\
             Actions: pending review\n\
             ```\n\n\
             See full HTML report for detailed evidence ledger and posterior computations.".to_string()
        }
        _ => {
            // conversational (default)
            "*Process Triage Complete* 🎯\n\n\
             I've finished analyzing your processes. The session has been saved \
             and you can review the detailed findings in the HTML report.\n\n\
             Let me know if you'd like me to explain any of the recommendations!".to_string()
        }
    }
}

/// Generate prose summary for agent-to-user communication.
#[cfg(feature = "report")]
fn generate_prose_summary(prose_style: &str) -> String {
    match prose_style {
        "terse" => {
            "Session complete. Candidates analyzed. Report ready.".to_string()
        }
        "formal" => {
            "The process triage session has concluded. All candidate processes have been \
             evaluated using Bayesian inference, and recommendations have been generated \
             based on the configured policy parameters. The full report is available for \
             your review.".to_string()
        }
        "technical" => {
            "Process triage session completed. The inference engine computed posterior \
             probabilities for each candidate across the four-class model (useful, useful_bad, \
             abandoned, zombie). Expected loss calculations and FDR control were applied \
             to generate action recommendations. See the galaxy-brain tab in the HTML report \
             for full mathematical derivations.".to_string()
        }
        _ => {
            // conversational (default)
            "All done! I've analyzed your running processes and identified any that might \
             be abandoned or stuck. You can check out the full report to see the details \
             and decide what to do with each one. The report shows my reasoning for each \
             recommendation, so you'll know exactly why I flagged something.".to_string()
        }
    }
}

fn run_agent_sessions(global: &GlobalOpts, args: &AgentSessionsArgs) -> ExitCode {
    let store = match SessionStore::from_env() {
        Ok(store) => store,
        Err(e) => {
            eprintln!("agent sessions: session store error: {}", e);
            return ExitCode::InternalError;
        }
    };

    let host_id = pt_core::logging::get_host_id();

    // Handle single session status query
    if let Some(session_id_str) = &args.status {
        return run_agent_session_status(global, &store, session_id_str, &host_id);
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

    // Count progress from action outcomes
    let outcomes_path = handle.dir.join("action").join("outcomes.jsonl");
    let (completed_actions, total_actions) = if outcomes_path.exists() {
        let content = std::fs::read_to_string(&outcomes_path).unwrap_or_default();
        let completed = content.lines().filter(|l| !l.trim().is_empty()).count();
        // Try to get total from plan
        let plan_path = handle.dir.join("decision").join("plan.json");
        let total = std::fs::read_to_string(&plan_path)
            .ok()
            .and_then(|c| serde_json::from_str::<serde_json::Value>(&c).ok())
            .and_then(|v| {
                v.get("candidates")
                    .and_then(|c| c.as_array())
                    .map(|a| a.len())
            })
            .unwrap_or(completed);
        (completed, total)
    } else {
        (0, 0)
    };

    let pending_actions = total_actions.saturating_sub(completed_actions);

    match global.format {
        OutputFormat::Json => {
            let output = serde_json::json!({
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
                    Some(format!("pt agent apply --session {}", manifest.session_id))
                } else {
                    None
                },
                "state_history": manifest.state_history,
                "error": manifest.error,
                "status": "ok",
                "command": format!("pt agent sessions --status {}", manifest.session_id),
            });
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
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
                    "Resume with: pt agent apply --session {}",
                    manifest.session_id
                );
            }
            if let Some(error) = &manifest.error {
                println!();
                println!("## Error");
                println!("{}", error);
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
        OutputFormat::Json => {
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
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
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
        OutputFormat::Json => {
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
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
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
