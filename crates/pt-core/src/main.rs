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
use pt_core::config::{load_config, ConfigError, ConfigOptions, Priors};
use pt_core::capabilities::{get_capabilities, ToolCapability};
use pt_core::events::{JsonlWriter, Phase, ProgressEmitter, ProgressEvent};
use pt_core::exit_codes::ExitCode;
use pt_core::session::{
    ListSessionsOptions, SessionContext, SessionManifest, SessionMode, SessionState, SessionStore,
};
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
    Agent(AgentArgs),

    /// Configuration management
    Config(ConfigArgs),

    /// Background monitoring daemon
    #[cfg(feature = "daemon")]
    Daemon(DaemonArgs),

    /// Telemetry management
    Telemetry(TelemetryArgs),

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
    },
    /// Inspect an existing bundle
    Inspect {
        /// Path to the bundle file
        path: String,

        /// Verify file checksums
        #[arg(long)]
        verify: bool,
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

#[derive(Args, Debug)]
struct AgentApplyArgs {
    /// Session ID (required)
    #[arg(long)]
    session: String,

    /// PIDs to act on (default: all recommended)
    #[arg(long, value_delimiter = ',')]
    pids: Vec<u32>,

    /// Skip safety gate confirmations
    #[arg(long)]
    yes: bool,
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

use pt_core::collect::{quick_scan, QuickScanOptions, ProcessRecord};
use pt_core::inference::{
    compute_posterior, CpuEvidence, Evidence, EvidenceLedger,
};

fn progress_emitter(global: &GlobalOpts) -> Option<Arc<dyn ProgressEmitter>> {
    match global.format {
        OutputFormat::Json | OutputFormat::Jsonl => {
            Some(Arc::new(JsonlWriter::new(std::io::stderr())))
        }
        _ => None,
    }
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
        pids: vec![],                  // Empty = all processes
        include_kernel_threads: false, // Default to false for quick scan
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
        } => run_bundle_create(global, session, output, profile, *include_telemetry, *include_dumps),
        BundleCommands::Inspect { path, verify } => run_bundle_inspect(global, path, *verify),
        BundleCommands::Extract { path, output, verify } => run_bundle_extract(global, path, output, *verify),
    }
}

fn run_bundle_create(
    global: &GlobalOpts,
    session_arg: &Option<String>,
    output_arg: &Option<String>,
    profile_str: &str,
    include_telemetry: bool,
    _include_dumps: bool,
) -> ExitCode {
    use pt_bundle::{BundleWriter, FileType};
    use pt_redact::ExportProfile;

    let session_id = SessionId::new();
    let host_id = pt_core::logging::get_host_id();

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
                OutputFormat::Md => eprintln!("Error: Invalid profile '{}'. Valid options: minimal, safe, forensic", profile_str),
                OutputFormat::Jsonl => println!("{}", serde_json::to_string(&error_output).unwrap()),
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
        let options = ListSessionsOptions { limit: Some(1), ..Default::default() };
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
                                writer.add_file(format!("telemetry/{}", name), content, Some(file_type));
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

    // Write the bundle
    match writer.write(&output_path) {
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
                },
            });
            match global.format {
                OutputFormat::Md => println!("Bundle created: {} ({} files, {} bytes)",
                    output_path.display(), manifest.file_count(), manifest.total_bytes()),
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
                OutputFormat::Jsonl => println!("{}", serde_json::to_string(&error_output).unwrap()),
                _ => println!("{}", serde_json::to_string_pretty(&error_output).unwrap()),
            }
            ExitCode::InternalError
        }
    }
}

fn run_bundle_inspect(global: &GlobalOpts, path: &str, verify: bool) -> ExitCode {
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

    let mut reader = match BundleReader::open(bundle_path) {
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
                OutputFormat::Jsonl => println!("{}", serde_json::to_string(&error_output).unwrap()),
                _ => println!("{}", serde_json::to_string_pretty(&error_output).unwrap()),
            }
            return ExitCode::InternalError;
        }
    };

    let manifest = reader.manifest();
    let files: Vec<_> = manifest.files.iter().map(|f| {
        serde_json::json!({
            "path": f.path,
            "bytes": f.bytes,
            "sha256": f.sha256,
            "mime_type": f.mime_type,
        })
    }).collect();

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
            "bundle_version": manifest.bundle_version,
            "source_session": manifest.session_id,
            "host_id": manifest.host_id,
            "created_at": manifest.created_at,
            "export_profile": format!("{}", manifest.export_profile),
            "pt_version": manifest.pt_version,
            "description": manifest.description,
            "file_count": manifest.file_count(),
            "total_bytes": manifest.total_bytes(),
        },
        "files": files,
        "verification": verification,
    });

    match global.format {
        OutputFormat::Md => {
            println!("Bundle: {}", path);
            println!("  Session: {}", manifest.session_id);
            println!("  Created: {}", manifest.created_at);
            println!("  Profile: {}", manifest.export_profile);
            println!("  Files: {} ({} bytes)", manifest.file_count(), manifest.total_bytes());
            if verify {
                let failures = reader.verify_all();
                if failures.is_empty() {
                    println!("  Verification: PASSED");
                } else {
                    println!("  Verification: FAILED ({} files)", failures.len());
                }
            }
        }
        OutputFormat::Jsonl => println!("{}", serde_json::to_string(&output).unwrap()),
        _ => println!("{}", serde_json::to_string_pretty(&output).unwrap()),
    }

    ExitCode::Clean
}

fn run_bundle_extract(global: &GlobalOpts, path: &str, output_arg: &Option<String>, verify: bool) -> ExitCode {
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

    let mut reader = match BundleReader::open(bundle_path) {
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
                OutputFormat::Jsonl => println!("{}", serde_json::to_string(&error_output).unwrap()),
                _ => println!("{}", serde_json::to_string_pretty(&error_output).unwrap()),
            }
            return ExitCode::InternalError;
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
            OutputFormat::Jsonl => println!("{}", serde_json::to_string(&error_output).unwrap()),
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
            println!("Extracted {} of {} files to {}", extracted, file_paths.len(), output_dir.display());
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
                        "hash": snapshot.priors_hash,
                        "using_defaults": snapshot.priors_path.is_none(),
                        "schema_version": snapshot.priors_schema_version,
                    },
                    "values": &config.priors
                },
                "policy": {
                    "source": {
                        "path": snapshot.policy_path.as_ref().map(|p| p.display().to_string()),
                        "hash": snapshot.policy_hash,
                        "using_defaults": snapshot.policy_path.is_none(),
                        "schema_version": snapshot.policy_schema_version,
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

fn output_stub_with_session(global: &GlobalOpts, session_id: &SessionId, command: &str, message: &str) {
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
        tool_info.insert("available".to_string(), serde_json::Value::Bool(tool.available));
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
            println!("UID: {} (root: {})", caps.permissions.effective_uid, caps.permissions.is_root);
            println!("Sudo: {}", caps.permissions.can_sudo);
            println!("Read others: {}", caps.permissions.can_read_others_procs);
            println!("Signal others: {}", caps.permissions.can_signal_others);
            println!();
            println!("## Tools ({}/{} available)", caps.tools.available_count(), caps.tools.total_count());
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
            println!("## Actions ({}/{} available)", caps.actions.available_count(), caps.actions.total_count());
            println!("  kill: {}, pause: {}, renice: {}", caps.actions.kill, caps.actions.pause, caps.actions.renice);
            println!("  cgroup_freeze: {}, cgroup_throttle: {}", caps.actions.cgroup_freeze, caps.actions.cgroup_throttle);
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
        .and_then(|output| {
            String::from_utf8(output.stdout)
                .ok()?
                .trim()
                .parse()
                .ok()
        })
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
                    total = rest.split_whitespace().next().and_then(|s| s.parse().ok()).unwrap_or(0);
                } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
                    available = rest.split_whitespace().next().and_then(|s| s.parse().ok()).unwrap_or(0);
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

fn run_agent_snapshot(global: &GlobalOpts, args: &AgentSnapshotArgs) -> ExitCode {
    let session_id = SessionId::new();

    let store = match SessionStore::from_env() {
        Ok(store) => store,
        Err(e) => {
            eprintln!("agent snapshot: session store error: {}", e);
            return ExitCode::InternalError;
        }
    };

    let manifest = SessionManifest::new(&session_id, None, SessionMode::RobotPlan, args.label.clone());
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
                eprintln!("agent snapshot: failed to read capabilities manifest {}: {}", path, e);
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
            let mem = system_state.get("memory").and_then(|m| m.get("used_gb")).and_then(|v| v.as_f64()).unwrap_or(0.0);
            let total = system_state.get("memory").and_then(|m| m.get("total_gb")).and_then(|v| v.as_f64()).unwrap_or(0.0);
            let procs = system_state.get("process_count").and_then(|v| v.as_u64()).unwrap_or(0);
            println!("[{}] agent snapshot: created ({} procs, {:.0}/{:.0}GB mem)", session_id, procs, mem, total);
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
                let load_strs: Vec<String> = load.iter().filter_map(|v| v.as_f64().map(|f| format!("{:.2}", f))).collect();
                println!("  Load: {}", load_strs.join(", "));
            }
            if let Some(cores) = system_state.get("cores").and_then(|v| v.as_u64()) {
                println!("  Cores: {}", cores);
            }
            if let Some(mem) = system_state.get("memory") {
                let total = mem.get("total_gb").and_then(|v| v.as_f64()).unwrap_or(0.0);
                let used = mem.get("used_gb").and_then(|v| v.as_f64()).unwrap_or(0.0);
                let avail = mem.get("available_gb").and_then(|v| v.as_f64()).unwrap_or(0.0);
                println!("  Memory: {:.1}GB total, {:.1}GB used, {:.1}GB available", total, used, avail);
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

    // Stub plan artifact (decision/plan.json) to establish durable session semantics.
    let plan = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "session_id": session_id.0,
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "status": "stub",
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
        "note": if created {
            "Created new session (no --session provided)"
        } else {
            "Reused existing session (--session)"
        }
    });

    let plan_path = handle.dir.join("decision").join("plan.json");
    if let Err(e) = std::fs::write(&plan_path, serde_json::to_string_pretty(&plan).unwrap()) {
        eprintln!(
            "agent plan: failed to write {}: {}",
            plan_path.display(),
            e
        );
        return ExitCode::InternalError;
    }

    // Update manifest state (best-effort; do not fail the whole command for manifest update).
    let _ = handle.update_state(SessionState::Planned);

    if let Some(emitter) = progress_emitter(global) {
        emitter.emit(
            ProgressEvent::new(pt_core::events::event_names::PLAN_READY, Phase::Plan)
                .with_session_id(session_id.to_string())
                .with_detail("plan_path", plan_path.display().to_string())
                .with_detail("status", "stub"),
        );
    }

    match global.format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&plan).unwrap());
        }
        OutputFormat::Summary => {
            println!("[{}] agent plan: stub plan written", session_id);
        }
        OutputFormat::Exitcode => {}
        _ => {
            println!("# pt-core agent plan");
            println!();
            println!("Session: {}", session_id);
            println!("Plan: {}", plan_path.display());
            println!();
            println!("(stub) Planning not yet implemented.");
        }
    }

    ExitCode::Clean
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
    if let Err(e) = std::fs::write(&explain_path, serde_json::to_string_pretty(&output).unwrap()) {
        eprintln!("agent explain: warning: failed to save to session: {}", e);
    }

    match global.format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
        }
        OutputFormat::Summary => {
            for expl in &explanations {
                if let (Some(pid), Some(class)) = (expl.get("pid"), expl.get("classification")) {
                    let conf = expl.get("confidence").and_then(|v| v.as_str()).unwrap_or("?");
                    println!("[{}] PID {}: {} ({})", sid, pid, class, conf);
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

                let class = expl.get("classification").and_then(|v| v.as_str()).unwrap_or("unknown");
                let conf = expl.get("confidence").and_then(|v| v.as_str()).unwrap_or("unknown");
                let why = expl.get("why_summary").and_then(|v| v.as_str()).unwrap_or("");

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
                            let strength = bf.get("strength").and_then(|v| v.as_str()).unwrap_or("?");
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
        net: None,      // Would need network scan
        io_active: None, // Would need /proc inspection
        state_flag: Some(state_to_flag(proc.state)),
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
                    "strength": bf.strength.label(),
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
fn state_to_flag(state: pt_core::collect::ProcessState) -> usize {
    use pt_core::collect::ProcessState;
    match state {
        ProcessState::Running => 0,
        ProcessState::Sleeping => 1,
        ProcessState::DiskSleep => 2,
        ProcessState::Zombie => 3,
        ProcessState::Stopped => 4,
        ProcessState::Idle => 5,
        ProcessState::Dead => 6,
        ProcessState::Unknown => 7,
    }
}

fn run_agent_apply(global: &GlobalOpts, args: &AgentApplyArgs) -> ExitCode {
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
    if let Err(e) = store.open(&sid) {
        eprintln!("agent apply: {}", e);
        return ExitCode::ArgsError;
    }
    output_stub_with_session(global, &sid, "agent apply", "Agent apply mode not yet implemented");
    ExitCode::Clean
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
    output_stub_with_session(global, &sid, "agent verify", "Agent verify mode not yet implemented");
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
    output_stub_with_session(global, &base, "agent diff", "Agent diff mode not yet implemented");
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
    let build_class_json = |name: &str, cp: &pt_core::config::priors::ClassPriors| -> serde_json::Value {
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
            response["hazard_regimes"] = serde_json::to_value(&priors.hazard_regimes).unwrap_or_default();
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
        OutputFormat::Summary => {
            let source = if snapshot.priors_path.is_some() { "custom" } else { "defaults" };
            println!("[{}] priors: {} class(es) from {}", session_id, classes_data.len(), source);
        }
        OutputFormat::Exitcode => {}
        _ => {
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
                    println!("| cpu_beta | α={:.2}, β={:.2} |", cpu["alpha"].as_f64().unwrap_or(0.0), cpu["beta"].as_f64().unwrap_or(0.0));
                }
                if let Some(orphan) = class_json.get("orphan_beta") {
                    println!("| orphan_beta | α={:.2}, β={:.2} |", orphan["alpha"].as_f64().unwrap_or(0.0), orphan["beta"].as_f64().unwrap_or(0.0));
                }
                if let Some(tty) = class_json.get("tty_beta") {
                    println!("| tty_beta | α={:.2}, β={:.2} |", tty["alpha"].as_f64().unwrap_or(0.0), tty["beta"].as_f64().unwrap_or(0.0));
                }
                if let Some(net) = class_json.get("net_beta") {
                    println!("| net_beta | α={:.2}, β={:.2} |", net["alpha"].as_f64().unwrap_or(0.0), net["beta"].as_f64().unwrap_or(0.0));
                }
                println!();
            }
            println!("Session: {}", session_id);
        }
    }

    ExitCode::Clean
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
            .and_then(|v| v.get("candidates").and_then(|c| c.as_array()).map(|a| a.len()))
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
            if resumable && matches!(manifest.state, SessionState::Planned | SessionState::Executing) {
                println!("Resume with: pt agent apply --session {}", manifest.session_id);
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
            println!("Preserved: {} sessions (active or in-progress)", result.preserved_count);
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
    let state_filter = args.state.as_ref().and_then(|s| match s.to_lowercase().as_str() {
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
                        s.candidates_count.map(|c| c.to_string()).unwrap_or_else(|| "-".to_string()),
                        s.actions_count.map(|c| c.to_string()).unwrap_or_else(|| "-".to_string()),
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

    let (num_str, unit) = if s.ends_with('d') {
        (&s[..s.len() - 1], 'd')
    } else if s.ends_with('h') {
        (&s[..s.len() - 1], 'h')
    } else if s.ends_with('m') {
        (&s[..s.len() - 1], 'm')
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
