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
use pt_core::config::{load_config, ConfigOptions, ConfigError};
use pt_core::exit_codes::ExitCode;
use std::path::PathBuf;

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
    /// Create a new diagnostic bundle
    Create {
        /// Output path for the bundle
        #[arg(short, long)]
        output: Option<String>,

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
    },
    /// Extract bundle contents
    Extract {
        /// Path to the bundle file
        path: String,

        /// Output directory
        #[arg(short, long)]
        output: Option<String>,
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

    /// Include galaxy-brain math ledger
    #[arg(long)]
    galaxy_brain: bool,
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

use pt_core::logging::{init_logging, LogConfig, LogFormat, LogLevel, LogContext, Stage, event_names};
use pt_core::log_event;

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
            run_interactive(&cli.global, &RunArgs {
                deep: false,
                signatures: None,
                community_signatures: false,
                min_age: None,
            })
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

use pt_core::collect::{quick_scan, QuickScanOptions};

fn run_scan(global: &GlobalOpts, args: &ScanArgs) -> ExitCode {
    let ctx = LogContext::new(
        pt_core::logging::generate_run_id(),
        pt_core::logging::get_host_id()
    );
    
    log_event!(ctx, INFO, event_names::RUN_STARTED, Stage::Init, "Starting scan command");

    if args.deep {
        return run_deep_scan(global, &DeepScanArgs { pids: vec![], budget: None });
    }

    // Configure scan options
    let options = QuickScanOptions {
        pids: vec![], // Empty = all processes
        include_kernel_threads: false, // Default to false for quick scan
        timeout: global.timeout.map(std::time::Duration::from_secs),
    };

    // Perform scan
    match quick_scan(&options) {
        Ok(result) => {
            log_event!(ctx, INFO, event_names::SCAN_COMPLETED, Stage::Scan, "Scan finished successfully", 
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
                    println!("Scanned {} processes in {}ms", 
                        result.metadata.process_count, 
                        result.metadata.duration_ms
                    );
                }
                OutputFormat::Exitcode => {} // Silent
                _ => {
                    // Human readable output
                    println!("# Quick Scan Results");
                    println!("Scanned {} processes in {}ms", 
                        result.metadata.process_count, 
                        result.metadata.duration_ms
                    );
                    println!("Platform: {}", result.metadata.platform);
                    println!();
                    
                    println!("{:<8} {:<8} {:<10} {:<6} {:<6} {:<6} {}", 
                        "PID", "PPID", "USER", "STATE", "%CPU", "RSS", "COMMAND");
                    
                    for p in result.processes.iter().take(20) {
                        println!("{:<8} {:<8} {:<10} {:<6} {:<6.1} {:<6} {}", 
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
            log_event!(ctx, ERROR, event_names::SCAN_FAILED, Stage::Scan, "Scan failed", error = e.to_string());
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

fn run_bundle(global: &GlobalOpts, _args: &BundleArgs) -> ExitCode {
    output_stub(global, "bundle", "Bundle mode not yet implemented");
    ExitCode::Clean
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
        AgentCommands::Plan(_) => {
            output_stub(global, "agent plan", "Agent plan mode not yet implemented");
        }
        AgentCommands::Explain(_) => {
            output_stub(global, "agent explain", "Agent explain mode not yet implemented");
        }
        AgentCommands::Apply(_) => {
            output_stub(global, "agent apply", "Agent apply mode not yet implemented");
        }
        AgentCommands::Verify(_) => {
            output_stub(global, "agent verify", "Agent verify mode not yet implemented");
        }
        AgentCommands::Diff(_) => {
            output_stub(global, "agent diff", "Agent diff mode not yet implemented");
        }
        AgentCommands::Snapshot(_) => {
            output_stub(global, "agent snapshot", "Agent snapshot mode not yet implemented");
        }
        AgentCommands::Capabilities => {
            output_capabilities(global);
        }
    }
    ExitCode::Clean
}

fn run_config(global: &GlobalOpts, args: &ConfigArgs) -> ExitCode {
    match &args.command {
        ConfigCommands::Show { file } => {
            run_config_show(global, file.as_deref())
        }
        ConfigCommands::Schema { file } => {
            output_stub(global, "config schema", &format!("Schema for {} not yet implemented", file));
            ExitCode::Clean
        }
        ConfigCommands::Validate { path } => {
            run_config_validate(global, path.as_ref())
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
            let priors_src = snapshot.priors_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "built-in defaults".to_string());
            let policy_src = snapshot.policy_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "built-in defaults".to_string());
            println!("[{}] config: priors={} policy={}", session_id, priors_src, policy_src);
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
        Err(e) => {
            output_config_error(global, &e)
        }
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
    output_stub(global, "telemetry", "Telemetry management not yet implemented");
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

    // Minimal capabilities stub - will be populated from manifest
    let capabilities = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "session_id": session_id.0,
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "os": {
            "family": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
        },
        "tools": {},
        "message": "Full capabilities manifest not loaded (use --capabilities or PT_CAPABILITIES_MANIFEST)"
    });

    match global.format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&capabilities).unwrap());
        }
        OutputFormat::Exitcode => {}
        _ => {
            println!("# Capabilities");
            println!();
            println!("OS: {} ({})", std::env::consts::OS, std::env::consts::ARCH);
            println!();
            println!("Note: Full capabilities manifest not loaded.");
            println!("Use --capabilities <path> or set PT_CAPABILITIES_MANIFEST");
        }
    }
}
