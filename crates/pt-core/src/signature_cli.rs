//! CLI commands for signature management.
//!
//! Provides list, show, add, remove, test, validate, and export subcommands
//! for managing user-defined process signatures.

use crate::exit_codes::ExitCode;
use crate::supervision::pattern_persistence::{AllPatternStats, DisabledPatterns};
use crate::supervision::signature::ProcessMatchContext;
use crate::supervision::{
    SignatureDatabase, SignaturePatterns, SignatureSchema, SupervisorCategory, SupervisorSignature,
    SCHEMA_VERSION as SIG_SCHEMA_VERSION,
};
use clap::{Args, Subcommand};
use pt_bundle::BundleReader;
use pt_common::{OutputFormat, SessionId, SCHEMA_VERSION};
use std::collections::HashMap;
use std::path::Path;

/// Bundle path for exported user signatures.
pub const BUNDLE_SIGNATURES_PATH: &str = "signatures/user_signatures.json";

/// Arguments for the signature command
#[derive(Args, Debug)]
pub struct SignatureArgs {
    #[command(subcommand)]
    pub command: SignatureCommands,
}

/// Signature subcommands
#[derive(Subcommand, Debug)]
pub enum SignatureCommands {
    /// List all signatures (built-in and user-defined)
    List {
        /// Only show user-defined signatures
        #[arg(long)]
        user_only: bool,
        /// Only show built-in signatures
        #[arg(long)]
        builtin_only: bool,
        /// Filter by category (agent, ide, ci, orchestrator, terminal, other)
        #[arg(long)]
        category: Option<String>,
    },
    /// Show details of a specific signature
    Show {
        /// Name of the signature to show
        name: String,
    },
    /// Add a new user signature
    Add {
        /// Name for the new signature
        name: String,
        /// Category (agent, ide, ci, orchestrator, terminal, other)
        #[arg(long)]
        category: String,
        /// Process name patterns (regex)
        #[arg(long = "pattern", value_name = "REGEX")]
        patterns: Vec<String>,
        /// Command line argument patterns (regex)
        #[arg(long = "arg-pattern", value_name = "REGEX")]
        arg_patterns: Vec<String>,
        /// Environment variable (format: NAME=VALUE_REGEX)
        #[arg(long = "env-var", value_name = "NAME=REGEX")]
        env_vars: Vec<String>,
        /// Confidence weight (0.0-1.0)
        #[arg(long, default_value = "0.8")]
        confidence: f64,
        /// Optional notes about the signature
        #[arg(long)]
        notes: Option<String>,
        /// Priority (higher = checked first)
        #[arg(long, default_value = "100")]
        priority: u32,
    },
    /// Remove a user signature
    Remove {
        /// Name of the signature to remove
        name: String,
        /// Skip confirmation
        #[arg(long)]
        force: bool,
    },
    /// Test if a process name matches any signature
    Test {
        /// Process name to test
        process_name: String,
        /// Optional command line to test
        #[arg(long)]
        cmdline: Option<String>,
        /// Show all matches (not just best)
        #[arg(long)]
        all: bool,
    },
    /// Validate user signatures file
    Validate,
    /// Export signatures to a file
    Export {
        /// Output file path
        output: String,
        /// Only export user signatures
        #[arg(long)]
        user_only: bool,
    },
    /// Disable a signature without deleting it
    Disable {
        /// Name of the signature to disable
        name: String,
        /// Optional reason for disabling
        #[arg(long)]
        reason: Option<String>,
    },
    /// Re-enable a previously disabled signature
    Enable {
        /// Name of the signature to enable
        name: String,
    },
    /// Show signature performance statistics
    Stats {
        /// Only show signatures with at least this many matches
        #[arg(long, default_value = "0")]
        min_matches: u32,
        /// Sort by: matches, accepts, rejects, rate
        #[arg(long, default_value = "matches")]
        sort: String,
    },
}

/// Get the path to user signatures file
pub fn user_signatures_path() -> std::path::PathBuf {
    let config_dir = dirs::config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("process_triage");
    config_dir.join("signatures.json")
}

/// Load user signatures from config directory
pub fn load_user_signatures() -> Option<SignatureSchema> {
    let path = user_signatures_path();
    if path.exists() {
        match std::fs::read_to_string(&path) {
            Ok(content) => match serde_json::from_str(&content) {
                Ok(schema) => Some(schema),
                Err(e) => {
                    eprintln!("Warning: Failed to parse user signatures: {}", e);
                    None
                }
            },
            Err(e) => {
                eprintln!("Warning: Failed to read user signatures: {}", e);
                None
            }
        }
    } else {
        None
    }
}

/// Save user signatures to config directory
pub fn save_user_signatures(schema: &SignatureSchema) -> Result<(), std::io::Error> {
    let path = user_signatures_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = serde_json::to_string_pretty(schema)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(&path, content)
}

/// Get the path to disabled signatures file
fn disabled_signatures_path() -> std::path::PathBuf {
    let config_dir = dirs::config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("process_triage")
        .join("patterns");
    config_dir.join("disabled.json")
}

/// Get the path to pattern statistics file
fn pattern_stats_path() -> std::path::PathBuf {
    let config_dir = dirs::config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("process_triage");
    config_dir.join("pattern_stats.json")
}

/// Save disabled patterns to config directory
pub fn save_disabled_patterns(disabled: &DisabledPatterns) -> Result<(), std::io::Error> {
    let path = disabled_signatures_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Convert PersistenceError to io::Error for compatibility
    disabled.save_to_file(&path).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
}

/// Parse a category string into SupervisorCategory
pub fn parse_category(s: &str) -> Option<SupervisorCategory> {
    match s.to_lowercase().as_str() {
        "agent" => Some(SupervisorCategory::Agent),
        "ide" => Some(SupervisorCategory::Ide),
        "ci" => Some(SupervisorCategory::Ci),
        "orchestrator" => Some(SupervisorCategory::Orchestrator),
        "terminal" => Some(SupervisorCategory::Terminal),
        "other" => Some(SupervisorCategory::Other),
        _ => None,
    }
}

/// Run the signature command dispatcher
pub fn run_signature(format: &OutputFormat, args: &SignatureArgs) -> ExitCode {
    match &args.command {
        SignatureCommands::List {
            user_only,
            builtin_only,
            category,
        } => run_signature_list(format, *user_only, *builtin_only, category.as_deref()),
        SignatureCommands::Show { name } => run_signature_show(format, name),
        SignatureCommands::Add {
            name,
            category,
            patterns,
            arg_patterns,
            env_vars,
            confidence,
            notes,
            priority,
        } => run_signature_add(
            format,
            name,
            category,
            patterns,
            arg_patterns,
            env_vars,
            *confidence,
            notes.as_deref(),
            *priority,
        ),
        SignatureCommands::Remove { name, force } => run_signature_remove(format, name, *force),
        SignatureCommands::Test {
            process_name,
            cmdline,
            all,
        } => run_signature_test(format, process_name, cmdline.as_deref(), *all),
        SignatureCommands::Validate => run_signature_validate(format),
        SignatureCommands::Export { output, user_only } => {
            run_signature_export(format, output, *user_only)
        }
        SignatureCommands::Disable { name, reason } => {
            run_signature_disable(format, name, reason.as_deref())
        }
        SignatureCommands::Enable { name } => run_signature_enable(format, name),
        SignatureCommands::Stats { min_matches, sort } => {
            run_signature_stats(format, *min_matches, sort)
        }
    }
}

fn run_signature_list(
    format: &OutputFormat,
    user_only: bool,
    builtin_only: bool,
    category_filter: Option<&str>,
) -> ExitCode {
    let session_id = SessionId::new();
    let mut all_sigs: Vec<serde_json::Value> = Vec::new();

    // Load built-in signatures
    if !user_only {
        let mut db = SignatureDatabase::new();
        db.add_default_signatures();
        for sig in db.signatures() {
            if let Some(cat) = category_filter {
                if let Some(parsed) = parse_category(cat) {
                    if sig.category != parsed {
                        continue;
                    }
                }
            }
            all_sigs.push(serde_json::json!({
                "name": sig.name,
                "category": format!("{:?}", sig.category),
                "source": "builtin",
                "priority": sig.priority,
                "confidence": sig.confidence_weight,
            }));
        }
    }

    // Load user signatures
    if !builtin_only {
        if let Some(user_schema) = load_user_signatures() {
            for sig in &user_schema.signatures {
                if let Some(cat) = category_filter {
                    if let Some(parsed) = parse_category(cat) {
                        if sig.category != parsed {
                            continue;
                        }
                    }
                }
                all_sigs.push(serde_json::json!({
                    "name": sig.name,
                    "category": format!("{:?}", sig.category),
                    "source": "user",
                    "priority": sig.priority,
                    "confidence": sig.confidence_weight,
                }));
            }
        }
    }

    // Sort by priority (higher first)
    all_sigs.sort_by(|a, b| {
        let pa = a["priority"].as_u64().unwrap_or(0);
        let pb = b["priority"].as_u64().unwrap_or(0);
        pb.cmp(&pa)
    });

    match format {
        OutputFormat::Json => {
            let output = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "session_id": session_id.0,
                "generated_at": chrono::Utc::now().to_rfc3339(),
                "command": "signature list",
                "signatures": all_sigs,
                "count": all_sigs.len(),
            });
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
        }
        _ => {
            println!("# Signatures ({} total)", all_sigs.len());
            println!();
            for sig in &all_sigs {
                println!(
                    "  {} ({}) [{}] priority={} confidence={}",
                    sig["name"].as_str().unwrap_or("?"),
                    sig["category"].as_str().unwrap_or("?"),
                    sig["source"].as_str().unwrap_or("?"),
                    sig["priority"],
                    sig["confidence"]
                );
            }
        }
    }

    ExitCode::Clean
}

fn run_signature_show(format: &OutputFormat, name: &str) -> ExitCode {
    let session_id = SessionId::new();

    // Check built-in first
    let mut db = SignatureDatabase::new();
    db.add_default_signatures();

    for sig in db.signatures() {
        if sig.name == name {
            let output = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "session_id": session_id.0,
                "generated_at": chrono::Utc::now().to_rfc3339(),
                "command": "signature show",
                "source": "builtin",
                "signature": {
                    "name": sig.name,
                    "category": format!("{:?}", sig.category),
                    "patterns": sig.patterns,
                    "priority": sig.priority,
                    "confidence": sig.confidence_weight,
                    "notes": sig.notes,
                }
            });
            match format {
                OutputFormat::Json => {
                    println!("{}", serde_json::to_string_pretty(&output).unwrap());
                }
                _ => {
                    println!("# Signature: {} (builtin)", name);
                    println!();
                    println!("  Category: {:?}", sig.category);
                    println!("  Priority: {}", sig.priority);
                    println!("  Confidence: {}", sig.confidence_weight);
                    if let Some(ref notes) = sig.notes {
                        println!("  Notes: {}", notes);
                    }
                    println!("  Patterns: {:?}", sig.patterns);
                }
            }
            return ExitCode::Clean;
        }
    }

    // Check user signatures
    if let Some(user_schema) = load_user_signatures() {
        for sig in &user_schema.signatures {
            if sig.name == name {
                let output = serde_json::json!({
                    "schema_version": SCHEMA_VERSION,
                    "session_id": session_id.0,
                    "generated_at": chrono::Utc::now().to_rfc3339(),
                    "command": "signature show",
                    "source": "user",
                    "signature": {
                        "name": sig.name,
                        "category": format!("{:?}", sig.category),
                        "patterns": sig.patterns,
                        "priority": sig.priority,
                        "confidence": sig.confidence_weight,
                        "notes": sig.notes,
                    }
                });
                match format {
                    OutputFormat::Json => {
                        println!("{}", serde_json::to_string_pretty(&output).unwrap());
                    }
                    _ => {
                        println!("# Signature: {} (user)", name);
                        println!();
                        println!("  Category: {:?}", sig.category);
                        println!("  Priority: {}", sig.priority);
                        println!("  Confidence: {}", sig.confidence_weight);
                        if let Some(ref notes) = sig.notes {
                            println!("  Notes: {}", notes);
                        }
                        println!("  Patterns: {:?}", sig.patterns);
                    }
                }
                return ExitCode::Clean;
            }
        }
    }

    eprintln!("Signature '{}' not found", name);
    ExitCode::ArgsError
}

#[allow(clippy::too_many_arguments)]
fn run_signature_add(
    format: &OutputFormat,
    name: &str,
    category: &str,
    patterns: &[String],
    arg_patterns: &[String],
    env_vars: &[String],
    confidence: f64,
    notes: Option<&str>,
    priority: u32,
) -> ExitCode {
    let session_id = SessionId::new();

    // Parse category
    let cat = match parse_category(category) {
        Some(c) => c,
        None => {
            eprintln!(
                "Invalid category '{}'. Valid: agent, ide, ci, orchestrator, terminal, other",
                category
            );
            return ExitCode::ArgsError;
        }
    };

    // Parse environment variables (NAME=REGEX format)
    let mut env_map: HashMap<String, String> = HashMap::new();
    for env_var in env_vars {
        if let Some((key, value)) = env_var.split_once('=') {
            env_map.insert(key.to_string(), value.to_string());
        } else {
            // Just check existence (any value)
            env_map.insert(env_var.clone(), ".*".to_string());
        }
    }

    // Build patterns
    let sig_patterns = SignaturePatterns {
        process_names: patterns.to_vec(),
        arg_patterns: arg_patterns.to_vec(),
        environment_vars: env_map,
        ..Default::default()
    };

    // Create new signature
    let new_sig = SupervisorSignature {
        name: name.to_string(),
        category: cat,
        patterns: sig_patterns,
        priority,
        confidence_weight: confidence,
        notes: notes.map(|s| s.to_string()),
        builtin: false,
        priors: Default::default(),
        expectations: Default::default(),
    };

    // Load or create user schema
    let mut schema = load_user_signatures().unwrap_or_else(|| SignatureSchema {
        schema_version: SIG_SCHEMA_VERSION,
        signatures: Vec::new(),
        metadata: None,
    });

    // Check for duplicate
    if schema.signatures.iter().any(|s| s.name == name) {
        eprintln!("Signature '{}' already exists. Use 'remove' first.", name);
        return ExitCode::ArgsError;
    }

    schema.signatures.push(new_sig);

    // Save
    if let Err(e) = save_user_signatures(&schema) {
        eprintln!("Failed to save signature: {}", e);
        return ExitCode::ArgsError;
    }

    match format {
        OutputFormat::Json => {
            let output = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "session_id": session_id.0,
                "generated_at": chrono::Utc::now().to_rfc3339(),
                "command": "signature add",
                "status": "success",
                "name": name,
                "path": user_signatures_path().display().to_string(),
            });
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
        }
        _ => {
            println!("Added signature '{}' to user signatures", name);
            println!("Saved to: {}", user_signatures_path().display());
        }
    }

    ExitCode::Clean
}

fn run_signature_remove(format: &OutputFormat, name: &str, force: bool) -> ExitCode {
    let session_id = SessionId::new();

    // Load user signatures
    let mut schema = match load_user_signatures() {
        Some(s) => s,
        None => {
            eprintln!("No user signatures file found");
            return ExitCode::ArgsError;
        }
    };

    // Find and remove
    let original_len = schema.signatures.len();
    schema.signatures.retain(|s| s.name != name);

    if schema.signatures.len() == original_len {
        eprintln!("Signature '{}' not found in user signatures", name);
        return ExitCode::ArgsError;
    }

    if !force {
        eprintln!("Removing signature '{}'. Use --force to confirm.", name);
        return ExitCode::ArgsError;
    }

    // Save
    if let Err(e) = save_user_signatures(&schema) {
        eprintln!("Failed to save: {}", e);
        return ExitCode::ArgsError;
    }

    match format {
        OutputFormat::Json => {
            let output = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "session_id": session_id.0,
                "generated_at": chrono::Utc::now().to_rfc3339(),
                "command": "signature remove",
                "status": "success",
                "name": name,
            });
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
        }
        _ => {
            println!("Removed signature '{}'", name);
        }
    }

    ExitCode::Clean
}

fn run_signature_test(
    format: &OutputFormat,
    process_name: &str,
    cmdline: Option<&str>,
    all: bool,
) -> ExitCode {
    let session_id = SessionId::new();

    // Build a database with both built-in and user signatures
    let mut db = SignatureDatabase::new();
    db.add_default_signatures();

    // Add user signatures
    if let Some(user_schema) = load_user_signatures() {
        for sig in user_schema.signatures {
            let _ = db.add(sig);
        }
    }

    // Build match context
    let ctx = ProcessMatchContext {
        comm: process_name,
        cmdline,
        cwd: None,
        env_vars: None,
        socket_paths: None,
        parent_comm: None,
    };

    // Test matching
    let matches = db.match_process(&ctx);

    let matches_json: Vec<serde_json::Value> = matches
        .iter()
        .map(|m| {
            serde_json::json!({
                "name": m.signature.name,
                "category": format!("{:?}", m.signature.category),
                "confidence": m.score,
            })
        })
        .collect();

    match format {
        OutputFormat::Json => {
            let output = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "session_id": session_id.0,
                "generated_at": chrono::Utc::now().to_rfc3339(),
                "command": "signature test",
                "process_name": process_name,
                "cmdline": cmdline.unwrap_or(""),
                "matches": matches_json,
                "count": matches.len(),
            });
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
        }
        _ => {
            println!("# Testing signature match for: {}", process_name);
            if let Some(cl) = cmdline {
                println!("  Cmdline: {}", cl);
            }
            println!();
            if matches.is_empty() {
                println!("  No matches found");
            } else {
                for m in &matches {
                    println!(
                        "  MATCH: {} ({:?}) score={}",
                        m.signature.name, m.signature.category, m.score
                    );
                    if !all {
                        break;
                    }
                }
            }
        }
    }

    ExitCode::Clean
}

fn run_signature_validate(format: &OutputFormat) -> ExitCode {
    let session_id = SessionId::new();
    let path = user_signatures_path();

    if !path.exists() {
        match format {
            OutputFormat::Json => {
                let output = serde_json::json!({
                    "schema_version": SCHEMA_VERSION,
                    "session_id": session_id.0,
                    "generated_at": chrono::Utc::now().to_rfc3339(),
                    "command": "signature validate",
                    "status": "no_file",
                    "message": "No user signatures file found",
                });
                println!("{}", serde_json::to_string_pretty(&output).unwrap());
            }
            _ => {
                println!("No user signatures file found at: {}", path.display());
            }
        }
        return ExitCode::Clean;
    }

    match std::fs::read_to_string(&path) {
        Ok(content) => match serde_json::from_str::<SignatureSchema>(&content) {
            Ok(schema) => {
                match format {
                    OutputFormat::Json => {
                        let output = serde_json::json!({
                            "schema_version": SCHEMA_VERSION,
                            "session_id": session_id.0,
                            "generated_at": chrono::Utc::now().to_rfc3339(),
                            "command": "signature validate",
                            "status": "valid",
                            "path": path.display().to_string(),
                            "signature_count": schema.signatures.len(),
                        });
                        println!("{}", serde_json::to_string_pretty(&output).unwrap());
                    }
                    _ => {
                        println!("User signatures file is valid");
                        println!("  Path: {}", path.display());
                        println!("  Signatures: {}", schema.signatures.len());
                    }
                }
                ExitCode::Clean
            }
            Err(e) => {
                match format {
                    OutputFormat::Json => {
                        let output = serde_json::json!({
                            "schema_version": SCHEMA_VERSION,
                            "session_id": session_id.0,
                            "generated_at": chrono::Utc::now().to_rfc3339(),
                            "command": "signature validate",
                            "status": "invalid",
                            "error": e.to_string(),
                        });
                        println!("{}", serde_json::to_string_pretty(&output).unwrap());
                    }
                    _ => {
                        eprintln!("Invalid user signatures file: {}", e);
                    }
                }
                ExitCode::ArgsError
            }
        },
        Err(e) => {
            eprintln!("Failed to read signatures file: {}", e);
            ExitCode::ArgsError
        }
    }
}

fn run_signature_export(format: &OutputFormat, output_path: &str, user_only: bool) -> ExitCode {
    let session_id = SessionId::new();

    let mut all_sigs = Vec::new();

    // Load built-in signatures
    if !user_only {
        let mut db = SignatureDatabase::new();
        db.add_default_signatures();
        for sig in db.signatures() {
            all_sigs.push(sig.clone());
        }
    }

    // Load user signatures
    if let Some(user_schema) = load_user_signatures() {
        for sig in user_schema.signatures {
            all_sigs.push(sig);
        }
    }

    let export_schema = SignatureSchema {
        schema_version: SIG_SCHEMA_VERSION,
        signatures: all_sigs,
        metadata: None,
    };

    let content = match serde_json::to_string_pretty(&export_schema) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to serialize: {}", e);
            return ExitCode::ArgsError;
        }
    };

    if let Err(e) = std::fs::write(output_path, &content) {
        eprintln!("Failed to write to '{}': {}", output_path, e);
        return ExitCode::ArgsError;
    }

    match format {
        OutputFormat::Json => {
            let output = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "session_id": session_id.0,
                "generated_at": chrono::Utc::now().to_rfc3339(),
                "command": "signature export",
                "status": "success",
                "path": output_path,
                "signature_count": export_schema.signatures.len(),
            });
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
        }
        _ => {
            println!(
                "Exported {} signatures to {}",
                export_schema.signatures.len(),
                output_path
            );
        }
    }

    ExitCode::Clean
}

fn run_signature_disable(format: &OutputFormat, name: &str, reason: Option<&str>) -> ExitCode {
    let session_id = SessionId::new();

    // First check if the signature exists (in either built-in or user signatures)
    let mut db = SignatureDatabase::new();
    db.add_default_signatures();

    let mut found = db.signatures().iter().any(|s| s.name == name);

    // Also check user signatures
    if !found {
        if let Some(user_schema) = load_user_signatures() {
            found = user_schema.signatures.iter().any(|s| s.name == name);
        }
    }

    if !found {
        match format {
            OutputFormat::Json => {
                let output = serde_json::json!({
                    "schema_version": SCHEMA_VERSION,
                    "session_id": session_id.0,
                    "generated_at": chrono::Utc::now().to_rfc3339(),
                    "command": "signature disable",
                    "status": "error",
                    "error": format!("Signature '{}' not found", name),
                });
                println!("{}", serde_json::to_string_pretty(&output).unwrap());
            }
            _ => eprintln!("Error: Signature '{}' not found", name),
        }
        return ExitCode::ArgsError;
    }

    // Load or create disabled patterns
    let disabled_path = disabled_signatures_path();
    let mut disabled = if disabled_path.exists() {
        match DisabledPatterns::from_file(&disabled_path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Warning: Failed to load disabled patterns: {}", e);
                DisabledPatterns::default()
            }
        }
    } else {
        DisabledPatterns::default()
    };

    // Check if already disabled
    if disabled.is_disabled(name) {
        match format {
            OutputFormat::Json => {
                let output = serde_json::json!({
                    "schema_version": SCHEMA_VERSION,
                    "session_id": session_id.0,
                    "generated_at": chrono::Utc::now().to_rfc3339(),
                    "command": "signature disable",
                    "status": "already_disabled",
                    "name": name,
                });
                println!("{}", serde_json::to_string_pretty(&output).unwrap());
            }
            _ => println!("Signature '{}' is already disabled", name),
        }
        return ExitCode::Clean;
    }

    // Disable the signature
    disabled.disable(name, reason);

    // Save
    if let Err(e) = save_disabled_patterns(&disabled) {
        eprintln!("Failed to save disabled patterns: {}", e);
        return ExitCode::ArgsError;
    }

    match format {
        OutputFormat::Json => {
            let output = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "session_id": session_id.0,
                "generated_at": chrono::Utc::now().to_rfc3339(),
                "command": "signature disable",
                "status": "success",
                "name": name,
                "reason": reason,
            });
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
        }
        _ => {
            println!("Disabled signature '{}'", name);
            if let Some(r) = reason {
                println!("  Reason: {}", r);
            }
        }
    }

    ExitCode::Clean
}

fn run_signature_enable(format: &OutputFormat, name: &str) -> ExitCode {
    let session_id = SessionId::new();

    // Load disabled patterns
    let disabled_path = disabled_signatures_path();
    let mut disabled = if disabled_path.exists() {
        match DisabledPatterns::from_file(&disabled_path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Warning: Failed to load disabled patterns: {}", e);
                DisabledPatterns::default()
            }
        }
    } else {
        DisabledPatterns::default()
    };

    // Check if it's actually disabled
    if !disabled.is_disabled(name) {
        match format {
            OutputFormat::Json => {
                let output = serde_json::json!({
                    "schema_version": SCHEMA_VERSION,
                    "session_id": session_id.0,
                    "generated_at": chrono::Utc::now().to_rfc3339(),
                    "command": "signature enable",
                    "status": "not_disabled",
                    "name": name,
                    "message": format!("Signature '{}' is not disabled", name),
                });
                println!("{}", serde_json::to_string_pretty(&output).unwrap());
            }
            _ => println!("Signature '{}' is not disabled", name),
        }
        return ExitCode::Clean;
    }

    // Enable (remove from disabled set)
    disabled.enable(name);

    // Save
    if let Err(e) = save_disabled_patterns(&disabled) {
        eprintln!("Failed to save disabled patterns: {}", e);
        return ExitCode::ArgsError;
    }

    match format {
        OutputFormat::Json => {
            let output = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "session_id": session_id.0,
                "generated_at": chrono::Utc::now().to_rfc3339(),
                "command": "signature enable",
                "status": "success",
                "name": name,
            });
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
        }
        _ => {
            println!("Enabled signature '{}'", name);
        }
    }

    ExitCode::Clean
}

fn run_signature_stats(format: &OutputFormat, min_matches: u32, sort_by: &str) -> ExitCode {
    let session_id = SessionId::new();

    // Load pattern stats
    let stats_path = pattern_stats_path();
    let stats = if stats_path.exists() {
        match AllPatternStats::from_file(&stats_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Warning: Failed to load pattern stats: {}", e);
                AllPatternStats::default()
            }
        }
    } else {
        AllPatternStats::default()
    };

    // Collect and filter stats
    let mut stat_entries: Vec<(&String, &crate::supervision::pattern_persistence::PatternStats)> =
        stats
            .patterns
            .iter()
            .filter(|(_, s)| s.match_count >= min_matches)
            .collect();

    // Sort based on sort_by parameter
    match sort_by {
        "accepts" => {
            stat_entries.sort_by(|a, b| b.1.accept_count.cmp(&a.1.accept_count));
        }
        "rejects" => {
            stat_entries.sort_by(|a, b| b.1.reject_count.cmp(&a.1.reject_count));
        }
        "rate" => {
            stat_entries.sort_by(|a, b| {
                let rate_a = a.1.acceptance_rate().unwrap_or(0.0);
                let rate_b = b.1.acceptance_rate().unwrap_or(0.0);
                rate_b.partial_cmp(&rate_a).unwrap_or(std::cmp::Ordering::Equal)
            });
        }
        _ => {
            // Default: sort by matches
            stat_entries.sort_by(|a, b| b.1.match_count.cmp(&a.1.match_count));
        }
    }

    match format {
        OutputFormat::Json => {
            let stats_json: Vec<serde_json::Value> = stat_entries
                .iter()
                .map(|(name, s)| {
                    serde_json::json!({
                        "name": name,
                        "match_count": s.match_count,
                        "accept_count": s.accept_count,
                        "reject_count": s.reject_count,
                        "acceptance_rate": s.acceptance_rate(),
                        "computed_confidence": s.computed_confidence,
                        "first_seen": s.first_seen,
                        "last_match": s.last_match,
                    })
                })
                .collect();

            let output = serde_json::json!({
                "schema_version": SCHEMA_VERSION,
                "session_id": session_id.0,
                "generated_at": chrono::Utc::now().to_rfc3339(),
                "command": "signature stats",
                "filters": {
                    "min_matches": min_matches,
                    "sort_by": sort_by,
                },
                "stats": stats_json,
                "count": stat_entries.len(),
            });
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
        }
        _ => {
            if stat_entries.is_empty() {
                println!("No signature statistics available.");
                if min_matches > 0 {
                    println!("  (filtered by min_matches={})", min_matches);
                }
            } else {
                println!("# Signature Statistics ({} patterns)", stat_entries.len());
                println!();
                println!(
                    "{:30} {:>8} {:>8} {:>8} {:>8}",
                    "NAME", "MATCHES", "ACCEPTS", "REJECTS", "RATE"
                );
                println!("{}", "-".repeat(66));

                for (name, s) in &stat_entries {
                    let rate: String = s
                        .acceptance_rate()
                        .map(|r| format!("{:.1}%", r * 100.0))
                        .unwrap_or_else(|| "-".to_string());

                    // Truncate name if too long
                    let display_name: String = if name.len() > 30 {
                        format!("{}...", &name[..27])
                    } else {
                        name.to_string()
                    };

                    println!(
                        "{:30} {:>8} {:>8} {:>8} {:>8}",
                        display_name, s.match_count, s.accept_count, s.reject_count, rate
                    );
                }
            }
        }
    }

    ExitCode::Clean
}
