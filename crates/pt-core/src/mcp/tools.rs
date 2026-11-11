//! MCP tool implementations.
//!
//! Tools expose scanning, planning, explanations and explicit human feedback.

use crate::collect::protected::{ProtectedFilter, ProtectedMatch};
#[cfg(target_os = "linux")]
use crate::collect::{deep_scan, DeepScanOptions, DeepScanRecord};
use crate::collect::{quick_scan, ProcessActivity, ProcessRecord, QuickScanOptions, ScanResult};
use crate::mcp::protocol::{ToolContent, ToolDefinition};
use crate::scoring::{ProcessScore, Scorer};
use crate::signature_cli::load_user_signatures;
use crate::supervision::signature::ProcessMatchContext;
use crate::supervision::{SignatureDatabase, SupervisorCategory};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

const DEFAULT_ACTIVITY_WINDOW_MS: u64 = 500;
const MAX_ACTIVITY_WINDOW_MS: u64 = 60_000;

fn activity_window_ms(params: &serde_json::Value) -> Result<u64, String> {
    match params.get("window_ms") {
        None => Ok(DEFAULT_ACTIVITY_WINDOW_MS),
        Some(value) => value
            .as_u64()
            .filter(|window| *window <= MAX_ACTIVITY_WINDOW_MS)
            .ok_or_else(|| {
                format!("window_ms must be an integer between 0 and {MAX_ACTIVITY_WINDOW_MS}")
            }),
    }
}

fn activity_window_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "integer",
        "description": "CPU and storage I/O sampling window in milliseconds; 0 uses lifetime CPU from the quick snapshot and leaves I/O activity unknown",
        "default": DEFAULT_ACTIVITY_WINDOW_MS,
        "minimum": 0,
        "maximum": MAX_ACTIVITY_WINDOW_MS,
    })
}

/// An unavailable sample is unknown, not a substitute for lifetime CPU. Only
/// explicit snapshot mode (window_ms = 0) retains the legacy CPU observation.
fn reported_cpu_percent(
    process: &ProcessRecord,
    activity: Option<&ProcessActivity>,
) -> Option<f64> {
    match activity {
        Some(activity) => activity.cpu_percent,
        None => Some(process.cpu_percent),
    }
}

/// The config directory `agent plan` uses (`--config` / `PT_CONFIG_DIR`, then
/// `PROCESS_TRIAGE_CONFIG`, then the XDG default).
fn config_dir() -> PathBuf {
    crate::config::resolve_config_dir(&crate::mcp::config_options())
        .unwrap_or_else(|_| PathBuf::from("."))
}

/// What the MCP tools score against: the scorer and protection rules `agent plan`
/// uses (priors, learned verdicts, signatures, desktop-app ownership, provenance).
struct Evaluator {
    scorer: Scorer,
    protected_filter: ProtectedFilter,
    /// Protection resolved against the complete scan, including ancestors.
    protected: HashMap<u32, ProtectedMatch>,
    /// `agent plan`'s default age floor for candidates.
    min_age_seconds: u64,
    /// Optional evidence joined to the quick scan by process incarnation.
    #[cfg(target_os = "linux")]
    deep_records: HashMap<u32, DeepScanRecord>,
}

impl Evaluator {
    fn load() -> Result<Self, String> {
        let config = crate::config::load_config(&crate::mcp::config_options())
            .map_err(|error| format!("failed to load config: {error}"))?;
        let protected_filter = ProtectedFilter::from_guardrails(&config.policy.guardrails)
            .map_err(|error| format!("failed to load protection rules: {error}"))?;
        Ok(Self {
            protected_filter,
            protected: HashMap::new(),
            min_age_seconds: config.policy.guardrails.min_process_age_seconds,
            scorer: Scorer::from_config(&config).0,
            #[cfg(target_os = "linux")]
            deep_records: HashMap::new(),
        })
    }

    /// Collect provenance as `agent plan` does: for the unprotected processes old
    /// enough to be candidates, plus `extra` (processes asked about explicitly).
    fn collect_provenance(&mut self, scan: &ScanResult, extra: &[&ProcessRecord]) {
        #[cfg(target_os = "linux")]
        self.deep_records.clear();
        // A per-process check misses the calling shell/agent and workers whose
        // service ownership is only visible through their ancestors. Use the same
        // full-scan filter as `agent plan`, before age/score filtering hides parents.
        self.protected = self
            .protected_filter
            .filter_scan_result(scan)
            .filtered
            .into_iter()
            .map(|protection| (protection.pid, protection))
            .collect();
        let mut set = self.eligible_processes(scan);
        for process in extra {
            if !set.iter().any(|p| p.pid == process.pid) {
                set.push(process);
            }
        }
        self.scorer.collect_provenance(&set);
    }

    fn eligible_processes<'a>(&self, scan: &'a ScanResult) -> Vec<&'a ProcessRecord> {
        scan.processes
            .iter()
            .filter(|process| {
                process.elapsed.as_secs() >= self.min_age_seconds
                    && !self.protected.contains_key(&process.pid.0)
            })
            .collect()
    }

    /// Collect across the full census, so age/protection filters cannot hide a
    /// duplicate's newer peer or lock holder. Call after activity sampling.
    fn collect_workloads(&mut self, scan: &ScanResult) -> serde_json::Value {
        let mut workloads = crate::collect::duplicates::collect_duplicate_work(&scan.processes);
        if !scan.metadata.warnings.is_empty() {
            workloads.mark_census_incomplete();
        }
        let output = serde_json::json!(&workloads);
        self.scorer.set_workload_snapshot(workloads);
        output
    }

    fn collect_deep_evidence(&mut self, scan: &ScanResult) -> serde_json::Value {
        #[cfg(target_os = "linux")]
        {
            self.deep_records.clear();
            let eligible = self.eligible_processes(scan);
            // An empty PID selection means "all processes" to deep_scan.
            if eligible.is_empty() {
                return serde_json::json!({
                    "requested": true,
                    "status": "no_eligible_processes",
                    "requested_processes": 0,
                    "matched_processes": 0,
                    "duration_ms": 0,
                });
            }
            let options = DeepScanOptions {
                pids: eligible.iter().map(|process| process.pid.0).collect(),
                ..Default::default()
            };
            let result = match deep_scan(&options) {
                Ok(result) => result,
                Err(error) => {
                    return serde_json::json!({
                        "requested": true,
                        "status": "unavailable",
                        "requested_processes": eligible.len(),
                        "matched_processes": 0,
                        "error": error.to_string(),
                    });
                }
            };
            let (mut records, identity_mismatches) =
                match_deep_records(&eligible, result.processes);
            // The deep collector reads stat before its optional probes. Recheck
            // after those reads so PID reuse during collection cannot attach a
            // replacement process's socket or I/O facts to the original row.
            use crate::action::{IdentityProvider, LiveIdentityProvider};
            let identity_provider = LiveIdentityProvider::new();
            let joined_count = records.len();
            records.retain(|_, record| {
                matches!(
                    identity_provider.revalidate(&record.to_identity()),
                    Ok(true)
                )
            });
            let identity_revalidation_failed = joined_count - records.len();
            self.deep_records = records;
            serde_json::json!({
                "requested": true,
                "status": if self.deep_records.len() == eligible.len() { "collected" } else { "partial" },
                "requested_processes": eligible.len(),
                "matched_processes": self.deep_records.len(),
                "identity_mismatches": identity_mismatches,
                "identity_revalidation_failed": identity_revalidation_failed,
                "skipped_processes": result.metadata.skipped_count,
                "started_at": result.metadata.started_at,
                "duration_ms": result.metadata.duration_ms,
                "warnings": result.metadata.warnings,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = scan;
            serde_json::json!({
                "requested": true,
                "status": "unsupported",
                "matched_processes": 0,
                "reason": "Deep probes are only available on Linux; quick-scan evidence is retained",
            })
        }
    }

    fn evidence(&self, process: &ProcessRecord) -> crate::inference::Evidence {
        let evidence = crate::inference::Evidence::from_snapshot(process);
        #[cfg(target_os = "linux")]
        let evidence = crate::inference::Evidence {
            net: self
                .deep_records
                .get(&process.pid.0)
                .and_then(deep_socket_presence),
            // /proc/PID/io is cumulative. A single deep scan cannot establish
            // current I/O activity or a queue service rate.
            ..evidence
        };
        evidence
    }

    fn deep_evidence(&self, process: &ProcessRecord) -> serde_json::Value {
        #[cfg(target_os = "linux")]
        {
            self.deep_records
                .get(&process.pid.0)
                .map(|record| {
                    serde_json::json!({
                        "start_id": record.start_id,
                        "source": record.source,
                        "has_network_sockets": deep_socket_presence(record),
                        "network": record.network.as_ref().map(|network| serde_json::json!({
                            "socket_counts": network.socket_counts,
                            "listening_ports": network.listen_ports,
                            "rx_queue_bytes": network.total_rx_queue(),
                            "tx_queue_bytes": network.total_tx_queue(),
                        })),
                        "io_counters": record.io,
                        "io_activity": self
                            .scorer
                            .activity_for(process)
                            .and_then(|activity| activity.io_active),
                        "fd_count": record.fd.as_ref().map(|fd| fd.count),
                        "fd_inspection_truncated": record.fd.as_ref().map(|fd| fd.truncated),
                        "wchan": record.wchan,
                    })
                })
                .unwrap_or(serde_json::Value::Null)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = process;
            serde_json::Value::Null
        }
    }

    /// The process's score, as `agent plan` computes it (None if the model cannot
    /// evaluate it).
    fn score(&self, process: &ProcessRecord) -> Option<ProcessScore<'_>> {
        self.scorer.score(process, self.evidence(process))
    }

    /// Posterior class probabilities (None if the model cannot evaluate it).
    fn posterior(&self, process: &ProcessRecord) -> Option<crate::inference::ClassScores> {
        self.score(process).map(|s| s.posterior.posterior)
    }

    /// `{rule, notes}` if `agent plan` would skip this process as protected.
    fn protection(&self, process: &ProcessRecord) -> serde_json::Value {
        match self.protected.get(&process.pid.0) {
            Some(m) => serde_json::json!({ "rule": m.pattern, "notes": m.notes }),
            None => serde_json::Value::Null,
        }
    }
}

#[cfg(target_os = "linux")]
fn match_deep_records(
    processes: &[&ProcessRecord],
    records: Vec<DeepScanRecord>,
) -> (HashMap<u32, DeepScanRecord>, usize) {
    let identities: HashMap<u32, pt_common::ProcessIdentity> = processes
        .iter()
        .map(|process| {
            (
                process.pid.0,
                pt_common::ProcessIdentity::new(
                    process.pid.0,
                    process.start_id.clone(),
                    process.uid,
                ),
            )
        })
        .collect();
    let mut matched = HashMap::new();
    let mut identity_mismatches = 0;
    for record in records {
        if record.can_automate()
            && identities
                .get(&record.pid.0)
                .is_some_and(|identity| identity.matches(&record.to_identity()))
        {
            matched.insert(record.pid.0, record);
        } else {
            identity_mismatches += 1;
        }
    }
    (matched, identity_mismatches)
}

/// Socket presence is evidence of a network resource, not measured traffic.
/// Empty socket/FD tables cannot prove absence in another namespace or when
/// descriptor iteration was incomplete. The collector does not yet preserve
/// every directory-read error, so only positive observations affect inference.
#[cfg(target_os = "linux")]
fn deep_socket_presence(record: &DeepScanRecord) -> Option<bool> {
    if record.network.as_ref().is_some_and(|network| {
        let counts = &network.socket_counts;
        [
            counts.tcp,
            counts.tcp6,
            counts.udp,
            counts.udp6,
            counts.unix,
            counts.raw,
        ]
        .iter()
        .any(|count| *count > 0)
            || !network.listen_ports.is_empty()
            || !network.tcp_connections.is_empty()
            || !network.udp_sockets.is_empty()
            || !network.unix_sockets.is_empty()
    }) {
        return Some(true);
    }
    record.fd.as_ref().filter(|fd| fd.sockets > 0).map(|_| true)
}

fn top_signature(process: &ProcessRecord, db: &SignatureDatabase) -> Option<String> {
    let ctx = ProcessMatchContext {
        comm: &process.comm,
        cmdline: Some(process.cmd.as_str()),
        cwd: None,
        env_vars: None,
        socket_paths: None,
        parent_comm: None,
    };
    db.match_process(&ctx)
        .first()
        .map(|m| m.signature.name.clone())
}

/// Arguments for `pt-core agent plan` derived from `pt_plan` tool params.
fn plan_command_args(params: &serde_json::Value) -> Result<Vec<String>, String> {
    let window_ms = activity_window_ms(params)?;
    let mut args = vec![
        "agent".to_string(),
        "plan".to_string(),
        "--format".to_string(),
        "json".to_string(),
        "--window-ms".to_string(),
        window_ms.to_string(),
    ];
    if params
        .get("deep")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        args.push("--deep".to_string());
    }
    if let Some(min) = params.get("min_score").and_then(|v| v.as_f64()) {
        args.push("--min-posterior".to_string());
        args.push(min.clamp(0.0, 1.0).to_string());
    }
    if let Some(min_age) = params.get("min_age").and_then(|v| v.as_u64()) {
        args.push("--min-age".to_string());
        args.push(min_age.to_string());
    }
    Ok(args)
}

/// Translate an explicit human verdict to the existing learning command. The
/// confirmation is separate from the verdict so a model's recommendation cannot
/// silently become its own training label.
fn label_command_args(params: &serde_json::Value) -> Result<Vec<String>, String> {
    let object = params
        .as_object()
        .ok_or_else(|| "pt_label arguments must be an object".to_string())?;
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "pid" | "cmd" | "comm" | "verdict" | "confirmed_by_user"
        ) {
            return Err(format!("unknown pt_label argument: {key}"));
        }
    }
    if params.get("confirmed_by_user").and_then(|v| v.as_bool()) != Some(true) {
        return Err("pt_label requires confirmed_by_user=true for an explicit human verdict; do not label model recommendations automatically".to_string());
    }
    let verdict = match params.get("verdict").and_then(|v| v.as_str()) {
        Some("kill") => "--kill",
        Some("spare") => "--spare",
        _ => return Err("verdict must be kill or spare".to_string()),
    };
    let mut args = vec![
        "agent".to_string(),
        "label".to_string(),
        "--format".to_string(),
        "json".to_string(),
    ];
    match (params.get("pid"), params.get("cmd")) {
        (Some(value), None) => {
            if params.get("comm").is_some() {
                return Err("comm is only valid with cmd".to_string());
            }
            let pid = value
                .as_u64()
                .and_then(|pid| u32::try_from(pid).ok())
                .filter(|pid| *pid > 0)
                .ok_or_else(|| "pid must be an integer between 1 and 4294967295".to_string())?;
            args.extend(["--pid".to_string(), pid.to_string()]);
        }
        (None, Some(value)) => {
            let cmd = value
                .as_str()
                .filter(|cmd| !cmd.trim().is_empty() && !cmd.contains('\0'))
                .ok_or_else(|| "cmd must be a nonempty string without NUL bytes".to_string())?;
            // An equals argument keeps leading dashes and shell syntax as data.
            args.push(format!("--cmd={cmd}"));
            if let Some(value) = params.get("comm") {
                let comm = value
                    .as_str()
                    .filter(|comm| !comm.trim().is_empty() && !comm.contains('\0'))
                    .ok_or_else(|| {
                        "comm must be a nonempty string without NUL bytes".to_string()
                    })?;
                args.push(format!("--comm={comm}"));
            }
        }
        _ => return Err("pt_label requires exactly one of pid or cmd".to_string()),
    }
    args.push(verdict.to_string());
    Ok(args)
}

/// Build the list of available MCP tool definitions.
pub fn tool_definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "pt_scan".to_string(),
            description: "Run a process scan and return candidates with scores. \
                          Returns a JSON array of process records with evidence."
                .to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "deep": {
                        "type": "boolean",
                        "description": "Add Linux /proc probes for eligible unprotected processes, preserving quick-scan identity, age, CPU and TTY; reports missing evidence explicitly",
                        "default": false
                    },
                    "min_score": {
                        "type": "number",
                        "description": "Minimum score threshold to include (0.0-1.0)",
                        "default": 0.0,
                        "minimum": 0.0,
                        "maximum": 1.0
                    },
                    "min_age": {
                        "type": "integer",
                        "description": "Minimum process age in seconds (default: policy guardrail, 1 hour, as for pt_plan; 0 returns every process)",
                        "minimum": 0
                    },
                    "window_ms": activity_window_schema()
                },
                "required": [],
                "additionalProperties": false
            }),
        },
        ToolDefinition {
            name: "pt_explain".to_string(),
            description: "Explain a specific process — why it was flagged and its evidence chain."
                .to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "pid": {
                        "type": "integer",
                        "description": "Process ID to explain"
                    },
                    "comm": {
                        "type": "string",
                        "description": "Process name (comm) to explain (alternative to pid)"
                    },
                    "window_ms": activity_window_schema()
                },
                "required": [],
                "additionalProperties": false
            }),
        },
        ToolDefinition {
            name: "pt_history".to_string(),
            description: "Get recent session history with summaries.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Max sessions to return (default: 10)",
                        "default": 10
                    }
                },
                "required": [],
                "additionalProperties": false
            }),
        },
        ToolDefinition {
            name: "pt_plan".to_string(),
            description: "Generate a triage plan with the same engine, protections and \
                 output as `pt agent plan --format json`."
                .to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "deep": {
                        "type": "boolean",
                        "description": "Enable deep probes",
                        "default": false
                    },
                    "min_score": {
                        "type": "number",
                        "description": "Minimum P(intervention warranted) in [0,1] (agent plan --min-posterior)"
                    },
                    "min_age": {
                        "type": "integer",
                        "description": "Minimum process age in seconds (default: policy guardrail, 1 hour)"
                    },
                    "window_ms": activity_window_schema()
                },
                "required": [],
                "additionalProperties": false
            }),
        },
        ToolDefinition {
            name: "pt_label".to_string(),
            description: "Record an explicitly user-confirmed kill/spare verdict using \
                          the same durable learning and shadow-label path as pt agent label. \
                          Updates future recommendations; never signals a process. \
                          Do not record model recommendations or accepted defaults as human verdicts. \
                          Each successful call adds one observation; do not retry a successful call."
                .to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "pid": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": u32::MAX,
                        "description": "Live process to label; records an identity-bound shadow verdict"
                    },
                    "cmd": {
                        "type": "string",
                        "minLength": 1,
                        "description": "Command pattern to label instead of pid; does not invent a shadow process identity"
                    },
                    "comm": {
                        "type": "string",
                        "minLength": 1,
                        "description": "Process name for cmd; defaults to the basename of the first command word"
                    },
                    "verdict": {
                        "type": "string",
                        "enum": ["kill", "spare"],
                        "description": "The human's explicit verdict; kill is a label and does not terminate anything"
                    },
                    "confirmed_by_user": {
                        "type": "boolean",
                        "const": true,
                        "description": "Must be true only after the user explicitly chose this verdict"
                    }
                },
                "required": ["verdict", "confirmed_by_user"],
                "oneOf": [
                    {
                        "required": ["pid"],
                        "not": {"anyOf": [{"required": ["cmd"]}, {"required": ["comm"]}]}
                    },
                    {
                        "required": ["cmd"],
                        "not": {"required": ["pid"]}
                    }
                ],
                "additionalProperties": false
            }),
        },
        ToolDefinition {
            name: "pt_signatures".to_string(),
            description: "List available process signatures (built-in and user-defined)."
                .to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "user_only": {
                        "type": "boolean",
                        "description": "Only show user-defined signatures",
                        "default": false
                    },
                    "category": {
                        "type": "string",
                        "description": "Filter by category: agent, ide, ci, orchestrator, terminal, other",
                        "enum": ["agent", "ide", "ci", "orchestrator", "terminal", "other"]
                    }
                },
                "required": [],
                "additionalProperties": false
            }),
        },
        ToolDefinition {
            name: "pt_capabilities".to_string(),
            description: "List available platform capabilities and probes.".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {},
                "required": [],
                "additionalProperties": false
            }),
        },
    ]
}

/// Dispatch a tool call by name and return content blocks.
pub fn call_tool(name: &str, params: &serde_json::Value) -> Result<Vec<ToolContent>, String> {
    match name {
        "pt_scan" => tool_scan(params),
        "pt_explain" => tool_explain(params),
        "pt_plan" => tool_plan(params),
        "pt_label" => tool_label(params),
        "pt_history" => tool_history(params),
        "pt_signatures" => tool_signatures(params),
        "pt_capabilities" => tool_capabilities(params),
        _ => Err(format!("Unknown tool: {}", name)),
    }
}

fn tool_scan(params: &serde_json::Value) -> Result<Vec<ToolContent>, String> {
    let window_ms = activity_window_ms(params)?;
    let deep = params
        .get("deep")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let min_score = params
        .get("min_score")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let mut evaluator = Evaluator::load()?;
    let scan_started = std::time::Instant::now();
    let scan_result = quick_scan(&QuickScanOptions::default())
        .map_err(|error| format!("Scan failed: {error}"))?;
    // `agent plan`'s age floor: a process younger than this is never a candidate, so
    // scoring it would only invite acting on a busy new process.
    if let Some(min_age) = params.get("min_age").and_then(|v| v.as_u64()) {
        evaluator.min_age_seconds = min_age;
    }
    evaluator.collect_provenance(&scan_result, &[]);
    let deep_scan = if deep {
        evaluator.collect_deep_evidence(&scan_result)
    } else {
        serde_json::json!({"requested": false, "status": "not_requested"})
    };
    let eligible = evaluator.eligible_processes(&scan_result);
    evaluator
        .scorer
        .collect_activity(&eligible, Duration::from_millis(window_ms));
    let workloads = evaluator.collect_workloads(&scan_result);

    // Score = P(abandoned or zombie) from the same posterior `agent plan` uses (it was
    // a signature-match score plus a state bonus, not a probability).
    let mut candidates = Vec::new();
    let mut younger_than_min_age = 0usize;
    for p in &scan_result.processes {
        if p.elapsed.as_secs() < evaluator.min_age_seconds {
            younger_than_min_age += 1;
            continue;
        }
        let Some(posterior) = evaluator.posterior(p) else {
            continue;
        };
        let score = posterior.abandonment_probability();
        if score >= min_score {
            let protected = evaluator.protection(p);
            candidates.push((
                p,
                score,
                posterior,
                protected,
                top_signature(p, &evaluator.scorer.signatures),
            ));
        }
    }

    // Unprotected first (protected ones are never acted on), then by score.
    candidates.sort_by(|a, b| {
        a.3.is_null()
            .cmp(&b.3.is_null())
            .reverse()
            .then(b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal))
    });
    let matching_processes = candidates.len();
    candidates.truncate(200);

    let result = serde_json::json!({
        "scanned_at": scan_result.metadata.started_at,
        "duration_ms": scan_started.elapsed().as_millis(),
        "quick_scan_duration_ms": scan_result.metadata.duration_ms,
        "platform": scan_result.metadata.platform,
        "warnings": scan_result.metadata.warnings,
        "deep_scan": deep_scan,
        "workloads": workloads,
        "window_ms": window_ms,
        "total_processes": scan_result.processes.len(),
        "min_age_seconds": evaluator.min_age_seconds,
        "younger_than_min_age": younger_than_min_age,
        "returned": candidates.len(),
        "matching_processes": matching_processes,
        "truncated": matching_processes > candidates.len(),
        "score_definition": "P(abandoned or zombie) from pt's posterior (0-1); suspicion_score = 100 x score",
        "processes": candidates.iter().map(|(p, score, posterior, protected, top_signature)| {
            let activity = evaluator.scorer.activity_for(p);
            serde_json::json!({
                "pid": p.pid.0,
                "ppid": p.ppid.0,
                "comm": p.comm,
                "cmd": p.cmd,
                "state": format!("{}", p.state),
                "uid": p.uid,
                "user": p.user,
                "start_id": p.start_id,
                "start_time_unix": p.start_time_unix,
                "cpu_pct": reported_cpu_percent(p, activity.as_ref()),
                "cpu_lifetime_pct": p.cpu_percent,
                "io_activity": activity.as_ref().and_then(|sample| sample.io_active),
                "activity": activity,
                "rss_bytes": p.rss_bytes,
                "vsz_bytes": p.vsz_bytes,
                "elapsed_sec": p.elapsed.as_secs(),
                "tty": p.tty,
                "deep_evidence": evaluator.deep_evidence(p),
                "work": evaluator.scorer.workload_diagnosis_for(p),
                "score": score,
                "suspicion_score": posterior.suspicion_score(),
                "posterior": posterior,
                "protected": protected,
                "top_signature": top_signature,
            })
        }).collect::<Vec<_>>(),
    });

    Ok(vec![ToolContent {
        content_type: "text".to_string(),
        text: serde_json::to_string_pretty(&result)
            .map_err(|e| format!("Serialization error: {}", e))?,
    }])
}

fn tool_explain(params: &serde_json::Value) -> Result<Vec<ToolContent>, String> {
    let window_ms = activity_window_ms(params)?;
    let pid = params.get("pid").and_then(|v| v.as_u64()).map(|v| v as u32);
    let comm = params.get("comm").and_then(|v| v.as_str());

    if pid.is_none() && comm.is_none() {
        return Err("Either 'pid' or 'comm' must be provided".to_string());
    }

    let mut evaluator = Evaluator::load()?;
    // Run a quick scan to find the process
    let options = QuickScanOptions::default();
    let scan = quick_scan(&options).map_err(|e| format!("Scan failed: {}", e))?;

    let process = scan.processes.iter().find(|p| {
        if let Some(target_pid) = pid {
            p.pid.0 == target_pid
        } else if let Some(target_comm) = comm {
            p.comm == target_comm
        } else {
            false
        }
    });

    match process {
        Some(p) => {
            // Build signature match context
            let ctx = ProcessMatchContext {
                comm: &p.comm,
                cmdline: Some(p.cmd.as_str()),
                cwd: None,
                env_vars: None,
                socket_paths: None,
                parent_comm: None,
            };

            // The same score and protection rules `agent plan` uses.
            evaluator.collect_provenance(&scan, &[p]);
            evaluator
                .scorer
                .collect_activity(&[p], Duration::from_millis(window_ms));
            let workloads = evaluator.collect_workloads(&scan);
            let activity = evaluator.scorer.activity_for(p);
            let matches = evaluator.scorer.signatures.match_process(&ctx);
            let score = evaluator.score(p);
            let evidence_terms: Vec<serde_json::Value> = score
                .as_ref()
                .map(|s| {
                    s.posterior
                        .evidence_terms
                        .iter()
                        .map(|t| {
                            serde_json::json!({
                                "feature": t.feature,
                                "log_likelihood": t.log_likelihood,
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            let prior_source = score.as_ref().map(|s| s.prior_source.clone());
            let learned_prior = score.as_ref().and_then(|s| s.learned_prior.clone());
            let desktop_app = score.as_ref().and_then(|s| s.desktop_app.clone());
            let desktop_app_credited = score.as_ref().is_some_and(|s| s.desktop_app_credited);
            let posterior = score.map(|s| s.posterior.posterior);

            let result = serde_json::json!({
                "pid": p.pid.0,
                "ppid": p.ppid.0,
                "comm": p.comm,
                "cmd": p.cmd,
                "state": format!("{}", p.state),
                "uid": p.uid,
                "user": p.user,
                "start_id": p.start_id,
                "start_time_unix": p.start_time_unix,
                "window_ms": window_ms,
                "cpu_pct": reported_cpu_percent(p, activity.as_ref()),
                "cpu_lifetime_pct": p.cpu_percent,
                "io_activity": activity.as_ref().and_then(|sample| sample.io_active),
                "activity": activity,
                "rss_bytes": p.rss_bytes,
                "vsz_bytes": p.vsz_bytes,
                "elapsed_sec": p.elapsed.as_secs(),
                "signature_matches": matches.iter().map(|m| {
                    serde_json::json!({
                        "name": m.signature.name,
                        "category": format!("{:?}", m.signature.category),
                        "score": m.score,
                    })
                }).collect::<Vec<_>>(),
                "posterior": posterior,
                "score": posterior.map(|s| s.abandonment_probability()),
                "suspicion_score": posterior.map(|s| s.suspicion_score()),
                "protected": evaluator.protection(p),
                "prior_source": prior_source,
                "learned_prior": learned_prior,
                "desktop_app": desktop_app,
                "desktop_app_credited": desktop_app_credited,
                "work": evaluator.scorer.workload_diagnosis_for(p),
                "workloads": workloads,
                "evidence": evidence_terms,
            });

            Ok(vec![ToolContent {
                content_type: "text".to_string(),
                text: serde_json::to_string_pretty(&result)
                    .map_err(|e| format!("Serialization error: {}", e))?,
            }])
        }
        None => {
            let target = if let Some(p) = pid {
                format!("PID {}", p)
            } else {
                format!("comm '{}'", comm.unwrap_or("?"))
            };
            Ok(vec![ToolContent {
                content_type: "text".to_string(),
                text: format!("Process {} not found in current scan.", target),
            }])
        }
    }
}

/// `pt_plan`: run the real planning engine (`pt-core agent plan`), not a second
/// heuristic. The previous MCP-only scorer ignored protection, the posterior and the
/// loss matrix, and recommended `kill` for zombies (which a signal cannot reap).
fn tool_plan(params: &serde_json::Value) -> Result<Vec<ToolContent>, String> {
    let args = plan_command_args(params)?;
    let exe = std::env::current_exe().map_err(|e| format!("cannot locate pt-core: {e}"))?;
    let output = std::process::Command::new(&exe)
        .arg("--config")
        .arg(config_dir())
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("failed to run `{} agent plan`: {e}", exe.display()))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    // agent plan exits 0 (nothing to do) or 1 (plan ready); anything else is an error.
    let ok = matches!(output.status.code(), Some(0) | Some(1));
    if !ok || serde_json::from_str::<serde_json::Value>(&stdout).is_err() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let tail: String = stderr.lines().rev().take(5).collect::<Vec<_>>().join("\n");
        return Err(format!(
            "agent plan failed (exit {:?}): {tail}",
            output.status.code()
        ));
    }
    Ok(vec![ToolContent {
        content_type: "text".to_string(),
        text: stdout,
    }])
}

/// Persist through the shipped CLI so MCP uses the same locking, decay,
/// generalization rules and identity-bound shadow events as explicit CLI labels.
fn tool_label(params: &serde_json::Value) -> Result<Vec<ToolContent>, String> {
    let args = label_command_args(params)?;
    let config = crate::config::resolve_config_dir(&crate::mcp::config_options())
        .map_err(|error| format!("cannot resolve label config directory: {error}"))?;
    let exe = std::env::current_exe().map_err(|e| format!("cannot locate pt-core: {e}"))?;
    let output = std::process::Command::new(&exe)
        .arg("--config")
        .arg(config)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("failed to run agent label: {e}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    if !output.status.success() || serde_json::from_str::<serde_json::Value>(&stdout).is_err() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let tail = stderr
            .lines()
            .rev()
            .take(5)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("\n");
        return Err(format!(
            "agent label failed (exit {:?}): {tail}",
            output.status.code()
        ));
    }
    Ok(vec![ToolContent {
        content_type: "text".to_string(),
        text: stdout,
    }])
}

fn tool_history(params: &serde_json::Value) -> Result<Vec<ToolContent>, String> {
    let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(10) as usize;

    let store = crate::session::SessionStore::from_env()
        .map_err(|e| format!("Session store error: {}", e))?;

    let sessions_root = store.sessions_root();
    let mut entries = Vec::new();

    if sessions_root.exists() {
        if let Ok(dir) = std::fs::read_dir(sessions_root) {
            let mut session_dirs: Vec<_> = dir
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
                .collect();
            session_dirs.sort_by(|a, b| {
                let ta = a.metadata().and_then(|m| m.modified()).ok();
                let tb = b.metadata().and_then(|m| m.modified()).ok();
                tb.cmp(&ta)
            });

            for entry in session_dirs.into_iter().take(limit) {
                let name = entry.file_name().to_string_lossy().to_string();
                let modified = entry
                    .metadata()
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .map(|t| chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339());

                entries.push(serde_json::json!({
                    "session_id": name,
                    "modified": modified,
                }));
            }
        }
    }

    let result = serde_json::json!({
        "sessions_dir": sessions_root.display().to_string(),
        "count": entries.len(),
        "sessions": entries,
    });

    Ok(vec![ToolContent {
        content_type: "text".to_string(),
        text: serde_json::to_string_pretty(&result)
            .map_err(|e| format!("Serialization error: {}", e))?,
    }])
}

fn tool_signatures(params: &serde_json::Value) -> Result<Vec<ToolContent>, String> {
    let user_only = params
        .get("user_only")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let category_filter = parse_signature_category_filter(params)?;

    let mut all_sigs = Vec::new();

    if !user_only {
        let mut db = SignatureDatabase::new();
        db.add_default_signatures();
        for sig in db.signatures() {
            if let Some(parsed) = category_filter {
                if sig.category != parsed {
                    continue;
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

    if let Some(user_schema) = load_user_signatures(&config_dir()) {
        for sig in &user_schema.signatures {
            if let Some(parsed) = category_filter {
                if sig.category != parsed {
                    continue;
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

    let result = serde_json::json!({
        "count": all_sigs.len(),
        "signatures": all_sigs,
    });

    Ok(vec![ToolContent {
        content_type: "text".to_string(),
        text: serde_json::to_string_pretty(&result)
            .map_err(|e| format!("Serialization error: {}", e))?,
    }])
}

fn parse_signature_category_filter(
    params: &serde_json::Value,
) -> Result<Option<SupervisorCategory>, String> {
    let Some(category) = params.get("category").and_then(|v| v.as_str()) else {
        return Ok(None);
    };

    crate::signature_cli::parse_category(category)
        .map(Some)
        .ok_or_else(|| {
            format!(
                "Invalid category '{}'. Valid categories: agent, ide, ci, orchestrator, terminal, other",
                category
            )
        })
}

fn tool_capabilities(_params: &serde_json::Value) -> Result<Vec<ToolContent>, String> {
    let caps = crate::capabilities::get_capabilities();

    // Capabilities derives Serialize, so serialize it directly
    let result = serde_json::to_value(&caps).map_err(|e| format!("Serialization error: {}", e))?;

    Ok(vec![ToolContent {
        content_type: "text".to_string(),
        text: serde_json::to_string_pretty(&result)
            .map_err(|e| format!("Serialization error: {}", e))?,
    }])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn protection_test_scan() -> ScanResult {
        const BASE: u32 = 1 << 22;
        let processes: Vec<ProcessRecord> = [
            (std::process::id(), BASE + 1, "pt-core"),
            (BASE + 1, BASE + 2, "bash"),
            (BASE + 2, 1, "cargo"),
            (BASE + 10, 1, "mattermost"),
            (BASE + 11, BASE + 10, "plugin-worker"),
            (BASE + 12, BASE + 11, "worker-child"),
            (BASE + 20, BASE + 21, "unrelated-worker"),
        ]
        .into_iter()
        .map(|(pid, ppid, comm)| ProcessRecord {
            pid: pt_common::ProcessId(pid),
            ppid: pt_common::ProcessId(ppid),
            uid: 1000,
            user: "test-user".to_string(),
            pgid: Some(pid),
            sid: Some(pid),
            start_id: pt_common::StartId::from_linux("test-boot", 1234567890, pid),
            comm: comm.to_string(),
            cmd: comm.to_string(),
            state: crate::collect::ProcessState::Sleeping,
            cpu_percent: 0.0,
            rss_bytes: 1024,
            vsz_bytes: 2048,
            tty: None,
            start_time_unix: 1234567890,
            elapsed: std::time::Duration::ZERO,
            source: "test".to_string(),
            container_info: None,
        })
        .collect();
        ScanResult {
            metadata: crate::collect::ScanMetadata {
                scan_type: "quick".to_string(),
                platform: std::env::consts::OS.to_string(),
                boot_id: None,
                started_at: "2026-10-06T12:00:00Z".to_string(),
                duration_ms: 0,
                process_count: processes.len(),
                warnings: Vec::new(),
            },
            processes,
        }
    }

    fn protection_test_evaluator(protected_filter: ProtectedFilter) -> Evaluator {
        Evaluator {
            scorer: Scorer::new(
                crate::config::Priors::default(),
                Default::default(),
                SignatureDatabase::new(),
                crate::scoring::fast_path_config(&crate::config::Policy::default()),
            ),
            protected_filter,
            protected: HashMap::new(),
            // Every record is below the age floor: ancestors must still protect
            // their descendants, without probing synthetic PIDs for provenance.
            min_age_seconds: 3600,
            #[cfg(target_os = "linux")]
            deep_records: HashMap::new(),
        }
    }

    #[cfg(target_os = "linux")]
    fn deep_test_record(process: &ProcessRecord) -> DeepScanRecord {
        DeepScanRecord {
            pid: process.pid,
            ppid: process.ppid,
            uid: process.uid,
            user: process.user.clone(),
            pgid: process.pgid,
            sid: process.sid,
            start_id: process.start_id.clone(),
            comm: process.comm.clone(),
            cmdline: process.cmd.clone(),
            exe: None,
            state: 'S',
            io: Some(crate::collect::IoStats {
                read_bytes: 1_000_000,
                write_bytes: 2_000_000,
                ..Default::default()
            }),
            schedstat: None,
            sched: None,
            mem: Some(crate::collect::MemStats {
                size: 1,
                resident: 1,
                ..Default::default()
            }),
            fd: None,
            local_resource_evidence: Vec::new(),
            gpu: None,
            cgroup: None,
            wchan: None,
            network: Some(crate::collect::NetworkInfo {
                socket_counts: crate::collect::SocketCounts {
                    tcp: 1,
                    ..Default::default()
                },
                ..Default::default()
            }),
            environ: None,
            starttime: 1234567890,
            source: "deep_scan".to_string(),
            identity_quality: pt_common::IdentityQuality::Full,
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn deep_evidence_preserves_quick_identity_runtime_cpu_and_tty() {
        let mut process = protection_test_scan().processes.pop().unwrap();
        process.elapsed = std::time::Duration::from_secs(7200);
        process.cpu_percent = 25.5;
        process.tty = Some("pts/7".to_string());
        process.rss_bytes = 123_456;
        process.vsz_bytes = 987_654;
        let original = serde_json::to_value(&process).unwrap();
        let (records, mismatches) =
            match_deep_records(&[&process], vec![deep_test_record(&process)]);
        assert_eq!(mismatches, 0);
        assert_eq!(records.len(), 1);
        let filter = ProtectedFilter::new(&[], &[], &[], &[]).unwrap();
        let mut evaluator = protection_test_evaluator(filter);
        evaluator.deep_records = records;

        let evidence = evaluator.evidence(&process);
        assert_eq!(evidence.runtime_seconds, Some(7200.0));
        assert_eq!(evidence.tty, Some(true));
        assert!(matches!(
            evidence.cpu,
            Some(crate::inference::CpuEvidence::Fraction { occupancy })
                if (occupancy - 0.255).abs() < 1e-12
        ));
        assert_eq!(evidence.net, Some(true));
        assert_eq!(
            evidence.io_active, None,
            "cumulative counters are not activity"
        );
        assert_eq!(evidence.queue_saturated, None, "no measured service rate");
        assert_eq!(serde_json::to_value(&process).unwrap(), original);

        let score = evaluator.score(&process).expect("score enriched process");
        assert!(score
            .posterior
            .evidence_terms
            .iter()
            .any(|term| term.feature == "net"));
        assert!(!score
            .posterior
            .evidence_terms
            .iter()
            .any(|term| term.feature == "io_active"));
        let deep = evaluator.deep_evidence(&process);
        assert_eq!(deep["start_id"], process.start_id.0);
        assert_eq!(deep["io_counters"]["read_bytes"], 1_000_000);
        assert!(deep["io_activity"].is_null());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn deep_records_reject_reused_pids_changed_owners_and_weak_identity() {
        let process = protection_test_scan().processes.pop().unwrap();
        for mismatch in ["pid", "start_id", "uid", "identity_quality"] {
            let mut record = deep_test_record(&process);
            match mismatch {
                "pid" => record.pid.0 += 1,
                "start_id" => {
                    record.start_id =
                        pt_common::StartId::from_linux("another-boot", 9, process.pid.0)
                }
                "uid" => record.uid += 1,
                "identity_quality" => record.identity_quality = pt_common::IdentityQuality::PidOnly,
                _ => unreachable!(),
            }
            let (records, mismatches) = match_deep_records(&[&process], vec![record]);
            assert!(records.is_empty(), "accepted mismatched {mismatch}");
            assert_eq!(mismatches, 1, "{mismatch}");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn deep_socket_absence_remains_unknown_without_collection_completeness() {
        let process = protection_test_scan().processes.pop().unwrap();
        let mut record = deep_test_record(&process);
        record.network = Some(crate::collect::NetworkInfo::default());
        assert_eq!(deep_socket_presence(&record), None);

        record.fd = Some(crate::collect::FdInfo {
            count: 2,
            by_type: HashMap::from([("file".to_string(), 1)]),
            ..Default::default()
        });
        assert_eq!(deep_socket_presence(&record), None);
        record
            .fd
            .as_mut()
            .unwrap()
            .by_type
            .insert("file".to_string(), 2);
        assert_eq!(deep_socket_presence(&record), None);
        record.fd.as_mut().unwrap().truncated = true;
        assert_eq!(deep_socket_presence(&record), None);
        record.fd.as_mut().unwrap().sockets = 1;
        assert_eq!(deep_socket_presence(&record), Some(true));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn deep_scan_does_not_expand_an_empty_eligible_set_into_all_pids() {
        let scan = protection_test_scan();
        let filter = ProtectedFilter::new(&[], &[], &[], &[]).unwrap();
        let mut evaluator = protection_test_evaluator(filter);
        evaluator.collect_provenance(&scan, &[]);
        let metadata = evaluator.collect_deep_evidence(&scan);
        assert_eq!(metadata["status"], "no_eligible_processes");
        assert_eq!(metadata["requested_processes"], 0);
        assert_eq!(metadata["matched_processes"], 0);
        assert!(evaluator.deep_records.is_empty());
    }

    #[test]
    fn evaluator_resolves_invoker_and_service_ancestors_before_age_filtering() {
        let mut scan = protection_test_scan();
        let filter = ProtectedFilter::new(&[], &[], &[], &[])
            .unwrap()
            .with_builtin_protection(true);
        let mut evaluator = protection_test_evaluator(filter);
        evaluator.collect_provenance(&scan, &[]);

        for process in &scan.processes[..3] {
            assert_eq!(
                evaluator.protection(process)["rule"],
                "builtin.invoker_chain",
                "caller {} lost its protection",
                process.pid.0
            );
        }
        for process in &scan.processes[4..6] {
            let protection = evaluator.protection(process);
            assert_eq!(protection["rule"], "builtin.service_child");
            assert!(protection["notes"].as_str().unwrap().contains("mattermost"));
        }
        assert!(evaluator.protection(&scan.processes[6]).is_null());

        // Protection belongs to this snapshot, not a previous occupant of a PID.
        scan.processes[4].ppid = scan.processes[6].ppid;
        evaluator.collect_provenance(&scan, &[]);
        assert!(evaluator.protection(&scan.processes[4]).is_null());
        assert!(evaluator.protection(&scan.processes[5]).is_null());
    }

    #[test]
    fn evaluator_honors_explicit_protection_when_builtin_rules_are_disabled() {
        let scan = protection_test_scan();
        let protected_pid = scan.processes[4].pid.0;
        let filter = ProtectedFilter::new(&[], &[], &[protected_pid], &[]).unwrap();
        let mut evaluator = protection_test_evaluator(filter);
        evaluator.collect_provenance(&scan, &[]);

        assert!(evaluator.protection(&scan.processes[0]).is_null());
        assert_eq!(
            evaluator.protection(&scan.processes[4])["rule"],
            format!("never_kill_pid[{protected_pid}]")
        );
        assert!(evaluator.protection(&scan.processes[5]).is_null());
    }

    #[test]
    fn tool_definitions_not_empty() {
        let defs = tool_definitions();
        assert!(!defs.is_empty());
    }

    #[test]
    fn tool_definitions_have_valid_schemas() {
        for def in tool_definitions() {
            assert!(!def.name.is_empty());
            assert!(!def.description.is_empty());
            assert_eq!(def.input_schema["type"], "object");
        }
    }

    #[test]
    fn tool_definitions_names_have_pt_prefix() {
        for def in tool_definitions() {
            assert!(
                def.name.starts_with("pt_"),
                "Tool '{}' missing pt_ prefix",
                def.name
            );
        }
    }

    #[test]
    fn call_unknown_tool_returns_error() {
        let result = call_tool("nonexistent", &serde_json::json!({}));
        assert!(result.is_err());
    }

    #[test]
    fn tool_explain_requires_pid_or_comm() {
        let result = call_tool("pt_explain", &serde_json::json!({}));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("pid"));
    }

    #[test]
    fn tool_signatures_returns_builtin() {
        let result = call_tool("pt_signatures", &serde_json::json!({})).unwrap();
        assert!(!result.is_empty());
        let parsed: serde_json::Value = serde_json::from_str(&result[0].text).unwrap();
        assert!(parsed["count"].as_u64().unwrap() > 0);
    }

    #[test]
    fn tool_capabilities_succeeds() {
        let result = call_tool("pt_capabilities", &serde_json::json!({})).unwrap();
        assert!(!result.is_empty());
    }

    #[test]
    fn tool_signatures_rejects_invalid_category() {
        let result = call_tool("pt_signatures", &serde_json::json!({"category": "bogus"}));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid category"));
    }

    #[test]
    fn tool_history_succeeds() {
        let result = call_tool("pt_history", &serde_json::json!({})).unwrap();
        assert!(!result.is_empty());
        let parsed: serde_json::Value = serde_json::from_str(&result[0].text).unwrap();
        assert!(parsed.get("sessions").is_some());
    }

    #[test]
    fn plan_tool_maps_params_to_agent_plan_args() {
        assert_eq!(
            plan_command_args(&serde_json::json!({})).unwrap(),
            ["agent", "plan", "--format", "json", "--window-ms", "500"]
        );
        assert_eq!(
            plan_command_args(&serde_json::json!({
                "deep": true,
                "min_score": 0.9,
                "min_age": 60,
                "window_ms": 250,
            }))
            .unwrap(),
            [
                "agent",
                "plan",
                "--format",
                "json",
                "--window-ms",
                "250",
                "--deep",
                "--min-posterior",
                "0.9",
                "--min-age",
                "60"
            ]
        );
        for window_ms in [0, MAX_ACTIVITY_WINDOW_MS] {
            let args = plan_command_args(&serde_json::json!({"window_ms": window_ms})).unwrap();
            assert_eq!(args[4], "--window-ms");
            assert_eq!(args[5], window_ms.to_string());
        }
        // Out-of-range scores are clamped into a valid posterior.
        let args = plan_command_args(&serde_json::json!({"min_score": 7.0})).unwrap();
        assert_eq!(args[args.len() - 1], "1");
    }

    #[test]
    fn activity_window_schema_matches_runtime_bounds_for_every_scoring_tool() {
        let definitions = tool_definitions();
        for name in ["pt_scan", "pt_explain", "pt_plan"] {
            let tool = definitions.iter().find(|tool| tool.name == name).unwrap();
            let window = &tool.input_schema["properties"]["window_ms"];
            assert_eq!(window["type"], "integer", "{name}");
            assert_eq!(window["default"], DEFAULT_ACTIVITY_WINDOW_MS, "{name}");
            assert_eq!(window["minimum"], 0, "{name}");
            assert_eq!(window["maximum"], MAX_ACTIVITY_WINDOW_MS, "{name}");
        }
        assert_eq!(
            activity_window_ms(&serde_json::json!({})).unwrap(),
            DEFAULT_ACTIVITY_WINDOW_MS
        );
        for window_ms in [0, 1, DEFAULT_ACTIVITY_WINDOW_MS, MAX_ACTIVITY_WINDOW_MS] {
            assert_eq!(
                activity_window_ms(&serde_json::json!({"window_ms": window_ms})).unwrap(),
                window_ms
            );
        }
    }

    #[test]
    fn scoring_tools_reject_invalid_sampling_windows_before_work() {
        for invalid in [
            serde_json::json!(-1),
            serde_json::json!(60_001),
            serde_json::json!(u64::MAX),
            serde_json::json!(0.5),
            serde_json::json!("500"),
            serde_json::Value::Null,
        ] {
            for name in ["pt_scan", "pt_explain", "pt_plan"] {
                let error = call_tool(name, &serde_json::json!({"pid": 1, "window_ms": invalid}))
                    .unwrap_err();
                assert!(error.contains("window_ms"), "{name}: {error}");
                assert!(error.contains("60000"), "{name}: {error}");
            }
        }
    }

    #[test]
    fn unavailable_activity_never_relabels_lifetime_cpu_as_current() {
        let mut process = protection_test_scan().processes.pop().unwrap();
        process.cpu_percent = 81.0;
        let filter = ProtectedFilter::new(&[], &[], &[], &[]).unwrap();
        let mut evaluator = protection_test_evaluator(filter);
        assert_eq!(reported_cpu_percent(&process, None), Some(81.0));

        // No procfs reads or sleep are needed: a subject outside the measured
        // set must carry unknown activity, including protected scan rows.
        evaluator
            .scorer
            .collect_activity(&[], Duration::from_millis(500));
        let mut activity = evaluator.scorer.activity_for(&process).unwrap();
        assert!(activity.cpu_percent.is_none());
        assert!(activity.io_active.is_none());
        assert!(activity.cpu_error.is_some());
        assert_eq!(reported_cpu_percent(&process, Some(&activity)), None);
        let score = evaluator
            .score(&process)
            .expect("unknown activity still scores");
        assert!(score.activity.as_ref().unwrap().cpu_percent.is_none());
        assert!(!score
            .posterior
            .evidence_terms
            .iter()
            .any(|term| term.feature == "cpu" || term.feature == "io_active"));

        activity.cpu_percent = Some(0.0);
        assert_eq!(reported_cpu_percent(&process, Some(&activity)), Some(0.0));
        activity.cpu_percent = Some(12.5);
        assert_eq!(reported_cpu_percent(&process, Some(&activity)), Some(12.5));
        assert_eq!(
            process.cpu_percent, 81.0,
            "lifetime observation is retained"
        );

        evaluator.scorer.collect_activity(&[], Duration::ZERO);
        assert!(evaluator.scorer.activity_for(&process).is_none());
        assert_eq!(reported_cpu_percent(&process, None), Some(81.0));
    }

    #[test]
    fn label_arguments_preserve_literal_commands_and_explicit_verdicts() {
        assert_eq!(
            label_command_args(&serde_json::json!({
                "pid": 123,
                "verdict": "spare",
                "confirmed_by_user": true,
            }))
            .unwrap(),
            ["agent", "label", "--format", "json", "--pid", "123", "--spare"]
        );
        let command = "--keep; $(touch /tmp/pt-label-must-not-execute) 'two words'";
        assert_eq!(
            label_command_args(&serde_json::json!({
                "cmd": command,
                "comm": "--literal",
                "verdict": "kill",
                "confirmed_by_user": true,
            }))
            .unwrap(),
            vec![
                "agent".to_string(),
                "label".to_string(),
                "--format".to_string(),
                "json".to_string(),
                format!("--cmd={command}"),
                "--comm=--literal".to_string(),
                "--kill".to_string(),
            ]
        );
    }

    #[test]
    fn label_rejects_unconfirmed_or_ambiguous_feedback_before_spawning() {
        for arguments in [
            serde_json::json!(null),
            serde_json::json!([]),
            serde_json::json!({"pid": 1, "verdict": "kill"}),
            serde_json::json!({"pid": 1, "verdict": "kill", "confirmed_by_user": false}),
            serde_json::json!({"pid": 1, "verdict": "kill", "confirmed_by_user": "true"}),
            serde_json::json!({"pid": 1, "verdict": "review", "confirmed_by_user": true}),
            serde_json::json!({"pid": 1, "verdict": null, "confirmed_by_user": true}),
            serde_json::json!({"pid": 1, "cmd": "sleep 1", "verdict": "kill", "confirmed_by_user": true}),
            serde_json::json!({"pid": 1, "comm": "sleep", "verdict": "kill", "confirmed_by_user": true}),
            serde_json::json!({"verdict": "spare", "confirmed_by_user": true}),
            serde_json::json!({"cmd": "", "verdict": "spare", "confirmed_by_user": true}),
            serde_json::json!({"cmd": " \t", "verdict": "spare", "confirmed_by_user": true}),
            serde_json::json!({"cmd": "sleep\0", "verdict": "spare", "confirmed_by_user": true}),
            serde_json::json!({"cmd": "sleep 1", "comm": "", "verdict": "spare", "confirmed_by_user": true}),
            serde_json::json!({"cmd": "sleep 1", "comm": null, "verdict": "spare", "confirmed_by_user": true}),
            serde_json::json!({"cmd": "sleep 1", "verdict": "spare", "confirmed_by_user": true, "apply": true}),
        ] {
            assert!(call_tool("pt_label", &arguments).is_err(), "{arguments}");
        }
        for pid in [
            serde_json::json!(0),
            serde_json::json!(-1),
            serde_json::json!(u64::MAX),
            serde_json::json!(0.5),
            serde_json::json!("123"),
            serde_json::Value::Null,
        ] {
            let error = call_tool(
                "pt_label",
                &serde_json::json!({
                    "pid": pid,
                    "verdict": "kill",
                    "confirmed_by_user": true,
                }),
            )
            .unwrap_err();
            assert!(error.contains("pid"), "{error}");
        }
    }

    #[test]
    fn label_schema_requires_a_human_verdict_and_one_target() {
        let definitions = tool_definitions();
        let label = definitions
            .iter()
            .find(|tool| tool.name == "pt_label")
            .unwrap();
        let schema = &label.input_schema;
        assert_eq!(
            schema["required"],
            serde_json::json!(["verdict", "confirmed_by_user"])
        );
        assert_eq!(schema["properties"]["confirmed_by_user"]["const"], true);
        assert_eq!(
            schema["properties"]["verdict"]["enum"],
            serde_json::json!(["kill", "spare"])
        );
        assert_eq!(schema["oneOf"].as_array().unwrap().len(), 2);
        assert_eq!(schema["additionalProperties"], false);
        assert!(label.description.contains("never signals"));
    }

    #[test]
    fn tool_definitions_count() {
        let defs = tool_definitions();
        assert_eq!(defs.len(), 7);
    }

    #[test]
    fn tool_scan_definition_has_min_score() {
        let defs = tool_definitions();
        let scan = defs.iter().find(|d| d.name == "pt_scan").unwrap();
        assert!(scan.input_schema["properties"].get("min_score").is_some());
    }

    #[test]
    fn tool_signatures_definition_has_category_enum() {
        let defs = tool_definitions();
        let signatures = defs.iter().find(|d| d.name == "pt_signatures").unwrap();
        let category = &signatures.input_schema["properties"]["category"]["enum"];
        assert!(category.is_array());
        assert!(category
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("agent")));
        assert!(category
            .as_array()
            .unwrap()
            .contains(&serde_json::json!("other")));
    }
}
