//! MCP tool implementations.
//!
//! Tools expose scanning, planning, explanations and explicit human feedback.

use crate::collect::protected::{ProtectedFilter, ProtectedMatch};
use crate::collect::tool_runner::{ToolConfig, ToolOutput, ToolRunner, ToolSpec};
#[cfg(target_os = "linux")]
use crate::collect::{deep_scan_with_budget, DeepScanOptions, DeepScanRecord, DeepScanResult};
use crate::collect::{quick_scan, ProcessActivity, ProcessRecord, QuickScanOptions, ScanResult};
use crate::mcp::protocol::{ToolContent, ToolDefinition};
use crate::scoring::{filter_planning_scan, AgentActivityReport, ProcessScore, Scorer};
use crate::supervision::pattern_persistence::{SignatureCatalog, SignatureOrigin};
use crate::supervision::signature::ProcessMatchContext;
use crate::supervision::{SignatureDatabase, SupervisorCategory};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

const DEFAULT_ACTIVITY_WINDOW_MS: u64 = 500;
const MAX_ACTIVITY_WINDOW_MS: u64 = 60_000;
const DEFAULT_PROBE_BUDGET_MS: u64 = 3_000;
const MAX_PROBE_BUDGET_MS: u64 = 60_000;
const DEFAULT_PLAN_TIMEOUT_SECS: u64 = 120;
const MAX_PLAN_TIMEOUT_SECS: u64 = 600;

fn probe_budget(params: &serde_json::Value) -> Result<Duration, String> {
    let millis = match params.get("probe_budget_ms") {
        None => DEFAULT_PROBE_BUDGET_MS,
        Some(value) => value
            .as_u64()
            .filter(|millis| *millis <= MAX_PROBE_BUDGET_MS)
            .ok_or_else(|| {
                format!("probe_budget_ms must be an integer between 0 and {MAX_PROBE_BUDGET_MS}")
            })?,
    };
    Ok(Duration::from_millis(millis))
}

fn probe_budget_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "integer",
        "description": "Total deep-probe collection budget in milliseconds, including worker startup and output. Partial evidence and coverage are retained on timeout; 0 disables deep probes. This is not an overall scan deadline",
        "default": DEFAULT_PROBE_BUDGET_MS,
        "minimum": 0,
        "maximum": MAX_PROBE_BUDGET_MS,
    })
}

fn plan_timeout(params: &serde_json::Value) -> Result<Duration, String> {
    let seconds = match params.get("timeout_secs") {
        None => DEFAULT_PLAN_TIMEOUT_SECS,
        Some(value) => value
            .as_u64()
            .filter(|seconds| (1..=MAX_PLAN_TIMEOUT_SECS).contains(seconds))
            .ok_or_else(|| {
                format!("timeout_secs must be an integer between 1 and {MAX_PLAN_TIMEOUT_SECS}")
            })?,
    };
    Ok(Duration::from_secs(seconds))
}

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
            scorer: Scorer::try_from_config(&config)
                .map_err(|error| format!("failed to load scoring model: {error}"))?,
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
        self.protected = filter_planning_scan(&self.protected_filter, scan, &mut self.scorer)
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
        self.scorer
            .collect_provenance(&set, &scan.processes, scan.metadata.warnings.is_empty());
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

    /// Use one shared window for the complete census, including young and
    /// protected descendants that can establish an agent root's current work.
    /// Sampling a process does not make it an action candidate.
    fn collect_activity(&mut self, scan: &ScanResult, window_ms: u64) -> AgentActivityReport {
        let population: Vec<_> = scan.processes.iter().collect();
        self.scorer
            .collect_activity(&population, Duration::from_millis(window_ms));
        self.scorer
            .prepare_agent_activity(&scan.processes, scan.metadata.warnings.is_empty())
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

    fn collect_deep_evidence(&mut self, scan: &ScanResult, budget: Duration) -> serde_json::Value {
        #[cfg(target_os = "linux")]
        {
            use crate::action::{IdentityProvider, LiveIdentityProvider};
            let identity_provider = std::sync::OnceLock::new();
            self.collect_deep_evidence_with(
                scan,
                budget,
                |options, budget| {
                    let executable = std::env::current_exe()
                        .map_err(|error| format!("cannot locate deep-scan worker: {error}"))?;
                    deep_scan_with_budget(options, budget, &executable)
                        .map_err(|error| error.to_string())
                },
                |identity| {
                    matches!(
                        identity_provider
                            .get_or_init(LiveIdentityProvider::new)
                            .revalidate(identity),
                        Ok(true)
                    )
                },
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = scan;
            serde_json::json!({
                "requested": true,
                "status": "unsupported",
                "budget_ms": budget.as_millis(),
                "matched_processes": 0,
                "reason": "Deep probes are only available on Linux; quick-scan evidence is retained",
            })
        }
    }

    #[cfg(target_os = "linux")]
    fn collect_deep_evidence_with(
        &mut self,
        scan: &ScanResult,
        budget: Duration,
        collect: impl FnOnce(&DeepScanOptions, Duration) -> Result<DeepScanResult, String>,
        revalidate: impl Fn(&pt_common::ProcessIdentity) -> bool,
    ) -> serde_json::Value {
        self.deep_records.clear();
        let eligible = self.eligible_processes(scan);
        // The collector interprets an empty PID list as "scan all". Neither an
        // empty eligible set nor an explicit zero budget may start a worker.
        if eligible.is_empty() || budget.is_zero() {
            return serde_json::json!({
                "requested": true,
                "status": if eligible.is_empty() { "no_eligible_processes" } else { "disabled_by_budget" },
                "budget_ms": budget.as_millis(),
                "requested_processes": eligible.len(),
                "matched_processes": 0,
                "duration_ms": 0,
            });
        }
        let options = DeepScanOptions {
            pids: eligible.iter().map(|process| process.pid.0).collect(),
            // Losing one target must not discard independent completed probes.
            skip_inaccessible: true,
            ..Default::default()
        };
        let result = match collect(&options, budget) {
            Ok(result) => result,
            Err(error) => {
                return serde_json::json!({
                    "requested": true,
                    "status": "unavailable",
                    "budget_ms": budget.as_millis(),
                    "requested_processes": eligible.len(),
                    "matched_processes": 0,
                    "error": error,
                });
            }
        };
        let (mut records, identity_mismatches) = match_deep_records(&eligible, result.processes);
        // Partial worker output is useful only for the original incarnation.
        // Recheck after all optional reads, including on timeout, so a new PID
        // occupant never inherits a predecessor's network or I/O evidence.
        let joined_count = records.len();
        records.retain(|_, record| revalidate(&record.to_identity()));
        let identity_revalidation_failed = joined_count - records.len();
        let complete = result.metadata.collection.complete && records.len() == eligible.len();
        self.deep_records = records;
        serde_json::json!({
            "requested": true,
            "status": if result.metadata.collection.timed_out { "timed_out" } else if complete { "collected" } else { "partial" },
            "budget_ms": budget.as_millis(),
            "requested_processes": eligible.len(),
            "matched_processes": self.deep_records.len(),
            "identity_mismatches": identity_mismatches,
            "identity_revalidation_failed": identity_revalidation_failed,
            "skipped_processes": result.metadata.skipped_count,
            "started_at": result.metadata.started_at,
            "duration_ms": result.metadata.duration_ms,
            "collection": result.metadata.collection,
            "warnings": result.metadata.warnings,
        })
    }

    fn evidence(&self, process: &ProcessRecord) -> crate::inference::Evidence {
        let evidence = self.scorer.snapshot_evidence(process);
        #[cfg(target_os = "linux")]
        let evidence = crate::inference::Evidence {
            net: self
                .deep_records
                .get(&process.pid.0)
                .and_then(DeepScanRecord::observed_socket_presence),
            queue_saturated: self
                .deep_records
                .get(&process.pid.0)
                .and_then(|record| record.network.as_ref())
                .and_then(|network| network.observed_queue_saturation()),
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
                    let complete = record.network_unavailable.is_empty();
                    let queue_observed = record.network.as_ref().is_some_and(|network| {
                        complete || network.tcp_data_connections().next().is_some()
                    });
                    serde_json::json!({
                        "start_id": record.start_id,
                        "source": record.source,
                        "has_network_sockets": record.observed_socket_presence(),
                        "network_coverage": record.network_coverage(),
                        "network_unavailable": record.network_unavailable,
                        "network": record.network.as_ref().map(|network| serde_json::json!({
                            "socket_counts": complete.then_some(&network.socket_counts),
                            "observed_socket_counts": network.socket_counts,
                            "listening_ports": network.listen_ports,
                            "rx_queue_bytes": complete.then(|| network.total_rx_queue()),
                            "tx_queue_bytes": complete.then(|| network.total_tx_queue()),
                            "observed_rx_queue_bytes": queue_observed
                                .then(|| network.total_rx_queue()),
                            "observed_tx_queue_bytes": queue_observed
                                .then(|| network.total_tx_queue()),
                            "queue_saturated": network.observed_queue_saturation(),
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

    /// Only report an eligible service's read-only binding. Independent
    /// protections still override a verified user-service placement.
    fn supervisor_restart(
        &self,
        process: &ProcessRecord,
    ) -> Option<&crate::action::SystemdUserServiceBinding> {
        if self.protected.contains_key(&process.pid.0) {
            return None;
        }
        self.scorer.supervisor_restart_for(process)
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

#[derive(Debug)]
enum ExplainRequest {
    Live {
        pid: Option<u32>,
        comm: Option<String>,
        window_ms: u64,
    },
    Recorded {
        session: String,
        pid: u32,
        start_id: Option<String>,
        args: Vec<String>,
        timeout: Duration,
    },
}

/// A saved explanation must select an existing observation explicitly. Never
/// turn an invalid session or process identity into a fresh live observation.
fn explain_request(params: &serde_json::Value) -> Result<ExplainRequest, String> {
    let object = params
        .as_object()
        .ok_or_else(|| "pt_explain arguments must be an object".to_string())?;
    let window_ms = activity_window_ms(params)?;
    let timeout = plan_timeout(params)?;
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "pid" | "comm" | "window_ms" | "session" | "start_id" | "include" | "timeout_secs"
        ) {
            return Err(format!("unknown pt_explain argument: {key}"));
        }
    }
    let pid = object
        .get("pid")
        .map(|value| {
            value
                .as_u64()
                .and_then(|pid| u32::try_from(pid).ok())
                .filter(|pid| *pid > 0)
                .ok_or("pid must be an integer between 1 and 4294967295")
        })
        .transpose()?;

    if let Some(value) = object.get("session") {
        let session = value
            .as_str()
            .filter(|session| pt_common::SessionId::parse(session).is_some())
            .ok_or("session must be a valid pt session ID")?;
        let pid = pid.ok_or("session requires pid to select a recorded process")?;
        if object.contains_key("comm") || object.contains_key("window_ms") {
            return Err("session cannot be combined with live comm or window_ms arguments".into());
        }
        let start_id = object
            .get("start_id")
            .map(|value| {
                let start_id = value
                    .as_str()
                    .filter(|value| !value.contains('\0'))
                    .and_then(pt_common::StartId::parse)
                    .ok_or("start_id must be a valid process birth identity")?;
                if start_id
                    .0
                    .rsplit(':')
                    .next()
                    .and_then(|value| value.parse::<u32>().ok())
                    != Some(pid)
                {
                    return Err("start_id must identify the requested pid");
                }
                Ok(start_id.0)
            })
            .transpose()?;
        let mut args = vec![
            "agent".to_string(),
            "explain".to_string(),
            "--format=json".to_string(),
            format!("--session={session}"),
        ];
        if let Some(start_id) = &start_id {
            args.push(format!("--target={pid}:{start_id}"));
        } else {
            args.push(format!("--pids={pid}"));
        }
        if let Some(value) = object.get("include") {
            let sections = value
                .as_array()
                .filter(|sections| !sections.is_empty())
                .ok_or("include must be a nonempty array of evidence, ledger or bayes_factors")?;
            let mut seen = std::collections::HashSet::new();
            for section in sections {
                let section = section
                    .as_str()
                    .filter(|section| matches!(*section, "evidence" | "ledger" | "bayes_factors"))
                    .ok_or("include must contain evidence, ledger or bayes_factors")?;
                if !seen.insert(section) {
                    return Err("include must not contain duplicate sections".into());
                }
                args.push(format!("--include={section}"));
            }
        }
        return Ok(ExplainRequest::Recorded {
            session: session.to_string(),
            pid,
            start_id,
            args,
            timeout,
        });
    }

    for parameter in ["start_id", "include", "timeout_secs"] {
        if object.contains_key(parameter) {
            return Err(format!(
                "{parameter} requires session for a recorded explanation"
            ));
        }
    }
    let comm = object
        .get("comm")
        .map(|value| {
            value
                .as_str()
                .filter(|value| !value.trim().is_empty() && !value.contains('\0'))
                .map(str::to_string)
                .ok_or("comm must be a nonempty process name without NUL bytes")
        })
        .transpose()?;
    if pid.is_some() && comm.is_some() {
        return Err("pid and comm are mutually exclusive".into());
    }
    if pid.is_none() && comm.is_none() {
        return Err("Either 'pid' or 'comm' must be provided".into());
    }
    Ok(ExplainRequest::Live {
        pid,
        comm,
        window_ms,
    })
}

/// Arguments for `pt-core agent plan` derived from `pt_plan` tool params.
fn plan_command_args(params: &serde_json::Value) -> Result<Vec<String>, String> {
    let object = params
        .as_object()
        .ok_or_else(|| "pt_plan arguments must be an object".to_string())?;
    let window_ms = activity_window_ms(params)?;
    probe_budget(params)?;
    plan_timeout(params)?;
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "deep"
                | "min_score"
                | "min_age"
                | "window_ms"
                | "probe_budget_ms"
                | "timeout_secs"
                | "goal"
                | "pids"
                | "max_candidates"
                | "since"
                | "since_time"
                | "include_predictions"
                | "prediction_fields"
        ) {
            return Err(format!("unknown pt_plan argument: {key}"));
        }
    }
    if object.contains_key("since") && object.contains_key("since_time") {
        return Err("since and since_time are mutually exclusive".to_string());
    }

    let mut args = vec![
        "agent".to_string(),
        "plan".to_string(),
        "--format".to_string(),
        "json".to_string(),
        "--window-ms".to_string(),
        window_ms.to_string(),
    ];
    if crate::mcp::robot_mode() {
        args.push("--robot".to_string());
    }
    if object.contains_key("probe_budget_ms") {
        args.push("--probe-budget-ms".to_string());
        args.push(probe_budget(params)?.as_millis().to_string());
    }
    for (parameter, flag) in [
        ("deep", "--deep"),
        ("include_predictions", "--include-predictions"),
    ] {
        if let Some(value) = object.get(parameter) {
            if value
                .as_bool()
                .ok_or_else(|| format!("{parameter} must be a boolean"))?
            {
                args.push(flag.to_string());
            }
        }
    }
    if let Some(value) = object.get("min_score") {
        let min = value
            .as_f64()
            .filter(|min| min.is_finite() && (0.0..=1.0).contains(min))
            .ok_or("min_score must be a number between 0 and 1")?;
        args.push("--min-posterior".to_string());
        args.push(min.to_string());
    }
    if let Some(value) = object.get("min_age") {
        let min_age = value
            .as_u64()
            .ok_or("min_age must be a nonnegative integer")?;
        args.push("--min-age".to_string());
        args.push(min_age.to_string());
    }
    if let Some(value) = object.get("max_candidates") {
        let max = value
            .as_u64()
            .and_then(|max| u32::try_from(max).ok())
            .filter(|max| *max > 0)
            .ok_or("max_candidates must be an integer between 1 and 4294967295")?;
        args.push("--max-candidates".to_string());
        args.push(max.to_string());
    }
    if let Some(value) = object.get("pids") {
        let pids = value
            .as_array()
            .filter(|pids| !pids.is_empty())
            .ok_or("pids must be a nonempty array of unique positive process IDs")?;
        let mut seen = std::collections::HashSet::new();
        let mut selection = Vec::with_capacity(pids.len());
        for value in pids {
            let pid = value
                .as_u64()
                .and_then(|pid| u32::try_from(pid).ok())
                .filter(|pid| *pid > 0)
                .ok_or("each pid must be an integer between 1 and 4294967295")?;
            if !seen.insert(pid) {
                return Err("pids must not contain duplicate process IDs".to_string());
            }
            selection.push(pid.to_string());
        }
        args.push(format!("--pids={}", selection.join(",")));
    }
    for (parameter, flag) in [
        ("goal", "--goal"),
        ("since", "--since"),
        ("since_time", "--since-time"),
    ] {
        if let Some(value) = object.get(parameter) {
            let text = value
                .as_str()
                .filter(|text| !text.trim().is_empty() && !text.contains('\0'))
                .ok_or_else(|| {
                    format!("{parameter} must be a nonempty string without NUL bytes")
                })?;
            if parameter == "goal" {
                crate::decision::goal_parser::parse_goal(text)
                    .map_err(|error| format!("invalid goal: {error}"))?
                    .disk_target()
                    .map_err(|error| format!("invalid goal: {error}"))?;
            }
            if parameter == "since" && pt_common::SessionId::parse(text).is_none() {
                return Err("since must be a valid pt session ID".to_string());
            }
            // The CLI owns relative-time parsing and baseline selection. An
            // equals argument preserves the whole literal value, including a
            // filesystem path with spaces, without invoking a shell.
            args.push(format!("{flag}={text}"));
        }
    }
    if let Some(value) = object.get("prediction_fields") {
        if object
            .get("include_predictions")
            .and_then(|value| value.as_bool())
            != Some(true)
        {
            return Err("prediction_fields requires include_predictions=true".to_string());
        }
        let fields: Vec<crate::output::predictions::PredictionField> =
            serde_json::from_value(value.clone()).map_err(|_| {
                "prediction_fields must be an array containing memory, cpu, eta_abandoned, eta_resource_limit, trajectory or diagnostics".to_string()
            })?;
        let mut seen = std::collections::HashSet::new();
        if fields.is_empty() || fields.iter().any(|field| !seen.insert(*field)) {
            return Err("prediction_fields must be a nonempty array of unique fields".to_string());
        }
        let names: Vec<String> = serde_json::from_value(
            serde_json::to_value(fields).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        args.push(format!("--prediction-fields={}", names.join(",")));
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
            "pid" | "session" | "cmd" | "comm" | "verdict" | "confirmed_by_user"
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
            if let Some(value) = params.get("session") {
                let session = value
                    .as_str()
                    .filter(|session| session.is_ascii())
                    .and_then(pt_common::SessionId::parse)
                    .ok_or_else(|| "session must be a valid session ID, not a path".to_string())?;
                args.extend(["--session".to_string(), session.0]);
            }
        }
        (None, Some(value)) => {
            if params.get("session").is_some() {
                return Err("session is only valid with pid".to_string());
            }
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
                          Includes measured agent-tree activity from the complete census, \
                          even when age or score filters omit processes from the candidate rows."
                .to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "deep": {
                        "type": "boolean",
                        "description": "Add bounded Linux /proc probes for eligible unprotected processes, preserving quick-scan identity, age, CPU and TTY; returns partial coverage explicitly when the probe budget expires",
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
                    "window_ms": activity_window_schema(),
                    "probe_budget_ms": probe_budget_schema()
                },
                "required": [],
                "additionalProperties": false
            }),
        },
        ToolDefinition {
            name: "pt_explain".to_string(),
            description: "Explain a specific process and its evidence chain. With session and pid, \
                          returns the exact recorded CLI explanation, even after process exit or \
                          configuration changes. Without session, observes the current process by pid or comm."
                .to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "pid": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": u32::MAX,
                        "description": "Process ID to explain; required with session"
                    },
                    "comm": {
                        "type": "string",
                        "minLength": 1,
                        "description": "Live process name (comm), an alternative to pid; incompatible with session"
                    },
                    "window_ms": activity_window_schema(),
                    "session": {
                        "type": "string",
                        "description": "Saved pt session ID from pt_plan or pt_history. Uses recorded evidence without rescanning; incompatible with comm and window_ms"
                    },
                    "start_id": {
                        "type": "string",
                        "description": "Optional recorded process birth identity (boot_id:start_time:pid); requires session and must match the recorded process"
                    },
                    "include": {
                        "type": "array",
                        "description": "Additional recorded explanation sections; requires session",
                        "items": {"type": "string", "enum": ["evidence", "ledger", "bayes_factors"]},
                        "minItems": 1,
                        "uniqueItems": true
                    },
                    "timeout_secs": {
                        "type": "integer",
                        "description": "Total recorded-explanation deadline, including worker startup and output; requires session",
                        "minimum": 1,
                        "maximum": MAX_PLAN_TIMEOUT_SECS,
                        "default": DEFAULT_PLAN_TIMEOUT_SECS
                    }
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
                 output as `pt agent plan --format json`. Supports resource recovery, \
                 pressure relief and comparisons with saved sessions; never applies actions."
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
                        "description": "Minimum P(intervention warranted) in [0,1] (agent plan --min-posterior)",
                        "minimum": 0.0,
                        "maximum": 1.0
                    },
                    "min_age": {
                        "type": "integer",
                        "description": "Minimum process age in seconds (default: policy guardrail, 1 hour)",
                        "minimum": 0,
                        "maximum": u64::MAX
                    },
                    "window_ms": activity_window_schema(),
                    "probe_budget_ms": probe_budget_schema(),
                    "timeout_secs": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": MAX_PLAN_TIMEOUT_SECS,
                        "default": DEFAULT_PLAN_TIMEOUT_SECS,
                        "description": "Total planner deadline in seconds, including probes and output collection; an incomplete or timed-out response is an error"
                    },
                    "goal": {
                        "type": "string",
                        "minLength": 1,
                        "description": "Resource or pressure goal using the CLI grammar, e.g. free 4GB RAM, free port 3000, free 100 FDs, free-disk 4GB on /data, relieve, cpu-pressure, mem-pressure or io-pressure; goals never bypass safety gates"
                    },
                    "pids": {
                        "type": "array",
                        "minItems": 1,
                        "uniqueItems": true,
                        "items": {"type": "integer", "minimum": 1, "maximum": u32::MAX},
                        "description": "Restrict candidate inference to these process IDs; ancestry, resource ownership and protection still use the full process census"
                    },
                    "max_candidates": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": u32::MAX,
                        "default": 20,
                        "description": "Maximum candidates in the plan"
                    },
                    "since": {
                        "type": "string",
                        "minLength": 1,
                        "description": "Compare with this saved same-host session ID while retaining a complete fresh plan; mutually exclusive with since_time"
                    },
                    "since_time": {
                        "type": "string",
                        "minLength": 1,
                        "description": "Compare with the latest same-host snapshot at or before a positive duration ago (e.g. 2h) or a past RFC3339 timestamp; mutually exclusive with since"
                    },
                    "include_predictions": {
                        "type": "boolean",
                        "default": false,
                        "description": "Include trajectory analysis from recorded process observations; unavailable or insufficient history stays unknown"
                    },
                    "prediction_fields": {
                        "type": "array",
                        "minItems": 1,
                        "uniqueItems": true,
                        "items": {
                            "type": "string",
                            "enum": ["memory", "cpu", "eta_abandoned", "eta_resource_limit", "trajectory", "diagnostics"]
                        },
                        "description": "Select prediction subfields; requires include_predictions=true"
                    }
                },
                "required": [],
                "allOf": [
                    {"not": {"required": ["since", "since_time"]}},
                    {"anyOf": [
                        {"not": {"required": ["prediction_fields"]}},
                        {"required": ["include_predictions"], "properties": {"include_predictions": {"const": true}}}
                    ]}
                ],
                "additionalProperties": false
            }),
        },
        ToolDefinition {
            name: "pt_label".to_string(),
            description: "Record an explicitly user-confirmed kill/spare verdict using \
                          the same durable learning and shadow-label path as pt agent label. \
                          Updates future recommendations; never signals a process. \
                          Supply session with pid to label the recorded incarnation after it exits. \
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
                        "description": "Process to label; live unless session is supplied. Records an identity-bound shadow verdict"
                    },
                    "session": {
                        "type": "string",
                        "pattern": "^pt-[0-9]{8}-[0-9]{6}-[a-z2-7]{4}$",
                        "description": "Local session ID with intact saved command and identity; requires pid and never inspects that PID live"
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
                        "not": {"anyOf": [{"required": ["pid"]}, {"required": ["session"]}]}
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
    let object = params
        .as_object()
        .ok_or("pt_scan arguments must be an object")?;
    let window_ms = activity_window_ms(params)?;
    let budget = probe_budget(params)?;
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "deep" | "min_score" | "min_age" | "window_ms" | "probe_budget_ms"
        ) {
            return Err(format!("unknown pt_scan argument: {key}"));
        }
    }
    let deep = match params.get("deep") {
        None => false,
        Some(value) => value.as_bool().ok_or("deep must be a boolean")?,
    };
    let min_score = match params.get("min_score") {
        None => 0.0,
        Some(value) => value
            .as_f64()
            .filter(|score| score.is_finite() && (0.0..=1.0).contains(score))
            .ok_or("min_score must be a number between 0 and 1")?,
    };
    let min_age = params
        .get("min_age")
        .map(|value| {
            value
                .as_u64()
                .ok_or("min_age must be a nonnegative integer")
        })
        .transpose()?;
    let mut evaluator = Evaluator::load()?;
    let scan_started = std::time::Instant::now();
    let scan_result = quick_scan(&QuickScanOptions::default())
        .map_err(|error| format!("Scan failed: {error}"))?;
    // `agent plan`'s age floor: a process younger than this is never a candidate, so
    // scoring it would only invite acting on a busy new process.
    if let Some(min_age) = min_age {
        evaluator.min_age_seconds = min_age;
    }
    evaluator.collect_provenance(&scan_result, &[]);
    let deep_scan = if deep {
        evaluator.collect_deep_evidence(&scan_result, budget)
    } else {
        serde_json::json!({"requested": false, "status": "not_requested"})
    };
    let agent_activity = evaluator.collect_activity(&scan_result, window_ms);
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

    let duration_ms = scan_started.elapsed().as_millis();
    let process_snapshots = candidates
        .iter()
        .map(|(p, score, posterior, protected, top_signature)| {
            let activity = evaluator.scorer.activity_for(p);
            serde_json::json!({
                "pid": p.pid.0,
                "ppid": p.ppid.0,
                "comm": p.comm,
                "cmd": p.cmd,
                "state": format!("{}", p.state),
                "decision_state": p.decision_state(activity.as_ref()).0.to_string(),
                "uid": p.uid,
                "user": p.user,
                "start_id": p.start_id,
                "start_time_unix": p.start_time_unix,
                "cpu_pct": reported_cpu_percent(p, activity.as_ref()),
                "cpu_lifetime_pct": p.cpu_percent,
                "io_activity": activity.as_ref().and_then(|sample| sample.io_active),
                "activity": activity,
                "agent_liveness": crate::scoring::agent_liveness(
                    p,
                    evaluator.scorer.agent_activity_for(p),
                ),
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
                "supervisor_restart": evaluator.supervisor_restart(p),
                "top_signature": top_signature,
            })
        })
        .collect::<Vec<_>>();
    let result = serde_json::json!({
        "scanned_at": scan_result.metadata.started_at,
        "duration_ms": duration_ms,
        "quick_scan_duration_ms": scan_result.metadata.duration_ms,
        "platform": scan_result.metadata.platform,
        "warnings": scan_result.metadata.warnings,
        "deep_scan": deep_scan,
        "workloads": workloads,
        "agent_activity": agent_activity,
        "window_ms": window_ms,
        "total_processes": scan_result.processes.len(),
        "min_age_seconds": evaluator.min_age_seconds,
        "younger_than_min_age": younger_than_min_age,
        "returned": candidates.len(),
        "matching_processes": matching_processes,
        "truncated": matching_processes > candidates.len(),
        "score_definition": "P(abandoned or zombie) from pt's posterior (0-1); suspicion_score = 100 x score",
        "processes": process_snapshots,
    });

    Ok(vec![ToolContent {
        content_type: "text".to_string(),
        text: serde_json::to_string_pretty(&result)
            .map_err(|e| format!("Serialization error: {}", e))?,
    }])
}

fn tool_explain(params: &serde_json::Value) -> Result<Vec<ToolContent>, String> {
    let (pid, comm, window_ms) = match explain_request(params)? {
        ExplainRequest::Recorded {
            session,
            pid,
            start_id,
            args,
            timeout,
        } => {
            let config = crate::config::resolve_config_dir(&crate::mcp::config_options())
                .map_err(|error| format!("cannot resolve explanation config directory: {error}"))?;
            let exe = std::env::current_exe()
                .map_err(|error| format!("cannot locate pt-core: {error}"))?;
            let spec = agent_worker_spec(&exe, &config, args, timeout)?;
            let output = run_agent_worker(&spec, "agent explain")?;
            let text = parse_explain_worker_output(&output, &session, pid, start_id.as_deref())?;
            return Ok(vec![ToolContent {
                content_type: "text".to_string(),
                text,
            }]);
        }
        ExplainRequest::Live {
            pid,
            comm,
            window_ms,
        } => (pid, comm, window_ms),
    };

    let mut evaluator = Evaluator::load()?;
    // Run a quick scan to find the process
    let options = QuickScanOptions::default();
    let scan = quick_scan(&options).map_err(|e| format!("Scan failed: {}", e))?;

    let process = scan.processes.iter().find(|p| {
        if let Some(target_pid) = pid {
            p.pid.0 == target_pid
        } else if let Some(target_comm) = comm.as_deref() {
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
            let agent_activity = evaluator.collect_activity(&scan, window_ms);
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
                "decision_state": p.decision_state(activity.as_ref()).0.to_string(),
                "uid": p.uid,
                "user": p.user,
                "start_id": p.start_id,
                "start_time_unix": p.start_time_unix,
                "window_ms": window_ms,
                "cpu_pct": reported_cpu_percent(p, activity.as_ref()),
                "cpu_lifetime_pct": p.cpu_percent,
                "io_activity": activity.as_ref().and_then(|sample| sample.io_active),
                "activity": activity,
                "agent_liveness": crate::scoring::agent_liveness(
                    p,
                    evaluator.scorer.agent_activity_for(p),
                ),
                "rss_bytes": p.rss_bytes,
                "vsz_bytes": p.vsz_bytes,
                "elapsed_sec": p.elapsed.as_secs(),
                "tty": p.tty,
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
                "supervisor_restart": evaluator.supervisor_restart(p),
                "prior_source": prior_source,
                "learned_prior": learned_prior,
                "desktop_app": desktop_app,
                "desktop_app_credited": desktop_app_credited,
                "work": evaluator.scorer.workload_diagnosis_for(p),
                "workloads": workloads,
                "agent_activity": agent_activity,
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
                format!("comm '{}'", comm.as_deref().unwrap_or("?"))
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
    let timeout = plan_timeout(params)?;
    let config = crate::config::resolve_config_dir(&crate::mcp::config_options())
        .map_err(|error| format!("cannot resolve plan config directory: {error}"))?;
    let exe = std::env::current_exe().map_err(|e| format!("cannot locate pt-core: {e}"))?;
    let spec = agent_worker_spec(&exe, &config, args, timeout)?;
    let stdout = run_plan_worker(&spec)?;
    Ok(vec![ToolContent {
        content_type: "text".to_string(),
        text: stdout,
    }])
}

/// Keep the CLI worker's configured policy and storage location while preventing
/// inherited output overrides or lock-bypass variables from changing its contract.
fn agent_worker_spec(
    executable: &Path,
    config: &Path,
    args: Vec<String>,
    timeout: Duration,
) -> Result<ToolSpec, String> {
    let executable = executable
        .to_str()
        .ok_or("MCP worker executable path is not UTF-8")?;
    let config = config
        .to_str()
        .ok_or("MCP worker config path is not UTF-8")?;
    let mut command_args = vec![
        "--config".to_string(),
        config.to_string(),
        format!("--timeout={}", timeout.as_secs()),
    ];
    command_args.extend(args);
    let mut spec = ToolSpec::new(executable, command_args).with_timeout(timeout);
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        // The runner retains the leader's identity until all owned descendants
        // and inherited output pipes have been cancelled on completion/timeout.
        spec.isolate_process_group = true;
    }
    for key in [
        "HOME",
        "HOSTNAME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_CACHE_HOME",
        "XDG_STATE_HOME",
        "XDG_RUNTIME_DIR",
        "PROCESS_TRIAGE_DATA",
        "PROCESS_TRIAGE_CONFIG",
        "PROCESS_TRIAGE_CONFIG_DIR",
        "PROCESS_TRIAGE_PRIORS",
        "PROCESS_TRIAGE_POLICY",
        "PROCESS_TRIAGE_RETENTION",
        "KUBERNETES_SERVICE_HOST",
        "TMPDIR",
    ] {
        match std::env::var(key) {
            Ok(value) => {
                spec.env.insert(key.to_string(), value);
            }
            Err(std::env::VarError::NotPresent) => {}
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(format!("MCP worker environment {key} is not UTF-8"));
            }
        }
    }
    Ok(spec)
}

fn run_plan_worker(spec: &ToolSpec) -> Result<String, String> {
    let output = run_agent_worker(spec, "agent plan")?;
    parse_plan_worker_output(&output)
}

fn run_agent_worker(spec: &ToolSpec, operation: &str) -> Result<ToolOutput, String> {
    let timeout = spec
        .timeout
        .unwrap_or(Duration::from_secs(DEFAULT_PLAN_TIMEOUT_SECS));
    let runner = ToolRunner::new(ToolConfig {
        default_timeout: timeout,
        // A collector's five-second budget is not the caller's CLI deadline.
        budget_ms: u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
        use_nice: false,
        #[cfg(target_os = "linux")]
        use_ionice: false,
        ..ToolConfig::default()
    });
    runner
        .run(spec)
        .map_err(|error| format!("{operation} could not complete: {error}"))
}

fn parse_explain_worker_output(
    output: &ToolOutput,
    session: &str,
    pid: u32,
    start_id: Option<&str>,
) -> Result<String, String> {
    if output.timed_out {
        return Err("agent explain timed out; no complete explanation was returned".into());
    }
    if output.truncated {
        return Err(
            "agent explain output was truncated; no complete explanation was returned".into(),
        );
    }
    let stdout = std::str::from_utf8(&output.stdout)
        .map_err(|_| "agent explain returned invalid UTF-8".to_string())?;
    if output.exit_code != Some(0) {
        let document = serde_json::from_str::<serde_json::Value>(stdout).ok();
        let detail = document
            .as_ref()
            .and_then(|value| value["explanations"][0]["error"].as_str())
            .map(str::to_string)
            .unwrap_or_else(|| {
                output
                    .stderr_str()
                    .lines()
                    .rev()
                    .take(5)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect::<Vec<_>>()
                    .join("\n")
            });
        return Err(format!(
            "agent explain failed (exit {:?}): {detail}",
            output.exit_code
        ));
    }
    let document: serde_json::Value = serde_json::from_str(stdout)
        .map_err(|error| format!("agent explain returned invalid JSON: {error}"))?;
    if document["command"] != "agent explain"
        || document["mode"] != "recorded"
        || document["session_id"] != session
    {
        return Err("agent explain returned an invalid recorded session identity".into());
    }
    let explanations = document["explanations"]
        .as_array()
        .filter(|explanations| explanations.len() == 1)
        .ok_or("agent explain returned an incomplete explanation inventory")?;
    let explanation = &explanations[0];
    if explanation["pid"].as_u64() != Some(u64::from(pid)) {
        return Err("agent explain returned a different process identity".into());
    }
    if let Some(error) = explanation["error"].as_str() {
        return Err(format!("agent explain: {error}"));
    }
    if start_id.is_some_and(|expected| explanation["start_id"].as_str() != Some(expected)) {
        return Err("agent explain returned a different process birth identity".into());
    }
    Ok(stdout.to_string())
}

fn parse_plan_worker_output(output: &ToolOutput) -> Result<String, String> {
    if output.timed_out {
        return Err("agent plan timed out; no complete plan was returned".into());
    }
    if output.truncated {
        return Err("agent plan output was truncated; no complete plan was returned".into());
    }
    // A valid JSON prefix is not success if the child failed afterwards.
    if !matches!(output.exit_code, Some(0) | Some(1)) {
        let stderr = output.stderr_str();
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
            "agent plan failed (exit {:?}): {tail}",
            output.exit_code
        ));
    }
    let stdout = std::str::from_utf8(&output.stdout)
        .map_err(|_| "agent plan returned invalid UTF-8".to_string())?;
    let document: serde_json::Value = serde_json::from_str(stdout)
        .map_err(|error| format!("agent plan returned invalid JSON: {error}"))?;
    let plan: crate::plan::Plan = serde_json::from_value(document.clone())
        .map_err(|error| format!("agent plan returned an incomplete plan: {error}"))?;
    if document["command"] != "agent plan"
        || pt_common::SessionId::parse(&plan.session_id).is_none()
        || plan.plan_id.is_empty()
    {
        return Err("agent plan returned an invalid plan identity".into());
    }
    let candidates = document["candidates"]
        .as_array()
        .ok_or("agent plan returned no candidate inventory")?;
    let count = candidates.len() as u64;
    if document["summary"]["candidates_returned"].as_u64() != Some(count)
        || !document["summary"]["total_processes_scanned"]
            .as_u64()
            .is_some_and(|scanned| scanned >= count)
        || output.exit_code != Some(i32::from(count > 0))
    {
        return Err("agent plan returned inconsistent candidate counts or exit status".into());
    }
    Ok(stdout.to_string())
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
    let user_only = match params.get("user_only") {
        None => false,
        Some(value) => value
            .as_bool()
            .ok_or_else(|| "user_only must be a boolean".to_string())?,
    };
    let category_filter = parse_signature_category_filter(params)?;
    let catalog = SignatureCatalog::load(&config_dir())
        .map_err(|error| format!("failed to load signature catalog: {error}"))?;
    let mut all_sigs = Vec::new();
    for entry in &catalog.entries {
        if user_only && entry.origin == SignatureOrigin::BuiltIn {
            continue;
        }
        let sig = &entry.signature;
        if category_filter.is_some_and(|category| sig.category != category) {
            continue;
        }
        all_sigs.push(serde_json::json!({
            "name": sig.name,
            "category": format!("{:?}", sig.category),
            "source": entry.origin.as_str(),
            "provenance": entry.source,
            "lifecycle": entry.lifecycle,
            "active": entry.is_active(),
            "disabled": entry.disabled,
            "priority": sig.priority,
            "confidence": sig.confidence_weight,
        }));
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

    fn worker_plan_document(count: usize) -> serde_json::Value {
        serde_json::json!({
            "command": "agent plan",
            "plan_id": "mcp-worker-plan",
            "session_id": pt_common::SessionId::new().0,
            "generated_at": "2026-11-20T12:00:00Z",
            "policy_id": null,
            "policy_version": "1.0.0",
            "actions": [],
            "pre_toggled": [],
            "gates_summary": {
                "total_candidates": count,
                "blocked_candidates": 0,
                "pre_toggled_actions": 0,
            },
            "candidates": (0..count).map(|index| serde_json::json!({"pid": index + 100}))
                .collect::<Vec<_>>(),
            "summary": {"candidates_returned": count, "total_processes_scanned": count + 1},
        })
    }

    #[test]
    fn plan_deadline_is_bounded_and_part_of_the_tool_contract() {
        assert_eq!(
            plan_timeout(&serde_json::json!({})).unwrap(),
            Duration::from_secs(120)
        );
        for seconds in [1, 120, MAX_PLAN_TIMEOUT_SECS] {
            let params = serde_json::json!({"timeout_secs": seconds});
            assert!(plan_command_args(&params).is_ok());
            assert_eq!(plan_timeout(&params).unwrap(), Duration::from_secs(seconds));
        }
        for seconds in [
            serde_json::Value::Null,
            serde_json::json!(0),
            serde_json::json!(-1),
            serde_json::json!(1.5),
            serde_json::json!("120"),
            serde_json::json!(MAX_PLAN_TIMEOUT_SECS + 1),
            serde_json::json!(u64::MAX),
        ] {
            assert!(plan_command_args(&serde_json::json!({"timeout_secs": seconds})).is_err());
        }
        let definition = tool_definitions()
            .into_iter()
            .find(|tool| tool.name == "pt_plan")
            .unwrap();
        let schema = &definition.input_schema["properties"]["timeout_secs"];
        assert_eq!(schema["minimum"], 1);
        assert_eq!(schema["maximum"], MAX_PLAN_TIMEOUT_SECS);
        assert_eq!(schema["default"], DEFAULT_PLAN_TIMEOUT_SECS);

        let spec = agent_worker_spec(
            Path::new("/tmp/pt core"),
            Path::new("/tmp/config with spaces"),
            plan_command_args(&serde_json::json!({"timeout_secs": 7})).unwrap(),
            Duration::from_secs(7),
        )
        .unwrap();
        assert_eq!(spec.command, "/tmp/pt core");
        assert_eq!(
            &spec.args[..3],
            ["--config", "/tmp/config with spaces", "--timeout=7"]
        );
        assert_eq!(spec.timeout, Some(Duration::from_secs(7)));
        assert!(!spec.env.contains_key("PT_SKIP_GLOBAL_LOCK"));
        assert!(!spec.env.contains_key("PT_FORMAT"));
        assert!(!spec.env.contains_key("LD_PRELOAD"));
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        assert!(spec.isolate_process_group);
    }

    #[test]
    fn plan_worker_rejects_incomplete_or_inconsistent_success() {
        let document = worker_plan_document(0);
        let original = ToolOutput {
            command: "pt-core".into(),
            args: Vec::new(),
            stdout: document.to_string().into_bytes(),
            stderr: Vec::new(),
            exit_code: Some(0),
            truncated: false,
            duration: Duration::ZERO,
            timed_out: false,
        };
        assert_eq!(
            parse_plan_worker_output(&original).unwrap(),
            document.to_string()
        );
        for (path, value) in [
            ("/command", serde_json::json!("agent scan")),
            ("/plan_id", serde_json::json!("")),
            ("/session_id", serde_json::json!("not-a-session")),
            ("/actions", serde_json::Value::Null),
            ("/candidates", serde_json::Value::Null),
            ("/summary/candidates_returned", serde_json::json!(1)),
            ("/summary/total_processes_scanned", serde_json::Value::Null),
        ] {
            let mut invalid = document.clone();
            *invalid.pointer_mut(path).unwrap() = value;
            let mut output = original.clone();
            output.stdout = invalid.to_string().into_bytes();
            assert!(
                parse_plan_worker_output(&output).is_err(),
                "accepted {path}"
            );
        }
        for bytes in [b"{}".to_vec(), b"{\"command\":".to_vec(), vec![0xff]] {
            let mut output = original.clone();
            output.stdout = bytes;
            assert!(parse_plan_worker_output(&output).is_err());
        }
        for status in [None, Some(1), Some(20)] {
            let mut output = original.clone();
            output.exit_code = status;
            assert!(parse_plan_worker_output(&output).is_err());
        }
        let mut output = original.clone();
        output.timed_out = true;
        assert!(parse_plan_worker_output(&output)
            .unwrap_err()
            .contains("timed out"));
        let mut output = original;
        output.truncated = true;
        assert!(parse_plan_worker_output(&output)
            .unwrap_err()
            .contains("truncated"));
    }

    #[test]
    fn recorded_explanations_select_an_exact_session_and_optional_birth_identity() {
        let session = pt_common::SessionId::new().0;
        let params = serde_json::json!({
            "session": session,
            "pid": 42,
            "start_id": "test-boot:123:42",
            "include": ["evidence", "ledger", "bayes_factors"],
            "timeout_secs": 7,
        });
        let ExplainRequest::Recorded {
            session: actual_session,
            pid,
            start_id,
            args,
            timeout,
        } = explain_request(&params).unwrap()
        else {
            panic!("session must select recorded explanation");
        };
        assert_eq!(actual_session, session);
        assert_eq!(pid, 42);
        assert_eq!(start_id.as_deref(), Some("test-boot:123:42"));
        assert_eq!(timeout, Duration::from_secs(7));
        assert_eq!(
            args,
            [
                "agent",
                "explain",
                "--format=json",
                &format!("--session={session}"),
                "--target=42:test-boot:123:42",
                "--include=evidence",
                "--include=ledger",
                "--include=bayes_factors",
            ]
        );
        let ExplainRequest::Recorded { args, .. } =
            explain_request(&serde_json::json!({"session": session, "pid": 42})).unwrap()
        else {
            panic!("session must not fall back to live observation");
        };
        assert!(args.contains(&"--pids=42".to_string()));
        assert!(!args.iter().any(|arg| arg == "--live"));
        assert!(matches!(
            explain_request(&serde_json::json!({"pid": 42, "window_ms": 0})).unwrap(),
            ExplainRequest::Live {
                pid: Some(42),
                comm: None,
                window_ms: 0,
            }
        ));
        assert!(matches!(
            explain_request(&serde_json::json!({"comm": "sleep"})).unwrap(),
            ExplainRequest::Live { pid: None, .. }
        ));
    }

    #[test]
    fn recorded_explanation_worker_rejects_unrelated_and_partial_outputs() {
        let session = pt_common::SessionId::new().0;
        let document = serde_json::json!({
            "command": "agent explain",
            "mode": "recorded",
            "session_id": session,
            "explanations": [{
                "pid": 42,
                "start_id": "test-boot:123:42",
                "score": 0.8123456789,
                "ledger_status": "not_recorded",
            }],
        });
        let original = ToolOutput {
            command: "pt-core".into(),
            args: Vec::new(),
            stdout: document.to_string().into_bytes(),
            stderr: Vec::new(),
            exit_code: Some(0),
            truncated: false,
            duration: Duration::ZERO,
            timed_out: false,
        };
        let parse = |output: &ToolOutput| {
            parse_explain_worker_output(output, &session, 42, Some("test-boot:123:42"))
        };
        assert_eq!(parse(&original).unwrap(), document.to_string());
        for (path, value) in [
            ("/command", serde_json::json!("agent plan")),
            ("/mode", serde_json::json!("live")),
            (
                "/session_id",
                serde_json::json!(pt_common::SessionId::new().0),
            ),
            ("/explanations", serde_json::json!([])),
            ("/explanations", serde_json::json!([{}, {}])),
            ("/explanations/0/pid", serde_json::json!(43)),
            (
                "/explanations/0/start_id",
                serde_json::json!("test-boot:124:42"),
            ),
        ] {
            let mut invalid = document.clone();
            *invalid.pointer_mut(path).unwrap() = value;
            let mut output = original.clone();
            output.stdout = invalid.to_string().into_bytes();
            assert!(parse(&output).is_err(), "accepted {path}");
        }
        for bytes in [b"{}".to_vec(), b"{\"command\":".to_vec(), vec![0xff]] {
            let mut output = original.clone();
            output.stdout = bytes;
            assert!(parse(&output).is_err());
        }
        for status in [None, Some(1), Some(20)] {
            let mut output = original.clone();
            output.exit_code = status;
            assert!(parse(&output).is_err());
        }
        let mut output = original.clone();
        output.timed_out = true;
        assert!(parse(&output).unwrap_err().contains("timed out"));
        output = original.clone();
        output.truncated = true;
        assert!(parse(&output).unwrap_err().contains("truncated"));
        let mut missing = document;
        missing["explanations"][0]["error"] =
            serde_json::json!("process not found in recorded session inference");
        output = original;
        output.stdout = missing.to_string().into_bytes();
        assert!(parse(&output).unwrap_err().contains("process not found"));
    }

    #[cfg(unix)]
    #[test]
    fn plan_worker_deadlines_cover_child_exit_output_and_owned_descendants() {
        for count in [0, 1] {
            let document = worker_plan_document(count).to_string();
            let spec = ToolSpec::new(
                "/bin/sh",
                vec![
                    "-c".into(),
                    "printf '%s' \"$1\"; exit \"$2\"".into(),
                    "mcp-planner-fixture".into(),
                    document.clone(),
                    count.to_string(),
                ],
            )
            .with_timeout(Duration::from_secs(5));
            assert_eq!(run_plan_worker(&spec).unwrap(), document);
            assert!(run_plan_worker(&spec.with_max_output(16))
                .unwrap_err()
                .contains("truncated"));
        }
        let sleeper = ToolSpec::new("/bin/sh", vec!["-c".into(), "exec sleep 30".into()])
            .with_timeout(Duration::from_millis(100));
        let started = std::time::Instant::now();
        assert!(run_plan_worker(&sleeper).unwrap_err().contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(5));

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            // A successful leader can leave a child holding the output pipes.
            // The original deadline must still apply to the complete response.
            let held_pipe = ToolSpec::new(
                "/bin/sh",
                vec![
                    "-c".into(),
                    "sleep 30 & printf '%s' \"$1\"; exit 0".into(),
                    "mcp-planner-held-pipe".into(),
                    worker_plan_document(0).to_string(),
                ],
            )
            .with_timeout(Duration::from_millis(100))
            .with_process_group();
            let started = std::time::Instant::now();
            assert!(run_plan_worker(&held_pipe)
                .unwrap_err()
                .contains("timed out"));
            assert!(started.elapsed() < Duration::from_secs(5));
        }
    }

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
            user_intent: None,
            workspace: None,
            cgroup: None,
            wchan: None,
            network: Some(crate::collect::NetworkInfo {
                socket_counts: crate::collect::SocketCounts {
                    tcp: 1,
                    ..Default::default()
                },
                ..Default::default()
            }),
            network_unavailable: Vec::new(),
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
    fn deep_network_partial_queues_preserve_positive_evidence_and_withhold_totals() {
        use crate::collect::{TcpConnection, TcpState};

        let process = protection_test_scan().processes.pop().unwrap();
        let mut record = deep_test_record(&process);
        record
            .network
            .as_mut()
            .unwrap()
            .tcp_connections
            .push(TcpConnection {
                local_addr: "127.0.0.1".into(),
                local_port: 8000,
                remote_addr: "127.0.0.1".into(),
                remote_port: 40000,
                state: TcpState::Established,
                inode: 41,
                is_ipv6: false,
                tx_queue: 16,
                rx_queue: 8192,
            });
        let mut evaluator =
            protection_test_evaluator(ProtectedFilter::new(&[], &[], &[], &[]).unwrap());
        for complete in [true, false] {
            if !complete {
                record
                    .network_unavailable
                    .push("unresolved socket inode".into());
            }
            evaluator.deep_records.insert(process.pid.0, record.clone());
            let evidence = evaluator.evidence(&process);
            assert_eq!(evidence.net, Some(true));
            assert_eq!(evidence.queue_saturated, Some(true));
            let deep = evaluator.deep_evidence(&process);
            assert_eq!(
                deep["network_coverage"],
                if complete { "complete" } else { "partial" }
            );
            assert_eq!(
                deep["network"]["rx_queue_bytes"].as_u64(),
                complete.then_some(8192)
            );
            assert_eq!(
                deep["network"]["socket_counts"]["tcp"].as_u64(),
                complete.then_some(1)
            );
            assert_eq!(deep["network"]["observed_rx_queue_bytes"], 8192);
            assert_eq!(deep["network"]["observed_socket_counts"]["tcp"], 1);
        }
        // One observed listener with 8192 pending accepts, plus an unresolved
        // socket. No data queue or process-wide byte total can be inferred.
        record.network.as_mut().unwrap().tcp_connections[0].state = TcpState::Listen;
        evaluator.deep_records.insert(process.pid.0, record);
        assert_eq!(evaluator.evidence(&process).queue_saturated, None);
        assert!(evaluator.deep_evidence(&process)["network"]["observed_rx_queue_bytes"].is_null());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn deep_socket_absence_remains_unknown_without_collection_completeness() {
        let process = protection_test_scan().processes.pop().unwrap();
        let mut record = deep_test_record(&process);
        record.network = Some(crate::collect::NetworkInfo::default());
        assert_eq!(record.observed_socket_presence(), None);

        record.fd = Some(crate::collect::FdInfo {
            count: 2,
            by_type: HashMap::from([("file".to_string(), 1)]),
            ..Default::default()
        });
        assert_eq!(record.observed_socket_presence(), None);
        record
            .fd
            .as_mut()
            .unwrap()
            .by_type
            .insert("file".to_string(), 2);
        assert_eq!(record.observed_socket_presence(), None);
        record.fd.as_mut().unwrap().truncated = true;
        assert_eq!(record.observed_socket_presence(), None);
        record.fd.as_mut().unwrap().sockets = 1;
        assert_eq!(record.observed_socket_presence(), Some(true));
    }

    #[cfg(target_os = "linux")]
    fn deep_test_result(records: Vec<DeepScanRecord>) -> DeepScanResult {
        let count = records.len();
        DeepScanResult {
            processes: records,
            metadata: crate::collect::DeepScanMetadata {
                started_at: "2026-11-23T12:00:00Z".to_string(),
                duration_ms: 20,
                process_count: count,
                skipped_count: 0,
                collection: crate::collect::DeepScanCollection {
                    complete: true,
                    budget_ms: Some(20),
                    requested_count: Some(count),
                    processed_count: count,
                    incomplete_count: Some(0),
                    enriched_count: count,
                    stage: crate::collect::DeepScanStage::Complete,
                    ..Default::default()
                },
                warnings: Vec::new(),
            },
            gpu: Default::default(),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn timed_out_deep_scan_retains_only_identity_bound_partial_evidence() {
        let mut scan = protection_test_scan();
        scan.processes.truncate(4);
        let filter = ProtectedFilter::new(&[], &[], &[], &[]).unwrap();
        let mut evaluator = protection_test_evaluator(filter);
        evaluator.min_age_seconds = 0;
        let retained = &scan.processes[0];
        let mut changed_owner = deep_test_record(&scan.processes[1]);
        changed_owner.uid += 1;
        let changed_after_probe = deep_test_record(&scan.processes[2]);
        let mut result = deep_test_result(vec![
            deep_test_record(retained),
            changed_owner,
            changed_after_probe,
        ]);
        result.metadata.collection.complete = false;
        result.metadata.collection.timed_out = true;
        result.metadata.collection.requested_count = Some(4);
        result.metadata.collection.incomplete_count = Some(1);
        result.metadata.collection.enriched_count = 0;
        result.metadata.collection.stage = crate::collect::DeepScanStage::Processes;
        result
            .metadata
            .warnings
            .push("probe deadline reached".into());
        let metadata = evaluator.collect_deep_evidence_with(
            &scan,
            Duration::from_millis(20),
            |options, budget| {
                assert_eq!(budget, Duration::from_millis(20));
                assert_eq!(
                    options.pids,
                    scan.processes
                        .iter()
                        .map(|process| process.pid.0)
                        .collect::<Vec<_>>()
                );
                assert!(options.skip_inaccessible);
                assert!(!options.include_environ);
                Ok(result)
            },
            |identity| identity.pid == retained.pid,
        );
        assert_eq!(metadata["status"], "timed_out");
        assert_eq!(metadata["budget_ms"], 20);
        assert_eq!(metadata["requested_processes"], 4);
        assert_eq!(metadata["matched_processes"], 1);
        assert_eq!(metadata["identity_mismatches"], 1);
        assert_eq!(metadata["identity_revalidation_failed"], 1);
        assert_eq!(metadata["collection"]["complete"], false);
        assert_eq!(metadata["collection"]["processed_count"], 3);
        assert_eq!(metadata["collection"]["incomplete_count"], 1);
        assert_eq!(metadata["warnings"][0], "probe deadline reached");
        assert_eq!(evaluator.evidence(retained).net, Some(true));
        for process in &scan.processes[1..] {
            assert!(evaluator.deep_evidence(process).is_null());
            assert_eq!(evaluator.evidence(process).net, None);
        }

        let unavailable = evaluator.collect_deep_evidence_with(
            &scan,
            Duration::from_millis(20),
            |_, _| Err("worker could not start".into()),
            |_| panic!("failed collection must not revalidate stale records"),
        );
        assert_eq!(unavailable["status"], "unavailable");
        assert_eq!(unavailable["error"], "worker could not start");
        assert!(evaluator.deep_records.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn deep_scan_coverage_does_not_confuse_all_records_with_completed_enrichment() {
        let mut scan = protection_test_scan();
        scan.processes.truncate(1);
        let filter = ProtectedFilter::new(&[], &[], &[], &[]).unwrap();
        let mut evaluator = protection_test_evaluator(filter);
        evaluator.min_age_seconds = 0;
        for (complete, truncated, expected) in [
            (true, false, "collected"),
            (false, false, "partial"),
            (false, true, "partial"),
        ] {
            let mut result = deep_test_result(vec![deep_test_record(&scan.processes[0])]);
            result.metadata.collection.complete = complete;
            result.metadata.collection.output_truncated = truncated;
            if !complete {
                result.metadata.collection.stage = crate::collect::DeepScanStage::Gpu;
                result.metadata.collection.enriched_count = 0;
            }
            let metadata = evaluator.collect_deep_evidence_with(
                &scan,
                Duration::from_millis(20),
                |_, _| Ok(result),
                |_| true,
            );
            assert_eq!(metadata["status"], expected);
            assert_eq!(metadata["matched_processes"], 1);
            assert_eq!(metadata["collection"]["complete"], complete);
            assert_eq!(metadata["collection"]["output_truncated"], truncated);
            assert_eq!(metadata["collection"]["incomplete_count"], 0);
            assert_eq!(evaluator.evidence(&scan.processes[0]).net, Some(true));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn zero_deep_budget_skips_worker_and_clears_previous_probe_evidence() {
        let scan = protection_test_scan();
        let filter = ProtectedFilter::new(&[], &[], &[], &[]).unwrap();
        let mut evaluator = protection_test_evaluator(filter);
        evaluator.min_age_seconds = 0;
        evaluator.deep_records.insert(
            scan.processes[0].pid.0,
            deep_test_record(&scan.processes[0]),
        );
        let metadata = evaluator.collect_deep_evidence_with(
            &scan,
            Duration::ZERO,
            |_, _| panic!("disabled probes must never resolve or start a worker"),
            |_| panic!("disabled probes must never revalidate stale records"),
        );
        assert_eq!(metadata["status"], "disabled_by_budget");
        assert_eq!(metadata["budget_ms"], 0);
        assert_eq!(metadata["requested_processes"], scan.processes.len());
        assert_eq!(metadata["matched_processes"], 0);
        assert!(evaluator.deep_records.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn deep_scan_does_not_expand_an_empty_eligible_set_into_all_pids() {
        let scan = protection_test_scan();
        let filter = ProtectedFilter::new(&[], &[], &[], &[]).unwrap();
        let mut evaluator = protection_test_evaluator(filter);
        evaluator.collect_provenance(&scan, &[]);
        let metadata = evaluator.collect_deep_evidence_with(
            &scan,
            Duration::from_millis(DEFAULT_PROBE_BUDGET_MS),
            |_, _| panic!("an empty eligible set must never invoke an all-PID scan"),
            |_| panic!("no records to revalidate"),
        );
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
    fn scan_rejects_invalid_probe_requests_before_collection() {
        for (arguments, expected) in [
            (serde_json::json!([]), "object"),
            (serde_json::json!({"unknown": 1}), "unknown"),
            (serde_json::json!({"deep": "true"}), "deep"),
            (serde_json::json!({"min_score": -0.1}), "min_score"),
            (serde_json::json!({"min_score": 1.1}), "min_score"),
            (serde_json::json!({"min_score": "0.5"}), "min_score"),
            (serde_json::json!({"min_age": -1}), "min_age"),
            (serde_json::json!({"min_age": 1.5}), "min_age"),
            (
                serde_json::json!({"probe_budget_ms": -1}),
                "probe_budget_ms",
            ),
            (
                serde_json::json!({"probe_budget_ms": 1.5}),
                "probe_budget_ms",
            ),
            (
                serde_json::json!({"probe_budget_ms": "3"}),
                "probe_budget_ms",
            ),
            (
                serde_json::json!({"probe_budget_ms": 60_001}),
                "probe_budget_ms",
            ),
        ] {
            let error = tool_scan(&arguments).unwrap_err();
            assert!(error.contains(expected), "{arguments}: {error}");
        }
    }

    #[test]
    fn scan_and_plan_share_bounded_probe_options() {
        assert_eq!(
            probe_budget(&serde_json::json!({})).unwrap(),
            Duration::from_secs(3)
        );
        for millis in [0, 1, DEFAULT_PROBE_BUDGET_MS, MAX_PROBE_BUDGET_MS] {
            let arguments = serde_json::json!({"deep": true, "probe_budget_ms": millis});
            assert_eq!(
                probe_budget(&arguments).unwrap(),
                Duration::from_millis(millis)
            );
            let command = plan_command_args(&arguments).unwrap();
            let flag = command
                .iter()
                .position(|part| part == "--probe-budget-ms")
                .unwrap();
            assert_eq!(command[flag + 1], millis.to_string());
            assert!(command.iter().any(|part| part == "--deep"));
        }
        for invalid in [
            serde_json::json!(null),
            serde_json::json!(-1),
            serde_json::json!(60_001),
            serde_json::json!(0.5),
            serde_json::json!("0"),
        ] {
            let arguments = serde_json::json!({"probe_budget_ms": invalid});
            assert!(probe_budget(&arguments).is_err());
            assert!(plan_command_args(&arguments).is_err());
        }
        for name in ["pt_scan", "pt_plan"] {
            let definition = tool_definitions()
                .into_iter()
                .find(|tool| tool.name == name)
                .unwrap();
            assert_eq!(
                definition.input_schema["properties"]["probe_budget_ms"],
                probe_budget_schema()
            );
        }
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
        // An invalid selection threshold must not silently change the request.
        assert!(plan_command_args(&serde_json::json!({"min_score": 7.0})).is_err());
    }

    #[test]
    fn plan_tool_forwards_scoped_goals_predictions_and_literal_paths() {
        let session = pt_common::SessionId::new();
        let goal = r#"free-disk 1GB on "/tmp/Build AND $(touch must-not-run); Cache""#;
        let args = plan_command_args(&serde_json::json!({
            "goal": goal,
            "pids": [42, u32::MAX],
            "max_candidates": 5,
            "since": session.0,
            "include_predictions": true,
            "prediction_fields": ["memory", "diagnostics"],
        }))
        .unwrap();
        assert_eq!(
            args,
            vec![
                "agent".to_string(),
                "plan".to_string(),
                "--format".to_string(),
                "json".to_string(),
                "--window-ms".to_string(),
                "500".to_string(),
                "--include-predictions".to_string(),
                "--max-candidates".to_string(),
                "5".to_string(),
                format!("--pids=42,{}", u32::MAX),
                format!("--goal={goal}"),
                format!("--since={}", session.0),
                "--prediction-fields=memory,diagnostics".to_string(),
            ]
        );
        for goal in [
            "free 4GB RAM",
            "free port 3000",
            "free 100 FDs",
            "free 1GB RAM AND free port 3000",
            "relieve",
            "cpu-pressure",
            "mem-pressure",
            "io-pressure",
        ] {
            let args = plan_command_args(&serde_json::json!({
                "goal": goal,
                "since_time": "2h",
            }))
            .unwrap();
            assert!(args.contains(&format!("--goal={goal}")), "{args:?}");
            assert!(args.contains(&"--since-time=2h".to_string()), "{args:?}");
        }
    }

    #[test]
    fn plan_tool_rejects_invalid_or_ambiguous_options_before_spawning() {
        let session = pt_common::SessionId::new();
        for arguments in [
            serde_json::json!(null),
            serde_json::json!([]),
            serde_json::json!({"pid": 42}),
            serde_json::json!({"pids": []}),
            serde_json::json!({"pids": [42, 42]}),
            serde_json::json!({"pids": "42,43"}),
            serde_json::json!({"pids": [0]}),
            serde_json::json!({"pids": [-1]}),
            serde_json::json!({"pids": [u64::MAX]}),
            serde_json::json!({"pids": [0.5]}),
            serde_json::json!({"pids": ["42"]}),
            serde_json::json!({"pids": [null]}),
            serde_json::json!({"max_candidates": 0}),
            serde_json::json!({"max_candidates": u64::MAX}),
            serde_json::json!({"max_candidates": 0.5}),
            serde_json::json!({"max_candidates": "5"}),
            serde_json::json!({"min_age": -1}),
            serde_json::json!({"min_age": "60"}),
            serde_json::json!({"min_score": -0.1}),
            serde_json::json!({"min_score": 1.1}),
            serde_json::json!({"min_score": "0.9"}),
            serde_json::json!({"deep": "true"}),
            serde_json::json!({"include_predictions": 1}),
            serde_json::json!({"goal": ""}),
            serde_json::json!({"goal": " \t"}),
            serde_json::json!({"goal": "relieve\0"}),
            serde_json::json!({"goal": "free port 0"}),
            serde_json::json!({"goal": "free-disk 1GB on relative/path"}),
            serde_json::json!({"goal": "free-disk 1GB on /data AND free-disk 1GB on /tmp"}),
            serde_json::json!({"goal": ["relieve"]}),
            serde_json::json!({"since": "not-a-session"}),
            serde_json::json!({"since": session.0, "since_time": "2h"}),
            serde_json::json!({"since_time": ""}),
            serde_json::json!({"since_time": 3600}),
            serde_json::json!({"prediction_fields": ["memory"]}),
            serde_json::json!({"prediction_fields": ["memory"], "include_predictions": false}),
            serde_json::json!({"prediction_fields": [], "include_predictions": true}),
            serde_json::json!({"prediction_fields": ["memory", "memory"], "include_predictions": true}),
            serde_json::json!({"prediction_fields": ["invented"], "include_predictions": true}),
            serde_json::json!({"prediction_fields": "memory,cpu", "include_predictions": true}),
            serde_json::json!({"apply": true}),
            serde_json::json!({"yes": true}),
            serde_json::json!({"robot": false}),
            serde_json::json!({"session": session.0}),
        ] {
            assert!(call_tool("pt_plan", &arguments).is_err(), "{arguments}");
        }
        for parameter in [
            "deep",
            "min_score",
            "min_age",
            "window_ms",
            "goal",
            "pids",
            "max_candidates",
            "since",
            "since_time",
            "include_predictions",
            "prediction_fields",
        ] {
            let mut arguments = serde_json::json!({});
            arguments[parameter] = serde_json::Value::Null;
            assert!(call_tool("pt_plan", &arguments).is_err(), "{parameter}");
        }
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
        assert_eq!(
            label_command_args(&serde_json::json!({
                "pid": 123,
                "session": "pt-20260115-143022-a7xq",
                "verdict": "kill",
                "confirmed_by_user": true,
            }))
            .unwrap(),
            [
                "agent",
                "label",
                "--format",
                "json",
                "--pid",
                "123",
                "--session",
                "pt-20260115-143022-a7xq",
                "--kill"
            ]
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
            serde_json::json!({"cmd": "sleep 1", "session": "pt-20260115-143022-a7xq", "verdict": "spare", "confirmed_by_user": true}),
            serde_json::json!({"session": "pt-20260115-143022-a7xq", "verdict": "spare", "confirmed_by_user": true}),
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
        for session in [
            serde_json::json!("../pt-20260115-143022-a7xq"),
            serde_json::json!("/tmp/session"),
            serde_json::json!("--help"),
            serde_json::json!("pt-2026011é-143022-a7xq"),
            serde_json::json!("pt-20260115-143022-💣"),
            serde_json::json!(123),
            serde_json::Value::Null,
        ] {
            let error = label_command_args(&serde_json::json!({
                "pid": 123, "session": session, "verdict": "spare", "confirmed_by_user": true,
            }))
            .unwrap_err();
            assert!(error.contains("session"), "{error}");
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
        assert_eq!(schema["properties"]["session"]["type"], "string");
        assert!(schema["oneOf"][1]["not"]["anyOf"]
            .as_array()
            .unwrap()
            .iter()
            .any(|exclusion| exclusion["required"] == serde_json::json!(["session"])));
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
