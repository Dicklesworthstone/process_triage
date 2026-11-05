//! Confirmed fleet execution of retained, identity-bound remote plans.
//!
//! A fleet summary is never an execution authorization. This module retains the
//! remote documents, verifies the pooled selection again, and sends only exact
//! targets to the host's existing `agent apply` safety pipeline. A lost SSH
//! response is unknown completion; commands are never retried automatically.

use super::ssh_scan::{
    build_ssh_command_args, parse_remote_plan, scan_result_to_host_input, FleetScanResult,
    HostScanResult, SshScanConfig,
};
use crate::collect::tool_runner::ToolOutput;
use crate::decision::Action;
use crate::plan::{ActionRouting, Plan, PlanAction};
use crate::session::fleet::{create_fleet_session, FleetSession};
use pt_common::{ProcessIdentity, SessionId};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::time::Duration;

pub const FLEET_EXECUTION_VERSION: u32 = 1;
pub const MAX_FLEET_PARALLEL: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetExecutionPlan {
    pub version: u32,
    pub transport: SshScanConfig,
    pub hosts: Vec<FleetHostBinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetHostBinding {
    pub host: String,
    pub remote_session_id: Option<String>,
    pub remote_host_id: Option<String>,
    pub plan_sha256: Option<String>,
    pub selected_targets: Vec<ProcessIdentity>,
    pub document: Option<Value>,
    pub error: Option<String>,
}

/// Binding acknowledged by the remote command after checking its saved plan
/// and current host under the normal apply lock, before attempting any action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyBindingReceipt {
    pub host_id: String,
    pub session_id: String,
    pub plan_sha256: String,
}

fn canonical_value(value: &Value) -> Value {
    match value {
        Value::Object(fields) => {
            let mut keys: Vec<_> = fields.keys().collect();
            keys.sort();
            let mut ordered = serde_json::Map::new();
            for key in keys {
                ordered.insert(key.clone(), canonical_value(&fields[key]));
            }
            Value::Object(ordered)
        }
        Value::Array(values) => Value::Array(values.iter().map(canonical_value).collect()),
        _ => value.clone(),
    }
}

/// Hash the complete document, including the recorded policy and exact action
/// identities. Whitespace and object key ordering do not change the binding.
pub fn plan_document_sha256(document: &Value) -> Result<String, String> {
    let bytes = serde_json::to_vec(&canonical_value(document))
        .map_err(|error| format!("serialize retained plan: {error}"))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

pub fn validate_apply_binding(
    document: &Value,
    expected_host_id: Option<&str>,
    expected_plan_sha256: Option<&str>,
    current_host_id: &str,
) -> Result<Option<ApplyBindingReceipt>, String> {
    let (expected_host, expected_digest) = match (expected_host_id, expected_plan_sha256) {
        (None, None) => return Ok(None),
        (Some(host), Some(digest)) => (host, digest),
        _ => return Err("host and plan digest bindings must be supplied together".into()),
    };
    if expected_host.is_empty()
        || expected_digest.len() != 64
        || !expected_digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("invalid expected host or plan digest".into());
    }
    if current_host_id != expected_host || document["host_id"].as_str() != Some(expected_host) {
        return Err("current host or recorded plan host differs from the approved host".into());
    }
    let actual_digest = plan_document_sha256(document)?;
    if !actual_digest.eq_ignore_ascii_case(expected_digest) {
        return Err(
            "saved remote plan changed after fleet approval; create a new fleet plan".into(),
        );
    }
    let session_id = document["session_id"]
        .as_str()
        .filter(|session| SessionId::parse(session).is_some())
        .ok_or("remote plan has no valid saved session identity")?;
    Ok(Some(ApplyBindingReceipt {
        host_id: current_host_id.to_string(),
        session_id: session_id.to_string(),
        plan_sha256: actual_digest,
    }))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostApplyRequest {
    pub host: String,
    pub binding: ApplyBindingReceipt,
    pub targets: Vec<ProcessIdentity>,
    pub actions: Vec<PlanAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedHostApply {
    pub host: String,
    pub request: Option<HostApplyRequest>,
    pub error: Option<String>,
}

fn request_from_document(
    host: &str,
    document: &Value,
    selected_pids: &[u32],
) -> Result<HostApplyRequest, String> {
    if document["command"].as_str() != Some("agent plan") {
        return Err("remote document is not a saved agent plan".into());
    }
    let plan: Plan = serde_json::from_value(document.clone())
        .map_err(|error| format!("remote executable Plan is unavailable: {error}"))?;
    let host_id = document["host_id"]
        .as_str()
        .filter(|host| !host.is_empty())
        .ok_or("remote plan host identity is unavailable")?;
    let digest = plan_document_sha256(document)?;
    let binding = validate_apply_binding(document, Some(host_id), Some(&digest), host_id)?
        .ok_or("remote plan binding is unavailable")?;
    if plan.session_id != binding.session_id {
        return Err("remote executable plan session does not match its document".into());
    }
    let selected: HashSet<u32> = selected_pids.iter().copied().collect();
    if selected.len() != selected_pids.len() {
        return Err("duplicate approved process identity".into());
    }
    let candidates = document["candidates"]
        .as_array()
        .ok_or("remote candidate evidence is unavailable")?;
    let mut targets = Vec::new();
    for &pid in selected_pids {
        let matching: Vec<_> = candidates
            .iter()
            .filter(|candidate| candidate["pid"].as_u64() == Some(u64::from(pid)))
            .collect();
        if matching.len() != 1 {
            return Err(format!(
                "approved PID {pid} has missing or ambiguous candidate evidence"
            ));
        }
        let candidate = matching[0];
        if candidate["recommended_action"].as_str() != Some("kill") {
            return Err(format!(
                "approved PID {pid} is not an executable kill recommendation"
            ));
        }
        let target: ProcessIdentity = serde_json::from_value(candidate["action_target"].clone())
            .map_err(|_| format!("approved PID {pid} has no complete action target"))?;
        if pid <= 1
            || i32::try_from(pid).is_err()
            || target.pid.0 != pid
            || candidate["start_id"].as_str() != Some(target.start_id.0.as_str())
            || candidate["uid"].as_u64() != Some(u64::from(target.uid))
            || !target.can_safely_revalidate()
            || pt_common::StartId::parse(&target.start_id.0).is_none()
            || target
                .start_id
                .0
                .rsplit(':')
                .next()
                .and_then(|value| value.parse::<u32>().ok())
                != Some(pid)
            || target
                .start_id
                .0
                .chars()
                .any(|character| character == ',' || character.is_control())
        {
            return Err(format!(
                "approved PID {pid} has inconsistent or unusable identity evidence"
            ));
        }
        targets.push(target);
    }
    let mut actions = Vec::new();
    let mut action_ids = HashSet::new();
    for target in &targets {
        // --targets identifies (pid, start_id). Require every action selected
        // by that remote interface to agree with the complete UID-bound target.
        let matching: Vec<_> = plan
            .actions
            .iter()
            .filter(|action| {
                action.target.pid == target.pid && action.target.start_id == target.start_id
            })
            .collect();
        let kills: Vec<_> = matching
            .iter()
            .filter(|action| action.action == Action::Kill)
            .collect();
        if kills.len() != 1 {
            return Err(format!(
                "approved PID {} does not have exactly one kill action",
                target.pid.0
            ));
        }
        let kill_stage = kills[0].stage;
        for action in matching {
            if action.target != *target
                || action.blocked
                || action.routing != ActionRouting::Direct
                || action.original_zombie_target.is_some()
                || !(action.action == Action::Kill
                    || (action.action == Action::Pause && action.stage < kill_stage))
                || !action_ids.insert(action.action_id.clone())
            {
                return Err(format!(
                    "approved PID {} has an unsafe or ambiguous action sequence",
                    target.pid.0
                ));
            }
            actions.push(action.clone());
        }
    }
    actions.sort_by_key(|action| action.order);
    Ok(HostApplyRequest {
        host: host.to_string(),
        binding,
        targets,
        actions,
    })
}

pub fn bind_fleet_execution(
    fleet: &FleetSession,
    scan: &FleetScanResult,
    transport: &SshScanConfig,
) -> FleetExecutionPlan {
    let hosts = fleet
        .hosts
        .iter()
        .map(|host| {
            let observed = scan
                .results
                .iter()
                .find(|result| result.host == host.host_id);
            let document = observed
                .and_then(|result| result.plan.as_ref())
                .and_then(|plan| plan.document.clone());
            let prepared = document.as_ref().map(|document| {
                request_from_document(&host.host_id, document, &host.selected_kill_pids)
            });
            let request = prepared.as_ref().and_then(|result| result.as_ref().ok());
            FleetHostBinding {
                host: host.host_id.clone(),
                remote_session_id: request.map(|request| request.binding.session_id.clone()),
                remote_host_id: request.map(|request| request.binding.host_id.clone()),
                plan_sha256: document
                    .as_ref()
                    .and_then(|document| plan_document_sha256(document).ok()),
                selected_targets: request
                    .map(|request| request.targets.clone())
                    .unwrap_or_default(),
                error: prepared.and_then(Result::err).or_else(|| {
                    observed
                        .and_then(|result| result.error.clone())
                        .or_else(|| {
                            document
                                .is_none()
                                .then(|| "complete remote plan was not retained".to_string())
                        })
                }),
                document,
            }
        })
        .collect();
    FleetExecutionPlan {
        version: FLEET_EXECUTION_VERSION,
        transport: transport.clone(),
        hosts,
    }
}

/// Validate every local binding before starting any SSH command. Recompute
/// pooled approval from retained evidence; counts alone never identify targets.
pub fn prepare_fleet_apply(fleet: &FleetSession) -> Result<Vec<PreparedHostApply>, String> {
    if SessionId::parse(&fleet.fleet_session_id).is_none() {
        return Err("invalid fleet session identity".into());
    }
    if !fleet.safety_budget.max_fdr.is_finite()
        || !(0.0..=1.0).contains(&fleet.safety_budget.max_fdr)
    {
        return Err("invalid fleet safety budget".into());
    }
    let execution = fleet
        .execution
        .as_ref()
        .ok_or("fleet session contains summaries only; create a new fleet plan before applying")?;
    if execution.version != FLEET_EXECUTION_VERSION || execution.hosts.len() != fleet.hosts.len() {
        return Err("fleet execution binding version or host set does not match".into());
    }
    let mut endpoints = HashSet::new();
    let mut reconstructed = Vec::new();
    for (host, binding) in fleet.hosts.iter().zip(&execution.hosts) {
        if host.host_id != binding.host || !endpoints.insert(&binding.host) {
            return Err("fleet host selection changed or contains duplicate endpoints".into());
        }
        build_ssh_command_args(
            &binding.host,
            &execution.transport,
            std::slice::from_ref(&execution.transport.remote_binary),
        )?;
        let plan = if let Some(document) = &binding.document {
            if binding.plan_sha256.as_deref() != Some(plan_document_sha256(document)?.as_str()) {
                return Err(format!("retained plan digest changed for {}", binding.host));
            }
            Some(parse_remote_plan(
                &serde_json::to_string(document).map_err(|error| error.to_string())?,
            )?)
        } else {
            if !binding.selected_targets.is_empty() || binding.plan_sha256.is_some() {
                return Err(format!(
                    "{} has targets without a retained plan",
                    binding.host
                ));
            }
            None
        };
        if let Some(plan) = &plan {
            let pids: HashSet<u32> = plan
                .candidates
                .iter()
                .map(|candidate| candidate.pid)
                .collect();
            if pids.len() != plan.candidates.len() {
                return Err(format!(
                    "{} has duplicate candidate identities",
                    binding.host
                ));
            }
        }
        reconstructed.push(scan_result_to_host_input(&HostScanResult {
            host: binding.host.clone(),
            success: plan.is_some(),
            plan,
            error: binding.error.clone(),
            duration_ms: 0,
            provenance: None,
        }));
    }
    let expected = create_fleet_session(
        &fleet.fleet_session_id,
        fleet.label.as_deref(),
        &reconstructed,
        fleet.safety_budget.max_fdr,
    );
    let mut remote_hosts = HashSet::new();
    let mut prepared = Vec::new();
    for ((host, binding), expected_host) in fleet
        .hosts
        .iter()
        .zip(&execution.hosts)
        .zip(&expected.hosts)
    {
        if host.session_id != expected_host.session_id
            || host.selected_kill_pids != expected_host.selected_kill_pids
        {
            return Err(format!(
                "{} session or pooled-approved selection changed",
                host.host_id
            ));
        }
        let request = binding.document.as_ref().map(|document| {
            request_from_document(&host.host_id, document, &host.selected_kill_pids)
        });
        match request {
            Some(Ok(request)) => {
                if binding.remote_session_id.as_deref() != Some(request.binding.session_id.as_str())
                    || binding.remote_host_id.as_deref() != Some(request.binding.host_id.as_str())
                    || binding.selected_targets != request.targets
                    || binding.error.is_some()
                {
                    return Err(format!(
                        "{} executable selection no longer matches its binding",
                        host.host_id
                    ));
                }
                if !remote_hosts.insert(request.binding.host_id.clone()) {
                    return Err(
                        "multiple endpoints resolve to the same recorded remote host".into(),
                    );
                }
                prepared.push(PreparedHostApply {
                    host: host.host_id.clone(),
                    request: Some(request),
                    error: None,
                });
            }
            Some(Err(error)) if !host.selected_kill_pids.is_empty() => {
                return Err(format!(
                    "{} cannot execute its pooled-approved selection: {error}; refusing the whole fleet because excluding it would change the approved FDR set",
                    host.host_id
                ));
            }
            Some(Err(error)) => prepared.push(PreparedHostApply {
                host: host.host_id.clone(),
                request: None,
                error: Some(error),
            }),
            None => prepared.push(PreparedHostApply {
                host: host.host_id.clone(),
                request: None,
                error: binding
                    .error
                    .clone()
                    .or_else(|| Some("remote plan unavailable".into())),
            }),
        }
    }
    Ok(prepared)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetApplyConfig {
    pub confirmed: bool,
    pub dry_run: bool,
    pub parallel: usize,
    pub timeout_secs: u64,
    pub continue_on_error: bool,
    pub max_kills_per_host: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostApplyStatus {
    Preview,
    NoActions,
    Applied,
    Partial,
    Blocked,
    Unknown,
    NotStarted,
}

impl HostApplyStatus {
    pub fn is_failure(self) -> bool {
        matches!(
            self,
            Self::Partial | Self::Blocked | Self::Unknown | Self::NotStarted
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostApplyResult {
    pub host: String,
    pub binding: Option<ApplyBindingReceipt>,
    pub selected_targets: Vec<ProcessIdentity>,
    pub status: HostApplyStatus,
    pub attempted: bool,
    pub successful_actions: usize,
    pub kill_signals_delivered: usize,
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    pub error: Option<String>,
    pub remote_response: Option<Value>,
}

impl HostApplyResult {
    fn new(prepared: &PreparedHostApply, status: HostApplyStatus) -> Self {
        Self {
            host: prepared.host.clone(),
            binding: prepared
                .request
                .as_ref()
                .map(|request| request.binding.clone()),
            selected_targets: prepared
                .request
                .as_ref()
                .map(|request| request.targets.clone())
                .unwrap_or_default(),
            status,
            attempted: false,
            successful_actions: 0,
            kill_signals_delivered: 0,
            exit_code: None,
            duration_ms: 0,
            error: prepared.error.clone(),
            remote_response: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetApplyReport {
    pub hosts: Vec<HostApplyResult>,
    pub persistence_error: Option<String>,
}

pub fn remote_apply_args(
    request: &HostApplyRequest,
    transport: &SshScanConfig,
    config: &FleetApplyConfig,
) -> Result<Vec<String>, String> {
    if request.targets.is_empty() {
        return Err("empty target set must never invoke remote apply".into());
    }
    if request.targets.len() > config.max_kills_per_host as usize {
        return Err(format!(
            "{} approved kills exceed per-host cap {}",
            request.targets.len(),
            config.max_kills_per_host
        ));
    }
    let targets = request
        .targets
        .iter()
        .map(|target| format!("{}:{}", target.pid.0, target.start_id.0))
        .collect::<Vec<_>>()
        .join(",");
    let mut transport = transport.clone();
    // Planning can enroll a new host key. Destructive commands must require
    // the key already observed during that planning connection.
    transport.ssh_options.retain(|option| {
        let key = option.split('=').next().unwrap_or_default();
        !key.eq_ignore_ascii_case("StrictHostKeyChecking") && !key.eq_ignore_ascii_case("BatchMode")
    });
    transport
        .ssh_options
        .insert(0, "StrictHostKeyChecking=yes".into());
    transport.ssh_options.insert(1, "BatchMode=yes".into());
    transport.connect_timeout = transport.connect_timeout.min(config.timeout_secs).max(1);
    build_ssh_command_args(
        &request.host,
        &transport,
        &[
            transport.remote_binary.clone(),
            "--format".into(),
            "json".into(),
            "--robot".into(),
            "agent".into(),
            "apply".into(),
            "--session".into(),
            request.binding.session_id.clone(),
            "--targets".into(),
            targets,
            "--expected-host-id".into(),
            request.binding.host_id.clone(),
            "--expected-plan-sha256".into(),
            request.binding.plan_sha256.clone(),
            "--max-kills".into(),
            config.max_kills_per_host.to_string(),
            "--yes".into(),
            "--resume".into(),
            "--abort-on-unknown".into(),
        ],
    )
}

fn interpret_remote_result(prepared: &PreparedHostApply, output: ToolOutput) -> HostApplyResult {
    let mut result = HostApplyResult::new(prepared, HostApplyStatus::Unknown);
    result.attempted = true;
    result.exit_code = output.exit_code;
    result.duration_ms = u64::try_from(output.duration.as_millis()).unwrap_or(u64::MAX);
    if output.timed_out || output.truncated {
        result.error =
            Some("SSH timed out or truncated its response; remote completion is unknown".into());
        return result;
    }
    let document: Value = match serde_json::from_slice(&output.stdout) {
        Ok(document) => document,
        Err(error) => {
            result.error = Some(format!(
                "remote response unavailable ({error}); completion is unknown: {}",
                output.stderr_str().trim()
            ));
            return result;
        }
    };
    result.remote_response = Some(document.clone());
    let Some(request) = prepared.request.as_ref() else {
        return result;
    };
    // A remote host cannot acknowledge a binding it rejected. It can still
    // prove that the requested binding was refused before any action began.
    let refused_binding: Option<ApplyBindingReceipt> =
        serde_json::from_value(document["expected_execution_binding"].clone()).ok();
    if output.exit_code == Some(4)
        && document["session_id"].as_str() == Some(request.binding.session_id.as_str())
        && document["mode"] == "robot_apply"
        && document["status"] == "blocked"
        && document["error"] == "fleet_binding_mismatch"
        && refused_binding.as_ref() == Some(&request.binding)
        && document["outcomes"].as_array().is_some_and(Vec::is_empty)
    {
        result.status = HostApplyStatus::Blocked;
        result.error = Some(format!(
            "remote host refused the approved binding before execution: {}",
            document["reason"].as_str().unwrap_or("binding mismatch")
        ));
        return result;
    }
    let binding: Option<ApplyBindingReceipt> =
        serde_json::from_value(document["execution_binding"].clone()).ok();
    if document["session_id"].as_str() != Some(request.binding.session_id.as_str())
        || document["mode"].as_str() != Some("robot_apply")
        || binding.as_ref() != Some(&request.binding)
    {
        result.error = Some(
            "remote response did not acknowledge the approved host, session and plan binding"
                .into(),
        );
        return result;
    }
    let Some(outcomes) = document["outcomes"].as_array() else {
        result.error = Some("remote response has no action outcomes; completion is unknown".into());
        return result;
    };
    if outcomes.is_empty() && output.exit_code == Some(0) && document["note"] == "nothing_to_do" {
        result.status = HostApplyStatus::NoActions;
        return result;
    }
    if outcomes.is_empty()
        && output.exit_code == Some(4)
        && document["status"] == "blocked"
        && document["error"].is_string()
    {
        result.status = HostApplyStatus::Blocked;
        result.error = Some(format!(
            "remote apply refused execution: {}",
            document["error"].as_str().unwrap()
        ));
        return result;
    }
    let actions: HashMap<&str, &PlanAction> = request
        .actions
        .iter()
        .map(|action| (action.action_id.as_str(), action))
        .collect();
    let mut seen = HashSet::new();
    let mut successes = 0;
    let mut delivered = 0;
    let mut refused = 0;
    for outcome in outcomes {
        let Some(action) = outcome["action_id"]
            .as_str()
            .and_then(|id| actions.get(id).copied())
        else {
            result.error =
                Some("remote outcome refers to an action outside the approved selection".into());
            return result;
        };
        if !seen.insert(action.action_id.as_str())
            || outcome["pid"].as_u64() != Some(u64::from(action.target.pid.0))
        {
            result.error = Some("remote outcome has a duplicate action or mismatched PID".into());
            return result;
        }
        let success = outcome["status"].as_str() == Some("success");
        let signaled = outcome["kill_signal_delivered"].as_bool() == Some(true);
        if success || signaled {
            let identity: Option<ProcessIdentity> =
                serde_json::from_value(outcome["target"].clone()).ok();
            let remedy: Option<Action> = serde_json::from_value(outcome["action"].clone()).ok();
            if identity.as_ref() != Some(&action.target) || remedy != Some(action.action) {
                result.error =
                    Some("reported execution lacks matching target and action evidence".into());
                return result;
            }
        }
        successes += usize::from(success);
        delivered += usize::from(signaled && action.action == Action::Kill);
        refused += usize::from(matches!(
            outcome["status"].as_str(),
            Some(
                "blocked_by_plan"
                    | "blocked_by_policy"
                    | "blocked_by_constraints"
                    | "precheck_blocked"
                    | "identity_mismatch"
                    | "identity_check_failed"
                    | "dry_run"
                    | "shadow"
                    | "unsupported_platform"
            )
        ));
    }
    result.successful_actions = successes;
    result.kill_signals_delivered = delivered;
    result.status = if successes == actions.len() && output.exit_code == Some(2) {
        HostApplyStatus::Applied
    } else if !outcomes.is_empty() && refused == outcomes.len() && delivered == 0 {
        HostApplyStatus::Blocked
    } else if successes > 0 || delivered > 0 {
        HostApplyStatus::Partial
    } else {
        HostApplyStatus::Unknown
    };
    if result.status.is_failure() {
        result.error = Some("not all approved actions have confirmed successful outcomes; inspect the remote receipt before retrying".into());
    }
    result
}

/// Execute bounded batches through an injectable transport. Results are kept
/// in host order; failure stops later batches unless explicitly overridden.
/// Receipt failure always stops subsequent batches, regardless of that flag.
pub fn execute_fleet_apply_with<E, R>(
    prepared: &[PreparedHostApply],
    transport: &SshScanConfig,
    config: &FleetApplyConfig,
    executor: E,
    mut record: R,
) -> FleetApplyReport
where
    E: Fn(&HostApplyRequest, &[String], Duration) -> Result<ToolOutput, String> + Sync,
    R: FnMut(&HostApplyResult) -> Result<(), String>,
{
    let execute = config.confirmed && !config.dry_run;
    // Pooled approval covers the complete selected set. A known local exclusion
    // can remove its most confident contributors and invalidate the remaining
    // set's expected FDR. Refuse every dispatch before starting any worker;
    // --continue-on-error cannot turn a known exclusion into partial approval.
    let preflight_refusal = prepared.iter().find_map(|host| {
        let local_error = if let Some(error) = &host.error {
            Some(error.clone())
        } else {
            match &host.request {
                None => Some("retained remote execution request is unavailable".to_string()),
                Some(request) if request.targets.is_empty() => None,
                Some(request) => remote_apply_args(request, transport, config).err(),
            }
        };
        local_error.map(|error| {
                format!(
                    "{}: {error}; no hosts started because a local refusal could change the approved FDR set",
                    host.host
                )
        })
    });
    let mut report = FleetApplyReport {
        hosts: Vec::new(),
        persistence_error: None,
    };
    let mut stopped = false;
    for batch in prepared.chunks(config.parallel.clamp(1, MAX_FLEET_PARALLEL)) {
        let results = std::thread::scope(|scope| {
            let handles: Vec<_> = batch
                .iter()
                .map(|host| {
                    let executor = &executor;
                    let preflight_refusal = &preflight_refusal;
                    scope.spawn(move || {
                        if let Some(error) = preflight_refusal {
                            let mut result = HostApplyResult::new(host, HostApplyStatus::Blocked);
                            result.error = Some(error.clone());
                            return result;
                        }
                        if stopped {
                            let mut result =
                                HostApplyResult::new(host, HostApplyStatus::NotStarted);
                            result.error =
                                Some("not started after an earlier host or receipt failure".into());
                            return result;
                        }
                        let Some(request) = &host.request else {
                            return HostApplyResult::new(host, HostApplyStatus::Blocked);
                        };
                        if request.targets.is_empty() {
                            return HostApplyResult::new(host, HostApplyStatus::NoActions);
                        }
                        let args = match remote_apply_args(request, transport, config) {
                            Ok(args) => args,
                            Err(error) => {
                                let mut result =
                                    HostApplyResult::new(host, HostApplyStatus::Blocked);
                                result.error = Some(error);
                                return result;
                            }
                        };
                        if !execute {
                            return HostApplyResult::new(host, HostApplyStatus::Preview);
                        }
                        match executor(
                            request,
                            &args,
                            Duration::from_secs(config.timeout_secs.max(1)),
                        ) {
                            Ok(output) => interpret_remote_result(host, output),
                            Err(error) => {
                                let mut result =
                                    HostApplyResult::new(host, HostApplyStatus::Unknown);
                                result.attempted = true;
                                result.error = Some(format!(
                                    "SSH transport failed; remote completion is unknown: {error}"
                                ));
                                result
                            }
                        }
                    })
                })
                .collect();
            handles
                .into_iter()
                .zip(batch)
                .map(|(handle, host)| {
                    handle.join().unwrap_or_else(|_| {
                        let mut result = HostApplyResult::new(host, HostApplyStatus::Unknown);
                        result.attempted = execute;
                        result.error =
                            Some("transport worker panicked; remote completion is unknown".into());
                        result
                    })
                })
                .collect::<Vec<_>>()
        });
        for result in results {
            if execute && result.status.is_failure() && !config.continue_on_error {
                stopped = true;
            }
            if report.persistence_error.is_none() {
                if let Err(error) = record(&result) {
                    report.persistence_error = Some(error);
                    stopped = true;
                }
            }
            report.hosts.push(result);
        }
    }
    report
}

pub fn execute_fleet_apply(
    prepared: &[PreparedHostApply],
    transport: &SshScanConfig,
    config: &FleetApplyConfig,
    record: impl FnMut(&HostApplyResult) -> Result<(), String>,
) -> FleetApplyReport {
    execute_fleet_apply_with(
        prepared,
        transport,
        config,
        |_, args, timeout| {
            let args: Vec<&str> = args.iter().map(String::as_str).collect();
            crate::collect::tool_runner::run_tool("ssh", &args, Some(timeout), None)
                .map_err(|error| error.to_string())
        },
        record,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::ActionTimeouts;
    use pt_common::StartId;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    fn remote_document(host: &str, rows: &[(u32, f64)]) -> Value {
        let mut actions = Vec::new();
        let mut candidates = Vec::new();
        for (order, &(pid, probability)) in rows.iter().enumerate() {
            let target =
                ProcessIdentity::new(pid, StartId::from_linux("fixture-boot", 42, pid), 1000);
            let action_id = format!("kill-{pid}");
            actions.push(serde_json::json!({
                "action_id": action_id,
                "target": target,
                "action": "kill",
                "order": order,
                "stage": 0,
                "timeouts": ActionTimeouts::default(),
                "pre_checks": [],
                "rationale": {},
                "on_success": [],
                "on_failure": [],
                "blocked": false,
            }));
            candidates.push(serde_json::json!({
                "pid": pid,
                "start_id": target.start_id,
                "uid": target.uid,
                "action_target": target,
                "recommended_action": "kill",
                "recommendation": "KILL",
                "command_short": "fixture-worker",
                "classification": "abandoned",
                "posterior": {"useful": 1.0 - probability, "useful_bad": 0.0, "abandoned": probability, "zombie": 0.0},
            }));
        }
        serde_json::json!({
            "command": "agent plan",
            "host_id": format!("machine-{host}"),
            "session_id": "pt-20261105-120000-abcd",
            "plan_id": format!("plan-{host}"),
            "pt_version": env!("CARGO_PKG_VERSION"),
            "generated_at": "2026-11-05T12:00:00Z",
            "policy_id": null,
            "policy_version": "1.0.0",
            "actions": actions,
            "pre_toggled": rows.iter().map(|(pid, _)| format!("kill-{pid}")).collect::<Vec<_>>(),
            "gates_summary": {"total_candidates": rows.len(), "blocked_candidates": 0, "pre_toggled_actions": rows.len()},
            "summary": {"total_processes_scanned": rows.len()},
            "candidates": candidates,
            "policy_snapshot": {"guardrails": {"max_kills_per_run": 3}},
        })
    }

    fn retained_fleet(documents: Vec<(&str, Value)>) -> FleetSession {
        retained_fleet_with_budget(documents, 0.05)
    }

    fn retained_fleet_with_budget(documents: Vec<(&str, Value)>, max_fdr: f64) -> FleetSession {
        let results: Vec<_> = documents
            .into_iter()
            .map(|(host, document)| HostScanResult {
                host: host.to_string(),
                success: true,
                plan: Some(parse_remote_plan(&document.to_string()).unwrap()),
                error: None,
                duration_ms: 1,
                provenance: None,
            })
            .collect();
        let scan = FleetScanResult {
            total_hosts: results.len(),
            successful: results.len(),
            failed: 0,
            results,
            duration_ms: 1,
            provenance_aggregate: None,
        };
        let inputs: Vec<_> = scan.results.iter().map(scan_result_to_host_input).collect();
        let mut fleet = create_fleet_session("pt-20261105-120001-efgh", None, &inputs, max_fdr);
        fleet.execution = Some(bind_fleet_execution(
            &fleet,
            &scan,
            &SshScanConfig::default(),
        ));
        fleet
    }

    fn config() -> FleetApplyConfig {
        FleetApplyConfig {
            confirmed: true,
            dry_run: false,
            parallel: 1,
            timeout_secs: 30,
            continue_on_error: false,
            max_kills_per_host: 3,
        }
    }

    fn result_output(request: &HostApplyRequest, status: &str, exit_code: i32) -> ToolOutput {
        let outcomes: Vec<_> = request
            .actions
            .iter()
            .map(|action| {
                serde_json::json!({
                    "action_id": action.action_id,
                    "pid": action.target.pid.0,
                    "action": action.action,
                    "target": action.target,
                    "status": status,
                    "kill_signal_delivered": status == "success" && action.action == Action::Kill,
                })
            })
            .collect();
        ToolOutput {
            command: "fake-ssh".into(),
            args: Vec::new(),
            stdout: serde_json::to_vec(&serde_json::json!({
                "session_id": request.binding.session_id,
                "mode": "robot_apply",
                "execution_binding": request.binding,
                "outcomes": outcomes,
            }))
            .unwrap(),
            stderr: Vec::new(),
            exit_code: Some(exit_code),
            truncated: false,
            duration: Duration::from_millis(12),
            timed_out: false,
        }
    }

    #[test]
    fn retained_fleet_keeps_real_session_and_exact_pooled_selection() {
        let fleet = retained_fleet(vec![
            (
                "alpha",
                remote_document("alpha", &[(101, 0.999), (102, 0.4)]),
            ),
            ("beta", remote_document("beta", &[(101, 0.999)])),
        ]);
        assert_eq!(fleet.safety_budget.pooled_fdr.selected_kills, 2);
        assert_eq!(fleet.hosts[0].selected_kill_pids, [101]);
        assert_eq!(fleet.hosts[0].session_id, "pt-20261105-120000-abcd");
        let restored: FleetSession =
            serde_json::from_str(&serde_json::to_string(&fleet).unwrap()).unwrap();
        let prepared = prepare_fleet_apply(&restored).unwrap();
        assert_eq!(prepared.len(), 2);
        for host in prepared {
            let request = host.request.unwrap();
            assert_eq!(request.targets.len(), 1);
            assert_eq!(request.targets[0].pid.0, 101);
            assert_eq!(request.targets[0].uid, 1000);
            assert_eq!(request.actions.len(), 1);
        }
        let mut legacy = restored;
        legacy.execution = None;
        assert!(prepare_fleet_apply(&legacy)
            .unwrap_err()
            .contains("summaries only"));
    }

    #[test]
    fn binding_checks_current_host_complete_plan_and_policy() {
        let document = remote_document("alpha", &[(101, 0.999)]);
        let digest = plan_document_sha256(&document).unwrap();
        let bound = validate_apply_binding(
            &document,
            Some("machine-alpha"),
            Some(&digest),
            "machine-alpha",
        )
        .unwrap()
        .unwrap();
        assert_eq!(bound.session_id, "pt-20261105-120000-abcd");
        assert!(validate_apply_binding(
            &document,
            Some("machine-alpha"),
            Some(&digest),
            "machine-beta"
        )
        .is_err());
        assert!(
            validate_apply_binding(&document, Some("machine-alpha"), None, "machine-alpha")
                .is_err()
        );
        assert!(validate_apply_binding(&document, None, None, "unrelated")
            .unwrap()
            .is_none());
        for field in ["policy", "target", "session"] {
            let mut changed = document.clone();
            match field {
                "policy" => {
                    changed["policy_snapshot"]["guardrails"]["max_kills_per_run"] =
                        serde_json::json!(99)
                }
                "target" => changed["actions"][0]["target"]["uid"] = serde_json::json!(0),
                _ => changed["session_id"] = serde_json::json!("pt-20261105-120001-zzzz"),
            }
            assert!(
                validate_apply_binding(
                    &changed,
                    Some("machine-alpha"),
                    Some(&digest),
                    "machine-alpha"
                )
                .is_err(),
                "{field}"
            );
        }
        let pretty = serde_json::to_string_pretty(&document).unwrap();
        assert_eq!(
            plan_document_sha256(&serde_json::from_str(&pretty).unwrap()).unwrap(),
            digest
        );
    }

    #[test]
    fn preparation_refuses_selection_host_identity_or_document_drift() {
        let original = retained_fleet(vec![(
            "alpha",
            remote_document("alpha", &[(101, 0.999), (102, 0.4)]),
        )]);
        for drift in [
            "selection",
            "uid",
            "document",
            "endpoint",
            "session",
            "budget",
        ] {
            let mut fleet = original.clone();
            match drift {
                "selection" => fleet.hosts[0].selected_kill_pids.push(102),
                "uid" => fleet.execution.as_mut().unwrap().hosts[0].selected_targets[0].uid = 0,
                "document" => {
                    fleet.execution.as_mut().unwrap().hosts[0]
                        .document
                        .as_mut()
                        .unwrap()["policy_snapshot"] = serde_json::json!({})
                }
                "endpoint" => fleet.execution.as_mut().unwrap().hosts[0].host = "beta".into(),
                "session" => fleet.hosts[0].session_id = "pt-20261105-120001-zzzz".into(),
                _ => fleet.safety_budget.max_fdr = f64::NAN,
            }
            assert!(prepare_fleet_apply(&fleet).is_err(), "{drift}");
        }
        let duplicate = retained_fleet(vec![
            ("alpha", remote_document("same-machine", &[(101, 0.999)])),
            ("beta", remote_document("same-machine", &[(201, 0.999)])),
        ]);
        assert!(prepare_fleet_apply(&duplicate)
            .unwrap_err()
            .contains("same recorded remote host"));
    }

    #[test]
    fn unsafe_remote_action_sequences_never_become_requests() {
        for refusal in [
            "uid",
            "start",
            "malformed_start",
            "embedded_pid",
            "zero_pid",
            "init_pid",
            "overflow_pid",
            "blocked",
            "zombie",
            "dstate",
            "other_action",
            "missing_identity",
        ] {
            let pid = match refusal {
                "zero_pid" => 0,
                "init_pid" => 1,
                "overflow_pid" => u32::MAX,
                _ => 101,
            };
            let mut document = remote_document("alpha", &[(pid, 0.999)]);
            match refusal {
                "uid" => document["candidates"][0]["uid"] = serde_json::json!(0),
                "start" => document["candidates"][0]["start_id"] = serde_json::json!("recycled"),
                "malformed_start" | "embedded_pid" => {
                    let start_id = if refusal == "malformed_start" {
                        "malformed"
                    } else {
                        "fixture-boot:42:999"
                    };
                    document["candidates"][0]["start_id"] = serde_json::json!(start_id);
                    document["candidates"][0]["action_target"]["start_id"] =
                        serde_json::json!(start_id);
                    document["actions"][0]["target"]["start_id"] = serde_json::json!(start_id);
                }
                "zero_pid" | "init_pid" | "overflow_pid" => {}
                "blocked" => document["actions"][0]["blocked"] = serde_json::json!(true),
                "zombie" => {
                    document["actions"][0]["routing"] = serde_json::json!("zombie_to_parent")
                }
                "dstate" => {
                    document["actions"][0]["routing"] = serde_json::json!("d_state_low_confidence")
                }
                "other_action" => {
                    let mut extra = document["actions"][0].clone();
                    extra["action"] = serde_json::json!("renice");
                    extra["action_id"] = serde_json::json!("unapproved-renice");
                    document["actions"].as_array_mut().unwrap().push(extra);
                }
                _ => {
                    document["candidates"][0]
                        .as_object_mut()
                        .unwrap()
                        .remove("action_target");
                }
            }
            let fleet = retained_fleet(vec![("alpha", document)]);
            assert!(prepare_fleet_apply(&fleet).is_err(), "{refusal}");
        }
    }

    #[test]
    fn known_host_exclusion_never_dispatches_an_unsafe_pooled_subset() {
        // All three pass pooled alpha=.002: (.005 + .0001 + .0001) / 3.
        // Omitting beta's two targets leaves alpha alone at .005, above budget.
        let fleet = retained_fleet_with_budget(
            vec![
                ("alpha", remote_document("alpha", &[(101, 0.995)])),
                (
                    "beta",
                    remote_document("beta", &[(201, 0.9999), (202, 0.9999)]),
                ),
            ],
            0.002,
        );
        assert_eq!(fleet.safety_budget.pooled_fdr.selected_kills, 3);
        let prepared = prepare_fleet_apply(&fleet).unwrap();
        for continue_on_error in [false, true] {
            let calls = AtomicUsize::new(0);
            let options = FleetApplyConfig {
                max_kills_per_host: 1,
                continue_on_error,
                ..config()
            };
            let report = execute_fleet_apply_with(
                &prepared,
                &fleet.execution.as_ref().unwrap().transport,
                &options,
                |request, _, _| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    Ok(result_output(request, "success", 2))
                },
                |_| Ok(()),
            );
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert!(report
                .hosts
                .iter()
                .all(|host| host.status == HostApplyStatus::Blocked && !host.attempted));
            assert!(report.hosts[0]
                .error
                .as_deref()
                .unwrap()
                .contains("approved FDR set"));
        }

        let mut invalid_beta = remote_document("beta", &[(201, 0.9999), (202, 0.9999)]);
        invalid_beta["actions"][0]["blocked"] = serde_json::json!(true);
        let invalid = retained_fleet_with_budget(
            vec![
                ("alpha", remote_document("alpha", &[(101, 0.995)])),
                ("beta", invalid_beta),
            ],
            0.002,
        );
        assert!(prepare_fleet_apply(&invalid)
            .unwrap_err()
            .contains("refusing the whole fleet"));

        // Even a failed host with no approved kills is a known batch-stopping
        // condition. It must not stop later hosts only after an earlier kill.
        let mut missing_host = prepared.clone();
        missing_host.insert(
            1,
            PreparedHostApply {
                host: "missing".into(),
                request: None,
                error: Some("planning failed; zero approved kills".into()),
            },
        );
        for continue_on_error in [false, true] {
            let options = FleetApplyConfig {
                continue_on_error,
                ..config()
            };
            let report = execute_fleet_apply_with(
                &missing_host,
                &fleet.execution.as_ref().unwrap().transport,
                &options,
                |_, _, _| panic!("known missing host must refuse before any SSH dispatch"),
                |_| Ok(()),
            );
            assert_eq!(report.hosts.len(), 3);
            assert!(report
                .hosts
                .iter()
                .all(|host| host.status == HostApplyStatus::Blocked && !host.attempted));
        }
    }

    #[test]
    fn default_preview_dry_run_and_host_cap_never_dispatch() {
        let fleet = retained_fleet(vec![(
            "alpha",
            remote_document("alpha", &[(101, 0.999), (102, 0.999)]),
        )]);
        let prepared = prepare_fleet_apply(&fleet).unwrap();
        let transport = &fleet.execution.as_ref().unwrap().transport;
        for (confirmed, dry_run, max_kills, expected) in [
            (false, false, 3, HostApplyStatus::Preview),
            (true, true, 3, HostApplyStatus::Preview),
            (true, false, 1, HostApplyStatus::Blocked),
        ] {
            let options = FleetApplyConfig {
                confirmed,
                dry_run,
                max_kills_per_host: max_kills,
                ..config()
            };
            let report = execute_fleet_apply_with(
                &prepared,
                transport,
                &options,
                |_, _, _| panic!("preview or cap refusal must not dispatch SSH"),
                |_| Ok(()),
            );
            assert_eq!(report.hosts[0].status, expected);
            assert!(!report.hosts[0].attempted);
            assert_eq!(report.hosts[0].successful_actions, 0);
        }
    }

    #[test]
    fn confirmed_apply_passes_only_exact_approved_targets_and_bound_receipts() {
        let fleet = retained_fleet(vec![(
            "alpha",
            remote_document("alpha", &[(101, 0.999), (102, 0.4)]),
        )]);
        let prepared = prepare_fleet_apply(&fleet).unwrap();
        let calls = Mutex::new(Vec::new());
        let mut receipts = Vec::new();
        let report = execute_fleet_apply_with(
            &prepared,
            &fleet.execution.as_ref().unwrap().transport,
            &config(),
            |request, args, timeout| {
                assert_eq!(timeout, Duration::from_secs(30));
                let command = args.last().unwrap();
                assert!(command.contains("--targets 101:fixture-boot:42:101"));
                assert!(!command.contains("--recommended"));
                assert!(!command.contains("102:"));
                assert!(command.contains("--expected-host-id machine-alpha"));
                assert!(command.contains(&request.binding.plan_sha256));
                assert!(command.contains("--max-kills 3"));
                assert!(command.contains("--yes --resume --abort-on-unknown"));
                assert!(args.contains(&"StrictHostKeyChecking=yes".to_string()));
                calls.lock().unwrap().push(request.targets.clone());
                Ok(result_output(request, "success", 2))
            },
            |receipt| {
                receipts.push(receipt.clone());
                Ok(())
            },
        );
        assert_eq!(calls.lock().unwrap().len(), 1);
        assert_eq!(report.hosts[0].status, HostApplyStatus::Applied);
        assert_eq!(report.hosts[0].successful_actions, 1);
        assert_eq!(report.hosts[0].kill_signals_delivered, 1);
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].binding, report.hosts[0].binding);
    }

    #[test]
    fn timeout_and_forged_or_empty_receipts_do_not_claim_success() {
        let fleet = retained_fleet(vec![("alpha", remote_document("alpha", &[(101, 0.999)]))]);
        let prepared = prepare_fleet_apply(&fleet).unwrap();
        let request = prepared[0].request.as_ref().unwrap();
        for failure in [
            "timeout",
            "truncated",
            "empty",
            "host",
            "session",
            "digest",
            "target",
            "extra_action",
            "exit_only",
        ] {
            let mut output = result_output(request, "success", 2);
            let mut response: Value = serde_json::from_slice(&output.stdout).unwrap();
            match failure {
                "timeout" => output.timed_out = true,
                "truncated" => output.truncated = true,
                "empty" => response = serde_json::json!({}),
                "host" => {
                    response["execution_binding"]["host_id"] = serde_json::json!("machine-other")
                }
                "session" => response["session_id"] = serde_json::json!("pt-20261105-120001-zzzz"),
                "digest" => {
                    response["execution_binding"]["plan_sha256"] = serde_json::json!("0".repeat(64))
                }
                "target" => response["outcomes"][0]["target"]["uid"] = serde_json::json!(0),
                "extra_action" => {
                    response["outcomes"][0]["action_id"] = serde_json::json!("unapproved")
                }
                _ => {
                    response["outcomes"] = serde_json::json!([]);
                    output.exit_code = Some(0);
                }
            }
            output.stdout = serde_json::to_vec(&response).unwrap();
            let result = interpret_remote_result(&prepared[0], output);
            assert_eq!(result.status, HostApplyStatus::Unknown, "{failure}");
            assert_eq!(result.successful_actions, 0, "{failure}");
            assert_eq!(result.kill_signals_delivered, 0, "{failure}");
        }
    }

    #[test]
    fn bound_pre_action_refusals_and_resumed_noop_report_no_new_signals() {
        let fleet = retained_fleet(vec![("alpha", remote_document("alpha", &[(101, 0.999)]))]);
        let prepared = prepare_fleet_apply(&fleet).unwrap();
        let request = prepared[0].request.as_ref().unwrap();
        for response in [
            serde_json::json!({
                "session_id": request.binding.session_id,
                "mode": "robot_apply",
                "status": "blocked",
                "error": "fleet_binding_mismatch",
                "reason": "saved plan changed",
                "expected_execution_binding": request.binding,
                "outcomes": [],
            }),
            serde_json::json!({
                "session_id": request.binding.session_id,
                "mode": "robot_apply",
                "status": "blocked",
                "error": "robot_mode_disabled",
                "execution_binding": request.binding,
                "outcomes": [],
            }),
        ] {
            let mut output = result_output(request, "precheck_blocked", 4);
            output.stdout = serde_json::to_vec(&response).unwrap();
            let result = interpret_remote_result(&prepared[0], output);
            assert_eq!(result.status, HostApplyStatus::Blocked);
            assert_eq!(result.successful_actions, 0);
            assert_eq!(result.kill_signals_delivered, 0);
        }
        let mut output = result_output(request, "success", 0);
        output.stdout = serde_json::to_vec(&serde_json::json!({
            "session_id": request.binding.session_id,
            "mode": "robot_apply",
            "note": "nothing_to_do",
            "execution_binding": request.binding,
            "outcomes": [],
        }))
        .unwrap();
        let result = interpret_remote_result(&prepared[0], output);
        assert_eq!(result.status, HostApplyStatus::NoActions);
        assert_eq!(result.successful_actions, 0);
        assert_eq!(result.kill_signals_delivered, 0);
    }

    #[test]
    fn rolling_failure_stops_later_hosts_without_retries() {
        let fleet = retained_fleet(vec![
            ("alpha", remote_document("alpha", &[(101, 0.999)])),
            ("beta", remote_document("beta", &[(201, 0.999)])),
            ("gamma", remote_document("gamma", &[(301, 0.999)])),
        ]);
        let prepared = prepare_fleet_apply(&fleet).unwrap();
        for continue_on_error in [false, true] {
            let calls = AtomicUsize::new(0);
            let options = FleetApplyConfig {
                continue_on_error,
                ..config()
            };
            let report = execute_fleet_apply_with(
                &prepared,
                &fleet.execution.as_ref().unwrap().transport,
                &options,
                |request, _, _| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    if request.host == "alpha" {
                        Err("connection lost after dispatch".into())
                    } else {
                        Ok(result_output(request, "success", 2))
                    }
                },
                |_| Ok(()),
            );
            assert_eq!(report.hosts.len(), 3);
            assert_eq!(report.hosts[0].status, HostApplyStatus::Unknown);
            assert_eq!(
                calls.load(Ordering::SeqCst),
                if continue_on_error { 3 } else { 1 }
            );
            assert_eq!(
                report.hosts[1].status,
                if continue_on_error {
                    HostApplyStatus::Applied
                } else {
                    HostApplyStatus::NotStarted
                }
            );
        }
    }

    #[test]
    fn receipt_failure_stops_dispatch_even_with_continue_on_error() {
        let fleet = retained_fleet(vec![
            ("alpha", remote_document("alpha", &[(101, 0.999)])),
            ("beta", remote_document("beta", &[(201, 0.999)])),
        ]);
        let prepared = prepare_fleet_apply(&fleet).unwrap();
        let calls = AtomicUsize::new(0);
        let options = FleetApplyConfig {
            continue_on_error: true,
            ..config()
        };
        let report = execute_fleet_apply_with(
            &prepared,
            &fleet.execution.as_ref().unwrap().transport,
            &options,
            |request, _, _| {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(result_output(request, "success", 2))
            },
            |_| Err("receipt disk full".into()),
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(report.hosts[0].status, HostApplyStatus::Applied);
        assert_eq!(report.hosts[0].successful_actions, 1);
        assert_eq!(report.hosts[1].status, HostApplyStatus::NotStarted);
        assert_eq!(
            report.persistence_error.as_deref(),
            Some("receipt disk full")
        );
    }

    #[test]
    fn concurrent_batches_respect_limit_and_keep_host_order() {
        let fleet = retained_fleet(vec![
            ("alpha", remote_document("alpha", &[(101, 0.999)])),
            ("beta", remote_document("beta", &[(201, 0.999)])),
            ("gamma", remote_document("gamma", &[(301, 0.999)])),
        ]);
        let prepared = prepare_fleet_apply(&fleet).unwrap();
        let running = AtomicUsize::new(0);
        let maximum = AtomicUsize::new(0);
        let options = FleetApplyConfig {
            parallel: 2,
            ..config()
        };
        let report = execute_fleet_apply_with(
            &prepared,
            &fleet.execution.as_ref().unwrap().transport,
            &options,
            |request, _, _| {
                let active = running.fetch_add(1, Ordering::SeqCst) + 1;
                maximum.fetch_max(active, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(10));
                running.fetch_sub(1, Ordering::SeqCst);
                Ok(result_output(request, "success", 2))
            },
            |_| Ok(()),
        );
        assert!(maximum.load(Ordering::SeqCst) <= 2);
        assert_eq!(
            report
                .hosts
                .iter()
                .map(|host| host.host.as_str())
                .collect::<Vec<_>>(),
            ["alpha", "beta", "gamma"]
        );
        assert!(report
            .hosts
            .iter()
            .all(|host| host.status == HostApplyStatus::Applied));
    }
}
