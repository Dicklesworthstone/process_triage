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

/// Approve only the exact reversible tier saved by an explicit pressure goal.
/// Re-run the shared selector against retained evidence: --targets selects every
/// action for a PID/start pair, so no extra stage or later tier may remain.
fn approved_pressure_remedies(
    document: &Value,
    plan: &Plan,
    candidates: &[Value],
) -> Result<Vec<PlanAction>, String> {
    use crate::decision::goal_parser::{parse_goal, Goal};
    use crate::decision::relief::select_relief_plan;

    let goal_text = document["goal"].as_str();
    let argument_goal = document["args"]["goal"].as_str();
    let parsed = goal_text.and_then(|goal| parse_goal(goal).ok());
    let summary = &document["goal_summary"];
    let scope = match parsed {
        Some(Goal::Relieve(scope)) => scope,
        _ => {
            if summary["execution_scope"] == "selected_pressure_remedies"
                || argument_goal
                    .and_then(|goal| parse_goal(goal).ok())
                    .is_some_and(|goal| matches!(goal, Goal::Relieve(_)))
            {
                return Err(
                    "pressure goal is missing or disagrees with its saved arguments".into(),
                );
            }
            return Ok(Vec::new());
        }
    };
    if argument_goal != goal_text
        || summary["goal"].as_str() != goal_text
        || summary["parsed"] != serde_json::json!(Goal::Relieve(scope).canonical())
        || summary["execution_scope"] != "selected_pressure_remedies"
        || !summary["error"].is_null()
    {
        return Err("pressure goal and its saved selection summary disagree".into());
    }

    let relief = select_relief_plan(scope, candidates, plan, None);
    let selected_ids: HashSet<&str> = relief
        .selected_action_ids
        .iter()
        .map(String::as_str)
        .collect();
    if selected_ids.len() != relief.selected_action_ids.len()
        || selected_ids.len() != plan.actions.len()
        || plan
            .actions
            .iter()
            .any(|action| !selected_ids.contains(action.action_id.as_str()))
    {
        return Err(
            "pressure goal contains unselected, unsafe, unsupported or later-tier actions".into(),
        );
    }
    let expected = serde_json::to_value(&relief)
        .map_err(|error| format!("cannot validate pressure goal selection: {error}"))?;
    for field in [
        "selected_tier",
        "selected_action_ids",
        "selected_targets",
        "selected_pids",
    ] {
        if summary[field] != expected[field] {
            return Err(format!(
                "pressure goal {field} differs from the independently validated selection"
            ));
        }
    }
    for candidate in candidates {
        let target: Option<ProcessIdentity> =
            serde_json::from_value(candidate["action_target"].clone()).ok();
        let action_ids: Vec<&str> = plan
            .actions
            .iter()
            .filter(|action| target.as_ref() == Some(&action.target))
            .map(|action| action.action_id.as_str())
            .collect();
        if candidate["goal_selected"].as_bool() != Some(!action_ids.is_empty())
            || candidate["plan_action_ids"] != serde_json::json!(action_ids)
        {
            return Err(
                "pressure candidate selection or action IDs disagree with the executable plan"
                    .into(),
            );
        }
    }

    let mut remedy_ids = HashSet::new();
    for step in &relief.remediation_ladder {
        match step.action {
            // A staged pause belongs to its kill. It must never be dispatched
            // separately when the fleet risk budget refuses the primary kill.
            Action::Kill => {}
            Action::Renice
            | Action::Throttle
            | Action::Pause
            | Action::Freeze
            | Action::CapMemory => {
                remedy_ids.extend(step.action_ids.iter().map(String::as_str));
            }
            _ => return Err("unsupported fleet pressure remedy".into()),
        }
    }
    let mut remedies = Vec::new();
    for action in &plan.actions {
        if !remedy_ids.contains(action.action_id.as_str()) {
            continue;
        }
        if i32::try_from(action.target.pid.0).is_err()
            || !action.target.can_safely_revalidate()
            || action
                .target
                .start_id
                .0
                .chars()
                .any(|character| character == ',' || character.is_control())
        {
            return Err("pressure remedy has an unusable remote target identity".into());
        }
        remedies.push(action.clone());
    }
    Ok(remedies)
}

fn request_from_document(
    host: &str,
    document: &Value,
    selected_pids: &[u32],
    max_fdr: f64,
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
    let pressure_remedies = approved_pressure_remedies(document, &plan, candidates)?;
    let mut targets = Vec::new();
    let mut posteriors = HashMap::new();
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
        let posterior: crate::inference::ClassScores =
            serde_json::from_value(candidate["posterior"].clone()).map_err(|_| {
                format!("approved PID {pid} has no complete recorded class posterior")
            })?;
        posteriors.insert(pid, posterior);
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
        if kills[0].rationale.posterior != posteriors.get(&target.pid.0).copied() {
            return Err(format!(
                "approved PID {} candidate and executable action disagree on posterior evidence",
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
    // Independently enforce the coordinator's budget on the exact actions, even
    // when a remote host disabled its local FDR policy. Evaluate a clone so the
    // approved document and its hash remain unchanged. This also rejects legacy
    // or malformed actions whose class evidence was omitted from the plan.
    let mut selected_plan = plan.clone();
    selected_plan.actions = actions.clone();
    let mut risk_policy = crate::config::Policy::default();
    risk_policy.fdr_control.enabled = true;
    risk_policy.fdr_control.method = crate::config::policy::FdrMethod::Bayesian;
    risk_policy.fdr_control.alpha = max_fdr;
    let risk = crate::decision::apply_plan_fdr_gate(&mut selected_plan, &risk_policy);
    if let Some(decision) = risk.decisions.iter().find(|decision| !decision.selected) {
        return Err(format!(
            "fleet posterior-risk limit refused PID {}: {}",
            decision.target.pid.0, decision.reason
        ));
    }
    // The original pooled-risk gate applies only to its approved kill sequence.
    // Reversible remedies have their own explicit goal/tier approval above and
    // retain the remote host's identity, policy, live checks and undo machinery.
    for action in pressure_remedies {
        if targets.iter().any(|target| target.pid == action.target.pid)
            || !action_ids.insert(action.action_id.clone())
        {
            return Err("pressure remedy overlaps an approved target or action".into());
        }
        targets.push(action.target.clone());
        actions.push(action);
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
                request_from_document(
                    &host.host_id,
                    document,
                    &host.selected_kill_pids,
                    fleet.safety_budget.max_fdr,
                )
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
            request_from_document(
                &host.host_id,
                document,
                &host.selected_kill_pids,
                fleet.safety_budget.max_fdr,
            )
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
            Some(Err(error))
                if !host.selected_kill_pids.is_empty() || !binding.selected_targets.is_empty() =>
            {
                return Err(format!(
                    "{} cannot execute its approved selection: {error}; refusing the whole fleet because an approved execution request is invalid",
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
    let kill_count = request
        .actions
        .iter()
        .filter(|action| matches!(action.action, Action::Kill | Action::Restart))
        .count();
    if kill_count > config.max_kills_per_host as usize {
        return Err(format!(
            "{} approved kills exceed per-host cap {}",
            kill_count, config.max_kills_per_host
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
            // The SSH watchdog cannot guarantee remote cancellation. Bound
            // admission independently on the host, starting when agent apply
            // starts; already-started cleanup retains its approved grace and
            // completes its receipts. Preserve zero as an expired remote budget,
            // independently of the one-second SSH watchdog floor.
            "--timeout".into(),
            config.timeout_secs.to_string(),
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
        if document["error"] == "incomplete_execution" {
            // Refusing a replay proves no new admission, but does not resolve
            // actions admitted before the remote journal became incomplete.
            result.error = Some(format!(
                "remote apply refused uncertain replay; earlier action completion is unknown: {}",
                document["message"]
                    .as_str()
                    .unwrap_or("incomplete execution history")
            ));
        } else {
            result.status = HostApplyStatus::Blocked;
            result.error = Some(format!(
                "remote apply refused execution: {}",
                document["error"].as_str().unwrap()
            ));
        }
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
    } else if !outcomes.is_empty()
        && seen.len() == actions.len()
        && refused == outcomes.len()
        && delivered == 0
    {
        HostApplyStatus::Blocked
    } else if successes > 0 || delivered > 0 {
        HostApplyStatus::Partial
    } else {
        HostApplyStatus::Unknown
    };
    if result.status.is_failure() {
        result.error = Some(if seen.len() < actions.len() {
            format!(
                "remote response omitted {} approved action outcome(s); their completion is unknown; inspect the remote receipt before retrying",
                actions.len() - seen.len()
            )
        } else {
            "not all approved actions have confirmed successful outcomes; inspect the remote receipt before retrying".into()
        });
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
    // Validate the complete approved operation before starting any worker.
    // Every approved target independently fits the posterior-risk ceiling, but
    // a known invalid request or cap violation still requires review rather
    // than silently changing what the user approved. Runtime failures retain
    // the existing stop/continue policy and never cause automatic retries.
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
                "{}: {error}; no hosts started because an approved execution request is invalid",
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
            crate::collect::tool_runner::run_ssh_tool(&args, Some(timeout), None)
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
                "rationale": {"posterior": {
                    "useful": 1.0 - probability,
                    "useful_bad": 0.0,
                    "abandoned": probability,
                    "zombie": 0.0,
                }},
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

    fn refresh_pressure_summary(document: &mut Value) {
        let plan: Plan = serde_json::from_value(document.clone()).unwrap();
        let goal_text = document["goal"].as_str().unwrap();
        let crate::decision::goal_parser::Goal::Relieve(scope) =
            crate::decision::goal_parser::parse_goal(goal_text).unwrap()
        else {
            panic!("pressure fixture requires a relief goal");
        };
        let relief = crate::decision::relief::select_relief_plan(
            scope,
            document["candidates"].as_array().unwrap(),
            &plan,
            None,
        );
        let mut summary = serde_json::to_value(relief).unwrap();
        summary["goal"] = serde_json::json!(goal_text);
        summary["parsed"] =
            serde_json::json!(crate::decision::goal_parser::Goal::Relieve(scope).canonical());
        summary["execution_scope"] = serde_json::json!("selected_pressure_remedies");
        document["goal_summary"] = summary;
    }

    fn remote_relief_document(host: &str, rows: &[(u32, Action)]) -> Value {
        let probabilities: Vec<_> = rows
            .iter()
            .map(|(pid, action)| (*pid, if *action == Action::Kill { 0.999 } else { 0.2 }))
            .collect();
        let mut document = remote_document(host, &probabilities);
        document["goal"] = serde_json::json!("relieve");
        document["args"]["goal"] = serde_json::json!("relieve");
        document["summary"]["goal_mode"] = serde_json::json!(true);
        for (index, &(pid, action)) in rows.iter().enumerate() {
            let boot = "11111111-2222-4333-8444-555555555555";
            let target = ProcessIdentity::full(
                pid,
                StartId::from_linux(boot, 42, pid),
                1000,
                Some(50),
                Some(40),
                pt_common::IdentityQuality::Full,
            );
            let action_id = format!("remedy-{pid}-{action:?}");
            document["actions"][index]["action_id"] = serde_json::json!(action_id);
            document["actions"][index]["target"] = serde_json::json!(target);
            document["actions"][index]["action"] = serde_json::json!(action);
            let memory = action == Action::CapMemory;
            let costs = if memory {
                serde_json::json!({"cpu": 0.0, "memory": 1.0, "io": 0.0})
            } else {
                serde_json::json!({"cpu": 1.0, "memory": 0.0, "io": 0.0})
            };
            let candidate = &mut document["candidates"][index];
            candidate["start_id"] = serde_json::json!(target.start_id);
            candidate["action_target"] = serde_json::json!(target);
            candidate["recommended_action"] = serde_json::json!(action);
            candidate["recommendation"] = serde_json::json!(serde_json::to_value(action)
                .unwrap()
                .as_str()
                .unwrap()
                .to_ascii_uppercase());
            candidate["state"] = serde_json::json!("S");
            candidate["goal_selected"] = serde_json::json!(true);
            candidate["plan_action_ids"] = serde_json::json!([action_id]);
            candidate["pressure_decision"] = serde_json::json!({
                "enabled": true, "applied": true, "status": "applied", "scope": "process",
                "chosen_action": action,
                "evidence_only_action": if action == Action::Kill { "kill" } else { "keep" },
                "severity": {"cpu": 0.5, "memory": 0.5, "io": 0.5},
                "shares": {"cpu": 0.25, "memory": 0.25, "io": 0.25},
                "modeled_pressure_relief": 1.0,
                "actions": [
                    {"action": "keep", "pressure_cost": 1.0, "pressure_by_resource": costs},
                    {"action": action, "pressure_cost": 0.0, "adjusted_loss": 0.1,
                     "eligible": true,
                     "pressure_by_resource": {"cpu": 0.0, "memory": 0.0, "io": 0.0}}
                ]
            });
            if memory {
                let cap = crate::action::memory_cap::MemoryCapPlan {
                    target: target.clone(),
                    scope: crate::action::reversal::ReversalScope {
                        cgroup_path: "/user.slice/owned/workload".into(),
                        device: 1,
                        inode: 2,
                        mount_id: 3,
                        boot_id: boot.into(),
                        mount_namespace_device: 4,
                        mount_namespace_inode: 5,
                        cgroup_namespace_device: 6,
                        cgroup_namespace_inode: 7,
                    },
                    limit_bytes: 180 * 1024 * 1024,
                    observed_high_bytes: None,
                    observed_current_bytes: 200 * 1024 * 1024,
                    observed_low_bytes: 0,
                    observed_min_bytes: 0,
                    page_size_bytes: 4096,
                };
                cap.validate(&target).unwrap();
                document["candidates"][index]["memory_cap"] = serde_json::json!(cap);
                document["actions"][index]["memory_cap"] = serde_json::json!(cap);
            }
        }
        document["pre_toggled"] = serde_json::json!(document["actions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|action| action["action_id"].as_str().unwrap())
            .collect::<Vec<_>>());
        refresh_pressure_summary(&mut document);
        document
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
    fn pressure_goal_remedies_survive_binding_and_dispatch_with_zero_kill_budget() {
        for action in [
            Action::Renice,
            Action::Throttle,
            Action::Pause,
            Action::Freeze,
            Action::CapMemory,
        ] {
            let document = remote_relief_document("alpha", &[(101, action)]);
            let original = document.clone();
            let fleet = retained_fleet(vec![("alpha", document)]);
            assert!(fleet.hosts[0].selected_kill_pids.is_empty());
            assert_eq!(fleet.safety_budget.pooled_fdr.selected_kills, 0);
            let restored: FleetSession =
                serde_json::from_str(&serde_json::to_string(&fleet).unwrap()).unwrap();
            let prepared = prepare_fleet_apply(&restored).unwrap();
            let request = prepared[0].request.as_ref().unwrap();
            assert_eq!(request.targets.len(), 1, "{action:?}");
            assert_eq!(request.targets[0].pid.0, 101);
            assert_eq!(request.targets[0].pgid, Some(50));
            assert_eq!(request.actions.len(), 1);
            assert_eq!(request.actions[0].action, action);
            assert_eq!(
                request.binding.plan_sha256,
                plan_document_sha256(&original).unwrap()
            );
            if action == Action::CapMemory {
                assert_eq!(
                    serde_json::to_value(&request.actions[0].memory_cap).unwrap(),
                    original["candidates"][0]["memory_cap"]
                );
            }
            let options = FleetApplyConfig {
                max_kills_per_host: 0,
                ..config()
            };
            let calls = AtomicUsize::new(0);
            let report = execute_fleet_apply_with(
                &prepared,
                &restored.execution.as_ref().unwrap().transport,
                &options,
                |request, args, _| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    let command = args.last().unwrap();
                    assert!(command.contains("--max-kills 0"));
                    assert!(command.contains("--yes --resume --abort-on-unknown"));
                    assert!(command.contains(&request.binding.plan_sha256));
                    assert!(!command.contains("--recommended"));
                    assert!(args.contains(&"StrictHostKeyChecking=yes".into()));
                    Ok(result_output(request, "success", 2))
                },
                |_| Ok(()),
            );
            assert_eq!(calls.load(Ordering::SeqCst), 1, "{action:?}");
            assert_eq!(report.hosts[0].status, HostApplyStatus::Applied);
            assert_eq!(report.hosts[0].successful_actions, 1);
            assert_eq!(report.hosts[0].kill_signals_delivered, 0);
            assert_eq!(report.hosts[0].selected_targets, request.targets);
        }
    }

    #[test]
    fn pressure_dispatch_does_not_expand_ordinary_plans_or_refused_kill_stages() {
        let mut ordinary = remote_relief_document("ordinary", &[(101, Action::Renice)]);
        ordinary["goal"] = Value::Null;
        ordinary["args"]["goal"] = Value::Null;
        ordinary["goal_summary"] = Value::Null;
        ordinary["summary"]["goal_mode"] = Value::Null;
        let mut refused = remote_relief_document("refused", &[(201, Action::Kill)]);
        let posterior = serde_json::json!({
            "useful": 0.04, "useful_bad": 0.0, "abandoned": 0.96, "zombie": 0.0,
        });
        refused["candidates"][0]["posterior"] = posterior.clone();
        refused["actions"][0]["rationale"]["posterior"] = posterior;
        let mut pause = refused["actions"][0].clone();
        pause["action_id"] = serde_json::json!("prepare-201");
        pause["action"] = serde_json::json!("pause");
        refused["actions"][0]["stage"] = serde_json::json!(1);
        refused["actions"][0]["order"] = serde_json::json!(1);
        refused["actions"].as_array_mut().unwrap().insert(0, pause);
        refused["candidates"][0]["plan_action_ids"] =
            serde_json::json!(["prepare-201", "remedy-201-Kill"]);
        refused["pre_toggled"] = serde_json::json!(["prepare-201", "remedy-201-Kill"]);
        refresh_pressure_summary(&mut refused);
        let fleet =
            retained_fleet_with_budget(vec![("ordinary", ordinary), ("refused", refused)], 0.01);
        let prepared = prepare_fleet_apply(&fleet).unwrap();
        assert!(prepared.iter().all(|host| {
            let request = host.request.as_ref().unwrap();
            request.targets.is_empty() && request.actions.is_empty()
        }));
        let options = FleetApplyConfig {
            max_kills_per_host: 0,
            ..config()
        };
        let report = execute_fleet_apply_with(
            &prepared,
            &fleet.execution.as_ref().unwrap().transport,
            &options,
            |_, _, _| panic!("unselected advice or a refused kill's pause must never dispatch"),
            |_| Ok(()),
        );
        assert!(report
            .hosts
            .iter()
            .all(|host| host.status == HostApplyStatus::NoActions));

        let kill_fleet = retained_fleet(vec![("kill", remote_document("kill", &[(301, 0.999)]))]);
        let kills = prepare_fleet_apply(&kill_fleet).unwrap();
        let blocked = execute_fleet_apply_with(
            &kills,
            &kill_fleet.execution.as_ref().unwrap().transport,
            &options,
            |_, _, _| panic!("zero kill cap must still refuse a pooled-approved kill"),
            |_| Ok(()),
        );
        assert_eq!(blocked.hosts[0].status, HostApplyStatus::Blocked);
    }

    #[test]
    fn pressure_binding_refuses_unselected_unsafe_or_changed_remedies() {
        for invalid in [
            "goal",
            "selection",
            "candidate_ids",
            "summary_ids",
            "summary_target",
            "attribution",
            "blocked",
            "routed",
            "uid",
            "extra_uid_stage",
            "extra_stage",
            "later_tier",
            "unsupported",
            "cap_binding",
        ] {
            let action = if invalid == "cap_binding" {
                Action::CapMemory
            } else {
                Action::Renice
            };
            let mut document = remote_relief_document("alpha", &[(101, action)]);
            match invalid {
                "goal" => document["args"]["goal"] = serde_json::json!("mem-pressure"),
                "selection" => {
                    document["candidates"][0]["goal_selected"] = serde_json::json!(false)
                }
                "candidate_ids" => {
                    document["candidates"][0]["plan_action_ids"] = serde_json::json!(["other"])
                }
                "summary_ids" => {
                    document["goal_summary"]["selected_action_ids"] = serde_json::json!(["other"])
                }
                "summary_target" => {
                    document["goal_summary"]["selected_targets"][0]["uid"] = serde_json::json!(0)
                }
                "attribution" => {
                    document["candidates"][0]["pressure_decision"]["shares"]["cpu"] = Value::Null
                }
                "blocked" => document["actions"][0]["blocked"] = serde_json::json!(true),
                "routed" => document["actions"][0]["routing"] = serde_json::json!("supervisor"),
                "uid" => document["actions"][0]["target"]["uid"] = serde_json::json!(0),
                "extra_uid_stage" | "extra_stage" => {
                    let mut extra = document["actions"][0].clone();
                    extra["action_id"] = serde_json::json!("unapproved-extra");
                    if invalid == "extra_uid_stage" {
                        extra["target"]["uid"] = serde_json::json!(0);
                    } else {
                        extra["action"] = serde_json::json!("pause");
                        extra["stage"] = serde_json::json!(1);
                    }
                    document["actions"].as_array_mut().unwrap().push(extra);
                }
                "later_tier" => {
                    document = remote_relief_document(
                        "alpha",
                        &[(101, Action::Renice), (201, Action::Pause)],
                    );
                }
                "unsupported" => {
                    document = remote_relief_document("alpha", &[(101, Action::Restart)]);
                }
                _ => {
                    document["actions"][0]["memory_cap"]["limit_bytes"] =
                        serde_json::json!(100 * 1024 * 1024);
                }
            }
            assert!(
                request_from_document("alpha", &document, &[], 0.05).is_err(),
                "{invalid}"
            );
        }

        let original = retained_fleet(vec![(
            "alpha",
            remote_relief_document("alpha", &[(101, Action::Renice)]),
        )]);
        let mut legacy = original.clone();
        legacy.execution.as_mut().unwrap().hosts[0]
            .selected_targets
            .clear();
        assert!(prepare_fleet_apply(&legacy)
            .unwrap_err()
            .contains("selection no longer matches"));
        let mut changed = original;
        changed.execution.as_mut().unwrap().hosts[0]
            .document
            .as_mut()
            .unwrap()["goal"] = serde_json::json!("mem-pressure");
        assert!(prepare_fleet_apply(&changed)
            .unwrap_err()
            .contains("digest changed"));
    }

    #[test]
    fn invalid_pressure_host_blocks_every_dispatch_before_ssh() {
        let good = remote_relief_document("alpha", &[(101, Action::Renice)]);
        let mut bad = remote_relief_document("beta", &[(201, Action::Throttle)]);
        bad["candidates"][0]["goal_selected"] = serde_json::json!(false);
        let fleet = retained_fleet(vec![("alpha", good), ("beta", bad)]);
        let prepared = prepare_fleet_apply(&fleet).unwrap();
        assert!(prepared[1].error.is_some());
        let options = FleetApplyConfig {
            max_kills_per_host: 0,
            continue_on_error: true,
            parallel: 2,
            ..config()
        };
        let report = execute_fleet_apply_with(
            &prepared,
            &fleet.execution.as_ref().unwrap().transport,
            &options,
            |_, _, _| panic!("invalid pressure binding must refuse the complete fleet"),
            |_| Ok(()),
        );
        assert!(report
            .hosts
            .iter()
            .all(|host| host.status == HostApplyStatus::Blocked && !host.attempted));
    }

    #[test]
    fn pressure_receipts_preserve_policy_refusals_and_uncertain_resume() {
        let fleet = retained_fleet(vec![(
            "alpha",
            remote_relief_document("alpha", &[(101, Action::Renice)]),
        )]);
        let prepared = prepare_fleet_apply(&fleet).unwrap();
        let request = prepared[0].request.as_ref().unwrap();
        let refused =
            interpret_remote_result(&prepared[0], result_output(request, "blocked_by_policy", 4));
        assert_eq!(refused.status, HostApplyStatus::Blocked);
        assert_eq!(refused.successful_actions, 0);

        let mut output = result_output(request, "success", 2);
        let mut response: Value = serde_json::from_slice(&output.stdout).unwrap();
        response["outcomes"] = serde_json::json!([]);
        response["note"] = serde_json::json!("nothing_to_do");
        output.stdout = serde_json::to_vec(&response).unwrap();
        output.exit_code = Some(0);
        let resumed = interpret_remote_result(&prepared[0], output.clone());
        assert_eq!(resumed.status, HostApplyStatus::NoActions);
        assert_eq!(resumed.successful_actions, 0);
        assert_eq!(resumed.selected_targets, request.targets);

        response["status"] = serde_json::json!("blocked");
        response["error"] = serde_json::json!("incomplete_execution");
        response["message"] = serde_json::json!("earlier action admission has no complete receipt");
        output.stdout = serde_json::to_vec(&response).unwrap();
        output.exit_code = Some(4);
        let uncertain = interpret_remote_result(&prepared[0], output);
        assert_eq!(uncertain.status, HostApplyStatus::Unknown);
        assert_eq!(uncertain.successful_actions, 0);
        assert_eq!(uncertain.kill_signals_delivered, 0);

        let mut forged = result_output(request, "success", 2);
        let mut response: Value = serde_json::from_slice(&forged.stdout).unwrap();
        response["outcomes"][0]["action"] = serde_json::json!("kill");
        forged.stdout = serde_json::to_vec(&response).unwrap();
        assert_eq!(
            interpret_remote_result(&prepared[0], forged).status,
            HostApplyStatus::Unknown
        );
    }

    #[test]
    fn model_produced_io_relief_reaches_confirmed_fleet_dispatch() {
        use crate::collect::ProcessState;
        use crate::decision::load_aware::{
            prepare_pressure_decision, PressureContext, ResourceShares,
        };
        use crate::decision::pressure_regime::ResourceSeverity;
        use crate::decision::{ActionFeasibility, DisabledAction};
        use crate::inference::ClassScores;
        use crate::plan::{generate_plan, DecisionBundle, DecisionCandidate};

        let mut policy = crate::config::Policy::default();
        policy.load_aware.enabled = true;
        policy.load_aware.pressure.pause_io_relief = 0.5;
        let posterior = ClassScores {
            useful: 0.0,
            useful_bad: 1.0,
            abandoned: 0.0,
            zombie: 0.0,
        };
        let feasibility = ActionFeasibility {
            disabled: Action::ALL
                .into_iter()
                .filter(|action| *action != Action::Keep && *action != Action::Pause)
                .map(|action| DisabledAction {
                    action,
                    reason: "only the observed stop capability is available".into(),
                })
                .collect(),
        };
        let pressure = prepare_pressure_decision(
            &posterior,
            &policy,
            &feasibility,
            &PressureContext {
                severity: ResourceSeverity {
                    io: 1.0,
                    ..Default::default()
                },
                shares: ResourceShares {
                    io: Some(0.8),
                    ..Default::default()
                },
                unavailable: Vec::new(),
            },
        )
        .unwrap();
        assert_eq!(pressure.decision.optimal_action, Action::Pause);
        assert_eq!(pressure.report.evidence_only_action, Action::Keep);

        let mut document = remote_relief_document("alpha", &[(101, Action::Pause)]);
        let target: ProcessIdentity =
            serde_json::from_value(document["candidates"][0]["action_target"].clone()).unwrap();
        let plan = generate_plan(&DecisionBundle {
            session_id: SessionId("pt-20261105-120000-abcd".into()),
            policy: policy.clone(),
            candidates: vec![DecisionCandidate {
                identity: target,
                ppid: Some(50),
                decision: pressure.decision,
                blocked_reasons: Vec::new(),
                stage_pause_before_kill: false,
                process_state: Some(ProcessState::Sleeping),
                parent_identity: None,
                d_state_diagnostics: None,
                supervisor_restart: None,
                memory_cap: None,
            }],
            generated_at: Some("2026-11-05T12:00:00Z".into()),
        });
        assert_eq!(plan.actions.len(), 1);
        assert!(!plan.actions[0].blocked);
        document["candidates"][0]["plan_action_ids"] =
            serde_json::json!([plan.actions[0].action_id]);
        document["candidates"][0]["posterior"] = serde_json::json!(posterior);
        document["candidates"][0]["pressure_decision"] =
            serde_json::to_value(pressure.report).unwrap();
        document["goal"] = serde_json::json!("io-pressure");
        document["args"]["goal"] = serde_json::json!("io-pressure");
        document["policy_snapshot"] = serde_json::to_value(policy).unwrap();
        let Value::Object(fields) = serde_json::to_value(plan).unwrap() else {
            unreachable!()
        };
        document.as_object_mut().unwrap().extend(fields);
        refresh_pressure_summary(&mut document);
        assert_eq!(
            document["goal_summary"]["selected_pids"],
            serde_json::json!([101])
        );
        assert_eq!(document["goal_summary"]["total_modeled_relief"], 0.4);

        let fleet = retained_fleet(vec![("alpha", document)]);
        let prepared = prepare_fleet_apply(&fleet).unwrap();
        let options = FleetApplyConfig {
            max_kills_per_host: 0,
            ..config()
        };
        let calls = AtomicUsize::new(0);
        let report = execute_fleet_apply_with(
            &prepared,
            &fleet.execution.as_ref().unwrap().transport,
            &options,
            |request, _, _| {
                calls.fetch_add(1, Ordering::SeqCst);
                assert_eq!(request.actions.len(), 1);
                assert_eq!(request.actions[0].action, Action::Pause);
                Ok(result_output(request, "success", 2))
            },
            |_| Ok(()),
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(report.hosts[0].status, HostApplyStatus::Applied);
        assert_eq!(report.hosts[0].successful_actions, 1);
        assert_eq!(report.hosts[0].kill_signals_delivered, 0);
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
    fn fleet_risk_refusals_survive_transport_failure_and_disabled_remote_policy() {
        let mut low = remote_document("low", &[(101, 0.999)]);
        let mut high = remote_document("high", &[(201, 0.901)]);
        let mut other = remote_document("other", &[(301, 0.96)]);
        for document in [&mut low, &mut high, &mut other] {
            document["policy_snapshot"]["fdr_control"] =
                serde_json::json!({"enabled": false, "method": "none", "alpha": 1.0});
        }
        let fleet = retained_fleet(vec![("low", low), ("high", high), ("other", other)]);
        assert!(fleet.hosts[1].selected_kill_pids.is_empty());
        let before = serde_json::to_value(&fleet).unwrap();
        let prepared = prepare_fleet_apply(&fleet).unwrap();
        let attempted = Mutex::new(Vec::new());
        let options = FleetApplyConfig {
            continue_on_error: true,
            ..config()
        };
        let report = execute_fleet_apply_with(
            &prepared,
            &fleet.execution.as_ref().unwrap().transport,
            &options,
            |request, _, _| {
                attempted
                    .lock()
                    .unwrap()
                    .extend(request.targets.iter().map(|target| target.pid.0));
                if request.host == "low" {
                    Err("connection lost after dispatch".into())
                } else {
                    Ok(result_output(request, "success", 2))
                }
            },
            |_| Ok(()),
        );
        assert_eq!(*attempted.lock().unwrap(), [101, 301]);
        assert_eq!(report.hosts[0].status, HostApplyStatus::Unknown);
        assert_eq!(report.hosts[1].status, HostApplyStatus::NoActions);
        assert_eq!(report.hosts[2].status, HostApplyStatus::Applied);
        assert_eq!(serde_json::to_value(&fleet).unwrap(), before);

        // A saved selection made by the older mean-risk rule is re-evaluated,
        // not grandfathered into execution after upgrading the coordinator.
        let mut legacy_selection = fleet;
        legacy_selection.hosts[1].selected_kill_pids = vec![201];
        legacy_selection.safety_budget.pooled_fdr.method = "bayes_expected_fdr".into();
        assert!(prepare_fleet_apply(&legacy_selection)
            .unwrap_err()
            .contains("pooled-approved selection changed"));
    }

    #[test]
    fn fleet_execution_requires_matching_normalized_action_posteriors() {
        for variant in ["missing", "conflicting", "unnormalized"] {
            let mut document = remote_document("alpha", &[(101, 0.999)]);
            match variant {
                "missing" => document["actions"][0]["rationale"]["posterior"] = Value::Null,
                "conflicting" => {
                    document["actions"][0]["rationale"]["posterior"] = serde_json::json!({
                        "useful": 0.04, "useful_bad": 0.0, "abandoned": 0.96, "zombie": 0.0,
                    });
                }
                _ => {
                    document["candidates"][0]["posterior"]["useful"] = serde_json::json!(0.9);
                    assert!(parse_remote_plan(&document.to_string())
                        .unwrap_err()
                        .contains("posterior probabilities exceed one"));
                    // The transport parser permits incomplete probability mass;
                    // the executable-action gate must still require normalization.
                    // Keep the target's high score so selection cannot hide the
                    // malformed evidence by rejecting it for excessive risk.
                    document["candidates"][0]["posterior"]["useful"] = serde_json::json!(0.0);
                    document["actions"][0]["rationale"]["posterior"] =
                        document["candidates"][0]["posterior"].clone();
                }
            }
            let fleet = retained_fleet(vec![("alpha", document)]);
            assert!(prepare_fleet_apply(&fleet).is_err(), "{variant}");
        }
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
    fn known_host_refusals_are_checked_before_any_dispatch() {
        // Alpha's target is independently too risky. Beta's two safe targets
        // still exceed the explicit per-host cap, so no dispatch may begin.
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
        assert_eq!(fleet.safety_budget.pooled_fdr.selected_kills, 2);
        assert!(fleet.hosts[0].selected_kill_pids.is_empty());
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
                .contains("approved execution request is invalid"));
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
                assert!(command.contains("--robot --timeout 30 agent apply"));
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
    fn zero_apply_budget_is_not_extended_by_the_ssh_watchdog_floor() {
        let fleet = retained_fleet(vec![("alpha", remote_document("alpha", &[(101, 0.999)]))]);
        let prepared = prepare_fleet_apply(&fleet).unwrap();
        let options = FleetApplyConfig {
            timeout_secs: 0,
            ..config()
        };
        let calls = AtomicUsize::new(0);
        let report = execute_fleet_apply_with(
            &prepared,
            &fleet.execution.as_ref().unwrap().transport,
            &options,
            |_request, args, timeout| {
                calls.fetch_add(1, Ordering::SeqCst);
                assert_eq!(timeout, Duration::from_secs(1));
                assert!(args.contains(&"ConnectTimeout=1".to_string()));
                assert!(args
                    .last()
                    .unwrap()
                    .contains("--robot --timeout 0 agent apply"));
                Err("simulated SSH timeout".to_string())
            },
            |_| Ok(()),
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(report.hosts[0].status, HostApplyStatus::Unknown);
        assert_eq!(report.hosts[0].successful_actions, 0);
        assert_eq!(report.hosts[0].kill_signals_delivered, 0);
    }

    #[cfg(unix)]
    #[test]
    fn remote_apply_deadline_and_bindings_survive_shell_quoting() {
        let fleet = retained_fleet(vec![("alpha", remote_document("alpha", &[(101, 0.999)]))]);
        let prepared = prepare_fleet_apply(&fleet).unwrap();
        let mut request = prepared[0].request.clone().unwrap();
        request.binding.host_id = "machine alpha's $(printf substituted); #".into();
        let transport = SshScanConfig {
            remote_binary: "/opt/pt tools/pt's core $(printf substituted)".into(),
            connect_timeout: 60,
            ..SshScanConfig::default()
        };
        let options = FleetApplyConfig {
            timeout_secs: 17,
            ..config()
        };
        let args = remote_apply_args(&request, &transport, &options).unwrap();
        assert!(args.contains(&"ConnectTimeout=17".to_string()));
        // Exercise the receiving shell's actual tokenization without invoking
        // SSH or the supplied executable. Shell syntax inside data must remain
        // literal, and --timeout must remain a separate global CLI argument.
        let output = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!(
                "set -- {}; printf '%s\\0' \"$@\"",
                args.last().unwrap()
            ))
            .output()
            .unwrap();
        assert!(output.status.success(), "{:?}", output.stderr);
        let words: Vec<_> = output
            .stdout
            .split(|byte| *byte == 0)
            .filter(|word| !word.is_empty())
            .map(|word| std::str::from_utf8(word).unwrap())
            .collect();
        assert_eq!(
            words,
            vec![
                transport.remote_binary.as_str(),
                "--format",
                "json",
                "--robot",
                "--timeout",
                "17",
                "agent",
                "apply",
                "--session",
                request.binding.session_id.as_str(),
                "--targets",
                "101:fixture-boot:42:101",
                "--expected-host-id",
                request.binding.host_id.as_str(),
                "--expected-plan-sha256",
                request.binding.plan_sha256.as_str(),
                "--max-kills",
                "3",
                "--yes",
                "--resume",
                "--abort-on-unknown",
            ]
        );
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
    fn all_refused_requires_receipts_for_the_complete_approved_selection() {
        let fleet = retained_fleet(vec![(
            "alpha",
            remote_document("alpha", &[(101, 0.999), (102, 0.999)]),
        )]);
        let prepared = prepare_fleet_apply(&fleet).unwrap();
        let request = prepared[0].request.as_ref().unwrap();
        assert_eq!(request.actions.len(), 2);
        let mut output = result_output(request, "precheck_blocked", 4);
        let mut response: Value = serde_json::from_slice(&output.stdout).unwrap();
        response["outcomes"][1]["status"] = serde_json::json!("blocked_by_policy");
        output.stdout = serde_json::to_vec(&response).unwrap();

        let complete = interpret_remote_result(&prepared[0], output.clone());
        assert_eq!(complete.status, HostApplyStatus::Blocked);
        assert_eq!(complete.successful_actions, 0);
        assert_eq!(complete.kill_signals_delivered, 0);

        response["outcomes"].as_array_mut().unwrap().pop();
        // Aggregate claims cannot supply the missing per-action evidence.
        response["status"] = serde_json::json!("blocked");
        response["summary"] = serde_json::json!({
            "selected": 2, "attempted": 0, "succeeded": 0, "blocked": 2
        });
        output.stdout = serde_json::to_vec(&response).unwrap();
        let partial = interpret_remote_result(&prepared[0], output);
        assert_eq!(partial.status, HostApplyStatus::Unknown);
        assert_eq!(partial.successful_actions, 0);
        assert_eq!(partial.kill_signals_delivered, 0);
        assert!(partial
            .error
            .as_deref()
            .unwrap()
            .contains("omitted 1 approved action outcome"));
    }

    #[test]
    fn missing_receipts_preserve_confirmed_partial_success() {
        let fleet = retained_fleet(vec![(
            "alpha",
            remote_document("alpha", &[(101, 0.999), (102, 0.999)]),
        )]);
        let prepared = prepare_fleet_apply(&fleet).unwrap();
        let request = prepared[0].request.as_ref().unwrap();
        assert_eq!(request.actions.len(), 2);
        let mut output = result_output(request, "success", 2);
        let mut response: Value = serde_json::from_slice(&output.stdout).unwrap();
        response["outcomes"].as_array_mut().unwrap().pop();
        response["summary"] = serde_json::json!({"succeeded": 2});
        output.stdout = serde_json::to_vec(&response).unwrap();

        let result = interpret_remote_result(&prepared[0], output);
        assert_eq!(result.status, HostApplyStatus::Partial);
        assert_eq!(result.successful_actions, 1);
        assert_eq!(result.kill_signals_delivered, 1);
        assert!(result
            .error
            .as_deref()
            .unwrap()
            .contains("omitted 1 approved action outcome"));
    }

    #[test]
    fn incomplete_execution_refusal_keeps_prior_action_completion_unknown() {
        let fleet = retained_fleet(vec![("alpha", remote_document("alpha", &[(101, 0.999)]))]);
        let prepared = prepare_fleet_apply(&fleet).unwrap();
        let request = prepared[0].request.as_ref().unwrap();
        let mut output = result_output(request, "precheck_blocked", 4);
        output.stdout = serde_json::to_vec(&serde_json::json!({
            "session_id": request.binding.session_id,
            "mode": "robot_apply",
            "status": "blocked",
            "error": "incomplete_execution",
            "message": "admitted action has no terminal receipt",
            "execution_binding": request.binding,
            "summary": {"attempted": 0},
            "outcomes": [],
        }))
        .unwrap();

        let result = interpret_remote_result(&prepared[0], output);
        assert_eq!(result.status, HostApplyStatus::Unknown);
        assert_eq!(result.successful_actions, 0);
        assert_eq!(result.kill_signals_delivered, 0);
        let error = result.error.unwrap();
        assert!(error.contains("earlier action completion is unknown"));
        assert!(error.contains("admitted action has no terminal receipt"));
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
