//! SSH-based remote planning for fleet mode.
//!
//! Runs `pt-core --format json agent plan` on each host via `ssh`, so every host
//! is judged by pt's real decision pipeline with its own live checks (protection,
//! cgroup placement, posterior, loss matrix, policy). The fleet only aggregates
//! those per-host decisions, restricting goal plans to their selected actions;
//! it never re-classifies processes itself. (It used
//! to fetch a raw scan and apply a local state heuristic that, for example,
//! recommended `kill` for every zombie and every process stopped for an hour.)

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::io;
use std::sync::Mutex;
use std::time::Duration;
use thiserror::Error;

use crate::collect::pressure::{
    FileHandles, LoadAvg, MemInfo, PressureSnapshot, PressureWindow, PsiLine, PsiResource,
    StallFractions, Unavailable, VmStat,
};
use crate::decision::pressure_regime::{assess, PressureThresholds, ProcessCensus, Severity};
use crate::session::fleet::{HostHealth, HostHealthStatus, PressureCoverage};

/// Explicit overrides for the remote planner. Absent values leave each host's
/// defaults intact; these options never change its policy or authorize execution.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RemotePlanOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub goal: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_age: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_posterior: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_candidates: Option<u32>,
}

impl RemotePlanOptions {
    /// Validate before any connection, using the local planner's own goal grammar.
    pub fn validate(&self) -> Result<(), String> {
        if let Some(goal) = &self.goal {
            crate::decision::goal_parser::parse_goal(goal)
                .map_err(|error| format!("invalid fleet --goal: {error}"))?;
        }
        if self
            .min_posterior
            .is_some_and(|value| !value.is_finite() || !(0.0..=1.0).contains(&value))
        {
            return Err("--min-posterior must be a finite probability between 0 and 1".into());
        }
        if self.window_ms.is_some_and(|value| value > 60_000) {
            return Err("--window-ms must be between 0 and 60000".into());
        }
        Ok(())
    }

    fn is_empty(&self) -> bool {
        self.goal.is_none()
            && self.min_age.is_none()
            && self.min_posterior.is_none()
            && self.window_ms.is_none()
            && self.max_candidates.is_none()
    }

    fn append_args(&self, command: &mut Vec<String>) {
        if let Some(goal) = &self.goal {
            command.extend(["--goal".to_string(), goal.clone()]);
        }
        if let Some(value) = self.min_age {
            command.extend(["--min-age".to_string(), value.to_string()]);
        }
        if let Some(value) = self.min_posterior {
            command.extend(["--min-posterior".to_string(), value.to_string()]);
        }
        if let Some(value) = self.window_ms {
            command.extend(["--window-ms".to_string(), value.to_string()]);
        }
        if let Some(value) = self.max_candidates {
            command.extend(["--max-candidates".to_string(), value.to_string()]);
        }
    }

    /// Explicit controls require acknowledgment from the host's saved output.
    /// Old hosts may still use their defaults when no override was requested.
    fn validate_response(&self, document: &serde_json::Value) -> Result<(), String> {
        let args = &document["args"];
        for (name, mismatched) in [
            (
                "goal",
                self.goal.as_deref().is_some_and(|value| {
                    args["goal"].as_str() != Some(value) || document["goal"].as_str() != Some(value)
                }),
            ),
            (
                "min-age",
                self.min_age
                    .is_some_and(|value| args["min_age"].as_u64() != Some(value)),
            ),
            (
                "min-posterior",
                self.min_posterior
                    .is_some_and(|value| args["min_posterior"].as_f64() != Some(value)),
            ),
            (
                "window-ms",
                self.window_ms
                    .is_some_and(|value| args["window_ms"].as_u64() != Some(value)),
            ),
            (
                "max-candidates",
                self.max_candidates
                    .is_some_and(|value| args["max_candidates"].as_u64() != Some(u64::from(value))),
            ),
        ] {
            if mismatched {
                return Err(format!(
                    "remote plan did not acknowledge requested --{name}; inspect or upgrade the remote pt-core"
                ));
            }
        }
        if self.goal.is_some() {
            if let Some(error) = document["goal_summary"]["error"].as_str() {
                return Err(format!(
                    "remote planner could not prepare the requested goal: {error}"
                ));
            }
        }
        Ok(())
    }
}

/// Configuration for SSH-based fleet scanning.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SshScanConfig {
    /// Explicit SSH config used for alias discovery and subsequent connections.
    /// Retained with fleet execution so apply uses the same alias configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_file: Option<String>,
    /// SSH user (if different from current user).
    pub user: Option<String>,
    /// Path to SSH identity file.
    pub identity_file: Option<String>,
    /// SSH port (default: 22).
    pub port: Option<u16>,
    /// Connection timeout in seconds.
    pub connect_timeout: u64,
    /// Command timeout in seconds (total time for scan to complete).
    pub command_timeout: u64,
    /// Remote binary name/path (default: "pt-core").
    pub remote_binary: String,
    /// Extra SSH options passed via -o.
    pub ssh_options: Vec<String>,
    /// Maximum concurrent SSH connections.
    pub parallel: usize,
    /// Continue scanning remaining hosts if one fails.
    pub continue_on_error: bool,
    /// Optional host-local planner controls, retained with the fleet session.
    #[serde(skip_serializing_if = "RemotePlanOptions::is_empty")]
    pub plan_options: RemotePlanOptions,
}

impl Default for SshScanConfig {
    fn default() -> Self {
        Self {
            config_file: None,
            user: None,
            identity_file: None,
            port: None,
            connect_timeout: 10,
            command_timeout: 30,
            remote_binary: "pt-core".to_string(),
            ssh_options: vec![
                "StrictHostKeyChecking=accept-new".to_string(),
                "BatchMode=yes".to_string(),
            ],
            parallel: 10,
            continue_on_error: true,
            plan_options: RemotePlanOptions::default(),
        }
    }
}

/// Errors from SSH scanning.
#[derive(Debug, Error)]
pub enum SshScanError {
    #[error("ssh connection to {host} failed: {message}")]
    ConnectionFailed { host: String, message: String },
    #[error("ssh command on {host} timed out after {timeout_secs}s")]
    Timeout { host: String, timeout_secs: u64 },
    #[error("remote scan on {host} exited with code {code}: {stderr}")]
    RemoteError {
        host: String,
        code: i32,
        stderr: String,
    },
    #[error("failed to parse scan output from {host}: {message}")]
    ParseError { host: String, message: String },
    #[error("ssh binary not found: {0}")]
    SshNotFound(#[source] io::Error),
    #[error("fleet scan aborted: {0}")]
    Aborted(String),
}

/// Result of scanning a single host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostScanResult {
    pub host: String,
    pub success: bool,
    /// The host's own `agent plan` result (present when `success`).
    pub plan: Option<RemotePlan>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub duration_ms: u64,
    /// Per-host provenance summary (when provenance was active on the remote).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<HostProvenanceSummary>,
}

/// Provenance summary for a single fleet host.
///
/// Fleet scans may have partial or missing provenance evidence because
/// the remote host may run an older pt version or have provenance
/// disabled. This struct represents what was available honestly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostProvenanceSummary {
    /// Whether provenance was active on this host.
    pub enabled: bool,
    /// Number of candidates with provenance evidence.
    pub candidates_with_evidence: usize,
    /// Mean evidence completeness across candidates (0.0 to 1.0).
    pub mean_evidence_completeness: f64,
    /// Number of high/critical blast-radius candidates.
    pub high_risk_count: usize,
    /// Whether evidence was degraded (remote had limited probes).
    pub degraded: bool,
    /// Reason for degradation (if any).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub degradation_reason: Option<String>,
}

/// Result of a fleet-wide scan across all hosts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetScanResult {
    pub total_hosts: usize,
    pub successful: usize,
    pub failed: usize,
    pub results: Vec<HostScanResult>,
    pub duration_ms: u64,
    /// Fleet-wide provenance aggregate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance_aggregate: Option<FleetProvenanceAggregate>,
}

/// Fleet-wide provenance aggregate across all hosts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetProvenanceAggregate {
    /// Hosts where provenance was active.
    pub hosts_with_provenance: usize,
    /// Hosts where provenance was unavailable or degraded.
    pub hosts_without_provenance: usize,
    /// Total high/critical blast-radius candidates across the fleet.
    pub total_high_risk: usize,
    /// Fleet-wide mean evidence completeness.
    pub mean_evidence_completeness: f64,
}

/// One candidate from a host's own `agent plan`: its decision, passed through.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RemoteCandidate {
    pub pid: u32,
    /// Short command name (`command_short` in the plan).
    pub comm: String,
    pub classification: String,
    /// The plan's recommendation (e.g. `KILL`, `REVIEW`, `KEEP`).
    pub recommendation: String,
    /// P(abandoned or zombie) from the host's posterior.
    pub score: f64,
}

/// A host's `agent plan` result, as much as fleet aggregation needs.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RemotePlan {
    /// When the host produced the plan (RFC 3339).
    pub generated_at: String,
    /// pt version that produced the plan on the host.
    #[serde(default)]
    pub pt_version: Option<String>,
    pub total_processes: u64,
    pub candidates: Vec<RemoteCandidate>,
    /// The complete saved remote plan document, retained for identity-bound apply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub document: Option<serde_json::Value>,
}

/// Goal plans retain independent advice for candidates outside the selected
/// recovery set. Keep that advice in the original document, but never pool an
/// excluded kill as executable fleet work.
fn goal_recommendation(
    candidate: &serde_json::Value,
    plan: &crate::plan::Plan,
) -> Result<String, &'static str> {
    let recommendation = candidate["recommendation"].as_str().unwrap_or_default();
    if !recommendation.eq_ignore_ascii_case("kill") {
        return Ok(recommendation.to_string());
    }
    match candidate["goal_selected"].as_bool() {
        Some(false) => return Ok("REVIEW".to_string()),
        Some(true) => {}
        None => return Err("goal candidate is missing its explicit selection"),
    }
    let target: pt_common::ProcessIdentity =
        serde_json::from_value(candidate["action_target"].clone())
            .map_err(|_| "selected goal kill has no complete action target")?;
    if candidate["recommended_action"].as_str() != Some("kill")
        || candidate["pid"].as_u64() != Some(u64::from(target.pid.0))
        || candidate["start_id"].as_str() != Some(target.start_id.0.as_str())
        || candidate["uid"].as_u64() != Some(u64::from(target.uid))
        || !target.can_safely_revalidate()
    {
        return Err("selected goal kill has inconsistent process identity or advice");
    }
    let mut kills = plan
        .actions
        .iter()
        .filter(|action| action.target == target && action.action == crate::decision::Action::Kill);
    let kill = kills
        .next()
        .ok_or("selected goal kill is absent from the executable plan")?;
    if kills.next().is_some()
        || kill.blocked
        || kill.routing != crate::plan::ActionRouting::Direct
        || kill.original_zombie_target.is_some()
    {
        return Err("selected goal kill has a blocked, routed or ambiguous executable action");
    }
    Ok(recommendation.to_string())
}

/// Parse `pt-core --format json agent plan` output.
pub fn parse_remote_plan(json: &str) -> Result<RemotePlan, String> {
    let v: serde_json::Value = serde_json::from_str(json).map_err(|e| format!("not JSON: {e}"))?;
    let goal_plan = if !v["goal"].is_null()
        || !v["args"]["goal"].is_null()
        || v["summary"]["goal_mode"].as_bool() == Some(true)
    {
        Some(
            serde_json::from_value::<crate::plan::Plan>(v.clone())
                .map_err(|error| format!("goal output has no valid executable plan: {error}"))?,
        )
    } else {
        None
    };
    let total_processes = v["summary"]["total_processes_scanned"]
        .as_u64()
        .ok_or("not an `agent plan` output: summary.total_processes_scanned missing")?;
    let candidates = v["candidates"]
        .as_array()
        .ok_or("not an `agent plan` output: candidates missing")?
        .iter()
        .map(|c| {
            let pid = c["pid"]
                .as_u64()
                .and_then(|p| u32::try_from(p).ok())
                .ok_or("candidate without pid")?;
            let text = |key: &str| c[key].as_str().unwrap_or_default().to_string();
            let posterior = &c["posterior"];
            if !posterior.is_null() && !posterior.is_object() {
                return Err("candidate posterior is not an object");
            }
            let mut probabilities = [0.0; 4];
            for (index, class) in ["useful", "useful_bad", "abandoned", "zombie"]
                .iter()
                .enumerate()
            {
                if let Some(value) = posterior.get(class) {
                    probabilities[index] = value
                        .as_f64()
                        .filter(|probability| {
                            probability.is_finite() && (0.0..=1.0).contains(probability)
                        })
                        .ok_or("candidate posterior contains an invalid probability")?;
                }
            }
            if probabilities.iter().sum::<f64>() > 1.0 + 1e-9 {
                return Err("candidate posterior probabilities exceed one");
            }
            Ok(RemoteCandidate {
                pid,
                comm: text("command_short"),
                classification: text("classification"),
                recommendation: match &goal_plan {
                    Some(plan) => goal_recommendation(c, plan)?,
                    None => text("recommendation"),
                },
                score: (probabilities[2] + probabilities[3]).min(1.0),
            })
        })
        .collect::<Result<Vec<_>, &str>>()?;
    Ok(RemotePlan {
        generated_at: v["generated_at"].as_str().unwrap_or_default().to_string(),
        pt_version: v["pt_version"].as_str().map(str::to_string),
        total_processes,
        candidates,
        document: Some(v),
    })
}

/// Read a sensor independently: a malformed memory reading must not hide a valid
/// CPU-pressure observation, or invalidate the remote host's process decisions.
fn remote_sensor<T: DeserializeOwned>(
    value: Option<&serde_json::Value>,
    source: &str,
    required: bool,
    unavailable: &mut Vec<Unavailable>,
) -> Option<T> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        if required {
            unavailable.push(Unavailable {
                source: source.to_string(),
                reason: "not reported by the remote host".to_string(),
            });
        }
        return None;
    };
    match serde_json::from_value(value.clone()) {
        Ok(value) => Some(value),
        Err(error) => {
            unavailable.push(Unavailable {
                source: source.to_string(),
                reason: format!("invalid remote observation: {error}"),
            });
            None
        }
    }
}

fn remote_psi(
    pressure: &serde_json::Value,
    name: &str,
    required: bool,
    unavailable: &mut Vec<Unavailable>,
) -> Option<PsiResource> {
    let source = format!("system_state.pressure.{name}");
    let resource = remote_sensor::<serde_json::Map<String, serde_json::Value>>(
        pressure.get(name),
        &source,
        required,
        unavailable,
    )?;
    let mut line = |name: &str, required: bool| {
        let source = format!("{source}.{name}");
        let line = remote_sensor::<PsiLine>(resource.get(name), &source, required, unavailable)?;
        if [line.avg10, line.avg60, line.avg300]
            .iter()
            .all(|average| average.is_finite() && (0.0..=100.0).contains(average))
        {
            Some(line)
        } else {
            unavailable.push(Unavailable {
                source,
                reason: "PSI averages must be finite percentages between 0 and 100".to_string(),
            });
            None
        }
    };
    let some = line("some", required);
    let full = line("full", false);
    (some.is_some() || full.is_some()).then_some(PsiResource { some, full })
}

/// Accept a measured rate only with its matching remote cumulative endpoint.
/// The start counter is not transmitted, but a nonnegative delta cannot exceed
/// the ending counter. Allow only floating-point roundoff in that comparison.
fn remote_window_counter_rate(
    value: Option<&serde_json::Value>,
    source: &str,
    elapsed: f64,
    end_counter: Option<u64>,
    unavailable: &mut Vec<Unavailable>,
) -> Option<f64> {
    let value = remote_sensor::<f64>(value, source, end_counter.is_some(), unavailable)?;
    let delta = value * elapsed;
    let reason = if !value.is_finite() || value < 0.0 {
        Some("window measurement must be finite and nonnegative")
    } else if let Some(counter) = end_counter {
        let maximum = counter as f64;
        let tolerance = maximum.max(1.0) * f64::EPSILON * 8.0;
        if !delta.is_finite() || delta > maximum + tolerance {
            Some("window delta exceeds its ending cumulative counter")
        } else {
            None
        }
    } else {
        Some("ending cumulative counter unavailable for window measurement")
    };
    if let Some(reason) = reason {
        unavailable.push(Unavailable {
            source: source.to_string(),
            reason: reason.to_string(),
        });
        None
    } else {
        Some(value)
    }
}

fn remote_window_stalls(
    value: Option<&serde_json::Value>,
    name: &str,
    endpoint: Option<PsiResource>,
    seconds: f64,
    unavailable: &mut Vec<Unavailable>,
) -> Option<StallFractions> {
    let source = format!("system_state.pressure_window.{name}");
    let raw = remote_sensor::<serde_json::Map<String, serde_json::Value>>(
        value,
        &source,
        endpoint.is_some(),
        unavailable,
    )?;
    let mut fraction = |name: &str, line: Option<PsiLine>| {
        let source = format!("{source}.{name}");
        let fraction = remote_window_counter_rate(
            raw.get(name),
            &source,
            seconds * 1e6,
            line.map(|line| line.total_us),
            unavailable,
        )?;
        if fraction <= 1.0 {
            Some(fraction)
        } else {
            unavailable.push(Unavailable {
                source,
                reason: "PSI window fraction must be between zero and one".to_string(),
            });
            None
        }
    };
    let some = fraction("some", endpoint.and_then(|resource| resource.some));
    let mut full = fraction("full", endpoint.and_then(|resource| resource.full));
    if some.zip(full).is_some_and(|(some, full)| full > some) {
        full = None;
        unavailable.push(Unavailable {
            source: format!("{source}.full"),
            reason: "full-stall fraction exceeds the some-stall fraction".to_string(),
        });
    }
    (some.is_some() || full.is_some()).then_some(StallFractions { some, full })
}

/// Parse optional host-measured intervals without trusting the remote diagnosis.
/// One bad channel leaves independently valid channels available. No interval
/// is inferred from controller time, SSH duration, or cumulative counters alone.
fn remote_pressure_window(
    value: Option<&serde_json::Value>,
    snapshot: &PressureSnapshot,
    unavailable: &mut Vec<Unavailable>,
) -> Option<PressureWindow> {
    let raw = remote_sensor::<serde_json::Map<String, serde_json::Value>>(
        value,
        "system_state.pressure_window",
        false,
        unavailable,
    )?;
    if snapshot.unavailable.iter().any(|issue| {
        issue.source == "pressure_window"
            || issue.source.starts_with("system_state.pressure_window")
    }) {
        unavailable.push(Unavailable {
            source: "system_state.pressure_window".to_string(),
            reason: "remote host reported the pressure window unavailable".to_string(),
        });
        return None;
    }
    let seconds = remote_sensor::<f64>(
        raw.get("seconds"),
        "system_state.pressure_window.seconds",
        true,
        unavailable,
    )?;
    if !seconds.is_finite() || seconds <= 0.0 {
        unavailable.push(Unavailable {
            source: "system_state.pressure_window.seconds".to_string(),
            reason: "measured interval must be finite and positive".to_string(),
        });
        return None;
    }
    let cpu = remote_window_stalls(raw.get("cpu"), "cpu", snapshot.cpu, seconds, unavailable);
    let memory = remote_window_stalls(
        raw.get("memory"),
        "memory",
        snapshot.memory,
        seconds,
        unavailable,
    );
    let io = remote_window_stalls(raw.get("io"), "io", snapshot.io, seconds, unavailable);
    let vm = snapshot.vmstat;
    let mut rate = |name: &str, counter: Option<u64>| {
        remote_window_counter_rate(
            raw.get(name),
            &format!("system_state.pressure_window.{name}"),
            seconds,
            counter,
            unavailable,
        )
    };
    let swap_in_per_s = rate("swap_in_per_s", vm.and_then(|vm| vm.pswpin));
    let swap_out_per_s = rate("swap_out_per_s", vm.and_then(|vm| vm.pswpout));
    let major_faults_per_s = rate("major_faults_per_s", vm.and_then(|vm| vm.pgmajfault));
    let direct_reclaim_scans_per_s = rate(
        "direct_reclaim_scans_per_s",
        vm.and_then(|vm| vm.pgscan_direct),
    );
    let alloc_stalls_per_s = rate("alloc_stalls_per_s", vm.and_then(|vm| vm.allocstall));
    let oom_total = vm.and_then(|vm| vm.oom_kill);
    let oom_kills = remote_sensor::<u64>(
        raw.get("oom_kills"),
        "system_state.pressure_window.oom_kills",
        oom_total.is_some(),
        unavailable,
    )
    .filter(|delta| {
        if oom_total.is_some_and(|total| *delta <= total) {
            true
        } else {
            unavailable.push(Unavailable {
                source: "system_state.pressure_window.oom_kills".to_string(),
                reason: "OOM delta has no matching ending counter or exceeds it".to_string(),
            });
            false
        }
    });
    Some(PressureWindow {
        seconds,
        cpu,
        memory,
        io,
        swap_in_per_s,
        swap_out_per_s,
        major_faults_per_s,
        direct_reclaim_scans_per_s,
        alloc_stalls_per_s,
        oom_kills,
    })
}

/// Recompute host health from remote measurements, never from the remote
/// `assessment` or a claimed severity. No local host readings fill remote gaps.
pub(super) fn remote_health(
    system_state: Option<&serde_json::Value>,
    total_processes: u64,
) -> HostHealth {
    let Some(system_state) = system_state.filter(|value| value.is_object()) else {
        return HostHealth::default();
    };
    let Some(raw) = system_state
        .get("pressure")
        .filter(|value| value.is_object())
    else {
        return HostHealth::default();
    };
    let mut unavailable = Vec::new();
    let Some(sampled_at_ms) = remote_sensor::<u64>(
        raw.get("sampled_at_ms"),
        "system_state.pressure.sampled_at_ms",
        true,
        &mut unavailable,
    ) else {
        return HostHealth {
            unavailable,
            ..HostHealth::default()
        };
    };
    let cpus = remote_sensor::<u32>(
        raw.get("cpus"),
        "system_state.pressure.cpus",
        true,
        &mut unavailable,
    )
    .unwrap_or(0);
    if cpus == 0 && raw.get("cpus").and_then(serde_json::Value::as_u64) == Some(0) {
        unavailable.push(Unavailable {
            source: "system_state.pressure.cpus".to_string(),
            reason: "online CPU count is unavailable".to_string(),
        });
    }
    let cpu = remote_psi(raw, "cpu", true, &mut unavailable);
    let memory = remote_psi(raw, "memory", true, &mut unavailable);
    let io = remote_psi(raw, "io", true, &mut unavailable);
    let irq = remote_psi(raw, "irq", false, &mut unavailable);
    let load = remote_sensor::<LoadAvg>(
        raw.get("load"),
        "system_state.pressure.load",
        true,
        &mut unavailable,
    )
    .filter(|load| {
        let valid = [load.one, load.five, load.fifteen]
            .iter()
            .all(|value| value.is_finite() && *value >= 0.0);
        if !valid {
            unavailable.push(Unavailable {
                source: "system_state.pressure.load".to_string(),
                reason: "load averages must be finite and nonnegative".to_string(),
            });
        }
        valid
    });
    let meminfo = remote_sensor::<MemInfo>(
        raw.get("meminfo"),
        "system_state.pressure.meminfo",
        true,
        &mut unavailable,
    )
    .map(|mut memory| {
        if memory.total == Some(0)
            || memory
                .total
                .zip(memory.available)
                .is_some_and(|(total, available)| available > total)
        {
            memory.total = None;
            memory.available = None;
            unavailable.push(Unavailable {
                source: "system_state.pressure.meminfo".to_string(),
                reason: "RAM total must be positive and available RAM must not exceed it"
                    .to_string(),
            });
        }
        if memory
            .swap_total
            .zip(memory.swap_free)
            .is_some_and(|(total, free)| free > total)
        {
            memory.swap_total = None;
            memory.swap_free = None;
            unavailable.push(Unavailable {
                source: "system_state.pressure.meminfo".to_string(),
                reason: "free swap must not exceed total swap".to_string(),
            });
        }
        for (field, value) in [
            ("total", memory.total),
            ("available", memory.available),
            ("swap_total", memory.swap_total),
            ("swap_free", memory.swap_free),
        ] {
            if value.is_none() {
                unavailable.push(Unavailable {
                    source: format!("system_state.pressure.meminfo.{field}"),
                    reason: "required snapshot-health reading unavailable".to_string(),
                });
            }
        }
        memory
    });
    let file_handles = remote_sensor::<FileHandles>(
        raw.get("file_handles"),
        "system_state.pressure.file_handles",
        true,
        &mut unavailable,
    )
    .filter(|handles| {
        if handles.max == 0 {
            unavailable.push(Unavailable {
                source: "system_state.pressure.file_handles".to_string(),
                reason: "file-handle limit is unavailable".to_string(),
            });
            false
        } else {
            // Allocations above the configured limit are pressure, not bad data.
            true
        }
    });
    let vmstat = remote_sensor::<VmStat>(
        raw.get("vmstat"),
        "system_state.pressure.vmstat",
        false,
        &mut unavailable,
    );
    let census = remote_sensor::<ProcessCensus>(
        system_state.get("census"),
        "system_state.census",
        true,
        &mut unavailable,
    )
    .filter(|census| {
        if u64::from(census.zombies) + u64::from(census.dstate) > total_processes {
            unavailable.push(Unavailable {
                source: "system_state.census".to_string(),
                reason: "process-state counts exceed the reported scan population".to_string(),
            });
            false
        } else {
            true
        }
    });
    let reported_unavailable = remote_sensor::<Vec<Unavailable>>(
        raw.get("unavailable"),
        "system_state.pressure.unavailable",
        false,
        &mut unavailable,
    )
    .unwrap_or_default();

    // Optional fields may be absent, but an explicit remote evidence failure
    // cannot earn an all-clear even if that host also supplies fallback numbers.
    unavailable.extend(reported_unavailable);
    let mut snapshot = PressureSnapshot {
        sampled_at_ms,
        cpus,
        cpu,
        memory,
        io,
        irq,
        load,
        meminfo,
        vmstat,
        file_handles,
        unavailable: unavailable.clone(),
    };
    // Some older/custom producers accompany unavailable sensors with fallback
    // numbers. Keep the raw block, but never assess those as observations.
    for issue in &snapshot.unavailable {
        match issue.source.as_str() {
            "online_cpu_count" | "hw.logicalcpu" => snapshot.cpus = 0,
            "/proc/pressure/cpu" => snapshot.cpu = None,
            "/proc/pressure/memory" => snapshot.memory = None,
            "/proc/pressure/io" => snapshot.io = None,
            "/proc/pressure/irq" => snapshot.irq = None,
            "/proc/loadavg" | "getloadavg" => snapshot.load = None,
            "/proc/meminfo" => snapshot.meminfo = None,
            "/proc/vmstat" => snapshot.vmstat = None,
            "/proc/sys/fs/file-nr" | "kern.num_files/kern.maxfiles" => snapshot.file_handles = None,
            "kern.memorystatus_vm_pressure_level" => {
                if let Some(memory) = &mut snapshot.meminfo {
                    memory.macos_pressure = None;
                }
            }
            "hw.memsize" => {
                if let Some(memory) = &mut snapshot.meminfo {
                    memory.total = None;
                }
            }
            "vm.swapusage" => {
                if let Some(memory) = &mut snapshot.meminfo {
                    memory.swap_total = None;
                    memory.swap_free = None;
                }
            }
            "vm_stat" => {
                snapshot.vmstat = None;
                if let Some(memory) = &mut snapshot.meminfo {
                    memory.free = None;
                    memory.cached = None;
                    memory.anon = None;
                }
            }
            _ => {}
        }
    }
    let pressure_window = remote_pressure_window(
        system_state.get("pressure_window"),
        &snapshot,
        &mut unavailable,
    );
    let complete = unavailable.is_empty();
    snapshot.unavailable = unavailable.clone();
    let observed = snapshot.cpu.and_then(|resource| resource.some).is_some()
        || snapshot.memory.and_then(|resource| resource.some).is_some()
        || snapshot.io.and_then(|resource| resource.some).is_some()
        || snapshot.load_ratio().is_some()
        || snapshot.meminfo.is_some_and(|memory| {
            memory.used_fraction().is_some()
                || memory.swap_used().is_some()
                || memory.macos_pressure.is_some()
        })
        || snapshot.file_handles.is_some()
        || pressure_window.as_ref().is_some_and(|window| {
            window.oom_kills.is_some()
                || (window.swap_in_per_s.is_some() && window.swap_out_per_s.is_some())
        })
        || census.is_some();
    let assessment = observed.then(|| {
        assess(
            &snapshot,
            pressure_window.as_ref(),
            census.as_ref(),
            &PressureThresholds::default(),
        )
    });
    let coverage = if complete {
        PressureCoverage::Complete
    } else if observed {
        PressureCoverage::Partial
    } else {
        PressureCoverage::Unavailable
    };
    let status = match assessment.as_ref().map(|assessment| assessment.worst) {
        Some(Severity::Crit) => HostHealthStatus::Crit,
        Some(Severity::Warn) => HostHealthStatus::Warn,
        Some(Severity::Ok) if complete => HostHealthStatus::Ok,
        _ => HostHealthStatus::Unknown,
    };
    HostHealth {
        status,
        coverage,
        pressure: Some(snapshot),
        pressure_window,
        census,
        assessment,
        unavailable,
    }
}

/// Quote one remote-shell argument without interpreting it as shell syntax.
pub(super) fn shell_argument(value: &str) -> String {
    if !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_./:@%+=,-".contains(&byte))
    {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

pub(super) fn validate_ssh_target(host: &str) -> Result<(), String> {
    if host.is_empty()
        || host.starts_with('-')
        || host.contains('\0')
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._@:%[]".contains(&byte))
        || host.matches('@').count() > 1
        || host
            .split('@')
            .any(|part| part.is_empty() || part.starts_with('-'))
    {
        return Err(format!("invalid SSH target: {host:?}"));
    }
    Ok(())
}

/// Build argv for the existing SSH executor; the remote command is one quoted
/// argument vector, never an interpolated shell program.
pub(super) fn build_ssh_command_args(
    host: &str,
    config: &SshScanConfig,
    command: &[String],
) -> Result<Vec<String>, String> {
    let target = if let Some(ref user) = config.user {
        format!("{user}@{host}")
    } else {
        host.to_string()
    };
    validate_ssh_target(&target)?;
    if command.is_empty() || command.iter().any(|argument| argument.contains('\0')) {
        return Err("invalid remote command argument".to_string());
    }
    let mut args = Vec::new();
    if let Some(ref path) = config.config_file {
        if path.is_empty() || path.contains('\0') {
            return Err("invalid SSH config path".to_string());
        }
        args.push("-F".to_string());
        args.push(path.clone());
    }
    args.push("-o".to_string());
    args.push(format!("ConnectTimeout={}", config.connect_timeout));
    for option in &config.ssh_options {
        args.push("-o".to_string());
        args.push(option.clone());
    }
    if let Some(ref identity) = config.identity_file {
        args.push("-i".to_string());
        args.push(identity.clone());
    }
    if let Some(port) = config.port {
        args.push("-p".to_string());
        args.push(port.to_string());
    }
    args.push("--".to_string());
    args.push(target);
    args.push(
        command
            .iter()
            .map(|argument| shell_argument(argument))
            .collect::<Vec<_>>()
            .join(" "),
    );
    Ok(args)
}

/// Build the SSH command arguments for scanning a remote host.
fn build_ssh_args(host: &str, config: &SshScanConfig) -> Result<Vec<String>, String> {
    config.plan_options.validate()?;
    let mut command = vec![
        config.remote_binary.clone(),
        "--format".to_string(),
        "json".to_string(),
        "agent".to_string(),
        "plan".to_string(),
    ];
    config.plan_options.append_args(&mut command);
    build_ssh_command_args(host, config, &command)
}

/// Scan a single host via SSH and parse the result.
pub fn ssh_scan_host(host: &str, config: &SshScanConfig) -> HostScanResult {
    let start = std::time::Instant::now();

    let args = match build_ssh_args(host, config) {
        Ok(args) => args,
        Err(error) => {
            return HostScanResult {
                host: host.to_string(),
                success: false,
                plan: None,
                error: Some(error),
                duration_ms: 0,
                provenance: None,
            };
        }
    };
    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let timeout = Duration::from_secs(config.command_timeout);

    let output = match crate::collect::tool_runner::run_ssh_tool(&args_ref, Some(timeout), None) {
        Ok(output) => output,
        Err(crate::collect::tool_runner::ToolError::CommandNotFound(_)) => {
            return HostScanResult {
                host: host.to_string(),
                success: false,
                plan: None,
                error: Some("ssh binary not found".to_string()),
                duration_ms: start.elapsed().as_millis() as u64,
                provenance: None,
            };
        }
        Err(crate::collect::tool_runner::ToolError::Timeout(_)) => {
            return HostScanResult {
                host: host.to_string(),
                success: false,
                plan: None,
                error: Some(format!("timed out after {}s", config.command_timeout)),
                duration_ms: start.elapsed().as_millis() as u64,
                provenance: None,
            };
        }
        Err(e) => {
            return HostScanResult {
                host: host.to_string(),
                success: false,
                plan: None,
                error: Some(format!("ssh failed: {}", e)),
                duration_ms: start.elapsed().as_millis() as u64,
                provenance: None,
            };
        }
    };

    let duration_ms = start.elapsed().as_millis() as u64;

    if output.timed_out || output.truncated {
        return HostScanResult {
            host: host.to_string(),
            success: false,
            plan: None,
            error: Some(if output.timed_out {
                format!("timed out after {}s", config.command_timeout)
            } else {
                "remote plan output was truncated".to_string()
            }),
            duration_ms,
            provenance: None,
        };
    }

    // `agent plan` exits 0 (nothing to do) or 1 (plan has candidates).
    if !matches!(output.exit_code, Some(0) | Some(1)) {
        let stderr = output.stderr_str();
        let code = output.exit_code.unwrap_or(-1);
        return HostScanResult {
            host: host.to_string(),
            success: false,
            plan: None,
            error: Some(format!("exit code {}: {}", code, stderr.trim())),
            duration_ms,
            provenance: None,
        };
    }

    let parsed = parse_remote_plan(&output.stdout_str()).and_then(|plan| {
        let document = plan
            .document
            .as_ref()
            .ok_or("remote plan document missing")?;
        config.plan_options.validate_response(document)?;
        Ok(plan)
    });
    match parsed {
        Ok(plan) => HostScanResult {
            host: host.to_string(),
            success: true,
            plan: Some(plan),
            error: None,
            duration_ms,
            provenance: None,
        },
        Err(e) => HostScanResult {
            host: host.to_string(),
            success: false,
            plan: None,
            error: Some(format!("failed to parse agent plan output: {e}")),
            duration_ms,
            provenance: None,
        },
    }
}

/// Scan multiple hosts in parallel via SSH.
///
/// A bounded worker pool takes the next host whenever a connection finishes, so
/// one slow host cannot strand the other slots behind a batch barrier. Results
/// remain in input order. When continuation is disabled, a failed result stops
/// new dispatch immediately; already running hosts still finish and are retained.
pub fn ssh_scan_fleet(hosts: &[String], config: &SshScanConfig) -> FleetScanResult {
    ssh_scan_fleet_with(hosts, config, ssh_scan_host)
}

fn ssh_scan_fleet_with<F>(hosts: &[String], config: &SshScanConfig, scan_host: F) -> FleetScanResult
where
    F: Fn(&str, &SshScanConfig) -> HostScanResult + Sync,
{
    let start = std::time::Instant::now();
    let (collected, _) = run_host_pool(
        hosts,
        config.parallel,
        usize::from(!config.continue_on_error),
        |host| scan_host(host, config),
        |result| result.success,
        |host, duration_ms| HostScanResult {
            host: host.to_string(),
            success: false,
            plan: None,
            error: Some("fleet scan worker panicked while reading the remote plan".into()),
            duration_ms,
            provenance: None,
        },
    );
    let results = complete_scan_results(hosts, collected);
    let successful = results.iter().filter(|r| r.success).count();
    let failed = results.iter().filter(|r| !r.success).count();

    FleetScanResult {
        total_hosts: hosts.len(),
        successful,
        failed,
        results,
        duration_ms: start.elapsed().as_millis() as u64,
        provenance_aggregate: None, // Populated when remote hosts report provenance
    }
}

/// Shared sliding pool for remote plans and read-only host inspections. Zero
/// disables the failure limit. Otherwise consecutive completed failures stop
/// new dispatch; an already running success cannot reopen the circuit.
pub(super) fn run_host_pool<R, F, S, P>(
    hosts: &[String],
    parallel: usize,
    max_consecutive_failures: usize,
    run_host: F,
    succeeded: S,
    panicked: P,
) -> (Vec<(usize, R)>, bool)
where
    R: Send,
    F: Fn(&str) -> R + Sync,
    S: Fn(&R) -> bool + Sync,
    P: Fn(&str, u64) -> R + Sync,
{
    let results = Mutex::new(Vec::with_capacity(hosts.len()));
    // Both assignment and failure publication use this lock. A worker cannot
    // take another host after a failure has stopped dispatch.
    let dispatch = Mutex::new((0_usize, false, 0_usize));
    let parallel = parallel.clamp(1, super::apply::MAX_FLEET_PARALLEL);

    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..parallel.min(hosts.len()))
            .map(|_| {
                let results = &results;
                let dispatch = &dispatch;
                let run_host = &run_host;
                let succeeded = &succeeded;
                let panicked = &panicked;
                scope.spawn(move || loop {
                    let index = {
                        let mut work = dispatch.lock().expect("dispatch lock poisoned");
                        let (next, stopped, _) = &mut *work;
                        if *stopped || *next >= hosts.len() {
                            break;
                        }
                        let index = *next;
                        *next += 1;
                        index
                    };

                    let host_started = std::time::Instant::now();
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        run_host(&hosts[index])
                    }))
                    .unwrap_or_else(|_| {
                        panicked(&hosts[index], host_started.elapsed().as_millis() as u64)
                    });
                    {
                        let mut work = dispatch.lock().expect("dispatch lock poisoned");
                        if succeeded(&result) {
                            work.2 = 0;
                        } else {
                            work.2 = work.2.saturating_add(1);
                            if max_consecutive_failures > 0 && work.2 >= max_consecutive_failures {
                                work.1 = true;
                            }
                        }
                    }
                    results
                        .lock()
                        .expect("results lock poisoned")
                        .push((index, result));
                })
            })
            .collect();
        for handle in handles {
            let _ = handle.join();
        }
    });

    (
        results.into_inner().expect("results lock poisoned"),
        dispatch.into_inner().expect("dispatch lock poisoned").1,
    )
}

/// Preserve every requested host when an earlier failure stops dispatch or a
/// worker fails. Omitted hosts must not silently disappear from saved approval.
fn complete_scan_results(
    hosts: &[String],
    collected: Vec<(usize, HostScanResult)>,
) -> Vec<HostScanResult> {
    let mut by_index: std::collections::HashMap<_, _> = collected.into_iter().collect();
    hosts
        .iter()
        .enumerate()
        .map(|(index, host)| {
            by_index.remove(&index).unwrap_or_else(|| HostScanResult {
                host: host.clone(),
                success: false,
                plan: None,
                error: Some(
                    "no plan returned: fleet dispatch stopped or worker failed".to_string(),
                ),
                duration_ms: 0,
                provenance: None,
            })
        })
        .collect()
}

/// Convert a HostScanResult into a HostInput for fleet session aggregation.
pub fn scan_result_to_host_input(result: &HostScanResult) -> crate::session::fleet::HostInput {
    use crate::session::fleet::{CandidateInfo, HostInput};

    match &result.plan {
        // Host decisions retain their final goal selection, if any. The complete
        // document also preserves independent advice for excluded candidates.
        Some(plan) => HostInput {
            host_id: result.host.clone(),
            session_id: plan
                .document
                .as_ref()
                .and_then(|document| document["session_id"].as_str())
                .unwrap_or("")
                .to_string(),
            scanned_at: plan.generated_at.clone(),
            total_processes: u32::try_from(plan.total_processes).unwrap_or(u32::MAX),
            candidates: plan
                .candidates
                .iter()
                .map(|c| CandidateInfo {
                    pid: c.pid,
                    signature: c.comm.clone(),
                    classification: c.classification.clone(),
                    recommended_action: c.recommendation.to_ascii_lowercase(),
                    score: c.score,
                    e_value: None,
                })
                .collect(),
            host: plan
                .document
                .as_ref()
                .and_then(|document| document.get("host"))
                .filter(|host| !host.is_null())
                .cloned(),
            system_state: plan
                .document
                .as_ref()
                .and_then(|document| document.get("system_state"))
                .filter(|state| !state.is_null())
                .cloned(),
            health: if result.success {
                remote_health(
                    plan.document
                        .as_ref()
                        .and_then(|document| document.get("system_state")),
                    plan.total_processes,
                )
            } else {
                failed_host_health(result)
            },
        },
        None => HostInput {
            host_id: result.host.clone(),
            session_id: format!("ssh-{}-failed", result.host),
            scanned_at: chrono::Utc::now().to_rfc3339(),
            total_processes: 0,
            candidates: Vec::new(),
            host: None,
            system_state: None,
            health: failed_host_health(result),
        },
    }
}

fn failed_host_health(result: &HostScanResult) -> HostHealth {
    HostHealth {
        unavailable: vec![Unavailable {
            source: "remote_scan".to_string(),
            reason: result
                .error
                .clone()
                .unwrap_or_else(|| "remote scan returned no usable plan".to_string()),
        }],
        ..HostHealth::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let config = SshScanConfig::default();
        assert_eq!(config.connect_timeout, 10);
        assert_eq!(config.command_timeout, 30);
        assert_eq!(config.parallel, 10);
        assert!(config.continue_on_error);
        assert_eq!(config.remote_binary, "pt-core");
    }

    #[test]
    fn build_ssh_args_basic() {
        let config = SshScanConfig::default();
        let args = build_ssh_args("myhost", &config).unwrap();

        assert!(args.iter().any(|i| i == "-o"));
        assert!(args.iter().any(|i| i == "ConnectTimeout=10"));
        assert!(args.iter().any(|i| i == "BatchMode=yes"));
        assert!(args.iter().any(|i| i == "myhost"));
        assert_eq!(
            args.last().map(String::as_str),
            Some("pt-core --format json agent plan")
        );
    }

    #[cfg(unix)]
    #[test]
    fn remote_planner_controls_survive_transport_and_shell_parsing() {
        let goal = r#"free-disk 1GB on "/data/agent's $(printf injected); cache""#;
        let config = SshScanConfig {
            remote_binary: "/opt/pt tools/pt-core".to_string(),
            plan_options: RemotePlanOptions {
                goal: Some(goal.to_string()),
                min_age: Some(0),
                min_posterior: Some(0.0),
                window_ms: Some(60_000),
                max_candidates: Some(200),
            },
            ..SshScanConfig::default()
        };
        let restored: SshScanConfig =
            serde_json::from_str(&serde_json::to_string(&config).unwrap()).unwrap();
        assert_eq!(restored.plan_options, config.plan_options);
        let args = build_ssh_args("worker", &restored).unwrap();
        // Parse exactly as the remote shell would, without running a planner.
        // If quoting regresses, command substitution changes the captured goal.
        let script = format!("set -- {}; printf '%s\\000' \"$@\"", args.last().unwrap());
        let output = std::process::Command::new("/bin/sh")
            .args(["-c", &script])
            .output()
            .unwrap();
        assert!(output.status.success());
        let bytes = output.stdout.strip_suffix(&[0]).unwrap();
        let parsed: Vec<_> = bytes
            .split(|byte| *byte == 0)
            .map(|argument| std::str::from_utf8(argument).unwrap())
            .collect();
        assert_eq!(
            parsed,
            [
                "/opt/pt tools/pt-core",
                "--format",
                "json",
                "agent",
                "plan",
                "--goal",
                goal,
                "--min-age",
                "0",
                "--min-posterior",
                "0",
                "--window-ms",
                "60000",
                "--max-candidates",
                "200",
            ]
        );
        let old: SshScanConfig = serde_json::from_str("{}").unwrap();
        assert!(old.plan_options.is_empty());
        assert_eq!(
            build_ssh_args("worker", &old).unwrap().last().unwrap(),
            "pt-core --format json agent plan"
        );
    }

    #[test]
    fn remote_planner_controls_reject_invalid_requests_before_ssh() {
        for goal in [
            "",
            "free port 70000",
            "free 1GB RAM and silently ignore this",
        ] {
            let config = SshScanConfig {
                plan_options: RemotePlanOptions {
                    goal: Some(goal.into()),
                    ..RemotePlanOptions::default()
                },
                ..SshScanConfig::default()
            };
            assert!(build_ssh_args("worker", &config).is_err(), "{goal:?}");
        }
        for probability in [f64::NAN, f64::INFINITY, -0.1, 1.01] {
            let options = RemotePlanOptions {
                min_posterior: Some(probability),
                ..RemotePlanOptions::default()
            };
            assert!(options.validate().is_err(), "{probability}");
        }
        assert!(RemotePlanOptions {
            window_ms: Some(60_001),
            ..RemotePlanOptions::default()
        }
        .validate()
        .is_err());
        for boundary in [0, 60_000] {
            assert!(RemotePlanOptions {
                window_ms: Some(boundary),
                min_age: Some(0),
                max_candidates: Some(0),
                ..RemotePlanOptions::default()
            }
            .validate()
            .is_ok());
        }
    }

    #[test]
    fn explicit_remote_controls_require_matching_saved_arguments() {
        let options = RemotePlanOptions {
            goal: Some("free port 43123".into()),
            min_age: Some(0),
            min_posterior: Some(0.25),
            window_ms: Some(1000),
            max_candidates: Some(40),
        };
        let document = serde_json::json!({
            "goal": "free port 43123",
            "args": {
                "goal": "free port 43123",
                "min_age": 0,
                "min_posterior": 0.25,
                "window_ms": 1000,
                "max_candidates": 40,
            },
        });
        assert!(options.validate_response(&document).is_ok());
        assert!(RemotePlanOptions::default()
            .validate_response(&serde_json::json!({}))
            .is_ok());
        for (field, flag, changed) in [
            ("goal", "--goal", serde_json::json!("free port 43124")),
            ("min_age", "--min-age", serde_json::json!(3600)),
            ("min_posterior", "--min-posterior", serde_json::json!(0.7)),
            ("window_ms", "--window-ms", serde_json::json!(500)),
            ("max_candidates", "--max-candidates", serde_json::json!(20)),
        ] {
            for value in [changed, serde_json::Value::Null] {
                let mut stale = document.clone();
                stale["args"][field] = value;
                assert!(
                    options
                        .validate_response(&stale)
                        .unwrap_err()
                        .contains(flag),
                    "{field}"
                );
            }
        }
        let mut no_goal = document.clone();
        no_goal["goal"] = serde_json::Value::Null;
        assert!(options
            .validate_response(&no_goal)
            .unwrap_err()
            .contains("--goal"));
        let mut failed_goal = document;
        failed_goal["goal_summary"] = serde_json::json!({"error": "private memory unavailable"});
        assert!(options
            .validate_response(&failed_goal)
            .unwrap_err()
            .contains("private memory unavailable"));
    }

    #[test]
    fn explicit_ssh_config_preserves_the_alias_and_literal_path() {
        let config = SshScanConfig {
            config_file: Some("/tmp/fleet config;literal".to_string()),
            ..SshScanConfig::default()
        };
        let args = build_ssh_args("worker-alias", &config).unwrap();
        assert_eq!(&args[..2], &["-F", "/tmp/fleet config;literal"]);
        let separator = args.iter().position(|argument| argument == "--").unwrap();
        assert_eq!(args[separator + 1], "worker-alias");
        assert_eq!(args.len(), separator + 3);
    }

    #[test]
    fn ssh_config_path_survives_transport_serialization() {
        let config = SshScanConfig {
            config_file: Some("/tmp/fleet/config".to_string()),
            ..SshScanConfig::default()
        };
        let restored: SshScanConfig =
            serde_json::from_str(&serde_json::to_string(&config).unwrap()).unwrap();
        assert_eq!(restored.config_file, config.config_file);
        // Previously saved fleet sessions still use the normal SSH configuration.
        let previous: SshScanConfig = serde_json::from_str("{}").unwrap();
        assert!(previous.config_file.is_none());
        assert!(!build_ssh_args("worker", &previous)
            .unwrap()
            .iter()
            .any(|i| i == "-F"));
    }

    #[test]
    fn invalid_ssh_config_paths_are_rejected_before_connecting() {
        for path in ["", "/tmp/config\0suffix"] {
            let config = SshScanConfig {
                config_file: Some(path.to_string()),
                ..SshScanConfig::default()
            };
            assert!(build_ssh_args("worker", &config).is_err());
        }
    }

    #[test]
    fn build_ssh_args_with_user() {
        let config = SshScanConfig {
            user: Some("admin".to_string()),
            ..SshScanConfig::default()
        };
        let args = build_ssh_args("myhost", &config).unwrap();
        assert!(args.iter().any(|i| i == "admin@myhost"));
    }

    #[test]
    fn build_ssh_args_with_port() {
        let config = SshScanConfig {
            port: Some(2222),
            ..SshScanConfig::default()
        };
        let args = build_ssh_args("myhost", &config).unwrap();
        assert!(args.iter().any(|i| i == "-p"));
        assert!(args.iter().any(|i| i == "2222"));
    }

    #[test]
    fn build_ssh_args_with_identity() {
        let config = SshScanConfig {
            identity_file: Some("/home/user/.ssh/fleet_key".to_string()),
            ..SshScanConfig::default()
        };
        let args = build_ssh_args("myhost", &config).unwrap();
        assert!(args.iter().any(|i| i == "-i"));
        assert!(args.iter().any(|i| i == "/home/user/.ssh/fleet_key"));
    }

    #[test]
    fn build_ssh_args_custom_binary() {
        let config = SshScanConfig {
            remote_binary: "/opt/pt/bin/pt-core".to_string(),
            ..SshScanConfig::default()
        };
        let args = build_ssh_args("myhost", &config).unwrap();
        assert_eq!(
            args.last().map(String::as_str),
            Some("/opt/pt/bin/pt-core --format json agent plan")
        );
    }

    #[test]
    fn remote_command_quotes_literal_arguments_and_separates_destination() {
        let args = build_ssh_command_args(
            "operator@host.example",
            &SshScanConfig::default(),
            &[
                "/opt/pt tools/pt-core".into(),
                "--label".into(),
                "literal 'quote'; $(not-a-command)".into(),
            ],
        )
        .unwrap();
        let separator = args.iter().position(|argument| argument == "--").unwrap();
        assert_eq!(args[separator + 1], "operator@host.example");
        assert_eq!(args.len(), separator + 3);
        assert_eq!(
            args.last().unwrap(),
            "'/opt/pt tools/pt-core' --label 'literal '\\''quote'\\''; $(not-a-command)'"
        );
    }

    #[test]
    fn ssh_destinations_cannot_be_options_or_shell_programs() {
        for host in [
            "",
            "-oProxyCommand=bad",
            "host;echo bad",
            "user@-host",
            "@host",
            "user@host@other",
            "host\nother",
        ] {
            assert!(
                build_ssh_args(host, &SshScanConfig::default()).is_err(),
                "{host:?}"
            );
        }
        let config = SshScanConfig {
            user: Some("-bad".into()),
            ..SshScanConfig::default()
        };
        assert!(build_ssh_args("host", &config).is_err());
        assert!(build_ssh_args("[2001:db8::1]", &SshScanConfig::default()).is_ok());
    }

    #[test]
    fn aborted_scan_preserves_unattempted_hosts_in_original_order() {
        let hosts = vec!["alpha".into(), "beta".into(), "gamma".into()];
        let returned = HostScanResult {
            host: "beta".into(),
            success: false,
            plan: None,
            error: Some("connection refused".into()),
            duration_ms: 10,
            provenance: None,
        };
        let results = complete_scan_results(&hosts, vec![(1, returned)]);
        assert_eq!(
            results
                .iter()
                .map(|result| result.host.as_str())
                .collect::<Vec<_>>(),
            ["alpha", "beta", "gamma"]
        );
        assert!(results
            .iter()
            .all(|result| !result.success && result.plan.is_none()));
        assert_eq!(results[1].error.as_deref(), Some("connection refused"));
        assert!(results[0]
            .error
            .as_deref()
            .unwrap()
            .contains("no plan returned"));
        assert_eq!(results[2].duration_ms, 0);
    }

    const PLAN_JSON: &str = r#"{
        "generated_at": "2026-09-25T10:00:00Z",
        "pt_version": "2.1.0",
        "summary": {"total_processes_scanned": 412},
        "candidates": [
            {"pid": 4242, "command_short": "sleep", "classification": "zombie",
             "recommendation": "RESTART",
             "posterior": {"useful": 0.01, "useful_bad": 0.01, "abandoned": 0.08, "zombie": 0.9}},
            {"pid": 777, "command_short": "node", "classification": "useful",
             "recommendation": "KEEP",
             "posterior": {"useful": 0.9, "useful_bad": 0.05, "abandoned": 0.05, "zombie": 0.0}}
        ]
    }"#;

    #[test]
    fn parse_remote_plan_reads_the_hosts_decisions() {
        let plan = parse_remote_plan(PLAN_JSON).unwrap();
        assert_eq!(plan.generated_at, "2026-09-25T10:00:00Z");
        assert_eq!(plan.pt_version.as_deref(), Some("2.1.0"));
        assert_eq!(plan.total_processes, 412);
        assert_eq!(plan.candidates.len(), 2);
        let z = &plan.candidates[0];
        assert_eq!((z.pid, z.comm.as_str()), (4242, "sleep"));
        assert_eq!(z.classification, "zombie");
        assert_eq!(z.recommendation, "RESTART");
        assert!((z.score - 0.98).abs() < 1e-9, "P(abandoned)+P(zombie)");
    }

    #[test]
    fn parse_remote_plan_rejects_other_output() {
        assert!(parse_remote_plan("not json").is_err());
        // A raw `scan` output (what fleet used to fetch) is not a plan.
        assert!(parse_remote_plan(r#"{"scan": {"processes": []}}"#).is_err());
        assert!(parse_remote_plan(
            r#"{"summary": {"total_processes_scanned": 1}, "candidates": [{"command_short": "x"}]}"#
        )
        .is_err());
    }

    fn selected_goal_document() -> serde_json::Value {
        let target = pt_common::ProcessIdentity::new(
            101,
            pt_common::StartId::from_linux("goal-boot", 42, 101),
            1000,
        );
        let posterior = serde_json::json!({
            "useful": 0.01,
            "useful_bad": 0.0,
            "abandoned": 0.99,
            "zombie": 0.0,
        });
        serde_json::json!({
            "command": "agent plan",
            "host_id": "goal-host",
            "session_id": "pt-20261105-120000-abcd",
            "plan_id": "selected-goal",
            "generated_at": "2026-11-05T12:00:00Z",
            "policy_version": "1.0.0",
            "goal": "free port 43123",
            "summary": {"total_processes_scanned": 2, "goal_mode": true},
            "actions": [{
                "action_id": "kill-101", "target": target, "action": "kill",
                "order": 0, "stage": 0, "timeouts": crate::plan::ActionTimeouts::default(),
                "pre_checks": [], "rationale": {"posterior": posterior},
                "on_success": [], "on_failure": [], "blocked": false,
            }],
            "pre_toggled": ["kill-101"],
            "gates_summary": {"total_candidates": 2, "blocked_candidates": 0, "pre_toggled_actions": 1},
            "candidates": [
                {
                    "pid": 101, "start_id": target.start_id, "uid": 1000,
                    "command_short": "listener", "classification": "abandoned",
                    "recommendation": "KILL", "recommended_action": "kill",
                    "posterior": posterior, "action_target": target, "goal_selected": true,
                },
                {
                    "pid": 102, "command_short": "other", "classification": "abandoned",
                    "recommendation": "KILL", "recommended_action": "kill",
                    "posterior": posterior, "goal_selected": false,
                },
            ],
        })
    }

    #[test]
    fn fleet_goal_approval_preserves_only_the_hosts_executable_selection() {
        let document = selected_goal_document();
        let plan = parse_remote_plan(&document.to_string()).unwrap();
        assert_eq!(plan.candidates[0].recommendation, "KILL");
        assert_eq!(plan.candidates[1].recommendation, "REVIEW");
        assert_eq!(plan.candidates[1].classification, "abandoned");
        assert_eq!(plan.document.as_ref().unwrap(), &document);
        let scan = FleetScanResult {
            total_hosts: 1,
            successful: 1,
            failed: 0,
            results: vec![HostScanResult {
                host: "worker".into(),
                success: true,
                plan: Some(plan),
                error: None,
                duration_ms: 1,
                provenance: None,
            }],
            duration_ms: 1,
            provenance_aggregate: None,
        };
        let inputs = vec![scan_result_to_host_input(&scan.results[0])];
        let mut fleet = crate::session::fleet::create_fleet_session(
            "pt-20261105-120001-abcd",
            None,
            &inputs,
            0.05,
        );
        assert_eq!(fleet.hosts[0].selected_kill_pids, [101]);
        fleet.execution = Some(crate::fleet::apply::bind_fleet_execution(
            &fleet,
            &scan,
            &SshScanConfig::default(),
        ));
        let prepared = crate::fleet::apply::prepare_fleet_apply(&fleet).unwrap();
        let request = prepared[0].request.as_ref().unwrap();
        assert_eq!(request.targets.len(), 1);
        assert_eq!(request.targets[0].pid.0, 101);
        assert_eq!(request.actions.len(), 1);
        assert_eq!(request.actions[0].action_id, "kill-101");
    }

    #[test]
    fn selected_goal_kills_require_complete_matching_executable_actions() {
        for case in [
            "selection",
            "target",
            "birth",
            "owner",
            "missing",
            "duplicate",
            "blocked",
            "routed",
            "original_zombie",
            "weak_identity",
        ] {
            let mut document = selected_goal_document();
            match case {
                "selection" => {
                    document["candidates"][0]["goal_selected"] = serde_json::Value::Null;
                }
                "target" => document["candidates"][0]["action_target"] = serde_json::Value::Null,
                "birth" => {
                    document["candidates"][0]["start_id"] = serde_json::json!("other:1:101");
                }
                "owner" => document["candidates"][0]["uid"] = serde_json::json!(1001),
                "missing" => document["actions"] = serde_json::json!([]),
                "duplicate" => {
                    let action = document["actions"][0].clone();
                    document["actions"].as_array_mut().unwrap().push(action);
                }
                "blocked" => document["actions"][0]["blocked"] = serde_json::json!(true),
                "routed" => {
                    document["actions"][0]["routing"] =
                        serde_json::to_value(crate::plan::ActionRouting::ZombieToParent).unwrap();
                }
                "original_zombie" => {
                    document["actions"][0]["original_zombie_target"] =
                        document["candidates"][0]["action_target"].clone();
                }
                "weak_identity" => {
                    let quality =
                        serde_json::to_value(pt_common::IdentityQuality::PidOnly).unwrap();
                    document["candidates"][0]["action_target"]["quality"] = quality.clone();
                    document["actions"][0]["target"]["quality"] = quality;
                }
                _ => unreachable!(),
            }
            assert!(parse_remote_plan(&document.to_string()).is_err(), "{case}");
        }
    }

    #[test]
    fn malformed_posteriors_cannot_become_certainty_for_pooled_approval() {
        for posterior in [
            serde_json::json!({"abandoned": 99.0}),
            serde_json::json!({"abandoned": -0.1}),
            serde_json::json!({"abandoned": "0.99"}),
            serde_json::json!({"abandoned": 0.8, "zombie": 0.3}),
            serde_json::json!({"abandoned": 0.8, "useful": 0.3}),
            serde_json::json!([0.99]),
        ] {
            let mut document: serde_json::Value = serde_json::from_str(PLAN_JSON).unwrap();
            document["candidates"][0]["posterior"] = posterior;
            assert!(parse_remote_plan(&document.to_string()).is_err());
        }
        let mut document: serde_json::Value = serde_json::from_str(PLAN_JSON).unwrap();
        document["candidates"][0]["posterior"] = serde_json::json!({"abandoned": 0.99});
        assert_eq!(
            parse_remote_plan(&document.to_string()).unwrap().candidates[0].score,
            0.99
        );
        document["candidates"][0]["posterior"] = serde_json::Value::Null;
        assert_eq!(
            parse_remote_plan(&document.to_string()).unwrap().candidates[0].score,
            0.0
        );
    }

    #[test]
    fn host_input_passes_remote_decisions_through_unchanged() {
        let result = HostScanResult {
            host: "host1".to_string(),
            success: true,
            plan: Some(parse_remote_plan(PLAN_JSON).unwrap()),
            error: None,
            duration_ms: 500,
            provenance: None,
        };

        let input = scan_result_to_host_input(&result);
        assert_eq!(input.host_id, "host1");
        assert_eq!(input.total_processes, 412);
        assert_eq!(input.scanned_at, "2026-09-25T10:00:00Z");
        assert_eq!(input.candidates.len(), 2);
        // The zombie keeps the host's routed action; nothing re-labels it `kill`.
        assert_eq!(input.candidates[0].recommended_action, "restart");
        assert_eq!(input.candidates[1].recommended_action, "keep");
        assert_eq!(input.candidates[1].signature, "node");
    }

    fn pressure_plan(hostname: &str, cpu: f64, io: f64) -> serde_json::Value {
        let mut document: serde_json::Value = serde_json::from_str(PLAN_JSON).unwrap();
        document["session_id"] = serde_json::json!(format!("session-{hostname}"));
        document["host"] = serde_json::json!({"hostname": hostname, "cores": 8});
        document["system_state"] = serde_json::json!({
            "pressure": {
                "sampled_at_ms": 1_790_325_600_000_u64,
                "cpus": 8,
                "cpu": {"some": {"avg10": cpu, "avg60": cpu, "avg300": cpu, "total_us": 1234}},
                "memory": {"some": {"avg10": 0.0, "avg60": 0.0, "avg300": 0.0, "total_us": 0}},
                "io": {"some": {"avg10": io, "avg60": io, "avg300": io, "total_us": 456}},
                "irq": null,
                "load": {"one": 2.0, "five": 1.0, "fifteen": 1.0},
                "meminfo": {
                    "total": 16_u64 << 30,
                    "available": 8_u64 << 30,
                    "swap_total": 2_u64 << 30,
                    "swap_free": 2_u64 << 30
                },
                "vmstat": {"pswpin": 100, "pswpout": 100, "oom_kill": 10},
                "file_handles": {"allocated": 100, "max": 10000},
                "unavailable": []
            },
            "census": {"zombies": 0, "dstate": 0},
            // A host's asserted assessment is not the fleet's evidence.
            "assessment": {"worst": "crit", "regimes": [{"kind": "oom_kills"}]}
        });
        document
    }

    fn scan_from_document(host: &str, document: &serde_json::Value) -> HostScanResult {
        HostScanResult {
            host: host.to_string(),
            success: true,
            plan: Some(parse_remote_plan(&document.to_string()).unwrap()),
            error: None,
            duration_ms: 10,
            provenance: None,
        }
    }

    fn measured_pressure_plan(hostname: &str) -> serde_json::Value {
        let mut document = pressure_plan(hostname, 0.0, 0.0);
        let before: PressureSnapshot =
            serde_json::from_value(document["system_state"]["pressure"].clone()).unwrap();
        let mut after = before.clone();
        after.sampled_at_ms += 500;
        after.cpu.as_mut().unwrap().some.as_mut().unwrap().total_us += 200_000;
        let vm = after.vmstat.as_mut().unwrap();
        vm.pswpin = Some(vm.pswpin.unwrap() + 3000);
        vm.pswpout = Some(vm.pswpout.unwrap() + 3000);
        vm.oom_kill = Some(vm.oom_kill.unwrap() + 2);
        let window = crate::collect::pressure::pressure_window_with_elapsed(
            &before,
            &after,
            Duration::from_millis(500),
        )
        .unwrap();
        document["system_state"]["pressure"] = serde_json::to_value(after).unwrap();
        document["system_state"]["pressure_window"] = serde_json::to_value(window).unwrap();
        document["system_state"]["assessment"] = serde_json::json!({"worst": "ok", "regimes": []});
        document
    }

    #[test]
    fn fleet_plan_health_retains_measured_psi_swap_and_oom_window() {
        use crate::decision::pressure_regime::RegimeKind;
        use crate::session::fleet::{create_fleet_session, FleetSession};

        let document = measured_pressure_plan("window.local");
        let input = scan_result_to_host_input(&scan_from_document("window", &document));
        assert_eq!(input.health.status, HostHealthStatus::Crit);
        assert_eq!(input.health.coverage, PressureCoverage::Complete);
        let window = input.health.pressure_window.unwrap();
        assert_eq!(window.seconds, 0.5);
        assert_eq!(window.cpu.unwrap().some, Some(0.4));
        assert_eq!(window.swap_in_per_s, Some(6000.0));
        assert_eq!(window.swap_out_per_s, Some(6000.0));
        assert_eq!(window.oom_kills, Some(2));
        let assessment = input.health.assessment.as_ref().unwrap();
        assert_eq!(assessment.cpu_some, Some(40.0));
        for kind in [
            RegimeKind::CpuContention,
            RegimeKind::SwapThrash,
            RegimeKind::OomKills,
        ] {
            assert!(assessment
                .regimes
                .iter()
                .any(|regime| regime.kind == kind && regime.severity == Severity::Crit));
        }
        assert_eq!(input.candidates[0].recommended_action, "restart");
        assert_eq!(input.candidates[1].recommended_action, "keep");
        assert_eq!(input.system_state.as_ref(), Some(&document["system_state"]));
        let fleet = create_fleet_session("window", None, &[input], 0.05);
        assert_eq!(fleet.aggregate.health.as_ref().unwrap().critical_hosts, 1);
        let restored: FleetSession =
            serde_json::from_str(&serde_json::to_string(&fleet).unwrap()).unwrap();
        assert_eq!(restored.hosts[0].health, fleet.hosts[0].health);

        let mut snapshot_only = document;
        snapshot_only["system_state"]["pressure_window"] = serde_json::Value::Null;
        let input = scan_result_to_host_input(&scan_from_document("window", &snapshot_only));
        assert!(input.health.pressure_window.is_none());
        assert_eq!(input.health.status, HostHealthStatus::Ok);
        assert!(input.health.assessment.unwrap().regimes.is_empty());
    }

    #[test]
    fn fleet_invalid_pressure_interval_cannot_invent_recent_incidents() {
        for bad in [
            serde_json::json!(0.0),
            serde_json::json!(-0.5),
            serde_json::json!("unknown"),
            serde_json::Value::Null,
        ] {
            let mut document = measured_pressure_plan("bad-window.local");
            document["system_state"]["pressure_window"]["seconds"] = bad;
            let input = scan_result_to_host_input(&scan_from_document("host", &document));
            assert!(input.health.pressure_window.is_none());
            assert_eq!(input.health.status, HostHealthStatus::Unknown);
            assert_eq!(input.health.coverage, PressureCoverage::Partial);
            assert!(input.health.assessment.as_ref().unwrap().regimes.is_empty());
            assert!(input
                .health
                .unavailable
                .iter()
                .any(|issue| issue.source == "system_state.pressure_window.seconds"));
            assert_eq!(input.candidates.len(), 2);
            assert_eq!(input.system_state.as_ref(), Some(&document["system_state"]));
        }
    }

    #[test]
    fn fleet_bad_window_channels_preserve_independent_measurements() {
        for (field, bad) in [
            ("/cpu", serde_json::json!("unreadable")),
            ("/cpu/some", serde_json::json!(1.5)),
            ("/swap_in_per_s", serde_json::json!(-1.0)),
            ("/swap_in_per_s", serde_json::json!(7000.0)),
            ("/swap_out_per_s", serde_json::Value::Null),
            ("/major_faults_per_s", serde_json::json!(1.0)),
            ("/oom_kills", serde_json::json!(13)),
        ] {
            let mut document = measured_pressure_plan("partial-window.local");
            *document["system_state"]["pressure_window"]
                .pointer_mut(field)
                .unwrap() = bad;
            let input = scan_result_to_host_input(&scan_from_document("host", &document));
            assert_eq!(input.health.status, HostHealthStatus::Crit, "{field}");
            assert_eq!(input.health.coverage, PressureCoverage::Partial, "{field}");
            let window = input.health.pressure_window.unwrap();
            assert_eq!(window.seconds, 0.5);
            let checked = serde_json::to_value(window).unwrap();
            assert!(checked
                .pointer(field)
                .is_none_or(serde_json::Value::is_null));
            if field != "/oom_kills" {
                assert_eq!(window.oom_kills, Some(2));
            } else {
                assert_eq!(window.cpu.unwrap().some, Some(0.4));
                assert_eq!(window.swap_in_per_s, Some(6000.0));
            }
            let suffix = field.trim_start_matches('/').replace('/', ".");
            assert!(input
                .health
                .unavailable
                .iter()
                .any(|issue| issue.source.ends_with(&suffix)));
            assert_eq!(input.system_state.as_ref(), Some(&document["system_state"]));
        }
    }

    #[test]
    fn fleet_failed_window_sources_cannot_supply_fallback_measurements() {
        let mut document = measured_pressure_plan("unreadable-vm.local");
        document["system_state"]["pressure"]["unavailable"] = serde_json::json!([
            {"source": "/proc/vmstat", "reason": "endpoint unreadable"}
        ]);
        let input = scan_result_to_host_input(&scan_from_document("host", &document));
        let window = input.health.pressure_window.unwrap();
        assert_eq!(window.cpu.unwrap().some, Some(0.4));
        assert!(window.swap_in_per_s.is_none());
        assert!(window.swap_out_per_s.is_none());
        assert!(window.oom_kills.is_none());
        assert_eq!(input.health.status, HostHealthStatus::Crit);
        assert_eq!(input.health.coverage, PressureCoverage::Partial);

        document["system_state"]["pressure"]["unavailable"] = serde_json::json!([
            {"source": "pressure_window", "reason": "sampling deadline"}
        ]);
        let input = scan_result_to_host_input(&scan_from_document("host", &document));
        assert!(input.health.pressure_window.is_none());
        assert_eq!(input.health.status, HostHealthStatus::Unknown);
        assert_eq!(input.health.coverage, PressureCoverage::Partial);
        assert!(input.health.assessment.unwrap().regimes.is_empty());
    }

    #[test]
    fn fleet_health_recomputes_pressure_and_keeps_each_hosts_observations() {
        use crate::decision::pressure_regime::RegimeKind;
        use crate::session::fleet::{create_fleet_session, FleetSession};

        let quiet = pressure_plan("quiet.local", 0.0, 0.0);
        let mut busy = pressure_plan("busy.local", 45.0, 0.0);
        busy["system_state"]["assessment"] = serde_json::json!({"worst": "ok", "regimes": []});
        busy["system_state"]["pressure"]["sampled_at_ms"] = serde_json::json!(12345678);
        let io = pressure_plan("io.local", 0.0, 8.0);
        let mut partial = pressure_plan("partial.local", 0.0, 0.0);
        partial["system_state"]["pressure"]["io"] = serde_json::Value::Null;
        let old: serde_json::Value = serde_json::from_str(PLAN_JSON).unwrap();
        let inputs = [
            scan_from_document("quiet", &quiet),
            scan_from_document("busy", &busy),
            scan_from_document("io", &io),
            scan_from_document("partial", &partial),
            scan_from_document("old", &old),
            HostScanResult {
                host: "offline".to_string(),
                success: false,
                plan: None,
                error: Some("SSH connection timed out".to_string()),
                duration_ms: 30000,
                provenance: None,
            },
        ]
        .iter()
        .map(scan_result_to_host_input)
        .collect::<Vec<_>>();
        let fleet = create_fleet_session("health", None, &inputs, 0.05);
        let health = fleet.aggregate.health.as_ref().unwrap();
        assert_eq!(health.healthy_hosts, 1);
        assert_eq!(health.warning_hosts, 1);
        assert_eq!(health.critical_hosts, 1);
        assert_eq!(health.unknown_hosts, 3);
        assert_eq!(health.partial_hosts, 1);
        assert_eq!(health.unavailable_hosts, 2);
        assert_eq!(health.worst_observed, Some(Severity::Crit));
        assert_eq!(fleet.hosts[0].health.status, HostHealthStatus::Ok);
        assert_eq!(fleet.hosts[0].health.coverage, PressureCoverage::Complete);
        assert_eq!(fleet.hosts[3].health.status, HostHealthStatus::Unknown);
        assert_eq!(fleet.hosts[3].health.coverage, PressureCoverage::Partial);
        assert_eq!(fleet.hosts[1].host.as_ref().unwrap(), &busy["host"]);
        assert_eq!(
            fleet.hosts[1].system_state.as_ref().unwrap(),
            &busy["system_state"]
        );
        assert_eq!(
            fleet.hosts[1]
                .health
                .pressure
                .as_ref()
                .unwrap()
                .sampled_at_ms,
            12345678
        );
        let regimes = &fleet.hosts[1].health.assessment.as_ref().unwrap().regimes;
        assert_eq!(regimes.len(), 1);
        assert_eq!(regimes[0].kind, RegimeKind::CpuContention);
        assert_eq!(regimes[0].severity, Severity::Crit);
        // Absolute vmstat counters never become an invented rate or recent OOM.
        assert!(fleet.hosts[0]
            .health
            .assessment
            .as_ref()
            .unwrap()
            .regimes
            .is_empty());
        assert!(fleet.hosts[5].health.unavailable[0]
            .reason
            .contains("timed out"));
        // Health annotation never changes a host's process classifications/actions.
        assert_eq!(
            fleet.hosts[0].summary.action_counts,
            fleet.hosts[1].summary.action_counts
        );
        assert_eq!(
            fleet.hosts[1].summary.action_counts.get("restart"),
            Some(&1)
        );

        let restored: FleetSession =
            serde_json::from_str(&serde_json::to_string(&fleet).unwrap()).unwrap();
        assert_eq!(restored.aggregate.health, fleet.aggregate.health);
        for (original, restored) in fleet.hosts.iter().zip(&restored.hosts) {
            assert_eq!(restored.host_id, original.host_id);
            assert_eq!(restored.health, original.health);
            assert_eq!(restored.host, original.host);
            assert_eq!(restored.system_state, original.system_state);
        }
    }

    #[test]
    fn missing_or_malformed_health_never_invalidates_a_remote_process_plan() {
        for (pointer, bad_value, source) in [
            (
                "/system_state/pressure/cpu/some/avg10",
                serde_json::json!(101.0),
                "cpu.some",
            ),
            (
                "/system_state/pressure/cpu/some/avg60",
                serde_json::json!(-1.0),
                "cpu.some",
            ),
            (
                "/system_state/pressure/io",
                serde_json::json!("unreadable"),
                "io",
            ),
            (
                "/system_state/pressure/load/one",
                serde_json::json!(-0.1),
                "load",
            ),
            ("/system_state/pressure/cpus", serde_json::json!(0), "cpus"),
            (
                "/system_state/pressure/meminfo/total",
                serde_json::json!(0),
                "meminfo",
            ),
            (
                "/system_state/pressure/meminfo/available",
                serde_json::json!(20_u64 << 30),
                "meminfo",
            ),
            (
                "/system_state/pressure/meminfo/swap_free",
                serde_json::json!(3_u64 << 30),
                "meminfo",
            ),
            (
                "/system_state/pressure/file_handles/max",
                serde_json::json!(0),
                "file_handles",
            ),
            ("/system_state/census", serde_json::Value::Null, "census"),
            (
                "/system_state/census/zombies",
                serde_json::json!(413),
                "census",
            ),
            (
                "/system_state/pressure/sampled_at_ms",
                serde_json::json!("unknown"),
                "sampled_at_ms",
            ),
        ] {
            let mut document = pressure_plan("host.local", 0.0, 0.0);
            *document.pointer_mut(pointer).unwrap() = bad_value;
            let result = scan_from_document("host", &document);
            let input = scan_result_to_host_input(&result);
            assert_eq!(input.health.status, HostHealthStatus::Unknown, "{pointer}");
            assert_ne!(
                input.health.coverage,
                PressureCoverage::Complete,
                "{pointer}"
            );
            assert!(
                input
                    .health
                    .unavailable
                    .iter()
                    .any(|unavailable| unavailable.source.contains(source)),
                "{pointer}"
            );
            assert_eq!(input.candidates.len(), 2, "{pointer}");
            assert_eq!(
                input.candidates[0].recommended_action, "restart",
                "{pointer}"
            );
            assert_eq!(
                input.system_state.as_ref().unwrap(),
                &document["system_state"]
            );
        }

        for state in [
            serde_json::Value::Null,
            serde_json::json!("bad snapshot"),
            serde_json::json!({"pressure": 42}),
        ] {
            let mut document = pressure_plan("host.local", 0.0, 0.0);
            document["system_state"] = state;
            let input = scan_result_to_host_input(&scan_from_document("host", &document));
            assert_eq!(input.health.status, HostHealthStatus::Unknown);
            assert_eq!(input.health.coverage, PressureCoverage::Unavailable);
            assert!(input.health.assessment.is_none());
            assert_eq!(input.candidates.len(), 2);
        }
    }

    #[test]
    fn bad_memory_sensor_preserves_real_cpu_pressure_and_remote_error_provenance() {
        let mut document = pressure_plan("busy.local", 45.0, 0.0);
        document["system_state"]["pressure"]["meminfo"] = serde_json::json!({"total": "bad"});
        document["system_state"]["pressure"]["unavailable"] = serde_json::json!([
            {"source": "/proc/meminfo", "reason": "remote permission denied"}
        ]);
        let input = scan_result_to_host_input(&scan_from_document("busy", &document));
        assert_eq!(input.health.status, HostHealthStatus::Crit);
        assert_eq!(input.health.coverage, PressureCoverage::Partial);
        assert!(input.health.pressure.as_ref().unwrap().meminfo.is_none());
        assert_eq!(
            input.health.assessment.as_ref().unwrap().cpu_some,
            Some(45.0)
        );
        assert!(input
            .health
            .unavailable
            .iter()
            .any(|item| item.reason == "remote permission denied"));
    }

    #[test]
    fn fleet_preserves_native_macos_pressure_with_explicit_partial_coverage() {
        use crate::collect::pressure::MacosPressureLevel;
        use crate::decision::pressure_regime::RegimeKind;

        let mut document = pressure_plan("mac.local", 0.0, 0.0);
        for field in ["cpu", "memory", "io", "file_handles"] {
            document["system_state"]["pressure"][field] = serde_json::Value::Null;
        }
        document["system_state"]["pressure"]["meminfo"]["available"] = serde_json::Value::Null;
        document["system_state"]["pressure"]["meminfo"]["macos_pressure"] =
            serde_json::json!("critical");
        let input = scan_result_to_host_input(&scan_from_document("mac", &document));
        assert_eq!(input.health.status, HostHealthStatus::Crit);
        assert_eq!(input.health.coverage, PressureCoverage::Partial);
        let memory = input.health.pressure.as_ref().unwrap().meminfo.unwrap();
        assert_eq!(memory.macos_pressure, Some(MacosPressureLevel::Critical));
        assert_eq!(memory.available, None);
        let assessment = input.health.assessment.as_ref().unwrap();
        assert_eq!(assessment.regimes[0].kind, RegimeKind::MemoryExhaustion);
        assert_eq!(assessment.memory_some, None);
        assert_eq!(assessment.memory_used_fraction, None);

        document["system_state"]["pressure"]["meminfo"]["macos_pressure"] =
            serde_json::json!("normal");
        let quiet = scan_result_to_host_input(&scan_from_document("mac", &document));
        assert_eq!(quiet.health.status, HostHealthStatus::Unknown);
        assert_eq!(quiet.health.coverage, PressureCoverage::Partial);

        document["system_state"]["pressure"]["file_handles"] =
            serde_json::json!({"allocated": 951, "max": 1000});
        let full = scan_result_to_host_input(&scan_from_document("mac", &document));
        assert_eq!(full.health.status, HostHealthStatus::Crit);
        assert!(full
            .health
            .assessment
            .unwrap()
            .regimes
            .iter()
            .any(|r| r.kind == RegimeKind::FdExhaustion));

        document["system_state"]["pressure"]["meminfo"]["macos_pressure"] =
            serde_json::json!("critical");
        document["system_state"]["pressure"]["unavailable"] = serde_json::json!([
            {"source": "kern.memorystatus_vm_pressure_level", "reason": "query timed out"},
            {"source": "vm.swapusage", "reason": "query failed"},
            {"source": "hw.logicalcpu", "reason": "query failed"},
            {"source": "kern.num_files/kern.maxfiles", "reason": "query failed"}
        ]);
        let failed = scan_result_to_host_input(&scan_from_document("mac", &document));
        assert_eq!(failed.health.status, HostHealthStatus::Unknown);
        let snapshot = failed.health.pressure.as_ref().unwrap();
        assert_eq!(snapshot.cpus, 0);
        assert_eq!(snapshot.file_handles, None);
        assert_eq!(snapshot.meminfo.unwrap().macos_pressure, None);
        assert_eq!(snapshot.meminfo.unwrap().swap_used(), None);
    }

    #[test]
    fn explicit_sensor_failure_and_failed_scan_cannot_claim_healthy() {
        let mut document = pressure_plan("host.local", 0.0, 90.0);
        document["system_state"]["pressure"]["unavailable"] = serde_json::json!([
            {"source": "/proc/pressure/io", "reason": "unreadable; returned zero fallback"}
        ]);
        let input = scan_result_to_host_input(&scan_from_document("host", &document));
        assert_eq!(input.health.coverage, PressureCoverage::Partial);
        assert_eq!(input.health.status, HostHealthStatus::Unknown);
        assert!(input.health.pressure.as_ref().unwrap().io.is_none());
        assert!(input.health.assessment.as_ref().unwrap().io_some.is_none());

        let mut failed = scan_from_document("host", &pressure_plan("host.local", 0.0, 0.0));
        failed.success = false;
        failed.error = Some("incomplete remote response".to_string());
        let input = scan_result_to_host_input(&failed);
        assert_eq!(input.health.status, HostHealthStatus::Unknown);
        assert_eq!(input.health.coverage, PressureCoverage::Unavailable);
        assert!(input.health.pressure.is_none());
    }

    #[test]
    fn pressure_health_does_not_change_fleet_kill_approval() {
        use crate::session::fleet::create_fleet_session;

        let mut document = pressure_plan("host.local", 90.0, 90.0);
        document["candidates"][0]["recommendation"] = serde_json::json!("KILL");
        document["candidates"][0]["classification"] = serde_json::json!("abandoned");
        document["candidates"][0]["posterior"] = serde_json::json!({
            "useful": 0.01, "useful_bad": 0.0, "abandoned": 0.99, "zombie": 0.0
        });
        let pressured = create_fleet_session(
            "same-plan",
            None,
            &[scan_result_to_host_input(&scan_from_document(
                "host", &document,
            ))],
            0.05,
        );
        document["system_state"] = serde_json::Value::Null;
        let unknown = create_fleet_session(
            "same-plan",
            None,
            &[scan_result_to_host_input(&scan_from_document(
                "host", &document,
            ))],
            0.05,
        );
        assert_eq!(pressured.hosts[0].health.status, HostHealthStatus::Crit);
        assert_eq!(unknown.hosts[0].health.status, HostHealthStatus::Unknown);
        assert_eq!(pressured.hosts[0].selected_kill_pids, vec![4242]);
        assert_eq!(
            pressured.hosts[0].selected_kill_pids,
            unknown.hosts[0].selected_kill_pids
        );
        assert_eq!(
            pressured.aggregate.action_counts,
            unknown.aggregate.action_counts
        );
        assert_eq!(
            serde_json::to_value(&pressured.safety_budget).unwrap(),
            serde_json::to_value(&unknown.safety_budget).unwrap()
        );
    }

    #[test]
    fn scan_result_to_host_input_failed() {
        let result = HostScanResult {
            host: "host2".to_string(),
            success: false,
            plan: None,
            error: Some("connection refused".to_string()),
            duration_ms: 100,
            provenance: None,
        };

        let input = scan_result_to_host_input(&result);
        assert_eq!(input.host_id, "host2");
        assert_eq!(input.total_processes, 0);
        assert!(input.candidates.is_empty());
    }

    #[test]
    fn fleet_scan_result_serde_roundtrip() {
        let fleet_result = FleetScanResult {
            total_hosts: 2,
            successful: 1,
            failed: 1,
            results: vec![
                HostScanResult {
                    host: "host1".to_string(),
                    success: true,
                    plan: None,
                    error: None,
                    duration_ms: 200,
                    provenance: None,
                },
                HostScanResult {
                    host: "host2".to_string(),
                    success: false,
                    plan: None,
                    error: Some("timeout".to_string()),
                    duration_ms: 30000,
                    provenance: None,
                },
            ],
            duration_ms: 30200,
            provenance_aggregate: None,
        };

        let json = serde_json::to_string(&fleet_result).unwrap();
        let restored: FleetScanResult = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.total_hosts, 2);
        assert_eq!(restored.successful, 1);
        assert_eq!(restored.failed, 1);
    }

    fn completed_scan(host: &str) -> HostScanResult {
        HostScanResult {
            host: host.to_string(),
            success: true,
            plan: Some(RemotePlan::default()),
            error: None,
            duration_ms: 0,
            provenance: None,
        }
    }

    #[test]
    fn fleet_scan_refills_a_slot_before_the_slow_host_finishes() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::mpsc;

        let hosts = ["slow", "fast", "later"].map(str::to_string);
        let config = SshScanConfig {
            parallel: 2,
            ..SshScanConfig::default()
        };
        let (slow_started, wait_for_slow) = mpsc::channel();
        let wait_for_slow = Mutex::new(wait_for_slow);
        let (later_started, release_slow) = mpsc::channel();
        let release_slow = Mutex::new(release_slow);
        let slow_finished = AtomicBool::new(false);

        let result = ssh_scan_fleet_with(&hosts, &config, |host, _| {
            match host {
                "slow" => {
                    slow_started.send(()).unwrap();
                    release_slow
                        .lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(10))
                        .expect("later host must start while the first host is still running");
                    slow_finished.store(true, Ordering::SeqCst);
                }
                "fast" => {
                    wait_for_slow
                        .lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(10))
                        .expect("both initial connections must start");
                }
                "later" => {
                    assert!(!slow_finished.load(Ordering::SeqCst));
                    later_started.send(()).unwrap();
                }
                _ => unreachable!(),
            }
            completed_scan(host)
        });

        assert_eq!(result.successful, 3);
        assert_eq!(result.failed, 0);
        assert!(slow_finished.load(Ordering::SeqCst));
        assert_eq!(
            result
                .results
                .iter()
                .map(|result| result.host.as_str())
                .collect::<Vec<_>>(),
            hosts.iter().map(String::as_str).collect::<Vec<_>>()
        );
    }

    #[test]
    fn fleet_scan_bounds_active_workers_and_keeps_every_result_in_host_order() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{mpsc, Condvar};

        let hosts: Vec<_> = (0..9).map(|index| format!("host-{index}")).collect();
        let config = SshScanConfig {
            parallel: 3,
            ..SshScanConfig::default()
        };
        let active = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        let gate = (Mutex::new(false), Condvar::new());
        let (started, observed_starts) = mpsc::channel();

        let (initial_starts, extra_start, result) = std::thread::scope(|scope| {
            let run = scope.spawn(|| {
                ssh_scan_fleet_with(&hosts, &config, |host, _| {
                    let concurrent = active.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(concurrent, Ordering::SeqCst);
                    started.send(host.to_string()).unwrap();
                    let mut released = gate.0.lock().unwrap();
                    while !*released {
                        released = gate.1.wait(released).unwrap();
                    }
                    drop(released);
                    active.fetch_sub(1, Ordering::SeqCst);
                    completed_scan(host)
                })
            });
            let initial_starts: Vec<_> = (0..3)
                .map(|_| observed_starts.recv_timeout(Duration::from_secs(10)))
                .collect();
            let extra_start = observed_starts.try_recv();
            // Always release workers before asserting, including on a failed
            // start observation, so a scheduler regression cannot hang this test.
            *gate.0.lock().unwrap() = true;
            gate.1.notify_all();
            (initial_starts, extra_start, run.join().unwrap())
        });

        assert!(initial_starts.iter().all(Result::is_ok));
        assert!(matches!(extra_start, Err(mpsc::TryRecvError::Empty)));
        assert_eq!(peak.load(Ordering::SeqCst), 3);
        assert_eq!(active.load(Ordering::SeqCst), 0);
        assert_eq!(result.total_hosts, hosts.len());
        assert_eq!(result.successful, hosts.len());
        assert_eq!(result.failed, 0);
        assert_eq!(
            result
                .results
                .iter()
                .map(|result| result.host.as_str())
                .collect::<Vec<_>>(),
            hosts.iter().map(String::as_str).collect::<Vec<_>>()
        );
    }

    #[test]
    fn fleet_scan_failure_stops_new_hosts_and_retains_in_flight_results() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::{mpsc, Condvar};

        let hosts = ["failed", "in-flight", "not-started", "also-not-started"].map(str::to_string);
        let config = SshScanConfig {
            parallel: 2,
            continue_on_error: false,
            ..SshScanConfig::default()
        };
        let attempts = AtomicUsize::new(0);
        let gate = (Mutex::new(false), Condvar::new());
        let (started, observed_starts) = mpsc::channel();

        let (initial_starts, result) = std::thread::scope(|scope| {
            let run = scope.spawn(|| {
                ssh_scan_fleet_with(&hosts, &config, |host, _| {
                    attempts.fetch_add(1, Ordering::SeqCst);
                    started.send(host.to_string()).unwrap();
                    let mut released = gate.0.lock().unwrap();
                    while !*released {
                        released = gate.1.wait(released).unwrap();
                    }
                    drop(released);
                    HostScanResult {
                        host: host.to_string(),
                        success: false,
                        plan: None,
                        error: Some(format!("observed scan failure on {host}")),
                        duration_ms: 1,
                        provenance: None,
                    }
                })
            });
            let initial_starts: Vec<_> = (0..2)
                .map(|_| observed_starts.recv_timeout(Duration::from_secs(10)))
                .collect();
            *gate.0.lock().unwrap() = true;
            gate.1.notify_all();
            (initial_starts, run.join().unwrap())
        });

        assert!(initial_starts.iter().all(Result::is_ok));
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert_eq!(result.total_hosts, 4);
        assert_eq!(result.failed, 4);
        for (index, host) in hosts.iter().enumerate() {
            let row = &result.results[index];
            assert_eq!(&row.host, host);
            assert!(!row.success);
            assert!(row.plan.is_none());
            if index < 2 {
                assert_eq!(row.error, Some(format!("observed scan failure on {host}")));
            } else {
                assert!(row.error.as_deref().unwrap().contains("dispatch stopped"));
            }
        }
    }

    #[test]
    fn fleet_scan_continues_after_errors_and_panics_with_zero_parallel_setting() {
        let hosts = ["first", "failed", "panicked", "last"].map(str::to_string);
        let config = SshScanConfig {
            parallel: 0,
            continue_on_error: true,
            ..SshScanConfig::default()
        };
        let attempts = Mutex::new(Vec::new());
        let result = ssh_scan_fleet_with(&hosts, &config, |host, _| {
            attempts.lock().unwrap().push(host.to_string());
            match host {
                "panicked" => panic!("scan task failed unexpectedly"),
                "failed" => HostScanResult {
                    host: host.to_string(),
                    success: false,
                    plan: None,
                    error: Some("remote connection failed".into()),
                    duration_ms: 1,
                    provenance: None,
                },
                _ => completed_scan(host),
            }
        });

        assert_eq!(*attempts.lock().unwrap(), hosts.to_vec());
        assert_eq!(result.total_hosts, 4);
        assert_eq!(result.successful, 2);
        assert_eq!(result.failed, 2);
        assert!(result.results[0].success);
        assert!(result.results[3].success);
        assert_eq!(
            result.results[1].error.as_deref(),
            Some("remote connection failed")
        );
        assert!(result.results[2]
            .error
            .as_deref()
            .unwrap()
            .contains("panicked"));
    }

    #[test]
    fn ssh_scan_fleet_empty_hosts() {
        let config = SshScanConfig::default();
        let result = ssh_scan_fleet(&[], &config);
        assert_eq!(result.total_hosts, 0);
        assert_eq!(result.successful, 0);
        assert_eq!(result.failed, 0);
        assert!(result.results.is_empty());
    }

    #[test]
    fn ssh_scan_fleet_zero_parallel_does_not_panic() {
        let config = SshScanConfig {
            parallel: 0,
            ..SshScanConfig::default()
        };
        let result = ssh_scan_fleet(&[], &config);
        assert_eq!(result.total_hosts, 0);
        assert_eq!(result.successful, 0);
        assert_eq!(result.failed, 0);
        assert!(result.results.is_empty());
    }
}
