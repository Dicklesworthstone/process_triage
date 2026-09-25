//! SSH-based remote planning for fleet mode.
//!
//! Runs `pt-core --format json agent plan` on each host via `ssh`, so every host
//! is judged by pt's real decision pipeline with its own live checks (protection,
//! cgroup placement, posterior, loss matrix, policy). The fleet only aggregates
//! those per-host decisions; it never re-classifies processes itself. (It used
//! to fetch a raw scan and apply a local state heuristic that, for example,
//! recommended `kill` for every zombie and every process stopped for an hour.)

use serde::{Deserialize, Serialize};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use thiserror::Error;

/// Configuration for SSH-based fleet scanning.
#[derive(Debug, Clone)]
pub struct SshScanConfig {
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
}

impl Default for SshScanConfig {
    fn default() -> Self {
        Self {
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
    pub total_processes: u64,
    pub candidates: Vec<RemoteCandidate>,
}

/// Parse `pt-core --format json agent plan` output.
pub fn parse_remote_plan(json: &str) -> Result<RemotePlan, String> {
    let v: serde_json::Value = serde_json::from_str(json).map_err(|e| format!("not JSON: {e}"))?;
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
            let p = |class: &str| c["posterior"][class].as_f64().unwrap_or(0.0);
            Ok(RemoteCandidate {
                pid,
                comm: text("command_short"),
                classification: text("classification"),
                recommendation: text("recommendation"),
                score: p("abandoned") + p("zombie"),
            })
        })
        .collect::<Result<Vec<_>, &str>>()?;
    Ok(RemotePlan {
        generated_at: v["generated_at"].as_str().unwrap_or_default().to_string(),
        total_processes,
        candidates,
    })
}

/// Build the SSH command arguments for scanning a remote host.
fn build_ssh_args(host: &str, config: &SshScanConfig) -> Vec<String> {
    let mut args = Vec::new();

    // Connection options
    args.push("-o".to_string());
    args.push(format!("ConnectTimeout={}", config.connect_timeout));

    for opt in &config.ssh_options {
        args.push("-o".to_string());
        args.push(opt.clone());
    }

    if let Some(ref identity) = config.identity_file {
        args.push("-i".to_string());
        args.push(identity.clone());
    }

    if let Some(port) = config.port {
        args.push("-p".to_string());
        args.push(port.to_string());
    }

    // Target
    let target = if let Some(ref user) = config.user {
        format!("{}@{}", user, host)
    } else {
        host.to_string()
    };
    args.push(target);

    // Remote command: the host's real planning pipeline (read-only).
    args.push(format!("{} --format json agent plan", config.remote_binary));

    args
}

/// Scan a single host via SSH and parse the result.
pub fn ssh_scan_host(host: &str, config: &SshScanConfig) -> HostScanResult {
    let start = std::time::Instant::now();

    let args = build_ssh_args(host, config);
    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let timeout = Duration::from_secs(config.command_timeout);

    let output = match crate::collect::tool_runner::run_tool("ssh", &args_ref, Some(timeout), None)
    {
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

    match parse_remote_plan(&output.stdout_str()) {
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
/// Uses a thread pool with configurable concurrency. Results are collected
/// and returned in the same order as the input hosts.
pub fn ssh_scan_fleet(hosts: &[String], config: &SshScanConfig) -> FleetScanResult {
    let start = std::time::Instant::now();
    let results: Arc<Mutex<Vec<(usize, HostScanResult)>>> = Arc::new(Mutex::new(Vec::new()));
    let aborted = Arc::new(Mutex::new(false));
    let parallel = config.parallel.max(1);

    // Process hosts in batches of `parallel`
    let chunks: Vec<Vec<(usize, &String)>> = hosts
        .iter()
        .enumerate()
        .collect::<Vec<_>>()
        .chunks(parallel)
        .map(|chunk| chunk.to_vec())
        .collect();

    for chunk in chunks {
        // Check if aborted
        if !config.continue_on_error && *aborted.lock().expect("lock poisoned") {
            break;
        }

        let handles: Vec<_> = chunk
            .into_iter()
            .map(|(idx, host)| {
                let host = host.clone();
                let config = config.clone();
                let results = Arc::clone(&results);
                let aborted = Arc::clone(&aborted);

                std::thread::spawn(move || {
                    if !config.continue_on_error && *aborted.lock().expect("lock poisoned") {
                        return;
                    }

                    let result = ssh_scan_host(&host, &config);

                    if !result.success && !config.continue_on_error {
                        *aborted.lock().expect("lock poisoned") = true;
                    }

                    results.lock().expect("lock poisoned").push((idx, result));
                })
            })
            .collect();

        for handle in handles {
            let _ = handle.join();
        }
    }

    // Sort by original index to maintain order
    let mut collected = Arc::try_unwrap(results)
        .expect("Arc has multiple owners")
        .into_inner()
        .expect("lock poisoned");
    collected.sort_by_key(|(idx, _)| *idx);
    let results: Vec<HostScanResult> = collected.into_iter().map(|(_, r)| r).collect();

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

/// Convert a HostScanResult into a HostInput for fleet session aggregation.
pub fn scan_result_to_host_input(result: &HostScanResult) -> crate::session::fleet::HostInput {
    use crate::session::fleet::{CandidateInfo, HostInput};

    match &result.plan {
        // The host's own decisions, unchanged.
        Some(plan) => HostInput {
            host_id: result.host.clone(),
            session_id: format!("ssh-{}", result.host),
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
        },
        None => HostInput {
            host_id: result.host.clone(),
            session_id: format!("ssh-{}-failed", result.host),
            scanned_at: chrono::Utc::now().to_rfc3339(),
            total_processes: 0,
            candidates: Vec::new(),
        },
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
        let args = build_ssh_args("myhost", &config);

        assert!(args.contains(&"-o".to_string()));
        assert!(args.contains(&"ConnectTimeout=10".to_string()));
        assert!(args.contains(&"BatchMode=yes".to_string()));
        assert!(args.contains(&"myhost".to_string()));
        assert_eq!(
            args.last().map(String::as_str),
            Some("pt-core --format json agent plan")
        );
    }

    #[test]
    fn build_ssh_args_with_user() {
        let config = SshScanConfig {
            user: Some("admin".to_string()),
            ..SshScanConfig::default()
        };
        let args = build_ssh_args("myhost", &config);
        assert!(args.contains(&"admin@myhost".to_string()));
    }

    #[test]
    fn build_ssh_args_with_port() {
        let config = SshScanConfig {
            port: Some(2222),
            ..SshScanConfig::default()
        };
        let args = build_ssh_args("myhost", &config);
        assert!(args.contains(&"-p".to_string()));
        assert!(args.contains(&"2222".to_string()));
    }

    #[test]
    fn build_ssh_args_with_identity() {
        let config = SshScanConfig {
            identity_file: Some("/home/user/.ssh/fleet_key".to_string()),
            ..SshScanConfig::default()
        };
        let args = build_ssh_args("myhost", &config);
        assert!(args.contains(&"-i".to_string()));
        assert!(args.contains(&"/home/user/.ssh/fleet_key".to_string()));
    }

    #[test]
    fn build_ssh_args_custom_binary() {
        let config = SshScanConfig {
            remote_binary: "/opt/pt/bin/pt-core".to_string(),
            ..SshScanConfig::default()
        };
        let args = build_ssh_args("myhost", &config);
        assert_eq!(
            args.last().map(String::as_str),
            Some("/opt/pt/bin/pt-core --format json agent plan")
        );
    }

    const PLAN_JSON: &str = r#"{
        "generated_at": "2026-09-25T10:00:00Z",
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
