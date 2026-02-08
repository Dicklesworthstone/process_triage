//! SSH-based remote scanning for fleet mode.
//!
//! Executes `pt-core scan --format json` on remote hosts via the `ssh` command
//! and parses the JSON output into `ScanResult` structures.

use crate::collect::{ProcessRecord, ScanResult};
use serde::{Deserialize, Serialize};
use std::io;
use std::process::Command;
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
    pub scan: Option<ScanResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub duration_ms: u64,
}

/// Result of a fleet-wide scan across all hosts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetScanResult {
    pub total_hosts: usize,
    pub successful: usize,
    pub failed: usize,
    pub results: Vec<HostScanResult>,
    pub duration_ms: u64,
}

/// Wrapper for the top-level JSON output of `pt-core scan --format json`.
#[derive(Debug, Deserialize)]
struct RemoteScanOutput {
    #[allow(dead_code)]
    schema_version: Option<String>,
    #[allow(dead_code)]
    session_id: Option<String>,
    scan: ScanResult,
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

    // Remote command
    args.push(format!("{} scan --format json", config.remote_binary));

    args
}

/// Scan a single host via SSH and parse the result.
pub fn ssh_scan_host(host: &str, config: &SshScanConfig) -> HostScanResult {
    let start = std::time::Instant::now();

    let args = build_ssh_args(host, config);
    let timeout = Duration::from_secs(config.command_timeout);

    let child = match Command::new("ssh").args(&args).output() {
        Ok(output) => output,
        Err(e) => {
            if e.kind() == io::ErrorKind::NotFound {
                return HostScanResult {
                    host: host.to_string(),
                    success: false,
                    scan: None,
                    error: Some(format!("ssh binary not found: {}", e)),
                    duration_ms: start.elapsed().as_millis() as u64,
                };
            }
            return HostScanResult {
                host: host.to_string(),
                success: false,
                scan: None,
                error: Some(format!("ssh failed: {}", e)),
                duration_ms: start.elapsed().as_millis() as u64,
            };
        }
    };

    let duration_ms = start.elapsed().as_millis() as u64;

    // Check for timeout (approximate — Command::output blocks)
    if duration_ms > timeout.as_millis() as u64 {
        return HostScanResult {
            host: host.to_string(),
            success: false,
            scan: None,
            error: Some(format!("timed out after {}s", config.command_timeout)),
            duration_ms,
        };
    }

    if !child.status.success() {
        let stderr = String::from_utf8_lossy(&child.stderr);
        let code = child.status.code().unwrap_or(-1);
        return HostScanResult {
            host: host.to_string(),
            success: false,
            scan: None,
            error: Some(format!("exit code {}: {}", code, stderr.trim())),
            duration_ms,
        };
    }

    let stdout = String::from_utf8_lossy(&child.stdout);

    // Parse the JSON output
    match serde_json::from_str::<RemoteScanOutput>(&stdout) {
        Ok(output) => HostScanResult {
            host: host.to_string(),
            success: true,
            scan: Some(output.scan),
            error: None,
            duration_ms,
        },
        Err(e) => {
            // Try parsing as bare ScanResult (older pt-core versions)
            match serde_json::from_str::<ScanResult>(&stdout) {
                Ok(scan) => HostScanResult {
                    host: host.to_string(),
                    success: true,
                    scan: Some(scan),
                    error: None,
                    duration_ms,
                },
                Err(_) => HostScanResult {
                    host: host.to_string(),
                    success: false,
                    scan: None,
                    error: Some(format!("failed to parse scan output: {}", e)),
                    duration_ms,
                },
            }
        }
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

    // Process hosts in batches of `parallel`
    let chunks: Vec<Vec<(usize, &String)>> = hosts
        .iter()
        .enumerate()
        .collect::<Vec<_>>()
        .chunks(config.parallel)
        .map(|chunk| chunk.to_vec())
        .collect();

    for chunk in chunks {
        // Check if aborted
        if !config.continue_on_error && *aborted.lock().unwrap() {
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
                    if !config.continue_on_error && *aborted.lock().unwrap() {
                        return;
                    }

                    let result = ssh_scan_host(&host, &config);

                    if !result.success && !config.continue_on_error {
                        *aborted.lock().unwrap() = true;
                    }

                    results.lock().unwrap().push((idx, result));
                })
            })
            .collect();

        for handle in handles {
            let _ = handle.join();
        }
    }

    // Sort by original index to maintain order
    let mut collected = Arc::try_unwrap(results).unwrap().into_inner().unwrap();
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
    }
}

/// Convert a HostScanResult into a HostInput for fleet session aggregation.
pub fn scan_result_to_host_input(result: &HostScanResult) -> crate::session::fleet::HostInput {
    use crate::session::fleet::{CandidateInfo, HostInput};

    match &result.scan {
        Some(scan) => {
            // Build candidate info from processes.
            // In a real fleet scan, this would go through inference to get
            // classifications and scores. For now, we use state-based heuristics.
            let candidates: Vec<CandidateInfo> = scan
                .processes
                .iter()
                .filter_map(|p| {
                    let (classification, action, score) = classify_process(p);
                    if score > 0.3 {
                        Some(CandidateInfo {
                            pid: p.pid.0,
                            signature: p.comm.clone(),
                            classification,
                            recommended_action: action,
                            score,
                            e_value: None,
                        })
                    } else {
                        None
                    }
                })
                .collect();

            HostInput {
                host_id: result.host.clone(),
                session_id: format!("ssh-{}", result.host),
                scanned_at: scan.metadata.started_at.clone(),
                total_processes: scan.metadata.process_count as u32,
                candidates,
            }
        }
        None => HostInput {
            host_id: result.host.clone(),
            session_id: format!("ssh-{}-failed", result.host),
            scanned_at: chrono::Utc::now().to_rfc3339(),
            total_processes: 0,
            candidates: Vec::new(),
        },
    }
}

/// Simple state-based process classification for fleet scanning.
///
/// Returns (classification, recommended_action, score).
fn classify_process(process: &ProcessRecord) -> (String, String, f64) {
    use crate::collect::ProcessState;

    match process.state {
        ProcessState::Zombie => ("zombie".to_string(), "kill".to_string(), 0.95),
        ProcessState::Stopped => {
            if process.elapsed.as_secs() > 3600 {
                ("abandoned".to_string(), "kill".to_string(), 0.7)
            } else {
                ("stopped".to_string(), "review".to_string(), 0.5)
            }
        }
        ProcessState::DiskSleep => {
            if process.elapsed.as_secs() > 600 {
                ("stuck".to_string(), "review".to_string(), 0.6)
            } else {
                ("io_wait".to_string(), "spare".to_string(), 0.2)
            }
        }
        ProcessState::Running | ProcessState::Sleeping => {
            if process.cpu_percent > 90.0 && process.elapsed.as_secs() > 3600 {
                ("runaway".to_string(), "review".to_string(), 0.5)
            } else {
                ("normal".to_string(), "spare".to_string(), 0.1)
            }
        }
        _ => ("unknown".to_string(), "spare".to_string(), 0.1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock_process::{MockProcessBuilder, MockScanBuilder};

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
        assert!(args
            .iter()
            .any(|a| a.contains("pt-core scan --format json")));
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
        assert!(args
            .iter()
            .any(|a| a.contains("/opt/pt/bin/pt-core scan --format json")));
    }

    #[test]
    fn classify_zombie_process() {
        let p = MockProcessBuilder::new()
            .pid(1)
            .comm("zombie_proc")
            .state_zombie()
            .elapsed_hours(1)
            .build();
        let (class, action, score) = classify_process(&p);
        assert_eq!(class, "zombie");
        assert_eq!(action, "kill");
        assert!(score > 0.9);
    }

    #[test]
    fn classify_stopped_old_process() {
        let p = MockProcessBuilder::new()
            .pid(2)
            .comm("old_worker")
            .state_stopped()
            .elapsed_hours(2)
            .build();
        let (class, action, score) = classify_process(&p);
        assert_eq!(class, "abandoned");
        assert_eq!(action, "kill");
        assert!(score > 0.5);
    }

    #[test]
    fn classify_running_process() {
        let p = MockProcessBuilder::new()
            .pid(3)
            .comm("nginx")
            .cpu_percent(5.0)
            .elapsed_days(1)
            .build();
        let (class, action, score) = classify_process(&p);
        assert_eq!(class, "normal");
        assert_eq!(action, "spare");
        assert!(score < 0.3);
    }

    #[test]
    fn scan_result_to_host_input_success() {
        let zombie = MockProcessBuilder::new()
            .pid(100)
            .comm("zombie_test")
            .state_zombie()
            .elapsed_hours(1)
            .build();
        let normal = MockProcessBuilder::new()
            .pid(101)
            .comm("nginx")
            .cpu_percent(1.0)
            .elapsed_days(1)
            .build();

        let scan = MockScanBuilder::new()
            .with_process(zombie)
            .with_process(normal)
            .build();

        let result = HostScanResult {
            host: "host1".to_string(),
            success: true,
            scan: Some(scan),
            error: None,
            duration_ms: 500,
        };

        let input = scan_result_to_host_input(&result);
        assert_eq!(input.host_id, "host1");
        assert_eq!(input.total_processes, 2);
        // Only the zombie should be a candidate (score > 0.3)
        assert_eq!(input.candidates.len(), 1);
        assert_eq!(input.candidates[0].signature, "zombie_test");
        assert_eq!(input.candidates[0].classification, "zombie");
    }

    #[test]
    fn scan_result_to_host_input_failed() {
        let result = HostScanResult {
            host: "host2".to_string(),
            success: false,
            scan: None,
            error: Some("connection refused".to_string()),
            duration_ms: 100,
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
                    scan: None,
                    error: None,
                    duration_ms: 200,
                },
                HostScanResult {
                    host: "host2".to_string(),
                    success: false,
                    scan: None,
                    error: Some("timeout".to_string()),
                    duration_ms: 30000,
                },
            ],
            duration_ms: 30200,
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
    fn classify_disk_sleep_long() {
        let p = MockProcessBuilder::new()
            .pid(10)
            .comm("stuck_io")
            .state_disksleep()
            .elapsed_hours(1)
            .build();
        let (class, action, score) = classify_process(&p);
        assert_eq!(class, "stuck");
        assert_eq!(action, "review");
        assert!(score > 0.5);
    }

    #[test]
    fn classify_disk_sleep_short() {
        let p = MockProcessBuilder::new()
            .pid(11)
            .comm("io_op")
            .state_disksleep()
            .elapsed_secs(60)
            .build();
        let (class, _action, score) = classify_process(&p);
        assert_eq!(class, "io_wait");
        assert!(score < 0.3);
    }

    #[test]
    fn classify_stopped_recent() {
        let p = MockProcessBuilder::new()
            .pid(12)
            .comm("debugged")
            .state_stopped()
            .elapsed_secs(300)
            .build();
        let (class, action, score) = classify_process(&p);
        assert_eq!(class, "stopped");
        assert_eq!(action, "review");
        assert!(score > 0.3 && score < 0.7);
    }
}
