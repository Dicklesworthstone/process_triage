//! Read-only fleet pressure snapshots and host hygiene audits.
//!
//! These routes never generate an executable fleet plan or apply a remedy. Each
//! host runs one bounded command through the same SSH transport and sliding pool
//! as planning. Unknown readings, failed connections and unattempted hosts remain
//! distinct, and remote suggested commands are retained only as report data.

use super::ssh_scan::{build_ssh_command_args, remote_health, run_host_pool, SshScanConfig};
use crate::collect::tool_runner::{run_tool, ToolError, ToolOutput};
use crate::decision::pressure_regime::{PressureAssessment, Severity};
use crate::session::fleet::{HostHealth, HostHealthStatus, PressureCoverage};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InspectionKind {
    Health,
    Doctor,
}

impl InspectionKind {
    pub fn command(self) -> &'static str {
        match self {
            Self::Health => "agent fleet health",
            Self::Doctor => "agent fleet doctor",
        }
    }

    fn remote_command(self) -> &'static str {
        match self {
            Self::Health => "agent snapshot",
            Self::Doctor => "doctor",
        }
    }

    fn arguments(self, binary: &str) -> Vec<String> {
        let mut args = vec![binary.to_string(), "--format".into(), "json".into()];
        match self {
            Self::Health => args.extend(["agent".into(), "snapshot".into(), "--minimal".into()]),
            Self::Doctor => args.push("doctor".into()),
        }
        args
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InspectionStatus {
    Completed,
    Failed,
    Skipped,
}

/// Owned wire representation: local doctor finding identifiers are static strings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteDoctorFinding {
    pub id: String,
    pub level: DoctorLevel,
    pub summary: String,
    pub observed: Value,
    pub recommended: Option<String>,
    pub rationale: String,
    #[serde(default)]
    pub commands: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DoctorLevel {
    Ok,
    Info,
    Warn,
    Crit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteDoctorReport {
    pub worst: DoctorLevel,
    pub pressure: PressureAssessment,
    pub findings: Vec<RemoteDoctorFinding>,
    pub facts: Value,
}

/// One requested host, including the transport result even when its data is invalid.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInspection {
    pub host: String,
    pub status: InspectionStatus,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub output_truncated: bool,
    pub stderr: String,
    pub error: Option<String>,
    pub duration_ms: u64,
    pub pt_version: Option<String>,
    pub matches_local_version: Option<bool>,
    pub remote_host_id: Option<String>,
    pub generated_at: Option<String>,
    /// Greatest observed problem; unknown when a quiet report has evidence gaps.
    pub observed_status: HostHealthStatus,
    pub coverage: PressureCoverage,
    pub health: Option<HostHealth>,
    pub system_state: Option<Value>,
    pub responsible_units: Option<Value>,
    pub doctor: Option<RemoteDoctorReport>,
    pub warnings: Vec<String>,
}

impl HostInspection {
    fn failed(host: &str, error: impl Into<String>, duration_ms: u64) -> Self {
        Self {
            host: host.to_string(),
            status: InspectionStatus::Failed,
            exit_code: None,
            timed_out: false,
            output_truncated: false,
            stderr: String::new(),
            error: Some(error.into()),
            duration_ms,
            pt_version: None,
            matches_local_version: None,
            remote_host_id: None,
            generated_at: None,
            observed_status: HostHealthStatus::Unknown,
            coverage: PressureCoverage::Unavailable,
            health: None,
            system_state: None,
            responsible_units: None,
            doctor: None,
            warnings: Vec::new(),
        }
    }

    fn severity(&self) -> Option<Severity> {
        match self.observed_status {
            HostHealthStatus::Crit => Some(Severity::Crit),
            HostHealthStatus::Warn => Some(Severity::Warn),
            HostHealthStatus::Ok => Some(Severity::Ok),
            HostHealthStatus::Unknown => self
                .health
                .as_ref()
                .and_then(|health| health.assessment.as_ref().map(|value| value.worst)),
        }
    }

    fn sort_priority(&self) -> u8 {
        match self.observed_status {
            HostHealthStatus::Crit => 0,
            HostHealthStatus::Warn => 1,
            HostHealthStatus::Unknown => 2,
            HostHealthStatus::Ok => 3,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetInspection {
    pub kind: InspectionKind,
    pub total_hosts: usize,
    pub completed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub circuit_open: bool,
    pub duration_ms: u64,
    pub warning_hosts: usize,
    pub critical_hosts: usize,
    pub unknown_hosts: usize,
    pub complete_hosts: usize,
    pub partial_hosts: usize,
    pub unavailable_hosts: usize,
    pub version_mismatches: usize,
    pub version_unavailable: usize,
    pub worst_observed: Option<Severity>,
    /// Critical findings first, then warnings, unknowns and fully observed quiet hosts.
    pub results: Vec<HostInspection>,
}

fn validate_envelope(document: &Value, kind: InspectionKind) -> Result<(), String> {
    if document["schema_version"].as_str() != Some(pt_common::SCHEMA_VERSION) {
        return Err(
            "unsupported or missing remote schema_version; update the remote pt-core".into(),
        );
    }
    if document["command"].as_str() != Some(kind.remote_command())
        || document["status"].as_str() != Some("ok")
        || !document["error"].is_null()
    {
        return Err(format!(
            "remote response is not a successful {}",
            kind.remote_command()
        ));
    }
    for field in ["pt_version", "host_id"] {
        if document[field].as_str().is_none_or(str::is_empty) {
            return Err(format!("remote response has no {field}"));
        }
    }
    document["generated_at"]
        .as_str()
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .ok_or("remote response has no valid observation timestamp")?;
    Ok(())
}

fn parse_health(document: &Value, result: &mut HostInspection) -> Result<(), String> {
    let system = document["system_state"]
        .as_object()
        .ok_or("snapshot has no system_state object")?;
    // A missing process count cannot certify a supplied zombie/D-state census.
    // Other independently valid pressure observations remain useful.
    let total = system.get("process_count").and_then(Value::as_u64);
    let mut validated_system = document["system_state"].clone();
    if total.is_none() {
        validated_system["census"] = Value::Null;
    }
    let health = remote_health(Some(&validated_system), total.unwrap_or(0));
    result.observed_status = health.status;
    result.coverage = health.coverage;
    result.health = Some(health);
    result.system_state = Some(document["system_state"].clone());
    match document
        .get("responsible_units")
        .filter(|value| !value.is_null())
    {
        Some(table)
            if table["units"].as_array().is_some_and(|units| {
                units.iter().all(|unit| {
                    unit["id"].as_str().is_some_and(|id| !id.is_empty())
                        && unit["label"].is_string()
                        && unit["member_count"].as_u64().is_some()
                        && unit["usage"].is_object()
                })
            }) =>
        {
            result.responsible_units = Some(table.clone())
        }
        _ => result
            .warnings
            .push("responsible-unit attribution unavailable or malformed".into()),
    }
    Ok(())
}

fn parse_doctor(document: &Value, result: &mut HostInspection) -> Result<(), String> {
    let report: RemoteDoctorReport = serde_json::from_value(document.clone())
        .map_err(|error| format!("invalid doctor report: {error}"))?;
    if !report.facts.is_object()
        || report.findings.is_empty()
        || report
            .findings
            .iter()
            .any(|finding| finding.id.is_empty() || finding.summary.is_empty())
        || report.findings.iter().map(|finding| finding.level).max() != Some(report.worst)
    {
        return Err(
            "doctor findings are missing, malformed, or disagree with worst severity".into(),
        );
    }
    let expected_exit = i32::from(report.worst >= DoctorLevel::Warn);
    if result.exit_code != Some(expected_exit) {
        return Err("doctor exit status disagrees with its findings".into());
    }
    let unsupported = report
        .findings
        .iter()
        .any(|finding| finding.id == "platform");
    // Doctor reports static observations and known gaps, not a witness that
    // every live host check succeeded. A quiet audit cannot certify host health.
    result.coverage = if unsupported {
        PressureCoverage::Unavailable
    } else {
        PressureCoverage::Partial
    };
    result.observed_status = match report.worst {
        DoctorLevel::Crit => HostHealthStatus::Crit,
        DoctorLevel::Warn => HostHealthStatus::Warn,
        DoctorLevel::Ok | DoctorLevel::Info => HostHealthStatus::Unknown,
    };
    if unsupported {
        result
            .warnings
            .push("doctor does not cover this remote platform".into());
    }
    result.doctor = Some(report);
    Ok(())
}

fn parse_output(host: &str, kind: InspectionKind, output: &ToolOutput) -> HostInspection {
    let mut result = HostInspection::failed(
        host,
        "remote inspection incomplete",
        output.duration.as_millis() as u64,
    );
    result.exit_code = output.exit_code;
    result.timed_out = output.timed_out;
    result.output_truncated = output.truncated;
    result.stderr = output.stderr_str();
    let parsed = (|| -> Result<(), String> {
        if output.timed_out {
            return Err("remote inspection timed out; no complete observation was accepted".into());
        }
        if output.truncated {
            return Err(
                "remote inspection output was truncated; no complete observation was accepted"
                    .into(),
            );
        }
        let accepted_exit = match kind {
            InspectionKind::Health => output.exit_code == Some(0),
            InspectionKind::Doctor => matches!(output.exit_code, Some(0 | 1)),
        };
        if !accepted_exit {
            return Err(format!(
                "remote {} exited with {:?}",
                kind.remote_command(),
                output.exit_code
            ));
        }
        let document: Value = serde_json::from_slice(&output.stdout)
            .map_err(|error| format!("remote inspection did not return valid JSON: {error}"))?;
        result.pt_version = document["pt_version"].as_str().map(str::to_string);
        result.matches_local_version = result
            .pt_version
            .as_deref()
            .map(|version| version == env!("CARGO_PKG_VERSION"));
        result.remote_host_id = document["host_id"].as_str().map(str::to_string);
        result.generated_at = document["generated_at"].as_str().map(str::to_string);
        validate_envelope(&document, kind)?;
        match kind {
            InspectionKind::Health => parse_health(&document, &mut result),
            InspectionKind::Doctor => parse_doctor(&document, &mut result),
        }
    })();
    match parsed {
        Ok(()) => {
            result.status = InspectionStatus::Completed;
            result.error = None;
        }
        Err(error) => result.error = Some(error),
    }
    result
}

fn tool_failure(host: &str, error: &ToolError, duration_ms: u64) -> HostInspection {
    let mut result =
        HostInspection::failed(host, format!("SSH inspection failed: {error}"), duration_ms);
    match error {
        ToolError::Timeout(_) => result.timed_out = true,
        ToolError::OutputTruncated { .. } => result.output_truncated = true,
        ToolError::NonZeroExit { code, stderr, .. } => {
            result.exit_code = Some(*code);
            result.stderr = String::from_utf8_lossy(stderr).into_owned();
        }
        _ => {}
    }
    result
}

pub fn inspect_host(host: &str, config: &SshScanConfig, kind: InspectionKind) -> HostInspection {
    let started = Instant::now();
    let args = match build_ssh_command_args(host, config, &kind.arguments(&config.remote_binary)) {
        Ok(args) if !config.remote_binary.is_empty() => args,
        Ok(_) => return HostInspection::failed(host, "remote binary is empty", 0),
        Err(error) => return HostInspection::failed(host, error, 0),
    };
    let args_ref: Vec<_> = args.iter().map(String::as_str).collect();
    match run_tool(
        "ssh",
        &args_ref,
        Some(Duration::from_secs(config.command_timeout.max(1))),
        None,
    ) {
        Ok(output) => parse_output(host, kind, &output),
        Err(error) => tool_failure(host, &error, started.elapsed().as_millis() as u64),
    }
}

/// One attempt per host; failed hosts are never retried in this run. The global
/// consecutive-failure limit also stops new connections during a fleet outage.
pub fn inspect_fleet(
    hosts: &[String],
    config: &SshScanConfig,
    kind: InspectionKind,
    max_consecutive_failures: usize,
) -> FleetInspection {
    inspect_fleet_with(hosts, config, kind, max_consecutive_failures, inspect_host)
}

fn inspect_fleet_with<F>(
    hosts: &[String],
    config: &SshScanConfig,
    kind: InspectionKind,
    max_consecutive_failures: usize,
    inspect: F,
) -> FleetInspection
where
    F: Fn(&str, &SshScanConfig, InspectionKind) -> HostInspection + Sync,
{
    let started = Instant::now();
    let (collected, circuit_open) = run_host_pool(
        hosts,
        config.parallel,
        max_consecutive_failures,
        |host| inspect(host, config, kind),
        |result| result.status == InspectionStatus::Completed,
        |host, duration_ms| {
            HostInspection::failed(host, "fleet inspection worker panicked", duration_ms)
        },
    );
    let mut by_index: HashMap<_, _> = collected.into_iter().collect();
    let mut results: Vec<_> = hosts
        .iter()
        .enumerate()
        .map(|(index, host)| {
            by_index.remove(&index).unwrap_or_else(|| {
                let mut result = HostInspection::failed(
                    host,
                    "not attempted: fleet failure limit stopped new connections",
                    0,
                );
                result.status = InspectionStatus::Skipped;
                result
            })
        })
        .collect();
    results.sort_by(|a, b| {
        a.sort_priority()
            .cmp(&b.sort_priority())
            .then_with(|| a.host.cmp(&b.host))
    });
    FleetInspection {
        kind,
        total_hosts: hosts.len(),
        completed: results
            .iter()
            .filter(|r| r.status == InspectionStatus::Completed)
            .count(),
        failed: results
            .iter()
            .filter(|r| r.status == InspectionStatus::Failed)
            .count(),
        skipped: results
            .iter()
            .filter(|r| r.status == InspectionStatus::Skipped)
            .count(),
        circuit_open,
        duration_ms: started.elapsed().as_millis() as u64,
        warning_hosts: results
            .iter()
            .filter(|r| r.observed_status == HostHealthStatus::Warn)
            .count(),
        critical_hosts: results
            .iter()
            .filter(|r| r.observed_status == HostHealthStatus::Crit)
            .count(),
        unknown_hosts: results
            .iter()
            .filter(|r| r.observed_status == HostHealthStatus::Unknown)
            .count(),
        complete_hosts: results
            .iter()
            .filter(|r| r.coverage == PressureCoverage::Complete)
            .count(),
        partial_hosts: results
            .iter()
            .filter(|r| r.coverage == PressureCoverage::Partial)
            .count(),
        unavailable_hosts: results
            .iter()
            .filter(|r| r.coverage == PressureCoverage::Unavailable)
            .count(),
        version_mismatches: results
            .iter()
            .filter(|r| r.matches_local_version == Some(false))
            .count(),
        version_unavailable: results.iter().filter(|r| r.pt_version.is_none()).count(),
        worst_observed: results.iter().filter_map(HostInspection::severity).max(),
        results,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{mpsc, Mutex};

    fn snapshot(cpu: f64) -> Value {
        json!({
            "schema_version": pt_common::SCHEMA_VERSION,
            "command": "agent snapshot",
            "status": "ok",
            "pt_version": env!("CARGO_PKG_VERSION"),
            "host_id": "observed-host-id",
            "generated_at": "2026-02-08T12:00:00Z",
            "system_state": {
                "process_count": 100,
                "census": {"zombies": 0, "dstate": 0},
                "assessment": {"worst": "ok", "regimes": []},
                "pressure": {
                    "sampled_at_ms": 1_770_552_000_000_u64,
                    "cpus": 8,
                    "cpu": {"some": {"avg10": cpu, "avg60": cpu, "avg300": cpu, "total_us": 100}},
                    "memory": {"some": {"avg10": 0.0, "avg60": 0.0, "avg300": 0.0, "total_us": 0}},
                    "io": {"some": {"avg10": 0.0, "avg60": 0.0, "avg300": 0.0, "total_us": 0}},
                    "load": {"one": 1.0, "five": 1.0, "fifteen": 1.0},
                    "meminfo": {"total": 16_u64 << 30, "available": 8_u64 << 30, "swap_total": 0, "swap_free": 0},
                    "file_handles": {"allocated": 10, "max": 10000},
                    "unavailable": []
                }
            },
            "responsible_units": {
                "rank_by": "cpu",
                "units": [{"id": "build-unit", "label": "compiler scope", "member_count": 2, "usage": {"cpu_cores": {"value": 4.0}}}]
            }
        })
    }

    fn output(document: &Value, exit_code: i32) -> ToolOutput {
        ToolOutput {
            command: "ssh".into(),
            args: vec![],
            stdout: serde_json::to_vec(document).unwrap(),
            stderr: Vec::new(),
            exit_code: Some(exit_code),
            truncated: false,
            duration: Duration::from_millis(25),
            timed_out: false,
        }
    }

    fn doctor(level: &str) -> Value {
        let snapshot = snapshot(0.0);
        let pressure = remote_health(Some(&snapshot["system_state"]), 100)
            .assessment
            .unwrap();
        json!({
            "schema_version": pt_common::SCHEMA_VERSION,
            "command": "doctor",
            "status": "ok",
            "pt_version": env!("CARGO_PKG_VERSION"),
            "host_id": "doctor-host",
            "generated_at": "2026-02-08T12:00:00Z",
            "worst": level,
            "pressure": pressure,
            "facts": {"meminfo": {"total": 16_u64 << 30}},
            "findings": [{
                "id": "vm.swappiness", "level": level,
                "summary": "Swap tuning needs review", "observed": 10,
                "recommended": "Review the proposed tuning", "rationale": "Recorded host facts",
                "commands": ["printf 'suggestion only; never executed'"],
            }]
        })
    }

    #[test]
    fn health_recomputes_pressure_and_preserves_remote_attribution() {
        let document = snapshot(45.0);
        let result = parse_output("ssh-alias", InspectionKind::Health, &output(&document, 0));
        assert_eq!(result.status, InspectionStatus::Completed);
        assert_eq!(result.observed_status, HostHealthStatus::Crit);
        assert_eq!(result.coverage, PressureCoverage::Complete);
        assert_eq!(result.remote_host_id.as_deref(), Some("observed-host-id"));
        assert_eq!(
            result.system_state.as_ref(),
            Some(&document["system_state"])
        );
        assert_eq!(
            result.responsible_units.as_ref(),
            Some(&document["responsible_units"])
        );
        assert_eq!(
            result.health.unwrap().assessment.unwrap().cpu_some,
            Some(45.0)
        );
        assert!(result.doctor.is_none());

        let mut quiet = snapshot(0.0);
        quiet["system_state"]["pressure"]["memory"] = Value::Null;
        let partial = parse_output("partial", InspectionKind::Health, &output(&quiet, 0));
        assert_eq!(partial.status, InspectionStatus::Completed);
        assert_eq!(partial.observed_status, HostHealthStatus::Unknown);
        assert_eq!(partial.coverage, PressureCoverage::Partial);
        assert!(partial.health.unwrap().pressure.unwrap().memory.is_none());

        quiet["system_state"]["pressure"] = Value::Null;
        let unavailable = parse_output("unavailable", InspectionKind::Health, &output(&quiet, 0));
        assert_eq!(unavailable.status, InspectionStatus::Completed);
        assert_eq!(unavailable.observed_status, HostHealthStatus::Unknown);
        assert_eq!(unavailable.coverage, PressureCoverage::Unavailable);
    }

    #[test]
    fn unknown_census_and_bad_attribution_never_hide_valid_pressure() {
        let mut document = snapshot(45.0);
        document["system_state"]["process_count"] = Value::Null;
        document["system_state"]["census"]["zombies"] = json!(1000);
        document["responsible_units"] = json!({"units": ["invalid unit"]});
        let result = parse_output("host", InspectionKind::Health, &output(&document, 0));
        assert_eq!(result.status, InspectionStatus::Completed);
        assert_eq!(result.observed_status, HostHealthStatus::Crit);
        assert_eq!(result.coverage, PressureCoverage::Partial);
        assert!(result.health.as_ref().unwrap().census.is_none());
        assert!(result.responsible_units.is_none());
        assert!(!result.warnings.is_empty());
    }

    #[test]
    fn wrong_command_schema_or_envelope_is_a_failed_inspection() {
        for (key, value) in [
            ("command", json!("agent plan")),
            ("schema_version", json!("99.0.0")),
            ("schema_version", Value::Null),
            ("status", json!("error")),
            ("error", json!("remote failure")),
            ("pt_version", Value::Null),
            ("host_id", json!("")),
            ("generated_at", json!("not-a-timestamp")),
            ("system_state", json!("unreadable")),
        ] {
            let mut document = snapshot(0.0);
            document[key] = value;
            let result = parse_output("host", InspectionKind::Health, &output(&document, 0));
            assert_eq!(result.status, InspectionStatus::Failed, "{key}");
            assert_eq!(result.observed_status, HostHealthStatus::Unknown, "{key}");
            assert_eq!(result.coverage, PressureCoverage::Unavailable, "{key}");
            assert!(result.health.is_none(), "{key}");
            assert_eq!(result.exit_code, Some(0), "{key}");
        }
        let mut other_version = snapshot(0.0);
        other_version["pt_version"] = json!("another-version");
        let result = parse_output("host", InspectionKind::Health, &output(&other_version, 0));
        assert_eq!(result.status, InspectionStatus::Completed);
        assert_eq!(result.matches_local_version, Some(false));
    }

    #[test]
    fn doctor_findings_exit_is_success_and_suggestions_remain_data() {
        let document = doctor("crit");
        let result = parse_output("host", InspectionKind::Doctor, &output(&document, 1));
        assert_eq!(result.status, InspectionStatus::Completed);
        assert_eq!(result.exit_code, Some(1));
        assert_eq!(result.observed_status, HostHealthStatus::Crit);
        assert_eq!(result.coverage, PressureCoverage::Partial);
        let report = result.doctor.unwrap();
        assert_eq!(
            report.findings[0].commands,
            ["printf 'suggestion only; never executed'"]
        );
        assert_eq!(report.facts, document["facts"]);
        assert!(result.health.is_none());
        assert_eq!(
            InspectionKind::Doctor.arguments("/opt/pt tools/pt-core"),
            ["/opt/pt tools/pt-core", "--format", "json", "doctor"]
        );

        let inconsistent = parse_output("host", InspectionKind::Doctor, &output(&document, 0));
        assert_eq!(inconsistent.status, InspectionStatus::Failed);
        assert!(inconsistent.doctor.is_none());

        let mut unsupported = doctor("info");
        unsupported["findings"][0]["id"] = json!("platform");
        let result = parse_output("mac", InspectionKind::Doctor, &output(&unsupported, 0));
        assert_eq!(result.status, InspectionStatus::Completed);
        assert_eq!(result.observed_status, HostHealthStatus::Unknown);
        assert_eq!(result.coverage, PressureCoverage::Unavailable);
        assert!(!result.warnings.is_empty());

        let mut inconsistent = document.clone();
        inconsistent["worst"] = json!("ok");
        assert_eq!(
            parse_output("host", InspectionKind::Doctor, &output(&inconsistent, 0)).status,
            InspectionStatus::Failed
        );
    }

    #[test]
    fn transport_timeout_truncation_and_errors_keep_actual_diagnostics() {
        let document = snapshot(0.0);
        for (timed_out, truncated, exit) in
            [(true, false, 0), (false, true, 0), (false, false, 255)]
        {
            let mut child = output(&document, exit);
            child.timed_out = timed_out;
            child.truncated = truncated;
            child.stderr = b"SSH connection diagnostic".to_vec();
            let result = parse_output("host", InspectionKind::Health, &child);
            assert_eq!(result.status, InspectionStatus::Failed);
            assert_eq!(result.exit_code, Some(exit));
            assert_eq!(result.timed_out, timed_out);
            assert_eq!(result.output_truncated, truncated);
            assert_eq!(result.stderr, "SSH connection diagnostic");
            assert!(result.health.is_none());
        }
        assert_eq!(
            parse_output("host", InspectionKind::Doctor, &output(&doctor("warn"), 2)).status,
            InspectionStatus::Failed
        );
    }

    #[test]
    fn typed_tool_errors_preserve_timeout_truncation_and_remote_exit_metadata() {
        let timeout = tool_failure("host", &ToolError::Timeout(Duration::from_secs(3)), 3000);
        assert_eq!(timeout.status, InspectionStatus::Failed);
        assert!(timeout.timed_out);
        assert_eq!(timeout.exit_code, None);
        assert_eq!(timeout.observed_status, HostHealthStatus::Unknown);
        assert!(timeout.health.is_none());

        let truncated = tool_failure(
            "host",
            &ToolError::OutputTruncated {
                limit: 10,
                actual: 20,
            },
            10,
        );
        assert!(truncated.output_truncated);
        assert!(!truncated.timed_out);

        let remote = tool_failure(
            "host",
            &ToolError::NonZeroExit {
                code: 255,
                stdout: Vec::new(),
                stderr: b"connection refused".to_vec(),
            },
            5,
        );
        assert_eq!(remote.status, InspectionStatus::Failed);
        assert_eq!(remote.exit_code, Some(255));
        assert_eq!(remote.stderr, "connection refused");
        assert!(!remote.timed_out);
        assert!(!remote.output_truncated);
    }

    #[test]
    fn inspections_use_a_sliding_bounded_pool_and_retain_failed_hosts() {
        let hosts = ["slow", "fast", "third", "bad", "last"].map(str::to_string);
        let config = SshScanConfig {
            parallel: 2,
            ..Default::default()
        };
        let (released, receiver) = mpsc::channel();
        let receiver = Mutex::new(receiver);
        let active = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        let report = inspect_fleet_with(
            &hosts,
            &config,
            InspectionKind::Health,
            3,
            |host, _, kind| {
                let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(current, Ordering::SeqCst);
                if host == "slow" {
                    receiver
                        .lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(2))
                        .expect("third host starts before slow host finishes");
                } else if host == "third" {
                    released.send(()).unwrap();
                }
                let result = if host == "bad" {
                    HostInspection::failed(host, "connection refused", 1)
                } else {
                    parse_output(
                        host,
                        kind,
                        &output(&snapshot(if host == "last" { 45.0 } else { 0.0 }), 0),
                    )
                };
                active.fetch_sub(1, Ordering::SeqCst);
                result
            },
        );
        assert_eq!(report.completed, 4);
        assert_eq!(report.failed, 1);
        assert_eq!(report.skipped, 0);
        assert!(!report.circuit_open);
        assert_eq!(report.results.len(), hosts.len());
        assert!(peak.load(Ordering::SeqCst) <= 2);
        assert_eq!(report.results[0].host, "last");
        assert_eq!(report.critical_hosts, 1);
        assert_eq!(report.unknown_hosts, 1);
        assert_eq!(report.worst_observed, Some(Severity::Crit));
    }

    #[test]
    fn consecutive_failure_circuit_resets_on_success_and_marks_unattempted_hosts() {
        let hosts =
            ["bad-one", "good", "bad-two", "bad-three", "not-attempted"].map(str::to_string);
        let config = SshScanConfig {
            parallel: 1,
            ..Default::default()
        };
        let attempted = Mutex::new(Vec::new());
        let report = inspect_fleet_with(
            &hosts,
            &config,
            InspectionKind::Health,
            2,
            |host, _, kind| {
                attempted.lock().unwrap().push(host.to_string());
                if host.starts_with("bad") {
                    HostInspection::failed(host, "unreachable", 1)
                } else {
                    parse_output(host, kind, &output(&snapshot(0.0), 0))
                }
            },
        );
        assert_eq!(*attempted.lock().unwrap(), hosts[..4]);
        assert!(report.circuit_open);
        assert_eq!(report.completed, 1);
        assert_eq!(report.failed, 3);
        assert_eq!(report.skipped, 1);
        let skipped = report
            .results
            .iter()
            .find(|result| result.host == "not-attempted")
            .unwrap();
        assert_eq!(skipped.status, InspectionStatus::Skipped);
        assert_eq!(skipped.exit_code, None);
        assert_eq!(skipped.coverage, PressureCoverage::Unavailable);
    }

    #[test]
    fn worker_panic_cannot_drop_a_requested_host_or_reopen_the_circuit() {
        let hosts = ["panics", "not-attempted"].map(str::to_string);
        let report = inspect_fleet_with(
            &hosts,
            &SshScanConfig {
                parallel: 1,
                ..Default::default()
            },
            InspectionKind::Health,
            1,
            |_, _, _| panic!("simulated worker fault"),
        );
        assert!(report.circuit_open);
        assert_eq!(report.failed, 1);
        assert_eq!(report.skipped, 1);
        assert_eq!(report.results.len(), 2);
        assert!(report
            .results
            .iter()
            .any(|result| result.error.as_deref() == Some("fleet inspection worker panicked")));
    }
}
