//! Integration-style tests for the scan → filter → inference pipeline.

use pt_common::{ProcessId, StartId};
use pt_core::collect::{ProcessRecord, ProcessState, ScanMetadata, ScanResult};
use pt_core::config::{policy::Policy, priors::Priors};
use pt_core::inference::{compute_posterior, CpuEvidence, Evidence};
use pt_core::collect::protected::{MatchedField, ProtectedFilter};
use std::time::Duration;

fn make_record(
    pid: u32,
    ppid: u32,
    user: &str,
    comm: &str,
    state: ProcessState,
    cpu_percent: f64,
    tty: Option<&str>,
) -> ProcessRecord {
    ProcessRecord {
        pid: ProcessId(pid),
        ppid: ProcessId(ppid),
        uid: if user == "root" { 0 } else { 1000 },
        user: user.to_string(),
        pgid: Some(pid),
        sid: Some(pid),
        start_id: StartId::from_linux("00000000-0000-0000-0000-000000000000", 0, pid),
        comm: comm.to_string(),
        cmd: comm.to_string(),
        state,
        cpu_percent,
        rss_bytes: 1024,
        vsz_bytes: 4096,
        tty: tty.map(|t| t.to_string()),
        start_time_unix: 0,
        elapsed: Duration::from_secs(3600),
        source: "test".to_string(),
    }
}

fn make_scan(processes: Vec<ProcessRecord>) -> ScanResult {
    let count = processes.len();
    ScanResult {
        processes,
        metadata: ScanMetadata {
            scan_type: "test".to_string(),
            platform: "test".to_string(),
            boot_id: None,
            started_at: "1970-01-01T00:00:00Z".to_string(),
            duration_ms: 0,
            process_count: count,
            warnings: vec![],
        },
    }
}

fn state_flag(state: ProcessState) -> Option<usize> {
    match state {
        ProcessState::Running => Some(0),
        ProcessState::Sleeping => Some(1),
        ProcessState::DiskSleep => Some(2),
        ProcessState::Zombie => Some(3),
        ProcessState::Stopped => Some(4),
        ProcessState::Idle => Some(5),
        ProcessState::Dead => Some(6),
        ProcessState::Unknown => None,
    }
}

#[test]
fn kernel_threads_filtered_by_guardrails() {
    let policy = Policy::default();
    let filter = ProtectedFilter::from_guardrails(&policy.guardrails)
        .expect("protected filter should compile");

    let processes = vec![
        make_record(2, 0, "root", "[kthreadd]", ProcessState::Sleeping, 0.0, None),
        make_record(42, 2, "root", "[kworker/0:0]", ProcessState::Idle, 0.0, None),
        make_record(9001, 1234, "testuser", "[cat]", ProcessState::Zombie, 0.0, None),
    ];
    let scan = make_scan(processes);

    let result = filter.filter_scan_result(&scan);

    let filtered_pids: Vec<u32> = result.filtered.iter().map(|m| m.pid).collect();
    assert!(
        filtered_pids.contains(&2) && filtered_pids.contains(&42),
        "expected kernel threads to be filtered: got {filtered_pids:?}"
    );
    assert!(
        result.filtered.iter().any(|m| m.matched_field == MatchedField::User),
        "expected kernel threads to be filtered by protected user (root)"
    );
    assert!(
        result.passed.iter().any(|p| p.pid.0 == 9001),
        "zombie process should remain after filtering"
    );
}

#[test]
fn candidates_sorted_by_posterior_not_pid_order() {
    let priors = Priors::default();

    let mut processes = Vec::new();
    for pid in 100..110 {
        processes.push(make_record(
            pid,
            200,
            "dev",
            "active_proc",
            ProcessState::Running,
            75.0,
            Some("pts/0"),
        ));
    }
    for pid in 9000..9005 {
        processes.push(make_record(
            pid,
            200,
            "dev",
            "[zombie]",
            ProcessState::Zombie,
            0.0,
            None,
        ));
    }

    let mut scored: Vec<(f64, u32)> = Vec::new();
    for proc in &processes {
        let evidence = Evidence {
            cpu: Some(CpuEvidence::Fraction {
                occupancy: (proc.cpu_percent / 100.0).clamp(0.0, 1.0),
            }),
            runtime_seconds: Some(proc.elapsed.as_secs_f64()),
            orphan: Some(proc.is_orphan()),
            tty: Some(proc.has_tty()),
            net: Some(false),
            io_active: Some(false),
            state_flag: state_flag(proc.state),
            command_category: None,
        };
        let posterior = compute_posterior(&priors, &evidence)
            .expect("posterior computation failed")
            .posterior;
        let max = posterior
            .useful
            .max(posterior.useful_bad)
            .max(posterior.abandoned)
            .max(posterior.zombie);
        scored.push((max, proc.pid.0));
    }

    scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    let top: Vec<u32> = scored.iter().take(5).map(|(_, pid)| *pid).collect();

    assert!(
        top.iter().all(|pid| *pid >= 9000),
        "expected top candidates to be zombies with high PIDs, got {top:?}"
    );
}
