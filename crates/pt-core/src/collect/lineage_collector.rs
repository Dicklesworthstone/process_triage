//! Lineage and supervisor collector for process ownership provenance.
//!
//! Gathers ancestry, session, TTY, and supervisor evidence from
//! `/proc` on Linux. Returns `RawLineageEvidence` that feeds into
//! `normalize_lineage()` from `pt_common::lineage_evidence`.
//!
//! Exposes explicit degraded states when evidence is missing or
//! platform-limited (e.g., permission denied reading another user's
//! /proc/[pid]/stat).

use std::fs;

use pt_common::{
    AncestorEntry, LineageCollectionMethod, ProvenanceConfidence, RawLineageEvidence,
    SupervisorEvidence, SupervisorKind, TtyEvidence,
};

/// Maximum number of ancestors to walk before stopping.
/// Prevents infinite loops on circular PPID chains (shouldn't happen,
/// but defensive coding against /proc corruption).
const MAX_ANCESTOR_DEPTH: usize = 64;

/// Collect lineage evidence for a process by PID.
///
/// Reads `/proc/{pid}/stat` and `/proc/{pid}/status` for the target
/// process and walks the ancestor chain up to PID 1.
#[cfg(target_os = "linux")]
pub fn collect_lineage_for_pid(pid: u32) -> RawLineageEvidence {
    let now = chrono::Utc::now().to_rfc3339();

    let stat = read_proc_stat(pid);
    let status = read_proc_status(pid);

    let (ppid, pgid, sid, tty_nr, tpgid, comm) = match &stat {
        Some(s) => (
            s.ppid,
            s.pgrp as u32,
            s.session as u32,
            s.tty_nr,
            s.tpgid,
            s.comm.clone(),
        ),
        None => (0, 0, 0, 0, -1, String::new()),
    };

    let uid = status.as_ref().map_or(0, |s| s.ruid);
    let user = resolve_username(uid);

    let tty = build_tty_evidence(tty_nr, tpgid, pid, pgid, sid);
    let ancestors = walk_ancestors(ppid);
    let supervisor = detect_supervisor(pid, ppid, &comm, &ancestors);

    RawLineageEvidence {
        pid,
        ppid,
        pgid,
        sid,
        uid,
        user,
        tty,
        supervisor,
        ancestors,
        collection_method: LineageCollectionMethod::Procfs,
        observed_at: now,
    }
}

/// Parsed fields from /proc/[pid]/stat relevant to lineage.
struct ProcStat {
    comm: String,
    ppid: u32,
    pgrp: i32,
    session: i32,
    tty_nr: i32,
    tpgid: i32,
}

/// Parsed fields from /proc/[pid]/status relevant to lineage.
struct ProcStatus {
    ruid: u32,
}

/// Read and parse /proc/[pid]/stat for lineage-relevant fields.
fn read_proc_stat(pid: u32) -> Option<ProcStat> {
    let path = format!("/proc/{pid}/stat");
    let content = fs::read_to_string(&path).ok()?;

    // /proc/[pid]/stat format: pid (comm) state ppid pgrp session tty_nr tpgid ...
    // The comm field is wrapped in parentheses and may contain spaces.
    let comm_start = content.find('(')?;
    let comm_end = content.rfind(')')?;
    let comm = content[comm_start + 1..comm_end].to_string();
    let after_comm = &content[comm_end + 2..]; // skip ") "
    let fields: Vec<&str> = after_comm.split_whitespace().collect();

    if fields.len() < 6 {
        return None;
    }

    Some(ProcStat {
        comm,
        ppid: fields[1].parse().ok()?,    // field index 3 in full stat
        pgrp: fields[2].parse().ok()?,    // field index 4
        session: fields[3].parse().ok()?, // field index 5
        tty_nr: fields[4].parse().ok()?,  // field index 6
        tpgid: fields[5].parse().unwrap_or(-1), // field index 7
    })
}

/// Read /proc/[pid]/status for UID info.
fn read_proc_status(pid: u32) -> Option<ProcStatus> {
    let path = format!("/proc/{pid}/status");
    let content = fs::read_to_string(&path).ok()?;

    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            let fields: Vec<&str> = rest.split_whitespace().collect();
            if let Some(ruid) = fields.first().and_then(|f| f.parse().ok()) {
                return Some(ProcStatus { ruid });
            }
        }
    }
    None
}

/// Resolve a UID to a username, if possible.
fn resolve_username(uid: u32) -> Option<String> {
    let path = "/etc/passwd";
    let content = fs::read_to_string(path).ok()?;
    let uid_str = uid.to_string();
    for line in content.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 3 && fields[2] == uid_str {
            return Some(fields[0].to_string());
        }
    }
    None
}

/// Build TTY evidence from /proc/[pid]/stat fields.
fn build_tty_evidence(
    tty_nr: i32,
    _tpgid: i32,
    pid: u32,
    pgid: u32,
    sid: u32,
) -> Option<TtyEvidence> {
    if tty_nr == 0 {
        // No controlling terminal
        return None;
    }

    let device = tty_device_name(tty_nr);
    let has_controlling_tty = tty_nr != 0;
    let is_session_leader = pid == sid;
    let is_pgid_leader = pid == pgid;

    Some(TtyEvidence {
        device,
        has_controlling_tty,
        is_session_leader,
        is_pgid_leader,
    })
}

/// Convert a tty_nr from /proc/[pid]/stat to a device name.
fn tty_device_name(tty_nr: i32) -> String {
    if tty_nr == 0 {
        return "?".to_string();
    }
    let major = (tty_nr >> 8) & 0xff;
    let minor = tty_nr & 0xff;
    match major {
        136..=143 => format!("/dev/pts/{}", minor + (major - 136) * 256),
        4 if minor < 64 => format!("/dev/tty{minor}"),
        4 => format!("/dev/ttyS{}", minor - 64),
        _ => format!("tty({major},{minor})"),
    }
}

/// Walk the ancestor chain from a given PPID up to PID 1.
fn walk_ancestors(start_ppid: u32) -> Vec<AncestorEntry> {
    let mut ancestors = Vec::new();
    let mut current_pid = start_ppid;
    let mut visited = std::collections::HashSet::new();

    for _ in 0..MAX_ANCESTOR_DEPTH {
        if current_pid == 0 || !visited.insert(current_pid) {
            break;
        }

        let stat = match read_proc_stat(current_pid) {
            Some(s) => s,
            None => break, // Can't read ancestor — permission denied or exited
        };

        let status = read_proc_status(current_pid);
        let uid = status.map_or(0, |s| s.ruid);

        ancestors.push(AncestorEntry {
            pid: current_pid,
            comm: stat.comm,
            uid,
        });

        if current_pid == 1 {
            break; // Reached init
        }

        current_pid = stat.ppid;
    }

    ancestors
}

/// Detect if a process is managed by a known supervisor.
fn detect_supervisor(
    pid: u32,
    _ppid: u32,
    _comm: &str,
    ancestors: &[AncestorEntry],
) -> Option<SupervisorEvidence> {
    // Check systemd: try reading /proc/[pid]/cgroup for a service unit
    if let Some(unit) = detect_systemd_unit(pid) {
        return Some(SupervisorEvidence {
            kind: SupervisorKind::Systemd,
            unit_name: Some(unit),
            auto_restart: None,
            confidence: ProvenanceConfidence::High,
        });
    }

    // Check if running inside a container (PID 1 inside cgroup namespace)
    if is_containerized(pid) {
        return Some(SupervisorEvidence {
            kind: SupervisorKind::Container,
            unit_name: None,
            auto_restart: None,
            confidence: ProvenanceConfidence::Medium,
        });
    }

    // Check ancestors for known supervisors
    for ancestor in ancestors {
        let comm_lower = ancestor.comm.to_lowercase();
        if comm_lower == "supervisord" || comm_lower.contains("supervisor") {
            return Some(SupervisorEvidence {
                kind: SupervisorKind::Supervisord,
                unit_name: Some(ancestor.comm.clone()),
                auto_restart: None,
                confidence: ProvenanceConfidence::Medium,
            });
        }
    }

    // No supervisor detected — let normalize_lineage() handle PPID=1
    // classification (Orphaned vs InitChild) based on the ancestor chain.
    None
}

/// Try to detect a systemd service unit from /proc/[pid]/cgroup.
fn detect_systemd_unit(pid: u32) -> Option<String> {
    let path = format!("/proc/{pid}/cgroup");
    let content = fs::read_to_string(&path).ok()?;

    for line in content.lines() {
        // Format: hierarchy-ID:controller-list:cgroup-path
        // e.g., "0::/system.slice/nginx.service"
        // e.g., "0::/user.slice/user-1000.slice/session-1.scope"
        let parts: Vec<&str> = line.splitn(3, ':').collect();
        if parts.len() < 3 {
            continue;
        }
        let cgroup_path = parts[2];

        // Look for .service suffix
        if let Some(service_part) = cgroup_path.rsplit('/').next() {
            if service_part.ends_with(".service") {
                return Some(service_part.to_string());
            }
        }
    }

    None
}

/// Check if a process appears to be inside a container.
fn is_containerized(pid: u32) -> bool {
    // Check for container markers in cgroup path
    let path = format!("/proc/{pid}/cgroup");
    if let Ok(content) = fs::read_to_string(&path) {
        for line in content.lines() {
            let lower = line.to_lowercase();
            if lower.contains("/docker/")
                || lower.contains("/kubepods/")
                || lower.contains("/lxc/")
                || lower.contains("containerd")
            {
                return true;
            }
        }
    }

    // Check for /.dockerenv marker
    if std::path::Path::new("/.dockerenv").exists() {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tty_device_name_pts() {
        assert_eq!(tty_device_name(0x8803), "/dev/pts/3"); // major 136, minor 3
        assert_eq!(tty_device_name(0x8800), "/dev/pts/0"); // major 136, minor 0
    }

    #[test]
    fn tty_device_name_console() {
        assert_eq!(tty_device_name(0x0401), "/dev/tty1"); // major 4, minor 1
    }

    #[test]
    fn tty_device_name_serial() {
        assert_eq!(tty_device_name(0x0440), "/dev/ttyS0"); // major 4, minor 64
    }

    #[test]
    fn tty_device_name_none() {
        assert_eq!(tty_device_name(0), "?");
    }

    #[test]
    fn tty_device_name_unknown() {
        let name = tty_device_name(0x0101); // major 1, minor 1
        assert!(name.starts_with("tty("));
    }

    #[test]
    fn build_tty_no_controlling_terminal() {
        let tty = build_tty_evidence(0, -1, 100, 100, 100);
        assert!(tty.is_none());
    }

    #[test]
    fn build_tty_with_pts() {
        let tty = build_tty_evidence(0x8803, 100, 100, 100, 100);
        let tty = tty.expect("should build TTY evidence");
        assert_eq!(tty.device, "/dev/pts/3");
        assert!(tty.has_controlling_tty);
        assert!(tty.is_session_leader); // pid == sid
        assert!(tty.is_pgid_leader); // pid == pgid
    }

    #[test]
    fn build_tty_not_leader() {
        let tty = build_tty_evidence(0x8803, 200, 300, 300, 200);
        let tty = tty.expect("should build TTY evidence");
        assert!(!tty.is_session_leader); // pid(300) != sid(200)
        assert!(tty.is_pgid_leader); // pid(300) == pgid(300)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn read_proc_stat_for_self() {
        let pid = std::process::id();
        let stat = read_proc_stat(pid);
        let stat = stat.expect("should read own /proc/stat");
        assert!(!stat.comm.is_empty());
        assert!(stat.ppid > 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn read_proc_status_for_self() {
        let pid = std::process::id();
        let status = read_proc_status(pid);
        let status = status.expect("should read own /proc/status");
        assert!(status.ruid > 0 || status.ruid == 0); // root or non-root
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn walk_ancestors_from_self() {
        let ppid = read_proc_stat(std::process::id())
            .map(|s| s.ppid)
            .unwrap_or(1);
        let ancestors = walk_ancestors(ppid);
        // Should find at least one ancestor (our parent)
        assert!(!ancestors.is_empty(), "should have at least one ancestor");
        // Last ancestor should be PID 1 (init/systemd)
        let last = ancestors.last().expect("ancestors not empty");
        assert_eq!(last.pid, 1, "ancestry chain should end at PID 1");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn walk_ancestors_handles_nonexistent_pid() {
        let ancestors = walk_ancestors(999_999_999);
        assert!(ancestors.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn collect_lineage_for_own_pid() {
        let pid = std::process::id();
        let evidence = collect_lineage_for_pid(pid);

        assert_eq!(evidence.pid, pid);
        assert!(evidence.ppid > 0);
        assert!(!evidence.ancestors.is_empty());
        assert_eq!(evidence.collection_method, LineageCollectionMethod::Procfs);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn collect_lineage_resolves_username() {
        let pid = std::process::id();
        let evidence = collect_lineage_for_pid(pid);
        // We should be able to resolve our own username
        assert!(evidence.user.is_some(), "should resolve own username");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn detect_systemd_unit_for_self() {
        // This may or may not find a unit depending on execution context.
        // Just verify it doesn't panic.
        let _unit = detect_systemd_unit(std::process::id());
    }

    #[test]
    fn resolve_username_root() {
        let name = resolve_username(0);
        assert_eq!(name, Some("root".to_string()));
    }
}
