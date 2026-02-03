//! Blast radius analysis for process termination safety.
//!
//! Estimates the downstream impact of killing a process by examining:
//! - Child process subtree (PPID descendants)
//! - Listening ports that would become unavailable
//! - Open write file handles (locks, WAL/journals, databases)
//!
//! Produces a structured `BlastRadius` with a cumulative risk score
//! and human-readable summary.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Risk factor contributing to blast radius.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    pub category: RiskCategory,
    pub description: String,
    pub weight: f64,
}

/// Category of risk factor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskCategory {
    Children,
    ListenPort,
    WriteHandle,
    Database,
    Lock,
    Other,
}

impl RiskCategory {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Children => "child processes",
            Self::ListenPort => "listening port",
            Self::WriteHandle => "write handle",
            Self::Database => "database file",
            Self::Lock => "lock file",
            Self::Other => "other",
        }
    }
}

/// Information about a child process in the subtree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChildProcess {
    pub pid: u32,
    pub comm: String,
    /// Depth relative to target (1 = direct child, 2 = grandchild, …).
    pub depth: u32,
}

/// Information about a listening port.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListeningPort {
    pub port: u16,
    pub protocol: String,
    pub address: String,
}

/// Information about an open write handle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteHandle {
    pub fd: u32,
    pub path: String,
    pub is_critical: bool,
}

/// Complete blast radius analysis result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlastRadius {
    pub target_pid: u32,
    pub children: Vec<ChildProcess>,
    pub listen_ports: Vec<ListeningPort>,
    pub write_handles: Vec<WriteHandle>,
    pub risk_factors: Vec<RiskFactor>,
    /// Cumulative risk score (0.0 = safe, higher = riskier).
    pub risk_score: f64,
    /// Human-readable summary.
    pub summary: String,
}

/// Input data for blast radius computation (avoids direct /proc access).
#[derive(Debug, Clone, Default)]
pub struct BlastRadiusInput {
    pub target_pid: u32,
    pub target_comm: String,
    /// Map of PID → (comm, ppid) for all known processes.
    pub process_table: HashMap<u32, (String, u32)>,
    /// Listening ports held by the target process.
    pub listen_ports: Vec<ListeningPort>,
    /// Open files with write mode for the target process.
    pub open_write_files: Vec<(u32, String)>,
    /// Paths flagged as critical writes.
    pub critical_paths: Vec<String>,
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------

/// Compute the blast radius for a process.
pub fn compute_blast_radius(input: &BlastRadiusInput) -> BlastRadius {
    let children = enumerate_children(input.target_pid, &input.process_table);
    let write_handles = build_write_handles(&input.open_write_files, &input.critical_paths);

    let mut risk_factors = Vec::new();
    let mut risk_score = 0.0;

    // Child process risk.
    if !children.is_empty() {
        let child_weight = (children.len() as f64).ln_1p() * 0.5;
        risk_score += child_weight;
        risk_factors.push(RiskFactor {
            category: RiskCategory::Children,
            description: format!("{} child process(es) would be orphaned", children.len()),
            weight: child_weight,
        });
    }

    // Listening port risk.
    for port in &input.listen_ports {
        let port_weight = if port.port < 1024 { 2.0 } else { 1.0 };
        risk_score += port_weight;
        risk_factors.push(RiskFactor {
            category: RiskCategory::ListenPort,
            description: format!("serves {}:{} ({})", port.address, port.port, port.protocol),
            weight: port_weight,
        });
    }

    // Write handle risk.
    for wh in &write_handles {
        let (category, weight) = categorize_write_handle(&wh.path, wh.is_critical);
        risk_score += weight;
        risk_factors.push(RiskFactor {
            category,
            description: format!("open write on {}", wh.path),
            weight,
        });
    }

    let summary = build_summary(&children, &input.listen_ports, &write_handles, risk_score);

    BlastRadius {
        target_pid: input.target_pid,
        children,
        listen_ports: input.listen_ports.clone(),
        write_handles,
        risk_factors,
        risk_score,
        summary,
    }
}

/// Walk the process table to find all descendants of `pid`.
fn enumerate_children(pid: u32, table: &HashMap<u32, (String, u32)>) -> Vec<ChildProcess> {
    let mut result = Vec::new();
    let mut queue: Vec<(u32, u32)> = Vec::new(); // (pid, depth)

    // Find direct children.
    for (&child_pid, &(ref comm, ppid)) in table {
        if ppid == pid && child_pid != pid {
            queue.push((child_pid, 1));
            result.push(ChildProcess {
                pid: child_pid,
                comm: comm.clone(),
                depth: 1,
            });
        }
    }

    // BFS for deeper descendants.
    let mut head = 0;
    while head < queue.len() {
        let (parent, depth) = queue[head];
        head += 1;

        for (&child_pid, &(ref comm, ppid)) in table {
            if ppid == parent && child_pid != parent {
                // Avoid duplicates.
                if result.iter().any(|c| c.pid == child_pid) {
                    continue;
                }
                queue.push((child_pid, depth + 1));
                result.push(ChildProcess {
                    pid: child_pid,
                    comm: comm.clone(),
                    depth: depth + 1,
                });
            }
        }
    }

    // Sort by depth then PID for determinism.
    result.sort_by(|a, b| a.depth.cmp(&b.depth).then(a.pid.cmp(&b.pid)));
    result
}

fn build_write_handles(
    open_files: &[(u32, String)],
    critical_paths: &[String],
) -> Vec<WriteHandle> {
    open_files
        .iter()
        .map(|(fd, path)| {
            let is_critical = critical_paths.iter().any(|cp| path.contains(cp));
            WriteHandle {
                fd: *fd,
                path: path.clone(),
                is_critical,
            }
        })
        .collect()
}

fn categorize_write_handle(path: &str, is_critical: bool) -> (RiskCategory, f64) {
    let p = path.to_lowercase();
    if p.ends_with(".db")
        || p.ends_with(".sqlite")
        || p.ends_with(".sqlite3")
        || p.contains("-wal")
        || p.contains("-journal")
    {
        (RiskCategory::Database, 3.0)
    } else if p.ends_with(".lock") || p.ends_with(".pid") || p.contains("/lock") {
        (RiskCategory::Lock, 2.0)
    } else if is_critical {
        (RiskCategory::WriteHandle, 2.0)
    } else {
        (RiskCategory::WriteHandle, 0.5)
    }
}

fn build_summary(
    children: &[ChildProcess],
    ports: &[ListeningPort],
    writes: &[WriteHandle],
    risk_score: f64,
) -> String {
    let mut parts = Vec::new();

    if !children.is_empty() {
        parts.push(format!("kills {} child(ren)", children.len()));
    }

    for wh in writes.iter().filter(|w| w.is_critical) {
        parts.push(format!("holds write lock on {}", wh.path));
    }

    for port in ports {
        parts.push(format!("serves port {}", port.port));
    }

    if parts.is_empty() {
        return format!("Minimal blast radius (risk score: {:.1}).", risk_score);
    }

    let risk_label = if risk_score > 5.0 {
        "HIGH"
    } else if risk_score > 2.0 {
        "MEDIUM"
    } else {
        "LOW"
    };

    format!(
        "{}. Risk: {} ({:.1}).",
        capitalise_first(&parts.join("; ")),
        risk_label,
        risk_score,
    )
}

fn capitalise_first(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) => c.to_uppercase().to_string() + chars.as_str(),
        None => String::new(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_table(entries: &[(u32, &str, u32)]) -> HashMap<u32, (String, u32)> {
        entries
            .iter()
            .map(|(pid, comm, ppid)| (*pid, (comm.to_string(), *ppid)))
            .collect()
    }

    #[test]
    fn test_no_blast_radius() {
        let input = BlastRadiusInput {
            target_pid: 100,
            target_comm: "app".to_string(),
            process_table: make_table(&[(100, "app", 1)]),
            ..Default::default()
        };
        let br = compute_blast_radius(&input);
        assert!(br.children.is_empty());
        assert!(br.listen_ports.is_empty());
        assert!(br.write_handles.is_empty());
        assert_eq!(br.risk_score, 0.0);
        assert!(br.summary.contains("Minimal"));
    }

    #[test]
    fn test_children_enumerated() {
        let input = BlastRadiusInput {
            target_pid: 100,
            target_comm: "supervisor".to_string(),
            process_table: make_table(&[
                (100, "supervisor", 1),
                (200, "worker1", 100),
                (201, "worker2", 100),
                (300, "subworker", 200),
            ]),
            ..Default::default()
        };
        let br = compute_blast_radius(&input);
        assert_eq!(br.children.len(), 3);
        assert_eq!(br.children[0].depth, 1); // worker1
        assert_eq!(br.children[1].depth, 1); // worker2
        assert_eq!(br.children[2].depth, 2); // subworker
    }

    #[test]
    fn test_listen_port_risk() {
        let input = BlastRadiusInput {
            target_pid: 100,
            target_comm: "nginx".to_string(),
            process_table: make_table(&[(100, "nginx", 1)]),
            listen_ports: vec![
                ListeningPort {
                    port: 80,
                    protocol: "tcp".to_string(),
                    address: "0.0.0.0".to_string(),
                },
                ListeningPort {
                    port: 8080,
                    protocol: "tcp".to_string(),
                    address: "127.0.0.1".to_string(),
                },
            ],
            ..Default::default()
        };
        let br = compute_blast_radius(&input);
        // Port 80 (privileged) = 2.0, port 8080 = 1.0
        assert!((br.risk_score - 3.0).abs() < 1e-9);
        assert!(br.summary.contains("port 80"));
    }

    #[test]
    fn test_write_handle_database_risk() {
        let input = BlastRadiusInput {
            target_pid: 100,
            target_comm: "app".to_string(),
            process_table: make_table(&[(100, "app", 1)]),
            open_write_files: vec![
                (3, "/var/data/app.db".to_string()),
                (4, "/tmp/scratch.log".to_string()),
            ],
            ..Default::default()
        };
        let br = compute_blast_radius(&input);
        // .db = 3.0, .log = 0.5
        assert!((br.risk_score - 3.5).abs() < 1e-9);
    }

    #[test]
    fn test_critical_path_detection() {
        let input = BlastRadiusInput {
            target_pid: 100,
            target_comm: "app".to_string(),
            process_table: make_table(&[(100, "app", 1)]),
            open_write_files: vec![(5, "/var/lib/myapp/data.bin".to_string())],
            critical_paths: vec!["/var/lib/myapp".to_string()],
            ..Default::default()
        };
        let br = compute_blast_radius(&input);
        assert!(br.write_handles[0].is_critical);
        assert!(br.summary.contains("write lock"));
    }

    #[test]
    fn test_lock_file_categorization() {
        let (cat, weight) = categorize_write_handle("/run/myapp.lock", false);
        assert_eq!(cat, RiskCategory::Lock);
        assert!((weight - 2.0).abs() < 1e-9);
    }

    #[test]
    fn test_combined_risk() {
        let input = BlastRadiusInput {
            target_pid: 100,
            target_comm: "server".to_string(),
            process_table: make_table(&[(100, "server", 1), (200, "worker", 100)]),
            listen_ports: vec![ListeningPort {
                port: 3000,
                protocol: "tcp".to_string(),
                address: "0.0.0.0".to_string(),
            }],
            open_write_files: vec![(3, "/data/app.sqlite3".to_string())],
            ..Default::default()
        };
        let br = compute_blast_radius(&input);
        // children: ln(2)*0.5 ≈ 0.347, port 3000: 1.0, sqlite3: 3.0
        assert!(br.risk_score > 4.0);
        assert!(br.summary.contains("MEDIUM") || br.summary.contains("HIGH"));
    }

    #[test]
    fn test_serialization() {
        let input = BlastRadiusInput {
            target_pid: 42,
            target_comm: "test".to_string(),
            process_table: make_table(&[(42, "test", 1), (43, "child", 42)]),
            ..Default::default()
        };
        let br = compute_blast_radius(&input);
        let json = serde_json::to_string(&br).unwrap();
        let restored: BlastRadius = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.target_pid, 42);
        assert_eq!(restored.children.len(), 1);
    }

    #[test]
    fn test_summary_format() {
        let input = BlastRadiusInput {
            target_pid: 100,
            target_comm: "app".to_string(),
            process_table: make_table(&[(100, "app", 1), (200, "w1", 100), (201, "w2", 100)]),
            listen_ports: vec![ListeningPort {
                port: 443,
                protocol: "tcp".to_string(),
                address: "0.0.0.0".to_string(),
            }],
            ..Default::default()
        };
        let br = compute_blast_radius(&input);
        assert!(br.summary.starts_with("Kills 2 child(ren)"));
        assert!(br.summary.contains("port 443"));
    }
}
