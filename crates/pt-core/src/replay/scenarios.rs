//! Pre-built replay scenarios for testing and demonstration.
//!
//! Each function returns a `ReplaySnapshot` containing a realistic process
//! mix representing a common situation. These are designed for:
//!
//! - Regression testing with known expected outcomes
//! - Demonstrations without live processes
//! - Bug reproduction templates
//! - Documentation examples

use super::snapshot::{DeepSignalRecord, ReplayMetadata, ReplaySnapshot, SystemContext};
use crate::collect::{ProcessRecord, ProcessState};
use pt_common::{ProcessId, StartId};
use std::collections::HashMap;
use std::time::Duration;

/// Mock boot ID for scenario processes.
const SCENARIO_BOOT_ID: &str = "00000000-0000-0000-0000-000000000001";

/// Helper: build a process record with minimal boilerplate.
struct ProcBuilder {
    rec: ProcessRecord,
}

impl ProcBuilder {
    fn new(pid: u32, comm: &str, cmd: &str) -> Self {
        Self {
            rec: ProcessRecord {
                pid: ProcessId(pid),
                ppid: ProcessId(1),
                uid: 1000,
                user: "user".to_string(),
                pgid: Some(pid),
                sid: Some(pid),
                start_id: StartId::from_linux(SCENARIO_BOOT_ID, 1234567890, pid),
                comm: comm.to_string(),
                cmd: cmd.to_string(),
                state: ProcessState::Sleeping,
                cpu_percent: 0.0,
                rss_bytes: 10 * 1024 * 1024,
                vsz_bytes: 50 * 1024 * 1024,
                tty: None,
                start_time_unix: chrono::Utc::now().timestamp() - 3600,
                elapsed: Duration::from_secs(3600),
                source: "scenario".to_string(),
                container_info: None,
            },
        }
    }

    fn ppid(mut self, ppid: u32) -> Self {
        self.rec.ppid = ProcessId(ppid);
        self
    }

    fn state(mut self, state: ProcessState) -> Self {
        self.rec.state = state;
        self
    }

    fn cpu(mut self, percent: f64) -> Self {
        self.rec.cpu_percent = percent;
        self
    }

    fn rss(mut self, bytes: u64) -> Self {
        self.rec.rss_bytes = bytes;
        self
    }

    fn elapsed_secs(mut self, secs: u64) -> Self {
        self.rec.elapsed = Duration::from_secs(secs);
        self.rec.start_time_unix = chrono::Utc::now().timestamp() - secs as i64;
        self
    }

    fn tty(mut self, tty: Option<&str>) -> Self {
        self.rec.tty = tty.map(|s| s.to_string());
        self
    }

    fn build(self) -> ProcessRecord {
        self.rec
    }
}

/// Helper: current timestamp string.
fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Helper: build a snapshot from a list of processes.
fn build_scenario(
    name: &str,
    description: &str,
    processes: Vec<crate::collect::ProcessRecord>,
    deep_signals: HashMap<u32, DeepSignalRecord>,
) -> ReplaySnapshot {
    ReplaySnapshot {
        schema_version: super::snapshot::REPLAY_SCHEMA_VERSION.to_string(),
        name: name.to_string(),
        description: Some(description.to_string()),
        context: SystemContext {
            hostname_hash: Some("scenario-host".to_string()),
            boot_id: Some("00000000-0000-0000-0000-000000000001".to_string()),
            recorded_at: now_rfc3339(),
            platform: "linux".to_string(),
            total_memory_bytes: Some(16 * 1024 * 1024 * 1024), // 16 GB
            cpu_count: Some(8),
        },
        scan_metadata: ReplayMetadata {
            scan_type: "scenario".to_string(),
            duration_ms: 0,
            process_count: processes.len(),
            warnings: vec![],
        },
        processes,
        deep_signals,
    }
}

/// Scenario: Multiple stuck test runners consuming resources.
///
/// Simulates a CI environment where test processes have hung:
/// - 3 stuck pytest processes (high CPU, long runtime, no TTY)
/// - 2 stuck cargo test processes
/// - 1 active webserver (should not be killed)
/// - 1 idle editor (should be kept)
pub fn stuck_tests() -> ReplaySnapshot {
    let mut deep = HashMap::new();

    let processes = vec![
        // Stuck pytest #1 - high CPU, been running 4 hours
        ProcBuilder::new(
            10001,
            "python3",
            "python3 -m pytest tests/ -v --timeout=300",
        )
        .ppid(1)
        .state(ProcessState::Running)
        .cpu(95.0)
        .rss(512 * 1024 * 1024) // 512 MB
        .elapsed_secs(4 * 3600)
        .build(),
        // Stuck pytest #2
        ProcBuilder::new(10002, "python3", "python3 -m pytest tests/integration/ -x")
            .ppid(1)
            .state(ProcessState::Running)
            .cpu(88.0)
            .rss(384 * 1024 * 1024)
            .elapsed_secs(3 * 3600)
            .build(),
        // Stuck pytest #3 - sleeping (deadlock)
        ProcBuilder::new(
            10003,
            "python3",
            "python3 -m pytest tests/slow/ --no-header",
        )
        .ppid(1)
        .state(ProcessState::Sleeping)
        .cpu(0.0)
        .rss(256 * 1024 * 1024)
        .elapsed_secs(6 * 3600)
        .build(),
        // Stuck cargo test #1
        ProcBuilder::new(10004, "cargo", "cargo test --release -- --test-threads=1")
            .ppid(1)
            .state(ProcessState::Running)
            .cpu(100.0)
            .rss(1024 * 1024 * 1024) // 1 GB
            .elapsed_secs(2 * 3600)
            .build(),
        // Stuck cargo test #2
        ProcBuilder::new(
            10005,
            "test_runner",
            "/target/release/deps/integration_tests-abc123",
        )
        .ppid(10004)
        .state(ProcessState::DiskSleep)
        .cpu(0.0)
        .rss(768 * 1024 * 1024)
        .elapsed_secs(2 * 3600)
        .build(),
        // Active webserver - should NOT be killed
        ProcBuilder::new(10006, "nginx", "nginx: worker process")
            .ppid(1)
            .state(ProcessState::Sleeping)
            .cpu(2.0)
            .rss(32 * 1024 * 1024)
            .elapsed_secs(72 * 3600)
            .build(),
        // Idle editor - should be kept
        ProcBuilder::new(10007, "vim", "vim src/main.rs")
            .ppid(1000)
            .state(ProcessState::Sleeping)
            .cpu(0.0)
            .rss(16 * 1024 * 1024)
            .elapsed_secs(3600)
            .tty(Some("pts/0"))
            .build(),
    ];

    // Deep signals: test runners have no network; webserver does
    deep.insert(
        10001,
        DeepSignalRecord {
            net_active: Some(false),
            io_active: Some(false),
        },
    );
    deep.insert(
        10006,
        DeepSignalRecord {
            net_active: Some(true),
            io_active: Some(true),
        },
    );

    build_scenario(
        "stuck_tests",
        "Multiple stuck test runners consuming resources. Expected: tests recommended for kill, webserver and editor kept.",
        processes,
        deep,
    )
}

/// Scenario: Process with gradual memory growth (memory leak).
///
/// Simulates a memory-leaking service:
/// - 1 leaking web app (growing RSS over days)
/// - 1 normal database process
/// - 2 healthy worker processes
pub fn memory_leak() -> ReplaySnapshot {
    let mut deep = HashMap::new();

    let processes = vec![
        // Leaking web app - massive RSS, been running 5 days
        ProcBuilder::new(20001, "node", "node /app/server.js")
            .ppid(1)
            .state(ProcessState::Sleeping)
            .cpu(15.0)
            .rss(8 * 1024 * 1024 * 1024) // 8 GB
            .elapsed_secs(5 * 86400)
            .build(),
        // Normal database
        ProcBuilder::new(20002, "postgres", "postgres: main process")
            .ppid(1)
            .state(ProcessState::Sleeping)
            .cpu(5.0)
            .rss(512 * 1024 * 1024)
            .elapsed_secs(30 * 86400)
            .build(),
        // Worker 1 - healthy
        ProcBuilder::new(20003, "node", "node /app/worker.js")
            .ppid(20001)
            .state(ProcessState::Sleeping)
            .cpu(3.0)
            .rss(128 * 1024 * 1024)
            .elapsed_secs(5 * 86400)
            .build(),
        // Worker 2 - healthy
        ProcBuilder::new(20004, "node", "node /app/worker.js")
            .ppid(20001)
            .state(ProcessState::Sleeping)
            .cpu(2.0)
            .rss(96 * 1024 * 1024)
            .elapsed_secs(5 * 86400)
            .build(),
    ];

    deep.insert(
        20001,
        DeepSignalRecord {
            net_active: Some(true),
            io_active: Some(true),
        },
    );
    deep.insert(
        20002,
        DeepSignalRecord {
            net_active: Some(true),
            io_active: Some(true),
        },
    );

    build_scenario(
        "memory_leak",
        "Web application with gradual memory growth (8GB RSS after 5 days). Workers healthy.",
        processes,
        deep,
    )
}

/// Scenario: Orphaned process tree (zombie tree).
///
/// Simulates a tree of zombies from a crashed parent:
/// - 1 zombie parent
/// - 4 zombie children
/// - 1 orphaned child (reparented to init)
/// - 2 normal background services
pub fn zombie_tree() -> ReplaySnapshot {
    let processes = vec![
        // Zombie parent - crashed build system
        ProcBuilder::new(30001, "make", "make -j8 all")
            .ppid(1)
            .state(ProcessState::Zombie)
            .cpu(0.0)
            .rss(0)
            .elapsed_secs(2 * 3600)
            .build(),
        // Zombie child 1
        ProcBuilder::new(30002, "cc1", "cc1 -O2 src/module1.c")
            .ppid(30001)
            .state(ProcessState::Zombie)
            .cpu(0.0)
            .rss(0)
            .elapsed_secs(2 * 3600)
            .build(),
        // Zombie child 2
        ProcBuilder::new(30003, "cc1", "cc1 -O2 src/module2.c")
            .ppid(30001)
            .state(ProcessState::Zombie)
            .cpu(0.0)
            .rss(0)
            .elapsed_secs(2 * 3600)
            .build(),
        // Zombie child 3
        ProcBuilder::new(30004, "ld", "ld -o output src/module1.o src/module2.o")
            .ppid(30001)
            .state(ProcessState::Zombie)
            .cpu(0.0)
            .rss(0)
            .elapsed_secs(2 * 3600)
            .build(),
        // Zombie child 4
        ProcBuilder::new(30005, "as", "as -o src/startup.o src/startup.s")
            .ppid(30001)
            .state(ProcessState::Zombie)
            .cpu(0.0)
            .rss(0)
            .elapsed_secs(2 * 3600)
            .build(),
        // Orphaned child (reparented to init)
        ProcBuilder::new(30006, "sleep", "sleep infinity")
            .ppid(1)
            .state(ProcessState::Sleeping)
            .cpu(0.0)
            .rss(4 * 1024 * 1024)
            .elapsed_secs(2 * 3600)
            .build(),
        // Normal service 1
        ProcBuilder::new(30007, "sshd", "/usr/sbin/sshd -D")
            .ppid(1)
            .state(ProcessState::Sleeping)
            .cpu(0.0)
            .rss(8 * 1024 * 1024)
            .elapsed_secs(30 * 86400)
            .build(),
        // Normal service 2
        ProcBuilder::new(30008, "cron", "/usr/sbin/cron -f")
            .ppid(1)
            .state(ProcessState::Sleeping)
            .cpu(0.0)
            .rss(4 * 1024 * 1024)
            .elapsed_secs(30 * 86400)
            .build(),
    ];

    build_scenario(
        "zombie_tree",
        "Orphaned process tree from crashed build system. 5 zombies + 1 orphan, 2 normal services.",
        processes,
        HashMap::new(),
    )
}

/// Scenario: Typical CI build environment with diverse process types.
pub fn ci_build() -> ReplaySnapshot {
    let mut deep = HashMap::new();

    let processes = vec![
        // CI agent
        ProcBuilder::new(40001, "gitlab-runner", "gitlab-runner run")
            .ppid(1)
            .state(ProcessState::Sleeping)
            .cpu(1.0)
            .rss(64 * 1024 * 1024)
            .elapsed_secs(86400)
            .build(),
        // Active build
        ProcBuilder::new(40002, "cargo", "cargo build --release")
            .ppid(40001)
            .state(ProcessState::Running)
            .cpu(100.0)
            .rss(2 * 1024 * 1024 * 1024)
            .elapsed_secs(600)
            .build(),
        // Completed test (zombie)
        ProcBuilder::new(40003, "pytest", "python3 -m pytest tests/")
            .ppid(40001)
            .state(ProcessState::Zombie)
            .cpu(0.0)
            .rss(0)
            .elapsed_secs(1200)
            .build(),
        // Docker daemon
        ProcBuilder::new(
            40004,
            "dockerd",
            "/usr/bin/dockerd -H unix:///var/run/docker.sock",
        )
        .ppid(1)
        .state(ProcessState::Sleeping)
        .cpu(0.5)
        .rss(128 * 1024 * 1024)
        .elapsed_secs(7 * 86400)
        .build(),
        // Stale container process
        ProcBuilder::new(40005, "containerd-shim", "containerd-shim -namespace moby")
            .ppid(40004)
            .state(ProcessState::Sleeping)
            .cpu(0.0)
            .rss(16 * 1024 * 1024)
            .elapsed_secs(3 * 86400)
            .build(),
        // Log collector
        ProcBuilder::new(
            40006,
            "filebeat",
            "/usr/share/filebeat/bin/filebeat -c /etc/filebeat.yml",
        )
        .ppid(1)
        .state(ProcessState::Sleeping)
        .cpu(2.0)
        .rss(64 * 1024 * 1024)
        .elapsed_secs(7 * 86400)
        .build(),
    ];

    deep.insert(
        40001,
        DeepSignalRecord {
            net_active: Some(true),
            io_active: Some(true),
        },
    );
    deep.insert(
        40004,
        DeepSignalRecord {
            net_active: Some(true),
            io_active: Some(true),
        },
    );

    build_scenario(
        "ci_build",
        "Typical CI environment: active build, stale zombie, docker daemon, log collector.",
        processes,
        deep,
    )
}

/// Scenario: Developer workstation with typical mixed workload.
pub fn dev_machine() -> ReplaySnapshot {
    let mut deep = HashMap::new();

    let processes = vec![
        // Editor
        ProcBuilder::new(50001, "code", "/usr/share/code/code --type=gpu-process")
            .ppid(1000)
            .state(ProcessState::Sleeping)
            .cpu(8.0)
            .rss(512 * 1024 * 1024)
            .elapsed_secs(8 * 3600)
            .build(),
        // Terminal
        ProcBuilder::new(50002, "bash", "-bash")
            .ppid(1000)
            .state(ProcessState::Sleeping)
            .cpu(0.0)
            .rss(8 * 1024 * 1024)
            .elapsed_secs(8 * 3600)
            .tty(Some("pts/0"))
            .build(),
        // Dev server
        ProcBuilder::new(50003, "node", "next dev")
            .ppid(50002)
            .state(ProcessState::Sleeping)
            .cpu(5.0)
            .rss(256 * 1024 * 1024)
            .elapsed_secs(2 * 3600)
            .build(),
        // Background music player
        ProcBuilder::new(50004, "spotify", "spotify --enable-audio-backend")
            .ppid(1000)
            .state(ProcessState::Sleeping)
            .cpu(3.0)
            .rss(384 * 1024 * 1024)
            .elapsed_secs(4 * 3600)
            .build(),
        // Forgotten dev server from yesterday
        ProcBuilder::new(50005, "python3", "python3 manage.py runserver 8000")
            .ppid(1)
            .state(ProcessState::Sleeping)
            .cpu(0.0)
            .rss(128 * 1024 * 1024)
            .elapsed_secs(24 * 3600)
            .build(),
        // Orphaned npm install
        ProcBuilder::new(50006, "npm", "npm install --legacy-peer-deps")
            .ppid(1)
            .state(ProcessState::Sleeping)
            .cpu(0.0)
            .rss(64 * 1024 * 1024)
            .elapsed_secs(12 * 3600)
            .build(),
        // Docker
        ProcBuilder::new(50007, "dockerd", "/usr/bin/dockerd")
            .ppid(1)
            .state(ProcessState::Sleeping)
            .cpu(0.5)
            .rss(96 * 1024 * 1024)
            .elapsed_secs(8 * 3600)
            .build(),
    ];

    deep.insert(
        50003,
        DeepSignalRecord {
            net_active: Some(true),
            io_active: Some(true),
        },
    );
    deep.insert(
        50005,
        DeepSignalRecord {
            net_active: Some(false),
            io_active: Some(false),
        },
    );
    deep.insert(
        50006,
        DeepSignalRecord {
            net_active: Some(false),
            io_active: Some(false),
        },
    );

    build_scenario(
        "dev_machine",
        "Developer workstation: editor, terminal, dev server, forgotten processes, orphaned npm.",
        processes,
        deep,
    )
}

/// Scenario: Mixed workload with various process types for comprehensive testing.
pub fn mixed_workload() -> ReplaySnapshot {
    let mut deep = HashMap::new();

    let processes = vec![
        // Healthy web server
        ProcBuilder::new(60001, "nginx", "nginx: master process /usr/sbin/nginx")
            .ppid(1)
            .state(ProcessState::Sleeping)
            .cpu(0.5)
            .rss(16 * 1024 * 1024)
            .elapsed_secs(90 * 86400)
            .build(),
        // Healthy database
        ProcBuilder::new(60002, "postgres", "postgres: checkpointer")
            .ppid(1)
            .state(ProcessState::Sleeping)
            .cpu(2.0)
            .rss(256 * 1024 * 1024)
            .elapsed_secs(90 * 86400)
            .build(),
        // Abandoned batch job
        ProcBuilder::new(60003, "python3", "python3 batch_export.py --once")
            .ppid(1)
            .state(ProcessState::Sleeping)
            .cpu(0.0)
            .rss(32 * 1024 * 1024)
            .elapsed_secs(7 * 86400)
            .build(),
        // Zombie
        ProcBuilder::new(60004, "defunct", "[nginx] <defunct>")
            .ppid(60001)
            .state(ProcessState::Zombie)
            .cpu(0.0)
            .rss(0)
            .elapsed_secs(86400)
            .build(),
        // CPU hog (useful but resource-heavy)
        ProcBuilder::new(
            60005,
            "ffmpeg",
            "ffmpeg -i input.mp4 -c:v libx264 output.mp4",
        )
        .ppid(1)
        .state(ProcessState::Running)
        .cpu(100.0)
        .rss(512 * 1024 * 1024)
        .elapsed_secs(1800)
        .tty(Some("pts/1"))
        .build(),
        // Stopped process
        ProcBuilder::new(60006, "vim", "vim config.yaml")
            .ppid(1000)
            .state(ProcessState::Stopped)
            .cpu(0.0)
            .rss(12 * 1024 * 1024)
            .elapsed_secs(3600)
            .tty(Some("pts/2"))
            .build(),
        // Short-lived process (just started)
        ProcBuilder::new(60007, "ls", "ls -la /tmp")
            .ppid(50002)
            .state(ProcessState::Running)
            .cpu(10.0)
            .rss(4 * 1024 * 1024)
            .elapsed_secs(1)
            .tty(Some("pts/0"))
            .build(),
    ];

    deep.insert(
        60001,
        DeepSignalRecord {
            net_active: Some(true),
            io_active: Some(true),
        },
    );
    deep.insert(
        60002,
        DeepSignalRecord {
            net_active: Some(true),
            io_active: Some(true),
        },
    );
    deep.insert(
        60003,
        DeepSignalRecord {
            net_active: Some(false),
            io_active: Some(false),
        },
    );

    build_scenario(
        "mixed_workload",
        "Mixed: healthy server/db, abandoned batch job, zombie, CPU hog, stopped editor, short-lived process.",
        processes,
        deep,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::priors::Priors;
    use crate::config::Policy;
    use crate::replay::replay_inference;

    #[test]
    fn test_stuck_tests_scenario() {
        let snapshot = stuck_tests();
        assert_eq!(snapshot.name, "stuck_tests");
        assert_eq!(snapshot.processes.len(), 7);
        assert!(!snapshot.deep_signals.is_empty());
    }

    #[test]
    fn test_memory_leak_scenario() {
        let snapshot = memory_leak();
        assert_eq!(snapshot.name, "memory_leak");
        assert_eq!(snapshot.processes.len(), 4);
    }

    #[test]
    fn test_zombie_tree_scenario() {
        let snapshot = zombie_tree();
        assert_eq!(snapshot.name, "zombie_tree");
        assert_eq!(snapshot.processes.len(), 8);

        // Count zombies
        let zombie_count = snapshot
            .processes
            .iter()
            .filter(|p| p.state == ProcessState::Zombie)
            .count();
        assert_eq!(zombie_count, 5);
    }

    #[test]
    fn test_ci_build_scenario() {
        let snapshot = ci_build();
        assert_eq!(snapshot.name, "ci_build");
        assert_eq!(snapshot.processes.len(), 6);
    }

    #[test]
    fn test_dev_machine_scenario() {
        let snapshot = dev_machine();
        assert_eq!(snapshot.name, "dev_machine");
        assert_eq!(snapshot.processes.len(), 7);
    }

    #[test]
    fn test_mixed_workload_scenario() {
        let snapshot = mixed_workload();
        assert_eq!(snapshot.name, "mixed_workload");
        assert_eq!(snapshot.processes.len(), 7);
    }

    #[test]
    fn test_all_scenarios_replay() {
        let priors = Priors::default();
        let policy = Policy::default();

        for scenario_fn in [
            stuck_tests,
            memory_leak,
            zombie_tree,
            ci_build,
            dev_machine,
            mixed_workload,
        ] {
            let snapshot = scenario_fn();
            let results = replay_inference(&snapshot, &priors, &policy)
                .unwrap_or_else(|e| panic!("replay failed for {}: {}", snapshot.name, e));

            assert_eq!(
                results.len(),
                snapshot.processes.len(),
                "result count mismatch for {}",
                snapshot.name
            );

            for r in &results {
                assert!(
                    !r.classification.is_empty(),
                    "empty classification in {}",
                    snapshot.name
                );
                assert!(
                    r.expected_loss.is_finite(),
                    "non-finite loss in {} for PID {}",
                    snapshot.name,
                    r.pid
                );
            }
        }
    }

    #[test]
    fn test_scenarios_serialize_roundtrip() {
        for scenario_fn in [
            stuck_tests,
            memory_leak,
            zombie_tree,
            ci_build,
            dev_machine,
            mixed_workload,
        ] {
            let snapshot = scenario_fn();
            let json = serde_json::to_string(&snapshot).unwrap();
            let loaded: ReplaySnapshot = serde_json::from_str(&json).unwrap();
            assert_eq!(loaded.processes.len(), snapshot.processes.len());
            assert_eq!(loaded.name, snapshot.name);
        }
    }
}
