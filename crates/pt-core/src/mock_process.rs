//! Mock process generator for testing.
//!
//! This module provides builders and factories for creating mock `ProcessRecord`
//! and `ScanResult` instances for testing purposes. It supports:
//!
//! - Builder pattern for ergonomic test setup
//! - Deterministic generation via seed for reproducible tests
//! - Factory functions for common scenarios (zombies, orphans, etc.)
//!
//! # Example
//!
//! ```ignore
//! use pt_core::mock_process::{MockProcessBuilder, MockScanBuilder};
//!
//! // Build a single process
//! let zombie = MockProcessBuilder::new()
//!     .pid(1234)
//!     .comm("defunct")
//!     .state_zombie()
//!     .build();
//!
//! // Build a complete scan result
//! let scan = MockScanBuilder::new()
//!     .with_process(zombie)
//!     .with_zombie(5678)
//!     .with_orphan(9999, "node")
//!     .build();
//! ```

use crate::collect::{ProcessRecord, ProcessState, ScanMetadata, ScanResult};
use pt_common::{ProcessId, StartId};
use std::time::Duration;

/// Default mock boot ID for test processes.
const MOCK_BOOT_ID: &str = "00000000-0000-0000-0000-000000000000";

// ============================================================================
// Deterministic RNG
// ============================================================================

/// Simple linear congruential generator for deterministic "random" values.
///
/// This is NOT cryptographically secure - it's only for generating
/// reproducible test data.
#[derive(Debug, Clone)]
pub struct MockRng {
    state: u64,
}

impl MockRng {
    /// Create a new RNG with the given seed.
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Generate the next pseudo-random u64.
    pub fn next_u64(&mut self) -> u64 {
        // LCG parameters from Numerical Recipes
        self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1);
        self.state
    }

    /// Generate a pseudo-random u32.
    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    /// Generate a pseudo-random f64 in [0, 1).
    pub fn next_f64(&mut self) -> f64 {
        (self.next_u64() as f64) / (u64::MAX as f64)
    }

    /// Generate a pseudo-random value in [min, max].
    pub fn range(&mut self, min: u64, max: u64) -> u64 {
        min + (self.next_u64() % (max - min + 1))
    }

    /// Choose a random element from a slice.
    pub fn choose<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        let idx = (self.next_u64() as usize) % items.len();
        &items[idx]
    }
}

impl Default for MockRng {
    fn default() -> Self {
        Self::new(42)
    }
}

// ============================================================================
// MockProcessBuilder
// ============================================================================

/// Builder for creating mock `ProcessRecord` instances.
///
/// All fields have sensible defaults, so you only need to set the fields
/// relevant to your test case.
#[derive(Debug, Clone)]
pub struct MockProcessBuilder {
    pid: u32,
    ppid: u32,
    uid: u32,
    user: String,
    pgid: Option<u32>,
    sid: Option<u32>,
    start_id: StartId,
    comm: String,
    cmd: String,
    state: ProcessState,
    cpu_percent: f64,
    rss_bytes: u64,
    vsz_bytes: u64,
    tty: Option<String>,
    start_time_unix: i64,
    elapsed: Duration,
    source: String,
}

impl Default for MockProcessBuilder {
    fn default() -> Self {
        Self {
            pid: 1000,
            ppid: 1,
            uid: 1000,
            user: "testuser".to_string(),
            pgid: Some(1000),
            sid: Some(1000),
            start_id: StartId::from_linux(MOCK_BOOT_ID, 1234567890, 1000),
            comm: "test".to_string(),
            cmd: "/usr/bin/test --flag".to_string(),
            state: ProcessState::Sleeping,
            cpu_percent: 0.0,
            rss_bytes: 10 * 1024 * 1024, // 10 MB
            vsz_bytes: 50 * 1024 * 1024, // 50 MB
            tty: None,
            start_time_unix: chrono::Utc::now().timestamp() - 3600, // 1 hour ago
            elapsed: Duration::from_secs(3600),
            source: "mock".to_string(),
        }
    }
}

impl MockProcessBuilder {
    /// Create a new builder with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a builder with deterministic values from an RNG.
    pub fn from_rng(rng: &mut MockRng) -> Self {
        let pid = rng.range(100, 65535) as u32;
        let ppid = rng.range(1, 1000) as u32;
        let uid = rng.range(1000, 65534) as u32;
        let elapsed_secs = rng.range(60, 86400 * 7); // 1 min to 1 week

        let comms = ["bash", "python", "node", "java", "sleep", "cat", "grep"];
        let comm = rng.choose(&comms).to_string();

        Self {
            pid,
            ppid,
            uid,
            user: format!("user{}", uid),
            pgid: Some(pid),
            sid: Some(pid),
            start_id: StartId::from_linux(MOCK_BOOT_ID, rng.next_u64(), pid),
            comm: comm.clone(),
            cmd: format!("/usr/bin/{}", comm),
            state: ProcessState::Sleeping,
            cpu_percent: rng.next_f64() * 10.0,
            rss_bytes: rng.range(1024 * 1024, 1024 * 1024 * 1024), // 1 MB - 1 GB
            vsz_bytes: rng.range(10 * 1024 * 1024, 4 * 1024 * 1024 * 1024), // 10 MB - 4 GB
            tty: None,
            start_time_unix: chrono::Utc::now().timestamp() - (elapsed_secs as i64),
            elapsed: Duration::from_secs(elapsed_secs),
            source: "mock".to_string(),
        }
    }

    // === Identity setters ===

    /// Set the process ID.
    pub fn pid(mut self, pid: u32) -> Self {
        self.pid = pid;
        // Update start_id to match - create a new one with the same boot_id
        self.start_id = StartId::from_linux(MOCK_BOOT_ID, 1234567890, pid);
        self
    }

    /// Set the parent process ID.
    pub fn ppid(mut self, ppid: u32) -> Self {
        self.ppid = ppid;
        self
    }

    /// Set the user ID.
    pub fn uid(mut self, uid: u32) -> Self {
        self.uid = uid;
        self
    }

    /// Set the username.
    pub fn user(mut self, user: impl Into<String>) -> Self {
        self.user = user.into();
        self
    }

    /// Set the process group ID.
    pub fn pgid(mut self, pgid: u32) -> Self {
        self.pgid = Some(pgid);
        self
    }

    /// Set the session ID.
    pub fn sid(mut self, sid: u32) -> Self {
        self.sid = Some(sid);
        self
    }

    /// Set the start ID directly.
    pub fn start_id(mut self, start_id: StartId) -> Self {
        self.start_id = start_id;
        self
    }

    // === Command setters ===

    /// Set the command name.
    pub fn comm(mut self, comm: impl Into<String>) -> Self {
        self.comm = comm.into();
        self
    }

    /// Set the full command line.
    pub fn cmd(mut self, cmd: impl Into<String>) -> Self {
        self.cmd = cmd.into();
        self
    }

    // === State setters ===

    /// Set the process state.
    pub fn state(mut self, state: ProcessState) -> Self {
        self.state = state;
        self
    }

    /// Set state to Running.
    pub fn state_running(mut self) -> Self {
        self.state = ProcessState::Running;
        self
    }

    /// Set state to Sleeping.
    pub fn state_sleeping(mut self) -> Self {
        self.state = ProcessState::Sleeping;
        self
    }

    /// Set state to Zombie.
    pub fn state_zombie(mut self) -> Self {
        self.state = ProcessState::Zombie;
        self
    }

    /// Set state to Stopped.
    pub fn state_stopped(mut self) -> Self {
        self.state = ProcessState::Stopped;
        self
    }

    /// Set state to DiskSleep (D-state).
    pub fn state_disksleep(mut self) -> Self {
        self.state = ProcessState::DiskSleep;
        self
    }

    // === Resource setters ===

    /// Set CPU usage percentage.
    pub fn cpu_percent(mut self, cpu: f64) -> Self {
        self.cpu_percent = cpu;
        self
    }

    /// Set resident set size in bytes.
    pub fn rss_bytes(mut self, bytes: u64) -> Self {
        self.rss_bytes = bytes;
        self
    }

    /// Set RSS in megabytes (convenience method).
    pub fn rss_mb(mut self, mb: u64) -> Self {
        self.rss_bytes = mb * 1024 * 1024;
        self
    }

    /// Set virtual size in bytes.
    pub fn vsz_bytes(mut self, bytes: u64) -> Self {
        self.vsz_bytes = bytes;
        self
    }

    /// Set VSZ in megabytes (convenience method).
    pub fn vsz_mb(mut self, mb: u64) -> Self {
        self.vsz_bytes = mb * 1024 * 1024;
        self
    }

    // === Terminal setters ===

    /// Set the controlling terminal.
    pub fn tty(mut self, tty: impl Into<String>) -> Self {
        self.tty = Some(tty.into());
        self
    }

    /// Remove the controlling terminal.
    pub fn no_tty(mut self) -> Self {
        self.tty = None;
        self
    }

    // === Timing setters ===

    /// Set the start time as Unix timestamp.
    pub fn start_time_unix(mut self, ts: i64) -> Self {
        self.start_time_unix = ts;
        self
    }

    /// Set the elapsed time.
    pub fn elapsed(mut self, duration: Duration) -> Self {
        self.elapsed = duration;
        self
    }

    /// Set elapsed time in seconds (convenience method).
    pub fn elapsed_secs(mut self, secs: u64) -> Self {
        self.elapsed = Duration::from_secs(secs);
        self
    }

    /// Set elapsed time in hours (convenience method).
    pub fn elapsed_hours(mut self, hours: u64) -> Self {
        self.elapsed = Duration::from_secs(hours * 3600);
        self
    }

    /// Set elapsed time in days (convenience method).
    pub fn elapsed_days(mut self, days: u64) -> Self {
        self.elapsed = Duration::from_secs(days * 86400);
        self
    }

    // === Source setter ===

    /// Set the source field.
    pub fn source(mut self, source: impl Into<String>) -> Self {
        self.source = source.into();
        self
    }

    // === Scenario helpers ===

    /// Configure as an orphan process (PPID = 1).
    pub fn orphan(mut self) -> Self {
        self.ppid = 1;
        self.tty = None;
        self
    }

    /// Configure as a zombie process.
    pub fn zombie(mut self) -> Self {
        self.state = ProcessState::Zombie;
        self.cpu_percent = 0.0;
        self.comm = "<defunct>".to_string();
        self
    }

    /// Configure as a long-running test runner.
    pub fn test_runner(mut self, framework: &str) -> Self {
        self.comm = framework.to_string();
        self.cmd = match framework {
            "jest" => "node /project/node_modules/.bin/jest --watch".to_string(),
            "pytest" => "python -m pytest -v".to_string(),
            "cargo" => "cargo test --workspace".to_string(),
            "bun" => "bun test --watch".to_string(),
            _ => format!("{} test", framework),
        };
        self.elapsed = Duration::from_secs(7200); // 2 hours
        self.cpu_percent = 5.0;
        self
    }

    /// Configure as a dev server.
    pub fn dev_server(mut self, server_type: &str) -> Self {
        match server_type {
            "next" => {
                self.comm = "node".to_string();
                self.cmd = "node /project/.next/server.js".to_string();
            }
            "vite" => {
                self.comm = "node".to_string();
                self.cmd = "node /project/node_modules/.bin/vite --port 3000".to_string();
            }
            "webpack" => {
                self.comm = "node".to_string();
                self.cmd = "node webpack serve --hot".to_string();
            }
            "django" => {
                self.comm = "python".to_string();
                self.cmd = "python manage.py runserver".to_string();
            }
            _ => {
                self.cmd = format!("{} serve", server_type);
            }
        }
        self.elapsed = Duration::from_secs(3 * 86400); // 3 days
        self.cpu_percent = 2.0;
        self.rss_bytes = 200 * 1024 * 1024; // 200 MB
        self
    }

    /// Configure as an agent process.
    pub fn agent(mut self, agent_type: &str) -> Self {
        match agent_type {
            "claude" => {
                self.comm = "node".to_string();
                self.cmd = "node /home/user/.claude/claude-code".to_string();
            }
            "codex" => {
                self.comm = "python".to_string();
                self.cmd = "python -m codex.cli".to_string();
            }
            "copilot" => {
                self.comm = "node".to_string();
                self.cmd = "node copilot-agent".to_string();
            }
            _ => {
                self.cmd = format!("{}-agent", agent_type);
            }
        }
        self.elapsed = Duration::from_secs(2 * 86400); // 2 days
        self.cpu_percent = 0.5;
        self
    }

    /// Configure as a system service (should be protected).
    pub fn system_service(mut self, service: &str) -> Self {
        self.ppid = 1;
        self.uid = 0;
        self.user = "root".to_string();
        self.comm = service.to_string();
        self.cmd = format!("/usr/sbin/{}", service);
        self.elapsed = Duration::from_secs(30 * 86400); // 30 days
        self.cpu_percent = 0.1;
        self
    }

    // === Build ===

    /// Build the `ProcessRecord`.
    pub fn build(self) -> ProcessRecord {
        ProcessRecord {
            pid: ProcessId(self.pid),
            ppid: ProcessId(self.ppid),
            uid: self.uid,
            user: self.user,
            pgid: self.pgid,
            sid: self.sid,
            start_id: self.start_id,
            comm: self.comm,
            cmd: self.cmd,
            state: self.state,
            cpu_percent: self.cpu_percent,
            rss_bytes: self.rss_bytes,
            vsz_bytes: self.vsz_bytes,
            tty: self.tty,
            start_time_unix: self.start_time_unix,
            elapsed: self.elapsed,
            source: self.source,
            container_info: None,
        }
    }
}

// ============================================================================
// MockScanBuilder
// ============================================================================

/// Builder for creating mock `ScanResult` instances.
#[derive(Debug, Clone)]
pub struct MockScanBuilder {
    processes: Vec<ProcessRecord>,
    scan_type: String,
    platform: String,
    boot_id: Option<String>,
    warnings: Vec<String>,
    rng: MockRng,
}

impl Default for MockScanBuilder {
    fn default() -> Self {
        Self {
            processes: Vec::new(),
            scan_type: "mock".to_string(),
            platform: "linux".to_string(),
            boot_id: Some("mock-boot-id".to_string()),
            warnings: Vec::new(),
            rng: MockRng::default(),
        }
    }
}

impl MockScanBuilder {
    /// Create a new builder with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new builder with a specific seed for deterministic generation.
    pub fn with_seed(seed: u64) -> Self {
        Self {
            rng: MockRng::new(seed),
            ..Default::default()
        }
    }

    // === Process addition ===

    /// Add a pre-built process record.
    pub fn with_process(mut self, process: ProcessRecord) -> Self {
        self.processes.push(process);
        self
    }

    /// Add multiple pre-built process records.
    pub fn with_processes(mut self, processes: impl IntoIterator<Item = ProcessRecord>) -> Self {
        self.processes.extend(processes);
        self
    }

    /// Add a zombie process with the given PID.
    pub fn with_zombie(mut self, pid: u32) -> Self {
        let process = MockProcessBuilder::new().pid(pid).zombie().build();
        self.processes.push(process);
        self
    }

    /// Add an orphan process with the given PID and command.
    pub fn with_orphan(mut self, pid: u32, comm: &str) -> Self {
        let process = MockProcessBuilder::new()
            .pid(pid)
            .comm(comm)
            .orphan()
            .build();
        self.processes.push(process);
        self
    }

    /// Add a test runner process.
    pub fn with_test_runner(mut self, pid: u32, framework: &str) -> Self {
        let process = MockProcessBuilder::new()
            .pid(pid)
            .test_runner(framework)
            .build();
        self.processes.push(process);
        self
    }

    /// Add a dev server process.
    pub fn with_dev_server(mut self, pid: u32, server_type: &str) -> Self {
        let process = MockProcessBuilder::new()
            .pid(pid)
            .dev_server(server_type)
            .build();
        self.processes.push(process);
        self
    }

    /// Add an agent process.
    pub fn with_agent(mut self, pid: u32, agent_type: &str) -> Self {
        let process = MockProcessBuilder::new()
            .pid(pid)
            .agent(agent_type)
            .build();
        self.processes.push(process);
        self
    }

    /// Add a system service process.
    pub fn with_system_service(mut self, pid: u32, service: &str) -> Self {
        let process = MockProcessBuilder::new()
            .pid(pid)
            .system_service(service)
            .build();
        self.processes.push(process);
        self
    }

    /// Add N random processes using the internal RNG.
    pub fn with_random_processes(mut self, count: usize) -> Self {
        for _ in 0..count {
            let process = MockProcessBuilder::from_rng(&mut self.rng).build();
            self.processes.push(process);
        }
        self
    }

    // === Metadata setters ===

    /// Set the scan type.
    pub fn scan_type(mut self, scan_type: impl Into<String>) -> Self {
        self.scan_type = scan_type.into();
        self
    }

    /// Set the platform.
    pub fn platform(mut self, platform: impl Into<String>) -> Self {
        self.platform = platform.into();
        self
    }

    /// Set the boot ID.
    pub fn boot_id(mut self, boot_id: impl Into<String>) -> Self {
        self.boot_id = Some(boot_id.into());
        self
    }

    /// Add a warning.
    pub fn with_warning(mut self, warning: impl Into<String>) -> Self {
        self.warnings.push(warning.into());
        self
    }

    // === Build ===

    /// Build the `ScanResult`.
    pub fn build(self) -> ScanResult {
        let process_count = self.processes.len();
        ScanResult {
            processes: self.processes,
            metadata: ScanMetadata {
                scan_type: self.scan_type,
                platform: self.platform,
                boot_id: self.boot_id,
                started_at: chrono::Utc::now().to_rfc3339(),
                duration_ms: 100, // Mock duration
                process_count,
                warnings: self.warnings,
            },
        }
    }
}

// ============================================================================
// Factory Functions
// ============================================================================

/// Create a minimal mock process with just a PID.
pub fn mock_process(pid: u32) -> ProcessRecord {
    MockProcessBuilder::new().pid(pid).build()
}

/// Create a zombie process.
pub fn mock_zombie(pid: u32) -> ProcessRecord {
    MockProcessBuilder::new().pid(pid).zombie().build()
}

/// Create an orphan process.
pub fn mock_orphan(pid: u32, comm: &str) -> ProcessRecord {
    MockProcessBuilder::new().pid(pid).comm(comm).orphan().build()
}

/// Create a long-running test runner.
pub fn mock_test_runner(pid: u32, framework: &str) -> ProcessRecord {
    MockProcessBuilder::new()
        .pid(pid)
        .test_runner(framework)
        .build()
}

/// Create a dev server process.
pub fn mock_dev_server(pid: u32, server_type: &str) -> ProcessRecord {
    MockProcessBuilder::new()
        .pid(pid)
        .dev_server(server_type)
        .build()
}

/// Create an empty scan result.
pub fn mock_empty_scan() -> ScanResult {
    MockScanBuilder::new().build()
}

/// Create a scan result with N random processes.
pub fn mock_random_scan(count: usize, seed: u64) -> ScanResult {
    MockScanBuilder::with_seed(seed)
        .with_random_processes(count)
        .build()
}

/// Create a scan result representing a "messy" system with various process types.
pub fn mock_messy_system(seed: u64) -> ScanResult {
    let mut rng = MockRng::new(seed);

    MockScanBuilder::new()
        // System services (should be protected)
        .with_system_service(1, "systemd")
        .with_system_service(rng.range(100, 200) as u32, "sshd")
        .with_system_service(rng.range(200, 300) as u32, "dbus-daemon")
        // Some zombies
        .with_zombie(rng.range(1000, 2000) as u32)
        .with_zombie(rng.range(2000, 3000) as u32)
        // Orphaned processes
        .with_orphan(rng.range(3000, 4000) as u32, "node")
        .with_orphan(rng.range(4000, 5000) as u32, "python")
        // Stale test runners
        .with_test_runner(rng.range(5000, 6000) as u32, "jest")
        .with_test_runner(rng.range(6000, 7000) as u32, "pytest")
        // Stale dev servers
        .with_dev_server(rng.range(7000, 8000) as u32, "next")
        .with_dev_server(rng.range(8000, 9000) as u32, "vite")
        // Agent processes
        .with_agent(rng.range(9000, 10000) as u32, "claude")
        // Some random background noise
        .with_random_processes(10)
        .build()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_process_builder_defaults() {
        let process = MockProcessBuilder::new().build();
        assert_eq!(process.pid.0, 1000);
        assert_eq!(process.ppid.0, 1);
        assert_eq!(process.comm, "test");
        assert_eq!(process.state, ProcessState::Sleeping);
    }

    #[test]
    fn test_mock_process_builder_chain() {
        let process = MockProcessBuilder::new()
            .pid(5678)
            .ppid(1234)
            .comm("myproc")
            .state_running()
            .cpu_percent(50.0)
            .rss_mb(100)
            .build();

        assert_eq!(process.pid.0, 5678);
        assert_eq!(process.ppid.0, 1234);
        assert_eq!(process.comm, "myproc");
        assert_eq!(process.state, ProcessState::Running);
        assert_eq!(process.cpu_percent, 50.0);
        assert_eq!(process.rss_bytes, 100 * 1024 * 1024);
    }

    #[test]
    fn test_mock_process_zombie() {
        let process = MockProcessBuilder::new().pid(999).zombie().build();
        assert_eq!(process.state, ProcessState::Zombie);
        assert_eq!(process.comm, "<defunct>");
        assert_eq!(process.cpu_percent, 0.0);
    }

    #[test]
    fn test_mock_process_orphan() {
        let process = MockProcessBuilder::new().pid(888).orphan().build();
        assert_eq!(process.ppid.0, 1);
        assert!(process.tty.is_none());
    }

    #[test]
    fn test_mock_process_test_runner() {
        let process = MockProcessBuilder::new()
            .pid(777)
            .test_runner("jest")
            .build();
        assert_eq!(process.comm, "jest");
        assert!(process.cmd.contains("jest"));
        assert!(process.elapsed.as_secs() >= 3600); // At least 1 hour
    }

    #[test]
    fn test_mock_process_dev_server() {
        let process = MockProcessBuilder::new()
            .pid(666)
            .dev_server("next")
            .build();
        assert_eq!(process.comm, "node");
        assert!(process.cmd.contains("next"));
        assert!(process.elapsed.as_secs() >= 86400); // At least 1 day
    }

    #[test]
    fn test_mock_scan_builder() {
        let scan = MockScanBuilder::new()
            .with_zombie(100)
            .with_orphan(200, "node")
            .with_test_runner(300, "pytest")
            .build();

        assert_eq!(scan.processes.len(), 3);
        assert_eq!(scan.metadata.process_count, 3);
        assert_eq!(scan.metadata.scan_type, "mock");
    }

    #[test]
    fn test_mock_scan_random_deterministic() {
        let scan1 = MockScanBuilder::with_seed(12345)
            .with_random_processes(5)
            .build();
        let scan2 = MockScanBuilder::with_seed(12345)
            .with_random_processes(5)
            .build();

        // Same seed should produce same PIDs
        for (p1, p2) in scan1.processes.iter().zip(scan2.processes.iter()) {
            assert_eq!(p1.pid, p2.pid);
            assert_eq!(p1.comm, p2.comm);
        }
    }

    #[test]
    fn test_factory_functions() {
        let zombie = mock_zombie(111);
        assert_eq!(zombie.state, ProcessState::Zombie);

        let orphan = mock_orphan(222, "bash");
        assert_eq!(orphan.ppid.0, 1);
        assert_eq!(orphan.comm, "bash");

        let test_runner = mock_test_runner(333, "cargo");
        assert_eq!(test_runner.comm, "cargo");

        let dev_server = mock_dev_server(444, "django");
        assert_eq!(dev_server.comm, "python");
    }

    #[test]
    fn test_mock_messy_system() {
        let scan = mock_messy_system(42);

        // Should have various process types
        assert!(scan.processes.len() >= 10);

        // Should have zombies
        let zombies: Vec<_> = scan
            .processes
            .iter()
            .filter(|p| p.state == ProcessState::Zombie)
            .collect();
        assert!(!zombies.is_empty());

        // Should have system services (PPID=1, UID=0)
        let services: Vec<_> = scan
            .processes
            .iter()
            .filter(|p| p.ppid.0 == 1 && p.uid == 0)
            .collect();
        assert!(!services.is_empty());
    }

    #[test]
    fn test_mock_rng_deterministic() {
        let mut rng1 = MockRng::new(999);
        let mut rng2 = MockRng::new(999);

        for _ in 0..100 {
            assert_eq!(rng1.next_u64(), rng2.next_u64());
        }
    }

    #[test]
    fn test_mock_empty_scan() {
        let scan = mock_empty_scan();
        assert!(scan.processes.is_empty());
        assert_eq!(scan.metadata.process_count, 0);
    }
}
