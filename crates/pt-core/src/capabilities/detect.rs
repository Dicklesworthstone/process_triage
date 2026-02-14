//! Capability detection implementation.

use crate::collect::tool_runner::run_tool;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, info, trace, warn};

/// Default timeout for tool detection probes.
const TOOL_PROBE_TIMEOUT_MS: u64 = 5000;

/// Errors during capability detection.
#[derive(Debug, Error)]
pub enum DetectionError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("tool probe failed: {0}")]
    ToolProbe(String),
}

/// Complete system capabilities snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capabilities {
    /// Platform information.
    pub platform: PlatformInfo,

    /// Available data sources for collection.
    pub data_sources: DataSourceCapabilities,

    /// Tool availability and versions.
    pub tools: ToolCapabilities,

    /// User permissions and capabilities.
    pub permissions: PermissionCapabilities,

    /// Supervisor systems available.
    pub supervisors: SupervisorCapabilities,

    /// Actions that can be performed.
    pub actions: ActionCapabilities,

    /// Timestamp when capabilities were detected.
    pub detected_at: String,
}

impl Capabilities {
    /// Check if we can perform deep scans (requires procfs).
    pub fn can_deep_scan(&self) -> bool {
        self.data_sources.procfs
    }

    /// Check if we can perform maximal instrumentation.
    pub fn can_maximal_scan(&self) -> bool {
        self.data_sources.perf_events || self.data_sources.ebpf
    }

    /// Get a summary of available capabilities.
    pub fn summary(&self) -> String {
        let tool_count = self.tools.available_count();
        let action_count = self.actions.available_count();

        format!(
            "Platform: {} {} | Tools: {}/{} | Actions: {}/{} | Container: {}",
            self.platform.os,
            self.platform.kernel_version.as_deref().unwrap_or("unknown"),
            tool_count,
            self.tools.total_count(),
            action_count,
            self.actions.total_count(),
            if self.platform.in_container {
                "yes"
            } else {
                "no"
            }
        )
    }
}

/// Platform information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformInfo {
    /// Operating system (linux, macos, freebsd).
    pub os: String,

    /// Kernel version string.
    pub kernel_version: Option<String>,

    /// Kernel release string (e.g., "6.1.0-25-generic").
    pub kernel_release: Option<String>,

    /// Machine architecture.
    pub arch: String,

    /// Whether running inside a container.
    pub in_container: bool,

    /// Container runtime if detected (docker, podman, lxc, etc.).
    pub container_runtime: Option<String>,
}

/// Data source availability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataSourceCapabilities {
    /// /proc filesystem available.
    pub procfs: bool,

    /// /sys filesystem available.
    pub sysfs: bool,

    /// perf_events available.
    pub perf_events: bool,

    /// eBPF available.
    pub ebpf: bool,

    /// schedstat available in /proc/\[pid\]/schedstat.
    pub schedstat: bool,

    /// cgroup v1 available.
    pub cgroup_v1: bool,

    /// cgroup v2 available.
    pub cgroup_v2: bool,
}

/// Single tool capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCapability {
    /// Whether tool is available.
    pub available: bool,

    /// Tool version if detected.
    pub version: Option<String>,

    /// Path to the tool.
    pub path: Option<String>,

    /// Whether tool works (tested with a simple probe).
    pub works: bool,

    /// Error message if tool doesn't work.
    pub error: Option<String>,
}

impl ToolCapability {
    /// Create a capability for an unavailable tool.
    pub fn unavailable() -> Self {
        Self {
            available: false,
            version: None,
            path: None,
            works: false,
            error: None,
        }
    }

    /// Create a capability for an available but non-working tool.
    pub fn available_broken(path: String, error: String) -> Self {
        Self {
            available: true,
            version: None,
            path: Some(path),
            works: false,
            error: Some(error),
        }
    }

    /// Create a capability for a working tool.
    pub fn working(path: String, version: Option<String>) -> Self {
        Self {
            available: true,
            version,
            path: Some(path),
            works: true,
            error: None,
        }
    }
}

/// Tool capabilities for all relevant tools.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCapabilities {
    /// ps command.
    pub ps: ToolCapability,

    /// lsof command.
    pub lsof: ToolCapability,

    /// ss command (Linux socket statistics).
    pub ss: ToolCapability,

    /// netstat command.
    pub netstat: ToolCapability,

    /// perf command.
    pub perf: ToolCapability,

    /// strace command (Linux).
    pub strace: ToolCapability,

    /// dtrace command (macOS/FreeBSD).
    pub dtrace: ToolCapability,

    /// bpftrace command.
    pub bpftrace: ToolCapability,

    /// systemctl command.
    pub systemctl: ToolCapability,

    /// docker command.
    pub docker: ToolCapability,

    /// podman command.
    pub podman: ToolCapability,

    /// nice command.
    pub nice: ToolCapability,

    /// renice command.
    pub renice: ToolCapability,

    /// ionice command (Linux).
    pub ionice: ToolCapability,

    /// Additional tools indexed by name.
    #[serde(default)]
    pub additional: HashMap<String, ToolCapability>,
}

impl ToolCapabilities {
    /// Count available tools.
    pub fn available_count(&self) -> usize {
        let base = [
            &self.ps,
            &self.lsof,
            &self.ss,
            &self.netstat,
            &self.perf,
            &self.strace,
            &self.dtrace,
            &self.bpftrace,
            &self.systemctl,
            &self.docker,
            &self.podman,
            &self.nice,
            &self.renice,
            &self.ionice,
        ]
        .iter()
        .filter(|t| t.available && t.works)
        .count();

        base + self
            .additional
            .values()
            .filter(|t| t.available && t.works)
            .count()
    }

    /// Total number of tracked tools.
    pub fn total_count(&self) -> usize {
        14 + self.additional.len()
    }

    /// Get tool by name.
    pub fn get(&self, name: &str) -> Option<&ToolCapability> {
        match name {
            "ps" => Some(&self.ps),
            "lsof" => Some(&self.lsof),
            "ss" => Some(&self.ss),
            "netstat" => Some(&self.netstat),
            "perf" => Some(&self.perf),
            "strace" => Some(&self.strace),
            "dtrace" => Some(&self.dtrace),
            "bpftrace" => Some(&self.bpftrace),
            "systemctl" => Some(&self.systemctl),
            "docker" => Some(&self.docker),
            "podman" => Some(&self.podman),
            "nice" => Some(&self.nice),
            "renice" => Some(&self.renice),
            "ionice" => Some(&self.ionice),
            other => self.additional.get(other),
        }
    }
}

/// Permission capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionCapabilities {
    /// Effective user ID.
    pub effective_uid: u32,

    /// Effective group ID.
    pub effective_gid: u32,

    /// Whether running as root.
    pub is_root: bool,

    /// Whether sudo is available and works.
    pub can_sudo: bool,

    /// Linux capabilities if available.
    #[serde(default)]
    pub linux_capabilities: Vec<String>,

    /// Whether we can read other users' processes.
    pub can_read_others_procs: bool,

    /// Whether we can send signals to other users' processes.
    pub can_signal_others: bool,
}

/// Supervisor system capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupervisorCapabilities {
    /// systemd available and running.
    pub systemd: bool,

    /// launchd available (macOS).
    pub launchd: bool,

    /// PM2 available.
    pub pm2: bool,

    /// supervisord available.
    pub supervisord: bool,

    /// Docker daemon running.
    pub docker_daemon: bool,

    /// Podman available.
    pub podman_available: bool,

    /// Kubernetes environment detected.
    pub kubernetes: bool,
}

/// Action capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionCapabilities {
    /// Can send SIGKILL.
    pub kill: bool,

    /// Can send SIGSTOP/SIGCONT (pause).
    pub pause: bool,

    /// Can use renice.
    pub renice: bool,

    /// Can use ionice (Linux).
    pub ionice: bool,

    /// Can use cgroup freeze (cgroup v2).
    pub cgroup_freeze: bool,

    /// Can use cgroup CPU throttle.
    pub cgroup_throttle: bool,

    /// Can use cpuset quarantine.
    pub cpuset_quarantine: bool,
}

impl ActionCapabilities {
    /// Count available actions.
    pub fn available_count(&self) -> usize {
        [
            self.kill,
            self.pause,
            self.renice,
            self.ionice,
            self.cgroup_freeze,
            self.cgroup_throttle,
            self.cpuset_quarantine,
        ]
        .iter()
        .filter(|&&x| x)
        .count()
    }

    /// Total number of tracked actions.
    pub fn total_count(&self) -> usize {
        7
    }
}

/// Detect all system capabilities.
pub fn detect_capabilities() -> Capabilities {
    info!("detecting system capabilities");

    let platform = detect_platform();
    let data_sources = detect_data_sources(&platform);
    let tools = detect_tools(&platform);
    let permissions = detect_permissions();
    let supervisors = detect_supervisors(&tools);
    let actions = detect_actions(&permissions, &data_sources, &tools);

    let caps = Capabilities {
        platform,
        data_sources,
        tools,
        permissions,
        supervisors,
        actions,
        detected_at: chrono::Utc::now().to_rfc3339(),
    };

    info!(summary = %caps.summary(), "capability detection complete");
    caps
}

/// Detect platform information.
fn detect_platform() -> PlatformInfo {
    debug!("detecting platform");

    let os = detect_os();
    let kernel_version = detect_kernel_version();
    let kernel_release = detect_kernel_release();
    let arch = std::env::consts::ARCH.to_string();
    let (in_container, container_runtime) = detect_container();

    PlatformInfo {
        os,
        kernel_version,
        kernel_release,
        arch,
        in_container,
        container_runtime,
    }
}

/// Detect operating system.
fn detect_os() -> String {
    #[cfg(target_os = "linux")]
    {
        "linux".to_string()
    }
    #[cfg(target_os = "macos")]
    {
        "macos".to_string()
    }
    #[cfg(target_os = "freebsd")]
    {
        "freebsd".to_string()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
    {
        std::env::consts::OS.to_string()
    }
}

/// Detect kernel version.
fn detect_kernel_version() -> Option<String> {
    #[cfg(unix)]
    {
        let mut uname = std::mem::MaybeUninit::<libc::utsname>::uninit();
        let result = unsafe { libc::uname(uname.as_mut_ptr()) };
        if result == 0 {
            let uname = unsafe { uname.assume_init() };
            let version = unsafe {
                std::ffi::CStr::from_ptr(uname.version.as_ptr())
                    .to_string_lossy()
                    .to_string()
            };
            return Some(version);
        }
    }
    None
}

/// Detect kernel release.
fn detect_kernel_release() -> Option<String> {
    #[cfg(unix)]
    {
        let mut uname = std::mem::MaybeUninit::<libc::utsname>::uninit();
        let result = unsafe { libc::uname(uname.as_mut_ptr()) };
        if result == 0 {
            let uname = unsafe { uname.assume_init() };
            let release = unsafe {
                std::ffi::CStr::from_ptr(uname.release.as_ptr())
                    .to_string_lossy()
                    .to_string()
            };
            return Some(release);
        }
    }
    None
}

/// Detect if running in a container.
fn detect_container() -> (bool, Option<String>) {
    // Check various container indicators
    trace!("checking container indicators");

    // Check for /.dockerenv
    if Path::new("/.dockerenv").exists() {
        return (true, Some("docker".to_string()));
    }

    // Check cgroup for container indicators
    if let Ok(cgroup) = fs::read_to_string("/proc/1/cgroup") {
        if cgroup.contains("/docker/") || cgroup.contains("/docker-") {
            return (true, Some("docker".to_string()));
        }
        if cgroup.contains("/kubepods/") {
            return (true, Some("kubernetes".to_string()));
        }
        if cgroup.contains("/lxc/") {
            return (true, Some("lxc".to_string()));
        }
        if cgroup.contains("/podman-") || cgroup.contains("/libpod-") {
            return (true, Some("podman".to_string()));
        }
    }

    // Check /proc/1/environ for container env vars
    if let Ok(environ) = fs::read_to_string("/proc/1/environ") {
        if environ.contains("container=") {
            return (true, None);
        }
    }

    // Check for Kubernetes service account
    if Path::new("/var/run/secrets/kubernetes.io").exists() {
        return (true, Some("kubernetes".to_string()));
    }

    (false, None)
}

/// Detect available data sources.
fn detect_data_sources(_platform: &PlatformInfo) -> DataSourceCapabilities {
    debug!("detecting data sources");

    let procfs = Path::new("/proc").is_dir() && Path::new("/proc/self").exists();
    let sysfs = Path::new("/sys").is_dir();

    let schedstat = if procfs {
        Path::new("/proc/self/schedstat").exists()
    } else {
        false
    };

    let cgroup_v1 = Path::new("/sys/fs/cgroup/cpu").is_dir();
    let cgroup_v2 = Path::new("/sys/fs/cgroup/cgroup.controllers").exists();

    // Check perf_events
    let perf_events = detect_perf_events();

    // Check eBPF
    let ebpf = detect_ebpf();

    DataSourceCapabilities {
        procfs,
        sysfs,
        perf_events,
        ebpf,
        schedstat,
        cgroup_v1,
        cgroup_v2,
    }
}

/// Check if perf_events are available.
fn detect_perf_events() -> bool {
    #[cfg(target_os = "linux")]
    {
        // Check perf_event_paranoid
        if let Ok(level) = fs::read_to_string("/proc/sys/kernel/perf_event_paranoid") {
            if let Ok(n) = level.trim().parse::<i32>() {
                // -1 = allow everything, 0-2 = restricted
                // We can use perf even with paranoid=2 for our own processes
                return n <= 2;
            }
        }
        false
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Check if eBPF is available.
fn detect_ebpf() -> bool {
    #[cfg(target_os = "linux")]
    {
        // Check for BPF syscall availability and permissions
        // Simple heuristic: check if /sys/kernel/btf/vmlinux exists (BTF support)
        if Path::new("/sys/kernel/btf/vmlinux").exists() {
            // Also need CAP_BPF or root
            let uid = unsafe { libc::geteuid() };
            if uid == 0 {
                return true;
            }
            // Could check CAP_BPF here, but that requires more complex logic
            // For now, just report false if not root
            return false;
        }
        false
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Detect tool availability.
fn detect_tools(_platform: &PlatformInfo) -> ToolCapabilities {
    debug!("detecting tools");

    let timeout = Duration::from_millis(TOOL_PROBE_TIMEOUT_MS);

    ToolCapabilities {
        ps: probe_tool("ps", &["--version"], &["-ef"], timeout),
        lsof: probe_tool("lsof", &["-v"], &["-c", "nonexistent123"], timeout),
        ss: probe_tool("ss", &["-V"], &["-tuln"], timeout),
        netstat: probe_tool("netstat", &["--version"], &["-tuln"], timeout),
        perf: probe_tool("perf", &["version"], &["stat", "--help"], timeout),
        strace: probe_tool("strace", &["-V"], &["-h"], timeout),
        dtrace: probe_tool("dtrace", &["-V"], &["-l"], timeout),
        bpftrace: probe_tool("bpftrace", &["--version"], &["-l"], timeout),
        systemctl: probe_tool("systemctl", &["--version"], &["--help"], timeout),
        docker: probe_tool("docker", &["--version"], &["info"], timeout),
        podman: probe_tool("podman", &["--version"], &["info"], timeout),
        nice: probe_tool("nice", &["--version"], &["echo", "test"], timeout),
        renice: probe_tool("renice", &["--version"], &["--help"], timeout),
        ionice: probe_tool("ionice", &["--version"], &["--help"], timeout),
        additional: HashMap::new(),
    }
}

/// Probe a tool to check availability and version.
fn probe_tool(
    name: &str,
    version_args: &[&str],
    test_args: &[&str],
    timeout: Duration,
) -> ToolCapability {
    trace!(tool = name, "probing tool");

    // First check if the tool exists using `which`
    let which_result = run_tool("which", &[name], Some(timeout), Some(1024));

    let path = match which_result {
        Ok(output) if output.success() => output.stdout_str().trim().to_string(),
        _ => {
            trace!(tool = name, "not found");
            return ToolCapability::unavailable();
        }
    };

    // Try to get version
    let version = match run_tool(name, version_args, Some(timeout), Some(4096)) {
        Ok(output) => {
            let text = if output.success() {
                output.stdout_str()
            } else {
                output.stderr_str()
            };
            parse_version(&text)
        }
        Err(_) => None,
    };

    // Test if the tool actually works
    let test_result = run_tool(name, test_args, Some(timeout), Some(4096));
    match test_result {
        Ok(output) if output.success() || output.exit_code.is_some() => {
            // Tool ran (even if non-zero exit for --help type commands)
            trace!(tool = name, version = ?version, "tool works");
            ToolCapability::working(path, version)
        }
        Ok(output) => {
            let err = output.stderr_str();
            warn!(tool = name, error = %err, "tool probe failed");
            ToolCapability::available_broken(path, err)
        }
        Err(e) => {
            warn!(tool = name, error = %e, "tool probe error");
            ToolCapability::available_broken(path, e.to_string())
        }
    }
}

/// Parse version from tool output.
fn parse_version(output: &str) -> Option<String> {
    // Try to extract version numbers from various formats
    // Common patterns: "X.Y.Z", "vX.Y.Z", "version X.Y"

    let version_regex_patterns = [
        r"(\d+\.\d+(?:\.\d+)?(?:-\w+)?)",  // X.Y.Z or X.Y.Z-suffix
        r"v(\d+\.\d+(?:\.\d+)?)",          // vX.Y.Z
        r"version\s+(\d+\.\d+(?:\.\d+)?)", // version X.Y.Z
    ];

    for _pattern in &version_regex_patterns {
        // Simple pattern matching without regex crate
        // Look for digit sequences separated by dots
        for word in output.split_whitespace() {
            let cleaned = word.trim_start_matches('v').trim_end_matches(',');
            if cleaned
                .chars()
                .next()
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false)
                && cleaned.contains('.')
            {
                // Validate it looks like a version
                let parts: Vec<&str> = cleaned.split('.').collect();
                if parts.len() >= 2
                    && parts
                        .iter()
                        .take(2)
                        .all(|p| p.chars().take(3).all(|c| c.is_ascii_digit()))
                {
                    return Some(cleaned.to_string());
                }
            }
        }
    }
    None
}

/// Detect user permissions.
fn detect_permissions() -> PermissionCapabilities {
    debug!("detecting permissions");

    let effective_uid = unsafe { libc::geteuid() };
    let effective_gid = unsafe { libc::getegid() };
    let is_root = effective_uid == 0;

    // Check sudo availability
    let can_sudo = check_sudo();

    // Check Linux capabilities
    let linux_capabilities = detect_linux_capabilities();

    // Check if we can read other users' processes
    let can_read_others_procs = check_read_others_procs(effective_uid);

    // Check if we can signal other users' processes
    let can_signal_others = is_root || linux_capabilities.contains(&"CAP_KILL".to_string());

    PermissionCapabilities {
        effective_uid,
        effective_gid,
        is_root,
        can_sudo,
        linux_capabilities,
        can_read_others_procs,
        can_signal_others,
    }
}

/// Check if sudo is available and usable.
fn check_sudo() -> bool {
    // Check if sudo exists and we can run it without password
    // Use sudo -n (non-interactive) to test
    let timeout = Duration::from_millis(2000);
    let result = run_tool("sudo", &["-n", "true"], Some(timeout), Some(1024));

    match result {
        Ok(output) => output.success(),
        Err(_) => false,
    }
}

/// Detect Linux capabilities for the current process.
fn detect_linux_capabilities() -> Vec<String> {
    #[cfg(target_os = "linux")]
    {
        let mut caps = Vec::new();

        // Read /proc/self/status for CapEff (effective capabilities)
        if let Ok(status) = fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(hex) = line.strip_prefix("CapEff:\t") {
                    if let Ok(bits) = u64::from_str_radix(hex.trim(), 16) {
                        caps = decode_capabilities(bits);
                    }
                    break;
                }
            }
        }
        caps
    }
    #[cfg(not(target_os = "linux"))]
    {
        Vec::new()
    }
}

/// Decode capability bits to names.
#[cfg(target_os = "linux")]
fn decode_capabilities(bits: u64) -> Vec<String> {
    const CAPABILITIES: &[(u64, &str)] = &[
        (1 << 0, "CAP_CHOWN"),
        (1 << 1, "CAP_DAC_OVERRIDE"),
        (1 << 2, "CAP_DAC_READ_SEARCH"),
        (1 << 3, "CAP_FOWNER"),
        (1 << 4, "CAP_FSETID"),
        (1 << 5, "CAP_KILL"),
        (1 << 6, "CAP_SETGID"),
        (1 << 7, "CAP_SETUID"),
        (1 << 8, "CAP_SETPCAP"),
        (1 << 9, "CAP_LINUX_IMMUTABLE"),
        (1 << 10, "CAP_NET_BIND_SERVICE"),
        (1 << 11, "CAP_NET_BROADCAST"),
        (1 << 12, "CAP_NET_ADMIN"),
        (1 << 13, "CAP_NET_RAW"),
        (1 << 14, "CAP_IPC_LOCK"),
        (1 << 15, "CAP_IPC_OWNER"),
        (1 << 16, "CAP_SYS_MODULE"),
        (1 << 17, "CAP_SYS_RAWIO"),
        (1 << 18, "CAP_SYS_CHROOT"),
        (1 << 19, "CAP_SYS_PTRACE"),
        (1 << 20, "CAP_SYS_PACCT"),
        (1 << 21, "CAP_SYS_ADMIN"),
        (1 << 22, "CAP_SYS_BOOT"),
        (1 << 23, "CAP_SYS_NICE"),
        (1 << 24, "CAP_SYS_RESOURCE"),
        (1 << 25, "CAP_SYS_TIME"),
        (1 << 26, "CAP_SYS_TTY_CONFIG"),
        (1 << 27, "CAP_MKNOD"),
        (1 << 28, "CAP_LEASE"),
        (1 << 29, "CAP_AUDIT_WRITE"),
        (1 << 30, "CAP_AUDIT_CONTROL"),
        (1 << 31, "CAP_SETFCAP"),
        (1 << 32, "CAP_MAC_OVERRIDE"),
        (1 << 33, "CAP_MAC_ADMIN"),
        (1 << 34, "CAP_SYSLOG"),
        (1 << 35, "CAP_WAKE_ALARM"),
        (1 << 36, "CAP_BLOCK_SUSPEND"),
        (1 << 37, "CAP_AUDIT_READ"),
        (1 << 38, "CAP_PERFMON"),
        (1 << 39, "CAP_BPF"),
        (1 << 40, "CAP_CHECKPOINT_RESTORE"),
    ];

    CAPABILITIES
        .iter()
        .filter_map(|(bit, name)| {
            if bits & bit != 0 {
                Some(name.to_string())
            } else {
                None
            }
        })
        .collect()
}

/// Check if we can read other users' processes.
fn check_read_others_procs(uid: u32) -> bool {
    if uid == 0 {
        return true;
    }

    // Try to read /proc/1/cmdline (init, owned by root)
    fs::read_to_string("/proc/1/cmdline").is_ok()
}

/// Detect available supervisor systems.
fn detect_supervisors(tools: &ToolCapabilities) -> SupervisorCapabilities {
    debug!("detecting supervisors");

    // Check systemd
    let systemd = tools.systemctl.works && check_systemd_running();

    // Check launchd (macOS)
    let launchd = cfg!(target_os = "macos") && Path::new("/var/run/launchd").exists();

    // Check PM2
    let pm2 = check_pm2_available();

    // Check supervisord
    let supervisord = check_supervisord_available();

    // Check Docker daemon
    let docker_daemon = tools.docker.works && check_docker_daemon();

    // Check Podman
    let podman_available = tools.podman.works;

    // Check Kubernetes
    let kubernetes = Path::new("/var/run/secrets/kubernetes.io").exists()
        || std::env::var("KUBERNETES_SERVICE_HOST").is_ok();

    SupervisorCapabilities {
        systemd,
        launchd,
        pm2,
        supervisord,
        docker_daemon,
        podman_available,
        kubernetes,
    }
}

/// Check if systemd is running.
fn check_systemd_running() -> bool {
    #[cfg(target_os = "linux")]
    {
        // Check if PID 1 is systemd
        if let Ok(cmdline) = fs::read_to_string("/proc/1/cmdline") {
            return cmdline.contains("systemd");
        }
        false
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Check if PM2 is available.
fn check_pm2_available() -> bool {
    let timeout = Duration::from_millis(2000);
    run_tool("pm2", &["--version"], Some(timeout), Some(1024))
        .map(|o| o.success())
        .unwrap_or(false)
}

/// Check if supervisord is available.
fn check_supervisord_available() -> bool {
    let timeout = Duration::from_millis(2000);
    run_tool("supervisorctl", &["--help"], Some(timeout), Some(1024))
        .map(|o| o.exit_code.is_some())
        .unwrap_or(false)
}

/// Check if Docker daemon is running.
fn check_docker_daemon() -> bool {
    let timeout = Duration::from_millis(3000);
    run_tool("docker", &["info"], Some(timeout), Some(4096))
        .map(|o| o.success())
        .unwrap_or(false)
}

/// Detect available actions.
fn detect_actions(
    permissions: &PermissionCapabilities,
    data_sources: &DataSourceCapabilities,
    tools: &ToolCapabilities,
) -> ActionCapabilities {
    debug!("detecting actions");

    // Basic actions based on permissions
    let kill = permissions.can_signal_others || permissions.is_root;
    let pause = kill; // Same permissions for SIGSTOP

    // renice requires root or CAP_SYS_NICE
    let renice = permissions.is_root
        || permissions
            .linux_capabilities
            .contains(&"CAP_SYS_NICE".to_string())
        || tools.renice.works;

    // ionice similar to renice (Linux only)
    let ionice = cfg!(target_os = "linux") && (permissions.is_root || tools.ionice.works);

    // cgroup operations require cgroup v2 and appropriate permissions
    let cgroup_freeze =
        data_sources.cgroup_v2 && (permissions.is_root || check_cgroup_write_access());

    let cgroup_throttle = cgroup_freeze; // Same requirements

    let cpuset_quarantine =
        data_sources.cgroup_v2 && (permissions.is_root || check_cgroup_write_access());

    ActionCapabilities {
        kill,
        pause,
        renice,
        ionice,
        cgroup_freeze,
        cgroup_throttle,
        cpuset_quarantine,
    }
}

/// Check if we have write access to cgroup v2 hierarchy.
fn check_cgroup_write_access() -> bool {
    // Check if we can write to our own cgroup
    if let Ok(cgroup) = fs::read_to_string("/proc/self/cgroup") {
        for line in cgroup.lines() {
            // cgroup v2 format: "0::<path>"
            if let Some(path) = line.strip_prefix("0::") {
                let cgroup_path = format!("/sys/fs/cgroup{}", path);
                // Try to check write access
                if let Ok(metadata) = fs::metadata(&cgroup_path) {
                    // This is a rough check - proper check would try to write
                    return !metadata.permissions().readonly();
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_os() {
        let os = detect_os();
        assert!(!os.is_empty());
        #[cfg(target_os = "linux")]
        assert_eq!(os, "linux");
        #[cfg(target_os = "macos")]
        assert_eq!(os, "macos");
    }

    #[test]
    fn test_detect_platform() {
        let platform = detect_platform();
        assert!(!platform.os.is_empty());
        assert!(!platform.arch.is_empty());
    }

    #[test]
    fn test_detect_capabilities() {
        let caps = detect_capabilities();

        // Basic sanity checks
        assert!(!caps.platform.os.is_empty());
        assert!(!caps.detected_at.is_empty());

        // ps should generally be available
        #[cfg(unix)]
        assert!(caps.tools.ps.available);
    }

    #[test]
    fn test_tool_capability_unavailable() {
        let cap = ToolCapability::unavailable();
        assert!(!cap.available);
        assert!(!cap.works);
    }

    #[test]
    fn test_tool_capability_working() {
        let cap = ToolCapability::working("/usr/bin/ps".to_string(), Some("1.0.0".to_string()));
        assert!(cap.available);
        assert!(cap.works);
        assert_eq!(cap.version, Some("1.0.0".to_string()));
    }

    #[test]
    fn test_parse_version() {
        assert_eq!(parse_version("ps version 1.2.3"), Some("1.2.3".to_string()));
        assert_eq!(parse_version("v1.0.0"), Some("1.0.0".to_string()));
        assert_eq!(
            parse_version("ss utility, v5.15.0"),
            Some("5.15.0".to_string())
        );
        assert_eq!(parse_version("no version here"), None);
    }

    #[test]
    fn test_capabilities_summary() {
        let caps = detect_capabilities();
        let summary = caps.summary();
        assert!(summary.contains("Platform:"));
        assert!(summary.contains("Tools:"));
        assert!(summary.contains("Actions:"));
    }

    #[test]
    fn test_data_sources_detection() {
        let platform = detect_platform();
        let sources = detect_data_sources(&platform);

        #[cfg(target_os = "linux")]
        {
            // Linux should have procfs
            assert!(sources.procfs);
            assert!(sources.sysfs);
        }
    }

    #[test]
    fn test_permissions_detection() {
        let perms = detect_permissions();

        // We should have valid uid/gid
        assert!(perms.effective_uid < u32::MAX);
        assert!(perms.effective_gid < u32::MAX);

        // Root check should be consistent
        assert_eq!(perms.is_root, perms.effective_uid == 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_decode_capabilities() {
        // Test with known capability bits
        let bits = (1 << 5) | (1 << 21); // CAP_KILL + CAP_SYS_ADMIN
        let caps = decode_capabilities(bits);
        assert!(caps.contains(&"CAP_KILL".to_string()));
        assert!(caps.contains(&"CAP_SYS_ADMIN".to_string()));
    }

    #[test]
    fn test_container_detection() {
        let (in_container, runtime) = detect_container();

        // If we're in a container, runtime should be detected
        if in_container {
            // Runtime might be None in some edge cases
            println!("Running in container: {:?}", runtime);
        }
    }

    #[test]
    fn test_tool_capabilities_get() {
        let caps = detect_capabilities();

        // Should be able to get known tools
        assert!(caps.tools.get("ps").is_some());
        assert!(caps.tools.get("lsof").is_some());
        assert!(caps.tools.get("nonexistent").is_none());
    }
}
