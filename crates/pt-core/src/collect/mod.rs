//! Process collection and scanning.
//!
//! This module provides the evidence collection layer for process triage:
//! - Quick scan via ps parsing (fast, universal)
//! - Deep scan via /proc inspection (detailed, Linux-only)
//! - Network connection collection
//! - Cgroup and resource limit collection
//! - Systemd unit detection
//! - Container detection (Docker, K8s, etc.)
//! - Tool runner for safe external command execution
//!
//! The collection layer produces structured records that feed into the
//! inference engine for classification.

#[cfg(target_os = "linux")]
pub mod cgroup;
#[cfg(target_os = "linux")]
pub mod container;
#[cfg(target_os = "linux")]
pub mod cpu_capacity;
#[cfg(target_os = "linux")]
mod deep_scan;
#[cfg(target_os = "linux")]
mod network;
#[cfg(target_os = "linux")]
mod proc_parsers;
pub mod protected;
mod quick_scan;
#[cfg(target_os = "linux")]
pub mod systemd;
#[cfg(target_os = "linux")]
pub mod tick_delta;
pub mod tool_runner;
mod types;

#[cfg(target_os = "linux")]
pub use deep_scan::{
    deep_scan, DeepScanError, DeepScanMetadata, DeepScanOptions, DeepScanRecord, DeepScanResult,
};
#[cfg(target_os = "linux")]
pub use network::{
    collect_network_info, ListenPort, NetworkInfo, SocketCounts, TcpConnection, TcpState,
    UdpSocket, UnixSocket, UnixSocketState, UnixSocketType,
};
#[cfg(target_os = "linux")]
pub use proc_parsers::{
    parse_cgroup, parse_environ, parse_fd, parse_io, parse_sched, parse_schedstat, parse_statm,
    parse_wchan, CgroupInfo, CriticalFile, CriticalFileCategory, FdInfo, FdType, IoStats, MemStats,
    OpenFile, OpenMode, SchedInfo, SchedStats,
};
pub use quick_scan::{quick_scan, QuickScanError, QuickScanOptions};
pub use tool_runner::{
    run_tool, run_tools_parallel, ToolConfig, ToolError, ToolOutput, ToolRunner, ToolRunnerBuilder,
    ToolSpec, DEFAULT_BUDGET_MS, DEFAULT_MAX_OUTPUT_BYTES, DEFAULT_MAX_PARALLEL,
    DEFAULT_TIMEOUT_SECS,
};
pub use types::{ProcessRecord, ProcessState, ScanMetadata, ScanResult};

// Re-export protected filter types
pub use protected::{
    CompiledProtectedPattern, FilterResult, MatchedField, PatternKind, ProtectedFilter,
    ProtectedFilterError, ProtectedMatch,
};

// Re-export cgroup types
#[cfg(target_os = "linux")]
pub use cgroup::{
    collect_cgroup_details, collect_cgroup_from_content, effective_cores_from_quota, CgroupDetails,
    CgroupProvenance, CgroupVersion, CpuLimitSource, CpuLimits, MemoryLimitSource, MemoryLimits,
};

// Re-export systemd types
#[cfg(target_os = "linux")]
pub use systemd::{
    collect_systemd_unit, is_systemd_available, is_systemd_managed, parse_systemctl_output,
    SystemdActiveState, SystemdDataSource, SystemdProvenance, SystemdUnit, SystemdUnitType,
};

// Re-export container types
#[cfg(target_os = "linux")]
pub use container::{
    detect_container_from_cgroup, detect_container_from_markers, detect_kubernetes_from_env,
    ContainerDetectionSource, ContainerInfo, ContainerProvenance, ContainerRuntime, KubernetesInfo,
};

// Re-export CPU capacity types
#[cfg(target_os = "linux")]
pub use cpu_capacity::{
    compute_cpu_capacity, compute_n_eff, count_cpus_in_list, num_logical_cpus,
    parse_cpus_allowed_list, AffinitySource, BindingConstraint, CpuCapacity, CpuCapacityProvenance,
    CpusetSource, QuotaSource,
};

// Re-export tick-delta feature types
#[cfg(target_os = "linux")]
pub use tick_delta::{
    clk_tck, collect_tick_snapshot, compute_tick_delta, parse_tick_snapshot, sample_tick_delta,
    BudgetConstraint, NEffPolicy, TickDeltaConfig, TickDeltaFeatures, TickDeltaProvenance,
    TickSnapshot,
};
