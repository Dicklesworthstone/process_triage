//! Container detection and identification.
//!
//! This module detects if a process is running inside a container and extracts
//! container-specific information:
//! - Container runtime (Docker, containerd, podman, etc.)
//! - Container ID
//! - Kubernetes pod/namespace information
//!
//! # Data Sources
//! - Cgroup path patterns
//! - Environment variables (for K8s)
//! - Container-specific files

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

/// Container information for a process.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct ContainerInfo {
    /// Whether process is running in a container.
    pub in_container: bool,

    /// Container runtime type.
    pub runtime: ContainerRuntime,

    /// Container ID (full hash).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_id: Option<String>,

    /// Short container ID (first 12 chars).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_id_short: Option<String>,

    /// Kubernetes-specific information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kubernetes: Option<KubernetesInfo>,

    /// Provenance tracking.
    pub provenance: ContainerProvenance,
}

/// Container runtime type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ContainerRuntime {
    /// Docker container.
    Docker,
    /// containerd (standalone or K8s CRI).
    Containerd,
    /// Podman container.
    Podman,
    /// LXC/LXD container.
    Lxc,
    /// CRI-O (K8s CRI runtime).
    Crio,
    /// Generic container (runtime unknown).
    Generic,
    /// Not in a container.
    #[default]
    None,
}

/// Kubernetes-specific container information.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct KubernetesInfo {
    /// Pod name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pod_name: Option<String>,

    /// Pod namespace.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,

    /// Pod UID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pod_uid: Option<String>,

    /// Container name within pod.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_name: Option<String>,

    /// QoS class (Guaranteed, Burstable, BestEffort).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qos_class: Option<String>,
}

/// Provenance tracking for container detection.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct ContainerProvenance {
    /// Source of container detection.
    pub source: ContainerDetectionSource,

    /// Original cgroup path used for detection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroup_path: Option<String>,

    /// Any warnings during detection.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// Source of container detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ContainerDetectionSource {
    /// Detected from cgroup path.
    CgroupPath,
    /// Detected from environment variables.
    Environment,
    /// Detected from /.dockerenv or similar marker files.
    MarkerFile,
    /// Not detected.
    #[default]
    None,
}

/// Detect container information from cgroup path.
///
/// # Arguments
/// * `cgroup_path` - The cgroup path (unified v2 or any v1 path)
///
/// # Returns
/// * `ContainerInfo` - Container detection results
pub fn detect_container_from_cgroup(cgroup_path: &str) -> ContainerInfo {
    let mut info = ContainerInfo {
        provenance: ContainerProvenance {
            cgroup_path: Some(cgroup_path.to_string()),
            ..Default::default()
        },
        ..Default::default()
    };

    // Kubernetes patterns: /kubepods/... or /kubepods.slice/...
    // Check this before runtime-specific extractors so we preserve Kubernetes metadata
    // for docker/containerd/crio paths nested under kubepods.
    if let Some(k8s_info) = extract_kubernetes_info(cgroup_path) {
        info.in_container = true;
        info.runtime = if cgroup_path.contains("crio") {
            ContainerRuntime::Crio
        } else if cgroup_path.contains("containerd") {
            ContainerRuntime::Containerd
        } else if cgroup_path.contains("docker") {
            ContainerRuntime::Docker
        } else {
            ContainerRuntime::Generic
        };
        info.container_id = k8s_info.container_id.clone();
        info.container_id_short = k8s_info
            .container_id
            .as_ref()
            .map(|id| id[..12.min(id.len())].to_string());
        info.kubernetes = Some(k8s_info.k8s);
        info.provenance.source = ContainerDetectionSource::CgroupPath;
        return info;
    }

    // Docker pattern: /docker/<container_id> or /docker-<container_id>
    if let Some(id) = extract_docker_id(cgroup_path) {
        info.in_container = true;
        info.runtime = ContainerRuntime::Docker;
        info.container_id_short = Some(id[..12.min(id.len())].to_string());
        info.container_id = Some(id);
        info.provenance.source = ContainerDetectionSource::CgroupPath;
        return info;
    }

    // Podman pattern: /libpod-<container_id> or /machine.slice/libpod-...
    if let Some(id) = extract_podman_id(cgroup_path) {
        info.in_container = true;
        info.runtime = ContainerRuntime::Podman;
        info.container_id_short = Some(id[..12.min(id.len())].to_string());
        info.container_id = Some(id);
        info.provenance.source = ContainerDetectionSource::CgroupPath;
        return info;
    }

    // containerd pattern: /containerd/<namespace>/<container_id>
    if let Some(id) = extract_containerd_id(cgroup_path) {
        info.in_container = true;
        info.runtime = ContainerRuntime::Containerd;
        info.container_id_short = Some(id[..12.min(id.len())].to_string());
        info.container_id = Some(id);
        info.provenance.source = ContainerDetectionSource::CgroupPath;
        return info;
    }

    // LXC/LXD pattern: /lxc/<container_name> or /lxc.payload.<name>
    if let Some(id) = extract_lxc_id(cgroup_path) {
        info.in_container = true;
        info.runtime = ContainerRuntime::Lxc;
        info.container_id_short = Some(id.clone());
        info.container_id = Some(id);
        info.provenance.source = ContainerDetectionSource::CgroupPath;
        return info;
    }

    info
}

/// Detect container by checking for marker files.
///
/// Should be called for processes where cgroup detection didn't find a container.
pub fn detect_container_from_markers() -> Option<ContainerInfo> {
    // Check for Docker marker
    if fs::metadata("/.dockerenv").is_ok() {
        return Some(ContainerInfo {
            in_container: true,
            runtime: ContainerRuntime::Docker,
            provenance: ContainerProvenance {
                source: ContainerDetectionSource::MarkerFile,
                ..Default::default()
            },
            ..Default::default()
        });
    }

    // Check for container indication in /proc/1/cgroup
    if let Ok(content) = fs::read_to_string("/proc/1/cgroup") {
        for line in content.lines() {
            let mut parts = line.splitn(3, ':');
            let _ = parts.next();
            let _ = parts.next();
            if let Some(path) = parts.next() {
                let info = detect_container_from_cgroup(path);
                if info.in_container {
                    return Some(info);
                }
            }
        }
    }

    None
}

/// Detect container info from environment variables (for K8s).
pub fn detect_kubernetes_from_env(env: &HashMap<String, String>) -> Option<KubernetesInfo> {
    let pod_name = env.get("HOSTNAME").or_else(|| env.get("POD_NAME")).cloned();
    let namespace = env
        .get("POD_NAMESPACE")
        .or_else(|| env.get("KUBERNETES_NAMESPACE"))
        .cloned();

    // K8s service account indicates K8s environment
    let is_k8s = env.contains_key("KUBERNETES_SERVICE_HOST")
        || env.contains_key("KUBERNETES_PORT")
        || namespace.is_some();

    if is_k8s {
        Some(KubernetesInfo {
            pod_name,
            namespace,
            pod_uid: env.get("POD_UID").cloned(),
            container_name: env.get("CONTAINER_NAME").cloned(),
            qos_class: None,
        })
    } else {
        None
    }
}

/// Extract Docker container ID from cgroup path.
fn extract_docker_id(path: &str) -> Option<String> {
    // Patterns:
    // /docker/<64-char-hex>
    // /docker-<64-char-hex>.scope
    // /system.slice/docker-<64-char-hex>.scope

    // Try /docker/<id> pattern
    if let Some(idx) = path.find("/docker/") {
        let after = &path[idx + 8..];
        let id = after.split('/').next()?;
        if is_container_id(id) {
            return Some(id.to_string());
        }
    }

    // Try docker-<id>.scope pattern (handle optional subpaths)
    if let Some(idx) = path.find("docker-") {
        let after = &path[idx + 7..];
        let first = after.split('/').next()?;
        let id = first.strip_suffix(".scope").unwrap_or(first);
        if is_container_id(id) {
            return Some(id.to_string());
        }
    }

    None
}

/// Extract Podman container ID from cgroup path.
fn extract_podman_id(path: &str) -> Option<String> {
    // Patterns:
    // /libpod-<64-char-hex>
    // /machine.slice/libpod-<64-char-hex>.scope

    if let Some(idx) = path.find("libpod-") {
        let after = &path[idx + 7..];
        let first = after.split('/').next()?;
        let id = first.strip_suffix(".scope").unwrap_or(first);
        if is_container_id(id) {
            return Some(id.to_string());
        }
    }

    None
}

/// Extract containerd container ID from cgroup path.
fn extract_containerd_id(path: &str) -> Option<String> {
    // Patterns:
    // /containerd/<namespace>/<id>
    // /system.slice/containerd.service/.../<id>

    if let Some(idx) = path.find("/containerd/") {
        let after = &path[idx + 12..];
        // Prefer the last segment that looks like a container ID.
        for part in after.split('/').rev() {
            let candidate = part.strip_suffix(".scope").unwrap_or(part);
            if is_container_id(candidate) {
                return Some(candidate.to_string());
            }
        }
    }

    None
}

/// Extract LXC/LXD container name from cgroup path.
fn extract_lxc_id(path: &str) -> Option<String> {
    // Patterns:
    // /lxc/<container_name>
    // /lxc.payload.<container_name>/...

    if let Some(idx) = path.find("/lxc/") {
        let after = &path[idx + 5..];
        let name = after.split('/').next()?;
        if !name.is_empty() {
            return Some(name.to_string());
        }
    }

    if let Some(idx) = path.find("lxc.payload.") {
        let after = &path[idx + 12..];
        let name = after.split('/').next()?;
        let name = name.split('.').next()?; // Remove any suffix
        if !name.is_empty() {
            return Some(name.to_string());
        }
    }

    None
}

/// Intermediate structure for K8s extraction.
struct K8sExtraction {
    k8s: KubernetesInfo,
    container_id: Option<String>,
}

/// Extract Kubernetes info from cgroup path.
fn extract_kubernetes_info(path: &str) -> Option<K8sExtraction> {
    // Patterns:
    // /kubepods/burstable/pod<uid>/<container_id>
    // /kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod<uid>.slice/cri-containerd-<id>.scope
    // /kubepods/besteffort/pod<uid>/crio-<id>

    if !path.contains("kubepods") {
        return None;
    }

    let mut info = KubernetesInfo::default();
    let mut container_id = None;

    // Extract QoS class
    if path.contains("burstable") {
        info.qos_class = Some("Burstable".to_string());
    } else if path.contains("besteffort") {
        info.qos_class = Some("BestEffort".to_string());
    } else if path.contains("guaranteed")
        || !path.contains("burstable") && !path.contains("besteffort")
    {
        info.qos_class = Some("Guaranteed".to_string());
    }

    // Extract pod UID
    // Pattern: pod<uid> or kubepods-*-pod<uid>
    for part in path.split('/') {
        // Direct pod<uid> pattern
        if part.starts_with("pod") && part.len() > 3 {
            let uid = &part[3..];
            // Remove .slice suffix if present
            let uid = uid.strip_suffix(".slice").unwrap_or(uid);
            if uid.contains('-') || uid.len() >= 32 {
                info.pod_uid = Some(uid.to_string());
            }
        }
        // kubepods-*-pod<uid>.slice pattern
        if part.contains("-pod") {
            if let Some(idx) = part.find("-pod") {
                let after = &part[idx + 4..];
                let uid = after.strip_suffix(".slice").unwrap_or(after);
                if !uid.is_empty() {
                    info.pod_uid = Some(uid.to_string());
                }
            }
        }
    }

    // Extract container ID
    let parts: Vec<&str> = path.split('/').collect();
    if let Some(last) = parts.last() {
        // cri-containerd-<id>.scope
        if last.starts_with("cri-containerd-") {
            let id = last
                .strip_prefix("cri-containerd-")
                .and_then(|s| s.strip_suffix(".scope"))
                .unwrap_or(last);
            if is_container_id(id) {
                container_id = Some(id.to_string());
            }
        }
        // crio-<id>.scope or crio-<id>
        else if last.starts_with("crio-") {
            let id = last
                .strip_prefix("crio-")
                .and_then(|s| s.strip_suffix(".scope").or(Some(s)))
                .unwrap_or(last);
            if is_container_id(id) {
                container_id = Some(id.to_string());
            }
        }
        // docker-<id>.scope
        else if last.starts_with("docker-") {
            let id = last
                .strip_prefix("docker-")
                .and_then(|s| s.strip_suffix(".scope"))
                .unwrap_or(last);
            if is_container_id(id) {
                container_id = Some(id.to_string());
            }
        }
        // Plain container ID (64 hex chars)
        else if is_container_id(last) {
            container_id = Some(last.to_string());
        }
    }

    Some(K8sExtraction {
        k8s: info,
        container_id,
    })
}

/// Check if a string looks like a container ID (64 hex chars).
fn is_container_id(s: &str) -> bool {
    // Container IDs are typically 64 hex characters
    // But can be truncated in some contexts
    s.len() >= 12 && s.len() <= 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_docker() {
        let path = "/docker/abc123def456789012345678901234567890123456789012345678901234";
        let info = detect_container_from_cgroup(path);

        assert!(info.in_container);
        assert_eq!(info.runtime, ContainerRuntime::Docker);
        assert!(info.container_id.is_some());
        assert_eq!(info.container_id_short, Some("abc123def456".to_string()));
    }

    #[test]
    fn test_detect_docker_scope() {
        let path = "/system.slice/docker-abc123def456789012345678901234567890123456789012345678901234.scope";
        let info = detect_container_from_cgroup(path);

        assert!(info.in_container);
        assert_eq!(info.runtime, ContainerRuntime::Docker);
    }

    #[test]
    fn test_detect_docker_scope_with_subpath() {
        let path = "/system.slice/docker-abc123def456789012345678901234567890123456789012345678901234.scope/xyz";
        let info = detect_container_from_cgroup(path);

        assert!(info.in_container);
        assert_eq!(info.runtime, ContainerRuntime::Docker);
        assert!(info.container_id.is_some());
    }

    #[test]
    fn test_detect_podman() {
        let path = "/machine.slice/libpod-abc123def456789012345678901234567890123456789012345678901234.scope";
        let info = detect_container_from_cgroup(path);

        assert!(info.in_container);
        assert_eq!(info.runtime, ContainerRuntime::Podman);
    }

    #[test]
    fn test_detect_podman_scope_with_subpath() {
        let path = "/machine.slice/libpod-abc123def456789012345678901234567890123456789012345678901234.scope/xyz";
        let info = detect_container_from_cgroup(path);

        assert!(info.in_container);
        assert_eq!(info.runtime, ContainerRuntime::Podman);
        assert!(info.container_id.is_some());
    }

    #[test]
    fn test_detect_containerd() {
        let path =
            "/containerd/default/abc123def456789012345678901234567890123456789012345678901234";
        let info = detect_container_from_cgroup(path);

        assert!(info.in_container);
        assert_eq!(info.runtime, ContainerRuntime::Containerd);
    }

    #[test]
    fn test_detect_containerd_deep_path() {
        let path = "/containerd/io.containerd.runtime.v2.task/default/abc123def456789012345678901234567890123456789012345678901234";
        let info = detect_container_from_cgroup(path);

        assert!(info.in_container);
        assert_eq!(info.runtime, ContainerRuntime::Containerd);
        assert!(info.container_id.is_some());
    }

    #[test]
    fn test_detect_lxc() {
        let path = "/lxc/mycontainer/init.scope";
        let info = detect_container_from_cgroup(path);

        assert!(info.in_container);
        assert_eq!(info.runtime, ContainerRuntime::Lxc);
        assert_eq!(info.container_id, Some("mycontainer".to_string()));
    }

    #[test]
    fn test_detect_kubernetes_burstable() {
        let path = "/kubepods/burstable/pod12345678-1234-1234-1234-123456789012/cri-containerd-abc123def456789012345678901234567890123456789012345678901234.scope";
        let info = detect_container_from_cgroup(path);

        assert!(info.in_container);
        assert_eq!(info.runtime, ContainerRuntime::Containerd);
        assert!(info.kubernetes.is_some());

        let k8s = info.kubernetes.unwrap();
        assert_eq!(k8s.qos_class, Some("Burstable".to_string()));
        assert!(k8s.pod_uid.is_some());
    }

    #[test]
    fn test_detect_kubernetes_crio() {
        let path = "/kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod12345678_1234_1234_1234_123456789012.slice/crio-abc123def456789012345678901234567890123456789012345678901234.scope";
        let info = detect_container_from_cgroup(path);

        assert!(info.in_container);
        assert_eq!(info.runtime, ContainerRuntime::Crio);
        assert!(info.kubernetes.is_some());

        let k8s = info.kubernetes.unwrap();
        assert_eq!(k8s.qos_class, Some("BestEffort".to_string()));
    }

    #[test]
    fn test_detect_kubernetes_docker_runtime_preserves_k8s_metadata() {
        let path = "/kubepods/burstable/pod12345678-1234-1234-1234-123456789012/docker-abc123def456789012345678901234567890123456789012345678901234.scope";
        let info = detect_container_from_cgroup(path);

        assert!(info.in_container);
        assert_eq!(info.runtime, ContainerRuntime::Docker);
        assert!(info.kubernetes.is_some());
        assert!(info.container_id.is_some());
    }

    #[test]
    fn test_detect_not_container() {
        let path = "/user.slice/user-1000.slice/session-1.scope";
        let info = detect_container_from_cgroup(path);

        assert!(!info.in_container);
        assert_eq!(info.runtime, ContainerRuntime::None);
    }

    #[test]
    fn test_is_container_id() {
        assert!(is_container_id("abc123def456"));
        assert!(is_container_id(
            "abc123def456789012345678901234567890123456789012345678901234"
        ));
        assert!(!is_container_id("abc")); // Too short
        assert!(!is_container_id("not-hex-chars!")); // Invalid chars
    }

    #[test]
    fn test_detect_k8s_from_env() {
        let mut env = HashMap::new();
        env.insert(
            "KUBERNETES_SERVICE_HOST".to_string(),
            "10.0.0.1".to_string(),
        );
        env.insert("HOSTNAME".to_string(), "my-pod-abc123".to_string());
        env.insert("POD_NAMESPACE".to_string(), "default".to_string());

        let k8s = detect_kubernetes_from_env(&env);
        assert!(k8s.is_some());

        let k8s = k8s.unwrap();
        assert_eq!(k8s.pod_name, Some("my-pod-abc123".to_string()));
        assert_eq!(k8s.namespace, Some("default".to_string()));
    }

    #[test]
    fn test_detect_k8s_from_env_not_k8s() {
        let env = HashMap::new();
        let k8s = detect_kubernetes_from_env(&env);
        assert!(k8s.is_none());
    }

    #[test]
    fn test_container_id_short() {
        let path = "/docker/abc123def456789012345678901234567890123456789012345678901234";
        let info = detect_container_from_cgroup(path);

        assert_eq!(info.container_id_short, Some("abc123def456".to_string()));
    }

    // =====================================================
    // No-mock tests using real system detection
    // =====================================================

    #[test]
    fn test_nomock_detect_container_from_markers_no_panic() {
        // This test just verifies detect_container_from_markers doesn't panic
        // and returns a reasonable result on any system
        crate::test_log!(INFO, "container marker detection test starting");

        let result = detect_container_from_markers();

        crate::test_log!(
            INFO,
            "container marker detection result",
            detected = result.is_some(),
            runtime = format!("{:?}", result.as_ref().map(|r| &r.runtime)).as_str()
        );

        // If we're in a container, we should have detected it
        // If not, the result should be None
        if let Some(info) = result {
            assert!(info.in_container);
            crate::test_log!(
                INFO,
                "container detected from markers",
                runtime = format!("{:?}", info.runtime).as_str(),
                source = format!("{:?}", info.provenance.source).as_str()
            );
        }
    }

    #[test]
    fn test_nomock_detect_container_from_real_cgroup() {
        // Test container detection using our actual cgroup path
        if !std::path::Path::new("/proc/self/cgroup").exists() {
            crate::test_log!(
                INFO,
                "Skipping no-mock test: /proc/self/cgroup not available"
            );
            return;
        }

        let content = match std::fs::read_to_string("/proc/self/cgroup") {
            Ok(c) => c,
            Err(e) => {
                crate::test_log!(
                    INFO,
                    "Skipping test: cannot read cgroup",
                    error = format!("{}", e).as_str()
                );
                return;
            }
        };

        crate::test_log!(INFO, "container detection from real cgroup test");

        // Try to find a cgroup path to test with
        for line in content.lines() {
            let parts: Vec<&str> = line.splitn(3, ':').collect();
            if parts.len() >= 3 {
                let path = parts[2];
                let info = detect_container_from_cgroup(path);

                crate::test_log!(
                    INFO,
                    "container detection result",
                    cgroup_path = path,
                    in_container = info.in_container,
                    runtime = format!("{:?}", info.runtime).as_str()
                );

                // The detection should not panic and should return consistent results
                if info.in_container {
                    assert_ne!(info.runtime, ContainerRuntime::None);
                } else {
                    assert_eq!(info.runtime, ContainerRuntime::None);
                }
            }
        }
    }

    #[test]
    fn test_nomock_detect_kubernetes_from_env_real() {
        // Test K8s detection using real environment (won't detect K8s in most test envs)
        let env: HashMap<String, String> = std::env::vars().collect();

        crate::test_log!(INFO, "kubernetes env detection test", env_count = env.len());

        let result = detect_kubernetes_from_env(&env);

        crate::test_log!(
            INFO,
            "kubernetes env detection result",
            is_k8s = result.is_some()
        );

        // If K8s is detected, verify the info is reasonable
        if let Some(k8s) = result {
            crate::test_log!(
                INFO,
                "kubernetes detected",
                pod_name = k8s.pod_name.as_deref().unwrap_or("none"),
                namespace = k8s.namespace.as_deref().unwrap_or("none")
            );
        }
    }

    #[test]
    fn test_nomock_container_detection_spawned_process() {
        use crate::collect::cgroup::collect_cgroup_details;
        use crate::test_utils::ProcessHarness;

        if !ProcessHarness::is_available() {
            crate::test_log!(INFO, "Skipping no-mock test: ProcessHarness not available");
            return;
        }

        let harness = ProcessHarness::default();
        let proc = harness
            .spawn_shell("sleep 30")
            .expect("spawn sleep process");

        crate::test_log!(
            INFO,
            "container detection for spawned process",
            pid = proc.pid()
        );

        // Get cgroup details first
        if let Some(cgroup_details) = collect_cgroup_details(proc.pid()) {
            // Try container detection on the unified path if available
            if let Some(ref unified_path) = cgroup_details.unified_path {
                let container_info = detect_container_from_cgroup(unified_path);

                crate::test_log!(
                    INFO,
                    "container detection from spawned process cgroup",
                    pid = proc.pid(),
                    cgroup_path = unified_path.as_str(),
                    in_container = container_info.in_container,
                    runtime = format!("{:?}", container_info.runtime).as_str()
                );
            }
        } else {
            crate::test_log!(
                INFO,
                "No cgroup details available for spawned process",
                pid = proc.pid()
            );
        }
    }
}
