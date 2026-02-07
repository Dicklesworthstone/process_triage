//! Container supervision detection.
//!
//! This module detects container-based supervision: processes running inside
//! Docker, containerd, Podman, or Kubernetes containers. Container-managed
//! processes should be handled via their supervisor (docker stop, kubectl delete pod)
//! rather than direct signals.
//!
//! # Why This Matters
//!
//! Killing a containerized process directly often triggers immediate respawn
//! by the container runtime's restart policy. The correct action is usually
//! to stop/remove the container via its management interface.
//!
//! # Safety
//!
//! By default, this module does NOT recommend destructive container actions.
//! It only provides detection and attribution. Container-level actions
//! (docker stop, kubectl delete pod) require explicit policy allowance.

use crate::collect::cgroup::{collect_cgroup_details, CgroupDetails};
use crate::collect::container::{
    detect_container_from_cgroup, detect_kubernetes_from_env, ContainerInfo, ContainerRuntime,
    KubernetesInfo,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use thiserror::Error;

use super::types::{EvidenceType, SupervisionEvidence};

/// Errors from container supervision detection.
#[derive(Debug, Error)]
pub enum ContainerSupervisionError {
    #[error("Process {0} not found")]
    ProcessNotFound(u32),

    #[error("Cannot read cgroup for process {0}: {1}")]
    CgroupReadError(u32, String),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Result of container supervision detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerSupervisionResult {
    /// The process ID analyzed.
    pub pid: u32,

    /// Whether the process is running in a container.
    pub in_container: bool,

    /// Whether this qualifies as supervision (container = supervisor).
    pub is_supervised: bool,

    /// Container runtime type.
    pub runtime: ContainerRuntime,

    /// Container ID (full).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_id: Option<String>,

    /// Container ID (short, first 12 chars).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_id_short: Option<String>,

    /// Kubernetes-specific information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kubernetes: Option<KubernetesInfo>,

    /// Confidence score (0.0-1.0).
    pub confidence: f64,

    /// Evidence supporting the detection.
    pub evidence: Vec<SupervisionEvidence>,

    /// Recommended supervisor action (if policy allows).
    /// NOTE: By default, destructive actions are NOT recommended.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommended_action: Option<ContainerAction>,

    /// Explanation for humans/agents.
    pub explanation: String,
}

impl ContainerSupervisionResult {
    /// Create a result indicating no container detected.
    pub fn not_in_container(pid: u32) -> Self {
        Self {
            pid,
            in_container: false,
            is_supervised: false,
            runtime: ContainerRuntime::None,
            container_id: None,
            container_id_short: None,
            kubernetes: None,
            confidence: 1.0,
            evidence: vec![],
            recommended_action: None,
            explanation: "Process is not running in a container".to_string(),
        }
    }
}

/// Container-level action recommendation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerAction {
    /// Action type.
    pub action_type: ContainerActionType,

    /// Command to execute (for reference, NOT auto-executed).
    pub command: String,

    /// Whether this action is considered safe (non-destructive).
    pub is_safe: bool,

    /// Warning message if action is destructive.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

/// Types of container-level actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerActionType {
    /// Stop the container (graceful).
    Stop,
    /// Restart the container.
    Restart,
    /// Remove/delete the container.
    Remove,
    /// Scale down (K8s).
    ScaleDown,
    /// Delete pod (K8s).
    DeletePod,
    /// Inspect only (read-only).
    Inspect,
}

/// Analyzer for container-based supervision.
pub struct ContainerSupervisionAnalyzer {
    /// Whether to include action recommendations (default: false for safety).
    include_action_recommendations: bool,

    /// Policy: allow destructive container actions (default: false).
    allow_destructive_actions: bool,
}

impl ContainerSupervisionAnalyzer {
    /// Create a new analyzer with safe defaults.
    pub fn new() -> Self {
        Self {
            include_action_recommendations: false,
            allow_destructive_actions: false,
        }
    }

    /// Create an analyzer that includes action recommendations.
    ///
    /// NOTE: Destructive actions are still not recommended by default.
    /// Use `with_destructive_actions(true)` to enable those.
    pub fn with_action_recommendations(mut self) -> Self {
        self.include_action_recommendations = true;
        self
    }

    /// Allow destructive action recommendations.
    ///
    /// WARNING: Only enable this if policy explicitly allows container-level actions.
    pub fn with_destructive_actions(mut self, allow: bool) -> Self {
        self.allow_destructive_actions = allow;
        self
    }

    /// Analyze a process for container supervision.
    pub fn analyze(
        &self,
        pid: u32,
    ) -> Result<ContainerSupervisionResult, ContainerSupervisionError> {
        // Get cgroup details for the process
        let cgroup_details = collect_cgroup_details(pid)
            .ok_or(ContainerSupervisionError::ProcessNotFound(pid))?;

        // Get cgroup path to analyze
        let cgroup_path = self.get_cgroup_path(&cgroup_details);

        if cgroup_path.is_none() {
            return Ok(ContainerSupervisionResult::not_in_container(pid));
        }
        let cgroup_path = cgroup_path.unwrap();

        // Detect container from cgroup path
        let container_info = detect_container_from_cgroup(&cgroup_path);

        if !container_info.in_container {
            return Ok(ContainerSupervisionResult::not_in_container(pid));
        }

        // Build result
        let mut result = self.build_result(pid, &container_info, &cgroup_path);

        // Enrich with K8s info from environment if available
        if let Some(env) = self.read_environ(pid) {
            if let Some(k8s_info) = detect_kubernetes_from_env(&env) {
                // Merge K8s info
                if result.kubernetes.is_none() {
                    result.kubernetes = Some(k8s_info.clone());
                } else if let Some(ref mut existing) = result.kubernetes {
                    // Enrich existing info
                    if existing.pod_name.is_none() {
                        existing.pod_name = k8s_info.pod_name;
                    }
                    if existing.namespace.is_none() {
                        existing.namespace = k8s_info.namespace;
                    }
                    if existing.container_name.is_none() {
                        existing.container_name = k8s_info.container_name;
                    }
                }

                // Add evidence for K8s detection
                result.evidence.push(SupervisionEvidence {
                    evidence_type: EvidenceType::Environment,
                    description:
                        "Process has Kubernetes environment variables (KUBERNETES_SERVICE_HOST)"
                            .to_string(),
                    weight: 0.3,
                });
            }
        }

        // Add action recommendations if enabled
        if self.include_action_recommendations {
            result.recommended_action = self.generate_action_recommendation(&result);
        }

        Ok(result)
    }

    /// Get the most relevant cgroup path for container detection.
    fn get_cgroup_path(&self, details: &CgroupDetails) -> Option<String> {
        // Prefer unified (v2) path
        if let Some(ref path) = details.unified_path {
            return Some(path.clone());
        }

        // Fall back to any v1 controller path
        details.v1_paths.values().next().cloned()
    }

    /// Build the supervision result from container info.
    fn build_result(
        &self,
        pid: u32,
        info: &ContainerInfo,
        cgroup_path: &str,
    ) -> ContainerSupervisionResult {
        let runtime_name = match info.runtime {
            ContainerRuntime::Docker => "Docker",
            ContainerRuntime::Containerd => "containerd",
            ContainerRuntime::Podman => "Podman",
            ContainerRuntime::Lxc => "LXC/LXD",
            ContainerRuntime::Crio => "CRI-O",
            ContainerRuntime::Generic => "container",
            ContainerRuntime::None => "none",
        };

        let explanation = if let Some(ref k8s) = info.kubernetes {
            format!(
                "Process is running in {} container{} (K8s {})",
                runtime_name,
                info.container_id_short
                    .as_ref()
                    .map(|id| format!(" {}", id))
                    .unwrap_or_default(),
                k8s.qos_class.as_deref().unwrap_or("pod")
            )
        } else {
            format!(
                "Process is running in {} container{}",
                runtime_name,
                info.container_id_short
                    .as_ref()
                    .map(|id| format!(" {}", id))
                    .unwrap_or_default()
            )
        };

        let mut evidence = vec![SupervisionEvidence {
            evidence_type: EvidenceType::Ancestry,
            description: format!(
                "Cgroup path {} indicates {} container",
                cgroup_path, runtime_name
            ),
            weight: 0.9,
        }];

        // Add K8s-specific evidence
        if info.kubernetes.is_some() {
            evidence.push(SupervisionEvidence {
                evidence_type: EvidenceType::Ancestry,
                description: "Process is in a Kubernetes pod (kubepods cgroup)".to_string(),
                weight: 0.8,
            });
        }

        ContainerSupervisionResult {
            pid,
            in_container: true,
            is_supervised: true, // Container = supervisor
            runtime: info.runtime,
            container_id: info.container_id.clone(),
            container_id_short: info.container_id_short.clone(),
            kubernetes: info.kubernetes.clone(),
            confidence: 0.95, // High confidence from cgroup detection
            evidence,
            recommended_action: None, // Set later if enabled
            explanation,
        }
    }

    /// Read process environment variables.
    #[cfg(target_os = "linux")]
    fn read_environ(&self, pid: u32) -> Option<HashMap<String, String>> {
        let path = format!("/proc/{}/environ", pid);
        let content = fs::read(&path).ok()?;

        let mut env = HashMap::new();
        for entry in content.split(|&b| b == 0) {
            if let Ok(s) = std::str::from_utf8(entry) {
                if let Some(eq_pos) = s.find('=') {
                    let key = &s[..eq_pos];
                    let value = &s[eq_pos + 1..];
                    env.insert(key.to_string(), value.to_string());
                }
            }
        }

        Some(env)
    }

    #[cfg(not(target_os = "linux"))]
    fn read_environ(&self, _pid: u32) -> Option<HashMap<String, String>> {
        None
    }

    /// Generate action recommendation based on container type.
    fn generate_action_recommendation(
        &self,
        result: &ContainerSupervisionResult,
    ) -> Option<ContainerAction> {
        if !result.in_container {
            return None;
        }

        // Kubernetes pods
        if let Some(ref k8s) = result.kubernetes {
            let namespace = k8s.namespace.as_deref().unwrap_or("default");
            let pod_name = k8s.pod_name.as_deref()?;

            if self.allow_destructive_actions {
                return Some(ContainerAction {
                    action_type: ContainerActionType::DeletePod,
                    command: format!("kubectl delete pod {} -n {}", pod_name, namespace),
                    is_safe: false,
                    warning: Some(
                        "Deleting pod will terminate all containers. Consider scaling down instead."
                            .to_string(),
                    ),
                });
            } else {
                // Suggest inspect only
                return Some(ContainerAction {
                    action_type: ContainerActionType::Inspect,
                    command: format!("kubectl describe pod {} -n {}", pod_name, namespace),
                    is_safe: true,
                    warning: None,
                });
            }
        }

        // Docker/Podman containers
        let container_id = result.container_id_short.as_ref()?;

        match result.runtime {
            ContainerRuntime::Docker => {
                if self.allow_destructive_actions {
                    Some(ContainerAction {
                        action_type: ContainerActionType::Stop,
                        command: format!("docker stop {}", container_id),
                        is_safe: false,
                        warning: Some(
                            "Stopping container may affect dependent services.".to_string(),
                        ),
                    })
                } else {
                    Some(ContainerAction {
                        action_type: ContainerActionType::Inspect,
                        command: format!("docker inspect {}", container_id),
                        is_safe: true,
                        warning: None,
                    })
                }
            }
            ContainerRuntime::Podman => {
                if self.allow_destructive_actions {
                    Some(ContainerAction {
                        action_type: ContainerActionType::Stop,
                        command: format!("podman stop {}", container_id),
                        is_safe: false,
                        warning: Some(
                            "Stopping container may affect dependent services.".to_string(),
                        ),
                    })
                } else {
                    Some(ContainerAction {
                        action_type: ContainerActionType::Inspect,
                        command: format!("podman inspect {}", container_id),
                        is_safe: true,
                        warning: None,
                    })
                }
            }
            ContainerRuntime::Containerd => Some(ContainerAction {
                action_type: ContainerActionType::Inspect,
                command: format!("ctr container info {}", container_id),
                is_safe: true,
                warning: None,
            }),
            ContainerRuntime::Lxc => Some(ContainerAction {
                action_type: ContainerActionType::Inspect,
                command: format!("lxc info {}", container_id),
                is_safe: true,
                warning: None,
            }),
            _ => None,
        }
    }
}

impl Default for ContainerSupervisionAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience function to detect container supervision.
pub fn detect_container_supervision(
    pid: u32,
) -> Result<ContainerSupervisionResult, ContainerSupervisionError> {
    let analyzer = ContainerSupervisionAnalyzer::new();
    analyzer.analyze(pid)
}

/// Detect container supervision with action recommendations.
///
/// NOTE: Destructive actions are still NOT recommended by default.
pub fn detect_container_supervision_with_actions(
    pid: u32,
) -> Result<ContainerSupervisionResult, ContainerSupervisionError> {
    let analyzer = ContainerSupervisionAnalyzer::new().with_action_recommendations();
    analyzer.analyze(pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_container_supervision_analyzer_new() {
        let analyzer = ContainerSupervisionAnalyzer::new();
        assert!(!analyzer.include_action_recommendations);
        assert!(!analyzer.allow_destructive_actions);
    }

    #[test]
    fn test_container_supervision_analyzer_with_actions() {
        let analyzer = ContainerSupervisionAnalyzer::new()
            .with_action_recommendations()
            .with_destructive_actions(true);
        assert!(analyzer.include_action_recommendations);
        assert!(analyzer.allow_destructive_actions);
    }

    #[test]
    fn test_container_supervision_result_not_in_container() {
        let result = ContainerSupervisionResult::not_in_container(1234);
        assert!(!result.in_container);
        assert!(!result.is_supervised);
        assert_eq!(result.runtime, ContainerRuntime::None);
    }

    #[test]
    fn test_container_action_type_serialization() {
        let action = ContainerAction {
            action_type: ContainerActionType::Stop,
            command: "docker stop abc123".to_string(),
            is_safe: false,
            warning: Some("Test warning".to_string()),
        };

        let json = serde_json::to_string(&action).unwrap();
        assert!(json.contains("\"action_type\":\"stop\""));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_detect_container_supervision_current_process() {
        let pid = std::process::id();
        let result = detect_container_supervision(pid);

        // Should succeed for current process
        assert!(result.is_ok());

        let result = result.unwrap();
        // May or may not be in a container depending on environment
        assert!(result.confidence >= 0.0 && result.confidence <= 1.0);

        crate::test_log!(
            INFO,
            "container supervision test",
            pid = pid,
            in_container = result.in_container,
            runtime = format!("{:?}", result.runtime).as_str()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_detect_container_supervision_with_actions_current_process() {
        let pid = std::process::id();
        let result = detect_container_supervision_with_actions(pid);

        assert!(result.is_ok());
        let result = result.unwrap();

        // If in a container, should have a (safe) action recommendation
        if result.in_container {
            if let Some(ref action) = result.recommended_action {
                // Without allow_destructive_actions, should only suggest Inspect
                assert!(action.is_safe);
                assert_eq!(action.action_type, ContainerActionType::Inspect);
            }
        }
    }

    // =====================================================
    // No-mock tests using real processes
    // =====================================================

    #[cfg(target_os = "linux")]
    #[test]
    fn test_nomock_container_supervision_spawned_process() {
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
            "container supervision spawned process test",
            pid = proc.pid()
        );

        let result = detect_container_supervision(proc.pid());
        assert!(result.is_ok());

        let result = result.unwrap();
        crate::test_log!(
            INFO,
            "container supervision result",
            pid = proc.pid(),
            in_container = result.in_container,
            runtime = format!("{:?}", result.runtime).as_str(),
            has_k8s = result.kubernetes.is_some()
        );

        // Verify result consistency
        if result.in_container {
            assert!(result.is_supervised);
            assert_ne!(result.runtime, ContainerRuntime::None);
        } else {
            assert!(!result.is_supervised);
            assert_eq!(result.runtime, ContainerRuntime::None);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_nomock_container_action_recommendations() {
        // Test that action recommendations are generated correctly
        let analyzer = ContainerSupervisionAnalyzer::new()
            .with_action_recommendations()
            .with_destructive_actions(false);

        let pid = std::process::id();
        let result = analyzer.analyze(pid);

        assert!(result.is_ok());
        let result = result.unwrap();

        crate::test_log!(
            INFO,
            "action recommendation test",
            pid = pid,
            in_container = result.in_container,
            has_action = result.recommended_action.is_some()
        );

        // If in container, action should be safe (inspect only)
        if let Some(ref action) = result.recommended_action {
            crate::test_log!(
                INFO,
                "recommended action",
                action_type = format!("{:?}", action.action_type).as_str(),
                command = action.command.as_str(),
                is_safe = action.is_safe
            );
            assert!(
                action.is_safe,
                "Non-destructive mode should only suggest safe actions"
            );
        }
    }
}
