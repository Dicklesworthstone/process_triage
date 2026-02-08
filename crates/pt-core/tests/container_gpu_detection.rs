//! Integration tests for container detection and GPU process detection.
//!
//! Container detection tests use cgroup path patterns (no Docker required).
//! GPU tests use mock nvidia-smi/rocm-smi output (no GPU required).

use std::collections::HashMap;

// Container detection types
use pt_core::collect::{
    detect_container_from_cgroup, detect_kubernetes_from_env, ContainerDetectionSource,
    ContainerRuntime,
};

// GPU detection types
use pt_core::collect::gpu::{
    parse_nvidia_device_csv, parse_nvidia_process_csv, parse_rocm_json, parse_rocm_process_json,
    parse_rocm_text, GpuDetectionSource, GpuDevice, GpuProvenance, GpuSnapshot, GpuType,
    ProcessGpuUsage,
};
use pt_core::collect::{gpu_usage_for_pid, total_vram_mib_for_pid};

// ===========================================================================
// 1. Container Detection: Docker
// ===========================================================================

#[test]
fn container_detect_docker_standard_cgroup() {
    let info = detect_container_from_cgroup(
        "/system.slice/docker-abc123def456789012345678901234567890123456789012345678901234.scope",
    );
    assert!(info.in_container);
    assert_eq!(info.runtime, ContainerRuntime::Docker);
    assert!(info.container_id.is_some());
    assert!(info.container_id_short.is_some());
    assert_eq!(info.container_id_short.as_deref().unwrap().len(), 12);
}

#[test]
fn container_detect_docker_short_path() {
    let info = detect_container_from_cgroup(
        "/docker/abc123def456789012345678901234567890123456789012345678901234",
    );
    assert!(info.in_container);
    assert_eq!(info.runtime, ContainerRuntime::Docker);
    assert!(info.container_id.is_some());
}

#[test]
fn container_detect_docker_scope_format() {
    let info = detect_container_from_cgroup(
        "/docker-abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678.scope",
    );
    assert!(info.in_container);
    assert_eq!(info.runtime, ContainerRuntime::Docker);
}

// ===========================================================================
// 2. Container Detection: Podman
// ===========================================================================

#[test]
fn container_detect_podman_libpod() {
    let info = detect_container_from_cgroup(
        "/machine.slice/libpod-abc123def456789012345678901234567890123456789012345678901234.scope",
    );
    assert!(info.in_container);
    assert_eq!(info.runtime, ContainerRuntime::Podman);
    assert!(info.container_id.is_some());
}

// ===========================================================================
// 3. Container Detection: containerd
// ===========================================================================

#[test]
fn container_detect_containerd() {
    let info = detect_container_from_cgroup(
        "/system.slice/containerd.service/kubepods-burstable-pod12345.slice:cri-containerd:abc123def456789012345678901234567890123456789012345678901234",
    );
    assert!(info.in_container);
    // Should detect as containerd (or kubernetes + containerd depending on path)
    assert!(
        info.runtime == ContainerRuntime::Containerd || info.runtime == ContainerRuntime::Docker,
        "expected containerd or docker, got {:?}",
        info.runtime
    );
}

// ===========================================================================
// 4. Container Detection: LXC
// ===========================================================================

#[test]
fn container_detect_lxc() {
    let info = detect_container_from_cgroup("/lxc/my-container");
    assert!(info.in_container);
    assert_eq!(info.runtime, ContainerRuntime::Lxc);
}

#[test]
fn container_detect_lxc_payload() {
    let info = detect_container_from_cgroup("/lxc.payload.my-container");
    assert!(info.in_container);
    assert_eq!(info.runtime, ContainerRuntime::Lxc);
}

// ===========================================================================
// 5. Container Detection: Kubernetes
// ===========================================================================

#[test]
fn container_detect_k8s_burstable_docker() {
    let info = detect_container_from_cgroup(
        "/kubepods/burstable/pod12345678-1234-1234-1234-123456789abc/docker-abc123def456789012345678901234567890123456789012345678901234",
    );
    assert!(info.in_container);
    assert!(info.kubernetes.is_some());
    let k8s = info.kubernetes.as_ref().unwrap();
    assert_eq!(k8s.qos_class.as_deref(), Some("Burstable"));
}

#[test]
fn container_detect_k8s_besteffort() {
    let info = detect_container_from_cgroup(
        "/kubepods/besteffort/podabc12345-def6-7890-abcd-ef1234567890/crio-abc123def456789012345678901234567890123456789012345678901234",
    );
    assert!(info.in_container);
    assert!(info.kubernetes.is_some());
    let k8s = info.kubernetes.as_ref().unwrap();
    assert_eq!(k8s.qos_class.as_deref(), Some("BestEffort"));
}

#[test]
fn container_detect_k8s_guaranteed() {
    // Guaranteed QoS pods are directly under kubepods (no burstable/besteffort sub-path)
    let info = detect_container_from_cgroup(
        "/kubepods/podabc12345-def6-7890-abcd-ef1234567890/docker-abc123def456789012345678901234567890123456789012345678901234",
    );
    assert!(info.in_container);
    assert!(info.kubernetes.is_some());
}

#[test]
fn container_detect_k8s_from_environment() {
    let mut env = HashMap::new();
    env.insert(
        "KUBERNETES_SERVICE_HOST".to_string(),
        "10.0.0.1".to_string(),
    );
    env.insert("POD_NAME".to_string(), "my-app-abc123".to_string());
    env.insert("POD_NAMESPACE".to_string(), "production".to_string());
    env.insert(
        "POD_UID".to_string(),
        "12345678-1234-1234-1234-123456789abc".to_string(),
    );

    let k8s = detect_kubernetes_from_env(&env).unwrap();
    assert_eq!(k8s.pod_name.as_deref(), Some("my-app-abc123"));
    assert_eq!(k8s.namespace.as_deref(), Some("production"));
    assert_eq!(
        k8s.pod_uid.as_deref(),
        Some("12345678-1234-1234-1234-123456789abc")
    );
}

#[test]
fn container_detect_k8s_env_minimal() {
    // Only KUBERNETES_SERVICE_HOST is set — enough to detect K8s.
    let mut env = HashMap::new();
    env.insert(
        "KUBERNETES_SERVICE_HOST".to_string(),
        "10.0.0.1".to_string(),
    );

    let k8s = detect_kubernetes_from_env(&env);
    assert!(k8s.is_some());
}

#[test]
fn container_detect_k8s_env_not_k8s() {
    let env = HashMap::new();
    let k8s = detect_kubernetes_from_env(&env);
    assert!(k8s.is_none());
}

// ===========================================================================
// 6. Container Detection: Non-Container Paths
// ===========================================================================

#[test]
fn container_detect_not_container_root() {
    let info = detect_container_from_cgroup("/");
    assert!(!info.in_container);
    assert_eq!(info.runtime, ContainerRuntime::None);
    assert!(info.container_id.is_none());
}

#[test]
fn container_detect_not_container_user_slice() {
    let info = detect_container_from_cgroup("/user.slice/user-1000.slice/session-1.scope");
    assert!(!info.in_container);
    assert_eq!(info.runtime, ContainerRuntime::None);
}

#[test]
fn container_detect_not_container_system_service() {
    let info = detect_container_from_cgroup("/system.slice/nginx.service");
    assert!(!info.in_container);
    assert_eq!(info.runtime, ContainerRuntime::None);
}

#[test]
fn container_detect_empty_path() {
    let info = detect_container_from_cgroup("");
    assert!(!info.in_container);
    assert_eq!(info.runtime, ContainerRuntime::None);
}

// ===========================================================================
// 7. Container Info Provenance
// ===========================================================================

#[test]
fn container_provenance_records_source() {
    let info = detect_container_from_cgroup(
        "/docker/abc123def456789012345678901234567890123456789012345678901234",
    );
    assert_eq!(info.provenance.source, ContainerDetectionSource::CgroupPath);
    assert!(info.provenance.cgroup_path.is_some());
}

#[test]
fn container_provenance_non_container_has_none_source() {
    let info = detect_container_from_cgroup("/system.slice/sshd.service");
    // Non-container paths return source=None since no container was detected.
    assert_eq!(info.provenance.source, ContainerDetectionSource::None);
}

// ===========================================================================
// 8. Container Info Serialization
// ===========================================================================

#[test]
fn container_info_json_roundtrip() {
    let info = detect_container_from_cgroup(
        "/docker/abc123def456789012345678901234567890123456789012345678901234",
    );
    let json = serde_json::to_string(&info).unwrap();
    // Verify it's valid JSON and contains the key fields.
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["in_container"], true);
    assert_eq!(parsed["runtime"], "docker");
    assert!(parsed["container_id"].is_string());
}

#[test]
fn container_info_default_serialization() {
    let json = serde_json::to_string(&pt_core::collect::ContainerInfo::default()).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["in_container"], false);
    assert_eq!(parsed["runtime"], "none");
}

// ===========================================================================
// 9. GPU: NVIDIA Device Parsing
// ===========================================================================

#[test]
fn gpu_nvidia_single_device() {
    let csv = "0, NVIDIA GeForce RTX 4090, GPU-uuid-1234, 24564, 1024, 30, 55, 545.23.08\n";
    let devices = parse_nvidia_device_csv(csv).unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].index, 0);
    assert_eq!(devices[0].name, "NVIDIA GeForce RTX 4090");
    assert_eq!(devices[0].memory_total_mib, Some(24564));
    assert_eq!(devices[0].memory_used_mib, Some(1024));
    assert_eq!(devices[0].utilization_percent, Some(30));
    assert_eq!(devices[0].temperature_c, Some(55));
}

#[test]
fn gpu_nvidia_multi_device() {
    let csv = "\
0, NVIDIA A100-SXM4-80GB, GPU-aaa, 81920, 512, 5, 42, 535.104.05
1, NVIDIA A100-SXM4-80GB, GPU-bbb, 81920, 40960, 95, 72, 535.104.05
2, NVIDIA A100-SXM4-80GB, GPU-ccc, 81920, 0, 0, 35, 535.104.05
3, NVIDIA A100-SXM4-80GB, GPU-ddd, 81920, 20480, 50, 58, 535.104.05
";
    let devices = parse_nvidia_device_csv(csv).unwrap();
    assert_eq!(devices.len(), 4);
    assert_eq!(devices[1].utilization_percent, Some(95));
    assert_eq!(devices[2].memory_used_mib, Some(0));
    assert_eq!(devices[3].memory_used_mib, Some(20480));
}

#[test]
fn gpu_nvidia_empty_input() {
    let devices = parse_nvidia_device_csv("").unwrap();
    assert!(devices.is_empty());
}

#[test]
fn gpu_nvidia_malformed_csv() {
    let result = parse_nvidia_device_csv("bad,data\n");
    assert!(result.is_err());
}

#[test]
fn gpu_nvidia_na_uuid() {
    let csv = "0, Tesla V100, [N/A], 32768, 100, 10, 40, 525.60.13\n";
    let devices = parse_nvidia_device_csv(csv).unwrap();
    assert!(devices[0].uuid.is_none());
}

// ===========================================================================
// 10. GPU: NVIDIA Process Parsing
// ===========================================================================

fn make_test_gpu_devices() -> Vec<GpuDevice> {
    vec![
        GpuDevice {
            index: 0,
            name: "GPU-0".into(),
            uuid: Some("GPU-aaa".into()),
            memory_total_mib: Some(40960),
            memory_used_mib: None,
            utilization_percent: None,
            temperature_c: None,
            driver_version: None,
        },
        GpuDevice {
            index: 1,
            name: "GPU-1".into(),
            uuid: Some("GPU-bbb".into()),
            memory_total_mib: Some(40960),
            memory_used_mib: None,
            utilization_percent: None,
            temperature_c: None,
            driver_version: None,
        },
    ]
}

#[test]
fn gpu_nvidia_process_basic() {
    let devices = make_test_gpu_devices();
    let csv = "1234, GPU-aaa, 4096\n5678, GPU-bbb, 8192\n";
    let usages = parse_nvidia_process_csv(csv, &devices).unwrap();
    assert_eq!(usages.len(), 2);
    assert_eq!(usages[0].pid, 1234);
    assert_eq!(usages[0].gpu_index, 0);
    assert_eq!(usages[0].used_gpu_memory_mib, Some(4096));
    assert_eq!(usages[1].pid, 5678);
    assert_eq!(usages[1].gpu_index, 1);
}

#[test]
fn gpu_nvidia_process_multi_gpu_same_pid() {
    let devices = make_test_gpu_devices();
    let csv = "1234, GPU-aaa, 2048\n1234, GPU-bbb, 4096\n";
    let usages = parse_nvidia_process_csv(csv, &devices).unwrap();
    assert_eq!(usages.len(), 2);
    assert_eq!(usages[0].pid, usages[1].pid);
    assert_ne!(usages[0].gpu_index, usages[1].gpu_index);
}

#[test]
fn gpu_nvidia_process_empty() {
    let devices = make_test_gpu_devices();
    let usages = parse_nvidia_process_csv("", &devices).unwrap();
    assert!(usages.is_empty());
}

#[test]
fn gpu_nvidia_process_no_running() {
    let devices = make_test_gpu_devices();
    // nvidia-smi says this when no compute processes
    let csv = "no running compute processes found\n";
    // Should either be empty or parse error — not a crash
    let result = parse_nvidia_process_csv(csv, &devices);
    // Either Ok(empty) or a parse error is acceptable
    match result {
        Ok(usages) => assert!(usages.is_empty()),
        Err(_) => {} // Also acceptable
    }
}

// ===========================================================================
// 11. GPU: ROCm JSON Parsing
// ===========================================================================

#[test]
fn gpu_rocm_json_single_card() {
    let json = r#"{
        "card0": {
            "Card Series": "AMD Instinct MI250X",
            "Temperature (Sensor edge) (C)": "42",
            "GPU use (%)": "85",
            "VRAM Total Memory (B)": "68719476736",
            "VRAM Total Used Memory (B)": "17179869184",
            "Unique ID": "0x12345"
        }
    }"#;
    let devices = parse_rocm_json(json).unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].index, 0);
    assert_eq!(devices[0].name, "AMD Instinct MI250X");
    assert_eq!(devices[0].temperature_c, Some(42));
    assert_eq!(devices[0].utilization_percent, Some(85));
    assert_eq!(devices[0].memory_total_mib, Some(65536)); // 68719476736 / 1048576
    assert_eq!(devices[0].memory_used_mib, Some(16384)); // 17179869184 / 1048576
    assert_eq!(devices[0].uuid.as_deref(), Some("0x12345"));
}

#[test]
fn gpu_rocm_json_multi_card() {
    let json = r#"{
        "card0": {
            "GPU ID": "0x73bf",
            "Card Series": "RX 7900 XTX",
            "Temperature (Sensor edge) (C)": "45.0",
            "GPU use (%)": "10"
        },
        "card1": {
            "GPU ID": "0x73bf",
            "Card Series": "RX 7900 XTX",
            "Temperature (Sensor edge) (C)": "50.0",
            "GPU use (%)": "80"
        }
    }"#;
    let devices = parse_rocm_json(json).unwrap();
    assert_eq!(devices.len(), 2);
    // Should be sorted by index
    assert_eq!(devices[0].index, 0);
    assert_eq!(devices[1].index, 1);
}

#[test]
fn gpu_rocm_json_invalid() {
    let result = parse_rocm_json("not json");
    assert!(result.is_err());
}

// ===========================================================================
// 12. GPU: ROCm Text Parsing
// ===========================================================================

#[test]
fn gpu_rocm_text_basic() {
    let output = r#"
========================= ROCm System Management Interface =========================
================================ Concise Info ======================================
GPU  Temp  AvgPwr  SCLK     MCLK     Fan  Perf    PwrCap  VRAM%  GPU%
0    42c   45.0W   300Mhz   1200Mhz  0%   auto    250.0W  10%    0%
1    55c   120.0W  1500Mhz  1200Mhz  30%  auto    250.0W  75%    95%
========================= End of ROCm SMI Log ======================================
"#;
    let devices = parse_rocm_text(output).unwrap();
    assert_eq!(devices.len(), 2);
    assert_eq!(devices[0].index, 0);
    assert_eq!(devices[0].temperature_c, Some(42));
    assert_eq!(devices[1].index, 1);
    assert_eq!(devices[1].temperature_c, Some(55));
}

#[test]
fn gpu_rocm_text_empty() {
    let result = parse_rocm_text("");
    match result {
        Ok(devices) => assert!(devices.is_empty()),
        Err(_) => {} // Also acceptable
    }
}

// ===========================================================================
// 13. GPU: ROCm Process JSON
// ===========================================================================

#[test]
fn gpu_rocm_process_json_basic() {
    let json = r#"{
        "card0": {
            "12345": "4294967296",
            "67890": "2147483648"
        }
    }"#;
    let usages = parse_rocm_process_json(json).unwrap();
    assert_eq!(usages.len(), 2);
    let pids: Vec<u32> = usages.iter().map(|u| u.pid).collect();
    assert!(pids.contains(&12345));
    assert!(pids.contains(&67890));
    // 4294967296 bytes = 4096 MiB
    let p1 = usages.iter().find(|u| u.pid == 12345).unwrap();
    assert_eq!(p1.used_gpu_memory_mib, Some(4096));
    assert_eq!(p1.gpu_index, 0);
}

// ===========================================================================
// 14. GPU: Snapshot Helpers
// ===========================================================================

fn make_test_snapshot() -> GpuSnapshot {
    let devices = vec![
        GpuDevice {
            index: 0,
            name: "Test GPU 0".into(),
            uuid: Some("GPU-test-0".into()),
            memory_total_mib: Some(8192),
            memory_used_mib: Some(2048),
            utilization_percent: Some(50),
            temperature_c: Some(60),
            driver_version: Some("1.0.0".into()),
        },
        GpuDevice {
            index: 1,
            name: "Test GPU 1".into(),
            uuid: Some("GPU-test-1".into()),
            memory_total_mib: Some(8192),
            memory_used_mib: Some(4096),
            utilization_percent: Some(80),
            temperature_c: Some(70),
            driver_version: Some("1.0.0".into()),
        },
    ];

    let mut process_usage = HashMap::new();
    process_usage.insert(
        1234,
        vec![
            ProcessGpuUsage {
                pid: 1234,
                gpu_index: 0,
                used_gpu_memory_mib: Some(1024),
                gpu_process_type: Some("C".into()),
            },
            ProcessGpuUsage {
                pid: 1234,
                gpu_index: 1,
                used_gpu_memory_mib: Some(2048),
                gpu_process_type: Some("C".into()),
            },
        ],
    );
    process_usage.insert(
        5678,
        vec![ProcessGpuUsage {
            pid: 5678,
            gpu_index: 0,
            used_gpu_memory_mib: Some(512),
            gpu_process_type: Some("G".into()),
        }],
    );

    GpuSnapshot {
        has_gpu: true,
        gpu_type: GpuType::Nvidia,
        devices,
        process_usage,
        gpu_process_count: 2,
        provenance: GpuProvenance {
            source: GpuDetectionSource::NvidiaSmi,
            warnings: vec![],
        },
    }
}

#[test]
fn gpu_snapshot_usage_for_pid_found() {
    let snapshot = make_test_snapshot();
    let usage = gpu_usage_for_pid(&snapshot, 1234);
    assert!(usage.is_some());
    assert_eq!(usage.unwrap().len(), 2); // On 2 GPUs
}

#[test]
fn gpu_snapshot_usage_for_pid_not_found() {
    let snapshot = make_test_snapshot();
    let usage = gpu_usage_for_pid(&snapshot, 9999);
    assert!(usage.is_none());
}

#[test]
fn gpu_snapshot_total_vram_for_pid() {
    let snapshot = make_test_snapshot();
    let total = total_vram_mib_for_pid(&snapshot, 1234);
    assert_eq!(total, Some(3072)); // 1024 + 2048
}

#[test]
fn gpu_snapshot_total_vram_single_gpu() {
    let snapshot = make_test_snapshot();
    let total = total_vram_mib_for_pid(&snapshot, 5678);
    assert_eq!(total, Some(512));
}

#[test]
fn gpu_snapshot_total_vram_not_found() {
    let snapshot = make_test_snapshot();
    let total = total_vram_mib_for_pid(&snapshot, 9999);
    assert!(total.is_none());
}

// ===========================================================================
// 15. GPU: Snapshot Serialization
// ===========================================================================

#[test]
fn gpu_snapshot_json_roundtrip() {
    let snapshot = make_test_snapshot();
    let json = serde_json::to_string_pretty(&snapshot).unwrap();
    let restored: GpuSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.has_gpu, true);
    assert_eq!(restored.gpu_type, GpuType::Nvidia);
    assert_eq!(restored.devices.len(), 2);
    assert_eq!(restored.gpu_process_count, 2);
}

#[test]
fn gpu_snapshot_empty_json_roundtrip() {
    let snapshot = GpuSnapshot {
        has_gpu: false,
        gpu_type: GpuType::None,
        devices: vec![],
        process_usage: HashMap::new(),
        gpu_process_count: 0,
        provenance: GpuProvenance {
            source: GpuDetectionSource::None,
            warnings: vec![],
        },
    };
    let json = serde_json::to_string(&snapshot).unwrap();
    // Empty vecs/maps are skipped by skip_serializing_if, so we validate via Value
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["has_gpu"], false);
    assert_eq!(parsed["gpu_type"], "none");
    assert_eq!(parsed["gpu_process_count"], 0);
}

// ===========================================================================
// 16. GPU: Graceful Degradation
// ===========================================================================

#[test]
fn gpu_collect_snapshot_no_gpu_tools() {
    // collect_gpu_snapshot should never panic, even if no GPU tools exist.
    // On a system without GPU, it should return a no-GPU snapshot.
    let snapshot = pt_core::collect::collect_gpu_snapshot();
    // Can be has_gpu=true or false depending on system
    assert!(snapshot.devices.len() <= 100); // Sanity check
                                            // Provenance should be set
    assert!(
        snapshot.provenance.source == GpuDetectionSource::NvidiaSmi
            || snapshot.provenance.source == GpuDetectionSource::RocmSmi
            || snapshot.provenance.source == GpuDetectionSource::None
    );
}

// ===========================================================================
// 17. Container: Live System Detection
// ===========================================================================

#[test]
fn container_detect_from_markers_does_not_panic() {
    // detect_container_from_markers reads real files — should never panic.
    let result = pt_core::collect::detect_container_from_markers();
    // In CI/dev environment, we're likely NOT in a container.
    // But either way it should not panic.
    match result {
        Some(info) => assert!(info.in_container),
        None => {} // Not in a container — expected in dev
    }
}

// ===========================================================================
// 18. Cross-Feature: Container + GPU + ProcessRecord
// ===========================================================================

#[test]
fn process_record_with_container_info_serializes() {
    use pt_core::mock_process::MockProcessBuilder;

    let process = MockProcessBuilder::new().pid(100).comm("nginx").build();

    // ProcessRecord has container_info field — verify it's serializable.
    let json = serde_json::to_string(&process).unwrap();
    let restored: pt_core::collect::ProcessRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.pid.0, 100);
    // Default mock process has no container info.
    assert!(restored.container_info.is_none());
}

// ===========================================================================
// 19. GPU: Multi-GPU Stress Test
// ===========================================================================

#[test]
fn gpu_nvidia_8_gpu_system() {
    // Simulate an 8-GPU DGX-like system
    let csv = (0..8)
        .map(|i| {
            format!(
                "{}, NVIDIA A100-SXM4-80GB, GPU-{:03x}, 81920, {}, {}, {}, 535.104.05",
                i,
                i,
                1024 * (i + 1),
                10 + i * 10,
                40 + i * 5
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let devices = parse_nvidia_device_csv(&csv).unwrap();
    assert_eq!(devices.len(), 8);
    for (i, dev) in devices.iter().enumerate() {
        assert_eq!(dev.index, i as u32);
        assert_eq!(dev.memory_total_mib, Some(81920));
    }
}

#[test]
fn gpu_nvidia_many_processes() {
    let devices = vec![GpuDevice {
        index: 0,
        name: "A100".into(),
        uuid: Some("GPU-main".into()),
        memory_total_mib: Some(81920),
        memory_used_mib: None,
        utilization_percent: None,
        temperature_c: None,
        driver_version: None,
    }];

    let csv: String = (1000..1100)
        .map(|pid| format!("{}, GPU-main, {}\n", pid, pid * 10))
        .collect();

    let usages = parse_nvidia_process_csv(&csv, &devices).unwrap();
    assert_eq!(usages.len(), 100);
    assert!(usages.iter().all(|u| u.gpu_index == 0));
}

// ===========================================================================
// 20. Container: Various Cgroup V2 Formats
// ===========================================================================

#[test]
fn container_detect_cgroupv2_docker_scope() {
    let info = detect_container_from_cgroup(
        "/system.slice/docker-abc123def456789012345678901234567890123456789012345678901234.scope",
    );
    assert!(info.in_container);
    assert_eq!(info.runtime, ContainerRuntime::Docker);
}

#[test]
fn container_detect_multiple_runtimes_identified_correctly() {
    // Test that we correctly distinguish between runtimes.
    let docker_id = "a".repeat(64);
    let podman_id = "b".repeat(64);

    let docker_info = detect_container_from_cgroup(&format!("/docker/{}", docker_id));
    let podman_info =
        detect_container_from_cgroup(&format!("/machine.slice/libpod-{}.scope", podman_id));

    assert_eq!(docker_info.runtime, ContainerRuntime::Docker);
    assert_eq!(podman_info.runtime, ContainerRuntime::Podman);
    assert_ne!(docker_info.container_id, podman_info.container_id);
}
