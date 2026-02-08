//! Integration tests for fleet mode: discovery, scanning, session aggregation,
//! FDR pooling, and persistence.

use std::collections::HashMap;

use pt_core::fleet::discovery::{FleetDiscoveryConfig, ProviderConfig, ProviderRegistry};
use pt_core::fleet::inventory::{parse_inventory_str, InventoryFormat};
use pt_core::fleet::ssh_scan::{
    scan_result_to_host_input, FleetScanResult, HostScanResult, SshScanConfig,
};
use pt_core::mock_process::{MockProcessBuilder, MockScanBuilder};
use pt_core::session::fleet::{
    create_fleet_session, record_alpha_spend, CandidateInfo, FleetSession, HostInput,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn host_input(id: &str, candidates: Vec<CandidateInfo>) -> HostInput {
    HostInput {
        host_id: id.to_string(),
        session_id: format!("session-{}", id),
        scanned_at: "2026-02-01T12:00:00Z".to_string(),
        total_processes: 200 + candidates.len() as u32,
        candidates,
    }
}

fn kill_candidate(pid: u32, sig: &str, score: f64) -> CandidateInfo {
    CandidateInfo {
        pid,
        signature: sig.to_string(),
        classification: "zombie".to_string(),
        recommended_action: "kill".to_string(),
        score,
        e_value: None,
    }
}

fn kill_candidate_with_evalue(pid: u32, sig: &str, score: f64, e: f64) -> CandidateInfo {
    CandidateInfo {
        pid,
        signature: sig.to_string(),
        classification: "zombie".to_string(),
        recommended_action: "kill".to_string(),
        score,
        e_value: Some(e),
    }
}

fn spare_candidate(pid: u32, sig: &str, score: f64) -> CandidateInfo {
    CandidateInfo {
        pid,
        signature: sig.to_string(),
        classification: "normal".to_string(),
        recommended_action: "spare".to_string(),
        score,
        e_value: None,
    }
}

fn review_candidate(pid: u32, sig: &str, score: f64) -> CandidateInfo {
    CandidateInfo {
        pid,
        signature: sig.to_string(),
        classification: "abandoned".to_string(),
        recommended_action: "review".to_string(),
        score,
        e_value: None,
    }
}

// ===========================================================================
// 1. Inventory Parsing
// ===========================================================================

#[test]
fn inventory_toml_simple_hosts() {
    let toml = r#"
schema_version = "1.0.0"
generated_at = "2026-02-01T00:00:00Z"
hosts = ["web1.example.com", "web2.example.com", "db1.example.com"]
"#;
    let inv = parse_inventory_str(toml, InventoryFormat::Toml).unwrap();
    assert_eq!(inv.hosts.len(), 3);
    assert_eq!(inv.hosts[0].hostname, "web1.example.com");
    assert_eq!(inv.hosts[2].hostname, "db1.example.com");
}

#[test]
fn inventory_yaml_simple_hosts() {
    let yaml = r#"
schema_version: "1.0.0"
generated_at: "2026-02-01T00:00:00Z"
hosts:
  - web1.example.com
  - web2.example.com
"#;
    let inv = parse_inventory_str(yaml, InventoryFormat::Yaml).unwrap();
    assert_eq!(inv.hosts.len(), 2);
}

#[test]
fn inventory_json_simple_hosts() {
    let json = r#"{
        "schema_version": "1.0.0",
        "generated_at": "2026-02-01T00:00:00Z",
        "hosts": ["alpha", "beta", "gamma"]
    }"#;
    let inv = parse_inventory_str(json, InventoryFormat::Json).unwrap();
    assert_eq!(inv.hosts.len(), 3);
}

#[test]
fn inventory_toml_detailed_hosts_with_tags() {
    let toml = r#"
schema_version = "1.0.0"
generated_at = "2026-02-01T00:00:00Z"

[[hosts]]
hostname = "web1.example.com"
access_method = "ssh"
[hosts.tags]
role = "webserver"
env = "production"

[[hosts]]
hostname = "db1.example.com"
access_method = "ssh"
[hosts.tags]
role = "database"
env = "production"
"#;
    let inv = parse_inventory_str(toml, InventoryFormat::Toml).unwrap();
    assert_eq!(inv.hosts.len(), 2);
    assert_eq!(
        inv.hosts[0].tags.get("role").map(|s| s.as_str()),
        Some("webserver")
    );
    assert_eq!(
        inv.hosts[1].tags.get("env").map(|s| s.as_str()),
        Some("production")
    );
}

#[test]
fn inventory_empty_hosts_is_error() {
    let toml = r#"
schema_version = "1.0.0"
generated_at = "2026-02-01T00:00:00Z"
hosts = []
"#;
    let result = parse_inventory_str(toml, InventoryFormat::Toml);
    assert!(result.is_err());
}

// ===========================================================================
// 2. Discovery Config Parsing (via temp files since parse_str is pub(crate))
// ===========================================================================

#[test]
fn discovery_config_static_provider() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("discovery.toml");
    std::fs::write(
        &path,
        r#"
schema_version = "1.0.0"

[[providers]]
type = "static"
path = "/etc/pt/fleet.toml"
"#,
    )
    .unwrap();

    let config = FleetDiscoveryConfig::load_from_path(&path).unwrap();
    assert_eq!(config.providers.len(), 1);
    match &config.providers[0] {
        ProviderConfig::Static { path } => assert_eq!(path, "/etc/pt/fleet.toml"),
        _ => panic!("expected Static provider"),
    }
}

#[test]
fn discovery_config_dns_provider() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("discovery.toml");
    std::fs::write(
        &path,
        r#"
schema_version = "1.0.0"

[[providers]]
type = "dns"
service = "_pt._tcp"
domain = "example.com"
use_srv = true
"#,
    )
    .unwrap();

    let config = FleetDiscoveryConfig::load_from_path(&path).unwrap();
    assert_eq!(config.providers.len(), 1);
    match &config.providers[0] {
        ProviderConfig::Dns {
            service, domain, ..
        } => {
            assert_eq!(service, "_pt._tcp");
            assert_eq!(domain.as_deref(), Some("example.com"));
        }
        _ => panic!("expected Dns provider"),
    }
}

#[test]
fn discovery_config_multiple_providers_json() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("discovery.json");
    std::fs::write(
        &path,
        r#"{
            "schema_version": "1.0.0",
            "providers": [
                {"type": "static", "path": "/etc/pt/hosts.json"},
                {"type": "dns", "service": "_pt._tcp", "use_srv": false}
            ]
        }"#,
    )
    .unwrap();

    let config = FleetDiscoveryConfig::load_from_path(&path).unwrap();
    assert_eq!(config.providers.len(), 2);
}

#[test]
fn discovery_config_empty_providers_registry_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("discovery.toml");
    std::fs::write(
        &path,
        r#"
schema_version = "1.0.0"
providers = []
"#,
    )
    .unwrap();

    let config = FleetDiscoveryConfig::load_from_path(&path).unwrap();
    let result = ProviderRegistry::from_config(&config);
    assert!(result.is_err());
}

#[test]
fn discovery_config_serde_roundtrip_via_json() {
    // Write a config file, load it, serialize to JSON, deserialize back.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("roundtrip.json");
    std::fs::write(
        &path,
        r#"{
            "schema_version": "1.0.0",
            "generated_at": "2026-02-01T00:00:00Z",
            "providers": [{"type": "static", "path": "/tmp/hosts.toml"}],
            "cache_ttl_secs": 300,
            "refresh_interval_secs": 60
        }"#,
    )
    .unwrap();

    let config = FleetDiscoveryConfig::load_from_path(&path).unwrap();
    let json = serde_json::to_string(&config).unwrap();
    let restored: FleetDiscoveryConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.providers.len(), 1);
    assert_eq!(restored.cache_ttl_secs, Some(300));
}

// ===========================================================================
// 3. SSH Scan Config and Conversion
// ===========================================================================

#[test]
fn ssh_config_defaults_are_sane() {
    let cfg = SshScanConfig::default();
    assert_eq!(cfg.connect_timeout, 10);
    assert_eq!(cfg.command_timeout, 30);
    assert_eq!(cfg.parallel, 10);
    assert!(cfg.continue_on_error);
    assert!(cfg.user.is_none());
    assert!(cfg.identity_file.is_none());
    assert!(cfg.port.is_none());
}

#[test]
fn scan_result_conversion_zombie_becomes_candidate() {
    let zombie = MockProcessBuilder::new()
        .pid(42)
        .comm("dead_worker")
        .state_zombie()
        .elapsed_hours(2)
        .build();
    let scan = MockScanBuilder::new().with_process(zombie).build();

    let host_result = HostScanResult {
        host: "server1".to_string(),
        success: true,
        scan: Some(scan),
        error: None,
        duration_ms: 150,
    };

    let input = scan_result_to_host_input(&host_result);
    assert_eq!(input.host_id, "server1");
    assert_eq!(input.candidates.len(), 1);
    assert_eq!(input.candidates[0].classification, "zombie");
    assert_eq!(input.candidates[0].recommended_action, "kill");
    assert!(input.candidates[0].score > 0.9);
}

#[test]
fn scan_result_conversion_normal_process_filtered_out() {
    let normal = MockProcessBuilder::new()
        .pid(100)
        .comm("nginx")
        .cpu_percent(2.0)
        .elapsed_days(7)
        .build();
    let scan = MockScanBuilder::new().with_process(normal).build();

    let host_result = HostScanResult {
        host: "web1".to_string(),
        success: true,
        scan: Some(scan),
        error: None,
        duration_ms: 200,
    };

    let input = scan_result_to_host_input(&host_result);
    // Normal process has score 0.1, filtered out (< 0.3 threshold)
    assert!(input.candidates.is_empty());
}

#[test]
fn scan_result_conversion_mixed_processes() {
    let zombie = MockProcessBuilder::new()
        .pid(1)
        .comm("zombie1")
        .state_zombie()
        .elapsed_hours(1)
        .build();
    let stopped_old = MockProcessBuilder::new()
        .pid(2)
        .comm("abandoned1")
        .state_stopped()
        .elapsed_hours(5)
        .build();
    let normal = MockProcessBuilder::new()
        .pid(3)
        .comm("nginx")
        .cpu_percent(10.0)
        .elapsed_days(1)
        .build();
    let stopped_recent = MockProcessBuilder::new()
        .pid(4)
        .comm("debugged")
        .state_stopped()
        .elapsed_secs(300)
        .build();

    let scan = MockScanBuilder::new()
        .with_process(zombie)
        .with_process(stopped_old)
        .with_process(normal)
        .with_process(stopped_recent)
        .build();

    let host_result = HostScanResult {
        host: "dev1".to_string(),
        success: true,
        scan: Some(scan),
        error: None,
        duration_ms: 300,
    };

    let input = scan_result_to_host_input(&host_result);
    // zombie (0.95 > 0.3), stopped_old (0.7 > 0.3), stopped_recent (0.5 > 0.3)
    // normal (0.1 < 0.3) → filtered
    assert_eq!(input.candidates.len(), 3);
    assert_eq!(input.total_processes, 4);

    let sigs: Vec<&str> = input.candidates.iter().map(|c| c.signature.as_str()).collect();
    assert!(sigs.contains(&"zombie1"));
    assert!(sigs.contains(&"abandoned1"));
    assert!(sigs.contains(&"debugged"));
}

#[test]
fn scan_result_conversion_failed_host_produces_empty_input() {
    let host_result = HostScanResult {
        host: "unreachable".to_string(),
        success: false,
        scan: None,
        error: Some("connection refused".to_string()),
        duration_ms: 5000,
    };

    let input = scan_result_to_host_input(&host_result);
    assert_eq!(input.host_id, "unreachable");
    assert_eq!(input.total_processes, 0);
    assert!(input.candidates.is_empty());
}

// ===========================================================================
// 4. Fleet Session Creation and Aggregation
// ===========================================================================

#[test]
fn fleet_session_single_host_aggregation() {
    let inputs = vec![host_input(
        "host1",
        vec![
            kill_candidate(1, "zombie_proc", 0.95),
            spare_candidate(2, "nginx", 0.1),
        ],
    )];
    let session = create_fleet_session("test-single", Some("single host"), &inputs, 0.05);

    assert_eq!(session.fleet_session_id, "test-single");
    assert_eq!(session.label.as_deref(), Some("single host"));
    assert_eq!(session.hosts.len(), 1);
    assert_eq!(session.aggregate.total_hosts, 1);
    assert_eq!(session.aggregate.total_candidates, 2);
    assert_eq!(session.aggregate.total_processes, 202);
    assert!(session.aggregate.recurring_patterns.is_empty());
}

#[test]
fn fleet_session_multi_host_counts_match() {
    let inputs = vec![
        host_input(
            "host1",
            vec![
                kill_candidate(1, "zombie1", 0.95),
                spare_candidate(2, "nginx", 0.1),
            ],
        ),
        host_input(
            "host2",
            vec![
                kill_candidate(3, "zombie2", 0.90),
                review_candidate(4, "suspicious", 0.5),
                spare_candidate(5, "sshd", 0.05),
            ],
        ),
        host_input("host3", vec![spare_candidate(6, "systemd", 0.02)]),
    ];
    let session = create_fleet_session("test-multi", None, &inputs, 0.05);

    assert_eq!(session.aggregate.total_hosts, 3);
    assert_eq!(session.aggregate.total_candidates, 6);
    // 202 + 203 + 201 = 606
    assert_eq!(session.aggregate.total_processes, 606);
}

#[test]
fn fleet_session_recurring_patterns_detected() {
    // Same signature "old_worker" on multiple hosts triggers a pattern.
    let inputs = vec![
        host_input(
            "host1",
            vec![
                kill_candidate(1, "old_worker", 0.9),
                spare_candidate(2, "nginx", 0.1),
            ],
        ),
        host_input("host2", vec![kill_candidate(3, "old_worker", 0.85)]),
        host_input(
            "host3",
            vec![
                kill_candidate(4, "old_worker", 0.88),
                kill_candidate(5, "old_worker", 0.87),
            ],
        ),
    ];
    let session = create_fleet_session("test-patterns", None, &inputs, 0.05);

    let patterns = &session.aggregate.recurring_patterns;
    assert!(!patterns.is_empty());

    let old_worker_pattern = patterns.iter().find(|p| p.signature == "old_worker");
    assert!(old_worker_pattern.is_some());
    let p = old_worker_pattern.unwrap();
    assert_eq!(p.host_count, 3);
    assert_eq!(p.total_instances, 4); // 1 + 1 + 2
}

#[test]
fn fleet_session_no_patterns_for_unique_signatures() {
    let inputs = vec![
        host_input("host1", vec![kill_candidate(1, "unique_a", 0.9)]),
        host_input("host2", vec![kill_candidate(2, "unique_b", 0.9)]),
        host_input("host3", vec![kill_candidate(3, "unique_c", 0.9)]),
    ];
    let session = create_fleet_session("test-unique", None, &inputs, 0.05);
    assert!(session.aggregate.recurring_patterns.is_empty());
}

#[test]
fn fleet_session_empty_fleet() {
    let session = create_fleet_session("test-empty", None, &[], 0.05);
    assert_eq!(session.aggregate.total_hosts, 0);
    assert_eq!(session.aggregate.total_candidates, 0);
    assert_eq!(session.aggregate.total_processes, 0);
    assert!((session.aggregate.mean_candidate_score).abs() < f64::EPSILON);
    assert!(session.aggregate.recurring_patterns.is_empty());
}

#[test]
fn fleet_session_host_with_no_candidates() {
    let inputs = vec![
        host_input("empty-host", vec![]),
        host_input("full-host", vec![kill_candidate(1, "proc", 0.9)]),
    ];
    let session = create_fleet_session("test-partial", None, &inputs, 0.05);

    assert_eq!(session.hosts.len(), 2);
    assert_eq!(session.hosts[0].candidate_count, 0);
    assert!((session.hosts[0].summary.mean_candidate_score).abs() < f64::EPSILON);
    assert_eq!(session.hosts[1].candidate_count, 1);
}

// ===========================================================================
// 5. FDR Pooling and Kill Selection
// ===========================================================================

#[test]
fn fdr_pooling_high_evidence_kills_approved() {
    // All kills have high e-values → all should be approved.
    let inputs = vec![
        host_input(
            "h1",
            vec![kill_candidate_with_evalue(1, "z1", 0.99, 500.0)],
        ),
        host_input(
            "h2",
            vec![kill_candidate_with_evalue(2, "z2", 0.98, 400.0)],
        ),
    ];
    let session = create_fleet_session("fdr-high", None, &inputs, 0.05);

    assert_eq!(session.safety_budget.pooled_fdr.total_kill_candidates, 2);
    assert_eq!(session.safety_budget.pooled_fdr.selected_kills, 2);
    assert_eq!(session.safety_budget.pooled_fdr.rejected_kills, 0);
}

#[test]
fn fdr_pooling_low_evidence_kills_rejected() {
    // Kills with very low e-values should be rejected by FDR control.
    let inputs = vec![
        host_input(
            "h1",
            vec![kill_candidate_with_evalue(1, "weak1", 0.99, 500.0)],
        ),
        host_input(
            "h2",
            vec![kill_candidate_with_evalue(2, "weak2", 0.3, 0.5)],
        ),
    ];
    let session = create_fleet_session("fdr-low", None, &inputs, 0.05);

    let fdr = &session.safety_budget.pooled_fdr;
    assert_eq!(fdr.total_kill_candidates, 2);
    // At least the weak candidate should be rejected
    assert!(fdr.rejected_kills >= 1);
}

#[test]
fn fdr_rejected_kills_downgraded_to_review() {
    // When a kill is rejected by FDR, it should appear as "review" in action counts.
    let inputs = vec![
        host_input(
            "h1",
            vec![
                kill_candidate_with_evalue(1, "strong", 0.99, 500.0),
                kill_candidate_with_evalue(2, "weak", 0.80, 1.0),
            ],
        ),
    ];
    let session = create_fleet_session("fdr-downgrade", None, &inputs, 0.05);

    let fdr = &session.safety_budget.pooled_fdr;
    if fdr.rejected_kills > 0 {
        // The rejected kills should show up as "review" not "kill"
        let kill_count = session
            .aggregate
            .action_counts
            .get("kill")
            .copied()
            .unwrap_or(0);
        let review_count = session
            .aggregate
            .action_counts
            .get("review")
            .copied()
            .unwrap_or(0);
        assert_eq!(kill_count as usize, fdr.selected_kills);
        assert!(review_count >= fdr.rejected_kills as u32);
    }
}

#[test]
fn fdr_no_kill_candidates_produces_empty_fdr() {
    let inputs = vec![
        host_input("h1", vec![spare_candidate(1, "nginx", 0.1)]),
        host_input("h2", vec![review_candidate(2, "stopped", 0.5)]),
    ];
    let session = create_fleet_session("fdr-none", None, &inputs, 0.05);

    assert_eq!(session.safety_budget.pooled_fdr.total_kill_candidates, 0);
    assert_eq!(session.safety_budget.pooled_fdr.selected_kills, 0);
    assert_eq!(session.safety_budget.pooled_fdr.rejected_kills, 0);
}

#[test]
fn fdr_per_host_tracking() {
    let inputs = vec![
        host_input(
            "h1",
            vec![
                kill_candidate_with_evalue(1, "z1", 0.99, 500.0),
                kill_candidate_with_evalue(2, "z2", 0.98, 400.0),
            ],
        ),
        host_input(
            "h2",
            vec![kill_candidate_with_evalue(3, "z3", 0.97, 350.0)],
        ),
    ];
    let session = create_fleet_session("fdr-hosts", None, &inputs, 0.05);

    let fdr = &session.safety_budget.pooled_fdr;
    // All high e-values should be selected.
    let h1_selected = fdr.selected_by_host.get("h1").copied().unwrap_or(0);
    let h2_selected = fdr.selected_by_host.get("h2").copied().unwrap_or(0);
    assert_eq!(h1_selected + h2_selected, fdr.selected_kills as u32);
}

// ===========================================================================
// 6. Safety Budget
// ===========================================================================

#[test]
fn safety_budget_allocation() {
    let inputs = vec![
        host_input("h1", vec![kill_candidate(1, "z", 0.9)]),
        host_input("h2", vec![kill_candidate(2, "z", 0.9)]),
        host_input("h3", vec![kill_candidate(3, "z", 0.9)]),
    ];
    let session = create_fleet_session("budget-test", None, &inputs, 0.09);

    assert!((session.safety_budget.max_fdr - 0.09).abs() < f64::EPSILON);
    assert!((session.safety_budget.alpha_remaining - 0.09).abs() < f64::EPSILON);
    assert!((session.safety_budget.alpha_spent).abs() < f64::EPSILON);

    // Each host gets 0.03 (= 0.09 / 3)
    for (_, alloc) in &session.safety_budget.host_allocations {
        assert!((*alloc - 0.03).abs() < f64::EPSILON);
    }
}

#[test]
fn safety_budget_alpha_spending() {
    let inputs = vec![
        host_input("h1", vec![kill_candidate(1, "z", 0.9)]),
        host_input("h2", vec![kill_candidate(2, "z", 0.9)]),
    ];
    let mut session = create_fleet_session("budget-spend", None, &inputs, 0.10);

    record_alpha_spend(&mut session.safety_budget, "h1", 0.02);
    assert!((session.safety_budget.alpha_spent - 0.02).abs() < f64::EPSILON);
    assert!((session.safety_budget.alpha_remaining - 0.08).abs() < f64::EPSILON);
    assert!(
        (*session
            .safety_budget
            .host_allocations
            .get("h1")
            .unwrap()
            - 0.03)
            .abs()
            < f64::EPSILON
    );

    record_alpha_spend(&mut session.safety_budget, "h2", 0.05);
    assert!((session.safety_budget.alpha_spent - 0.07).abs() < f64::EPSILON);
    assert!((session.safety_budget.alpha_remaining - 0.03).abs() < f64::EPSILON);
}

#[test]
fn safety_budget_alpha_cannot_go_negative() {
    let inputs = vec![host_input("h1", vec![kill_candidate(1, "z", 0.9)])];
    let mut session = create_fleet_session("budget-clamp", None, &inputs, 0.05);

    // Overspend
    record_alpha_spend(&mut session.safety_budget, "h1", 0.10);
    assert!((session.safety_budget.alpha_remaining).abs() < f64::EPSILON);
    assert!(
        (*session
            .safety_budget
            .host_allocations
            .get("h1")
            .unwrap())
        .abs()
            < f64::EPSILON
    );
}

// ===========================================================================
// 7. Fleet Session Serialization and Persistence
// ===========================================================================

#[test]
fn fleet_session_json_roundtrip() {
    let inputs = vec![
        host_input(
            "host-a",
            vec![
                kill_candidate(1, "zombie_proc", 0.95),
                spare_candidate(2, "nginx", 0.1),
            ],
        ),
        host_input(
            "host-b",
            vec![
                kill_candidate(3, "zombie_proc", 0.92),
                review_candidate(4, "stale_job", 0.6),
            ],
        ),
    ];
    let original = create_fleet_session("roundtrip", Some("persistence test"), &inputs, 0.05);

    let json = serde_json::to_string_pretty(&original).unwrap();
    let restored: FleetSession = serde_json::from_str(&json).unwrap();

    assert_eq!(restored.fleet_session_id, "roundtrip");
    assert_eq!(restored.label.as_deref(), Some("persistence test"));
    assert_eq!(restored.hosts.len(), 2);
    assert_eq!(
        restored.aggregate.total_hosts,
        original.aggregate.total_hosts
    );
    assert_eq!(
        restored.aggregate.total_candidates,
        original.aggregate.total_candidates
    );
    assert_eq!(
        restored.aggregate.recurring_patterns.len(),
        original.aggregate.recurring_patterns.len()
    );
    assert_eq!(
        restored.safety_budget.pooled_fdr.total_kill_candidates,
        original.safety_budget.pooled_fdr.total_kill_candidates
    );
}

#[test]
fn fleet_session_persists_to_disk_and_restores() {
    let inputs = vec![
        host_input("h1", vec![kill_candidate(1, "z", 0.9)]),
        host_input("h2", vec![spare_candidate(2, "n", 0.1)]),
    ];
    let session = create_fleet_session("disk-test", None, &inputs, 0.05);

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fleet.json");
    let json = serde_json::to_string_pretty(&session).unwrap();
    std::fs::write(&path, &json).unwrap();

    let content = std::fs::read_to_string(&path).unwrap();
    let restored: FleetSession = serde_json::from_str(&content).unwrap();
    assert_eq!(restored.fleet_session_id, "disk-test");
    assert_eq!(restored.hosts.len(), 2);
}

// ===========================================================================
// 8. End-to-End: SSH Scan → Host Input → Fleet Session
// ===========================================================================

#[test]
fn e2e_scan_to_fleet_session_pipeline() {
    // Simulate a 3-host fleet scan result.
    let host1_scan = MockScanBuilder::new()
        .with_process(
            MockProcessBuilder::new()
                .pid(1)
                .comm("zombie_worker")
                .state_zombie()
                .elapsed_hours(3)
                .build(),
        )
        .with_process(
            MockProcessBuilder::new()
                .pid(2)
                .comm("nginx")
                .cpu_percent(5.0)
                .elapsed_days(30)
                .build(),
        )
        .build();

    let host2_scan = MockScanBuilder::new()
        .with_process(
            MockProcessBuilder::new()
                .pid(10)
                .comm("zombie_worker")
                .state_zombie()
                .elapsed_hours(2)
                .build(),
        )
        .with_process(
            MockProcessBuilder::new()
                .pid(11)
                .comm("stale_job")
                .state_stopped()
                .elapsed_hours(8)
                .build(),
        )
        .build();

    let host3_scan = MockScanBuilder::new()
        .with_process(
            MockProcessBuilder::new()
                .pid(20)
                .comm("stuck_io")
                .state_disksleep()
                .elapsed_hours(2)
                .build(),
        )
        .build();

    let fleet_result = FleetScanResult {
        total_hosts: 3,
        successful: 3,
        failed: 0,
        results: vec![
            HostScanResult {
                host: "web1".to_string(),
                success: true,
                scan: Some(host1_scan),
                error: None,
                duration_ms: 200,
            },
            HostScanResult {
                host: "web2".to_string(),
                success: true,
                scan: Some(host2_scan),
                error: None,
                duration_ms: 300,
            },
            HostScanResult {
                host: "db1".to_string(),
                success: true,
                scan: Some(host3_scan),
                error: None,
                duration_ms: 150,
            },
        ],
        duration_ms: 350,
    };

    // Convert scan results to host inputs.
    let host_inputs: Vec<HostInput> = fleet_result
        .results
        .iter()
        .map(scan_result_to_host_input)
        .collect();

    assert_eq!(host_inputs.len(), 3);
    // web1: zombie_worker is candidate (0.95), nginx filtered (0.1)
    assert_eq!(host_inputs[0].candidates.len(), 1);
    // web2: zombie_worker (0.95) + stale_job stopped>1hr (0.7)
    assert_eq!(host_inputs[1].candidates.len(), 2);
    // db1: stuck_io disksleep>600s (0.6)
    assert_eq!(host_inputs[2].candidates.len(), 1);

    // Create fleet session.
    let session = create_fleet_session("e2e-fleet", Some("E2E test"), &host_inputs, 0.05);

    assert_eq!(session.aggregate.total_hosts, 3);
    assert_eq!(session.aggregate.total_candidates, 4);

    // zombie_worker appears on 2 hosts → should be a recurring pattern.
    let zombie_pattern = session
        .aggregate
        .recurring_patterns
        .iter()
        .find(|p| p.signature == "zombie_worker");
    assert!(zombie_pattern.is_some());
    assert_eq!(zombie_pattern.unwrap().host_count, 2);

    // Safety budget should be initialized.
    assert!((session.safety_budget.max_fdr - 0.05).abs() < f64::EPSILON);
    assert_eq!(session.safety_budget.host_allocations.len(), 3);

    // Verify serialization roundtrip.
    let json = serde_json::to_string_pretty(&session).unwrap();
    let restored: FleetSession = serde_json::from_str(&json).unwrap();
    assert_eq!(
        restored.aggregate.total_candidates,
        session.aggregate.total_candidates
    );
}

#[test]
fn e2e_mixed_success_failure_fleet() {
    // Some hosts succeed, some fail — the fleet session should still be created.
    let good_scan = MockScanBuilder::new()
        .with_process(
            MockProcessBuilder::new()
                .pid(1)
                .comm("zombie")
                .state_zombie()
                .elapsed_hours(1)
                .build(),
        )
        .build();

    let fleet_result = FleetScanResult {
        total_hosts: 3,
        successful: 1,
        failed: 2,
        results: vec![
            HostScanResult {
                host: "ok-host".to_string(),
                success: true,
                scan: Some(good_scan),
                error: None,
                duration_ms: 200,
            },
            HostScanResult {
                host: "fail-host1".to_string(),
                success: false,
                scan: None,
                error: Some("connection refused".to_string()),
                duration_ms: 5000,
            },
            HostScanResult {
                host: "fail-host2".to_string(),
                success: false,
                scan: None,
                error: Some("timeout".to_string()),
                duration_ms: 30000,
            },
        ],
        duration_ms: 30100,
    };

    let host_inputs: Vec<HostInput> = fleet_result
        .results
        .iter()
        .map(scan_result_to_host_input)
        .collect();

    let session = create_fleet_session("e2e-mixed", None, &host_inputs, 0.05);

    assert_eq!(session.aggregate.total_hosts, 3);
    // Only the successful host has candidates.
    assert_eq!(session.aggregate.total_candidates, 1);
    // Failed hosts have 0 processes.
    assert_eq!(session.hosts[1].process_count, 0);
    assert_eq!(session.hosts[2].process_count, 0);
}

// ===========================================================================
// 9. Determinism
// ===========================================================================

#[test]
fn fleet_session_is_deterministic() {
    let inputs = vec![
        host_input(
            "h1",
            vec![
                kill_candidate_with_evalue(1, "proc_a", 0.95, 200.0),
                spare_candidate(2, "nginx", 0.1),
            ],
        ),
        host_input(
            "h2",
            vec![
                kill_candidate_with_evalue(3, "proc_a", 0.92, 180.0),
                kill_candidate_with_evalue(4, "proc_b", 0.88, 120.0),
            ],
        ),
    ];

    let s1 = create_fleet_session("det1", None, &inputs, 0.05);
    let s2 = create_fleet_session("det1", None, &inputs, 0.05);

    assert_eq!(s1.aggregate.total_candidates, s2.aggregate.total_candidates);
    assert_eq!(s1.aggregate.class_counts, s2.aggregate.class_counts);
    assert_eq!(s1.aggregate.action_counts, s2.aggregate.action_counts);
    assert!(
        (s1.aggregate.mean_candidate_score - s2.aggregate.mean_candidate_score).abs()
            < f64::EPSILON
    );
    assert_eq!(
        s1.safety_budget.pooled_fdr.selected_kills,
        s2.safety_budget.pooled_fdr.selected_kills
    );
    assert_eq!(
        s1.aggregate.recurring_patterns.len(),
        s2.aggregate.recurring_patterns.len()
    );
}

// ===========================================================================
// 10. Mathematical Properties: FDR
// ===========================================================================

#[test]
fn fdr_selected_plus_rejected_equals_total() {
    let inputs = vec![
        host_input(
            "h1",
            vec![
                kill_candidate_with_evalue(1, "a", 0.99, 500.0),
                kill_candidate_with_evalue(2, "b", 0.50, 2.0),
            ],
        ),
        host_input(
            "h2",
            vec![
                kill_candidate_with_evalue(3, "c", 0.95, 100.0),
                kill_candidate_with_evalue(4, "d", 0.40, 0.8),
            ],
        ),
    ];
    let session = create_fleet_session("fdr-math", None, &inputs, 0.05);
    let fdr = &session.safety_budget.pooled_fdr;

    assert_eq!(fdr.selected_kills + fdr.rejected_kills, fdr.total_kill_candidates);
}

#[test]
fn fdr_host_counts_sum_to_total() {
    let inputs = vec![
        host_input(
            "h1",
            vec![
                kill_candidate_with_evalue(1, "a", 0.99, 500.0),
                kill_candidate_with_evalue(2, "b", 0.95, 200.0),
            ],
        ),
        host_input(
            "h2",
            vec![kill_candidate_with_evalue(3, "c", 0.90, 100.0)],
        ),
        host_input(
            "h3",
            vec![kill_candidate_with_evalue(4, "d", 0.85, 80.0)],
        ),
    ];
    let session = create_fleet_session("fdr-counts", None, &inputs, 0.05);
    let fdr = &session.safety_budget.pooled_fdr;

    let total_selected: u32 = fdr.selected_by_host.values().sum();
    let total_rejected: u32 = fdr.rejected_by_host.values().sum();
    assert_eq!(total_selected, fdr.selected_kills as u32);
    assert_eq!(total_rejected, fdr.rejected_kills as u32);
    assert_eq!(
        total_selected + total_rejected,
        fdr.total_kill_candidates as u32
    );
}

#[test]
fn fdr_method_is_eby() {
    let inputs = vec![host_input(
        "h1",
        vec![kill_candidate(1, "z", 0.9)],
    )];
    let session = create_fleet_session("fdr-method", None, &inputs, 0.05);
    assert_eq!(session.safety_budget.pooled_fdr.method, "eby");
}

#[test]
fn fdr_alpha_matches_max_fdr() {
    let inputs = vec![host_input(
        "h1",
        vec![kill_candidate(1, "z", 0.9)],
    )];
    for alpha in [0.01, 0.05, 0.10, 0.20] {
        let session = create_fleet_session("fdr-alpha", None, &inputs, alpha);
        assert!(
            (session.safety_budget.pooled_fdr.alpha - alpha).abs() < f64::EPSILON,
            "alpha={} but pooled_fdr.alpha={}",
            alpha,
            session.safety_budget.pooled_fdr.alpha
        );
    }
}

// ===========================================================================
// 11. Large Fleet Stress Test
// ===========================================================================

#[test]
fn fleet_session_100_hosts() {
    let inputs: Vec<HostInput> = (0..100)
        .map(|i| {
            let candidates = (0..10)
                .map(|j| {
                    if j < 3 {
                        kill_candidate(
                            i * 10 + j,
                            &format!("pattern_{}", j % 5),
                            0.8 + 0.02 * (j as f64),
                        )
                    } else {
                        spare_candidate(i * 10 + j, &format!("service_{}", j), 0.1)
                    }
                })
                .collect();
            host_input(&format!("host-{}", i), candidates)
        })
        .collect();

    let start = std::time::Instant::now();
    let session = create_fleet_session("stress-100", None, &inputs, 0.05);
    let elapsed = start.elapsed();

    assert_eq!(session.aggregate.total_hosts, 100);
    assert_eq!(session.aggregate.total_candidates, 1000);

    // Recurring patterns should exist (same pattern_N across hosts).
    assert!(!session.aggregate.recurring_patterns.is_empty());

    // Should complete well within 1 second for 100 hosts.
    assert!(
        elapsed.as_millis() < 1000,
        "Fleet session creation took {}ms for 100 hosts",
        elapsed.as_millis()
    );
}

#[test]
fn fleet_session_many_candidates_per_host() {
    // Test with hosts that each have many candidates.
    let inputs: Vec<HostInput> = (0..5)
        .map(|i| {
            let candidates = (0..500)
                .map(|j| {
                    kill_candidate_with_evalue(
                        j,
                        &format!("sig_{}", j % 20),
                        0.5 + 0.001 * (j as f64),
                        10.0 + (j as f64),
                    )
                })
                .collect();
            host_input(&format!("host-{}", i), candidates)
        })
        .collect();

    let start = std::time::Instant::now();
    let session = create_fleet_session("stress-candidates", None, &inputs, 0.05);
    let elapsed = start.elapsed();

    assert_eq!(session.aggregate.total_hosts, 5);
    assert_eq!(session.aggregate.total_candidates, 2500);
    assert_eq!(
        session.safety_budget.pooled_fdr.total_kill_candidates,
        2500
    );

    // Patterns should be detected (sig_N appears on all 5 hosts).
    assert!(!session.aggregate.recurring_patterns.is_empty());

    // Should complete within 1 second.
    assert!(
        elapsed.as_millis() < 1000,
        "Fleet session creation took {}ms for 2500 candidates",
        elapsed.as_millis()
    );
}

// ===========================================================================
// 12. FleetScanResult Serialization
// ===========================================================================

#[test]
fn fleet_scan_result_json_roundtrip() {
    let scan = MockScanBuilder::new()
        .with_process(MockProcessBuilder::new().pid(1).comm("test").build())
        .with_warning("test warning")
        .build();

    let result = FleetScanResult {
        total_hosts: 2,
        successful: 1,
        failed: 1,
        results: vec![
            HostScanResult {
                host: "ok".to_string(),
                success: true,
                scan: Some(scan),
                error: None,
                duration_ms: 100,
            },
            HostScanResult {
                host: "fail".to_string(),
                success: false,
                scan: None,
                error: Some("timeout".to_string()),
                duration_ms: 30000,
            },
        ],
        duration_ms: 30100,
    };

    let json = serde_json::to_string(&result).unwrap();
    let restored: FleetScanResult = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.total_hosts, 2);
    assert_eq!(restored.successful, 1);
    assert_eq!(restored.failed, 1);
    assert!(restored.results[0].scan.is_some());
    assert!(restored.results[1].scan.is_none());
}

// ===========================================================================
// 13. Discovery Provider Registry
// ===========================================================================

#[test]
fn provider_registry_from_static_config() {
    let config = FleetDiscoveryConfig {
        schema_version: "1.0.0".to_string(),
        generated_at: None,
        providers: vec![ProviderConfig::Static {
            path: "/nonexistent/path.toml".to_string(),
        }],
        cache_ttl_secs: None,
        refresh_interval_secs: None,
        stale_while_revalidate_secs: None,
    };

    let registry = ProviderRegistry::from_config(&config).unwrap();
    // discover_all will fail because the file doesn't exist,
    // but the registry should be created successfully.
    let result = registry.discover_all();
    assert!(result.is_err());
}

#[test]
fn provider_registry_aws_not_implemented() {
    let config = FleetDiscoveryConfig {
        schema_version: "1.0.0".to_string(),
        generated_at: None,
        providers: vec![ProviderConfig::Aws {
            region: Some("us-east-1".to_string()),
            tag_filters: HashMap::new(),
        }],
        cache_ttl_secs: None,
        refresh_interval_secs: None,
        stale_while_revalidate_secs: None,
    };

    let result = ProviderRegistry::from_config(&config);
    assert!(result.is_err());
}

// ===========================================================================
// 14. Inventory Format Detection
// ===========================================================================

#[test]
fn inventory_format_detection_by_extension() {
    use pt_core::fleet::inventory::load_inventory_from_path;

    // Use a temp file with unknown extension to trigger format detection error.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.unknown");
    std::fs::write(&path, "some content").unwrap();

    let result = load_inventory_from_path(&path);
    assert!(result.is_err());
    let err_str = format!("{}", result.unwrap_err());
    assert!(
        err_str.contains("unsupported") || err_str.contains("format") || err_str.contains("extension"),
        "Expected format error but got: {}",
        err_str
    );
}
