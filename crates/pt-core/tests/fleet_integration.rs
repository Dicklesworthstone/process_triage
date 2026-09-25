//! Integration tests for fleet mode: discovery, scanning, session aggregation,
//! FDR pooling, and persistence.

use std::collections::HashMap;

use pt_core::fleet::discovery::{FleetDiscoveryConfig, ProviderConfig, ProviderRegistry};
use pt_core::fleet::inventory::{parse_inventory_str, InventoryFormat};
use pt_core::fleet::ssh_scan::{
    parse_remote_plan, scan_result_to_host_input, FleetScanResult, HostScanResult, RemoteCandidate,
    RemotePlan, SshScanConfig,
};
use pt_core::session::fleet::{
    create_fleet_session, record_alpha_spend, CandidateInfo, FleetSession, HostInput,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A host's `agent plan` result: (pid, comm, classification, recommendation, score).
fn plan(total: u64, candidates: &[(u32, &str, &str, &str, f64)]) -> RemotePlan {
    RemotePlan {
        generated_at: "2026-09-25T10:00:00Z".to_string(),
        total_processes: total,
        candidates: candidates
            .iter()
            .map(|&(pid, comm, class, rec, score)| RemoteCandidate {
                pid,
                comm: comm.to_string(),
                classification: class.to_string(),
                recommendation: rec.to_string(),
                score,
            })
            .collect(),
    }
}

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
fn host_plan_conversion_keeps_the_hosts_decisions() {
    let host_result = HostScanResult {
        host: "dev1".to_string(),
        success: true,
        plan: Some(plan(
            4,
            &[
                (1, "zombie1", "zombie", "RESTART", 0.97),
                (2, "abandoned1", "abandoned", "REVIEW", 0.8),
                (4, "debugged", "useful_bad", "KEEP", 0.2),
            ],
        )),
        error: None,
        duration_ms: 300,
        provenance: None,
    };

    let input = scan_result_to_host_input(&host_result);
    assert_eq!(input.host_id, "dev1");
    assert_eq!(input.total_processes, 4);
    let got: Vec<(u32, &str, &str)> = input
        .candidates
        .iter()
        .map(|c| (c.pid, c.signature.as_str(), c.recommended_action.as_str()))
        .collect();
    // Nothing is re-classified: the zombie keeps its parent-routed action.
    assert_eq!(
        got,
        vec![
            (1, "zombie1", "restart"),
            (2, "abandoned1", "review"),
            (4, "debugged", "keep"),
        ]
    );
}

/// Contract: the real `pt-core agent plan` output parses into a RemotePlan with
/// every candidate the plan returned.
#[test]
fn real_agent_plan_output_parses_as_remote_plan() {
    let data_dir = tempfile::tempdir().expect("data dir");
    let output = assert_cmd::cargo::cargo_bin_cmd!("pt-core")
        .timeout(std::time::Duration::from_secs(300))
        .env("PT_SKIP_GLOBAL_LOCK", "1")
        .env("PROCESS_TRIAGE_DATA", data_dir.path())
        .env("PROCESS_TRIAGE_RETENTION", "off")
        .args(["--format", "json", "agent", "plan", "--min-posterior", "0"])
        .output()
        .expect("run agent plan");
    assert!(
        matches!(output.status.code(), Some(0) | Some(1)),
        "agent plan exit {:?}",
        output.status.code()
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed = parse_remote_plan(&stdout).expect("agent plan output parses");
    let raw: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(parsed.total_processes > 0);
    assert_eq!(
        parsed.candidates.len(),
        raw["candidates"].as_array().unwrap().len()
    );
    assert!(parsed.candidates.iter().all(|c| c.pid > 0
        && !c.recommendation.is_empty()
        && (0.0..=1.0 + 1e-9).contains(&c.score)));
}

#[test]
fn scan_result_conversion_failed_host_produces_empty_input() {
    let host_result = HostScanResult {
        host: "unreachable".to_string(),
        success: false,
        plan: None,
        error: Some("connection refused".to_string()),
        duration_ms: 5000,
        provenance: None,
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
        host_input("h1", vec![kill_candidate_with_evalue(1, "z1", 0.99, 500.0)]),
        host_input("h2", vec![kill_candidate_with_evalue(2, "z2", 0.98, 400.0)]),
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
        host_input("h2", vec![kill_candidate_with_evalue(2, "weak2", 0.3, 0.5)]),
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
    let inputs = vec![host_input(
        "h1",
        vec![
            kill_candidate_with_evalue(1, "strong", 0.99, 500.0),
            kill_candidate_with_evalue(2, "weak", 0.80, 1.0),
        ],
    )];
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
        host_input("h2", vec![kill_candidate_with_evalue(3, "z3", 0.97, 350.0)]),
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
    for alloc in session.safety_budget.host_allocations.values() {
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
        (*session.safety_budget.host_allocations.get("h1").unwrap() - 0.03).abs() < f64::EPSILON
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
    assert!((*session.safety_budget.host_allocations.get("h1").unwrap()).abs() < f64::EPSILON);
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
    // A 3-host fleet: each host's own `agent plan` candidates.
    let host1_scan = plan(2, &[(1, "zombie_worker", "zombie", "RESTART", 0.97)]);
    let host2_scan = plan(
        2,
        &[
            (10, "zombie_worker", "zombie", "RESTART", 0.96),
            (11, "stale_job", "abandoned", "REVIEW", 0.8),
        ],
    );
    let host3_scan = plan(1, &[(20, "stuck_io", "useful_bad", "REVIEW", 0.6)]);

    let fleet_result = FleetScanResult {
        total_hosts: 3,
        successful: 3,
        failed: 0,
        results: vec![
            HostScanResult {
                host: "web1".to_string(),
                success: true,
                plan: Some(host1_scan),
                error: None,
                duration_ms: 200,
                provenance: None,
            },
            HostScanResult {
                host: "web2".to_string(),
                success: true,
                plan: Some(host2_scan),
                error: None,
                duration_ms: 300,
                provenance: None,
            },
            HostScanResult {
                host: "db1".to_string(),
                success: true,
                plan: Some(host3_scan),
                error: None,
                duration_ms: 150,
                provenance: None,
            },
        ],
        duration_ms: 350,
        provenance_aggregate: None,
    };

    // Convert scan results to host inputs.
    let host_inputs: Vec<HostInput> = fleet_result
        .results
        .iter()
        .map(scan_result_to_host_input)
        .collect();

    assert_eq!(host_inputs.len(), 3);
    assert_eq!(host_inputs[0].candidates.len(), 1);
    assert_eq!(host_inputs[1].candidates.len(), 2);
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
    let good_scan = plan(1, &[(1, "zombie", "zombie", "RESTART", 0.97)]);

    let fleet_result = FleetScanResult {
        total_hosts: 3,
        successful: 1,
        failed: 2,
        results: vec![
            HostScanResult {
                host: "ok-host".to_string(),
                success: true,
                plan: Some(good_scan),
                error: None,
                duration_ms: 200,
                provenance: None,
            },
            HostScanResult {
                host: "fail-host1".to_string(),
                success: false,
                plan: None,
                error: Some("connection refused".to_string()),
                duration_ms: 5000,
                provenance: None,
            },
            HostScanResult {
                host: "fail-host2".to_string(),
                success: false,
                plan: None,
                error: Some("timeout".to_string()),
                duration_ms: 30000,
                provenance: None,
            },
        ],
        duration_ms: 30100,
        provenance_aggregate: None,
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

    assert_eq!(
        fdr.selected_kills + fdr.rejected_kills,
        fdr.total_kill_candidates
    );
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
        host_input("h2", vec![kill_candidate_with_evalue(3, "c", 0.90, 100.0)]),
        host_input("h3", vec![kill_candidate_with_evalue(4, "d", 0.85, 80.0)]),
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
    let inputs = vec![host_input("h1", vec![kill_candidate(1, "z", 0.9)])];
    let session = create_fleet_session("fdr-method", None, &inputs, 0.05);
    assert_eq!(session.safety_budget.pooled_fdr.method, "eby");
}

#[test]
fn fdr_alpha_matches_max_fdr() {
    let inputs = vec![host_input("h1", vec![kill_candidate(1, "z", 0.9)])];
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
    assert_eq!(session.safety_budget.pooled_fdr.total_kill_candidates, 2500);

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
    let scan = plan(1, &[(1, "test", "abandoned", "REVIEW", 0.7)]);
    let expected = scan.clone();

    let result = FleetScanResult {
        total_hosts: 2,
        successful: 1,
        failed: 1,
        results: vec![
            HostScanResult {
                host: "ok".to_string(),
                success: true,
                plan: Some(scan),
                error: None,
                duration_ms: 100,
                provenance: None,
            },
            HostScanResult {
                host: "fail".to_string(),
                success: false,
                plan: None,
                error: Some("timeout".to_string()),
                duration_ms: 30000,
                provenance: None,
            },
        ],
        duration_ms: 30100,
        provenance_aggregate: None,
    };

    let json = serde_json::to_string(&result).unwrap();
    let restored: FleetScanResult = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.total_hosts, 2);
    assert_eq!(restored.successful, 1);
    assert_eq!(restored.failed, 1);
    assert_eq!(restored.results[0].plan.as_ref(), Some(&expected));
    assert!(restored.results[1].plan.is_none());
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
        err_str.contains("unsupported")
            || err_str.contains("format")
            || err_str.contains("extension"),
        "Expected format error but got: {}",
        err_str
    );
}
