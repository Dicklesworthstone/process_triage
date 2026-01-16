use pt_telemetry::shadow::{ShadowStorage, ShadowStorageConfig, Observation, StateSnapshot, BeliefState};
use tempfile::TempDir;
use chrono::Utc;

#[test]
fn test_shadow_storage_identity_leak_on_pid_reuse() {
    let temp_dir = TempDir::new().unwrap();
    let config = ShadowStorageConfig {
        base_dir: temp_dir.path().to_path_buf(),
        auto_compact: false,
        ..Default::default()
    };

    let mut storage = ShadowStorage::new(config).unwrap();
    let pid = 1234;

    // 1. Record observation for Identity A (e.g. "python")
    let obs_a = Observation {
        timestamp: Utc::now(),
        pid,
        identity_hash: "identity_A".to_string(),
        state: StateSnapshot { cpu_percent: 10.0, ..Default::default() },
        ..Default::default()
    };
    storage.record(obs_a).unwrap();

    // 2. Record observation for Identity B (e.g. "bash", reusing PID)
    let obs_b = Observation {
        timestamp: Utc::now() + chrono::Duration::seconds(10),
        pid,
        identity_hash: "identity_B".to_string(),
        state: StateSnapshot { cpu_percent: 20.0, ..Default::default() },
        ..Default::default()
    };
    storage.record(obs_b).unwrap();

    // 3. Query history for Identity A
    let history_a = storage.get_history(
        "identity_A", 
        Utc::now() - chrono::Duration::hours(1), 
        Utc::now() + chrono::Duration::hours(1), 
        100
    );

    // Should only contain observations for A
    assert_eq!(history_a.observations.len(), 1, "Should have 1 observation for A");
    assert_eq!(history_a.observations[0].identity_hash, "identity_A");
    
    // If the bug exists, we might get 2 observations (A and B) because they share the PID
}
