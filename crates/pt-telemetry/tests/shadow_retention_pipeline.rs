//! Shadow retention pipeline tests using real storage and timestamps.

use chrono::{Duration as ChronoDuration, Utc};
use filetime::FileTime;
use pt_telemetry::shadow::{BeliefState, Observation, ShadowStorage, ShadowStorageConfig, StateSnapshot};
use std::fs;
use tempfile::TempDir;

fn make_observation(timestamp: chrono::DateTime<Utc>, pid: u32, identity: &str) -> Observation {
    Observation {
        timestamp,
        pid,
        identity_hash: identity.to_string(),
        state: StateSnapshot {
            cpu_percent: 5.0,
            memory_bytes: 1024,
            rss_bytes: 512,
            fd_count: 3,
            thread_count: 1,
            state_char: 'S',
            io_read_bytes: 0,
            io_write_bytes: 0,
            has_tty: false,
            child_count: 0,
        },
        belief: BeliefState {
            p_abandoned: 0.4,
            p_legitimate: 0.4,
            p_zombie: 0.1,
            p_useful_but_bad: 0.1,
            confidence: 0.2,
            score: 10.0,
            recommendation: "keep".to_string(),
        },
        events: Vec::new(),
    }
}

fn count_json_files(dir: &std::path::Path) -> usize {
    let mut count = 0usize;
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                count += count_json_files(&path);
            } else if path.extension().and_then(|s| s.to_str()) == Some("json") {
                count += 1;
            }
        }
    }
    count
}

#[test]
fn shadow_compaction_applies_retention_tiers() {
    let temp_dir = TempDir::new().unwrap();
    let config = ShadowStorageConfig {
        base_dir: temp_dir.path().to_path_buf(),
        auto_compact: false,
        ..Default::default()
    };

    let mut storage = ShadowStorage::new(config).unwrap();
    let now = Utc::now();

    storage
        .record(make_observation(now - ChronoDuration::minutes(10), 100, "hash_hot"))
        .unwrap();
    storage
        .record(make_observation(now - ChronoDuration::hours(2), 101, "hash_warm"))
        .unwrap();
    storage
        .record(make_observation(now - ChronoDuration::days(2), 102, "hash_cold"))
        .unwrap();
    storage
        .record(make_observation(now - ChronoDuration::days(10), 103, "hash_archive"))
        .unwrap();

    storage.compact().unwrap();

    let stats = storage.stats();
    assert_eq!(stats.hot_observations, 1);
    assert_eq!(stats.warm_observations, 1);
    assert_eq!(stats.cold_observations, 1);
    assert_eq!(stats.archive_observations, 1);

    let warm_dir = temp_dir.path().join("warm");
    let cold_dir = temp_dir.path().join("cold");
    assert!(warm_dir.exists());
    assert!(cold_dir.exists());

    let warm_files = count_json_files(&warm_dir);
    let cold_files = count_json_files(&cold_dir);

    assert!(warm_files >= 1);
    assert!(cold_files >= 1);
}

#[test]
fn shadow_cleanup_removes_expired_archive_files() {
    let temp_dir = TempDir::new().unwrap();
    let config = ShadowStorageConfig {
        base_dir: temp_dir.path().to_path_buf(),
        auto_compact: false,
        delete_expired: true,
        ..Default::default()
    };

    let mut storage = ShadowStorage::new(config).unwrap();

    let archive_dir = temp_dir.path().join("archive");
    fs::create_dir_all(&archive_dir).unwrap();
    let stale_path = archive_dir.join("stale.json");
    fs::write(&stale_path, "[]").unwrap();

    let stale_time = std::time::SystemTime::now() - std::time::Duration::from_secs(60 * 60 * 24 * 40);
    let stale_ft = FileTime::from_system_time(stale_time);
    filetime::set_file_times(&stale_path, stale_ft, stale_ft).unwrap();

    let cleaned = storage.cleanup().unwrap();
    assert!(cleaned >= 1);
    assert!(!stale_path.exists());
}
