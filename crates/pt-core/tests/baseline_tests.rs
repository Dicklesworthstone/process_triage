//! Integration tests for per-machine baseline computation and drift detection.

use pt_core::calibrate::baseline::{
    blend_with_global, fit_baseline, score_anomaly, BaselineConfig, BaselineSummary, BaselineStore,
};
use pt_core::calibrate::baseline_persist::{
    BaselineEventType, BaselineManager, BaselineUpdateEvent,
};
use pt_core::inference::wasserstein::{
    wasserstein_1d, DriftSeverity, WassersteinConfig, WassersteinDetector,
};

fn make_series(start: f64, step: f64, n: usize) -> Vec<f64> {
    (0..n).map(|i| start + step * i as f64).collect()
}

fn make_summary(n: usize, mean: f64, std_dev: f64) -> BaselineSummary {
    BaselineSummary {
        n,
        mean,
        std_dev,
        median: mean,
        mad: std_dev * 0.75,
        percentiles: [mean - 2.0 * std_dev, mean - std_dev, mean, mean + std_dev, mean + 2.0 * std_dev],
        cold_start: n < 30,
        schema_version: 1,
    }
}

#[test]
fn test_baseline_initialization_from_24h_data() {
    let observations = make_series(10.0, 0.1, 24);
    let config = BaselineConfig::default();
    let baseline = fit_baseline(&observations, &config).expect("baseline should fit");

    assert_eq!(baseline.n, 24);
    assert!(baseline.cold_start); // 24 < cold_start_threshold (30)
    assert!((baseline.mean - 11.15).abs() < 0.5);
}

#[test]
fn test_baseline_update_replaces_summary_and_updates_metadata() {
    let mut manager = BaselineManager::new("host-alpha".to_string(), BaselineConfig::default());
    let first = make_summary(50, 0.10, 0.02);
    let second = make_summary(80, 0.18, 0.03);

    manager.update_baseline("cpu_baseline".to_string(), first.clone(), 1000.0);
    assert_eq!(manager.state.metadata.total_observations, 50);

    manager.update_baseline("cpu_baseline".to_string(), second.clone(), 2000.0);
    let stored = manager.state.baselines.get("cpu_baseline").unwrap();
    assert!((stored.mean - second.mean).abs() < 1e-6);
    assert_eq!(manager.state.metadata.total_observations, 80);
    assert_eq!(manager.state.updated_at, 2000.0);
}

#[test]
fn test_baseline_drift_detection_wasserstein() {
    let baseline = make_series(10.0, 0.1, 50);
    let current = make_series(15.0, 0.1, 50);

    let detector = WassersteinDetector::new(WassersteinConfig {
        adaptive_threshold: false,
        drift_threshold: 1.0,
        ..WassersteinConfig::default()
    });
    let result = detector.detect_drift(&baseline, &current);

    assert!(result.drifted);
    assert!(matches!(result.severity, DriftSeverity::Significant | DriftSeverity::Severe));
}

#[test]
fn test_baseline_persistence_roundtrip_cross_reboot() {
    let mut manager = BaselineManager::new("host-old".to_string(), BaselineConfig::default());
    manager.update_baseline("memory_baseline".to_string(), make_summary(100, 500.0, 50.0), 1000.0);
    manager.set_global(make_summary(500, 400.0, 40.0), 1000.0);

    let json = manager.export_json().expect("export JSON");
    let imported = BaselineManager::import_json(&json, "host-new", 2000.0).expect("import JSON");

    assert_eq!(imported.state.host_fingerprint, "host-new");
    assert_eq!(imported.state.metadata.imported_from.as_deref(), Some("host-old"));
    assert_eq!(imported.baseline_count(), 1);
    assert!(imported.state.global.is_some());
}

#[test]
fn test_baseline_reset_for_hardware_change() {
    let mut manager = BaselineManager::new("host-old".to_string(), BaselineConfig::default());
    manager.update_baseline("cpu_baseline".to_string(), make_summary(120, 0.2, 0.05), 1000.0);

    manager.reset(2000.0);
    assert_eq!(manager.baseline_count(), 0);
    assert_eq!(manager.state.metadata.reset_count, 1);
    assert_eq!(manager.state.metadata.last_reset_at, Some(2000.0));
}

#[test]
fn test_workload_shift_flags_anomaly() {
    let baseline = make_summary(200, 0.10, 0.03);
    let score = score_anomaly(0.20, &baseline);

    assert!(score.z_score > 3.0);
    assert!(score.is_anomalous);
}

#[test]
fn test_gradual_drift_updates_baseline_mean() {
    let first_window = make_series(50.0, 1.0, 5);
    let extended_window = make_series(50.0, 1.0, 10);

    let config = BaselineConfig::default();
    let baseline_initial = fit_baseline(&first_window, &config).unwrap();
    let baseline_updated = fit_baseline(&extended_window, &config).unwrap();

    assert!(baseline_updated.mean > baseline_initial.mean);
}

#[test]
fn test_multi_day_baseline_stability() {
    let mut observations = Vec::new();
    for _ in 0..7 {
        observations.extend(make_series(100.0, 0.2, 24));
    }

    let config = BaselineConfig::default();
    let baseline = fit_baseline(&observations, &config).unwrap();

    assert!(baseline.std_dev < 5.0);
    assert!((baseline.mean - 102.3).abs() < 1.0);
}

#[test]
fn test_seasonal_pattern_anomaly() {
    let weekend_low = vec![10.0, 12.0, 11.0, 9.0, 10.0, 11.5];
    let config = BaselineConfig::default();
    let baseline = fit_baseline(&weekend_low, &config).unwrap();

    let saturday_high = 25.0;
    let score = score_anomaly(saturday_high, &baseline);
    assert!(score.is_anomalous);
}

#[test]
fn test_baseline_metric_keys_present() {
    let mut store = BaselineStore::default();
    store.baselines.insert("cpu_baseline".to_string(), make_summary(100, 0.2, 0.05));
    store
        .baselines
        .insert("memory_baseline".to_string(), make_summary(100, 512.0, 64.0));
    store
        .baselines
        .insert("lifetime_baseline".to_string(), make_summary(100, 3600.0, 300.0));
    store
        .baselines
        .insert("spawn_rate_baseline".to_string(), make_summary(100, 15.0, 2.0));
    store
        .baselines
        .insert("kill_rate_baseline".to_string(), make_summary(100, 14.0, 2.0));
    store
        .baselines
        .insert("orphan_rate_baseline".to_string(), make_summary(100, 1.0, 0.5));

    let manager = BaselineManager::from_store(&store, "host-metrics".to_string(), 1000.0);
    assert_eq!(manager.baseline_count(), 6);
}

#[test]
fn test_wasserstein_formula_simple_case() {
    let p = vec![1.0, 2.0, 3.0];
    let q = vec![2.0, 3.0, 4.0];
    let dist = wasserstein_1d(&p, &q);

    assert!((dist - 1.0).abs() < 1e-9);
}

#[test]
fn test_z_score_accuracy() {
    let baseline = make_summary(100, 100.0, 10.0);
    let score = score_anomaly(120.0, &baseline);

    assert!((score.z_score - 2.0).abs() < 0.01);
}

#[test]
fn test_baseline_event_logging_shape() {
    let event = BaselineUpdateEvent {
        event_type: BaselineEventType::Updated,
        timestamp: 1234.0,
        host_fingerprint: "host-alpha".to_string(),
        affected_keys: vec!["cpu_baseline".to_string()],
        context: Some("baseline_update".to_string()),
    };

    let json = serde_json::to_string(&event).expect("serialize event");
    assert!(json.contains("\"event_type\":\"Updated\""));
    assert!(json.contains("cpu_baseline"));
}

#[test]
fn test_blend_with_global_cold_start_shrinkage() {
    let host = make_summary(10, 100.0, 15.0);
    let global = make_summary(100, 200.0, 30.0);

    let blended = blend_with_global(&host, &global, 30);
    assert!(blended.mean > 100.0 && blended.mean < 200.0);
    assert!(blended.cold_start);
}
