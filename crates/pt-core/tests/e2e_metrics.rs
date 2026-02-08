//! E2E tests for the Prometheus metrics endpoint (process_triage-jhvm).
//!
//! Requires the `metrics` feature: `cargo test --features metrics --test e2e_metrics`

#![cfg(feature = "metrics")]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use pt_core::daemon::metrics::{DaemonMetrics, MetricsConfig, MetricsServer};
use pt_core::daemon::{DaemonState, TickMetrics};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Pick a port that is unlikely to collide across parallel test runs.
fn test_port(offset: u16) -> u16 {
    20_000 + (std::process::id() % 5000) as u16 + offset
}

/// Send an HTTP/1.0 request and return the full response (headers + body).
fn http_get(addr: std::net::SocketAddr, path: &str) -> String {
    let mut stream = TcpStream::connect(addr).expect("connect failed");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let req = format!("GET {} HTTP/1.0\r\nHost: localhost\r\n\r\n", path);
    stream.write_all(req.as_bytes()).expect("write failed");
    let mut buf = String::new();
    let _ = stream.read_to_string(&mut buf);
    buf
}

/// Extract just the HTTP body (after the blank line) from a raw response.
fn extract_body(raw: &str) -> &str {
    raw.find("\r\n\r\n")
        .map(|pos| &raw[pos + 4..])
        .unwrap_or(raw)
}

/// Extract HTTP status code from response.
fn extract_status(raw: &str) -> u16 {
    raw.lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or(0)
}

/// Start a metrics server on a test port, returning the server + its actual address.
fn start_test_server(offset: u16, metrics: DaemonMetrics) -> MetricsServer {
    let port = test_port(offset);
    let config = MetricsConfig {
        enabled: true,
        bind: "127.0.0.1".to_string(),
        port,
        path: "/metrics".to_string(),
        rate_limit_per_sec: 100,
    };
    let server = MetricsServer::start(&config, metrics)
        .unwrap_or_else(|e| panic!("Failed to start metrics server on port {}: {}", port, e));
    // Let the server bind
    std::thread::sleep(Duration::from_millis(100));
    server
}

// ---------------------------------------------------------------------------
// Prometheus format compliance
// ---------------------------------------------------------------------------

mod prometheus_format {
    use super::*;

    #[test]
    fn metrics_endpoint_returns_200() {
        let metrics = DaemonMetrics::new().unwrap();
        let server = start_test_server(0, metrics);
        let resp = http_get(server.addr(), "/metrics");
        assert_eq!(extract_status(&resp), 200);
        server.shutdown();
    }

    #[test]
    fn content_type_is_prometheus_text() {
        let metrics = DaemonMetrics::new().unwrap();
        let server = start_test_server(1, metrics);
        let resp = http_get(server.addr(), "/metrics");
        let headers = resp.split("\r\n\r\n").next().unwrap_or("");
        assert!(
            headers.contains("text/plain"),
            "Content-Type should be text/plain, got headers: {}",
            headers
        );
        server.shutdown();
    }

    #[test]
    fn every_metric_has_help_and_type() {
        let metrics = DaemonMetrics::new().unwrap();
        // Observe so histograms appear
        metrics.record_scan("success", 1.0);
        metrics.record_tick_duration("normal", 0.05);

        let server = start_test_server(2, metrics);
        let resp = http_get(server.addr(), "/metrics");
        let body = extract_body(&resp);

        // Collect all metric names from # HELP lines
        let help_names: Vec<&str> = body
            .lines()
            .filter(|l| l.starts_with("# HELP "))
            .filter_map(|l| {
                l.strip_prefix("# HELP ")
                    .and_then(|s| s.split_whitespace().next())
            })
            .collect();

        // Every HELP should have a matching TYPE
        for name in &help_names {
            let type_line = format!("# TYPE {}", name);
            assert!(
                body.contains(&type_line),
                "Metric {} has HELP but no TYPE line",
                name
            );
        }

        server.shutdown();
    }

    #[test]
    fn no_duplicate_help_lines() {
        let metrics = DaemonMetrics::new().unwrap();
        metrics.record_scan("success", 1.0);
        let server = start_test_server(3, metrics);
        let resp = http_get(server.addr(), "/metrics");
        let body = extract_body(&resp);

        let help_lines: Vec<&str> = body.lines().filter(|l| l.starts_with("# HELP ")).collect();
        let mut seen = std::collections::HashSet::new();
        for line in &help_lines {
            let name = line
                .strip_prefix("# HELP ")
                .and_then(|s| s.split_whitespace().next())
                .unwrap_or("");
            assert!(seen.insert(name), "Duplicate HELP for metric: {}", name);
        }
        server.shutdown();
    }
}

// ---------------------------------------------------------------------------
// Metric types and values
// ---------------------------------------------------------------------------

mod metric_values {
    use super::*;

    #[test]
    fn build_info_present_with_version() {
        let metrics = DaemonMetrics::new().unwrap();
        let server = start_test_server(10, metrics);
        let resp = http_get(server.addr(), "/metrics");
        let body = extract_body(&resp);

        assert!(body.contains("pt_build_info"), "build_info missing");
        assert!(
            body.contains(&format!("version=\"{}\"", env!("CARGO_PKG_VERSION"))),
            "build_info missing version label"
        );
        server.shutdown();
    }

    #[test]
    fn counters_increment() {
        let metrics = DaemonMetrics::new().unwrap();
        metrics.record_scan("success", 1.0);
        metrics.record_scan("success", 2.0);
        metrics.record_scan("failed", 0.5);

        let server = start_test_server(11, metrics);
        let resp = http_get(server.addr(), "/metrics");
        let body = extract_body(&resp);

        assert!(
            body.contains("pt_scans_total{status=\"success\"} 2"),
            "Expected 2 success scans, body: {}",
            body
        );
        assert!(
            body.contains("pt_scans_total{status=\"failed\"} 1"),
            "Expected 1 failed scan"
        );
        server.shutdown();
    }

    #[test]
    fn gauges_reflect_tick_state() {
        let metrics = DaemonMetrics::new().unwrap();
        let tick = TickMetrics {
            timestamp: "2026-01-15T12:00:00Z".to_string(),
            load_avg_1: 3.14,
            load_avg_5: 2.71,
            memory_used_mb: 6000,
            memory_total_mb: 16000,
            swap_used_mb: 200,
            process_count: 450,
            orphan_count: 12,
        };
        let state = DaemonState {
            started_at: "2026-01-15T00:00:00Z".to_string(),
            tick_count: 100,
            last_tick_at: None,
            last_escalation_at: None,
            escalation_count: 7,
            deferred_count: 3,
            recent_events: std::collections::VecDeque::new(),
        };
        metrics.update_from_tick(&tick, &state);

        let server = start_test_server(12, metrics);
        let resp = http_get(server.addr(), "/metrics");
        let body = extract_body(&resp);

        assert!(body.contains("pt_tick_count 100"), "tick_count mismatch");
        assert!(
            body.contains("pt_escalation_count 7"),
            "escalation_count mismatch"
        );
        assert!(
            body.contains("pt_deferred_count 3"),
            "deferred_count mismatch"
        );
        assert!(
            body.contains("pt_memory_used_mb 6000"),
            "memory_used_mb mismatch"
        );
        assert!(
            body.contains("pt_memory_total_mb 16000"),
            "memory_total_mb mismatch"
        );
        assert!(
            body.contains("pt_swap_used_mb 200"),
            "swap_used_mb mismatch"
        );
        assert!(
            body.contains("pt_process_count 450"),
            "process_count mismatch"
        );
        assert!(body.contains("pt_orphan_count 12"), "orphan_count mismatch");
        server.shutdown();
    }

    #[test]
    fn histogram_has_buckets_sum_count() {
        let metrics = DaemonMetrics::new().unwrap();
        metrics.record_scan("success", 0.3);
        metrics.record_scan("success", 1.5);
        metrics.record_scan("success", 7.0);

        let server = start_test_server(13, metrics);
        let resp = http_get(server.addr(), "/metrics");
        let body = extract_body(&resp);

        // Histogram should have _bucket, _sum, _count lines
        assert!(
            body.contains("pt_scan_duration_seconds_bucket{"),
            "Missing histogram buckets"
        );
        assert!(
            body.contains("pt_scan_duration_seconds_sum{"),
            "Missing histogram sum"
        );
        assert!(
            body.contains("pt_scan_duration_seconds_count{"),
            "Missing histogram count"
        );

        // Verify count = 3
        for line in body.lines() {
            if line.starts_with("pt_scan_duration_seconds_count{type=\"success\"}") {
                let count: f64 = line.split_whitespace().last().unwrap().parse().unwrap();
                assert_eq!(count, 3.0, "Expected 3 observations");
            }
        }

        server.shutdown();
    }

    #[test]
    fn load_average_labels() {
        let metrics = DaemonMetrics::new().unwrap();
        let tick = TickMetrics {
            timestamp: "2026-01-15T12:00:00Z".to_string(),
            load_avg_1: 4.2,
            load_avg_5: 3.1,
            memory_used_mb: 1000,
            memory_total_mb: 8000,
            swap_used_mb: 0,
            process_count: 100,
            orphan_count: 0,
        };
        let state = DaemonState::new();
        metrics.update_from_tick(&tick, &state);

        let server = start_test_server(14, metrics);
        let resp = http_get(server.addr(), "/metrics");
        let body = extract_body(&resp);

        assert!(
            body.contains("pt_load_average{period=\"1m\"}"),
            "Missing 1m load average"
        );
        assert!(
            body.contains("pt_load_average{period=\"5m\"}"),
            "Missing 5m load average"
        );
        server.shutdown();
    }

    #[test]
    fn escalation_types_tracked() {
        let metrics = DaemonMetrics::new().unwrap();
        metrics.record_escalation("completed");
        metrics.record_escalation("completed");
        metrics.record_escalation("deferred");

        let server = start_test_server(15, metrics);
        let resp = http_get(server.addr(), "/metrics");
        let body = extract_body(&resp);

        assert!(
            body.contains("pt_escalations_total{type=\"completed\"} 2"),
            "Expected 2 completed escalations"
        );
        assert!(
            body.contains("pt_escalations_total{type=\"deferred\"} 1"),
            "Expected 1 deferred escalation"
        );
        server.shutdown();
    }

    #[test]
    fn error_types_tracked() {
        let metrics = DaemonMetrics::new().unwrap();
        metrics.record_error("config_load");
        metrics.record_error("scan_failure");
        metrics.record_error("scan_failure");

        let server = start_test_server(16, metrics);
        let resp = http_get(server.addr(), "/metrics");
        let body = extract_body(&resp);

        assert!(
            body.contains("pt_errors_total{type=\"config_load\"} 1"),
            "Expected 1 config_load error"
        );
        assert!(
            body.contains("pt_errors_total{type=\"scan_failure\"} 2"),
            "Expected 2 scan_failure errors"
        );
        server.shutdown();
    }

    #[test]
    fn uptime_increases_over_time() {
        let metrics = DaemonMetrics::new().unwrap();
        let server = start_test_server(17, metrics);

        // First scrape
        let resp1 = http_get(server.addr(), "/metrics");
        let body1 = extract_body(&resp1);
        let uptime1 = extract_gauge_value(body1, "pt_daemon_uptime_seconds");

        std::thread::sleep(Duration::from_secs(2));

        // Second scrape
        let resp2 = http_get(server.addr(), "/metrics");
        let body2 = extract_body(&resp2);
        let uptime2 = extract_gauge_value(body2, "pt_daemon_uptime_seconds");

        assert!(
            uptime2 > uptime1,
            "Uptime should increase: {} vs {}",
            uptime1,
            uptime2
        );
        server.shutdown();
    }

    fn extract_gauge_value(body: &str, metric_name: &str) -> f64 {
        for line in body.lines() {
            if line.starts_with(metric_name) && !line.starts_with('#') {
                if let Some(val) = line.split_whitespace().last() {
                    return val.parse().unwrap_or(0.0);
                }
            }
        }
        panic!("Metric {} not found in body", metric_name);
    }
}

// ---------------------------------------------------------------------------
// Health endpoint
// ---------------------------------------------------------------------------

mod health_endpoint {
    use super::*;

    #[test]
    fn health_returns_200_ok() {
        let metrics = DaemonMetrics::new().unwrap();
        let server = start_test_server(20, metrics);
        let resp = http_get(server.addr(), "/health");
        assert_eq!(extract_status(&resp), 200);
        assert!(extract_body(&resp).contains("ok"));
        server.shutdown();
    }

    #[test]
    fn healthz_returns_200_ok() {
        let metrics = DaemonMetrics::new().unwrap();
        let server = start_test_server(21, metrics);
        let resp = http_get(server.addr(), "/healthz");
        assert_eq!(extract_status(&resp), 200);
        assert!(extract_body(&resp).contains("ok"));
        server.shutdown();
    }

    #[test]
    fn unknown_path_returns_404() {
        let metrics = DaemonMetrics::new().unwrap();
        let server = start_test_server(22, metrics);
        let resp = http_get(server.addr(), "/nonexistent");
        assert_eq!(extract_status(&resp), 404);
        server.shutdown();
    }

    #[test]
    fn root_path_returns_404() {
        let metrics = DaemonMetrics::new().unwrap();
        let server = start_test_server(23, metrics);
        let resp = http_get(server.addr(), "/");
        assert_eq!(extract_status(&resp), 404);
        server.shutdown();
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

mod configuration {
    use super::*;

    #[test]
    fn custom_path() {
        let metrics = DaemonMetrics::new().unwrap();
        metrics.record_scan("success", 1.0);

        let port = test_port(30);
        let config = MetricsConfig {
            enabled: true,
            bind: "127.0.0.1".to_string(),
            port,
            path: "/custom/prometheus".to_string(),
            rate_limit_per_sec: 100,
        };
        let server = MetricsServer::start(&config, metrics).unwrap();
        std::thread::sleep(Duration::from_millis(100));

        // Default path should 404
        let resp = http_get(server.addr(), "/metrics");
        assert_eq!(extract_status(&resp), 404);

        // Custom path should 200
        let resp = http_get(server.addr(), "/custom/prometheus");
        assert_eq!(extract_status(&resp), 200);
        assert!(extract_body(&resp).contains("pt_scans_total"));

        server.shutdown();
    }

    #[test]
    fn default_config_values() {
        let config = MetricsConfig::default();
        assert_eq!(config.port, 9184);
        assert_eq!(config.bind, "127.0.0.1");
        assert_eq!(config.path, "/metrics");
        assert!(config.enabled);
        assert_eq!(config.rate_limit_per_sec, 10);
    }

    #[test]
    fn config_serialization_roundtrip() {
        let config = MetricsConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let restored: MetricsConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.port, config.port);
        assert_eq!(restored.bind, config.bind);
        assert_eq!(restored.path, config.path);
    }
}

// ---------------------------------------------------------------------------
// Multiple scrapes / stability
// ---------------------------------------------------------------------------

mod stability {
    use super::*;

    #[test]
    fn multiple_sequential_scrapes() {
        let metrics = DaemonMetrics::new().unwrap();
        metrics.record_scan("success", 1.0);

        let server = start_test_server(40, metrics);

        for i in 0..5 {
            let resp = http_get(server.addr(), "/metrics");
            assert_eq!(
                extract_status(&resp),
                200,
                "Scrape {} failed with non-200",
                i
            );
            assert!(
                extract_body(&resp).contains("pt_build_info"),
                "Scrape {} missing build_info",
                i
            );
        }

        server.shutdown();
    }

    #[test]
    fn graceful_shutdown() {
        let metrics = DaemonMetrics::new().unwrap();
        let server = start_test_server(41, metrics);

        // Verify server is running
        let resp = http_get(server.addr(), "/health");
        assert_eq!(extract_status(&resp), 200);

        let addr = server.addr();

        // Shutdown
        server.shutdown();

        // After shutdown, connections should be refused
        std::thread::sleep(Duration::from_millis(200));
        let result = TcpStream::connect_timeout(&addr.into(), Duration::from_millis(500));
        assert!(
            result.is_err(),
            "Should not be able to connect after shutdown"
        );
    }
}

// ---------------------------------------------------------------------------
// Naming conventions
// ---------------------------------------------------------------------------

mod naming_conventions {
    use super::*;

    #[test]
    fn all_metrics_use_pt_prefix() {
        let metrics = DaemonMetrics::new().unwrap();
        metrics.record_scan("success", 1.0);
        metrics.record_tick_duration("normal", 0.05);

        let server = start_test_server(50, metrics);
        let resp = http_get(server.addr(), "/metrics");
        let body = extract_body(&resp);

        for line in body.lines() {
            if line.starts_with("# HELP ") {
                let name = line
                    .strip_prefix("# HELP ")
                    .and_then(|s| s.split_whitespace().next())
                    .unwrap_or("");
                assert!(
                    name.starts_with("pt_"),
                    "Metric {} does not use pt_ prefix",
                    name
                );
            }
        }
        server.shutdown();
    }

    #[test]
    fn counter_names_end_with_total() {
        let metrics = DaemonMetrics::new().unwrap();
        metrics.record_scan("success", 1.0);
        metrics.record_escalation("completed");
        metrics.record_error("test");

        let server = start_test_server(51, metrics);
        let resp = http_get(server.addr(), "/metrics");
        let body = extract_body(&resp);

        // Find all counter TYPE lines
        for line in body.lines() {
            if line.starts_with("# TYPE ") && line.ends_with(" counter") {
                let name = line
                    .strip_prefix("# TYPE ")
                    .and_then(|s| s.split_whitespace().next())
                    .unwrap_or("");
                assert!(
                    name.ends_with("_total"),
                    "Counter {} should end with _total",
                    name
                );
            }
        }
        server.shutdown();
    }

    #[test]
    fn histogram_names_include_unit() {
        let metrics = DaemonMetrics::new().unwrap();
        metrics.record_scan("success", 1.0);
        metrics.record_tick_duration("normal", 0.05);

        let server = start_test_server(52, metrics);
        let resp = http_get(server.addr(), "/metrics");
        let body = extract_body(&resp);

        // Find histogram TYPE lines
        for line in body.lines() {
            if line.starts_with("# TYPE ") && line.ends_with(" histogram") {
                let name = line
                    .strip_prefix("# TYPE ")
                    .and_then(|s| s.split_whitespace().next())
                    .unwrap_or("");
                assert!(
                    name.contains("_seconds") || name.contains("_bytes"),
                    "Histogram {} should include unit suffix (_seconds or _bytes)",
                    name
                );
            }
        }
        server.shutdown();
    }
}
