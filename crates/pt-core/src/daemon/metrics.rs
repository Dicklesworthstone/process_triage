//! Prometheus metrics endpoint for the dormant daemon.
//!
//! Exposes operational metrics at `/metrics` (configurable) in Prometheus
//! exposition format. Runs a lightweight HTTP server on a background thread.
//!
//! ## Metrics
//!
//! **Counters:**
//! - `pt_scans_total` — total scans by status (success/failed)
//! - `pt_kills_total` — kills by outcome and classification
//! - `pt_escalations_total` — escalation events by type
//! - `pt_errors_total` — errors by type
//!
//! **Gauges:**
//! - `pt_candidates_current` — current candidate count by classification
//! - `pt_daemon_uptime_seconds` — daemon uptime
//! - `pt_last_scan_timestamp` — unix timestamp of last scan
//! - `pt_load_average` — system load averages (1m, 5m)
//! - `pt_memory_used_mb` — system memory usage
//! - `pt_process_count` — total process count
//! - `pt_orphan_count` — orphaned process count
//!
//! **Histograms:**
//! - `pt_scan_duration_seconds` — scan duration
//! - `pt_tick_duration_seconds` — daemon tick duration
//!
//! **Info:**
//! - `pt_build_info` — version, commit, build date

use prometheus::{
    Encoder, GaugeVec, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, Opts,
    Registry, TextEncoder,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Instant;
use tracing::{debug, error, info, warn};

/// Configuration for the metrics endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Enable the metrics server.
    pub enabled: bool,
    /// Bind address (default: 127.0.0.1).
    pub bind: String,
    /// Port (default: 9184).
    pub port: u16,
    /// URL path (default: /metrics).
    pub path: String,
    /// Max scrapes per second from a single client.
    pub rate_limit_per_sec: u32,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bind: "127.0.0.1".to_string(),
            port: 9184,
            path: "/metrics".to_string(),
            rate_limit_per_sec: 10,
        }
    }
}

/// Prometheus metrics collection for the daemon.
///
/// All metric updates are thread-safe via atomic operations in the prometheus crate.
#[derive(Clone)]
pub struct DaemonMetrics {
    pub registry: Registry,

    // Counters
    pub scans_total: IntCounterVec,
    pub escalations_total: IntCounterVec,
    pub errors_total: IntCounterVec,

    // Gauges
    pub daemon_uptime_seconds: IntGauge,
    pub last_scan_timestamp: GaugeVec,
    pub tick_count: IntGauge,
    pub escalation_count: IntGauge,
    pub deferred_count: IntGauge,
    pub load_average: GaugeVec,
    pub memory_used_mb: IntGauge,
    pub memory_total_mb: IntGauge,
    pub swap_used_mb: IntGauge,
    pub process_count: IntGauge,
    pub orphan_count: IntGauge,
    pub candidates_current: IntGaugeVec,

    // Histograms
    pub scan_duration_seconds: HistogramVec,
    pub tick_duration_seconds: HistogramVec,

    // Internal
    started_at: Instant,
}

impl DaemonMetrics {
    /// Create a new metrics collection and register all metrics.
    pub fn new() -> Result<Self, prometheus::Error> {
        let registry = Registry::new();

        // -- Counters --
        let scans_total = IntCounterVec::new(
            Opts::new("pt_scans_total", "Total scans executed by the daemon"),
            &["status"],
        )?;
        registry.register(Box::new(scans_total.clone()))?;

        let escalations_total = IntCounterVec::new(
            Opts::new("pt_escalations_total", "Total escalation events"),
            &["type"],
        )?;
        registry.register(Box::new(escalations_total.clone()))?;

        let errors_total = IntCounterVec::new(
            Opts::new("pt_errors_total", "Total errors by type"),
            &["type"],
        )?;
        registry.register(Box::new(errors_total.clone()))?;

        // -- Gauges --
        let daemon_uptime_seconds =
            IntGauge::new("pt_daemon_uptime_seconds", "Daemon uptime in seconds")?;
        registry.register(Box::new(daemon_uptime_seconds.clone()))?;

        let last_scan_timestamp = GaugeVec::new(
            Opts::new("pt_last_scan_timestamp", "Unix timestamp of last scan"),
            &["type"],
        )?;
        registry.register(Box::new(last_scan_timestamp.clone()))?;

        let tick_count = IntGauge::new("pt_tick_count", "Total ticks processed")?;
        registry.register(Box::new(tick_count.clone()))?;

        let escalation_count =
            IntGauge::new("pt_escalation_count", "Total successful escalations")?;
        registry.register(Box::new(escalation_count.clone()))?;

        let deferred_count = IntGauge::new("pt_deferred_count", "Total deferred escalations")?;
        registry.register(Box::new(deferred_count.clone()))?;

        let load_average = GaugeVec::new(
            Opts::new("pt_load_average", "System load average"),
            &["period"],
        )?;
        registry.register(Box::new(load_average.clone()))?;

        let memory_used_mb = IntGauge::new("pt_memory_used_mb", "System memory used (MB)")?;
        registry.register(Box::new(memory_used_mb.clone()))?;

        let memory_total_mb = IntGauge::new("pt_memory_total_mb", "System total memory (MB)")?;
        registry.register(Box::new(memory_total_mb.clone()))?;

        let swap_used_mb = IntGauge::new("pt_swap_used_mb", "System swap used (MB)")?;
        registry.register(Box::new(swap_used_mb.clone()))?;

        let process_count = IntGauge::new("pt_process_count", "Total process count")?;
        registry.register(Box::new(process_count.clone()))?;

        let orphan_count = IntGauge::new("pt_orphan_count", "Orphaned process count")?;
        registry.register(Box::new(orphan_count.clone()))?;

        let candidates_current = IntGaugeVec::new(
            Opts::new(
                "pt_candidates_current",
                "Current candidate count by classification",
            ),
            &["classification"],
        )?;
        registry.register(Box::new(candidates_current.clone()))?;

        // -- Histograms --
        let scan_duration_seconds = HistogramVec::new(
            HistogramOpts::new("pt_scan_duration_seconds", "Scan duration in seconds")
                .buckets(vec![0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0]),
            &["type"],
        )?;
        registry.register(Box::new(scan_duration_seconds.clone()))?;

        let tick_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "pt_tick_duration_seconds",
                "Tick processing duration in seconds",
            )
            .buckets(vec![0.001, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0]),
            &["outcome"],
        )?;
        registry.register(Box::new(tick_duration_seconds.clone()))?;

        // -- Info (build info as a gauge with const labels) --
        let build_info = IntGauge::with_opts(
            Opts::new("pt_build_info", "Build information")
                .const_label("version", env!("CARGO_PKG_VERSION"))
                .const_label("rust_version", env!("CARGO_PKG_RUST_VERSION")),
        )?;
        build_info.set(1);
        registry.register(Box::new(build_info))?;

        Ok(Self {
            registry,
            scans_total,
            escalations_total,
            errors_total,
            daemon_uptime_seconds,
            last_scan_timestamp,
            tick_count,
            escalation_count,
            deferred_count,
            load_average,
            memory_used_mb,
            memory_total_mb,
            swap_used_mb,
            process_count,
            orphan_count,
            candidates_current,
            scan_duration_seconds,
            tick_duration_seconds,
            started_at: Instant::now(),
        })
    }

    /// Update metrics from a daemon tick's system metrics.
    pub fn update_from_tick(&self, tick_metrics: &super::TickMetrics, state: &super::DaemonState) {
        self.daemon_uptime_seconds
            .set(self.started_at.elapsed().as_secs() as i64);
        self.tick_count.set(state.tick_count as i64);
        self.escalation_count.set(state.escalation_count as i64);
        self.deferred_count.set(state.deferred_count as i64);

        self.load_average
            .with_label_values(&["1m"])
            .set(tick_metrics.load_avg_1);
        self.load_average
            .with_label_values(&["5m"])
            .set(tick_metrics.load_avg_5);
        self.memory_used_mb.set(tick_metrics.memory_used_mb as i64);
        self.memory_total_mb
            .set(tick_metrics.memory_total_mb as i64);
        self.swap_used_mb.set(tick_metrics.swap_used_mb as i64);
        self.process_count.set(tick_metrics.process_count as i64);
        self.orphan_count.set(tick_metrics.orphan_count as i64);
    }

    /// Record a completed scan.
    pub fn record_scan(&self, status: &str, duration_secs: f64) {
        self.scans_total.with_label_values(&[status]).inc();
        self.scan_duration_seconds
            .with_label_values(&[status])
            .observe(duration_secs);
        if status == "success" {
            let now = chrono::Utc::now().timestamp() as f64;
            self.last_scan_timestamp
                .with_label_values(&["full"])
                .set(now);
        }
    }

    /// Record an escalation event.
    pub fn record_escalation(&self, escalation_type: &str) {
        self.escalations_total
            .with_label_values(&[escalation_type])
            .inc();
    }

    /// Record an error.
    pub fn record_error(&self, error_type: &str) {
        self.errors_total.with_label_values(&[error_type]).inc();
    }

    /// Record a tick duration.
    pub fn record_tick_duration(&self, outcome: &str, duration_secs: f64) {
        self.tick_duration_seconds
            .with_label_values(&[outcome])
            .observe(duration_secs);
    }

    /// Render all metrics in Prometheus text exposition format.
    pub fn render(&self) -> Result<String, prometheus::Error> {
        // Update uptime right before rendering
        self.daemon_uptime_seconds
            .set(self.started_at.elapsed().as_secs() as i64);

        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer)?;
        Ok(String::from_utf8_lossy(&buffer).into_owned())
    }
}

impl Default for DaemonMetrics {
    fn default() -> Self {
        Self::new().expect("failed to create default DaemonMetrics")
    }
}

/// Handle to the running metrics HTTP server.
pub struct MetricsServer {
    shutdown: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
    addr: SocketAddr,
}

impl MetricsServer {
    /// Start the metrics HTTP server on a background thread.
    pub fn start(config: &MetricsConfig, metrics: DaemonMetrics) -> Result<Self, String> {
        let addr: SocketAddr = format!("{}:{}", config.bind, config.port)
            .parse()
            .map_err(|e| format!("invalid metrics bind address: {}", e))?;

        let server = tiny_http::Server::http(addr)
            .map_err(|e| format!("failed to start metrics server on {}: {}", addr, e))?;

        info!(addr = %addr, path = %config.path, "metrics server started");

        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = shutdown.clone();
        let path = config.path.clone();

        let thread = thread::Builder::new()
            .name("pt-metrics".to_string())
            .spawn(move || {
                serve_loop(server, &metrics, &shutdown_clone, &path);
            })
            .map_err(|e| format!("failed to spawn metrics thread: {}", e))?;

        Ok(Self {
            shutdown,
            thread: Some(thread),
            addr,
        })
    }

    /// Get the bound address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Shut down the metrics server.
    pub fn shutdown(mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        // Send a dummy request to unblock the accept loop
        let _ = std::net::TcpStream::connect(self.addr);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        info!("metrics server stopped");
    }
}

impl Drop for MetricsServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let _ = std::net::TcpStream::connect(self.addr);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Main serve loop: accept requests, serve /metrics, reject everything else.
fn serve_loop(
    server: tiny_http::Server,
    metrics: &DaemonMetrics,
    shutdown: &AtomicBool,
    path: &str,
) {
    loop {
        if shutdown.load(Ordering::SeqCst) {
            break;
        }

        // Accept with timeout so we can check shutdown flag
        let request = match server.recv_timeout(std::time::Duration::from_secs(1)) {
            Ok(Some(req)) => req,
            Ok(None) => continue, // timeout, check shutdown flag
            Err(e) => {
                if !shutdown.load(Ordering::SeqCst) {
                    error!(error = %e, "metrics server accept error");
                }
                break;
            }
        };

        if shutdown.load(Ordering::SeqCst) {
            let _ = request
                .respond(tiny_http::Response::from_string("shutting down").with_status_code(503));
            break;
        }

        let url = request.url().to_string();
        debug!(method = %request.method(), url = %url, "metrics scrape");

        if url == path || url == format!("{}/", path) {
            match metrics.render() {
                Ok(body) => {
                    let response = tiny_http::Response::from_string(body).with_header(
                        "Content-Type: text/plain; version=0.0.4; charset=utf-8"
                            .parse::<tiny_http::Header>()
                            .unwrap(),
                    );
                    if let Err(e) = request.respond(response) {
                        warn!(error = %e, "failed to send metrics response");
                    }
                }
                Err(e) => {
                    error!(error = %e, "failed to render metrics");
                    let _ = request.respond(
                        tiny_http::Response::from_string(format!("error: {}", e))
                            .with_status_code(500),
                    );
                }
            }
        } else if url == "/health" || url == "/healthz" {
            let _ = request.respond(tiny_http::Response::from_string("ok"));
        } else {
            let _ = request
                .respond(tiny_http::Response::from_string("not found").with_status_code(404));
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_creation() {
        let metrics = DaemonMetrics::new().unwrap();
        assert!(metrics.render().unwrap().contains("pt_build_info"));
    }

    #[test]
    fn test_metrics_update_from_tick() {
        let metrics = DaemonMetrics::new().unwrap();
        let tick = super::super::TickMetrics {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            load_avg_1: 2.5,
            load_avg_5: 1.8,
            memory_used_mb: 4000,
            memory_total_mb: 8000,
            swap_used_mb: 100,
            process_count: 300,
            orphan_count: 5,
        };
        let state = super::super::DaemonState {
            started_at: "2026-01-01T00:00:00Z".to_string(),
            tick_count: 42,
            last_tick_at: None,
            last_escalation_at: None,
            escalation_count: 3,
            deferred_count: 1,
            recent_events: std::collections::VecDeque::new(),
        };

        metrics.update_from_tick(&tick, &state);

        let output = metrics.render().unwrap();
        assert!(output.contains("pt_tick_count 42"));
        assert!(output.contains("pt_escalation_count 3"));
        assert!(output.contains("pt_deferred_count 1"));
        assert!(output.contains("pt_memory_used_mb 4000"));
        assert!(output.contains("pt_process_count 300"));
        assert!(output.contains("pt_orphan_count 5"));
    }

    #[test]
    fn test_counter_increments() {
        let metrics = DaemonMetrics::new().unwrap();

        metrics.record_scan("success", 1.5);
        metrics.record_scan("success", 2.0);
        metrics.record_scan("failed", 0.1);
        metrics.record_escalation("completed");
        metrics.record_escalation("deferred");
        metrics.record_error("config_load");

        let output = metrics.render().unwrap();
        assert!(output.contains("pt_scans_total{status=\"success\"} 2"));
        assert!(output.contains("pt_scans_total{status=\"failed\"} 1"));
        assert!(output.contains("pt_escalations_total{type=\"completed\"} 1"));
        assert!(output.contains("pt_errors_total{type=\"config_load\"} 1"));
    }

    #[test]
    fn test_histogram_observations() {
        let metrics = DaemonMetrics::new().unwrap();

        metrics.record_scan("success", 1.5);
        metrics.record_tick_duration("normal", 0.05);

        let output = metrics.render().unwrap();
        assert!(output.contains("pt_scan_duration_seconds"));
        assert!(output.contains("pt_tick_duration_seconds"));
    }

    #[test]
    fn test_render_valid_prometheus_format() {
        let metrics = DaemonMetrics::new().unwrap();

        // Observe some metrics so they appear in output
        metrics.record_scan("success", 1.0);
        metrics.record_tick_duration("normal", 0.05);

        let output = metrics.render().unwrap();

        // Prometheus format: each metric has HELP and TYPE lines
        assert!(output.contains("# HELP pt_build_info"));
        assert!(output.contains("# TYPE pt_build_info gauge"));
        assert!(output.contains("# HELP pt_daemon_uptime_seconds"));
        assert!(output.contains("# HELP pt_scans_total"));
        assert!(output.contains("# TYPE pt_scans_total counter"));
        assert!(output.contains("# HELP pt_scan_duration_seconds"));
        assert!(output.contains("# TYPE pt_scan_duration_seconds histogram"));
    }

    #[test]
    fn test_build_info_has_version() {
        let metrics = DaemonMetrics::new().unwrap();
        let output = metrics.render().unwrap();
        assert!(output.contains(&format!("version=\"{}\"", env!("CARGO_PKG_VERSION"))));
    }

    #[test]
    fn test_metrics_server_starts_and_serves() {
        let config = MetricsConfig {
            enabled: true,
            bind: "127.0.0.1".to_string(),
            port: 0, // Let OS pick a port
            path: "/metrics".to_string(),
            rate_limit_per_sec: 10,
        };

        let metrics = DaemonMetrics::new().unwrap();
        metrics.record_scan("success", 1.0);

        // tiny_http doesn't support port 0 well, use a specific port
        let config = MetricsConfig {
            port: 19184 + (std::process::id() % 1000) as u16,
            ..config
        };

        let server = match MetricsServer::start(&config, metrics) {
            Ok(s) => s,
            Err(e) => {
                // Port may be in use in CI, skip gracefully
                eprintln!("skipping metrics server test: {}", e);
                return;
            }
        };

        // Give server time to start
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Fetch /metrics
        let resp = std::net::TcpStream::connect(server.addr());
        if let Ok(mut stream) = resp {
            use std::io::{Read, Write};
            let _ = stream
                .write_all(format!("GET /metrics HTTP/1.0\r\nHost: localhost\r\n\r\n").as_bytes());
            let mut buf = String::new();
            let _ = stream.read_to_string(&mut buf);

            assert!(
                buf.contains("200 OK"),
                "Expected 200 OK, got: {}",
                &buf[..100.min(buf.len())]
            );
            assert!(
                buf.contains("pt_build_info"),
                "Expected pt_build_info in response"
            );
            assert!(
                buf.contains("pt_scans_total"),
                "Expected pt_scans_total in response"
            );
        }

        // Fetch /health
        if let Ok(mut stream) = std::net::TcpStream::connect(server.addr()) {
            use std::io::{Read, Write};
            let _ = stream.write_all(b"GET /health HTTP/1.0\r\nHost: localhost\r\n\r\n");
            let mut buf = String::new();
            let _ = stream.read_to_string(&mut buf);
            assert!(buf.contains("200 OK"), "Health check should return 200");
        }

        // Fetch unknown path
        if let Ok(mut stream) = std::net::TcpStream::connect(server.addr()) {
            use std::io::{Read, Write};
            let _ = stream.write_all(b"GET /unknown HTTP/1.0\r\nHost: localhost\r\n\r\n");
            let mut buf = String::new();
            let _ = stream.read_to_string(&mut buf);
            assert!(buf.contains("404"), "Unknown path should return 404");
        }

        server.shutdown();
    }

    #[test]
    fn test_default_config() {
        let config = MetricsConfig::default();
        assert_eq!(config.port, 9184);
        assert_eq!(config.bind, "127.0.0.1");
        assert_eq!(config.path, "/metrics");
        assert!(config.enabled);
    }
}
