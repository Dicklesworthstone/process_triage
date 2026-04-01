//! High-performance telemetry recorder using a lock-free ring buffer.
//!
//! This module implements bd-g0q5.2.3: integrating the lock-free ring buffer
//! into the telemetry recording API and background flusher.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::warn;

use arrow::array::{Int32Array, StringArray, TimestampMicrosecondArray};
use arrow::record_batch::RecordBatch;

use crate::disruptor::{FixedSizeEvent, TelemetryRingBuffer, MAX_DETAILS_LEN};
use crate::schema::TableName;
use crate::shadow::EventType;
use crate::writer::{BatchedWriter, WriterConfig};

/// A thread-safe telemetry recorder backed by a lock-free ring buffer.
pub struct TelemetryRecorder {
    ring: Arc<TelemetryRingBuffer>,
    shutdown: Arc<AtomicBool>,
    flusher_handle: Option<thread::JoinHandle<()>>,
}

#[derive(Debug)]
struct AuditRow {
    audit_ts_micros: i64,
    event_type: String,
    severity: &'static str,
    actor: &'static str,
    target_pid: Option<i32>,
    message: String,
    details_json: Option<String>,
}

impl TelemetryRecorder {
    /// Create a new telemetry recorder.
    pub fn new(capacity: usize, config: WriterConfig) -> Self {
        let ring = Arc::new(TelemetryRingBuffer::new(capacity));
        let ring_clone = ring.clone();
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = shutdown.clone();

        // Spawn background flusher thread
        let flusher_handle = thread::spawn(move || {
            let mut writer = BatchedWriter::new(
                TableName::Audit,
                Arc::new(crate::schema::audit_schema()),
                config.clone(),
            );

            let mut last_sequence = 0;
            let flush_interval = Duration::from_secs(crate::DEFAULT_FLUSH_INTERVAL_SECS);
            let mut last_flush = Instant::now();
            let mut pending_rows = Vec::with_capacity(config.batch_size.max(1));

            loop {
                let mut drained_any = false;
                while let Some((seq, event)) = ring_clone.try_read(last_sequence) {
                    drained_any = true;
                    pending_rows.push(audit_row_from_event(&event));
                    last_sequence = seq + 1;
                    ring_clone.advance_consumer(seq);

                    if pending_rows.len() >= config.batch_size.max(1) {
                        if flush_pending_rows(&mut writer, &config, &mut pending_rows).is_ok() {
                            last_flush = Instant::now();
                        }
                    }
                }

                let shutdown_requested = shutdown_clone.load(Ordering::Acquire);
                if !pending_rows.is_empty()
                    && (shutdown_requested || last_flush.elapsed() >= flush_interval)
                {
                    if flush_pending_rows(&mut writer, &config, &mut pending_rows).is_ok() {
                        last_flush = Instant::now();
                    }
                }

                if shutdown_requested {
                    let producer_sequence =
                        ring_clone.producer_sequence.value.load(Ordering::Acquire);
                    if last_sequence >= producer_sequence {
                        break;
                    }
                }

                if !drained_any {
                    thread::sleep(Duration::from_millis(25));
                }
            }

            if !pending_rows.is_empty() {
                let _ = flush_pending_rows(&mut writer, &config, &mut pending_rows);
            }
            if writer.output_path().is_some() {
                let _ = writer.close();
            }
        });

        Self {
            ring,
            shutdown,
            flusher_handle: Some(flusher_handle),
        }
    }

    /// Record a telemetry event.
    ///
    /// This call is lock-free for the producer and publishes a unique slot.
    pub fn record_event(&self, event_type: EventType, pid: u32, details: &str) {
        if let Some(seq) = self.ring.claim() {
            let timestamp_ns = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;
            let event = FixedSizeEvent::from_parts(timestamp_ns, event_type as u32, pid, details);
            self.ring.write_event(seq, event);
            self.ring.commit(seq);
        } else {
            warn!("Telemetry ring buffer full, dropping event");
        }
    }
}

impl Drop for TelemetryRecorder {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(handle) = self.flusher_handle.take() {
            let _ = handle.join();
        }
    }
}

fn audit_row_from_event(event: &FixedSizeEvent) -> AuditRow {
    let details_len = (event.details_len as usize).min(MAX_DETAILS_LEN);
    let details = String::from_utf8_lossy(&event.details[..details_len]).into_owned();
    let event_type = EventType::from_repr(event.event_type)
        .map(|kind| kind.as_str().to_string())
        .unwrap_or_else(|| format!("unknown_event_{}", event.event_type));
    let message = if details.is_empty() {
        event_type.clone()
    } else {
        details.clone()
    };

    AuditRow {
        audit_ts_micros: (event.timestamp_ns / 1_000) as i64,
        event_type,
        severity: "info",
        actor: "telemetry_recorder",
        target_pid: Some(event.pid as i32),
        message,
        details_json: (!details.is_empty())
            .then(|| serde_json::json!({ "details": details }).to_string()),
    }
}

fn flush_pending_rows(
    writer: &mut BatchedWriter,
    config: &WriterConfig,
    pending_rows: &mut Vec<AuditRow>,
) -> Result<(), crate::writer::WriteError> {
    if pending_rows.is_empty() {
        return Ok(());
    }

    let batch = build_audit_batch(config, pending_rows)?;
    writer.write(batch)?;
    writer.flush()?;
    pending_rows.clear();
    Ok(())
}

fn build_audit_batch(
    config: &WriterConfig,
    rows: &[AuditRow],
) -> Result<RecordBatch, crate::writer::WriteError> {
    let audit_ts = TimestampMicrosecondArray::from(
        rows.iter()
            .map(|row| Some(row.audit_ts_micros))
            .collect::<Vec<_>>(),
    )
    .with_timezone("UTC");
    let session_id = StringArray::from(
        rows.iter()
            .map(|_| Some(config.session_id.as_str()))
            .collect::<Vec<_>>(),
    );
    let event_type = StringArray::from(
        rows.iter()
            .map(|row| Some(row.event_type.as_str()))
            .collect::<Vec<_>>(),
    );
    let severity = StringArray::from(
        rows.iter()
            .map(|row| Some(row.severity))
            .collect::<Vec<_>>(),
    );
    let actor = StringArray::from(rows.iter().map(|row| Some(row.actor)).collect::<Vec<_>>());
    let target_pid = Int32Array::from(rows.iter().map(|row| row.target_pid).collect::<Vec<_>>());
    let target_start_id = StringArray::from(vec![None::<&str>; rows.len()]);
    let message = StringArray::from(
        rows.iter()
            .map(|row| Some(row.message.as_str()))
            .collect::<Vec<_>>(),
    );
    let details_json = StringArray::from(
        rows.iter()
            .map(|row| row.details_json.as_deref())
            .collect::<Vec<_>>(),
    );
    let host_id = StringArray::from(
        rows.iter()
            .map(|_| Some(config.host_id.as_str()))
            .collect::<Vec<_>>(),
    );

    RecordBatch::try_new(
        Arc::new(crate::schema::audit_schema()),
        vec![
            Arc::new(audit_ts),
            Arc::new(session_id),
            Arc::new(event_type),
            Arc::new(severity),
            Arc::new(actor),
            Arc::new(target_pid),
            Arc::new(target_start_id),
            Arc::new(message),
            Arc::new(details_json),
            Arc::new(host_id),
        ],
    )
    .map_err(crate::writer::WriteError::from)
}
