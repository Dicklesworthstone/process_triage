use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier};
use std::thread;

use arrow::array::{Int32Array, StringArray};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use pt_telemetry::recorder::TelemetryRecorder;
use pt_telemetry::shadow::EventType;
use pt_telemetry::writer::WriterConfig;
use tempfile::TempDir;

fn collect_parquet_files(root: &Path, out: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(root).expect("read dir");
    for entry in entries {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.is_dir() {
            collect_parquet_files(&path, out);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("parquet") {
            out.push(path);
        }
    }
}

fn read_audit_rows(parquet_files: &[PathBuf]) -> Vec<(String, i32, String)> {
    let mut rows = Vec::new();

    for path in parquet_files {
        let file = fs::File::open(path).expect("open parquet");
        let builder = ParquetRecordBatchReaderBuilder::try_new(file).expect("reader");
        let reader = builder.build().expect("build reader");
        let batches = reader.collect::<Result<Vec<_>, _>>().expect("read batches");

        for batch in batches {
            let event_types = batch
                .column(2)
                .as_any()
                .downcast_ref::<StringArray>()
                .expect("event_type column");
            let target_pids = batch
                .column(5)
                .as_any()
                .downcast_ref::<Int32Array>()
                .expect("target_pid column");
            let messages = batch
                .column(7)
                .as_any()
                .downcast_ref::<StringArray>()
                .expect("message column");

            for row in 0..batch.num_rows() {
                rows.push((
                    event_types.value(row).to_string(),
                    target_pids.value(row),
                    messages.value(row).to_string(),
                ));
            }
        }
    }

    rows
}

#[test]
fn recorder_persists_audit_events_on_drop() {
    let temp_dir = TempDir::new().expect("temp dir");
    let config = WriterConfig::new(
        temp_dir.path().to_path_buf(),
        "pt-20260401-telemetry-recorder".to_string(),
        "test-host".to_string(),
    )
    .with_batch_size(1);

    let recorder = TelemetryRecorder::new(8, config);
    recorder.record_event(EventType::CpuSpike, 4242, "cpu threshold crossed");
    recorder.record_event(EventType::ProcessExit, 4242, "process disappeared");
    drop(recorder);

    let mut parquet_files = Vec::new();
    collect_parquet_files(temp_dir.path(), &mut parquet_files);
    assert_eq!(parquet_files.len(), 1, "expected one parquet output file");

    let rows = read_audit_rows(&parquet_files);
    assert_eq!(rows.len(), 2, "expected both audit events to persist");
    assert_eq!(rows[0].0, "cpu_spike");
    assert_eq!(rows[0].1, 4242);
    assert_eq!(rows[0].2, "cpu threshold crossed");
}

#[test]
fn recorder_persists_all_concurrent_producer_events() {
    let temp_dir = TempDir::new().expect("temp dir");
    let config = WriterConfig::new(
        temp_dir.path().to_path_buf(),
        "pt-20260401-telemetry-concurrent".to_string(),
        "test-host".to_string(),
    )
    .with_batch_size(32);

    let thread_count = 8;
    let events_per_thread = 16;
    let recorder = Arc::new(TelemetryRecorder::new(256, config));
    let start = Arc::new(Barrier::new(thread_count));

    let handles = (0..thread_count)
        .map(|thread_id| {
            let recorder = recorder.clone();
            let start = start.clone();
            thread::spawn(move || {
                start.wait();
                for event_idx in 0..events_per_thread {
                    recorder.record_event(
                        EventType::CpuSpike,
                        10_000 + thread_id as u32,
                        &format!("concurrent-{thread_id}-{event_idx}"),
                    );
                }
            })
        })
        .collect::<Vec<_>>();

    for handle in handles {
        handle.join().expect("thread join");
    }
    drop(recorder);

    let mut parquet_files = Vec::new();
    collect_parquet_files(temp_dir.path(), &mut parquet_files);
    assert!(!parquet_files.is_empty(), "expected parquet output files");

    let rows = read_audit_rows(&parquet_files);
    let expected_rows = thread_count * events_per_thread;
    assert_eq!(rows.len(), expected_rows, "expected every event to persist");

    let unique_messages = rows
        .iter()
        .map(|(_, _, message)| message.clone())
        .collect::<HashSet<_>>();
    assert_eq!(
        unique_messages.len(),
        expected_rows,
        "expected every concurrent producer message to remain distinct",
    );
}
