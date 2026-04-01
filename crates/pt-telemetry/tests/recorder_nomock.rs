use std::fs;
use std::path::{Path, PathBuf};

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

    let file = fs::File::open(&parquet_files[0]).expect("open parquet");
    let builder = ParquetRecordBatchReaderBuilder::try_new(file).expect("reader");
    let reader = builder.build().expect("build reader");
    let batches = reader.collect::<Result<Vec<_>, _>>().expect("read batches");
    let total_rows: usize = batches.iter().map(|batch| batch.num_rows()).sum();
    assert_eq!(total_rows, 2, "expected both audit events to persist");

    let first = &batches[0];
    let event_types = first
        .column(2)
        .as_any()
        .downcast_ref::<StringArray>()
        .expect("event_type column");
    let target_pids = first
        .column(5)
        .as_any()
        .downcast_ref::<Int32Array>()
        .expect("target_pid column");
    let messages = first
        .column(7)
        .as_any()
        .downcast_ref::<StringArray>()
        .expect("message column");

    assert_eq!(event_types.value(0), "cpu_spike");
    assert_eq!(target_pids.value(0), 4242);
    assert_eq!(messages.value(0), "cpu threshold crossed");
}
