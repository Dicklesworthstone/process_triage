//! Batched Parquet writer for telemetry data.
//!
//! Provides buffered writes with automatic flushing and crash safety.

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use arrow::array::RecordBatch;
use arrow::datatypes::Schema;
use parquet::arrow::ArrowWriter;
use parquet::basic::{Compression, Encoding, ZstdLevel};
use parquet::file::properties::{WriterProperties, WriterVersion};
use thiserror::Error;

use crate::schema::TableName;

static OUTPUT_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Errors from telemetry writer operations.
#[derive(Error, Debug)]
pub enum WriteError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Parquet error: {0}")]
    Parquet(#[from] parquet::errors::ParquetError),

    #[error("Arrow error: {0}")]
    Arrow(#[from] arrow::error::ArrowError),

    #[error("Invalid path: {0}")]
    InvalidPath(String),

    #[error("Writer not initialized")]
    NotInitialized,

    #[error("Buffer empty")]
    EmptyBuffer,
}

/// Configuration for the batched writer.
#[derive(Debug, Clone)]
pub struct WriterConfig {
    /// Directory for telemetry files.
    pub base_dir: PathBuf,

    /// Compression codec.
    pub compression: Compression,

    /// Row group size in bytes.
    pub row_group_size: usize,

    /// Maximum rows to buffer before flushing.
    pub batch_size: usize,

    /// Session ID for file naming.
    pub session_id: String,

    /// Host ID for partitioning.
    pub host_id: String,
}

impl WriterConfig {
    /// Create config with defaults.
    pub fn new(base_dir: PathBuf, session_id: String, host_id: String) -> Self {
        WriterConfig {
            base_dir,
            compression: Compression::ZSTD(ZstdLevel::try_new(3).expect("valid zstd level")),
            row_group_size: 512 * 1024, // 512KB default
            batch_size: crate::DEFAULT_BATCH_SIZE,
            session_id,
            host_id,
        }
    }

    /// Use snappy compression instead of zstd.
    pub fn with_snappy(mut self) -> Self {
        self.compression = Compression::SNAPPY;
        self
    }

    /// Set custom batch size.
    pub fn with_batch_size(mut self, size: usize) -> Self {
        self.batch_size = size;
        self
    }

    /// Set custom row group size.
    pub fn with_row_group_size(mut self, size: usize) -> Self {
        self.row_group_size = size;
        self
    }
}

/// Batched writer for a single telemetry table.
pub struct BatchedWriter {
    table: TableName,
    schema: Arc<Schema>,
    config: WriterConfig,
    buffer: Vec<RecordBatch>,
    rows_buffered: usize,
    output_path: Option<PathBuf>,
    temp_path: Option<PathBuf>,
    writer: Option<ArrowWriter<File>>,
}

impl BatchedWriter {
    /// Create a new batched writer for a table.
    pub fn new(table: TableName, schema: Arc<Schema>, config: WriterConfig) -> Self {
        BatchedWriter {
            table,
            schema,
            config,
            buffer: Vec::new(),
            rows_buffered: 0,
            output_path: None,
            temp_path: None,
            writer: None,
        }
    }

    /// Write a record batch to the buffer.
    ///
    /// If the buffer exceeds the batch size, it will be flushed to disk.
    pub fn write(&mut self, batch: RecordBatch) -> Result<(), WriteError> {
        let num_rows = batch.num_rows();
        self.buffer.push(batch);
        self.rows_buffered += num_rows;

        if self.rows_buffered >= self.config.batch_size {
            self.flush()?;
        }

        Ok(())
    }

    /// Flush buffered data to disk.
    pub fn flush(&mut self) -> Result<(), WriteError> {
        if self.buffer.is_empty() {
            return Ok(());
        }

        // Ensure writer is initialized
        if self.writer.is_none() {
            self.init_writer()?;
        }

        let writer = self.writer.as_mut().ok_or(WriteError::NotInitialized)?;
        let mut written_batches = 0usize;
        let mut written_rows = 0usize;

        // Write buffered batches, but keep the current and remaining batches in memory
        // if a later write fails so callers can decide how to recover.
        for batch in &self.buffer {
            if let Err(err) = writer.write(batch) {
                self.buffer.drain(..written_batches);
                self.rows_buffered = self.rows_buffered.saturating_sub(written_rows);
                return Err(err.into());
            }
            written_batches += 1;
            written_rows += batch.num_rows();
        }

        self.buffer.clear();
        self.rows_buffered = 0;
        Ok(())
    }

    /// Close the writer and finalize the file.
    pub fn close(mut self) -> Result<PathBuf, WriteError> {
        if self.writer.is_none() && self.buffer.is_empty() {
            return Err(WriteError::EmptyBuffer);
        }
        // Flush any remaining data
        self.flush()?;

        // Close the writer
        if let Some(writer) = self.writer.take() {
            writer.close()?;
        }

        // Atomic rename from temp to final path
        let temp_path = self.temp_path.take().ok_or(WriteError::NotInitialized)?;
        let output_path = self.output_path.take().ok_or(WriteError::NotInitialized)?;
        atomic_rename(&temp_path, &output_path)?;

        Ok(output_path)
    }

    /// Get the current output path (if writer is initialized).
    pub fn output_path(&self) -> Option<&Path> {
        self.output_path.as_deref()
    }

    /// Initialize the Parquet writer.
    fn init_writer(&mut self) -> Result<(), WriteError> {
        let output_path = self.build_output_path()?;

        // Create parent directories
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Create temp file for atomic write
        let temp_path = output_path.with_extension("parquet.tmp");
        let file = File::create(&temp_path)?;

        // Configure writer properties
        let props = WriterProperties::builder()
            .set_writer_version(WriterVersion::PARQUET_2_0)
            .set_compression(self.config.compression)
            .set_max_row_group_size(self.config.row_group_size)
            // Dictionary encoding for string columns
            .set_dictionary_enabled(true)
            // Use plain encoding for numeric columns
            .set_encoding(Encoding::PLAIN)
            .build();

        let writer = ArrowWriter::try_new(file, self.schema.clone(), Some(props))?;

        self.writer = Some(writer);
        self.temp_path = Some(temp_path);
        self.output_path = Some(output_path);

        Ok(())
    }

    /// Build the output path with partitioning.
    fn build_output_path(&self) -> Result<PathBuf, WriteError> {
        let now = chrono::Utc::now();
        let host_partition = sanitize_path_component(&self.config.host_id, "unknown");

        // Partitioning: year=YYYY/month=MM/day=DD/host_id=<hash>/
        let partition_path = self
            .config
            .base_dir
            .join(self.table.as_str())
            .join(format!("year={}", now.format("%Y")))
            .join(format!("month={}", now.format("%m")))
            .join(format!("day={}", now.format("%d")))
            .join(format!("host_id={host_partition}"));

        // File name: <table>_<timestamp>_<pid>_<nonce>_<session_suffix>.parquet
        let session_suffix = sanitize_path_component(
            self.config
                .session_id
                .split('-')
                .next_back()
                .unwrap_or("xxxx"),
            "xxxx",
        );
        let timestamp = now.format("%Y%m%dT%H%M%S%.6fZ");
        let process_id = std::process::id();
        let counter = OUTPUT_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);

        let filename = format!(
            "{}_{}_{}_{}_{}.parquet",
            self.table.as_str(),
            timestamp,
            process_id,
            counter,
            session_suffix,
        );

        Ok(partition_path.join(filename))
    }
}

fn sanitize_path_component(value: &str, fallback: &str) -> String {
    let sanitized: String = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect();

    if sanitized.is_empty() {
        fallback.to_string()
    } else {
        sanitized
    }
}

impl Drop for BatchedWriter {
    fn drop(&mut self) {
        // Best-effort flush, close, and rename on drop
        let mut finalize_ok = true;
        if !self.buffer.is_empty() {
            if self.flush().is_err() {
                finalize_ok = false;
            }
        }

        if let Some(writer) = self.writer.take() {
            if writer.close().is_err() {
                finalize_ok = false;
            }
        }

        match (self.temp_path.take(), self.output_path.take()) {
            (Some(temp_path), Some(output_path)) if finalize_ok => {
                let _ = atomic_rename(&temp_path, &output_path);
            }
            (Some(temp_path), _) => {
                let _ = fs::remove_file(temp_path);
            }
            _ => {}
        }
    }
}

/// Helper to rename temp file to final path atomically.
pub fn atomic_rename(temp_path: &Path, final_path: &Path) -> Result<(), WriteError> {
    fs::rename(temp_path, final_path)?;
    Ok(())
}

/// Get the telemetry base directory from XDG data dir.
pub fn default_telemetry_dir() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("process_triage")
        .join("telemetry")
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow::array::{Int32Array, StringArray, TimestampMicrosecondArray};
    use arrow::datatypes::{DataType, Field};
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    fn create_test_batch(schema: &Schema) -> RecordBatch {
        // Create a minimal audit batch for testing
        let audit_ts = TimestampMicrosecondArray::from(vec![chrono::Utc::now().timestamp_micros()])
            .with_timezone("UTC");
        let session_id = StringArray::from(vec!["pt-20260115-143022-test"]);
        let event_type = StringArray::from(vec!["test_event"]);
        let severity = StringArray::from(vec!["info"]);
        let actor = StringArray::from(vec!["system"]);
        let target_pid: Int32Array = Int32Array::from(vec![None::<i32>]);
        let target_start_id: StringArray = StringArray::from(vec![None::<&str>]);
        let message = StringArray::from(vec!["Test message"]);
        let details_json: StringArray = StringArray::from(vec![None::<&str>]);
        let host_id = StringArray::from(vec!["test-host"]);

        RecordBatch::try_new(
            Arc::new(schema.clone()),
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
        .unwrap()
    }

    fn create_incompatible_batch() -> RecordBatch {
        let schema = Schema::new(vec![Field::new("wrong", DataType::Utf8, false)]);
        RecordBatch::try_new(
            Arc::new(schema),
            vec![Arc::new(StringArray::from(vec!["bad-row"]))],
        )
        .unwrap()
    }

    fn collect_paths_with_extension(root: &Path, ext: &str, out: &mut Vec<PathBuf>) {
        let entries = fs::read_dir(root).unwrap();
        for entry in entries {
            let path = entry.unwrap().path();
            if path.is_dir() {
                collect_paths_with_extension(&path, ext, out);
            } else if path.extension().and_then(|value| value.to_str()) == Some(ext) {
                out.push(path);
            }
        }
    }

    #[test]
    fn test_writer_config_defaults() {
        let config = WriterConfig::new(
            PathBuf::from("/tmp/test"),
            "pt-test".to_string(),
            "host123".to_string(),
        );
        assert_eq!(config.batch_size, crate::DEFAULT_BATCH_SIZE);
        assert!(matches!(config.compression, Compression::ZSTD(_)));
    }

    #[test]
    fn test_writer_config_snappy() {
        let config = WriterConfig::new(
            PathBuf::from("/tmp/test"),
            "pt-test".to_string(),
            "host123".to_string(),
        )
        .with_snappy();
        assert!(matches!(config.compression, Compression::SNAPPY));
    }

    #[test]
    fn test_batched_writer_write_and_close() {
        let temp_dir = TempDir::new().unwrap();
        let schema = Arc::new(crate::schema::audit_schema());
        let config = WriterConfig::new(
            temp_dir.path().to_path_buf(),
            "pt-20260115-143022-test".to_string(),
            "test-host".to_string(),
        )
        .with_batch_size(1); // Flush after every row

        let mut writer = BatchedWriter::new(TableName::Audit, schema.clone(), config);

        // Write a batch
        let batch = create_test_batch(&schema);
        writer.write(batch).unwrap();

        // Close and get output path
        let output_path = writer.close().unwrap();
        assert!(output_path.exists());
        assert!(output_path.to_string_lossy().contains("audit"));
        assert!(output_path.to_string_lossy().ends_with(".parquet"));
    }

    #[test]
    fn test_close_without_writes_returns_empty_buffer() {
        let temp_dir = TempDir::new().unwrap();
        let schema = Arc::new(crate::schema::audit_schema());
        let config = WriterConfig::new(
            temp_dir.path().to_path_buf(),
            "pt-20260115-143022-test".to_string(),
            "test-host".to_string(),
        );
        let writer = BatchedWriter::new(TableName::Audit, schema, config);
        let err = writer.close().unwrap_err();
        match err {
            WriteError::EmptyBuffer => {}
            _ => panic!("unexpected error"),
        }
    }

    #[test]
    fn test_build_output_path() {
        let temp_dir = TempDir::new().unwrap();
        let schema = Arc::new(crate::schema::audit_schema());
        let config = WriterConfig::new(
            temp_dir.path().to_path_buf(),
            "pt-20260115-143022-a7xq".to_string(),
            "abc123".to_string(),
        );

        let writer = BatchedWriter::new(TableName::Audit, schema, config);
        let path = writer.build_output_path().unwrap();

        // Check partitioning structure
        let path_str = path.to_string_lossy();
        assert!(path_str.contains("audit/year="));
        assert!(path_str.contains("/month="));
        assert!(path_str.contains("/day="));
        assert!(path_str.contains("/host_id=abc123/"));
        assert!(path_str.contains("/audit_"));
        assert!(path_str.ends_with("_a7xq.parquet"));
    }

    #[test]
    fn test_multiple_writers_same_session_do_not_collide() {
        let temp_dir = TempDir::new().unwrap();
        let schema = Arc::new(crate::schema::audit_schema());
        let config = WriterConfig::new(
            temp_dir.path().to_path_buf(),
            "pt-20260115-143022-a7xq".to_string(),
            "abc123".to_string(),
        )
        .with_batch_size(1);

        let mut first = BatchedWriter::new(TableName::Audit, schema.clone(), config.clone());
        first.write(create_test_batch(&schema)).unwrap();
        let first_path = first.close().unwrap();

        let second_batch = create_test_batch(&schema);
        let mut second = BatchedWriter::new(TableName::Audit, schema, config);
        second.write(second_batch).unwrap();
        let second_path = second.close().unwrap();

        assert_ne!(first_path, second_path, "writer outputs should be unique");
        assert!(first_path.exists());
        assert!(second_path.exists());
    }

    #[test]
    fn test_flush_failure_keeps_unwritten_batches_buffered() {
        let temp_dir = TempDir::new().unwrap();
        let schema = Arc::new(crate::schema::audit_schema());
        let config = WriterConfig::new(
            temp_dir.path().to_path_buf(),
            "pt-20260115-143022-fail".to_string(),
            "abc123".to_string(),
        )
        .with_batch_size(10);

        let mut writer = BatchedWriter::new(TableName::Audit, schema.clone(), config);
        writer.write(create_test_batch(&schema)).unwrap();
        writer.write(create_incompatible_batch()).unwrap();

        assert!(writer.flush().is_err(), "expected mismatched batch to fail");
        assert_eq!(
            writer.buffer.len(),
            1,
            "failed batch should remain buffered"
        );
        assert_eq!(
            writer.rows_buffered, 1,
            "row count should track unwritten batch"
        );

        writer.buffer.clear();
        writer.rows_buffered = 0;
        let path = writer.close().unwrap();

        let file = File::open(path).unwrap();
        let builder = ParquetRecordBatchReaderBuilder::try_new(file).unwrap();
        let reader = builder.build().unwrap();
        let batches = reader.collect::<Result<Vec<_>, _>>().unwrap();
        let total_rows: usize = batches.iter().map(|batch| batch.num_rows()).sum();
        assert_eq!(total_rows, 1, "successful rows should remain persisted");
    }

    #[test]
    fn test_drop_after_flush_failure_does_not_publish_partial_file() {
        let temp_dir = TempDir::new().unwrap();
        let schema = Arc::new(crate::schema::audit_schema());
        let config = WriterConfig::new(
            temp_dir.path().to_path_buf(),
            "pt-20260115-143022-drop".to_string(),
            "abc123".to_string(),
        )
        .with_batch_size(10);

        let mut writer = BatchedWriter::new(TableName::Audit, schema, config);
        writer.write(create_incompatible_batch()).unwrap();
        drop(writer);

        let mut parquet_files = Vec::new();
        collect_paths_with_extension(temp_dir.path(), "parquet", &mut parquet_files);
        assert!(
            parquet_files.is_empty(),
            "drop should not publish a final parquet file after flush failure",
        );
    }

    #[test]
    fn test_build_output_path_sanitizes_untrusted_components() {
        let temp_dir = TempDir::new().unwrap();
        let schema = Arc::new(crate::schema::audit_schema());
        let config = WriterConfig::new(
            temp_dir.path().to_path_buf(),
            "pt-20260115-143022-../a b".to_string(),
            "../host/root".to_string(),
        );

        let writer = BatchedWriter::new(TableName::Audit, schema, config);
        let path = writer.build_output_path().unwrap();
        let path_str = path.to_string_lossy();

        assert!(path_str.contains("/host_id=___host_root/"));
        assert!(path_str.ends_with("___a_b.parquet"));
        assert!(!path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir)));
    }

    #[test]
    fn test_default_telemetry_dir() {
        let dir = default_telemetry_dir();
        assert!(dir.to_string_lossy().contains("process_triage"));
        assert!(dir.to_string_lossy().contains("telemetry"));
    }
}
