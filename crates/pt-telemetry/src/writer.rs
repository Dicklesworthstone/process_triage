//! Batched Parquet writer for telemetry data.
//!
//! Provides buffered writes with automatic flushing and crash safety.

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arrow::array::RecordBatch;
use arrow::datatypes::Schema;
use parquet::arrow::ArrowWriter;
use parquet::basic::{Compression, Encoding, ZstdLevel};
use parquet::file::properties::{WriterProperties, WriterVersion};
use thiserror::Error;

use crate::schema::TableName;

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

        // Write all buffered batches
        for batch in self.buffer.drain(..) {
            writer.write(&batch)?;
        }

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

        // Partitioning: year=YYYY/month=MM/day=DD/host_id=<hash>/
        let partition_path = self.config.base_dir
            .join(self.table.as_str())
            .join(format!("year={}", now.format("%Y")))
            .join(format!("month={}", now.format("%m")))
            .join(format!("day={}", now.format("%d")))
            .join(format!("host_id={}", &self.config.host_id));

        // File name: <table>_<timestamp>_<session_suffix>.parquet
        let session_suffix = self.config.session_id
            .split('-')
            .last()
            .unwrap_or("xxxx");

        let filename = format!(
            "{}_{}.parquet",
            self.table.as_str(),
            session_suffix,
        );

        Ok(partition_path.join(filename))
    }
}

impl Drop for BatchedWriter {
    fn drop(&mut self) {
        // Best-effort flush on drop
        if !self.buffer.is_empty() {
            let _ = self.flush();
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
    use tempfile::TempDir;

    fn create_test_batch(schema: &Schema) -> RecordBatch {
        // Create a minimal audit batch for testing
        let audit_ts = TimestampMicrosecondArray::from(vec![
            chrono::Utc::now().timestamp_micros(),
        ]).with_timezone("UTC");
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
        ).unwrap()
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
        ).with_snappy();
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
        ).with_batch_size(1); // Flush after every row

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
        assert!(path_str.ends_with("audit_a7xq.parquet"));
    }

    #[test]
    fn test_default_telemetry_dir() {
        let dir = default_telemetry_dir();
        assert!(dir.to_string_lossy().contains("process_triage"));
        assert!(dir.to_string_lossy().contains("telemetry"));
    }
}
