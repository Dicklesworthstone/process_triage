//! Bounded queries and streaming exports of the existing Parquet telemetry lake.
//!
//! Event timestamps, rather than file modification times, define a query range.
//! Readers never create storage or consume unfinished writer files.

use std::cmp::{Ordering, Reverse};
use std::collections::BinaryHeap;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use arrow::array::{Array, BooleanArray, StringArray, TimestampMicrosecondArray};
use arrow::compute::filter_record_batch;
use arrow::json::writer::{JsonArray, LineDelimited, WriterBuilder};
use arrow::record_batch::RecordBatch;
use chrono::{DateTime, Utc};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::arrow::ArrowWriter;
use serde::Serialize;
use serde_json::Value;
use thiserror::Error;

use crate::schema::{TableName, TelemetrySchema};

pub(crate) const READ_BATCH_SIZE: usize = 1024;
pub const MAX_QUERY_ROWS: usize = 10_000;

#[derive(Debug, Error)]
pub enum QueryError {
    #[error("invalid telemetry query: {0}")]
    Invalid(String),
    #[error("unsafe telemetry path: {0}")]
    UnsafePath(PathBuf),
    #[error("telemetry schema does not match table {table}: {path}")]
    Schema { table: String, path: PathBuf },
    #[error("telemetry I/O: {0}")]
    Io(#[from] io::Error),
    #[error("telemetry Parquet: {0}")]
    Parquet(#[from] parquet::errors::ParquetError),
    #[error("telemetry Arrow: {0}")]
    Arrow(#[from] arrow::error::ArrowError),
    #[error("telemetry JSON: {0}")]
    Json(#[from] serde_json::Error),
}

/// Filters shared by queries and exports. Bounds are inclusive and in UTC.
#[derive(Debug, Clone)]
pub struct QueryOptions {
    pub table: TableName,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    pub session_id: Option<String>,
}

impl QueryOptions {
    pub fn new(table: TableName) -> Self {
        Self {
            table,
            since: None,
            until: None,
            session_id: None,
        }
    }

    fn validate(&self) -> Result<(), QueryError> {
        if matches!((self.since, self.until), (Some(start), Some(end)) if start > end) {
            return Err(QueryError::Invalid("range start is after its end".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct ReadSummary {
    pub files_read: usize,
    pub rows_scanned: u64,
    pub rows_matched: u64,
}

#[derive(Debug, Serialize)]
pub struct QueryResult {
    pub summary: ReadSummary,
    pub rows: Vec<Value>,
    pub truncated: bool,
}

struct RankedRow {
    timestamp: i64,
    sequence: u64,
    value: Value,
}

impl PartialEq for RankedRow {
    fn eq(&self, other: &Self) -> bool {
        (self.timestamp, self.sequence) == (other.timestamp, other.sequence)
    }
}

impl Eq for RankedRow {}

impl PartialOrd for RankedRow {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RankedRow {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.timestamp, self.sequence).cmp(&(other.timestamp, other.sequence))
    }
}

/// Return the newest matching rows across every partition, retaining at most
/// the requested limit plus one read batch in memory. All files are checked,
/// so a limit cannot hide corrupt later partitions.
pub fn query_rows(
    root: &Path,
    options: &QueryOptions,
    limit: usize,
) -> Result<QueryResult, QueryError> {
    if !(1..=MAX_QUERY_ROWS).contains(&limit) {
        return Err(QueryError::Invalid(format!(
            "limit must be between 1 and {MAX_QUERY_ROWS}"
        )));
    }
    let mut newest = BinaryHeap::<Reverse<RankedRow>>::with_capacity(limit);
    let mut sequence = 0;
    let summary = scan_batches(root, options, |batch| {
        let times = timestamps(batch, options.table)?;
        let mut writer = WriterBuilder::new()
            .with_explicit_nulls(true)
            .build::<_, JsonArray>(Vec::new());
        writer.write(batch)?;
        writer.finish()?;
        let rows: Vec<Value> = serde_json::from_slice(&writer.into_inner())?;
        for (index, value) in rows.into_iter().enumerate() {
            let row = RankedRow {
                timestamp: times.value(index),
                sequence,
                value,
            };
            sequence += 1;
            if newest.len() < limit {
                newest.push(Reverse(row));
            } else if newest.peek().is_some_and(|oldest| row > oldest.0) {
                newest.pop();
                newest.push(Reverse(row));
            }
        }
        Ok(())
    })?;
    let truncated = summary.rows_matched > limit as u64;
    let rows = newest
        .into_sorted_vec()
        .into_iter()
        .map(|row| row.0.value)
        .collect();
    Ok(QueryResult {
        summary,
        rows,
        truncated,
    })
}

#[derive(Debug, Clone, Copy)]
pub enum ExportFormat {
    Parquet,
    Csv,
    Json,
    Jsonl,
}

impl std::str::FromStr for ExportFormat {
    type Err = QueryError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "parquet" => Ok(Self::Parquet),
            "csv" => Ok(Self::Csv),
            "json" => Ok(Self::Json),
            "jsonl" => Ok(Self::Jsonl),
            _ => Err(QueryError::Invalid(format!(
                "unknown export format: {value}"
            ))),
        }
    }
}

/// Stream one table to a private file and publish it only after every input and
/// output batch succeeds. Existing output paths are never replaced. Exports
/// must be outside the input lake to avoid ingesting them as duplicate telemetry.
pub fn export_table(
    root: &Path,
    options: &QueryOptions,
    output: &Path,
    format: ExportFormat,
) -> Result<ReadSummary, QueryError> {
    options.validate()?;
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = parent.canonicalize()?;
    let output = parent.join(
        output
            .file_name()
            .ok_or_else(|| QueryError::Invalid("export destination must name a file".into()))?,
    );
    let root_location = match root.canonicalize() {
        Ok(location) => Some(location),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            // A missing lake is a valid empty input, but an export must not
            // create a regular file where that lake directory would belong.
            let root_parent = root
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            match root_parent.canonicalize() {
                Ok(parent) => root.file_name().map(|name| parent.join(name)),
                Err(err) if err.kind() == io::ErrorKind::NotFound => None,
                Err(err) => return Err(err.into()),
            }
        }
        Err(err) => return Err(err.into()),
    };
    if root_location.is_some_and(|root| output.starts_with(root)) {
        return Err(QueryError::Invalid(
            "export destination must be outside the telemetry directory".into(),
        ));
    }
    match fs::symlink_metadata(&output) {
        Ok(_) => return Err(io::Error::from(io::ErrorKind::AlreadyExists).into()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }

    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    let schema = TelemetrySchema::new().get(options.table);
    let summary = match format {
        ExportFormat::Parquet => {
            let mut writer = ArrowWriter::try_new(temporary.as_file_mut(), schema, None)?;
            let summary = scan_batches(root, options, |batch| {
                writer.write(batch)?;
                Ok(())
            })?;
            writer.close()?;
            summary
        }
        ExportFormat::Csv => {
            let mut writer = arrow::csv::Writer::new(temporary.as_file_mut());
            // Empty tables still export a usable header.
            writer.write(&RecordBatch::new_empty(schema))?;
            scan_batches(root, options, |batch| {
                writer.write(batch)?;
                Ok(())
            })?
        }
        ExportFormat::Json => {
            let mut writer = WriterBuilder::new()
                .with_explicit_nulls(true)
                .build::<_, JsonArray>(temporary.as_file_mut());
            let summary = scan_batches(root, options, |batch| {
                writer.write(batch)?;
                Ok(())
            })?;
            writer.finish()?;
            summary
        }
        ExportFormat::Jsonl => {
            let mut writer = WriterBuilder::new()
                .with_explicit_nulls(true)
                .build::<_, LineDelimited>(temporary.as_file_mut());
            let summary = scan_batches(root, options, |batch| {
                writer.write(batch)?;
                Ok(())
            })?;
            writer.finish()?;
            summary
        }
    };
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(output)
        .map_err(|err| QueryError::Io(err.error))?;
    Ok(summary)
}

fn scan_batches(
    root: &Path,
    options: &QueryOptions,
    mut visit: impl FnMut(&RecordBatch) -> Result<(), QueryError>,
) -> Result<ReadSummary, QueryError> {
    options.validate()?;
    let mut matched = 0;
    let mut summary = scan_table_batches(root, options.table, |batch| {
        let times = timestamps(batch, options.table)?;
        let sessions = batch
            .column_by_name("session_id")
            .and_then(|array| array.as_any().downcast_ref::<StringArray>())
            .ok_or_else(|| QueryError::Invalid("session_id must be UTF-8".into()))?;
        let selected = BooleanArray::from(
            (0..batch.num_rows())
                .map(|index| {
                    !times.is_null(index)
                        && options
                            .since
                            .is_none_or(|time| times.value(index) >= time.timestamp_micros())
                        && options
                            .until
                            .is_none_or(|time| times.value(index) <= time.timestamp_micros())
                        && options.session_id.as_ref().is_none_or(|session| {
                            !sessions.is_null(index) && sessions.value(index) == session
                        })
                })
                .collect::<Vec<_>>(),
        );
        let batch = filter_record_batch(batch, &selected)?;
        matched += batch.num_rows() as u64;
        if batch.num_rows() > 0 {
            visit(&batch)?;
        }
        Ok(())
    })?;
    summary.rows_matched = matched;
    Ok(summary)
}

/// Shared schema-checked traversal for queries and complete sanitized copies.
/// Empty Parquet files are validated before iteration; unfinished files are not
/// read. Row filtering belongs to the caller, so a copy cannot silently discard
/// observations merely because their event timestamp is absent.
pub(crate) fn scan_table_batches(
    root: &Path,
    table: TableName,
    mut visit: impl FnMut(&RecordBatch) -> Result<(), QueryError>,
) -> Result<ReadSummary, QueryError> {
    let mut files = Vec::new();
    match fs::symlink_metadata(root) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => return Err(QueryError::UnsafePath(root.to_path_buf())),
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(ReadSummary::default()),
        Err(err) => return Err(err.into()),
    }
    collect_files(&root.join(table.as_str()), 0, &mut files)?;
    files.sort();
    let expected = TelemetrySchema::new().get(table);
    let mut summary = ReadSummary::default();
    for path in files {
        let builder = ParquetRecordBatchReaderBuilder::try_new(open_regular_file(&path)?)?;
        if builder.schema().fields() != expected.fields() {
            return Err(QueryError::Schema {
                table: table.to_string(),
                path,
            });
        }
        let reader = builder.with_batch_size(READ_BATCH_SIZE).build()?;
        summary.files_read += 1;
        for batch in reader {
            let batch = batch?;
            summary.rows_scanned += batch.num_rows() as u64;
            summary.rows_matched += batch.num_rows() as u64;
            visit(&batch)?;
        }
    }
    Ok(summary)
}

fn timestamps(
    batch: &RecordBatch,
    table: TableName,
) -> Result<&TimestampMicrosecondArray, QueryError> {
    batch
        .column_by_name(table.timestamp_column())
        .and_then(|array| array.as_any().downcast_ref::<TimestampMicrosecondArray>())
        .ok_or_else(|| {
            QueryError::Invalid(format!(
                "{} must be a microsecond timestamp",
                table.timestamp_column()
            ))
        })
}

fn collect_files(
    directory: &Path,
    depth: usize,
    files: &mut Vec<PathBuf>,
) -> Result<(), QueryError> {
    if depth > 16 {
        return Err(QueryError::Invalid(
            "telemetry partition nesting exceeds 16 levels".into(),
        ));
    }
    match fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => return Err(QueryError::UnsafePath(directory.to_path_buf())),
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err.into()),
    }
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        let path = entry.path();
        if kind.is_symlink() {
            return Err(QueryError::UnsafePath(path));
        }
        if kind.is_dir() {
            collect_files(&path, depth + 1, files)?;
        } else if path
            .extension()
            .is_some_and(|extension| extension == "parquet")
        {
            if !kind.is_file() {
                return Err(QueryError::UnsafePath(path));
            }
            files.push(path);
        }
    }
    Ok(())
}

fn open_regular_file(path: &Path) -> Result<File, QueryError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(QueryError::UnsafePath(path.to_path_buf()));
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow::array::Int32Array;
    use std::sync::Arc;

    use crate::writer::{BatchedWriter, WriterConfig};

    fn write_rows(root: &Path, rows: &[(i64, &str, &str)]) -> PathBuf {
        let schema = TelemetrySchema::new().audit;
        let count = rows.len();
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(
                    TimestampMicrosecondArray::from(
                        rows.iter().map(|row| row.0).collect::<Vec<_>>(),
                    )
                    .with_timezone("UTC"),
                ),
                Arc::new(StringArray::from(
                    rows.iter().map(|row| row.1).collect::<Vec<_>>(),
                )),
                Arc::new(StringArray::from(vec!["state_change"; count])),
                Arc::new(StringArray::from(vec!["info"; count])),
                Arc::new(StringArray::from(vec!["test"; count])),
                Arc::new(Int32Array::from(vec![None; count])),
                Arc::new(StringArray::from(vec![None::<&str>; count])),
                Arc::new(StringArray::from(
                    rows.iter().map(|row| row.2).collect::<Vec<_>>(),
                )),
                Arc::new(StringArray::from(vec![None::<&str>; count])),
                Arc::new(StringArray::from(vec!["host"; count])),
            ],
        )
        .unwrap();
        let mut writer = BatchedWriter::new(
            TableName::Audit,
            schema,
            WriterConfig::new(root.to_path_buf(), "session".into(), "host".into()),
        );
        writer.write(batch).unwrap();
        writer.close().unwrap()
    }

    #[test]
    fn query_filters_event_time_and_retains_newest_across_partitions() {
        let temp = tempfile::tempdir().unwrap();
        write_rows(temp.path(), &[(10, "a", "old"), (30, "a", "newer")]);
        write_rows(temp.path(), &[(20, "b", "middle"), (40, "b", "newest")]);
        fs::write(
            temp.path().join("audit/incomplete.parquet.tmp"),
            b"unfinished",
        )
        .unwrap();
        let mut options = QueryOptions::new(TableName::Audit);
        let result = query_rows(temp.path(), &options, 2).unwrap();
        assert_eq!(result.summary.files_read, 2);
        assert_eq!(result.summary.rows_scanned, 4);
        assert_eq!(result.summary.rows_matched, 4);
        assert!(result.truncated);
        assert_eq!(result.rows[0]["message"], "newest");
        assert_eq!(result.rows[1]["message"], "newer");
        assert!(result.rows[0]["target_pid"].is_null());

        options.since = DateTime::from_timestamp_micros(15);
        options.until = DateTime::from_timestamp_micros(35);
        let result = query_rows(temp.path(), &options, 10).unwrap();
        assert_eq!(result.rows.len(), 2);
        assert_eq!(result.rows[0]["message"], "newer");
        assert_eq!(result.rows[1]["message"], "middle");
        assert!(!result.truncated);
        options.session_id = Some("a".into());
        let result = query_rows(temp.path(), &options, 10).unwrap();
        assert_eq!(result.rows.len(), 1);
        assert_eq!(result.rows[0]["message"], "newer");
    }

    #[test]
    fn query_bounds_rows_across_multiple_read_batches() {
        let temp = tempfile::tempdir().unwrap();
        let rows: Vec<_> = (0..2500).map(|time| (time, "a", "event")).collect();
        write_rows(temp.path(), &rows);
        let result = query_rows(temp.path(), &QueryOptions::new(TableName::Audit), 7).unwrap();
        assert_eq!(result.summary.rows_matched, 2500);
        assert_eq!(result.rows.len(), 7);
        assert!(result.truncated);
        let timestamps: Vec<_> = result
            .rows
            .iter()
            .map(|row| {
                DateTime::parse_from_rfc3339(row["audit_ts"].as_str().unwrap())
                    .unwrap()
                    .timestamp_micros()
            })
            .collect();
        assert_eq!(timestamps, (2493..2500).rev().collect::<Vec<_>>());
    }

    #[test]
    fn export_roundtrips_parquet_json_jsonl_and_csv() {
        let temp = tempfile::tempdir().unwrap();
        let lake = temp.path().join("lake");
        let message = "a comma, a \"quote\"\nand a newline";
        write_rows(&lake, &[(10, "keep", message), (20, "omit", "excluded")]);
        let mut options = QueryOptions::new(TableName::Audit);
        options.session_id = Some("keep".into());

        for (format, name) in [
            (ExportFormat::Parquet, "export.parquet"),
            (ExportFormat::Json, "export.json"),
            (ExportFormat::Jsonl, "export.jsonl"),
            (ExportFormat::Csv, "export.csv"),
        ] {
            let output = temp.path().join(name);
            let summary = export_table(&lake, &options, &output, format).unwrap();
            assert_eq!(summary.rows_scanned, 2);
            assert_eq!(summary.rows_matched, 1);
            match format {
                ExportFormat::Parquet => {
                    let mut reader =
                        ParquetRecordBatchReaderBuilder::try_new(File::open(&output).unwrap())
                            .unwrap()
                            .build()
                            .unwrap();
                    let batch = reader.next().unwrap().unwrap();
                    assert_eq!(batch.num_rows(), 1);
                    let messages = batch
                        .column_by_name("message")
                        .unwrap()
                        .as_any()
                        .downcast_ref::<StringArray>()
                        .unwrap();
                    assert_eq!(messages.value(0), message);
                    assert!(reader.next().is_none());
                }
                ExportFormat::Json => {
                    let rows: Vec<Value> =
                        serde_json::from_reader(File::open(&output).unwrap()).unwrap();
                    assert_eq!(rows.len(), 1);
                    assert_eq!(rows[0]["message"], message);
                    assert!(rows[0]["target_pid"].is_null());
                }
                ExportFormat::Jsonl => {
                    let text = fs::read_to_string(&output).unwrap();
                    let rows: Vec<Value> = text
                        .lines()
                        .map(|line| serde_json::from_str(line).unwrap())
                        .collect();
                    assert_eq!(rows.len(), 1);
                    assert_eq!(rows[0]["message"], message);
                }
                ExportFormat::Csv => {
                    let mut reader = arrow::csv::ReaderBuilder::new(TelemetrySchema::new().audit)
                        .with_header(true)
                        .build(File::open(&output).unwrap())
                        .unwrap();
                    let batch = reader.next().unwrap().unwrap();
                    assert_eq!(batch.num_rows(), 1);
                    let messages = batch
                        .column_by_name("message")
                        .unwrap()
                        .as_any()
                        .downcast_ref::<StringArray>()
                        .unwrap();
                    assert_eq!(messages.value(0), message);
                    assert!(reader.next().is_none());
                }
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    fs::metadata(output).unwrap().permissions().mode() & 0o077,
                    0
                );
            }
        }
    }

    #[test]
    fn empty_lake_has_valid_exports_without_creating_storage() {
        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("missing");
        let options = QueryOptions::new(TableName::Audit);
        let result = query_rows(&missing, &options, 10).unwrap();
        assert!(result.rows.is_empty());
        assert!(matches!(
            export_table(&missing, &options, &missing, ExportFormat::Json),
            Err(QueryError::Invalid(_))
        ));
        assert!(!missing.exists());
        for (format, name) in [
            (ExportFormat::Parquet, "empty.parquet"),
            (ExportFormat::Json, "empty.json"),
            (ExportFormat::Jsonl, "empty.jsonl"),
            (ExportFormat::Csv, "empty.csv"),
        ] {
            let output = temp.path().join(name);
            assert_eq!(
                export_table(&missing, &options, &output, format)
                    .unwrap()
                    .rows_matched,
                0
            );
            match format {
                ExportFormat::Parquet => {
                    let reader =
                        ParquetRecordBatchReaderBuilder::try_new(File::open(output).unwrap())
                            .unwrap()
                            .build()
                            .unwrap();
                    assert_eq!(reader.count(), 0);
                }
                ExportFormat::Json => assert_eq!(fs::read_to_string(output).unwrap(), "[]"),
                ExportFormat::Jsonl => assert!(fs::read_to_string(output).unwrap().is_empty()),
                ExportFormat::Csv => {
                    let text = fs::read_to_string(output).unwrap();
                    assert_eq!(text.lines().count(), 1);
                    assert!(text.starts_with("audit_ts,session_id,"));
                }
            }
        }
        assert!(!missing.exists());
    }

    #[test]
    fn corrupt_partitions_never_publish_partial_exports_or_hide_behind_limits() {
        let temp = tempfile::tempdir().unwrap();
        let lake = temp.path().join("lake");
        write_rows(&lake, &[(10, "a", "valid")]);
        fs::write(lake.join("audit/zz-corrupt.parquet"), b"not parquet").unwrap();
        let options = QueryOptions::new(TableName::Audit);
        assert!(query_rows(&lake, &options, 1).is_err());
        let output = temp.path().join("export.json");
        assert!(export_table(&lake, &options, &output, ExportFormat::Json).is_err());
        assert!(!output.exists());
        fs::write(&output, b"existing result").unwrap();
        assert!(export_table(&lake, &options, &output, ExportFormat::Json).is_err());
        assert_eq!(fs::read(output).unwrap(), b"existing result");
    }

    #[test]
    fn invalid_options_and_exports_inside_the_lake_are_refused() {
        let temp = tempfile::tempdir().unwrap();
        let lake = temp.path().join("lake");
        write_rows(&lake, &[(10, "a", "event")]);
        let mut options = QueryOptions::new(TableName::Audit);
        assert!(query_rows(&lake, &options, 0).is_err());
        assert!(query_rows(&lake, &options, MAX_QUERY_ROWS + 1).is_err());
        let output = lake.join("copy.parquet");
        assert!(export_table(&lake, &options, &output, ExportFormat::Parquet).is_err());
        assert!(!output.exists());
        options.since = DateTime::from_timestamp_micros(20);
        options.until = DateTime::from_timestamp_micros(10);
        assert!(query_rows(&lake, &options, 1).is_err());
    }

    #[test]
    fn every_table_has_a_readable_event_timestamp() {
        for table in TableName::ALL {
            let schema = TelemetrySchema::new().get(table);
            let batch = RecordBatch::new_empty(schema);
            assert!(timestamps(&batch, table).is_ok(), "{table}");
            assert_eq!(table.as_str().parse::<TableName>().unwrap(), table);
        }
        assert!("../../outside".parse::<TableName>().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_partitions_files_and_fifos_are_refused() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let file = write_rows(&source, &[(10, "a", "private")]);
        let options = QueryOptions::new(TableName::Audit);

        let linked_table = temp.path().join("linked-table");
        fs::create_dir(&linked_table).unwrap();
        symlink(source.join("audit"), linked_table.join("audit")).unwrap();
        assert!(matches!(
            query_rows(&linked_table, &options, 1),
            Err(QueryError::UnsafePath(_))
        ));

        let linked_file = temp.path().join("linked-file");
        fs::create_dir_all(linked_file.join("audit")).unwrap();
        symlink(file, linked_file.join("audit/link.parquet")).unwrap();
        assert!(matches!(
            query_rows(&linked_file, &options, 1),
            Err(QueryError::UnsafePath(_))
        ));

        let fifo_lake = temp.path().join("fifo-lake");
        fs::create_dir_all(fifo_lake.join("audit")).unwrap();
        let fifo = fifo_lake.join("audit/blocked.parquet");
        let name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: name is a NUL-terminated path inside this test's private directory.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(matches!(
            query_rows(&fifo_lake, &options, 1),
            Err(QueryError::UnsafePath(_))
        ));
    }
}
