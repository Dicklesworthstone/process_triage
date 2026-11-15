//! Streaming, out-of-place sanitization of a complete telemetry lake.
//!
//! A copy retains all seven typed tables and their join relationships while sanitizing
//! command lines, paths, messages, and structured JSON with `pt-redact`. The
//! source is read-only; a private staging directory is published atomically
//! only after every input file has passed schema validation.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use arrow::array::{Array, StringArray};
use arrow::datatypes::DataType;
use arrow::record_batch::RecordBatch;
use parquet::arrow::ArrowWriter;
use parquet::file::properties::WriterProperties;
use pt_redact::{Action, ExportProfile, FieldClass, RedactionEngine};
use serde::Serialize;
use serde_json::Value;

use crate::query::{QueryError, READ_BATCH_SIZE, scan_table_batches};
use crate::schema::{TableName, TelemetrySchema};

/// Counts describe published data, never an incomplete staging directory.
#[derive(Debug, Default, Clone, Serialize)]
pub struct RedactionSummary {
    pub files_read: usize,
    pub files_written: usize,
    pub rows_scanned: u64,
    /// Number of non-null string cells changed, including JSON cells.
    pub values_redacted: u64,
    pub tables: Vec<TableRedactionSummary>,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct TableRedactionSummary {
    pub table: String,
    pub files_read: usize,
    pub files_written: usize,
    pub rows_scanned: u64,
    pub values_redacted: u64,
}

/// Write a sanitized Parquet lake to a new directory outside `root`.
///
/// The engine's default profile must be `safe` or `minimal`. Numeric, Boolean,
/// timestamp, and null values retain their Arrow types; join identifiers and
/// existing command hashes receive consistent engine-keyed pseudonyms. Policies that require
/// redacting numeric UID/PID columns are rejected rather than silently ignored
/// or converted to a different schema. Nested JSON uses the engine's structured
/// export rules, including mandatory credential and environment redaction.
///
/// Every table gets one file, including empty tables. Files are read in sorted
/// partition order and rows retain their original order. Both read batches and
/// output row groups are bounded. Existing destinations, symlinks, malformed
/// JSON, incompatible schemas, and unsupported atomic publication fail without
/// publishing the destination or modifying the source.
pub fn redact_telemetry(
    root: &Path,
    output: &Path,
    engine: &RedactionEngine,
) -> Result<RedactionSummary, QueryError> {
    let profile = engine.policy().default_profile;
    if !matches!(profile, ExportProfile::Safe | ExportProfile::Minimal) {
        return Err(QueryError::Invalid(
            "telemetry redaction requires the safe or minimal profile".into(),
        ));
    }
    for class in [FieldClass::Uid, FieldClass::Pid] {
        if engine.policy().action_for_profile(class, profile) != Action::Allow {
            return Err(QueryError::Invalid(format!(
                "telemetry redaction cannot preserve typed {class} columns with this policy"
            )));
        }
    }

    let root = checked_absolute_path(root)?;
    let destination_name = output.file_name().ok_or_else(|| {
        QueryError::Invalid("redaction destination must name a new directory".into())
    })?;
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = checked_absolute_path(parent)?;
    if !fs::symlink_metadata(&parent)?.is_dir() {
        return Err(QueryError::UnsafePath(parent));
    }
    let output = parent.join(destination_name);
    if output.starts_with(&root) || root.starts_with(&output) {
        return Err(QueryError::Invalid(
            "redaction destination must be outside the telemetry directory".into(),
        ));
    }
    match fs::symlink_metadata(&output) {
        Ok(_) => return Err(io::Error::from(io::ErrorKind::AlreadyExists).into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    let staging = tempfile::Builder::new()
        .prefix(".pt-redacted-")
        .tempdir_in(&parent)?;
    let schemas = TelemetrySchema::new();
    let mut summary = RedactionSummary::default();
    for table in TableName::ALL {
        let directory = staging.path().join(table.as_str());
        create_private_directory(&directory)?;
        let mut file = create_private_file(&directory.join("part-00000.parquet"))?;
        let properties = WriterProperties::builder()
            .set_max_row_group_size(READ_BATCH_SIZE)
            .build();
        let mut writer = ArrowWriter::try_new(&mut file, schemas.get(table), Some(properties))?;
        let mut values_redacted = 0;
        let read = scan_table_batches(&root, table, |batch| {
            let (redacted, changed) = redact_batch(batch, table, engine)?;
            values_redacted += changed;
            writer.write(&redacted)?;
            Ok(())
        })?;
        writer.close()?;
        file.sync_all()?;
        sync_directory(&directory)?;
        summary.files_read += read.files_read;
        summary.files_written += 1;
        summary.rows_scanned += read.rows_scanned;
        summary.values_redacted += values_redacted;
        summary.tables.push(TableRedactionSummary {
            table: table.to_string(),
            files_read: read.files_read,
            files_written: 1,
            rows_scanned: read.rows_scanned,
            values_redacted,
        });
    }
    sync_directory(staging.path())?;
    publish_directory(staging.path(), &output)?;
    // Publication is complete. A parent fsync can be unsupported by some file
    // systems; do not report a failed copy after its complete output is visible.
    if let Err(error) = sync_directory(&parent) {
        tracing::warn!(%error, "could not sync published telemetry parent directory");
    }
    Ok(summary)
}

fn redact_batch(
    batch: &RecordBatch,
    table: TableName,
    engine: &RedactionEngine,
) -> Result<(RecordBatch, u64), QueryError> {
    let mut columns = Vec::with_capacity(batch.num_columns());
    let mut changed = 0;
    for (field, column) in batch.schema().fields().iter().zip(batch.columns()) {
        if field.data_type() != &DataType::Utf8 {
            columns.push(column.clone());
            continue;
        }
        let strings = column
            .as_any()
            .downcast_ref::<StringArray>()
            .ok_or_else(|| QueryError::Invalid("telemetry string column must be UTF-8".into()))?;
        let mut values = Vec::with_capacity(strings.len());
        for value in strings.iter() {
            values.push(match value {
                Some(value) => {
                    let redacted = redact_string(field.name(), value, table, engine)?;
                    changed += u64::from(redacted != value);
                    Some(redacted)
                }
                None => None,
            });
        }
        columns.push(Arc::new(StringArray::from(values)));
    }
    // Deliberately discard input schema metadata, which may contain private
    // free text even when its fields match the expected table schema.
    let batch = RecordBatch::try_new(TelemetrySchema::new().get(table), columns)?;
    Ok((batch, changed))
}

fn redact_string(
    field: &str,
    value: &str,
    table: TableName,
    engine: &RedactionEngine,
) -> Result<String, QueryError> {
    if field.ends_with("_json") || field == "config_snapshot" {
        let parsed: Value = serde_json::from_str(value).map_err(|_| {
            QueryError::Invalid(format!("invalid JSON in telemetry {table}.{field}"))
        })?;
        let redacted = redact_json(&parsed, engine);
        return if redacted == parsed {
            Ok(value.to_owned())
        } else {
            Ok(serde_json::to_string(&redacted)?)
        };
    }
    if field == "safety_gate_details" {
        if let Ok(parsed) = serde_json::from_str::<Value>(value) {
            return Ok(serde_json::to_string(&redact_json(&parsed, engine))?);
        }
    }
    if let Some(identifier) = redact_identifier(field, value, engine) {
        return Ok(identifier);
    }
    if value == "[REDACTED]" {
        return Ok(value.to_owned());
    }
    // These telemetry names share the existing engine's validated public
    // vocabulary. Unknown categories still receive stable pseudonyms.
    let classification = match field {
        "pt_core_version" => "pt_version",
        "decision" | "prior_decision" | "human_decision" => "recommendation",
        "process_state_after" => "state",
        "prediction_class" => "classification",
        _ => field,
    };
    let object = Value::Object(serde_json::Map::from_iter([(
        classification.to_owned(),
        Value::String(value.to_owned()),
    )]));
    let redacted = engine.redact_json_for_export(&object, engine.policy().default_profile);
    redacted
        .as_object()
        .and_then(|fields| fields.values().next())
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| QueryError::Invalid("redaction engine returned a non-string value".into()))
}

fn redact_identifier(field: &str, value: &str, engine: &RedactionEngine) -> Option<String> {
    let class = match field {
        "target_start_id" => "start_id",
        "session_id" | "host_id" | "start_id" | "signature_id" | "cmdline_hash"
        | "capabilities_hash" => field,
        _ => return None,
    };
    if matches!(value, "unknown" | "[REDACTED]") {
        return Some(value.to_owned());
    }
    // Full keyed hashes keep distinct identities distinct even when a custom
    // display policy would collapse their strings into a redaction placeholder.
    Some(engine.artifact_identifier(&format!("telemetry:{class}:{value}")))
}

fn redact_json(value: &Value, engine: &RedactionEngine) -> Value {
    let mut redacted = engine.redact_json_for_export(value, engine.policy().default_profile);
    align_json_identifiers(value, &mut redacted, None, engine);
    redacted
}

/// Apply the same pseudonyms to embedded IDs after the structured engine has
/// enforced secret-field rules. A subtree that the engine removes (notably
/// environment/credential data) is never rebuilt or traversed.
fn align_json_identifiers(
    original: &Value,
    redacted: &mut Value,
    field: Option<&str>,
    engine: &RedactionEngine,
) {
    if field.is_some_and(|field| field.eq_ignore_ascii_case("environment_vars")) {
        return;
    }
    if let (Some(field), Some(value)) = (field, original.as_str()) {
        if let Some(identifier) = redact_identifier(field, value, engine) {
            *redacted = Value::String(identifier);
            return;
        }
    }
    match (original, redacted) {
        (Value::Object(original), Value::Object(redacted)) => {
            for (field, value) in original {
                let probe =
                    Value::Object(serde_json::Map::from_iter([(field.clone(), Value::Null)]));
                let probe = engine.redact_json_for_export(&probe, engine.policy().default_profile);
                if let Some(key) = probe.as_object().and_then(|fields| fields.keys().next()) {
                    if let Some(exported) = redacted.get_mut(key) {
                        align_json_identifiers(value, exported, Some(field), engine);
                    }
                }
            }
        }
        (Value::Array(original), Value::Array(redacted)) => {
            for (original, redacted) in original.iter().zip(redacted) {
                align_json_identifiers(original, redacted, field, engine);
            }
        }
        _ => {}
    }
}

/// Resolve lexical components while refusing every existing symlink component,
/// including ancestors of a missing input lake. No directories are created.
fn checked_absolute_path(path: &Path) -> Result<PathBuf, QueryError> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut checked = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::ParentDir => {
                checked.pop();
            }
            Component::CurDir => {}
            component => {
                checked.push(component.as_os_str());
                match fs::symlink_metadata(&checked) {
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        return Err(QueryError::UnsafePath(checked));
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
    }
    Ok(checked)
}

fn create_private_directory(path: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

fn create_private_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

/// Unlike `fs::rename`, these operations cannot replace even an empty directory
/// created by another writer after the initial destination check.
fn publish_directory(staging: &Path, output: &Path) -> io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let staging = CString::new(staging.as_os_str().as_bytes())?;
        let output = CString::new(output.as_os_str().as_bytes())?;
        #[cfg(target_os = "linux")]
        // SAFETY: both C strings are owned and live for this syscall; the
        // operation only renames the completed private directory without replace.
        let result = unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                staging.as_ptr(),
                libc::AT_FDCWD,
                output.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        #[cfg(target_os = "macos")]
        // SAFETY: both C strings are valid for the duration of the syscall.
        let result =
            unsafe { libc::renamex_np(staging.as_ptr(), output.as_ptr(), libc::RENAME_EXCL) };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (staging, output);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "atomic telemetry directory publication is unsupported on this platform",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow::array::{
        ArrayRef, BooleanArray, Float32Array, Int8Array, Int16Array, Int32Array, Int64Array,
        TimestampMicrosecondArray,
    };
    use arrow::datatypes::{Field, Schema};
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
    use pt_redact::{KeyMaterial, RedactionPolicy};

    const SESSION: &str = "pt-20261114-120000-abcd";
    const START: &str = "550e8400-e29b-41d4-a716-446655440000:123:456";
    const HOST: &str = "host-01234567";
    const HASH: &str = "[HASH:old:0123456789abcdef]";

    fn engine(key: u8) -> RedactionEngine {
        RedactionEngine::with_key(
            RedactionPolicy::default(),
            KeyMaterial::from_bytes([key; 32], "test"),
        )
    }

    fn string_value(field: &str, row: usize) -> String {
        match field {
            "session_id" => SESSION.into(),
            "start_id" | "target_start_id" => START.into(),
            "host_id" => HOST.into(),
            "cmdline_hash" | "capabilities_hash" => HASH.into(),
            "signature_id" => "private-customer-signature".into(),
            "cmd" | "cmdline" | "cmd_pattern" => {
                format!("python /home/private-customer/job-{row}.py --token=super_secret_token")
            }
            "exe" | "cwd" => "/home/private-customer/project".into(),
            "mode" => "quick".into(),
            "state" => "running".into(),
            "recommendation" | "decision" => "spare".into(),
            "confidence" => "high".into(),
            "pt_version" | "pt_core_version" | "schema_version" => "1.0.0".into(),
            "os_family" => "linux".into(),
            "arch" => "x86_64".into(),
            field if field.ends_with("_json") || field == "config_snapshot" => serde_json::json!({
                "session_id": SESSION,
                "start_id": START,
                "cmd": "/home/private-customer/job.py",
                "count": row,
                "success": true,
                "metadata": {"private-customer-key": {"message": "private-customer-message"}},
                "environment": {"TOKEN": "super_secret_token"},
                "environment_vars": {"target_start_id": "super_secret_token"},
                "token": "AKIAIOSFODNN7EXAMPLE"
            })
            .to_string(),
            _ => format!("private-customer-{field}-{row}"),
        }
    }

    fn sample_batch(table: TableName, offset: usize, count: usize) -> RecordBatch {
        let schema = TelemetrySchema::new().get(table);
        let columns: Vec<ArrayRef> = schema
            .fields()
            .iter()
            .map(|field| {
                let rows = || {
                    (offset..offset + count).map(|row| {
                        if field.is_nullable() && row % 3 == 1 {
                            None
                        } else {
                            Some(row)
                        }
                    })
                };
                match field.data_type() {
                    DataType::Utf8 => Arc::new(StringArray::from(
                        rows()
                            .map(|row| row.map(|row| string_value(field.name(), row)))
                            .collect::<Vec<_>>(),
                    )) as ArrayRef,
                    DataType::Boolean => Arc::new(BooleanArray::from(
                        rows()
                            .map(|row| row.map(|row| row % 2 == 0))
                            .collect::<Vec<_>>(),
                    )),
                    DataType::Int8 => Arc::new(Int8Array::from(
                        rows()
                            .map(|row| row.map(|row| row as i8))
                            .collect::<Vec<_>>(),
                    )),
                    DataType::Int16 => Arc::new(Int16Array::from(
                        rows()
                            .map(|row| row.map(|row| row as i16))
                            .collect::<Vec<_>>(),
                    )),
                    DataType::Int32 => Arc::new(Int32Array::from(
                        rows()
                            .map(|row| row.map(|row| row as i32))
                            .collect::<Vec<_>>(),
                    )),
                    DataType::Int64 => Arc::new(Int64Array::from(
                        rows()
                            .map(|row| row.map(|row| row as i64))
                            .collect::<Vec<_>>(),
                    )),
                    DataType::Float32 => Arc::new(Float32Array::from(
                        rows()
                            .map(|row| row.map(|row| row as f32 / 10.0))
                            .collect::<Vec<_>>(),
                    )),
                    DataType::Timestamp(_, _) => Arc::new(
                        TimestampMicrosecondArray::from(
                            rows()
                                .map(|row| row.map(|row| row as i64))
                                .collect::<Vec<_>>(),
                        )
                        .with_timezone("UTC"),
                    ),
                    other => panic!("unhandled telemetry test type: {other:?}"),
                }
            })
            .collect();
        RecordBatch::try_new(schema, columns).unwrap()
    }

    fn write_batch(root: &Path, table: TableName, name: &str, batch: &RecordBatch) -> PathBuf {
        let directory = root.join(table.as_str());
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join(name);
        let mut writer =
            ArrowWriter::try_new(File::create(&path).unwrap(), batch.schema(), None).unwrap();
        writer.write(batch).unwrap();
        writer.close().unwrap();
        path
    }

    fn read_table(root: &Path, table: TableName) -> RecordBatch {
        let file = File::open(root.join(table.as_str()).join("part-00000.parquet")).unwrap();
        let builder = ParquetRecordBatchReaderBuilder::try_new(file).unwrap();
        assert_eq!(
            builder.schema().fields(),
            TelemetrySchema::new().get(table).fields()
        );
        let batches = builder
            .build()
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        arrow::compute::concat_batches(&TelemetrySchema::new().get(table), &batches).unwrap()
    }

    fn string_at<'a>(batch: &'a RecordBatch, field: &str, row: usize) -> &'a str {
        batch
            .column_by_name(field)
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap()
            .value(row)
    }

    #[test]
    fn sanitizes_all_tables_and_preserves_types_nulls_and_source_bytes() {
        let workspace = tempfile::tempdir().unwrap();
        let source = workspace.path().join("source");
        let output = workspace.path().join("copy");
        let mut originals = Vec::new();
        for table in TableName::ALL {
            let batch = sample_batch(table, 0, 3);
            let path = write_batch(&source, table, "private-source-name.parquet", &batch);
            originals.push((table, batch, path.clone(), fs::read(path).unwrap()));
        }
        let summary = redact_telemetry(&source, &output, &engine(1)).unwrap();
        assert_eq!(summary.files_read, 7);
        assert_eq!(summary.files_written, 7);
        assert_eq!(summary.rows_scanned, 21);
        assert_eq!(summary.tables.len(), 7);
        assert!(summary.values_redacted > 0);
        let mut changed = 0;
        for (table, original, path, bytes) in originals {
            assert_eq!(
                fs::read(path).unwrap(),
                bytes,
                "source must remain byte-identical"
            );
            let copied = read_table(&output, table);
            assert_eq!(copied.num_rows(), original.num_rows());
            for ((field, before), after) in original
                .schema()
                .fields()
                .iter()
                .zip(original.columns())
                .zip(copied.columns())
            {
                assert_eq!(
                    before.null_count(),
                    after.null_count(),
                    "{table}.{}",
                    field.name()
                );
                if field.data_type() != &DataType::Utf8 {
                    assert_eq!(
                        before.to_data(),
                        after.to_data(),
                        "{table}.{}",
                        field.name()
                    );
                } else {
                    let before = before.as_any().downcast_ref::<StringArray>().unwrap();
                    let after = after.as_any().downcast_ref::<StringArray>().unwrap();
                    for (before, after) in before.iter().zip(after.iter()) {
                        changed += u64::from(before != after);
                        if let Some(after) = after {
                            assert!(
                                !after.contains("private-customer"),
                                "{table}.{}: {after}",
                                field.name()
                            );
                            assert!(!after.contains("super_secret_token"));
                            assert!(!after.contains("AKIAIOSFODNN7EXAMPLE"));
                            assert!(!after.contains(START));
                            assert!(!after.contains(SESSION));
                            assert!(!after.contains(HASH));
                        }
                    }
                }
            }
        }
        assert_eq!(summary.values_redacted, changed);
        let audit = read_table(&output, TableName::Audit);
        let details: Value = serde_json::from_str(string_at(&audit, "details_json", 0)).unwrap();
        assert_eq!(details["count"], 0);
        assert_eq!(details["success"], true);
        assert_eq!(details["session_id"], string_at(&audit, "session_id", 0));
        assert_eq!(details["start_id"], string_at(&audit, "target_start_id", 0));
        assert_eq!(details["environment"], "[REDACTED]");
        assert!(
            details["environment_vars"]
                .as_object()
                .unwrap()
                .values()
                .all(|value| value == "[REDACTED]")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&output).unwrap().permissions().mode() & 0o077,
                0
            );
            for table in TableName::ALL {
                let directory = output.join(table.as_str());
                assert_eq!(
                    fs::metadata(&directory).unwrap().permissions().mode() & 0o077,
                    0
                );
                assert_eq!(
                    fs::metadata(directory.join("part-00000.parquet"))
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o077,
                    0
                );
            }
        }
    }

    #[test]
    fn identifier_joins_agree_across_tables_and_change_with_the_key() {
        let first = engine(1);
        let second = engine(2);
        for (field, raw) in [
            ("session_id", SESSION),
            ("host_id", HOST),
            ("start_id", START),
            ("signature_id", "private-signature"),
            ("cmdline_hash", HASH),
            ("capabilities_hash", HASH),
        ] {
            let token = redact_string(field, raw, TableName::Runs, &first).unwrap();
            assert_ne!(token, raw);
            assert_eq!(
                token,
                redact_string(field, raw, TableName::Outcomes, &first).unwrap()
            );
            assert_ne!(
                token,
                redact_string(field, raw, TableName::Runs, &second).unwrap()
            );
        }
        assert_eq!(
            redact_string("start_id", START, TableName::ProcSamples, &first).unwrap(),
            redact_string("target_start_id", START, TableName::Audit, &first).unwrap()
        );
        assert_ne!(
            redact_identifier("session_id", "same", &first),
            redact_identifier("host_id", "same", &first)
        );
    }

    #[test]
    fn reads_sorted_partitions_and_bounds_output_row_groups() {
        let workspace = tempfile::tempdir().unwrap();
        let source = workspace.path().join("source");
        let output = workspace.path().join("copy");
        let first = sample_batch(TableName::Audit, 0, READ_BATCH_SIZE + 7);
        let second = sample_batch(TableName::Audit, READ_BATCH_SIZE + 7, 2);
        write_batch(&source, TableName::Audit, "b.parquet", &second);
        write_batch(&source, TableName::Audit, "a.parquet", &first);
        fs::write(source.join("audit/unfinished.parquet.tmp"), b"unfinished").unwrap();
        let summary = redact_telemetry(&source, &output, &engine(1)).unwrap();
        assert_eq!(summary.files_read, 2);
        assert_eq!(summary.rows_scanned, (READ_BATCH_SIZE + 9) as u64);
        let batch = read_table(&output, TableName::Audit);
        let times = batch
            .column_by_name("audit_ts")
            .unwrap()
            .as_any()
            .downcast_ref::<TimestampMicrosecondArray>()
            .unwrap();
        for (index, time) in times.iter().enumerate() {
            assert_eq!(time, Some(index as i64));
        }
        let file = File::open(output.join("audit/part-00000.parquet")).unwrap();
        let builder = ParquetRecordBatchReaderBuilder::try_new(file).unwrap();
        assert!(builder.metadata().num_row_groups() > 1);
        assert!(
            builder
                .metadata()
                .row_groups()
                .iter()
                .all(|group| group.num_rows() <= READ_BATCH_SIZE as i64)
        );
    }

    #[test]
    fn missing_source_publishes_all_empty_schemas_without_creating_input() {
        let workspace = tempfile::tempdir().unwrap();
        let source = workspace.path().join("missing/source");
        let output = workspace.path().join("copy");
        let summary = redact_telemetry(&source, &output, &engine(1)).unwrap();
        assert_eq!(summary.files_read, 0);
        assert_eq!(summary.files_written, 7);
        assert_eq!(summary.rows_scanned, 0);
        assert_eq!(summary.values_redacted, 0);
        assert!(!source.exists());
        assert!(!source.parent().unwrap().exists());
        for table in TableName::ALL {
            assert_eq!(read_table(&output, table).num_rows(), 0);
        }
    }

    #[test]
    fn rejects_bad_empty_schema_and_corrupt_late_files_without_publication() {
        for corrupt in [false, true] {
            let workspace = tempfile::tempdir().unwrap();
            let source = workspace.path().join("source");
            let output = workspace.path().join("copy");
            let path = write_batch(
                &source,
                TableName::Runs,
                "valid.parquet",
                &sample_batch(TableName::Runs, 0, 1),
            );
            let before = fs::read(&path).unwrap();
            let bad = if corrupt {
                let path = source.join("signature_matches/corrupt.parquet");
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(&path, b"not parquet").unwrap();
                path
            } else {
                let schema = Arc::new(Schema::new(vec![Field::new(
                    "unexpected",
                    DataType::Int32,
                    false,
                )]));
                write_batch(
                    &source,
                    TableName::SignatureMatches,
                    "empty.parquet",
                    &RecordBatch::new_empty(schema),
                )
            };
            let bad_before = fs::read(&bad).unwrap();
            assert!(redact_telemetry(&source, &output, &engine(1)).is_err());
            assert!(!output.exists());
            assert_eq!(fs::read(path).unwrap(), before);
            assert_eq!(fs::read(bad).unwrap(), bad_before);
            assert_eq!(
                fs::read_dir(workspace.path()).unwrap().count(),
                1,
                "staging directory must be cleaned up"
            );
        }
    }

    #[test]
    fn malformed_json_fails_without_echoing_private_data_or_publishing() {
        let workspace = tempfile::tempdir().unwrap();
        let source = workspace.path().join("source");
        let output = workspace.path().join("copy");
        let batch = sample_batch(TableName::Audit, 0, 1);
        let mut columns = batch.columns().to_vec();
        let index = batch.schema().index_of("details_json").unwrap();
        columns[index] = Arc::new(StringArray::from(vec!["{private-customer-invalid"]));
        let batch = RecordBatch::try_new(batch.schema(), columns).unwrap();
        let path = write_batch(&source, TableName::Audit, "part.parquet", &batch);
        let bytes = fs::read(&path).unwrap();
        let error = redact_telemetry(&source, &output, &engine(1)).unwrap_err();
        assert!(error.to_string().contains("audit.details_json"));
        assert!(!error.to_string().contains("private-customer"));
        assert!(!output.exists());
        assert_eq!(fs::read(path).unwrap(), bytes);
    }

    #[test]
    fn refuses_existing_overlapping_destinations_and_unsafe_profiles() {
        let workspace = tempfile::tempdir().unwrap();
        let source = workspace.path().join("source");
        fs::create_dir(&source).unwrap();
        let output = workspace.path().join("copy");
        fs::create_dir(&output).unwrap();
        fs::write(output.join("sentinel"), b"keep").unwrap();
        assert!(redact_telemetry(&source, &output, &engine(1)).is_err());
        assert_eq!(fs::read(output.join("sentinel")).unwrap(), b"keep");
        assert!(redact_telemetry(&source, &source.join("inside"), &engine(1)).is_err());
        assert!(!source.join("inside").exists());
        let output = workspace.path().join("new");
        let policy = RedactionPolicy {
            default_profile: ExportProfile::Forensic,
            ..Default::default()
        };
        let forensic = RedactionEngine::with_key(policy, KeyMaterial::from_bytes([0; 32], "test"));
        assert!(redact_telemetry(&source, &output, &forensic).is_err());
        let mut policy = RedactionPolicy::default();
        policy.set_action(FieldClass::Uid, Action::Redact);
        let strict = RedactionEngine::with_key(policy, KeyMaterial::from_bytes([0; 32], "test"));
        assert!(redact_telemetry(&source, &output, &strict).is_err());
        assert!(!output.exists());
        let policy = RedactionPolicy {
            default_profile: ExportProfile::Minimal,
            ..Default::default()
        };
        let minimal = RedactionEngine::with_key(policy, KeyMaterial::from_bytes([0; 32], "test"));
        assert!(redact_telemetry(&source, &output, &minimal).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_source_and_destination_symlinks() {
        use std::os::unix::fs::symlink;
        for kind in [
            "root",
            "table",
            "partition",
            "file",
            "parent",
            "destination",
        ] {
            let workspace = tempfile::tempdir().unwrap();
            let source = workspace.path().join("source");
            let output = workspace.path().join("copy");
            let external = workspace.path().join("external");
            fs::create_dir(&external).unwrap();
            let mut requested_output = output.clone();
            match kind {
                "root" => symlink(&external, &source).unwrap(),
                "table" => {
                    fs::create_dir(&source).unwrap();
                    symlink(&external, source.join("audit")).unwrap();
                }
                "partition" | "file" => {
                    fs::create_dir_all(source.join("audit")).unwrap();
                    symlink(
                        &external,
                        source.join("audit").join(if kind == "file" {
                            "linked.parquet"
                        } else {
                            "linked"
                        }),
                    )
                    .unwrap();
                }
                "parent" => {
                    let parent = workspace.path().join("linked-parent");
                    symlink(&external, &parent).unwrap();
                    requested_output = parent.join("copy");
                }
                "destination" => symlink(&external, &output).unwrap(),
                _ => unreachable!(),
            }
            assert!(
                redact_telemetry(&source, &requested_output, &engine(1)).is_err(),
                "{kind}"
            );
            assert_eq!(fs::read_dir(&external).unwrap().count(), 0);
            if kind != "destination" {
                assert!(!output.exists());
            }
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn publication_cannot_replace_an_empty_directory_created_concurrently() {
        let workspace = tempfile::tempdir().unwrap();
        let staging = workspace.path().join("staging");
        let output = workspace.path().join("copy");
        fs::create_dir(&staging).unwrap();
        fs::write(staging.join("complete"), b"data").unwrap();
        fs::create_dir(&output).unwrap();
        assert!(publish_directory(&staging, &output).is_err());
        assert_eq!(fs::read_dir(&output).unwrap().count(), 0);
        assert_eq!(fs::read(staging.join("complete")).unwrap(), b"data");
    }
}
