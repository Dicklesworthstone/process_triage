//! Structured test logging utilities.
//!
//! Emits JSONL entries to target/test-logs for machine-parsable test traces.

use chrono::{SecondsFormat, Utc};
use serde_json::{Map, Value};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

const LOG_DIR_NAME: &str = "test-logs";

fn log_lock() -> &'static Mutex<()> {
    static LOG_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOG_LOCK.get_or_init(|| Mutex::new(()))
}

fn target_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("CARGO_TARGET_DIR") {
        return PathBuf::from(dir);
    }

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.join("../../target")
}

fn log_file_path() -> PathBuf {
    let mut path = target_dir();
    path.push(LOG_DIR_NAME);
    let filename = format!("pt-core-tests-{}.jsonl", std::process::id());
    path.push(filename);
    path
}

fn write_log_line(line: &str) {
    let _guard = log_lock().lock().unwrap_or_else(|err| err.into_inner());
    let path = log_file_path();
    if let Some(parent) = path.parent() {
        if let Err(err) = fs::create_dir_all(parent) {
            eprintln!(
                "test_log: failed to create log dir {}: {}",
                parent.display(),
                err
            );
            return;
        }
    }

    let mut file = match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(file) => file,
        Err(err) => {
            eprintln!(
                "test_log: failed to open log file {}: {}",
                path.display(),
                err
            );
            return;
        }
    };

    if let Err(err) = file.write_all(line.as_bytes()) {
        eprintln!(
            "test_log: failed to write log file {}: {}",
            path.display(),
            err
        );
    }
    if let Err(err) = file.write_all(b"\n") {
        eprintln!(
            "test_log: failed to finalize log line {}: {}",
            path.display(),
            err
        );
    }
}

/// Emit a structured JSONL log entry for tests.
pub fn log_event(level: &str, msg: &str, file: &str, line: u32, fields: &[(&str, Value)]) {
    let ts = Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true);
    let mut map = Map::new();
    map.insert("ts".to_string(), Value::String(ts));
    map.insert("level".to_string(), Value::String(level.to_string()));
    map.insert("msg".to_string(), Value::String(msg.to_string()));
    map.insert("file".to_string(), Value::String(file.to_string()));
    map.insert(
        "line".to_string(),
        Value::Number(serde_json::Number::from(line)),
    );
    map.insert(
        "pid".to_string(),
        Value::Number(serde_json::Number::from(std::process::id())),
    );
    let thread_name = std::thread::current()
        .name()
        .unwrap_or("unnamed")
        .to_string();
    map.insert("thread".to_string(), Value::String(thread_name));

    for (key, value) in fields {
        if map.contains_key(*key) {
            let prefixed = format!("extra_{}", key);
            map.insert(prefixed, value.clone());
        } else {
            map.insert((*key).to_string(), value.clone());
        }
    }

    if !map.contains_key("test") {
        if let Some(Value::String(test_name)) = map.get("test_name") {
            map.insert("test".to_string(), Value::String(test_name.clone()));
        } else if let Some(Value::String(thread_name)) = map.get("thread") {
            map.insert("test".to_string(), Value::String(thread_name.clone()));
        }
    }

    match serde_json::to_string(&Value::Object(map)) {
        Ok(line) => write_log_line(&line),
        Err(err) => eprintln!("test_log: failed to serialize log entry: {}", err),
    }
}

/// Log a failed equality assertion with expected/actual context.
pub fn log_assert_eq(
    msg: &str,
    expected: &str,
    actual: &str,
    file: &str,
    line: u32,
    fields: &[(&str, Value)],
) {
    let mut extra_fields = Vec::with_capacity(fields.len() + 2);
    extra_fields.push(("expected", Value::String(expected.to_string())));
    extra_fields.push(("actual", Value::String(actual.to_string())));
    for (key, value) in fields {
        extra_fields.push((*key, value.clone()));
    }
    log_event("ERROR", msg, file, line, &extra_fields);
}

#[macro_export]
macro_rules! test_log {
    ($level:ident, $msg:expr $(, $key:ident = $val:expr )* $(,)?) => {{
        let fields = vec![
            $(
                (stringify!($key), serde_json::json!($val)),
            )*
        ];
        let msg_string = $msg.to_string();
        $crate::test_log::log_event(stringify!($level), &msg_string, file!(), line!(), &fields);
    }};
    ($($arg:tt)+) => {{
        $crate::test_log!(INFO, format!($($arg)+));
    }};
}

#[macro_export]
macro_rules! test_assert_eq {
    ($expected:expr, $actual:expr, $msg:expr $(, $key:ident = $val:expr )* $(,)?) => {{
        let expected_val = &$expected;
        let actual_val = &$actual;
        if expected_val != actual_val {
            let expected_str = format!("{:?}", expected_val);
            let actual_str = format!("{:?}", actual_val);
            let fields = vec![
                $(
                    (stringify!($key), serde_json::json!($val)),
                )*
            ];
            $crate::test_log::log_assert_eq(
                $msg,
                &expected_str,
                &actual_str,
                file!(),
                line!(),
                &fields,
            );
            panic!(
                "assertion failed: {} (expected: {:?}, actual: {:?})",
                $msg,
                expected_val,
                actual_val
            );
        }
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_event_serializes() {
        log_event(
            "INFO",
            "test-log",
            "test_log.rs",
            123,
            &[(
                "test",
                Value::String("test_log_event_serializes".to_string()),
            )],
        );

        let path = log_file_path();
        let content = std::fs::read_to_string(path).expect("log file should be readable");
        let mut matched = false;
        for line in content.lines() {
            if let Ok(parsed) = serde_json::from_str::<Value>(line) {
                if parsed["msg"] == "test-log" && parsed["test"] == "test_log_event_serializes" {
                    assert_eq!(parsed["level"], "INFO");
                    matched = true;
                    break;
                }
            }
        }
        assert!(matched, "expected structured log entry not found");
    }

    #[test]
    #[should_panic(expected = "assertion failed")]
    fn test_assert_eq_macro_panics() {
        test_assert_eq!(
            1,
            2,
            "values should match",
            test = "test_assert_eq_macro_panics"
        );
    }
}
