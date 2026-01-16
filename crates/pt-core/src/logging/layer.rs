//! Custom tracing layer for JSONL output.
//!
//! This layer produces machine-parseable JSONL logs on stderr while
//! keeping stdout clean for command payloads.

use std::io::{self, Write};
use std::sync::Mutex;

use chrono::Utc;
use tracing::span::{Attributes, Id};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

use super::events::Level;
use crate::logging::get_redactor;
use pt_redact::FieldClass;

/// Storage for span context data.
#[derive(Debug, Clone, Default)]
struct SpanContext {
    run_id: Option<String>,
    session_id: Option<String>,
    host_id: Option<String>,
    stage: Option<String>,
    pid: Option<u32>,
    start_id: Option<String>,
}

/// A visitor that extracts field values from tracing events.
struct JsonFieldVisitor {
    fields: serde_json::Map<String, serde_json::Value>,
    message: Option<String>,
}

impl JsonFieldVisitor {
    fn new() -> Self {
        JsonFieldVisitor {
            fields: serde_json::Map::new(),
            message: None,
        }
    }
}

impl tracing::field::Visit for JsonFieldVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            // Messages are FreeText, subject to secret detection
            let redacted = get_redactor().redact(value, FieldClass::FreeText);
            self.message = Some(redacted.output);
        } else {
            let class = guess_field_class(field.name());
            let redacted = get_redactor().redact(value, class);
            self.fields.insert(
                field.name().to_string(),
                serde_json::Value::String(redacted.output),
            );
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let s = format!("{:?}", value);
        if field.name() == "message" {
            let redacted = get_redactor().redact(&s, FieldClass::FreeText);
            self.message = Some(redacted.output);
        } else {
            // Debug output is treated as FreeText by default unless we know better
            let class = guess_field_class(field.name());
            let redacted = get_redactor().redact(&s, class);
            self.fields
                .insert(field.name().to_string(), serde_json::Value::String(redacted.output));
        }
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.fields.insert(
            field.name().to_string(),
            serde_json::Value::Number(value.into()),
        );
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.fields.insert(
            field.name().to_string(),
            serde_json::Value::Number(serde_json::Number::from(value)),
        );
    }

    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        if let Some(n) = serde_json::Number::from_f64(value) {
            self.fields
                .insert(field.name().to_string(), serde_json::Value::Number(n));
        }
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.fields
            .insert(field.name().to_string(), serde_json::Value::Bool(value));
    }
}

/// Guess the field class based on the field name.
fn guess_field_class(name: &str) -> FieldClass {
    match name {
        "cmd" | "command" | "exe" => FieldClass::Cmd,
        "args" | "cmdline" => FieldClass::Cmdline,
        "path" | "file" | "cwd" | "dir" => FieldClass::PathProject,
        "home" => FieldClass::PathHome,
        "tmp" | "temp" => FieldClass::PathTmp,
        "env" | "environ" => FieldClass::EnvValue,
        "user" | "username" => FieldClass::Username,
        "host" | "hostname" => FieldClass::Hostname,
        "ip" | "addr" | "address" => FieldClass::IpAddress,
        "url" | "uri" => FieldClass::Url,
        "pid" | "ppid" => FieldClass::Pid,
        "uid" | "gid" => FieldClass::Uid,
        "port" => FieldClass::Port,
        "container" | "container_id" => FieldClass::ContainerId,
        "unit" | "service" => FieldClass::SystemdUnit,
        _ => FieldClass::FreeText,
    }
}

/// A visitor for extracting span context.
struct SpanContextVisitor {
    context: SpanContext,
}

impl SpanContextVisitor {
    fn new() -> Self {
        SpanContextVisitor {
            context: SpanContext::default(),
        }
    }
}

impl tracing::field::Visit for SpanContextVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        match field.name() {
            "run_id" => self.context.run_id = Some(value.to_string()),
            "session_id" => self.context.session_id = Some(value.to_string()),
            "host_id" => self.context.host_id = Some(value.to_string()),
            "stage" => self.context.stage = Some(value.to_string()),
            "start_id" => self.context.start_id = Some(value.to_string()),
            _ => {}
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        match field.name() {
            "run_id" => self.context.run_id = Some(format!("{:?}", value)),
            "session_id" => self.context.session_id = Some(format!("{:?}", value)),
            "host_id" => self.context.host_id = Some(format!("{:?}", value)),
            "stage" => self.context.stage = Some(format!("{:?}", value)),
            _ => {}
        }
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        if field.name() == "pid" {
            self.context.pid = Some(value as u32);
        }
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        if field.name() == "pid" && value >= 0 {
            self.context.pid = Some(value as u32);
        }
    }

    fn record_bool(&mut self, _field: &tracing::field::Field, _value: bool) {}
    fn record_f64(&mut self, _field: &tracing::field::Field, _value: f64) {}
}

/// JSONL tracing layer that outputs to stderr.
pub struct JsonlLayer<W = io::Stderr> {
    writer: Mutex<W>,
}

impl JsonlLayer<io::Stderr> {
    /// Create a new JSONL layer writing to stderr.
    pub fn stderr() -> Self {
        JsonlLayer {
            writer: Mutex::new(io::stderr()),
        }
    }
}

impl<W: Write> JsonlLayer<W> {
    /// Create a new JSONL layer with a custom writer.
    #[allow(dead_code)]
    pub fn new(writer: W) -> Self {
        JsonlLayer {
            writer: Mutex::new(writer),
        }
    }
}

impl<S, W> Layer<S> for JsonlLayer<W>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    W: Write + 'static,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        // Extract and store span context
        let mut visitor = SpanContextVisitor::new();
        attrs.record(&mut visitor);

        if let Some(span) = ctx.span(id) {
            span.extensions_mut().insert(visitor.context);
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let ts = Utc::now();

        // Collect span context from parent spans
        let mut run_id = None;
        let mut session_id = None;
        let mut host_id = None;
        let mut stage = None;
        let mut pid = None;
        let mut start_id = None;

        if let Some(scope) = ctx.event_scope(event) {
            for span in scope {
                if let Some(span_ctx) = span.extensions().get::<SpanContext>() {
                    if run_id.is_none() {
                        run_id.clone_from(&span_ctx.run_id);
                    }
                    if session_id.is_none() {
                        session_id.clone_from(&span_ctx.session_id);
                    }
                    if host_id.is_none() {
                        host_id.clone_from(&span_ctx.host_id);
                    }
                    if stage.is_none() {
                        stage.clone_from(&span_ctx.stage);
                    }
                    if pid.is_none() {
                        pid = span_ctx.pid;
                    }
                    if start_id.is_none() {
                        start_id.clone_from(&span_ctx.start_id);
                    }
                }
            }
        }

        // Extract event fields
        let mut visitor = JsonFieldVisitor::new();
        event.record(&mut visitor);

        // Build JSON object
        let level: Level = (*event.metadata().level()).into();
        let mut obj = serde_json::Map::new();

        obj.insert("ts".to_string(), serde_json::json!(ts.to_rfc3339()));
        obj.insert("level".to_string(), serde_json::json!(level));
        obj.insert(
            "event".to_string(),
            serde_json::json!(event.metadata().target()),
        );

        if let Some(id) = run_id {
            obj.insert("run_id".to_string(), serde_json::json!(id));
        }
        if let Some(id) = session_id {
            obj.insert("session_id".to_string(), serde_json::json!(id));
        }
        if let Some(id) = host_id {
            obj.insert("host_id".to_string(), serde_json::json!(id));
        }
        if let Some(s) = stage {
            obj.insert("stage".to_string(), serde_json::json!(s));
        }
        if let Some(msg) = visitor.message {
            obj.insert("message".to_string(), serde_json::json!(msg));
        }
        if let Some(p) = pid {
            obj.insert("pid".to_string(), serde_json::json!(p));
        }
        if let Some(id) = start_id {
            obj.insert("start_id".to_string(), serde_json::json!(id));
        }

        // Add remaining fields
        if !visitor.fields.is_empty() {
            obj.insert(
                "fields".to_string(),
                serde_json::Value::Object(visitor.fields),
            );
        }

        // Write JSONL
        let json = serde_json::to_string(&serde_json::Value::Object(obj)).unwrap_or_default();
        if let Ok(mut writer) = self.writer.lock() {
            let _ = writeln!(writer, "{}", json);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tracing_subscriber::layer::SubscriberExt;

    #[test]
    fn test_jsonl_layer_output() {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let writer = {
            struct BufWriter(Arc<Mutex<Vec<u8>>>);
            impl Write for BufWriter {
                fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                    self.0.lock().unwrap().write(buf)
                }
                fn flush(&mut self) -> io::Result<()> {
                    Ok(())
                }
            }
            BufWriter(buffer.clone())
        };

        let layer = JsonlLayer::new(writer);
        let subscriber = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "test.event", message = "test message");
        });

        let output = buffer.lock().unwrap();
        let json_str = String::from_utf8_lossy(&output);
        assert!(json_str.contains("\"level\":\"info\""));
        assert!(json_str.contains("\"message\":\"test message\""));
    }
}
