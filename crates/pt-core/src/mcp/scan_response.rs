//! Bound a ranked scan after scoring the complete census.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub(super) const DEFAULT_BYTES: usize = 64 * 1024;
pub(super) const MIN_BYTES: usize = 4096;
pub(super) const MAX_BYTES: usize = 1024 * 1024;
pub(super) const MAX_ROWS: usize = 200;
const CMD_PREVIEW_BYTES: usize = 256;

pub(super) struct ScanOutput {
    max_bytes: usize,
    limit: usize,
    full_cmd: bool,
}

impl ScanOutput {
    pub(super) fn parse(params: &Value) -> Result<Self, String> {
        let size = |name: &str, default, min, max| match params.get(name) {
            None => Ok(default),
            Some(value) => value
                .as_u64()
                .and_then(|n| usize::try_from(n).ok())
                .filter(|n| (min..=max).contains(n))
                .ok_or_else(|| format!("{name} must be an integer between {min} and {max}")),
        };
        Ok(Self {
            max_bytes: size("max_response_bytes", DEFAULT_BYTES, MIN_BYTES, MAX_BYTES)?,
            limit: size("limit", MAX_ROWS, 1, MAX_ROWS)?,
            full_cmd: params
                .get("full_cmd")
                .map(|v| v.as_bool().ok_or("full_cmd must be a boolean"))
                .transpose()?
                .unwrap_or(false),
        })
    }

    /// Fingerprint the full display command before shortening it. The kernel
    /// process identity remains in pid/start_id/uid.
    pub(super) fn command<'a>(&self, cmd: &'a str) -> (&'a str, bool, Option<String>) {
        if self.full_cmd || cmd.len() <= CMD_PREVIEW_BYTES {
            return (cmd, false, None);
        }
        let mut end = CMD_PREVIEW_BYTES;
        while !cmd.is_char_boundary(end) {
            end -= 1;
        }
        (
            &cmd[..end],
            true,
            Some(hex::encode(Sha256::digest(cmd.as_bytes()))),
        )
    }

    pub(super) fn render(
        &self,
        mut document: Value,
        matching: usize,
        rows: impl Iterator<Item = Value>,
        sections: [(&str, Value); 4],
    ) -> Result<String, String> {
        let considered = matching.min(self.limit);
        // Reserve the widest possible counters and elision report up front so
        // rows can be sized once, including their JSON-in-JSON escaping.
        document["matching_processes"] = json!(matching);
        document["returned"] = json!(considered);
        document["truncated"] = json!(false);
        document["response"] = json!({
            "max_bytes": self.max_bytes,
            "row_limit": self.limit,
            "omitted_by_row_limit": matching - considered,
            "omitted_by_byte_budget": considered,
            "commands_truncated": considered,
            "elided_sections": sections.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
        });
        document["processes"] = json!([]);

        // Leave room for ranked rows. Complete census-wide evidence may use
        // the entire budget when there are no candidates.
        let section_limit = if considered == 0 {
            self.max_bytes
        } else {
            self.max_bytes / 2
        };
        let mut used = result_size(&document.to_string());
        let mut omitted = Vec::new();
        for (name, section) in sections {
            // Each field contributes comma, quoted key, colon and value.
            // Accounting includes the extra quoting of the nested MCP text.
            let extra = 6 + name.len() + escaped_len(&section.to_string());
            if used + extra <= section_limit {
                document[name] = section;
                used += extra;
            } else {
                omitted.push(name);
            }
        }
        document["response"]["elided_sections"] = json!(omitted);
        used = result_size(&document.to_string());
        let mut kept = Vec::new();
        let mut commands_truncated = 0;
        for row in rows.take(considered) {
            let row_size = escaped_len(&row.to_string()) + usize::from(!kept.is_empty());
            if used + row_size <= self.max_bytes {
                used += row_size;
                commands_truncated += usize::from(row["cmd_truncated"] == true);
                kept.push(row);
            }
        }
        let returned = kept.len();
        document["returned"] = json!(returned);
        document["truncated"] = json!(matching > returned);
        document["response"]["omitted_by_byte_budget"] = json!(considered - returned);
        document["response"]["commands_truncated"] = json!(commands_truncated);
        document["processes"] = Value::Array(kept);
        let text = document.to_string();
        if result_size(&text) > self.max_bytes {
            return Err("scan metadata exceeds the MCP response byte budget".into());
        }
        Ok(text)
    }
}

// The inner JSON is compact, so it contains no literal ASCII control bytes.
// Each quote and backslash uses one additional byte in the outer JSON string.
fn escaped_len(text: &str) -> usize {
    text.len() + text.bytes().filter(|b| matches!(b, b'"' | b'\\')).count()
}

fn result_size(text: &str) -> usize {
    // Allow the success-result wrapper and ordinary JSON-RPC framing. Request
    // IDs are echoed by the transport and can have an arbitrary client length.
    128 + escaped_len(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(options: Value, commands: &[String], warning: &str) -> (String, Value) {
        let output = ScanOutput::parse(&options).unwrap();
        let rows = commands.iter().enumerate().map(|(pid, input)| {
            let (cmd, cut, digest) = output.command(input);
            json!({"pid": pid + 1, "start_id": format!("boot:9:{}", pid+1),
                "cmd": cmd, "cmd_truncated": cut, "cmd_sha256": digest})
        });
        let text = output
            .render(
                json!({"total_processes": commands.len()}),
                commands.len(),
                rows,
                [
                    ("deep_scan", json!({"status": "not_requested"})),
                    ("warnings", json!([warning])),
                    ("agent_activity", json!({"units": []})),
                    ("workloads", json!({})),
                ],
            )
            .unwrap();
        let parsed = serde_json::from_str(&text).unwrap();
        (text, parsed)
    }

    #[test]
    fn large_census_has_bounded_wire_size_unicode_previews_and_exact_elisions() {
        let prefix = format!("{}🦀", "\\".repeat(255));
        let command = format!("{prefix}{}", "\"\n".repeat(5000));
        let digest = hex::encode(Sha256::digest(command.as_bytes()));
        let commands = vec![command; 1000];
        let (text, doc) = scan(json!({}), &commands, &"x".repeat(DEFAULT_BYTES));
        let content = crate::mcp::protocol::ToolContent {
            content_type: "text".into(),
            text,
        };
        let rpc = crate::mcp::protocol::JsonRpcResponse::success(
            Some(json!(1)),
            json!({"content":[content],"isError":false}),
        );
        let wire = serde_json::to_vec(&rpc).unwrap();
        assert!(wire.len() <= DEFAULT_BYTES);
        let rows = doc["processes"].as_array().unwrap();
        assert!(!rows.is_empty() && rows.len() < 200);
        assert_eq!(doc["returned"], rows.len());
        assert_eq!(doc["truncated"], true);
        assert_eq!(doc["matching_processes"], 1000);
        assert_eq!(
            doc["response"],
            json!({"max_bytes":DEFAULT_BYTES,"row_limit":200,
            "omitted_by_row_limit":800,"omitted_by_byte_budget":200-rows.len(),
            "commands_truncated":rows.len(),"elided_sections":["warnings"]})
        );
        for (index, row) in rows.iter().enumerate() {
            assert_eq!(row["pid"], index + 1);
            assert_eq!(row["cmd"], "\\".repeat(255));
            assert_eq!(row["cmd_sha256"], digest);
            assert_eq!(row["cmd_truncated"], true);
        }
    }

    #[test]
    fn full_commands_respect_budget_without_hiding_smaller_ranked_results() {
        let commands = vec!["x".repeat(MIN_BYTES * 2), "🦀".repeat(200), "last".into()];
        let (text, doc) = scan(
            json!({"full_cmd":true,"limit":2,"max_response_bytes":MIN_BYTES}),
            &commands,
            "",
        );
        assert!(result_size(&text) <= MIN_BYTES);
        assert_eq!(doc["returned"], 1);
        assert_eq!(doc["response"]["omitted_by_byte_budget"], 1);
        assert_eq!(doc["response"]["omitted_by_row_limit"], 1);
        assert_eq!(doc["processes"][0]["cmd"], commands[1]);
        assert_eq!(doc["processes"][0]["cmd_truncated"], false);
        let (_, full) = scan(json!({"full_cmd":true}), &commands, "");
        assert_eq!(full["truncated"], false);
        assert_eq!(full["processes"][0]["cmd"], commands[0]);
        assert_eq!(full["response"]["elided_sections"], json!([]));
    }

    #[test]
    fn validates_response_options_and_exact_preview_boundary() {
        for bad in [
            json!({"max_response_bytes":MIN_BYTES-1}),
            json!({"max_response_bytes":MAX_BYTES+1}),
            json!({"max_response_bytes":null}),
            json!({"limit":0}),
            json!({"limit":201}),
            json!({"full_cmd":1}),
        ] {
            assert!(ScanOutput::parse(&bad).is_err(), "{bad}");
        }
        let out = ScanOutput::parse(&json!({})).unwrap();
        let exact = "🦀".repeat(64);
        assert_eq!(out.command(&exact), (exact.as_str(), false, None));
        let over = format!("{exact}x");
        let (preview, cut, hash) = out.command(&over);
        assert_eq!(preview, exact);
        assert!(cut && hash.is_some());
    }
}
