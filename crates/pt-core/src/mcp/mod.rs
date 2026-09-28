//! MCP (Model Context Protocol) server for process triage.
//!
//! Exposes pt functionality to AI agents via the standardized MCP protocol
//! over stdio (JSON-RPC 2.0).

pub mod protocol;
pub mod resources;
pub mod server;
pub mod tools;

pub use server::McpServer;

use std::path::PathBuf;
use std::sync::OnceLock;

static CONFIG_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Use `dir` (the `--config` / `PT_CONFIG_DIR` directory) for every config file the
/// MCP tools and resources read, as the CLI commands do. Set once, before serving.
pub fn set_config_dir(dir: PathBuf) {
    let _ = CONFIG_DIR.set(dir);
}

/// Config options for the MCP tools and resources: the directory given to
/// [`set_config_dir`], else the usual resolution (`PROCESS_TRIAGE_CONFIG`, XDG).
pub(crate) fn config_options() -> crate::config::ConfigOptions {
    crate::config::ConfigOptions {
        config_dir: CONFIG_DIR.get().cloned(),
        ..Default::default()
    }
}
