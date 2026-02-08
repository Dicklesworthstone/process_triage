//! MCP (Model Context Protocol) server for process triage.
//!
//! Exposes pt functionality to AI agents via the standardized MCP protocol
//! over stdio (JSON-RPC 2.0).

pub mod protocol;
pub mod resources;
pub mod server;
pub mod tools;

pub use server::McpServer;
