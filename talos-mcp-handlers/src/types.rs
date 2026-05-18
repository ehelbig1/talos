//! Re-export of the canonical JSON-RPC / MCP wire-format types.
//!
//! Types live in the `talos-mcp` crate; this module preserves the
//! existing `crate::types::*` import path so call sites don't need
//! to change.
pub use talos_mcp::{JsonRpcError, JsonRpcRequest, JsonRpcResponse};

#[cfg(test)]
#[path = "types_tests.rs"]
mod tests;
