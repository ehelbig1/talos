//! JSON-RPC 2.0 / MCP wire-format types.
//!
//! Extracted from `controller::mcp::types` and a small set of response
//! helpers from `controller::mcp::utils` so non-controller crates (and
//! eventually downstream consumers) can speak MCP without depending on
//! the entire controller binary.
//!
//! Scope of this crate: the wire format only. Tool dispatch, handler
//! state (`McpState`), parameter validation that depends on `uuid`,
//! and anything Postgres- or async-bound stays in `controller`.

use serde::{Deserialize, Serialize};

/// JSON-RPC 2.0 request envelope. `params` is left as `serde_json::Value`
/// so per-method param schemas are validated by individual handlers.
#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Option<serde_json::Value>,
    pub method: String,
    pub params: Option<serde_json::Value>,
}

/// JSON-RPC 2.0 response envelope. Either `result` or `error` is set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

/// JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// Build an MCP-style error response.
///
/// Returns the error as an MCP **tool result** (`result.isError = true`)
/// rather than a JSON-RPC `error` object, so MCP clients (Claude Desktop
/// and friends) display the actual message instead of a generic
/// "Error occurred during tool execution". The numeric code is preserved
/// in `result.errorCode` for programmatic discrimination.
pub fn mcp_error(id: Option<serde_json::Value>, code: i32, msg: &str) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id,
        result: Some(serde_json::json!({
            "content": [{ "type": "text", "text": msg }],
            "isError": true,
            "errorCode": code
        })),
        error: None,
    }
}

/// Build an MCP-style success response carrying a single text content block.
pub fn mcp_text(id: Option<serde_json::Value>, text: &str) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id,
        result: Some(serde_json::json!({
            "content": [{ "type": "text", "text": text }]
        })),
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcp_error_shape_matches_protocol() {
        let resp = mcp_error(Some(serde_json::json!(7)), -32602, "missing 'workflow_id'");
        assert_eq!(resp.jsonrpc, "2.0");
        assert!(resp.error.is_none());
        let result = resp.result.expect("result populated");
        assert_eq!(result["isError"], serde_json::json!(true));
        assert_eq!(result["errorCode"], serde_json::json!(-32602));
        assert_eq!(result["content"][0]["text"], "missing 'workflow_id'");
    }

    #[test]
    fn mcp_text_shape_matches_protocol() {
        let resp = mcp_text(None, "ok");
        let result = resp.result.expect("result populated");
        assert_eq!(result["content"][0]["type"], "text");
        assert_eq!(result["content"][0]["text"], "ok");
        assert!(result.get("isError").is_none());
    }

    #[test]
    fn round_trip_request() {
        let json = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}"#;
        let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.method, "tools/call");
    }
}
