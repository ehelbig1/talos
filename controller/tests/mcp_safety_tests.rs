//! Integration tests for MCP safety features.
//!
//! The core dependency allowlist validation, rate limiter, and handler logic
//! are `pub(crate)` in the `mcp` module. Comprehensive unit tests for these
//! are in `controller/src/mcp/tests.rs` (including dependency allowlist
//! validation, rate limiter tracking/limiting, and window expiry).
//!
//! This integration test file validates the publicly accessible MCP types
//! and serialization behaviour.

use serde_json::json;

// ---------------------------------------------------------------------------
// JsonRpcRequest deserialization
// ---------------------------------------------------------------------------

#[test]
fn json_rpc_request_deserializes_with_all_fields() {
    let raw = r#"{"jsonrpc":"2.0","id":"req-1","method":"tools/call","params":{"name":"test","arguments":{}}}"#;
    let req: controller::mcp::JsonRpcRequest = serde_json::from_str(raw).unwrap();
    assert_eq!(req.jsonrpc, "2.0");
    assert_eq!(req.method, "tools/call");
    assert_eq!(req.id, Some(json!("req-1")));
    assert!(req.params.is_some());
}

#[test]
fn json_rpc_request_deserializes_without_optional_fields() {
    let raw = r#"{"jsonrpc":"2.0","method":"initialize"}"#;
    let req: controller::mcp::JsonRpcRequest = serde_json::from_str(raw).unwrap();
    assert_eq!(req.method, "initialize");
    assert!(req.id.is_none());
    assert!(req.params.is_none());
}

#[test]
fn json_rpc_request_with_numeric_id() {
    let raw = r#"{"jsonrpc":"2.0","id":42,"method":"tools/list"}"#;
    let req: controller::mcp::JsonRpcRequest = serde_json::from_str(raw).unwrap();
    assert_eq!(req.id, Some(json!(42)));
}

// ---------------------------------------------------------------------------
// JsonRpcResponse serialization
// ---------------------------------------------------------------------------

#[test]
fn json_rpc_response_omits_null_error() {
    let resp = controller::mcp::JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(1)),
        result: Some(json!({"ok": true})),
        error: None,
    };
    let json_str = serde_json::to_string(&resp).unwrap();
    assert!(
        !json_str.contains("\"error\""),
        "null error should be omitted via skip_serializing_if"
    );
}

#[test]
fn json_rpc_response_omits_null_result() {
    let resp = controller::mcp::JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(1)),
        result: None,
        error: Some(controller::mcp::JsonRpcError {
            code: -32601,
            message: "Method not found".to_string(),
            data: None,
        }),
    };
    let json_str = serde_json::to_string(&resp).unwrap();
    assert!(
        !json_str.contains("\"result\""),
        "null result should be omitted"
    );
    assert!(json_str.contains("\"error\""));
}

// ---------------------------------------------------------------------------
// JsonRpcError serialization
// ---------------------------------------------------------------------------

#[test]
fn json_rpc_error_serializes_correctly() {
    let err = controller::mcp::JsonRpcError {
        code: -32602,
        message: "Invalid params".to_string(),
        data: Some(json!({"details": "missing field"})),
    };
    let val = serde_json::to_value(&err).unwrap();
    assert_eq!(val["code"], -32602);
    assert_eq!(val["message"], "Invalid params");
    assert!(val["data"].is_object());
}

#[test]
fn json_rpc_error_omits_null_data() {
    let err = controller::mcp::JsonRpcError {
        code: -32000,
        message: "Internal error".to_string(),
        data: None,
    };
    let json_str = serde_json::to_string(&err).unwrap();
    assert!(
        !json_str.contains("\"data\""),
        "null data should be omitted"
    );
}

// ---------------------------------------------------------------------------
// Round-trip: request -> serialize -> deserialize
// ---------------------------------------------------------------------------

#[test]
fn json_rpc_request_round_trips() {
    let original = controller::mcp::JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!("test-id")),
        method: "tools/call".to_string(),
        params: Some(json!({"name": "my_tool", "arguments": {"key": "value"}})),
    };
    let serialized = serde_json::to_string(&original).unwrap();
    let deserialized: controller::mcp::JsonRpcRequest = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized.jsonrpc, original.jsonrpc);
    assert_eq!(deserialized.method, original.method);
    assert_eq!(deserialized.id, original.id);
    assert_eq!(deserialized.params, original.params);
}

// ---------------------------------------------------------------------------
// Note on dependency allowlist and rate limiter tests
// ---------------------------------------------------------------------------
// The following features are comprehensively tested in the internal unit test
// module at controller/src/mcp/tests.rs:
//
// - validate_deps_accepts_approved_crate
// - validate_deps_accepts_all_default_allowed_crates
// - validate_deps_rejects_unapproved_crate
// - validate_deps_rejects_wildcard_version
// - validate_deps_rejects_empty_version
// - validate_deps_is_case_insensitive_for_crate_names
// - rate_limiter_allows_requests_under_limit
// - rate_limiter_blocks_requests_over_limit
// - rate_limiter_tracks_agents_independently
// - rate_limiter_resets_after_window_expires
