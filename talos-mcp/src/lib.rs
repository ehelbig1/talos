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

/// What an error response MEANT, carried OUT OF BAND.
///
/// # The constraint this type exists to satisfy
///
/// The OPERATOR needs to tell a refusal from a failure; the CALLER must not
/// be given the same distinction. `"Actor not found or access denied"` is one
/// sentence on purpose — a reply that split "no such actor" from "not yours"
/// would hand anyone who can guess a uuid an existence oracle, and CLAUDE.md
/// records that argument three times (`resolve_actor_via_repo`,
/// `caller_facing_unauthorized`, #754's collapsed `write_ceiling_unreadable`).
/// The wire code cannot carry the distinction either: measured on this tree,
/// `-32000` has 648 sites carrying both meanings, and `-32601`, `-32603` and
/// `-32004` are mixed too.
///
/// So the meaning travels on the RESPONSE VALUE and never on the wire. The
/// field is `#[serde(skip)]`, which is why this is the shape that was taken
/// over a task-local (which a `tokio::spawn` loses and a
/// constructed-then-discarded refusal mislabels) and over a reserved key
/// inside `result` stripped at the chokepoint (which rests on the strip
/// running, i.e. on discipline). Here a leak is not expressible.
///
/// Absence is a real third state and means *no site said*: the response is
/// then classified from its code exactly as it was before this type existed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum McpErrorKind {
    /// The platform refused this well-formed request: an authorization or
    /// capability-ceiling denial, an org-membership refusal, a lifecycle or
    /// policy state that forbids the action, or the deliberately COLLAPSED
    /// "not found or access denied" — one label for the one sentence, since
    /// splitting it in the instrument would be the same oracle one surface
    /// over if the label ever reached a reply.
    Denied,
    /// The named row is not there, with no tenancy question attached. A `get`
    /// on something never created is the normal path, not a finding —
    /// `RpcOutcome::NotFound => Declined` (#787) is the precedent.
    NotFound,
    /// The platform could not serve the call. Stated EXPLICITLY rather than
    /// left to the code, at sites whose code would otherwise classify them as
    /// a refusal.
    Failed,
}

impl McpErrorKind {
    /// Every variant, for tests and for anything that must enumerate them.
    pub const ALL: &'static [Self] = &[Self::Denied, Self::NotFound, Self::Failed];
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
    /// What the constructing site MEANT, for the instrument only. NEVER
    /// serialized, never deserialized, never rendered to a caller — see
    /// [`McpErrorKind`]. `None` is "no site said".
    #[serde(skip)]
    pub error_kind: Option<McpErrorKind>,
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
    build_error(id, code, msg, None)
}

/// Build an MCP-style error response that ALSO tells the instrument what it
/// meant — see [`McpErrorKind`].
///
/// The wire output is BYTE-IDENTICAL to [`mcp_error`] with the same
/// arguments, and that is structural rather than a promise: both go through
/// the one private [`build_error`] body, so there is no second literal to
/// drift. `mcp_error_kind_matches_mcp_error_byte_for_byte` drives all three
/// kinds through `serde_json::to_string` and compares.
#[must_use]
pub fn mcp_error_kind(
    id: Option<serde_json::Value>,
    code: i32,
    kind: McpErrorKind,
    msg: &str,
) -> JsonRpcResponse {
    build_error(id, code, msg, Some(kind))
}

/// [`mcp_error_kind`] with [`McpErrorKind::Denied`]. Same bytes as
/// [`mcp_error`]; the spelling exists so a refusal site reads as one.
#[must_use]
#[inline]
pub fn mcp_denied(id: Option<serde_json::Value>, code: i32, msg: &str) -> JsonRpcResponse {
    build_error(id, code, msg, Some(McpErrorKind::Denied))
}

/// [`mcp_error_kind`] with [`McpErrorKind::NotFound`].
#[must_use]
#[inline]
pub fn mcp_not_found(id: Option<serde_json::Value>, code: i32, msg: &str) -> JsonRpcResponse {
    build_error(id, code, msg, Some(McpErrorKind::NotFound))
}

/// [`mcp_error_kind`] with [`McpErrorKind::Failed`] — for a site whose CODE
/// would otherwise classify it as a refusal.
#[must_use]
#[inline]
pub fn mcp_failed(id: Option<serde_json::Value>, code: i32, msg: &str) -> JsonRpcResponse {
    build_error(id, code, msg, Some(McpErrorKind::Failed))
}

/// The ONE body every error response is built from.
///
/// Every constructor above differs only in the `kind` it passes, so the
/// serialized bytes cannot diverge between a classified site and an
/// unclassified one — the invariant package 35 had to hold.
fn build_error(
    id: Option<serde_json::Value>,
    code: i32,
    msg: &str,
    kind: Option<McpErrorKind>,
) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id,
        result: Some(serde_json::json!({
            "content": [{ "type": "text", "text": msg }],
            "isError": true,
            "errorCode": code
        })),
        error: None,
        error_kind: kind,
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
        error_kind: None,
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

    /// THE WIRE-BYTE PIN.
    ///
    /// Written BEFORE the out-of-band classification of package 35 so it can
    /// prove the bytes did not move, and kept afterwards as the guard on the
    /// invariant that made that change shippable: **an MCP client sees exactly
    /// what it saw before.** The operator gains the refusal-vs-failure split;
    /// the caller must not, because a reply that distinguishes "no such actor"
    /// from "not yours" hands anyone who can guess a uuid an existence oracle
    /// (CLAUDE.md records that argument at `resolve_actor_via_repo`, at
    /// `caller_facing_unauthorized`, and at #754's collapsed
    /// `write_ceiling_unreadable`).
    ///
    /// Asserted on the SERIALIZED string, not on the struct: a field that is
    /// `#[serde(skip)]` is invisible here by construction, and a field that
    /// stopped being skipped would appear in these literals.
    #[test]
    fn the_serialized_reply_bytes_are_pinned() {
        let cases: Vec<(JsonRpcResponse, &str)> = vec![
            (
                mcp_error(
                    Some(serde_json::json!(1)),
                    -32000,
                    "Actor not found or access denied",
                ),
                r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"text":"Actor not found or access denied","type":"text"}],"errorCode":-32000,"isError":true}}"#,
            ),
            (
                mcp_error(
                    Some(serde_json::json!(1)),
                    -32000,
                    "Failed to fetch workflow",
                ),
                r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"text":"Failed to fetch workflow","type":"text"}],"errorCode":-32000,"isError":true}}"#,
            ),
            (
                mcp_error(
                    Some(serde_json::json!("req-9")),
                    -32003,
                    "Unauthorized: get_system_health requires admin capability",
                ),
                r#"{"jsonrpc":"2.0","id":"req-9","result":{"content":[{"text":"Unauthorized: get_system_health requires admin capability","type":"text"}],"errorCode":-32003,"isError":true}}"#,
            ),
            (
                mcp_error(None, -32602, "missing 'workflow_id'"),
                r#"{"jsonrpc":"2.0","id":null,"result":{"content":[{"text":"missing 'workflow_id'","type":"text"}],"errorCode":-32602,"isError":true}}"#,
            ),
            (
                mcp_text(Some(serde_json::json!(2)), "{\"ok\":true}"),
                r#"{"jsonrpc":"2.0","id":2,"result":{"content":[{"text":"{\"ok\":true}","type":"text"}]}}"#,
            ),
        ];
        for (resp, expected) in cases {
            let rendered = serde_json::to_string(&resp).expect("serialize");
            assert_eq!(
                rendered, expected,
                "the reply bytes moved — an MCP client sees a different response"
            );
        }
    }

    /// The invariant, asserted on BYTES rather than on the struct: a
    /// classified refusal and an unclassified one are the same reply.
    #[test]
    fn mcp_error_kind_matches_mcp_error_byte_for_byte() {
        let msg = "Workflow not found or access denied";
        let plain = serde_json::to_string(&mcp_error(Some(serde_json::json!(3)), -32000, msg))
            .expect("serialize");
        for kind in McpErrorKind::ALL {
            let classified = serde_json::to_string(&mcp_error_kind(
                Some(serde_json::json!(3)),
                -32000,
                *kind,
                msg,
            ))
            .expect("serialize");
            assert_eq!(
                classified, plain,
                "{kind:?} changed the reply bytes — the caller must not be able \
                 to tell a classified refusal from an unclassified one"
            );
        }
        // The three spellings are the same function with the kind fixed.
        for (built, kind) in [
            (mcp_denied(None, -32000, msg), McpErrorKind::Denied),
            (mcp_not_found(None, -32000, msg), McpErrorKind::NotFound),
            (mcp_failed(None, -32000, msg), McpErrorKind::Failed),
        ] {
            assert_eq!(built.error_kind, Some(kind));
            assert_eq!(
                serde_json::to_string(&built).expect("serialize"),
                serde_json::to_string(&mcp_error(None, -32000, msg)).expect("serialize")
            );
        }
    }

    /// The kind is out of band in BOTH directions: it never serializes, and a
    /// response parsed off the wire carries `None` rather than inventing one.
    #[test]
    fn the_kind_never_crosses_the_wire() {
        let sent = mcp_denied(Some(serde_json::json!(1)), -32000, "denied");
        let rendered = serde_json::to_string(&sent).expect("serialize");
        assert!(
            !rendered.contains("error_kind") && !rendered.contains("Denied"),
            "the classification reached the wire: {rendered}"
        );
        let parsed: JsonRpcResponse = serde_json::from_str(&rendered).expect("parse");
        assert_eq!(parsed.error_kind, None);
    }

    #[test]
    fn round_trip_request() {
        let json = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}"#;
        let req: JsonRpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.method, "tools/call");
    }
}
