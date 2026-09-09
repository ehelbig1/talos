//! The closed label set for the MCP `tools/call` instrument (2026-09-08).
//!
//! Two decisions live here, and both are about what a caller can make the
//! controller export.
//!
//! **The `tool` label is never the caller's string.** `params.name` arrives
//! from the wire; a `CounterVec`/`HistogramVec` keyed on it grows one series
//! per distinct value, so anyone who can reach `/mcp` could mint unbounded
//! series in the controller's registry and in every Prometheus that scrapes
//! it. That is check 58's rule ("any caller-derived label value is an
//! unbounded-cardinality DoS surface"). [`canonical_tool_label`] therefore
//! RESOLVES the request's name against the static tool-schema registry and
//! returns a `&'static str` **borrowed from that registry**, or one of two
//! `const` sentinels. The returned pointer is never derived from the input:
//! `an_unrecognised_name_records_under_one_shared_pointer` asserts that two
//! different unknown names return the SAME pointer, which is the property that
//! bounds the series count at 1 for the whole unrecognised population.
//!
//! **The `outcome` label is decided from the response SHAPE**, not from the
//! handler that produced it — [`classify_outcome`]. The handler tree is 21
//! `dispatch` functions and ~320 arms; a per-handler decision would be 320
//! places to forget. The response is one value with one shape.
//!
//! # Stated blind spot, measured rather than implied
//!
//! The registry this borrows from is the ADVERTISED set —
//! [`crate::tool_hints::declared_tool_params`], built from the same
//! `tool_schemas()` functions `tools/list` renders. Measured on this tree,
//! **29** identifier-shaped names appear in a `dispatch` body and in no
//! schema: the deprecated `agent_*` aliases (`agent_recall`, `create_agent`,
//! `list_agents`, …) and a handful of unadvertised siblings
//! (`bulk_tag_workflows`, `get_workflow_summary`, `get_workflow_topology`, …).
//! A call to one of those is instrumented — its latency and outcome are
//! recorded — under `unknown`, not under its own name. That is a deliberate
//! trade: the alternative is a hand-maintained alias list, which is the rot
//! mode check 74's name glob and check 64's runner list already cost this
//! repo. A client that discovered its tools from `tools/list` cannot reach
//! any of the 29.

use talos_mcp::JsonRpcResponse;
use talos_metrics::McpToolOutcome;

/// The one label value for every name no schema advertises.
///
/// A `const`, so every unrecognised name yields the same pointer and the same
/// series — the whole point of the type being `&'static str`.
pub const TOOL_LABEL_UNKNOWN: &str = "unknown";

/// The one label value for a `*-v1` catalog-template invocation.
///
/// `handle_tools_call`'s tail routes any `-v1` name to
/// `install_module_from_catalog`, and the catalog is DATA — its contents are
/// rows, not literals in this binary — so a catalog name is as
/// caller-influenced as any other string and must not be a label. One fixed
/// value for the whole class keeps "a catalog template was invoked"
/// distinguishable from "nobody recognised this name" at a cardinality of 1.
pub const TOOL_LABEL_CATALOG_TEMPLATE: &str = "catalog_template";

/// Resolve a request's tool name to a label value from the closed set.
///
/// Returns a `&'static str` that is either a KEY of the static tool-schema
/// registry (process-lifetime, built once from the `tool_schemas()`
/// functions) or one of the two sentinels above. It never returns anything
/// derived from `name`.
#[must_use]
pub fn canonical_tool_label(name: &str) -> &'static str {
    // `declared_tool_params()` is `&'static`, so the borrowed key is too —
    // no interning table and no `Box::leak` is needed, and the set cannot
    // grow at runtime because the map is built once from static literals.
    if let Some((advertised, _)) = crate::tool_hints::declared_tool_params().get_key_value(name) {
        return advertised.as_str();
    }
    if name.ends_with("-v1") {
        return TOOL_LABEL_CATALOG_TEMPLATE;
    }
    TOOL_LABEL_UNKNOWN
}

/// Classify one `tools/call` response into the closed outcome set.
///
/// Shape only. `mcp_error` renders a refusal INSIDE `result`
/// (`isError: true`, the JSON-RPC code preserved as `errorCode`) rather than
/// in the JSON-RPC `error` member — the MCP tool-error convention — so
/// reading `resp.error` alone would classify all ~820 refusal sites in this
/// crate as `ok`.
///
/// A response carrying NEITHER member is malformed and classified `Error`,
/// never `Ok`: an unclassifiable answer is not a successful one (check 77's
/// rule for `__error`, applied to the response envelope).
#[must_use]
pub fn classify_outcome(resp: &JsonRpcResponse) -> McpToolOutcome {
    if resp.error.is_some() {
        return McpToolOutcome::Error;
    }
    let Some(result) = resp.result.as_ref() else {
        return McpToolOutcome::Error;
    };
    if !result
        .get("isError")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        return McpToolOutcome::Ok;
    }
    match result.get("errorCode").and_then(serde_json::Value::as_i64) {
        // -32601 MethodNotFound: no dispatch arm claimed the name.
        Some(-32601) => McpToolOutcome::UnknownTool,
        // -32602 InvalidParams: the caller can fix it. 411 of this crate's
        // `mcp_error` sites use this code; folding them into `error` would
        // make a client looping on a typo indistinguishable from an outage.
        Some(-32602) => McpToolOutcome::Refused,
        // -32000 (409 sites), -32603, -32003, -32004 and anything else are
        // server-side. Unknown codes land here deliberately: a code nobody
        // classified is not evidence the caller was at fault.
        _ => McpToolOutcome::Error,
    }
}

/// A bounded rendering of the JSON-RPC request id for the per-call log line.
///
/// The id is caller-controlled and appears in a LOG FIELD (never a metric
/// label), but an unbounded one would still let a caller write arbitrarily
/// long lines into the controller's stdout, so it is capped at 64 chars on a
/// char boundary. Absent ids render `-` rather than an empty field.
#[must_use]
pub fn request_id_field(id: Option<&serde_json::Value>) -> String {
    const MAX: usize = 64;
    let raw = match id {
        None | Some(serde_json::Value::Null) => return "-".to_string(),
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    };
    if raw.chars().count() <= MAX {
        return raw;
    }
    let cut = raw
        .char_indices()
        .nth(MAX)
        .map(|(i, _)| i)
        .unwrap_or(raw.len());
    format!("{}…", &raw[..cut])
}

#[cfg(test)]
mod tests {
    use super::*;
    use talos_mcp::{mcp_error, mcp_text, JsonRpcError};

    #[test]
    fn every_advertised_tool_interns_to_the_registry_key() {
        let registry = crate::tool_hints::declared_tool_params();
        assert!(
            registry.len() > 200,
            "the static registry should carry the whole advertised surface, got {}",
            registry.len()
        );
        for name in registry.keys() {
            let label = canonical_tool_label(name);
            assert_eq!(label, name.as_str(), "label must be the tool's own name");
            // Pointer equality with the registry key: the label is BORROWED
            // from the process-lifetime map, not rebuilt from the request.
            assert!(
                std::ptr::eq(label.as_ptr(), name.as_str().as_ptr()),
                "{name} must borrow the registry key, not copy the caller's string"
            );
        }
    }

    #[test]
    fn an_unrecognised_name_records_under_one_shared_pointer() {
        // The cardinality guard. If a future edit passed the request's own
        // string through, these would be three DIFFERENT pointers and three
        // series; they must be one.
        let a = canonical_tool_label("definitely_not_a_tool");
        let b = canonical_tool_label("../../etc/passwd");
        let c = canonical_tool_label(&"x".repeat(4096));
        assert_eq!(a, TOOL_LABEL_UNKNOWN);
        assert_eq!(b, TOOL_LABEL_UNKNOWN);
        assert_eq!(c, TOOL_LABEL_UNKNOWN);
        assert!(std::ptr::eq(a.as_ptr(), b.as_ptr()));
        assert!(std::ptr::eq(b.as_ptr(), c.as_ptr()));
    }

    #[test]
    fn catalog_template_names_collapse_to_one_value() {
        let a = canonical_tool_label("Redis_Cache-v1");
        let b = canonical_tool_label("Whatever_The_Caller_Invented-v1");
        assert_eq!(a, TOOL_LABEL_CATALOG_TEMPLATE);
        assert_eq!(b, TOOL_LABEL_CATALOG_TEMPLATE);
        assert!(std::ptr::eq(a.as_ptr(), b.as_ptr()));
    }

    #[test]
    fn outcome_is_read_from_the_response_shape() {
        assert_eq!(
            classify_outcome(&mcp_text(None, "{}")),
            McpToolOutcome::Ok,
            "a plain text result is a success"
        );
        assert_eq!(
            classify_outcome(&mcp_error(None, -32601, "Unknown tool: 'x'")),
            McpToolOutcome::UnknownTool
        );
        assert_eq!(
            classify_outcome(&mcp_error(None, -32602, "missing 'workflow_id'")),
            McpToolOutcome::Refused
        );
        assert_eq!(
            classify_outcome(&mcp_error(None, -32000, "Database error")),
            McpToolOutcome::Error
        );
        assert_eq!(
            classify_outcome(&mcp_error(None, -32603, "internal")),
            McpToolOutcome::Error
        );
        // Neither member: malformed, and NOT `ok`.
        assert_eq!(
            classify_outcome(&JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: None,
                result: None,
                error: None,
            }),
            McpToolOutcome::Error
        );
        // A JSON-RPC error member (the transport-level shape).
        assert_eq!(
            classify_outcome(&JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: None,
                result: None,
                error: Some(JsonRpcError {
                    code: -32700,
                    message: "parse error".to_string(),
                    data: None,
                }),
            }),
            McpToolOutcome::Error
        );
    }

    #[test]
    fn the_request_id_field_is_bounded() {
        assert_eq!(request_id_field(None), "-");
        assert_eq!(request_id_field(Some(&serde_json::Value::Null)), "-");
        assert_eq!(request_id_field(Some(&serde_json::json!(7))), "7");
        assert_eq!(request_id_field(Some(&serde_json::json!("req-1"))), "req-1");
        let long = serde_json::json!("é".repeat(500));
        let rendered = request_id_field(Some(&long));
        assert!(
            rendered.chars().count() <= 65,
            "id field must be capped, got {} chars",
            rendered.chars().count()
        );
        assert!(rendered.ends_with('…'));
    }

    #[test]
    fn the_outcome_label_set_is_four_closed_values() {
        let values: Vec<&str> = McpToolOutcome::ALL.iter().map(|o| o.as_str()).collect();
        assert_eq!(values, ["ok", "error", "refused", "unknown_tool"]);
    }
}
