//! The closed label set for the MCP `tools/call` instrument (2026-09-08,
//! extended 2026-09-09).
//!
//! Three decisions live here. Two are about what a caller can make the
//! controller export; the third is about what the controller can say about
//! the caller WITHOUT saying it to the caller.
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
//! **…and the SHAPE is not enough on its own, so the site may state what it
//! meant.** The wire code is the only thing the shape carries, and measured
//! on this tree `-32000` (648 sites), `-32601`, `-32603` and `-32004` each
//! carry BOTH a refusal and a failure. The site says which through
//! [`talos_mcp::McpErrorKind`], which never reaches the wire — the reply for
//! `"Actor not found or access denied"` is deliberately collapsed and must
//! stay so. Absence of a statement is a real third value and falls back to
//! the code table, whose default is the LOUD one.
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

use talos_mcp::{JsonRpcResponse, McpErrorKind};
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

/// The site's own statement, mapped to the outcome label.
///
/// Exhaustive by construction: a fourth [`McpErrorKind`] cannot be added
/// without deciding here what it records as.
#[must_use]
const fn outcome_for_kind(kind: McpErrorKind) -> McpToolOutcome {
    match kind {
        McpErrorKind::Denied => McpToolOutcome::Denied,
        McpErrorKind::NotFound => McpToolOutcome::NotFound,
        McpErrorKind::Failed => McpToolOutcome::Error,
    }
}

/// Classify one `tools/call` response into the closed outcome set.
///
/// Shape first, then two sources in a fixed order.
///
/// `mcp_error` renders a refusal INSIDE `result` (`isError: true`, the
/// JSON-RPC code preserved as `errorCode`) rather than in the JSON-RPC
/// `error` member — the MCP tool-error convention — so reading `resp.error`
/// alone would classify all ~1590 error sites in this crate as `ok`.
///
/// A response carrying NEITHER member is malformed and classified `Error`,
/// never `Ok`: an unclassifiable answer is not a successful one (check 77's
/// rule for `__error`, applied to the response envelope).
///
/// # Why the code alone cannot do this (measured, 2026-09-09)
///
/// `scripts/mcp-error-inventory.py` walks every `mcp_error` argument list
/// with comments and string content masked first. Of the **1590** production
/// call sites, **648** are `-32000`, and that code carries `"Workflow not
/// found or access denied"` (123 sites in that family) beside `"Failed to
/// fetch workflow"`. Three more codes are mixed the same way: **11 of 12**
/// `-32601` sites are platform-admin refusals, **7 of 15** `-32603` sites are
/// capability-ceiling refusals, and BOTH `-32004` sites carry both arms of
/// one helper. Re-assigning codes is not available either — the reply bytes
/// are an interface MCP clients may depend on, and the "not found or access
/// denied" collapse is a deliberate anti-enumeration property that must not
/// be split in a reply.
///
/// So the SITE says what it meant, out of band, via
/// [`JsonRpcResponse::error_kind`], and that statement WINS over the code.
/// The code table below is the fallback for the 1363 sites that carry no
/// statement — 883 of them `-32602`, which the table answers correctly — and
/// its default is the LOUD one: a site nobody has read is not evidence the
/// caller was at fault.
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
        // Deliberately BEFORE the kind is read: a success response carrying
        // a stale kind (a handler that built a refusal, discarded it and
        // reused the envelope) must still record `ok`.
        return McpToolOutcome::Ok;
    }
    if let Some(kind) = resp.error_kind {
        return outcome_for_kind(kind);
    }
    match result.get("errorCode").and_then(serde_json::Value::as_i64) {
        // -32601 MethodNotFound: the ONE site that means it is
        // `handle_tools_call_inner`'s tail. The eleven platform-admin
        // refusals that also use this code say `Denied` explicitly above.
        Some(-32601) => McpToolOutcome::UnknownTool,
        // -32602 InvalidParams: the caller can fix it. 883 of this crate's
        // `mcp_error` sites use this code (NOT the 411 this comment used to
        // claim — that number came from a single-line regex and the house
        // call style breaks the call across lines); folding them into `error`
        // would make a client looping on a typo indistinguishable from an
        // outage.
        Some(-32602) => McpToolOutcome::Refused,
        // Codes whose whole population is a refusal, verified site by site
        // with the inventory — so these need no per-site statement and
        // changed no reply. -32003 (13 sites: admin capability, capability
        // ceiling, org membership, a workflow that is not dispatchable),
        // -32001 (2: "requires an authenticated user context"), -32002 (1:
        // "Actor not found, not active, or belongs to a different user"),
        // -32600 (1: "Agent must have a bound user_id").
        //
        // This is a statement about TODAY's population, which is why
        // `McpErrorKind::Failed` exists: a future failure on one of these
        // codes says so at the site rather than needing this table changed.
        Some(-32003 | -32002 | -32001 | -32600) => McpToolOutcome::Denied,
        // -32000 (648 sites), -32603 (15), -32004 (2) and anything else are
        // UNCLASSIFIED, and unclassified records as `error`. Deliberately the
        // loud default: a code nobody has read is not evidence the caller was
        // at fault. Roughly 250 of the -32000 sites are in fact refusals and
        // are counted, by file, in this package's notes.
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
    use talos_mcp::{mcp_denied, mcp_error, mcp_failed, mcp_not_found, mcp_text, JsonRpcError};

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
                error_kind: None,
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
                error_kind: None,
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
    fn the_outcome_label_set_is_six_closed_values() {
        let values: Vec<&str> = McpToolOutcome::ALL.iter().map(|o| o.as_str()).collect();
        assert_eq!(
            values,
            [
                "ok",
                "refused",
                "unknown_tool",
                "denied",
                "not_found",
                "error"
            ]
        );
    }

    /// The SITE's statement wins over the code. This is the whole mechanism:
    /// `-32000` cannot classify itself, so the handler says what it meant.
    #[test]
    fn the_sites_own_statement_overrides_the_code() {
        // The live C1 case: a capability refusal that USED to record `error`.
        assert_eq!(
            classify_outcome(&mcp_error(
                None,
                -32003,
                "Unauthorized: get_system_health requires admin capability"
            )),
            McpToolOutcome::Denied,
            "-32003's whole population is refusals, so the code alone suffices \
             there and no site had to change"
        );
        // The two arms of one ownership gate, on ONE code, with ONE reply
        // shape. Nothing but the out-of-band kind can separate them.
        assert_eq!(
            classify_outcome(&mcp_denied(
                None,
                -32000,
                "Actor not found or access denied"
            )),
            McpToolOutcome::Denied
        );
        assert_eq!(
            classify_outcome(&mcp_failed(
                None,
                -32000,
                "Could not verify actor ownership — the actor registry is unavailable."
            )),
            McpToolOutcome::Error
        );
        assert_eq!(
            classify_outcome(&mcp_not_found(
                None,
                -32000,
                "Node 'x' not found in workflow"
            )),
            McpToolOutcome::NotFound
        );
        // A platform-admin refusal that used to record `unknown_tool`.
        assert_eq!(
            classify_outcome(&mcp_denied(
                None,
                -32601,
                "query_paginated requires platform-admin privileges."
            )),
            McpToolOutcome::Denied
        );
        // …while the ONE site that really means it still does.
        assert_eq!(
            classify_outcome(&mcp_error(None, -32601, "Unknown tool: 'x'")),
            McpToolOutcome::UnknownTool
        );
    }

    /// A kind on a SUCCESS response must not be honoured. The shape check
    /// runs first, so a handler that built a refusal, discarded it and reused
    /// the envelope cannot record its call as declined.
    #[test]
    fn a_kind_on_a_success_response_is_ignored() {
        let mut ok = mcp_text(None, "{}");
        ok.error_kind = Some(McpErrorKind::Denied);
        assert_eq!(classify_outcome(&ok), McpToolOutcome::Ok);
    }

    /// The kind → outcome mapping, pinned by NAME. Exhaustive over the enum,
    /// so a fourth kind cannot be added without deciding what it records as.
    #[test]
    fn every_kind_maps_to_the_outcome_that_was_argued() {
        let pairs: Vec<(&str, &str)> = McpErrorKind::ALL
            .iter()
            .map(|k| {
                (
                    match k {
                        McpErrorKind::Denied => "Denied",
                        McpErrorKind::NotFound => "NotFound",
                        McpErrorKind::Failed => "Failed",
                    },
                    outcome_for_kind(*k).as_str(),
                )
            })
            .collect();
        assert_eq!(
            pairs,
            vec![
                ("Denied", "denied"),
                ("NotFound", "not_found"),
                ("Failed", "error"),
            ]
        );
    }

    /// The class partition reaching THIS surface, pinned by name here too —
    /// `talos_metrics::mcp` owns the table, and this asserts that the
    /// classifier's answers land where the operator expects.
    #[test]
    fn a_refusal_classes_declined_and_a_failure_classes_finding() {
        use talos_metrics::OutcomeClass;
        for (resp, class) in [
            (
                mcp_denied(None, -32000, "Workflow not found or access denied"),
                OutcomeClass::Declined,
            ),
            (
                mcp_error(None, -32602, "missing 'workflow_id'"),
                OutcomeClass::Declined,
            ),
            (
                mcp_not_found(None, -32000, "Node 'x' not found in workflow"),
                OutcomeClass::Declined,
            ),
            (
                mcp_error(None, -32601, "Unknown tool: 'x'"),
                OutcomeClass::Declined,
            ),
            (
                mcp_error(None, -32000, "Failed to fetch workflow"),
                OutcomeClass::Finding,
            ),
            (mcp_text(None, "{}"), OutcomeClass::Served),
        ] {
            assert_eq!(classify_outcome(&resp).class(), class);
        }
    }
}
