//! Pure helpers extracted from `handle_create_workflow` (controller/src/mcp/workflows.rs).
//!
//! Phase 1 of the refactor in MEMORY.md task #6 (2026-04-22). The helpers
//! are intentionally state-free — no `state: McpState` or DB pool — so
//! they're trivially unit-testable and can be reused by other create-style
//! handlers (e.g. `create_workflow_from_spec`, future template-instantiate
//! flows). Phase 2 will move stateful sub-operations (actor lookup, module
//! resolution) into a dedicated `WorkflowCreationService`.

use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

const STRUCTURAL_NODE_TYPES: &[&str] = &["collect", "loop", "sub_workflow", "capability_dispatch"];

/// Partition `nodes` into (structural, regular). A node is structural if
/// its `node_type` matches one of the built-in primitives (collect / loop /
/// sub_workflow / capability_dispatch); otherwise it's a regular module
/// node that needs a `module_id`.
pub fn partition_nodes_by_kind(nodes: &[Value]) -> (Vec<&Value>, Vec<&Value>) {
    nodes.iter().partition(|n| {
        n.get("node_type")
            .and_then(|v| v.as_str())
            .map(|t| STRUCTURAL_NODE_TYPES.contains(&t))
            .unwrap_or(false)
    })
}

/// Validate the `id` field on every node: ≤200 chars, ASCII alphanumeric +
/// `-`, `_`, `.` only. Returns the offending message on first failure.
/// Charset matches the `add_node_to_workflow` validator so the two paths
/// can't accept different IDs.
pub fn validate_node_ids(nodes: &[Value]) -> Result<(), String> {
    for node in nodes.iter() {
        if let Some(nid) = node.get("id").and_then(|v| v.as_str()) {
            if nid.len() > 200 {
                return Err(format!(
                    "node id '{}...' exceeds 200 characters",
                    &nid.chars().take(20).collect::<String>()
                ));
            }
            if !nid
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            {
                return Err(format!(
                    "node id '{}' may only contain ASCII alphanumeric characters, hyphens, underscores, and dots",
                    nid
                ));
            }
        }
    }
    Ok(())
}

/// Verify each regular (non-structural) node carries a parseable UUID
/// `module_id`. Catalog names and display names are NOT accepted here —
/// the caller must resolve them via `install_module_from_catalog` first.
/// Returns the offending message on first failure.
pub fn validate_regular_module_ids(regular_nodes: &[&Value]) -> Result<(), String> {
    for node in regular_nodes {
        let mid = node.get("module_id").and_then(|v| v.as_str()).unwrap_or("");
        if mid.is_empty() || uuid::Uuid::parse_str(mid).is_err() {
            let nid = node.get("id").and_then(|v| v.as_str()).unwrap_or("?");
            return Err(format!(
                "Invalid module_id '{}' on node '{}'. Must be a valid UUID from list_templates, or set node_type for structural nodes (collect, loop, sub_workflow, capability_dispatch).",
                talos_text_util::bounded_preview(mid, 64),
                talos_text_util::bounded_preview(nid, 64)
            ));
        }
    }
    Ok(())
}

/// MCP-1052 (2026-05-15): canonical capability-name predicate. Pre-fix
/// the `^[a-z0-9-]{1,50}$` regex was compiled inline at 3 production
/// sites (talos-mcp-handlers/src/graph.rs:3104,
/// talos-mcp-handlers/src/analytics.rs:4308, and this crate) — each
/// paying the regex-compile cost on first hit AND drifting if the
/// canonical shape changes. Same N-inline-copies class as MCP-1037
/// (validate_payload_size), MCP-1049 (validate_json_size), MCP-1050
/// (char-boundary walks), MCP-1051 (scrubber whitelist).
///
/// The matched shape is the contract that
/// `set_workflow_capabilities`, `capability_dispatch`, and the
/// upstream LLM-scaffold `validate_capabilities` array check all
/// agree on. Centralising the predicate ensures a future tightening
/// (e.g. require trailing alphanumeric, ban consecutive hyphens)
/// propagates everywhere.
pub fn is_valid_capability_name(name: &str) -> bool {
    static CAP_RE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"^[a-z0-9-]{1,50}$").expect("valid capability regex")
    });
    CAP_RE.is_match(name)
}

/// Validate the workflow's `capabilities` array: ≤20 items, each one
/// matching `^[a-z0-9-]{1,50}$`. Mirrors the regex enforced for capability
/// dispatch / `set_workflow_capabilities`.
pub fn validate_capabilities(capabilities: &[String]) -> Result<(), String> {
    if capabilities.len() > 20 {
        return Err("Maximum 20 capabilities allowed".to_string());
    }
    for cap in capabilities {
        if !is_valid_capability_name(cap) {
            return Err(format!(
                "Invalid capability '{}'. Must be lowercase alphanumeric + hyphens, 1-50 chars.",
                talos_text_util::bounded_preview(cap, 64)
            ));
        }
    }
    Ok(())
}

/// Validate the workflow's `intent` object — string fields ≤500 chars
/// AND non-empty/non-whitespace, total serialized size ≤10 KiB. The
/// 10 KiB cap matches what `set_workflow_intent` enforces.
///
/// MCP-193 (2026-05-08): pre-fix only `action` and `subject` were
/// length-checked, and even those accepted whitespace-only values.
/// `output_type` and `trigger_context` were unchecked entirely. The
/// intent surfaces in semantic search and the workflow summary, so
/// whitespace pollutes both with no signal to operators. Now: every
/// present string field must be non-whitespace and ≤500 chars; the
/// helper is the single source of truth used by create_workflow,
/// set_workflow_intent, AND publish_version.
pub fn validate_intent(intent: &Value) -> Result<(), String> {
    const ALLOWED_FIELDS: &[&str] = &["action", "subject", "output_type", "trigger_context"];
    // MCP-247 (2026-05-08): reject unknown fields. A real probe with
    // `intent: {"action": "watch", "subject": "endor-labs", "extra_field":
    // "should this be allowed?"}` persisted the extra_field on the
    // workflow's intent JSON — operator typos / stale schema fields
    // silently polluted the intent metadata. The schema documents
    // exactly four fields; anything else is malformed input. Reject
    // upfront with the offending field name so the operator can fix it.
    if let Some(obj) = intent.as_object() {
        for k in obj.keys() {
            if !ALLOWED_FIELDS.contains(&k.as_str()) {
                return Err(format!(
                    "intent has unknown field '{k}' — allowed fields: action, subject, output_type, trigger_context"
                ));
            }
        }
    }
    for field in ALLOWED_FIELDS {
        if let Some(s) = intent.get(field).and_then(|v| v.as_str()) {
            if s.trim().is_empty() {
                return Err(format!(
                    "intent.{field} must be non-empty and non-whitespace when provided"
                ));
            }
            // MCP-424 (2026-05-11): length check on TRIMMED value.
            // Pre-fix `s.len() > 500` used UNTRIMMED length, so a
            // 495-char visible value with 10 chars of padding bypassed
            // the gate even though the trimmed string (which is what
            // operators see in the UI) fits. Same trim-after-length-
            // check class as MCP-419/420.
            if s.trim().len() > 500 {
                return Err(format!("intent.{field} must be ≤ 500 characters"));
            }
            // MCP-424: control-char / null-byte check. intent fields
            // are persisted to the workflow's intent JSONB column and
            // surface in list_workflows / search_workflows / dashboard
            // views. `\0` in a field hits Postgres' "invalid byte
            // sequence for encoding UTF8" at the upsert with an
            // opaque error; control chars render unpredictably across
            // dashboards. Closes the gap in all three call sites
            // (create_workflow, set_workflow_intent, publish_version)
            // at once. Same defense-in-depth as MCP-422 on the
            // manifest path.
            if s.contains('\0') || s.chars().any(|c| c.is_control() && c != '\t') {
                return Err(format!(
                    "intent.{field} cannot contain control characters or null bytes"
                ));
            }
        }
    }
    let intent_len = intent.to_string().len();
    if intent_len > 10_000 {
        return Err("intent object must be ≤ 10000 characters when serialized".to_string());
    }
    Ok(())
}

/// Append `extra` edges to `existing` while skipping any whose
/// `(source, target)` pair already appears. Used when merging
/// `connect_from`/`connect_to`-derived edges into the user-supplied edges
/// array. Pure: the inputs are not mutated; a new vec is returned so the
/// extracted helper composes cleanly with iterator chains.
pub fn merge_edges_dedup(existing: Vec<Value>, extra: Vec<Value>) -> Vec<Value> {
    let mut existing_pairs: HashSet<(String, String)> = existing
        .iter()
        .map(|e| {
            (
                e.get("source")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                e.get("target")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            )
        })
        .collect();
    let mut out = existing;
    for edge in extra {
        let src = edge
            .get("source")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let tgt = edge
            .get("target")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let key = (src, tgt);
        if existing_pairs.insert(key) {
            out.push(edge);
        }
    }
    out
}

/// Validate every edge against the set of declared node IDs:
/// reject self-edges and edges whose source/target isn't a node in the
/// same `nodes[]` array. Returns the human-readable error message on
/// the first failure (matches the original handler's tip-bearing
/// wording verbatim — IDE/agent prompts depend on it).
///
/// Does NOT validate edge `condition` length — see
/// [`validate_edge_condition_lengths`].
pub fn validate_edge_targets(edges: &[Value], all_node_ids: &HashSet<&str>) -> Result<(), String> {
    for edge in edges {
        let src = edge.get("source").and_then(|v| v.as_str()).unwrap_or("");
        let tgt = edge.get("target").and_then(|v| v.as_str()).unwrap_or("");
        if src == tgt {
            return Err(format!(
                "Self-referencing edge: {} -> {}. Cycles are not allowed.",
                src, tgt
            ));
        }
        if !all_node_ids.contains(src) {
            return Err(format!(
                "Edge source '{}' does not match any node ID in this create_workflow call. \
                 Tip: edges can only reference nodes declared in the same nodes[] array. \
                 To add edges after nodes are created (e.g. for nodes added via add_node_to_workflow with rust_code), \
                 omit edges from create_workflow and call add_edge_to_workflow after all nodes are in place.",
                src
            ));
        }
        if !all_node_ids.contains(tgt) {
            return Err(format!(
                "Edge target '{}' does not match any node ID in this create_workflow call. \
                 Tip: edges can only reference nodes declared in the same nodes[] array. \
                 To add edges after nodes are created (e.g. for nodes added via add_node_to_workflow with rust_code), \
                 omit edges from create_workflow and call add_edge_to_workflow after all nodes are in place.",
                tgt
            ));
        }
    }
    Ok(())
}

/// Reject directed cycles across the full edge set.
///
/// `validate_edge_targets` only rejects the trivial self-edge case
/// (`n -> n`); a multi-node cycle (`a -> b -> a`) slips past it. The
/// workflow engine requires a DAG — `is_cyclic_directed` fails the run
/// with "workflow graph contains a cycle" — and both the `add_edge` and
/// from-description authoring paths already reject cycles up front. This
/// closes the gap on `create_workflow`, which otherwise persists an
/// unexecutable workflow whose only error surfaces at trigger time.
///
/// Pure (no `petgraph` dependency in this crate): iterative three-colour
/// DFS over an adjacency map keyed by node id. Only edges whose endpoints
/// are both declared nodes are considered — call AFTER
/// `validate_edge_targets`, which guarantees that.
pub fn validate_acyclic(edges: &[Value], node_ids: &HashSet<&str>) -> Result<(), String> {
    let mut adj: HashMap<String, Vec<String>> = HashMap::new();
    for edge in edges {
        let src = edge.get("source").and_then(|v| v.as_str()).unwrap_or("");
        let tgt = edge.get("target").and_then(|v| v.as_str()).unwrap_or("");
        if node_ids.contains(src) && node_ids.contains(tgt) {
            adj.entry(src.to_string())
                .or_default()
                .push(tgt.to_string());
        }
    }

    // colour: absent/0 = unvisited, 1 = on the current DFS path, 2 = done.
    // Iterative (explicit stack) so a pathological chain can't overflow.
    let mut color: HashMap<String, u8> = HashMap::new();
    for start in node_ids {
        if color.get(*start).copied().unwrap_or(0) != 0 {
            continue;
        }
        let mut stack: Vec<(String, usize)> = vec![(start.to_string(), 0)];
        color.insert(start.to_string(), 1);
        while let Some((node, idx)) = stack.last().map(|(n, i)| (n.clone(), *i)) {
            let next = adj.get(&node).and_then(|ch| ch.get(idx)).cloned();
            match next {
                Some(child) => {
                    stack.last_mut().unwrap().1 += 1;
                    match color.get(&child).copied().unwrap_or(0) {
                        1 => {
                            return Err(format!(
                                "Workflow graph contains a cycle involving node '{child}'. \
                                 Cycles are not allowed — the workflow engine requires a DAG.",
                            ));
                        }
                        0 => {
                            color.insert(child.clone(), 1);
                            stack.push((child, 0));
                        }
                        _ => {}
                    }
                }
                None => {
                    color.insert(node, 2);
                    stack.pop();
                }
            }
        }
    }
    Ok(())
}

/// Cap edge `condition` strings at 2000 characters. Long Rhai
/// expressions inflate `graph_json` rapidly and the engine truncates at
/// the same boundary; rejecting up-front gives a clearer error.
pub fn validate_edge_condition_lengths(edges: &[Value]) -> Result<(), String> {
    for e in edges {
        if let Some(cond) = e.get("condition").and_then(|v| v.as_str()) {
            if cond.len() > 2000 {
                return Err("Edge condition must be ≤ 2000 characters".to_string());
            }
        }
    }
    Ok(())
}

/// Build the `data` JSON for a structural node (`loop` / `sub_workflow`
/// / `capability_dispatch` / `collect`). Pure: only reads from the
/// input node — no side effects, no defaults beyond what the original
/// handler set.
///
/// Each variant accepts its parameters either at the top level of the
/// node OR nested under `node.config` — the closure-based getter
/// preserves the original handler's tolerant parsing.
pub fn build_structural_node_data(kind: &str, node: &Value) -> Value {
    let ncfg = node.get("config");
    let get_s = |k: &str| {
        node.get(k)
            .or_else(|| ncfg.and_then(|c| c.get(k)))
            .and_then(|v| v.as_str())
    };
    let get_u = |k: &str| {
        node.get(k)
            .or_else(|| ncfg.and_then(|c| c.get(k)))
            .and_then(|v| v.as_u64())
    };
    match kind {
        "loop" => serde_json::json!({
            "body_node_id": get_s("body_node_id").unwrap_or(""),
            "condition": get_s("condition").unwrap_or("true"),
            "max_iterations": get_u("max_iterations").unwrap_or(10),
        }),
        "sub_workflow" => serde_json::json!({
            "sub_workflow_id": get_s("sub_workflow_id").unwrap_or(""),
            "timeout_secs": get_u("timeout_secs").unwrap_or(60),
        }),
        "capability_dispatch" => {
            let caps = node
                .get("required_capabilities")
                .or_else(|| ncfg.and_then(|c| c.get("required_capabilities")))
                .cloned()
                .unwrap_or(serde_json::json!([]));
            serde_json::json!({
                "required_capabilities": caps,
                "timeout_secs": get_u("timeout_secs").unwrap_or(60),
            })
        }
        // collect (and any future variant we forgot to handle) → empty object.
        _ => serde_json::json!({}),
    }
}

/// Apply retry-policy fields to a regular module node's graph entry.
/// Resolution order per field, matching the original handler exactly:
///   1. node-level field (`retry_count` / `retry_backoff_ms` / etc.)
///   2. `default_retry_policy` fallback
///   3. (retry_count only) template's catalog `max_retries`, so catalog
///      modules with `max_retries=0` (e.g. human-approval) override the
///      engine's `unwrap_or(2)` default. Same pattern as
///      `add_node_to_workflow`.
pub fn apply_retry_policy(
    node_obj: &mut Map<String, Value>,
    input_node: &Value,
    default_retry: &Value,
    template_max_retries: Option<i32>,
) {
    if let Some(rc) = input_node
        .get("retry_count")
        .or_else(|| default_retry.get("retry_count"))
    {
        node_obj.insert("retry_count".to_string(), rc.clone());
    } else if let Some(mr) = template_max_retries {
        node_obj.insert("retry_count".to_string(), serde_json::json!(mr));
    }
    if let Some(rb) = input_node
        .get("retry_backoff_ms")
        .or_else(|| default_retry.get("retry_backoff_ms"))
    {
        node_obj.insert("retry_backoff_ms".to_string(), rb.clone());
    }
    if let Some(rcond) = input_node
        .get("retry_condition")
        .or_else(|| default_retry.get("retry_condition"))
    {
        node_obj.insert("retry_condition".to_string(), rcond.clone());
    }
    if let Some(rde) = input_node
        .get("retry_delay_expression")
        .or_else(|| default_retry.get("retry_delay_expression"))
    {
        node_obj.insert("retry_delay_expression".to_string(), rde.clone());
    }
}

/// Extract `connect_from` / `connect_to` shorthand on a single input
/// node into explicit `(source, target)` edges. Returns the edges in
/// declaration order: `connect_from` first (those edges have the
/// current node as `target`), then `connect_to` (current node as
/// `source`). Original handler iterated in this order; preserved so
/// downstream dedup is deterministic.
pub fn extract_connect_edges(input_node: &Value, node_id: &str) -> Vec<Value> {
    let mut out = Vec::new();
    if let Some(from_arr) = input_node.get("connect_from").and_then(|v| v.as_array()) {
        for src in from_arr {
            if let Some(src_str) = src.as_str() {
                out.push(serde_json::json!({
                    "source": src_str,
                    "target": node_id,
                }));
            }
        }
    }
    if let Some(to_arr) = input_node.get("connect_to").and_then(|v| v.as_array()) {
        for tgt in to_arr {
            if let Some(tgt_str) = tgt.as_str() {
                out.push(serde_json::json!({
                    "source": node_id,
                    "target": tgt_str,
                }));
            }
        }
    }
    out
}

/// Build a single graph node entry. Returns `(node_json, connect_edges)`
/// — the connect_from/connect_to shorthand on this node is harvested
/// inline so the caller doesn't have to walk the input twice.
///
/// `y_offset` is read+mutated only when this node lacks an explicit
/// `position.y`. The original handler advanced the cursor by 120.0 per
/// node-without-position, regardless of where that node fell in the
/// input order; preserved verbatim.
pub fn build_graph_node(
    input_node: &Value,
    default_retry: &Value,
    template_max_retries_map: &HashMap<Uuid, i32>,
    y_offset: &mut f64,
) -> (Value, Vec<Value>) {
    let node_id = input_node
        .get("id")
        .and_then(|v| v.as_str())
        .unwrap_or("node-1");
    let pos_x = input_node
        .get("position")
        .and_then(|p| p.get("x"))
        .and_then(|x| x.as_f64())
        .unwrap_or(250.0);
    let pos_y = input_node
        .get("position")
        .and_then(|p| p.get("y"))
        .and_then(|y| y.as_f64())
        .unwrap_or_else(|| {
            *y_offset += 120.0;
            *y_offset
        });

    let node_type_str = input_node
        .get("node_type")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let node_json = if STRUCTURAL_NODE_TYPES.contains(&node_type_str) {
        let kind = node_type_str;
        let sys_type = format!("system:{}", kind);
        let data = build_structural_node_data(kind, input_node);
        serde_json::json!({
            "id": node_id,
            "type": sys_type,
            "kind": kind,
            "position": { "x": pos_x, "y": pos_y },
            "data": data,
        })
    } else {
        let mut node_json = serde_json::json!({
            "id": node_id,
            "type": input_node.get("module_id").and_then(|v| v.as_str()).unwrap_or(""),
            "position": { "x": pos_x, "y": pos_y },
            "data": input_node.get("config").cloned().unwrap_or(serde_json::json!({})),
        });
        if let Some(obj) = node_json.as_object_mut() {
            let template_max_retries = input_node
                .get("module_id")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<Uuid>().ok())
                .and_then(|uid| template_max_retries_map.get(&uid).copied());
            apply_retry_policy(obj, input_node, default_retry, template_max_retries);
        }
        node_json
    };

    let connect_edges = extract_connect_edges(input_node, node_id);
    (node_json, connect_edges)
}

/// Detect the "tool-call XML leaked into a free-text field" failure
/// mode and reject the input loudly. Triggered when an MCP client (or
/// a script constructing the JSON-RPC payload) emits Anthropic-format
/// tool-call XML and a buggy parser captures the wrong scope,
/// embedding `</description>` + a follow-on `<parameter name="...">VALUE`
/// into the description string instead of parsing each `<parameter>`
/// as a separate JSON argument.
///
/// Real prod incident (2026-04-29): discovery-call-synthesizer was
/// created with
/// `description = "...accumulating, queryable signal.</description>\n<parameter name=\"actor_id\">7554e278-..."`.
/// The intended `actor_id` parameter never bound — `workflow.actor_id`
/// stayed NULL — and `__memory_write__` envelopes silently dropped on
/// every trigger that didn't pass actor_id explicitly. The artifact
/// also leaked a UUID into the human-facing description text. r237
/// added trigger-time validation for the symptom; this check defends
/// against the source.
///
/// Detection is intentionally narrow:
///   1. `</description>` — closing tag for the field itself; cannot
///      legitimately appear in a description's text content.
///   2. `<parameter name=` — Anthropic XML parameter open tag; high
///      precision because no human-written description should embed
///      tool-call syntax verbatim.
///
/// False-positive risk: a description that DOCUMENTS XML tool-call
/// syntax could trip this. Acceptable trade — that documentation
/// belongs in markdown elsewhere (README, docstrings), not in the
/// workflow's 2KB description field.
pub fn detect_tool_call_xml_leak(description: &str) -> Option<&'static str> {
    if description.contains("</description>") {
        return Some(
            "Description contains '</description>' — looks like an XML tool-call \
             parsing artifact where the next parameter spilled into the description \
             value. Use the proper top-level parameters (actor_id, etc.) instead of \
             embedding XML tool-call syntax in the description text.",
        );
    }
    // Anthropic-prefixed parameter open tag — same artifact class,
    // different layout.
    if description.contains("<parameter name=") {
        return Some(
            "Description contains '<parameter name=' — looks like an XML tool-call \
             parsing artifact (Anthropic-format) where a tool argument leaked into \
             the description value. Pass arguments via top-level parameters (actor_id, \
             etc.) instead of embedding tool-call XML in description text.",
        );
    }
    None
}

/// Result of validating a workflow description input.
#[derive(Debug, Default)]
pub struct ValidatedDescription {
    /// `Some(s)` for a non-empty trimmed string; `None` when the
    /// caller passed nothing or whitespace-only content.
    pub description: Option<String>,
    /// Set when the description ended up as `None` — semantic search
    /// won't surface this workflow without one. Verbatim string the
    /// original handler emitted; agents key off the prefix.
    pub semantic_search_warning: Option<&'static str>,
}

/// Validate the user-supplied workflow description and produce both
/// the trimmed value and a search-warning hint. Hard-error checks (in
/// the same order the original handler ran them):
///
///   1. Length cap (≤ 2000 characters).
///   2. Forbidden control characters: NUL, plus any `is_control()`
///      character other than tab/LF/CR. NUL bytes confuse Postgres'
///      text encoder; non-printable controls are leak / display-
///      corruption risks.
///   3. XML tool-call leak (see [`detect_tool_call_xml_leak`]).
///
/// On success: trims the input. Whitespace-only collapses to `None`
/// and surfaces the search-search warning so callers can guide the
/// operator to add a real description.
///
/// Pure: no I/O. Used by both `handle_create_workflow` and
/// `set_workflow_description`-style update paths.
pub fn validate_workflow_description(input: Option<&str>) -> Result<ValidatedDescription, String> {
    let Some(d) = input else {
        return Ok(ValidatedDescription {
            description: None,
            semantic_search_warning: Some(
                "No description provided. Semantic search (search_workflows, tool_search) will return poor results for this workflow. Set a description with update_workflow or recreate with a 'description' field.",
            ),
        });
    };

    // MCP-425 (2026-05-11): length check on TRIMMED value. Pre-fix
    // `d.len() > 2_000` used UNTRIMMED length, so a 1998-char visible
    // description with 5 chars of padding bypassed the gate even
    // though the trimmed string (which IS what persists at the end
    // of this function via `d.trim()`) fits. Consistency with the
    // post-trim persistence below; same trim-after-length-check
    // class as MCP-419/420/424.
    if d.trim().len() > 2_000 {
        return Err("Workflow description must be ≤ 2000 characters".to_string());
    }
    if d.contains('\0')
        || d.chars()
            .any(|c| c.is_control() && c != '\t' && c != '\n' && c != '\r')
    {
        return Err(
            "Workflow description cannot contain control characters or null bytes".to_string(),
        );
    }
    if let Some(reason) = detect_tool_call_xml_leak(d) {
        return Err(reason.to_string());
    }

    let trimmed = d.trim().to_string();
    if trimmed.is_empty() {
        Ok(ValidatedDescription {
            description: None,
            semantic_search_warning: Some(
                "No description provided. Semantic search (search_workflows, tool_search) will return poor results for this workflow. Set a description with update_workflow or recreate with a 'description' field.",
            ),
        })
    } else {
        Ok(ValidatedDescription {
            description: Some(trimmed),
            semantic_search_warning: None,
        })
    }
}

/// Inputs to [`build_create_workflow_response`]. Bundled in a single
/// struct so the function signature stays scannable and so future
/// fields land in one place rather than as positional arguments.
pub struct CreateResponseInputs {
    pub workflow_id: Uuid,
    pub workflow_name: String,
    pub node_count: usize,
    pub edge_count: usize,
    /// Rendered by `render_ascii_graph` upstream — the helper stays
    /// state-free and doesn't depend on the renderer's location.
    pub ascii_graph: String,
    pub ready_to_run: bool,
    /// True when the workflow was created with zero nodes — the
    /// engine will fail at dispatch with "graph load failed: Workflow
    /// has no nodes", so we guide the caller to add nodes first.
    pub graph_is_empty: bool,
    pub missing_config: Vec<Value>,
    pub required_secrets: HashSet<String>,
    pub vault_warnings: Vec<String>,
    /// Set when the workflow has no description — semantic search
    /// will return poor results without one.
    pub description_warning: Option<String>,
    /// Set when the chosen name collides with an existing workflow's
    /// search-text. Surfaced as `name_collision_warning` in the
    /// response so the caller can rename if desired.
    pub name_collision_warning: Option<String>,
}

/// Build the success-path JSON response for `create_workflow`.
///
/// Composes:
/// * Top-level fields (`workflow_id`, `name`, `status`, etc.).
/// * `next_steps` — a 1–3 line caller-facing summary that names the
///   single next move.
/// * `next_steps_checklist` — structured, monotonically-numbered
///   items the caller can iterate through. Order is stable: any
///   missing-config / required-secrets gating items first (when
///   present), then the standard four items (quickstart, call,
///   test, delta).
/// * Warnings (`semantic_search_warning`, `name_collision_warning`,
///   `warnings` array for vault paths) — all conditional, only
///   present when non-empty.
///
/// Pure: no I/O, no clock reads, no randomness. Output deterministic
/// for any given input. Test-coverage strategy is to assert each
/// optional surface independently so a future tweak to one branch
/// can't quietly drop another.
pub fn build_create_workflow_response(inputs: CreateResponseInputs) -> Value {
    let wf_id_str = inputs.workflow_id.to_string();
    let mut next_steps: Vec<String> = Vec::new();
    let mut next_steps_checklist: Vec<Value> = Vec::new();

    if !inputs.missing_config.is_empty() {
        next_steps.push(format!(
            "Set required config on {} node(s) using update_node_config or re-create with config fields populated.",
            inputs.missing_config.len()
        ));
        next_steps_checklist.push(serde_json::json!({
            "step": 1,
            "action": "Configure nodes",
            "tool": "update_node_config",
            "nodes_needing_config": &inputs.missing_config,
        }));
    }
    if !inputs.required_secrets.is_empty() {
        // MCP-1201 (2026-05-17): secret writes moved exclusively to the
        // GraphQL surface (require_2fa + SecretsWrite). Provisioning
        // happens in the dashboard (Settings → Secrets); the next-step
        // entry no longer references the deleted `set_secret` MCP tool.
        next_steps.push(
            "Provision required secrets in the dashboard (Settings → Secrets), then reference them in node config — secret writes require 2FA and aren't available through MCP."
                .to_string(),
        );
        next_steps_checklist.push(serde_json::json!({
            "step": next_steps_checklist.len() + 1,
            "action": "Provision secrets",
            "tool": null,
            "required_secrets": inputs.required_secrets.iter().collect::<Vec<_>>(),
        }));
    }
    next_steps_checklist.push(serde_json::json!({
        "step": next_steps_checklist.len() + 1,
        "action": "Full readiness check",
        "tool": format!("get_workflow_quickstart with workflow_id: {}", wf_id_str),
    }));
    next_steps_checklist.push(serde_json::json!({
        "step": next_steps_checklist.len() + 1,
        "action": "Test run (synchronous — returns inline result)",
        "tool": "call_workflow",
        "args": { "workflow_id": &wf_id_str },
        "note": "call_workflow waits for completion and returns the output inline. Use trigger_workflow for async fire-and-forget.",
    }));
    next_steps_checklist.push(serde_json::json!({
        "step": next_steps_checklist.len() + 1,
        "action": "Test with assertions (preferred for correctness)",
        "tool": "test_workflow",
        "args": {
            "workflow_id": &wf_id_str,
            "input": {},
            "assert_status": "completed",
        },
        "note": "test_workflow runs synchronously AND validates assertions (status, output, max duration). Use instead of call_workflow when output correctness matters.",
    }));
    next_steps_checklist.push(serde_json::json!({
        "step": next_steps_checklist.len() + 1,
        "action": "After several runs — compare output evolution across executions",
        "tool": "get_execution_delta",
        "args": { "workflow_id": &wf_id_str, "n": 5 },
        "note": "get_execution_delta shows field-level changes across the last N executions. Excellent for spotting regressions, verifying improvements, and demo presentations. Run after 3+ executions.",
    }));
    if inputs.ready_to_run {
        next_steps.push(format!(
            "Workflow is ready. Run: call_workflow(workflow_id: \"{}\")",
            inputs.workflow_id
        ));
    } else if inputs.graph_is_empty {
        next_steps.push(format!(
            "Empty workflow — add at least one node before running. \
             Use add_node_to_workflow(workflow_id: \"{}\", node_id: \"<id>\", module_id: \"<uuid>\") \
             or install_module_from_catalog then add_node_to_workflow.",
            inputs.workflow_id
        ));
    }

    let mut resp = serde_json::json!({
        "workflow_id": wf_id_str,
        "name": inputs.workflow_name,
        "status": "created",
        "readiness_score": 0,
        "node_count": inputs.node_count,
        "edge_count": inputs.edge_count,
        "ascii_graph": inputs.ascii_graph,
        "ready_to_run": inputs.ready_to_run,
        "missing_config": inputs.missing_config,
        "required_secrets": inputs.required_secrets.into_iter().collect::<Vec<_>>(),
        "next_steps": next_steps,
        "next_steps_checklist": next_steps_checklist,
    });
    if let (Some(obj), Some(warn)) = (resp.as_object_mut(), inputs.description_warning) {
        obj.insert(
            "semantic_search_warning".to_string(),
            serde_json::json!(warn),
        );
    }
    if let (Some(obj), Some(warn)) = (resp.as_object_mut(), inputs.name_collision_warning) {
        obj.insert(
            "name_collision_warning".to_string(),
            serde_json::json!(warn),
        );
    }
    if !inputs.vault_warnings.is_empty() {
        if let Some(obj) = resp.as_object_mut() {
            obj.insert(
                "warnings".to_string(),
                serde_json::json!(inputs.vault_warnings),
            );
        }
    }
    resp
}

/// Per-template metadata needed by [`analyze_workflow_for_quickstart`].
/// `allowed_secrets` is the *effective* list — per-installation
/// `wasm_modules.allowed_secrets` overrides the template default when
/// present. The handler is responsible for resolving the override
/// before constructing this struct (so the analyzer stays state-free).
#[derive(Debug, Clone)]
pub struct TemplateMeta {
    pub name: String,
    pub config_schema: Value,
    pub allowed_secrets: Vec<String>,
}

/// Aggregate signals produced by [`analyze_workflow_for_quickstart`].
/// None of these block workflow creation — they shape the response
/// (`missing_config` + `required_secrets` populate the
/// `next_steps_checklist`; `vault_warnings` surface as a top-level
/// `warnings` field).
#[derive(Debug, Default)]
pub struct PostCreateAnalysis {
    /// One entry per node with at least one unmet required-config
    /// field. Shape matches the original handler exactly:
    /// `{node_id, module, missing_required: [field, ...]}`.
    pub missing_config: Vec<Value>,
    /// Union of every node's effective `allowed_secrets`, with the `"*"`
    /// wildcard (a grant notation, not a provisionable path) excluded
    /// — listing it would tell operators to `set_secret "*"` which is
    /// wrong.
    pub required_secrets: HashSet<String>,
    /// Per-node `vault://` reference issues: empty path, or a path the
    /// module's `allowed_secrets` doesn't include. Warnings, not
    /// errors — the access denial would surface at runtime anyway, but
    /// flagging at create-time saves a deploy-then-fail cycle.
    pub vault_warnings: Vec<String>,
}

/// Walk every input node against the resolved template metadata and
/// produce three things in one pass:
///
///   1. **Hard error (returned via `Err`)** — config-type or
///      enum mismatches. The original handler treated these as a
///      blocking pre-flight; the function preserves that contract.
///      Failure message is the original "Config type error(s) —
///      workflow NOT created:\n…" text agents/tests grep for.
///   2. **`missing_config`** — required schema fields that are
///      absent / null / empty-string in `node.config`.
///   3. **`required_secrets`** — wildcard-filtered union of effective
///      `allowed_secrets` across every regular module node.
///   4. **`vault_warnings`** — `vault://` config values whose path
///      isn't permitted by the module's effective allowed_secrets.
///
/// Pure function — only reads `input_nodes` + `template_meta`. The
/// caller fetches `template_meta` via two parallel repo calls
/// (`get_templates_by_ids`, `get_installed_secrets_by_template_ids`),
/// resolves the install-time override, and hands the result here.
///
/// Iteration order matches the original handler: for each node,
/// missing/required-secret signals are recorded before vault warnings,
/// and overall the lists are built in `input_nodes` order.
pub fn analyze_workflow_for_quickstart(
    input_nodes: &[Value],
    template_meta: &HashMap<Uuid, TemplateMeta>,
) -> Result<PostCreateAnalysis, String> {
    // Phase 1 — hard-error gate. Run first so a config-type bug never
    // slips into the response as a quiet warning.
    let type_errors = collect_config_type_errors(input_nodes, template_meta);
    if !type_errors.is_empty() {
        return Err(format!(
            "Config type error(s) — workflow NOT created:\n{}",
            type_errors.join("\n")
        ));
    }

    let mut analysis = PostCreateAnalysis::default();
    for node in input_nodes {
        let node_id = node.get("id").and_then(|v| v.as_str()).unwrap_or("?");
        let node_config = node.get("config").cloned().unwrap_or(serde_json::json!({}));
        let Some(tid) = node
            .get("module_id")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<Uuid>().ok())
        else {
            continue;
        };
        let Some(meta) = template_meta.get(&tid) else {
            continue;
        };

        // Missing-required and required-secrets — single per-node pass.
        let required: Vec<String> = meta
            .config_schema
            .get("required")
            .and_then(|r| r.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let missing: Vec<String> = required
            .iter()
            .filter(|f| {
                node_config
                    .get(f.as_str())
                    .map(|v| v.is_null() || v.as_str().map(|s| s.is_empty()).unwrap_or(false))
                    .unwrap_or(true)
            })
            .cloned()
            .collect();
        if !missing.is_empty() {
            analysis.missing_config.push(serde_json::json!({
                "node_id": node_id,
                "module": &meta.name,
                "missing_required": missing,
            }));
        }
        for s in &meta.allowed_secrets {
            if s != "*" {
                analysis.required_secrets.insert(s.clone());
            }
        }

        // Vault-reference warnings. Wildcard short-circuits — no need
        // to validate per-key when the module accepts everything.
        let has_wildcard = meta.allowed_secrets.iter().any(|s| s == "*");
        if let Some(cfg_obj) = node_config.as_object() {
            for (field_key, field_val) in cfg_obj {
                let Some(val_str) = field_val.as_str() else {
                    continue;
                };
                let Some(path) = val_str.strip_prefix("vault://") else {
                    continue;
                };
                if path.is_empty() {
                    analysis.vault_warnings.push(format!(
                        "Node '{}' config key '{}' has an empty vault:// \
                         reference. Must be 'vault://path/to/key'.",
                        node_id, field_key
                    ));
                    continue;
                }
                if !has_wildcard
                    && !talos_workflow_job_protocol::vault_path_permitted(
                        &meta.allowed_secrets,
                        path,
                    )
                {
                    analysis.vault_warnings.push(format!(
                        "Node '{}' config key '{}' references vault://{} \
                         but the module's allowed_secrets does not include \
                         it. The secret will be inaccessible at runtime.",
                        node_id, field_key, path
                    ));
                }
            }
        }
    }
    Ok(analysis)
}

/// Internal: collect schema-type and enum mismatches for every
/// (node, field) pair. Empty result = clean pass. Pulled out so it
/// can be tested independently and so the public analyzer's success
/// path stays focused on the warning/inventory build-up.
fn collect_config_type_errors(
    input_nodes: &[Value],
    template_meta: &HashMap<Uuid, TemplateMeta>,
) -> Vec<String> {
    let mut errors: Vec<String> = Vec::new();
    for node in input_nodes {
        let node_id = node.get("id").and_then(|v| v.as_str()).unwrap_or("?");
        let node_config = node.get("config").cloned().unwrap_or(serde_json::json!({}));
        let Some(tid) = node
            .get("module_id")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<Uuid>().ok())
        else {
            continue;
        };
        let Some(meta) = template_meta.get(&tid) else {
            continue;
        };
        let Some(props) = meta
            .config_schema
            .get("properties")
            .and_then(|p| p.as_object())
        else {
            continue;
        };
        for (field, spec) in props {
            let Some(provided) = node_config.get(field) else {
                continue;
            };
            if provided.is_null() {
                continue;
            }
            let expected_type = spec.get("type").and_then(|t| t.as_str()).unwrap_or("");
            let type_ok = match expected_type {
                "number" | "integer" => provided.is_number(),
                "boolean" => provided.is_boolean(),
                "string" => provided.is_string(),
                "array" => provided.is_array(),
                "object" => provided.is_object(),
                _ => true,
            };
            if !type_ok {
                let actual = if provided.is_string() {
                    "string"
                } else if provided.is_number() {
                    "number"
                } else if provided.is_boolean() {
                    "boolean"
                } else if provided.is_array() {
                    "array"
                } else {
                    "object"
                };
                errors.push(format!(
                    "Node '{}': field '{}' should be {}, got {}",
                    node_id, field, expected_type, actual
                ));
            }
            if let Some(allowed) = spec.get("enum").and_then(|e| e.as_array()) {
                if !allowed.contains(provided) {
                    errors.push(format!(
                        "Node '{}': field '{}' value {:?} not in allowed enum values: {:?}",
                        node_id, field, provided, allowed
                    ));
                }
            }
        }
    }
    errors
}

/// Project user-supplied edges into the canonical graph_json edge
/// shape: `{source, target}` plus optional `condition` and `edge_type`
/// when present. Pure transformation — no validation. Run validators
/// (`validate_edge_targets`, `validate_edge_condition_lengths`) before
/// calling this.
pub fn project_input_edges(input_edges: &[Value]) -> Vec<Value> {
    input_edges
        .iter()
        .map(|e| {
            let mut edge = serde_json::json!({
                "source": e.get("source").and_then(|v| v.as_str()).unwrap_or(""),
                "target": e.get("target").and_then(|v| v.as_str()).unwrap_or(""),
            });
            if let Some(condition) = e.get("condition").and_then(|v| v.as_str()) {
                if let Some(o) = edge.as_object_mut() {
                    o.insert("condition".to_string(), serde_json::json!(condition));
                }
            }
            if let Some(edge_type) = e.get("edge_type").and_then(|v| v.as_str()) {
                if let Some(o) = edge.as_object_mut() {
                    o.insert("edge_type".to_string(), serde_json::json!(edge_type));
                }
            }
            edge
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Inline-Rust compile helpers (shared by add_node_to_workflow + compile_custom_sandbox)
// ─────────────────────────────────────────────────────────────────────────────

/// Inject the `#[talos_sdk_macros::talos_module(world = "...")]` attribute
/// before `fn run(` in the source, unless the source is already wrapped
/// (carries `#[talos_node`, `#[talos_module`, `talos_sdk_macros::talos_*`,
/// or `wit_bindgen::generate!` markers — any of these tell us the caller
/// already owns the macro layer).
///
/// Targets `fn run` specifically rather than the first `fn` because helper
/// functions defined before `run` at module scope must NOT absorb the macro
/// annotation (the macro expects the `run(String) -> Result<String, String>`
/// signature; misapplying it to a helper produces a misleading type error).
///
/// Returns the source verbatim when no `fn run(` is found — the resulting
/// compile failure is the right surface for that error.
pub fn wrap_rust_code_with_talos_module(rust_code: &str, capability_world: &str) -> String {
    if rust_code.contains("wit_bindgen::generate!")
        || rust_code.contains("#[talos_node")
        || rust_code.contains("talos_sdk_macros::talos_node")
        || rust_code.contains("#[talos_module")
        || rust_code.contains("talos_sdk_macros::talos_module")
    {
        return rust_code.to_string();
    }
    static RE_RUN_FN: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(r"(?m)^[ \t]*(pub[ \t]+)?fn[ \t]+run[ \t]*\(").unwrap()
    });
    match RE_RUN_FN.find(rust_code) {
        Some(m) => format!(
            "{}#[talos_sdk_macros::talos_module(world = \"{}\")]\n{}",
            &rust_code[..m.start()],
            capability_world,
            &rust_code[m.start()..]
        ),
        None => rust_code.to_string(),
    }
}

/// Compute the default `allowed_hosts` list for an inline-compiled node
/// when the caller didn't supply one explicitly.
///
/// Network-capable worlds (anything containing `http`, `network`, `secrets`,
/// `automation`, or `database`) get `["*"]` (wildcard); pure-compute worlds
/// get an empty list. Mirrors the historical inline behaviour in
/// `handle_add_node_to_workflow` and `handle_compile_custom_sandbox`.
///
/// `explicit` short-circuits — when `Some(_)` the caller's list wins
/// regardless of world. `None` means "fall through to defaults".
pub fn resolve_default_allowed_hosts(world: &str, explicit: Option<Vec<String>>) -> Vec<String> {
    if let Some(hosts) = explicit {
        return hosts;
    }
    if world.contains("http")
        || world.contains("network")
        || world.contains("secrets")
        || world.contains("automation")
        || world.contains("database")
    {
        vec!["*".to_string()]
    } else {
        Vec::new()
    }
}

/// Format the user-facing error when an inline-compile would clobber a
/// module that's referenced by other live workflows.
///
/// `other_users` is the list of `(workflow_id, workflow_name)` pairs the
/// caller queried; it must be non-empty (callers should branch out before
/// calling this). The first 5 are listed inline; remaining counts are
/// summarised as "… and N more" so the message stays bounded.
pub fn format_shared_module_overwrite_error(
    node_id: &str,
    existing_module_id: Uuid,
    other_users: &[(Uuid, String)],
) -> String {
    let preview: Vec<String> = other_users
        .iter()
        .take(5)
        .map(|(id, name)| format!("  - {} ({})", name, id))
        .collect();
    let more = if other_users.len() > 5 {
        format!("\n  … and {} more", other_users.len() - 5)
    } else {
        String::new()
    };
    format!(
        "Refusing to overwrite shared module '{}' (id {}). \
         It is referenced by {} other live workflow(s):\n{}{}\n\
         Inline-compile would silently mutate every dependent workflow's behavior.\n\
         Choose one:\n\
         1. Pick a unique node_id (the inline compile names the module after node_id).\n\
         2. Update the existing module in place: hot_update_module(module_id: '{}', rust_code: ...).\n\
         3. Compile a new module: compile_custom_sandbox(name: '...', rust_code: ...) then add_node_to_workflow with the returned module_id.",
        node_id,
        existing_module_id,
        other_users.len(),
        preview.join("\n"),
        more,
        existing_module_id,
    )
}

/// Existing stored permissions for a module, used by [`compute_permission_drift`].
/// Mirrors the shape `WorkflowRepository::get_module_permissions` returns
/// without taking that crate as a dependency (this crate is the
/// helpers crate; it stays free of repository imports by design).
///
/// Wasm-security review 2026-05-23 (L-finding-1): `capability_world` is
/// included so an inline-recompile that silently widens the world
/// (e.g. existing module is `http-node`, caller requests `agent-node`
/// while keeping the same node_id) surfaces as drift instead of
/// upserting a higher-capability module into a graph that was
/// authored against the narrower one. The actor's
/// `max_capability_world` is still the hard ceiling and is enforced
/// pre-compile by `InlineCompileService` regardless of drift — the
/// drift check is the additional "caller MUST make the world-change
/// explicit" gate that prevents a silent capability upgrade on
/// name-collision.
pub struct StoredPermissions {
    pub allowed_hosts: Vec<String>,
    pub allowed_secrets: Vec<String>,
    pub allowed_methods: Vec<String>,
    /// The stored module's normalised `capability_world` (e.g.
    /// `"http-node"`). Empty string is the legacy / migration default
    /// meaning "no recorded value"; in that case the drift check
    /// skips the world comparison because there's no anchor to
    /// compare against. Callers that DO know a stored value should
    /// always pass it through.
    pub capability_world: String,
}

/// Build the per-field drift report comparing caller-explicit
/// permissions to the stored module's existing permissions.
///
/// Each `Option<&[String]>` is `Some` only when the caller passed the
/// key in the request; `None` means "caller omitted, preserve stored
/// behaviour". Mismatches are reported one line per field. Returns
/// an empty vec when no drift exists — caller proceeds with the
/// inline-compile.
///
/// L-finding-1: `explicit_capability_world` follows the same
/// `Option<&str>` convention. `None` = caller omitted (preserve
/// stored); `Some("http-node")` = caller asked explicitly, drift fires
/// if `stored.capability_world` is a different normalised world. The
/// comparison uses the normalised `xxx-node` form so callers can pass
/// either `"http"` or `"http-node"` interchangeably.
pub fn compute_permission_drift(
    explicit_allowed_hosts: Option<&[String]>,
    explicit_allowed_secrets: Option<&[String]>,
    explicit_allowed_methods: Option<&[String]>,
    explicit_capability_world: Option<&str>,
    stored: &StoredPermissions,
) -> Vec<String> {
    fn perm_lists_equal(a: &[String], b: &[String]) -> bool {
        // Order- AND duplicate-insensitive: sort then dedup so callers that
        // accidentally double-list a host/secret aren't reported as drift
        // against a stored single-entry list.
        let mut a_sorted: Vec<&str> = a.iter().map(String::as_str).collect();
        let mut b_sorted: Vec<&str> = b.iter().map(String::as_str).collect();
        a_sorted.sort_unstable();
        a_sorted.dedup();
        b_sorted.sort_unstable();
        b_sorted.dedup();
        a_sorted == b_sorted
    }

    fn fmt_perm_list(p: &[String]) -> String {
        if p.is_empty() {
            "[]".to_string()
        } else {
            format!("[{}]", p.join(", "))
        }
    }

    // L-finding-1: normalise both sides to the `xxx-node` form so a
    // caller passing `"http"` vs the stored `"http-node"` is NOT a
    // false-positive drift. Mirrors `normalise_world_to_node` in
    // inline-compile-service without taking that crate as a dep.
    fn norm_world(w: &str) -> String {
        let trimmed = w.trim();
        if trimmed.is_empty() {
            return String::new();
        }
        if trimmed.ends_with("-node") {
            trimmed.to_string()
        } else {
            format!("{trimmed}-node")
        }
    }

    let mut drift_lines: Vec<String> = Vec::new();
    if let Some(h) = explicit_allowed_hosts {
        if !perm_lists_equal(h, &stored.allowed_hosts) {
            drift_lines.push(format!(
                "  - allowed_hosts: stored={} vs requested={}",
                fmt_perm_list(&stored.allowed_hosts),
                fmt_perm_list(h)
            ));
        }
    }
    if let Some(s) = explicit_allowed_secrets {
        if !perm_lists_equal(s, &stored.allowed_secrets) {
            drift_lines.push(format!(
                "  - allowed_secrets: stored={} vs requested={}",
                fmt_perm_list(&stored.allowed_secrets),
                fmt_perm_list(s)
            ));
        }
    }
    if let Some(m) = explicit_allowed_methods {
        if !perm_lists_equal(m, &stored.allowed_methods) {
            drift_lines.push(format!(
                "  - allowed_methods: stored={} vs requested={}",
                fmt_perm_list(&stored.allowed_methods),
                fmt_perm_list(m)
            ));
        }
    }
    // L-finding-1: capability_world drift. Stored value can be empty
    // string for legacy rows (no recorded world) — skip the check
    // there because there's no anchor to compare against, AND
    // operators upgrading legacy modules need a one-time path to
    // backfill the field without tripping drift on every existing row.
    if let Some(w) = explicit_capability_world {
        let stored_norm = norm_world(&stored.capability_world);
        let requested_norm = norm_world(w);
        if !stored_norm.is_empty() && stored_norm != requested_norm {
            drift_lines.push(format!(
                "  - capability_world: stored=\"{}\" vs requested=\"{}\" \
                 (a world change is a capability-surface change — declare it explicitly \
                 by deleting and recreating the module, or use a fresh node_id)",
                stored.capability_world, w
            ));
        }
    }
    drift_lines
}

/// Format the user-facing error when caller-explicit permissions differ
/// from the existing stored module's permissions. `drift_lines` comes
/// from [`compute_permission_drift`].
pub fn format_permission_drift_error(
    node_id: &str,
    existing_module_id: Uuid,
    drift_lines: &[String],
) -> String {
    format!(
        "Refusing to silently inherit permissions on existing module '{}' (id {}). \
         Caller-passed permissions differ from the stored module:\n{}\n\
         Inline-compile preserves existing permissions on name-collision to avoid \
         dropping grants during hot-updates — but that means explicit permissions \
         passed here would be silently discarded. Pick one:\n\
         1. Use a unique node_id so a FRESH module is compiled with the requested permissions.\n\
         2. Apply the requested permissions to the existing module first: \
         update_module_hosts / update_module_secrets / update_module_methods.\n\
         3. Compile a new module: compile_custom_sandbox(name: '...', allowed_hosts: [...], allowed_secrets: [...], ...), \
         then add_node_to_workflow with the returned module_id.",
        node_id,
        existing_module_id,
        drift_lines.join("\n"),
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// add_node_to_workflow helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Match `{{key}}` template-syntax interpolations inside config string values.
///
/// Used by `add_node_to_workflow` and `update_node_config` to surface a warning
/// when the caller embedded `{{...}}` in a config value — interpolation is a
/// runtime feature, so authoring-time visibility helps catch keys that won't
/// resolve at execution. The returned `Vec<String>` is the user-facing warning
/// text (multiple lines if multiple fields), keyed off the field name and the
/// captured key. An empty vec means no interpolations detected; callers should
/// surface it as `template_interpolation_warnings` in their response.
pub fn detect_template_interpolation_warnings(config: &Value) -> Vec<String> {
    static RE_TEMPLATE: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(r"\{\{([^}]+)\}\}").unwrap());

    let Some(obj) = config.as_object() else {
        return Vec::new();
    };
    let mut warnings = Vec::new();
    for (field, val) in obj {
        let Some(s) = val.as_str() else { continue };
        let keys: Vec<&str> = RE_TEMPLATE
            .captures_iter(s)
            .filter_map(|c| c.get(1).map(|m| m.as_str()))
            .collect();
        if keys.is_empty() {
            continue;
        }
        warnings.push(format!(
            "Config field '{}' uses template syntax {{{{{}}}}}. \
             Interpolation is a runtime feature — ensure '{}' is present in \
             the upstream node's output (data[\"input\"][\"{}\"]) or \
             in data[\"__trigger_input__\"][\"{}\"]. \
             If the upstream is a catalog module that transforms data \
             (e.g. Data_Validator), original trigger fields are only \
             accessible via __trigger_input__.",
            field,
            keys.join(", "),
            keys[0],
            keys[0],
            keys[0]
        ));
    }
    warnings
}

/// Append-or-update edges connecting a node into the surrounding graph.
///
/// `connect_from` adds an edge `(from → node_id)`; `connect_to` adds
/// `(node_id → to)`. Both are deduped — re-running with the same
/// connect_from doesn't duplicate the edge. When BOTH are set the
/// helper first removes any direct `(from → to)` edge so the new node
/// is inserted between them rather than running parallel.
///
/// `length_caps` aren't enforced here — caller validates condition /
/// retry-string lengths before this point.
pub fn upsert_node_edges(
    edges: &mut Vec<Value>,
    node_id: &str,
    connect_from: Option<&str>,
    connect_to: Option<&str>,
) {
    // When both ends are specified, remove the direct edge that would
    // otherwise bypass the new node.
    if let (Some(from), Some(to)) = (connect_from, connect_to) {
        edges.retain(|e| {
            let src = e.get("source").and_then(|v| v.as_str()).unwrap_or("");
            let tgt = e.get("target").and_then(|v| v.as_str()).unwrap_or("");
            !(src == from && tgt == to)
        });
    }
    if let Some(from) = connect_from {
        let already = edges.iter().any(|e| {
            e.get("source").and_then(|v| v.as_str()) == Some(from)
                && e.get("target").and_then(|v| v.as_str()) == Some(node_id)
        });
        if !already {
            edges.push(serde_json::json!({ "source": from, "target": node_id }));
        }
    }
    if let Some(to) = connect_to {
        let already = edges.iter().any(|e| {
            e.get("source").and_then(|v| v.as_str()) == Some(node_id)
                && e.get("target").and_then(|v| v.as_str()) == Some(to)
        });
        if !already {
            edges.push(serde_json::json!({ "source": node_id, "target": to }));
        }
    }
}

/// Inputs to [`build_add_node_payload`]. Owned values; the caller is
/// responsible for clones if needed.
pub struct AddNodeInputs<'a> {
    pub node_id: &'a str,
    pub module_id: &'a str,
    pub config: Value,
    pub last_y: f64,
    pub existing_node: Option<&'a Value>,
    /// Caller-supplied retry/skip/timeout overrides. `None` means "fall
    /// through to the existing node's value if any, else apply
    /// `template_max_retries` for retry_count only".
    pub timeout_secs: Option<&'a Value>,
    pub retry_count: Option<&'a Value>,
    pub retry_backoff_ms: Option<&'a Value>,
    pub retry_condition: Option<&'a str>,
    pub retry_delay_expression: Option<&'a str>,
    pub skip_condition: Option<&'a str>,
    pub continue_on_error: Option<&'a Value>,
    /// Template's declared `max_retries` (catalog-bound default for
    /// retry_count when neither caller-arg nor existing-node provides
    /// one). Catches the human-approval-style modules that ship with
    /// max_retries=0 — without this they'd silently inherit the
    /// engine's unwrap_or(2) and trigger retry storms on rejection.
    pub template_max_retries: Option<i32>,
}

/// Build the JSON payload for a new (or re-bound) workflow node, applying
/// the caller's overrides while preserving every field the existing node
/// already had where the caller didn't supply a value.
///
/// Field-preservation rules (matching the inline handler's behaviour):
///   * `config` → caller-explicit > existing node's `data` > `{}`.
///   * `timeout_secs` / `retry_backoff_ms` / `continue_on_error` →
///     caller-arg if present, otherwise preserve from existing.
///   * `retry_count` → caller-arg if present, else existing if any,
///     else `template_max_retries` (only the template-default branch
///     fires for fresh nodes; existing wins for re-binds).
///   * `retry_condition` / `retry_delay_expression` / `skip_condition`
///     → caller-arg if present (already length-validated); else
///     preserve.
///
/// Position: `{ x: 250, y: last_y + 120 }` for fresh nodes. The caller
/// is responsible for upserting this into the `nodes` array (this
/// helper is non-mutating; no array indexing).
pub fn build_add_node_payload(inputs: AddNodeInputs<'_>) -> Value {
    let AddNodeInputs {
        node_id,
        module_id,
        config,
        last_y,
        existing_node,
        timeout_secs,
        retry_count,
        retry_backoff_ms,
        retry_condition,
        retry_delay_expression,
        skip_condition,
        continue_on_error,
        template_max_retries,
    } = inputs;

    let mut new_node = serde_json::json!({
        "id": node_id,
        "type": module_id,
        "position": { "x": 250.0_f64, "y": last_y + 120.0 },
        "data": config,
    });
    let Some(obj) = new_node.as_object_mut() else {
        return new_node;
    };

    let preserve = |key: &str, obj: &mut Map<String, Value>| {
        if let Some(existing) = existing_node.and_then(|n| n.get(key)).cloned() {
            obj.insert(key.to_string(), existing);
        }
    };

    // timeout_secs
    if let Some(v) = timeout_secs {
        obj.insert("timeout_secs".to_string(), v.clone());
    } else {
        preserve("timeout_secs", obj);
    }

    // retry_count — three-way: caller > existing > template default
    if let Some(v) = retry_count {
        obj.insert("retry_count".to_string(), v.clone());
    } else if existing_node.and_then(|n| n.get("retry_count")).is_some() {
        preserve("retry_count", obj);
    } else if let Some(mr) = template_max_retries {
        obj.insert("retry_count".to_string(), serde_json::json!(mr));
    }

    // retry_backoff_ms
    if let Some(v) = retry_backoff_ms {
        obj.insert("retry_backoff_ms".to_string(), v.clone());
    } else {
        preserve("retry_backoff_ms", obj);
    }

    // retry_condition (string)
    if let Some(s) = retry_condition {
        obj.insert("retry_condition".to_string(), Value::String(s.to_string()));
    } else {
        preserve("retry_condition", obj);
    }

    // retry_delay_expression (string)
    if let Some(s) = retry_delay_expression {
        obj.insert(
            "retry_delay_expression".to_string(),
            Value::String(s.to_string()),
        );
    } else {
        preserve("retry_delay_expression", obj);
    }

    // skip_condition (string)
    if let Some(s) = skip_condition {
        obj.insert("skip_condition".to_string(), Value::String(s.to_string()));
    } else {
        preserve("skip_condition", obj);
    }

    // continue_on_error
    if let Some(v) = continue_on_error {
        obj.insert("continue_on_error".to_string(), v.clone());
    } else {
        preserve("continue_on_error", obj);
    }

    new_node
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ids<'a>(v: &[&'a str]) -> HashSet<&'a str> {
        v.iter().copied().collect()
    }

    #[test]
    fn acyclic_linear_chain_ok() {
        let edges = vec![
            json!({"source": "a", "target": "b"}),
            json!({"source": "b", "target": "c"}),
        ];
        assert!(validate_acyclic(&edges, &ids(&["a", "b", "c"])).is_ok());
    }

    #[test]
    fn acyclic_diamond_dag_ok() {
        // a -> b, a -> c, b -> d, c -> d  (fan-out/fan-in, no cycle)
        let edges = vec![
            json!({"source": "a", "target": "b"}),
            json!({"source": "a", "target": "c"}),
            json!({"source": "b", "target": "d"}),
            json!({"source": "c", "target": "d"}),
        ];
        assert!(validate_acyclic(&edges, &ids(&["a", "b", "c", "d"])).is_ok());
    }

    #[test]
    fn acyclic_two_node_cycle_rejected() {
        let edges = vec![
            json!({"source": "a", "target": "b"}),
            json!({"source": "b", "target": "a"}),
        ];
        let err = validate_acyclic(&edges, &ids(&["a", "b"])).unwrap_err();
        assert!(err.contains("cycle"), "got: {err}");
    }

    #[test]
    fn acyclic_three_node_cycle_rejected() {
        let edges = vec![
            json!({"source": "a", "target": "b"}),
            json!({"source": "b", "target": "c"}),
            json!({"source": "c", "target": "a"}),
        ];
        assert!(validate_acyclic(&edges, &ids(&["a", "b", "c"])).is_err());
    }

    #[test]
    fn acyclic_self_loop_rejected() {
        let edges = vec![json!({"source": "a", "target": "a"})];
        assert!(validate_acyclic(&edges, &ids(&["a"])).is_err());
    }

    #[test]
    fn acyclic_disconnected_and_empty_ok() {
        assert!(validate_acyclic(&[], &ids(&["a", "b"])).is_ok());
        // two independent edges, no shared cycle
        let edges = vec![
            json!({"source": "a", "target": "b"}),
            json!({"source": "c", "target": "d"}),
        ];
        assert!(validate_acyclic(&edges, &ids(&["a", "b", "c", "d"])).is_ok());
    }

    #[test]
    fn acyclic_ignores_edges_to_undeclared_nodes() {
        // edge into a node not in the declared set is ignored (validate_edge_targets
        // owns that rejection); cycle detection must not panic or false-positive.
        let edges = vec![json!({"source": "a", "target": "ghost"})];
        assert!(validate_acyclic(&edges, &ids(&["a"])).is_ok());
    }

    #[test]
    fn partition_separates_structural_from_regular() {
        let nodes = vec![
            json!({"id": "n1", "module_id": "abc"}),
            json!({"id": "n2", "node_type": "collect"}),
            json!({"id": "n3", "node_type": "loop"}),
            json!({"id": "n4", "module_id": "xyz"}),
            json!({"id": "n5", "node_type": "unknown"}), // unknown → regular
        ];
        let (structural, regular) = partition_nodes_by_kind(&nodes);
        assert_eq!(structural.len(), 2);
        assert_eq!(regular.len(), 3);
        assert_eq!(structural[0]["id"], "n2");
        assert!(regular.iter().any(|n| n["id"] == "n5"));
    }

    #[test]
    fn node_id_validation_accepts_safe_chars() {
        let nodes = vec![json!({"id": "valid-node_1.v2"}), json!({"id": "alphaNUM"})];
        assert!(validate_node_ids(&nodes).is_ok());
    }

    #[test]
    fn node_id_validation_rejects_long_id() {
        let long = "a".repeat(201);
        let nodes = vec![json!({"id": long})];
        assert!(validate_node_ids(&nodes)
            .unwrap_err()
            .contains("exceeds 200"));
    }

    #[test]
    fn node_id_validation_rejects_unsafe_chars() {
        let nodes = vec![json!({"id": "bad/node"})];
        let err = validate_node_ids(&nodes).unwrap_err();
        assert!(err.contains("ASCII alphanumeric"));
        let nodes = vec![json!({"id": "spaces no good"})];
        assert!(validate_node_ids(&nodes).is_err());
    }

    #[test]
    fn module_id_validation_requires_uuid() {
        let nodes = [json!({"id": "n1", "module_id": "550e8400-e29b-41d4-a716-446655440000"})];
        let regs: Vec<&Value> = nodes.iter().collect();
        assert!(validate_regular_module_ids(&regs).is_ok());

        let bad = [json!({"id": "n1", "module_id": "redis-cache"})];
        let regs: Vec<&Value> = bad.iter().collect();
        let err = validate_regular_module_ids(&regs).unwrap_err();
        assert!(err.contains("Invalid module_id"));
        assert!(err.contains("redis-cache"));
        assert!(err.contains("'n1'"));
    }

    #[test]
    fn capabilities_charset_is_enforced() {
        assert!(validate_capabilities(&["http-fetch".to_string()]).is_ok());
        assert!(
            validate_capabilities(&["data-transform".to_string(), "send-email".to_string()])
                .is_ok()
        );
        assert!(validate_capabilities(&["UPPER".to_string()]).is_err());
        assert!(validate_capabilities(&["under_score".to_string()]).is_err());
        assert!(validate_capabilities(&["spaces no".to_string()]).is_err());
        assert!(validate_capabilities(&["".to_string()]).is_err());
    }

    #[test]
    fn capabilities_count_capped_at_20() {
        let twenty: Vec<String> = (0..20).map(|i| format!("cap-{}", i)).collect();
        assert!(validate_capabilities(&twenty).is_ok());
        let twenty_one: Vec<String> = (0..21).map(|i| format!("cap-{}", i)).collect();
        assert!(validate_capabilities(&twenty_one).is_err());
    }

    #[test]
    fn intent_field_lengths_capped() {
        assert!(validate_intent(&json!({})).is_ok());
        assert!(validate_intent(&json!({"action": "ok"})).is_ok());
        assert!(validate_intent(&json!({"action": "x".repeat(501)})).is_err());
        assert!(validate_intent(&json!({"subject": "x".repeat(501)})).is_err());
    }

    /// MCP-193 (2026-05-08): every present string field on intent
    /// must be non-whitespace. Pre-fix only length was checked, so
    /// {"action": "   ", "subject": "   "} survived all the way to
    /// the search index.
    #[test]
    fn intent_rejects_whitespace_only_fields() {
        for field in ["action", "subject", "output_type", "trigger_context"] {
            let intent = json!({ field: "             " });
            let err = validate_intent(&intent).unwrap_err();
            assert!(
                err.contains(field) && err.contains("non-whitespace"),
                "{field} should reject whitespace; got: {err}"
            );
        }
    }

    #[test]
    fn intent_validates_optional_fields_too() {
        // output_type and trigger_context were unchecked pre-fix;
        // confirm length cap fires now.
        for field in ["output_type", "trigger_context"] {
            let intent = json!({ field: "x".repeat(501) });
            assert!(
                validate_intent(&intent).is_err(),
                "{field} should reject 501-char value"
            );
        }
    }

    #[test]
    fn intent_serialized_size_capped() {
        // MCP-247 (2026-05-08): the previous test fixture used an
        // unknown field `description` to exercise the 10000-char cap;
        // that test now hits the unknown-field rejection first. Use
        // the allowed `action` field at exactly 501 chars to fail the
        // per-field cap (≤ 500). The serialized-size cap is still
        // checked but is harder to trigger via an allowed field; the
        // per-field cap is the operationally-relevant guard.
        let big = "x".repeat(501);
        let intent = json!({"action": big});
        let err = validate_intent(&intent).unwrap_err();
        assert!(err.contains("≤ 500"), "unexpected err: {err}");
    }

    #[test]
    fn intent_rejects_unknown_field() {
        let intent = json!({"action": "watch", "extra_field": "should reject"});
        let err = validate_intent(&intent).unwrap_err();
        assert!(err.contains("unknown field"), "unexpected err: {err}");
        assert!(err.contains("extra_field"), "missing field name: {err}");
    }

    #[test]
    fn edge_dedup_skips_existing_pairs() {
        let existing = vec![
            json!({"source": "a", "target": "b"}),
            json!({"source": "b", "target": "c"}),
        ];
        let extra = vec![
            json!({"source": "a", "target": "b"}), // duplicate — skip
            json!({"source": "c", "target": "d"}), // new
            json!({"source": "b", "target": "c"}), // duplicate — skip
        ];
        let merged = merge_edges_dedup(existing, extra);
        assert_eq!(merged.len(), 3);
        assert_eq!(merged[2]["source"], "c");
        assert_eq!(merged[2]["target"], "d");
    }

    #[test]
    fn edge_dedup_preserves_order() {
        let existing = vec![json!({"source": "a", "target": "b"})];
        let extra = vec![
            json!({"source": "x", "target": "y"}),
            json!({"source": "x", "target": "z"}),
        ];
        let merged = merge_edges_dedup(existing, extra);
        assert_eq!(merged[0]["source"], "a");
        assert_eq!(merged[1]["source"], "x");
        assert_eq!(merged[1]["target"], "y");
        assert_eq!(merged[2]["target"], "z");
    }

    // ── validate_edge_targets ────────────────────────────────────────
    #[test]
    fn edge_target_validation_rejects_self_edge() {
        let edges = vec![json!({"source": "a", "target": "a"})];
        let ids: HashSet<&str> = ["a"].into_iter().collect();
        let err = validate_edge_targets(&edges, &ids).unwrap_err();
        assert!(err.contains("Self-referencing"));
    }

    #[test]
    fn edge_target_validation_rejects_unknown_source() {
        let edges = vec![json!({"source": "ghost", "target": "b"})];
        let ids: HashSet<&str> = ["a", "b"].into_iter().collect();
        let err = validate_edge_targets(&edges, &ids).unwrap_err();
        assert!(err.contains("Edge source 'ghost'"));
        assert!(err.contains("add_edge_to_workflow"));
    }

    #[test]
    fn edge_target_validation_rejects_unknown_target() {
        let edges = vec![json!({"source": "a", "target": "ghost"})];
        let ids: HashSet<&str> = ["a", "b"].into_iter().collect();
        let err = validate_edge_targets(&edges, &ids).unwrap_err();
        assert!(err.contains("Edge target 'ghost'"));
    }

    #[test]
    fn edge_target_validation_accepts_well_formed() {
        let edges = vec![
            json!({"source": "a", "target": "b"}),
            json!({"source": "b", "target": "c"}),
        ];
        let ids: HashSet<&str> = ["a", "b", "c"].into_iter().collect();
        assert!(validate_edge_targets(&edges, &ids).is_ok());
    }

    // ── validate_edge_condition_lengths ──────────────────────────────
    #[test]
    fn edge_condition_length_at_boundary() {
        let edges = vec![json!({"source": "a", "target": "b", "condition": "x".repeat(2000)})];
        assert!(validate_edge_condition_lengths(&edges).is_ok());
        let edges = vec![json!({"source": "a", "target": "b", "condition": "x".repeat(2001)})];
        assert!(validate_edge_condition_lengths(&edges).is_err());
    }

    #[test]
    fn edge_condition_length_ignores_missing() {
        let edges = vec![json!({"source": "a", "target": "b"})];
        assert!(validate_edge_condition_lengths(&edges).is_ok());
    }

    // ── build_structural_node_data ───────────────────────────────────
    #[test]
    fn structural_loop_data_picks_up_top_level_fields() {
        let n = json!({
            "id": "l1", "node_type": "loop",
            "body_node_id": "body", "condition": "x > 0", "max_iterations": 5
        });
        let data = build_structural_node_data("loop", &n);
        assert_eq!(data["body_node_id"], "body");
        assert_eq!(data["condition"], "x > 0");
        assert_eq!(data["max_iterations"], 5);
    }

    #[test]
    fn structural_loop_data_falls_back_to_config_block() {
        let n = json!({
            "id": "l1", "node_type": "loop",
            "config": {"body_node_id": "body", "condition": "y", "max_iterations": 3}
        });
        let data = build_structural_node_data("loop", &n);
        assert_eq!(data["body_node_id"], "body");
        assert_eq!(data["max_iterations"], 3);
    }

    #[test]
    fn structural_loop_data_defaults_when_missing() {
        let data = build_structural_node_data("loop", &json!({}));
        assert_eq!(data["body_node_id"], "");
        assert_eq!(data["condition"], "true");
        assert_eq!(data["max_iterations"], 10);
    }

    #[test]
    fn structural_sub_workflow_data_resolves_both_layers() {
        let n = json!({
            "id": "s1", "node_type": "sub_workflow",
            "config": {"sub_workflow_id": "sub-uuid", "timeout_secs": 90}
        });
        let data = build_structural_node_data("sub_workflow", &n);
        assert_eq!(data["sub_workflow_id"], "sub-uuid");
        assert_eq!(data["timeout_secs"], 90);
    }

    #[test]
    fn structural_capability_dispatch_carries_required_capabilities() {
        let n = json!({
            "id": "c1", "node_type": "capability_dispatch",
            "required_capabilities": ["http-fetch", "send-email"]
        });
        let data = build_structural_node_data("capability_dispatch", &n);
        assert_eq!(data["required_capabilities"][0], "http-fetch");
        assert_eq!(data["timeout_secs"], 60);
    }

    #[test]
    fn structural_collect_returns_empty_data() {
        let n = json!({"id": "c1", "node_type": "collect"});
        let data = build_structural_node_data("collect", &n);
        assert_eq!(data, json!({}));
    }

    // ── apply_retry_policy ───────────────────────────────────────────
    #[test]
    fn retry_policy_node_level_wins_over_default_and_template() {
        let mut obj = Map::new();
        let n = json!({"retry_count": 5, "retry_backoff_ms": 100});
        let default_retry = json!({"retry_count": 99, "retry_condition": "always"});
        apply_retry_policy(&mut obj, &n, &default_retry, Some(7));
        assert_eq!(obj["retry_count"], 5, "node-level retry_count wins");
        assert_eq!(obj["retry_backoff_ms"], 100);
        assert_eq!(
            obj["retry_condition"], "always",
            "default applies when node omits"
        );
    }

    #[test]
    fn retry_policy_template_max_retries_used_when_node_and_default_absent() {
        let mut obj = Map::new();
        apply_retry_policy(&mut obj, &json!({}), &json!({}), Some(0));
        // The whole point of carrying template max_retries: human-approval
        // (max_retries=0) should NOT be retried by the engine's default.
        assert_eq!(obj["retry_count"], 0);
    }

    #[test]
    fn retry_policy_no_template_no_default_no_node_means_no_retry_count_field() {
        let mut obj = Map::new();
        apply_retry_policy(&mut obj, &json!({}), &json!({}), None);
        assert!(
            !obj.contains_key("retry_count"),
            "absent retry_count means engine falls through to its own default"
        );
    }

    #[test]
    fn retry_policy_default_applies_when_node_omits() {
        let mut obj = Map::new();
        let default_retry = json!({
            "retry_count": 3, "retry_backoff_ms": 250,
            "retry_condition": "status >= 500", "retry_delay_expression": "n * 100"
        });
        apply_retry_policy(&mut obj, &json!({}), &default_retry, None);
        assert_eq!(obj["retry_count"], 3);
        assert_eq!(obj["retry_backoff_ms"], 250);
        assert_eq!(obj["retry_condition"], "status >= 500");
        assert_eq!(obj["retry_delay_expression"], "n * 100");
    }

    // ── extract_connect_edges ────────────────────────────────────────
    #[test]
    fn connect_from_becomes_inbound_edges() {
        let n = json!({"id": "downstream", "connect_from": ["a", "b"]});
        let edges = extract_connect_edges(&n, "downstream");
        assert_eq!(edges.len(), 2);
        assert_eq!(edges[0]["source"], "a");
        assert_eq!(edges[0]["target"], "downstream");
        assert_eq!(edges[1]["source"], "b");
    }

    #[test]
    fn connect_to_becomes_outbound_edges() {
        let n = json!({"id": "upstream", "connect_to": ["x", "y"]});
        let edges = extract_connect_edges(&n, "upstream");
        assert_eq!(edges.len(), 2);
        assert_eq!(edges[0]["source"], "upstream");
        assert_eq!(edges[0]["target"], "x");
    }

    #[test]
    fn connect_from_listed_before_connect_to_for_deterministic_dedup() {
        let n = json!({"id": "n", "connect_from": ["a"], "connect_to": ["b"]});
        let edges = extract_connect_edges(&n, "n");
        assert_eq!(edges[0]["source"], "a", "connect_from edges come first");
        assert_eq!(edges[1]["target"], "b");
    }

    // ── build_graph_node ─────────────────────────────────────────────
    #[test]
    fn build_graph_node_uses_explicit_position_without_advancing_y_offset() {
        let n = json!({
            "id": "n1",
            "module_id": "550e8400-e29b-41d4-a716-446655440000",
            "position": {"x": 42.0, "y": 84.0},
            "config": {"k": "v"}
        });
        let mut y = 100.0;
        let (node, _) = build_graph_node(&n, &json!({}), &HashMap::new(), &mut y);
        assert_eq!(node["position"]["x"], 42.0);
        assert_eq!(node["position"]["y"], 84.0);
        assert_eq!(y, 100.0, "explicit y must NOT advance the cursor");
    }

    #[test]
    fn build_graph_node_advances_y_offset_when_position_omitted() {
        let n = json!({"id": "n1", "module_id": "550e8400-e29b-41d4-a716-446655440000"});
        let mut y = 100.0;
        let (node1, _) = build_graph_node(&n, &json!({}), &HashMap::new(), &mut y);
        let (node2, _) = build_graph_node(&n, &json!({}), &HashMap::new(), &mut y);
        assert_eq!(node1["position"]["x"], 250.0, "default x preserved");
        assert_eq!(node1["position"]["y"], 220.0);
        assert_eq!(node2["position"]["y"], 340.0);
        assert_eq!(y, 340.0);
    }

    #[test]
    fn build_graph_node_emits_structural_shape_for_known_kinds() {
        let n = json!({
            "id": "loop1", "node_type": "loop",
            "body_node_id": "body", "condition": "true", "max_iterations": 1
        });
        let mut y = 100.0;
        let (node, _) = build_graph_node(&n, &json!({}), &HashMap::new(), &mut y);
        assert_eq!(node["type"], "system:loop");
        assert_eq!(node["kind"], "loop");
        assert_eq!(node["data"]["body_node_id"], "body");
    }

    #[test]
    fn build_graph_node_applies_template_max_retries_when_node_unset() {
        let module_uuid: Uuid = "550e8400-e29b-41d4-a716-446655440000".parse().unwrap();
        let mut tmap = HashMap::new();
        tmap.insert(module_uuid, 0); // human-approval-style: never retry
        let n = json!({
            "id": "n1",
            "module_id": "550e8400-e29b-41d4-a716-446655440000",
            "config": {}
        });
        let mut y = 100.0;
        let (node, _) = build_graph_node(&n, &json!({}), &tmap, &mut y);
        assert_eq!(node["retry_count"], 0);
    }

    #[test]
    fn build_graph_node_emits_connect_edges() {
        let n = json!({
            "id": "mid",
            "module_id": "550e8400-e29b-41d4-a716-446655440000",
            "connect_from": ["upstream"],
            "connect_to": ["downstream"]
        });
        let mut y = 100.0;
        let (_, edges) = build_graph_node(&n, &json!({}), &HashMap::new(), &mut y);
        assert_eq!(edges.len(), 2);
        assert_eq!(edges[0]["source"], "upstream");
        assert_eq!(edges[0]["target"], "mid");
        assert_eq!(edges[1]["source"], "mid");
        assert_eq!(edges[1]["target"], "downstream");
    }

    // ── project_input_edges ──────────────────────────────────────────
    #[test]
    fn project_input_edges_strips_extras_keeps_optional_fields() {
        let edges = vec![
            json!({"source": "a", "target": "b", "extra_garbage": 1}),
            json!({"source": "b", "target": "c", "condition": "x", "edge_type": "default"}),
        ];
        let out = project_input_edges(&edges);
        assert_eq!(
            out[0].as_object().unwrap().len(),
            2,
            "extra fields stripped"
        );
        assert_eq!(out[1]["condition"], "x");
        assert_eq!(out[1]["edge_type"], "default");
    }

    // ── analyze_workflow_for_quickstart ──────────────────────────────
    fn meta_with(name: &str, schema: Value, secrets: Vec<&str>) -> TemplateMeta {
        TemplateMeta {
            name: name.to_string(),
            config_schema: schema,
            allowed_secrets: secrets.into_iter().map(String::from).collect(),
        }
    }

    fn meta_map(entries: Vec<(&str, TemplateMeta)>) -> HashMap<Uuid, TemplateMeta> {
        // Use stable v5 UUIDs derived from the string id so tests can
        // mention the same id in both the meta map and the input nodes.
        entries
            .into_iter()
            .map(|(k, v)| (Uuid::new_v5(&Uuid::NAMESPACE_DNS, k.as_bytes()), v))
            .collect()
    }

    fn id_for(k: &str) -> String {
        Uuid::new_v5(&Uuid::NAMESPACE_DNS, k.as_bytes()).to_string()
    }

    #[test]
    fn quickstart_missing_required_config_listed_per_node() {
        let metas = meta_map(vec![(
            "slack",
            meta_with(
                "Slack Message",
                json!({"required": ["CHANNEL", "TOKEN"]}),
                vec![],
            ),
        )]);
        let nodes = vec![json!({
            "id": "n1",
            "module_id": id_for("slack"),
            "config": {"CHANNEL": ""},  // empty → still missing
        })];
        let analysis = analyze_workflow_for_quickstart(&nodes, &metas).unwrap();
        assert_eq!(analysis.missing_config.len(), 1);
        assert_eq!(analysis.missing_config[0]["node_id"], "n1");
        assert_eq!(analysis.missing_config[0]["module"], "Slack Message");
        let missing: Vec<&str> = analysis.missing_config[0]["missing_required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(missing.contains(&"CHANNEL"), "empty string is missing");
        assert!(missing.contains(&"TOKEN"), "absent key is missing");
    }

    #[test]
    fn quickstart_required_secrets_drops_wildcard() {
        let metas = meta_map(vec![(
            "m",
            meta_with(
                "Mod",
                json!({}),
                vec!["slack/bot_token", "*", "anthropic/api_key"],
            ),
        )]);
        let nodes = vec![json!({"id": "n1", "module_id": id_for("m"), "config": {}})];
        let analysis = analyze_workflow_for_quickstart(&nodes, &metas).unwrap();
        assert!(analysis.required_secrets.contains("slack/bot_token"));
        assert!(analysis.required_secrets.contains("anthropic/api_key"));
        assert!(
            !analysis.required_secrets.contains("*"),
            "wildcard MUST be excluded from the operator-facing list"
        );
    }

    #[test]
    fn quickstart_vault_warning_fires_for_disallowed_path() {
        let metas = meta_map(vec![(
            "m",
            meta_with(
                "Mod",
                json!({"properties": {"AUTH": {"type": "string"}}}),
                vec!["slack/bot_token"],
            ),
        )]);
        let nodes = vec![json!({
            "id": "n1",
            "module_id": id_for("m"),
            "config": {"AUTH": "vault://anthropic/api_key"},
        })];
        let analysis = analyze_workflow_for_quickstart(&nodes, &metas).unwrap();
        assert_eq!(analysis.vault_warnings.len(), 1);
        let w = &analysis.vault_warnings[0];
        assert!(w.contains("Node 'n1'"));
        assert!(w.contains("config key 'AUTH'"));
        assert!(w.contains("vault://anthropic/api_key"));
        assert!(w.contains("inaccessible at runtime"));
    }

    #[test]
    fn quickstart_vault_wildcard_grant_silences_path_warnings() {
        let metas = meta_map(vec![(
            "m",
            meta_with(
                "Mod",
                json!({"properties": {"AUTH": {"type": "string"}}}),
                vec!["*"],
            ),
        )]);
        let nodes = vec![json!({
            "id": "n1",
            "module_id": id_for("m"),
            "config": {"AUTH": "vault://anything/at/all"},
        })];
        let analysis = analyze_workflow_for_quickstart(&nodes, &metas).unwrap();
        assert!(
            analysis.vault_warnings.is_empty(),
            "wildcard grant short-circuits per-key validation"
        );
    }

    #[test]
    fn quickstart_vault_warning_for_empty_path() {
        let metas = meta_map(vec![(
            "m",
            meta_with(
                "Mod",
                json!({"properties": {"K": {"type": "string"}}}),
                vec![],
            ),
        )]);
        let nodes = vec![json!({
            "id": "n1",
            "module_id": id_for("m"),
            "config": {"K": "vault://"},
        })];
        let analysis = analyze_workflow_for_quickstart(&nodes, &metas).unwrap();
        assert_eq!(analysis.vault_warnings.len(), 1);
        assert!(analysis.vault_warnings[0].contains("empty vault://"));
    }

    #[test]
    fn quickstart_config_type_mismatch_returns_hard_error() {
        let metas = meta_map(vec![(
            "m",
            meta_with(
                "Mod",
                json!({"properties": {"COUNT": {"type": "integer"}}}),
                vec![],
            ),
        )]);
        let nodes = vec![json!({
            "id": "n1",
            "module_id": id_for("m"),
            "config": {"COUNT": "five"},
        })];
        let err = analyze_workflow_for_quickstart(&nodes, &metas).unwrap_err();
        assert!(
            err.starts_with("Config type error(s) — workflow NOT created:"),
            "preserves original handler's error prefix (agents/tests grep for it)"
        );
        assert!(err.contains("Node 'n1'"));
        assert!(err.contains("'COUNT'"));
        assert!(err.contains("should be integer"));
        assert!(err.contains("got string"));
    }

    #[test]
    fn quickstart_enum_mismatch_returns_hard_error() {
        let metas = meta_map(vec![(
            "m",
            meta_with(
                "Mod",
                json!({"properties": {"MODE": {"type": "string", "enum": ["a", "b"]}}}),
                vec![],
            ),
        )]);
        let nodes = vec![json!({
            "id": "n1",
            "module_id": id_for("m"),
            "config": {"MODE": "c"},
        })];
        let err = analyze_workflow_for_quickstart(&nodes, &metas).unwrap_err();
        assert!(err.contains("not in allowed enum values"));
    }

    #[test]
    fn quickstart_null_config_value_skips_type_check() {
        // Original handler intentionally treats `null` as "not provided",
        // not a type mismatch — a JSON null in a typed field becomes a
        // missing-required signal (if the field is required), not a
        // hard error.
        let metas = meta_map(vec![(
            "m",
            meta_with(
                "Mod",
                json!({
                    "required": ["COUNT"],
                    "properties": {"COUNT": {"type": "integer"}}
                }),
                vec![],
            ),
        )]);
        let nodes = vec![json!({
            "id": "n1",
            "module_id": id_for("m"),
            "config": {"COUNT": null},
        })];
        let analysis = analyze_workflow_for_quickstart(&nodes, &metas).unwrap();
        assert_eq!(analysis.missing_config.len(), 1);
    }

    #[test]
    fn quickstart_node_with_unknown_module_id_is_silently_ignored() {
        // If a module_id has no template_meta entry (race / cache miss /
        // structural node), the analyzer skips it rather than panicking
        // — matches original handler.
        let metas = meta_map(vec![]);
        let nodes = vec![
            json!({"id": "n1", "module_id": id_for("nonexistent"), "config": {"K": "v"}}),
            json!({"id": "n2", "node_type": "collect"}),
        ];
        let analysis = analyze_workflow_for_quickstart(&nodes, &metas).unwrap();
        assert!(analysis.missing_config.is_empty());
        assert!(analysis.required_secrets.is_empty());
        assert!(analysis.vault_warnings.is_empty());
    }

    #[test]
    fn quickstart_clean_workflow_returns_default() {
        let metas = meta_map(vec![(
            "m",
            meta_with(
                "Mod",
                json!({
                    "required": ["K"],
                    "properties": {"K": {"type": "string"}}
                }),
                vec![],
            ),
        )]);
        let nodes = vec![json!({
            "id": "n1",
            "module_id": id_for("m"),
            "config": {"K": "value"},
        })];
        let analysis = analyze_workflow_for_quickstart(&nodes, &metas).unwrap();
        assert!(analysis.missing_config.is_empty());
        assert!(analysis.required_secrets.is_empty());
        assert!(analysis.vault_warnings.is_empty());
    }

    #[test]
    fn quickstart_iteration_order_preserves_node_order() {
        let metas = meta_map(vec![(
            "m",
            meta_with("Mod", json!({"required": ["K"]}), vec![]),
        )]);
        let nodes = vec![
            json!({"id": "first", "module_id": id_for("m"), "config": {}}),
            json!({"id": "second", "module_id": id_for("m"), "config": {}}),
            json!({"id": "third", "module_id": id_for("m"), "config": {}}),
        ];
        let analysis = analyze_workflow_for_quickstart(&nodes, &metas).unwrap();
        assert_eq!(analysis.missing_config[0]["node_id"], "first");
        assert_eq!(analysis.missing_config[1]["node_id"], "second");
        assert_eq!(analysis.missing_config[2]["node_id"], "third");
    }

    // ── build_create_workflow_response ───────────────────────────────
    fn baseline_inputs() -> CreateResponseInputs {
        CreateResponseInputs {
            workflow_id: Uuid::nil(),
            workflow_name: "wf".into(),
            node_count: 1,
            edge_count: 0,
            ascii_graph: "[ascii]".into(),
            ready_to_run: true,
            graph_is_empty: false,
            missing_config: vec![],
            required_secrets: HashSet::new(),
            vault_warnings: vec![],
            description_warning: None,
            name_collision_warning: None,
        }
    }

    fn checklist_actions(resp: &Value) -> Vec<&str> {
        resp["next_steps_checklist"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["action"].as_str().unwrap())
            .collect()
    }

    #[test]
    fn response_clean_workflow_has_four_standard_checklist_items() {
        let resp = build_create_workflow_response(baseline_inputs());
        let actions = checklist_actions(&resp);
        assert_eq!(
            actions,
            vec![
                "Full readiness check",
                "Test run (synchronous — returns inline result)",
                "Test with assertions (preferred for correctness)",
                "After several runs — compare output evolution across executions",
            ]
        );
    }

    #[test]
    fn response_missing_config_prepends_configure_step() {
        let mut inputs = baseline_inputs();
        inputs.missing_config = vec![json!({"node_id": "n1", "missing_required": ["TOKEN"]})];
        inputs.ready_to_run = false;
        let resp = build_create_workflow_response(inputs);
        let actions = checklist_actions(&resp);
        assert_eq!(actions[0], "Configure nodes");
        assert_eq!(actions.len(), 5);
        // Step numbers are monotonic
        let steps: Vec<u64> = resp["next_steps_checklist"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["step"].as_u64().unwrap())
            .collect();
        assert_eq!(steps, vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn response_required_secrets_adds_provision_step_after_configure() {
        let mut inputs = baseline_inputs();
        inputs.missing_config = vec![json!({"node_id": "n1", "missing_required": ["X"]})];
        let mut secrets = HashSet::new();
        secrets.insert("slack/bot_token".into());
        inputs.required_secrets = secrets;
        inputs.ready_to_run = false;
        let resp = build_create_workflow_response(inputs);
        let actions = checklist_actions(&resp);
        assert_eq!(actions[0], "Configure nodes");
        assert_eq!(actions[1], "Provision secrets");
        assert_eq!(actions[2], "Full readiness check");
    }

    #[test]
    fn response_required_secrets_only_no_configure_step() {
        let mut inputs = baseline_inputs();
        let mut secrets = HashSet::new();
        secrets.insert("slack/bot_token".into());
        inputs.required_secrets = secrets;
        inputs.ready_to_run = false;
        let resp = build_create_workflow_response(inputs);
        let actions = checklist_actions(&resp);
        assert_eq!(actions[0], "Provision secrets");
        // First step is correctly numbered 1 (not 2) when configure is absent
        assert_eq!(resp["next_steps_checklist"][0]["step"].as_u64().unwrap(), 1);
    }

    #[test]
    fn response_ready_to_run_emits_call_workflow_summary_line() {
        let resp = build_create_workflow_response(baseline_inputs());
        let summary: Vec<&str> = resp["next_steps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap())
            .collect();
        assert_eq!(summary.len(), 1);
        assert!(summary[0].starts_with("Workflow is ready"));
        assert!(summary[0].contains("call_workflow"));
    }

    #[test]
    fn response_empty_graph_routes_to_add_node_guidance() {
        let mut inputs = baseline_inputs();
        inputs.node_count = 0;
        inputs.ready_to_run = false;
        inputs.graph_is_empty = true;
        let resp = build_create_workflow_response(inputs);
        let summary: Vec<&str> = resp["next_steps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap())
            .collect();
        assert_eq!(summary.len(), 1);
        assert!(summary[0].starts_with("Empty workflow"));
        assert!(summary[0].contains("add_node_to_workflow"));
    }

    #[test]
    fn response_not_ready_with_nonempty_graph_emits_no_summary_line() {
        let mut inputs = baseline_inputs();
        inputs.missing_config = vec![json!({"node_id": "n1"})];
        inputs.ready_to_run = false;
        let resp = build_create_workflow_response(inputs);
        // No "Workflow is ready" + no "Empty workflow" — caller derives
        // intent from the checklist items instead. Matches original
        // handler's silent next_steps when neither branch fires.
        let summary = resp["next_steps"].as_array().unwrap();
        assert_eq!(summary.len(), 1, "only the configure-nodes summary line");
        assert!(summary[0]
            .as_str()
            .unwrap()
            .starts_with("Set required config"));
    }

    #[test]
    fn response_warnings_appear_only_when_non_empty() {
        // Default → no warning fields present.
        let resp = build_create_workflow_response(baseline_inputs());
        let obj = resp.as_object().unwrap();
        assert!(!obj.contains_key("semantic_search_warning"));
        assert!(!obj.contains_key("name_collision_warning"));
        assert!(!obj.contains_key("warnings"));

        // With each warning populated, each surfaces under its own key.
        let mut inputs = baseline_inputs();
        inputs.description_warning = Some("desc warn".into());
        inputs.name_collision_warning = Some("name warn".into());
        inputs.vault_warnings = vec!["vault warn 1".into(), "vault warn 2".into()];
        let resp = build_create_workflow_response(inputs);
        assert_eq!(resp["semantic_search_warning"], "desc warn");
        assert_eq!(resp["name_collision_warning"], "name warn");
        assert_eq!(resp["warnings"][0], "vault warn 1");
        assert_eq!(resp["warnings"][1], "vault warn 2");
    }

    // ── detect_tool_call_xml_leak (moved from mcp/workflows.rs) ──────
    #[test]
    fn detect_tool_call_xml_leak_real_prod_artifact() {
        // Verbatim 2026-04-29 prod artifact that motivated the check.
        let leaked = "...accumulating, queryable signal.</description>\n<parameter name=\"actor_id\">7554e278-3069-4896-ab12-e4ca8b8cb989";
        assert!(
            detect_tool_call_xml_leak(leaked).is_some(),
            "real prod artifact MUST be detected"
        );
    }

    #[test]
    fn detect_tool_call_xml_leak_closing_tag_only() {
        let s = "ends with </description>";
        assert!(detect_tool_call_xml_leak(s).is_some());
    }

    #[test]
    fn detect_tool_call_xml_leak_parameter_tag_only() {
        let s = "leaked <parameter name=\"x\">y";
        assert!(detect_tool_call_xml_leak(s).is_some());
    }

    #[test]
    fn detect_tool_call_xml_leak_clean_text_passes() {
        assert!(detect_tool_call_xml_leak("a normal description").is_none());
        assert!(
            detect_tool_call_xml_leak("Mentions <description> in passing.").is_none(),
            "open tag alone is fine — the artifact is the *closing* tag"
        );
    }

    // ── validate_workflow_description ────────────────────────────────
    #[test]
    fn description_none_returns_search_warning() {
        let v = validate_workflow_description(None).unwrap();
        assert!(v.description.is_none());
        let warn = v.semantic_search_warning.unwrap();
        assert!(warn.starts_with("No description provided"));
    }

    #[test]
    fn description_empty_string_returns_search_warning() {
        let v = validate_workflow_description(Some("")).unwrap();
        assert!(v.description.is_none());
        assert!(v.semantic_search_warning.is_some());
    }

    #[test]
    fn description_whitespace_only_collapses_to_none_with_warning() {
        let v = validate_workflow_description(Some("   \n\t  ")).unwrap();
        assert!(v.description.is_none());
        assert!(v.semantic_search_warning.is_some());
    }

    #[test]
    fn description_trims_surrounding_whitespace() {
        let v = validate_workflow_description(Some("  hello world  ")).unwrap();
        assert_eq!(v.description.as_deref(), Some("hello world"));
        assert!(v.semantic_search_warning.is_none());
    }

    #[test]
    fn description_at_2000_byte_boundary() {
        let s = "x".repeat(2000);
        assert!(validate_workflow_description(Some(&s)).is_ok());
        let s = "x".repeat(2001);
        let err = validate_workflow_description(Some(&s)).unwrap_err();
        assert!(err.contains("≤ 2000 characters"));
    }

    #[test]
    fn description_rejects_null_byte() {
        let s = "abc\0def";
        let err = validate_workflow_description(Some(s)).unwrap_err();
        assert!(err.contains("control characters or null bytes"));
    }

    #[test]
    fn description_rejects_other_control_chars_but_allows_tab_lf_cr() {
        // Bell character (0x07) — control, not allowed.
        let err = validate_workflow_description(Some("a\u{0007}b")).unwrap_err();
        assert!(err.contains("control characters"));
        // Tab, newline, CR are allowed (legitimate in prose).
        assert!(validate_workflow_description(Some("line1\nline2\ttabbed\r\n")).is_ok());
    }

    #[test]
    fn description_rejects_xml_tool_call_leak() {
        let leaked = "real description ends here.</description>\n<parameter name=\"x\">y";
        let err = validate_workflow_description(Some(leaked)).unwrap_err();
        assert!(
            err.contains("tool-call"),
            "leak detector's error message must surface to the caller"
        );
    }

    #[test]
    fn description_check_order_length_then_control_then_xml() {
        // A 2001-character string with a NUL inside trips the length
        // check first — the NUL never gets a chance to be reported.
        let mut s = "x".repeat(2000);
        s.push('\0');
        let err = validate_workflow_description(Some(&s)).unwrap_err();
        assert!(err.contains("≤ 2000"), "length error wins");
    }

    #[test]
    fn response_missing_config_payload_is_passed_through_to_checklist() {
        let mut inputs = baseline_inputs();
        let entry = json!({
            "node_id": "synthesize",
            "module": "LLM Inference",
            "missing_required": ["MODEL", "PROMPT"]
        });
        inputs.missing_config = vec![entry.clone()];
        inputs.ready_to_run = false;
        let resp = build_create_workflow_response(inputs);
        // The full structured entry must appear under nodes_needing_config
        // (the checklist is what callers iterate over to fix things).
        assert_eq!(
            resp["next_steps_checklist"][0]["nodes_needing_config"][0],
            entry
        );
    }

    // ── add_node_to_workflow helper tests ───────────────────────────────────

    #[test]
    fn template_warnings_empty_for_plain_config() {
        let cfg = json!({"url": "https://example.com", "count": 5});
        assert!(detect_template_interpolation_warnings(&cfg).is_empty());
    }

    #[test]
    fn template_warnings_detects_single_interpolation() {
        let cfg = json!({"url": "https://api.com/{{user_id}}/profile"});
        let warnings = detect_template_interpolation_warnings(&cfg);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("'url'"));
        assert!(warnings[0].contains("user_id"));
    }

    #[test]
    fn template_warnings_skips_non_string_values() {
        let cfg = json!({
            "count": 5,
            "active": true,
            "tags": ["{{tag}}"]
        });
        // Only top-level string values are scanned; the array is ignored.
        assert!(detect_template_interpolation_warnings(&cfg).is_empty());
    }

    #[test]
    fn template_warnings_handles_non_object_config() {
        // Caller passed a string / null / array — defensively return empty.
        assert!(detect_template_interpolation_warnings(&json!(null)).is_empty());
        assert!(detect_template_interpolation_warnings(&json!("x")).is_empty());
        assert!(detect_template_interpolation_warnings(&json!([])).is_empty());
    }

    #[test]
    fn upsert_edges_adds_connect_from() {
        let mut edges = vec![];
        upsert_node_edges(&mut edges, "n2", Some("n1"), None);
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0]["source"], "n1");
        assert_eq!(edges[0]["target"], "n2");
    }

    #[test]
    fn upsert_edges_adds_connect_to() {
        let mut edges = vec![];
        upsert_node_edges(&mut edges, "n2", None, Some("n3"));
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0]["source"], "n2");
        assert_eq!(edges[0]["target"], "n3");
    }

    #[test]
    fn upsert_edges_dedups_existing_edge() {
        let mut edges = vec![json!({"source": "n1", "target": "n2"})];
        upsert_node_edges(&mut edges, "n2", Some("n1"), None);
        // Should not duplicate.
        assert_eq!(edges.len(), 1);
    }

    #[test]
    fn upsert_edges_inserts_between_when_both_set() {
        // Pre-existing direct edge n1→n3 is removed when we insert n2 between.
        let mut edges = vec![json!({"source": "n1", "target": "n3"})];
        upsert_node_edges(&mut edges, "n2", Some("n1"), Some("n3"));
        assert_eq!(edges.len(), 2);
        assert!(edges
            .iter()
            .any(|e| e["source"] == "n1" && e["target"] == "n2"));
        assert!(edges
            .iter()
            .any(|e| e["source"] == "n2" && e["target"] == "n3"));
        // The bypass edge is gone.
        assert!(!edges
            .iter()
            .any(|e| e["source"] == "n1" && e["target"] == "n3"));
    }

    #[test]
    fn upsert_edges_no_args_is_noop() {
        let mut edges = vec![json!({"source": "x", "target": "y"})];
        upsert_node_edges(&mut edges, "n2", None, None);
        assert_eq!(edges.len(), 1);
    }

    #[test]
    fn build_node_uses_caller_config_when_explicit() {
        let cfg = json!({"url": "https://example.com"});
        let node = build_add_node_payload(AddNodeInputs {
            node_id: "n1",
            module_id: "abc",
            config: cfg.clone(),
            last_y: 100.0,
            existing_node: None,
            timeout_secs: None,
            retry_count: None,
            retry_backoff_ms: None,
            retry_condition: None,
            retry_delay_expression: None,
            skip_condition: None,
            continue_on_error: None,
            template_max_retries: None,
        });
        assert_eq!(node["id"], "n1");
        assert_eq!(node["type"], "abc");
        assert_eq!(node["data"], cfg);
        assert_eq!(node["position"]["y"], 220.0); // 100 + 120
    }

    #[test]
    fn build_node_applies_template_max_retries_when_no_caller_or_existing() {
        let node = build_add_node_payload(AddNodeInputs {
            node_id: "approval",
            module_id: "human-approval",
            config: json!({}),
            last_y: 0.0,
            existing_node: None,
            timeout_secs: None,
            retry_count: None,
            retry_backoff_ms: None,
            retry_condition: None,
            retry_delay_expression: None,
            skip_condition: None,
            continue_on_error: None,
            template_max_retries: Some(0), // catalog default
        });
        // template_max_retries=0 must surface in retry_count to prevent
        // retry storms on rejection (the human-approval pattern).
        assert_eq!(node["retry_count"], 0);
    }

    #[test]
    fn build_node_caller_arg_wins_over_template_default() {
        let rc = json!(5);
        let node = build_add_node_payload(AddNodeInputs {
            node_id: "x",
            module_id: "y",
            config: json!({}),
            last_y: 0.0,
            existing_node: None,
            timeout_secs: None,
            retry_count: Some(&rc),
            retry_backoff_ms: None,
            retry_condition: None,
            retry_delay_expression: None,
            skip_condition: None,
            continue_on_error: None,
            template_max_retries: Some(0),
        });
        assert_eq!(node["retry_count"], 5);
    }

    #[test]
    fn build_node_preserves_existing_fields_when_caller_omits() {
        let existing = json!({
            "id": "n1",
            "data": {"foo": "bar"},
            "timeout_secs": 60,
            "retry_count": 7,
            "skip_condition": "input.value == null"
        });
        let node = build_add_node_payload(AddNodeInputs {
            node_id: "n1",
            module_id: "rebound",
            config: json!({"foo": "bar"}),
            last_y: 0.0,
            existing_node: Some(&existing),
            timeout_secs: None,
            retry_count: None,
            retry_backoff_ms: None,
            retry_condition: None,
            retry_delay_expression: None,
            skip_condition: None,
            continue_on_error: None,
            template_max_retries: Some(2),
        });
        assert_eq!(node["timeout_secs"], 60);
        assert_eq!(node["retry_count"], 7); // preserved, NOT overridden by template default
        assert_eq!(node["skip_condition"], "input.value == null");
    }

    #[test]
    fn build_node_caller_string_overrides_existing() {
        let existing = json!({"skip_condition": "old"});
        let node = build_add_node_payload(AddNodeInputs {
            node_id: "n1",
            module_id: "x",
            config: json!({}),
            last_y: 0.0,
            existing_node: Some(&existing),
            timeout_secs: None,
            retry_count: None,
            retry_backoff_ms: None,
            retry_condition: None,
            retry_delay_expression: None,
            skip_condition: Some("new"),
            continue_on_error: None,
            template_max_retries: None,
        });
        assert_eq!(node["skip_condition"], "new");
    }

    // ─── wrap_rust_code_with_talos_module ───

    #[test]
    fn wrap_injects_macro_before_fn_run() {
        let src = "fn run(input: String) -> Result<String, String> { Ok(input) }";
        let wrapped = wrap_rust_code_with_talos_module(src, "minimal-node");
        assert!(wrapped.contains("#[talos_sdk_macros::talos_module(world = \"minimal-node\")]"));
        assert!(wrapped.contains("fn run("));
        // Macro line must appear *before* fn run, not after.
        let macro_pos = wrapped.find("#[talos_sdk_macros::talos_module").unwrap();
        let run_pos = wrapped.find("fn run(").unwrap();
        assert!(macro_pos < run_pos);
    }

    #[test]
    fn wrap_injects_pub_fn_run() {
        let src = "pub fn run(input: String) -> Result<String, String> { Ok(input) }";
        let wrapped = wrap_rust_code_with_talos_module(src, "http-node");
        assert!(wrapped.contains("#[talos_sdk_macros::talos_module(world = \"http-node\")]"));
    }

    #[test]
    fn wrap_skips_helpers_targets_run_specifically() {
        let src = "fn helper() {}\nfn run(input: String) -> Result<String, String> { Ok(input) }";
        let wrapped = wrap_rust_code_with_talos_module(src, "minimal-node");
        // Macro must appear AFTER the helper fn but BEFORE fn run — not on the helper.
        let helper_pos = wrapped.find("fn helper()").unwrap();
        let macro_pos = wrapped.find("#[talos_sdk_macros::talos_module").unwrap();
        let run_pos = wrapped.find("fn run(").unwrap();
        assert!(helper_pos < macro_pos);
        assert!(macro_pos < run_pos);
    }

    #[test]
    fn wrap_passthrough_when_already_has_talos_module_attribute() {
        let src = "#[talos_module(world = \"http-node\")]\nfn run() {}";
        let wrapped = wrap_rust_code_with_talos_module(src, "minimal-node");
        assert_eq!(wrapped, src); // unchanged
    }

    #[test]
    fn wrap_passthrough_when_already_has_talos_node_attribute() {
        let src = "#[talos_node]\nfn run() {}";
        let wrapped = wrap_rust_code_with_talos_module(src, "minimal-node");
        assert_eq!(wrapped, src);
    }

    #[test]
    fn wrap_passthrough_when_uses_full_path_macro() {
        let src = "#[talos_sdk_macros::talos_module(world = \"x\")]\nfn run() {}";
        let wrapped = wrap_rust_code_with_talos_module(src, "minimal-node");
        assert_eq!(wrapped, src);
    }

    #[test]
    fn wrap_passthrough_when_uses_wit_bindgen() {
        let src = "wit_bindgen::generate!({ world: \"x\" });\nfn run() {}";
        let wrapped = wrap_rust_code_with_talos_module(src, "minimal-node");
        assert_eq!(wrapped, src);
    }

    #[test]
    fn wrap_returns_source_verbatim_when_no_fn_run() {
        let src = "fn other() { 1 }";
        let wrapped = wrap_rust_code_with_talos_module(src, "minimal-node");
        assert_eq!(wrapped, src); // no-op; downstream compile error is the right surface
    }

    // ─── resolve_default_allowed_hosts ───

    #[test]
    fn allowed_hosts_explicit_short_circuits() {
        let explicit = vec!["api.example.com".to_string()];
        let out = resolve_default_allowed_hosts("minimal-node", Some(explicit.clone()));
        assert_eq!(out, explicit);
    }

    #[test]
    fn allowed_hosts_explicit_empty_short_circuits() {
        // Caller explicitly passing [] means "no hosts" — must be respected, not
        // expanded to a wildcard even if the world is network-capable.
        let out = resolve_default_allowed_hosts("http-node", Some(vec![]));
        assert_eq!(out, Vec::<String>::new());
    }

    #[test]
    fn allowed_hosts_default_for_http_world() {
        let out = resolve_default_allowed_hosts("http-node", None);
        assert_eq!(out, vec!["*".to_string()]);
    }

    #[test]
    fn allowed_hosts_default_for_network_world() {
        let out = resolve_default_allowed_hosts("network-egress", None);
        assert_eq!(out, vec!["*".to_string()]);
    }

    #[test]
    fn allowed_hosts_default_for_secrets_world() {
        let out = resolve_default_allowed_hosts("secrets-handler", None);
        assert_eq!(out, vec!["*".to_string()]);
    }

    #[test]
    fn allowed_hosts_default_for_automation_world() {
        let out = resolve_default_allowed_hosts("automation-node", None);
        assert_eq!(out, vec!["*".to_string()]);
    }

    #[test]
    fn allowed_hosts_default_for_database_world() {
        let out = resolve_default_allowed_hosts("database-node", None);
        assert_eq!(out, vec!["*".to_string()]);
    }

    #[test]
    fn allowed_hosts_default_empty_for_minimal_world() {
        let out = resolve_default_allowed_hosts("minimal-node", None);
        assert!(out.is_empty());
    }

    // ─── format_shared_module_overwrite_error ───

    #[test]
    fn shared_overwrite_error_lists_users() {
        let id = Uuid::new_v4();
        let other = vec![
            (Uuid::new_v4(), "wf-alpha".to_string()),
            (Uuid::new_v4(), "wf-beta".to_string()),
        ];
        let msg = format_shared_module_overwrite_error("my-node", id, &other);
        assert!(msg.contains("my-node"));
        assert!(msg.contains(&id.to_string()));
        assert!(msg.contains("wf-alpha"));
        assert!(msg.contains("wf-beta"));
        assert!(msg.contains("2 other live workflow(s)"));
        // No "and N more" summary line for ≤5 entries.
        assert!(!msg.contains("… and "));
    }

    #[test]
    fn shared_overwrite_error_truncates_to_first_five() {
        let id = Uuid::new_v4();
        let mut other: Vec<(Uuid, String)> = (0..10)
            .map(|i| (Uuid::new_v4(), format!("wf-{i}")))
            .collect();
        let msg = format_shared_module_overwrite_error("n", id, &other);
        // First 5 are inlined.
        for i in 0..5 {
            assert!(msg.contains(&format!("wf-{i}")));
        }
        // Items past 5 are summarised, not listed.
        assert!(msg.contains("… and 5 more"));
        assert!(!msg.contains("wf-7")); // sanity: any one of 5..10 should NOT appear inline
        other.truncate(0);
    }

    // ─── compute_permission_drift ───

    /// Test helper: build a `StoredPermissions` with no recorded
    /// capability_world (legacy / migration default). Used by tests
    /// that don't exercise the world-drift branch so they don't
    /// accidentally trip it.
    fn stored_no_world(
        allowed_hosts: Vec<String>,
        allowed_secrets: Vec<String>,
        allowed_methods: Vec<String>,
    ) -> StoredPermissions {
        StoredPermissions {
            allowed_hosts,
            allowed_secrets,
            allowed_methods,
            capability_world: String::new(),
        }
    }

    #[test]
    fn drift_empty_when_caller_omits_all() {
        let stored = stored_no_world(
            vec!["api.example.com".to_string()],
            vec!["k1".to_string()],
            vec!["GET".to_string()],
        );
        let drift = compute_permission_drift(None, None, None, None, &stored);
        assert!(drift.is_empty());
    }

    #[test]
    fn drift_empty_when_explicit_matches_stored() {
        let stored = stored_no_world(
            vec!["a".to_string(), "b".to_string()],
            vec!["x".to_string()],
            vec!["GET".to_string()],
        );
        let h = vec!["a".to_string(), "b".to_string()];
        let s = vec!["x".to_string()];
        let m = vec!["GET".to_string()];
        let drift = compute_permission_drift(Some(&h), Some(&s), Some(&m), None, &stored);
        assert!(drift.is_empty());
    }

    #[test]
    fn drift_sort_order_independence() {
        // Differing iteration order must not be reported as drift.
        let stored = stored_no_world(vec!["b".to_string(), "a".to_string()], vec![], vec![]);
        let explicit = vec!["a".to_string(), "b".to_string()];
        let drift = compute_permission_drift(Some(&explicit), None, None, None, &stored);
        assert!(drift.is_empty());
    }

    #[test]
    fn drift_treats_duplicates_as_equivalent() {
        // Caller-listed dupes must not be reported as drift against the
        // dedup'd stored list.
        let stored = stored_no_world(vec!["a".to_string()], vec![], vec![]);
        let explicit = vec!["a".to_string(), "a".to_string()];
        let drift = compute_permission_drift(Some(&explicit), None, None, None, &stored);
        assert!(drift.is_empty());
    }

    #[test]
    fn drift_detects_hosts_mismatch() {
        let stored = stored_no_world(vec!["old.example.com".to_string()], vec![], vec![]);
        let explicit = vec!["new.example.com".to_string()];
        let drift = compute_permission_drift(Some(&explicit), None, None, None, &stored);
        assert_eq!(drift.len(), 1);
        assert!(drift[0].contains("allowed_hosts"));
        assert!(drift[0].contains("old.example.com"));
        assert!(drift[0].contains("new.example.com"));
    }

    #[test]
    fn drift_detects_secrets_mismatch_only() {
        let stored = stored_no_world(
            vec!["a".to_string()],
            vec!["k1".to_string()],
            vec!["GET".to_string()],
        );
        // Hosts + methods match; only secrets differ.
        let h = vec!["a".to_string()];
        let s = vec!["k2".to_string()];
        let m = vec!["GET".to_string()];
        let drift = compute_permission_drift(Some(&h), Some(&s), Some(&m), None, &stored);
        assert_eq!(drift.len(), 1);
        assert!(drift[0].contains("allowed_secrets"));
    }

    #[test]
    fn drift_detects_methods_length_mismatch() {
        let stored = stored_no_world(vec![], vec![], vec!["GET".to_string(), "POST".to_string()]);
        let m = vec!["GET".to_string()];
        let drift = compute_permission_drift(None, None, Some(&m), None, &stored);
        assert_eq!(drift.len(), 1);
        assert!(drift[0].contains("allowed_methods"));
    }

    #[test]
    fn drift_formats_empty_list_as_brackets() {
        let stored = stored_no_world(vec!["a".to_string()], vec![], vec![]);
        let h: Vec<String> = Vec::new();
        let drift = compute_permission_drift(Some(&h), None, None, None, &stored);
        assert_eq!(drift.len(), 1);
        assert!(drift[0].contains("requested=[]"));
    }

    // ─── L-finding-1: capability_world drift ───

    /// Caller omits world → no drift, even if stored has a value.
    /// Preserves the pre-L-finding-1 caller semantics (omit = inherit).
    #[test]
    fn drift_world_omitted_is_no_drift() {
        let stored = StoredPermissions {
            allowed_hosts: vec![],
            allowed_secrets: vec![],
            allowed_methods: vec![],
            capability_world: "http-node".to_string(),
        };
        let drift = compute_permission_drift(None, None, None, None, &stored);
        assert!(drift.is_empty());
    }

    /// Caller explicit matches stored → no drift.
    #[test]
    fn drift_world_matching_is_no_drift() {
        let stored = StoredPermissions {
            allowed_hosts: vec![],
            allowed_secrets: vec![],
            allowed_methods: vec![],
            capability_world: "http-node".to_string(),
        };
        let drift = compute_permission_drift(None, None, None, Some("http-node"), &stored);
        assert!(drift.is_empty());
    }

    /// `"http"` and `"http-node"` normalise to the same world →
    /// no drift. Mirrors the inline-compile-service's tolerance
    /// for both forms in caller input.
    #[test]
    fn drift_world_normalises_short_form() {
        let stored = StoredPermissions {
            allowed_hosts: vec![],
            allowed_secrets: vec![],
            allowed_methods: vec![],
            capability_world: "http-node".to_string(),
        };
        let drift = compute_permission_drift(None, None, None, Some("http"), &stored);
        assert!(drift.is_empty(), "got drift: {drift:?}");
    }

    /// Caller asks for a different world → drift. The capability-
    /// upgrade case (http-node stored, agent-node requested) — the
    /// exact silent-escalation gap this fix closes.
    #[test]
    fn drift_world_upgrade_detected() {
        let stored = StoredPermissions {
            allowed_hosts: vec![],
            allowed_secrets: vec![],
            allowed_methods: vec![],
            capability_world: "http-node".to_string(),
        };
        let drift = compute_permission_drift(None, None, None, Some("agent-node"), &stored);
        assert_eq!(drift.len(), 1);
        assert!(drift[0].contains("capability_world"));
        assert!(drift[0].contains("http-node"));
        assert!(drift[0].contains("agent-node"));
    }

    /// Caller asks for a NARROWER world → also drift. Capability
    /// CHANGE in either direction should surface, not just upgrades.
    /// A narrower world might fail to import host functions the
    /// existing graph expects.
    #[test]
    fn drift_world_downgrade_also_detected() {
        let stored = StoredPermissions {
            allowed_hosts: vec![],
            allowed_secrets: vec![],
            allowed_methods: vec![],
            capability_world: "agent-node".to_string(),
        };
        let drift = compute_permission_drift(None, None, None, Some("http-node"), &stored);
        assert_eq!(drift.len(), 1);
        assert!(drift[0].contains("capability_world"));
    }

    /// Legacy row with empty `capability_world` → caller-explicit
    /// world does NOT trigger drift (no anchor to compare). This
    /// preserves the migration path for existing modules without
    /// forcing a "drift" message on every existing row.
    #[test]
    fn drift_world_empty_stored_skips_check() {
        let stored = StoredPermissions {
            allowed_hosts: vec![],
            allowed_secrets: vec![],
            allowed_methods: vec![],
            capability_world: String::new(),
        };
        let drift = compute_permission_drift(None, None, None, Some("agent-node"), &stored);
        assert!(drift.is_empty());
    }

    /// Mixed drift: world AND hosts mismatch produce two lines.
    /// Confirms world drift composes with the other fields rather
    /// than short-circuiting them.
    #[test]
    fn drift_world_and_hosts_both_reported() {
        let stored = StoredPermissions {
            allowed_hosts: vec!["api.old.com".to_string()],
            allowed_secrets: vec![],
            allowed_methods: vec![],
            capability_world: "http-node".to_string(),
        };
        let h = vec!["api.new.com".to_string()];
        let drift = compute_permission_drift(Some(&h), None, None, Some("agent-node"), &stored);
        assert_eq!(drift.len(), 2);
        let joined = drift.join("\n");
        assert!(joined.contains("allowed_hosts"));
        assert!(joined.contains("capability_world"));
    }

    // ─── format_permission_drift_error ───

    #[test]
    fn permission_drift_error_includes_node_id_module_id_and_drift_lines() {
        let id = Uuid::new_v4();
        let lines = vec!["  - allowed_hosts: stored=[a] vs requested=[b]".to_string()];
        let msg = format_permission_drift_error("my-node", id, &lines);
        assert!(msg.contains("my-node"));
        assert!(msg.contains(&id.to_string()));
        assert!(msg.contains("allowed_hosts"));
        assert!(msg.contains("update_module_hosts"));
    }
}
