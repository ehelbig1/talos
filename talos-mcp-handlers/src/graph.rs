use super::types::JsonRpcResponse;
use super::utils::{compute_mcp_graph_diff, mcp_error, mcp_text, mcp_text_with_json};
use super::{auth, McpState};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

// Thread-local Rhai validation engine — created once per thread, reused for syntax checks.
// `rhai::Engine` contains `Rc` and is not `Send`; `thread_local!` avoids that constraint.
// We only use `compile` for syntax validation; no scripts are executed.
std::thread_local! {
    static RHAI_VALIDATION_ENGINE: rhai::Engine = {
        let mut e = rhai::Engine::new_raw();
        e.disable_symbol("eval");
        e
    };
}

fn with_rhai_validation_engine<F, R>(f: F) -> R
where
    F: FnOnce(&rhai::Engine) -> R,
{
    RHAI_VALIDATION_ENGINE.with(f)
}

/// Compile-only Rhai syntax check used by every handler that accepts a
/// user-supplied expression (edge condition, retry condition, retry
/// delay, dispatch expression, skip condition, …).
///
/// On failure, returns a single user-facing error string that names the
/// `field_name` and includes the line/column from `rhai::ParseError`.
/// Callers map this to MCP -32602 verbatim — no error-class branching
/// needed.
fn validate_rhai_expression(field_name: &str, source: &str) -> Result<(), String> {
    with_rhai_validation_engine(|eng| eng.compile(source)).map_err(|e| {
        format!(
            "{} Rhai syntax error at line {}, column {}: {}",
            field_name,
            e.position().line().unwrap_or(0),
            e.position().position().unwrap_or(0),
            e
        )
    })?;
    Ok(())
}

/// Apply an RFC 7386 JSON Merge Patch to `target` in place.
///
/// Backs the `merge_config` action on `update_node_config` (DX pain
/// point 21, found live 2026-07-14): `update_config` REPLACES a node's
/// whole config object, so an operator setting `{"DRY_RUN": false}`
/// via `update_config` silently wiped every sibling key (`TO`,
/// `AUTH_HEADER`, ...) — a patch-sounding name with replace semantics
/// and zero warning. `merge_config` gives callers real patch semantics.
///
/// Semantics (RFC 7386 §2, transcribed from the spec's pseudocode):
/// - If `patch` is not a JSON object, `target` is replaced wholesale
///   by `patch` (covers scalar/array/null patches).
/// - Otherwise, for each key in `patch`: a `null` value DELETES that
///   key from `target`; an object value recurses (resetting the
///   target's existing value to `{}` first if it isn't already an
///   object — RFC 7386 discards non-object targets rather than
///   merging onto them); any other value REPLACES the key verbatim.
pub(crate) fn json_merge_patch(target: &mut serde_json::Value, patch: &serde_json::Value) {
    let Some(patch_obj) = patch.as_object() else {
        // Patch is a scalar / array / null: wholesale replace.
        *target = patch.clone();
        return;
    };

    if !target.is_object() {
        *target = serde_json::json!({});
    }
    // Safe: just ensured `target` is an object above.
    let target_obj = target.as_object_mut().expect("target is an object");

    for (key, patch_value) in patch_obj {
        if patch_value.is_null() {
            target_obj.remove(key);
        } else if patch_value.is_object() {
            let entry = target_obj
                .entry(key.clone())
                .or_insert_with(|| serde_json::json!({}));
            if !entry.is_object() {
                *entry = serde_json::json!({});
            }
            json_merge_patch(entry, patch_value);
        } else {
            target_obj.insert(key.clone(), patch_value.clone());
        }
    }
}

/// Top-level keys present in `old` but absent from `new`.
///
/// Used by `update_config` (the replace-semantics action) to surface
/// which config keys a wholesale replace silently dropped — so the
/// caller learns about the wipe from the SUCCESS response, not from
/// the next scheduled run failing with "Missing X config". Returns an
/// empty `Vec` when `old` isn't an object (nothing meaningful was
/// "present" to drop).
fn dropped_top_level_keys(old: &serde_json::Value, new: &serde_json::Value) -> Vec<String> {
    let Some(old_obj) = old.as_object() else {
        return Vec::new();
    };
    let new_obj = new.as_object();
    let mut dropped: Vec<String> = old_obj
        .keys()
        .filter(|k| !new_obj.is_some_and(|n| n.contains_key(*k)))
        .cloned()
        .collect();
    dropped.sort();
    dropped
}

/// Insert a system node into the graph's `nodes` array, replacing an
/// existing node with the same `id` if one is present (upsert) instead
/// of blindly pushing a duplicate.
///
/// Without this, every system-node tool (add_loop_node, add_sub_workflow_node,
/// add_capability_dispatch_node, …) silently accumulates duplicate
/// node IDs when called twice with the same `node_id`. The runtime
/// engine picks whichever entry appears first, so "updating" a node's
/// config via re-call actually leaves the original in place and hides
/// a stale copy of the config at the stale entry. Matches the
/// idempotent/upsert semantics already documented on
/// `add_node_to_workflow`.
fn upsert_system_node_into_graph(graph: &mut serde_json::Value, node: serde_json::Value) {
    let Some(new_id) = crate::utils::json_optional_string(&node, "id") else {
        return;
    };
    if let Some(nodes) = graph.get_mut("nodes").and_then(|n| n.as_array_mut()) {
        if let Some(existing_idx) = nodes
            .iter()
            .position(|n| n.get("id").and_then(|v| v.as_str()) == Some(new_id.as_str()))
        {
            nodes[existing_idx] = node;
        } else {
            nodes.push(node);
        }
    }
}

/// Fetch the graph_json for a workflow via the repository, returning a
/// standard MCP error response when the workflow is not found.
async fn fetch_graph_json(
    state: &McpState,
    wf_id: Uuid,
    user_id: Uuid,
    req_id: &Option<serde_json::Value>,
) -> Result<String, JsonRpcResponse> {
    match state.workflow_repo.get_workflow_graph(wf_id, user_id).await {
        Ok(Some(gj)) => Ok(gj),
        Ok(None) => Err(mcp_error(
            req_id.clone(),
            -32000,
            "Workflow not found or access denied",
        )),
        Err(e) => {
            tracing::error!("fetch_graph_json: {}", e);
            Err(mcp_error(
                req_id.clone(),
                -32000,
                "Failed to fetch workflow",
            ))
        }
    }
}

/// Fetch graph_json without ownership check (used by system-node builders
/// that have already verified ownership).
async fn fetch_graph_json_unchecked(
    state: &McpState,
    wf_id: Uuid,
    req_id: &Option<serde_json::Value>,
) -> Result<String, JsonRpcResponse> {
    match state
        .workflow_repo
        .get_workflow_graph_unchecked(wf_id)
        .await
    {
        Ok(Some(gj)) => Ok(gj),
        Ok(None) => Err(mcp_error(req_id.clone(), -32000, "Workflow not found")),
        Err(e) => {
            tracing::error!("fetch_graph_json_unchecked: {}", e);
            Err(mcp_error(
                req_id.clone(),
                -32000,
                "Failed to fetch workflow",
            ))
        }
    }
}

/// MCP-11: HTML-decode Rhai-expression fields in graph_json before
/// persistence. Every node-config write path bottlenecks through
/// `save_graph_json` / `save_graph_json_unchecked`, so applying the
/// decode here covers `update_node_config`, `add_node_to_workflow`,
/// `add_skip_condition`, `add_synthesize_node`, and every other
/// system-node setter in one shot. The runtime decode in
/// `talos_engine::rhai_helpers` is the safety net; this is the
/// canonicalisation that prevents `get_workflow_raw_json` from
/// surfacing the encoded form back to inspectors.
///
/// On parse failure (graph_json is not valid JSON) we save the
/// payload as-is — the persistence layer's own validation will then
/// reject it with a clearer error than "decode_rhai_in_graph
/// silently mutated unparseable bytes".
fn canonicalise_rhai_in_graph_json(graph_json: &str) -> std::borrow::Cow<'_, str> {
    let Ok(mut parsed) = serde_json::from_str::<serde_json::Value>(graph_json) else {
        return std::borrow::Cow::Borrowed(graph_json);
    };
    let decoded_sites = talos_text_util::decode_rhai_in_graph(&mut parsed);
    if decoded_sites == 0 {
        return std::borrow::Cow::Borrowed(graph_json);
    }
    match serde_json::to_string(&parsed) {
        Ok(s) => std::borrow::Cow::Owned(s),
        Err(_) => std::borrow::Cow::Borrowed(graph_json),
    }
}

/// Save updated graph_json for a workflow via the repository, returning a
/// standard MCP error response on failure.
///
/// MCP-1226 (2026-05-18): canonical-validator chokepoint for every
/// in-Rust graph mutation. Pre-fix `update_node_config` with
/// `action: "update_config", config: { timeout_secs: 86400,
/// retry_count: 9000, retry_backoff_ms: 99999999 }` wrote those
/// over-cap values straight through `save_graph_json` to the DB —
/// `validate_graph_timeouts` was only invoked at `create_workflow` /
/// `update_workflow` / `import_workflow` time, so any mutation tool
/// that loads-modify-saves the graph (`update_node_config`,
/// `add_node_to_workflow`, `add_edge_to_workflow`, `add_skip_condition`,
/// the 20+ system-node add_* tools, etc.) bypassed the MCP-1218 /
/// MCP-1219 / MCP-1220 / MCP-1221 caps entirely. Live-verified:
/// timeout_secs: 86400 (max 600), retry_count: 9000 (max 100),
/// retry_backoff_ms: 99999999 (max 600000) all persisted.
///
/// Routing the canonical validator through the persistence helper
/// closes every current bypass path AND any future graph-mutation
/// tool inherits the contract for free — same `push validator into
/// the canonical helper` pattern as MCP-1224 (memory_key at
/// `persist_memory_with_metadata`).
async fn save_graph_json(
    state: &McpState,
    wf_id: Uuid,
    user_id: Uuid,
    graph_json: &str,
    req_id: &Option<serde_json::Value>,
) -> Result<(), JsonRpcResponse> {
    let canonical = canonicalise_rhai_in_graph_json(graph_json);
    crate::utils::ensure_graph_within_caps(canonical.as_ref(), req_id)?;
    match state
        .workflow_repo
        .update_workflow_graph(wf_id, user_id, canonical.as_ref())
        .await
    {
        Ok(_) => Ok(()),
        Err(e) => {
            tracing::error!("save_graph_json: {}", e);
            Err(mcp_error(
                req_id.clone(),
                -32000,
                "Failed to save workflow graph",
            ))
        }
    }
}

/// Save updated graph_json without user_id ownership check (used by handlers
/// that have already verified ownership earlier in the call).
async fn save_graph_json_unchecked(
    state: &McpState,
    wf_id: Uuid,
    graph_json: &str,
    req_id: &Option<serde_json::Value>,
) -> Result<(), JsonRpcResponse> {
    let canonical = canonicalise_rhai_in_graph_json(graph_json);
    crate::utils::ensure_graph_within_caps(canonical.as_ref(), req_id)?;
    match state
        .workflow_repo
        .update_workflow_graph_unchecked(wf_id, canonical.as_ref())
        .await
    {
        Ok(_) => Ok(()),
        Err(e) => {
            tracing::error!("save_graph_json_unchecked: {}", e);
            Err(mcp_error(
                req_id.clone(),
                -32000,
                "Failed to save workflow graph",
            ))
        }
    }
}

/// What to do after a graph mutation, decided from the
/// `workflow_has_active_version` probe. Pulled out as a pure function so
/// the publish-or-skip decision is unit-testable without a database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PublishAction {
    /// Workflow has an active published version — publish a new one to
    /// keep the published copy in sync with the edited draft.
    Publish,
    /// Draft-only workflow (never published) — nothing to sync, stay draft.
    Skip,
    /// Couldn't determine published-version status (DB hiccup) — warn +
    /// skip, and tell the operator to publish manually if needed.
    ProbeFailed,
}

/// Decide the post-mutation publish action from the
/// `workflow_has_active_version` probe result. `None` = probe errored.
pub(crate) fn decide_publish_action(has_active_version: Option<bool>) -> PublishAction {
    match has_active_version {
        Some(true) => PublishAction::Publish,
        Some(false) => PublishAction::Skip,
        None => PublishAction::ProbeFailed,
    }
}

/// Outcome of [`maybe_auto_publish`]. Carries the message suffix that
/// each graph-mutating handler appends to its response so the operator
/// learns whether the published version was kept in sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AutoPublishOutcome {
    /// Draft-only workflow — no publish attempted (empty suffix).
    DraftOnly,
    /// A fresh version was published to keep the published copy in sync.
    Published,
    /// Auto-publish was attempted but failed — draft saved, published stale.
    PublishFailed,
    /// Published-version status could not be probed (DB hiccup).
    ProbeFailed,
}

impl AutoPublishOutcome {
    /// The (space-prefixed) message suffix to append to a handler's
    /// response text. Empty for the draft-only case. Mirrors the exact
    /// wording `update_node_config` used before this was generalized.
    pub(crate) fn message_suffix(self) -> &'static str {
        match self {
            AutoPublishOutcome::DraftOnly => "",
            AutoPublishOutcome::Published => {
                " Auto-published new version to keep published workflow in sync."
            }
            AutoPublishOutcome::PublishFailed => {
                " Warning: auto-publish failed; the draft was saved but the published version is \
                 out of sync. Run publish_version manually."
            }
            AutoPublishOutcome::ProbeFailed => {
                " Warning: couldn't verify published-version status (DB hiccup). If this workflow \
                 has a published version, run publish_version to apply the change."
            }
        }
    }

    /// Whether a new version was actually published. Exercised by the
    /// unit tests (asserts published→true, draft-only/failure→false);
    /// kept as a first-class accessor so callers that want to branch on
    /// "did we sync?" don't re-`matches!` the variant.
    #[allow(dead_code)]
    pub(crate) fn published(self) -> bool {
        matches!(self, AutoPublishOutcome::Published)
    }
}

/// Auto-publish a new workflow version after a graph mutation, when — and
/// only when — the workflow already has an active published version.
///
/// This is the ONE shared implementation of the "keep published in sync"
/// behavior. Since PR #531 every trigger path (manual, MCP `call_workflow`,
/// scheduler) runs the ACTIVE PUBLISHED version of a workflow, so a graph
/// edit made through any mutation tool silently never executes until an
/// explicit `publish_version`. Historically only `update_node_config`
/// auto-published; every other graph-mutating handler
/// (`add_node_to_workflow`, `add_edge_to_workflow`, `swap_node_module`,
/// the `add_*_node` system-node setters, standalone `add_edge`/`remove_edge`,
/// …) left the published copy stale — that cost 30 min of live debugging
/// on 2026-07-21 ("the classify node didn't run"). Routing every mutation
/// through this helper makes the behavior uniform.
///
/// Draft-only workflows (never published) stay drafts. The caller is
/// expected to have already persisted the new graph via `save_graph_json`
/// (or the repository's `update_workflow_graph[_unchecked]`) — this only
/// snapshots the just-saved `workflows.graph_json` into a new active
/// version. Validation is deliberately skipped on the sync publish (the
/// `None` arg) — the draft was already accepted by the mutation.
pub(crate) async fn maybe_auto_publish(
    state: &McpState,
    wf_id: Uuid,
    user_id: Uuid,
    description: &str,
) -> AutoPublishOutcome {
    let probe = state.workflow_repo.workflow_has_active_version(wf_id).await;
    let has_active = match probe {
        Ok(v) => Some(v),
        Err(ref e) => {
            tracing::warn!(
                target: "talos_audit",
                workflow_id = %wf_id,
                error = %e,
                "auto-publish: couldn't probe workflow_has_active_version — skipped"
            );
            None
        }
    };
    match decide_publish_action(has_active) {
        PublishAction::Skip => AutoPublishOutcome::DraftOnly,
        PublishAction::ProbeFailed => AutoPublishOutcome::ProbeFailed,
        PublishAction::Publish => {
            match talos_workflow_versions::WorkflowVersionService::publish_version(
                &state.db_pool,
                wf_id,
                user_id,
                Some(description.to_string()),
                None, // skip validation on auto-publish sync
            )
            .await
            {
                Ok((_v, _warnings)) => AutoPublishOutcome::Published,
                Err(e) => {
                    tracing::error!(err = ?e, workflow_id = %wf_id, "Auto-publish after graph mutation failed");
                    AutoPublishOutcome::PublishFailed
                }
            }
        }
    }
}

/// Shape returned by [`upsert_system_node`]. Carries the verified
/// workflow_id + node_id plus pre-formatted wiring strings so handler
/// bodies can splice them into their response text without re-
/// implementing the formatting for each node kind.
pub(crate) struct AddedSystemNode {
    pub workflow_id: Uuid,
    pub node_id: String,
    pub wiring_in: String,
    /// Trailing text spliced after `wiring_in` in the handler's response —
    /// the outgoing-edge line PLUS the auto-publish sync note (see
    /// [`maybe_auto_publish`]). Folding the note here means every handler
    /// that already prints `wiring_out` surfaces the "kept published in
    /// sync" status for free. Handlers that build their own response body
    /// (loop/collect/dispatch/…) instead read `auto_publish_note`.
    pub wiring_out: String,
    /// The bare auto-publish sync note (possibly empty), for handlers that
    /// don't print `wiring_out` and want to append it to their own message.
    pub auto_publish_note: String,
}

/// Shared boilerplate for `add_*_node` MCP handlers that write a
/// single system-kind node into a workflow graph. Handles:
///
/// - `workflow_id` parse + ownership check (auth gate BEFORE any
///   other lookups, so errors don't leak whether a foreign workflow
///   or node exists).
/// - `node_id` validation via `require_node_id`.
/// - Graph JSON fetch → upsert the new node with the supplied `kind`
///   + `data` → save back through the repository.
/// - `connect_from` (string or array, capped at 50) and `connect_to`
///   (single string) edge wiring.
/// - Pre-formatted `wiring_in` / `wiring_out` strings for splicing
///   into the handler's response text.
///
/// Callers are left with just the kind-specific work: parse extra
/// params, validate them, build the `data` JSON, call this helper,
/// format the response string using the returned [`AddedSystemNode`].
///
/// Before this existed, every system-node handler (~80 lines each)
/// repeated the same 8-step ritual. Three real bugs in review came
/// from drift between the per-handler copies — e.g. one handler
/// missed the `.filter(|s| uuid::Uuid::parse_str(s).is_ok())` pattern
/// and silently accepted malformed UUIDs. Routing every handler
/// through one path makes the contract uniform and each handler
/// inspectable in one screen.
pub(crate) async fn upsert_system_node(
    req_id: &Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: &auth::AgentIdentity,
    kind: &str,
    data: serde_json::Value,
) -> Result<AddedSystemNode, JsonRpcResponse> {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let workflow_id = match args
        .get("workflow_id")
        .and_then(|v| v.as_str())
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
    {
        Some(id) => id,
        None => {
            return Err(mcp_error(
                req_id.clone(),
                -32602,
                "Missing or invalid 'workflow_id' parameter",
            ))
        }
    };
    let node_id = crate::utils::require_node_id(args, "node_id", req_id.clone())?;

    if !state
        .workflow_repo
        .workflow_exists(workflow_id, user_id)
        .await
    {
        return Err(crate::utils::workflow_not_found_error(req_id.clone()));
    }

    let graph_json_str = fetch_graph_json_unchecked(state, workflow_id, req_id).await?;
    let mut graph: serde_json::Value = serde_json::from_str(&graph_json_str)
        .unwrap_or_else(|_| serde_json::json!({"nodes": [], "edges": []}));

    let new_node = serde_json::json!({
        "id": node_id,
        "type": format!("system:{}", kind),
        "kind": kind,
        "data": data,
        "position": { "x": 300, "y": 300 }
    });
    upsert_system_node_into_graph(&mut graph, new_node);

    let connect_from_sources: Vec<String> = match args.get("connect_from") {
        Some(serde_json::Value::String(s)) => vec![s.clone()],
        Some(serde_json::Value::Array(arr)) => {
            if arr.len() > 50 {
                return Err(mcp_error(
                    req_id.clone(),
                    -32602,
                    "connect_from must contain ≤ 50 source nodes",
                ));
            }
            arr.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        }
        _ => vec![],
    };
    let connect_to = args
        .get("connect_to")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    if let Some(edges) = graph.get_mut("edges").and_then(|e| e.as_array_mut()) {
        for from in &connect_from_sources {
            edges.push(serde_json::json!({ "source": from, "target": &node_id }));
        }
        if let Some(ref to) = connect_to {
            edges.push(serde_json::json!({ "source": &node_id, "target": to }));
        }
    }

    save_graph_json(
        state,
        workflow_id,
        user_id,
        &serde_json::to_string(&graph).unwrap_or_default(),
        req_id,
    )
    .await?;

    let auto_publish_note = maybe_auto_publish(
        state,
        workflow_id,
        user_id,
        &format!("Auto-published after adding {} node", kind),
    )
    .await
    .message_suffix()
    .to_string();

    let wiring_in = if !connect_from_sources.is_empty() {
        format!("\nWired: {} → {}", connect_from_sources.join(", "), node_id)
    } else {
        String::new()
    };
    let mut wiring_out = connect_to
        .map(|t| format!("\nWired: {} → {}", node_id, t))
        .unwrap_or_default();
    // Fold the auto-publish note into wiring_out so every handler that
    // already splices wiring_out surfaces it; the raw note is also
    // exposed for handlers that build a bespoke response body.
    wiring_out.push_str(&auto_publish_note);

    Ok(AddedSystemNode {
        workflow_id,
        node_id,
        wiring_in,
        wiring_out,
        auto_publish_note,
    })
}

pub fn tool_schemas() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
            "name": "update_node_config",
            "description": "Update a node's configuration, retry settings, or position; or remove a node or edge. \
                Prefer the dedicated remove_edge tool for edge removal and the standalone node delete via \
                workflow graph tools for node removal — they have clearer required-field contracts. \
                \
                IMPORTANT — update_config vs merge_config: 'update_config' REPLACES the node's entire \
                config object with the given 'config' value — any existing key not present in the new \
                value is DROPPED (its success response reports what was dropped as 'dropped_keys', but \
                the drop already happened). 'merge_config' applies 'config' as an RFC 7386 JSON Merge \
                Patch ONTO the existing config: objects merge key-by-key, scalars/arrays replace just \
                that key, and an explicit `null` deletes just that key — every other existing key is left \
                untouched. Use merge_config when you only want to change one or two keys (e.g. toggling \
                DRY_RUN) without restating the whole config; use update_config when you intend a full \
                replace and have the complete config in hand. \
                Required fields per action: \
                update_config — workflow_id, node_id, config (replaces the whole config); \
                merge_config — workflow_id, node_id, config (RFC 7386 merge patch onto the existing config; null deletes a key); \
                update_retry — workflow_id, node_id, plus any retry_* fields; \
                update_position — workflow_id, node_id, x, y; \
                remove_node — workflow_id, node_id; \
                remove_edge — workflow_id, edge_source, edge_target.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string" },
                    "node_id": { "type": "string", "description": "Node to update or remove (required for all actions except remove_edge)" },
                    "action": {
                        "type": "string",
                        "enum": ["update_config", "merge_config", "update_retry", "update_position", "remove_node", "remove_edge"],
                        "description": "Action to perform. Each action has different required fields — see tool description. 'update_config' replaces the whole config (dropping unlisted keys); 'merge_config' patches just the given keys (RFC 7386 JSON Merge Patch; null deletes a key)."
                    },
                    "x": { "type": "number", "description": "X position (for update_position action)" },
                    "y": { "type": "number", "description": "Y position (for update_position action)" },
                    "config": { "type": "object", "description": "For update_config: the full replacement config (existing keys not listed here are dropped). For merge_config: an RFC 7386 JSON Merge Patch applied onto the existing config — only the listed keys change; set a key to null to delete it." },
                    "retry_count": { "type": "number", "description": "Max retries on failure (for update_retry action)" },
                    "retry_backoff_ms": { "type": "number", "description": "Base backoff in ms (for update_retry action)" },
                    "retry_condition": { "type": "string", "description": "Rhai expression: if false, skip retry and fail immediately (for update_retry action)" },
                    "retry_delay_expression": { "type": "string", "description": "Rhai expression returning delay in ms from error output. Overrides exponential backoff. Capped at 60000ms (for update_retry action)" },
                    "edge_source": { "type": "string", "description": "Source node ID (for remove_edge action)" },
                    "edge_target": { "type": "string", "description": "Target node ID (for remove_edge action)" }
                },
                "required": ["workflow_id", "action"]
            }
        }),
        serde_json::json!({
            "name": "update_node_positions",
            "description": "Bulk update node positions in a workflow for UI layout. Accepts a map of node_id -> {x, y}.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow" },
                    "positions": { "type": "object", "description": "Map of node_id -> {x: number, y: number}" }
                },
                "required": ["workflow_id", "positions"]
            }
        }),
        serde_json::json!({
            "name": "duplicate_node",
            "description": "Copy a node within a workflow (same module, same config, new ID). Useful when building parallel branches.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow" },
                    "source_node_id": { "type": "string", "description": "ID of the node to duplicate" },
                    "new_node_id": { "type": "string", "description": "ID for the new (duplicated) node" }
                },
                "required": ["workflow_id", "source_node_id", "new_node_id"]
            }
        }),
        serde_json::json!({
            "name": "add_edge",
            "description": "Add an edge between two existing nodes in a workflow without rebuilding the whole workflow.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow" },
                    "source": { "type": "string", "description": "Source node ID" },
                    "target": { "type": "string", "description": "Target node ID" },
                    "condition": { "type": "string", "description": "Optional Rhai condition expression (edge is only followed when true)" },
                    "edge_type": { "type": "string", "description": "Edge type: 'default' (normal flow), 'error' (only followed on node failure), or 'conditional' (only followed when the 'condition' expression is true). When a 'condition' is set without specifying edge_type, the type is automatically set to 'conditional'. (default: 'default')" }
                },
                "required": ["workflow_id", "source", "target"]
            }
        }),
        serde_json::json!({
            "name": "remove_edge",
            "description": "Remove a specific edge between two nodes in a workflow.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow" },
                    "source": { "type": "string", "description": "Source node ID" },
                    "target": { "type": "string", "description": "Target node ID" }
                },
                "required": ["workflow_id", "source", "target"]
            }
        }),
        serde_json::json!({
            "name": "add_loop_node",
            "description": "Add a loop node to an existing workflow. The loop re-dispatches a target (body) node while a Rhai condition evaluates to true against the body's output. The body_node_id must already exist in the workflow before calling this tool. For new workflows, prefer declaring this node inline via node_type: 'loop' in create_workflow. Use this tool to add the node to an existing workflow. Use connect_from/connect_to to wire edges in the same call (avoids a separate add_edge step).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": {
                        "type": "string",
                        "description": "UUID of the workflow to add the loop node to"
                    },
                    "node_id": {
                        "type": "string",
                        "description": "Unique string ID for the new loop node"
                    },
                    "body_node_id": {
                        "type": "string",
                        "description": "ID of an existing node in the workflow to use as the loop body"
                    },
                    "condition": {
                        "type": "string",
                        "description": "Rhai expression evaluated against the body node's output each iteration. Loop continues while true."
                    },
                    "max_iterations": {
                        "type": "number",
                        "description": "Maximum number of iterations (default: 10, max: 100)"
                    },
                    "connect_from": {
                        "type": "string",
                        "description": "Optional: ID of an existing node to connect FROM into this loop node (adds a default edge). Avoids a separate add_edge call."
                    },
                    "connect_to": {
                        "type": "string",
                        "description": "Optional: ID of an existing node to connect this loop node TO (adds a default edge). Avoids a separate add_edge call."
                    }
                },
                "required": ["workflow_id", "node_id", "body_node_id", "condition"]
            }
        }),
        serde_json::json!({
            "name": "add_assistant_report_node",
            "description": "Add an assistant-report node to an existing workflow. Controller-side system node: emits a trailing-window activity + learning-health snapshot (per-workflow execution stats, fuel/cost totals, ops-alerts week stats with correction candidates, ML loop health incl. gold accuracy and shadow agreement) as node output for downstream compose nodes — the canonical feed for a weekly assistant report. No worker dispatch, no secrets; degrades to {available: false} instead of failing.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to add the node to" },
                    "node_id": { "type": "string", "description": "Unique string ID for the new node" },
                    "days": { "type": "number", "description": "Trailing window in days (1-31, default 7)" },
                    "connect_from": {
                        "description": "Node ID(s) to wire INTO this node (usually the trigger).",
                        "oneOf": [ { "type": "string" }, { "type": "array", "items": { "type": "string" } } ]
                    },
                    "connect_to": { "type": "string", "description": "Optional: ID of an existing node to connect this node TO (e.g. the compose node)." }
                },
                "required": ["workflow_id", "node_id"]
            }
        }),
        serde_json::json!({
            "name": "add_ops_alerts_digest_node",
            "description": "Add an ops-alerts digest node to an existing workflow. Controller-side system node: reads the caller's ops-alerts triage store (digest counts over active alerts + the top-N active alerts, severity-ranked) and emits it as node output for downstream nodes — the canonical feed for daily-brief compose nodes. No worker dispatch, no secrets, tenancy from the execution's resolved identity. Degrades to {available: false} instead of failing the workflow when the store is unreachable.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": {
                        "type": "string",
                        "description": "UUID of the workflow to add the node to"
                    },
                    "node_id": {
                        "type": "string",
                        "description": "Unique string ID for the new node"
                    },
                    "top_limit": {
                        "type": "number",
                        "description": "How many active alerts to include verbatim in top_active (1-25, default 10)"
                    },
                    "connect_from": {
                        "description": "Node ID(s) to wire INTO this node (usually the trigger).",
                        "oneOf": [
                            { "type": "string" },
                            { "type": "array", "items": { "type": "string" } }
                        ]
                    },
                    "connect_to": {
                        "type": "string",
                        "description": "Optional: ID of an existing node to connect this node TO (e.g. the compose node)."
                    }
                },
                "required": ["workflow_id", "node_id"]
            }
        }),
        serde_json::json!({
            "name": "add_collect_node",
            "description": "Add a collect node to an existing workflow. Gathers all parent branch outputs into a JSON array for aggregate operations after parallel fan-out. For new workflows, prefer declaring this node inline via node_type: 'collect' in create_workflow. Use this tool to add the node to an existing workflow. Use connect_from to wire one or more branch endpoints in the same call.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": {
                        "type": "string",
                        "description": "UUID of the workflow to add the collect node to"
                    },
                    "node_id": {
                        "type": "string",
                        "description": "Unique string ID for the new collect node"
                    },
                    "connect_from": {
                        "description": "Node ID(s) to wire INTO this collect node. Accepts a single string or an array of strings for multi-branch wiring in one call.",
                        "oneOf": [
                            { "type": "string" },
                            { "type": "array", "items": { "type": "string" } }
                        ]
                    },
                    "connect_to": {
                        "type": "string",
                        "description": "Optional: ID of an existing node to connect this collect node TO (adds a default edge)."
                    }
                },
                "required": ["workflow_id", "node_id"]
            }
        }),
        serde_json::json!({
            "name": "add_sub_workflow_node",
            "description": "Add a sub-workflow node to a parent workflow. The node invokes another workflow as a single step during execution. For new workflows, prefer declaring this node inline via node_type: 'sub_workflow' in create_workflow. Use this tool to add the node to an existing workflow. Use connect_from/connect_to to wire edges in the same call (avoids a separate add_edge step).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": {
                        "type": "string",
                        "description": "UUID of the parent workflow to add the node to"
                    },
                    "node_id": {
                        "type": "string",
                        "description": "Unique string ID for the new node in the workflow graph"
                    },
                    "sub_workflow_id": {
                        "type": "string",
                        "description": "UUID of the child workflow to invoke"
                    },
                    "timeout_secs": {
                        "type": "number",
                        "description": "Execution timeout in seconds for the sub-workflow (default: 60). Per-node timeouts are honored as-set — there is no implicit clamp against the global ceiling."
                    },
                    "connect_from": {
                        "type": "string",
                        "description": "Optional: ID of an existing node to connect FROM into this sub-workflow node (adds a default edge). Avoids a separate add_edge call."
                    },
                    "connect_to": {
                        "type": "string",
                        "description": "Optional: ID of an existing node to connect this sub-workflow node TO (adds a default edge). Avoids a separate add_edge call."
                    }
                },
                "required": ["workflow_id", "node_id", "sub_workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "copy_node",
            "description": "Copy a node from one workflow to another. The node retains its module and config but gets a new ID and an offset position in the target workflow.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "source_workflow_id": { "type": "string", "description": "UUID of the source workflow" },
                    "source_node_id": { "type": "string", "description": "ID of the node to copy from the source workflow" },
                    "target_workflow_id": { "type": "string", "description": "UUID of the target workflow" },
                    "target_node_id": { "type": "string", "description": "ID for the new node in the target workflow" }
                },
                "required": ["source_workflow_id", "source_node_id", "target_workflow_id", "target_node_id"]
            }
        }),
        serde_json::json!({
            "name": "set_node_description",
            "description": "Set or update a human-readable description on a specific node in a workflow. Useful for documenting what each node does.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow" },
                    "node_id": { "type": "string", "description": "ID of the node to annotate" },
                    "description": { "type": "string", "description": "Description text (max 500 characters)" }
                },
                "required": ["workflow_id", "node_id", "description"]
            }
        }),
        serde_json::json!({
            "name": "duplicate_workflow",
            "description": "Clone a workflow with optional inline modifications: remove specific nodes and add tags. More powerful than clone_workflow for rapid iteration.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to duplicate" },
                    "name": { "type": "string", "description": "Optional name for the duplicated workflow (defaults to 'Copy of <original>')" },
                    "copy_schema": {
                        "type": "boolean",
                        "description": "When true, copies the original workflow's declared input_schema to the duplicate. Default: false.",
                        "default": false
                    },
                    "modifications": {
                        "type": "object",
                        "description": "Optional inline modifications to apply after cloning",
                        "properties": {
                            "remove_nodes": {
                                "type": "array",
                                "items": { "type": "string" },
                                "description": "Array of node IDs to remove from the cloned graph (their edges are also removed)"
                            },
                            "add_tags": {
                                "type": "array",
                                "items": { "type": "string" },
                                "description": "Array of tags to add to the duplicated workflow"
                            },
                            "patch_node_configs": {
                                "type": "object",
                                "description": "Map of node_id → config patch object to apply after cloning. Use to override specific config keys (e.g., target URL, API endpoint) without update_node_config. Keys are merged into existing node config — unspecified keys are preserved.",
                                "additionalProperties": { "type": "object" }
                            }
                        }
                    }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "add_skip_condition",
            "description": "Add a Rhai expression to a workflow node that, when true, causes the node to be skipped at runtime. The expression is evaluated against the gathered inputs.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow" },
                    "node_id": { "type": "string", "description": "ID of the node within the workflow graph" },
                    "skip_condition": { "type": "string", "description": "Rhai expression that returns true to skip the node" }
                },
                "required": ["workflow_id", "node_id", "skip_condition"]
            }
        }),
        serde_json::json!({
            "name": "add_capability_dispatch_node",
            "description": "Add a capability-based dispatch node to an existing workflow. At runtime, finds the best matching workflow with ALL the required capabilities and executes it as a sub-workflow. This enables agentic routing: an LLM can author a workflow that says 'run whatever handles HTTP pagination' without knowing which specific workflow that is. For new workflows, prefer declaring this node inline via node_type: 'capability_dispatch' in create_workflow. Use this tool to add the node to an existing workflow. Use connect_from/connect_to to wire edges in the same call (avoids a separate add_edge step). For expression-based routing (evaluate a Rhai script to select a workflow ID) use add_expression_dispatch_node instead.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": {
                        "type": "string",
                        "description": "UUID of the parent workflow to add the node to"
                    },
                    "node_id": {
                        "type": "string",
                        "description": "Unique string ID for the new capability dispatch node"
                    },
                    "required_capabilities": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Capability tags the target workflow must have (all required). E.g. ['http-fetch', 'pagination']"
                    },
                    "timeout_secs": {
                        "type": "number",
                        "description": "Execution timeout in seconds for the dispatched sub-workflow (default: 60). Per-node timeouts are honored as-set — there is no implicit clamp against the global ceiling."
                    },
                    "fallback_workflow_id": {
                        "type": "string",
                        "description": "Optional UUID of a workflow to dispatch to when no registered workflow matches all required_capabilities at runtime. Without this, unmatched dispatch fails hard. Use a no-op or error-logging workflow as a safe default."
                    },
                    "connect_from": {
                        "type": "string",
                        "description": "Optional: ID of an existing node to connect FROM into this dispatch node (adds a default edge). Avoids a separate add_edge call."
                    },
                    "connect_to": {
                        "type": "string",
                        "description": "Optional: ID of an existing node to connect this dispatch node TO (adds a default edge). Avoids a separate add_edge call."
                    }
                },
                "required": ["workflow_id", "node_id", "required_capabilities"]
            }
        }),
        serde_json::json!({
            "name": "add_expression_dispatch_node",
            "description": "Add a Rhai expression-based dispatch node to a workflow. At runtime, evaluates a Rhai expression against the node's input to select a child workflow ID, then executes it as a sub-workflow. For capability-based routing (find any workflow matching a set of tags) use add_capability_dispatch_node instead.\n\nExpression scope: top-level input fields are available as bare variables (e.g. `route == \"A\"` when input is `{\"route\": \"A\"}`). The whole input is ALSO available as `input`, `ctx`, and `inputs` (aliases) so `input.route`, `ctx.route`, and `inputs.route` all work. Use the wrapper form for nested fields (e.g. `input.user.tier == \"premium\"`). The expression MUST return a string — the target workflow's UUID or name.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": {
                        "type": "string",
                        "description": "UUID of the parent workflow to add the dispatch node to"
                    },
                    "node_id": {
                        "type": "string",
                        "description": "Unique string ID for the new dispatch node"
                    },
                    "dispatch_expression": {
                        "type": "string",
                        "description": "Rhai expression that evaluates against the node's input and returns a workflow ID string (UUID or name). Access input fields as bare variables (`route`) OR via `input.route` / `ctx.route` / `inputs.route` (all equivalent). Use the wrapper form for nested fields."
                    },
                    "timeout_secs": {
                        "type": "number",
                        "description": "Execution timeout in seconds for the dispatched sub-workflow (default: 60). Per-node timeouts are honored as-set — there is no implicit clamp against the global ceiling."
                    }
                },
                "required": ["workflow_id", "node_id", "dispatch_expression"]
            }
        }),
        serde_json::json!({
            "name": "set_continue_on_error",
            "description": "Set or clear the continue_on_error flag on a workflow node. When enabled, if the node fails, the workflow inserts an error result and continues executing downstream nodes instead of failing.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow" },
                    "node_id": { "type": "string", "description": "ID of the node within the workflow graph" },
                    "enabled": { "type": "boolean", "description": "true to enable continue_on_error, false to disable" }
                },
                "required": ["workflow_id", "node_id", "enabled"]
            }
        }),
        serde_json::json!({
            "name": "fix_fan_in",
            "description": "Automatically fix a fan-in convergence issue by inserting a Collect node before the convergence node and rewiring all incoming edges through it. Call this when get_workflow_quickstart reports structural_warnings about missing Collect nodes before a convergence point.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to fix" },
                    "node_id": { "type": "string", "description": "ID of the convergence node that has 2 or more incoming edges (from the structural_warnings)" }
                },
                "required": ["workflow_id", "node_id"]
            }
        }),
        serde_json::json!({
            "name": "preview_capability_dispatch",
            "description": "Show which workflows would be selected at runtime by a capability dispatch node with the given required_capabilities — without executing anything. Returns matching published workflows sorted by readiness_score descending (best match first). Use before add_capability_dispatch_node to verify routing will resolve correctly.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "required_capabilities": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "All capability tags that must be present on a matching workflow (array containment match)"
                    }
                },
                "required": ["required_capabilities"]
            }
        }),
        serde_json::json!({
            "name": "add_verify_node",
            "description": "Add a step-level verification node to a workflow. Evaluates the parent output against a Rhai condition expression. \
                When the condition passes: output is forwarded unchanged with __verified__: true. \
                When the condition fails: behavior depends on on_failure setting. \
                  - 'error' (default): emits a workflow error that can be caught by an error handler. Good for hard quality gates. \
                  - 'passthrough': injects __verification_failed__: true into the output for downstream conditional routing. \
                Use cases: confidence threshold checks ('output.confidence >= 0.8'), required field validation, \
                output schema enforcement. Pairs well with add_error_handler to route failures to a retry workflow.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow" },
                    "node_id": { "type": "string", "description": "Unique string ID for the new verify node" },
                    "condition": {
                        "type": "string",
                        "description": "Rhai expression evaluated against the parent output. Must return bool. Example: 'output[\"confidence\"] >= 0.8'"
                    },
                    "check_label": {
                        "type": "string",
                        "description": "Human-readable label for this check (used in error messages). Example: 'confidence threshold'"
                    },
                    "on_failure": {
                        "type": "string",
                        "description": "Behaviour when condition is false: 'error' (default, stops workflow with error) or 'passthrough' (forwards output with __verification_failed__: true)"
                    },
                    "connect_from": { "type": "string", "description": "Optional: ID of an existing node to connect FROM into this verify node." },
                    "connect_to": { "type": "string", "description": "Optional: ID of an existing node to connect this verify node TO." }
                },
                "required": ["workflow_id", "node_id", "condition"]
            }
        }),
        serde_json::json!({
            "name": "add_synthesize_node",
            "description": "Add a synthesize node to a workflow. Like collect, it gathers all parent branch outputs into an array. Unlike collect, it applies an optional Rhai expression to produce a synthesized result — perfect for cross-actor result merging and pattern extraction after parallel fan-out. \
                Without a synthesis_expr: output is {items: [...], count: N} (identical to collect). \
                With a synthesis_expr: the expression runs with `items` and `count` in scope and its return value becomes the node output. \
                Example: `items.reduce(|a, b| a + \" \" + b.summary, \"\")` to concatenate summaries. \
                Use connect_from to wire multiple incoming branches in one call.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow" },
                    "node_id": { "type": "string", "description": "Unique string ID for the new synthesize node" },
                    "synthesis_expr": {
                        "type": "string",
                        "description": "Optional Rhai expression evaluated over `items` (array of parent outputs) and `count`. Return the synthesized value. If omitted, behaves like add_collect_node."
                    },
                    "connect_from": {
                        "description": "Node ID(s) to wire INTO this synthesize node.",
                        "oneOf": [
                            { "type": "string" },
                            { "type": "array", "items": { "type": "string" } }
                        ]
                    },
                    "connect_to": { "type": "string", "description": "Optional: ID of an existing node to connect this synthesize node TO." }
                },
                "required": ["workflow_id", "node_id"]
            }
        }),
        serde_json::json!({
            "name": "add_agent_loop_node",
            "description": "Add a ReAct-style agent loop node to a workflow. Iteratively executes a body workflow, injecting accumulated history between iterations. Ideal for workflows where an LLM needs to reason, act, and observe multiple times before returning a final answer. \
                The body workflow receives on each iteration: \
                  - __agent_iteration__ (1-based counter) \
                  - __agent_history__ (array of prior outputs, if inject_history: true) \
                  - All parent inputs (minus __-prefixed engine keys) \
                Terminates when: (a) the body output contains {\"finished\": true} or {\"action\": \"FINISH\"}, or (b) max_iterations is reached. \
                Output: {iterations, finished, history: [...], final_output: {...}}. \
                Requires a separate body_workflow_id — create the body workflow first with the LLM inference node inside it.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the parent workflow to add the agent loop node to" },
                    "node_id": { "type": "string", "description": "Unique string ID for the new agent loop node" },
                    "body_workflow_id": { "type": "string", "description": "UUID of the workflow to execute on each iteration (must contain the LLM/reasoning node)" },
                    "max_iterations": { "type": "number", "description": "Maximum iterations before forced termination (1–50, default 10)" },
                    "inject_history": { "type": "boolean", "description": "Inject __agent_history__ array into each iteration input (default: true)" },
                    "timeout_secs": { "type": "number", "description": "Per-iteration execution timeout in seconds (default: 60)" },
                    "connect_from": { "type": "string", "description": "Optional: ID of an existing node to connect FROM into this agent loop node." },
                    "connect_to": { "type": "string", "description": "Optional: ID of an existing node to connect this agent loop node TO." }
                },
                "required": ["workflow_id", "node_id", "body_workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "add_react_loop_node",
            "description": "Add a ReActLoop node — alternative agent-loop shape (reason → act → observe with history). Engine-level difference from add_agent_loop_node: ReActLoop is the canonical ReAct primitive variant; agent_loop is the general-purpose loop. Same termination contract ({finished: true} or {action: \"FINISH\"} in body output) and same output shape ({iterations, finished, history, final_output}). Use ReActLoop when you want the explicit ReAct semantics on trace and observability. Requires a separate body_workflow_id — create the body workflow first with the LLM inference node inside it.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the parent workflow to add this node to" },
                    "node_id": { "type": "string", "description": "Unique string ID for the new ReActLoop node" },
                    "body_workflow_id": { "type": "string", "description": "UUID of the workflow to execute on each iteration" },
                    "max_iterations": { "type": "number", "description": "Maximum iterations before forced termination (1–50, default 10)" },
                    "inject_history": { "type": "boolean", "description": "Inject prior iteration outputs as history into each iteration input (default: true)" },
                    "timeout_secs": { "type": "number", "description": "Per-iteration execution timeout in seconds (default: 60)" },
                    "connect_from": { "type": "string", "description": "Optional: ID of an existing node to connect FROM into this ReActLoop node." },
                    "connect_to": { "type": "string", "description": "Optional: ID of an existing node to connect this ReActLoop node TO." }
                },
                "required": ["workflow_id", "node_id", "body_workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "add_wait_node",
            "description": "Add a Wait node — pauses the workflow execution until an external signal resumes it. The engine emits a `__waiting__: true` envelope and stores it as the node output, then the workflow transitions to the `waiting` state. Resume by calling resume_workflow_by_correlation_id (or the equivalent external signal). Useful for human-in-the-loop handoffs where the wait is the primary mechanism (distinct from approval gates, which are explicitly approval-oriented). The optional message surfaces to whoever inspects the pending execution.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to add this node to" },
                    "node_id": { "type": "string", "description": "Unique string ID for the new Wait node" },
                    "message": { "type": "string", "description": "Optional human-readable message surfaced to whoever is resuming this wait (max 500 chars)" },
                    "connect_from": { "type": "string", "description": "Optional: ID of an existing node to connect FROM into this Wait node." },
                    "connect_to": { "type": "string", "description": "Optional: ID of an existing node to connect this Wait node TO (wires the resume path)." }
                },
                "required": ["workflow_id", "node_id"]
            }
        }),
        serde_json::json!({
            "name": "set_speculative_prefetch",
            "description": "Enable speculative module pre-loading on a node to reduce latency for its successors. \
                When set, the engine starts fetching the WASM modules for all direct successor nodes in the background \
                as soon as this node begins executing — so by the time this node completes, successor modules are \
                already loaded and cached. Effective for linear chains where the slow node (e.g. an LLM call) has \
                a predictable successor (e.g. a data transformer or notifier). \
                Has no effect on the first execution (cold path), maximum benefit on warm reruns and long-running nodes. \
                Set enable: false to remove the flag.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow" },
                    "node_id": { "type": "string", "description": "ID of the node to configure" },
                    "enable": { "type": "boolean", "description": "true to enable speculative prefetch (default), false to disable" }
                },
                "required": ["workflow_id", "node_id"]
            }
        }),
        serde_json::json!({
            "name": "add_error_handler",
            "description": "Wire a notification/handler node onto all at-risk nodes in one call. Finds every node in the workflow that lacks an outgoing error edge, adds a handler node using the specified module, and adds error-type edges from each at-risk node to the handler. Use this to make workflows resilient to node failures without manually calling add_edge for each one. The risk_assessment tool flags 'missing error edge' nodes — this tool resolves all of them in a single call.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to add error handling to" },
                    "handler_module_id": { "type": "string", "description": "UUID of the module to use as error handler. Preferred over handler_module_name — unambiguous. Use list_modules to find the UUID." },
                    "handler_module_name": { "type": "string", "description": "Display name of the module to use for error handling (e.g. 'Slack Message', 'Microsoft Teams Message', 'PagerDuty Alert'). Must match a module in the catalog." },
                    "handler_label": { "type": "string", "description": "Label for the handler node (default: 'Error Handler')" },
                    "target_node_ids": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Specific node IDs to wire error edges from. Defaults to all nodes that currently have no outgoing error edge."
                    }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "add_judge_node",
            "description": "Add an LLM-as-Judge node to a workflow. The judge node executes a dedicated judge workflow that evaluates the parent output against a natural-language rubric. The judge workflow receives {content, rubric} and must return {score: 0.0–1.0, passed: bool, reasoning: string, feedback: string}. The parent output is forwarded downstream enriched with __judge_score__, __judge_passed__, __judge_reasoning__, and __judge_feedback__ metadata fields. Use this for automated quality gates that cannot be expressed as boolean Rhai conditions.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to add this node to" },
                    "node_id": { "type": "string", "description": "Unique node identifier within this workflow" },
                    "judge_workflow_id": { "type": "string", "description": "UUID of the judge workflow (must return {score, passed, reasoning, feedback})" },
                    "rubric": { "type": "string", "description": "Natural-language evaluation criteria passed to the judge workflow" },
                    "pass_threshold": { "type": "number", "description": "Minimum score (0.0–1.0) required to pass. If omitted, only the judge's passed field governs." },
                    "on_failure": {
                        "type": "string",
                        "enum": ["error", "passthrough"],
                        "description": "Behavior when the verdict is rejected. 'error' (default) emits an __error envelope that fails the node unless continue_on_error is set — the conservative default. 'passthrough' forwards the parent output enriched with __judge_passed__: false (plus score, reasoning, feedback, __judge_rejected__: true) so downstream edges can conditional-route on the verdict without tripping the error path. Mirrors verify's on_failure field."
                    },
                    "timeout_secs": { "type": "number", "description": "Execution timeout for the judge workflow in seconds (default: 60)" },
                    "connect_from": {
                        "description": "Optional node_id(s) to wire an edge from. Accepts a single string or an array of strings.",
                        "oneOf": [
                            { "type": "string" },
                            { "type": "array", "items": { "type": "string" } }
                        ]
                    },
                    "connect_to": { "type": "string", "description": "Optional node_id to wire an edge to" }
                },
                "required": ["workflow_id", "node_id", "judge_workflow_id", "rubric"]
            }
        }),
        serde_json::json!({
            "name": "add_inline_judge_node",
            "description": "Add an inline-judge node. Unlike add_judge_node (which spawns a judge sub-workflow), this evaluates a Rhai expression against the parent output inline — no LLM round-trip, no extra execution, just a fast boolean gate. The expression MUST return an object with {score: 0.0–1.0, passed: bool, reasoning: string, feedback: string}. Top-level fields of the parent output are available as bare scope variables (e.g. `score`, `status`). The parent output is forwarded downstream enriched with __judge_score__, __judge_passed__, __judge_reasoning__, __judge_feedback__ — identical shape to add_judge_node so downstream consumers don't have to distinguish. Use this when the quality gate is structural (length check, field presence, numeric threshold, etc.) and doesn't need an LLM's judgment.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to add this node to" },
                    "node_id": { "type": "string", "description": "Unique node identifier within this workflow" },
                    "verdict_expr": { "type": "string", "description": "Rhai expression returning {score, passed, reasoning, feedback}. Parent output fields are in scope as bare variables. Max 2000 chars. Example: `#{ score: if len > 20 { 1.0 } else { 0.2 }, passed: len > 20, reasoning: \"length check\", feedback: \"\" }`" },
                    "pass_threshold": { "type": "number", "description": "Minimum score (0.0–1.0) required to pass. If omitted, only the expression's 'passed' field governs." },
                    "on_failure": {
                        "type": "string",
                        "enum": ["error", "passthrough"],
                        "description": "Behavior when the verdict is rejected. 'error' (default) emits an __error envelope that fails the node unless continue_on_error is set. 'passthrough' forwards the parent output enriched with __judge_passed__: false plus __judge_rejected__: true so downstream edges can conditional-route on the verdict without tripping the error path. Mirrors add_judge_node."
                    },
                    "connect_from": {
                        "description": "Optional node_id(s) to wire an edge from. Accepts a single string or an array of strings.",
                        "oneOf": [
                            { "type": "string" },
                            { "type": "array", "items": { "type": "string" } }
                        ]
                    },
                    "connect_to": { "type": "string", "description": "Optional node_id to wire an edge to" }
                },
                "required": ["workflow_id", "node_id", "verdict_expr"]
            }
        }),
        serde_json::json!({
            "name": "add_ensemble_node",
            "description": "Add an ensemble (self-consistency) node that runs the same child workflow N times concurrently and applies a consensus strategy. Use majority_vote for classification tasks where reliability matters. Use best_of_n with a judge_workflow_id to pick the highest-quality output. Use first_pass for simple parallel diversity checks. Output includes __ensemble_method__, __ensemble_size__, and __ensemble_votes__ metadata.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to add this node to" },
                    "node_id": { "type": "string", "description": "Unique node identifier within this workflow" },
                    "child_workflow_id": { "type": "string", "description": "UUID of the workflow to run N times" },
                    "count": { "type": "number", "description": "Number of parallel executions (2–10, default: 3)" },
                    "consensus": { "type": "string", "enum": ["majority_vote", "best_of_n", "first_pass"], "description": "How to select the final output" },
                    "judge_workflow_id": { "type": "string", "description": "Required for best_of_n: judge workflow that scores each candidate" },
                    "timeout_secs": { "type": "number", "description": "Timeout per child execution in seconds (default: 60)" },
                    "connect_from": {
                        "description": "Optional node_id(s) to wire an edge from. Accepts a single string or an array of strings.",
                        "oneOf": [
                            { "type": "string" },
                            { "type": "array", "items": { "type": "string" } }
                        ]
                    },
                    "connect_to": { "type": "string", "description": "Optional node_id to wire an edge to" }
                },
                "required": ["workflow_id", "node_id", "child_workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "add_confidence_gate_node",
            "description": "Add a confidence gate node that reads a __confidence__ field (or custom path) from the parent output and routes based on whether it meets the threshold. The upstream LLM node must include a __confidence__ value (0.0–1.0) in its output — prompt it explicitly. On low confidence: 'pause' suspends execution for human review (requires submit_workflow_approval to resume), 'error' blocks downstream, 'passthrough' forwards with __confidence_gate_failed__: true for conditional routing.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to add this node to" },
                    "node_id": { "type": "string", "description": "Unique node identifier within this workflow" },
                    "threshold": { "type": "number", "description": "Minimum confidence (0.0–1.0) to pass (default: 0.7)" },
                    "confidence_path": { "type": "string", "description": "JSON key in parent output holding confidence value (default: __confidence__)" },
                    "on_low_confidence": { "type": "string", "enum": ["pause", "error", "passthrough"], "description": "Behaviour below threshold (default: pause)" },
                    "connect_from": {
                        "description": "Optional node_id(s) to wire an edge from. Accepts a single string or an array of strings.",
                        "oneOf": [
                            { "type": "string" },
                            { "type": "array", "items": { "type": "string" } }
                        ]
                    },
                    "connect_to": { "type": "string", "description": "Optional node_id to wire an edge to" }
                },
                "required": ["workflow_id", "node_id"]
            }
        }),
        serde_json::json!({
            "name": "add_reflective_retry_node",
            "description": "Add a reflective retry node. On failure, it runs a reflection workflow that receives {input, error, attempt} and returns corrective guidance, then retries the child workflow with the enriched input. Unlike blind retry (which re-executes with identical input), reflection lets the child adapt its approach based on failure analysis. Output includes __reflective_retry_attempts__ on success.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to add this node to" },
                    "node_id": { "type": "string", "description": "Unique node identifier within this workflow" },
                    "child_workflow_id": { "type": "string", "description": "Workflow to attempt" },
                    "reflection_workflow_id": { "type": "string", "description": "Workflow that analyzes failures and returns corrective input fields" },
                    "max_retries": { "type": "number", "description": "Max retry attempts after initial failure (1–5, default: 2)" },
                    "timeout_secs": { "type": "number", "description": "Timeout per attempt in seconds (default: 60)" },
                    "connect_from": {
                        "description": "Optional node_id(s) to wire an edge from. Accepts a single string or an array of strings.",
                        "oneOf": [
                            { "type": "string" },
                            { "type": "array", "items": { "type": "string" } }
                        ]
                    },
                    "connect_to": { "type": "string", "description": "Optional node_id to wire an edge to" }
                },
                "required": ["workflow_id", "node_id", "child_workflow_id", "reflection_workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "add_llm_dispatch_node",
            "description": "Add an LLM-based dispatch node (Mixture-of-Experts routing). A classifier workflow analyzes the input and returns {class: string}, then the engine dispatches to the corresponding workflow from the routes map. Use this when inputs need semantic routing beyond static Rhai rules — e.g., routing customer requests to billing/support/account specialists. The classifier workflow should be a lightweight LLM node returning a single class label.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to add this node to" },
                    "node_id": { "type": "string", "description": "Unique node identifier within this workflow" },
                    "classifier_workflow_id": { "type": "string", "description": "Workflow that classifies input and returns {class: string}" },
                    "routes": { "type": "object", "description": "Map of class label → workflow UUID to dispatch to", "additionalProperties": { "type": "string" } },
                    "fallback_workflow_id": { "type": "string", "description": "Optional workflow to execute when class doesn't match any route" },
                    "timeout_secs": { "type": "number", "description": "Timeout per sub-workflow execution in seconds (default: 60)" },
                    "connect_from": {
                        "description": "Optional node_id(s) to wire an edge from. Accepts a single string or an array of strings.",
                        "oneOf": [
                            { "type": "string" },
                            { "type": "array", "items": { "type": "string" } }
                        ]
                    },
                    "connect_to": { "type": "string", "description": "Optional node_id to wire an edge to" }
                },
                "required": ["workflow_id", "node_id", "classifier_workflow_id", "routes"]
            }
        }),
    ]
}

pub async fn dispatch(
    name: &str,
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> Option<JsonRpcResponse> {
    match name {
        "update_node_config" => Some(handle_update_node_config(req_id, args, state, agent).await),
        "update_node_positions" => {
            Some(handle_update_node_positions(req_id, args, state, agent).await)
        }
        "duplicate_node" => Some(handle_duplicate_node(req_id, args, state, agent).await),
        "add_edge" => Some(handle_add_edge(req_id, args, state, agent).await),
        "remove_edge" => Some(handle_remove_edge(req_id, args, state, agent).await),
        "add_loop_node" => Some(handle_add_loop_node(req_id, args, state, agent).await),
        "add_collect_node" => Some(handle_add_collect_node(req_id, args, state, agent).await),
        "add_ops_alerts_digest_node" => {
            Some(handle_add_ops_alerts_digest_node(req_id, args, state, agent).await)
        }
        "add_assistant_report_node" => {
            Some(handle_add_assistant_report_node(req_id, args, state, agent).await)
        }
        "add_sub_workflow_node" => {
            Some(handle_add_sub_workflow_node(req_id, args, state, agent).await)
        }
        "copy_node" => Some(handle_copy_node(req_id, args, state, agent).await),
        "set_node_description" => {
            Some(handle_set_node_description(req_id, args, state, agent).await)
        }
        "duplicate_workflow" => Some(handle_duplicate_workflow(req_id, args, state, agent).await),
        "add_skip_condition" => Some(handle_add_skip_condition(req_id, args, state, agent).await),
        "add_capability_dispatch_node" => {
            Some(handle_add_capability_dispatch_node(req_id, args, state, agent).await)
        }
        "add_expression_dispatch_node" | "add_dispatch_node" => {
            Some(handle_add_dispatch_node(req_id, args, state, agent).await)
        }
        "set_continue_on_error" => {
            Some(handle_set_continue_on_error(req_id, args, state, agent).await)
        }
        "add_verify_node" => Some(handle_add_verify_node(req_id, args, state, agent).await),
        "add_synthesize_node" => Some(handle_add_synthesize_node(req_id, args, state, agent).await),
        "add_react_loop_node" => Some(handle_add_react_loop_node(req_id, args, state, agent).await),
        "add_wait_node" => Some(handle_add_wait_node(req_id, args, state, agent).await),
        "add_agent_loop_node" => Some(handle_add_agent_loop_node(req_id, args, state, agent).await),
        "set_speculative_prefetch" => {
            Some(handle_set_speculative_prefetch(req_id, args, state, agent).await)
        }
        "add_error_handler" => Some(handle_add_error_handler(req_id, args, state, agent).await),
        "fix_fan_in" => Some(handle_fix_fan_in(req_id, args, state, agent).await),
        "preview_capability_dispatch" => {
            Some(handle_preview_capability_dispatch(req_id, args, state, agent).await)
        }
        "add_judge_node" => Some(handle_add_judge_node(req_id, args, state, agent).await),
        "add_inline_judge_node" => {
            Some(handle_add_inline_judge_node(req_id, args, state, agent).await)
        }
        "add_ensemble_node" => Some(handle_add_ensemble_node(req_id, args, state, agent).await),
        "add_confidence_gate_node" => {
            Some(handle_add_confidence_gate_node(req_id, args, state, agent).await)
        }
        "add_reflective_retry_node" => {
            Some(handle_add_reflective_retry_node(req_id, args, state, agent).await)
        }
        "add_llm_dispatch_node" => {
            Some(handle_add_llm_dispatch_node(req_id, args, state, agent).await)
        }
        _ => None,
    }
}

// ── set_speculative_prefetch ────────────────────────────────────────────────

async fn handle_set_speculative_prefetch(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    // MCP-226 (2026-05-08): trim node_id at the boundary.
    let node_id = match args.get("node_id").and_then(|v| v.as_str()) {
        Some(id) => {
            let trimmed = id.trim();
            if trimmed.is_empty() {
                return mcp_error(req_id, -32602, "node_id required");
            }
            trimmed.to_string()
        }
        None => return mcp_error(req_id, -32602, "node_id required"),
    };
    // MCP-245 (2026-05-08): pre-fix `enable: "false"` (string) became
    // true via as_bool-then-unwrap_or — user trying to DISABLE
    // speculative prefetch actually enabled it. Direction-class bug.
    // validate_optional_bool rejects wrong-type loudly.
    let enable = match crate::utils::validate_optional_bool(args, "enable", true, &req_id) {
        Ok(b) => b,
        Err(resp) => return resp,
    };

    let graph_json_str = match fetch_graph_json(state, wf_id, user_id, &req_id).await {
        Ok(gj) => gj,
        Err(e) => return e,
    };

    let mut graph: serde_json::Value =
        serde_json::from_str(&graph_json_str).unwrap_or(serde_json::json!({"nodes":[],"edges":[]}));

    let mut found = false;
    if let Some(nodes) = graph.get_mut("nodes").and_then(|n| n.as_array_mut()) {
        for node in nodes.iter_mut() {
            if node.get("id").and_then(|v| v.as_str()) == Some(&node_id) {
                let data = node.get_mut("data").and_then(|d| d.as_object_mut());
                if let Some(data_obj) = data {
                    if enable {
                        data_obj.insert(
                            "speculative_prefetch".to_string(),
                            serde_json::Value::Bool(true),
                        );
                    } else {
                        data_obj.remove("speculative_prefetch");
                    }
                } else if enable {
                    node.as_object_mut().map(|n| {
                        n.insert(
                            "data".to_string(),
                            serde_json::json!({"speculative_prefetch": true}),
                        )
                    });
                }
                found = true;
                break;
            }
        }
    }

    if !found {
        return mcp_error(req_id, -32000, "Node not found in workflow");
    }

    if let Err(e) = save_graph_json_unchecked(
        state,
        wf_id,
        &serde_json::to_string(&graph).unwrap_or_default(),
        &req_id,
    )
    .await
    {
        return e;
    }

    mcp_text(
        req_id,
        &format!(
            "Speculative prefetch {} on node '{}' in workflow {}.\n\
             When this node executes, the engine will pre-load WASM modules for all \
             direct successor nodes in the background — reducing their dispatch latency \
             when this node completes.",
            if enable { "enabled" } else { "disabled" },
            node_id,
            wf_id,
        ),
    )
}

// ── update_node_config ──────────────────────────────────────────────────────

async fn handle_update_node_config(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let action = args.get("action").and_then(|v| v.as_str()).unwrap_or("");

    // Load existing graph
    let graph_json_str = match fetch_graph_json(state, wf_id, user_id, &req_id).await {
        Ok(gj) => gj,
        Err(e) => return e,
    };

    let mut graph: serde_json::Value =
        serde_json::from_str(&graph_json_str).unwrap_or(serde_json::json!({"nodes":[],"edges":[]}));

    let mut template_warnings: Vec<String> = Vec::new();
    // Populated only by the `update_config` (replace-semantics) arm —
    // see the "dropped_keys" response addition below.
    let mut dropped_keys: Option<Vec<String>> = None;

    match action {
        "update_config" => {
            // MCP-226: trim node_id at the boundary.
            let raw_node_id = match args.get("node_id").and_then(|v| v.as_str()) {
                Some(id) if !id.trim().is_empty() => id.trim(),
                _ => return mcp_error(req_id, -32602, "node_id required for update_config"),
            };
            let node_id = raw_node_id;
            let raw_config = args.get("config").cloned().unwrap_or(serde_json::json!({}));
            // MCP-408 (2026-05-11): cap config size at 1 MB. Pre-fix
            // an unbounded `config` payload could be persisted into
            // the node's data field, bloating graph_json forever. Every
            // subsequent workflow read deserializes the full graph; a
            // 50MB config would balloon memory on every list /
            // get_workflow / engine load. The wire-level controller
            // cap eventually rejects egregious cases but the much
            // smaller per-node cap fails fast with actionable
            // diagnostic. Same 1 MB ceiling that trigger_workflow /
            // test_workflow / run_sandbox already enforce.
            if let Err(resp) =
                crate::utils::enforce_payload_size_limit(&raw_config, req_id.clone())
            {
                return resp;
            }

            // SECURITY: strip engine-internal keys that start with "__". These are runtime
            // control fields (e.g. __skip_condition, __continue_on_error) managed exclusively
            // by the engine and by their dedicated MCP actions (add_skip_condition,
            // set_continue_on_error). Allowing them here would bypass length/Rhai validation.
            let new_config = if let Some(obj) = raw_config.as_object() {
                let filtered: serde_json::Map<String, serde_json::Value> = obj
                    .iter()
                    .filter(|(k, _)| !k.starts_with("__"))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                // Validate skip_condition if caller is trying to set it here.
                if let Some(sc) = filtered.get("skip_condition") {
                    if let Some(expr) = sc.as_str() {
                        if expr.len() > 2000 {
                            return mcp_error(req_id, -32602, "skip_condition must be ≤ 2000 characters; use add_skip_condition for validated updates");
                        }
                    } else {
                        return mcp_error(req_id, -32602, "skip_condition must be a string; use add_skip_condition for validated updates");
                    }
                }
                serde_json::Value::Object(filtered)
            } else if raw_config.is_null() || raw_config == serde_json::json!({}) {
                serde_json::json!({})
            } else {
                return mcp_error(req_id, -32602, "config must be a JSON object");
            };

            if serde_json::to_string(&new_config)
                .map(|s| s.len())
                .unwrap_or(0)
                > 100_000
            {
                return mcp_error(req_id, -32602, "config must be ≤ 100 KB when serialized");
            }

            // MCP-1053 (2026-05-15): route through canonical
            // `talos_workflow_creation_helpers::detect_template_interpolation_warnings`.
            // Pre-fix this site re-compiled the same `\{\{([^}]+)\}\}`
            // regex inline AND emitted a near-identical warning string
            // (one-word wording difference). Same N-inline-copies class
            // as MCP-1037/1049/1050/1051/1052.
            template_warnings.extend(
                talos_workflow_creation_helpers::detect_template_interpolation_warnings(
                    &new_config,
                ),
            );

            let mut found = false;
            if let Some(nodes) = graph.get_mut("nodes").and_then(|n| n.as_array_mut()) {
                for node in nodes.iter_mut() {
                    if node.get("id").and_then(|v| v.as_str()) == Some(node_id) {
                        // DX pain point 21 (2026-07-14): capture the config
                        // BEFORE the replace so the response can report which
                        // keys the wholesale overwrite dropped.
                        let old_config = node.get("data").cloned().unwrap_or(serde_json::json!({}));
                        if let Some(obj) = node.as_object_mut() { obj.insert("data".to_string(), new_config.clone()); } else { return mcp_error(req_id, -32602, "Invalid node structure: expected object"); }
                        dropped_keys = Some(dropped_top_level_keys(&old_config, &new_config));
                        found = true;
                        break;
                    }
                }
            }

            if !found {
                return mcp_error(req_id, -32000, &format!("Node '{}' not found in workflow", node_id));
            }
        }
        "merge_config" => {
            // MCP-DX21 (2026-07-14): RFC 7386 JSON Merge Patch onto the
            // node's EXISTING config, instead of `update_config`'s
            // wholesale replace. See `json_merge_patch` doc comment for
            // the full rationale/semantics.
            let raw_node_id = match args.get("node_id").and_then(|v| v.as_str()) {
                Some(id) if !id.trim().is_empty() => id.trim(),
                _ => return mcp_error(req_id, -32602, "node_id required for merge_config"),
            };
            let node_id = raw_node_id;
            let raw_patch = args.get("config").cloned().unwrap_or(serde_json::json!({}));

            // Same 1 MB wire-level cap as update_config.
            if let Err(resp) =
                crate::utils::enforce_payload_size_limit(&raw_patch, req_id.clone())
            {
                return resp;
            }

            // SECURITY: same "__"-prefixed engine-internal-key guard as
            // update_config — strip them out of the patch (both value
            // sets AND explicit-null deletes) so a merge patch can't
            // touch runtime control fields reserved for the engine and
            // their dedicated MCP actions.
            let patch = if let Some(obj) = raw_patch.as_object() {
                let filtered: serde_json::Map<String, serde_json::Value> = obj
                    .iter()
                    .filter(|(k, _)| !k.starts_with("__"))
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                // Validate skip_condition if caller is trying to set it here.
                // Unlike update_config, an explicit `null` here is a valid
                // RFC 7386 "delete this key" instruction, not a type error.
                if let Some(sc) = filtered.get("skip_condition") {
                    if let Some(expr) = sc.as_str() {
                        if expr.len() > 2000 {
                            return mcp_error(req_id, -32602, "skip_condition must be ≤ 2000 characters; use add_skip_condition for validated updates");
                        }
                    } else if !sc.is_null() {
                        return mcp_error(req_id, -32602, "skip_condition must be a string (or null to delete it); use add_skip_condition for validated updates");
                    }
                }
                serde_json::Value::Object(filtered)
            } else {
                raw_patch
            };

            template_warnings.extend(
                talos_workflow_creation_helpers::detect_template_interpolation_warnings(&patch),
            );

            let mut found = false;
            if let Some(nodes) = graph.get_mut("nodes").and_then(|n| n.as_array_mut()) {
                for node in nodes.iter_mut() {
                    if node.get("id").and_then(|v| v.as_str()) == Some(node_id) {
                        let mut merged = node.get("data").cloned().unwrap_or(serde_json::json!({}));
                        json_merge_patch(&mut merged, &patch);

                        if serde_json::to_string(&merged).map(|s| s.len()).unwrap_or(0) > 100_000 {
                            return mcp_error(req_id, -32602, "config must be ≤ 100 KB when serialized after merge");
                        }

                        if let Some(obj) = node.as_object_mut() {
                            obj.insert("data".to_string(), merged);
                        } else {
                            return mcp_error(req_id, -32602, "Invalid node structure: expected object");
                        }
                        found = true;
                        break;
                    }
                }
            }

            if !found {
                return mcp_error(req_id, -32000, &format!("Node '{}' not found in workflow", node_id));
            }
        }
        "update_retry" => {
            // MCP-226: trim node_id at the boundary.
            let raw_node_id = match args.get("node_id").and_then(|v| v.as_str()) {
                Some(id) if !id.trim().is_empty() => id.trim(),
                _ => return mcp_error(req_id, -32602, "node_id required for update_retry"),
            };
            let node_id = raw_node_id;

            let mut found = false;
            if let Some(nodes) = graph.get_mut("nodes").and_then(|n| n.as_array_mut()) {
                for node in nodes.iter_mut() {
                    if node.get("id").and_then(|v| v.as_str()) == Some(node_id) {
                        // MCP-380 (2026-05-11): pre-fix the
                        // `rc.clone()` / `rb.clone()` insert took ANY
                        // JSON value from the operator and wrote it
                        // verbatim into the node config — `retry_count:
                        // "5"` (string) persisted a string where the
                        // schema declared a number. The engine's graph
                        // parser would then fail on the next execution
                        // with a confusing deserialization error
                        // pointing at the node. Schema declares
                        // `number`; enforce non-negative integer at
                        // the boundary so the typo is caught before
                        // the workflow is broken.
                        if let Some(rc) = args.get("retry_count") {
                            match rc.as_u64() {
                                Some(n) if n <= 100 => {
                                    if let Some(obj) = node.as_object_mut() {
                                        obj.insert(
                                            "retry_count".to_string(),
                                            serde_json::json!(n),
                                        );
                                    } else {
                                        return mcp_error(
                                            req_id,
                                            -32602,
                                            "Invalid node structure",
                                        );
                                    }
                                }
                                Some(n) => {
                                    return mcp_error(
                                        req_id,
                                        -32602,
                                        &format!(
                                            "retry_count must be a non-negative integer ≤ 100, got {n}"
                                        ),
                                    )
                                }
                                None => {
                                    let kind = crate::utils::json_type_name(rc);
                                    return mcp_error(
                                        req_id,
                                        -32602,
                                        &format!(
                                            "retry_count must be a non-negative integer, got {kind}"
                                        ),
                                    );
                                }
                            }
                        }
                        if let Some(rb) = args.get("retry_backoff_ms") {
                            match rb.as_u64() {
                                Some(n) if n <= 600_000 => {
                                    if let Some(obj) = node.as_object_mut() {
                                        obj.insert(
                                            "retry_backoff_ms".to_string(),
                                            serde_json::json!(n),
                                        );
                                    } else {
                                        return mcp_error(
                                            req_id,
                                            -32602,
                                            "Invalid node structure",
                                        );
                                    }
                                }
                                Some(n) => {
                                    return mcp_error(
                                        req_id,
                                        -32602,
                                        &format!(
                                            "retry_backoff_ms must be a non-negative integer ≤ 600000 (10 min), got {n}"
                                        ),
                                    )
                                }
                                None => {
                                    let kind = crate::utils::json_type_name(rb);
                                    return mcp_error(
                                        req_id,
                                        -32602,
                                        &format!(
                                            "retry_backoff_ms must be a non-negative integer, got {kind}"
                                        ),
                                    );
                                }
                            }
                        }
                        if let Some(rcond) = args.get("retry_condition").and_then(|v| v.as_str()) {
                            if rcond.len() > 500 {
                                return mcp_error(req_id, -32602, "retry_condition must be ≤500 characters");
                            }
                            if let Err(msg) = validate_rhai_expression("retry_condition", rcond) {
                                return mcp_error(req_id, -32602, &msg);
                            }
                            if let Some(obj) = node.as_object_mut() { obj.insert("retry_condition".to_string(), serde_json::json!(rcond)); } else { return mcp_error(req_id, -32602, "Invalid node structure"); }
                        }
                        if let Some(rde) = args.get("retry_delay_expression").and_then(|v| v.as_str()) {
                            if rde.len() > 500 {
                                return mcp_error(req_id, -32602, "retry_delay_expression must be ≤500 characters");
                            }
                            if let Err(msg) =
                                validate_rhai_expression("retry_delay_expression", rde)
                            {
                                return mcp_error(req_id, -32602, &msg);
                            }
                            if let Some(obj) = node.as_object_mut() { obj.insert("retry_delay_expression".to_string(), serde_json::json!(rde)); } else { return mcp_error(req_id, -32602, "Invalid node structure"); }
                        }
                        found = true;
                        break;
                    }
                }
            }

            if !found {
                return mcp_error(req_id, -32000, &format!("Node '{}' not found in workflow", node_id));
            }
        }
        "update_position" => {
            // MCP-226: trim node_id at the boundary.
            let raw_node_id = match args.get("node_id").and_then(|v| v.as_str()) {
                Some(id) if !id.trim().is_empty() => id.trim(),
                _ => return mcp_error(req_id, -32602, "node_id required for update_position"),
            };
            let node_id = raw_node_id;
            // MCP-353 (2026-05-11): pre-fix `.and_then(as_f64)` silently
            // dropped wrong-type x / y values into None. Operator passing
            // `x: "100"` (string — JSON-strict typing not always obvious
            // to UI tooling) silently became `x: None`. If y was a real
            // number, the `is_none() && is_none()` check passed AND the
            // x update silently no-op'd — node moved vertically only,
            // operator believed diagonal. Reject wrong-type loudly; an
            // absent / null axis still means "leave that axis alone".
            let parse_axis = |field: &str| -> Result<Option<f64>, JsonRpcResponse> {
                match args.get(field) {
                    None | Some(serde_json::Value::Null) => Ok(None),
                    Some(v) => match v.as_f64() {
                        Some(n) => Ok(Some(n)),
                        None => {
                            let kind = crate::utils::json_type_name(v);
                            Err(mcp_error(
                                req_id.clone(),
                                -32602,
                                &format!(
                                    "'{field}' must be a number, got {kind}"
                                ),
                            ))
                        }
                    },
                }
            };
            let x = match parse_axis("x") {
                Ok(v) => v,
                Err(resp) => return resp,
            };
            let y = match parse_axis("y") {
                Ok(v) => v,
                Err(resp) => return resp,
            };
            if x.is_none() && y.is_none() {
                return mcp_error(req_id, -32602, "At least one of 'x' or 'y' required for update_position");
            }

            let mut found = false;
            if let Some(nodes) = graph.get_mut("nodes").and_then(|n| n.as_array_mut()) {
                for node in nodes.iter_mut() {
                    if node.get("id").and_then(|v| v.as_str()) == Some(node_id) {
                        let pos = node.get_mut("position")
                            .and_then(|p| p.as_object_mut());
                        if let Some(pos) = pos {
                            if let Some(xv) = x { pos.insert("x".to_string(), serde_json::json!(xv)); }
                            if let Some(yv) = y { pos.insert("y".to_string(), serde_json::json!(yv)); }
                        } else {
                            if let Some(obj) = node.as_object_mut() {
                                obj.insert("position".to_string(), serde_json::json!({
                                    "x": x.unwrap_or(0.0),
                                    "y": y.unwrap_or(0.0),
                                }));
                            } else {
                                return mcp_error(req_id, -32602, "Invalid node structure");
                            }

                        }
                        found = true;
                        break;
                    }
                }
            }

            if !found {
                return mcp_error(req_id, -32000, &format!("Node '{}' not found in workflow", node_id));
            }
        }
        "remove_node" => {
            // MCP-226: trim node_id at the boundary.
            let raw_node_id = match args.get("node_id").and_then(|v| v.as_str()) {
                Some(id) if !id.trim().is_empty() => id.trim(),
                _ => return mcp_error(req_id, -32602, "node_id required for remove_node"),
            };
            let node_id = raw_node_id;

            // Remove the node
            if let Some(nodes) = graph.get_mut("nodes").and_then(|n| n.as_array_mut()) {
                nodes.retain(|n| n.get("id").and_then(|v| v.as_str()) != Some(node_id));
            }

            // Auto-reconnect: find parents and children of the removed node
            let mut parents: Vec<String> = Vec::new();
            let mut children: Vec<String> = Vec::new();
            let mut removed_edges: Vec<String> = Vec::new();

            if let Some(edges) = graph.get_mut("edges").and_then(|e| e.as_array_mut()) {
                // Collect parents, children, and any edge metadata that will be lost
                let mut had_conditions = false;
                for e in edges.iter() {
                    let src = e.get("source").and_then(|v| v.as_str()).unwrap_or("");
                    let tgt = e.get("target").and_then(|v| v.as_str()).unwrap_or("");
                    if tgt == node_id { parents.push(src.to_string()); }
                    if src == node_id { children.push(tgt.to_string()); }
                    if (src == node_id || tgt == node_id) && e.get("condition").is_some() {
                        had_conditions = true;
                    }
                }

                // Remove all edges connected to the node
                edges.retain(|e| {
                    let src = e.get("source").and_then(|v| v.as_str()).unwrap_or("");
                    let tgt = e.get("target").and_then(|v| v.as_str()).unwrap_or("");
                    let connected = src == node_id || tgt == node_id;
                    if connected {
                        removed_edges.push(format!("{} -> {}", src, tgt));
                    }
                    !connected
                });

                // Auto-reconnect: bridge each parent to each child
                let mut reconnected = Vec::new();
                for p in &parents {
                    for c in &children {
                        edges.push(serde_json::json!({ "source": p, "target": c }));
                        reconnected.push(format!("{} -> {}", p, c));
                    }
                }

                let updated_json = graph.to_string();
                if let Err(e) = save_graph_json(state, wf_id, user_id, &updated_json, &req_id).await {
                    return e;
                }
                {
                        let mut msg = format!("Node '{}' removed from workflow {}.", node_id, wf_id);
                        if !removed_edges.is_empty() {
                            msg.push_str(&format!("\nRemoved edges: [{}]", removed_edges.join(", ")));
                        }
                        if !reconnected.is_empty() {
                            msg.push_str(&format!("\nAuto-reconnected: [{}]", reconnected.join(", ")));
                            if had_conditions {
                                msg.push_str("\nNote: Conditional edge expressions were dropped during reconnect. Add conditions manually if needed.");
                            }
                        }

                        // Auto-publish if this workflow has an active published
                        // version (shared helper — see maybe_auto_publish).
                        msg.push_str(
                            maybe_auto_publish(state, wf_id, user_id, "Auto-published after node removal")
                                .await
                                .message_suffix(),
                        );

                        return mcp_text(req_id, &msg);
                }
            }
        }
        "remove_edge" => {
            let edge_source = match args.get("edge_source").and_then(|v| v.as_str()) {
                Some(s) => s,
                None => return mcp_error(req_id, -32602, "edge_source required for remove_edge"),
            };
            let edge_target = match args.get("edge_target").and_then(|v| v.as_str()) {
                Some(t) => t,
                None => return mcp_error(req_id, -32602, "edge_target required for remove_edge"),
            };

            talos_workflow_repository::remove_edge_by_endpoints(
                &mut graph,
                edge_source,
                edge_target,
            );
        }
        _ => return mcp_error(req_id, -32602, &format!("Unknown action '{}'. Use 'update_config', 'merge_config', 'update_retry', 'update_position', 'remove_node', or 'remove_edge'.", action)),
    }

    let updated_json = graph.to_string();
    if let Err(e) = save_graph_json(state, wf_id, user_id, &updated_json, &req_id).await {
        return e;
    }

    let mut msg = format!("Workflow {} updated (action: {}).", wf_id, action);
    for w in &template_warnings {
        msg.push_str(&format!("\n\nWarning: {}", w));
    }

    // DX pain point 21 (2026-07-14): `update_config` replaces the whole
    // config object, so surface which existing keys the replace dropped
    // — in the message AND as a machine-parsable "dropped_keys" field
    // (additive: existing consumers reading content[0] text see the
    // same shape as before, just with this warning appended when it
    // fires). Always present (possibly empty) for update_config; a
    // "hint" pointing at merge_config is added only when non-empty.
    let mut machine_block: Option<serde_json::Value> = None;
    if action == "update_config" {
        let dk = dropped_keys.unwrap_or_default();
        if dk.is_empty() {
            machine_block = Some(serde_json::json!({ "dropped_keys": dk }));
        } else {
            let hint = "update_config replaces the whole config object, so keys not present in \
                the new value are dropped. Use merge_config (RFC 7386 JSON Merge Patch) to change \
                specific keys without touching the rest.";
            msg.push_str(&format!(
                "\n\nWarning: dropped {} existing config key(s) not present in the new config: [{}]. {}",
                dk.len(),
                dk.join(", "),
                hint
            ));
            machine_block = Some(serde_json::json!({ "dropped_keys": dk, "hint": hint }));
        }
    }

    // Auto-publish if this workflow has an active published version
    // (shared helper — see maybe_auto_publish).
    msg.push_str(
        maybe_auto_publish(state, wf_id, user_id, "Auto-published after config update")
            .await
            .message_suffix(),
    );

    match machine_block {
        Some(mb) => mcp_text_with_json(req_id, &msg, mb),
        None => mcp_text(req_id, &msg),
    }
}

// ── update_node_positions ───────────────────────────────────────────────────

async fn handle_update_node_positions(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let positions = match args.get("positions").and_then(|v| v.as_object()) {
        Some(p) => p.clone(),
        None => return mcp_error(req_id, -32602, "Missing 'positions' object"),
    };
    if positions.is_empty() {
        return mcp_error(req_id, -32602, "Positions map is empty");
    }
    if positions.len() > 5000 {
        return mcp_error(req_id, -32602, "positions map must contain ≤ 5000 entries");
    }

    let graph_json_str = match fetch_graph_json(state, wf_id, user_id, &req_id).await {
        Ok(gj) => gj,
        Err(e) => return e,
    };

    let mut graph: serde_json::Value =
        serde_json::from_str(&graph_json_str).unwrap_or(serde_json::json!({"nodes":[],"edges":[]}));
    let mut updated_count = 0;
    // MCP-149 (2026-05-08): track which positions actually matched a
    // node so we can surface the rest as `unknown_node_ids`. Pre-fix
    // this surface silently dropped typo'd ids and reported a
    // misleading "Updated positions for N nodes" — operator passing
    // 5 ids with 3 typos couldn't tell anything was wrong.
    let mut matched_node_ids: std::collections::HashSet<String> = std::collections::HashSet::new();

    if let Some(nodes) = graph.get_mut("nodes").and_then(|n| n.as_array_mut()) {
        for node in nodes.iter_mut() {
            let node_id = node
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if let Some(pos_val) = positions.get(&node_id) {
                // MCP-244 (2026-05-08): pre-fix `pos_val.get("x").and_then(|v|
                // v.as_f64())` returned None for both ABSENT and WRONG-TYPE
                // (`x: "abc"`). The downstream `if x.is_some() || y.is_some()`
                // would then partially apply: y updates, x silently dropped.
                // Same MCP-187 wrong-type confusion. Distinguish absent from
                // wrong-type and reject the wrong-type case explicitly.
                let x = match pos_val.get("x") {
                    None | Some(serde_json::Value::Null) => None,
                    Some(v) => match v.as_f64() {
                        Some(f) => Some(f),
                        None => {
                            return mcp_error(
                                req_id,
                                -32602,
                                &format!(
                                    "position x for node '{}' must be a number, got {}",
                                    node_id,
                                    crate::utils::json_type_name(v)
                                ),
                            )
                        }
                    },
                };
                let y = match pos_val.get("y") {
                    None | Some(serde_json::Value::Null) => None,
                    Some(v) => match v.as_f64() {
                        Some(f) => Some(f),
                        None => {
                            return mcp_error(
                                req_id,
                                -32602,
                                &format!(
                                    "position y for node '{}' must be a number, got {}",
                                    node_id,
                                    crate::utils::json_type_name(v)
                                ),
                            )
                        }
                    },
                };
                if let Some(xv) = x {
                    if !xv.is_finite() {
                        return mcp_error(req_id, -32602, "position x must be a finite number");
                    }
                }
                if let Some(yv) = y {
                    if !yv.is_finite() {
                        return mcp_error(req_id, -32602, "position y must be a finite number");
                    }
                }
                if x.is_some() || y.is_some() {
                    let pos = node.get_mut("position").and_then(|p| p.as_object_mut());
                    if let Some(pos) = pos {
                        if let Some(xv) = x {
                            pos.insert("x".to_string(), serde_json::json!(xv));
                        }
                        if let Some(yv) = y {
                            pos.insert("y".to_string(), serde_json::json!(yv));
                        }
                    } else if let Some(obj) = node.as_object_mut() {
                        obj.insert(
                            "position".to_string(),
                            serde_json::json!({
                                "x": x.unwrap_or(0.0),
                                "y": y.unwrap_or(0.0),
                            }),
                        );
                    } else {
                        return mcp_error(req_id, -32602, "Invalid node structure");
                    }
                    matched_node_ids.insert(node_id.clone());
                    updated_count += 1;
                }
            }
        }
    }

    // Compute the set of position keys that did NOT correspond to a real
    // node. Sorted for deterministic output.
    let mut unknown_node_ids: Vec<String> = positions
        .keys()
        .filter(|k| !matched_node_ids.contains(k.as_str()))
        .cloned()
        .collect();
    unknown_node_ids.sort();

    let updated_json = serde_json::to_string(&graph).unwrap_or_default();
    if let Err(e) = save_graph_json(state, wf_id, user_id, &updated_json, &req_id).await {
        return e;
    }

    // MCP-150 (2026-05-08): JSON envelope. Pre-fix this surface
    // returned plain text — same sweep family as MCP-141.
    let mut response = serde_json::json!({
        "success": true,
        "workflow_id": wf_id.to_string(),
        "updated_count": updated_count,
        "count": updated_count,
        "message": format!("Updated positions for {} nodes in workflow {}.", updated_count, wf_id),
    });
    if !unknown_node_ids.is_empty() {
        if let Some(map) = response.as_object_mut() {
            map.insert(
                "unknown_node_ids".to_string(),
                serde_json::json!(unknown_node_ids),
            );
            map.insert(
                "warning".to_string(),
                serde_json::json!(format!(
                    "{} node id(s) in the positions map did not match any node in the workflow and were ignored. Check unknown_node_ids for the list.",
                    unknown_node_ids.len()
                )),
            );
        }
    }
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&response).unwrap_or_default(),
    )
}

// ── duplicate_node ──────────────────────────────────────────────────────────

async fn handle_duplicate_node(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let source_node_id = match crate::utils::require_node_id(args, "source_node_id", req_id.clone())
    {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let new_node_id = match crate::utils::require_node_id(args, "new_node_id", req_id.clone()) {
        Ok(s) => s,
        Err(resp) => return resp,
    };

    // Load existing graph
    let graph_json_str = match fetch_graph_json(state, wf_id, user_id, &req_id).await {
        Ok(gj) => gj,
        Err(e) => return e,
    };

    let mut graph: serde_json::Value =
        serde_json::from_str(&graph_json_str).unwrap_or(serde_json::json!({"nodes":[],"edges":[]}));

    // Find the source node
    let source_node = match talos_workflow_repository::find_node_by_id(&graph, &source_node_id) {
        Some(n) => n.clone(),
        None => {
            return mcp_error(
                req_id,
                -32000,
                &format!("Source node '{}' not found in workflow", source_node_id),
            )
        }
    };

    // Check new_node_id doesn't already exist
    if talos_workflow_repository::graph_contains_node_id(&graph, &new_node_id) {
        return mcp_error(
            req_id,
            -32602,
            &format!("Node '{}' already exists in workflow", new_node_id),
        );
    }

    // Clone the node with new ID and offset position
    let mut new_node = source_node.clone();
    if let Some(obj) = new_node.as_object_mut() {
        obj.insert("id".to_string(), serde_json::json!(new_node_id));
    } else {
        return mcp_error(req_id, -32602, "Invalid node structure");
    }

    // Offset position by +150px on x
    let orig_x = source_node
        .get("position")
        .and_then(|p| p.get("x"))
        .and_then(|x| x.as_f64())
        .unwrap_or(250.0);
    let orig_y = source_node
        .get("position")
        .and_then(|p| p.get("y"))
        .and_then(|y| y.as_f64())
        .unwrap_or(100.0);
    if let Some(obj) = new_node.as_object_mut() {
        obj.insert(
            "position".to_string(),
            serde_json::json!({ "x": orig_x + 150.0, "y": orig_y }),
        );
    } else {
        return mcp_error(req_id, -32602, "Invalid node structure");
    }

    if let Some(nodes) = graph.get_mut("nodes").and_then(|n| n.as_array_mut()) {
        nodes.push(new_node.clone());
    }

    let updated_json = graph.to_string();
    // MCP-737 (2026-05-13): propagate save errors instead of silently
    // discarding. Pre-fix `let _ = save_graph_json_unchecked(...).await;`
    // swallowed the Err(JsonRpcResponse) — the handler then returned
    // "Node 'X' duplicated" success even when the underlying graph
    // save failed (DB outage, encryption-key rotation in flight,
    // etc.). User reloaded, saw no change, and had no signal that
    // their mutation was lost. The save_graph_json_unchecked
    // signature is explicitly `Result<(), JsonRpcResponse>` so the
    // Err variant carries a fully-formed error response — propagating
    // it is the documented contract. Sibling siblings at lines 2098
    // (handle_remove_node) and 2151 (handle_update_node_config)
    // closed in the same commit.
    if let Err(resp) = save_graph_json_unchecked(state, wf_id, &updated_json, &req_id).await {
        return resp;
    }

    let sync_note =
        maybe_auto_publish(state, wf_id, user_id, "Auto-published after node duplicate")
            .await
            .message_suffix();

    mcp_text(
        req_id,
        &format!(
            "Node '{}' duplicated as '{}' in workflow {}.\nNew node: {}{}",
            source_node_id,
            new_node_id,
            wf_id,
            serde_json::to_string_pretty(&new_node).unwrap_or_default(),
            sync_note
        ),
    )
}

// ── add_edge ────────────────────────────────────────────────────────────────

async fn handle_add_edge(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let source = match crate::utils::require_node_id(args, "source", req_id.clone()) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let target = match crate::utils::require_node_id(args, "target", req_id.clone()) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    // MCP-236 (2026-05-08): trim edge condition. Pre-fix `condition: "   "`
    // bypassed the optional check (was Some), passed Rhai compile (whitespace
    // is a valid empty Rhai script), and was persisted on the edge — at
    // runtime the empty script evaluates to unit `()` instead of bool, and
    // the engine's boolean coercion silently treats every edge as falsy
    // (or truthy depending on coercion path). Same MCP-235 family. Empty
    // string and pure whitespace fall through to None so the edge is
    // unconditional, matching the documented "omit for unconditional"
    // contract.
    let condition_owned: Option<String> = match args.get("condition").and_then(|v| v.as_str()) {
        Some(c) if c.len() > 2000 => {
            return mcp_error(req_id, -32602, "condition must be ≤2000 characters");
        }
        Some(c) => {
            let trimmed = c.trim();
            if trimmed.is_empty() {
                None
            } else {
                if let Err(msg) = validate_rhai_expression("condition", trimmed) {
                    return mcp_error(req_id, -32602, &msg);
                }
                Some(trimmed.to_string())
            }
        }
        None => None,
    };
    let condition: Option<&str> = condition_owned.as_deref();
    // MCP-359 (2026-05-11): pre-fix `.and_then(as_str)` collapsed both
    // absent AND wrong-type into "default". Operator passing
    // `edge_type: 42` (number) silently got "default" — see the
    // sibling fix in workflows.rs::handle_add_edge_to_workflow for the
    // direction-class rationale.
    let edge_type = match args.get("edge_type") {
        None | Some(serde_json::Value::Null) => "default",
        Some(v) => match v.as_str() {
            Some(et) if et.len() > 50 => {
                return mcp_error(req_id, -32602, "edge_type must be ≤ 50 characters")
            }
            Some(et) => et,
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("edge_type must be a string, got {kind}"),
                );
            }
        },
    };

    // Load existing graph
    let graph_json_str = match fetch_graph_json(state, wf_id, user_id, &req_id).await {
        Ok(gj) => gj,
        Err(e) => return e,
    };

    let mut graph: serde_json::Value =
        serde_json::from_str(&graph_json_str).unwrap_or(serde_json::json!({"nodes":[],"edges":[]}));

    // Validate both nodes exist
    if !talos_workflow_repository::graph_contains_node_id(&graph, &source) {
        return mcp_error(
            req_id,
            -32000,
            &format!("Source node '{}' not found in workflow", source),
        );
    }
    if !talos_workflow_repository::graph_contains_node_id(&graph, &target) {
        return mcp_error(
            req_id,
            -32000,
            &format!("Target node '{}' not found in workflow", target),
        );
    }

    // Build the new edge
    let mut new_edge = serde_json::json!({
        "source": source,
        "target": target,
    });
    if edge_type != "default" {
        if let Some(obj) = new_edge.as_object_mut() {
            obj.insert("edge_type".to_string(), serde_json::json!(edge_type));
        }
    }
    if let Some(cond) = condition {
        if let Some(obj) = new_edge.as_object_mut() {
            obj.insert("condition".to_string(), serde_json::json!(cond));
        }
        if edge_type == "default" {
            if let Some(obj) = new_edge.as_object_mut() {
                obj.insert("edge_type".to_string(), serde_json::json!("conditional"));
            }
        }
    }

    if let Some(edges) = graph.get_mut("edges").and_then(|e| e.as_array_mut()) {
        edges.push(new_edge);
    }

    let updated_json = graph.to_string();
    // MCP-737: propagate save errors — see duplicate_node above for rationale.
    if let Err(resp) = save_graph_json_unchecked(state, wf_id, &updated_json, &req_id).await {
        return resp;
    }

    let sync_note = maybe_auto_publish(state, wf_id, user_id, "Auto-published after edge add")
        .await
        .message_suffix();

    mcp_text(
        req_id,
        &format!(
            "Edge added: {} -> {} in workflow {}.{}",
            source, target, wf_id, sync_note
        ),
    )
}

// ── remove_edge ─────────────────────────────────────────────────────────────

async fn handle_remove_edge(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let source = match crate::utils::require_node_id(args, "source", req_id.clone()) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let target = match crate::utils::require_node_id(args, "target", req_id.clone()) {
        Ok(s) => s,
        Err(resp) => return resp,
    };

    // Load existing graph
    let graph_json_str = match fetch_graph_json(state, wf_id, user_id, &req_id).await {
        Ok(gj) => gj,
        Err(e) => return e,
    };

    let mut graph: serde_json::Value =
        serde_json::from_str(&graph_json_str).unwrap_or(serde_json::json!({"nodes":[],"edges":[]}));

    let removed = talos_workflow_repository::remove_edge_by_endpoints(&mut graph, &source, &target);

    if !removed {
        return mcp_error(
            req_id,
            -32000,
            &format!("Edge {} -> {} not found in workflow", source, target),
        );
    }

    let updated_json = graph.to_string();
    // MCP-737: propagate save errors — see duplicate_node above for rationale.
    if let Err(resp) = save_graph_json_unchecked(state, wf_id, &updated_json, &req_id).await {
        return resp;
    }

    let sync_note = maybe_auto_publish(state, wf_id, user_id, "Auto-published after edge removal")
        .await
        .message_suffix();

    mcp_text(
        req_id,
        &format!(
            "Edge {} -> {} removed from workflow {}.{}",
            source, target, wf_id, sync_note
        ),
    )
}

// ── add_loop_node ──────────────────────────────────────────────────────────

async fn handle_add_loop_node(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let workflow_id = match args
        .get("workflow_id")
        .and_then(|v| v.as_str())
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
    {
        Some(id) => id,
        None => return mcp_error(req_id, -32602, "Missing or invalid 'workflow_id' parameter"),
    };
    let body_node_id = match crate::utils::require_node_id(args, "body_node_id", req_id.clone()) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    // MCP-235 (2026-05-08): trim Rhai expressions at the boundary;
    // whitespace passed `c.is_empty()`, was persisted into the loop
    // node config, and at runtime Rhai evaluated the empty script as
    // unit `()` — surfacing the misleading "Output type incorrect"
    // error attributed to the operator's expression. Same MCP-208
    // (test_condition) family.
    let condition = match args.get("condition").and_then(|v| v.as_str()) {
        Some(c) if c.trim().is_empty() => {
            return mcp_error(
                req_id,
                -32602,
                "Missing or empty (whitespace-only) 'condition' parameter",
            )
        }
        Some(c) if c.len() > 2000 => {
            return mcp_error(req_id, -32602, "condition must be ≤2000 characters")
        }
        Some(c) => c.trim().to_string(),
        None => return mcp_error(req_id, -32602, "Missing or empty 'condition' parameter"),
    };
    if let Err(msg) = validate_rhai_expression("condition", &condition) {
        return mcp_error(req_id, -32602, &msg);
    }
    // MCP-160 (2026-05-08): reject out-of-range max_iterations
    // loudly instead of silently clamping. The pre-fix code was
    // `unwrap_or(10).min(100) as u32`, which accepted 9999 and
    // returned 100 with no warning — the message echoed the
    // clamped value, so a caller had no way to notice they were
    // not getting the loop budget they asked for. Mirrors the
    // [1, 50] validation already on `add_react_loop_node` and
    // `add_agent_loop_node`. Range stays at [1, 100] for
    // back-compat with workflows that explicitly set 100.
    let max_iterations =
        match crate::utils::validate_range_u64(args, "max_iterations", 1, 100, 10, &req_id) {
            Ok(n) => n as u32,
            Err(resp) => return resp,
        };

    // Verify workflow ownership AND body_node_id exists in the graph.
    // The body_node_id check requires fetching the graph BEFORE the
    // helper does its own fetch — accepted as a one-time double-fetch
    // (graphs are small, the second read hits the warm Postgres cache)
    // to avoid extending the helper's signature with a graph-validator
    // callback for a single caller. Both reads go through the
    // user-scoped repo method, so the auth gate fires twice.
    if !state
        .workflow_repo
        .workflow_exists(workflow_id, user_id)
        .await
    {
        return crate::utils::workflow_not_found_error(req_id);
    }
    let pre_graph_json = match fetch_graph_json_unchecked(state, workflow_id, &req_id).await {
        Ok(gj) => gj,
        Err(e) => return e,
    };
    let pre_graph: serde_json::Value = serde_json::from_str(&pre_graph_json)
        .unwrap_or_else(|_| serde_json::json!({"nodes": [], "edges": []}));
    if !talos_workflow_repository::graph_contains_node_id(&pre_graph, &body_node_id) {
        return mcp_error(
            req_id,
            -32602,
            &format!(
                "body_node_id '{}' not found in workflow. The body node must already exist.",
                body_node_id
            ),
        );
    }

    let data = serde_json::json!({
        "body_node_id": body_node_id,
        "condition": condition,
        "max_iterations": max_iterations,
    });

    let connect_from = args
        .get("connect_from")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let connect_to = args
        .get("connect_to")
        .and_then(|v| v.as_str())
        .map(str::to_string);

    let added = match upsert_system_node(&req_id, args, state, &agent, "loop", data).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    let mut edges_wired: Vec<String> = Vec::new();
    if let Some(ref f) = connect_from {
        edges_wired.push(format!("{} → {}", f, added.node_id));
    }
    if let Some(ref t) = connect_to {
        edges_wired.push(format!("{} → {}", added.node_id, t));
    }
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            "workflow_id": added.workflow_id.to_string(),
            "node_id": added.node_id,
            "node_type": "loop",
            "body_node_id": body_node_id,
            "condition": condition,
            "max_iterations": max_iterations,
            "edges_wired": edges_wired,
            "message": format!(
                "Loop node '{}' added to workflow {}. Body: '{}', condition: '{}', max_iterations: {}.{}",
                added.node_id, added.workflow_id, body_node_id, condition, max_iterations, added.auto_publish_note
            ),
        }))
        .unwrap_or_default(),
    )
}

// ── add_collect_node ────────────────────────────────────────────────────────

async fn handle_add_collect_node(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    // Capture connect_from sources ahead of the helper so the response
    // body can include the parent-branches list (helper drops the list
    // after converting it to a display string).
    let connect_from_sources: Vec<String> = match args.get("connect_from") {
        Some(serde_json::Value::String(s)) => vec![s.clone()],
        Some(serde_json::Value::Array(arr)) => arr
            .iter()
            .filter_map(|x| x.as_str().map(str::to_string))
            .collect(),
        _ => vec![],
    };
    let connect_to = args
        .get("connect_to")
        .and_then(|v| v.as_str())
        .map(str::to_string);

    let added = match upsert_system_node(
        &req_id,
        args,
        state,
        &agent,
        "collect",
        serde_json::json!({}),
    )
    .await
    {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    let mut edges_wired: Vec<String> = connect_from_sources
        .iter()
        .map(|f| format!("{} → {}", f, added.node_id))
        .collect();
    if let Some(ref t) = connect_to {
        edges_wired.push(format!("{} → {}", added.node_id, t));
    }
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            "workflow_id": added.workflow_id.to_string(),
            "node_id": added.node_id,
            "node_type": "collect",
            "parent_branches": connect_from_sources,
            "downstream": connect_to,
            "edges_wired": edges_wired,
            "message": format!(
                "Collect node '{}' added to workflow {}. Fan-in node — gathers all parent branch outputs into {{count, items: [...]}}.{}",
                added.node_id, added.workflow_id, added.auto_publish_note
            ),
        }))
        .unwrap_or_default(),
    )
}

// ── add_assistant_report_node ────────────────────────────────────────────────

async fn handle_add_assistant_report_node(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    // Clamp mirrors the graph parser (defense in depth).
    let days = args
        .get("days")
        .and_then(serde_json::Value::as_u64)
        .map_or(7u64, |v| v.clamp(1, 31));
    let connect_to = args
        .get("connect_to")
        .and_then(|v| v.as_str())
        .map(str::to_string);

    let added = match upsert_system_node(
        &req_id,
        args,
        state,
        &agent,
        "assistant_report",
        serde_json::json!({ "days": days }),
    )
    .await
    {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            "workflow_id": added.workflow_id.to_string(),
            "node_id": added.node_id,
            "node_type": "assistant_report",
            "days": days,
            "downstream": connect_to,
            "message": format!(
                "Assistant-report node '{}' added to workflow {}. Emits {{available, window_days, workflows: [...], cost, ops_alerts: {{..., correction_candidates}}, ml: {{models: [...]}}}} for downstream compose nodes.{}",
                added.node_id, added.workflow_id, added.auto_publish_note
            ),
        }))
        .unwrap_or_default(),
    )
}

// ── add_ops_alerts_digest_node ───────────────────────────────────────────────

async fn handle_add_ops_alerts_digest_node(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    // Clamp mirrors the graph parser (defense in depth — a hand-edited
    // graph re-clamps at parse time anyway).
    let top_limit = args
        .get("top_limit")
        .and_then(serde_json::Value::as_u64)
        .map_or(10u64, |v| v.clamp(1, 25));
    let connect_to = args
        .get("connect_to")
        .and_then(|v| v.as_str())
        .map(str::to_string);

    let added = match upsert_system_node(
        &req_id,
        args,
        state,
        &agent,
        "ops_alerts_digest",
        serde_json::json!({ "top_limit": top_limit }),
    )
    .await
    {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            "workflow_id": added.workflow_id.to_string(),
            "node_id": added.node_id,
            "node_type": "ops_alerts_digest",
            "top_limit": top_limit,
            "downstream": connect_to,
            "message": format!(
                "Ops-alerts digest node '{}' added to workflow {}. Emits {{available, digest: {{active_by_severity, active_by_source, new_last_24h, reopened_active}}, top_active: [...]}} for downstream compose nodes.{}",
                added.node_id, added.workflow_id, added.auto_publish_note
            ),
        }))
        .unwrap_or_default(),
    )
}

// ── add_sub_workflow_node ────────────────────────────────────────────────────

async fn handle_add_sub_workflow_node(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let sub_workflow_id = match args
        .get("sub_workflow_id")
        .and_then(|v| v.as_str())
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
    {
        Some(id) => id,
        None => {
            return mcp_error(
                req_id,
                -32602,
                "Missing or invalid 'sub_workflow_id' parameter",
            )
        }
    };
    // Extra gates BEFORE the helper: self-reference and sub-workflow
    // ownership. Parent ownership is handled inside the helper.
    if let Some(parent_wf_id) = crate::utils::optional_uuid(args, "workflow_id") {
        if parent_wf_id == sub_workflow_id {
            return mcp_error(
                req_id,
                -32602,
                "A workflow cannot reference itself as a sub-workflow",
            );
        }
    }
    if !state
        .workflow_repo
        .workflow_exists(sub_workflow_id, user_id)
        .await
    {
        return mcp_error(req_id, -32000, "Sub-workflow not found or access denied");
    }
    // MCP-237 (2026-05-08): MCP-227 family — pre-fix as_u64-then-
    // unwrap_or silently substituted 30 for negative / fractional /
    // wrong-type. Switched to validate_range_u64 [1, 600] (per-node
    // timeout matches workflow-level test_workflow ceiling).
    let timeout_secs =
        match crate::utils::validate_range_u64(args, "timeout_secs", 1, 600, 30, &req_id) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    let data = serde_json::json!({
        "sub_workflow_id": sub_workflow_id.to_string(),
        "timeout_secs": timeout_secs,
    });

    let connect_from = args
        .get("connect_from")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let connect_to = args
        .get("connect_to")
        .and_then(|v| v.as_str())
        .map(str::to_string);

    let added = match upsert_system_node(&req_id, args, state, &agent, "sub_workflow", data).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    let mut edges_wired: Vec<String> = Vec::new();
    if let Some(ref f) = connect_from {
        edges_wired.push(format!("{} → {}", f, added.node_id));
    }
    if let Some(ref t) = connect_to {
        edges_wired.push(format!("{} → {}", added.node_id, t));
    }
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            "workflow_id": added.workflow_id.to_string(),
            "node_id": added.node_id,
            "node_type": "sub_workflow",
            "sub_workflow_id": sub_workflow_id.to_string(),
            "timeout_secs": timeout_secs,
            "edges_wired": edges_wired,
            "message": format!(
                "Sub-workflow node '{}' added to workflow {}. Invokes workflow {} with {}s timeout.{}",
                added.node_id, added.workflow_id, sub_workflow_id, timeout_secs, added.auto_publish_note
            ),
        }))
        .unwrap_or_default(),
    )
}

// ── copy_node ────────────────────────────────────────────────────────────────

async fn handle_copy_node(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let source_wf_id = match crate::utils::require_uuid(args, "source_workflow_id", req_id.clone())
    {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let source_node_id = match crate::utils::require_node_id(args, "source_node_id", req_id.clone())
    {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let target_wf_id = match crate::utils::require_uuid(args, "target_workflow_id", req_id.clone())
    {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let target_node_id = match crate::utils::require_node_id(args, "target_node_id", req_id.clone())
    {
        Ok(s) => s,
        Err(resp) => return resp,
    };

    // Load source workflow graph
    let source_graph_str = match fetch_graph_json(state, source_wf_id, user_id, &req_id).await {
        Ok(gj) => gj,
        Err(e) => return e,
    };

    let source_graph: serde_json::Value = serde_json::from_str(&source_graph_str)
        .unwrap_or(serde_json::json!({"nodes":[],"edges":[]}));

    // Find the source node
    let source_node =
        match talos_workflow_repository::find_node_by_id(&source_graph, &source_node_id) {
            Some(n) => n.clone(),
            None => {
                return mcp_error(
                    req_id,
                    -32000,
                    &format!("Node '{}' not found in source workflow", source_node_id),
                )
            }
        };

    // Load target workflow graph
    let target_graph_str = match fetch_graph_json(state, target_wf_id, user_id, &req_id).await {
        Ok(gj) => gj,
        Err(e) => return e,
    };

    let mut target_graph: serde_json::Value = serde_json::from_str(&target_graph_str)
        .unwrap_or(serde_json::json!({"nodes":[],"edges":[]}));

    // Check target_node_id doesn't already exist
    if talos_workflow_repository::graph_contains_node_id(&target_graph, &target_node_id) {
        return mcp_error(
            req_id,
            -32602,
            &format!(
                "Node '{}' already exists in target workflow",
                target_node_id
            ),
        );
    }

    // Build the new node with target_node_id and offset position
    let mut new_node = source_node.clone();
    if let Some(obj) = new_node.as_object_mut() {
        obj.insert("id".to_string(), serde_json::json!(target_node_id));
    }

    // Offset position by +100,+100 to avoid overlap
    if let Some(pos) = new_node.get("position").cloned() {
        let x = pos.get("x").and_then(|v| v.as_f64()).unwrap_or(0.0) + 100.0;
        let y = pos.get("y").and_then(|v| v.as_f64()).unwrap_or(0.0) + 100.0;
        if let Some(obj) = new_node.as_object_mut() {
            obj.insert("position".to_string(), serde_json::json!({"x": x, "y": y}));
        }
    }

    // Add the node to target graph
    if let Some(nodes) = target_graph.get_mut("nodes").and_then(|n| n.as_array_mut()) {
        nodes.push(new_node);
    }

    // Save target workflow
    let updated_graph_str = serde_json::to_string(&target_graph).unwrap_or_default();
    if let Err(e) = save_graph_json(state, target_wf_id, user_id, &updated_graph_str, &req_id).await
    {
        return e;
    }

    let sync_note = maybe_auto_publish(
        state,
        target_wf_id,
        user_id,
        "Auto-published after node copy",
    )
    .await
    .message_suffix();

    mcp_text(
        req_id,
        &format!(
            "Node '{}' copied from workflow {} to workflow {} as '{}'.{}",
            source_node_id, source_wf_id, target_wf_id, target_node_id, sync_note
        ),
    )
}

// ── set_node_description ─────────────────────────────────────────────────────

async fn handle_set_node_description(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    // MCP-226 (2026-05-08): trim node_id at the boundary, mirroring
    // require_node_id (utils.rs). Pre-fix `!id.is_empty()` accepted
    // whitespace-only IDs which were then either (a) persisted into
    // the graph or (b) sent to a node lookup that always missed.
    let node_id = match args.get("node_id").and_then(|v| v.as_str()) {
        Some(id) => {
            let trimmed = id.trim();
            if trimmed.is_empty() {
                return mcp_error(req_id, -32602, "Invalid or missing 'node_id'");
            }
            trimmed.to_string()
        }
        _ => return mcp_error(req_id, -32602, "Invalid or missing 'node_id'"),
    };
    // MCP-186 (2026-05-08): reject whitespace-only descriptions.
    // Pre-fix only the length was validated, so a 16-space
    // description was accepted and persisted on the node — same
    // family as MCP-167 (workflow_suspension description).
    //
    // MCP-381 (2026-05-11): pre-fix `Some(d) => d.to_string()`
    // persisted UNTRIMMED. Node descriptions surface in the workflow
    // graph display, get_workflow_graph response, and the
    // `node_description` field that downstream observability uses for
    // operator-facing labels. Padding pollutes all three. Trim post-
    // emptiness-check; re-validate length on the trimmed value so
    // padding can't bypass the 500-char cap. Same MCP-372 / MCP-373 /
    // MCP-374 family applied to node-level description.
    let description = match args.get("description").and_then(|v| v.as_str()) {
        Some(d) if d.trim().is_empty() => {
            return mcp_error(
                req_id,
                -32602,
                "description must be a non-empty, non-whitespace string",
            )
        }
        Some(d) if d.trim().len() > 500 => {
            return mcp_error(req_id, -32602, "description must be ≤ 500 characters")
        }
        Some(d) => d.trim().to_string(),
        None => return mcp_error(req_id, -32602, "Invalid or missing 'description'"),
    };

    // Load workflow graph
    let graph_json_str = match fetch_graph_json(state, wf_id, user_id, &req_id).await {
        Ok(gj) => gj,
        Err(e) => return e,
    };

    let mut graph: serde_json::Value =
        serde_json::from_str(&graph_json_str).unwrap_or(serde_json::json!({"nodes":[],"edges":[]}));

    // Find the node and set description
    let mut found = false;
    if let Some(nodes) = graph.get_mut("nodes").and_then(|n| n.as_array_mut()) {
        for node in nodes.iter_mut() {
            if node.get("id").and_then(|v| v.as_str()) == Some(&node_id) {
                if let Some(obj) = node.as_object_mut() {
                    obj.insert("description".to_string(), serde_json::json!(description));
                }
                found = true;
                break;
            }
        }
    }

    if !found {
        return mcp_error(
            req_id,
            -32000,
            &format!("Node '{}' not found in workflow", node_id),
        );
    }

    // Save updated graph
    let updated_graph_str = serde_json::to_string(&graph).unwrap_or_default();
    if let Err(e) = save_graph_json(state, wf_id, user_id, &updated_graph_str, &req_id).await {
        return e;
    }

    let sync_note = maybe_auto_publish(
        state,
        wf_id,
        user_id,
        "Auto-published after node description update",
    )
    .await
    .message_suffix();

    // MCP-150 (2026-05-08): JSON envelope on success.
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            "success": true,
            "workflow_id": wf_id.to_string(),
            "node_id": node_id,
            "message": format!(
                "Description set on node '{}' in workflow {}.{}",
                node_id, wf_id, sync_note
            ),
        }))
        .unwrap_or_default(),
    )
}

// ── duplicate_workflow ────────────────────────────────────────────────────────

async fn handle_duplicate_workflow(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);

    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // Fetch original workflow
    let src = match state
        .workflow_repo
        .get_workflow_for_duplicate(wf_id, user_id)
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return mcp_error(req_id, -32000, "Workflow not found or access denied"),
        Err(e) => {
            tracing::error!("duplicate_workflow fetch failed: {:#}", e);
            return mcp_error(req_id, -32000, "Failed to fetch workflow");
        }
    };

    let original_name = src.name;
    let mut graph_json = src.graph_json;
    let existing_tags = src.tags;

    // MCP-173 (2026-05-08): reject whitespace-only override names.
    // Same family as MCP-172 (clone_workflow). Pre-fix a 16-space
    // name silently persisted as the duplicate's name.
    let new_name = match args.get("name").and_then(|v| v.as_str()) {
        Some(n) if n.trim().is_empty() => {
            return mcp_error(
                req_id,
                -32602,
                "Workflow name must be a non-empty, non-whitespace string",
            )
        }
        Some(n) if n.len() > 200 => {
            return mcp_error(req_id, -32602, "Workflow name too long (max 200 chars)")
        }
        Some(n) => n.to_string(),
        None => format!("Copy of {}", original_name),
    };

    // Apply modifications
    let modifications = args.get("modifications");

    // Remove nodes from graph
    // MCP-297 (2026-05-11): pre-fix `filter_map(|v| v.as_str()...)`
    // silently dropped non-string entries in remove_nodes. Operator's
    // `remove_nodes: ["node-1", 42, "node-2"]` silently dropped 42
    // and only removed two of the three nodes they intended. Reject
    // malformed entries upfront with the bad index. Same MCP-274
    // family. (Destructive op; silent drop = silent retention.)
    if let Some(remove_nodes) = modifications
        .and_then(|m| m.get("remove_nodes"))
        .and_then(|v| v.as_array())
    {
        let remove_ids: std::collections::HashSet<String> = {
            let mut out: std::collections::HashSet<String> =
                std::collections::HashSet::with_capacity(remove_nodes.len());
            for (i, v) in remove_nodes.iter().enumerate() {
                match v.as_str() {
                    Some(s) => {
                        out.insert(s.to_string());
                    }
                    None => {
                        let kind = crate::utils::json_type_name(v);
                        return mcp_error(
                            req_id,
                            -32602,
                            &format!(
                                "modifications.remove_nodes[{i}] must be a string, got {kind}"
                            ),
                        );
                    }
                }
            }
            out
        };

        if !remove_ids.is_empty() {
            if let Ok(mut graph) = serde_json::from_str::<serde_json::Value>(&graph_json) {
                // Remove specified nodes
                if let Some(nodes) = graph.get_mut("nodes").and_then(|n| n.as_array_mut()) {
                    nodes.retain(|node| {
                        let node_id = node.get("id").and_then(|v| v.as_str()).unwrap_or("");
                        !remove_ids.contains(node_id)
                    });
                }

                // Remove edges connected to removed nodes
                if let Some(edges) = graph.get_mut("edges").and_then(|e| e.as_array_mut()) {
                    edges.retain(|edge| {
                        let source = edge.get("source").and_then(|v| v.as_str()).unwrap_or("");
                        let target = edge.get("target").and_then(|v| v.as_str()).unwrap_or("");
                        !remove_ids.contains(source) && !remove_ids.contains(target)
                    });
                }

                graph_json = serde_json::to_string(&graph).unwrap_or(graph_json);
            }
        }
    }

    // Patch node configs (merge specified keys into matching node's config/data)
    if let Some(patches) = modifications
        .and_then(|m| m.get("patch_node_configs"))
        .and_then(|v| v.as_object())
    {
        if !patches.is_empty() {
            if let Ok(mut graph) = serde_json::from_str::<serde_json::Value>(&graph_json) {
                if let Some(nodes) = graph.get_mut("nodes").and_then(|n| n.as_array_mut()) {
                    for node in nodes.iter_mut() {
                        let node_id = node
                            .get("id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        if let Some(patch) = patches.get(&node_id).and_then(|v| v.as_object()) {
                            // Merge patch into node's data object (or config)
                            let data = node
                                .as_object_mut()
                                .and_then(|n| n.get_mut("data"))
                                .and_then(|d| d.as_object_mut());
                            if let Some(data_map) = data {
                                for (k, v) in patch {
                                    data_map.insert(k.clone(), v.clone());
                                }
                            } else if let Some(node_map) = node.as_object_mut() {
                                // Fallback: merge directly into node if no data sub-object
                                for (k, v) in patch {
                                    node_map.insert(k.clone(), v.clone());
                                }
                            }
                        }
                    }
                }
                graph_json = serde_json::to_string(&graph).unwrap_or(graph_json);
            }
        }
    }

    // Merge tags
    let mut tags: Vec<String> = existing_tags;

    if let Some(add_tags) = modifications
        .and_then(|m| m.get("add_tags"))
        .and_then(|v| v.as_array())
    {
        for tag_val in add_tags {
            if tags.len() >= 100 {
                return mcp_error(
                    req_id,
                    -32602,
                    "Cannot add tags: workflow would exceed 100-tag maximum",
                );
            }
            if let Some(tag) = tag_val.as_str() {
                let tag_str = tag.to_string();
                if !tags.contains(&tag_str) && tag_str.len() <= 50 {
                    tags.push(tag_str);
                }
            }
        }
    }

    let new_id = uuid::Uuid::new_v4();

    match state
        .workflow_repo
        .insert_duplicated_workflow(new_id, user_id, &new_name, &graph_json, &tags)
        .await
    {
        Ok(_) => {
            // #15 — optionally copy the input_schema from the source workflow
            // MCP-246 (2026-05-08): pre-fix `copy_schema: "true"` (string)
            // silently became false; caller's intent to copy the source
            // schema dropped with no signal. Use validate_optional_bool.
            let copy_schema =
                match crate::utils::validate_optional_bool(args, "copy_schema", false, &req_id) {
                    Ok(b) => b,
                    Err(resp) => return resp,
                };
            // MCP-738 (2026-05-13): reflect the ACTUAL outcome of
            // copy_input_schema instead of echoing the request flag.
            // Pre-fix `let _ = ...await;` silently swallowed copy
            // failures AND the response asserted `input_schema_copied:
            // copy_schema` (the request value, not the outcome) — so
            // when copy_input_schema failed (DB outage, schema-too-
            // large, etc.) the user believed the schema was copied
            // when it wasn't. Now: only true when the copy actually
            // succeeded; log on failure so operators see the gap.
            // Same misleading-success class as MCP-737 (graph save
            // failed but handler returned "Node duplicated").
            let input_schema_copied = if copy_schema {
                match state.workflow_repo.copy_input_schema(wf_id, new_id).await {
                    Ok(_) => true,
                    Err(e) => {
                        tracing::warn!(
                            target: "talos_audit",
                            wf_id = %wf_id,
                            new_id = %new_id,
                            error = %e,
                            "duplicate_workflow: copy_input_schema failed — duplicate succeeded but schema not carried over"
                        );
                        false
                    }
                }
            } else {
                false
            };
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&serde_json::json!({
                    "workflow_id": new_id.to_string(),
                    "name": new_name,
                    "cloned_from": wf_id.to_string(),
                    "tags": tags,
                    "input_schema_copied": input_schema_copied,
                }))
                .unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!("duplicate_workflow insert failed: {:#}", e);
            mcp_error(req_id, -32000, "Failed to duplicate workflow")
        }
    }
}

// ── add_skip_condition ──────────────────────────────────────────────────────

async fn handle_add_skip_condition(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let workflow_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let node_id = match crate::utils::require_node_id(args, "node_id", req_id.clone()) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    // MCP-235 (2026-05-08): trim skip_condition; whitespace bypasses
    // the empty check and gets persisted, then Rhai eval at runtime
    // returns unit `()` instead of bool — silently treats every node
    // as "should NOT skip" rather than the operator's intended skip
    // logic. MCP-208 family.
    let skip_condition = match args.get("skip_condition").and_then(|v| v.as_str()) {
        Some(c) if c.trim().is_empty() => {
            return mcp_error(
                req_id,
                -32602,
                "Missing or empty (whitespace-only) 'skip_condition'",
            )
        }
        Some(c) if c.len() > 2000 => {
            return mcp_error(req_id, -32602, "skip_condition must be ≤2000 characters")
        }
        Some(c) => c.trim().to_string(),
        None => return mcp_error(req_id, -32602, "Missing or empty 'skip_condition'"),
    };

    // Validate the Rhai expression by attempting a dry-run parse
    if let Err(msg) = talos_engine::rhai_helpers::evaluate_condition_with_error(
        &skip_condition,
        &serde_json::json!({}),
    ) {
        // evaluate_condition_with_error returns Err on parse errors, but also on eval errors
        // with empty context. We only reject obvious parse failures.
        if msg.contains("Syntax error") || msg.contains("Parse error") {
            return mcp_error(req_id, -32602, &format!("Invalid Rhai expression: {}", msg));
        }
    }

    let graph_json_str = match fetch_graph_json(state, workflow_id, user_id, &req_id).await {
        Ok(gj) => gj,
        Err(e) => return e,
    };

    let mut graph: serde_json::Value = match serde_json::from_str(&graph_json_str) {
        Ok(g) => g,
        Err(_) => return mcp_error(req_id, -32000, "Invalid graph JSON"),
    };

    // Find and update the node
    let mut found = false;
    if let Some(nodes) = graph.get_mut("nodes").and_then(|n| n.as_array_mut()) {
        for node in nodes.iter_mut() {
            if node.get("id").and_then(|v| v.as_str()) == Some(&node_id) {
                // Add skip_condition to node's data
                if node.get("data").is_none() {
                    if let Some(obj) = node.as_object_mut() {
                        obj.insert("data".to_string(), serde_json::json!({}));
                    }
                }
                if let Some(data) = node.get_mut("data") {
                    if let Some(obj) = data.as_object_mut() {
                        obj.insert(
                            "skip_condition".to_string(),
                            serde_json::json!(skip_condition),
                        );
                    }
                }
                found = true;
                break;
            }
        }
    }

    if !found {
        return mcp_error(
            req_id,
            -32000,
            &format!("Node '{}' not found in workflow graph", node_id),
        );
    }

    let updated_json = serde_json::to_string(&graph).unwrap_or_default();
    if let Err(e) = save_graph_json(state, workflow_id, user_id, &updated_json, &req_id).await {
        return e;
    }

    // Auto-publish if this workflow has an active published version, so the
    // skip condition actually takes effect (shared helper — see
    // maybe_auto_publish). Previously this only appended an advisory note and
    // left the operator to publish manually.
    let note = maybe_auto_publish(
        state,
        workflow_id,
        user_id,
        "Auto-published after skip-condition change",
    )
    .await
    .message_suffix();

    mcp_text(
        req_id,
        &format!(
            "Skip condition added to node '{}' in workflow {}.\nCondition: {}{}",
            node_id, workflow_id, skip_condition, note
        ),
    )
}

// ── add_capability_dispatch_node ─────────────────────────────────────────────

async fn handle_add_capability_dispatch_node(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    // MCP-234 (2026-05-08): trim each capability AND apply the same
    // strict format validation that set_workflow_capabilities uses
    // (lowercase alphanumeric + hyphens, 1-50 chars). Pre-fix:
    //   1. whitespace strings passed through and were PERSISTED into
    //      the dispatch node's required_capabilities, so runtime
    //      dispatch would silently miss every workflow.
    //   2. set_workflow_capabilities already enforces the strict
    //      regex when WRITING capability tags to the workflows table;
    //      the dispatcher accepting looser strings to MATCH against
    //      that table guaranteed save-time matches at preview but
    //      runtime mismatches.
    //   3. cap of 256 chars was inconsistent with the producer's 50.
    //      Aligned for consistency.
    // MCP-1052: route through canonical `is_valid_capability_name`
    // (talos-workflow-creation-helpers/src/lib.rs) — pre-fix this site
    // re-compiled the same `^[a-z0-9-]{1,50}$` regex inline.
    // MCP-349 (2026-05-11): pre-fix `filter_map(|v| v.as_str())` silently
    // dropped non-string entries — `required_capabilities: ["http", 42,
    // "secrets"]` persisted as 2 caps, not 3. The dispatch node's routing
    // would then match against fewer capabilities than the operator
    // declared, silently broadening the dispatch fan-out. Same
    // MCP-285/313/335 family applied to a dispatch-routing surface.
    let raw_caps = match crate::utils::json_string_array_field_strict(
        args,
        "required_capabilities",
        &req_id,
    ) {
        Ok(Some(v)) => v,
        Ok(None) => return mcp_error(req_id, -32602, "Missing 'required_capabilities' parameter"),
        Err(resp) => return resp,
    };
    let required_capabilities: Vec<String> = raw_caps
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if required_capabilities.is_empty() {
        return mcp_error(
            req_id,
            -32602,
            "'required_capabilities' must contain at least one non-empty, non-whitespace capability",
        );
    }
    for cap in &required_capabilities {
        if !talos_workflow_creation_helpers::is_valid_capability_name(cap) {
            return mcp_error(
                req_id,
                -32602,
                &format!(
                    "Invalid capability '{}'. Must be lowercase alphanumeric + hyphens, 1-50 chars (matches set_workflow_capabilities format).",
                    talos_text_util::bounded_preview(cap, 64)
                ),
            );
        }
    }
    // MCP-234: timeout_secs same family as MCP-227 — pre-fix
    // as_u64-then-unwrap_or silently substituted 30 for negative,
    // fractional, or wrong-type. Use validate_range_u64.
    let timeout_secs =
        match crate::utils::validate_range_u64(args, "timeout_secs", 1, 300, 30, &req_id) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    // MCP-386 (2026-05-11): strict-parse so a typo'd or wrong-type
    // `fallback_workflow_id` doesn't silently drop the fallback. Pre-fix
    // `optional_uuid` returned None for both ABSENT and INVALID — the
    // operator's intended fallback got silently lost, the node was
    // created without it, and runtime dispatch failed when no
    // capability match was found (when the operator clearly wanted
    // the fallback to catch that case). Same MCP-309 family applied
    // to a dispatch-routing surface.
    let fallback_wf_id: Option<uuid::Uuid> =
        match crate::utils::parse_optional_uuid_strict(args, "fallback_workflow_id", &req_id) {
            Ok(v) => v,
            Err(resp) => return resp,
        };

    // Fallback ownership check — security gate. Without this, a user
    // could point capability_dispatch at another user's workflow UUID
    // and the engine would attempt to run it at dispatch time. The
    // helper handles parent-workflow auth; we add the fallback check
    // here.
    if let Some(fb) = fallback_wf_id {
        if !state.workflow_repo.workflow_exists(fb, user_id).await {
            return mcp_error(
                req_id,
                -32602,
                "fallback_workflow_id not found or access denied",
            );
        }
    }

    // Pre-flight capability resolution: warn (save-time) if no matching
    // workflow exists AND no fallback is set. Runtime dispatch will
    // fail until either a matching workflow is published or the node
    // is reconfigured. Warning, not error — the user may be authoring
    // the dispatcher before the providers intentionally.
    let preflight_matches = state
        .workflow_repo
        .find_workflows_for_capability_dispatch_preview(user_id, &required_capabilities, 1)
        .await
        .unwrap_or_default();
    let preflight_warning = if preflight_matches.is_empty() && fallback_wf_id.is_none() {
        Some(format!(
            "WARNING: no workflows currently match capabilities {:?} AND no fallback_workflow_id is set. \
             Runtime dispatch will fail hard until either (a) a workflow with these capability tags is \
             published, or (b) this node is reconfigured with a fallback_workflow_id. Run \
             preview_capability_dispatch to confirm.",
            required_capabilities
        ))
    } else {
        None
    };

    let data = serde_json::json!({
        "required_capabilities": required_capabilities,
        "timeout_secs": timeout_secs,
        "fallback_workflow_id": fallback_wf_id.map(|u| u.to_string()),
    });

    let connect_from = args
        .get("connect_from")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let connect_to = args
        .get("connect_to")
        .and_then(|v| v.as_str())
        .map(str::to_string);

    let added =
        match upsert_system_node(&req_id, args, state, &agent, "capability_dispatch", data).await {
            Ok(a) => a,
            Err(resp) => return resp,
        };

    let wiring = match (&connect_from, &connect_to) {
        (Some(f), Some(t)) => format!("\nWired: {} → dispatch-node → {}", f, t),
        (Some(f), None) => format!("\nWired: {} → dispatch-node", f),
        (None, Some(t)) => format!("\nWired: dispatch-node → {}", t),
        (None, None) => String::new(),
    };
    let warning_line = preflight_warning
        .map(|w| format!("\n\n{}", w))
        .unwrap_or_default();
    mcp_text(req_id, &format!(
        "Capability dispatch node '{}' added to workflow {}.\nRequired capabilities: {:?}\nTimeout: {}s\n\nAt runtime, the engine will find the best-matching workflow with ALL required capabilities and execute it as a sub-workflow.{}{}{}",
        added.node_id, added.workflow_id, required_capabilities, timeout_secs, wiring, warning_line, added.auto_publish_note
    ))
}

// ── add_dispatch_node ────────────────────────────────────────────────────────

async fn handle_add_dispatch_node(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    // MCP-200 (2026-05-08): reject whitespace-only dispatch_expression.
    // Pre-fix `expr.is_empty()` returned false for "                "
    // (16 spaces), and Rhai successfully compiled the empty AST, so
    // the node persisted. At fire time the expression evaluated to
    // unit (no return value), couldn't coerce to a workflow ID
    // string, and dispatch silently failed. Same configure-success-
    // but-fire-time-fail family as MCP-195/196/197.
    let dispatch_expression = match args.get("dispatch_expression").and_then(|v| v.as_str()) {
        Some(expr) if expr.trim().is_empty() => {
            return mcp_error(
                req_id,
                -32602,
                "Missing or empty 'dispatch_expression' parameter — must be a non-empty, non-whitespace Rhai expression that returns a workflow ID string",
            )
        }
        Some(expr) if expr.len() > 2000 => {
            return mcp_error(
                req_id,
                -32602,
                "dispatch_expression must be ≤2000 characters",
            )
        }
        Some(expr) => expr.to_string(),
        None => {
            return mcp_error(
                req_id,
                -32602,
                "Missing or empty 'dispatch_expression' parameter",
            )
        }
    };
    if let Err(msg) = validate_rhai_expression("dispatch_expression", &dispatch_expression) {
        return mcp_error(req_id, -32602, &msg);
    }
    // MCP-237 (2026-05-08): MCP-227 family — pre-fix as_u64-then-
    // unwrap_or silently substituted 30 for negative / fractional /
    // wrong-type. Switched to validate_range_u64 [1, 600] (per-node
    // timeout matches workflow-level test_workflow ceiling).
    let timeout_secs =
        match crate::utils::validate_range_u64(args, "timeout_secs", 1, 600, 30, &req_id) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    let data = serde_json::json!({
        "dispatch_expression": dispatch_expression,
        "timeout_secs": timeout_secs,
    });

    let added = match upsert_system_node(&req_id, args, state, &agent, "dispatch", data).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    mcp_text(req_id, &format!(
        "Dynamic dispatch node '{}' added to workflow {}.\nExpression: {}\nTimeout: {}s\n\nAt runtime, the expression is evaluated against the node's input to determine which workflow to invoke.{}",
        added.node_id, added.workflow_id, dispatch_expression, timeout_secs, added.auto_publish_note
    ))
}

// ── set_continue_on_error ───────────────────────────────────────────────────

async fn handle_set_continue_on_error(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let workflow_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let node_id = match crate::utils::require_node_id(args, "node_id", req_id.clone()) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let enabled = match args.get("enabled").and_then(|v| v.as_bool()) {
        Some(e) => e,
        None => {
            return mcp_error(
                req_id,
                -32602,
                "Missing or invalid 'enabled' parameter (must be boolean)",
            )
        }
    };

    let graph_json_str = match fetch_graph_json(state, workflow_id, user_id, &req_id).await {
        Ok(gj) => gj,
        Err(e) => return e,
    };

    let mut graph: serde_json::Value = match serde_json::from_str(&graph_json_str) {
        Ok(g) => g,
        Err(_) => return mcp_error(req_id, -32000, "Invalid graph JSON"),
    };

    // Find and update the node
    let mut found = false;
    if let Some(nodes) = graph.get_mut("nodes").and_then(|n| n.as_array_mut()) {
        for node in nodes.iter_mut() {
            if node.get("id").and_then(|v| v.as_str()) == Some(&node_id) {
                if node.get("data").is_none() {
                    if let Some(obj) = node.as_object_mut() {
                        obj.insert("data".to_string(), serde_json::json!({}));
                    }
                }
                if let Some(data) = node.get_mut("data") {
                    if let Some(obj) = data.as_object_mut() {
                        if enabled {
                            obj.insert("continue_on_error".to_string(), serde_json::json!(true));
                        } else {
                            obj.remove("continue_on_error");
                        }
                    }
                }
                found = true;
                break;
            }
        }
    }

    if !found {
        return mcp_error(
            req_id,
            -32000,
            &format!("Node '{}' not found in workflow graph", node_id),
        );
    }

    let updated_json = serde_json::to_string(&graph).unwrap_or_default();
    if let Err(e) = save_graph_json(state, workflow_id, user_id, &updated_json, &req_id).await {
        return e;
    }

    // Auto-publish if this workflow has an active published version so the
    // change takes effect (shared helper — see maybe_auto_publish). Was an
    // advisory-note-only path before.
    let note = maybe_auto_publish(
        state,
        workflow_id,
        user_id,
        "Auto-published after continue_on_error change",
    )
    .await
    .message_suffix();

    let action = if enabled { "enabled" } else { "disabled" };
    mcp_text(
        req_id,
        &format!(
            "continue_on_error {} for node '{}' in workflow {}.{}",
            action, node_id, workflow_id, note
        ),
    )
}

// ── add_error_handler ─────────────────────────────────────────────────────────

async fn handle_add_error_handler(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(Uuid::nil);

    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // MCP-241 (2026-05-08): trim handler_label. Pre-fix the optional
    // path accepted whitespace and persisted it as the error-handler
    // node's display label — UI / list_workflows would render a
    // blank-looking handler with no recoverable identifier. Empty-
    // after-trim falls through to the documented "Error Handler" default.
    let handler_label_owned: Option<String> =
        match args.get("handler_label").and_then(|v| v.as_str()) {
            Some(l) if l.len() > 200 => {
                return mcp_error(req_id, -32602, "handler_label must be ≤ 200 characters")
            }
            Some(l) => {
                let trimmed = l.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                }
            }
            None => None,
        };
    let handler_label: &str = handler_label_owned.as_deref().unwrap_or("Error Handler");

    // MCP-349 (2026-05-11): pre-fix `filter_map(|v| v.as_str()...)` on the
    // explicit-targets list silently dropped non-string entries —
    // `target_node_ids: ["llm_1", 42, "transform_2"]` narrowed the
    // error-handler attachment from 3 targets to 2. Operator's typed-
    // wrong entry vanished BEFORE downstream node-existence validation
    // could flag it. Same MCP-285/313/335 family.
    let explicit_targets: Option<Vec<String>> =
        match crate::utils::json_string_array_field_strict(args, "target_node_ids", &req_id) {
            Ok(v) => v,
            Err(resp) => return resp,
        };

    // Resolve handler module template ID — prefer handler_module_id (UUID), fall back to handler_module_name
    let (handler_template_id, handler_display): (Uuid, String) =
        if let Some(id_str) = args.get("handler_module_id").and_then(|v| v.as_str()) {
            match id_str.parse::<Uuid>() {
                Ok(id) => (id, id_str.to_string()),
                Err(_) => return mcp_error(req_id, -32602, "Invalid 'handler_module_id' UUID"),
            }
        } else if let Some(handler_module_name_raw) =
            args.get("handler_module_name").and_then(|v| v.as_str())
        {
            if handler_module_name_raw.len() > 200 {
                return mcp_error(
                    req_id,
                    -32602,
                    "handler_module_name must be ≤ 200 characters",
                );
            }
            // MCP-241 (2026-05-08): trim before lookup. Pre-fix
            // `handler_module_name: "   "` was sent verbatim to
            // find_template_id_by_name_ci which missed and returned the
            // misleading "Module '   ' not found" with the typo'd
            // suggestions list. Trim and reject empty-after-trim early.
            let handler_module_name = handler_module_name_raw.trim();
            if handler_module_name.is_empty() {
                return mcp_error(
                    req_id,
                    -32602,
                    "handler_module_name must be a non-empty, non-whitespace string",
                );
            }
            let handler_id = state
                .module_repo
                .find_template_id_by_name_ci(handler_module_name, user_id)
                .await
                .unwrap_or(None);

            match handler_id {
                Some(id) => (id, handler_module_name.to_string()),
                None => {
                    // 1. Full-name LIKE (substring match)
                    let mut suggestions = state
                        .module_repo
                        .suggest_template_names_like(handler_module_name, user_id, 5)
                        .await
                        .unwrap_or_default();

                    // 2. Word-by-word LIKE — catches partial/typo matches like "Slack" from "slack msg"
                    if suggestions.is_empty() {
                        let words: Vec<&str> = handler_module_name
                            .split_whitespace()
                            .filter(|w| w.len() >= 3)
                            .collect();
                        for word in &words {
                            let word_hits = state
                                .module_repo
                                .suggest_template_names_like(word, user_id, 3)
                                .await
                                .unwrap_or_default();
                            for hit in word_hits {
                                if !suggestions.contains(&hit) {
                                    suggestions.push(hit);
                                }
                            }
                            if suggestions.len() >= 5 {
                                break;
                            }
                        }
                    }

                    // 3. Trigram similarity via pg_trgm (silently skipped if not enabled).
                    if suggestions.is_empty() {
                        suggestions = state
                            .module_repo
                            .suggest_template_names_trgm(handler_module_name, user_id, 5)
                            .await
                            .unwrap_or_default();
                    }

                    // 4. Final fallback: first 5 alphabetically so the agent always has something
                    if suggestions.is_empty() {
                        suggestions = state
                            .module_repo
                            .list_template_names_alphabetical(user_id, 5)
                            .await
                            .unwrap_or_default();
                    }

                    let hint = if suggestions.is_empty() {
                        "Call list_modules to see available modules.".to_string()
                    } else {
                        format!(
                            "Did you mean one of: {}? Call list_modules for all options.",
                            suggestions.join(", ")
                        )
                    };
                    return mcp_error(
                        req_id,
                        -32000,
                        &format!("Module '{}' not found. {}", handler_module_name, hint),
                    );
                }
            }
        } else {
            return mcp_error(
                req_id,
                -32602,
                "Either 'handler_module_id' or 'handler_module_name' is required",
            );
        };

    // Load workflow graph
    let graph_json_str = match fetch_graph_json(state, wf_id, user_id, &req_id).await {
        Ok(gj) => gj,
        Err(e) => return e,
    };

    let mut graph: serde_json::Value =
        serde_json::from_str(&graph_json_str).unwrap_or(json!({"nodes":[],"edges":[]}));

    // Collect IDs of nodes that already have an outgoing error edge
    let already_wired: std::collections::HashSet<String> = graph
        .get("edges")
        .and_then(|e| e.as_array())
        .map(|edges| {
            edges
                .iter()
                .filter(|e| {
                    e.get("edge_type")
                        .and_then(|t| t.as_str())
                        .map(|t| t == "error")
                        .unwrap_or(false)
                })
                .filter_map(|e| e.get("source").and_then(|s| s.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default();

    // Determine which nodes to wire
    let nodes_to_wire: Vec<String> = match explicit_targets {
        Some(ids) => ids,
        None => graph
            .get("nodes")
            .and_then(|n| n.as_array())
            .map(|nodes| {
                nodes
                    .iter()
                    .filter_map(|n| n.get("id").and_then(|v| v.as_str()))
                    .filter(|id| !already_wired.contains(*id))
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default(),
    };

    if nodes_to_wire.is_empty() {
        return mcp_text(
            req_id,
            &serde_json::to_string_pretty(&json!({
                "workflow_id": wf_id.to_string(),
                "message": "All nodes already have outgoing error edges — no changes made.",
                "already_wired": already_wired.len(),
            }))
            .unwrap_or_default(),
        );
    }

    // Compute handler node position: right of the rightmost existing node
    let max_x = graph
        .get("nodes")
        .and_then(|n| n.as_array())
        .map(|nodes| {
            nodes
                .iter()
                .filter_map(|n| {
                    n.get("position")
                        .and_then(|p| p.get("x"))
                        .and_then(|x| x.as_f64())
                })
                .fold(0.0_f64, f64::max)
        })
        .unwrap_or(0.0);

    let handler_node_id = format!("error-handler-{}", Uuid::new_v4().simple());

    // Add handler node
    let handler_node = json!({
        "id": handler_node_id,
        "type": handler_template_id.to_string(),
        "position": { "x": max_x + 350.0, "y": 100.0 },
        "data": { "label": handler_label },
    });
    if let Some(nodes) = graph.get_mut("nodes").and_then(|n| n.as_array_mut()) {
        nodes.push(handler_node);
    }

    // Add error edges from each target node to the handler
    for node_id in &nodes_to_wire {
        if let Some(edges) = graph.get_mut("edges").and_then(|e| e.as_array_mut()) {
            edges.push(json!({
                "source": node_id,
                "target": &handler_node_id,
                "edge_type": "error",
            }));
        }
    }

    let updated_json = graph.to_string();
    if let Err(e) = save_graph_json(state, wf_id, user_id, &updated_json, &req_id).await {
        return e;
    }

    let sync_note = maybe_auto_publish(
        state,
        wf_id,
        user_id,
        "Auto-published after adding error handler",
    )
    .await
    .message_suffix();

    let skipped_nodes: Vec<String> = already_wired.into_iter().collect();
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&json!({
            "workflow_id": wf_id.to_string(),
            "handler_node_id": handler_node_id,
            "handler_module": handler_display,
            "wired_nodes": nodes_to_wire,
            "skipped_nodes": skipped_nodes,
            "error_edges_added": nodes_to_wire.len(),
            "auto_publish_note": sync_note.trim(),
            "next_steps": [
                format!(
                    "Configure the handler: update_node_config workflow_id={} node_id={}",
                    wf_id, handler_node_id
                ),
                "Run get_workflow_quickstart to verify handler config requirements",
                "Test the error path: trigger a failing node to confirm the handler is invoked",
            ],
        }))
        .unwrap_or_default(),
    )
}

async fn handle_fix_fan_in(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(Uuid::nil);

    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let convergence_node_id = match crate::utils::require_node_id(args, "node_id", req_id.clone()) {
        Ok(s) => s,
        Err(resp) => return resp,
    };

    // Load graph
    let graph_json_str = match fetch_graph_json(state, wf_id, user_id, &req_id).await {
        Ok(gj) => gj,
        Err(e) => return e,
    };

    let mut graph: serde_json::Value =
        serde_json::from_str(&graph_json_str).unwrap_or(json!({"nodes":[],"edges":[]}));

    // Find all incoming edges to the convergence node
    let incoming_edges: Vec<serde_json::Value> = graph
        .get("edges")
        .and_then(|e| e.as_array())
        .map(|edges| {
            edges
                .iter()
                .filter(|e| {
                    e.get("target")
                        .and_then(|t| t.as_str())
                        .map(|t| t == convergence_node_id)
                        .unwrap_or(false)
                })
                .cloned()
                .collect()
        })
        .unwrap_or_default();

    if incoming_edges.len() < 2 {
        return mcp_text(
            req_id,
            &serde_json::to_string_pretty(&json!({
                "workflow_id": wf_id.to_string(),
                "node_id": convergence_node_id,
                "message": "No fan-in detected on this node — fewer than 2 incoming edges.",
                "incoming_edge_count": incoming_edges.len(),
            }))
            .unwrap_or_default(),
        );
    }

    // system:collect is a built-in engine node — no catalog lookup needed.
    // The engine recognises any node whose type starts with "system:" and dispatches
    // it as a system node (parallel.rs line ~954).

    // Calculate collect node position: average of source node positions
    let source_ids: Vec<String> = incoming_edges
        .iter()
        .filter_map(|e| crate::utils::json_optional_string(e, "source"))
        .collect();

    let (avg_x, avg_y) = {
        let nodes = graph
            .get("nodes")
            .and_then(|n| n.as_array())
            .cloned()
            .unwrap_or_default();

        let positions: Vec<(f64, f64)> = nodes
            .iter()
            .filter(|n| {
                n.get("id")
                    .and_then(|v| v.as_str())
                    .map(|id| source_ids.contains(&id.to_string()))
                    .unwrap_or(false)
            })
            .filter_map(|n| {
                let x = n
                    .get("position")
                    .and_then(|p| p.get("x"))
                    .and_then(|v| v.as_f64());
                let y = n
                    .get("position")
                    .and_then(|p| p.get("y"))
                    .and_then(|v| v.as_f64());
                x.zip(y)
            })
            .collect();

        if positions.is_empty() {
            (250.0, 300.0)
        } else {
            let sum_x: f64 = positions.iter().map(|(x, _)| x).sum();
            let sum_y: f64 = positions.iter().map(|(_, y)| y).sum();
            let count = positions.len() as f64;
            (sum_x / count + 250.0, sum_y / count)
        }
    };

    // Build collect node id
    let collect_node_id = format!("collect-{}", Uuid::new_v4().simple());

    // Add collect node — type "system:collect" + kind "collect" ensure the engine
    // recognises it as a built-in primitive and skips module lookup.
    let collect_node = json!({
        "id": collect_node_id,
        "type": "system:collect",
        "kind": "collect",
        "position": { "x": avg_x, "y": avg_y },
        "data": { "label": "Collect" },
    });

    if let Some(nodes) = graph.get_mut("nodes").and_then(|n| n.as_array_mut()) {
        nodes.push(collect_node);
    }

    // Rewire edges: redirect incoming edges to point to collect node
    let edges_rewired = incoming_edges.len();
    if let Some(edges) = graph.get_mut("edges").and_then(|e| e.as_array_mut()) {
        for edge in edges.iter_mut() {
            let target = edge
                .get("target")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if target == convergence_node_id {
                edge["target"] = serde_json::json!(collect_node_id);
            }
        }
        // Add edge from collect node to convergence node
        edges.push(json!({
            "source": collect_node_id,
            "target": convergence_node_id,
        }));
    }

    // Persist
    let updated_json = graph.to_string();
    if let Err(e) = save_graph_json(state, wf_id, user_id, &updated_json, &req_id).await {
        return e;
    }

    let diff = compute_mcp_graph_diff(&graph_json_str, &updated_json);

    let sync_note = maybe_auto_publish(state, wf_id, user_id, "Auto-published after fan-in fix")
        .await
        .message_suffix();

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&json!({
            "workflow_id": wf_id.to_string(),
            "collect_node_id": collect_node_id,
            "edges_rewired": edges_rewired,
            "convergence_node": convergence_node_id,
            "diff": diff,
            "auto_publish_note": sync_note.trim(),
            "next_steps": [
                format!("Run get_workflow_quickstart workflow_id={} to verify structural_warnings are resolved", wf_id),
                "Test the workflow with trigger_workflow to confirm fan-in outputs are collected correctly",
                format!("Configure the Collect node if needed: update_node_config workflow_id={} node_id={}", wf_id, collect_node_id),
            ]
        }))
        .unwrap_or_default(),
    )
}

// ── preview_capability_dispatch ───────────────────────────────────────────────

async fn handle_preview_capability_dispatch(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);

    // MCP-233 (2026-05-08): trim each capability and reject whitespace-
    // only entries. Pre-fix `required_capabilities: ["   "]` was passed
    // verbatim to SQL — never matched anything because no workflow
    // capability is whitespace, surfaced as "match_count: 0" with the
    // misleading echo `required_capabilities: ["   "]` in the response.
    // Same MCP-210 / MCP-218 family extended to array fields.
    // MCP-349 (2026-05-11): pre-fix `filter_map(|v| v.as_str())` silently
    // dropped non-string entries on the preview-mode handler too.
    // `preview_capability_dispatch` echoes the resolved caps back to the
    // operator, so the operator visually sees the narrowed list — but
    // they can also miss it when scanning long results. Better to reject
    // loudly at the input boundary. Same MCP-285/313/335 family.
    let required_caps: Vec<String> = match crate::utils::json_string_array_field_strict(
        args,
        "required_capabilities",
        &req_id,
    ) {
        Ok(Some(arr)) if !arr.is_empty() => {
            let cleaned: Vec<String> = arr
                .into_iter()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if cleaned.is_empty() {
                return mcp_error(
                        req_id,
                        -32602,
                        "required_capabilities must contain at least one non-empty, non-whitespace string",
                    );
            }
            cleaned
        }
        Err(resp) => return resp,
        _ => {
            return mcp_error(
                req_id,
                -32602,
                "Missing or empty 'required_capabilities' array",
            )
        }
    };

    // Match the engine's exact SQL (parallel.rs:2715-2718 and 4519-4522):
    // No status filter — the runtime dispatches to any workflow regardless of status.
    // Ordered by updated_at DESC — most recently updated workflow wins.
    let rows = state
        .workflow_repo
        .find_workflows_for_capability_dispatch_preview(user_id, &required_caps, 10)
        .await
        .unwrap_or_default();

    let matches: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "workflow_id": r.id.to_string(),
                "name": r.name,
                "status": r.status,
                "capabilities": r.capabilities,
                "readiness_score": r.readiness_score.unwrap_or(0),
                "updated_at": r.updated_at.map(|t| t.to_rfc3339()),
            })
        })
        .collect();

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            "required_capabilities": required_caps,
            "match_count": matches.len(),
            "matches": matches,
            "dispatch_note": "At runtime, the engine selects the most recently updated (updated_at DESC) matching workflow regardless of status. The first entry in 'matches' is what will be selected. If match_count is 0, dispatch fails hard unless fallback_workflow_id is set on the node.",
        }))
        .unwrap_or_default(),
    )
}

// ── add_verify_node ──────────────────────────────────────────────────────────

async fn handle_add_verify_node(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    // MCP-235 (2026-05-08): trim verify-node condition. MCP-208 family.
    let condition = match args.get("condition").and_then(|v| v.as_str()) {
        Some(c) if c.trim().is_empty() => {
            return mcp_error(
                req_id,
                -32602,
                "condition must not be empty or whitespace-only",
            )
        }
        Some(c) if c.len() > 2000 => {
            return mcp_error(req_id, -32602, "condition must be 2000 characters or fewer")
        }
        Some(c) => c.trim().to_string(),
        None => return mcp_error(req_id, -32602, "Missing required field: condition"),
    };
    // Validate Rhai syntax at creation time — fail fast rather than at execution time.
    // eval() is disabled to match the runtime engine's security policy (rhai_helpers.rs).
    if let Err(msg) = validate_rhai_expression("condition", &condition) {
        return mcp_error(req_id, -32602, &msg);
    }
    // MCP-253 (2026-05-10): trim before empty filter so a whitespace-only
    // `check_label: "   "` falls through to None instead of persisting as
    // a label that renders blank in the UI. Same family as MCP-249.
    let check_label = match args
        .get("check_label")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(l) if l.len() > 200 => {
            return mcp_error(
                req_id,
                -32602,
                "check_label must be 200 characters or fewer",
            )
        }
        other => other.map(str::to_string),
    };
    // MCP-348 (2026-05-11): pre-fix `.and_then(as_str).filter(allowed).unwrap_or("error")`
    // collapsed BOTH wrong-type AND invalid-string (typo) into "error".
    // An operator passing `on_failure: "passthough"` (typo for
    // "passthrough") silently got "error" — verify failures halted the
    // workflow when the operator deliberately asked for permissive
    // passthrough semantics. Direction-class: operator opted IN to
    // continue-on-failure, server silently opted them OUT back to
    // halt-on-failure. Same MCP-346/347 family applied to a verify-
    // node policy surface; matches the already-fixed shape in
    // `add_confidence_gate_node` (graph.rs ~4466).
    let on_failure = match crate::utils::validate_optional_string(
        args,
        "on_failure",
        "error",
        Some(&["error", "passthrough"]),
        &req_id,
    ) {
        Ok(s) => s,
        Err(resp) => return resp,
    };
    let mut data = serde_json::json!({
        "condition": condition,
        "on_failure": on_failure,
    });
    if let Some(ref label) = check_label {
        data["check_label"] = serde_json::Value::String(label.clone());
    }

    let added = match upsert_system_node(&req_id, args, state, &agent, "verify", data).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    mcp_text(
        req_id,
        &format!(
            "Verify node '{}' added to workflow {}.\n\
         Condition: {}\n\
         On failure: {} | Check label: {}\n\
         When condition passes: output forwarded with __verified__: true\n\
         When condition fails ({}): {}{}{}",
            added.node_id,
            added.workflow_id,
            condition,
            on_failure,
            check_label.as_deref().unwrap_or("(none)"),
            on_failure,
            if on_failure == "error" {
                "workflow fails with verification error"
            } else {
                "output forwarded with __verification_failed__: true"
            },
            added.wiring_in,
            added.wiring_out
        ),
    )
}

// ── add_synthesize_node ──────────────────────────────────────────────────────

async fn handle_add_synthesize_node(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let synthesis_expr = match args
        .get("synthesis_expr")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        Some(expr) if expr.len() > 2000 => {
            return mcp_error(
                req_id,
                -32602,
                "synthesis_expr must be 2000 characters or fewer",
            )
        }
        Some(expr) => {
            if let Err(msg) = validate_rhai_expression("synthesis_expr", expr) {
                return mcp_error(req_id, -32602, &msg);
            }
            Some(expr.to_string())
        }
        None => None,
    };
    let mut data = serde_json::json!({});
    if let Some(ref expr) = synthesis_expr {
        data["synthesis_expr"] = serde_json::Value::String(expr.clone());
    }

    let added = match upsert_system_node(&req_id, args, state, &agent, "synthesize", data).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    let expr_note = synthesis_expr
        .as_deref()
        .map(|e| format!("\nSynthesis expression: {}", e))
        .unwrap_or_else(|| {
            "\nNo expression — behaves like collect (outputs {items, count})".to_string()
        });
    mcp_text(
        req_id,
        &format!(
            "Synthesize node '{}' added to workflow {}.{}{}{}",
            added.node_id, added.workflow_id, expr_note, added.wiring_in, added.wiring_out
        ),
    )
}

// ── add_agent_loop_node ──────────────────────────────────────────────────────

async fn handle_add_agent_loop_node(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let body_workflow_id = match args
        .get("body_workflow_id")
        .and_then(|v| v.as_str())
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
    {
        Some(id) => id,
        None => {
            return mcp_error(
                req_id,
                -32602,
                "Missing or invalid 'body_workflow_id' — provide the UUID of the body workflow",
            )
        }
    };
    // Body-workflow ownership gate — validated BEFORE the helper so
    // the user can't point AgentLoop at another user's workflow.
    if !state
        .workflow_repo
        .workflow_exists(body_workflow_id, user_id)
        .await
    {
        return mcp_error(
            req_id,
            -32602,
            "body_workflow_id not found or access denied",
        );
    }
    let max_iterations =
        match crate::utils::validate_range_u64(args, "max_iterations", 1, 50, 10, &req_id) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    // MCP-267 (2026-05-10): direction-class wrong-type rejection.
    // Default true; pre-fix `inject_history: "false"` string silently
    // re-enabled history injection when the operator wanted to disable.
    let inject_history =
        match crate::utils::validate_optional_bool(args, "inject_history", true, &req_id) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    // MCP-237 (2026-05-08): MCP-227 family — fix silent default.
    let timeout_secs =
        match crate::utils::validate_range_u64(args, "timeout_secs", 1, 600, 60, &req_id) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    let data = serde_json::json!({
        "body_workflow_id": body_workflow_id.to_string(),
        "max_iterations": max_iterations,
        "inject_history": inject_history,
        "timeout_secs": timeout_secs,
    });

    let added = match upsert_system_node(&req_id, args, state, &agent, "agent_loop", data).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    mcp_text(
        req_id,
        &format!(
            "AgentLoop node '{}' added to workflow {}.\n\
             Body workflow: {}\n\
             Max iterations: {}, inject_history: {}, timeout: {}s\n\
             The body workflow runs on each iteration and receives __agent_iteration__ and __agent_history__.\n\
             Terminate the loop by returning {{\"finished\": true}} or {{\"action\": \"FINISH\"}} from any node in the body.{}{}",
            added.node_id, added.workflow_id, body_workflow_id,
            max_iterations, inject_history, timeout_secs,
            added.wiring_in, added.wiring_out
        ),
    )
}

// ── add_react_loop_node ──────────────────────────────────────────────────────

async fn handle_add_react_loop_node(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let body_workflow_id = match args
        .get("body_workflow_id")
        .and_then(|v| v.as_str())
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
    {
        Some(id) => id,
        None => {
            return mcp_error(
                req_id,
                -32602,
                "Missing or invalid 'body_workflow_id' — provide the UUID of the body workflow",
            )
        }
    };
    // Body-workflow ownership gate — validated BEFORE calling the
    // shared helper (which validates the parent workflow). Without
    // this, the user could point ReActLoop at another user's body.
    if !state
        .workflow_repo
        .workflow_exists(body_workflow_id, user_id)
        .await
    {
        return mcp_error(
            req_id,
            -32602,
            "body_workflow_id not found or access denied",
        );
    }
    let max_iterations =
        match crate::utils::validate_range_u64(args, "max_iterations", 1, 50, 10, &req_id) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    // MCP-267 (2026-05-10): direction-class wrong-type rejection.
    // Default true; pre-fix `inject_history: "false"` string silently
    // re-enabled history injection when the operator wanted to disable.
    let inject_history =
        match crate::utils::validate_optional_bool(args, "inject_history", true, &req_id) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    // MCP-237 (2026-05-08): MCP-227 family — fix silent default.
    let timeout_secs =
        match crate::utils::validate_range_u64(args, "timeout_secs", 1, 600, 60, &req_id) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    let data = serde_json::json!({
        "body_workflow_id": body_workflow_id.to_string(),
        "max_iterations": max_iterations,
        "inject_history": inject_history,
        "timeout_secs": timeout_secs,
    });

    let added = match upsert_system_node(&req_id, args, state, &agent, "react_loop", data).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    mcp_text(
        req_id,
        &format!(
            "ReActLoop node '{}' added to workflow {}.\n\
             Body workflow: {}\n\
             Max iterations: {}, inject_history: {}, timeout: {}s\n\
             Terminate the loop by returning {{\"finished\": true}} or {{\"action\": \"FINISH\"}} from any node in the body.{}{}",
            added.node_id, added.workflow_id, body_workflow_id,
            max_iterations, inject_history, timeout_secs,
            added.wiring_in, added.wiring_out
        ),
    )
}

// ── add_wait_node ────────────────────────────────────────────────────────────

async fn handle_add_wait_node(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    // MCP-201 (2026-05-08): treat whitespace-only message the same as
    // an empty/absent one (None — surfaces as "no message" in the UI).
    // Pre-fix a 16-space message persisted verbatim and surfaced as
    // visually-empty text on operator dashboards reviewing pending
    // waits. Same family as MCP-186.
    let message = match args.get("message").and_then(|v| v.as_str()) {
        Some(m) if m.len() > 500 => {
            return mcp_error(req_id, -32602, "message must be 500 characters or fewer")
        }
        Some(m) if m.trim().is_empty() => None,
        Some(m) => Some(m.to_string()),
        None => None,
    };
    let data = if let Some(ref m) = message {
        serde_json::json!({ "message": m })
    } else {
        serde_json::json!({})
    };

    let added = match upsert_system_node(&req_id, args, state, &agent, "wait", data).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    let msg_line = message
        .as_ref()
        .map(|m| format!("\nMessage: {}", m))
        .unwrap_or_default();
    mcp_text(
        req_id,
        &format!(
            "Wait node '{}' added to workflow {}.{}\n\
             At runtime the node pauses execution with a `__waiting__: true` envelope. \
             Resume via resume_workflow_by_correlation_id or the equivalent external signal.{}{}",
            added.node_id, added.workflow_id, msg_line, added.wiring_in, added.wiring_out
        ),
    )
}

// ── add_judge_node ────────────────────────────────────────────────────────────

async fn handle_add_judge_node(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let judge_workflow_id =
        match args
            .get("judge_workflow_id")
            .and_then(|v| v.as_str())
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
        {
            Some(id) => id,
            None => return mcp_error(
                req_id,
                -32602,
                "Missing or invalid 'judge_workflow_id' — provide the UUID of the judge workflow",
            ),
        };
    // Judge-workflow ownership gate — validated BEFORE the helper so
    // a user can't point Judge at another user's workflow.
    if !state
        .workflow_repo
        .workflow_exists(judge_workflow_id, user_id)
        .await
    {
        return mcp_error(
            req_id,
            -32000,
            "judge_workflow_id not found or access denied",
        );
    }
    // MCP-235 (2026-05-08): trim judge rubric. Whitespace rubric was
    // persisted and forwarded to the judge LLM workflow as the natural-
    // language criteria — guaranteed nonsense judgments at runtime.
    let rubric = match args.get("rubric").and_then(|v| v.as_str()) {
        Some(r) if r.trim().is_empty() => {
            return mcp_error(
                req_id,
                -32602,
                "rubric must not be empty or whitespace-only",
            )
        }
        Some(r) if r.len() > 2000 => {
            return mcp_error(req_id, -32602, "rubric must be 2000 characters or fewer")
        }
        Some(r) => r.trim().to_string(),
        None => return mcp_error(req_id, -32602, "Missing required field: rubric"),
    };
    let pass_threshold = match args.get("pass_threshold") {
        Some(v) => match v.as_f64() {
            Some(f) if !(0.0..=1.0).contains(&f) => {
                return mcp_error(req_id, -32602, "pass_threshold must be between 0.0 and 1.0")
            }
            Some(f) => Some(f),
            None => {
                return mcp_error(
                    req_id,
                    -32602,
                    "pass_threshold must be a number between 0.0 and 1.0",
                )
            }
        },
        None => None,
    };
    // MCP-334 (2026-05-11): pre-fix `args.get("on_failure").and_then(
    // |v| v.as_str())` collapsed wrong-type into None, and the
    // `Some("error") | None` arm then matched None silently — so a
    // caller passing `on_failure: 42` (number, intending the
    // passthrough mode but mistyping) got the "error" failure mode
    // silently. Direction-class: operator intended passthrough,
    // system applied the stricter "error" behavior with no signal.
    // Same MCP-189 / MCP-318 wrong-type-silent-default family.
    // Distinguish absent / null (legitimate default) from wrong-type
    // / unknown-string (loud reject). Fixed at both add_judge_node
    // and add_inline_judge_node call sites.
    let on_failure = match args.get("on_failure") {
        None | Some(serde_json::Value::Null) => "error".to_string(),
        Some(v) => match v.as_str() {
            Some("error") => "error".to_string(),
            Some("passthrough") => "passthrough".to_string(),
            Some(other) => {
                return mcp_error(
                    req_id,
                    -32602,
                    &format!(
                        "on_failure must be 'error' or 'passthrough', got '{}'",
                        talos_text_util::bounded_preview(other, 64)
                    ),
                )
            }
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("on_failure must be a string, got {kind}"),
                );
            }
        },
    };
    // MCP-237 (2026-05-08): MCP-227 family — fix silent default.
    let timeout_secs =
        match crate::utils::validate_range_u64(args, "timeout_secs", 1, 600, 60, &req_id) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    let mut data = serde_json::json!({
        "judge_workflow_id": judge_workflow_id.to_string(),
        "rubric": rubric,
        "on_failure": on_failure,
        "timeout_secs": timeout_secs,
    });
    if let Some(threshold) = pass_threshold {
        data["pass_threshold"] = serde_json::Value::from(threshold);
    }

    let added = match upsert_system_node(&req_id, args, state, &agent, "judge", data).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    let threshold_str = pass_threshold
        .map(|t| format!("\nPass threshold: {}", t))
        .unwrap_or_else(|| "\nPass threshold: (judge's 'passed' field only)".to_string());
    mcp_text(
        req_id,
        &format!(
            "Judge node '{}' added to workflow {}.\n\
             Judge workflow: {}\n\
             Rubric: {}{}\n\
             Timeout: {}s\n\
             Parent output is forwarded enriched with __judge_score__, __judge_passed__, __judge_reasoning__, and __judge_feedback__.{}{}",
            added.node_id, added.workflow_id, judge_workflow_id,
            rubric, threshold_str, timeout_secs,
            added.wiring_in, added.wiring_out
        ),
    )
}

// ── add_inline_judge_node ─────────────────────────────────────────────────────

async fn handle_add_inline_judge_node(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    // MCP-235 (2026-05-08): trim verdict_expr. MCP-208 family.
    let verdict_expr = match args.get("verdict_expr").and_then(|v| v.as_str()) {
        Some(e) if e.trim().is_empty() => {
            return mcp_error(
                req_id,
                -32602,
                "verdict_expr must not be empty or whitespace-only",
            )
        }
        Some(e) if e.len() > 2000 => {
            return mcp_error(
                req_id,
                -32602,
                "verdict_expr must be 2000 characters or fewer",
            )
        }
        Some(e) => e.trim().to_string(),
        None => return mcp_error(req_id, -32602, "Missing required field: verdict_expr"),
    };
    if let Err(msg) = validate_rhai_expression("verdict_expr", &verdict_expr) {
        return mcp_error(req_id, -32602, &msg);
    }
    let pass_threshold = match args.get("pass_threshold") {
        Some(v) if v.is_null() => None,
        Some(v) => match v.as_f64() {
            Some(f) if !(0.0..=1.0).contains(&f) => {
                return mcp_error(req_id, -32602, "pass_threshold must be between 0.0 and 1.0")
            }
            Some(f) => Some(f),
            None => {
                return mcp_error(
                    req_id,
                    -32602,
                    "pass_threshold must be a number between 0.0 and 1.0",
                )
            }
        },
        None => None,
    };
    // MCP-334 (2026-05-11): pre-fix `args.get("on_failure").and_then(
    // |v| v.as_str())` collapsed wrong-type into None, and the
    // `Some("error") | None` arm then matched None silently — so a
    // caller passing `on_failure: 42` (number, intending the
    // passthrough mode but mistyping) got the "error" failure mode
    // silently. Direction-class: operator intended passthrough,
    // system applied the stricter "error" behavior with no signal.
    // Same MCP-189 / MCP-318 wrong-type-silent-default family.
    // Distinguish absent / null (legitimate default) from wrong-type
    // / unknown-string (loud reject). Fixed at both add_judge_node
    // and add_inline_judge_node call sites.
    let on_failure = match args.get("on_failure") {
        None | Some(serde_json::Value::Null) => "error".to_string(),
        Some(v) => match v.as_str() {
            Some("error") => "error".to_string(),
            Some("passthrough") => "passthrough".to_string(),
            Some(other) => {
                return mcp_error(
                    req_id,
                    -32602,
                    &format!(
                        "on_failure must be 'error' or 'passthrough', got '{}'",
                        talos_text_util::bounded_preview(other, 64)
                    ),
                )
            }
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("on_failure must be a string, got {kind}"),
                );
            }
        },
    };
    let mut data = serde_json::json!({
        "verdict_expr": verdict_expr,
        "on_failure": on_failure,
    });
    if let Some(threshold) = pass_threshold {
        data["pass_threshold"] = serde_json::Value::from(threshold);
    }

    let added = match upsert_system_node(&req_id, args, state, &agent, "inline_judge", data).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    let threshold_str = pass_threshold
        .map(|t| format!("\nPass threshold: {}", t))
        .unwrap_or_else(|| "\nPass threshold: (expression's 'passed' field only)".to_string());
    mcp_text(
        req_id,
        &format!(
            "Inline-judge node '{}' added to workflow {}.\n\
             Verdict expression: {}{}\n\
             Parent output is forwarded enriched with __judge_score__, __judge_passed__, __judge_reasoning__, and __judge_feedback__.{}{}",
            added.node_id, added.workflow_id, verdict_expr, threshold_str, added.wiring_in, added.wiring_out
        ),
    )
}

// ── add_ensemble_node ─────────────────────────────────────────────────────────

async fn handle_add_ensemble_node(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let child_workflow_id = match args
        .get("child_workflow_id")
        .and_then(|v| v.as_str())
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
    {
        Some(id) => id,
        None => return mcp_error(req_id, -32602, "Missing or invalid 'child_workflow_id' — provide the UUID of the workflow to run N times"),
    };
    // Child-workflow ownership gate — validated BEFORE the helper.
    if !state
        .workflow_repo
        .workflow_exists(child_workflow_id, user_id)
        .await
    {
        return mcp_error(
            req_id,
            -32000,
            "child_workflow_id not found or access denied",
        );
    }
    // MCP-238 (2026-05-08): pre-fix the inline match's `None` arm
    // caught both "absent" AND "wrong type" (negative / fractional /
    // string), silently defaulting to 3. Caller passing `count: -5`
    // expecting an error got an ensemble node persisted with count: 3
    // and no signal that their input was malformed. validate_range_u64
    // distinguishes absent (default) from wrong-type (explicit -32602).
    let count = match crate::utils::validate_range_u64(args, "count", 2, 10, 3, &req_id) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let consensus = match args.get("consensus").and_then(|v| v.as_str()) {
        Some(c) if c == "majority_vote" || c == "best_of_n" || c == "first_pass" => c.to_string(),
        Some(other) => {
            return mcp_error(
                req_id,
                -32602,
                &format!(
                    "consensus must be one of: majority_vote, best_of_n, first_pass — got '{}'",
                    talos_text_util::bounded_preview(other, 64)
                ),
            )
        }
        None => "majority_vote".to_string(),
    };
    let judge_workflow_id = if consensus == "best_of_n" {
        match args
            .get("judge_workflow_id")
            .and_then(|v| v.as_str())
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
        {
            Some(id) => {
                if !state.workflow_repo.workflow_exists(id, user_id).await {
                    return mcp_error(
                        req_id,
                        -32000,
                        "judge_workflow_id not found or access denied",
                    );
                }
                Some(id)
            }
            None => {
                return mcp_error(
                    req_id,
                    -32602,
                    "judge_workflow_id is required when consensus is 'best_of_n'",
                )
            }
        }
    } else {
        None
    };
    // MCP-237 (2026-05-08): MCP-227 family — fix silent default.
    let timeout_secs =
        match crate::utils::validate_range_u64(args, "timeout_secs", 1, 600, 60, &req_id) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    let mut data = serde_json::json!({
        "child_workflow_id": child_workflow_id.to_string(),
        "count": count,
        "consensus": consensus,
        "timeout_secs": timeout_secs,
    });
    data["judge_workflow_id"] = match judge_workflow_id {
        Some(id) => serde_json::Value::String(id.to_string()),
        None => serde_json::Value::Null,
    };

    let added = match upsert_system_node(&req_id, args, state, &agent, "ensemble", data).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    mcp_text(req_id, &format!(
        "Ensemble node '{}' added to workflow {}.\n\
         Child workflow: {} (runs {} times)\n\
         Consensus: {}\n\
         Timeout: {}s per execution\n\
         Output includes __ensemble_method__, __ensemble_size__, and __ensemble_votes__ metadata.{}{}",
        added.node_id, added.workflow_id, child_workflow_id, count,
        consensus, timeout_secs,
        added.wiring_in, added.wiring_out
    ))
}

// ── add_confidence_gate_node ──────────────────────────────────────────────────

async fn handle_add_confidence_gate_node(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let threshold = match args.get("threshold") {
        Some(v) => match v.as_f64() {
            Some(f) if !(0.0..=1.0).contains(&f) => {
                return mcp_error(req_id, -32602, "threshold must be between 0.0 and 1.0")
            }
            Some(f) => f,
            None => {
                return mcp_error(
                    req_id,
                    -32602,
                    "threshold must be a number between 0.0 and 1.0",
                )
            }
        },
        None => 0.7,
    };
    // MCP-240 (2026-05-08): trim confidence_path. Pre-fix `"   "` was
    // accepted (filter is `!s.is_empty()` which whitespace passes) and
    // got persisted on the gate node as the JSON path. Runtime
    // would look up `data["   "]` (no such key), fail closed via the
    // pause/error/passthrough fallback, and the resulting error message
    // would point at the wrong thing. Trim and treat empty-after-trim
    // as "use the default" (matches the documented optional contract).
    let confidence_path = args
        .get("confidence_path")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("__confidence__")
        .to_string();
    let on_low_confidence = match args.get("on_low_confidence").and_then(|v| v.as_str()) {
        Some(v) if v == "pause" || v == "error" || v == "passthrough" => v.to_string(),
        Some(other) => {
            return mcp_error(
                req_id,
                -32602,
                &format!(
                    "on_low_confidence must be one of: pause, error, passthrough — got '{}'",
                    talos_text_util::bounded_preview(other, 64)
                ),
            )
        }
        None => "pause".to_string(),
    };
    let data = serde_json::json!({
        "threshold": threshold,
        "confidence_path": confidence_path,
        "on_low_confidence": on_low_confidence,
    });

    let added =
        match upsert_system_node(&req_id, args, state, &agent, "confidence_gate", data).await {
            Ok(a) => a,
            Err(resp) => return resp,
        };

    mcp_text(req_id, &format!(
        "Confidence gate node '{}' added to workflow {}.\n\
         Threshold: {} | Confidence path: {} | On low confidence: {}\n\
         Tip: ensure the upstream LLM node explicitly includes a {} field (0.0–1.0) in its output.{}{}",
        added.node_id, added.workflow_id,
        threshold, confidence_path, on_low_confidence, confidence_path,
        added.wiring_in, added.wiring_out
    ))
}

// ── add_reflective_retry_node ─────────────────────────────────────────────────

async fn handle_add_reflective_retry_node(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let child_workflow_id = match args
        .get("child_workflow_id")
        .and_then(|v| v.as_str())
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
    {
        Some(id) => id,
        None => {
            return mcp_error(
                req_id,
                -32602,
                "Missing or invalid 'child_workflow_id' — provide a valid workflow UUID",
            )
        }
    };
    let reflection_workflow_id = match args
        .get("reflection_workflow_id")
        .and_then(|v| v.as_str())
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
    {
        Some(id) => id,
        None => {
            return mcp_error(
                req_id,
                -32602,
                "Missing or invalid 'reflection_workflow_id' — provide a valid workflow UUID",
            )
        }
    };
    if !state
        .workflow_repo
        .workflow_exists(child_workflow_id, user_id)
        .await
    {
        return mcp_error(
            req_id,
            -32000,
            "child_workflow_id not found or access denied",
        );
    }
    if !state
        .workflow_repo
        .workflow_exists(reflection_workflow_id, user_id)
        .await
    {
        return mcp_error(
            req_id,
            -32000,
            "reflection_workflow_id not found or access denied",
        );
    }
    // MCP-238 (2026-05-08): same inline-match shape as count above.
    // Negative / fractional / wrong-type silently became 2.
    let max_retries = match crate::utils::validate_range_u64(args, "max_retries", 1, 5, 2, &req_id)
    {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    // MCP-237 (2026-05-08): MCP-227 family — fix silent default.
    let timeout_secs =
        match crate::utils::validate_range_u64(args, "timeout_secs", 1, 600, 60, &req_id) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    let data = serde_json::json!({
        "child_workflow_id": child_workflow_id.to_string(),
        "reflection_workflow_id": reflection_workflow_id.to_string(),
        "max_retries": max_retries,
        "timeout_secs": timeout_secs,
    });

    let added =
        match upsert_system_node(&req_id, args, state, &agent, "reflective_retry", data).await {
            Ok(a) => a,
            Err(resp) => return resp,
        };

    mcp_text(req_id, &format!(
        "Reflective retry node '{}' added to workflow {}.\n\
         Child workflow: {}\n\
         Reflection workflow: {}\n\
         Max retries: {} | Timeout: {}s per attempt\n\
         On failure: reflection workflow receives {{input, error, attempt}} and returns corrective fields.\n\
         On success: output includes __reflective_retry_attempts__ metadata.{}{}",
        added.node_id, added.workflow_id,
        child_workflow_id, reflection_workflow_id,
        max_retries, timeout_secs,
        added.wiring_in, added.wiring_out
    ))
}

// ── add_llm_dispatch_node ─────────────────────────────────────────────────────

async fn handle_add_llm_dispatch_node(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    let classifier_workflow_id = match args
        .get("classifier_workflow_id")
        .and_then(|v| v.as_str())
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
    {
        Some(id) => id,
        None => {
            return mcp_error(
                req_id,
                -32602,
                "Missing or invalid 'classifier_workflow_id' — provide a valid workflow UUID",
            )
        }
    };
    if !state
        .workflow_repo
        .workflow_exists(classifier_workflow_id, user_id)
        .await
    {
        return mcp_error(
            req_id,
            -32000,
            "classifier_workflow_id not found or access denied",
        );
    }
    let routes = match args.get("routes").and_then(|v| v.as_object()) {
        Some(r) => r,
        None => return mcp_error(req_id, -32602, "Missing required field: routes (must be an object mapping class label to workflow UUID)"),
    };
    if routes.is_empty() {
        return mcp_error(req_id, -32602, "routes must contain at least one entry");
    }
    if routes.len() > 20 {
        return mcp_error(req_id, -32602, "routes must have at most 20 entries");
    }
    // Validate all route values are valid UUIDs owned by the requesting user.
    // Without ownership checks an attacker could reference other users' workflows,
    // leaking their existence and (at execution time) dispatching into them.
    let mut routes_map: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
    for (class_label, route_val) in routes {
        if class_label.len() > 100 {
            return mcp_error(
                req_id,
                -32602,
                &format!(
                    "class_label '{}...' exceeds 100 characters",
                    talos_text_util::truncate_at_char_boundary(class_label, 50)
                ),
            );
        }
        let route_uuid_str = match route_val.as_str() {
            Some(s) => s,
            None => {
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("Route value for '{}' must be a string UUID", class_label),
                )
            }
        };
        let route_uuid = match uuid::Uuid::parse_str(route_uuid_str) {
            Ok(id) => id,
            Err(_) => {
                return mcp_error(
                    req_id,
                    -32602,
                    &format!(
                        "Route value for '{}' is not a valid UUID: '{}'",
                        class_label, route_uuid_str
                    ),
                )
            }
        };
        if !state
            .workflow_repo
            .workflow_exists(route_uuid, user_id)
            .await
        {
            return mcp_error(
                req_id,
                -32000,
                &format!(
                    "Route workflow for class '{}' not found or access denied",
                    class_label
                ),
            );
        }
        routes_map.insert(
            class_label.clone(),
            serde_json::Value::String(route_uuid_str.to_string()),
        );
    }
    let fallback_workflow_id = match args.get("fallback_workflow_id") {
        Some(v) if v.is_null() => None,
        Some(v) => {
            let id = match v.as_str().and_then(|s| uuid::Uuid::parse_str(s).ok()) {
                Some(id) => id,
                None => {
                    return mcp_error(
                        req_id,
                        -32602,
                        "fallback_workflow_id must be a valid UUID if provided",
                    )
                }
            };
            if !state.workflow_repo.workflow_exists(id, user_id).await {
                return mcp_error(
                    req_id,
                    -32000,
                    "fallback_workflow_id not found or access denied",
                );
            }
            Some(id)
        }
        None => None,
    };
    // MCP-237 (2026-05-08): MCP-227 family — fix silent default.
    let timeout_secs =
        match crate::utils::validate_range_u64(args, "timeout_secs", 1, 600, 60, &req_id) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    let route_count = routes_map.len();
    let mut data = serde_json::json!({
        "classifier_workflow_id": classifier_workflow_id.to_string(),
        "routes": serde_json::Value::Object(routes_map),
        "timeout_secs": timeout_secs,
    });
    data["fallback_workflow_id"] = match fallback_workflow_id {
        Some(id) => serde_json::Value::String(id.to_string()),
        None => serde_json::Value::Null,
    };

    let added = match upsert_system_node(&req_id, args, state, &agent, "llm_dispatch", data).await {
        Ok(a) => a,
        Err(resp) => return resp,
    };

    mcp_text(req_id, &format!(
        "LLM dispatch node '{}' added to workflow {}.\n\
         Classifier workflow: {}\n\
         Routes: {} class labels configured\n\
         Fallback: {}\n\
         Timeout: {}s per sub-workflow\n\
         The classifier workflow receives the input and must return {{\"class\": \"<label>\"}} to select a route.{}{}",
        added.node_id, added.workflow_id,
        classifier_workflow_id,
        route_count,
        fallback_workflow_id.map_or_else(|| "(none — unmatched class causes error)".to_string(), |id| id.to_string()),
        timeout_secs,
        added.wiring_in, added.wiring_out
    ))
}

#[cfg(test)]
mod canonicalise_rhai_tests {
    use super::canonicalise_rhai_in_graph_json;

    #[test]
    fn decodes_retry_condition() {
        let raw = r#"{"nodes":[{"id":"n1","retry_condition":"a &amp;&amp; b"}],"edges":[]}"#;
        let canonical = canonicalise_rhai_in_graph_json(raw);
        assert!(canonical.contains(r#""retry_condition":"a && b""#));
    }

    #[test]
    fn passes_through_unchanged_when_no_entities() {
        let raw = r#"{"nodes":[{"id":"n1","retry_condition":"a && b"}],"edges":[]}"#;
        let canonical = canonicalise_rhai_in_graph_json(raw);
        // Cow::Borrowed → reference equality with input
        assert!(matches!(canonical, std::borrow::Cow::Borrowed(_)));
    }

    #[test]
    fn invalid_json_passes_through() {
        let raw = "not json";
        let canonical = canonicalise_rhai_in_graph_json(raw);
        assert_eq!(canonical.as_ref(), raw);
    }
}

/// RFC 7386 Appendix A test vectors, transcribed verbatim, plus a
/// nested-object case that goes one level deeper than any Appendix A
/// example. See https://www.rfc-editor.org/rfc/rfc7386 §Appendix A.
#[cfg(test)]
mod json_merge_patch_tests {
    use super::json_merge_patch;
    use serde_json::json;

    fn merged(target: serde_json::Value, patch: serde_json::Value) -> serde_json::Value {
        let mut target = target;
        json_merge_patch(&mut target, &patch);
        target
    }

    #[test]
    fn rfc7386_vector_01_replace_scalar() {
        assert_eq!(merged(json!({"a":"b"}), json!({"a":"c"})), json!({"a":"c"}));
    }

    #[test]
    fn rfc7386_vector_02_add_key() {
        assert_eq!(
            merged(json!({"a":"b"}), json!({"b":"c"})),
            json!({"a":"b","b":"c"})
        );
    }

    #[test]
    fn rfc7386_vector_03_delete_only_key() {
        assert_eq!(merged(json!({"a":"b"}), json!({"a": null})), json!({}));
    }

    #[test]
    fn rfc7386_vector_04_delete_one_of_two_keys() {
        assert_eq!(
            merged(json!({"a":"b","b":"c"}), json!({"a": null})),
            json!({"b":"c"})
        );
    }

    #[test]
    fn rfc7386_vector_05_array_replaced_by_scalar() {
        assert_eq!(
            merged(json!({"a":["b"]}), json!({"a":"c"})),
            json!({"a":"c"})
        );
    }

    #[test]
    fn rfc7386_vector_06_scalar_replaced_by_array() {
        assert_eq!(
            merged(json!({"a":"c"}), json!({"a":["b"]})),
            json!({"a":["b"]})
        );
    }

    #[test]
    fn rfc7386_vector_07_nested_object_merge_with_delete() {
        assert_eq!(
            merged(json!({"a": {"b":"c"}}), json!({"a": {"b":"d", "c": null}})),
            json!({"a": {"b":"d"}})
        );
    }

    #[test]
    fn rfc7386_vector_08_array_of_objects_replaced_wholesale() {
        assert_eq!(
            merged(json!({"a": [{"b":"c"}]}), json!({"a": [1]})),
            json!({"a": [1]})
        );
    }

    #[test]
    fn rfc7386_vector_09_top_level_array_replaced() {
        assert_eq!(
            merged(json!(["a", "b"]), json!(["c", "d"])),
            json!(["c", "d"])
        );
    }

    #[test]
    fn rfc7386_vector_10_object_replaced_by_array_patch() {
        assert_eq!(merged(json!({"a":"b"}), json!(["c"])), json!(["c"]));
    }

    #[test]
    fn rfc7386_vector_11_object_replaced_by_null_patch() {
        assert_eq!(merged(json!({"a":"foo"}), json!(null)), json!(null));
    }

    #[test]
    fn rfc7386_vector_12_object_replaced_by_string_patch() {
        assert_eq!(merged(json!({"a":"foo"}), json!("bar")), json!("bar"));
    }

    #[test]
    fn rfc7386_vector_13_null_value_preserved_when_not_targeted() {
        assert_eq!(
            merged(json!({"e": null}), json!({"a": 1})),
            json!({"e": null, "a": 1})
        );
    }

    #[test]
    fn rfc7386_vector_14_non_object_target_with_delete_of_absent_key() {
        assert_eq!(
            merged(json!([1, 2]), json!({"a":"b", "c": null})),
            json!({"a":"b"})
        );
    }

    #[test]
    fn rfc7386_vector_15_deeply_nested_delete_leaves_empty_object() {
        assert_eq!(
            merged(json!({}), json!({"a": {"bb": {"ccc": null}}})),
            json!({"a": {"bb": {}}})
        );
    }

    #[test]
    fn nested_merge_three_levels_preserves_untouched_siblings() {
        // Beyond the RFC vectors: three levels deep, with sibling keys at
        // every level that must survive the patch untouched — this is the
        // shape the update_node_config footgun fix actually needs (patch
        // one nested key, keep everything else).
        let target = json!({
            "AUTH": { "TO": "ops@example.com", "AUTH_HEADER": "Bearer xyz" },
            "DRY_RUN": true,
            "nested": { "keep": "me", "inner": { "a": 1, "b": 2 } }
        });
        let patch = json!({
            "DRY_RUN": false,
            "nested": { "inner": { "a": 99 } }
        });
        assert_eq!(
            merged(target, patch),
            json!({
                "AUTH": { "TO": "ops@example.com", "AUTH_HEADER": "Bearer xyz" },
                "DRY_RUN": false,
                "nested": { "keep": "me", "inner": { "a": 99, "b": 2 } }
            })
        );
    }

    #[test]
    fn null_deletes_nested_key_without_touching_siblings() {
        let target = json!({ "a": { "b": "c", "d": "e" } });
        let patch = json!({ "a": { "b": null } });
        assert_eq!(merged(target, patch), json!({ "a": { "d": "e" } }));
    }

    #[test]
    fn empty_patch_is_a_no_op() {
        let target = json!({"a": "b", "c": {"d": 1}});
        assert_eq!(merged(target.clone(), json!({})), target);
    }
}

#[cfg(test)]
mod dropped_top_level_keys_tests {
    use super::dropped_top_level_keys;
    use serde_json::json;

    #[test]
    fn reports_keys_missing_from_new_config() {
        let old = json!({"TO": "a@example.com", "AUTH_HEADER": "Bearer xyz", "DRY_RUN": true});
        let new = json!({"DRY_RUN": false});
        let mut dropped = dropped_top_level_keys(&old, &new);
        dropped.sort();
        assert_eq!(dropped, vec!["AUTH_HEADER".to_string(), "TO".to_string()]);
    }

    #[test]
    fn empty_when_nothing_dropped() {
        let old = json!({"DRY_RUN": true});
        let new = json!({"DRY_RUN": false, "TO": "a@example.com"});
        assert!(dropped_top_level_keys(&old, &new).is_empty());
    }

    #[test]
    fn empty_when_old_config_absent_or_not_object() {
        assert!(dropped_top_level_keys(&json!(null), &json!({})).is_empty());
        assert!(dropped_top_level_keys(&json!({}), &json!({})).is_empty());
    }

    #[test]
    fn all_dropped_when_new_config_is_empty() {
        let old = json!({"A": 1, "B": 2});
        let new = json!({});
        let mut dropped = dropped_top_level_keys(&old, &new);
        dropped.sort();
        assert_eq!(dropped, vec!["A".to_string(), "B".to_string()]);
    }
}

#[cfg(test)]
mod auto_publish_decision_tests {
    use super::{decide_publish_action, AutoPublishOutcome, PublishAction};

    // ── decide_publish_action: the publish-or-skip decision ──────────────

    #[test]
    fn published_workflow_triggers_publish() {
        // An active published version exists → publish a new one to sync.
        assert_eq!(decide_publish_action(Some(true)), PublishAction::Publish);
    }

    #[test]
    fn draft_only_workflow_skips_publish() {
        // Never published → stay a draft, nothing to sync.
        assert_eq!(decide_publish_action(Some(false)), PublishAction::Skip);
    }

    #[test]
    fn probe_error_does_not_publish() {
        // Couldn't determine status (DB hiccup) → warn + skip, never a
        // blind publish that could clobber a good published version.
        assert_eq!(decide_publish_action(None), PublishAction::ProbeFailed);
    }

    // ── AutoPublishOutcome: message suffix + published() flag ─────────────

    #[test]
    fn draft_only_outcome_is_silent_and_unpublished() {
        assert_eq!(AutoPublishOutcome::DraftOnly.message_suffix(), "");
        assert!(!AutoPublishOutcome::DraftOnly.published());
    }

    #[test]
    fn published_outcome_mirrors_merge_config_message() {
        // Byte-for-byte the wording update_node_config used pre-refactor,
        // so existing operator-facing text doesn't change.
        assert_eq!(
            AutoPublishOutcome::Published.message_suffix(),
            " Auto-published new version to keep published workflow in sync."
        );
        assert!(AutoPublishOutcome::Published.published());
    }

    #[test]
    fn publish_failed_outcome_warns_and_is_unpublished() {
        assert!(AutoPublishOutcome::PublishFailed
            .message_suffix()
            .contains("auto-publish failed"));
        assert!(!AutoPublishOutcome::PublishFailed.published());
    }

    #[test]
    fn probe_failed_outcome_warns_and_is_unpublished() {
        assert!(AutoPublishOutcome::ProbeFailed
            .message_suffix()
            .contains("couldn't verify published-version status"));
        assert!(!AutoPublishOutcome::ProbeFailed.published());
    }
}
