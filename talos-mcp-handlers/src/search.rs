//! MCP handlers for the search / embedding tools. The pipeline (config,
//! generator, batch generator, provider health probe, fallback chain)
//! lives in `talos-search-service`; this module is now thin protocol
//! glue: arg parsing, response shaping, and dispatch.
//!
//! Re-exports preserve the historical `crate::search::X` import paths
//! so the rest of `talos-mcp-handlers` (advanced.rs, actor.rs,
//! workflows.rs, versions.rs, utils.rs) and `controller/src/main.rs`
//! keep compiling without churn. The function bodies all live in
//! `talos-search-service` post-r305.

use super::types::JsonRpcResponse;
use super::utils::{mcp_error, mcp_text};
use super::{auth, McpState};
use std::sync::Arc;
use uuid::Uuid;

// Re-export the embedding pipeline + provider-health helpers from the
// service crate so existing `crate::search::*` callers keep resolving.
pub use talos_search_service::{
    auto_embed_workflow, embedding_provider_available, embedding_provider_status,
    generate_embedding, generate_embeddings_batch, refresh_embedding_provider_health,
    vec_to_pgvector_literal, workflow_embedding_text, EmbeddingConfig, EmbeddingError,
    EMBED_BATCH_MAX, PROVIDER_PROBE_INTERVAL,
};

// Local re-export of the SQL-input safety helper used by the
// keyword/trigram fallback handlers.
use talos_search_service::escape_like;

pub fn tool_schemas() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
            "name": "search_workflows",
            "description": "Search workflows by name (substring match, case-insensitive). Returns up to 20 matching workflows. Archived workflows are excluded by default.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": { "type": "string", "description": "Search query (minimum 2 characters)" },
                    "tag": { "type": "string", "description": "Optional: filter results to workflows with this tag" },
                    "include_archived": { "type": "boolean", "description": "If true, include archived workflows in results. Default: false." }
                },
                "required": ["query"]
            }
        }),
        serde_json::json!({
            "name": "tag_workflow",
            "description": "Add a tag to a workflow. Tags are unique per workflow (adding an existing tag is a no-op).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to tag" },
                    "tag": { "type": "string", "description": "Tag string to add" }
                },
                "required": ["workflow_id", "tag"]
            }
        }),
        serde_json::json!({
            "name": "untag_workflow",
            "description": "Remove a tag from a workflow.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to untag" },
                    "tag": { "type": "string", "description": "Tag string to remove" }
                },
                "required": ["workflow_id", "tag"]
            }
        }),
        serde_json::json!({
            "name": "add_workflow_tags",
            "description": "Add a tag to multiple workflows at once. Returns counts of tagged and already-tagged workflows. Note: tags are free-form human labels for organization and filtering. For machine-readable functional classification used by capability_dispatch routing, use set_workflow_capabilities instead.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_ids": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Array of workflow UUID strings to tag"
                    },
                    "tag": { "type": "string", "description": "Tag string to add to all specified workflows" }
                },
                "required": ["workflow_ids", "tag"]
            }
        }),
        serde_json::json!({
            "name": "find_similar_workflows",
            "description": "Find workflows that share the same modules as a given workflow. Returns up to 10 workflows sorted by overlap count, with shared module lists.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the source workflow" }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "search_workflows_semantic",
            "description": "Search workflows by natural language query. When an embedding provider is configured (EMBEDDING_API_URL / EMBEDDING_API_KEY, or Ollama via docker-compose default), automatically generates a query embedding and performs true vector similarity search (match_method: 'vector') against embedded workflows. Falls back to trigram/keyword matching when no provider is configured or no embeddings exist. Use generate_workflow_embeddings to index all workflows for full semantic coverage.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": { "type": "string", "description": "Natural language search query (e.g. 'detect when CI starts failing', 'watch repo for broken builds')" },
                    "limit": { "type": "number", "description": "Max results (default: 10)" },
                    "tag": { "type": "string", "description": "Optional tag filter to narrow results" },
                    "include_archived": { "type": "boolean", "description": "Include archived workflows in results (default: false — archived workflows are excluded)" },
                    "min_score": { "type": "number", "minimum": 0.0, "maximum": 1.0, "description": "Minimum cosine-similarity score [0.0–1.0] below which results are dropped. Default: 0.40 (calibrated for nomic-embed-text; override via SEMANTIC_SEARCH_MIN_SCORE env var if running a different embedding provider). Raise (e.g. 0.6) for tight matches only; lower to see best-effort results for unfamiliar queries — pass min_score=0.0 for exhaustive ranked-by-score output (caller filters themselves). The applied threshold is echoed in the response envelope as min_score_applied." }
                },
                "required": ["query"]
            }
        }),
        serde_json::json!({
            "name": "set_workflow_embedding",
            "description": "Store a pre-computed embedding vector for a workflow. Enables vector-based semantic search via search_workflows_semantic. The orchestrating LLM should generate the embedding externally and pass it here. Requires pgvector extension.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow" },
                    "embedding": {
                        "type": "array",
                        "items": { "type": "number" },
                        "description": "Pre-computed embedding vector (1536-dimensional float array)"
                    }
                },
                "required": ["workflow_id", "embedding"]
            }
        }),
        serde_json::json!({
            "name": "generate_workflow_embeddings",
            "description": "Auto-generate and store embeddings for workflows using the configured embedding provider. Supports any OpenAI-compatible API. Configure via environment: EMBEDDING_API_KEY (or OPENAI_API_KEY as fallback), EMBEDDING_MODEL (default: text-embedding-3-small), EMBEDDING_API_URL (default: OpenAI; set to http://localhost:11434/v1/embeddings for Ollama, etc.), EMBEDDING_DIMENSIONS (default: 1536). Processes workflows missing embeddings, enabling true semantic vector search. Call get_embedding_config to see the active provider.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "force_refresh": {
                        "type": "boolean",
                        "description": "If true, regenerate embeddings for ALL workflows, not just those missing them (default: false)"
                    },
                    "limit": {
                        "type": "number",
                        "description": "Maximum number of workflows to embed in this call (default: 50, max: 200). Use for incremental processing."
                    }
                }
            }
        }),
        serde_json::json!({
            "name": "get_embedding_config",
            "description": "Show the active embedding provider configuration: which API endpoint, model, and dimension count will be used for generate_workflow_embeddings and search_workflows_semantic. Useful to verify provider setup before bulk embedding.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }),
        serde_json::json!({
            "name": "tool_search",
            "description": "Search the 300+ Talos MCP tools by keyword — call this FIRST when unsure which tool handles a task. Returns matching tool names and descriptions ranked by relevance. By default returns the full inputSchema for each match so agents can call the tool without a second lookup; pass compact: true to get names + descriptions only (cheaper on context, useful for browsing). Key domain keywords: catalog, module, schedule, analytics, version, webhook, agent, secret, sandbox, alert, graph, execution, approval, actor, dlp, config.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Keyword or phrase to search for (case-insensitive, minimum 2 characters)"
                    },
                    "limit": {
                        "type": "number",
                        "description": "Maximum results to return (default: 10, max: 50)"
                    },
                    "compact": {
                        "type": "boolean",
                        "description": "If true, omit inputSchema from each result (name + description + relevance only). Default: false. Use for discovery browsing; follow up with another tool_search using a more specific query or invoke the tool directly once you've identified the target."
                    }
                },
                "required": ["query"]
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
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    match name {
        "search_workflows" => Some(handle_search_workflows(req_id, args, state, user_id).await),
        "tag_workflow" => Some(handle_tag_workflow(req_id, args, state, user_id).await),
        "untag_workflow" => Some(handle_untag_workflow(req_id, args, state, user_id).await),
        "add_workflow_tags" => Some(handle_bulk_tag_workflows(req_id, args, state, user_id).await),
        "bulk_tag_workflows" => Some(handle_bulk_tag_workflows(req_id, args, state, user_id).await), // grace-period alias
        "find_similar_workflows" => {
            Some(handle_find_similar_workflows(req_id, args, state, user_id).await)
        }
        "search_workflows_semantic" => {
            Some(handle_search_workflows_semantic(req_id, args, state, user_id).await)
        }
        "set_workflow_embedding" => {
            Some(handle_set_workflow_embedding(req_id, args, state, user_id).await)
        }
        "generate_workflow_embeddings" => {
            Some(handle_generate_workflow_embeddings(req_id, args, state, user_id).await)
        }
        "get_embedding_config" => Some(handle_get_embedding_config(req_id)),
        "tool_search" => Some(handle_tool_search(req_id, args).await),
        _ => None,
    }
}

async fn handle_search_workflows(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    // MCP-210 (2026-05-08): pre-fix `q.len() >= 2` accepted
    // whitespace-only queries like `"   "` (3 chars long) and ran a
    // SQL `LIKE '%   %'` which matched nothing. Trimmed-out queries
    // also caused silent zero-match (`"  ab  "` ran `LIKE '%  ab  %'`,
    // matching nothing because no workflow name has surrounding
    // double-spaces). Trim before the length check, then run the
    // SQL pattern against the trimmed query so accidental whitespace
    // in operator-typed queries doesn't silently neuter the search.
    let query_owned: String = match args.get("query").and_then(|v| v.as_str()) {
        Some(q) if q.len() > 1000 => {
            return mcp_error(req_id, -32602, "Query must be ≤ 1000 characters")
        }
        Some(q) => {
            let trimmed = q.trim();
            if trimmed.len() < 2 {
                return mcp_error(
                    req_id,
                    -32602,
                    "Query must be at least 2 non-whitespace characters",
                );
            }
            trimmed.to_string()
        }
        None => return mcp_error(req_id, -32602, "Missing 'query' parameter"),
    };
    let query = query_owned.as_str();
    // MCP-222 (2026-05-08): pre-fix `tag: "   "` was passed verbatim
    // to SQL — a real probe returned `count: 0, tag_filter: "   "`,
    // a confident "no matches" for what looked like a normal filter.
    // Same family as MCP-210 / MCP-221 list_workflows tag fix.
    let tag_filter_owned: Option<String> = match args.get("tag").and_then(|v| v.as_str()) {
        Some(t) if t.len() > 100 => {
            return mcp_error(req_id, -32602, "Tag filter must be ≤ 100 characters")
        }
        Some(t) => {
            let trimmed = t.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        None => None,
    };
    let tag_filter: Option<&str> = tag_filter_owned.as_deref();
    // MCP-267 (2026-05-10): direction-class wrong-type rejection.
    // Pre-fix `include_archived: "true"` (string) silently fell back
    // to false — operator searching for archived workflows got the
    // unarchived-only result with no signal. Same family as MCP-251.
    let include_archived =
        match crate::utils::validate_optional_bool(args, "include_archived", false, &req_id) {
            Ok(v) => v,
            Err(resp) => return resp,
        };

    // MCP-78 (2026-05-07): hard cap remains 20 by description; expose it
    // as `truncated_at` so callers can detect when their query saturated
    // the limit instead of having to count results manually.
    const SEARCH_LIMIT: i64 = 20;
    let search_pattern = format!("%{}%", escape_like(query));
    match state
        .workflow_repo
        .search_workflows_by_name_ilike(
            user_id,
            &search_pattern,
            tag_filter,
            include_archived,
            SEARCH_LIMIT,
        )
        .await
    {
        Ok(rows) => {
            let workflows: Vec<serde_json::Value> = rows
                .iter()
                .map(|r| {
                    let mut obj = serde_json::json!({
                        "id": r.id,
                        "workflow_id": r.id,
                        "name": r.name,
                        "tags": r.tags,
                        "status": r.status.as_deref().unwrap_or("draft"),
                        "created_at": r.created_at.to_rfc3339(),
                        "updated_at": r.updated_at.to_rfc3339(),
                    });
                    if let Some(obj_ref) = obj.as_object_mut() {
                        if let Some(ref desc) = r.description {
                            obj_ref.insert("description".to_string(), serde_json::json!(desc));
                        }
                    }
                    obj
                })
                .collect();
            let mut envelope = serde_json::json!({
                "count": workflows.len(),
                "query": query,
                "include_archived": include_archived,
                "truncated_at": SEARCH_LIMIT,
                "result_truncated": workflows.len() as i64 == SEARCH_LIMIT,
                "workflows": workflows,
            });
            if let Some(t) = tag_filter {
                if let Some(map) = envelope.as_object_mut() {
                    map.insert("tag_filter".to_string(), serde_json::Value::String(t.to_string()));
                }
            }
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&envelope).unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!("search_workflows query failed: {:#}", e);
            mcp_error(req_id, -32000, "Failed to search workflows")
        }
    }
}

async fn handle_tag_workflow(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let tag = match args.get("tag").and_then(|v| v.as_str()) {
        Some(t) if !t.is_empty() && t.len() <= 100 => t,
        _ => return mcp_error(req_id, -32602, "Tag must be 1-100 characters"),
    };
    // MCP-151 (2026-05-08): explicit format validation at handler
    // level. Pre-fix any DB-layer rejection (e.g. trailing whitespace
    // tripping a CHECK trigger) surfaced as a generic
    // "Failed to tag workflow" — operator couldn't tell what was
    // wrong. Reject control chars, null bytes, and leading/trailing
    // whitespace explicitly with actionable error messages.
    if let Err(reason) = validate_tag_format(tag) {
        return mcp_error(req_id, -32602, &reason);
    }

    // Enforce per-workflow tag count cap (100 tags max).
    let tag_count = state
        .workflow_repo
        .get_tag_count(wf_id, user_id)
        .await
        .unwrap_or(0);

    if tag_count >= 100 {
        return mcp_error(
            req_id,
            -32000,
            "Workflow already has the maximum of 100 tags",
        );
    }

    match state.workflow_repo.add_tag(wf_id, user_id, tag).await {
        Ok(n) if n > 0 => mcp_text(
            req_id,
            &format!("Tag '{}' added to workflow {}.", tag, wf_id),
        ),
        Ok(_) => mcp_text(
            req_id,
            &format!(
                "Tag '{}' already exists on workflow {} (or workflow not found).",
                tag, wf_id
            ),
        ),
        Err(e) => {
            tracing::error!("tag_workflow failed: {}", e);
            mcp_error(req_id, -32000, "Failed to tag workflow")
        }
    }
}

async fn handle_untag_workflow(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let tag = match args.get("tag").and_then(|v| v.as_str()) {
        Some(t) if !t.is_empty() && t.len() <= 100 => t,
        Some(_) => return mcp_error(req_id, -32602, "Tag must be 1-100 characters"),
        None => return mcp_error(req_id, -32602, "Missing or empty 'tag' parameter"),
    };
    // MCP-151: validate format so untag-by-typo gives a specific error
    // instead of a silent miss against the workflow_not_found_error path.
    if let Err(reason) = validate_tag_format(tag) {
        return mcp_error(req_id, -32602, &reason);
    }

    match state.workflow_repo.remove_tag(wf_id, user_id, tag).await {
        Ok(n) if n > 0 => mcp_text(
            req_id,
            &format!("Tag '{}' removed from workflow {}.", tag, wf_id),
        ),
        Ok(_) => crate::utils::workflow_not_found_error(req_id),
        Err(e) => {
            tracing::error!("untag_workflow failed: {}", e);
            mcp_error(req_id, -32000, "Failed to untag workflow")
        }
    }
}

async fn handle_bulk_tag_workflows(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let workflow_ids: Vec<uuid::Uuid> = match args.get("workflow_ids").and_then(|v| v.as_array()) {
        Some(arr) => {
            let mut ids = Vec::new();
            // MCP-249 (2026-05-08): dedup workflow_ids in-place. Pre-fix
            // a duplicate UUID in the input array (e.g. operator copy-
            // paste of the same id twice) inflated `total_requested`
            // without inflating `owned_count`, producing a misleading
            // `not_found_count: 1` warning even when every distinct
            // workflow was found and owned. A real probe with
            // `[X, X]` returned `tagged_count: 1, not_found_count: 1`
            // — the warning falsely accused the second entry of being
            // a missing/unauthorized workflow.
            let mut seen: std::collections::HashSet<uuid::Uuid> =
                std::collections::HashSet::new();
            for item in arr {
                match item.as_str().and_then(|s| s.parse::<uuid::Uuid>().ok()) {
                    Some(id) => {
                        if seen.insert(id) {
                            ids.push(id);
                        }
                    }
                    None => {
                        return mcp_error(
                            req_id,
                            -32602,
                            &format!(
                                "Invalid UUID in workflow_ids: {}",
                                talos_text_util::bounded_preview(&item.to_string(), 64)
                            ),
                        )
                    }
                }
            }
            if ids.is_empty() {
                return mcp_error(req_id, -32602, "workflow_ids array is empty");
            }
            if ids.len() > 100 {
                return mcp_error(req_id, -32602, "workflow_ids array exceeds maximum of 100");
            }
            ids
        }
        None => return mcp_error(req_id, -32602, "Missing or invalid workflow_ids array"),
    };
    let tag = match args.get("tag").and_then(|v| v.as_str()) {
        Some(t) if !t.is_empty() && t.len() <= 100 => t,
        _ => return mcp_error(req_id, -32602, "Tag must be 1-100 characters"),
    };
    // MCP-151: same format validation as the single-tag path so bulk
    // typos surface specifically instead of via DB-layer generic error.
    if let Err(reason) = validate_tag_format(tag) {
        return mcp_error(req_id, -32602, &reason);
    }

    // Single-query batch tag — the NOT ($1 = ANY(tags)) guard in the repo
    // method is idempotent, so workflows that already have the tag are skipped.
    // Per-workflow 100-tag cap is a soft limit enforced on the single-tag path;
    // bulk operations skip it to avoid N+1 queries.
    let tagged_count = state
        .workflow_repo
        .bulk_add_tag(&workflow_ids, user_id, tag)
        .await
        .unwrap_or(0);

    // MCP-152 (2026-05-08): the previous shape collapsed three cases —
    // workflow doesn't exist, isn't owned by caller, or is already
    // tagged — into a single "already_tagged_count". Operators typing a
    // UUID typo got back a confident "already tagged" result with no
    // signal that the id was bogus. Add a count-owned probe to break
    // them apart so the response distinguishes:
    //   tagged_count            — newly tagged
    //   already_tagged_count    — owned & already had the tag
    //   not_found_count         — id missing from workflows OR not owned
    let owned_count = state
        .workflow_repo
        .count_owned_workflows_in_set(&workflow_ids, user_id)
        .await
        .unwrap_or(0);
    let total = workflow_ids.len() as u64;
    let already_tagged_count = owned_count.saturating_sub(tagged_count);
    let not_found_count = total.saturating_sub(owned_count);

    let mut result = serde_json::json!({
        "tag": tag,
        "tagged_count": tagged_count,
        "already_tagged_count": already_tagged_count,
        "not_found_count": not_found_count,
        "total_requested": total,
    });
    if not_found_count > 0 {
        if let Some(map) = result.as_object_mut() {
            map.insert(
                "warning".to_string(),
                serde_json::json!(format!(
                    "{} workflow id(s) were not found or not owned by you and were skipped. Verify the UUIDs in the workflow_ids array.",
                    not_found_count
                )),
            );
        }
    }
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

async fn handle_find_similar_workflows(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // Load source workflow graph
    let source_graph_str = match state
        .workflow_repo
        .get_workflow_graph_for_similarity(wf_id, user_id)
        .await
    {
        Ok(Some(s)) => s,
        Ok(None) => return mcp_error(req_id, -32000, "Workflow not found or access denied"),
        Err(e) => {
            tracing::error!("find_similar_workflows source query failed: {:#}", e);
            return mcp_error(req_id, -32000, "Failed to fetch workflow");
        }
    };

    let source_graph: serde_json::Value = serde_json::from_str(&source_graph_str)
        .unwrap_or(serde_json::json!({"nodes":[],"edges":[]}));

    // Extract module_ids (node types) from source workflow
    let source_modules = talos_workflow_repository::extract_node_type_strings(&source_graph);

    if source_modules.is_empty() {
        return mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "workflow_id": wf_id.to_string(),
                "count": 0,
                "similar_workflows": [],
                "message": "Source workflow has no modules"
            }))
            .unwrap_or_default(),
        );
    }

    // Load all other workflows for this user
    let other_rows = state
        .workflow_repo
        .list_workflows_for_similarity(user_id, wf_id, 200)
        .await
        .unwrap_or_default();

    let mut similarities: Vec<(uuid::Uuid, String, usize, Vec<String>)> = Vec::new();

    for r in &other_rows {
        let other_graph: serde_json::Value = serde_json::from_str(&r.graph_json)
            .unwrap_or(serde_json::json!({"nodes":[],"edges":[]}));

        let other_modules = talos_workflow_repository::extract_node_type_strings(&other_graph);

        let shared: Vec<String> = source_modules
            .intersection(&other_modules)
            .cloned()
            .collect();
        if !shared.is_empty() {
            similarities.push((r.id, r.name.clone(), shared.len(), shared));
        }
    }

    // Sort by overlap count descending, take top 10
    similarities.sort_by_key(|a| std::cmp::Reverse(a.2));
    similarities.truncate(10);

    // MCP-44 (2026-05-07): resolve module UUIDs to names so the
    // shared_modules field surfaces both ID and human-readable label.
    // Pre-fix operators saw bare UUIDs and had to cross-reference
    // list_modules to know which modules overlapped. Single batch
    // query against `modules` covers every module referenced across
    // all top-10 results.
    let mut all_module_ids: std::collections::HashSet<Uuid> = std::collections::HashSet::new();
    for (_, _, _, shared) in &similarities {
        for s in shared {
            if let Ok(uuid) = s.parse::<Uuid>() {
                all_module_ids.insert(uuid);
            }
        }
    }
    let module_id_vec: Vec<Uuid> = all_module_ids.into_iter().collect();
    let name_map: std::collections::HashMap<Uuid, String> = state
        .module_repo
        .list_template_names_by_ids(&module_id_vec)
        .await
        .ok()
        .map(|rows| rows.into_iter().collect())
        .unwrap_or_default();

    let similar: Vec<serde_json::Value> = similarities
        .iter()
        .map(|(id, name, count, shared)| {
            let shared_with_names: Vec<serde_json::Value> = shared
                .iter()
                .map(|s| {
                    let resolved_name = s
                        .parse::<Uuid>()
                        .ok()
                        .and_then(|uuid| name_map.get(&uuid).cloned());
                    serde_json::json!({
                        "module_id": s,
                        "name": resolved_name,
                    })
                })
                .collect();
            serde_json::json!({
                "workflow_id": id.to_string(),
                "workflow_name": name,
                "overlap_count": count,
                "shared_modules": shared_with_names,
            })
        })
        .collect();

    // MCP-100 (2026-05-08): emit canonical `count` envelope + truncation
    // signal. Tool description caps at 10 results — surface that so
    // callers can detect saturation (same MCP-78 pattern as
    // search_workflows).
    const SIMILAR_LIMIT: usize = 10;
    let result_truncated = similar.len() == SIMILAR_LIMIT;
    let result = serde_json::json!({
        "source_workflow_id": wf_id.to_string(),
        "source_module_count": source_modules.len(),
        "count": similar.len(),
        "truncated_at": SIMILAR_LIMIT,
        "result_truncated": result_truncated,
        "similar_workflows": similar,
    });

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

async fn handle_search_workflows_semantic(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    // Protocol-level arg parsing. The service expects already-validated
    // typed inputs and does not second-guess clamps.
    // MCP-210 (2026-05-08): pre-fix `!q.is_empty() && q.len() <= 500`
    // accepted whitespace-only queries (`"   "`), running a vector-
    // embedding lookup on what is effectively a no-op input — the
    // resulting embedding is meaningless and matches semantically-
    // unrelated workflows, wasting embedding-provider quota too.
    // Reject whitespace at the boundary, mirroring search_workflows.
    let query_owned: String = match args.get("query").and_then(|v| v.as_str()) {
        Some(q) if q.len() > 500 => {
            return mcp_error(req_id, -32602, "Query must be ≤500 characters")
        }
        Some(q) => {
            let trimmed = q.trim();
            if trimmed.is_empty() {
                return mcp_error(
                    req_id,
                    -32602,
                    "Query must be non-empty and non-whitespace",
                );
            }
            trimmed.to_string()
        }
        None => return mcp_error(req_id, -32602, "Missing or empty 'query' parameter"),
    };
    let query_str = query_owned.as_str();
    let limit = match crate::utils::validate_range_i64(args, "limit", 1, 50, 10, &req_id) {
        Ok(v) => v as i32,
        Err(resp) => return resp,
    };
    // MCP-222 (2026-05-08): trim tag filter — semantic-search probe with
    // `tag: "   "` returned count: 0 because the whitespace was passed
    // verbatim to the DB filter. Mirrors the search_workflows fix above.
    let tag_filter_owned: Option<String> = match args.get("tag").and_then(|v| v.as_str()) {
        Some(t) if t.len() > 100 => {
            return mcp_error(req_id, -32602, "Tag filter must be ≤ 100 characters")
        }
        Some(t) => {
            let trimmed = t.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        None => None,
    };
    let tag_filter: Option<&str> = tag_filter_owned.as_deref();
    // MCP-267 (2026-05-10): see search_workflows above.
    let include_archived =
        match crate::utils::validate_optional_bool(args, "include_archived", false, &req_id) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    // Minimum cosine similarity threshold. Provider-specific: the
    // default-deploy `nomic-embed-text` (Ollama, 768 dims) produces
    // cosine scores in roughly [0.35, 0.65] for English-text matches
    // — NOT the [0.5, 0.9] distribution typical of OpenAI's
    // text-embedding-ada-002. The pre-fix 0.55 default was calibrated
    // for the OpenAI distribution and silently filtered out genuine
    // on-topic matches under nomic (M-H audit, 2026-05-06: query
    // "competitive intelligence on AI security vendors" against the
    // watch-* workflows scored 0.40-0.47, all below the old default).
    //
    // Default lowered to 0.40 to cover the nomic noise floor (~0.35)
    // without exposing the [0.0, 0.35] random-noise band. Operators
    // running a different embedding provider can override via the
    // `SEMANTIC_SEARCH_MIN_SCORE` env var (parsed at request time so
    // a config change takes effect without restart) or per-request via
    // the `min_score` arg.
    const DEFAULT_MIN_SCORE_FALLBACK: f64 = 0.40;
    let env_default = std::env::var("SEMANTIC_SEARCH_MIN_SCORE")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .map(|f| f.clamp(0.0, 1.0));
    let default_min_score = env_default.unwrap_or(DEFAULT_MIN_SCORE_FALLBACK);
    let min_score =
        match crate::utils::validate_range_f64(args, "min_score", 0.0, 1.0, default_min_score, &req_id) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    // MCP-308 (2026-05-11): strict-parse via parse_embedding_array — see
    // `handle_set_workflow_embedding` above for the rationale.
    let caller_embedding: Option<Vec<f64>> = match args
        .get("embedding")
        .and_then(|v| v.as_array())
    {
        Some(arr) => match crate::utils::parse_embedding_array(arr) {
            Ok(parsed) => Some(parsed),
            Err(msg) => return mcp_error(req_id, -32602, &msg),
        },
        None => None,
    };
    // Dimension check uses EMBEDDING_DIMENSIONS env var (defaults to
    // 768 for nomic-embed-text). Must match the pgvector column size
    // — see migration 20260317000100_resize_embedding_vector.sql.
    //
    // MCP-1055 (2026-05-15): route through `positive_env_or_default`.
    // Pre-fix `parse::<usize>().ok().unwrap_or(768)` accepted
    // `EMBEDDING_DIMENSIONS=0` as `Some(0)`, propagating zero
    // dimensions to the search service and producing a confusing
    // pgvector "dimension mismatch" error at query time instead of
    // a clean "operator misconfiguration" substitution. Same
    // `=0` footgun class as MCP-638/643/661/663/664/665/703/758 —
    // helper substitutes the default + emits a structured WARN.
    let expected_dims =
        talos_config::positive_env_or_default::<usize>("EMBEDDING_DIMENSIONS", 768);

    let outcome = match state
        .search_service
        .search_semantic(talos_search_service::SemanticSearchInput {
            user_id,
            query: query_str,
            limit,
            tag_filter,
            include_archived,
            min_score,
            caller_embedding,
            expected_dims,
        })
        .await
    {
        Ok(o) => o,
        Err(e) => {
            // Internal errors are logged inside the service; the
            // wrapper just emits the user-facing redacted message.
            return mcp_error(req_id, e.jsonrpc_code(), &e.user_facing_message());
        }
    };

    // M-G (2026-05-06): serialise the WHOLE outcome (envelope +
    // results) so empty results still tell the operator which path
    // ran and what threshold was applied. Pre-fix, an empty result
    // set returned a bare `[]` and the operator could not tell
    // whether the threshold filtered everything out, embeddings were
    // missing, or the provider was unreachable.
    //
    // MCP-87 (2026-05-07): post-process the outcome to:
    //   * add top-level `count` field (envelope sweep).
    //   * add `workflow_id` per result alongside legacy `id` (MCP-31).
    //   * drop per-row `match_method` (top-level field already carries
    //     it and is uniform across rows for a single search call).
    //   * round per-row `match_score` to 4 decimals so f64 noise digits
    //     don't leak.
    let mut envelope = serde_json::to_value(&outcome).unwrap_or(serde_json::Value::Null);
    if let Some(map) = envelope.as_object_mut() {
        // Compute count + post-process each result entry first (releases
        // the mutable borrow of `results`), then re-borrow `map` to
        // insert the count field — borrow checker doesn't allow holding
        // both mutable references simultaneously.
        let count = if let Some(serde_json::Value::Array(results)) =
            map.get_mut("results")
        {
            for entry in results.iter_mut() {
                if let Some(obj) = entry.as_object_mut() {
                    if let Some(id_val) = obj.get("id").cloned() {
                        obj.insert("workflow_id".to_string(), id_val);
                    }
                    obj.remove("match_method");
                    if let Some(score) = obj.get_mut("match_score") {
                        if let Some(f) = score.as_f64() {
                            if f.is_finite() {
                                let rounded = (f * 10000.0).round() / 10000.0;
                                if let Some(n) = serde_json::Number::from_f64(rounded) {
                                    *score = serde_json::Value::Number(n);
                                }
                            }
                        }
                    }
                }
            }
            Some(results.len())
        } else {
            None
        };
        if let Some(c) = count {
            map.insert(
                "count".to_string(),
                serde_json::Value::Number(c.into()),
            );
        }
    }
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&envelope).unwrap_or_default(),
    )
}

async fn handle_set_workflow_embedding(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    // MCP-308 (2026-05-11): strict-parse via parse_embedding_array.
    // Pre-fix `filter_map(|v| v.as_f64())` silently dropped non-number
    // entries — an operator passing `embedding: ["abc", 1.0, ...]` (1536
    // entries with a string at index 0) saw "Embedding must be exactly
    // 1536 dimensions, got 1535" instead of "embedding[0] must be a
    // number, got string". The misleading length error obscured the real
    // shape bug.
    let embedding: Vec<f64> = match args.get("embedding").and_then(|v| v.as_array()) {
        Some(arr) => match crate::utils::parse_embedding_array(arr) {
            Ok(parsed) => {
                if parsed.len() != 1536 {
                    return mcp_error(
                        req_id,
                        -32602,
                        &format!(
                            "Embedding must be exactly 1536 dimensions, got {}",
                            parsed.len()
                        ),
                    );
                }
                parsed
            }
            Err(msg) => return mcp_error(req_id, -32602, &msg),
        },
        None => return mcp_error(req_id, -32602, "Missing 'embedding' array"),
    };

    // Verify workflow ownership
    let exists: bool = state.workflow_repo.workflow_exists(wf_id, user_id).await;

    if !exists {
        return crate::utils::workflow_not_found_error(req_id);
    }

    // Store embedding as pgvector
    match state.workflow_repo.set_workflow_embedding(wf_id, user_id, &embedding).await {
        Ok(_) => mcp_text(
            req_id,
            &format!(
                "Embedding stored for workflow {}. Vector search is now available for this workflow via search_workflows_semantic.",
                wf_id
            ),
        ),
        Err(e) => {
            let err_str = e.to_string();
            if err_str.contains("vector") || err_str.contains("type") {
                return mcp_error(
                    req_id,
                    -32000,
                    "pgvector extension not available. Install pgvector to enable embedding storage.",
                );
            }
            tracing::error!("set_workflow_embedding failed: {}", e);
            mcp_error(req_id, -32000, "Failed to store embedding")
        }
    }
}

fn handle_get_embedding_config(req_id: Option<serde_json::Value>) -> JsonRpcResponse {
    match EmbeddingConfig::from_env() {
        Some(config) => {
            let result = serde_json::json!({
                "configured": true,
                "model": config.model,
                "api_url": config.api_url,
                "dimensions": config.dimensions,
                "key_source": if std::env::var("EMBEDDING_API_KEY").ok().filter(|k| !k.is_empty()).is_some() {
                    "EMBEDDING_API_KEY"
                } else if std::env::var("OPENAI_API_KEY").ok().filter(|k| !k.is_empty()).is_some() {
                    "OPENAI_API_KEY (fallback)"
                } else {
                    "none (keyless endpoint)"
                },
                "env_vars": {
                    "EMBEDDING_API_KEY": "Provider API key (preferred over OPENAI_API_KEY)",
                    "OPENAI_API_KEY": "OpenAI key — used as fallback when EMBEDDING_API_KEY is unset",
                    "EMBEDDING_API_URL": "Embedding endpoint (default: https://api.openai.com/v1/embeddings). Examples: http://localhost:11434/v1/embeddings (Ollama), https://<resource>.openai.azure.com/openai/deployments/<deployment>/embeddings?api-version=2024-02-01 (Azure)",
                    "EMBEDDING_MODEL": "Model name (default: text-embedding-3-small). Examples: nomic-embed-text (Ollama), text-embedding-ada-002, jina-embeddings-v3",
                    "EMBEDDING_DIMENSIONS": "Expected output dimensions (default: 1536). Must match the DB column size."
                },
            });
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&result).unwrap_or_default(),
            )
        }
        None => {
            let result = serde_json::json!({
                "configured": false,
                "reason": "No embedding provider configured. Set EMBEDDING_API_KEY (or OPENAI_API_KEY for OpenAI) to enable semantic search.",
                "env_vars": {
                    "EMBEDDING_API_KEY": "Provider API key (preferred)",
                    "OPENAI_API_KEY": "OpenAI key (fallback)",
                    "EMBEDDING_API_URL": "Custom endpoint for Ollama/Azure/other providers (set this even for keyless local models)",
                    "EMBEDDING_MODEL": "Model name (default: text-embedding-3-small)",
                    "EMBEDDING_DIMENSIONS": "Expected output size (default: 1536)"
                },
                "examples": [
                    "OpenAI: EMBEDDING_API_KEY=sk-... EMBEDDING_MODEL=text-embedding-3-small",
                    "Ollama: EMBEDDING_API_URL=http://localhost:11434/v1/embeddings EMBEDDING_MODEL=nomic-embed-text EMBEDDING_DIMENSIONS=768",
                    "Azure: EMBEDDING_API_URL=https://<res>.openai.azure.com/openai/deployments/<dep>/embeddings?api-version=2024-02-01 EMBEDDING_API_KEY=<key>",
                    "Jina: EMBEDDING_API_URL=https://api.jina.ai/v1/embeddings EMBEDDING_API_KEY=<key> EMBEDDING_MODEL=jina-embeddings-v3 EMBEDDING_DIMENSIONS=1024"
                ],
            });
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&result).unwrap_or_default(),
            )
        }
    }
}

async fn handle_generate_workflow_embeddings(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    // Verify an embedding provider is configured before doing any work
    let embed_config = match EmbeddingConfig::from_env() {
        Some(c) => c,
        None => {
            return mcp_error(
                req_id,
                -32000,
                "No embedding provider configured. Set EMBEDDING_API_KEY (or OPENAI_API_KEY for OpenAI) \
                 to enable automatic embedding generation. See get_embedding_config for setup options.",
            )
        }
    };

    // MCP-267 (2026-05-10): direction-class — `force_refresh: "true"`
    // string silently fell back to false, the embedding regeneration
    // wouldn't refresh stale rows when the operator explicitly asked.
    let force_refresh =
        match crate::utils::validate_optional_bool(args, "force_refresh", false, &req_id) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    let limit = match crate::utils::validate_range_i64(args, "limit", 1, 200, 50, &req_id) {
        Ok(v) => v as i32,
        Err(resp) => return resp,
    };

    // Fetch workflows that need embeddings
    let rows = match state
        .workflow_repo
        .list_workflows_for_embedding_generation(user_id, force_refresh, limit)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("generate_workflow_embeddings query failed: {:#}", e);
            return mcp_error(req_id, -32000, "Failed to fetch workflows");
        }
    };

    if rows.is_empty() {
        return mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "embedded": 0,
                "skipped": 0,
                "total_candidates": 0,
                "message": if force_refresh {
                    "No workflows found for this user."
                } else {
                    "All workflows already have embeddings. Use force_refresh: true to regenerate."
                }
            }))
            .unwrap_or_default(),
        );
    }

    let total = rows.len();
    let mut embedded = 0usize;
    let mut skipped = 0usize;
    let mut errors: Vec<String> = Vec::new();

    // Build the text inputs in deterministic order so we can map response
    // vectors back to workflow ids. Order matters — generate_embeddings_batch
    // returns vectors in the same order as the input slice.
    let mut inputs: Vec<String> = Vec::with_capacity(rows.len());
    for r in &rows {
        let intent_str = r
            .intent
            .as_ref()
            .and_then(|v| v.as_str())
            .map(String::from)
            .or_else(|| r.intent.as_ref().map(|v| v.to_string()));
        inputs.push(workflow_embedding_text(
            &r.name,
            r.description.as_deref(),
            &r.capabilities,
            intent_str.as_deref(),
        ));
    }

    // One batched embedding request (chunked to EMBED_BATCH_MAX inside the
    // helper) followed by ONE batched DB UPDATE via UNNEST. Pre-r241 the
    // embedding side was N HTTP calls; pre-iteration-33 the DB side was N
    // UPDATEs. End state: ⌈N/50⌉ provider calls + 1 DB round-trip for up
    // to 200 workflows.
    match generate_embeddings_batch(&inputs).await {
        Ok(vectors) => {
            let pairs: Vec<(uuid::Uuid, String)> = rows
                .iter()
                .zip(vectors.iter())
                .map(|(r, embedding)| (r.id, vec_to_pgvector_literal(embedding)))
                .collect();
            match state
                .workflow_repo
                .bulk_set_workflow_embeddings_from_str(&pairs, user_id)
                .await
            {
                Ok(n_updated) => {
                    // rows_affected == rows we actually updated. Anything
                    // less than total means a row was deleted between the
                    // initial fetch and the UPDATE (TOCTOU); we no longer
                    // know WHICH rows specifically (single statement, no
                    // per-row error), so the operator-facing message says
                    // "concurrent deletion" rather than naming a workflow.
                    embedded = n_updated as usize;
                    skipped = total.saturating_sub(embedded);
                    if skipped > 0 {
                        errors.push(format!(
                            "{} workflow(s) were not updated — likely deleted between fetch and update",
                            skipped
                        ));
                    }
                    tracing::debug!(
                        embedded,
                        total,
                        "bulk_set_workflow_embeddings_from_str complete"
                    );
                }
                Err(e) => {
                    // DB-level failure (dimension mismatch, connection drop,
                    // pgvector unavailable). Whole UPDATE rolled back — no
                    // partial state. Surface the actual error so operators
                    // see e.g. "expected dim 1024 got 768" rather than the
                    // generic "Embedding generation failed".
                    let detail = format!("Embedding storage failed: {:#}", e);
                    tracing::warn!(error = %e, "bulk_set_workflow_embeddings_from_str failed");
                    for r in &rows {
                        errors.push(format!("'{}': {}", r.name, detail));
                        skipped += 1;
                    }
                }
            }
        }
        Err(e) => {
            // Batch-level provider failure: rejected, network down, etc.
            // Every workflow in this call gets the SAME status-bearing error
            // string so the operator can see "Voyage 429" rather than
            // N copies of "Embedding generation failed".
            //
            // MCP-768: the `EmbeddingError::Network(reqwest_err_str)`
            // variant embeds the configured `EMBEDDING_API_URL` via the
            // reqwest error Display (e.g. cluster-internal hostnames
            // like `http://embedding.talos.svc.cluster.local:8080/embed`
            // on DNS / connect failures). The pre-fix `format!("{}", e)`
            // surfaced that URL in the response `errors[]` array to any
            // authenticated MCP caller — same enumeration class as
            // MCP-634 (cached `provider_last_error`) and MCP-217
            // (Ollama URL leak). Sanitize the caller-bound copy through
            // the shared helper; the controller-side `tracing::warn!`
            // below keeps the raw URL for operator visibility.
            let raw = format!("Embedding API failed [{}]: {}", e.kind(), e);
            let detail = talos_search_service::sanitize_provider_error_for_caller(raw);
            tracing::warn!(kind = e.kind(), error = %e, "bulk embed failed");
            for r in &rows {
                errors.push(format!("'{}': {}", r.name, detail));
                skipped += 1;
            }
        }
    }

    let result = serde_json::json!({
        "embedded": embedded,
        "skipped": skipped,
        "total_candidates": total,
        "provider": embed_config.describe(),
        "errors": errors,
        "message": format!(
            "Embedded {}/{} workflows using {}. Semantic search is now active — search_workflows_semantic will use vector similarity for embedded workflows.",
            embedded, total, embed_config.model
        ),
    });

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

// ── tool_search ───────────────────────────────────────────────────────────────
// Searches the static MCP tool manifest by keyword so agents can discover
// which tool to call without having to enumerate the full 70+ tool list.
// Ranking: exact name match (score 3) > name contains (score 2) >
//          description contains (score 1). Ties broken by name order.

async fn handle_tool_search(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
) -> JsonRpcResponse {
    // MCP-283 (2026-05-10): pre-fix `q.len() >= 2` accepted `"  "`
    // (2 spaces) — passes the length gate, then lower-cased and
    // substring-matched against tool names / descriptions, which
    // produces empty results with no useful signal. Trim before
    // length check. Same MCP-210 family.
    let query = match args.get("query").and_then(|v| v.as_str()) {
        Some(q) if q.len() > 1000 => {
            return mcp_error(req_id, -32602, "Query must be ≤ 1000 characters")
        }
        Some(q) => {
            let trimmed = q.trim();
            if trimmed.len() < 2 {
                return mcp_error(
                    req_id,
                    -32602,
                    "Query must be at least 2 non-whitespace characters",
                );
            }
            trimmed.to_lowercase()
        }
        None => return mcp_error(req_id, -32602, "Missing required parameter: query"),
    };
    // MCP-180 (2026-05-08): replace silent-clamp with explicit
    // validation. Pre-fix `unwrap_or(10).min(50)` silently rewrote
    // 99999 → 50 with no signal — agents asking for "give me as
    // many tools as you can" got 50 every time without knowing.
    let limit = match crate::utils::validate_range_u64(args, "limit", 1, 50, 10, &req_id) {
        Ok(v) => v as usize,
        Err(resp) => return resp,
    };
    // MCP-270 (2026-05-10): direction-class wrong-type rejection.
    let compact = match crate::utils::validate_optional_bool(args, "compact", false, &req_id) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // Collect all static tool schemas from every domain module.
    // Dynamic template-derived tools are intentionally excluded; use
    // list_module_catalog / list_templates to browse those.
    // Deduplicate by name (first occurrence wins, preserving domain priority order).
    let all_tools: Vec<serde_json::Value> = {
        let raw = [
            super::sandbox::tool_schemas(),
            super::workflows::tool_schemas(),
            super::executions::tool_schemas(),
            super::secrets::tool_schemas(),
            super::schedules::tool_schemas(),
            super::versions::tool_schemas(),
            super::webhooks::tool_schemas(),
            super::graph::tool_schemas(),
            super::modules::tool_schemas(),
            super::analytics::tool_schemas(),
            super::search::tool_schemas(),
            super::alerts::tool_schemas(),
            super::schemas::tool_schemas(),
            super::platform::tool_schemas(),
            super::advanced::tool_schemas(),
            super::actor::tool_schemas(),
        ]
        .concat();
        let mut seen = std::collections::HashSet::new();
        raw.into_iter()
            .filter(|t| {
                let name = t
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                seen.insert(name)
            })
            .collect()
    };

    // Tokenize the query: split on whitespace and underscores so multi-word
    // queries like "create workflow blank new" and underscore-joined queries
    // like "create_workflow add_node_to_workflow" search term-by-term rather
    // than as a single literal substring.  Tokens shorter than 3 characters
    // are dropped to reduce noise ("to", "a", "of").  If all tokens are too
    // short we fall back to the raw query so two-character queries still work.
    let tokens: Vec<&str> = {
        let v: Vec<&str> = query
            .split(|c: char| c.is_whitespace() || c == '_')
            .filter(|t| t.len() >= 3)
            .collect();
        if v.is_empty() {
            vec![query.as_str()]
        } else {
            v
        }
    };

    // Score each tool against every token independently.
    // Per-token scoring: exact name = 3, name contains token = 2, desc contains token = 1.
    // Total score is the sum across all tokens; tools with score 0 are excluded.
    let mut scored: Vec<(u32, serde_json::Value)> = all_tools
        .into_iter()
        .filter_map(|tool| {
            let name = tool
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let desc = tool
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let name_lower = name.to_lowercase();
            let desc_lower = desc.to_lowercase();

            let score: u32 = tokens
                .iter()
                .map(|&tok| {
                    if name_lower == tok {
                        3 // Exact name match
                    } else if name_lower.contains(tok) {
                        2 // Name substring match
                    } else if desc_lower.contains(tok) {
                        1 // Description contains token
                    } else {
                        0
                    }
                })
                .sum();

            if score == 0 {
                None
            } else {
                Some((score, tool))
            }
        })
        .collect();

    // Sort descending by score, then ascending by name for stable ordering.
    scored.sort_by(|(sa, ta), (sb, tb)| {
        sb.cmp(sa).then_with(|| {
            let na = ta.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let nb = tb.get("name").and_then(|v| v.as_str()).unwrap_or("");
            na.cmp(nb)
        })
    });

    // Static co-loading groups: tools commonly used together.
    // When any returned result is in a group, surface the rest of that group.
    const TOOL_GROUPS: &[(&str, &[&str])] = &[
        (
            "schedule",
            &[
                "list_schedules",
                "create_schedule",
                "pause_schedule",
                "resume_schedule",
                "delete_schedule",
                "get_schedule_next_runs",
            ],
        ),
        (
            "execution",
            &[
                "trigger_workflow",
                "get_execution_status",
                "get_execution_status",
                "list_recent_executions",
                "cancel_execution",
                "cancel_queued_executions",
                "get_execution_lineage",
                "get_workflow_quickstart",
            ],
        ),
        (
            "module",
            &[
                "list_modules",
                "install_module_from_catalog",
                "restore_pinned_modules",
                "list_module_catalog",
                "compile_and_add_module",
            ],
        ),
        (
            "secret",
            &[
                "list_secrets",
                "list_secret_namespaces",
                "list_secret_usage",
                "list_expiring_secrets",
                "get_unused_secrets",
                "check_secret_health",
                "refresh_oauth_token",
                "get_secret_access_log",
            ],
        ),
        (
            "workflow",
            &[
                "create_workflow",
                "list_workflows",
                "get_workflow",
                "update_workflow",
                "get_workflow_quickstart",
                "add_workflow_tags",
            ],
        ),
        (
            "version",
            &[
                "publish_version",
                "list_versions",
                "rollback_version",
                "compare_versions",
                "get_workflow_quickstart",
            ],
        ),
        (
            "graph",
            &[
                "add_node_to_workflow",
                "add_edge",
                "add_collect_node",
                "add_loop_node",
                "remove_node",
                "update_node_config",
                "get_workflow_quickstart",
            ],
        ),
        (
            "sandbox",
            &[
                "create_sandbox",
                "lint_sandbox",
                "compile_sandbox",
                "get_rust_scaffold",
                "get_js_scaffold",
                "get_python_scaffold",
                "add_node_to_workflow",
                "get_workflow_quickstart",
            ],
        ),
        (
            "webhook",
            &[
                "create_webhook",
                "list_webhooks",
                "pause_webhook",
                "resume_webhook",
                "test_webhook",
            ],
        ),
    ];

    // Include the full inputSchema so agents have parameter names and types
    // in context — enabling correct tool calls without a separate schema lookup.
    // Note: tool_search DISCOVERS tools that are already registered in the
    // session's tools/list manifest; it does not register new callable tools.
    let results: Vec<serde_json::Value> = scored
        .into_iter()
        .take(limit)
        .map(|(score, tool)| {
            let relevance = match score {
                3 => "exact_name",
                2 => "name_match",
                _ => "description_match",
            };
            if compact {
                serde_json::json!({
                    "name": tool.get("name"),
                    "description": tool.get("description"),
                    "relevance": relevance,
                })
            } else {
                serde_json::json!({
                    "name": tool.get("name"),
                    "description": tool.get("description"),
                    "inputSchema": tool.get("inputSchema"),
                    "relevance": relevance,
                })
            }
        })
        .collect();

    // Build related_tools: for each group, check if ≥1 result tool is in that group.
    // Emit that group's remaining tools (excluding already-returned ones) as suggestions.
    let returned_names: std::collections::HashSet<&str> = results
        .iter()
        .filter_map(|t| t.get("name").and_then(|v| v.as_str()))
        .collect();

    let mut related_tools: Vec<serde_json::Value> = Vec::new();
    for &(group_name, group_tools) in TOOL_GROUPS {
        let matched: Vec<&str> = group_tools
            .iter()
            .filter(|&&t| returned_names.contains(t))
            .copied()
            .collect();
        if matched.is_empty() {
            continue;
        }
        let suggestions: Vec<&str> = group_tools
            .iter()
            .filter(|&&t| !returned_names.contains(t))
            .copied()
            .collect();
        if !suggestions.is_empty() {
            related_tools.push(serde_json::json!({
                "group": group_name,
                "tools": suggestions,
                "note": "Commonly used together",
            }));
        }
    }

    let count = results.len();
    let hint: Option<&str> = if count == 0 {
        Some(
            "No matches found. Try a broader term. Available search domains: \
              workflow, execution, schedule, analytics, version, webhook, agent, \
              secret, sandbox, alert, graph, module, template, configuration, platform",
        )
    } else if count < 3 {
        Some("Tip: if you expected more results, try a broader search term or a different domain keyword")
    } else {
        None
    };
    let mut resp = serde_json::json!({
        "query": query,
        "count": count,
        "tools": results,
    });
    if let Some(obj) = resp.as_object_mut() {
        if !related_tools.is_empty() {
            obj.insert(
                "related_tools".to_string(),
                serde_json::json!(related_tools),
            );
        }
        if let Some(h) = hint {
            obj.insert("hint".to_string(), serde_json::json!(h));
        }
    }
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&resp).unwrap_or_default(),
    )
}

/// MCP-151 (2026-05-08): pre-flight validation for free-form workflow
/// tags. Tags are intentionally less strict than capabilities (which
/// match `^[a-z0-9-]+$`) — operators are allowed mixed-case names and
/// punctuation for human-readable filtering. But trailing whitespace,
/// embedded control chars, and null bytes all caused DB-layer
/// rejections that surfaced as a generic "Failed to tag workflow" with
/// no hint of what was wrong; reject them up-front with specific
/// messages instead.
fn validate_tag_format(tag: &str) -> Result<(), String> {
    if tag != tag.trim() {
        return Err("Tag cannot have leading or trailing whitespace".to_string());
    }
    if tag.contains('\0') {
        return Err("Tag cannot contain null bytes".to_string());
    }
    if tag.chars().any(|c| c.is_control()) {
        return Err("Tag cannot contain control characters".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tag_format_tests {
    use super::validate_tag_format;

    #[test]
    fn accepts_normal_tag() {
        assert!(validate_tag_format("ceo-operations").is_ok());
        assert!(validate_tag_format("Production").is_ok());
        assert!(validate_tag_format("v2-rollout").is_ok());
    }

    #[test]
    fn rejects_trailing_whitespace() {
        assert!(validate_tag_format("trailing ").is_err());
        assert!(validate_tag_format(" leading").is_err());
        assert!(validate_tag_format("\ttab").is_err());
    }

    #[test]
    fn rejects_null_byte() {
        assert!(validate_tag_format("nul\0byte").is_err());
    }

    #[test]
    fn rejects_control_char() {
        assert!(validate_tag_format("newline\nin-tag").is_err());
        assert!(validate_tag_format("ascii-bell\x07").is_err());
    }
}
