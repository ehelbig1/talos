use super::types::JsonRpcResponse;
use super::utils::{compute_mcp_graph_diff, mcp_error, mcp_text};
use super::{auth, McpState};
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;

pub fn tool_schemas() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
            "name": "publish_version",
            "description": "Publish the current draft of a workflow as an immutable version. The new version becomes the active published version used when triggering the workflow.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow to publish" },
                    "description": { "type": "string", "description": "Optional description of what changed in this version" },
                    "intent": {
                        "type": "object",
                        "description": "Optional structured intent metadata to set on the workflow",
                        "properties": {
                            "action": { "type": "string" },
                            "subject": { "type": "string" },
                            "output_type": { "type": "string" },
                            "trigger_context": { "type": "string" }
                        }
                    },
                    "capabilities": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Optional capability tags to set on the workflow"
                    }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "list_versions",
            "description": "List published versions of a workflow, ordered by version number descending.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow" }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "rollback_workflow",
            "description": "Rollback a workflow's draft to a previously published version. Copies that version's graph_json back to the draft and creates a new active version.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow" },
                    "version_number": { "type": "number", "description": "Version number to rollback to" }
                },
                "required": ["workflow_id", "version_number"]
            }
        }),
        serde_json::json!({
            "name": "diff_versions",
            "description": "Compare two published versions of a workflow. Shows added/removed/changed nodes and edges.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow" },
                    "version_a": { "type": "number", "description": "First version number to compare" },
                    "version_b": { "type": "number", "description": "Second version number to compare" }
                },
                "required": ["workflow_id", "version_a", "version_b"]
            }
        }),
        serde_json::json!({
            "name": "get_version_diff_summary",
            "description": "Quick diff between the current draft and the last published version. Returns a human-readable summary like '3 nodes added, 1 removed, 2 edges changed'.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow" }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "list_workflow_versions_with_diff",
            "description": "List published versions of a workflow with inline diffs showing what changed from the predecessor. Combines list_versions + diff_versions into a single call.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow" },
                    "limit": { "type": "number", "description": "Max versions to return (default 20, max 100)" }
                },
                "required": ["workflow_id"]
            }
        }),
    ]
}

pub async fn dispatch(
    name: &str,
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> Option<JsonRpcResponse> {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    match name {
        "publish_version" => Some(handle_publish_version(req_id, args, state, user_id).await),
        "list_versions" => Some(handle_list_versions(req_id, args, state, user_id).await),
        "rollback_workflow" => Some(handle_rollback_workflow(req_id, args, state, user_id).await),
        "diff_versions" => Some(handle_diff_versions(req_id, args, state, user_id).await),
        "get_version_diff_summary" => {
            Some(handle_get_version_diff_summary(req_id, args, state, user_id).await)
        }
        "list_workflow_versions_with_diff" => {
            Some(handle_list_workflow_versions_with_diff(req_id, args, state, user_id).await)
        }
        _ => None,
    }
}

async fn handle_publish_version(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let workflow_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    // MCP-186 (2026-05-08): reject whitespace-only descriptions.
    // MCP-431 (2026-05-11): migrate to canonical multi-line helper.
    // Pre-fix `Some(d) => Some(d.to_string())` persisted UNTRIMMED
    // values, AND length was checked on untrimmed, AND no control-
    // char check. Version history is IMMUTABLE — a row with
    // "   release notes   " is permanently in the audit trail with
    // surrounding padding, and `\0` would crash the publish tx with
    // an opaque Postgres error. Same migration pattern as MCP-426
    // → MCP-429.
    let description = match crate::utils::validate_multiline_description(
        "description",
        args.get("description").and_then(|v| v.as_str()),
        2000,
        "",
        req_id.clone(),
    ) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    // MCP-193 (2026-05-08): validate intent shape if provided.
    // Pre-fix publish_version skipped intent validation entirely, so
    // a publish with intent={"action":"   ","subject":"   "} stamped
    // whitespace into version history. Mirrors create_workflow's
    // call site.
    let intent = args.get("intent").cloned();
    if let Some(ref intent_value) = intent {
        if let Err(msg) = talos_workflow_creation_helpers::validate_intent(intent_value) {
            return mcp_error(req_id, -32602, &msg);
        }
    }
    // MCP-313 (2026-05-11): strict-parse capabilities to parity with
    // set_workflow_capabilities (MCP-285). Pre-fix
    // `filter_map(|s| s.as_str().map(String::from))` silently dropped
    // non-string entries — `capabilities: ["http", 42, "secrets"]` was
    // persisted to version history as `["http", "secrets"]`, narrowing
    // the operator's deliberate 3-cap declaration to 2 with no signal.
    // The published version is immutable, so the silent narrowing
    // becomes a permanent record of an unintended capability set.
    let capabilities: Option<Vec<String>> =
        match args.get("capabilities").and_then(|v| v.as_array()) {
            Some(arr) => {
                let mut out: Vec<String> = Vec::with_capacity(arr.len());
                for (i, v) in arr.iter().enumerate() {
                    match v.as_str() {
                        Some(s) => out.push(s.to_string()),
                        None => {
                            let kind = crate::utils::json_type_name(v);
                            return mcp_error(
                                req_id,
                                -32602,
                                &format!("capabilities[{i}] must be a string, got {kind}"),
                            );
                        }
                    }
                }
                Some(out)
            }
            None => None,
        };

    // Update intent and capabilities if provided
    if intent.is_some() || capabilities.is_some() {
        let _ = state
            .workflow_repo
            .update_workflow_intent_and_capabilities(
                workflow_id,
                user_id,
                intent.as_ref(),
                capabilities.as_deref(),
            )
            .await;
    }

    // Build a narrow policy hook so the version service can evaluate
    // actor_approval_policies inside its transaction without
    // depending on actor_policies directly.
    let policy_hook = talos_actor_policies::PublishVersionPolicyHook {
        evaluator: state.policy_evaluator.clone(),
    };
    let publish_result: Result<_, anyhow::Error> =
        talos_workflow_versions::WorkflowVersionService::publish_version_with_policy(
            &state.db_pool,
            workflow_id,
            user_id,
            description,
            Some(&state.workflow_repo),
            Some(&policy_hook),
        )
        .await;
    match publish_result {
        Ok(talos_workflow_versions::PublishOutcome::Blocked {
            policy_id,
            gate_id,
            approve_url,
            reject_url,
            trigger_label,
            approvers,
            reason,
        }) => {
            // Surface the block as a structured MCP error. The caller
            // must share approve_url with an approver, then retry
            // publish_version once the gate resolves. The gate itself
            // persists across the rolled-back publish tx (it was
            // inserted via the AdvancedRepository pool, not the tx).
            // reject_url is surfaced in the hint so the caller can
            // share a decline path with the same approver.
            let hint = format!(
                "{reason}. Approve at {approve_url} (or reject at {reject_url}) and retry publish_version. \
                 (policy_id: {policy_id}, gate_id: {gate_id}, trigger: {trigger_label}, \
                  approvers: {})",
                approvers.join(", ")
            );
            mcp_error(req_id, -32000, &hint)
        }
        Ok(talos_workflow_versions::PublishOutcome::Published {
            version,
            warnings: validation_warnings,
        }) => {
            // Move workflow to 'active' status now that it has a published version
            let _ = state
                .workflow_repo
                .set_workflow_status(workflow_id, user_id, "active")
                .await;
            // Spawn best-effort search text update
            let db_pool = state.db_pool.clone();
            tokio::spawn(async move {
                crate::utils::update_workflow_search_text(&db_pool, workflow_id, user_id).await;
            });
            // Spawn best-effort embedding update
            let db2 = state.db_pool.clone();
            tokio::spawn(async move {
                crate::search::auto_embed_workflow(workflow_id, user_id, &db2).await;
            });
            let wf_id_str = workflow_id.to_string();
            let warn_messages: Vec<String> = validation_warnings
                .iter()
                .map(|w: &talos_workflow_validation::ValidationIssue| w.message.clone())
                .collect();
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&serde_json::json!({
                    "version_id": version.id,
                    "version_number": version.version_number,
                    "published_at": version.published_at.to_rfc3339(),
                    "is_active": version.is_active,
                    "validation_warnings": warn_messages,
                    "next_steps_checklist": [
                        {
                            "step": 1,
                            "action": "Activate and deploy",
                            "tool": "deploy_workflow",
                            "args": { "workflow_id": &wf_id_str },
                            "note": "Makes this version the live version. Pass cron_expression to also set a schedule.",
                        },
                        {
                            "step": 2,
                            "action": "Test the published version",
                            "tool": "test_workflow",
                            "args": { "workflow_id": &wf_id_str, "assert_status": "completed" },
                            "note": "Runs synchronously against this version and validates output before going live.",
                        },
                    ],
                }))
                .unwrap_or_default(),
            )
        }
        Err(e) => {
            let err_str = e.to_string();
            if err_str.contains("Workflow validation failed") {
                // Surface validation errors directly to the caller
                tracing::warn!(workflow_id = %workflow_id, "publish_version blocked by validation: {}", err_str);
                mcp_error(req_id, -32000, &err_str)
            } else {
                tracing::error!(err = ?e, workflow_id = %workflow_id, "publish_version failed");
                mcp_error(req_id, -32000, "Failed to publish version")
            }
        }
    }
}

async fn handle_list_versions(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let workflow_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // Verify ownership
    let wf_exists: bool = state
        .workflow_repo
        .workflow_exists(workflow_id, user_id)
        .await;

    if !wf_exists {
        return crate::utils::workflow_not_found_error(req_id);
    }

    match talos_workflow_versions::WorkflowVersionService::list_versions(
        &state.db_pool,
        workflow_id,
        50,
        0,
    )
    .await
    {
        Ok(versions) => {
            let items: Vec<serde_json::Value> = versions
                .iter()
                .map(|v| {
                    serde_json::json!({
                        "version_number": v.version_number,
                        "description": v.description,
                        "published_at": v.published_at.to_rfc3339(),
                        "is_active": v.is_active,
                    })
                })
                .collect();
            // MCP-48 (2026-05-07): structured envelope (count + items +
            // workflow_id) — matches list_workflow_versions_with_diff so
            // callers can swap between the two without reshaping
            // their parser.
            let envelope = serde_json::json!({
                "workflow_id": workflow_id.to_string(),
                "count": items.len(),
                "versions": items,
            });
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&envelope).unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!(err = ?e, workflow_id = %workflow_id, "list_versions failed");
            mcp_error(req_id, -32000, "Failed to list versions")
        }
    }
}

async fn handle_rollback_workflow(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let workflow_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    // MCP-206 (2026-05-08): version_number is 1-indexed; pre-fix
    // accepted 0, negative, or i32::MAX-overflowing values (silent
    // `as i32` truncation), then surfaced "Version N not found" from
    // the DB miss — masking malformed input as a real lookup gap.
    let version_number =
        match crate::utils::require_int_range_i32(args, "version_number", 1, i32::MAX, &req_id) {
            Ok(n) => n,
            Err(resp) => return resp,
        };

    // MCP-206: check workflow ownership upfront so a non-existent or
    // unauthorised workflow returns "Workflow not found" instead of the
    // misleading "Version N not found" (matches diff_versions, list_versions,
    // and get_version_diff_summary which already do this).
    if !state
        .workflow_repo
        .workflow_exists(workflow_id, user_id)
        .await
    {
        return crate::utils::workflow_not_found_error(req_id);
    }

    // Look up the target version's graph_json. MCP-206: surface DB
    // errors loudly instead of `unwrap_or(None)` — same swallowed-error
    // anti-pattern as MCP-188 (get_schedule_health).
    let (version_id, graph_json) = match state
        .workflow_repo
        .get_version_by_number(workflow_id, version_number, user_id)
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => {
            return mcp_error(
                req_id,
                -32000,
                &format!("Version {} not found", version_number),
            )
        }
        Err(e) => {
            tracing::error!(err = ?e, workflow_id = %workflow_id, version_number, "rollback_workflow version lookup failed");
            return crate::utils::database_error(req_id);
        }
    };

    // MCP-1226 (2026-05-18): mirror the `save_graph_json` chokepoint
    // for non-graph.rs write paths. A legacy version snapshot
    // recorded before the per-node / per-loop / per-retry caps were
    // enforced may still carry over-cap values; surface them at the
    // rollback boundary so the operator notices and edits before
    // pinning the legacy snapshot as the new active draft. Without
    // this check `rollback_workflow` would happily restore an
    // unbounded retry_count / timeout / loop count.
    if let Err(resp) = crate::utils::ensure_graph_within_caps(&graph_json, &req_id) {
        return resp;
    }

    // Update the draft graph_json
    if let Err(e) = state
        .workflow_repo
        .update_workflow_graph_json(workflow_id, user_id, &graph_json)
        .await
    {
        tracing::error!(workflow_id = %workflow_id, "rollback_workflow update failed: {:#}", e);
        return mcp_error(req_id, -32000, "Failed to rollback workflow draft");
    }

    // Create a new active version from the rolled-back state
    match talos_workflow_versions::WorkflowVersionService::rollback_to_version(
        &state.db_pool,
        workflow_id,
        version_id,
        user_id,
    )
    .await
    {
        Ok(new_version) => mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "rolled_back_to_version": version_number,
                "new_version_number": new_version.version_number,
                "new_version_id": new_version.id,
                "published_at": new_version.published_at.to_rfc3339(),
            }))
            .unwrap_or_default(),
        ),
        Err(e) => {
            tracing::error!(err = ?e, workflow_id = %workflow_id, "rollback_to_version failed");
            mcp_error(req_id, -32000, "Rollback failed")
        }
    }
}

async fn handle_diff_versions(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let workflow_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    // MCP-206 (2026-05-08): version_a/version_b are 1-indexed.
    // Pre-fix `as i32` accepted -1, 0, and i64-overflowing values
    // and the DB miss masked them as "Version N not found".
    let version_a =
        match crate::utils::require_int_range_i32(args, "version_a", 1, i32::MAX, &req_id) {
            Ok(n) => n,
            Err(resp) => return resp,
        };
    let version_b =
        match crate::utils::require_int_range_i32(args, "version_b", 1, i32::MAX, &req_id) {
            Ok(n) => n,
            Err(resp) => return resp,
        };

    // Verify workflow ownership
    let wf_exists: bool = state
        .workflow_repo
        .workflow_exists(workflow_id, user_id)
        .await;

    if !wf_exists {
        return crate::utils::workflow_not_found_error(req_id);
    }

    // Fetch version A graph_json. MCP-206: surface DB errors loudly
    // instead of `unwrap_or(None)` (same swallowed-error class as
    // MCP-188 / get_schedule_health).
    let graph_a_str = match state
        .workflow_repo
        .get_version_graph_text_by_number(workflow_id, version_a, user_id)
        .await
    {
        Ok(Some(g)) => g,
        Ok(None) => return mcp_error(req_id, -32000, &format!("Version {} not found", version_a)),
        Err(e) => {
            tracing::error!(err = ?e, workflow_id = %workflow_id, version_a, "diff_versions version_a lookup failed");
            return crate::utils::database_error(req_id);
        }
    };

    // Fetch version B graph_json
    let graph_b_str = match state
        .workflow_repo
        .get_version_graph_text_by_number(workflow_id, version_b, user_id)
        .await
    {
        Ok(Some(g)) => g,
        Ok(None) => return mcp_error(req_id, -32000, &format!("Version {} not found", version_b)),
        Err(e) => {
            tracing::error!(err = ?e, workflow_id = %workflow_id, version_b, "diff_versions version_b lookup failed");
            return crate::utils::database_error(req_id);
        }
    };

    let graph_a: serde_json::Value =
        serde_json::from_str(&graph_a_str).unwrap_or(serde_json::json!({"nodes":[],"edges":[]}));
    let graph_b: serde_json::Value =
        serde_json::from_str(&graph_b_str).unwrap_or(serde_json::json!({"nodes":[],"edges":[]}));

    let nodes_a = graph_a
        .get("nodes")
        .and_then(|n| n.as_array())
        .cloned()
        .unwrap_or_default();
    let nodes_b = graph_b
        .get("nodes")
        .and_then(|n| n.as_array())
        .cloned()
        .unwrap_or_default();
    let edges_a = graph_a
        .get("edges")
        .and_then(|e| e.as_array())
        .cloned()
        .unwrap_or_default();
    let edges_b = graph_b
        .get("edges")
        .and_then(|e| e.as_array())
        .cloned()
        .unwrap_or_default();

    // Build node maps by ID
    let nodes_a_map: std::collections::HashMap<String, &serde_json::Value> = nodes_a
        .iter()
        .filter_map(|n| {
            n.get("id")
                .and_then(|v| v.as_str())
                .map(|id| (id.to_string(), n))
        })
        .collect();
    let nodes_b_map: std::collections::HashMap<String, &serde_json::Value> = nodes_b
        .iter()
        .filter_map(|n| {
            n.get("id")
                .and_then(|v| v.as_str())
                .map(|id| (id.to_string(), n))
        })
        .collect();

    let mut added_nodes: Vec<String> = Vec::new();
    let mut removed_nodes: Vec<String> = Vec::new();
    let mut changed_nodes: Vec<serde_json::Value> = Vec::new();

    // Added nodes: in B but not in A
    for id in nodes_b_map.keys() {
        if !nodes_a_map.contains_key(id) {
            added_nodes.push(id.clone());
        }
    }

    // Removed nodes: in A but not in B
    for id in nodes_a_map.keys() {
        if !nodes_b_map.contains_key(id) {
            removed_nodes.push(id.clone());
        }
    }

    // Changed nodes: in both but with different type or data
    for (id, node_a) in &nodes_a_map {
        if let Some(node_b) = nodes_b_map.get(id) {
            let type_a = node_a.get("type");
            let type_b = node_b.get("type");
            let data_a = node_a.get("data");
            let data_b = node_b.get("data");
            if type_a != type_b || data_a != data_b {
                let mut change = serde_json::json!({ "node_id": id });
                if type_a != type_b {
                    if let Some(obj) = change.as_object_mut() {
                        obj.insert(
                            "module_changed".to_string(),
                            serde_json::json!({
                                "from": type_a,
                                "to": type_b,
                            }),
                        );
                    }
                }
                if data_a != data_b {
                    if let Some(obj) = change.as_object_mut() {
                        obj.insert("config_changed".to_string(), serde_json::json!(true));
                    }
                }
                changed_nodes.push(change);
            }
        }
    }

    // Edge comparison by source+target key
    let edge_key = |e: &serde_json::Value| -> String {
        let src = e.get("source").and_then(|v| v.as_str()).unwrap_or("");
        let tgt = e.get("target").and_then(|v| v.as_str()).unwrap_or("");
        format!("{}->{}", src, tgt)
    };

    let edges_a_set: std::collections::HashSet<String> = edges_a.iter().map(&edge_key).collect();
    let edges_b_set: std::collections::HashSet<String> = edges_b.iter().map(edge_key).collect();

    let added_edges: Vec<&String> = edges_b_set.difference(&edges_a_set).collect();
    let removed_edges: Vec<&String> = edges_a_set.difference(&edges_b_set).collect();

    let diff = serde_json::json!({
        "workflow_id": workflow_id,
        "version_a": version_a,
        "version_b": version_b,
        "added_nodes": added_nodes,
        "removed_nodes": removed_nodes,
        "changed_nodes": changed_nodes,
        "added_edges": added_edges,
        "removed_edges": removed_edges,
    });

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&diff).unwrap_or_default(),
    )
}

async fn handle_get_version_diff_summary(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // Get draft graph
    let draft_json = match state
        .workflow_repo
        .get_workflow_graph_for_similarity(wf_id, user_id)
        .await
        .unwrap_or(None)
    {
        Some(g) => g,
        None => return mcp_error(req_id, -32000, "Workflow not found or access denied"),
    };

    // Get active published version
    let published_json = match state
        .workflow_repo
        .get_active_version_graph_text(wf_id)
        .await
        .unwrap_or(None)
    {
        Some(p) => p,
        None => {
            // Return a structured envelope mirroring the populated branch's
            // diff shape so callers don't have to type-test the response.
            let result = serde_json::json!({
                "diff": null,
                "note": "No published version — all changes are new",
            });
            return mcp_text(
                req_id,
                &serde_json::to_string_pretty(&result).unwrap_or_default(),
            );
        }
    };

    let diff = compute_mcp_graph_diff(&published_json, &draft_json);
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&diff).unwrap_or_default(),
    )
}

async fn handle_list_workflow_versions_with_diff(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let workflow_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let limit = match crate::utils::validate_range_i64(args, "limit", 1, 100, 20, &req_id) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // Verify ownership
    let wf_exists: bool = state
        .workflow_repo
        .workflow_exists(workflow_id, user_id)
        .await;

    if !wf_exists {
        return crate::utils::workflow_not_found_error(req_id);
    }

    match talos_workflow_versions::WorkflowVersionService::list_versions(
        &state.db_pool,
        workflow_id,
        limit,
        0,
    )
    .await
    {
        Ok(versions) => {
            let mut result_versions: Vec<serde_json::Value> = Vec::new();

            for (i, version) in versions.iter().enumerate() {
                let changes = if i < versions.len() - 1 {
                    // Compare this version with the next one (which is the predecessor since ordered DESC)
                    let predecessor = &versions[i + 1];
                    let graph_a_str =
                        serde_json::to_string(&predecessor.graph_json).unwrap_or_default();
                    let graph_b_str =
                        serde_json::to_string(&version.graph_json).unwrap_or_default();
                    compute_mcp_graph_diff(&graph_a_str, &graph_b_str)
                } else {
                    // First version ever
                    serde_json::json!({ "summary": "Initial version" })
                };

                result_versions.push(serde_json::json!({
                    "version_number": version.version_number,
                    "description": version.description,
                    "published_at": version.published_at.to_rfc3339(),
                    "is_active": version.is_active,
                    "changes": changes,
                }));
            }

            // MCP-81 (2026-05-07): emit canonical `count` field for envelope
            // consistency with sibling list tools (post-MCP-45 sweep).
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&serde_json::json!({
                    "workflow_id": workflow_id.to_string(),
                    "count": result_versions.len(),
                    "versions": result_versions,
                }))
                .unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!(err = ?e, workflow_id = %workflow_id, "list_workflow_versions_with_diff failed");
            mcp_error(req_id, -32000, "Failed to list versions")
        }
    }
}
