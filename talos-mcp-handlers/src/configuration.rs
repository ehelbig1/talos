use super::types::JsonRpcResponse;
use super::utils::{mcp_error, mcp_text, update_workflow_search_text};
use super::{auth, McpState};
use std::sync::Arc;
use uuid::Uuid;

pub async fn dispatch(
    name: &str,
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> Option<JsonRpcResponse> {
    let user_id = agent.user_id.unwrap_or_else(uuid::Uuid::nil);
    match name {
        "describe_capability_world" => Some(handle_describe_capability_world(req_id, args).await),
        "test_condition" => Some(handle_test_condition(req_id, args).await),
        "get_workflow_graph" => Some(handle_get_workflow_graph(req_id, args, state, user_id).await),
        "set_workflow_priority" => {
            Some(handle_set_workflow_priority(req_id, args, state, user_id).await)
        }
        "get_workflow_input_schema" => {
            Some(handle_get_workflow_input_schema(req_id, args, state, user_id).await)
        }
        "set_workflow_intent" => {
            Some(handle_set_workflow_intent(req_id, args, state, user_id).await)
        }
        "get_session_context" => {
            Some(handle_get_session_context(req_id, args, state, user_id).await)
        }
        "get_workflow_identity" => {
            Some(handle_get_workflow_identity(req_id, args, state, user_id).await)
        }
        _ => None,
    }
}

/// MCP-71: turn the prose-as-key inheritance markers used in `schemas.rs`
/// (e.g. `"all http + secrets + llm interfaces"`) into a structured
/// `inherits_from_worlds: ["http", "secrets", "llm"]` array on the
/// response. Removes the placeholder keys from `interfaces` so callers
/// can iterate that map cleanly. Idempotent: a world without any
/// placeholders gets no `inherits_from_worlds` field added.
fn promote_inherited_world_keys(world_value: &mut serde_json::Value) {
    let interfaces = match world_value.get_mut("interfaces").and_then(|v| v.as_object_mut()) {
        Some(m) => m,
        None => return,
    };

    // Collect placeholder keys + the worlds they reference, then delete.
    let mut inherits: Vec<String> = Vec::new();
    let mut to_remove: Vec<String> = Vec::new();
    for (key, _) in interfaces.iter() {
        // Match patterns of the form "all <words> interfaces", with
        // " + " or " " separating the inherited world names.
        let stripped = key
            .strip_prefix("all ")
            .and_then(|rest| rest.strip_suffix(" interfaces"));
        if let Some(inner) = stripped {
            for tok in inner.split('+') {
                let name = tok.trim();
                if !name.is_empty() && !inherits.iter().any(|i| i == name) {
                    inherits.push(name.to_string());
                }
            }
            to_remove.push(key.clone());
        }
    }
    for k in to_remove {
        interfaces.remove(&k);
    }

    if !inherits.is_empty() {
        if let Some(map) = world_value.as_object_mut() {
            map.insert(
                "inherits_from_worlds".to_string(),
                serde_json::Value::Array(
                    inherits
                        .into_iter()
                        .map(serde_json::Value::String)
                        .collect(),
                ),
            );
        }
    }
}

async fn handle_describe_capability_world(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
) -> JsonRpcResponse {
    let world = args
        .get("capability_world")
        .or_else(|| args.get("world")) // legacy alias
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let worlds = super::schemas::capability_worlds();
    let complex_examples = super::schemas::complex_examples();
    let fuel_cost_guidance = super::schemas::fuel_cost_guidance();

    // Normalize the world name (strip -node suffix if present)
    let normalized = talos_capability_world::world_short(world);

    // Special case: `llm-node` is an actor capability ceiling, NOT a
    // compile world (per `talos-capability-world::lib.rs:312-318`).
    // Modules requesting LLM access compile against `secrets` (which
    // includes the `llm` WIT interface). Returning a generic "Unknown
    // world" message left callers grepping the available list and
    // missing the actual answer; this branch surfaces the rule
    // directly. Same special-case for `llm` short form.
    if normalized == "llm" {
        return mcp_error(
            req_id,
            -32602,
            "'llm-node' is an actor capability ceiling, not a compile world. \
             Modules that need LLM access compile against the 'secrets' world \
             (capability_world: 'secrets-node'), which includes the llm WIT \
             interface. Set the actor's max_llm_tier to 'tier1' or 'tier2' to \
             control external-vs-local LLM provider access; do not pass \
             'llm-node' to compile_custom_sandbox / hot_update_module / \
             create_workflow node configs.",
        );
    }

    match worlds.get(normalized) {
        Some(desc) => {
            let mut enriched = desc.clone();
            if let Some(examples) = complex_examples.get(normalized) {
                enriched["complex_examples"] = examples.clone();
            }
            if let Some(costs) = fuel_cost_guidance.get(normalized) {
                enriched["fuel_cost_guidance"] = costs.clone();
            }
            // MCP-71 (2026-05-07): rewrite the prose-as-key
            // "all <X> interfaces" placeholders into a structured
            // `inherits_from_worlds: [...]` array. Pre-fix, callers had
            // to substring-match keys like "all http + secrets + llm
            // interfaces" to know what was inherited. The map below
            // covers the canonical strings used in schemas.rs.
            promote_inherited_world_keys(&mut enriched);
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&enriched).unwrap_or_default(),
            )
        }
        None => {
            let available: Vec<&str> = worlds
                .as_object()
                .map(|m| m.keys().map(|k| k.as_str()).filter(|k| !k.starts_with('_')).collect())
                .unwrap_or_default();
            mcp_error(
                req_id,
                -32602,
                &format!(
                    "Unknown world '{}'. Available compile worlds: {:?}. \
                     Note: 'llm-node' and 'network-node' are actor-level capability \
                     ceilings, not compile worlds — modules requesting LLM access \
                     compile against 'secrets-node' (includes the llm interface).",
                    world, available
                ),
            )
        }
    }
}

async fn handle_test_condition(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
) -> JsonRpcResponse {
    // MCP-208 (2026-05-08): pre-fix accepted whitespace-only conditions
    // (`"   "`), passed them to Rhai which returned the confusing
    // "Output type incorrect: () (expecting bool)" error attributed to
    // the caller's expression. Reject whitespace-only at the boundary
    // so the caller gets a clear "non-empty / non-whitespace" message.
    let condition = match args.get("condition").and_then(|v| v.as_str()) {
        Some(c) if c.len() > 2000 => {
            return mcp_error(req_id, -32602, "condition must be ≤ 2000 characters")
        }
        Some(c) if c.trim().is_empty() => {
            return mcp_error(
                req_id,
                -32602,
                "condition must be non-empty and non-whitespace",
            )
        }
        Some(c) => c,
        _ => return mcp_error(req_id, -32602, "Missing or empty 'condition' parameter"),
    };
    let payload = args
        .get("payload")
        .cloned()
        .unwrap_or(serde_json::json!({}));
    if serde_json::to_string(&payload)
        .map(|s| s.len())
        .unwrap_or(0)
        > 1_048_576
    {
        return mcp_error(req_id, -32602, "payload exceeds 1 MB limit");
    }

    // Use the Rhai engine directly to get error details
    let eval_result =
        talos_engine::rhai_helpers::evaluate_condition_with_error(condition, &payload);
    match eval_result {
        Ok(result) => mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "result": result,
                "error": serde_json::Value::Null
            }))
            .unwrap_or_default(),
        ),
        Err(e) => mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "result": serde_json::Value::Null,
                "error": e
            }))
            .unwrap_or_default(),
        ),
    }
}

async fn handle_get_workflow_graph(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // MCP-416 (2026-05-11): sibling fix to MCP-415. Pre-fix
    // `.unwrap_or_else(|e| { warn!; None })` swallowed DB errors
    // into the same None branch as a legitimately-missing workflow,
    // returning "workflow not found" for both. Surface DB-error
    // class loudly with database_error helper.
    let (wf_name, graph_json_str) = match state
        .workflow_repo
        .get_workflow_name_and_graph(wf_id, user_id)
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return mcp_error(req_id, -32000, "Workflow not found or access denied"),
        Err(e) => {
            tracing::error!(workflow_id = %wf_id, error = %e, "get_session_context: workflow lookup failed");
            return crate::utils::database_error(req_id);
        }
    };

    let graph: serde_json::Value =
        serde_json::from_str(&graph_json_str).unwrap_or(serde_json::json!({"nodes":[],"edges":[]}));

    // Batch-fetch module names and capability worlds for all nodes
    let module_ids: Vec<uuid::Uuid> = graph
        .get("nodes")
        .and_then(|n| n.as_array())
        .map(|nodes| {
            nodes
                .iter()
                .filter_map(|n| {
                    n.get("type")
                        .and_then(|v| v.as_str())
                        .and_then(|s| s.parse().ok())
                })
                .collect()
        })
        .unwrap_or_default();

    let module_names: std::collections::HashMap<uuid::Uuid, String> = if !module_ids.is_empty() {
        let tmpl_rows = state
            .module_repo
            .list_template_names_by_ids(&module_ids)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "DB error fetching template names");
                vec![]
            });
        let mod_rows = state
            .workflow_repo
            .list_wasm_module_names_by_ids_unscoped(&module_ids)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "DB error fetching module names");
                vec![]
            });
        tmpl_rows.into_iter().chain(mod_rows).collect()
    } else {
        std::collections::HashMap::new()
    };

    let module_worlds: std::collections::HashMap<uuid::Uuid, String> = if !module_ids.is_empty() {
        let world_rows = state
            .module_repo
            .list_template_world_overrides(&module_ids)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "DB error fetching module worlds");
                vec![]
            });

        // Also check wasm_modules directly by id for non-template modules
        let direct_world_rows = state
            .workflow_repo
            .list_wasm_module_worlds_by_ids(&module_ids)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "DB error fetching direct module worlds");
                vec![]
            });

        world_rows.into_iter().chain(direct_world_rows).collect()
    } else {
        std::collections::HashMap::new()
    };

    // Build node label map: node_id -> display label
    let nodes = graph.get("nodes").and_then(|n| n.as_array());
    let mut node_labels: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    let mut node_lines = Vec::new();

    if let Some(nodes) = nodes {
        for n in nodes {
            let node_id = n.get("id").and_then(|v| v.as_str()).unwrap_or("?");
            let type_str = n.get("type").and_then(|v| v.as_str()).unwrap_or("");
            let module_uuid: Option<uuid::Uuid> = type_str.parse().ok();

            let label = if type_str.starts_with("system:") {
                // System node — show kind and sub-workflow name if available
                let kind = n.get("kind").and_then(|v| v.as_str()).unwrap_or("system");
                if kind == "sub_workflow" {
                    let sub_id = n
                        .get("data")
                        .and_then(|d| d.get("sub_workflow_id"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("?");
                    // Try to resolve sub-workflow name
                    let sub_name = if let Ok(uid) = sub_id.parse::<uuid::Uuid>() {
                        state
                            .workflow_repo
                            .get_workflow_name_by_id(uid)
                            .await
                            .unwrap_or_else(|e| {
                                tracing::warn!(error = %e, "DB error resolving sub-workflow name");
                                None
                            })
                            .unwrap_or_else(|| sub_id.to_string())
                    } else {
                        sub_id.to_string()
                    };
                    format!("{} (-> {}) [sub_workflow]", node_id, sub_name)
                } else if kind == "loop" {
                    // Enhanced loop node label: show body_node_id, condition, and max_iterations
                    let data = n.get("data");
                    let body_node = data
                        .and_then(|d| d.get("body_node_id"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("?");
                    let condition = data
                        .and_then(|d| d.get("condition"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("true");
                    let max_iter = data
                        .and_then(|d| d.get("max_iterations"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or(10);
                    format!(
                        "{} (-> {} while: {}) [loop, max: {}]",
                        node_id, body_node, condition, max_iter
                    )
                } else if kind == "capability_dispatch" {
                    let data = n.get("data");
                    let caps: Vec<String> = data
                        .and_then(|d| d.get("required_capabilities"))
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                .collect()
                        })
                        .unwrap_or_default();
                    format!(
                        "{} (-> best match for [{}]) [capability_dispatch]",
                        node_id,
                        caps.join(", ")
                    )
                } else {
                    format!("{} [{}]", node_id, kind)
                }
            } else {
                let module_name = module_uuid
                    .and_then(|uid| module_names.get(&uid))
                    .map(|s| s.as_str())
                    .unwrap_or("unknown");
                let world = module_uuid
                    .and_then(|uid| module_worlds.get(&uid))
                    .map(|s| s.as_str())
                    .unwrap_or("unknown");
                format!("{} ({}) [{}]", node_id, module_name, world)
            };
            node_labels.insert(node_id.to_string(), label.clone());
            node_lines.push(format!("  {}", label));
        }
    }

    // Build edge lines
    let edges = graph.get("edges").and_then(|e| e.as_array());
    let mut edge_lines = Vec::new();
    if let Some(edges) = edges {
        for e in edges {
            let src = e.get("source").and_then(|v| v.as_str()).unwrap_or("?");
            let tgt = e.get("target").and_then(|v| v.as_str()).unwrap_or("?");
            let edge_type = e
                .get("edge_type")
                .and_then(|v| v.as_str())
                .unwrap_or("default");
            let condition = e.get("condition").and_then(|v| v.as_str());

            let src_label = node_labels.get(src).map(|s| s.as_str()).unwrap_or(src);
            let tgt_label = node_labels.get(tgt).map(|s| s.as_str()).unwrap_or(tgt);

            let annotation = if let Some(cond) = condition {
                format!(" [{}:{}]", edge_type, cond)
            } else if edge_type != "default" {
                format!(" [{}]", edge_type)
            } else {
                String::new()
            };

            edge_lines.push(format!("  {} -> {}{}", src_label, tgt_label, annotation));
        }
    }

    let node_count = nodes.map(|n| n.len()).unwrap_or(0);
    let edge_count = edges.map(|e| e.len()).unwrap_or(0);

    let mut output = format!(
        "Workflow: {} ({})\nNodes: {}  Edges: {}\n",
        wf_name, wf_id, node_count, edge_count
    );
    output.push_str("\n--- Nodes ---\n");
    if node_lines.is_empty() {
        output.push_str("  (none)\n");
    } else {
        for line in &node_lines {
            output.push_str(line);
            output.push('\n');
        }
    }
    output.push_str("\n--- Edges ---\n");
    if edge_lines.is_empty() {
        output.push_str("  (none)\n");
    } else {
        for line in &edge_lines {
            output.push_str(line);
            output.push('\n');
        }
    }

    let ascii = super::workflows::render_ascii_graph(&graph_json_str);
    if !ascii.is_empty() {
        output.push_str("\n--- Graph ---\n");
        output.push_str(&ascii);
        output.push('\n');
    }

    mcp_text(req_id, &output)
}

async fn handle_set_workflow_priority(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    // MCP-361 (2026-05-11): pre-fix `.and_then(|v| v.as_str())` collapsed
    // wrong-type AND absent into the same None branch → "Missing required
    // 'priority' parameter". Operator passing `priority: 1` (number,
    // expecting positional priority) silently got told the field was
    // missing. Same diagnostic-distinction class as MCP-358 / MCP-360.
    let priority = match args.get("priority") {
        None => return mcp_error(req_id, -32602, "Missing required 'priority' parameter"),
        Some(v) => match v.as_str() {
            Some(p) if p == "high" || p == "normal" || p == "low" => p.to_string(),
            Some(other) => {
                return mcp_error(
                    req_id,
                    -32602,
                    &format!(
                        "priority must be 'high', 'normal', or 'low', got '{}'",
                        talos_text_util::bounded_preview(other, 64)
                    ),
                )
            }
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!(
                        "priority must be a string ('high', 'normal', or 'low'), got {kind}"
                    ),
                );
            }
        },
    };

    // MCP-415 (2026-05-11): distinguish DB error from not-found.
    // Pre-fix `.unwrap_or_else(|e| { warn!; None })` swallowed DB
    // errors into the same None branch as a legitimately-missing
    // workflow, returning "workflow not found" for both. Operator
    // saw a confident not-found error during a real DB outage. The
    // WARN log was emitted but the API caller — typically scripting
    // the next step on that response — had no way to distinguish
    // "your workflow doesn't exist" from "the database hiccupped,
    // retry". Surface the error class loudly. Same swallowed-error
    // anti-pattern as MCP-188 (get_schedule_health).
    let gj = match state
        .workflow_repo
        .get_workflow_graph_for_similarity(wf_id, user_id)
        .await
    {
        Ok(Some(g)) => g,
        Ok(None) => return crate::utils::workflow_not_found_error(req_id),
        Err(e) => {
            tracing::error!(workflow_id = %wf_id, error = %e, "set_workflow_priority: graph fetch failed");
            return crate::utils::database_error(req_id);
        }
    };

    let mut graph: serde_json::Value = serde_json::from_str(&gj).unwrap_or(serde_json::json!({}));
    if let Some(obj) = graph.as_object_mut() {
        obj.insert("priority".to_string(), serde_json::json!(priority));
    }
    let updated = graph.to_string();
    // MCP-1226 (2026-05-18): mirror the `save_graph_json` chokepoint
    // for non-graph.rs write paths. `set_workflow_priority` loads
    // the existing graph, stamps a top-level `priority` key, and
    // writes the whole thing back via `update_workflow_graph_json`
    // — bypassing the `save_graph_json` validator. If the workflow
    // already has over-cap timeouts (e.g. from a legacy create
    // before the caps were added) this surfaces them at the next
    // priority edit instead of letting them linger.
    if let Err(resp) = crate::utils::ensure_graph_within_caps(&updated, &req_id) {
        return resp;
    }
    match state
        .workflow_repo
        .update_workflow_graph_json(wf_id, user_id, &updated)
        .await
    {
        Ok(_) => mcp_text(req_id, &format!(
            "Workflow {} priority set to '{}'.\nNew executions will be dispatched with this priority.",
            wf_id, priority
        )),
        Err(e) => {
            tracing::error!(workflow_id = %wf_id, "set_workflow_priority update failed: {:#}", e);
            mcp_error(req_id, -32000, "Failed to save workflow priority")
        }
    }
}

async fn handle_get_workflow_input_schema(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // MCP-416 (2026-05-11): sibling fix to MCP-415. Surface DB-error
    // class loudly instead of masquerading as not-found.
    match state
        .workflow_repo
        .get_workflow_name_for_user(wf_id, user_id)
        .await
    {
        Ok(Some(_)) => {}
        Ok(None) => return crate::utils::workflow_not_found_error(req_id),
        Err(e) => {
            tracing::error!(workflow_id = %wf_id, error = %e, "schema_inference: workflow lookup failed");
            return crate::utils::database_error(req_id);
        }
    }

    // Load last 10 successful executions' output_data (which contains __trigger_input__).
    // Also fetch the wider total successful count so the response can surface
    // the gap (executions with no output_data we could analyse) — see MCP-16.
    let (rows, total_completed) = tokio::join!(
        state
            .workflow_repo
            .list_recent_completed_outputs(wf_id, user_id, 10),
        state.workflow_repo.count_completed_executions(wf_id, user_id),
    );
    let rows = rows.unwrap_or_default();
    let total_completed = total_completed.unwrap_or(0);

    if rows.is_empty() {
        return mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "error": "No successful executions with input data found. Cannot infer schema.",
                "total_successful_executions": total_completed,
                "based_on_executions": 0,
                "note": if total_completed > 0 {
                    serde_json::json!(format!(
                        "{} successful execution(s) exist but none carry output_data with a __trigger_input__ field — likely all scheduler-fired (no trigger payload). Run via trigger_workflow / test_workflow / a webhook to seed an inferable example.",
                        total_completed
                    ))
                } else {
                    serde_json::json!("Trigger the workflow at least once via trigger_workflow / test_workflow / a webhook to seed an inferable example.")
                },
            }))
            .unwrap_or_default(),
        );
    }

    let mut key_types: std::collections::HashMap<String, std::collections::HashMap<String, usize>> =
        std::collections::HashMap::new();
    let mut key_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut sample_values: std::collections::HashMap<String, serde_json::Value> =
        std::collections::HashMap::new();
    let total_executions = rows.len();

    for output_data in &rows {
        if let Some(input_val) = output_data.get("__trigger_input__") {
            if let Some(obj) = input_val.as_object() {
                for (key, val) in obj {
                    // Skip internal keys
                    if key.starts_with("__") && key.ends_with("__") {
                        continue;
                    }
                    *key_counts.entry(key.clone()).or_insert(0) += 1;
                    let type_name = match val {
                        serde_json::Value::Null => "null",
                        serde_json::Value::Bool(_) => "boolean",
                        serde_json::Value::Number(_) => "number",
                        serde_json::Value::String(_) => "string",
                        serde_json::Value::Array(_) => "array",
                        serde_json::Value::Object(_) => "object",
                    };
                    *key_types
                        .entry(key.clone())
                        .or_default()
                        .entry(type_name.to_string())
                        .or_insert(0) += 1;
                    // Store first non-null sample
                    if !val.is_null() && !sample_values.contains_key(key) {
                        // Truncate long string values for sample display
                        let sample = match val {
                            serde_json::Value::String(s) if s.len() > 100 => {
                                serde_json::Value::String(format!(
                                    "{}...",
                                    talos_text_util::truncate_at_char_boundary(s, 100)
                                ))
                            }
                            _ => val.clone(),
                        };
                        sample_values.insert(key.clone(), sample);
                    }
                }
            }
        }
    }

    let mut properties = serde_json::Map::new();
    let mut required_keys: Vec<String> = Vec::new();

    for (key, count) in &key_counts {
        let types = key_types.get(key).cloned().unwrap_or_default();
        let dominant_type = types
            .iter()
            .filter(|(t, _)| t.as_str() != "null")
            .max_by_key(|(_, c)| *c)
            .map(|(t, _)| t.clone())
            .unwrap_or_else(|| "string".to_string());

        let is_required = *count == total_executions;
        if is_required {
            required_keys.push(key.clone());
        }

        properties.insert(
            key.clone(),
            serde_json::json!({
                "type": dominant_type,
                "required": is_required,
                "seen_in": format!("{}/{}", count, total_executions),
            }),
        );
    }

    let inferred_schema = serde_json::json!({
        "type": "object",
        "properties": properties,
        "required": required_keys,
    });

    // MCP-246 (2026-05-08): `confirm_inferred_schema: "true"` (string)
    // silently became false; caller asked for the schema to be applied
    // and got back schema_applied: false with no signal that the
    // confirmation was malformed. Same MCP-189 / MCP-245 family.
    let confirm = match crate::utils::validate_optional_bool(
        args,
        "confirm_inferred_schema",
        false,
        &req_id,
    ) {
        Ok(b) => b,
        Err(resp) => return resp,
    };

    let schema_applied = if confirm {
        match state
            .workflow_repo
            .set_workflow_input_schema(wf_id, user_id, &inferred_schema)
            .await
        {
            Ok(_) => true,
            Err(e) => {
                tracing::error!("Failed to save inferred schema: {:?}", e);
                return mcp_error(req_id, -32603, "Failed to save inferred schema");
            }
        }
    } else {
        false
    };

    // MCP-16: surface the gap between "successful executions overall" and
    // "executions we could analyse" so a small `based_on_executions` is
    // self-explanatory.
    let excluded_count = (total_completed - total_executions as i64).max(0);
    let mut result = serde_json::json!({
        "inferred_schema": inferred_schema,
        "sample_values": sample_values,
        "based_on_executions": total_executions,
        "total_successful_executions": total_completed,
        "excluded_count": excluded_count,
    });
    if excluded_count > 0 {
        result["excluded_note"] = serde_json::json!(format!(
            "{} successful execution(s) excluded — no output_data with __trigger_input__ (typically scheduler-fired runs without a trigger payload).",
            excluded_count
        ));
    }

    if confirm {
        result["schema_applied"] = serde_json::json!(schema_applied);
        result["note"] = serde_json::json!(
            "Schema has been saved to the workflow. It will be used to validate future trigger inputs."
        );
    }

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

async fn handle_set_workflow_intent(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    let intent = match args.get("intent") {
        Some(v) if v.is_object() => v,
        _ => return mcp_error(req_id, -32602, "Missing or invalid 'intent' object"),
    };
    // MCP-193 (2026-05-08): delegate intent shape + length + whitespace
    // validation to the shared helper so all three call sites
    // (create_workflow, set_workflow_intent, publish_version) enforce
    // identical rules. Pre-fix this handler had its own inline checks
    // that used `.unwrap_or("").is_empty()` (accepts whitespace) and
    // didn't validate output_type / trigger_context at all.
    if let Err(msg) = talos_workflow_creation_helpers::validate_intent(intent) {
        return mcp_error(req_id, -32602, &msg);
    }
    // Required-field check stays in the handler (the helper treats
    // every field as optional — `set_workflow_intent` is the only
    // caller that needs action + subject to be present).
    if intent.get("action").and_then(|v| v.as_str()).is_none() {
        return mcp_error(req_id, -32602, "Intent 'action' field is required");
    }
    if intent.get("subject").and_then(|v| v.as_str()).is_none() {
        return mcp_error(req_id, -32602, "Intent 'subject' field is required");
    }

    match state
        .workflow_repo
        .set_workflow_intent_field(wf_id, user_id, intent)
        .await
    {
        Ok(rows) if rows > 0 => {
            // Best-effort: update search_text
            let pool = state.db_pool.clone();
            let uid = user_id;
            tokio::spawn(async move {
                update_workflow_search_text(&pool, wf_id, uid).await;
            });
            mcp_text(
                req_id,
                &format!(
                    "Intent set on workflow {}:\n{}",
                    wf_id,
                    serde_json::to_string_pretty(intent).unwrap_or_default()
                ),
            )
        }
        Ok(_) => crate::utils::workflow_not_found_error(req_id),
        Err(e) => {
            tracing::error!(workflow_id = %wf_id, "set_workflow_intent failed: {:#}", e);
            mcp_error(req_id, -32000, "Failed to update intent")
        }
    }
}

async fn handle_get_session_context(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let limit = match crate::utils::validate_range_i64(args, "limit", 1, 20, 10, &req_id) {
        Ok(v) => v as i32,
        Err(resp) => return resp,
    };
    let task_description = args.get("task_description").and_then(|v| v.as_str());
    if let Some(task) = task_description {
        if task.len() > 500 {
            return mcp_error(req_id, -32602, "task_description must be ≤500 characters");
        }
    }

    // Top N by readiness_score
    let top_rows = state
        .workflow_repo
        .list_top_workflows_by_readiness(user_id, limit)
        .await
        .unwrap_or_default();

    // Top 5 most recently used
    let recent_rows = state
        .workflow_repo
        .list_recently_used_workflows(user_id, 5)
        .await
        .unwrap_or_default();

    let mut lines: Vec<String> = Vec::new();
    lines.push("=== Top Workflows ===".to_string());

    // Collect workflow IDs from top_rows for dedup
    let mut seen_ids: std::collections::HashSet<uuid::Uuid> = std::collections::HashSet::new();

    for r in &top_rows {
        // Infer input keys from graph
        let node_count = serde_json::from_str::<serde_json::Value>(&r.graph_json)
            .ok()
            .and_then(|g| g.get("nodes").and_then(|n| n.as_array()).map(|a| a.len()))
            .unwrap_or(0);

        let caps_str = if r.capabilities.is_empty() {
            "-".to_string()
        } else {
            r.capabilities.join(",")
        };
        lines.push(format!(
            "{} | {} | {} | readiness:{} | nodes:{}",
            r.id,
            r.name,
            caps_str,
            r.readiness_score.unwrap_or(0),
            node_count
        ));
        seen_ids.insert(r.id);
    }

    if !recent_rows.is_empty() {
        lines.push("=== Recently Used ===".to_string());
        for r in &recent_rows {
            if seen_ids.contains(&r.workflow_id) {
                continue;
            }
            let caps_str = if r.capabilities.is_empty() {
                "-".to_string()
            } else {
                r.capabilities.join(",")
            };
            lines.push(format!("{} | {} | {}", r.workflow_id, r.name, caps_str));
        }
    }

    // Keyword matching if task_description provided
    if let Some(task) = task_description {
        // MCP-474: escape PostgreSQL LIKE wildcards (`%` / `_` / `\`) in
        // user-supplied task tokens. Without escaping, a token like
        // "50%" or "_x" turns into a wildcard-bypass pattern that
        // matches every row in the user's namespace. Cross-tenant
        // isolation is intact (user_id scope at the SQL layer), but
        // within-namespace search-result manipulation is closed. Other
        // search paths in this codebase already route through
        // `talos_search_service::escape_like`; this site was the
        // single straggler.
        let words: Vec<String> = task
            .split_whitespace()
            .filter(|w| w.len() > 2)
            .map(|w| {
                format!(
                    "%{}%",
                    talos_search_service::escape_like(&w.to_lowercase())
                )
            })
            .collect();

        if !words.is_empty() {
            // Search with first word for simplicity (avoids complex dynamic SQL)
            let matched_rows = state
                .workflow_repo
                .match_workflows_by_keyword(user_id, &words[0], 5)
                .await
                .unwrap_or_default();

            if !matched_rows.is_empty() {
                lines.push(format!("=== Matched '{}' ===", task));
                for r in &matched_rows {
                    if seen_ids.contains(&r.workflow_id) {
                        continue;
                    }
                    let caps_str = if r.capabilities.is_empty() {
                        "-".to_string()
                    } else {
                        r.capabilities.join(",")
                    };
                    lines.push(format!("{} | {} | {}", r.workflow_id, r.name, caps_str));
                }
            }
        }
    }

    mcp_text(req_id, &lines.join("\n"))
}

async fn handle_get_workflow_identity(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    match state
        .workflow_repo
        .get_workflow_identity_row(wf_id, user_id)
        .await
    {
        Ok(Some(r)) => {
            // Count nodes
            let node_count = serde_json::from_str::<serde_json::Value>(&r.graph_json)
                .ok()
                .and_then(|g| g.get("nodes").and_then(|n| n.as_array()).map(|a| a.len()))
                .unwrap_or(0);

            let result = serde_json::json!({
                "id": wf_id,
                "name": r.name,
                "description": r.description,
                "capabilities": r.capabilities,
                "intent": r.intent,
                "input_schema": r.input_schema,
                "readiness_score": r.readiness_score,
                "readiness_computed_at": r.readiness_computed_at.map(|t| t.to_rfc3339()),
                "node_count": node_count,
                "_see_also": {
                    "inferred_input_schema": "Call get_workflow_input_schema(workflow_id) to derive an input shape from recent executions.",
                    "readiness_breakdown": "Call get_readiness_breakdown(workflow_id) for the per-component decomposition behind readiness_score.",
                    "output_structure": "Call get_node_output(execution_id, node_label) on a recent run to inspect actual output shape."
                }
            });

            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&result).unwrap_or_default(),
            )
        }
        Ok(None) => crate::utils::workflow_not_found_error(req_id),
        Err(e) => {
            tracing::error!(workflow_id = %wf_id, "get_workflow_identity failed: {:#}", e);
            mcp_error(req_id, -32000, "Failed to load workflow identity")
        }
    }
}
