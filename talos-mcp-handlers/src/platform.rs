use super::types::JsonRpcResponse;
use super::utils::{mcp_error, mcp_text};
use super::{auth, McpState};
use std::sync::Arc;
use uuid::Uuid;

pub fn tool_schemas() -> Vec<serde_json::Value> {
    let worlds_csv = crate::capability_worlds::compilable_worlds_csv();
    let worlds_enum: Vec<&str> = crate::capability_worlds::compilable_worlds().to_vec();
    vec![
        serde_json::json!({
            "name": "get_wasm_config",
            "description": "Get the current WASM runtime resource limits (memory, fuel, timeout, result caps).",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }),
        serde_json::json!({
            "name": "set_wasm_config",
            "description": "Set WASM runtime resource limits. These are advisory defaults stored in system_settings. \
                execution_timeout_secs is the default per-node timeout used when a node doesn't specify its own; \
                it is NOT a hard ceiling — individual node timeout_secs and workflow timeout_secs are honored \
                as-set and not clamped to this value. Raise per-node timeout_secs directly for LLM-bound or \
                HTTP-heavy nodes rather than bumping this global default.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "max_memory_mb": { "type": "number", "description": "Maximum WASM memory in MB (16-512, default: 128)" },
                    "max_fuel": { "type": "number", "description": "Maximum fuel units (100000-10000000, default: 10000000)" },
                    "execution_timeout_secs": { "type": "number", "description": "Default per-node execution timeout in seconds (5-300, default: 60). Individual nodes can override via their own `timeout_secs` — per-node values are NOT clamped to this ceiling, they're used as-is. This value sets the default for nodes that don't specify one." },
                    "max_result_rows": { "type": "number", "description": "Maximum result rows (100-10000, default: 1000)" },
                    "max_result_size_bytes": { "type": "number", "description": "Maximum result size in bytes (102400-10485760, default: 1048576)" }
                },
            }
        }),
        serde_json::json!({
            "name": "get_queue_status",
            "description": "Get batch processing progress for a workflow: counts of queued, running, completed, failed, and cancelled executions in the last 24 hours.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow" }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "set_failure_notification",
            "description": "Configure a webhook URL to be called when a workflow execution fails. Pass an empty string to clear.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow" },
                    "webhook_url": { "type": "string", "description": "Webhook URL to POST failure alerts to, or empty string to clear" }
                },
                "required": ["workflow_id", "webhook_url"]
            }
        }),
        serde_json::json!({
            "name": "get_failure_notification",
            "description": "Get the configured failure notification webhook URL for a workflow.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow" }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "get_platform_info",
            "description": "Get Talos platform metadata: version, tool count, database status, uptime, and feature capabilities.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }),
        serde_json::json!({
            "name": "set_concurrency_limit",
            "description": "Set or clear the maximum number of concurrent executions for a workflow. Prevents a single workflow from monopolizing workers.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow" },
                    "max_concurrent": { "type": ["number", "null"], "description": "Max concurrent executions (1-100), or null to clear the limit" }
                },
                "required": ["workflow_id", "max_concurrent"]
            }
        }),
        serde_json::json!({
            "name": "export_platform_state",
            "description": "Export all workflows, schedules, and secret references for the current user as a portable manifest. Secret values are NOT exported. The manifest includes a module_manifest that maps module UUIDs to names, enabling import_platform_state to remap UUIDs to the target instance automatically. Use import_platform_state to restore after a DB reset or instance migration.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }),
        serde_json::json!({
            "name": "import_platform_state",
            "description": "Import a manifest produced by export_platform_state. Restores workflows and schedules. Module UUIDs are automatically remapped to the current instance using the module_manifest embedded in the export — workflows are immediately executable once their modules are installed. Secret references are listed but must be re-provisioned in the dashboard (Settings → Secrets) — secret writes require 2FA and aren't available through MCP. Use dry_run=true to preview changes and see which modules require reinstallation before writing.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "manifest": { "type": "object", "description": "The manifest object from export_platform_state (version 2). Must include module_manifest for automatic UUID remapping. Version 1 manifests (produced by older instances without module_manifest) are rejected with an explicit 'Unsupported manifest version' error — re-export from the source instance to obtain a version 2 manifest." },
                    "dry_run": { "type": "boolean", "description": "If true, validate and preview changes without writing to the database. Shows which module UUIDs can be remapped and which require reinstallation (default: false)" }
                },
                "required": ["manifest"]
            }
        }),
        serde_json::json!({
            "name": "security_audit",
            "description": "Programmatic security posture check. Validates encryption keys, JWT configuration, audit triggers, CORS, and TLS settings. Returns a scored assessment with actionable recommendations.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }),
        // ── Scaffold generators ────────────────────────────────────────────
        serde_json::json!({
            "name": "get_js_scaffold",
            "description": "Returns a ready-to-use JavaScript scaffold for WASM modules targeting the `jco componentize` toolchain. Includes the correct `export function run(input)` signature, JSON parse/serialize patterns, and world-specific interface comments.\n\nUse this scaffold as the starting point for JavaScript-based modules.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "capability_world": {
                        "type": "string",
                        "enum": worlds_enum.clone(),
                        "description": format!("WIT capability world for the scaffold. Valid: {}. Default: minimal-node", worlds_csv)
                    }
                },
                "required": []
            }
        }),
        serde_json::json!({
            "name": "get_python_scaffold",
            "description": "Returns a ready-to-use Python scaffold for WASM modules targeting the `componentize-py` toolchain. Includes the correct `def run(input: str) -> str` signature, JSON parse/serialize patterns, and world-specific interface comments.\n\nUse this scaffold as the starting point for Python-based modules.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "capability_world": {
                        "type": "string",
                        "enum": worlds_enum.clone(),
                        "description": format!("WIT capability world for the scaffold. Valid: {}. Default: minimal-node", worlds_csv)
                    }
                },
                "required": []
            }
        }),
        // ── Secret access audit ───────────────────────────────────────────
        serde_json::json!({
            "name": "get_secret_access_log",
            "description": "Query the secret access audit log. Shows who accessed what secrets and when. Useful for security reviews and compliance audits.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "key_path": { "type": "string", "description": "Filter by secret key path (optional)" },
                    "hours": { "type": "number", "description": "Look back N hours (default: 24)" },
                    "limit": { "type": "number", "description": "Max results (default: 50)" }
                }
            }
        }),
        // ── P12: A2A protocol tools ────────────────────────────────────────
        serde_json::json!({
            "name": "get_agent_card",
            "description": "Generate an A2A (Agent-to-Agent) protocol Agent Card for an actor. \
                The Agent Card describes the actor's capabilities, available workflows, and \
                the endpoint URL for receiving A2A task requests — conforming to Google's A2A \
                agent discovery specification. Other AI systems can use this card to discover \
                what this actor can do and how to call it. \
                Share the agent card's endpoint_url with other agents to enable cross-agent collaboration.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "actor_id": { "type": "string", "description": "UUID of the actor to generate the card for" },
                    "base_url": { "type": "string", "description": "Base URL of this Talos instance (e.g. 'https://talos.example.com'). Defaults to the TALOS_BASE_URL env var." }
                },
                "required": ["actor_id"]
            }
        }),
        serde_json::json!({
            "name": "call_a2a_agent",
            "description": "Send a task to a remote A2A-compatible agent and return its result. \
                Implements the Google A2A protocol: POSTs a task request to the remote agent's endpoint, \
                polls for completion if needed, and returns the final output. \
                Use get_agent_card to discover an agent's endpoint_url and supported capabilities. \
                The remote agent must expose a POST endpoint accepting {task_id, message} \
                and returning {status, result}.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "endpoint_url": { "type": "string", "description": "The A2A endpoint URL from the remote agent's Agent Card" },
                    "message": { "type": "string", "description": "Natural language task description or instruction for the remote agent" },
                    "input": { "type": "object", "description": "Optional structured input payload for the remote agent" },
                    "timeout_secs": { "type": "number", "description": "Maximum seconds to wait for a response (default: 30, max: 120)" }
                },
                "required": ["endpoint_url", "message"]
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
    // MCP-330 / MCP-331: deployment-wide admin handlers
    // (`set_wasm_config`, `get_secret_access_log`) now compute their
    // own `is_platform_admin(user_id)` gate; the agent-level
    // `is_admin()` capability is no longer consulted here.
    match name {
        "get_wasm_config" => Some(handle_get_wasm_config(req_id, state).await),
        "set_wasm_config" => Some(handle_set_wasm_config(req_id, args, state, user_id).await),
        "get_queue_status" => Some(handle_get_queue_status(req_id, args, state, user_id).await),
        "set_failure_notification" => {
            Some(handle_set_failure_notification(req_id, args, state, user_id).await)
        }
        "get_failure_notification" => {
            Some(handle_get_failure_notification(req_id, args, state, user_id).await)
        }
        "get_platform_info" => Some(handle_get_platform_info(req_id, state, agent).await),
        "set_concurrency_limit" => {
            Some(handle_set_concurrency_limit(req_id, args, state, user_id).await)
        }
        "export_platform_state" => Some(handle_export_platform_state(req_id, state, user_id).await),
        "import_platform_state" => {
            Some(handle_import_platform_state(req_id, args, state, user_id).await)
        }
        "security_audit" => Some(handle_security_audit(req_id, state).await),
        "get_js_scaffold" => Some(handle_get_js_scaffold(req_id, args)),
        "get_python_scaffold" => Some(handle_get_python_scaffold(req_id, args)),
        "get_secret_access_log" => {
            Some(handle_get_secret_access_log(req_id, args, state, user_id).await)
        }
        "get_agent_card" => Some(handle_get_agent_card(req_id, args, state, user_id).await),
        "call_a2a_agent" => Some(handle_call_a2a_agent(req_id, args, state).await),
        _ => None,
    }
}

async fn handle_get_wasm_config(
    req_id: Option<serde_json::Value>,
    state: &McpState,
) -> JsonRpcResponse {
    let sysrepo = talos_system_repo::SystemRepository::new(state.db_pool.clone());
    // MCP-552: previously `.unwrap_or(None)` silently treated a DB read
    // failure as "no DB overrides set," misrepresenting the effective
    // config to the operator (the response would proclaim
    // `"source": "env defaults only"` even when the DB was unreachable).
    // Symmetric to MCP-551 (set_wasm_config). Fail closed so the
    // operator can't be misled about which settings are actually in
    // effect.
    let db_value = match sysrepo.get_setting("wasm_config").await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(
                target: "talos_mcp_handlers::platform",
                event_kind = "get_wasm_config_failed",
                error = %e,
                "get_wasm_config: existing-config lookup failed — refusing to report misleading 'env defaults only' on DB outage"
            );
            return mcp_error(req_id, -32000, "Failed to read WASM config");
        }
    };

    // MCP-640 (2026-05-13): align `get_wasm_config` defaults with the
    // runtime substitution behavior (MCP-639) — `=0` is treated as
    // misconfiguration and the worker substitutes the default. The
    // reporter has to match or the operator's view of "what will the
    // worker use" lies (UI says `0` for `max_fuel` while the worker
    // silently uses 10M). Inline `.filter(|&n| n > 0)` so missing,
    // invalid, AND zero all collapse to the same default.
    let nonzero_u64 = |var: &str, default: u64| -> u64 {
        std::env::var(var)
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(default)
    };
    let defaults = serde_json::json!({
        "max_memory_mb": nonzero_u64("WASM_MAX_MEMORY_MB", 128),
        "max_fuel": nonzero_u64("WASM_FUEL_LIMIT", 10_000_000),
        // Default is 60s (was 30s). Raised 2026-04-14 because agent-node modules
        // calling `llm::complete` routinely need 20–45s for Ollama synthesis and
        // can exceed 30s on Anthropic for larger prompts. 60s covers both without
        // blessing truly-runaway workflows; operators can still override via
        // WASM_EXECUTION_TIMEOUT_SECS or the set_wasm_config tool.
        "execution_timeout_secs": nonzero_u64("WASM_EXECUTION_TIMEOUT_SECS", 60),
        "max_result_rows": nonzero_u64("WASM_MAX_RESULT_ROWS", 1000),
        "max_result_size_bytes": nonzero_u64("WASM_MAX_RESULT_SIZE_BYTES", 1_048_576),
    });

    let effective = if let Some(ref db_val) = db_value {
        // Merge DB settings over defaults.
        // MCP-759 (2026-05-13): align overlay with the runtime
        // substitution behavior (MCP-639/MCP-640). For numeric keys
        // (every key in the wasm_config schema is a u64-shaped limit),
        // a `0` overlay would shadow the safe default with "0 fuel" /
        // "0 memory" — the worker substitutes the default in that case
        // (the `nonzero_u64` helper above does the same for env reads),
        // but the reporter was unconditionally overlaying. Operator
        // saw `effective.max_fuel = 0` while the worker actually used
        // 10_000_000. Skip overlay when the DB value is a number ≤ 0;
        // non-numeric values pass through (no current keys use non-
        // numeric types, but the path stays general).
        let mut merged = defaults.clone();
        if let (Some(m), Some(d)) = (db_val.as_object(), merged.as_object_mut()) {
            for (k, v) in m {
                let is_nonpositive_number = v
                    .as_u64()
                    .map(|n| n == 0)
                    .or_else(|| v.as_i64().map(|n| n <= 0))
                    .unwrap_or(false);
                if is_nonpositive_number {
                    tracing::warn!(
                        target: "talos_mcp_handlers::platform",
                        event_kind = "wasm_config_nonpositive_substituted",
                        key = %k,
                        configured = ?v,
                        "wasm_config DB-override for {} is non-positive — \
                         ignored to match worker's =0 substitution behavior; \
                         reporting env default instead",
                        k
                    );
                    continue;
                }
                d.insert(k.clone(), v.clone());
            }
        }
        merged
    } else {
        defaults.clone()
    };

    let response = serde_json::json!({
        "effective": effective,
        "defaults": defaults,
        "db_overrides": db_value,
        "source": if db_value.is_some() { "database + env defaults" } else { "env defaults only" },
    });
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&response).unwrap_or_default(),
    )
}

async fn handle_set_wasm_config(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    // MCP-330 (2026-05-11): `wasm_config` lives in the `system_settings`
    // table — one row read by every WASM execution across every tenant
    // (fuel limit, memory cap, execution timeout, result-size caps).
    // The pre-fix gate was the agent-level `is_admin` (per-tenant
    // admin role); an organization-scoped admin agent could push
    // `max_fuel: 100_000` (the minimum) and cripple every tenant's
    // WASM execution, or `max_memory_mb: 16` to OOM-throttle them.
    // Same require_platform_admin family as MCP-323/324/325/326/327/
    // 328/329 — use the `users.is_platform_admin` column.
    let is_platform_admin = state
        .actor_repo
        .is_platform_admin(user_id)
        .await
        .unwrap_or(false);
    if !is_platform_admin {
        return mcp_error(
            req_id,
            -32601,
            "set_wasm_config requires platform-admin privileges. \
             It mutates the deployment-wide WASM resource caps consulted \
             by every tenant's execution.",
        );
    }
    let mut config = serde_json::Map::new();

    // MCP-282 (2026-05-10): pre-fix `if let Some(v) = args.get(k).and_then(|v| v.as_u64())`
    // collapsed wrong-type into None — the field was silently dropped from
    // the config update. Operator passes `max_memory_mb: "256"` (string) +
    // `max_fuel: 1000000` and gets back "WASM config updated" listing
    // ONLY max_fuel — the memory-cap update was lost without a signal.
    // For an admin handler that controls runtime resource caps this is
    // a high-impact silent-drop. Each field uses validate_range_u64 now,
    // which distinguishes absent (skip) from wrong-type / out-of-range
    // (loud reject). Default is u64::MAX as a sentinel since the
    // None case is the only valid skip-this-field path.
    let read_optional_u64 = |field: &str,
                             min: u64,
                             max: u64|
     -> Result<Option<u64>, JsonRpcResponse> {
        match args.get(field) {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(v) => match v.as_u64() {
                Some(n) if (min..=max).contains(&n) => Ok(Some(n)),
                Some(n) => Err(mcp_error(
                    req_id.clone(),
                    -32602,
                    &format!("{field} must be between {min} and {max}, got {n}"),
                )),
                None => {
                    let kind = crate::utils::json_type_name(v);
                    Err(mcp_error(
                        req_id.clone(),
                        -32602,
                        &format!(
                            "{field} must be a non-negative integer, got {kind}"
                        ),
                    ))
                }
            },
        }
    };

    match read_optional_u64("max_memory_mb", 16, 512) {
        Ok(Some(v)) => {
            config.insert("max_memory_mb".to_string(), serde_json::json!(v));
        }
        Ok(None) => {}
        Err(resp) => return resp,
    }
    match read_optional_u64("max_fuel", 100_000, 10_000_000) {
        Ok(Some(v)) => {
            config.insert("max_fuel".to_string(), serde_json::json!(v));
        }
        Ok(None) => {}
        Err(resp) => return resp,
    }
    match read_optional_u64("execution_timeout_secs", 5, 300) {
        Ok(Some(v)) => {
            config.insert("execution_timeout_secs".to_string(), serde_json::json!(v));
        }
        Ok(None) => {}
        Err(resp) => return resp,
    }
    match read_optional_u64("max_result_rows", 100, 10_000) {
        Ok(Some(v)) => {
            config.insert("max_result_rows".to_string(), serde_json::json!(v));
        }
        Ok(None) => {}
        Err(resp) => return resp,
    }
    match read_optional_u64("max_result_size_bytes", 102_400, 10_485_760) {
        Ok(Some(v)) => {
            config.insert("max_result_size_bytes".to_string(), serde_json::json!(v));
        }
        Ok(None) => {}
        Err(resp) => return resp,
    }

    if config.is_empty() {
        return mcp_error(req_id, -32602, "No valid configuration fields provided");
    }

    // Merge with existing DB config.
    // MCP-551: previously `.unwrap_or(None)` silently treated a DB lookup
    // failure as "no existing config." That's destructive on a patch
    // operation — the caller's partial patch becomes the entire config,
    // wiping every key the caller didn't explicitly set. Operator
    // patches `{max_fuel: ...}` during a DB hiccup → existing
    // `{max_fuel, max_memory_mb, custom_setting, ...}` collapses to
    // `{max_fuel: ...}` and the rest disappears. Fail closed.
    let sysrepo = talos_system_repo::SystemRepository::new(state.db_pool.clone());
    let existing = match sysrepo.get_setting("wasm_config").await {
        Ok(opt) => opt,
        Err(e) => {
            tracing::error!(
                target: "talos_mcp_handlers::platform",
                event_kind = "get_wasm_config_failed",
                error = %e,
                "set_wasm_config: existing-config lookup failed — refusing to merge to avoid destructive partial overwrite"
            );
            return mcp_error(req_id, -32000, "Failed to read existing WASM config");
        }
    };

    let mut merged = existing
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default();
    for (k, v) in &config {
        merged.insert(k.clone(), v.clone());
    }

    let merged_val = serde_json::Value::Object(merged.clone());
    match sysrepo.upsert_setting("wasm_config", &merged_val).await {
        Ok(_) => mcp_text(
            req_id,
            &format!(
                "WASM config updated.\n{}",
                serde_json::to_string_pretty(&serde_json::Value::Object(merged))
                    .unwrap_or_default()
            ),
        ),
        Err(e) => {
            tracing::error!("set_wasm_config failed: {:#}", e);
            mcp_error(req_id, -32000, "Failed to save WASM config")
        }
    }
}

async fn handle_get_queue_status(
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
        .get_workflow_queue_stats_24h(wf_id, user_id)
        .await
    {
        Ok(stats) => {
            // MCP-106 (2026-05-08): emit progress_percent via format_percent
            // for consistency with MCP-19 platform-wide standardization
            // (1-decimal precision). Pre-fix this was raw f64 — clean for
            // 100.0 but a workflow with completed:2 / total:7 would have
            // emitted 28.571428571428573 (16-digit drift).
            let progress_pct: f64 = if stats.total > 0 {
                let raw = (stats.completed + stats.failed + stats.cancelled) as f64
                    / stats.total as f64
                    * 100.0;
                talos_analytics_repository::format_percent(raw)
            } else {
                0.0
            };

            let mut result = serde_json::json!({
                "workflow_id": wf_id.to_string(),
                "queued": stats.queued,
                "running": stats.running,
                "completed": stats.completed,
                "failed": stats.failed,
                "cancelled": stats.cancelled,
                "total": stats.total,
                "progress_percent": progress_pct,
            });
            if let Some(fs) = stats.first_started {
                result["first_started"] = serde_json::json!(fs.to_rfc3339());
            }
            if let Some(lc) = stats.last_completed {
                result["last_completed"] = serde_json::json!(lc.to_rfc3339());
            }

            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&result).unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!("get_queue_status query failed: {:#}", e);
            mcp_error(req_id, -32000, "Failed to get queue status")
        }
    }
}

async fn handle_set_failure_notification(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };
    // MCP-336 (2026-05-11): pre-fix `args.get("webhook_url").and_then(
    // |v| v.as_str())` collapsed wrong-type into None, then errored
    // with "Missing 'webhook_url' parameter" — misleading when the
    // operator clearly DID send the field but typed it wrong (e.g.
    // `webhook_url: 42`). Distinguish absent / wrong-type with
    // observed kind named. Empty string clears the webhook; whitespace-
    // only is a likely operator typo (and previously fell through to
    // the SSRF check which would error with "Invalid URL" — actionable
    // but pointing at the wrong fix), so reject it loudly with the
    // intent-clarifying message.
    let webhook_url = match args.get("webhook_url") {
        None => return mcp_error(req_id, -32602, "Missing 'webhook_url' parameter"),
        Some(serde_json::Value::Null) => "",
        Some(v) => match v.as_str() {
            Some(s) => s,
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!(
                        "webhook_url must be a string (pass empty string to clear), got {kind}"
                    ),
                );
            }
        },
    };

    // Store NULL if empty string (to clear); reject whitespace-only as
    // a likely typo; otherwise validate the URL.
    let url_val: Option<&str> = if webhook_url.is_empty() {
        None
    } else if webhook_url.trim().is_empty() {
        return mcp_error(
            req_id,
            -32602,
            "webhook_url must be empty (to clear) OR a non-whitespace URL — whitespace-only is rejected to surface operator typos.",
        );
    } else {
        // SSRF protection: validate before storing so the URL is never persisted
        // in a state that would cause the workflow engine to make an unvalidated
        // outbound request on failure. The check is intentionally at storage time,
        // not at call time, to fail fast and avoid silent data-exfiltration vectors.
        if let Err(reason) = check_outbound_url_no_ssrf(webhook_url) {
            return mcp_error(req_id, -32602, reason);
        }
        Some(webhook_url)
    };

    match state
        .workflow_repo
        .set_failure_webhook_url_column(wf_id, user_id, url_val)
        .await
    {
        Ok(rows) if rows > 0 => {
            // MCP-436 (2026-05-11): audit log on a failure-notification
            // webhook change. Architectural follow-up flagged across
            // recent cycles. The webhook URL is the exfiltration
            // channel for workflow failure data (error messages,
            // stack traces, sometimes secrets that surfaced in
            // exceptions). Threat: attacker with stolen MCP key
            // flips the webhook to an attacker-controlled URL,
            // waits for a failure event to fire (or causes one),
            // then reverts. The SSRF check at storage prevents
            // private-IP exfil but doesn't prevent a public
            // attacker-controlled domain. Auditing the change
            // makes the flip-exfil-flip-back pattern visible in
            // admin_event_log.
            //
            // The `is_configured` boolean distinguishes set vs
            // clear in details (the resource_id stays the workflow
            // either way). url_val is recorded too — operators
            // investigating an exfil can see which destination got
            // configured at the time of the change.
            crate::actor::spawn_log_admin_event(
                state.db_pool.clone(),
                user_id,
                "workflow_failure_webhook_changed",
                "workflow",
                Some(wf_id),
                if url_val.is_some() {
                    format!("Workflow {} failure webhook set", wf_id)
                } else {
                    format!("Workflow {} failure webhook cleared", wf_id)
                },
                Some(serde_json::json!({
                    "is_configured": url_val.is_some(),
                    "webhook_url": url_val,
                })),
            );
            let msg = if url_val.is_some() {
                format!("Failure notification webhook set for workflow {}.", wf_id)
            } else {
                format!(
                    "Failure notification webhook cleared for workflow {}.",
                    wf_id
                )
            };
            mcp_text(req_id, &msg)
        }
        Ok(_) => crate::utils::workflow_not_found_error(req_id),
        Err(e) => {
            tracing::error!("set_failure_notification update failed: {:#}", e);
            mcp_error(req_id, -32000, "Failed to set failure notification")
        }
    }
}

async fn handle_get_failure_notification(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // MCP-97 (2026-05-07): the underlying repo returns Option<Option<String>>:
    //   * Outer None → workflow not found / not owned.
    //   * Outer Some(None) → workflow exists, webhook column is NULL.
    //   * Outer Some(Some(url)) → webhook configured.
    // Pre-fix the handler collapsed both null cases via `.unwrap_or(None)`,
    // so an unconfigured workflow looked the same as a missing one.
    // The new shape distinguishes them: 404 only when the row truly
    // doesn't exist, otherwise emit `is_configured` + a `note` so the
    // operator knows the next step.
    let lookup = match state
        .workflow_repo
        .get_failure_webhook_url_column(wf_id, user_id)
        .await
    {
        Ok(opt) => opt,
        Err(e) => {
            tracing::error!(workflow_id = %wf_id, "get_failure_notification db error: {}", e);
            return mcp_error(req_id, -32000, "Failed to fetch failure notification");
        }
    };

    match lookup {
        None => crate::utils::workflow_not_found_error(req_id),
        Some(None) => {
            let result = serde_json::json!({
                "workflow_id": wf_id.to_string(),
                "webhook_url": serde_json::Value::Null,
                "is_configured": false,
                "note": "No failure notification webhook configured for this workflow. Use set_failure_notification(workflow_id, webhook_url) to receive alerts on execution failures.",
            });
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&result).unwrap_or_default(),
            )
        }
        Some(Some(url)) => {
            let result = serde_json::json!({
                "workflow_id": wf_id.to_string(),
                "webhook_url": url,
                "is_configured": true,
            });
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&result).unwrap_or_default(),
            )
        }
    }
}

async fn handle_get_platform_info(
    req_id: Option<serde_json::Value>,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    // PROCESS_START_TIME is force-initialized in main() before any handler
    // runs, so elapsed() always reflects true server uptime.
    let uptime_secs = super::PROCESS_START_TIME.elapsed().as_secs();

    // Database connectivity check
    let sysrepo = talos_system_repo::SystemRepository::new(state.db_pool.clone());
    let db_status = if sysrepo.ping().await {
        "connected"
    } else {
        "disconnected"
    };

    // Compute tool count using the exact same logic as handle_tools_list so the
    // two values are guaranteed identical — static domain tools + catalog templates
    // visible to this agent's capability grants.
    // Single source of truth shared with handle_initialize — see
    // crate::static_tool_count(). Previously this site maintained its own
    // list that had drifted 8 tools out of sync (missed knowledge_graph + ollama).
    let static_count = super::static_tool_count();

    // Count catalog templates visible to this agent (same filter as handle_tools_list).
    let catalog_count = if let Ok(templates) = state.registry.list_templates(None).await {
        let template_ids: Vec<uuid::Uuid> = templates.iter().map(|t| t.id).collect();
        let world_rows = state
            .module_repo
            .list_template_world_overrides(&template_ids)
            .await
            .unwrap_or_default();
        let world_map: std::collections::HashMap<uuid::Uuid, String> =
            world_rows.into_iter().collect();

        templates
            .iter()
            .filter(|t| t.category != "sandbox" && t.category != "workflow_template")
            .filter(|t| {
                let template_world = world_map
                    .get(&t.id)
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string());
                if template_world == "minimal" {
                    return true;
                }
                let world_base = template_world.trim_end_matches("-node").to_string();
                agent.has_capability(&world_base)
                    || agent
                        .allowed_capabilities
                        .iter()
                        .any(|c| format!("{}-node", c) == template_world)
            })
            .count()
    } else {
        0
    };

    let tool_count = static_count + catalog_count;

    // MCP-27 (2026-05-07): emit `build_version` with the same composite
    // shape session_start uses (`{cargo_pkg}+{git_sha}{-dirty?}`) so
    // operators tailing either surface see the same version string.
    // TALOS_VERSION still wins when set (docker-compose / CI override).
    let build_version = std::env::var("TALOS_VERSION").unwrap_or_else(|_| {
        format!(
            "{}+{}{}",
            env!("CARGO_PKG_VERSION"),
            env!("GIT_SHA"),
            if env!("GIT_DIRTY") == "true" {
                "-dirty"
            } else {
                ""
            }
        )
    });

    let features = vec![
        "talos_workflow_engine",
        "parallel_execution",
        "wasm_sandboxing",
        "module_marketplace",
        "secrets_management",
        "webhook_triggers",
        "cron_scheduling",
        "workflow_versioning",
        "execution_archival",
        "mcp_tools",
        "sse_transport",
        "streamable_http",
    ];

    // MCP-28 (2026-05-07): break the tool count down so the
    // 394-vs-325 delta is self-explanatory. session_start emits
    // `static_tool_count` only; this surface emits the full
    // breakdown so operators on either surface can reconcile.
    let response = serde_json::json!({
        "build_version": build_version,
        "total_mcp_tools": tool_count,
        "static_tool_count": static_count,
        "catalog_tool_count": catalog_count,
        "tool_count_note": "total_mcp_tools = static_tool_count + catalog_tool_count. session_start.static_tool_count matches static_tool_count here.",
        "database_status": db_status,
        "uptime_seconds": uptime_secs,
        "uptime_human": format!("{}h {}m {}s", uptime_secs / 3600, (uptime_secs % 3600) / 60, uptime_secs % 60),
        "features": features,
    });
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&response).unwrap_or_default(),
    )
}

async fn handle_set_concurrency_limit(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let wf_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let max_concurrent: Option<i32> = if args
        .get("max_concurrent")
        .map(|v| v.is_null())
        .unwrap_or(true)
    {
        None
    } else {
        match args.get("max_concurrent").and_then(|v| v.as_i64()) {
            Some(n) if (1..=100).contains(&n) => Some(n as i32),
            Some(_) => {
                return mcp_error(
                    req_id,
                    -32602,
                    "max_concurrent must be between 1 and 100, or null to clear",
                )
            }
            None => return mcp_error(req_id, -32602, "Invalid 'max_concurrent' value"),
        }
    };

    match state
        .workflow_repo
        .set_max_concurrent_executions(wf_id, user_id, max_concurrent)
        .await
    {
        Ok(rows) if rows > 0 => {
            let msg = match max_concurrent {
                Some(n) => format!("Concurrency limit set to {} for workflow {}", n, wf_id),
                None => format!("Concurrency limit cleared for workflow {}", wf_id),
            };
            mcp_text(req_id, &msg)
        }
        Ok(_) => crate::utils::workflow_not_found_error(req_id),
        Err(e) => {
            tracing::error!("Failed to set concurrency limit: {:#}", e);
            mcp_error(req_id, -32000, "Failed to set concurrency limit")
        }
    }
}

async fn handle_export_platform_state(
    req_id: Option<serde_json::Value>,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    match state.workflow_manifest_service.export(user_id).await {
        Ok(out) => mcp_text(
            req_id,
            &serde_json::to_string_pretty(&out.manifest).unwrap_or_default(),
        ),
        Err(e) => crate::utils::manifest_error_to_response(e, req_id),
    }
}

async fn handle_import_platform_state(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let manifest = match args.get("manifest") {
        Some(m) => m,
        None => return mcp_error(req_id, -32602, "Missing required argument: manifest"),
    };
    // MCP-267 (2026-05-10): direction-class wrong-type rejection.
    // Pre-fix `dry_run: "true"` (string) silently fell back to false
    // — manifest IMPORT would actually run when the operator was
    // probing. High-blast-radius. Same family as MCP-251 / MCP-252.
    let dry_run = match crate::utils::validate_optional_bool(args, "dry_run", false, &req_id) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    let outcome = match state
        .workflow_manifest_service
        .import(talos_workflow_manifest::ImportInput {
            manifest,
            dry_run,
            user_id,
        })
        .await
    {
        Ok(o) => o,
        Err(e) => return crate::utils::manifest_error_to_response(e, req_id),
    };

    // Render the canonical response shape. Dry-run keeps the
    // human-facing `note` line; live runs omit it (matches the
    // pre-extraction handler exactly).
    let mut body = match serde_json::to_value(&outcome) {
        Ok(v) => v,
        Err(_) => {
            return mcp_error(req_id, -32000, "Failed to serialize import outcome")
        }
    };
    if outcome.dry_run {
        if let Some(obj) = body.as_object_mut() {
            obj.insert(
                "note".to_string(),
                serde_json::json!(
                    "Run with dry_run=false to apply changes. Unresolvable modules require reinstallation via install_module_from_catalog before the workflow can execute."
                ),
            );
        }
    }
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&body).unwrap_or_default(),
    )
}

// ────────────────────────────────────────────────────────────────────────────
// Security audit
// ────────────────────────────────────────────────────────────────────────────

async fn handle_security_audit(
    req_id: Option<serde_json::Value>,
    state: &McpState,
) -> JsonRpcResponse {
    let mut checks: Vec<serde_json::Value> = Vec::new();
    let mut score: u32 = 0;
    let max_score: u32 = 100;

    // Check 1: Production mode
    let is_prod = talos_config::is_production();
    checks.push(serde_json::json!({
        "check": "production_mode",
        "status": if is_prod { "pass" } else { "info" },
        "detail": if is_prod { "RUST_ENV=production" } else { "Development mode — some security features relaxed" },
    }));
    if is_prod {
        score += 10;
    }

    // Check 2: JWT algorithm — deployment-topology aware.
    //
    // MCP-1209 (2026-05-17): the previous version emitted a generic
    // "upgrade to RS256/ES256 for microservice deployments" warn for ANY
    // non-asymmetric algorithm, even on single-pod deployments where the
    // recommendation doesn't apply. HS256 (symmetric HMAC-SHA256) is
    // operationally appropriate when the SAME process both signs and
    // verifies JWTs — there's no "verifier-only service" whose key
    // exposure RS256/ES256 would mitigate. The 5-point deduction
    // for single-pod deployments was cosmetic, not security-grounded.
    //
    // Operators on multi-controller / split-verifier topologies should
    // set TALOS_DEPLOYMENT_TOPOLOGY=microservices to opt into the strict
    // grading; the default `single_pod` matches the canonical Talos
    // deployment (one controller pod, one process signing and verifying).
    let jwt_algo = talos_config::get_env("JWT_ALGORITHM", "HS256");
    let is_asymmetric = jwt_algo == "RS256" || jwt_algo == "ES256";
    let topology = talos_config::get_env("TALOS_DEPLOYMENT_TOPOLOGY", "single_pod");
    let is_single_pod = topology == "single_pod";
    let jwt_status = if is_asymmetric {
        "pass"
    } else if is_single_pod {
        // HS256 is fine for single-pod — same process signs + verifies,
        // no asymmetric-key advantage to claim.
        "pass"
    } else {
        "warn"
    };
    let jwt_detail = if is_asymmetric {
        format!("JWT_ALGORITHM={} — asymmetric (recommended)", jwt_algo)
    } else if is_single_pod {
        format!(
            "JWT_ALGORITHM={} — symmetric (acceptable for single-pod deployment, \
             topology={}). Move to RS256/ES256 only if splitting into a \
             multi-controller / dedicated-verifier topology.",
            jwt_algo, topology
        )
    } else {
        format!(
            "JWT_ALGORITHM={} — symmetric (upgrade to RS256/ES256 for \
             microservice deployments, topology={})",
            jwt_algo, topology
        )
    };
    checks.push(serde_json::json!({
        "check": "jwt_algorithm",
        "status": jwt_status,
        "detail": jwt_detail,
    }));
    if jwt_status == "pass" {
        score += 10;
    } else {
        score += 5;
    }

    // MCP-625 (2026-05-12): every security-key health check below used
    // `env::var(KEY).is_ok()`, which matches `Ok("")` — so a Helm
    // `values.yaml` placeholder `talosMasterKey: ""` made the audit
    // report "TALOS_MASTER_KEY is configured" + score +15 while the
    // downstream runtime (kek_provider) refused to load the empty
    // key. Operators saw a green dashboard while critical security
    // primitives were disabled. Same empty-env-var class as
    // MCP-590/591/592/597/598/599/611/615/620/621.
    //
    // Affected checks: master_encryption_key, job_signing_key,
    // aot_integrity_key, audit_event_signing. Inline closure so the
    // four sites share one helper without escaping a module-level
    // function (this file already has a different `env_set` helper
    // shape in the validator crate, but this file doesn't depend on it).
    let env_present = |var: &str| {
        std::env::var(var)
            .ok()
            .filter(|v| !v.is_empty())
            .is_some()
    };

    // Check 3: TALOS_MASTER_KEY set
    let has_master_key = env_present("TALOS_MASTER_KEY");
    checks.push(serde_json::json!({
        "check": "master_encryption_key",
        "status": if has_master_key { "pass" } else { "fail" },
        "detail": if has_master_key { "TALOS_MASTER_KEY is configured" } else { "CRITICAL: TALOS_MASTER_KEY not set — secrets cannot be encrypted" },
    }));
    if has_master_key {
        score += 15;
    }

    // Check 4: Worker shared key
    let has_worker_key = env_present("WORKER_SHARED_KEY");
    checks.push(serde_json::json!({
        "check": "job_signing_key",
        "status": if has_worker_key { "pass" } else { "warn" },
        "detail": if has_worker_key { "WORKER_SHARED_KEY set — job payloads are HMAC-signed" } else { "WORKER_SHARED_KEY not set — job payloads are unsigned" },
    }));
    if has_worker_key {
        score += 15;
    }

    // Check 5: AOT HMAC key.
    //
    // MCP-1210 (2026-05-17): two changes from the previous version.
    //
    // (a) The env-var is now wired into the controller deployment
    //     (`deploy/helm/talos/templates/controller/deployment.yaml`) as
    //     a no-op pass-through from `bootstrapSecret.data
    //     .TALOS_AOT_HMAC_KEY` so the audit check can see it. Pre-fix
    //     the key was wired only into the worker deployment — the
    //     controller's audit check could never report "pass" no matter
    //     how the operator configured the bootstrap secret. The
    //     controller process itself never reads the value (the WASM
    //     AOT cache lives on the worker); the env var serves purely as
    //     an operator-attestation marker that the bootstrap secret was
    //     populated.
    //
    // (b) The check now requires the key to be ≥ 32 bytes after hex
    //     decoding (= 64 hex chars), mirroring the worker-side strict
    //     length validation in `worker/src/runtime.rs::aot_key_ring`.
    //     A short / placeholder value (e.g. `"changeme"`) is now caught
    //     here at the controller-audit boundary instead of waiting for
    //     the worker to panic on first WASM execution.
    const MIN_AOT_KEY_BYTES: usize = 32;
    let aot_key_raw = std::env::var("TALOS_AOT_HMAC_KEY").unwrap_or_default();
    // Worker accepts hex OR raw bytes; canonical form is hex (per
    // worker/src/runtime.rs comments). Measure decoded length when the
    // value parses as hex; otherwise measure raw byte length.
    let aot_key_decoded_len = hex::decode(&aot_key_raw)
        .map(|b| b.len())
        .unwrap_or_else(|_| aot_key_raw.len());
    let aot_key_state = if aot_key_raw.is_empty() {
        "missing"
    } else if aot_key_decoded_len < MIN_AOT_KEY_BYTES {
        "too_short"
    } else {
        "valid"
    };
    let (aot_status, aot_detail) = match aot_key_state {
        "valid" => (
            "pass",
            "TALOS_AOT_HMAC_KEY set (≥32 bytes) — AOT blobs are integrity-verified".to_string(),
        ),
        "too_short" => (
            "warn",
            format!(
                "TALOS_AOT_HMAC_KEY is too short ({} bytes decoded; need ≥{}) \
                 — worker will panic at first WASM execution. Regenerate with \
                 `openssl rand -hex 32`.",
                aot_key_decoded_len, MIN_AOT_KEY_BYTES
            ),
        ),
        _ => (
            "info",
            "Using ephemeral AOT key — blobs not cached across restarts. \
             Generate a persistent key with `openssl rand -hex 32` and set \
             it on `bootstrapSecret.data.TALOS_AOT_HMAC_KEY`."
                .to_string(),
        ),
    };
    checks.push(serde_json::json!({
        "check": "aot_integrity_key",
        "status": aot_status,
        "detail": aot_detail,
    }));
    if aot_status == "pass" {
        score += 10;
    }

    // Check 6: Audit signing key
    let has_audit_key = env_present("TALOS_AUDIT_SIGNING_KEY");
    checks.push(serde_json::json!({
        "check": "audit_event_signing",
        "status": if has_audit_key { "pass" } else { "warn" },
        "detail": if has_audit_key { "Audit events are HMAC-signed for tamper detection" } else { "TALOS_AUDIT_SIGNING_KEY not set — audit events are unsigned" },
    }));
    if has_audit_key {
        score += 10;
    }

    // Check 7: Redis TLS (critical in production)
    let redis_url = std::env::var("REDIS_URL").unwrap_or_default();
    let redis_tls = redis_url.starts_with("rediss://") || redis_url.is_empty();
    checks.push(serde_json::json!({
        "check": "redis_tls",
        "status": if redis_tls { "pass" } else if is_prod { "fail" } else { "info" },
        "detail": if redis_url.is_empty() { "Redis not configured" }
            else if redis_tls { "Redis using TLS (rediss://)" }
            else { "Redis using plaintext (redis://) — use rediss:// in production" },
    }));
    if redis_tls && !redis_url.is_empty() {
        score += 10;
    }

    // Check 8: Database immutability triggers
    let sysrepo = talos_system_repo::SystemRepository::new(state.db_pool.clone());
    let trigger_check = sysrepo.count_triggers_like("trg_%_immutable").await;
    let has_triggers = trigger_check > 0;
    checks.push(serde_json::json!({
        "check": "audit_immutability_triggers",
        "status": if has_triggers { "pass" } else { "fail" },
        "detail": if has_triggers { format!("{} immutability trigger(s) active", trigger_check) } else { "No audit immutability triggers found — run migrations".to_string() },
    }));
    if has_triggers {
        score += 10;
    }

    // Check 9: ALLOWED_ORIGIN set (CORS)
    let has_origins = std::env::var("ALLOWED_ORIGIN").is_ok();
    checks.push(serde_json::json!({
        "check": "cors_origins",
        "status": if has_origins || !is_prod { "pass" } else { "fail" },
        "detail": if has_origins { "ALLOWED_ORIGIN is explicitly configured" }
            else if !is_prod { "Using default localhost origins (dev mode)" }
            else { "CRITICAL: ALLOWED_ORIGIN not set in production" },
    }));
    if has_origins {
        score += 10;
    }

    // MCP-69 (2026-05-07): score → grade thresholds were undocumented;
    // operators couldn't tell what would move them from B to A. The
    // mapping is now explicit on the response so the relationship is
    // auditable.
    const GRADE_A: u32 = 90;
    const GRADE_B: u32 = 75;
    const GRADE_C: u32 = 60;
    const GRADE_D: u32 = 40;
    let grade = if score >= GRADE_A {
        "A"
    } else if score >= GRADE_B {
        "B"
    } else if score >= GRADE_C {
        "C"
    } else if score >= GRADE_D {
        "D"
    } else {
        "F"
    };

    // MCP-69 (2026-05-07): per-check status counts so dashboards can
    // triage at a glance without re-walking the array. `info` is a real
    // status value used by the production_mode + aot_integrity_key checks
    // for "configured but not security-relevant" outcomes — neither pass
    // nor warn. Documented in `status_legend`.
    let mut pass_count = 0u32;
    let mut warn_count = 0u32;
    let mut fail_count = 0u32;
    let mut info_count = 0u32;
    for c in &checks {
        match c.get("status").and_then(|v| v.as_str()).unwrap_or("") {
            "pass" => pass_count += 1,
            "warn" => warn_count += 1,
            "fail" => fail_count += 1,
            "info" => info_count += 1,
            _ => {}
        }
    }

    let result = serde_json::json!({
        "security_score": score,
        "max_score": max_score,
        "grade": grade,
        "grade_thresholds": {
            "A": GRADE_A,
            "B": GRADE_B,
            "C": GRADE_C,
            "D": GRADE_D,
            "F": 0,
        },
        "status_counts": {
            "pass": pass_count,
            "warn": warn_count,
            "fail": fail_count,
            "info": info_count,
        },
        "status_legend": {
            "pass": "Security control is configured correctly.",
            "warn": "Control is configured but not at the recommended hardening level.",
            "fail": "Control is missing or misconfigured — fix before going to production.",
            "info": "Configuration noted; not security-graded (e.g. dev-mode posture).",
        },
        "checks": checks,
        "recommendation": if score >= GRADE_A { "Excellent security posture" }
            else if score >= GRADE_B { "Good — address warnings for production hardening" }
            else if score >= GRADE_C { "Acceptable for development — address failures before production" }
            else { "Critical gaps — do not deploy to production without fixing failures" },
    });

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

// ────────────────────────────────────────────────────────────────────────────
// P12: A2A agent card + cross-agent calling
// ────────────────────────────────────────────────────────────────────────────

async fn handle_get_agent_card(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let actor_id = match crate::utils::require_uuid(args, "actor_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // Resolve base_url with explicit "is this real?" tracking. The
    // previous shape silently substituted `https://talos.example.com`
    // when neither the arg nor TALOS_BASE_URL was set, then returned
    // the card with `shareable: true` — operators sharing this card
    // would ship a placeholder URL that resolves to nothing on the
    // receiving agent. Now we return the placeholder ONLY in the
    // payload so the caller can preview it, but flip `shareable`
    // false and surface a clear setup hint.
    // MCP-253 (2026-05-10): trim before empty check so
    // `base_url: "   "` (3 spaces) falls through to env / placeholder
    // instead of being concatenated into agent-card URLs as `"   /api/.."`.
    // Same family as MCP-249. The env var is also trimmed for symmetry.
    let arg_url = args
        .get("base_url")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let env_url = std::env::var("TALOS_BASE_URL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let (base_url, base_url_is_real) = match arg_url.or(env_url) {
        Some(u) => (u, true),
        None => ("https://talos.example.com".to_string(), false),
    };

    // Load actor info
    let info = match state
        .actor_repo
        .get_actor_card_info(actor_id, user_id)
        .await
        .unwrap_or(None)
    {
        Some(i) => i,
        None => return mcp_error(req_id, -32000, "Actor not found or access denied"),
    };
    let actor_name = info.name;
    let actor_desc = info.description;
    let actor_status = info.status;
    let actor_world = info.max_capability_world;

    // Load published workflows for this actor
    let workflows: Vec<serde_json::Value> = state
        .actor_repo
        .list_published_workflows_for_actor(actor_id, 20)
        .await
        .unwrap_or_default()
        .iter()
        .map(|w| {
            serde_json::json!({
                "workflow_id": w.id.to_string(),
                "name": w.name,
                "description": w.description,
                "capabilities": w.capabilities,
            })
        })
        .collect();

    // Build the A2A Agent Card following Google's A2A spec
    let agent_card = serde_json::json!({
        // A2A spec required fields
        "name": actor_name,
        "description": actor_desc.unwrap_or_else(|| format!("Talos actor: {}", actor_name)),
        "url": format!("{}/a2a/actors/{}", base_url.trim_end_matches('/'), actor_id),
        "version": "1.0",
        "capabilities": {
            "streaming": false,
            "pushNotifications": false,
            "stateTransitionHistory": true
        },
        // Well-known endpoint for discovery
        "provider": {
            "organization": "Talos AI Workflows",
            "url": base_url.trim_end_matches('/')
        },
        // Talos-specific extensions
        "actor_id": actor_id.to_string(),
        "status": actor_status,
        "max_capability_world": actor_world,
        "available_workflows": workflows,
        "endpoint_url": format!("{}/a2a/actors/{}/tasks", base_url.trim_end_matches('/'), actor_id),
        "authentication": {
            "type": "bearer",
            "description": "Include the Talos API key as Authorization: Bearer <token>"
        },
        "usage": {
            "description": "POST a task to endpoint_url with {message: string, input: object, workflow_id?: string}. Response: {task_id, status, result}.",
            "example_request": {
                "message": "Process this data",
                "input": {"data": "..."},
                "workflow_id": workflows.first()
                    .and_then(|w| w.get("workflow_id"))
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
            }
        }
    });

    let response = if base_url_is_real {
        serde_json::json!({
            "agent_card": agent_card,
            "well_known_url": format!(
                "{}/a2a/actors/{}/.well-known/agent.json",
                base_url.trim_end_matches('/'), actor_id
            ),
            "shareable": true,
            "note": "Share the endpoint_url with other A2A-compatible agents to enable cross-agent task delegation. The well_known_url can be registered in A2A agent registries for discovery.",
        })
    } else {
        serde_json::json!({
            "agent_card": agent_card,
            "well_known_url": format!(
                "{}/a2a/actors/{}/.well-known/agent.json",
                base_url.trim_end_matches('/'), actor_id
            ),
            "shareable": false,
            "warning": "Card was rendered with the placeholder base_url 'https://talos.example.com' because neither the `base_url` argument nor the TALOS_BASE_URL env var was set. The card MUST NOT be shared in this state — the receiving agent's calls would resolve to a non-existent host. Configure `base_url` on the call OR set TALOS_BASE_URL on the controller, then re-run.",
            "fix_with": {
                "option_a": "Pass `base_url: 'https://your-deployment.example.com'` to this call.",
                "option_b": "Set TALOS_BASE_URL on the controller environment and restart.",
            },
        })
    };
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&response).unwrap_or_default(),
    )
}

// SSRF validation is provided by the shared utils module so it can be reused
// across platform.rs, workflows.rs, advanced.rs, and any future outbound HTTP handlers.
use super::utils::check_outbound_url_no_ssrf;

async fn handle_call_a2a_agent(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    _state: &McpState,
) -> JsonRpcResponse {
    let endpoint_url = match args.get("endpoint_url").and_then(|v| v.as_str()) {
        Some(u) if !u.is_empty() => u.to_string(),
        _ => return mcp_error(req_id, -32602, "Missing required field: endpoint_url"),
    };

    if let Err(reason) = check_outbound_url_no_ssrf(&endpoint_url) {
        return mcp_error(req_id, -32602, reason);
    }

    // MCP-265 (2026-05-10): pre-fix `!m.is_empty()` accepted whitespace
    // ("   ") and forwarded it as the agent message. The remote A2A
    // agent received whitespace as the user prompt, an LLM call would
    // either return an unhelpful response or 400 — operator confusion
    // looks like an A2A protocol bug. Same MCP-249 family.
    let message = match args.get("message").and_then(|v| v.as_str()) {
        Some(m) if m.len() > 10_000 => {
            return mcp_error(req_id, -32602, "message must be ≤ 10 000 characters")
        }
        Some(m) if m.trim().is_empty() => {
            return mcp_error(
                req_id,
                -32602,
                "message must be non-empty and non-whitespace",
            )
        }
        Some(m) => m.to_string(),
        _ => return mcp_error(req_id, -32602, "Missing required field: message"),
    };

    let input = args.get("input").cloned().unwrap_or(serde_json::json!({}));
    if serde_json::to_string(&input).map(|s| s.len()).unwrap_or(0) > 1_048_576 {
        return mcp_error(req_id, -32602, "input exceeds 1 MB limit");
    }
    // MCP-183 (2026-05-08): replace silent-clamp with explicit
    // validation. Pre-fix `unwrap_or(30).min(120)` silently rewrote
    // out-of-range values — caller asking for a 600s timeout got
    // 120s with no warning.
    let timeout_secs =
        match crate::utils::validate_range_u64(args, "timeout_secs", 1, 120, 30, &req_id) {
            Ok(v) => v,
            Err(resp) => return resp,
        };

    // Build A2A task request per Google A2A spec.
    let task_id = Uuid::new_v4().to_string();
    let task_request = serde_json::json!({
        "id": task_id,
        "message": {
            "role": "user",
            "parts": [
                { "type": "text", "text": message }
            ]
        },
        "input": input
    });

    // MCP-470: disable redirect following. The SSRF check above
    // validates `endpoint_url` itself, but reqwest's default
    // `Policy::limited(10)` would silently follow a 302/303 to an
    // internal host (192.168.x.x, 127.0.0.1, ::ffff:127.0.0.1,
    // 100.64.x.x CGNAT, etc.) chosen by an attacker who controls a
    // public-looking A2A endpoint. Pivot beneath the SSRF gate.
    // Same fix class as MCP-469; canonical pattern in
    // `talos-engine::approval_gate` / `talos-mcp-handlers::advanced`.
    // MCP-1034: explicit connect_timeout for fast-fail on black-holed
    // A2A endpoint — `timeout_secs` is operator-supplied and may be
    // 60s+, but connect should complete in seconds.
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .connect_timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            // MCP-351 (2026-05-11): reqwest::Error from Client::builder()
            // is typically a TLS / config issue (cert chain, native-tls
            // backend, system-CA load). Surfacing it raw to the operator
            // leaks TLS-backend details about the controller host. Log
            // server-side; return generic.
            tracing::error!(error = %e, "call_a2a_agent: reqwest client build failed");
            return mcp_error(req_id, -32000, "Failed to create HTTP client");
        }
    };

    let resp = match client
        .post(&endpoint_url)
        .header("Content-Type", "application/json")
        .json(&task_request)
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return mcp_error(
                req_id,
                -32000,
                &format!(
                    "A2A request failed: {} — verify the endpoint_url is reachable",
                    e
                ),
            )
        }
    };

    let status = resp.status().as_u16();
    // Bounded read, NOT unbounded `resp.json()`: `endpoint_url` is
    // caller-supplied, so a malicious / misconfigured A2A endpoint returning
    // a multi-GB body would otherwise OOM the controller (talos-http-body).
    let body: serde_json::Value = talos_http_body::read_json_capped(resp)
        .await
        .unwrap_or(serde_json::json!({}));

    if status >= 400 {
        return mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "status": "error",
                "http_status": status,
                "task_id": task_id,
                "endpoint_url": endpoint_url,
                "response": body,
            }))
            .unwrap_or_default(),
        );
    }

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            "status": "sent",
            "task_id": task_id,
            "endpoint_url": endpoint_url,
            "http_status": status,
            "response": body,
            "note": "If response.status is 'working' the remote agent is processing asynchronously. \
                     The task_id can be used to poll for completion if the remote agent supports it."
        }))
        .unwrap_or_default(),
    )
}

// ── JS scaffold generator ─────────────────────────────────────────────────

fn handle_get_js_scaffold(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
) -> JsonRpcResponse {
    // MCP-379 (2026-05-11): strict-parse sibling — see MCP-377.
    // Scaffold-only surface (operator sees commented imports), so the
    // direction-class impact is lower than compile_custom_sandbox,
    // but the typo still leads the operator down a wrong-WIT path.
    let world = match args.get("capability_world") {
        None | Some(serde_json::Value::Null) => "minimal-node",
        Some(v) => match v.as_str() {
            Some(s) => s,
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!(
                        "capability_world must be a string (e.g. 'agent-node'), got {kind}"
                    ),
                );
            }
        },
    };

    let world_comments = match world {
        "minimal-node" => "// No host I/O — pure computation only.",
        "http-node" => {
            "// Available interfaces: HTTP requests, webhooks, GraphQL.\n\
             // import { request } from 'talos:http/outbound';\n\
             // import { send } from 'talos:webhook/outbound';"
        }
        "network-node" => {
            "// Available interfaces: HTTP requests, webhooks, GraphQL, raw sockets.\n\
             // import { request } from 'talos:http/outbound';\n\
             // import { send } from 'talos:webhook/outbound';"
        }
        "secrets-node" => {
            "// Secret access — modules MUST NOT see plaintext. Two correct paths:\n\
             // (Tier-3, recommended) vault:// in HTTP headers — host substitutes at fetch time:\n\
             //   1. set_secret(key_path: 'jira/token', value: '...')\n\
             //   2. update_node_config -> {\"AUTH\": \"vault://jira/token\"}; allowed_secrets: ['jira/token']\n\
             //   3. Read AUTH literal: const auth = parsed.config?.AUTH ?? '';   // 'vault://jira/token'\n\
             //   4. Pass as-is in headers: { Authorization: auth } — host resolves before sending.\n\
             // (Tier-1, when you need a slot in JS): import { getSecret } from 'talos:secrets/get';\n\
             //   const slot = getSecret('jira/token');  // u64 handle, NOT the plaintext\n\
             //   then pass `slot` to fetch_with_bearer / fetch_with_header."
        }
        "filesystem-node" => {
            "// Available interfaces: file read/write.\n\
             // import { read, write } from 'talos:files/fs';"
        }
        "messaging-node" => {
            "// Available interfaces: message publish/request.\n\
             // import { publish, request as msgRequest } from 'talos:messaging/pubsub';"
        }
        "cache-node" => {
            "// Available interfaces: cache get/set/delete.\n\
             // import { get, set, del } from 'talos:cache/kv';"
        }
        "governance-node" => {
            "// Available interfaces: approval requests.\n\
             // import { requestApproval } from 'talos:governance/approval';\n\
             //\n\
             // NOTE: governance-node modules CANNOT run via run_sandbox or test_module.\n\
             // Use lint_sandbox to validate, then trigger_workflow to execute."
        }
        "database-node" => {
            "// Available interfaces: database queries, secrets, LLM.\n\
             // import { executeQuery } from 'talos:database/query';\n\
             // import { getSecret } from 'talos:secrets/vault';\n\
             // import { complete } from 'talos:llm/inference';"
        }
        "agent-node" => {
            "// Available interfaces: LLM, secrets, embeddings, memory, governance,\n\
             // orchestration, events, SSE streams.\n\
             // import { complete } from 'talos:llm/inference';\n\
             // import { getSecret } from 'talos:secrets/vault';\n\
             // import { set, get, search } from 'talos:agent-memory/store';"
        }
        "automation-node" => {
            "// Available interfaces: HTTP, webhooks, secrets, LLM, files, messaging,\n\
             // cache, governance, database.\n\
             // import { request } from 'talos:http/outbound';\n\
             // import { getSecret } from 'talos:secrets/vault';\n\
             // import { complete } from 'talos:llm/inference';\n\
             //\n\
             // vault:// config pattern available for custom sandboxes.\n\
             // Slot TTL: 300s from resolution, per-node scope, auto-released on exit."
        }
        _ => "// No additional host interfaces documented for this world.",
    };

    let scaffold = format!(
        r#"// ── Talos JavaScript Sandbox Scaffold — {world} ────────────────────────
// Toolchain: jco componentize
// 1. Fill in your logic in the `run` function below.
// 2. Input and output are JSON-encoded strings.
// 3. In a workflow, upstream output arrives under parsed.input,
//    not at the top level. Original trigger input is in parsed.__trigger_input__.
// ──────────────────────────────────────────────────────────────────────

{world_comments}

// Template for JS capability world: {world}
export function run(input) {{
    const parsed = JSON.parse(input);

    // ── Input access patterns ──────────────────────────────────────
    // 1. Previous node output:  parsed.input?.field_name
    // 2. Original trigger:      parsed.__trigger_input__?.field_name
    // 3. Node config:           parsed.config?.MY_CONFIG_KEY
    // ────────────────────────────────────────────────────────────────

    // Your logic here
    const result = {{
        message: "Hello from JavaScript module",
        input_received: parsed
    }};

    return JSON.stringify(result);
}}"#,
        world = world,
        world_comments = world_comments,
    );

    let text = format!(
        "**JavaScript scaffold for `{world}`:**\n\n```javascript\n{scaffold}\n```\n\n\
         **Next steps:**\n\
         1. Fill in your logic in the scaffold above\n\
         2. Compile with `jco componentize` targeting the `{world}` world\n\
         3. Use `compile_custom_sandbox` or `add_node_to_workflow` to deploy"
    );

    mcp_text(req_id, &text)
}

// ── Python scaffold generator ─────────────────────────────────────────────

fn handle_get_python_scaffold(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
) -> JsonRpcResponse {
    // MCP-379 (2026-05-11): strict-parse sibling — same as
    // get_js_scaffold above. Scaffold output is operator-visible
    // code; wrong-type silently leads them to import the wrong WIT.
    let world = match args.get("capability_world") {
        None | Some(serde_json::Value::Null) => "minimal-node",
        Some(v) => match v.as_str() {
            Some(s) => s,
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!(
                        "capability_world must be a string (e.g. 'agent-node'), got {kind}"
                    ),
                );
            }
        },
    };

    let world_comments = match world {
        "minimal-node" => "# No host I/O — pure computation only.",
        "http-node" => {
            "# Available interfaces: HTTP requests, webhooks, GraphQL.\n\
             # from talos.http import request, HttpMethod\n\
             # from talos.webhook import send"
        }
        "network-node" => {
            "# Available interfaces: HTTP requests, webhooks, GraphQL, raw sockets.\n\
             # from talos.http import request, HttpMethod\n\
             # from talos.webhook import send"
        }
        "secrets-node" => {
            "# Secret access — modules MUST NOT see plaintext. Two correct paths:\n\
             # (Tier-3, recommended) vault:// in HTTP headers — host substitutes at fetch time:\n\
             #   1. set_secret(key_path='jira/token', value='...')\n\
             #   2. update_node_config -> {\"AUTH\": \"vault://jira/token\"}; allowed_secrets=['jira/token']\n\
             #   3. Read AUTH literal: auth = parsed.get('config', {}).get('AUTH', '')   # 'vault://jira/token'\n\
             #   4. Pass as-is in headers: {'Authorization': auth} — host resolves before sending.\n\
             # (Tier-1, when you need a slot in Python): from talos.secrets import get_secret\n\
             #   slot = get_secret('jira/token')   # u64 handle, NOT the plaintext\n\
             #   then pass `slot` to fetch_with_bearer / fetch_with_header."
        }
        "filesystem-node" => {
            "# Available interfaces: file read/write.\n\
             # from talos.files import read, write"
        }
        "messaging-node" => {
            "# Available interfaces: message publish/request.\n\
             # from talos.messaging import publish, request as msg_request"
        }
        "cache-node" => {
            "# Available interfaces: cache get/set/delete.\n\
             # from talos.cache import get, set, delete"
        }
        "governance-node" => {
            "# Available interfaces: approval requests.\n\
             # from talos.governance import request_approval\n\
             #\n\
             # NOTE: governance-node modules CANNOT run via run_sandbox or test_module.\n\
             # Use lint_sandbox to validate, then trigger_workflow to execute."
        }
        "database-node" => {
            "# Available interfaces: database queries, secrets, LLM.\n\
             # from talos.database import execute_query\n\
             # from talos.secrets import get_secret\n\
             # from talos.llm import complete"
        }
        "agent-node" => {
            "# Available interfaces: LLM, secrets, embeddings, memory, governance,\n\
             # orchestration, events, SSE streams.\n\
             # from talos.llm import complete\n\
             # from talos.secrets import get_secret\n\
             # from talos.agent_memory import set, get, search"
        }
        "automation-node" => {
            "# Available interfaces: HTTP, webhooks, secrets, LLM, files, messaging,\n\
             # cache, governance, database.\n\
             # from talos.http import request\n\
             # from talos.secrets import get_secret\n\
             # from talos.llm import complete\n\
             #\n\
             # vault:// config pattern available for custom sandboxes.\n\
             # Slot TTL: 300s from resolution, per-node scope, auto-released on exit."
        }
        _ => "# No additional host interfaces documented for this world.",
    };

    let scaffold = format!(
        r#"# ── Talos Python Sandbox Scaffold — {world} ──────────────────────────────
# Toolchain: componentize-py
# 1. Fill in your logic in the `run` function below.
# 2. Input and output are JSON-encoded strings.
# 3. In a workflow, upstream output arrives under parsed["input"],
#    not at the top level. Original trigger input is in parsed["__trigger_input__"].
# ──────────────────────────────────────────────────────────────────────────

{world_comments}

# Template for Python capability world: {world}
import json

def run(input: str) -> str:
    parsed = json.loads(input)

    # ── Input access patterns ──────────────────────────────────────
    # 1. Previous node output:  parsed.get("input", {{}}).get("field_name")
    # 2. Original trigger:      parsed.get("__trigger_input__", {{}}).get("field_name")
    # 3. Node config:           parsed.get("config", {{}}).get("MY_CONFIG_KEY", "default")
    # ────────────────────────────────────────────────────────────────

    # Your logic here
    result = {{
        "message": "Hello from Python module",
        "input_received": parsed
    }}

    return json.dumps(result)"#,
        world = world,
        world_comments = world_comments,
    );

    let text = format!(
        "**Python scaffold for `{world}`:**\n\n```python\n{scaffold}\n```\n\n\
         **Next steps:**\n\
         1. Fill in your logic in the scaffold above\n\
         2. Compile with `componentize-py` targeting the `{world}` world\n\
         3. Use `compile_custom_sandbox` or `add_node_to_workflow` to deploy"
    );

    mcp_text(req_id, &text)
}

// ── Secret access audit log ───────────────────────────────────────────────

async fn handle_get_secret_access_log(
    req_id: Option<serde_json::Value>,
    args: &serde_json::Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    // MCP-331 (2026-05-11): `SecretsManager::list_secret_access_log`
    // queries `secret_audit_log` joined to `secrets` with NO user
    // filter — every row across every tenant comes back. The pre-fix
    // gate was the agent-level `is_admin` (per-tenant); an
    // organization-scoped admin agent in a multi-tenant deployment
    // could read every other tenant's secret-access trail (which
    // secrets, accessed when, by which actor, from which IP) — a
    // cross-tenant audit-log disclosure. Same require_platform_admin
    // family as MCP-323/324/325/326/327/328/329/330. Use the
    // `users.is_platform_admin` column.
    //
    // The right per-tenant path would be a user-scoped variant that
    // joins on `secrets.created_by = $user_id` — separate work; this
    // patch closes the cross-tenant leak fail-closed.
    let is_platform_admin = state
        .actor_repo
        .is_platform_admin(user_id)
        .await
        .unwrap_or(false);
    if !is_platform_admin {
        return mcp_error(
            req_id,
            -32601,
            "get_secret_access_log requires platform-admin privileges. \
             The audit-log query spans every tenant's secret accesses.",
        );
    }

    // MCP-258 (2026-05-10): trim key_path so `"   "` falls through to None
    // instead of running SQL `WHERE key_path = '   '` and silently
    // returning zero rows. Same MCP-249 family.
    let key_path_owned: Option<String> = args
        .get("key_path")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from);
    let key_path: Option<&str> = key_path_owned.as_deref();
    // MCP-258 (2026-05-10): pre-fix `as_f64().unwrap_or(24.0)` silently
    // substituted the default for any wrong-type (`hours: "24"` string),
    // negative values (yielding an interval-in-future for no rows), and
    // NaN/Inf (Postgres make_interval would error mid-query). Range
    // [0.01, 8760] covers minutes-to-1-year.
    let hours: f64 = match args.get("hours") {
        None | Some(serde_json::Value::Null) => 24.0,
        Some(v) => match v.as_f64() {
            Some(h) if !h.is_finite() => {
                return mcp_error(req_id, -32602, "hours must be a finite number")
            }
            Some(h) if !(0.01..=8760.0).contains(&h) => {
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("hours must be in [0.01, 8760], got {h}"),
                )
            }
            Some(h) => h,
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("hours must be a number, got {kind}"),
                );
            }
        },
    };
    // MCP-184 (2026-05-08): replace silent-clamp with explicit
    // validation. Pre-fix `unwrap_or(50).min(500)` silently capped
    // out-of-range limits.
    let limit: i64 = match crate::utils::validate_range_i64(args, "limit", 1, 500, 50, &req_id) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    match state
        .secrets_manager
        .list_secret_access_log(key_path, hours, limit)
        .await
    {
        Ok(rows) => {
            let entries: Vec<serde_json::Value> = rows
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "id": r.id.to_string(),
                        "secret_name": r.secret_name.clone().unwrap_or_default(),
                        "action": r.action,
                        "actor_type": r.actor_type,
                        "actor": r.actor.clone().unwrap_or_default(),
                        "ip_address": r.ip_address.clone().unwrap_or_default(),
                        "created_at": r.created_at.to_rfc3339(),
                    })
                })
                .collect();

            let result = serde_json::json!({
                "entries": entries,
                "count": entries.len(),
                "filter": {
                    "key_path": key_path,
                    "hours": hours,
                    "limit": limit,
                },
            });
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&result).unwrap_or_default(),
            )
        }
        Err(e) => {
            // Table may not exist in some environments
            let err_str = e.to_string();
            if err_str.contains("does not exist") || err_str.contains("relation") {
                mcp_text(
                    req_id,
                    &serde_json::to_string_pretty(&serde_json::json!({
                        "entries": [],
                        "count": 0,
                        "note": "secret_audit_log table not found — secret auditing may not be enabled in this environment."
                    }))
                    .unwrap_or_default(),
                )
            } else {
                tracing::error!("get_secret_access_log query failed: {:#}", e);
                mcp_error(req_id, -32000, "Failed to query secret access log")
            }
        }
    }
}
