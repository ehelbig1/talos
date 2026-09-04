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
            "name": "whoami",
            "description": "Return the identity this MCP token authenticates as — the user (id + email), the MCP agent (name + role), the personal organization, and the capability ceiling. USE THIS FIRST when resources you created via MCP (workflows, actors, secrets) don't appear in the web UI: every resource is owned by the user_id returned here, and Talos row-level security only shows it to a UI session logged in as the SAME email. If that email differs from your browser login, that mismatch is the cause — create the MCP token under your own account (in the UI) so ownership matches.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }),
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
            "description": "Get Talos platform metadata: version, tool count, database status, uptime, feature capabilities, and a 'fleet' section — every ACTIVE registered worker with the build it reported at registration, PLUS every worker pinned in the controller's static TALOS_WORKER_PUBLIC_KEYS ring (source: 'static-env'), and a build_skew flag when a worker's commit provably differs from the controller's. Use it to answer 'are the controller and workers running the same build?' before chasing a signature-verification failure. build_version is worker-self-reported and diagnostic only (never an authorization input); null means a pre-handshake worker or a static-env worker that cannot report at all, and build_status 'unverifiable' is not the same as 'match'. The two sources are NEVER deduped, so one worker_id legitimately appears twice (once per source) — that is a disagreement to read, not a duplicate to collapse; read the 'note' field for what each count is defined over.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }),
        serde_json::json!({
            "name": "get_public_url_status",
            "description": "Show the resolved PUBLIC base URL (explicit TALOS_PUBLIC_BASE_URL, ngrok tunnel discovery, or localhost fallback) and per-integration guidance: which externally-registered endpoints (GCP Pub/Sub push subscriptions, Google watch webhooks, inbound webhooks, approval links) update automatically vs. need the printed commands after a URL change.",
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
            "description": "Programmatic security posture check. Validates encryption keys, JWT configuration, audit triggers, CORS, TLS settings, and whether the registered worker fleet enforces the per-actor write ceiling. Returns a scored assessment with actionable recommendations. Every check carries a 'verification' level: 'not_verified' means the check could NOT run, and describes what was not learned — it is never a pass. The write-ceiling check is reported but unscored (its flag is default-off by design, so a deployment using the default is not marked down for it).",
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
        "whoami" => Some(handle_whoami(req_id, state, agent).await),
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
        "get_public_url_status" => Some(handle_get_public_url_status(req_id)),
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

/// `whoami` — surface the identity this MCP token resolves to so an
/// identity/tenancy mismatch (the #1 "my workflows don't show in the UI"
/// cause) is diagnosable in one call. Reads only the caller's own
/// identity + user row; no cross-tenant exposure.
async fn handle_whoami(
    req_id: Option<serde_json::Value>,
    state: &McpState,
    agent: Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let repo = &state.actor_repo;
    let (email, org, ceiling, is_admin) = match agent.user_id {
        Some(uid) => {
            let email = repo.get_user_email(uid).await.ok().flatten();
            let org = repo.get_user_org_summary(uid).await.ok().flatten();
            let ceiling = repo
                .get_user_max_capability_world(uid)
                .await
                .ok()
                .flatten()
                .unwrap_or_else(|| "http-node".to_string());
            let is_admin = repo.is_platform_admin(uid).await.unwrap_or(false);
            (email, org, ceiling, is_admin)
        }
        None => (None, None, "http-node".to_string(), false),
    };
    let body = serde_json::json!({
        "agent": {
            "id": agent.agent_id.to_string(),
            "name": agent.name,
            "role": agent.role_name,
        },
        "user": {
            "id": agent.user_id.map(|u| u.to_string()),
            "email": email,
        },
        "organization": org.map(|(id, name)| serde_json::json!({
            "id": id.to_string(),
            "name": name,
        })),
        "capability_ceiling": ceiling,
        "is_platform_admin": is_admin,
        "visibility_note": "Resources you create via MCP (workflows, actors, secrets) are owned by \
                            the user above. Under row-level security they appear in the web UI ONLY \
                            to a browser session logged in as this same email. If your UI shows an \
                            empty list, your browser login is a different user than this token — \
                            create the MCP token under your own account (UI → API keys / MCP agents) \
                            so ownership matches.",
    });
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&body).unwrap_or_default(),
    )
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
        // calling `llm::complete` routinely need 20–45s for Ollama synthesis (and
        // longer on CPU-bound local models), can exceed 30s on Anthropic for larger
        // prompts, and a single module commonly chains HTTP + LLM + HTTP. 120s
        // matches the worker's single-op ceiling (EXTERNAL_LLM/HTTP = 120s) so the
        // controller doesn't abandon a still-working node; operators can still
        // override via WASM_EXECUTION_TIMEOUT_SECS or the set_wasm_config tool.
        // Keep in lockstep with DEFAULT_NODE_TIMEOUT_SECS (talos-workflow-engine).
        "execution_timeout_secs": nonzero_u64("WASM_EXECUTION_TIMEOUT_SECS", 120),
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
    let read_optional_u64 =
        |field: &str, min: u64, max: u64| -> Result<Option<u64>, JsonRpcResponse> {
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
                            &format!("{field} must be a non-negative integer, got {kind}"),
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

/// Public base-URL status + per-integration guidance. Pure formatting
/// over `talos_public_url` state — no DB, no auth-sensitive data (the
/// URL itself is public by definition; push tokens are NOT echoed).
fn handle_get_public_url_status(req_id: Option<serde_json::Value>) -> JsonRpcResponse {
    let (base, source) = talos_public_url::resolve(talos_config::get_base_url);
    let discovered = talos_public_url::discovered();
    let publicly_reachable = source != talos_public_url::UrlSource::Fallback;

    let guidance = serde_json::json!([
        {
            "integration": "inbound_webhooks",
            "automatic": true,
            "detail": format!(
                "Webhook URLs are formatted with the public base at display time — \
                 re-run list_webhooks/create_webhook to see {base}/webhooks/<id>. \
                 Nothing is registered provider-side, so URL changes are free."
            )
        },
        {
            "integration": "approval_links",
            "automatic": true,
            "detail": "Approval-gate and callback links format with the public base when generated. Links minted BEFORE a URL change keep the old origin — re-fire the gate if one goes stale."
        },
        {
            "integration": "gcp_pubsub_push",
            "automatic": false,
            "detail": format!(
                "Each GCP watch's push endpoint is {base}/api/gcp/pubsub/<push_token> \
                 (create_watch_channel returns the full URL; list endpoints via the \
                 watch-channels API). After a URL change, update the subscription: \
                 gcloud pubsub subscriptions update <SUB> \
                 --push-endpoint='{base}/api/gcp/pubsub/<push_token>' \
                 --push-auth-service-account=<SA_EMAIL>. A reserved ngrok domain \
                 (NGROK_STATIC_DOMAIN) makes this a one-time setup."
            )
        },
        {
            "integration": "google_calendar_watch",
            "automatic": false,
            "detail": format!(
                "Google registers the channel address at watch-creation time. After a \
                 URL change, stop + re-create the watch channel so Google learns \
                 {base}/api/google-calendar/webhook. (Google requires https and \
                 rejects localhost — a tunnel or public deploy is mandatory for GCal.)"
            )
        },
        {
            "integration": "oauth_redirect_uris",
            "automatic": true,
            "detail": "OAuth callbacks deliberately stay on FRONTEND_URL (browser-mediated; localhost works in dev and the provider console allowlists it). No action needed unless you want to run the consent flow THROUGH the tunnel — then add the public callback URLs to the provider console once."
        }
    ]);

    let result = serde_json::json!({
        "public_base_url": base,
        "source": source.as_str(),
        "publicly_reachable": publicly_reachable,
        "ngrok": {
            // Empty-env class (MCP-625): `.is_ok()` reported CONFIGURED for
            // `TALOS_NGROK_API_URL=""`, but `talos_public_url::spawn_discovery`
            // trims the value and returns early when it is empty — the
            // discovery loop never starts. The operator then read
            // `agent_api_configured: true` + `agent_api_reachable: false` and
            // went looking for a network fault, when nothing was configured.
            "agent_api_configured": talos_config::env_var_is_set_nonempty("TALOS_NGROK_API_URL"),
            "agent_api_reachable": talos_public_url::ngrok_api_reachable(),
            "discovered_url": discovered,
        },
        "note": if publicly_reachable {
            "Externally-reachable endpoints format with this origin."
        } else {
            "No public origin active — push-based integrations (GCP Pub/Sub, Google watches) \
             cannot reach this stack. Start the tunnel: add NGROK_AUTHTOKEN to .env and \
             `make up` (compose profile `public`), or set TALOS_PUBLIC_BASE_URL explicitly."
        },
        "guidance": guidance,
    });
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

/// Assemble `get_platform_info.fleet` — the controller↔worker build-identity
/// report. Reads the ACTIVE `worker_identities` rows through the repository
/// (bounded + deterministically ordered there) and classifies each against this
/// controller's build.
///
/// THREE states per worker, deliberately kept apart:
/// * `"match"`      — same commit sha; the fleet agrees here.
/// * `"skew"`       — both sides report a real sha and they DIFFER (including
///                    a `-dirty` suffix on one side only: same commit, but a
///                    dirty tree corresponds to no commit, so the bytes differ).
///                    The actionable one: version-coupled signed wire formats
///                    (job dispatch, memory RPC, envelope sealing) break in
///                    ways that look like signature bugs.
/// * `"unverifiable"` — one side reported nothing (a pre-handshake worker), or
///                    an `unknown` sha (built with no git checkout and no
///                    `GIT_SHA_OVERRIDE`). NOT a match: absence of evidence is
///                    not evidence of agreement (#578). `build_skew` therefore
///                    counts only the PROVEN differences, and
///                    `unverifiable_workers` is reported alongside it so an
///                    operator never reads a clean `build_skew: false` as
///                    "everything checked out".
///
/// TWO SOURCES, deliberately not merged into one identity. `source` is a closed
/// set:
/// * `"registered"` — a `worker_identities` row: the worker proved possession of
///   its key against the registration endpoint and reported a build.
/// * `"static-env"` — an entry in the controller's operator-pinned
///   `TALOS_WORKER_PUBLIC_KEYS` ring. Such a worker never contacts the
///   registration endpoint, so it has NO row, reports NO build, and was
///   structurally invisible here until this merge (the dev stack's only real
///   worker was missing from the report for exactly this reason).
///
/// A DB failure degrades to an `error` field rather than failing the whole
/// platform-info call — the rest of the response is still useful, and this
/// section is diagnostic. The message is the generic one; details go to the log.
/// Read the fleet's write-ceiling enforcement posture. `None` = the registry
/// read FAILED, which every consumer must report as "not verified" rather than
/// as an absence of enforcement — the two are different findings and only one
/// of them is about the database.
///
/// ONE query, and one per calling surface: `get_platform_info` already reads
/// the same rows for its build report, so this is used by the surfaces that
/// need the summary WITHOUT the build listing (`security_audit`,
/// `set_actor_write_ceiling`, `get_actor_summary`,
/// `get_my_capability_ceiling`).
pub(crate) async fn read_write_ceiling_fleet(
    db_pool: &sqlx::PgPool,
) -> Option<talos_worker_identity_repository::WriteCeilingFleetSummary> {
    let repo = talos_worker_identity_repository::WorkerIdentityRepository::new(db_pool.clone());
    match repo.list_active_builds().await {
        Ok(rows) => {
            Some(talos_worker_identity_repository::summarize_write_ceiling_enforcement(&rows))
        }
        Err(e) => {
            tracing::warn!(
                error = %format!("{e:#}"),
                "write-ceiling fleet summary unavailable; surfaces must report it as unverified"
            );
            None
        }
    }
}

async fn build_fleet_report(db_pool: &sqlx::PgPool, controller_build: &str) -> serde_json::Value {
    use talos_worker_identity_repository::WorkerIdentityRepository;

    let repo = WorkerIdentityRepository::new(db_pool.clone());
    let rows = match repo.list_active_builds().await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!("fleet build-identity listing failed: {:#}", e);
            return serde_json::json!({
                "controller_build": controller_build,
                "error": "fleet registry unavailable",
            });
        }
    };

    assemble_fleet_report(
        controller_build,
        &rows,
        &talos_workflow_job_protocol::static_worker_ring(),
    )
}

/// Pure assembly of the fleet report — split from the DB read so every
/// classification, count and merge rule is unit-testable without a Postgres
/// (the whole surface was untestable while it lived inside the async fetch).
///
/// `static_ring` is `(worker_id, key_count)` from
/// [`talos_workflow_job_protocol::static_worker_ring`] — ids and counts only,
/// never key bytes.
fn assemble_fleet_report(
    controller_build: &str,
    rows: &[talos_worker_identity_repository::WorkerBuildRow],
    static_ring: &[(String, usize)],
) -> serde_json::Value {
    use talos_worker_identity_repository::{
        build_is_verifiable, builds_match, MAX_FLEET_BUILD_ROWS,
    };

    let controller_verifiable = build_is_verifiable(controller_build);
    let mut skew = 0usize;
    let mut unverifiable = 0usize;
    let mut workers: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            let status = match r.build_version.as_deref() {
                Some(wb) if builds_match(controller_build, wb) => "match",
                Some(wb) if controller_verifiable && build_is_verifiable(wb) => {
                    skew += 1;
                    "skew"
                }
                _ => {
                    unverifiable += 1;
                    "unverifiable"
                }
            };
            serde_json::json!({
                "worker_id": r.worker_id,
                "source": "registered",
                // null = this worker registered before the build-identity
                // handshake existed (or through the operator CLI, which has no
                // build to report) — NOT "unknown build of a new worker".
                "build_version": r.build_version,
                "build_status": status,
                "supports_sealing": r.supports_sealing,
                "last_seen_at": r.last_seen_at.to_rfc3339(),
                // null = this row has NEVER proved liveness, which means
                // UNKNOWN, not departed — the automatic reaper deliberately
                // refuses to act on it. A timestamp means the worker held this
                // key's private half at that instant, and its key is trusted
                // for at most TALOS_WORKER_IDENTITY_REAP_HOURS past it plus the
                // reaper sweep interval plus one worker-key overlay refresh
                // (see DEFAULT_REAP_SILENCE_HOURS) — and only while the reaper
                // is enabled at all, which it is not by default.
                // `last_seen_at` above is BOOT REGISTRATION only and is not a
                // liveness signal; do not read the two the same way.
                "last_liveness_at": r.last_liveness_at.map(|t| t.to_rfc3339()),
                // What THIS worker reported about the per-actor write ceiling
                // it will enforce. null = UNREPORTED (a pre-feature worker, or
                // an operator-CLI registration), which is NOT the same as
                // `false` — see `write_ceiling` below for the fleet answer.
                // Diagnostic only, on exactly the `build_version` terms.
                "write_ceiling_enforced": r.write_ceiling_enforced,
                // Subordinate to the above: inert while enforcement is off.
                "write_ceiling_strict_egress": r.write_ceiling_strict_egress,
            })
        })
        .collect();

    // NO DEDUPE against the registered rows, on purpose. A worker_id present in
    // BOTH sources appears TWICE — once per source — because the two rows are
    // claims from different trust roots: one is what the worker proved and
    // reported about itself, the other is what the operator pinned in this
    // controller's env. Collapsing them would hide precisely the disagreement an
    // operator needs to see (a stale env pin next to a live registration), the
    // same reason `list_active_builds` refuses to collapse a worker's two
    // rotation keys into one row.
    //
    // Capped by the SAME runaway guard the DB listing uses. `TALOS_WORKER_PUBLIC_KEYS`
    // is operator-authored, so a huge ring is self-inflicted rather than
    // adversarial — but this section rides inside `get_platform_info`, a
    // general-purpose response every MCP client parses, and a 10k-entry env
    // would blow that tool up for a reason unrelated to it. Same posture as
    // MAX_FLEET_BUILD_ROWS on the DB side: a runaway guard, not pagination, with
    // `truncated` saying so.
    let static_cap = MAX_FLEET_BUILD_ROWS as usize;
    let static_truncated = static_ring.len() > static_cap;
    let static_shown = static_ring.len().min(static_cap);
    for (worker_id, key_count) in static_ring.iter().take(static_shown) {
        workers.push(serde_json::json!({
            "worker_id": worker_id,
            "source": "static-env",
            // Nothing about a static-ring entry is self-reported: the env pins
            // an id and its key(s), full stop. build_version/last_seen_at are
            // null because there is no report, and supports_sealing is null
            // rather than false because the ring format carries no sealing bit —
            // `false` would read as "this worker said it cannot seal", a claim
            // the ring cannot make.
            "build_version": serde_json::Value::Null,
            "build_status": "unverifiable",
            "static_key_count": key_count,
            "supports_sealing": serde_json::Value::Null,
            "last_seen_at": serde_json::Value::Null,
            // A statically-keyed worker never calls the registration endpoint,
            // so it reports NOTHING about write-ceiling enforcement — the same
            // reason it can report no build. Emitted as explicit nulls rather
            // than omitted so the two sources have one shape and a reader
            // cannot mistake absence for `false`.
            "write_ceiling_enforced": serde_json::Value::Null,
            "write_ceiling_strict_egress": serde_json::Value::Null,
        }));
        unverifiable += 1;
    }

    // "How many workers do I actually have?" — the one question `worker_count`
    // does NOT answer. That is a ROW count: a worker mid key-rotation is two
    // rows, and a worker in both sources is two more. Left as-is for
    // back-compat and disambiguated by an ADDED field rather than a rename
    // (misleading-report-field rule, #579/#580).
    let distinct_ids: std::collections::HashSet<&str> = rows
        .iter()
        .map(|r| r.worker_id.as_str())
        .chain(
            static_ring
                .iter()
                .take(static_shown)
                .map(|(w, _)| w.as_str()),
        )
        .collect();

    serde_json::json!({
        "controller_build": controller_build,
        "workers": workers,
        // ROWS in `workers`, not distinct workers — see `distinct_worker_ids`.
        "worker_count": workers.len(),
        "distinct_worker_ids": distinct_ids.len(),
        "registered_workers": rows.len(),
        // Rows IN THIS REPORT, not fleet totals — both sources are capped (see
        // `truncated`). Keeping this equal to the emitted static rows is what
        // makes the note's `unverifiable_workers - static_env_workers`
        // arithmetic hold in the capped case too.
        "static_env_workers": static_shown,
        // Only PROVEN disagreement, and only among REGISTERED rows — a static
        // entry reports no build at all, so it can never contribute skew. A
        // static-only fleet therefore reads `build_skew: false` with every
        // worker unverifiable, which is the honest answer.
        "build_skew": skew > 0,
        "skewed_workers": skew,
        "unverifiable_workers": unverifiable,
        // The fleet's write-ceiling ENFORCEMENT posture. Derived from the
        // REGISTERED rows only (a static-env worker reports nothing), by the
        // one shared summariser every other surface also renders, so
        // get_platform_info, set_actor_write_ceiling, get_actor_summary,
        // get_my_capability_ceiling and security_audit cannot word the same
        // fleet differently.
        "write_ceiling": talos_worker_identity_repository::
            summarize_write_ceiling_enforcement(rows).to_json(),
        // PER SOURCE, never of the merged array length: static rows are appended
        // after the DB LIMIT, so they must not make a short listing look
        // truncated — and a capped ring must not be silently dropped just
        // because the listing was short. True when EITHER source was cut.
        "truncated": rows.len() as i64 >= MAX_FLEET_BUILD_ROWS || static_truncated,
        "note": "TWO SOURCES, never deduped. source='registered': one entry per ACTIVE registered \
                 (worker_id, signing key) — a worker mid key-rotation appears twice by design. \
                 source='static-env': a worker_id pinned in this controller's TALOS_WORKER_PUBLIC_KEYS \
                 ring; it authenticates without ever calling the registration endpoint, so it has no row, \
                 no last_seen_at and CANNOT report a build — its 'unverifiable' means 'this deployment \
                 has not enabled worker self-registration', not 'a registered worker went quiet'. The \
                 same worker_id may legitimately appear under both sources (different trust roots: what \
                 the worker proved vs. what the operator pinned); disagreement between them is signal. \
                 unverifiable_workers counts BOTH, and every static_env_workers entry is in it by \
                 construction, so registered-but-silent = unverifiable_workers - static_env_workers. \
                 build_version is worker-self-reported and NOT covered by the registration \
                 proof-of-possession: it is diagnostic only and never gates authorization. null \
                 build_version on a registered row = a pre-handshake worker (or an operator-CLI \
                 registration) that never reported one. build_status 'unverifiable' means one side has no \
                 usable commit sha — that is not the same as 'match'. worker_count is the number of ROWS \
                 in 'workers' (rotation keys and both-source workers each add one); distinct_worker_ids \
                 is the answer to 'how many workers do I have'. Every count above describes the rows IN \
                 THIS REPORT: each source is independently capped at 200 rows and 'truncated' is true \
                 when either one was cut. write_ceiling summarises the per-actor write-ceiling \
                 ENFORCEMENT posture over the REGISTERED rows ONLY, because a static-env worker never \
                 registers and so reports nothing — a static-only fleet therefore reads \
                 enforced_by='unknown' with registered_rows=0, which is the honest answer and not \
                 'none'. enforced_by is 'all' | 'some' | 'none' | 'unknown': 'some' is the dangerous \
                 one, because nothing routes jobs by enforcement posture, so a readonly actor's job may \
                 land on the worker that does not enforce. Unreported rows are counted separately and \
                 never folded into not_enforcing. Like build_version these bits are worker-self-reported \
                 and outside the registration proof-of-possession: diagnostic only, never an \
                 authorization input.",
    })
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

    // Fleet build-identity handshake: which build is each registered worker
    // actually running, and does it agree with this controller?
    //
    // "Are the controller and worker on the same build?" was unanswerable
    // during the 2026-07-27 signing outage without comparing image digests by
    // hand — it cost a wrong hypothesis and several diagnostic turns. Signed
    // wire formats are version-coupled three ways (job dispatch #598, memory
    // RPC #600, envelope sealing), so this belongs next to `build_version`.
    //
    // The read goes through the repository (no raw sqlx in a handler — check 6).
    let fleet = build_fleet_report(&state.db_pool, &build_version).await;

    // A COMPILE-TIME list of what this BUILD contains. Nothing here reads
    // runtime state, and the accompanying `features_note` says so — because
    // this list has already made a false claim: `execution_archival` was
    // advertised for the ~5 months in which the archival pass archived exactly
    // zero rows (#746). A list that reads no state is a claim about the build,
    // and it must be labelled as one.
    //
    // Deliberately NOT measured, and the reason is not cost. Measuring ONE
    // entry would imply the other eleven are measured too — a reader has no way
    // to tell which is which — so a per-entry probe is all-or-nothing, and
    // eleven probes is not what `get_platform_info` should be. The surfaces
    // that DO measure are named in the note.
    //
    // Deliberately NOT renamed either: `features` is an existing response key,
    // and the house rule for a misleading field is to disambiguate with an
    // ADDED field rather than a rename (#579/#580).
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
        "features_note": "BUILD CAPABILITIES, NOT RUNTIME STATE. This is a compile-time list of \
                          what this controller binary contains; no entry is verified against a \
                          live database, a running worker, or any configuration flag. An entry \
                          therefore means 'this build can do it', never 'this deployment is doing \
                          it' — 'execution_archival' was listed here throughout the period in \
                          which the archival pass archived zero rows. For measured answers use \
                          'fleet' (registered workers, their builds, and their write-ceiling \
                          enforcement posture) in this same response, get_archive_policy, \
                          get_system_health, and security_audit, each of which reports what it \
                          could NOT establish rather than defaulting.",
        "fleet": fleet,
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
        Err(_) => return mcp_error(req_id, -32000, "Failed to serialize import outcome"),
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

/// Thin protocol wrapper. Every check, every probe and every rendering rule
/// lives in `talos-security-audit`, where each one is unit-testable — including
/// the present-but-non-functional cases, which are the whole reason the audit
/// was rewritten from presence tests into verifications.
async fn handle_security_audit(
    req_id: Option<serde_json::Value>,
    state: &McpState,
) -> JsonRpcResponse {
    let sysrepo = talos_system_repo::SystemRepository::new(state.db_pool.clone());
    let write_ceiling_fleet = read_write_ceiling_fleet(&state.db_pool).await;
    let result = talos_security_audit::run_security_audit(
        &sysrepo,
        state.secrets_manager.as_ref(),
        write_ceiling_fleet,
    )
    .await;
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
    // Built via the shared SSRF-safe builder: redirect(none) + the connect-time
    // ControllerSsrfResolver closing the DNS-rebinding TOCTOU the call-time
    // `check_outbound_url_no_ssrf` (above) can't. `endpoint_url` is fully
    // caller-supplied, so without the resolver an attacker controlling its DNS
    // could rebind it to 169.254.169.254 / the controller's own datastores after
    // validation. `timeout_secs` is operator-supplied (may be 60s+).
    let client = match talos_http_utils::outbound::build_outbound_webhook_client_with_timeout(
        "talos-a2a/1.0",
        std::time::Duration::from_secs(timeout_secs),
    ) {
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
                    &format!("capability_world must be a string (e.g. 'agent-node'), got {kind}"),
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
         2. Submit it via `compile_custom_sandbox` with `language: \"javascript\"` and \
         `capability_world: \"{world}\"` — the server compiles it sandboxed via jco \
         (no local toolchain needed; `dependencies` must be omitted)"
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
                    &format!("capability_world must be a string (e.g. 'agent-node'), got {kind}"),
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
         2. Submit it via `compile_custom_sandbox` with `language: \"python\"` and \
         `capability_world: \"{world}\"` — the server compiles it sandboxed via \
         componentize-py (no local toolchain needed; a module-level \
         `def run(input: str) -> str` is adapted automatically; `dependencies` \
         must be omitted)"
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
    // allow-benign-default: fail-CLOSED admin gate. A failed read denies the
    // operation, costing the caller a refusal rather than granting anything —
    // the second shape check 74's opt-out admits. Direction, not disclosure,
    // is what makes this one correct.
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

/// `read_write_ceiling_fleet` must distinguish a FAILED read from an EMPTY
/// fleet. No live database required: a lazily-connected pool aimed at a dead
/// port makes the query fail for real.
#[cfg(test)]
mod write_ceiling_read_tests {
    /// A registry read that FAILS must return `None`, never an empty summary.
    ///
    /// The two render differently on purpose and the difference is what an
    /// operator acts on: `None` says "the database could not be read", an
    /// empty fleet says "no worker has registered". Collapsing the error into
    /// `Some(summarize(&[]))` is a one-token change that compiles, keeps the
    /// advisory verdict correct, and sends an operator to investigate their
    /// fleet during a Postgres outage — the same misdiagnosis class as
    /// answering "not found" for a row you could not read (#736/#749).
    ///
    /// This test exists because the mutation SURVIVED every other test here.
    #[tokio::test]
    async fn a_failed_registry_read_is_none_not_an_empty_fleet() {
        let dead = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_millis(600))
            .connect_lazy("postgres://nobody:nobody@127.0.0.1:1/nope")
            .expect("connect_lazy never dials");

        let got = super::read_write_ceiling_fleet(&dead).await;
        assert!(
            got.is_none(),
            "an unreadable registry must be None; got a summary, which would be \
             rendered as a statement about the fleet rather than about the database"
        );
        // ...and the shared renderer turns that into a database finding.
        let j = talos_worker_identity_repository::render_write_ceiling_enforcement(got);
        assert_eq!(j["enforced_by"], "unknown");
        assert!(j["note"].as_str().unwrap().contains("database problem"));
        assert!(j["registered_rows"].is_null(), "nothing was counted");
    }
}

#[cfg(test)]
mod fleet_report_tests {
    use super::assemble_fleet_report;
    use talos_worker_identity_repository::WorkerBuildRow;

    fn row(worker_id: &str, build: Option<&str>) -> WorkerBuildRow {
        WorkerBuildRow {
            worker_id: worker_id.to_string(),
            build_version: build.map(str::to_string),
            supports_sealing: false,
            last_seen_at: chrono::Utc::now(),
            last_liveness_at: None,
            // Unreported by default — the pre-feature-worker shape, and the
            // state the existing build tests should be indifferent to.
            write_ceiling_enforced: None,
            write_ceiling_strict_egress: None,
        }
    }

    /// A row reporting a write-ceiling enforcement posture.
    fn ceiling_row(
        worker_id: &str,
        enforced: Option<bool>,
        strict: Option<bool>,
    ) -> WorkerBuildRow {
        WorkerBuildRow {
            write_ceiling_enforced: enforced,
            write_ceiling_strict_egress: strict,
            ..row(worker_id, Some("0.1.0+aaaaaaa"))
        }
    }

    // ── write-ceiling enforcement in the fleet report ─────────────────────

    /// The per-worker bits reach the registered rows, unswapped, and an
    /// unreported row renders as JSON `null` rather than `false`.
    #[test]
    fn registered_rows_carry_the_write_ceiling_bits() {
        let r = assemble_fleet_report(
            "0.1.0+aaaaaaa",
            &[
                ceiling_row("enforcing", Some(true), Some(false)),
                ceiling_row("silent", None, None),
            ],
            &[],
        );
        let ws = workers(&r);
        assert_eq!(ws[0]["write_ceiling_enforced"], true);
        assert_eq!(ws[0]["write_ceiling_strict_egress"], false);
        assert!(
            ws[1]["write_ceiling_enforced"].is_null(),
            "unreported must be null, never false — the two are different claims"
        );
    }

    /// A statically-keyed worker never registers, so it reports nothing. The
    /// keys are emitted as explicit nulls rather than omitted so both sources
    /// have ONE shape and a reader cannot mistake an absent key for `false`.
    #[test]
    fn static_env_rows_report_no_enforcement_explicitly() {
        let r = assemble_fleet_report("0.1.0+aaaaaaa", &[], &ring(&[("pinned", 1)]));
        let ws = workers(&r);
        assert_eq!(ws[0]["source"], "static-env");
        assert!(ws[0].get("write_ceiling_enforced").is_some());
        assert!(ws[0]["write_ceiling_enforced"].is_null());
        assert!(ws[0]["write_ceiling_strict_egress"].is_null());
    }

    /// The fleet-level summary is present and is the SHARED one — the same
    /// `enforced_by` vocabulary every other surface renders.
    #[test]
    fn the_fleet_summary_is_present_and_shared() {
        let r = assemble_fleet_report(
            "0.1.0+aaaaaaa",
            &[
                ceiling_row("a", Some(true), Some(true)),
                ceiling_row("b", Some(false), None),
            ],
            &[],
        );
        assert_eq!(r["write_ceiling"]["enforced_by"], "some");
        assert_eq!(r["write_ceiling"]["enforcing"], 1);
        assert_eq!(r["write_ceiling"]["not_enforcing"], 1);
        assert_eq!(r["write_ceiling"]["strict_egress_effective"], 1);
    }

    /// A STATIC-ONLY fleet must read `unknown`, not `none`.
    ///
    /// The summary is over REGISTERED rows, and a static worker has none — so
    /// the tempting answer ("nobody reports enforcement, therefore nothing
    /// enforces") is exactly the unmeasured claim this feature exists to stop.
    #[test]
    fn a_static_only_fleet_is_unknown_not_none() {
        let r = assemble_fleet_report("0.1.0+aaaaaaa", &[], &ring(&[("pinned", 2)]));
        assert_eq!(r["write_ceiling"]["enforced_by"], "unknown");
        assert_eq!(r["write_ceiling"]["registered_rows"], 0);
    }

    fn ring(entries: &[(&str, usize)]) -> Vec<(String, usize)> {
        entries
            .iter()
            .map(|(w, n)| ((*w).to_string(), *n))
            .collect()
    }

    fn workers(report: &serde_json::Value) -> Vec<serde_json::Value> {
        report["workers"].as_array().cloned().unwrap_or_default()
    }

    /// No static ring configured → byte-identical classification to the
    /// pre-merge report (plus the new `source` label), so a deployment that
    /// self-registers everything sees no behaviour change.
    #[test]
    fn registered_only_classification_is_unchanged() {
        let report = assemble_fleet_report(
            "1.0.0+aaaaaaa",
            &[
                row("w-match", Some("0.1.0+aaaaaaa")),
                row("w-skew", Some("0.1.0+bbbbbbb")),
                row("w-silent", None),
            ],
            &[],
        );
        let ws = workers(&report);
        assert_eq!(ws.len(), 3);
        assert!(ws.iter().all(|w| w["source"] == "registered"));
        assert_eq!(ws[0]["build_status"], "match");
        assert_eq!(ws[1]["build_status"], "skew");
        assert_eq!(ws[2]["build_status"], "unverifiable");
        assert_eq!(report["build_skew"], true);
        assert_eq!(report["skewed_workers"], 1);
        assert_eq!(report["unverifiable_workers"], 1);
        assert_eq!(report["registered_workers"], 3);
        assert_eq!(report["static_env_workers"], 0);
        assert_eq!(report["worker_count"], 3);
        assert_eq!(report["distinct_worker_ids"], 3);
    }

    /// A worker mid key-rotation is two REGISTERED rows for one worker — the
    /// pre-existing reason `worker_count` overcounts, now stated by a field
    /// instead of only by prose.
    #[test]
    fn rotation_rows_inflate_worker_count_but_not_distinct_ids() {
        let report = assemble_fleet_report(
            "1.0.0+aaaaaaa",
            &[
                row("w-rotating", Some("0.1.0+aaaaaaa")),
                row("w-rotating", Some("0.1.0+aaaaaaa")),
            ],
            &[],
        );
        assert_eq!(report["worker_count"], 2);
        assert_eq!(report["distinct_worker_ids"], 1);
        assert_eq!(report["build_skew"], false);
    }

    /// The defect this merge fixes: a fleet whose workers all authenticate off
    /// the static env ring used to report ZERO workers — indistinguishable from
    /// "no workers running".
    #[test]
    fn static_only_fleet_is_visible_and_never_counts_as_skew() {
        let report = assemble_fleet_report("1.0.0+aaaaaaa", &[], &ring(&[("dev-worker-fleet", 1)]));
        let ws = workers(&report);
        assert_eq!(ws.len(), 1);
        assert_eq!(ws[0]["worker_id"], "dev-worker-fleet");
        assert_eq!(ws[0]["source"], "static-env");
        assert_eq!(ws[0]["build_status"], "unverifiable");
        assert_eq!(ws[0]["static_key_count"], 1);
        // Nothing self-reported: all three are null, not defaulted.
        assert!(ws[0]["build_version"].is_null());
        assert!(ws[0]["supports_sealing"].is_null());
        assert!(ws[0]["last_seen_at"].is_null());

        assert_eq!(report["worker_count"], 1);
        assert_eq!(report["registered_workers"], 0);
        assert_eq!(report["static_env_workers"], 1);
        assert_eq!(report["unverifiable_workers"], 1);
        // Honest answer: nothing PROVEN to differ, and the report says why.
        assert_eq!(report["build_skew"], false);
        assert_eq!(report["skewed_workers"], 0);
    }

    /// Same worker_id in both sources = two rows. Deduping would hide the
    /// disagreement between what the worker proved and what the operator pinned.
    #[test]
    fn same_worker_id_in_both_sources_yields_two_rows() {
        let report = assemble_fleet_report(
            "1.0.0+aaaaaaa",
            &[row("dev-worker-fleet", Some("0.1.0+aaaaaaa"))],
            &ring(&[("dev-worker-fleet", 2)]),
        );
        let ws = workers(&report);
        assert_eq!(ws.len(), 2, "one row per SOURCE, never collapsed");
        assert_eq!(ws[0]["source"], "registered");
        assert_eq!(ws[0]["build_status"], "match");
        assert_eq!(ws[1]["source"], "static-env");
        assert_eq!(ws[1]["build_status"], "unverifiable");
        assert_eq!(ws[1]["static_key_count"], 2, "rotation overlap is visible");

        // Counts split by source; the static row is unverifiable but not skew.
        assert_eq!(report["worker_count"], 2, "ROW count: one per source");
        assert_eq!(
            report["distinct_worker_ids"], 1,
            "…but it is ONE worker; worker_count must not be read as a fleet size"
        );
        assert_eq!(report["registered_workers"], 1);
        assert_eq!(report["static_env_workers"], 1);
        assert_eq!(report["unverifiable_workers"], 1);
        assert_eq!(report["build_skew"], false);
    }

    /// A static row must not drag a proven-skew verdict either way, and
    /// "registered but silent" stays derivable from the two counts.
    #[test]
    fn static_rows_do_not_perturb_skew_and_counts_stay_derivable() {
        let report = assemble_fleet_report(
            "1.0.0+aaaaaaa",
            &[
                row("w-skew", Some("0.1.0+bbbbbbb")),
                row("w-silent", None),
                row("w-unknown-sha", Some("0.1.0+unknown")),
            ],
            &ring(&[("pinned-a", 1), ("pinned-b", 1)]),
        );
        assert_eq!(report["build_skew"], true);
        assert_eq!(report["skewed_workers"], 1, "static rows never add skew");
        assert_eq!(report["unverifiable_workers"], 4);
        assert_eq!(report["static_env_workers"], 2);
        // The note's arithmetic: registered-but-silent = 4 - 2 = 2.
        let silent = report["unverifiable_workers"].as_u64().unwrap()
            - report["static_env_workers"].as_u64().unwrap();
        assert_eq!(silent, 2);
    }

    /// `truncated` describes the DB listing hitting its LIMIT. Static entries
    /// are appended after that LIMIT, so they must never flip the flag.
    ///
    /// Sized to actually DISCRIMINATE: the merged array is deliberately pushed
    /// PAST `MAX_FLEET_BUILD_ROWS` while the listing itself is one row short of
    /// it, so a `workers.len() >= MAX` implementation reports a truncation that
    /// did not happen and this test fails. A three-row toy fleet would pass
    /// under both the right and the wrong rule — i.e. assert nothing.
    #[test]
    fn truncated_reflects_the_db_listing_not_the_merged_array() {
        let cap = talos_worker_identity_repository::MAX_FLEET_BUILD_ROWS as usize;
        let rows: Vec<_> = (0..cap - 1)
            .map(|i| row(&format!("w{i:05}"), None))
            .collect();
        let ring = ring(&[("pinned-a", 1), ("pinned-b", 1), ("pinned-c", 1)]);
        let report = assemble_fleet_report("1.0.0+aaaaaaa", &rows, &ring);

        assert_eq!(
            report["worker_count"],
            (cap + 2) as u64,
            "merged exceeds cap"
        );
        assert_eq!(
            report["truncated"], false,
            "neither source was cut; only the merged length exceeds the cap"
        );
    }

    /// The other half of the same rule: the DB listing hitting its LIMIT DOES
    /// set the flag, even with no static ring at all.
    #[test]
    fn truncated_is_set_when_the_db_listing_hits_its_limit() {
        let cap = talos_worker_identity_repository::MAX_FLEET_BUILD_ROWS as usize;
        let rows: Vec<_> = (0..cap).map(|i| row(&format!("w{i:05}"), None)).collect();
        let report = assemble_fleet_report("1.0.0+aaaaaaa", &rows, &[]);
        assert_eq!(report["truncated"], true);
        assert_eq!(report["registered_workers"], cap as u64);
    }

    /// An operator-authored ring is unbounded input to an operator-facing JSON
    /// blob: cap it with the same runaway guard the DB listing uses, say so via
    /// `truncated`, and keep every count describing the rows actually emitted so
    /// the note's arithmetic still holds when the cap bites.
    #[test]
    fn an_oversized_static_ring_is_capped_and_says_so() {
        let cap = talos_worker_identity_repository::MAX_FLEET_BUILD_ROWS as usize;
        let huge: Vec<(String, usize)> = (0..cap + 37).map(|i| (format!("w{i:05}"), 1)).collect();
        let report = assemble_fleet_report("1.0.0+aaaaaaa", &[], &huge);

        assert_eq!(workers(&report).len(), cap, "static rows are capped");
        assert_eq!(report["static_env_workers"], cap as u64);
        assert_eq!(report["worker_count"], cap as u64);
        assert_eq!(report["truncated"], true, "a cut ring must announce itself");
        // The counts stay internally consistent under the cap: every emitted
        // static row is unverifiable, and registered-but-silent is still
        // derivable as unverifiable_workers - static_env_workers (= 0 here).
        assert_eq!(report["unverifiable_workers"], cap as u64);
        assert_eq!(report["registered_workers"], 0);
        assert_eq!(report["build_skew"], false);
    }

    /// A ring exactly AT the cap is complete, not truncated — off-by-one guard
    /// so `truncated` never cries wolf on the largest honest fleet.
    #[test]
    fn a_static_ring_exactly_at_the_cap_is_not_truncated() {
        let cap = talos_worker_identity_repository::MAX_FLEET_BUILD_ROWS as usize;
        let exact: Vec<(String, usize)> = (0..cap).map(|i| (format!("w{i:05}"), 1)).collect();
        let report = assemble_fleet_report("1.0.0+aaaaaaa", &[], &exact);
        assert_eq!(workers(&report).len(), cap);
        assert_eq!(report["truncated"], false);
    }
}
