use super::types::JsonRpcResponse;
use super::utils::{mcp_error, mcp_text};
use super::{auth, McpState};
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;

pub fn tool_schemas() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
            "name": "create_webhook",
            "description": "Create a new webhook trigger. Pass EITHER module_id (fires a single module) OR workflow_id (fires an entire workflow — recommended for multi-node or actor-scoped work). Returns the webhook URL + verification token. Supports both static-token auth (default) and optional HMAC-SHA256 auth (when signing_secret is provided).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": { "type": "string", "description": "Human-readable name for the webhook trigger (unique per user)" },
                    "module_id": { "type": "string", "description": "UUID of a compiled module (from list_modules) to fire when the webhook POSTs. Mutually exclusive with workflow_id; exactly one is required." },
                    "workflow_id": { "type": "string", "description": "UUID of a workflow to fire when the webhook POSTs. The workflow's actor binding is preserved — recommended when the handler needs actor-scoped memory/budget/identity. Mutually exclusive with module_id." },
                    "auto_respond": { "type": "boolean", "description": "When true, the HTTP response body is the module/workflow's execution result (JSON). When false (default), the body is 'OK' and the work runs async. Use true for synchronous-response patterns (Slack /command, ChatOps). Honors sync_timeout_secs." },
                    "sync_timeout_secs": { "type": "number", "description": "Max seconds to wait for synchronous response when auto_respond=true (default: 30, max: 120). Exceeded requests return 504." },
                    "signing_secret": { "type": "string", "description": "Optional HMAC signing secret. When set, incoming POSTs must include ONE of: X-Slack-Signature (v0= prefix + X-Slack-Request-Timestamp), X-Hub-Signature-256 (sha256= prefix), or X-Signature (+ X-Webhook-Timestamp for replay protection). All HMACs are SHA-256 with this secret as the key. When omitted, the webhook uses static-token auth (X-Verification-Token) only." },
                    "max_requests_per_minute": { "type": "number", "description": "Rate limit for incoming requests (default: 100, max: 10000)" },
                    "event_filter": { "type": "object", "description": "Optional event-type filter, evaluated AFTER signature verification. A non-matching delivery is acknowledged 200 with NO dispatch (so it doesn't burn an execution) — use it so a GitHub repo webhook fires only for, e.g., pull_request opened/synchronize and ignores push/star/etc. Omit to fire on every verified delivery. Shape: { \"header\": \"X-GitHub-Event\", \"values\": [\"pull_request\"], \"payload_match\": { \"action\": [\"opened\",\"synchronize\",\"reopened\"] } } — `header`+`values` gate on a request header; `payload_match` gates on top-level body fields; both are ANDed. At least one of a non-empty `values` or `payload_match` is required." }
                },
                "required": ["name"]
            }
        }),
        serde_json::json!({
            "name": "list_webhooks",
            "description": "List all webhook triggers owned by the current user.",
            "inputSchema": {
                "type": "object",
                "properties": {},
            }
        }),
        serde_json::json!({
            "name": "delete_webhook",
            "description": "Delete a webhook trigger by ID.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "webhook_id": { "type": "string", "description": "UUID of the webhook trigger to delete" }
                },
                "required": ["webhook_id"]
            }
        }),
        serde_json::json!({
            "name": "enable_webhook",
            "description": "Enable a webhook trigger (resume receiving requests).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "webhook_id": { "type": "string", "description": "UUID of the webhook trigger to enable" }
                },
                "required": ["webhook_id"]
            }
        }),
        serde_json::json!({
            "name": "disable_webhook",
            "description": "Disable a webhook trigger (stop receiving requests without deleting it).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "webhook_id": { "type": "string", "description": "UUID of the webhook trigger to disable" }
                },
                "required": ["webhook_id"]
            }
        }),
        serde_json::json!({
            "name": "list_workflow_webhooks",
            "description": "List webhook triggers connected to a specific workflow's modules.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workflow_id": { "type": "string", "description": "UUID of the workflow" }
                },
                "required": ["workflow_id"]
            }
        }),
        serde_json::json!({
            "name": "get_webhook_security_stats",
            "description": "Return security statistics for webhooks: auth failure counts, rate-limit hits, and success counts per trigger (last 24h), plus a list of IPs currently blocked by the circuit breaker.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }),
        serde_json::json!({
            "name": "reset_webhook_circuit_breaker",
            "description": "Manually clear the circuit breaker block for a specific IP address, allowing it to attempt webhook authentication again.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "ip_address": { "type": "string", "description": "IPv4 or IPv6 address to unblock (e.g., '1.2.3.4' or '::1')" }
                },
                "required": ["ip_address"]
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
        "create_webhook" => Some(handle_create_webhook(req_id, args, state, user_id).await),
        "list_webhooks" => Some(handle_list_webhooks(req_id, args, state, user_id).await),
        "delete_webhook" => Some(handle_delete_webhook(req_id, args, state, user_id).await),
        "enable_webhook" => Some(handle_enable_webhook(req_id, args, state, user_id).await),
        "disable_webhook" => Some(handle_disable_webhook(req_id, args, state, user_id).await),
        "list_workflow_webhooks" => {
            Some(handle_list_workflow_webhooks(req_id, args, state, user_id).await)
        }
        "get_webhook_security_stats" => {
            Some(handle_get_webhook_security_stats(req_id, state, user_id).await)
        }
        "reset_webhook_circuit_breaker" => {
            Some(handle_reset_webhook_circuit_breaker(req_id, args, state, user_id).await)
        }
        _ => None,
    }
}

async fn handle_create_webhook(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    // MCP-203 (2026-05-08): reject whitespace-only webhook names.
    // Same family as MCP-161 — operator-facing field; whitespace-only
    // pollutes list_webhooks and the dashboard.
    //
    // MCP-364 (2026-05-11): two more issues in the same block:
    //   1. Wrong-type (e.g. `name: 42`) silently collapsed via `.as_str()
    //      → None → "non-empty/non-whitespace" message — misleading
    //      diagnostic. Distinguish wrong-type from absent loudly.
    //   2. The non-empty branch stored the UNTRIMMED string. Operator
    //      passing `name: "   prod-hook   "` persisted with surrounding
    //      whitespace, polluting the list view (sort order broken,
    //      dashboard looks ragged, JSON serialisation embeds the
    //      whitespace into client UI). Trim at the boundary so the
    //      stored value matches what the operator sees in editors that
    //      auto-trim. Length check moves to the trimmed value so a
    //      "   nm   " with 250 visible chars doesn't reject on padding.
    let name = match args.get("name") {
        None => {
            return mcp_error(
                req_id,
                -32602,
                "Webhook name must be a non-empty, non-whitespace string",
            )
        }
        Some(v) => match v.as_str() {
            Some(n) => {
                let trimmed = n.trim();
                if trimmed.is_empty() {
                    return mcp_error(
                        req_id,
                        -32602,
                        "Webhook name must be a non-empty, non-whitespace string",
                    );
                }
                if trimmed.len() > 255 {
                    return mcp_error(req_id, -32602, "Webhook name must be 1–255 characters");
                }
                // MCP-406/410 (2026-05-11): name-field control-char
                // check via the canonical helper. See
                // utils::validate_name_no_control_chars.
                if let Err(resp) = crate::utils::validate_name_no_control_chars(
                    "Webhook name",
                    trimmed,
                    req_id.clone(),
                ) {
                    return resp;
                }
                trimmed.to_string()
            }
            None => {
                let kind = crate::utils::json_type_name(v);
                return mcp_error(
                    req_id,
                    -32602,
                    &format!("Webhook name must be a string, got {kind}"),
                );
            }
        },
    };

    // module_id XOR workflow_id — exactly one must be provided.
    let module_id_opt: Option<Uuid> = match args.get("module_id").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => match s.parse::<Uuid>() {
            Ok(id) => Some(id),
            Err(_) => return mcp_error(req_id, -32602, "Invalid module_id — must be a UUID"),
        },
        _ => None,
    };
    let workflow_id_opt: Option<Uuid> = match args.get("workflow_id").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => match s.parse::<Uuid>() {
            Ok(id) => Some(id),
            Err(_) => return mcp_error(req_id, -32602, "Invalid workflow_id — must be a UUID"),
        },
        _ => None,
    };
    match (module_id_opt, workflow_id_opt) {
        (None, None) => {
            return mcp_error(
                req_id,
                -32602,
                "Must provide exactly one of 'module_id' (single module fire) or 'workflow_id' (full workflow fire).",
            )
        }
        (Some(_), Some(_)) => {
            return mcp_error(
                req_id,
                -32602,
                "Pass EITHER module_id OR workflow_id, not both — they're mutually exclusive.",
            )
        }
        _ => {}
    }

    let max_rpm = match crate::utils::validate_range_i64(
        args,
        "max_requests_per_minute",
        1,
        10000,
        100,
        &req_id,
    ) {
        Ok(v) => v as i32,
        Err(resp) => return resp,
    };

    // MCP-267 (2026-05-10): pre-fix `as_bool().unwrap_or(false)`
    // collapsed wrong-type into the default — `auto_respond: "true"`
    // (string) silently disabled auto-respond. Direction-class:
    // operator opted IN but the system opted OUT. Same family as
    // MCP-251 / MCP-252.
    let auto_respond =
        match crate::utils::validate_optional_bool(args, "auto_respond", false, &req_id) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    let sync_timeout_secs =
        match crate::utils::validate_range_i64(args, "sync_timeout_secs", 1, 120, 30, &req_id) {
            Ok(v) => v as i32,
            Err(resp) => return resp,
        };

    // MCP-202 (2026-05-08): enforce minimum entropy on signing_secret.
    // Pre-fix the only check was `!s.is_empty()` — `signing_secret: "x"`
    // (1 char) and `signing_secret: "                "` (whitespace)
    // both persisted, leaving the webhook with a trivially brute-
    // forceable HMAC. The webhook is still flagged hmac_enabled and
    // rejects static-token requests, so an attacker who guesses the
    // secret has full code-execution access. 16 chars matches the
    // industry minimum for HMAC-SHA256 secrets (Slack's signing
    // secrets are 32 hex chars, GitHub's are user-chosen with no
    // explicit minimum but their docs recommend 16+).
    let signing_secret_opt = match args.get("signing_secret").and_then(|v| v.as_str()) {
        None => None,
        Some(s) if s.is_empty() => None,
        Some(s) if s.trim().is_empty() => {
            return mcp_error(
                req_id,
                -32602,
                "signing_secret must be a non-empty, non-whitespace string when provided. Omit the field for static-token auth.",
            )
        }
        Some(s) if s.len() < 16 => {
            return mcp_error(
                req_id,
                -32602,
                "signing_secret must be at least 16 characters — shorter secrets are trivially brute-forceable for HMAC. \
                 Use a cryptographically random 32-character hex string (32 hex chars = 128 bits of entropy).",
            )
        }
        Some(s) if s.len() > 1024 => {
            return mcp_error(
                req_id,
                -32602,
                "signing_secret must be ≤ 1024 characters",
            )
        }
        Some(s) => Some(s.to_string()),
    };

    // RFC 0007: optional event filter. Validated via the canonical
    // `talos_webhooks::validate_event_filter` so the MCP and GraphQL create
    // surfaces enforce ONE shape contract (matcher/validator drift is a
    // documented hazard). Fail-CLOSED here (reject malformed) — the fire-time
    // matcher is fail-OPEN. Absent/null → fire on every verified delivery.
    let event_filter_opt: Option<serde_json::Value> = match args.get("event_filter") {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => {
            if let Err(e) = talos_webhooks::validate_event_filter(v) {
                return mcp_error(req_id, -32602, &format!("Invalid event_filter: {e}"));
            }
            Some(v.clone())
        }
    };

    // Pre-flight: verify whichever target the caller specified actually exists
    // AND that this user can dispatch it. A bare `module_exists` would let an
    // attacker bind a webhook to another user's private module — the dispatch
    // path would later reject the request, but we'd silently store a bricked
    // trigger row and confirm the target UUID exists via the error message
    // ("Module {} not found" only fires for non-existent UUIDs, not for
    // unauthorised ones).
    if let Some(module_id) = module_id_opt {
        let accessible = state
            .module_repo
            .module_accessible_by_user(module_id, user_id)
            .await
            .unwrap_or(false);
        if !accessible {
            return mcp_error(
                req_id,
                -32602,
                &format!(
                    "Module {} not found or not accessible. Use list_modules to see your modules.",
                    module_id
                ),
            );
        }
    }
    if let Some(wf_id) = workflow_id_opt {
        let wf_exists = state.workflow_repo.workflow_exists(wf_id, user_id).await;
        if !wf_exists {
            return mcp_error(
                req_id,
                -32602,
                &format!(
                    "Workflow {} not found or not owned by you. Use list_workflows to see your workflows.",
                    wf_id
                ),
            );
        }
    }

    let webhook_repo = talos_webhook_repository::WebhookRepository::new(state.db_pool.clone());

    // Pre-flight: enforce unique webhook name per user.
    // There is no DB-level unique constraint on webhook_triggers.name, so a
    // plain INSERT would silently create two webhooks with the same name —
    // confusing any name-based lookup or dispatch expression.
    let name_exists = webhook_repo
        .name_exists_for_user(&name, user_id)
        .await
        .unwrap_or(false);
    if name_exists {
        return mcp_error(
            req_id,
            -32602,
            &format!(
                "A webhook named '{}' already exists. Use list_webhooks to see existing \
                 webhooks, or choose a different name.",
                name
            ),
        );
    }

    // Enforce per-user webhook limit to prevent resource exhaustion.
    // MCP-367 (2026-05-11): fail-CLOSED on DB error so the cap isn't
    // silently bypassed.
    // MCP-686 (2026-05-13): the cap check + insert now happen in one
    // transaction under a per-user advisory lock (same shape as
    // MCP-685 on api-keys). Pre-fix the handler called
    // `count_for_user` then `insert_webhook` in two separate
    // transactions — TOCTOU window during which two concurrent
    // creates could both pass the gate at count = cap - 1. The new
    // repository method `try_create_under_cap` runs both inside one
    // transaction; if the cap is breached it rolls back, releasing
    // the lock for the next waiter.
    const MAX_WEBHOOKS_PER_USER: i64 = 500;
    let verification_token = Uuid::new_v4().to_string();
    let webhook_id = Uuid::new_v4();

    match webhook_repo
        .try_create_under_cap(
            webhook_id,
            user_id,
            &name,
            module_id_opt,
            workflow_id_opt,
            &verification_token,
            max_rpm,
            auto_respond,
            sync_timeout_secs,
            signing_secret_opt.as_deref(),
            event_filter_opt.as_ref(),
            &state.secrets_manager,
            MAX_WEBHOOKS_PER_USER,
        )
        .await
    {
        Ok(None) => mcp_error(
            req_id,
            -32602,
            &format!(
                "Webhook limit reached ({MAX_WEBHOOKS_PER_USER}). Delete unused webhooks with delete_webhook \
                 before creating new ones."
            ),
        ),
        Ok(Some(_)) => {
            let base_url =
                talos_public_url::public_base_url_or(talos_config::get_base_url);
            // Route is `/webhooks/{id}` (plural) — see
            // `webhook_routes` in main.rs. Returning `/webhook/{id}`
            // here used to produce a 404 on every first POST.
            let webhook_url = format!("{}/webhooks/{}", base_url, webhook_id);

            let auth_note = if signing_secret_opt.is_some() {
                "HMAC auth REQUIRED (signing_secret is set, static-token fallback is intentionally disabled to prevent downgrade attacks). Send ONE of: \
                 (1) X-Hub-Signature-256: sha256=<hex_hmac_sha256(body, signing_secret)>  — GitHub style, simplest; \
                 (2) X-Slack-Signature: v0=<hex_hmac_sha256(\"v0:\"+ts+\":\"+body, signing_secret)> + X-Slack-Request-Timestamp: <unix_secs>  — Slack style with timestamp; \
                 (3) X-Signature: <hex_hmac_sha256(ts+body, signing_secret)> + X-Webhook-Timestamp: <unix_secs>  — generic format with replay protection. \
                 The verification_token returned in this response is ONLY for callers that cannot compute HMAC; it is NOT accepted on this webhook.".to_string()
            } else {
                "Static-token auth only. Include header X-Verification-Token: <the verification_token returned here>. \
                 To enable HMAC auth on a future webhook, pass a `signing_secret` to create_webhook (HMAC-secured webhooks reject static-token requests outright)."
                    .to_string()
            };

            let curl_example = if signing_secret_opt.is_some() {
                format!(
                    "BODY='{{\"example\":\"payload\"}}'; SIG=$(printf '%%s' \"$BODY\" | openssl dgst -sha256 -hmac 'YOUR_SIGNING_SECRET' -binary | xxd -p -c 64); \
                     curl -X POST {} -H \"X-Hub-Signature-256: sha256=$SIG\" -H 'Content-Type: application/json' -d \"$BODY\"",
                    webhook_url
                )
            } else {
                format!(
                    "curl -X POST {} -H 'X-Verification-Token: {}' -H 'Content-Type: application/json' -d '{{\"...\":\"...\"}}'",
                    webhook_url, verification_token
                )
            };

            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&serde_json::json!({
                    "webhook_id": webhook_id.to_string(),
                    "name": name,
                    "webhook_url": webhook_url,
                    "module_id": module_id_opt.map(|u| u.to_string()),
                    "workflow_id": workflow_id_opt.map(|u| u.to_string()),
                    "verification_token": verification_token,
                    "max_requests_per_minute": max_rpm,
                    "auto_respond": auto_respond,
                    "sync_timeout_secs": sync_timeout_secs,
                    "hmac_enabled": signing_secret_opt.is_some(),
                    "enabled": true,
                    "event_filter": event_filter_opt,
                    "usage": {
                        "method": "POST",
                        "auth": auth_note,
                        "example_curl": curl_example,
                        "response_shape": match (auto_respond, module_id_opt.is_some()) {
                            (true, true)  => "HTTP 200 + JSON body = the MODULE's output (synchronous). HTTP 500 on module error. HTTP 504 on sync_timeout_secs elapsed.",
                            (true, false) => "HTTP 200 + JSON body = {execution_id, status: 'completed', output: {<node_label>: <node_output>, ...}} (synchronous workflow run). HTTP 500 + {error} on engine error. HTTP 504 + {execution_id, status: 'timeout'} when the workflow exceeds sync_timeout_secs (engine is dropped on timeout — find the execution_id in your history to inspect partial state).",
                            (false, _)    => "HTTP 202 + JSON body = {execution_id, status: 'queued'} (async). Work runs in the background; poll list_recent_executions or get_execution_status for the result.",
                        },
                    },
                }))
                .unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!("create_webhook failed: {:#}", e);
            mcp_error(req_id, -32000, "Failed to create webhook")
        }
    }
}

async fn handle_list_webhooks(
    req_id: Option<serde_json::Value>,
    _args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let webhook_repo = talos_webhook_repository::WebhookRepository::new(state.db_pool.clone());
    let rows = webhook_repo.list_for_user(user_id, 1000).await;

    match rows {
        Ok(rows) => {
            let base_url = talos_public_url::public_base_url_or(talos_config::get_base_url);
            let webhooks: Vec<serde_json::Value> = rows
                .iter()
                .map(|r| {
                    let webhook_url = format!("{}/webhook/{}", base_url, r.id);
                    serde_json::json!({
                        "id": r.id,
                        "name": r.name,
                        "module_id": r.module_id,
                        "webhook_url": webhook_url,
                        "enabled": r.enabled,
                        "max_requests_per_minute": r.max_requests_per_minute,
                        "created_at": r.created_at.to_rfc3339(),
                        "event_filter": r.event_filter,
                    })
                })
                .collect();
            // MCP-45 (2026-05-07): structured envelope (count + items).
            let envelope = serde_json::json!({
                "count": webhooks.len(),
                "webhooks": webhooks,
            });
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&envelope).unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!("list_webhooks failed: {:#}", e);
            mcp_error(req_id, -32000, "Failed to list webhooks")
        }
    }
}

async fn handle_delete_webhook(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let webhook_id = match crate::utils::require_uuid(args, "webhook_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let webhook_repo = talos_webhook_repository::WebhookRepository::new(state.db_pool.clone());
    match webhook_repo.delete(webhook_id, user_id).await {
        Ok(rows) if rows > 0 => mcp_text(
            req_id,
            &format!("Webhook {} deleted successfully.", webhook_id),
        ),
        Ok(_) => mcp_error(req_id, -32000, "Webhook not found or access denied"),
        Err(e) => {
            tracing::error!("delete_webhook failed: {:#}", e);
            mcp_error(req_id, -32000, "Failed to delete webhook")
        }
    }
}

async fn handle_enable_webhook(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let webhook_id = match crate::utils::require_uuid(args, "webhook_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let webhook_repo = talos_webhook_repository::WebhookRepository::new(state.db_pool.clone());
    match webhook_repo.set_enabled(webhook_id, user_id, true).await {
        Ok(rows) if rows > 0 => mcp_text(req_id, &format!("Webhook {} enabled.", webhook_id)),
        Ok(_) => mcp_error(req_id, -32000, "Webhook not found or access denied"),
        Err(e) => {
            tracing::error!("enable_webhook failed: {:#}", e);
            mcp_error(req_id, -32000, "Failed to enable webhook")
        }
    }
}

async fn handle_disable_webhook(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let webhook_id = match crate::utils::require_uuid(args, "webhook_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let webhook_repo = talos_webhook_repository::WebhookRepository::new(state.db_pool.clone());
    match webhook_repo.set_enabled(webhook_id, user_id, false).await {
        Ok(rows) if rows > 0 => mcp_text(req_id, &format!("Webhook {} disabled.", webhook_id)),
        Ok(_) => mcp_error(req_id, -32000, "Webhook not found or access denied"),
        Err(e) => {
            tracing::error!("disable_webhook failed: {:#}", e);
            mcp_error(req_id, -32000, "Failed to disable webhook")
        }
    }
}

async fn handle_list_workflow_webhooks(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let workflow_id = match crate::utils::require_uuid(args, "workflow_id", req_id.clone()) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // Get the graph_json from the workflow
    let graph_str = match state
        .workflow_repo
        .get_workflow_graph_for_similarity(workflow_id, user_id)
        .await
        .unwrap_or(None)
    {
        Some(g) => g,
        None => return mcp_error(req_id, -32000, "Workflow not found or access denied"),
    };

    // Extract module IDs from graph_json (handles v1/v2 format)
    let graph: serde_json::Value = match serde_json::from_str(&graph_str) {
        Ok(g) => g,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to parse workflow graph_json; treating as empty");
            serde_json::json!({"nodes": []})
        }
    };
    let mut module_ids: Vec<Uuid> = Vec::new();

    if let Some(nodes) = graph.get("nodes").and_then(|n| n.as_array()) {
        for node in nodes {
            // v0 format (most common in production graphs): node.type is the
            // UUID of the module the node dispatches. Pre-fix the handler
            // missed this projection entirely and reported "No modules found
            // in workflow graph" for every workflow using this layout —
            // which is the canonical layout (see `handle_get_workflow_graph`
            // configuration.rs:165-170 for the matching extraction). All
            // schedule + webhook visibility for the legitimate caller flow
            // was effectively broken.
            if let Some(mid_str) = node
                .get("type")
                .and_then(|v| v.as_str())
                .filter(|s| !s.starts_with("system:"))
            {
                if let Ok(mid) = mid_str.parse::<Uuid>() {
                    module_ids.push(mid);
                }
            }
            // v1 format: node.data.moduleId
            if let Some(mid_str) = node
                .get("data")
                .and_then(|d| d.get("moduleId"))
                .and_then(|v| v.as_str())
            {
                if let Ok(mid) = mid_str.parse::<Uuid>() {
                    module_ids.push(mid);
                }
            }
            // v2 format: node.module_id
            if let Some(mid_str) = node.get("module_id").and_then(|v| v.as_str()) {
                if let Ok(mid) = mid_str.parse::<Uuid>() {
                    module_ids.push(mid);
                }
            }
        }
    }

    if module_ids.is_empty() {
        return mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "workflow_id": workflow_id,
                "webhooks": [],
                "message": "No modules found in workflow graph."
            }))
            .unwrap_or_default(),
        );
    }

    let webhook_repo = talos_webhook_repository::WebhookRepository::new(state.db_pool.clone());
    let rows = webhook_repo
        .list_for_modules(&module_ids, user_id, 1000)
        .await;

    match rows {
        Ok(rows) => {
            let base_url = talos_public_url::public_base_url_or(talos_config::get_base_url);
            let webhooks: Vec<serde_json::Value> = rows
                .iter()
                .map(|r| {
                    let webhook_url = format!("{}/webhook/{}", base_url, r.id);
                    serde_json::json!({
                        "id": r.id,
                        "name": r.name,
                        "module_id": r.module_id,
                        "webhook_url": webhook_url,
                        "enabled": r.enabled,
                        "max_requests_per_minute": r.max_requests_per_minute,
                        "created_at": r.created_at.to_rfc3339(),
                        "event_filter": r.event_filter,
                    })
                })
                .collect();

            // MCP-82 (2026-05-07): emit canonical `count` for envelope
            // consistency with sibling list tools (post-MCP-45).
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&serde_json::json!({
                    "workflow_id": workflow_id,
                    "count": webhooks.len(),
                    "webhooks": webhooks,
                }))
                .unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!("list_workflow_webhooks failed: {:#}", e);
            mcp_error(req_id, -32000, "Failed to list webhooks for workflow")
        }
    }
}

async fn handle_get_webhook_security_stats(
    req_id: Option<serde_json::Value>,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    // Query auth failures, rate-limit hits, and successes per trigger for the last 24h.
    // Scoped to the calling user's webhooks only.
    let webhook_repo = talos_webhook_repository::WebhookRepository::new(state.db_pool.clone());
    let trigger_stats = match webhook_repo.get_security_stats_24h(user_id, 100).await {
        Ok(rows) => rows
            .iter()
            .map(|s| {
                serde_json::json!({
                    "id": s.trigger_id,
                    "name": s.trigger_name.clone().unwrap_or_else(|| "<deleted>".to_string()),
                    "failures_24h": s.auth_failures,
                    "rate_limit_hits_24h": s.rate_limit_hits,
                    "successes_24h": s.successes,
                })
            })
            .collect::<Vec<_>>(),
        Err(e) => {
            tracing::error!("get_webhook_security_stats DB query failed: {:#}", e);
            return mcp_error(req_id, -32000, "Failed to query webhook security stats");
        }
    };

    // Collect currently-blocked IPs from the in-memory circuit breaker.
    //
    // MCP-329 (2026-05-11): the breaker is deployment-wide (not tenant-
    // bucketed), so the IP list discloses whose endpoints are under
    // active attack across other tenants — a cross-tenant info leak
    // (the IP itself + that "someone in this deployment" is being
    // attacked). The pre-fix gate was the agent-level `is_admin`
    // (per-tenant admin role), so an organization-scoped admin agent
    // in a multi-tenant deployment saw IPs failing against OTHER
    // tenants' webhooks. Same require_platform_admin family as
    // MCP-325 (reset_webhook_circuit_breaker); the sibling pair now
    // gates on the same deployment-wide flag.
    let is_platform_admin = state
        .actor_repo
        .is_platform_admin(user_id)
        .await
        .unwrap_or(false);
    let blocked_ips: Vec<serde_json::Value> = if is_platform_admin {
        let now = std::time::Instant::now();
        state
            .circuit_breaker
            .blocked_ips()
            .into_iter()
            .map(|(ip, blocked_until)| {
                let remaining_secs = blocked_until.saturating_duration_since(now).as_secs();
                serde_json::json!({
                    "ip": ip.to_string(),
                    "remaining_seconds": remaining_secs,
                })
            })
            .collect()
    } else {
        Vec::new()
    };

    let mut response = serde_json::json!({
        "triggers": trigger_stats,
        "blocked_ips": blocked_ips,
    });
    if !is_platform_admin {
        response["blocked_ips_note"] = serde_json::json!(
            "Hidden — circuit-breaker IP list is deployment-wide state and only visible to platform admins."
        );
    }
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&response).unwrap_or_default(),
    )
}

async fn handle_reset_webhook_circuit_breaker(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    // MCP-325 (2026-05-11): the webhook circuit breaker is deployment-
    // wide state — entries hold IPs that failed against ANY tenant's
    // webhook. The pre-fix comment already acknowledged this and gated
    // to "admin agents only" via the agent-level `is_admin` capability
    // — but that's the per-tenant admin role. An organization-scoped
    // admin in a multi-tenant deployment passed the check and could
    // clear blocks on IPs that had been failing against other tenants'
    // webhooks, letting an attacker resume hitting them. Same cross-
    // tenant family as pause_executions / query_paginated. Switch to
    // `ActorRepository::is_platform_admin(user_id)` — the
    // `users.is_platform_admin` column flagged for deployment-wide
    // operators only.
    let is_platform_admin = state
        .actor_repo
        .is_platform_admin(user_id)
        .await
        .unwrap_or(false);
    if !is_platform_admin {
        return mcp_error(
            req_id,
            -32601,
            "reset_webhook_circuit_breaker requires platform-admin privileges. \
             The breaker is deployment-wide state — clearing it affects every tenant's \
             webhook protection. Per-tenant scope would require bucketing the breaker by \
             trigger owner first.",
        );
    }

    let ip_str = match args.get("ip_address").and_then(|v| v.as_str()) {
        Some(s) if !s.is_empty() => s,
        _ => return mcp_error(req_id, -32602, "Missing or empty 'ip_address'"),
    };

    let ip: std::net::IpAddr = match ip_str.parse() {
        Ok(ip) => ip,
        Err(_) => {
            return mcp_error(
                req_id,
                -32602,
                &format!("'{}' is not a valid IPv4 or IPv6 address", ip_str),
            )
        }
    };

    state.circuit_breaker.record_success(ip);
    tracing::info!(ip = %ip, "MCP operator reset webhook circuit breaker for IP");

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            "cleared": true,
            "ip": ip.to_string(),
            "message": "Circuit breaker reset. The IP may now attempt webhook authentication again.",
        }))
        .unwrap_or_default(),
    )
}
