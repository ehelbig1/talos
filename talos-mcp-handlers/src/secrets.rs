use super::types::JsonRpcResponse;
use super::utils::{mcp_error, mcp_text};
use super::{auth, McpState};
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;

// MCP-1201 (2026-05-17): MCP is intentionally READ-ONLY for secrets.
// All mutating secret operations (create, update, delete, rotate,
// expiry, namespace move) live exclusively on the GraphQL surface in
// `talos-api/src/schema/secrets/mutations.rs`, which gates on
// `require_2fa` + `ApiKeyScope::SecretsWrite`. MCP API keys are
// long-lived bearer tokens with no 2FA equivalent — routing secret
// writes through this surface would create a no-2FA bypass of the
// discipline the GraphQL path enforces. The four write handlers
// (handle_set_secret / handle_delete_secret / handle_set_secret_
// namespace / handle_set_secret_expiry / handle_rotate_secret) and
// their gates were removed; the `secrets:write` capability string is
// still in `KNOWN_CAPABILITIES` + the DB CHECK constraint so any
// migration that pre-seeded it survives — but the runtime never
// consults it anymore. See the project memory entry for MCP-1201
// for the architectural rationale.

pub fn tool_schemas() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({
            "name": "list_secrets",
            "description": "List all secrets owned by the current user. Returns name, key_path, namespace, and description (NEVER returns secret values). Optionally filter by namespace.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "namespace": { "type": "string", "description": "Optional namespace filter (e.g. 'production'). Omit to list all." }
                },
            }
        }),
        serde_json::json!({
            "name": "list_secret_namespaces",
            "description": "List all secret namespaces and their secret counts for the current user.",
            "inputSchema": {
                "type": "object",
                "properties": {},
            }
        }),
        serde_json::json!({
            "name": "list_secret_usage",
            "description": "Show which modules and workflows reference a given secret. Critical before rotating or deleting secrets.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "secret_name": { "type": "string", "description": "Name of the secret to check" }
                },
                "required": ["secret_name"]
            }
        }),
        serde_json::json!({
            "name": "list_expiring_secrets",
            "description": "List secrets that will expire within a given number of days.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "within_days": { "type": "number", "description": "Show secrets expiring within this many days (default: 30)" }
                },
            }
        }),
        serde_json::json!({
            "name": "get_unused_secrets",
            "description": "Find secrets that are not referenced by any module's allowed_secrets list. Helps identify orphaned secrets for cleanup.",
            "inputSchema": {
                "type": "object",
                "properties": {},
            }
        }),
        serde_json::json!({
            "name": "check_secret_health",
            "description": "Audit secrets for health issues: missing expiry on API tokens, secrets not rotated in >90 days. Returns recommendations for each flagged secret.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }),
        serde_json::json!({
            "name": "normalize_secret_paths",
            "description": "Identify secrets with inconsistent naming conventions (e.g. 'github-token' vs 'github_token') that likely serve the same purpose. Compares user vault entries against canonical paths declared in compiled modules' allowed_secrets. Returns a list of potential mismatches with rename suggestions. Prevents duplicate secret proliferation across workflows.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }),
        serde_json::json!({
            "name": "refresh_oauth_token",
            "description": "Force-refresh a stored OAuth access token by calling the provider's token endpoint with the stored refresh_token. Use when a workflow is getting HTTP 401 from a provider (Gmail, Google Calendar, Atlassian) and you suspect the cached access_token is expired.\n\nPath format: `oauth/{provider}/{user_id}/{provider_key}/access_token`. You can only refresh tokens belonging to your own user_id — cross-user refresh attempts are rejected.\n\nReturns `{ refreshed: bool, reason: string, expires_in_seconds: int|null }`. `refreshed=true` means a new access_token was written to vault; `false` with `reason=\"still_valid\"` means no refresh was needed.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "vault_path": { "type": "string", "description": "Full vault path of the access_token, e.g. 'oauth/gmail/{user_id}/{email}/access_token'. Must match the caller's user_id." }
                },
                "required": ["vault_path"]
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
    // MCP-1201 (2026-05-17): all read-only. Write operations were
    // removed; the GraphQL surface (require_2fa + SecretsWrite) is the
    // single point of secret mutation. `agent.has_capability(...)` is
    // no longer consulted here — the runtime gate is the absence of
    // write-handler dispatch arms.
    match name {
        // ── Read-only ──────────────────────────────────────────────────────────
        "list_secrets" => Some(handle_list_secrets(req_id, args, state, user_id).await),
        "list_secret_namespaces" => {
            Some(handle_list_secret_namespaces(req_id, args, state, user_id).await)
        }
        "list_secret_usage" => Some(handle_list_secret_usage(req_id, args, state, user_id).await),
        "list_expiring_secrets" => {
            Some(handle_list_expiring_secrets(req_id, args, state, user_id).await)
        }
        "get_unused_secrets" => Some(handle_get_unused_secrets(req_id, args, state, user_id).await),
        "check_secret_health" => {
            Some(handle_check_secret_health(req_id, args, state, user_id).await)
        }
        // `normalize_secret_paths` only SELECTs from secrets + node_templates
        // and returns rename recommendations — it does not rename anything.
        // Open to any authenticated caller; the per-row data is already
        // scoped to user_id at the query layer.
        "normalize_secret_paths" => {
            Some(handle_normalize_secret_paths(req_id, state, user_id).await)
        }
        // `refresh_oauth_token` writes a new access_token but only for the
        // calling user's own OAuth credentials. Parsing the vault path
        // enforces scoping (path's user_id must match the caller's user_id).
        // Open to any authenticated user because it's self-service OAuth
        // maintenance — not a privileged operation. Intentionally NOT
        // gated as a secret-mutation: it never sees the new token value
        // from MCP-supplied input, it just triggers the provider-side
        // refresh flow against credentials already in the vault.
        "refresh_oauth_token" => {
            Some(handle_refresh_oauth_token(req_id, args, state, user_id).await)
        }
        _ => None,
    }
}

async fn handle_list_secrets(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    // MCP-223 (2026-05-08): pre-fix `namespace: "   "` was passed
    // verbatim to the secrets-manager filter and returned a confident
    // count: 0 — operator's typed-with-whitespace namespace silently
    // matched nothing. Same family as MCP-210 / MCP-221 / MCP-222.
    let namespace_owned: Option<String> = match args.get("namespace").and_then(|v| v.as_str()) {
        Some(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        None => None,
    };
    let namespace_filter: Option<&str> = namespace_owned.as_deref();

    match state
        .secrets_manager
        .list_secret_summaries(user_id, namespace_filter, 100)
        .await
    {
        Ok(rows) => {
            let secrets: Vec<serde_json::Value> = rows
                .iter()
                .map(|s| {
                    let mut secret_json = serde_json::json!({
                        "name": s.name,
                        "key_path": s.key_path,
                        "namespace": s.namespace,
                        "description": s.description,
                        "created_at": s.created_at.to_rfc3339(),
                    });
                    if let Some(exp) = s.expires_at {
                        secret_json["expires_at"] = serde_json::json!(exp.to_rfc3339());
                    }
                    secret_json
                })
                .collect();
            // MCP-45 (2026-05-07): structured envelope (count + items).
            let envelope = serde_json::json!({
                "count": secrets.len(),
                "secrets": secrets,
            });
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&envelope).unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!("list_secrets query failed: {:#}", e);
            mcp_error(req_id, -32000, "Failed to list secrets")
        }
    }
}

async fn handle_list_secret_namespaces(
    req_id: Option<serde_json::Value>,
    _args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    match state.secrets_manager.list_namespaces(user_id).await {
        Ok(rows) => {
            let namespaces: Vec<serde_json::Value> = rows
                .iter()
                .map(|(ns, count)| {
                    serde_json::json!({
                        "namespace": ns,
                        "secret_count": count,
                    })
                })
                .collect();
            // MCP-45 (2026-05-07): structured envelope (count + items).
            let envelope = serde_json::json!({
                "count": namespaces.len(),
                "namespaces": namespaces,
            });
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&envelope).unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!("list_secret_namespaces query failed: {:#}", e);
            mcp_error(req_id, -32000, "Failed to list secret namespaces")
        }
    }
}

async fn handle_list_secret_usage(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    // MCP-231 (2026-05-08): trim secret name lookup.
    let secret_name = match args.get("secret_name").and_then(|v| v.as_str()) {
        Some(n) if !n.trim().is_empty() => n.trim(),
        _ => return mcp_error(req_id, -32602, "Missing or empty 'secret_name' parameter"),
    };

    let sm = state.secrets_manager.as_ref();

    // Run the module/template lookup and the secret lookup in parallel — they
    // are independent of each other, and the secret lookup is only one row.
    let (modules_res, lookup_res) = tokio::join!(
        sm.find_modules_referencing_secret(user_id, secret_name),
        sm.lookup_secret_by_name(user_id, secret_name),
    );

    // MCP-549: previously both lookups used `.unwrap_or_default()` /
    // `.unwrap_or(None)`, silently masking DB errors. The risk: operator
    // runs `list_secret_usage` to ask "safe to delete?", gets a falsely-
    // empty result (because the lookup failed), deletes the secret,
    // breaks every module/workflow that depended on it. Fail closed so
    // the operator sees the error.
    let modules = match modules_res {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(
                target: "talos_mcp_handlers::secrets",
                event_kind = "find_modules_referencing_secret_failed",
                error = %e,
                "list_secret_usage: find_modules_referencing_secret query failed — refusing to return partial results"
            );
            return mcp_error(req_id, -32000, "Failed to look up secret usage");
        }
    };
    let secret_lookup = match lookup_res {
        Ok(opt) => opt,
        Err(e) => {
            tracing::error!(
                target: "talos_mcp_handlers::secrets",
                event_kind = "lookup_secret_by_name_failed",
                error = %e,
                "list_secret_usage: lookup_secret_by_name query failed — refusing to return partial results"
            );
            return mcp_error(req_id, -32000, "Failed to look up secret usage");
        }
    };
    // MCP-154 (2026-05-08): pre-fix the surface returned empty-arrays
    // for nonexistent secret names with no signal — operator typing a
    // typo got back a confident "no usage" response. When the secret
    // doesn't exist AND no module references the name, return the
    // uniform not-found error. The branch where the secret is missing
    // but other modules reference the name is preserved (catalog
    // template required path that the operator hasn't created yet —
    // operator wants to see those references).
    if secret_lookup.is_none() && modules.is_empty() {
        return mcp_error(req_id, -32000, "Secret not found or access denied");
    }
    let key_path = secret_lookup
        .as_ref()
        .map(|s| s.key_path.clone())
        .unwrap_or_else(|| secret_name.to_string());
    let secret_namespace = secret_lookup
        .as_ref()
        .map(|s| s.namespace.clone())
        .unwrap_or_else(|| "default".to_string());

    // For each referencing module, look up the workflows that depend on it.
    // We could do this in a single GIN/GiST scan if `graph_json` were indexed
    // for substring search, but it isn't — so we issue one LIKE query per
    // module. Cap the per-module fanout at 50 to bound the worst case.
    //
    // MCP-549: previously this used `.unwrap_or_default()` on the per-module
    // query, silently dropping workflows whose lookup failed. Bail loudly
    // so the operator can't be misled into deleting a secret that has
    // dependent workflows.
    let mut results: Vec<serde_json::Value> = Vec::with_capacity(modules.len());
    for m in &modules {
        let wf_rows = match sm
            .find_workflows_using_module(user_id, m.module_id, 50)
            .await
        {
            Ok(rows) => rows,
            Err(e) => {
                tracing::error!(
                    target: "talos_mcp_handlers::secrets",
                    event_kind = "find_workflows_using_module_failed",
                    module_id = %m.module_id,
                    error = %e,
                    "list_secret_usage: per-module workflow lookup failed — refusing to return partial results"
                );
                return mcp_error(req_id, -32000, "Failed to look up secret usage");
            }
        };
        let workflows: Vec<serde_json::Value> = wf_rows
            .iter()
            .map(|(id, name)| {
                serde_json::json!({
                    "workflow_id": id,
                    "workflow_name": name,
                })
            })
            .collect();
        results.push(serde_json::json!({
            "module_id": m.module_id,
            "module_name": m.module_name,
            "module_type": m.source.as_str(),
            "access_type": if m.wildcard { "wildcard" } else { "explicit" },
            "workflows": workflows,
        }));
    }

    let explicit_references: Vec<&serde_json::Value> = results
        .iter()
        .filter(|r| r.get("access_type").and_then(|v| v.as_str()) == Some("explicit"))
        .collect();
    let wildcard_access: Vec<&serde_json::Value> = results
        .iter()
        .filter(|r| r.get("access_type").and_then(|v| v.as_str()) == Some("wildcard"))
        .collect();

    // ── Pass 2: graph_json direct-reference scan ──────────────────────────────
    // The allowed_secrets join is only populated when modules are installed via
    // install_module_from_catalog. Workflows that reference a secret directly in
    // node config (e.g. API_KEY_SECRET: "llm/api_key") are invisible to the
    // module scan above.
    //
    // MCP-549: fail loudly on lookup error — silent empty would let the
    // operator delete a secret still referenced from a workflow's graph.
    let graph_rows = match sm
        .find_workflows_with_secret_in_graph(user_id, secret_name, &key_path, 100)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(
                target: "talos_mcp_handlers::secrets",
                event_kind = "find_workflows_with_secret_in_graph_failed",
                error = %e,
                "list_secret_usage: graph_json direct-reference scan failed — refusing to return partial results"
            );
            return mcp_error(req_id, -32000, "Failed to look up secret usage");
        }
    };

    // Collect workflow IDs already found via module scan to avoid duplication.
    let module_wf_ids: std::collections::HashSet<Uuid> = results
        .iter()
        .flat_map(|r| {
            r.get("workflows")
                .and_then(|w| w.as_array())
                .cloned()
                .unwrap_or_default()
        })
        .filter_map(|w| crate::utils::optional_uuid(&w, "workflow_id"))
        .collect();

    let direct_references: Vec<serde_json::Value> = graph_rows
        .iter()
        .filter_map(|(wf_id, wf_name)| {
            if module_wf_ids.contains(wf_id) {
                None // already surfaced via module scan
            } else {
                Some(serde_json::json!({
                    "workflow_id": wf_id,
                    "workflow_name": wf_name,
                    "reference_type": "node_config",
                    "note": "Secret referenced by value in a node's config — module allowed_secrets not required",
                }))
            }
        })
        .collect();

    // Host-internal consumers — secrets whose `key_path` matches an LLM
    // provider entry in `LLM_PROVIDER_VAULT_PATHS` are consumed by
    // controller-side host code (the Tier-2 `LlmClient` for in-process
    // LLM dispatch and `GraphRagService` for actor-memory entity
    // extraction). They never appear in module `allowed_secrets` or
    // node config — every workflow's LLM Inference module gets the
    // key resolved automatically by the host. Without this surface,
    // operators would see empty references for `anthropic/api_key`
    // and conclude the key is safe to delete; the next LLM call
    // would then fail platform-wide.
    let host_consumers: Vec<serde_json::Value> =
        if talos_workflow_job_protocol::is_llm_provider_vault_path(&key_path) {
            vec![
                serde_json::json!({
                    "consumer": "talos_llm::LlmClient",
                    "purpose": "Controller-side Tier-2 LLM dispatch (workflow scaffolding, hot-update, sub-workflow contract).",
                    "rotation_safe": true,
                    "rotation_note": "Per-request resolution via 60s vault cache — `rotate_secret` propagates within one TTL window without restart.",
                }),
                serde_json::json!({
                    "consumer": "talos_graph_rag::GraphRagService",
                    "purpose": "LLM-fallback entity extraction on actor_memory writes (rule-based runs first; LLM only when rule-based returns empty).",
                    "rotation_safe": true,
                    "rotation_note": "Vault-first resolution per call (post r306) — `rotate_secret` propagates without restart. Tier-1 actors skip this path entirely.",
                }),
                serde_json::json!({
                    "consumer": "Engine job dispatch (ParallelWorkflowEngine::build_encrypted_secrets)",
                    "purpose": "Pre-fetched into every job's encrypted_secrets so guest LLM Inference modules can resolve the key via the host llm:: WIT interface (Tier-2 actors only).",
                    "rotation_safe": true,
                    "rotation_note": "Resolved per-dispatch from the same vault cache; rotation lands on the next dispatch.",
                }),
            ]
        } else {
            vec![]
        };

    let structured_output = serde_json::json!({
        "secret_name": secret_name,
        "key_path": key_path,
        "namespace": secret_namespace,
        "explicit_references": explicit_references,
        "wildcard_access": wildcard_access,
        "direct_references": direct_references,
        "host_consumers": host_consumers,
        "note": "explicit_references = modules with this secret in allowed_secrets; \
                 direct_references = workflows whose node configs reference the key_path or name directly; \
                 wildcard_access = modules that can access ANY secret via '*'; \
                 host_consumers = controller-side code that resolves this key automatically (LLM provider keys only) — not visible in module allowlists or node config but rotation-safe."
    });

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&structured_output).unwrap_or_default(),
    )
}

async fn handle_list_expiring_secrets(
    req_id: Option<serde_json::Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let within_days =
        match crate::utils::validate_range_i64(args, "within_days", 1, 365, 30, &req_id) {
            Ok(v) => v as i32,
            Err(resp) => return resp,
        };

    match state
        .secrets_manager
        .list_expiring_secrets(user_id, within_days)
        .await
    {
        Ok(rows) => {
            let now = chrono::Utc::now();
            let secrets: Vec<serde_json::Value> = rows
                .iter()
                .map(|s| {
                    let expires_at = s.expires_at.unwrap_or_default();
                    let days_until = (expires_at - now).num_days();
                    serde_json::json!({
                        "name": s.name,
                        "key_path": s.key_path,
                        "namespace": s.namespace,
                        "expires_at": expires_at.to_rfc3339(),
                        "days_until_expiry": days_until,
                        "expired": days_until < 0,
                        "rotation_reminder_days": s.rotation_reminder_days,
                    })
                })
                .collect();
            // Return a structured JSON envelope so machine callers can parse
            // without string-stripping the prose header. `within_days` is
            // echoed back so the response is self-describing.
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&serde_json::json!({
                    "count": secrets.len(),
                    "within_days": within_days,
                    "secrets": secrets,
                }))
                .unwrap_or_default(),
            )
        }
        Err(e) => {
            tracing::error!("list_expiring_secrets query failed: {:#}", e);
            mcp_error(req_id, -32000, "Failed to list expiring secrets")
        }
    }
}

async fn handle_get_unused_secrets(
    req_id: Option<serde_json::Value>,
    _args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let secrets = match state
        .secrets_manager
        .list_secret_summaries(user_id, None, 200)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!("get_unused_secrets secrets query failed: {:#}", e);
            return mcp_error(req_id, -32000, "Failed to list secrets");
        }
    };

    if secrets.is_empty() {
        return mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "unused_secrets": [],
                "message": "No secrets found."
            }))
            .unwrap_or_default(),
        );
    }

    let (referenced, has_wildcard) = match state
        .secrets_manager
        .list_referenced_secret_names(user_id)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("get_unused_secrets references query failed: {:#}", e);
            return mcp_error(req_id, -32000, "Failed to scan module references");
        }
    };

    // If any module uses wildcard, all secrets are potentially referenced
    if has_wildcard {
        return mcp_text(req_id, &serde_json::to_string_pretty(&serde_json::json!({
            "unused_secrets": [],
            "message": "At least one module uses wildcard (*) allowed_secrets, so all secrets are potentially referenced.",
            "total_secrets": secrets.len(),
        })).unwrap_or_default());
    }

    // M-E (2026-05-06): exclude host-managed vault paths from the
    // "unused" classification. Per
    // `talos_workflow_job_protocol::is_controller_internal_vault_path`,
    // these are paths that are by-design absent from every module's
    // `allowed_secrets` grant because the controller resolves them
    // internally (LLM client cache → `prefetch_llm_vault_keys`; OAuth
    // refresh loop → `oauth/<provider>/<user>/<key>/refresh_token`).
    // Pre-fix this report flagged `anthropic/api_key` (and any OAuth
    // refresh token) as orphaned; an operator following the
    // recommendation would `delete_secret` the very key every LLM
    // workflow or OAuth integration depends on. The sibling
    // `get_platform_hygiene_report::orphaned_secrets` detector
    // already uses this predicate (`talos-analytics-repository/src/lib.rs:2918`);
    // this brings the standalone tool into parity.
    let unused: Vec<serde_json::Value> = secrets
        .iter()
        .filter(|s| !referenced.contains(&s.name))
        .filter(|s| !talos_workflow_job_protocol::is_controller_internal_vault_path(&s.key_path))
        .map(|s| {
            serde_json::json!({
                "name": s.name,
                "key_path": s.key_path,
                "namespace": s.namespace,
                "description": s.description,
                "created_at": s.created_at.to_rfc3339(),
            })
        })
        .collect();

    let result = serde_json::json!({
        "unused_secrets": unused,
        "count": unused.len(),
        "total_secrets": secrets.len(),
        "unused_count": unused.len(),
    });
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

async fn handle_check_secret_health(
    req_id: Option<serde_json::Value>,
    _args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let rows = match state
        .secrets_manager
        .list_secrets_for_health_check(user_id, 200)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("check_secret_health query failed: {:#}", e);
            return mcp_error(req_id, -32000, "Failed to fetch secrets");
        }
    };

    let token_patterns = ["token", "key", "pat", "api"];
    let now = chrono::Utc::now();
    let mut findings: Vec<serde_json::Value> = Vec::new();

    for s in &rows {
        let key_path_lower = s.key_path.to_lowercase();
        let looks_like_token = token_patterns.iter().any(|p| key_path_lower.contains(p));
        let has_expiry = s.expires_at.is_some();
        let days_since_creation = (now - s.created_at).num_days();

        let mut recommendations = Vec::new();

        if looks_like_token && !has_expiry {
            recommendations.push("Set an expiry on this API token/key secret in the dashboard (Settings → Secrets) — secret writes require 2FA and aren't available through MCP".to_string());
        }

        if days_since_creation > 90 {
            recommendations.push(format!(
                "Secret is {} days old — consider rotating it",
                days_since_creation
            ));
        }

        if !recommendations.is_empty() {
            findings.push(serde_json::json!({
                "name": s.name,
                "key_path": s.key_path,
                "days_since_creation": days_since_creation,
                "has_expiry": has_expiry,
                "looks_like_token": looks_like_token,
                "recommendations": recommendations,
            }));
        }
    }

    let result = serde_json::json!({
        "count": findings.len(),
        "total_secrets_checked": rows.len(),
        "issues_found": findings.len(),
        "findings": findings,
    });

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&result).unwrap_or_default(),
    )
}

async fn handle_normalize_secret_paths(
    req_id: Option<serde_json::Value>,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    // 1. Fetch all user secrets — secrets table uses created_by, not user_id
    // MCP-550: previously `.unwrap_or_default()` silently masked DB errors.
    // For normalize_secret_paths the wrong answer is dangerous — operator
    // sees "no secrets in vault" / "no canonical paths to compare against"
    // and concludes there's nothing to clean up, when actually a DB
    // outage masked real inconsistencies. Fail closed.
    let user_secrets = match state
        .secrets_manager
        .list_user_secret_key_paths(user_id)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(
                target: "talos_mcp_handlers::secrets",
                event_kind = "list_user_secret_key_paths_failed",
                error = %e,
                "normalize_secret_paths: list_user_secret_key_paths query failed — refusing to return partial results"
            );
            return mcp_error(req_id, -32000, "Failed to enumerate user secrets");
        }
    };

    if user_secrets.is_empty() {
        return mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "message": "No secrets in vault.",
                "inconsistencies": [],
                "canonical_mismatches": [],
            }))
            .unwrap_or_default(),
        );
    }

    // 2. Fetch all canonical paths declared by installed modules
    let canonical_rows = match state.secrets_manager.list_canonical_secret_paths().await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(
                target: "talos_mcp_handlers::secrets",
                event_kind = "list_canonical_secret_paths_failed",
                error = %e,
                "normalize_secret_paths: list_canonical_secret_paths query failed — refusing to return partial results"
            );
            return mcp_error(req_id, -32000, "Failed to enumerate canonical secret paths");
        }
    };

    // Build a map: normalised_path → canonical_path (normalise = lowercase + replace hyphens with underscores)
    let mut canonical_map: std::collections::HashMap<String, (String, String)> =
        std::collections::HashMap::new(); // normalised → (canonical_path, module_name)
    for (module_name, paths) in &canonical_rows {
        for path in paths {
            let normalised = path.to_lowercase().replace('-', "_");
            canonical_map.insert(normalised, (path.clone(), module_name.clone()));
        }
    }

    // 3. Detect naming inconsistencies between user secrets themselves
    //    Two secrets are "variants" if their normalised forms match.
    let mut normalised_to_paths: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();
    for path in &user_secrets {
        let norm = path.to_lowercase().replace('-', "_");
        normalised_to_paths
            .entry(norm)
            .or_default()
            .push(path.clone());
    }

    let mut inconsistencies: Vec<serde_json::Value> = Vec::new();
    for (norm, paths) in &normalised_to_paths {
        if paths.len() > 1 {
            // Multiple secrets with the same normalised name — likely duplicates
            let canonical = canonical_map
                .get(norm)
                .map(|(p, _)| p.as_str())
                .unwrap_or(&paths[0]);
            inconsistencies.push(serde_json::json!({
                "type": "duplicate_variants",
                "paths": paths,
                "normalised": norm,
                "recommended_canonical": canonical,
                "action": format!(
                    "Keep '{}' and delete the others in the dashboard (Settings → Secrets) — secret writes require 2FA and aren't available through MCP.",
                    canonical
                ),
            }));
        }
    }

    // 4. Detect mismatches vs module canonical paths
    //    User secret normalises to a known canonical but uses different spelling.
    let mut canonical_mismatches: Vec<serde_json::Value> = Vec::new();
    for path in &user_secrets {
        let norm = path.to_lowercase().replace('-', "_");
        if let Some((canonical, module_name)) = canonical_map.get(&norm) {
            if path != canonical {
                canonical_mismatches.push(serde_json::json!({
                    "type": "canonical_mismatch",
                    "your_path": path,
                    "canonical_path": canonical,
                    "module": module_name,
                    "action": format!(
                        "Rename '{}' → '{}' so {} can find it automatically. \
                         Re-create with key_path='{}' and delete the old path in the dashboard (Settings → Secrets) — secret writes require 2FA and aren't available through MCP.",
                        path, canonical, module_name, canonical
                    ),
                }));
            }
        }
    }

    let healthy = inconsistencies.is_empty() && canonical_mismatches.is_empty();

    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&serde_json::json!({
            "vault_secret_count": user_secrets.len(),
            "healthy": healthy,
            "inconsistencies": inconsistencies,
            "canonical_mismatches": canonical_mismatches,
            "tip": if healthy {
                "All secret paths are consistent with module canonical paths."
            } else {
                "Fix mismatches in the dashboard (Settings → Secrets) — re-create at the new path and delete the old one. Workflows referencing the old path will need their config updated via update_node_config. Secret writes require 2FA and aren't available through MCP."
            },
        }))
        .unwrap_or_default(),
    )
}

/// Force a refresh of a stored OAuth access token. Parses the vault path to
/// enforce per-user scoping: the caller can only refresh tokens whose path
/// embeds their own user_id. Returns a structured outcome so workflow
/// authors debugging 401s have an observable signal for whether the
/// refresh layer actually ran.
async fn handle_refresh_oauth_token(
    req_id: Option<Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let vault_path = match args.get("vault_path").and_then(|v| v.as_str()) {
        Some(p) => p.trim(),
        None => {
            return mcp_error(
                req_id,
                -32602,
                "vault_path is required (e.g. 'oauth/gmail/{user_id}/{account}/access_token')",
            );
        }
    };

    // Canonical shape: oauth/{provider}/{user_id}/{provider_key}/access_token
    let parts: Vec<&str> = vault_path.split('/').collect();
    if parts.len() != 5 || parts[0] != "oauth" || parts[4] != "access_token" {
        return mcp_error(
            req_id,
            -32602,
            "vault_path must match 'oauth/{provider}/{user_id}/{provider_key}/access_token'",
        );
    }

    let path_user_id: Uuid = match parts[2].parse() {
        Ok(u) => u,
        Err(_) => {
            return mcp_error(
                req_id,
                -32602,
                "vault_path segment 2 is not a valid UUID (expected user_id)",
            );
        }
    };
    if path_user_id != user_id {
        // Do not reveal whether the target user exists — generic message.
        return mcp_error(
            req_id,
            -32601,
            "cannot refresh OAuth tokens for another user — path user_id does not match caller",
        );
    }

    let oauth_service = std::sync::Arc::new(talos_oauth::OAuthCredentialService::new(
        state.secrets_manager.db_pool().clone(),
        state.secrets_manager.clone(),
    ));
    match oauth_service.refresh_oauth_token_if_needed(vault_path).await {
        Ok(true) => mcp_text(
            req_id,
            &serde_json::json!({
                "refreshed": true,
                "reason": "refreshed",
                "vault_path": vault_path,
                "tip": "A new access_token has been written to the vault. Retry the failing workflow.",
            })
            .to_string(),
        ),
        Ok(false) => mcp_text(
            req_id,
            &serde_json::json!({
                "refreshed": false,
                "reason": "still_valid",
                "vault_path": vault_path,
                "tip": "Stored token_expires_at is > 10min from now. If workflows are still 401ing, check whether token_expires_at reflects reality or whether the provider revoked the token on its side.",
            })
            .to_string(),
        ),
        Err(e) => {
            tracing::warn!(
                target: "talos_oauth_refresh",
                %vault_path,
                error = %e,
                "manual refresh_oauth_token failed"
            );
            mcp_error(
                req_id,
                -32000,
                &format!(
                    "OAuth refresh failed: {}. Common causes: (1) missing env vars (GOOGLE_CLIENT_ID/SECRET, ATLASSIAN_CLIENT_ID/SECRET); (2) the refresh_token is revoked (user needs to re-authorize); (3) the integration_credentials row is missing or marked is_active=false.",
                    e
                ),
            )
        }
    }
}
