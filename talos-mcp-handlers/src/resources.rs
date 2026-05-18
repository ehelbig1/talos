use super::types::{JsonRpcRequest, JsonRpcResponse};
use super::utils::{mcp_error, resource_not_found_error};

pub async fn handle_resources_list(
    req: JsonRpcRequest,
    db_pool: sqlx::PgPool,
    agent: std::sync::Arc<super::auth::AgentIdentity>,
) -> JsonRpcResponse {
    // SECURITY: Scope resource listing to the agent's user_id to prevent cross-user data access.
    let user_id = match agent.user_id {
        Some(uid) => uid,
        None => {
            return JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: req.id,
                result: Some(serde_json::json!({ "resources": [] })),
                error: None,
            };
        }
    };

    // Fetch recent 10 executions scoped to the agent's user
    let exec_repo = talos_execution_repository::ExecutionRepository::new(db_pool.clone());
    let records = match exec_repo
        .list_recent_module_executions_for_user(user_id, 10)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(err = ?e, user_id = %user_id, "list_resources: database query failed");
            return mcp_error(req.id, -32000, "Database error");
        }
    };

    let mut resources = Vec::new();
    for rec in records {
        resources.push(serde_json::json!({
            "uri": format!("talos://executions/{}", rec.id),
            "name": format!("Execution {}", rec.id),
            "mimeType": "application/json",
            "description": format!("Module execution {} (status: {})", rec.module_id, rec.status)
        }));

        resources.push(serde_json::json!({
            "uri": format!("talos://executions/{}/logs", rec.id),
            "name": format!("Execution {} Logs", rec.id),
            "mimeType": "text/plain",
            "description": format!("Execution logs for {}", rec.id)
        }));
    }

    JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id: req.id,
        result: Some(serde_json::json!({
            "resources": resources
        })),
        error: None,
    }
}

pub async fn handle_resources_read(
    req: JsonRpcRequest,
    // MCP-681 (2026-05-13): db_pool no longer needed — every callsite
    // here used it to construct a fresh ExecutionRepository that was
    // missing `with_encryption`, surfacing `output_data: null` for
    // every encrypted module execution. Take the shared
    // ExecutionRepository instead so decryption is transparent.
    _db_pool: sqlx::PgPool,
    execution_repo: std::sync::Arc<talos_execution_repository::ExecutionRepository>,
    agent: std::sync::Arc<super::auth::AgentIdentity>,
) -> JsonRpcResponse {
    let params = match req.params {
        Some(p) => p,
        None => return mcp_error(req.id, -32602, "Missing params"),
    };

    let uri = match params.get("uri").and_then(|u| u.as_str()) {
        Some(u) => u,
        None => return mcp_error(req.id, -32602, "Missing uri parameter"),
    };

    // SECURITY: Scope resource reads to the agent's user_id.
    let user_id = agent.user_id;

    if uri.starts_with("talos://executions/") && uri.ends_with("/logs") {
        let exec_id_str = uri
            .trim_start_matches("talos://executions/")
            .trim_end_matches("/logs");
        let exec_id = match uuid::Uuid::parse_str(exec_id_str) {
            Ok(id) => id,
            Err(_) => return resource_not_found_error(req.id, uri),
        };

        // Verify the execution belongs to this user before returning logs.
        // MCP-681: use the shared encryption-aware repo so other callsites
        // here (output_data decrypt) work; `module_execution_owned_by`
        // doesn't need encryption but the consistent reference keeps the
        // function simple.
        let exec_repo = execution_repo.clone();
        if let Some(uid) = user_id {
            let owns = exec_repo
                .module_execution_owned_by(exec_id, uid)
                .await
                .unwrap_or(false);
            if !owns {
                return resource_not_found_error(req.id, uri);
            }
        } else {
            return resource_not_found_error(req.id, uri);
        }

        // Fetch logs
        let logs = match exec_repo.list_module_execution_logs(exec_id).await {
            Ok(r) => r,
            Err(_) => return resource_not_found_error(req.id, uri),
        };

        let mut log_text = String::new();
        for l in logs {
            log_text.push_str(&format!("[{}] {} - {}\n", l.created_at, l.level, l.message));
        }

        return JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: req.id,
            result: Some(serde_json::json!({
                "contents": [
                    {
                        "uri": uri,
                        "mimeType": "text/plain",
                        "text": log_text
                    }
                ]
            })),
            error: None,
        };
    } else if uri.starts_with("talos://executions/") {
        let exec_id_str = uri.trim_start_matches("talos://executions/");
        let exec_id = match uuid::Uuid::parse_str(exec_id_str) {
            Ok(id) => id,
            Err(_) => return resource_not_found_error(req.id, uri),
        };

        // MCP-681: use shared encryption-aware repo. Pre-fix
        // `ExecutionRepository::new(db_pool)` was missing the
        // `with_encryption` builder, so `output_data` came back None for
        // every encrypted module execution. The shared repo from McpState
        // has SecretsManager wired so decryption is transparent.
        let exec_repo = execution_repo.clone();
        let record_opt = match user_id {
            Some(uid) => exec_repo.get_module_execution_for_user(exec_id, uid).await,
            None => Ok(None),
        };
        let record_opt = match record_opt {
            Ok(r) => r,
            _ => return resource_not_found_error(req.id, uri),
        };

        if let Some(record) = record_opt {
            let val = serde_json::json!({
                "id": record.id,
                "module_id": record.module_id,
                "status": record.status,
                "error_message": record.error_message,
                "output_data": record.output_data
            });

            return JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: req.id,
                result: Some(serde_json::json!({
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": "application/json",
                            "text": serde_json::to_string_pretty(&val).unwrap_or_default()
                        }
                    ]
                })),
                error: None,
            };
        } else {
            return resource_not_found_error(req.id, uri);
        }
    }

    resource_not_found_error(req.id, uri)
}
