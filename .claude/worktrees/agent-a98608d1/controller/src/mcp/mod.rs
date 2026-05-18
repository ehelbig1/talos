use axum::{
    extract::State,
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse,
    },
    routing::{get, post},
    Json, Router,
};
use futures_util::stream::Stream;
use serde::{Deserialize, Serialize};
use std::{convert::Infallible, time::Duration};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt as _;

use crate::compilation::CompilationService;
use crate::registry::ModuleRegistry;

pub mod auth;

// -----------------------------------------------------------------------------
// MCP Types
// -----------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Option<serde_json::Value>,
    pub method: String,
    pub params: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

// -----------------------------------------------------------------------------
// App State for MCP
// -----------------------------------------------------------------------------

#[derive(Clone)]
pub struct McpState {
    pub db_pool: sqlx::PgPool,
    pub registry: std::sync::Arc<ModuleRegistry>,
    pub sse_sender: broadcast::Sender<Event>,
    pub runtime: std::sync::Arc<worker::runtime::TalosRuntime>,
    pub compiler: std::sync::Arc<CompilationService>,
}

pub fn create_router(
    registry: std::sync::Arc<ModuleRegistry>,
    db_pool: sqlx::PgPool,
    runtime: std::sync::Arc<worker::runtime::TalosRuntime>,
    compiler: std::sync::Arc<CompilationService>,
) -> Router {
    let (sse_sender, _) = broadcast::channel(100);
    let state = McpState {
        db_pool: db_pool.clone(),
        registry,
        sse_sender,
        runtime,
        compiler,
    };

    Router::new()
        .route("/sse", get(sse_handler))
        .route("/message", post(message_handler))
        .route_layer(axum::middleware::from_fn_with_state(
            db_pool.clone(),
            auth::mcp_auth_middleware,
        ))
        .with_state(state)
}

/// Establish an SSE connection (acting as an MCP transport).
async fn sse_handler(
    State(state): State<McpState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.sse_sender.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|res| res.ok()).map(Ok);

    // Provide the initial `endpoint` event according to MCP spec
    let init_event = Event::default().event("endpoint").data("/mcp/message");

    let stream = futures_util::stream::once(async move { Ok(init_event) }).chain(stream);

    Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
}

/// Accept JSON-RPC messages from the MCP client.
async fn message_handler(
    State(state): State<McpState>,
    axum::extract::Extension(agent): axum::extract::Extension<std::sync::Arc<auth::AgentIdentity>>,
    Json(payload): Json<JsonRpcRequest>,
) -> impl IntoResponse {
    let response = match payload.method.as_str() {
        "initialize" => handle_initialize(payload),
        "tools/list" => handle_tools_list(payload, state.registry.clone(), agent.clone()).await,
        "tools/call" => handle_tools_call(payload, state.clone(), agent.clone()).await,
        "resources/list" => handle_resources_list(payload, state.db_pool.clone()).await,
        "resources/read" => handle_resources_read(payload, state.db_pool.clone()).await,
        _ => JsonRpcResponse {
            jsonrpc: "2.0".to_string(),
            id: payload.id,
            result: None,
            error: Some(JsonRpcError {
                code: -32601, // Method not found
                message: "Method not found".to_string(),
                data: None,
            }),
        },
    };

    // Send response back via SSE
    if let Ok(json_str) = serde_json::to_string(&response) {
        let event = Event::default().event("message").data(json_str);
        let _ = state.sse_sender.send(event);
    }

    // Acknowledge the POST
    axum::http::StatusCode::ACCEPTED
}

// -----------------------------------------------------------------------------
// Message Handlers
// -----------------------------------------------------------------------------

fn handle_initialize(req: JsonRpcRequest) -> JsonRpcResponse {
    let result = serde_json::json!({
        "protocolVersion": "2024-11-05", // MCP spec version
        "serverInfo": {
            "name": "Talos Native MCP Server",
            "version": "1.0.0"
        },
        "capabilities": {
            "tools": {},
            "resources": {}
        }
    });

    JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id: req.id,
        result: Some(result),
        error: None,
    }
}

async fn handle_tools_list(
    req: JsonRpcRequest,
    registry: std::sync::Arc<ModuleRegistry>,
    agent: std::sync::Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let templates = match registry.list_templates(None).await {
        Ok(t) => t,
        Err(e) => {
            return JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: req.id,
                result: None,
                error: Some(JsonRpcError {
                    code: -32000,
                    message: format!("Database error: {}", e),
                    data: None,
                }),
            }
        }
    };

    let mut tools = Vec::new();
    let state_db_pool = registry.db_pool.clone();

    for t in templates {
        // Enforce RBAC filtering: only show tools the agent has capabilities for
        // NodeTemplate in the registry might not have capability_world directly,
        // it requires joining with wasm_modules, but for now we skip RBAC on list or query it.
        // Actually we will query wasm_modules for this template's capabilities.
        let template_world = sqlx::query_scalar::<_, String>(
            "SELECT capability_world FROM wasm_modules WHERE template_id = $1 ORDER BY compiled_at DESC LIMIT 1"
        ).bind(t.id).fetch_optional(&state_db_pool).await.unwrap_or(None).unwrap_or("unknown".to_string());

        let world_base = template_world.trim_end_matches("-node");
        let has_cap = agent
            .allowed_capabilities
            .iter()
            .any(|c| c == "*" || c == world_base || format!("{}-node", c) == template_world);
        if !has_cap && template_world != "minimal" {
            continue;
        }

        let input_schema = if t.config_schema.is_null() {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "input": {
                        "type": "string",
                        "description": "Input data for the node"
                    }
                },
                "required": ["input"]
            })
        } else {
            t.config_schema
        };

        tools.push(serde_json::json!({
            "name": format!("{}-v1", t.name.replace(" ", "_")), // sanitized name
            "description": t.description.unwrap_or_default(),
            "inputSchema": input_schema
        }));
    }

    // Add compile_custom_sandbox tool for AI Authorship
    tools.push(serde_json::json!({
        "name": "compile_custom_sandbox",
        "description": "Compiles a totally custom Rust function into a secure Wasm sandbox. You provide the core logic and dependencies, and it generates the boilerplate and returns a node_address that you can then execute.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "capability_world": {
                    "type": "string",
                    "description": "The specific WIT world this code requires to run (e.g., 'network-node', 'automation-node', 'secrets-node')"
                },
                "dependencies": {
                    "type": "object",
                    "description": "A JSON object mapping crate names to version strings (e.g. {\"reqwest\": \"0.11\"}). DO NOT include standard dependencies like serde or the talos SDK, only third-party crates needed for your specific logic."
                },
                "rust_code": {
                    "type": "string",
                    "description": "The exact Rust source code for the module's execution logic. \n\
                    CRITICAL RULES:\n\
                    1. ONLY output valid Rust code. Do not include markdown formatting like ```rust, just the raw code.\n\
                    2. Provide ONLY your `use` statements and a `pub fn run(input: serde_json::Value) -> Result<serde_json::Value, String>` function (or async fn run). \n\
                    3. DO NOT wrap the code in a module or add the `#[talos_node]` macro. The system will automatically generate the macro boilerplate and module wrapper.\n\
                    4. DO NOT use or import `talos_sdk`. It does not exist in this environment. Use standard Rust standard library and external crates."
                }
            },
            "required": ["rust_code", "capability_world"]
        }
    }));

    JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id: req.id,
        result: Some(serde_json::json!({
            "tools": tools
        })),
        error: None,
    }
}

async fn handle_tools_call(
    req: JsonRpcRequest,
    state: McpState,
    agent: std::sync::Arc<auth::AgentIdentity>,
) -> JsonRpcResponse {
    let name = req
        .params
        .as_ref()
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
        .unwrap_or("");

    let args = req
        .params
        .as_ref()
        .and_then(|p| p.get("arguments"))
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));

    if name == "compile_custom_sandbox" {
        let capability_world = args
            .get("capability_world")
            .and_then(|v| v.as_str())
            .unwrap_or("http-node");

        // RBAC CHECK 1: Ensure agent is allowed to compile/use this capability world
        let world_base = capability_world.trim_end_matches("-node");
        let has_cap = agent
            .allowed_capabilities
            .iter()
            .any(|c| c == "*" || c == world_base || format!("{}-node", c) == capability_world);

        if !has_cap && capability_world != "minimal" {
            return JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: req.id,
                result: None,
                error: Some(JsonRpcError {
                    code: -32003, // Unauthorized
                    message: format!(
                        "Unauthorized: Agent role '{}' lacks capability to compile tools for the '{}' world. Allowed capabilities: {:?}", 
                        agent.role_name, capability_world, agent.allowed_capabilities
                    ),
                    data: None,
                }),
            };
        }

        let dependencies = args.get("dependencies");

        let inner_rust_code = args
            .get("rust_code")
            .and_then(|v| v.as_str())
            .unwrap_or_default();

        if inner_rust_code.is_empty() {
            return JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: req.id,
                result: None,
                error: Some(JsonRpcError {
                    code: -32602,
                    message: "Missing 'rust_code' argument".to_string(),
                    data: None,
                }),
            };
        }

        let rust_code = if inner_rust_code.contains("#[talos_node")
            || inner_rust_code.contains("talos_sdk_macros::talos_node")
        {
            inner_rust_code.to_string()
        } else {
            match regex::Regex::new(r"(?m)^\s*(pub\s+)?(async\s+)?fn\s+run") {
                Ok(re) => {
                    let replacement = format!(
                        "#[talos_sdk_macros::talos_node(world = \"{}\")]\n$0",
                        capability_world
                    );
                    re.replace(inner_rust_code, replacement.as_str())
                        .to_string()
                }
                Err(e) => {
                    return JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        id: req.id,
                        result: None,
                        error: Some(JsonRpcError {
                            code: -32603,
                            message: format!("Regex error: {}", e),
                            data: None,
                        }),
                    };
                }
            }
        };

        let compilation = state
            .compiler
            .compile_to_wasm_with_config(
                "custom_sandbox",
                &rust_code,
                &serde_json::json!({}),
                dependencies,
            )
            .await;

        match compilation {
            Ok(res) if res.success => {
                let wasm_bytes = match res.wasm_bytes {
                    Some(b) => b,
                    None => {
                        return JsonRpcResponse {
                            jsonrpc: "2.0".to_string(),
                            id: req.id,
                            result: None,
                            error: Some(JsonRpcError {
                                code: -32603,
                                message: "Compilation success but missing wasm_bytes".to_string(),
                                data: None,
                            }),
                        };
                    }
                };
                let sandbox_id = uuid::Uuid::new_v4();
                // Short ID for cleaner tool names
                let short_id = &sandbox_id.to_string()[0..8];
                let template_name = format!("sandbox {}", short_id);

                let db_result = sqlx::query(
                    "INSERT INTO node_templates (name, category, description, config_schema, code_template, precompiled_wasm, icon)
                     VALUES ($1, $2, $3, $4, $5, $6, $7)"
                )
                .bind(&template_name)
                .bind("sandbox")
                .bind("Custom AI-generated sandbox node")
                .bind(serde_json::json!({}))
                .bind(&rust_code)
                .bind(wasm_bytes)
                .bind("🧪")
                .execute(&state.db_pool)
                .await;

                if let Err(e) = db_result {
                    return JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        id: req.id,
                        result: None,
                        error: Some(JsonRpcError {
                            code: -32000,
                            message: format!("Failed to save compiled sandbox to registry: {}", e),
                            data: None,
                        }),
                    };
                }

                let tool_name = format!("sandbox_{}-v1", short_id);
                return JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: req.id,
                    result: Some(serde_json::json!({
                        "content": [
                            {
                                "type": "text",
                                "text": format!("Compilation successful! You can now execute your module by calling the newly registered tool: '{}'", tool_name)
                            }
                        ]
                    })),
                    error: None,
                };
            }
            Ok(res) => {
                let error_msgs: Vec<String> = res.errors.into_iter().map(|e| e.message).collect();
                return JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: req.id,
                    result: Some(serde_json::json!({
                        "content": [
                            {
                                "type": "text",
                                "text": format!("Compilation failed with the following errors:\n{}", error_msgs.join("\n"))
                            }
                        ]
                    })),
                    error: None,
                };
            }
            Err(e) => {
                return JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: req.id,
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32000,
                        message: format!("Compilation service encountered an error: {}", e),
                        data: None,
                    }),
                };
            }
        }
    }

    // Connect to the tool in the registry
    let templates = state
        .registry
        .list_templates(None)
        .await
        .unwrap_or_default();
    let original_name = name.strip_suffix("-v1").unwrap_or(name).replace("_", " ");

    let target_template = templates.into_iter().find(|t| t.name == original_name);

    if let Some(template) = target_template {
        // RBAC CHECK 2: Ensure agent is allowed to execute this specific template
        let template_world = sqlx::query_scalar::<_, String>(
            "SELECT capability_world FROM wasm_modules WHERE template_id = $1 ORDER BY compiled_at DESC LIMIT 1"
        ).bind(template.id).fetch_optional(&state.db_pool).await.unwrap_or_default().unwrap_or("unknown".to_string());

        let world_base = template_world.trim_end_matches("-node");
        let has_cap = agent
            .allowed_capabilities
            .iter()
            .any(|c| c == "*" || c == world_base || format!("{}-node", c) == template_world);

        if !has_cap && template_world != "minimal" {
            return JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: req.id,
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32003, // Unauthorized
                        message: format!(
                            "Unauthorized: Agent role '{}' lacks capability to execute tools requiring the '{}' world. Allowed capabilities: {:?}", 
                            agent.role_name, template_world, agent.allowed_capabilities
                        ),
                        data: None,
                    }),
                };
        }

        let wasm_bytes = match template
            .precompiled_wasm
            .filter(|b| b.starts_with(b"\0asm"))
        {
            Some(b) => b,
            None => {
                return JsonRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    id: req.id,
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32000,
                        message: format!("Template {} has no precompiled WASM", template.name),
                        data: None,
                    }),
                };
            }
        };

        let (tx, mut rx) = tokio::sync::mpsc::channel(100);
        let sse_sender_local = state.sse_sender.clone();

        let progress_task = tokio::spawn(async move {
            while let Some(chunk) = rx.recv().await {
                if let Ok(s) = String::from_utf8(chunk) {
                    let event = Event::default().event("stdout").data(s);
                    let _ = sse_sender_local.send(event);
                }
            }
        });

        let payload = serde_json::json!({
            "config": args,
            "input": null
        });

        let execution_result = state
            .runtime
            .execute_job_with_full_features(
                &wasm_bytes,
                vec![],                                  // allowed_hosts
                vec![],                                  // allowed_methods
                128,                                     // max_memory_mb
                payload,                                 // input
                None,                                    // execution_fs_dir
                None,                                    // execution_context
                std::collections::HashMap::new(),        // secrets
                Some(tx),                                // token_sender
                Duration::from_secs(30),                 // timeout
                worker::runtime::RetryPolicy::default(), // retry_policy
                None,                                    // result_cache_ttl_secs
            )
            .await;

        let _ = progress_task.await;

        return match execution_result {
            Ok(val) => JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: req.id,
                result: Some(serde_json::json!({
                    "content": [
                        {
                            "type": "text",
                            "text": val.to_string()
                        }
                    ]
                })),
                error: None,
            },
            Err(e) => JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: req.id,
                result: None,
                error: Some(JsonRpcError {
                    code: -32000,
                    message: format!("Execution failed: {}", e),
                    data: None,
                }),
            },
        };
    }

    JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id: req.id,
        result: None,
        error: Some(JsonRpcError {
            code: -32601,
            message: format!("Tool not found: {}", name),
            data: None,
        }),
    }
}

// -----------------------------------------------------------------------------
// MCP Resources
// -----------------------------------------------------------------------------

async fn handle_resources_list(req: JsonRpcRequest, db_pool: sqlx::PgPool) -> JsonRpcResponse {
    use sqlx::Row;
    // Fetch recent 10 executions to expose as resources for the AI
    let records = match sqlx::query(
        r#"
        SELECT id, module_id, status, error_message
        FROM module_executions
        ORDER BY started_at DESC NULLS LAST
        LIMIT 10
        "#,
    )
    .fetch_all(&db_pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            return JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: req.id,
                result: None,
                error: Some(JsonRpcError {
                    code: -32000,
                    message: format!("Database error: {}", e),
                    data: None,
                }),
            };
        }
    };

    let mut resources = Vec::new();
    for rec in records {
        let id: uuid::Uuid = rec.get("id");
        let module_id: uuid::Uuid = rec.get("module_id");
        let status: String = rec.get("status");

        resources.push(serde_json::json!({
            "uri": format!("talos://executions/{}", id),
            "name": format!("Execution {}", id),
            "mimeType": "application/json",
            "description": format!("Module execution {} (status: {})", module_id, status)
        }));

        resources.push(serde_json::json!({
            "uri": format!("talos://executions/{}/logs", id),
            "name": format!("Execution {} Logs", id),
            "mimeType": "text/plain",
            "description": format!("Execution logs for {}", id)
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

async fn handle_resources_read(req: JsonRpcRequest, db_pool: sqlx::PgPool) -> JsonRpcResponse {
    use sqlx::Row;
    let params = match req.params {
        Some(p) => p,
        None => {
            return JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: req.id,
                result: None,
                error: Some(JsonRpcError {
                    code: -32602,
                    message: "Missing params".to_string(),
                    data: None,
                }),
            };
        }
    };

    let uri = match params.get("uri").and_then(|u| u.as_str()) {
        Some(u) => u,
        None => {
            return JsonRpcResponse {
                jsonrpc: "2.0".to_string(),
                id: req.id,
                result: None,
                error: Some(JsonRpcError {
                    code: -32602,
                    message: "Missing uri parameter".to_string(),
                    data: None,
                }),
            };
        }
    };

    if uri.starts_with("talos://executions/") && uri.ends_with("/logs") {
        let exec_id_str = uri
            .trim_start_matches("talos://executions/")
            .trim_end_matches("/logs");
        let exec_id = match uuid::Uuid::parse_str(exec_id_str) {
            Ok(id) => id,
            Err(_) => return resource_not_found_error(req.id, uri),
        };

        // Fetch logs
        let logs = match sqlx::query(
            r#"
            SELECT level, message, created_at
            FROM module_execution_logs
            WHERE execution_id = $1
            ORDER BY created_at ASC
            "#,
        )
        .bind(exec_id)
        .fetch_all(&db_pool)
        .await
        {
            Ok(r) => r,
            Err(_) => return resource_not_found_error(req.id, uri),
        };

        let mut log_text = String::new();
        for l in logs {
            let log_level: String = l.get("level");
            let message: String = l.get("message");
            let created_at: chrono::DateTime<chrono::Utc> = l.get("created_at");
            log_text.push_str(&format!("[{}] {} - {}\n", created_at, log_level, message));
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

        let record_opt = match sqlx::query(
            r#"
            SELECT id, module_id, status, error_message, output_data
            FROM module_executions
            WHERE id = $1
            "#,
        )
        .bind(exec_id)
        .fetch_optional(&db_pool)
        .await
        {
            Ok(r) => r,
            _ => return resource_not_found_error(req.id, uri),
        };

        if let Some(record) = record_opt {
            let id: uuid::Uuid = record.get("id");
            let module_id: uuid::Uuid = record.get("module_id");
            let status: String = record.get("status");
            let error_message: Option<String> = record.get("error_message");
            let output_data: Option<serde_json::Value> = record.get("output_data");

            let val = serde_json::json!({
                "id": id,
                "module_id": module_id,
                "status": status,
                "error_message": error_message,
                "output_data": output_data
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

fn resource_not_found_error(id: Option<serde_json::Value>, uri: &str) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        id,
        result: None,
        error: Some(JsonRpcError {
            code: -32001,
            message: format!("Resource not found: {}", uri),
            data: None,
        }),
    }
}
