use super::types::JsonRpcResponse;
use super::utils::{mcp_denied, mcp_error, mcp_text};
use super::McpState;
use serde_json::Value;
use std::sync::Arc;

/// MCP tool schemas for Ollama (Tier 1 — local LLM) management and inference.
pub fn tool_schemas() -> Vec<Value> {
    vec![
        serde_json::json!({
            "name": "ollama_list_models",
            "description": "List all locally available Ollama models with sizes, quantization, and parameter counts. Use this to check which models are ready for local inference before calling local_llm_complete.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }),
        serde_json::json!({
            "name": "ollama_pull_model",
            "description": "Pull (download) a model from the Ollama registry into local storage. This can take several minutes for large models. Common models: mistral (7B, fast), llama3 (8B, balanced), phi3 (3.8B, compact), codellama (7B, code-focused), gemma2 (9B, multilingual).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": { "type": "string", "description": "Model name to pull (e.g. 'mistral', 'llama3:8b', 'phi3')" }
                },
                "required": ["name"]
            }
        }),
        serde_json::json!({
            "name": "ollama_delete_model",
            "description": "Delete a locally cached Ollama model to free disk space.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": { "type": "string", "description": "Model name to delete" }
                },
                "required": ["name"]
            }
        }),
        serde_json::json!({
            "name": "ollama_show_model",
            "description": "Get detailed information about a locally available model: parameters, quantization level, template format, and system prompt.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "name": { "type": "string", "description": "Model name to inspect" }
                },
                "required": ["name"]
            }
        }),
        serde_json::json!({
            "name": "local_llm_complete",
            "description": "Run a chat completion against a local Ollama model (Tier 1 — data stays on-prem, no API costs, no DLP needed). Ideal for: classification, entity extraction, simple summarization, JSON structuring, and processing sensitive data. For complex reasoning or large context, use the anthropic-structured-llm module (Tier 2) instead. The reply is the answer text, then a second block with {model, stop_reason, usage: {prompt_tokens, completion_tokens}, duration_ms}: `stop_reason` is the model's own word, and `length` means the answer was cut off at max_tokens (with an empty answer, the whole budget went on reasoning). Only a model that runs on this machine is called: a cloud-hosted Ollama model is refused.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "model": { "type": "string", "description": "Ollama model name (default: 'mistral')" },
                    "system_prompt": { "type": "string", "description": "System instructions for the model" },
                    "user_prompt": { "type": "string", "description": "User message / input to process" },
                    "max_tokens": { "type": "integer", "description": "Maximum tokens to generate (default: 1024). For a model that reasons first, reasoning counts against it." },
                    "options": { "type": "object", "description": "Provider options, the same object a module passes to `llm::complete_with_options`, checked and applied by the same code (at most 8 KiB): `think` (true/false), `response_format` ({\"type\": \"json_object\"} or a json_schema), `temperature`, `top_p`, `top_k`, `seed`, `stop`, `num_ctx`, `keep_alive`, … Use it to try a prompt exactly as a module will send it. Options tune the request: `model`, `messages`, `system` and `stream` in it are dropped, so it cannot change which model is called. `think` is off unless options sets it (a module that sets no `think` gets the model's own default, which for a reasoning model is on: pass \"think\": true to reproduce that)." }
                },
                "required": ["user_prompt"]
            }
        }),
    ]
}

/// Dispatch an MCP tool call to the appropriate handler.
pub async fn dispatch(
    tool_name: &str,
    req_id: Option<Value>,
    args: &Value,
    state: &McpState,
    agent: Arc<super::auth::AgentIdentity>,
) -> Option<JsonRpcResponse> {
    // MCP-328 (2026-05-11): pull/delete affect deployment-wide Ollama
    // state — the disk-cached model registry is shared across every
    // tenant. Per-tenant agent admin no longer carries authority over
    // shared infra; route through user_id so the handler can verify
    // `is_platform_admin` against the `users` table.
    let user_id = agent.user_id;
    match tool_name {
        "ollama_list_models" => Some(handle_list_models(req_id, state).await),
        "ollama_pull_model" => Some(handle_pull_model(req_id, args, state, user_id).await),
        "ollama_delete_model" => Some(handle_delete_model(req_id, args, state, user_id).await),
        "ollama_show_model" => Some(handle_show_model(req_id, args, state).await),
        "local_llm_complete" => Some(handle_local_complete(req_id, args, state, user_id).await),
        _ => None,
    }
}

async fn handle_list_models(req_id: Option<Value>, state: &McpState) -> JsonRpcResponse {
    let client = match &state.ollama_client {
        Some(c) => c,
        None => return mcp_error(req_id, -32000, "Ollama not configured (OLLAMA_URL not set)"),
    };

    match client.list_models().await {
        Ok(resp) => {
            let models = resp.get("models").cloned().unwrap_or(serde_json::json!([]));
            let summary: Vec<Value> = models
                .as_array()
                .unwrap_or(&vec![])
                .iter()
                .map(|m| {
                    serde_json::json!({
                        "name": m.get("name").and_then(|v| v.as_str()).unwrap_or("?"),
                        "size_gb": m.get("size").and_then(|v| v.as_f64()).map(|s| format!("{:.1}", s / 1_073_741_824.0)).unwrap_or_default(),
                        "modified_at": m.get("modified_at").and_then(|v| v.as_str()).unwrap_or(""),
                        "family": m.get("details").and_then(|d| d.get("family")).and_then(|v| v.as_str()).unwrap_or(""),
                        "parameter_size": m.get("details").and_then(|d| d.get("parameter_size")).and_then(|v| v.as_str()).unwrap_or(""),
                        "quantization": m.get("details").and_then(|d| d.get("quantization_level")).and_then(|v| v.as_str()).unwrap_or(""),
                    })
                })
                .collect();
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&serde_json::json!({
                    "models": summary,
                    "count": summary.len(),
                }))
                .unwrap_or_default(),
            )
        }
        Err(e) => {
            // MCP-217: log full error server-side, return generic message.
            tracing::error!("ollama list_models failed: {:#}", e);
            mcp_error(req_id, -32000, "Failed to list Ollama models")
        }
    }
}

async fn handle_pull_model(
    req_id: Option<Value>,
    args: &Value,
    state: &McpState,
    user_id: uuid::Uuid,
) -> JsonRpcResponse {
    // MCP-328 (2026-05-11): pulling a model consumes shared disk +
    // bandwidth on the Ollama host that backs every tenant in this
    // deployment. The pre-fix comment already named the issue
    // ("shared across tenants — pulls consume disk and bandwidth
    // globally") but the gate was the agent-level `is_admin` (per-
    // tenant admin role). An organization-scoped admin agent passed
    // and could DoS the inference plane by repeatedly pulling large
    // variants. Same require_platform_admin family as MCP-323/324/
    // 325/326/327; use `users.is_platform_admin`.
    let is_platform_admin = state
        .actor_repo
        .is_platform_admin(user_id)
        .await
        .unwrap_or(false);
    if !is_platform_admin {
        return mcp_denied(
            req_id,
            -32601,
            "ollama_pull_model requires platform-admin privileges. \
             The Ollama instance is shared across tenants — pulls consume disk \
             and bandwidth globally.",
        );
    }

    let client = match &state.ollama_client {
        Some(c) => c,
        None => return mcp_error(req_id, -32000, "Ollama not configured"),
    };

    let name = match validate_ollama_model_name(args, req_id.clone()) {
        Ok(n) => n,
        Err(resp) => return resp,
    };

    tracing::info!(model = %name, "Pulling Ollama model");
    match client.pull_model(&name).await {
        Ok(status) => mcp_text(
            req_id,
            &format!("Model '{}' pull completed. Status: {}", name, status),
        ),
        Err(e) => {
            // MCP-217 (2026-05-08): redact internal cluster details
            // (e.g. `http://talos-ollama.talos.svc.cluster.local:11434/...`)
            // from caller-visible errors. Log the full error server-side.
            tracing::error!(model = %name, "ollama pull_model failed: {:#}", e);
            mcp_error(req_id, -32000, &format!("Failed to pull model '{}'", name))
        }
    }
}

/// MCP-217 (2026-05-08): canonical Ollama model-name validator.
/// Rejects whitespace-only / wrong-type, enforces the same allowlist
/// pull_model already used (alphanumeric + `-:./_`). Used by
/// pull_model / delete_model / show_model so callers can't bypass the
/// allowlist by routing through one of the two handlers that didn't
/// have it. Returns the trimmed value so downstream HTTP requests
/// don't carry stray whitespace.
fn validate_ollama_model_name(
    args: &Value,
    req_id: Option<Value>,
) -> Result<String, JsonRpcResponse> {
    let raw = match args.get("name").and_then(|v| v.as_str()) {
        Some(n) if n.len() > 200 => {
            return Err(mcp_error(req_id, -32602, "name must be ≤ 200 characters"))
        }
        Some(n) => n,
        None => {
            return Err(mcp_error(
                req_id,
                -32602,
                "name is required (max 200 chars)",
            ))
        }
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(mcp_error(
            req_id,
            -32602,
            "name must be a non-empty, non-whitespace string",
        ));
    }
    if !trimmed.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '-' || c == ':' || c == '.' || c == '/' || c == '_'
    }) {
        return Err(mcp_error(req_id, -32602, "Invalid model name characters"));
    }
    Ok(trimmed.to_string())
}

async fn handle_delete_model(
    req_id: Option<Value>,
    args: &Value,
    state: &McpState,
    user_id: uuid::Uuid,
) -> JsonRpcResponse {
    // MCP-328 (2026-05-11): deleting a model is destructive cross-
    // tenant: any other tenant's workflows that target this model
    // fail until it's re-pulled. The pre-fix `is_admin` gate was per-
    // tenant — an organization-scoped admin agent could DoS every
    // other tenant's inference jobs by deleting their model. Switch
    // to the deployment-wide `is_platform_admin` gate.
    let is_platform_admin = state
        .actor_repo
        .is_platform_admin(user_id)
        .await
        .unwrap_or(false);
    if !is_platform_admin {
        return mcp_denied(
            req_id,
            -32601,
            "ollama_delete_model requires platform-admin privileges. \
             The Ollama instance is shared across tenants — deletions break \
             every tenant's inference jobs that target the model.",
        );
    }

    let client = match &state.ollama_client {
        Some(c) => c,
        None => return mcp_error(req_id, -32000, "Ollama not configured"),
    };

    let name = match validate_ollama_model_name(args, req_id.clone()) {
        Ok(n) => n,
        Err(resp) => return resp,
    };

    match client.delete_model(&name).await {
        Ok(()) => mcp_text(req_id, &format!("Model '{}' deleted.", name)),
        Err(e) => {
            // MCP-217: redact internal cluster details from caller errors.
            tracing::error!(model = %name, "ollama delete_model failed: {:#}", e);
            mcp_error(
                req_id,
                -32000,
                &format!("Failed to delete model '{}'", name),
            )
        }
    }
}

async fn handle_show_model(
    req_id: Option<Value>,
    args: &Value,
    state: &McpState,
) -> JsonRpcResponse {
    let client = match &state.ollama_client {
        Some(c) => c,
        None => return mcp_error(req_id, -32000, "Ollama not configured"),
    };

    let name = match validate_ollama_model_name(args, req_id.clone()) {
        Ok(n) => n,
        Err(resp) => return resp,
    };

    match client.show_model(&name).await {
        Ok(info) => {
            // Extract key details, omit raw model weights
            let summary = serde_json::json!({
                "model": name,
                "modelfile": info.get("modelfile").and_then(|v| v.as_str()).map(|s| s.chars().take(2000).collect::<String>()),
                "parameters": info.get("parameters"),
                "template": info.get("template"),
                "details": info.get("details"),
            });
            mcp_text(
                req_id,
                &serde_json::to_string_pretty(&summary).unwrap_or_default(),
            )
        }
        Err(e) => {
            // MCP-217 (2026-05-08): pre-fix the raw error string was
            // included in the MCP response body, leaking the internal
            // ollama service URL (e.g.
            // `http://talos-ollama.talos.svc.cluster.local:11434/api/show`).
            // Log full error server-side; return generic message.
            tracing::error!(model = %name, "ollama show_model failed: {:#}", e);
            mcp_error(req_id, -32000, &format!("Failed to show model '{}'", name))
        }
    }
}

/// Read the `options` argument of `local_llm_complete`: an object, checked
/// by the rule the worker applies to a module's `complete-with-options`
/// (`talos_worker_runtime::provider_options`), not by one written here.
///
/// # Errors
/// The worker's own words, or that the argument is not an object.
pub(crate) fn local_complete_options(
    args: &Value,
) -> Result<Option<serde_json::Map<String, Value>>, String> {
    match args.get("options") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(map)) if map.is_empty() => Ok(None),
        Some(object @ Value::Object(_)) => {
            talos_worker_runtime::provider_options::parse_provider_options(Some(
                &object.to_string(),
            ))
        }
        Some(other) => Err(format!(
            "options must be an object (for example {{\"think\": true}}), got {}",
            crate::utils::json_type_name(other)
        )),
    }
}

/// What `local_llm_complete` says about a completion, beside its text.
pub(crate) fn local_complete_report(
    model: &str,
    reply: &talos_llm::ChatReply,
    elapsed: std::time::Duration,
) -> Value {
    let cut_off = reply
        .stop_reason
        .as_deref()
        .is_some_and(|reason| reason.eq_ignore_ascii_case("length"));
    let mut report = serde_json::json!({
        "model": model,
        "stop_reason": reply.stop_reason,
        "usage": {
            "prompt_tokens": reply.prompt_tokens,
            "completion_tokens": reply.completion_tokens,
        },
        "duration_ms": u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
    });
    if cut_off {
        report["note"] = Value::String(if reply.text.is_empty() {
            "Stopped for length with no answer: the whole max_tokens budget went on reasoning. \
             Raise max_tokens, or pass options {\"think\": false}."
                .to_string()
        } else {
            "Stopped for length: the answer above is cut off at max_tokens.".to_string()
        });
    }
    report
}

async fn handle_local_complete(
    req_id: Option<Value>,
    args: &Value,
    state: &McpState,
    user_id: uuid::Uuid,
) -> JsonRpcResponse {
    let client = match &state.ollama_client {
        Some(c) => c,
        None => return mcp_error(req_id, -32000, "Ollama not configured (OLLAMA_URL not set)"),
    };

    // MCP-347 (2026-05-11): pre-fix `as_str().unwrap_or("mistral")`
    // collapsed wrong-type into "mistral". An operator passing
    // `model: 42` (number — e.g. confused after copy-pasting a
    // configured model id meant for a different field) silently
    // dispatched the inference against "mistral" instead of the
    // specifically-requested model. Wastes inference budget AND the
    // operator gets responses that don't match the model they
    // believe they're testing. Same MCP-346 family applied to an
    // inference-target surface.
    let model =
        match crate::utils::validate_optional_string(args, "model", "mistral", None, &req_id) {
            Ok(s) => s,
            Err(resp) => return resp,
        };
    let system_prompt = args
        .get("system_prompt")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    // MCP-230 (2026-05-08): trim user_prompt at the boundary. Pre-fix
    // `!p.is_empty()` accepted whitespace and dispatched a real
    // ollama inference on noise — wastes inference budget AND
    // returns gibberish to the caller.
    let user_prompt = match args.get("user_prompt").and_then(|v| v.as_str()) {
        Some(p) if !p.trim().is_empty() => p.trim(),
        _ => return mcp_error(req_id, -32602, "user_prompt is required (non-whitespace)"),
    };
    // MCP-185 (2026-05-08): replace silent-clamp with explicit
    // validation. The 8K ceiling stays as a resource-exhaustion
    // guard, but reject out-of-range values loudly so the caller
    // knows their max_tokens didn't take effect.
    let max_tokens =
        match crate::utils::validate_range_u64(args, "max_tokens", 1, 8192, 1024, &req_id) {
            Ok(v) => v as u32,
            Err(resp) => return resp,
        };

    // SECURITY: No DLP needed — data stays local (Tier 1).
    // Input size validation to prevent excessive memory use.
    if user_prompt.len() > 100_000 {
        return mcp_error(req_id, -32602, "user_prompt exceeds 100KB limit");
    }
    if system_prompt.len() > 50_000 {
        return mcp_error(req_id, -32602, "system_prompt exceeds 50KB limit");
    }

    // `options`: what a module passes to `llm::complete-with-options`,
    // checked by the worker's own rule and applied by its own translation,
    // so a prompt tried here is sent as the module would send it.
    let options = match local_complete_options(args) {
        Ok(options) => options,
        Err(message) => return mcp_error(req_id, -32602, &message),
    };
    let apply_options = |body: &mut Value| {
        if let Some(options) = options.clone() {
            talos_worker_runtime::provider_options::apply_to_local_body(body, options);
        }
    };

    // R2 token ledger: attribute usage to the requesting user. An agent
    // identity always carries one (D-7), so there is no unscoped branch.
    let started = std::time::Instant::now();
    let call = client.complete_with_options(
        &model,
        system_prompt,
        user_prompt,
        max_tokens,
        apply_options,
    );
    let completion = talos_llm::usage::scoped_user(user_id, call).await;
    match completion {
        Ok(reply) => {
            let report = local_complete_report(&model, &reply, started.elapsed());
            // The answer first and on its own, as it has always been; what
            // the model said about it in a second block.
            let mut resp = mcp_text(req_id, &reply.text);
            crate::utils::append_warning_block(&mut resp, &report.to_string());
            resp
        }
        Err(e) => {
            // MCP-316 (2026-05-11): mirror the MCP-217 redaction applied
            // to list/pull/delete/show. The four sibling handlers all
            // log full errors server-side and return generic messages
            // (so the internal Ollama URL like
            // `http://talos-ollama.talos.svc.cluster.local:11434/...`
            // doesn't surface to callers when reqwest fails on
            // connection / DNS / timeout), but this handler was the
            // outlier — it formatted `{}` of the anyhow error into the
            // MCP response body, leaking the cluster-internal URL on
            // every network failure. Same handler family, same redaction.
            tracing::error!(model = %model, "ollama local_complete failed: {:#}", e);
            mcp_error(req_id, -32000, "Local LLM completion failed")
        }
    }
}

#[cfg(test)]
mod local_complete_tests {
    use super::{local_complete_options, local_complete_report};
    use serde_json::json;

    /// The request the tool sends for `args`, as the client builds it.
    fn request(args: &serde_json::Value) -> serde_json::Value {
        let options = local_complete_options(args).expect("options accepted");
        talos_llm::local_request_with_options("local-model", "sys", "ask", 1500, |body| {
            if let Some(options) = options.clone() {
                talos_worker_runtime::provider_options::apply_to_local_body(body, options);
            }
        })
    }

    /// The observed module passed `{"think": true, "response_format":
    /// {"type": "json_object"}}`; the tool took no options, so the same
    /// prompt answered in 0.6 s and differently. With the same options the
    /// tool now sends what the module sends.
    #[test]
    fn a_modules_options_are_sent_as_the_module_would_send_them() {
        let body = request(&json!({
            "options": { "think": true, "response_format": { "type": "json_object" }, "seed": 7 }
        }));
        assert_eq!(body["think"], true);
        assert_eq!(body["format"], "json");
        assert_eq!(body["options"]["seed"], 7);
        assert_eq!(body["options"]["num_predict"], 1500);

        // No options: the call the tool has always made (thinking off).
        for args in [
            json!({}),
            json!({ "options": null }),
            json!({ "options": {} }),
        ] {
            let body = request(&args);
            assert_eq!(body["think"], false, "{args}");
            assert!(body.get("format").is_none(), "{args}");
        }
    }

    /// Options are the worker's to check. What it refuses, the tool refuses,
    /// in the worker's words.
    #[test]
    fn options_the_validator_refuses_are_refused_and_the_model_cannot_be_moved() {
        for (bad, why) in [
            (json!("think"), "options must be an object"),
            (json!(["think"]), "options must be an object"),
            (json!(true), "options must be an object"),
            (
                json!({ "pad": "x".repeat(9 * 1024) }),
                "provider options exceed 8192 bytes",
            ),
        ] {
            let refusal = local_complete_options(&json!({ "options": bad })).unwrap_err();
            assert!(refusal.contains(why), "{refusal}");
        }

        // Not a refusal, and not obeyed: an option naming another model or
        // other messages is dropped, so the model that is called is the one
        // the locality check was asked about.
        let body = request(&json!({ "options": {
            "model": "someone-elses:cloud",
            "messages": [{ "role": "user", "content": "other" }],
            "stream": true,
        }}));
        assert_eq!(body["model"], "local-model");
        assert_eq!(body["messages"][1]["content"], "ask");
        assert_eq!(body["stream"], false);
    }

    #[test]
    fn the_report_says_when_the_answer_was_cut_off_and_whether_any_arrived() {
        let reply = |text: &str, stop: &str, completion: u64| talos_llm::ChatReply {
            text: text.to_string(),
            stop_reason: Some(stop.to_string()),
            prompt_tokens: Some(412),
            completion_tokens: Some(completion),
        };
        let elapsed = std::time::Duration::from_millis(41_000);
        let cut = local_complete_report("local-model", &reply("", "length", 1500), elapsed);
        assert_eq!(cut["stop_reason"], "length");
        assert_eq!(
            cut["usage"],
            json!({ "prompt_tokens": 412, "completion_tokens": 1500 })
        );
        assert_eq!(cut["duration_ms"], 41_000);
        assert!(cut["note"].as_str().unwrap().contains("went on reasoning"));

        let partial =
            local_complete_report("local-model", &reply("{\"a\":", "length", 1500), elapsed);
        assert!(partial["note"]
            .as_str()
            .unwrap()
            .contains("cut off at max_tokens"));

        let whole = local_complete_report("local-model", &reply("{}", "stop", 12), elapsed);
        assert_eq!(whole["stop_reason"], "stop");
        assert!(whole.get("note").is_none());
    }
}
