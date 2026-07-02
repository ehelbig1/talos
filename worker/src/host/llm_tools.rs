//! `llm-tools` (function calling / structured output) host interface.

use super::*;

// ============================================================================
// LLM Tool Use (function calling / structured output)
// ============================================================================

impl wit_llm_tools::Host for TalosContext {
    #[::tracing::instrument(name = "llm.complete_with_tools", skip_all)]
    async fn complete_with_tools(
        &mut self,
        req: wit_llm_tools::ToolCompletionRequest,
    ) -> Result<wit_llm_tools::ToolCompletionResponse, wit_llm_tools::Error> {
        // MCP-609 (2026-05-12): per-method capability gate. WIT linkage
        // restricts `talos:core/llm-tools` to llm-node, secrets-node,
        // database-node, agent-node, automation-node (verified by grep
        // `import llm-tools` in wit/talos.wit). The wit_inspector
        // `classify_world` collapses llm-node to `CapabilityWorld::Secrets`,
        // so the runtime set is {Secrets, Database, Agent, Trusted}.
        // Pre-fix: same gap as MCP-607 (wit_llm_streaming) — Tier-1
        // privacy check exists for external providers but Ollama
        // branch (`is_local_tools`) skips all key resolution, letting
        // a Minimal-world module that linked invoke local LLM tools.
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Secrets
                | CapabilityWorld::Database
                | CapabilityWorld::Agent
                | CapabilityWorld::Trusted
        ) {
            // MCP-697 (2026-05-13): audit-ledger parity. Sibling Tier-1
            // denial branches in this same impl audit via
            // `record_capability_denied`; capability-world denial branch
            // was silent (`tracing::warn!` only). Both denial classes
            // should produce a WORM ledger entry. Target encodes the
            // provider so operators can correlate the audit row with the
            // policy that should have caught it.
            let provider = format!(
                "{:?}",
                req.provider.unwrap_or(wit_llm_tools::Provider::Anthropic)
            );
            self.record_capability_denied(
                "wit_llm_tools::complete_with_tools",
                "capability-world",
                &provider,
            )
            .await;
            tracing::warn!(
                world = ?self.capability_world,
                "WASM module attempted wit_llm_tools::complete_with_tools but lacks Secrets/Database/Agent/Trusted capability"
            );
            return Err(wit_llm_tools::Error::NotConfigured(
                "capability_world does not permit LLM tools".to_string(),
            ));
        }
        // 1. Check cancellation before making an expensive API call.
        if self.is_cancelled() {
            tracing::info!(module_id = ?self.module_id, "Execution cancelled");
            return Err(wit_llm_tools::Error::BudgetExhausted);
        }

        // 2. Resolve provider and look up the API key from secrets.
        // Ollama (Tier 1) needs no API key — it runs locally.
        let provider = req.provider.unwrap_or(wit_llm_tools::Provider::Anthropic);
        let is_local_tools = matches!(provider, wit_llm_tools::Provider::Ollama);
        let provider_name = match provider {
            wit_llm_tools::Provider::Anthropic => "anthropic",
            wit_llm_tools::Provider::Openai => "openai",
            wit_llm_tools::Provider::Gemini => "gemini",
            wit_llm_tools::Provider::Ollama => "ollama",
        };

        let api_key = if is_local_tools {
            String::new()
        } else {
            match self.get_llm_api_key_by_name(provider_name).await {
                Some(k) => k,
                None => {
                    let (vault_path, env_name) =
                        llm_key_lookup_paths(provider_name).unwrap_or(("<unknown>", "<unknown>"));
                    let msg = format!(
                        "LLM API key not configured. Set vault path `{}` in the dashboard (Settings → Secrets), \
                         or export {} in the worker environment as a fallback.",
                        vault_path, env_name
                    );
                    tracing::warn!(vault_path, env_name, module_id = ?self.module_id, "{}", msg);
                    return Err(wit_llm_tools::Error::NotConfigured(msg));
                }
            }
        };

        // 3. Select default model per provider.
        let model = req.model.unwrap_or_else(|| match provider {
            wit_llm_tools::Provider::Anthropic => "claude-sonnet-4-20250514".to_string(),
            wit_llm_tools::Provider::Openai => "gpt-4o".to_string(),
            wit_llm_tools::Provider::Gemini => "gemini-1.5-pro".to_string(),
            wit_llm_tools::Provider::Ollama => "mistral".to_string(),
        });

        // 4. Build the messages array from rich messages.
        let messages: Vec<serde_json::Value> = req
            .messages
            .iter()
            .map(|msg| {
                let role = match msg.role {
                    wit_llm_tools::Role::System => "user",
                    wit_llm_tools::Role::User => "user",
                    wit_llm_tools::Role::Assistant => "assistant",
                    wit_llm_tools::Role::Tool => "user",
                };
                let content: Vec<serde_json::Value> = msg
                    .content
                    .iter()
                    .map(|block| match block {
                        wit_llm_tools::ContentBlock::Text(t) => {
                            serde_json::json!({"type": "text", "text": t})
                        }
                        wit_llm_tools::ContentBlock::ToolUse(tc) => {
                            serde_json::json!({
                                "type": "tool_use",
                                "id": tc.call_id,
                                "name": tc.tool_name,
                                "input": serde_json::from_str::<serde_json::Value>(&tc.arguments)
                                    .unwrap_or(serde_json::json!({})),
                            })
                        }
                        wit_llm_tools::ContentBlock::ToolResult(tr) => {
                            serde_json::json!({
                                "type": "tool_result",
                                "tool_use_id": tr.call_id,
                                "content": tr.output,
                                "is_error": tr.is_error,
                            })
                        }
                        wit_llm_tools::ContentBlock::Image(img) => {
                            serde_json::json!({
                                "type": "image",
                                "source": {
                                    "type": "base64",
                                    "media_type": img.media_type,
                                    "data": img.data,
                                }
                            })
                        }
                    })
                    .collect();
                serde_json::json!({"role": role, "content": content})
            })
            .collect();

        // 5. Build tools array from tool definitions.
        let tools: Vec<serde_json::Value> = req
            .tools
            .iter()
            .map(|t| {
                serde_json::json!({
                    "name": t.name,
                    "description": t.description,
                    "input_schema": serde_json::from_str::<serde_json::Value>(&t.input_schema)
                        .unwrap_or(serde_json::json!({})),
                })
            })
            .collect();

        // 6. Assemble the request body.
        let mut body = serde_json::json!({
            "model": model,
            "messages": messages,
            "tools": tools,
            "max_tokens": req.max_tokens.unwrap_or(4096),
        });

        if let Some(temp) = req.temperature {
            body["temperature"] = serde_json::json!(temp);
        }
        if let Some(ref sys) = req.system_prompt {
            body["system"] = serde_json::json!(sys);
        }
        if let Some(ref force) = req.force_tool {
            body["tool_choice"] = serde_json::json!({"type": "tool", "name": force});
        }

        // For OpenAI-compatible providers, convert system_prompt to a message.
        let uses_openai_format_tools = matches!(
            provider,
            wit_llm_tools::Provider::Openai | wit_llm_tools::Provider::Ollama
        );
        if uses_openai_format_tools {
            if let Some(ref sys) = req.system_prompt {
                body.as_object_mut().and_then(|obj| {
                    obj.get_mut("messages").and_then(|m| {
                        m.as_array_mut().map(|arr| {
                            arr.insert(0, serde_json::json!({"role": "system", "content": sys}));
                        })
                    })
                });
                body.as_object_mut().map(|obj| obj.remove("system"));
            }
        }

        // 7. Determine endpoint and auth based on provider.
        let ollama_url_tools = ollama_base_url();

        let (url, auth_header, auth_value) = match provider {
            wit_llm_tools::Provider::Anthropic => (
                "https://api.anthropic.com/v1/messages".to_string(),
                "x-api-key",
                api_key,
            ),
            wit_llm_tools::Provider::Openai => (
                "https://api.openai.com/v1/chat/completions".to_string(),
                "Authorization",
                format!("Bearer {}", api_key),
            ),
            wit_llm_tools::Provider::Gemini => (
                "https://generativelanguage.googleapis.com/v1beta/models".to_string(),
                "x-goog-api-key",
                api_key,
            ),
            wit_llm_tools::Provider::Ollama => (
                format!("{}/v1/chat/completions", ollama_url_tools),
                "",
                String::new(),
            ),
        };

        let body_bytes = serde_json::to_vec(&body).map_err(|e| {
            wit_llm_tools::Error::InvalidRequest(format!("Failed to serialize request body: {e}"))
        })?;

        tracing::info!(
            module_id = ?self.module_id,
            model = %model,
            tool_count = req.tools.len(),
            message_count = req.messages.len(),
            "LLM tool-use completion request"
        );

        // 8. Send the HTTP request to the LLM provider.
        // MCP-1213 (2026-05-18): single timeout over the full exchange
        // (send + body read), bounded body read, sibling fix to the
        // bare `complete` path above. See helper
        // `read_llm_response_body_bounded` and constants
        // `EXTERNAL_LLM_EXCHANGE_TIMEOUT_SECS` / `MAX_LLM_BODY_BYTES`.
        let client = self.http_client.clone();
        let timeout_secs_tools: u64 = if is_local_tools {
            LOCAL_LLM_EXCHANGE_TIMEOUT_SECS
        } else {
            EXTERNAL_LLM_EXCHANGE_TIMEOUT_SECS
        };
        let mut http_req_tools = client.post(&url).header("Content-Type", "application/json");
        if !auth_header.is_empty() {
            http_req_tools = http_req_tools.header(auth_header, &auth_value);
        }
        if matches!(provider, wit_llm_tools::Provider::Anthropic) {
            http_req_tools = http_req_tools.header("anthropic-version", "2023-06-01");
        }
        let resp_body: serde_json::Value = tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs_tools),
            async move {
                let response = http_req_tools.body(body_bytes).send().await.map_err(|e| {
                    tracing::error!(error = %e, "LLM tool-use API request failed");
                    wit_llm_tools::Error::ApiError(format!("Network error: {e}"))
                })?;

                if !response.status().is_success() {
                    let status = response.status().as_u16();
                    tracing::warn!(status, "LLM tool-use API returned error status");
                    if status == 429 {
                        return Err(wit_llm_tools::Error::RateLimited);
                    }
                    let preview_bytes =
                        read_llm_response_body_bounded(response, MAX_LLM_BODY_BYTES)
                            .await
                            .unwrap_or_default();
                    let body_preview = String::from_utf8_lossy(&preview_bytes);
                    let preview_truncated: String = body_preview.chars().take(500).collect();
                    let preview_redacted = talos_dlp_provider::redact_str(&preview_truncated);
                    tracing::warn!(
                        status,
                        body_len = preview_bytes.len(),
                        body_preview = %preview_redacted,
                        "LLM tool-use API returned error"
                    );
                    return Err(wit_llm_tools::Error::ApiError(format!(
                        "LLM API returned HTTP {status}"
                    )));
                }

                let body_bytes = read_llm_response_body_bounded(response, MAX_LLM_BODY_BYTES)
                    .await
                    .ok_or_else(|| {
                        wit_llm_tools::Error::ApiError(format!(
                            "LLM tool-use response exceeded {} bytes; aborted body read",
                            MAX_LLM_BODY_BYTES
                        ))
                    })?;
                serde_json::from_slice::<serde_json::Value>(&body_bytes).map_err(|e| {
                    wit_llm_tools::Error::ApiError(format!("Failed to parse response JSON: {e}"))
                })
            },
        )
        .await
        .map_err(|_| wit_llm_tools::Error::Timeout)??;

        // 9. Parse response into content blocks.
        let content_blocks: Vec<wit_llm_tools::ContentBlock> = resp_body
            .get("content")
            .and_then(|c| c.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|block| {
                        let block_type = block.get("type")?.as_str()?;
                        match block_type {
                            "text" => {
                                let text = block.get("text")?.as_str()?.to_string();
                                Some(wit_llm_tools::ContentBlock::Text(text))
                            }
                            "tool_use" => {
                                let tc = wit_llm_tools::ToolCall {
                                    tool_name: block.get("name")?.as_str()?.to_string(),
                                    call_id: block.get("id")?.as_str()?.to_string(),
                                    arguments: block.get("input")?.to_string(),
                                };
                                Some(wit_llm_tools::ContentBlock::ToolUse(tc))
                            }
                            _ => None,
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        let usage = resp_body.get("usage").map(|u| wit_llm_tools::TokenUsage {
            // MCP-1008: saturate-on-overflow (see helper docs).
            input_tokens: json_token_count_as_u32(u.get("input_tokens"), 0),
            output_tokens: json_token_count_as_u32(u.get("output_tokens"), 0),
        });

        let stop_reason = resp_body
            .get("stop_reason")
            .and_then(|v| v.as_str())
            .map(String::from);

        Ok(wit_llm_tools::ToolCompletionResponse {
            content: content_blocks,
            model,
            usage,
            stop_reason,
        })
    }
}
