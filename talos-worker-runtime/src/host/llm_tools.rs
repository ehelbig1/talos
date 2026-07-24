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

        // 4. Convert the WIT rich messages + tool defs into canonical form
        //    and let the provider adapter build its own wire body.
        //    Pre-trait, every provider received the ANTHROPIC tools shape
        //    (`input_schema` tools, `content[]` block messages) — on
        //    OpenAI-format wires the tools were silently ignored and no
        //    tool call ever parsed back.
        let adapter = llm_providers::adapter_for(provider_name);

        let messages: Vec<llm_providers::ToolMessage> = req
            .messages
            .iter()
            .map(|msg| llm_providers::ToolMessage {
                role: match msg.role {
                    wit_llm_tools::Role::System => llm_providers::ChatRole::System,
                    wit_llm_tools::Role::Assistant => llm_providers::ChatRole::Assistant,
                    wit_llm_tools::Role::User | wit_llm_tools::Role::Tool => {
                        llm_providers::ChatRole::User
                    }
                },
                is_tool_result_turn: matches!(msg.role, wit_llm_tools::Role::Tool),
                content: msg
                    .content
                    .iter()
                    .map(|block| match block {
                        wit_llm_tools::ContentBlock::Text(t) => {
                            llm_providers::ToolContentBlock::Text(t.clone())
                        }
                        wit_llm_tools::ContentBlock::ToolUse(tc) => {
                            llm_providers::ToolContentBlock::ToolUse {
                                call_id: tc.call_id.clone(),
                                tool_name: tc.tool_name.clone(),
                                arguments: tc.arguments.clone(),
                            }
                        }
                        wit_llm_tools::ContentBlock::ToolResult(tr) => {
                            llm_providers::ToolContentBlock::ToolResult {
                                call_id: tr.call_id.clone(),
                                output: tr.output.clone(),
                                is_error: tr.is_error,
                            }
                        }
                        wit_llm_tools::ContentBlock::Image(img) => {
                            llm_providers::ToolContentBlock::Image {
                                media_type: img.media_type.clone(),
                                data: img.data.clone(),
                            }
                        }
                    })
                    .collect(),
            })
            .collect();

        let tools: Vec<llm_providers::ToolDef> = req
            .tools
            .iter()
            .map(|t| llm_providers::ToolDef {
                name: &t.name,
                description: &t.description,
                input_schema: serde_json::from_str::<serde_json::Value>(&t.input_schema)
                    .unwrap_or(serde_json::json!({})),
            })
            .collect();

        let body = adapter
            .build_tools_body(&llm_providers::ToolCompletionParams {
                model: &model,
                messages: &messages,
                tools: &tools,
                system_prompt: req.system_prompt.as_deref(),
                max_tokens: req.max_tokens.unwrap_or(4096),
                temperature: req.temperature,
                force_tool: req.force_tool.as_deref(),
            })
            .map_err(wit_llm_tools::Error::NotConfigured)?;

        let url = adapter.completion_url(&model);
        let auth_headers = adapter.auth_headers(&api_key);

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
        //
        // Local provider (Ollama) bypasses the guest SSRF resolver —
        // mirrors `complete_impl` / `spawn_llm_stream`. Pre-2026-07-10
        // this path used the SSRF-filtered per-execution client for ALL
        // providers, so local tool-use died at connect with "Network
        // error" (the RFC1918 filter blocks the in-cluster/host Ollama
        // address). Masked pre-#456 because the tools wire itself was
        // broken; found live-probing the fixed wire through real worker
        // dispatch (the controller-embedded runtime's client resolves
        // differently, so test_module alone could not catch it).
        let client = if is_local_tools {
            local_llm_http_client().clone()
        } else {
            self.http_client.clone()
        };
        let timeout_secs_tools: u64 = if is_local_tools {
            LOCAL_LLM_EXCHANGE_TIMEOUT_SECS
        } else {
            EXTERNAL_LLM_EXCHANGE_TIMEOUT_SECS
        };
        let mut http_req_tools = client.post(&url).header("Content-Type", "application/json");
        // Adapter-owned auth + protocol-version headers (empty for local
        // providers). Values may embed the API key — never logged.
        for (name, value) in &auth_headers {
            http_req_tools = http_req_tools.header(*name, value);
        }
        let resp_bytes: Vec<u8> = tokio::time::timeout(
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

                read_llm_response_body_bounded(response, MAX_LLM_BODY_BYTES)
                    .await
                    .ok_or_else(|| {
                        wit_llm_tools::Error::ApiError(format!(
                            "LLM tool-use response exceeded {} bytes; aborted body read",
                            MAX_LLM_BODY_BYTES
                        ))
                    })
            },
        )
        .await
        .map_err(|_| wit_llm_tools::Error::Timeout)??;

        // 9. Adapter-owned parse into canonical blocks. `arguments` is
        //    ALWAYS the JSON string form here — the native-Ollama wire
        //    returns an object and its adapter re-serializes it.
        let parsed = adapter
            .parse_tool_completion(&resp_bytes)
            .map_err(wit_llm_tools::Error::ApiError)?;

        // R2 token ledger: fold provider-reported usage into the per-job
        // accumulator (drained into the signed JobResult at completion).
        crate::context::fold_llm_usage(
            &self.llm_usage,
            adapter.name(),
            &model,
            parsed.input_tokens.unwrap_or(0),
            parsed.output_tokens.unwrap_or(0),
        );

        let content_blocks: Vec<wit_llm_tools::ContentBlock> = parsed
            .blocks
            .into_iter()
            .map(|b| match b {
                llm_providers::ParsedToolBlock::Text(t) => wit_llm_tools::ContentBlock::Text(t),
                llm_providers::ParsedToolBlock::ToolUse {
                    call_id,
                    tool_name,
                    arguments,
                } => wit_llm_tools::ContentBlock::ToolUse(wit_llm_tools::ToolCall {
                    tool_name,
                    call_id,
                    arguments,
                }),
            })
            .collect();

        // MCP-1008: saturate-on-overflow; `usage` stays `None` when the
        // provider sent no counts at all.
        let usage = match (parsed.input_tokens, parsed.output_tokens) {
            (None, None) => None,
            (i, o) => Some(wit_llm_tools::TokenUsage {
                input_tokens: u32::try_from(i.unwrap_or(0)).unwrap_or(u32::MAX),
                output_tokens: u32::try_from(o.unwrap_or(0)).unwrap_or(u32::MAX),
            }),
        };

        Ok(wit_llm_tools::ToolCompletionResponse {
            content: content_blocks,
            model,
            usage,
            stop_reason: parsed.stop_reason,
        })
    }
}
