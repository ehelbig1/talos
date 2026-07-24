//! `llm-streaming` host interface and its SSE stream helpers.

use super::*;

// ============================================================================
// LLM Streaming — helpers
// ============================================================================

impl TalosContext {
    /// Build the provider-specific URL and auth headers, spawn a stream
    /// reader task, and return a stream ID that can be polled with
    /// `next_event`. The provider adapter owns the wire framing — SSE
    /// (`data: ` lines) for Anthropic/OpenAI, bare JSON-lines for native
    /// Ollama — via its `StreamDecoder`; this helper owns everything
    /// provider-independent: the channel, stream caps, connect + idle
    /// timeouts, and the no-newline buffer bound.
    fn spawn_llm_stream(
        &mut self,
        adapter: &'static dyn llm_providers::ProviderAdapter,
        api_key: &str,
        model: &str,
        body: serde_json::Value,
    ) -> Result<String, wit_llm_streaming::Error> {
        let Some(mut decoder) = adapter.stream_decoder() else {
            return Err(wit_llm_streaming::Error::NotConfigured(format!(
                "streaming is not supported for provider `{}`",
                adapter.name()
            )));
        };
        let url = adapter.stream_url(model);
        let auth_headers = adapter.auth_headers(api_key);

        // Enforce concurrent stream cap to prevent resource leaks from unbounded creation.
        {
            let streams = self.streams.llm.lock().map_err(|_| {
                wit_llm_streaming::Error::ApiError("Failed to acquire stream lock".to_string())
            })?;
            if streams.len() >= MAX_LLM_STREAMS_PER_EXECUTION {
                tracing::warn!(
                    module_id = ?self.module_id,
                    active_streams = streams.len(),
                    "LLM stream limit reached ({} max) — cancel existing streams first",
                    MAX_LLM_STREAMS_PER_EXECUTION
                );
                return Err(wit_llm_streaming::Error::BudgetExhausted);
            }
        }

        let (tx, rx) = tokio::sync::mpsc::channel::<serde_json::Value>(1_000);
        let stream_id = uuid::Uuid::new_v4().to_string();

        // Store receiver so `next_event` can poll it.
        {
            let mut streams = self.streams.llm.lock().map_err(|_| {
                wit_llm_streaming::Error::ApiError("Failed to acquire stream lock".to_string())
            })?;
            streams.insert(stream_id.clone(), rx);
        }

        tracing::info!(
            module_id = ?self.module_id,
            model = %model,
            provider = %adapter.name(),
            stream_id = %stream_id,
            "LLM streaming request started"
        );

        // Local providers bypass the guest SSRF resolver, mirroring
        // `complete_impl` (pre-trait, Ollama streams went through the
        // SSRF-FILTERED per-execution client whose RFC1918 filter blocks
        // the in-cluster `ollama:11434` — local streaming never even
        // connected).
        let spawn_http_client = if adapter.is_local() {
            local_llm_http_client().clone()
        } else {
            self.http_client.clone()
        };

        // R2 token ledger: usage events arrive inside the spawned reader
        // loop; clone the per-job accumulator + identity in so the fold
        // lands on this job even though the loop outlives the host call.
        let usage_acc = self.llm_usage.clone();
        let usage_provider = adapter.name();
        let usage_model = model.to_string();

        tokio::spawn(async move {
            let client = spawn_http_client;
            let mut req_builder = client.post(&url).header("Content-Type", "application/json");
            for (name, value) in &auth_headers {
                req_builder = req_builder.header(*name, value);
            }

            // MCP-1215: connect-phase timeout — mirrors MCP-721 on
            // wit_http_stream::connect. The global http_client has no
            // client-level timeout; without this wrap a provider that
            // opens TCP but never returns response headers would park
            // this task until the engine's node timeout fires.
            let response = match tokio::time::timeout(
                std::time::Duration::from_secs(LLM_STREAM_CONNECT_TIMEOUT_SECS),
                req_builder.json(&body).send(),
            )
            .await
            {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => {
                    tracing::error!(error = %e, "LLM streaming request failed");
                    let _ = tx
                        .send(serde_json::json!({"type": "error", "data": "request failed"}))
                        .await;
                    return;
                }
                Err(_) => {
                    tracing::warn!(
                        url = %url,
                        timeout_secs = LLM_STREAM_CONNECT_TIMEOUT_SECS,
                        "LLM streaming connect timed out before response headers"
                    );
                    let _ = tx
                        .send(serde_json::json!({"type": "error", "data": "connect timeout"}))
                        .await;
                    return;
                }
            };

            if !response.status().is_success() {
                let status = response.status().as_u16();
                tracing::warn!(status, "LLM streaming API returned error status");
                let _ = tx
                    .send(serde_json::json!({"type": "error", "data": "API error"}))
                    .await;
                return;
            }

            // Read the byte stream and feed complete lines to the
            // provider's decoder (which owns SSE-vs-JSONL framing and any
            // per-stream tool-call accumulation, with its own MCP-1113
            // caps).
            use futures_util::StreamExt;
            let mut byte_stream = response.bytes_stream();
            let mut buffer = String::new();

            // MCP-1215: idle-between-chunks timeout. Both major
            // providers emit something within seconds (Anthropic
            // `ping` ~15s, OpenAI continuous chunks); 60s silence
            // means the stream is dead. Without this the loop
            // blocks on `next().await` until the node timeout fires.
            let idle_timeout = std::time::Duration::from_secs(LLM_STREAM_IDLE_TIMEOUT_SECS);
            loop {
                let chunk = match tokio::time::timeout(idle_timeout, byte_stream.next()).await {
                    Ok(Some(Ok(c))) => c,
                    Ok(Some(Err(e))) => {
                        tracing::warn!(error = %e, "SSE stream chunk error");
                        break;
                    }
                    Ok(None) => break, // stream ended
                    Err(_) => {
                        tracing::warn!(
                            url = %url,
                            idle_secs = LLM_STREAM_IDLE_TIMEOUT_SECS,
                            "LLM streaming idle timeout — no bytes received within window"
                        );
                        let _ = tx
                            .send(serde_json::json!({
                                "type": "error",
                                "data": "idle timeout"
                            }))
                            .await;
                        return;
                    }
                };
                buffer.push_str(&String::from_utf8_lossy(&chunk));

                // MCP-1113: cap the no-newline accumulator. A
                // misbehaving provider streaming a long line without `\n`
                // would otherwise grow `buffer` monotonically until
                // worker OOM. Same shape as the sibling SSE consumer
                // at line ~10186 (TALOS_SSE_MAX_EVENT_BYTES).
                if buffer.len() > MAX_LLM_STREAM_BUFFER_BYTES {
                    tracing::warn!(
                        max_bytes = MAX_LLM_STREAM_BUFFER_BYTES,
                        actual_bytes = buffer.len(),
                        "LLM SSE buffer exceeded max bytes with no newline; aborting stream"
                    );
                    let _ = tx
                        .send(serde_json::json!({
                            "type": "error",
                            "data": "stream buffer overflow"
                        }))
                        .await;
                    return;
                }

                // Process complete lines. The decoder translates its
                // provider's wire framing into canonical events; the
                // channel JSON protocol below is unchanged from the
                // pre-trait code so `next_event` needs no changes.
                while let Some(line_end) = buffer.find('\n') {
                    let line = buffer[..line_end].trim().to_string();
                    buffer = buffer[line_end + 1..].to_string();

                    let mut events = Vec::new();
                    decoder.feed_line(&line, &mut events);
                    for ev in events {
                        match ev {
                            llm_providers::StreamEventOut::TextDelta(t) => {
                                let _ = tx
                                    .send(serde_json::json!({"type": "text_delta", "data": t}))
                                    .await;
                            }
                            llm_providers::StreamEventOut::ToolCall {
                                call_id,
                                tool_name,
                                arguments,
                            } => {
                                let _ = tx
                                    .send(serde_json::json!({
                                        "type": "tool_call",
                                        "data": {
                                            "name": tool_name,
                                            "id": call_id,
                                            "input": serde_json::from_str::<serde_json::Value>(&arguments)
                                                .unwrap_or(serde_json::Value::Null),
                                        }
                                    }))
                                    .await;
                            }
                            llm_providers::StreamEventOut::Usage {
                                input_tokens,
                                output_tokens,
                            } => {
                                // R2 token ledger: record even if the guest
                                // never polls this event off the channel —
                                // the tokens were spent either way.
                                crate::context::fold_llm_usage(
                                    &usage_acc,
                                    usage_provider,
                                    &usage_model,
                                    input_tokens,
                                    output_tokens,
                                );
                                let _ = tx
                                    .send(serde_json::json!({
                                        "type": "usage",
                                        "data": {
                                            "input_tokens": input_tokens,
                                            "output_tokens": output_tokens,
                                        }
                                    }))
                                    .await;
                            }
                            llm_providers::StreamEventOut::Done(reason) => {
                                let _ = tx
                                    .send(serde_json::json!({"type": "done", "data": reason}))
                                    .await;
                                return;
                            }
                        }
                    }
                }
            }
        });

        Ok(stream_id)
    }
}

// ============================================================================
// LLM Streaming
// ============================================================================

// MCP-607 (2026-05-12): per-method capability gate for llm-streaming.
// WIT-world linkage restricts `talos:core/llm-streaming` to llm-node,
// secrets-node, database-node, agent-node, automation-node (verified
// via grep `import llm-streaming` in wit/talos.wit). The wit_inspector
// `classify_world` collapses llm-node modules to `CapabilityWorld::Secrets`
// (LLM imports imply has_secrets per classify_world rules), so the
// runtime set is {Secrets, Database, Agent, Trusted}.
//
// Pre-fix: none of the four methods (start_stream / start_tool_stream /
// next_event / cancel_stream) gated on capability_world. `get_llm_api_key_by_name`
// is Tier-1-aware but Tier-1 is a privacy ceiling (privacy of *data*
// flowing to external providers), NOT a capability gate (whether the
// module is permitted the surface at all). A Minimal-world module with
// access to llm-streaming bindings could stream from local Ollama
// (the `is_local_stream` branch skips API key resolution and Tier-1
// rejection entirely) and exfiltrate response tokens via next_event.
// Same shape as MCP-602/603/604/606.
fn require_llm_streaming_capability(
    world: &crate::wit_inspector::CapabilityWorld,
) -> Result<(), wit_llm_streaming::Error> {
    use crate::wit_inspector::CapabilityWorld;
    if matches!(
        world,
        CapabilityWorld::Secrets
            | CapabilityWorld::Database
            | CapabilityWorld::Agent
            | CapabilityWorld::Trusted
    ) {
        Ok(())
    } else {
        tracing::warn!(
            ?world,
            "WASM module attempted wit_llm_streaming call but lacks Secrets/Database/Agent/Trusted capability"
        );
        Err(wit_llm_streaming::Error::NotConfigured(
            "capability_world does not permit LLM streaming".to_string(),
        ))
    }
}

impl wit_llm_streaming::Host for TalosContext {
    async fn start_stream(
        &mut self,
        req: wit_llm_streaming::StreamRequest,
    ) -> Result<String, wit_llm_streaming::Error> {
        // MCP-697 (2026-05-13): audit-ledger parity (sibling of MCP-696).
        // The shared helper `require_llm_streaming_capability` is sync +
        // pure (takes `&CapabilityWorld`) so the audit emission can't
        // happen inside it — emit here at the call site before delegating.
        // Mirror at start_tool_stream below.
        let provider_label = req.provider.as_deref().unwrap_or("anthropic").to_string();
        if !matches!(
            self.capability_world,
            crate::wit_inspector::CapabilityWorld::Secrets
                | crate::wit_inspector::CapabilityWorld::Database
                | crate::wit_inspector::CapabilityWorld::Agent
                | crate::wit_inspector::CapabilityWorld::Trusted
        ) {
            self.record_capability_denied(
                "wit_llm_streaming::start_stream",
                "capability-world",
                &provider_label,
            )
            .await;
        }
        require_llm_streaming_capability(&self.capability_world)?;
        if self.is_cancelled() {
            return Err(wit_llm_streaming::Error::BudgetExhausted);
        }

        // Resolve provider and API key.
        // Ollama needs no API key — it runs locally.
        let provider_str = req.provider.as_deref().unwrap_or("anthropic");
        let is_local_stream = provider_str == "ollama";
        let api_key = if is_local_stream {
            String::new()
        } else {
            let canonical_name = match provider_str {
                "openai" => "openai",
                "gemini" => "gemini",
                _ => "anthropic",
            };
            match self.get_llm_api_key_by_name(canonical_name).await {
                Some(k) => k,
                None => {
                    let (vault_path, env_name) =
                        llm_key_lookup_paths(canonical_name).unwrap_or(("<unknown>", "<unknown>"));
                    let msg = format!(
                        "LLM API key not configured. Set vault path `{}` in the dashboard (Settings → Secrets), \
                         or export {} in the worker environment as a fallback.",
                        vault_path, env_name
                    );
                    tracing::warn!(vault_path, env_name, module_id = ?self.module_id, "{}", msg);
                    return Err(wit_llm_streaming::Error::NotConfigured(msg));
                }
            }
        };

        let model = req.model.unwrap_or_else(|| {
            if is_local_stream {
                "mistral".to_string()
            } else {
                "claude-sonnet-4-20250514".to_string()
            }
        });

        // Parse messages from JSON.
        let messages: serde_json::Value =
            serde_json::from_str(&req.messages_json).map_err(|e| {
                wit_llm_streaming::Error::InvalidRequest(format!("Invalid messages JSON: {e}"))
            })?;

        // Adapter-owned body: system prompt placement and stream framing
        // are provider-specific (pre-trait, a top-level `system` field
        // was sent to ALL providers — OpenAI/Ollama simply ignored it).
        let adapter = llm_providers::adapter_for(provider_str);
        let body = adapter
            .build_stream_body(
                &model,
                messages,
                None,
                req.system_prompt.as_deref(),
                req.max_tokens.unwrap_or(4096),
                req.temperature,
            )
            .map_err(wit_llm_streaming::Error::NotConfigured)?;

        self.spawn_llm_stream(adapter, &api_key, &model, body)
    }

    async fn start_tool_stream(
        &mut self,
        req: wit_llm_streaming::StreamToolRequest,
    ) -> Result<String, wit_llm_streaming::Error> {
        // MCP-697 (2026-05-13): audit-ledger parity — see start_stream above.
        let provider_label = req.provider.as_deref().unwrap_or("anthropic").to_string();
        if !matches!(
            self.capability_world,
            crate::wit_inspector::CapabilityWorld::Secrets
                | crate::wit_inspector::CapabilityWorld::Database
                | crate::wit_inspector::CapabilityWorld::Agent
                | crate::wit_inspector::CapabilityWorld::Trusted
        ) {
            self.record_capability_denied(
                "wit_llm_streaming::start_tool_stream",
                "capability-world",
                &provider_label,
            )
            .await;
        }
        require_llm_streaming_capability(&self.capability_world)?;
        if self.is_cancelled() {
            return Err(wit_llm_streaming::Error::BudgetExhausted);
        }

        let provider_str = req.provider.as_deref().unwrap_or("anthropic");
        let is_local_tool_stream = provider_str == "ollama";
        let api_key = if is_local_tool_stream {
            String::new()
        } else {
            let canonical_name = match provider_str {
                "openai" => "openai",
                "gemini" => "gemini",
                _ => "anthropic",
            };
            match self.get_llm_api_key_by_name(canonical_name).await {
                Some(k) => k,
                None => {
                    let (vault_path, env_name) =
                        llm_key_lookup_paths(canonical_name).unwrap_or(("<unknown>", "<unknown>"));
                    let msg = format!(
                        "LLM API key not configured. Set vault path `{}` in the dashboard (Settings → Secrets), \
                         or export {} in the worker environment as a fallback.",
                        vault_path, env_name
                    );
                    tracing::warn!(vault_path, env_name, module_id = ?self.module_id, "{}", msg);
                    return Err(wit_llm_streaming::Error::NotConfigured(msg));
                }
            }
        };

        let model = req.model.unwrap_or_else(|| {
            if is_local_tool_stream {
                "mistral".to_string()
            } else {
                "claude-sonnet-4-20250514".to_string()
            }
        });

        let messages: serde_json::Value =
            serde_json::from_str(&req.messages_json).map_err(|e| {
                wit_llm_streaming::Error::InvalidRequest(format!("Invalid messages JSON: {e}"))
            })?;
        let tools: serde_json::Value = serde_json::from_str(&req.tools_json).map_err(|e| {
            wit_llm_streaming::Error::InvalidRequest(format!("Invalid tools JSON: {e}"))
        })?;

        let adapter = llm_providers::adapter_for(provider_str);
        let body = adapter
            .build_stream_body(
                &model,
                messages,
                Some(tools),
                req.system_prompt.as_deref(),
                req.max_tokens.unwrap_or(4096),
                req.temperature,
            )
            .map_err(wit_llm_streaming::Error::NotConfigured)?;

        self.spawn_llm_stream(adapter, &api_key, &model, body)
    }

    async fn next_event(&mut self, stream_id: String) -> Option<wit_llm_streaming::StreamEvent> {
        // Take the receiver out of the map so we don't hold the mutex during await.
        let mut rx = {
            let mut streams = self.streams.llm.lock().ok()?;
            streams.remove(&stream_id)?
        };

        // Block until the next event arrives (or channel closes).
        // This fixes the ambiguity where try_recv().ok() returned None for both
        // "no event yet" and "stream ended", making streaming unusable for
        // real-time use cases.
        let event = rx.recv().await;

        // Put the receiver back unless the channel is closed (None = sender dropped).
        if event.is_some() {
            if let Ok(mut streams) = self.streams.llm.lock() {
                streams.insert(stream_id, rx);
            }
        }
        // If event is None, the sender dropped — stream is done. Don't reinsert.

        event.and_then(|v| {
            let event_type = v.get("type")?.as_str()?;
            let data = v.get("data")?;
            match event_type {
                "text_delta" => Some(wit_llm_streaming::StreamEvent::TextDelta(
                    data.as_str()?.to_string(),
                )),
                "done" => Some(wit_llm_streaming::StreamEvent::Done(
                    data.as_str()?.to_string(),
                )),
                "error" => Some(wit_llm_streaming::StreamEvent::Error(
                    data.as_str()?.to_string(),
                )),
                "usage" => {
                    // MCP-1008: saturate-on-overflow (see helper docs).
                    let input = json_token_count_as_u32(data.get("input_tokens"), 0);
                    let output = json_token_count_as_u32(data.get("output_tokens"), 0);
                    Some(wit_llm_streaming::StreamEvent::Usage(
                        wit_llm_streaming::StreamUsage {
                            input_tokens: input,
                            output_tokens: output,
                        },
                    ))
                }
                "tool_call" => Some(wit_llm_streaming::StreamEvent::ToolCall(
                    wit_llm_streaming::StreamToolCall {
                        tool_name: data
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        call_id: data
                            .get("id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        arguments: data.get("input").map(|v| v.to_string()).unwrap_or_default(),
                    },
                )),
                _ => None,
            }
        })
    }

    async fn cancel_stream(&mut self, stream_id: String) {
        // Remove the receiver — the sender task will detect the closed channel and stop.
        if let Ok(mut streams) = self.streams.llm.lock() {
            streams.remove(&stream_id);
        }
    }
}
