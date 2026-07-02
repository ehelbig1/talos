//! `llm-streaming` host interface and its SSE stream helpers.

use super::*;

// ============================================================================
// LLM Streaming — helpers
// ============================================================================

impl TalosContext {
    /// Build the provider-specific URL and auth headers, spawn an SSE reader
    /// task, and return a stream ID that can be polled with `next_event`.
    fn spawn_sse_stream(
        &mut self,
        provider_str: &str,
        api_key: &str,
        model: &str,
        body: serde_json::Value,
    ) -> Result<String, wit_llm_streaming::Error> {
        let ollama_url_stream = ollama_base_url();
        let (url, auth_header, auth_value): (String, &str, String) = match provider_str {
            "openai" => (
                "https://api.openai.com/v1/chat/completions".to_string(),
                "Authorization",
                format!("Bearer {}", api_key),
            ),
            "gemini" => (
                "https://generativelanguage.googleapis.com/v1beta/models".to_string(),
                "x-goog-api-key",
                api_key.to_string(),
            ),
            "ollama" => (
                format!("{}/v1/chat/completions", ollama_url_stream),
                "",
                String::new(),
            ),
            _ => (
                "https://api.anthropic.com/v1/messages".to_string(),
                "x-api-key",
                api_key.to_string(),
            ),
        };

        // Enforce concurrent stream cap to prevent resource leaks from unbounded creation.
        {
            let streams = self.llm_streams.lock().map_err(|_| {
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
            let mut streams = self.llm_streams.lock().map_err(|_| {
                wit_llm_streaming::Error::ApiError("Failed to acquire stream lock".to_string())
            })?;
            streams.insert(stream_id.clone(), rx);
        }

        tracing::info!(
            module_id = ?self.module_id,
            model = %model,
            provider = %provider_str,
            stream_id = %stream_id,
            "LLM streaming request started"
        );

        // Owned copies for the spawned task.
        let url = url.to_string();
        let auth_header = auth_header.to_string();
        let is_anthropic = provider_str == "anthropic";
        let spawn_http_client = self.http_client.clone();

        tokio::spawn(async move {
            let client = spawn_http_client;
            let mut req_builder = client.post(&url).header("Content-Type", "application/json");
            if !auth_header.is_empty() {
                req_builder = req_builder.header(&auth_header, &auth_value);
            }
            if is_anthropic {
                req_builder = req_builder.header("anthropic-version", "2023-06-01");
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

            // Read SSE byte stream and parse events.
            use futures_util::StreamExt;
            let mut byte_stream = response.bytes_stream();
            let mut buffer = String::new();
            // For tool-use streaming, accumulate partial JSON inputs per content block index.
            let mut tool_input_bufs: std::collections::HashMap<u64, (String, String, String)> =
                std::collections::HashMap::new();

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

                // Process complete SSE lines.
                while let Some(line_end) = buffer.find('\n') {
                    let line = buffer[..line_end].trim().to_string();
                    buffer = buffer[line_end + 1..].to_string();

                    if !line.starts_with("data: ") {
                        continue;
                    }
                    let data = &line[6..];
                    if data == "[DONE]" {
                        let _ = tx
                            .send(serde_json::json!({"type": "done", "data": "end_turn"}))
                            .await;
                        return;
                    }

                    if let Ok(event) = serde_json::from_str::<serde_json::Value>(data) {
                        let event_type = event.get("type").and_then(|t| t.as_str()).unwrap_or("");
                        match event_type {
                            "content_block_start" => {
                                // Track start of tool_use blocks so we can
                                // accumulate their streamed JSON input.
                                if let Some(cb) = event.get("content_block") {
                                    if cb.get("type").and_then(|t| t.as_str()) == Some("tool_use") {
                                        // MCP-1113: cap the per-stream
                                        // tool_use block count. A
                                        // misbehaving provider emitting
                                        // many `content_block_start`s
                                        // without matching `_stop`s
                                        // would otherwise grow this
                                        // HashMap unbounded. Drop the
                                        // new block (no insert) instead
                                        // of aborting the whole stream
                                        // — well-behaved tool-use
                                        // workflows stay under 64.
                                        if tool_input_bufs.len() >= MAX_TOOL_INPUT_BUFS_PER_STREAM {
                                            tracing::warn!(
                                                cap = MAX_TOOL_INPUT_BUFS_PER_STREAM,
                                                "LLM SSE tool_input_bufs at cap; dropping new content_block_start"
                                            );
                                            continue;
                                        }
                                        let idx = event
                                            .get("index")
                                            .and_then(|i| i.as_u64())
                                            .unwrap_or(0);
                                        let name = cb
                                            .get("name")
                                            .and_then(|n| n.as_str())
                                            .unwrap_or("")
                                            .to_string();
                                        let id = cb
                                            .get("id")
                                            .and_then(|i| i.as_str())
                                            .unwrap_or("")
                                            .to_string();
                                        tool_input_bufs.insert(idx, (name, id, String::new()));
                                    }
                                }
                            }
                            "content_block_delta" => {
                                if let Some(delta) = event.get("delta") {
                                    let delta_type =
                                        delta.get("type").and_then(|t| t.as_str()).unwrap_or("");
                                    if delta_type == "text_delta" {
                                        if let Some(text) =
                                            delta.get("text").and_then(|t| t.as_str())
                                        {
                                            let _ = tx
                                                .send(serde_json::json!({
                                                    "type": "text_delta",
                                                    "data": text
                                                }))
                                                .await;
                                        }
                                    } else if delta_type == "input_json_delta" {
                                        // Accumulate partial JSON for tool input.
                                        let idx = event
                                            .get("index")
                                            .and_then(|i| i.as_u64())
                                            .unwrap_or(0);
                                        if let Some(partial) =
                                            delta.get("partial_json").and_then(|p| p.as_str())
                                        {
                                            if let Some(entry) = tool_input_bufs.get_mut(&idx) {
                                                // MCP-1113: cap per-
                                                // entry accumulator. A
                                                // misbehaving provider
                                                // streaming long
                                                // `partial_json`s
                                                // without `_stop`
                                                // would otherwise grow
                                                // this String
                                                // unbounded.
                                                if entry.2.len().saturating_add(partial.len())
                                                    > MAX_TOOL_INPUT_BUF_BYTES
                                                {
                                                    tracing::warn!(
                                                        cap = MAX_TOOL_INPUT_BUF_BYTES,
                                                        idx,
                                                        "LLM SSE tool input buf at cap; dropping delta"
                                                    );
                                                } else {
                                                    entry.2.push_str(partial);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            "content_block_stop" => {
                                // Emit completed tool calls.
                                let idx = event.get("index").and_then(|i| i.as_u64()).unwrap_or(0);
                                if let Some((name, id, input)) = tool_input_bufs.remove(&idx) {
                                    let _ = tx
                                        .send(serde_json::json!({
                                            "type": "tool_call",
                                            "data": {
                                                "name": name,
                                                "id": id,
                                                "input": serde_json::from_str::<serde_json::Value>(&input).unwrap_or(serde_json::Value::Null),
                                            }
                                        }))
                                        .await;
                                }
                            }
                            "message_delta" => {
                                if let Some(usage) = event.get("usage") {
                                    let _ = tx
                                        .send(serde_json::json!({
                                            "type": "usage",
                                            "data": usage
                                        }))
                                        .await;
                                }
                                if let Some(reason) = event
                                    .get("delta")
                                    .and_then(|d| d.get("stop_reason"))
                                    .and_then(|s| s.as_str())
                                {
                                    let _ = tx
                                        .send(serde_json::json!({
                                            "type": "done",
                                            "data": reason
                                        }))
                                        .await;
                                }
                            }
                            "message_stop" => {
                                let _ = tx
                                    .send(serde_json::json!({
                                        "type": "done",
                                        "data": "end_turn"
                                    }))
                                    .await;
                                return;
                            }
                            _ => {} // Skip ping, message_start, etc.
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

        let mut body = serde_json::json!({
            "model": model,
            "messages": messages,
            "max_tokens": req.max_tokens.unwrap_or(4096),
            "stream": true,
        });
        if let Some(temp) = req.temperature {
            body["temperature"] = serde_json::json!(temp);
        }
        if let Some(ref sys) = req.system_prompt {
            body["system"] = serde_json::json!(sys);
        }

        self.spawn_sse_stream(provider_str, &api_key, &model, body)
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

        let mut body = serde_json::json!({
            "model": model,
            "messages": messages,
            "max_tokens": req.max_tokens.unwrap_or(4096),
            "stream": true,
            "tools": tools,
        });
        if let Some(temp) = req.temperature {
            body["temperature"] = serde_json::json!(temp);
        }
        if let Some(ref sys) = req.system_prompt {
            body["system"] = serde_json::json!(sys);
        }

        self.spawn_sse_stream(provider_str, &api_key, &model, body)
    }

    async fn next_event(&mut self, stream_id: String) -> Option<wit_llm_streaming::StreamEvent> {
        // Take the receiver out of the map so we don't hold the mutex during await.
        let mut rx = {
            let mut streams = self.llm_streams.lock().ok()?;
            streams.remove(&stream_id)?
        };

        // Block until the next event arrives (or channel closes).
        // This fixes the ambiguity where try_recv().ok() returned None for both
        // "no event yet" and "stream ended", making streaming unusable for
        // real-time use cases.
        let event = rx.recv().await;

        // Put the receiver back unless the channel is closed (None = sender dropped).
        if event.is_some() {
            if let Ok(mut streams) = self.llm_streams.lock() {
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
        if let Ok(mut streams) = self.llm_streams.lock() {
            streams.remove(&stream_id);
        }
    }
}
