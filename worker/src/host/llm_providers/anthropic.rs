//! Anthropic Messages API (`/v1/messages`) adapter.
//!
//! Behavior-preserving extraction of the pre-trait logic in `llm.rs` /
//! `llm_tools.rs` / `llm_streaming.rs` — Anthropic was the shape every
//! provider used to be funneled through, so this adapter is the
//! reference for "what the old code did".

use super::*;

pub(crate) struct AnthropicAdapter;

const BASE_URL: &str = "https://api.anthropic.com/v1/messages";

/// Typed response projection (2026-05-28 Perf#1: no full `Value` tree).
#[derive(serde::Deserialize)]
struct AnthropicResponse {
    #[serde(default)]
    content: Vec<AnthropicContentBlock>,
    #[serde(default)]
    usage: Option<AnthropicUsage>,
    #[serde(default)]
    stop_reason: Option<String>,
}

#[derive(serde::Deserialize)]
struct AnthropicContentBlock {
    #[serde(rename = "type", default)]
    block_type: Option<String>,
    #[serde(default)]
    text: Option<String>,
    // tools-path fields
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    input: Option<serde_json::Value>,
}

#[derive(serde::Deserialize)]
struct AnthropicUsage {
    #[serde(default)]
    input_tokens: Option<u64>,
    #[serde(default)]
    output_tokens: Option<u64>,
}

impl ProviderAdapter for AnthropicAdapter {
    fn name(&self) -> &'static str {
        "anthropic"
    }

    fn completion_url(&self, _model: &str) -> String {
        BASE_URL.to_string()
    }

    fn auth_headers(&self, api_key: &str) -> Vec<(&'static str, String)> {
        vec![
            ("x-api-key", api_key.to_string()),
            ("anthropic-version", "2023-06-01".to_string()),
        ]
    }

    fn build_completion_body(&self, p: &CompletionParams) -> serde_json::Value {
        // Anthropic has no `system` message role — System-role messages
        // map to `user`, and the request-level prompt uses the top-level
        // `system` field.
        let messages: Vec<serde_json::Value> = p
            .messages
            .iter()
            .map(|m| {
                let role = match m.role {
                    ChatRole::System | ChatRole::User => "user",
                    ChatRole::Assistant => "assistant",
                };
                serde_json::json!({"role": role, "content": m.content})
            })
            .collect();
        let mut body = serde_json::json!({
            "model": p.model,
            "messages": messages,
            "max_tokens": p.max_tokens,
        });
        if let Some(t) = p.temperature {
            body["temperature"] = serde_json::json!(t);
        }
        if let Some(sys) = p.system_prompt {
            body["system"] = serde_json::json!(sys);
        }
        body
    }

    fn apply_response_format(&self, _body: &mut serde_json::Value, _json_schema: Option<&str>) {
        // No structured-output request knob — `complete_json` on
        // Anthropic degrades to prompt-level JSON, exactly like the
        // pre-trait behavior.
    }

    fn apply_provider_options(
        &self,
        body: &mut serde_json::Value,
        opts: serde_json::Map<String, serde_json::Value>,
    ) {
        // Merge every option, then re-assert prompt integrity (`messages`
        // + the host-assembled `system`) and force non-streaming. This is
        // the original `apply_provider_options` contract.
        let orig_messages = body.get("messages").cloned();
        let orig_system = body.get("system").cloned();
        if let Some(obj) = body.as_object_mut() {
            for (k, v) in opts {
                obj.insert(k, v);
            }
            if let Some(m) = orig_messages {
                obj.insert("messages".to_string(), m);
            }
            match orig_system {
                Some(s) => {
                    obj.insert("system".to_string(), s);
                }
                None => {
                    obj.remove("system");
                }
            }
            // Explicitly FORCE non-streaming rather than merely removing
            // the key — uniform rule across adapters so an endpoint whose
            // default is `stream: true` (native Ollama) can never regress
            // by omission.
            obj.insert("stream".to_string(), serde_json::json!(false));
        }
    }

    fn parse_completion(&self, bytes: &[u8]) -> Result<ParsedCompletion, String> {
        let r: AnthropicResponse = serde_json::from_slice(bytes)
            .map_err(|e| format!("Failed to parse Anthropic-format response: {e}"))?;
        let text = r
            .content
            .iter()
            .filter(|b| b.block_type.as_deref() == Some("text"))
            .filter_map(|b| b.text.as_deref())
            .collect::<Vec<_>>()
            .join("");
        Ok(ParsedCompletion {
            text,
            input_tokens: r.usage.as_ref().and_then(|u| u.input_tokens),
            output_tokens: r.usage.as_ref().and_then(|u| u.output_tokens),
            stop_reason: r.stop_reason,
        })
    }

    fn build_tools_body(&self, p: &ToolCompletionParams) -> Result<serde_json::Value, String> {
        let messages: Vec<serde_json::Value> = p
            .messages
            .iter()
            .map(|msg| {
                // Anthropic: tool results ride in `user` messages as
                // `tool_result` blocks; there is no `tool` role.
                let role = match msg.role {
                    ChatRole::Assistant => "assistant",
                    _ => "user",
                };
                let content: Vec<serde_json::Value> = msg
                    .content
                    .iter()
                    .map(|block| match block {
                        ToolContentBlock::Text(t) => {
                            serde_json::json!({"type": "text", "text": t})
                        }
                        ToolContentBlock::ToolUse {
                            call_id,
                            tool_name,
                            arguments,
                        } => serde_json::json!({
                            "type": "tool_use",
                            "id": call_id,
                            "name": tool_name,
                            "input": serde_json::from_str::<serde_json::Value>(arguments)
                                .unwrap_or(serde_json::json!({})),
                        }),
                        ToolContentBlock::ToolResult {
                            call_id,
                            output,
                            is_error,
                        } => serde_json::json!({
                            "type": "tool_result",
                            "tool_use_id": call_id,
                            "content": output,
                            "is_error": is_error,
                        }),
                        ToolContentBlock::Image { media_type, data } => serde_json::json!({
                            "type": "image",
                            "source": {
                                "type": "base64",
                                "media_type": media_type,
                                "data": data,
                            }
                        }),
                    })
                    .collect();
                serde_json::json!({"role": role, "content": content})
            })
            .collect();

        let tools: Vec<serde_json::Value> = p
            .tools
            .iter()
            .map(|t| {
                serde_json::json!({
                    "name": t.name,
                    "description": t.description,
                    "input_schema": t.input_schema,
                })
            })
            .collect();

        let mut body = serde_json::json!({
            "model": p.model,
            "messages": messages,
            "tools": tools,
            "max_tokens": p.max_tokens,
        });
        if let Some(t) = p.temperature {
            body["temperature"] = serde_json::json!(t);
        }
        if let Some(sys) = p.system_prompt {
            body["system"] = serde_json::json!(sys);
        }
        if let Some(force) = p.force_tool {
            body["tool_choice"] = serde_json::json!({"type": "tool", "name": force});
        }
        Ok(body)
    }

    fn parse_tool_completion(&self, bytes: &[u8]) -> Result<ParsedToolCompletion, String> {
        let r: AnthropicResponse = serde_json::from_slice(bytes)
            .map_err(|e| format!("Failed to parse Anthropic tools response: {e}"))?;
        let blocks = r
            .content
            .iter()
            .filter_map(|b| match b.block_type.as_deref() {
                Some("text") => b.text.clone().map(ParsedToolBlock::Text),
                Some("tool_use") => Some(ParsedToolBlock::ToolUse {
                    call_id: b.id.clone().unwrap_or_default(),
                    tool_name: b.name.clone().unwrap_or_default(),
                    arguments: b
                        .input
                        .as_ref()
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "{}".to_string()),
                }),
                _ => None,
            })
            .collect();
        Ok(ParsedToolCompletion {
            blocks,
            input_tokens: r.usage.as_ref().and_then(|u| u.input_tokens),
            output_tokens: r.usage.as_ref().and_then(|u| u.output_tokens),
            stop_reason: r.stop_reason,
        })
    }

    fn build_stream_body(
        &self,
        model: &str,
        messages: serde_json::Value,
        tools: Option<serde_json::Value>,
        system_prompt: Option<&str>,
        max_tokens: u32,
        temperature: Option<f32>,
    ) -> Result<serde_json::Value, String> {
        let mut body = serde_json::json!({
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "stream": true,
        });
        if let Some(t) = temperature {
            body["temperature"] = serde_json::json!(t);
        }
        if let Some(sys) = system_prompt {
            body["system"] = serde_json::json!(sys);
        }
        if let Some(tools) = tools {
            body["tools"] = tools;
        }
        Ok(body)
    }

    fn stream_decoder(&self) -> Option<Box<dyn StreamDecoder>> {
        Some(Box::new(AnthropicSseDecoder::default()))
    }
}

/// Anthropic SSE event decoder — the pre-trait parse loop, verbatim in
/// spirit: `content_block_start`/`_delta`/`_stop` accumulate tool-call
/// JSON per block index; `message_delta` carries usage + stop reason;
/// `message_stop` (or the OpenAI-style `[DONE]` sentinel some proxies
/// emit) ends the stream. The MCP-1113 caps carry over.
#[derive(Default)]
pub(crate) struct AnthropicSseDecoder {
    tool_input_bufs: std::collections::HashMap<u64, (String, String, String)>,
}

// MCP-1113 caps — canonical values live in `host::limits`; the decoder
// state they bound now lives per-adapter.
use crate::host::{MAX_TOOL_INPUT_BUFS_PER_STREAM, MAX_TOOL_INPUT_BUF_BYTES};

impl StreamDecoder for AnthropicSseDecoder {
    fn feed_line(&mut self, line: &str, out: &mut Vec<StreamEventOut>) {
        let Some(data) = line.strip_prefix("data: ") else {
            return;
        };
        if data == "[DONE]" {
            out.push(StreamEventOut::Done("end_turn".to_string()));
            return;
        }
        let Ok(event) = serde_json::from_str::<serde_json::Value>(data) else {
            return;
        };
        let event_type = event.get("type").and_then(|t| t.as_str()).unwrap_or("");
        match event_type {
            "content_block_start" => {
                if let Some(cb) = event.get("content_block") {
                    if cb.get("type").and_then(|t| t.as_str()) == Some("tool_use") {
                        if self.tool_input_bufs.len() >= MAX_TOOL_INPUT_BUFS_PER_STREAM {
                            tracing::warn!(
                                cap = MAX_TOOL_INPUT_BUFS_PER_STREAM,
                                "LLM SSE tool_input_bufs at cap; dropping new content_block_start"
                            );
                            return;
                        }
                        let idx = event.get("index").and_then(|i| i.as_u64()).unwrap_or(0);
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
                        self.tool_input_bufs.insert(idx, (name, id, String::new()));
                    }
                }
            }
            "content_block_delta" => {
                if let Some(delta) = event.get("delta") {
                    let delta_type = delta.get("type").and_then(|t| t.as_str()).unwrap_or("");
                    if delta_type == "text_delta" {
                        if let Some(text) = delta.get("text").and_then(|t| t.as_str()) {
                            out.push(StreamEventOut::TextDelta(text.to_string()));
                        }
                    } else if delta_type == "input_json_delta" {
                        let idx = event.get("index").and_then(|i| i.as_u64()).unwrap_or(0);
                        if let Some(partial) = delta.get("partial_json").and_then(|p| p.as_str()) {
                            if let Some(entry) = self.tool_input_bufs.get_mut(&idx) {
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
                let idx = event.get("index").and_then(|i| i.as_u64()).unwrap_or(0);
                if let Some((name, id, input)) = self.tool_input_bufs.remove(&idx) {
                    out.push(StreamEventOut::ToolCall {
                        call_id: id,
                        tool_name: name,
                        arguments: if input.is_empty() {
                            "null".to_string()
                        } else {
                            input
                        },
                    });
                }
            }
            "message_delta" => {
                if let Some(usage) = event.get("usage") {
                    out.push(StreamEventOut::Usage {
                        input_tokens: usage
                            .get("input_tokens")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0),
                        output_tokens: usage
                            .get("output_tokens")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0),
                    });
                }
                if let Some(reason) = event
                    .get("delta")
                    .and_then(|d| d.get("stop_reason"))
                    .and_then(|s| s.as_str())
                {
                    out.push(StreamEventOut::Done(reason.to_string()));
                }
            }
            "message_stop" => {
                out.push(StreamEventOut::Done("end_turn".to_string()));
            }
            _ => {} // ping, message_start, …
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completion_body_maps_system_role_to_user_and_top_level_system() {
        let msgs = vec![
            ChatMessage {
                role: ChatRole::System,
                content: "be brief".into(),
            },
            ChatMessage {
                role: ChatRole::User,
                content: "hi".into(),
            },
        ];
        let body = AnthropicAdapter.build_completion_body(&CompletionParams {
            model: "claude-x",
            messages: &msgs,
            system_prompt: Some("SYS"),
            max_tokens: 100,
            temperature: Some(0.2),
        });
        assert_eq!(body["system"], "SYS");
        assert_eq!(body["messages"][0]["role"], "user"); // System mapped down
        assert_eq!(body["messages"][1]["role"], "user");
        assert_eq!(body["max_tokens"], 100);
    }

    #[test]
    fn options_cannot_replace_prompt_and_streaming_is_forced_off() {
        let msgs = vec![ChatMessage {
            role: ChatRole::User,
            content: "real".into(),
        }];
        let mut body = AnthropicAdapter.build_completion_body(&CompletionParams {
            model: "m",
            messages: &msgs,
            system_prompt: Some("REAL_SYS"),
            max_tokens: 10,
            temperature: None,
        });
        let opts = serde_json::json!({
            "messages": [{"role":"user","content":"HIJACKED"}],
            "system": "HIJACKED",
            "stream": true,
            "top_k": 40,
        });
        AnthropicAdapter.apply_provider_options(&mut body, opts.as_object().cloned().unwrap());
        assert_eq!(body["messages"][0]["content"], "real");
        assert_eq!(body["system"], "REAL_SYS");
        assert_eq!(body["stream"], false);
        assert_eq!(body["top_k"], 40); // tuning params DO apply
    }

    #[test]
    fn options_injected_system_is_dropped_when_host_set_none() {
        let msgs = vec![ChatMessage {
            role: ChatRole::User,
            content: "x".into(),
        }];
        let mut body = AnthropicAdapter.build_completion_body(&CompletionParams {
            model: "m",
            messages: &msgs,
            system_prompt: None,
            max_tokens: 10,
            temperature: None,
        });
        let opts = serde_json::json!({"system": "sneaky"});
        AnthropicAdapter.apply_provider_options(&mut body, opts.as_object().cloned().unwrap());
        assert!(body.get("system").is_none());
    }

    #[test]
    fn parse_completion_joins_text_blocks_and_reads_usage() {
        let body = serde_json::json!({
            "content": [
                {"type": "text", "text": "Hello "},
                {"type": "tool_use", "id": "t1", "name": "x", "input": {}},
                {"type": "text", "text": "world"},
            ],
            "usage": {"input_tokens": 7, "output_tokens": 3},
            "stop_reason": "end_turn",
        });
        let p = AnthropicAdapter
            .parse_completion(serde_json::to_vec(&body).unwrap().as_slice())
            .unwrap();
        assert_eq!(p.text, "Hello world");
        assert_eq!(p.input_tokens, Some(7));
        assert_eq!(p.output_tokens, Some(3));
        assert_eq!(p.stop_reason.as_deref(), Some("end_turn"));
    }

    #[test]
    fn parse_completion_handles_missing_optional_fields() {
        // Ported from the pre-trait `llm_response_parse_tests`: minimal
        // valid response must parse, with non-text blocks skipped.
        let p = AnthropicAdapter.parse_completion(br#"{"content": []}"#).unwrap();
        assert_eq!(p.text, "");
        assert!(p.stop_reason.is_none());
        let p2 = AnthropicAdapter
            .parse_completion(
                br#"{"content":[{"type":"tool_use","name":"calc","input":{}},
                     {"type":"text","text":"the answer is 42"}]}"#,
            )
            .unwrap();
        assert_eq!(p2.text, "the answer is 42");
    }

    #[test]
    fn parse_tool_completion_extracts_tool_use_blocks() {
        let body = serde_json::json!({
            "content": [
                {"type": "tool_use", "id": "call_1", "name": "get_weather",
                 "input": {"city": "Paris"}},
            ],
            "usage": {"input_tokens": 1, "output_tokens": 2},
            "stop_reason": "tool_use",
        });
        let p = AnthropicAdapter
            .parse_tool_completion(serde_json::to_vec(&body).unwrap().as_slice())
            .unwrap();
        assert_eq!(p.blocks.len(), 1);
        match &p.blocks[0] {
            ParsedToolBlock::ToolUse {
                call_id,
                tool_name,
                arguments,
            } => {
                assert_eq!(call_id, "call_1");
                assert_eq!(tool_name, "get_weather");
                assert_eq!(
                    serde_json::from_str::<serde_json::Value>(arguments).unwrap()["city"],
                    "Paris"
                );
            }
            other => panic!("expected ToolUse, got {other:?}"),
        }
    }

    #[test]
    fn sse_decoder_text_tool_and_done_flow() {
        let mut d = AnthropicSseDecoder::default();
        let mut out = Vec::new();
        d.feed_line(
            r#"data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hi"}}"#,
            &mut out,
        );
        d.feed_line(
            r#"data: {"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"c1","name":"f"}}"#,
            &mut out,
        );
        d.feed_line(
            r#"data: {"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"a\":1}"}}"#,
            &mut out,
        );
        d.feed_line(r#"data: {"type":"content_block_stop","index":1}"#, &mut out);
        d.feed_line(
            r#"data: {"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"input_tokens":5,"output_tokens":9}}"#,
            &mut out,
        );
        assert_eq!(out[0], StreamEventOut::TextDelta("Hi".into()));
        assert_eq!(
            out[1],
            StreamEventOut::ToolCall {
                call_id: "c1".into(),
                tool_name: "f".into(),
                arguments: "{\"a\":1}".into()
            }
        );
        assert_eq!(
            out[2],
            StreamEventOut::Usage {
                input_tokens: 5,
                output_tokens: 9
            }
        );
        assert_eq!(out[3], StreamEventOut::Done("tool_use".into()));
    }
}
