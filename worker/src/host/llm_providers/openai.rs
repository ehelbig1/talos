//! OpenAI Chat Completions API (`/v1/chat/completions`) adapter.
//!
//! The plain-completion logic is a behavior-preserving extraction from
//! the pre-trait `llm.rs`. The TOOLS and STREAMING paths are NEW correct
//! implementations: pre-trait, OpenAI received Anthropic-shaped `tools`
//! bodies (silently ignored) and its SSE chunks (`choices[].delta`) never
//! matched the Anthropic event decoder — no tool call or text delta ever
//! reached a guest.

use super::*;

pub(crate) struct OpenAiAdapter;

const BASE_URL: &str = "https://api.openai.com/v1/chat/completions";

/// Typed response projection (2026-05-28 Perf#1).
#[derive(serde::Deserialize)]
struct OpenAiResponse {
    #[serde(default)]
    choices: Vec<OpenAiChoice>,
    #[serde(default)]
    usage: Option<OpenAiUsage>,
}

#[derive(serde::Deserialize)]
struct OpenAiChoice {
    #[serde(default)]
    message: Option<OpenAiMessage>,
    #[serde(default)]
    finish_reason: Option<String>,
}

#[derive(serde::Deserialize)]
struct OpenAiMessage {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    tool_calls: Vec<OpenAiToolCall>,
}

#[derive(serde::Deserialize)]
struct OpenAiToolCall {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    function: Option<OpenAiFunctionCall>,
}

#[derive(serde::Deserialize)]
struct OpenAiFunctionCall {
    #[serde(default)]
    name: Option<String>,
    /// OpenAI wire: a JSON STRING (contrast: native Ollama sends an
    /// object — see `ollama.rs`).
    #[serde(default)]
    arguments: Option<String>,
}

#[derive(serde::Deserialize)]
struct OpenAiUsage {
    #[serde(default)]
    prompt_tokens: Option<u64>,
    #[serde(default)]
    completion_tokens: Option<u64>,
}

/// Structured-output overlay for OpenAI-compatible wires (moved verbatim
/// from the pre-trait `build_response_format` in `llm.rs`): `None` →
/// JSON mode; a valid JSON-object schema → strict `json_schema`;
/// malformed schema degrades to JSON mode rather than hard-failing.
pub(crate) fn build_response_format(json_schema: Option<&str>) -> serde_json::Value {
    match json_schema {
        None => serde_json::json!({ "type": "json_object" }),
        Some(schema_str) => match serde_json::from_str::<serde_json::Value>(schema_str) {
            Ok(schema) if schema.is_object() => serde_json::json!({
                "type": "json_schema",
                "json_schema": {
                    "name": "response",
                    "strict": true,
                    "schema": schema,
                }
            }),
            _ => {
                tracing::warn!(
                    "complete_json: json-schema was not a valid JSON object — \
                     falling back to plain JSON mode"
                );
                serde_json::json!({ "type": "json_object" })
            }
        },
    }
}

fn openai_messages(p: &CompletionParams) -> Vec<serde_json::Value> {
    let mut messages: Vec<serde_json::Value> = Vec::with_capacity(p.messages.len() + 1);
    // OpenAI supports `system` as a message role — the request-level
    // system prompt is PREPENDED as the first message.
    if let Some(sys) = p.system_prompt {
        messages.push(serde_json::json!({"role": "system", "content": sys}));
    }
    for m in p.messages {
        let role = match m.role {
            ChatRole::System => "system",
            ChatRole::User => "user",
            ChatRole::Assistant => "assistant",
        };
        messages.push(serde_json::json!({"role": role, "content": m.content}));
    }
    messages
}

impl ProviderAdapter for OpenAiAdapter {
    fn name(&self) -> &'static str {
        "openai"
    }

    fn completion_url(&self, _model: &str) -> String {
        BASE_URL.to_string()
    }

    fn auth_headers(&self, api_key: &str) -> Vec<(&'static str, String)> {
        vec![("Authorization", format!("Bearer {api_key}"))]
    }

    fn build_completion_body(&self, p: &CompletionParams) -> serde_json::Value {
        let mut body = serde_json::json!({
            "model": p.model,
            "messages": openai_messages(p),
            "max_tokens": p.max_tokens,
        });
        if let Some(t) = p.temperature {
            body["temperature"] = serde_json::json!(t);
        }
        body
    }

    fn apply_response_format(&self, body: &mut serde_json::Value, json_schema: Option<&str>) {
        body["response_format"] = build_response_format(json_schema);
    }

    fn apply_provider_options(
        &self,
        body: &mut serde_json::Value,
        opts: serde_json::Map<String, serde_json::Value>,
    ) {
        let orig_messages = body.get("messages").cloned();
        if let Some(obj) = body.as_object_mut() {
            for (k, v) in opts {
                obj.insert(k, v);
            }
            if let Some(m) = orig_messages {
                obj.insert("messages".to_string(), m);
            }
            // OpenAI bodies carry the system prompt INSIDE `messages`;
            // a caller-injected top-level `system` is meaningless here
            // and is dropped (pre-trait guardrail behavior).
            obj.remove("system");
            obj.insert("stream".to_string(), serde_json::json!(false));
        }
    }

    fn parse_completion(&self, bytes: &[u8]) -> Result<ParsedCompletion, String> {
        let r: OpenAiResponse = serde_json::from_slice(bytes)
            .map_err(|e| format!("Failed to parse OpenAI-format response: {e}"))?;
        let text = r
            .choices
            .first()
            .and_then(|c| c.message.as_ref())
            .and_then(|m| m.content.clone())
            .unwrap_or_default();
        let stop_reason = r.choices.into_iter().next().and_then(|c| c.finish_reason);
        Ok(ParsedCompletion {
            text,
            input_tokens: r.usage.as_ref().and_then(|u| u.prompt_tokens),
            output_tokens: r.usage.as_ref().and_then(|u| u.completion_tokens),
            stop_reason,
        })
    }

    fn build_tools_body(&self, p: &ToolCompletionParams) -> Result<serde_json::Value, String> {
        let mut messages: Vec<serde_json::Value> = Vec::new();
        if let Some(sys) = p.system_prompt {
            messages.push(serde_json::json!({"role": "system", "content": sys}));
        }
        for msg in p.messages {
            if msg.is_tool_result_turn {
                // OpenAI wants each tool result as its OWN `role:"tool"`
                // message keyed by tool_call_id.
                for block in &msg.content {
                    if let ToolContentBlock::ToolResult {
                        call_id,
                        output,
                        is_error: _,
                    } = block
                    {
                        messages.push(serde_json::json!({
                            "role": "tool",
                            "tool_call_id": call_id,
                            "content": output,
                        }));
                    }
                }
                continue;
            }
            let role = match msg.role {
                ChatRole::System => "system",
                ChatRole::User => "user",
                ChatRole::Assistant => "assistant",
            };
            // Split the rich blocks into what OpenAI models understand:
            // text (joined), assistant tool_calls, image_url parts.
            let mut text_parts: Vec<&str> = Vec::new();
            let mut tool_calls: Vec<serde_json::Value> = Vec::new();
            let mut image_parts: Vec<serde_json::Value> = Vec::new();
            for block in &msg.content {
                match block {
                    ToolContentBlock::Text(t) => text_parts.push(t),
                    ToolContentBlock::ToolUse {
                        call_id,
                        tool_name,
                        arguments,
                    } => tool_calls.push(serde_json::json!({
                        "id": call_id,
                        "type": "function",
                        "function": {"name": tool_name, "arguments": arguments},
                    })),
                    ToolContentBlock::ToolResult { .. } => {
                        // Tool results outside a tool-result turn are a
                        // caller shape error; skip rather than corrupt
                        // the transcript.
                    }
                    ToolContentBlock::Image { media_type, data } => {
                        image_parts.push(serde_json::json!({
                            "type": "image_url",
                            "image_url": {"url": format!("data:{media_type};base64,{data}")},
                        }));
                    }
                }
            }
            let mut m = serde_json::json!({"role": role});
            if !image_parts.is_empty() {
                // Multimodal content array: text part(s) + images.
                let mut parts = Vec::new();
                let joined = text_parts.join("");
                if !joined.is_empty() {
                    parts.push(serde_json::json!({"type": "text", "text": joined}));
                }
                parts.extend(image_parts);
                m["content"] = serde_json::json!(parts);
            } else {
                m["content"] = serde_json::json!(text_parts.join(""));
            }
            if !tool_calls.is_empty() {
                m["tool_calls"] = serde_json::json!(tool_calls);
            }
            messages.push(m);
        }

        let tools: Vec<serde_json::Value> = p
            .tools
            .iter()
            .map(|t| {
                serde_json::json!({
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.input_schema,
                    }
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
        if let Some(force) = p.force_tool {
            body["tool_choice"] =
                serde_json::json!({"type": "function", "function": {"name": force}});
        }
        Ok(body)
    }

    fn parse_tool_completion(&self, bytes: &[u8]) -> Result<ParsedToolCompletion, String> {
        let r: OpenAiResponse = serde_json::from_slice(bytes)
            .map_err(|e| format!("Failed to parse OpenAI tools response: {e}"))?;
        let mut blocks = Vec::new();
        let mut stop_reason = None;
        if let Some(choice) = r.choices.into_iter().next() {
            stop_reason = choice.finish_reason;
            if let Some(msg) = choice.message {
                if let Some(content) = msg.content {
                    if !content.is_empty() {
                        blocks.push(ParsedToolBlock::Text(content));
                    }
                }
                for tc in msg.tool_calls {
                    let f = tc.function.unwrap_or(OpenAiFunctionCall {
                        name: None,
                        arguments: None,
                    });
                    blocks.push(ParsedToolBlock::ToolUse {
                        call_id: tc.id.unwrap_or_default(),
                        tool_name: f.name.unwrap_or_default(),
                        arguments: f.arguments.unwrap_or_else(|| "{}".to_string()),
                    });
                }
            }
        }
        Ok(ParsedToolCompletion {
            blocks,
            input_tokens: r.usage.as_ref().and_then(|u| u.prompt_tokens),
            output_tokens: r.usage.as_ref().and_then(|u| u.completion_tokens),
            stop_reason,
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
        // Caller-shaped messages pass through; the system prompt is
        // prepended as a system-role message (OpenAI has no top-level
        // `system` field).
        let mut msgs = match messages {
            serde_json::Value::Array(a) => a,
            other => vec![other],
        };
        if let Some(sys) = system_prompt {
            msgs.insert(0, serde_json::json!({"role": "system", "content": sys}));
        }
        let mut body = serde_json::json!({
            "model": model,
            "messages": msgs,
            "max_tokens": max_tokens,
            "stream": true,
        });
        if let Some(t) = temperature {
            body["temperature"] = serde_json::json!(t);
        }
        if let Some(tools) = tools {
            body["tools"] = tools;
        }
        Ok(body)
    }

    fn stream_decoder(&self) -> Option<Box<dyn StreamDecoder>> {
        Some(Box::new(OpenAiSseDecoder::default()))
    }
}

/// OpenAI SSE chunk decoder — `choices[0].delta.content` text deltas,
/// index-accumulated `delta.tool_calls` fragments (arguments stream as
/// string pieces), `finish_reason` → flush accumulated tool calls + Done,
/// `[DONE]` sentinel → Done. Bounded like the Anthropic decoder.
#[derive(Default)]
pub(crate) struct OpenAiSseDecoder {
    /// index → (call_id, name, arguments-fragments)
    tool_bufs: std::collections::BTreeMap<u64, (String, String, String)>,
    done_emitted: bool,
}

// MCP-1113 caps — same bounds as the Anthropic decoder, canonical values
// in `host::limits`.
use crate::host::MAX_TOOL_INPUT_BUFS_PER_STREAM as MAX_TOOL_BUFS;
use crate::host::MAX_TOOL_INPUT_BUF_BYTES as MAX_TOOL_BUF_BYTES;

impl OpenAiSseDecoder {
    fn flush_tools(&mut self, out: &mut Vec<StreamEventOut>) {
        // BTreeMap keeps tool calls in wire index order.
        for (_, (id, name, args)) in std::mem::take(&mut self.tool_bufs) {
            out.push(StreamEventOut::ToolCall {
                call_id: id,
                tool_name: name,
                arguments: if args.is_empty() {
                    "{}".to_string()
                } else {
                    args
                },
            });
        }
    }
}

impl StreamDecoder for OpenAiSseDecoder {
    fn feed_line(&mut self, line: &str, out: &mut Vec<StreamEventOut>) {
        let Some(data) = line.strip_prefix("data: ") else {
            return;
        };
        if data == "[DONE]" {
            if !self.done_emitted {
                self.flush_tools(out);
                out.push(StreamEventOut::Done("stop".to_string()));
                self.done_emitted = true;
            }
            return;
        }
        let Ok(event) = serde_json::from_str::<serde_json::Value>(data) else {
            return;
        };
        // Usage arrives on a (possibly choice-less) final chunk when the
        // caller set stream_options.include_usage.
        if let Some(usage) = event.get("usage").filter(|u| !u.is_null()) {
            out.push(StreamEventOut::Usage {
                input_tokens: usage
                    .get("prompt_tokens")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
                output_tokens: usage
                    .get("completion_tokens")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
            });
        }
        let Some(choice) = event
            .get("choices")
            .and_then(|c| c.as_array())
            .and_then(|a| a.first())
        else {
            return;
        };
        if let Some(delta) = choice.get("delta") {
            if let Some(text) = delta.get("content").and_then(|c| c.as_str()) {
                if !text.is_empty() {
                    out.push(StreamEventOut::TextDelta(text.to_string()));
                }
            }
            if let Some(tcs) = delta.get("tool_calls").and_then(|t| t.as_array()) {
                for tc in tcs {
                    let idx = tc.get("index").and_then(|i| i.as_u64()).unwrap_or(0);
                    if !self.tool_bufs.contains_key(&idx) && self.tool_bufs.len() >= MAX_TOOL_BUFS {
                        tracing::warn!(
                            cap = MAX_TOOL_BUFS,
                            "OpenAI SSE tool_calls buffer at cap; dropping fragment"
                        );
                        continue;
                    }
                    let entry = self.tool_bufs.entry(idx).or_default();
                    if let Some(id) = tc.get("id").and_then(|v| v.as_str()) {
                        entry.0 = id.to_string();
                    }
                    if let Some(f) = tc.get("function") {
                        if let Some(name) = f.get("name").and_then(|v| v.as_str()) {
                            entry.1 = name.to_string();
                        }
                        if let Some(frag) = f.get("arguments").and_then(|v| v.as_str()) {
                            if entry.2.len().saturating_add(frag.len()) > MAX_TOOL_BUF_BYTES {
                                tracing::warn!(
                                    cap = MAX_TOOL_BUF_BYTES,
                                    idx,
                                    "OpenAI SSE tool arguments buffer at cap; dropping fragment"
                                );
                            } else {
                                entry.2.push_str(frag);
                            }
                        }
                    }
                }
            }
        }
        if let Some(reason) = choice.get("finish_reason").and_then(|r| r.as_str()) {
            if !self.done_emitted {
                self.flush_tools(out);
                out.push(StreamEventOut::Done(reason.to_string()));
                self.done_emitted = true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_format_none_yields_json_object_mode() {
        let rf = build_response_format(None);
        assert_eq!(rf["type"], "json_object");
    }

    #[test]
    fn response_format_valid_schema_yields_strict_json_schema() {
        let rf = build_response_format(Some(r#"{"type":"object"}"#));
        assert_eq!(rf["type"], "json_schema");
        assert_eq!(rf["json_schema"]["strict"], true);
        assert_eq!(rf["json_schema"]["schema"]["type"], "object");
    }

    #[test]
    fn response_format_malformed_schema_degrades_to_json_mode() {
        let rf = build_response_format(Some("not json"));
        assert_eq!(rf["type"], "json_object");
        let rf2 = build_response_format(Some("[1,2]"));
        assert_eq!(rf2["type"], "json_object");
    }

    #[test]
    fn completion_body_prepends_system_message() {
        let msgs = vec![ChatMessage {
            role: ChatRole::User,
            content: "hi".into(),
        }];
        let body = OpenAiAdapter.build_completion_body(&CompletionParams {
            model: "gpt-x",
            messages: &msgs,
            system_prompt: Some("SYS"),
            max_tokens: 64,
            temperature: None,
        });
        assert_eq!(body["messages"][0]["role"], "system");
        assert_eq!(body["messages"][0]["content"], "SYS");
        assert_eq!(body["messages"][1]["role"], "user");
        assert!(body.get("system").is_none());
    }

    #[test]
    fn options_guardrails_preserve_messages_and_force_nonstream() {
        let msgs = vec![ChatMessage {
            role: ChatRole::User,
            content: "real".into(),
        }];
        let mut body = OpenAiAdapter.build_completion_body(&CompletionParams {
            model: "m",
            messages: &msgs,
            system_prompt: None,
            max_tokens: 10,
            temperature: None,
        });
        let opts = serde_json::json!({
            "messages": "HIJACKED", "system": "sneaky", "stream": true, "seed": 42
        });
        OpenAiAdapter.apply_provider_options(&mut body, opts.as_object().cloned().unwrap());
        assert_eq!(body["messages"][0]["content"], "real");
        assert!(body.get("system").is_none());
        assert_eq!(body["stream"], false);
        assert_eq!(body["seed"], 42);
    }

    #[test]
    fn tools_body_uses_function_format_and_tool_choice() {
        let tools = [ToolDef {
            name: "get_weather",
            description: "d",
            input_schema: serde_json::json!({"type":"object"}),
        }];
        let messages = [ToolMessage {
            role: ChatRole::User,
            is_tool_result_turn: false,
            content: vec![ToolContentBlock::Text("weather?".into())],
        }];
        let body = OpenAiAdapter
            .build_tools_body(&ToolCompletionParams {
                model: "gpt-x",
                messages: &messages,
                tools: &tools,
                system_prompt: Some("SYS"),
                max_tokens: 100,
                temperature: None,
                force_tool: Some("get_weather"),
            })
            .unwrap();
        assert_eq!(body["tools"][0]["type"], "function");
        assert_eq!(body["tools"][0]["function"]["name"], "get_weather");
        assert_eq!(body["tool_choice"]["type"], "function");
        assert_eq!(body["messages"][0]["role"], "system");
        assert_eq!(body["messages"][1]["content"], "weather?");
    }

    #[test]
    fn tools_body_maps_tool_results_to_tool_role_messages() {
        let messages = [ToolMessage {
            role: ChatRole::User,
            is_tool_result_turn: true,
            content: vec![ToolContentBlock::ToolResult {
                call_id: "c9".into(),
                output: "42".into(),
                is_error: false,
            }],
        }];
        let body = OpenAiAdapter
            .build_tools_body(&ToolCompletionParams {
                model: "m",
                messages: &messages,
                tools: &[],
                system_prompt: None,
                max_tokens: 10,
                temperature: None,
                force_tool: None,
            })
            .unwrap();
        assert_eq!(body["messages"][0]["role"], "tool");
        assert_eq!(body["messages"][0]["tool_call_id"], "c9");
        assert_eq!(body["messages"][0]["content"], "42");
    }

    #[test]
    fn parse_tool_completion_reads_string_arguments() {
        // Captured shape: OpenAI-compat tool response (arguments = STRING).
        let body = serde_json::json!({
            "choices": [{"message": {"role": "assistant", "content": "",
                "tool_calls": [{"id": "call_1", "type": "function", "index": 0,
                    "function": {"name": "get_weather", "arguments": "{\"city\":\"Paris\"}"}}]},
                "finish_reason": "tool_calls"}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5},
        });
        let p = OpenAiAdapter
            .parse_tool_completion(serde_json::to_vec(&body).unwrap().as_slice())
            .unwrap();
        assert_eq!(
            p.blocks[0],
            ParsedToolBlock::ToolUse {
                call_id: "call_1".into(),
                tool_name: "get_weather".into(),
                arguments: "{\"city\":\"Paris\"}".into()
            }
        );
        assert_eq!(p.stop_reason.as_deref(), Some("tool_calls"));
    }

    // ── ported from the pre-trait `llm_response_parse_tests` (2026-05-28
    // audit Perf#1): the parse contract must tolerate provider drift. ──

    #[test]
    fn parse_completion_handles_empty_choices_and_missing_usage() {
        // Some Ollama-compat wrappers return `{"choices": []}` on rate
        // limit or model-not-found; providers omit `usage` on errors.
        let p = OpenAiAdapter.parse_completion(br#"{"choices": []}"#).unwrap();
        assert_eq!(p.text, "");
        assert!(p.input_tokens.is_none() && p.output_tokens.is_none());
    }

    #[test]
    fn parse_completion_ignores_unknown_fields() {
        let body = br#"{
            "choices": [{"message": {"content": "x"}}],
            "system_fingerprint": "fp_abc",
            "x_some_future_field": {"nested": "value"}
        }"#;
        assert_eq!(OpenAiAdapter.parse_completion(body).unwrap().text, "x");
    }

    #[test]
    fn parse_completion_passes_u64_token_counts_through() {
        // Saturation to u32 (MCP-1008) happens at the WIT boundary in
        // llm.rs; the adapter must carry the full u64.
        let body = br#"{"choices":[{"message":{"content":"y"}}],
            "usage": {"prompt_tokens": 5000000000, "completion_tokens": 1}}"#;
        let p = OpenAiAdapter.parse_completion(body).unwrap();
        assert_eq!(p.input_tokens, Some(5_000_000_000));
    }

    #[test]
    fn sse_decoder_text_deltas_and_done() {
        let mut d = OpenAiSseDecoder::default();
        let mut out = Vec::new();
        d.feed_line(
            r#"data: {"choices":[{"delta":{"content":"Hel"},"index":0}]}"#,
            &mut out,
        );
        d.feed_line(
            r#"data: {"choices":[{"delta":{"content":"lo"},"index":0}]}"#,
            &mut out,
        );
        d.feed_line(
            r#"data: {"choices":[{"delta":{},"finish_reason":"stop","index":0}]}"#,
            &mut out,
        );
        d.feed_line("data: [DONE]", &mut out);
        assert_eq!(out[0], StreamEventOut::TextDelta("Hel".into()));
        assert_eq!(out[1], StreamEventOut::TextDelta("lo".into()));
        assert_eq!(out[2], StreamEventOut::Done("stop".into()));
        assert_eq!(out.len(), 3, "[DONE] after finish_reason must not double-emit");
    }

    #[test]
    fn sse_decoder_accumulates_tool_call_fragments() {
        let mut d = OpenAiSseDecoder::default();
        let mut out = Vec::new();
        d.feed_line(
            r#"data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"c1","function":{"name":"f","arguments":""}}]}}]}"#,
            &mut out,
        );
        d.feed_line(
            r#"data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"a\":"}}]}}]}"#,
            &mut out,
        );
        d.feed_line(
            r#"data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"1}"}}]}}]}"#,
            &mut out,
        );
        d.feed_line(
            r#"data: {"choices":[{"delta":{},"finish_reason":"tool_calls"}]}"#,
            &mut out,
        );
        assert_eq!(
            out[0],
            StreamEventOut::ToolCall {
                call_id: "c1".into(),
                tool_name: "f".into(),
                arguments: "{\"a\":1}".into()
            }
        );
        assert_eq!(out[1], StreamEventOut::Done("tool_calls".into()));
    }
}
