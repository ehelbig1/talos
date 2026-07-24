//! Native Ollama Chat API (`/api/chat`) adapter.
//!
//! Migrated OFF the OpenAI-compat shim (2026-07-09) because the shim
//! silently drops capabilities the native API makes first-class:
//!   * `think` — thinking-model control. The compat endpoint ignores
//!     `think` AND the `/no_think` soft switch (verified empirically on
//!     0.31.2); qwen3.6 with thinking enabled ran 65s+ on a 24-email
//!     classification batch, over the 60s LOCAL_LLM_EXCHANGE_TIMEOUT.
//!     (The compat layer's `reasoning_effort:"none"` mapping worked but
//!     is undocumented — `"minimal"` 400s — so we shim it here instead.)
//!   * `options.num_ctx` — context window. NOT settable via compat, so a
//!     growing prompt (the organizer's accumulating few-shot examples)
//!     silently truncates at the model default. Correctness hazard.
//!   * `format` — native structured outputs accept `"json"` or a full
//!     JSON Schema (XGrammar-constrained).
//!   * `keep_alive` — per-request residency control for the 23 GB-class
//!     local models.
//!   * `prompt_eval_count`/`eval_count` — real token counts (the compat
//!     `usage` block is a translation of these).
//!
//! Wire-shape facts pinned from a live 0.31.2 (see PR):
//!   * response: `{message:{role,content}, done, done_reason,
//!     prompt_eval_count, eval_count, …durations}`
//!   * `tool_calls[].function.arguments` is a JSON OBJECT (the compat
//!     endpoint returns a STRING) — normalized back to a string here so
//!     the WIT surface never notices.
//!   * streaming is JSON-LINES (`{message:{content:"…"},done:false}` per
//!     line; final line has `done:true` + counts), NOT SSE.
//!   * `think:false` is tolerated on non-thinking models (0.31.2), but we
//!     only send it when the caller asked (defense against older
//!     servers that reject it).

use super::*;

pub(crate) struct OllamaAdapter;

/// Runner/sampler option keys that live under `options` in the native
/// API but arrive TOP-LEVEL from OpenAI-compat-era `PROVIDER_OPTIONS`
/// configs. Remapped so existing module configs keep working unchanged.
const SAMPLER_OPTION_KEYS: &[&str] = &[
    "temperature",
    "top_p",
    "top_k",
    "min_p",
    "seed",
    "stop",
    "num_predict",
    "num_ctx",
    "num_batch",
    "num_gpu",
    "num_thread",
    "repeat_penalty",
    "repeat_last_n",
    "presence_penalty",
    "frequency_penalty",
    "mirostat",
    "mirostat_eta",
    "mirostat_tau",
    "tfs_z",
    "typical_p",
];

/// Keys an option payload may NOT smuggle into the native body: the
/// prompt/model/transport fields are host-assembled (re-asserted after
/// the merge anyway), and `template`/`raw` are prompt-formatting
/// overrides that would bypass SPOTLIGHTING if a future Ollama version
/// started honoring them on `/api/chat`. Fail-closed: strip.
const STRIPPED_OPTION_KEYS: &[&str] = &["model", "messages", "system", "stream", "template", "raw"];

/// Typed native response projection.
#[derive(serde::Deserialize)]
struct NativeChatResponse {
    #[serde(default)]
    message: Option<NativeMessage>,
    #[serde(default)]
    done_reason: Option<String>,
    #[serde(default)]
    prompt_eval_count: Option<u64>,
    #[serde(default)]
    eval_count: Option<u64>,
}

#[derive(serde::Deserialize)]
struct NativeMessage {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    tool_calls: Vec<NativeToolCall>,
}

#[derive(serde::Deserialize)]
struct NativeToolCall {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    function: Option<NativeFunctionCall>,
}

#[derive(serde::Deserialize)]
struct NativeFunctionCall {
    #[serde(default)]
    name: Option<String>,
    /// Native wire: a JSON OBJECT (not the OpenAI string form).
    #[serde(default)]
    arguments: Option<serde_json::Value>,
}

fn chat_url() -> String {
    format!("{}/api/chat", crate::host::ollama_base_url())
}

fn role_str(role: ChatRole) -> &'static str {
    match role {
        ChatRole::System => "system",
        ChatRole::User => "user",
        ChatRole::Assistant => "assistant",
    }
}

/// Translate an OpenAI-compat `response_format` value into the native
/// `format` field: `{"type":"json_object"}` → `"json"`;
/// `{"type":"json_schema","json_schema":{schema:…}}` → the schema object.
/// Deployed `PROVIDER_OPTIONS` configs (and the LLM-Inference module's
/// `want_json` injection) predate this adapter and speak compat — keep
/// them working without a re-deploy.
fn translate_response_format(v: &serde_json::Value) -> Option<serde_json::Value> {
    match v.get("type").and_then(|t| t.as_str()) {
        Some("json_object") => Some(serde_json::json!("json")),
        Some("json_schema") => v
            .get("json_schema")
            .and_then(|js| js.get("schema"))
            .cloned()
            .or(Some(serde_json::json!("json"))),
        _ => None,
    }
}

impl ProviderAdapter for OllamaAdapter {
    fn name(&self) -> &'static str {
        "ollama"
    }

    fn is_local(&self) -> bool {
        true
    }

    fn completion_url(&self, _model: &str) -> String {
        chat_url()
    }

    fn auth_headers(&self, _api_key: &str) -> Vec<(&'static str, String)> {
        Vec::new() // local provider — no auth
    }

    fn build_completion_body(&self, p: &CompletionParams) -> serde_json::Value {
        let mut messages: Vec<serde_json::Value> = Vec::with_capacity(p.messages.len() + 1);
        if let Some(sys) = p.system_prompt {
            messages.push(serde_json::json!({"role": "system", "content": sys}));
        }
        for m in p.messages {
            messages.push(serde_json::json!({"role": role_str(m.role), "content": m.content}));
        }
        // Native default is stream:true — ALWAYS explicit here.
        let mut options = serde_json::json!({ "num_predict": p.max_tokens });
        if let Some(t) = p.temperature {
            options["temperature"] = serde_json::json!(t);
        }
        serde_json::json!({
            "model": p.model,
            "messages": messages,
            "stream": false,
            "options": options,
        })
    }

    fn apply_response_format(&self, body: &mut serde_json::Value, json_schema: Option<&str>) {
        // Native structured outputs: `format:"json"` (any-shape JSON) or
        // a full JSON Schema object (grammar-constrained). Malformed
        // schema degrades to JSON mode — same contract as the OpenAI
        // adapter's `build_response_format`.
        body["format"] = match json_schema {
            None => serde_json::json!("json"),
            Some(s) => match serde_json::from_str::<serde_json::Value>(s) {
                Ok(schema) if schema.is_object() => schema,
                _ => {
                    tracing::warn!(
                        "complete_json: json-schema was not a valid JSON object — \
                         falling back to plain JSON mode"
                    );
                    serde_json::json!("json")
                }
            },
        };
    }

    fn apply_provider_options(
        &self,
        body: &mut serde_json::Value,
        opts: serde_json::Map<String, serde_json::Value>,
    ) {
        // Defensive accessor for the nested `options` map: never index
        // into a non-object (serde_json's IndexMut PANICS on type
        // mismatch, and a worker-host panic is a co-tenant DoS). The
        // builder always seeds `options` as an object and no merge arm
        // writes a non-object there, but this must stay panic-free under
        // any future call-order change.
        fn options_obj(
            obj: &mut serde_json::Map<String, serde_json::Value>,
        ) -> &mut serde_json::Value {
            let entry = obj
                .entry("options")
                .or_insert_with(|| serde_json::json!({}));
            if !entry.is_object() {
                *entry = serde_json::json!({});
            }
            entry
        }

        let orig_messages = body.get("messages").cloned();
        let orig_model = body.get("model").cloned();
        let Some(obj) = body.as_object_mut() else {
            return;
        };
        // TWO-PASS merge with EXPLICIT precedence: compat-era spellings
        // first, native fields second — so on collision (e.g. caller sends
        // both `max_tokens` AND `options.num_predict`, or `response_format`
        // AND `format`) the NATIVE spelling always wins, deterministically.
        // Without the split, precedence depended on serde_json::Map
        // iteration order — BTreeMap-sorted today, which arbitrarily gave
        // nested-options wins for keys < "o" and compat wins for keys > "o",
        // and would silently flip to insertion order if ANY workspace crate
        // ever enabled serde_json/preserve_order (cargo feature unification
        // is global).
        //
        // Pass 1 — compat-era spellings, translated to native.
        for (k, v) in &opts {
            match k.as_str() {
                "max_tokens" => {
                    options_obj(obj)["num_predict"] = v.clone();
                }
                "response_format" => {
                    if let Some(fmt) = translate_response_format(v) {
                        obj.insert("format".to_string(), fmt);
                    } else {
                        tracing::warn!(
                            "ollama provider options: unrecognized response_format shape; ignored"
                        );
                    }
                }
                "reasoning_effort" => {
                    // Undocumented compat mapping, shimmed for the configs
                    // deployed while the worker still spoke compat:
                    // none/minimal → thinking OFF; other LEVELS → ON.
                    // A NON-STRING value is ignored with a warning rather
                    // than defaulting thinking ON — failing open into the
                    // expensive direction is the exact 65s-over-the-60s-
                    // local-timeout mode this control exists to prevent.
                    match v.as_str() {
                        Some("none") | Some("minimal") | Some("off") => {
                            obj.insert("think".to_string(), serde_json::json!(false));
                        }
                        Some(_) => {
                            obj.insert("think".to_string(), serde_json::json!(true));
                        }
                        None => {
                            tracing::warn!(
                                "ollama provider options: non-string reasoning_effort; ignored"
                            );
                        }
                    }
                }
                k2 if SAMPLER_OPTION_KEYS.contains(&k2) => {
                    options_obj(obj)[k2] = v.clone();
                }
                _ => {}
            }
        }
        // Pass 2 — native request-level fields; win over pass-1
        // translations on collision.
        for (k, v) in opts {
            match k.as_str() {
                _ if STRIPPED_OPTION_KEYS.contains(&k.as_str()) => {
                    // Guardrail-stripped (re-asserted below anyway, but
                    // skipping avoids ever holding a hijacked value).
                }
                // consumed by pass 1
                "max_tokens" | "response_format" | "reasoning_effort" => {}
                k2 if SAMPLER_OPTION_KEYS.contains(&k2) => {}
                // ── native request-level fields ──
                "options" => {
                    // Merge (not replace) so explicit nested options
                    // compose with — and override — the remapped sampler
                    // keys from pass 1.
                    if let Some(incoming) = v.as_object() {
                        if let Some(existing) = options_obj(obj).as_object_mut() {
                            for (ok, ov) in incoming {
                                existing.insert(ok.clone(), ov.clone());
                            }
                        }
                    } else {
                        tracing::warn!(
                            "ollama provider options: non-object `options` value; ignored"
                        );
                    }
                }
                // `think`, `format`, `keep_alive`, and any future native
                // request-level field pass through top-level.
                _ => {
                    obj.insert(k, v);
                }
            }
        }
        // Re-assert prompt integrity + transport shape.
        if let Some(m) = orig_messages {
            obj.insert("messages".to_string(), m);
        }
        if let Some(m) = orig_model {
            obj.insert("model".to_string(), m);
        }
        obj.insert("stream".to_string(), serde_json::json!(false));
        obj.remove("template");
        obj.remove("raw");
    }

    fn parse_completion(&self, bytes: &[u8]) -> Result<ParsedCompletion, String> {
        let r: NativeChatResponse = serde_json::from_slice(bytes)
            .map_err(|e| format!("Failed to parse native Ollama response: {e}"))?;
        Ok(ParsedCompletion {
            text: r.message.and_then(|m| m.content).unwrap_or_default(),
            input_tokens: r.prompt_eval_count,
            output_tokens: r.eval_count,
            stop_reason: r.done_reason,
        })
    }

    fn build_tools_body(&self, p: &ToolCompletionParams) -> Result<serde_json::Value, String> {
        // Native /api/chat accepts OpenAI-style function tools and the
        // same message roles (incl. `tool` results keyed by name — but
        // the OpenAI `tool_call_id` form is also accepted ≥0.4). Reuse
        // the OpenAI message/tool assembly, then swap the transport
        // fields to native shape.
        let openai_body = super::openai::OpenAiAdapter.build_tools_body(p)?;
        let mut messages = openai_body.get("messages").cloned().unwrap_or_default();
        normalize_native_message_content(&mut messages);
        nativize_tool_call_arguments(&mut messages);
        let mut body = serde_json::json!({
            "model": p.model,
            "messages": messages,
            "tools": openai_body.get("tools").cloned().unwrap_or_default(),
            "stream": false,
            "options": { "num_predict": p.max_tokens },
        });
        if let Some(t) = p.temperature {
            body["options"]["temperature"] = serde_json::json!(t);
        }
        // Native API has no tool_choice; `force_tool` is best-effort via
        // prompt upstream. Not an error — matches compat-era behavior
        // where the field was ignored.
        Ok(body)
    }

    fn parse_tool_completion(&self, bytes: &[u8]) -> Result<ParsedToolCompletion, String> {
        let r: NativeChatResponse = serde_json::from_slice(bytes)
            .map_err(|e| format!("Failed to parse native Ollama tools response: {e}"))?;
        let mut blocks = Vec::new();
        if let Some(msg) = r.message {
            if let Some(content) = msg.content {
                if !content.is_empty() {
                    blocks.push(ParsedToolBlock::Text(content));
                }
            }
            for tc in msg.tool_calls {
                let f = tc.function.unwrap_or(NativeFunctionCall {
                    name: None,
                    arguments: None,
                });
                blocks.push(ParsedToolBlock::ToolUse {
                    call_id: tc.id.unwrap_or_default(),
                    tool_name: f.name.unwrap_or_default(),
                    // Native arguments are an OBJECT — normalize to the
                    // canonical JSON-string form.
                    arguments: f
                        .arguments
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "{}".to_string()),
                });
            }
        }
        Ok(ParsedToolCompletion {
            blocks,
            input_tokens: r.prompt_eval_count,
            output_tokens: r.eval_count,
            stop_reason: r.done_reason,
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
        let mut msgs = match messages {
            serde_json::Value::Array(a) => a,
            other => vec![other],
        };
        if let Some(sys) = system_prompt {
            msgs.insert(0, serde_json::json!({"role": "system", "content": sys}));
        }
        let mut msgs = serde_json::Value::Array(msgs);
        normalize_native_message_content(&mut msgs);
        nativize_tool_call_arguments(&mut msgs);
        let mut options = serde_json::json!({ "num_predict": max_tokens });
        if let Some(t) = temperature {
            options["temperature"] = serde_json::json!(t);
        }
        let mut body = serde_json::json!({
            "model": model,
            "messages": msgs,
            "stream": true,
            "options": options,
        });
        if let Some(tools) = tools {
            body["tools"] = tools;
        }
        Ok(body)
    }

    fn stream_decoder(&self) -> Option<Box<dyn StreamDecoder>> {
        Some(Box::new(OllamaJsonlDecoder::default()))
    }
}

/// Native `/api/chat` requires `message.content` to be a STRING — it
/// 400s on array content ("json: cannot unmarshal array into Go struct
/// field ChatRequest.messages.content of type string", verified live on
/// 0.31.2). The OpenAI-compat endpoint tolerated two array shapes that
/// can still reach this adapter:
///   * OpenAI multimodal parts (`{type:"text"|"image_url", …}`) from the
///     shared tools-body assembly when images are present;
///   * rich blocks (`{type:"text", text}`) per the WIT `stream-request`
///     doc for `messages-json`.
/// Flatten both: text parts join into the string `content`; image parts
/// move to the native per-message `images` field (raw base64 — strip the
/// data-URL prefix); other block kinds are dropped (native chat has no
/// wire for them).
fn normalize_native_message_content(messages: &mut serde_json::Value) {
    let Some(arr) = messages.as_array_mut() else {
        return;
    };
    for msg in arr {
        let Some(parts) = msg.get("content").and_then(|c| c.as_array()).cloned() else {
            continue; // already a string (or absent) — native-safe
        };
        let mut text = String::new();
        let mut images: Vec<serde_json::Value> = Vec::new();
        for part in &parts {
            match part.get("type").and_then(|t| t.as_str()) {
                Some("text") => {
                    if let Some(t) = part.get("text").and_then(|t| t.as_str()) {
                        text.push_str(t);
                    }
                }
                Some("image_url") => {
                    // OpenAI part: {"image_url":{"url":"data:<mime>;base64,<DATA>"}}
                    if let Some(url) = part
                        .get("image_url")
                        .and_then(|i| i.get("url"))
                        .and_then(|u| u.as_str())
                    {
                        if let Some((_, b64)) = url.split_once("base64,") {
                            images.push(serde_json::json!(b64));
                        }
                    }
                }
                Some("image") => {
                    // rich block: {"type":"image","source":{"data": <b64>}}
                    if let Some(d) = part
                        .get("source")
                        .and_then(|s| s.get("data"))
                        .and_then(|d| d.as_str())
                    {
                        images.push(serde_json::json!(d));
                    }
                }
                _ => {
                    // tool-use / tool-result / unknown blocks have no
                    // native content wire — dropped (assistant tool calls
                    // ride the separate `tool_calls` field, already
                    // handled by the body builders).
                }
            }
        }
        msg["content"] = serde_json::json!(text);
        if !images.is_empty() {
            msg["images"] = serde_json::json!(images);
        }
    }
}

/// Native `/api/chat` unmarshals assistant-history
/// `tool_calls[].function.arguments` as a MAP — echoing the canonical
/// JSON-STRING form back 400s with `"Value looks like object, but can't
/// find closing '}' symbol"` (verified live on 0.31.2; the object form
/// round-trips fine). Parse the string form back to an object; an
/// unparseable arguments string degrades to `{}` rather than failing the
/// whole request. Sibling of `normalize_native_message_content` — same
/// compat-tolerated-it, native-rejects-it class, for the multi-turn tool
/// loop (turn 2+) instead of message content.
fn nativize_tool_call_arguments(messages: &mut serde_json::Value) {
    let Some(arr) = messages.as_array_mut() else {
        return;
    };
    for msg in arr {
        let Some(tcs) = msg.get_mut("tool_calls").and_then(|t| t.as_array_mut()) else {
            continue;
        };
        for tc in tcs {
            let Some(f) = tc.get_mut("function").and_then(|f| f.as_object_mut()) else {
                continue;
            };
            if let Some(s) = f.get("arguments").and_then(|a| a.as_str()) {
                let parsed = serde_json::from_str::<serde_json::Value>(s)
                    .unwrap_or_else(|_| serde_json::json!({}));
                f.insert("arguments".to_string(), parsed);
            }
        }
    }
}

/// Native Ollama stream decoder — JSON-LINES, one object per line:
/// `{message:{content:"delta"},done:false}` per chunk; complete
/// `message.tool_calls` arrive whole (no fragment accumulation needed);
/// the final line has `done:true`, `done_reason`, and the eval counts.
#[derive(Default)]
pub(crate) struct OllamaJsonlDecoder {
    done_emitted: bool,
}

impl StreamDecoder for OllamaJsonlDecoder {
    fn feed_line(&mut self, line: &str, out: &mut Vec<StreamEventOut>) {
        let line = line.trim();
        if line.is_empty() || self.done_emitted {
            return;
        }
        let Ok(chunk) = serde_json::from_str::<serde_json::Value>(line) else {
            return;
        };
        if let Some(msg) = chunk.get("message") {
            if let Some(text) = msg.get("content").and_then(|c| c.as_str()) {
                if !text.is_empty() {
                    out.push(StreamEventOut::TextDelta(text.to_string()));
                }
            }
            if let Some(tcs) = msg.get("tool_calls").and_then(|t| t.as_array()) {
                for tc in tcs {
                    let f = tc.get("function");
                    out.push(StreamEventOut::ToolCall {
                        call_id: tc
                            .get("id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        tool_name: f
                            .and_then(|f| f.get("name"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        arguments: f
                            .and_then(|f| f.get("arguments"))
                            .map(|v| v.to_string())
                            .unwrap_or_else(|| "{}".to_string()),
                    });
                }
            }
        }
        if chunk.get("done").and_then(|d| d.as_bool()) == Some(true) {
            let input = chunk
                .get("prompt_eval_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let output = chunk
                .get("eval_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            if input > 0 || output > 0 {
                out.push(StreamEventOut::Usage {
                    input_tokens: input,
                    output_tokens: output,
                });
            }
            let reason = chunk
                .get("done_reason")
                .and_then(|r| r.as_str())
                .unwrap_or("stop");
            out.push(StreamEventOut::Done(reason.to_string()));
            self.done_emitted = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_body() -> serde_json::Value {
        let msgs = vec![ChatMessage {
            role: ChatRole::User,
            content: "real".into(),
        }];
        OllamaAdapter.build_completion_body(&CompletionParams {
            model: "qwen3.6:latest",
            messages: &msgs,
            system_prompt: Some("SYS"),
            max_tokens: 1800,
            temperature: Some(0.1),
        })
    }

    #[test]
    fn completion_body_is_native_shape_with_explicit_stream_false() {
        let body = base_body();
        assert_eq!(
            body["stream"], false,
            "native default is stream:true — must be explicit"
        );
        assert_eq!(body["options"]["num_predict"], 1800);
        assert!((body["options"]["temperature"].as_f64().unwrap() - 0.1).abs() < 1e-6);
        assert_eq!(body["messages"][0]["role"], "system");
        assert!(
            body.get("max_tokens").is_none(),
            "compat spelling must not leak"
        );
    }

    #[test]
    fn response_format_json_mode_and_schema() {
        let mut body = base_body();
        OllamaAdapter.apply_response_format(&mut body, None);
        assert_eq!(body["format"], "json");
        OllamaAdapter.apply_response_format(&mut body, Some(r#"{"type":"object"}"#));
        assert_eq!(body["format"]["type"], "object");
        OllamaAdapter.apply_response_format(&mut body, Some("not json"));
        assert_eq!(body["format"], "json");
    }

    #[test]
    fn options_remap_compat_spellings_to_native() {
        let mut body = base_body();
        let opts = serde_json::json!({
            "reasoning_effort": "none",
            "response_format": {"type": "json_object"},
            "max_tokens": 512,
            "top_p": 0.9,
            "keep_alive": "30m",
        });
        OllamaAdapter.apply_provider_options(&mut body, opts.as_object().cloned().unwrap());
        assert_eq!(body["think"], false, "reasoning_effort:none → think:false");
        assert_eq!(body["format"], "json");
        assert_eq!(body["options"]["num_predict"], 512);
        assert!((body["options"]["top_p"].as_f64().unwrap() - 0.9).abs() < 1e-6);
        assert_eq!(body["keep_alive"], "30m");
        assert!(body.get("response_format").is_none());
        assert!(body.get("reasoning_effort").is_none());
        assert!(body.get("max_tokens").is_none());
        assert!(
            body.get("top_p").is_none(),
            "sampler keys must nest under options"
        );
    }

    #[test]
    fn options_reasoning_effort_levels_map_to_think_true() {
        for level in ["low", "medium", "high"] {
            let mut body = base_body();
            let opts = serde_json::json!({ "reasoning_effort": level });
            OllamaAdapter.apply_provider_options(&mut body, opts.as_object().cloned().unwrap());
            assert_eq!(body["think"], true, "reasoning_effort:{level}");
        }
    }

    #[test]
    fn options_native_think_and_nested_options_pass_through() {
        let mut body = base_body();
        let opts = serde_json::json!({
            "think": false,
            "options": {"num_ctx": 16384, "seed": 7},
        });
        OllamaAdapter.apply_provider_options(&mut body, opts.as_object().cloned().unwrap());
        assert_eq!(body["think"], false);
        assert_eq!(body["options"]["num_ctx"], 16384);
        assert_eq!(body["options"]["seed"], 7);
        // builder-set options survive the nested merge
        assert_eq!(body["options"]["num_predict"], 1800);
    }

    #[test]
    fn tools_body_nativizes_echo_back_string_arguments_to_objects() {
        // Multi-turn tool loop, turn 2: the guest echoes the assistant's
        // prior ToolUse (canonical STRING arguments). Native /api/chat
        // 400s on the string form (verified live 0.31.2) — the builder
        // must re-parse it to an object.
        let messages = [
            ToolMessage {
                role: ChatRole::Assistant,
                is_tool_result_turn: false,
                content: vec![ToolContentBlock::ToolUse {
                    call_id: "c1".into(),
                    tool_name: "get_weather".into(),
                    arguments: "{\"city\":\"Paris\"}".into(),
                }],
            },
            ToolMessage {
                role: ChatRole::User,
                is_tool_result_turn: true,
                content: vec![ToolContentBlock::ToolResult {
                    call_id: "c1".into(),
                    output: "22C".into(),
                    is_error: false,
                }],
            },
        ];
        let body = OllamaAdapter
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
        let args = &body["messages"][0]["tool_calls"][0]["function"]["arguments"];
        assert!(
            args.is_object(),
            "arguments must be an OBJECT on the native wire, got {args}"
        );
        assert_eq!(args["city"], "Paris");
    }

    #[test]
    fn options_native_spellings_win_over_compat_on_collision() {
        // Explicit two-pass precedence: native always beats the compat
        // translation, deterministically — NOT dependent on
        // serde_json::Map iteration order.
        let mut body = base_body();
        let opts = serde_json::json!({
            "max_tokens": 100,
            "options": {"num_predict": 200},
            "response_format": {"type": "json_object"},
            "format": {"type": "object"},
            "reasoning_effort": "none",
            "think": true,
        });
        OllamaAdapter.apply_provider_options(&mut body, opts.as_object().cloned().unwrap());
        assert_eq!(
            body["options"]["num_predict"], 200,
            "nested options beats max_tokens"
        );
        assert_eq!(
            body["format"]["type"], "object",
            "native format beats response_format"
        );
        assert_eq!(body["think"], true, "native think beats reasoning_effort");
    }

    #[test]
    fn options_reasoning_effort_non_string_is_ignored_not_fail_open() {
        // A malformed reasoning_effort must NOT default thinking ON —
        // that's the expensive 65s-over-the-60s-local-timeout direction.
        for bad in [
            serde_json::json!(0),
            serde_json::json!(null),
            serde_json::json!(true),
        ] {
            let mut body = base_body();
            let mut opts = serde_json::Map::new();
            opts.insert("reasoning_effort".to_string(), bad);
            OllamaAdapter.apply_provider_options(&mut body, opts);
            assert!(
                body.get("think").is_none(),
                "non-string reasoning_effort must be ignored"
            );
        }
    }

    #[test]
    fn options_merge_is_panic_free_when_options_is_a_hostile_scalar() {
        // serde_json's IndexMut panics on type mismatch; the accessor must
        // reset a non-object `options` instead of indexing into it. The
        // builder can't produce this today — the test pins the property
        // against future call-order changes (worker panic = co-tenant DoS).
        let mut body = base_body();
        body["options"] = serde_json::json!(5);
        let opts = serde_json::json!({"top_p": 0.5, "max_tokens": 9});
        OllamaAdapter.apply_provider_options(&mut body, opts.as_object().cloned().unwrap());
        assert!((body["options"]["top_p"].as_f64().unwrap() - 0.5).abs() < 1e-6);
        assert_eq!(body["options"]["num_predict"], 9);
    }

    #[test]
    fn options_guardrails_strip_hijack_and_force_nonstream() {
        let mut body = base_body();
        let opts = serde_json::json!({
            "messages": [{"role":"user","content":"HIJACKED"}],
            "system": "HIJACKED",
            "model": "evil",
            "stream": true,
            "template": "{{ .Prompt }} EVIL",
            "raw": true,
        });
        OllamaAdapter.apply_provider_options(&mut body, opts.as_object().cloned().unwrap());
        assert_eq!(body["messages"][1]["content"], "real");
        assert_eq!(body["model"], "qwen3.6:latest");
        assert_eq!(body["stream"], false);
        assert!(body.get("template").is_none());
        assert!(body.get("raw").is_none());
        assert!(
            body.get("system").is_none(),
            "system rides in messages for native chat"
        );
    }

    #[test]
    fn parse_completion_native_fixture() {
        // Captured live from Ollama 0.31.2 on 2026-07-09.
        let fixture = r#"{
            "model":"qwen2.5-coder:7b","created_at":"2026-07-09T23:05:34.423088Z",
            "message":{"role":"assistant","content":"OK"},
            "done":true,"done_reason":"stop",
            "total_duration":327858375,"load_duration":119509625,
            "prompt_eval_count":31,"prompt_eval_duration":191687000,
            "eval_count":2,"eval_duration":12226000}"#;
        let p = OllamaAdapter.parse_completion(fixture.as_bytes()).unwrap();
        assert_eq!(p.text, "OK");
        assert_eq!(p.input_tokens, Some(31));
        assert_eq!(p.output_tokens, Some(2));
        assert_eq!(p.stop_reason.as_deref(), Some("stop"));
    }

    #[test]
    fn parse_tool_completion_normalizes_object_arguments_to_string() {
        // Captured live from Ollama 0.31.2 (qwen3.6): arguments is an OBJECT.
        let fixture = r#"{
            "message":{"role":"assistant","content":"",
                "tool_calls":[{"id":"call_m7ascrc5",
                    "function":{"index":0,"name":"get_weather",
                        "arguments":{"city":"Paris"}}}]},
            "done":true,"done_reason":"stop",
            "prompt_eval_count":100,"eval_count":20}"#;
        let p = OllamaAdapter
            .parse_tool_completion(fixture.as_bytes())
            .unwrap();
        match &p.blocks[0] {
            ParsedToolBlock::ToolUse {
                call_id,
                tool_name,
                arguments,
            } => {
                assert_eq!(call_id, "call_m7ascrc5");
                assert_eq!(tool_name, "get_weather");
                // Normalized to the canonical string form.
                let args: serde_json::Value = serde_json::from_str(arguments).unwrap();
                assert_eq!(args["city"], "Paris");
            }
            other => panic!("expected ToolUse, got {other:?}"),
        }
    }

    #[test]
    fn jsonl_decoder_text_then_final_stats() {
        // Chunk lines captured live from Ollama 0.31.2 streaming.
        let mut d = OllamaJsonlDecoder::default();
        let mut out = Vec::new();
        d.feed_line(
            r#"{"model":"m","created_at":"t","message":{"role":"assistant","content":"One"},"done":false}"#,
            &mut out,
        );
        d.feed_line(
            r#"{"model":"m","created_at":"t","message":{"role":"assistant","content":","},"done":false}"#,
            &mut out,
        );
        d.feed_line(
            r#"{"model":"m","created_at":"t","message":{"role":"assistant","content":""},"done":true,"done_reason":"stop","prompt_eval_count":30,"eval_count":16}"#,
            &mut out,
        );
        // Trailing garbage after done must be ignored.
        d.feed_line(r#"{"message":{"content":"late"},"done":false}"#, &mut out);
        assert_eq!(out[0], StreamEventOut::TextDelta("One".into()));
        assert_eq!(out[1], StreamEventOut::TextDelta(",".into()));
        assert_eq!(
            out[2],
            StreamEventOut::Usage {
                input_tokens: 30,
                output_tokens: 16
            }
        );
        assert_eq!(out[3], StreamEventOut::Done("stop".into()));
        assert_eq!(out.len(), 4);
    }

    #[test]
    fn stream_body_flattens_rich_block_content_to_string() {
        // Native /api/chat 400s on array content (verified live 0.31.2);
        // the WIT stream-request doc tells guests to send rich blocks.
        let messages = serde_json::json!([
            {"role": "user", "content": [{"type": "text", "text": "Hello "},
                                          {"type": "text", "text": "world"}]},
            {"role": "assistant", "content": "already a string"},
        ]);
        let body = OllamaAdapter
            .build_stream_body("m", messages, None, Some("SYS"), 64, None)
            .unwrap();
        assert_eq!(body["messages"][0]["content"], "SYS"); // system prepend
        assert_eq!(body["messages"][1]["content"], "Hello world");
        assert_eq!(body["messages"][2]["content"], "already a string");
    }

    #[test]
    fn tools_body_moves_image_parts_to_native_images_field() {
        // Images arrive from the shared OpenAI assembly as multimodal
        // parts with data-URLs; native wants raw base64 in `images`.
        let messages = [ToolMessage {
            role: ChatRole::User,
            is_tool_result_turn: false,
            content: vec![
                ToolContentBlock::Text("what is this?".into()),
                ToolContentBlock::Image {
                    media_type: "image/png".into(),
                    data: "AAAABBBB".into(),
                },
            ],
        }];
        let body = OllamaAdapter
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
        assert_eq!(body["messages"][0]["content"], "what is this?");
        assert_eq!(body["messages"][0]["images"][0], "AAAABBBB");
    }

    #[test]
    fn jsonl_decoder_emits_whole_tool_calls() {
        let mut d = OllamaJsonlDecoder::default();
        let mut out = Vec::new();
        d.feed_line(
            r#"{"message":{"role":"assistant","content":"","tool_calls":[{"id":"c1","function":{"name":"f","arguments":{"a":1}}}]},"done":false}"#,
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
    }
}
