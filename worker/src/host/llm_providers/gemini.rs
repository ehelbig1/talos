//! Google Gemini API (`generateContent`) adapter.
//!
//! HONESTY NOTE (2026-07-09): pre-trait, "Gemini support" sent an
//! Anthropic-shaped body to `…/v1beta/models` (no model in the path, no
//! `contents`) and parsed the reply as an Anthropic response — a
//! guaranteed 404/parse failure on every call. This adapter implements
//! the REAL `generateContent` wire shape for plain completions (worst
//! case it fails differently; it cannot fail harder than always). Tools
//! and streaming return explicit `Err`s instead of the old silent
//! garbage — they were never functional, and an honest "not supported"
//! beats an inscrutable parse error. Live-key validation is still
//! pending (no Gemini key in this deployment); shapes are pinned by unit
//! fixtures from the published API reference.

use super::*;

pub(crate) struct GeminiAdapter;

const BASE_URL: &str = "https://generativelanguage.googleapis.com/v1beta/models";

const TOOLS_UNSUPPORTED: &str =
    "gemini tool-use is not implemented (the pre-2026-07 path sent malformed bodies and never \
     worked); use anthropic/openai/ollama for tools";
const STREAMING_UNSUPPORTED: &str =
    "gemini streaming is not implemented (the pre-2026-07 path sent malformed bodies and never \
     worked); use anthropic/openai/ollama for streaming";

#[derive(serde::Deserialize)]
struct GeminiResponse {
    #[serde(default)]
    candidates: Vec<GeminiCandidate>,
    #[serde(default, rename = "usageMetadata")]
    usage_metadata: Option<GeminiUsage>,
}

#[derive(serde::Deserialize)]
struct GeminiCandidate {
    #[serde(default)]
    content: Option<GeminiContent>,
    #[serde(default, rename = "finishReason")]
    finish_reason: Option<String>,
}

#[derive(serde::Deserialize)]
struct GeminiContent {
    #[serde(default)]
    parts: Vec<GeminiPart>,
}

#[derive(serde::Deserialize)]
struct GeminiPart {
    #[serde(default)]
    text: Option<String>,
}

#[derive(serde::Deserialize)]
struct GeminiUsage {
    #[serde(default, rename = "promptTokenCount")]
    prompt_token_count: Option<u64>,
    #[serde(default, rename = "candidatesTokenCount")]
    candidates_token_count: Option<u64>,
}

impl ProviderAdapter for GeminiAdapter {
    fn name(&self) -> &'static str {
        "gemini"
    }

    fn completion_url(&self, model: &str) -> String {
        // Gemini encodes the model in the path. The model name is host-
        // resolved (request field or worker default), not guest-free-form
        // URL content, but percent-encode defensively anyway.
        let safe: String = model
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'))
            .collect();
        format!("{BASE_URL}/{safe}:generateContent")
    }

    fn auth_headers(&self, api_key: &str) -> Vec<(&'static str, String)> {
        vec![("x-goog-api-key", api_key.to_string())]
    }

    fn build_completion_body(&self, p: &CompletionParams) -> serde_json::Value {
        // Gemini: `contents` with roles user|model; system prompt is the
        // separate `systemInstruction`; System-role MESSAGES fold into
        // user turns (Gemini has no system role in contents).
        let contents: Vec<serde_json::Value> = p
            .messages
            .iter()
            .map(|m| {
                let role = match m.role {
                    ChatRole::Assistant => "model",
                    ChatRole::System | ChatRole::User => "user",
                };
                serde_json::json!({"role": role, "parts": [{"text": m.content}]})
            })
            .collect();
        let mut generation_config = serde_json::json!({ "maxOutputTokens": p.max_tokens });
        if let Some(t) = p.temperature {
            generation_config["temperature"] = serde_json::json!(t);
        }
        let mut body = serde_json::json!({
            "contents": contents,
            "generationConfig": generation_config,
        });
        if let Some(sys) = p.system_prompt {
            body["systemInstruction"] = serde_json::json!({"parts": [{"text": sys}]});
        }
        body
    }

    fn apply_response_format(&self, body: &mut serde_json::Value, json_schema: Option<&str>) {
        let gc = body
            .as_object_mut()
            .map(|o| {
                o.entry("generationConfig")
                    .or_insert_with(|| serde_json::json!({}))
            })
            .expect("body is an object");
        gc["responseMimeType"] = serde_json::json!("application/json");
        if let Some(s) = json_schema {
            if let Ok(schema) = serde_json::from_str::<serde_json::Value>(s) {
                if schema.is_object() {
                    gc["responseSchema"] = schema;
                }
            }
        }
    }

    fn apply_provider_options(
        &self,
        body: &mut serde_json::Value,
        opts: serde_json::Map<String, serde_json::Value>,
    ) {
        // Merge, then re-assert the prompt payload (`contents` +
        // `systemInstruction`). Gemini's generateContent has no `stream`
        // body field (streaming is a different endpoint), so nothing to
        // force — but drop one if a caller injected it.
        let orig_contents = body.get("contents").cloned();
        let orig_system = body.get("systemInstruction").cloned();
        if let Some(obj) = body.as_object_mut() {
            for (k, v) in opts {
                obj.insert(k, v);
            }
            if let Some(c) = orig_contents {
                obj.insert("contents".to_string(), c);
            }
            match orig_system {
                Some(s) => {
                    obj.insert("systemInstruction".to_string(), s);
                }
                None => {
                    obj.remove("systemInstruction");
                }
            }
            obj.remove("stream");
        }
    }

    fn parse_completion(&self, bytes: &[u8]) -> Result<ParsedCompletion, String> {
        let r: GeminiResponse = serde_json::from_slice(bytes)
            .map_err(|e| format!("Failed to parse Gemini response: {e}"))?;
        let first = r.candidates.into_iter().next();
        let text = first
            .as_ref()
            .and_then(|c| c.content.as_ref())
            .map(|c| {
                c.parts
                    .iter()
                    .filter_map(|p| p.text.as_deref())
                    .collect::<Vec<_>>()
                    .join("")
            })
            .unwrap_or_default();
        Ok(ParsedCompletion {
            text,
            input_tokens: r.usage_metadata.as_ref().and_then(|u| u.prompt_token_count),
            output_tokens: r
                .usage_metadata
                .as_ref()
                .and_then(|u| u.candidates_token_count),
            stop_reason: first.and_then(|c| c.finish_reason),
        })
    }

    fn build_tools_body(&self, _p: &ToolCompletionParams) -> Result<serde_json::Value, String> {
        Err(TOOLS_UNSUPPORTED.to_string())
    }

    fn parse_tool_completion(&self, _bytes: &[u8]) -> Result<ParsedToolCompletion, String> {
        Err(TOOLS_UNSUPPORTED.to_string())
    }

    fn build_stream_body(
        &self,
        _model: &str,
        _messages: serde_json::Value,
        _tools: Option<serde_json::Value>,
        _system_prompt: Option<&str>,
        _max_tokens: u32,
        _temperature: Option<f32>,
    ) -> Result<serde_json::Value, String> {
        Err(STREAMING_UNSUPPORTED.to_string())
    }

    fn stream_decoder(&self) -> Option<Box<dyn StreamDecoder>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completion_url_encodes_model_in_path() {
        assert_eq!(
            GeminiAdapter.completion_url("gemini-1.5-pro"),
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent"
        );
        // path-traversal / query characters are stripped, not forwarded —
        // the model segment must contain no '/', '?', '&' or '#'.
        assert_eq!(
            GeminiAdapter.completion_url("a/../b?k=v&x#y"),
            format!("{BASE_URL}/a..bkvxy:generateContent")
        );
    }

    #[test]
    fn completion_body_is_gemini_shape() {
        let msgs = vec![
            ChatMessage {
                role: ChatRole::User,
                content: "hi".into(),
            },
            ChatMessage {
                role: ChatRole::Assistant,
                content: "hello".into(),
            },
        ];
        let body = GeminiAdapter.build_completion_body(&CompletionParams {
            model: "gemini-1.5-pro",
            messages: &msgs,
            system_prompt: Some("SYS"),
            max_tokens: 256,
            temperature: Some(0.3),
        });
        assert_eq!(body["contents"][0]["role"], "user");
        assert_eq!(body["contents"][1]["role"], "model");
        assert_eq!(body["contents"][0]["parts"][0]["text"], "hi");
        assert_eq!(body["systemInstruction"]["parts"][0]["text"], "SYS");
        assert_eq!(body["generationConfig"]["maxOutputTokens"], 256);
    }

    #[test]
    fn response_format_sets_mime_and_schema() {
        let msgs = vec![ChatMessage {
            role: ChatRole::User,
            content: "x".into(),
        }];
        let mut body = GeminiAdapter.build_completion_body(&CompletionParams {
            model: "m",
            messages: &msgs,
            system_prompt: None,
            max_tokens: 10,
            temperature: None,
        });
        GeminiAdapter.apply_response_format(&mut body, Some(r#"{"type":"object"}"#));
        assert_eq!(
            body["generationConfig"]["responseMimeType"],
            "application/json"
        );
        assert_eq!(body["generationConfig"]["responseSchema"]["type"], "object");
    }

    #[test]
    fn parse_completion_reads_candidates_and_usage() {
        let fixture = serde_json::json!({
            "candidates": [{
                "content": {"parts": [{"text": "Hello "}, {"text": "Gemini"}], "role": "model"},
                "finishReason": "STOP",
            }],
            "usageMetadata": {"promptTokenCount": 12, "candidatesTokenCount": 4},
        });
        let p = GeminiAdapter
            .parse_completion(serde_json::to_vec(&fixture).unwrap().as_slice())
            .unwrap();
        assert_eq!(p.text, "Hello Gemini");
        assert_eq!(p.input_tokens, Some(12));
        assert_eq!(p.output_tokens, Some(4));
        assert_eq!(p.stop_reason.as_deref(), Some("STOP"));
    }

    #[test]
    fn tools_and_streaming_are_explicit_errors() {
        assert!(GeminiAdapter
            .build_tools_body(&ToolCompletionParams {
                model: "m",
                messages: &[],
                tools: &[],
                system_prompt: None,
                max_tokens: 1,
                temperature: None,
                force_tool: None,
            })
            .is_err());
        assert!(GeminiAdapter.stream_decoder().is_none());
    }
}
