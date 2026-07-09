//! Per-provider LLM wire-format adapters.
//!
//! Each provider with its own API gets DEDICATED logic behind one trait;
//! everything security-relevant that is provider-INDEPENDENT (tier gate,
//! key resolution, SSRF client selection, exchange timeouts, bounded body
//! reads, stream buffer caps) stays in the host interface files
//! (`llm.rs`, `llm_tools.rs`, `llm_streaming.rs`) exactly where it was —
//! adapters are PURE (no I/O, no `TalosContext`), so every wire format is
//! unit-testable against captured fixtures without a live provider.
//!
//! History (2026-07-09): before this module every provider was funneled
//! through ONE Anthropic-shaped body builder + a two-way
//! `is_openai_format` parse branch. That worked for plain completions on
//! Anthropic/OpenAI/Ollama-compat, but tools + streaming silently sent
//! Anthropic wire shapes to OpenAI-compatible endpoints (no tool ever
//! parsed back; no stream delta ever decoded), and Gemini received
//! Anthropic bodies on a Gemini URL. Ollama now speaks its NATIVE
//! `/api/chat` (first-class `think`, `format`, `options.num_ctx`,
//! `keep_alive` — none of which the OpenAI-compat shim honors; the
//! compat `think` gap produced 65s thinking runs that blew the 60s
//! local-LLM exchange timeout).

pub(crate) mod anthropic;
pub(crate) mod gemini;
pub(crate) mod ollama;
pub(crate) mod openai;

/// Role of a canonical chat message. Adapters own the mapping to their
/// wire role strings (e.g. Anthropic has no `system` role — it maps to
/// `user` + a top-level `system` field; Gemini calls the assistant
/// `model`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ChatRole {
    System,
    User,
    Assistant,
}

/// One canonical text message, provider-independent.
#[derive(Clone, Debug)]
pub(crate) struct ChatMessage {
    pub role: ChatRole,
    pub content: String,
}

/// Canonical completion request assembled by the WIT host layer.
pub(crate) struct CompletionParams<'a> {
    pub model: &'a str,
    pub messages: &'a [ChatMessage],
    pub system_prompt: Option<&'a str>,
    pub max_tokens: u32,
    pub temperature: Option<f32>,
}

/// Parsed provider response, normalized. Token counts stay `u64` here;
/// the WIT boundary saturates to `u32` (MCP-1008) in the host layer.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct ParsedCompletion {
    pub text: String,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub stop_reason: Option<String>,
}

/// One tool definition, canonical (name + description + JSON Schema for
/// the input). The schema arrives as a pre-parsed `Value` so adapters
/// don't each re-parse the caller string.
pub(crate) struct ToolDef<'a> {
    pub name: &'a str,
    pub description: &'a str,
    pub input_schema: serde_json::Value,
}

/// Canonical rich content block for the tools path (subset of the WIT
/// `content-block` variant that crosses provider wires).
pub(crate) enum ToolContentBlock {
    Text(String),
    /// A tool call the ASSISTANT made earlier in the conversation.
    /// `arguments` is the raw JSON string form (WIT-side canonical).
    ToolUse {
        call_id: String,
        tool_name: String,
        arguments: String,
    },
    /// The result the runtime produced for an earlier tool call.
    ToolResult {
        call_id: String,
        output: String,
        is_error: bool,
    },
    Image {
        media_type: String,
        data: String,
    },
}

/// One rich message on the tools path.
pub(crate) struct ToolMessage {
    pub role: ChatRole,
    /// `true` when this message carries tool RESULTS (WIT `Role::Tool`) —
    /// OpenAI-format wires need it split into `role:"tool"` messages while
    /// Anthropic keeps it a `user` message of `tool_result` blocks.
    pub is_tool_result_turn: bool,
    pub content: Vec<ToolContentBlock>,
}

/// Canonical tools-path request.
pub(crate) struct ToolCompletionParams<'a> {
    pub model: &'a str,
    pub messages: &'a [ToolMessage],
    pub tools: &'a [ToolDef<'a>],
    pub system_prompt: Option<&'a str>,
    pub max_tokens: u32,
    pub temperature: Option<f32>,
    pub force_tool: Option<&'a str>,
}

/// Normalized tools-path response block. `arguments` is ALWAYS the JSON
/// string form — the native-Ollama wire returns an object and its adapter
/// re-serializes, so the WIT surface never notices the difference.
#[derive(Debug, PartialEq)]
pub(crate) enum ParsedToolBlock {
    Text(String),
    ToolUse {
        call_id: String,
        tool_name: String,
        arguments: String,
    },
}

#[derive(Debug, Default)]
pub(crate) struct ParsedToolCompletion {
    pub blocks: Vec<ParsedToolBlock>,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub stop_reason: Option<String>,
}

/// Provider-independent internal stream event, produced by per-provider
/// `StreamDecoder`s and consumed by the shared spawn loop in
/// `llm_streaming.rs` (which owns the channel, caps and timeouts).
#[derive(Debug, PartialEq)]
pub(crate) enum StreamEventOut {
    TextDelta(String),
    ToolCall {
        call_id: String,
        tool_name: String,
        /// JSON string form (see `ParsedToolBlock::arguments`).
        arguments: String,
    },
    Usage {
        input_tokens: u64,
        output_tokens: u64,
    },
    /// Stream finished cleanly; payload is the stop reason.
    Done(String),
}

/// Stateful per-stream line decoder. The shared reader loop splits the
/// byte stream into lines (with the MCP-1113 buffer caps) and feeds each
/// COMPLETE line here; the decoder owns the wire framing — SSE `data: `
/// prefixes for Anthropic/OpenAI, bare JSONL for native Ollama.
///
/// Returning `Done` stops the loop; the decoder must also tolerate
/// trailing lines after `Done` (providers may flush more bytes).
pub(crate) trait StreamDecoder: Send {
    fn feed_line(&mut self, line: &str, out: &mut Vec<StreamEventOut>);
}

/// The per-provider wire-format adapter. Implementations MUST stay pure:
/// body building and response parsing only — no network, no secrets, no
/// context. That keeps the guardrail surface reviewable in one place and
/// the formats testable from fixtures.
pub(crate) trait ProviderAdapter: Send + Sync {
    /// Canonical lowercase provider label (metrics, logs).
    fn name(&self) -> &'static str;

    /// Local providers bypass the guest SSRF resolver and use the
    /// shorter `LOCAL_LLM_EXCHANGE_TIMEOUT_SECS` (see `llm.rs`).
    fn is_local(&self) -> bool {
        false
    }

    /// Endpoint for a (non-streaming) completion. `model` participates
    /// only for providers that encode it in the path (Gemini).
    fn completion_url(&self, model: &str) -> String;

    /// Endpoint for a streaming completion. Defaults to the completion
    /// URL; Gemini would differ (`:streamGenerateContent`) when
    /// implemented.
    fn stream_url(&self, model: &str) -> String {
        self.completion_url(model)
    }

    /// Auth (and protocol-version) headers. Empty for local providers.
    /// Header VALUES may embed the key — callers must never log them.
    fn auth_headers(&self, api_key: &str) -> Vec<(&'static str, String)>;

    /// Build the full non-streaming completion body.
    fn build_completion_body(&self, p: &CompletionParams) -> serde_json::Value;

    /// Constrain the response to JSON (`schema = None` → any-shape JSON
    /// mode; `Some` → that JSON Schema). Providers without a structured-
    /// output knob leave the body unchanged (prompt-level JSON only).
    fn apply_response_format(&self, body: &mut serde_json::Value, json_schema: Option<&str>);

    /// Merge caller-supplied provider options (from
    /// `llm::complete-with-options`) into the body, then RE-ASSERT the
    /// prompt-integrity + transport guardrails: the message payload the
    /// host assembled always wins, and streaming is forced OFF (the
    /// non-streaming exchange parses a single JSON body). Provider-
    /// specific: adapters translate option spellings native to their API
    /// (see `ollama.rs` for the compat→native remap).
    fn apply_provider_options(
        &self,
        body: &mut serde_json::Value,
        opts: serde_json::Map<String, serde_json::Value>,
    );

    /// Parse a completion response body. `Err` is a plain description —
    /// the host layer wraps it into the WIT error type (and never leaks
    /// raw bodies to guests).
    fn parse_completion(&self, bytes: &[u8]) -> Result<ParsedCompletion, String>;

    /// Build the tools-path body. `Err` when the provider has no
    /// functional tools wire yet (Gemini).
    fn build_tools_body(&self, p: &ToolCompletionParams) -> Result<serde_json::Value, String>;

    /// Parse a tools-path response.
    fn parse_tool_completion(&self, bytes: &[u8]) -> Result<ParsedToolCompletion, String>;

    /// Build a streaming body from caller-shaped `messages`/`tools` JSON
    /// (the WIT streaming surface passes raw JSON strings through).
    /// `Err` when streaming is not supported for this provider.
    fn build_stream_body(
        &self,
        model: &str,
        messages: serde_json::Value,
        tools: Option<serde_json::Value>,
        system_prompt: Option<&str>,
        max_tokens: u32,
        temperature: Option<f32>,
    ) -> Result<serde_json::Value, String>;

    /// Fresh per-stream decoder. `None` when streaming is unsupported.
    fn stream_decoder(&self) -> Option<Box<dyn StreamDecoder>>;
}

/// Resolve an adapter from the canonical provider label. Unknown labels
/// fall back to Anthropic, matching the historical
/// `req.provider.unwrap_or(Anthropic)` default across all three WIT
/// surfaces.
pub(crate) fn adapter_for(name: &str) -> &'static dyn ProviderAdapter {
    match name {
        "openai" => &openai::OpenAiAdapter,
        "ollama" => &ollama::OllamaAdapter,
        "gemini" => &gemini::GeminiAdapter,
        _ => &anthropic::AnthropicAdapter,
    }
}
