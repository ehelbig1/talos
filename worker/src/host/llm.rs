//! `llm` (completion) host interface plus shared LLM plumbing: local
//! Ollama client, tier-decision policy, provider key lookup paths,
//! bounded response reads, response parsing, `context-window` token
//! estimation and the standalone `embedding` interface.

use super::*;

/// Cached Ollama base URL (read once from OLLAMA_URL env var).
///
/// MCP-630 (2026-05-12): treat `OLLAMA_URL=""` (a Helm placeholder
/// pattern) as unset and fall through to the in-cluster default. Pre-fix
/// the bare `unwrap_or_else(|_| default)` returned `""`, producing a
/// base-URL-less `format!("{}/v1/chat/completions", "")` that failed at
/// request time with a confusing url-parse error rather than using the
/// default. Sibling to MCP-615/620/621/623 (empty-env-var class). The
/// worker is credential-free and doesn't depend on `talos-config`, so
/// the helper is inlined here.
pub(crate) fn ollama_base_url() -> &'static str {
    static URL: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    URL.get_or_init(|| {
        std::env::var("OLLAMA_URL")
            .ok()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "http://ollama:11434".to_string())
    })
}

/// Dedicated HTTP client for LOCAL LLM-provider calls (Ollama).
///
/// The per-execution `self.http_client` carries the guest SSRF resolver, which
/// filters private/RFC1918 IPs to stop a guest's `http::fetch` from reaching
/// internal services. But the local LLM provider (Ollama) IS an internal service
/// on a private IP (`ollama:11434` → 172.x), so routing the `llm::complete` call
/// through that client makes a Tier-2 actor's local inference fail with
/// "every resolved IP was filtered". The provider URL here is host-configured
/// (`OLLAMA_URL`, fixed), NOT guest-supplied, and the per-provider tier ceiling
/// is already enforced upstream by `decide_llm_tier_access` (Tier-1 ⇒ Ollama
/// only), so this dedicated client safely bypasses the guest SSRF filter for the
/// local provider only. Redirects are disabled so a compromised local endpoint
/// can't bounce the request elsewhere. External providers keep using the
/// SSRF-filtered `self.http_client`.
pub(crate) fn local_llm_http_client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .user_agent("Talos-Worker/1.0")
            .connect_timeout(std::time::Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("worker: failed to build local-LLM reqwest client")
    })
}

#[cfg(test)]
mod response_format_tests {
    use super::build_response_format;

    #[test]
    fn none_yields_json_object_mode() {
        let rf = build_response_format(None).expect("some");
        assert_eq!(rf["type"], "json_object");
    }

    #[test]
    fn valid_schema_yields_json_schema_mode() {
        let schema = r#"{"type":"object","required":["title"]}"#;
        let rf = build_response_format(Some(schema.to_string())).expect("some");
        assert_eq!(rf["type"], "json_schema");
        assert_eq!(rf["json_schema"]["strict"], true);
        assert_eq!(rf["json_schema"]["schema"]["required"][0], "title");
    }

    #[test]
    fn malformed_schema_degrades_to_json_mode_not_error() {
        // A bad schema must never harden into a hard failure on an
        // otherwise-valid completion request.
        for bad in ["not json", "[1,2,3]", "\"a string\"", "42"] {
            let rf = build_response_format(Some(bad.to_string())).expect("some");
            assert_eq!(
                rf["type"], "json_object",
                "malformed/non-object schema {bad:?} should degrade to json_object mode"
            );
        }
    }
}

#[cfg(test)]
mod provider_options_tests {
    use super::apply_provider_options;
    use serde_json::json;

    fn map(v: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn merges_tuning_params() {
        let mut body = json!({"model":"m","messages":[{"role":"user","content":"hi"}]});
        apply_provider_options(
            &mut body,
            map(json!({"seed": 42, "top_p": 0.9, "response_format": {"type":"json_object"}})),
        );
        assert_eq!(body["seed"], 42);
        assert_eq!(body["top_p"], 0.9);
        assert_eq!(body["response_format"]["type"], "json_object");
    }

    #[test]
    fn options_cannot_replace_messages() {
        let mut body = json!({"model":"m","messages":[{"role":"user","content":"REAL prompt"}]});
        apply_provider_options(
            &mut body,
            map(json!({"messages":[{"role":"user","content":"HIJACKED"}]})),
        );
        assert_eq!(
            body["messages"][0]["content"], "REAL prompt",
            "options must not hijack the assembled prompt"
        );
    }

    #[test]
    fn options_cannot_enable_streaming() {
        let mut body = json!({"model":"m","messages":[]});
        apply_provider_options(&mut body, map(json!({"stream": true})));
        assert!(
            body.get("stream").is_none(),
            "stream must be stripped so the single-shot response stays parseable"
        );
    }

    #[test]
    fn anthropic_system_is_preserved() {
        let mut body = json!({"model":"m","system":"REAL system","messages":[]});
        apply_provider_options(&mut body, map(json!({"system":"HIJACKED","top_k":40})));
        assert_eq!(body["system"], "REAL system");
        assert_eq!(body["top_k"], 40);
    }

    #[test]
    fn injected_system_dropped_on_openai_body() {
        // OpenAI-format body has no top-level system; an injected one is
        // dropped (system belongs in the messages array the host built).
        let mut body = json!({"model":"m","messages":[{"role":"system","content":"real"}]});
        apply_provider_options(&mut body, map(json!({"system":"sneaky"})));
        assert!(body.get("system").is_none());
    }
}

#[cfg(test)]
mod llm_tier_decision_tests {
    use super::{decide_llm_tier_access, LlmTierDecision};
    use talos_workflow_job_protocol::LlmTier;

    #[test]
    fn ollama_always_needs_no_key_regardless_of_tier() {
        // Ollama is local — no vault lookup, no tier gate.
        assert_eq!(
            decide_llm_tier_access("ollama", LlmTier::Tier1),
            LlmTierDecision::NoKeyNeeded
        );
        assert_eq!(
            decide_llm_tier_access("ollama", LlmTier::Tier2),
            LlmTierDecision::NoKeyNeeded
        );
    }

    #[test]
    fn tier1_refuses_every_external_provider() {
        // The security contract: a tier-1 ceiling MUST block every
        // non-Ollama provider. Adding a new external provider and
        // forgetting to add a tier check here would regress privacy.
        for provider in ["anthropic", "openai", "gemini", "future-provider"] {
            assert_eq!(
                decide_llm_tier_access(provider, LlmTier::Tier1),
                LlmTierDecision::Refused,
                "tier1 must refuse `{provider}`"
            );
        }
    }

    #[test]
    fn tier2_allows_every_external_provider() {
        for provider in ["anthropic", "openai", "gemini"] {
            assert_eq!(
                decide_llm_tier_access(provider, LlmTier::Tier2),
                LlmTierDecision::Allowed,
                "tier2 must allow `{provider}`"
            );
        }
    }

    #[test]
    fn tier1_blocks_unknown_provider_conservatively() {
        // Unknown providers under tier1 must be refused — `provider_tier`
        // in job-protocol defaults unknown providers to Tier2 (external),
        // so tier-1 actors should never reach them.
        assert_eq!(
            decide_llm_tier_access("cohere", LlmTier::Tier1),
            LlmTierDecision::Refused
        );
    }

    #[test]
    fn default_tier_is_tier2() {
        // Backward-compat default — existing workflows without an
        // explicit ceiling continue to reach external providers.
        let default_tier = LlmTier::default();
        assert_eq!(
            decide_llm_tier_access("anthropic", default_tier),
            LlmTierDecision::Allowed,
            "default tier must allow external providers for backward compat"
        );
    }
}

#[cfg(test)]
mod external_llm_host_tests {
    use talos_workflow_job_protocol::{is_external_llm_host, is_tier2_llm_vault_path};

    #[test]
    fn canonical_llm_hosts_are_blocked() {
        // The C3-bypass closers. If any of these return false, a
        // tier-1 guest reaches that provider via wit_http::fetch and
        // the privacy ceiling is broken.
        for host in [
            "api.anthropic.com",
            "api.openai.com",
            "generativelanguage.googleapis.com",
            "aiplatform.googleapis.com",
        ] {
            assert!(
                is_external_llm_host(host),
                "{host} must be on the external-LLM deny list"
            );
        }
    }

    #[test]
    fn region_subdomains_are_blocked() {
        // Region subdomains (eu.api.openai.com, eu.api.anthropic.com)
        // must also trigger — attackers can use them to reach the
        // same provider via a regional endpoint.
        assert!(is_external_llm_host("eu.api.openai.com"));
        assert!(is_external_llm_host("us-east-1.api.anthropic.com"));
        assert!(is_external_llm_host(
            "us-central1.aiplatform.googleapis.com"
        ));
    }

    #[test]
    fn benign_hosts_are_not_blocked() {
        // Obvious false-positive check — the deny-list must not
        // accidentally catch user APIs.
        for host in [
            "api.example.com",
            "httpbin.org",
            "api.github.com",
            "slack.com",
            "api.notion.com",
        ] {
            assert!(
                !is_external_llm_host(host),
                "{host} must not be on the external-LLM deny list"
            );
        }
    }

    #[test]
    fn case_insensitive_and_trailing_dot_safe() {
        // Wasm-security review 2026-05-23: the helper now normalises
        // both trailing-dot AND case at the matcher entry as
        // defense-in-depth against an upstream caller forgetting
        // to lowercase or strip the dot. Pre-fix the contract was
        // "callers MUST pass lowercased / dot-stripped host";
        // post-fix the contract is "matcher hardens what you give it"
        // — same correctness, smaller surface for upstream regressions.
        assert!(is_external_llm_host("api.anthropic.com"));
        assert!(
            is_external_llm_host("API.ANTHROPIC.COM"),
            "matcher now lowercases internally (defense in depth)"
        );
        assert!(
            is_external_llm_host("api.anthropic.com."),
            "matcher now strips trailing dot (defense in depth)"
        );
        assert!(
            is_external_llm_host("EU.API.OPENAI.COM."),
            "matcher handles uppercase + trailing dot together"
        );
    }

    #[test]
    fn tier2_vault_paths_recognised() {
        // Complements the host-deny-list: the vault:// header path
        // must also refuse external LLM credentials for tier-1 jobs.
        for path in ["anthropic/api_key", "openai/api_key", "gemini/api_key"] {
            assert!(is_tier2_llm_vault_path(path));
        }
        assert!(!is_tier2_llm_vault_path("oauth/gmail/user/access_token"));
        assert!(!is_tier2_llm_vault_path("my-app/secret"));
    }
}

/// MCP-1008 (2026-05-15): saturating u64→u32 conversion for parsing
/// LLM provider `input_tokens` / `output_tokens` fields out of the
/// untrusted response JSON. Same defense-in-depth pattern as MCP-962
/// closed for `workflow_chains` config — the legacy
/// `.as_u64().unwrap_or(0) as u32` shape silently wraps any value
/// above `u32::MAX` (~4.29 billion), producing under-counted token
/// totals in metrics + cost-attribution dashboards.
///
/// A misbehaving / compromised LLM provider returning
/// `input_tokens: 5_000_000_000` would have wrapped to ~705 M tokens,
/// charging the user ~705 M tokens of cost-attribution for a request
/// that actually consumed 5 B. Saturating to `u32::MAX` preserves the
/// "something weird happened" signal — `u32::MAX` in a token-count
/// dashboard is visibly absurd and triggers operator investigation.
///
/// Returns `default` when the JSON field is missing or wrong-typed
/// (preserves the pre-fix behaviour for that case).
pub(crate) fn json_token_count_as_u32(field: Option<&serde_json::Value>, default: u32) -> u32 {
    match field.and_then(|v| v.as_u64()) {
        Some(n) => u32::try_from(n).unwrap_or(u32::MAX),
        None => default,
    }
}

/// MCP-1213 (2026-05-18): bounded-body read for LLM responses.
/// Streams chunks from `response.bytes_stream()` until either the body
/// completes or `max_bytes` is exceeded.  Returns `Some(body_bytes)`
/// on success, `None` if the body exceeds the cap (caller decides how
/// to surface — typically as `ApiError`).
///
/// Pre-fix `response.json()` / `response.text()` had no size limit:
/// a 1 GB body from a misbehaving / compromised provider would buffer
/// in worker memory, OOMing the pod. This helper paired with an
/// outer `tokio::time::timeout` over the WHOLE exchange replaces both
/// `.json()` and `.text()` at the LLM call sites — bytes-then-parse
/// is a wider-net pattern that catches both the size class AND the
/// hang class in a single helper.
pub(crate) async fn read_llm_response_body_bounded(
    response: reqwest::Response,
    max_bytes: usize,
) -> Option<Vec<u8>> {
    use futures_util::StreamExt;
    let content_length = response
        .headers()
        .get(reqwest::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    // Pre-allocate at the smaller of (Content-Length, max_bytes) — saves
    // allocator churn on legitimate responses (typical 1-100 KiB) while
    // refusing to honour a hostile Content-Length larger than the cap.
    let capacity = std::cmp::min(content_length, max_bytes);
    let mut buf = Vec::with_capacity(capacity);
    let mut stream = response.bytes_stream();
    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result.ok()?;
        if buf.len() + chunk.len() > max_bytes {
            tracing::warn!(
                limit = max_bytes,
                buffered = buf.len(),
                chunk_size = chunk.len(),
                "LLM response exceeded size cap; aborting body read"
            );
            return None;
        }
        buf.extend_from_slice(&chunk);
    }
    Some(buf)
}

/// Canonical (vault-path, env-var-name) tuple for each LLM provider.
/// Returns `None` for Ollama (no key required) or unknown providers.
pub(crate) fn llm_key_lookup_paths(provider: &str) -> Option<(&'static str, &'static str)> {
    match provider.to_ascii_lowercase().as_str() {
        "anthropic" => Some(("anthropic/api_key", "ANTHROPIC_API_KEY")),
        "openai" => Some(("openai/api_key", "OPENAI_API_KEY")),
        "gemini" => Some(("gemini/api_key", "GEMINI_API_KEY")),
        _ => None,
    }
}

/// Outcome of the tier-ceiling check for an `llm::*` host call.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LlmTierDecision {
    /// Provider is `ollama` — no key needed, always allowed.
    NoKeyNeeded,
    /// External provider allowed by the ceiling.
    Allowed,
    /// External provider blocked by a Tier-1 ceiling. Caller MUST NOT
    /// resolve any vault or env value for this provider.
    Refused,
}

/// Pure, testable tier check. Returns the decision for `(provider, ceiling)`
/// without touching vault or env. The live `get_llm_api_key` uses this,
/// as do the tier-enforcement tests.
pub(crate) fn decide_llm_tier_access(
    provider_lower: &str,
    ceiling: talos_workflow_job_protocol::LlmTier,
) -> LlmTierDecision {
    if provider_lower == "ollama" {
        return LlmTierDecision::NoKeyNeeded;
    }
    match ceiling {
        talos_workflow_job_protocol::LlmTier::Tier1 => LlmTierDecision::Refused,
        talos_workflow_job_protocol::LlmTier::Tier2 => LlmTierDecision::Allowed,
        // `LlmTier` is `#[non_exhaustive]` upstream. Fail-closed for any
        // future variant — we'd rather refuse than silently allow data
        // egress to a yet-unclassified provider tier.
        _ => LlmTierDecision::Refused,
    }
}

// ============================================================================
// LLM
// ============================================================================

/// Build the OpenAI-compatible `response_format` value for `complete_json`.
///
/// * `None` → JSON mode: `{"type":"json_object"}` — the provider must emit
///   syntactically-valid JSON (any shape).
/// * `Some(schema)` where `schema` parses to a JSON **object** → structured
///   outputs: `{"type":"json_schema","json_schema":{...}}` — the provider
///   constrains generation to that JSON Schema (Ollama/OpenAI).
/// * `Some(malformed)` → degrades to JSON mode rather than failing the call,
///   with a warning. A bad schema should never harden into a hard error on
///   an otherwise-valid completion request.
fn build_response_format(json_schema: Option<String>) -> Option<serde_json::Value> {
    match json_schema {
        None => Some(serde_json::json!({ "type": "json_object" })),
        Some(s) => match serde_json::from_str::<serde_json::Value>(&s) {
            Ok(schema) if schema.is_object() => Some(serde_json::json!({
                "type": "json_schema",
                "json_schema": { "name": "output", "strict": true, "schema": schema }
            })),
            _ => {
                tracing::warn!(
                    "complete_json: json-schema was not a valid JSON object — \
                     falling back to plain JSON mode"
                );
                Some(serde_json::json!({ "type": "json_object" }))
            }
        },
    }
}

/// Merge caller-supplied provider `options` into an already-built request
/// `body`, then re-assert the fields that carry prompt integrity and
/// transport correctness. This is the guardrail behind
/// `llm::complete-with-options`:
///   * Every option key is merged (so callers can add/override tuning
///     params: `seed`, `top_p`, `stop`, `response_format`, penalties, …).
///   * `messages` (OpenAI-format) and `system` (Anthropic) are restored
///     to what the host assembled — options can never replace the
///     SPOTLIGHTING-wrapped prompt. A `system` the caller injected on an
///     OpenAI-format body (where there was none) is dropped.
///   * `stream` is removed unconditionally — the worker parses a single
///     non-streamed response; `stream=true` would make the body
///     unparseable.
/// Pure so the guardrails are unit-tested without a live provider.
fn apply_provider_options(
    body: &mut serde_json::Value,
    opts: serde_json::Map<String, serde_json::Value>,
) {
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
        obj.remove("stream");
    }
}

/// 2026-05-28 audit Perf#1 (H7 sibling): typed projection of an LLM
/// provider response. Deserializing into one of these instead of
/// `serde_json::Value` saves the per-field `HashMap<String, Value>`
/// allocation tree. The two variants match the only two formats the
/// callers branch on (`is_openai_format`).
///
/// Lives at module scope so the structs participate in `#[derive]` —
/// `serde::Deserialize` traits can't be derived inside a function body.
enum LlmResponse {
    OpenAi(OpenAiResponse),
    Anthropic(AnthropicResponse),
}

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
}

#[derive(serde::Deserialize)]
struct OpenAiUsage {
    #[serde(default)]
    prompt_tokens: Option<u64>,
    #[serde(default)]
    completion_tokens: Option<u64>,
}

#[derive(serde::Deserialize)]
struct AnthropicResponse {
    #[serde(default)]
    content: Vec<AnthropicBlock>,
    #[serde(default)]
    usage: Option<AnthropicUsage>,
    #[serde(default)]
    stop_reason: Option<String>,
}

#[derive(serde::Deserialize)]
struct AnthropicBlock {
    /// Renamed because `type` is a Rust keyword.
    #[serde(rename = "type", default)]
    block_type: Option<String>,
    #[serde(default)]
    text: Option<String>,
}

#[derive(serde::Deserialize)]
struct AnthropicUsage {
    #[serde(default)]
    input_tokens: Option<u64>,
    #[serde(default)]
    output_tokens: Option<u64>,
}

impl wit_llm::Host for TalosContext {
    #[::tracing::instrument(name = "llm.complete", skip_all)]
    async fn complete(
        &mut self,
        req: wit_llm::CompletionRequest,
    ) -> Result<wit_llm::CompletionResponse, wit_llm::Error> {
        self.complete_impl(req, None, None).await
    }

    /// Structured-output completion — see the WIT doc on `complete-json`.
    /// `json_schema = None` → JSON mode (valid JSON, any shape);
    /// `Some(schema)` → response constrained to that JSON Schema. The
    /// `response_format` only reaches OpenAI-compatible providers (OpenAI,
    /// Ollama); Anthropic ignores it and behaves like `complete`.
    #[::tracing::instrument(name = "llm.complete_json", skip_all)]
    async fn complete_json(
        &mut self,
        req: wit_llm::CompletionRequest,
        json_schema: Option<String>,
    ) -> Result<wit_llm::CompletionResponse, wit_llm::Error> {
        let response_format = build_response_format(json_schema);
        self.complete_impl(req, response_format, None).await
    }

    /// Flexible provider-feature passthrough — see the WIT doc on
    /// `complete-with-options`. Parses `options` into a JSON object and
    /// merges it into the outbound provider body (guardrailed in
    /// `complete_impl`). A missing/empty `options` is equivalent to
    /// `complete`; a malformed or non-object `options` is a hard
    /// `invalid-request` (the caller set it explicitly and expects it to
    /// apply).
    #[::tracing::instrument(name = "llm.complete_with_options", skip_all)]
    async fn complete_with_options(
        &mut self,
        req: wit_llm::CompletionRequest,
        options: Option<String>,
    ) -> Result<wit_llm::CompletionResponse, wit_llm::Error> {
        let extra = match options {
            None => None,
            Some(s) if s.trim().is_empty() => None,
            Some(s) => {
                if s.len() > MAX_PROVIDER_OPTIONS_BYTES {
                    return Err(wit_llm::Error::InvalidRequest(format!(
                        "provider options exceed {MAX_PROVIDER_OPTIONS_BYTES} bytes"
                    )));
                }
                match serde_json::from_str::<serde_json::Value>(&s) {
                    Ok(v) if v.is_object() => Some(v),
                    _ => {
                        return Err(wit_llm::Error::InvalidRequest(
                            "provider options must be a JSON object".to_string(),
                        ))
                    }
                }
            }
        };
        self.complete_impl(req, None, extra).await
    }
}

impl TalosContext {
    /// Shared completion kernel behind `complete` (no overlay),
    /// `complete_json` (response_format overlay), and
    /// `complete_with_options` (arbitrary provider-options overlay).
    /// Factored so the tier gate, SSRF client selection, timeouts, bounded
    /// body read, and response parsing live in exactly one place.
    ///
    /// `response_format` (worker-built, trusted) is injected only for
    /// OpenAI-compatible providers. `extra_options` (caller-supplied, via
    /// `complete_with_options`) is merged for ALL providers, then the
    /// prompt-integrity + transport guardrails re-assert `messages` /
    /// Anthropic `system` and force non-streaming.
    async fn complete_impl(
        &mut self,
        req: wit_llm::CompletionRequest,
        response_format: Option<serde_json::Value>,
        extra_options: Option<serde_json::Value>,
    ) -> Result<wit_llm::CompletionResponse, wit_llm::Error> {
        // Check cancellation before making an expensive API call.
        if self.is_cancelled() {
            tracing::info!(module_id = ?self.module_id, "Execution cancelled");
            if let Some(ref m) = self.metrics {
                m.record_execution_cancelled();
            }
            return Err(wit_llm::Error::BudgetExhausted);
        }

        let llm_start = std::time::Instant::now();

        // Resolve provider and look up the API key.
        // Ollama (Tier 1) runs locally and needs no API key.
        let provider = req.provider.unwrap_or(wit_llm::Provider::Anthropic);
        let is_local = matches!(provider, wit_llm::Provider::Ollama);

        let api_key = if is_local {
            String::new()
        } else {
            match self.get_llm_api_key(provider).await {
                Some(k) => k,
                None => {
                    let (vault_path, env_name) = match provider {
                        wit_llm::Provider::Anthropic => ("anthropic/api_key", "ANTHROPIC_API_KEY"),
                        wit_llm::Provider::Openai => ("openai/api_key", "OPENAI_API_KEY"),
                        wit_llm::Provider::Gemini => ("gemini/api_key", "GEMINI_API_KEY"),
                        wit_llm::Provider::Ollama => unreachable!(),
                    };
                    let msg = format!(
                        "LLM API key not configured. Set vault path `{}` in the dashboard (Settings → Secrets), \
                         or export {} in the worker environment as a fallback.",
                        vault_path, env_name
                    );
                    tracing::warn!(vault_path, env_name, module_id = ?self.module_id, "{}", msg);
                    return Err(wit_llm::Error::NotConfigured(msg));
                }
            }
        };

        let model = req.model.unwrap_or_else(|| match provider {
            wit_llm::Provider::Anthropic => "claude-sonnet-4-20250514".to_string(),
            wit_llm::Provider::Openai => "gpt-4o".to_string(),
            wit_llm::Provider::Gemini => "gemini-1.5-pro".to_string(),
            wit_llm::Provider::Ollama => "mistral".to_string(),
        });

        // Build the messages array. Anthropic doesn't support "system" as a
        // message role (it uses a top-level field), so System maps to "user".
        // OpenAI/Ollama support "system" as a message role natively.
        let is_openai_format = matches!(
            provider,
            wit_llm::Provider::Openai | wit_llm::Provider::Ollama
        );
        let messages: Vec<serde_json::Value> = req
            .messages
            .iter()
            .map(|msg| {
                let role = match msg.role {
                    wit_llm::Role::System => {
                        if is_openai_format {
                            "system"
                        } else {
                            "user"
                        }
                    }
                    wit_llm::Role::User => "user",
                    wit_llm::Role::Assistant => "assistant",
                };
                serde_json::json!({"role": role, "content": msg.content})
            })
            .collect();

        let mut body = serde_json::json!({
            "model": model,
            "messages": messages,
            "max_tokens": req.max_tokens.unwrap_or(4096),
        });

        if let Some(temp) = req.temperature {
            body["temperature"] = serde_json::json!(temp);
        }
        if let Some(ref sys) = req.system_prompt {
            body["system"] = serde_json::json!(sys);
        }

        // For OpenAI-compatible providers (OpenAI, Ollama), inject system_prompt
        // as a system-role message rather than Anthropic's top-level "system" field.
        if is_openai_format {
            if let Some(ref sys) = req.system_prompt {
                // Prepend system message for OpenAI-format providers
                body.as_object_mut().and_then(|obj| {
                    obj.get_mut("messages").and_then(|m| {
                        m.as_array_mut().map(|arr| {
                            arr.insert(0, serde_json::json!({"role": "system", "content": sys}));
                        })
                    })
                });
                // Remove the Anthropic-style top-level "system" field
                body.as_object_mut().map(|obj| obj.remove("system"));
            }
        }

        // Structured-output constraint (from complete_json). Only OpenAI-
        // compatible providers (OpenAI, Ollama) honor `response_format`;
        // Anthropic ignores it (its request has no such field), so a
        // complete_json call to Anthropic degrades to prompt-only JSON —
        // exactly like `complete`. Ollama's OpenAI-compat endpoint accepts
        // both {"type":"json_object"} and {"type":"json_schema",...}.
        if is_openai_format {
            if let Some(ref rf) = response_format {
                body["response_format"] = rf.clone();
            }
        }

        // Flexible provider-feature passthrough (from complete_with_options).
        // Merge the caller-supplied options object into the body, then
        // re-assert the fields that carry prompt integrity + transport
        // correctness. Net effect: options can only TUNE the request (seed,
        // top_p, stop, response_format, penalties, …) — they can never
        // replace the SPOTLIGHTING-wrapped prompt or switch on streaming
        // (which would make the single-shot response body unparseable).
        // Auth + URL live in headers / worker config and are never in the
        // body, so options can't reach them.
        if let Some(serde_json::Value::Object(opts)) = extra_options {
            apply_provider_options(&mut body, opts);
        }

        let ollama_url = ollama_base_url();

        let (url, auth_header, auth_value) = match provider {
            wit_llm::Provider::Anthropic => (
                "https://api.anthropic.com/v1/messages".to_string(),
                "x-api-key",
                api_key,
            ),
            wit_llm::Provider::Openai => (
                "https://api.openai.com/v1/chat/completions".to_string(),
                "Authorization",
                format!("Bearer {}", api_key),
            ),
            wit_llm::Provider::Gemini => (
                "https://generativelanguage.googleapis.com/v1beta/models".to_string(),
                "x-goog-api-key",
                api_key,
            ),
            wit_llm::Provider::Ollama => (
                format!("{}/v1/chat/completions", ollama_url),
                "", // no auth header
                String::new(),
            ),
        };

        let body_bytes = serde_json::to_vec(&body).map_err(|e| {
            wit_llm::Error::InvalidRequest(format!("Failed to serialize request body: {e}"))
        })?;

        let provider_label = match provider {
            wit_llm::Provider::Anthropic => "anthropic",
            wit_llm::Provider::Openai => "openai",
            wit_llm::Provider::Gemini => "gemini",
            wit_llm::Provider::Ollama => "ollama",
        };
        tracing::info!(
            module_id = ?self.module_id,
            model = %model,
            provider = provider_label,
            message_count = req.messages.len(),
            "LLM completion request"
        );

        // Local provider (Ollama) bypasses the guest SSRF resolver — see
        // local_llm_http_client(). External providers keep the SSRF-filtered
        // per-execution client (public IPs, retains the guest egress gate).
        let client = if is_local {
            local_llm_http_client().clone()
        } else {
            self.http_client.clone()
        };
        // MCP-1213 (2026-05-18): one timeout for the FULL exchange
        // (send + body read), not just `.send()`. Pre-fix the outer
        // timeout wrapped only header receipt — once headers arrived,
        // `.json()` / `.text()` could hang indefinitely on a slow
        // body stream. Real prod symptom: daily-brief synthesize hung
        // 5+ minutes after the MCP-1212 re-sign fix unmasked it.
        let timeout_secs: u64 = if is_local {
            LOCAL_LLM_EXCHANGE_TIMEOUT_SECS
        } else {
            EXTERNAL_LLM_EXCHANGE_TIMEOUT_SECS
        };
        let mut http_req = client.post(&url).header("Content-Type", "application/json");
        if !auth_header.is_empty() {
            http_req = http_req.header(auth_header, &auth_value);
        }
        if matches!(provider, wit_llm::Provider::Anthropic) {
            http_req = http_req.header("anthropic-version", "2023-06-01");
        }
        let resp_body: LlmResponse = tokio::time::timeout(
            std::time::Duration::from_secs(timeout_secs),
            async move {
                let response = http_req
                    .body(body_bytes)
                    .send()
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, provider = provider_label, "LLM API request failed");
                        wit_llm::Error::ApiError(format!("Network error: {e}"))
                    })?;

                if !response.status().is_success() {
                    let status = response.status().as_u16();
                    tracing::warn!(status, "LLM API returned error status");
                    if status == 429 {
                        return Err(wit_llm::Error::RateLimited);
                    }
                    // MCP-528 + MCP-1213: DLP-scrub the body preview AND
                    // bound it by MAX_LLM_BODY_BYTES. Pre-fix `.text()`
                    // had no size limit — a misbehaving provider could
                    // stream multi-GB error bodies into worker memory.
                    let preview_bytes = read_llm_response_body_bounded(
                        response,
                        MAX_LLM_BODY_BYTES,
                    )
                    .await
                    .unwrap_or_default();
                    let body_preview = String::from_utf8_lossy(&preview_bytes);
                    let preview_truncated: String =
                        body_preview.chars().take(500).collect();
                    let preview_redacted =
                        talos_dlp_provider::redact_str(&preview_truncated);
                    tracing::warn!(
                        status,
                        body_len = preview_bytes.len(),
                        body_preview = %preview_redacted,
                        "LLM API returned error"
                    );
                    return Err(wit_llm::Error::ApiError(format!(
                        "LLM API returned HTTP {status}"
                    )));
                }

                // MCP-1213: bounded streaming body read + parse, NOT
                // unbounded `.json()`. Caps response at MAX_LLM_BODY_BYTES.
                let body_bytes = read_llm_response_body_bounded(
                    response,
                    MAX_LLM_BODY_BYTES,
                )
                .await
                .ok_or_else(|| {
                    wit_llm::Error::ApiError(format!(
                        "LLM response exceeded {} bytes; aborted body read",
                        MAX_LLM_BODY_BYTES
                    ))
                })?;
                // 2026-05-28 audit Perf#1: H7 sibling. Pre-fix this
                // materialised the full `serde_json::Value` tree only
                // to pluck 3-5 fields per branch. Now we deserialize
                // into format-specific typed structs — serde only
                // allocates the strings we actually use, skipping the
                // `HashMap<String, Value>` tree for every other field
                // in the provider response. The two structs match the
                // exact shape consumed below.
                //
                // OpenAI/Ollama:
                //   { choices: [{ message: { content: "..." },
                //                 finish_reason: "..." }],
                //     usage: { prompt_tokens, completion_tokens } }
                // Anthropic/Gemini:
                //   { content: [{ type: "text", text: "..." }, ...],
                //     usage: { input_tokens, output_tokens },
                //     stop_reason: "..." }
                //
                // The format-divergent shapes return as enum variants
                // so the extraction logic below stays
                // strongly-typed instead of `get("...").and_then(...)`
                // chains over `Value`.
                if is_openai_format {
                    serde_json::from_slice::<OpenAiResponse>(&body_bytes)
                        .map(LlmResponse::OpenAi)
                        .map_err(|e| {
                            wit_llm::Error::ApiError(format!(
                                "Failed to parse OpenAI-format response: {e}"
                            ))
                        })
                } else {
                    serde_json::from_slice::<AnthropicResponse>(&body_bytes)
                        .map(LlmResponse::Anthropic)
                        .map_err(|e| {
                            wit_llm::Error::ApiError(format!(
                                "Failed to parse Anthropic-format response: {e}"
                            ))
                        })
                }
            },
        )
        .await
        .map_err(|_| wit_llm::Error::Timeout)??;

        // Extract text + usage + stop_reason from the typed response.
        let (text, usage, stop_reason) = match resp_body {
            LlmResponse::OpenAi(r) => {
                let text = r
                    .choices
                    .first()
                    .and_then(|c| c.message.as_ref())
                    .and_then(|m| m.content.clone())
                    .unwrap_or_default();
                let usage = r.usage.map(|u| wit_llm::TokenUsage {
                    // MCP-1008: saturate-on-overflow to surface
                    // malicious / corrupted provider responses as
                    // visible spikes.
                    input_tokens: u32::try_from(u.prompt_tokens.unwrap_or(0)).unwrap_or(u32::MAX),
                    output_tokens: u32::try_from(u.completion_tokens.unwrap_or(0))
                        .unwrap_or(u32::MAX),
                });
                let stop_reason = r.choices.into_iter().next().and_then(|c| c.finish_reason);
                (text, usage, stop_reason)
            }
            LlmResponse::Anthropic(r) => {
                let text = r
                    .content
                    .iter()
                    .filter(|b| b.block_type.as_deref() == Some("text"))
                    .filter_map(|b| b.text.as_deref())
                    .collect::<Vec<_>>()
                    .join("");
                let usage = r.usage.map(|u| wit_llm::TokenUsage {
                    // MCP-1008: saturate-on-overflow.
                    input_tokens: u32::try_from(u.input_tokens.unwrap_or(0)).unwrap_or(u32::MAX),
                    output_tokens: u32::try_from(u.output_tokens.unwrap_or(0)).unwrap_or(u32::MAX),
                });
                (text, usage, r.stop_reason)
            }
        };
        if let Some(ref m) = self.metrics {
            let duration_ms = llm_start.elapsed().as_millis() as f64;
            m.record_llm_request(provider_label, duration_ms);
            if let Some(ref u) = usage {
                m.record_llm_tokens("input", u.input_tokens as u64);
                m.record_llm_tokens("output", u.output_tokens as u64);
            }
        }

        Ok(wit_llm::CompletionResponse {
            text,
            model,
            usage,
            stop_reason,
        })
    }
}

// ============================================================================
// Context Window (token estimation)
// ============================================================================

impl wit_context_window::Host for TalosContext {
    async fn estimate_tokens(&mut self, text: String, model: Option<String>) -> u32 {
        // Model-aware token estimation using character-class heuristics.
        // More accurate than naive len/4 -- handles code, CJK, and whitespace.

        let model_name = model.as_deref().unwrap_or("claude-sonnet-4-20250514");

        // Count different character classes for weighted estimation
        let mut ascii_words = 0u32;
        let mut cjk_chars = 0u32;
        let mut code_tokens = 0u32;
        let mut other_chars = 0u32;
        let mut in_word = false;

        for ch in text.chars() {
            if ch.is_ascii_whitespace() {
                if in_word {
                    ascii_words += 1;
                    in_word = false;
                }
            } else if ch.is_ascii_alphanumeric() {
                in_word = true;
            } else if ('\u{4e00}'..='\u{9fff}').contains(&ch)
                || ('\u{3400}'..='\u{4dbf}').contains(&ch)
            {
                // CJK characters: roughly 1 token each
                cjk_chars += 1;
                if in_word {
                    ascii_words += 1;
                    in_word = false;
                }
            } else if "{}[]()=><;:,.!?+-*/&|^~#@$%\\\"'`".contains(ch) {
                code_tokens += 1;
                if in_word {
                    ascii_words += 1;
                    in_word = false;
                }
            } else {
                other_chars += 1;
            }
        }
        if in_word {
            ascii_words += 1;
        }

        // Weighted estimation:
        // - English words: ~1.3 tokens per word (BPE splits some words)
        // - CJK characters: ~1 token each
        // - Code punctuation: ~1 token per 1-2 chars
        // - Other: ~0.5 tokens per char
        let estimate = (ascii_words as f64 * 1.3)
            + (cjk_chars as f64)
            + (code_tokens as f64 * 0.7)
            + (other_chars as f64 * 0.5);

        // Apply model-specific multiplier (GPT models tokenize slightly differently)
        let multiplier = if model_name.contains("gpt") { 1.1 } else { 1.0 };

        (estimate * multiplier).ceil() as u32
    }

    async fn get_context_info(&mut self, model: Option<String>) -> wit_context_window::ContextInfo {
        let model_name = model.as_deref().unwrap_or("claude-sonnet-4-20250514");

        // Model-specific context windows
        let max_tokens = if model_name.contains("claude-3")
            || model_name.contains("claude-sonnet-4")
            || model_name.contains("claude-opus-4")
        {
            200_000
        } else if model_name.contains("gpt-4o") || model_name.contains("gpt-4-turbo") {
            128_000
        } else if model_name.contains("gpt-4") {
            8_192
        } else if model_name.contains("gpt-3.5") {
            16_385
        } else if model_name.contains("gemini-1.5-pro") {
            2_097_152 // 2M tokens
        } else if model_name.contains("gemini") {
            1_048_576
        } else {
            200_000 // default to Claude
        };

        wit_context_window::ContextInfo {
            max_tokens,
            used_tokens: 0, // Would need conversation tracking to be accurate
            available_tokens: max_tokens,
        }
    }
}

// ============================================================================
// Embedding (standalone vector generation via OpenAI API)
// ============================================================================

impl wit_embedding::Host for TalosContext {
    async fn generate(
        &mut self,
        text: String,
        model: Option<String>,
    ) -> Result<Vec<f32>, wit_embedding::Error> {
        if self.is_cancelled() {
            return Err(wit_embedding::Error::BudgetExhausted);
        }
        use crate::wit_inspector::CapabilityWorld;
        if !matches!(
            self.capability_world,
            CapabilityWorld::Secrets
                | CapabilityWorld::Database
                | CapabilityWorld::Agent
                | CapabilityWorld::Trusted
        ) {
            // MCP-697 (2026-05-13): audit-ledger parity. The Tier-1 LLM-egress
            // denial branch below (MCP-687) audits via record_capability_denied;
            // capability-world denial was silent. Probing the embedding
            // surface from Minimal world should leave a WORM trail.
            self.record_capability_denied(
                "wit_embedding::generate",
                "capability-world",
                model.as_deref().unwrap_or(""),
            )
            .await;
            return Err(wit_embedding::Error::NotConfigured(
                "Embedding requires secrets-node or higher capability world".into(),
            ));
        }

        // MCP-687 (2026-05-13): defense-in-depth Tier-1 surface. Pre-fix
        // the only barrier was `get_llm_api_key_by_name("openai")`
        // returning None on Tier-1; a future regression that lets a key
        // leak through would silently POST the prompt to api.openai.com
        // because this function bypasses `wit_http::fetch` (the
        // documented 3rd of five Tier-1 surfaces) and uses
        // `self.http_client` directly. The function IS an LLM-egress
        // surface — it makes outbound POSTs to api.openai.com with the
        // caller's `text` as the body — so the Tier-1 ceiling MUST be
        // enforced here independently, the same shape as
        // `wit_http_stream::connect` (5th surface, line ~8341) and
        // `wit_webhook::send` / `wit_graphql::execute`. CLAUDE.md's
        // "Five enforcement surfaces" enumeration should be amended to
        // include `wit_embedding::generate` as the sixth surface (and
        // any future wit_embedding methods that add new providers).
        if matches!(
            self.max_llm_tier,
            talos_workflow_job_protocol::LlmTier::Tier1
        ) {
            self.record_capability_denied(
                "wit_embedding::generate",
                "tier1-llm-egress",
                "api.openai.com",
            )
            .await;
            tracing::warn!(
                actor_id = ?self.actor_id,
                "tier-1 actor attempted wit_embedding::generate; refused (external LLM-host egress)"
            );
            return Err(wit_embedding::Error::NotConfigured(
                "Tier-1 actors cannot use external embedding providers. \
                 Reconfigure the actor with `max_llm_tier=tier2` or run \
                 embeddings via a local-only provider in a future release."
                    .into(),
            ));
        }

        // MCP-585: cap caller-supplied text size BEFORE building the
        // outbound JSON body. Pre-fix the input was unbounded; a
        // module could ship a 100 MB string through the worker's
        // outbound network buffer (plus a serde_json clone for the
        // body) before the upstream OpenAI API returned 400 for
        // exceeding its 8192-token limit. The 64 KiB cap above
        // already covers worst-case multi-byte UTF-8 input that
        // still falls within the model's token window.
        if text.len() > MAX_EMBEDDING_TEXT_BYTES {
            tracing::warn!(
                module_id = ?self.module_id,
                bytes = text.len(),
                cap = MAX_EMBEDDING_TEXT_BYTES,
                "wit_embedding::generate text exceeds size cap; refusing before outbound dispatch"
            );
            return Err(wit_embedding::Error::ApiError(format!(
                "Embedding input text exceeds {MAX_EMBEDDING_TEXT_BYTES}-byte cap"
            )));
        }

        let api_key = match self.get_llm_api_key_by_name("openai").await {
            Some(k) => k,
            None => {
                return Err(wit_embedding::Error::NotConfigured(
                    "OpenAI API key not configured. Set vault path `openai/api_key` in \
                     the dashboard (Settings → Secrets), or export OPENAI_API_KEY in the \
                     worker environment as a fallback."
                        .into(),
                ));
            }
        };

        let model_name = model.unwrap_or_else(|| "text-embedding-3-small".to_string());
        let body = serde_json::json!({
            "model": model_name,
            "input": text,
        });

        let client = self.http_client.clone();
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            client
                .post("https://api.openai.com/v1/embeddings")
                .header("Authorization", format!("Bearer {}", api_key))
                .header("Content-Type", "application/json")
                .json(&body)
                .send(),
        )
        .await
        .map_err(|_| wit_embedding::Error::ApiError("Embedding request timed out".into()))?
        .map_err(|e| wit_embedding::Error::ApiError(format!("Network error: {e}")))?;

        let status = response.status().as_u16();
        if status == 429 {
            return Err(wit_embedding::Error::RateLimited);
        }
        if !response.status().is_success() {
            tracing::warn!(status, "Embedding API returned error");
            return Err(wit_embedding::Error::ApiError(format!(
                "Embedding API returned HTTP {status}"
            )));
        }

        // MCP-1213 sibling: bounded streaming body read + parse, NOT
        // unbounded `.json()`. This was the last uncapped outbound `.json()`
        // in the worker — same OOM class the LLM completion path closed.
        // OpenAI is a trusted endpoint, but a compromised/MITM'd upstream or
        // an upstream bug returning a 1 GB body would buffer in worker memory
        // and OOM the pod; the cap is defense-in-depth on a hardcoded host.
        let body_bytes = read_llm_response_body_bounded(response, MAX_LLM_BODY_BYTES)
            .await
            .ok_or_else(|| {
                wit_embedding::Error::ApiError(format!(
                    "Embedding response exceeded {MAX_LLM_BODY_BYTES} bytes; aborted body read"
                ))
            })?;
        let resp_body: serde_json::Value = serde_json::from_slice(&body_bytes).map_err(|e| {
            wit_embedding::Error::ApiError(format!("Failed to parse response: {e}"))
        })?;

        let embedding = resp_body
            .get("data")
            .and_then(|d| d.get(0))
            .and_then(|e| e.get("embedding"))
            .and_then(|v| v.as_array())
            .ok_or_else(|| {
                wit_embedding::Error::ApiError("Missing embedding in response".into())
            })?;

        let vec: Vec<f32> = embedding
            .iter()
            .filter_map(|v| v.as_f64().map(|f| f as f32))
            .collect();

        if vec.is_empty() {
            return Err(wit_embedding::Error::ApiError(
                "Empty embedding vector returned".into(),
            ));
        }

        Ok(vec)
    }
}

#[cfg(test)]
mod llm_response_parse_tests {
    //! 2026-05-28 audit Perf#1: typed-deserialize parser tests.
    //!
    //! Pre-fix the LLM response materialised into `serde_json::Value`
    //! and the consumers did `get("...").and_then(...)` chains over
    //! it. Post-fix the response goes through `OpenAiResponse` /
    //! `AnthropicResponse` typed structs. These tests pin the field-
    //! extraction contract end-to-end so a future refactor can't
    //! regress the field plucking that the LLM hot path depends on.

    use super::{AnthropicResponse, OpenAiResponse};

    #[test]
    fn openai_response_pulls_content_and_usage() {
        let body = br#"{
            "id": "chat-1",
            "object": "chat.completion",
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "hello world"
                },
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": 12,
                "completion_tokens": 25,
                "total_tokens": 37
            }
        }"#;
        let r: OpenAiResponse = serde_json::from_slice(body).expect("parse");
        let choice = &r.choices[0];
        assert_eq!(
            choice.message.as_ref().unwrap().content.as_deref(),
            Some("hello world")
        );
        assert_eq!(choice.finish_reason.as_deref(), Some("stop"));
        let u = r.usage.unwrap();
        assert_eq!(u.prompt_tokens, Some(12));
        assert_eq!(u.completion_tokens, Some(25));
    }

    #[test]
    fn openai_response_handles_missing_usage() {
        // Providers sometimes omit `usage` on streaming or error
        // responses. Parser must accept this without panicking.
        let body = br#"{
            "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]
        }"#;
        let r: OpenAiResponse = serde_json::from_slice(body).expect("parse");
        assert!(r.usage.is_none());
        assert_eq!(
            r.choices[0].message.as_ref().unwrap().content.as_deref(),
            Some("ok")
        );
    }

    #[test]
    fn openai_response_handles_empty_choices() {
        // Some Ollama wrappers return `{"choices": []}` on rate limit
        // or model-not-found. Parser must accept; downstream code
        // surfaces empty text.
        let body = br#"{"choices": []}"#;
        let r: OpenAiResponse = serde_json::from_slice(body).expect("parse");
        assert!(r.choices.is_empty());
        assert!(r.usage.is_none());
    }

    #[test]
    fn openai_response_ignores_unknown_fields() {
        // Providers add fields over time (e.g., `system_fingerprint`).
        // Parser must not break on unknown keys.
        let body = br#"{
            "choices": [{"message": {"content": "x"}}],
            "system_fingerprint": "fp_abc",
            "logprobs": null,
            "x_some_future_field": {"nested": "value"}
        }"#;
        let r: OpenAiResponse = serde_json::from_slice(body).expect("parse");
        assert_eq!(
            r.choices[0].message.as_ref().unwrap().content.as_deref(),
            Some("x")
        );
    }

    #[test]
    fn anthropic_response_pulls_text_blocks() {
        let body = br#"{
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "content": [
                {"type": "text", "text": "hello "},
                {"type": "text", "text": "world"}
            ],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 7, "output_tokens": 3}
        }"#;
        let r: AnthropicResponse = serde_json::from_slice(body).expect("parse");
        assert_eq!(r.stop_reason.as_deref(), Some("end_turn"));
        let u = r.usage.unwrap();
        assert_eq!(u.input_tokens, Some(7));
        assert_eq!(u.output_tokens, Some(3));
        // Match the post-fix join: filter for `type == "text"` then
        // concatenate `.text`.
        let joined: String = r
            .content
            .iter()
            .filter(|b| b.block_type.as_deref() == Some("text"))
            .filter_map(|b| b.text.as_deref())
            .collect::<Vec<_>>()
            .join("");
        assert_eq!(joined, "hello world");
    }

    #[test]
    fn anthropic_response_ignores_non_text_blocks() {
        // Future Anthropic responses may include `tool_use`,
        // `image`, etc. blocks. Parser must skip them when
        // extracting text — matches the post-fix filter.
        let body = br#"{
            "content": [
                {"type": "tool_use", "name": "calculator", "input": {}},
                {"type": "text", "text": "the answer is 42"}
            ]
        }"#;
        let r: AnthropicResponse = serde_json::from_slice(body).expect("parse");
        let joined: String = r
            .content
            .iter()
            .filter(|b| b.block_type.as_deref() == Some("text"))
            .filter_map(|b| b.text.as_deref())
            .collect::<Vec<_>>()
            .join("");
        assert_eq!(joined, "the answer is 42");
    }

    #[test]
    fn anthropic_response_handles_missing_optional_fields() {
        // Minimal valid response.
        let body = br#"{"content": []}"#;
        let r: AnthropicResponse = serde_json::from_slice(body).expect("parse");
        assert!(r.content.is_empty());
        assert!(r.usage.is_none());
        assert!(r.stop_reason.is_none());
    }

    #[test]
    fn token_count_saturates_on_overflow() {
        // Direct integer larger than u32::MAX should deserialize
        // into u64 cleanly. The post-fix saturating cast to u32 in
        // the host_impl extraction is tested at the call site; here
        // we just confirm the typed field accepts the full u64.
        let body = br#"{"usage": {"prompt_tokens": 5000000000, "completion_tokens": 1}}"#;
        let r: OpenAiResponse = serde_json::from_slice(body).expect("parse");
        let u = r.usage.unwrap();
        assert_eq!(u.prompt_tokens, Some(5_000_000_000));
        // The saturating-cast logic lives in the call site:
        let saturated = u32::try_from(u.prompt_tokens.unwrap_or(0)).unwrap_or(u32::MAX);
        assert_eq!(saturated, u32::MAX);
    }

    #[test]
    fn token_count_handles_missing_with_default() {
        // Older Ollama versions omit `usage` entirely; the
        // call-site `.unwrap_or(0)` then `u32::try_from` produces 0.
        let body = br#"{"usage": {}}"#;
        let r: OpenAiResponse = serde_json::from_slice(body).expect("parse");
        let u = r.usage.unwrap();
        assert_eq!(u.prompt_tokens, None);
        assert_eq!(u.completion_tokens, None);
    }
}
