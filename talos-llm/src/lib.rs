use anyhow::{anyhow, Result};
use reqwest::Client;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, warn};
use zeroize::Zeroizing;

pub mod usage;

// ── HTTP timeouts ────────────────────────────────────────────────────
//
// These three values were previously hardcoded as bare `Duration::from_secs(30/60/600)`
// at three different sites in this file. Naming them makes it obvious to
// an operator tuning latency budgets which knob covers which path, and a
// future change won't drift one site out of sync with the others.

/// Anthropic / external-LLM HTTP client default timeout. Covers a single
/// completion call including connect + body. Anthropic typically responds
/// in 1–10 s for a paragraph and up to 30 s for very long completions;
/// 30 s is the practical 99th-percentile ceiling.
const ANTHROPIC_HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Default Ollama HTTP client timeout for completions. Local Ollama is
/// fast on a warm model (sub-second) but a cold-start with a 7B+ model
/// can take 20–40 s while the model loads into VRAM. 60 s gives headroom
/// without masking an actually-stuck call.
const OLLAMA_HTTP_TIMEOUT: Duration = Duration::from_secs(60);

/// Per-request override for `ollama pull` — model downloads are 0.5–8 GB
/// and can take minutes on a cold registry. 10 minutes is the longest a
/// reasonable model pull should ever need; anything beyond is almost
/// certainly a stuck network rather than legitimate progress.
const OLLAMA_PULL_TIMEOUT: Duration = Duration::from_secs(600);

/// Source of the Anthropic API key used by [`LlmClient`].
///
/// The controller has two legitimate sources: the vault (user-rotatable,
/// audited, matches the worker's LLM resolution path) and the process env
/// (12-factor config, set at deploy time). Prefer vault — it lets a user
/// call `rotate_secret anthropic/api_key` and have the rotation propagate
/// to both worker-side `llm::*` host calls AND controller-side scaffolding
/// without a process restart.
///
/// When a vault source is configured, the key is resolved per-request via
/// the cached `SecretsManager::get_llm_vault_keys` path (60s TTL, eager
/// invalidation on rotation), with a falls-through to the env fallback
/// when the vault has nothing stored. `ResolvedKey` caches the last
/// successfully-resolved value to avoid a cache lookup on every request
/// without masking rotations for more than the TTL window.
#[derive(Clone)]
enum KeySource {
    /// Key read from the process environment at startup; never changes.
    Env(String),
    /// Resolved from the vault on each request (via cached getter), with
    /// `env_fallback` used only when the vault lookup returns no key.
    Vault {
        secrets_manager: Arc<talos_secrets_manager::SecretsManager>,
        env_fallback: Option<String>,
    },
}

#[derive(Clone)]
pub struct LlmClient {
    client: Client,
    key_source: KeySource,
}

impl LlmClient {
    /// Construct an env-only client. Prefer [`LlmClient::with_vault`] in
    /// production so vault rotations propagate to controller calls.
    pub fn new(api_key: String) -> Self {
        let client = Self::build_http();
        Self {
            client,
            key_source: KeySource::Env(api_key),
        }
    }

    /// Construct a vault-backed client. Per-request key resolution goes
    /// through `SecretsManager::get_llm_vault_keys` (60s-TTL cache, eager
    /// invalidation on `rotate_secret`). `env_fallback` is consulted only
    /// when the vault has no `anthropic/api_key` entry — typical for a
    /// fresh deploy before the user has provisioned the vault.
    ///
    /// Returns `None` if neither source would produce a usable key (no
    /// vault entry AND no env fallback), so callers can short-circuit the
    /// "LLM is available" check.
    pub fn with_vault(
        secrets_manager: Arc<talos_secrets_manager::SecretsManager>,
        env_fallback: Option<String>,
    ) -> Self {
        let client = Self::build_http();
        Self {
            client,
            key_source: KeySource::Vault {
                secrets_manager,
                env_fallback,
            },
        }
    }

    fn build_http() -> Client {
        // MCP-496: stop falling back to `Client::default()` on build
        // failure. `Client::default()` is `Client::new()` which has
        // (a) no timeout — a stuck Anthropic response could pin a
        // controller task forever — and (b) the default redirect
        // policy following up to 10 hops. reqwest strips only the
        // `Authorization` header on cross-origin redirects; the
        // Anthropic API uses `x-api-key` instead, which is NOT
        // automatically stripped. A 302 response from api.anthropic.com
        // (MITM'd or if Anthropic ever changes URL structure) would
        // therefore exfiltrate the Anthropic API key to the redirect
        // target. Same bug class as MCP-471.
        //
        // `.build()` only fails on TLS init, which is a deployment
        // failure that should be loud, not a silent security
        // downgrade. Redirect policy is set to none for defense in
        // depth — the Anthropic API doesn't redirect today, but the
        // controller should not be a key oracle if that ever changes.
        // MCP-1034: explicit connect_timeout matches the canonical
        // hardened-client shape (see talos-atlassian / talos-gmail /
        // talos-slack). Without it, a black-holed api.anthropic.com
        // (DNS failure, network partition) can hold the connection pool
        // until ANTHROPIC_HTTP_TIMEOUT fires.
        Client::builder()
            .timeout(ANTHROPIC_HTTP_TIMEOUT)
            .connect_timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("talos-llm: failed to build hardened Anthropic HTTP client")
    }

    /// Resolve the current Anthropic API key. Vault-backed clients hit
    /// the cache (cheap); env-backed clients are a clone of a `String`.
    /// Returns an `anyhow::Error` when nothing is usable so callers can
    /// turn it into a user-facing "LLM not configured" message.
    ///
    /// Wrapped in [`Zeroizing`] so the plaintext bytes are wiped from
    /// heap when the value is dropped — the key flows into a reqwest
    /// request header for one HTTP call and then drops, so the heap
    /// exposure window is bounded to the request lifetime.
    async fn resolve_api_key(&self) -> Result<Zeroizing<String>> {
        match &self.key_source {
            KeySource::Env(k) => {
                if k.is_empty() {
                    Err(anyhow!(
                        "LLM client has no API key (env source was empty at startup)"
                    ))
                } else {
                    Ok(Zeroizing::new(k.clone()))
                }
            }
            KeySource::Vault {
                secrets_manager,
                env_fallback,
            } => {
                // None owner scopes the lookup to org/wildcard secrets —
                // controller-side LLM keys live under the platform's
                // trust boundary, not a specific end-user.
                match secrets_manager.get_llm_vault_keys(None).await {
                    Ok(map) => {
                        if let Some(v) = map.get("anthropic/api_key") {
                            // Clone preserves the Zeroizing wrapper.
                            return Ok(v.clone());
                        }
                    }
                    Err(e) => {
                        warn!(
                            error = %e,
                            "LLM vault lookup failed — falling back to env"
                        );
                    }
                }
                match env_fallback {
                    Some(k) if !k.is_empty() => Ok(Zeroizing::new(k.clone())),
                    _ => Err(anyhow!(
                        "LLM client: no `anthropic/api_key` in vault and no env fallback. \
                         Set the vault path via `set_secret anthropic/api_key` or export \
                         ANTHROPIC_API_KEY in the controller environment."
                    )),
                }
            }
        }
    }

    pub async fn generate_code(
        &self,
        prompt: &str,
        current_code: &str,
        capability_world: &str,
    ) -> Result<String> {
        let system_prompt = format!(
            "You are an expert Rust WebAssembly module developer. \
            Generate or modify the code based on the user's prompt. \
            The module runs in the '{}' world. \
            \
            CRITICAL RULES:\n\
            1. ONLY output valid Rust code. Do not include markdown formatting like ```rust, just the raw code.\n\
            2. ALWAYS include the `use talos_sdk_macros::talos_node;` statement at the very top of the file.\n\
            3. Any additional `use` statements (like `use std::net::ToSocketAddrs;`) MUST be placed at the top of the file, BEFORE the `#[talos_node]` macro.\n\
            4. ALWAYS apply the `#[talos_node(world = \"...\")]` macro directly above the `pub fn run` function.\n\
            5. DO NOT use or import `talos_sdk`. It does not exist in this environment. Use standard Rust standard library and external crates if network access is allowed.",
            capability_world
        );

        let user_prompt = format!("Current code:\n{}\n\nPrompt: {}", current_code, prompt);

        let api_key = self.resolve_api_key().await?;
        let mut retries = 0;
        let max_retries = 3;
        // Named so the usage-record call below can't drift from the request.
        const MODEL: &str = "claude-sonnet-4-6";

        let response = loop {
            let req = self
                .client
                .post("https://api.anthropic.com/v1/messages")
                .header("x-api-key", api_key.as_str())
                .header("anthropic-version", "2023-06-01")
                .json(&json!({
                    "model": MODEL,
                    "max_tokens": 4096,
                    "system": &system_prompt,
                    "messages": [
                        {
                            "role": "user",
                            "content": &user_prompt
                        }
                    ]
                }));

            let resp = req.send().await?;

            if resp.status().is_success() {
                break resp;
            }

            let status = resp.status();

            // Retry on 529 Overloaded or other 5xx server errors
            if status.as_u16() == 529 || status.is_server_error() || status.as_u16() == 429 {
                if retries >= max_retries {
                    // MCP-454: log full body server-side (audit), but
                    // return only the status to the caller. Anthropic
                    // error responses can echo parts of the user
                    // prompt (especially content-moderation errors
                    // that quote the offending input) — if the caller
                    // is an MCP handler whose error surfaces to the
                    // operator, that body could leak. Same pattern as
                    // OllamaClient::complete just below.
                    let text = talos_http_body::read_error_text_capped(resp).await;
                    let redacted = talos_dlp_provider::redact_str(&text);
                    error!(
                        status = %status,
                        body_len = text.len(),
                        retries,
                        body = %redacted,
                        "Anthropic API error after retries"
                    );
                    return Err(anyhow!(
                        "Failed to generate code from LLM API: HTTP {}",
                        status
                    ));
                }

                retries += 1;
                let backoff_secs = 2_u64.pow(retries);
                warn!(
                    "Anthropic API returned {}. Retrying in {}s... ({}/{})",
                    status, backoff_secs, retries, max_retries
                );
                tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                continue;
            }

            // Non-retriable error — same redaction posture as the
            // retry-exhausted branch above (MCP-454).
            let text = talos_http_body::read_error_text_capped(resp).await;
            let redacted = talos_dlp_provider::redact_str(&text);
            error!(
                status = %status,
                body_len = text.len(),
                body = %redacted,
                "Anthropic API error"
            );
            return Err(anyhow!(
                "Failed to generate code from LLM API: HTTP {}",
                status
            ));
        };

        let body: serde_json::Value = talos_http_body::read_json_capped(response).await?;
        usage::record_anthropic(MODEL, &body);

        let mut text = body["content"][0]["text"]
            .as_str()
            .unwrap_or("")
            .to_string();

        // Strip control characters
        text.retain(|c| !c.is_control() || c == '\n' || c == '\r' || c == '\t');

        if text.starts_with("```rust") {
            text = text.trim_start_matches("```rust").to_string();
        } else if text.starts_with("```") {
            text = text.trim_start_matches("```").to_string();
        }
        if text.ends_with("```") {
            text = text.trim_end_matches("```").to_string();
        }

        Ok(text.trim().to_string())
    }

    /// Make a simple text completion. Returns the raw LLM response as a String.
    /// Used for lightweight AI-powered hints (e.g., config value suggestions).
    pub async fn generate_text(&self, system_prompt: &str, user_prompt: &str) -> Result<String> {
        let api_key = self.resolve_api_key().await?;
        let mut retries = 0u32;
        let max_retries = 2u32;
        // Named so the usage-record call below can't drift from the request.
        const MODEL: &str = "claude-haiku-4-5-20251001";

        let response = loop {
            let req = self
                .client
                .post("https://api.anthropic.com/v1/messages")
                .header("x-api-key", api_key.as_str())
                .header("anthropic-version", "2023-06-01")
                .json(&json!({
                    "model": MODEL,
                    "max_tokens": 512,
                    "system": system_prompt,
                    "messages": [{ "role": "user", "content": user_prompt }]
                }));

            let resp = req.send().await?;
            if resp.status().is_success() {
                break resp;
            }
            let status = resp.status();
            if (status.as_u16() == 529 || status.is_server_error() || status.as_u16() == 429)
                && retries < max_retries
            {
                retries += 1;
                let backoff = 2_u64.pow(retries);
                warn!(
                    "generate_text: API {} — retry {}/{} in {}s",
                    status, retries, max_retries, backoff
                );
                tokio::time::sleep(std::time::Duration::from_secs(backoff)).await;
                continue;
            }
            // MCP-454: log full body server-side, return status to caller.
            // MCP-527: DLP-redact the body before logging — Anthropic
            // moderation responses can echo prompt content verbatim
            // (including embedded secrets a user pasted into a workflow
            // description). Log aggregators downstream are often shared
            // surfaces; full echo would leak via that path.
            let text = talos_http_body::read_error_text_capped(resp).await;
            let redacted = talos_dlp_provider::redact_str(&text);
            error!(
                status = %status,
                body_len = text.len(),
                body = %redacted,
                "generate_text API error"
            );
            return Err(anyhow!("LLM API error: HTTP {}", status));
        };

        let body: serde_json::Value = talos_http_body::read_json_capped(response).await?;
        usage::record_anthropic(MODEL, &body);
        let mut text = body["content"][0]["text"]
            .as_str()
            .unwrap_or("")
            .trim()
            .to_string();

        // Strip markdown fences — models sometimes wrap JSON in ```json ... ``` even when asked not to
        if let Some(s) = text.strip_prefix("```json") {
            text = s.to_string();
        } else if let Some(s) = text.strip_prefix("```") {
            text = s.to_string();
        }
        if let Some(s) = text.strip_suffix("```") {
            text = s.to_string();
        }

        Ok(text.trim().to_string())
    }

    /// Generate a workflow scaffold from a natural language description and a compact catalog.
    ///
    /// Returns a JSON string with the suggested workflow structure:
    /// `{ suggested_name, reasoning, nodes: [{label, module_name, config_hint, config_values}], edges: [{from, to}], suggested_schedule? }`
    pub async fn scaffold_workflow(&self, description: &str, catalog_json: &str) -> Result<String> {
        let system_prompt = "You are a workflow architect for the Talos automation platform. \
            Respond ONLY with valid JSON, no prose, no markdown code fences. \
            The JSON must match exactly: \
            { \"suggested_name\": string, \"reasoning\": string, \
              \"nodes\": [{\"label\": string, \"module_name\": string, \"config_hint\": string, \"config_values\": {key: value}}], \
              \"edges\": [{\"from\": string, \"to\": string, \"edge_type\": \"default\"|\"error\"|\"conditional\"}], \
              \"suggested_schedule\": string|null, \
              \"suggested_error_handling\": [{\"node_label\": string, \"risk\": string, \"handler_module\": string}] }. \
            Use module_name values that exactly match the display_name field in the catalog. \
            suggested_schedule must be a standard 5-field cron expression or null. \
            For config_values: populate sensible defaults based on the user's request \
            (e.g. CHANNEL: '#engineering', URL: 'https://api.example.com/status', MODEL: 'claude-sonnet-4-6'). \
            Leave fields that require secrets empty — do not guess secret values. \
            PARALLEL EXECUTION: Identify nodes that can run concurrently (e.g., independent API fetches, \
            parallel notifications). Represent parallelism as multiple edges FROM the same source node \
            to several target nodes. \
            FAN-IN RULE (critical): At every point where 2+ parallel branches converge into a single \
            downstream node, you MUST insert a node with module_name='system:collect' BEFORE the \
            convergence node. Without a Collect node, parallel branch outputs will race and overwrite \
            each other. Use label='Collect' and module_name='system:collect' exactly — this is a \
            built-in engine node and must not be renamed. \
            Example: fan_out → [branch_a, branch_b] → collect_node (system:collect) → summarizer. \
            TRIGGER NODE RULE: If all parallel fan-out branches are driven by the same external input \
            (e.g., a repo URL, a webhook payload) and the first node does nothing but forward that \
            input to the branches, do NOT add an intermediate HTTP Request node as a trigger. \
            Fan-out directly from the workflow's own input. Only include an entry fetch node when it \
            performs a real retrieval or transformation (e.g., fetching a list to iterate over, or \
            calling an API whose response feeds all branches). \
            edge_type defaults to 'default'. Use 'error' for edges that should only fire on node failure. \
            suggested_error_handling: for each node with a meaningful failure risk (e.g., HTTP calls, \
            external APIs), list the risk and recommend a handler module (e.g. 'Slack Message', \
            'PagerDuty Alert'). Omit suggested_error_handling entries for trivial transform-only nodes.";

        let user_prompt = format!(
            "Available modules (catalog):\n{}\n\nUser request: {}",
            catalog_json, description
        );

        let api_key = self.resolve_api_key().await?;
        let mut retries = 0;
        let max_retries = 3;
        // Named so the usage-record call below can't drift from the request.
        const MODEL: &str = "claude-sonnet-4-6";

        let response = loop {
            let req = self
                .client
                .post("https://api.anthropic.com/v1/messages")
                .header("x-api-key", api_key.as_str())
                .header("anthropic-version", "2023-06-01")
                .json(&json!({
                    "model": MODEL,
                    "max_tokens": 2048,
                    "system": system_prompt,
                    "messages": [{ "role": "user", "content": &user_prompt }]
                }));

            let resp = req.send().await?;

            if resp.status().is_success() {
                break resp;
            }

            let status = resp.status();
            if status.as_u16() == 529 || status.is_server_error() || status.as_u16() == 429 {
                if retries >= max_retries {
                    // MCP-454: log full body server-side, return status to caller.
                    // MCP-527: DLP-redact before tracing — see generate_text.
                    let text = talos_http_body::read_error_text_capped(resp).await;
                    let redacted = talos_dlp_provider::redact_str(&text);
                    error!(
                        status = %status,
                        body_len = text.len(),
                        retries,
                        body = %redacted,
                        "scaffold_workflow API error after retries"
                    );
                    return Err(anyhow!("LLM API error: HTTP {}", status));
                }
                retries += 1;
                let backoff_secs = 2_u64.pow(retries);
                warn!(
                    "scaffold_workflow: API returned {}. Retry {}/{} in {}s",
                    status, retries, max_retries, backoff_secs
                );
                tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                continue;
            }

            // MCP-454: log full body server-side, return status to caller.
            // MCP-527: DLP-redact before tracing — see generate_text.
            let text = talos_http_body::read_error_text_capped(resp).await;
            let redacted = talos_dlp_provider::redact_str(&text);
            error!(
                status = %status,
                body_len = text.len(),
                body = %redacted,
                "scaffold_workflow API error"
            );
            return Err(anyhow!("LLM API error: HTTP {}", status));
        };

        let body: serde_json::Value = talos_http_body::read_json_capped(response).await?;
        usage::record_anthropic(MODEL, &body);
        let mut text = body["content"][0]["text"]
            .as_str()
            .unwrap_or("")
            .to_string();

        // Strip markdown fences if present
        if let Some(stripped) = text.strip_prefix("```json") {
            text = stripped.to_string();
        } else if let Some(stripped) = text.strip_prefix("```") {
            text = stripped.to_string();
        }
        if let Some(stripped) = text.strip_suffix("```") {
            text = stripped.to_string();
        }

        Ok(text.trim().to_string())
    }
}

// ============================================================================
// Tier 1: Ollama (Local LLM) Client
// ============================================================================

/// Client for local Ollama inference. Data never leaves the network — no DLP
/// needed. Used for quick, frequent, simple tasks (classification, extraction,
/// summarization) and for processing sensitive data that must stay on-prem.
#[derive(Clone)]
pub struct OllamaClient {
    client: Client,
    base_url: String,
}

impl OllamaClient {
    pub fn new(base_url: String) -> Self {
        // MCP-496: same hardened-build-or-fail discipline as
        // LlmClient::build_http. Ollama is local-only so the redirect
        // surface is moot, but `unwrap_or_default()` would drop the
        // timeout — and a stuck Ollama call with no timeout will pin
        // the controller's request task indefinitely. Make the build
        // failure loud at startup rather than degrading later.
        // MCP-1034: connect_timeout — Ollama is typically a local
        // sidecar so a TCP-connect failure should surface within a
        // couple of seconds; without an explicit cap a misconfigured
        // OLLAMA_BASE_URL (wrong port, stopped service) would pin the
        // call until OLLAMA_HTTP_TIMEOUT fires.
        let client = Client::builder()
            .timeout(OLLAMA_HTTP_TIMEOUT)
            .connect_timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("talos-llm: failed to build Ollama HTTP client");
        Self { client, base_url }
    }

    /// Run a chat completion against a local Ollama model.
    ///
    /// Uses the NATIVE `/api/chat` endpoint (migrated off the
    /// OpenAI-compat shim 2026-07-09, in lockstep with the worker's
    /// `llm_providers::ollama` adapter): `max_tokens` maps to the native
    /// `options.num_predict`, and the response is `message.content`
    /// rather than `choices[0]`. Native also keeps the door open for
    /// `think` / `format` / `options.num_ctx` without another endpoint
    /// change. `stream:false` is explicit — the native default is
    /// streaming.
    pub async fn complete(
        &self,
        model: &str,
        system_prompt: &str,
        user_prompt: &str,
        max_tokens: u32,
    ) -> Result<String> {
        let mut messages = vec![];
        if !system_prompt.is_empty() {
            messages.push(json!({"role": "system", "content": system_prompt}));
        }
        messages.push(json!({"role": "user", "content": user_prompt}));

        let body = json!({
            "model": model,
            "messages": messages,
            "stream": false,
            "options": { "num_predict": max_tokens },
        });

        let resp = self
            .client
            .post(format!("{}/api/chat", self.base_url))
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = talos_http_body::read_error_text_capped(resp).await;
            // SECURITY: don't leak full response to caller — log server-side only
            error!(status = %status, body_len = text.len(), "Ollama API error");
            return Err(anyhow!("Ollama returned HTTP {}", status));
        }

        let body: serde_json::Value = talos_http_body::read_json_capped(resp).await?;
        usage::record_ollama(model, &body);
        let text = body
            .get("message")
            .and_then(|m| m.get("content"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();

        Ok(text)
    }

    /// List locally available models via Ollama API.
    pub async fn list_models(&self) -> Result<serde_json::Value> {
        let resp = self
            .client
            .get(format!("{}/api/tags", self.base_url))
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(anyhow!("Ollama list models failed: HTTP {}", resp.status()));
        }
        talos_http_body::read_json_capped(resp).await
    }

    /// Pull a model from the Ollama registry.
    pub async fn pull_model(&self, name: &str) -> Result<String> {
        let resp = self
            .client
            .post(format!("{}/api/pull", self.base_url))
            .json(&json!({"name": name, "stream": false}))
            .timeout(OLLAMA_PULL_TIMEOUT)
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(anyhow!("Ollama pull failed: HTTP {}", resp.status()));
        }
        let body: serde_json::Value = talos_http_body::read_json_capped(resp).await?;
        Ok(body
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string())
    }

    /// Delete a locally cached model.
    pub async fn delete_model(&self, name: &str) -> Result<()> {
        let resp = self
            .client
            .delete(format!("{}/api/delete", self.base_url))
            .json(&json!({"name": name}))
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(anyhow!("Ollama delete failed: HTTP {}", resp.status()));
        }
        Ok(())
    }

    /// Get model details (parameters, quantization, etc.)
    pub async fn show_model(&self, name: &str) -> Result<serde_json::Value> {
        let resp = self
            .client
            .post(format!("{}/api/show", self.base_url))
            .json(&json!({"name": name}))
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(anyhow!("Ollama show failed: HTTP {}", resp.status()));
        }
        talos_http_body::read_json_capped(resp).await
    }
}
