//! Embedding pipeline: env-driven config, rate-limited single + batch
//! generators, plus pure helpers for input shaping and pgvector-literal
//! formatting. Lifted from `talos-mcp-handlers/src/search.rs` verbatim
//! during the r305 SearchService extraction; behaviour preserved.

use std::num::NonZeroU32;
use std::sync::{Arc, LazyLock, OnceLock};

use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use thiserror::Error;
use uuid::Uuid;

// MCP-1110 (2026-05-16): cache the hardened embedding HTTP client at
// module scope so `generate_embeddings_batch` doesn't rebuild it on
// every call. Pre-fix every embed request paid:
//   * `reqwest::Client::builder()` config alloc + TLS context init
//   * `.build()` returning a fresh inner `Arc` with its own connection
//     pool — no connection reuse across calls, so every embed reopened
//     TCP+TLS to the provider (significant added latency on hot paths
//     like semantic memory recall; also amplifies provider rate-limit
//     consumption because the per-Client pool can't keep keep-alive
//     connections warm).
// Sibling pattern to `talos-llm::LlmClient::build_http()` which builds
// the hardened client ONCE in the constructor; the embedding crate is
// the holdout (no struct lifecycle to hang the client off, so module-
// scope LazyLock is the right shape).
//
// `.expect()` on TLS-init failure matches sibling `talos-llm`
// behaviour — TLS init failing is a deployment-time issue (missing
// system roots, OS broken), not a request-time recoverable error;
// surfacing it loudly at first call beats silently degrading every
// embed for the lifetime of the pod.
//
// MCP-1034 timeout + connect_timeout values preserved exactly. Redirect
// policy stays `none` for the bearer-leak defense documented at the
// call site (MCP-520).
static EMBED_HTTP_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .connect_timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("talos-search-service: failed to build embedding HTTP client (TLS init)")
});

// -----------------------------------------------------------------------------
// EmbeddingError
// -----------------------------------------------------------------------------

/// Pre-r241 `generate_embedding` returned `Option<Vec<f32>>`, which
/// collapsed every failure (no provider / network down / 401 / 429 /
/// dim mismatch) into a single `None` — operators reading the MCP
/// response had no way to tell apart "provider not configured" from
/// "Voyage rate-limited us" from "key revoked." Surfacing the
/// specific cause is the single biggest debuggability win in this
/// whole pipeline.
///
/// `body` is truncated to 512 chars before construction so a
/// provider-side HTML error page can't blow up logs / response
/// bodies.
#[derive(Debug, Clone, Error)]
pub enum EmbeddingError {
    #[error("embedding provider not configured (set EMBEDDING_API_KEY or EMBEDDING_API_URL)")]
    NotConfigured,

    #[error("embedding HTTP request failed: {0}")]
    Network(String),

    #[error("embedding API returned {status}: {body}")]
    ApiError { status: u16, body: String },

    #[error("embedding response had {got} dimensions, expected {expected} (set EMBEDDING_DIMENSIONS={got} or change EMBEDDING_MODEL)")]
    DimensionMismatch { got: usize, expected: usize },

    #[error("embedding response missing data[].embedding")]
    InvalidResponse,

    #[error("embedding response had {returned} results for {requested} inputs (provider violated batch contract)")]
    BatchSizeMismatch { returned: usize, requested: usize },
}

impl EmbeddingError {
    /// Stable string slug for metrics / coverage gauges. Avoid the
    /// human-readable `Display` impl when grouping or alerting — it
    /// embeds variable data.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::NotConfigured => "not_configured",
            Self::Network(_) => "network",
            Self::ApiError { .. } => "api_error",
            Self::DimensionMismatch { .. } => "dimension_mismatch",
            Self::InvalidResponse => "invalid_response",
            Self::BatchSizeMismatch { .. } => "batch_size_mismatch",
        }
    }
}

// -----------------------------------------------------------------------------
// EmbeddingConfig
// -----------------------------------------------------------------------------

/// The DB column dimension must match the model output (set via
/// migration). The docker-compose default is `nomic-embed-text` →
/// 768 dims. Set `EMBEDDING_DIMENSIONS` to the expected output size;
/// defaults to 1536 (OpenAI `text-embedding-3-small`).
pub struct EmbeddingConfig {
    pub api_url: String,
    pub api_key: Option<String>,
    pub model: String,
    pub dimensions: usize,
}

impl EmbeddingConfig {
    /// Load from environment. Returns `None` if no API key is
    /// available AND no explicit URL is set. Empty-string env vars
    /// are treated as unset (matches operator intent when install.sh
    /// writes `--from-literal=EMBEDDING_API_URL=""` for the
    /// not-yet-configured case — without this, `std::env::var`
    /// returns `Ok("")` and downstream code constructs requests
    /// against the empty URL).
    pub fn from_env() -> Option<Self> {
        let api_key = nonempty_env("EMBEDDING_API_KEY").or_else(|| nonempty_env("OPENAI_API_KEY"));

        let explicit_url = nonempty_env("EMBEDDING_API_URL");
        let api_url = explicit_url
            .clone()
            .unwrap_or_else(|| "https://api.openai.com/v1/embeddings".to_string());

        // If neither key is set, only allow keyless endpoints (e.g.
        // local Ollama). Require the user to set EMBEDDING_API_URL
        // explicitly for keyless use.
        if api_key.is_none() && explicit_url.is_none() {
            return None;
        }

        let model =
            nonempty_env("EMBEDDING_MODEL").unwrap_or_else(|| "text-embedding-3-small".to_string());

        // OpenAI text-embedding-3-small → 1536. Voyage voyage-3 →
        // 1024. nomic-embed-text → 768. Always set this explicitly to
        // match the chosen model AND the pgvector column dimension.
        let dimensions = nonempty_env("EMBEDDING_DIMENSIONS")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(1536);

        Some(EmbeddingConfig {
            api_url,
            api_key,
            model,
            dimensions,
        })
    }

    /// Human-readable description of the active configuration (safe
    /// to return to agents).
    pub fn describe(&self) -> String {
        format!(
            "model={}, endpoint={}, dimensions={}",
            self.model, self.api_url, self.dimensions
        )
    }
}

/// Read an env var and treat empty strings as unset. Critical for
/// env-from-secret pipelines that materialise unset keys as `""`
/// rather than omitting them.
pub(crate) fn nonempty_env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}

// -----------------------------------------------------------------------------
// Rate limiter (process-wide; shared by all embed callers)
// -----------------------------------------------------------------------------

// Pre-r241 `auto_embed_workflow` fanned out N parallel embed requests
// with no concurrency cap. Against any rate-limited provider this
// guaranteed N-K failures on first contact (we hit it on Voyage
// free-tier 3 RPM: first 3 succeed, next 9 all 429 and silently
// no-op). The fix is a process-wide token-bucket rate limiter on the
// embed call path itself. All callers (auto-heal, MCP handlers,
// semantic search) share the same limiter so one chatty caller can't
// starve another.
//
// Default 60 RPM = 1/sec — safe headroom under OpenAI tier-1 (3000
// RPM), Voyage paid tier 1 (300 RPM), and most other providers.
// Voyage free tier operators must set `EMBEDDING_MAX_RPM=3` to avoid
// burning 80% of attempts on rate-limit failures.

type EmbedLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;
static EMBED_LIMITER: OnceLock<Arc<EmbedLimiter>> = OnceLock::new();

fn embed_limiter() -> &'static Arc<EmbedLimiter> {
    EMBED_LIMITER.get_or_init(|| {
        let rpm = nonempty_env("EMBEDDING_MAX_RPM")
            .and_then(|s| s.parse::<u32>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(60);
        // SAFETY: filter ensures rpm > 0; NonZeroU32::new returns Some.
        let quota = Quota::per_minute(NonZeroU32::new(rpm).expect("rpm > 0 enforced above"));
        Arc::new(RateLimiter::direct(quota))
    })
}

// -----------------------------------------------------------------------------
// Embed (single + batch)
// -----------------------------------------------------------------------------

// Voyage and OpenAI both accept `input: ["text1","text2",...]` and
// respond with `data: [{embedding: ...}, {embedding: ...}]` in the
// same order. r241 switches the bulk-embed code path to use the batch
// shape (drops 12 calls to 1 for full backfill). The single-input
// path (`generate_embedding`) is a thin wrapper around the batch
// shape so the two stay in lockstep.
//
// Inputs over EMBED_INPUT_CHAR_BUDGET (8000 chars per item) are
// truncated. Inputs per batch capped at EMBED_BATCH_MAX (50) —
// Voyage's per-request limit is 128 inputs / ~120K tokens; 50 stays
// comfortably inside.

const EMBED_INPUT_CHAR_BUDGET: usize = 8000;
pub const EMBED_BATCH_MAX: usize = 50;

fn truncate_input(text: &str) -> &str {
    // MCP-1050: canonical helper — `truncate_at_char_boundary` is the
    // identical pattern this function reimplemented inline.
    talos_text_util::truncate_at_char_boundary(text, EMBED_INPUT_CHAR_BUDGET)
}

/// Generate an embedding for a single input. Returns the typed error
/// so callers can decide whether to fall back to keyword search,
/// retry, or surface the failure to the user.
pub async fn generate_embedding(text: &str) -> Result<Vec<f32>, EmbeddingError> {
    let inputs = vec![text.to_string()];
    let mut batch = generate_embeddings_batch(&inputs).await?;
    Ok(batch.remove(0))
}

/// Generate embeddings for a batch of inputs in a single API request.
/// Returns vectors in the same order as `texts`. Empty input slice
/// returns `Ok(vec![])` without making a network call.
pub async fn generate_embeddings_batch(
    texts: &[String],
) -> Result<Vec<Vec<f32>>, EmbeddingError> {
    if texts.is_empty() {
        return Ok(Vec::new());
    }
    if texts.len() > EMBED_BATCH_MAX {
        // Recurse on chunks. Each chunk consumes one rate-limit token.
        let mut all = Vec::with_capacity(texts.len());
        for chunk in texts.chunks(EMBED_BATCH_MAX) {
            let mut part = Box::pin(generate_embeddings_batch(chunk)).await?;
            all.append(&mut part);
        }
        return Ok(all);
    }

    let config = EmbeddingConfig::from_env().ok_or(EmbeddingError::NotConfigured)?;

    // Wait for a rate-limit token. Background callers are happy to
    // block; foreground callers (semantic search) under the default
    // 60 RPM cap virtually never wait.
    embed_limiter().until_ready().await;

    let truncated: Vec<&str> = texts.iter().map(|t| truncate_input(t)).collect();

    // MCP-520: embedding provider URL is operator-configured
    // (`EMBEDDING_API_URL`) and the request carries `bearer_auth(key)`.
    // reqwest's default redirect policy strips `Authorization` on
    // cross-origin redirects (since 0.12) but preserves it on
    // same-origin redirects. A legitimate provider that 302s to its
    // own CDN, or an attacker-controlled URL pointing at attacker.com
    // with a self-301 to its own logging endpoint, can capture the
    // bearer token. Disable redirects entirely — every supported
    // provider answers the embed request directly without redirect.
    // Same Mode-B credential-leak class as MCP-469..471.
    // MCP-1034: explicit connect_timeout — provider DNS failure or
    // TCP-handshake stall should fail fast (5s) rather than holding
    // the connection pool for the full 30s request timeout.
    // MCP-1110 (2026-05-16): shared once-built client (see
    // EMBED_HTTP_CLIENT at module scope). One TLS context + one
    // connection pool process-wide — keep-alive connections to the
    // provider stay warm across embed calls.
    let client: &reqwest::Client = &EMBED_HTTP_CLIENT;

    // Single-input requests use the string shape (Cohere v2 / Jina /
    // older Ollama versions reject array-of-one); batch requests use
    // the array shape that every OpenAI-compatible provider supports.
    let body = if truncated.len() == 1 {
        serde_json::json!({
            "input": truncated[0],
            "model": config.model,
        })
    } else {
        serde_json::json!({
            "input": truncated,
            "model": config.model,
        })
    };

    let mut req = client.post(&config.api_url).json(&body);
    if let Some(ref key) = config.api_key {
        req = req.bearer_auth(key);
    }

    let resp = req
        .send()
        .await
        .map_err(|e| EmbeddingError::Network(e.to_string()))?;

    let status = resp.status();
    if !status.is_success() {
        // Bounded read (NOT unbounded `resp.text()`): only 512 chars are
        // retained for logging, so cap the buffer to a small bound.
        let body =
            talos_http_body::read_body_capped(resp, talos_http_body::DEFAULT_MAX_ERROR_BODY_BYTES)
                .await
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .unwrap_or_else(|_| "<unreadable or oversized response body>".to_string());
        let body_truncated = if body.len() > 512 {
            format!(
                "{}…",
                talos_text_util::truncate_at_char_boundary(&body, 512)
            )
        } else {
            body
        };
        // MCP-576: DLP-scrub the response body before logging AND
        // before propagating to the EmbeddingError. Embedding providers
        // often echo the request `input` field verbatim in error
        // responses (especially OpenAI-style "input too long" errors
        // include the offending text). The `input` for workflow
        // semantic-search is `workflow_embedding_text` which composes
        // name + description + capabilities + intent — operator-
        // supplied strings that may contain secrets a user pasted
        // into a workflow description ("API key sk-... is broken").
        // Same pattern as MCP-527 in talos-llm::generate_text.
        let scrubbed_body = talos_dlp_provider::redact_str(&body_truncated);
        tracing::warn!(
            status = %status,
            url = %config.api_url,
            body = %scrubbed_body,
            "Embedding API request failed"
        );
        return Err(EmbeddingError::ApiError {
            status: status.as_u16(),
            body: scrubbed_body,
        });
    }

    // Bounded read, NOT unbounded `resp.json()` (OOM defense-in-depth).
    let bytes =
        talos_http_body::read_body_capped(resp, talos_http_body::DEFAULT_MAX_RESPONSE_BYTES)
            .await
            .map_err(|e| EmbeddingError::Network(e.to_string()))?;
    let json: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| EmbeddingError::Network(e.to_string()))?;

    let data = json
        .get("data")
        .and_then(|v| v.as_array())
        .ok_or(EmbeddingError::InvalidResponse)?;

    if data.len() != truncated.len() {
        return Err(EmbeddingError::BatchSizeMismatch {
            returned: data.len(),
            requested: truncated.len(),
        });
    }

    let mut out: Vec<Vec<f32>> = Vec::with_capacity(data.len());
    for entry in data {
        let embedding: Vec<f32> = entry
            .get("embedding")
            .and_then(|v| v.as_array())
            .ok_or(EmbeddingError::InvalidResponse)?
            .iter()
            .filter_map(|v| v.as_f64().map(|f| f as f32))
            .collect();

        if embedding.len() != config.dimensions {
            tracing::warn!(
                got = embedding.len(),
                expected = config.dimensions,
                model = %config.model,
                "Embedding provider returned unexpected dimension count. \
                 Set EMBEDDING_DIMENSIONS={} to match your model.",
                embedding.len()
            );
            return Err(EmbeddingError::DimensionMismatch {
                got: embedding.len(),
                expected: config.dimensions,
            });
        }
        out.push(embedding);
    }

    Ok(out)
}

// -----------------------------------------------------------------------------
// Pure helpers
// -----------------------------------------------------------------------------

/// Build the searchable text for a workflow from its metadata fields.
pub fn workflow_embedding_text(
    name: &str,
    description: Option<&str>,
    capabilities: &[String],
    intent: Option<&str>,
) -> String {
    let mut parts = vec![name.to_string()];
    if let Some(d) = description {
        if !d.is_empty() {
            parts.push(d.to_string());
        }
    }
    if !capabilities.is_empty() {
        parts.push(capabilities.join(", "));
    }
    if let Some(i) = intent {
        if !i.is_empty() {
            parts.push(i.to_string());
        }
    }
    parts.join(". ")
}

/// Format a `Vec<f32>` as a pgvector literal: `"[0.1,0.2,...]"`.
/// Used by every `set_*_embedding_from_str` call site so they share
/// one allocator path and one numeric-format choice.
pub fn vec_to_pgvector_literal(v: &[f32]) -> String {
    let mut s = String::with_capacity(v.len() * 12 + 2);
    s.push('[');
    for (i, f) in v.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        // f32::to_string is locale-independent and produces the
        // shortest round-trippable form — exactly what pgvector
        // parses.
        s.push_str(&f.to_string());
    }
    s.push(']');
    s
}

// -----------------------------------------------------------------------------
// Best-effort fire-and-forget auto-embed
// -----------------------------------------------------------------------------

/// Fetch workflow metadata and store an embedding. Never panics.
/// Called as a fire-and-forget `tokio::spawn` after publish or
/// scaffold. Provider-misconfiguration cases stay quiet (boot WARN
/// already covers them); transient errors log at DEBUG so per-row
/// fan-out doesn't spam.
pub async fn auto_embed_workflow(
    workflow_id: Uuid,
    user_id: Uuid,
    pool: &sqlx::PgPool,
) {
    let repo = talos_workflow_repository::WorkflowRepository::new(pool.clone());
    let src = match repo
        .get_workflow_embedding_source(workflow_id, user_id)
        .await
    {
        Ok(Some(s)) => s,
        Ok(None) => {
            tracing::debug!("auto_embed_workflow: workflow {} not found", workflow_id);
            return;
        }
        Err(e) => {
            tracing::warn!(
                "auto_embed_workflow: query failed for {}: {:#}",
                workflow_id,
                e
            );
            return;
        }
    };

    let intent_str = src
        .intent
        .as_ref()
        .and_then(|v| v.as_str())
        .map(String::from)
        .or_else(|| src.intent.as_ref().map(|v| v.to_string()));

    let text = workflow_embedding_text(
        &src.name,
        src.description.as_deref(),
        &src.capabilities,
        intent_str.as_deref(),
    );

    match generate_embedding(&text).await {
        Ok(embedding) => {
            let emb_str = vec_to_pgvector_literal(&embedding);
            if let Err(e) = repo
                .set_workflow_embedding_from_str(workflow_id, user_id, &emb_str)
                .await
            {
                tracing::warn!(
                    "auto_embed_workflow: failed to store embedding for {}: {:#}",
                    workflow_id,
                    e
                );
            } else {
                tracing::debug!(
                    "auto_embed_workflow: embedded workflow {} ({})",
                    workflow_id,
                    src.name
                );
            }
        }
        Err(e) => {
            tracing::debug!(
                kind = e.kind(),
                workflow = %workflow_id,
                "auto_embed_workflow: embed failed"
            );
        }
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_input_respects_char_boundaries() {
        // 4000 'a' (1-byte) + 4001 'é' (2-byte each) = 12,002 bytes
        // total. EMBED_INPUT_CHAR_BUDGET=8000 falls inside the 'é'
        // run; without boundary-walk-back this would panic on the
        // slice.
        let text = format!("{}{}", "a".repeat(4000), "é".repeat(4001));
        let out = truncate_input(&text);
        assert!(out.len() <= EMBED_INPUT_CHAR_BUDGET);
        assert!(text.starts_with(out));
    }

    // The pre-extraction `nonempty_env_treats_blank_as_unset` test was
    // env-mutation-based; in Rust 2024 / 2026 std::env::set_var is
    // `unsafe`. This crate's `#![forbid(unsafe_code)]` is the right
    // boundary, so the test is dropped — `nonempty_env` is a 1-line
    // wrapper around `std::env::var` + filter that does not warrant
    // its own integration-style test.

    #[test]
    fn embedding_error_kind_slugs_are_stable() {
        // Slugs are referenced by metric labels — changing them
        // silently breaks dashboards/alerts.
        assert_eq!(EmbeddingError::NotConfigured.kind(), "not_configured");
        assert_eq!(EmbeddingError::Network("x".into()).kind(), "network");
        assert_eq!(
            EmbeddingError::ApiError {
                status: 429,
                body: "x".into()
            }
            .kind(),
            "api_error"
        );
        assert_eq!(
            EmbeddingError::DimensionMismatch {
                got: 1,
                expected: 2,
            }
            .kind(),
            "dimension_mismatch",
        );
        assert_eq!(EmbeddingError::InvalidResponse.kind(), "invalid_response");
        assert_eq!(
            EmbeddingError::BatchSizeMismatch {
                returned: 3,
                requested: 5,
            }
            .kind(),
            "batch_size_mismatch",
        );
    }

    #[test]
    fn vec_to_pgvector_literal_brackets_and_comma_separates() {
        assert_eq!(vec_to_pgvector_literal(&[]), "[]");
        assert_eq!(vec_to_pgvector_literal(&[0.5]), "[0.5]");
        assert_eq!(vec_to_pgvector_literal(&[0.1, 0.2, 0.3]), "[0.1,0.2,0.3]");
    }

    #[test]
    fn workflow_embedding_text_drops_empty_parts() {
        let s = workflow_embedding_text("name", Some(""), &[], None);
        assert_eq!(s, "name");

        let s = workflow_embedding_text("name", Some("desc"), &["c1".into()], Some(""));
        assert_eq!(s, "name. desc. c1");
    }

    #[test]
    fn workflow_embedding_text_joins_capabilities() {
        let s = workflow_embedding_text("n", None, &["a".into(), "b".into()], Some("intent"));
        assert_eq!(s, "n. a, b. intent");
    }
}
