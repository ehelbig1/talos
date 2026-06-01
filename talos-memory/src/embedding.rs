//! Embedding client — OpenAI-compatible embeddings endpoint.
//!
//! Configured from env (shared between controller and worker):
//! - `EMBEDDING_API_URL` (default `https://api.openai.com/v1/embeddings`)
//! - `EMBEDDING_API_KEY` or fallback `OPENAI_API_KEY`
//! - `EMBEDDING_MODEL` (default `text-embedding-3-small`)
//! - `EMBEDDING_DIMENSIONS` (default `768` — matches Ollama `nomic-embed-text`)
//!
//! Returns `None` on any failure (missing config, bad response, wrong
//! dimensions). All callers fall back to keyword search when embedding
//! is unavailable, so a misconfigured provider degrades gracefully
//! rather than blocking writes.
//!
//! ## In-memory cache
//!
//! Identical queries within [`CACHE_TTL`] reuse a cached vector rather
//! than re-hitting the provider. Keyed by SHA-256 of the truncated
//! input so variable-length inputs produce fixed-size hash keys. The
//! cache is capped at [`CACHE_MAX_ENTRIES`] with FIFO-by-timestamp
//! eviction — fine for our workloads (repeat semantic queries during
//! a workflow run) and cheap to implement without an LRU crate.

#[derive(Debug, Clone)]
pub struct EmbeddingConfig {
    pub api_url: String,
    pub api_key: Option<String>,
    pub model: String,
    pub dimensions: usize,
}

impl EmbeddingConfig {
    /// Build a fresh `EmbeddingConfig` by reading 4-5 env vars. Most
    /// callers should use [`Self::cached`] instead; this method is kept
    /// for tests that need to bypass the OnceLock cache.
    pub fn from_env() -> Option<Self> {
        Self::from_env_uncached()
    }

    fn from_env_uncached() -> Option<Self> {
        // MCP-620 (2026-05-12): treat empty env values as unset throughout.
        // Pre-fix:
        // - `env::var("EMBEDDING_API_URL").unwrap_or_else(|_| default)` returned
        //   `""` (not the default) when the operator set the var to "".
        // - `env::var("EMBEDDING_API_URL").is_ok()` matched the empty string,
        //   so `explicit_url = true` even when the operator's intent was
        //   "leave this disabled."
        // - `env::var("EMBEDDING_MODEL").unwrap_or_else(|_| default)` had the
        //   same shape.
        // Combined, a Helm `values.yaml` placeholder
        // `embeddingApiUrl: ""` + no API key would produce
        // `EmbeddingConfig { api_url: "", api_key: None, ... }` instead of
        // `None`, then every downstream embedding request fired against an
        // empty URL and failed at HTTP-client-build time. Same fix shape as
        // the canonical `nonempty_env` helper in talos-search-service
        // (which this crate was inconsistent with) and the bedrock
        // MCP-615 `talos_config::get_env` fix.
        fn env_nonempty(key: &str) -> Option<String> {
            std::env::var(key).ok().filter(|v| !v.is_empty())
        }
        let api_key = env_nonempty("EMBEDDING_API_KEY").or_else(|| env_nonempty("OPENAI_API_KEY"));
        let explicit_url = env_nonempty("EMBEDDING_API_URL").is_some();
        let api_url = env_nonempty("EMBEDDING_API_URL")
            .unwrap_or_else(|| "https://api.openai.com/v1/embeddings".to_string());
        if api_key.is_none() && !explicit_url {
            return None;
        }
        let model =
            env_nonempty("EMBEDDING_MODEL").unwrap_or_else(|| "text-embedding-3-small".to_string());
        let dimensions = env_nonempty("EMBEDDING_DIMENSIONS")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(768);
        Some(EmbeddingConfig {
            api_url,
            api_key,
            model,
            dimensions,
        })
    }

    /// L-3: cached snapshot of the embedding config, computed on first
    /// use and reused for the process lifetime.
    ///
    /// `generate_embedding` is on the hot path of every memory write
    /// + every semantic-search call; the previous code re-read 4-5 env
    /// vars per invocation. Caching matches `request_timeout_secs`'s
    /// pattern (also `OnceLock`-backed) so config-rotation semantics
    /// are uniform across the file: env-var changes require a process
    /// restart for both embedding URL/key/model/dimensions AND timeout.
    /// Operators rotate by re-deploying, never by editing env in
    /// place — same as the rest of the controller.
    pub fn cached() -> Option<Self> {
        static CACHED: std::sync::OnceLock<Option<EmbeddingConfig>> = std::sync::OnceLock::new();
        CACHED.get_or_init(Self::from_env_uncached).clone()
    }

    pub fn describe(&self) -> String {
        format!(
            "model={}, endpoint={}, dimensions={}",
            self.model, self.api_url, self.dimensions
        )
    }
}

/// Generate an embedding for `text`, or return `None` if the provider
/// is unconfigured / unreachable / returns a dimension mismatch.
///
/// ## Latency budget
///
/// A single embedding call gets at most the configured timeout per
/// attempt and we retry exactly once on connect / request errors.
/// This prevents slow-provider pathology from burning WASM fuel inside
/// sandbox `agent_memory::search` calls — the previous 15 s timeout
/// let a single stuck Ollama call chew through the default 1 M fuel
/// budget before the sandbox even got control back. On degradation we
/// log at WARN so operators can see the provider is slow without
/// reading every callsite.
///
/// The 8 s default covers Ollama cold-start (nomic-embed-text ~5 s from
/// idle → first token after a container restart) without being so
/// generous that a persistently stuck provider pins a fuel-bounded
/// sandbox call. Override via `EMBEDDING_TIMEOUT_SECS` (range 1–60)
/// if your provider is slower (e.g. large local model on CPU-only) or
/// you want a tighter ceiling for hot-path cache-miss calls.
pub const REQUEST_TIMEOUT_SECS_DEFAULT: u64 = 8;

fn request_timeout_secs() -> u64 {
    static CACHED: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *CACHED.get_or_init(|| {
        std::env::var("EMBEDDING_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| (1..=60).contains(v))
            .unwrap_or(REQUEST_TIMEOUT_SECS_DEFAULT)
    })
}

/// Legacy constant — kept for anywhere external callers still read it.
/// Prefer `request_timeout_secs()` which honors the env override.
pub const REQUEST_TIMEOUT_SECS: u64 = REQUEST_TIMEOUT_SECS_DEFAULT;

/// Maximum cached embeddings. Keep modest — the real hit rate comes
/// from hot queries within a single workflow execution, not long-term
/// caching.
pub const CACHE_MAX_ENTRIES: usize = 128;
/// Cache TTL. Embedding models don't change mid-deployment so this
/// could be much longer, but keeping it short bounds staleness if
/// the provider/model is swapped at runtime.
pub const CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(300);

struct CacheEntry {
    vector: Vec<f32>,
    inserted_at: std::time::Instant,
}

static EMBEDDING_CACHE: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<[u8; 32], CacheEntry>>,
> = std::sync::LazyLock::new(|| {
    std::sync::Mutex::new(std::collections::HashMap::with_capacity(CACHE_MAX_ENTRIES))
});

#[cfg(test)]
pub(crate) fn cache_key_for_test(model: &str, input: &str) -> [u8; 32] {
    cache_key(model, input)
}

fn cache_key(model: &str, input: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    // Mix in the model name so changing EMBEDDING_MODEL invalidates
    // old vectors automatically — the dimensionality check would
    // reject them anyway, but this keeps the cache honest.
    hasher.update(model.as_bytes());
    hasher.update([0]);
    hasher.update(input.as_bytes());
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

fn cache_lookup(key: &[u8; 32]) -> Option<Vec<f32>> {
    let guard = EMBEDDING_CACHE.lock().ok()?;
    let entry = guard.get(key)?;
    if entry.inserted_at.elapsed() > CACHE_TTL {
        return None;
    }
    Some(entry.vector.clone())
}

fn cache_insert(key: [u8; 32], vector: Vec<f32>) {
    let Ok(mut guard) = EMBEDDING_CACHE.lock() else {
        return;
    };
    // Evict expired entries opportunistically on every insert so the
    // map doesn't grow without bound when keys churn.
    let now = std::time::Instant::now();
    guard.retain(|_, v| now.duration_since(v.inserted_at) < CACHE_TTL);
    if guard.len() >= CACHE_MAX_ENTRIES {
        // Drop the oldest entry. O(n) scan — fine at 128 entries.
        if let Some(oldest_key) = guard
            .iter()
            .min_by_key(|(_, v)| v.inserted_at)
            .map(|(k, _)| *k)
        {
            guard.remove(&oldest_key);
        }
    }
    guard.insert(
        key,
        CacheEntry {
            vector,
            inserted_at: std::time::Instant::now(),
        },
    );
}

/// In-flight map: when a miss is outstanding, concurrent callers
/// share the same `OnceCell` rather than each launching their own
/// HTTP request. Prevents thundering herd on hot queries that arrive
/// at the same time from multiple sandboxes.
///
/// `DashMap` rather than `Mutex<HashMap>` so concurrent embedding
/// requests for *different* keys don't serialize through one lock.
type InFlightCell = std::sync::Arc<tokio::sync::OnceCell<Option<Vec<f32>>>>;
type InFlightMap = dashmap::DashMap<[u8; 32], InFlightCell>;

static IN_FLIGHT: std::sync::LazyLock<InFlightMap> =
    std::sync::LazyLock::new(dashmap::DashMap::new);

/// RAII guard that removes the in-flight entry when dropped, even
/// if the awaiting future panics. Without this, a panic mid-
/// `do_embedding_request` would orphan the OnceCell in `IN_FLIGHT`
/// and future callers would await it forever (well — for our 7.5 s
/// timeout under the old polling design; with `get_or_init` they'd
/// re-init it themselves, but the entry would still leak memory).
struct InFlightGuard<'a> {
    map: &'a InFlightMap,
    key: [u8; 32],
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.map.remove(&self.key);
    }
}

pub async fn generate_embedding(text: &str) -> Option<Vec<f32>> {
    // L-3: serve config from the OnceLock-backed cache. First call pays
    // the env-var read cost; subsequent calls are a single Arc clone.
    let config = EmbeddingConfig::cached()?;
    // MCP-479: byte-slice at fixed offset 8000 panics when byte 8000 falls
    // inside a multi-byte UTF-8 sequence. `text` is user-supplied actor-
    // memory content; an attacker can store an 8001-byte memory containing
    // a multi-byte codepoint at position 8000 and crash this entry point
    // on every subsequent embedding generation for that actor. Cross-
    // tenant impact bounded to the actor's own scope, but still a real
    // stability bug. Walk backward from 8000 to the nearest char boundary;
    // worst-case loses up to 3 bytes (a 4-byte UTF-8 char).
    // MCP-1050: route through canonical helper. Pre-fix was an inline
    // char-boundary walk-back identical to `talos_text_util::
    // truncate_at_char_boundary(text, 8000)`. Helper returns a `&str`
    // (borrowed slice) so the API call site below sees the same shape.
    let truncated = talos_text_util::truncate_at_char_boundary(text, 8000);

    let key = cache_key(&config.model, truncated);
    if let Some(cached) = cache_lookup(&key) {
        return Some(cached);
    }

    // Thundering-herd dedupe: concurrent callers awaiting the same
    // key share one OnceCell. Only the first caller's init future
    // actually runs; followers await the same shared result via
    // `get_or_init` — no polling, no race, no leader/follower split.
    //
    // We use the DashMap Entry API to detect the leader (the caller
    // that actually inserted) so that ONLY the leader installs an
    // RAII cleanup guard. If every caller had a guard, a follower
    // dropping (cancellation, timeout, panic) mid-flight would
    // remove the IN_FLIGHT entry and any new arrival would launch
    // a fresh HTTP call — defeating the dedupe. Leader-only
    // cleanup means the entry survives until the leader's task
    // unwinds, no matter what followers do.
    use dashmap::mapref::entry::Entry;
    let (cell, is_leader) = match IN_FLIGHT.entry(key) {
        Entry::Occupied(e) => (e.get().clone(), false),
        Entry::Vacant(e) => {
            let cell = std::sync::Arc::new(tokio::sync::OnceCell::new());
            e.insert(cell.clone());
            (cell, true)
        }
    };

    // Only the leader holds the cleanup guard. Followers Drop
    // without affecting the IN_FLIGHT entry, so concurrent
    // newcomers continue to share the leader's cell.
    let _guard = is_leader.then(|| InFlightGuard {
        map: &IN_FLIGHT,
        key,
    });

    let result = cell
        .get_or_init(|| do_embedding_request(&config, truncated))
        .await
        .clone();

    if let Some(ref v) = result {
        cache_insert(key, v.clone());
    }
    result
}

/// MCP-1111 (2026-05-16): cache the hardened embedding HTTP client at
/// module scope so `do_embedding_request` doesn't rebuild it per call.
/// Sibling-sweep of MCP-1110 (talos-search-service) — same anti-pattern
/// across both embedding clients: per-call `reqwest::Client::builder()`
/// → fresh TLS context + fresh connection pool → zero keep-alive
/// reuse → TCP+TLS handshake on every embed request.
///
/// Hot path: every `recall_semantic` / `recall_semantic_filtered` /
/// `persist_memory_with_metadata` invocation through memory_rpc hits
/// this on cache miss. The `cache_insert` LRU at line ~307 above
/// dedupes WITHIN-process repeat queries; cross-process and cross-
/// pod recalls still pay the embed request, so the per-call client
/// rebuild was visible at production memory-rpc QPS.
///
/// Behaviour change: pre-fix `.build().ok()?` silently returned None
/// on TLS-init failure, degrading every embed call to keyword
/// fallback for the pod's lifetime with no panic / no log line.
/// Post-fix `.expect()` matches the sibling MCP-1110 pattern —
/// TLS init failure is a deployment-time issue (broken system roots,
/// OS misconfiguration), surfacing it loudly at first call beats
/// silent semantic-search degradation. MCP-1034 timeout +
/// connect_timeout + MCP-520 redirect policy preserved exactly.
///
/// `request_timeout_secs()` is itself OnceLock-cached (see fn at
/// line ~126) so reading it inside the LazyLock initialiser is
/// equivalent to reading it once at first embed call.
static EMBED_HTTP_CLIENT: std::sync::LazyLock<reqwest::Client> = std::sync::LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(request_timeout_secs()))
        .connect_timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("talos-memory: failed to build embedding HTTP client (TLS init)")
});

async fn do_embedding_request(config: &EmbeddingConfig, truncated: &str) -> Option<Vec<f32>> {
    // MCP-520: same Mode-B credential-leak class as the sibling
    // `talos-search-service` embedding client. Operator-configured
    // `EMBEDDING_API_URL` + `bearer_auth(key)` means a same-origin
    // redirect (legit provider → its CDN) preserves the Authorization
    // header into the redirect target. Disable redirects entirely;
    // every supported embedding API answers the request without one.
    // MCP-1034: explicit connect_timeout so a black-holed
    // EMBEDDING_API_URL (network partition, DNS failure, slow-loris
    // on TCP-handshake) fails fast — without it, the embedding
    // request pins the pool until request_timeout_secs() fires.
    // MCP-1111: shared once-built client (see EMBED_HTTP_CLIENT
    // above). One TLS context + one connection pool process-wide.
    let client: &reqwest::Client = &EMBED_HTTP_CLIENT;

    let body = serde_json::json!({
        "input": truncated,
        "model": config.model,
    });

    // Two attempts total — first fast; if that fails on connect/timeout
    // (not on a real 4xx/5xx) try once more. Anything beyond two
    // attempts should degrade to keyword fallback instead of pinning a
    // worker thread.
    let mut last_err: Option<String> = None;
    for attempt in 0..2 {
        let mut req = client.post(&config.api_url).json(&body);
        if let Some(ref key) = config.api_key {
            req = req.bearer_auth(key);
        }
        match req.send().await {
            Ok(resp) if resp.status().is_success() => {
                // Bounded read, NOT unbounded `resp.json()` — OOM
                // defense-in-depth on the controller (talos-http-body).
                let body = match talos_http_body::read_body_capped(
                    resp,
                    talos_http_body::DEFAULT_MAX_RESPONSE_BYTES,
                )
                .await
                {
                    Ok(b) => b,
                    Err(e) => {
                        last_err = Some(e.to_string());
                        continue;
                    }
                };
                let json: serde_json::Value = match serde_json::from_slice(&body) {
                    Ok(j) => j,
                    Err(e) => {
                        last_err = Some(format!("json decode: {e}"));
                        continue;
                    }
                };
                let embedding: Vec<f32> = match json
                    .get("data")
                    .and_then(|d| d.get(0))
                    .and_then(|d| d.get("embedding"))
                    .and_then(|e| e.as_array())
                {
                    Some(arr) => arr
                        .iter()
                        .filter_map(|v| v.as_f64().map(|f| f as f32))
                        .collect(),
                    None => {
                        last_err = Some("malformed response shape".to_string());
                        continue;
                    }
                };
                if embedding.len() == config.dimensions {
                    // Cache insertion is done by the caller
                    // (`generate_embedding`) so the dedupe path can
                    // populate cache AND the OnceCell atomically.
                    return Some(embedding);
                }
                tracing::warn!(
                    got = embedding.len(),
                    expected = config.dimensions,
                    model = %config.model,
                    "Embedding provider returned unexpected dimension count — no retry"
                );
                return None;
            }
            Ok(resp) => {
                let status = resp.status();
                if status.is_client_error() {
                    tracing::warn!(
                        status = %status,
                        url = %config.api_url,
                        "Embedding API 4xx — no retry"
                    );
                    return None;
                }
                last_err = Some(format!("http {status}"));
            }
            Err(e) => {
                last_err = Some(format!(
                    "{}{}",
                    if e.is_timeout() {
                        "timeout: "
                    } else {
                        "transport: "
                    },
                    e
                ));
            }
        }
        if attempt == 0 {
            tracing::debug!(
                url = %config.api_url,
                error = ?last_err,
                "Embedding API transient failure — retrying once"
            );
        }
    }
    tracing::warn!(
        url = %config.api_url,
        error = ?last_err,
        "Embedding API unavailable after retry — falling back to keyword search"
    );
    None
}

/// Fire-and-forget embedding warmup. Call once at controller startup to
/// trigger the provider's model load before the first user-facing call.
///
/// Why: local providers like Ollama lazy-load models into VRAM/RAM on
/// first request (3–5 s for nomic-embed-text). Without warmup, the very
/// first `persist_memory_with_metadata` or `actor_memory::search` call
/// after a container restart times out on cold-start, writes a row with
/// `embedding = NULL`, and future searches on that row silently degrade
/// to keyword fallback. Warmup avoids that cliff.
///
/// No-op if the embedding provider isn't configured (the inner
/// `generate_embedding` returns None). Spawned as a background task by
/// the caller so controller startup isn't delayed by a slow provider.
pub async fn warmup() {
    let started = std::time::Instant::now();
    let result = generate_embedding("talos embedding warmup ping").await;
    match result {
        Some(v) => tracing::info!(
            dims = v.len(),
            duration_ms = started.elapsed().as_millis() as u64,
            "Embedding provider warmup OK — model loaded"
        ),
        None => tracing::warn!(
            duration_ms = started.elapsed().as_millis() as u64,
            "Embedding provider warmup failed — memory writes will degrade \
             to no-embedding (searches fall back to keyword). \
             Configure EMBEDDING_API_URL + EMBEDDING_TIMEOUT_SECS or disable."
        ),
    }
}
