//! Cached embedding-provider health probe. Lifted from
//! `talos-mcp-handlers/src/search.rs` verbatim during the r305
//! SearchService extraction.
//!
//! Pre-r241 `embedding_provider_available()` was a syntactic check:
//! it only validated that the env vars were *set*, not that the URL
//! actually responded. We hit the false-positive in prod when
//! `EMBEDDING_API_URL` pointed at a non-existent in-cluster Ollama
//! service — every probe reported "available" while every embed
//! request failed at the network layer.
//!
//! r241: a real round-trip ("ok" → 1-token embed) at boot + every 5
//! min. `embedding_provider_available()` reads from cache (lock-free
//! via `ArcSwap`), so the hot path stays cheap and the truth is
//! grounded in actual provider behaviour. The cached `last_error` is
//! exposed via `embedding_provider_status` for surfacing in
//! `session_start`.

use std::sync::{Arc, LazyLock, OnceLock};
use std::time::Duration;

use arc_swap::ArcSwap;
use regex::Regex;

use crate::embedding::{generate_embedding, EmbeddingError};

/// MCP-634 (2026-05-12): URL-stripping regex used by `sanitize_last_error`.
///
/// `EmbeddingError::Network(reqwest_err.to_string())` embeds the
/// configured `EMBEDDING_API_URL` on connection failures (DNS,
/// connect-refused, TLS). The cached `last_error` is exposed to MCP
/// callers via `session_start.provider_last_error`, which means a
/// cluster-internal hostname like
/// `http://embedding.talos.svc.cluster.local:8080/embed` leaks to any
/// authenticated MCP client. Same enumeration class as MCP-217
/// (Ollama URL leak via show_model error).
///
/// `&str` `to_string()` panics are not a concern — we operate on
/// `&str` from `EmbeddingError::Display`. Compiled once at first use.
static URL_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    // Match http(s):// followed by any non-whitespace run, then a
    // trim pass strips trailing punctuation that's almost certainly
    // not part of the URL itself ()", >, ], }, ., ,, ;).
    Regex::new("https?://[^ \t\n\r]+")
        .expect("BUG: provider-health URL strip regex must compile")
});

/// MCP-634/MCP-768: strip URL-looking substrings from an error string
/// before exposing to authenticated callers, so cluster-internal
/// endpoints don't leak via response bodies (`session_start.provider_last_error`
/// MCP-634, `handle_generate_workflow_embeddings` errors[] array MCP-768)
/// or any other surface that echoes provider errors back to the caller.
/// Preserves the surrounding categorical text so operators still see
/// "DNS lookup failed" / "connection refused" / "HTTP 429" — just
/// without the URL.
///
/// **Where to use:** any code path that formats an `EmbeddingError`
/// (or raw reqwest error string from the embedding stack) into a
/// caller-bound response. Controller-side logs MAY keep the raw URL —
/// operator visibility outweighs URL hygiene in the controller's own
/// log stream — but anything that ships back over the wire must
/// sanitize first.
pub fn sanitize_provider_error_for_caller(raw: String) -> String {
    URL_PATTERN.replace_all(&raw, "<url>").into_owned()
}

#[derive(Clone, Debug)]
pub struct ProviderHealth {
    pub available: bool,
    pub last_error: Option<String>,
}

impl Default for ProviderHealth {
    fn default() -> Self {
        Self {
            available: false,
            last_error: Some("not yet probed".to_string()),
        }
    }
}

static PROVIDER_HEALTH: OnceLock<ArcSwap<ProviderHealth>> = OnceLock::new();

fn provider_health_cell() -> &'static ArcSwap<ProviderHealth> {
    PROVIDER_HEALTH.get_or_init(|| ArcSwap::from_pointee(ProviderHealth::default()))
}

/// Returns the cached availability — `true` iff the last probe
/// succeeded. Lock-free read; safe to call from hot paths.
pub fn embedding_provider_available() -> bool {
    provider_health_cell().load().available
}

/// Returns `(available, last_error)` so `session_start` can surface
/// the actual provider failure mode instead of just "unavailable."
/// `last_error` is the stringified `EmbeddingError` from the most
/// recent probe.
pub fn embedding_provider_status() -> (bool, Option<String>) {
    let g = provider_health_cell().load();
    (g.available, g.last_error.clone())
}

/// Run a real round-trip against the configured provider and
/// atomically update the cached health. Called from `main.rs` at
/// boot AND from the background refresh task every 5 minutes
/// (`PROVIDER_PROBE_INTERVAL`).
///
/// The probe consumes one rate-limit token (same code path as real
/// embeds) — under the default 60 RPM cap that's 12 probes/hour
/// worst case, well inside any provider's free tier.
pub async fn refresh_embedding_provider_health() {
    let (available, last_error) = match generate_embedding("ok").await {
        Ok(_) => (true, None),
        Err(e @ EmbeddingError::NotConfigured) => (false, Some(e.to_string())),
        Err(e) => {
            // Once-per-process WARN for the not-configured case is
            // replaced by the boot-time WARN in main.rs; for
            // transient/network errors we log at INFO so operators
            // can correlate "search returned no results" with
            // provider state without spamming WARN every 5 min.
            //
            // Server-side log keeps the full error (`%e`) — operator
            // visibility matters more than internal-URL hygiene in
            // the controller's own log stream. The CACHED string that
            // gets exposed via `session_start.provider_last_error` is
            // sanitized below.
            tracing::info!(
                kind = e.kind(),
                error = %e,
                "embedding provider probe failed"
            );
            (false, Some(sanitize_provider_error_for_caller(e.to_string())))
        }
    };
    provider_health_cell().store(Arc::new(ProviderHealth {
        available,
        last_error,
    }));
}

/// Background task interval for the provider health probe.
pub const PROVIDER_PROBE_INTERVAL: Duration = Duration::from_secs(300);

#[cfg(test)]
mod tests {
    use super::sanitize_provider_error_for_caller as sanitize_last_error;

    #[test]
    fn strips_internal_cluster_url_from_reqwest_error() {
        // MCP-634: representative reqwest connection-failure shape.
        // The cluster-internal hostname MUST NOT survive into the
        // string that gets exposed to authenticated MCP callers via
        // `session_start.provider_last_error`.
        let raw = "embedding HTTP request failed: error sending request \
                   for url (http://embedding.talos.svc.cluster.local:8080/embed): \
                   error trying to connect: dns error: failed to lookup address"
            .to_string();
        let sanitized = sanitize_last_error(raw);
        assert!(
            !sanitized.contains("cluster.local"),
            "internal URL must be stripped: {sanitized}"
        );
        assert!(
            !sanitized.contains("http://"),
            "http:// scheme must be stripped: {sanitized}"
        );
        // Categorical context preserved so operators still know "DNS failed".
        assert!(
            sanitized.contains("dns error"),
            "failure-mode context must survive: {sanitized}"
        );
    }

    #[test]
    fn strips_https_endpoint_url() {
        let raw = "embedding HTTP request failed: error sending request \
                   for url (https://api.openai.com/v1/embeddings): timeout"
            .to_string();
        let sanitized = sanitize_last_error(raw);
        assert!(!sanitized.contains("api.openai.com"));
        assert!(sanitized.contains("timeout"));
    }

    #[test]
    fn passthrough_when_no_url() {
        let raw = "embedding response had 768 dimensions, expected 1536".to_string();
        assert_eq!(sanitize_last_error(raw.clone()), raw);
    }
}
