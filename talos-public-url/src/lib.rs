//! Public base-URL resolution for externally-reachable endpoints.
//!
//! Local dev runs behind localhost, but three endpoint families must be
//! reachable from the outside to work at all: Pub/Sub push targets
//! (`/api/gcp/pubsub/{token}`), Google watch webhooks
//! (`/api/google-calendar/webhook`), and inbound webhooks
//! (`/webhooks/{id}`), plus human-clicked approval links. This crate
//! answers "what public origin should those URLs be formatted with?"
//! from ONE place, with a three-step resolution chain:
//!
//!   1. **`TALOS_PUBLIC_BASE_URL`** — explicit operator override
//!      (production origin, or a hand-managed tunnel). Validated with
//!      the same predicate as `FRONTEND_URL` (scheme + host, no path —
//!      the open-redirect-misconfig defense); an invalid value is
//!      WARNed and ignored rather than half-used.
//!   2. **ngrok discovery** — when `TALOS_NGROK_API_URL` is set (the
//!      compose `public` profile points it at the ngrok sidecar's local
//!      API), a background task polls `/api/tunnels` and caches the
//!      https tunnel origin. First resolution logs loudly; a CHANGE
//!      (tunnel restart without a reserved domain) logs a WARN naming
//!      the externally-registered things that now point at a dead URL.
//!   3. **Caller fallback** — [`public_base_url_or`] takes the
//!      caller's legacy default (`get_frontend_url` for nginx-proxied
//!      paths, `get_base_url` for controller-direct paths) so behavior
//!      without a tunnel is byte-identical to before this crate.
//!
//! OAuth redirect URIs deliberately do NOT route through here: they
//! must match the provider console's allowlist, and the browser-mediated
//! localhost redirect works fine in dev. Only server-reachable endpoint
//! construction uses the public base. See docs/local-public-url.md.

use arc_swap::ArcSwapOption;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::OnceLock;

/// Latest tunnel origin discovered from the ngrok agent API. `None`
/// until the first successful poll (or forever, when no sidecar runs).
static DISCOVERED: OnceLock<ArcSwapOption<String>> = OnceLock::new();
/// Whether the last poll attempt reached the ngrok API at all — feeds
/// the MCP status surface so "sidecar down" and "no tunnel yet" are
/// distinguishable.
static API_REACHABLE: AtomicBool = AtomicBool::new(false);

fn discovered_cell() -> &'static ArcSwapOption<String> {
    DISCOVERED.get_or_init(ArcSwapOption::empty)
}

/// Where the resolved public base URL came from — surfaced by the MCP
/// status tool so operators can see which layer of the chain is active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlSource {
    /// `TALOS_PUBLIC_BASE_URL` env override.
    Explicit,
    /// Discovered from the ngrok sidecar's agent API.
    Ngrok,
    /// Neither — the caller's legacy fallback is in effect.
    Fallback,
}

impl UrlSource {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Explicit => "explicit",
            Self::Ngrok => "ngrok",
            Self::Fallback => "fallback",
        }
    }
}

/// The explicit override, if set AND valid. Invalid values WARN once
/// per call site invocation (cheap; boot + rare formatting paths).
fn explicit_override() -> Option<String> {
    let raw = std::env::var("TALOS_PUBLIC_BASE_URL").ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if talos_config::is_valid_frontend_url(trimmed) {
        return Some(trimmed.trim_end_matches('/').to_string());
    }
    tracing::warn!(
        value = %trimmed,
        "TALOS_PUBLIC_BASE_URL failed validation (must be http(s)://host with no path) — ignoring"
    );
    None
}

/// The ngrok-discovered origin, if any.
#[must_use]
pub fn discovered() -> Option<String> {
    discovered_cell().load_full().map(|s| (*s).clone())
}

/// Resolve the public base URL, falling back to `fallback()` when no
/// explicit override is set and no tunnel has been discovered. The
/// fallback is lazy so callers keep their exact legacy default
/// (`get_frontend_url` vs `get_base_url`).
pub fn public_base_url_or(fallback: impl FnOnce() -> String) -> String {
    resolve(fallback).0
}

/// [`public_base_url_or`] plus which chain step answered.
pub fn resolve(fallback: impl FnOnce() -> String) -> (String, UrlSource) {
    if let Some(explicit) = explicit_override() {
        return (explicit, UrlSource::Explicit);
    }
    if let Some(tunnel) = discovered() {
        return (tunnel, UrlSource::Ngrok);
    }
    (fallback(), UrlSource::Fallback)
}

/// Whether the last discovery attempt reached the ngrok agent API.
#[must_use]
pub fn ngrok_api_reachable() -> bool {
    API_REACHABLE.load(Ordering::Relaxed)
}

/// Extract the public https tunnel origin from an ngrok
/// `GET /api/tunnels` response body. Prefers the `https` tunnel; falls
/// back to the first tunnel whose `public_url` validates. Pure — unit
/// tested without an agent.
#[must_use]
pub fn extract_public_url(body: &serde_json::Value) -> Option<String> {
    let tunnels = body.get("tunnels")?.as_array()?;
    let url_of = |t: &serde_json::Value| {
        t.get("public_url")
            .and_then(|u| u.as_str())
            .map(|u| u.trim_end_matches('/').to_string())
            .filter(|u| talos_config::is_valid_frontend_url(u))
    };
    tunnels
        .iter()
        .filter(|t| t.get("proto").and_then(|p| p.as_str()) == Some("https"))
        .find_map(url_of)
        .or_else(|| tunnels.iter().find_map(url_of))
}

/// Spawn the background discovery loop. No-op (with a debug log) when
/// `TALOS_NGROK_API_URL` is unset. The loop polls the agent API every
/// `TALOS_PUBLIC_URL_REFRESH_SECS` (default 60, min 10); unreachable
/// agents log at debug (the sidecar is optional — the `public` compose
/// profile may simply be off), while a discovered-then-lost tunnel and
/// a CHANGED tunnel URL log at WARN because externally-registered
/// endpoints go stale at that moment.
pub fn spawn_discovery() {
    let Ok(api_base) = std::env::var("TALOS_NGROK_API_URL") else {
        tracing::debug!("TALOS_NGROK_API_URL unset — ngrok public-URL discovery disabled");
        return;
    };
    let api_base = api_base.trim().trim_end_matches('/').to_string();
    if api_base.is_empty() {
        return;
    }
    let interval_secs = std::env::var("TALOS_PUBLIC_URL_REFRESH_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map_or(60, |v| v.max(10));

    tokio::spawn(async move {
        let client = talos_http_utils::trusted_client::build_integration_client(
            std::time::Duration::from_secs(5),
        );
        let tunnels_url = format!("{api_base}/api/tunnels");
        loop {
            match poll_once(&client, &tunnels_url).await {
                Ok(Some(url)) => {
                    API_REACHABLE.store(true, Ordering::Relaxed);
                    let prev = discovered_cell().swap(Some(Arc::new(url.clone())));
                    match prev.as_deref() {
                        None => {
                            tracing::info!(
                                public_url = %url,
                                "🌐 ngrok tunnel discovered — externally-reachable endpoints \
                                 (Pub/Sub push, watch webhooks, inbound webhooks, approval links) \
                                 now format with this origin. Run the get_public_url_status MCP \
                                 tool for per-integration setup instructions."
                            );
                        }
                        Some(old) if *old != url => {
                            tracing::warn!(
                                old_url = %old,
                                new_url = %url,
                                "ngrok tunnel URL CHANGED — Pub/Sub push subscriptions, Google \
                                 watch channels, and any provider-side registrations still point \
                                 at the OLD origin and will fail until updated. Run \
                                 get_public_url_status for the commands (a reserved ngrok domain \
                                 via NGROK_STATIC_DOMAIN eliminates this class)."
                            );
                        }
                        _ => {}
                    }
                }
                Ok(None) => {
                    // Agent up, no usable tunnel (yet). Keep any previous
                    // value — a transient agent restart shouldn't flap
                    // formatted URLs back to localhost.
                    API_REACHABLE.store(true, Ordering::Relaxed);
                    tracing::debug!("ngrok agent reachable but no https tunnel found");
                }
                Err(e) => {
                    let was_reachable = API_REACHABLE.swap(false, Ordering::Relaxed);
                    if was_reachable {
                        tracing::warn!(
                            error = %e,
                            "ngrok agent API became unreachable — keeping last-known public URL"
                        );
                    } else {
                        tracing::debug!(error = %e, "ngrok agent API not reachable");
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
        }
    });
}

async fn poll_once(client: &reqwest::Client, tunnels_url: &str) -> anyhow::Result<Option<String>> {
    let resp = client.get(tunnels_url).send().await?;
    // Capped read (lint 31) — the agent API is local + trusted, but the
    // OOM-bound discipline is uniform across every outbound read.
    let body: serde_json::Value = talos_http_body::read_json_capped(resp).await?;
    Ok(extract_public_url(&body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extracts_https_tunnel_preferentially() {
        let body = json!({"tunnels": [
            {"proto": "http", "public_url": "http://abc.ngrok-free.app"},
            {"proto": "https", "public_url": "https://abc.ngrok-free.app"},
        ]});
        assert_eq!(
            extract_public_url(&body).as_deref(),
            Some("https://abc.ngrok-free.app")
        );
    }

    #[test]
    fn falls_back_to_any_valid_tunnel_and_strips_trailing_slash() {
        let body = json!({"tunnels": [
            {"proto": "http", "public_url": "http://abc.ngrok-free.app/"},
        ]});
        assert_eq!(
            extract_public_url(&body).as_deref(),
            Some("http://abc.ngrok-free.app")
        );
    }

    #[test]
    fn rejects_invalid_or_missing_tunnels() {
        assert!(extract_public_url(&json!({"tunnels": []})).is_none());
        assert!(extract_public_url(&json!({})).is_none());
        // A public_url with a path fails the origin validator.
        let body = json!({"tunnels": [
            {"proto": "https", "public_url": "https://abc.ngrok-free.app/some/path"},
        ]});
        assert!(extract_public_url(&body).is_none());
    }

    #[test]
    fn resolve_falls_back_when_nothing_discovered() {
        // No env override in the test environment for this var name and
        // no discovery has run — the caller's fallback must win.
        let (url, source) = resolve(|| "http://localhost:8000".to_string());
        assert_eq!(source, UrlSource::Fallback);
        assert_eq!(url, "http://localhost:8000");
    }
}
