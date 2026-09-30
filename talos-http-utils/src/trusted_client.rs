//! Hardened reqwest client for outbound calls to a FIXED, TRUSTED host —
//! OAuth providers (accounts.google.com, auth.atlassian.com, slack.com),
//! provider APIs (googleapis.com, api.atlassian.com), HashiCorp Vault, etc.
//!
//! This is the counterpart to [`crate::outbound`]: that module builds clients
//! for USER/CALLER-SUPPLIED URLs and additionally installs the SSRF-rebinding
//! DNS resolver. A fixed trusted host is a compile-time constant, so it needs no
//! SSRF resolver — but every such client still needs the SAME baseline the
//! integration crates were each hand-rolling (and occasionally drifting on):
//!
//! * `redirect(Policy::none())` — requests carry `Authorization: Bearer <token>`
//!   or `X-Vault-Token` etc.; a compromised or misconfigured host that returns a
//!   3xx to `attacker.com` would otherwise leak the credential (reqwest strips
//!   `Authorization`/`Cookie` on cross-origin redirects but NOT custom headers).
//!   MCP-533 / MCP-571 / MCP-572 fixed this crate-by-crate; this is the single
//!   source of truth so a NEW integration can't reintroduce it.
//! * `connect_timeout(5s)` + `timeout(..)` — a black-holed host fails fast
//!   instead of wedging the connection pool until the overall timeout (MCP-1034).
//!
//! Integration crates should build every outbound client through
//! [`hardened_client_builder`] / [`build_integration_client`] rather than
//! `reqwest::Client::builder()` directly (enforced by `scripts/lint-structural.sh`).

use std::time::Duration;

/// Connect-timeout applied to every hardened client — matches the
/// outbound-webhook client so a wedged host fails fast on the TCP handshake.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// A hardened reqwest [`ClientBuilder`](reqwest::ClientBuilder) for a fixed,
/// trusted host: `redirect(Policy::none())` + `connect_timeout(5s)` +
/// `timeout(timeout)`. Returns the builder (not a built client) so callers can
/// layer on host-specific config — e.g. an in-cluster private CA root for a
/// self-signed Vault — before `.build()`. When no extra config is needed, prefer
/// [`build_integration_client`].
#[must_use]
pub fn hardened_client_builder(timeout: Duration) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(CONNECT_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
}

/// Convenience: [`hardened_client_builder`] built into a [`Client`](reqwest::Client).
///
/// Panics on the (config-only, deterministic) build failure — matching the
/// `.expect()` discipline the integrations already use, so a broken rustls/TLS
/// stack surfaces loudly at startup rather than as endlessly-retrying refreshes.
#[must_use]
pub fn build_integration_client(timeout: Duration) -> reqwest::Client {
    hardened_client_builder(timeout)
        .build()
        .expect("failed to build hardened integration HTTP client")
}

/// Longest rendering [`error_chain`] returns, in characters.
const MAX_ERROR_CHAIN_CHARS: usize = 512;

/// An error and every `source()` beneath it, joined with `": "`, bounded to
/// [`MAX_ERROR_CHAIN_CHARS`].
///
/// reqwest's own `Display` stops at the outermost layer — `error sending
/// request for url (...)` — which says a request failed and not why. The
/// sources name the layer: `dns error`, `tcp connect error`, `operation timed
/// out`, a TLS failure. A layer whose text the rendering already contains is
/// skipped, since hyper and reqwest often repeat their child's message.
///
/// For a log field about a request to a FIXED, trusted host: the URL in the
/// outermost message is that host's, and no layer carries a request header or
/// body. Do not use it on an error from a caller-supplied URL without first
/// deciding that URL may be logged.
#[must_use]
pub fn error_chain(err: &(dyn std::error::Error + 'static)) -> String {
    let mut out = err.to_string();
    let mut source = err.source();
    while let Some(layer) = source {
        let text = layer.to_string();
        if !text.is_empty() && !out.contains(&text) {
            out.push_str(": ");
            out.push_str(&text);
        }
        source = layer.source();
    }
    if out.chars().count() > MAX_ERROR_CHAIN_CHARS {
        out = out.chars().take(MAX_ERROR_CHAIN_CHARS).collect();
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct Layer(&'static str, Option<Box<Layer>>);
    impl std::fmt::Display for Layer {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.0)
        }
    }
    impl std::error::Error for Layer {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.1
                .as_deref()
                .map(|l| l as &(dyn std::error::Error + 'static))
        }
    }

    #[test]
    fn error_chain_names_every_layer_once() {
        let e = Layer(
            "error sending request for url (https://example.test/)",
            Some(Box::new(Layer(
                "client error (Connect)",
                Some(Box::new(Layer(
                    "dns error",
                    Some(Box::new(Layer("dns error", None))),
                ))),
            ))),
        );
        assert_eq!(
            error_chain(&e),
            "error sending request for url (https://example.test/): client error (Connect): dns error"
        );
        let long = Layer(Box::leak("x".repeat(2_000).into_boxed_str()), None);
        assert_eq!(
            error_chain(&long).chars().count(),
            MAX_ERROR_CHAIN_CHARS + 1
        );
    }

    /// A real reqwest failure carries its cause below the top layer.
    #[tokio::test]
    async fn error_chain_shows_the_cause_of_a_reqwest_failure() {
        // A bound-then-dropped port on loopback: nothing listens there.
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let err = build_integration_client(Duration::from_secs(5))
            .get(format!("http://127.0.0.1:{port}/"))
            .send()
            .await
            .unwrap_err();
        let top = err.to_string();
        let chain = error_chain(&err);
        assert!(chain.starts_with(&top));
        assert!(chain.len() > top.len(), "no cause below `{top}`: {chain}");
    }

    #[test]
    fn hardened_client_builds() {
        // Config-only construction succeeds; the redirect/timeout posture is a
        // compile-time-fixed baseline, so there's nothing runtime to assert
        // beyond "it builds" (reqwest exposes no getters for these).
        let _ = build_integration_client(Duration::from_secs(15));
        let _ = hardened_client_builder(Duration::from_secs(5))
            .build()
            .expect("builder variant builds");
    }
}
