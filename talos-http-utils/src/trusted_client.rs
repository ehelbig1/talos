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

#[cfg(test)]
mod tests {
    use super::*;

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
