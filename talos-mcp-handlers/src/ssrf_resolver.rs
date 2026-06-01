//! L4 (2026-05-28 review): connect-time SSRF resolver for the controller's
//! outbound-webhook reqwest clients (approval-gate notify, SLA webhook, and the
//! approval-webhook test fire).
//!
//! ## Problem closed
//!
//! Those senders call `talos_http_utils::ssrf::check_outbound_url_no_ssrf()` to
//! validate the operator-supplied webhook URL and use `redirect(none)` — but
//! that URL check happens at call time, and reqwest performs its OWN DNS
//! resolution again at connect time. `check_outbound_url_no_ssrf` explicitly
//! does NOT defend against DNS rebinding. An attacker controlling DNS for an
//! operator-configured webhook host can therefore return a public IP during the
//! validation step and a private / loopback / cloud-metadata IP
//! (169.254.169.254, 127.0.0.1, RFC-1918, …) a few milliseconds later when
//! reqwest re-resolves — reaching internal services from the controller (which
//! holds Postgres / Neo4j credentials).
//!
//! ## Closure
//!
//! This installs a `reqwest::dns::Resolve` that re-applies the canonical
//! `talos_http_utils::ssrf::classify_private_ip` deny-list at the point of
//! resolution, so every address reqwest gets back has already passed the gate
//! and the TOCTOU window collapses to zero. The call-time
//! `check_outbound_url_no_ssrf` stays in place as defense-in-depth + the
//! operator-friendly error path.
//!
//! Unlike the worker's `SsrfFilteringResolver`, there is NO per-host bypass:
//! controller outbound webhooks target operator-configured EXTERNAL services and
//! must never resolve to an internal / metadata IP. (A legitimate config never
//! points at a private address — `check_outbound_url_no_ssrf` already rejects
//! such URLs at validation time.)

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::net::SocketAddr;
use std::sync::Arc;

/// Connect-time DNS resolver that drops any resolved address classified private
/// / loopback / link-local / metadata / CGNAT / unspecified by
/// [`talos_http_utils::ssrf::classify_private_ip`].
#[derive(Debug, Default, Clone)]
pub struct ControllerSsrfResolver;

impl Resolve for ControllerSsrfResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            // The port is a placeholder; reqwest rewrites it from the URL scheme
            // before connecting. tokio's `lookup_host` just needs one to return
            // `SocketAddr`s.
            let lookup = tokio::net::lookup_host(format!("{host}:443")).await;
            let addrs = match lookup {
                Ok(it) => it.collect::<Vec<SocketAddr>>(),
                Err(e) => return Err(Box::new(e) as Box<dyn std::error::Error + Send + Sync>),
            };

            let filtered: Vec<SocketAddr> = addrs
                .into_iter()
                .filter(
                    |sa| match talos_http_utils::ssrf::classify_private_ip(sa.ip()) {
                        None => true,
                        Some(policy) => {
                            tracing::warn!(
                                host = %host,
                                ip = %sa.ip(),
                                policy,
                                "controller SSRF resolver: filtered private/metadata IP from DNS \
                                 result for an outbound webhook (possible DNS-rebinding attempt)"
                            );
                            false
                        }
                    },
                )
                .collect();

            if filtered.is_empty() {
                tracing::warn!(
                    host = %host,
                    "controller SSRF resolver: every resolved IP for this outbound webhook host \
                     was private/blocked — the connection will fail (DNS rebinding or a \
                     misconfigured internal endpoint)"
                );
            }

            let iter: Addrs = Box::new(filtered.into_iter());
            Ok(iter)
        })
    }
}

/// Build an outbound-webhook reqwest client with the full controller-side SSRF
/// posture — SINGLE SOURCE OF TRUTH for the three outbound-webhook fire sites:
/// * 10 s overall timeout, 5 s connect-timeout (MCP-1034 fast-fail),
/// * NO redirect following (MCP-469 — a redirect-pivot beneath the URL check
///   would otherwise reach 169.254.169.254 / internal ports),
/// * the connect-time [`ControllerSsrfResolver`] (L4) closing the DNS-rebinding
///   TOCTOU.
pub fn build_outbound_webhook_client(user_agent: &str) -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .connect_timeout(std::time::Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(user_agent.to_string())
        .dns_resolver(Arc::new(ControllerSsrfResolver))
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outbound_webhook_client_builds() {
        // Smoke test: the builder (with the custom resolver wired in) constructs
        // successfully. The resolver's filtering correctness is covered by
        // talos_http_utils::ssrf::classify_private_ip_tests.
        assert!(build_outbound_webhook_client("talos-test/1.0").is_ok());
    }
}
