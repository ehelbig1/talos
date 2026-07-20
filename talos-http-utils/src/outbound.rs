//! SSRF-safe outbound HTTP client construction for the CONTROLLER.
//!
//! The controller fires outbound HTTP at several user/caller-supplied URLs:
//! A2A agent calls (`call_a2a_agent` `endpoint_url`), approval-gate notification
//! webhooks, workflow failure webhooks, SLA webhooks. Each validates the URL at
//! call time with [`crate::ssrf::check_outbound_url_no_ssrf`] and uses
//! `redirect(Policy::none())` — but `check_outbound_url_no_ssrf` resolves DNS
//! ONCE for validation, and reqwest re-resolves at connect time. It explicitly
//! does NOT defend against DNS rebinding: an attacker who controls DNS for a
//! configured webhook host can return a public IP during validation and a
//! private / loopback / cloud-metadata IP (169.254.169.254, 127.0.0.1, the
//! controller's own Postgres/Neo4j/Redis/NATS ports, RFC-1918 internal services)
//! a few milliseconds later when reqwest connects.
//!
//! [`build_outbound_webhook_client`] installs a [`ControllerSsrfResolver`] as
//! reqwest's `dns_resolver`, re-applying [`talos_ssrf_classify::classify_private_ip`]
//! at the point of resolution so every address reqwest gets back has passed the
//! gate and the TOCTOU window collapses to zero. SINGLE SOURCE OF TRUTH — every
//! controller outbound-webhook fire site MUST build its reqwest client here.
//!
//! L4 (2026-05-28 review) introduced the resolver in `talos-mcp-handlers`, but
//! that crate sits ABOVE `talos-engine` / `talos-execution-orchestration` in the
//! dependency graph, so their sibling fire sites (approval-gate, failure
//! webhook) could not reach it and shipped plain clients (the DNS-rebinding
//! gap). Hoisting it into `talos-http-utils` — which all three already depend on
//! for `classify_private_ip` — makes the safe builder reachable everywhere.

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// Default overall request timeout for an outbound webhook.
const DEFAULT_WEBHOOK_TIMEOUT: Duration = Duration::from_secs(10);
/// Connect-timeout (fast-fail on a black-holed endpoint). Connect should
/// complete in seconds regardless of the overall timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Connect-time DNS resolver that drops any resolved address classified private
/// / loopback / link-local / metadata / CGNAT / unspecified by
/// [`talos_ssrf_classify::classify_private_ip`]. There is NO per-host bypass
/// (unlike the worker's resolver): controller outbound webhooks target
/// operator/user-configured EXTERNAL services and must never resolve to an
/// internal / metadata IP.
#[derive(Debug, Default, Clone)]
pub struct ControllerSsrfResolver;

impl Resolve for ControllerSsrfResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            // The `:443` here is only to satisfy `lookup_host`'s need for a
            // port; the REAL port is reset to 0 below so hyper-util substitutes
            // the URL/scheme port at connect time (see the map at the end).
            let lookup = tokio::net::lookup_host(format!("{host}:443")).await;
            let addrs = match lookup {
                Ok(it) => it.collect::<Vec<SocketAddr>>(),
                Err(e) => return Err(Box::new(e) as Box<dyn std::error::Error + Send + Sync>),
            };

            let filtered: Vec<SocketAddr> = addrs
                .into_iter()
                .filter(
                    |sa| match talos_ssrf_classify::classify_private_ip(sa.ip()) {
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

            // Reset the placeholder port to 0 so hyper-util substitutes the
            // actual URL/scheme port at connect time. hyper-util only performs
            // that substitution when the resolved port is 0 — a non-zero port
            // (the 443 placeholder above) is used VERBATIM, so leaving it would
            // send every outbound webhook to :443 regardless of the URL's port
            // (an `https://host:8443/` webhook would wrongly hit :443). Mirrors
            // the worker's SsrfFilteringResolver (security review 2026-07-19, L9).
            let iter: Addrs = Box::new(filtered.into_iter().map(|mut sa| {
                sa.set_port(0);
                sa
            }));
            Ok(iter)
        })
    }
}

/// Build an outbound-webhook reqwest client with the full controller-side SSRF
/// posture and the default 10 s timeout: no redirect following (a redirect-pivot
/// beneath the URL check would otherwise reach 169.254.169.254 / internal
/// ports), 5 s connect-timeout, and the connect-time [`ControllerSsrfResolver`]
/// closing the DNS-rebinding TOCTOU.
pub fn build_outbound_webhook_client(user_agent: &str) -> reqwest::Result<reqwest::Client> {
    build_outbound_webhook_client_with_timeout(user_agent, DEFAULT_WEBHOOK_TIMEOUT)
}

/// As [`build_outbound_webhook_client`] but with a caller-chosen overall
/// `timeout` — for sites with an operator-configured timeout (A2A `timeout_secs`
/// up to 120 s) or a tuned value (failure webhook). The SSRF posture (no
/// redirect, connect-timeout, the SSRF resolver) is identical and non-optional.
pub fn build_outbound_webhook_client_with_timeout(
    user_agent: &str,
    timeout: Duration,
) -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(CONNECT_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(user_agent.to_string())
        .dns_resolver(Arc::new(ControllerSsrfResolver))
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outbound_webhook_clients_build() {
        // The builders (with the custom resolver wired in) construct
        // successfully. The resolver's filtering correctness is covered by
        // talos_ssrf_classify's classify_private_ip tests.
        assert!(build_outbound_webhook_client("talos-test/1.0").is_ok());
        assert!(build_outbound_webhook_client_with_timeout(
            "talos-test/1.0",
            Duration::from_secs(120)
        )
        .is_ok());
    }
}
