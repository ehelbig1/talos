//! M4 (2026-05-22): SSRF-aware DNS resolver for the WIT host's reqwest
//! client.
//!
//! ## Problem closed
//!
//! Pre-M4 the worker validated DNS at the host-function entry
//! (`validate_no_dns_rebinding` / inline checks in `wit_http::fetch`,
//! `fetch_all`, `webhook::send`, etc.), then handed the request off to
//! reqwest which performed its OWN DNS resolution and connected to
//! whatever the system resolver returned at that moment. An attacker
//! controlling DNS for an allowlisted hostname could win the race:
//! return a public IP during the validation step (passes the
//! private-IP deny-list) then return `127.0.0.1` / RFC1918 / `::ffff:*`
//! when reqwest re-resolved a few milliseconds later (would connect to
//! an internal target).
//!
//! ## Closure
//!
//! This module installs a `reqwest::dns::Resolve` implementation that
//! re-applies the same `classify_private_ip` deny-list at the point
//! of resolution. Any address reqwest gets back has already passed
//! the gate; the TOCTOU window collapses to zero because there is no
//! "after the gate, before connect" interval — the gate IS the
//! connect.
//!
//! The per-call check at the host-function entry stays in place. It
//! provides the audit-log signal (`record_capability_denied`) and the
//! operator-friendly error path; the resolver-side check is the
//! correctness gate.
//!
//! ## Behaviour
//!
//! * `WORKER_ALLOW_PRIVATE_HOST_TARGETS=1` bypass — when set, the
//!   resolver passes through to the system resolver without filtering.
//!   This matches the host-function-entry bypass logic so operators
//!   running local-development sibling-service setups keep working.
//! * All other modes — every returned `SocketAddr` is checked via
//!   `classify_private_ip`. A `SocketAddr` whose IP is in the
//!   deny-list is filtered out. If ALL addresses are filtered, the
//!   resolver returns an empty iterator; reqwest then errors with a
//!   "could not connect" type message and the request fails closed.

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::net::SocketAddr;

/// Default-policy resolver: uses the OS resolver via
/// `tokio::net::lookup_host`, then filters out any address that fails
/// `classify_private_ip`. Pure wrapper — no per-request state.
#[derive(Debug, Clone, Default)]
pub struct SsrfFilteringResolver;

impl Resolve for SsrfFilteringResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            // The reqwest `Name` carries only the hostname; the port
            // is injected by reqwest's connect layer based on the URL
            // scheme. We use port 80 here as a placeholder because
            // tokio's `lookup_host` needs a port to return SocketAddr
            // (the port is rewritten by reqwest before the connect).
            let bypass = std::env::var("WORKER_ALLOW_PRIVATE_HOST_TARGETS")
                .ok()
                .as_deref()
                == Some("1");

            let lookup = tokio::net::lookup_host(format!("{}:80", host)).await;
            let addrs = match lookup {
                Ok(it) => it.collect::<Vec<SocketAddr>>(),
                Err(e) => {
                    return Err(Box::new(e) as Box<dyn std::error::Error + Send + Sync>);
                }
            };

            let filtered: Vec<SocketAddr> = if bypass {
                addrs
            } else {
                addrs
                    .into_iter()
                    .filter(|sa| {
                        match crate::host_impl::classify_private_ip(sa.ip()) {
                            None => true,
                            Some(policy) => {
                                tracing::warn!(
                                    host = %host,
                                    ip = %sa.ip(),
                                    policy,
                                    "SSRF resolver: filtered private IP from DNS result"
                                );
                                false
                            }
                        }
                    })
                    .collect()
            };

            if filtered.is_empty() {
                tracing::warn!(
                    host = %host,
                    "SSRF resolver: every resolved IP was filtered (all private). \
                     Connection will fail."
                );
            }

            let iter: Addrs = Box::new(filtered.into_iter());
            Ok(iter)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[tokio::test]
    async fn unparseable_hosts_error_via_lookup() {
        // Resolving an obviously-bogus host returns Err from the OS
        // resolver and propagates as-is. The filter never runs.
        let r = SsrfFilteringResolver;
        let name = Name::from_str("this-host-genuinely-does-not-exist-talos-test.invalid")
            .expect("Name::from_str");
        let result = r.resolve(name).await;
        // Either an Err (most platforms) OR an empty iterator
        // (some stubbed resolvers); both are acceptable.
        match result {
            Err(_) => {}
            Ok(iter) => {
                let v: Vec<SocketAddr> = iter.collect();
                assert!(v.is_empty());
            }
        }
    }
}
