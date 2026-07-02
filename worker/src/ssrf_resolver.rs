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
//! ## Per-host bypass scoping (M4 follow-up)
//!
//! The original M4 resolver took a binary global bypass: setting
//! `WORKER_ALLOW_PRIVATE_HOST_TARGETS=1` disabled private-IP filtering
//! for EVERY hostname resolved through that worker's reqwest client.
//! The host-function-entry pre-call check (`validate_no_dns_rebinding`)
//! scoped the bypass correctly — only specific allowlisted hostnames —
//! but the resolver-level gate did not, so the operator-visible deny
//! relied on the pre-call check holding. A future bypass of the
//! pre-call check would have given the guest unfiltered DNS for any
//! host once the env var was set.
//!
//! Closure: the resolver now carries the SAME per-execution scoping
//! that the pre-call check uses. The bypass requires BOTH:
//!   1. `WORKER_ALLOW_PRIVATE_HOST_TARGETS=1` env (global toggle), AND
//!   2. The queried hostname is in the per-execution explicit list
//!      (the module's `allowed_hosts`, minus any `*` wildcard entries).
//! Hostnames NOT in the explicit list are always filtered, even when
//! the env var is set. This matches the host-function pre-call bypass
//! condition `WORKER_ALLOW_PRIVATE_HOST_TARGETS && allowed_hosts.iter().any(|p| p != "*" && p == host)`.

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;

/// SSRF-aware resolver scoped to a single execution's allowed-hosts.
///
/// Each `TalosContext::new` constructs one of these from the module's
/// `allowed_hosts` list, attaches it to the per-execution reqwest
/// client, and drops it with the context when the execution ends.
///
/// `explicit_private_host_allowed`: hostnames for which the resolver
/// MAY return private IPs when the operator-level env var
/// `WORKER_ALLOW_PRIVATE_HOST_TARGETS=1` is set. Constructed from the
/// caller's `allowed_hosts` with `*` wildcards stripped so a module
/// declaring `["*"]` cannot also opt into the private-IP bypass. An
/// empty set means "always filter every private IP regardless of env".
///
/// `local_egress_only`: when `true` (a Tier-1, local-Ollama-only actor),
/// the resolver INVERTS the default public-allow posture and DENIES any
/// resolved address that is NOT loopback/private/link-local. This closes
/// the S3 DNS hole (2026-06-23 review): the per-host
/// `tier1_egress_deny_reason` gate only catches known LLM-provider
/// hostnames and public IP *literals*, so a Tier-1 actor with a broad
/// `allowed_hosts` could resolve `data-sink.attacker.com` → a public IP
/// and POST sensitive data off-host. Enforcing local-only egress at the
/// connect-time resolver (where the resolved IP is known) aligns the code
/// with the documented Tier-1 contract — "data must NOT leave host" — and
/// defeats DNS-rebinding because the gate IS the connect. Local Ollama on
/// loopback / private-LAN IPs is still reachable.
#[derive(Debug, Clone, Default)]
pub struct SsrfFilteringResolver {
    explicit_private_host_allowed: Arc<HashSet<String>>,
    /// Tier-1 local-only egress: deny every non-private/non-loopback
    /// resolved address regardless of hostname. See struct doc.
    local_egress_only: bool,
}

impl SsrfFilteringResolver {
    /// Build a resolver scoped to a module's `allowed_hosts`. Any `*`
    /// wildcard entries are filtered out (a wildcard allowlist must
    /// not also unlock the private-IP bypass). Hostnames are lowercased
    /// to match the case-insensitive convention used elsewhere in the
    /// worker's HTTP path.
    ///
    /// `local_egress_only` mirrors the Tier-1 data-egress ceiling — set it
    /// from `max_llm_tier == Tier1` at the call site so the resolver can
    /// refuse public egress for privacy-ceiled actors.
    pub fn for_allowed_hosts(allowed_hosts: &[String], local_egress_only: bool) -> Self {
        let explicit = allowed_hosts
            .iter()
            .filter(|h| h.as_str() != "*")
            .map(|h| h.to_ascii_lowercase())
            .collect::<HashSet<String>>();
        Self {
            explicit_private_host_allowed: Arc::new(explicit),
            local_egress_only,
        }
    }

    /// Test helper: build a resolver with the bypass available for the
    /// given hostnames regardless of the env var (Tier-2 / public-allow
    /// posture).
    #[cfg(test)]
    pub fn with_explicit_hosts(hosts: &[&str]) -> Self {
        Self::for_allowed_hosts(
            &hosts.iter().map(|h| h.to_string()).collect::<Vec<_>>(),
            false,
        )
    }

    /// Pure bypass decision so the scoping is unit-testable without
    /// the env or DNS. The resolver follows the same logic at runtime.
    ///
    /// Three AND conditions must hold for the bypass to apply:
    ///   1. `env_toggle_on` — operator has set the global env toggle.
    ///   2. `!production` — the deployment is dev/test; production
    ///      ignores the env toggle entirely (wasm-security-review
    ///      2026-05-22).
    ///   3. The queried hostname is in this execution's explicit
    ///      `allowed_hosts` (no `*` wildcards).
    ///
    /// `#[cfg(test)]`: test-only pure mirror of the inline decision in
    /// `resolve()` (which additionally folds in `local_egress_only`).
    /// No production caller — compiled for tests only so the dead-code
    /// lint stays honest for release builds.
    #[cfg(test)]
    fn bypass_allowed(&self, host_lower: &str, env_toggle_on: bool) -> bool {
        self.bypass_allowed_with_prod(host_lower, env_toggle_on, false)
    }

    /// Production-aware variant. Exists for testing — callers in
    /// production paths use the env- and production-aware shape via
    /// `resolve()`. `#[cfg(test)]` for the same reason as
    /// [`Self::bypass_allowed`].
    #[cfg(test)]
    pub(crate) fn bypass_allowed_with_prod(
        &self,
        host_lower: &str,
        env_toggle_on: bool,
        production: bool,
    ) -> bool {
        env_toggle_on && !production && self.explicit_private_host_allowed.contains(host_lower)
    }
}

impl Resolve for SsrfFilteringResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_string();
        let host_lower = host.to_ascii_lowercase();
        let explicit_allowed = self.explicit_private_host_allowed.clone();
        let local_egress_only = self.local_egress_only;
        Box::pin(async move {
            // The reqwest `Name` carries only the hostname; the port
            // is injected by reqwest's connect layer based on the URL
            // scheme. We use port 80 here as a placeholder because
            // tokio's `lookup_host` needs a port to return SocketAddr
            // (the port is rewritten by reqwest before the connect).
            let env_toggle = std::env::var("WORKER_ALLOW_PRIVATE_HOST_TARGETS")
                .ok()
                .as_deref()
                == Some("1");
            // wasm-security-review (2026-05-22): refuse the bypass in
            // production regardless of the env toggle. The flag is a
            // dev-only convenience (reaching `host.docker.internal`
            // from a worker pod, etc.); leaving it active in
            // production widens the SSRF blast radius for what is at
            // best a marginal local-dev workflow improvement. The
            // host-function-entry pre-call check in `host_impl.rs`
            // mirrors this restriction.
            let production = talos_config::is_production();
            if env_toggle && production {
                tracing::warn!(
                    host = %host,
                    "WORKER_ALLOW_PRIVATE_HOST_TARGETS=1 is ignored in production — \
                     the env toggle is dev-only. Unset it on the deployment, or \
                     unset RUST_ENV=production if this is a single-pod dev cluster."
                );
            }
            // Per-execution scoping: the env toggle alone is not
            // sufficient — the hostname must ALSO appear in this
            // execution's explicit allowed-hosts (no `*`). Same shape
            // as `bypass_allowed_with_prod` so the unit-test pure
            // function agrees with this runtime path.
            //
            // The private-IP bypass is meaningless for a Tier-1
            // local-egress-only actor (it would only ever re-permit a
            // private IP that's already permitted), so we never enter it
            // when `local_egress_only` is set — keep the two postures
            // disjoint to avoid any "bypass re-permits public" footgun.
            let bypass = !local_egress_only
                && env_toggle
                && !production
                && explicit_allowed.contains(&host_lower);

            // `lookup_host` needs a port to return SocketAddrs; this `:80` is a
            // throwaway placeholder. The real port is selected by the connector
            // AFTER we zero it out below (see the `set_port(0)` at the return) —
            // do NOT treat this 80 as meaningful, it leaks to the wire otherwise.
            let lookup = tokio::net::lookup_host(format!("{}:80", host)).await;
            let addrs = match lookup {
                Ok(it) => it.collect::<Vec<SocketAddr>>(),
                Err(e) => {
                    return Err(Box::new(e) as Box<dyn std::error::Error + Send + Sync>);
                }
            };

            let filtered: Vec<SocketAddr> = if bypass {
                addrs
            } else if local_egress_only {
                // S3 (2026-06-23): Tier-1 = "data must NOT leave host".
                // INVERT the default posture — keep ONLY loopback /
                // private / link-local addresses, deny every public
                // (globally-routable) one regardless of hostname. This
                // blocks `data-sink.attacker.com → public IP` egress that
                // the name-based `tier1_egress_deny_reason` gate misses,
                // and defeats DNS-rebinding because the resolved IP is
                // re-classified at the connect point. Local Ollama on
                // loopback / private-LAN still resolves.
                addrs
                    .into_iter()
                    .filter(|sa| match crate::host_impl::classify_private_ip(sa.ip()) {
                        // Private / loopback / link-local — local egress, allowed.
                        Some(_) => true,
                        // Public / globally-routable — denied for Tier-1.
                        None => {
                            tracing::warn!(
                                host = %host,
                                ip = %sa.ip(),
                                "SECURITY: Tier-1 local-egress-only — blocked public IP from \
                                 DNS result (data must not leave host)"
                            );
                            false
                        }
                    })
                    .collect()
            } else {
                addrs
                    .into_iter()
                    .filter(|sa| match crate::host_impl::classify_private_ip(sa.ip()) {
                        None => true,
                        Some(policy) => {
                            tracing::warn!(
                                host = %host,
                                ip = %sa.ip(),
                                policy,
                                env_toggle,
                                explicit_scoped = explicit_allowed.contains(&host_lower),
                                "SSRF resolver: filtered private IP from DNS result"
                            );
                            false
                        }
                    })
                    .collect()
            };

            if filtered.is_empty() {
                tracing::warn!(
                    host = %host,
                    local_egress_only,
                    "SSRF resolver: every resolved IP was filtered. Connection will fail."
                );
            }

            // Zero the port on every returned address. The reqwest `Resolve`
            // contract (matching reqwest's own GaiResolver, which queries with
            // port 0) is that the resolver returns the IP and the connector fills
            // in the scheme-default port — 443 for https, 80 for http. hyper-util
            // only performs that substitution when the resolved port is 0; a
            // NON-zero port (the `:80` placeholder we pass to `lookup_host` so it
            // returns SocketAddrs at all) is trusted verbatim and leaks, so an
            // https URL connects to :80 and the TLS handshake fails with a bare
            // "networkerror". Resetting to 0 hands port selection back to the
            // connector. (The SSRF/private-IP classification above is on the IP
            // only and is unaffected by the port.)
            let iter: Addrs = Box::new(filtered.into_iter().map(|mut sa| {
                sa.set_port(0);
                sa
            }));
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
        let r = SsrfFilteringResolver::default();
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

    #[test]
    fn wildcard_entries_do_not_unlock_bypass() {
        // `*` in allowed_hosts grants HTTP wildcard but MUST NOT
        // unlock the private-IP bypass. The resolver's per-host set
        // is empty after wildcard filtering, so the bypass decision
        // returns false even with the env toggle on.
        let r = SsrfFilteringResolver::for_allowed_hosts(&["*".to_string()], false);
        assert!(!r.bypass_allowed("any-host.example.com", true));
        assert!(!r.bypass_allowed("any-host.example.com", false));
    }

    #[test]
    fn explicit_host_requires_env_toggle() {
        let r = SsrfFilteringResolver::with_explicit_hosts(&["host.docker.internal"]);
        // Env off — bypass denied.
        assert!(!r.bypass_allowed("host.docker.internal", false));
        // Env on — bypass allowed for THIS host only.
        assert!(r.bypass_allowed("host.docker.internal", true));
        // Env on but different host — bypass denied (per-host scoping).
        assert!(!r.bypass_allowed("api.public.example.com", true));
    }

    #[test]
    fn hostname_matching_is_case_insensitive() {
        let r = SsrfFilteringResolver::with_explicit_hosts(&["Host.Docker.Internal"]);
        // Stored lowercased; queries normalised before lookup at runtime.
        assert!(r.bypass_allowed("host.docker.internal", true));
        assert!(r.bypass_allowed("HOST.DOCKER.INTERNAL".to_ascii_lowercase().as_str(), true));
    }

    #[test]
    fn empty_explicit_set_blocks_all_bypass() {
        let r = SsrfFilteringResolver::default();
        assert!(!r.bypass_allowed("anything", true));
        assert!(!r.bypass_allowed("anything", false));
    }

    /// S3 (2026-06-23): a Tier-1 local-egress-only resolver must DENY a
    /// public IP and PERMIT loopback/private/link-local. IP-literal hosts
    /// are resolved by `tokio::net::lookup_host` without any network I/O,
    /// so this exercises the real `resolve()` filter deterministically.
    #[tokio::test]
    async fn local_egress_only_denies_public_permits_local() {
        let r = SsrfFilteringResolver::for_allowed_hosts(&["*".to_string()], true);

        // Public IP literal → filtered to empty (deny).
        let public = r
            .resolve(Name::from_str("8.8.8.8").expect("name"))
            .await
            .expect("resolve");
        assert!(
            public.collect::<Vec<SocketAddr>>().is_empty(),
            "Tier-1 local-egress-only must drop a public IP"
        );

        // Loopback → permitted.
        let loopback = r
            .resolve(Name::from_str("127.0.0.1").expect("name"))
            .await
            .expect("resolve");
        assert!(
            !loopback.collect::<Vec<SocketAddr>>().is_empty(),
            "Tier-1 local-egress-only must keep loopback (local Ollama)"
        );

        // Private LAN (RFC1918) → permitted (host-local Ollama on the LAN).
        let private = r
            .resolve(Name::from_str("192.168.1.50").expect("name"))
            .await
            .expect("resolve");
        assert!(
            !private.collect::<Vec<SocketAddr>>().is_empty(),
            "Tier-1 local-egress-only must keep a private-LAN address"
        );
    }

    /// The Tier-1 inversion must NOT be re-opened by the dev env-var
    /// bypass: `local_egress_only` forces `bypass = false` even with the
    /// toggle on and the hostname explicitly listed.
    #[tokio::test]
    async fn local_egress_only_ignores_private_host_bypass() {
        std::env::set_var("WORKER_ALLOW_PRIVATE_HOST_TARGETS", "1");
        let r = SsrfFilteringResolver::for_allowed_hosts(&["8.8.8.8".to_string()], true);
        let public = r
            .resolve(Name::from_str("8.8.8.8").expect("name"))
            .await
            .expect("resolve");
        assert!(
            public.collect::<Vec<SocketAddr>>().is_empty(),
            "local_egress_only must not be unlocked by the dev bypass toggle"
        );
        std::env::remove_var("WORKER_ALLOW_PRIVATE_HOST_TARGETS");
    }

    /// Tier-2 (default) posture is unchanged by the S3 change: public IPs
    /// pass, private IPs are filtered.
    #[tokio::test]
    async fn tier2_default_permits_public_filters_private() {
        let r = SsrfFilteringResolver::for_allowed_hosts(&[], false);
        let public = r
            .resolve(Name::from_str("8.8.8.8").expect("name"))
            .await
            .expect("resolve");
        assert!(
            !public.collect::<Vec<SocketAddr>>().is_empty(),
            "Tier-2 must still reach public hosts"
        );
        let private = r
            .resolve(Name::from_str("127.0.0.1").expect("name"))
            .await
            .expect("resolve");
        assert!(
            private.collect::<Vec<SocketAddr>>().is_empty(),
            "Tier-2 default still SSRF-filters private IPs"
        );
    }

    /// Regression: every resolved `SocketAddr` must carry port 0 so the
    /// connector substitutes the scheme-default port.
    ///
    /// WHY: `tokio::net::lookup_host` needs a port to produce a
    /// `SocketAddr`, so `resolve()` queries with a throwaway `:80`. The
    /// reqwest/hyper-util `Resolve` contract is that the resolver returns
    /// the IP and the *connector* fills in the scheme port (443 for https,
    /// 80 for http) — but hyper-util only performs that substitution when
    /// the resolved port is 0. If a NON-zero port leaks (the `:80`
    /// placeholder), it is trusted verbatim: an https URL connects to :80
    /// and the TLS handshake fails with a bare "networkerror". The fix maps
    /// `set_port(0)` over every returned addr; this test pins that so the
    /// placeholder port can never leak again. (IP literal → no network I/O,
    /// fully deterministic; mirrors `tier2_default_permits_public_filters_private`.)
    #[tokio::test]
    async fn resolve_returns_zero_port_so_connector_picks_scheme_port() {
        let r = SsrfFilteringResolver::for_allowed_hosts(&[], false);
        let addrs: Vec<SocketAddr> = r
            .resolve(Name::from_str("1.1.1.1").expect("name"))
            .await
            .expect("resolve")
            .collect();
        assert!(
            !addrs.is_empty(),
            "Tier-2 must resolve a public IP literal (1.1.1.1)"
        );
        for sa in &addrs {
            assert_eq!(
                sa.port(),
                0,
                "resolver must zero the port so the connector picks the scheme-default \
                 (443 for https); a non-zero port leaks and https connects to :80"
            );
        }
    }

    /// wasm-security-review (2026-05-22): production gate refuses the
    /// bypass regardless of env toggle + allowlist hit.
    #[test]
    fn production_ignores_env_toggle() {
        let r = SsrfFilteringResolver::with_explicit_hosts(&["host.docker.internal"]);
        // Dev mode + env on + hostname allowed → bypass.
        assert!(r.bypass_allowed_with_prod("host.docker.internal", true, false));
        // Production + env on + hostname allowed → still NO bypass.
        assert!(!r.bypass_allowed_with_prod("host.docker.internal", true, true));
        // Production + env off → no bypass (sanity).
        assert!(!r.bypass_allowed_with_prod("host.docker.internal", false, true));
    }
}
