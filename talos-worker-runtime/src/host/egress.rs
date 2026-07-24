//! Network-egress policy shared by every outbound host function:
//! SSRF private-IP classification, IP-literal deny list, tier-1
//! LLM-host gate, host allowlist matching, and URL-scheme policy.

// ============================================================================
// SSRF private-IP classification
// ============================================================================
//
// "Is this IP one we refuse to reach?" Used by every place we have an IP in
// hand: the IP-literal arms in `fetch` / `fetch_all`, and the DNS-resolved arm
// in `fetch`. Returns the `record_capability_denied` policy string when the IP
// is denied so the caller emits a consistent audit trail. The logic is shared
// with the controller via `talos-ssrf-classify` — adding a new range is one
// edit in that crate, for both gates.

// Both functions now live in `talos-ssrf-classify` (std-only), shared with the
// controller's `talos_http_utils::ssrf` so the SSRF deny-list — including the
// IPv6 transition-form coverage (IPv4-mapped/compatible, NAT64, 6to4) added in
// the 2026-05-31 consolidation — is defined in exactly one place. The policy
// strings ("private-ip", "private-ip-unspecified", "private-ip-cgnat",
// "private-ip-ipv4-mapped-ipv6", …) are preserved for the audit trail.
pub(crate) use talos_ssrf_classify::classify_private_ip;

/// SSRF chokepoint: extract an IP-literal host from `url` and classify it
/// against the shared deny-list in ONE place. Returns `Some((ip, policy))` when
/// the URL host is an IP literal in a denied range (private / loopback /
/// link-local / metadata / CGNAT / IPv4-mapped-IPv6 / …), else `None`.
///
/// EVERY guest egress path (`wit_http::fetch` / `fetch_all`,
/// `wit_graphql::execute`, `wit_webhook::send`, `wit_http_stream::connect`)
/// MUST funnel its literal-IP SSRF check through here. The check used to be
/// inlined at each call site, and the inline copies DRIFTED — some were missing
/// CGNAT / IPv4-mapped-IPv6 until they were consolidated onto
/// `classify_private_ip`. Worse, a copy that forgets the `Host::Ipv6` arm
/// silently lets `http://[::1]/` through. One helper makes both failure modes
/// structurally impossible: a new egress path that calls this gets IPv4 + IPv6
/// + the full classifier for free, and can't half-implement the check.
///
/// IP-literal extraction uses `url::Host` (WHATWG-normalised), so decimal /
/// octal / hex encodings (`http://2130706433/`) are already dotted-quad here.
pub(crate) fn denied_ip_literal(url: &url::Url) -> Option<(std::net::IpAddr, &'static str)> {
    let ip: std::net::IpAddr = match url.host() {
        Some(url::Host::Ipv4(a)) => a.into(),
        Some(url::Host::Ipv6(a)) => a.into(),
        _ => return None,
    };
    classify_private_ip(ip).map(|policy| (ip, policy))
}

#[cfg(test)]
mod denied_ip_literal_tests {
    fn denied(u: &str) -> Option<&'static str> {
        let url = url::Url::parse(u).expect("parse url");
        super::denied_ip_literal(&url).map(|(_, policy)| policy)
    }

    #[test]
    fn blocks_ipv4_private_and_metadata() {
        assert!(denied("http://127.0.0.1/").is_some());
        assert!(denied("http://10.0.0.1/").is_some());
        assert!(denied("http://192.168.1.1/").is_some());
        // Cloud-metadata IAM credentials — the canonical SSRF prize.
        assert!(denied("http://169.254.169.254/latest/meta-data/").is_some());
    }

    #[test]
    fn blocks_ipv6_loopback_and_mapped() {
        // The `Host::Ipv6`-arm-omission bypass the chokepoint exists to make
        // structurally impossible: a path that forgot the IPv6 arm let `[::1]`
        // through.
        assert!(denied("http://[::1]/").is_some());
        assert!(denied("http://[::ffff:127.0.0.1]/").is_some());
    }

    #[test]
    fn blocks_decimal_encoded_loopback() {
        // `url::Host` is WHATWG-normalised, so 2130706433 is already 127.0.0.1
        // here — the decimal/octal/hex IP-encoding bypass is closed for free.
        assert!(
            denied("http://2130706433/").is_some(),
            "decimal-encoded loopback must be blocked"
        );
    }

    #[test]
    fn allows_public_ips_and_domains() {
        assert!(denied("http://8.8.8.8/").is_none());
        assert!(denied("http://[2001:4860:4860::8888]/").is_none());
        // A domain is NOT an IP literal — it's allowed past this gate and
        // checked at DNS-resolution time by the SSRF-aware resolver.
        assert!(denied("http://example.com/").is_none());
    }
}

/// Tier-1 (local-Ollama-only) data-egress deny-check on a URL host.
///
/// Returns `Some(policy)` — the `record_capability_denied` reason — when a
/// Tier-1 actor must be refused this destination, `None` when allowed.
///
/// Two cases:
/// 1. A known external LLM provider hostname (`is_external_llm_host`).
/// 2. A **globally-routable IP literal**. The hostname deny-list (case 1) is
///    name-based, so a guest with `allowed_hosts: ["*"]` could otherwise reach
///    a provider by raw IP (`https://<ip>/v1/messages`) and slip the ceiling —
///    the IP-literal bypass found in the 2026-05-28 review. A public IP literal
///    is "data leaving the host" and has no legitimate Tier-1 use (local Ollama
///    is reached via hostname/localhost/private IP). Private, loopback,
///    link-local, CGNAT, and unspecified literals are governed by the SSRF
///    classifier and remain allowed here (so `127.0.0.1:11434` Ollama works).
///
/// `host_lower` MUST already be lowercased by the caller (matches the existing
/// call sites). IPv6 literals are accepted with or without surrounding
/// brackets.
pub(crate) fn tier1_egress_deny_reason(host_lower: &str) -> Option<&'static str> {
    if talos_workflow_job_protocol::is_external_llm_host(host_lower) {
        return Some("tier1-llm-egress");
    }
    let bare = host_lower
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(host_lower);
    if let Ok(ip) = bare.parse::<std::net::IpAddr>() {
        // Public/routable IP literal (SSRF classifier returns None) → deny.
        if classify_private_ip(ip).is_none() {
            return Some("tier1-public-ip-egress");
        }
    }
    None
}

#[cfg(test)]
mod tier1_egress_tests {
    use super::tier1_egress_deny_reason;

    #[test]
    fn denies_known_provider_hostname() {
        assert_eq!(
            tier1_egress_deny_reason("api.anthropic.com"),
            Some("tier1-llm-egress")
        );
    }

    #[test]
    fn denies_public_ip_literal() {
        // Public IPv4 / IPv6 literals — the bypass class.
        assert_eq!(
            tier1_egress_deny_reason("160.79.104.10"),
            Some("tier1-public-ip-egress")
        );
        assert_eq!(
            tier1_egress_deny_reason("8.8.8.8"),
            Some("tier1-public-ip-egress")
        );
        assert_eq!(
            tier1_egress_deny_reason("[2606:4700:4700::1111]"),
            Some("tier1-public-ip-egress")
        );
    }

    #[test]
    fn allows_local_ip_literals_for_ollama() {
        // Local Ollama at loopback / private IP must still work for Tier-1.
        assert_eq!(tier1_egress_deny_reason("127.0.0.1"), None);
        assert_eq!(tier1_egress_deny_reason("192.168.1.50"), None);
        assert_eq!(tier1_egress_deny_reason("10.0.0.3"), None);
        assert_eq!(tier1_egress_deny_reason("[::1]"), None);
        assert_eq!(tier1_egress_deny_reason("0.0.0.0"), None);
    }

    #[test]
    fn allows_non_provider_hostnames() {
        // A DNS hostname that isn't a provider is governed by allowed_hosts,
        // not by this Tier-1 deny-check.
        assert_eq!(tier1_egress_deny_reason("ollama.internal"), None);
        assert_eq!(tier1_egress_deny_reason("example.com"), None);
    }
}

/// Match a host against the per-module `allowed_hosts` patterns.
///
/// Patterns can be:
/// * `"*"` — wildcard, matches any host (per-job override; SSRF / IP-literal
///   / tier-1 LLM deny-list still apply on top).
/// * `"example.com"` — exact match.
/// * `".example.com"` — suffix match (matches `api.example.com`,
///   `foo.bar.example.com`, but NOT bare `example.com`).
///
/// **Case handling.** Both sides are lowercased before comparison. The
/// `url` crate's WHATWG-conformant parser already lowercases ASCII
/// hostnames in `Url::host_str()`, but operator-supplied `allowed_hosts`
/// patterns come straight off the signed `JobRequest` and may be
/// mixed-case. Without this normalisation, an operator who configures
/// `allowed_hosts: ["API.example.com"]` (mixed case) silently denies
/// every legitimate request to the (already-lowercased) host
/// `api.example.com` — a configuration footgun. Lowercasing both sides
/// closes the gap defensively.
///
/// **Performance.** The lowercased host is computed once per `fetch` and
/// the pattern lowercase happens lazily inside the closure — for the
/// common all-lowercase case this is `ASCII fast-path` in the stdlib
/// (no allocation on `String::to_ascii_lowercase` only if the string is
/// already lowercase? — no, it allocates always). For `fetch_all` (which
/// loops over a batch) we lowercase the host once outside the batch loop
/// and let the caller pass the pre-lowercased host in.
///
/// **What this does NOT do.** Punycode / IDN normalisation, scheme check,
/// port check, or path check. SSRF / IP-literal blocking is upstream of
/// this matcher (see `classify_private_ip` + `validate_no_dns_rebinding`).
/// Tier-1 LLM-host deny-list is downstream (see
/// `is_external_llm_host`). This function is the operator-grant gate,
/// not the platform deny-gate.
pub(crate) fn host_allowlist_match(allowed: &[String], host: &str) -> bool {
    host_allowlist_match_kind(allowed, host).is_some()
}

/// HOW an allowlist admitted a host. The write-ceiling strict-egress gate
/// treats a wildcard admission differently from a named one: an operator
/// who typed the host (or its domain suffix) made a deliberate egress
/// decision; `"*"` made none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostMatchKind {
    /// Exact hostname entry (`api.example.com`).
    Exact,
    /// Leading-dot suffix pattern (`.example.com`).
    Suffix,
    /// The `"*"` wildcard — no host-specific operator intent.
    Wildcard,
}

/// Like [`host_allowlist_match`] but reports HOW the host matched
/// (`None` = not admitted). A named match wins over a coexisting `"*"`
/// entry — `["*", "api.example.com"]` reports `Exact` for that host —
/// because the strict-egress gate must credit explicit operator intent
/// wherever it exists.
pub(crate) fn host_allowlist_match_kind(allowed: &[String], host: &str) -> Option<HostMatchKind> {
    if allowed.is_empty() {
        return None;
    }
    // Strip the FQDN trailing dot before compare. `url::Url::parse` preserves
    // it (RFC 3986); DNS resolves both forms to the same record. Without the
    // strip, a host `example.com.` would silently fail to match an operator
    // grant of `example.com`. We also strip the dot from the pattern side so
    // an operator who pastes a copy of the FQDN-with-dot still matches the
    // dotless form a client sends.
    let host_lower = host.trim_end_matches('.').to_ascii_lowercase();
    let mut saw_wildcard = false;
    for pattern in allowed {
        if pattern == "*" {
            saw_wildcard = true;
            continue;
        }
        // Patterns starting with `.` are suffix patterns by design — preserve
        // that leading dot, only strip the TRAILING one. `.example.com.` and
        // `.example.com` should both match `api.example.com`.
        let pattern_lower = pattern.trim_end_matches('.').to_ascii_lowercase();
        if pattern_lower.starts_with('.') {
            if host_lower.ends_with(pattern_lower.as_str()) {
                return Some(HostMatchKind::Suffix);
            }
        } else if host_lower == pattern_lower {
            return Some(HostMatchKind::Exact);
        }
    }
    if saw_wildcard {
        return Some(HostMatchKind::Wildcard);
    }
    None
}

#[cfg(test)]
mod host_allowlist_match_kind_tests {
    use super::{host_allowlist_match_kind, HostMatchKind};

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn reports_exact_suffix_wildcard_and_none() {
        assert_eq!(
            host_allowlist_match_kind(&v(&["api.example.com"]), "api.example.com"),
            Some(HostMatchKind::Exact)
        );
        assert_eq!(
            host_allowlist_match_kind(&v(&[".example.com"]), "api.example.com"),
            Some(HostMatchKind::Suffix)
        );
        assert_eq!(
            host_allowlist_match_kind(&v(&["*"]), "anything.example.com"),
            Some(HostMatchKind::Wildcard)
        );
        assert_eq!(
            host_allowlist_match_kind(&v(&["other.com"]), "api.example.com"),
            None
        );
        assert_eq!(host_allowlist_match_kind(&[], "api.example.com"), None);
    }

    #[test]
    fn named_entry_wins_over_coexisting_wildcard() {
        // The strict-egress gate must credit explicit operator intent:
        // ["*", "api.example.com"] reports Exact for that host, Wildcard
        // for everything else.
        let allowed = v(&["*", "api.example.com", ".trusted.com"]);
        assert_eq!(
            host_allowlist_match_kind(&allowed, "api.example.com"),
            Some(HostMatchKind::Exact)
        );
        assert_eq!(
            host_allowlist_match_kind(&allowed, "svc.trusted.com"),
            Some(HostMatchKind::Suffix)
        );
        assert_eq!(
            host_allowlist_match_kind(&allowed, "elsewhere.io"),
            Some(HostMatchKind::Wildcard)
        );
    }
}

#[cfg(test)]
mod host_allowlist_match_tests {
    use super::host_allowlist_match;

    #[test]
    fn exact_match_lowercases_pattern() {
        // Operator misconfigures with mixed case — should still match
        // the (already-lowercased) host from `Url::host_str()`.
        let allowed = vec!["API.Example.com".to_string()];
        assert!(host_allowlist_match(&allowed, "api.example.com"));
    }

    #[test]
    fn exact_match_lowercases_host() {
        // Defensive: even if a caller passes an unnormalised host, the
        // matcher lowercases it.
        let allowed = vec!["api.example.com".to_string()];
        assert!(host_allowlist_match(&allowed, "API.EXAMPLE.COM"));
    }

    #[test]
    fn suffix_match_lowercased() {
        let allowed = vec![".EXAMPLE.com".to_string()];
        assert!(host_allowlist_match(&allowed, "api.example.com"));
        assert!(host_allowlist_match(&allowed, "FOO.bar.Example.com"));
    }

    #[test]
    fn suffix_match_does_not_match_bare_domain() {
        // ".example.com" means subdomains only — bare "example.com"
        // must NOT match (else the dot prefix is meaningless).
        let allowed = vec![".example.com".to_string()];
        assert!(!host_allowlist_match(&allowed, "example.com"));
    }

    #[test]
    fn suffix_match_does_not_match_sibling_domain() {
        // Defense against the classic suffix-confusion: "badexample.com"
        // must NOT match ".example.com". The leading dot in the pattern
        // ensures we match a sub-domain boundary, not a substring.
        let allowed = vec![".example.com".to_string()];
        assert!(!host_allowlist_match(&allowed, "badexample.com"));
    }

    #[test]
    fn wildcard_matches_any_host() {
        let allowed = vec!["*".to_string()];
        assert!(host_allowlist_match(&allowed, "anything.example.com"));
        assert!(host_allowlist_match(&allowed, "10.0.0.1"));
        // (Wildcard does not bypass SSRF gates — those run before this matcher.)
    }

    #[test]
    fn empty_allowlist_denies_all() {
        let allowed: Vec<String> = vec![];
        assert!(!host_allowlist_match(&allowed, "api.example.com"));
    }

    #[test]
    fn no_pattern_matches_unrelated_host() {
        let allowed = vec!["api.example.com".to_string()];
        assert!(!host_allowlist_match(&allowed, "evil.example.com"));
        assert!(!host_allowlist_match(&allowed, "example.com"));
    }

    // Wasm-security review 2026-05-23: trailing-dot normalisation. Same
    // class as `is_external_llm_host` — `url::Url::parse` preserves the
    // FQDN trailing dot and the strict equality check would otherwise let
    // an attacker bypass a tightly-scoped operator grant.
    #[test]
    fn trailing_dot_on_host_does_not_bypass() {
        let allowed = vec!["api.example.com".to_string()];
        assert!(host_allowlist_match(&allowed, "api.example.com."));
        assert!(host_allowlist_match(&allowed, "API.EXAMPLE.COM."));
    }

    #[test]
    fn trailing_dot_on_pattern_still_matches() {
        // Operator who copy-pastes an FQDN with the trailing dot should not
        // have their pattern silently break against a dotless host (which
        // is what `host_str()` returns when the URL has no trailing dot).
        let allowed = vec!["api.example.com.".to_string()];
        assert!(host_allowlist_match(&allowed, "api.example.com"));
        assert!(host_allowlist_match(&allowed, "api.example.com."));
    }

    #[test]
    fn trailing_dot_suffix_pattern_still_matches() {
        let allowed = vec![".example.com".to_string()];
        assert!(host_allowlist_match(&allowed, "api.example.com."));
        assert!(host_allowlist_match(&allowed, "foo.bar.example.com."));
        // Leading-dot suffix pattern must still NOT match the bare apex
        // even with trailing-dot — the suffix-match invariant from the
        // existing test cases must hold.
        assert!(!host_allowlist_match(&allowed, "example.com."));
    }
}

/// Outcome of the URL-scheme check applied to every outbound WIT
/// host call (`fetch`, `fetch_all`, `webhook::send`, `graphql::execute`,
/// `http_stream::connect`). Plaintext HTTP is denied by default
/// because:
///   1. `vault://` header substitution can interpolate a secret into
///      a plaintext request, exfiltrating it to any on-path observer.
///   2. The SSRF gates protect the network destination but cannot
///      protect data in flight.
///   3. The Talos SDK's idiomatic config flow encourages outbound
///      calls to first-party APIs which are uniformly HTTPS.
///
/// Operators with a legitimate plaintext target (dev sidecars, local
/// services already gated by `WORKER_ALLOW_PRIVATE_HOST_TARGETS`)
/// opt in with `WASM_ALLOW_INSECURE_HTTP=1`. The opt-in is process-
/// wide because it covers per-execution `http://` use rather than
/// per-execution policy.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum UrlSchemeVerdict {
    /// Scheme is `https`. Always allowed.
    Https,
    /// Scheme is something other than `https` AND the operator-level
    /// opt-in is set. Allowed, but the caller MUST emit an audit row
    /// so the deviation is visible to operators.
    InsecureAllowedByOptIn { scheme: String },
    /// Scheme is not `https` and there is no opt-in. Deny.
    InsecureRefused { scheme: String },
}

/// Pure scheme-policy decision. Side-effect free so the security-
/// critical default is unit-testable without touching DNS, sockets,
/// or the env. Callers translate the verdict into the right deny
/// + audit shape for their host-fn boundary.
pub(crate) fn classify_url_scheme(scheme: &str, insecure_opt_in: bool) -> UrlSchemeVerdict {
    // The scheme is already lowercased by `url::Url::parse`. Compare
    // exact for determinism; treat anything else as insecure.
    if scheme == "https" {
        return UrlSchemeVerdict::Https;
    }
    // 2026-05-28 audit F4: the `WASM_ALLOW_INSECURE_HTTP` env var is
    // documented as "permit plaintext HTTP". Pre-fix the implementation
    // greenlit ANY non-`https` scheme under the opt-in, including
    // `file://`, `ftp://`, `data:`, and any future scheme. Reqwest
    // refuses these today so the practical hole is closed, but a
    // future HTTP-client swap (curl, ureq, hyper-multiplex) would
    // inherit the gap. Whitelist `http` explicitly so the opt-in's
    // scope matches its name and any other scheme falls through to
    // `InsecureRefused` regardless of opt-in state.
    if scheme == "http" && insecure_opt_in {
        return UrlSchemeVerdict::InsecureAllowedByOptIn {
            scheme: scheme.to_string(),
        };
    }
    UrlSchemeVerdict::InsecureRefused {
        scheme: scheme.to_string(),
    }
}

/// Read the operator-level opt-in env var. Recognised forms: `1`,
/// `true`, `yes` (case-insensitive). Anything else is treated as off.
/// Empty / unset → off — same fail-closed default as
/// `TALOS_ALLOW_UNATTESTED_WASM`.
pub(crate) fn insecure_http_opt_in() -> bool {
    std::env::var("WASM_ALLOW_INSECURE_HTTP")
        .ok()
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

#[cfg(test)]
mod url_scheme_policy_tests {
    use super::{classify_url_scheme, UrlSchemeVerdict};

    #[test]
    fn https_always_allowed() {
        assert_eq!(classify_url_scheme("https", false), UrlSchemeVerdict::Https);
        assert_eq!(classify_url_scheme("https", true), UrlSchemeVerdict::Https);
    }

    #[test]
    fn http_refused_by_default() {
        assert!(matches!(
            classify_url_scheme("http", false),
            UrlSchemeVerdict::InsecureRefused { .. }
        ));
    }

    #[test]
    fn http_allowed_when_opt_in_set() {
        assert!(matches!(
            classify_url_scheme("http", true),
            UrlSchemeVerdict::InsecureAllowedByOptIn { .. }
        ));
    }

    #[test]
    fn unusual_schemes_treated_as_insecure() {
        // `file://`, `ftp://`, custom — all denied by default. The
        // outer reqwest connect would refuse most of these anyway,
        // but failing closed here keeps the policy uniform.
        assert!(matches!(
            classify_url_scheme("file", false),
            UrlSchemeVerdict::InsecureRefused { .. }
        ));
        assert!(matches!(
            classify_url_scheme("ftp", false),
            UrlSchemeVerdict::InsecureRefused { .. }
        ));
    }

    #[test]
    fn opt_in_does_not_extend_to_non_http_schemes() {
        // 2026-05-28 audit F4: the `WASM_ALLOW_INSECURE_HTTP` opt-in
        // is documented as "permit plaintext HTTP". Pre-fix it greenlit
        // ANY non-https scheme. Reqwest refuses these today but a
        // future client swap would inherit the hole. Pin the
        // post-fix behaviour: only `http` is widened by the opt-in;
        // every other scheme stays Refused even when opt-in is on.
        for s in ["file", "ftp", "data", "ws", "wss", "javascript", "ldap"] {
            assert!(
                matches!(
                    classify_url_scheme(s, true),
                    UrlSchemeVerdict::InsecureRefused { .. }
                ),
                "scheme {s} must stay Refused under opt-in; got {:?}",
                classify_url_scheme(s, true)
            );
        }
    }
}

#[cfg(test)]
mod classify_private_ip_tests {
    //! MCP-553: cover the IPv4/IPv6 unspecified range. Without these
    //! a guest with `allowed_hosts: ["*"]` could reach loopback by
    //! spelling it `http://0.0.0.0:PORT` (Linux kernel substitutes
    //! 127.0.0.1) — bypassing the SSRF gate that already covers
    //! `is_loopback`/`is_private`/`is_link_local`/CGNAT.
    use super::classify_private_ip;
    use talos_ssrf_classify::classify_private_ipv4;

    #[test]
    fn ipv4_unspecified_is_blocked() {
        let unspec: std::net::Ipv4Addr = "0.0.0.0".parse().unwrap();
        assert_eq!(
            classify_private_ipv4(unspec),
            Some("private-ip-unspecified")
        );
    }

    #[test]
    fn ipv4_unspecified_subnet_is_blocked() {
        // MCP-1069 (2026-05-15): widened from is_unspecified() (exact
        // `0.0.0.0` only) to the FULL 0.0.0.0/8 "this network" range
        // (RFC 1122). Pre-1069 this test pinned narrow `0.1.2.3 → None`
        // behaviour with a "expand if CVE" note. The note acknowledged
        // 0.x.x.x is kernel-substituted on some Linux versions — so
        // narrow coverage was a known gap, not a verified safe behaviour.
        // Sibling of the ssrf.rs MCP-1067/1068 widening of the
        // controller-side guard. Bringing the runtime classifier and
        // the pre-validation guard into consistent /8 coverage.
        for ip in &["0.0.0.0", "0.0.0.1", "0.1.2.3", "0.255.255.255"] {
            let addr: std::net::Ipv4Addr = ip.parse().unwrap();
            assert_eq!(
                classify_private_ipv4(addr),
                Some("private-ip-unspecified"),
                "should block {ip} (0.0.0.0/8 subnet)"
            );
        }
    }

    #[test]
    fn ipv6_unspecified_is_blocked() {
        let unspec: std::net::IpAddr = "::".parse().unwrap();
        assert_eq!(classify_private_ip(unspec), Some("private-ip-unspecified"));
    }

    #[test]
    fn ipv4_mapped_unspecified_is_blocked_via_mapping() {
        // ::ffff:0.0.0.0 should map to 0.0.0.0 and be rejected via
        // the IPv4-mapped path (with the v6-mapped label).
        //
        // MCP-1069: ALSO covers the rest of the IPv4-mapped 0.0.0.0/8
        // range (`::ffff:0.0.0.1` etc.) since the underlying
        // `classify_private_ipv4` now blocks the full /8.
        for mapped_str in &[
            "::ffff:0.0.0.0",
            "::ffff:0.0.0.1",
            "::ffff:0.42.42.42",
            "::ffff:0.255.255.255",
        ] {
            let mapped: std::net::IpAddr = mapped_str.parse().unwrap();
            let result = classify_private_ip(mapped);
            assert_eq!(
                result,
                Some("private-ip-ipv4-mapped-ipv6"),
                "should block {mapped_str}"
            );
        }
    }

    #[test]
    fn public_addresses_still_pass() {
        // Sanity tripwire: 8.8.8.8 and 2001:4860::8888 must NOT be
        // blocked by the new unspecified gate.
        let pub_v4: std::net::Ipv4Addr = "8.8.8.8".parse().unwrap();
        assert_eq!(classify_private_ipv4(pub_v4), None);
        let pub_v6: std::net::IpAddr = "2001:4860::8888".parse().unwrap();
        assert_eq!(classify_private_ip(pub_v6), None);
    }
}

#[cfg(test)]
mod private_ip_tests {
    use super::classify_private_ip;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }
    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse::<Ipv6Addr>().unwrap())
    }

    #[test]
    fn allows_public_ipv4() {
        assert_eq!(classify_private_ip(v4(8, 8, 8, 8)), None);
        assert_eq!(classify_private_ip(v4(1, 1, 1, 1)), None);
    }

    #[test]
    fn blocks_ipv4_private_ranges() {
        assert_eq!(classify_private_ip(v4(127, 0, 0, 1)), Some("private-ip"));
        assert_eq!(classify_private_ip(v4(10, 0, 0, 1)), Some("private-ip"));
        assert_eq!(classify_private_ip(v4(192, 168, 1, 1)), Some("private-ip"));
        assert_eq!(classify_private_ip(v4(172, 16, 0, 1)), Some("private-ip"));
        assert_eq!(classify_private_ip(v4(169, 254, 0, 1)), Some("private-ip"));
        assert_eq!(classify_private_ip(v4(224, 0, 0, 1)), Some("private-ip"));
    }

    #[test]
    fn blocks_ipv4_cgnat() {
        // 100.64.0.0/10 covers 100.64.0.0 – 100.127.255.255.
        assert_eq!(
            classify_private_ip(v4(100, 64, 0, 1)),
            Some("private-ip-cgnat")
        );
        assert_eq!(
            classify_private_ip(v4(100, 127, 255, 254)),
            Some("private-ip-cgnat")
        );
        // 100.63.x.x is OUTSIDE the CGNAT block — public.
        assert_eq!(classify_private_ip(v4(100, 63, 0, 1)), None);
        // 100.128.x.x is OUTSIDE the CGNAT block — public.
        assert_eq!(classify_private_ip(v4(100, 128, 0, 1)), None);
    }

    #[test]
    fn allows_public_ipv6() {
        assert_eq!(classify_private_ip(v6("2001:4860:4860::8888")), None);
    }

    #[test]
    fn blocks_ipv6_loopback_multicast_linklocal_uniquelocal() {
        assert_eq!(classify_private_ip(v6("::1")), Some("private-ip"));
        assert_eq!(classify_private_ip(v6("ff02::1")), Some("private-ip"));
        assert_eq!(classify_private_ip(v6("fe80::1")), Some("private-ip"));
        assert_eq!(classify_private_ip(v6("fc00::1")), Some("private-ip"));
        assert_eq!(classify_private_ip(v6("fd00::1")), Some("private-ip"));
    }

    #[test]
    fn blocks_ipv4_mapped_ipv6_to_private() {
        // ::ffff:127.0.0.1 — loopback via mapped IPv6.
        assert_eq!(
            classify_private_ip(v6("::ffff:127.0.0.1")),
            Some("private-ip-ipv4-mapped-ipv6")
        );
        assert_eq!(
            classify_private_ip(v6("::ffff:10.0.0.1")),
            Some("private-ip-ipv4-mapped-ipv6")
        );
        assert_eq!(
            classify_private_ip(v6("::ffff:192.168.1.1")),
            Some("private-ip-ipv4-mapped-ipv6")
        );
    }

    #[test]
    fn blocks_ipv4_mapped_ipv6_to_cgnat() {
        // The bug we're fixing — mapped CGNAT must use the cgnat policy.
        assert_eq!(
            classify_private_ip(v6("::ffff:100.64.0.1")),
            Some("private-ip-cgnat-ipv4-mapped-ipv6")
        );
        assert_eq!(
            classify_private_ip(v6("::ffff:100.127.255.254")),
            Some("private-ip-cgnat-ipv4-mapped-ipv6")
        );
    }

    #[test]
    fn allows_ipv4_mapped_ipv6_to_public() {
        assert_eq!(classify_private_ip(v6("::ffff:8.8.8.8")), None);
        assert_eq!(classify_private_ip(v6("::ffff:1.1.1.1")), None);
    }
}
