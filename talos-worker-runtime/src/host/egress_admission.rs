//! The per-request URL admission shared by every guest HTTP surface that
//! takes a URL: `http::fetch`, each entry of `http::fetch_all`, and (from its
//! own parsed authority) the raw `wasi:http` gate.
//!
//! These gates were written out once per surface, in the same order, and that
//! duplication is how siblings drifted before (the method-allowlist and body
//! substitution parity packages). The DECISION now has one home; recording it
//! (audit denial, reason latch, guest error) stays with the caller, because
//! each surface reports through a different error type.
//!
//! Order, cheapest first and identical on every surface: URL byte cap → parse
//! → scheme → empty allowlist → denied IP literal → `allowed_hosts` → egress
//! posture (tier-1 LLM host / public literal under local-only egress).

use super::egress::{
    classify_url_scheme, denied_ip_literal, egress_posture_deny_reason, host_allowlist_match_kind,
    HostMatchKind, UrlSchemeVerdict,
};
use super::limits::MAX_OUTBOUND_URL_BYTES;
use crate::reason_class;

/// The policy one request is judged against, read from the context.
pub(crate) struct UrlPolicy<'a> {
    pub(crate) allowed_hosts: &'a [String],
    pub(crate) max_llm_tier: talos_workflow_job_protocol::LlmTier,
    pub(crate) local_egress_only: bool,
    pub(crate) insecure_http_opt_in: bool,
}

/// The WIT discriminant a refusal is paired with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DenialKind {
    Forbidden,
    InvalidUrl,
}

/// A policy refusal: recorded as an audit denial (`policy`, `target`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyRefusal {
    /// Audit `policy` token (same vocabulary on every surface).
    pub(crate) policy: &'static str,
    /// Audit target: host, IP, or `"<scheme> <host>"`; never a secret.
    pub(crate) target: String,
    /// Reason class latched for the retry gates.
    pub(crate) class: &'static str,
    pub(crate) kind: DenialKind,
}

/// Why a raw URL string was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UrlRefusal {
    /// Over [`MAX_OUTBOUND_URL_BYTES`]; checked before the O(n) parse. A pure
    /// cap: no audit denial.
    TooLong {
        len: usize,
    },
    /// Not a URL (an author typo). No audit denial.
    Unparsable,
    Policy(PolicyRefusal),
}

impl UrlRefusal {
    pub(crate) fn class(&self) -> &'static str {
        match self {
            Self::TooLong { .. } => reason_class::URL_TOO_LONG,
            Self::Unparsable => reason_class::URL_PARSE,
            Self::Policy(p) => p.class,
        }
    }

    pub(crate) fn kind(&self) -> DenialKind {
        match self {
            Self::TooLong { .. } | Self::Unparsable => DenialKind::InvalidUrl,
            Self::Policy(p) => p.kind,
        }
    }
}

/// An admitted URL and what the later gates need from it.
#[derive(Debug, Clone)]
pub(crate) struct UrlAdmitted {
    pub(crate) url: url::Url,
    pub(crate) host: String,
    /// How `allowed_hosts` admitted the host (the strict-egress gate reads it).
    pub(crate) host_match: HostMatchKind,
    /// `host:port` (port when known) — the per-host rate-limit key.
    pub(crate) host_for_limit: String,
    /// `Some(scheme)` when a plaintext scheme passed only by the operator
    /// opt-in (`WASM_ALLOW_INSECURE_HTTP`); the caller logs the deviation.
    pub(crate) insecure_opt_in: Option<String>,
}

impl crate::context::TalosContext {
    /// The URL policy this execution's requests are judged against.
    pub(crate) fn url_policy(&self) -> UrlPolicy<'_> {
        UrlPolicy {
            allowed_hosts: &self.allowed_hosts,
            max_llm_tier: self.max_llm_tier,
            local_egress_only: self.local_egress_only,
            insecure_http_opt_in: super::egress::insecure_http_opt_in(),
        }
    }
}

/// Admit a guest-supplied URL string.
pub(crate) fn admit_url(raw: &str, policy: &UrlPolicy<'_>) -> Result<UrlAdmitted, UrlRefusal> {
    if raw.len() > MAX_OUTBOUND_URL_BYTES {
        return Err(UrlRefusal::TooLong { len: raw.len() });
    }
    let url: url::Url = raw.parse().map_err(|_| UrlRefusal::Unparsable)?;
    admit_parsed_url(url, policy).map_err(UrlRefusal::Policy)
}

/// The policy half of [`admit_url`], for a surface that builds its own `Url`.
pub(crate) fn admit_parsed_url(
    url: url::Url,
    policy: &UrlPolicy<'_>,
) -> Result<UrlAdmitted, PolicyRefusal> {
    let host = url.host_str().unwrap_or("").to_string();
    let refuse = |policy: &'static str, target: String, class: &'static str, kind| PolicyRefusal {
        policy,
        target,
        class,
        kind,
    };

    // HTTPS-only by default: plaintext can leak `vault://` headers in flight.
    let insecure_opt_in = match classify_url_scheme(url.scheme(), policy.insecure_http_opt_in) {
        UrlSchemeVerdict::Https => None,
        UrlSchemeVerdict::InsecureAllowedByOptIn { scheme } => Some(scheme),
        UrlSchemeVerdict::InsecureRefused { scheme } => {
            return Err(refuse(
                "insecure-scheme",
                format!("{scheme} {host}"),
                reason_class::INSECURE_SCHEME,
                DenialKind::InvalidUrl,
            ));
        }
    };
    // An empty allowlist means DENY ALL.
    if policy.allowed_hosts.is_empty() {
        return Err(refuse(
            "no-allowlist-configured",
            host,
            reason_class::NO_ALLOWLIST,
            DenialKind::Forbidden,
        ));
    }
    // SSRF: an IP literal in a denied range is refused even under `"*"`.
    if let Some((ip, p)) = denied_ip_literal(&url) {
        return Err(refuse(
            p,
            ip.to_string(),
            reason_class::PRIVATE_IP,
            DenialKind::Forbidden,
        ));
    }
    let Some(host_match) = host_allowlist_match_kind(policy.allowed_hosts, &host) else {
        return Err(refuse(
            "allowed-hosts",
            host,
            reason_class::ALLOWED_HOSTS,
            DenialKind::Forbidden,
        ));
    };
    // Tier-1 LLM hosts + public IP literals, and public IP literals for ANY
    // local-egress-only actor (a resolver never sees a literal).
    if let Some(p) = egress_posture_deny_reason(
        &host.to_ascii_lowercase(),
        policy.max_llm_tier,
        policy.local_egress_only,
    ) {
        return Err(refuse(
            p,
            host,
            reason_class::tier1_egress_class(p),
            DenialKind::Forbidden,
        ));
    }
    let host_for_limit = match url.port_or_known_default() {
        Some(port) => format!("{host}:{port}"),
        None => host.clone(),
    };
    Ok(UrlAdmitted {
        url,
        host,
        host_match,
        host_for_limit,
        insecure_opt_in,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use talos_workflow_job_protocol::LlmTier;

    fn policy(hosts: &[String], tier: LlmTier, local: bool, insecure: bool) -> UrlPolicy<'_> {
        UrlPolicy {
            allowed_hosts: hosts,
            max_llm_tier: tier,
            local_egress_only: local,
            insecure_http_opt_in: insecure,
        }
    }

    fn hosts(h: &[&str]) -> Vec<String> {
        h.iter().map(|s| s.to_string()).collect()
    }

    fn policy_of(r: Result<UrlAdmitted, UrlRefusal>) -> (&'static str, String, &'static str) {
        match r {
            Err(UrlRefusal::Policy(p)) => (p.policy, p.target, p.class),
            other => panic!("expected a policy refusal, got {other:?}"),
        }
    }

    #[test]
    fn caps_and_typos_are_invalid_url_without_an_audit_policy() {
        let h = hosts(&["*"]);
        let p = policy(&h, LlmTier::Tier2, false, false);
        let long = format!("https://a.example/{}", "a".repeat(MAX_OUTBOUND_URL_BYTES));
        let e = admit_url(&long, &p).unwrap_err();
        assert!(matches!(e, UrlRefusal::TooLong { .. }));
        assert_eq!(
            (e.class(), e.kind()),
            (reason_class::URL_TOO_LONG, DenialKind::InvalidUrl)
        );
        let e = admit_url("not a url", &p).unwrap_err();
        assert_eq!(e, UrlRefusal::Unparsable);
        assert_eq!(
            (e.class(), e.kind()),
            (reason_class::URL_PARSE, DenialKind::InvalidUrl)
        );
    }

    #[test]
    fn each_policy_refusal_in_order() {
        let star = hosts(&["*"]);
        let none: Vec<String> = vec![];
        let named = hosts(&["example.com"]);
        let tier2 = |h| policy(h, LlmTier::Tier2, false, false);

        // Scheme is decided before the allowlist is even consulted.
        let e = admit_url("http://example.com/x", &tier2(&none)).unwrap_err();
        assert_eq!(e.kind(), DenialKind::InvalidUrl);
        assert_eq!(
            policy_of(Err(e)),
            (
                "insecure-scheme",
                "http example.com".into(),
                reason_class::INSECURE_SCHEME
            )
        );
        // Empty allowlist before the IP-literal check.
        assert_eq!(
            policy_of(admit_url("https://127.0.0.1/x", &tier2(&none))),
            (
                "no-allowlist-configured",
                "127.0.0.1".into(),
                reason_class::NO_ALLOWLIST
            )
        );
        // A denied literal even under "*".
        assert_eq!(
            policy_of(admit_url("https://127.0.0.1/x", &tier2(&star))),
            ("private-ip", "127.0.0.1".into(), reason_class::PRIVATE_IP)
        );
        assert_eq!(
            policy_of(admit_url("https://other.example/x", &tier2(&named))),
            (
                "allowed-hosts",
                "other.example".into(),
                reason_class::ALLOWED_HOSTS
            )
        );
        // Allowlist before egress posture: an unlisted LLM host reads as
        // `allowed-hosts`, a listed one as the tier-1 refusal.
        let t1 = policy(&named, LlmTier::Tier1, true, false);
        assert_eq!(
            policy_of(admit_url("https://api.anthropic.com/v1", &t1)).0,
            "allowed-hosts"
        );
        let llm = hosts(&["api.anthropic.com"]);
        assert_eq!(
            policy_of(admit_url(
                "https://api.anthropic.com/v1",
                &policy(&llm, LlmTier::Tier1, true, false)
            )),
            (
                "tier1-llm-egress",
                "api.anthropic.com".into(),
                reason_class::TIER1_LLM_EGRESS
            )
        );
        assert_eq!(
            policy_of(admit_url(
                "https://203.0.113.9/x",
                &policy(&star, LlmTier::Tier2, true, false)
            )),
            (
                "local-egress-public-ip",
                "203.0.113.9".into(),
                reason_class::TIER1_EGRESS
            )
        );
    }

    #[test]
    fn admitted_carries_the_rate_limit_key_and_match_kind() {
        let h = hosts(&["example.com"]);
        let a = admit_url(
            "https://example.com/x",
            &policy(&h, LlmTier::Tier2, false, false),
        )
        .unwrap();
        assert_eq!(a.host, "example.com");
        assert_eq!(a.host_for_limit, "example.com:443");
        assert_eq!(a.host_match, HostMatchKind::Exact);
        assert_eq!(a.insecure_opt_in, None);
        let a = admit_url(
            "http://example.com:8080/x",
            &policy(&h, LlmTier::Tier2, false, true),
        )
        .unwrap();
        assert_eq!(a.host_for_limit, "example.com:8080");
        assert_eq!(a.insecure_opt_in.as_deref(), Some("http"));
    }
}
