//! The controller-side home for the worker's `[reason_class=<token>]` marker:
//! the closed token set, the extractor, and the **remediation family** each
//! token belongs to.
//!
//! # Why this crate exists
//!
//! `talos_worker_runtime::reason_class` MINTS the tokens, but no controller
//! crate can depend on it — that would pull wasmtime into the retry path, the
//! MCP handler tree and the ops-alert reconciler. The established workaround
//! was a HAND-MIRRORED list plus a pin-by-test
//! (`reason_class::closed_set_snapshot` fails when a token is added or renamed,
//! and its failure message names the classifier arms that must move with it).
//!
//! That works for ONE mirror. It does not scale: as of #714/#717 there were
//! three controller-side classifiers that read worker failure text, and only
//! `talos_retry_intelligence` knew any token at all —
//! `talos_failure_analysis_service::classify_error` and
//! `talos_ops_alerts_repository::self_monitor` knew **zero of thirty-one**, so
//! every egress denial reached an operator as `runtime_error` /
//! "unclassified failure" while the cause sat in the string the classifier had
//! just read. Adding two more hand-mirrors would have made four copies of a
//! closed set, which is the drift class this workspace has repeatedly paid for.
//!
//! So the mirror lives HERE, once, and the consumers depend on this crate.
//! [`ALL`] is still pinned to the producer by [`closed_set_snapshot`] below
//! (identical literal list to the worker's own snapshot); the worker's snapshot
//! names this crate so a token change fails on both sides.
//!
//! # What this crate deliberately does NOT decide
//!
//! It maps a token to a [`Family`] — "what kind of thing went wrong, and
//! therefore what class of fix applies". It does **not** name buckets, alert
//! classes, severities or remediation steps: those are per-surface vocabularies
//! that already exist on disk (an `error_type` in an MCP report, a dedup-key
//! segment under a `UNIQUE` constraint), and collapsing them into one enum here
//! would be minting the parallel taxonomy this crate exists to avoid. Each
//! consumer matches on [`Family`] and answers in its own vocabulary.
//!
//! # The marker's position in the message
//!
//! The worker APPENDS the marker to the node-failure text
//! (`runtime::last_network_reason_suffix`), so it is normally the last ~40
//! bytes. Consumers cap their input before scanning (4 KiB, the MCP-1135 /
//! MCP-1138 anti-OOM cap), which means a message longer than the cap hides its
//! own marker and classifies exactly as it did before this crate existed —
//! the safe direction, and documented on [`token`].

#![forbid(unsafe_code)]

/// Every token `talos_worker_runtime::reason_class` can stamp.
///
/// HAND-MIRRORED from `talos_worker_runtime::reason_class::ALL`, in the same
/// order, and pinned by [`closed_set_snapshot`]. The worker's own
/// `closed_set_snapshot` carries the identical literal list, so a token added
/// or renamed there fails BOTH tests and the failure message on each side
/// names the other.
///
/// The set is genuinely CLOSED on the wire. Every emitting site passes one of
/// the `reason_class` consts by name; the two sites that pass a variable
/// (`tier1_egress_class`, `dns_rebinding_class`) are `match`es that return one
/// of these consts, precisely so a growing policy vocabulary cannot leak a
/// token no classifier knows. Two members are family PREFIXES rather than
/// exact policy strings for the same reason: `private-ip` stands for the open
/// SSRF family (`private-ip-cgnat`, `private-ip-nat64`, …) and
/// `graphql-introspection` for its two-member family. A consumer that wants
/// the precise variant reads the worker's `[host:<policy>]` line via
/// `tail_worker_logs`; it is not on this wire.
pub const ALL: &[&str] = &[
    "dns",
    "tls",
    "connect-refused",
    "connect-failed",
    "send-failed",
    "circuit-open",
    "tier1-egress",
    "cancelled",
    "response-too-large",
    "header-cap",
    "response-stream",
    "timeout",
    "secret-lookup",
    "url-too-long",
    "url-parse",
    "insecure-scheme",
    "capability-world",
    "no-allowlist",
    "private-ip",
    "allowed-hosts",
    "tier1-llm-egress",
    "tier1-public-ip-egress",
    "write-ceiling",
    "write-ceiling-strict-egress",
    "method-allowlist",
    "execution-rate-limit",
    "per-host-rate-limit",
    "request-header-cap",
    "request-body-cap",
    "graphql-introspection",
    "sse-stream-cap",
];

/// The rendered marker key. Public because a consumer's own doc-comments and
/// tests should quote it from here rather than retyping it.
pub const MARKER_KEY: &str = "reason_class=";

/// What KIND of failure a token names — i.e. which class of fix resolves it.
///
/// One variant per distinct operator ACTION, which is why several tokens share
/// a variant (`allowed-hosts` and `no-allowlist` are both "the module's host
/// allowlist does not admit this host", fixed the same way) and why some
/// near-neighbours do not (`request-header-cap` is *your request is too big*
/// while `header-cap` is *the upstream response is too big* — opposite
/// directions of travel and opposite fixes).
///
/// A variant exists to name a remediation. If two tokens would always produce
/// the same advice, they belong in the same variant; if the same variant would
/// have to give two different instructions, it needs splitting.
///
/// Deliberately NOT `#[non_exhaustive]`. A new family is a new REMEDIATION,
/// and the only safe way to add one is for every consuming surface to fail to
/// compile until it says what it would tell an operator. A `_` arm forced on
/// downstream crates would let a new family ship silently answering whatever
/// that arm happened to say — which is the class of defect this crate exists
/// to remove, one level up.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Family {
    /// A real transport failure — DNS, TLS, connect, send, or a mid-response
    /// stream error. Possibly transient; nothing is misconfigured.
    Transport,
    /// The per-request deadline elapsed.
    Timeout,
    /// The worker's per-host circuit breaker is open and fast-failed the call
    /// without attempting it.
    CircuitOpen,
    /// The execution was cancelled; the in-flight call was abandoned.
    Cancelled,
    /// A `vault://` header could not be resolved — the slot is missing from
    /// the vault or is not granted to this module.
    SecretLookup,
    /// The INBOUND response exceeded a size cap (body or headers).
    ResponseCap,
    /// The OUTBOUND request exceeded a size cap (body or headers). Also covers
    /// the GraphQL query-size cap, because a GraphQL query IS the request body.
    RequestCap,
    /// The URL could not be used: unparseable, or longer than the byte cap.
    /// An AUTHORING error, not a policy denial — saying "a policy refused you"
    /// here sends the operator hunting a gate that never fired.
    MalformedUrl,
    /// A plaintext (`http://`) target was refused. A SECURITY gate: it is what
    /// stops a `vault://`-substituted header going out in the clear.
    InsecureScheme,
    /// The module's compiled `capability_world` does not grant this call at
    /// all. Fixed on the MODULE, by recompiling into a world that does.
    CapabilityWorld,
    /// The host is not admitted by the module's `allowed_hosts` — either it
    /// matches no pattern, or the module declared an EMPTY list (which denies
    /// every host).
    HostAllowlist,
    /// SSRF: the target resolved, or was written, as a private / loopback /
    /// link-local / CGNAT / IPv4-mapped address. Widening an allowlist does
    /// not lift this and is not supposed to.
    PrivateAddress,
    /// The ACTOR's egress ceiling refused the destination — the Tier-1
    /// external-LLM deny-list, the Tier-1 public-IP-literal deny, or the
    /// blanket local-egress-only resolver gate. Fixed on the ACTOR, never on
    /// the module.
    ActorEgressTier,
    /// The ACTOR's write ceiling refused the call — a mutating method, or
    /// (under strict-egress) a read through a wildcard host match.
    WriteCeiling,
    /// The HTTP verb is not in the module's declared `allowed_methods`.
    MethodAllowlist,
    /// A per-execution egress budget is spent: total calls, calls to one host,
    /// or concurrent SSE streams.
    EgressBudget,
    /// A GraphQL introspection query was refused.
    GraphqlIntrospection,
}

impl Family {
    /// Whether this family is a POLICY or CAP decision rather than a transport
    /// outcome — i.e. deterministic, and identical on the next attempt.
    ///
    /// Provided so a consumer can phrase "the platform refused this" without
    /// re-listing variants. [`Family::Transport`] and [`Family::Timeout`] are
    /// the only two that can differ on a retry; [`Family::CircuitOpen`] is
    /// deterministic *now* but clears on its own cooldown, and
    /// [`Family::Cancelled`] and [`Family::MalformedUrl`] are neither
    /// transport nor policy — all three answer `false`, so this is a narrow
    /// "a gate said no" predicate and not a transience predicate. Transience
    /// is `talos_retry_intelligence`'s decision and stays there.
    #[must_use]
    pub fn is_policy_denial(self) -> bool {
        matches!(
            self,
            Self::SecretLookup
                | Self::ResponseCap
                | Self::RequestCap
                | Self::InsecureScheme
                | Self::CapabilityWorld
                | Self::HostAllowlist
                | Self::PrivateAddress
                | Self::ActorEgressTier
                | Self::WriteCeiling
                | Self::MethodAllowlist
                | Self::EgressBudget
                | Self::GraphqlIntrospection
        )
    }
}

/// The token → [`Family`] map. `None` for anything not in [`ALL`].
///
/// Returning `None` rather than a catch-all variant is deliberate: a consumer
/// that sees `None` must fall through to whatever it did before the marker
/// existed, which is the only behaviour that is safe for a token this build
/// has never heard of (an older controller reading a newer worker's message).
/// `every_token_has_a_family` below proves the map is TOTAL over [`ALL`], so
/// `None` can only ever mean "not one of ours".
#[must_use]
pub fn family(token: &str) -> Option<Family> {
    Some(match token {
        "dns" | "tls" | "connect-refused" | "connect-failed" | "send-failed"
        | "response-stream" => Family::Transport,
        "timeout" => Family::Timeout,
        "circuit-open" => Family::CircuitOpen,
        "cancelled" => Family::Cancelled,
        "secret-lookup" => Family::SecretLookup,
        "response-too-large" | "header-cap" => Family::ResponseCap,
        "request-header-cap" | "request-body-cap" => Family::RequestCap,
        "url-too-long" | "url-parse" => Family::MalformedUrl,
        "insecure-scheme" => Family::InsecureScheme,
        "capability-world" => Family::CapabilityWorld,
        "no-allowlist" | "allowed-hosts" => Family::HostAllowlist,
        "private-ip" => Family::PrivateAddress,
        "tier1-egress" | "tier1-llm-egress" | "tier1-public-ip-egress" => Family::ActorEgressTier,
        "write-ceiling" | "write-ceiling-strict-egress" => Family::WriteCeiling,
        "method-allowlist" => Family::MethodAllowlist,
        "execution-rate-limit" | "per-host-rate-limit" | "sse-stream-cap" => Family::EgressBudget,
        "graphql-introspection" => Family::GraphqlIntrospection,
        _ => return None,
    })
}

/// Extract the `[reason_class=<token>]` token the worker stamped, if any.
///
/// `lower` MUST already be lowercased and length-capped by the caller — every
/// consumer already does both for its own substring chain, and doing it again
/// here would allocate a second full copy of a caller-controlled string.
///
/// Parsed ONCE rather than adding thirty-one `.contains()` scans to a chain
/// whose input cap exists precisely because the chain is the cost.
///
/// **Cap interaction, stated rather than implied.** The worker appends the
/// marker, so on a message longer than the caller's cap the marker is
/// TRUNCATED AWAY and this returns `None` — the message then classifies
/// exactly as it did before any marker existed. That is the safe direction (a
/// missing explanation, never a wrong one), and it is the reason the caps are
/// left at 4 KiB rather than widened: the caps bound an O(N) scan over a
/// guest-influenced string, and a guest that emits a megabyte of error text is
/// degrading its own diagnostics, not defeating a control. Policy denials —
/// the failures this whole marker exists to name — are short by construction:
/// the request never left the host, so there is no response body to inflate
/// the message.
///
/// The token is returned verbatim, INCLUDING one this build does not know.
/// Callers pair this with [`family`] and fall through on `None`.
#[must_use]
pub fn token(lower: &str) -> Option<&str> {
    let start = lower.find(MARKER_KEY)? + MARKER_KEY.len();
    let rest = &lower[start..];
    let end = rest.find(']').unwrap_or(rest.len());
    let tok = &rest[..end];
    if tok.is_empty() {
        None
    } else {
        Some(tok)
    }
}

/// Extract the token AND its family in one pass. `None` when there is no
/// marker OR when the marker names a token this build does not know.
#[must_use]
pub fn token_family(lower: &str) -> Option<(&str, Family)> {
    let tok = token(lower)?;
    family(tok).map(|f| (tok, f))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mirror, pinned as literals.
    ///
    /// The twin of `talos_worker_runtime::reason_class::closed_set_snapshot`,
    /// which carries the identical list. A behavioural test cannot catch a
    /// drift that moved the producer and this mirror together; two independent
    /// literal snapshots can.
    #[test]
    fn closed_set_snapshot() {
        assert_eq!(
            ALL,
            &[
                "dns",
                "tls",
                "connect-refused",
                "connect-failed",
                "send-failed",
                "circuit-open",
                "tier1-egress",
                "cancelled",
                "response-too-large",
                "header-cap",
                "response-stream",
                "timeout",
                "secret-lookup",
                "url-too-long",
                "url-parse",
                "insecure-scheme",
                "capability-world",
                "no-allowlist",
                "private-ip",
                "allowed-hosts",
                "tier1-llm-egress",
                "tier1-public-ip-egress",
                "write-ceiling",
                "write-ceiling-strict-egress",
                "method-allowlist",
                "execution-rate-limit",
                "per-host-rate-limit",
                "request-header-cap",
                "request-body-cap",
                "graphql-introspection",
                "sse-stream-cap",
            ]
        );
        assert_eq!(ALL.len(), 31);
    }

    /// TOTALITY. A token in [`ALL`] with no family would be a token every
    /// consumer silently falls through on — the exact "knows zero of them"
    /// state this crate was built to end, reintroduced one token at a time.
    #[test]
    fn every_token_has_a_family() {
        for t in ALL {
            assert!(
                family(t).is_some(),
                "token {t:?} is in ALL but has no Family — every consumer would \
                 fall through to its pre-marker bucket for it"
            );
        }
    }

    /// No token appears twice, and nothing outside the set resolves.
    #[test]
    fn the_set_is_a_set_and_nothing_else_resolves() {
        let mut seen: Vec<&str> = ALL.to_vec();
        seen.sort_unstable();
        let before = seen.len();
        seen.dedup();
        assert_eq!(seen.len(), before, "ALL contains a duplicate token");

        for bogus in ["", "not-a-real-token", "dn", "dnsx", "private", "llm"] {
            assert_eq!(family(bogus), None, "{bogus:?} unexpectedly resolved");
        }
    }

    /// Every family is reachable from at least one token. An unreachable
    /// variant is a remediation playbook nothing can ever route to.
    #[test]
    fn every_family_is_reachable() {
        use Family::*;
        for f in [
            Transport,
            Timeout,
            CircuitOpen,
            Cancelled,
            SecretLookup,
            ResponseCap,
            RequestCap,
            MalformedUrl,
            InsecureScheme,
            CapabilityWorld,
            HostAllowlist,
            PrivateAddress,
            ActorEgressTier,
            WriteCeiling,
            MethodAllowlist,
            EgressBudget,
            GraphqlIntrospection,
        ] {
            assert!(
                ALL.iter().any(|t| family(t) == Some(f)),
                "no token maps to {f:?}"
            );
        }
    }

    #[test]
    fn token_extraction() {
        assert_eq!(token("nothing here"), None);
        assert_eq!(
            token(r#"error { name: "forbiddenhost" } [reason_class=allowed-hosts]"#),
            Some("allowed-hosts")
        );
        // Marker first, not last — the worker appends, but a wrapper may not.
        assert_eq!(
            token("[reason_class=cancelled] networkerror"),
            Some("cancelled")
        );
        // Unterminated marker: take the rest of the (already capped) string.
        assert_eq!(token("boom [reason_class=dns"), Some("dns"));
        // Empty token is not a token.
        assert_eq!(token("boom [reason_class=]"), None);
        // Unknown token still extracts; family() is what refuses it.
        assert_eq!(
            token("boom [reason_class=from-the-future]"),
            Some("from-the-future")
        );
        assert_eq!(token_family("boom [reason_class=from-the-future]"), None);
    }

    /// The cap interaction, as an assertion rather than a paragraph: a marker
    /// past the caller's cap is simply absent.
    #[test]
    fn a_marker_past_the_callers_cap_is_absent() {
        let long = format!("{} [reason_class=allowed-hosts]", "x".repeat(5000));
        // What a caller with a 4 KiB cap actually hands us.
        let capped = &long[..4096];
        assert_eq!(token(capped), None);
        // Uncapped, it is found — so the loss is the cap's, not the parser's.
        assert_eq!(token(&long), Some("allowed-hosts"));
    }

    /// `is_policy_denial` is a "a gate said no" predicate, NOT a transience
    /// predicate — pinned so a future reader does not repurpose it as one.
    #[test]
    fn policy_denial_predicate_excludes_the_non_gate_families() {
        assert!(!Family::Transport.is_policy_denial());
        assert!(!Family::Timeout.is_policy_denial());
        assert!(!Family::CircuitOpen.is_policy_denial());
        assert!(!Family::Cancelled.is_policy_denial());
        assert!(!Family::MalformedUrl.is_policy_denial());
        assert!(Family::HostAllowlist.is_policy_denial());
        assert!(Family::ActorEgressTier.is_policy_denial());
        assert!(Family::PrivateAddress.is_policy_denial());
    }
}
