//! The closed set of host-side HTTP **reason classes** — the machine-readable
//! cause behind an otherwise opaque `wit_http::Error`.
//!
//! # Why this exists
//!
//! `wit/talos.wit` declares `enum error { invalidurl, timeout, networkerror,
//! forbiddenhost }` — a C-style discriminant with **no payload**. Eight
//! distinct host-side outcomes in [`crate::host::http`] collapse into the
//! single `networkerror` value, so a module author (and every retry gate
//! downstream) sees the literal string
//! `Error { code: 2, name: "networkerror", message: "" }` whether the cause was
//! a DNS outage, a TLS handshake failure, a refused TCP connect, an open
//! circuit breaker, or a Tier-1 data-egress policy deny. Those causes have
//! *opposite* retry semantics: DNS/TLS/reset are transient and must be
//! retried, while circuit-open / tier1-egress / the response caps are
//! deterministic and must not be.
//!
//! Widening the WIT `enum` to a `variant` would carry the cause natively but
//! is a full ABI break (every compiled module recompiles in lockstep), so
//! instead each emitting site tags its failure with one of the fixed tokens
//! below. The token is (a) published as the host-diagnostic `reason` and
//! (b) appended to the node-failure message as `[reason_class=<token>]`, which
//! is what makes `retry_condition: error_message.contains("circuit-open")`
//! writable and lets both transient classifiers tell the causes apart.
//!
//! # Sanitization contract
//!
//! Verbatim from [`crate::context::TalosContext::emit_host_diagnostic`]: the
//! class is a **fixed token chosen by the emitting site** — never derived from
//! request content — and any accompanying message is built only from values
//! the module author already controls (their host, method, key path) plus
//! fixed policy names. The raw `reqwest` string, the resolved IP (an SSRF
//! oracle), vault-substituted header values and the full URL with its query
//! params NEVER appear in it. [`sanitized_transport_detail`] is the one
//! function permitted to look at the raw error, and its output is
//! **worker-log-only** — it never crosses the host→guest boundary.

/// Hostname resolution failed before the request was sent.
pub const DNS: &str = "dns";
/// The TLS handshake failed (certificate, protocol alert, or peer rejection).
///
/// Split out from the connect classes deliberately: `reqwest::Error::is_connect`
/// is `true` for TLS handshake failures too, so trusting it alone actively
/// MISREPORTS a certificate problem as "connection refused".
pub const TLS: &str = "tls";
/// The peer actively refused the TCP connection (`ECONNREFUSED`).
pub const CONNECT_REFUSED: &str = "connect-refused";
/// The connect phase failed for a reason that is not a refusal — host or
/// network unreachable, no route, or a connect-phase timeout.
///
/// Deliberately distinct from [`CONNECT_REFUSED`]: naming an unreachable
/// network "refused" claims a precision the error does not carry.
pub const CONNECT_FAILED: &str = "connect-failed";
/// The request failed AFTER the connection was established — peer reset,
/// broken pipe, or a protocol-level error mid-exchange.
pub const SEND_FAILED: &str = "send-failed";
/// The per-host circuit breaker was OPEN; the request was never sent.
///
/// NON-transient by design — the host is known-down and cooling down, so
/// re-dispatching only hammers it.
pub const CIRCUIT_OPEN: &str = "circuit-open";
/// A Tier-1 (local-egress-only) actor's data-egress gate blocked the target.
///
/// NON-transient: the actor's ceiling will not change between attempts.
pub const TIER1_EGRESS: &str = "tier1-egress";
/// The execution was cancelled before the request was sent. NON-transient.
pub const CANCELLED: &str = "cancelled";
/// The upstream response exceeded the configured body-size limit.
/// NON-transient — the same request returns the same oversized body.
pub const RESPONSE_TOO_LARGE: &str = "response-too-large";
/// The upstream response exceeded the inbound header count / header value cap.
/// NON-transient for the same reason as [`RESPONSE_TOO_LARGE`].
pub const HEADER_CAP: &str = "header-cap";
/// The response body stream errored mid-transfer (transport reset or a
/// decode failure on a chunked / compressed body).
pub const RESPONSE_STREAM: &str = "response-stream";
/// The request timed out. Paired with `wit_http::Error::Timeout` (not
/// `networkerror`) but carried through the same channel for uniformity.
pub const TIMEOUT: &str = "timeout";
/// A `fetch-with-bearer` / `fetch-with-header` secret slot could not be
/// resolved, so the request was never built.
///
/// NON-transient: a missing or ungranted vault slot is identical on the next
/// attempt. Tagged explicitly because these sites ALSO return the bare
/// `networkerror` discriminant — without a class they would inherit the
/// transient-by-default reading and burn a retry budget on a configuration
/// error.
pub const SECRET_LOOKUP: &str = "secret-lookup";

/// Every token this module can emit. Exists so the classifiers on both sides
/// can be pinned against the producer by test rather than by hand-copied
/// string lists — a token added or renamed here fails `closed_set_snapshot`
/// below, whose failure message points at the two classifier arms that must
/// be updated with it.
pub const ALL: &[&str] = &[
    DNS,
    TLS,
    CONNECT_REFUSED,
    CONNECT_FAILED,
    SEND_FAILED,
    CIRCUIT_OPEN,
    TIER1_EGRESS,
    CANCELLED,
    RESPONSE_TOO_LARGE,
    HEADER_CAP,
    RESPONSE_STREAM,
    TIMEOUT,
    SECRET_LOOKUP,
];

/// Tokens whose cause is deterministic — a retry re-runs the same policy
/// decision or re-reads the same oversized response, so it must NOT be
/// classified transient even though the guest sees a bare `networkerror`.
pub const NON_TRANSIENT: &[&str] = &[
    CIRCUIT_OPEN,
    TIER1_EGRESS,
    CANCELLED,
    RESPONSE_TOO_LARGE,
    HEADER_CAP,
    SECRET_LOOKUP,
];

/// The rendered marker appended to a node-failure message, e.g.
/// `[reason_class=dns]`. Both classifiers match on the `reason_class=<token>`
/// substring, so a `retry_condition` of `error_message.contains("circuit-open")`
/// also matches — the plain token is a substring of the marker.
pub fn marker(class: &str) -> String {
    format!("[reason_class={class}]")
}

/// Lowercased markers found in a `reqwest` error's **source chain** that
/// indicate a TLS-layer failure rather than a transport-layer one.
const TLS_MARKERS: &[&str] = &[
    "certificate",
    "tls",
    "ssl",
    "handshake",
    "received fatal alert",
    "invalid peer",
    "corrupt message",
    "unknown issuer",
    "self-signed",
    "self signed",
    "bad record mac",
];

/// Lowercased markers indicating the peer actively REFUSED the connection,
/// as opposed to being unreachable.
const REFUSED_MARKERS: &[&str] = &["connection refused", "econnrefused"];

/// Classify a failed `reqwest` send into one of the connect/transport tokens.
///
/// The `reqwest::Error`'s own `Display` is deliberately NOT inspected: it
/// appends ` for url (<full url>)` (reqwest 0.12 `error.rs`), so a host named
/// `tls.example.com` — or a query parameter containing the word `handshake` —
/// would steer the classification from attacker- or author-controlled request
/// content. Only the `source()` chain (hyper / rustls / `std::io` errors) is
/// examined; those are produced by the transport stack, not by the request.
///
/// TLS is checked BEFORE `is_connect()` because a TLS handshake failure sets
/// `is_connect() == true` — the misreport this function exists to fix.
pub fn classify_reqwest_send_error(e: &reqwest::Error) -> &'static str {
    let detail = source_chain_detail(e);
    classify_transport_detail(&detail, e.is_connect())
}

/// Pure core of [`classify_reqwest_send_error`], split out so the mapping is
/// unit-testable without constructing real `reqwest` errors (whose inner
/// `Kind` is private and cannot be forged from outside the crate).
///
/// `detail` must already be lowercased and must contain ONLY source-chain
/// text — see the caller's doc-comment for why request-derived text is barred.
pub(crate) fn classify_transport_detail(detail: &str, is_connect: bool) -> &'static str {
    if TLS_MARKERS.iter().any(|m| detail.contains(m)) {
        return TLS;
    }
    if is_connect {
        if REFUSED_MARKERS.iter().any(|m| detail.contains(m)) {
            return CONNECT_REFUSED;
        }
        return CONNECT_FAILED;
    }
    SEND_FAILED
}

/// Concatenate the lowercased `Display` of every error in the source chain,
/// skipping the top-level `reqwest::Error` itself (which carries the URL).
fn source_chain_detail(e: &reqwest::Error) -> String {
    let mut out = String::new();
    let mut src: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(e);
    // Bounded walk: a cyclic or pathologically deep chain must not spin.
    for _ in 0..16 {
        let Some(cur) = src else { break };
        out.push_str(&cur.to_string().to_lowercase());
        out.push(' ');
        src = cur.source();
    }
    out
}

/// Render a transport error for the WORKER LOG only — never for the guest,
/// never for a stored payload.
///
/// Three passes, in order:
/// 1. **URL erasure.** `reqwest`'s `Display` appends the FULL request URL
///    including its query string, which routinely carries access tokens
///    (`?access_token=…`) — so every `scheme://…` run is replaced wholesale.
///    The target host is logged separately as a structured field; it is a
///    value the module author already declared in `allowed_hosts`.
/// 2. **DLP redaction** (`sk-*`, `ghp_*`, `Bearer …`) for anything a proxy or
///    upstream embedded in the chain.
/// 3. [`crate::error_sanitize::sanitize_error_message`] — strips RFC1918 /
///    loopback / link-local IPs (incl. the `169.254.169.254` cloud-metadata
///    address, which would otherwise reveal which cloud the worker runs on),
///    file paths and line numbers, and truncates to 2000 chars.
pub fn sanitized_transport_detail(e: &reqwest::Error) -> String {
    // Chain, including the top level — the URL is erased in pass 1, and the
    // top-level kind ("error sending request" / "request or response body
    // error") is the only place the failure PHASE is stated.
    let mut raw = e.to_string();
    let mut src: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(e);
    for _ in 0..16 {
        let Some(cur) = src else { break };
        raw.push_str(": ");
        raw.push_str(&cur.to_string());
        src = cur.source();
    }
    let no_urls = url_re().replace_all(&raw, "[URL]").into_owned();
    let dlp = talos_dlp_provider::redact_str(&no_urls);
    crate::error_sanitize::sanitize_error_message(&dlp)
}

fn url_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        // Any `scheme://` run up to the first whitespace or closing paren.
        // reqwest renders it as ` for url (https://host/path?q=v)`, so the
        // `)` terminator matters or the trailing paren is swallowed.
        regex::Regex::new(r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s)]*").expect("invalid regex")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_is_split_from_connect_refused() {
        // The headline D2 defect: rustls surfaces a handshake failure through
        // a connect-phase error, so `is_connect()` alone reports a CERTIFICATE
        // problem as "connection refused". Both inputs below set is_connect.
        assert_eq!(
            classify_transport_detail("invalid peer certificate: unknownissuer", true),
            TLS
        );
        assert_eq!(
            classify_transport_detail("received fatal alert: handshakefailure", true),
            TLS
        );
        assert_eq!(
            classify_transport_detail("tcp connect error: connection refused (os error 61)", true),
            CONNECT_REFUSED
        );
    }

    #[test]
    fn connect_failures_that_are_not_refusals_say_so() {
        // Naming an unreachable network "refused" would claim a precision the
        // error does not carry — these get the honest CONNECT_FAILED token.
        for detail in [
            "tcp connect error: network is unreachable (os error 51)",
            "tcp connect error: no route to host (os error 65)",
            "tcp connect error: operation timed out (os error 60)",
        ] {
            assert_eq!(
                classify_transport_detail(detail, true),
                CONNECT_FAILED,
                "detail: {detail}"
            );
        }
    }

    #[test]
    fn post_connect_failures_are_send_failed() {
        assert_eq!(
            classify_transport_detail("connection reset by peer (os error 54)", false),
            SEND_FAILED
        );
        assert_eq!(classify_transport_detail("broken pipe", false), SEND_FAILED);
    }

    #[test]
    fn tls_wins_even_after_connect_established() {
        // A TLS alert can also surface post-connect; the TLS token still wins
        // so the operator is not told "the peer reset us".
        assert_eq!(
            classify_transport_detail("received fatal alert: bad_certificate", false),
            TLS
        );
    }

    #[test]
    fn every_token_is_in_all_and_kebab_case() {
        // The closed-set guarantee: no token may carry uppercase, spaces, or
        // an `=`/`]` that would break the `[reason_class=…]` marker parse.
        for t in ALL {
            assert!(!t.is_empty());
            assert!(
                t.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                "token {t:?} is not kebab-case ascii"
            );
        }
        for t in NON_TRANSIENT {
            assert!(
                ALL.contains(t),
                "NON_TRANSIENT token {t:?} missing from ALL"
            );
        }
    }

    /// Snapshot of the CLOSED set. `talos-retry-intelligence` classifies these
    /// same tokens but cannot depend on this crate (it would pull wasmtime
    /// into the controller's retry path), so its arms are hand-written. This
    /// test is the tripwire: adding or renaming a token here fails, and the
    /// fix is to add the matching arm in
    /// `talos_retry_intelligence::classify_error` before updating the list.
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
            ]
        );
        assert_eq!(
            NON_TRANSIENT,
            &[
                "circuit-open",
                "tier1-egress",
                "cancelled",
                "response-too-large",
                "header-cap",
                "secret-lookup",
            ]
        );
    }

    #[test]
    fn marker_contains_the_bare_token_for_retry_conditions() {
        // `retry_condition: error_message.contains("circuit-open")` must keep
        // working against the rendered marker.
        let m = marker(CIRCUIT_OPEN);
        assert_eq!(m, "[reason_class=circuit-open]");
        assert!(m.contains("circuit-open"));
    }

    #[test]
    fn sanitizer_erases_urls_ips_and_secrets() {
        // Not a reqwest error (its Kind is private) — exercise the same three
        // passes `sanitized_transport_detail` composes.
        let raw = "error sending request for url (https://api.example.com/v1/x?access_token=sk-canary-000111222333) \
                   : tcp connect error: dial 10.1.2.3:443 and 169.254.169.254 failed at /app/src/http.rs:584:9";
        let no_urls = url_re().replace_all(raw, "[URL]").into_owned();
        let out = crate::error_sanitize::sanitize_error_message(&talos_dlp_provider::redact_str(
            &no_urls,
        ));
        assert!(
            !out.contains("sk-canary-000111222333"),
            "secret leaked: {out}"
        );
        assert!(!out.contains("access_token"), "query string leaked: {out}");
        assert!(
            !out.contains("api.example.com/v1/x"),
            "url path leaked: {out}"
        );
        assert!(!out.contains("10.1.2.3"), "RFC1918 IP leaked: {out}");
        assert!(!out.contains("169.254.169.254"), "IMDS IP leaked: {out}");
        assert!(out.contains("[URL]"));
        assert!(out.contains("[INTERNAL_IP]"));
        // The useful part survives.
        assert!(out.contains("tcp connect error"));
    }

    #[test]
    fn url_erasure_keeps_the_trailing_paren_intact() {
        let out = url_re().replace_all("for url (https://h/p?q=1) : boom", "[URL]");
        assert_eq!(out, "for url ([URL]) : boom");
    }

    #[test]
    fn classification_never_reads_request_derived_text() {
        // A host literally named `tls.example.com` must not steer the class:
        // `classify_reqwest_send_error` feeds only the SOURCE chain in, and
        // the URL lives on the top-level error. Simulate by passing a detail
        // string that contains no TLS marker.
        assert_eq!(
            classify_transport_detail("tcp connect error: connection refused", true),
            CONNECT_REFUSED
        );
    }
}
