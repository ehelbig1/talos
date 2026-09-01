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
//! # The collapse is not unique to `networkerror`
//!
//! `invalidurl` collapses THREE causes — a hostile-guest URL byte cap, a
//! genuine author typo, and the plaintext-scheme SECURITY refusal (which
//! exists because a `vault://` header would otherwise go out in the clear).
//! An operator reading `Error { code: 0, name: "invalidurl", message: "" }`
//! cannot tell a policy denial from a typo, and `invalidurl` matched NO arm
//! in `talos_retry_intelligence::classify_error`, so every one of them was
//! filed under `unknown`. `forbiddenhost` collapses 28 emitting sites across
//! at least ten distinct policies whose remediations differ completely —
//! "add the host to allowed_hosts" is the wrong advice for a capability-world
//! or method-allowlist denial.
//!
//! So a class is stored as a [`Reason`]: the token PLUS the WIT discriminant
//! it is allowed to explain. See
//! [`crate::runtime::last_network_reason_suffix`] for why that pairing —
//! rather than "stamp whenever a class is latched" — is what keeps the latch
//! from mis-attributing a stale cause to an unrelated later failure.
//!
//! # Coverage, and what is still outside it (measured, not assumed)
//!
//! All FOUR egress surfaces are covered: `host/http` (`fetch` / `fetch_all`),
//! `host/graphql`, `host/webhook` and `host/http_stream`. Each needed a
//! different amount of work, and the measurements that decided it are worth
//! keeping because the obvious reading of the code was wrong in every case:
//!
//! * **`host/graphql.rs`** — 17 sites return `Networkerror`, and **16 of them
//!   are deterministic**; exactly ONE is the genuine transport failure. Since
//!   a bare `networkerror` is TRANSIENT in every classifier, every one of
//!   those 16 denials was being re-dispatched: an SSRF block and a Tier-1
//!   data-egress refusal each burned three attempts and told the operator
//!   "network transient". This is the only surface where the marker moves a
//!   message from transient to non-transient.
//! * **`host/webhook.rs`** — 16 sites return `Sendfailed`, 15 of them
//!   deterministic. `sendfailed` matches no arm in any classifier, so every
//!   one already read as `unknown` / `runtime_error` / `other` — NON-transient,
//!   hence a pure diagnostic fix with no retry consequence in either direction.
//! * **`host/http_stream.rs`** — the WIT enum spells its cases with hyphens
//!   (`forbidden-host`, `invalid-url`, `connection-failed`, `rate-limited`),
//!   which no `forbiddenhost` arm matches. `forbidden-host` contains
//!   "forbidden" and so classified `auth_failure` / `http_403`: non-transient,
//!   but pointing the operator at a credential that was never the problem.
//!   Its three `ConnectionFailed` sites are NOT transport failures (one
//!   cancellation, two mutex-poison guards) — a `connect` transport failure
//!   happens in a spawned task and never reaches the guest as an error at all.
//!
//! ## Totality, not clearing — and why
//!
//! `wit_graphql`'s deny sites and its ONE transport site return the SAME
//! discriminant, so [`Reason`]'s pairing is vacuous there: a stale deny class
//! latched by a swallowed denial could land on a later GENUINE transport
//! failure and SUPPRESS its retry. Under-retrying real transient failures is
//! the 2026-07-23 outage class, so that had to be closed before the denials
//! could be latched at all.
//!
//! The rule adopted is **totality**: on all four surfaces, every failing
//! return either latches a class paired with the discriminant it returns, or
//! explicitly CLEARS the latch. The transport site therefore always overwrites
//! whatever was there immediately before returning, and no stale class can
//! ride it.
//!
//! Two designs were rejected in favour of it, both measured rather than
//! assumed:
//!
//! * **Clear the latch at every host-call ENTRY.** Sufficient for the
//!   graphql hazard, and fail-safe against a future unlatched return — but it
//!   also destroys a class latched by an EARLIER call on ANOTHER surface. A
//!   `circuit-open` latched by `fetch`, swallowed, followed by a successful
//!   `graphql` call, would lose its marker and the fetch message would go back
//!   to reading `networkerror` ⇒ TRANSIENT. That is a deterministic failure
//!   becoming retryable — the same defect one direction over.
//! * **Clear on SUCCESS on the new surfaces** (what `fetch` does). Same
//!   objection: clearing can only ever REMOVE a marker, and removing a
//!   [`NON_TRANSIENT`] one is the forbidden direction. `fetch`'s clear-on-
//!   success predates the pairing and is left exactly as it ships; it is not
//!   replicated onto the three siblings.
//!
//! A host-call SEQUENCE NUMBER was considered and buys nothing over totality
//! (the suffix reader has no independent sequence to compare against, so
//! "not the most recent call" and "cleared" are the same observable). Adding a
//! deny variant to the three WIT enums is a full ABI break — every compiled
//! module recompiles in lockstep, and this repository carries 75 catalog
//! templates with checked-in `bindings.rs` — so it is out of the question for
//! a diagnostic.
//!
//! ## Still outside
//!
//! The ~50 `capability-world` denials on the NON-HTTP host functions (cache,
//! files, memory, state, object_storage, …): the latch is per-execution and
//! egress-shaped, and covering them needs a general per-call reason mechanism
//! rather than this one.
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

// ── HTTP-surface POLICY / CAP denials ────────────────────────────────────
//
// These are the causes behind the OTHER two `wit_http::Error` discriminants.
// Every one of them is DETERMINISTIC — the same call re-runs the same policy
// decision or re-hits the same cap — so every one is in [`NON_TRANSIENT`]
// below. That is not a coincidence to be relied on loosely: it is what makes
// a mis-attribution among these tokens unable to change a retry decision.
//
// The token is the SAME string the site already passes to
// `TalosContext::record_capability_denied` as its `policy`, so the
// `[host:<policy>]` diagnostic and the `[reason_class=…]` marker cannot drift
// into disagreeing about why a call was refused. Two deliberate deviations,
// both documented at their consts: [`NO_ALLOWLIST`] and [`PRIVATE_IP`].

/// The caller-supplied URL exceeded `MAX_OUTBOUND_URL_BYTES`.
///
/// A hostile-guest DoS guard (`url::Url::parse` is O(N)), not an author typo —
/// which is exactly the distinction the bare `invalidurl` discriminant loses.
pub const URL_TOO_LONG: &str = "url-too-long";
/// `url::Url::parse` rejected the caller's URL. The ONE genuine author error
/// among the `invalidurl` causes.
pub const URL_PARSE: &str = "url-parse";
/// A non-`https` scheme was refused (`WASM_ALLOW_INSECURE_HTTP` is off).
///
/// A SECURITY refusal — plaintext egress can leak a `vault://`-substituted
/// header in flight — reported to the guest as `invalidurl`, i.e. as a typo.
/// Live instance: workflow execution `43b78079-d0a0-4aff-83f1-e3e80dc7195a`.
pub const INSECURE_SCHEME: &str = "insecure-scheme";
/// The module's `capability_world` does not grant HTTP at all.
pub const CAPABILITY_WORLD: &str = "capability-world";
/// The module declared an EMPTY `allowed_hosts`, which denies every host.
///
/// Deviation from the `policy` token (`no-allowlist-configured`) and the only
/// one that is not cosmetic: `configured` contains the substring `config`,
/// which `talos_ops_alerts_repository::self_monitor` tests for in an arm
/// ABOVE its `forbiddenhost` arm. Reusing the policy string verbatim would
/// re-class an egress denial as `missing_config` in the ops-alert dedup key
/// whenever the module's own text also said "missing" — a downstream class
/// change is drift too. Pinned by `tokens_never_collide_with_a_foreign_needle`.
pub const NO_ALLOWLIST: &str = "no-allowlist";
/// SSRF: the target resolved (or was written) as a private / loopback /
/// link-local / CGNAT / IPv4-mapped address.
///
/// The `policy` token here is an OPEN family — `private-ip`,
/// `private-ip-cgnat`, `private-ip-ipv4-mapped-ipv6`, `private-ip-nat64`, … —
/// derived per-address by `talos_ssrf_classify`. [`ALL`] must stay CLOSED (the
/// snapshot test and the hand-written classifier arms depend on it), so the
/// class is the family's common PREFIX: every member starts with `private-ip`,
/// so nothing drifts and the precise variant stays in the `[host:…]`
/// diagnostic.
pub const PRIVATE_IP: &str = "private-ip";
/// The host is not matched by any `allowed_hosts` pattern.
pub const ALLOWED_HOSTS: &str = "allowed-hosts";
/// A Tier-1 actor was refused an EXTERNAL LLM PROVIDER host.
///
/// Distinct from [`TIER1_EGRESS`], which is the blanket local-egress-only
/// resolver gate inferred from a connect-phase failure. This one is the
/// destination deny-list and is known at validation time.
pub const TIER1_LLM_EGRESS: &str = "tier1-llm-egress";
/// A Tier-1 actor was refused a PUBLIC IP literal.
pub const TIER1_PUBLIC_IP_EGRESS: &str = "tier1-public-ip-egress";
/// A read-only actor attempted a mutating HTTP method.
pub const WRITE_CEILING: &str = "write-ceiling";
/// A read-only actor under `TALOS_WRITE_CEILING_STRICT_EGRESS` attempted a
/// read from a host admitted only by a wildcard rather than named explicitly.
pub const WRITE_CEILING_STRICT_EGRESS: &str = "write-ceiling-strict-egress";
/// The HTTP method is not in the module's `allowed_methods`.
pub const METHOD_ALLOWLIST: &str = "method-allowlist";
/// `MAX_HTTP_CALLS_PER_EXECUTION` is spent for this execution.
///
/// No `policy` token exists for this site (it does not audit), so the token is
/// minted here. Hyphenated deliberately: `rate limit` with a SPACE is a needle
/// in two downstream classifiers' own buckets.
pub const EXECUTION_RATE_LIMIT: &str = "execution-rate-limit";
/// `MAX_HTTP_CALLS_PER_HOST_PER_EXECUTION` is spent for this host.
pub const PER_HOST_RATE_LIMIT: &str = "per-host-rate-limit";
/// The OUTBOUND request carried more headers than `MAX_OUTBOUND_HEADERS`.
///
/// Named apart from [`HEADER_CAP`], which is the INBOUND response cap — the
/// two have opposite remediations (shrink your request vs. the upstream is
/// misbehaving) and opposite directions of travel.
pub const REQUEST_HEADER_CAP: &str = "request-header-cap";
/// The OUTBOUND body exceeded `MAX_OUTBOUND_HTTP_BODY_BYTES`.
///
/// Also the class for `wit_graphql`'s 1 MB query cap: a GraphQL query IS the
/// request body, so minting a second token for it would split one cap across
/// two names that mean the same thing to an operator.
pub const REQUEST_BODY_CAP: &str = "request-body-cap";
/// A GraphQL introspection query (`__schema` / `__type`) was refused.
///
/// The site's `policy` is an open two-member family (`tier1-introspection`
/// when a privacy-class actor probes a third-party schema shape,
/// `env-introspection-block` under the operator-wide
/// `TALOS_WIT_GRAPHQL_BLOCK_INTROSPECTION`), collapsed to one class for the
/// same reason [`PRIVATE_IP`] is: [`ALL`] must stay CLOSED. The precise
/// variant stays in the `[host:…]` diagnostic.
pub const GRAPHQL_INTROSPECTION: &str = "graphql-introspection";
/// `MAX_SSE_STREAMS_PER_EXECUTION` concurrent SSE streams are already open.
///
/// Named apart from [`EXECUTION_RATE_LIMIT`] deliberately: that one is a
/// CUMULATIVE per-execution call budget which, once spent, stays spent, while
/// this is a CONCURRENCY cap that clears the moment the guest calls
/// `http-stream::close`. The remediations are opposite (raise the budget vs.
/// close your streams), and a class exists to name a remediation.
pub const SSE_STREAM_CAP: &str = "sse-stream-cap";

/// The EGRESS-surface policy / cap classes, as one list.
///
/// Named `HTTP_POLICY_CLASSES` from when `host::http` was the only covered
/// surface; it now spans all four (`http`, `graphql`, `webhook`,
/// `http_stream`). The name is load-bearing downstream — the hand-mirrored
/// `talos_retry_intelligence::HTTP_POLICY_DENIAL_CLASSES` is pinned to it by
/// `closed_set_snapshot` — so it is left alone rather than renamed for tidiness.
///
/// These are the tokens minted for every discriminant that is not a transport
/// failure. Kept as a named subset of [`ALL`] because three separate
/// things need exactly this set and nothing else: the non-transient property
/// test below, the foreign-needle collision test below, and the hand-written
/// mirror arm in `talos_retry_intelligence::classify_error` (which cannot
/// import it — see [`ALL`]).
///
/// UNLIKE the transport classes above, every member is DETERMINISTIC, so every
/// member is also in [`NON_TRANSIENT`]. `every_http_policy_class_is_non_transient`
/// enforces that rather than trusting the eye.
pub const HTTP_POLICY_CLASSES: &[&str] = &[
    URL_TOO_LONG,
    URL_PARSE,
    INSECURE_SCHEME,
    CAPABILITY_WORLD,
    NO_ALLOWLIST,
    PRIVATE_IP,
    ALLOWED_HOSTS,
    TIER1_LLM_EGRESS,
    TIER1_PUBLIC_IP_EGRESS,
    WRITE_CEILING,
    WRITE_CEILING_STRICT_EGRESS,
    METHOD_ALLOWLIST,
    EXECUTION_RATE_LIMIT,
    PER_HOST_RATE_LIMIT,
    REQUEST_HEADER_CAP,
    REQUEST_BODY_CAP,
    GRAPHQL_INTROSPECTION,
    SSE_STREAM_CAP,
];

// ── The guest-visible WIT discriminants a class is allowed to explain ────
//
// These are the `name` strings the generated bindings render into the guest's
// `Error { code: N, name: "…", message: "" }` Debug output — the literal text
// the node-failure message carries. A class is latched TOGETHER with the one
// it explains; see [`Reason`].

/// `wit_http::Error::Networkerror` / `wit_graphql::Error::Networkerror`.
pub const WIT_NETWORKERROR: &str = "networkerror";
/// `wit_http::Error::Invalidurl`.
pub const WIT_INVALIDURL: &str = "invalidurl";
/// `wit_http::Error::Forbiddenhost`.
pub const WIT_FORBIDDENHOST: &str = "forbiddenhost";
/// `wit_http::Error::Timeout` and `wit_webhook::Error::Timeout`.
pub const WIT_TIMEOUT: &str = "timeout";
/// `wit_graphql::Error::Queryerror`.
///
/// One emitting site (the write-ceiling gate), and it needs a marker for a
/// reason the count hides: `queryerror` contains the substring **`query`**,
/// which `talos_retry_intelligence::classify_error` keys on for its
/// `database_error` bucket. A read-only actor refused a GraphQL operation was
/// therefore reported as a DATABASE failure. Non-transient either way, so this
/// is a remediation fix, not a retry fix.
pub const WIT_QUERYERROR: &str = "queryerror";
/// `wit_webhook::Error::Sendfailed`.
///
/// Note this is NOT a prefix or suffix of [`SEND_FAILED`] (`send-failed`) —
/// the WIT case is unhyphenated and the reason class is hyphenated, so no
/// message can satisfy one by carrying the other.
pub const WIT_SENDFAILED: &str = "sendfailed";
/// `wit_http_stream::Error::ForbiddenHost`.
///
/// The `http-stream` WIT enum spells its cases with HYPHENS, and wit-bindgen
/// renders the case name verbatim into both `Debug` (`name: "forbidden-host"`)
/// and `Display` (`forbidden-host (error 1)`) — verified against the
/// checked-in `module-templates/*/src/bindings.rs`. So `forbiddenhost`, the
/// `wit_http` spelling, does NOT match it, which is why this surface needed
/// its own consts rather than reusing [`WIT_FORBIDDENHOST`].
pub const WIT_FORBIDDEN_HOST_HYPHENATED: &str = "forbidden-host";
/// `wit_http_stream::Error::InvalidUrl`. Hyphenated; see
/// [`WIT_FORBIDDEN_HOST_HYPHENATED`].
pub const WIT_INVALID_URL_HYPHENATED: &str = "invalid-url";
/// `wit_http_stream::Error::ConnectionFailed`.
///
/// Despite the name, NONE of its three emitting sites is a transport failure:
/// one is a cancellation and two are mutex-poison guards. A `connect`
/// transport failure happens inside a spawned task and never reaches the guest
/// as an error at all — the stream simply yields no events.
pub const WIT_CONNECTION_FAILED: &str = "connection-failed";
/// `wit_http_stream::Error::RateLimited`.
pub const WIT_RATE_LIMITED: &str = "rate-limited";

/// A latched host-side failure: the [`reason_class`](self) token PLUS the WIT
/// discriminant it is allowed to explain.
///
/// The pairing is the whole safety mechanism. The latch is set on failure and
/// cleared only on `fetch` SUCCESS, so a module that swallows a failure and
/// then fails for an unrelated reason still holds a stale class. Binding the
/// class to the token it explains means the marker can only ever land on a
/// message that carries that exact opaque discriminant — an
/// `insecure-scheme` class raised at an `invalidurl` site can never be stamped
/// onto a `forbiddenhost` or a `401`. See
/// [`crate::runtime::last_network_reason_suffix`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reason {
    /// One of the `reason_class` consts. Never request-derived.
    pub class: &'static str,
    /// One of the `WIT_*` consts — the discriminant name the guest will see.
    pub wit: &'static str,
}

impl Reason {
    /// A class raised at a site returning `wit_http::Error::Networkerror`.
    pub const fn network(class: &'static str) -> Self {
        Self {
            class,
            wit: WIT_NETWORKERROR,
        }
    }
    /// A class raised at a site returning `wit_http::Error::Invalidurl`.
    pub const fn invalid_url(class: &'static str) -> Self {
        Self {
            class,
            wit: WIT_INVALIDURL,
        }
    }
    /// A class raised at a site returning `wit_http::Error::Forbiddenhost`.
    pub const fn forbidden_host(class: &'static str) -> Self {
        Self {
            class,
            wit: WIT_FORBIDDENHOST,
        }
    }
    /// A class raised at a site returning `wit_http::Error::Timeout`.
    pub const fn timeout(class: &'static str) -> Self {
        Self {
            class,
            wit: WIT_TIMEOUT,
        }
    }
    /// A class raised at a site returning `wit_graphql::Error::Queryerror`.
    pub const fn graphql_query_error(class: &'static str) -> Self {
        Self {
            class,
            wit: WIT_QUERYERROR,
        }
    }
    /// A class raised at a site returning `wit_webhook::Error::Sendfailed`.
    pub const fn webhook_send_failed(class: &'static str) -> Self {
        Self {
            class,
            wit: WIT_SENDFAILED,
        }
    }
    /// A class raised at a site returning
    /// `wit_http_stream::Error::ForbiddenHost`.
    pub const fn stream_forbidden_host(class: &'static str) -> Self {
        Self {
            class,
            wit: WIT_FORBIDDEN_HOST_HYPHENATED,
        }
    }
    /// A class raised at a site returning `wit_http_stream::Error::InvalidUrl`.
    pub const fn stream_invalid_url(class: &'static str) -> Self {
        Self {
            class,
            wit: WIT_INVALID_URL_HYPHENATED,
        }
    }
    /// A class raised at a site returning
    /// `wit_http_stream::Error::ConnectionFailed`.
    pub const fn stream_connection_failed(class: &'static str) -> Self {
        Self {
            class,
            wit: WIT_CONNECTION_FAILED,
        }
    }
    /// A class raised at a site returning
    /// `wit_http_stream::Error::RateLimited`.
    pub const fn stream_rate_limited(class: &'static str) -> Self {
        Self {
            class,
            wit: WIT_RATE_LIMITED,
        }
    }
}

/// Map a `tier1_egress_deny_reason` policy onto its closed-set reason class.
///
/// An explicit `match` rather than passing the policy string straight through:
/// the policy vocabulary lives in `host::egress` and can grow, while [`ALL`]
/// must stay CLOSED (`closed_set_snapshot` and the hand-written classifier
/// arms both depend on it). A future policy therefore falls back to the
/// generic [`TIER1_EGRESS`] — which IS in the set and IS non-transient —
/// instead of stamping a token no classifier knows.
///
/// Lives here rather than in `host::http` because all four egress surfaces
/// (`http`, `graphql`, `webhook`, `http_stream`) call the same
/// `tier1_egress_deny_reason` and must agree on the mapping; a per-file copy
/// is the drift this workspace has paid for repeatedly.
pub(crate) fn tier1_egress_class(policy: &str) -> &'static str {
    match policy {
        "tier1-llm-egress" => TIER1_LLM_EGRESS,
        "tier1-public-ip-egress" => TIER1_PUBLIC_IP_EGRESS,
        _ => TIER1_EGRESS,
    }
}

/// Split `TalosContext::validate_no_dns_rebinding`'s `Err` into the two
/// materially different things it means.
///
/// That function is the ONE MIXED deny site on every surface that calls it: it
/// returns `Err(policy)` for an SSRF answer (the hostname resolved into a
/// private range — deterministic, a denial) and `Err("dns-resolution-failed")`
/// when the resolver itself failed (transient, and NOT a denial at all).
/// Reading its `Err` as one thing is how a DNS blip would have been filed as a
/// capability denial and permanently un-retried.
///
/// `Some(PRIVATE_IP)` is the SSRF case — the family PREFIX, for the same
/// closed-set reason as [`PRIVATE_IP`] itself. `None` is the resolver failure;
/// each caller then decides what preserves ITS surface's current transience
/// (`graphql` latches [`DNS`], which is transient exactly as a bare
/// `networkerror` already was; `webhook` and `http_stream` CLEAR, because
/// their discriminants are non-transient today and latching a transient class
/// would GRANT a retry that does not exist — on `webhook` that would be a
/// retry of a mutating POST).
pub(crate) fn dns_rebinding_class(err: &str) -> Option<&'static str> {
    if err == "dns-resolution-failed" {
        None
    } else {
        Some(PRIVATE_IP)
    }
}

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
    URL_TOO_LONG,
    URL_PARSE,
    INSECURE_SCHEME,
    CAPABILITY_WORLD,
    NO_ALLOWLIST,
    PRIVATE_IP,
    ALLOWED_HOSTS,
    TIER1_LLM_EGRESS,
    TIER1_PUBLIC_IP_EGRESS,
    WRITE_CEILING,
    WRITE_CEILING_STRICT_EGRESS,
    METHOD_ALLOWLIST,
    EXECUTION_RATE_LIMIT,
    PER_HOST_RATE_LIMIT,
    REQUEST_HEADER_CAP,
    REQUEST_BODY_CAP,
    GRAPHQL_INTROSPECTION,
    SSE_STREAM_CAP,
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
    // Every HTTP-surface policy / cap denial. A policy re-runs identically and
    // a cap re-trips identically, so none of them may earn a retry. Listed in
    // the same order as `ALL` so a missing entry is visible by eye as well as
    // by `closed_set_snapshot`.
    URL_TOO_LONG,
    URL_PARSE,
    INSECURE_SCHEME,
    CAPABILITY_WORLD,
    NO_ALLOWLIST,
    PRIVATE_IP,
    ALLOWED_HOSTS,
    TIER1_LLM_EGRESS,
    TIER1_PUBLIC_IP_EGRESS,
    WRITE_CEILING,
    WRITE_CEILING_STRICT_EGRESS,
    METHOD_ALLOWLIST,
    EXECUTION_RATE_LIMIT,
    PER_HOST_RATE_LIMIT,
    REQUEST_HEADER_CAP,
    REQUEST_BODY_CAP,
    GRAPHQL_INTROSPECTION,
    SSE_STREAM_CAP,
];

/// The rendered marker appended to a node-failure message, e.g.
/// `[reason_class=dns]`. Both classifiers match on the `reason_class=<token>`
/// substring, so a `retry_condition` of `error_message.contains("circuit-open")`
/// also matches — the plain token is a substring of the marker.
pub fn marker(class: &str) -> String {
    format!("[reason_class={class}]")
}

/// Should a connect-phase failure be attributed to the blanket
/// local-egress-only SSRF gate rather than to the network?
///
/// `local_egress_only` MUST be the posture the context's own HTTP client was
/// built with (`TalosContext::local_egress_only`) — never `max_llm_tier ==
/// Tier1`, which disagrees with it in both directions since the `egress_scope`
/// split. Pure so the matrix is testable without building a context.
///
/// Only the two CONNECT classes qualify: under local-egress-only the resolver
/// hands hyper an EMPTY address list, which surfaces as a connect-phase
/// failure. A TLS alert or a post-connect reset means the connection was
/// permitted and actually reached a peer, so it is not the gate.
pub(crate) fn is_local_egress_attributable(class: &str, local_egress_only: bool) -> bool {
    local_egress_only && matches!(class, CONNECT_REFUSED | CONNECT_FAILED)
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
    classify_transport_detail_with_kind(&detail, e.is_connect(), source_chain_io_kind(e))
}

/// The `std::io::ErrorKind` of the first `std::io::Error` in the source chain,
/// if any.
///
/// This is the AUTHORITATIVE refusal signal. `hyper_util`'s `ConnectError`
/// wraps the raw `std::io::Error` from `connect(2)`, and `ErrorKind` is
/// derived from the errno — unlike the error's `Display`, which comes from
/// `strerror_r` and is therefore locale-dependent (a non-C `LC_MESSAGES` in
/// the worker image renders `ECONNREFUSED` in the operator's language, and the
/// `"connection refused"` substring silently stops matching). The substring
/// pass stays as a fallback for chains that stringify the io error instead of
/// nesting it.
fn source_chain_io_kind(e: &reqwest::Error) -> Option<std::io::ErrorKind> {
    let mut src: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(e);
    for _ in 0..16 {
        let cur = src?;
        if let Some(io) = cur.downcast_ref::<std::io::Error>() {
            return Some(io.kind());
        }
        src = cur.source();
    }
    None
}

/// Test shorthand for [`classify_transport_detail_with_kind`] with no
/// downcastable `io::Error` in the chain — i.e. the substring fallback path.
/// Production always has the real error object and so always passes a kind.
#[cfg(test)]
pub(crate) fn classify_transport_detail(detail: &str, is_connect: bool) -> &'static str {
    classify_transport_detail_with_kind(detail, is_connect, None)
}

/// Pure core of [`classify_reqwest_send_error`], split out so the mapping is
/// unit-testable without constructing real `reqwest` errors (whose inner
/// `Kind` is private and cannot be forged from outside the crate).
///
/// `detail` must already be lowercased and must contain ONLY source-chain
/// text — see the caller's doc-comment for why request-derived text is barred.
///
/// `io_kind` is the authoritative refusal signal (errno-derived, therefore
/// locale-independent); the `REFUSED_MARKERS` substring pass is only consulted
/// when no `io::Error` was found to downcast.
pub(crate) fn classify_transport_detail_with_kind(
    detail: &str,
    is_connect: bool,
    io_kind: Option<std::io::ErrorKind>,
) -> &'static str {
    if TLS_MARKERS.iter().any(|m| detail.contains(m)) {
        return TLS;
    }
    if is_connect {
        let refused = match io_kind {
            Some(k) => k == std::io::ErrorKind::ConnectionRefused,
            None => REFUSED_MARKERS.iter().any(|m| detail.contains(m)),
        };
        if refused {
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

    /// The refusal signal must come from the errno, not from `strerror`'s
    /// locale-dependent prose. A worker image with a non-C `LC_MESSAGES`
    /// renders `ECONNREFUSED` in the operator's language, and a substring-only
    /// detector silently degrades every refusal to `connect-failed` — the
    /// token claiming a precision the code no longer has.
    #[test]
    fn io_error_kind_beats_locale_dependent_error_text() {
        use std::io::ErrorKind;
        // Localized text, no English marker — the errno still decides.
        assert_eq!(
            classify_transport_detail_with_kind(
                "tcp connect error: verbindungsaufbau abgelehnt",
                true,
                Some(ErrorKind::ConnectionRefused),
            ),
            CONNECT_REFUSED
        );
        // And the converse: hyper's EMPTY-address-list error (what a
        // local-egress-only resolver produces) is NotConnected, so it must
        // NOT be called a refusal even if some other frame said "refused".
        assert_eq!(
            classify_transport_detail_with_kind(
                "tcp connect error: connection refused",
                true,
                Some(ErrorKind::NotConnected),
            ),
            CONNECT_FAILED
        );
        // No io error to downcast → substring fallback still works.
        assert_eq!(
            classify_transport_detail_with_kind(
                "tcp connect error: connection refused",
                true,
                None
            ),
            CONNECT_REFUSED
        );
    }

    /// The egress-attribution predicate. Keyed on the resolver's OWN posture,
    /// not on the LLM tier — the two disagree in both directions.
    #[test]
    fn egress_attribution_keys_on_the_resolver_posture_only() {
        // Tier1 + egress_scope=Public (the house pattern) → public egress is
        // PERMITTED, so a connect failure is an ordinary transport failure and
        // must stay retryable.
        assert!(!is_local_egress_attributable(CONNECT_FAILED, false));
        assert!(!is_local_egress_attributable(CONNECT_REFUSED, false));
        // Tier2 + egress_scope=Local → the gate IS the cause.
        assert!(is_local_egress_attributable(CONNECT_FAILED, true));
        assert!(is_local_egress_attributable(CONNECT_REFUSED, true));
        // A TLS alert or a post-connect reset means a peer was reached, so the
        // blanket gate cannot be the explanation even under local-egress-only.
        for c in [TLS, SEND_FAILED, RESPONSE_STREAM, TIMEOUT] {
            assert!(!is_local_egress_attributable(c, true), "class {c}");
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
        assert_eq!(
            NON_TRANSIENT,
            &[
                "circuit-open",
                "tier1-egress",
                "cancelled",
                "response-too-large",
                "header-cap",
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
    }

    /// Every token appended to a node-failure message is TEXT that three
    /// OTHER classifiers then pattern-match. None of them can be updated in
    /// lockstep from here — two are in crates this one deliberately does not
    /// depend on, and one is a repository crate — so the guard is that a token
    /// must not contain a needle any of them tests for in an arm ABOVE the arm
    /// the message already lands in.
    ///
    /// This is not hypothetical. `no-allowlist-configured` — the literal
    /// `policy` string the site already passes to `record_capability_denied`,
    /// i.e. the obvious token to reuse — contains `config`, and
    /// `talos_ops_alerts_repository::self_monitor` tests
    /// `has("missing") && has("config")` in an arm ABOVE its `forbiddenhost`
    /// arm. Reusing it verbatim would silently re-class an egress denial as
    /// `missing_config` (a dedup-key segment) for any module whose own error
    /// text also said "missing". [`NO_ALLOWLIST`] is the shortened token, and
    /// this test is why.
    #[test]
    fn tokens_never_collide_with_a_foreign_needle() {
        // Needles tested by an arm that runs BEFORE the arm a
        // `forbiddenhost` / `invalidurl` message already reaches, in:
        //   * talos_ops_alerts_repository::self_monitor::classify  (repo crate)
        //   * talos_failure_analysis_service::classify_error
        //   * talos_retry_intelligence::classify_error
        //   * crate::runtime::is_transient_error_text
        // Plus the needles those crates use for buckets a marker must never
        // drag a message into (a timeout / rate-limit / auth reading).
        const FOREIGN_NEEDLES: &[&str] = &[
            "approval denied",
            "approval was denied",
            "missing",
            "config",
            "fuel exhausted",
            "out of fuel",
            "circuit open",
            "circuit breaker open",
            "output_schema",
            "output schema",
            "required keys",
            "got prose",
            "signature",
            "hmac",
            "no upstream",
            "timeout",
            "timed out",
            "deadline exceeded",
            "rate limit",
            "too many requests",
            "unauthorized",
            "forbidden",
            "not found",
            "notfound",
            "invalid token",
            "access_token invalid",
            "wasm trap",
            "trap: ",
            "panic",
            "memory",
            "oom",
            "vault",
            "secret",
            "sql",
            "query",
            "database",
            "postgres",
            "sqlite",
            "deadlock",
            "connection pool",
            "connection refused",
            "connection reset",
            "connection aborted",
            "connection failed",
            "connectionfailed",
            "broken pipe",
            "unexpected eof",
            "no route to host",
            "failed to connect",
            "connect error",
            "dns",
            "network",
            "expected",
            "found ",
            "invalid type",
            "invalid json",
            "trailing characters",
            "serde",
            "from_str",
            "cargo",
            "compile",
            "401",
            "403",
            "404",
            "429",
            "500",
            "502",
            "503",
            "504",
            "temporary failure",
            "try again",
            "unavailable",
            "lock timeout",
            "pool timed out",
            "pool exhausted",
            "no available connection",
            "no such host",
        ];
        // Scoped to the classes this change MINTS. The four pre-existing
        // transport tokens deliberately ARE downstream vocabulary — `dns`,
        // `tls`, `timeout` and `secret-lookup` each contain a needle by
        // design, because each already has a HAND-WRITTEN arm in the
        // classifier that reads it, and each is stamped only onto a
        // `networkerror` (or `timeout`) message whose bucket those arms
        // already own. Asserting their collisions here would fail the test on
        // shipped, intentional behaviour, so they are exempt BY NAME rather
        // than by the list happening not to mention them.
        const EXEMPT: &[&str] = &[DNS, TLS, TIMEOUT, SECRET_LOOKUP];
        for t in EXEMPT {
            assert!(ALL.contains(t), "exemption names a token not in ALL: {t:?}");
        }
        for t in HTTP_POLICY_CLASSES {
            for n in FOREIGN_NEEDLES {
                assert!(
                    !t.contains(n),
                    "reason_class token {t:?} contains {n:?}, a needle a DOWNSTREAM \
                     classifier keys on — appending [reason_class={t}] to a message \
                     would silently move it into that bucket. Rename the token."
                );
            }
        }
        // Every token in ALL is either a minted HTTP class (checked above) or
        // a named exemption. Without this the check silently stops covering a
        // token added to ALL but not to HTTP_POLICY_CLASSES.
        for t in ALL {
            assert!(
                HTTP_POLICY_CLASSES.contains(t)
                    || EXEMPT.contains(t)
                    || !FOREIGN_NEEDLES.iter().any(|n| t.contains(n)),
                "token {t:?} is in ALL, is not an HTTP policy class, is not a named \
                 exemption, and collides with a downstream needle"
            );
        }
        assert_eq!(TIMEOUT, WIT_TIMEOUT);
    }

    /// Every class the HTTP surface can raise is DETERMINISTIC, so every one
    /// of them must be non-transient. Stated as a property over the two lists
    /// rather than left to the eye: this is the invariant that makes a
    /// mis-attribution AMONG these tokens unable to change a retry decision,
    /// which is the whole reason the pairing is safe to extend.
    #[test]
    fn every_http_policy_class_is_non_transient() {
        assert_eq!(HTTP_POLICY_CLASSES.len(), 18);
        for t in HTTP_POLICY_CLASSES {
            assert!(ALL.contains(t), "{t:?} missing from ALL");
            assert!(
                NON_TRANSIENT.contains(t),
                "{t:?} is an HTTP policy/cap denial and MUST be non-transient"
            );
        }
    }

    /// `PRIVATE_IP` is the CLOSED-set stand-in for `talos_ssrf_classify`'s
    /// open policy family. The substitution is only honest if it is a prefix
    /// of every member — otherwise the marker and the `[host:…]` diagnostic
    /// name different things.
    #[test]
    fn private_ip_class_is_a_prefix_of_every_ssrf_policy_variant() {
        for policy in [
            "private-ip",
            "private-ip-unspecified",
            "private-ip-cgnat",
            "private-ip-ipv4-mapped-ipv6",
            "private-ip-cgnat-ipv4-mapped-ipv6",
            "private-ip-ipv4-compat-ipv6",
            "private-ip-nat64",
            "private-ip-6to4",
            "private-ip-embedded-ipv4",
        ] {
            assert!(
                policy.starts_with(PRIVATE_IP),
                "SSRF policy {policy:?} is not covered by the {PRIVATE_IP:?} class"
            );
        }
    }

    /// The pairing constructors must produce the WIT token the emitting site
    /// actually returns — a `Reason::forbidden_host` that carried
    /// `networkerror` would be stamped onto the wrong messages and withheld
    /// from the right ones.
    #[test]
    fn reason_constructors_bind_the_right_discriminant() {
        assert_eq!(Reason::network(DNS).wit, "networkerror");
        assert_eq!(Reason::invalid_url(URL_PARSE).wit, "invalidurl");
        assert_eq!(Reason::forbidden_host(ALLOWED_HOSTS).wit, "forbiddenhost");
        assert_eq!(Reason::timeout(TIMEOUT).wit, "timeout");
        assert_eq!(Reason::forbidden_host(ALLOWED_HOSTS).class, ALLOWED_HOSTS);
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

    /// END-TO-END against a REAL `reqwest::Error`, not a hand-built string.
    ///
    /// The two claims this PR makes about the send path are only worth as much
    /// as the real error object supports, and `reqwest::Error`'s inner `Kind`
    /// is private so no unit test can forge one. Here we produce a genuine one
    /// — connect to a loopback port nothing is listening on, with a canary
    /// access token in the query string — and assert both claims at once:
    ///
    /// 1. **No leak.** The full URL (reqwest's `Display` appends
    ///    ` for url (…)` verbatim, query string included) is erased BEFORE
    ///    truncation, so neither the token, the query parameter name, the
    ///    path, nor the loopback IP survives into the worker log.
    /// 2. **Honest class.** The real source chain classifies `connect-refused`
    ///    via the errno, exercising the `io::ErrorKind` downcast rather than
    ///    the locale-dependent substring fallback.
    ///
    /// Hermetic: loopback only, no external network, no listener.
    #[tokio::test]
    async fn real_reqwest_error_is_classified_and_never_leaks_its_url() {
        // Bind then drop to obtain a port that is (almost certainly) free, so
        // connect() gets a prompt ECONNREFUSED instead of hanging.
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
            l.local_addr().expect("addr").port()
        };
        let url =
            format!("http://127.0.0.1:{port}/v1/messages?access_token=sk-canary-000111222333");
        let err = reqwest::Client::builder()
            // Explicit per lint check 32 — the connect never succeeds here, but
            // the rule is "no client without a stated redirect posture".
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .expect("client")
            .get(&url)
            .send()
            .await
            .expect_err("connect to a closed loopback port must fail");

        // Premise: the raw error really does carry the secret-bearing URL —
        // if reqwest ever stops doing this the test still holds, but the
        // assertion below would be vacuous, so state it.
        let raw = err.to_string();
        assert!(
            raw.contains("sk-canary-000111222333") || !raw.contains("127.0.0.1"),
            "premise check: raw reqwest Display was {raw:?}"
        );

        let out = sanitized_transport_detail(&err);
        assert!(
            !out.contains("sk-canary-000111222333"),
            "secret leaked: {out}"
        );
        assert!(!out.contains("access_token"), "query param leaked: {out}");
        assert!(!out.contains("/v1/messages"), "url path leaked: {out}");
        assert!(!out.contains("127.0.0.1"), "loopback IP leaked: {out}");
        assert!(!out.contains(&port.to_string()), "port leaked: {out}");

        // And the class is the honest one, derived from the errno.
        assert_eq!(classify_reqwest_send_error(&err), CONNECT_REFUSED);
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
