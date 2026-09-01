//! Reason classes on the THREE sibling egress surfaces — `wit_graphql`,
//! `wit_webhook` and `wit_http_stream` — driven through the real host
//! functions on a real [`TalosContext`].
//!
//! ## What was broken, measured rather than assumed
//!
//! [`crate::reason_class`] covered `host::http` only. The three siblings were
//! inventoried by script and every headline number in the brief that motivated
//! this change turned out to be wrong in the direction that mattered:
//!
//! * **`graphql`** — 17 sites return `Networkerror`, and **16 of them are
//!   deterministic** (nine policy denials, four caps, a URL parse, a
//!   secret-slot failure, a cancellation). Exactly ONE is the genuine
//!   transport failure. Since a bare `networkerror` is TRANSIENT in every
//!   classifier, every one of those 16 was being re-dispatched by the
//!   controller: an SSRF block and a Tier-1 data-egress refusal each burned
//!   three attempts and told the operator "network transient". This is the
//!   live bug, and it is the ONLY one of the three surfaces where a marker
//!   moves a message across the transient boundary.
//! * **`webhook`** — 16 sites return `Sendfailed`, 15 deterministic, one
//!   transport. `sendfailed` matches no arm in any classifier, so all 16
//!   already read NON-transient. Diagnostic fix only.
//! * **`http_stream`** — its WIT enum is hyphenated (`forbidden-host`,
//!   `invalid-url`, `connection-failed`, `rate-limited`), which no
//!   `forbiddenhost` arm matches; `forbidden-host` instead matched the
//!   substring `forbidden` and read as `auth_failure` / `http_403`. Its three
//!   `ConnectionFailed` sites are NOT transport failures — one cancellation
//!   and two mutex-poison guards. A `connect` transport failure happens in a
//!   spawned task and never reaches the guest as an error at all.
//!
//! ## The property these tests exist to pin
//!
//! On `graphql` the deny sites and the transport site return the SAME
//! discriminant, so [`crate::reason_class::Reason`]'s pairing — the mechanism
//! that bounds a stale latch on `host::http` — is VACUOUS there. The bound
//! that replaces it is **totality**: every failing return either latches a
//! class or explicitly clears, so the latch always describes the call that
//! just ran and the transport site overwrites any deny class immediately
//! before returning.
//!
//! Both directions are taken throughout. A one-directional test passes against
//! the broken tree too — the broken tree also classifies, it just classifies
//! everything the same.
//!
//! ## The differential, and why it is not zero
//!
//! A 1,152-pair corpus — every (surface, WIT discriminant, class) pairing the
//! producer can actually emit, in both the `Debug` and `Display` forms, under
//! six message prefixes — was run through the pre-change classifier extracted
//! from `HEAD` and the post-change one. Two comparisons, because the
//! interesting change here is in the PRODUCER, not the consumer:
//!
//! * **Classifier-only** (same text, both versions): **2** differences, both
//!   on tokens minted by this change (`graphql-introspection`,
//!   `sse-stream-cap`). Nothing that existed before moves. 0 differences over
//!   44 non-WIT controller failure strings.
//! * **End-to-end** (what the retry gate saw BEFORE — the bare discriminant,
//!   since these three surfaces stamped nothing — versus what it sees AFTER):
//!   **58** distinct pairs move, of which 40 are on the three surfaces this
//!   change touches. **204 message variants move from TRANSIENT to
//!   NON-TRANSIENT, and every one is a `graphql` denial or cap** — the live
//!   bug. **ZERO move from non-transient to transient**, on any surface.
//!
//! The `webhook` and `http_stream` rows change BUCKET only
//! (`unknown`/`auth_failure` → `capability_denied` / `missing_secret` /
//! `invalid_url` / `cancelled`); their transience is unchanged in every row,
//! which is the structural reason those two surfaces carry no retry risk.

use std::collections::HashMap;
use std::sync::Arc;

use talos_workflow_job_protocol::LlmTier;

use super::{wit_graphql, wit_http, wit_http_stream, wit_webhook, TalosContext};
use crate::reason_class;
use crate::wit_inspector::CapabilityWorld;

/// The literal text the generated bindings render, quoted from the
/// checked-in `module-templates/*/src/bindings.rs`. `Error::name()` returns
/// the WIT case name VERBATIM, so the hyphenated `http-stream` cases really do
/// reach the operator hyphenated — which is the whole reason those needed
/// their own `WIT_*` consts.
const GUEST_GQL_NETWORKERROR: &str =
    r#"Component returned error: gql: Error { code: 0, name: "networkerror", message: "" }"#;
const GUEST_GQL_QUERYERROR: &str =
    r#"Component returned error: gql: Error { code: 2, name: "queryerror", message: "" }"#;
const GUEST_WEBHOOK_SENDFAILED: &str =
    r#"Component returned error: hook: Error { code: 1, name: "sendfailed", message: "" }"#;
const GUEST_STREAM_FORBIDDEN: &str =
    r#"Component returned error: sse: Error { code: 1, name: "forbidden-host", message: "" }"#;
const GUEST_STREAM_INVALID_URL: &str =
    r#"Component returned error: sse: Error { code: 0, name: "invalid-url", message: "" }"#;
const GUEST_STREAM_CONNECTION_FAILED: &str =
    r#"Component returned error: sse: Error { code: 2, name: "connection-failed", message: "" }"#;
const GUEST_STREAM_RATE_LIMITED: &str =
    r#"Component returned error: sse: Error { code: 3, name: "rate-limited", message: "" }"#;

fn ctx_with(world: CapabilityWorld, allowed_hosts: Vec<String>) -> TalosContext {
    ctx_full(world, allowed_hosts, vec![], LlmTier::Tier2)
}

fn ctx_full(
    world: CapabilityWorld,
    allowed_hosts: Vec<String>,
    allowed_methods: Vec<String>,
    tier: LlmTier,
) -> TalosContext {
    TalosContext::new(
        world,
        allowed_hosts,
        allowed_methods,
        128,
        HashMap::new(),
        None,
        None,
        false,
        None,
        Arc::new(crate::expose_fallback::ExposeFallback::new()),
        tier,
        None,
    )
    .expect("context builds")
}

fn gql(url: &str) -> wit_graphql::Request {
    wit_graphql::Request {
        url: url.to_string(),
        query: "{ viewer { id } }".to_string(),
        variables: None,
        headers: None,
        timeout_ms: None,
    }
}

fn hook(url: &str) -> wit_webhook::WebhookRequest {
    wit_webhook::WebhookRequest {
        url: url.to_string(),
        headers: vec![],
        body: "{}".to_string(),
        max_retries: Some(0),
        retry_delay_ms: Some(0),
    }
}

/// Render the node-failure message the runtime would build, using the
/// PRODUCTION suffix function against the PRODUCTION latch.
fn message_for(ctx: &TalosContext, guest_error: &str) -> String {
    let latch = ctx.network_reason_handle();
    format!(
        "{guest_error}{}",
        crate::runtime::last_network_reason_suffix(&latch, guest_error)
    )
}

fn latched_class(ctx: &TalosContext) -> Option<&'static str> {
    ctx.network_reason_handle().lock().unwrap().map(|r| r.class)
}

// ---------------------------------------------------------------------------
// graphql — the live bug
// ---------------------------------------------------------------------------

/// THE HEADLINE CASE. A GraphQL SSRF block reached the controller as a bare
/// `networkerror`, which `classify_error` reads as `network_transient` and
/// `is_transient_error_type` calls retryable — so the controller RE-DISPATCHED
/// a security control's refusal, three times, and told the operator the
/// network was flaky.
///
/// Asserted in BOTH directions: the unmarked message really is transient (so
/// the marker is load-bearing, not decoration) and the marked one is not.
#[tokio::test]
async fn a_graphql_ssrf_block_is_no_longer_retried_as_a_network_blip() {
    let mut ctx = ctx_with(CapabilityWorld::Http, vec!["*".to_string()]);
    assert!(
        latched_class(&ctx).is_none(),
        "precondition: nothing latched"
    );

    let out =
        <TalosContext as wit_graphql::Host>::execute(&mut ctx, gql("https://127.0.0.1/graphql"))
            .await;
    assert!(
        matches!(out, Err(wit_graphql::Error::Networkerror)),
        "premise: the SSRF gate still reports this as networkerror — if the WIT \
         enum ever gains a deny variant this whole mechanism can retire"
    );
    assert_eq!(latched_class(&ctx), Some(reason_class::PRIVATE_IP));

    let msg = message_for(&ctx, GUEST_GQL_NETWORKERROR);
    assert!(msg.contains("[reason_class=private-ip]"), "{msg}");

    // FALSIFICATION DIRECTION: the unmarked message is what shipped, and it
    // really was transient. Without this the test passes on the broken tree.
    assert!(
        crate::runtime::is_transient_error_text(GUEST_GQL_NETWORKERROR),
        "premise: a bare graphql networkerror WAS retried"
    );
    assert!(
        !crate::runtime::is_transient_error_text(&msg),
        "an SSRF denial is still classified transient: {msg}"
    );
}

/// Nine distinct graphql policies, nine distinct classes. `capability_denied`
/// as one bucket is not enough — "add the host to allowed_hosts" is the wrong
/// instruction for seven of these, and the marker is the only thing carrying
/// which one fired.
#[tokio::test]
async fn distinct_graphql_policies_latch_distinct_classes() {
    // No GraphQL capability at all.
    let mut ctx = ctx_with(CapabilityWorld::Minimal, vec!["*".to_string()]);
    let out =
        <TalosContext as wit_graphql::Host>::execute(&mut ctx, gql("https://ex.test/g")).await;
    assert!(matches!(out, Err(wit_graphql::Error::Networkerror)));
    assert_eq!(latched_class(&ctx), Some(reason_class::CAPABILITY_WORLD));

    // Empty allowlist denies everything — a different fix from "this host is
    // missing from your list".
    let mut ctx = ctx_with(CapabilityWorld::Http, vec![]);
    let _ = <TalosContext as wit_graphql::Host>::execute(&mut ctx, gql("https://ex.test/g")).await;
    assert_eq!(latched_class(&ctx), Some(reason_class::NO_ALLOWLIST));

    // Host simply not matched.
    let mut ctx = ctx_with(CapabilityWorld::Http, vec!["allowed.test".to_string()]);
    let _ =
        <TalosContext as wit_graphql::Host>::execute(&mut ctx, gql("https://other.test/g")).await;
    assert_eq!(latched_class(&ctx), Some(reason_class::ALLOWED_HOSTS));

    // Plaintext scheme — a SECURITY refusal (a `vault://` header would go out
    // in the clear), previously indistinguishable from a flaky network.
    let mut ctx = ctx_with(CapabilityWorld::Http, vec!["*".to_string()]);
    let _ = <TalosContext as wit_graphql::Host>::execute(&mut ctx, gql("http://ex.test/g")).await;
    assert_eq!(latched_class(&ctx), Some(reason_class::INSECURE_SCHEME));

    // Author typo.
    let mut ctx = ctx_with(CapabilityWorld::Http, vec!["*".to_string()]);
    let _ = <TalosContext as wit_graphql::Host>::execute(&mut ctx, gql("not a url")).await;
    assert_eq!(latched_class(&ctx), Some(reason_class::URL_PARSE));

    // Hostile-guest URL byte cap.
    let mut ctx = ctx_with(CapabilityWorld::Http, vec!["*".to_string()]);
    let long = format!(
        "https://ex.test/{}",
        "a".repeat(super::MAX_OUTBOUND_URL_BYTES)
    );
    let _ = <TalosContext as wit_graphql::Host>::execute(&mut ctx, gql(&long)).await;
    assert_eq!(latched_class(&ctx), Some(reason_class::URL_TOO_LONG));

    // The query IS the request body, so it shares `request-body-cap`.
    let mut ctx = ctx_with(CapabilityWorld::Http, vec!["*".to_string()]);
    let mut req = gql("https://ex.test/g");
    req.query = "q".repeat(1_000_001);
    let _ = <TalosContext as wit_graphql::Host>::execute(&mut ctx, req).await;
    assert_eq!(latched_class(&ctx), Some(reason_class::REQUEST_BODY_CAP));

    // Outbound header count cap.
    let mut ctx = ctx_with(CapabilityWorld::Http, vec!["*".to_string()]);
    let mut req = gql("https://ex.test/g");
    req.headers = Some(
        (0..=super::MAX_OUTBOUND_HEADERS)
            .map(|i| (format!("x-{i}"), "v".to_string()))
            .collect(),
    );
    let _ = <TalosContext as wit_graphql::Host>::execute(&mut ctx, req).await;
    assert_eq!(latched_class(&ctx), Some(reason_class::REQUEST_HEADER_CAP));

    // GraphQL is always POST; a module that declared GET-only must be refused,
    // and told THAT rather than "the host is blocked".
    //
    // Targeted by IP LITERAL, and that is not cosmetic: the method gate sits
    // BELOW the DNS-rebinding gate, and `validate_no_dns_rebinding` only runs
    // for `url::Host::Domain`. A hostname here reaches the resolver, fails to
    // resolve in any hermetic environment, and latches `dns` instead — which
    // is what this assertion caught on its first run. `PUBLIC_IP_LITERAL` is
    // RFC 5737 TEST-NET-3: routable as far as the SSRF classifier is
    // concerned, never actually routed anywhere.
    let mut ctx = ctx_full(
        CapabilityWorld::Http,
        vec!["*".to_string()],
        vec!["GET".to_string()],
        LlmTier::Tier2,
    );
    let _ = <TalosContext as wit_graphql::Host>::execute(
        &mut ctx,
        gql(&format!("https://{PUBLIC_IP_LITERAL}/g")),
    )
    .await;
    assert_eq!(latched_class(&ctx), Some(reason_class::METHOD_ALLOWLIST));
}

/// RFC 5737 TEST-NET-3. The SSRF classifier calls it public (it is not
/// RFC1918 / loopback / link-local / CGNAT), so it reaches the gates BELOW the
/// private-IP check — and because it is an IP LITERAL it skips
/// `validate_no_dns_rebinding` entirely, which is the only way to exercise
/// those gates without a resolver. It is reserved for documentation and is
/// never routed, so nothing can be reached at it.
const PUBLIC_IP_LITERAL: &str = "203.0.113.10";

/// A Tier-1 (privacy-class) actor's data-egress ceiling refused a GraphQL
/// target. The highest-consequence misclassification of the set: the egress
/// ceiling is exactly the thing that cannot change between attempts, and it
/// was being retried.
///
/// Driven through the IP-literal arm of `tier1_egress_deny_reason` rather than
/// its LLM-hostname arm, because the hostname arm sits below the DNS-rebinding
/// gate and reaching it would make this test depend on live DNS resolving
/// `api.anthropic.com`. Both arms map through the same
/// `reason_class::tier1_egress_class`, which has its own exhaustive test.
#[tokio::test]
async fn a_tier1_graphql_egress_refusal_is_non_transient() {
    let mut ctx = ctx_full(
        CapabilityWorld::Http,
        vec!["*".to_string()],
        vec![],
        LlmTier::Tier1,
    );
    let out = <TalosContext as wit_graphql::Host>::execute(
        &mut ctx,
        gql(&format!("https://{PUBLIC_IP_LITERAL}/g")),
    )
    .await;
    assert!(matches!(out, Err(wit_graphql::Error::Networkerror)));
    assert_eq!(
        latched_class(&ctx),
        Some(reason_class::TIER1_PUBLIC_IP_EGRESS)
    );
    let msg = message_for(&ctx, GUEST_GQL_NETWORKERROR);
    assert!(!crate::runtime::is_transient_error_text(&msg), "{msg}");
    // The sibling arm, asserted through the shared mapper rather than through
    // a network call.
    assert_eq!(
        reason_class::tier1_egress_class("tier1-llm-egress"),
        reason_class::TIER1_LLM_EGRESS
    );
}

/// A Tier-1 actor is also blocked from introspecting a third-party schema.
/// Its `policy` is an open two-member family; the class is the closed-set
/// collapse, so `reason_class::ALL` stays closed.
#[tokio::test]
async fn a_blocked_graphql_introspection_gets_its_own_class() {
    let mut ctx = ctx_full(
        CapabilityWorld::Http,
        vec!["*".to_string()],
        vec![],
        LlmTier::Tier1,
    );
    let mut req = gql("https://ex.test/g");
    req.query = "{ __schema { types { name } } }".to_string();
    let out = <TalosContext as wit_graphql::Host>::execute(&mut ctx, req).await;
    assert!(matches!(out, Err(wit_graphql::Error::Networkerror)));
    assert_eq!(
        latched_class(&ctx),
        Some(reason_class::GRAPHQL_INTROSPECTION)
    );
}

/// The `queryerror` half. `write_ceiling_refuses` is the one site returning
/// that discriminant, and it needed a marker for a reason the site count
/// hides: `queryerror` contains `query`, so `talos_retry_intelligence`
/// reported a read-only actor's refusal as a DATABASE error. Non-transient
/// either way, so this is a remediation fix.
///
/// The gate is inert unless `TALOS_WRITE_CEILING_ENFORCED=1`, so this asserts
/// the PAIRING rather than driving the gate: a `write-ceiling` class raised at
/// the `queryerror` site must never be stamped onto a `networkerror`.
#[test]
fn the_write_ceiling_class_is_paired_with_queryerror_not_networkerror() {
    let ctx = ctx_with(CapabilityWorld::Http, vec!["*".to_string()]);
    ctx.record_http_denial(reason_class::WRITE_CEILING, reason_class::WIT_QUERYERROR);
    assert!(message_for(&ctx, GUEST_GQL_QUERYERROR).contains("[reason_class=write-ceiling]"));
    assert_eq!(
        message_for(&ctx, GUEST_GQL_NETWORKERROR),
        GUEST_GQL_NETWORKERROR,
        "a queryerror-paired class must not explain a networkerror"
    );
}

// ---------------------------------------------------------------------------
// graphql — the design property
// ---------------------------------------------------------------------------

/// **THE SAFETY PROPERTY.** A swallowed denial must not suppress the retry of
/// a later GENUINE transport failure.
///
/// On `graphql` the pairing cannot do this job: the denial and the transport
/// failure return the SAME discriminant, so a `Reason` paired with
/// `networkerror` is licensed to explain either. The bound is that the
/// transport site LATCHES, unconditionally, immediately before returning —
/// overwriting whatever a swallowed earlier call left behind.
///
/// Driven through production code end to end. The denial is a real
/// `execute` call; the transport latch is the production
/// `record_graphql_transport_outcome` fed a REAL `reqwest::Error` (its inner
/// `Kind` is private, so no test can forge one) obtained hermetically from a
/// closed loopback port. The graphql transport path itself cannot be reached
/// from a test — every route to it passes the SSRF gate, which is the point of
/// the gate — so the call this makes is the same call, with the same argument,
/// that the production site makes.
///
/// FAILS if the transport site is changed to not latch: the stale
/// `capability-world` would be stamped and the message would go non-transient.
#[tokio::test]
async fn a_swallowed_graphql_denial_cannot_suppress_a_later_transport_retry() {
    let mut ctx = ctx_with(CapabilityWorld::Minimal, vec!["*".to_string()]);
    // 1. A real denial the guest then swallows.
    let _ = <TalosContext as wit_graphql::Host>::execute(&mut ctx, gql("https://ex.test/g")).await;
    assert_eq!(latched_class(&ctx), Some(reason_class::CAPABILITY_WORLD));
    assert!(
        !crate::runtime::is_transient_error_text(&message_for(&ctx, GUEST_GQL_NETWORKERROR)),
        "premise: while the denial is latched, a networkerror reads non-transient"
    );

    // 2. A genuine transport failure, classified by the production path.
    let err = hermetic_connect_error().await;
    ctx.record_graphql_transport_outcome("allowed.test", &err)
        .await;

    // 3. The stale denial is gone and the retry survives.
    assert_eq!(
        latched_class(&ctx),
        Some(reason_class::CONNECT_REFUSED),
        "the transport site must overwrite the stale deny class"
    );
    let msg = message_for(&ctx, GUEST_GQL_NETWORKERROR);
    assert!(
        crate::runtime::is_transient_error_text(&msg),
        "a genuine transport failure was made NON-transient by a stale denial \
         — this is the 2026-07-23 outage class: {msg}"
    );
    assert!(msg.contains("[reason_class=connect-refused]"), "{msg}");
}

/// A REAL `reqwest::Error` from a connect that cannot succeed. Hermetic:
/// loopback only, no listener, no external network. Same technique as
/// `reason_class::tests::real_reqwest_error_is_classified_and_never_leaks_its_url`.
async fn hermetic_connect_error() -> reqwest::Error {
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        l.local_addr().expect("addr").port()
    };
    reqwest::Client::builder()
        // Explicit per lint check 32 — the connect never succeeds here, but
        // the rule is "no client without a stated redirect posture".
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .expect("client")
        .get(format!("http://127.0.0.1:{port}/g"))
        .send()
        .await
        .expect_err("connect to a closed loopback port must fail")
}

/// The `graphql` deny classes are paired with `networkerror`, the SAME token
/// `host::http` uses — so the bound has to hold ACROSS surfaces too. A
/// swallowed graphql denial must not be stamped onto a later `http::fetch_all`
/// transport failure, which is genuinely transient.
///
/// `fetch_all`'s send path runs inside a moved future with no `self`, so it
/// cannot latch where it fails; the batch decides the latch after the join.
/// Before that, its failures returned an UNLATCHED `networkerror` — invisible
/// while only `host::http` could raise that token, and a live hazard the
/// moment `graphql` shares it.
#[tokio::test]
async fn a_swallowed_graphql_denial_cannot_ride_a_fetch_all_transport_failure() {
    let mut ctx = ctx_with(CapabilityWorld::Http, vec!["allowed.test".to_string()]);
    // A real graphql denial (host not in the allowlist), swallowed.
    let _ =
        <TalosContext as wit_graphql::Host>::execute(&mut ctx, gql("https://other.test/g")).await;
    assert_eq!(latched_class(&ctx), Some(reason_class::ALLOWED_HOSTS));

    // A fetch_all batch whose only entry reaches the dispatch path and fails
    // there (nothing is listening on the loopback port, and the host is named
    // in the allowlist so it passes validation).
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        l.local_addr().expect("addr").port()
    };
    let mut ctx = {
        // Rebuild with `localhost` allowed so validation admits it; the SSRF
        // IP-literal gate only inspects literals, and the resolver check is
        // what a real deployment would apply.
        let mut c = ctx_with(CapabilityWorld::Http, vec!["allowed.test".to_string()]);
        let _ =
            <TalosContext as wit_graphql::Host>::execute(&mut c, gql("https://other.test/g")).await;
        c
    };
    assert_eq!(latched_class(&ctx), Some(reason_class::ALLOWED_HOSTS));
    let out = <TalosContext as wit_http::Host>::fetch_all(
        &mut ctx,
        vec![wit_http::Request {
            method: wit_http::Method::Get,
            url: format!("https://allowed.test:{port}/x"),
            headers: vec![],
            body: vec![],
            timeout_ms: Some(1_000),
        }],
    )
    .await;
    assert!(out[0].is_err(), "premise: the batch entry must fail");

    // Whatever it failed with, the stale graphql denial must not be explaining
    // it. `allowed-hosts` is NON_TRANSIENT, so a stamp here would veto the
    // retry a transport failure is entitled to.
    let msg = message_for(&ctx, GUEST_GQL_NETWORKERROR);
    assert!(
        !msg.contains("[reason_class=allowed-hosts]"),
        "a stale graphql denial rode an http::fetch_all failure: {msg}"
    );
}

// ---------------------------------------------------------------------------
// webhook
// ---------------------------------------------------------------------------

/// Every `webhook` denial gets a class. `sendfailed` matches NO arm in any of
/// the four classifiers, so all of these already read `unknown` /
/// `runtime_error` / `other` — non-transient. The fix is that an operator can
/// now tell an SSRF block from a missing allowlist from a bad URL.
#[tokio::test]
async fn distinct_webhook_policies_latch_distinct_classes() {
    let cases: &[(&str, Vec<String>, &'static str)] = &[
        (
            "https://127.0.0.1/hook",
            vec!["*".into()],
            reason_class::PRIVATE_IP,
        ),
        ("https://ex.test/hook", vec![], reason_class::NO_ALLOWLIST),
        (
            "https://other.test/hook",
            vec!["allowed.test".into()],
            reason_class::ALLOWED_HOSTS,
        ),
        (
            "http://ex.test/hook",
            vec!["*".into()],
            reason_class::INSECURE_SCHEME,
        ),
        ("not a url", vec!["*".into()], reason_class::URL_PARSE),
    ];
    for (url, hosts, expected) in cases {
        let mut ctx = ctx_with(CapabilityWorld::Http, hosts.clone());
        let out = <TalosContext as wit_webhook::Host>::send(&mut ctx, hook(url)).await;
        assert!(
            matches!(out, Err(wit_webhook::Error::Sendfailed)),
            "premise for {url}: still a bare sendfailed"
        );
        assert_eq!(latched_class(&ctx), Some(*expected), "url {url}");
        let msg = message_for(&ctx, GUEST_WEBHOOK_SENDFAILED);
        assert!(msg.contains(&reason_class::marker(expected)), "{msg}");
        // Both directions on transience: it was non-transient and it stays
        // non-transient. This surface must not gain a retry.
        assert!(!crate::runtime::is_transient_error_text(
            GUEST_WEBHOOK_SENDFAILED
        ));
        assert!(!crate::runtime::is_transient_error_text(&msg), "{msg}");
    }
}

/// A `webhook` send is a mutating POST, and it already carries its own
/// `1 + max_retries` loop. NOTHING this surface latches may become transient —
/// a controller-level re-dispatch on top of the internal loop is a
/// double-delivery hazard. That is why the transport site CLEARS rather than
/// latching an honest-but-TRANSIENT `send-failed` / `connect-*` / `dns` class,
/// and why the DNS-rebinding site's resolver-failure branch clears too.
///
/// The property is stated over the classes this surface can actually latch,
/// not over `reason_class::ALL`. Written the broad way first, it failed on
/// `[reason_class=timeout]` — a class the webhook path never raises (it is
/// paired with `WIT_TIMEOUT`, only on `host::http`) but whose TOKEN is itself
/// a transient needle. That is a real caution about token choice, so it is
/// asserted separately below rather than dropped.
#[test]
fn no_class_webhook_latches_can_make_a_message_transient() {
    for class in WEBHOOK_LATCHED_CLASSES {
        assert!(
            reason_class::NON_TRANSIENT.contains(class),
            "webhook latches {class:?}, which is not in NON_TRANSIENT — a \
             mutating POST would earn a controller-level re-dispatch"
        );
        let marked = format!("{GUEST_WEBHOOK_SENDFAILED} {}", reason_class::marker(class));
        assert!(
            !crate::runtime::is_transient_error_text(&marked),
            "[reason_class={class}] made a webhook sendfailed message TRANSIENT"
        );
    }
}

/// Every class `host::webhook` can latch, transcribed from its call sites.
/// A list, not a derivation: the point is to be told when the code and this
/// list disagree, which a derivation could not do.
const WEBHOOK_LATCHED_CLASSES: &[&str] = &[
    reason_class::WRITE_CEILING,
    reason_class::URL_TOO_LONG,
    reason_class::REQUEST_HEADER_CAP,
    reason_class::REQUEST_BODY_CAP,
    reason_class::URL_PARSE,
    reason_class::INSECURE_SCHEME,
    reason_class::NO_ALLOWLIST,
    reason_class::PRIVATE_IP,
    reason_class::ALLOWED_HOSTS,
    reason_class::TIER1_EGRESS,
    reason_class::TIER1_LLM_EGRESS,
    reason_class::TIER1_PUBLIC_IP_EGRESS,
    reason_class::EXECUTION_RATE_LIMIT,
    reason_class::CANCELLED,
    reason_class::SECRET_LOOKUP,
];

/// The caution the broad version of the test above surfaced, kept as its own
/// assertion rather than dropped.
///
/// Some tokens in the closed set are TRANSIENT-BY-TOKEN: appending one to an
/// otherwise non-transient message flips it. Latching such a class on a
/// non-transient discriminant would silently make a deterministic failure
/// retryable, so no site on these three surfaces may raise one.
///
/// The two gates disagree about WHICH tokens those are, and the disagreement
/// is worth stating because getting it wrong is how this assertion failed on
/// its first run:
///
/// * The WORKER gate (`is_transient_error_text`) matches the bare substring
///   `"timeout"`, so `[reason_class=timeout]` alone is enough. It does NOT
///   have a `reason_class=dns` arm — `dns` only reads transient there via the
///   `networkerror` token that would already be in the message.
/// * The CONTROLLER gate (`talos_retry_intelligence`) has explicit
///   `reason_class=dns` / `=tls` / `=connect-*` / `=send-failed` /
///   `=response-stream` arms, so ALL of those are transient-by-token there.
///
/// Both lists are covered below; the controller-side half is asserted by
/// membership (this crate deliberately does not depend on the retry crate),
/// with its twin living in `talos_retry_intelligence`'s own tests.
#[test]
fn the_transient_by_token_classes_are_never_latched_on_these_surfaces() {
    // Worker-gate: proven by driving the real gate.
    let marked = format!(
        "{GUEST_WEBHOOK_SENDFAILED} {}",
        reason_class::marker(reason_class::TIMEOUT)
    );
    assert!(
        crate::runtime::is_transient_error_text(&marked),
        "premise: the bare token `timeout` really does flip the worker gate"
    );

    // The full transient-by-token set across BOTH gates. Latching any of these
    // on `sendfailed` / `forbidden-host` / `invalid-url` / `connection-failed`
    // / `rate-limited` would newly grant a retry — on `webhook`, to a mutating
    // POST.
    const TRANSIENT_BY_TOKEN: &[&str] = &[
        reason_class::TIMEOUT,
        reason_class::DNS,
        reason_class::TLS,
        reason_class::CONNECT_REFUSED,
        reason_class::CONNECT_FAILED,
        reason_class::SEND_FAILED,
        reason_class::RESPONSE_STREAM,
    ];
    for class in TRANSIENT_BY_TOKEN {
        assert!(
            !reason_class::NON_TRANSIENT.contains(class),
            "premise: {class:?} is meant to be a transient class"
        );
        assert!(
            !WEBHOOK_LATCHED_CLASSES.contains(class),
            "webhook must never latch the transient token {class:?}"
        );
        assert!(
            !STREAM_LATCHED_CLASSES.contains(class),
            "http_stream must never latch the transient token {class:?}"
        );
    }
}

/// Every class `host::http_stream` can latch, transcribed from its call sites.
/// Companion to [`WEBHOOK_LATCHED_CLASSES`]; a list rather than a derivation
/// so a drift between code and list is what fails.
const STREAM_LATCHED_CLASSES: &[&str] = &[
    reason_class::CAPABILITY_WORLD,
    reason_class::CANCELLED,
    reason_class::URL_TOO_LONG,
    reason_class::SSE_STREAM_CAP,
    reason_class::URL_PARSE,
    reason_class::INSECURE_SCHEME,
    reason_class::NO_ALLOWLIST,
    reason_class::PRIVATE_IP,
    reason_class::ALLOWED_HOSTS,
    reason_class::WRITE_CEILING_STRICT_EGRESS,
    reason_class::TIER1_EGRESS,
    reason_class::TIER1_LLM_EGRESS,
    reason_class::TIER1_PUBLIC_IP_EGRESS,
    reason_class::PER_HOST_RATE_LIMIT,
    reason_class::REQUEST_HEADER_CAP,
    reason_class::SECRET_LOOKUP,
];

/// Every class `http_stream` latches is deterministic, so every one must be in
/// [`reason_class::NON_TRANSIENT`]. The surface has no transport-failure
/// return at all — a `connect` transport failure happens in a spawned task —
/// so there is nothing here a retry could ever help.
#[test]
fn every_class_http_stream_latches_is_non_transient() {
    for class in STREAM_LATCHED_CLASSES {
        assert!(reason_class::ALL.contains(class), "{class:?} not in ALL");
        assert!(
            reason_class::NON_TRANSIENT.contains(class),
            "http_stream latches {class:?}, which is not in NON_TRANSIENT"
        );
        for shape in [
            GUEST_STREAM_FORBIDDEN,
            GUEST_STREAM_INVALID_URL,
            GUEST_STREAM_CONNECTION_FAILED,
            GUEST_STREAM_RATE_LIMITED,
        ] {
            let marked = format!("{shape} {}", reason_class::marker(class));
            assert!(
                !crate::runtime::is_transient_error_text(&marked),
                "[reason_class={class}] made {shape} transient"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// http_stream
// ---------------------------------------------------------------------------

/// The hyphen trap, driven end to end. `forbidden-host` is not `forbiddenhost`
/// — it matched the substring `forbidden` instead and was reported as an AUTH
/// failure, sending the operator after a credential that was fine.
#[tokio::test]
async fn a_stream_host_denial_no_longer_reads_as_an_auth_failure() {
    let mut ctx = ctx_with(CapabilityWorld::Http, vec!["allowed.test".to_string()]);
    let out = <TalosContext as wit_http_stream::Host>::connect(
        &mut ctx,
        "https://other.test/sse".to_string(),
        vec![],
    )
    .await;
    assert!(
        matches!(out, Err(wit_http_stream::Error::ForbiddenHost)),
        "premise: still the hyphenated forbidden-host discriminant"
    );
    assert_eq!(latched_class(&ctx), Some(reason_class::ALLOWED_HOSTS));

    let msg = message_for(&ctx, GUEST_STREAM_FORBIDDEN);
    assert!(msg.contains("[reason_class=allowed-hosts]"), "{msg}");
    // FALSIFICATION: the bare hyphenated token really does miss the
    // `forbiddenhost` arm — if it stopped missing it, this file's premise
    // would be gone.
    assert!(
        !GUEST_STREAM_FORBIDDEN.contains("forbiddenhost"),
        "the hyphenated case name is what makes the existing arms miss"
    );
    assert!(!crate::runtime::is_transient_error_text(&msg));
}

/// Each of `http_stream`'s four discriminants carries its own classes, and a
/// class raised at one may never explain another. Unlike `graphql`, the
/// pairing here is NOT vacuous — every `ForbiddenHost` and `InvalidUrl` site
/// is a denial and no transport failure returns either — so this is the
/// property doing the work on this surface.
#[tokio::test]
async fn stream_classes_only_explain_their_own_hyphenated_discriminant() {
    // A `forbidden-host` class …
    let mut ctx = ctx_with(CapabilityWorld::Minimal, vec!["*".to_string()]);
    let _ = <TalosContext as wit_http_stream::Host>::connect(
        &mut ctx,
        "https://ex.test/sse".to_string(),
        vec![],
    )
    .await;
    assert_eq!(latched_class(&ctx), Some(reason_class::CAPABILITY_WORLD));
    assert!(message_for(&ctx, GUEST_STREAM_FORBIDDEN).contains("[reason_class="));
    for unrelated in [
        GUEST_STREAM_INVALID_URL,
        GUEST_STREAM_CONNECTION_FAILED,
        GUEST_STREAM_RATE_LIMITED,
        GUEST_GQL_NETWORKERROR,
        GUEST_WEBHOOK_SENDFAILED,
        "Component returned error: 401 Unauthorized",
    ] {
        assert_eq!(
            message_for(&ctx, unrelated),
            unrelated,
            "a stale forbidden-host class was attached to: {unrelated}"
        );
    }

    // … and an `invalid-url` class, which must not explain a forbidden-host.
    let mut ctx = ctx_with(CapabilityWorld::Http, vec!["*".to_string()]);
    let _ = <TalosContext as wit_http_stream::Host>::connect(
        &mut ctx,
        "http://ex.test/sse".to_string(),
        vec![],
    )
    .await;
    assert_eq!(latched_class(&ctx), Some(reason_class::INSECURE_SCHEME));
    assert_eq!(
        message_for(&ctx, GUEST_STREAM_FORBIDDEN),
        GUEST_STREAM_FORBIDDEN
    );
    assert!(message_for(&ctx, GUEST_STREAM_INVALID_URL).contains("insecure-scheme"));
}

/// The hyphenated `invalid-url` spelling is DISJOINT from `wit_http`'s
/// `invalidurl` — neither contains the other — so the two surfaces' classes
/// can never cross-explain. Stated as a test because it is a property of the
/// literal strings, and the whole pairing mechanism rests on it.
#[test]
fn the_hyphenated_and_unhyphenated_wit_tokens_are_disjoint() {
    assert!(!reason_class::WIT_INVALID_URL_HYPHENATED.contains(reason_class::WIT_INVALIDURL));
    assert!(!reason_class::WIT_INVALIDURL.contains(reason_class::WIT_INVALID_URL_HYPHENATED));
    assert!(!reason_class::WIT_FORBIDDEN_HOST_HYPHENATED.contains(reason_class::WIT_FORBIDDENHOST));
    assert!(!reason_class::WIT_FORBIDDENHOST.contains(reason_class::WIT_FORBIDDEN_HOST_HYPHENATED));
    // And `sendfailed` is not `send-failed`, so the webhook discriminant can
    // never be satisfied by the transport CLASS of the same name.
    assert!(!reason_class::WIT_SENDFAILED.contains(reason_class::SEND_FAILED));
    assert!(!reason_class::SEND_FAILED.contains(reason_class::WIT_SENDFAILED));
}

/// The SSE stream-count cap and the per-host connect cap are different
/// refusals with opposite remediations (close your streams vs. raise the
/// budget), and both ride `rate-limited`.
#[tokio::test]
async fn the_two_stream_rate_limits_are_told_apart() {
    let mut ctx = ctx_with(CapabilityWorld::Http, vec!["allowed.test".to_string()]);
    // Fill the concurrency cap with dummy receivers so the guard trips before
    // any network work.
    {
        let mut streams = ctx.streams.sse.lock().unwrap();
        for i in 0..super::MAX_SSE_STREAMS_PER_EXECUTION {
            let (_tx, rx) = tokio::sync::mpsc::channel(1);
            streams.insert(format!("dummy-{i}"), rx);
        }
    }
    let out = <TalosContext as wit_http_stream::Host>::connect(
        &mut ctx,
        "https://allowed.test/sse".to_string(),
        vec![],
    )
    .await;
    assert!(matches!(out, Err(wit_http_stream::Error::RateLimited)));
    assert_eq!(latched_class(&ctx), Some(reason_class::SSE_STREAM_CAP));
    assert!(message_for(&ctx, GUEST_STREAM_RATE_LIMITED).contains("[reason_class=sse-stream-cap]"));
}

/// A cancelled `connect` returns `ConnectionFailed`, which reads as neither a
/// denial nor a transport failure to any classifier. It is deterministic — the
/// re-dispatched attempt would be cancelled again — so it carries `cancelled`.
#[tokio::test]
async fn a_cancelled_stream_connect_is_marked_cancelled() {
    let mut ctx = ctx_with(CapabilityWorld::Http, vec!["*".to_string()]);
    ctx.cancelled
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let out = <TalosContext as wit_http_stream::Host>::connect(
        &mut ctx,
        "https://ex.test/sse".to_string(),
        vec![],
    )
    .await;
    assert!(matches!(out, Err(wit_http_stream::Error::ConnectionFailed)));
    assert_eq!(latched_class(&ctx), Some(reason_class::CANCELLED));
    let msg = message_for(&ctx, GUEST_STREAM_CONNECTION_FAILED);
    assert!(msg.contains("[reason_class=cancelled]"), "{msg}");
    assert!(!crate::runtime::is_transient_error_text(&msg));
}

// ---------------------------------------------------------------------------
// The cross-surface safety property
// ---------------------------------------------------------------------------

/// NO MESSAGE MAY MOVE FROM TRANSIENT TO NON-TRANSIENT on any shape these
/// three surfaces can produce.
///
/// This is the direction the brief names as non-negotiable and it is the
/// OPPOSITE of the one `host::http` had to worry about: there, the hazard was
/// a deterministic failure being retried; here, a badly-placed marker could
/// veto the retry of a real transport failure.
///
/// Asserted for every token in the CLOSED set against every discriminant the
/// three surfaces can render — including pairings the producer does not emit,
/// so the property survives a future site that pairs differently.
#[test]
fn no_marker_can_veto_a_transient_reading_on_these_surfaces() {
    let discriminants = [
        // graphql
        "networkerror",
        "parseerror",
        "queryerror",
        "invalidvariables",
        // webhook
        "sendfailed",
        "invalidurl",
        "timeout",
        // http-stream (hyphenated)
        "forbidden-host",
        "invalid-url",
        "connection-failed",
        "rate-limited",
    ];
    for wit in discriminants {
        let bare = format!(r#"Component returned error: x: Error {{ name: "{wit}" }}"#);
        let before = crate::runtime::is_transient_error_text(&bare);
        if !before {
            continue;
        }
        for class in reason_class::ALL {
            // A transient shape may only keep a transient reading, or be
            // explained by a class that is itself transient.
            let marked = format!("{bare} {}", reason_class::marker(class));
            let after = crate::runtime::is_transient_error_text(&marked);
            assert_eq!(
                after,
                !reason_class::NON_TRANSIENT.contains(class),
                "[reason_class={class}] on a {wit} message: a transient shape may \
                 only lose its retry to a class that IS deterministic, and the \
                 producer must never pair those two"
            );
        }
    }
}

/// The pre-change reading of every shape these surfaces produce TODAY, pinned
/// as literals rather than derived. A behavioural test written against the new
/// code cannot catch a change that moved producer and consumer together —
/// the same reason this workspace carries wire-format snapshots.
///
/// Every entry here is the UNMARKED shape, i.e. what an operator sees when the
/// latch says nothing. All of them must be byte-for-byte unaffected by this
/// change.
#[test]
fn unmarked_shapes_keep_their_worker_side_transience() {
    let cases: &[(&str, bool)] = &[
        (GUEST_GQL_NETWORKERROR, true),
        (GUEST_GQL_QUERYERROR, false),
        (GUEST_WEBHOOK_SENDFAILED, false),
        (GUEST_STREAM_FORBIDDEN, false),
        (GUEST_STREAM_INVALID_URL, false),
        (GUEST_STREAM_CONNECTION_FAILED, false),
        (GUEST_STREAM_RATE_LIMITED, false),
        (
            r#"Component returned error: hook: Error { code: 2, name: "timeout", message: "" }"#,
            true,
        ),
        (
            r#"Component returned error: gql: Error { code: 1, name: "parseerror", message: "" }"#,
            false,
        ),
        // The Display form the bindings also render — a guest using `{}`
        // rather than `{:?}` produces this, and it must read the same.
        ("Component returned error: forbidden-host (error 1)", false),
        ("Component returned error: sendfailed (error 1)", false),
        ("Component returned error: networkerror (error 0)", true),
    ];
    for (msg, transient) in cases {
        assert_eq!(
            crate::runtime::is_transient_error_text(msg),
            *transient,
            "shape: {msg}"
        );
    }
}
