//! The `invalidurl` / `forbiddenhost` half of the reason-class contract,
//! driven through the REAL `wit_http::Host::fetch` on a real `TalosContext`.
//!
//! ## What was broken
//!
//! `wit/talos.wit` declares `enum error { invalidurl, timeout, networkerror,
//! forbiddenhost }` — payload-less, so the guest can only render
//! `Error { code: N, name: "…", message: "" }`. [`crate::reason_class`] solved
//! that for `networkerror` and for `networkerror` only: the marker was gated
//! on the guest error containing that literal token, so no class raised at an
//! `invalidurl` or `forbiddenhost` site could ever be stamped.
//!
//! Both of the other discriminants collapse just as badly.
//! `Error::Invalidurl` is returned for THREE unrelated causes — a
//! hostile-guest URL byte cap, a genuine author typo, and the plaintext-scheme
//! SECURITY refusal that exists to stop a `vault://` header going out in the
//! clear — and `invalidurl` matched NO arm in either transient classifier, so
//! all three were filed under `unknown`. Observed live: workflow execution
//! `43b78079-d0a0-4aff-83f1-e3e80dc7195a` reported
//! `Component returned error: HTTP request failed: Error { code: 0, name:
//! "invalidurl", message: "" }` for a policy denial. A security control fired
//! and it read as a typo.
//!
//! ## What these tests pin
//!
//! Every assertion drives production code — `fetch` itself, then the real
//! [`crate::runtime::last_network_reason_suffix`] and
//! [`crate::runtime::is_transient_error_text`]. Nothing here re-implements the
//! classification it is checking.
//!
//! Both DIRECTIONS are taken throughout, for the same reason the sibling
//! `cancellation_tests` does it: a one-directional test passes against the
//! broken tree, because the broken tree also classifies — it just classifies
//! everything the same.

use std::collections::HashMap;
use std::sync::Arc;

use talos_workflow_job_protocol::LlmTier;

use super::{wit_http, TalosContext};
use crate::reason_class;
use crate::wit_inspector::CapabilityWorld;

/// The literal text the generated bindings render for each discriminant —
/// the `name` field, which is what actually lands in
/// `workflow_executions.error_message`. Quoted from
/// `module-templates/http-request/src/bindings.rs::Error::name`.
const GUEST_INVALIDURL: &str = r#"Component returned error: HTTP request failed: Error { code: 0, name: "invalidurl", message: "" }"#;
const GUEST_FORBIDDENHOST: &str =
    r#"Component returned error: fetch: Error { code: 3, name: "forbiddenhost", message: "" }"#;
const GUEST_NETWORKERROR: &str =
    r#"Component returned error: fetch: Error { code: 2, name: "networkerror", message: "" }"#;

fn ctx_with(world: CapabilityWorld, allowed_hosts: Vec<String>) -> TalosContext {
    TalosContext::new(
        world,
        allowed_hosts,
        vec![],
        128,
        HashMap::new(),
        None,
        None,
        false,
        None,
        Arc::new(crate::expose_fallback::ExposeFallback::new()),
        LlmTier::Tier2,
        None,
    )
    .expect("context builds")
}

fn get(url: &str) -> wit_http::Request {
    wit_http::Request {
        method: wit_http::Method::Get,
        url: url.to_string(),
        headers: vec![],
        body: vec![],
        timeout_ms: None,
    }
}

/// Render the node-failure message the runtime would build for this guest
/// error, using the production suffix function and the production latch.
fn message_for(ctx: &TalosContext, guest_error: &str) -> String {
    let latch = ctx.network_reason_handle();
    format!(
        "{guest_error}{}",
        crate::runtime::last_network_reason_suffix(&latch, guest_error)
    )
}

// ---------------------------------------------------------------------------
// The reproduced defect
// ---------------------------------------------------------------------------

/// THE HEADLINE CASE, end to end through `fetch`.
///
/// A plaintext `http://` target is refused because the SSRF gate protects the
/// destination but not the data in flight — a `vault://`-substituted
/// `Authorization` header would leave the worker in the clear. The guest is
/// told `invalidurl`, i.e. that it made a typo.
#[tokio::test]
async fn an_insecure_scheme_refusal_no_longer_reads_as_a_typo() {
    let mut ctx = ctx_with(CapabilityWorld::Http, vec!["example.com".to_string()]);
    assert!(
        ctx.network_reason_handle().lock().unwrap().is_none(),
        "precondition: nothing latched yet"
    );

    let out = <TalosContext as wit_http::Host>::fetch(&mut ctx, get("http://example.com/x")).await;
    assert!(
        matches!(out, Err(wit_http::Error::Invalidurl)),
        "premise: the scheme gate still reports this as invalidurl — if this \
         changes the WIT enum widened and this whole mechanism can retire"
    );

    assert_eq!(
        *ctx.network_reason_handle().lock().unwrap(),
        Some(reason_class::Reason::invalid_url(
            reason_class::INSECURE_SCHEME
        )),
        "the scheme refusal must latch its class PAIRED with invalidurl"
    );

    let msg = message_for(&ctx, GUEST_INVALIDURL);
    assert!(
        msg.contains("[reason_class=insecure-scheme]"),
        "the operator message still cannot distinguish a security refusal \
         from a typo: {msg}"
    );
    // FALSIFICATION DIRECTION: without the marker the message says nothing.
    // If this passed too, the marker would not be load-bearing.
    assert!(!GUEST_INVALIDURL.contains("insecure-scheme"));
    assert!(!crate::runtime::is_transient_error_text(&msg));
}

/// The other two `invalidurl` causes latch DIFFERENT classes. Same
/// discriminant, three answers — which is the entire point, and is what a
/// single "invalidurl means bad URL" mapping would have thrown away.
#[tokio::test]
async fn the_three_invalidurl_causes_are_told_apart() {
    // (a) the hostile-guest byte cap.
    let mut ctx = ctx_with(CapabilityWorld::Http, vec!["*".to_string()]);
    let long = format!(
        "https://example.com/{}",
        "a".repeat(super::MAX_OUTBOUND_URL_BYTES)
    );
    let out = <TalosContext as wit_http::Host>::fetch(&mut ctx, get(&long)).await;
    assert!(matches!(out, Err(wit_http::Error::Invalidurl)));
    assert_eq!(
        ctx.network_reason_handle().lock().unwrap().map(|r| r.class),
        Some(reason_class::URL_TOO_LONG)
    );

    // (b) a genuine author typo.
    let mut ctx = ctx_with(CapabilityWorld::Http, vec!["*".to_string()]);
    let out = <TalosContext as wit_http::Host>::fetch(&mut ctx, get("not a url at all")).await;
    assert!(matches!(out, Err(wit_http::Error::Invalidurl)));
    assert_eq!(
        ctx.network_reason_handle().lock().unwrap().map(|r| r.class),
        Some(reason_class::URL_PARSE)
    );

    // (c) the security refusal — covered end to end above; asserted here so
    //     the three are visibly DIFFERENT rather than merely each non-empty.
    let mut ctx = ctx_with(CapabilityWorld::Http, vec!["*".to_string()]);
    let _ = <TalosContext as wit_http::Host>::fetch(&mut ctx, get("http://example.com/x")).await;
    assert_eq!(
        ctx.network_reason_handle().lock().unwrap().map(|r| r.class),
        Some(reason_class::INSECURE_SCHEME)
    );
}

// ---------------------------------------------------------------------------
// forbiddenhost: one discriminant, many policies
// ---------------------------------------------------------------------------

/// `forbiddenhost` was already NON-transient, so this is not a retry fix — it
/// is a REMEDIATION fix. `talos_failure_analysis_service` answers every
/// `forbiddenhost` with "add the host to allowed_hosts", which is the wrong
/// instruction for four of the five denials below.
#[tokio::test]
async fn distinct_forbiddenhost_policies_latch_distinct_classes() {
    // The module has no HTTP capability at all.
    let mut ctx = ctx_with(CapabilityWorld::Minimal, vec!["*".to_string()]);
    let out = <TalosContext as wit_http::Host>::fetch(&mut ctx, get("https://example.com/x")).await;
    assert!(matches!(out, Err(wit_http::Error::Forbiddenhost)));
    assert_eq!(
        *ctx.network_reason_handle().lock().unwrap(),
        Some(reason_class::Reason::forbidden_host(
            reason_class::CAPABILITY_WORLD
        ))
    );

    // An EMPTY allowlist denies everything — a distinct fix (declare hosts)
    // from "this host is missing from your list".
    let mut ctx = ctx_with(CapabilityWorld::Http, vec![]);
    let out = <TalosContext as wit_http::Host>::fetch(&mut ctx, get("https://example.com/x")).await;
    assert!(matches!(out, Err(wit_http::Error::Forbiddenhost)));
    assert_eq!(
        ctx.network_reason_handle().lock().unwrap().map(|r| r.class),
        Some(reason_class::NO_ALLOWLIST)
    );

    // A host that simply is not matched.
    let mut ctx = ctx_with(CapabilityWorld::Http, vec!["allowed.example".to_string()]);
    let out =
        <TalosContext as wit_http::Host>::fetch(&mut ctx, get("https://other.example/x")).await;
    assert!(matches!(out, Err(wit_http::Error::Forbiddenhost)));
    assert_eq!(
        ctx.network_reason_handle().lock().unwrap().map(|r| r.class),
        Some(reason_class::ALLOWED_HOSTS)
    );

    // SSRF: an IP literal in a denied range, admitted by the wildcard and
    // stopped by the classifier. The class is the family PREFIX, never the
    // per-address variant — `reason_class::ALL` has to stay closed.
    let mut ctx = ctx_with(CapabilityWorld::Http, vec!["*".to_string()]);
    let out = <TalosContext as wit_http::Host>::fetch(&mut ctx, get("https://127.0.0.1/x")).await;
    assert!(matches!(out, Err(wit_http::Error::Forbiddenhost)));
    assert_eq!(
        ctx.network_reason_handle().lock().unwrap().map(|r| r.class),
        Some(reason_class::PRIVATE_IP)
    );
}

/// `fetch_all` denies PER ENTRY, so its latch must be written from the
/// validation loop and not only from the batch-level guards. Sibling parity
/// with the single-request path; without it a batch-only module gets no marker
/// at all.
#[tokio::test]
async fn fetch_all_latches_a_per_entry_denial() {
    let mut ctx = ctx_with(CapabilityWorld::Http, vec!["allowed.example".to_string()]);
    let out =
        <TalosContext as wit_http::Host>::fetch_all(&mut ctx, vec![get("https://other.example/x")])
            .await;
    assert!(matches!(out[0], Err(wit_http::Error::Forbiddenhost)));
    assert_eq!(
        *ctx.network_reason_handle().lock().unwrap(),
        Some(reason_class::Reason::forbidden_host(
            reason_class::ALLOWED_HOSTS
        ))
    );
    assert!(message_for(&ctx, GUEST_FORBIDDENHOST).contains("[reason_class=allowed-hosts]"));
}

// ---------------------------------------------------------------------------
// The anti-mis-attribution property, at its new boundary
// ---------------------------------------------------------------------------

/// THE REASON THE PAIRING EXISTS.
///
/// The latch is set on failure and cleared only on `fetch` SUCCESS, so a
/// module that swallows a denial and then fails for an unrelated reason still
/// holds a stale class. The original gate bounded that by requiring the guest
/// error to say `networkerror`.
///
/// The two obvious ways to extend it are both wrong, and this test fails for
/// each of them:
///
/// * DROP condition 2 → the stale class lands on the `401`, which
///   `classify_error` reads as `network_transient` (that bucket is checked
///   before `auth_failure`), and a permanent auth error retries forever.
/// * WIDEN it to "any WIT token" → a stale `insecure-scheme` lands on a
///   `networkerror`, and a stale transport class lands on a `forbiddenhost`.
///   The second is the dangerous direction: transport classes are TRANSIENT,
///   capability denials are not.
#[tokio::test]
async fn a_latched_class_is_stamped_only_on_the_discriminant_it_explains() {
    let mut ctx = ctx_with(CapabilityWorld::Http, vec!["allowed.example".to_string()]);
    // Latch a real `forbiddenhost` class through production code.
    let _ = <TalosContext as wit_http::Host>::fetch(&mut ctx, get("https://other.example/x")).await;

    // Explains its own discriminant …
    assert!(message_for(&ctx, GUEST_FORBIDDENHOST).contains("[reason_class="));
    // … and NOTHING else.
    for unrelated in [
        GUEST_NETWORKERROR,
        GUEST_INVALIDURL,
        "Component returned error: 401 Unauthorized",
        "Component returned error: 404 Not Found",
        "Pipeline step 'x' returned error: business rule violated",
    ] {
        assert_eq!(
            message_for(&ctx, unrelated),
            unrelated,
            "a stale forbiddenhost class was attached to: {unrelated}"
        );
    }

    // And the converse, with a class latched at an `invalidurl` site: it must
    // NOT explain a `forbiddenhost`. Same discriminant family, different cause.
    let mut ctx = ctx_with(CapabilityWorld::Http, vec!["*".to_string()]);
    let _ = <TalosContext as wit_http::Host>::fetch(&mut ctx, get("http://example.com/x")).await;
    assert_eq!(message_for(&ctx, GUEST_FORBIDDENHOST), GUEST_FORBIDDENHOST);
    assert!(message_for(&ctx, GUEST_INVALIDURL).contains("insecure-scheme"));
}

/// A SUCCESSFUL `fetch` clears the latch, so a denial early in an execution
/// cannot be attributed to a later, unrelated failure. Pinned on the new
/// classes because the clear is a `record_network_outcome(None)` on the
/// success path — a code path that has no idea which discriminant the latch
/// was paired with, and must not grow one.
#[tokio::test]
async fn a_later_success_clears_a_policy_class() {
    let mut ctx = ctx_with(CapabilityWorld::Http, vec!["allowed.example".to_string()]);
    let _ = <TalosContext as wit_http::Host>::fetch(&mut ctx, get("https://other.example/x")).await;
    assert!(ctx.network_reason_handle().lock().unwrap().is_some());
    // No network in tests, so clear through the production setter the success
    // path uses rather than by making a real request.
    ctx.record_network_outcome(None);
    assert_eq!(message_for(&ctx, GUEST_FORBIDDENHOST), GUEST_FORBIDDENHOST);
}

// ---------------------------------------------------------------------------
// The safety property
// ---------------------------------------------------------------------------

/// NO MESSAGE MAY MOVE FROM NON-TRANSIENT TO TRANSIENT. That direction burns
/// retry budget on a deterministic failure — the 2026-07-23 outage class.
///
/// Checked against the worker's own gate for every newly minted class on every
/// discriminant it could ride on, including pairings the producer does not
/// currently emit, so the property survives a future site that pairs
/// differently. The controller-side twin is
/// `talos_retry_intelligence::no_new_token_can_make_any_message_transient`.
#[test]
fn no_http_policy_class_can_make_a_message_transient() {
    for class in reason_class::HTTP_POLICY_CLASSES {
        for wit in ["invalidurl", "forbiddenhost", "networkerror", "timeout"] {
            let bare = format!(r#"Component returned error: fetch: Error {{ name: "{wit}" }}"#);
            let marked = format!("{bare} {}", reason_class::marker(class));
            let before = crate::runtime::is_transient_error_text(&bare);
            let after = crate::runtime::is_transient_error_text(&marked);
            assert!(
                !(after && !before),
                "[reason_class={class}] moved a {wit} message from NON-TRANSIENT \
                 to TRANSIENT"
            );
        }
    }
}

/// The pre-change reading of every shape that exists today is unchanged.
/// Literals, not derivations: a behavioural test written against the new code
/// cannot catch a change that moved producer and consumer together — the same
/// reason this workspace carries wire-format snapshots.
#[test]
fn existing_shapes_keep_their_worker_side_transience() {
    let cases: &[(&str, bool)] = &[
        (GUEST_NETWORKERROR, true),
        (GUEST_FORBIDDENHOST, false),
        (GUEST_INVALIDURL, false),
        (
            r#"Component returned error: fetch: Error { code: 1, name: "timeout", message: "" }"#,
            true,
        ),
        (
            r#"Component returned error: fetch: Error { name: "networkerror" } [reason_class=dns]"#,
            true,
        ),
        (
            r#"Component returned error: fetch: Error { name: "networkerror" } [reason_class=circuit-open]"#,
            false,
        ),
        (
            r#"Component returned error: fetch: Error { name: "networkerror" } [reason_class=tier1-egress]"#,
            false,
        ),
        ("Component returned error: 401 Unauthorized", false),
        ("WASM fuel exhausted after 10000000", false),
        ("connection refused", true),
    ];
    for (msg, transient) in cases {
        assert_eq!(
            crate::runtime::is_transient_error_text(msg),
            *transient,
            "shape: {msg}"
        );
    }
}
