//! An EMPTY `allowed_methods` denies at EVERY egress gate (2026-09-24).
//!
//! Five gates read the module's method grant — `http::fetch`, `http::fetch_all`,
//! `graphql::execute`, `webhook::send` and `http_stream::connect` — and until
//! this package each spelled the test itself as
//! `!allowed.is_empty() && !allowed.contains(m)`, so an empty grant admitted
//! every verb. `allowed_hosts` and `allowed_secrets` have always DENIED on
//! empty, which made `allowed_methods` the one member of the three-part module
//! grant where declaring nothing granted everything.
//!
//! These drive the PRODUCTION host functions, not the predicate: the predicate
//! has its own tests in `talos-workflow-job-protocol`, and a guard at the
//! primitive cannot see a call site (checks 74b/79b — the lesson EE's M8, EG's
//! G6 and EC's Q5 each paid for). Every case carries a CONTROL declaring the
//! verb, so a refusal cannot pass because the gate refuses unconditionally.
//!
//! Each gate is reached only AFTER its host gate, so every fixture declares a
//! host: the host gates run first (`http.rs` 269/298 before 625), which is also
//! why the one PRODUCTION context built with an empty method list —
//! `runtime.rs`'s `run_sandbox`/`test_module` path — is unaffected by the flip:
//! its `allowed_hosts` is `vec![]` too, so it never reaches the method gate.

use std::collections::HashMap;

use talos_workflow_job_protocol::LlmTier;

use super::{wit_graphql, wit_http, wit_http_stream, wit_webhook, TalosContext};
use crate::reason_class;
use crate::wit_inspector::CapabilityWorld;

const HOST: &str = "1.0.0.9";

fn ctx(methods: &[&str]) -> TalosContext {
    TalosContext::new(
        CapabilityWorld::Http,
        vec![HOST.to_string()],
        methods.iter().map(|s| (*s).to_string()).collect(),
        128,
        HashMap::new(),
        None,
        None,
        false,
        None,
        std::sync::Arc::new(crate::expose_fallback::ExposeFallback::new()),
        LlmTier::Tier2,
        None,
    )
    .expect("test context")
}

fn latched(c: &TalosContext) -> Option<&'static str> {
    c.network_reason_handle().lock().unwrap().map(|r| r.class)
}

fn get_req() -> wit_http::Request {
    wit_http::Request {
        url: format!("https://{HOST}/r"),
        method: wit_http::Method::Get,
        headers: vec![],
        body: vec![],
        timeout_ms: Some(1),
    }
}

#[tokio::test]
async fn fetch_refuses_an_undeclared_method_list() {
    let mut c = ctx(&[]);
    let r = <TalosContext as wit_http::Host>::fetch(&mut c, get_req()).await;
    assert!(matches!(r, Err(wit_http::Error::Forbiddenhost)), "{r:?}");
    assert_eq!(latched(&c), Some(reason_class::METHOD_ALLOWLIST));
}

#[tokio::test]
async fn fetch_admits_the_same_call_once_get_is_declared() {
    // CONTROL. Declaring GET must carry the call PAST the method gate — if it
    // did not, the assertion above would pass for the wrong reason. The call
    // then fails on the network (no listener at 1.0.0.9), which is a different
    // class, so the method gate is provably not what refused it.
    let mut c = ctx(&["GET"]);
    let r = <TalosContext as wit_http::Host>::fetch(&mut c, get_req()).await;
    assert_ne!(
        latched(&c),
        Some(reason_class::METHOD_ALLOWLIST),
        "declared GET must not be refused by the method gate: {r:?}"
    );
}

#[tokio::test]
async fn fetch_all_refuses_an_undeclared_method_list() {
    let mut c = ctx(&[]);
    let out = <TalosContext as wit_http::Host>::fetch_all(&mut c, vec![get_req()]).await;
    assert_eq!(out.len(), 1);
    assert!(
        matches!(out[0], Err(wit_http::Error::Forbiddenhost)),
        "{out:?}"
    );
    assert_eq!(latched(&c), Some(reason_class::METHOD_ALLOWLIST));
}

#[tokio::test]
async fn fetch_all_admits_the_same_batch_once_get_is_declared() {
    let mut c = ctx(&["GET"]);
    let _ = <TalosContext as wit_http::Host>::fetch_all(&mut c, vec![get_req()]).await;
    assert_ne!(latched(&c), Some(reason_class::METHOD_ALLOWLIST));
}

#[tokio::test]
async fn graphql_refuses_an_undeclared_method_list() {
    // GraphQL is always POST, so an undeclared module cannot execute one.
    let mut c = ctx(&[]);
    let req = wit_graphql::Request {
        url: format!("https://{HOST}/graphql"),
        query: "{ ok }".to_string(),
        variables: None,
        headers: None,
        timeout_ms: Some(1),
    };
    let r = <TalosContext as wit_graphql::Host>::execute(&mut c, req).await;
    assert!(r.is_err(), "{r:?}");
    assert_eq!(latched(&c), Some(reason_class::METHOD_ALLOWLIST));
}

#[tokio::test]
async fn graphql_admits_the_same_call_once_post_is_declared() {
    let mut c = ctx(&["POST"]);
    let req = wit_graphql::Request {
        url: format!("https://{HOST}/graphql"),
        query: "{ ok }".to_string(),
        variables: None,
        headers: None,
        timeout_ms: Some(1),
    };
    let _ = <TalosContext as wit_graphql::Host>::execute(&mut c, req).await;
    assert_ne!(latched(&c), Some(reason_class::METHOD_ALLOWLIST));
}

#[tokio::test]
async fn sse_connect_refuses_an_undeclared_method_list() {
    // The gate this package ADDED. Without it, "an undeclared module cannot
    // make HTTP calls" would have been false: the other four would deny and
    // the SSE read channel would stay open.
    let mut c = ctx(&[]);
    let r = <TalosContext as wit_http_stream::Host>::connect(
        &mut c,
        format!("https://{HOST}/sse"),
        vec![],
    )
    .await;
    assert!(r.is_err(), "{r:?}");
    assert_eq!(latched(&c), Some(reason_class::METHOD_ALLOWLIST));
}

#[tokio::test]
async fn sse_connect_admits_the_same_url_once_get_is_declared() {
    let mut c = ctx(&["GET"]);
    let _ = <TalosContext as wit_http_stream::Host>::connect(
        &mut c,
        format!("https://{HOST}/sse"),
        vec![],
    )
    .await;
    assert_ne!(latched(&c), Some(reason_class::METHOD_ALLOWLIST));
}

#[tokio::test]
async fn webhook_refuses_an_undeclared_method_list() {
    let mut c = ctx(&[]);
    c.dry_run = true;
    let req = wit_webhook::WebhookRequest {
        url: format!("https://{HOST}/hook"),
        headers: vec![],
        body: "{}".to_string(),
        max_retries: Some(0),
        retry_delay_ms: Some(1),
    };
    let r = <TalosContext as wit_webhook::Host>::send(&mut c, req).await;
    assert!(matches!(r, Err(wit_webhook::Error::Sendfailed)), "{r:?}");
    assert_eq!(latched(&c), Some(reason_class::METHOD_ALLOWLIST));
}

/// TEXTUAL pin, stated as such: the five gates share ONE predicate.
///
/// The needles are ASSEMBLED so this file cannot vouch for itself — EI's pin
/// reported three call sites for two gates before its needles were built from
/// parts, and this is the same trap one package later.
#[test]
fn every_egress_gate_reads_the_one_home() {
    let files = [
        ("http.rs", include_str!("http.rs"), 2usize),
        ("graphql.rs", include_str!("graphql.rs"), 1),
        ("webhook.rs", include_str!("webhook.rs"), 1),
        ("http_stream.rs", include_str!("http_stream.rs"), 1),
    ];
    let call = format!("{}::method_permitted(", "talos_workflow_job_protocol");
    // The shape every gate used before this package. It must be gone: a file
    // that still spells the test itself is a fifth opinion on what a grant
    // means, which is the defect rather than a style difference.
    let old = format!("allowed_methods{}", ".is_empty()");
    for (name, src, want) in files {
        assert_eq!(
            src.matches(&call).count(),
            want,
            "{name} must call the shared predicate exactly {want} time(s)"
        );
        assert!(
            !src.contains(&old),
            "{name} still hand-rolls the method test"
        );
    }
}
