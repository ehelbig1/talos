//! A local-egress-only actor that is NOT tier 1 (`tier2` + `egress_scope =
//! local`) must be refused a PUBLIC IP literal on every guest HTTP surface
//! (2026-09-25).
//!
//! Local-only egress is enforced at CONNECT by `SsrfFilteringResolver`, and a
//! resolver is never consulted for an IP literal. The literal deny that covers
//! that hole sat inside `if max_llm_tier == Tier1` at all five call sites, so
//! for this posture `https://203.0.113.10/` was sent. Each test below drives
//! the REAL host function and asserts the refusal happened at the posture gate
//! — the latched class is the local-egress class and the call never reached the
//! network (every assertion here completes without a socket: 203.0.113.0/24 is
//! RFC 5737 TEST-NET-3, never routed, so a regression would surface as a
//! connect failure or timeout rather than as this class).

use std::collections::HashMap;
use std::sync::Arc;

use talos_workflow_job_protocol::{EgressScope, LlmTier};

use super::sibling_egress_reason_tests::{all_verbs, latched_class, PUBLIC_IP_LITERAL};
use super::{wit_graphql, wit_http, wit_http_stream, wit_webhook, TalosContext};
use crate::reason_class;
use crate::wit_inspector::CapabilityWorld;

/// tier 2, public LLM providers permitted, but ALL public egress refused.
fn tier2_local_ctx() -> TalosContext {
    let ctx = TalosContext::new(
        CapabilityWorld::Http,
        vec!["*".to_string()],
        all_verbs(),
        128,
        HashMap::new(),
        None,
        None,
        false,
        None,
        Arc::new(crate::expose_fallback::ExposeFallback::new()),
        LlmTier::Tier2,
        Some(EgressScope::Local),
    )
    .expect("context builds");
    assert!(
        ctx.local_egress_only,
        "premise: tier2 + egress_scope=local is local-egress-only"
    );
    ctx
}

fn get(url: &str) -> wit_http::Request {
    wit_http::Request {
        method: wit_http::Method::Get,
        url: url.to_string(),
        headers: vec![],
        body: vec![],
        timeout_ms: Some(1_000),
    }
}

fn literal_url(path: &str) -> String {
    format!("https://{PUBLIC_IP_LITERAL}{path}")
}

#[tokio::test]
async fn http_fetch_refuses_a_public_literal() {
    let mut ctx = tier2_local_ctx();
    let out = <TalosContext as wit_http::Host>::fetch(&mut ctx, get(&literal_url("/x"))).await;
    assert!(
        matches!(out, Err(wit_http::Error::Forbiddenhost)),
        "{out:?}"
    );
    assert_eq!(latched_class(&ctx), Some(reason_class::TIER1_EGRESS));
}

#[tokio::test]
async fn http_fetch_all_refuses_a_public_literal() {
    let mut ctx = tier2_local_ctx();
    let out = <TalosContext as wit_http::Host>::fetch_all(
        &mut ctx,
        vec![get(&literal_url("/a")), get(&literal_url("/b"))],
    )
    .await;
    assert_eq!(out.len(), 2);
    for r in &out {
        assert!(matches!(r, Err(wit_http::Error::Forbiddenhost)), "{r:?}");
    }
    assert_eq!(latched_class(&ctx), Some(reason_class::TIER1_EGRESS));
}

#[tokio::test]
async fn graphql_refuses_a_public_literal() {
    let mut ctx = tier2_local_ctx();
    let out = <TalosContext as wit_graphql::Host>::execute(
        &mut ctx,
        wit_graphql::Request {
            url: literal_url("/g"),
            query: "{ viewer { id } }".to_string(),
            variables: None,
            headers: None,
            timeout_ms: None,
        },
    )
    .await;
    assert!(out.is_err(), "{out:?}");
    assert_eq!(latched_class(&ctx), Some(reason_class::TIER1_EGRESS));
}

#[tokio::test]
async fn webhook_refuses_a_public_literal() {
    let mut ctx = tier2_local_ctx();
    let out = <TalosContext as wit_webhook::Host>::send(
        &mut ctx,
        wit_webhook::WebhookRequest {
            url: literal_url("/hook"),
            headers: vec![],
            body: "{}".to_string(),
            max_retries: Some(0),
            retry_delay_ms: Some(0),
        },
    )
    .await;
    assert!(out.is_err(), "{out:?}");
    assert_eq!(latched_class(&ctx), Some(reason_class::TIER1_EGRESS));
}

#[tokio::test]
async fn http_stream_refuses_a_public_literal() {
    let mut ctx = tier2_local_ctx();
    let out =
        <TalosContext as wit_http_stream::Host>::connect(&mut ctx, literal_url("/sse"), vec![])
            .await;
    assert!(
        matches!(out, Err(wit_http_stream::Error::ForbiddenHost)),
        "{out:?}"
    );
    assert_eq!(latched_class(&ctx), Some(reason_class::TIER1_EGRESS));
}
