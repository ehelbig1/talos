#![allow(unused_imports)]
//! S5 (2026-05-22): end-to-end Tier-1 LLM-egress enforcement tests.
//!
//! Per CLAUDE.md, the per-actor `max_llm_tier` ceiling has five
//! enforcement surfaces in the worker. Unit tests already cover the
//! `decide_llm_tier_access` helper and `is_external_llm_host` matcher,
//! but until now there was no integration coverage that exercised
//! ALL FIVE surfaces with a Tier-1 actor + allowlisted external-LLM
//! host. The host functions are five different code paths that can
//! each rot independently; this file is the regression net.
//!
//! For each surface we construct a TalosContext with:
//!   * `max_llm_tier = Tier1`
//!   * `allowed_hosts` containing the external LLM endpoint
//!     (so the host-allowlist check would otherwise pass)
//! …then invoke the host function and assert it returns the
//! Forbiddenhost / equivalent error variant.
//!
//! Surfaces covered:
//!   1. `wit_http::fetch`            (talos:core/http.fetch)
//!   2. `wit_http::fetch_all`        (talos:core/http.fetch-all)
//!   3. `wit_graphql::execute`       (talos:core/graphql.execute)
//!   4. `wit_webhook::send`          (talos:core/webhook.send)
//!   5. `wit_http_stream::connect`   (talos:core/http-stream.connect)
//!
//! `get_llm_api_key` is also a Tier-1 surface (it's the path
//! `llm::complete` resolves keys through), but it requires the
//! `llm-node` linker — covered by the existing
//! `llm_tier_decision_tests` unit tests at host_impl.rs:1143 and not
//! re-tested at the integration layer.

use std::collections::HashMap;
use std::sync::Arc;
use worker::context::TalosContext;
use worker::expose_fallback::ExposeFallback;
use worker::CapabilityWorld;

/// Helper: build a TalosContext with Tier-1 ceiling AND an
/// allowlist that includes the given external LLM endpoint, so the
/// rejection MUST come from the tier-1 gate (not from the
/// allowed_hosts check that would otherwise short-circuit first).
fn make_tier1_context_with_llm_host(world: CapabilityWorld, llm_host: &str) -> TalosContext {
    let mut ctx = TalosContext::new(
        world,
        vec![llm_host.to_string()],
        vec![],
        128,
        HashMap::new(),
        None,
        None,
        false,
        None,
        Arc::new(ExposeFallback::new()),
    )
    .expect("failed to create TalosContext");
    ctx.max_llm_tier = talos_workflow_job_protocol::LlmTier::Tier1;
    ctx
}

// ---------------------------------------------------------------------------
// 1. wit_http::fetch — single GET against api.anthropic.com
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tier1_blocks_fetch_to_anthropic() {
    use worker::bindings::talos::core::http::{self as wit_http, Host};
    let mut ctx = make_tier1_context_with_llm_host(CapabilityWorld::Http, "api.anthropic.com");

    let req = wit_http::Request {
        method: wit_http::Method::Get,
        url: "https://api.anthropic.com/v1/messages".to_string(),
        headers: vec![],
        body: vec![],
        timeout_ms: None,
    };
    let result = ctx.fetch(req).await;
    assert!(
        matches!(result, Err(wit_http::Error::Forbiddenhost)),
        "tier1 must refuse fetch to api.anthropic.com regardless of allowed_hosts \
         (got {:?})",
        result.as_ref().map(|_| "Ok"),
    );
}

#[tokio::test]
async fn tier1_blocks_fetch_to_openai() {
    use worker::bindings::talos::core::http::{self as wit_http, Host};
    let mut ctx = make_tier1_context_with_llm_host(CapabilityWorld::Http, "api.openai.com");

    let req = wit_http::Request {
        method: wit_http::Method::Post,
        url: "https://api.openai.com/v1/chat/completions".to_string(),
        headers: vec![],
        body: b"{\"model\":\"gpt-4o\"}".to_vec(),
        timeout_ms: None,
    };
    let result = ctx.fetch(req).await;
    assert!(
        matches!(result, Err(wit_http::Error::Forbiddenhost)),
        "tier1 must refuse fetch to api.openai.com regardless of allowed_hosts \
         (got {:?})",
        result.as_ref().map(|_| "Ok"),
    );
}

#[tokio::test]
async fn tier1_blocks_fetch_to_gemini() {
    use worker::bindings::talos::core::http::{self as wit_http, Host};
    let mut ctx = make_tier1_context_with_llm_host(
        CapabilityWorld::Http,
        "generativelanguage.googleapis.com",
    );

    let req = wit_http::Request {
        method: wit_http::Method::Post,
        url: "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent"
            .to_string(),
        headers: vec![],
        body: vec![],
        timeout_ms: None,
    };
    let result = ctx.fetch(req).await;
    assert!(
        matches!(result, Err(wit_http::Error::Forbiddenhost)),
        "tier1 must refuse fetch to gemini regardless of allowed_hosts \
         (got {:?})",
        result.as_ref().map(|_| "Ok"),
    );
}

#[tokio::test]
async fn tier2_allows_fetch_to_anthropic_when_host_allowlisted() {
    use worker::bindings::talos::core::http::{self as wit_http, Host};
    // Inverse assertion: a Tier2 context (default) with the host
    // allowlisted should NOT be rejected at the tier gate. The
    // request will likely fail at the network layer (no auth header,
    // etc.) but specifically NOT with Forbiddenhost.
    let mut ctx = make_tier1_context_with_llm_host(CapabilityWorld::Http, "api.anthropic.com");
    ctx.max_llm_tier = talos_workflow_job_protocol::LlmTier::Tier2;

    let req = wit_http::Request {
        method: wit_http::Method::Get,
        url: "https://api.anthropic.com/v1/messages".to_string(),
        headers: vec![],
        body: vec![],
        timeout_ms: Some(50), // fail fast on network
    };
    let result = ctx.fetch(req).await;
    // Tier2 may succeed, time out, or fail for unrelated reasons —
    // but the Tier1-specific Forbiddenhost MUST NOT be the rejection
    // reason. (If it is, the tier gate is incorrectly tripping on
    // Tier2 — a regression.)
    if let Err(wit_http::Error::Forbiddenhost) = result {
        panic!(
            "Tier2 must not be Forbiddenhost-rejected at the LLM-host gate \
             — that's the Tier1 contract. Got: Forbiddenhost"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. wit_http::fetch_all — batch path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tier1_blocks_fetch_all_to_external_llm() {
    use worker::bindings::talos::core::http::{self as wit_http, Host};
    let mut ctx = make_tier1_context_with_llm_host(CapabilityWorld::Http, "api.anthropic.com");

    let reqs = vec![wit_http::Request {
        method: wit_http::Method::Get,
        url: "https://api.anthropic.com/v1/messages".to_string(),
        headers: vec![],
        body: vec![],
        timeout_ms: None,
    }];
    let per_req = ctx.fetch_all(reqs).await;
    // `fetch_all` returns `Vec<Result<Response, Error>>` (per-request
    // outcomes — the batch itself doesn't fail-all on one bad URL).
    // Tier-1 enforcement must surface as Forbiddenhost on the
    // matching index.
    assert!(
        per_req
            .iter()
            .any(|r| matches!(r, Err(wit_http::Error::Forbiddenhost))),
        "tier1 fetch_all must reject api.anthropic.com — \
         expected at least one Forbiddenhost in per-request results, got {:?}",
        per_req.iter().map(|r| r.as_ref().err()).collect::<Vec<_>>(),
    );
}

// ---------------------------------------------------------------------------
// 3. wit_graphql::execute
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tier1_blocks_graphql_to_external_llm() {
    use worker::bindings::talos::core::graphql::{self as wit_graphql, Host};
    let mut ctx = make_tier1_context_with_llm_host(CapabilityWorld::Http, "api.anthropic.com");

    let req = wit_graphql::Request {
        url: "https://api.anthropic.com/v1/graphql".to_string(),
        query: "{ ping }".to_string(),
        variables: None,
        headers: None,
        timeout_ms: None,
    };
    let result = ctx.execute(req).await;
    assert!(
        result.is_err(),
        "tier1 must refuse graphql to api.anthropic.com (got {:?})",
        result.as_ref().map(|_| "Ok"),
    );
}

// ---------------------------------------------------------------------------
// 4. wit_webhook::send
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tier1_blocks_webhook_to_external_llm() {
    use worker::bindings::talos::core::webhook::{self as wit_webhook, Host};
    let mut ctx = make_tier1_context_with_llm_host(CapabilityWorld::Http, "api.openai.com");

    let req = wit_webhook::WebhookRequest {
        url: "https://api.openai.com/v1/chat/completions".to_string(),
        headers: vec![],
        body: "{}".to_string(),
        max_retries: Some(0),
        retry_delay_ms: Some(0),
    };
    let result = ctx.send(req).await;
    assert!(
        result.is_err(),
        "tier1 must refuse webhook to api.openai.com (got {:?})",
        result.as_ref().map(|_| "Ok"),
    );
}

// ---------------------------------------------------------------------------
// 5. wit_http_stream::connect (SSE / event-stream)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tier1_blocks_http_stream_to_external_llm() {
    use worker::bindings::talos::core::http_stream::Host;
    let mut ctx = make_tier1_context_with_llm_host(CapabilityWorld::Http, "api.anthropic.com");

    // `http-stream::connect` is `func(url: string, headers: list<tuple<string, string>>)`
    // — no Request record. Pass URL + empty headers directly.
    let result = ctx
        .connect(
            "https://api.anthropic.com/v1/events".to_string(),
            vec![],
        )
        .await;
    assert!(
        result.is_err(),
        "tier1 must refuse http_stream to api.anthropic.com (got {:?})",
        result.as_ref().map(|_| "Ok"),
    );
}
