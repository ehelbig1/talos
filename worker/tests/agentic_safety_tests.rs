#![allow(unused_imports)]
//! Agentic safety integration tests for the Talos worker.
//!
//! The core security validation functions (`validate_wasm_sql`,
//! `validate_nats_topic`, `is_private_or_reserved_ip`) are module-private
//! in `worker::host_impl` and are comprehensively tested via the
//! `#[cfg(test)] mod agentic_safety_tests` unit test module inside that file.
//!
//! This integration test file exercises the publicly accessible safety
//! behavior through the `TalosContext` API where possible, and validates
//! end-to-end security properties.

use std::collections::HashMap;
use std::sync::Arc;
use worker::context::TalosContext;
use worker::expose_fallback::ExposeFallback;
use worker::CapabilityWorld;

/// Helper: create a TalosContext with the given capability world.
fn make_context(world: CapabilityWorld) -> TalosContext {
    TalosContext::new(
        world,
        vec!["*".to_string()],
        vec![],
        128,
        HashMap::new(),
        None,
        None,
        false,
        None,
        Arc::new(ExposeFallback::new()),
        // Tier-2 default (external egress allowed) for these non-tier tests.
        talos_workflow_job_protocol::LlmTier::Tier2,
        None, // egress_scope: tier-derived default
    )
    .expect("failed to create TalosContext")
}

// ---------------------------------------------------------------------------
// SSRF protection: private IPs should be blocked at the HTTP level
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ssrf_blocks_loopback_v4() {
    use worker::bindings::talos::core::http::{self as wit_http, Host};
    let mut ctx = make_context(CapabilityWorld::Http);

    // `https://` so the scheme gate doesn't short-circuit the SSRF
    // check — this test exists to demonstrate the IP-literal block.
    let req = wit_http::Request {
        method: wit_http::Method::Get,
        url: "https://127.0.0.1/admin".to_string(),
        headers: vec![],
        body: vec![],
        timeout_ms: None,
    };
    let result = ctx.fetch(req).await;
    assert!(
        matches!(result, Err(wit_http::Error::Forbiddenhost)),
        "loopback should be blocked by SSRF protection"
    );
}

#[tokio::test]
async fn ssrf_blocks_private_10_network() {
    use worker::bindings::talos::core::http::{self as wit_http, Host};
    let mut ctx = make_context(CapabilityWorld::Http);

    let req = wit_http::Request {
        method: wit_http::Method::Get,
        url: "https://10.0.0.1/secret".to_string(),
        headers: vec![],
        body: vec![],
        timeout_ms: None,
    };
    let result = ctx.fetch(req).await;
    assert!(
        matches!(result, Err(wit_http::Error::Forbiddenhost)),
        "10.x.x.x should be blocked"
    );
}

#[tokio::test]
async fn ssrf_blocks_link_local() {
    use worker::bindings::talos::core::http::{self as wit_http, Host};
    let mut ctx = make_context(CapabilityWorld::Http);

    let req = wit_http::Request {
        method: wit_http::Method::Get,
        url: "https://169.254.169.254/latest/meta-data".to_string(),
        headers: vec![],
        body: vec![],
        timeout_ms: None,
    };
    let result = ctx.fetch(req).await;
    assert!(
        matches!(result, Err(wit_http::Error::Forbiddenhost)),
        "cloud metadata endpoint should be blocked"
    );
}

#[tokio::test]
async fn ssrf_blocks_ipv6_loopback() {
    use worker::bindings::talos::core::http::{self as wit_http, Host};
    let mut ctx = make_context(CapabilityWorld::Http);

    let req = wit_http::Request {
        method: wit_http::Method::Get,
        url: "https://[::1]/admin".to_string(),
        headers: vec![],
        body: vec![],
        timeout_ms: None,
    };
    let result = ctx.fetch(req).await;
    assert!(
        matches!(result, Err(wit_http::Error::Forbiddenhost)),
        "IPv6 loopback should be blocked"
    );
}

#[tokio::test]
async fn insecure_scheme_blocked_by_default() {
    // Companion to the SSRF tests: confirm http:// is refused at the
    // scheme gate before any host/SSRF resolution, regardless of
    // whether the target IP is public. Without this, an operator
    // reading the audit ledger would think every plaintext fetch was
    // an SSRF probe.
    use worker::bindings::talos::core::http::{self as wit_http, Host};
    let mut ctx = make_context(CapabilityWorld::Http);

    let req = wit_http::Request {
        method: wit_http::Method::Get,
        url: "http://example.com/".to_string(),
        headers: vec![],
        body: vec![],
        timeout_ms: None,
    };
    let result = ctx.fetch(req).await;
    assert!(
        matches!(result, Err(wit_http::Error::Invalidurl)),
        "plaintext http:// must be refused by the scheme gate by default; \
         got {result:?}"
    );
}

// ---------------------------------------------------------------------------
// Capability world enforcement: minimal world cannot make HTTP requests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn minimal_world_blocks_http() {
    use worker::bindings::talos::core::http::{self as wit_http, Host};
    let mut ctx = make_context(CapabilityWorld::Minimal);

    let req = wit_http::Request {
        method: wit_http::Method::Get,
        url: "https://example.com".to_string(),
        headers: vec![],
        body: vec![],
        timeout_ms: None,
    };
    let result = ctx.fetch(req).await;
    assert!(
        matches!(result, Err(wit_http::Error::Forbiddenhost)),
        "minimal world should not allow HTTP requests"
    );
}

// ---------------------------------------------------------------------------
// Crypto limits: oversized inputs should be rejected
// ---------------------------------------------------------------------------

#[tokio::test]
async fn crypto_hash_rejects_oversized_input() {
    use worker::bindings::talos::core::crypto::{self as wit_crypto, Host};
    let mut ctx = make_context(CapabilityWorld::Minimal);

    // 101 MB exceeds the 100 MB limit
    let huge = vec![0u8; 101 * 1024 * 1024];
    let result =
        <TalosContext as wit_crypto::Host>::hash(&mut ctx, wit_crypto::HashAlgorithm::Sha256, huge)
            .await;
    assert!(
        result.is_empty(),
        "oversized hash input should return empty"
    );
}

#[tokio::test]
async fn crypto_random_bytes_rejects_oversized_request() {
    use worker::bindings::talos::core::crypto::{self as wit_crypto, Host};
    let mut ctx = make_context(CapabilityWorld::Minimal);

    let result = <TalosContext as wit_crypto::Host>::random_bytes(&mut ctx, 1_100_000).await;
    assert!(
        result.is_empty(),
        "oversized random request should return empty"
    );
}
