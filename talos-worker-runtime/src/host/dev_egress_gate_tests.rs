//! The dev-only private-target opt-in at the three host-function pre-checks
//! that read it — `http::fetch`, `http::fetch_all` and
//! `validate_no_dns_rebinding` (webhook / graphql / http-stream) — driven
//! through the real methods with the opt-in STATED on the context.
//!
//! The pre-checks are the audited refusal (`forbiddenhost`, class
//! `private-ip`); the connect-time resolver is the correctness gate behind
//! them and has its own tests (`ssrf_resolver`, `wasi_http`). What is pinned
//! here is that each pre-check reads the opt-in from ITS context: with the
//! opt-in off a name resolving to loopback is refused BEFORE connect, whatever
//! any other context in the process was built with.
//!
//! No socket is opened: `localhost` resolves from the hosts file, and every
//! refusal asserted here is decided before `send()`. The opt-in ON direction
//! through `fetch` and `fetch_all` is the loopback tests in `host_impl_tests`.

use std::collections::HashMap;
use std::sync::Arc;

use talos_workflow_job_protocol::LlmTier;

use super::{wit_http, TalosContext};
use crate::context::DevEgressOptIns;
use crate::reason_class;
use crate::wit_inspector::CapabilityWorld;

const PRIVATE_TARGETS_ONLY: DevEgressOptIns = DevEgressOptIns {
    private_host_targets: true,
    insecure_http: false,
};

fn ctx(hosts: &[&str], dev_egress: DevEgressOptIns) -> TalosContext {
    TalosContext::new(
        CapabilityWorld::Http,
        hosts.iter().map(|h| (*h).to_string()).collect(),
        vec!["GET".to_string()],
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
    .with_dev_egress(dev_egress)
}

fn get_localhost() -> wit_http::Request {
    wit_http::Request {
        method: wit_http::Method::Get,
        // Port 9 (discard): nothing listens, and nothing is meant to connect.
        url: "https://localhost:9/x".to_string(),
        headers: vec![],
        body: vec![],
        timeout_ms: Some(1_000),
    }
}

fn latched(c: &TalosContext) -> Option<&'static str> {
    c.network_reason_handle().lock().unwrap().map(|r| r.class)
}

/// `fetch`: an explicitly allowed NAME that resolves to loopback is refused by
/// the pre-check — `forbiddenhost`, class `private-ip` — when this context has
/// not opted in. Were the pre-check to stop reading the context, the request
/// would fall through to the resolver and come back as a connect failure
/// (`networkerror`), which is a different, retry-shaped answer.
#[tokio::test]
async fn fetch_refuses_a_name_resolving_private_before_connect() {
    let mut c = ctx(&["localhost"], DevEgressOptIns::default());
    let out = <TalosContext as wit_http::Host>::fetch(&mut c, get_localhost()).await;
    assert!(
        matches!(out, Err(wit_http::Error::Forbiddenhost)),
        "{:?}",
        out.map(|r| r.status)
    );
    assert_eq!(latched(&c), Some(reason_class::PRIVATE_IP));
}

/// `fetch_all`: the same refusal, per entry.
#[tokio::test]
async fn fetch_all_refuses_a_name_resolving_private_before_connect() {
    let mut c = ctx(&["localhost"], DevEgressOptIns::default());
    let out = <TalosContext as wit_http::Host>::fetch_all(&mut c, vec![get_localhost()]).await;
    assert_eq!(out.len(), 1);
    assert!(
        matches!(out[0], Err(wit_http::Error::Forbiddenhost)),
        "{:?}",
        out[0].as_ref().map(|r| r.status)
    );
    assert_eq!(latched(&c), Some(reason_class::PRIVATE_IP));
}

/// `validate_no_dns_rebinding`, the pre-check `webhook::send`,
/// `graphql::execute` and `http_stream::connect` share: refused without the
/// opt-in, admitted with it for an EXPLICIT entry, and still refused with it
/// when the name is reached only through `*`.
#[tokio::test]
async fn the_shared_dns_pre_check_reads_the_opt_in_from_its_own_context() {
    let mut off = ctx(&["localhost"], DevEgressOptIns::default());
    assert!(
        off.validate_no_dns_rebinding("localhost", "webhook")
            .await
            .is_err(),
        "no opt-in: a name resolving to loopback is refused"
    );

    let mut on = ctx(&["localhost"], PRIVATE_TARGETS_ONLY);
    assert!(
        on.validate_no_dns_rebinding("localhost", "webhook")
            .await
            .is_ok(),
        "control: the opt-in admits an explicitly named host"
    );

    let mut wildcard = ctx(&["*"], PRIVATE_TARGETS_ONLY);
    assert!(
        wildcard
            .validate_no_dns_rebinding("localhost", "webhook")
            .await
            .is_err(),
        "the opt-in never widens a `*` allowlist"
    );
}
