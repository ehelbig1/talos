//! E-3 (2026-10-14): a granted secret is substituted only into a request to a
//! host the operator NAMED in `allowed_hosts` — never to a host admitted only
//! by `"*"`, and never into a message-bus header.
//!
//! Driven through the production host functions where the surface can run
//! without a socket or a NATS connection, and through the shared resolver
//! (`resolve_vault_header` / `resolve_vault_json_body`, the one home every
//! surface calls) for the rest. Every refusal is paired with a control on the
//! same context shape, so none can pass because the surface refuses
//! unconditionally. Hosts are TEST-NET-3 literals (public to the SSRF
//! classifier, never routed), so no DNS lookup runs.

use std::collections::HashMap;
use std::sync::Arc;

use talos_workflow_job_protocol::LlmTier;

use super::{wit_http, wit_webhook, TalosContext};
use crate::context::{HostDiagSink, SecretUseSurface};
use crate::reason_class;
use crate::wit_inspector::CapabilityWorld;

/// Distinct from every other test module's literal, so the process-global
/// circuit breaker cannot be in a state another test left it in.
const HOST: &str = "203.0.113.143";
const GRANTED_PATH: &str = "test/destination-token";
const PLAINTEXT: &str = "destination-test-plaintext";

fn ctx(hosts: &[&str]) -> (TalosContext, HostDiagSink) {
    let mut secrets = HashMap::new();
    secrets.insert(
        GRANTED_PATH.to_string(),
        zeroize::Zeroizing::new(PLAINTEXT.to_string()),
    );
    let mut c = TalosContext::new(
        CapabilityWorld::Http,
        hosts.iter().map(|h| h.to_string()).collect(),
        vec!["GET".to_string(), "POST".to_string()],
        128,
        secrets,
        None,
        None,
        false,
        None,
        Arc::new(crate::expose_fallback::ExposeFallback::new()),
        LlmTier::Tier2,
        None,
    )
    .expect("context builds");
    c.allowed_secrets = vec![GRANTED_PATH.to_string()];
    let sink: HostDiagSink = Arc::new(std::sync::Mutex::new(Vec::new()));
    c.host_diag_sink = Some(sink.clone());
    (c, sink)
}

fn latched(c: &TalosContext) -> Option<&'static str> {
    c.network_reason_handle().lock().unwrap().map(|r| r.class)
}

fn diag(sink: &HostDiagSink) -> String {
    sink.lock().unwrap().join("\n")
}

fn marker() -> String {
    format!("Bearer vault://{GRANTED_PATH}")
}

fn get_with_vault_header() -> wit_http::Request {
    wit_http::Request {
        method: wit_http::Method::Get,
        url: format!("https://{HOST}/r"),
        headers: vec![("authorization".to_string(), marker())],
        body: vec![],
        timeout_ms: Some(1),
    }
}

/// The finding's case: `allowed_hosts: ["*"]` + a granted `vault://` header.
#[tokio::test]
async fn fetch_refuses_a_credential_bound_for_a_wildcard_only_host() {
    let (mut c, sink) = ctx(&["*"]);
    let r = <TalosContext as wit_http::Host>::fetch(&mut c, get_with_vault_header()).await;
    assert!(matches!(r, Err(wit_http::Error::Forbiddenhost)), "{r:?}");
    assert_eq!(latched(&c), Some(reason_class::SECRET_LOOKUP));
    assert!(
        diag(&sink).contains(&format!(
            "vault-header denied by policy 'secret-destination' (target: {HOST})"
        )),
        "{}",
        diag(&sink)
    );
}

/// CONTROL: the same request to a NAMED host resolves the credential (the
/// call then fails on the 1 ms deadline, not on the secret).
#[tokio::test]
async fn fetch_substitutes_a_credential_for_a_named_host() {
    let (mut c, sink) = ctx(&[HOST]);
    let _ = <TalosContext as wit_http::Host>::fetch(&mut c, get_with_vault_header()).await;
    assert_ne!(latched(&c), Some(reason_class::SECRET_LOOKUP));
    assert!(
        !diag(&sink).contains("secret-destination"),
        "{}",
        diag(&sink)
    );
}

/// The remedy the refusal names: the destination beside `"*"`.
#[tokio::test]
async fn naming_the_destination_beside_the_wildcard_is_enough() {
    let (mut c, _) = ctx(&["*", HOST]);
    let m = marker();
    let out = c
        .resolve_vault_header(SecretUseSurface::HttpHeader, HOST, "authorization", &m)
        .await
        .expect("a named destination resolves");
    assert_eq!(out.as_ref(), format!("Bearer {PLAINTEXT}"));
}

#[tokio::test]
async fn the_body_placement_is_judged_the_same_way() {
    let body = format!(r#"{{"token":"vault://{GRANTED_PATH}"}}"#).into_bytes();
    let (mut c, sink) = ctx(&["*"]);
    let r = c
        .resolve_vault_json_body(
            SecretUseSurface::HttpJsonBody,
            HOST,
            &body,
            Some("application/json"),
        )
        .await;
    assert!(r.is_err(), "{r:?}");
    assert!(
        diag(&sink).contains("vault-json-body denied by policy 'secret-destination'"),
        "{}",
        diag(&sink)
    );
    // CONTROL: named.
    let (mut c, _) = ctx(&[HOST]);
    let out = c
        .resolve_vault_json_body(
            SecretUseSurface::HttpJsonBody,
            HOST,
            &body,
            Some("application/json"),
        )
        .await
        .expect("named host resolves")
        .expect("a marker was present");
    assert!(String::from_utf8(out).unwrap().contains(PLAINTEXT));
}

/// `webhook::send` — the catalog's `webhook-fanout` shape (`"*"` + a
/// `vault://` auth header). The resolve sits before the retry loop and the
/// breaker permit, so the refusal opens no connection.
#[tokio::test]
async fn webhook_refuses_a_credential_bound_for_a_wildcard_only_host() {
    let (mut c, sink) = ctx(&["*"]);
    let r = <TalosContext as wit_webhook::Host>::send(
        &mut c,
        wit_webhook::WebhookRequest {
            url: format!("https://{HOST}/hook"),
            headers: vec![("authorization".to_string(), marker())],
            body: "{}".to_string(),
            max_retries: Some(0),
            retry_delay_ms: Some(1),
        },
    )
    .await;
    assert!(matches!(r, Err(wit_webhook::Error::Sendfailed)), "{r:?}");
    assert_eq!(latched(&c), Some(reason_class::SECRET_LOOKUP));
    assert!(
        diag(&sink).contains("'secret-destination'"),
        "{}",
        diag(&sink)
    );
}

/// A NATS header has no destination host: refused outright, even when the
/// module names hosts.
#[tokio::test]
async fn a_message_bus_header_never_carries_a_credential() {
    let (mut c, sink) = ctx(&[HOST]);
    let m = marker();
    let r = c
        .resolve_vault_header(
            SecretUseSurface::MessagingHeader,
            "events.topic",
            "authorization",
            &m,
        )
        .await;
    assert!(r.is_err(), "{r:?}");
    assert!(
        diag(&sink).contains(
            "vault-header denied by policy 'secret-destination' (target: messaging-header)"
        ),
        "{}",
        diag(&sink)
    );
    // A header with no marker is untouched on the same surface.
    let plain = c
        .resolve_vault_header(
            SecretUseSurface::MessagingHeader,
            "events.topic",
            "x-trace",
            "abc",
        )
        .await
        .expect("no marker, nothing to refuse");
    assert_eq!(plain.as_ref(), "abc");
}
