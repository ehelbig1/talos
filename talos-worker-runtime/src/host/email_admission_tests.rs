//! E-1 (2026-10-14): the email API URL passes the same egress admission as
//! every other surface — driven through the production
//! [`TalosContext::admit_email_api_url`] and through `email::send` itself.
//!
//! Every case completes without a socket: hosts are IP literals (no DNS), and
//! every refusal happens before a send. `203.0.113.0/24` is RFC 5737
//! TEST-NET-3 — public to the SSRF classifier, never routed. The env-sourced
//! leg (the `EMAIL_API_URL` variable reaching a real POST) is in
//! `tests/dev_egress_env.rs`, the one binary that sets environment variables.

use std::collections::HashMap;
use std::sync::Arc;

use talos_workflow_job_protocol::LlmTier;

use super::{wit_email, TalosContext};
use crate::context::{DevEgressOptIns, HostDiagSink};
use crate::wit_inspector::CapabilityWorld;

const PUBLIC: &str = "203.0.113.10";

fn ctx(
    hosts: &[&str],
    secrets: talos_workflow_job_protocol::SecretMap,
) -> (TalosContext, HostDiagSink) {
    let mut c = TalosContext::new(
        CapabilityWorld::Http,
        hosts.iter().map(|h| h.to_string()).collect(),
        vec!["POST".to_string()],
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
    .expect("context builds")
    // Stated, never read from the shell: no dev opt-in.
    .with_dev_egress(DevEgressOptIns::default());
    let sink: HostDiagSink = Arc::new(std::sync::Mutex::new(Vec::new()));
    c.host_diag_sink = Some(sink.clone());
    (c, sink)
}

fn diag(sink: &HostDiagSink) -> String {
    sink.lock().unwrap().join("\n")
}

/// The finding's case (a): a private or metadata IP literal is refused even
/// under `allowed_hosts: ["*"]`, and the refusal is recorded.
#[tokio::test]
async fn a_private_literal_is_refused_under_the_wildcard() {
    for (url, ip) in [
        ("https://127.0.0.1:1/", "127.0.0.1"),
        (
            "https://169.254.169.254/latest/api/token",
            "169.254.169.254",
        ),
        ("https://10.0.0.5:5432/", "10.0.0.5"),
    ] {
        let (mut c, sink) = ctx(&["*"], HashMap::new());
        let r = c.admit_email_api_url(url).await;
        assert!(
            matches!(r, Err(wit_email::Error::Sendfailed)),
            "{url}: {r:?}"
        );
        let d = diag(&sink);
        assert!(
            d.contains(&format!(
                "email-send denied by policy 'private-ip' (target: {ip})"
            )),
            "{url}: {d}"
        );
    }
    // CONTROL: a public literal under the same wildcard is admitted, so the
    // refusal above is the literal's, not the surface's.
    let (mut c, sink) = ctx(&["*"], HashMap::new());
    let ok = c
        .admit_email_api_url(&format!("https://{PUBLIC}/v3/mail/send"))
        .await
        .expect("a public literal under '*' is admitted");
    assert_eq!(ok.host_str(), Some(PUBLIC));
    assert!(diag(&sink).is_empty());
}

/// Case (b): plaintext is refused unless this context opted in.
#[tokio::test]
async fn plaintext_is_refused_without_the_opt_in() {
    let url = format!("http://{PUBLIC}/v3/mail/send");
    let (mut c, sink) = ctx(&[PUBLIC], HashMap::new());
    let r = c.admit_email_api_url(&url).await;
    assert!(matches!(r, Err(wit_email::Error::Sendfailed)), "{r:?}");
    assert!(
        diag(&sink).contains("email-send denied by policy 'insecure-scheme'"),
        "{}",
        diag(&sink)
    );
    // CONTROL: the same URL with the opt-in stated on the context passes.
    let (c, _) = ctx(&[PUBLIC], HashMap::new());
    let mut c = c.with_dev_egress(DevEgressOptIns {
        private_host_targets: false,
        insecure_http: true,
    });
    assert!(c.admit_email_api_url(&url).await.is_ok());
}

/// Case (c): a host outside `allowed_hosts` is refused.
#[tokio::test]
async fn a_host_outside_allowed_hosts_is_refused() {
    let url = format!("https://{PUBLIC}/v3/mail/send");
    let (mut c, sink) = ctx(&["api.example.test"], HashMap::new());
    let r = c.admit_email_api_url(&url).await;
    assert!(matches!(r, Err(wit_email::Error::Sendfailed)), "{r:?}");
    assert!(
        diag(&sink).contains(&format!(
            "email-send denied by policy 'allowed-hosts' (target: {PUBLIC})"
        )),
        "{}",
        diag(&sink)
    );
    // An empty allowlist denies too.
    let (mut c, sink) = ctx(&[], HashMap::new());
    assert!(c.admit_email_api_url(&url).await.is_err());
    assert!(diag(&sink).contains("'no-allowlist-configured'"));
}

/// The refusal never echoes the URL (it is a configured secret): an
/// unparseable value is recorded with an empty target.
#[tokio::test]
async fn an_unparseable_url_is_refused_without_echoing_it() {
    let (mut c, sink) = ctx(&["*"], HashMap::new());
    let r = c.admit_email_api_url("not a url with-a-token-in-it").await;
    assert!(r.is_err());
    let d = diag(&sink);
    assert!(d.contains("'invalid-email-api-url' (target: )"), "{d}");
    assert!(!d.contains("with-a-token-in-it"), "{d}");
}

fn message() -> wit_email::Message {
    wit_email::Message {
        to: vec!["someone@example.test".to_string()],
        cc: None,
        bcc: None,
        subject: "s".to_string(),
        body: "b".to_string(),
        html: None,
        attachments: None,
    }
}

/// Wiring: `email::send` reaches the gate. The URL here comes from the job's
/// secret map, under the wildcard, and is a private literal: before E-1 it
/// went to `reqwest` and nothing was recorded.
#[tokio::test]
async fn send_records_a_refusal_from_the_gate_before_any_post() {
    let mut secrets = HashMap::new();
    secrets.insert(
        "EMAIL_API_URL".to_string(),
        zeroize::Zeroizing::new("https://127.0.0.1:1/".to_string()),
    );
    secrets.insert(
        "EMAIL_API_KEY".to_string(),
        zeroize::Zeroizing::new("test-key".to_string()),
    );
    let (mut c, sink) = ctx(&["*"], secrets);
    let r = <TalosContext as wit_email::Host>::send(&mut c, message()).await;
    assert!(matches!(r, Err(wit_email::Error::Sendfailed)), "{r:?}");
    assert!(
        diag(&sink).contains("email-send denied by policy '"),
        "the send must be refused by the admission, not by the transport: {}",
        diag(&sink)
    );
}
