//! The dev-only egress opt-ins, from the process ENVIRONMENT to a real fetch.
//!
//! `TalosContext::new` reads `WORKER_ALLOW_PRIVATE_HOST_TARGETS` and
//! `WASM_ALLOW_INSECURE_HTTP` once and carries the answer on the context
//! (`DevEgressOptIns`). The unit tests in the library state the opt-ins on a
//! context directly and never touch the environment, so nothing there shows
//! that the two variables still reach a context at all. This file does, and it
//! is the ONE place in the crate that sets them.
//!
//! It is an integration-test binary on purpose: its own process under plain
//! `cargo test` as well as under nextest, so the variables it sets are seen by
//! no other test. Inside the binary every test takes [`EnvGuard`], which holds
//! one lock for its lifetime and puts the variables back when it drops — a
//! second test added here must take it too.
//!
//! It also owns `EMAIL_API_URL` / `EMAIL_API_KEY` (E-1, 2026-10-14): the
//! operator-wide fallback `email::send` reads from the environment, which is
//! the one route by which that URL reaches a real POST in a test.

use std::collections::HashMap;
use std::ffi::OsString;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use talos_worker_runtime::bindings::talos::core::email as wit_email;
use talos_worker_runtime::bindings::talos::core::http::{self as wit_http, Host};
use talos_worker_runtime::context::{DevEgressOptIns, TalosContext};
use talos_worker_runtime::expose_fallback::ExposeFallback;
use talos_worker_runtime::wit_inspector::CapabilityWorld;
use talos_workflow_job_protocol::LlmTier;

const PRIVATE_TARGETS: &str = "WORKER_ALLOW_PRIVATE_HOST_TARGETS";
const INSECURE_HTTP: &str = "WASM_ALLOW_INSECURE_HTTP";
const RUST_ENV: &str = "RUST_ENV";
const EMAIL_URL: &str = "EMAIL_API_URL";
const EMAIL_KEY: &str = "EMAIL_API_KEY";
const VARS: [&str; 5] = [
    PRIVATE_TARGETS,
    INSECURE_HTTP,
    RUST_ENV,
    EMAIL_URL,
    EMAIL_KEY,
];

static ENV: Mutex<()> = Mutex::new(());

/// Serialises every environment-touching test in this binary and restores the
/// three variables to what they were, on every exit including a panic.
struct EnvGuard {
    prior: Vec<(&'static str, Option<OsString>)>,
    _serial: MutexGuard<'static, ()>,
}

impl EnvGuard {
    /// Take the lock, remember the three variables, and clear them.
    fn cleared() -> Self {
        let serial = ENV.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let prior = VARS.iter().map(|v| (*v, std::env::var_os(v))).collect();
        for v in VARS {
            std::env::remove_var(v);
        }
        Self {
            prior,
            _serial: serial,
        }
    }

    fn set(&self, var: &'static str, value: Option<&str>) {
        assert!(VARS.contains(&var), "{var} is not restored by this guard");
        match value {
            Some(v) => std::env::set_var(var, v),
            None => std::env::remove_var(var),
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (var, value) in &self.prior {
            match value {
                Some(v) => std::env::set_var(var, v),
                None => std::env::remove_var(var),
            }
        }
    }
}

/// Loopback server answering every connection `200 {}`; returns its port.
async fn spawn_loopback_server() -> u16 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let port = listener.local_addr().expect("local_addr").port();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let mut buf = vec![0u8; 8192];
            let _ = socket.read(&mut buf).await;
            let _ = socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                .await;
            let _ = socket.flush().await;
        }
    });
    port
}

/// A context built the way a job builds one: `TalosContext::new`, which is
/// where the environment is read.
fn job_context() -> TalosContext {
    TalosContext::new(
        CapabilityWorld::Http,
        vec!["localhost".to_string()],
        vec!["GET".to_string()],
        128,
        HashMap::new(),
        None,
        None,
        false,
        None,
        Arc::new(ExposeFallback::new()),
        LlmTier::default(),
        None,
    )
    .expect("context builds")
}

/// One GET to the loopback listener by the `localhost` NAME (an IP literal is
/// refused regardless of any opt-in).
async fn fetch_loopback(ctx: &mut TalosContext, port: u16) -> Result<u16, wit_http::Error> {
    ctx.fetch(wit_http::Request {
        method: wit_http::Method::Get,
        url: format!("http://localhost:{port}/"),
        headers: vec![],
        body: vec![],
        timeout_ms: Some(5_000),
    })
    .await
    .map(|r| r.status)
}

/// A context built from the environment as it is now, and its fetch.
async fn opt_ins_and_fetch(port: u16) -> (DevEgressOptIns, Result<u16, wit_http::Error>) {
    let mut ctx = job_context();
    let out = fetch_loopback(&mut ctx, port).await;
    (ctx.dev_egress(), out)
}

#[tokio::test]
async fn the_environment_reaches_a_context_and_production_refuses_the_private_target_toggle() {
    let env = EnvGuard::cleared();
    let port = spawn_loopback_server().await;

    // Neither variable: both opt-ins off, and the plaintext scheme is refused
    // before the address is looked at.
    let (opt_ins, out) = opt_ins_and_fetch(port).await;
    assert_eq!(opt_ins, DevEgressOptIns::default());
    assert!(
        matches!(out, Err(wit_http::Error::Invalidurl)),
        "no opt-in: plaintext http is refused by the scheme gate: {out:?}"
    );

    // Plaintext admitted, private targets not: the scheme gate passes and the
    // private-address refusal is what stops the request.
    env.set(INSECURE_HTTP, Some("1"));
    let (opt_ins, out) = opt_ins_and_fetch(port).await;
    assert_eq!(
        opt_ins,
        DevEgressOptIns {
            private_host_targets: false,
            insecure_http: true,
        }
    );
    assert!(
        matches!(out, Err(wit_http::Error::Forbiddenhost)),
        "without the private-target opt-in a name resolving to loopback is refused: {out:?}"
    );

    // Both: the request reaches the listener. This is the leg that fails if
    // the variables stop reaching a context.
    env.set(PRIVATE_TARGETS, Some("1"));
    let (opt_ins, out) = opt_ins_and_fetch(port).await;
    assert_eq!(
        opt_ins,
        DevEgressOptIns {
            private_host_targets: true,
            insecure_http: true,
        }
    );
    assert!(
        matches!(out, Ok(200)),
        "both opt-ins set in the environment: the loopback listener answers: {out:?}"
    );

    // Production: BOTH toggles are ignored however they are set (the insecure
    // one since E-6, 2026-10-14), so the plaintext request is refused again by
    // the scheme gate, before the address is looked at.
    env.set(RUST_ENV, Some("production"));
    let (opt_ins, out) = opt_ins_and_fetch(port).await;
    assert!(
        !opt_ins.private_host_targets,
        "RUST_ENV=production ignores WORKER_ALLOW_PRIVATE_HOST_TARGETS"
    );
    assert!(
        !opt_ins.insecure_http,
        "RUST_ENV=production ignores WASM_ALLOW_INSECURE_HTTP"
    );
    assert_eq!(opt_ins, DevEgressOptIns::default());
    assert!(
        matches!(out, Err(wit_http::Error::Invalidurl)),
        "in production plaintext http is refused with the toggle set: {out:?}"
    );

    // Read once: a context keeps the answer it was built with. Built while
    // both are set (and production is not), it still reaches the listener
    // after the environment is cleared; one built after the clearing does not.
    env.set(RUST_ENV, None);
    let mut built_while_set = job_context();
    env.set(PRIVATE_TARGETS, None);
    env.set(INSECURE_HTTP, None);
    let out = fetch_loopback(&mut built_while_set, port).await;
    assert!(
        matches!(out, Ok(200)),
        "a context keeps the opt-ins it was built with: {out:?}"
    );
    let (opt_ins, out) = opt_ins_and_fetch(port).await;
    assert_eq!(opt_ins, DevEgressOptIns::default());
    assert!(
        matches!(out, Err(wit_http::Error::Invalidurl)),
        "control: a context built after the clearing is refused again: {out:?}"
    );
}

/// Loopback server answering every connection `200 {}`, counting accepts.
async fn spawn_counting_server() -> (u16, Arc<AtomicUsize>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let port = listener.local_addr().expect("local_addr").port();
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = accepted.clone();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            let mut buf = vec![0u8; 16384];
            let _ = socket.read(&mut buf).await;
            let _ = socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                .await;
            let _ = socket.flush().await;
        }
    });
    (port, accepted)
}

fn email_context(hosts: &[&str]) -> TalosContext {
    TalosContext::new(
        CapabilityWorld::Http,
        hosts.iter().map(|h| h.to_string()).collect(),
        vec!["POST".to_string()],
        128,
        HashMap::new(),
        None,
        None,
        false,
        None,
        Arc::new(ExposeFallback::new()),
        LlmTier::default(),
        None,
    )
    .expect("context builds")
}

fn email() -> wit_email::Message {
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

/// E-1: `EMAIL_API_URL` from the environment passes the egress admission.
/// Before 2026-10-14 a private IP literal there was dialled with the API key
/// as its bearer, under any `allowed_hosts` — the connect-time resolver never
/// sees a literal.
#[tokio::test]
async fn the_email_api_url_from_the_environment_passes_the_egress_admission() {
    let env = EnvGuard::cleared();
    let (port, accepted) = spawn_counting_server().await;
    env.set(EMAIL_KEY, Some("test-key"));

    // A private literal under "*": refused before any connection.
    let private = format!("https://127.0.0.1:{port}/v3/mail/send");
    env.set(EMAIL_URL, Some(&private));
    let mut ctx = email_context(&["*"]);
    let out = wit_email::Host::send(&mut ctx, email()).await;
    assert!(
        matches!(out, Err(wit_email::Error::Sendfailed)),
        "a private literal is refused: {out:?}"
    );
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        0,
        "the refused URL must never be dialled"
    );

    // CONTROL: the same listener, by a NAME the module lists, with both dev
    // opt-ins set — the send reaches it, so the refusal above is the
    // literal's and the environment does reach the surface.
    env.set(INSECURE_HTTP, Some("1"));
    env.set(PRIVATE_TARGETS, Some("1"));
    let named = format!("http://localhost:{port}/v3/mail/send");
    env.set(EMAIL_URL, Some(&named));
    let mut ctx = email_context(&["localhost"]);
    let out = wit_email::Host::send(&mut ctx, email()).await;
    assert!(out.is_ok(), "an admitted URL is sent: {out:?}");
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
}
