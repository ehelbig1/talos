//! Characterization of the per-request admission gates of `http::fetch` and
//! `http::fetch_all`, driven through the REAL `wit_http::Host` methods.
//!
//! Written BEFORE the two surfaces' shared URL admission was extracted into
//! `host::egress_admission`, and run green against the pre-extraction code, so
//! the extraction is proven not to move any refusal: the guest-visible error,
//! the latched reason class, the operator diagnostic (the text the audit
//! denial also carries) and the HTTP call budget are pinned per refusal.
//!
//! Every case completes without a socket. Hosts are IP literals so no DNS
//! lookup runs (`203.0.113.0/24` is RFC 5737 TEST-NET-3: public to the SSRF
//! classifier, never routed), and every case refuses before `send()`.
//!
//! The `divergence_*` cases pin places where the two surfaces DISAGREE today.
//! They are recorded, not endorsed: unifying them is a behaviour change.
//!
//! Out of range, stated: the write-ceiling and strict-egress gates read a
//! process-global `OnceLock` that sibling tests race, and the DNS-rebinding
//! gate needs a resolver; their decisions are unit-tested at their own homes.

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use talos_workflow_job_protocol::{EgressScope, LlmTier};

use super::limits::{
    MAX_HTTP_CALLS_PER_EXECUTION, MAX_HTTP_CALLS_PER_HOST_PER_EXECUTION, MAX_OUTBOUND_HEADERS,
    MAX_OUTBOUND_HTTP_BODY_BYTES, MAX_OUTBOUND_URL_BYTES,
};
use super::{wit_http, TalosContext};
use crate::context::HostDiagSink;
use crate::wit_inspector::CapabilityWorld;

/// A public literal no other test module uses, so the process-global circuit
/// breaker cannot be in a state another test left it in.
const IP: &str = "203.0.113.77";

struct Ctx {
    world: CapabilityWorld,
    hosts: Vec<String>,
    methods: Vec<String>,
    tier: LlmTier,
    scope: Option<EgressScope>,
}

impl Ctx {
    fn new() -> Self {
        Self {
            world: CapabilityWorld::Http,
            hosts: vec![IP.to_string(), "example.com".to_string()],
            methods: ["GET", "POST", "PUT", "PATCH", "DELETE"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
            tier: LlmTier::Tier2,
            scope: None,
        }
    }
    fn hosts(mut self, h: &[&str]) -> Self {
        self.hosts = h.iter().map(|s| s.to_string()).collect();
        self
    }
    fn methods(mut self, m: &[&str]) -> Self {
        self.methods = m.iter().map(|s| s.to_string()).collect();
        self
    }
    fn build(&self) -> (TalosContext, HostDiagSink) {
        let mut c = TalosContext::new(
            self.world.clone(),
            self.hosts.clone(),
            self.methods.clone(),
            128,
            HashMap::new(),
            None,
            None,
            false,
            None,
            Arc::new(crate::expose_fallback::ExposeFallback::new()),
            self.tier,
            self.scope,
        )
        .expect("context builds");
        let sink: HostDiagSink = Arc::new(std::sync::Mutex::new(Vec::new()));
        c.host_diag_sink = Some(sink.clone());
        (c, sink)
    }
}

fn req(method: wit_http::Method, url: &str) -> wit_http::Request {
    wit_http::Request {
        method,
        url: url.to_string(),
        headers: vec![],
        body: vec![],
        timeout_ms: Some(1_000),
    }
}

fn get(url: &str) -> wit_http::Request {
    req(wit_http::Method::Get, url)
}

fn at_ip(path: &str) -> String {
    format!("https://{IP}{path}")
}

/// What one call left behind.
#[derive(Debug, PartialEq, Eq)]
struct Seen {
    outcome: Vec<String>,
    class: Option<&'static str>,
    diag: Vec<String>,
    calls: u64,
}

fn render(r: &Result<wit_http::Response, wit_http::Error>) -> String {
    match r {
        Ok(resp) => format!("ok:{}", resp.status),
        Err(wit_http::Error::Invalidurl) => "Invalidurl".into(),
        Err(wit_http::Error::Timeout) => "Timeout".into(),
        Err(wit_http::Error::Networkerror) => "Networkerror".into(),
        Err(wit_http::Error::Forbiddenhost) => "Forbiddenhost".into(),
    }
}

fn seen(c: &TalosContext, sink: &HostDiagSink, outcome: Vec<String>) -> Seen {
    Seen {
        outcome,
        class: c.network_reason_handle().lock().unwrap().map(|r| r.class),
        diag: sink.lock().unwrap().clone(),
        calls: c.http_call_count.load(Ordering::Relaxed),
    }
}

async fn fetch(mut c: TalosContext, sink: HostDiagSink, r: wit_http::Request) -> Seen {
    let out = <TalosContext as wit_http::Host>::fetch(&mut c, r).await;
    seen(&c, &sink, vec![render(&out)])
}

async fn fetch_all(mut c: TalosContext, sink: HostDiagSink, r: Vec<wit_http::Request>) -> Seen {
    let out = <TalosContext as wit_http::Host>::fetch_all(&mut c, r).await;
    seen(&c, &sink, out.iter().map(render).collect())
}

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

/// `[host:<policy>] <op> denied by policy '<policy>' (target: <target>)`.
fn denied(op: &str, policy: &str, target: &str) -> String {
    format!("[host:{policy}] {op} denied by policy '{policy}' (target: {target})")
}

/// Drive the same single request through both surfaces and assert each.
async fn both(ctx: Ctx, r: wit_http::Request, want_fetch: Seen, want_all: Seen) {
    let (c, sink) = ctx.build();
    assert_eq!(fetch(c, sink, r.clone()).await, want_fetch, "fetch");
    let (c, sink) = ctx.build();
    assert_eq!(fetch_all(c, sink, vec![r]).await, want_all, "fetch_all");
}

/// A refusal both surfaces render identically (op label aside).
fn same(class: &'static str, err: &str, diag: Option<(&str, &str)>, op: &str) -> Seen {
    Seen {
        outcome: s(&[err]),
        class: Some(class),
        diag: diag
            .map(|(policy, target)| vec![denied(op, policy, target)])
            .unwrap_or_default(),
        calls: 0,
    }
}

async fn both_same(
    ctx: Ctx,
    r: wit_http::Request,
    class: &'static str,
    err: &str,
    diag: Option<(&str, &str)>,
) {
    both(
        ctx,
        r,
        same(class, err, diag, "http-fetch"),
        same(class, err, diag, "http-fetch-all"),
    )
    .await;
}

// ── The shared URL-admission sequence ───────────────────────────────────────

#[tokio::test]
async fn capability_world_refusal() {
    let mut ctx = Ctx::new();
    ctx.world = CapabilityWorld::Minimal;
    both_same(
        ctx,
        get(&at_ip("/x")),
        "capability-world",
        "Forbiddenhost",
        None,
    )
    .await;
}

#[tokio::test]
async fn url_too_long_refusal() {
    let long = format!("https://{IP}/{}", "a".repeat(MAX_OUTBOUND_URL_BYTES));
    both_same(Ctx::new(), get(&long), "url-too-long", "Invalidurl", None).await;
}

#[tokio::test]
async fn url_parse_refusal() {
    both_same(
        Ctx::new(),
        get("not a url"),
        "url-parse",
        "Invalidurl",
        None,
    )
    .await;
}

#[tokio::test]
async fn insecure_scheme_refusal() {
    both_same(
        Ctx::new(),
        get("http://example.com/x"),
        "insecure-scheme",
        "Invalidurl",
        Some(("insecure-scheme", "http example.com")),
    )
    .await;
}

#[tokio::test]
async fn empty_allowlist_refusal() {
    both_same(
        Ctx::new().hosts(&[]),
        get(&at_ip("/x")),
        "no-allowlist",
        "Forbiddenhost",
        Some(("no-allowlist-configured", IP)),
    )
    .await;
}

#[tokio::test]
async fn private_ip_literal_refusal() {
    both_same(
        Ctx::new().hosts(&["*"]),
        get("https://127.0.0.1/x"),
        "private-ip",
        "Forbiddenhost",
        Some(("private-ip", "127.0.0.1")),
    )
    .await;
}

#[tokio::test]
async fn allowed_hosts_refusal() {
    both_same(
        Ctx::new(),
        get("https://other.example/x"),
        "allowed-hosts",
        "Forbiddenhost",
        Some(("allowed-hosts", "other.example")),
    )
    .await;
}

#[tokio::test]
async fn tier1_llm_host_refusal() {
    let mut ctx = Ctx::new().hosts(&["api.anthropic.com"]);
    ctx.tier = LlmTier::Tier1;
    both_same(
        ctx,
        get("https://api.anthropic.com/v1/messages"),
        crate::reason_class::TIER1_LLM_EGRESS,
        "Forbiddenhost",
        Some(("tier1-llm-egress", "api.anthropic.com")),
    )
    .await;
}

#[tokio::test]
async fn tier1_public_literal_refusal() {
    let mut ctx = Ctx::new().hosts(&["*"]);
    ctx.tier = LlmTier::Tier1;
    both_same(
        ctx,
        get(&at_ip("/x")),
        crate::reason_class::TIER1_PUBLIC_IP_EGRESS,
        "Forbiddenhost",
        Some(("tier1-public-ip-egress", IP)),
    )
    .await;
}

#[tokio::test]
async fn local_egress_public_literal_refusal() {
    let mut ctx = Ctx::new().hosts(&["*"]);
    ctx.scope = Some(EgressScope::Local);
    both_same(
        ctx,
        get(&at_ip("/x")),
        "tier1-egress",
        "Forbiddenhost",
        Some(("local-egress-public-ip", IP)),
    )
    .await;
}

// ── Gates after URL admission ───────────────────────────────────────────────

#[tokio::test]
async fn method_allowlist_refusal() {
    let detail = talos_workflow_job_protocol::METHOD_ALLOWLIST_REMEDY;
    let line = |op: &str| {
        format!(
            "{} — {detail}",
            denied(op, "method-allowlist", &format!("POST {IP}"))
        )
    };
    both(
        Ctx::new().methods(&["GET"]),
        req(wit_http::Method::Post, &at_ip("/x")),
        // `fetch` charges the budget before the method gate.
        Seen {
            outcome: s(&["Forbiddenhost"]),
            class: Some("method-allowlist"),
            diag: vec![line("http-fetch")],
            calls: 1,
        },
        Seen {
            outcome: s(&["Forbiddenhost"]),
            class: Some("method-allowlist"),
            diag: vec![line("http-fetch-all")],
            calls: 0,
        },
    )
    .await;
}

#[tokio::test]
async fn per_host_rate_limit_refusal() {
    let exhaust = |c: &TalosContext| {
        for _ in 0..MAX_HTTP_CALLS_PER_HOST_PER_EXECUTION {
            assert!(c.check_per_host_rate_limit(
                &format!("{IP}:443"),
                MAX_HTTP_CALLS_PER_HOST_PER_EXECUTION
            ));
        }
    };
    let (c, sink) = Ctx::new().build();
    exhaust(&c);
    assert_eq!(
        fetch(c, sink, get(&at_ip("/x"))).await,
        // No audit diagnostic on this surface; the execution slot IS spent.
        Seen {
            outcome: s(&["Forbiddenhost"]),
            class: Some("per-host-rate-limit"),
            diag: vec![],
            calls: 1
        }
    );
    let (c, sink) = Ctx::new().build();
    exhaust(&c);
    assert_eq!(
        fetch_all(c, sink, vec![get(&at_ip("/x"))]).await,
        Seen {
            outcome: s(&["Forbiddenhost"]),
            class: Some("per-host-rate-limit"),
            diag: vec![denied(
                "http-fetch-all",
                "per-host-rate-limit",
                &format!("{IP}:443")
            )],
            calls: 0,
        }
    );
}

#[tokio::test]
async fn execution_rate_limit_refusal() {
    let (c, sink) = Ctx::new().build();
    c.http_call_count
        .store(MAX_HTTP_CALLS_PER_EXECUTION, Ordering::Relaxed);
    assert_eq!(
        fetch(c, sink, get(&at_ip("/x"))).await,
        Seen {
            outcome: s(&["Forbiddenhost"]),
            class: Some("execution-rate-limit"),
            diag: vec![],
            calls: MAX_HTTP_CALLS_PER_EXECUTION,
        }
    );
    // `fetch_all` refuses a batch that cannot fit up front.
    let (c, sink) = Ctx::new().build();
    c.http_call_count
        .store(MAX_HTTP_CALLS_PER_EXECUTION, Ordering::Relaxed);
    assert_eq!(
        fetch_all(c, sink, vec![get(&at_ip("/x"))]).await,
        Seen {
            outcome: s(&["Forbiddenhost"]),
            class: Some("execution-rate-limit"),
            diag: vec![],
            calls: MAX_HTTP_CALLS_PER_EXECUTION,
        }
    );
}

#[tokio::test]
async fn cancelled_refusal() {
    let (c, sink) = Ctx::new().build();
    c.cancelled.store(true, Ordering::Relaxed);
    let got = fetch(c, sink, get(&at_ip("/x"))).await;
    assert_eq!(got.outcome, s(&["Networkerror"]));
    assert_eq!(got.class, Some("cancelled"));
    // `fetch` checks cancellation after the budget charge.
    assert_eq!(got.calls, 1);
    let (c, sink) = Ctx::new().build();
    c.cancelled.store(true, Ordering::Relaxed);
    let got = fetch_all(c, sink, vec![get(&at_ip("/x"))]).await;
    assert_eq!(got.outcome, s(&["Networkerror"]));
    assert_eq!(got.class, Some("cancelled"));
    assert_eq!(got.calls, 0);
}

#[tokio::test]
async fn header_cap_refusal() {
    let mut r = get(&at_ip("/x"));
    r.headers = (0..=MAX_OUTBOUND_HEADERS)
        .map(|i| (format!("x-h{i}"), "v".to_string()))
        .collect();
    both(
        Ctx::new(),
        r,
        Seen {
            outcome: s(&["Forbiddenhost"]),
            class: Some("request-header-cap"),
            diag: vec![],
            calls: 1,
        },
        Seen {
            outcome: s(&["Forbiddenhost"]),
            class: Some("request-header-cap"),
            diag: vec![],
            calls: 0,
        },
    )
    .await;
}

#[tokio::test]
async fn body_cap_refusal() {
    let mut r = req(wit_http::Method::Post, &at_ip("/x"));
    r.body = vec![b'x'; MAX_OUTBOUND_HTTP_BODY_BYTES + 1];
    both(
        Ctx::new(),
        r,
        Seen {
            outcome: s(&["Forbiddenhost"]),
            class: Some("request-body-cap"),
            diag: vec![],
            calls: 1,
        },
        Seen {
            outcome: s(&["Forbiddenhost"]),
            class: Some("request-body-cap"),
            diag: vec![],
            calls: 0,
        },
    )
    .await;
}

#[tokio::test]
async fn vault_header_refusal() {
    let mut r = get(&at_ip("/x"));
    r.headers = vec![(
        "authorization".to_string(),
        "Bearer vault://svc/key".to_string(),
    )];
    let (c, sink) = Ctx::new().build();
    let f = fetch(c, sink, r.clone()).await;
    let (c, sink) = Ctx::new().build();
    let a = fetch_all(c, sink, vec![r]).await;
    assert_eq!(f.outcome, s(&["Forbiddenhost"]));
    assert_eq!(f.class, Some("secret-lookup"));
    assert_eq!(f.calls, 1);
    assert_eq!(a.outcome, s(&["Forbiddenhost"]));
    assert_eq!(a.class, Some("secret-lookup"));
    assert_eq!(a.calls, 0);
    // The resolver emits its own diagnostic, identical on both surfaces.
    assert_eq!(f.diag, a.diag);
    assert_eq!(f.diag.len(), 1, "{:?}", f.diag);
}

#[tokio::test]
async fn vault_body_refusal() {
    let mut r = req(wit_http::Method::Post, &at_ip("/x"));
    r.headers = vec![("content-type".to_string(), "application/json".to_string())];
    r.body = br#"{"token":"vault://svc/key"}"#.to_vec();
    let (c, sink) = Ctx::new().build();
    let f = fetch(c, sink, r.clone()).await;
    let (c, sink) = Ctx::new().build();
    let a = fetch_all(c, sink, vec![r]).await;
    assert_eq!(f.outcome, s(&["Forbiddenhost"]));
    assert_eq!(f.class, Some("secret-lookup"));
    assert_eq!(f.calls, 1);
    assert_eq!(a.outcome, s(&["Forbiddenhost"]));
    assert_eq!(a.class, Some("secret-lookup"));
    assert_eq!(a.calls, 0);
    assert_eq!(f.diag, a.diag);
    assert!(!f.diag.is_empty());
}

#[tokio::test]
async fn dry_run_mutation_is_mocked() {
    let (mut c, sink) = Ctx::new().build();
    c.dry_run = true;
    let got = fetch(c, sink, req(wit_http::Method::Post, &at_ip("/x"))).await;
    assert_eq!(
        got,
        Seen {
            outcome: s(&["ok:200"]),
            class: None,
            diag: vec![],
            calls: 1
        }
    );
    let (mut c, sink) = Ctx::new().build();
    c.dry_run = true;
    let got = fetch_all(c, sink, vec![req(wit_http::Method::Post, &at_ip("/x"))]).await;
    assert_eq!(
        got,
        Seen {
            outcome: s(&["ok:200"]),
            class: None,
            diag: vec![],
            calls: 1
        }
    );
}

// ── Recorded divergences between the two surfaces ──────────────────────────

/// `fetch_all` checks the body cap FIRST; `fetch` only after the URL gates.
#[tokio::test]
async fn divergence_body_cap_order() {
    let mut r = req(wit_http::Method::Post, "not a url");
    r.body = vec![b'x'; MAX_OUTBOUND_HTTP_BODY_BYTES + 1];
    both(
        Ctx::new(),
        r,
        Seen {
            outcome: s(&["Invalidurl"]),
            class: Some("url-parse"),
            diag: vec![],
            calls: 0,
        },
        Seen {
            outcome: s(&["Forbiddenhost"]),
            class: Some("request-body-cap"),
            diag: vec![],
            calls: 0,
        },
    )
    .await;
}

/// `fetch` mocks a dry-run mutation BEFORE the method allowlist (by design, see
/// its dry-run comment); `fetch_all` runs the allowlist in validation.
#[tokio::test]
async fn divergence_dry_run_skips_the_method_allowlist_only_in_fetch() {
    let ctx = Ctx::new().methods(&["GET"]);
    let (mut c, sink) = ctx.build();
    c.dry_run = true;
    let f = fetch(c, sink, req(wit_http::Method::Post, &at_ip("/x"))).await;
    assert_eq!(f.outcome, s(&["ok:200"]));
    let (mut c, sink) = ctx.build();
    c.dry_run = true;
    let a = fetch_all(c, sink, vec![req(wit_http::Method::Post, &at_ip("/x"))]).await;
    assert_eq!(a.outcome, s(&["Forbiddenhost"]));
    assert_eq!(a.class, Some("method-allowlist"));
}

/// Mixed batch: each entry keeps its own refusal; only the admitted one is
/// charged. Pins per-entry independence of the shared admission.
#[tokio::test]
async fn fetch_all_refuses_per_entry() {
    let (mut c, sink) = Ctx::new().build();
    c.dry_run = true;
    let got = fetch_all(
        c,
        sink,
        vec![
            get("not a url"),
            get("https://other.example/x"),
            get("https://127.0.0.1/x"),
            req(wit_http::Method::Post, &at_ip("/x")),
        ],
    )
    .await;
    assert_eq!(
        got.outcome,
        s(&["Invalidurl", "Forbiddenhost", "Forbiddenhost", "ok:200"])
    );
    assert_eq!(
        got.diag,
        vec![
            denied("http-fetch-all", "allowed-hosts", "other.example"),
            denied("http-fetch-all", "private-ip", "127.0.0.1"),
        ]
    );
    assert_eq!(got.calls, 1);
}
