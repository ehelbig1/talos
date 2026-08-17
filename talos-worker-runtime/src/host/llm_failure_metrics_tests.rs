//! Every non-success exit of `llm::complete` must increment
//! `wasm_llm_failures_total`, driven through the PRODUCTION entry point.
//!
//! ## Why these tests are shaped the way they are
//!
//! Structural lint check 58 (registered-but-never-incremented metric) is a
//! grep, and its own documented limit is that an increment wrapped in a helper
//! reads as live even if nothing calls the helper. A test that called
//! `record_llm_failure` directly would satisfy the lint and prove nothing. So
//! every assertion below goes through `wit_llm::Host::complete` — the same
//! method the WASM guest calls — and reads the counter back out of the
//! Prometheus exposition, not out of a mock.
//!
//! ## Constraints that forced the single-runtime design
//!
//! Three pieces of process-global state make the obvious `#[tokio::test]`
//! per case wrong here:
//!
//! * `local_llm_http_client()` is a `OnceLock<reqwest::Client>`. Pooled
//!   connections are bound to the runtime that created them, so tests on
//!   per-test runtimes can hand each other a connection whose reactor is gone.
//! * `ollama_base_url()` is a `OnceLock<String>` read from `OLLAMA_URL`, so the
//!   provider endpoint can only be pointed at a mock ONCE per process.
//! * `tokio::time::pause()` requires a current-thread runtime.
//!
//! Hence one shared current-thread runtime, one mock provider, and a mutex so
//! the clock-manipulating case cannot overlap the others. The mock dispatches
//! on the request's `model` field, so each case gets its own behaviour without
//! any shared mode flag.
//!
//! ## What is NOT proven here
//!
//! `LlmFailure::InvalidRequest` — the `serde_json::to_vec` exit. It is not
//! reachable from any input (see the variant's doc); it is asserted for
//! classification only, in `every_outcome_has_a_distinct_stable_label`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use talos_workflow_job_protocol::LlmTier;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{llm_provider_label, wit_llm, TalosContext};
use crate::metrics::{
    get_prometheus_metrics, init_telemetry_for_tests, LlmFailure, RuntimeMetrics,
    LLM_PROVIDER_LABELS,
};
use crate::wit_inspector::CapabilityWorld;

// ---------------------------------------------------------------------------
// Shared runtime + mock provider
// ---------------------------------------------------------------------------

/// Serializes the cases. Only load-bearing for `stalls_are_counted_as_timeout`,
/// which pauses the shared runtime's clock — but held by all of them, because a
/// paused clock is process-visible and "only the clock test needs it" is the
/// kind of scoping assumption that rots.
static SERIALIZE: Mutex<()> = Mutex::new(());

fn guard() -> MutexGuard<'static, ()> {
    SERIALIZE.lock().unwrap_or_else(|e| e.into_inner())
}

/// One current-thread runtime for the whole binary, never dropped, so the
/// process-global reqwest client's pooled connections stay valid.
fn rt() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime")
    })
}

/// Permits added by the mock when it has read a full `mock-stall` request.
fn stall_signal() -> &'static tokio::sync::Semaphore {
    static S: OnceLock<tokio::sync::Semaphore> = OnceLock::new();
    S.get_or_init(|| tokio::sync::Semaphore::new(0))
}

static REQUESTS_SERVED: AtomicU64 = AtomicU64::new(0);

/// Start the mock provider (once) and point `OLLAMA_URL` at it.
///
/// Must be called from inside `rt()`. Returns nothing; the assertion that the
/// redirect actually took effect is made by the caller, because a silently
/// ignored `set_var` would leave every case below firing at a real endpoint.
async fn ensure_mock_provider() {
    static ADDR: OnceLock<String> = OnceLock::new();
    if ADDR.get().is_some() {
        return;
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock provider");
    let addr = listener.local_addr().expect("local addr");
    let base = format!("http://{addr}");
    // Safe on edition 2021. Set before any code path can call
    // `ollama_base_url()`, whose OnceLock latches the first read.
    std::env::set_var("OLLAMA_URL", &base);
    ADDR.set(base).ok();

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            tokio::spawn(serve_one(stream));
        }
    });
}

/// Read one HTTP request fully (headers + `Content-Length` body) and reply
/// according to the `model` field in the JSON body.
async fn serve_one(mut stream: tokio::net::TcpStream) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];

    // Headers.
    let header_end = loop {
        match stream.read(&mut chunk).await {
            Ok(0) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => return,
        }
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break p + 4;
        }
    };
    let headers = String::from_utf8_lossy(&buf[..header_end]).to_ascii_lowercase();
    let content_length = headers
        .split("content-length:")
        .nth(1)
        .and_then(|r| r.split("\r\n").next())
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0);

    // Body.
    while buf.len() < header_end + content_length {
        match stream.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => return,
        }
    }
    REQUESTS_SERVED.fetch_add(1, Ordering::Relaxed);

    let body = String::from_utf8_lossy(&buf[header_end..]).to_string();
    let model = body
        .split("\"model\":\"")
        .nth(1)
        .and_then(|r| r.split('"').next())
        .unwrap_or("")
        .to_string();

    // Write failures are ignored throughout: several cases make the client
    // hang up mid-response on purpose.
    let _ = match model.as_str() {
        // Connection closed with no bytes written at all → reqwest `send()`
        // fails → `LlmFailure::Network`.
        "mock-abort" => return,
        // Accepted, request fully read, nothing ever written → the exchange
        // timeout wrapper is the only thing that can end this.
        "mock-stall" => {
            stall_signal().add_permits(1);
            std::future::pending::<()>().await
        }
        "mock-429" => write_simple(&mut stream, 429, "Too Many Requests", "{}").await,
        "mock-500" => {
            write_simple(&mut stream, 500, "Internal Server Error", "upstream boom").await
        }
        "mock-badjson" => write_simple(&mut stream, 200, "OK", "this is not JSON at all").await,
        "mock-huge" => write_oversized(&mut stream).await,
        // Default: a valid native-Ollama completion.
        _ => {
            write_simple(
                &mut stream,
                200,
                "OK",
                r#"{"message":{"role":"assistant","content":"OK"},"done":true,
                    "done_reason":"stop","prompt_eval_count":3,"eval_count":1}"#,
            )
            .await
        }
    };
}

async fn write_simple(stream: &mut tokio::net::TcpStream, code: u16, reason: &str, body: &str) {
    let resp = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(resp.as_bytes()).await;
    let _ = stream.flush().await;
}

/// Stream more than `MAX_LLM_BODY_BYTES` (10 MiB) so the bounded reader aborts.
async fn write_oversized(stream: &mut tokio::net::TcpStream) {
    let total = super::MAX_LLM_BODY_BYTES + 1024 * 1024;
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
         Content-Length: {total}\r\nConnection: close\r\n\r\n"
    );
    if stream.write_all(head.as_bytes()).await.is_err() {
        return;
    }
    let filler = vec![b'x'; 256 * 1024];
    let mut sent = 0usize;
    while sent < total {
        let n = filler.len().min(total - sent);
        if stream.write_all(&filler[..n]).await.is_err() {
            return; // client hung up after hitting the cap — expected
        }
        sent += n;
    }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn context_with_metrics(tier: LlmTier) -> TalosContext {
    init_telemetry_for_tests();
    let mut ctx = TalosContext::new(
        CapabilityWorld::Minimal,
        vec![],
        vec![],
        128,
        HashMap::new(),
        None,
        None,
        false,
        None,
        Arc::new(crate::expose_fallback::ExposeFallback::new()),
        tier,
        None,
    )
    .expect("context builds");
    ctx.set_metrics(Arc::new(RuntimeMetrics::new()));
    ctx
}

fn request(provider: wit_llm::Provider, model: &str) -> wit_llm::CompletionRequest {
    wit_llm::CompletionRequest {
        messages: vec![wit_llm::Message {
            role: wit_llm::Role::User,
            content: "ping".to_string(),
        }],
        model: Some(model.to_string()),
        provider: Some(provider),
        max_tokens: Some(16),
        temperature: None,
        system_prompt: None,
    }
}

/// Read one `wasm_llm_failures_total{provider,outcome}` series out of the
/// rendered exposition. `None` means the series is absent, which is a
/// different thing from 0 and is asserted as such in the seeding test.
fn failure_count(provider: &str, outcome: LlmFailure) -> Option<u64> {
    let needle_a = format!("provider=\"{provider}\"");
    let needle_b = format!("outcome=\"{}\"", outcome.label());
    get_prometheus_metrics()
        .lines()
        .filter(|l| l.starts_with("wasm_llm_failures_total{"))
        .find(|l| l.contains(&needle_a) && l.contains(&needle_b))
        .and_then(|l| l.rsplit(' ').next().map(str::to_string))
        .and_then(|v| v.parse::<f64>().ok())
        .map(|v| v as u64)
}

/// Drive `wit_llm::Host::complete` — the guest-facing entry point — and assert
/// that exactly the expected `(provider, outcome)` series advanced by one.
///
/// Delta-based rather than absolute: the counter is process-global and other
/// tests in this binary share it. Each case below uses a DISTINCT
/// `(provider, outcome)` pair, so the deltas cannot collide even if the
/// harness stops serializing them.
fn assert_complete_fails_with(
    tier: LlmTier,
    provider: wit_llm::Provider,
    model: &str,
    expected: LlmFailure,
) -> wit_llm::Error {
    let _g = guard();
    let label = llm_provider_label(provider);
    rt().block_on(async move {
        ensure_mock_provider().await;
        let before = failure_count(label, expected).unwrap_or(0);

        let mut ctx = context_with_metrics(tier);
        let err = <TalosContext as wit_llm::Host>::complete(&mut ctx, request(provider, model))
            .await
            .expect_err("this case must not return a completion");

        let after = failure_count(label, expected).unwrap_or_else(|| {
            panic!("no wasm_llm_failures_total series for {label}/{expected:?}")
        });
        assert_eq!(
            after,
            before + 1,
            "wasm_llm_failures_total{{provider=\"{label}\",outcome=\"{}\"}} \
             did not advance by 1 ({before} -> {after}). Before 2026-08-14 EVERY \
             failure exit incremented nothing at all; this is the regression that \
             re-opens.",
            expected.label()
        );
        err
    })
}

// ---------------------------------------------------------------------------
// One case per production exit
// ---------------------------------------------------------------------------

#[test]
fn the_mock_provider_is_actually_where_requests_go() {
    // Guards every other case in this file. `ollama_base_url()` latches the
    // first read of OLLAMA_URL for the process; if some other test in this
    // binary reads it first, the redirect below is silently ignored and every
    // "network failure" case would be passing for the wrong reason — against a
    // real endpoint that happens to be absent.
    let _g = guard();
    rt().block_on(async {
        ensure_mock_provider().await;
        let base = super::ollama_base_url();
        assert!(
            base.starts_with("http://127.0.0.1:"),
            "OLLAMA_URL redirect did not take effect (base = {base}); the OnceLock \
             was latched before this test ran and the cases below are not \
             exercising the mock"
        );

        let served_before = REQUESTS_SERVED.load(Ordering::Relaxed);
        let mut ctx = context_with_metrics(LlmTier::Tier1);
        let ok = <TalosContext as wit_llm::Host>::complete(
            &mut ctx,
            request(wit_llm::Provider::Ollama, "mock-ok"),
        )
        .await
        .expect("the happy path must still work through the refactor");
        assert_eq!(ok.text, "OK");
        assert!(
            REQUESTS_SERVED.load(Ordering::Relaxed) > served_before,
            "the mock served no request; the completion resolved from somewhere else"
        );
    });
}

#[test]
fn a_cancelled_execution_is_counted_before_any_request() {
    let _g = guard();
    let label = llm_provider_label(wit_llm::Provider::Ollama);
    rt().block_on(async {
        ensure_mock_provider().await;
        let before = failure_count(label, LlmFailure::Cancelled).unwrap_or(0);
        let served_before = REQUESTS_SERVED.load(Ordering::Relaxed);

        let mut ctx = context_with_metrics(LlmTier::Tier1);
        ctx.cancelled
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let err = <TalosContext as wit_llm::Host>::complete(
            &mut ctx,
            request(wit_llm::Provider::Ollama, "mock-ok"),
        )
        .await
        .expect_err("a cancelled execution must not complete");

        assert!(matches!(err, wit_llm::Error::BudgetExhausted));
        assert_eq!(
            failure_count(label, LlmFailure::Cancelled).unwrap_or(0),
            before + 1,
            "the pre-flight cancellation exit is the FIRST early return in \
             complete_impl and the easiest one to leave uncounted"
        );
        assert_eq!(
            REQUESTS_SERVED.load(Ordering::Relaxed),
            served_before,
            "cancellation must short-circuit before the provider is contacted"
        );
    });
}

#[test]
fn a_tier1_ceiling_refusing_an_external_provider_is_counted() {
    // Reaches `NotConfigured` without touching process env: `get_llm_api_key`
    // returns `None` for a tier refusal exactly as it does for a missing key,
    // and `complete_inner` cannot tell them apart. Asserting through the tier
    // gate keeps the case deterministic regardless of whether the developer
    // running it has ANTHROPIC_API_KEY exported.
    let err = assert_complete_fails_with(
        LlmTier::Tier1,
        wit_llm::Provider::Anthropic,
        "claude-sonnet-4-20250514",
        LlmFailure::NotConfigured,
    );
    assert!(matches!(err, wit_llm::Error::NotConfigured(_)));
}

#[test]
fn a_dropped_connection_is_counted_as_network() {
    let err = assert_complete_fails_with(
        LlmTier::Tier1,
        wit_llm::Provider::Ollama,
        "mock-abort",
        LlmFailure::Network,
    );
    assert!(matches!(err, wit_llm::Error::ApiError(_)));
}

#[test]
fn http_429_is_counted_as_rate_limited_not_http_status() {
    let err = assert_complete_fails_with(
        LlmTier::Tier1,
        wit_llm::Provider::Ollama,
        "mock-429",
        LlmFailure::RateLimited,
    );
    assert!(
        matches!(err, wit_llm::Error::RateLimited),
        "429 has its own early return above the generic non-2xx branch"
    );
}

#[test]
fn a_non_2xx_status_is_counted_as_http_status() {
    let err = assert_complete_fails_with(
        LlmTier::Tier1,
        wit_llm::Provider::Ollama,
        "mock-500",
        LlmFailure::HttpStatus,
    );
    match err {
        wit_llm::Error::ApiError(m) => {
            assert!(
                m.contains("HTTP 500"),
                "the guest-visible message must keep naming the status: {m}"
            );
            assert!(
                !m.contains("upstream boom"),
                "the provider's response body must never reach the guest error \
                 (or, by extension, a metric label): {m}"
            );
        }
        other => panic!("expected ApiError, got {other:?}"),
    }
}

#[test]
fn an_unparseable_200_is_counted_as_decode() {
    let err = assert_complete_fails_with(
        LlmTier::Tier1,
        wit_llm::Provider::Ollama,
        "mock-badjson",
        LlmFailure::Decode,
    );
    assert!(matches!(err, wit_llm::Error::ApiError(_)));
}

#[test]
fn a_body_over_the_cap_is_counted_as_oversized_response() {
    let err = assert_complete_fails_with(
        LlmTier::Tier1,
        wit_llm::Provider::Ollama,
        "mock-huge",
        LlmFailure::OversizedResponse,
    );
    match err {
        wit_llm::Error::ApiError(m) => assert!(m.contains("exceeded"), "unexpected message: {m}"),
        other => panic!("expected ApiError, got {other:?}"),
    }
}

#[test]
fn a_stalled_exchange_is_counted_as_timeout() {
    // The one case that manipulates the clock. The order is what makes it
    // deterministic: the mock signals only AFTER it has read the complete
    // request, so by the time time is paused the TCP connection is established
    // and reqwest's 5 s connect timer is long gone. The 60 s exchange timeout
    // is then the only armed timer, so advancing past it can only fire the
    // exit under test.
    let _g = guard();
    let label = llm_provider_label(wit_llm::Provider::Ollama);
    rt().block_on(async {
        ensure_mock_provider().await;
        let before = failure_count(label, LlmFailure::Timeout).unwrap_or(0);

        let mut ctx = context_with_metrics(LlmTier::Tier1);
        let fut = <TalosContext as wit_llm::Host>::complete(
            &mut ctx,
            request(wit_llm::Provider::Ollama, "mock-stall"),
        );
        tokio::pin!(fut);

        tokio::select! {
            r = &mut fut => panic!("returned before the provider even read the request: {r:?}"),
            p = stall_signal().acquire() => { p.expect("semaphore").forget(); }
        }

        tokio::time::pause();
        tokio::time::advance(std::time::Duration::from_secs(
            super::LOCAL_LLM_EXCHANGE_TIMEOUT_SECS + 1,
        ))
        .await;
        let err = fut.await.expect_err("a stalled exchange must not complete");
        tokio::time::resume();

        assert!(
            matches!(err, wit_llm::Error::Timeout),
            "expected Timeout, got {err:?}"
        );
        assert_eq!(
            failure_count(label, LlmFailure::Timeout).unwrap_or(0),
            before + 1,
            "the timeout wrapper sits OUTSIDE the async block, so its error is \
             the one most easily left unclassified"
        );
    });
}

// ---------------------------------------------------------------------------
// Label hygiene
// ---------------------------------------------------------------------------

#[test]
fn every_outcome_has_a_distinct_stable_label() {
    // Distinct: two outcomes sharing a label would silently merge two failure
    // classes into one series. Stable: these strings are the operator-facing
    // contract and a PromQL selector, so renaming one is a breaking change,
    // not a refactor.
    let labels: Vec<&str> = LlmFailure::ALL.iter().map(|o| o.label()).collect();
    let unique: std::collections::BTreeSet<&str> = labels.iter().copied().collect();
    assert_eq!(
        unique.len(),
        labels.len(),
        "duplicate outcome label: {labels:?}"
    );
    assert_eq!(
        unique,
        [
            "cancelled",
            "decode",
            "http_status",
            "invalid_request",
            "network",
            "not_configured",
            "oversized_response",
            "rate_limited",
            "timeout",
        ]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>()
    );
    // Cheap guard against a label ever being built from a message: every value
    // must be lowercase snake_case and short.
    for l in labels {
        assert!(
            l.len() <= 24 && l.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
            "outcome label `{l}` does not look like a closed-set constant"
        );
    }
}

#[test]
fn provider_labels_cover_the_closed_wit_enum() {
    // If a provider is added to the WIT enum without an arm here, the metric
    // silently starts folding it into `other` — which is exactly the bug this
    // change fixed for `ollama`.
    for p in [
        wit_llm::Provider::Anthropic,
        wit_llm::Provider::Openai,
        wit_llm::Provider::Gemini,
        wit_llm::Provider::Ollama,
    ] {
        let l = llm_provider_label(p);
        assert!(
            LLM_PROVIDER_LABELS.contains(&l),
            "{l} is produced by llm_provider_label but is not in \
             LLM_PROVIDER_LABELS, so it is neither seeded nor expected"
        );
        assert_ne!(
            crate::metrics::normalize_llm_provider(l),
            "other",
            "provider `{l}` reaches complete_impl but normalizes to `other`"
        );
    }
}
