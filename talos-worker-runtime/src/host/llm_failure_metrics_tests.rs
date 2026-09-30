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

use super::{llm_provider_label, wit_llm, wit_llm_streaming, wit_llm_tools, TalosContext};
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

/// Released by `mock-idle` once it has written its first chunk.
fn idle_signal() -> &'static tokio::sync::Semaphore {
    static S: OnceLock<tokio::sync::Semaphore> = OnceLock::new();
    S.get_or_init(|| tokio::sync::Semaphore::new(0))
}

static REQUESTS_SERVED: AtomicU64 = AtomicU64::new(0);

/// Requests the mock received with `"stream":true` in the body. RFC 0014 P1:
/// every local call from both production call sites must ask for a stream.
static STREAMED_REQUESTS: AtomicU64 = AtomicU64::new(0);

/// Permits added by the mock when it has read a full `mock-steady` request.
fn steady_signal() -> &'static tokio::sync::Semaphore {
    static S: OnceLock<tokio::sync::Semaphore> = OnceLock::new();
    S.get_or_init(|| tokio::sync::Semaphore::new(0))
}

/// One permit per `mock-steady` chunk; the test releases them as it advances
/// the paused clock, so the answer's pace is set in VIRTUAL time.
fn steady_release() -> &'static tokio::sync::Semaphore {
    static S: OnceLock<tokio::sync::Semaphore> = OnceLock::new();
    S.get_or_init(|| tokio::sync::Semaphore::new(0))
}

/// Chunks `mock-steady` sends before its `done` line.
const STEADY_CHUNKS: usize = 5;

/// Requests the MOCK currently has in flight, and the high-water mark.
///
/// Server-side, deliberately: the gate's claim is about how many exchanges
/// reach the backend at once, and the only place that can be observed without
/// trusting the code under test is the backend itself.
static MOCK_LIVE: AtomicU64 = AtomicU64::new(0);
static MOCK_PEAK: AtomicU64 = AtomicU64::new(0);

fn note_mock_arrival() {
    let now = MOCK_LIVE.fetch_add(1, Ordering::SeqCst) + 1;
    MOCK_PEAK.fetch_max(now, Ordering::SeqCst);
}

fn note_mock_departure() {
    MOCK_LIVE.fetch_sub(1, Ordering::SeqCst);
}

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
    // A tier-1 call first asks the backend which models run locally
    // (`talos_local_inference::locality`). Answer as Ollama would, listing
    // every mock model as local, and do not count it as a chat request.
    // The loaded context the truncation check reads (`/api/ps`): every mock
    // model is "loaded" with a 4 096-token context.
    if headers.starts_with("get /api/ps") {
        let payload = serde_json::json!({"models": [
            {"name": "mock-truncated:latest", "model": "mock-truncated:latest", "context_length": 4096},
            {"name": "mock-ok:latest", "model": "mock-ok:latest", "context_length": 4096},
        ]})
        .to_string();
        write_simple(&mut stream, 200, "OK", &payload).await;
        return;
    }
    if headers.starts_with("get /api/tags") {
        let names = [
            "mock-429",
            "mock-500",
            "mock-abort",
            "mock-badjson",
            "mock-huge",
            "mock-idle",
            "mock-ok",
            "mock-slow",
            "mock-stall",
            "mock-steady",
            "mock-tool-stream",
            "mock-truncated",
        ];
        let models: Vec<serde_json::Value> = names
            .iter()
            .map(|n| serde_json::json!({"name": format!("{n}:latest"), "model": format!("{n}:latest")}))
            // An alias of an Ollama cloud model: its name does not say
            // "cloud", Ollama's `remote_host` does.
            .chain(std::iter::once(serde_json::json!({
                "name": "mock-cloud-alias:latest",
                "model": "mock-cloud-alias:latest",
                "remote_host": "https://ollama.com",
            })))
            .collect();
        let payload = serde_json::json!({ "models": models }).to_string();
        write_simple(&mut stream, 200, "OK", &payload).await;
        return;
    }
    REQUESTS_SERVED.fetch_add(1, Ordering::Relaxed);

    let body = String::from_utf8_lossy(&buf[header_end..]).to_string();
    let model = body
        .split("\"model\":\"")
        .nth(1)
        .and_then(|r| r.split('"').next())
        .unwrap_or("")
        .to_string();
    if body.contains("\"stream\":true") {
        STREAMED_REQUESTS.fetch_add(1, Ordering::Relaxed);
    }

    // Write failures are ignored throughout: several cases make the client
    // hang up mid-response on purpose.
    match model.as_str() {
        // Connection closed with no bytes written at all → reqwest `send()`
        // fails → `LlmFailure::Network`. Nothing follows this match, so an
        // empty arm drops the stream exactly as a `return` did.
        "mock-abort" => {}
        // Accepted, request fully read, nothing ever written → the exchange
        // timeout wrapper is the only thing that can end this.
        "mock-stall" => {
            stall_signal().add_permits(1);
            std::future::pending::<()>().await
        }
        // One chunk of the answer, then nothing: the IDLE deadline is the only
        // thing that can end this (RFC 0014 P4a).
        "mock-idle" => {
            let _ = stream.write_all(NDJSON_HEAD.as_bytes()).await;
            let _ = stream
                .write_all(content_line("partial", false).as_bytes())
                .await;
            let _ = stream.flush().await;
            idle_signal().add_permits(1);
            std::future::pending::<()>().await
        }
        // Holds the connection open long enough that a SECOND simultaneous
        // request would overlap it, and records the overlap server-side.
        "mock-slow" => {
            note_mock_arrival();
            tokio::time::sleep(std::time::Duration::from_millis(60)).await;
            note_mock_departure();
            write_ndjson(&mut stream, &[ok_line()]).await
        }
        // A steady answer paced by the test in virtual time (see
        // `a_steady_local_answer_longer_than_the_old_total_completes`).
        "mock-steady" => {
            steady_signal().add_permits(1);
            let _ = stream.write_all(NDJSON_HEAD.as_bytes()).await;
            for i in 0..STEADY_CHUNKS {
                steady_release()
                    .acquire()
                    .await
                    .expect("semaphore")
                    .forget();
                let line = content_line(&i.to_string(), false);
                if stream.write_all(line.as_bytes()).await.is_err() {
                    return;
                }
                let _ = stream.flush().await;
            }
            let _ = stream.write_all(done_line().as_bytes()).await;
            let _ = stream.flush().await;
        }
        // A tool call split across streamed lines, as Ollama sends it.
        "mock-tool-stream" => {
            let call = serde_json::json!({
                "message": {"role": "assistant", "content": "", "tool_calls": [
                    {"function": {"name": "noop", "arguments": {"a": 1}}}
                ]},
                "done": false
            });
            write_ndjson(
                &mut stream,
                &[
                    content_line("Calling ", false),
                    content_line("noop.", false),
                    format!("{call}\n"),
                    done_line(),
                ],
            )
            .await
        }
        "mock-429" => write_simple(&mut stream, 429, "Too Many Requests", "{}").await,
        "mock-500" => {
            write_simple(&mut stream, 500, "Internal Server Error", "upstream boom").await
        }
        "mock-badjson" => {
            write_ndjson(&mut stream, &["this is not JSON at all\n".to_string()]).await
        }
        "mock-huge" => write_oversized(&mut stream).await,
        // Default: a valid native-Ollama completion, streamed as one line.
        // Ollama truncated the prompt to fit a 4 096-token context: the
        // evaluated count is the measured signature, context/2 + 2.
        "mock-truncated" => {
            let v = serde_json::json!({
                "message": {"role": "assistant", "content": "an answer without its system prompt"},
                "done": true, "done_reason": "stop",
                "prompt_eval_count": 2050, "eval_count": 8
            });
            write_ndjson(&mut stream, &[format!("{v}\n")]).await
        }
        _ => write_ndjson(&mut stream, &[ok_line()]).await,
    }
}

const NDJSON_HEAD: &str =
    "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nConnection: close\r\n\r\n";

fn content_line(content: &str, done: bool) -> String {
    let v = serde_json::json!({
        "message": {"role": "assistant", "content": content},
        "done": done
    });
    format!("{v}\n")
}

fn done_line() -> String {
    let v = serde_json::json!({
        "message": {"role": "assistant", "content": ""},
        "done": true, "done_reason": "stop",
        "prompt_eval_count": 3, "eval_count": 1
    });
    format!("{v}\n")
}

/// The whole answer in one streamed line, as Ollama sends a short reply.
fn ok_line() -> String {
    let v = serde_json::json!({
        "message": {"role": "assistant", "content": "OK"},
        "done": true, "done_reason": "stop",
        "prompt_eval_count": 3, "eval_count": 1
    });
    format!("{v}\n")
}

/// A streamed (close-delimited) body of JSON lines, as Ollama answers
/// `stream: true`.
async fn write_ndjson(stream: &mut tokio::net::TcpStream, lines: &[String]) {
    let _ = stream.write_all(NDJSON_HEAD.as_bytes()).await;
    for l in lines {
        if stream.write_all(l.as_bytes()).await.is_err() {
            return;
        }
    }
    let _ = stream.flush().await;
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
    context_with_metrics_in_world(tier, CapabilityWorld::Minimal)
}

/// `complete_with_tools` is capability-gated to {Secrets, Database, Agent,
/// Trusted}, so the tools case cannot reuse the `Minimal` fixture.
fn context_with_metrics_in_world(tier: LlmTier, world: CapabilityWorld) -> TalosContext {
    init_telemetry_for_tests();
    let mut ctx = TalosContext::new(
        world,
        vec![],
        ["GET", "POST", "PUT", "PATCH", "DELETE"]
            .iter()
            .map(|s| s.to_string())
            .collect(),
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
    // returns `None` for a tier refusal exactly as it does for a missing key.
    // The metric label is shared; the MESSAGE names the ceiling (see
    // `a_tier1_refusal_names_the_ceiling_not_a_missing_key_on_every_path`).
    // Asserting through the tier gate keeps the case deterministic regardless
    // of whether the developer running it has ANTHROPIC_API_KEY exported.
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
    // exit under test. Since RFC 0014 P1 that timer is the FIRST-BYTE deadline:
    // the mock never writes a byte of the answer.
    let _g = guard();
    let label = llm_provider_label(wit_llm::Provider::Ollama);
    rt().block_on(async {
        ensure_mock_provider().await;
        let before = failure_count(label, LlmFailure::Timeout).unwrap_or(0);

        let mut ctx = context_with_metrics(LlmTier::Tier1);
        let latch = ctx.network_reason_handle();
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
            super::LOCAL_LLM_FIRST_BYTE_TIMEOUT_SECS + 1,
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
        // RFC 0014 P4a: which deadline fired reaches the node failure.
        assert_inference_timeout_marked(
            &latch,
            &err,
            crate::reason_class::INFERENCE_FIRST_BYTE_TIMEOUT,
        );
    });
}

/// The node failure a module builds from `err` — its `Debug`, and the
/// `llm-inference` template's prose — carries `[reason_class=<class>]`.
fn assert_inference_timeout_marked(
    latch: &Arc<std::sync::Mutex<Option<crate::reason_class::Reason>>>,
    err: &wit_llm::Error,
    class: &str,
) {
    let marker = crate::reason_class::marker(class);
    for guest_error in [
        format!("Component returned error: {err:?}"),
        "Component returned error: LLM provider 'ollama' timed out: the host stopped \
         waiting because the response made no progress in time."
            .to_string(),
    ] {
        let suffix = crate::runtime::last_network_reason_suffix(latch, &guest_error);
        assert!(
            suffix.contains(&marker),
            "{guest_error:?} got suffix {suffix:?}, want {marker}"
        );
    }
}

/// RFC 0014 P4a: an exchange that made progress and then stopped is cut at
/// the IDLE deadline and marked as such — the class the retry decision caps
/// at one retry.
#[test]
fn a_stall_after_progress_is_marked_idle() {
    let _g = guard();
    let label = llm_provider_label(wit_llm::Provider::Ollama);
    rt().block_on(async {
        ensure_mock_provider().await;
        let before = failure_count(label, LlmFailure::Timeout).unwrap_or(0);

        let mut ctx = context_with_metrics(LlmTier::Tier1);
        let latch = ctx.network_reason_handle();
        let fut = <TalosContext as wit_llm::Host>::complete(
            &mut ctx,
            request(wit_llm::Provider::Ollama, "mock-idle"),
        );
        tokio::pin!(fut);

        tokio::select! {
            r = &mut fut => panic!("returned before the provider sent its first chunk: {r:?}"),
            p = idle_signal().acquire() => { p.expect("semaphore").forget(); }
        }
        // Let the client read the chunk before time is frozen.
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        tokio::time::pause();
        tokio::time::advance(std::time::Duration::from_secs(
            super::LOCAL_LLM_IDLE_TIMEOUT_SECS + 1,
        ))
        .await;
        let err = fut.await.expect_err("a stalled exchange must not complete");
        tokio::time::resume();

        assert!(matches!(err, wit_llm::Error::Timeout), "{err:?}");
        assert_eq!(
            failure_count(label, LlmFailure::Timeout).unwrap_or(0),
            before + 1
        );
        assert_inference_timeout_marked(&latch, &err, crate::reason_class::INFERENCE_IDLE_TIMEOUT);
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
            "prompt_truncated",
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

// ---------------------------------------------------------------------------
// The local-LLM in-flight gate, driven through the PRODUCTION entry point
// ---------------------------------------------------------------------------
//
// `llm_gate_tests.rs` proves the gate's BEHAVIOUR against its own semaphore.
// It structurally cannot prove that `complete_impl` takes a permit and HOLDS
// it across the exchange — that is a call-site property, and checks 74b/79b
// state exactly this as their own limit: a guard at the primitive cannot see a
// caller that computes the right answer and discards it. So these two cases
// drive `wit_llm::Host::complete` — the method the WASM guest calls — and read
// the peak concurrency out of the MOCK PROVIDER rather than out of the gate.

/// Read one `wasm_llm_gate_total{outcome}` series out of the exposition.
/// `None` means ABSENT, which is a different thing from 0.
fn gate_count(outcome: &str) -> Option<u64> {
    let needle = format!("outcome=\"{outcome}\"");
    get_prometheus_metrics()
        .lines()
        .filter(|l| l.starts_with("wasm_llm_gate_total{"))
        .find(|l| l.contains(&needle))
        .and_then(|l| l.rsplit(' ').next().map(str::to_string))
        .and_then(|v| v.parse::<f64>().ok())
        .map(|v| v as u64)
}

/// Four simultaneous local completions must reach the backend ONE AT A TIME,
/// and the gate counter must move once per call.
///
/// The default cap is `DEFAULT_LOCAL_LLM_MAX_IN_FLIGHT` = 1 and
/// `TALOS_LOCAL_LLM_MAX_IN_FLIGHT` is unset in this binary, so this exercises
/// the shipped configuration rather than a fixture.
#[test]
fn four_concurrent_local_completions_reach_the_backend_one_at_a_time() {
    let _g = guard();
    rt().block_on(async {
        ensure_mock_provider().await;
        MOCK_PEAK.store(0, Ordering::SeqCst);
        MOCK_LIVE.store(0, Ordering::SeqCst);
        let before = gate_count("acquired").unwrap_or(0);

        let mut ctxs: Vec<TalosContext> = (0..4)
            .map(|_| context_with_metrics(LlmTier::Tier1))
            .collect();
        let mut futs = Vec::new();
        for ctx in ctxs.iter_mut() {
            futs.push(<TalosContext as wit_llm::Host>::complete(
                ctx,
                request(wit_llm::Provider::Ollama, "mock-slow"),
            ));
        }
        let results = futures_util::future::join_all(futs).await;
        for r in &results {
            assert!(
                r.is_ok(),
                "the gate must never turn a slow call into a failed one: {r:?}"
            );
        }

        assert_eq!(
            MOCK_PEAK.load(Ordering::SeqCst),
            1,
            "the backend observed more than one simultaneous exchange; the gate \
             is not being held across the exchange"
        );
        assert_eq!(
            gate_count("acquired").unwrap_or(0),
            before + 4,
            "every local call must record a gate outcome"
        );
    });
}

/// THE CONTROL. Without it, `MOCK_PEAK == 1` above is equally consistent with
/// a mock that cannot serve two requests at once or a current-thread runtime
/// that never interleaves them — which is the shape that lets a gate test pass
/// over a gate that does nothing.
///
/// Four RAW requests, bypassing `complete` and therefore the gate, against the
/// same mock in the same runtime, must overlap.
#[test]
fn the_control_the_mock_really_can_serve_two_at_once() {
    let _g = guard();
    rt().block_on(async {
        ensure_mock_provider().await;
        MOCK_PEAK.store(0, Ordering::SeqCst);
        MOCK_LIVE.store(0, Ordering::SeqCst);

        let url = format!("{}/api/chat", super::ollama_base_url());
        let client = super::local_llm_http_client().clone();
        let body = serde_json::json!({
            "model": "mock-slow",
            "messages": [{"role": "user", "content": "ping"}],
            "stream": false
        });
        let mut futs = Vec::new();
        for _ in 0..4 {
            futs.push(client.post(&url).json(&body).send());
        }
        let results = futures_util::future::join_all(futs).await;
        for r in &results {
            assert!(r.is_ok(), "raw control request failed: {r:?}");
        }
        assert!(
            MOCK_PEAK.load(Ordering::SeqCst) > 1,
            "the mock served four ungated requests without ever overlapping, so \
             the serialization assertion above proves nothing"
        );
    });
}

/// The SECOND gated call site: `llm::complete-with-tools`.
///
/// It exists because M8 was a MEASURED SURVIVOR — reverting `llm_tools.rs`'s
/// binding to `let _ =` left all 651 crate tests green while that path went
/// straight back to unbounded concurrency. One test per SITE whose consequence
/// is a real behaviour change, not one per shape.
#[test]
fn the_tool_use_path_is_gated_too() {
    let _g = guard();
    rt().block_on(async {
        ensure_mock_provider().await;
        MOCK_PEAK.store(0, Ordering::SeqCst);
        MOCK_LIVE.store(0, Ordering::SeqCst);

        let tool_req = || wit_llm_tools::ToolCompletionRequest {
            provider: Some(wit_llm_tools::Provider::Ollama),
            model: Some("mock-slow".to_string()),
            messages: vec![wit_llm_tools::RichMessage {
                role: wit_llm_tools::Role::User,
                content: vec![wit_llm_tools::ContentBlock::Text("ping".to_string())],
            }],
            tools: vec![wit_llm_tools::ToolDefinition {
                name: "noop".to_string(),
                description: "does nothing".to_string(),
                input_schema: r#"{"type":"object","properties":{}}"#.to_string(),
            }],
            max_tokens: Some(16),
            temperature: None,
            system_prompt: None,
            force_tool: None,
            response_schema: None,
        };

        let mut ctxs: Vec<TalosContext> = (0..4)
            .map(|_| context_with_metrics_in_world(LlmTier::Tier1, CapabilityWorld::Secrets))
            .collect();
        let mut futs = Vec::new();
        for ctx in ctxs.iter_mut() {
            futs.push(<TalosContext as wit_llm_tools::Host>::complete_with_tools(
                ctx,
                tool_req(),
            ));
        }
        let results = futures_util::future::join_all(futs).await;
        for r in &results {
            assert!(
                r.is_ok(),
                "the gate must never turn a slow tool call into a failed one: {r:?}"
            );
        }
        assert_eq!(
            MOCK_PEAK.load(Ordering::SeqCst),
            1,
            "the backend observed more than one simultaneous tool-use exchange; \
             the llm_tools call site is not holding the permit"
        );
    });
}

// ---------------------------------------------------------------------------
// RFC 0014 P1 — progress-based deadlines, driven through the PRODUCTION path
// ---------------------------------------------------------------------------

/// Both gated call sites must ask Ollama for a stream: a site that stayed
/// non-streaming would still work against the mock (which answers either way)
/// while quietly keeping the old total-deadline behaviour. One call per site.
#[test]
fn local_calls_are_streamed_at_both_call_sites() {
    let _g = guard();
    rt().block_on(async {
        ensure_mock_provider().await;

        let before = STREAMED_REQUESTS.load(Ordering::Relaxed);
        let mut ctx = context_with_metrics(LlmTier::Tier1);
        <TalosContext as wit_llm::Host>::complete(
            &mut ctx,
            request(wit_llm::Provider::Ollama, "mock-ok"),
        )
        .await
        .expect("complete");
        assert_eq!(
            STREAMED_REQUESTS.load(Ordering::Relaxed),
            before + 1,
            "llm::complete sent a non-streaming local request"
        );

        let mut ctx = context_with_metrics_in_world(LlmTier::Tier1, CapabilityWorld::Secrets);
        <TalosContext as wit_llm_tools::Host>::complete_with_tools(
            &mut ctx,
            tool_request("mock-ok"),
        )
        .await
        .expect("complete_with_tools");
        assert_eq!(
            STREAMED_REQUESTS.load(Ordering::Relaxed),
            before + 2,
            "llm-tools::complete-with-tools sent a non-streaming local request"
        );
    });
}

fn tool_request(model: &str) -> wit_llm_tools::ToolCompletionRequest {
    wit_llm_tools::ToolCompletionRequest {
        provider: Some(wit_llm_tools::Provider::Ollama),
        model: Some(model.to_string()),
        messages: vec![wit_llm_tools::RichMessage {
            role: wit_llm_tools::Role::User,
            content: vec![wit_llm_tools::ContentBlock::Text("ping".to_string())],
        }],
        tools: vec![wit_llm_tools::ToolDefinition {
            name: "noop".to_string(),
            description: "does nothing".to_string(),
            input_schema: r#"{"type":"object","properties":{}}"#.to_string(),
        }],
        max_tokens: Some(16),
        temperature: None,
        system_prompt: None,
        force_tool: None,
        response_schema: None,
    }
}

/// THE regression, through the guest-facing entry point. The answer arrives
/// one chunk every 20 s of VIRTUAL time, 100 s in all: every gap is inside the
/// idle deadline, the total is well past the 60 s the old single deadline
/// allowed. Before RFC 0014 P1 this call was cut at 60 s — the 2026-09-28
/// failure of a healthy generation on an otherwise idle backend.
///
/// The clock is advanced by the test, never auto-advanced, so the pace is
/// exact: the mock writes a chunk only when the test releases it.
#[test]
fn a_steady_local_answer_longer_than_the_old_total_completes() {
    let _g = guard();
    rt().block_on(async {
        ensure_mock_provider().await;
        let mut ctx = context_with_metrics(LlmTier::Tier1);
        let fut = <TalosContext as wit_llm::Host>::complete(
            &mut ctx,
            request(wit_llm::Provider::Ollama, "mock-steady"),
        );
        tokio::pin!(fut);

        tokio::select! {
            r = &mut fut => panic!("returned before the provider read the request: {r:?}"),
            p = steady_signal().acquire() => { p.expect("semaphore").forget(); }
        }

        tokio::time::pause();
        let gap = std::time::Duration::from_secs(20);
        let mut elapsed = std::time::Duration::ZERO;
        let driver = async {
            for _ in 0..STEADY_CHUNKS {
                tokio::time::advance(gap).await;
                elapsed += gap;
                steady_release().add_permits(1);
                // Let the chunk cross the loopback and be read before the
                // clock moves again. Real time, not virtual: the bytes travel
                // through the kernel.
                for _ in 0..20 {
                    tokio::task::yield_now().await;
                    std::thread::sleep(std::time::Duration::from_millis(2));
                }
            }
        };
        let (result, ()) = tokio::join!(&mut fut, driver);
        tokio::time::resume();

        assert!(
            elapsed.as_secs() > super::LOCAL_LLM_FIRST_BYTE_TIMEOUT_SECS,
            "the test must outlast the old 60 s total to prove anything"
        );
        assert!(
            gap.as_secs() < super::LOCAL_LLM_IDLE_TIMEOUT_SECS,
            "each gap must be progress within the idle deadline"
        );
        let resp = result.expect("a steady answer must complete, however long it takes");
        assert_eq!(resp.text, "01234");
    });
}

/// RFC 0014 P4a, the tool-calling call site: an idle stall there is marked
/// the same way as on `complete`.
#[test]
fn a_tool_call_stall_after_progress_is_marked_idle() {
    let _g = guard();
    rt().block_on(async {
        ensure_mock_provider().await;
        let mut ctx = context_with_metrics_in_world(LlmTier::Tier1, CapabilityWorld::Secrets);
        let latch = ctx.network_reason_handle();
        let fut = <TalosContext as wit_llm_tools::Host>::complete_with_tools(
            &mut ctx,
            tool_request("mock-idle"),
        );
        tokio::pin!(fut);

        tokio::select! {
            r = &mut fut => panic!("returned before the provider sent its first chunk: {r:?}"),
            p = idle_signal().acquire() => { p.expect("semaphore").forget(); }
        }
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        tokio::time::pause();
        tokio::time::advance(std::time::Duration::from_secs(
            super::LOCAL_LLM_IDLE_TIMEOUT_SECS + 1,
        ))
        .await;
        let err = fut.await.expect_err("a stalled exchange must not complete");
        tokio::time::resume();

        assert!(matches!(err, wit_llm_tools::Error::Timeout), "{err:?}");
        let guest_error = format!("Component returned error: {err:?}");
        let suffix = crate::runtime::last_network_reason_suffix(&latch, &guest_error);
        assert!(
            suffix.contains(&crate::reason_class::marker(
                crate::reason_class::INFERENCE_IDLE_TIMEOUT
            )),
            "{guest_error:?} got {suffix:?}"
        );
    });
}

/// Tool calls arrive in their own streamed line; the reassembled response
/// must hand them to the guest exactly as the non-streaming API did.
#[test]
fn a_streamed_tool_call_reaches_the_guest() {
    let _g = guard();
    rt().block_on(async {
        ensure_mock_provider().await;
        let mut ctx = context_with_metrics_in_world(LlmTier::Tier1, CapabilityWorld::Secrets);
        let resp = <TalosContext as wit_llm_tools::Host>::complete_with_tools(
            &mut ctx,
            tool_request("mock-tool-stream"),
        )
        .await
        .expect("streamed tool call");

        let mut text = String::new();
        let mut calls = Vec::new();
        for block in &resp.content {
            match block {
                wit_llm_tools::ContentBlock::Text(t) => text.push_str(t),
                wit_llm_tools::ContentBlock::ToolUse(c) => calls.push(c),
                other => panic!("unexpected block {other:?}"),
            }
        }
        assert_eq!(text, "Calling noop.");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].tool_name, "noop");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&calls[0].arguments).unwrap(),
            serde_json::json!({"a": 1})
        );
        let usage = resp.usage.expect("usage from the done line");
        assert_eq!((usage.input_tokens, usage.output_tokens), (3, 1));
    });
}

// ---------------------------------------------------------------------------
// RFC 0014 P2 — a queued call records its wait on the JOB's ledger, at both
// production call sites
// ---------------------------------------------------------------------------

#[derive(Default)]
struct HeardWaits {
    waiting: AtomicU64,
    admitted: AtomicU64,
}

impl crate::inference_wait::WaitNotifier for HeardWaits {
    fn notify(
        &self,
        state: talos_workflow_job_protocol::JobProgressState,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        match state {
            talos_workflow_job_protocol::JobProgressState::Waiting => {
                self.waiting.fetch_add(1, Ordering::SeqCst)
            }
            talos_workflow_job_protocol::JobProgressState::Admitted => {
                self.admitted.fetch_add(1, Ordering::SeqCst)
            }
        };
        Box::pin(async {})
    }
}

fn with_ledger(mut ctx: TalosContext, heard: &Arc<HeardWaits>) -> TalosContext {
    ctx.inference_wait = Some(Arc::new(crate::inference_wait::InferenceWaitLedger::new(
        Some(heard.clone() as Arc<dyn crate::inference_wait::WaitNotifier>),
    )));
    ctx
}

/// Two simultaneous local completions on a cap of 1: exactly ONE of them
/// queues, so exactly one wait is opened and closed across the two jobs'
/// ledgers. A call site that stopped passing `self.inference_wait` to the gate
/// would record none — and the job's deadlines would be charged for its queue.
#[test]
fn a_queued_completion_records_its_wait_on_the_jobs_ledger() {
    let _g = guard();
    rt().block_on(async {
        ensure_mock_provider().await;
        let heard = Arc::new(HeardWaits::default());
        let mut a = with_ledger(context_with_metrics(LlmTier::Tier1), &heard);
        let mut b = with_ledger(context_with_metrics(LlmTier::Tier1), &heard);
        let (ra, rb) = futures_util::future::join(
            <TalosContext as wit_llm::Host>::complete(
                &mut a,
                request(wit_llm::Provider::Ollama, "mock-slow"),
            ),
            <TalosContext as wit_llm::Host>::complete(
                &mut b,
                request(wit_llm::Provider::Ollama, "mock-slow"),
            ),
        )
        .await;
        assert!(ra.is_ok() && rb.is_ok(), "{ra:?} {rb:?}");
        assert_eq!(
            heard.waiting.load(Ordering::SeqCst),
            1,
            "exactly one call queued"
        );
        assert_eq!(heard.admitted.load(Ordering::SeqCst), 1);
        let waited: Vec<_> = [&a, &b]
            .iter()
            .map(|c| c.inference_wait.as_ref().unwrap().excluded())
            .collect();
        assert_eq!(
            waited.iter().filter(|w| !w.is_zero()).count(),
            1,
            "the queued job's ledger excludes its wait, the other's excludes nothing: {waited:?}"
        );
    });
}

/// The same property at the SECOND call site, `llm-tools::complete-with-tools`.
#[test]
fn a_queued_tool_completion_records_its_wait_on_the_jobs_ledger() {
    let _g = guard();
    rt().block_on(async {
        ensure_mock_provider().await;
        let heard = Arc::new(HeardWaits::default());
        let mut a = with_ledger(
            context_with_metrics_in_world(LlmTier::Tier1, CapabilityWorld::Secrets),
            &heard,
        );
        let mut b = with_ledger(
            context_with_metrics_in_world(LlmTier::Tier1, CapabilityWorld::Secrets),
            &heard,
        );
        let (ra, rb) = futures_util::future::join(
            <TalosContext as wit_llm_tools::Host>::complete_with_tools(
                &mut a,
                tool_request("mock-slow"),
            ),
            <TalosContext as wit_llm_tools::Host>::complete_with_tools(
                &mut b,
                tool_request("mock-slow"),
            ),
        )
        .await;
        assert!(ra.is_ok() && rb.is_ok(), "{ra:?} {rb:?}");
        assert_eq!(
            heard.waiting.load(Ordering::SeqCst),
            1,
            "exactly one call queued"
        );
        assert_eq!(heard.admitted.load(Ordering::SeqCst), 1);
    });
}

// ---------------------------------------------------------------------------
// Tier-1 local calls must reach a model that runs on this host
// ---------------------------------------------------------------------------

fn stream_request(model: &str) -> wit_llm_streaming::StreamRequest {
    wit_llm_streaming::StreamRequest {
        provider: Some("ollama".to_string()),
        model: Some(model.to_string()),
        messages_json: r#"[{"role":"user","content":[{"type":"text","text":"ping"}]}]"#.to_string(),
        max_tokens: Some(16),
        temperature: None,
        system_prompt: None,
    }
}

fn stream_tool_request(model: &str) -> wit_llm_streaming::StreamToolRequest {
    wit_llm_streaming::StreamToolRequest {
        provider: Some("ollama".to_string()),
        model: Some(model.to_string()),
        messages_json: r#"[{"role":"user","content":[{"type":"text","text":"ping"}]}]"#
            .to_string(),
        tools_json: r#"[{"name":"noop","description":"does nothing","input_schema":{"type":"object","properties":{}}}]"#
            .to_string(),
        max_tokens: Some(16),
        temperature: None,
        system_prompt: None,
    }
}

/// Drive every worker path to the local Ollama for `model` under `tier` and
/// return, per surface, `None` when the call was admitted or the refusal text.
/// Each surface is a separate call site; a guard at the shared helper cannot
/// see whether one of them stopped calling it.
async fn local_call_outcomes(tier: LlmTier, model: &str) -> Vec<(&'static str, Option<String>)> {
    let refused = |e: String| -> Option<String> { Some(e) };
    let mut out = Vec::new();

    let mut ctx = context_with_metrics(tier);
    out.push((
        "complete",
        match <TalosContext as wit_llm::Host>::complete(
            &mut ctx,
            request(wit_llm::Provider::Ollama, model),
        )
        .await
        {
            Err(wit_llm::Error::NotConfigured(m)) => refused(m),
            _ => None,
        },
    ));

    let mut ctx = context_with_metrics_in_world(tier, CapabilityWorld::Agent);
    out.push((
        "complete-with-tools",
        match <TalosContext as wit_llm_tools::Host>::complete_with_tools(
            &mut ctx,
            tool_request(model),
        )
        .await
        {
            Err(wit_llm_tools::Error::NotConfigured(m)) => refused(m),
            _ => None,
        },
    ));

    let mut ctx = context_with_metrics_in_world(tier, CapabilityWorld::Agent);
    out.push((
        "start-stream",
        match <TalosContext as wit_llm_streaming::Host>::start_stream(
            &mut ctx,
            stream_request(model),
        )
        .await
        {
            Err(wit_llm_streaming::Error::NotConfigured(m)) => refused(m),
            _ => None,
        },
    ));

    let mut ctx = context_with_metrics_in_world(tier, CapabilityWorld::Agent);
    out.push((
        "start-tool-stream",
        match <TalosContext as wit_llm_streaming::Host>::start_tool_stream(
            &mut ctx,
            stream_tool_request(model),
        )
        .await
        {
            Err(wit_llm_streaming::Error::NotConfigured(m)) => refused(m),
            _ => None,
        },
    ));
    out
}

/// An Ollama cloud model forwards the prompt off the host. A tier-1 actor must
/// never reach one — by its cloud tag, by an alias Ollama marks remote, or by
/// a name the local listing does not contain — on ANY of the four paths, and
/// nothing may be sent to the backend.
#[test]
fn a_tier1_call_to_a_model_not_proven_local_is_refused_on_every_path() {
    let _g = guard();
    rt().block_on(async {
        ensure_mock_provider().await;
        for (model, expect) in [
            ("glm-5.3-flash:cloud", "not on this host"),
            ("mock-cloud-alias", "https://ollama.com"),
            ("never-pulled", "not in the local Ollama's model list"),
        ] {
            let served_before = REQUESTS_SERVED.load(Ordering::Relaxed);
            for (surface, outcome) in local_call_outcomes(LlmTier::Tier1, model).await {
                let msg = outcome.unwrap_or_else(|| panic!("{surface}: {model} was admitted"));
                assert!(msg.contains(expect), "{surface}/{model}: {msg}");
                assert!(msg.contains("tier1"), "{surface}/{model}: {msg}");
            }
            assert_eq!(
                REQUESTS_SERVED.load(Ordering::Relaxed),
                served_before,
                "{model} reached the backend"
            );
        }
    });
}

/// Controls. A model the listing marks local is admitted on every path under
/// tier-1, and a cloud model is admitted under tier-2 (it is an external
/// provider there, which that ceiling allows) — so the refusals above are the
/// ceiling and the listing talking, not a blanket refusal.
#[test]
fn a_local_model_under_tier1_and_a_cloud_model_under_tier2_are_admitted() {
    let _g = guard();
    rt().block_on(async {
        ensure_mock_provider().await;
        for (tier, model) in [
            (LlmTier::Tier1, "mock-ok"),
            (LlmTier::Tier2, "glm-5.3-flash:cloud"),
            (LlmTier::Tier2, "mock-cloud-alias"),
        ] {
            for (surface, outcome) in local_call_outcomes(tier, model).await {
                assert!(
                    outcome.is_none(),
                    "{surface}: {model} under {tier:?} was refused: {outcome:?}"
                );
            }
        }
    });
}

/// The pure halves of `admit_local_model`: which ceilings need proof, and what
/// each locality answer means. An unreadable listing is a refusal (a gate that
/// cannot read its rule must not grant) and only `Local` is admitted.
#[test]
fn the_local_model_decision_admits_only_proven_local() {
    use super::{ceiling_requires_local_model, local_model_refusal, LocalModelRefusal};
    use talos_local_inference::locality::{LocalityUnreadable, ModelLocality};

    assert!(ceiling_requires_local_model(LlmTier::Tier1));
    assert!(!ceiling_requires_local_model(LlmTier::Tier2));

    assert_eq!(local_model_refusal(Ok(ModelLocality::Local)), None);
    assert_eq!(
        local_model_refusal(Ok(ModelLocality::Remote {
            host: "https://ollama.com".into()
        })),
        Some(LocalModelRefusal::Remote {
            host: "https://ollama.com".into()
        })
    );
    assert_eq!(
        local_model_refusal(Ok(ModelLocality::Unlisted)),
        Some(LocalModelRefusal::Unlisted)
    );
    let unreadable = local_model_refusal(Err(LocalityUnreadable("status 500".into())));
    assert_eq!(
        unreadable,
        Some(LocalModelRefusal::Unreadable("status 500".into()))
    );

    // Policy vocabulary operators filter on.
    assert_eq!(
        LocalModelRefusal::Remote { host: "h".into() }.policy(),
        "tier1-llm-egress"
    );
    assert_eq!(
        LocalModelRefusal::Unlisted.policy(),
        "tier1-llm-locality-unverified"
    );
    // A guest-supplied model name is bounded in what reaches the ledger/log.
    let long = "m".repeat(10_000);
    assert!(LocalModelRefusal::Unlisted.message(&long).len() < 1_000);
}

// ---------------------------------------------------------------------------
// A refused external provider names the ceiling, not a missing key
// ---------------------------------------------------------------------------

/// A tier-1 actor calling Anthropic is refused by its ceiling. Every path must
/// SAY so: until 2026-09-30 each one answered "LLM API key not configured. Set
/// vault path `anthropic/api_key`", the one remedy that must not be taken.
/// Driven through all four WIT entry points (each renders the message at its
/// own call site). Deterministic: a ceiling refusal resolves no key, so an
/// exported ANTHROPIC_API_KEY cannot change the answer.
#[test]
fn a_tier1_refusal_names_the_ceiling_not_a_missing_key_on_every_path() {
    let _g = guard();
    rt().block_on(async {
        let mut msgs: Vec<(&str, String)> = Vec::new();

        let mut ctx = context_with_metrics(LlmTier::Tier1);
        match <TalosContext as wit_llm::Host>::complete(
            &mut ctx,
            request(wit_llm::Provider::Anthropic, "claude-sonnet-4-20250514"),
        )
        .await
        {
            Err(wit_llm::Error::NotConfigured(m)) => msgs.push(("complete", m)),
            other => panic!("complete: {other:?}"),
        }

        let mut ctx = context_with_metrics_in_world(LlmTier::Tier1, CapabilityWorld::Agent);
        let mut req = tool_request("claude-sonnet-4-20250514");
        req.provider = Some(wit_llm_tools::Provider::Anthropic);
        match <TalosContext as wit_llm_tools::Host>::complete_with_tools(&mut ctx, req).await {
            Err(wit_llm_tools::Error::NotConfigured(m)) => msgs.push(("complete-with-tools", m)),
            other => panic!("complete-with-tools: {other:?}"),
        }

        let mut ctx = context_with_metrics_in_world(LlmTier::Tier1, CapabilityWorld::Agent);
        let mut req = stream_request("claude-sonnet-4-20250514");
        req.provider = Some("anthropic".to_string());
        match <TalosContext as wit_llm_streaming::Host>::start_stream(&mut ctx, req).await {
            Err(wit_llm_streaming::Error::NotConfigured(m)) => msgs.push(("start-stream", m)),
            other => panic!("start-stream: {other:?}"),
        }

        let mut ctx = context_with_metrics_in_world(LlmTier::Tier1, CapabilityWorld::Agent);
        let mut req = stream_tool_request("claude-sonnet-4-20250514");
        req.provider = Some("anthropic".to_string());
        match <TalosContext as wit_llm_streaming::Host>::start_tool_stream(&mut ctx, req).await {
            Err(wit_llm_streaming::Error::NotConfigured(m)) => msgs.push(("start-tool-stream", m)),
            other => panic!("start-tool-stream: {other:?}"),
        }

        for (surface, m) in msgs {
            assert!(m.contains("max_llm_tier is tier1"), "{surface}: {m}");
            assert!(m.contains("set_actor_llm_tier_ceiling"), "{surface}: {m}");
            assert!(
                !m.contains("Set vault path"),
                "{surface} advises a key: {m}"
            );
        }
    });
}

/// The two reasons, decided by the same pure ceiling rule the key lookup
/// uses. The tier-2 case is the missing-key sentence, naming the provider's
/// vault path and env var.
#[test]
fn a_missing_key_and_a_ceiling_refusal_are_told_apart() {
    use super::LlmKeyUnavailable;
    assert_eq!(
        LlmKeyUnavailable::classify("Anthropic", LlmTier::Tier1),
        LlmKeyUnavailable::CeilingRefused {
            provider: "anthropic".into()
        }
    );
    let missing = LlmKeyUnavailable::classify("openai", LlmTier::Tier2);
    assert_eq!(
        missing,
        LlmKeyUnavailable::Missing {
            vault_path: "openai/api_key",
            env_name: "OPENAI_API_KEY",
        }
    );
    let m = missing.message();
    assert!(
        m.contains("Set vault path `openai/api_key`") && m.contains("OPENAI_API_KEY"),
        "{m}"
    );
    assert!(!m.contains("tier1"), "{m}");
}

/// Ollama truncated the prompt to fit the loaded context (the measured
/// signature, context/2 + 2 evaluated tokens): the answer is refused, the
/// guest gets `invalid-request` naming the counts, and
/// `wasm_llm_failures_total{outcome="prompt_truncated"}` moves exactly once.
#[test]
fn an_answer_to_a_truncated_prompt_is_refused_and_counted() {
    let err = assert_complete_fails_with(
        LlmTier::Tier1,
        wit_llm::Provider::Ollama,
        "mock-truncated",
        LlmFailure::PromptTruncated,
    );
    match err {
        wit_llm::Error::InvalidRequest(m) => {
            assert!(
                m.contains("truncated the prompt") && m.contains("4096"),
                "{m}"
            )
        }
        other => panic!("expected invalid-request, got {other:?}"),
    }
}

/// The tools path has its own call site; it refuses a truncated prompt too.
#[test]
fn a_tool_call_answer_to_a_truncated_prompt_is_refused() {
    let _g = guard();
    rt().block_on(async {
        ensure_mock_provider().await;
        let mut ctx = context_with_metrics_in_world(LlmTier::Tier1, CapabilityWorld::Agent);
        match <TalosContext as wit_llm_tools::Host>::complete_with_tools(
            &mut ctx,
            tool_request("mock-truncated"),
        )
        .await
        {
            Err(wit_llm_tools::Error::InvalidRequest(m)) => {
                assert!(m.contains("truncated the prompt"), "{m}")
            }
            other => panic!("expected invalid-request, got {other:?}"),
        }
    });
}
