//! `OllamaClient::chat` against a loopback Ollama — RFC 0014 P3a.
//!
//! What these prove, each against the PRODUCTION `complete*` methods:
//!
//! * the request streams and the answer is reassembled (a non-streaming
//!   client would send `stream: false` and fail to parse the NDJSON reply);
//! * an answer that keeps making progress outlives the client-wide timeout,
//!   i.e. the per-request backstop really overrides it;
//! * an answer that stops making progress is cut at the idle deadline;
//! * an HTTP 400 still reads as `HTTP 400`, so the `think` retry still works;
//! * two calls on one client reach the backend one at a time (the gate), with
//!   a control proving the mock can serve two at once.
//!
//! The deadlines run at millisecond scale through `OllamaClient::for_tests`;
//! production uses `ProgressDeadlines::LOCAL`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use talos_local_inference::stream::ProgressDeadlines;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::OllamaClient;

struct Reply {
    status: u16,
    /// Each chunk is written after its delay.
    chunks: Vec<(Duration, String)>,
}

#[derive(Default)]
struct Seen {
    requests: AtomicUsize,
    in_flight: AtomicUsize,
    peak: AtomicUsize,
    bodies: Mutex<Vec<Value>>,
}

type Handler = dyn Fn(usize, &Value) -> Reply + Send + Sync;

async fn read_request(sock: &mut TcpStream) -> Value {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    let header_end = loop {
        let n = sock.read(&mut tmp).await.unwrap();
        assert!(n > 0, "client closed before sending a request");
        buf.extend_from_slice(&tmp[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_ascii_lowercase();
    let len: usize = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .map(|v| v.trim().parse().unwrap())
        .unwrap_or(0);
    while buf.len() < header_end + len {
        let n = sock.read(&mut tmp).await.unwrap();
        assert!(n > 0);
        buf.extend_from_slice(&tmp[..n]);
    }
    serde_json::from_slice(&buf[header_end..header_end + len]).unwrap_or(Value::Null)
}

async fn serve(handler: Arc<Handler>) -> (String, Arc<Seen>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Seen::default());
    let s = seen.clone();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = listener.accept().await.unwrap();
            let handler = handler.clone();
            let seen = s.clone();
            tokio::spawn(async move {
                let body = read_request(&mut sock).await;
                let idx = seen.requests.fetch_add(1, Ordering::SeqCst);
                let now = seen.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                seen.peak.fetch_max(now, Ordering::SeqCst);
                seen.bodies.lock().unwrap().push(body.clone());
                let reply = handler(idx, &body);
                let head = format!(
                    "HTTP/1.1 {} X\r\nContent-Type: application/x-ndjson\r\nConnection: close\r\n\r\n",
                    reply.status
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let last = reply.chunks.len().saturating_sub(1);
                let mut released = false;
                for (i, (delay, chunk)) in reply.chunks.into_iter().enumerate() {
                    tokio::time::sleep(delay).await;
                    // Leave the in-flight count BEFORE the last chunk: the
                    // client can only finish (and release its slot) after
                    // reading it, so the next request is ordered after this.
                    if i == last {
                        seen.in_flight.fetch_sub(1, Ordering::SeqCst);
                        released = true;
                    }
                    if sock.write_all(chunk.as_bytes()).await.is_err() {
                        break;
                    }
                    let _ = sock.flush().await;
                }
                if !released {
                    seen.in_flight.fetch_sub(1, Ordering::SeqCst);
                }
                let _ = sock.shutdown().await;
            });
        }
    });
    (format!("http://{addr}"), seen)
}

fn chunk(content: &str) -> String {
    format!(
        "{}\n",
        json!({"model": "m", "message": {"role": "assistant", "content": content}, "done": false})
    )
}

fn done() -> String {
    format!(
        "{}\n",
        json!({"model": "m", "message": {"role": "assistant", "content": ""},
               "done": true, "done_reason": "stop", "prompt_eval_count": 7, "eval_count": 3})
    )
}

fn streamed(parts: &[&str], gap: Duration) -> Reply {
    let mut chunks: Vec<(Duration, String)> = parts.iter().map(|p| (gap, chunk(p))).collect();
    chunks.push((gap, done()));
    Reply {
        status: 200,
        chunks,
    }
}

const MS_DEADLINES: ProgressDeadlines = ProgressDeadlines {
    first_byte: Duration::from_secs(1),
    idle: Duration::from_secs(1),
    ceiling: Duration::from_secs(10),
};

fn client(base: String, client_timeout: Duration, deadlines: ProgressDeadlines) -> OllamaClient {
    OllamaClient::for_tests(
        base,
        client_timeout,
        deadlines,
        deadlines.ceiling + Duration::from_secs(1),
    )
}

#[tokio::test]
async fn a_chat_streams_and_is_reassembled() {
    let (base, seen) = serve(Arc::new(|_, _| {
        streamed(&["  hel", "lo ", "world  "], Duration::ZERO)
    }))
    .await;
    let c = client(base, Duration::from_secs(10), MS_DEADLINES);
    let text = c.complete("m", "sys", "user", 64).await.unwrap();
    assert_eq!(text, "hello world");
    let bodies = seen.bodies.lock().unwrap();
    assert_eq!(
        bodies[0]["stream"], true,
        "the transport must ask to stream"
    );
    assert_eq!(bodies[0]["options"]["num_predict"], 64);
}

/// The client-wide timeout stands in for the production 60 s. An answer that
/// takes longer in total but keeps making progress must complete.
#[tokio::test]
async fn an_answer_that_keeps_progressing_outlives_the_client_wide_timeout() {
    let (base, _) = serve(Arc::new(|_, _| {
        streamed(
            &["a", "b", "c", "d", "e", "f", "g", "h"],
            Duration::from_millis(100),
        )
    }))
    .await;
    let c = client(base, Duration::from_millis(300), MS_DEADLINES);
    let text = c.complete("m", "", "user", 64).await.unwrap();
    assert_eq!(text, "abcdefgh");
}

#[tokio::test]
async fn an_answer_that_stops_progressing_is_cut_at_the_idle_deadline() {
    let (base, _) = serve(Arc::new(|_, _| Reply {
        status: 200,
        chunks: vec![
            (Duration::ZERO, chunk("partial")),
            (Duration::from_secs(30), done()),
        ],
    }))
    .await;
    let deadlines = ProgressDeadlines {
        idle: Duration::from_millis(200),
        ..MS_DEADLINES
    };
    let c = client(base, Duration::from_secs(60), deadlines);
    let started = std::time::Instant::now();
    let err = c.complete("m", "", "user", 64).await.unwrap_err();
    assert!(
        err.to_string().contains("idle deadline"),
        "unexpected error: {err}"
    );
    assert!(started.elapsed() < Duration::from_secs(10));
}

/// `complete_structured` retries without `think` on exactly `HTTP 400`; the
/// streamed transport must keep that wording.
#[tokio::test]
async fn an_http_400_still_triggers_the_think_retry() {
    let (base, seen) = serve(Arc::new(|idx, _| {
        if idx == 0 {
            Reply {
                status: 400,
                chunks: vec![(Duration::ZERO, "{\"error\":\"think not supported\"}".into())],
            }
        } else {
            streamed(&["{\"ok\":true}"], Duration::ZERO)
        }
    }))
    .await;
    let c = client(base, Duration::from_secs(10), MS_DEADLINES);
    let text = c.complete_structured("m", "", "user", 64).await.unwrap();
    assert_eq!(text, "{\"ok\":true}");
    let bodies = seen.bodies.lock().unwrap();
    assert_eq!(bodies.len(), 2);
    assert_eq!(bodies[0]["think"], false);
    assert!(bodies[1].get("think").is_none());
    assert_eq!(bodies[1]["format"], "json");
}

/// The gate: two calls on one client reach the backend one at a time.
#[tokio::test]
async fn two_calls_reach_the_backend_one_at_a_time() {
    let (base, seen) = serve(Arc::new(|_, _| {
        streamed(&["x"], Duration::from_millis(150))
    }))
    .await;
    let c = Arc::new(client(base, Duration::from_secs(10), MS_DEADLINES));
    let (a, b) = tokio::join!(c.complete("m", "", "one", 8), c.complete("m", "", "two", 8));
    assert_eq!(a.unwrap(), "x");
    assert_eq!(b.unwrap(), "x");
    assert_eq!(seen.requests.load(Ordering::SeqCst), 2);
    assert_eq!(
        seen.peak.load(Ordering::SeqCst),
        1,
        "the gate admitted two at once"
    );
}

/// Control for the case above: without the gate the same mock serves two
/// requests at once, so "peak == 1" is the gate's doing, not the mock's.
#[tokio::test]
async fn control_the_mock_serves_two_ungated_requests_at_once() {
    let (base, seen) = serve(Arc::new(|_, _| {
        streamed(&["x"], Duration::from_millis(150))
    }))
    .await;
    let raw = reqwest::Client::new();
    let send = |body: Value| {
        let raw = raw.clone();
        let url = format!("{base}/api/chat");
        async move {
            raw.post(url)
                .json(&body)
                .send()
                .await
                .unwrap()
                .bytes()
                .await
        }
    };
    let (a, b) = tokio::join!(send(json!({"n": 1})), send(json!({"n": 2})));
    a.unwrap();
    b.unwrap();
    assert_eq!(seen.peak.load(Ordering::SeqCst), 2);
}

/// RFC 0014 P4b: the controller's chat hands the gate its model, so the fleet
/// queue can count model switches. A TEXTUAL pin: the fleet queue is not
/// installed in this test binary.
#[test]
fn chat_passes_its_model_to_the_gate() {
    let src: String = include_str!("lib.rs").split_whitespace().collect();
    assert!(
        src.contains("gate::acquire_process_slot::<gate::NoWaitObserver>(None,model)"),
        "OllamaClient::chat does not pass its model to the gate"
    );
}
