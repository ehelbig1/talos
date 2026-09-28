//! The assembler against the adapter's own parser, and the three deadlines
//! against a loopback server at millisecond scale. The PRODUCTION call sites
//! are driven in `llm_failure_metrics_tests`.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::host::llm_providers::{adapter_for, ParsedToolBlock};
use talos_local_inference::deadlines::{
    LOCAL_LLM_EXCHANGE_CEILING_SECS, LOCAL_LLM_FIRST_BYTE_TIMEOUT_SECS, LOCAL_LLM_IDLE_TIMEOUT_SECS,
};

fn line(v: serde_json::Value) -> String {
    format!("{v}\n")
}

fn chunk(content: &str) -> String {
    line(serde_json::json!({
        "model": "m", "created_at": "t",
        "message": {"role": "assistant", "content": content},
        "done": false
    }))
}

fn done_line() -> String {
    line(serde_json::json!({
        "model": "m", "created_at": "t",
        "message": {"role": "assistant", "content": ""},
        "done": true, "done_reason": "stop",
        "prompt_eval_count": 12, "eval_count": 5
    }))
}

fn assemble(wire: &[u8], max_bytes: usize) -> Result<Vec<u8>, LocalExchangeError> {
    let mut a = OllamaStreamAssembler::new(max_bytes);
    a.push(wire)?;
    a.finish()
}

// ---------------------------------------------------------------------------
// Assembly — parity with the non-streaming response
// ---------------------------------------------------------------------------

#[test]
fn a_streamed_completion_parses_exactly_like_the_non_streaming_one() {
    let adapter = adapter_for("ollama");
    let non_stream = serde_json::json!({
        "model": "m",
        "message": {"role": "assistant", "content": "Grüße, café ☕ — done"},
        "done": true, "done_reason": "stop",
        "prompt_eval_count": 12, "eval_count": 5
    });
    let expected = adapter
        .parse_completion(&serde_json::to_vec(&non_stream).unwrap())
        .unwrap();

    let wire = [
        chunk("Grüße, "),
        chunk("café ☕"),
        chunk(" — done"),
        done_line(),
    ]
    .concat();
    let bytes = wire.as_bytes();
    // Every split point, including inside a multi-byte character and inside
    // a JSON line: the network does not respect either boundary.
    for split in 1..bytes.len() {
        let mut a = OllamaStreamAssembler::new(1 << 20);
        a.push(&bytes[..split]).unwrap();
        a.push(&bytes[split..]).unwrap();
        let got = adapter.parse_completion(&a.finish().unwrap()).unwrap();
        assert_eq!(got, expected, "split at byte {split}");
    }
}

#[test]
fn streamed_tool_calls_parse_exactly_like_the_non_streaming_ones() {
    let adapter = adapter_for("ollama");
    let call = serde_json::json!({
        "id": "call_1",
        "function": {"name": "lookup", "arguments": {"q": "rust", "n": 2}}
    });
    let non_stream = serde_json::json!({
        "message": {"role": "assistant", "content": "Let me check.", "tool_calls": [call]},
        "done": true, "done_reason": "stop",
        "prompt_eval_count": 12, "eval_count": 5
    });
    let expected = adapter
        .parse_tool_completion(&serde_json::to_vec(&non_stream).unwrap())
        .unwrap();

    let wire = [
        chunk("Let me "),
        chunk("check."),
        line(serde_json::json!({
            "message": {"role": "assistant", "content": "", "tool_calls": [call]},
            "done": false
        })),
        done_line(),
    ]
    .concat();
    let got = adapter
        .parse_tool_completion(&assemble(wire.as_bytes(), 1 << 20).unwrap())
        .unwrap();
    assert_eq!(got.blocks, expected.blocks);
    assert!(matches!(
        got.blocks.last(),
        Some(ParsedToolBlock::ToolUse { tool_name, .. }) if tool_name == "lookup"
    ));
    assert_eq!(
        (got.input_tokens, got.output_tokens, got.stop_reason),
        (Some(12), Some(5), Some("stop".to_string()))
    );
}

#[test]
fn thinking_counts_as_progress_but_not_as_content() {
    // The non-streaming API returns reasoning in `message.thinking`, which the
    // adapter ignores; the assembled body must not fold it into the answer.
    let wire = [
        line(serde_json::json!({"message": {"role": "assistant", "content": "", "thinking": "hmm"}, "done": false})),
        chunk("answer"),
        done_line(),
    ]
    .concat();
    let parsed = adapter_for("ollama")
        .parse_completion(&assemble(wire.as_bytes(), 1 << 20).unwrap())
        .unwrap();
    assert_eq!(parsed.text, "answer");
}

#[test]
fn a_final_line_without_its_newline_is_still_read() {
    let wire = [chunk("x"), done_line().trim_end().to_string()].concat();
    let parsed = adapter_for("ollama")
        .parse_completion(&assemble(wire.as_bytes(), 1 << 20).unwrap())
        .unwrap();
    assert_eq!(parsed.text, "x");
}

#[test]
fn lines_after_done_are_ignored() {
    let wire = [chunk("x"), done_line(), "not json at all\n".to_string()].concat();
    assert!(assemble(wire.as_bytes(), 1 << 20).is_ok());
}

#[test]
fn an_error_line_is_a_provider_error_and_its_text_is_not_returned() {
    let wire = [
        chunk("partial"),
        line(serde_json::json!({"error": "model runner crashed: secret-ish detail"})),
    ]
    .concat();
    let err = assemble(wire.as_bytes(), 1 << 20).unwrap_err();
    assert!(matches!(err, LocalExchangeError::ProviderError), "{err:?}");
}

#[test]
fn a_stream_that_ends_before_done_is_a_network_failure() {
    let wire = [chunk("a"), chunk("b")].concat();
    let err = assemble(wire.as_bytes(), 1 << 20).unwrap_err();
    assert!(matches!(err, LocalExchangeError::Network(_)), "{err:?}");
}

#[test]
fn a_line_that_is_not_json_is_a_decode_failure() {
    let err = assemble(b"this is not JSON at all", 1 << 20).unwrap_err();
    assert!(matches!(err, LocalExchangeError::Decode(_)), "{err:?}");
}

#[test]
fn the_wire_bytes_are_capped_not_the_assembled_text() {
    let wire = [chunk("x"), chunk("y"), done_line()].concat();
    let fits = wire.len();
    assert!(assemble(wire.as_bytes(), fits).is_ok());
    let err = assemble(wire.as_bytes(), fits - 1).unwrap_err();
    assert!(matches!(err, LocalExchangeError::Oversized), "{err:?}");
    // One endless line with no newline is capped too.
    let mut a = OllamaStreamAssembler::new(64);
    assert!(matches!(
        a.push(&[b'x'; 65]),
        Err(LocalExchangeError::Oversized)
    ));
}

#[test]
fn the_host_streams_whatever_the_adapter_and_guest_options_said() {
    // The adapter re-asserts `stream: false` after merging guest options, so a
    // guest cannot switch streaming on; the host then does, deliberately.
    let adapter = adapter_for("ollama");
    let mut body = adapter.build_completion_body(&crate::host::llm_providers::CompletionParams {
        model: "m",
        messages: &[],
        system_prompt: None,
        max_tokens: 16,
        temperature: None,
    });
    let opts = serde_json::json!({"stream": false, "seed": 7});
    adapter.apply_provider_options(&mut body, opts.as_object().unwrap().clone());
    assert_eq!(body["stream"], serde_json::json!(false));
    request_streaming(&mut body);
    assert_eq!(body["stream"], serde_json::json!(true));
    assert_eq!(
        body["options"]["seed"],
        serde_json::json!(7),
        "options survive"
    );
}

#[test]
fn the_production_deadlines_are_the_limits_constants() {
    let d = ProgressDeadlines::LOCAL;
    assert_eq!(d.first_byte.as_secs(), LOCAL_LLM_FIRST_BYTE_TIMEOUT_SECS);
    assert_eq!(d.idle.as_secs(), LOCAL_LLM_IDLE_TIMEOUT_SECS);
    assert_eq!(d.ceiling.as_secs(), LOCAL_LLM_EXCHANGE_CEILING_SECS);
}

// ---------------------------------------------------------------------------
// Deadlines — a loopback server, millisecond scale
// ---------------------------------------------------------------------------

/// What the server does after reading the request.
enum Step {
    /// Wait, then write these bytes.
    Send(u64, String),
    /// Hold the connection open and write nothing more.
    Hang,
}

const NDJSON_HEAD: &str =
    "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nConnection: close\r\n\r\n";

async fn serve(steps: Vec<Step>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/api/chat", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        // Read the whole request (headers + Content-Length body).
        loop {
            let n = s.read(&mut tmp).await.unwrap_or(0);
            if n == 0 {
                return;
            }
            buf.extend_from_slice(&tmp[..n]);
            if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&buf[..p]).to_ascii_lowercase();
                let len = head
                    .split("content-length:")
                    .nth(1)
                    .and_then(|r| r.split("\r\n").next())
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if buf.len() >= p + 4 + len {
                    break;
                }
            }
        }
        for step in steps {
            match step {
                Step::Send(delay, bytes) => {
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                    if s.write_all(bytes.as_bytes()).await.is_err() {
                        return;
                    }
                    let _ = s.flush().await;
                }
                Step::Hang => std::future::pending::<()>().await,
            }
        }
    });
    url
}

fn ms(first_byte: u64, idle: u64, ceiling: u64) -> ProgressDeadlines {
    ProgressDeadlines {
        first_byte: Duration::from_millis(first_byte),
        idle: Duration::from_millis(idle),
        ceiling: Duration::from_millis(ceiling),
    }
}

async fn run(url: String, deadlines: ProgressDeadlines) -> Result<Vec<u8>, LocalExchangeError> {
    let req = reqwest::Client::new().post(url).body(r#"{"stream":true}"#);
    exchange_local_stream(req, deadlines, 1 << 20).await
}

/// THE regression. A steady answer whose total is several times longer than
/// every per-gap deadline completes. Under the old single total deadline of
/// the same size (300 ms here, 60 s in production) it could not.
#[tokio::test]
async fn a_steady_answer_longer_than_any_single_deadline_completes() {
    let mut steps = vec![Step::Send(100, NDJSON_HEAD.to_string() + &chunk("0"))];
    for i in 1..10 {
        steps.push(Step::Send(100, chunk(&i.to_string())));
    }
    steps.push(Step::Send(100, done_line()));
    let url = serve(steps).await;

    let started = std::time::Instant::now();
    let body = run(url, ms(300, 300, 10_000)).await.expect("steady stream");
    let took = started.elapsed();
    assert!(
        took >= Duration::from_millis(900),
        "the answer must really have outlasted 3x the per-gap deadline: {took:?}"
    );
    let parsed = adapter_for("ollama").parse_completion(&body).unwrap();
    assert_eq!(parsed.text, "0123456789");
}

#[tokio::test]
async fn silence_after_progress_is_an_idle_timeout() {
    let url = serve(vec![
        Step::Send(0, NDJSON_HEAD.to_string() + &chunk("x")),
        Step::Hang,
    ])
    .await;
    let err = run(url, ms(2_000, 200, 10_000)).await.unwrap_err();
    assert!(
        matches!(err, LocalExchangeError::Timeout(StallKind::Idle)),
        "{err:?}"
    );
}

#[tokio::test]
async fn no_answer_at_all_is_a_first_byte_timeout() {
    let url = serve(vec![Step::Hang]).await;
    let err = run(url, ms(200, 2_000, 10_000)).await.unwrap_err();
    assert!(
        matches!(err, LocalExchangeError::Timeout(StallKind::FirstByte)),
        "{err:?}"
    );
}

/// Headers are not the answer: a backend that accepts the request, sends a
/// 200 and then evaluates the prompt for too long is caught by the FIRST-BYTE
/// deadline, not the idle one.
#[tokio::test]
async fn headers_alone_do_not_start_the_idle_clock() {
    let url = serve(vec![Step::Send(0, NDJSON_HEAD.to_string()), Step::Hang]).await;
    let err = run(url, ms(200, 5_000, 10_000)).await.unwrap_err();
    assert!(
        matches!(err, LocalExchangeError::Timeout(StallKind::FirstByte)),
        "{err:?}"
    );
}

#[tokio::test]
async fn an_endless_answer_is_stopped_by_the_ceiling() {
    let mut steps = vec![Step::Send(0, NDJSON_HEAD.to_string())];
    for _ in 0..100 {
        steps.push(Step::Send(50, chunk("x")));
    }
    let url = serve(steps).await;
    let err = run(url, ms(1_000, 1_000, 400)).await.unwrap_err();
    assert!(
        matches!(err, LocalExchangeError::Timeout(StallKind::Ceiling)),
        "{err:?}"
    );
}

#[tokio::test]
async fn a_non_2xx_status_and_a_429_keep_their_classification() {
    let url = serve(vec![Step::Send(
        0,
        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 5\r\nConnection: close\r\n\r\nboom!"
            .to_string(),
    )])
    .await;
    let err = run(url, ms(1_000, 1_000, 10_000)).await.unwrap_err();
    assert!(
        matches!(err, LocalExchangeError::HttpStatus(500)),
        "{err:?}"
    );

    let url = serve(vec![Step::Send(
        0,
        "HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            .to_string(),
    )])
    .await;
    let err = run(url, ms(1_000, 1_000, 10_000)).await.unwrap_err();
    assert!(matches!(err, LocalExchangeError::RateLimited), "{err:?}");
}

#[tokio::test]
async fn a_connection_closed_before_done_is_a_network_failure() {
    let url = serve(vec![Step::Send(0, NDJSON_HEAD.to_string() + &chunk("x"))]).await;
    let err = run(url, ms(1_000, 1_000, 10_000)).await.unwrap_err();
    assert!(matches!(err, LocalExchangeError::Network(_)), "{err:?}");
}
