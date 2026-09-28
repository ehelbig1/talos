//! Progress-based deadlines for a LOCAL (Ollama) LLM exchange — RFC 0014 P1.
//!
//! ## The defect this closes
//!
//! A local exchange used to be one non-streaming `/api/chat` request wrapped
//! in one 60 s total timeout. The answer is a single JSON object, so nothing
//! arrives until the last token is generated, and a call 59 s into a healthy
//! generation was indistinguishable from a stuck one. Measured over 32 days of
//! the host Ollama's request log: 47 requests cut at exactly 60 s, one on 19 of
//! September's 20 weekday mornings, and on 2026-09-28 the flagship briefing's
//! first attempt was cut while it was the ONLY request on a model that was
//! already loaded.
//!
//! ## Shape
//!
//! The request is sent with `stream: true`, and three deadlines replace the one
//! (values and the Pareto argument live beside the constants in `deadlines`):
//!
//! * **first byte** — send + model load + prompt evaluation;
//! * **idle** — between any two chunks;
//! * **ceiling** — the whole exchange, a backstop.
//!
//! The JSON lines are assembled back into exactly the object the
//! non-streaming API returns, and that object goes to the caller's UNCHANGED
//! parser — the worker's provider adapter, or the controller's
//! `talos_llm::OllamaClient` (RFC 0014 P3a) — so each stays the one owner of
//! its wire format and sees one completion, as before. Nothing here is visible
//! to a caller except that a long answer no longer times out.
//!
//! ## Classification (unchanged from the non-streaming exchange)
//!
//! * a deadline → `Timeout` (which one is logged, not a label — RFC 0014 P4);
//! * an `{"error": …}` line → the provider reporting a failure, classified as
//!   the HTTP 500 the same failure produced without streaming; its text is
//!   logged DLP-redacted and never returned to the caller;
//! * a stream that ends without its `done` line → `Network`;
//! * more than `max_bytes` on the wire → `Oversized` (the streamed bytes are
//!   counted, not the assembled text, so the cap stays a memory bound);
//! * a line that is not the expected JSON → `Decode`.

use std::time::Duration;

use futures_util::StreamExt;
use tokio::time::Instant;

use crate::deadlines::{
    LOCAL_LLM_EXCHANGE_CEILING_SECS, LOCAL_LLM_FIRST_BYTE_TIMEOUT_SECS, LOCAL_LLM_IDLE_TIMEOUT_SECS,
};
use crate::line_reader::LineReader;

/// The three progress deadlines of one exchange. A parameter rather than read
/// from the constants inside, so the reader can be driven in tests at
/// millisecond scale; production passes [`ProgressDeadlines::LOCAL`].
#[derive(Debug, Clone, Copy)]
pub struct ProgressDeadlines {
    pub first_byte: Duration,
    pub idle: Duration,
    pub ceiling: Duration,
}

impl ProgressDeadlines {
    pub const LOCAL: Self = Self {
        first_byte: Duration::from_secs(LOCAL_LLM_FIRST_BYTE_TIMEOUT_SECS),
        idle: Duration::from_secs(LOCAL_LLM_IDLE_TIMEOUT_SECS),
        ceiling: Duration::from_secs(LOCAL_LLM_EXCHANGE_CEILING_SECS),
    };
}

/// Which deadline ended an exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StallKind {
    FirstByte,
    Idle,
    Ceiling,
}

impl StallKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            StallKind::FirstByte => "first_byte",
            StallKind::Idle => "idle",
            StallKind::Ceiling => "ceiling",
        }
    }
}

/// Why a local exchange produced no completion. Each caller maps this to its
/// own error: the worker to a WIT error and an `LlmFailure` label, the
/// controller's `OllamaClient` to an `anyhow` message.
#[derive(Debug)]
pub enum LocalExchangeError {
    /// The request failed on the wire, or the stream ended before `done`.
    Network(String),
    /// Which deadline fired. It is already in the exchange's WARN line; it
    /// becomes a metric label in RFC 0014 P4.
    Timeout(StallKind),
    RateLimited,
    HttpStatus(u16),
    /// An `{"error": …}` line mid-stream.
    ProviderError,
    Oversized,
    Decode(String),
}

/// Turn a local request body into a streaming one. Called by the HOST after
/// the adapter and any guest options have shaped the body: the adapter keeps
/// `stream: false` (its non-streaming contract, which guest options cannot
/// change), and the transport decides to stream.
pub fn request_streaming(body: &mut serde_json::Value) {
    if let Some(obj) = body.as_object_mut() {
        obj.insert("stream".to_string(), serde_json::Value::Bool(true));
    }
}

#[derive(serde::Deserialize)]
struct StreamLine {
    #[serde(default)]
    message: Option<StreamMessage>,
    #[serde(default)]
    done: bool,
    #[serde(default)]
    done_reason: Option<String>,
    #[serde(default)]
    prompt_eval_count: Option<u64>,
    #[serde(default)]
    eval_count: Option<u64>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(serde::Deserialize)]
struct StreamMessage {
    #[serde(default)]
    content: Option<String>,
    /// Kept as raw values so no field of a tool call is lost on the way to the
    /// adapter's own parser.
    #[serde(default)]
    tool_calls: Vec<serde_json::Value>,
}

/// Reassembles Ollama's streamed JSON lines into the non-streaming response.
pub struct OllamaStreamAssembler {
    lines: LineReader,
    wire_bytes: usize,
    max_bytes: usize,
    content: String,
    tool_calls: Vec<serde_json::Value>,
    done: Option<StreamLine>,
}

impl OllamaStreamAssembler {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            // The total cap bounds a single line too.
            lines: LineReader::new(max_bytes),
            wire_bytes: 0,
            max_bytes,
            content: String::new(),
            tool_calls: Vec::new(),
            done: None,
        }
    }

    /// Whether the `done` line has been seen; the reader stops there.
    pub fn is_done(&self) -> bool {
        self.done.is_some()
    }

    /// Feed one network chunk.
    pub fn push(&mut self, chunk: &[u8]) -> Result<(), LocalExchangeError> {
        if self.wire_bytes + chunk.len() > self.max_bytes {
            return Err(LocalExchangeError::Oversized);
        }
        self.wire_bytes += chunk.len();
        self.lines
            .push(chunk)
            .map_err(|_| LocalExchangeError::Oversized)?;
        while !self.is_done() {
            let Some(line) = self.lines.next_line() else {
                break;
            };
            self.consume(&line)?;
        }
        Ok(())
    }

    fn consume(&mut self, line: &str) -> Result<(), LocalExchangeError> {
        if line.trim().is_empty() {
            return Ok(());
        }
        let parsed: StreamLine = serde_json::from_str(line).map_err(|e| {
            LocalExchangeError::Decode(format!("Failed to parse Ollama stream line: {e}"))
        })?;
        if let Some(err) = parsed.error.as_deref() {
            let preview: String = err.chars().take(500).collect();
            tracing::warn!(
                error_preview = %talos_dlp_provider::redact_str(&preview),
                "local LLM reported an error mid-stream"
            );
            return Err(LocalExchangeError::ProviderError);
        }
        if let Some(msg) = parsed.message.as_ref() {
            if let Some(c) = msg.content.as_deref() {
                self.content.push_str(c);
            }
            self.tool_calls.extend(msg.tool_calls.iter().cloned());
        }
        if parsed.done {
            self.done = Some(parsed);
        }
        Ok(())
    }

    /// End of stream: the non-streaming response body, for the adapter.
    pub fn finish(mut self) -> Result<Vec<u8>, LocalExchangeError> {
        if !self.is_done() {
            while let Some(line) = self.lines.next_line() {
                self.consume(&line)?;
                if self.is_done() {
                    break;
                }
            }
        }
        if !self.is_done() {
            if let Some(tail) = self.lines.take_tail() {
                self.consume(&tail)?;
            }
        }
        let Some(done) = self.done else {
            return Err(LocalExchangeError::Network(
                "stream ended before the final chunk".to_string(),
            ));
        };
        let body = serde_json::json!({
            "message": {
                "role": "assistant",
                "content": self.content,
                "tool_calls": self.tool_calls,
            },
            "done": true,
            "done_reason": done.done_reason,
            "prompt_eval_count": done.prompt_eval_count,
            "eval_count": done.eval_count,
        });
        serde_json::to_vec(&body)
            .map_err(|e| LocalExchangeError::Decode(format!("Failed to reassemble stream: {e}")))
    }
}

/// Run one local exchange under progress deadlines. `request` must carry a
/// body made streaming by [`request_streaming`]. Returns the reassembled
/// non-streaming response body.
pub async fn exchange_local_stream(
    request: reqwest::RequestBuilder,
    deadlines: ProgressDeadlines,
    max_bytes: usize,
) -> Result<Vec<u8>, LocalExchangeError> {
    let started = Instant::now();
    let ceiling_at = started + deadlines.ceiling;
    let first_byte_at = (started + deadlines.first_byte).min(ceiling_at);
    let mut chunks: u64 = 0;
    let mut wire_bytes: usize = 0;

    let stalled = |kind: StallKind, chunks: u64, wire_bytes: usize| {
        tracing::warn!(
            stall = kind.as_str(),
            elapsed_ms = started.elapsed().as_millis() as u64,
            chunks,
            wire_bytes,
            "local LLM exchange made no progress within its deadline"
        );
        LocalExchangeError::Timeout(kind)
    };
    // The deadline that fires is the ceiling when the ceiling is the earlier
    // of the two; otherwise it is the phase's own.
    let kind_at = |deadline: Instant, phase: StallKind| {
        if deadline >= ceiling_at {
            StallKind::Ceiling
        } else {
            phase
        }
    };

    let response = match tokio::time::timeout_at(first_byte_at, request.send()).await {
        Err(_) => return Err(stalled(kind_at(first_byte_at, StallKind::FirstByte), 0, 0)),
        Ok(Err(e)) => {
            tracing::error!(error = %e, provider = "ollama", "LLM API request failed");
            return Err(LocalExchangeError::Network(e.to_string()));
        }
        Ok(Ok(r)) => r,
    };

    if !response.status().is_success() {
        let status = response.status().as_u16();
        tracing::warn!(status, "LLM API returned error status");
        if status == 429 {
            return Err(LocalExchangeError::RateLimited);
        }
        // Bounded in bytes by the reader and in time by the idle deadline, so
        // an error body cannot hold the call open.
        let preview_bytes = tokio::time::timeout(
            deadlines.idle,
            talos_http_body::read_body_capped(response, max_bytes),
        )
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default();
        let preview: String = String::from_utf8_lossy(&preview_bytes)
            .chars()
            .take(500)
            .collect();
        tracing::warn!(
            status,
            body_len = preview_bytes.len(),
            body_preview = %talos_dlp_provider::redact_str(&preview),
            "LLM API returned error"
        );
        return Err(LocalExchangeError::HttpStatus(status));
    }

    let mut assembler = OllamaStreamAssembler::new(max_bytes);
    let mut stream = response.bytes_stream();
    loop {
        let deadline = if chunks == 0 {
            first_byte_at
        } else {
            (Instant::now() + deadlines.idle).min(ceiling_at)
        };
        let phase = if chunks == 0 {
            StallKind::FirstByte
        } else {
            StallKind::Idle
        };
        match tokio::time::timeout_at(deadline, stream.next()).await {
            Err(_) => return Err(stalled(kind_at(deadline, phase), chunks, wire_bytes)),
            Ok(None) => break,
            Ok(Some(Err(e))) => {
                tracing::warn!(error = %e, chunks, wire_bytes, "local LLM stream broke");
                return Err(LocalExchangeError::Network(e.to_string()));
            }
            Ok(Some(Ok(bytes))) => {
                chunks += 1;
                wire_bytes += bytes.len();
                if let Err(e) = assembler.push(&bytes) {
                    if matches!(e, LocalExchangeError::Oversized) {
                        tracing::warn!(
                            limit = max_bytes,
                            wire_bytes,
                            "LLM response exceeded size cap; aborting body read"
                        );
                    }
                    return Err(e);
                }
                if assembler.is_done() {
                    break;
                }
            }
        }
    }
    tracing::debug!(
        elapsed_ms = started.elapsed().as_millis() as u64,
        chunks,
        wire_bytes,
        "local LLM exchange streamed"
    );
    assembler.finish()
}
