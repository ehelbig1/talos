//! One home for the Anthropic Messages transport used by every controller-side
//! caller: [`crate::LlmClient`] and graph-RAG triple extraction. Before this
//! module the endpoint, API version, model names, hardened client and retry
//! loop were copied into each call site (five copies, none honouring
//! `Retry-After`).

use std::sync::OnceLock;
use std::time::Duration;

use reqwest::header::{HeaderValue, RETRY_AFTER};
use reqwest::{Client, RequestBuilder, Response, StatusCode};
use tracing::{error, warn};

/// Messages API endpoint.
pub const MESSAGES_URL: &str = "https://api.anthropic.com/v1/messages";
/// `anthropic-version` header value.
pub const API_VERSION: &str = "2023-06-01";
/// Model for code / workflow generation and graph-RAG triple extraction.
pub const GENERATION_MODEL: &str = "claude-sonnet-4-6";
/// Model for short text and structured-output completions.
pub const FAST_MODEL: &str = "claude-haiku-4-5-20251001";

/// Per-request timeout (connect + body). Anthropic answers a paragraph in
/// 1–10 s and a long completion in up to ~30 s.
pub const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Longest wait honoured between attempts. A `Retry-After` beyond it ends the
/// retries: retrying earlier than the server asked only earns another 429.
pub const MAX_RETRY_DELAY: Duration = Duration::from_secs(30);

/// The shared hardened client, built once per process (reqwest clients are
/// `Arc`-backed; cloning shares the connection pool).
///
/// Redirects are OFF: the API key travels in `x-api-key`, which reqwest does
/// not strip on a cross-origin redirect (MCP-496/497). Building only fails on
/// TLS init — a deployment failure that must be loud, never a fallback to an
/// unhardened client.
pub fn http_client() -> Client {
    static CLIENT: OnceLock<Client> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            Client::builder()
                .timeout(HTTP_TIMEOUT)
                .connect_timeout(CONNECT_TIMEOUT)
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("talos-llm: failed to build hardened Anthropic HTTP client")
        })
        .clone()
}

/// A Messages API POST carrying the key and version headers.
pub fn messages_request(
    client: &Client,
    api_key: &str,
    body: &serde_json::Value,
) -> RequestBuilder {
    client
        .post(MESSAGES_URL)
        .header("x-api-key", api_key)
        .header("anthropic-version", API_VERSION)
        .json(body)
}

/// 429, 529 (overloaded) and other 5xx are transient; everything else is final.
pub fn is_retryable(status: StatusCode) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS || status.as_u16() == 529 || status.is_server_error()
}

/// `Retry-After` in its delta-seconds form (what Anthropic sends). The
/// HTTP-date form and anything unparseable read as absent.
pub fn parse_retry_after(value: Option<&HeaderValue>) -> Option<Duration> {
    let secs: u64 = value?.to_str().ok()?.trim().parse().ok()?;
    Some(Duration::from_secs(secs))
}

/// Delay before retry number `attempt` (1-based, counting failed attempts),
/// or `None` to stop: a final status, retries exhausted, or a server-requested
/// wait longer than [`MAX_RETRY_DELAY`]. Without `Retry-After` the backoff is
/// `2^attempt` seconds.
pub fn retry_delay(
    status: StatusCode,
    attempt: u32,
    max_retries: u32,
    retry_after: Option<Duration>,
) -> Option<Duration> {
    if !is_retryable(status) || attempt > max_retries {
        return None;
    }
    let delay = retry_after.unwrap_or_else(|| Duration::from_secs(2u64.saturating_pow(attempt)));
    (delay <= MAX_RETRY_DELAY).then_some(delay)
}

/// Why [`send_with_retry`] gave up.
#[derive(Debug)]
pub enum SendError {
    /// The request never produced a response (connect, TLS, timeout).
    /// Not retried: a timed-out completion may already have been billed.
    Transport(reqwest::Error),
    /// A non-success status after any retries. The body was logged
    /// server-side (DLP-redacted) and is deliberately not carried: Anthropic
    /// error bodies can echo the prompt (MCP-454/527).
    Status(StatusCode),
}

impl SendError {
    /// The caller-facing error: `"<prefix>: HTTP <status>"` for a status, the
    /// transport error itself otherwise.
    pub fn into_anyhow(self, prefix: &str) -> anyhow::Error {
        match self {
            SendError::Transport(e) => anyhow::Error::from(e),
            SendError::Status(status) => anyhow::anyhow!("{prefix}: HTTP {status}"),
        }
    }
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendError::Transport(e) => write!(f, "request failed: {e}"),
            SendError::Status(status) => write!(f, "HTTP {status}"),
        }
    }
}

impl std::error::Error for SendError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SendError::Transport(e) => Some(e),
            SendError::Status(_) => None,
        }
    }
}

/// Send the request `build` produces, retrying transient statuses per
/// [`retry_delay`] (honouring `Retry-After`). `what` names the caller in logs.
pub async fn send_with_retry<F>(
    build: F,
    max_retries: u32,
    what: &'static str,
) -> Result<Response, SendError>
where
    F: Fn() -> RequestBuilder,
{
    let mut attempt = 0u32;
    loop {
        let resp = build().send().await.map_err(SendError::Transport)?;
        let status = resp.status();
        if status.is_success() {
            return Ok(resp);
        }
        attempt += 1;
        let retry_after = parse_retry_after(resp.headers().get(RETRY_AFTER));
        if let Some(delay) = retry_delay(status, attempt, max_retries, retry_after) {
            warn!(
                what,
                status = %status,
                attempt,
                max_retries,
                delay_secs = delay.as_secs(),
                from_retry_after = retry_after.is_some(),
                "Anthropic API returned a transient error — retrying"
            );
            drop(resp);
            tokio::time::sleep(delay).await;
            continue;
        }
        let text = talos_http_body::read_error_text_capped(resp).await;
        let redacted = talos_dlp_provider::redact_str(&text);
        error!(
            what,
            status = %status,
            attempts = attempt,
            retry_after_secs = retry_after.map(|d| d.as_secs()),
            body_len = text.len(),
            body = %redacted,
            "Anthropic API error"
        );
        return Err(SendError::Status(status));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_transient_statuses_retry() {
        for s in [429, 500, 502, 503, 529] {
            assert!(is_retryable(StatusCode::from_u16(s).unwrap()), "{s}");
        }
        for s in [400, 401, 403, 404, 413] {
            assert!(!is_retryable(StatusCode::from_u16(s).unwrap()), "{s}");
        }
    }

    #[test]
    fn retry_after_is_honoured_and_backoff_is_exponential_without_it() {
        let busy = StatusCode::TOO_MANY_REQUESTS;
        assert_eq!(retry_delay(busy, 1, 3, None), Some(Duration::from_secs(2)));
        assert_eq!(retry_delay(busy, 3, 3, None), Some(Duration::from_secs(8)));
        assert_eq!(retry_delay(busy, 4, 3, None), None, "retries exhausted");
        assert_eq!(
            retry_delay(busy, 1, 3, Some(Duration::from_secs(11))),
            Some(Duration::from_secs(11)),
            "the server's wait wins over the backoff"
        );
        assert_eq!(
            retry_delay(busy, 1, 3, Some(Duration::from_secs(31))),
            None,
            "a wait past the cap stops rather than retrying early"
        );
        assert_eq!(retry_delay(StatusCode::BAD_REQUEST, 1, 3, None), None);
    }

    #[test]
    fn retry_after_parses_delta_seconds_only() {
        let h = |s: &str| HeaderValue::from_str(s).unwrap();
        assert_eq!(
            parse_retry_after(Some(&h("7"))),
            Some(Duration::from_secs(7))
        );
        assert_eq!(parse_retry_after(Some(&h(" 0 "))), Some(Duration::ZERO));
        assert_eq!(
            parse_retry_after(Some(&h("Wed, 21 Oct 2026 07:28:00 GMT"))),
            None
        );
        assert_eq!(parse_retry_after(Some(&h("-1"))), None);
        assert_eq!(parse_retry_after(None), None);
    }

    #[test]
    fn caller_errors_keep_their_wording() {
        let e = SendError::Status(StatusCode::TOO_MANY_REQUESTS).into_anyhow("LLM API error");
        assert_eq!(e.to_string(), "LLM API error: HTTP 429 Too Many Requests");
    }
}
