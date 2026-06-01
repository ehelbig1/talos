//! Bounded HTTP response-body reads — the OOM defense for outbound calls.
//!
//! `reqwest::Response::json()` / `::text()` / `::bytes()` buffer the WHOLE
//! response body with no size limit. A compromised / MITM'd / buggy upstream
//! (an LLM or embedding provider, a Google API, an OAuth token endpoint, an
//! OCI registry, Vault) returning a multi-GB body would buffer it entirely in
//! controller memory and OOM the pod — and the controller is the
//! credential-holding host, the higher-value target.
//!
//! This crate is the single source of truth for the cap loop that PRs
//! #76–#81 established per-crate. It uses [`reqwest::Response::chunk`], which
//! is available without reqwest's `stream` cargo feature (most controller
//! crates build reqwest without it), so it can be pulled in everywhere.
//!
//! Caps are passed explicitly; [`DEFAULT_MAX_RESPONSE_BYTES`] and
//! [`DEFAULT_MAX_ERROR_BODY_BYTES`] are the conventional values used across
//! the workspace (10 MiB success / 64 KiB error), surfaced by the
//! convenience wrappers [`read_json_capped`] and [`read_error_text_capped`].

use anyhow::{bail, Result};

/// Conventional cap for a success-response body: 10 MiB. Matches the worker's
/// `MAX_LLM_BODY_BYTES` (PR #76). Completion / embedding / API payloads are at
/// most a few hundred KiB, so this leaves ample headroom while refusing a
/// runaway body.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 10 * 1024 * 1024;

/// Conventional cap for an error-response body: 64 KiB. Error bodies are only
/// surfaced in log/error messages (and truncated there), so there is no reason
/// to buffer more than a small bound of them.
pub const DEFAULT_MAX_ERROR_BODY_BYTES: usize = 64 * 1024;

/// Read a response body into memory, aborting if it exceeds `max` bytes.
///
/// Streams via [`reqwest::Response::chunk`] and checks the cap as it
/// accumulates, so an oversized body is rejected without ever fully
/// buffering. Takes the response by value (a body read consumes it anyway),
/// so call sites need no `mut` binding.
pub async fn read_body_capped(mut resp: reqwest::Response, max: usize) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if body.len() + chunk.len() > max {
            bail!("response body exceeded {}-byte cap", max);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Bounded equivalent of `resp.json::<T>().await` — caps at
/// [`DEFAULT_MAX_RESPONSE_BYTES`] before parsing.
pub async fn read_json_capped<T: serde::de::DeserializeOwned>(
    resp: reqwest::Response,
) -> Result<T> {
    let bytes = read_body_capped(resp, DEFAULT_MAX_RESPONSE_BYTES).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Bounded, infallible equivalent of `resp.text().await.unwrap_or_default()`
/// for error-log paths — caps at [`DEFAULT_MAX_ERROR_BODY_BYTES`] and returns
/// lossy UTF-8 (empty string on read error / oversize).
pub async fn read_error_text_capped(resp: reqwest::Response) -> String {
    match read_body_capped(resp, DEFAULT_MAX_ERROR_BODY_BYTES).await {
        Ok(b) => String::from_utf8_lossy(&b).into_owned(),
        Err(_) => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Serve one HTTP/1.1 response carrying `body_len` bytes, then return the
    /// bound address. Lets the cap loop be exercised against a real socket.
    async fn serve_body_once(body_len: usize) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // Drain the request line/headers (best-effort).
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            let body = vec![b'x'; body_len];
            let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
            sock.write_all(head.as_bytes()).await.unwrap();
            sock.write_all(&body).await.unwrap();
            let _ = sock.flush().await;
        });
        addr
    }

    async fn get(addr: std::net::SocketAddr) -> reqwest::Response {
        reqwest::Client::new()
            .get(format!("http://{addr}/"))
            .send()
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn rejects_body_over_cap() {
        let addr = serve_body_once(5_000).await;
        let resp = get(addr).await;
        let result = read_body_capped(resp, 1_000).await;
        assert!(
            result.is_err(),
            "a 5000-byte body must be rejected under a 1000-byte cap"
        );
    }

    #[tokio::test]
    async fn accepts_body_at_or_under_cap() {
        let addr = serve_body_once(900).await;
        let resp = get(addr).await;
        let body = read_body_capped(resp, 1_000).await.expect("under cap");
        assert_eq!(body.len(), 900);
    }

    #[tokio::test]
    async fn error_text_is_lossy_and_bounded() {
        // Body under the error cap is returned verbatim (lossy UTF-8).
        let addr = serve_body_once(10).await;
        let resp = get(addr).await;
        let text = read_error_text_capped(resp).await;
        assert_eq!(text, "xxxxxxxxxx");
    }
}
