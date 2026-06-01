//! Bounded HTTP response-body reads for the Gmail API + OAuth token paths.
//!
//! Controller-side sibling of the worker's `read_llm_response_body_bounded`
//! (PR #76) and the embedding / LLM / Google-Calendar caps (PRs #78, #79,
//! #80): `resp.json()` / `resp.text()` buffer the WHOLE body with no size
//! limit, so a compromised / MITM'd / buggy upstream (Google API or the
//! OAuth token endpoint) returning a multi-GB body would OOM the controller —
//! the credential-holding host. `reqwest` is built here without the `stream`
//! feature, so `Response::chunk()` (always available) streams the body and we
//! cap as we accumulate.

use anyhow::{bail, Result};

/// Max bytes buffered from a success response. Gmail history / watch payloads
/// are at most a few hundred KiB; 10 MiB (matching the worker's
/// `MAX_LLM_BODY_BYTES`) refuses a runaway body with ample headroom.
pub(crate) const MAX_RESPONSE_BYTES: usize = 10 * 1024 * 1024;

/// Error bodies are truncated to ~500 chars for logging, so buffer at most a
/// small bound of a provider's error response.
pub(crate) const MAX_ERROR_BODY_BYTES: usize = 64 * 1024;

/// Read a response body into memory, aborting if it exceeds `max` bytes.
pub(crate) async fn read_body_capped(mut resp: reqwest::Response, max: usize) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        if body.len() + chunk.len() > max {
            bail!("response exceeded {}-byte cap", max);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Bounded equivalent of `resp.json::<T>().await` — caps at
/// [`MAX_RESPONSE_BYTES`] before parsing. Takes the response by value (the
/// body read consumes it anyway), so call sites need no `mut`.
pub(crate) async fn read_json_capped<T: serde::de::DeserializeOwned>(
    resp: reqwest::Response,
) -> Result<T> {
    let bytes = read_body_capped(resp, MAX_RESPONSE_BYTES).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Bounded, infallible equivalent of `resp.text().await.unwrap_or_default()`
/// for error bodies — caps at [`MAX_ERROR_BODY_BYTES`] and returns lossy UTF-8.
pub(crate) async fn read_error_text_capped(resp: reqwest::Response) -> String {
    match read_body_capped(resp, MAX_ERROR_BODY_BYTES).await {
        Ok(b) => String::from_utf8_lossy(&b).into_owned(),
        Err(_) => String::new(),
    }
}
