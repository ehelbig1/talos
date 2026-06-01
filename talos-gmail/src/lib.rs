// Gmail integration functions are not exercised by the current tests.

use anyhow::{anyhow, Context, Result};
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Json},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;

pub mod admin;
pub mod api;
pub mod dispatch;
pub mod integration;
pub mod pubsub_jwt;
pub mod scheduler;
pub mod watch;
pub mod watch_channel_service;
#[allow(unused_imports)]
pub use integration::{GmailIntegration, GmailIntegrationInfo, GmailIntegrationService};

pub mod handlers;
pub use handlers::{
    connect_gmail_handler, disconnect_integration_handler, get_integration_handler,
    gmail_callback_handler, list_integrations_handler,
};

/// Gmail API HTTP client request timeout. Covers connect + body for
/// a single API call. Gmail allows up to 30 s for some endpoints
/// (large `list_messages` pages, message-body fetches with attachments).
pub(crate) const GMAIL_HTTP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Gmail API HTTP client connect timeout. Tighter than the request
/// timeout because TCP+TLS handshake should complete fast even
/// across continents; a slow handshake usually indicates DNS or
/// upstream-network issues that retry won't fix.
pub(crate) const GMAIL_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Gmail API client for enrichment and browsing
pub struct GmailApiClient {
    http_client: reqwest::Client,
}

impl Default for GmailApiClient {
    fn default() -> Self {
        // MCP-534: same Mode-B credential-leak hardening as the
        // OAuth-callback paths fixed in MCP-533. This client carries
        // `Bearer <access_token>` on every Gmail API call. Disable
        // redirects so a stray 302 from googleapis.com can't replay
        // the Authorization header to a redirect target, and fail
        // loudly on TLS init instead of silently re-enabling default
        // redirect-following via the `unwrap_or_else(Client::new)`
        // footgun documented in ssrf_via_redirect_pattern.md.
        let http_client = reqwest::Client::builder()
            .timeout(GMAIL_HTTP_TIMEOUT)
            .connect_timeout(GMAIL_CONNECT_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("GmailApiClient: failed to build hardened reqwest client");
        GmailApiClient { http_client }
    }
}

#[derive(Deserialize)]
pub struct GmailApiParams {
    pub access_token: String,
}

/// Redacted `Debug` so `tracing::*!("{:?}", params)` in any future
/// handler can't dump the access token into logs. (The token is
/// already URL-query-bound which is itself a footgun — proxy access
/// logs may capture the query string — but mitigating *this* surface
/// at least closes the in-process logging vector.)
impl std::fmt::Debug for GmailApiParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GmailApiParams")
            .field("access_token", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Serialize)]
pub struct GmailApiResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl GmailApiClient {
    /// Construct with the standard Gmail HTTP-client config: 30 s
    /// request timeout, 5 s connect timeout. Delegates to `Default`
    /// so there's exactly one source of truth for the timeouts —
    /// pre-fix this constructor used 10 s and no connect_timeout,
    /// which caused intermittent flakes on slow `list_messages`
    /// pages and message-body fetches.
    pub fn new() -> Self {
        Self::default()
    }

    /// List Gmail labels
    pub async fn list_labels(&self, access_token: &str) -> Result<Value> {
        self.call_gmail_api("users/me/labels", access_token, &[])
            .await
    }

    /// Get user profile (email address, etc.)
    pub async fn get_profile(&self, access_token: &str) -> Result<Value> {
        self.call_gmail_api("users/me/profile", access_token, &[])
            .await
    }

    /// List messages (for preview)
    pub async fn list_messages(
        &self,
        access_token: &str,
        label_ids: Option<&[String]>,
        max_results: Option<u32>,
    ) -> Result<Value> {
        let mut params = Vec::new();

        if let Some(labels) = label_ids {
            for label in labels {
                params.push(("labelIds", label.as_str()));
            }
        }

        let max_results_str;
        if let Some(max) = max_results {
            max_results_str = max.to_string();
            params.push(("maxResults", &max_results_str));
        }

        self.call_gmail_api("users/me/messages", access_token, &params)
            .await
    }

    /// Get a specific message
    pub async fn get_message(&self, access_token: &str, message_id: &str) -> Result<Value> {
        self.call_gmail_api(
            &format!("users/me/messages/{}", message_id),
            access_token,
            &[("format", "full")],
        )
        .await
    }

    /// Generic Gmail API call
    async fn call_gmail_api(
        &self,
        endpoint: &str,
        access_token: &str,
        params: &[(&str, &str)],
    ) -> Result<Value> {
        let url = format!("https://gmail.googleapis.com/gmail/v1/{}", endpoint);

        let mut request = self.http_client.get(&url).bearer_auth(access_token);

        for (key, value) in params {
            request = request.query(&[(key, value)]);
        }

        let response = request.send().await.context("Failed to call Gmail API")?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(anyhow!(
                "Gmail API returned non-success status {}: {}",
                status,
                error_text
            ));
        }

        let json: Value = response
            .json()
            .await
            .context("Failed to parse Gmail API response")?;

        Ok(json)
    }
}

/// Axum handler for listing Gmail labels
pub async fn list_labels_handler(
    Query(params): Query<GmailApiParams>,
    State(client): State<Arc<GmailApiClient>>,
) -> impl IntoResponse {
    match client.list_labels(&params.access_token).await {
        Ok(data) => Json(GmailApiResponse {
            ok: true,
            data: Some(data),
            error: None,
        })
        .into_response(),
        Err(e) => {
            // MCP-927 (2026-05-14): log server-side, generic to
            // client. Sibling sweep to MCP-923/924/925/926 — these
            // two Axum handlers live in `src/lib.rs` instead of
            // `src/handlers.rs`, so the file-pattern sweep missed
            // them. Live routes: /api/gmail/labels and
            // /api/gmail/profile, wired in controller/src/main.rs.
            // The `anyhow::Error` chain from `GmailApiClient` can
            // carry upstream Google error bodies (auth detail,
            // quota text) and reqwest connect-error specifics.
            tracing::error!(error = %e, "Gmail labels handler failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(GmailApiResponse {
                    ok: false,
                    data: None,
                    error: Some("Failed to list Gmail labels".to_string()),
                }),
            )
                .into_response()
        }
    }
}

/// Axum handler for getting Gmail profile
pub async fn get_profile_handler(
    Query(params): Query<GmailApiParams>,
    State(client): State<Arc<GmailApiClient>>,
) -> impl IntoResponse {
    match client.get_profile(&params.access_token).await {
        Ok(data) => Json(GmailApiResponse {
            ok: true,
            data: Some(data),
            error: None,
        })
        .into_response(),
        Err(e) => {
            // MCP-927: log server-side, generic to client. See list_labels_handler.
            tracing::error!(error = %e, "Gmail profile handler failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(GmailApiResponse {
                    ok: false,
                    data: None,
                    error: Some("Failed to fetch Gmail profile".to_string()),
                }),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod redaction_tests {
    use super::*;

    #[test]
    fn debug_redacts_access_token() {
        let p = GmailApiParams {
            access_token: "ya29.LIVE_ACCESS_TOKEN_ABCDEF".into(),
        };
        let dbg = format!("{:?}", p);
        assert!(
            !dbg.contains("ya29.LIVE_ACCESS_TOKEN_ABCDEF"),
            "access_token leaked: {dbg}"
        );
        assert!(
            dbg.contains("[REDACTED]"),
            "redaction marker missing: {dbg}"
        );
    }
}
