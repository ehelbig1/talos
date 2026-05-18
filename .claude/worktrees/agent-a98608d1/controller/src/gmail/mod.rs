// Gmail integration functions are not exercised by the current tests.
#![allow(dead_code, unused_imports)]
use anyhow::{anyhow, Context, Result};
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Json},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;

pub mod integration;
#[allow(unused_imports)]
pub use integration::{GmailIntegration, GmailIntegrationInfo, GmailIntegrationService};

pub mod handlers;
pub use handlers::{
    connect_gmail_handler, disconnect_integration_handler, get_integration_handler,
    gmail_callback_handler, list_integrations_handler,
};

/// Gmail API client for enrichment and browsing
pub struct GmailApiClient {
    http_client: reqwest::Client,
}

impl Default for GmailApiClient {
    fn default() -> Self {
        GmailApiClient {
            http_client: reqwest::Client::new(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct GmailApiParams {
    pub access_token: String,
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
    pub fn new() -> Self {
        Self {
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
        }
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
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(GmailApiResponse {
                ok: false,
                data: None,
                error: Some(e.to_string()),
            }),
        )
            .into_response(),
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
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(GmailApiResponse {
                ok: false,
                data: None,
                error: Some(e.to_string()),
            }),
        )
            .into_response(),
    }
}
