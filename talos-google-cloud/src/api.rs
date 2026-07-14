//! Read-only Cloud Resource Manager (v3) API client for GCP projects.
//!
//! All requests use the shared hardened integration client
//! (`build_integration_client`, lint 49: redirect-none + connect timeout) and
//! read bodies through `talos_http_body` (lint 31: capped). Errors carry the
//! HTTP status only — upstream Google error bodies are DLP-scrubbed into the
//! logs, never returned to the caller.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

/// Cloud Resource Manager request timeout (connect + body for one call).
const GCP_HTTP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

const CRM_BASE: &str = "https://cloudresourcemanager.googleapis.com/v3/";

/// One GCP project (subset of the Cloud Resource Manager v3 Project resource).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Project {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub project_id: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub create_time: String,
}

/// Response of `projects:search`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectSearchResponse {
    #[serde(default)]
    pub projects: Vec<Project>,
    #[serde(default)]
    pub next_page_token: Option<String>,
}

/// HTTP client for the Cloud Resource Manager v3 API.
pub struct GcpApiClient {
    http_client: reqwest::Client,
}

impl Default for GcpApiClient {
    fn default() -> Self {
        Self {
            http_client: talos_http_utils::trusted_client::build_integration_client(
                GCP_HTTP_TIMEOUT,
            ),
        }
    }
}

impl GcpApiClient {
    pub fn new() -> Self {
        Self::default()
    }

    /// Search projects visible to the caller. `query` uses Cloud Resource
    /// Manager search syntax (e.g. `"state:ACTIVE"`). `page_size` is clamped
    /// upstream by Google; pass a bounded value.
    pub async fn search_projects(
        &self,
        access_token: &str,
        query: Option<&str>,
        page_size: u32,
        page_token: Option<&str>,
    ) -> Result<ProjectSearchResponse> {
        let url = format!("{CRM_BASE}projects:search");
        let mut req = self
            .http_client
            .get(&url)
            .bearer_auth(access_token)
            .query(&[("pageSize", page_size.to_string())]);
        if let Some(q) = query {
            if !q.is_empty() {
                req = req.query(&[("query", q)]);
            }
        }
        if let Some(tok) = page_token {
            if !tok.is_empty() {
                req = req.query(&[("pageToken", tok)]);
            }
        }

        let resp = req
            .send()
            .await
            .context("Failed to call Cloud Resource Manager projects:search")?;
        self.decode(resp).await
    }

    /// Fetch a single project by its project id (e.g. `my-project-123`).
    /// `project_id` is validated against the GCP id charset before being
    /// interpolated into the URL path.
    pub async fn get_project(&self, access_token: &str, project_id: &str) -> Result<Project> {
        if !is_valid_project_id(project_id) {
            return Err(anyhow!("Invalid project_id"));
        }
        let url = format!("{CRM_BASE}projects/{project_id}");
        let resp = self
            .http_client
            .get(&url)
            .bearer_auth(access_token)
            .send()
            .await
            .context("Failed to call Cloud Resource Manager get project")?;
        self.decode(resp).await
    }

    /// Shared response decode: status check with DLP-scrubbed body preview on
    /// error, capped JSON parse on success.
    async fn decode<T: serde::de::DeserializeOwned>(
        &self,
        response: reqwest::Response,
    ) -> Result<T> {
        if !response.status().is_success() {
            let status = response.status();
            let text = talos_http_body::read_error_text_capped(response).await;
            let preview = talos_text_util::truncate_at_char_boundary(&text, 500);
            let redacted = talos_dlp_provider::redact_str(preview);
            tracing::warn!(%status, body = %redacted, "GCP API returned error");
            return Err(anyhow!("GCP API returned non-success status {}", status));
        }
        let parsed: T = talos_http_body::read_json_capped(response)
            .await
            .context("Failed to parse GCP API response")?;
        Ok(parsed)
    }
}

/// GCP project ids are 6–30 chars of lowercase letters, digits, and hyphens.
/// We validate the charset (and non-empty) before URL interpolation so a
/// crafted id can't inject path/query segments.
pub fn is_valid_project_id(project_id: &str) -> bool {
    !project_id.is_empty()
        && project_id.len() <= 64
        && project_id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_search_happy_path() {
        let raw = r#"{
            "projects": [
                {"name":"projects/123","projectId":"my-proj","displayName":"My Proj","state":"ACTIVE","createTime":"2026-01-01T00:00:00Z"}
            ],
            "nextPageToken": "abc123"
        }"#;
        let resp: ProjectSearchResponse = serde_json::from_str(raw).expect("parse");
        assert_eq!(resp.projects.len(), 1);
        assert_eq!(resp.projects[0].project_id, "my-proj");
        assert_eq!(resp.projects[0].display_name, "My Proj");
        assert_eq!(resp.next_page_token.as_deref(), Some("abc123"));
    }

    #[test]
    fn decodes_missing_optionals() {
        // No nextPageToken, project missing displayName/createTime.
        let raw = r#"{"projects":[{"projectId":"p2","state":"ACTIVE"}]}"#;
        let resp: ProjectSearchResponse = serde_json::from_str(raw).expect("parse");
        assert_eq!(resp.projects.len(), 1);
        assert_eq!(resp.projects[0].project_id, "p2");
        assert_eq!(resp.projects[0].display_name, "");
        assert_eq!(resp.projects[0].create_time, "");
        assert!(resp.next_page_token.is_none());
    }

    #[test]
    fn decodes_empty_response() {
        let resp: ProjectSearchResponse = serde_json::from_str("{}").expect("parse");
        assert!(resp.projects.is_empty());
        assert!(resp.next_page_token.is_none());
    }

    #[test]
    fn pagination_token_present_and_absent() {
        let with = r#"{"projects":[],"nextPageToken":"tok"}"#;
        let without = r#"{"projects":[]}"#;
        let a: ProjectSearchResponse = serde_json::from_str(with).unwrap();
        let b: ProjectSearchResponse = serde_json::from_str(without).unwrap();
        assert_eq!(a.next_page_token.as_deref(), Some("tok"));
        assert!(b.next_page_token.is_none());
    }

    #[test]
    fn project_id_charset_validation() {
        assert!(is_valid_project_id("my-project-123"));
        assert!(is_valid_project_id("abc"));
        assert!(!is_valid_project_id(""));
        assert!(!is_valid_project_id("Bad_Upper"));
        assert!(!is_valid_project_id("has space"));
        assert!(!is_valid_project_id("slash/inject"));
        assert!(!is_valid_project_id("q?query=1"));
    }
}
