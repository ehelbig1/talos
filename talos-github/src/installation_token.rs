//! GitHub App installation access tokens.
//!
//! Once we hold an App JWT (see [`crate::AppSigningKey`]), we exchange it for an
//! *installation access token* — a short-lived (1-hour), repo-scoped,
//! server-to-server credential — via
//! `POST /app/installations/{installation_id}/access_tokens`.
//!
//! This module is intentionally **network-free**: it builds the request parts
//! and parses the response. The actual HTTP call + token caching live in the
//! wiring layer (RFC 0008 B3) so this crate stays fully unit-testable and free
//! of an HTTP-client dependency.

use serde::Deserialize;
use zeroize::Zeroizing;

use crate::error::GithubAppError;

/// GitHub's public API base. Overridable for GitHub Enterprise Server (a future
/// non-goal) and for tests.
pub const GITHUB_API_BASE: &str = "https://api.github.com";

/// A minted installation access token.
///
/// `token` is a short-lived secret: it's held in a [`Zeroizing`] buffer, the
/// [`std::fmt::Debug`] impl redacts it, and it must never be logged (log its
/// presence / `expires_at` only).
pub struct InstallationToken {
    pub token: Zeroizing<String>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// The permissions actually granted to this token (GitHub echoes them).
    pub permissions: serde_json::Value,
    /// `"all"` or `"selected"` — the installation's repository selection.
    pub repository_selection: Option<String>,
}

impl std::fmt::Debug for InstallationToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstallationToken")
            .field("token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .field("repository_selection", &self.repository_selection)
            .finish()
    }
}

/// Wire DTO — separated from [`InstallationToken`] so the public type can wrap
/// the token in `Zeroizing` (which doesn't derive `Deserialize`).
#[derive(Deserialize)]
struct InstallationTokenWire {
    token: String,
    expires_at: String,
    #[serde(default)]
    permissions: serde_json::Value,
    #[serde(default)]
    repository_selection: Option<String>,
}

/// Build the URL + headers for the installation-token request. The App JWT
/// authorizes it (Bearer). Returned as parts so the HTTP call itself lives in
/// the wiring layer (keeps this crate network-free + unit-testable).
///
/// `api_base` is normally [`GITHUB_API_BASE`]; a trailing slash is tolerated.
pub fn installation_token_request(
    api_base: &str,
    installation_id: i64,
    app_jwt: &str,
) -> (String, Vec<(&'static str, String)>) {
    let url = format!(
        "{}/app/installations/{}/access_tokens",
        api_base.trim_end_matches('/'),
        installation_id
    );
    let headers = vec![
        ("Authorization", format!("Bearer {app_jwt}")),
        ("Accept", "application/vnd.github+json".to_string()),
        ("X-GitHub-Api-Version", "2022-11-28".to_string()),
        ("User-Agent", "talos".to_string()),
    ];
    (url, headers)
}

/// Parse the `POST .../access_tokens` response body into an [`InstallationToken`].
pub fn parse_installation_token_response(body: &[u8]) -> Result<InstallationToken, GithubAppError> {
    let wire: InstallationTokenWire =
        serde_json::from_slice(body).map_err(|e| GithubAppError::ParseResponse(e.to_string()))?;

    let expires_at = chrono::DateTime::parse_from_rfc3339(&wire.expires_at)
        .map_err(|e| GithubAppError::ParseResponse(format!("invalid expires_at: {e}")))?
        .with_timezone(&chrono::Utc);

    Ok(InstallationToken {
        token: Zeroizing::new(wire.token),
        expires_at,
        permissions: wire.permissions,
        repository_selection: wire.repository_selection,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_url_and_headers() {
        let (url, headers) = installation_token_request(GITHUB_API_BASE, 42, "JWT123");
        assert_eq!(
            url,
            "https://api.github.com/app/installations/42/access_tokens"
        );
        let map: std::collections::HashMap<_, _> = headers.into_iter().collect();
        assert_eq!(map["Authorization"], "Bearer JWT123");
        assert_eq!(map["Accept"], "application/vnd.github+json");
        assert_eq!(map["X-GitHub-Api-Version"], "2022-11-28");
        assert!(map.contains_key("User-Agent"));
    }

    #[test]
    fn request_tolerates_trailing_slash_and_ghes_base() {
        let (url, _) = installation_token_request("https://ghe.example.com/api/v3/", 7, "j");
        assert_eq!(
            url,
            "https://ghe.example.com/api/v3/app/installations/7/access_tokens"
        );
    }

    #[test]
    fn parses_github_response() {
        let body = br#"{
            "token": "ghs_exampletoken",
            "expires_at": "2026-06-27T13:00:00Z",
            "permissions": { "contents": "read", "pull_requests": "write" },
            "repository_selection": "selected"
        }"#;
        let t = parse_installation_token_response(body).unwrap();
        assert_eq!(&*t.token, "ghs_exampletoken");
        assert_eq!(t.repository_selection.as_deref(), Some("selected"));
        assert_eq!(t.permissions["pull_requests"], "write");
        assert_eq!(t.expires_at.to_rfc3339(), "2026-06-27T13:00:00+00:00");
    }

    #[test]
    fn parses_response_with_minimal_fields() {
        // permissions / repository_selection are optional in our DTO.
        let body = br#"{"token":"ghs_x","expires_at":"2026-06-27T13:00:00Z"}"#;
        let t = parse_installation_token_response(body).unwrap();
        assert_eq!(&*t.token, "ghs_x");
        assert!(t.repository_selection.is_none());
    }

    #[test]
    fn rejects_bad_expiry() {
        let body = br#"{"token":"x","expires_at":"not-a-date"}"#;
        assert!(parse_installation_token_response(body).is_err());
    }

    #[test]
    fn rejects_malformed_json() {
        assert!(parse_installation_token_response(b"{not json").is_err());
    }

    #[test]
    fn debug_redacts_token() {
        let body = br#"{"token":"ghs_supersecret","expires_at":"2026-06-27T13:00:00Z"}"#;
        let t = parse_installation_token_response(body).unwrap();
        let dbg = format!("{t:?}");
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains("ghs_supersecret"));
    }
}
