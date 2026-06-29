//! Installation account metadata (`GET /app/installations/{installation_id}`).
//!
//! The connect callback (B2b) needs the account login + permissions to persist
//! a [`talos_github_repository`-style] installation row. Like the token module,
//! the PARSE step is network-free and unit-tested here; the HTTP GET lives in
//! the feature-gated [`crate::GithubAppClient`].

use crate::error::GithubAppError;

/// Account metadata for an App installation.
#[derive(Debug, Clone)]
pub struct InstallationInfo {
    /// The GitHub account (org or user) the App is installed on.
    pub account_login: String,
    /// `"User"` or `"Organization"`.
    pub account_type: Option<String>,
    /// Permissions granted to the installation.
    pub permissions: serde_json::Value,
    /// `"all"` or `"selected"`.
    pub repository_selection: Option<String>,
}

/// Parse a `GET /app/installations/{id}` response body into [`InstallationInfo`].
pub fn parse_installation_info(body: &[u8]) -> Result<InstallationInfo, GithubAppError> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| GithubAppError::ParseResponse(e.to_string()))?;

    let account = v.get("account");
    let account_login = account
        .and_then(|a| a.get("login"))
        .and_then(|l| l.as_str())
        .ok_or_else(|| {
            GithubAppError::ParseResponse("installation response missing account.login".to_string())
        })?
        .to_string();
    let account_type = account
        .and_then(|a| a.get("type"))
        .and_then(|t| t.as_str())
        .map(str::to_string);
    let permissions = v
        .get("permissions")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let repository_selection = v
        .get("repository_selection")
        .and_then(|r| r.as_str())
        .map(str::to_string);

    Ok(InstallationInfo {
        account_login,
        account_type,
        permissions,
        repository_selection,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_org_installation() {
        let body = br#"{
            "id": 42,
            "account": { "login": "acme-org", "type": "Organization" },
            "repository_selection": "selected",
            "permissions": { "contents": "read", "pull_requests": "write" }
        }"#;
        let info = parse_installation_info(body).unwrap();
        assert_eq!(info.account_login, "acme-org");
        assert_eq!(info.account_type.as_deref(), Some("Organization"));
        assert_eq!(info.repository_selection.as_deref(), Some("selected"));
        assert_eq!(info.permissions["pull_requests"], "write");
    }

    #[test]
    fn parses_user_installation_minimal() {
        let body = br#"{"account":{"login":"octocat","type":"User"}}"#;
        let info = parse_installation_info(body).unwrap();
        assert_eq!(info.account_login, "octocat");
        assert_eq!(info.account_type.as_deref(), Some("User"));
        assert!(info.repository_selection.is_none());
        assert!(info.permissions.is_null());
    }

    #[test]
    fn rejects_missing_account_login() {
        let body = br#"{"id":1,"repository_selection":"all"}"#;
        assert!(parse_installation_info(body).is_err());
    }

    #[test]
    fn rejects_malformed_json() {
        assert!(parse_installation_info(b"not json").is_err());
    }
}
