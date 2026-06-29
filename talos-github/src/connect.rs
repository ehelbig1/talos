//! Connect / install-flow helpers (RFC 0008 B2b).
//!
//! Pure, network-free pieces of the GitHub App install flow: building the
//! install-redirect URL and parsing the **untrusted** setup-callback query
//! params GitHub sends back. Isolated + unit-tested here (a security boundary —
//! `installation_id` is attacker-influenceable) so the controller handler that
//! wires them (B2b-2: CSRF state + session binding + `get_installation` +
//! upsert) stays thin over validated logic.

use crate::error::GithubAppError;

/// GitHub's `setup_action` on the post-install redirect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupAction {
    Install,
    Update,
}

/// Validated setup-callback parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupCallback {
    pub installation_id: i64,
    pub setup_action: SetupAction,
}

/// GitHub App slugs are ASCII alphanumeric + hyphens. Validating before
/// interpolating into the redirect URL prevents query/URL injection via a
/// malformed operator-configured slug.
fn validate_slug(slug: &str) -> Result<(), GithubAppError> {
    if slug.is_empty() || !slug.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err(GithubAppError::Config(format!(
            "invalid GitHub App slug (expected ASCII alphanumeric + hyphens): {slug:?}"
        )));
    }
    Ok(())
}

/// A CSRF `state` token byte must be URL-safe (RFC 3986 unreserved) so it can be
/// placed in the query string without encoding or injection risk.
fn is_url_safe_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~')
}

/// Build the GitHub App installation redirect URL. The browser is sent here to
/// choose repositories and install; GitHub then returns to the App's configured
/// Setup URL with `installation_id`, `setup_action`, and the echoed `state`.
///
/// Both inputs are charset-validated (slug + the caller-generated CSRF `state`)
/// so neither can inject into the URL.
pub fn install_url(app_slug: &str, state: &str) -> Result<String, GithubAppError> {
    validate_slug(app_slug)?;
    if state.is_empty() || !state.bytes().all(is_url_safe_token_byte) {
        return Err(GithubAppError::Config(
            "install_url: state must be a non-empty URL-safe token".to_string(),
        ));
    }
    Ok(format!(
        "https://github.com/apps/{app_slug}/installations/new?state={state}"
    ))
}

/// Parse + validate the untrusted setup-callback query params.
///
/// * `installation_id` — required; must be a positive integer.
/// * `setup_action` — `install` / `update`; absent defaults to `install` (a
///   direct install can omit it). Any other value (notably `request` — a pending
///   admin-approval with no installation yet) is rejected so the caller can
///   surface a clear "not approved" message instead of storing a bad row.
pub fn parse_setup_callback(
    installation_id: Option<&str>,
    setup_action: Option<&str>,
) -> Result<SetupCallback, GithubAppError> {
    let raw = installation_id
        .ok_or_else(|| GithubAppError::Config("missing installation_id".to_string()))?;
    let id: i64 = raw
        .parse()
        .map_err(|_| GithubAppError::Config("installation_id must be an integer".to_string()))?;
    if id <= 0 {
        return Err(GithubAppError::Config(
            "installation_id must be positive".to_string(),
        ));
    }

    let setup_action = match setup_action {
        Some("install") | None => SetupAction::Install,
        Some("update") => SetupAction::Update,
        Some(other) => {
            return Err(GithubAppError::Config(format!(
                "unsupported setup_action {other:?} (no installation to persist)"
            )))
        }
    };

    Ok(SetupCallback {
        installation_id: id,
        setup_action,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_url_ok() {
        let url = install_url("my-app", "abc123_-.~").unwrap();
        assert_eq!(
            url,
            "https://github.com/apps/my-app/installations/new?state=abc123_-.~"
        );
    }

    #[test]
    fn install_url_rejects_bad_slug() {
        assert!(install_url("bad slug", "s").is_err());
        assert!(install_url("evil/../path", "s").is_err());
        assert!(install_url("", "s").is_err());
        assert!(install_url("a?b=c", "s").is_err());
    }

    #[test]
    fn install_url_rejects_unsafe_state() {
        assert!(install_url("app", "").is_err());
        assert!(install_url("app", "has space").is_err());
        assert!(install_url("app", "inject&foo=bar").is_err());
    }

    #[test]
    fn parse_callback_install() {
        let c = parse_setup_callback(Some("12345"), Some("install")).unwrap();
        assert_eq!(c.installation_id, 12345);
        assert_eq!(c.setup_action, SetupAction::Install);
    }

    #[test]
    fn parse_callback_update_and_absent_action() {
        assert_eq!(
            parse_setup_callback(Some("7"), Some("update"))
                .unwrap()
                .setup_action,
            SetupAction::Update
        );
        // Absent action defaults to install.
        assert_eq!(
            parse_setup_callback(Some("7"), None).unwrap().setup_action,
            SetupAction::Install
        );
    }

    #[test]
    fn parse_callback_rejects_bad_installation_id() {
        assert!(parse_setup_callback(None, Some("install")).is_err());
        assert!(parse_setup_callback(Some(""), Some("install")).is_err());
        assert!(parse_setup_callback(Some("abc"), Some("install")).is_err());
        assert!(parse_setup_callback(Some("0"), Some("install")).is_err());
        assert!(parse_setup_callback(Some("-3"), Some("install")).is_err());
    }

    #[test]
    fn parse_callback_rejects_request_action() {
        // `request` = pending org-admin approval; no installation to store yet.
        let err = parse_setup_callback(Some("9"), Some("request"));
        assert!(err.is_err());
    }
}
