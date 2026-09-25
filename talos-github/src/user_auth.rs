//! GitHub App **user authorization** — the proof the connect flow was missing.
//!
//! GitHub documents that the Setup-URL redirect's `installation_id` can be
//! spoofed and says to "generate a user access token for the user who installed
//! the GitHub App and then check that the installation is associated with that
//! user". This module is that check: exchange the web-flow `code` for a
//! short-lived user token ([`GithubUserAuthClient::exchange_code`]) and ask
//! GitHub whether the installation is among the ones that user can access
//! ([`GithubUserAuthClient::user_can_access_installation`], `GET
//! /user/installations`).
//!
//! The parsers are always compiled and unit-tested; the HTTP half is the
//! feature-gated [`GithubUserAuthClient`]. The user token is never stored, never
//! logged, and dropped (zeroized) as soon as the check returns.

use zeroize::Zeroizing;

use crate::error::GithubAppError;

/// GitHub's web host (authorize + token endpoints live here, not on the API).
pub const GITHUB_WEB_BASE: &str = "https://github.com";

/// `GET /user/installations` page size (GitHub's maximum).
pub const USER_INSTALLATIONS_PER_PAGE: usize = 100;

/// Pages read before giving up. 1 000 installations of ONE App visible to one
/// user is far past any real account; past it the answer is "could not verify",
/// which the caller refuses.
pub const USER_INSTALLATIONS_MAX_PAGES: usize = 10;

/// A GitHub user-to-server access token (`ghu_…`). `Debug` is redacted and the
/// value zeroizes on drop.
pub struct UserAccessToken(Zeroizing<String>);

impl std::fmt::Debug for UserAccessToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UserAccessToken(<redacted>)")
    }
}

impl UserAccessToken {
    pub fn secret(&self) -> &str {
        &self.0
    }
}

/// Parse `POST /login/oauth/access_token` (`Accept: application/json`).
///
/// GitHub answers a bad `code` with **HTTP 200** and an `error` body, so the
/// status alone is not the verdict; an `error` field is a refusal whatever the
/// status was. Only the error CODE is carried into the message — never the body.
pub fn parse_user_token_response(body: &[u8]) -> Result<UserAccessToken, GithubAppError> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| GithubAppError::ParseResponse(e.to_string()))?;
    if let Some(code) = v.get("error").and_then(|e| e.as_str()) {
        let code: String = code
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
            .take(64)
            .collect();
        return Err(GithubAppError::ParseResponse(format!(
            "user-token exchange refused: {code}"
        )));
    }
    match v.get("access_token").and_then(|t| t.as_str()) {
        Some(t) if !t.is_empty() => Ok(UserAccessToken(Zeroizing::new(t.to_string()))),
        _ => Err(GithubAppError::ParseResponse(
            "user-token response missing access_token".to_string(),
        )),
    }
}

/// One parsed `GET /user/installations` page: GitHub's `total_count` and the
/// installation ids on this page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserInstallationsPage {
    pub total_count: u64,
    pub installation_ids: Vec<i64>,
}

/// Parse one `GET /user/installations` page.
pub fn parse_user_installations_page(body: &[u8]) -> Result<UserInstallationsPage, GithubAppError> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| GithubAppError::ParseResponse(e.to_string()))?;
    let total_count = v
        .get("total_count")
        .and_then(|c| c.as_u64())
        .ok_or_else(|| {
            GithubAppError::ParseResponse("user installations missing total_count".to_string())
        })?;
    let list = v
        .get("installations")
        .and_then(|i| i.as_array())
        .ok_or_else(|| {
            GithubAppError::ParseResponse("user installations missing installations".to_string())
        })?;
    let installation_ids = list
        .iter()
        .map(|i| {
            i.get("id").and_then(|id| id.as_i64()).ok_or_else(|| {
                GithubAppError::ParseResponse("installation entry missing id".to_string())
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(UserInstallationsPage {
        total_count,
        installation_ids,
    })
}

/// What a scan of the user's installations concluded. Three-valued on purpose:
/// "GitHub did not list it" and "we could not read the whole list" are
/// different facts, though the connect flow refuses both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallationAccess {
    /// The installation is on the authorizing user's list.
    Accessible,
    /// The whole list was read and the installation is not on it.
    NotAccessible,
    /// The list is longer than [`USER_INSTALLATIONS_MAX_PAGES`] pages.
    TooManyToVerify,
}

#[cfg(feature = "client")]
pub use client::GithubUserAuthClient;

#[cfg(feature = "client")]
mod client {
    use std::time::Duration;

    use anyhow::{bail, Context, Result};

    use super::*;
    use crate::config::GithubUserAuthConfig;
    use crate::GITHUB_API_BASE;

    const HTTP_TIMEOUT: Duration = Duration::from_secs(15);
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);

    /// The App's user-authorization client: exchanges a web-flow `code` and
    /// reads the authorizing user's installations.
    pub struct GithubUserAuthClient {
        config: GithubUserAuthConfig,
        web_base: String,
        api_base: String,
        http: reqwest::Client,
    }

    impl std::fmt::Debug for GithubUserAuthClient {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("GithubUserAuthClient")
                .field("config", &self.config) // redacts itself
                .field("web_base", &self.web_base)
                .field("api_base", &self.api_base)
                .finish()
        }
    }

    impl GithubUserAuthClient {
        /// A client against github.com / api.github.com.
        pub fn new(config: GithubUserAuthConfig) -> Result<Self> {
            Self::with_bases(config, GITHUB_WEB_BASE, GITHUB_API_BASE)
        }

        /// A client against explicit bases. Tests point both at a loopback
        /// listener; deliberately NOT reachable from configuration.
        #[doc(hidden)]
        pub fn with_bases(
            config: GithubUserAuthConfig,
            web_base: impl Into<String>,
            api_base: impl Into<String>,
        ) -> Result<Self> {
            // Shared hardened builder: redirect-none (a redirect could replay the
            // client secret or the user token to another host) + connect timeout.
            let http = talos_http_utils::trusted_client::hardened_client_builder(HTTP_TIMEOUT)
                .connect_timeout(CONNECT_TIMEOUT)
                .build()
                .context("build GitHub user-authorization reqwest client")?;
            Ok(Self {
                config,
                web_base: web_base.into().trim_end_matches('/').to_string(),
                api_base: api_base.into().trim_end_matches('/').to_string(),
                http,
            })
        }

        pub fn authorize_url(&self) -> String {
            format!("{}/login/oauth/authorize", self.web_base)
        }

        pub fn token_url(&self) -> String {
            format!("{}/login/oauth/access_token", self.web_base)
        }

        pub fn config(&self) -> &GithubUserAuthConfig {
            &self.config
        }

        /// Exchange a web-flow `code` (+ its PKCE verifier) for a user token.
        pub async fn exchange_code(
            &self,
            code: &str,
            pkce_verifier: Option<&str>,
        ) -> Result<UserAccessToken> {
            let mut form: Vec<(&str, &str)> = vec![
                ("client_id", self.config.client_id.as_str()),
                ("client_secret", self.config.client_secret()),
                ("code", code),
                ("redirect_uri", self.config.redirect_uri.as_str()),
            ];
            if let Some(v) = pkce_verifier {
                form.push(("code_verifier", v));
            }
            let body = serde_urlencode(&form);
            let resp = self
                .http
                .post(self.token_url())
                .header("Accept", "application/json")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("User-Agent", "talos")
                .body(body)
                .send()
                .await
                .context("GitHub user-token exchange request failed")?;
            if !resp.status().is_success() {
                let status = resp.status();
                // Drain (capped) without logging: an error body can echo the
                // request, which carried the client secret.
                let _ = talos_http_body::read_error_text_capped(resp).await;
                bail!("GitHub user-token exchange returned HTTP {status}");
            }
            let body = talos_http_body::read_body_capped(
                resp,
                talos_http_body::DEFAULT_MAX_RESPONSE_BYTES,
            )
            .await
            .context("read GitHub user-token response")?;
            parse_user_token_response(&body).map_err(|e| anyhow::anyhow!("{e}"))
        }

        /// Is `installation_id` among the installations the token's user can
        /// access? Pages `GET /user/installations` until found, exhausted, or
        /// [`USER_INSTALLATIONS_MAX_PAGES`].
        pub async fn user_can_access_installation(
            &self,
            token: &UserAccessToken,
            installation_id: i64,
        ) -> Result<InstallationAccess> {
            let mut seen: u64 = 0;
            for page in 1..=USER_INSTALLATIONS_MAX_PAGES {
                let url = format!(
                    "{}/user/installations?per_page={USER_INSTALLATIONS_PER_PAGE}&page={page}",
                    self.api_base
                );
                let resp = self
                    .http
                    .get(&url)
                    .header("Authorization", format!("Bearer {}", token.secret()))
                    .header("Accept", "application/vnd.github+json")
                    .header("X-GitHub-Api-Version", "2022-11-28")
                    .header("User-Agent", "talos")
                    .send()
                    .await
                    .context("GitHub user-installations request failed")?;
                if !resp.status().is_success() {
                    let status = resp.status();
                    let _ = talos_http_body::read_error_text_capped(resp).await;
                    bail!("GitHub user-installations returned HTTP {status}");
                }
                let body = talos_http_body::read_body_capped(
                    resp,
                    talos_http_body::DEFAULT_MAX_RESPONSE_BYTES,
                )
                .await
                .context("read GitHub user-installations response")?;
                let parsed =
                    parse_user_installations_page(&body).map_err(|e| anyhow::anyhow!("{e}"))?;
                if parsed.installation_ids.contains(&installation_id) {
                    return Ok(InstallationAccess::Accessible);
                }
                seen += parsed.installation_ids.len() as u64;
                if parsed.installation_ids.is_empty() || seen >= parsed.total_count {
                    return Ok(InstallationAccess::NotAccessible);
                }
            }
            Ok(InstallationAccess::TooManyToVerify)
        }
    }

    /// `application/x-www-form-urlencoded` without pulling reqwest's `form`
    /// feature into a credential-bearing client for one call.
    fn serde_urlencode(pairs: &[(&str, &str)]) -> String {
        pairs
            .iter()
            .map(|(k, v)| format!("{}={}", pct(k), pct(v)))
            .collect::<Vec<_>>()
            .join("&")
    }

    fn pct(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for b in s.bytes() {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                out.push(b as char);
            } else {
                out.push_str(&format!("%{b:02X}"));
            }
        }
        out
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn form_encoding_escapes_reserved_bytes() {
            assert_eq!(
                serde_urlencode(&[("redirect_uri", "https://x.test/a?b=c&d")]),
                "redirect_uri=https%3A%2F%2Fx.test%2Fa%3Fb%3Dc%26d"
            );
            assert_eq!(serde_urlencode(&[("a", "b"), ("c", "d")]), "a=b&c=d");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_response_yields_the_token() {
        let t = parse_user_token_response(
            br#"{"access_token":"ghu_abc","token_type":"bearer","scope":"","expires_in":28800}"#,
        )
        .unwrap();
        assert_eq!(t.secret(), "ghu_abc");
        assert!(!format!("{t:?}").contains("ghu_abc"));
    }

    #[test]
    fn a_200_error_body_is_a_refusal_carrying_only_the_code() {
        let err = parse_user_token_response(
            br#"{"error":"bad_verification_code","error_description":"The code passed is incorrect or expired."}"#,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("bad_verification_code"));
        assert!(
            !err.contains("incorrect"),
            "the description is not carried: {err}"
        );
    }

    #[test]
    fn a_missing_or_empty_token_is_refused() {
        assert!(parse_user_token_response(br#"{"token_type":"bearer"}"#).is_err());
        assert!(parse_user_token_response(br#"{"access_token":""}"#).is_err());
        assert!(parse_user_token_response(b"not json").is_err());
    }

    #[test]
    fn an_installations_page_parses_ids_and_total() {
        let page = parse_user_installations_page(
            br#"{"total_count":3,"installations":[{"id":11,"account":{"login":"a"}},{"id":22}]}"#,
        )
        .unwrap();
        assert_eq!(page.total_count, 3);
        assert_eq!(page.installation_ids, vec![11, 22]);
    }

    #[test]
    fn a_malformed_installations_page_is_an_error_not_an_empty_list() {
        // An empty list would read as "not accessible"; a parse failure must
        // not be allowed to masquerade as that answer.
        assert!(parse_user_installations_page(br#"{"installations":[]}"#).is_err());
        assert!(parse_user_installations_page(br#"{"total_count":1}"#).is_err());
        assert!(
            parse_user_installations_page(br#"{"total_count":1,"installations":[{}]}"#).is_err()
        );
    }
}
