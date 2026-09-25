//! GitHub App platform configuration (RFC 0008 — resolves open-question 2).
//!
//! The App credentials are **platform-level**, not per-user — one operator
//! registers one GitHub App per Talos deployment. So they are provisioned the
//! same way every other platform credential is (master DEK, LLM keys, the Vault
//! token): the bootstrap / k8s Secret, surfaced as env vars. The per-user
//! `SecretsManager` vault is for user/module secrets, not platform infra creds.
//!
//! | env var                     | secret? | use                              |
//! |-----------------------------|---------|----------------------------------|
//! | `GITHUB_APP_ID`             | no      | JWT `iss`; presence = App enabled |
//! | `GITHUB_APP_SLUG`           | no      | install-redirect URL (B2b)        |
//! | `GITHUB_APP_PRIVATE_KEY`    | YES     | RS256 signing key (PEM)           |
//! | `GITHUB_APP_WEBHOOK_SECRET` | YES     | App webhook HMAC secret (B5)      |
//! | `GITHUB_APP_CLIENT_ID`      | no      | user-authorization (connect flow) |
//! | `GITHUB_APP_CLIENT_SECRET`  | YES     | user-authorization token exchange |
//! | `GITHUB_APP_REDIRECT_URI`   | no      | the App's registered Callback URL |
//!
//! The last three are ALL-OR-NOTHING and OPTIONAL: without them the App still
//! mints installation tokens for installations already connected, but the
//! connect flow refuses to run — it cannot prove the connecting user can access
//! the installation GitHub's Setup-URL redirect names (that `installation_id` is
//! spoofable, per GitHub's own docs), and claiming it without that proof is the
//! installation-takeover defect fixed 2026-09-25.
//!
//! Secrets are held in [`Zeroizing`] and redacted from `Debug`. Empty / blank
//! env values are treated as unset (the empty-env-bypass hardening class).

use zeroize::Zeroizing;

use crate::app_jwt::AppSigningKey;
use crate::error::GithubAppError;

const ENV_APP_ID: &str = "GITHUB_APP_ID";
const ENV_APP_SLUG: &str = "GITHUB_APP_SLUG";
const ENV_PRIVATE_KEY: &str = "GITHUB_APP_PRIVATE_KEY";
const ENV_WEBHOOK_SECRET: &str = "GITHUB_APP_WEBHOOK_SECRET";
const ENV_CLIENT_ID: &str = "GITHUB_APP_CLIENT_ID";
const ENV_CLIENT_SECRET: &str = "GITHUB_APP_CLIENT_SECRET";
const ENV_REDIRECT_URI: &str = "GITHUB_APP_REDIRECT_URI";

/// The App's user-authorization (OAuth web flow) credentials. The connect flow
/// uses them to obtain a short-lived user token for the person connecting and
/// check the installation is theirs to claim. `Debug` redacts the secret.
#[derive(Clone)]
pub struct GithubUserAuthConfig {
    pub client_id: String,
    client_secret: Zeroizing<String>,
    /// Must equal a Callback URL registered on the App (e.g.
    /// `https://talos.example.com/api/github/authorized`).
    pub redirect_uri: String,
}

impl std::fmt::Debug for GithubUserAuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GithubUserAuthConfig")
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .field("redirect_uri", &self.redirect_uri)
            .finish()
    }
}

impl GithubUserAuthConfig {
    /// Build from explicit values; every field must be non-blank and the
    /// redirect URI must be an absolute `http(s)://` URL.
    pub fn from_values(
        client_id: String,
        client_secret: String,
        redirect_uri: String,
    ) -> Result<Self, GithubAppError> {
        let client_id = require_non_blank(ENV_CLIENT_ID, client_id)?;
        let client_secret = require_non_blank(ENV_CLIENT_SECRET, client_secret)?;
        let redirect_uri = require_non_blank(ENV_REDIRECT_URI, redirect_uri)?;
        if !(redirect_uri.starts_with("https://") || redirect_uri.starts_with("http://")) {
            return Err(GithubAppError::Config(format!(
                "{ENV_REDIRECT_URI} must be an absolute http(s) URL"
            )));
        }
        Ok(Self {
            client_id,
            client_secret: Zeroizing::new(client_secret),
            redirect_uri,
        })
    }

    /// The OAuth client secret (the user-token exchange only).
    pub fn client_secret(&self) -> &str {
        &self.client_secret
    }

    /// Read the three vars. `Ok(None)` when all are unset/blank; `Err` when
    /// some but not all are set — a half-configured connect flow fails loudly,
    /// the same policy as the App's own companions.
    fn from_env() -> Result<Option<Self>, GithubAppError> {
        let id = env_non_blank(ENV_CLIENT_ID);
        let secret = env_non_blank(ENV_CLIENT_SECRET);
        let redirect = env_non_blank(ENV_REDIRECT_URI);
        match (id, secret, redirect) {
            (None, None, None) => Ok(None),
            (Some(id), Some(secret), Some(redirect)) => {
                Self::from_values(id, secret, redirect).map(Some)
            }
            _ => Err(GithubAppError::Config(format!(
                "{ENV_CLIENT_ID}, {ENV_CLIENT_SECRET} and {ENV_REDIRECT_URI} must be set \
                 together (GitHub App user authorization is half-configured)"
            ))),
        }
    }
}

/// Resolved, validated GitHub App platform config.
///
/// `Clone` is derived (the secret fields are `Zeroizing`, which clones) so the
/// controller can hand the same config to both the connect service and the
/// token resolver. Both copies zeroize on drop.
#[derive(Clone)]
pub struct GithubAppConfig {
    pub app_id: String,
    pub app_slug: String,
    webhook_secret: Zeroizing<String>,
    private_key_pem: Zeroizing<String>,
    /// `None` = the connect flow is disabled (see the module docs).
    user_auth: Option<GithubUserAuthConfig>,
}

impl std::fmt::Debug for GithubAppConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GithubAppConfig")
            .field("app_id", &self.app_id)
            .field("app_slug", &self.app_slug)
            .field("webhook_secret", &"<redacted>")
            .field("private_key_pem", &"<redacted>")
            .field("user_auth", &self.user_auth)
            .finish()
    }
}

impl GithubAppConfig {
    /// Build from explicit values (the testable core of [`from_env`]). Rejects
    /// empty/blank fields and verifies the private key actually parses, so a
    /// misconfiguration fails at load time, not on the first mint.
    ///
    /// [`from_env`]: GithubAppConfig::from_env
    pub fn from_values(
        app_id: String,
        app_slug: String,
        private_key_pem: String,
        webhook_secret: String,
    ) -> Result<Self, GithubAppError> {
        let app_id = require_non_blank(ENV_APP_ID, app_id)?;
        let app_slug = require_non_blank(ENV_APP_SLUG, app_slug)?;
        let private_key_pem = require_non_blank(ENV_PRIVATE_KEY, private_key_pem)?;
        let webhook_secret = require_non_blank(ENV_WEBHOOK_SECRET, webhook_secret)?;

        let cfg = Self {
            app_id,
            app_slug,
            webhook_secret: Zeroizing::new(webhook_secret),
            private_key_pem: Zeroizing::new(private_key_pem),
            user_auth: None,
        };
        // Fail fast: a malformed key should error at config load, not at first use.
        cfg.signing_key()?;
        Ok(cfg)
    }

    /// Load from the environment.
    ///
    /// * `Ok(None)` — `GITHUB_APP_ID` is unset/blank: GitHub App support is
    ///   simply disabled (it's optional).
    /// * `Err` — partially configured (app id present but another required field
    ///   missing/blank, or the key won't parse). A half-config fails LOUDLY
    ///   rather than silently disabling the feature.
    pub fn from_env() -> Result<Option<Self>, GithubAppError> {
        let Some(app_id) = env_non_blank(ENV_APP_ID) else {
            return Ok(None);
        };
        let cfg = Self::from_values(
            app_id,
            env_required(ENV_APP_SLUG)?,
            env_required(ENV_PRIVATE_KEY)?,
            env_required(ENV_WEBHOOK_SECRET)?,
        )?;
        let cfg = match GithubUserAuthConfig::from_env()? {
            Some(user_auth) => cfg.with_user_auth(user_auth),
            None => cfg,
        };
        Ok(Some(cfg))
    }

    /// Attach the user-authorization credentials the connect flow needs.
    pub fn with_user_auth(mut self, user_auth: GithubUserAuthConfig) -> Self {
        self.user_auth = Some(user_auth);
        self
    }

    /// The user-authorization credentials; `None` = connect flow disabled.
    pub fn user_auth(&self) -> Option<&GithubUserAuthConfig> {
        self.user_auth.as_ref()
    }

    /// Parse the configured private key into a signing key.
    pub fn signing_key(&self) -> Result<AppSigningKey, GithubAppError> {
        AppSigningKey::from_pem(&self.private_key_pem)
    }

    /// The App webhook HMAC secret (B5 — verifying App-delivered webhooks).
    pub fn webhook_secret(&self) -> &str {
        &self.webhook_secret
    }

    /// Build a live API client for this App (feature `client`).
    #[cfg(feature = "client")]
    pub fn client(&self) -> Result<crate::GithubAppClient, GithubAppError> {
        let key = self.signing_key()?;
        crate::GithubAppClient::new(key, self.app_id.clone())
            .map_err(|e| GithubAppError::Config(format!("build client: {e}")))
    }
}

/// An env value with empty/blank treated as unset (empty-env-bypass hardening).
fn env_non_blank(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

/// A required companion env var (once `GITHUB_APP_ID` is set).
fn env_required(name: &str) -> Result<String, GithubAppError> {
    env_non_blank(name).ok_or_else(|| {
        GithubAppError::Config(format!(
            "{name} is required when {ENV_APP_ID} is set (GitHub App is half-configured)"
        ))
    })
}

fn require_non_blank(name: &str, value: String) -> Result<String, GithubAppError> {
    if value.trim().is_empty() {
        return Err(GithubAppError::Config(format!(
            "{name} must be a non-empty, non-blank value"
        )));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs8::{EncodePrivateKey, LineEnding};
    use rsa::RsaPrivateKey;

    fn test_key_pem() -> String {
        let mut rng = rand::thread_rng();
        RsaPrivateKey::new(&mut rng, 2048)
            .unwrap()
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap()
            .as_str()
            .to_string()
    }

    #[test]
    fn from_values_ok_and_signing_key_parses() {
        let cfg = GithubAppConfig::from_values(
            "123".into(),
            "my-app".into(),
            test_key_pem(),
            "whsec".into(),
        )
        .unwrap();
        assert_eq!(cfg.app_id, "123");
        assert_eq!(cfg.app_slug, "my-app");
        assert_eq!(cfg.webhook_secret(), "whsec");
        assert!(cfg.signing_key().is_ok());
    }

    #[test]
    fn rejects_blank_fields() {
        let k = test_key_pem();
        assert!(
            GithubAppConfig::from_values("  ".into(), "a".into(), k.clone(), "s".into()).is_err()
        );
        assert!(
            GithubAppConfig::from_values("1".into(), "".into(), k.clone(), "s".into()).is_err()
        );
        assert!(
            GithubAppConfig::from_values("1".into(), "a".into(), "   ".into(), "s".into()).is_err()
        );
        assert!(GithubAppConfig::from_values("1".into(), "a".into(), k, "".into()).is_err());
    }

    #[test]
    fn rejects_unparseable_key() {
        let err =
            GithubAppConfig::from_values("1".into(), "a".into(), "not a pem".into(), "s".into());
        assert!(err.is_err());
    }

    #[test]
    fn user_auth_rejects_blank_fields_and_a_relative_redirect() {
        let ok = || {
            GithubUserAuthConfig::from_values(
                "Iv1.abc".into(),
                "shh".into(),
                "https://talos.example/api/github/authorized".into(),
            )
        };
        assert!(ok().is_ok());
        assert!(
            GithubUserAuthConfig::from_values(" ".into(), "s".into(), "https://x/y".into())
                .is_err()
        );
        assert!(
            GithubUserAuthConfig::from_values("i".into(), "".into(), "https://x/y".into()).is_err()
        );
        assert!(GithubUserAuthConfig::from_values(
            "i".into(),
            "s".into(),
            "/api/github/authorized".into()
        )
        .is_err());
    }

    #[test]
    fn user_auth_debug_redacts_the_client_secret() {
        let ua = GithubUserAuthConfig::from_values(
            "Iv1.abc".into(),
            "client-SECRET-must-not-leak".into(),
            "https://talos.example/api/github/authorized".into(),
        )
        .unwrap();
        let cfg = GithubAppConfig::from_values("1".into(), "a".into(), test_key_pem(), "w".into())
            .unwrap()
            .with_user_auth(ua);
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("Iv1.abc"));
        assert!(!dbg.contains("client-SECRET-must-not-leak"));
        assert_eq!(
            cfg.user_auth().unwrap().client_secret(),
            "client-SECRET-must-not-leak"
        );
    }

    #[test]
    fn debug_redacts_secrets() {
        let cfg = GithubAppConfig::from_values(
            "1".into(),
            "a".into(),
            test_key_pem(),
            "supersecret".into(),
        )
        .unwrap();
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains("supersecret"));
        assert!(!dbg.contains("PRIVATE"));
    }
}
