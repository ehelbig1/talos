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
}

impl std::fmt::Debug for GithubAppConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GithubAppConfig")
            .field("app_id", &self.app_id)
            .field("app_slug", &self.app_slug)
            .field("webhook_secret", &"<redacted>")
            .field("private_key_pem", &"<redacted>")
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
        Ok(Some(cfg))
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
