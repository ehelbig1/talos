//! Plaid environment selection and app credentials.
//!
//! Plaid issues a DIFFERENT secret per environment and serves each from its
//! own host. Picking the host from a string is therefore a security decision,
//! not a formatting one: a sandbox secret sent to the production host is a
//! failed request, but a production secret sent anywhere it does not belong is
//! a credential disclosed to the wrong endpoint. The environment is a closed
//! enum and an unrecognised value REFUSES rather than defaulting.

use std::fmt;

/// Which Plaid environment this deployment talks to.
///
/// Deliberately has no `Default`. There is no safe guess: defaulting to
/// sandbox silently makes a production deployment read nothing, and defaulting
/// to production points real credentials at real banks because a variable was
/// misspelt. An operator states it or the integration stays off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaidEnv {
    Sandbox,
    Production,
}

impl PlaidEnv {
    /// Parse the `PLAID_ENV` value. Case-insensitive, trimmed; anything else
    /// is `None` so the caller refuses instead of guessing.
    ///
    /// `development` is deliberately NOT accepted: Plaid retired that
    /// environment, and silently treating it as sandbox or production would be
    /// exactly the guess this function exists to avoid.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "sandbox" => Some(Self::Sandbox),
            "production" => Some(Self::Production),
            _ => None,
        }
    }

    /// The API host for this environment. A fixed, known host — which is what
    /// makes `build_integration_client` (rather than the SSRF-resolving
    /// outbound client) the right tool.
    #[must_use]
    pub const fn host(self) -> &'static str {
        match self {
            Self::Sandbox => "https://sandbox.plaid.com",
            Self::Production => "https://production.plaid.com",
        }
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sandbox => "sandbox",
            Self::Production => "production",
        }
    }

    /// True when this environment can reach a real person's real bank account.
    /// Used to decide how loudly to log and whether sandbox-only helpers are
    /// permitted to run at all.
    #[must_use]
    pub const fn is_live_money(self) -> bool {
        matches!(self, Self::Production)
    }
}

/// Plaid app credentials, read from the environment.
///
/// `client_id` is not secret (it appears in Link tokens); `secret` is. The
/// hand-written `Debug` below is what keeps the secret out of a panic message,
/// a `tracing` field, or an `anyhow` chain — deriving `Debug` here is lint 37's
/// defect and would leak on the first error anyone prints.
#[derive(Clone)]
pub struct PlaidConfig {
    pub client_id: String,
    secret: String,
    pub env: PlaidEnv,
}

impl PlaidConfig {
    /// Build from explicit values. The secret is moved in and never exposed
    /// again except through [`PlaidConfig::secret`].
    #[must_use]
    pub fn new(client_id: String, secret: String, env: PlaidEnv) -> Self {
        Self {
            client_id,
            secret,
            env,
        }
    }

    /// The API secret. Kept behind a method rather than a public field so
    /// every read site is greppable.
    #[must_use]
    pub fn secret(&self) -> &str {
        &self.secret
    }

    /// Read `PLAID_CLIENT_ID`, `PLAID_SECRET` and `PLAID_ENV`.
    ///
    /// Returns `Ok(None)` when the integration is simply not configured —
    /// absent or empty credentials are "off", not an error, so a deployment
    /// that does not use Plaid boots cleanly. A PARTIAL or INVALID
    /// configuration is an `Err`: it means someone intended to enable this and
    /// got it wrong, and silently running with it off would hide that.
    ///
    /// An empty string counts as absent (check 73's rule: a Helm placeholder
    /// or a bare `export PLAID_SECRET=` must not read as configured).
    pub fn from_env() -> Result<Option<Self>, ConfigError> {
        // Each variable is read with its name as a LITERAL argument to
        // `std::env::var`, not through a helper taking the name as a
        // parameter. A closure would be tidier and would make these reads
        // invisible to `docs/configuration-reference.md`'s Component check
        // (check 89), which resolves readers textually — the doc row would
        // then claim a crate that, as far as any grep can tell, reads nothing.
        let id = non_empty(std::env::var("PLAID_CLIENT_ID").ok());
        let secret = non_empty(std::env::var("PLAID_SECRET").ok());
        let env_raw = non_empty(std::env::var("PLAID_ENV").ok());

        match (id, secret, env_raw) {
            (None, None, None) => Ok(None),
            (Some(client_id), Some(secret), Some(env_raw)) => match PlaidEnv::parse(&env_raw) {
                Some(env) => Ok(Some(Self::new(client_id, secret, env))),
                None => Err(ConfigError::UnknownEnv),
            },
            (id, secret, env_raw) => Err(ConfigError::Partial {
                client_id: id.is_some(),
                secret: secret.is_some(),
                env: env_raw.is_some(),
            }),
        }
    }
}

/// `Debug` that cannot leak the secret. The client id is shown because it is
/// not secret and is what an operator needs to tell two configurations apart.
impl fmt::Debug for PlaidConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PlaidConfig")
            .field("client_id", &self.client_id)
            .field("secret", &"[REDACTED]")
            .field("env", &self.env.as_str())
            .finish()
    }
}

/// Trim, and treat an empty string as ABSENT.
///
/// Check 73's rule: a Helm placeholder (`plaidSecret: ""`) or a bare
/// `export PLAID_SECRET=` must not read as configured.
fn non_empty(raw: Option<String>) -> Option<String> {
    raw.map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// Some of the three were set and some were not. Named per variable so the
    /// operator is told WHICH is missing without the value being echoed.
    Partial {
        client_id: bool,
        secret: bool,
        env: bool,
    },
    /// `PLAID_ENV` was set to something that is not a Plaid environment.
    UnknownEnv,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Partial {
                client_id,
                secret,
                env,
            } => {
                let mut missing = Vec::new();
                if !client_id {
                    missing.push("PLAID_CLIENT_ID");
                }
                if !secret {
                    missing.push("PLAID_SECRET");
                }
                if !env {
                    missing.push("PLAID_ENV");
                }
                write!(
                    f,
                    "Plaid is partially configured — missing {}. Set all three or none.",
                    missing.join(", ")
                )
            }
            Self::UnknownEnv => write!(
                f,
                "PLAID_ENV must be exactly 'sandbox' or 'production'; refusing to guess a host for an unrecognised value"
            ),
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_two_real_environments_parse() {
        assert_eq!(PlaidEnv::parse("sandbox"), Some(PlaidEnv::Sandbox));
        assert_eq!(PlaidEnv::parse("  Production "), Some(PlaidEnv::Production));
        assert_eq!(PlaidEnv::parse("SANDBOX"), Some(PlaidEnv::Sandbox));
        // Retired by Plaid. Guessing either way would point real credentials
        // at the wrong host, which is the whole reason this refuses.
        assert_eq!(PlaidEnv::parse("development"), None);
        assert_eq!(PlaidEnv::parse(""), None);
        assert_eq!(PlaidEnv::parse("prod"), None);
    }

    #[test]
    fn each_environment_has_its_own_host_and_they_differ() {
        assert_eq!(PlaidEnv::Sandbox.host(), "https://sandbox.plaid.com");
        assert_eq!(PlaidEnv::Production.host(), "https://production.plaid.com");
        assert_ne!(PlaidEnv::Sandbox.host(), PlaidEnv::Production.host());
        // Every host is HTTPS. A plaintext host would send the secret in the
        // clear, and the hosts are constants so this is checkable here.
        for e in [PlaidEnv::Sandbox, PlaidEnv::Production] {
            assert!(e.host().starts_with("https://"), "{}", e.host());
        }
    }

    #[test]
    fn only_production_is_live_money() {
        assert!(PlaidEnv::Production.is_live_money());
        assert!(!PlaidEnv::Sandbox.is_live_money());
    }

    /// The regression lint 37 exists for: a secret must not be printable.
    #[test]
    fn debug_never_renders_the_secret() {
        let c = PlaidConfig::new(
            "client-abc".into(),
            "super-secret-value".into(),
            PlaidEnv::Sandbox,
        );
        let rendered = format!("{c:?}");
        assert!(
            !rendered.contains("super-secret-value"),
            "the secret leaked into Debug: {rendered}"
        );
        assert!(rendered.contains("[REDACTED]"));
        // The client id is NOT secret and is what tells two configs apart.
        assert!(rendered.contains("client-abc"));
        // And the accessor still returns it, so redaction is a rendering
        // property rather than the value being lost.
        assert_eq!(c.secret(), "super-secret-value");
    }

    #[test]
    fn a_partial_configuration_names_what_is_missing_without_echoing_values() {
        let e = ConfigError::Partial {
            client_id: true,
            secret: false,
            env: false,
        };
        let msg = e.to_string();
        assert!(msg.contains("PLAID_SECRET"));
        assert!(msg.contains("PLAID_ENV"));
        assert!(
            !msg.contains("PLAID_CLIENT_ID"),
            "a variable that IS set must not be listed as missing: {msg}"
        );
    }

    #[test]
    fn an_unknown_environment_refuses_rather_than_defaulting() {
        let msg = ConfigError::UnknownEnv.to_string();
        assert!(msg.contains("sandbox"));
        assert!(msg.contains("production"));
        assert!(
            msg.contains("refusing"),
            "the message must say it refused, not merely what is valid: {msg}"
        );
    }
}
