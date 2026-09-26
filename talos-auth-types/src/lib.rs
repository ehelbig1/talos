//! Pure-data auth types shared across the Talos workspace.
//!
//! Extracted from `controller::auth`, `controller::api_keys`, and
//! `controller::organizations`. The structs/enums here are the bits a
//! consumer can reason about without pulling in `sqlx`, `bcrypt`,
//! `jsonwebtoken`, Postgres, or async machinery.
//!
//! - [`Claims`] — the JWT claim set issued + verified by the controller.
//! - [`ApiKeyScope`] — the per-route capability vocabulary stored on
//!   `api_keys.scopes`.
//! - [`OrgRole`] — privilege ordering for organisation members.
//!
//! Service code that constructs / validates these (`AuthService`,
//! `ApiKeyService`, `OrganizationService`) stays in `controller`.

mod claims;
mod org_role;
mod scope;

pub use claims::{Claims, SessionAuth};
pub use org_role::OrgRole;
pub use scope::ApiKeyScope;

/// Glob-friendly re-export so `use talos_auth_types::prelude::*;`
/// pulls in every type at once without bringing in the module names.
pub mod prelude {
    pub use super::{ApiKeyScope, Claims, OrgRole, SessionAuth};
}

/// Is browser-facing hardening required — `Secure` cookies, no GraphiQL, a
/// scrape token on `/metrics/prometheus`, no dev CSRF bypass?
///
/// True for every `RUST_ENV` except the development spellings (unset, empty,
/// `development`, `dev`, `local`, `test`). Until 2026-09-26 these controls
/// followed `is_production()` alone, so `docker-compose.prod.yml` — which runs
/// `RUST_ENV=staging` behind TLS — served non-`Secure` session cookies and an
/// unauthenticated metrics endpoint.
#[must_use]
pub fn browser_hardening_required() -> bool {
    hardening_required_for(std::env::var("RUST_ENV").ok().as_deref())
}

/// Pure core of [`browser_hardening_required`].
#[must_use]
pub fn hardening_required_for(rust_env: Option<&str>) -> bool {
    let v = rust_env
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default();
    !matches!(v.as_str(), "" | "development" | "dev" | "local" | "test")
}

#[cfg(test)]
mod hardening_tests {
    use super::hardening_required_for;

    #[test]
    fn only_development_spellings_relax_hardening() {
        for dev in [
            None,
            Some(""),
            Some("development"),
            Some(" Dev "),
            Some("local"),
            Some("test"),
        ] {
            assert!(!hardening_required_for(dev), "{dev:?}");
        }
        for hard in [
            Some("production"),
            Some("staging"),
            Some("prod"),
            Some("qa"),
        ] {
            assert!(hardening_required_for(hard), "{hard:?}");
        }
    }
}
