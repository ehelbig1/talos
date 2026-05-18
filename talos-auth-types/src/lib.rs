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

pub use claims::Claims;
pub use org_role::OrgRole;
pub use scope::ApiKeyScope;

/// Glob-friendly re-export so `use talos_auth_types::prelude::*;`
/// pulls in every type at once without bringing in the module names.
pub mod prelude {
    pub use super::{ApiKeyScope, Claims, OrgRole};
}
