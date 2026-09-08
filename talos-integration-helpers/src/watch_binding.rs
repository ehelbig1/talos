//! The one gate a push-channel create applies to a caller-supplied `module_id`.
//!
//! A push channel may bind a WASM module: one inbound event → one dispatched
//! module job. Until 2026-09-08 all three integrations copied the caller's
//! `module_id` straight into the row with no check, and the first thing that
//! ever looked at it was the DISPATCH, weeks or months later. Measured live
//! 2026-09-07: the fleet's only module-binding channel named a module that
//! matches zero rows in `modules`, and had since it was created on 2026-07-17
//! — every push to it failing at load, with no surface saying so.
//!
//! This lives in the shared kernel rather than in each integration because the
//! three-arm mapping (`Visible` → allow, `Absent` → refuse, `Unreadable` →
//! refuse-differently) IS the decision, and two copies of a decision is two
//! answers to one question. The READ it consults —
//! `talos_registry::module_visibility` — is pinned equal to the predicate the
//! dispatch-time `ModuleRegistry::get_module` applies, so a create that passes
//! this gate is a load that will succeed.

use axum::http::StatusCode;
use sqlx::{Pool, Postgres};
use uuid::Uuid;

/// Why a channel's module binding was refused.
///
/// TWO variants, because "the module is not there" and "we could not look" are
/// different facts and only one of them is the caller's to fix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ModuleBindingRefusal {
    /// The query answered, and `module_id` names no module this user can load.
    ///
    /// **Deliberately one variant for "no such module" and "someone else's
    /// module"**: splitting them in the reply hands anyone who can guess a uuid
    /// a module EXISTENCE oracle (the `caller_facing_unauthorized` argument,
    /// and #754's collapsed `write_ceiling_unreadable` reply). The operator
    /// keeps the distinction, in [`Self::event_kind`].
    #[error("module binding names no module this user can load")]
    NotBindable,
    /// The visibility read itself failed. NOT [`Self::NotBindable`]: refusing
    /// with "that module does not exist" while the database is the broken thing
    /// is the determinate negative checks 74 / 79 / 81 exist to remove. The
    /// create is still refused — a channel minted on an unverified binding is
    /// exactly what this gate is for — but the caller is told to retry.
    #[error("module binding could not be verified")]
    Unreadable,
}

impl ModuleBindingRefusal {
    #[must_use]
    pub fn status_code(self) -> StatusCode {
        match self {
            Self::NotBindable => StatusCode::BAD_REQUEST,
            // Retryable: the rule could not be read, not broken.
            Self::Unreadable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    /// What the caller is told. One sentence for both absent-and-not-yours.
    #[must_use]
    pub fn user_facing_message(self) -> &'static str {
        match self {
            Self::NotBindable => {
                "module_id names no module you can load. A channel bound to it would fail \
                 every push at module load. Bind a module that exists, or omit module_id to \
                 create a channel that only acknowledges pushes."
            }
            Self::Unreadable => {
                "Could not verify the module binding right now, so the channel was not \
                 created. Retry shortly."
            }
        }
    }

    /// The operator-facing classification. This is where absent and unreadable
    /// stay apart.
    #[must_use]
    pub fn event_kind(self) -> &'static str {
        match self {
            Self::NotBindable => "watch_module_binding_absent",
            Self::Unreadable => "watch_module_binding_unreadable",
        }
    }
}

/// Refuse a channel whose `module_id` names no module this user can load.
///
/// `None` is not a failure: a channel that binds no module acknowledges pushes
/// and dispatches nothing, which is a deliberate configuration.
///
/// Call this BEFORE the create lock and before any write, so a refused create
/// leaves nothing behind.
pub async fn check_module_binding(
    pool: &Pool<Postgres>,
    user_id: Uuid,
    module_id: Option<Uuid>,
    integration: &'static str,
) -> Result<(), ModuleBindingRefusal> {
    use talos_registry::module_visibility::{module_visibility, ModuleVisibility};

    let Some(module_id) = module_id else {
        return Ok(());
    };
    let refusal = match module_visibility(pool, module_id, user_id).await {
        ModuleVisibility::Visible { .. } => return Ok(()),
        ModuleVisibility::Absent => ModuleBindingRefusal::NotBindable,
        ModuleVisibility::Unreadable => ModuleBindingRefusal::Unreadable,
    };
    tracing::warn!(
        target: "talos_audit",
        event_kind = refusal.event_kind(),
        integration,
        %user_id,
        %module_id,
        "refusing watch create: {}",
        refusal
    );
    Err(refusal)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The caller must not be able to tell "no such module" from "not yours".
    /// The operator must. Both halves, in one test, because a future edit that
    /// "helpfully" splits the message would otherwise pass silently.
    #[test]
    fn the_caller_sees_one_sentence_and_the_operator_sees_two_kinds() {
        assert_ne!(
            ModuleBindingRefusal::NotBindable.event_kind(),
            ModuleBindingRefusal::Unreadable.event_kind()
        );
        assert_ne!(
            ModuleBindingRefusal::NotBindable.user_facing_message(),
            ModuleBindingRefusal::Unreadable.user_facing_message()
        );
        // …and neither sentence may name the OWNER of a module, which is the
        // shape an existence oracle takes.
        for m in [
            ModuleBindingRefusal::NotBindable.user_facing_message(),
            ModuleBindingRefusal::Unreadable.user_facing_message(),
        ] {
            assert!(!m.contains("another user"));
            assert!(!m.contains("belongs to"));
            assert!(!m.contains("access denied"));
        }
    }

    /// An unreadable rule is retryable; an absent module is the caller's to fix.
    /// A single status for both would tell the caller to retry forever, or to
    /// stop retrying a transient fault.
    #[test]
    fn the_two_refusals_carry_different_statuses() {
        assert_eq!(
            ModuleBindingRefusal::NotBindable.status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            ModuleBindingRefusal::Unreadable.status_code(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
}
