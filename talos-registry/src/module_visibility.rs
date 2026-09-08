//! "Can this user load this module?" — asked THREE ways, in one place.
//!
//! [`ModuleRegistry::get_module`](crate::ModuleRegistry::get_module) is the
//! dispatch-time read, and it folds two different answers into one `Err`: a
//! genuinely absent row and a database failure both arrive as
//! `anyhow::Error`, the first with the text "Module not found or access
//! denied". That is correct for the dispatcher — either way the job cannot
//! run — and it is exactly wrong for a caller that must DECIDE something,
//! which is why the 2026-09-07 package recorded "no three-valued
//! module-visibility read exists" as the reason a push channel's `module_id`
//! was never validated at create time.
//!
//! This module is that read. The predicate is deliberately byte-identical to
//! `get_module`'s — `id = $1 AND (user_id = $2 OR user_id IS NULL)`, the
//! `NULL` arm being the shared catalog — so a create-time gate and the
//! dispatch that follows it answer with ONE rule. A gate that is stricter or
//! looser than the load it guards is a third answer to a question that
//! already has two.

use std::collections::HashMap;

use sqlx::{Pool, Postgres};
use uuid::Uuid;

/// Whether a module is loadable by a given user.
///
/// `#[must_use]`, with no `Into<Option>`, no `is_visible()` boolean and no
/// `.ok()`: a boolean gate is one `unwrap_or(true)` from failing open, and its
/// caller could not tell a module that does not exist from a database that did
/// not answer when it renders the refusal. Same shape as
/// `ExecutionLookup` (#748) and `WorkflowDispatchLookup` (#777).
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum ModuleVisibility {
    /// The row exists and this user may load it. Carries the name so a caller
    /// that also wants to display it does not need a second read.
    Visible { name: String },
    /// The query answered, and no row matched. Collapses "no such module" and
    /// "someone else's module" DELIBERATELY: splitting them in a
    /// caller-facing message hands anyone who can guess a uuid a module
    /// EXISTENCE oracle (the `caller_facing_unauthorized` argument, and #754's
    /// collapsed `write_ceiling_unreadable` reply). The operator keeps the
    /// distinction in the log, not the caller.
    Absent,
    /// The query did not answer. NOT `Absent`: refusing with "that module does
    /// not exist" while the database is the broken thing is the determinate
    /// negative checks 74 / 79 / 81 exist to remove.
    Unreadable,
}

impl ModuleVisibility {
    /// The module's name, when there is one. Never a fabricated name for an
    /// `Absent` or `Unreadable` answer.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Visible { name } => Some(name.as_str()),
            _ => None,
        }
    }
}

/// The shared predicate, as SQL. One home, so the single-id gate and the
/// batched list read cannot drift apart — and so a reader can see at a glance
/// that it matches `get_module`'s.
const VISIBLE_PREDICATE: &str = "SELECT id, name FROM modules \
                                 WHERE id = ANY($1) AND (user_id = $2 OR user_id IS NULL)";

#[derive(sqlx::FromRow)]
struct VisibleRow {
    id: Uuid,
    name: String,
}

/// Three-valued visibility for ONE module. Used by the push-channel create
/// gates, which must refuse a binding they cannot vouch for.
///
/// The database error is logged here rather than returned: it carries schema
/// and query detail that must not reach an API response, and having one home
/// for that log means a new caller cannot forget it.
pub async fn module_visibility(
    pool: &Pool<Postgres>,
    module_id: Uuid,
    user_id: Uuid,
) -> ModuleVisibility {
    match visible_module_names(pool, &[module_id], user_id).await {
        Ok(map) => match map.into_iter().next() {
            Some((_, name)) => ModuleVisibility::Visible { name },
            None => ModuleVisibility::Absent,
        },
        Err(e) => {
            tracing::warn!(
                target: "talos_audit",
                event_kind = "module_visibility_unreadable",
                %module_id,
                %user_id,
                error = %e,
                "module-visibility lookup failed; reported as unreadable, not as absent"
            );
            ModuleVisibility::Unreadable
        }
    }
}

/// Batched visibility for MANY modules, as the lookup's OWN `Result`.
///
/// The `Result` is the return type on purpose — every caller here feeds
/// `talos_push_channel_inventory::classify_module_binding`, which reads the
/// `Result` rather than a flattened `Option` so that "the query failed" cannot
/// be spelled as "the module is gone" by a defaulted argument.
pub async fn visible_module_names(
    pool: &Pool<Postgres>,
    module_ids: &[Uuid],
    user_id: Uuid,
) -> Result<HashMap<Uuid, String>, sqlx::Error> {
    if module_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let rows: Vec<VisibleRow> = sqlx::query_as(VISIBLE_PREDICATE)
        .bind(module_ids)
        .bind(user_id)
        .fetch_all(pool)
        .await?;
    Ok(rows.into_iter().map(|r| (r.id, r.name)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The gate and the load it guards must ask the same question. If
    /// `get_module`'s predicate ever changes, this fails and the reader is
    /// pointed at the drift rather than discovering it as a channel that
    /// passes creation and fails every push.
    #[test]
    fn the_predicate_matches_the_dispatch_time_load() {
        assert!(VISIBLE_PREDICATE.contains("(user_id = $2 OR user_id IS NULL)"));
        let dispatch_read = include_str!("lib.rs");
        assert!(
            dispatch_read.contains("AND (user_id = $2 OR user_id IS NULL)"),
            "ModuleRegistry::get_module's tenancy predicate moved; \
             module_visibility must move with it"
        );
    }

    #[test]
    fn a_name_is_only_available_for_a_visible_module() {
        assert_eq!(
            ModuleVisibility::Visible {
                name: "gcp-alert-normalize".into()
            }
            .name(),
            Some("gcp-alert-normalize")
        );
        assert_eq!(ModuleVisibility::Absent.name(), None);
        assert_eq!(ModuleVisibility::Unreadable.name(), None);
    }
}
