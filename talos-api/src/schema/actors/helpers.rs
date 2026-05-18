//! Shared helpers for the actors GraphQL surface. Everything here is
//! `pub(super)` — these are private to the `actors` module.
//!
//! The motivating duplicate: `create_actor`, `update_actor_status`,
//! `update_actor`, and `clone_actor` each need to re-fetch the actor
//! after a mutation in the GraphQL `ActorSummary` shape. Pre-extraction
//! the SELECT + row-mapping was paste-duplicated four times. Now there's
//! one place: `fetch_actor_summary_post_mutation`.

use sqlx::PgPool;
use uuid::Uuid;

use crate::schema::types::ActorSummary;

/// Re-fetch an actor in the GraphQL `ActorSummary` shape after a mutation.
///
/// Returns `Err(sqlx::Error::RowNotFound)` if the `(actor_id, user_id)` pair
/// doesn't match — callers treat that as "not found or access denied" using
/// whatever wording fits the surrounding handler. Errors are deliberately
/// returned as `sqlx::Error` (not `async_graphql::Error`) so each callsite
/// can keep its own error-message style: some use a tracing-error + generic
/// "Failed to fetch <verb> actor" wrapper, others use the bare
/// `e.extend_safe()` translation.
///
/// Behaviour is bit-for-bit identical to the four inline copies:
/// * Same SQL (correlated subqueries for `workflow_count` /
///   `total_executions`, scoped to `(a.id = $1 AND a.user_id = $2)`).
/// * Same defaults — `status` falls back to `"active"`,
///   `max_capability_world` to `"minimal-node"`, both counters to `0`.
/// * `total_budget_usd` and `spent_budget_usd` are surfaced as
///   `None` / `0.0` because the GraphQL handlers historically never
///   populated them in mutation contexts (budget tracking is owned by a
///   different code path; the inline copies all hardcoded these).
pub(super) async fn fetch_actor_summary_post_mutation(
    pool: &PgPool,
    actor_id: Uuid,
    user_id: Uuid,
) -> Result<ActorSummary, sqlx::Error> {
    let repo = talos_actor_repository::ActorRepository::new(pool.clone());
    let row = repo
        .get_actor_post_mutation_summary(actor_id, user_id)
        .await
        .map_err(|e| {
            // Repository returns anyhow::Error; downcast to sqlx::Error so the
            // caller's existing `.map_err(|e: sqlx::Error| ...)` translators
            // continue to work without each callsite learning about anyhow.
            e.downcast::<sqlx::Error>()
                .unwrap_or_else(|_| sqlx::Error::Protocol("actor summary fetch failed".into()))
        })?
        .ok_or(sqlx::Error::RowNotFound)?;

    Ok(ActorSummary {
        id: row.id,
        name: row.name,
        description: row.description,
        status: row.status.unwrap_or_else(|| "active".to_string()),
        max_capability_world: row
            .max_capability_world
            .unwrap_or_else(|| "minimal-node".to_string()),
        workflow_count: row.workflow_count,
        execution_count: row.total_executions,
        total_budget_usd: None,
        spent_budget_usd: 0.0,
        created_at: row.created_at.to_rfc3339(),
        updated_at: row.updated_at.to_rfc3339(),
    })
}
