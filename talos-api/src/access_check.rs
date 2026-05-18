//! Repository-style access-check helpers for the GraphQL surface.
//!
//! These centralise the "does this user have access to this row" SQL that
//! was previously paste-duplicated across every query/mutation handler.
//! Single audit point for the org-aware ACL — if the predicate ever needs
//! tightening (e.g. add tenant scoping, enforce a feature flag), only one
//! place changes.
//!
//! Most functions return `Result<_, sqlx::Error>` and let the caller pick
//! the user-facing wording (some sites want generic "Workflow not found",
//! others want a logged-detail-then-generic-message split).
//!
//! Exception: `authorize_execution_subscription` returns
//! `async_graphql::Error` directly. Subscription auth has a strict rule
//! that EVERY failure mode (not-found, unauthorized, DB error) must
//! surface as the same generic "Execution not found" — distinguishing
//! between them lets an attacker enumerate execution IDs. Centralising
//! that mapping here means the rule can't accidentally drift at one
//! callsite.

use sqlx::PgPool;
use uuid::Uuid;

use crate::schema::SafeErrorExtensions;

/// True iff `workflow_id` exists and either:
/// * `user_id` is the row's `user_id` (personal-owned workflow), OR
/// * `org_id` is in `org_ids` (org-shared workflow the caller can access).
///
/// `org_ids` is the caller-scoped list — readers should pass
/// `user_accessible_org_ids`, writers should pass `user_writable_org_ids`.
/// The repository doesn't know read-vs-write semantics; it only checks
/// against whatever org list the handler chose.
///
/// Empty `org_ids` short-circuits to "user-only" semantics — the
/// `org_id = ANY($3)` term still evaluates against an empty array (which
/// is always false), but skipping the bind is no faster on the SQL side.
pub(crate) async fn workflow_accessible_for_user(
    pool: &PgPool,
    workflow_id: Uuid,
    user_id: Uuid,
    org_ids: &[Uuid],
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM workflows \
         WHERE id = $1 AND (user_id = $2 OR org_id = ANY($3)))",
    )
    .bind(workflow_id)
    .bind(user_id)
    .bind(org_ids)
    .fetch_one(pool)
    .await
}

/// Authorize a caller to subscribe to a workflow execution.
///
/// Returns `Ok(())` iff the execution exists AND either:
/// * `caller_user_id` is the row's `user_id` (personal-owned), OR
/// * the row's `org_id` is set and the caller has at least `Viewer` in
///   that org (delegated to `OrganizationService::check_org_access`).
///
/// Returns `Err(async_graphql::Error::new("Execution not found"))` for
/// EVERY failure mode — not-found, unauthorized, or DB error. The
/// uniform wording is a security invariant: if the caller could
/// distinguish "exists but I can't see it" from "doesn't exist", they
/// could enumerate live execution IDs. DB errors are tracing::error!'d
/// server-side so operators can still diagnose them.
///
/// Two callsites today (`subscribeExecution`, `subscribeLlmStream`); any
/// future subscription that auths against an execution should call this
/// instead of re-implementing the JOIN + role check. If a future caller
/// also needs the row's `status` / `org_id` after the auth check, change
/// this to return a record — for now both callsites discard, so we
/// don't introduce dead public surface.
pub(crate) async fn authorize_execution_subscription(
    pool: &PgPool,
    execution_id: Uuid,
    caller_user_id: Uuid,
) -> Result<(), async_graphql::Error> {
    #[derive(sqlx::FromRow)]
    struct Row {
        user_id: Uuid,
        org_id: Option<Uuid>,
    }

    let row: Option<Row> = sqlx::query_as(
        "SELECT we.user_id, w.org_id \
         FROM workflow_executions we \
         LEFT JOIN workflows w ON w.id = we.workflow_id \
         WHERE we.id = $1",
    )
    .bind(execution_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        tracing::error!(
            execution_id = %execution_id,
            error = %e,
            "execution-subscription auth: db error"
        );
        // MCP-964 (2026-05-15): extend_safe so production scrubber
        // keeps "Execution not found" verbatim. The case-sensitive
        // "Not found" whitelist substring doesn't match the
        // lowercase 'n' in "Execution not found" → pre-fix this
        // got scrubbed to "Internal server error", muddying real
        // not-found cases against actual server errors.
        async_graphql::Error::new("Execution not found").extend_safe()
    })?;

    let row = row.ok_or_else(|| {
        async_graphql::Error::new("Execution not found").extend_safe()
    })?;

    if row.user_id == caller_user_id {
        return Ok(());
    }

    if let Some(org_id) = row.org_id {
        let ok = talos_organizations::OrganizationService::check_org_access(
            pool,
            org_id,
            caller_user_id,
            talos_organizations::OrgRole::Viewer,
        )
        .await
        .is_ok();
        if ok {
            return Ok(());
        }
    }

    // MCP-918: .extend_safe() — the uniform "Execution not found"
    // wording is an explicit security invariant (see fn doc), but the
    // production scrubber's whitelist is case-sensitive on "Not found"
    // (capital N), so the lowercase "not found" message was being
    // replaced with "Internal server error" — defeating the
    // uniform-wording invariant the doc-comment promises.
    Err(async_graphql::Error::new("Execution not found").extend_safe())
}
