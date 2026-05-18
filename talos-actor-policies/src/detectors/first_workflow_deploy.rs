//! `first_workflow_deploy` detector.
//!
//! Matches when the actor has no published workflow versions *yet*.
//! Evaluated inside the caller's transaction with a PostgreSQL
//! advisory lock keyed on `(tag, actor_id)` so concurrent publish
//! calls for the same actor serialize cleanly — exactly one of them
//! sees `is_first = true`, the others see `false`.
//!
//! The advisory lock is transaction-scoped (`pg_advisory_xact_lock`):
//! it releases on commit *or* rollback, so a blocked-and-rolled-back
//! tx doesn't leave a poisoned lock behind.

use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use super::DetectionResult;

/// Stable hash tag that gets paired with actor_id to form the
/// advisory-lock key. Using two 32-bit ints (hashtext result) with
/// `pg_advisory_xact_lock(bigint_hi, bigint_lo)` avoids collisions
/// with any other advisory lock in the system.
const ADVISORY_LOCK_TAG: &str = "actor_policy.first_workflow_deploy";

pub async fn detect(
    actor_id: Uuid,
    tx: &mut Transaction<'_, Postgres>,
) -> anyhow::Result<DetectionResult> {
    // Take the advisory lock first — serializes concurrent callers for
    // this same actor. The lock releases on tx commit/rollback.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2::text))")
        .bind(ADVISORY_LOCK_TAG)
        .bind(actor_id)
        .execute(&mut **tx)
        .await?;

    // After holding the lock, check: does this actor have any
    // `workflow_versions` row already? Join through `workflows` so we
    // catch versions on any of the actor's workflows.
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(\
             SELECT 1 \
             FROM workflow_versions wv \
             JOIN workflows w ON w.id = wv.workflow_id \
             WHERE w.actor_id = $1\
         )",
    )
    .bind(actor_id)
    .fetch_one(&mut **tx)
    .await?;

    if exists {
        Ok(DetectionResult::NoMatch)
    } else {
        Ok(DetectionResult::Match)
    }
}
