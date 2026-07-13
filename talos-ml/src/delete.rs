//! RFC 0011 — model deletion (the cleanup path the platform was missing).
//!
//! Deletes a registered model and (optionally) its dataset, owner-scoped.
//! Until this existed, test/demo classifiers were immortal: the only
//! removal paths were lifecycle archival or raw DB surgery.
//!
//! Safety gates, all checked BEFORE any delete:
//! - The model must belong to the caller (resolve_by_name is user-scoped;
//!   RLS on the tenant tx is the backstop).
//! - A model referenced by any of the caller's workflow graphs (a node
//!   config naming it — Smart Classifier / Model_Predict `MODEL_NAME`) is
//!   refused: deleting it would flip those nodes to permanent-error at the
//!   next run with no editor-visible cause.
//! - `delete_dataset` refuses when OTHER models still point at the dataset
//!   (`ml_models.dataset_id` is ON DELETE SET NULL, so dropping a shared
//!   dataset would silently orphan the siblings' training data).
//!
//! Row cleanup is schema-driven: `ml_model_versions`, `ml_shadow_stats`,
//! and `ml_disagreements` all cascade from the model row; `ml_examples`
//! cascade from the dataset row. No manual child deletes.
//!
//! Same cross-protocol shape as [`crate::provision::provision_classifier`].

use sqlx::PgPool;
use uuid::Uuid;

use crate::registry::ModelRegistry;
use crate::serve::invalidate_serving_cache;

#[derive(Debug)]
pub struct DeleteOutcome {
    pub model_id: Uuid,
    pub model_deleted: bool,
    /// The dataset id when one was attached, whether or not it was deleted.
    pub dataset_id: Option<Uuid>,
    pub dataset_deleted: bool,
}

#[derive(Debug)]
pub enum DeleteError {
    /// No model of that name owned by the caller (not-found and not-yours
    /// are deliberately indistinguishable).
    NotFound,
    /// The caller's workflows reference this model by name — count included.
    ReferencedByWorkflows(i64),
    /// `delete_dataset` was requested but other models still use the
    /// dataset — their names included (caller-owned, safe to show).
    DatasetShared(Vec<String>),
    Internal(anyhow::Error),
}

/// Escape LIKE metacharacters — backslash FIRST, then `%`/`_` (the
/// LIKE-escape order rule; see talos_search_service::escape_like, not a
/// dependency of this crate).
fn escape_like(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

/// Delete a model (and optionally its dataset), owner-scoped. `user_id` is
/// the SIGNED caller.
pub async fn delete_model(
    pool: &PgPool,
    name: &str,
    delete_dataset: bool,
    user_id: Uuid,
) -> Result<DeleteOutcome, DeleteError> {
    let mut tx = talos_db::begin_tenant_read_scoped(
        pool,
        &talos_tenancy::TenantReadScope::new(user_id, Vec::new()),
    )
    .await
    .map_err(|e| DeleteError::Internal(anyhow::anyhow!("open delete tx: {e}")))?;

    let Some(model) = ModelRegistry::resolve_by_name(&mut tx, name, user_id)
        .await
        .map_err(DeleteError::Internal)?
    else {
        return Err(DeleteError::NotFound);
    };

    // Refuse when any of the caller's workflow graphs reference the model by
    // name. Match the QUOTED name so an unrelated substring can't trip it;
    // model names allow `_` (a LIKE metachar), so escape before binding.
    // jsonb::text quoting makes `"<name>"` present for any node config value
    // equal to the name — a rename-then-delete still requires two steps,
    // which is the point.
    let pattern = format!("%\"{}\"%", escape_like(name));
    let refs: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM workflows \
         WHERE user_id = $1 AND graph_json::text LIKE $2 ESCAPE '\\'",
    )
    .bind(user_id)
    .bind(&pattern)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| DeleteError::Internal(e.into()))?;
    if refs > 0 {
        return Err(DeleteError::ReferencedByWorkflows(refs));
    }

    // Shared-dataset guard: ml_models.dataset_id is ON DELETE SET NULL, so
    // deleting a dataset other models still train on would silently orphan
    // them. Refuse with the sibling names so the caller can decide.
    if delete_dataset {
        if let Some(dataset_id) = model.dataset_id {
            let siblings: Vec<String> = sqlx::query_scalar(
                "SELECT name FROM ml_models \
                 WHERE dataset_id = $1 AND user_id = $2 AND id <> $3 \
                 ORDER BY name LIMIT 10",
            )
            .bind(dataset_id)
            .bind(user_id)
            .bind(model.model_id)
            .fetch_all(&mut *tx)
            .await
            .map_err(|e| DeleteError::Internal(e.into()))?;
            if !siblings.is_empty() {
                return Err(DeleteError::DatasetShared(siblings));
            }
        }
    }

    // Model first: versions / shadow stats / disagreements cascade from it.
    // The explicit user_id predicate is the app-layer belt on top of RLS.
    let deleted = sqlx::query("DELETE FROM ml_models WHERE id = $1 AND user_id = $2")
        .bind(model.model_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| DeleteError::Internal(e.into()))?;
    if deleted.rows_affected() == 0 {
        // RLS or a concurrent delete got there first — treat as not found.
        return Err(DeleteError::NotFound);
    }

    let mut dataset_deleted = false;
    if delete_dataset {
        if let Some(dataset_id) = model.dataset_id {
            // Examples cascade from the dataset row.
            let d = sqlx::query("DELETE FROM ml_datasets WHERE id = $1 AND user_id = $2")
                .bind(dataset_id)
                .bind(user_id)
                .execute(&mut *tx)
                .await
                .map_err(|e| DeleteError::Internal(e.into()))?;
            dataset_deleted = d.rows_affected() > 0;
        }
    }

    tx.commit()
        .await
        .map_err(|e| DeleteError::Internal(e.into()))?;

    // Post-commit: evict the resolved serving entry so a stale 15s-TTL hit
    // can't serve a deleted model. (LINEAR_CACHE entries are keyed by the
    // now-unreachable version_id, immutable, and cap-bounded — they age out.)
    invalidate_serving_cache(user_id, name);

    tracing::info!(
        target: "talos_ml",
        model_id = %model.model_id,
        dataset_deleted,
        "model deleted"
    );

    Ok(DeleteOutcome {
        model_id: model.model_id,
        model_deleted: true,
        dataset_id: model.dataset_id,
        dataset_deleted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_like_backslash_first() {
        // Backslash must be escaped FIRST or the later escapes double up.
        assert_eq!(escape_like(r"a\b"), r"a\\b");
        assert_eq!(escape_like("a_b%c"), r"a\_b\%c");
        // A valid model name with underscores becomes a literal match.
        assert_eq!(escape_like("smart_node"), r"smart\_node");
    }
}
