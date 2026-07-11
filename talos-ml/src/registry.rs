//! ModelRegistry — versioned models over datasets; the promoted version
//! is what workflows reference by name. Executor discipline matches
//! DatasetService (`&mut PgConnection`, scoped-tx-compatible).

use anyhow::{Context, Result};
use sqlx::PgConnection;
use sqlx::Row;
use uuid::Uuid;

#[derive(Debug, Clone, serde::Serialize)]
pub struct ModelVersionRow {
    pub id: Uuid,
    pub model_id: Uuid,
    pub version: i32,
    pub backend: String,
    pub metrics_json: serde_json::Value,
    pub status: String,
}

/// Name-resolution result (named struct, not tuple-soup — future fields
/// like task_type are additive instead of positionally breaking).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ResolvedModel {
    pub name: String,
    pub model_id: Uuid,
    pub dataset_id: Option<Uuid>,
    pub config_json: serde_json::Value,
    pub promoted_version: Option<ModelVersionRow>,
}

pub struct ModelRegistry;

impl ModelRegistry {
    pub async fn create_model(
        conn: &mut PgConnection,
        user_id: Uuid,
        org_id: Option<Uuid>,
        name: &str,
        task_type: &str,
        dataset_id: Option<Uuid>,
        config_json: &serde_json::Value,
    ) -> Result<Uuid> {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO ml_models (id, user_id, org_id, name, task_type, dataset_id, config_json) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(id)
        .bind(user_id)
        .bind(org_id)
        .bind(name)
        .bind(task_type)
        .bind(dataset_id)
        .bind(config_json)
        .execute(&mut *conn)
        .await
        .context("create ml_model")?;
        Ok(id)
    }

    /// Insert the next version for a model. Artifact integrity: sha256
    /// computed here, at write time, so a corrupted artifact can never
    /// enter the registry with a matching digest.
    pub async fn create_version(
        conn: &mut PgConnection,
        model_id: Uuid,
        user_id: Uuid,
        org_id: Option<Uuid>,
        backend: &str,
        artifact: Option<&[u8]>,
        metrics_json: &serde_json::Value,
    ) -> Result<ModelVersionRow> {
        let id = Uuid::new_v4();
        let sha = artifact.map(talos_text_util::sha256_hex_bytes);
        // Serialize concurrent version creates for one model: without
        // the lock, two writers both read MAX(version)=N and the loser
        // dies on the UNIQUE(model_id, version) constraint AFTER its
        // (expensive) train/eval work. xact-scoped, so it releases with
        // the caller's transaction. hashtextextended = full-width int8
        // key (the L-17 birthday-collision lesson).
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('ml_model:' || $1::text, 0))")
            .bind(model_id)
            .execute(&mut *conn)
            .await
            .context("advisory-lock model")?;
        let row = sqlx::query(
            "INSERT INTO ml_model_versions \
               (id, model_id, user_id, org_id, version, backend, artifact, \
                artifact_sha256, metrics_json) \
             VALUES ($1, $2, $3, $4, \
                     COALESCE((SELECT MAX(version) FROM ml_model_versions \
                               WHERE model_id = $2), 0) + 1, \
                     $5, $6, $7, $8) \
             RETURNING version",
        )
        .bind(id)
        .bind(model_id)
        .bind(user_id)
        .bind(org_id)
        .bind(backend)
        .bind(artifact)
        .bind(&sha)
        .bind(metrics_json)
        .fetch_one(&mut *conn)
        .await
        .context("insert ml_model_version")?;
        let version: i32 = row.try_get("version")?;
        Ok(ModelVersionRow {
            id,
            model_id,
            version,
            backend: backend.to_string(),
            metrics_json: metrics_json.clone(),
            status: "trained".to_string(),
        })
    }

    /// Promote a version: it becomes what `predict(model_name)` serves.
    /// The previous promoted version is retired in the same transaction
    /// scope (caller owns the tx).
    pub async fn promote_version(
        conn: &mut PgConnection,
        model_id: Uuid,
        version_id: Uuid,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE ml_model_versions SET status = 'retired' \
             WHERE model_id = $1 AND status = 'promoted'",
        )
        .bind(model_id)
        .execute(&mut *conn)
        .await?;
        let updated = sqlx::query(
            "UPDATE ml_model_versions SET status = 'promoted' \
             WHERE id = $1 AND model_id = $2",
        )
        .bind(version_id)
        .bind(model_id)
        .execute(&mut *conn)
        .await?;
        anyhow::ensure!(
            updated.rows_affected() == 1,
            "version {version_id} not found on model {model_id}"
        );
        sqlx::query(
            "UPDATE ml_models SET production_version_id = $2, updated_at = NOW() \
             WHERE id = $1",
        )
        .bind(model_id)
        .bind(version_id)
        .execute(&mut *conn)
        .await?;
        Ok(())
    }

    /// List the caller's models with their promoted-version summary.
    ///
    /// App-layer `user_id` scoping is the belt; RLS (when enforced) is
    /// the suspenders — same defense-in-depth posture as
    /// `require_dataset_owner` on the dataset surface, because RLS only
    /// enforces under `TALOS_RLS_SET_ROLE` and is bypassed entirely on
    /// superuser pools (the common in-cluster deploy). P2 is
    /// personal-only; org-shared visibility is a P2d decision.
    pub async fn list_models(
        conn: &mut PgConnection,
        user_id: Uuid,
    ) -> Result<Vec<serde_json::Value>> {
        let rows = sqlx::query(
            "SELECT m.id, m.name, m.task_type, m.dataset_id, m.created_at,                     v.version AS promoted_version, v.backend AS promoted_backend,                     v.metrics_json AS promoted_metrics              FROM ml_models m              LEFT JOIN ml_model_versions v ON v.id = m.production_version_id              WHERE m.user_id = $1              ORDER BY m.created_at DESC LIMIT 100",
        )
        .bind(user_id)
        .fetch_all(&mut *conn)
        .await?;
        rows.into_iter()
            .map(|r| -> Result<serde_json::Value> {
                Ok(serde_json::json!({
                    "id": r.try_get::<Uuid, _>("id")?.to_string(),
                    "name": r.try_get::<String, _>("name")?,
                    "task_type": r.try_get::<String, _>("task_type")?,
                    "dataset_id": r.try_get::<Option<Uuid>, _>("dataset_id")?.map(|d| d.to_string()),
                    "promoted_version": r.try_get::<Option<i32>, _>("promoted_version")?,
                    "promoted_backend": r.try_get::<Option<String>, _>("promoted_backend")?,
                    "promoted_metrics": r.try_get::<Option<serde_json::Value>, _>("promoted_metrics")?,
                }))
            })
            .collect()
    }

    /// All versions of one model, newest first (the model card's history).
    pub async fn list_versions(
        conn: &mut PgConnection,
        model_id: Uuid,
    ) -> Result<Vec<ModelVersionRow>> {
        let rows = sqlx::query(
            "SELECT id, model_id, version, backend, metrics_json, status              FROM ml_model_versions WHERE model_id = $1 ORDER BY version DESC",
        )
        .bind(model_id)
        .fetch_all(&mut *conn)
        .await?;
        rows.into_iter()
            .map(|r| -> Result<ModelVersionRow> {
                Ok(ModelVersionRow {
                    id: r.try_get("id")?,
                    model_id: r.try_get("model_id")?,
                    version: r.try_get("version")?,
                    backend: r.try_get("backend")?,
                    metrics_json: r.try_get("metrics_json")?,
                    status: r.try_get("status")?,
                })
            })
            .collect()
    }

    /// Resolve a model by id, scoped to its OWNER (same shape as name
    /// resolution). The `user_id` predicate is the app-layer tenancy
    /// belt (foreign and absent ids are indistinguishable — `None`);
    /// RLS backstops it when enforced. Every mutating caller (promote)
    /// relies on this scoping as its ownership gate.
    pub async fn resolve_by_id(
        conn: &mut PgConnection,
        model_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<ResolvedModel>> {
        let model = sqlx::query(
            "SELECT id, name, dataset_id, config_json, production_version_id \
             FROM ml_models WHERE id = $1 AND user_id = $2",
        )
        .bind(model_id)
        .bind(user_id)
        .fetch_optional(&mut *conn)
        .await?;
        Self::hydrate_resolved(conn, model).await
    }

    /// Resolve a model by name, scoped to the caller's PERSONAL models.
    ///
    /// The `user_id` predicate is the app-layer tenancy belt (review
    /// finding 2026-07-11: without it, cross-tenant isolation rested
    /// entirely on RLS, which only enforces under `TALOS_RLS_SET_ROLE`
    /// and never on superuser pools — a first for the signed-RPC
    /// family, whose siblings all scope reads by the signed identity in
    /// SQL). Name is unique per (user, name) under this predicate, so
    /// the resolution is deterministic; the ORDER BY guards the org
    /// extension (P2d), where a caller may additionally see same-named
    /// org rows and personal must win deterministically.
    pub async fn resolve_by_name(
        conn: &mut PgConnection,
        name: &str,
        user_id: Uuid,
    ) -> Result<Option<ResolvedModel>> {
        let model = sqlx::query(
            "SELECT id, name, dataset_id, config_json, production_version_id \
             FROM ml_models WHERE name = $1 AND user_id = $2 \
             ORDER BY (org_id IS NULL) DESC, org_id, id LIMIT 1",
        )
        .bind(name)
        .bind(user_id)
        .fetch_optional(&mut *conn)
        .await?;
        Self::hydrate_resolved(conn, model).await
    }

    /// Shared tail of the by-name/by-id resolvers: decode the model row
    /// and fetch its promoted version.
    async fn hydrate_resolved(
        conn: &mut PgConnection,
        model: Option<sqlx::postgres::PgRow>,
    ) -> Result<Option<ResolvedModel>> {
        let Some(m) = model else { return Ok(None) };
        let model_id: Uuid = m.try_get("id")?;
        let name: String = m.try_get("name")?;
        let dataset_id: Option<Uuid> = m.try_get("dataset_id")?;
        let config: serde_json::Value = m.try_get("config_json")?;
        let prod_id: Option<Uuid> = m.try_get("production_version_id")?;
        let version = match prod_id {
            Some(vid) => {
                let v = sqlx::query(
                    "SELECT id, model_id, version, backend, metrics_json, status \
                     FROM ml_model_versions WHERE id = $1",
                )
                .bind(vid)
                .fetch_optional(&mut *conn)
                .await?;
                v.map(|r| -> Result<ModelVersionRow> {
                    Ok(ModelVersionRow {
                        id: r.try_get("id")?,
                        model_id: r.try_get("model_id")?,
                        version: r.try_get("version")?,
                        backend: r.try_get("backend")?,
                        metrics_json: r.try_get("metrics_json")?,
                        status: r.try_get("status")?,
                    })
                })
                .transpose()?
            }
            None => None,
        };
        Ok(Some(ResolvedModel {
            model_id,
            name,
            dataset_id,
            config_json: config,
            promoted_version: version,
        }))
    }
}
