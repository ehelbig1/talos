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

    /// Resolve a model by name. RLS scopes visibility; name is unique
    /// only PER SCOPE (personal / each org), so a caller may see several
    /// same-named rows — precedence is deterministic: the caller's OWN
    /// personal model first, then org models by fixed org order. Without
    /// the ORDER BY, `LIMIT 1` was planner-dependent and an org member
    /// could shadow a colleague's personal model name nondeterministically.
    pub async fn resolve_by_name(
        conn: &mut PgConnection,
        name: &str,
    ) -> Result<Option<ResolvedModel>> {
        let model = sqlx::query(
            "SELECT id, dataset_id, config_json, production_version_id \
             FROM ml_models WHERE name = $1 \
             ORDER BY (org_id IS NULL) DESC, org_id, id LIMIT 1",
        )
        .bind(name)
        .fetch_optional(&mut *conn)
        .await?;
        let Some(m) = model else { return Ok(None) };
        let model_id: Uuid = m.try_get("id")?;
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
            dataset_id,
            config_json: config,
            promoted_version: version,
        }))
    }
}
