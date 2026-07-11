//! DatasetService — append/sample/split over `ml_datasets`/`ml_examples`.
//!
//! Every method takes `&mut PgConnection` so request paths run on
//! tenant-scoped transactions (RLS fail-closed; the check-50 executor
//! discipline). Feature payloads are encrypted per-org (AEAD
//! v4-or-global). Embeddings use the LOCAL pipeline only
//! (`local_only = true`) — dataset content never leaves the host even
//! when an external embedding provider is configured platform-wide.

use anyhow::{Context, Result};
use sqlx::PgConnection;
use std::sync::Arc;
use talos_secrets_manager::SecretsManager;
use uuid::Uuid;

use crate::knn::Neighbor;

/// One example to append. `features_text` is BOTH the encrypted payload
/// and the embedded text — the label is deliberately NOT part of it, so
/// training-example embeddings share geometry with inference-time
/// queries (which obviously don't contain the answer).
#[derive(Debug, Clone)]
pub struct AppendExample {
    pub features_text: String,
    pub label: String,
    /// 'llm_bootstrap' | 'correction' | 'llm_fallback' | 'import' | 'synthetic'
    pub source: String,
    /// Dedupe/upsert key (e.g. gmail message id). Rows with the same key
    /// REPLACE earlier ones — corrections beat bootstrap labels.
    pub example_key: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DatasetStats {
    pub total: i64,
    pub by_label: Vec<(String, i64)>,
    pub by_source: Vec<(String, i64)>,
    pub with_embedding: i64,
    pub holdout: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SampledExample {
    pub id: Uuid,
    pub features_text: String,
    pub label: String,
    pub source: String,
}

pub struct DatasetService {
    secrets: Arc<SecretsManager>,
}

/// AAD binds the ciphertext to its logical identity. Keyed rows bind on
/// `example_key` (STABLE across upserts — the conflict arm keeps the
/// original row id, so binding on id would break decryption after a
/// correction overwrites a bootstrap row); keyless rows bind on id.
fn example_aad(dataset_id: Uuid, example_key: Option<&str>, id: Uuid) -> Vec<u8> {
    match example_key {
        Some(k) => format!("ml_example:{dataset_id}:k:{k}").into_bytes(),
        None => format!("ml_example:{dataset_id}:i:{id}").into_bytes(),
    }
}

impl DatasetService {
    pub fn new(secrets: Arc<SecretsManager>) -> Self {
        Self { secrets }
    }

    pub async fn create_dataset(
        &self,
        conn: &mut PgConnection,
        user_id: Uuid,
        org_id: Option<Uuid>,
        name: &str,
        task_type: &str,
        schema_json: &serde_json::Value,
    ) -> Result<Uuid> {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO ml_datasets (id, user_id, org_id, name, task_type, schema_json) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(id)
        .bind(user_id)
        .bind(org_id)
        .bind(name)
        .bind(task_type)
        .bind(schema_json)
        .execute(&mut *conn)
        .await
        .context("create ml_dataset")?;
        Ok(id)
    }

    /// Append (upsert) examples: encrypt features, embed locally, write.
    /// Returns the number stored. Embedding failures degrade to
    /// embedding-NULL rows (they still train parametric backends and are
    /// backfillable) rather than dropping the labeled example.
    pub async fn append_examples(
        &self,
        conn: &mut PgConnection,
        dataset_id: Uuid,
        user_id: Uuid,
        org_id: Option<Uuid>,
        examples: Vec<AppendExample>,
    ) -> Result<usize> {
        let mut stored = 0usize;
        for ex in examples {
            let id = Uuid::new_v4();
            let aad = example_aad(dataset_id, ex.example_key.as_deref(), id);
            let (key_id, ciphertext, format) = self
                .secrets
                .encrypt_value_aad_v4_or_global(&ex.features_text, org_id, &aad)
                .await
                .context("encrypt ml_example features")?;
            let embedding: Option<pgvector::Vector> =
                talos_memory::embedding::generate_embedding(&ex.features_text, true)
                    .await
                    .map(pgvector::Vector::from);
            if embedding.is_none() {
                tracing::warn!(
                    target: "talos_ml",
                    %dataset_id,
                    example_key = ?ex.example_key,
                    "append_examples: local embedding unavailable — storing embedding-NULL row"
                );
            }
            let label_json = serde_json::json!({ "label": ex.label });
            sqlx::query(
                "INSERT INTO ml_examples \
                   (id, dataset_id, user_id, org_id, features_enc, features_key_id, \
                    features_format, label_json, embedding, source, example_key) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
                 ON CONFLICT (dataset_id, example_key) WHERE example_key IS NOT NULL \
                 DO UPDATE SET features_enc = EXCLUDED.features_enc, \
                               features_key_id = EXCLUDED.features_key_id, \
                               features_format = EXCLUDED.features_format, \
                               label_json = EXCLUDED.label_json, \
                               embedding = EXCLUDED.embedding, \
                               source = EXCLUDED.source",
            )
            .bind(id)
            .bind(dataset_id)
            .bind(user_id)
            .bind(org_id)
            .bind(&ciphertext)
            .bind(key_id)
            .bind(format)
            .bind(&label_json)
            .bind(&embedding)
            .bind(&ex.source)
            .bind(&ex.example_key)
            .execute(&mut *conn)
            .await
            .context("insert ml_example")?;
            stored += 1;
        }
        // Touch the dataset's updated_at so staleness is observable.
        sqlx::query("UPDATE ml_datasets SET updated_at = NOW() WHERE id = $1")
            .bind(dataset_id)
            .execute(&mut *conn)
            .await
            .context("touch ml_dataset")?;
        Ok(stored)
    }

    pub async fn stats(&self, conn: &mut PgConnection, dataset_id: Uuid) -> Result<DatasetStats> {
        let total: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM ml_examples WHERE dataset_id = $1")
                .bind(dataset_id)
                .fetch_one(&mut *conn)
                .await?;
        let by_label: Vec<(String, i64)> = sqlx::query_as(
            "SELECT label_json->>'label', COUNT(*) FROM ml_examples \
             WHERE dataset_id = $1 GROUP BY 1 ORDER BY 2 DESC",
        )
        .bind(dataset_id)
        .fetch_all(&mut *conn)
        .await?;
        let by_source: Vec<(String, i64)> = sqlx::query_as(
            "SELECT source, COUNT(*) FROM ml_examples \
             WHERE dataset_id = $1 GROUP BY 1 ORDER BY 2 DESC",
        )
        .bind(dataset_id)
        .fetch_all(&mut *conn)
        .await?;
        let with_embedding: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM ml_examples WHERE dataset_id = $1 AND embedding IS NOT NULL",
        )
        .bind(dataset_id)
        .fetch_one(&mut *conn)
        .await?;
        let holdout: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM ml_examples WHERE dataset_id = $1 AND split = 'holdout'",
        )
        .bind(dataset_id)
        .fetch_one(&mut *conn)
        .await?;
        Ok(DatasetStats {
            total,
            by_label,
            by_source,
            with_embedding,
            holdout,
        })
    }

    /// Decrypt up to `per_label` examples per label for human review.
    pub async fn sample_examples(
        &self,
        conn: &mut PgConnection,
        dataset_id: Uuid,
        per_label: i64,
    ) -> Result<Vec<SampledExample>> {
        let per_label = per_label.clamp(1, 25);
        let rows: Vec<(Uuid, Vec<u8>, Uuid, i16, String, String, Option<String>)> = sqlx::query_as(
            "SELECT id, features_enc, features_key_id, features_format, \
                    label_json->>'label', source, example_key \
             FROM (SELECT *, ROW_NUMBER() OVER \
                     (PARTITION BY label_json->>'label' ORDER BY RANDOM()) AS rn \
                   FROM ml_examples WHERE dataset_id = $1) t \
             WHERE rn <= $2",
        )
        .bind(dataset_id)
        .bind(per_label)
        .fetch_all(&mut *conn)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for (id, enc, key_id, format, label, source, example_key) in rows {
            let aad = example_aad(dataset_id, example_key.as_deref(), id);
            let text = self
                .secrets
                .decrypt_versioned(key_id, &enc, &aad, format)
                .await
                .map(|z| z.to_string())
                .context("decrypt ml_example features")?;
            out.push(SampledExample {
                id,
                features_text: text,
                label,
                source,
            });
        }
        Ok(out)
    }

    /// (id, label) pairs for split assignment — no decryption needed.
    pub async fn load_labels(
        &self,
        conn: &mut PgConnection,
        dataset_id: Uuid,
    ) -> Result<Vec<(Uuid, String)>> {
        Ok(
            sqlx::query_as(
                "SELECT id, label_json->>'label' FROM ml_examples WHERE dataset_id = $1",
            )
            .bind(dataset_id)
            .fetch_all(&mut *conn)
            .await?,
        )
    }

    /// Persist a holdout assignment (everything else becomes 'train').
    pub async fn assign_splits(
        &self,
        conn: &mut PgConnection,
        dataset_id: Uuid,
        holdout_ids: &[Uuid],
    ) -> Result<()> {
        sqlx::query("UPDATE ml_examples SET split = 'train' WHERE dataset_id = $1")
            .bind(dataset_id)
            .execute(&mut *conn)
            .await?;
        sqlx::query(
            "UPDATE ml_examples SET split = 'holdout' \
             WHERE dataset_id = $1 AND id = ANY($2)",
        )
        .bind(dataset_id)
        .bind(holdout_ids)
        .execute(&mut *conn)
        .await?;
        Ok(())
    }

    /// Decrypt the holdout set for eval (truth labels + feature text).
    pub async fn load_holdout(
        &self,
        conn: &mut PgConnection,
        dataset_id: Uuid,
    ) -> Result<Vec<SampledExample>> {
        let rows: Vec<(Uuid, Vec<u8>, Uuid, i16, String, String, Option<String>)> = sqlx::query_as(
            "SELECT id, features_enc, features_key_id, features_format, \
                    label_json->>'label', source, example_key \
             FROM ml_examples WHERE dataset_id = $1 AND split = 'holdout'",
        )
        .bind(dataset_id)
        .fetch_all(&mut *conn)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for (id, enc, key_id, format, label, source, example_key) in rows {
            let aad = example_aad(dataset_id, example_key.as_deref(), id);
            let text = self
                .secrets
                .decrypt_versioned(key_id, &enc, &aad, format)
                .await
                .map(|z| z.to_string())
                .context("decrypt holdout example")?;
            out.push(SampledExample {
                id,
                features_text: text,
                label,
                source,
            });
        }
        Ok(out)
    }

    /// knn retrieval for one query embedding. `train_only` excludes the
    /// holdout so eval never lets a holdout row vote for itself.
    pub async fn knn_search(
        &self,
        conn: &mut PgConnection,
        dataset_id: Uuid,
        query: &[f32],
        k: i64,
        train_only: bool,
    ) -> Result<Vec<Neighbor>> {
        let k = k.clamp(1, 50);
        let qvec = pgvector::Vector::from(query.to_vec());
        let sql = if train_only {
            "SELECT label_json->>'label', 1 - (embedding <=> $2) AS sim \
             FROM ml_examples \
             WHERE dataset_id = $1 AND embedding IS NOT NULL \
               AND (split IS NULL OR split = 'train') \
             ORDER BY embedding <=> $2 LIMIT $3"
        } else {
            "SELECT label_json->>'label', 1 - (embedding <=> $2) AS sim \
             FROM ml_examples \
             WHERE dataset_id = $1 AND embedding IS NOT NULL \
             ORDER BY embedding <=> $2 LIMIT $3"
        };
        let rows: Vec<(String, f64)> = sqlx::query_as(sql)
            .bind(dataset_id)
            .bind(&qvec)
            .bind(k)
            .fetch_all(&mut *conn)
            .await?;
        Ok(rows
            .into_iter()
            .map(|(label, sim)| Neighbor {
                label,
                similarity: sim as f32,
            })
            .collect())
    }
}
