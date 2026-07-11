//! DatasetService — append/sample/split over `ml_datasets`/`ml_examples`.
//!
//! Every DB method takes `&mut PgConnection` so request paths run on
//! tenant-scoped transactions (RLS fail-closed; the check-50 executor
//! discipline). Feature payloads are encrypted per-org (AEAD
//! v4-or-global). Embeddings use the LOCAL pipeline only
//! (`local_only = true`) — dataset content never leaves the host even
//! when an external embedding provider is configured platform-wide.
//!
//! Tenancy invariant (review fix): example rows inherit `user_id` /
//! `org_id` FROM THE PARENT DATASET ROW — callers cannot supply them, so
//! a confused handler can't write rows readable by the wrong org or
//! poison another tenant's dataset.
//!
//! Batch shape (review fix): the expensive per-example work (AEAD
//! encrypt + local embedding HTTP call) happens in `prepare_examples`,
//! which takes NO connection — callers embed OUTSIDE their transaction
//! and then run one short `insert_prepared` (chunked multi-row INSERT).
//! `append_examples` composes the two for small batches.

use anyhow::{Context, Result};
use sqlx::PgConnection;
use std::sync::Arc;
use talos_secrets_manager::{SecretsManager, Zeroizing};
use uuid::Uuid;

use crate::knn::Neighbor;

/// The embedding column is `vector(768)` (local nomic). A configured
/// local model with different dimensionality must degrade to
/// embedding-NULL rows (backfillable) rather than failing every INSERT —
/// the actor_memory 1536-vs-768 incident class.
const EMBEDDING_COLUMN_DIMS: usize = 768;

/// Rows per multi-row INSERT statement (11 binds per row; comfortably
/// under Postgres' 65535-bind limit with headroom).
const INSERT_CHUNK: usize = 200;

/// Concurrent embedding requests during `prepare_examples`. Local
/// Ollama; modest parallelism cuts wall time without saturating it.
const EMBED_CONCURRENCY: usize = 8;

/// Provenance of a labeled example. Enum at the service boundary so a
/// typo fails in Rust before burning an encrypt + embed per example on
/// its way to the DB CHECK (single source of truth: `as_str` ↔ the
/// migration's CHECK list).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExampleSource {
    LlmBootstrap,
    Correction,
    LlmFallback,
    Import,
    Synthetic,
}

impl ExampleSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LlmBootstrap => "llm_bootstrap",
            Self::Correction => "correction",
            Self::LlmFallback => "llm_fallback",
            Self::Import => "import",
            Self::Synthetic => "synthetic",
        }
    }
}

/// One example to append. `features_text` is BOTH the encrypted payload
/// and the embedded text — the label is deliberately NOT part of it, so
/// training-example embeddings share geometry with inference-time
/// queries (which obviously don't contain the answer).
#[derive(Debug, Clone)]
pub struct AppendExample {
    pub features_text: String,
    pub label: String,
    pub source: ExampleSource,
    /// Dedupe/upsert key (e.g. gmail message id). Rows with the same key
    /// REPLACE earlier ones — corrections beat bootstrap labels.
    pub example_key: Option<String>,
}

/// Output of the connection-free preparation phase: encrypted + embedded,
/// ready for a short batched INSERT.
pub struct PreparedExample {
    id: Uuid,
    features_enc: Vec<u8>,
    features_key_id: Uuid,
    features_format: i16,
    label_json: serde_json::Value,
    embedding: Option<pgvector::Vector>,
    source: &'static str,
    example_key: Option<String>,
}

/// Parent-dataset tenancy, read once per batch and stamped on every row.
#[derive(Debug, Clone, Copy)]
pub struct DatasetTenancy {
    pub user_id: Uuid,
    pub org_id: Option<Uuid>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DatasetStats {
    pub total: i64,
    pub by_label: Vec<(String, i64)>,
    pub by_source: Vec<(String, i64)>,
    pub with_embedding: i64,
    pub holdout: i64,
    /// Rows whose label_json carries no 'label' key (non-classification
    /// shapes) — excluded from by_label and every classification path.
    pub unlabeled: i64,
}

/// Review-surface row (small, capped, human-facing by design).
#[derive(Debug, Clone, serde::Serialize)]
pub struct SampledExample {
    pub id: Uuid,
    pub features_text: String,
    pub label: String,
    pub source: String,
}

/// Eval-surface row: bulk-decrypted, so the plaintext stays in a
/// wipe-on-drop container, and the STORED embedding rides along so eval
/// never re-embeds what append already computed (also keeps holdout
/// scoring deterministic w.r.t. the stored geometry).
pub struct HoldoutExample {
    pub id: Uuid,
    pub features_text: Zeroizing<String>,
    pub label: String,
    pub embedding: Option<Vec<f32>>,
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

/// The 7-column encrypted-row projection shared by every decrypt path
/// (one tuple type + one decrypt helper, so the AAD scheme can't drift
/// between the review and eval surfaces).
type EncRow = (
    Uuid,
    Vec<u8>,
    Uuid,
    i16,
    Option<String>,
    String,
    Option<String>,
);
const ENC_ROW_COLS: &str = "id, features_enc, features_key_id, features_format, \
                            label_json->>'label', source, example_key";

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

    /// Read the parent dataset's tenancy — the ONLY source of the
    /// `user_id`/`org_id` stamped on example rows.
    pub async fn dataset_tenancy(
        &self,
        conn: &mut PgConnection,
        dataset_id: Uuid,
    ) -> Result<DatasetTenancy> {
        let row: Option<(Uuid, Option<Uuid>)> =
            sqlx::query_as("SELECT user_id, org_id FROM ml_datasets WHERE id = $1")
                .bind(dataset_id)
                .fetch_optional(&mut *conn)
                .await?;
        let (user_id, org_id) =
            row.ok_or_else(|| anyhow::anyhow!("dataset {dataset_id} not found"))?;
        Ok(DatasetTenancy { user_id, org_id })
    }

    /// Connection-free preparation: AEAD-encrypt and locally-embed each
    /// example, with bounded concurrency on the embedding HTTP calls.
    /// Run this OUTSIDE any open transaction — it's the long pole
    /// (network round-trips), and holding a tenant-scoped tx across it
    /// is the idle-in-transaction/pool-exhaustion pattern the review
    /// flagged.
    pub async fn prepare_examples(
        &self,
        dataset_id: Uuid,
        tenancy: DatasetTenancy,
        examples: Vec<AppendExample>,
    ) -> Result<Vec<PreparedExample>> {
        use futures::stream::{self, StreamExt, TryStreamExt};
        let secrets = self.secrets.clone();
        let org_id = tenancy.org_id;
        let prepared: Vec<PreparedExample> = stream::iter(examples.into_iter().map(|ex| {
            let secrets = secrets.clone();
            async move {
                let id = Uuid::new_v4();
                let aad = example_aad(dataset_id, ex.example_key.as_deref(), id);
                let (key_id, ciphertext, format) = secrets
                    .encrypt_value_aad_v4_or_global(&ex.features_text, org_id, &aad)
                    .await
                    .context("encrypt ml_example features")?;
                let embedding =
                    talos_memory::embedding::generate_embedding(&ex.features_text, true)
                        .await
                        .and_then(|v| {
                            if v.len() == EMBEDDING_COLUMN_DIMS {
                                Some(pgvector::Vector::from(v))
                            } else {
                                // Configured local model has a different
                                // dimensionality than the column — degrade
                                // to NULL (backfillable) instead of failing
                                // the whole batch at INSERT time.
                                tracing::warn!(
                                    target: "talos_ml",
                                    %dataset_id,
                                    got_dims = v.len(),
                                    expected_dims = EMBEDDING_COLUMN_DIMS,
                                    "embedding dimensionality mismatch — storing NULL"
                                );
                                None
                            }
                        });
                anyhow::Ok(PreparedExample {
                    id,
                    features_enc: ciphertext,
                    features_key_id: key_id,
                    features_format: format,
                    label_json: serde_json::json!({ "label": ex.label }),
                    embedding,
                    source: ex.source.as_str(),
                    example_key: ex.example_key,
                })
            }
        }))
        .buffer_unordered(EMBED_CONCURRENCY)
        .try_collect()
        .await?;

        let missing = prepared.iter().filter(|p| p.embedding.is_none()).count();
        if missing > 0 {
            // Aggregate signal: a dead local embedder otherwise "succeeds"
            // its way to a knn backend that can only abstain.
            tracing::warn!(
                target: "talos_ml",
                %dataset_id,
                missing,
                total = prepared.len(),
                "prepare_examples: rows stored WITHOUT embeddings — knn cannot use them until backfilled"
            );
        }
        Ok(prepared)
    }

    /// Short write phase: chunked multi-row upserts + one touch UPDATE.
    /// Tenancy comes from `dataset_tenancy`, never from the caller's
    /// request context.
    pub async fn insert_prepared(
        &self,
        conn: &mut PgConnection,
        dataset_id: Uuid,
        tenancy: DatasetTenancy,
        prepared: Vec<PreparedExample>,
    ) -> Result<usize> {
        let mut stored = 0usize;
        for chunk in prepared.chunks(INSERT_CHUNK) {
            let mut qb: sqlx::QueryBuilder<sqlx::Postgres> = sqlx::QueryBuilder::new(
                "INSERT INTO ml_examples \
                 (id, dataset_id, user_id, org_id, features_enc, features_key_id, \
                  features_format, label_json, embedding, source, example_key) ",
            );
            qb.push_values(chunk, |mut b, p| {
                b.push_bind(p.id)
                    .push_bind(dataset_id)
                    .push_bind(tenancy.user_id)
                    .push_bind(tenancy.org_id)
                    .push_bind(&p.features_enc)
                    .push_bind(p.features_key_id)
                    .push_bind(p.features_format)
                    .push_bind(&p.label_json)
                    .push_bind(&p.embedding)
                    .push_bind(p.source)
                    .push_bind(&p.example_key);
            });
            // COALESCE keeps an existing good embedding when a correction
            // re-labels a row while the embedder is down (talos-memory's
            // upsert discipline) — the text is unchanged, so the old
            // vector is still correct for the new label.
            qb.push(
                " ON CONFLICT (dataset_id, example_key) WHERE example_key IS NOT NULL \
                  DO UPDATE SET features_enc = EXCLUDED.features_enc, \
                                features_key_id = EXCLUDED.features_key_id, \
                                features_format = EXCLUDED.features_format, \
                                label_json = EXCLUDED.label_json, \
                                embedding = COALESCE(EXCLUDED.embedding, ml_examples.embedding), \
                                source = EXCLUDED.source",
            );
            let res = qb
                .build()
                .execute(&mut *conn)
                .await
                .context("insert ml_examples chunk")?;
            stored += res.rows_affected() as usize;
        }
        sqlx::query("UPDATE ml_datasets SET updated_at = NOW() WHERE id = $1")
            .bind(dataset_id)
            .execute(&mut *conn)
            .await
            .context("touch ml_dataset")?;
        Ok(stored)
    }

    /// Convenience wrapper for SMALL batches (a bootstrap page, a
    /// correction sweep). The embedding round-trips still run while the
    /// caller's connection sits idle — large imports should call
    /// `dataset_tenancy` → `prepare_examples` (no tx) → `insert_prepared`
    /// on a fresh short transaction.
    pub async fn append_examples(
        &self,
        conn: &mut PgConnection,
        dataset_id: Uuid,
        examples: Vec<AppendExample>,
    ) -> Result<usize> {
        let tenancy = self.dataset_tenancy(&mut *conn, dataset_id).await?;
        let prepared = self.prepare_examples(dataset_id, tenancy, examples).await?;
        self.insert_prepared(conn, dataset_id, tenancy, prepared)
            .await
    }

    /// Two statements: scalar counts via FILTER, breakdowns via GROUPING
    /// SETS (was five sequential full scans).
    pub async fn stats(&self, conn: &mut PgConnection, dataset_id: Uuid) -> Result<DatasetStats> {
        let (total, with_embedding, holdout, unlabeled): (i64, i64, i64, i64) = sqlx::query_as(
            "SELECT COUNT(*), \
                    COUNT(embedding), \
                    COUNT(*) FILTER (WHERE split = 'holdout'), \
                    COUNT(*) FILTER (WHERE NOT label_json ? 'label') \
             FROM ml_examples WHERE dataset_id = $1",
        )
        .bind(dataset_id)
        .fetch_one(&mut *conn)
        .await?;
        let rows: Vec<(Option<String>, Option<String>, i64)> = sqlx::query_as(
            "SELECT label_json->>'label', source, COUNT(*) \
             FROM ml_examples WHERE dataset_id = $1 \
             GROUP BY GROUPING SETS ((label_json->>'label'), (source)) \
             ORDER BY 3 DESC",
        )
        .bind(dataset_id)
        .fetch_all(&mut *conn)
        .await?;
        let mut by_label = Vec::new();
        let mut by_source = Vec::new();
        for (label, source, count) in rows {
            match (label, source) {
                (Some(l), None) => by_label.push((l, count)),
                (None, Some(s)) => by_source.push((s, count)),
                // (None, None) = the label-NULL group (non-classification
                // rows) — already counted in `unlabeled`.
                _ => {}
            }
        }
        Ok(DatasetStats {
            total,
            by_label,
            by_source,
            with_embedding,
            holdout,
            unlabeled,
        })
    }

    /// Decrypt up to `per_label` examples per label for human review.
    /// The window subquery ranks by (id, label) ONLY — the ciphertext is
    /// joined back for just the winners, so the RANDOM() sort never
    /// materializes the whole dataset's BYTEA payloads.
    pub async fn sample_examples(
        &self,
        conn: &mut PgConnection,
        dataset_id: Uuid,
        per_label: i64,
    ) -> Result<Vec<SampledExample>> {
        let per_label = per_label.clamp(1, 25);
        let rows: Vec<EncRow> = sqlx::query_as(&format!(
            "SELECT {ENC_ROW_COLS} FROM ml_examples \
             WHERE id IN ( \
                 SELECT id FROM (SELECT id, ROW_NUMBER() OVER \
                     (PARTITION BY label_json->>'label' ORDER BY RANDOM()) AS rn \
                   FROM ml_examples \
                   WHERE dataset_id = $1 AND label_json ? 'label') t \
                 WHERE rn <= $2)",
        ))
        .bind(dataset_id)
        .bind(per_label)
        .fetch_all(&mut *conn)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let (id, label, source, text) = self.decrypt_row(dataset_id, row).await?;
            out.push(SampledExample {
                id,
                // Review surface: deliberately human-facing plaintext,
                // small and capped.
                features_text: text.to_string(),
                label,
                source,
            });
        }
        Ok(out)
    }

    /// (id, label) pairs for split assignment — classification rows only,
    /// no decryption needed.
    pub async fn load_labels(
        &self,
        conn: &mut PgConnection,
        dataset_id: Uuid,
    ) -> Result<Vec<(Uuid, String)>> {
        Ok(sqlx::query_as(
            "SELECT id, label_json->>'label' FROM ml_examples \
             WHERE dataset_id = $1 AND label_json ? 'label'",
        )
        .bind(dataset_id)
        .fetch_all(&mut *conn)
        .await?)
    }

    /// Serialize split/eval work per dataset. `pg_advisory_xact_lock`
    /// holds until the caller's transaction ends, so an eval that locks,
    /// assigns splits, and scores inside ONE tx cannot have its holdout
    /// thrashed by a concurrent eval (which would let holdout rows
    /// re-enter the train set and vote for themselves at similarity 1.0).
    pub async fn lock_dataset(&self, conn: &mut PgConnection, dataset_id: Uuid) -> Result<()> {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))")
            .bind(dataset_id)
            .execute(&mut *conn)
            .await
            .context("advisory-lock dataset")?;
        Ok(())
    }

    /// Persist a holdout assignment (everything else becomes 'train').
    /// Takes the per-dataset advisory lock; callers running a full eval
    /// should ALSO call `lock_dataset` at the top of their transaction
    /// so the lock spans scoring, not just assignment.
    pub async fn assign_splits(
        &self,
        conn: &mut PgConnection,
        dataset_id: Uuid,
        holdout_ids: &[Uuid],
    ) -> Result<()> {
        self.lock_dataset(&mut *conn, dataset_id).await?;
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

    /// Decrypt the holdout set for eval: wipe-on-drop plaintext + the
    /// STORED embedding (eval reuses it instead of re-embedding, which
    /// is both ~N HTTP calls cheaper and deterministic w.r.t. the
    /// geometry knn actually searches).
    pub async fn load_holdout(
        &self,
        conn: &mut PgConnection,
        dataset_id: Uuid,
    ) -> Result<Vec<HoldoutExample>> {
        let rows: Vec<(
            Uuid,
            Vec<u8>,
            Uuid,
            i16,
            Option<String>,
            String,
            Option<String>,
            Option<pgvector::Vector>,
        )> = sqlx::query_as(&format!(
            "SELECT {ENC_ROW_COLS}, embedding FROM ml_examples \
                 WHERE dataset_id = $1 AND split = 'holdout' AND label_json ? 'label'",
        ))
        .bind(dataset_id)
        .fetch_all(&mut *conn)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for (id, enc, key_id, format, label, source, example_key, embedding) in rows {
            let (id, label, _source, text) = self
                .decrypt_row(
                    dataset_id,
                    (id, enc, key_id, format, label, source, example_key),
                )
                .await?;
            out.push(HoldoutExample {
                id,
                features_text: text,
                label,
                embedding: embedding.map(|v| v.to_vec()),
            });
        }
        Ok(out)
    }

    /// Shared decrypt for the review + eval surfaces: one place derives
    /// the AAD, so the binding scheme cannot drift between them. Returns
    /// wipe-on-drop plaintext; the caller decides whether its surface
    /// justifies a plain-String copy.
    async fn decrypt_row(
        &self,
        dataset_id: Uuid,
        row: EncRow,
    ) -> Result<(Uuid, String, String, Zeroizing<String>)> {
        let (id, enc, key_id, format, label, source, example_key) = row;
        let label = label.ok_or_else(|| {
            anyhow::anyhow!("example {id} has no 'label' key (non-classification row)")
        })?;
        let aad = example_aad(dataset_id, example_key.as_deref(), id);
        let text = self
            .secrets
            .decrypt_versioned(key_id, &enc, &aad, format)
            .await
            .with_context(|| format!("decrypt ml_example {id}"))?;
        Ok((id, label, source, text))
    }

    /// End-to-end text prediction on the knn backend: embed locally,
    /// retrieve, vote. Returns None when the input can't be embedded or
    /// the neighborhood abstains — the caller decides the fallback.
    pub async fn knn_predict_text(
        &self,
        conn: &mut PgConnection,
        dataset_id: Uuid,
        text: &str,
        k: i64,
    ) -> Result<Option<crate::knn::KnnPrediction>> {
        let Some(embedding) = talos_memory::embedding::generate_embedding(text, true).await else {
            return Ok(None);
        };
        if embedding.len() != EMBEDDING_COLUMN_DIMS {
            return Ok(None);
        }
        let neighbors = self
            .knn_search(conn, dataset_id, &embedding, k, true)
            .await?;
        Ok(crate::knn::knn_vote(&neighbors))
    }

    /// knn retrieval for one query embedding. `train_only` excludes the
    /// holdout so eval never lets a holdout row vote for itself.
    ///
    /// Pins `ivfflat.probes` to the index's `lists` (20) for THIS
    /// transaction: at the default probes=1 the shared multi-dataset
    /// index probes one globally-nearest cell and the dataset_id
    /// post-filter starves small datasets (fewer than k, unstable
    /// neighbors) — corrupting both production votes and the eval
    /// numbers that gate promotion. probes=lists is an exact scan
    /// within the index, single-digit ms at P1 scale. Requires the
    /// caller to be inside a transaction (every tenant-scoped path is;
    /// `set_config(..., true)` is transaction-local so nothing leaks to
    /// the pooled connection).
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
        sqlx::query_scalar::<_, String>("SELECT set_config('ivfflat.probes', '20', true)")
            .fetch_one(&mut *conn)
            .await
            .context("pin ivfflat.probes")?;
        let rows: Vec<(String, f64)> = sqlx::query_as(
            "SELECT label_json->>'label', 1 - (embedding <=> $2) AS sim \
             FROM ml_examples \
             WHERE dataset_id = $1 AND embedding IS NOT NULL \
               AND label_json ? 'label' \
               AND (NOT $4 OR split IS DISTINCT FROM 'holdout') \
             ORDER BY embedding <=> $2 LIMIT $3",
        )
        .bind(dataset_id)
        .bind(&qvec)
        .bind(k)
        .bind(train_only)
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
