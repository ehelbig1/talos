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

/// Expected embedding dimensionality — read from the deployment's
/// embedding config (the same source `generate_embedding` validates
/// against), falling back to the platform default (1024,
/// mxbai-embed-large-class, per migration 20260429120000 which resized
/// every embedding column). A vector of any OTHER length must degrade
/// to an embedding-NULL row (backfillable) rather than failing every
/// INSERT — the actor_memory dimensionality-drift incident class. The
/// column type is corrected to vector(1024) by 20260711150000.
pub(crate) fn expected_embedding_dims() -> usize {
    talos_memory::embedding::EmbeddingConfig::cached()
        .map(|c| c.dimensions)
        .unwrap_or(1024)
}

/// Rows per multi-row INSERT statement (11 binds per row; comfortably
/// under Postgres' 65535-bind limit with headroom).
const INSERT_CHUNK: usize = 200;

/// Row ceiling for the inline dedupe on the append path. Above this the append
/// declines and logs, so a growing dataset can never quietly turn every ingest
/// into an O(N) hash-and-sort; the operator tool is unbounded by design.
const AUTO_DEDUPE_MAX_ROWS: i64 = 20_000;

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
    /// Auto-appended from live traffic by the DISTILL lifecycle hook.
    LlmProduction,
    Import,
    Synthetic,
}

impl ExampleSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LlmBootstrap => "llm_bootstrap",
            Self::Correction => "correction",
            Self::LlmFallback => "llm_fallback",
            Self::LlmProduction => "llm_production",
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

/// Gold-slice row for the teacher audit: a decrypted human correction
/// plus the dedup key the audit reports mismatches under.
#[derive(Debug, Clone)]
pub struct GoldExample {
    pub example_key: Option<String>,
    pub features_text: String,
    pub label: String,
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
    /// Provenance — 'correction' rows are GOLD truth (human labels);
    /// everything else is silver (teacher labels). Eval reports both.
    pub source: String,
    pub embedding: Option<Vec<f32>>,
}

/// Outcome of [`DatasetService::dedupe_by_content`]. Every field is reported in
/// BOTH dry-run and executed mode so the preview a caller approves is the same
/// arithmetic the delete performs.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ContentDedupeOutcome {
    pub dry_run: bool,
    /// Groups of >=2 rows whose embeddings are byte-identical.
    pub duplicate_groups: i64,
    /// Duplicate groups carrying MORE THAN ONE label — the rows that were
    /// actively teaching the model contradictory things.
    pub conflicting_groups: i64,
    /// Rows the precedence order would drop (survivors excluded).
    pub rows_removable: i64,
    /// Removable rows that are themselves corrections — a human labelled the
    /// same content twice, so only the newest survives. Reported separately
    /// because it decrements `corrections_banked` and can move the
    /// `min_corrections_per_class` gate.
    pub corrections_superseded: i64,
    /// Rows actually deleted (0 in dry-run).
    pub rows_removed: u64,
    /// Rows in the dataset that content-dedupe CANNOT see: they have no stored
    /// embedding, so they have no content key to group on.
    ///
    /// Reported because every other number here is scoped to the embedded
    /// population, and a survey that silently hid rows reads as "I checked
    /// everything" when it did not (the misleading-report-field class). A
    /// non-zero value usually means the local embedder was down during an
    /// append — those rows are also invisible to `knn_search` and to the
    /// parametric fit until they are backfilled.
    pub rows_without_embedding: i64,
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
                            if v.len() == expected_embedding_dims() {
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
                                    expected_dims = expected_embedding_dims(),
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
                  features_format, label_json, embedding, embedding_model, source, example_key) ",
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
                    .push_bind(
                        p.embedding
                            .as_ref()
                            .and_then(|_| talos_memory::embedding::active_embedding_model()),
                    )
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
                                embedding_model = COALESCE(EXCLUDED.embedding_model, ml_examples.embedding_model), \
                                source = EXCLUDED.source \
                  WHERE ml_examples.source <> 'correction' \
                     OR EXCLUDED.source = 'correction'",
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
        self.enforce_growth_cap(conn, dataset_id).await?;
        // After the cap, so the two never fight over which rows go: the cap
        // evicts by age, this collapses by content, and running it second means
        // the cap's count reflects rows that actually earned their place.
        self.auto_dedupe_after_append(conn, dataset_id).await;
        Ok(stored)
    }

    /// RFC 0011 P2d growth cap: when `schema_json.max_examples` is set,
    /// evict the OLDEST non-correction rows past the cap — corrections
    /// are PINNED (human truth is never auto-evicted; if corrections
    /// alone exceed the cap, nothing more is removed). Runs inside every
    /// append so the DISTILL auto-append can't grow a dataset
    /// unboundedly between digests. One indexed count + one bounded
    /// delete; no-op when the cap is unset or unexceeded.
    /// Public so the lifecycle integration tests can exercise the
    /// eviction invariant (corrections pinned) directly; production
    /// callers reach it through `insert_prepared`.
    pub async fn enforce_growth_cap(
        &self,
        conn: &mut PgConnection,
        dataset_id: Uuid,
    ) -> Result<()> {
        let schema: Option<serde_json::Value> =
            sqlx::query_scalar("SELECT schema_json FROM ml_datasets WHERE id = $1")
                .bind(dataset_id)
                .fetch_optional(&mut *conn)
                .await
                .context("read dataset schema_json")?;
        let Some(cap) = schema
            .as_ref()
            .and_then(|s| s.get("max_examples"))
            .and_then(|v| v.as_i64())
            .filter(|c| *c > 0)
        else {
            return Ok(());
        };
        let total: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM ml_examples WHERE dataset_id = $1")
                .bind(dataset_id)
                .fetch_one(&mut *conn)
                .await
                .context("count dataset examples")?;
        let excess = total - cap;
        if excess <= 0 {
            return Ok(());
        }
        let evicted = sqlx::query(
            "DELETE FROM ml_examples WHERE id IN ( \
                 SELECT id FROM ml_examples \
                 WHERE dataset_id = $1 AND source <> 'correction' \
                 ORDER BY created_at ASC, id LIMIT $2)",
        )
        .bind(dataset_id)
        .bind(excess)
        .execute(&mut *conn)
        .await
        .context("evict oldest non-correction examples past growth cap")?;
        tracing::info!(
            %dataset_id,
            cap,
            evicted = evicted.rows_affected(),
            "ml dataset growth cap enforced (corrections pinned)"
        );
        Ok(())
    }

    /// Precedence-ranked duplicate groups within ONE dataset, keyed on
    /// embedding identity **within one embedding model**.
    ///
    /// Identical `features_text` deterministically yields an identical
    /// embedding, so the vector IS a usable content key — which lets this run
    /// entirely in SQL with **no decryption**. `md5` here is a GROUPING key
    /// over a column already stored in the row, not a security primitive.
    ///
    /// This is also why the grouping is decoupled from `example_key`: that
    /// column is now a KEYED fingerprint (`crate::content_identity`), so it
    /// changes across a purpose-key rotation, whereas embedding identity does
    /// not. The embedding-keyed collapse is therefore the era-independent
    /// backstop behind the `ch:` → `ck1:` seam — it cleans up any duplicate
    /// the upsert misses because the two eras' keys did not match.
    ///
    /// **Model scoping.** `md5(embedding::text)` is only a content key WITHIN
    /// one embedding model: the same text under two models yields two
    /// different vectors, and during a partial re-embed backfill a dataset
    /// legitimately holds both. Both windows therefore partition by
    /// `(embedding_model, content_key)`, which
    /// * makes cross-model collapse structurally impossible, and
    /// * keeps every embedded row in the population. A strict
    ///   `embedding_model = <active>` FILTER would instead hide rows — the
    ///   survey would report "0 duplicates" for a dataset full of them, and
    ///   `active_embedding_model()` returning `None` (embeddings disabled)
    ///   would silently turn both the operator tool and the on-append
    ///   auto-dedupe into no-ops.
    ///
    /// Legacy rows with `embedding_model IS NULL` (pre-provenance-migration,
    /// stamped by `grandfather_examples_embedding_model`) form their OWN
    /// group-space: SQL `PARTITION BY` treats NULLs as equal to each other and
    /// distinct from every value, which is exactly the wanted semantics — they
    /// collapse among themselves and never mix with a stamped model.
    ///
    /// Rows with `embedding IS NULL` have no content key at all and are
    /// excluded; [`ContentDedupeOutcome::rows_without_embedding`] reports how
    /// many, so the survey never implies a coverage it does not have.
    ///
    /// Two windows are required, not one: attaching `ORDER BY` to a window
    /// changes its default frame to `RANGE UNBOUNDED PRECEDING AND CURRENT
    /// ROW`, which would silently make `COUNT`/`MIN`/`MAX` running aggregates
    /// over a partial partition instead of whole-group facts.
    ///
    /// The ordering ends in `id` for the same reason as the kNN neighbour
    /// query: without a unique tiebreaker the survivor of a tie is chosen by
    /// heap order and can differ between the preview and the delete.
    const CONTENT_RANK_CTE: &'static str = "\
        WITH grouped AS ( \
            SELECT id, source, label_json->>'label' AS label, created_at, \
                   embedding_model, md5(embedding::text) AS content_key \
            FROM ml_examples \
            WHERE dataset_id = $1 AND embedding IS NOT NULL \
        ), ranked AS ( \
            SELECT id, source, \
                   ROW_NUMBER() OVER wo AS rn, \
                   COUNT(*) OVER wp AS grp_size, \
                   (MIN(label) OVER wp) IS DISTINCT FROM (MAX(label) OVER wp) \
                       AS has_conflict \
            FROM grouped \
            WINDOW wo AS ( \
                       PARTITION BY embedding_model, content_key \
                       ORDER BY CASE source \
                                  WHEN 'correction' THEN 0 \
                                  WHEN 'llm_production' THEN 1 \
                                  ELSE 2 END, \
                                created_at DESC, id), \
                   wp AS (PARTITION BY embedding_model, content_key) \
        ) ";

    /// Collapse content-duplicate examples to one row per distinct content,
    /// keeping the highest-precedence label: `correction` > `llm_production`
    /// > everything else (i.e. `llm_bootstrap`), newest first, `id` last.
    ///
    /// WHY this exists (observed 2026-07-27 on inbox-classifier-personal): a
    /// scheduled CI workflow re-failing on the same commit emits many DISTINCT
    /// emails whose `Subject`/`From`/`Snippet` are byte-identical. The
    /// `(dataset_id, example_key)` upsert cannot collapse them — the message
    /// ids genuinely differ — so the dataset accumulated one email template as
    /// ~72% of the `archive` class, including NINE copies of a single alert
    /// carrying FIVE `archive` labels and FOUR human `to_read` corrections.
    /// That is an irreducible contradiction in feature space: no model or
    /// feature can separate rows that are identical, so the majority simply
    /// outvotes the human. It also mints the duplicate embeddings that made
    /// the kNN neighbour vote tie-dependent.
    ///
    /// `dry_run` performs the identical grouping and reports what WOULD go,
    /// deleting nothing — the intended first call, since this is destructive
    /// and training data is not trivially reconstructible.
    ///
    /// `protect_corrections` exempts `source = 'correction'` rows from removal.
    /// The UNATTENDED path (see [`Self::auto_dedupe_after_append`]) always sets
    /// it: collapsing duplicate corrections is semantically right — the newest
    /// carries the human's latest intent for identical content — but it also
    /// decrements `corrections_banked` and can move the
    /// `min_corrections_per_class` promotion gate, and a background task must
    /// not silently delete human-authored data or move a gate nobody asked it
    /// to move. An operator can still opt in explicitly.
    ///
    /// Caller must supply a tenant-scoped connection; `dataset_id` is
    /// additionally re-asserted on the delete as a belt-and-braces predicate.
    pub async fn dedupe_by_content(
        &self,
        conn: &mut PgConnection,
        dataset_id: Uuid,
        dry_run: bool,
        protect_corrections: bool,
    ) -> Result<ContentDedupeOutcome> {
        // `$2` = protect_corrections. A protected run reports what IT would
        // remove, not what an unprotected run could — the preview must match
        // the delete that follows it, not a hypothetical one.
        let survey_sql = format!(
            "{}SELECT \
                 COUNT(*) FILTER (WHERE rn > 1 AND (NOT $2 OR source <> 'correction')) \
                     AS rows_removable, \
                 COUNT(*) FILTER (WHERE rn = 1 AND grp_size > 1) AS duplicate_groups, \
                 COUNT(*) FILTER (WHERE rn = 1 AND has_conflict) AS conflicting_groups, \
                 COUNT(*) FILTER (WHERE rn > 1 AND source = 'correction' AND NOT $2) \
                     AS corrections_superseded \
             FROM ranked",
            Self::CONTENT_RANK_CTE
        );
        let (rows_removable, duplicate_groups, conflicting_groups, corrections_superseded): (
            i64,
            i64,
            i64,
            i64,
        ) = sqlx::query_as(&survey_sql)
            .bind(dataset_id)
            .bind(protect_corrections)
            .fetch_one(&mut *conn)
            .await
            .context("survey content-duplicate examples")?;

        // The population this survey could NOT consider. Counted separately
        // from the CTE (which drops these rows before it can count anything)
        // and reported unconditionally, in dry-run and executed mode alike.
        let rows_without_embedding: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM ml_examples WHERE dataset_id = $1 AND embedding IS NULL",
        )
        .bind(dataset_id)
        .fetch_one(&mut *conn)
        .await
        .context("count examples without an embedding")?;

        let mut outcome = ContentDedupeOutcome {
            dry_run,
            duplicate_groups,
            conflicting_groups,
            rows_removable,
            corrections_superseded,
            rows_removed: 0,
            rows_without_embedding,
        };
        if dry_run || rows_removable == 0 {
            return Ok(outcome);
        }

        let delete_sql = format!(
            "{}DELETE FROM ml_examples e USING ranked r \
             WHERE e.id = r.id AND r.rn > 1 AND e.dataset_id = $1 \
               AND (NOT $2 OR r.source <> 'correction')",
            Self::CONTENT_RANK_CTE
        );
        let res = sqlx::query(&delete_sql)
            .bind(dataset_id)
            .bind(protect_corrections)
            .execute(&mut *conn)
            .await
            .context("delete content-duplicate examples")?;
        outcome.rows_removed = res.rows_affected();

        sqlx::query("UPDATE ml_datasets SET updated_at = NOW() WHERE id = $1")
            .bind(dataset_id)
            .execute(&mut *conn)
            .await
            .context("touch ml_dataset after dedupe")?;

        tracing::info!(
            %dataset_id,
            duplicate_groups,
            conflicting_groups,
            corrections_superseded,
            rows_without_embedding,
            rows_removed = outcome.rows_removed,
            "ml dataset content-dedupe applied"
        );
        Ok(outcome)
    }

    /// Keep the dataset content-clean as it grows, on the append path.
    ///
    /// Every ingest cycle re-delivers templated mail (the CI alert that fires
    /// again on the same commit), so duplicates REACCUMULATE after a one-off
    /// sweep. Left alone they resume acting as unearned vote weight: 803 of
    /// 1800 rows (45%) had built up before the first manual dedupe, and the
    /// stale majority was outvoting human corrections.
    ///
    /// Deliberately conservative next to the operator-invoked tool:
    /// * corrections are PROTECTED — a background task never deletes
    ///   human-authored rows, nor silently moves the
    ///   `min_corrections_per_class` gate;
    /// * it is best-effort — a dedupe failure must not fail the append that
    ///   just did the expensive encrypt + embed work, so the error is logged
    ///   and swallowed (same posture as the growth cap's eviction);
    /// * above [`AUTO_DEDUPE_MAX_ROWS`] it declines and says so, rather than
    ///   silently adding an O(N) hash-and-sort to every append. The whole-table
    ///   scan is a few tens of ms at the scale this runs at, but that is a
    ///   property of the current size, not a guarantee — the operator tool has
    ///   no such bound and stays the right call for a large backlog.
    async fn auto_dedupe_after_append(&self, conn: &mut PgConnection, dataset_id: Uuid) {
        let total: i64 =
            match sqlx::query_scalar("SELECT COUNT(*) FROM ml_examples WHERE dataset_id = $1")
                .bind(dataset_id)
                .fetch_one(&mut *conn)
                .await
            {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!(%dataset_id, error = %e, "auto-dedupe: count failed; skipped");
                    return;
                }
            };
        if total > AUTO_DEDUPE_MAX_ROWS {
            tracing::warn!(
                %dataset_id,
                total,
                limit = AUTO_DEDUPE_MAX_ROWS,
                "auto-dedupe skipped: dataset above the inline bound — run ml_dedupe_dataset"
            );
            return;
        }
        match self.dedupe_by_content(conn, dataset_id, false, true).await {
            Ok(o) if o.rows_removed > 0 => tracing::info!(
                %dataset_id,
                rows_removed = o.rows_removed,
                conflicting_groups = o.conflicting_groups,
                "auto-dedupe collapsed content duplicates on append"
            ),
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(%dataset_id, error = %e, "auto-dedupe failed; append kept")
            }
        }
    }

    /// The dataset's label vocabulary — every distinct class it has ever
    /// carried, sorted.
    ///
    /// The review UI needs this to offer a correct-label button per class.
    /// Deriving that list from the labels PRESENT IN THE FEED (what it did
    /// before) silently omits any class no pending row happens to propose, and
    /// the reviewer then cannot express the answer at all. That case is not an
    /// edge case — it is the MOST informative correction available, because
    /// both models being wrong is a stronger signal than either being wrong
    /// alone. Observed 2026-07-27: a CI-failure row where fast said `to_read`
    /// and the teacher said `archive`, while the reviewer judged it
    /// `follow_up`; no button existed.
    ///
    /// Reads the dataset, not a sample, so a class stays offerable even when
    /// nothing in the current queue proposes it.
    pub async fn label_vocabulary(
        &self,
        conn: &mut PgConnection,
        dataset_id: Uuid,
    ) -> Result<Vec<String>> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT DISTINCT label_json->>'label' AS label FROM ml_examples \
             WHERE dataset_id = $1 AND label_json ? 'label' \
             ORDER BY label",
        )
        .bind(dataset_id)
        .fetch_all(&mut *conn)
        .await
        .context("read dataset label vocabulary")?;
        Ok(rows.into_iter().map(|(l,)| l).collect())
    }

    /// Human-correction counts per class (`source = 'correction'`) —
    /// the lifecycle policy's human-in-the-loop gate input.
    pub async fn corrections_per_class(
        &self,
        conn: &mut PgConnection,
        dataset_id: Uuid,
    ) -> Result<std::collections::BTreeMap<String, i64>> {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT label_json->>'label', COUNT(*) FROM ml_examples \
             WHERE dataset_id = $1 AND source = 'correction' \
               AND label_json->>'label' IS NOT NULL GROUP BY 1",
        )
        .bind(dataset_id)
        .fetch_all(&mut *conn)
        .await
        .context("count corrections per class")?;
        Ok(rows.into_iter().collect())
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

    /// Class-balanced, most-recent-first human CORRECTIONS for few-shot
    /// teacher anchoring (the `talos.ml.fewshot` op). Recency ordering is
    /// deliberate — corrections encode the CURRENT boundary truth, and the
    /// newest reviews are the ones fixing what the teacher gets wrong
    /// today. Features are truncated to the wire cap at a char boundary:
    /// anchors need the discriminative head of the text, and the cap
    /// bounds both reply size and the prompt-injection surface a stored
    /// example can carry into future prompts.
    ///
    /// Returns up to `k_total` (features_text, label) pairs, interleaved
    /// round-robin across labels so a lopsided correction history (e.g.
    /// 49 to_read vs 16 archive) still anchors every corrected class.
    pub async fn few_shot_corrections(
        &self,
        conn: &mut PgConnection,
        dataset_id: Uuid,
        k_total: u32,
    ) -> Result<Vec<(String, String)>> {
        let k_total = k_total.clamp(1, talos_memory::ml_rpc::MAX_FEWSHOT_K) as usize;
        // Up to k_total per label (the interleave below trims to k_total
        // overall); ranked window first, ciphertext joined only for the
        // winners — same shape as `sample_examples`.
        let rows: Vec<EncRow> = sqlx::query_as(&format!(
            "SELECT {ENC_ROW_COLS} FROM ml_examples \
             WHERE id IN ( \
                 SELECT id FROM (SELECT id, ROW_NUMBER() OVER \
                     (PARTITION BY label_json->>'label' ORDER BY created_at DESC) AS rn \
                   FROM ml_examples \
                   WHERE dataset_id = $1 AND source = 'correction' \
                     AND label_json ? 'label') t \
                 WHERE rn <= $2) \
             ORDER BY created_at DESC",
        ))
        .bind(dataset_id)
        .bind(k_total as i64)
        .fetch_all(&mut *conn)
        .await?;

        // Decrypt + truncate, grouped per label preserving recency order.
        let mut per_label: std::collections::BTreeMap<String, Vec<String>> =
            std::collections::BTreeMap::new();
        for row in rows {
            let (_id, label, _source, text) = self.decrypt_row(dataset_id, row).await?;
            let truncated = talos_text_util::truncate_at_char_boundary(
                &text,
                talos_memory::ml_rpc::MAX_FEWSHOT_FEATURE_BYTES,
            )
            .to_string();
            per_label.entry(label).or_default().push(truncated);
        }

        // Round-robin across labels: one from each class per pass, so no
        // class dominates the anchor budget.
        let mut queues: Vec<(String, std::collections::VecDeque<String>)> =
            per_label.into_iter().map(|(l, v)| (l, v.into())).collect();
        let mut out = Vec::with_capacity(k_total);
        while out.len() < k_total {
            let mut yielded = false;
            for (label, q) in queues.iter_mut() {
                if out.len() >= k_total {
                    break;
                }
                if let Some(text) = q.pop_front() {
                    out.push((text, label.clone()));
                    yielded = true;
                }
            }
            if !yielded {
                break;
            }
        }
        Ok(out)
    }

    /// Most-recent human corrections, decrypted with their dedup keys —
    /// the teacher-vs-gold audit's input (every `source='correction'`
    /// row IS gold truth; the audit needs the full slice, not the
    /// eval-holdout subset). Capped by the caller.
    pub async fn load_corrections_decrypted(
        &self,
        conn: &mut PgConnection,
        dataset_id: Uuid,
        limit: i64,
    ) -> Result<Vec<GoldExample>> {
        let limit = limit.clamp(1, 100);
        let rows: Vec<EncRow> = sqlx::query_as(&format!(
            "SELECT {ENC_ROW_COLS} FROM ml_examples \
             WHERE dataset_id = $1 AND source = 'correction' AND label_json ? 'label' \
             ORDER BY created_at DESC, id LIMIT $2",
        ))
        .bind(dataset_id)
        .bind(limit)
        .fetch_all(&mut *conn)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let example_key = row.6.clone();
            let (_id, label, _source, text) = self.decrypt_row(dataset_id, row).await?;
            out.push(GoldExample {
                example_key,
                features_text: text.to_string(),
                label,
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

    /// [`Self::load_labels`] plus `source` and `example_key` per row —
    /// the inputs the correction-aware splitter needs (corrections are
    /// partitioned by a stable hash of `example_key`, falling back to
    /// the row id; see `eval::correction_aware_holdout`).
    pub async fn load_labels_with_source(
        &self,
        conn: &mut PgConnection,
        dataset_id: Uuid,
    ) -> Result<Vec<(Uuid, String, String, Option<String>)>> {
        Ok(sqlx::query_as(
            "SELECT id, label_json->>'label', source, example_key FROM ml_examples \
             WHERE dataset_id = $1 AND label_json ? 'label'",
        )
        .bind(dataset_id)
        .fetch_all(&mut *conn)
        .await?)
    }

    /// Train-split embeddings + labels for fitting a parametric backend.
    /// Skips decryption (only the vector + label are needed) and rows with
    /// no stored embedding (a parametric model can't use them — they'd
    /// have abstained under knn too). Mirrors `knn_search(train_only)`'s
    /// exclusion of the holdout so the fit never sees eval rows.
    pub async fn load_train_embeddings(
        &self,
        conn: &mut PgConnection,
        dataset_id: Uuid,
    ) -> Result<Vec<(Vec<f32>, String)>> {
        Ok(self
            .load_train_embeddings_with_source(conn, dataset_id)
            .await?
            .into_iter()
            .map(|(emb, label, _)| (emb, label))
            .collect())
    }

    /// [`Self::load_train_embeddings`] plus an `is_correction` flag per
    /// row so the weighted fit can emphasize human corrections
    /// (corrections-as-training, 2026-07-19).
    pub async fn load_train_embeddings_with_source(
        &self,
        conn: &mut PgConnection,
        dataset_id: Uuid,
    ) -> Result<Vec<(Vec<f32>, String, bool)>> {
        let rows: Vec<(Option<pgvector::Vector>, Option<String>, bool)> = sqlx::query_as(
            "SELECT embedding, label_json->>'label', source = 'correction' \
             FROM ml_examples \
             WHERE dataset_id = $1 AND split = 'train' \
               AND embedding IS NOT NULL AND embedding_model = $2 \
               AND label_json ? 'label'",
        )
        .bind(dataset_id)
        .bind(talos_memory::embedding::active_embedding_model())
        .fetch_all(&mut *conn)
        .await
        .context("load train embeddings")?;
        Ok(rows
            .into_iter()
            .filter_map(|(emb, label, is_corr)| match (emb, label) {
                (Some(v), Some(l)) => Some((v.to_vec(), l, is_corr)),
                _ => None,
            })
            .collect())
    }

    /// Dataset-level label frequencies (classification rows only) — the
    /// class priors for balanced voting. One indexed grouped count.
    pub async fn class_counts(
        &self,
        conn: &mut PgConnection,
        dataset_id: Uuid,
    ) -> Result<std::collections::HashMap<String, i64>> {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT label_json->>'label', COUNT(*) FROM ml_examples \
             WHERE dataset_id = $1 AND label_json->>'label' IS NOT NULL GROUP BY 1",
        )
        .bind(dataset_id)
        .fetch_all(&mut *conn)
        .await?;
        Ok(rows.into_iter().collect())
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
    /// Re-embed rows whose vector was produced by a DIFFERENT model
    /// than the active one (provenance migration follow-path): decrypt
    /// features, regenerate locally (`local_only = true`, matching the
    /// append path — dataset text never leaves the host for embedding),
    /// stamp the new model. Batched; call repeatedly until it returns
    /// 0. Rows whose embedder call fails are left untouched (still
    /// invisible to reads via the strict filter — degrade, never mix).
    pub async fn re_embed_examples(
        &self,
        conn: &mut PgConnection,
        dataset_id: Uuid,
        limit: i64,
    ) -> Result<usize> {
        let Some(active) = talos_memory::embedding::active_embedding_model() else {
            return Ok(0);
        };
        let limit = limit.clamp(1, 500);
        let rows: Vec<(
            Uuid,
            Vec<u8>,
            Uuid,
            i16,
            Option<String>,
            String,
            Option<String>,
        )> = sqlx::query_as(&format!(
            "SELECT {ENC_ROW_COLS} FROM ml_examples \
                 WHERE dataset_id = $1 AND embedding IS NOT NULL \
                   AND embedding_model IS DISTINCT FROM $2 \
                 ORDER BY created_at ASC LIMIT $3",
        ))
        .bind(dataset_id)
        .bind(&active)
        .bind(limit)
        .fetch_all(&mut *conn)
        .await?;

        let mut done = 0usize;
        for row in rows {
            let (id, _label, _source, text) = self.decrypt_row(dataset_id, row).await?;
            let Some(emb) = talos_memory::embedding::generate_embedding(&text, true).await else {
                tracing::warn!(%id, "re_embed_examples: embedder unavailable — row left for retry");
                continue;
            };
            sqlx::query(
                "UPDATE ml_examples SET embedding = $1, embedding_model = $2 WHERE id = $3",
            )
            .bind(pgvector::Vector::from(emb))
            .bind(&active)
            .bind(id)
            .execute(&mut *conn)
            .await?;
            done += 1;
        }
        Ok(done)
    }

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
            let (id, label, source, text) = self
                .decrypt_row(
                    dataset_id,
                    (id, enc, key_id, format, label, source, example_key),
                )
                .await?;
            out.push(HoldoutExample {
                id,
                features_text: text,
                label,
                source,
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

    /// Pin `ivfflat.probes` to the index's `lists` for THIS transaction
    /// (exact scan within the index; `set_config(..., true)` is
    /// transaction-local so nothing leaks to the pooled connection).
    /// Idempotent and cheap, but per-search re-pinning doubles eval's
    /// statement count, so `knn_search` does NOT pin — every caller
    /// pins once per transaction (`run_knn_eval` and `knn_predict_text`
    /// both do; new callers must too or they silently search at
    /// probes=1 recall).
    pub async fn pin_ann_probes(&self, conn: &mut PgConnection) -> Result<()> {
        sqlx::query_scalar::<_, String>("SELECT set_config('ivfflat.probes', '20', true)")
            .fetch_one(&mut *conn)
            .await
            .context("pin ivfflat.probes")?;
        Ok(())
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
        if embedding.len() != expected_embedding_dims() {
            return Ok(None);
        }
        self.pin_ann_probes(&mut *conn).await?;
        let neighbors = self
            .knn_search(conn, dataset_id, &embedding, k, true)
            .await?;
        if neighbors.is_empty() {
            // Abstain without paying the class-priors aggregate.
            return Ok(None);
        }
        // Hot-path note (P2d): priors change only on append — the
        // lifecycle service should cache these keyed on the dataset's
        // updated_at instead of re-aggregating per prediction.
        let counts = self.class_counts(conn, dataset_id).await?;
        Ok(crate::knn::knn_vote_balanced(&neighbors, &counts))
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
    ///
    /// The `ORDER BY … <=> $2, id` tiebreaker is LOAD-BEARING, not tidiness
    /// (2026-07-26). `ml_examples` legitimately holds exact-duplicate feature
    /// text with CONFLICTING labels — the same GitHub "Run failed" notification
    /// appears bootstrap-labelled `archive` and human-corrected `to_read`.
    /// Duplicate text means duplicate embeddings, so those rows tie exactly on
    /// distance, and without a unique tiebreaker Postgres breaks the tie by
    /// whatever heap order the scan happens to produce. The k-neighbour vote
    /// then flips between runs on identical data.
    ///
    /// Observed: two evals of the SAME model with the SAME policy returned
    /// macro_f1 0.7065 vs 0.6152 and selected a DIFFERENT backend, while the
    /// logistic-regression arm was bit-identical across both runs — isolating
    /// the nondeterminism to this query. That makes the promotion gate a
    /// coin-flip, and with `auto_advance` a model can promote on a lucky draw.
    ///
    /// Same defect as structural lint check 28 (OFFSET pagination needs a
    /// unique ORDER BY tiebreaker), in the ANN path.
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
        let rows: Vec<(String, f64, bool)> = sqlx::query_as(
            "SELECT label_json->>'label', 1 - (embedding <=> $2) AS sim, \
                    source = 'correction' AS is_correction \
             FROM ml_examples \
             WHERE dataset_id = $1 AND embedding IS NOT NULL \
               AND embedding_model = $5 \
               AND label_json ? 'label' \
               AND (NOT $4 OR split IS DISTINCT FROM 'holdout') \
             ORDER BY embedding <=> $2, id LIMIT $3",
        )
        .bind(dataset_id)
        .bind(&qvec)
        .bind(k)
        .bind(train_only)
        .bind(talos_memory::embedding::active_embedding_model())
        .fetch_all(&mut *conn)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(label, sim, is_correction)| Neighbor {
                label,
                similarity: sim as f32,
                is_correction,
            })
            .collect())
    }
}

/// One-time grandfather stamp for the provenance migration (ml_examples
/// side; sibling of `talos_memory::grandfather_embedding_model`).
pub async fn grandfather_examples_embedding_model(
    pool: &sqlx::Pool<sqlx::Postgres>,
) -> anyhow::Result<u64> {
    let Some(model) = talos_memory::embedding::active_embedding_model() else {
        return Ok(0);
    };
    let res = sqlx::query(
        "UPDATE ml_examples SET embedding_model = $1 \
         WHERE embedding IS NOT NULL AND embedding_model IS NULL",
    )
    .bind(&model)
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}
