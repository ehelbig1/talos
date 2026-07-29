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
    /// When the row was written — i.e. when the eval that produced
    /// `metrics_json` completed (RFC 3339).
    ///
    /// Added 2026-07-28 (measurement envelope, D1): the column has existed
    /// since the RFC-0011 migration, but every reader stripped it, so a model
    /// card rendered a promoted accuracy with no indication of whether it was
    /// measured this morning or in April. `None` only when a caller
    /// constructed the row without reading the column.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trained_at: Option<String>,
}

/// Per-model summary for the human-in-the-loop review UI: lifecycle
/// position, promoted accuracy, and the count of pending disagreements —
/// everything the review surface needs to show a model list with a
/// "needs review" badge, resolved in ONE query.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ModelReviewSummary {
    pub model_id: Uuid,
    pub name: String,
    pub task_type: String,
    pub lifecycle_state: String,
    pub promoted_version: Option<i32>,
    /// The bare holdout accuracy of the promoted version.
    ///
    /// KEPT for the live GraphQL consumer (`MlModelSummary.promotedAccuracy`,
    /// rendered by `frontend/src/pages/ModelReview.tsx`), which would
    /// otherwise lose its column. It is the #588 shape — a float with no
    /// sample size, no version and no date — so anything NEW should read
    /// [`Self::promoted_accuracy_measurement`], which carries all three.
    pub promoted_accuracy: Option<f64>,
    /// The same number, enveloped: `n` = the holdout total the accuracy was
    /// computed over, `source_version` = the promoted version, `measured_at` =
    /// the version row's `trained_at`, plus the Wilson 95% interval.
    ///
    /// `None` when the model is unpromoted, when the stored report carries no
    /// `total` (every version written by this codebase does), or when the
    /// pair is not a valid proportion — an envelope is never fabricated to
    /// dress up a number whose denominator we do not know.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub promoted_accuracy_measurement: Option<talos_measurement::Measurement>,
    /// The promoted version's backend — the fourth thing the row already knew
    /// and the reader threw away.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub promoted_backend: Option<String>,
    pub pending_disagreements: i64,
}

/// What `promoted_accuracy_measurement` (and the model card's promoted-metrics
/// block) is computed over.
pub const PROMOTED_ACCURACY_POPULATION: &str =
    "holdout split of the model's dataset at eval time (report.total rows); \
     abstentions count as errors";

/// Reading guide for the `promoted_metrics` passthrough blob.
pub const PROMOTED_METRICS_NOTE: &str =
    "promoted_metrics is the SERVING version's stored eval, not the latest one — \
     promoted_version/promoted_trained_at/promoted_artifact_sha256 identify exactly which run \
     produced it. promoted_trained_at is when that eval was recorded; a blob whose \
     provenance keys are null was written before 2026-07-28 and its age is unknown, which is \
     not the same as recent.";

/// Format a DB timestamp as RFC 3339 for a carried `measured_at`.
///
/// A read-side FORMATTING of a stored instant — not a clock read. There is no
/// current-time fallback here, and there must never be one: the whole
/// point of the field is to distinguish a fresh measurement from an old one.
fn rfc3339(ts: chrono::DateTime<chrono::Utc>) -> String {
    ts.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Decode one `ml_model_versions` row — ONE place, so a column added to the
/// projection can never reach one reader and not the other (`trained_at` was
/// projected by neither before 2026-07-28).
fn decode_version_row(r: sqlx::postgres::PgRow) -> Result<ModelVersionRow> {
    let trained_at: Option<chrono::DateTime<chrono::Utc>> = r.try_get("trained_at")?;
    Ok(ModelVersionRow {
        id: r.try_get("id")?,
        model_id: r.try_get("model_id")?,
        version: r.try_get("version")?,
        backend: r.try_get("backend")?,
        metrics_json: r.try_get("metrics_json")?,
        status: r.try_get("status")?,
        trained_at: trained_at.map(rfc3339),
    })
}

/// Envelope a promoted version's holdout accuracy with the provenance that
/// lives on the SAME row: its denominator, its version and its measurement
/// time.
///
/// Pure, so the compat rules are unit-pinned without a database:
/// * no `total` → `None`. A number whose denominator we do not know does not
///   get an envelope that implies we do; the bare `promoted_accuracy` field
///   still carries it.
/// * no `trained_at` / no `version` → the envelope is still built, with those
///   fields simply ABSENT. There is no substitute value (no `now()`, no "v?").
#[must_use]
fn promoted_accuracy_envelope(
    accuracy: Option<f64>,
    total: Option<i64>,
    version: Option<i32>,
    trained_at: Option<chrono::DateTime<chrono::Utc>>,
) -> Option<talos_measurement::Measurement> {
    let accuracy = accuracy?;
    let n = u64::try_from(total?).ok()?;
    let mut m = talos_measurement::Measurement::from_fraction(accuracy, n)?
        .with_population(PROMOTED_ACCURACY_POPULATION);
    if let Some(v) = version {
        m = m.with_source_version(format!("v{v}"));
    }
    if let Some(at) = trained_at {
        m = m.with_measured_at(rfc3339(at));
    }
    Some(m)
}

/// Name-resolution result (named struct, not tuple-soup — future fields
/// like task_type are additive instead of positionally breaking).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ResolvedModel {
    pub name: String,
    /// P2d lifecycle position (llm_only/shadow/hybrid/fast_primary).
    pub lifecycle_state: String,
    pub model_id: Uuid,
    pub dataset_id: Option<Uuid>,
    pub config_json: serde_json::Value,
    /// The lifecycle transition policy (ml_set_policy), when set —
    /// surfaced on the model card so "which gates apply" doesn't need a
    /// separate DB query.
    pub policy_json: Option<serde_json::Value>,
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
             RETURNING version, trained_at",
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
        // The DB's own write instant, returned by the INSERT — the same value
        // every later reader of this row will see, so the card and the row
        // can never disagree about when the eval landed.
        let trained_at: chrono::DateTime<chrono::Utc> = row.try_get("trained_at")?;
        Ok(ModelVersionRow {
            id,
            model_id,
            version,
            backend: backend.to_string(),
            metrics_json: metrics_json.clone(),
            status: "trained".to_string(),
            trained_at: Some(rfc3339(trained_at)),
        })
    }

    /// Promote a version: it becomes what `predict(model_name)` serves.
    /// The previous promoted version is retired in the same transaction
    /// scope (caller owns the tx).
    /// Owner-scoped policy write. Callers MUST have validated the value
    /// through `PolicyJson::parse` + `validate()` first — this method is
    /// storage only.
    pub async fn set_policy(
        conn: &mut PgConnection,
        model_id: Uuid,
        user_id: Uuid,
        policy_json: &serde_json::Value,
    ) -> Result<bool> {
        let res = sqlx::query(
            "UPDATE ml_models SET policy_json = $1, updated_at = NOW() \
             WHERE id = $2 AND user_id = $3",
        )
        .bind(policy_json)
        .bind(model_id)
        .bind(user_id)
        .execute(&mut *conn)
        .await?;
        Ok(res.rows_affected() == 1)
    }

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
        // New serving version = new shadow era: agreement accumulated by
        // the retired version must not feed the drift guard's judgment
        // of this one (migration 20260714170000).
        crate::lifecycle::bump_shadow_epoch(&mut *conn, model_id).await?;
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
        // `trained_at` + `artifact_sha256` come off the SAME row already being
        // read (no extra query, no N+1): the provenance was always one column
        // over from `promoted_metrics` and was simply not projected, so a
        // reader could not tell a metrics blob measured this morning from one
        // measured in April, nor which artifact produced it.
        let rows = sqlx::query(
            "SELECT m.id, m.name, m.task_type, m.dataset_id, m.created_at, \
                    v.version AS promoted_version, v.backend AS promoted_backend, \
                    v.metrics_json AS promoted_metrics, \
                    v.trained_at AS promoted_trained_at, \
                    v.artifact_sha256 AS promoted_artifact_sha256 \
             FROM ml_models m \
             LEFT JOIN ml_model_versions v ON v.id = m.production_version_id \
             WHERE m.user_id = $1 \
             ORDER BY m.created_at DESC LIMIT 100",
        )
        .bind(user_id)
        .fetch_all(&mut *conn)
        .await?;
        rows.into_iter()
            .map(|r| -> Result<serde_json::Value> {
                let trained_at: Option<chrono::DateTime<chrono::Utc>> =
                    r.try_get("promoted_trained_at")?;
                Ok(serde_json::json!({
                    "id": r.try_get::<Uuid, _>("id")?.to_string(),
                    "name": r.try_get::<String, _>("name")?,
                    "task_type": r.try_get::<String, _>("task_type")?,
                    "dataset_id": r.try_get::<Option<Uuid>, _>("dataset_id")?.map(|d| d.to_string()),
                    "promoted_version": r.try_get::<Option<i32>, _>("promoted_version")?,
                    "promoted_backend": r.try_get::<Option<String>, _>("promoted_backend")?,
                    "promoted_metrics": r.try_get::<Option<serde_json::Value>, _>("promoted_metrics")?,
                    // Provenance for the blob above, carried from the row.
                    // Null on an unpromoted model — never a stand-in "now".
                    "promoted_trained_at": trained_at.map(rfc3339),
                    "promoted_artifact_sha256":
                        r.try_get::<Option<String>, _>("promoted_artifact_sha256")?,
                    "promoted_metrics_note": PROMOTED_METRICS_NOTE,
                }))
            })
            .collect()
    }

    /// Per-model review summaries, owner-scoped, in ONE query. The
    /// pending-disagreement count is a correlated subquery (no N+1);
    /// ordered so the models with the most pending review float to the
    /// top. `promoted_accuracy` is lifted from the promoted version's
    /// eval report (NULL when unpromoted).
    ///
    /// The accuracy is returned TWICE, deliberately (2026-07-28, D1): the bare
    /// float for the existing GraphQL/frontend column, and
    /// `promoted_accuracy_measurement` — the same number with the denominator
    /// (`report.total`), the version, the backend and the row's `trained_at`
    /// attached. Those four columns were always on the joined row and were
    /// stripped by this reader; it is the #588 defect (an accuracy attributed
    /// to the wrong model version) in its original location.
    pub async fn list_models_for_review(
        conn: &mut PgConnection,
        user_id: Uuid,
    ) -> Result<Vec<ModelReviewSummary>> {
        let rows = sqlx::query(
            "SELECT m.id, m.name, m.task_type, m.lifecycle_state, \
                    v.version AS promoted_version, v.backend AS promoted_backend, \
                    v.trained_at AS promoted_trained_at, \
                    (v.metrics_json #>> '{report,accuracy}')::float8 AS promoted_accuracy, \
                    (v.metrics_json #>> '{report,total}')::int8 AS promoted_total, \
                    (SELECT COUNT(*) FROM ml_disagreements d \
                       WHERE d.model_id = m.id AND d.user_id = m.user_id \
                         AND d.status = 'pending') AS pending \
             FROM ml_models m \
             LEFT JOIN ml_model_versions v ON v.id = m.production_version_id \
             WHERE m.user_id = $1 \
             ORDER BY pending DESC, m.created_at DESC LIMIT 100",
        )
        .bind(user_id)
        .fetch_all(&mut *conn)
        .await
        .context("list models for review")?;
        rows.into_iter()
            .map(|r| -> Result<ModelReviewSummary> {
                let promoted_accuracy: Option<f64> = r.try_get("promoted_accuracy")?;
                let promoted_total: Option<i64> = r.try_get("promoted_total")?;
                let promoted_version: Option<i32> = r.try_get("promoted_version")?;
                let promoted_backend: Option<String> = r.try_get("promoted_backend")?;
                let trained_at: Option<chrono::DateTime<chrono::Utc>> =
                    r.try_get("promoted_trained_at")?;
                Ok(ModelReviewSummary {
                    model_id: r.try_get("id")?,
                    name: r.try_get("name")?,
                    task_type: r.try_get("task_type")?,
                    lifecycle_state: r.try_get("lifecycle_state")?,
                    promoted_version,
                    promoted_accuracy,
                    promoted_accuracy_measurement: promoted_accuracy_envelope(
                        promoted_accuracy,
                        promoted_total,
                        promoted_version,
                        trained_at,
                    ),
                    promoted_backend,
                    // NULL can't occur (COUNT), but read as Option so a
                    // schema/type drift errors via `?` instead of panicking.
                    pending_disagreements: r.try_get::<Option<i64>, _>("pending")?.unwrap_or(0),
                })
            })
            .collect()
    }

    /// Load a version's artifact bytes (parametric backends only),
    /// verifying the stored sha256 — a corrupted or tampered artifact must
    /// never be loaded into a live serving path. `None` = no artifact
    /// (e.g. a lazy knn version) or the version doesn't exist.
    pub async fn get_version_artifact(
        conn: &mut PgConnection,
        version_id: Uuid,
    ) -> Result<Option<Vec<u8>>> {
        let row: Option<(Option<Vec<u8>>, Option<String>)> =
            sqlx::query_as("SELECT artifact, artifact_sha256 FROM ml_model_versions WHERE id = $1")
                .bind(version_id)
                .fetch_optional(&mut *conn)
                .await
                .context("load version artifact")?;
        let Some((Some(bytes), sha)) = row else {
            return Ok(None);
        };
        // Fail CLOSED: an artifact must carry its digest. `create_version`
        // always writes both, so a present artifact with a NULL sha256 is a
        // partial/hand-written row — refuse the unverified bytes rather than
        // loading them into the live serving path.
        let expected =
            sha.context("artifact present but no sha256 digest — refusing unverified bytes")?;
        let actual = talos_text_util::sha256_hex_bytes(&bytes);
        anyhow::ensure!(
            actual == expected,
            "version artifact sha256 mismatch — refusing to load a corrupted model"
        );
        Ok(Some(bytes))
    }

    /// All versions of one model, newest first (the model card's history).
    pub async fn list_versions(
        conn: &mut PgConnection,
        model_id: Uuid,
    ) -> Result<Vec<ModelVersionRow>> {
        let rows = sqlx::query(
            "SELECT id, model_id, version, backend, metrics_json, status, trained_at \
             FROM ml_model_versions WHERE model_id = $1 ORDER BY version DESC",
        )
        .bind(model_id)
        .fetch_all(&mut *conn)
        .await?;
        rows.into_iter().map(decode_version_row).collect()
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
            "SELECT id, name, lifecycle_state, dataset_id, config_json, policy_json, \
                    production_version_id \
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
            "SELECT id, name, lifecycle_state, dataset_id, config_json, policy_json, \
                    production_version_id \
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
        let lifecycle_state: String = m.try_get("lifecycle_state")?;
        let dataset_id: Option<Uuid> = m.try_get("dataset_id")?;
        let config: serde_json::Value = m.try_get("config_json")?;
        let policy: Option<serde_json::Value> = m.try_get("policy_json")?;
        let prod_id: Option<Uuid> = m.try_get("production_version_id")?;
        let version = match prod_id {
            Some(vid) => {
                let v = sqlx::query(
                    "SELECT id, model_id, version, backend, metrics_json, status, trained_at \
                     FROM ml_model_versions WHERE id = $1",
                )
                .bind(vid)
                .fetch_optional(&mut *conn)
                .await?;
                v.map(decode_version_row).transpose()?
            }
            None => None,
        };
        Ok(Some(ResolvedModel {
            model_id,
            name,
            lifecycle_state,
            dataset_id,
            config_json: config,
            policy_json: policy,
            promoted_version: version,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(y: i32, m: u32, d: u32) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc.with_ymd_and_hms(y, m, d, 12, 0, 0).unwrap()
    }

    /// D1: the #588 shape, closed. The accuracy arrives with the denominator,
    /// the version and the date that were always one column over on the same
    /// row — and with the Wilson interval, so 1-of-1 cannot read as 400-of-400.
    #[test]
    fn the_promoted_accuracy_envelope_carries_n_version_and_date() {
        let m = promoted_accuracy_envelope(Some(0.8), Some(35), Some(19), Some(at(2026, 4, 3)))
            .expect("a promoted version with a report total is envelopable");
        assert!((m.value - 0.8).abs() < 1e-12);
        assert_eq!(m.n, 35, "n is report.total — the eval denominator");
        assert_eq!(m.source_version.as_deref(), Some("v19"));
        assert_eq!(m.measured_at.as_deref(), Some("2026-04-03T12:00:00.000Z"));
        assert_eq!(m.population.as_deref(), Some(PROMOTED_ACCURACY_POPULATION));
        let [lo, hi] = m.ci95.expect("a rate carries its Wilson interval");
        assert!(lo < 0.8 && hi > 0.8);
        // The whole point of n: the SAME accuracy over one row is a visibly
        // different claim.
        let tiny = promoted_accuracy_envelope(Some(0.8), Some(35), Some(19), Some(at(2026, 4, 3)))
            .unwrap();
        let one = promoted_accuracy_envelope(Some(1.0), Some(1), Some(19), None).unwrap();
        assert_eq!(one.n, 1);
        assert!(
            one.ci95.unwrap()[0] < tiny.ci95.unwrap()[0],
            "a 1-of-1 interval must be wider at the bottom than a 35-row one"
        );
    }

    /// The fabrication guard for D1: missing provenance stays MISSING. No
    /// `now()` stand-in for `trained_at`, no `0` stand-in for the denominator,
    /// no `v?` stand-in for the version.
    #[test]
    fn missing_provenance_is_never_substituted() {
        // No denominator → no envelope at all. (The bare `promoted_accuracy`
        // field still carries the number; it just does not get dressed up as
        // a measurement whose population we know.)
        assert!(
            promoted_accuracy_envelope(Some(0.8), None, Some(19), Some(at(2026, 4, 3))).is_none()
        );
        assert!(promoted_accuracy_envelope(Some(0.8), Some(0), Some(19), None).is_none());
        // Unpromoted model → nothing to envelope.
        assert!(promoted_accuracy_envelope(None, Some(35), Some(19), None).is_none());
        // A nonsense stored accuracy is refused rather than clamped.
        assert!(promoted_accuracy_envelope(Some(1.4), Some(35), Some(19), None).is_none());
        assert!(promoted_accuracy_envelope(Some(f64::NAN), Some(35), None, None).is_none());
        // A negative total (impossible, but the column is signed) is refused.
        assert!(promoted_accuracy_envelope(Some(0.8), Some(-1), None, None).is_none());
        // Row with no trained_at / no version: the envelope exists, those two
        // fields are ABSENT — and absent must serialize as absent, because a
        // null date read as "just now" is the defect being closed.
        let m = promoted_accuracy_envelope(Some(0.5), Some(20), None, None).unwrap();
        assert_eq!(m.measured_at, None);
        assert_eq!(m.source_version, None);
        let v = serde_json::to_value(&m).unwrap();
        let obj = v.as_object().unwrap();
        assert!(!obj.contains_key("measured_at"), "{v}");
        assert!(!obj.contains_key("source_version"), "{v}");
    }

    /// The summary serializes the envelope beside the bare float — the bare
    /// one is kept because `frontend/src/pages/ModelReview.tsx` renders it, so
    /// removing it would blank a live column.
    #[test]
    fn the_summary_keeps_the_bare_field_and_adds_the_envelope() {
        let s = ModelReviewSummary {
            model_id: Uuid::nil(),
            name: "inbox-classifier".into(),
            task_type: "classification".into(),
            lifecycle_state: "shadow".into(),
            promoted_version: Some(19),
            promoted_accuracy: Some(0.8),
            promoted_accuracy_measurement: promoted_accuracy_envelope(
                Some(0.8),
                Some(35),
                Some(19),
                Some(at(2026, 4, 3)),
            ),
            promoted_backend: Some("knn-pgvector".into()),
            pending_disagreements: 3,
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["promoted_accuracy"], 0.8);
        assert_eq!(v["promoted_accuracy_measurement"]["n"], 35);
        assert_eq!(v["promoted_accuracy_measurement"]["source_version"], "v19");
        assert_eq!(v["promoted_backend"], "knn-pgvector");
        // An unpromoted model omits the envelope entirely rather than
        // emitting a zero-valued one.
        let none = ModelReviewSummary {
            promoted_accuracy: None,
            promoted_accuracy_measurement: None,
            promoted_backend: None,
            ..s
        };
        let v = serde_json::to_value(&none).unwrap();
        assert!(!v
            .as_object()
            .unwrap()
            .contains_key("promoted_accuracy_measurement"));
        assert!(v["promoted_accuracy"].is_null());
    }

    /// A version row rendered on the model card says WHEN it was trained; a
    /// row constructed without the column says nothing rather than "now".
    #[test]
    fn version_rows_render_their_trained_at_and_omit_an_unknown_one() {
        let row = ModelVersionRow {
            id: Uuid::nil(),
            model_id: Uuid::nil(),
            version: 43,
            backend: "linear-logreg".into(),
            metrics_json: serde_json::json!({ "report": { "accuracy": 0.8 } }),
            status: "promoted".into(),
            trained_at: Some(rfc3339(at(2026, 7, 27))),
        };
        let v = serde_json::to_value(&row).unwrap();
        assert_eq!(v["trained_at"], "2026-07-27T12:00:00.000Z");
        let unknown = ModelVersionRow {
            trained_at: None,
            ..row
        };
        let v = serde_json::to_value(&unknown).unwrap();
        assert!(!v.as_object().unwrap().contains_key("trained_at"), "{v}");
    }

    #[test]
    fn the_promoted_metrics_note_says_what_a_null_provenance_key_means() {
        assert!(PROMOTED_METRICS_NOTE.contains("SERVING version"));
        assert!(PROMOTED_METRICS_NOTE.contains("not the same as recent"));
        assert!(PROMOTED_ACCURACY_POPULATION.contains("holdout"));
    }
}
