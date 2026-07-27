//! Learning-loop health snapshot — the `assistant_report` system
//! node's ML section. Read-only aggregates, all tenant-scoped by
//! `user_id`; returns JSON directly (the report node's output IS graph
//! data, so there is no typed consumer to serve).

use anyhow::Result;
use serde_json::{json, Value as JsonValue};
use sqlx::{PgPool, Row};
use uuid::Uuid;

/// Per-model loop health: lifecycle state, promoted version + its gold
/// accuracy (from the stored metrics), corrections banked in the
/// dataset, and current-epoch shadow agreement.
pub async fn loop_health(pool: &PgPool, user_id: Uuid) -> Result<JsonValue> {
    // LATEST version as well as the promoted one. For a model parked in
    // `shadow` the promoted version can be arbitrarily old — inbox-classifier
    // -personal sat on v19 while evaluation had reached v43 — so reporting
    // gold from the promoted row alone freezes "loop health" at the last
    // promotion and hides every improvement since. Observed 2026-07-27: the
    // digest still showed gold 0.15 (v19) after a dataset fix had moved the
    // live figure to 0.486, i.e. the panel whose job is to say whether the
    // loop is working said "not converging" about a loop that had just
    // started converging. LATERAL + LIMIT 1 keeps it one indexed lookup per
    // model rather than loading every version.
    let rows = sqlx::query(
        "SELECT m.name, m.lifecycle_state, m.shadow_epoch, m.dataset_id, \
                v.version AS promoted_version, v.backend AS promoted_backend, \
                v.metrics_json AS promoted_metrics, \
                lv.version AS latest_version, lv.metrics_json AS latest_metrics \
         FROM ml_models m \
         LEFT JOIN ml_model_versions v ON v.id = m.production_version_id \
         LEFT JOIN LATERAL ( \
             SELECT version, metrics_json FROM ml_model_versions \
             WHERE model_id = m.id ORDER BY version DESC LIMIT 1 \
         ) lv ON TRUE \
         WHERE m.user_id = $1 ORDER BY m.name LIMIT 20",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    let mut models = Vec::with_capacity(rows.len());
    for r in rows {
        let name: String = r.try_get("name")?;
        let lifecycle_state: String = r.try_get("lifecycle_state")?;
        let shadow_epoch: i32 = r.try_get::<Option<i32>, _>("shadow_epoch")?.unwrap_or(0);
        let dataset_id: Option<Uuid> = r.try_get("dataset_id")?;
        let promoted_version: Option<i32> = r.try_get("promoted_version")?;
        let promoted_backend: Option<String> = r.try_get("promoted_backend")?;
        let metrics: Option<JsonValue> = r.try_get("promoted_metrics")?;

        let latest_version: Option<i32> = r.try_get("latest_version")?;
        let latest_metrics: Option<JsonValue> = r.try_get("latest_metrics")?;

        let gold_of = |m: Option<&JsonValue>| -> Option<JsonValue> {
            m.and_then(|m| m.get("report"))
                .and_then(|rep| rep.get("gold"))
                .map(|g| json!({ "accuracy": g.get("accuracy"), "total": g.get("total") }))
        };
        // `gold` tracks the LATEST evaluation — it answers "are corrections
        // being learned RIGHT NOW", which is the question this panel exists
        // for. Falls back to the promoted report when a model has no newer
        // version. `gold_promoted` keeps the serving-version figure visible,
        // since that is the one describing what actually runs today.
        let gold = gold_of(latest_metrics.as_ref()).or_else(|| gold_of(metrics.as_ref()));
        let gold_promoted = gold_of(metrics.as_ref());
        let gold_is_stale = latest_version.is_some()
            && promoted_version.is_some()
            && latest_version != promoted_version;

        // Corrections banked in the dataset (train + gold).
        let corrections: i64 = match dataset_id {
            Some(ds) => {
                sqlx::query_scalar(
                    "SELECT COUNT(*)::bigint FROM ml_examples \
                 WHERE dataset_id = $1 AND source = 'correction'",
                )
                .bind(ds)
                .fetch_one(pool)
                .await?
            }
            None => 0,
        };

        // Current-epoch shadow agreement (band-summed) — the drift-guard
        // signal, aggregated the same way the lifecycle job reads it.
        let (agree, total): (i64, i64) = sqlx::query_as(
            "SELECT COALESCE(SUM(agree_count), 0)::bigint, \
                    COALESCE(SUM(total_count), 0)::bigint \
             FROM ml_shadow_stats s \
             JOIN ml_models m ON m.id = s.model_id \
             WHERE m.user_id = $1 AND m.name = $2 AND s.epoch = $3",
        )
        .bind(user_id)
        .bind(&name)
        .bind(shadow_epoch)
        .fetch_one(pool)
        .await?;

        models.push(json!({
            "name": name,
            "lifecycle_state": lifecycle_state,
            "promoted_version": promoted_version,
            "promoted_backend": promoted_backend,
            // From the LATEST eval — the live answer to "are corrections being
            // learned". See `gold_promoted` for the serving version's figure.
            "gold": gold,
            "latest_version": latest_version,
            "gold_promoted": gold_promoted,
            // true when the serving version predates the latest evaluation, so
            // a reader never mistakes a frozen promoted metric for current state.
            "gold_promoted_is_stale": gold_is_stale,
            "corrections_banked": corrections,
            "shadow": {
                "epoch": shadow_epoch,
                "agree": agree,
                "total": total,
                "agreement": if total > 0 {
                    Some(agree as f64 / total as f64)
                } else {
                    None
                },
            },
        }));
    }
    Ok(json!({ "models": models }))
}
