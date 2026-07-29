//! Learning-loop health snapshot — the `assistant_report` system
//! node's ML section. Read-only aggregates, all tenant-scoped by
//! `user_id`; returns JSON directly (the report node's output IS graph
//! data, so there is no typed consumer to serve).

use anyhow::Result;
use serde_json::{json, Value as JsonValue};
use sqlx::{PgPool, Row};
use uuid::Uuid;

/// What the `gold` / `gold_promoted` blocks are, and what their `measured_at`
/// is (and is not).
pub const GOLD_PROVENANCE_NOTE: &str =
    "gold/gold_promoted: accuracy is over `total` HELD-OUT CORRECTIONS from ONE version's eval — \
     source_version and measured_at say which version and when it was recorded, so a stale loop \
     is visible as an old timestamp rather than as a plausible-looking number. `gold` is the \
     LATEST version's slice (falling back to the promoted one when there is no newer version, in \
     which case both blocks carry the same source_version); `gold_promoted` is always the SERVING \
     version's. A null measured_at means the version predates provenance capture — unknown age, \
     not recent.";

/// Lift one version's gold slice into the panel shape, annotated with the
/// version and the time it was recorded.
///
/// `measured_at` is the row's `trained_at` — the instant the eval that
/// produced these numbers was written — passed in by the caller from the SAME
/// row the metrics came from. It is never a read-time clock: this function has
/// no access to one, which is the point.
fn gold_of(
    metrics: Option<&JsonValue>,
    version: Option<i32>,
    trained_at: Option<chrono::DateTime<chrono::Utc>>,
) -> Option<JsonValue> {
    let g = metrics?.get("report")?.get("gold")?;
    Some(json!({
        "accuracy": g.get("accuracy"),
        "total": g.get("total"),
        "source_version": version,
        "measured_at": trained_at
            .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
    }))
}

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
    // `trained_at` is projected for BOTH arms (2026-07-28, D5): the panel
    // already distinguished the promoted figure from the latest one by
    // VERSION, but neither carried a TIME, so "the loop is converging" and
    // "the loop stopped running three weeks ago" rendered identically. Both
    // columns come off rows the query already reads — no extra round trip.
    let rows = sqlx::query(
        "SELECT m.name, m.lifecycle_state, m.shadow_epoch, m.dataset_id, \
                v.version AS promoted_version, v.backend AS promoted_backend, \
                v.metrics_json AS promoted_metrics, v.trained_at AS promoted_trained_at, \
                lv.version AS latest_version, lv.metrics_json AS latest_metrics, \
                lv.trained_at AS latest_trained_at \
         FROM ml_models m \
         LEFT JOIN ml_model_versions v ON v.id = m.production_version_id \
         LEFT JOIN LATERAL ( \
             SELECT version, metrics_json, trained_at FROM ml_model_versions \
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
        let promoted_trained_at: Option<chrono::DateTime<chrono::Utc>> =
            r.try_get("promoted_trained_at")?;

        let latest_version: Option<i32> = r.try_get("latest_version")?;
        let latest_metrics: Option<JsonValue> = r.try_get("latest_metrics")?;
        let latest_trained_at: Option<chrono::DateTime<chrono::Utc>> =
            r.try_get("latest_trained_at")?;

        // `gold` tracks the LATEST evaluation — it answers "are corrections
        // being learned RIGHT NOW", which is the question this panel exists
        // for. Falls back to the promoted report when a model has no newer
        // version. `gold_promoted` keeps the serving-version figure visible,
        // since that is the one describing what actually runs today.
        //
        // Each arm is annotated with ITS OWN version + trained_at, so a
        // fallback can never present the promoted row's numbers under the
        // latest row's identity (the #588 mis-attribution, one level down).
        let gold_latest = gold_of(latest_metrics.as_ref(), latest_version, latest_trained_at);
        let gold_promoted = gold_of(metrics.as_ref(), promoted_version, promoted_trained_at);
        let gold = gold_latest.or_else(|| gold_promoted.clone());
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
            // When each arm's eval was RECORDED (RFC 3339, from the version
            // row's trained_at). `gold_promoted_is_stale` answers staleness in
            // VERSIONS; these answer it in TIME, which is the axis an operator
            // reads when asking "is this loop still running at all".
            "promoted_trained_at": promoted_trained_at
                .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
            "latest_trained_at": latest_trained_at
                .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
            // From the LATEST eval — the live answer to "are corrections being
            // learned". See `gold_promoted` for the serving version's figure.
            "gold": gold,
            "latest_version": latest_version,
            "gold_promoted": gold_promoted,
            // true when the serving version predates the latest evaluation, so
            // a reader never mistakes a frozen promoted metric for current state.
            // UNCHANGED by the provenance pass: it is a version comparison and
            // stays one.
            "gold_promoted_is_stale": gold_is_stale,
            "gold_provenance_note": GOLD_PROVENANCE_NOTE,
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(d: u32) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc.with_ymd_and_hms(2026, 7, d, 9, 30, 0).unwrap()
    }

    fn metrics(accuracy: f64, total: i64) -> JsonValue {
        json!({ "report": { "accuracy": 0.8, "total": 200,
                            "gold": { "accuracy": accuracy, "total": total } } })
    }

    /// D5: each arm's gold block is annotated with ITS OWN version and time.
    /// The panel already separated promoted from latest by version; without a
    /// timestamp, "the loop is converging" and "the loop last ran in April"
    /// rendered identically.
    #[test]
    fn each_arm_carries_its_own_version_and_measurement_time() {
        let latest = metrics(0.486, 35);
        let promoted = metrics(0.094, 44);
        let g_latest = gold_of(Some(&latest), Some(43), Some(at(27))).unwrap();
        let g_promoted = gold_of(Some(&promoted), Some(19), Some(at(3))).unwrap();
        assert_eq!(g_latest["accuracy"], 0.486);
        assert_eq!(g_latest["total"], 35);
        assert_eq!(g_latest["source_version"], 43);
        assert_eq!(g_latest["measured_at"], "2026-07-27T09:30:00.000Z");
        assert_eq!(g_promoted["source_version"], 19);
        assert_eq!(g_promoted["measured_at"], "2026-07-03T09:30:00.000Z");
        // The two must not share a stamp — that is the mis-attribution.
        assert_ne!(g_latest["measured_at"], g_promoted["measured_at"]);
    }

    /// The fallback path: with no newer version, `gold` IS the promoted
    /// block, and it must then advertise the promoted version/date rather than
    /// borrowing an identity it does not have.
    #[test]
    fn the_fallback_advertises_the_promoted_identity_not_a_latest_one() {
        let promoted = metrics(0.094, 44);
        let gold_latest = gold_of(None, None, None);
        let gold_promoted = gold_of(Some(&promoted), Some(19), Some(at(3)));
        let gold = gold_latest.or_else(|| gold_promoted.clone()).unwrap();
        assert_eq!(gold["source_version"], 19);
        assert_eq!(gold["measured_at"], "2026-07-03T09:30:00.000Z");
        assert_eq!(gold, gold_promoted.unwrap());
    }

    /// A version written before provenance capture leaves `measured_at` null —
    /// UNKNOWN age, not "now". Nothing in this path may read a clock.
    #[test]
    fn an_unstamped_version_reports_a_null_measurement_time() {
        let g = gold_of(Some(&metrics(0.5, 40)), Some(7), None).unwrap();
        assert!(g["measured_at"].is_null(), "{g}");
        assert_eq!(g["source_version"], 7);
        // Deterministic: no clock inside.
        assert_eq!(gold_of(Some(&metrics(0.5, 40)), Some(7), None).unwrap(), g);
    }

    /// No gold slice / no metrics at all → no block, unchanged from before.
    #[test]
    fn absent_gold_stays_absent() {
        assert!(gold_of(None, Some(1), Some(at(1))).is_none());
        assert!(gold_of(Some(&json!({})), Some(1), Some(at(1))).is_none());
        assert!(gold_of(
            Some(&json!({ "report": { "accuracy": 0.8 } })),
            Some(1),
            Some(at(1))
        )
        .is_none());
    }

    #[test]
    fn the_gold_note_states_which_version_each_block_describes() {
        assert!(GOLD_PROVENANCE_NOTE.contains("HELD-OUT CORRECTIONS"));
        assert!(GOLD_PROVENANCE_NOTE.contains("source_version"));
        assert!(GOLD_PROVENANCE_NOTE.contains("unknown age, not recent"));
    }
}
