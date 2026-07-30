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
///
/// The `gold_promoted` clause used to read "always the SERVING version's" /
/// "the one describing what actually runs today". For a model in `shadow` or
/// `llm_only` that is FALSE — `serve::state_serves_production` is false there,
/// so production consults the model not at all and every prediction falls back
/// to the LLM. The note now states what the field IS (the PROMOTED version's
/// slice) and defers the serving claim to the per-model `serves_production`
/// flag, which is computed FROM the gate rather than asserted beside it.
pub const GOLD_PROVENANCE_NOTE: &str =
    "gold/gold_promoted: accuracy is over `total` HELD-OUT CORRECTIONS from ONE version's eval — \
     source_version and measured_at say which version and when it was recorded, so a stale loop \
     is visible as an old timestamp rather than as a plausible-looking number. `gold` is the \
     LATEST version's slice (falling back to the promoted one when there is no newer version, in \
     which case both blocks carry the same source_version); `gold_promoted` is the PROMOTED \
     version's slice. PROMOTED IS NOT THE SAME AS SERVING: production only consults the model in \
     lifecycle_state hybrid/fast_primary, so read `serves_production` (and \
     `gold_promoted_serving_note`, both derived from the serving gate) before treating \
     gold_promoted as a measurement of what runs today. A null measured_at means the version \
     predates provenance capture — unknown age, not recent.";

/// What `gold_promoted` describes for THIS model, derived from the serving
/// gate ([`crate::serve::state_serves_production`]) rather than asserted.
///
/// The two arms make different claims because the platform knows two different
/// facts; neither wording may be reused for the other state.
#[must_use]
pub fn gold_promoted_serving_note(lifecycle_state: &str) -> &'static str {
    if crate::serve::state_serves_production(lifecycle_state) {
        "the promoted version IS consulted by production: this lifecycle_state passes the serving \
         gate (hybrid/fast_primary). Individual predictions below the model's \
         confidence_threshold still abstain to the LLM, so this is what the fast path scores when \
         it answers — not the share of traffic it answers."
    } else {
        "the promoted version SERVES NOTHING: this lifecycle_state does not pass the serving gate \
         (only hybrid/fast_primary do), so every production prediction falls back to the LLM and \
         these numbers describe a candidate, not what runs today. Advancing the lifecycle is what \
         changes that — promoting a version alone does not."
    }
}

/// What the `policy_verdict` block is — and, when it is absent, what that
/// absence means.
pub const POLICY_VERDICT_NOTE: &str =
    "policy_verdict is the newest STORED lifecycle-policy judgment on any version of this model \
     (ml_model_versions.metrics_json.policy_decision), verbatim — source_version and measured_at \
     say which version it judged and when. It is NOT re-computed at read time and NOT necessarily \
     about latest_version: versions_since_verdict counts the evaluations recorded after it that \
     carry no verdict of their own. A null policy_verdict means NO version of this model has ever \
     had its policy evaluated — 'not evaluated', never 'satisfied' and never 'unsatisfied'.";

/// What `shadow.agreement` measures, and the one case where it mixes versions.
pub const SHADOW_AGREEMENT_NOTE: &str =
    "shadow.agreement is how often the fast path matched the LLM teacher over `total` \
     observations in the CURRENT epoch. It measures shadow.measures_version — the PROMOTED \
     version, which is the one serve_predict_batch resolves — not latest_version. The epoch \
     rotates on every lifecycle transition, so a demote/advance never mixes eras; a PROMOTE alone \
     does NOT rotate it, so observations recorded before and after a mid-epoch promotion are \
     summed together and measures_version then names only the current end of that window. A null \
     agreement means zero observations in this epoch, not zero agreement.";

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

/// Lift the newest STORED policy verdict into the panel shape, annotated with
/// the version it judged and how many evaluations have been recorded since.
///
/// Pure, and deliberately conservative about what it will claim:
///
/// * No stored verdict → `None`. The caller renders `policy_verdict: null`,
///   which [`POLICY_VERDICT_NOTE`] defines as "never evaluated". A default of
///   `satisfied: false` here would be indistinguishable from a real failing
///   gate — 30 of one live model's 44 versions carry no verdict, so this is
///   the common case, not the edge one.
/// * `unmet` is copied VERBATIM out of the stored decision, never re-worded.
///   Those strings are `evaluate_policy`'s own (`"min_corrections_per_class:
///   'follow_up' has 1 < 3"`) — the actionable sentence the platform already
///   computed. A non-array `unmet` (or a missing one) becomes `null`, not `[]`:
///   an empty list reads as "nothing is blocking".
/// * `satisfied` is only reported when the stored value is a real bool.
/// * `versions_since_verdict` is `latest_version - verdict_version`, i.e. how
///   many evaluations were recorded AFTER the last judged one. Non-zero means
///   the verdict describes older evidence than the numbers beside it.
fn policy_verdict_of(
    decision: Option<&JsonValue>,
    verdict_version: Option<i32>,
    verdict_trained_at: Option<chrono::DateTime<chrono::Utc>>,
    latest_version: Option<i32>,
) -> Option<JsonValue> {
    let d = decision?;
    if !d.is_object() {
        return None;
    }
    let unmet = d
        .get("unmet")
        .and_then(JsonValue::as_array)
        .map(|a| JsonValue::Array(a.clone()));
    Some(json!({
        "source_version": verdict_version,
        "measured_at": verdict_trained_at
            .map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
        "satisfied": d.get("satisfied").and_then(JsonValue::as_bool),
        "unmet": unmet,
        "versions_since_verdict": latest_version
            .zip(verdict_version)
            .map(|(latest, judged)| (latest - judged).max(0)),
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
    //
    // The third arm (`pv`, 2026-07-30) is the newest version carrying a STORED
    // policy verdict. It is a separate lookup because it is usually NEITHER of
    // the other two: measured on the live database, `inbox-classifier-personal`
    // had 44 versions, 30 of them with no verdict at all, and the newest stored
    // verdict was v31's. Reading the verdict off `lv` would have rendered the
    // gate as "not evaluated" for a model the platform had in fact judged, and
    // whose blocking reasons it could name. Same LATERAL + LIMIT 1 shape — one
    // indexed lookup per model, no N+1 added to the digest path.
    let rows = sqlx::query(
        "SELECT m.name, m.lifecycle_state, m.shadow_epoch, m.dataset_id, \
                v.version AS promoted_version, v.backend AS promoted_backend, \
                v.metrics_json AS promoted_metrics, v.trained_at AS promoted_trained_at, \
                lv.version AS latest_version, lv.metrics_json AS latest_metrics, \
                lv.trained_at AS latest_trained_at, \
                pv.version AS verdict_version, pv.trained_at AS verdict_trained_at, \
                pv.metrics_json -> 'policy_decision' AS policy_decision \
         FROM ml_models m \
         LEFT JOIN ml_model_versions v ON v.id = m.production_version_id \
         LEFT JOIN LATERAL ( \
             SELECT version, metrics_json, trained_at FROM ml_model_versions \
             WHERE model_id = m.id ORDER BY version DESC LIMIT 1 \
         ) lv ON TRUE \
         LEFT JOIN LATERAL ( \
             SELECT version, metrics_json, trained_at FROM ml_model_versions \
             WHERE model_id = m.id AND jsonb_exists(metrics_json, 'policy_decision') \
             ORDER BY version DESC LIMIT 1 \
         ) pv ON TRUE \
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

        let verdict_version: Option<i32> = r.try_get("verdict_version")?;
        let verdict_trained_at: Option<chrono::DateTime<chrono::Utc>> =
            r.try_get("verdict_trained_at")?;
        let policy_decision: Option<JsonValue> = r.try_get("policy_decision")?;
        let policy_verdict = policy_verdict_of(
            policy_decision.as_ref(),
            verdict_version,
            verdict_trained_at,
            latest_version,
        );

        // `gold` tracks the LATEST evaluation — it answers "are corrections
        // being learned RIGHT NOW", which is the question this panel exists
        // for. Falls back to the promoted report when a model has no newer
        // version. `gold_promoted` keeps the serving-version figure visible,
        // since that is the one describing what actually runs today.
        //
        // Each arm is annotated with ITS OWN version + trained_at, so a
        // fallback can never present the promoted row's numbers under the
        // latest row's identity (the #588 mis-attribution, one level down).
        let serves_production = crate::serve::state_serves_production(&lifecycle_state);
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
            // Whether production consults this model AT ALL, computed by the
            // serving gate itself (`serve::state_serves_production`) rather
            // than asserted in prose beside it. `gold_promoted` is the
            // promoted version's eval either way; this is what says whether
            // that version is a description of production or of a candidate.
            "serves_production": serves_production,
            "gold_promoted_serving_note": gold_promoted_serving_note(&lifecycle_state),
            // The newest STORED policy judgment, verbatim, with the version it
            // judged. null = never evaluated (NOT "unsatisfied").
            "policy_verdict": policy_verdict,
            "policy_verdict_note": POLICY_VERDICT_NOTE,
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
                // WHICH version these observations are about. The shadow hook
                // predicts through `serve_predict_batch`, which resolves the
                // PROMOTED version — so beside a `gold` block reporting the
                // LATEST version's numbers, an unannotated agreement reads as
                // the latest version's. It is not.
                "measures_version": promoted_version,
                "note": SHADOW_AGREEMENT_NOTE,
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

    /// D3a. The note must not claim the promoted version is the SERVING one —
    /// for a model in `shadow` (where `inbox-classifier-personal` has sat
    /// since 2026-07-14) production consults it not at all.
    #[test]
    fn the_gold_note_never_asserts_serving() {
        let lowered = GOLD_PROVENANCE_NOTE.to_ascii_lowercase();
        assert!(
            !lowered.contains("always the serving"),
            "the promoted version serves nothing in shadow/llm_only"
        );
        assert!(
            !lowered.contains("what actually runs today"),
            "that claim belongs to serves_production, which is computed from the gate"
        );
        // It must instead point at the field that IS derived from the gate.
        assert!(GOLD_PROVENANCE_NOTE.contains("serves_production"));
        assert!(GOLD_PROVENANCE_NOTE.contains("PROMOTED IS NOT THE SAME AS SERVING"));
    }

    /// D3a. The per-model wording is a FUNCTION of the serving gate: a
    /// non-serving state must say so in the direction that matters (the model
    /// serves nothing), and a serving state must not overclaim (gated votes
    /// still abstain below the confidence threshold).
    #[test]
    fn the_serving_note_follows_the_gate_in_both_directions() {
        for parked in ["shadow", "llm_only"] {
            let n = gold_promoted_serving_note(parked);
            assert!(n.contains("SERVES NOTHING"), "{parked}: {n}");
            assert!(n.contains("falls back to the LLM"), "{parked}: {n}");
        }
        for live in ["hybrid", "fast_primary"] {
            let n = gold_promoted_serving_note(live);
            assert!(n.contains("IS consulted by production"), "{live}: {n}");
            // …but not "serves every prediction".
            assert!(n.contains("abstain to the LLM"), "{live}: {n}");
        }
        // Same predicate the serving path uses — no second state list here.
        assert_ne!(
            gold_promoted_serving_note("shadow"),
            gold_promoted_serving_note("hybrid")
        );
    }

    /// D3b. A stored verdict is surfaced with its OWN version, its own date,
    /// and its unmet reasons byte-for-byte.
    #[test]
    fn a_stored_verdict_surfaces_its_reasons_verbatim() {
        let unmet = "min_corrections_per_class: 'follow_up' has 1 < 3";
        let d = json!({ "satisfied": false, "unmet": [unmet, "accuracy_at_coverage: no threshold reaches 0.95"] });
        let v = policy_verdict_of(Some(&d), Some(31), Some(at(25)), Some(44)).unwrap();
        assert_eq!(v["source_version"], 31);
        assert_eq!(v["measured_at"], "2026-07-25T09:30:00.000Z");
        assert_eq!(v["satisfied"], false);
        assert_eq!(v["unmet"][0], unmet, "reasons are copied, never re-worded");
        assert_eq!(
            v["versions_since_verdict"], 13,
            "13 evaluations recorded after the last judged one"
        );
    }

    /// The old-row case, which is the COMMON one: no version of the model
    /// carries a verdict. That must render as absent — never as a verdict.
    #[test]
    fn an_unjudged_model_reports_no_verdict_rather_than_an_unsatisfied_one() {
        assert!(policy_verdict_of(None, None, None, Some(44)).is_none());
        // A non-object stored under the key is equally not a verdict.
        assert!(policy_verdict_of(Some(&json!("satisfied")), Some(3), None, Some(3)).is_none());
        assert!(policy_verdict_of(Some(&JsonValue::Null), Some(3), None, Some(3)).is_none());
    }

    /// A malformed stored decision must degrade to "unknown", not to a
    /// confident answer: `satisfied` null (not false), `unmet` null (not []).
    #[test]
    fn a_malformed_verdict_degrades_to_unknown_not_to_a_verdict() {
        let v = policy_verdict_of(Some(&json!({})), Some(9), None, Some(9)).unwrap();
        assert!(v["satisfied"].is_null(), "{v}");
        assert!(
            v["unmet"].is_null(),
            "an empty array would read as 'nothing is blocking': {v}"
        );
        assert_eq!(v["versions_since_verdict"], 0);
        assert!(v["measured_at"].is_null());
        // A non-array unmet is also unknown, not empty.
        let bad = policy_verdict_of(
            Some(&json!({ "satisfied": true, "unmet": "none" })),
            Some(9),
            None,
            Some(9),
        )
        .unwrap();
        assert!(bad["unmet"].is_null(), "{bad}");
        assert_eq!(bad["satisfied"], true);
    }

    /// The verdict note must define ABSENCE, because absence is the state most
    /// of the fleet is in.
    #[test]
    fn the_verdict_note_defines_what_absence_means() {
        assert!(POLICY_VERDICT_NOTE.contains("never 'satisfied' and never 'unsatisfied'"));
        assert!(POLICY_VERDICT_NOTE.contains("versions_since_verdict"));
        assert!(POLICY_VERDICT_NOTE.contains("verbatim"));
    }

    /// D3c. The shadow note must name the version the agreement measures and
    /// admit the one case where the epoch does not isolate it.
    #[test]
    fn the_shadow_note_names_its_version_and_its_one_mixing_case() {
        assert!(SHADOW_AGREEMENT_NOTE.contains("shadow.measures_version"));
        assert!(SHADOW_AGREEMENT_NOTE.contains("PROMOTED version"));
        assert!(SHADOW_AGREEMENT_NOTE.contains("not latest_version"));
        assert!(SHADOW_AGREEMENT_NOTE.contains("PROMOTE alone does NOT rotate it"));
        assert!(SHADOW_AGREEMENT_NOTE.contains("zero observations in this epoch"));
    }
}
