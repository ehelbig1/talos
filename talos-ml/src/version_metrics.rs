//! The ONE assembly point for a model version's `metrics_json`.
//!
//! Before this module the payload was hand-built twice — once in
//! `talos-mcp-handlers/src/ml.rs` (`ml_eval_model`, the manual path) and once
//! in [`crate::lifecycle_job`] (the scheduled policy evaluator) — with the two
//! copies already drifted (`evaluator` existed on one side only). A stored
//! eval could therefore not answer the three questions a reader needs before
//! believing any number in it:
//!
//! * **when** was it measured (the row's `trained_at` is the INSERT time, and
//!   nothing inside the payload said so),
//! * **over how much data** (the report's `total` is the holdout, not the
//!   dataset it was drawn from),
//! * **embedded how** (a re-embedding under a different model silently
//!   changes every geometry-derived number).
//!
//! # The carried-provenance rule
//!
//! [`build_version_metrics`] has NO clock. `measured_at` is copied out of
//! [`EvalReport::measured_at`], which the eval runner stamped when scoring
//! finished. If the report carries no stamp the key is OMITTED — a payload
//! that says nothing is honest, a payload stamped `now()` at assembly (let
//! alone at render) is a fabricated freshness claim.

use crate::eval::EvalReport;
use serde_json::{json, Value};

/// What the reader needs in order not to over-read a stored eval.
pub const METRICS_PROVENANCE_NOTE: &str =
    "PROVENANCE: measured_at is when the eval finished scoring (carried from the run, not the \
     time you are reading this); dataset_rows is the number of LABELED rows in the dataset at \
     that moment — the population the holdout was drawn from, NOT the eval denominator, which is \
     report.total; embedding_model is the embedding model that was active when this eval ran — \
     the TRAIN side loaded ONLY rows embedded under it, so rows carrying another model's vector \
     contributed no neighbours and no fit rows, while a holdout row with no usable vector \
     abstains and counts as an error in report.total. A key that is absent was NOT MEASURED — \
     versions recorded before 2026-07-28 carry none of these three, and absence must never be \
     rendered as 0 or as now().";

/// Everything one eval run contributes to its version row.
///
/// Deliberately a struct rather than a nine-argument function: the two call
/// sites differ only in `evaluator` / `policy_decision`, and a positional
/// signature is how the two hand-built copies drifted in the first place.
pub struct VersionMetricsInput<'a> {
    /// The winning backend (`knn-pgvector`, `linear-logreg`, …).
    pub backend: &'a str,
    /// The holdout fraction the split used.
    pub holdout_fraction: f64,
    /// The winner's report. Its `measured_at` is the ONLY source of the
    /// payload's `measured_at`.
    pub report: &'a EvalReport,
    /// Backend-specific hyperparameters, merged into the top level (`{voting,
    /// k}` for knn, `{epochs, l2, balanced}` for linear).
    pub params: &'a Value,
    /// Every candidate's headline scores, best-first.
    pub backend_comparison: Vec<Value>,
    /// Who ran it: `"manual"` (`ml_eval_model`) or `"scheduled"` (the policy
    /// evaluator). Pre-2026-07-28 rows from the manual path have no
    /// `evaluator` key at all.
    pub evaluator: &'a str,
    /// The policy gate's verdict, when the caller evaluated one.
    pub policy_decision: Option<Value>,
    /// Labeled rows in the dataset AT EVAL TIME (the population the holdout
    /// was drawn from). `None` when the caller could not count them — the key
    /// is then omitted rather than zeroed.
    pub dataset_rows: Option<i64>,
    /// The embedding model that was active when this eval ran — i.e.
    /// `talos_memory::embedding::active_embedding_model()`, which is the value
    /// the TRAIN-side loaders (`load_train_embeddings_with_source`,
    /// `knn_search`) filtered on. It is process-cached (`OnceLock`), so it
    /// cannot change under a running eval. Holdout rows are NOT filtered by it:
    /// one carrying another model's vector is still scored, and one with no
    /// vector abstains — either way it is inside `report.total`.
    /// `None` when embeddings are disabled.
    pub embedding_model: Option<String>,
}

/// Assemble a version's `metrics_json`, provenance included.
///
/// Pure: same input, same output, no clock and no I/O — so the fabrication
/// guard (`build_never_invents_a_timestamp`) can pin that an unstamped report
/// yields a payload with no `measured_at`.
#[must_use]
pub fn build_version_metrics(input: VersionMetricsInput<'_>) -> Value {
    let VersionMetricsInput {
        backend,
        holdout_fraction,
        report,
        params,
        backend_comparison,
        evaluator,
        policy_decision,
        dataset_rows,
        embedding_model,
    } = input;

    let mut metrics = json!({
        "backend": backend,
        "holdout_fraction": holdout_fraction,
        "report": report,
        "selected_backend": backend,
        "backend_comparison": backend_comparison,
        "evaluator": evaluator,
        "provenance_note": METRICS_PROVENANCE_NOTE,
    });
    let Some(obj) = metrics.as_object_mut() else {
        // `json!` above is an object by construction; the branch exists so a
        // future edit cannot silently drop the provenance.
        return metrics;
    };
    if let Some(decision) = policy_decision {
        obj.insert("policy_decision".into(), decision);
    }
    // CARRIED, never derived. No `else` branch: an unstamped report leaves the
    // key absent, which every reader renders as "not measured".
    if let Some(at) = report.measured_at.as_ref() {
        obj.insert("measured_at".into(), json!(at));
    }
    if let Some(rows) = dataset_rows {
        obj.insert("dataset_rows".into(), json!(rows));
    }
    if let Some(model) = embedding_model {
        obj.insert("embedding_model".into(), json!(model));
    }
    // Backend hyperparameters last, matching the pre-extraction order.
    if let Some(p) = params.as_object() {
        for (k, v) in p {
            obj.insert(k.clone(), v.clone());
        }
    }
    metrics
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eval::evaluate_predictions;

    fn report_with(measured_at: Option<&str>) -> EvalReport {
        let mut r = evaluate_predictions(
            &["a".to_string(), "b".to_string()],
            &[Some("a".to_string()), Some("b".to_string())],
        )
        .unwrap();
        r.measured_at = measured_at.map(str::to_string);
        r
    }

    fn build(report: &EvalReport, rows: Option<i64>, model: Option<&str>) -> Value {
        build_version_metrics(VersionMetricsInput {
            backend: "knn-pgvector",
            holdout_fraction: 0.2,
            report,
            params: &json!({ "k": 7, "voting": "balanced-sqrt" }),
            backend_comparison: vec![json!({ "backend": "knn-pgvector", "macro_recall": 0.9 })],
            evaluator: "manual",
            policy_decision: None,
            dataset_rows: rows,
            embedding_model: model.map(str::to_string),
        })
    }

    /// D3: the payload answers "over which data, embedded how, when?".
    #[test]
    fn stamps_the_three_provenance_keys_from_the_measurement_event() {
        let r = report_with(Some("2026-07-28T10:00:00.000Z"));
        let v = build(&r, Some(721), Some("nomic-embed-text"));
        assert_eq!(v["measured_at"], "2026-07-28T10:00:00.000Z");
        assert_eq!(v["dataset_rows"], 721);
        assert_eq!(v["embedding_model"], "nomic-embed-text");
        // The stamp is the REPORT's, byte-for-byte — not a second clock read.
        assert_eq!(v["measured_at"], json!(r.measured_at.unwrap()));
        // …and the report itself still carries it, so a consumer reading only
        // `report` is not left provenance-less.
        assert_eq!(v["report"]["measured_at"], "2026-07-28T10:00:00.000Z");
        assert!(v["provenance_note"]
            .as_str()
            .unwrap()
            .contains("NOT the eval denominator"));
    }

    /// The fabrication guard. Stamping `measured_at` with a clock read HERE
    /// (or at any read/render site) would make an unstamped legacy report
    /// claim a freshness it never had.
    #[test]
    fn build_never_invents_a_timestamp_or_a_count() {
        let r = report_with(None);
        let v = build(&r, None, None);
        let obj = v.as_object().unwrap();
        assert!(
            !obj.contains_key("measured_at"),
            "an unstamped report must yield NO measured_at, not now(): {v}"
        );
        assert!(!obj.contains_key("dataset_rows"));
        assert!(!obj.contains_key("embedding_model"));
        // Determinism is the mechanical proof there is no clock inside.
        assert_eq!(build(&r, None, None), v);
    }

    /// D3 round-trip: the stamps survive the JSONB write→read, and the
    /// report nested inside keeps its own. A payload stored BEFORE the stamps
    /// existed comes back with the keys simply missing — which every reader
    /// renders as "not measured" (the `teacher_ceilings` convention).
    #[test]
    fn stored_payloads_round_trip_and_legacy_ones_stay_bare() {
        let r = report_with(Some("2026-07-28T10:00:00.000Z"));
        let stored: Value = serde_json::from_str(
            &serde_json::to_string(&build(&r, Some(721), Some("nomic"))).unwrap(),
        )
        .unwrap();
        assert_eq!(stored["measured_at"], "2026-07-28T10:00:00.000Z");
        assert_eq!(stored["dataset_rows"], 721);
        assert_eq!(stored["embedding_model"], "nomic");
        // The nested report parses back into the typed shape, stamp intact —
        // so a consumer reading `metrics_json.report` alone is not stranded.
        let back: EvalReport = serde_json::from_value(stored["report"].clone()).unwrap();
        assert_eq!(
            back.measured_at.as_deref(),
            Some("2026-07-28T10:00:00.000Z")
        );

        // A real pre-2026-07-28 payload shape.
        let legacy: Value = serde_json::json!({
            "backend": "knn-pgvector",
            "holdout_fraction": 0.2,
            "selected_backend": "knn-pgvector",
            "report": { "accuracy": 0.8, "total": 35, "abstained": 0, "per_class": {} },
            "k": 7,
        });
        for absent in [
            "measured_at",
            "dataset_rows",
            "embedding_model",
            "evaluator",
        ] {
            assert!(
                legacy.get(absent).is_none(),
                "{absent} must be ABSENT on an old row — a reader that defaults \
                 it is inventing a measurement that never happened"
            );
        }
        let old: EvalReport = serde_json::from_value(legacy["report"].clone()).unwrap();
        assert_eq!(old.measured_at, None);
    }

    /// The structural half of the fabrication guard: NO provenance READER may
    /// hold a clock.
    ///
    /// The value-level tests above prove today's code carries its timestamps;
    /// this one fails the moment a future edit reaches for the current time
    /// inside a read/assembly path, which is how a stale number acquires a
    /// fresh-looking date. The eval RUNNER (`eval.rs::measurement_instant`) is
    /// the only sanctioned clock read on this route, and it is deliberately
    /// not scanned here.
    #[test]
    fn no_provenance_reader_reads_a_clock() {
        // Needles assembled with `concat!` so this test's own text is not a
        // match for them.
        let needle = concat!("Utc::", "now");
        for (name, src) in [
            ("version_metrics.rs", include_str!("version_metrics.rs")),
            ("registry.rs", include_str!("registry.rs")),
            ("loop_health.rs", include_str!("loop_health.rs")),
        ] {
            assert!(
                !src.contains(needle),
                "{name} reads a clock: a measured_at derived at read/assembly \
                 time claims a freshness the data does not have (the \
                 misleading-report-field class). Carry the stamp from the \
                 measurement event instead."
            );
        }
    }

    /// Byte-compat with the two hand-built copies this replaced: every key the
    /// old payloads carried is still there, spelled the same.
    #[test]
    fn preserves_the_pre_extraction_key_shape() {
        let r = report_with(Some("2026-07-28T10:00:00.000Z"));
        let v = build_version_metrics(VersionMetricsInput {
            backend: "linear-logreg",
            holdout_fraction: 0.25,
            report: &r,
            params: &json!({ "epochs": 40, "l2": 0.01 }),
            backend_comparison: vec![json!({ "backend": "linear-logreg" })],
            evaluator: "scheduled",
            policy_decision: Some(json!({ "satisfied": true, "unmet": [] })),
            dataset_rows: Some(10),
            embedding_model: None,
        });
        assert_eq!(v["backend"], "linear-logreg");
        assert_eq!(v["selected_backend"], "linear-logreg");
        assert_eq!(v["holdout_fraction"], 0.25);
        assert_eq!(v["evaluator"], "scheduled");
        assert_eq!(v["policy_decision"]["satisfied"], true);
        assert!(v["backend_comparison"].is_array());
        assert!(v["report"]["accuracy"].is_number());
        // Hyperparameters are merged at the TOP level, as before.
        assert_eq!(v["epochs"], 40);
        assert_eq!(v["l2"], 0.01);
        // A manual run without a policy gate carries no policy_decision key.
        let manual = build(&r, None, None);
        assert!(!manual.as_object().unwrap().contains_key("policy_decision"));
    }
}
