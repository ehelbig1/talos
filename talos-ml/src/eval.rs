//! Eval harness — the backend SELECTOR.
//!
//! Given (truth, prediction) pairs from a holdout run, computes
//! per-class precision/recall/F1 + accuracy. The metrics kernel is pure;
//! the async orchestration (split assignment, running backends over the
//! holdout) lives in the service layer so this stays unit-testable.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Population disclosure for the accuracy@coverage curve.
///
/// Every renderer of `report.coverage_curve` states this ONCE (D2,
/// 2026-07-28): `accuracy` at a band is over `n` rows, not over the holdout,
/// and `n` shrinks as the threshold rises — 1.0 at n=6 is not 1.0 at n=600.
/// Kept as a constant so the two surfaces that render the curve (the
/// `ml_eval_model` response and the model card) cannot drift apart.
pub const COVERAGE_CURVE_POPULATION_NOTE: &str =
    "coverage_curve: each point is over its OWN population — `n` is the number of holdout rows \
     predicted at-or-above that confidence threshold, and `accuracy` is the fraction of those n \
     that were right (NOT of the whole holdout). `coverage` is n / holdout total. n falls as the \
     threshold rises, so a high-threshold accuracy is the least-supported number on the curve; \
     read n before the accuracy. `accuracy` is null when n = 0 (nothing covered), never 0.0. \
     Points written before 2026-07-28 carry no `n` — absent means not recorded, not zero.";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClassMetrics {
    pub precision: f64,
    pub recall: f64,
    pub f1: f64,
    pub support: usize,
}

/// One point on the accuracy@coverage curve: among predictions with
/// confidence >= threshold, what fraction of ALL examples is covered
/// and how accurate is the covered fast path. Production falls back to
/// the LLM below the threshold, so THIS — not overall accuracy — is
/// the deploy-decision number.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoveragePoint {
    pub threshold: f64,
    pub coverage: f64,
    /// None when NOTHING was covered at this threshold — a no-data band
    /// must be distinguishable from "everything covered was wrong"
    /// (a policy evaluator reading 0.0 would treat absence of data as
    /// catastrophic quality).
    pub accuracy: Option<f64>,
    /// The DENOMINATOR of `accuracy`: holdout rows predicted at-or-above
    /// `threshold`. Added 2026-07-28 (measurement envelope, D2) — its own
    /// doc called this "the deploy-decision number" while shipping without a
    /// sample size, so `accuracy = 1.0` over 6 rows rendered identically to
    /// 1.0 over 600.
    ///
    /// `Option` ONLY so payloads stored before the field existed deserialize
    /// as absent rather than as a fabricated `0`. Every producer in this
    /// crate fills it — [`coverage_curve`] is the sole one, and
    /// `coverage_points_carry_their_denominator` pins that.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalReport {
    pub accuracy: f64,
    pub total: usize,
    /// Predictions where the backend abstained (e.g. empty knn
    /// neighborhood). Counted as errors in `accuracy` — an abstention in
    /// production falls back to the LLM, but the eval measures the fast
    /// path alone.
    pub abstained: usize,
    /// BTreeMap for deterministic JSON ordering in metrics_json.
    pub per_class: BTreeMap<String, ClassMetrics>,
    /// accuracy@coverage at the standard thresholds (empty when the
    /// caller supplied no confidences).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub coverage_curve: Vec<CoveragePoint>,
    /// GOLD subset (source='correction' — human truth) scored
    /// separately: teacher labels grade agreement, gold grades
    /// correctness, and a distilled model can legitimately beat its
    /// teacher here. None until corrections exist in the holdout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gold: Option<Box<EvalReport>>,
    /// When this report was PRODUCED (RFC 3339), stamped once by the eval
    /// runner at completion — see [`stamp_measured_at`].
    ///
    /// Carried, never re-derived: a reader that fills this in at render time
    /// would be inventing a freshness the numbers do not have. Absent on the
    /// pure kernel ([`evaluate_predictions`], which has no clock) and on every
    /// report stored before 2026-07-28 — absent means "not recorded", and a
    /// reader must render it as such rather than substituting `now()`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub measured_at: Option<String>,
}

impl EvalReport {
    /// Stamp `measured_at` on this report AND its gold sub-report with ONE
    /// instant — the moment the eval finished scoring.
    ///
    /// The parent and the gold slice are the same measurement event (gold is a
    /// re-score of a subset of the same holdout run), so they must not carry
    /// two different clocks.
    pub fn stamp_measured_at(&mut self, at: impl Into<String>) {
        let at = at.into();
        if let Some(g) = self.gold.as_mut() {
            g.measured_at = Some(at.clone());
        }
        self.measured_at = Some(at);
    }
}

/// Compute the report from parallel truth/prediction slices.
/// `predictions[i] = None` records an abstention. Errors (rather than
/// panicking a tokio task) on desynced slices — the zip below would
/// otherwise silently truncate and compute wrong accuracy.
pub fn evaluate_predictions(
    truths: &[String],
    predictions: &[Option<String>],
) -> anyhow::Result<EvalReport> {
    anyhow::ensure!(
        truths.len() == predictions.len(),
        "truth/prediction slices must be parallel ({} vs {})",
        truths.len(),
        predictions.len()
    );
    let total = truths.len();
    let mut correct = 0usize;
    let mut abstained = 0usize;
    // tp/fp/fn per class.
    let mut tp: BTreeMap<&str, usize> = BTreeMap::new();
    let mut fp: BTreeMap<&str, usize> = BTreeMap::new();
    let mut fn_: BTreeMap<&str, usize> = BTreeMap::new();
    let mut classes: BTreeSet<&str> = BTreeSet::new();

    for (truth, pred) in truths.iter().zip(predictions.iter()) {
        classes.insert(truth.as_str());
        match pred {
            Some(p) if p == truth => {
                correct += 1;
                *tp.entry(truth.as_str()).or_insert(0) += 1;
            }
            Some(p) => {
                classes.insert(p.as_str());
                *fp.entry(p.as_str()).or_insert(0) += 1;
                *fn_.entry(truth.as_str()).or_insert(0) += 1;
            }
            None => {
                abstained += 1;
                *fn_.entry(truth.as_str()).or_insert(0) += 1;
            }
        }
    }

    let per_class = classes
        .into_iter()
        .map(|c| {
            let tp = *tp.get(c).unwrap_or(&0) as f64;
            let fp = *fp.get(c).unwrap_or(&0) as f64;
            let fn_ = *fn_.get(c).unwrap_or(&0) as f64;
            let precision = if tp + fp > 0.0 { tp / (tp + fp) } else { 0.0 };
            let recall = if tp + fn_ > 0.0 { tp / (tp + fn_) } else { 0.0 };
            let f1 = if precision + recall > 0.0 {
                2.0 * precision * recall / (precision + recall)
            } else {
                0.0
            };
            (
                c.to_string(),
                ClassMetrics {
                    precision,
                    recall,
                    f1,
                    support: (tp + fn_) as usize,
                },
            )
        })
        .collect();

    Ok(EvalReport {
        accuracy: if total > 0 {
            correct as f64 / total as f64
        } else {
            0.0
        },
        total,
        abstained,
        per_class,
        coverage_curve: Vec::new(),
        gold: None,
        // The pure kernel has no clock and no eval context: the RUNNER
        // stamps this at completion (`report_from_scored`). Fabricating a
        // timestamp here would put one on every unit-test report too.
        measured_at: None,
    })
}

/// accuracy@coverage from (truth, prediction-with-confidence) rows.
/// Abstentions count as below every threshold (they cover nothing).
pub fn coverage_curve(
    truths: &[String],
    predictions: &[Option<(String, f32)>],
) -> Vec<CoveragePoint> {
    const THRESHOLDS: [f64; 5] = [0.5, 0.6, 0.7, 0.8, 0.9];
    let total = truths.len();
    if total == 0 {
        return Vec::new();
    }
    THRESHOLDS
        .iter()
        .map(|&t| {
            let mut covered = 0usize;
            let mut correct = 0usize;
            for (truth, pred) in truths.iter().zip(predictions.iter()) {
                if let Some((label, conf)) = pred {
                    if f64::from(*conf) >= t {
                        covered += 1;
                        if label == truth {
                            correct += 1;
                        }
                    }
                }
            }
            CoveragePoint {
                threshold: t,
                coverage: covered as f64 / total as f64,
                accuracy: (covered > 0).then(|| correct as f64 / covered as f64),
                // The accuracy denominator, always recorded: `coverage` is a
                // fraction of the holdout and cannot be inverted into a count
                // by a reader who does not also have the holdout total.
                n: Some(covered as u64),
            }
        })
        .collect()
}

/// Classes smaller than this stay wholly in the train set: a class with
/// 1-2 examples would otherwise donate its ONLY representation to the
/// holdout, making it unpredictable-by-construction and skewing the
/// eval against the fast backend for a splitter artifact, not model
/// quality.
pub const MIN_CLASS_FOR_HOLDOUT: usize = 3;

/// Deterministic stratified holdout assignment: within each class,
/// examples are sorted by UUID (v4 → a uniformly random but STABLE
/// permutation, independent of insertion/query order) and the first
/// `round(n × fraction)` are assigned to the holdout. Determinism
/// matters: re-running eval on an unchanged dataset must produce the
/// same split, or metric deltas between runs are noise. Classes below
/// [`MIN_CLASS_FOR_HOLDOUT`] are excluded (kept wholly in train).
/// Returns the ids assigned to the holdout.
pub fn stratified_holdout(
    examples: &[(uuid::Uuid, String)],
    holdout_fraction: f64,
) -> Vec<uuid::Uuid> {
    let fraction = holdout_fraction.clamp(0.05, 0.5);
    let mut by_class: BTreeMap<&str, Vec<uuid::Uuid>> = BTreeMap::new();
    for (id, label) in examples {
        by_class.entry(label.as_str()).or_default().push(*id);
    }
    let mut holdout = Vec::new();
    for ids in by_class.values_mut() {
        if ids.len() < MIN_CLASS_FOR_HOLDOUT {
            continue;
        }
        ids.sort(); // stable order independent of query order
        let take = (((ids.len() as f64) * fraction).round() as usize).clamp(1, ids.len() - 1); // never donate a whole class
        holdout.extend_from_slice(&ids[..take]);
    }
    holdout
}

/// Corrections handling for eval + training (corrections-as-training,
/// 2026-07-19). Defaults mirror `PolicyJson`'s.
#[derive(Debug, Clone, Copy)]
pub struct CorrectionsCfg {
    /// Per-sample emphasis for correction rows in training (LR sample
    /// weight; knn vote multiplier). Clamped 1..=10 downstream.
    pub weight: f32,
    /// Fraction of corrections held out as the GOLD eval slice.
    pub gold_fraction: f64,
    /// Global floor on the gold slice (topped up deterministically when
    /// the fraction yields fewer), bounded by what the per-class ≥1-in-
    /// train rule allows.
    pub min_gold: usize,
}

impl Default for CorrectionsCfg {
    fn default() -> Self {
        Self {
            weight: 3.0,
            gold_fraction: 0.3,
            min_gold: 8,
        }
    }
}

/// Stable per-row split key for corrections: sha256 of `example_key`
/// when present (survives delete+reinsert — upserts keep the row id,
/// but a reinsert mints a new UUID and would silently churn gold
/// membership), falling back to the row id.
fn correction_sort_key(id: uuid::Uuid, example_key: Option<&str>) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    match example_key {
        Some(k) if !k.is_empty() => Sha256::digest(k.as_bytes()).into(),
        _ => Sha256::digest(id.as_bytes()).into(),
    }
}

/// Correction-aware split (replaces source-blind [`stratified_holdout`]
/// in the selection eval). Pre-change, corrections were UUID-hashed
/// into train/holdout like any other row: the `gold` block was
/// "whichever corrections happened to land in holdout" — floorless
/// (could be empty), and its membership churned as the dataset grew.
///
/// Now: NON-correction rows keep the exact legacy stratified holdout.
/// CORRECTIONS are partitioned separately and deterministically (per
/// class, ordered by [`correction_sort_key`]): `gold_fraction` of each
/// class (clamp 1..=n-1, classes < [`MIN_CLASS_FOR_HOLDOUT`] wholly in
/// train) goes to the holdout — becoming the gold slice — topped up to
/// `min_gold` from the remaining hash order where a class can spare a
/// row. Every correction NOT in gold lands in train, where the weighted
/// fit/vote emphasizes it. Returns the full holdout id set.
pub fn correction_aware_holdout(
    examples: &[(uuid::Uuid, String, String, Option<String>)],
    holdout_fraction: f64,
    cfg: &CorrectionsCfg,
) -> Vec<uuid::Uuid> {
    let gold_fraction = cfg.gold_fraction.clamp(0.1, 0.5);

    let (corrections, others): (Vec<_>, Vec<_>) = examples
        .iter()
        .partition(|(_, _, source, _)| source == "correction");

    // Non-corrections: legacy behavior verbatim.
    let other_labels: Vec<(uuid::Uuid, String)> = others
        .iter()
        .map(|(id, l, _, _)| (*id, l.clone()))
        .collect();
    let mut holdout = stratified_holdout(&other_labels, holdout_fraction);

    // Corrections: per-class deterministic gold slice.
    let mut by_class: BTreeMap<&str, Vec<(uuid::Uuid, [u8; 32])>> = BTreeMap::new();
    for (id, label, _, key) in &corrections {
        by_class
            .entry(label.as_str())
            .or_default()
            .push((*id, correction_sort_key(*id, key.as_deref())));
    }
    let mut gold: Vec<uuid::Uuid> = Vec::new();
    // (class, remaining hash-ordered candidates that can still move to
    // gold without emptying the class's train share) for the top-up.
    let mut spare: Vec<(uuid::Uuid, [u8; 32])> = Vec::new();
    for ids in by_class.values_mut() {
        ids.sort_by_key(|(_, h)| *h);
        if ids.len() < MIN_CLASS_FOR_HOLDOUT {
            continue; // wholly in train — same rule as the legacy split
        }
        let take = (((ids.len() as f64) * gold_fraction).round() as usize).clamp(1, ids.len() - 1);
        gold.extend(ids[..take].iter().map(|(id, _)| *id));
        // Rows beyond `take` may top up the floor — but always leave ≥1
        // in train per class.
        if ids.len() - take > 1 {
            spare.extend_from_slice(&ids[take..ids.len() - 1]);
        }
    }
    if gold.len() < cfg.min_gold {
        spare.sort_by_key(|(_, h)| *h);
        for (id, _) in spare {
            if gold.len() >= cfg.min_gold {
                break;
            }
            gold.push(id);
        }
    }
    holdout.extend(gold);
    holdout
}

/// Macro-averaged F1, over the classes actually PRESENT in the holdout
/// truth (support > 0) — reported alongside the selection score for
/// transparency. Excluding `support == 0` classes matters: a backend that
/// predicts a label absent from the holdout truth (e.g. a rare class kept
/// wholly in train by the min-class rule) would otherwise add a phantom
/// recall-0 class that unfairly deflates exactly the diverse-predicting
/// backend. Standard macro averaging is over y_true classes only.
pub fn macro_f1(report: &EvalReport) -> f64 {
    let scored: Vec<f64> = report
        .per_class
        .values()
        .filter(|m| m.support > 0)
        .map(|m| m.f1)
        .collect();
    if scored.is_empty() {
        return 0.0;
    }
    scored.iter().sum::<f64>() / scored.len() as f64
}

/// Macro-averaged recall (a.k.a. balanced accuracy) — the unweighted mean
/// of per-class recall. This is the BACKEND-SELECTION score, chosen over
/// macro-F1 deliberately: the promotion policy gates on per-class recall
/// FLOORS, and macro-recall is the metric that rewards lifting the worst
/// class rather than letting one strong class (archive) mask a weak one
/// (follow_up). On the live inbox model knn and a converged linear tie on
/// macro-F1 (~0.83), but linear wins macro-recall clearly (~0.89 vs ~0.84)
/// precisely because it recovers the minority class knn abandons.
pub fn macro_recall(report: &EvalReport) -> f64 {
    // Over the classes PRESENT in the holdout truth (support > 0) only — a
    // predicted-only phantom class (support 0, recall 0) would otherwise
    // deflate the score of the very backend that predicts more diverse
    // labels. See [`macro_f1`].
    let scored: Vec<f64> = report
        .per_class
        .values()
        .filter(|m| m.support > 0)
        .map(|m| m.recall)
        .collect();
    if scored.is_empty() {
        return 0.0;
    }
    scored.iter().sum::<f64>() / scored.len() as f64
}

/// The single clock read of the eval path: the instant a backend finished
/// scoring the holdout, in RFC 3339.
///
/// Every `measured_at` downstream (the report's own, the version's
/// `metrics_json`, the model card's) is a COPY of this value, propagated by
/// value. No reader ever calls `now()` — a render-time timestamp claims a
/// freshness the numbers do not have, which is the misleading-report-field
/// class this whole change exists to close.
fn measurement_instant() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Build the full report (overall + coverage curve + gold subset) from a
/// backend's scored holdout. Shared by every backend so the eval shape is
/// identical no matter which one produced the predictions.
///
/// This is where `measured_at` is stamped: it is the completion point of one
/// backend's scoring pass, and it is shared by the parent report and its gold
/// sub-report (one measurement event, one clock).
fn report_from_scored(
    truths: &[String],
    sources: &[String],
    scored: &[Option<(String, f32)>],
) -> anyhow::Result<EvalReport> {
    let predictions: Vec<Option<String>> = scored
        .iter()
        .map(|p| p.as_ref().map(|(l, _)| l.clone()))
        .collect();
    let mut report = evaluate_predictions(truths, &predictions)?;
    report.coverage_curve = coverage_curve(truths, scored);
    // GOLD subset: human-corrected rows only.
    let gold_idx: Vec<usize> = sources
        .iter()
        .enumerate()
        .filter(|(_, s)| s.as_str() == "correction")
        .map(|(i, _)| i)
        .collect();
    if !gold_idx.is_empty() {
        let gt: Vec<String> = gold_idx.iter().map(|&i| truths[i].clone()).collect();
        let gs: Vec<Option<(String, f32)>> = gold_idx.iter().map(|&i| scored[i].clone()).collect();
        let gp: Vec<Option<String>> = gs
            .iter()
            .map(|p| p.as_ref().map(|(l, _)| l.clone()))
            .collect();
        let mut gold = evaluate_predictions(&gt, &gp)?;
        gold.coverage_curve = coverage_curve(&gt, &gs);
        report.gold = Some(Box::new(gold));
    }
    report.stamp_measured_at(measurement_instant());
    Ok(report)
}

/// One backend's evaluation on the shared holdout, plus what's needed to
/// persist it as a model version.
pub struct BackendCandidate {
    pub backend: &'static str,
    pub report: EvalReport,
    /// Serialized model bytes to store as the version artifact (linear);
    /// `None` for the lazy knn backend (nothing to persist).
    pub artifact: Option<Vec<u8>>,
    /// Backend-specific hyperparameters folded into the version's
    /// `metrics_json` (`{voting,k}` for knn, `{epochs,l2,balanced}` for
    /// linear).
    pub params: serde_json::Value,
    /// Reported for transparency (see [`macro_f1`]).
    pub macro_f1: f64,
    /// The SELECTION score — see [`macro_recall`].
    pub macro_recall: f64,
}

/// Evaluate EVERY available backend on ONE shared stratified holdout and
/// return the candidates ordered best-first (macro-RECALL; ties break
/// toward `knn-pgvector`, which serves without an artifact). This is the RFC's
/// "eval harness selects a backend empirically" — the split is assigned
/// once so knn and linear are compared apples-to-apples on the same rows.
/// A linear-fit failure (too little train signal, single class) is a
/// warn+skip, never a hard error: knn stands alone.
pub async fn run_backend_selection_eval(
    service: &crate::dataset::DatasetService,
    conn: &mut sqlx::PgConnection,
    dataset_id: uuid::Uuid,
    k: i64,
    holdout_fraction: f64,
    linear_opts: crate::linear::FitOpts,
    corrections: CorrectionsCfg,
) -> anyhow::Result<Vec<BackendCandidate>> {
    service.lock_dataset(&mut *conn, dataset_id).await?;
    service.pin_ann_probes(&mut *conn).await?;
    let labels = service
        .load_labels_with_source(&mut *conn, dataset_id)
        .await?;
    anyhow::ensure!(
        labels.len() >= 10,
        "dataset has only {} labeled examples — need at least 10 for a meaningful eval",
        labels.len()
    );
    let holdout_ids = correction_aware_holdout(&labels, holdout_fraction, &corrections);
    anyhow::ensure!(
        !holdout_ids.is_empty(),
        "stratified split produced an empty holdout (all classes below the minimum size)"
    );
    service
        .assign_splits(&mut *conn, dataset_id, &holdout_ids)
        .await?;
    let holdout = service.load_holdout(&mut *conn, dataset_id).await?;
    let counts = service.class_counts(&mut *conn, dataset_id).await?;
    let truths: Vec<String> = holdout.iter().map(|e| e.label.clone()).collect();
    let sources: Vec<String> = holdout.iter().map(|e| e.source.clone()).collect();

    let mut candidates = Vec::new();

    // --- knn (lazy): vote over the train split for each holdout row ---
    let mut knn_scored = Vec::with_capacity(holdout.len());
    for ex in &holdout {
        let pred = match &ex.embedding {
            Some(embedding) => service
                .knn_search(&mut *conn, dataset_id, embedding, k, true)
                .await
                .map(|n| crate::knn::knn_vote_balanced_weighted(&n, &counts, corrections.weight))?,
            None => None,
        };
        knn_scored.push(pred.map(|p| (p.label, p.confidence)));
    }
    let knn_report = report_from_scored(&truths, &sources, &knn_scored)?;
    candidates.push(BackendCandidate {
        backend: "knn-pgvector",
        macro_f1: macro_f1(&knn_report),
        macro_recall: macro_recall(&knn_report),
        report: knn_report,
        artifact: None,
        params: serde_json::json!({
            "voting": "balanced-sqrt",
            "k": k,
            "correction_weight": corrections.weight,
        }),
    });

    // --- linear (parametric): fit on train, predict holdout ---
    // Regularization is the dominant lever in the high-dim / few-rows
    // embedding regime, so sweep L2 and keep the best-macro-F1 fit
    // (auto-tuning; a few sub-second fits). Everything else comes from the
    // caller's base opts.
    let train: Vec<(Vec<f32>, String, f32)> = service
        .load_train_embeddings_with_source(&mut *conn, dataset_id)
        .await?
        .into_iter()
        .map(|(emb, label, is_corr)| {
            let w = if is_corr {
                corrections.weight.clamp(1.0, 10.0)
            } else {
                1.0
            };
            (emb, label, w)
        })
        .collect();
    if train.len() >= 10 {
        const L2_GRID: [f32; 3] = [1e-4, 1e-2, 1e-1];
        // (report, artifact, l2, macro_recall) of the best fit so far —
        // grid points are ranked by the same macro-recall selection score.
        let mut best: Option<(EvalReport, Vec<u8>, f32, f64)> = None;
        for &l2 in &L2_GRID {
            let opts = crate::linear::FitOpts { l2, ..linear_opts };
            let model = match crate::linear::fit_weighted(&train, opts) {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!(target: "talos_ml", %l2, error = %e, "linear fit failed at this l2");
                    continue;
                }
            };
            let scored: Vec<Option<(String, f32)>> = holdout
                .iter()
                .map(|ex| {
                    ex.embedding
                        .as_ref()
                        .and_then(|e| model.predict(e))
                        .map(|p| (p.label, p.confidence))
                })
                .collect();
            let report = report_from_scored(&truths, &sources, &scored)?;
            let mr = macro_recall(&report);
            if best.as_ref().map(|(_, _, _, b)| mr > *b).unwrap_or(true) {
                best = Some((report, model.to_artifact()?, l2, mr));
            }
        }
        match best {
            Some((report, artifact, l2, _mr)) => candidates.push(BackendCandidate {
                backend: crate::linear::BACKEND_NAME,
                macro_f1: macro_f1(&report),
                macro_recall: macro_recall(&report),
                report,
                artifact: Some(artifact),
                params: serde_json::json!({
                    "epochs": linear_opts.epochs,
                    "lr": linear_opts.lr,
                    "l2": l2,
                    "balanced": linear_opts.balanced,
                    "correction_weight": corrections.weight,
                    "selected_by": "l2-grid",
                }),
            }),
            None => {
                tracing::warn!(target: "talos_ml", "all linear fits failed; knn stands alone")
            }
        }
    }

    // Best macro-RECALL first; a tie prefers knn (no artifact, cheaper).
    candidates.sort_by(|a, b| {
        b.macro_recall
            .partial_cmp(&a.macro_recall)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| (a.backend != "knn-pgvector").cmp(&(b.backend != "knn-pgvector")))
    });
    Ok(candidates)
}

/// Full knn eval pass, designed to run inside ONE caller transaction:
/// takes the per-dataset advisory lock (held to tx end, so a concurrent
/// eval can't thrash the splits mid-scoring), assigns a fresh stratified
/// split, then scores every holdout example using its STORED embedding
/// (no re-embedding; deterministic w.r.t. the geometry knn searches).
/// Examples without stored embeddings score as abstentions — they'd
/// abstain in production too.
pub async fn run_knn_eval(
    service: &crate::dataset::DatasetService,
    conn: &mut sqlx::PgConnection,
    dataset_id: uuid::Uuid,
    k: i64,
    holdout_fraction: f64,
    corrections: CorrectionsCfg,
) -> anyhow::Result<EvalReport> {
    service.lock_dataset(&mut *conn, dataset_id).await?;
    // ONCE per tx — knn_search does not pin (see pin_ann_probes).
    service.pin_ann_probes(&mut *conn).await?;
    let labels = service
        .load_labels_with_source(&mut *conn, dataset_id)
        .await?;
    anyhow::ensure!(
        labels.len() >= 10,
        "dataset has only {} labeled examples — need at least 10 for a meaningful eval",
        labels.len()
    );
    let holdout_ids = correction_aware_holdout(&labels, holdout_fraction, &corrections);
    anyhow::ensure!(
        !holdout_ids.is_empty(),
        "stratified split produced an empty holdout (all classes below the minimum size)"
    );
    service
        .assign_splits(&mut *conn, dataset_id, &holdout_ids)
        .await?;
    let holdout = service.load_holdout(&mut *conn, dataset_id).await?;
    // Class priors for balanced voting (matches knn_predict_text so the
    // eval measures exactly what production serves).
    let counts = service.class_counts(&mut *conn, dataset_id).await?;
    let mut truths = Vec::with_capacity(holdout.len());
    let mut scored = Vec::with_capacity(holdout.len());
    let mut sources = Vec::with_capacity(holdout.len());
    for ex in &holdout {
        truths.push(ex.label.clone());
        sources.push(ex.source.clone());
        let pred = match &ex.embedding {
            Some(embedding) => service
                .knn_search(&mut *conn, dataset_id, embedding, k, true)
                .await
                .map(|n| crate::knn::knn_vote_balanced_weighted(&n, &counts, corrections.weight))?,
            None => None,
        };
        scored.push(pred.map(|p| (p.label, p.confidence)));
    }
    report_from_scored(&truths, &sources, &scored)
}

#[cfg(test)]
mod tests {
    use super::{correction_aware_holdout, CorrectionsCfg};

    fn rows(
        spec: &[(u128, &str, &str, Option<&str>)],
    ) -> Vec<(uuid::Uuid, String, String, Option<String>)> {
        spec.iter()
            .map(|(n, l, s, k)| {
                (
                    uuid::Uuid::from_u128(*n),
                    l.to_string(),
                    s.to_string(),
                    k.map(str::to_string),
                )
            })
            .collect()
    }

    #[test]
    fn correction_split_is_deterministic_and_floored() {
        // 12 corrections in one class + 20 teacher rows in another.
        let mut spec: Vec<(u128, &str, &str, Option<&str>)> = Vec::new();
        for i in 0..12u128 {
            spec.push((
                i,
                "a",
                "correction",
                Some(Box::leak(format!("k{i}").into_boxed_str()) as &str),
            ));
        }
        for i in 100..120u128 {
            spec.push((i, "b", "llm", None));
        }
        let examples = rows(&spec);
        let cfg = CorrectionsCfg {
            weight: 3.0,
            gold_fraction: 0.3,
            min_gold: 8,
        };
        let h1 = correction_aware_holdout(&examples, 0.2, &cfg);
        let h2 = correction_aware_holdout(&examples, 0.2, &cfg);
        assert_eq!(h1, h2, "split must be deterministic");
        // Gold floor: fraction gives round(12×0.3)=4, floor tops up to 8,
        // bounded by leave-one-in-train (max 11 gold; spare rule leaves the
        // per-class last row in train).
        let correction_ids: std::collections::HashSet<_> =
            (0..12u128).map(uuid::Uuid::from_u128).collect();
        let gold: Vec<_> = h1.iter().filter(|id| correction_ids.contains(id)).collect();
        assert_eq!(
            gold.len(),
            8,
            "floor must top the gold slice up to min_gold"
        );
        // At least one correction stays in train.
        assert!(gold.len() < 12);
    }

    #[test]
    fn tiny_correction_classes_stay_wholly_in_train() {
        let examples = rows(&[
            (1, "a", "correction", Some("x1")),
            (2, "a", "correction", Some("x2")),
            (100, "b", "llm", None),
            (101, "b", "llm", None),
            (102, "b", "llm", None),
            (103, "b", "llm", None),
        ]);
        let cfg = CorrectionsCfg::default();
        let holdout = correction_aware_holdout(&examples, 0.2, &cfg);
        // Class "a" has 2 corrections (< MIN_CLASS_FOR_HOLDOUT) — none may
        // be donated to gold even with the floor unmet.
        assert!(!holdout.contains(&uuid::Uuid::from_u128(1)));
        assert!(!holdout.contains(&uuid::Uuid::from_u128(2)));
    }

    use super::*;
    use uuid::Uuid;

    fn s(v: &str) -> String {
        v.to_string()
    }

    #[test]
    fn perfect_predictions_score_one() {
        let truths = vec![s("a"), s("b"), s("a")];
        let preds = vec![Some(s("a")), Some(s("b")), Some(s("a"))];
        let r = evaluate_predictions(&truths, &preds).unwrap();
        assert_eq!(r.accuracy, 1.0);
        assert_eq!(r.per_class["a"].f1, 1.0);
        assert_eq!(r.per_class["a"].support, 2);
        assert_eq!(r.abstained, 0);
    }

    #[test]
    fn abstentions_count_against_accuracy_and_recall() {
        let truths = vec![s("a"), s("a")];
        let preds = vec![Some(s("a")), None];
        let r = evaluate_predictions(&truths, &preds).unwrap();
        assert_eq!(r.accuracy, 0.5);
        assert_eq!(r.abstained, 1);
        assert_eq!(r.per_class["a"].recall, 0.5);
        // Precision unaffected by the abstention (no false positive).
        assert_eq!(r.per_class["a"].precision, 1.0);
    }

    #[test]
    fn misprediction_hits_both_classes() {
        // truth b predicted a: fp for a, fn for b.
        let truths = vec![s("b")];
        let preds = vec![Some(s("a"))];
        let r = evaluate_predictions(&truths, &preds).unwrap();
        assert_eq!(r.per_class["a"].precision, 0.0);
        assert_eq!(r.per_class["b"].recall, 0.0);
        assert_eq!(r.per_class["b"].support, 1);
    }

    /// D2: every coverage point carries the DENOMINATOR its accuracy is over.
    ///
    /// Mutation guard — deleting `n` from [`CoveragePoint`], or filling it
    /// with anything other than the covered count, fails here. Before this
    /// field, `accuracy = 1.0` at `coverage = 0.03` (2 rows) rendered
    /// identically to 1.0 over 600, and the doc-comment on this very struct
    /// called it "the deploy-decision number".
    #[test]
    fn coverage_points_carry_their_denominator() {
        let truths = vec![s("a"), s("a"), s("b"), s("b")];
        let preds = vec![
            Some((s("a"), 0.95f32)),
            Some((s("a"), 0.85)),
            Some((s("a"), 0.55)), // wrong, low confidence
            None,                 // abstention: covers nothing at any threshold
        ];
        let curve = coverage_curve(&truths, &preds);
        // n IS the accuracy denominator, exactly: at 0.5 three rows are
        // covered and two are right (2/3); at 0.9 one row is covered.
        assert_eq!(curve[0].n, Some(3));
        assert_eq!(curve[4].n, Some(1));
        // …and it is consistent with `coverage` (n / holdout total) at every
        // point, so the two fields can never tell different stories.
        for p in &curve {
            let n = p.n.expect("every produced point carries n");
            assert!(
                (p.coverage - n as f64 / truths.len() as f64).abs() < 1e-12,
                "coverage {} disagrees with n {n} at threshold {}",
                p.coverage,
                p.threshold
            );
            // A band with nothing in it reports no accuracy — not 0.0.
            assert_eq!(p.accuracy.is_none(), n == 0, "n/accuracy disagree at {p:?}");
        }
        // MONOTONIC: raising the confidence floor can only shed rows. A curve
        // whose n rises with the threshold would mean the bands are not nested
        // and none of the accuracies mean what they claim.
        for w in curve.windows(2) {
            assert!(w[0].threshold < w[1].threshold);
            assert!(
                w[0].n.unwrap() >= w[1].n.unwrap(),
                "n rose from {:?} to {:?} as the threshold rose",
                w[0],
                w[1]
            );
        }
    }

    /// D2's other half: the per-band population is stated ONCE, in the shared
    /// constant both renderers (`ml_eval_model`, the model card) emit.
    #[test]
    fn the_coverage_note_states_the_denominator_and_what_absence_means() {
        assert!(COVERAGE_CURVE_POPULATION_NOTE.contains("its OWN population"));
        assert!(COVERAGE_CURVE_POPULATION_NOTE.contains("NOT of the whole holdout"));
        assert!(COVERAGE_CURVE_POPULATION_NOTE.contains("read n before the accuracy"));
        assert!(
            COVERAGE_CURVE_POPULATION_NOTE.contains("absent means not recorded, not zero"),
            "old points carry no n and the note must say what that means"
        );
    }

    /// D4: the eval RUNNER stamps `measured_at`; the pure kernel does not.
    ///
    /// One instant covers the report and its gold sub-report — they are one
    /// measurement event (gold re-scores a subset of the same holdout run), so
    /// two different clocks there would be two different claims about when.
    #[test]
    fn the_runner_stamps_one_instant_and_the_kernel_stamps_none() {
        let truths = vec![s("a"), s("b"), s("a")];
        let scored = vec![
            Some((s("a"), 0.9f32)),
            Some((s("b"), 0.8)),
            Some((s("a"), 0.7)),
        ];
        // Only the middle row is a human correction → a gold slice exists.
        let sources = vec![s("llm"), s("correction"), s("llm")];
        let report = report_from_scored(&truths, &sources, &scored).unwrap();
        let stamp = report.measured_at.clone().expect("runner must stamp");
        // RFC 3339, UTC.
        chrono::DateTime::parse_from_rfc3339(&stamp).expect("measured_at must be RFC 3339");
        assert!(stamp.ends_with('Z'), "{stamp}");
        assert_eq!(
            report.gold.as_ref().unwrap().measured_at.as_deref(),
            Some(stamp.as_str()),
            "gold is the same measurement event and must carry the same instant"
        );
        // The REAL eval path (not just `coverage_curve` in isolation) fills
        // the per-band denominator, on the parent AND on the gold slice.
        assert_eq!(report.coverage_curve[0].n, Some(3));
        assert_eq!(report.gold.as_ref().unwrap().coverage_curve[0].n, Some(1));
        // The PURE kernel has no clock — a unit-test report must not look like
        // it was measured against production data.
        let bare = evaluate_predictions(&truths, &[Some(s("a")), None, None]).unwrap();
        assert_eq!(bare.measured_at, None);
    }

    /// D3/D4 compat: a report stored BEFORE the provenance fields existed
    /// deserializes with them ABSENT — never defaulted to `0` or to a
    /// fabricated timestamp — and round-trips back out without inventing them.
    #[test]
    fn a_legacy_stored_report_deserializes_with_its_provenance_absent() {
        let legacy = serde_json::json!({
            "accuracy": 0.8,
            "total": 35,
            "abstained": 2,
            "per_class": {
                "archive": { "precision": 0.9, "recall": 0.8, "f1": 0.85, "support": 20 }
            },
            "coverage_curve": [
                { "threshold": 0.5, "coverage": 0.6, "accuracy": 1.0 }
            ],
            "gold": {
                "accuracy": 0.4857, "total": 35, "abstained": 0, "per_class": {}
            }
        });
        let r: EvalReport = serde_json::from_value(legacy).expect("old shape must still parse");
        assert_eq!(r.total, 35);
        assert_eq!(r.measured_at, None, "absent means NOT MEASURED");
        assert_eq!(r.coverage_curve[0].n, None, "absent means NOT RECORDED");
        assert_eq!(r.gold.as_ref().unwrap().measured_at, None);
        // Re-serializing must not materialize the missing keys as zeros.
        let back = serde_json::to_value(&r).unwrap();
        let point = back["coverage_curve"][0].as_object().unwrap();
        assert!(!point.contains_key("n"), "n must stay absent: {back}");
        assert!(!back.as_object().unwrap().contains_key("measured_at"));
        // A 1.0 accuracy with no n is exactly the number a reader must not
        // over-read; it survives as-is so the renderer can say "unknown n".
        assert_eq!(point["accuracy"], 1.0);
    }

    #[test]
    fn coverage_curve_trades_coverage_for_accuracy() {
        let truths = vec![s("a"), s("a"), s("b"), s("b")];
        // Two confident correct, one hesitant wrong, one abstention.
        let preds = vec![
            Some((s("a"), 0.95f32)),
            Some((s("a"), 0.85)),
            Some((s("a"), 0.55)), // wrong, low confidence
            None,
        ];
        let curve = coverage_curve(&truths, &preds);
        let p50 = &curve[0];
        let p90 = &curve[4];
        assert!((p50.coverage - 0.75).abs() < 1e-9);
        assert!((p50.accuracy.unwrap() - 2.0 / 3.0).abs() < 1e-9);
        assert!((p90.coverage - 0.25).abs() < 1e-9);
        assert!(
            (p90.accuracy.unwrap() - 1.0).abs() < 1e-9,
            "high threshold sheds the wrong answer"
        );
        assert!(coverage_curve(&[], &[]).is_empty());
    }

    #[test]
    fn tiny_classes_stay_wholly_in_train() {
        // 1- and 2-example classes must not donate to holdout; a
        // 3-example class donates exactly one but never all.
        let mut examples = vec![
            (Uuid::from_u128(1), s("singleton")),
            (Uuid::from_u128(2), s("pair")),
            (Uuid::from_u128(3), s("pair")),
        ];
        for i in 0..3 {
            examples.push((Uuid::from_u128(10 + i), s("trio")));
        }
        let h = stratified_holdout(&examples, 0.5);
        assert!(!h.contains(&Uuid::from_u128(1)), "singleton donated");
        assert!(
            !h.iter()
                .any(|id| *id == Uuid::from_u128(2) || *id == Uuid::from_u128(3)),
            "pair donated"
        );
        let trio_in_holdout = h
            .iter()
            .filter(|id| (10..13).contains(&id.as_u128()))
            .count();
        assert!(trio_in_holdout >= 1 && trio_in_holdout < 3);
    }

    #[test]
    fn desynced_slices_error_instead_of_panicking() {
        assert!(evaluate_predictions(&[s("a")], &[]).is_err());
    }

    #[test]
    fn macro_metrics_exclude_predicted_only_phantom_classes() {
        // Holdout truth is all class "a"; a backend predicts "b" on one row.
        // "b" is a phantom (support 0 — never a truth) and must NOT drag the
        // macro scores down, or it would penalize the diverse-predicting
        // backend the selector is meant to favor.
        let truths = vec![s("a"), s("a"), s("a")];
        let preds = vec![Some(s("a")), Some(s("a")), Some(s("b"))];
        let r = evaluate_predictions(&truths, &preds).unwrap();
        assert_eq!(r.per_class["a"].support, 3);
        assert_eq!(r.per_class["b"].support, 0, "b is predicted-only");
        // Macro over support>0 = just 'a' (recall 2/3), NOT (2/3 + 0)/2.
        assert!((macro_recall(&r) - 2.0 / 3.0).abs() < 1e-9);
        assert!((macro_f1(&r) - r.per_class["a"].f1).abs() < 1e-9);
    }

    #[test]
    fn stratified_holdout_is_deterministic_and_covers_all_classes() {
        let mut examples = Vec::new();
        for i in 0..100 {
            let label = if i % 10 == 0 { "rare" } else { "common" };
            examples.push((Uuid::from_u128(i as u128 + 1), label.to_string()));
        }
        let a = stratified_holdout(&examples, 0.2);
        let b = stratified_holdout(&examples, 0.2);
        assert_eq!(a, b, "same input must produce the same split");
        // Rare class (10 examples) gets at least one holdout slot.
        let rare_ids: std::collections::HashSet<_> = examples
            .iter()
            .filter(|(_, l)| l == "rare")
            .map(|(id, _)| *id)
            .collect();
        assert!(a.iter().any(|id| rare_ids.contains(id)));
        // Roughly 20% overall.
        assert!(a.len() >= 15 && a.len() <= 25, "got {}", a.len());
    }
}
