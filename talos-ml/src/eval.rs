//! Eval harness — the backend SELECTOR.
//!
//! Given (truth, prediction) pairs from a holdout run, computes
//! per-class precision/recall/F1 + accuracy. The metrics kernel is pure;
//! the async orchestration (split assignment, running backends over the
//! holdout) lives in the service layer so this stays unit-testable.

use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, PartialEq)]
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
#[derive(Debug, Clone, Serialize)]
pub struct CoveragePoint {
    pub threshold: f64,
    pub coverage: f64,
    pub accuracy: f64,
}

#[derive(Debug, Clone, Serialize)]
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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub coverage_curve: Vec<CoveragePoint>,
    /// GOLD subset (source='correction' — human truth) scored
    /// separately: teacher labels grade agreement, gold grades
    /// correctness, and a distilled model can legitimately beat its
    /// teacher here. None until corrections exist in the holdout.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gold: Option<Box<EvalReport>>,
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
                accuracy: if covered > 0 {
                    correct as f64 / covered as f64
                } else {
                    0.0
                },
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
) -> anyhow::Result<EvalReport> {
    service.lock_dataset(&mut *conn, dataset_id).await?;
    let labels = service.load_labels(&mut *conn, dataset_id).await?;
    anyhow::ensure!(
        labels.len() >= 10,
        "dataset has only {} labeled examples — need at least 10 for a meaningful eval",
        labels.len()
    );
    let holdout_ids = stratified_holdout(&labels, holdout_fraction);
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
                .map(|n| crate::knn::knn_vote_balanced(&n, &counts))?,
            None => None,
        };
        scored.push(pred.map(|p| (p.label, p.confidence)));
    }
    let predictions: Vec<Option<String>> = scored
        .iter()
        .map(|p| p.as_ref().map(|(l, _)| l.clone()))
        .collect();
    let mut report = evaluate_predictions(&truths, &predictions)?;
    report.coverage_curve = coverage_curve(&truths, &scored);
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
    Ok(report)
}

#[cfg(test)]
mod tests {
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
        assert!((p50.accuracy - 2.0 / 3.0).abs() < 1e-9);
        assert!((p90.coverage - 0.25).abs() < 1e-9);
        assert!(
            (p90.accuracy - 1.0).abs() < 1e-9,
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
