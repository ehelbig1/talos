//! The per-actor learned ranker: a tiny weighted binary logistic regression
//! over the Phase-1 provenance features, plus the coefficient → fused-weight
//! mapping that feeds the existing ranker.
//!
//! ## The one-model insight
//! The smart ranker's fused score is
//! `w_rel·relevance + w_rec·recency + w_imp·importance` (with `access_weight`
//! folded into the importance term). A logistic regression over the SAME four
//! recorded features `[relevance, recency, importance, access_boost]`, fit to
//! predict the execution OUTCOME label, yields coefficients that ARE the
//! adaptive per-actor blend weights — "learned importance" and "adaptive
//! weights" are one model.
//!
//! ## Why RAW features (no standardization at serve time)
//! We fit on the RAW recorded features. All four live in `[0, 1]` already
//! (relevance/recency/importance are `[0,1]`; `access_boost` is `[0,1)`), so
//! they are on a comparable, bounded scale and standardization is not needed
//! for convergence. Critically, the ranker's fused score multiplies the
//! coefficients by the SAME raw features — so a raw-feature coefficient can be
//! used DIRECTLY as a fused weight ([`rank_weights_to_fused`]). If we fit on
//! standardized features we would have to un-standardize before the mapping;
//! fitting raw keeps the mapping a clean `coefficient → weight`. `feature_mean`
//! / `feature_std` are still recorded on the artifact as observability /
//! self-description, but are NOT applied at serve time.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use talos_memory::RankTrainingExample;

/// Number of features the model fits over: `[relevance, recency, importance,
/// access_boost]`.
pub const N_FEATURES: usize = 4;

/// Upper cap on a mapped fused weight — the SAME bound the global weight knobs
/// use, so learned and global weights share one ceiling. Referenced from
/// `talos-config` (not a hand-mirrored literal) so a retune of that constant
/// can't silently drift the two apart (AOT-fingerprint-version-rot class).
/// A `+Inf`/runaway coefficient must not make every `fused_score` `Inf` and
/// collapse ranking to tie-break order. Lower bound is 0 (see
/// [`rank_weights_to_fused`]).
pub const FUSED_WEIGHT_MAX: f64 = talos_config::SMART_MEMORY_WEIGHT_MAX;

// Fit hyperparameters. This is a TINY model (4 features), so a bespoke
// full-batch gradient-descent loop is ample and sub-millisecond. Bounded
// epochs + L2 guard the small-actor overfit regime.
const FIT_EPOCHS: usize = 500;
const FIT_LR: f64 = 0.1;
const FIT_L2: f64 = 1e-3;

/// Sample weight for a judge-labeled example — the strongest outcome signal.
pub const JUDGE_SAMPLE_WEIGHT: f64 = 1.0;
/// Sample weight for a status-only example (weaker signal than a judge verdict).
pub const STATUS_SAMPLE_WEIGHT: f64 = 0.3;

/// The learned per-actor rank model, serialized into
/// `actors.metadata.rank_weights`. Self-describing: it carries the fit
/// provenance (`n_examples`, `fitted_at`) and the feature statistics so an
/// operator can inspect what was learned.
///
/// `w_relevance` / `w_recency` / `w_importance` / `w_access` are the RAW
/// logistic coefficients (logit scale — CAN be negative). The non-negative,
/// clamped fused weights are derived at serve time by [`rank_weights_to_fused`];
/// storing the raw coefficients keeps this a faithful model record.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RankWeights {
    /// Raw logistic coefficient for the relevance feature.
    pub w_relevance: f64,
    /// Raw logistic coefficient for the recency feature.
    pub w_recency: f64,
    /// Raw logistic coefficient for the importance feature.
    pub w_importance: f64,
    /// Raw logistic coefficient for the access-boost feature.
    pub w_access: f64,
    /// Intercept (not used by the fused ranker — recorded for completeness).
    pub bias: f64,
    /// Per-feature mean over the training set (observability; NOT applied at
    /// serve time — see the module doc on RAW-feature fitting).
    pub feature_mean: [f64; N_FEATURES],
    /// Per-feature std over the training set (observability; NOT applied at
    /// serve time).
    pub feature_std: [f64; N_FEATURES],
    /// Number of usable labeled examples the fit consumed.
    pub n_examples: i64,
    /// When the fit ran.
    pub fitted_at: DateTime<Utc>,
}

/// Extract the 4-D feature vector from a Phase-1 training example, in the fixed
/// order `[relevance, recency, importance, access_boost]`. `access_boost` is
/// `None` for older rows / no-signal → treated as the NEUTRAL `0.0` (exactly
/// how the ranker's importance term treats a `None` boost). Deliberately EXCLUDES
/// `rank` and `fused_score` — those are OUTPUTS of ranking, not memory features,
/// and including them would be circular.
pub fn example_to_features(ex: &RankTrainingExample) -> [f64; N_FEATURES] {
    [
        ex.relevance,
        ex.recency,
        ex.importance,
        ex.access_boost.unwrap_or(0.0),
    ]
}

/// Derive the outcome `(label, sample_weight)` for one example, or `None` when
/// the example has no usable label (skip it):
/// * a judge verdict wins (`judge_passed` → 1.0/0.0) at full weight; else
/// * `execution_status` maps `completed → 1.0`, `failed`/`cancelled → 0.0` at
///   the weaker [`STATUS_SAMPLE_WEIGHT`]; any other status (e.g. `running`,
///   `pending`, `resuming`, or `None`) is unlabeled → skipped.
pub fn example_label(ex: &RankTrainingExample) -> Option<(f64, f64)> {
    if let Some(passed) = ex.judge_passed {
        return Some((if passed { 1.0 } else { 0.0 }, JUDGE_SAMPLE_WEIGHT));
    }
    match ex.execution_status.as_deref() {
        Some("completed") => Some((1.0, STATUS_SAMPLE_WEIGHT)),
        Some("failed") | Some("cancelled") => Some((0.0, STATUS_SAMPLE_WEIGHT)),
        _ => None,
    }
}

/// Build the `(features, label, sample_weight)` training triples from a batch of
/// Phase-1 examples: keep only examples with a usable label AND finite features
/// (a non-finite recorded signal would poison the fit — skip it).
pub fn build_training_set(examples: &[RankTrainingExample]) -> Vec<(Vec<f64>, f64, f64)> {
    let mut out = Vec::with_capacity(examples.len());
    for ex in examples {
        let Some((label, weight)) = example_label(ex) else {
            continue;
        };
        let feats = example_to_features(ex);
        if !feats.iter().all(|f| f.is_finite()) {
            continue;
        }
        out.push((feats.to_vec(), label, weight));
    }
    out
}

fn sigmoid(z: f64) -> f64 {
    1.0 / (1.0 + (-z).exp())
}

/// Fit a compact L2-regularized, sample-weighted binary logistic regression over
/// the `[relevance, recency, importance, access_boost]` features, targeting the
/// outcome label. Full-batch gradient descent on RAW features (all in `[0,1]`),
/// mirroring `talos-ml`'s `linear.rs` gradient shape (mean gradient + L2 weight
/// decay, no decay on the bias).
///
/// Returns `None` — meaning "keep the global defaults, do not write a model" —
/// when there is no learnable signal:
/// * fewer than [`talos_config::adaptive_rank_min_examples`] usable examples
///   (cold-start), OR
/// * the label set is single-class (all-positive or all-negative → no contrast),
///   OR
/// * the fit produced a non-finite coefficient/bias (degenerate).
///
/// `examples` are the `(features, label, sample_weight)` triples from
/// [`build_training_set`].
pub fn fit_rank_weights(examples: &[(Vec<f64>, f64, f64)]) -> Option<RankWeights> {
    let min_examples = talos_config::adaptive_rank_min_examples().max(0) as usize;
    if examples.len() < min_examples {
        return None;
    }
    // Single-class guard: with no label contrast the fit has nothing to learn;
    // keep global defaults rather than a degenerate all-one-way model.
    let any_pos = examples.iter().any(|(_, y, _)| *y >= 0.5);
    let any_neg = examples.iter().any(|(_, y, _)| *y < 0.5);
    if !(any_pos && any_neg) {
        return None;
    }

    let n_examples = examples.len();
    // Every row must be N_FEATURES wide (build_training_set guarantees this,
    // but be defensive against a hand-built caller).
    if examples.iter().any(|(x, _, _)| x.len() != N_FEATURES) {
        return None;
    }

    // Feature statistics (observability only — not applied at serve time).
    let mut feature_mean = [0.0f64; N_FEATURES];
    for (x, _, _) in examples {
        for j in 0..N_FEATURES {
            feature_mean[j] += x[j];
        }
    }
    for m in feature_mean.iter_mut() {
        *m /= n_examples as f64;
    }
    let mut feature_std = [0.0f64; N_FEATURES];
    for (x, _, _) in examples {
        for j in 0..N_FEATURES {
            let d = x[j] - feature_mean[j];
            feature_std[j] += d * d;
        }
    }
    for s in feature_std.iter_mut() {
        *s = (*s / n_examples as f64).sqrt();
    }

    // Weighted full-batch gradient descent.
    let weight_sum: f64 = examples
        .iter()
        .map(|(_, _, w)| w.max(1e-6))
        .sum::<f64>()
        .max(1e-6);
    let mut coef = [0.0f64; N_FEATURES];
    let mut bias = 0.0f64;
    for _ in 0..FIT_EPOCHS {
        let mut grad_coef = [0.0f64; N_FEATURES];
        let mut grad_bias = 0.0f64;
        for (x, y, w) in examples {
            let w = w.max(1e-6);
            let mut z = bias;
            for j in 0..N_FEATURES {
                z += coef[j] * x[j];
            }
            let err = w * (sigmoid(z) - y);
            grad_bias += err;
            for j in 0..N_FEATURES {
                grad_coef[j] += err * x[j];
            }
        }
        let scale = FIT_LR / weight_sum;
        // L2 decay pulls coefficients toward 0 (weight decay); the bias is
        // unregularized (matching linear.rs).
        bias -= scale * grad_bias;
        for j in 0..N_FEATURES {
            coef[j] -= scale * grad_coef[j] + FIT_LR * FIT_L2 * coef[j];
        }
    }

    // Degenerate-fit guard: a non-finite coefficient/bias must not be persisted.
    if !coef.iter().all(|c| c.is_finite()) || !bias.is_finite() {
        return None;
    }

    Some(RankWeights {
        w_relevance: coef[0],
        w_recency: coef[1],
        w_importance: coef[2],
        w_access: coef[3],
        bias,
        feature_mean,
        feature_std,
        n_examples: n_examples as i64,
        fitted_at: Utc::now(),
    })
}

/// Map a learned [`RankWeights`] to the ranker's `(Weights, access_weight)`
/// serving pair.
///
/// The logistic coefficients live on the logit scale and can be NEGATIVE; the
/// fused ranker needs NON-NEGATIVE weights. Mapping rule (per base signal):
/// `fused_weight = coefficient.max(0.0)` then clamp to `[0, FUSED_WEIGHT_MAX]`.
/// Rationale: all three base signals (relevance/recency/importance) SHOULD be
/// positively predictive of a good outcome; a negative coefficient is overfit
/// noise, so it gets weight 0 (drop the signal), never a negative weight that
/// would INVERT the ranking. `w_access` maps to the `access_weight` arg, clamped
/// to `[0, 1]` (its documented range). Non-finite inputs degrade to 0
/// (NaN/Inf-safe — the ranker's own guards are a further backstop).
///
/// The recency HALF-LIFE is NOT learned — it is kept from the global config
/// (`smart_memory_context_recency_halflife_days`); the model learns only the 3
/// blend weights + the access weight.
///
/// KNOWN APPROXIMATION (access fidelity): the fit treats `access_boost` as an
/// INDEPENDENT additive logit term, but the fused ranker folds access INSIDE
/// the importance term — `w_importance · (base + access_weight · access_boost)`.
/// So the served access effect is scaled by the importance weight: if
/// `w_importance` clamps to 0 the access signal is dropped even when the model
/// found it predictive, and when `w_importance` is large the access effect is
/// amplified beyond what was fit. This is a fidelity gap, not a correctness bug
/// — it can't break ranking or violate flag-off parity — and mirrors the
/// heuristic nature of the negative-clamp above. A structurally-faithful access
/// term (fitting over the importance-blended feature) is a follow-up.
pub fn rank_weights_to_fused(rw: &RankWeights) -> (talos_memory::actor_context::Weights, f64) {
    let clamp_weight = |c: f64| -> f64 {
        if c.is_finite() {
            // Finite-guarded above, so clamp() cannot see NaN bounds/input.
            c.clamp(0.0, FUSED_WEIGHT_MAX)
        } else {
            0.0
        }
    };
    let weights = talos_memory::actor_context::Weights {
        relevance: clamp_weight(rw.w_relevance),
        recency: clamp_weight(rw.w_recency),
        importance: clamp_weight(rw.w_importance),
        recency_halflife_days: talos_config::smart_memory_context_recency_halflife_days(),
    };
    let access_weight = if rw.w_access.is_finite() {
        rw.w_access.clamp(0.0, 1.0)
    } else {
        0.0
    };
    (weights, access_weight)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ex(
        relevance: f64,
        recency: f64,
        importance: f64,
        access_boost: Option<f64>,
        judge_passed: Option<bool>,
        status: Option<&str>,
    ) -> RankTrainingExample {
        RankTrainingExample {
            memory_key: "k".to_string(),
            relevance,
            recency,
            importance,
            access_boost,
            fused_score: 0.0,
            rank: 0,
            judge_score: None,
            judge_passed,
            execution_status: status.map(|s| s.to_string()),
            created_at: Utc::now(),
        }
    }

    #[test]
    fn label_prefers_judge_then_status_then_skips() {
        // Judge verdict wins at full weight.
        assert_eq!(
            example_label(&ex(0.5, 0.5, 0.5, None, Some(true), Some("failed"))),
            Some((1.0, JUDGE_SAMPLE_WEIGHT))
        );
        assert_eq!(
            example_label(&ex(0.5, 0.5, 0.5, None, Some(false), None)),
            Some((0.0, JUDGE_SAMPLE_WEIGHT))
        );
        // Status-only at the weaker weight.
        assert_eq!(
            example_label(&ex(0.5, 0.5, 0.5, None, None, Some("completed"))),
            Some((1.0, STATUS_SAMPLE_WEIGHT))
        );
        assert_eq!(
            example_label(&ex(0.5, 0.5, 0.5, None, None, Some("cancelled"))),
            Some((0.0, STATUS_SAMPLE_WEIGHT))
        );
        // Unlabeled statuses / none → skipped.
        assert_eq!(
            example_label(&ex(0.5, 0.5, 0.5, None, None, Some("running"))),
            None
        );
        assert_eq!(example_label(&ex(0.5, 0.5, 0.5, None, None, None)), None);
    }

    #[test]
    fn features_are_relevance_recency_importance_access_neutral_none() {
        let f = example_to_features(&ex(0.9, 0.8, 0.7, Some(0.6), None, None));
        assert_eq!(f, [0.9, 0.8, 0.7, 0.6]);
        // None access_boost → neutral 0.0.
        let f2 = example_to_features(&ex(0.1, 0.2, 0.3, None, None, None));
        assert_eq!(f2, [0.1, 0.2, 0.3, 0.0]);
    }

    #[test]
    fn build_training_set_skips_unlabeled_and_nonfinite() {
        let examples = vec![
            ex(0.9, 0.5, 0.8, None, Some(true), None),       // kept
            ex(0.2, 0.5, 0.1, None, None, Some("running")),  // skipped: unlabeled
            ex(f64::NAN, 0.5, 0.1, None, Some(false), None), // skipped: non-finite
            ex(0.3, 0.4, 0.2, None, None, Some("failed")),   // kept
        ];
        let train = build_training_set(&examples);
        assert_eq!(train.len(), 2);
        assert_eq!(train[0].1, 1.0); // judge pass
        assert_eq!(train[1].1, 0.0); // failed status
        assert_eq!(train[1].2, STATUS_SAMPLE_WEIGHT);
    }

    #[test]
    fn fit_returns_none_below_min_examples() {
        // A handful of examples is below the default min (50).
        let train: Vec<(Vec<f64>, f64, f64)> = (0..10)
            .map(|i| (vec![0.5, 0.5, 0.5, 0.0], (i % 2) as f64, 1.0))
            .collect();
        assert!(fit_rank_weights(&train).is_none());
    }

    #[test]
    fn fit_returns_none_single_class() {
        // 80 examples but ALL positive → no contrast → None.
        let train: Vec<(Vec<f64>, f64, f64)> = (0..80)
            .map(|_| (vec![0.9, 0.5, 0.8, 0.1], 1.0, 1.0))
            .collect();
        assert!(fit_rank_weights(&train).is_none());
    }

    #[test]
    fn fit_recovers_positive_signal_direction_on_separable_data() {
        // Synthetic separable set: the OUTCOME is driven by relevance +
        // importance (features 0 and 2); recency + access are pure noise. A
        // correct fit gives features 0 and 2 clearly positive coefficients,
        // and the mapping produces positive relevance/importance weights.
        let mut train: Vec<(Vec<f64>, f64, f64)> = Vec::new();
        for i in 0..120 {
            let good = i % 2 == 0;
            // Deterministic pseudo-noise in [0,1] for the noise features.
            let noise_a = ((i * 37) % 100) as f64 / 100.0;
            let noise_b = ((i * 53) % 100) as f64 / 100.0;
            if good {
                // high relevance + high importance → label 1
                train.push((vec![0.9, noise_a, 0.85, noise_b], 1.0, 1.0));
            } else {
                // low relevance + low importance → label 0
                train.push((vec![0.1, noise_a, 0.15, noise_b], 0.0, 1.0));
            }
        }
        let rw = fit_rank_weights(&train).expect("separable data must fit");
        assert_eq!(rw.n_examples, 120);
        // The predictive features moved positive.
        assert!(
            rw.w_relevance > 0.0,
            "relevance coef should be positive, got {}",
            rw.w_relevance
        );
        assert!(
            rw.w_importance > 0.0,
            "importance coef should be positive, got {}",
            rw.w_importance
        );
        // The predictive coefficients dominate the noise ones in magnitude.
        assert!(rw.w_relevance > rw.w_recency.abs());
        assert!(rw.w_importance > rw.w_access.abs());

        // Mapping produces non-negative, finite fused weights.
        let (weights, access_weight) = rank_weights_to_fused(&rw);
        assert!(weights.relevance > 0.0);
        assert!(weights.importance > 0.0);
        assert!(weights.relevance.is_finite() && weights.recency.is_finite());
        assert!((0.0..=1.0).contains(&access_weight));
        // Half-life is kept from global config, not learned.
        assert!(
            (weights.recency_halflife_days
                - talos_config::smart_memory_context_recency_halflife_days())
            .abs()
                < 1e-9
        );
    }

    #[test]
    fn mapping_clamps_negative_to_zero_and_caps_and_bounds_access() {
        let rw = RankWeights {
            w_relevance: -3.0,   // negative → 0
            w_recency: 2.5,      // kept
            w_importance: 5.0e9, // above cap → FUSED_WEIGHT_MAX
            w_access: 4.0,       // above 1 → clamped to 1
            bias: 0.0,
            feature_mean: [0.0; N_FEATURES],
            feature_std: [0.0; N_FEATURES],
            n_examples: 100,
            fitted_at: Utc::now(),
        };
        let (weights, access_weight) = rank_weights_to_fused(&rw);
        assert_eq!(weights.relevance, 0.0);
        assert!((weights.recency - 2.5).abs() < 1e-9);
        assert!((weights.importance - FUSED_WEIGHT_MAX).abs() < 1e-9);
        assert!((access_weight - 1.0).abs() < 1e-9);
    }

    #[test]
    fn mapping_is_nan_inf_safe() {
        let rw = RankWeights {
            w_relevance: f64::NAN,
            w_recency: f64::INFINITY,
            w_importance: f64::NEG_INFINITY,
            w_access: f64::NAN,
            bias: 0.0,
            feature_mean: [0.0; N_FEATURES],
            feature_std: [0.0; N_FEATURES],
            n_examples: 100,
            fitted_at: Utc::now(),
        };
        let (weights, access_weight) = rank_weights_to_fused(&rw);
        // NaN → 0; +Inf → capped; -Inf → 0 (via max(0.0) after the finite check
        // fails → 0).
        assert_eq!(weights.relevance, 0.0);
        assert_eq!(weights.recency, 0.0); // +Inf is non-finite → 0
        assert_eq!(weights.importance, 0.0); // -Inf is non-finite → 0
        assert_eq!(access_weight, 0.0);
        assert!(weights.relevance.is_finite());
    }

    #[test]
    fn rank_weights_json_round_trips() {
        let rw = RankWeights {
            w_relevance: 1.25,
            w_recency: -0.4,
            w_importance: 0.9,
            w_access: 0.2,
            bias: -0.1,
            feature_mean: [0.5, 0.4, 0.6, 0.1],
            feature_std: [0.2, 0.1, 0.3, 0.05],
            n_examples: 73,
            fitted_at: Utc::now(),
        };
        let json = serde_json::to_value(&rw).unwrap();
        let back: RankWeights = serde_json::from_value(json).unwrap();
        assert!((back.w_relevance - 1.25).abs() < 1e-12);
        assert!((back.w_recency + 0.4).abs() < 1e-12);
        assert_eq!(back.n_examples, 73);
        assert_eq!(back.feature_mean, [0.5, 0.4, 0.6, 0.1]);
    }
}
