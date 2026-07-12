//! RFC 0011 P3 — parametric backend: multinomial logistic regression over
//! the stored embeddings.
//!
//! The parametric counterpart to `knn-pgvector`. Instead of a per-query
//! ANN vote over the whole dataset, it fits a single global softmax
//! decision boundary ONCE (the serialized artifact) and serves each query
//! as one `W·x + b` + softmax — constant-time, no DB round-trip, and it
//! generalizes across the feature space rather than trusting local
//! neighborhoods. Inverse-frequency class weighting is the parametric
//! analog of knn's balanced-sqrt vote: it lifts minority-class recall
//! (the `follow_up` gap that gates promotion) by making a rare class's
//! errors cost proportionally more during training.
//!
//! Pure Rust, no ML dependency: full-batch gradient descent with L2
//! regularization on L2-normalized features (matching the cosine geometry
//! knn searches). Training a ~3-class × 1024-dim model over a few hundred
//! examples is sub-second, and it reruns only at eval time — never on the
//! serving hot path.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Registry backend tag — the specific ALGORITHM, consistent with
/// `knn-pgvector` being algorithm-specific rather than a family. The
/// `ml_model_versions.backend` CHECK is widened to allow it in migration
/// `20260712210000`. Hyperparameters ride in the version's `metrics_json`.
pub const BACKEND_NAME: &str = "logistic-regression";

/// Current artifact schema version (bumped only on a breaking layout
/// change; `open` refuses anything it doesn't understand rather than
/// mis-reading weights).
const ARTIFACT_VERSION: u32 = 1;

/// Training hyperparameters. Defaults are tuned for L2-normalized
/// embedding features; they converge well under sub-second budgets.
#[derive(Debug, Clone, Copy)]
pub struct FitOpts {
    pub epochs: usize,
    pub lr: f32,
    /// L2 (weight-decay) strength — guards against the many-features /
    /// few-examples overfit regime (1024 dims, hundreds of rows).
    pub l2: f32,
    /// Inverse-frequency class weighting (sklearn `balanced`) — the
    /// minority-class lift. Off = unweighted cross-entropy.
    pub balanced: bool,
}

impl Default for FitOpts {
    fn default() -> Self {
        // epochs=1000/lr=0.3 converge the softmax on L2-normalized
        // embeddings (a live sweep showed 300 epochs UNDER-trains — macro-F1
        // 0.74 vs 0.84 at 1000+). l2 is the per-dataset lever the eval
        // selector grids over, so this is only the starting point.
        Self {
            epochs: 1000,
            lr: 0.3,
            l2: 1e-4,
            balanced: true,
        }
    }
}

/// The fitted model — serialized into `ml_model_versions.artifact`
/// (sha256-integrity-checked by the registry). `weights` is row-major
/// `[class][dim]` so class `c`'s row is `weights[c*dims .. (c+1)*dims]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinearModel {
    pub version: u32,
    /// Label for each class index — the argmax maps back through this.
    pub classes: Vec<String>,
    pub dims: usize,
    pub weights: Vec<f32>,
    pub bias: Vec<f32>,
}

pub struct LinearPrediction {
    pub label: String,
    /// Max softmax probability — same [0,1] confidence semantics the
    /// serving gate + coverage curve expect.
    pub confidence: f32,
}

/// L2-normalize in place (no-op on a zero vector — it stays zero and
/// predicts the bias-only argmax, which is the correct degenerate
/// behavior for a missing embedding).
fn l2_normalize(x: &mut [f32]) {
    let norm = x.iter().map(|v| v * v).sum::<f32>().sqrt();
    if norm > 1e-12 {
        for v in x.iter_mut() {
            *v /= norm;
        }
    }
}

/// Numerically stable softmax over `logits` (max-subtracted), written in
/// place. Returns nothing; `logits` becomes the probability vector.
fn softmax_inplace(logits: &mut [f32]) {
    let max = logits.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
    let mut sum = 0.0f32;
    for v in logits.iter_mut() {
        *v = (*v - max).exp();
        sum += *v;
    }
    if sum > 0.0 {
        for v in logits.iter_mut() {
            *v /= sum;
        }
    }
}

/// Fit a multinomial logistic-regression model. `train` is `(embedding,
/// label)`; embeddings shorter/longer than the modal dimensionality are
/// dropped (an embedder change mid-dataset would otherwise poison the fit).
pub fn fit(train: &[(Vec<f32>, String)], opts: FitOpts) -> Result<LinearModel> {
    anyhow::ensure!(!train.is_empty(), "cannot fit on an empty train set");
    // Modal dimensionality — the dims the majority of rows agree on.
    let mut dim_votes: BTreeMap<usize, usize> = BTreeMap::new();
    for (x, _) in train {
        *dim_votes.entry(x.len()).or_insert(0) += 1;
    }
    let dims = dim_votes
        .iter()
        .max_by_key(|(_, n)| **n)
        .map(|(d, _)| *d)
        .context("no rows to infer dimensionality")?;
    anyhow::ensure!(dims > 0, "embeddings have zero dimensionality");

    // Normalize features + drop dim-mismatched rows FIRST, then derive the
    // class set from the SURVIVORS. A class whose rows are ALL dropped by
    // dim-filtering (embedder drift hitting exactly that class) must not
    // linger in `n_classes` with count 0: that would make `weight_sum` fall
    // below `n`, silently mis-scaling both the gradient-mean/L2 balance
    // (which relies on `weight_sum == n`) and the balanced class weights.
    let mut norm_rows: Vec<(Vec<f32>, &str)> = Vec::with_capacity(train.len());
    for (x, label) in train {
        if x.len() != dims {
            continue;
        }
        let mut xn = x.clone();
        l2_normalize(&mut xn);
        norm_rows.push((xn, label.as_str()));
    }
    anyhow::ensure!(
        !norm_rows.is_empty(),
        "no usable rows after dimensionality filtering"
    );

    // Stable class index over the SURVIVING rows (sorted → deterministic
    // weight layout; every class here has ≥1 row so counts are all > 0).
    let mut class_set: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for (_, label) in &norm_rows {
        class_set.insert(label);
    }
    let classes: Vec<String> = class_set.iter().map(|s| s.to_string()).collect();
    let class_idx: BTreeMap<&str, usize> = classes
        .iter()
        .enumerate()
        .map(|(i, c)| (c.as_str(), i))
        .collect();
    let n_classes = classes.len();
    anyhow::ensure!(
        n_classes >= 2,
        "need at least 2 classes to fit a classifier"
    );

    let mut xs: Vec<Vec<f32>> = Vec::with_capacity(norm_rows.len());
    let mut ys: Vec<usize> = Vec::with_capacity(norm_rows.len());
    let mut class_counts = vec![0usize; n_classes];
    for (xn, label) in norm_rows {
        let ci = class_idx[label];
        class_counts[ci] += 1;
        xs.push(xn);
        ys.push(ci);
    }
    let n = xs.len();

    // Per-class sample weights: balanced = n / (n_classes * count_c) so a
    // rare class's gradient contribution matches an abundant one's. Every
    // count is > 0 (classes derive from survivors), so `weight_sum == n`
    // exactly — keeping the mean-gradient and L2 terms on the same scale.
    let class_weight: Vec<f32> = class_counts
        .iter()
        .map(|&count| {
            if opts.balanced && count > 0 {
                n as f32 / (n_classes as f32 * count as f32)
            } else {
                1.0
            }
        })
        .collect();
    let weight_sum: f32 = ys.iter().map(|&y| class_weight[y]).sum::<f32>().max(1e-6);

    let mut weights = vec![0.0f32; n_classes * dims];
    let mut bias = vec![0.0f32; n_classes];
    let mut grad_w = vec![0.0f32; n_classes * dims];
    let mut grad_b = vec![0.0f32; n_classes];
    // Reused across every sample/epoch (fully overwritten each pass) — avoids
    // ~epochs×n heap allocations of a tiny Vec on the eval hot path.
    let mut probs = vec![0.0f32; n_classes];

    for _ in 0..opts.epochs {
        grad_w.iter_mut().for_each(|g| *g = 0.0);
        grad_b.iter_mut().for_each(|g| *g = 0.0);
        for (x, &y) in xs.iter().zip(ys.iter()) {
            // logits = W·x + b, then softmax (probs overwritten in full).
            for (c, prob) in probs.iter_mut().enumerate() {
                let row = &weights[c * dims..(c + 1) * dims];
                *prob = bias[c] + row.iter().zip(x.iter()).map(|(w, xi)| w * xi).sum::<f32>();
            }
            softmax_inplace(&mut probs);
            let w = class_weight[y];
            for (c, gb) in grad_b.iter_mut().enumerate() {
                // dL/dz_c = w * (p_c - 1{c==y}); backprop into W_c, b_c.
                let err = w * (probs[c] - if c == y { 1.0 } else { 0.0 });
                *gb += err;
                let grow = &mut grad_w[c * dims..(c + 1) * dims];
                for (gd, xi) in grow.iter_mut().zip(x.iter()) {
                    *gd += err * xi;
                }
            }
        }
        // Mean gradient + L2, then a step.
        let scale = opts.lr / weight_sum;
        for (c, b) in bias.iter_mut().enumerate() {
            *b -= scale * grad_b[c];
            let wrow = &mut weights[c * dims..(c + 1) * dims];
            let grow = &grad_w[c * dims..(c + 1) * dims];
            for (wd, gd) in wrow.iter_mut().zip(grow.iter()) {
                // L2 pulls weights toward 0 each step (weight decay).
                *wd -= scale * gd + opts.lr * opts.l2 * *wd;
            }
        }
    }

    Ok(LinearModel {
        version: ARTIFACT_VERSION,
        classes,
        dims,
        weights,
        bias,
    })
}

impl LinearModel {
    /// Predict one embedding. `None` on a dimensionality mismatch (the
    /// serving layer treats that as an abstention → LLM fallback), same
    /// as knn's dim-drift guard.
    pub fn predict(&self, embedding: &[f32]) -> Option<LinearPrediction> {
        if embedding.len() != self.dims || self.classes.is_empty() {
            return None;
        }
        let mut x = embedding.to_vec();
        l2_normalize(&mut x);
        let mut probs = vec![0.0f32; self.classes.len()];
        for (c, prob) in probs.iter_mut().enumerate() {
            let row = &self.weights[c * self.dims..(c + 1) * self.dims];
            *prob = self.bias[c] + row.iter().zip(x.iter()).map(|(w, xi)| w * xi).sum::<f32>();
        }
        softmax_inplace(&mut probs);
        let (best, conf) = probs
            .iter()
            .enumerate()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))?;
        Some(LinearPrediction {
            label: self.classes[best].clone(),
            confidence: *conf,
        })
    }

    /// Serialize to artifact bytes (registry stores + sha256-checks these).
    pub fn to_artifact(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).context("serialize linear artifact")
    }

    /// Parse artifact bytes, refusing an unknown schema version.
    pub fn open(bytes: &[u8]) -> Result<Self> {
        let model: LinearModel = serde_json::from_slice(bytes).context("parse linear artifact")?;
        anyhow::ensure!(
            model.version == ARTIFACT_VERSION,
            "unsupported linear artifact version {}",
            model.version
        );
        anyhow::ensure!(
            model.dims > 0 && model.classes.len() >= 2,
            "degenerate linear artifact (dims={}, classes={})",
            model.dims,
            model.classes.len()
        );
        anyhow::ensure!(
            model.weights.len() == model.classes.len() * model.dims
                && model.bias.len() == model.classes.len(),
            "linear artifact shape mismatch"
        );
        Ok(model)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two linearly separable clusters in 4-D → the fit must reach 100%
    /// train accuracy and round-trip through the artifact unchanged.
    #[test]
    fn fits_separable_data_and_round_trips() {
        let mut train = Vec::new();
        for i in 0..20 {
            let j = i as f32 * 0.01;
            train.push((vec![1.0 + j, 0.0, 0.1, 0.0], "left".to_string()));
            train.push((vec![0.0, 1.0 + j, 0.0, 0.1], "right".to_string()));
        }
        let model = fit(&train, FitOpts::default()).unwrap();
        for (x, y) in &train {
            let p = model.predict(x).unwrap();
            assert_eq!(&p.label, y, "separable point misclassified");
            assert!(p.confidence > 0.5);
        }
        // Artifact round-trip is lossless.
        let bytes = model.to_artifact().unwrap();
        let reopened = LinearModel::open(&bytes).unwrap();
        let a = model.predict(&train[0].0).unwrap();
        let b = reopened.predict(&train[0].0).unwrap();
        assert_eq!(a.label, b.label);
        assert!((a.confidence - b.confidence).abs() < 1e-6);
    }

    /// Balanced weighting must recover a minority class that unweighted
    /// training would swamp. 60 majority vs 6 minority, cleanly separable:
    /// the balanced fit recalls the minority, proving the lever works.
    #[test]
    fn balanced_weighting_recovers_minority_class() {
        let mut train = Vec::new();
        for _ in 0..60 {
            train.push((vec![1.0, 0.0], "major".to_string()));
        }
        for _ in 0..6 {
            train.push((vec![0.0, 1.0], "minor".to_string()));
        }
        let model = fit(&train, FitOpts::default()).unwrap();
        let p = model.predict(&[0.0, 1.0]).unwrap();
        assert_eq!(
            p.label, "minor",
            "balanced weighting lost the minority class"
        );
    }

    #[test]
    fn class_emptied_by_dim_filter_is_dropped() {
        // "c"'s rows are all the WRONG dimensionality (3 vs the modal 2), so
        // they're filtered out — the fit must drop "c" entirely rather than
        // carry a count-0 class (which would push weight_sum below n and
        // mis-scale the L2/gradient balance + the balanced weights).
        let train = vec![
            (vec![1.0, 0.0], "a".to_string()),
            (vec![1.0, 0.1], "a".to_string()),
            (vec![0.0, 1.0], "b".to_string()),
            (vec![0.1, 1.0], "b".to_string()),
            (vec![0.0, 0.0, 1.0], "c".to_string()),
            (vec![0.0, 0.1, 1.0], "c".to_string()),
        ];
        let model = fit(&train, FitOpts::default()).unwrap();
        assert_eq!(model.dims, 2);
        assert_eq!(
            model.classes,
            vec!["a".to_string(), "b".to_string()],
            "the dim-mismatched class must be dropped, not carried empty"
        );
    }

    #[test]
    fn predict_abstains_on_dim_mismatch() {
        let train = vec![
            (vec![1.0, 0.0], "a".to_string()),
            (vec![0.0, 1.0], "b".to_string()),
        ];
        let model = fit(&train, FitOpts::default()).unwrap();
        assert!(model.predict(&[1.0, 0.0, 0.0]).is_none());
    }

    #[test]
    fn open_rejects_bad_shape() {
        let bad = LinearModel {
            version: ARTIFACT_VERSION,
            classes: vec!["a".into(), "b".into()],
            dims: 4,
            weights: vec![0.0; 3], // should be 2*4
            bias: vec![0.0, 0.0],
        };
        let bytes = serde_json::to_vec(&bad).unwrap();
        assert!(LinearModel::open(&bytes).is_err());
    }
}
