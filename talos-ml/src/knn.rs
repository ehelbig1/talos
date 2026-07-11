//! knn-pgvector backend: the dataset + its embeddings ARE the model.
//!
//! Inference = embed the input text (local nomic), cosine-search the
//! dataset's examples, majority-vote over the top-k with the vote margin
//! as confidence. The vote kernel is pure so the confidence semantics
//! are unit-tested without a database.

use serde::Serialize;

/// One retrieved training example (post-similarity-search).
#[derive(Debug, Clone)]
pub struct Neighbor {
    pub label: String,
    /// Cosine similarity in [0, 1] (pgvector `1 - cosine_distance`).
    pub similarity: f32,
}

#[derive(Debug, Clone, Serialize)]
pub struct KnnPrediction {
    pub label: String,
    /// Similarity-weighted vote share of the winning label in [0, 1].
    /// 1.0 = unanimous neighborhood; ~1/n_classes = coin flip. This is
    /// the value compared against `confidence_threshold` for LLM
    /// fallback.
    pub confidence: f32,
    pub neighbors_considered: usize,
}

/// Similarity-weighted majority vote.
///
/// Weighting by similarity (not plain counts) makes the confidence
/// degrade smoothly when the neighborhood is far away — a unanimous but
/// distant neighborhood should read less confident than a unanimous
/// close one, which plain-count voting can't express. Returns `None`
/// on an empty neighborhood (dataset too small / no embeddings) so the
/// caller falls back rather than fabricating a guess.
pub fn knn_vote(neighbors: &[Neighbor]) -> Option<KnnPrediction> {
    if neighbors.is_empty() {
        return None;
    }
    let mut weights: std::collections::HashMap<&str, f32> = std::collections::HashMap::new();
    let mut total = 0.0f32;
    for n in neighbors {
        // Clamp: cosine similarity of normalized embeddings is [0,1],
        // but guard against pgvector edge cases / denormalized rows.
        let w = n.similarity.clamp(0.0, 1.0);
        *weights.entry(n.label.as_str()).or_insert(0.0) += w;
        total += w;
    }
    if total <= f32::EPSILON {
        // Every neighbor at ~zero similarity: geometrically meaningless.
        return None;
    }
    let (label, weight) = weights
        .into_iter()
        .max_by(|a, b| a.1.total_cmp(&b.1))
        .expect("non-empty by construction");
    Some(KnnPrediction {
        label: label.to_string(),
        confidence: weight / total,
        neighbors_considered: neighbors.len(),
    })
}

/// Class-balanced variant: each neighbor's similarity weight is divided
/// by its class's dataset frequency, so a 77%-archive corpus can't
/// outvote a close follow_up neighborhood by sheer population (P1: the
/// imbalance dragged follow_up recall to 0.545 while archive scored
/// 0.94). `class_counts` are dataset-level label counts; classes absent
/// from the map fall back to weight-1 division (unbalanced behavior).
/// Confidence stays the winning share of BALANCED weight, comparable
/// against the same thresholds.
pub fn knn_vote_balanced(
    neighbors: &[Neighbor],
    class_counts: &std::collections::HashMap<String, i64>,
) -> Option<KnnPrediction> {
    if neighbors.is_empty() {
        return None;
    }
    let mut weights: std::collections::HashMap<&str, f32> = std::collections::HashMap::new();
    let mut total = 0.0f32;
    for n in neighbors {
        let freq = class_counts.get(&n.label).copied().unwrap_or(1).max(1) as f32;
        let w = n.similarity.clamp(0.0, 1.0) / freq;
        *weights.entry(n.label.as_str()).or_insert(0.0) += w;
        total += w;
    }
    if total <= f32::EPSILON {
        return None;
    }
    let (label, weight) = weights
        .into_iter()
        .max_by(|a, b| a.1.total_cmp(&b.1))
        .expect("non-empty by construction");
    Some(KnnPrediction {
        label: label.to_string(),
        confidence: weight / total,
        neighbors_considered: neighbors.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(label: &str, sim: f32) -> Neighbor {
        Neighbor {
            label: label.to_string(),
            similarity: sim,
        }
    }

    #[test]
    fn unanimous_neighborhood_is_full_confidence() {
        let p = knn_vote(&[n("archive", 0.9), n("archive", 0.8), n("archive", 0.7)]).unwrap();
        assert_eq!(p.label, "archive");
        assert!((p.confidence - 1.0).abs() < 1e-6);
        assert_eq!(p.neighbors_considered, 3);
    }

    #[test]
    fn similarity_weighting_beats_plain_counts() {
        // Two weak "archive" votes vs one strong "follow_up" — counts say
        // archive, weights say follow_up.
        let p = knn_vote(&[n("archive", 0.1), n("archive", 0.1), n("follow_up", 0.9)]).unwrap();
        assert_eq!(p.label, "follow_up");
        assert!(p.confidence > 0.5 && p.confidence < 1.0);
    }

    #[test]
    fn empty_and_degenerate_neighborhoods_abstain() {
        assert!(knn_vote(&[]).is_none());
        assert!(knn_vote(&[n("a", 0.0), n("b", 0.0)]).is_none());
    }

    #[test]
    fn balanced_vote_lets_minority_class_win() {
        use std::collections::HashMap;
        // 2 archive neighbors (majority class, 557 examples) vs 1 equally
        // close follow_up (55 examples): plain vote picks archive; the
        // balanced vote divides by class frequency and follow_up wins.
        let ns = [n("archive", 0.8), n("archive", 0.8), n("follow_up", 0.8)];
        let counts: HashMap<String, i64> = [
            ("archive".to_string(), 557i64),
            ("follow_up".to_string(), 55i64),
        ]
        .into();
        assert_eq!(knn_vote(&ns).unwrap().label, "archive");
        let b = knn_vote_balanced(&ns, &counts).unwrap();
        assert_eq!(b.label, "follow_up");
        assert!(b.confidence > 0.5);
        // Missing counts degrade to unbalanced, and degenerate similarity
        // still abstains.
        assert!(knn_vote_balanced(&[n("a", 0.0)], &counts).is_none());
    }

    #[test]
    fn out_of_range_similarities_are_clamped() {
        let p = knn_vote(&[n("a", 5.0), n("b", -3.0)]).unwrap();
        assert_eq!(p.label, "a");
        assert!(
            (p.confidence - 1.0).abs() < 1e-6,
            "negative weight must not vote"
        );
    }
}
