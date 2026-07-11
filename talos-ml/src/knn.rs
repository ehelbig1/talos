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

/// Similarity-weighted majority vote (no class priors). Delegates to
/// the balanced kernel with empty priors — ONE kernel, so clamp/abstain
/// /tie-break semantics can never fork between the two paths.
pub fn knn_vote(neighbors: &[Neighbor]) -> Option<KnnPrediction> {
    knn_vote_balanced(neighbors, &std::collections::HashMap::new())
}

/// Class-balanced similarity vote with SQRT-DAMPED inverse-frequency
/// weights: weight = similarity / sqrt(class_count).
///
/// Why sqrt and not raw 1/frequency: with raw division a single stray
/// minority neighbor outvotes an unanimous majority neighborhood as
/// soon as the class ratio exceeds k (review finding: archive 557 /
/// follow_up 55, k=7 — 6×0.85/557 < 0.75/55, so a genuinely-archive
/// email served follow_up ABOVE the confidence threshold). Sqrt keeps
/// the minority boost (~3× here) without inverting the bias.
///
/// Classes absent from a NON-empty priors map are clamped to the map's
/// minimum count (not 1): a label that appears mid-eval (concurrent
/// append) must not get a frequency-times advantage. An EMPTY map means
/// "no priors" — every class divides by 1 (plain similarity vote).
///
/// Ties break by label (deterministic — HashMap iteration order must
/// never pick the winner). Confidence is the winning share of DAMPED
/// weight; the semantics changed vs the P1 raw-share vote, so eval
/// records the voting scheme in metrics_json and thresholds must be
/// calibrated against the same scheme that serves.
pub fn knn_vote_balanced(
    neighbors: &[Neighbor],
    class_counts: &std::collections::HashMap<String, i64>,
) -> Option<KnnPrediction> {
    if neighbors.is_empty() {
        return None;
    }
    let min_count = class_counts.values().copied().min().unwrap_or(1).max(1);
    let mut weights: std::collections::HashMap<&str, f32> = std::collections::HashMap::new();
    let mut total = 0.0f32;
    for n in neighbors {
        let count = class_counts
            .get(&n.label)
            .copied()
            .unwrap_or(min_count)
            .max(1);
        let w = n.similarity.clamp(0.0, 1.0) / (count as f32).sqrt();
        *weights.entry(n.label.as_str()).or_insert(0.0) += w;
        total += w;
    }
    if total <= f32::EPSILON {
        return None;
    }
    let (label, weight) = weights
        .into_iter()
        .max_by(|a, b| a.1.total_cmp(&b.1).then(b.0.cmp(a.0)))
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
    fn balanced_vote_boosts_minority_without_inverting() {
        use std::collections::HashMap;
        let counts: HashMap<String, i64> = [
            ("archive".to_string(), 557i64),
            ("follow_up".to_string(), 55),
        ]
        .into();
        // A real archive neighborhood with one stray follow_up must stay
        // archive (raw 1/freq inverted this — the review finding).
        let stray = [
            n("archive", 0.85),
            n("archive", 0.85),
            n("archive", 0.85),
            n("archive", 0.85),
            n("archive", 0.85),
            n("archive", 0.85),
            n("follow_up", 0.75),
        ];
        assert_eq!(knn_vote_balanced(&stray, &counts).unwrap().label, "archive");
        // A majority-follow_up neighborhood beats equal-count archive
        // (plain vote ties on count; sqrt boost breaks toward minority).
        let close = [
            n("follow_up", 0.8),
            n("follow_up", 0.8),
            n("archive", 0.8),
            n("archive", 0.8),
        ];
        let b = knn_vote_balanced(&close, &counts).unwrap();
        assert_eq!(b.label, "follow_up");
        // Mid-eval unseen class clamps to the MAP MINIMUM (55), not 1:
        // an unseen label scores EXACTLY like the smallest seen class
        // would in its place — no frequency-times advantage.
        let unseen = [n("newsletter", 0.7), n("archive", 0.8), n("archive", 0.8)];
        let seen = [n("follow_up", 0.7), n("archive", 0.8), n("archive", 0.8)];
        let u = knn_vote_balanced(&unseen, &counts).unwrap();
        let s = knn_vote_balanced(&seen, &counts).unwrap();
        assert!(
            (u.confidence - s.confidence).abs() < 1e-6,
            "clamp == min-count class"
        );
        // And three close majority neighbors still outvote the stray.
        let three = [
            n("newsletter", 0.7),
            n("archive", 0.8),
            n("archive", 0.8),
            n("archive", 0.8),
        ];
        assert_eq!(knn_vote_balanced(&three, &counts).unwrap().label, "archive");
        // Empty map == plain vote; degenerate similarity abstains.
        assert_eq!(
            knn_vote_balanced(&close, &HashMap::new())
                .unwrap()
                .confidence,
            0.5
        );
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
