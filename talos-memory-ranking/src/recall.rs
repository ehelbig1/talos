//! Grounding-backed semantic recall — routes the EXPLICIT recall path through
//! the smart-context fused ranker.
//!
//! [`recall_semantic_ranked`] is a drop-in for `talos_memory::recall_semantic_filtered`
//! that, when `ENABLE_RANKED_RECALL` is on, overfetches the cosine-nearest hits
//! and re-orders them by the same fused blend the `__actor_context__` grounding
//! path uses (relevance + recency-decay + importance + access-frequency) — and by
//! the LEARNED per-actor weights when `ENABLE_ADAPTIVE_RANK` is also on. Flag OFF
//! ⇒ it delegates straight to `recall_semantic_filtered`, byte-identical to today.
//!
//! It lives in `talos-memory-ranking` (not `talos-memory`) because the learned
//! weights come from [`crate::load_serving_weights`], and `talos-memory-ranking`
//! already depends on `talos-memory` — the reverse dependency would be a cycle.
//!
//! ## Why this is the "grounding any time memory is needed" switch
//! Both the worker `agent_memory::search` RPC path and the MCP
//! `actor_recall_semantic` / `actor_recall_hyde` handlers funnel through the
//! recall functions this wraps, so pointing those three call sites at
//! `recall_semantic_ranked` makes every workflow that recalls memory benefit
//! from the adaptive-memory arc with no per-workflow change.
//!
//! ## Safety
//! * **Default-OFF** (`ENABLE_RANKED_RECALL`) ⇒ byte-identical to plain recall.
//! * **Actor-scoped** — `recall_semantic_filtered` filters `WHERE actor_id = $1`;
//!   `load_serving_weights` reads only that actor's learned weights. No cross-actor
//!   leakage.
//! * **No new egress** — ranking is a pure numeric re-sort; the only embedding
//!   call already lives (tier-1 local-gated) inside `recall_semantic_filtered`.
//! * **Bounded cost** — one extra `SELECT` for learned weights (only when adaptive
//!   is on) and a 3× overfetch of already-indexed rows.

use std::collections::HashMap;

use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use talos_memory::actor_context::{rank_candidates, select_candidates, Weights};
use talos_memory::{recall_semantic_filtered, MemoryHit, SearchMethod, SearchOutcome};

/// Overfetch multiplier — give the ranker a real pool to reorder rather than
/// re-sorting only the `limit` cosine-nearest (which would barely change order).
const OVERFETCH: i64 = 3;

/// Grounding-backed variant of `recall_semantic_filtered`. Same signature +
/// semantics; only the ordering (and only when `ENABLE_RANKED_RECALL` is on)
/// differs. See the module docs.
#[allow(clippy::too_many_arguments)]
pub async fn recall_semantic_ranked(
    pool: &PgPool,
    actor_id: Uuid,
    query: &str,
    limit: i64,
    min_score: f64,
    memory_type_filter: Option<&str>,
    method: SearchMethod,
    exclude_kinds: &[String],
) -> anyhow::Result<SearchOutcome> {
    // Flag OFF → plain cosine recall, byte-identical to before this feature.
    if !talos_config::ranked_recall_enabled() {
        return recall_semantic_filtered(
            pool,
            actor_id,
            query,
            limit,
            min_score,
            memory_type_filter,
            method,
            exclude_kinds,
        )
        .await;
    }

    let limit = limit.clamp(1, 50);
    // Overfetch (capped at the DB layer's own 50 ceiling) so the ranker has a
    // real candidate pool. The DB still returns cosine-nearest; we re-order it.
    let fetch = (limit.saturating_mul(OVERFETCH)).clamp(1, 50);
    let outcome = recall_semantic_filtered(
        pool,
        actor_id,
        query,
        fetch,
        min_score,
        memory_type_filter,
        method,
        exclude_kinds,
    )
    .await?;

    let method_label = outcome.method;
    let embedding_attempted = outcome.embedding_attempted;

    // Weights: learned per-actor when adaptive rank is on (falls back to global
    // on any miss/error), else the global config blend — the SAME resolution the
    // `__actor_context__` grounding path uses.
    let global_weights = Weights {
        relevance: talos_config::smart_memory_context_w_relevance(),
        recency: talos_config::smart_memory_context_w_recency(),
        importance: talos_config::smart_memory_context_w_importance(),
        recency_halflife_days: talos_config::smart_memory_context_recency_halflife_days(),
    };
    let global_access_weight = talos_config::smart_memory_context_access_weight();
    let (weights, access_weight) = if talos_config::adaptive_rank_enabled() {
        crate::load_serving_weights(pool, actor_id)
            .await
            .unwrap_or((global_weights, global_access_weight))
    } else {
        (global_weights, global_access_weight)
    };

    let hits = rank_hits(
        outcome.hits,
        &weights,
        access_weight,
        min_score,
        limit as usize,
        Utc::now(),
    );

    Ok(SearchOutcome {
        hits,
        method: method_label,
        embedding_attempted,
    })
}

/// Pure core: re-order `hits` by the fused ranker and return the top `limit`.
/// Extracted from [`recall_semantic_ranked`] so the novel reorder + reassemble
/// logic is unit-testable without a DB. `now` is injected for determinism.
///
/// The ranker's `Candidate` drops the hit's `score`/`metadata`/`importance`/
/// `access_count`, so we index the full hits by key and reassemble in ranked
/// order — the returned `MemoryHit`s are the originals, just re-sequenced.
fn rank_hits(
    hits: Vec<MemoryHit>,
    weights: &Weights,
    access_weight: f64,
    min_score: f64,
    limit: usize,
    now: chrono::DateTime<Utc>,
) -> Vec<MemoryHit> {
    // 0/1 hits: nothing to reorder — return as-is (truncated).
    if hits.len() <= 1 {
        let mut h = hits;
        h.truncate(limit);
        return h;
    }
    // Preserve the original DB (cosine) order + full hits by key. `select_candidates`
    // silently drops `scratchpad`-type rows, so we re-append anything it drops in
    // original order — ranked recall is a strict REORDER of the same hit set,
    // never a filter (that would be a behavior change beyond ordering).
    let original_order: Vec<String> = hits.iter().map(|h| h.key.clone()).collect();
    let mut by_key: HashMap<String, MemoryHit> = HashMap::with_capacity(hits.len());
    for h in &hits {
        by_key.insert(h.key.clone(), h.clone());
    }
    // Build candidates from the hits alone — NO graph/recency layers (pure
    // recall: return query-relevant matches re-ranked, not recency fallback).
    let candidates = select_candidates(None, hits, vec![], min_score, 0.0, 0.0);
    let ranked = rank_candidates(candidates, weights, now, access_weight);
    let mut out: Vec<MemoryHit> = Vec::with_capacity(limit);
    for c in ranked {
        if out.len() >= limit {
            break;
        }
        if let Some(h) = by_key.remove(&c.key) {
            out.push(h);
        }
    }
    // Re-append any hits the ranker dropped (scratchpad), in original order,
    // so the returned set equals the input set (just reordered + truncated).
    if out.len() < limit {
        for k in &original_order {
            if out.len() >= limit {
                break;
            }
            if let Some(h) = by_key.remove(k) {
                out.push(h);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn hit(key: &str, score: f64, importance: Option<f64>) -> MemoryHit {
        MemoryHit {
            key: key.to_string(),
            value: serde_json::json!({ "k": key }),
            memory_type: "semantic".to_string(),
            expires_at: None,
            updated_at: Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            score,
            metadata: None,
            importance,
            access_count: Some(0),
        }
    }

    fn now() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 2, 0, 0, 0).unwrap()
    }

    // Relevance-only weights → order follows the cosine score, so the ranker
    // reproduces the DB order (sanity that reassembly preserves the hits).
    #[test]
    fn ranks_by_relevance_and_reassembles_full_hits() {
        let hits = vec![
            hit("low", 0.30, None),
            hit("high", 0.90, None),
            hit("mid", 0.60, None),
        ];
        let w = Weights {
            relevance: 1.0,
            recency: 0.0,
            importance: 0.0,
            recency_halflife_days: 7.0,
        };
        let out = rank_hits(hits, &w, 0.0, 0.0, 10, now());
        assert_eq!(
            out.iter().map(|h| h.key.as_str()).collect::<Vec<_>>(),
            vec!["high", "mid", "low"]
        );
        // Reassembled hits are the ORIGINALS (score preserved), not lossy candidates.
        assert_eq!(out[0].score, 0.90);
    }

    // Importance-dominant weights flip the order away from raw cosine — the
    // whole point of ranker-backed recall.
    #[test]
    fn importance_weight_overrides_cosine_order() {
        let hits = vec![
            hit("cosine_top", 0.90, Some(0.10)),
            hit("important", 0.50, Some(1.0)),
        ];
        let w = Weights {
            relevance: 0.2,
            recency: 0.0,
            importance: 2.0,
            recency_halflife_days: 7.0,
        };
        let out = rank_hits(hits, &w, 0.0, 0.0, 10, now());
        assert_eq!(out[0].key, "important", "importance should outrank cosine");
    }

    #[test]
    fn truncates_to_limit() {
        let hits = vec![
            hit("a", 0.9, None),
            hit("b", 0.8, None),
            hit("c", 0.7, None),
        ];
        let w = Weights {
            relevance: 1.0,
            recency: 0.0,
            importance: 0.0,
            recency_halflife_days: 7.0,
        };
        let out = rank_hits(hits, &w, 0.0, 0.0, 2, now());
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].key, "a");
        assert_eq!(out[1].key, "b");
    }

    // Ranked recall is a strict reorder: a scratchpad hit (which the ranker's
    // select_candidates drops) is re-appended, never lost.
    #[test]
    fn scratchpad_hits_preserved_not_filtered() {
        let mut scratch = hit("scratch", 0.95, None);
        scratch.memory_type = "scratchpad".to_string();
        let hits = vec![
            scratch,
            hit("semantic_a", 0.60, None),
            hit("semantic_b", 0.40, None),
        ];
        let w = Weights {
            relevance: 1.0,
            recency: 0.0,
            importance: 0.0,
            recency_halflife_days: 7.0,
        };
        let out = rank_hits(hits, &w, 0.0, 0.0, 10, now());
        // All three hits survive (same set), semantics ranked first, scratchpad appended.
        assert_eq!(out.len(), 3);
        let keys: Vec<&str> = out.iter().map(|h| h.key.as_str()).collect();
        assert_eq!(&keys[0..2], &["semantic_a", "semantic_b"]);
        assert!(keys.contains(&"scratch"));
    }

    #[test]
    fn single_hit_passthrough() {
        let hits = vec![hit("only", 0.5, None)];
        let w = Weights {
            relevance: 1.0,
            recency: 0.0,
            importance: 0.0,
            recency_halflife_days: 7.0,
        };
        let out = rank_hits(hits, &w, 0.0, 0.0, 10, now());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].key, "only");
    }
}
