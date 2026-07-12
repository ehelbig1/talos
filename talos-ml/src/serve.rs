//! Serving layer for `talos.ml.predict` (RFC 0011 P2c).
//!
//! One entry point, [`serve_predict_batch`], designed for the RPC
//! subscriber: resolve the named model under the SIGNED user's OWNER
//! scope (app-layer `user_id` predicate in the registry + the caller's
//! tenant-scoped connection as the RLS backstop), check the promoted
//! version is servable, then run the batch with the expensive
//! invariants hoisted — probes pinned once, class priors aggregated
//! once, embeddings computed CONCURRENTLY (they are independent local
//! HTTP calls; only the ANN queries serialize on the tx connection) —
//! so a full 32-input batch fits comfortably inside the subscriber's
//! 8 s op guard.
//!
//! Model resolution is cached process-globally (TTL + explicit
//! invalidation from the promote path, which runs in the same
//! controller process). Cache entries carry NO dataset content — only
//! registry metadata — and are keyed by (user_id, model_name); entries
//! are only ever written AFTER the owner-scoped resolution and the
//! dataset-ownership belt both pass, so a cached entry can never serve
//! another tenant's request.

use std::collections::HashMap;
use std::sync::{LazyLock, RwLock};
use std::time::{Duration, Instant};

use anyhow::Result;
use sqlx::PgConnection;
use uuid::Uuid;

use crate::dataset::DatasetService;
use crate::knn::knn_vote_balanced;
use crate::registry::ModelRegistry;

/// Default knn neighborhood when the model's `config_json` doesn't pin
/// one. SINGLE source of truth for the MCP eval/predict handlers AND
/// this serving path — a divergence here means the promotion gate
/// certifies a different model than the one being served.
pub const DEFAULT_KNN_K: i64 = 7;

/// Confidence floor applied by the CONSUMER serving gate when a model's
/// `config_json` doesn't set `confidence_threshold`. Non-zero on
/// purpose: an unset threshold must NOT serve thin, low-confidence votes
/// to production — those fall back to the LLM (safe default; an explicit
/// `confidence_threshold: 0.0` opts out).
pub const GATED_DEFAULT_THRESHOLD: f32 = 0.5;

/// How long a resolved (user, model_name) → serving-config entry may be
/// reused. Promotion invalidates same-process immediately (the MCP
/// promote handler calls [`invalidate_serving_cache`]); the TTL bounds
/// staleness for out-of-band writers.
const SERVING_CACHE_TTL: Duration = Duration::from_secs(15);
const SERVING_CACHE_MAX: usize = 4096;

/// Concurrent local-embed calls per batch. Embeds are independent
/// requests against the local embedding endpoint (which has its own
/// LRU + in-flight dedupe); 8 keeps a full 32-input batch ~4 embed
/// round-trips deep instead of 32 sequential ones without saturating
/// a single-instance Ollama.
const EMBED_CONCURRENCY: usize = 8;

/// Registry metadata needed to serve — no tenant content. Cached; the
/// lifecycle-transition + promote paths invalidate on change, so
/// `lifecycle_state` here is never staler than the 15 s TTL.
#[derive(Debug, Clone)]
struct ServingConfig {
    dataset_id: Uuid,
    version: i32,
    backend: String,
    k: i64,
    lifecycle_state: String,
    confidence_threshold: f32,
}

/// Whether a call applies the lifecycle serving gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServingMode {
    /// Predict unconditionally, return every neighborhood vote. Used by
    /// the shadow-accounting hook (needs all predictions + confidences
    /// to record per-band agreement) and the MCP sanity-check tool.
    Raw,
    /// Production consumer serving: the model only serves when it has
    /// earned it. Returns a prediction ONLY when the model is in
    /// `hybrid`/`fast_primary` AND the vote is at/above the model's
    /// `confidence_threshold`; otherwise the slot abstains so the
    /// caller falls back to the LLM. This is what makes the
    /// shadow → hybrid → fast_primary progression actually change what
    /// production serves (in shadow/llm_only the consumer gets
    /// abstain-all and nothing about the workflow's behavior changes).
    Gated,
}

/// Whether the model may serve the consumer at all, given its lifecycle
/// state. Raw always serves; Gated serves only once the model advanced
/// to `hybrid`/`fast_primary`.
fn model_serves(mode: ServingMode, lifecycle_state: &str) -> bool {
    match mode {
        ServingMode::Raw => true,
        ServingMode::Gated => matches!(lifecycle_state, "hybrid" | "fast_primary"),
    }
}

/// Whether one slot's vote is returned to the consumer. Gated abstains
/// below the confidence threshold (→ LLM fallback); Raw keeps every
/// vote for agreement accounting.
fn keep_vote(mode: ServingMode, confidence: f32, threshold: f32) -> bool {
    match mode {
        ServingMode::Raw => true,
        ServingMode::Gated => confidence >= threshold,
    }
}

static SERVING_CACHE: LazyLock<RwLock<HashMap<(Uuid, String), (ServingConfig, Instant)>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// Recover from lock poisoning instead of silently no-op'ing: the map
/// holds only plain data (no invariants spanning entries), so the
/// poisoned contents are safe to keep using. Without this, one panic
/// while holding the write lock would permanently turn
/// [`invalidate_serving_cache`] into a no-op and pin stale promotions
/// until process restart.
fn cache_write(
) -> std::sync::RwLockWriteGuard<'static, HashMap<(Uuid, String), (ServingConfig, Instant)>> {
    SERVING_CACHE
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Drop the cached resolution for one (user, model) — called by the
/// promote handler so a newly promoted version serves immediately.
pub fn invalidate_serving_cache(user_id: Uuid, model_name: &str) {
    cache_write().remove(&(user_id, model_name.to_string()));
}

fn cache_get(user_id: Uuid, model_name: &str) -> Option<ServingConfig> {
    let cache = SERVING_CACHE
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    cache
        .get(&(user_id, model_name.to_string()))
        .and_then(|(cfg, at)| (at.elapsed() < SERVING_CACHE_TTL).then(|| cfg.clone()))
}

fn cache_put(user_id: Uuid, model_name: &str, cfg: ServingConfig) {
    let mut cache = cache_write();
    if cache.len() >= SERVING_CACHE_MAX && !cache.contains_key(&(user_id, model_name.to_string())) {
        cache.retain(|_, (_, at)| at.elapsed() < SERVING_CACHE_TTL);
        if cache.len() >= SERVING_CACHE_MAX {
            // Still saturated with FRESH entries: evict the single
            // oldest instead of clearing — a full clear() collapses the
            // hit rate for every tenant to admit one key.
            if let Some(oldest) = cache
                .iter()
                .min_by_key(|(_, (_, at))| *at)
                .map(|(k, _)| k.clone())
            {
                cache.remove(&oldest);
            }
        }
    }
    cache.insert((user_id, model_name.to_string()), (cfg, Instant::now()));
}

/// Serve-time failure taxonomy — mirrors the wire enum; deliberately
/// coarse (NotFound covers absent AND foreign, so replies can't
/// enumerate other tenants' models).
#[derive(Debug)]
pub enum ServeError {
    NotFound,
    NotPromoted,
    /// Backend can't serve: dataset gone, unsupported backend.
    NotAvailable,
    Internal(anyhow::Error),
}

pub struct ServedPrediction {
    pub label: String,
    pub confidence: f32,
}

pub struct ServeReply {
    /// Parallel to `inputs`; None = abstained (caller's LLM fallback).
    pub predictions: Vec<Option<ServedPrediction>>,
    pub model_version: i32,
    pub backend: String,
}

/// Batch predict for one signed principal. The connection MUST be a
/// tenant-scoped transaction for `user_id` (RLS backstop) — the RPC
/// subscriber opens it from the SIGNED request's user_id, never from
/// anything the guest supplied unsigned. Tenancy does NOT rest on the
/// connection alone: the registry resolver carries an app-layer
/// `user_id` predicate, and the dataset the model points at is
/// ownership-checked before anything is cached or searched.
pub async fn serve_predict_batch(
    service: &DatasetService,
    conn: &mut PgConnection,
    user_id: Uuid,
    model_name: &str,
    inputs: &[String],
    mode: ServingMode,
) -> Result<ServeReply, ServeError> {
    // 1. Resolve (cached) — registry metadata only.
    let cfg = match cache_get(user_id, model_name) {
        Some(cfg) => cfg,
        None => {
            let resolved = ModelRegistry::resolve_by_name(&mut *conn, model_name, user_id)
                .await
                .map_err(ServeError::Internal)?
                .ok_or(ServeError::NotFound)?;
            let promoted = resolved.promoted_version.ok_or(ServeError::NotPromoted)?;
            let dataset_id = resolved.dataset_id.ok_or(ServeError::NotAvailable)?;
            // Dataset-ownership belt (mirrors the MCP handlers'
            // `require_dataset_owner`): even a legitimately-owned model
            // must not search a dataset the signed user doesn't own.
            // Coarse NotAvailable — no foreign-dataset enumeration.
            match service.dataset_tenancy(&mut *conn, dataset_id).await {
                Ok(t) if t.user_id == user_id => {}
                Ok(_) => return Err(ServeError::NotAvailable),
                Err(_) => return Err(ServeError::NotAvailable),
            }
            let k = resolved
                .config_json
                .get("k")
                .and_then(|v| v.as_i64())
                .unwrap_or(DEFAULT_KNN_K)
                .clamp(1, 50);
            // Safe-by-default (review 2026-07-12): an UNSET threshold
            // defaults to GATED_DEFAULT_THRESHOLD, not 0.0 — otherwise a
            // model created with the default `{}` config would, in
            // hybrid, serve every non-abstaining vote (including thin
            // 0.05-confidence guesses) and the "below threshold → LLM"
            // fallback would never fire. An EXPLICIT 0.0 is honored as a
            // deliberate "serve everything the model votes on" opt-out.
            let confidence_threshold = resolved
                .config_json
                .get("confidence_threshold")
                .and_then(|v| v.as_f64())
                .map(|t| t.clamp(0.0, 1.0) as f32)
                .unwrap_or(GATED_DEFAULT_THRESHOLD);
            let cfg = ServingConfig {
                dataset_id,
                version: promoted.version,
                backend: promoted.backend,
                k,
                lifecycle_state: resolved.lifecycle_state,
                confidence_threshold,
            };
            cache_put(user_id, model_name, cfg.clone());
            cfg
        }
    };

    // Consumer serving gate: in shadow/llm_only the model has not earned
    // the right to serve, so abstain on every slot and let the caller's
    // LLM handle the whole batch (the workflow behaves exactly as it did
    // pre-distillation). The append/shadow-accounting path uses
    // `ServingMode::Raw` and skips this.
    if !model_serves(mode, &cfg.lifecycle_state) {
        return Ok(ServeReply {
            predictions: inputs.iter().map(|_| None).collect(),
            model_version: cfg.version,
            backend: cfg.backend,
        });
    }
    if cfg.backend != "knn-pgvector" {
        // P2 serves the lazy backend; parametric backends arrive with
        // the tract runtime. Loud, distinct failure (RFC lifecycle).
        return Err(ServeError::NotAvailable);
    }

    // 2. Hoist per-batch invariants: probes pin + class priors, once.
    service
        .pin_ann_probes(&mut *conn)
        .await
        .map_err(ServeError::Internal)?;
    let counts = service
        .class_counts(&mut *conn, cfg.dataset_id)
        .await
        .map_err(ServeError::Internal)?;
    if counts.is_empty() {
        return Err(ServeError::NotAvailable);
    }

    // 3. Embed all inputs CONCURRENTLY in waves of EMBED_CONCURRENCY
    // (independent local HTTP calls; join_all preserves order). None =
    // embedder down / non-local config → that slot abstains and
    // production callers fall back to their LLM branch per input.
    let mut embeddings: Vec<Option<Vec<f32>>> = Vec::with_capacity(inputs.len());
    for wave in inputs.chunks(EMBED_CONCURRENCY) {
        let results = futures::future::join_all(
            wave.iter()
                .map(|input| talos_memory::embedding::generate_embedding(input, true)),
        )
        .await;
        embeddings.extend(results);
    }

    // 4. Per input: knn → damped balanced vote (sequential — the ANN
    // queries share the one tx connection, but each is a fast indexed
    // lookup once the embeds are in hand).
    let expected_dims = crate::dataset::expected_embedding_dims();
    let mut predictions = Vec::with_capacity(inputs.len());
    for embedding in &embeddings {
        let Some(embedding) = embedding else {
            predictions.push(None);
            continue;
        };
        if embedding.len() != expected_dims {
            // Dimensionality drift (embedding model changed under the
            // dataset): abstain rather than error mid-batch — same
            // guard as `knn_predict_text`.
            predictions.push(None);
            continue;
        }
        let neighbors = service
            .knn_search(&mut *conn, cfg.dataset_id, embedding, cfg.k, true)
            .await
            .map_err(ServeError::Internal)?;
        let vote = knn_vote_balanced(&neighbors, &counts).filter(|p| {
            // Gated: a below-threshold vote abstains so the LLM handles
            // it (the RFC's "below the threshold, the LLM answers"
            // path). Raw keeps every vote for agreement accounting.
            keep_vote(mode, p.confidence, cfg.confidence_threshold)
        });
        predictions.push(vote.map(|p| ServedPrediction {
            label: p.label,
            confidence: p.confidence,
        }));
    }

    Ok(ServeReply {
        predictions,
        model_version: cfg.version,
        backend: cfg.backend,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cfg(k: i64) -> ServingConfig {
        ServingConfig {
            dataset_id: Uuid::from_u128(8),
            version: 3,
            backend: "knn-pgvector".into(),
            k,
            lifecycle_state: "shadow".into(),
            confidence_threshold: 0.6,
        }
    }

    #[test]
    fn gate_serves_only_in_hybrid_or_above() {
        // Raw always serves regardless of state.
        for s in ["llm_only", "shadow", "hybrid", "fast_primary"] {
            assert!(model_serves(ServingMode::Raw, s));
        }
        // Gated serves only once the model earned hybrid+.
        assert!(!model_serves(ServingMode::Gated, "llm_only"));
        assert!(!model_serves(ServingMode::Gated, "shadow"));
        assert!(model_serves(ServingMode::Gated, "hybrid"));
        assert!(model_serves(ServingMode::Gated, "fast_primary"));
    }

    #[test]
    fn gate_threshold_abstains_below_only_when_gated() {
        // Raw keeps every vote (agreement accounting needs them all).
        assert!(keep_vote(ServingMode::Raw, 0.1, 0.6));
        // Gated abstains below threshold → LLM fallback, serves at/above.
        assert!(!keep_vote(ServingMode::Gated, 0.59, 0.6));
        assert!(keep_vote(ServingMode::Gated, 0.6, 0.6));
        assert!(keep_vote(ServingMode::Gated, 0.95, 0.6));
    }

    #[test]
    fn cache_roundtrip_ttl_and_invalidate() {
        let user = Uuid::from_u128(7);
        cache_put(user, "m-test", test_cfg(5));
        assert!(cache_get(user, "m-test").is_some());
        // Tenancy isolation: same name, different user — miss.
        assert!(cache_get(Uuid::from_u128(9), "m-test").is_none());
        invalidate_serving_cache(user, "m-test");
        assert!(cache_get(user, "m-test").is_none());
    }

    #[test]
    fn saturated_cache_evicts_one_not_all() {
        // Use a disjoint user-id range so this test doesn't interact
        // with the roundtrip test sharing the process-global cache.
        let base = 1_000_000u128;
        for i in 0..SERVING_CACHE_MAX as u128 {
            cache_put(Uuid::from_u128(base + i), "m-sat", test_cfg(7));
        }
        // All entries are fresh; inserting one more must evict exactly
        // one (the oldest), not clear the map.
        cache_put(
            Uuid::from_u128(base + SERVING_CACHE_MAX as u128),
            "m-sat",
            test_cfg(7),
        );
        let cache = SERVING_CACHE
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let survivors = (0..=SERVING_CACHE_MAX as u128)
            .filter(|i| cache.contains_key(&(Uuid::from_u128(base + i), "m-sat".to_string())))
            .count();
        assert!(
            survivors >= SERVING_CACHE_MAX - 1,
            "clear()-style mass eviction detected"
        );
    }
}
