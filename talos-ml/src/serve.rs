//! Serving layer for `talos.ml.predict` (RFC 0011 P2c).
//!
//! One entry point, [`serve_predict_batch`], designed for the RPC
//! subscriber: resolve the named model UNDER THE SIGNED USER'S TENANCY
//! (the caller supplies a tenant-scoped connection), check the promoted
//! version is servable, then run the batch with the expensive
//! invariants hoisted — probes pinned once, class priors aggregated
//! once — so per-input cost is one local embed + one indexed knn query.
//!
//! Model resolution is cached process-globally (TTL + explicit
//! invalidation from the promote path, which runs in the same
//! controller process). Cache entries carry NO dataset content — only
//! registry metadata — and are keyed by (user_id, model_name) so one
//! tenant's resolution can never serve another's request.

use std::collections::HashMap;
use std::sync::{LazyLock, RwLock};
use std::time::{Duration, Instant};

use anyhow::Result;
use sqlx::PgConnection;
use uuid::Uuid;

use crate::dataset::DatasetService;
use crate::knn::knn_vote_balanced;
use crate::registry::ModelRegistry;

/// How long a resolved (user, model_name) → serving-config entry may be
/// reused. Promotion invalidates same-process immediately (the MCP
/// promote handler calls [`invalidate_serving_cache`]); the TTL bounds
/// staleness for out-of-band writers.
const SERVING_CACHE_TTL: Duration = Duration::from_secs(15);
const SERVING_CACHE_MAX: usize = 4096;

/// Registry metadata needed to serve — no tenant content.
#[derive(Debug, Clone)]
struct ServingConfig {
    dataset_id: Uuid,
    version: i32,
    backend: String,
    k: i64,
}

static SERVING_CACHE: LazyLock<RwLock<HashMap<(Uuid, String), (ServingConfig, Instant)>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

/// Drop the cached resolution for one (user, model) — called by the
/// promote handler so a newly promoted version serves immediately.
pub fn invalidate_serving_cache(user_id: Uuid, model_name: &str) {
    if let Ok(mut cache) = SERVING_CACHE.write() {
        cache.remove(&(user_id, model_name.to_string()));
    }
}

fn cache_get(user_id: Uuid, model_name: &str) -> Option<ServingConfig> {
    let cache = SERVING_CACHE.read().ok()?;
    cache
        .get(&(user_id, model_name.to_string()))
        .and_then(|(cfg, at)| (at.elapsed() < SERVING_CACHE_TTL).then(|| cfg.clone()))
}

fn cache_put(user_id: Uuid, model_name: &str, cfg: ServingConfig) {
    if let Ok(mut cache) = SERVING_CACHE.write() {
        if cache.len() >= SERVING_CACHE_MAX
            && !cache.contains_key(&(user_id, model_name.to_string()))
        {
            cache.retain(|_, (_, at)| at.elapsed() < SERVING_CACHE_TTL);
            if cache.len() >= SERVING_CACHE_MAX {
                cache.clear();
            }
        }
        cache.insert((user_id, model_name.to_string()), (cfg, Instant::now()));
    }
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
/// tenant-scoped transaction for `user_id` (RLS enforcement) — the RPC
/// subscriber opens it from the SIGNED request's user_id, never from
/// anything the guest supplied unsigned.
pub async fn serve_predict_batch(
    service: &DatasetService,
    conn: &mut PgConnection,
    user_id: Uuid,
    model_name: &str,
    inputs: &[String],
) -> Result<ServeReply, ServeError> {
    // 1. Resolve (cached) — registry metadata only.
    let cfg = match cache_get(user_id, model_name) {
        Some(cfg) => cfg,
        None => {
            let resolved = ModelRegistry::resolve_by_name(&mut *conn, model_name)
                .await
                .map_err(ServeError::Internal)?
                .ok_or(ServeError::NotFound)?;
            let promoted = resolved.promoted_version.ok_or(ServeError::NotPromoted)?;
            let dataset_id = resolved.dataset_id.ok_or(ServeError::NotAvailable)?;
            let k = resolved
                .config_json
                .get("k")
                .and_then(|v| v.as_i64())
                .unwrap_or(5)
                .clamp(1, 50);
            let cfg = ServingConfig {
                dataset_id,
                version: promoted.version,
                backend: promoted.backend,
                k,
            };
            cache_put(user_id, model_name, cfg.clone());
            cfg
        }
    };
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

    // 3. Per input: local embed → knn → damped balanced vote.
    let mut predictions = Vec::with_capacity(inputs.len());
    for input in inputs {
        let Some(embedding) = talos_memory::embedding::generate_embedding(input, true).await else {
            // Embedder down / non-local config: abstain — production
            // callers fall back to their LLM branch per input.
            predictions.push(None);
            continue;
        };
        if embedding.len() != crate::dataset::expected_embedding_dims() {
            // Dimensionality drift (embedding model changed under the
            // dataset): abstain rather than error mid-batch — same
            // guard as `knn_predict_text`.
            predictions.push(None);
            continue;
        }
        let neighbors = service
            .knn_search(&mut *conn, cfg.dataset_id, &embedding, cfg.k, true)
            .await
            .map_err(ServeError::Internal)?;
        predictions.push(
            knn_vote_balanced(&neighbors, &counts).map(|p| ServedPrediction {
                label: p.label,
                confidence: p.confidence,
            }),
        );
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

    #[test]
    fn cache_roundtrip_ttl_and_invalidate() {
        let user = Uuid::from_u128(7);
        let cfg = ServingConfig {
            dataset_id: Uuid::from_u128(8),
            version: 3,
            backend: "knn-pgvector".into(),
            k: 5,
        };
        cache_put(user, "m-test", cfg);
        assert!(cache_get(user, "m-test").is_some());
        // Tenancy isolation: same name, different user — miss.
        assert!(cache_get(Uuid::from_u128(9), "m-test").is_none());
        invalidate_serving_cache(user, "m-test");
        assert!(cache_get(user, "m-test").is_none());
    }
}
