//! RFC 0011 P2d — the DISTILL hook: LLM answers → dataset + shadow.
//!
//! Mirrors the `__memory_write__` protocol exactly: a node that wants
//! its LLM answers distilled emits an `__ml_distill__` envelope in its
//! OUTPUT, and the controller's node-lifecycle hook hands the envelope
//! here. Everything downstream runs in a `tokio::spawn` — the
//! production node's completion latency is unchanged (task #31 perf
//! gate); a distill failure is a WARN + metric, never a workflow error.
//!
//! Envelope (single or batch form):
//!
//! ```json
//! { "__ml_distill__": {
//!     "model": "inbox-classifier-personal",
//!     "items": [ { "features_text": "Subject: ...", "label": "archive",
//!                  "example_key": "gmail-msg-id" } ] } }
//! ```
//!
//! What runs per envelope, by the model's `lifecycle_state`:
//! - **all states**: answers auto-append as `source='llm_production'`
//!   through `DatasetService` (the ONLY writer — encryption + local
//!   embedding + growth-cap eviction ride along, task #31 security
//!   gate).
//! - **shadow / hybrid / fast_primary**: the fast backend predicts the
//!   same items via `serve_predict_batch` (same code path production
//!   serving uses), agreement lands in `ml_shadow_stats` per confidence
//!   band, and divergences / abstentions land in `ml_disagreements`
//!   for the digest.
//!
//! Identity: the envelope carries NO tenancy. The owning user resolves
//! from the HOST-SUPPLIED actor binding (engine-stamped `actor_id` →
//! `actors.user_id`), the same trust chain `__memory_write__` uses; a
//! guest cannot name another tenant's model into scope because model
//! resolution is owner-predicated on that resolved user.

use std::sync::OnceLock;

use anyhow::{Context, Result};
use uuid::Uuid;

use crate::dataset::{AppendExample, DatasetService, ExampleSource};
use crate::lifecycle::{LifecycleService, LifecycleState};
use crate::registry::ModelRegistry;
use crate::serve::serve_predict_batch;

/// Cap on items per envelope — matches the predict RPC posture (a
/// classify node batches ~25); oversized envelopes are truncated with
/// a WARN, never dropped wholesale.
pub const MAX_DISTILL_ITEMS: usize = 64;
const MAX_FEATURE_BYTES: usize = 16 * 1024;
const MAX_LABEL_BYTES: usize = 256;
/// Cap on `example_key`. It indexes the `(dataset_id, example_key)`
/// partial-unique btree; a key over Postgres's ~2704-byte btree row limit
/// errors the whole append chunk. Kept well under that — an oversized key
/// is dropped (append still succeeds; it just won't dedup), never fatal.
const MAX_EXAMPLE_KEY_BYTES: usize = 512;

/// Services the spawned flow needs — installed once from `main()`
/// (same OnceLock-injection shape as `GRAPH_SERVICE` /
/// `ML_PREDICT_CONTEXT`). Until installed, envelopes are dropped with
/// a WARN (never a panic).
pub struct DistillContext {
    pub db_pool: sqlx::PgPool,
    pub dataset_service: DatasetService,
    pub lifecycle_service: LifecycleService,
}

pub static DISTILL_CONTEXT: OnceLock<DistillContext> = OnceLock::new();

/// Concurrency bound on in-flight distill flows (review 2026-07-11):
/// guest output triggers the spawn, and each flow costs embeds + a knn
/// batch + AEAD round-trips — without a bound, a loop node emitting
/// envelopes per iteration is a guest-triggerable amplification DoS.
/// Saturation SHEDS (WARN + drop): distillation is best-effort
/// observation, and shedding under pressure is strictly safer than an
/// unbounded queue of parked tasks.
const MAX_CONCURRENT_DISTILL_FLOWS: usize = 4;
static DISTILL_PERMITS: OnceLock<std::sync::Arc<tokio::sync::Semaphore>> = OnceLock::new();

/// Per-model serialization of the shadow→append critical section. Two
/// distill flows for the SAME model must not interleave: if flow A's
/// append lands between flow B's shadow predict and B's own append, B's
/// `knn_search` sees A's fresh (split-NULL) row as a self-match at
/// similarity ~1.0 carrying the LLM label, structurally inflating shadow
/// agreement — the number the auto-demote guard and the human trust.
/// Different models still run fully concurrent. The map is self-cleaning
/// (entries removed once the last flow releases) so it can't grow with
/// distinct-models-ever-seen — a keyed map needs a sweep, and reference
/// counting is the sweep here.
type FlowLockMap = std::collections::HashMap<Uuid, std::sync::Arc<tokio::sync::Mutex<()>>>;
static MODEL_FLOW_LOCKS: OnceLock<std::sync::Mutex<FlowLockMap>> = OnceLock::new();

/// Acquire (or create) the per-model lock arc. Cloning under the map lock
/// keeps strong-count observations consistent with [`ModelFlowGuard`]'s
/// removal check.
fn model_flow_lock(model_id: Uuid) -> std::sync::Arc<tokio::sync::Mutex<()>> {
    let map = MODEL_FLOW_LOCKS.get_or_init(|| std::sync::Mutex::new(FlowLockMap::new()));
    let mut g = map.lock().unwrap_or_else(|p| p.into_inner());
    g.entry(model_id)
        .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

/// Drops the map entry once no flow holds it. Declared BEFORE the owned
/// mutex guard so it drops AFTER it (reverse drop order) — by then the
/// guard has released its arc ref, so `strong_count == 1` means only the
/// map holds it and it is safe to remove under the same map lock that
/// [`model_flow_lock`] clones under.
struct ModelFlowGuard {
    model_id: Uuid,
}
impl Drop for ModelFlowGuard {
    fn drop(&mut self) {
        if let Some(map) = MODEL_FLOW_LOCKS.get() {
            let mut g = map.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(a) = g.get(&self.model_id) {
                if std::sync::Arc::strong_count(a) == 1 {
                    g.remove(&self.model_id);
                }
            }
        }
    }
}

#[derive(Debug, serde::Deserialize)]
struct DistillEnvelope {
    model: String,
    #[serde(default)]
    items: Vec<DistillItem>,
    // Single-item convenience form (LLM_Inference's DISTILL_MODEL).
    #[serde(default)]
    features_text: Option<String>,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    example_key: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct DistillItem {
    features_text: String,
    label: String,
    #[serde(default)]
    example_key: Option<String>,
}

/// Normalize + validate the envelope into a bounded item list. Items
/// with blank/oversized fields are skipped with a count (partial
/// batches still distill).
fn normalize(envelope: DistillEnvelope) -> Option<(String, Vec<DistillItem>)> {
    let model = envelope.model.trim().to_string();
    if model.is_empty()
        || model.len() > 128
        || !model
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return None;
    }
    let mut items = envelope.items;
    if let (Some(f), Some(l)) = (envelope.features_text, envelope.label) {
        items.push(DistillItem {
            features_text: f,
            label: l,
            example_key: envelope.example_key,
        });
    }
    // Normalize + validate each item. The label is TRIMMED before storage
    // and comparison: an untrimmed "  archive  " would pass validation,
    // be stored as a DISTINCT class, and never equal the model's trimmed
    // prediction — corrupting the demote signal with false divergences and
    // splitting the kNN label space. features_text stays verbatim (it is
    // freeform and the model predicts on the same untrimmed text).
    let before = items.len();
    let mut cleaned: Vec<DistillItem> = Vec::with_capacity(items.len());
    for mut i in items {
        i.label = i.label.trim().to_string();
        if i.features_text.trim().is_empty()
            || i.features_text.len() > MAX_FEATURE_BYTES
            || i.label.is_empty()
            || i.label.len() > MAX_LABEL_BYTES
        {
            continue;
        }
        // Oversized dedup key → replace with the content hash below (a
        // dropped key would bypass dedupe entirely, see next comment).
        if i.example_key
            .as_ref()
            .is_some_and(|k| k.len() > MAX_EXAMPLE_KEY_BYTES)
        {
            i.example_key = None;
        }
        // Content-hash fallback key. The ml_examples dedupe index is partial
        // (`WHERE example_key IS NOT NULL`), so a keyless row is NEVER
        // deduped — retries, replays, and poll loops re-seeing the same item
        // would append duplicate rows forever, inflating min_examples and
        // class balance toward the promotion gate with repeated data. Keying
        // by the hash of the features text makes re-teaching identical
        // content an UPDATE (newest teacher label wins; corrections stay
        // protected by the upsert's source guard) instead of a new row.
        // Done here, not per-emitter, so every __ml_distill__ producer
        // inherits it.
        if i.example_key.is_none() {
            use sha2::{Digest, Sha256};
            let digest = Sha256::digest(i.features_text.as_bytes());
            i.example_key = Some(format!("ch:{digest:x}"));
        }
        cleaned.push(i);
    }
    let mut items = cleaned;
    if items.len() > MAX_DISTILL_ITEMS {
        tracing::warn!(
            model,
            dropped = items.len() - MAX_DISTILL_ITEMS,
            "__ml_distill__ envelope over item cap; truncating"
        );
        items.truncate(MAX_DISTILL_ITEMS);
    }
    if items.len() < before {
        tracing::warn!(
            model,
            skipped = before - items.len(),
            "__ml_distill__ envelope had invalid items; skipped"
        );
    }
    (!items.is_empty()).then_some((model, items))
}

/// Entry point for the controller node hook (node-completion AND
/// per-pipeline-step, mirroring `__memory_write__`). Sync + cheap:
/// extract, validate, `tokio::spawn`, return.
pub fn spawn_distill_from_output(actor_id: Option<Uuid>, output: &serde_json::Value) {
    let Some(raw) = output.get("__ml_distill__") else {
        return;
    };
    let Some(actor_id) = actor_id else {
        // Same contract as __memory_write__: no actor binding → no
        // tenancy principal → the envelope is dropped LOUDLY.
        tracing::warn!(
            "__ml_distill__ emitted by an execution with no actor binding; envelope dropped"
        );
        return;
    };
    let envelope: DistillEnvelope = match serde_json::from_value(raw.clone()) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(error = %e, "__ml_distill__ envelope malformed; dropped");
            return;
        }
    };
    let Some((model, items)) = normalize(envelope) else {
        tracing::warn!("__ml_distill__ envelope empty/invalid after validation; dropped");
        return;
    };
    let Some(ctx) = DISTILL_CONTEXT.get() else {
        tracing::warn!(
            model,
            "__ml_distill__ dropped: distill context not installed"
        );
        return;
    };
    let permits = DISTILL_PERMITS.get_or_init(|| {
        std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_DISTILL_FLOWS))
    });
    let Ok(permit) = permits.clone().try_acquire_owned() else {
        tracing::warn!(
            model,
            cap = MAX_CONCURRENT_DISTILL_FLOWS,
            "__ml_distill__ shed: concurrent distill flows saturated"
        );
        return;
    };
    // Fire-and-forget: the hot path ends here.
    tokio::spawn(async move {
        let _permit = permit;
        if let Err(e) = process_distill(ctx, actor_id, &model, items).await {
            tracing::warn!(
                target: "talos_ml",
                %actor_id,
                model,
                error = %e,
                "distill flow failed (production output unaffected)"
            );
        }
    });
}

/// The spawned flow: resolve tenancy → append → shadow.
async fn process_distill(
    ctx: &'static DistillContext,
    actor_id: Uuid,
    model_name: &str,
    items: Vec<DistillItem>,
) -> Result<()> {
    // Tenancy from the engine-stamped actor binding.
    let user_id: Option<Uuid> = sqlx::query_scalar("SELECT user_id FROM actors WHERE id = $1")
        .bind(actor_id)
        .fetch_optional(&ctx.db_pool)
        .await
        .context("resolve distill actor -> user")?;
    let Some(user_id) = user_id else {
        anyhow::bail!("actor {actor_id} not found; distill envelope dropped");
    };

    // Resolve model + state under the owner's read scope (RLS backstop
    // + app-layer owner predicate in the resolver).
    let mut tx = talos_db::begin_tenant_read_scoped(
        &ctx.db_pool,
        &talos_tenancy::TenantReadScope::new(user_id, Vec::new()),
    )
    .await
    .context("open distill tenant tx")?;
    let Some(resolved) = ModelRegistry::resolve_by_name(&mut tx, model_name, user_id).await? else {
        anyhow::bail!("model '{model_name}' not found for the owning user");
    };
    let Some(dataset_id) = resolved.dataset_id else {
        anyhow::bail!("model '{model_name}' has no dataset; nothing to distill into");
    };
    let state = LifecycleState::parse(&resolved.lifecycle_state).unwrap_or(LifecycleState::LlmOnly);
    let tenancy = ctx
        .dataset_service
        .dataset_tenancy(&mut tx, dataset_id)
        .await
        .context("distill dataset tenancy")?;
    if tenancy.user_id != user_id {
        anyhow::bail!("model '{model_name}' dataset is not owned by the resolving user");
    }
    tx.commit().await.context("commit distill resolve tx")?;

    // Serialize the shadow→append critical section per model so a
    // concurrent flow's append can't interleave and self-match-inflate
    // this flow's shadow agreement (see MODEL_FLOW_LOCKS). `_flow_cleanup`
    // is declared BEFORE `_flow_guard` so it drops AFTER the mutex guard
    // has released its arc ref — only then does strong_count==1 mean the
    // map is the sole holder and the entry is safe to remove.
    let _flow_cleanup = ModelFlowGuard {
        model_id: resolved.model_id,
    };
    let _flow_guard = model_flow_lock(resolved.model_id).lock_owned().await;

    // 1. Shadow FIRST (shadow/hybrid/fast_primary): predict these items
    // BEFORE they enter the dataset — `knn_search` includes fresh
    // (split-NULL) rows, so predicting after the append would find each
    // item as its own nearest neighbor at similarity 1.0 carrying the
    // LLM's label, structurally inflating shadow agreement (the one number
    // the demote guard and the human trust). The doubled embedding cost is
    // absorbed by the embedding LRU (prepare_examples re-embeds as hits).
    //
    // A shadow FAILURE (predict OR a stats/disagreement write) is logged
    // and swallowed here — it must NEVER block the durable append below.
    // The append is the teacher signal; shadow is best-effort observation.
    // (Pre-fix, a mid-loop `?` on a shadow-stat write aborted the whole
    // flow and silently dropped the append.)
    let shadow_recorded = if state != LifecycleState::LlmOnly {
        match run_shadow(
            ctx,
            resolved.model_id,
            user_id,
            tenancy.org_id,
            model_name,
            &items,
        )
        .await
        {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!(
                    target: "talos_ml",
                    model = model_name,
                    error = %e,
                    "shadow accounting failed; proceeding to append"
                );
                0
            }
        }
    } else {
        0
    };

    // 2. Auto-append (ALL states): prepare (embed+encrypt, NO conn
    // held) → short write tx. DatasetService is the only writer, so
    // encryption/embedding/growth-cap all apply.
    let append: Vec<AppendExample> = items
        .iter()
        .map(|i| AppendExample {
            features_text: i.features_text.clone(),
            label: i.label.clone(),
            source: ExampleSource::LlmProduction,
            example_key: i.example_key.clone(),
        })
        .collect();
    let prepared = ctx
        .dataset_service
        .prepare_examples(dataset_id, tenancy, append)
        .await
        .context("prepare distill examples")?;
    let mut tx = talos_db::begin_tenant_read_scoped(
        &ctx.db_pool,
        &talos_tenancy::TenantReadScope::new(user_id, Vec::new()),
    )
    .await
    .context("open distill write tx")?;
    let stored = ctx
        .dataset_service
        .insert_prepared(&mut tx, dataset_id, tenancy, prepared)
        .await
        .context("insert distill examples")?;
    tx.commit().await.context("commit distill write tx")?;

    tracing::info!(
        target: "talos_ml",
        model = model_name,
        state = state.as_str(),
        appended = stored,
        shadow_recorded,
        "distill hook processed"
    );
    Ok(())
}

/// Shadow accounting: predict `items` with the fast path (Raw mode) in a
/// dedicated tx and record per-band agreement + divergences. A predict
/// failure returns `Ok(0)` (unavailable fast path is best-effort); a
/// record/commit failure returns `Err` for the caller to LOG — the caller
/// MUST still run the append (shadow errors are never fatal to the durable
/// teacher signal). The per-model flow lock is held by the caller across
/// this call AND the subsequent append, so no concurrent same-model append
/// can contaminate this prediction. Returns the number of items recorded.
async fn run_shadow(
    ctx: &'static DistillContext,
    model_id: Uuid,
    user_id: Uuid,
    org_id: Option<Uuid>,
    model_name: &str,
    items: &[DistillItem],
) -> Result<usize> {
    let mut tx = talos_db::begin_tenant_read_scoped(
        &ctx.db_pool,
        &talos_tenancy::TenantReadScope::new(user_id, Vec::new()),
    )
    .await
    .context("open distill shadow tx")?;
    let inputs: Vec<String> = items.iter().map(|i| i.features_text.clone()).collect();
    let reply = match serve_predict_batch(
        &ctx.dataset_service,
        &mut tx,
        user_id,
        model_name,
        &inputs,
        crate::serve::ServingMode::Raw,
    )
    .await
    {
        Ok(reply) => reply,
        Err(e) => {
            // Unavailable fast path is best-effort — NOT an error to the
            // caller (which would then skip the append). Swallow here.
            tracing::warn!(
                target: "talos_ml",
                model = model_name,
                error = ?e,
                "shadow predict failed; proceeding to append"
            );
            return Ok(0);
        }
    };
    let mut shadow_recorded = 0usize;
    for (item, slot) in items.iter().zip(reply.predictions) {
        match slot {
            Some(p) => {
                let agreed = p.label == item.label;
                ctx.lifecycle_service
                    .record_shadow_outcome(
                        &mut tx,
                        model_id,
                        user_id,
                        org_id,
                        Some(p.confidence),
                        agreed,
                    )
                    .await?;
                if !agreed {
                    ctx.lifecycle_service
                        .record_disagreement(
                            &mut tx,
                            model_id,
                            user_id,
                            org_id,
                            item.example_key.as_deref(),
                            &item.features_text,
                            Some((&p.label, p.confidence)),
                            &item.label,
                            "divergence",
                        )
                        .await?;
                }
                shadow_recorded += 1;
            }
            None => {
                ctx.lifecycle_service
                    .record_shadow_outcome(&mut tx, model_id, user_id, org_id, None, false)
                    .await?;
                ctx.lifecycle_service
                    .record_disagreement(
                        &mut tx,
                        model_id,
                        user_id,
                        org_id,
                        item.example_key.as_deref(),
                        &item.features_text,
                        None,
                        &item.label,
                        "low_confidence",
                    )
                    .await?;
                shadow_recorded += 1;
            }
        }
    }
    tx.commit().await.context("commit distill shadow tx")?;
    Ok(shadow_recorded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_accepts_batch_and_single_forms() {
        let batch: DistillEnvelope = serde_json::from_value(serde_json::json!({
            "model": "inbox-classifier-personal",
            "items": [
                {"features_text": "Subject: hi", "label": "archive", "example_key": "m1"},
                {"features_text": "  ", "label": "archive"},
                {"features_text": "Subject: q", "label": ""}
            ]
        }))
        .unwrap();
        let (model, items) = normalize(batch).unwrap();
        assert_eq!(model, "inbox-classifier-personal");
        assert_eq!(items.len(), 1, "blank feature + blank label skipped");

        let single: DistillEnvelope = serde_json::from_value(serde_json::json!({
            "model": "m1",
            "features_text": "text",
            "label": "yes"
        }))
        .unwrap();
        let (_, items) = normalize(single).unwrap();
        assert_eq!(items.len(), 1);
    }

    #[test]
    fn normalize_rejects_bad_model_names_and_empty() {
        let bad: DistillEnvelope = serde_json::from_value(serde_json::json!({
            "model": "../etc", "items": [{"features_text": "x", "label": "y"}]
        }))
        .unwrap();
        assert!(normalize(bad).is_none());
        let empty: DistillEnvelope =
            serde_json::from_value(serde_json::json!({"model": "ok", "items": []})).unwrap();
        assert!(normalize(empty).is_none());
    }

    #[test]
    fn normalize_truncates_over_cap() {
        let items: Vec<serde_json::Value> = (0..(MAX_DISTILL_ITEMS + 10))
            .map(|i| serde_json::json!({"features_text": format!("t{i}"), "label": "l"}))
            .collect();
        let env: DistillEnvelope =
            serde_json::from_value(serde_json::json!({"model": "m", "items": items})).unwrap();
        let (_, items) = normalize(env).unwrap();
        assert_eq!(items.len(), MAX_DISTILL_ITEMS);
    }

    #[test]
    fn normalize_trims_label_before_storage() {
        // An untrimmed label would be stored as a DISTINCT class and never
        // equal the model's trimmed prediction (false divergences).
        let env: DistillEnvelope = serde_json::from_value(serde_json::json!({
            "model": "m",
            "items": [{"features_text": "Subject: hi", "label": "  archive  "}]
        }))
        .unwrap();
        let (_, items) = normalize(env).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].label, "archive", "label must be trimmed");
    }

    #[test]
    fn normalize_replaces_oversized_example_key_keeps_item() {
        // Oversized key would blow the (dataset_id, example_key) btree row
        // limit and error the whole append — replace it with the content
        // hash (a bare drop would bypass dedupe entirely), keep the item.
        let big_key = "k".repeat(MAX_EXAMPLE_KEY_BYTES + 1);
        let env: DistillEnvelope = serde_json::from_value(serde_json::json!({
            "model": "m",
            "items": [
                {"features_text": "Subject: a", "label": "archive", "example_key": big_key},
                {"features_text": "Subject: b", "label": "to_read", "example_key": "ok"}
            ]
        }))
        .unwrap();
        let (_, items) = normalize(env).unwrap();
        assert_eq!(items.len(), 2, "both items retained");
        let replaced = items[0].example_key.as_deref().expect("hash key");
        assert!(replaced.starts_with("ch:"), "oversized key → content hash");
        assert!(replaced.len() <= MAX_EXAMPLE_KEY_BYTES);
        assert_eq!(
            items[1].example_key.as_deref(),
            Some("ok"),
            "caller-supplied key kept verbatim"
        );
    }

    #[test]
    fn normalize_derives_content_hash_key_when_absent() {
        // The ml_examples dedupe index is partial (WHERE example_key IS NOT
        // NULL): a keyless row is NEVER deduped, so retries/replays of the
        // same content would append duplicate rows forever and inflate the
        // promotion gate. Absent keys therefore get a deterministic
        // content-hash key — identical text twice yields the SAME key
        // (upsert → one row), different text yields different keys.
        let env = |text: &str| -> DistillEnvelope {
            serde_json::from_value(serde_json::json!({
                "model": "m",
                "items": [{"features_text": text, "label": "archive"}]
            }))
            .unwrap()
        };
        let (_, a1) = normalize(env("Subject: same email")).unwrap();
        let (_, a2) = normalize(env("Subject: same email")).unwrap();
        let (_, b) = normalize(env("Subject: different email")).unwrap();
        let k1 = a1[0].example_key.as_deref().expect("derived key");
        let k2 = a2[0].example_key.as_deref().expect("derived key");
        let kb = b[0].example_key.as_deref().expect("derived key");
        assert!(k1.starts_with("ch:"));
        assert_eq!(k1, k2, "identical content → identical key (dedupes)");
        assert_ne!(k1, kb, "different content → different key");
    }
}
