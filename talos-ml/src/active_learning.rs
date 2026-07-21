//! RFC 0011 R3 — gray-band active learning.
//!
//! When the Gated serving path returns a prediction whose confidence
//! lands JUST above the fallback threshold (`[threshold, threshold +
//! gray_band)`), the answer was served — but it is exactly the kind of
//! boundary example where the model is least reliable and a human label
//! is most informative. This module routes those examples into the same
//! review queue the shadow flow uses (`ml_disagreements`,
//! kind='low_confidence'), where the existing digest / `ml_disagreements`
//! / `ml_resolve_disagreement` surfaces pick them up unchanged —
//! resolving one appends a `source='correction'` gold example.
//!
//! Invariants:
//! - **Never touches serving**: the serve path only collects the items
//!   and calls [`spawn_gray_band_review`]; every fallible step (cap
//!   COUNT, dedup probe, AEAD encrypt, insert) runs in the spawned task
//!   and failures are WARN-logged, never propagated.
//! - **Capped**: routing stops for the day once the model has
//!   `gray_band_daily_cap` gray-band rows (counted as
//!   kind='low_confidence' AND fast_label IS NOT NULL — shadow
//!   abstentions have fast_label NULL and don't consume the budget).
//! - **Deduped**: an example with ANY pending review row for the same
//!   `example_key` is skipped (kind-agnostic on purpose: a pending
//!   shadow divergence for the same item already puts it in front of
//!   the human; a second row would be duplicate review work).
//! - **Bounded concurrency**: guest traffic drives serving, so the
//!   spawn sheds (debug log) when the small task budget is saturated —
//!   the same posture as the distill flow's semaphore.

use std::sync::OnceLock;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::distill::DISTILL_CONTEXT;

/// Feature-text cap for stored review rows — mirrors the distill
/// validator's MAX_FEATURE_BYTES so a review row can never exceed what
/// the dataset itself would accept on resolve.
const MAX_FEATURE_BYTES: usize = 16 * 1024;

/// In-flight gray-band tasks. Routing is best-effort observation;
/// shedding under pressure is strictly safer than queueing.
const MAX_CONCURRENT_REVIEW_TASKS: usize = 4;
static REVIEW_PERMITS: OnceLock<std::sync::Arc<tokio::sync::Semaphore>> = OnceLock::new();

/// One served-but-barely prediction, captured by the serve path.
pub struct GrayBandItem {
    pub features_text: String,
    pub label: String,
    pub confidence: f32,
}

/// Content-hash review key — the SAME derivation the distill flow uses
/// for keyless items, so a gray-band row and a later distill/correction
/// row for identical text share one `example_key` (dedup + upsert
/// converge on the same identity).
fn content_hash_key(features_text: &str) -> String {
    let digest = Sha256::digest(features_text.as_bytes());
    format!("ch:{digest:x}")
}

/// Fire-and-forget entry point called by `serve_predict_batch` AFTER a
/// Gated batch is served. Cheap on the caller: permit try-acquire +
/// `tokio::spawn`. No context installed (tests, tools) → silent skip.
pub(crate) fn spawn_gray_band_review(
    model_id: Uuid,
    user_id: Uuid,
    org_id: Option<Uuid>,
    daily_cap: i64,
    items: Vec<GrayBandItem>,
) {
    let Some(ctx) = DISTILL_CONTEXT.get() else {
        tracing::debug!(target: "talos_ml", %model_id, "gray-band routing skipped: no context");
        return;
    };
    let permits = REVIEW_PERMITS.get_or_init(|| {
        std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_REVIEW_TASKS))
    });
    let Ok(permit) = permits.clone().try_acquire_owned() else {
        tracing::debug!(target: "talos_ml", %model_id, "gray-band routing shed: tasks saturated");
        return;
    };
    tokio::spawn(async move {
        let _permit = permit;
        if let Err(e) =
            record_gray_band_reviews(ctx, model_id, user_id, org_id, daily_cap, items).await
        {
            tracing::warn!(
                target: "talos_ml",
                %model_id,
                error = %e,
                "gray-band review routing failed (serving unaffected)"
            );
        }
    });
}

/// The spawned body: cap check (one cheap COUNT), per-item dedup, then
/// insert via the same encrypted `record_disagreement` path shadow rows
/// use. Runs on an owner-scoped tx (RLS backstop, same as distill).
async fn record_gray_band_reviews(
    ctx: &'static crate::distill::DistillContext,
    model_id: Uuid,
    user_id: Uuid,
    org_id: Option<Uuid>,
    daily_cap: i64,
    items: Vec<GrayBandItem>,
) -> Result<usize> {
    let mut tx = talos_db::begin_tenant_read_scoped(
        &ctx.db_pool,
        &talos_tenancy::TenantReadScope::new(user_id, Vec::new()),
    )
    .await
    .context("open gray-band review tx")?;

    // Daily budget: gray-band rows only (fast_label IS NOT NULL), so a
    // burst of shadow abstentions can't starve active-learning routing
    // and vice versa. UTC day boundary — a cadence knob, not a contract.
    let today: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM ml_disagreements \
         WHERE model_id = $1 AND kind = 'low_confidence' \
           AND fast_label IS NOT NULL \
           AND created_at >= date_trunc('day', NOW())",
    )
    .bind(model_id)
    .fetch_one(&mut *tx)
    .await
    .context("count today's gray-band rows")?;
    let mut budget = daily_cap.saturating_sub(today);
    if budget <= 0 {
        return Ok(0);
    }

    let mut routed = 0usize;
    for item in items {
        if budget <= 0 {
            break;
        }
        let features =
            talos_text_util::truncate_at_char_boundary(&item.features_text, MAX_FEATURE_BYTES);
        let example_key = content_hash_key(features);
        // Dedup: any pending review row for this example (either kind)
        // means a human is already going to see it.
        let pending: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM ml_disagreements \
             WHERE model_id = $1 AND example_key = $2 AND status = 'pending')",
        )
        .bind(model_id)
        .bind(&example_key)
        .fetch_one(&mut *tx)
        .await
        .context("gray-band dedup probe")?;
        if pending {
            continue;
        }
        // No LLM opinion exists for a served prediction — the model's
        // own label doubles as the row's llm_label (NOT NULL display
        // column); reviewers judge from the feature text either way and
        // the resolve path takes only the human-supplied label.
        ctx.lifecycle_service
            .record_disagreement(
                &mut tx,
                model_id,
                user_id,
                org_id,
                Some(&example_key),
                features,
                Some((&item.label, item.confidence)),
                &item.label,
                "low_confidence",
            )
            .await?;
        budget -= 1;
        routed += 1;
    }
    tx.commit().await.context("commit gray-band review tx")?;
    if routed > 0 {
        tracing::info!(
            target: "talos_ml",
            %model_id,
            routed,
            "gray-band predictions routed to review"
        );
    }
    Ok(routed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_hash_key_is_deterministic_and_distill_compatible() {
        let a = content_hash_key("Subject: same email");
        let b = content_hash_key("Subject: same email");
        let c = content_hash_key("Subject: different email");
        assert_eq!(a, b, "identical text → identical key");
        assert_ne!(a, c);
        // Same "ch:" prefix + hex the distill normalizer emits, so both
        // producers converge on one example identity.
        assert!(a.starts_with("ch:") && a.len() == 3 + 64);
    }
}
